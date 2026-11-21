"""Runtime v2: :func:`sandroid.ai.loop.run_turn` via :class:`AgentSession`.

A scripted fake client (typed ``stream()`` chunks, no network) drives the
loop; every test uses a private registry and a tmp session root.
"""

from __future__ import annotations

import copy
import itertools
import json
import os
import stat
import threading
import time

import pytest

import sandroid.ai.arbiter as arbiter_module
import sandroid.ai.tool_permissions as perms
from sandroid.ai import session as session_module
from sandroid.ai.arbiter import DeviceResourceArbiter, ResourceId
from sandroid.ai.client import (
    ModelProfile,
    RetryInfo,
    StreamChunk,
    StreamError,
    ToolCallDelta,
    Usage,
)
from sandroid.ai.errors import AIClientError
from sandroid.ai.loop import Budgets, build_request_messages
from sandroid.ai.session import AgentSession, ConversationStore, list_threads
from sandroid.ai.tool_permissions import ApprovalBroker, ToolPermissionStore
from sandroid.ai.tools.meta import register_meta_tools
from sandroid.ai.tools.registry import RiskTier, ToolRegistry, ToolSpec

AMBIENT = "Live Sandroid state (auto-refreshed each turn):\n- test"

PROFILE = ModelProfile(
    name="test",
    context_window=262_144,
    system_mode="multi",
    think_tags=False,
    echo_reasoning="all",
    stream_usage=True,
    tool_choice_none=True,
)


# -- fake transport -------------------------------------------------------------


def usage(prompt=100, completion=10, reasoning=0):
    return Usage(prompt, completion, reasoning, prompt + completion)


def text_reply(text, *, reasoning="", finish="stop"):
    chunks = []
    if reasoning:
        chunks.append(StreamChunk("reasoning", text=reasoning))
    chunks.append(StreamChunk("text", text=text))
    chunks.append(StreamChunk("done", finish_reason=finish, usage=usage()))
    return chunks


def tool_reply(*calls, reasoning="", finish="tool_calls"):
    """calls: (name, raw_args[, call_id]); args are streamed in two fragments."""
    chunks = []
    if reasoning:
        chunks.append(StreamChunk("reasoning", text=reasoning))
    for index, call in enumerate(calls):
        name, raw = call[0], call[1]
        call_id = call[2] if len(call) > 2 else f"call_{index}_{name}"
        half = len(raw) // 2
        chunks.append(
            StreamChunk(
                "tool_call",
                tool_call=ToolCallDelta(index, call_id, name, raw[:half]),
            )
        )
        chunks.append(
            StreamChunk(
                "tool_call", tool_call=ToolCallDelta(index, None, None, raw[half:])
            )
        )
    chunks.append(StreamChunk("done", finish_reason=finish, usage=usage()))
    return chunks


class FakeClient:
    """Replays one scripted chunk list (or callable) per ``stream()`` call."""

    model = "fake-model"

    def __init__(self, script, profile=PROFILE):
        self.script = list(script)
        self.profile = profile
        self.calls = []

    def stream(self, messages, tools=None, *, tool_choice=None, cancel_event=None, **_):
        self.calls.append(
            {
                "messages": copy.deepcopy(messages),
                "tools": tools,
                "tool_choice": tool_choice,
            }
        )
        item = self.script.pop(0)
        if callable(item):
            item = item(messages)
        yield from item


# -- fixtures -------------------------------------------------------------------


@pytest.fixture
def perm_store(tmp_path, monkeypatch):
    store = ToolPermissionStore(path=tmp_path / "perms.toml")
    monkeypatch.setattr(perms, "_tool_permission_store", store)
    return store


@pytest.fixture
def arbiter(monkeypatch):
    instance = DeviceResourceArbiter()
    monkeypatch.setattr(arbiter_module, "_arbiter", instance)
    return instance


@pytest.fixture
def registry():
    reg = ToolRegistry()
    register_meta_tools(reg)
    reg.register(
        ToolSpec(
            name="core_info",
            description="Core info tool.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=lambda: {"device": "emulator", "items": [1, 2, 3]},
            core=True,
        )
    )
    reg.register(
        ToolSpec(
            name="deep_lookup",
            description="Look up a package in a deferred toolset.",
            parameters={
                "type": "object",
                "properties": {"package": {"type": "string", "description": "pkg"}},
                "required": ["package"],
            },
            func=lambda package: {"package": package, "found": True},
            toolset="apps",
        )
    )
    return reg


def make_session(tmp_path, client, registry, *, root="tmp", **kwargs):
    kwargs.setdefault("ambient_provider", lambda: AMBIENT)
    kwargs.setdefault("spawn_worker", lambda fn: fn())
    kwargs.setdefault("task_registrar", None)
    return AgentSession.open_new(
        root=tmp_path / "session" if root == "tmp" else root,
        client=client,
        registry=registry,
        **kwargs,
    )


def run(session, text="hello"):
    return session.submit_user_message(text).result(timeout=10)


class Events(list):
    def __call__(self, event):
        self.append(event)

    def of(self, type_):
        return [e for e in self if e.type == type_]


# -- tests ----------------------------------------------------------------------


def test_tool_search_then_call_tool_round_trip(tmp_path, registry, perm_store):
    events = Events()
    client = FakeClient(
        [
            tool_reply(("tool_search", '{"query": "select:deep_lookup"}')),
            tool_reply(
                (
                    "call_tool",
                    '{"name": "deep_lookup", "arguments": {"package": "com.x"}}',
                )
            ),
            text_reply("Found it (R2)."),
        ]
    )
    session = make_session(tmp_path, client, registry, sink=events)
    result = run(session, "find com.x")

    assert result.status == "completed"
    assert result.final_text == "Found it (R2)."
    assert result.rounds == 3
    tool_msgs = [m for m in session.messages if m["role"] == "tool"]
    found = json.loads(tool_msgs[1]["content"])
    assert found["found"] is True
    assert found["_rid"] == "R2"
    assert "deep_lookup" in session.loaded
    calls = events.of("tool_call")
    assert calls[1].payload["name"] == "deep_lookup"
    assert calls[1].payload["via_call_tool"] is True
    res = events.of("tool_result")
    assert [r.payload["status"] for r in res] == ["ok", "ok"]
    assert res[1].payload["result_id"] == "R2"
    assert res[1].payload["ref"]["msg_id"]
    # Same fixed tools array on every request; deep_lookup never added.
    names = [t["function"]["name"] for t in client.calls[0]["tools"]]
    assert names == ["core_info", "tool_search", "call_tool", "read_result"]
    assert all(c["tools"] == client.calls[0]["tools"] for c in client.calls)
    assert (tmp_path / "session/ai/results/R2.json").is_file()
    types = [e.type for e in events]
    assert types[0] == "turn_start"
    assert types[-1] == "turn_end"


def test_direct_call_of_loaded_tool_and_not_loaded_error(tmp_path, registry):
    client = FakeClient(
        [
            tool_reply(("deep_lookup", '{"package": "a"}')),
            tool_reply(("tool_search", '{"query": "select:deep_lookup"}')),
            tool_reply(("deep_lookup", '{"package": "a"}')),
            text_reply("done"),
        ]
    )
    session = make_session(tmp_path, client, registry)
    run(session)
    tools = [json.loads(m["content"]) for m in session.messages if m["role"] == "tool"]
    assert tools[0]["error"]["code"] == "not_loaded"
    assert tools[2]["found"] is True


def test_invalid_arguments_are_returned_to_the_model(tmp_path, registry):
    events = Events()
    client = FakeClient(
        [
            tool_reply(("deep_lookup", "{oops"), ("core_info", '{"x": 1}')),
            text_reply("sorry"),
        ]
    )
    session = make_session(tmp_path, client, registry, sink=events)
    run(session)
    tools = [json.loads(m["content"]) for m in session.messages if m["role"] == "tool"]
    assert tools[0]["error"]["code"] == "invalid_arguments"
    assert tools[0]["error"]["received"] == "{oops"
    assert tools[1]["error"]["code"] == "invalid_arguments"
    assert events.of("tool_call")[0].payload["parse_error"]
    # The echoed assistant message always carries valid JSON arguments.
    assistant = next(m for m in session.messages if m.get("tool_calls"))
    for call in assistant["tool_calls"]:
        json.loads(call["function"]["arguments"])


def test_denied_with_note_reaches_the_model_and_is_not_persisted(
    tmp_path, registry, perm_store
):
    ran = []
    registry.register(
        ToolSpec(
            name="change_device",
            description="Changes the device.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=lambda: ran.append(1) or {"ok": True},
            risk=RiskTier.REVERSIBLE,
            core=True,
        )
    )
    broker = ApprovalBroker(perm_store)
    broker.add_listener(
        lambda kind, request, decision: (
            broker.resolve(request.request_id, "no", note="use the emulator snapshot")
            if kind == "added"
            else None
        )
    )
    events = Events()
    client = FakeClient([tool_reply(("change_device", "{}")), text_reply("ok")])
    session = make_session(tmp_path, client, registry, sink=events, broker=broker)
    run(session)

    assert ran == []
    payload = json.loads(
        next(m for m in session.messages if m["role"] == "tool")["content"]
    )
    assert payload["error"]["code"] == "denied"
    assert payload["error"]["note"] == "use the emulator snapshot"
    assert "use the emulator snapshot" in payload["error"]["message"]
    assert events.of("approval_request")[0].payload["agent_label"] == "Sandroid AI"
    resolved = events.of("approval_resolved")[0].payload
    assert resolved["decision"] == "no"
    assert resolved["by"] == "user"
    assert events.of("tool_result")[0].payload["status"] == "denied"
    assert perm_store.deny_rules() == []
    assert perm_store.allow_rules() == []
    records = ConversationStore.read(session.thread_path)
    assert any(r["type"] == "approval" and r["decision"] == "no" for r in records)


def test_approval_mode_deny_refuses_without_asking(tmp_path, registry, perm_store):
    registry.register(
        ToolSpec(
            name="change_device",
            description="Changes the device.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=lambda: {"ok": True},
            risk=RiskTier.CONSEQUENTIAL,
            core=True,
        )
    )
    client = FakeClient([tool_reply(("change_device", "{}")), text_reply("ok")])
    session = make_session(tmp_path, client, registry, approval_mode="deny")
    run(session)
    payload = json.loads(
        next(m for m in session.messages if m["role"] == "tool")["content"]
    )
    assert payload["error"]["code"] == "denied"


def test_timeout_keeps_lease_until_the_tool_thread_exits(
    tmp_path, registry, arbiter, perm_store
):
    release = threading.Event()
    exited = threading.Event()

    def slow():
        release.wait(5)
        exited.set()
        return {"started": True}

    registry.register(
        ToolSpec(
            name="slow_start",
            description="Slow.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=slow,
            core=True,
            resources=frozenset({ResourceId.MITMPROXY}),
        )
    )
    registry.get_spec("slow_start").timeout_s = 0.3
    events = Events()
    client = FakeClient([tool_reply(("slow_start", "{}")), text_reply("timed out")])
    session = make_session(tmp_path, client, registry, sink=events)
    result = run(session)

    assert result.status == "completed"
    assert events.of("tool_result")[0].payload["status"] == "timeout"
    payload = json.loads(
        next(m for m in session.messages if m["role"] == "tool")["content"]
    )
    assert payload["error"]["code"] == "timeout"
    # The tool still runs: the lease must still be held.
    assert arbiter.snapshot() == {ResourceId.MITMPROXY: "orchestrator"}
    release.set()
    assert exited.wait(2)
    deadline = time.monotonic() + 2
    while arbiter.snapshot() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert arbiter.snapshot() == {}


def test_budget_wrap_up_uses_same_tools_and_tool_choice_none(tmp_path, registry):
    events = Events()
    client = FakeClient(
        [
            tool_reply(("core_info", "{}")),
            tool_reply(("core_info", "{}")),
            text_reply("Summary: R1, R2. Remaining: more."),
        ]
    )
    session = make_session(
        tmp_path, client, registry, sink=events, budgets=Budgets(max_rounds=2)
    )
    result = run(session)

    assert result.status == "max_rounds"
    assert result.budget_kind == "rounds"
    assert result.final_text.startswith("Summary")
    assert client.calls[-1]["tool_choice"] == "none"
    assert client.calls[-1]["tools"] == client.calls[0]["tools"]
    wrap = client.calls[-1]["messages"][-1]
    assert wrap["role"] == "user"
    assert "budget" in wrap["content"]
    # Built on the existing prefix.
    assert (
        client.calls[-1]["messages"][: len(client.calls[1]["messages"])]
        == (client.calls[1]["messages"])
    )
    exhausted = events.of("budget_exhausted")[0].payload
    assert exhausted == {"kind": "rounds", "can_continue": True}
    assert events.of("turn_end")[0].payload["reason"] == "max_rounds"

    # Continue grants N more rounds in the same thread.
    client.script.append(text_reply("continuing"))
    cont = session.continue_turn(extra_rounds=3).result(timeout=5)
    assert cont.status == "completed"
    user = [m for m in session.messages if m["role"] == "user"][-1]
    assert user["content"] == "Continue."
    records = ConversationStore.read(session.thread_path)
    assert any(r.get("continuation") is True for r in records if r["type"] == "msg")


def test_finish_reason_length(tmp_path, registry):
    events = Events()
    client = FakeClient(
        [
            tool_reply(("deep_lookup", '{"package": "com.'), finish="length"),
            text_reply("partial answer", finish="length"),
        ]
    )
    calls = []
    registry.get_spec("core_info").func = lambda: calls.append(1) or {}
    session = make_session(tmp_path, client, registry, sink=events)
    result = run(session)

    payload = json.loads(
        next(m for m in session.messages if m["role"] == "tool")["content"]
    )
    assert payload["error"]["code"] == "invalid_arguments"
    assert "output limit" in payload["error"]["message"]
    assert result.status == "length"
    assert result.final_text == "partial answer"
    assert events.of("turn_end")[0].payload["reason"] == "length"


def test_retry_and_error_events(tmp_path, registry):
    events = Events()
    client = FakeClient(
        [
            [
                StreamChunk("retry", retry=RetryInfo(1, 4, 1.0, "HTTP 503")),
                *text_reply("ok"),
            ],
            [
                StreamChunk("text", text="half"),
                StreamChunk(
                    "error",
                    error=StreamError(
                        "interrupted", "stream interrupted", retryable=True
                    ),
                ),
            ],
        ]
    )
    session = make_session(tmp_path, client, registry, sink=events)
    assert run(session).status == "completed"
    retry = events.of("retry")[0].payload
    assert retry["attempt"] == 1
    assert retry["reason"] == "HTTP 503"

    second = run(session, "again")
    assert second.status == "error"
    assert second.final_text == "half"
    err = events.of("error")[0].payload
    assert err["kind"] == "interrupted"
    assert err["retryable"] is True
    assert session.messages[-1] == {"role": "assistant", "content": "half"}


def test_content_filter_ends_with_error_event(tmp_path, registry):
    events = Events()
    client = FakeClient([text_reply("x", finish="content_filter")])
    session = make_session(tmp_path, client, registry, sink=events)
    assert run(session).status == "content_filter"
    assert events.of("error")[0].payload["kind"] == "content_filter"


def test_reasoning_is_echoed_across_turns(tmp_path, registry):
    client = FakeClient(
        [
            tool_reply(("core_info", "{}"), reasoning="think-1"),
            text_reply("one", reasoning="think-2"),
            text_reply("two"),
        ]
    )
    session = make_session(tmp_path, client, registry)
    run(session, "first")
    run(session, "second")
    sent = client.calls[2]["messages"]
    reasonings = [m.get("reasoning_content") for m in sent if m["role"] == "assistant"]
    assert reasonings == ["think-1", "think-2"]

    turn_profile = ModelProfile(echo_reasoning="turn")
    stripped = build_request_messages(
        sent + [{"role": "assistant", "content": "x", "reasoning_content": "now"}],
        turn_profile,
    )
    assert [
        m.get("reasoning_content") for m in stripped if m["role"] == "assistant"
    ] == [
        None,
        None,
        "now",
    ]
    none_profile = ModelProfile(echo_reasoning="none")
    assert all(
        "reasoning_content" not in m for m in build_request_messages(sent, none_profile)
    )


def test_ambient_placement_keeps_request_prefixes_stable(tmp_path, registry):
    blocks = iter(["state-1", "state-2"])
    client = FakeClient(
        [
            tool_reply(("core_info", "{}")),
            text_reply("a"),
            text_reply("b"),
        ]
    )
    session = make_session(
        tmp_path, client, registry, ambient_provider=lambda: next(blocks)
    )
    run(session, "q1")
    run(session, "q2")
    requests = [c["messages"] for c in client.calls]
    for earlier, later in itertools.pairwise(requests):
        assert later[: len(earlier)] == earlier
    last = requests[-1]
    assert last[-2] == {"role": "system", "content": "state-2"}
    assert last[-1] == {"role": "user", "content": "q2"}
    assert {"role": "system", "content": "state-1"} in last
    assert last[0]["role"] == "system"
    assert "Toolsets" in last[0]["content"]


def test_first_only_profile_appends_ambient_to_user_message(tmp_path, registry):
    profile = ModelProfile(system_mode="first_only", echo_reasoning="turn")
    client = FakeClient([text_reply("a")], profile=profile)
    session = make_session(tmp_path, client, registry)
    run(session, "question")
    roles = [m["role"] for m in client.calls[0]["messages"]]
    assert roles == ["system", "user"]
    assert client.calls[0]["messages"][1]["content"] == f"question\n\n{AMBIENT}"


def test_persistence_and_resume_round_trip(tmp_path, registry):
    root = tmp_path / "session"
    client = FakeClient(
        [
            tool_reply(("tool_search", '{"query": "select:deep_lookup"}')),
            text_reply("first", reasoning="r1"),
        ]
    )
    session = make_session(tmp_path, client, registry)
    run(session, "first question")
    session.close("new")

    path = root / "ai" / "threads" / f"{session.thread_id}.jsonl"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE((root / "ai").stat().st_mode) == 0o700
    records = ConversationStore.read(path)
    types = [r["type"] for r in records]
    assert types[0] == "header"
    assert types[-1] == "close"
    assert "usage" in types
    assert "ambient" in types
    assert [r["seq"] for r in records] == list(range(1, len(records) + 1))
    # User message persisted before the first request.
    assert types.index("msg") < types.index("usage")
    threads = list_threads(root)
    assert threads[0]["thread_id"] == session.thread_id
    assert threads[0]["title"] == "first question"
    assert threads[0]["closed"] is True

    client2 = FakeClient([text_reply("second")])
    resumed = AgentSession.resume(
        session.thread_id,
        root=root,
        client=client2,
        registry=registry,
        ambient_provider=lambda: AMBIENT,
        spawn_worker=lambda fn: fn(),
        task_registrar=None,
    )
    assert resumed.messages[1:] == session.messages[1:]
    assert "deep_lookup" in resumed.loaded
    run(resumed, "second question")
    sent = client2.calls[0]["messages"]
    assert sent[: len(session.messages)] == build_request_messages(
        session.messages, PROFILE
    )
    assert list_threads(root)[0]["closed"] is False
    # R-ids continue after resume.
    assert resumed.result_store.ids() == ["R1"]


def test_resume_repairs_unanswered_tool_calls(tmp_path, registry):
    root = tmp_path / "session"
    client = FakeClient([text_reply("x")])
    session = make_session(tmp_path, client, registry)
    run(session)
    session.store.append(
        "msg",
        role="assistant",
        content=None,
        tool_calls=[
            {
                "id": "c9",
                "type": "function",
                "function": {"name": "a", "arguments": "{}"},
            }
        ],
        msg_id="m99",
        turn="u2",
    )
    resumed = AgentSession.resume(
        session.thread_id,
        root=root,
        client=FakeClient([]),
        registry=registry,
        task_registrar=None,
    )
    assert resumed.messages[-1]["role"] == "tool"
    assert resumed.messages[-1]["tool_call_id"] == "c9"


def test_compaction_checkpoint_is_persisted_and_restored(
    tmp_path, registry, monkeypatch
):
    from sandroid.ai import compaction

    calls = {"n": 0}

    def fake_prepare(messages, tools, meter, cfg, *, summarize, valid_ids):
        calls["n"] += 1
        if calls["n"] != 2:
            return compaction.PrepareResult(list(messages), [], False)
        new = [messages[0], {"role": "user", "content": "[Summary #1 of earlier] x"}]
        new += messages[-2:]
        event = {
            "type": "compaction",
            "kind": "summary",
            "tokens_before": 100,
            "tokens_after": 10,
            "ids": [],
        }
        return compaction.PrepareResult(new, [event], True)

    monkeypatch.setattr(compaction, "prepare", fake_prepare)
    events = Events()
    client = FakeClient([text_reply("a"), text_reply("b")])
    session = make_session(tmp_path, client, registry, sink=events)
    run(session, "one")
    run(session, "two")
    assert events.of("compaction")[0].payload["kind"] == "summary"
    assert session.messages[1]["content"].startswith("[Summary #1")
    assert client.calls[1]["messages"][1]["content"].startswith("[Summary #1")

    resumed = AgentSession.resume(
        session.thread_id,
        root=tmp_path / "session",
        client=FakeClient([]),
        registry=registry,
        task_registrar=None,
    )
    assert resumed.messages[1:] == session.messages[1:]


def test_memory_only_mode_writes_nothing(tmp_path, registry, monkeypatch):
    monkeypatch.chdir(tmp_path)
    client = FakeClient([tool_reply(("core_info", "{}")), text_reply("ok")])
    session = make_session(tmp_path, client, registry, root=None)
    assert run(session).status == "completed"
    session.close()
    assert session.thread_path is None
    assert list(tmp_path.iterdir()) == []
    assert [r["type"] for r in session.store.memory][0] == "header"
    assert session.store.memory[-1]["type"] == "close"
    assert list_threads(None) == []


def test_unused_thread_creates_no_files(tmp_path, registry):
    session = make_session(tmp_path, FakeClient([]), registry)
    session.close()
    assert not (tmp_path / "session").exists()


def test_timeline_emit_failure_never_breaks_a_turn(tmp_path, registry, monkeypatch):
    from sandroid.core import timeline

    def boom(*args, **kwargs):
        raise RuntimeError("timeline down")

    monkeypatch.setattr(timeline, "emit", boom)
    client = FakeClient([tool_reply(("core_info", "{}")), text_reply("fine")])
    session = make_session(tmp_path, client, registry)
    assert run(session).status == "completed"


def test_timeline_lines(tmp_path, registry):
    from sandroid.core import timeline

    client = FakeClient([tool_reply(("core_info", "{}")), text_reply("fine")])
    session = make_session(tmp_path, client, registry)
    with timeline.capture() as lines:
        run(session, "secret question")
    kinds = [(ln["src"], ln["kind"]) for ln in lines]
    assert ("ai", "prompt") in kinds
    assert ("ai", "tool") in kinds
    assert ("ai", "turn") in kinds
    prompt = next(ln for ln in lines if ln["kind"] == "prompt")
    assert prompt["actor"] == "user"
    assert "secret question" not in json.dumps(lines)
    tool = next(ln for ln in lines if ln["kind"] == "tool")
    assert tool["data"]["result_id"] == "R1"
    assert tool["ref"]["path"].endswith(f"ai/threads/{session.thread_id}.jsonl")
    assert tool["ref"]["sha256"]


def test_turn_queue_serialises_and_coalesces_wakes(tmp_path, registry):
    gate = threading.Event()
    active = {"now": 0, "max": 0}
    lock = threading.Lock()

    def slow(text):
        def reply(messages):
            with lock:
                active["now"] += 1
                active["max"] = max(active["max"], active["now"])
            gate.wait(5)
            time.sleep(0.01)
            with lock:
                active["now"] -= 1
            return text_reply(text)

        return reply

    client = FakeClient([slow("a"), slow("b"), slow("c")])
    session = make_session(
        tmp_path, client, registry, spawn_worker=session_module._daemon_worker
    )
    f1 = session.submit_user_message("one")
    f2 = session.enqueue_wake(
        "<subagent-result id=r1>x</subagent-result>", {"id": "r1"}
    )
    f3 = session.enqueue_wake(
        "<subagent-result id=r2>y</subagent-result>", {"id": "r2"}
    )
    f4 = session.submit_user_message("two")
    assert session.running
    gate.set()
    results = [f.result(timeout=10) for f in (f1, f2, f3, f4)]
    assert [r.final_text for r in results] == ["a", "b", "b", "c"]
    assert active["max"] == 1
    assert session.wait_idle(5)
    users = [m["content"] for m in session.messages if m["role"] == "user"]
    assert users[0] == "one"
    assert users[2] == "two"
    assert "id=r1" in users[1]
    assert "id=r2" in users[1]
    session.close()
    with pytest.raises(session_module.SessionBusyError):
        session.submit_user_message("three").result(timeout=1)


def test_close_refused_while_running(tmp_path, registry):
    gate = threading.Event()

    def blocked(messages):
        gate.wait(5)
        return text_reply("x")

    client = FakeClient([blocked])
    session = make_session(
        tmp_path, client, registry, spawn_worker=session_module._daemon_worker
    )
    fut = session.submit_user_message("go")
    with pytest.raises(session_module.SessionBusyError):
        session.close()
    gate.set()
    fut.result(timeout=5)
    assert session.wait_idle(5)
    session.close()
    assert session.closed


def test_cancel_stops_a_running_tool(tmp_path, registry):
    release = threading.Event()
    registry.register(
        ToolSpec(
            name="hang",
            description="Hangs.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=lambda: release.wait(5) and {},
            core=True,
        )
    )
    events = Events()
    client = FakeClient([tool_reply(("hang", "{}"), ("core_info", "{}"))])
    session = make_session(
        tmp_path,
        client,
        registry,
        sink=events,
        spawn_worker=session_module._daemon_worker,
    )
    fut = session.submit_user_message("go")
    deadline = time.monotonic() + 5
    while not events.of("tool_call") and time.monotonic() < deadline:
        time.sleep(0.01)
    session.cancel()
    result = fut.result(timeout=5)
    release.set()
    assert result.status == "cancelled"
    statuses = [e.payload["status"] for e in events.of("tool_result")]
    assert statuses == ["cancelled", "cancelled"]
    # Every tool call is answered.
    assert [m["role"] for m in session.messages[-3:]] == ["assistant", "tool", "tool"]


def test_registers_chat_background_task(tmp_path, registry):
    seen = []

    def registrar(name, display, stop):
        seen.append((name, display))
        return lambda: seen.append(("unregistered", name))

    client = FakeClient([text_reply("x")])
    session = make_session(tmp_path, client, registry, task_registrar=registrar)
    run(session)
    assert seen == [("chat", "AI Chat"), ("unregistered", "chat")]


def test_client_refused_when_settings_have_a_problem(tmp_path, registry):
    class Cfg:
        base_url = None
        api_key = None
        model = None
        allow_remote = False

    with pytest.raises(AIClientError):
        AgentSession.open_new(root=tmp_path, ai_cfg=Cfg(), registry=registry)


def test_usage_events_and_meter(tmp_path, registry):
    events = Events()
    client = FakeClient([text_reply("x")])
    session = make_session(tmp_path, client, registry, sink=events)
    run(session)
    u = events.of("usage")[0].payload
    assert u["prompt"] == 100
    assert u["completion"] == 10
    assert u["context_window"] == 262_144
    assert u["context_used"] == session.meter.used
    assert session.context_breakdown()


# -- cancellation windows (fix pass A) --------------------------------------------


def test_cancel_between_job_pop_and_turn_start_is_not_lost(
    tmp_path, registry, perm_store
):
    client = FakeClient([text_reply("should never be requested")])
    session = make_session(
        tmp_path,
        client,
        registry,
        spawn_worker=lambda fn: threading.Thread(target=fn, daemon=True).start(),
    )
    session._run_lock.acquire()  # e.g. /compact holds it
    try:
        future = session.submit_user_message("hi")
        deadline = time.monotonic() + 5
        while session._queue and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not session._queue  # popped; the drainer waits for the lock
        session.cancel()
    finally:
        session._run_lock.release()

    assert future.result(5).status == "cancelled"
    assert client.calls == []


def test_compact_now_summary_request_is_cancellable(
    tmp_path, registry, perm_store, monkeypatch
):
    entered = threading.Event()
    seen = {}

    class BlockingClient:
        model = "fake-model"
        profile = PROFILE

        def stream(self, messages, tools=None, *, tool_choice=None, **kwargs):
            seen["cancel_event"] = kwargs.get("cancel_event")
            entered.set()
            event = kwargs.get("cancel_event")
            while event is not None and not event.wait(0.02):
                pass
            yield StreamChunk("cancelled")

    def fake_compact_now(messages, tools, meter, cfg, *, summarize, **_):
        try:
            summarize(messages[:1], "summarise")
        except AIClientError as exc:
            seen["error"] = str(exc)
        from sandroid.ai.compaction import PrepareResult

        return PrepareResult(list(messages), [], False)

    monkeypatch.setattr(session_module._compaction, "compact_now", fake_compact_now)
    session = make_session(tmp_path, BlockingClient(), registry)
    done = threading.Event()
    worker = threading.Thread(
        target=lambda: (session.compact_now(), done.set()), daemon=True
    )
    worker.start()
    assert entered.wait(5)
    assert seen["cancel_event"] is not None

    session.cancel()

    assert done.wait(3), "the /compact summary request ignored cancel()"
    assert "cancelled" in seen["error"]
    assert session._aux_cancels == set()


# -- N2 fixes ---------------------------------------------------------------------


def test_mask_sensitive_masks_a_secret_typed_into_a_prompt(
    tmp_path, registry, monkeypatch
):
    """N2-B3: with ai.mask_sensitive on, the model, the thread title
    (ai/index.json) and the transcript never see the typed secret.
    """
    monkeypatch.setattr("sandroid.ai.row_classifier.mask_enabled", lambda: True)
    root = tmp_path / "session"
    client = FakeClient([text_reply("ok")])
    session = make_session(tmp_path, client, registry)
    run(session, "My test key is sk-test1234567890abcd and password=hunter2x")
    session.close("new")

    sent = json.dumps(client.calls[0]["messages"])
    path = root / "ai" / "threads" / f"{session.thread_id}.jsonl"
    stored = path.read_text()
    index = (root / "ai" / "index.json").read_text()
    for text in (sent, stored, index, session.title):
        assert "sk-test1234567890abcd" not in text
        assert "hunter2x" not in text
    assert session.title == "My test key is sk-*** and password=[text, 8 chars]"


def test_prompt_is_unchanged_with_mask_off(tmp_path, registry, monkeypatch):
    monkeypatch.setattr("sandroid.ai.row_classifier.mask_enabled", lambda: False)
    client = FakeClient([text_reply("ok")])
    session = make_session(tmp_path, client, registry)
    run(session, "key sk-test1234567890abcd")
    assert "sk-test1234567890abcd" in json.dumps(client.calls[0]["messages"])


def test_token_totals_survive_a_resume(tmp_path, registry):
    """N2-B7: /threads resume restores the thread's token totals."""
    root = tmp_path / "session"
    client = FakeClient([text_reply("a"), text_reply("b")])
    session = make_session(tmp_path, client, registry)
    run(session, "one")
    run(session, "two")
    totals = dict(session.totals)
    assert totals == {"prompt_tokens": 200, "completion_tokens": 20, "requests": 2}
    session.close("new")
    resumed = AgentSession.resume(
        session.thread_id,
        root=root,
        client=FakeClient([]),
        registry=registry,
        ambient_provider=lambda: AMBIENT,
        spawn_worker=lambda fn: fn(),
        task_registrar=None,
    )
    assert resumed.totals == totals
