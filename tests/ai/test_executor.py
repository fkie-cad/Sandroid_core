"""ToolExecutor: abandoned dispatches, lease settlement and result fallbacks.

The executor runs every tool on a helper thread; on timeout/cancel it stops
waiting while the thread may keep running. These tests pin down that leases
are only settled when that thread really exits, whoever releases the owner
in the meantime (agent end, thread close, reconcile), and that a newer call
of the same owner is never undercut by an older call's rollback.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

import sandroid.ai.arbiter as arbiter_module
import sandroid.ai.tool_permissions as perms
from sandroid.ai.arbiter import Conflict, DeviceResourceArbiter, ResourceId
from sandroid.ai.client import ModelProfile, StreamChunk, ToolCallDelta, Usage
from sandroid.ai.loop import (
    RunContext,
    ToolExecutor,
    current_call_id,
    repair_tool_pairs,
    report_tool_progress,
    run_turn,
    tool_time_remaining,
)
from sandroid.ai.results import ResultStore, TurnBudget
from sandroid.ai.session import AgentSession
from sandroid.ai.tool_permissions import ToolPermissionStore
from sandroid.ai.tools.meta import register_meta_tools
from sandroid.ai.tools.registry import RiskTier, ToolRegistry, ToolSpec

PROFILE = ModelProfile(
    name="test",
    context_window=262_144,
    system_mode="multi",
    think_tags=False,
    echo_reasoning="all",
    stream_usage=True,
    tool_choice_none=True,
)
NO_ARGS = {"type": "object", "properties": {}, "required": []}


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


class SlowTool:
    """A tool that blocks until released; records that it really exited."""

    def __init__(self, result=None):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.exited = threading.Event()
        self.result = {"ok": True} if result is None else result

    def __call__(self):
        self.entered.set()
        self.release.wait(10)
        self.exited.set()
        return self.result


def make_registry(**tools):
    reg = ToolRegistry()
    register_meta_tools(reg)
    for name, (func, resources, timeout) in tools.items():
        reg.register(
            ToolSpec(
                name=name,
                description=f"Tool {name}.",
                parameters=NO_ARGS,
                func=func,
                risk=RiskTier.READ_ONLY,
                core=True,
                resources=frozenset(resources),
            )
        )
        reg.get_spec(name).timeout_s = timeout
    return reg


def executor(reg, agent_id="a-re-aaaaaa", **kwargs):
    ctx = RunContext(
        agent_id=agent_id,
        kind="agent" if agent_id != "orchestrator" else "chat",
        depth=1 if agent_id != "orchestrator" else 0,
        registry=reg,
        exposed=frozenset(spec.name for spec in reg.specs()),
        store=ResultStore(None),
        **kwargs,
    )
    return ToolExecutor(ctx)


def call(ex, name, call_id="c1"):
    return ex.execute(call_id, name, "{}", budget=TurnBudget(None))


def wait_until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.01)


# -- abandoned dispatches -------------------------------------------------------------


def test_agent_end_does_not_release_a_timed_out_tools_lease(perm_store, arbiter):
    """Repro: AgentManager._run's finally calls forget_subtask while the tool
    thread the executor gave up on still runs.
    """
    slow = SlowTool()
    reg = make_registry(slow_dev=(slow, {ResourceId.FRIDA_SERVER}, 0.2))
    arbiter.note_subtask("a-re-aaaaaa")

    outcome = call(executor(reg), "slow_dev")

    assert outcome.status == "timeout"
    assert slow.entered.is_set()
    assert not slow.exited.is_set()
    arbiter.forget_subtask("a-re-aaaaaa")  # the agent ends
    assert arbiter.snapshot() == {ResourceId.FRIDA_SERVER: "a-re-aaaaaa"}
    assert "a-re-aaaaaa" in arbiter.live_subtasks()
    assert isinstance(
        arbiter.claim("orchestrator", frozenset({ResourceId.FRIDA_SERVER})), Conflict
    )
    assert isinstance(
        arbiter.claim("orchestrator", frozenset({ResourceId.WORLD})), Conflict
    )

    slow.release.set()
    assert slow.exited.wait(5)
    wait_until(lambda: not arbiter.snapshot())
    wait_until(lambda: "a-re-aaaaaa" not in arbiter.live_subtasks())
    assert arbiter.claim("orchestrator", frozenset({ResourceId.WORLD})) == frozenset(
        {ResourceId.WORLD}
    )


def test_cancelled_tool_keeps_its_lease_through_reconcile(perm_store, arbiter):
    slow = SlowTool()
    reg = make_registry(slow_dev=(slow, {ResourceId.MONITOR}, 0))
    cancel = threading.Event()
    ex = executor(reg, cancel_event=cancel)
    timer = threading.Timer(0.2, cancel.set)
    timer.start()

    outcome = call(ex, "slow_dev")

    assert outcome.status == "cancelled"
    arbiter.reconcile({"orchestrator"})  # the agent is no longer running
    assert arbiter.snapshot() == {ResourceId.MONITOR: "a-re-aaaaaa"}
    assert arbiter.abandoned_owners() == {"a-re-aaaaaa": 1}
    slow.release.set()
    wait_until(lambda: not arbiter.abandoned_owners())
    assert arbiter.snapshot() == {}


def test_thread_close_does_not_release_an_abandoned_tools_lease(
    tmp_path, perm_store, arbiter
):
    """Repro: session.close() -> release_all(orchestrator) while it runs."""
    slow = SlowTool()
    reg = make_registry(slow_start=(slow, {ResourceId.MITMPROXY}, 0.2))
    replies = [
        [
            StreamChunk(
                "tool_call", tool_call=ToolCallDelta(0, "c1", "slow_start", "{}")
            ),
            StreamChunk("done", finish_reason="tool_calls", usage=Usage(1, 1, 0, 2)),
        ],
        [
            StreamChunk("text", text="it timed out"),
            StreamChunk("done", finish_reason="stop", usage=Usage(1, 1, 0, 2)),
        ],
    ]

    class Client:
        model = "fake"
        profile = PROFILE

        def stream(self, *_a, **_k):
            yield from replies.pop(0)

    session = AgentSession.open_new(
        root=tmp_path / "s",
        client=Client(),
        registry=reg,
        ambient_provider=lambda: "",
        spawn_worker=lambda fn: fn(),
        task_registrar=None,
    )
    assert session.submit_user_message("go").result(10).status == "completed"
    session.close()

    assert arbiter.snapshot() == {ResourceId.MITMPROXY: "orchestrator"}
    assert isinstance(
        arbiter.claim("a-op-other", frozenset({ResourceId.MITMPROXY})), Conflict
    )
    slow.release.set()
    wait_until(lambda: not arbiter.snapshot())


def test_newer_same_owner_call_keeps_a_lease_the_abandoned_call_claimed(
    perm_store, arbiter
):
    """Tool A claims X and times out; tool B reuses X and succeeds; A's late
    rollback must not release X under B.
    """
    slow = SlowTool(result={"error": "failed late"})
    reg = make_registry(
        start_a=(slow, {ResourceId.FRIDA_SERVER}, 0.2),
        start_b=(lambda: {"started": True}, {ResourceId.FRIDA_SERVER}, 5),
    )
    ex = executor(reg, agent_id="orchestrator")

    assert call(ex, "start_a").status == "timeout"
    assert call(ex, "start_b", "c2").status == "ok"
    slow.release.set()
    assert slow.exited.wait(5)
    wait_until(lambda: not arbiter.abandoned_owners())

    assert arbiter.snapshot() == {ResourceId.FRIDA_SERVER: "orchestrator"}


def test_abandoned_call_alone_is_rolled_back_when_it_exits(perm_store, arbiter):
    slow = SlowTool()  # even a late success: the model was told it timed out
    reg = make_registry(start_a=(slow, {ResourceId.FRIDA_SERVER}, 0.2))
    assert call(executor(reg, agent_id="orchestrator"), "start_a").status == "timeout"
    assert arbiter.snapshot() == {ResourceId.FRIDA_SERVER: "orchestrator"}
    slow.release.set()
    wait_until(lambda: not arbiter.snapshot())


def test_tool_sees_the_time_left_before_the_executor_gives_up(perm_store, arbiter):
    seen = {}

    def probe():
        seen["left"] = tool_time_remaining()
        return {}

    reg = make_registry(probe=(probe, (), 30), untimed=(dict, (), 0))
    assert call(executor(reg), "probe").status == "ok"
    assert 25 < seen["left"] <= 30
    assert tool_time_remaining() is None


def test_tool_progress_carries_the_call_id_and_is_throttled(perm_store, arbiter):
    events = []
    seen = {}

    def busy():
        seen["call_id"] = current_call_id()
        sent = [report_tool_progress(0, 10, matched=0, note="classifying", force=True)]
        sent.append(report_tool_progress(5, 10, matched=1, note="classifying"))
        sent.append(report_tool_progress(10, 10, matched=2, note="done", force=True))
        seen["sent"] = sent
        return {"ok": True}

    reg = make_registry(busy=(busy, (), 30))
    ex = executor(reg, agent_id="orchestrator", sink=events.append)
    assert call(ex, "busy", call_id="call-42").status == "ok"
    assert seen["call_id"] == "call-42"
    assert seen["sent"] == [True, False, True]  # the middle one is throttled
    progress = [e for e in events if e.type == "tool_progress"]
    assert [e.payload["call_id"] for e in progress] == ["call-42", "call-42"]
    assert progress[0].payload == {
        "call_id": "call-42",
        "done": 0,
        "total": 10,
        "matched": 0,
        "note": "classifying",
    }
    types = [e.type for e in events]
    assert types.index("tool_call") < types.index("tool_progress")
    # Outside a tool call it is a no-op.
    assert report_tool_progress(1, 2) is False
    assert current_call_id() is None


# -- result fallbacks and history repair ----------------------------------------------


def test_store_failure_sends_a_capped_preview_not_the_whole_result(
    perm_store, arbiter, monkeypatch
):
    big = {"rows": ["x" * 100] * 5000}  # ~0.5 MB
    reg = make_registry(big=(lambda: big, (), 5))
    ex = executor(reg, cap_tokens=1000)
    monkeypatch.setattr(
        ResultStore, "put", lambda *a, **k: (_ for _ in ()).throw(OSError("disk"))
    )

    outcome = call(ex, "big")

    assert outcome.status == "ok"
    assert len(outcome.content) < 5000
    payload = json.loads(outcome.content)
    assert payload["truncated"] is True
    assert "OSError" in payload["note"]
    assert payload["total_chars"] > 400_000
    assert outcome.truncated


def test_internal_error_repairs_unanswered_tool_calls(perm_store, arbiter, monkeypatch):
    """A non-ToolError escaping _run_tools must not leave the assistant's
    tool_calls unanswered in memory (the next request would be rejected).
    """
    reg = make_registry(core_info=(dict, (), 5))
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "go"},
    ]

    class Client:
        model = "fake"
        profile = PROFILE

        def stream(self, *_a, **_k):
            for index, call_id in enumerate(("c1", "c2")):
                yield StreamChunk(
                    "tool_call",
                    tool_call=ToolCallDelta(index, call_id, "core_info", "{}"),
                )
            yield StreamChunk(
                "done", finish_reason="tool_calls", usage=Usage(1, 1, 0, 2)
            )

    original = ToolExecutor.execute

    def flaky(self, call_id, name, raw, *, budget):
        if call_id == "c2":
            raise RuntimeError("executor bug")
        return original(self, call_id, name, raw, budget=budget)

    monkeypatch.setattr(ToolExecutor, "execute", flaky)
    ctx = RunContext(
        registry=reg,
        exposed=frozenset(s.name for s in reg.specs()),
        store=ResultStore(None),
    )

    result = run_turn(messages, ctx, client=Client(), tools=[])

    assert result.status == "error"
    assistant = next(m for m in messages if m.get("tool_calls"))
    after = messages[messages.index(assistant) + 1 :]
    assert [m.get("tool_call_id") for m in after] == ["c1", "c2"]
    assert json.loads(after[-1]["content"])["error"]["code"] == "cancelled"
    assert repair_tool_pairs(messages) == messages


def test_failed_replay_result_summary_reads_as_words():
    """A {"success": false} replay result: the failed chip said "6 fields"."""
    from sandroid.ai.loop import summarize_result

    diverged = {
        "success": False,
        "run_id": "r1",
        "error": None,
        "result": "diverged",
        "diverged_at_step": 3,
        "unchecked_steps": [],
    }
    assert summarize_result(diverged) == "replay diverged at step 3"
    unchecked = {**diverged, "result": "unchecked", "diverged_at_step": None}
    unchecked["unchecked_steps"] = [2, 5]
    assert summarize_result(unchecked) == "replay not checked (steps 2, 5)"
    refused = {"success": False, "message": "No recording in progress"}
    assert summarize_result(refused) == "No recording in progress"
    # Unchanged for successes and plain errors.
    assert summarize_result({"success": True, "selected": ["a"]}) == "1 selected"
    assert summarize_result({"error": "boom"}) == "boom"


def test_prompts_say_a_diverged_or_unchecked_replay_is_no_success():
    from sandroid.ai.prompts import (
        OPERATOR_PROMPT,
        ORCHESTRATOR_PROMPT_V2,
        RESEARCHER_PROMPT,
    )

    for prompt in (ORCHESTRATOR_PROMPT_V2, OPERATOR_PROMPT, RESEARCHER_PROMPT):
        flat = " ".join(prompt.split())
        assert '"success": false means the call did not succeed' in flat
        assert '"diverged"' in flat
        assert '"unchecked"' in flat
        assert "never" in flat
    # The addition sits after the approvals rule; the start is unchanged.
    assert ORCHESTRATOR_PROMPT_V2.startswith("You are Sandroid's built-in AI assistant")
