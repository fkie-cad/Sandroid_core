"""Unit tests for sandroid.ai.loop.run_agent_turn.

No real network / OpenAIClient involved: a hand-written FakeOpenAIClient
yields scripted ChatEvent sequences, one list per call to .chat(). The
ToolRegistry used by the loop is monkeypatched to a fresh, test-local
instance so these tests never depend on (or pollute) the process-wide
singleton populated by sandroid.ai's import-time side effects.
"""

import json
import threading

import pytest

import sandroid.ai.loop as loop_module
import sandroid.ai.tool_permissions as tool_permissions_module
from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.loop import run_agent_turn
from sandroid.ai.tool_permissions import ToolPermissionStore
from sandroid.ai.tools.registry import RiskTier, ToolRegistry, ToolSpec


class FakeOpenAIClient:
    """Replays one scripted event list per call to .chat(), in order."""

    def __init__(self, scripted_calls):
        self._scripted_calls = list(scripted_calls)
        self.calls = []  # (messages snapshot, tools) per .chat() call

    def chat(self, messages, tools=None, stream=True):
        self.calls.append((list(messages), tools))
        events = self._scripted_calls.pop(0)
        return iter(events)


@pytest.fixture
def test_registry(monkeypatch):
    registry = ToolRegistry()
    monkeypatch.setattr(loop_module, "get_tool_registry", lambda: registry)
    return registry


@pytest.fixture
def permission_store(tmp_path, monkeypatch):
    """A fresh ToolPermissionStore backed by a temp file, wired up wherever
    the gate reads it from: `resolve_tool_policy` (defined in
    tool_permissions.py) calls the module-level `get_tool_permission_store`
    in *its own* module's globals, while `_dispatch_one` (loop.py) calls the
    name it imported into *loop.py's* globals -- both must be patched to the
    same instance, or `mark_allowed`/`mark_never` and policy resolution would
    silently disagree. Mirrors test_tool_permissions.py's `store` fixture.
    """
    instance = ToolPermissionStore(path=tmp_path / "ai_tool_permissions.toml")
    monkeypatch.setattr(tool_permissions_module, "_tool_permission_store", None)
    monkeypatch.setattr(
        tool_permissions_module, "get_tool_permission_store", lambda: instance
    )
    monkeypatch.setattr(loop_module, "get_tool_permission_store", lambda: instance)
    return instance


def test_no_tool_call_returns_accumulated_text(test_registry):
    client = FakeOpenAIClient(
        [
            [
                {"type": "text_delta", "content": "Hello"},
                {"type": "text_delta", "content": ", world"},
                {"type": "done"},
            ]
        ]
    )
    received = []
    messages = [{"role": "user", "content": "hi"}]

    result = run_agent_turn(
        messages=messages,
        tools=[],
        client=client,
        cancel_event=threading.Event(),
        on_event=received.append,
    )

    assert result == "Hello, world"
    assert [e["content"] for e in received if e["type"] == "text_delta"] == [
        "Hello",
        ", world",
    ]
    assert len(client.calls) == 1


def test_single_tool_call_round_trip_with_fragmented_arguments(test_registry):
    recorded_kwargs = []

    def fake_tool(limit):
        recorded_kwargs.append({"limit": limit})
        return {"result": "ok", "limit": limit}

    test_registry.register(
        ToolSpec(
            name="test_tool",
            description="A fake test tool.",
            parameters={
                "type": "object",
                "properties": {"limit": {"type": "integer"}},
                "required": ["limit"],
            },
            func=fake_tool,
        )
    )

    client = FakeOpenAIClient(
        [
            # Turn 1: a single tool call, arguments split across two fragments.
            [
                {
                    "type": "tool_call_delta",
                    "index": 0,
                    "id": "call_abc",
                    "name": "test_tool",
                    "arguments_fragment": '{"lim',
                },
                {
                    "type": "tool_call_delta",
                    "index": 0,
                    "id": None,
                    "name": None,
                    "arguments_fragment": 'it": 3}',
                },
                {"type": "done"},
            ],
            # Turn 2: model replies with plain text after seeing the tool result.
            [
                {"type": "text_delta", "content": "Done!"},
                {"type": "done"},
            ],
        ]
    )
    received = []
    messages = [{"role": "user", "content": "please call the tool"}]

    result = run_agent_turn(
        messages=messages,
        tools=test_registry.openai_tools_schema(),
        client=client,
        cancel_event=threading.Event(),
        on_event=received.append,
    )

    assert result == "Done!"
    assert recorded_kwargs == [{"limit": 3}]
    assert len(client.calls) == 2

    tool_call_done_events = [e for e in received if e["type"] == "tool_call_done"]
    assert tool_call_done_events == [
        {
            "type": "tool_call_done",
            "index": 0,
            "id": "call_abc",
            "name": "test_tool",
            "arguments": {"limit": 3},
        }
    ]

    assistant_message = messages[-2]
    assert assistant_message["role"] == "assistant"
    assert assistant_message["tool_calls"][0]["id"] == "call_abc"
    assert assistant_message["tool_calls"][0]["function"]["name"] == "test_tool"

    tool_message = messages[-1]
    assert tool_message["role"] == "tool"
    assert tool_message["tool_call_id"] == "call_abc"
    assert json.loads(tool_message["content"]) == {"result": "ok", "limit": 3}


def test_tool_error_is_caught_and_fed_back_as_tool_result(test_registry):
    def failing_tool(**kwargs):
        raise ValueError("boom")

    test_registry.register(
        ToolSpec(
            name="failing_tool",
            description="A tool that always raises.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=failing_tool,
        )
    )

    client = FakeOpenAIClient(
        [
            [
                {
                    "type": "tool_call_delta",
                    "index": 0,
                    "id": "call_1",
                    "name": "failing_tool",
                    "arguments_fragment": "{}",
                },
                {"type": "done"},
            ],
            [
                {"type": "text_delta", "content": "I saw the error."},
                {"type": "done"},
            ],
        ]
    )
    messages = [{"role": "user", "content": "call the failing tool"}]

    result = run_agent_turn(
        messages=messages,
        tools=test_registry.openai_tools_schema(),
        client=client,
        cancel_event=threading.Event(),
    )

    # Must not raise -- the model gets to see and react to the failure.
    assert result == "I saw the error."
    assert len(client.calls) == 2

    tool_message = messages[-1]
    assert tool_message["role"] == "tool"
    payload = json.loads(tool_message["content"])
    assert "error" in payload
    assert "boom" in payload["error"]


def test_unknown_tool_name_is_also_fed_back_as_tool_result(test_registry):
    client = FakeOpenAIClient(
        [
            [
                {
                    "type": "tool_call_delta",
                    "index": 0,
                    "id": "call_1",
                    "name": "does_not_exist",
                    "arguments_fragment": "{}",
                },
                {"type": "done"},
            ],
            [
                {"type": "text_delta", "content": "ok"},
                {"type": "done"},
            ],
        ]
    )
    messages = [{"role": "user", "content": "call a bogus tool"}]

    result = run_agent_turn(
        messages=messages, tools=[], client=client, cancel_event=threading.Event()
    )

    assert result == "ok"
    payload = json.loads(messages[-1]["content"])
    assert "error" in payload


def test_tool_round_text_is_not_duplicated_when_caller_appends_result(test_registry):
    """Regression test for a real bug found by review: a tool-calling round's
    narration text was persisted into `messages` by `_dispatch_tool_calls`
    *and* re-included in the aggregate return value, so a caller that
    appends `result` (as `chat_panel.py` genuinely does) duplicated it.
    """

    def note_tool(**kwargs):
        return {"ok": True}

    test_registry.register(
        ToolSpec(
            name="note_tool",
            description="A no-op tool.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=note_tool,
        )
    )

    client = FakeOpenAIClient(
        [
            # Round 1: narrates, then calls a tool.
            [
                {"type": "text_delta", "content": "Let me check that. "},
                {
                    "type": "tool_call_delta",
                    "index": 0,
                    "id": "call_1",
                    "name": "note_tool",
                    "arguments_fragment": "{}",
                },
                {"type": "done"},
            ],
            # Round 2: final plain-text answer, no more tool calls.
            [
                {"type": "text_delta", "content": "All good."},
                {"type": "done"},
            ],
        ]
    )
    messages = [{"role": "user", "content": "please check"}]

    result = run_agent_turn(
        messages=messages,
        tools=test_registry.openai_tools_schema(),
        client=client,
        cancel_event=threading.Event(),
    )

    # Only round 2's text should come back for the caller to append --
    # round 1's narration is already in `messages` via _dispatch_tool_calls.
    assert result == "All good."

    # Simulate the real caller pattern (chat_panel.py._run_turn_sync).
    if result:
        messages.append({"role": "assistant", "content": result})

    occurrences = sum(
        1
        for m in messages
        if isinstance(m.get("content"), str) and "Let me check that." in m["content"]
    )
    assert occurrences == 1, (
        "round 1's narration text must appear exactly once in the final "
        f"message history, found {occurrences} times: {messages}"
    )


def test_cancel_mid_multi_tool_dispatch_leaves_every_tool_call_answered(test_registry):
    """Regression test for a real bug found by review: cancelling between two
    tool dispatches in the same round left the later tool_call_id with no
    matching tool-role response, which a real OpenAI-compatible backend
    rejects (400) on the very next turn.
    """
    cancel_event = threading.Event()
    tool_b_called = []

    def tool_a(**kwargs):
        cancel_event.set()  # simulates the user hitting Ctrl+X mid-dispatch
        return {"ok": True}

    def tool_b(**kwargs):
        tool_b_called.append(True)
        return {"ok": True}

    test_registry.register(
        ToolSpec(
            name="tool_a",
            description="First tool; triggers cancellation.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=tool_a,
        )
    )
    test_registry.register(
        ToolSpec(
            name="tool_b",
            description="Second tool; must not run once cancelled.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=tool_b,
        )
    )

    client = FakeOpenAIClient(
        [
            [
                {
                    "type": "tool_call_delta",
                    "index": 0,
                    "id": "call_a",
                    "name": "tool_a",
                    "arguments_fragment": "{}",
                },
                {
                    "type": "tool_call_delta",
                    "index": 1,
                    "id": "call_b",
                    "name": "tool_b",
                    "arguments_fragment": "{}",
                },
                {"type": "done"},
            ],
        ]
    )
    messages = [{"role": "user", "content": "call both tools"}]

    run_agent_turn(
        messages=messages,
        tools=test_registry.openai_tools_schema(),
        client=client,
        cancel_event=cancel_event,
    )

    assert tool_b_called == [], "tool_b must not run once cancelled mid-dispatch"

    assistant_msg = next(m for m in messages if m.get("role") == "assistant")
    declared_ids = {tc["id"] for tc in assistant_msg["tool_calls"]}
    answered_ids = {m["tool_call_id"] for m in messages if m.get("role") == "tool"}
    assert (
        declared_ids == answered_ids == {"call_a", "call_b"}
    ), "every declared tool_call_id must have a matching tool-role response"

    call_b_response = next(m for m in messages if m.get("tool_call_id") == "call_b")
    assert "cancelled" in json.loads(call_b_response["content"])["error"]


def test_cancel_event_stops_early_with_partial_text(test_registry):
    cancel_event = threading.Event()

    def scripted_events():
        yield {"type": "text_delta", "content": "Hello"}
        cancel_event.set()
        yield {"type": "text_delta", "content": ", world"}
        yield {"type": "done"}

    class OneShotClient:
        def __init__(self):
            self.calls = 0

        def chat(self, messages, tools=None, stream=True):
            self.calls += 1
            return scripted_events()

    client = OneShotClient()
    messages = [{"role": "user", "content": "hi"}]

    result = run_agent_turn(
        messages=messages, tools=[], client=client, cancel_event=cancel_event
    )

    assert result == "Hello"
    assert client.calls == 1


def test_cancel_event_set_before_call_returns_immediately(test_registry):
    cancel_event = threading.Event()
    cancel_event.set()

    class ShouldNotBeCalledClient:
        def chat(self, messages, tools=None, stream=True):
            raise AssertionError("chat() should not be called once already cancelled")

    result = run_agent_turn(
        messages=[{"role": "user", "content": "hi"}],
        tools=[],
        client=ShouldNotBeCalledClient(),
        cancel_event=cancel_event,
    )

    assert result == ""


def test_current_turn_context_available_during_turn_and_cleared_after(test_registry):
    seen = {}

    def tool_that_reads_context(**kwargs):
        ctx = loop_module.get_current_turn_context()
        seen["context"] = ctx
        return "ok"

    test_registry.register(
        ToolSpec(
            name="context_probe",
            description="Reads the active turn context.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=tool_that_reads_context,
        )
    )

    client = FakeOpenAIClient(
        [
            [
                {
                    "type": "tool_call_delta",
                    "index": 0,
                    "id": "call_1",
                    "name": "context_probe",
                    "arguments_fragment": "{}",
                },
                {"type": "done"},
            ],
            [{"type": "text_delta", "content": "done"}, {"type": "done"}],
        ]
    )
    cancel_event = threading.Event()

    assert loop_module.get_current_turn_context() is None

    run_agent_turn(
        messages=[{"role": "user", "content": "hi"}],
        tools=test_registry.openai_tools_schema(),
        client=client,
        cancel_event=cancel_event,
    )

    assert seen["context"] == (client, cancel_event, None)
    assert loop_module.get_current_turn_context() is None


def test_tool_execution_error_is_a_normal_exception_subclass():
    # Sanity check relied on implicitly by loop.py's broad except Exception:
    # ToolExecutionError must be an Exception subclass, or the catch-all in
    # _dispatch_one would not cover it.
    assert issubclass(ToolExecutionError, Exception)


# -- Tool-permission gate: resolve_tool_policy consulted before dispatch -----


def _single_tool_call_then_text(tool_name, final_text="done", call_id="call_1"):
    """Two scripted .chat() rounds: one tool call, then a plain-text reply."""
    return [
        [
            {
                "type": "tool_call_delta",
                "index": 0,
                "id": call_id,
                "name": tool_name,
                "arguments_fragment": "{}",
            },
            {"type": "done"},
        ],
        [{"type": "text_delta", "content": final_text}, {"type": "done"}],
    ]


def test_read_only_tool_runs_and_approve_is_never_called(
    test_registry, permission_store
):
    func_calls = []

    def read_only_tool(**kwargs):
        func_calls.append("ran")
        return {"ok": True}

    test_registry.register(
        ToolSpec(
            name="read_only_tool",
            description="A read-only tool.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=read_only_tool,
            risk=RiskTier.READ_ONLY,
        )
    )

    approve_calls = []

    def approve(spec, arguments):
        approve_calls.append((spec, arguments))
        return "once"

    client = FakeOpenAIClient(_single_tool_call_then_text("read_only_tool"))

    result = run_agent_turn(
        messages=[{"role": "user", "content": "hi"}],
        tools=test_registry.openai_tools_schema(),
        client=client,
        cancel_event=threading.Event(),
        approve=approve,
    )

    assert result == "done"
    assert func_calls == ["ran"]
    assert approve_calls == []


def test_ask_policy_tool_refuses_on_decline_and_persists_never(
    test_registry, permission_store
):
    func_calls = []

    def reversible_tool(**kwargs):
        func_calls.append("ran")
        return {"ok": True}

    test_registry.register(
        ToolSpec(
            name="reversible_tool",
            description="A reversible tool needing confirmation.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=reversible_tool,
            risk=RiskTier.REVERSIBLE,
        )
    )

    client = FakeOpenAIClient(_single_tool_call_then_text("reversible_tool"))
    messages = [{"role": "user", "content": "hi"}]

    run_agent_turn(
        messages=messages,
        tools=test_registry.openai_tools_schema(),
        client=client,
        cancel_event=threading.Event(),
        approve=lambda spec, arguments: "decline",
    )

    assert func_calls == [], "declined tool must never reach registry.dispatch"
    tool_message = next(m for m in messages if m.get("role") == "tool")
    payload = json.loads(tool_message["content"])
    assert "error" in payload
    assert permission_store.is_never("reversible_tool")
    assert not permission_store.is_allowed("reversible_tool")


def test_cancelled_approve_refuses_but_does_not_persist(
    test_registry, permission_store
):
    func_calls = []

    def reversible_tool(**kwargs):
        func_calls.append("ran")
        return {"ok": True}

    test_registry.register(
        ToolSpec(
            name="reversible_tool",
            description="A reversible tool needing confirmation.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=reversible_tool,
            risk=RiskTier.REVERSIBLE,
        )
    )

    client = FakeOpenAIClient(_single_tool_call_then_text("reversible_tool"))
    messages = [{"role": "user", "content": "hi"}]

    run_agent_turn(
        messages=messages,
        tools=test_registry.openai_tools_schema(),
        client=client,
        cancel_event=threading.Event(),
        approve=lambda spec, arguments: "cancelled",
    )

    assert func_calls == []
    tool_message = next(m for m in messages if m.get("role") == "tool")
    payload = json.loads(tool_message["content"])
    assert "error" in payload
    assert not permission_store.is_never(
        "reversible_tool"
    ), "a cancelled wait must not be conflated with an explicit decline"
    assert not permission_store.is_allowed("reversible_tool")


def test_ask_policy_tool_refuses_safely_when_approve_is_none(
    test_registry, permission_store
):
    func_calls = []

    def reversible_tool(**kwargs):
        func_calls.append("ran")
        return {"ok": True}

    test_registry.register(
        ToolSpec(
            name="reversible_tool",
            description="A reversible tool needing confirmation.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=reversible_tool,
            risk=RiskTier.REVERSIBLE,
        )
    )

    client = FakeOpenAIClient(_single_tool_call_then_text("reversible_tool"))
    messages = [{"role": "user", "content": "hi"}]

    # approve intentionally omitted -- defaults to None, i.e. no UI available.
    run_agent_turn(
        messages=messages,
        tools=test_registry.openai_tools_schema(),
        client=client,
        cancel_event=threading.Event(),
    )

    assert func_calls == []
    tool_message = next(m for m in messages if m.get("role") == "tool")
    payload = json.loads(tool_message["content"])
    assert "error" in payload
    assert "no UI is available" in payload["error"]


def test_approve_raising_is_caught_and_fed_back_as_tool_result(
    test_registry, permission_store
):
    func_calls = []

    def reversible_tool(**kwargs):
        func_calls.append("ran")
        return {"ok": True}

    test_registry.register(
        ToolSpec(
            name="reversible_tool",
            description="A reversible tool needing confirmation.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=reversible_tool,
            risk=RiskTier.REVERSIBLE,
        )
    )

    def approve(spec, arguments):
        raise RuntimeError("approve blew up")

    client = FakeOpenAIClient(_single_tool_call_then_text("reversible_tool"))
    messages = [{"role": "user", "content": "hi"}]

    result = run_agent_turn(
        messages=messages,
        tools=test_registry.openai_tools_schema(),
        client=client,
        cancel_event=threading.Event(),
        approve=approve,
    )

    # Must not raise -- the turn completes normally, same contract as an
    # ordinary tool bug already caught by registry.dispatch's try/except.
    assert result == "done"
    assert func_calls == []
    tool_message = next(m for m in messages if m.get("role") == "tool")
    payload = json.loads(tool_message["content"])
    assert "error" in payload
    assert "approve blew up" in payload["error"]


def test_always_persists_and_second_call_same_turn_skips_approve(
    test_registry, permission_store
):
    func_calls = []

    def reversible_tool(**kwargs):
        func_calls.append("ran")
        return {"ok": True}

    test_registry.register(
        ToolSpec(
            name="reversible_tool",
            description="A reversible tool needing confirmation.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=reversible_tool,
            risk=RiskTier.REVERSIBLE,
        )
    )

    approve_calls = []

    def approve(spec, arguments):
        approve_calls.append((spec, arguments))
        return "always"

    client = FakeOpenAIClient(
        [
            [
                {
                    "type": "tool_call_delta",
                    "index": 0,
                    "id": "call_1",
                    "name": "reversible_tool",
                    "arguments_fragment": "{}",
                },
                {"type": "done"},
            ],
            [
                {
                    "type": "tool_call_delta",
                    "index": 0,
                    "id": "call_2",
                    "name": "reversible_tool",
                    "arguments_fragment": "{}",
                },
                {"type": "done"},
            ],
            [{"type": "text_delta", "content": "done"}, {"type": "done"}],
        ]
    )

    result = run_agent_turn(
        messages=[{"role": "user", "content": "hi"}],
        tools=test_registry.openai_tools_schema(),
        client=client,
        cancel_event=threading.Event(),
        approve=approve,
    )

    assert result == "done"
    assert func_calls == ["ran", "ran"]
    assert len(approve_calls) == 1, (
        "the second call to the same tool within this turn must resolve to "
        "'allowed' via the now-persisted store entry, without asking again"
    )
    assert permission_store.is_allowed("reversible_tool")


def test_can_remember_choice_false_still_asks_despite_prior_allowed_entry(
    test_registry, permission_store
):
    # Simulates a stale/pre-existing "allowed" entry under this tool's name
    # (e.g. left over from a prior test/run before the tool was marked
    # can_remember_choice=False).
    permission_store.mark_allowed("arg_sensitive_tool")

    func_calls = []

    def arg_sensitive_tool(**kwargs):
        func_calls.append("ran")
        return {"ok": True}

    test_registry.register(
        ToolSpec(
            name="arg_sensitive_tool",
            description="A tool whose risk lives in its arguments.",
            parameters={"type": "object", "properties": {}, "required": []},
            func=arg_sensitive_tool,
            risk=RiskTier.CONSEQUENTIAL,
            can_remember_choice=False,
        )
    )

    approve_calls = []

    def approve(spec, arguments):
        approve_calls.append((spec, arguments))
        return "once"

    client = FakeOpenAIClient(_single_tool_call_then_text("arg_sensitive_tool"))

    result = run_agent_turn(
        messages=[{"role": "user", "content": "hi"}],
        tools=test_registry.openai_tools_schema(),
        client=client,
        cancel_event=threading.Event(),
        approve=approve,
    )

    assert result == "done"
    assert func_calls == ["ran"]
    assert len(approve_calls) == 1, (
        "can_remember_choice=False must always ask, even against a stored "
        "'allowed' entry under the same name"
    )
