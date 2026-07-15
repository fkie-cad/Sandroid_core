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
from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.loop import run_agent_turn
from sandroid.ai.tools.registry import ToolRegistry, ToolSpec


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

    assert seen["context"] == (client, cancel_event)
    assert loop_module.get_current_turn_context() is None


def test_tool_execution_error_is_a_normal_exception_subclass():
    # Sanity check relied on implicitly by loop.py's broad except Exception:
    # ToolExecutionError must be an Exception subclass, or the catch-all in
    # _dispatch_one would not cover it.
    assert issubclass(ToolExecutionError, Exception)
