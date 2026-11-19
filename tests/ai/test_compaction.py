"""Tests for sandroid.ai.compaction: token meter, masking, summary compaction."""

import copy
import json
from types import SimpleNamespace

import pytest

from sandroid.ai.client import Usage
from sandroid.ai.compaction import (
    MASK_MIN_CLEAR_TOKENS,
    REASONING_ELIDED,
    SUMMARY_HEADINGS,
    TokenMeter,
    cited_ids,
    compact_now,
    find_result_id,
    is_marker_message,
    is_summary_message,
    make_stub,
    messages_chars,
    prepare,
)

TOOLS = [{"type": "function", "function": {"name": "get_state", "parameters": {}}}]


def _cfg(**overrides):
    values = {
        "mask_at": 0.50,
        "keep_recent_results": 10,
        "summarize_at": 0.85,
        "summary_keep_tokens": 40_000,
        "output_reserve_tokens": 32_000,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _result(rid: int, chars: int) -> str:
    return json.dumps({"data": "x" * chars, "_rid": f"R{rid}"})


def _turn(n: int, *, result_chars: int = 100, tool: str = "get_state", reasoning=""):
    """One user turn: user, assistant tool call, tool reply, final answer."""
    call_id = f"call_{n}"
    return [
        {"role": "user", "content": f"question {n}"},
        {
            "role": "assistant",
            "content": "",
            "reasoning_content": reasoning,
            "tool_calls": [
                {
                    "id": call_id,
                    "type": "function",
                    "function": {"name": tool, "arguments": json.dumps({"n": n})},
                }
            ],
        },
        {"role": "tool", "tool_call_id": call_id, "content": _result(n, result_chars)},
        {"role": "assistant", "content": f"answer {n}", "reasoning_content": reasoning},
    ]


def _conversation(turns: int, **kwargs) -> list[dict]:
    messages = [{"role": "system", "content": "You are Sandroid."}]
    for n in range(1, turns + 1):
        messages.extend(_turn(n, **kwargs))
    return messages


def _tool_pairs_intact(messages: list[dict]) -> bool:
    """Every tool reply directly follows its assistant call group."""
    pending: set[str] = set()
    for msg in messages:
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            if pending:
                return False
            pending = {c["id"] for c in msg["tool_calls"]}
        elif msg.get("role") == "tool":
            if msg.get("tool_call_id") not in pending:
                return False
            pending.discard(msg["tool_call_id"])
        elif pending:
            return False
    return not pending


# ---------------------------------------------------------------------------
# TokenMeter
# ---------------------------------------------------------------------------


def test_meter_calibrates_ratio_as_running_average():
    meter = TokenMeter(window=100_000, output_reserve=10_000)
    assert meter.chars_per_token == pytest.approx(3.5)
    meter.update_from_usage(Usage(prompt_tokens=1000), 4000, tools=[])
    assert meter.chars_per_token == pytest.approx(4.0)
    meter.update_from_usage(Usage(prompt_tokens=1000), 3000, tools=[])
    assert meter.chars_per_token == pytest.approx(3.5)
    # Zero usage is ignored.
    meter.update_from_usage(Usage(prompt_tokens=0), 9999, tools=[])
    assert meter.chars_per_token == pytest.approx(3.5)
    assert meter.last_prompt_tokens == 1000


def test_meter_uses_tools_from_last_estimate_for_calibration():
    meter = TokenMeter(window=100_000, output_reserve=10_000)
    messages = [{"role": "user", "content": "a" * 1000}]
    meter.estimate(messages, TOOLS)
    tools_len = len(json.dumps(TOOLS, sort_keys=True))
    meter.update_from_usage(Usage(prompt_tokens=300), messages_chars(messages))
    expected = (messages_chars(messages) + tools_len) / 300
    assert meter.chars_per_token == pytest.approx(expected)


def test_meter_estimate_adds_local_estimate_to_ground_truth():
    meter = TokenMeter(window=100_000, output_reserve=10_000)
    messages = _conversation(1)
    meter.update_from_usage(
        Usage(prompt_tokens=5000, completion_tokens=300, reasoning_tokens=200),
        messages_chars(messages),
        tools=TOOLS,
    )
    assert meter.estimate(messages, TOOLS) == 5000
    assert meter.used == 5000
    appended = [
        *messages,
        {"role": "assistant", "content": "x" * 70, "reasoning_content": "think"},
        {"role": "user", "content": "y" * 700},
    ]
    user_tokens = meter.local_tokens(messages_chars([appended[-1]]))
    # The replayed assistant message counts as the server's completion tokens.
    assert meter.estimate(appended, TOOLS) == 5000 + 300 + user_tokens
    # Without echoed reasoning, the reasoning tokens are not replayed.
    no_reasoning = [*messages, {"role": "assistant", "content": "x" * 70}]
    assert meter.estimate(no_reasoning, TOOLS) == 5000 + 100


def test_meter_falls_back_to_full_local_estimate_when_prefix_changed():
    meter = TokenMeter(window=100_000, output_reserve=10_000)
    messages = _conversation(2)
    meter.update_from_usage(Usage(prompt_tokens=5000), messages_chars(messages))
    changed = copy.deepcopy(messages)
    changed[2]["reasoning_content"] = "different length reasoning"
    expected = meter.local_tokens(
        messages_chars(changed) + len(json.dumps(TOOLS, sort_keys=True))
    )
    assert meter.estimate(changed, TOOLS) == expected


def test_meter_percent_window_and_breakdown():
    meter = TokenMeter(window=200_000, output_reserve=32_000)
    assert meter.window == 200_000
    assert meter.input_limit == 168_000
    messages = [
        {"role": "system", "content": "s" * 3500},
        {"role": "system", "content": "a" * 700},
        {"role": "user", "content": "[Summary #1 of earlier conversation]" + "z" * 700},
        {"role": "user", "content": "u" * 700},
        {"role": "assistant", "content": "c", "reasoning_content": "r" * 1400},
        {"role": "tool", "tool_call_id": "t", "content": _result(1, 7000)},
    ]
    meter.update_from_usage(Usage(prompt_tokens=50_000), messages_chars(messages))
    parts = meter.breakdown(messages, TOOLS)
    assert set(parts) == {
        "system",
        "tools_schema",
        "ambient",
        "history",
        "tool_results",
        "summaries",
        "reasoning",
    }
    assert sum(parts.values()) == 50_000
    assert parts["tool_results"] > parts["system"] > parts["reasoning"]
    assert parts["reasoning"] > parts["ambient"] > 0
    assert parts["summaries"] > 0
    assert parts["tools_schema"] > 0
    assert meter.percent == pytest.approx(25.0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_find_result_id_variants():
    assert find_result_id(json.dumps({"a": 1, "_rid": "R17"})) == "R17"
    preview = {"truncated": True, "result_id": "R4", "bytes": 10}
    assert find_result_id(json.dumps(preview)) == "R4"
    assert find_result_id(make_stub("R9", "t", "x")) == "R9"
    # read_result output: the outer _rid wins over the inner result_id.
    nested = json.dumps({"result_id": "R2", "tool": "x", "_rid": "R30"})
    assert find_result_id(nested) == "R30"
    assert find_result_id('broken json "_rid": "R5" …') == "R5"
    assert find_result_id("no id here") is None


def test_cited_ids():
    assert cited_ids("see R17 and #123, also (R2); not RX1 or ##") == {
        "R17",
        "R2",
        "#123",
    }


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------

BIG = 20_000  # chars per tool result (~5.7k tokens)


def _masking_setup(turns=16, window=200_000, **kwargs):
    messages = _conversation(turns, result_chars=BIG, **kwargs)
    meter = TokenMeter(window=window, output_reserve=32_000)
    return messages, meter


def test_mask_below_threshold_does_nothing():
    messages, meter = _masking_setup(turns=4)
    result = prepare(messages, TOOLS, meter, _cfg(), summarize=None, valid_ids=None)
    assert not result.changed
    assert result.events == []
    assert result.messages == messages
    assert result.messages is not messages


def test_mask_keeps_last_n_results_and_stubs_older():
    messages, meter = _masking_setup(turns=20)
    before = copy.deepcopy(messages)
    assert meter.estimate(messages, TOOLS) >= 100_000
    result = prepare(messages, TOOLS, meter, _cfg(), summarize=None, valid_ids=None)
    assert result.changed
    assert messages == before  # input untouched
    tool_msgs = [m for m in result.messages if m["role"] == "tool"]
    stubs = [m for m in tool_msgs if '"elided"' in m["content"]]
    assert len(stubs) == 10
    assert all('"elided"' not in m["content"] for m in tool_msgs[-10:])
    stub = json.loads(tool_msgs[0]["content"])
    assert stub["elided"] == "R1"
    assert stub["tool"] == "get_state"
    assert stub["note"] == "content moved to disk, not empty — read_result('R1')"
    assert len(stub["one_line"]) <= 100
    # Tool inputs are kept.
    calls = [m for m in result.messages if m.get("tool_calls")]
    assert calls == [m for m in messages if m.get("tool_calls")]
    (event,) = result.events
    assert event["type"] == "compaction"
    assert event["kind"] == "mask"
    assert event["ids"] == [f"R{n}" for n in range(1, 11)]
    assert event["tokens_before"] - event["tokens_after"] >= MASK_MIN_CLEAR_TOKENS
    assert _tool_pairs_intact(result.messages)


def test_mask_is_byte_stable():
    messages, meter = _masking_setup(turns=20)
    first = prepare(messages, TOOLS, meter, _cfg(), summarize=None, valid_ids=None)
    second = prepare(
        messages,
        TOOLS,
        TokenMeter(window=200_000, output_reserve=32_000),
        _cfg(),
        summarize=None,
        valid_ids=None,
    )
    assert json.dumps(first.messages) == json.dumps(second.messages)
    # Re-masking the masked output leaves the stubs byte-identical.
    grown = first.messages + _turn(21, result_chars=BIG * 6)
    third = prepare(
        grown,
        TOOLS,
        TokenMeter(window=200_000, output_reserve=32_000),
        _cfg(),
        summarize=None,
        valid_ids=None,
    )
    old_stubs = [m["content"] for m in first.messages if m["role"] == "tool"][:10]
    new_stubs = [m["content"] for m in third.messages if m["role"] == "tool"][:10]
    assert old_stubs == new_stubs
    assert make_stub("R1", "t", "x") == make_stub("R1", "t", "x")


def test_mask_elides_old_reasoning_only():
    messages, meter = _masking_setup(turns=20, reasoning="r" * 2000)
    result = prepare(messages, TOOLS, meter, _cfg(), summarize=None, valid_ids=None)
    assistants = [m for m in result.messages if m["role"] == "assistant"]
    assert all(m["reasoning_content"] == REASONING_ELIDED for m in assistants[:-10])
    assert all(m["reasoning_content"] == "r" * 2000 for m in assistants[-10:])


def test_mask_requires_30k_tokens_cleared():
    # Many small results: masking would clear far less than 30k tokens.
    messages = _conversation(30, result_chars=500)
    messages.insert(1, {"role": "user", "content": "p" * 400_000})
    meter = TokenMeter(window=200_000, output_reserve=32_000)
    assert meter.estimate(messages, TOOLS) >= 100_000
    result = prepare(messages, TOOLS, meter, _cfg(), summarize=None, valid_ids=None)
    assert not result.changed
    assert result.events == []


def test_mask_hysteresis():
    # mask_at = 60k; summaries effectively off (0.99, tiny output reserve).
    messages, _ = _masking_setup(turns=20)
    meter = TokenMeter(window=120_000, output_reserve=1000)
    cfg = _cfg(summarize_at=0.99)
    first = prepare(messages, TOOLS, meter, cfg, summarize=None, valid_ids=None)
    assert first.events[0]["trigger"] == "threshold"
    level = meter.state.mask_level
    assert level == first.events[0]["tokens_after"]
    # Back over mask_at, < 30k above the post-mask level, and R11/R12 have
    # become maskable: no new pass.
    grown = first.messages + _turn(21, result_chars=BIG) + _turn(22, result_chars=BIG)
    estimate = meter.estimate(grown, TOOLS)
    assert 60_000 <= estimate < level + MASK_MIN_CLEAR_TOKENS
    second = prepare(grown, TOOLS, meter, cfg, summarize=None, valid_ids=None)
    assert not second.changed
    # Grow by >= 30k tokens beyond the post-mask level: masks again.
    more = list(grown)
    for n in range(23, 30):
        more += _turn(n, result_chars=BIG)
    assert meter.estimate(more, TOOLS) >= level + MASK_MIN_CLEAR_TOKENS
    third = prepare(more, TOOLS, meter, cfg, summarize=None, valid_ids=None)
    assert third.changed
    assert third.events[0]["ids"][0] == "R11"
    # The stubs of the first pass are byte-identical in the second pass.
    old = [m["content"] for m in first.messages if m["role"] == "tool"][:10]
    assert [m["content"] for m in third.messages if m["role"] == "tool"][:10] == old


def test_mask_exempts_recent_read_result():
    messages, meter = _masking_setup(turns=20)
    # Turns 19/20 use read_result (recent rounds; 20 via call_tool) and so
    # does turn 1 (old). keep_recent_results=0, so only the exemption keeps
    # results.
    for msg in messages:
        if msg.get("tool_calls") and msg["tool_calls"][0]["id"] == "call_19":
            msg["tool_calls"][0]["function"]["name"] = "read_result"
        if msg.get("tool_calls") and msg["tool_calls"][0]["id"] == "call_20":
            msg["tool_calls"][0]["function"] = {
                "name": "call_tool",
                "arguments": json.dumps({"name": "read_result", "arguments": {}}),
            }
        if msg.get("tool_calls") and msg["tool_calls"][0]["id"] == "call_1":
            msg["tool_calls"][0]["function"]["name"] = "read_result"
    cfg = _cfg(keep_recent_results=0)
    result = prepare(messages, TOOLS, meter, cfg, summarize=None, valid_ids=None)
    by_call = {m["tool_call_id"]: m for m in result.messages if m["role"] == "tool"}
    assert '"elided"' not in by_call["call_19"]["content"]
    assert '"elided"' not in by_call["call_20"]["content"]
    # An old read_result round is not exempt.
    assert json.loads(by_call["call_1"]["content"])["tool"] == "read_result"
    assert '"elided"' in by_call["call_18"]["content"]


def test_mask_forced_when_over_summary_threshold_without_summariser():
    messages = _conversation(30, result_chars=500)
    messages.insert(1, {"role": "user", "content": "p" * 620_000})
    meter = TokenMeter(window=200_000, output_reserve=32_000)
    assert meter.estimate(messages, TOOLS) >= 170_000
    result = prepare(messages, TOOLS, meter, _cfg(), summarize=None, valid_ids=None)
    assert result.changed
    assert result.events[0]["kind"] == "mask"
    assert result.events[0]["trigger"] == "forced"


# ---------------------------------------------------------------------------
# Summary compaction
# ---------------------------------------------------------------------------

SUMMARY_WINDOW = 20_000


def _summary_setup(turns=12, ambient=True):
    """A conversation over 85% of a small window, with ambient blocks."""
    messages = [{"role": "system", "content": "You are Sandroid."}]
    for n in range(1, turns + 1):
        if ambient:
            messages.append({"role": "system", "content": f"Live state {n}"})
        messages.extend(_turn(n, result_chars=5000))
    meter = TokenMeter(window=SUMMARY_WINDOW, output_reserve=2000)
    cfg = _cfg(summary_keep_tokens=4000)
    assert meter.estimate(messages, TOOLS) >= 0.85 * SUMMARY_WINDOW
    return messages, meter, cfg


class FakeSummariser:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls: list[tuple[list[dict], str]] = []

    def __call__(self, prefix, instructions):
        self.calls.append((prefix, instructions))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def _good_summary(ids="R1 R2 #5"):
    return "\n".join(f"## {h}\n- see {ids}" for h in SUMMARY_HEADINGS)


def test_summary_cuts_at_turn_boundary_and_keeps_pairs():
    messages, meter, cfg = _summary_setup()
    before = copy.deepcopy(messages)
    fake = FakeSummariser(_good_summary())
    result = prepare(
        messages, TOOLS, meter, cfg, summarize=fake, valid_ids=lambda ids: ids
    )
    assert messages == before
    assert result.changed
    new = result.messages
    assert new[0] == messages[0]
    assert is_summary_message(new[1])
    assert new[1]["content"].startswith(
        "[Summary #1 of earlier conversation — cited evidence retrievable via "
        "read_result]"
    )
    # Tail starts with the ambient block of a turn, followed by its user msg.
    assert new[2]["role"] == "system"
    assert new[2]["content"].startswith("Live state")
    assert new[3]["role"] == "user"
    assert _tool_pairs_intact(new)
    tail = new[2:]
    assert tail == messages[len(messages) - len(tail) :]
    # The summariser got the exact prefix (with system[0]) before the tail.
    prefix, instructions = fake.calls[0]
    assert prefix == messages[: len(messages) - len(tail)]
    assert prefix[0] == messages[0]
    for heading in SUMMARY_HEADINGS:
        assert heading in instructions
    (event,) = result.events
    assert event["kind"] == "summary"
    assert event["summary_index"] == 1
    assert event["ids"] == ["R1", "R2", "#5"]
    assert event["tokens_after"] < event["tokens_before"]
    assert meter.state.summary_count == 1


def test_summary_validator_retries_once_with_errors():
    messages, meter, cfg = _summary_setup()
    fake = FakeSummariser(_good_summary("R1 R999"), _good_summary("R1"))
    result = prepare(
        messages,
        TOOLS,
        meter,
        cfg,
        summarize=fake,
        valid_ids=lambda ids: {i for i in ids if i != "R999"},
    )
    assert len(fake.calls) == 2
    assert "R999" in fake.calls[1][1]
    assert "rejected" in fake.calls[1][1]
    assert result.events[0]["kind"] == "summary"
    assert meter.state.consecutive_failures == 0


def test_summary_fallback_after_invalid_retry():
    messages, meter, cfg = _summary_setup()
    fake = FakeSummariser(_good_summary("R999"), _good_summary("R998"))
    result = prepare(
        messages, TOOLS, meter, cfg, summarize=fake, valid_ids=lambda ids: set()
    )
    assert len(fake.calls) == 2
    (event,) = result.events
    assert event["kind"] == "fallback"
    assert event["errors"]
    markers = [m for m in result.messages if is_marker_message(m)]
    assert len(markers) == 1
    assert markers[0]["role"] == "system"
    assert "moved to disk (summary unavailable); R-ids: R1–R" in markers[0]["content"]
    assert is_marker_message(result.messages[1])
    assert _tool_pairs_intact(result.messages)
    assert meter.estimate(result.messages, TOOLS) < 0.85 * SUMMARY_WINDOW
    assert meter.state.consecutive_failures == 1


def test_summary_exception_falls_back_without_retry():
    messages, meter, cfg = _summary_setup()
    fake = FakeSummariser(RuntimeError("gateway down"))
    result = prepare(messages, TOOLS, meter, cfg, summarize=fake, valid_ids=None)
    assert len(fake.calls) == 1
    assert result.events[0]["kind"] == "fallback"
    assert "gateway down" in result.events[0]["errors"][0]


def test_summary_previous_ids_must_survive():
    messages, meter, cfg = _summary_setup()
    previous = {
        "role": "user",
        "content": "[Summary #1 of earlier conversation — cited evidence "
        "retrievable via read_result]\n\n## Findings\n- token in R3 (#42)",
    }
    messages.insert(1, previous)
    fake = FakeSummariser(_good_summary("R1"), _good_summary("R1 R3 #42"))
    result = prepare(messages, TOOLS, meter, cfg, summarize=fake, valid_ids=None)
    assert len(fake.calls) == 2
    assert "R3" in fake.calls[1][1]
    assert "#42" in fake.calls[1][1]
    assert result.events[0]["summary_index"] == 2
    summaries = [m for m in result.messages if is_summary_message(m)]
    assert len(summaries) == 1
    assert summaries[0]["content"].startswith("[Summary #2 ")


def test_thrash_guard_disables_auto_summaries():
    messages, meter, cfg = _summary_setup()
    fake = FakeSummariser(RuntimeError("a"), RuntimeError("b"), _good_summary())
    first = prepare(messages, TOOLS, meter, cfg, summarize=fake, valid_ids=None)
    assert [e["kind"] for e in first.events] == ["fallback"]
    second = prepare(messages, TOOLS, meter, cfg, summarize=fake, valid_ids=None)
    assert [e["kind"] for e in second.events] == ["fallback", "compaction_disabled"]
    assert second.events[1]["type"] == "warning"
    assert meter.state.auto_summary_disabled
    third = prepare(messages, TOOLS, meter, cfg, summarize=fake, valid_ids=None)
    assert len(fake.calls) == 2  # no further summary attempts
    assert all(e["type"] != "warning" for e in third.events)
    # A manual compaction still works and re-enables auto summaries.
    manual = compact_now(messages, TOOLS, meter, cfg, summarize=fake, valid_ids=None)
    assert manual.events[0]["kind"] == "summary"
    assert not meter.state.auto_summary_disabled
    assert meter.state.consecutive_failures == 0


def test_would_not_fit_triggers_summary():
    messages, meter, cfg = _summary_setup()
    # Raise the threshold so only the fit check can trigger.
    cfg.summarize_at = 0.99
    meter = TokenMeter(window=SUMMARY_WINDOW, output_reserve=10_000)
    fake = FakeSummariser(_good_summary())
    result = prepare(messages, TOOLS, meter, cfg, summarize=fake, valid_ids=None)
    assert result.events[0]["kind"] == "summary"
    assert result.events[0]["trigger"] == "would_not_fit"


def test_no_input_mutation_anywhere():
    messages, meter, cfg = _summary_setup()
    for msg in messages:
        if msg["role"] == "assistant":
            msg["reasoning_content"] = "r" * 500
    snapshot = copy.deepcopy(messages)

    def mutating(prefix, instructions):
        prefix.clear()
        return _good_summary()

    prepare(messages, TOOLS, meter, cfg, summarize=mutating, valid_ids=None)
    compact_now(messages, TOOLS, meter, cfg, summarize=mutating, valid_ids=None)
    prepare(
        messages,
        TOOLS,
        meter,
        cfg,
        summarize=FakeSummariser(RuntimeError("x")),
        valid_ids=None,
    )
    big, big_meter = _masking_setup(turns=20, reasoning="r" * 2000)
    big_snapshot = copy.deepcopy(big)
    prepare(big, TOOLS, big_meter, _cfg(), summarize=None, valid_ids=None)
    assert messages == snapshot
    assert big == big_snapshot


def test_compact_now_with_focus_ignores_thresholds():
    messages = _conversation(6, result_chars=200)
    meter = TokenMeter(window=262_144, output_reserve=32_000)
    cfg = _cfg(summary_keep_tokens=100)
    fake = FakeSummariser(_good_summary("R1"))
    result = compact_now(
        messages,
        TOOLS,
        meter,
        cfg,
        summarize=fake,
        valid_ids=None,
        focus="the TLS pinning bypass",
    )
    assert "the TLS pinning bypass" in fake.calls[0][1]
    assert result.events[0]["kind"] == "summary"
    assert result.events[0]["trigger"] == "manual"
    assert result.messages[-4:] == messages[-4:]
    assert len(result.messages) == 2 + 4


def test_compact_now_nothing_to_compact():
    messages = _conversation(1)
    meter = TokenMeter(window=262_144, output_reserve=32_000)
    fake = FakeSummariser()
    result = compact_now(messages, TOOLS, meter, _cfg(), summarize=fake, valid_ids=None)
    assert not result.changed
    assert result.events[0]["kind"] == "compaction_noop"
    assert fake.calls == []
