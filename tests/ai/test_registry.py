"""Unit tests for sandroid.ai.tools.registry.

Every test builds its own fresh ToolRegistry() instance rather than using the
process-wide get_tool_registry() singleton, to stay isolated from the
tools registered as import-time side effects elsewhere in sandroid.ai
(app_query, device_query, subagents).
"""

import pytest

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools.registry import (
    RiskTier,
    ToolRegistry,
    ToolSpec,
    get_tool_registry,
)


def _make_spec(name="echo", func=None, **overrides):
    defaults = {
        "name": name,
        "description": "Echo the given value back.",
        "parameters": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
        },
        "func": func or (lambda value: value),
    }
    defaults.update(overrides)
    return ToolSpec(**defaults)


def test_register_and_schema_shape():
    registry = ToolRegistry()
    registry.register(_make_spec())

    schema = registry.openai_tools_schema()

    assert schema == [
        {
            "type": "function",
            "function": {
                "name": "echo",
                "description": "Echo the given value back.",
                "parameters": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                },
            },
        }
    ]


def test_dispatch_success_passes_kwargs_through():
    registry = ToolRegistry()
    calls = []

    def record(value):
        calls.append(value)
        return f"got:{value}"

    registry.register(_make_spec(func=record))

    result = registry.dispatch("echo", {"value": "hello"})

    assert result == "got:hello"
    assert calls == ["hello"]


def test_dispatch_unknown_tool_raises_tool_execution_error():
    registry = ToolRegistry()

    with pytest.raises(ToolExecutionError, match="echo"):
        registry.dispatch("echo", {})


def test_subset_filters_by_name():
    registry = ToolRegistry()
    registry.register(_make_spec(name="a"))
    registry.register(_make_spec(name="b"))
    registry.register(_make_spec(name="c"))

    subset = registry.subset(["a", "c"])
    names = {entry["function"]["name"] for entry in subset}

    assert names == {"a", "c"}
    assert len(subset) == 2


def test_subset_silently_skips_unregistered_names():
    registry = ToolRegistry()
    registry.register(_make_spec(name="a"))

    subset = registry.subset(["a", "does-not-exist"])

    assert [entry["function"]["name"] for entry in subset] == ["a"]


def test_register_overwrites_existing_name_without_raising():
    registry = ToolRegistry()
    registry.register(_make_spec(func=lambda value: "first"))
    registry.register(_make_spec(func=lambda value: "second"))

    assert registry.dispatch("echo", {"value": "x"}) == "second"
    assert len(registry.openai_tools_schema()) == 1


def test_default_risk_tier_is_read_only():
    spec = _make_spec()
    assert spec.risk == RiskTier.READ_ONLY


def test_default_can_remember_choice_is_true():
    spec = _make_spec()
    assert spec.can_remember_choice is True


def test_get_tool_registry_is_a_singleton():
    first = get_tool_registry()
    second = get_tool_registry()
    assert first is second


def test_get_spec_returns_the_registered_spec_without_executing_it():
    registry = ToolRegistry()
    calls = []
    spec = _make_spec(func=calls.append)
    registry.register(spec)

    found = registry.get_spec("echo")

    assert found is spec
    assert calls == []  # get_spec is a non-executing peek, unlike dispatch


def test_get_spec_returns_none_for_unregistered_name():
    registry = ToolRegistry()
    assert registry.get_spec("does-not-exist") is None
