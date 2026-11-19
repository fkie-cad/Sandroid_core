"""Unit tests for sandroid.ai.tools.registry.

Every test builds its own fresh ToolRegistry() instance rather than using the
process-wide get_tool_registry() singleton, to stay isolated from the
tools registered as import-time side effects elsewhere in sandroid.ai
(app_query, device_query).
"""

import pytest

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools.registry import (
    RiskTier,
    ToolError,
    ToolRegistry,
    ToolSpec,
    get_tool_registry,
    parse_tool_arguments,
    tools_schema_hash,
    validate_arguments,
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


# ---------------------------------------------------------------------------
# Validation, structured errors, exposure (AI foundations WP2)
# ---------------------------------------------------------------------------


def _rich_spec(**overrides):
    overrides.setdefault("func", lambda **kw: kw)
    return _make_spec(
        name="rich",
        parameters={
            "type": "object",
            "properties": {
                "pkg": {"type": "string", "description": "Package."},
                "mode": {
                    "type": "string",
                    "enum": ["attach", "spawn"],
                    "description": "Mode.",
                },
                "pids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Pids.",
                },
            },
            "required": ["pkg"],
        },
        **overrides,
    )


def test_tool_error_is_a_tool_execution_error_with_structured_payload():
    err = ToolError("not_loaded", "x is not loaded", retryable=True, hint="search")
    assert isinstance(err, ToolExecutionError)
    assert err.to_dict() == {
        "error": {
            "code": "not_loaded",
            "message": "x is not loaded",
            "retryable": True,
            "hint": "search",
        }
    }
    with pytest.raises(ValueError, match="unknown tool error code"):
        ToolError("bogus", "m")


@pytest.mark.parametrize(
    ("args", "fragment"),
    [
        ({}, "missing required argument(s): pkg"),
        ({"pkg": "a", "extra": 1}, "unknown argument(s): extra"),
        ({"pkg": 3}, "must be of type string"),
        ({"pkg": "a", "mode": "fork"}, "must be one of ['attach', 'spawn']"),
        ({"pkg": "a", "pids": [1, "2"]}, "items must be of type integer"),
        ({"pkg": True}, "must be of type string"),
    ],
)
def test_validate_arguments_reports_structured_invalid_arguments(args, fragment):
    err = validate_arguments(_rich_spec(), args)
    assert err is not None
    assert err.code == "invalid_arguments"
    assert fragment in err.message
    assert err.to_dict()["error"]["valid_parameters"] == ["mode", "pids", "pkg"]


def test_validate_arguments_accepts_valid_and_rejects_non_dict():
    assert validate_arguments(_rich_spec(), {"pkg": "a", "mode": "spawn"}) is None
    err = validate_arguments(_rich_spec(), ["pkg"])
    assert err is not None
    assert err.code == "invalid_arguments"
    assert "JSON object" in err.message


def test_additional_properties_true_allows_unknown_keys():
    spec = _make_spec(
        parameters={"type": "object", "properties": {}, "additionalProperties": True}
    )
    assert validate_arguments(spec, {"anything": 1}) is None


def test_dispatch_raises_tool_error_before_calling_the_tool():
    registry = ToolRegistry()
    calls = []
    registry.register(_rich_spec(func=lambda **kw: calls.append(kw)))
    with pytest.raises(ToolError) as info:
        registry.dispatch("rich", {"pkg": "a", "bogus": 1})
    assert info.value.code == "invalid_arguments"
    with pytest.raises(ToolError) as info:
        registry.dispatch("nope", {})
    assert info.value.code == "unknown_tool"
    assert calls == []


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, {}),
        ("", {}),
        ({"a": 1}, {"a": 1}),
        ('{"a": 1}', {"a": 1}),
        ('```json\n{"a": 1,}\n```', {"a": 1}),
        ('{"a": [1, 2,],}', {"a": [1, 2]}),
    ],
)
def test_parse_tool_arguments_parses_and_repairs(raw, expected):
    assert parse_tool_arguments(raw) == expected


@pytest.mark.parametrize("raw", ["[1, 2]", '"text"', "{not json", "42"])
def test_parse_tool_arguments_never_falls_back_to_empty(raw):
    with pytest.raises(ToolError) as info:
        parse_tool_arguments(raw)
    assert info.value.code == "invalid_arguments"
    assert info.value.details["received"] == raw[:500]


def test_register_resolves_toolset_table_and_bumps_version():
    registry = ToolRegistry()
    before = registry.version
    spec = _make_spec(name="install_apk")
    registry.register(spec)
    assert registry.version == before + 1
    assert spec.toolset == "apps"
    assert spec.core is False
    assert spec.timeout_s >= 600
    assert spec.permission_key == "apk_path"
    core = _make_spec(name="take_screenshot")
    registry.register(core)
    assert core.core is True
    assert core.toolset == "capture"
    assert registry.unregister("install_apk") is True
    assert registry.unregister("install_apk") is False
    assert registry.version == before + 3


def test_unlisted_and_mcp_tools_get_derived_exposure():
    registry = ToolRegistry()
    plain = _make_spec(name="echo", category="misc")
    mcp = _make_spec(name="mcp:demo:reverse", core=True)
    registry.register(plain)
    registry.register(mcp)
    assert plain.toolset == "misc"
    assert plain.timeout_s == 120
    assert mcp.toolset == "mcp:demo"
    assert mcp.core is False


def test_fixed_tools_array_is_deterministic_and_filtered():
    registry = ToolRegistry()
    for name in ("take_screenshot", "launch_app", "install_apk", "tool_search"):
        registry.register(_make_spec(name=name))
    extra = {"type": "function", "function": {"name": "spawn_agent", "x": 1}}
    first = registry.fixed_tools_array(extras=[extra, "install_apk"])
    names = [t["function"]["name"] for t in first]
    assert names == [
        "launch_app",
        "take_screenshot",
        "tool_search",
        "spawn_agent",
        "install_apk",
    ]
    # Key order is canonical, so the serialisation is byte-stable.
    assert list(first[0]) == ["function", "type"]
    assert list(first[0]["function"]) == ["description", "name", "parameters"]
    second = registry.fixed_tools_array(extras=[extra, "install_apk"])
    assert tools_schema_hash(first) == tools_schema_hash(second)
    only_launch = registry.fixed_tools_array(
        allowed=lambda s: s.name != "take_screenshot"
    )
    assert [t["function"]["name"] for t in only_launch] == [
        "launch_app",
        "tool_search",
    ]


def test_toolset_catalogue_lists_deferred_tools_and_skips_mcp():
    registry = ToolRegistry()
    for name in ("install_apk", "take_screenshot", "start_frida_server"):
        registry.register(_make_spec(name=name))
    registry.register(_make_spec(name="mcp:demo:reverse"))
    text = registry.toolset_catalogue()
    assert text.splitlines() == [
        line for line in text.splitlines() if line.startswith(("- apps:", "- frida:"))
    ]
    assert "install_apk" in text
    assert "take_screenshot" not in text
    assert "mcp:" not in text
    assert "mcp:demo" in registry.mcp_catalogue()
