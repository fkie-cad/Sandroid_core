"""Tests for the toolset table, schema lint and meta tools (AI foundations WP2).

Covers :mod:`sandroid.ai.tools.toolsets`, the schema lint for every native
tool, and :mod:`sandroid.ai.tools.meta` (BM25 ``tool_search``, ``select:``,
``resolve_call`` incl. ``call_tool`` unwrapping, ``read_result``).
"""

import json
import re

import pytest

import sandroid.ai.tools
from sandroid.ai import results
from sandroid.ai.tools.meta import (
    LoadedTools,
    MetaContext,
    register_meta_tools,
    resolve_call,
    search_tools,
    tokenize,
    use_meta_context,
)
from sandroid.ai.tools.registry import (
    RiskTier,
    ToolError,
    ToolRegistry,
    ToolSpec,
    get_tool_registry,
)
from sandroid.ai.tools.toolsets import (
    AGENTS_TOOLSET,
    LONG_TIMEOUT_S,
    META_TOOL_NAMES,
    TOOLSET_DESCRIPTIONS,
    TOOLSET_TABLE,
    core_tool_names,
)

# ---------------------------------------------------------------------------
# Toolset table
# ---------------------------------------------------------------------------


def _native_specs() -> list[ToolSpec]:
    return [s for s in get_tool_registry().specs() if not s.name.startswith("mcp:")]


def test_every_registered_native_tool_has_a_table_entry():
    missing = [s.name for s in _native_specs() if s.name not in TOOLSET_TABLE]
    assert missing == []


def test_every_table_name_is_registered_except_optional_agent_tools():
    registered = set(get_tool_registry().names())
    stale = [
        name
        for name, entry in TOOLSET_TABLE.items()
        if name not in registered and entry.toolset != AGENTS_TOOLSET
    ]
    assert stale == []


def test_every_core_name_exists_and_core_size_is_15_to_20():
    registered = set(get_tool_registry().names())
    core = core_tool_names()
    assert set(core) <= registered
    assert set(META_TOOL_NAMES) <= set(core)
    assert 15 <= len(core) <= 20


def test_toolsets_are_known_and_registered_specs_carry_them():
    for name, entry in TOOLSET_TABLE.items():
        assert entry.toolset in TOOLSET_DESCRIPTIONS, name
    for spec in _native_specs():
        entry = TOOLSET_TABLE[spec.name]
        assert (spec.toolset, spec.core, spec.timeout_s, spec.permission_key) == (
            entry.toolset,
            entry.core,
            entry.timeout_s,
            entry.permission_key,
        )


@pytest.mark.parametrize(
    "name",
    [
        "restart_emulator",
        "kill_emulator",
        "start_replay",
        "install_apk",
        "load_snapshot",
    ],
)
def test_long_tools_get_at_least_600s(name):
    assert TOOLSET_TABLE[name].timeout_s >= LONG_TIMEOUT_S


def test_permission_keys_name_real_parameters():
    for spec in _native_specs():
        key = spec.permission_key
        if key is not None:
            assert key in spec.parameters.get("properties", {}), spec.name


def test_argument_dependent_tools_have_a_permission_key_where_possible():
    for spec in _native_specs():
        if spec.can_remember_choice or spec.toolset == AGENTS_TOOLSET:
            continue
        if spec.parameters.get("properties"):
            assert spec.permission_key is not None, spec.name


# ---------------------------------------------------------------------------
# Schema lint
# ---------------------------------------------------------------------------

#: Current violators (fix the tool, then remove it here). set_spotlight_app is
#: listed so the concurrent app-lens schema changes do not fail the lint.
_LINT_ALLOWLIST = frozenset({"get_captured_flows", "set_spotlight_app"})
_SNAKE = re.compile(r"^[a-z][a-z0-9_]*$")


def test_schema_lint_for_native_tools():
    problems = []
    for spec in _native_specs():
        if spec.name in _LINT_ALLOWLIST:
            continue
        if not _SNAKE.match(spec.name):
            problems.append(f"{spec.name}: not snake_case")
        if len(spec.description) > 600:
            problems.append(f"{spec.name}: description {len(spec.description)} > 600")
        if not spec.description.strip():
            problems.append(f"{spec.name}: empty description")
        params = spec.parameters or {}
        if params.get("type") != "object":
            problems.append(f"{spec.name}: parameters must be an object schema")
        for pname, prop in (params.get("properties") or {}).items():
            if not _SNAKE.match(pname):
                problems.append(f"{spec.name}.{pname}: not snake_case")
            if not isinstance(prop, dict) or not str(prop.get("description", "")):
                problems.append(f"{spec.name}.{pname}: no description")
    assert problems == []


def test_lint_allowlist_has_no_unknown_names():
    assert set(TOOLSET_TABLE) >= _LINT_ALLOWLIST


# ---------------------------------------------------------------------------
# tool_search (BM25)
# ---------------------------------------------------------------------------


def test_tokenize_splits_snake_camel_and_stems():
    assert tokenize("get_captured_flows") == ["get", "captur", "flow"]
    assert tokenize("startFridaServer") == ["start", "frida", "server"]
    assert tokenize("processes") == tokenize("process")
    assert tokenize("monitoring") == tokenize("monitor")


@pytest.mark.parametrize(
    ("query", "first", "all_in"),
    [
        ("install apk", "install_apk", None),
        ("screenshot", "take_screenshot", None),
        ("frida server", None, {"start_frida_server", "stop_frida_server"}),
        (
            "file monitor",
            None,
            {"start_file_monitor", "stop_file_monitor", "get_file_monitor_status"},
        ),
        ("kill process", "kill_process", None),
        ("selinux", "get_selinux_status", None),
        ("exported components", "list_exported_components", None),
        ("mitm", None, {"start_mitmproxy"}),
    ],
)
def test_golden_queries(query, first, all_in):
    names = search_tools(query)["loaded"]
    assert len(names) <= 5
    if first:
        assert names[0] == first
    if all_in:
        assert all_in <= set(names)


def test_proxy_query_returns_only_proxy_toolset():
    result = search_tools("proxy")
    assert len(result["tools"]) == 5
    assert {t["toolset"] for t in result["tools"]} == {"proxy"}
    tool = result["tools"][0]
    assert set(tool) == {"name", "toolset", "risk", "description", "parameters"}


def test_search_is_deterministic_and_json_serialisable():
    first = search_tools("frida server")
    assert first == search_tools("frida server")
    json.dumps(first)


def test_select_loads_exact_names_and_reports_unknown():
    loaded = LoadedTools()
    result = search_tools("select:install_apk, kill_process,nope", loaded=loaded)
    assert result["loaded"] == ["install_apk", "kill_process"]
    assert result["not_found"] == ["nope"]
    assert loaded.names() == ["install_apk", "kill_process"]


def test_allowed_predicate_filters_search():
    def read_only(spec):
        return spec.risk == RiskTier.READ_ONLY

    names = search_tools("frida server", allowed=read_only)["loaded"]
    assert "start_frida_server" not in names
    assert "check_frida_server_status" in names
    blocked = search_tools("select:install_apk", allowed=read_only)
    assert blocked["tools"] == []
    assert blocked["not_found"] == ["install_apk"]


def test_no_match_gives_a_note():
    result = search_tools("zzzqqq")
    assert result["tools"] == []
    assert "No matching tool" in result["note"]


def _fresh_registry() -> ToolRegistry:
    registry = ToolRegistry()
    register_meta_tools(registry)
    registry.register(
        ToolSpec(
            name="alpha_tool",
            description="Alpha thing.",
            parameters={"type": "object", "properties": {}},
            func=lambda: "alpha",
        )
    )
    return registry


def test_index_rebuilds_when_late_tools_register():
    registry = _fresh_registry()
    assert search_tools("reverse string", registry=registry)["loaded"] == []
    registry.register(
        ToolSpec(
            name="mcp:demo:reverse_string",
            description="Reverse a string.",
            parameters={
                "type": "object",
                "properties": {"text": {"type": "string", "description": "In."}},
            },
            func=lambda text: text[::-1],
        )
    )
    found = search_tools("reverse string", registry=registry)
    assert found["loaded"] == ["mcp:demo:reverse_string"]
    assert found["tools"][0]["toolset"] == "mcp:demo"


# ---------------------------------------------------------------------------
# resolve_call
# ---------------------------------------------------------------------------


def test_direct_call_to_core_tool_resolves():
    call = resolve_call("take_screenshot", "{}", loaded=LoadedTools())
    assert call.name == "take_screenshot"
    assert call.arguments == {}
    assert call.via_call_tool is False


def test_direct_call_to_unloaded_tool_is_not_loaded_until_searched():
    loaded = LoadedTools()
    with pytest.raises(ToolError) as info:
        resolve_call("kill_process", {"pid": 3}, loaded=loaded)
    assert info.value.code == "not_loaded"
    assert "tool_search" in info.value.hint
    search_tools("select:kill_process", loaded=loaded)
    call = resolve_call("kill_process", {"pid": 3}, loaded=loaded)
    assert call.spec.risk == RiskTier.REVERSIBLE


def test_exposed_overrides_the_default_core_set():
    with pytest.raises(ToolError) as info:
        resolve_call("take_screenshot", {}, loaded=LoadedTools(), exposed=set())
    assert info.value.code == "not_loaded"
    call = resolve_call(
        "kill_process", {"pid": 1}, loaded=LoadedTools(), exposed={"kill_process"}
    )
    assert call.name == "kill_process"


def test_unknown_tool_suggests_close_names():
    with pytest.raises(ToolError) as info:
        resolve_call("take_screenshots", {}, loaded=LoadedTools())
    assert info.value.code == "unknown_tool"
    assert "take_screenshot" in info.value.hint


def test_call_tool_unwraps_string_arguments_and_marks_loaded():
    loaded = LoadedTools()
    call = resolve_call(
        "call_tool",
        json.dumps({"name": "kill_process", "arguments": '{"pid": 42}'}),
        loaded=loaded,
    )
    assert call.name == "kill_process"
    assert call.arguments == {"pid": 42}
    assert call.via_call_tool is True
    assert "kill_process" in loaded


def test_call_tool_repairs_flat_arguments():
    call = resolve_call(
        "call_tool", {"name": "kill_process", "pid": 7}, loaded=LoadedTools()
    )
    assert call.arguments == {"pid": 7}


@pytest.mark.parametrize(
    ("args", "code"),
    [
        ({"arguments": {}}, "invalid_arguments"),
        ({"name": "call_tool", "arguments": {}}, "invalid_arguments"),
        ({"name": "kill_process", "arguments": "[1]"}, "invalid_arguments"),
        ({"name": "kill_process", "arguments": {}, "x": 1}, "invalid_arguments"),
        ({"name": "kill_process", "arguments": {"pid": "1;id"}}, "invalid_arguments"),
        ({"name": "nope", "arguments": {}}, "unknown_tool"),
    ],
)
def test_call_tool_errors(args, code):
    with pytest.raises(ToolError) as info:
        resolve_call("call_tool", args, loaded=LoadedTools())
    assert info.value.code == code


def test_non_object_arguments_are_invalid():
    with pytest.raises(ToolError) as info:
        resolve_call("take_screenshot", "[1, 2]", loaded=LoadedTools())
    assert info.value.code == "invalid_arguments"


def test_disallowed_tool_is_denied_even_via_call_tool():
    def no_kill(spec):
        return spec.name != "kill_process"

    with pytest.raises(ToolError) as info:
        resolve_call(
            "call_tool",
            {"name": "kill_process", "arguments": {"pid": 1}},
            loaded=LoadedTools(),
            allowed=no_kill,
        )
    assert info.value.code == "denied"


def test_optional_null_arguments_are_dropped():
    call = resolve_call(
        "launch_app",
        {"package_name": "com.x", "activity_name": None},
        loaded=LoadedTools(),
    )
    assert call.arguments == {"package_name": "com.x"}


def test_call_tool_fails_closed_when_dispatched_directly():
    with pytest.raises(ToolError) as info:
        get_tool_registry().dispatch(
            "call_tool", {"name": "kill_process", "arguments": {"pid": 1}}
        )
    assert info.value.code == "tool_failed"


def test_meta_tools_are_read_only_core():
    registry = get_tool_registry()
    for name in META_TOOL_NAMES:
        spec = registry.get_spec(name)
        assert spec.risk == RiskTier.READ_ONLY
        assert spec.core is True
        assert spec.toolset == "core"


# ---------------------------------------------------------------------------
# Registered tool functions read the MetaContext
# ---------------------------------------------------------------------------


@pytest.fixture
def _fresh_results():
    results.reset_for_tests()
    yield
    results.reset_for_tests()


def test_tool_search_tool_uses_context_loaded_and_allowed():
    loaded = LoadedTools()
    ctx = MetaContext(loaded=loaded, allowed=lambda s: s.name != "install_apk")
    with use_meta_context(ctx):
        out = get_tool_registry().dispatch("tool_search", {"query": "install apk"})
    assert "install_apk" not in out["loaded"]
    assert loaded.names() == sorted(out["loaded"])


def test_read_result_tool_reads_the_context_store(_fresh_results):
    store = results.ResultStore(None)
    rid = store.put("x", {}, {"lines": [f"row {i}" for i in range(100)]}).id
    ctx = MetaContext(store=store, cap_tokens=8000)
    with use_meta_context(ctx):
        out = get_tool_registry().dispatch("read_result", {"id": rid, "grep": "7"})
    assert out["result_id"] == rid
    assert out["match_count"] == 19
    assert all("7" in m for m in out["matches"])
