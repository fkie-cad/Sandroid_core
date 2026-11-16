"""Integration tests for the MCP client manager against the real bundled
demo fixture server (sandroid.ai.mcp_demo_server), spawned as a real subprocess.

No network involved -- the "external" server here is just another local
process talking stdio JSON-RPC, which is exactly what lets this be a fast,
deterministic test rather than a live-network integration test.

config.mcp.servers may not exist yet in sandroid.config.schema (a sibling
in-progress change lands it) -- these tests build their own duck-typed
server-config stand-in and monkeypatch sandroid.config.get_config, so they
don't depend on that landing schedule.
"""

import sys
from dataclasses import dataclass, field

import psutil
import pytest

import sandroid.config as config_module
from sandroid.ai.errors import AIClientError
from sandroid.ai.mcp_client import MCPClientManager
from sandroid.ai.tool_permissions import resolve_tool_policy
from sandroid.ai.tools.mcp_bridge import bridge_mcp_tools
from sandroid.ai.tools.registry import RiskTier, ToolRegistry


@dataclass
class FakeMCPServerConfig:
    name: str
    command: str
    args: list = field(default_factory=list)
    transport: str = "stdio"
    url: str | None = None
    enabled: bool = True


@dataclass
class FakeMCPConfig:
    servers: list = field(default_factory=list)


@dataclass
class FakeSandroidConfig:
    mcp: FakeMCPConfig


SERVER = "sandroid-demo-fake-data"


def _dummy_server_config(name=SERVER, enabled=True):
    return FakeMCPServerConfig(
        name=name,
        command=sys.executable,
        args=["-m", "sandroid.ai.mcp_demo_server"],
        enabled=enabled,
    )


@pytest.fixture
def ai_ready(monkeypatch):
    """MCPClientManager.start() is a no-op unless the AI Chat is configured
    (see sandroid.ai.safety) -- configure a local endpoint for these tests.
    """
    from sandroid.ai import safety

    settings = safety.AISettings(
        base_url="http://localhost:11434/v1", api_key="k-test", model="m"
    )
    monkeypatch.setattr(safety, "get_ai_settings", lambda *a, **kw: settings)
    return settings


@pytest.fixture
def fake_config(monkeypatch, ai_ready):
    cfg = FakeSandroidConfig(mcp=FakeMCPConfig(servers=[_dummy_server_config()]))
    monkeypatch.setattr(config_module, "get_config", lambda: cfg)
    return cfg


@pytest.fixture
def manager(fake_config):
    mgr = MCPClientManager()
    yield mgr
    # Always attempt a clean stop, even if the test body failed/raised, so a
    # failing assertion never leaks the dummy-server subprocess.
    mgr.stop()


def test_start_connects_and_lists_both_tools(manager):
    manager.start()

    tools = manager.list_all_tools()

    assert SERVER in tools
    names = {t.name for t in tools[SERVER]}
    assert names == {"demo_reverse_string", "demo_fake_ioc_lookup"}


def test_call_tool_reverse_string_round_trips_real_data(manager):
    manager.start()

    result = manager.call_tool(SERVER, "demo_reverse_string", {"text": "sandroid"})

    assert result.isError is False
    assert result.content[0].text == "diordnas"


def test_demo_lookup_self_identifies_as_fake(manager):
    manager.start()

    result = manager.call_tool(
        SERVER, "demo_fake_ioc_lookup", {"indicator": "1.2.3.4"}
    )

    assert result.isError is False
    payload = result.content[0].text
    assert "1.2.3.4" in payload
    assert "FAKE_DEMO_DATA" in payload
    assert "not real" in payload


def test_bridge_registers_and_dispatches_both_mcp_tools(manager):
    manager.start()
    registry = ToolRegistry()

    # bridge_mcp_tools() always targets the process-wide singletons; exercise
    # the real bridging logic against our test-local manager/registry by
    # patching the names as bound in mcp_bridge's own module namespace (it
    # imported them via `from ... import ...`, so the origin modules'
    # attributes must be patched there, not on the origin modules themselves).
    import sandroid.ai.tools.mcp_bridge as bridge_module

    original_get_manager = bridge_module.get_mcp_client_manager
    original_get_registry = bridge_module.get_tool_registry
    bridge_module.get_mcp_client_manager = lambda: manager
    bridge_module.get_tool_registry = lambda: registry
    try:
        bridge_mcp_tools()
    finally:
        bridge_module.get_mcp_client_manager = original_get_manager
        bridge_module.get_tool_registry = original_get_registry

    schema_names = {
        entry["function"]["name"] for entry in registry.openai_tools_schema()
    }
    assert schema_names == {
        f"mcp:{SERVER}:demo_reverse_string",
        f"mcp:{SERVER}:demo_fake_ioc_lookup",
    }

    # Unknown external tools must never auto-run: always behind the gate.
    for name in schema_names:
        spec = registry.get_spec(name)
        assert spec.risk == RiskTier.CONSEQUENTIAL
        assert resolve_tool_policy(name, spec.risk, spec.can_remember_choice) == "ask"
        assert spec.description.startswith("[external MCP server")

    assert (
        registry.dispatch(f"mcp:{SERVER}:demo_reverse_string", {"text": "abc"})
        == "cba"
    )
    lookup_result = registry.dispatch(
        f"mcp:{SERVER}:demo_fake_ioc_lookup", {"indicator": "8.8.8.8"}
    )
    assert lookup_result["FAKE_DEMO_DATA"] is True
    assert lookup_result["indicator"] == "8.8.8.8"
    assert lookup_result["confidence"] == 0.0
    assert "FAKE" in lookup_result["notice"]


def test_start_is_noop_when_ai_not_configured(monkeypatch):
    """No MCP subprocess is ever spawned while the AI Chat is off."""
    from sandroid.ai import safety

    cfg = FakeSandroidConfig(mcp=FakeMCPConfig(servers=[_dummy_server_config()]))
    monkeypatch.setattr(config_module, "get_config", lambda: cfg)
    monkeypatch.setattr(
        safety, "get_ai_settings", lambda *a, **kw: safety.AISettings()
    )
    mgr = MCPClientManager()
    try:
        mgr.start()
        assert mgr._thread is None
    finally:
        mgr.stop()


def test_start_is_noop_without_enabled_servers(monkeypatch, ai_ready):
    monkeypatch.setattr(
        config_module, "get_config", lambda: FakeSandroidConfig(mcp=FakeMCPConfig())
    )
    mgr = MCPClientManager()
    mgr.start()
    assert mgr._thread is None
    mgr.stop()


def test_missing_mcp_package_gives_clear_error(monkeypatch, fake_config):
    """Without the optional `mcp` package, start() fails with an actionable
    message instead of an ImportError at `import sandroid.ai` time.
    """
    import builtins

    from sandroid.ai import mcp_client

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "mcp" or name.startswith("mcp."):
            raise ImportError("No module named 'mcp'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert mcp_client.mcp_available() is False
    mgr = MCPClientManager()
    with pytest.raises(AIClientError, match="pip install mcp"):
        mgr.start()
    assert mgr._thread is None


def test_default_config_enables_no_mcp_server():
    """The fake-data demo fixture must never be on by default."""
    from sandroid.config.schema import MCPConfig, SandroidConfig

    assert MCPConfig().servers == []
    assert SandroidConfig().mcp.servers == []



def test_disabled_server_is_not_connected(fake_config):
    fake_config.mcp.servers = [_dummy_server_config(enabled=False)]
    mgr = MCPClientManager()
    try:
        mgr.start()
        assert mgr.list_all_tools() == {}
    finally:
        mgr.stop()


def test_stop_cleans_up_subprocess_without_leaving_a_zombie(manager):
    """The single most important assertion in this suite (per the task spec):
    stop() must not just kill the asyncio loop -- it must cleanly exit the
    stdio_client/ClientSession context managers first, or the dummy server's
    subprocess is left running (zombied) after the manager reports stopped.
    """
    manager.start()

    current_process = psutil.Process()
    children_before = current_process.children(recursive=True)
    assert len(children_before) >= 1, "expected the dummy server subprocess to exist"

    manager.stop()

    # Give the OS a brief moment to finish reaping; psutil.is_running() also
    # returns False once the process has been waited on.
    still_alive = [child for child in children_before if child.is_running()]
    assert still_alive == [], f"dummy server subprocess(es) leaked: {still_alive}"


def test_stop_is_idempotent_and_safe_before_start():
    mgr = MCPClientManager()
    mgr.stop()  # must not raise even though start() was never called
    mgr.stop()  # and calling it twice must also not raise


def test_restart_after_stop_reconnects_cleanly(manager):
    manager.start()
    assert SERVER in manager.list_all_tools()

    manager.stop()
    assert manager.list_all_tools() == {}

    manager.start()
    assert SERVER in manager.list_all_tools()
    result = manager.call_tool(SERVER, "demo_reverse_string", {"text": "ok"})
    assert result.content[0].text == "ko"
