"""Integration tests for the MCP client manager against the real bundled
dummy server (sandroid.ai.mcp_dummy_server), spawned as a real subprocess.

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
from sandroid.ai.mcp_client import MCPClientManager
from sandroid.ai.tools.mcp_bridge import bridge_mcp_tools
from sandroid.ai.tools.registry import ToolRegistry


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


def _dummy_server_config(name="sandroid-dummy", enabled=True):
    return FakeMCPServerConfig(
        name=name,
        command=sys.executable,
        args=["-m", "sandroid.ai.mcp_dummy_server"],
        enabled=enabled,
    )


@pytest.fixture
def fake_config(monkeypatch):
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

    assert "sandroid-dummy" in tools
    names = {t.name for t in tools["sandroid-dummy"]}
    assert names == {"reverse_string", "sample_forensic_lookup"}


def test_call_tool_reverse_string_round_trips_real_data(manager):
    manager.start()

    result = manager.call_tool("sandroid-dummy", "reverse_string", {"text": "sandroid"})

    assert result.isError is False
    assert result.content[0].text == "diordnas"


def test_call_tool_sample_forensic_lookup_round_trips_real_data(manager):
    manager.start()

    result = manager.call_tool(
        "sandroid-dummy", "sample_forensic_lookup", {"indicator": "1.2.3.4"}
    )

    assert result.isError is False
    payload = result.content[0].text
    assert "1.2.3.4" in payload
    assert "sample-malware-family-X" in payload


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
        "mcp:sandroid-dummy:reverse_string",
        "mcp:sandroid-dummy:sample_forensic_lookup",
    }

    assert (
        registry.dispatch("mcp:sandroid-dummy:reverse_string", {"text": "abc"}) == "cba"
    )
    lookup_result = registry.dispatch(
        "mcp:sandroid-dummy:sample_forensic_lookup", {"indicator": "8.8.8.8"}
    )
    assert lookup_result == {
        "indicator": "8.8.8.8",
        "match": "sample-malware-family-X",
        "confidence": 0.42,
        "source": "sandroid-dummy-mcp (fabricated sample data)",
    }


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
    assert "sandroid-dummy" in manager.list_all_tools()

    manager.stop()
    assert manager.list_all_tools() == {}

    manager.start()
    assert "sandroid-dummy" in manager.list_all_tools()
    result = manager.call_tool("sandroid-dummy", "reverse_string", {"text": "ok"})
    assert result.content[0].text == "ko"
