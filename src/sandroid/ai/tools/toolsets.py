"""Central toolset table for the AI tool layer.

Maps every native tool name to its toolset, whether it is a *core* tool (part
of the fixed per-session ``tools`` array), its executor timeout and its
permission key. Tool modules are deliberately not edited for this: the table
is the single place that decides how a tool is exposed, and
:meth:`~sandroid.ai.tools.registry.ToolRegistry.register` applies it to every
spec it registers.

Everything not in ``core`` is loaded on demand through ``tool_search`` /
``call_tool`` (see :mod:`sandroid.ai.tools.meta`). MCP-bridged tools are not
listed here; their toolset ``mcp:<server>`` is derived from the qualified name
(``mcp:<server>:<tool>``) and they are never core.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Default executor timeout (seconds) for a tool without an explicit entry.
DEFAULT_TIMEOUT_S = 120.0

#: Timeout for long-running tools (emulator restart, installs, snapshots).
LONG_TIMEOUT_S = 600.0

#: Toolset of the meta tools (``tool_search``, ``call_tool``, ``read_result``).
META_TOOLSET = "core"

#: Toolset of orchestrator agent tools; supplied as caller extras, never
#: listed in the toolset catalogue.
AGENTS_TOOLSET = "agents"

#: Prefix of the derived toolset of a bridged MCP server.
MCP_TOOLSET_PREFIX = "mcp:"


@dataclass(frozen=True)
class ToolsetEntry:
    """How one tool is exposed to the model.

    Attributes:
        toolset: Toolset name (see :data:`TOOLSET_DESCRIPTIONS`).
        core: Whether the tool is part of the fixed per-session tools array.
        timeout_s: Seconds the executor waits before giving up on the call.
        permission_key: For argument-dependent tools, the argument a
            remembered permission rule must constrain (e.g. ``package_name``).
            ``None`` for tools whose risk is their identity alone.
    """

    toolset: str
    core: bool = False
    timeout_s: float = DEFAULT_TIMEOUT_S
    permission_key: str | None = None


#: Toolset name -> one-line description for the system-prompt catalogue.
#: Dict order is the catalogue order.
TOOLSET_DESCRIPTIONS: dict[str, str] = {
    "core": "tool discovery and stored results (always loaded)",
    "device": "device build, patch level, root/Magisk, SELinux, adb root",
    "apps": (
        "installed packages, package details, exported components, "
        "foreground and spotlight app, install/uninstall/launch"
    ),
    "processes": "processes, services, activity stack, kill a process",
    "files": "pull/push device files, pull APKs and app data, read host files",
    "network": "connections, network info, captured HTTP(S) flows",
    "proxy": "mitmproxy, device-wide proxy, per-app proxy lanes, QUIC blocking",
    "certs": "CA certificate detection, push and system-store injection",
    "frida": "frida-server lifecycle, running Frida jobs, SSL unpinning",
    "capture": "screenshots and screen recordings",
    "emulator": "snapshots and emulator restart/kill",
    "monitor": "file-system monitor: live changes and per-file diffs",
    "recording": "record and replay device input, past runs and their diffs",
    "agents": "subagents (orchestrator only)",
}


def _e(
    toolset: str,
    *,
    core: bool = False,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    permission_key: str | None = None,
) -> ToolsetEntry:
    return ToolsetEntry(toolset, core, timeout_s, permission_key)


_LONG = LONG_TIMEOUT_S

#: Tool name -> exposure entry. Every registered non-MCP tool must have one
#: (enforced by ``tests/ai/tools/test_toolsets.py``).
TOOLSET_TABLE: dict[str, ToolsetEntry] = {
    # core (meta)
    "tool_search": _e("core", core=True, timeout_s=30),
    "call_tool": _e("core", core=True),
    "read_result": _e("core", core=True, timeout_s=30),
    # device
    "get_build_and_patch_info": _e("device", core=True),
    "check_root_and_magisk": _e("device", core=True),
    "get_selinux_status": _e("device"),
    "enable_adb_root": _e("device", timeout_s=180),
    # apps
    "get_spotlight_app": _e("apps", core=True),
    "set_spotlight_app": _e("apps", core=True, timeout_s=180),
    "get_foreground_app": _e("apps", core=True),
    "list_installed_packages": _e("apps", core=True),
    "get_package_details": _e("apps", core=True),
    "get_package_pid": _e("apps", core=True),
    "launch_app": _e("apps", core=True),
    "start_spotlight_app": _e("apps", timeout_s=180),
    "is_package_installed": _e("apps"),
    "list_exported_components": _e("apps"),
    "install_apk": _e("apps", timeout_s=_LONG, permission_key="apk_path"),
    "uninstall_apk": _e("apps", timeout_s=180, permission_key="package_name"),
    # processes
    "list_processes": _e("processes", core=True),
    "get_process_detail": _e("processes"),
    "list_services": _e("processes"),
    "get_activity_stack": _e("processes"),
    "kill_process": _e("processes", permission_key="package_name"),
    # files
    "pull_path": _e("files", timeout_s=_LONG),
    "push_path": _e("files", timeout_s=_LONG, permission_key="remote_path"),
    "pull_apk": _e("files", timeout_s=_LONG),
    "pull_app_data": _e("files", timeout_s=_LONG),
    "list_host_dir": _e("files"),
    "read_host_file": _e("files"),
    "list_allowed_host_paths": _e("files"),
    # network
    "get_captured_flows": _e("network", core=True),
    "get_flow_detail": _e("network", core=True),
    "clear_captured_flows": _e("network"),
    "list_connections": _e("network"),
    "get_network_info": _e("network"),
    # proxy
    "start_mitmproxy": _e("proxy", timeout_s=180),
    "stop_mitmproxy": _e("proxy"),
    "get_mitmproxy_status": _e("proxy"),
    "set_device_proxy": _e("proxy"),
    "clear_device_proxy": _e("proxy"),
    "get_device_proxy_status": _e("proxy"),
    "enable_app_proxy": _e("proxy", timeout_s=180, permission_key="package"),
    "disable_app_proxy": _e("proxy"),
    "get_app_proxy_status": _e("proxy"),
    "set_app_proxy_quic_blocking": _e("proxy"),
    # certs
    "list_detected_ca_certificates": _e("certs"),
    "check_ca_injection_status": _e("certs"),
    "push_ca_certificate": _e("certs", timeout_s=180),
    "inject_ca_certificate": _e("certs", timeout_s=_LONG, permission_key="source"),
    # frida
    "check_frida_server_status": _e("frida", core=True),
    "start_frida_server": _e("frida", timeout_s=180),
    "stop_frida_server": _e("frida"),
    "install_frida_server": _e("frida", timeout_s=_LONG, permission_key="version"),
    "get_running_frida_jobs": _e("frida"),
    "check_hook_conflicts": _e("frida"),
    "start_ssl_unpin": _e("frida", timeout_s=180),
    "stop_ssl_unpin": _e("frida"),
    "get_ssl_unpin_status": _e("frida"),
    # capture
    "take_screenshot": _e("capture", core=True),
    "start_screen_recording": _e("capture"),
    "stop_screen_recording": _e("capture", timeout_s=180),
    # emulator
    "list_snapshots": _e("emulator"),
    "create_snapshot": _e("emulator", timeout_s=_LONG),
    "load_snapshot": _e("emulator", timeout_s=_LONG, permission_key="name"),
    "delete_snapshot": _e("emulator", timeout_s=180, permission_key="name"),
    "restart_emulator": _e("emulator", timeout_s=900),
    "kill_emulator": _e("emulator", timeout_s=_LONG),
    # monitor
    "get_recent_file_changes": _e("monitor", core=True),
    "start_file_monitor": _e("monitor", timeout_s=180),
    "stop_file_monitor": _e("monitor"),
    "get_file_monitor_status": _e("monitor"),
    "get_file_diff": _e("monitor"),
    # recording
    "start_device_recording": _e("recording"),
    "stop_device_recording": _e("recording", timeout_s=180),
    "start_replay": _e("recording", timeout_s=_LONG),
    "get_recording_status": _e("recording"),
    "get_replay_status": _e("recording"),
    "list_recent_runs": _e("recording"),
    "get_run_detail": _e("recording"),
    # agents (ai/agents.py; registered lazily by orchestrator_extra_tools, so
    # they may be absent). spawn_agent's risk depends on its profile (operator spawns ask,
    # researcher spawns do not), so remembered rules are keyed by profile; with
    # wait=true it blocks until the agent's result (the agent wall budget plus
    # queueing), hence the long timeout.
    "spawn_agent": _e("agents", timeout_s=1800, permission_key="profile"),
    "wait_agent": _e("agents", timeout_s=90),
    "get_agent_result": _e("agents"),
    "cancel_agent": _e("agents"),
    "send_to_agent": _e("agents"),
    "list_agents": _e("agents"),
}

#: Names of the three meta tools, in their fixed tools-array order.
META_TOOL_NAMES: tuple[str, ...] = ("tool_search", "call_tool", "read_result")


def mcp_toolset(name: str) -> str | None:
    """Return ``mcp:<server>`` for a qualified MCP tool name, else ``None``."""
    if not name.startswith(MCP_TOOLSET_PREFIX):
        return None
    server = name[len(MCP_TOOLSET_PREFIX) :].split(":", 1)[0]
    return f"{MCP_TOOLSET_PREFIX}{server}"


def is_mcp_toolset(toolset: str) -> bool:
    """Whether *toolset* is a derived MCP toolset (``mcp:<server>``)."""
    return toolset.startswith(MCP_TOOLSET_PREFIX)


def lookup_entry(name: str) -> ToolsetEntry | None:
    """Return the exposure entry for a tool name.

    Native tools come from :data:`TOOLSET_TABLE`; MCP tools get a derived,
    never-core entry. Unknown names return ``None``.
    """
    entry = TOOLSET_TABLE.get(name)
    if entry is not None:
        return entry
    derived = mcp_toolset(name)
    if derived is not None:
        return ToolsetEntry(derived)
    return None


def core_tool_names() -> list[str]:
    """Return every table name flagged core (meta tools included), sorted."""
    return sorted(n for n, e in TOOLSET_TABLE.items() if e.core)
