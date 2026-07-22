"""Process-inspection and process-control tools for the Sandroid AI chat.

Every tool here dispatches to a genuinely existing :class:`~sandroid.core.adb.Adb`
classmethod -- ``ps -A`` parsing, ``/proc/<pid>/status`` parsing, and
``dumpsys activity services``/``dumpsys activity activities`` parsing (see
:mod:`sandroid.core.adb_process` and :mod:`sandroid.core.adb_dumpsys` for the
underlying implementations and their live-device-verification caveats).

Importing this module registers all five tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). All tools in this module have
``category="process_control"``.
"""

import logging
import shlex
from typing import Any

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools._shared import validate_package_name
from sandroid.ai.tools.registry import RiskTier, sandroid_tool
from sandroid.core.adb import Adb

logger = logging.getLogger(__name__)

#: Signals ``kill_process`` accepts, mirroring ``core.adb_process``'s own
#: ``_ALLOWED_SIGNALS`` allowlist. Kept as a separate copy here (rather than
#: imported) since the core module treats it as a private implementation
#: detail of its own interpolation-safety argument -- this tool's schema
#: enum is the actual enforcement surface for calls coming from the model.
_ALLOWED_SIGNALS = ("TERM", "KILL", "HUP", "INT")


@sandroid_tool(
    name="list_processes",
    description=(
        "List running processes on the device via 'ps -A'. Optionally "
        "filter to process names containing a substring."
    ),
    parameters={
        "type": "object",
        "properties": {
            "package_filter": {
                "type": "string",
                "description": (
                    "Optional substring to match against each process name. "
                    "Omit to list every running process on the device."
                ),
            },
        },
        "required": [],
    },
    risk=RiskTier.READ_ONLY,
    category="process_control",
)
def list_processes(package_filter: str | None = None) -> dict[str, Any]:
    """List running processes, optionally filtered by name substring.

    Real integration point: :meth:`sandroid.core.adb.Adb.list_processes`.

    Args:
        package_filter: Optional substring to match against each process
            name. Omit to list every running process on the device.

    Returns:
        ``{"processes": [...], "count": len(...)}`` -- ``processes`` is the
        raw list of dicts (``pid``, ``user``, ``name``) returned by
        ``Adb.list_processes``.
    """
    processes = Adb.list_processes(package_filter=package_filter)
    return {"processes": processes, "count": len(processes)}


@sandroid_tool(
    name="get_process_detail",
    description=(
        "Get detailed info for one running process from /proc/<pid>: name, "
        "state, parent PID, thread count, uid, memory usage (RSS/virtual "
        "size), open file-descriptor count, and memory-map region count."
    ),
    parameters={
        "type": "object",
        "properties": {
            "pid": {
                "type": "integer",
                "description": "The process ID to inspect.",
            },
        },
        "required": ["pid"],
    },
    risk=RiskTier.READ_ONLY,
    category="process_control",
)
def get_process_detail(pid: int) -> dict[str, Any]:
    """Get detailed process info from ``/proc/<pid>``.

    Real integration point: :meth:`sandroid.core.adb.Adb.get_process_detail`.

    Args:
        pid: The process ID to inspect.

    Returns:
        A dict with keys ``'pid'``, ``'name'``, ``'state'``, ``'ppid'``,
        ``'threads'``, ``'uid'``, ``'uid_map'``, ``'gid'``, ``'gid_map'``,
        ``'vm_rss_kb'``, ``'vm_size_kb'``, ``'fd_count'``, and
        ``'map_region_count'``.

    Raises:
        ToolExecutionError: The process is gone or ``/proc/<pid>/status`` is
            otherwise unreadable.
    """
    detail = Adb.get_process_detail(pid)
    if detail is None:
        raise ToolExecutionError(
            f"process {pid} is not running or its /proc entry is unreadable"
        )
    return detail


@sandroid_tool(
    name="list_services",
    description=(
        "List running Android services via 'dumpsys activity services'. "
        "Supports two modes: omit package_name to list every running "
        "service on the device; pass a package_name to filter to just that "
        "app's services."
    ),
    parameters={
        "type": "object",
        "properties": {
            "package_name": {
                "type": "string",
                "description": (
                    "Fully qualified package name to filter to (e.g. "
                    "'com.example.app'). Omit to list every running service "
                    "device-wide -- there is no spotlight-app fallback here, "
                    "omitting truly means 'device-wide', not 'the current "
                    "app'."
                ),
            },
        },
        "required": [],
    },
    risk=RiskTier.READ_ONLY,
    category="process_control",
)
def list_services(package_name: str | None = None) -> dict[str, Any]:
    """List running services, device-wide or filtered to one package.

    Real integration point: :meth:`sandroid.core.adb.Adb.list_services`.
    Deliberately does **not** route through
    :func:`sandroid.ai.tools._shared.resolve_package_name`'s
    spotlight-fallback-or-raise convention -- omitting ``package_name`` here
    means "list every running service on the device", not "use the current
    spotlight app". When given, ``package_name`` is validated via
    :func:`sandroid.ai.tools._shared.validate_package_name` before it
    reaches ``Adb.list_services``'s own ``shlex.quote()``-d, shell-adjacent
    ``dumpsys`` call -- defense in depth alongside that existing quoting.

    Args:
        package_name: Fully qualified package name to filter to, or
            ``None``/omitted to list every running service device-wide.

    Returns:
        ``{"services": [...], "count": len(...)}`` -- ``services`` is the
        raw list of dicts returned by ``Adb.list_services``.

    Raises:
        ToolExecutionError: *package_name* was given but does not match
            Android's package identifier format.
    """
    if package_name:
        package_name = validate_package_name(package_name)
    services = Adb.list_services(package_name=package_name)
    return {"services": services, "count": len(services)}


@sandroid_tool(
    name="get_activity_stack",
    description=(
        "Get the device's activity task stack via 'dumpsys activity "
        "activities' -- every task and the activities within it."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="process_control",
)
def get_activity_stack() -> dict[str, Any]:
    """Get the device's activity task stack.

    Real integration point: :meth:`sandroid.core.adb.Adb.get_activity_stack`.

    Returns:
        ``{"tasks": [...], "count": len(...)}`` -- ``tasks`` is the raw list
        of task dicts (each with its own ``activities`` list) returned by
        ``Adb.get_activity_stack``.
    """
    tasks = Adb.get_activity_stack()
    return {"tasks": tasks, "count": len(tasks)}


@sandroid_tool(
    name="kill_process",
    description=(
        "Kill a running process, either by package name (force-stop, the "
        "safe/standard Android way to stop an app) or by raw PID (sends a "
        "signal directly, retrying as root if needed -- can target any "
        "process on the device, not just app processes). Pass exactly one "
        "of package_name or pid."
    ),
    parameters={
        "type": "object",
        "properties": {
            "package_name": {
                "type": "string",
                "description": (
                    "Fully qualified package name to force-stop. Mutually "
                    "exclusive with pid."
                ),
            },
            "pid": {
                "type": "integer",
                "description": (
                    "Raw process ID to signal directly. Mutually exclusive "
                    "with package_name."
                ),
            },
            "signal": {
                "type": "string",
                "description": (
                    "Signal to send when killing by pid. Ignored when "
                    "killing by package_name (force-stop has no signal "
                    "concept). Defaults to 'TERM'."
                ),
                "enum": list(_ALLOWED_SIGNALS),
                "default": "TERM",
            },
        },
        "required": [],
    },
    risk=RiskTier.REVERSIBLE,
    category="process_control",
    can_remember_choice=False,
)
def kill_process(
    package_name: str | None = None,
    pid: int | None = None,
    signal: str = "TERM",
) -> dict[str, Any]:
    """Kill a process by package name (force-stop) or by raw PID.

    Real integration points: :meth:`sandroid.core.adb.Adb.force_stop` (package
    path) and :meth:`sandroid.core.adb.Adb.kill_pid` (pid path).
    ``can_remember_choice=False`` because the pid path can target *any*
    process on the device, including system-critical ones unrelated to
    whatever the analyst approved last time -- an unbounded
    argument-dependent risk, the same reasoning as ``load_snapshot``/
    ``install_frida_server``.

    Exactly one of ``package_name``/``pid`` must be given. The package path
    validates ``package_name`` against Android's real package-identifier
    format (:func:`sandroid.ai.tools._shared.validate_package_name`) and
    additionally quotes it with :func:`shlex.quote` before it reaches
    ``Adb.force_stop``'s internal, unquoted f-string (per this task's
    injection-hardening scope: fix at new call sites only, the shared ``Adb``
    function itself is untouched) -- validation and quoting solve different
    problems (device-side re-injection vs. host-side shell injection), so
    both are kept. The pid path rejects ``pid <= 0`` outright (POSIX
    ``kill()`` gives 0 and negative pids special process-group-wide
    semantics -- never what a single-process "kill this pid" call should
    trigger) before ever reaching ``Adb.kill_pid``, whose own plain
    ``ValueError`` for a non-integer pid or an unsupported signal is
    wrapped into :class:`ToolExecutionError` here.

    Args:
        package_name: Fully qualified package name to force-stop. Mutually
            exclusive with ``pid``.
        pid: Raw process ID to signal. Mutually exclusive with
            ``package_name``. Must be a positive integer.
        signal: Signal name for the pid path (``'TERM'``, ``'KILL'``,
            ``'HUP'``, or ``'INT'``). Ignored for the package path.

    Returns:
        Package path: ``{"method": "force_stop", "package_name": pkg,
        "success": bool, "message": str}``.
        Pid path: ``{"method": "kill_pid", "pid": pid, "signal": signal,
        "killed": bool, "used_root": bool}``.

    Raises:
        ToolExecutionError: Neither or both of ``package_name``/``pid`` were
            given, ``package_name`` does not match Android's package
            identifier format, ``pid`` is not a positive integer, or
            ``Adb.kill_pid`` rejected the pid/signal.
    """
    if bool(package_name) == bool(pid is not None):
        raise ToolExecutionError(
            "kill_process requires exactly one of package_name or pid"
        )

    if package_name:
        package_name = validate_package_name(package_name)
        success, message = Adb.force_stop(shlex.quote(package_name))
        return {
            "method": "force_stop",
            "package_name": package_name,
            "success": success,
            "message": message,
        }

    if pid <= 0:
        raise ToolExecutionError(f"pid must be a positive integer, got {pid}")

    try:
        killed, used_root = Adb.kill_pid(pid, signal)
    except ValueError as exc:
        raise ToolExecutionError(str(exc)) from exc

    return {
        "method": "kill_pid",
        "pid": pid,
        "signal": signal,
        "killed": killed,
        "used_root": used_root,
    }
