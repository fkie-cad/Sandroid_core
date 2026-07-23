"""AI-chat tools for Sandroid's filesystem monitor (kprobe/fsmon).

Importing this module registers all five tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). ``category="fs_monitor"``.

Unlike every other AI-tools module, these tools do NOT dispatch to a
``sandroid.services`` singleton -- Monitor's real orchestration (backend
fallback between kprobe/fsmon, ``AnalysisEngine`` wiring, run-history
persistence) lives entirely in the TUI-only
:class:`~sandroid.tui.controllers.monitor_controller.MonitorController`,
constructed once in ``app.py`` and never a singleton. Reaching it here goes
through the tiny :mod:`sandroid.tui.controller_registry` seam (rather than
duplicating hundreds of lines of that orchestration into a parallel service
layer, or importing ``app.py``/``MainScreen`` directly into ``sandroid.ai``,
which would pull in the whole Textual ``App`` class hierarchy as an
import-time dependency of this package).

- ``start_file_monitor``, ``stop_file_monitor`` -- ``RiskTier.REVERSIBLE``,
  claiming/releasing :attr:`~sandroid.ai.arbiter.ResourceId.MONITOR`
  respectively (a still-running monitor session naturally blocks a second AI
  owner from starting another one).
- ``get_file_monitor_status``, ``get_recent_file_changes``, ``get_file_diff``
  -- all ``RiskTier.READ_ONLY``, no resource claimed.

``get_file_diff`` is the odd one out: it does not touch ``MonitorController``
at all. It drives the existing Files-tab Watchlist mechanism instead (see
``tui/widgets/watchlist_view.py``'s ``_pull_and_diff_one``, which this
mirrors) -- the on-demand "diff this one file" need is already exactly what
Watchlist's previous/current pull-and-cache does, so this reuses it rather
than building a second cache.
"""

import os
from typing import Any

from sandroid.ai.arbiter import ResourceId
from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools.registry import RiskTier, sandroid_tool

#: Valid ``mode`` values for ``start_file_monitor``. Note "all" has no direct
#: equivalent on ``MonitorConfig`` itself (which only ever knows "pid"/"path"
#: -- see ``tui/modals/monitor_modal.py``'s own two-option RadioSet): it is a
#: convenience alias this tool layer maps onto path-mode with the dataclass's
#: own broad default (``target_path="/data/"``, no ``target_paths``
#: narrowing), for a caller that just wants "watch everything" without first
#: having to pick a specific pid or path.
_VALID_MODES = ("pid", "path", "all")


def _require_monitor_controller() -> Any:
    """Return the registered ``MonitorController``, or raise.

    Shouldn't happen in practice -- the AI chat only ever runs inside an
    already-running TUI, by which point ``app.py``'s ``_init_controllers``
    has already called ``register_monitor_controller`` -- but keeps every
    tool function honest about the dependency rather than raising a bare
    ``AttributeError`` deep inside a ``None.foo()`` call.
    """
    from sandroid.tui.controller_registry import get_monitor_controller

    controller = get_monitor_controller()
    if controller is None:
        raise ToolExecutionError("Monitor controller is not available")
    return controller


def _build_monitor_config(
    mode: str,
    path: str | None,
    paths: list[str] | None,
    pid: int | None,
    app_name: str,
) -> Any:
    """Validate ``start_file_monitor``'s arguments and build a ``MonitorConfig``.

    Raises:
        ToolExecutionError: *mode* isn't one of :data:`_VALID_MODES`, "pid"
            mode is missing *pid*, or "path" mode is missing both *path* and
            *paths*.
    """
    from sandroid.tui.controllers.monitor_controller import MonitorConfig

    if mode not in _VALID_MODES:
        raise ToolExecutionError(f"mode must be one of {_VALID_MODES}, got {mode!r}")

    if mode == "pid":
        if pid is None:
            raise ToolExecutionError("pid is required for mode='pid'")
        # A path is optional here -- it only narrows/filters which events
        # under that PID are surfaced (see monitor_modal.py's own hint text
        # for the same PID+path combination); the dataclass default
        # ("/data/") applies when omitted.
        target_path = path or (paths[0] if paths else "/data/")
        return MonitorConfig(
            mode="pid",
            target_path=target_path,
            target_paths=list(paths) if paths else [],
            target_pid=int(pid),
            app_name=app_name or "",
        )

    if mode == "path":
        if not path and not paths:
            raise ToolExecutionError("path or paths is required for mode='path'")
        resolved_paths = list(paths) if paths else [path]  # type: ignore[list-item]
        return MonitorConfig(
            mode="path",
            target_path=resolved_paths[0],
            target_paths=resolved_paths,
            target_pid=None,
            app_name=app_name or "",
        )

    # mode == "all": the dataclass's own broad default -- see _VALID_MODES.
    return MonitorConfig(
        mode="path",
        target_path="/data/",
        target_paths=[],
        target_pid=None,
        app_name=app_name or "",
    )


@sandroid_tool(
    name="start_file_monitor",
    description=(
        "Start the filesystem monitor (kprobe, falling back to fsmon), "
        "scoped to a PID, one or more paths, or 'all' (everything under "
        "/data/). Exactly one of the mode-specific arguments applies: "
        "mode='pid' needs 'pid'; mode='path' needs 'path' and/or 'paths'; "
        "mode='all' needs neither. The kprobe backend resolves "
        "asynchronously -- a 'pending' true result means the concrete "
        "backend isn't known yet; follow up with get_file_monitor_status "
        "to confirm it actually started."
    ),
    parameters={
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "description": "One of: pid, path, all.",
            },
            "path": {
                "type": "string",
                "description": (
                    "Single on-device directory to monitor (mode='path'), "
                    "or an optional event filter under a PID (mode='pid')."
                ),
            },
            "paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Multiple on-device directories (mode='path').",
            },
            "pid": {
                "type": "integer",
                "description": "Target process id (mode='pid', required).",
            },
            "app_name": {
                "type": "string",
                "description": (
                    "Package name associated with 'pid', if known -- used "
                    "only to re-resolve a fresh PID if the monitor needs to "
                    "resume after a later replay's snapshot revert."
                ),
                "default": "",
            },
        },
        "required": ["mode"],
    },
    risk=RiskTier.REVERSIBLE,
    category="fs_monitor",
    resources=frozenset({ResourceId.MONITOR}),
)
def start_file_monitor(
    mode: str,
    path: str | None = None,
    paths: list[str] | None = None,
    pid: int | None = None,
    app_name: str = "",
) -> dict[str, Any]:
    """Start the filesystem monitor scoped to a PID/path(es)/everything.

    Real integration point:
    :meth:`~sandroid.tui.controllers.monitor_controller.MonitorController.start_with_config`
    (itself a thin, modal-free wrapper around the existing
    ``_start_monitor``).

    Raises:
        ToolExecutionError: The Monitor controller isn't available yet, or
            *mode*/its required companion argument(s) are invalid -- see
            :func:`_build_monitor_config`.

    Returns:
        ``{"success": bool, "backend": str | None, "mode": str, "target":
        str | int | None, "pending": bool}`` -- see
        ``MonitorController.start_with_config``'s own docstring for exactly
        when ``pending`` is True.
    """
    controller = _require_monitor_controller()
    config = _build_monitor_config(mode, path, paths, pid, app_name)
    return controller.start_with_config(config)


@sandroid_tool(
    name="stop_file_monitor",
    description="Stop the filesystem monitor if it is currently running.",
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.REVERSIBLE,
    category="fs_monitor",
    releases=frozenset({ResourceId.MONITOR}),
)
def stop_file_monitor() -> dict[str, Any]:
    """Stop the running monitor session, if any.

    Real integration point:
    :meth:`~sandroid.tui.controllers.monitor_controller.MonitorController.stop_from_ai`
    -- a thread-safe wrapper around ``stop()`` (this tool runs on the AI
    tool-dispatch thread, never Textual's main thread).

    Returns:
        ``{"success": bool, "message": str}``. ``success`` is False (with an
        explanatory message) when the monitor wasn't running -- a benign
        no-op, not an error.
    """
    controller = _require_monitor_controller()
    stopped = controller.stop_from_ai()
    if not stopped:
        return {"success": False, "message": "Monitor was not running"}
    return {"success": True, "message": "Monitor stopped"}


@sandroid_tool(
    name="get_file_monitor_status",
    description=(
        "Get the filesystem monitor's current running state, resolved "
        "backend (kprobe/fsmon), mode, and target path(s)/pid."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="fs_monitor",
)
def get_file_monitor_status() -> dict[str, Any]:
    """Return the running monitor session's status.

    Real integration point:
    :meth:`~sandroid.tui.controllers.monitor_controller.MonitorController.get_status`.

    Returns:
        ``{"running": bool, "backend": str | None, "mode": str | None,
        "target_path": str | None, "target_paths": list[str],
        "target_pid": int | None, "app_name": str | None}``.
    """
    controller = _require_monitor_controller()
    return controller.get_status()


@sandroid_tool(
    name="get_recent_file_changes",
    description=(
        "List recently observed filesystem events from the running (or "
        "most recently run) monitor session, oldest-first. Pass a prior "
        "call's next_seq as since_cursor to page forward for 'what's new "
        "since I last checked'; omit it to get the most recent `limit` "
        "events instead."
    ),
    parameters={
        "type": "object",
        "properties": {
            "since_cursor": {
                "type": "integer",
                "description": ("Only return events with seq greater than this value."),
            },
            "limit": {
                "type": "integer",
                "description": "Max events to return. Default 200, hard-capped at 2000.",
                "default": 200,
            },
        },
        "required": [],
    },
    risk=RiskTier.READ_ONLY,
    category="fs_monitor",
)
def get_recent_file_changes(
    since_cursor: int | None = None, limit: int = 200
) -> dict[str, Any]:
    """List recently observed filesystem events, cursor-paginated.

    Real integration point:
    :meth:`~sandroid.tui.controllers.monitor_controller.MonitorController.get_recent_events`
    -- reads the genuinely new, non-cleared ``recent_events`` deque on
    ``MonitorProcessWrapper``, NOT the transient per-flush ``item_buffer``/
    ``line_buffer`` closures MonitorView's own live rendering uses (those are
    cleared roughly every 0.15s and hold at most one flush interval's events
    at any instant).

    Returns:
        ``{"events": [...], "next_seq": int, "count": int, "truncated":
        bool}``. Every field is empty/zero when the monitor has never run
        this session.
    """
    controller = _require_monitor_controller()
    return controller.get_recent_events(since_seq=since_cursor, limit=limit)


@sandroid_tool(
    name="get_file_diff",
    description=(
        "Pull a fresh copy of one on-device file and diff it against the "
        "last-pulled version, via the Files tab's Watchlist mechanism. "
        "Adds 'path' to the watchlist first if it isn't already tracked. "
        "The very first pull of a path has nothing to diff against yet -- "
        "that call reports a fresh baseline instead of a diff."
    ),
    parameters={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Absolute on-device file path to pull and diff.",
            },
        },
        "required": ["path"],
    },
    risk=RiskTier.READ_ONLY,
    category="fs_monitor",
)
def get_file_diff(path: str) -> dict[str, Any]:
    """Pull one on-device file and diff it against its watchlist baseline.

    Mirrors ``watchlist_view.py``'s ``_pull_and_diff_one`` exactly (same
    pull call, same best-effort SQLite ``-wal``/``-journal`` companion pull,
    same promote-after-diff step) rather than reaching into the widget
    itself -- that method runs on the widget's own background thread and
    reports back via Textual message-posting, neither of which applies to a
    synchronous AI-tool dispatch. Uses the shared, promoted
    :func:`sandroid.core.file_diff.diff_files` (the same function
    ``watchlist_view.py``'s own ``_compute_diff`` now delegates to) so both
    call sites agree on the extension/magic-header dispatch.

    Deliberately passes ``file_extraction_service.is_sqlite_file`` (a plain,
    uncached magic-header read) as the sqlite check, NOT
    ``file_diff.is_sqlite_file`` -- that module keeps a process-lifetime
    cache keyed by path string with no invalidation, which would go stale
    here: this path's ``current``/``previous`` files get overwritten in
    place on every call.

    Raises:
        ToolExecutionError: *path* is empty, or the device pull failed
            (e.g. file not found, permission denied).

    Returns:
        ``{"path": str, "baseline": bool, "changed": bool | None, "message":
        str | None, "diff": str | None}``. ``baseline=True`` (with
        ``changed``/``diff`` both ``None``) means this was the first-ever
        pull of *path* -- nothing existed yet to diff against.
    """
    if not path:
        raise ToolExecutionError("path must not be empty")

    from sandroid.core import file_diff, watchlist_store
    from sandroid.core.adb import Adb
    from sandroid.services import get_file_extraction_service, get_forensic_service
    from sandroid.services.file_extraction_service import is_sqlite_file

    get_forensic_service().add_spotlight_file(path, adb=Adb)

    had_previous = watchlist_store.has_baseline(path)
    current_dir = watchlist_store.reset_current(path)
    basename = os.path.basename(path.rstrip("/")) or "pulled_file"
    current_main = current_dir / basename

    fx = get_file_extraction_service()
    result = fx.pull_file(path, str(current_main))
    if not result.success:
        raise ToolExecutionError(result.error or f"Failed to pull {path!r}")

    # Best-effort SQLite companions, same as _pull_and_diff_one -- pulled
    # directly (not via FileExtractionService's private companion-pull
    # helper) so the destination stays inside our own current/ cache dir.
    if is_sqlite_file(str(current_main)):
        for suffix in ("-wal", "-journal"):
            fx.pull_file(f"{path}{suffix}", f"{current_main}{suffix}")

    if not had_previous:
        watchlist_store.promote(path)
        return {
            "path": path,
            "baseline": True,
            "changed": None,
            "message": "Baseline captured, no prior version to diff against.",
            "diff": None,
        }

    previous_main = watchlist_store.previous_dir(path) / basename
    diff_text, changed = file_diff.diff_files(
        previous_main, current_main, is_sqlite_file
    )
    watchlist_store.promote(path)
    return {
        "path": path,
        "baseline": False,
        "changed": changed,
        "message": None if changed else "No changes since last pull.",
        "diff": diff_text if changed else None,
    }
