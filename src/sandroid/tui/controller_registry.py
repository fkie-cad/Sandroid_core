"""Process-wide registry for the TUI's Monitor/Recording controller singletons.

``MonitorController`` and ``RecordingController`` are constructed exactly
once, in ``app.py``'s ``_init_controllers``, wired with constructor-injected
UI callbacks specifically so they're reusable outside the TUI's own widget
plumbing (see each controller's own docstring). The AI-chat tools in
:mod:`sandroid.ai.tools.monitor_control`/:mod:`sandroid.ai.tools.recording_control`
need to reach those SAME instances -- their real orchestration (backend
fallback, kprobe/fsmon dispatch, ``AnalysisEngine`` wiring, run-history
persistence) lives entirely in these controllers, and duplicating hundreds of
lines of that into a parallel service layer would be substantial, risky
rework for no benefit.

This module is the tiny seam that lets the AI tool modules reach the
controllers without importing ``app.py``/``MainScreen`` directly (which would
pull in the whole Textual ``App`` class hierarchy as an import-time
dependency of the ``sandroid.ai`` package). Mirrors the plain
module-level-singleton pattern already used throughout this codebase (e.g.
:func:`sandroid.ai.arbiter.get_arbiter`,
:func:`sandroid.ai.tools.registry.get_tool_registry`) -- no locking, since
registration happens once at app startup on the main thread, before any AI
tool could possibly run.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sandroid.tui.controllers.monitor_controller import MonitorController
    from sandroid.tui.controllers.recording_controller import RecordingController

_monitor_controller: "MonitorController | None" = None
_recording_controller: "RecordingController | None" = None


def register_monitor_controller(controller: "MonitorController") -> None:
    """Register the TUI's single ``MonitorController`` instance.

    Called once from ``app.py``'s ``_init_controllers``, right after the
    controller itself is constructed.
    """
    global _monitor_controller
    _monitor_controller = controller


def get_monitor_controller() -> "MonitorController | None":
    """Return the registered ``MonitorController``.

    Returns:
        The TUI's ``MonitorController`` instance, or ``None`` if the TUI
        hasn't started one yet (in practice this only happens if something
        calls in before ``app.py`` finishes initializing -- the AI chat
        itself only ever runs inside an already-running TUI).
    """
    return _monitor_controller


def register_recording_controller(controller: "RecordingController") -> None:
    """Register the TUI's single ``RecordingController`` instance.

    Called once from ``app.py``'s ``_init_controllers``, right after the
    controller itself is constructed.
    """
    global _recording_controller
    _recording_controller = controller


def get_recording_controller() -> "RecordingController | None":
    """Return the registered ``RecordingController``.

    Returns:
        The TUI's ``RecordingController`` instance, or ``None`` if the TUI
        hasn't started one yet (see :func:`get_monitor_controller`'s
        docstring for the same caveat).
    """
    return _recording_controller


__all__ = [
    "get_monitor_controller",
    "get_recording_controller",
    "register_monitor_controller",
    "register_recording_controller",
]
