"""Monitor sub-tab: fsmon's live filesystem-event stream.

Replaces the ``MonitorView`` stub in ``files_panel.py`` with the first real
sub-view of the Files tab. Reuses :class:`~sandroid.tui.widgets.fritap_panel.
FriTapPanel`'s shape (a colored status header ``Static`` above a
``RichLog``) as its template, and the same thread-safe EventBus idiom:
capture the running loop in ``on_mount`` and marshal callbacks with
``loop.call_soon_threadsafe`` — never ``call_from_thread``, which would
deadlock a caller on a background thread (see ``FriTapPanel``/``FilesPanel``
for the identical pattern).

fsmon itself has zero EventBus integration otherwise: its output only ever
reached the Activity Log (throttled to the last 5 lines per flush batch) and
the now-legacy observer modal. ``FSMonController._log_fsmon_output_batch``
was extended (additively — the Activity Log/observer routing is untouched)
to also publish every line as an ``EventType.TASK_OUTPUT`` event with
``source="fsmon"``, via the module-level ``_publish_fsmon_event`` helper
there (mirrors ``analysis/fritap.py``'s ``_publish_fritap_event``). This view
is the consumer of that stream and gets the FULL, un-throttled feed.

Stateless like ``FriTapPanel``: no new manager, no config schema. Live
running/target state is read straight from ``TaskService``; the only local
state is a client-side event tally (fsmon has no counter of its own), reset
on ``TASK_STARTED`` for ``task_name == "fsmon"`` — a more reliable reset
signal than FriTapPanel's ad hoc "FriTap started for" substring match, since
``TaskService.register()`` already publishes that event for every task.

Bindings (when focused):
    Enter:  start/stop fsmon (delegates to ``action_fsmon``, key ``o`` — the
            same command, not a second code path)
    Ctrl+L: clear the log view + reset the event-category counters

**Log cap** (``tui.fsmon_max_lines``, default 500): the now-retired
``FSMonRunningModal`` capped its ``RichLog`` at this value via the
constructor's ``max_lines`` parameter (Textual's ``RichLog`` trims old lines
off the top once the buffer exceeds it — see ``RichLog.write``); this view
reads the same config field the same way (see ``_get_config_max_lines``,
mirroring ``FSMonController._get_buffer_interval``'s read pattern) so
Monitor's live, un-throttled feed doesn't grow unbounded for a long-running
session. Read once at construction time (matches the old modal, which was
itself recreated fresh per fsmon session) -- a config change made via the
Settings screen takes effect on the next TUI restart, not live.
"""

from __future__ import annotations

import logging
from typing import Any

from textual.containers import Horizontal
from textual.widgets import Button, RichLog, Static

from sandroid.services import get_task_service
from sandroid.tui.controllers.fsmon_controller import FSMON_COLOR_RULES

from .files_panel import FilesSubViewBase

logger = logging.getLogger(__name__)

# colorize_fsmon_line's color choice -> the human category label Monitor's
# counters use. Derived from the SAME FSMON_COLOR_RULES the controller uses
# to colorize lines in the first place, rather than re-implementing the
# CREATE/DELETE/RENAME/OPEN substring matching a second time.
_CATEGORY_BY_COLOR = {
    "green": "create",
    "red": "delete",
    "yellow": "rename",
    "cyan": "access",
}


def _categorize_fsmon_line(message: str) -> str | None:
    """Classify an (already colorized) fsmon line into one of four buckets.

    Runs the same keyword search ``colorize_fsmon_line`` used to pick a
    color, so this only ever agrees with what's actually on screen. Safe to
    run on the post-``colorize_fsmon_line`` string: that function only
    escapes ``[``/``]`` for Rich markup safety, it does not remove the plain
    uppercase keywords (``CREATE``, ``DELETE``, ...) the rules match on.
    """
    for keywords, color in FSMON_COLOR_RULES:
        if any(kw in message for kw in keywords):
            return _CATEGORY_BY_COLOR.get(color)
    return None


class MonitorView(FilesSubViewBase):
    """Files tab sub-view: fsmon status header + live event-stream log."""

    _LABEL = "Monitor"

    can_focus = True

    BINDINGS = [
        ("enter", "toggle_running", "Start/Stop"),
        ("ctrl+l", "clear_log", "Clear log"),
    ]

    DEFAULT_CSS = """
    MonitorView {
        layout: vertical;
        padding: 0;
    }
    MonitorView > #monitor-header {
        height: 1;
        color: #38bdf8;
        text-style: bold;
        padding: 0 1;
    }
    MonitorView > #monitor-log {
        height: 1fr;
        background: #050811;
        scrollbar-size: 1 1;
    }
    MonitorView > #monitor-resume-bar {
        height: 1;
        background: #1f2937;
    }
    MonitorView > #monitor-resume-bar.-hidden {
        display: none;
    }
    MonitorView > #monitor-resume-bar > #monitor-resume-label {
        width: 1fr;
        color: #facc15;
        padding: 0 1;
        content-align: left middle;
    }
    MonitorView > #monitor-resume-bar > #monitor-resume-btn {
        min-width: 22;
        height: 1;
        border: none;
        background: #facc15;
        color: #1f2937;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        self._main_loop = None
        self._event_handlers: list = []
        # Glance/header counters. fsmon has no notion of these itself, so
        # they are purely client-side tallies of what has streamed through
        # this view — reset on a fresh TASK_STARTED("fsmon"), not on unmount,
        # so switching sub-tabs and back doesn't lose the running count.
        self._total = 0
        self._create = 0
        self._delete = 0
        self._rename = 0
        self._access = 0
        # The FSMonConfig fsmon was running with before Play's safety-net
        # auto-stopped it (see recording_controller._stop_fsmon_before_
        # revert) — stashed here so the "Resume monitoring" button can hand
        # it back to FSMonController.resume_after_playback(). None whenever
        # no resume offer is pending.
        self._resume_config: Any = None
        # tui.fsmon_max_lines -- see module docstring's "Log cap" section.
        self._max_lines = self._get_config_max_lines()

    # -- compose / mount ---------------------------------------------------

    def compose(self):
        yield Static(self._render_header(), id="monitor-header")
        with Horizontal(id="monitor-resume-bar", classes="-hidden"):
            yield Static("", id="monitor-resume-label")
            yield Button("Resume monitoring", id="monitor-resume-btn")
        yield RichLog(
            highlight=False,
            markup=True,
            wrap=False,
            auto_scroll=True,
            max_lines=self._max_lines,
            id="monitor-log",
        )

    def on_mount(self) -> None:
        self._subscribe_events()
        try:
            self.query_one("#monitor-log", RichLog).write(
                "[#5b6479]Enter: start/stop · Ctrl+L: clear · press 'o' to configure[/]"
            )
        except Exception:
            pass
        self.refresh_header()

    def on_unmount(self) -> None:
        self._unsubscribe_events()

    @staticmethod
    def _get_config_max_lines() -> int:
        """Read ``tui.fsmon_max_lines`` from config.

        Mirrors ``FSMonController._get_buffer_interval``'s read pattern (same
        ``ConfigLoader().load()`` call, same try/except-to-default shape) --
        the sibling read for the sibling config field in the same feature
        area. Falls back to the schema's own default (500) on any error, so
        a missing/corrupt config file still yields a bounded log rather than
        an unbounded one.
        """
        try:
            from sandroid.config.loader import ConfigLoader

            loader = ConfigLoader()
            config = loader.load()
            return config.tui.fsmon_max_lines
        except Exception:
            return 500

    # -- FilesPanel hooks ----------------------------------------------------

    def on_activated(self) -> None:
        """Called by ``FilesPanel._select_subtab`` when Monitor becomes active."""
        self.refresh_header()

    def glance_fragment(self) -> str:
        running = False
        try:
            running = bool(get_task_service().is_running("fsmon"))
        except Exception:
            pass
        if running:
            return f"fsmon ● running · {self._total} events"
        return "fsmon ○ stopped"

    # -- EventBus wiring (non-blocking, thread-safe) ------------------------

    def _subscribe_events(self) -> None:
        try:
            import asyncio

            from sandroid.core.events import EventBus, EventType

            try:
                self._main_loop = asyncio.get_running_loop()
            except RuntimeError:
                self._main_loop = None

            bus = EventBus.get()

            def _schedule(fn, *args) -> None:
                # Fire-and-forget onto the main loop; never blocks the
                # publisher's thread (avoids the call_from_thread deadlock —
                # see FriTapPanel/FilesPanel for the same idiom).
                loop = self._main_loop
                try:
                    if loop is not None and not loop.is_closed():
                        loop.call_soon_threadsafe(fn, *args)
                except RuntimeError:
                    pass

            def _output_cb(event) -> None:
                _schedule(self._on_task_output, event)

            bus.subscribe(EventType.TASK_OUTPUT, _output_cb)
            self._event_handlers.append((EventType.TASK_OUTPUT, _output_cb))

            def _started_cb(event) -> None:
                data = getattr(event, "data", None) or {}
                if data.get("task_name") != "fsmon":
                    return
                _schedule(self._on_fsmon_started)

            bus.subscribe(EventType.TASK_STARTED, _started_cb)
            self._event_handlers.append((EventType.TASK_STARTED, _started_cb))

            def _stopped_cb(event) -> None:
                data = getattr(event, "data", None) or {}
                if data.get("task_name") != "fsmon":
                    return
                _schedule(self.refresh_header)

            bus.subscribe(EventType.TASK_STOPPED, _stopped_cb)
            self._event_handlers.append((EventType.TASK_STOPPED, _stopped_cb))
        except Exception as exc:
            logger.debug(f"MonitorView event subscribe failed: {exc}")

    def _unsubscribe_events(self) -> None:
        try:
            from sandroid.core.events import EventBus

            bus = EventBus.get()
            for event_type, cb in self._event_handlers:
                bus.unsubscribe(event_type, cb)
        except Exception:
            pass
        self._event_handlers = []

    def _on_task_output(self, event) -> None:
        """Handle a TASK_OUTPUT event (runs on the UI thread).

        Source-only match, same reasoning as ``FriTapPanel``: another task
        that happens to share the "FSMon" display name must not leak into
        this view, so filter on ``event.source == "fsmon"`` and nothing else.
        """
        if getattr(event, "source", None) != "fsmon":
            return
        data = getattr(event, "data", None) or {}
        message = data.get("message", "")
        if message:
            self._append_line(message)

    def _on_fsmon_started(self) -> None:
        """A fresh fsmon session started — reset the client-side tally.

        Also clears any pending "Resume monitoring" offer: whether fsmon
        just (re-)started via this button, the global 'o' key, or any other
        path, a stale offer referring to an already-superseded config would
        only confuse the user.
        """
        self._total = self._create = self._delete = self._rename = self._access = 0
        self.clear_resume_offer()
        self.refresh_header()

    # -- Play safety-net notice + "Resume monitoring" offer -----------------

    def notify_fsmon_stopped_for_playback(self) -> None:
        """Inline notice: Play's snapshot revert safety-net auto-stopped fsmon.

        Invoked via app.py's ``on_fsmon_stopped_for_playback`` callback,
        itself invoked (via ``call_from_thread``, so always on the main
        thread by the time this runs) from
        ``RecordingController._stop_fsmon_before_revert``. Written directly
        to the log rather than through ``_append_line`` so it does NOT bump
        the live-event tally/category counters — this is a system notice
        about fsmon's lifecycle, not an fsmon-reported filesystem event.
        ``refresh_header`` picks up the now-stopped TaskService state
        (already refreshed once by the TASK_STOPPED subscription, but
        calling it again here is harmless and keeps this method
        self-contained).
        """
        try:
            self.query_one("#monitor-log", RichLog).write(
                "[#facc15]⚠ fsmon stopped — won't survive Play's snapshot revert.[/]"
            )
        except Exception:
            pass
        self.refresh_header()

    def offer_resume(self, config: Any) -> None:
        """Show the one-click "Resume monitoring" bar once Play has finished.

        ``config`` is the (possibly PID-stale) FSMonConfig fsmon was running
        with before the Play-triggered auto-stop. Stashed on this view so
        the button handler can hand it back to
        ``FSMonController.resume_after_playback`` — this view never
        resolves PIDs or re-forks fsmon itself, it only presents the offer.
        """
        self._resume_config = config
        try:
            target = "?"
            if config is not None:
                if getattr(config, "mode", None) == "pid" and getattr(
                    config, "app_name", None
                ):
                    target = f"{config.app_name} (pid mode)"
                elif getattr(config, "target_path", None):
                    target = config.target_path
            self.query_one("#monitor-resume-label", Static).update(
                f"fsmon was stopped for Play — {target}"
            )
            self.query_one("#monitor-resume-bar").remove_class("-hidden")
        except Exception:
            pass

    def clear_resume_offer(self) -> None:
        """Hide the Resume bar and drop the stashed config."""
        self._resume_config = None
        try:
            self.query_one("#monitor-resume-bar").add_class("-hidden")
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle the "Resume monitoring" button.

        Delegates entirely to ``App.resume_fsmon_after_playback``, which
        calls ``FSMonController.resume_after_playback`` (PID re-resolution
        and the path-mode/refuse-to-start fallbacks live there — this view
        stays a thin presentation layer, same division of responsibility as
        ``action_toggle_running`` delegating Start/Stop to
        ``app.action_fsmon()``). Left showing on failure (rather than
        auto-hidden) so the user can retry — e.g. after manually relaunching
        the target app — without losing the offer; a successful resume
        clears it automatically via the TASK_STARTED -> _on_fsmon_started
        path.
        """
        if event.button.id != "monitor-resume-btn":
            return
        event.stop()
        config = self._resume_config
        try:
            self.app.resume_fsmon_after_playback(config)
        except Exception:
            logger.warning("Resume monitoring failed", exc_info=True)

    # -- log rendering ----------------------------------------------------

    def _append_line(self, message: str) -> None:
        try:
            log = self.query_one("#monitor-log", RichLog)
        except Exception:
            return
        log.write(message)

        self._total += 1
        category = _categorize_fsmon_line(message)
        if category == "create":
            self._create += 1
        elif category == "delete":
            self._delete += 1
        elif category == "rename":
            self._rename += 1
        elif category == "access":
            self._access += 1

        self.refresh_header()

    # -- header -----------------------------------------------------------

    def _render_header(self) -> str:
        running = False
        task = None
        try:
            svc = get_task_service()
            running = bool(svc.is_running("fsmon"))
            task = svc.get_task("fsmon")
        except Exception:
            pass

        if not running:
            return "[#fb7185]○ stopped[/]"

        inst = getattr(task, "instance", None)
        config = getattr(inst, "config", None)

        target_desc = "?"
        if (
            config is not None
            and getattr(config, "mode", None) == "pid"
            and getattr(config, "target_pid", None)
        ):
            target_desc = f"pid {config.target_pid}"
            if getattr(config, "app_name", None):
                target_desc += f"  [#5b6479]{config.app_name}[/]"
        elif config is not None and getattr(config, "target_path", None):
            target_desc = f"path {config.target_path}"
        elif task is not None:
            # Fallback to TaskService's own fields if the wrapper/config
            # isn't reachable for some reason.
            target_desc = getattr(task, "app_name", None) or (
                f"pid {task.target_pid}" if getattr(task, "target_pid", None) else "?"
            )

        head = f"[#4ade80]● running[/]   [b]{target_desc}[/]"
        counters = (
            f"events [b]{self._total}[/]  "
            f"[#4ade80]{self._create}c[/]  "
            f"[#fb7185]{self._delete}d[/]  "
            f"[#facc15]{self._rename}r[/]  "
            f"[#7dd3fc]{self._access}a[/]"
        )
        return f"{head}   {counters}"

    def refresh_header(self) -> None:
        """Re-render the status header (main thread; best-effort).

        Public so ``MainScreen._select_bottom_tab``/``FilesPanel`` can
        refresh it the moment Monitor is activated, avoiding a stale header
        (same reasoning as ``FriTapPanel.refresh_header``).
        """
        try:
            self.query_one("#monitor-header", Static).update(self._render_header())
        except Exception:
            pass

    # -- actions ----------------------------------------------------------

    def action_toggle_running(self) -> None:
        """Enter — delegate Start/Stop to the existing fsmon command (key o).

        ``action_fsmon`` owns ALL preconditions (config modal, task
        registration, the "already running -> stop" toggle) — this just
        triggers it, exactly like ``FriTapPanel.action_toggle_running``
        delegates to ``action_action_key("h")`` rather than duplicating
        friTap's start/stop logic.
        """
        try:
            self.app.action_fsmon()
        except Exception as exc:
            logger.warning("fsmon toggle failed: %s", exc)
        self.refresh_header()

    def action_clear_log(self) -> None:
        try:
            self.query_one("#monitor-log", RichLog).clear()
        except Exception:
            pass
        self._total = self._create = self._delete = self._rename = self._access = 0
        self.refresh_header()
