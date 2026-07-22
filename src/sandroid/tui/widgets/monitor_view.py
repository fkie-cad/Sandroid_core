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
to publish each flush batch as ONE ``EventType.TASK_OUTPUT`` event with
``source="fsmon"`` and ``data["batch"]`` a list of structured
``FSMonDisplayItem``s (one per parsed line -- see ``_publish_fsmon_batch``
there, mirrors ``analysis/fritap.py``'s ``_publish_fritap_event``). This view
is the consumer of that stream and gets the FULL, un-throttled feed --
grouping/dedup/visibility-filtering/tallying/width-aware rendering all live
HERE (not in the controller): the controller only parses+categorizes+
prefix-strips each line, this view decides how the result looks, since it's
the only place with a real widget reference (needed for width-aware
truncation) and the "always tally, conditionally render" invariant the
header/badge depend on (see the monitor follow-up plan's "Part B"/B1 for the
full reasoning -- an earlier draft that computed grouping in the controller
was rejected by two independent review passes for exactly this reason).

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
    v:      toggle the session-only "verbose" mode, revealing categories
            configured as ``tui.fsmon_event_visibility`` = "verbose" (e.g.
            OPEN/CLOSE "noise" by default) going forward, not retroactively
    u:      toggle the session-only "full path" view: bypasses grouping/dedup
            entirely and shows every passing-the-gate event on its own row
            with the complete, untruncated path (wrapped, never cut off),
            going forward only -- same forward-only semantics as 'v'

Grouped/compact view (the default -- see B2 of the monitor follow-up plan):
one batch's passing-the-gate items are walked in order, tracking the current
directory-run; a run of 2+ consecutive same-directory items gets a
``▸ <directory>/`` breadcrumb once, with just the filename shown per row
underneath; an isolated single-directory item renders inline (directory +
filename together, truncated to the RichLog's own rendered content width);
consecutive items sharing the exact same (directory, filename, label)
collapse into one row with a trailing "xN" counter. Renames show
``old_filename -> new_filename`` when grouped under a breadcrumb and the
rename didn't also change directory, else full relative paths on both
sides. Grouping only ever considers state within one batch (no cross-batch
run continuation) -- the reader thread flushes every ``fsmon_buffer_
interval`` (default 0.15s) already, so this is a rare, self-limiting
cosmetic edge case, not a correctness concern.

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
from datetime import datetime
from typing import TYPE_CHECKING, Any

from rich.markup import escape
from textual.containers import Horizontal
from textual.widgets import Button, RichLog, Static

from sandroid.services import get_task_service

from .files_panel import FilesSubViewBase

if TYPE_CHECKING:
    from sandroid.tui.controllers.fsmon_controller import FSMonDisplayItem

logger = logging.getLogger(__name__)


class MonitorView(FilesSubViewBase):
    """Files tab sub-view: fsmon status header + live event-stream log."""

    _LABEL = "Monitor"

    can_focus = True

    BINDINGS = [
        ("enter", "toggle_running", "Start/Stop"),
        ("ctrl+l", "clear_log", "Clear log"),
        ("v", "toggle_verbose", "Verbose"),
        ("u", "toggle_view_mode", "Untruncated"),
    ]

    # Fixed constant (not user-configurable this pass -- see B5 of the
    # monitor follow-up plan): a directory-run needs at least this many
    # consecutive same-directory items before it gets a breadcrumb; shorter
    # runs render inline instead.
    _GROUP_THRESHOLD = 2
    # Sane fallback truncation width for the grouped/isolated-item and
    # full-path-wrap cases when #monitor-log's real rendered content width
    # isn't available yet (e.g. before first layout).
    _FALLBACK_WIDTH = 70

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
        self._modify = 0
        self._delete = 0
        self._rename = 0
        self._attrs = 0
        self._noise = 0
        # The FSMonConfig fsmon was running with before Play's safety-net
        # auto-stopped it (see recording_controller._stop_fsmon_before_
        # revert) — stashed here so the "Resume monitoring" button can hand
        # it back to FSMonController.resume_after_playback(). None whenever
        # no resume offer is pending.
        self._resume_config: Any = None
        # tui.fsmon_max_lines -- see module docstring's "Log cap" section.
        self._max_lines = self._get_config_max_lines()
        # tui.fsmon_event_visibility -- per-category Always/Verbose/Never
        # mode, read once at construction (mirrors _get_config_max_lines).
        self._visibility: dict[str, str] = self._get_config_visibility()
        # Session-only "show verbose-tier categories too" toggle (key 'v'),
        # not persisted -- forward-only (see action_toggle_verbose).
        self._verbose: bool = False
        # Session-only "show full, untruncated paths" toggle (key 'u'), not
        # persisted -- forward-only, same semantics as _verbose (see
        # action_toggle_view_mode). When True, batch processing bypasses ALL
        # grouping/dedup (B3 of the monitor follow-up plan).
        self._full_path_view: bool = False

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
                "[#5b6479]Enter: start/stop · Ctrl+L: clear · "
                "v: verbose · u: untruncated · press 'o' to configure[/]"
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

    @staticmethod
    def _get_config_visibility() -> dict[str, str]:
        """Read ``tui.fsmon_event_visibility`` from config.

        Mirrors ``_get_config_max_lines``'s read pattern. Falls back to an
        empty dict on any error, so ``.get(category, "always")`` downstream
        just defaults everything to "always" if config is unreadable.
        """
        try:
            from sandroid.config.loader import ConfigLoader

            loader = ConfigLoader()
            config = loader.load()
            return dict(config.tui.fsmon_event_visibility)
        except Exception:
            return {}

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

        Part B change: the event now carries a whole BATCH of structured
        ``FSMonDisplayItem``s (``data["batch"]``, see ``fsmon_controller.py``'s
        ``_log_fsmon_output_batch``/``_publish_fsmon_batch``) instead of one
        pre-rendered message string -- ``_process_batch`` does the tallying/
        visibility-gating/grouping/rendering this view now owns entirely.
        """
        if getattr(event, "source", None) != "fsmon":
            return
        data = getattr(event, "data", None) or {}
        batch = data.get("batch")
        if batch:
            self._process_batch(batch)

    def _on_fsmon_started(self) -> None:
        """A fresh fsmon session started — reset the client-side tally.

        Also clears any pending "Resume monitoring" offer: whether fsmon
        just (re-)started via this button, the global 'o' key, or any other
        path, a stale offer referring to an already-superseded config would
        only confuse the user.
        """
        self._total = self._create = self._modify = self._delete = 0
        self._rename = self._attrs = self._noise = 0
        self.clear_resume_offer()
        self.refresh_header()

    # -- Play safety-net notice + "Resume monitoring" offer -----------------

    def notify_fsmon_stopped_for_playback(self) -> None:
        """Inline notice: Play's snapshot revert safety-net auto-stopped fsmon.

        Invoked via app.py's ``on_fsmon_stopped_for_playback`` callback,
        itself invoked (via ``call_from_thread``, so always on the main
        thread by the time this runs) from
        ``RecordingController._stop_fsmon_before_revert``. Written directly
        to the log rather than through ``_process_batch``/``_tally_category``
        so it does NOT bump the live-event tally/category counters — this is
        a system notice
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

    def notify_pid_mode_fallback(self, path: str) -> None:
        """Inline notice: PID-mode silently fell back to path-mode.

        Invoked via app.py's ``_notify_pid_mode_fallback`` callback, itself
        invoked directly (no thread marshaling -- ``_start_fsmon`` already
        runs on the main thread) from
        ``FSMonController._start_fsmon``'s PID-mode branch when
        ``FSMon.fanotify_supported()`` reports the device's kernel lacks
        fanotify. Mirrors ``notify_fsmon_stopped_for_playback`` exactly:
        written directly to the log rather than through
        ``_process_batch``/``_tally_category`` so it does NOT bump the
        live-event tally/category counters -- this is a system notice about
        fsmon's lifecycle, not an fsmon-reported filesystem event.
        """
        try:
            log = self.query_one("#monitor-log", RichLog)
            # Found during E2E testing on a real (narrow-terminal) run: this
            # notice was written unwrapped even though #monitor-log is
            # wrap=False, so its tail end could get clipped -- inconsistent
            # with the rest of this view's "never cut off" design goal (see
            # the full-path view). Wrap it the same way (B3's helper).
            message = f"⚠ PID mode unavailable (no fanotify) — monitoring {path} by path instead."
            for i, line in enumerate(
                self._wrap_text_on_slash(message, self._content_width())
            ):
                prefix = "  " if i > 0 else ""
                log.write(f"[#facc15]{prefix}{escape(line)}[/]")
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

    # -- batch processing (tally + visibility gate) ------------------------

    def _tally_category(self, category: str | None) -> None:
        """Bump the client-side event counters -- UNCONDITIONALLY.

        This must run for every item in a batch regardless of whether it
        ends up rendered, collapsed into an "xN" row, or hidden inside a
        directory breadcrumb group -- the header's per-category counts and
        the ``+N hidden (v)`` badge depend on this invariant (see the
        monitor follow-up plan's B1 "Defect 1": a controller-side pre-filter
        or pre-collapse would silently undercount). ``category`` of
        ``None``/unrecognized doesn't bump any counter (mirrors the old
        ``_append_line``'s behavior exactly).
        """
        self._total += 1
        if category == "create":
            self._create += 1
        elif category == "modify":
            self._modify += 1
        elif category == "delete":
            self._delete += 1
        elif category == "rename":
            self._rename += 1
        elif category == "attrs":
            self._attrs += 1
        elif category == "noise":
            self._noise += 1

    def _is_visible(self, category: str | None) -> bool:
        """Same always/verbose/never gate the old ``_append_line`` used.

        ``category`` of ``None``/unrecognized always renders (better to show
        something unexpected than silently hide it).
        """
        if not category:
            return True
        mode = self._visibility.get(category, "always")
        return mode == "always" or (mode == "verbose" and self._verbose)

    def _process_batch(self, batch: list[FSMonDisplayItem]) -> None:
        """Process one whole batch of parsed fsmon items (see B1/B2/B3).

        Order of operations is the exact invariant B1 requires:
        1. Tally + visibility-gate EVERY item, unconditionally, first --
           counters/the hidden badge must reflect every item regardless of
           what rendering does with it next.
        2. Only over the items that passed the gate (in original order), do
           either the grouping/dedup pass (default grouped view) or a
           one-row-per-item full, untruncated render (the 'u' toggle) --
           purely a display concern from here on, it doesn't touch any
           counter.
        """
        visible_items: list[FSMonDisplayItem] = []
        for item in batch:
            category = item.category
            self._tally_category(category)
            if self._is_visible(category):
                visible_items.append(item)

        if visible_items:
            log = self._get_log()
            if log is not None:
                if self._full_path_view:
                    self._render_full_path(visible_items, log)
                else:
                    self._render_grouped(visible_items, log)

        self.refresh_header()

    def _get_log(self) -> RichLog | None:
        try:
            return self.query_one("#monitor-log", RichLog)
        except Exception:
            return None

    def _content_width(self) -> int:
        """Best-effort read of ``#monitor-log``'s real rendered content width.

        ``content_size.width`` (not ``.size.width``, which includes the CSS
        scrollbar gutter -- ``scrollbar-size: 1 1`` above) excludes it.
        Falls back to ``_FALLBACK_WIDTH`` when unavailable (e.g. before
        first layout) rather than hard-coding a fixed truncation width
        regardless of real available space.
        """
        try:
            log = self.query_one("#monitor-log", RichLog)
            width = log.content_size.width
            if width and width > 0:
                return width
        except Exception:
            pass
        return self._FALLBACK_WIDTH

    # -- grouped/compact view (default) --------------------------------------

    @staticmethod
    def _directory_runs(
        items: list[FSMonDisplayItem],
    ) -> list[tuple[str, list[FSMonDisplayItem]]]:
        """Group CONSECUTIVE items by exact ``.directory`` match.

        Renames group by their OLD directory (``.directory``, not
        ``.new_directory``) -- a rename joins the run of the directory it
        originated from.
        """
        runs: list[tuple[str, list[FSMonDisplayItem]]] = []
        current_dir: str | None = None
        current_run: list[FSMonDisplayItem] = []
        for item in items:
            if current_run and item.directory == current_dir:
                current_run.append(item)
            else:
                if current_run:
                    runs.append((current_dir or "", current_run))
                current_dir = item.directory
                current_run = [item]
        if current_run:
            runs.append((current_dir or "", current_run))
        return runs

    @staticmethod
    def _collapse_consecutive(
        run: list[FSMonDisplayItem],
    ) -> list[tuple[FSMonDisplayItem, int]]:
        """Collapse consecutive items sharing the same displayed identity.

        Rendering-only -- tallying already happened, unconditionally, in
        ``_process_batch`` before this ever runs, so this collapsing cannot
        undercount anything (B1's "Defect 1" again: the count is preserved
        in the returned ``int``, not lost).
        """
        collapsed: list[tuple[FSMonDisplayItem, int]] = []
        prev_key: tuple | None = None
        prev_item: FSMonDisplayItem | None = None
        count = 0
        for item in run:
            key = (
                item.directory,
                item.filename,
                item.label,
                item.new_directory,
                item.new_filename,
            )
            if key == prev_key:
                count += 1
            else:
                if prev_item is not None:
                    collapsed.append((prev_item, count))
                prev_item = item
                prev_key = key
                count = 1
        if prev_item is not None:
            collapsed.append((prev_item, count))
        return collapsed

    def _render_grouped(self, items: list[FSMonDisplayItem], log: RichLog) -> None:
        """Grouped/compact rendering pass -- see B2.

        Only ever called with items that already passed the visibility
        gate; purely a layout/dedup concern, tallies nothing.
        """
        width = self._content_width()
        for directory, run in self._directory_runs(items):
            in_run = len(run) >= self._GROUP_THRESHOLD
            if in_run:
                self._write_breadcrumb(directory, log)
            for collapsed_item, count in self._collapse_consecutive(run):
                self._write_row(collapsed_item, count, in_run, width, log)

    def _write_breadcrumb(self, directory: str, log: RichLog) -> None:
        try:
            log.write(f"[#5b6479]▸ {escape(directory)}/[/]")
        except Exception:
            pass

    @staticmethod
    def _label_markup(item: FSMonDisplayItem) -> str:
        if not item.label:
            return ""
        text = escape(item.label)
        if item.color:
            return f"[{item.color}]{text:<10}[/]"
        return f"{text:<10}"

    @staticmethod
    def _join_path(directory: str, filename: str) -> str:
        return f"{directory}/{filename}" if directory else filename

    @classmethod
    def _truncate_keep_tail(cls, text: str, width: int) -> str:
        if len(text) > width:
            return "…" + text[-(width - 1) :]
        return text

    def _format_path_segment(
        self, item: FSMonDisplayItem, in_run: bool, width: int
    ) -> str:
        """The path portion of a row for a NON-rename item.

        Inside a directory-run (breadcrumb already shown above) -> just the
        filename. Isolated (no breadcrumb) -> directory + filename combined,
        truncated (keep-tail, mirrors ``watchlist_view.py``'s idiom) to the
        real rendered width.
        """
        if in_run:
            return escape(item.filename)
        combined = self._join_path(item.directory, item.filename)
        return escape(self._truncate_keep_tail(combined, width))

    def _format_rename_segment(
        self, item: FSMonDisplayItem, in_run: bool, width: int
    ) -> str:
        """The path portion of a row for a rename item.

        Short form (``old_filename -> new_filename``) only when BOTH: grouped
        under a breadcrumb, AND the rename didn't also change directory
        (the common case -- the breadcrumb's directory correctly describes
        both endpoints). Otherwise (isolated, or the rename moved the file to
        a different directory) falls back to full relative paths on both
        sides, truncated independently.
        """
        same_dir = item.new_directory == item.directory
        if in_run and same_dir:
            return f"{escape(item.filename)} -> {escape(item.new_filename or '')}"

        old_full = self._truncate_keep_tail(
            self._join_path(item.directory, item.filename), width
        )
        new_full = self._truncate_keep_tail(
            self._join_path(item.new_directory or "", item.new_filename or ""),
            width,
        )
        return f"{escape(old_full)} -> {escape(new_full)}"

    def _write_row(
        self,
        item: FSMonDisplayItem,
        count: int,
        in_run: bool,
        width: int,
        log: RichLog,
    ) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        label_part = self._label_markup(item)
        if item.new_filename is not None:
            path_part = self._format_rename_segment(item, in_run, width)
        else:
            path_part = self._format_path_segment(item, in_run, width)

        row = f"{ts}  {label_part}  {path_part}" if label_part else f"{ts}  {path_part}"
        if count > 1:
            row += f"  [#5b6479]×{count}[/]"
        try:
            log.write(row)
        except Exception:
            pass

    # -- full-path view (toggleable, key 'u') --------------------------------

    def _render_full_path(self, items: list[FSMonDisplayItem], log: RichLog) -> None:
        """Full-path rendering pass -- entirely bypasses grouping/dedup.

        Every item gets its own row with the complete, untruncated path
        (prefix-stripped only, no truncation) -- see B3. ``#monitor-log`` is
        ``wrap=False`` (needed for the grouped view's column alignment), so
        long rows are manually pre-wrapped into indented continuation lines
        rather than relying on RichLog's own auto-wrap.
        """
        width = self._content_width()
        for item in items:
            self._write_full_path_row(item, width, log)

    @staticmethod
    def _wrap_text_on_slash(text: str, width: int) -> list[str]:
        """Break ``text`` into chunks of at most ``width`` chars.

        Prefers breaking at a ``/`` within a small lookback window near the
        wrap boundary (keeps path segments intact); hard-breaks otherwise --
        this view's whole point is completeness over aesthetics, so a
        mid-hash break in a worst-case long filename is acceptable (B3).
        """
        if width <= 0:
            width = 1
        if len(text) <= width:
            return [text]

        chunks: list[str] = []
        remaining = text
        lookback = min(15, width)
        while len(remaining) > width:
            window_start = max(width - lookback, 1)
            slash_idx = remaining.rfind("/", window_start, width)
            break_at = slash_idx + 1 if slash_idx != -1 else width
            chunks.append(remaining[:break_at])
            remaining = remaining[break_at:]
        if remaining:
            chunks.append(remaining)
        return chunks

    def _write_full_path_row(
        self, item: FSMonDisplayItem, width: int, log: RichLog
    ) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        label_markup = self._label_markup(item)

        if item.new_filename is not None:
            old_full = self._join_path(item.directory, item.filename)
            new_full = self._join_path(item.new_directory or "", item.new_filename)
            path_text = f"{old_full} -> {new_full}"
        else:
            path_text = self._join_path(item.directory, item.filename)

        prefix = f"{ts}  {label_markup}  " if label_markup else f"{ts}  "
        # Visible-width overhead of the prefix (timestamp + optional
        # 10-wide label + separating spaces) -- markup tags themselves are
        # zero-width once rendered, so they're excluded from this count.
        visible_prefix_len = len(ts) + 2 + (12 if label_markup else 0)
        available = max(width - visible_prefix_len, 10)
        indent = " " * visible_prefix_len

        for i, chunk in enumerate(self._wrap_text_on_slash(path_text, available)):
            text = escape(chunk)
            row = f"{prefix}{text}" if i == 0 else f"{indent}{text}"
            try:
                log.write(row)
            except Exception:
                pass

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
            f"[#a78bfa]{self._modify}m[/]  "
            f"[#fb7185]{self._delete}d[/]  "
            f"[#facc15]{self._rename}r[/]  "
            f"[#7dd3fc]{self._attrs}a[/]"
        )
        badge = ""
        if not self._verbose:
            counts_by_category = {
                "create": self._create,
                "modify": self._modify,
                "delete": self._delete,
                "rename": self._rename,
                "attrs": self._attrs,
                "noise": self._noise,
            }
            hidden = sum(
                count
                for category, count in counts_by_category.items()
                if self._visibility.get(category, "always") == "verbose"
            )
            if hidden > 0:
                badge = f"  [#5b6479]+{hidden} hidden (v)[/]"
        return f"{head}   {counters}{badge}"

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
        self._total = self._create = self._modify = self._delete = 0
        self._rename = self._attrs = self._noise = 0
        self.refresh_header()

    def action_toggle_verbose(self) -> None:
        """Key 'v' — reveal/hide verbose-tier categories going forward.

        Forward-only (matches ``WatchlistView``'s existing auto-mode toggle
        precedent): toggling on reveals subsequent verbose-tier events, it
        does not retroactively replay lines already skipped. A category
        configured to "never" stays hidden regardless of this toggle.
        """
        self._verbose = not self._verbose
        state = "shown" if self._verbose else "hidden"
        try:
            self.query_one("#monitor-log", RichLog).write(
                f"[#5b6479]— Verbose {state} —[/]"
            )
        except Exception:
            pass
        self.refresh_header()

    def action_toggle_view_mode(self) -> None:
        """Key 'u' — toggle the full, untruncated-path view on/off.

        Forward-only, same semantics as ``action_toggle_verbose``: only
        affects how SUBSEQUENT batches render, doesn't retroactively
        reformat rows already written to the log (see B4 of the monitor
        follow-up plan).
        """
        self._full_path_view = not self._full_path_view
        state = "on" if self._full_path_view else "off"
        try:
            self.query_one("#monitor-log", RichLog).write(
                f"[#5b6479]— Full paths {state} —[/]"
            )
        except Exception:
            pass
        self.refresh_header()
