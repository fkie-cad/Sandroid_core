"""Files lens: one table of live file activity, with watch marks.

One question per screen -- *what is the app writing, and what changed in
it?* -- answered by ONE full-width table, collapsed per file::

    ★ shared_prefs/consent.xml    M    3x  10:42:07
    ★ databases/app.db            CM  11x  10:42:05
      cache/okhttp/journal        M   40x  10:41:58   (noise: hidden by default)
      files/aaid.txt              C    1x  10:40:12

Rows come from the file monitor (``o`` starts/stops it): each
``TASK_OUTPUT``/``source="monitor"`` batch is folded into
:class:`~sandroid.tui.widgets.monitor_view.FileActivity` (tally, per-path
collapse, noise/visibility rules). Watched files -- the Spotlight-Files
watchlist owned by the hidden
:class:`~sandroid.tui.widgets.watchlist_view.WatchlistView` engine -- carry
★ and are pinned on top, also before they saw any activity (wildcard
patterns included). Details live in the Inspector only (Enter): Summary
(full path, ops with times, processes, watch + last pull), Versions (every
kept pull, newest first; the selected one's structured diff against the
version before it or a marked base), Content (a first look inside the
selected version's local copy) and Events -- see ``file_inspect``. The Inspector forwards the lens keys it
advertises while it has focus (``lens_shell.Inspector.on_key``).

Keys (on this lens): ``w`` watch/unwatch · ``u`` pull the row · ``U`` pull
all watched · ``/`` filter · ``n`` watch a path or pattern that is not in
the table · ``a`` auto-pull · ``N`` show noise (as in the Network lens) ·
``.`` full paths · ``z`` zoom the diff · ``O`` sort (recent / name /
count) · ``Home``/``End`` first/last row · ``Ctrl+L`` clear. Only
``w``/``u`` are shown in the footer (the rest are in ``?``).

REVIEW scope (``MainScreen.set_scope(run_dir)``): the same table lists the
run's changed/new/deleted files (from the run's ``RunRecord``, the data the
Runs lens shows) and Enter shows that file's diff for the run.

The inline input (``/`` and ``n``) must swallow Escape itself: the App binds
Escape with ``priority=True`` (quit confirmation), so :class:`_LensInput`
claims the key in ``check_consume_key``, which filters it out of every
ancestor's binding map -- see the same trick in the old Watchlist view.

Thread-safety: EventBus callbacks are marshalled with
``loop.call_soon_threadsafe`` (never ``call_from_thread``, which would
deadlock a publisher on a background thread).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.table import Table
from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, Static

from sandroid.core.adb_utils import watch_path_problem
from sandroid.tui.utils.ui_thread import UiDispatcher

from . import file_inspect
from .lens_shell import InspectorContent, is_shown
from .monitor_view import (
    OPS,
    SOURCE_TEXT,
    FileActivity,
    PathActivity,
    app_package,
    app_relative,
    smart_truncate,
)
from .watchlist_view import RowState, WatchlistView
from .watchlist_view import is_database_path as _is_database

if TYPE_CHECKING:
    from datetime import datetime

    from textual.app import ComposeResult

    from .lens_shell import ScopeChanged

logger = logging.getLogger(__name__)

#: How often a dirty table is redrawn (monitor batches arrive every ~0.15 s).
_REFRESH_INTERVAL = 0.4

#: Fixed column widths (★, ops, count, last); the path takes the rest.
_W_MARK, _W_OPS, _W_COUNT, _W_LAST = 1, 5, 5, 8

_DIM = "#5b6479"
_STAR = "#7dd3fc"
_STATE_STAR = {
    RowState.CHANGED: "bold #facc15",
    RowState.ERROR: "bold #ef4444",
    RowState.SETTLING: "#a3873f",
}


def _load_run_record(scope: str):
    """The ``RunRecord`` of the run under review (``scope`` = run directory).

    Same loader as the Runs lens (``run_history.run_dir_for_scope`` +
    ``load_run_dir``); raises ``RunHistoryError`` for an unknown run.
    """
    from sandroid.core import run_history

    run_dir = run_history.run_dir_for_scope(scope)
    if run_dir is None:
        raise run_history.RunHistoryError(f"No run in '{scope}'")
    return run_history.load_run_dir(run_dir)


def render_diff(diff: str | list[str] | None) -> Text:
    """A diff (DiffView's markup lines) as one Rich ``Text``.

    Same size rule as :class:`~sandroid.tui.widgets.diff_view.DiffView`:
    below ``SOFT_LINE_THRESHOLD`` lines everything, else a ``PREVIEW_LINES``
    preview and a pointer to the zoom view (``z``).
    """
    from .diff_view import DiffView

    lines = diff.splitlines() if isinstance(diff, str) else list(diff or [])
    shown = lines
    if len(lines) >= DiffView.SOFT_LINE_THRESHOLD:
        shown = lines[: DiffView.PREVIEW_LINES]
    out = Text()
    for i, line in enumerate(shown):
        line = line.replace("\t", "  ")  # file_diff indents with tabs
        if i:
            out.append("\n")
        out.append_text(diff_line_text(line))
    if len(shown) < len(lines):
        out.append(f"\n… {len(lines)} lines — z for the full diff", style=_DIM)
    return out


#: Style tags the diff producers really use (SQLite diffs, run records). A
#: line without one is plain text: XML paths such as ``string[@name="k"]``
#: and file content must not be parsed as Rich markup (``[@...]`` is a tag
#: to Rich, so the key name of a changed preference used to vanish).
_MARKUP_HINT = re.compile(
    r"\[/?(?:success|warning|error|green|red|yellow|cyan|blue|magenta|bold|dim|"
    r"italic|#[0-9a-fA-F]{3})"
)
_LINE_STYLES = (
    (("[ADDED]", "[LINE ADDED]", "[INSERT]", "+"), "#4ade80"),
    (("[DELETED]", "[LINE DELETED]", "[DELETE]", "-"), "#fb7185"),
    (("[UPDATED]", "[UPDATE]"), "#facc15"),
    (("@@",), _DIM),
)


def diff_line_text(line: str) -> Text:
    """One diff line as ``Text``: Rich markup when it carries style tags,
    otherwise literal text coloured by its ``[ADDED]``/``[DELETED]``/... tag.
    """
    if _MARKUP_HINT.search(line):
        try:
            return Text.from_markup(line)
        except Exception:
            pass
    text = Text(line)
    head = line.lstrip()
    for prefixes, style in _LINE_STYLES:
        if head.startswith(prefixes):
            text.stylize(style)
            break
    return text


def diff_markup(diff: str | list[str]) -> str:
    """A diff as safe Rich markup (plain lines escaped) for the zoom view."""
    from rich.markup import escape

    lines = diff.splitlines() if isinstance(diff, str) else list(diff)
    return "\n".join(
        line if _MARKUP_HINT.search(line) else escape(line) for line in lines
    )


def _fmt_time(when: datetime | None) -> str:
    return when.strftime("%H:%M:%S") if when else ""


def _fmt_size(size: int | None) -> str:
    if size is None:
        return "?"
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


@dataclass
class _Row:
    """One table row (live or review)."""

    key: str  # full path / pattern
    watched: str | None = None  # the path or pattern watching it
    activity: PathActivity | None = None
    pattern: bool = False
    review_kind: str | None = None  # "changed" / "new" / "deleted"
    review_diff: list[str] | None = None


class FilesSubViewBase(Widget):
    """Shared base of the lens sub-views that still use it (``DiffsView``).

    ``glance_fragment()`` is kept for those callers; the Files lens itself no
    longer has sub-views.
    """

    can_focus = True

    DEFAULT_CSS = """
    FilesSubViewBase {
        layout: vertical;
        height: 1fr;
        background: #050811;
        padding: 0 1;
    }
    FilesSubViewBase .files-subview-placeholder {
        color: #5b6479;
    }
    """

    _LABEL = "Files"

    def compose(self) -> ComposeResult:
        yield Static(
            f"{self._LABEL} — coming soon",
            classes="files-subview-placeholder",
        )

    def glance_fragment(self) -> str:
        return f"{self._LABEL} —"


class _FilesTable(DataTable):
    """The lens table: ``Home``/``End`` move the row cursor.

    DataTable binds them to *horizontal* scrolling (its ``ctrl+home`` is the
    row jump); this table never scrolls sideways, so Home/End jump rows.
    """

    def action_scroll_home(self) -> None:
        self.action_scroll_top()

    def action_scroll_end(self) -> None:
        self.action_scroll_bottom()


def _natural_key(text: str) -> list:
    """``f_2`` before ``f_10`` (digits compare as numbers)."""
    return [
        int(part) if part.isdigit() else part.lower() for part in _DIGITS.split(text)
    ]


_DIGITS = re.compile(r"(\d+)")

#: ``O`` cycles the order of the unpinned rows.
SORT_MODES = ("recent", "name", "count")


class _LensInput(Input):
    """The lens's one inline input: ``/`` filter or ``n`` add-a-path.

    Claims Escape (see module docstring) and hands Shift+←/→ to lens
    navigation while empty.
    """

    BINDINGS = [
        Binding("escape", "cancel_input", "Cancel", show=False),
        Binding("shift+left", "nav_or_select(-1)", show=False),
        Binding("shift+right", "nav_or_select(1)", show=False),
    ]

    mode = "filter"

    def check_consume_key(self, key: str, character: str | None) -> bool:
        if key == "escape":
            return True
        return super().check_consume_key(key, character)

    def action_nav_or_select(self, delta: int) -> None:
        if self.value:
            if delta < 0:
                self.action_cursor_left(select=True)
            else:
                self.action_cursor_right(select=True)
            return
        cycle = getattr(self.screen, "cycle_active_level", None)
        if cycle is not None:
            cycle(delta)

    def action_cancel_input(self) -> None:
        for node in self.ancestors:
            if isinstance(node, FilesPanel):
                node.close_input(cancel=True)
                return


class FilesPanel(Widget):
    """The Files lens (id ``files-panel``); see the module docstring."""

    can_focus = True

    BINDINGS = [
        Binding("w", "toggle_watch", "Watch"),
        Binding("u", "pull", "Pull"),
        Binding("U", "pull_all", "Pull all watched", show=False),
        Binding("slash", "filter", "Filter", show=False),
        Binding("n", "add_path", "Watch a path…", show=False),
        Binding("a", "toggle_auto", "Auto-pull watched", show=False),
        Binding("N", "toggle_noise", "Show noise", show=False),
        Binding("full_stop", "toggle_full_paths", "Full paths", show=False),
        Binding("z", "zoom", "Zoom diff", show=False),
        Binding("O", "cycle_sort", "Sort: recent / name / count", show=False),
        Binding("ctrl+l", "clear", "Clear activity", show=False),
    ]

    DEFAULT_CSS = """
    FilesPanel {
        layout: vertical;
        height: 1fr;
        background: #080c18;
    }
    FilesPanel > #files-notice {
        height: 1;
        display: none;
        padding: 0 1;
    }
    FilesPanel > #files-notice.-shown {
        display: block;
    }
    FilesPanel #files-notice-text {
        width: 1fr;
        color: #facc15;
    }
    FilesPanel #files-resume-btn {
        display: none;
        min-width: 20;
        height: 1;
        border: none;
        background: #facc15;
        color: #1f2937;
    }
    FilesPanel #files-resume-btn.-shown {
        display: block;
    }
    FilesPanel > #files-table {
        height: 1fr;
        background: #080c18;
        overflow-x: hidden;
        scrollbar-size-vertical: 1;
    }
    FilesPanel > #files-table > .datatable--cursor {
        background: #11203a;
        color: #e2e8f0;
    }
    FilesPanel > #files-empty {
        height: 1fr;
        content-align: center middle;
        color: #8f9bb3;
        display: none;
    }
    FilesPanel.-empty > #files-table {
        display: none;
    }
    FilesPanel.-empty > #files-empty {
        display: block;
    }
    FilesPanel > #files-input {
        display: none;
        height: 1;
        border: none;
        padding: 0 1;
        background: #0b1628;
    }
    FilesPanel > #files-input.-shown {
        display: block;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.activity = FileActivity(
            FileActivity.config_visibility(), FileActivity.config_max_paths()
        )
        self._filter = ""
        self._full_paths = False
        self._sort = "recent"
        self._scope: str | None = None
        self._scope_label: str | None = None
        self._review_rows: list[_Row] = []
        self._review_record: Any = None
        self._review_error: str | None = None
        self._rows: list[_Row] = []
        self._dirty = True
        self._path_width = 0
        self._notice_kind: str | None = None
        self._resume_config: Any = None
        self._event_handlers: list = []
        self._main_loop = None
        self._ui = UiDispatcher()

    # -- compose / mount -----------------------------------------------------

    def compose(self) -> ComposeResult:
        with Horizontal(id="files-notice"):
            yield Static("", id="files-notice-text")
            yield Button("Resume monitoring", id="files-resume-btn")
        table: DataTable = _FilesTable(
            id="files-table", cursor_type="row", show_header=False, zebra_stripes=False
        )
        yield table
        yield Static("", id="files-empty")
        # No select-all on focus: the `n` prefill (the app's data directory)
        # is meant to be extended, not replaced by the first key typed.
        yield _LensInput(id="files-input", select_on_focus=False)
        yield WatchlistView(id="files-watchlist")

    def on_mount(self) -> None:
        self._subscribe_events()
        self.set_interval(_REFRESH_INTERVAL, self._tick)
        self.refresh_rows()

    def on_unmount(self) -> None:
        self._unsubscribe_events()

    # -- small accessors -------------------------------------------------------

    @property
    def watchlist(self) -> WatchlistView:
        return self.query_one("#files-watchlist", WatchlistView)

    @property
    def table(self) -> DataTable:
        return self.query_one("#files-table", DataTable)

    @property
    def review(self) -> bool:
        return self._scope is not None

    @staticmethod
    def _monitor_task():
        try:
            from sandroid.services import get_task_service

            svc = get_task_service()
            return bool(svc.is_running("monitor")), svc.get_task("monitor")
        except Exception:
            return False, None

    def _app_root(self) -> str | None:
        """``/data/data/<pkg>/`` of the monitored app, if known."""
        _running, task = self._monitor_task()
        config = getattr(getattr(task, "instance", None), "config", None)
        app_name = getattr(config, "app_name", None) or getattr(task, "app_name", None)
        return f"/data/data/{app_name}/" if app_name else None

    def _absolute(self, path: str) -> str | None:
        if path.startswith("/"):
            return path
        root = self._app_root()
        return root + path if root else None

    def _main_screen(self):
        screen = getattr(self, "screen", None)
        return screen if hasattr(screen, "set_lens_caption") else None

    # -- lens hooks ------------------------------------------------------------

    def focus(self, scroll_visible: bool = True):
        """Focus the table (or this lens while the table is empty)."""
        try:
            table = self.table
            if not self.has_class("-empty"):
                table.focus(scroll_visible)
                return self
        except Exception:
            pass
        return super().focus(scroll_visible)

    def on_lens_activated(self) -> None:
        wl = self._watchlist_or_none()
        if wl is not None:
            wl.reload()
        self._dirty = True
        self.refresh_rows()

    def select_subtab(self, panel_id: str) -> None:
        """Legacy ``open_files_tab(sub_tab=...)`` target: just land on the table.

        ``files-watchlist`` (key ``l``) puts the cursor on the first (pinned,
        watched) row.
        """
        if panel_id == "files-watchlist":
            try:
                if self.table.row_count:
                    self.table.move_cursor(row=0, animate=False)
            except Exception:
                pass
        self.focus()

    def on_scope_changed(self, message: ScopeChanged) -> None:
        self._scope = message.run_id
        self._scope_label = message.label
        self._review_rows = []
        self._review_record = None
        self._review_error = None
        if self._scope is not None:
            self._start_review_load(self._scope)
        self._dirty = True
        self.refresh_rows()
        self.refresh_bindings()

    # -- EventBus wiring (non-blocking, thread-safe) ----------------------------

    def _subscribe_events(self) -> None:
        try:
            from sandroid.core.events import EventBus, EventType

            # Thread -> UI hand-off in the UI's contextvars context (see
            # sandroid.tui.utils.ui_thread: a bare loop callback lacks
            # Textual's active_app and its timers raised LookupError).
            self._ui = UiDispatcher.capture()
            self._main_loop = self._ui.loop
            bus = EventBus.get()

            _schedule = self._ui.post

            def _output_cb(event) -> None:
                _schedule(self._on_task_output, event)

            def _lifecycle_cb(event) -> None:
                data = getattr(event, "data", None) or {}
                if data.get("task_name") == "monitor":
                    _schedule(self._on_monitor_lifecycle, event.type)

            for event_type, cb in (
                (EventType.TASK_OUTPUT, _output_cb),
                (EventType.TASK_STARTED, _lifecycle_cb),
                (EventType.TASK_STOPPED, _lifecycle_cb),
            ):
                bus.subscribe(event_type, cb)
                self._event_handlers.append((event_type, cb))
        except Exception as exc:
            logger.debug(f"FilesPanel event subscribe failed: {exc}")

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
        """A monitor batch (source-only match: other tasks never leak in)."""
        if getattr(event, "source", None) != "monitor":
            return
        batch = (getattr(event, "data", None) or {}).get("batch")
        if batch:
            self.ingest(batch)

    def ingest(self, batch, now: datetime | None = None) -> None:
        """Fold a monitor batch in; the table redraws on the next tick."""
        touched = self.activity.ingest(batch, now=now)
        if touched:
            self._dirty = True
            self._refresh_inspector(touched)

    def _on_monitor_lifecycle(self, event_type) -> None:
        from sandroid.core.events import EventType

        if event_type == EventType.TASK_STARTED:
            self.clear_resume_offer()
            if self._notice_kind == "playback":
                self._set_notice(None)
        elif self._notice_kind == "backend":
            self._set_notice(None)
        self._dirty = True
        self.refresh_rows()

    # -- notices (backend fallbacks, Play safety net, resume offer) -------------

    def _set_notice(self, text: str | None, kind: str | None = None) -> None:
        self._notice_kind = kind if text else None
        try:
            self.query_one("#files-notice-text", Static).update(
                Text(f"⚠ {text}") if text else ""
            )
            self.query_one("#files-notice").set_class(
                bool(text) or self._resume_config is not None, "-shown"
            )
        except Exception:
            pass

    @property
    def notice(self) -> str:
        try:
            return str(self.query_one("#files-notice-text", Static).render())
        except Exception:
            return ""

    def notify_monitor_stopped_for_playback(self) -> None:
        """Play's snapshot revert auto-stopped the monitor (app.py callback)."""
        self._set_notice(
            "Monitor stopped — it can't survive Play's revert.", "playback"
        )
        self.refresh_rows()

    def notify_pid_mode_fallback(self, path: str) -> None:
        """PID mode fell back to path mode (no fanotify on this kernel)."""
        self._set_notice(
            f"PID mode unavailable (no fanotify) — watching {path} by path.", "backend"
        )
        self.refresh_rows()

    def notify_backend_fallback(self, reason: str) -> None:
        """The kprobe backend was unavailable; the monitor uses fsmon."""
        self._set_notice(reason, "backend")
        self.refresh_rows()

    def offer_resume(self, config: Any) -> None:
        """One-click "Resume monitoring" once Play has finished."""
        self._resume_config = config
        target = "?"
        if config is not None:
            if getattr(config, "mode", None) == "pid" and getattr(
                config, "app_name", None
            ):
                target = f"{config.app_name} (pid mode)"
            elif getattr(config, "target_path", None):
                target = config.target_path
        self._set_notice(f"Monitor was stopped for Play — {target}", "playback")
        try:
            self.query_one("#files-resume-btn").set_class(True, "-shown")
        except Exception:
            pass

    def clear_resume_offer(self) -> None:
        self._resume_config = None
        try:
            self.query_one("#files-resume-btn").set_class(False, "-shown")
        except Exception:
            pass
        if self._notice_kind == "playback":
            self._set_notice(None)

    @property
    def resume_offered(self) -> bool:
        return self._resume_config is not None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "files-resume-btn":
            return
        event.stop()
        try:
            self.app.resume_monitor_after_playback(self._resume_config)
        except Exception:
            logger.warning("Resume monitoring failed", exc_info=True)

    # -- rows ----------------------------------------------------------------------

    def _live_rows(self) -> list[_Row]:
        wl = self._watchlist_or_none()
        pinned: dict[str, _Row] = {}
        rest: list[_Row] = []
        if wl is not None:
            for path in wl.rows:
                pinned[path] = _Row(key=path, watched=path)
            for pattern in wl.patterns:
                pinned[pattern] = _Row(key=pattern, watched=pattern, pattern=True)
        for key, act in self.activity.paths.items():
            watched = wl.watched_by(key) if wl is not None else None
            if (
                watched is not None
                and watched != key
                and key not in wl.rows
                and (act.deleted or act.is_dir or act.moved_to)
            ):
                # A wildcard pattern watches files that exist: not a deleted
                # path or a directory it happens to match.
                watched = None
            if watched is not None:
                row = pinned.setdefault(key, _Row(key=key, watched=watched))
                row.activity = act
            elif self.activity.is_visible(act):
                rest.append(_Row(key=key, activity=act))

        def recency(row: _Row):
            last = row.activity.last if row.activity else None
            return (last is None, -(last.timestamp() if last else 0), row.key)

        def order(row: _Row):
            if self._sort == "name":
                return _natural_key(app_relative(row.key))
            if self._sort == "count":
                count = row.activity.count if row.activity else 0
                return (-count, *recency(row))
            return recency(row)

        rows = sorted(pinned.values(), key=order) + sorted(rest, key=order)
        return [r for r in rows if self._matches(r)]

    def _matches(self, row: _Row) -> bool:
        if not self._filter:
            return True
        needle = self._filter.lower()
        return needle in row.key.lower()

    def _watchlist_or_none(self) -> WatchlistView | None:
        try:
            return self.watchlist
        except Exception:
            return None

    def _start_review_load(self, scope: str) -> None:
        def work() -> None:
            try:
                record, error = _load_run_record(scope), None
            except Exception as exc:
                record, error = None, str(exc)
            self._post(self._apply_review, scope, record, error)

        if self.is_running:
            self.run_worker(work, name="files_review_load", thread=True, exclusive=True)
        else:
            work()

    def _post(self, fn, *args) -> None:
        import threading

        if threading.current_thread() is threading.main_thread():
            fn(*args)
            return
        try:
            self.app.call_from_thread(fn, *args)
        except Exception:
            logger.debug("FilesPanel: call_from_thread failed", exc_info=True)

    def _apply_review(self, scope: str, record: Any, error: str | None) -> None:
        if scope != self._scope:
            return  # scope changed while loading
        self._review_record = record
        self._review_error = error
        rows: list[_Row] = []
        wl = self._watchlist_or_none()
        if record is not None:
            from sandroid.core import run_history

            rows = [
                _Row(key=r.path, review_kind=r.kind, review_diff=r.diff)
                for r in run_history.file_diff_rows(record)
            ]
        unique: dict[str, _Row] = {}
        for row in rows:  # a path listed twice keeps its first (changed) entry
            unique.setdefault(row.key, row)
            row.watched = wl.watched_by(row.key) if wl is not None else None
        self._review_rows = list(unique.values())
        self._dirty = True
        self.refresh_rows()

    def _review_title(self) -> str:
        record = self._review_record
        if self._scope_label:
            return self._scope_label
        if record is not None and getattr(record, "label", ""):
            return record.label
        return f"Run {Path(self._scope or '').name}"

    # -- drawing ------------------------------------------------------------------

    def _tick(self) -> None:
        if self._dirty and is_shown(self):
            self.refresh_rows()

    def on_resize(self, _event) -> None:
        self._dirty = True
        self.call_after_refresh(self.refresh_rows)

    def _cursor_key(self) -> str | None:
        try:
            table = self.table
            if not table.row_count:
                return None
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            return row_key.value
        except Exception:
            return None

    def current_row(self) -> _Row | None:
        key = self._cursor_key()
        for row in self._rows:
            if row.key == key:
                return row
        return None

    def _ensure_columns(self, table: DataTable) -> None:
        """Fit the columns to the table width.

        When it gets narrow (beside the Inspector at 100 columns) the count
        goes first -- the time of the last change is the more useful of the
        two -- then the time too.
        """
        width = table.size.width or self.size.width or 100
        base = _W_MARK + _W_OPS + 2 * 3 + 1  # + cell padding, scrollbar
        path_width = width - base
        columns = ["mark", "path", "ops"]
        if path_width - (_W_COUNT + 2) - (_W_LAST + 2) >= 20:
            columns += ["count", "last"]
            path_width -= _W_COUNT + 2 + _W_LAST + 2
        elif path_width - (_W_LAST + 2) >= 16:
            columns += ["last"]
            path_width -= _W_LAST + 2
        elif path_width - (_W_COUNT + 2) >= 16:
            columns += ["count"]
            path_width -= _W_COUNT + 2
        path_width = max(8, path_width)
        current = [str(c.value) for c in table.columns]
        if path_width == self._path_width and current == columns:
            return
        self._path_width = path_width
        table.clear(columns=True)
        widths = {
            "mark": _W_MARK,
            "path": path_width,
            "ops": _W_OPS,
            "count": _W_COUNT,
            "last": _W_LAST,
        }
        for key in columns:
            label = "" if key == "mark" else key
            table.add_column(label, width=widths[key], key=key)

    def _foreign_package(self, row: _Row) -> str | None:
        """The package to show in front of a short path, or None.

        In REVIEW every app path names its package (a run diffs the whole
        device); live, only paths outside the monitored app do.
        """
        package = app_package(row.key)
        if package is None:
            return None
        if row.review_kind is not None:
            return package
        root = self._app_root()
        own = app_package(root) if root else None
        return package if own and package != own else None

    def _path_cell(self, row: _Row) -> Text:
        act = row.activity
        moved = act.moved_to if act is not None else None
        # "old.txt → new.txt": the renamed-away row says where the file went.
        suffix = f" → {moved.rsplit('/', 1)[-1]}" if moved else ""
        shown = row.key if self._full_paths else app_relative(row.key)
        # Short paths drop /data/data/<pkg>/: name the package whenever it
        # is not the monitored app's -- always in REVIEW, where a run lists
        # files of several apps (bugle_db must not read as Wikipedia's).
        owner = None if self._full_paths else self._foreign_package(row)
        if not self._full_paths:
            width = self._path_width - len(suffix)
            if suffix and width < 12:
                suffix = " →"
                width = self._path_width - 2
            if owner:
                owner = smart_truncate(owner, max(6, min(len(owner), width // 2)))
                width -= len(owner) + 2
            shown = smart_truncate(shown, max(4, width))
        head, sep, name = shown.rpartition("/")
        text = Text(no_wrap=True, overflow="ellipsis")
        if owner:
            text.append(f"{owner}: ", style="#7dd3fc")
        if sep:
            text.append(head + sep, style=_DIM)
        gone = act is not None and (act.deleted or bool(moved))
        style = "italic" if row.pattern else ""
        if gone:
            style = "strike #8f9bb3"  # deleted / renamed away: no longer there
        text.append(name, style=style)
        if suffix:
            text.append(suffix, style="#facc15")
        return text

    def _mark_cell(self, row: _Row) -> Text:
        if row.watched is None:
            return Text("")
        wl = self._watchlist_or_none()
        info = wl.rows.get(row.key) if wl is not None else None
        style = _STATE_STAR.get(info.state, _STAR) if info is not None else _STAR
        return Text("★", style=style)

    def _cells(self, row: _Row) -> tuple:
        if row.review_kind is not None:
            letter, color = {
                "changed": OPS["modify"],
                "new": OPS["create"],
                "deleted": OPS["delete"],
            }[row.review_kind]
            return (
                self._mark_cell(row),
                self._path_cell(row),
                Text(letter, style=color),
                Text(""),
                Text(""),
            )
        act = row.activity
        ops = Text()
        if act is not None:
            for letter, color in act.op_letters():
                if letter != OPS["noise"][0] or self.activity.show_all:
                    ops.append(letter, style=color)
        elif row.pattern:
            ops.append("*", style=_DIM)
        count = Text(f"{act.count}×" if act else "", style=_DIM, justify="right")
        last = Text(_fmt_time(act.last) if act else "", style=_DIM)
        return self._mark_cell(row), self._path_cell(row), ops, count, last

    def refresh_rows(self) -> None:
        """Rebuild the table from the current model (keeps the cursor row)."""
        self._dirty = False
        try:
            table = self.table
        except Exception:
            return
        keep = self._cursor_key()
        keep_index = table.cursor_row if table.row_count else 0
        keep_scroll = table.scroll_y
        self._ensure_columns(table)
        rows = (
            [r for r in self._review_rows if self._matches(r)]
            if self.review
            else self._live_rows()
        )
        self._rows = rows
        with self.app.batch_update():
            table.clear()
            order = ("mark", "path", "ops", "count", "last")
            picks = [order.index(str(c.value)) for c in table.columns]
            for row in rows:
                cells = self._cells(row)
                table.add_row(*(cells[i] for i in picks), key=row.key)
            if rows:
                index = keep_index
                if keep is not None:
                    try:
                        index = table.get_row_index(keep)
                    except Exception:
                        index = min(keep_index, len(rows) - 1)
                index = max(0, min(index, len(rows) - 1))
                # clear() scrolled to the top: put the viewport back unless
                # the cursor row moved out of it (one row = one line).
                height = max(1, table.scrollable_content_region.height)
                in_view = keep_scroll <= index < keep_scroll + height
                table.move_cursor(row=index, animate=False, scroll=not in_view)
                if in_view and keep_scroll:
                    table.call_after_refresh(
                        table.scroll_to, y=keep_scroll, animate=False, immediate=True
                    )
        empty = not rows
        had_focus = self.app.focused is table
        self.set_class(empty, "-empty")
        if empty:
            self.query_one("#files-empty", Static).update(self._empty_text())
            if had_focus:
                super().focus()
        elif self.app.focused is self:
            table.focus()
        self._update_caption()

    def _empty_text(self) -> Text:
        if self._filter:
            return Text(f"Nothing matches “{self._filter}”", style=_DIM)
        if self.review:
            if self._review_error:
                return Text(f"Could not load this run: {self._review_error}")
            if self._review_record is None:
                return Text("Loading the run…", style=_DIM)
            return Text("This run changed no files.")
        running, task = self._monitor_task()
        if not running:
            return Text.assemble(
                "Monitor off — press ", ("o", "bold"), " to watch file activity"
            )
        config = getattr(getattr(task, "instance", None), "config", None)
        target = getattr(config, "app_name", None) or getattr(
            config, "target_path", None
        )
        hidden = self._hidden_count()
        tail = f" · {hidden} noisy paths hidden (N)" if hidden else ""
        where = f" in {target}" if target else ""
        return Text(f"Watching for file activity{where} — nothing yet{tail}")

    def caption(self) -> tuple[str, str]:
        """``(title, info)`` for the lens frame."""
        rows = self._rows
        if self.review:
            title = self._review_title()
            parts = [f"{len(rows)} files"] if self._review_record is not None else []
        else:
            title = "LIVE"
            wl = self._watchlist_or_none()
            n_paths = sum(1 for r in rows if not r.pattern)
            n_patterns = len(rows) - n_paths
            count = f"{n_paths} path{'s' if n_paths != 1 else ''}"
            if n_patterns:
                count += f" + {n_patterns} pattern{'s' if n_patterns != 1 else ''}"
            parts = [count]
            if wl is not None and wl.summary():
                parts.append(wl.summary())
            hidden = self._hidden_count()
            if hidden:
                parts.append(f"{hidden} hidden")
            if self._sort != "recent":
                parts.append(f"by {self._sort}")
            if wl is not None and wl.auto_enabled:
                parts.append("auto-pull")
            running, _task = self._monitor_task()
            if not running and rows:
                parts.append("monitor off")
        if self._filter:
            parts.insert(0, f"/{self._filter}")
        if not rows and not self._filter:
            parts = []
        return title, " · ".join(parts)

    def _hidden_count(self) -> int:
        """Noise rows actually hidden: matching the filter and not pinned."""
        if self.activity.show_all:
            return 0
        shown = {r.key for r in self._rows}
        needle = self._filter.lower()
        return sum(
            1
            for key, act in self.activity.paths.items()
            if key not in shown
            and self.activity.is_quiet(act)
            and (not needle or needle in key.lower())
        )

    def _update_caption(self) -> None:
        ms = self._main_screen()
        if ms is None:
            return
        title, info = self.caption()
        try:
            ms.set_lens_caption("files", title, info)
        except Exception:
            pass

    # -- inspector -----------------------------------------------------------------

    def inspect_selected(self) -> InspectorContent | None:
        row = self.current_row()
        return self._inspector_for(row) if row is not None else None

    def _inspector_key(self, path: str) -> tuple:
        return ("files", self._scope or "live", path)

    def _refresh_inspector(self, touched=None) -> None:
        ms = self._main_screen()
        if ms is None or not getattr(ms, "inspector_is_open", False):
            return
        content = ms.inspector_content
        key = getattr(content, "key", None)
        if not (isinstance(key, tuple) and len(key) == 3 and key[0] == "files"):
            return
        if key[1] != (self._scope or "live"):
            return
        path = key[2]
        if touched is not None and path not in touched:
            return
        row = next((r for r in self._rows if r.key == path), None)
        if row is None:
            row = self._row_for(path)
        if row is not None:
            ms.update_inspector(self._inspector_for(row))

    def _row_for(self, path: str) -> _Row | None:
        wl = self._watchlist_or_none()
        act = self.activity.paths.get(path)
        watched = wl.watched_by(path) if wl is not None else None
        if act is None and watched is None:
            return None
        return _Row(key=path, watched=watched, activity=act)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """While the Inspector shows a Files row, follow the cursor."""
        ms = self._main_screen()
        if ms is None or not getattr(ms, "inspector_is_open", False):
            return
        key = getattr(ms.inspector_content, "key", None)
        if not (isinstance(key, tuple) and key and key[0] == "files"):
            return
        row = self.current_row()
        if row is not None and key[2] != row.key:
            ms.update_inspector(self._inspector_for(row))

    def _inspector_for(self, row: _Row) -> InspectorContent:
        title = app_relative(row.key).rpartition("/")[2] or row.key
        key = self._inspector_key(row.key)
        keys = {
            "less_than_sign": lambda tab: self._inspect_step(row, tab, -1),
            "greater_than_sign": lambda tab: self._inspect_step(row, tab, 1),
            "B": lambda tab: self._inspect_base(row, tab),
        }
        click = lambda tab, y: self._inspect_click(row, tab, y)  # noqa: E731
        if row.review_kind is not None:
            tabs = [
                ("Summary", self._review_summary(row)),
                ("Diff", [("", self._review_diff(row))]),
            ]
            content = file_inspect.review_content_sections(
                self._scope, row.key, row.review_kind, self._inspect_notify
            )
            if content is not None:
                tabs.append(("Content", content))
            return InspectorContent(
                title=title,
                subtitle=row.key,
                tabs=tabs,
                footer="z zoom",
                key=key,
                keys=keys,
                click=click,
            )
        return InspectorContent(
            title=title,
            subtitle=row.key,
            tabs=[
                ("Summary", self._live_summary(row)),
                ("Versions", self._versions_tab(row)),
                ("Content", self._content_tab(row)),
                ("Events", [("", self._events_text(row))]),
            ],
            footer="w watch  u pull  z zoom",
            key=key,
            keys=keys,
            click=click,
        )

    # Versions / Content tabs: rendering and state live in file_inspect.

    def _inspect_notify(self) -> None:
        """A background diff/preview finished (worker thread): redraw."""
        self._post(self._refresh_inspector)

    def _unpulled_text(self, row: _Row) -> Text | None:
        """Why a row has no versions (not watched / a pattern), else None."""
        wl = self._watchlist_or_none()
        if wl is not None and row.key in wl.rows:
            return None
        if row.pattern:
            return Text("Pull a matching file to see its versions.", style=_DIM)
        return Text.assemble(
            ("Watch (", _DIM), ("w", "bold"), (") and pull (", _DIM),
            ("u", "bold"), (") to diff this file — every pull is kept as a version.", _DIM),
        )  # fmt: skip

    def _versions_tab(self, row: _Row) -> list:
        reason = self._unpulled_text(row)
        if reason is not None:
            return [("", reason)]
        wl = self._watchlist_or_none()
        info = wl.rows.get(row.key) if wl is not None else None
        status = None
        if info is not None and info.state is RowState.ERROR:
            status = Text(
                f"✕ {info.detail or 'The last pull failed.'}", style="#ef4444"
            )
        elif info is not None and info.state is RowState.SETTLING:
            status = Text(
                "◇ A change is settling; auto-pull keeps it as a new version.",
                style="#a3873f",
            )
        return file_inspect.versions_sections(row.key, self._inspect_notify, status)

    def _content_tab(self, row: _Row) -> list:
        reason = self._unpulled_text(row)
        if reason is not None:
            return [("", reason)]
        return file_inspect.content_sections(row.key, self._inspect_notify)

    def _content_target(self, row: _Row) -> tuple[str, Path | None, str]:
        """``(state key, local file, label)`` the Content tab shows."""
        if row.review_kind is None:
            if self._unpulled_text(row) is not None:
                return row.key, None, ""  # not watched: no versions to read
            file = file_inspect.content_file(row.key)
            return row.key, file, file_inspect.content_label(row.key)
        before, after = file_inspect.run_copies(self._scope, row.key)
        file = before if row.review_kind == "deleted" else after
        label = "before the run" if file is before else "after the run"
        return f"{self._scope}|{row.key}", file, label

    def _reinspect(self, row: _Row) -> None:
        ms = self._main_screen()
        if ms is not None and getattr(ms, "inspector_is_open", False):
            ms.update_inspector(self._inspector_for(row))

    def _inspect_step(self, row: _Row, tab: str | None, delta: int) -> None:
        if tab == "Content":
            state_key, file, _label = self._content_target(row)
            moved = file_inspect.step_table(state_key, file, delta)
        elif tab == "Versions" and self._unpulled_text(row) is None:
            moved = file_inspect.step_version(row.key, delta)
        else:
            return
        if moved:
            self._reinspect(row)

    def _inspect_base(self, row: _Row, tab: str | None) -> None:
        if row.review_kind is not None or tab not in ("Versions", "Content"):
            return
        if self._unpulled_text(row) is not None:
            return
        notice = file_inspect.toggle_base(row.key)
        if notice:
            self.app.notify(notice, timeout=4)
        self._reinspect(row)

    def _inspect_click(self, row: _Row, tab: str | None, line: int) -> bool:
        if tab == "Versions" and row.review_kind is None:
            if self._unpulled_text(row) is not None:
                return False
            done = file_inspect.select_version_row(row.key, line)
        elif tab == "Content":
            state_key, file, _label = self._content_target(row)
            done = file_inspect.select_table_row(state_key, file, line)
        else:
            return False
        if done:
            self._reinspect(row)
        return done

    def _zoom_inspected(self, row: _Row) -> bool:
        """``z`` on the Versions / Content / (review) Diff tab: the structured
        view full-screen. False when there is nothing structured to show.
        """
        from rich.console import Group

        tab = None
        ms = self._main_screen()
        content = getattr(ms, "inspector_content", None) if ms is not None else None
        if (
            ms is not None
            and getattr(ms, "inspector_is_open", False)
            and getattr(content, "key", None) == self._inspector_key(row.key)
        ):
            try:
                tab = ms.query_one("#inspector").tab_name
            except Exception:
                tab = None
        if tab == "Content":
            state_key, file, label = self._content_target(row)
            zoom = file_inspect.zoom_content(state_key, file, label)
            if zoom is None:
                return False
            title, body, wide = zoom
            self.app.push_screen(file_inspect.InspectZoomModal(title, body, wide))
            return True
        if row.review_kind is not None:
            body = file_inspect.review_diff_body(
                self._scope, row.key, row.review_diff, full=True
            )
            if body is None:
                return False
            title = Path(row.key).name or row.key
            self.app.push_screen(
                file_inspect.InspectZoomModal(f"{title} · run diff", body)
            )
            return True
        zoom = (
            file_inspect.zoom_versions(row.key)
            if self._unpulled_text(row) is None
            else None
        )
        if zoom is None:
            return False
        heading, body = zoom
        self.app.push_screen(
            file_inspect.InspectZoomModal(
                Path(row.key).name or row.key,
                Group(Text(heading, style="bold #8f9bb3"), body),
            )
        )
        return True

    @staticmethod
    def _grid() -> Table:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=_DIM, no_wrap=True)
        grid.add_column()
        return grid

    def _watch_text(self, row: _Row) -> Text:
        if row.pattern:
            wl = self._watchlist_or_none()
            n = (
                sum(1 for p in wl.rows if wl._pattern_matches(row.key, p))
                if wl is not None
                else 0
            )
            return Text(f"★ pattern · {n} matching file{'s' if n != 1 else ''}")
        if row.watched is None:
            return Text.assemble("not watched — ", ("w", "bold"), " to watch")
        if row.watched != row.key:
            return Text(f"★ via {row.watched}")
        return Text("★ watched")

    def _live_summary(self, row: _Row) -> list:
        grid = self._grid()
        act = row.activity
        grid.add_row("watch", self._watch_text(row))
        if act is not None:
            ops = Text()
            for cat, (letter, color) in OPS.items():
                n = act.ops.get(cat)
                if n:
                    if ops:
                        ops.append("  ")
                    ops.append(letter, style=color)
                    ops.append(f" {n}×")
            grid.add_row("ops", ops)
            grid.add_row("first", _fmt_time(act.first))
            grid.add_row("last", _fmt_time(act.last))
            if act.processes:
                top = sorted(act.processes.items(), key=lambda kv: -kv[1])[:3]
                grid.add_row("by", ", ".join(name for name, _n in top))
            if act.moved_to:
                grid.add_row("now", Text(f"renamed → {app_relative(act.moved_to)}"))
            elif act.deleted:
                grid.add_row("now", Text("deleted", style=OPS["delete"][1]))
        else:
            grid.add_row("activity", Text("none seen yet", style=_DIM))
        sections: list = [("", grid)]
        if not row.pattern and _is_database(row.key):
            # H2: the probes attribute writes by the file opened under the
            # monitor; a database the app opened before the start is only
            # caught by the periodic re-stat (and the stop rescan).
            sections.append(
                (
                    "Note",
                    Text(
                        "Databases are usually opened when the app starts. If "
                        "that was before the monitor, their writes are found by "
                        "a re-stat every few seconds (events marked “re-stat”), "
                        "not as they happen. Start the monitor before the app "
                        "(spawn) to see every write.",
                        style=_DIM,
                    ),
                )
            )
        wl = self._watchlist_or_none()
        info = wl.rows.get(row.key) if wl is not None else None
        if info is not None:
            pull = self._grid()
            pull.add_row("state", self._state_text(info.state))
            if info.pulled_at:
                pull.add_row("pulled", info.pulled_at.replace("T", " "))
                pull.add_row("size", _fmt_size(info.size))
                if info.sha256:
                    pull.add_row("sha256", info.sha256[:16] + "…")
            if info.detail and info.state is not RowState.CHANGED:
                pull.add_row("", Text(info.detail, style=_DIM))
            sections.append(("Last pull", pull))
        return sections

    @staticmethod
    def _state_text(state: RowState) -> Text:
        return {
            RowState.NEVER_PULLED: Text("never pulled — u to pull", style=_DIM),
            RowState.BASELINE_ONLY: Text("baseline captured"),
            RowState.UNCHANGED: Text("unchanged since the pull before"),
            RowState.CHANGED: Text("◆ changed since the pull before", style="#facc15"),
            RowState.ERROR: Text("✕ last pull failed", style="#ef4444"),
            RowState.SETTLING: Text("◇ change detected, settling", style="#a3873f"),
        }[state]

    def _events_text(self, row: _Row) -> Text:
        act = row.activity
        if act is None or not act.events:
            return Text("No events seen.", style=_DIM)
        out = Text()
        for i, ev in enumerate(reversed(act.events)):
            if i:
                out.append("\n")
            out.append(_fmt_time(ev.when), style=_DIM)
            out.append("  ")
            out.append(f"{ev.label or '?':<7}", style=ev.color or "")
            extra = []
            if ev.via:
                extra.append(ev.via)
            if ev.source == "renamed" and ev.other:
                extra.append(f"to {app_relative(ev.other)}")
            elif ev.source == "parent" and ev.other:
                extra.append(f"directory {app_relative(ev.other)} deleted")
            elif ev.other:
                extra.append(f"from {app_relative(ev.other)}")
            if ev.source in SOURCE_TEXT and ev.source != "parent":
                extra.append(SOURCE_TEXT[ev.source])
            if ev.process:
                extra.append(ev.process)
            if extra:
                out.append("  " + " · ".join(extra), style=_DIM)
        return out

    def _review_summary(self, row: _Row) -> list:
        grid = self._grid()
        word = {"changed": "changed", "new": "new file", "deleted": "deleted"}
        letter, color = {
            "changed": OPS["modify"],
            "new": OPS["create"],
            "deleted": OPS["delete"],
        }[row.review_kind or "changed"]
        grid.add_row(
            "change",
            Text(f"{letter} {word[row.review_kind or 'changed']}", style=color),
        )
        grid.add_row("run", self._review_title())
        record = self._review_record
        when = getattr(record, "completed_at", "") or getattr(record, "recorded_at", "")
        if when:
            grid.add_row("when", str(when).replace("T", " ")[:19])
        grid.add_row("watch", self._watch_text(row))
        return [("", grid)]

    def _review_diff(self, row: _Row):
        body = file_inspect.review_diff_body(
            self._scope, row.key, row.review_diff, self._inspect_notify
        )
        if body is not None:
            return body
        if row.review_diff:
            return render_diff(row.review_diff)
        return Text(
            {
                "new": "New in this run — no earlier version to diff.",
                "deleted": "Deleted in this run.",
            }.get(row.review_kind or "", "Changed, but the run kept no diff for it."),
            style=_DIM,
        )

    # -- actions ----------------------------------------------------------------------

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action in ("pull", "pull_all") and self.review:
            return False
        return True

    def action_toggle_watch(self) -> None:
        row = self.current_row()
        if row is None:
            self.app.notify("No file selected.", severity="warning")
            return
        wl = self.watchlist
        if row.watched is not None and row.watched != row.key and not row.pattern:
            self.app.notify(
                f"Watched via {row.watched} — unwatch that row.", severity="warning"
            )
            return
        if row.watched is not None:
            wl.unwatch(row.key)
            return
        path = self._absolute(row.key)
        if path is None:
            self.app.notify(
                "Unknown app root — use n to watch the full path.", severity="warning"
            )
            return
        from .monitor_view import split_companion

        wl.add_path(split_companion(path)[0])

    def action_pull(self) -> None:
        row = self.current_row()
        if row is None:
            self.app.notify("No file selected.", severity="warning")
            return
        wl = self.watchlist
        if row.pattern:
            wl.pull([p for p in wl.rows if wl._pattern_matches(row.key, p)])
            return
        if row.key in wl.rows:
            wl.pull([row.key])
            return
        act = row.activity
        if act is not None and (act.deleted or act.moved_to or act.is_dir):
            what = (
                "a directory"
                if act.is_dir
                else "renamed away"
                if act.moved_to
                else "deleted on the device"
            )
            self.app.notify(f"Nothing to pull: {what}.", severity="warning")
            return
        if row.watched is None:
            path = self._absolute(row.key)
            if path is not None and wl.add_path(path) and path in wl.rows:
                wl.pull([path])
                return
        self.app.notify("Nothing to pull for this row yet.", severity="warning")

    def action_pull_all(self) -> None:
        self.watchlist.pull_all()

    def action_toggle_auto(self) -> None:
        self.watchlist.toggle_auto()

    def action_toggle_noise(self) -> None:
        self.activity.show_all = not self.activity.show_all
        self.app.notify(
            "Showing all paths." if self.activity.show_all else "Noise hidden."
        )
        self.refresh_rows()

    def action_toggle_full_paths(self) -> None:
        self._full_paths = not self._full_paths
        self.refresh_rows()

    def action_cycle_sort(self) -> None:
        """``O``: order the rows by recency, name (natural) or event count."""
        self._sort = SORT_MODES[(SORT_MODES.index(self._sort) + 1) % len(SORT_MODES)]
        self.app.notify(f"Sorted by {self._sort}.")
        self.refresh_rows()

    def action_clear(self) -> None:
        self.activity.reset()
        self.refresh_rows()

    def action_zoom(self) -> None:
        row = self.current_row()
        if row is not None and self._zoom_inspected(row):
            return
        diff: Any = None
        if row is not None and row.review_diff:
            diff = row.review_diff
        elif row is not None:
            wl = self._watchlist_or_none()
            info = wl.rows.get(row.key) if wl is not None else None
            diff = info.diff_text if info is not None else None
        if not diff:
            self.app.notify("No diff for this row.", severity="warning")
            return
        from sandroid.tui.modals.diff_zoom_modal import DiffZoomModal

        self.app.push_screen(DiffZoomModal(diff_text=diff_markup(diff), title=row.key))

    # -- inline input (/ filter, n add path) ---------------------------------------

    def action_filter(self) -> None:
        self.open_input("filter")

    def action_add_path(self) -> None:
        self.open_input("add")

    def open_input(self, mode: str) -> None:
        field = self.query_one("#files-input", _LensInput)
        field.mode = mode
        if mode == "filter":
            field.placeholder = "filter paths   ⏎ keep · esc clear"
            field.value = self._filter
        else:
            field.placeholder = "/data/data/<pkg>/databases/*   ⏎ watch · esc cancel"
            field.value = self._app_root() or ""
        field.set_class(True, "-shown")
        field.focus()
        field.cursor_position = len(field.value)

    def close_input(self, cancel: bool = False) -> None:
        field = self.query_one("#files-input", _LensInput)
        if cancel and field.mode == "filter" and self._filter:
            self._filter = ""
            self.refresh_rows()
        field.value = ""
        field.set_class(False, "-shown")
        self.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "files-input" or event.input.mode != "filter":
            return
        if not event.input.has_class("-shown"):
            return
        self._filter = event.value.strip()
        self.refresh_rows()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "files-input":
            return
        event.stop()
        if event.input.mode == "filter":
            self._filter = event.value.strip()
            self.close_input()
            return
        path = event.value.strip()
        if not path or (path.endswith("/") and "*" not in path):
            self.app.notify("Type a file path or a pattern with *.", severity="warning")
            return
        # Absolute device paths only, no shell metacharacters (quoting is
        # safe either way; such input is a typo or a smuggled command).
        problem = watch_path_problem(path)
        if problem is not None:
            self.app.notify(problem, severity="warning")
            return
        if self.watchlist.add_path(path):
            self.close_input()

    # -- watchlist changes ------------------------------------------------------------

    def on_watchlist_view_changed(self, event: WatchlistView.Changed) -> None:
        event.stop()
        if self.review:
            wl = self._watchlist_or_none()
            for row in self._review_rows:
                row.watched = wl.watched_by(row.key) if wl is not None else None
        self.refresh_rows()
        self._refresh_inspector(event.paths)
