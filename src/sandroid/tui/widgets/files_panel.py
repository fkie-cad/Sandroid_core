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
(full path, ops with times, processes, watch + last pull), Diff (the last
pull against the one before it) and Events.

Keys (on this lens): ``w`` watch/unwatch · ``u`` pull the row · ``U`` pull
all watched · ``/`` filter · ``n`` watch a path or pattern that is not in
the table · ``a`` auto-pull · ``N`` show noise (as in the Network lens) ·
``.`` full paths · ``z`` zoom the diff · ``Ctrl+L`` clear. Only ``w``/``u``
are shown in the footer (the rest are in ``?``).

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

import contextvars
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.table import Table
from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, Static

from .lens_shell import InspectorContent, is_shown
from .monitor_view import OPS, FileActivity, PathActivity, app_relative, smart_truncate
from .watchlist_view import RowState, WatchlistView

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
        try:
            out.append_text(Text.from_markup(line))
        except Exception:
            out.append(line)
    if len(shown) < len(lines):
        out.append(f"\n… {len(lines)} lines — z for the full diff", style=_DIM)
    return out


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

    # -- compose / mount -----------------------------------------------------

    def compose(self) -> ComposeResult:
        with Horizontal(id="files-notice"):
            yield Static("", id="files-notice-text")
            yield Button("Resume monitoring", id="files-resume-btn")
        table: DataTable = DataTable(
            id="files-table", cursor_type="row", show_header=False, zebra_stripes=False
        )
        yield table
        yield Static("", id="files-empty")
        yield _LensInput(id="files-input")
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
            import asyncio

            from sandroid.core.events import EventBus, EventType

            try:
                self._main_loop = asyncio.get_running_loop()
                # Loop callbacks run in the *scheduling* thread's contextvars
                # context, which lacks Textual's active_app: a set_timer made in
                # one then failed with LookupError. Run them in the UI context.
                self._ui_ctx = contextvars.copy_context()
            except RuntimeError:
                self._main_loop = None
            bus = EventBus.get()

            def _schedule(fn, *args) -> None:
                loop = self._main_loop
                try:
                    if loop is not None and not loop.is_closed():
                        loop.call_soon_threadsafe(
                            fn, *args, context=getattr(self, "_ui_ctx", None)
                        )
                except RuntimeError:
                    pass

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
            if watched is not None:
                row = pinned.setdefault(key, _Row(key=key, watched=watched))
                row.activity = act
            elif self.activity.is_visible(act):
                rest.append(_Row(key=key, activity=act))

        def recency(row: _Row):
            last = row.activity.last if row.activity else None
            return (last is None, -(last.timestamp() if last else 0), row.key)

        rows = sorted(pinned.values(), key=recency) + sorted(rest, key=recency)
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

        The "last" column goes first when it gets narrow (e.g. beside the
        Inspector at 100 columns).
        """
        width = table.size.width or self.size.width or 100
        fixed = _W_MARK + _W_OPS + _W_COUNT + 2 * 4 + 1  # + cell padding, scrollbar
        path_width = width - fixed
        with_last = path_width - (_W_LAST + 2) >= 28
        if with_last:
            path_width -= _W_LAST + 2
        path_width = max(8, path_width)
        if path_width == self._path_width and len(table.columns) == 4 + with_last:
            return
        self._path_width = path_width
        table.clear(columns=True)
        table.add_column("", width=_W_MARK, key="mark")
        table.add_column("path", width=path_width, key="path")
        table.add_column("ops", width=_W_OPS, key="ops")
        table.add_column("count", width=_W_COUNT, key="count")
        if with_last:
            table.add_column("last", width=_W_LAST, key="last")

    def _path_cell(self, row: _Row) -> Text:
        shown = row.key if self._full_paths else app_relative(row.key)
        if not self._full_paths:
            shown = smart_truncate(shown, self._path_width)
        head, sep, name = shown.rpartition("/")
        text = Text(no_wrap=True, overflow="ellipsis")
        if sep:
            text.append(head + sep, style=_DIM)
        text.append(name, style="italic" if row.pattern else "")
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
            n_cols = len(table.columns)
            for row in rows:
                table.add_row(*self._cells(row)[:n_cols], key=row.key)
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
        hidden = self.activity.hidden_count()
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
            parts = [f"{n_paths} path{'s' if n_paths != 1 else ''}"]
            if wl is not None and wl.summary():
                parts.append(wl.summary())
            hidden = self.activity.hidden_count()
            if hidden:
                parts.append(f"{hidden} hidden")
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
        if row.review_kind is not None:
            return InspectorContent(
                title=title,
                subtitle=row.key,
                tabs=[
                    ("Summary", self._review_summary(row)),
                    ("Diff", [("", self._review_diff(row))]),
                ],
                footer="z zoom",
                key=key,
            )
        return InspectorContent(
            title=title,
            subtitle=row.key,
            tabs=[
                ("Summary", self._live_summary(row)),
                ("Diff", [("", self._live_diff(row))]),
                ("Events", [("", self._events_text(row))]),
            ],
            footer="w watch  u pull  z zoom",
            key=key,
        )

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
        else:
            grid.add_row("activity", Text("none seen yet", style=_DIM))
        sections: list = [("", grid)]
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

    def _live_diff(self, row: _Row) -> Text:
        wl = self._watchlist_or_none()
        info = wl.rows.get(row.key) if wl is not None else None
        if info is None:
            if row.pattern:
                return Text("Pull a matching file to see its diff.", style=_DIM)
            return Text.assemble(
                ("Watch (", _DIM), ("w", "bold"), (") and pull (", _DIM),
                ("u", "bold"), (") to diff this file.", _DIM),
            )  # fmt: skip
        if info.state is RowState.CHANGED and info.diff_text is not None:
            return render_diff(info.diff_text)
        messages = {
            RowState.NEVER_PULLED: "Not pulled yet — u pulls a baseline.",
            RowState.BASELINE_ONLY: "Baseline captured — pull again (u) to see what changed.",
            RowState.UNCHANGED: "No changes since the pull before.",
            RowState.CHANGED: "Changed in an earlier session — pull again (u) for a diff.",
            RowState.ERROR: info.detail or "The last pull failed.",
            RowState.SETTLING: "A change is settling; auto-pull will diff it.",
        }
        return Text(messages[info.state], style=_DIM)

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
            if ev.other:
                extra.append(f"from {app_relative(ev.other)}")
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

    def _review_diff(self, row: _Row) -> Text:
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

    def action_clear(self) -> None:
        self.activity.reset()
        self.refresh_rows()

    def action_zoom(self) -> None:
        row = self.current_row()
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

        text = diff if isinstance(diff, str) else "\n".join(diff)
        self.app.push_screen(DiffZoomModal(diff_text=text, title=row.key))

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
