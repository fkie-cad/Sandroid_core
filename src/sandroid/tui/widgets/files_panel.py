"""Files lens: one table of live file activity, with watch marks.

One question per screen -- *what is the app writing, and what changed in
it?* -- answered by ONE full-width table, collapsed per file, newest at the
bottom (watched ★ rows pinned on top)::

    ★ databases/app.db            CM  11x  10:42:05
    ★ shared_prefs/consent.xml    M    3x  10:42:07
      files/aaid.txt              C    1x  10:40:12
    ▸ cache/ · 340 files          CM 412x  10:41:58   (a cache group, ⏎/→ opens)

**Follow** (the Timeline / Network rules, ``follow.py``; the default
"recent" order): a file that changes moves to the bottom and, while *live*,
the cursor sticks to that newest row. ↑, PgUp, Home, a wheel up or a click
on a row above the newest one stop following (the monitor keeps recording),
``End`` resumes, also with a file open in the Inspector (which then follows
the newest row); the caption title says ``live`` or ``scrolled back · 3 new
below · End = live`` (unpinned rows that changed since; ★ rows stay on top).
The frame title says ``monitor on`` / ``monitor off`` for the monitor.

Rows come from the file monitor (``o`` starts/stops it): each
``TASK_OUTPUT``/``source="monitor"`` batch is folded into
:class:`~sandroid.tui.widgets.monitor_view.FileActivity` (tally, per-path
collapse, path rules, mark segments). Watched files -- the Spotlight-Files
watchlist owned by the hidden
:class:`~sandroid.tui.widgets.watchlist_view.WatchlistView` engine -- carry
★ and are pinned on top, also before they saw any activity (wildcard
patterns included). Details live in the Inspector only (Enter): Summary
(full path, ops with times, processes, watch + last pull), Versions (every
kept pull, newest first; the selected one's structured diff against the
version before it or a marked base), Content (a first look inside the
selected version's local copy) and Events (with the marks as separator
lines) -- see ``file_inspect``. In the Inspector ``{``/``}`` pick an older/
newer version (or the previous/next table on Content) and ``*`` sets the
diff base; these are MainScreen keys bound nowhere else, so they never clash
with the lens's ``<``/``>``/``B`` marks. The Inspector forwards the lens keys
it advertises while it has focus (``lens_shell.Inspector.on_key``).

**Marks** (shell-level, ``MainScreen.marks``, a view over the session
timeline's labels): the global ``B`` drops a timestamped mark ("bookmark";
the time is taken when the key is pressed) and asks for an optional name
(⏎ on an empty name = unnamed, Esc = no mark); ``#`` starts and ``-`` stops
a top-level label, whose start and end are segment boundaries too ("label 7
'x'", "after label 7 (no label)"). The table then
shows only what happened since that mark: counts/ops per segment, rows
without activity in the segment hidden, ★ rows with activity in it pinned on
top. The idle ★ rows (and patterns) fold into ONE row below them --
``▸ ★ 21 watched · idle since mark 3`` -- that ⏎/→ opens and ← folds like a
cache group (a single idle ★ row stays as it is). The everything view
(``A``) folds idle ★ rows only when they flood the table (4 or more never
touched this session: ``▸ ★ 20 watched · idle``). ``A`` toggles everything /
since the last mark; ``<``/``>`` step through the segments (before mark 1,
mark 1 → 2, ...). The caption names the segment ("since mark 3 'tap login'
· 10:42:07").

**Path rules** (``tui.files_noise_rules``): by default only OS paths
(``/proc/``, ``/system/``, ``/data/dalvik-cache/``...) and open-only rows are
hidden -- never the app's own data, nor ``/data/local/tmp``. ``cache/`` and
``code_cache/`` collapse into one row per folder (⏎ or → expands, ← folds).
``N`` shows every path raw. ``R`` opens the rule editor (add / remove /
toggle prefix, segment, suffix and glob rules; applies at once, persists in
the config, reset to defaults). The caption counts hidden rows by rule kind.

**Auto-pull** (``tui.auto_pull_on_change``, default on): a write the monitor
reports for a ★ file pulls it once the writes are quiet (~1.5 s), see
``WatchlistView.note_write``. No polling: with the monitor off and files
watched the caption says "monitor off — watched files not tracked · o
starts it".

**Monitor status** (``MonitorWatch`` of the running session): the caption
says what is recorded and how to stop it ("App org.x · 5 proc · following
· o stops", "Path /sdcard · every process", "N events lost"), and replaces
LIVE with "monitor blind since HH:MM:SS · target gone" once the session
records nothing for its app. The watch's timeline lines (app restarted +
gap, exited, events lost) are separators in every file's Events, next to
the marks; Summary "by" counts writes per app process (main, tab_17, gpu).

Keys (on this lens): ``w`` watch/unwatch · ``u`` pull the row · ``U`` pull
all watched · ``/`` filter · ``n`` watch a path or pattern that is not in
the table · ``A`` all / since mark · ``<``/``>`` mark
segments · ``N`` show everything raw (as in the Network lens) · ``R`` path
rules · ``.`` full paths · ``z`` zoom the diff · ``O`` sort (recent / name /
count) · ``Home``/``End`` first/last row · ``Ctrl+L`` clear. Only
``w``/``u`` are shown in the footer (the rest are in ``?``).

Jump target: ``reveal(path, version=None)`` puts the cursor on a file's row
and opens its Inspector on the Versions tab (the Timeline lens's ``J`` on a
``files/pull`` line).

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

import functools
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

from rich.table import Table
from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, Static

from sandroid.core.adb_utils import canonical_device_path, watch_path_problem
from sandroid.core.file_diff import is_legacy_markup_line
from sandroid.tui.row_annotations import LENS_FILES, AnnotationFeed, AnnotationTintMixin
from sandroid.tui.utils.ui_thread import UiDispatcher

from . import file_inspect
from .follow import Follow
from .highlight_bar import (
    HL_WIDTH,
    HighlightBar,
    HighlightView,
    canonical_key,
    escape_markup,
    file_snapshot,
)
from .lens_shell import InspectorContent, Mark, SessionMarks, ShellHeader, is_shown
from .monitor_view import (
    OPS,
    FileActivity,
    NoiseRules,
    PathActivity,
    SegmentStats,
    app_package,
    app_relative,
    smart_truncate,
)
from .network_panel import (
    PRIVACY_COLUMN_MIN_WIDTH,
    privacy_annotations,
    privacy_has_hits,
    privacy_service,
    tag_words,
)
from .watchlist_view import RowState, WatchlistView

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from .lens_shell import MarksChanged, ScopeChanged

logger = logging.getLogger(__name__)

#: How often a dirty table is redrawn (monitor batches arrive every ~0.15 s).
_REFRESH_INTERVAL = 0.4

#: Fixed column widths (★, ops, count, last); the path takes the rest.
_W_MARK, _W_OPS, _W_COUNT, _W_LAST = 1, 5, 5, 8
#: The Identity column (values of the identity profile found in the file).
_W_IDENT = 16

_DIM = "#5b6479"
#: A monitor note that stands out (restart, exit, lost events).
_NOTE_WARNING = "#fb923c"
_STAR = "#7dd3fc"
_STATE_STAR = {
    RowState.CHANGED: "bold #facc15",
    RowState.ERROR: "bold #ef4444",
    RowState.SETTLING: "#a3873f",
}


class _Sep(NamedTuple):
    """A separator line in the Events tab (a mark or a monitor note)."""

    when: datetime
    text: str
    style: str


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


#: Diff lines are plain text; only legacy SQLite lines of runs / versions
#: recorded before that (``\[[success]INSERT[/success]] ...``,
#: ``file_diff.is_legacy_markup_line``) and display lines that *start* with a
#: style tag carry Rich markup. Anything else -- XML paths such as
#: ``string[@name="k"]``, file content, row values -- must not be parsed as
#: markup (``[@...]`` is a tag to Rich).
_MARKUP_START = re.compile(
    r"\[/?(?:success|warning|error|green|red|yellow|cyan|blue|magenta|bold|dim|"
    r"italic|#[0-9a-fA-F]{3})"
)


def _is_markup(line: str) -> bool:
    return is_legacy_markup_line(line) or bool(_MARKUP_START.match(line.lstrip()))


_LINE_STYLES = (
    (("[ADDED]", "[LINE ADDED]", "[INSERT]", "+"), "#4ade80"),
    (("[DELETED]", "[LINE DELETED]", "[DELETE]", "-"), "#fb7185"),
    (("[UPDATED]", "[UPDATE]"), "#facc15"),
    (("@@",), _DIM),
)


def diff_line_text(line: str) -> Text:
    """One diff line as ``Text``: a legacy markup line rendered as markup,
    otherwise literal text coloured by its ``[ADDED]``/``[DELETED]``/... tag.
    """
    if _is_markup(line):
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
    return "\n".join(line if _is_markup(line) else escape(line) for line in lines)


def _fmt_time(when: datetime | None) -> str:
    return when.strftime("%H:%M:%S") if when else ""


#: Follow notes this close to the first of a run are one Events line.
FOLLOW_BURST = timedelta(seconds=10)
_FOLLOW_NOTE_RE = re.compile(
    r"^\+ (?P<label>.+?) \(PID \d+\) followed(?: · (?P<gap>.*))?$"
)
_GAP_RE = re.compile(r"gap ≈(\d+(?:\.\d+)?) s")


def collapse_follow_notes(
    notes: list[tuple[datetime, str, str]],
) -> list[tuple[datetime, str, str]]:
    """One line per burst of ``follow`` notes (sub-processes joining).

    A restart brings 4-5 "+ tab_… (PID n) followed" lines; in a file's
    Events they pushed the file's own events down. Consecutive follow notes
    within :data:`FOLLOW_BURST` of the first become "+ N app processes
    followed · tab_17, gpu, … · gap ≤X s" (each process stays in the log).
    """
    out: list[tuple[datetime, str, str]] = []
    run: list[tuple[datetime, str, str]] = []

    def flush() -> None:
        if len(run) == 1:
            out.append(run[0])
        elif run:
            labels, gaps = [], []
            for _when, text, _level in run:
                m = _FOLLOW_NOTE_RE.match(text)
                labels.append(m.group("label") if m else text)
                g = _GAP_RE.search(text)
                if g:
                    gaps.append(float(g.group(1)))
            shown = ", ".join(labels[:4]) + (", …" if len(labels) > 4 else "")
            text = f"+ {len(run)} app processes followed · {shown}"
            if gaps:
                text += f" · gap ≤{max(gaps):.1f} s"
            out.append((run[0][0], text, "follow"))
        run.clear()

    for note in sorted(notes, key=lambda n: n[0]):
        if note[2] == "follow" and (not run or note[0] - run[0][0] <= FOLLOW_BURST):
            run.append(note)
            continue
        flush()
        if note[2] == "follow":
            run.append(note)
        else:
            out.append(note)
    flush()
    return out


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
    #: What the row shows: the whole session, or one mark segment.
    stats: SegmentStats | None = None
    #: A ★ row without activity in the viewed segment (drawn dim).
    dim: bool = False
    #: A collapsed group row: its folder and member rows.
    group: str | None = None
    members: list[_Row] = field(default_factory=list)
    #: 1 for a member row shown below its expanded group.
    depth: int = 0
    #: The group row folding the idle ★ rows (``group`` is ``IDLE_FOLD``).
    fold: bool = False


def _hl_key(row: _Row) -> str | None:
    """A row's AI highlight key (canonical path); group/fold/pattern: None."""
    if row.group is not None or row.pattern or row.fold:
        return None
    return canonical_key(row.key)


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


class _FilesTable(AnnotationTintMixin, DataTable):
    """The lens table: ``Home``/``End`` move the row cursor.

    DataTable binds them to *horizontal* scrolling (its ``ctrl+home`` is the
    row jump); this table never scrolls sideways, so Home/End jump rows.
    Rows are tinted by their row annotations (``row_annotations``: files
    holding identity-profile values, AI marks), keyed by canonical path.
    """

    annotation_lens = LENS_FILES

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._owner_panel: FilesPanel | None = None

    def annotation_key(self, row_key_value: Any) -> str | None:
        """Row key -> canonical device path (file rows only)."""
        panel = self._owner_panel
        if panel is None:
            panel = next((n for n in self.ancestors if isinstance(n, FilesPanel)), None)
            self._owner_panel = panel
        return panel.annotation_path(row_key_value) if panel is not None else None

    def action_scroll_home(self) -> None:
        self.action_scroll_top()

    def action_scroll_end(self) -> None:
        self.action_scroll_bottom()

    def _panel(self) -> FilesPanel | None:
        parent = self.parent
        return parent if isinstance(parent, FilesPanel) else None

    # Moving up stops following the newest row; End resumes (follow.py).

    def _follow(self, live: bool) -> None:
        panel = self._panel()
        if panel is not None:
            panel.set_following(live)

    def action_cursor_up(self) -> None:
        super().action_cursor_up()
        self._follow(False)

    def action_page_up(self) -> None:
        super().action_page_up()
        self._follow(False)

    def action_scroll_top(self) -> None:
        super().action_scroll_top()
        self._follow(False)

    def action_scroll_bottom(self) -> None:
        super().action_scroll_bottom()
        self._follow(True)

    def on_click(self, event) -> None:
        try:
            row = event.style.meta.get("row")
        except Exception:
            row = None
        if isinstance(row, int) and 0 <= row < self.row_count - 1:
            self._follow(False)

    def on_mouse_scroll_up(self, _event) -> None:
        self._follow(False)

    def action_cursor_right(self) -> None:
        """→ opens a cache group row (the table never scrolls sideways)."""
        panel = self._panel()
        if panel is not None and panel.expand_current(True):
            return
        super().action_cursor_right()

    def action_cursor_left(self) -> None:
        """← folds the group of the row (from the group or one of its files)."""
        panel = self._panel()
        if panel is not None and panel.expand_current(False):
            return
        super().action_cursor_left()


@functools.lru_cache(maxsize=4096)
def _canonical_path(path: str) -> str:
    return canonical_device_path(path)


def _natural_key(text: str) -> list:
    """``f_2`` before ``f_10`` (digits compare as numbers)."""
    return [
        int(part) if part.isdigit() else part.lower() for part in _DIGITS.split(text)
    ]


_DIGITS = re.compile(r"(\d+)")

#: ``O`` cycles the order of the unpinned rows.
SORT_MODES = ("recent", "name", "count")

#: Group id (and row key) of the one row folding the idle ★ rows.
IDLE_FOLD = "\u2605 idle"
#: Idle ★ rows fold into one row from this many on: in a mark segment (the
#: E2E flood: 20 shared_prefs/*.xml watches without activity buried the
#: segment's real activity) and in the everything view (A), where only a
#: flood of never-touched watches folds.
FOLD_IDLE_IN_SEGMENT = 2
FOLD_IDLE_IN_ALL = 4


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
        Binding(
            "A",
            "toggle_since_mark",
            "All / since the last note or section",
            show=False,
        ),
        Binding(
            "less_than_sign",
            "step_mark(-1)",
            "Earlier note / section segment",
            show=False,
        ),
        Binding(
            "greater_than_sign",
            "step_mark(1)",
            "Later note / section segment",
            show=False,
        ),
        Binding("N", "toggle_noise", "Show everything (raw)", show=False),
        Binding("H", "cycle_highlight_filter", "AI filter: next set / off", show=False),
        Binding("X", "clear_highlights", "Clear the AI highlights", show=False),
        Binding("R", "noise_rules", "Hide / group rules…", show=False),
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
            FileActivity.config_visibility(),
            FileActivity.config_max_paths(),
            rules=NoiseRules.from_config(),
        )
        self._filter = ""
        #: Marks of the session (a copy of ``MainScreen.marks``; a lens
        #: outside a MainScreen keeps its own list).
        self._marks: list[Mark] = []
        self._local_marks = SessionMarks()
        #: Viewed segment: None = everything, n = since mark n (0 = before
        #: the first mark).
        self._segment: int | None = None
        #: The time of a label / mark being named (prompt open; MarksChanged).
        self._pending_mark: datetime | None = None
        #: The pending boundaries (one, or two when the label being named
        #: ends an open one at the same instant: end + start).
        self._pending_times: list[datetime] = []
        #: Expanded group folders.
        self._expanded: set[str] = set()
        #: Hidden rows of the last live redraw, by rule kind / "open-only".
        self._hidden: dict[str, int] = {}
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
        #: ``(when, text, level)`` monitor timeline lines (add_monitor_note).
        self._monitor_notes: list[tuple[datetime, str, str]] = []
        self._resume_config: Any = None
        self._event_handlers: list = []
        self._main_loop = None
        self._ui = UiDispatcher()
        #: Follow the newest row (``follow.py``; the "recent" order only) and
        #: the paths that changed since following stopped.
        self._follow = Follow()
        self._new_keys: set[str] = set()
        #: The last refresh put the cursor on the newest row (following).
        self._followed_last = False
        #: Row annotations (privacy, AI marks) of files changed.
        self._privacy_feed = AnnotationFeed(self, LENS_FILES, self._privacy_flush)
        #: (rows, row key -> row): the annotation key of a table row.
        self._row_index: tuple[Any, dict[str, _Row]] = (None, {})
        #: AI highlight sets (``highlight_bar``), keyed by canonical path.
        self._hl = HighlightView(LENS_FILES, noun="file")

    # -- compose / mount -----------------------------------------------------

    def compose(self) -> ComposeResult:
        yield HighlightBar("", id="files-highlights")
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
        self._privacy_feed.attach()
        self.set_interval(_REFRESH_INTERVAL, self._tick)
        marks = getattr(self.screen, "marks", None)
        if isinstance(marks, SessionMarks) and len(marks):
            self._set_marks(marks.marks)
        self.refresh_rows()
        self._hl.attach(self, self._redraw_highlights, self._highlight_rows_snapshot)
        try:
            self.app.theme_changed_signal.subscribe(self, self._repaint_for_theme)
        except Exception:
            pass

    def _repaint_for_theme(self, _theme: Any = None) -> None:
        """A live theme switch: rows, bar and caption take the new palette
        (their Rich styles are built from ``lens_palette()`` at render time).
        """
        if self.is_attached:
            self.refresh_rows()

    def on_unmount(self) -> None:
        self._unsubscribe_events()
        self._privacy_feed.detach()
        self._hl.detach()

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
        else:  # back to LIVE: follow the newest row again
            self._follow.resume()
            self._new_keys.clear()
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
        data = getattr(event, "data", None) or {}
        note = data.get("monitor_note")
        if note:
            self.add_monitor_note(
                note.get("text", ""), note.get("when"), note.get("level", "warning")
            )
        if note or data.get("monitor_status"):
            self._update_caption()  # the caption shows the monitor's scope
        batch = data.get("batch")
        if batch:
            self.ingest(batch)

    #: Monitor timeline lines kept for the Events tab.
    _MAX_NOTES = 200

    def add_monitor_note(
        self, text: str, when: datetime | None = None, level: str = "warning"
    ) -> None:
        """A monitor timeline line (restart + gap, exit, lost events).

        Shown as a separator in every file's Events, like a mark.
        """
        if not text:
            return
        self._monitor_notes.append((when or datetime.now(), text, level))
        del self._monitor_notes[: -self._MAX_NOTES]
        self._refresh_inspector()

    def _monitor_watch(self):
        """The running session's ``MonitorWatch`` (None: none / not running)."""
        running, task = self._monitor_task()
        watch = getattr(getattr(task, "instance", None), "watch", None)
        return watch if running and hasattr(watch, "caption") else None

    def ingest(self, batch, now: datetime | None = None) -> None:
        """Fold a monitor batch in; the table redraws on the next tick."""
        now = now or datetime.now()
        batch = list(batch)
        touched = self.activity.ingest(batch, now=now)
        if touched and not self._follow.live:
            self._new_keys.update(touched)
        writes = self.activity.writes
        if writes:
            wl = self._watchlist_or_none()
            if wl is not None and (wl.has_watches or wl.privacy_watching):
                for key, when, _category in writes:
                    act = self.activity.paths.get(key)
                    if act is not None and (act.deleted or act.moved_to or act.is_dir):
                        continue  # gone again by the end of the batch
                    wl.note_write(key, when)
        if touched:
            self._dirty = True
            self._refresh_inspector(touched)

    def _on_monitor_lifecycle(self, event_type) -> None:
        from sandroid.core.events import EventType

        if event_type == EventType.TASK_STARTED:
            self.clear_resume_offer()
            if self._notice_kind == "playback":
                self._set_notice(None)
            self._on_monitor_started()
        elif self._notice_kind == "backend":
            self._set_notice(None)
        self._dirty = True
        self.refresh_rows()

    def _on_monitor_started(self) -> None:
        """A device clock sample (``monitor-start``) and the session-start
        pulls of the monitored app's watched files, both in the background.
        """
        try:
            from sandroid.core import device_clock

            device_clock.record_async("monitor-start")
        except Exception:
            logger.debug("Files lens: device clock sample failed", exc_info=True)
        wl = self._watchlist_or_none()
        if wl is None:
            return
        root = self._app_root()
        package = root.strip("/").rsplit("/", 1)[-1] if root else None
        wl.pull_session_baselines(package)

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
        """Rewind's start point load auto-stopped the monitor (app.py callback)."""
        self._set_notice(
            "Monitor stopped: it cannot run while Rewind loads the start point.",
            "playback",
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
        """Pinned ★ rows, then activity (and cache groups), in sort order.

        In a mark segment only rows with activity in it are listed (★ rows
        stay; idle ones fold into one ``IDLE_FOLD`` row, see the module doc).
        Rows hidden by a rule are counted per rule kind in ``self._hidden``.
        """
        wl = self._watchlist_or_none()
        segment = self._segment
        pinned: dict[str, _Row] = {}
        rest: list[_Row] = []
        groups: dict[str, list[_Row]] = {}
        hidden: dict[str, int] = {}
        if wl is not None:
            for path in wl.rows:
                pinned[path] = _Row(key=path, watched=path, dim=segment is not None)
            for pattern in wl.patterns:
                pinned[pattern] = _Row(
                    key=pattern, watched=pattern, pattern=True, dim=segment is not None
                )
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
            stats = act.stats(segment)
            if watched is not None:
                row = pinned.setdefault(key, _Row(key=key, watched=watched))
                row.activity = act
                if self._hidden_only(stats):
                    stats = None  # only hidden OPEN events: still idle
                row.stats = stats
                row.dim = segment is not None and stats is None
                continue
            if stats is None:
                continue  # nothing in the viewed segment
            row = _Row(key=key, activity=act, stats=stats)
            if not self._matches(row):
                continue
            reason = self.activity.hide_reason(act, segment)
            if reason is not None and not self._hl.bypass_noise(canonical_key(key)):
                hidden[reason] = hidden.get(reason, 0) + 1
                continue
            folder = (
                None
                if self.activity.show_all or self._hl.filter_id()
                else self.activity.rules.group_of(key)
            )
            if folder is not None:
                groups.setdefault(folder, []).append(row)
            else:
                rest.append(row)
        self._hidden = hidden
        for folder, members in groups.items():
            rest.append(self._group_row(folder, members))

        def recency(row: _Row):
            last = row.stats.last if row.stats else None
            return (last is None, -(last.timestamp() if last else 0), row.key)

        def newest_last(row: _Row):
            last = row.stats.last if row.stats else None
            return (last is not None, last.timestamp() if last else 0, row.key)

        def order(row: _Row):
            if self._sort == "name":
                return _natural_key(app_relative(row.group or row.key))
            if self._sort == "count":
                count = row.stats.count if row.stats else 0
                return (-count, *recency(row))
            return newest_last(row)

        pinned_rows = sorted(
            (r for r in pinned.values() if self._matches(r)), key=order
        )
        # Idle ★ rows (no activity in the viewed segment / ever) fold into
        # one expandable row below the active ★ rows: watching 20 prefs
        # files must not push the segment's real activity off the screen.
        idle = [r for r in pinned_rows if r.stats is None]
        limit = FOLD_IDLE_IN_ALL if segment is None else FOLD_IDLE_IN_SEGMENT
        if len(idle) >= limit:
            active = [r for r in pinned_rows if r.stats is not None]
            fold = _Row(key=IDLE_FOLD, group=IDLE_FOLD, members=idle, fold=True)
            # Newest last: the idle fold above the ★ rows that changed.
            pinned_rows = [fold, *active] if self._sort == "recent" else [*active, fold]
        rows = pinned_rows + sorted(rest, key=order)
        out: list[_Row] = []
        for row in rows:
            out.append(row)
            if row.group is not None and row.group in self._expanded:
                for member in sorted(row.members, key=order):
                    member.depth = 1
                    out.append(member)
        return out

    def _hidden_only(self, stats: SegmentStats | None) -> bool:
        """Every event in ``stats`` is of a hidden (verbose) kind -- OPEN
        and the like -- while the raw view (``N``) is off.
        """
        if stats is None or not stats.ops or self.activity.show_all:
            return False
        return all(self.activity.category_mode(c) == "verbose" for c in stats.ops)

    @staticmethod
    def _group_row(folder: str, members: list[_Row]) -> _Row:
        """One row for a cache folder: summed counts, union of ops."""
        total = SegmentStats()
        for member in members:
            stats = member.stats
            if stats is None:
                continue
            total.count += stats.count
            for cat, n in stats.ops.items():
                total.ops[cat] = total.ops.get(cat, 0) + n
            if stats.first and (total.first is None or stats.first < total.first):
                total.first = stats.first
            if stats.last and (total.last is None or stats.last > total.last):
                total.last = stats.last
        return _Row(key=folder + "/", stats=total, group=folder, members=members)

    def _matches(self, row: _Row, *, ai: bool = True) -> bool:
        """The ``/`` filter and (``ai``) the AI filter (``highlight_bar``)."""
        if ai and not self._hl.passes(_hl_key(row)):
            return False
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

    # -- identity profile values (privacy scan) --------------------------------
    #
    # A file holding values of the identity profile gets a faint warn tint and,
    # from PRIVACY_COLUMN_MIN_WIDTH, the value names in an Identity column.
    # The Versions / Content tabs highlight the found text (file_inspect).
    # New hits (scan worker) mark the table dirty, at most once a second.

    def _privacy_column(self, width: int, path_width: int) -> bool:
        if width < PRIVACY_COLUMN_MIN_WIDTH or path_width - (_W_IDENT + 2) < 24:
            return False
        service = privacy_service()
        try:
            return bool(
                service is not None and (service.is_active or privacy_has_hits(service))
            )
        except Exception:
            return False

    def _privacy_tags(self, row: _Row) -> list:
        if row.group is not None or row.pattern:
            return []
        provider = privacy_annotations()
        if provider is not None:
            return provider.file_tags(row.key)
        return file_inspect.privacy_tags(row.key)

    def _privacy_cell(self, row: _Row) -> Text:
        """The Identity cell (the row tint comes from the row annotations)."""
        return tag_words(self._privacy_tags(row), _W_IDENT)

    def annotation_path(self, key: Any) -> str | None:
        """The annotation key (canonical path) of table row ``key``; file rows only."""
        rows = self._rows
        owner, index = self._row_index
        if owner is not rows:
            index = {r.key: r for r in rows}
            self._row_index = (rows, index)
        row = index.get(str(key)) if key is not None else None
        if row is None or row.group is not None or row.pattern:
            return None
        return _canonical_path(row.key)

    def _privacy_flush(self, paths: set[str] | None) -> None:
        """Row annotations of ``paths`` (canonical; None: every file) changed:
        redraw the table and the Inspector.
        """
        self._dirty = True
        if is_shown(self):
            self.refresh_rows()
        if paths is None:  # a session switch: every file
            self._refresh_inspector()
            return
        from sandroid.core.adb_utils import device_path_aliases

        touched = set(paths)
        for path in paths:
            touched.update(device_path_aliases(path))
        self._refresh_inspector(touched)

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

    @property
    def follow_applies(self) -> bool:
        """Follow the newest row: the live table in the "recent" order."""
        return not self.review and self._sort == "recent"

    @property
    def following(self) -> bool:
        return self._follow.live

    def set_following(self, live: bool) -> None:
        """Stop following (a move up) or resume it (End: the newest row).

        End always resumes, also with a file open in the Inspector: while
        live the Inspector follows the newest row.
        """
        if live:
            changed = self._follow.resume()
            self._new_keys.clear()
            if changed or self.follow_applies:
                self.refresh_rows()
        else:
            changed = self._follow.stop()
            if changed:  # a 2nd ↑ keeps what arrived since the first
                self._new_keys.clear()
        if changed:
            self._update_caption()

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
        if self._privacy_column(width, path_width):
            columns.append("ident")
            path_width -= _W_IDENT + 2
        if self._hl.show_column(width) and path_width - (HL_WIDTH + 2) >= 30:
            columns.append("hl")
            path_width -= HL_WIDTH + 2
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
            "ident": _W_IDENT,
            "hl": HL_WIDTH,
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

    def _idle_label(self) -> str:
        """``idle since Note 3`` / ``idle Note 1 → Section 2`` / ``idle``
        (no notes or sections).
        """
        seg, marks = self._segment, self._marks
        if seg is None or not marks:
            return "idle"
        if seg == 0:
            return f"idle before {marks[0].label()}"
        if seg >= len(marks):
            return f"idle since {marks[seg - 1].label()}"
        return f"idle {marks[seg - 1].label()} → {marks[seg].label()}"

    def _fold_cell(self, row: _Row) -> Text:
        """``★ 21 watched · idle since Note 3`` (shortest form on a narrow
        table: ``★ 21 watched · idle``, ``★ 21 idle``).
        """
        n = len(row.members)
        idle = self._idle_label()
        for tail in (f" watched · {idle}", " watched · idle", " idle"):
            if 2 + len(str(n)) + len(tail) <= self._path_width:
                break
        text = Text(no_wrap=True, overflow="ellipsis")
        text.append("★ ", style=_STAR)
        text.append(str(n), style="#c4b5fd")
        text.append(tail, style=_DIM)
        return text

    def _group_cell(self, row: _Row) -> Text:
        if row.fold:
            return self._fold_cell(row)
        shown = (row.group or "") if self._full_paths else app_relative(row.group or "")
        n = len(row.members)
        tail = f" · {n} file{'s' if n != 1 else ''}"
        if not self._full_paths:
            # Keep the folder's own name ("…/Default/Cache/", never "…/"):
            # on a narrow table the file count gets shorter first.
            name = shown.rpartition("/")[2]
            for candidate in (tail, f" · {n}", ""):
                tail = candidate
                if len(name) + 1 + len(tail) <= self._path_width:
                    break
            shown = smart_truncate(shown, max(4, self._path_width - len(tail) - 1))
        shown += "/"
        text = Text(no_wrap=True, overflow="ellipsis")
        text.append(shown, style="#c4b5fd")
        text.append(tail, style=_DIM)
        return text

    def _path_cell(self, row: _Row) -> Text:
        if row.group is not None:
            return self._group_cell(row)
        if row.depth:
            inner = self._path_cell_inner(row, indent=2)
            return Text("  ").append_text(inner)
        return self._path_cell_inner(row)

    def _path_cell_inner(self, row: _Row, indent: int = 0) -> Text:
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
            width = self._path_width - len(suffix) - indent
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
        if row.dim:
            style = _DIM  # ★ row untouched in the viewed mark segment
        text.append(name, style=style)
        if suffix:
            text.append(suffix, style="#facc15")
        return text

    def _mark_cell(self, row: _Row) -> Text:
        if row.group is not None:
            opened = row.group in self._expanded
            return Text("▾" if opened else "▸", style="#c4b5fd")
        if row.watched is None:
            return Text("")
        wl = self._watchlist_or_none()
        info = wl.rows.get(row.key) if wl is not None else None
        style = _STATE_STAR.get(info.state, _STAR) if info is not None else _STAR
        if row.dim and (info is None or info.state not in _STATE_STAR):
            style = _DIM
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
        stats = row.stats
        if stats is None and row.activity is not None and self._segment is None:
            stats = row.activity.stats(None)
        if self._hidden_only(stats):
            stats = None  # no empty ops column with a count of hidden events
        ops = Text()
        if stats is not None:
            for letter, color in stats.op_letters():
                if letter != OPS["noise"][0] or self.activity.show_all:
                    ops.append(letter, style=color)
        elif row.pattern:
            ops.append("*", style=_DIM)
        count = Text(f"{stats.count}×" if stats else "", style=_DIM, justify="right")
        last = Text(_fmt_time(stats.last) if stats else "", style=_DIM)
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
        if (
            self._follow.live
            and self.follow_applies
            and self._followed_last
            and table.row_count
            and table.cursor_row < table.row_count - 1
        ):
            # The cursor was moved off the newest row (a jump, a select):
            # stop following, never yank it back.
            self._follow.stop()
            self._new_keys.clear()
        follow = self.follow_applies and self._follow.live
        self._followed_last = follow
        self._ensure_columns(table)
        rows = (
            [r for r in self._review_rows if self._matches(r)]
            if self.review
            else self._live_rows()
        )
        self._rows = rows
        if self.follow_applies and not self._follow.live:
            # Rows that changed since: the unpinned ones (they move below);
            # a pinned ★ row stays on top and is no "new below".
            new = self._new_keys
            self._follow.new_below = sum(
                1
                for r in rows
                if r.watched is None
                and not r.fold
                and (r.key in new or any(m.key in new for m in r.members))
            )
        with self.app.batch_update():
            table.clear()
            order = ("mark", "path", "ops", "count", "last", "ident", "hl")
            picks = [order.index(str(c.value)) for c in table.columns]
            for row in rows:
                cells = (*self._cells(row), self._privacy_cell(row), self._hl_cell(row))
                table.add_row(*(cells[i] for i in picks), key=row.key)
            if rows and follow:
                table.move_cursor(row=len(rows) - 1, animate=False)
            elif rows:
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
        # This screen's focus, not app.focused (the top screen's): with a
        # modal open the table could be hidden while it still held this
        # screen's focus, and Textual then dropped focus to nothing.
        focused = self.screen.focused
        had_focus = focused is table
        self.set_class(empty, "-empty")
        if empty:
            self.query_one("#files-empty", Static).update(self._empty_text())
            if had_focus:
                super().focus()
        elif focused is self:
            table.focus()
        self._update_highlight_bar()
        self._update_caption()

    def _empty_text(self) -> Text:
        ai = self._hl.empty_text(self._filter)
        if ai is not None:
            return Text(f"{ai[0]} — {ai[1]}", style=_DIM)
        if self._filter:
            return Text(f"Nothing matches “{self._filter}”", style=_DIM)
        if self.review:
            if self._review_error:
                return Text(f"Could not load this run: {self._review_error}")
            if self._review_record is None:
                return Text("Loading the run…", style=_DIM)
            return Text("This run changed no files.")
        if self._segment is not None and self.activity.paths:
            return Text.assemble(
                (f"Nothing {self._segment_title()} — ", _DIM),
                ("A", "bold"),
                (" shows everything", _DIM),
            )
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
            running, _task = self._monitor_task()
            if self._segment is not None:
                title = self._segment_title()
            else:
                title = "monitor on" if running else "monitor off"
            wl = self._watchlist_or_none()
            n_groups = sum(1 for r in rows if r.group is not None and not r.fold)
            n_paths = sum(
                1 for r in rows if not r.pattern and r.group is None and not r.depth
            )
            n_patterns = sum(1 for r in rows if r.pattern)
            count = f"{n_paths} path{'s' if n_paths != 1 else ''}"
            if n_patterns:
                count += f" + {n_patterns} pattern{'s' if n_patterns != 1 else ''}"
            if n_groups:
                count += f" + {n_groups} group{'s' if n_groups != 1 else ''}"
            parts = [count]
            if wl is not None and wl.summary():
                parts.append(wl.summary())
            hidden = self.hidden_summary()
            if hidden:
                parts.append(hidden)
            if self._sort != "recent":
                parts.append(f"by {self._sort}")
            if self._segment is not None:
                parts.append("A all · </> notes and sections")
            watching = wl is not None and wl.has_watches
            if not running and watching:
                parts.append("monitor off — watched files not tracked · o starts it")
            elif watching and not wl._auto_pull_enabled():
                parts.append("auto-pull off")
            if not rows and not self._filter and not (watching and not running):
                parts = []
            # What the monitor records: scope, following, lost events, how to
            # stop -- and "blind" instead of LIVE once it records nothing.
            watch = self._monitor_watch() if running else None
            if watch is not None:
                try:
                    blind, status = watch.caption()
                except Exception:
                    blind, status = None, []
                if blind:
                    if self._segment is not None:
                        parts.insert(0, title)
                    title = blind
                parts = list(status) + parts
            if self.follow_applies and rows:
                # Follow state: in ONE place, the title (as in every lens).
                title = f"{self._follow.text} · {title}"
        if self._filter:
            parts.insert(0, f"/{escape_markup(self._filter)}")
        ai = self._hl.caption_count(self._hl.view_shown, self._hl.view_total)
        if ai is not None:
            # The frame caption is markup; the label is chat agent text.
            parts.insert(0, escape_markup(ai))
        return title, " · ".join(parts)

    def hidden_summary(self) -> str:
        """``"14 hidden: prefix 12 · open-only 2"`` (empty when none)."""
        if self.activity.show_all or not self._hidden:
            return ""
        total = sum(self._hidden.values())
        kinds = " · ".join(
            f"{kind} {n}"
            for kind, n in sorted(self._hidden.items(), key=lambda kv: -kv[1])
        )
        return f"{total} hidden: {kinds} (N shows)"

    def _hidden_count(self) -> int:
        """Rows hidden by a rule in the last redraw (0 while showing all)."""
        if self.activity.show_all:
            return 0
        return sum(self._hidden.values())

    def _update_caption(self) -> None:
        ms = self._main_screen()
        if ms is None:
            return
        title, info = self.caption()
        try:
            ms.set_lens_caption("files", title, info)
        except Exception:
            pass
        # The header's "● LIVE" must not claim a recording monitor while
        # it is blind (the session's app is gone and nothing is followed).
        blind = None
        watch = self._monitor_watch()
        if watch is not None and getattr(watch, "blind_since", None) is not None:
            blind = "monitor blind"
        try:
            ms.query_one("#shell-header", ShellHeader).set_live_note(blind)
        except Exception:
            pass

    # -- marks + segments ---------------------------------------------------------

    def _segment_title(self) -> str:
        """Caption title of the viewed segment.

        A segment that starts at a label's end has no label:
        ``after Section 7 (no section)``; notes keep ``Note N``.
        """
        seg = self._segment
        marks = self._marks
        if seg is None or not marks:
            return "LIVE"
        if seg == 0:
            return f"before {marks[0].label()} · until {marks[0].when:%H:%M:%S}"
        start = marks[seg - 1]
        after_end = getattr(start, "kind", "point") == "end"
        head = f"{start.label()} (no section)" if after_end else start.label()
        if seg >= len(marks):
            if after_end:
                return f"{head} · {start.when:%H:%M:%S}"
            return f"since {head} · {start.when:%H:%M:%S}"
        end = marks[seg]
        return f"{head} → {end.label()} · {start.when:%H:%M:%S}–{end.when:%H:%M:%S}"

    def _set_marks(self, marks: list[Mark], follow: bool = True) -> None:
        """Adopt the session's marks; ``follow`` jumps to the newest segment."""
        self._marks = list(marks)
        self.activity.set_marks(m.when for m in self._marks)
        wl = self._watchlist_or_none()
        if wl is not None:
            wl.marks = list(self._marks)  # kept versions record their mark
        if follow and self._marks:
            self._segment = len(self._marks)
        elif not self._marks:
            self._segment = None
        self._dirty = True

    def on_marks_changed(self, message: MarksChanged) -> None:
        pending = getattr(message, "pending", None)
        if pending is not None:
            # A label name prompt is open: segment the activity from the key
            # press on, before anything is written (Esc settles it again).
            # ``pending_times`` has the boundaries the label will add (two
            # when it ends an open label), so the pre-split segment numbers
            # are the final ones.
            times = list(getattr(message, "pending_times", None) or [pending])
            self._pending_mark = pending
            self._pending_times = times
            self.activity.set_marks([*(m.when for m in self._marks), *times])
            self._dirty = True
            self.refresh_rows()
            return
        self._pending_mark = None
        self._pending_times = []
        self._set_marks(message.marks, follow=message.added is not None)
        self.refresh_rows()
        self._refresh_inspector()

    @property
    def marks(self) -> list[Mark]:
        return list(self._marks)

    @property
    def segment(self) -> int | None:
        return self._segment

    def drop_mark(self, name: str = "", when: datetime | None = None) -> Mark:
        """Add a mark through the shell (``MainScreen.add_mark``) if there is
        one, else to this lens's own list.
        """
        when = when or datetime.now()
        screen = self._main_screen()
        adder = getattr(screen, "add_mark", None)
        if adder is not None:
            return adder(name, when)  # posts MarksChanged back to this lens
        mark = self._local_marks.add(name, when)
        self._set_marks(self._local_marks.marks)
        self.refresh_rows()
        return mark

    # -- jump target ------------------------------------------------------------------

    def reveal(self, path: str, version: str | None = None) -> bool:
        """Show ``path`` (a device path): cursor on its row, its Inspector on
        the Versions tab, ``version`` (a version folder name) selected.

        Used by the Timeline lens's ``J``. Leaves a mark segment or a filter
        that hides the row. False when the lens does not know the file.
        """
        if self.review:
            self.app.notify("Files lens is in REVIEW (L goes back to live).")
            return False
        path = self._known_alias(path)
        if path not in {r.key for r in self._rows}:
            self._segment = None
            self._filter = ""
            self._dirty = True
            self.refresh_rows()
        row = next((r for r in self._rows if r.key == path and r.group is None), None)
        if row is None:
            row = self._row_for(path)
        if row is None:
            return False
        self.set_following(False)
        try:
            self.table.move_cursor(row=self.table.get_row_index(path), animate=False)
        except Exception:
            pass
        if version:
            file_inspect.state_for(path).selected = version
        ms = self._main_screen()
        if ms is None:
            return True
        ms.open_inspector(self._inspector_for(row))
        try:
            from .lens_shell import Inspector

            inspector = ms.query_one("#inspector", Inspector)
            names = [name for name, _sections in inspector.content.tabs]
            if "Versions" in names:
                inspector.select_tab(names.index("Versions"))
        except Exception:
            pass
        return True

    # -- groups ----------------------------------------------------------------------

    def expand_current(self, expand: bool) -> bool:
        """→/⏎ open the cache group (or the idle ★ fold) under the cursor,
        ← folds it (also from one of its files). False when the row is not
        part of a group.
        """
        row = self.current_row()
        if row is None:
            return False
        folder = row.group
        if folder is None and row.depth:
            folder = next(
                (r.group for r in self._rows if r.group and row in r.members), None
            )
            if folder is None or expand:
                return False
        if folder is None:
            return False
        if expand == (folder in self._expanded):
            return row.group is not None  # already so: swallow on the group row
        if expand:
            self._expanded.add(folder)
        else:
            self._expanded.discard(folder)
        self.set_following(False)
        self.refresh_rows()
        try:
            key = next(r.key for r in self._rows if r.group == folder)
            self.table.move_cursor(row=self.table.get_row_index(key), animate=False)
        except Exception:
            pass
        return True

    # -- inspector -----------------------------------------------------------------

    def inspect_selected(self) -> InspectorContent | None:
        row = self.current_row()
        if row is not None and row.group is not None:
            self.expand_current(row.group not in self._expanded)
            return None
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
        row = next((r for r in self._rows if r.key == path and r.group is None), None)
        if row is None:
            row = self._row_for(path)
        if row is not None:
            ms.update_inspector(self._inspector_for(row))

    def _known_alias(self, path: str) -> str:
        """The form of ``path`` the lens knows it by (rows, activity, the
        watchlist), else its canonical form.
        """
        from sandroid.core.adb_utils import device_path_aliases

        try:
            known = device_path_aliases(path)
        except Exception:
            return path
        aliases = list(dict.fromkeys([path, *known]))
        wl = self._watchlist_or_none()
        keys = {r.key for r in self._rows}
        for alias in aliases:
            if (
                alias in keys
                or alias in self.activity.paths
                or (wl is not None and alias in wl.rows)
            ):
                return alias
        return known[0] if known else path

    def _row_for(self, path: str) -> _Row | None:
        wl = self._watchlist_or_none()
        act = self.activity.paths.get(path)
        watched = wl.watched_by(path) if wl is not None else None
        if act is None and watched is None:
            # An unstarred file the identity profile's auto-watch pulled.
            if self._has_versions(path):
                return _Row(key=path)
            return None
        return _Row(key=path, watched=watched, activity=act)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """⏎ on a cache group row opens/folds it (no Inspector for a group)."""
        row = self.current_row()
        if row is not None and row.group is not None:
            event.stop()
            self.expand_current(row.group not in self._expanded)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """While the Inspector shows a Files row, follow the cursor."""
        ms = self._main_screen()
        if ms is None or not getattr(ms, "inspector_is_open", False):
            return
        key = getattr(ms.inspector_content, "key", None)
        if not (isinstance(key, tuple) and key and key[0] == "files"):
            return
        row = self.current_row()
        if row is not None and row.group is None and key[2] != row.key:
            ms.update_inspector(self._inspector_for(row))

    def _inspector_for(self, row: _Row) -> InspectorContent:
        title = app_relative(row.key).rpartition("/")[2] or row.key
        key = self._inspector_key(row.key)
        keys = {
            # { } * (MainScreen): never a lens key -- < > B are the marks.
            "left_curly_bracket": lambda tab: self._inspect_step(row, tab, -1),
            "right_curly_bracket": lambda tab: self._inspect_step(row, tab, 1),
            "asterisk": lambda tab: self._inspect_base(row, tab),
        }
        click = lambda tab, y: self._inspect_click(row, tab, y)  # noqa: E731
        if row.review_kind is not None:
            tabs = [
                ("Summary", self._review_summary(row) + self._hl_sections(row)),
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
                ("Summary", self._live_summary(row) + self._hl_sections(row)),
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
        """Why a row has no versions (not watched / a pattern), else None.

        A file with kept versions shows them whether or not it is starred:
        the identity profile's auto-watch pulls unstarred app files.
        """
        wl = self._watchlist_or_none()
        if wl is not None and row.key in wl.rows:
            return None
        if not row.pattern and self._has_versions(row.key):
            return None
        if row.pattern:
            return Text("Pull a matching file to see its versions.", style=_DIM)
        return Text.assemble(
            ("Watch (", _DIM), ("w", "bold"), (") and pull (", _DIM),
            ("u", "bold"), (") to diff this file — every pull is kept as a version.", _DIM),
        )  # fmt: skip

    @staticmethod
    def _has_versions(path: str) -> bool:
        """``path`` has kept versions this session (no I/O: the privacy
        scan's in-memory index of pulled files).
        """
        from .network_panel import privacy_service

        service = privacy_service()
        check = getattr(service, "has_versions", None)
        try:
            return bool(check is not None and check(path))
        except Exception:
            return False

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
            if act.pids:
                # Per process (pid), never per thread: "main (4665), tab_17
                # (5395)"; a process without an app label is "PID n".
                top = sorted(act.pids.items(), key=lambda kv: -kv[1])[:3]
                names = []
                for pid, _n in top:
                    label = act.pid_labels.get(pid)
                    names.append(f"{label} ({pid})" if label else f"PID {pid}")
                grid.add_row("by", ", ".join(names))
            elif act.processes:
                # No pid reported: "tab_17 · DOM Worker" counts as tab_17.
                procs: dict[str, int] = {}
                for name, n in act.processes.items():
                    key = name.split(" · ", 1)[0]
                    procs[key] = procs.get(key, 0) + n
                top = sorted(procs.items(), key=lambda kv: -kv[1])[:3]
                grid.add_row("by", ", ".join(name for name, _n in top))
            if act.moved_to:
                grid.add_row("now", Text(f"renamed → {app_relative(act.moved_to)}"))
            elif act.deleted:
                grid.add_row("now", Text("deleted", style=OPS["delete"][1]))
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
                    # The set hash: the file with its -wal / -journal.
                    pull.add_row("set sha256", info.sha256[:16] + "…")
            clock = self._clock_text(info.device_clock)
            if clock is not None:
                pull.add_row("device clock", clock)
            if info.detail and info.state is not RowState.CHANGED:
                pull.add_row("", Text(info.detail, style=_DIM))
            sections.append(("Last pull", pull))
        return sections

    @staticmethod
    def _clock_text(sample: dict | None) -> Text | None:
        """``-75 min vs host`` (amber) when the device clock of the last pull
        was more than 1 s off; device times (mtimes, DB values) are on it.
        """
        from sandroid.core import device_clock

        if not device_clock.notable(sample):
            return None
        offset = device_clock.format_offset(device_clock.device_minus_host(sample))
        return Text(f"{offset} vs host (device times are on it)", style="#fbbf24")

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
        # Separators: the marks, and the monitor's own timeline lines
        # (restart + gap, exit, lost events) -- see add_monitor_note.
        seps = [
            _Sep(m.when, f"── {m.label()} · {m.when:%H:%M:%S} ──", "#facc15")
            for m in self._marks
        ]
        seps += [
            # A restart / exit / loss stands out; a followed sub-process less.
            _Sep(
                when,
                f"── {text} ──",
                _NOTE_WARNING if level == "warning" else "#a3873f",
            )
            for when, text, level in collapse_follow_notes(self._notes())
        ]
        # Separators newer than an event are printed above it (newest
        # first). The newest mark before the oldest event closes the list;
        # a restart / exit / loss between that mark and the oldest event
        # is in the file's time range too (a file first touched after a
        # restart still shows the restart).
        pending = sorted(seps, key=lambda m: m.when, reverse=True)
        oldest = act.events[0].when
        older = [m for m in pending if m.when < oldest and m.style == "#facc15"]
        start = older[0].when if older else None
        notes = [
            m
            for m in pending
            if m.when < oldest
            and m.style == _NOTE_WARNING
            and (start is None or m.when >= start)
        ][: self._MAX_OLDER_NOTES]
        pending = [m for m in pending if m.when >= oldest] + notes + older[:1]
        for ev in reversed(act.events):
            while pending and pending[0].when > ev.when:
                mark = pending.pop(0)
                if out:
                    out.append("\n")
                out.append(mark.text, style=mark.style)
            if out:
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
            if ev.process:
                extra.append(ev.process)
            if extra:
                out.append("  " + " · ".join(extra), style=_DIM)
        for mark in pending:
            out.append("\n")
            out.append(mark.text, style=mark.style)
        return out

    #: Restart/exit/loss lines shown before a file's first event (newest).
    _MAX_OLDER_NOTES = 5

    def _notes(self) -> list[tuple[datetime, str, str]]:
        return list(getattr(self, "_monitor_notes", ()))

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

    # -- AI highlights (highlight_bar) --------------------------------------------

    def _hl_cell(self, row: _Row) -> Text:
        if row.group is not None:
            return self._hl.inside_cell(_hl_key(m) for m in row.members)
        return self._hl.cell(_hl_key(row))

    def _hl_sections(self, row: _Row) -> list:
        last = row.activity.last if row.activity is not None else None
        return self._hl.sections(
            _hl_key(row), last_change=last.timestamp() if last else None
        )

    def _update_highlight_bar(self) -> None:
        """Count the view per highlight set and redraw the bar."""
        try:
            bar = self.query_one("#files-highlights", HighlightBar)
        except Exception:
            return
        if self._hl.active:
            if self.review:
                items: Any = (
                    (_hl_key(r), self._matches(r, ai=False), None, None)
                    for r in self._review_rows
                )
            else:
                items = self._hl_live_items()
            self._hl.measure(items, live=not self.review, changes=True)
        bar.show_text(self._hl.bar_text(self.size.width or 160, self._scope))

    def _hl_live_items(self):
        """``(key, passes the other filters, None, last change)`` per live path.

        Watched (★) files are listed whatever their activity -- idle ones in
        the idle fold -- so they count as present while the ``/`` filter
        lets them through.
        """
        segment = self._segment
        wl = self._watchlist_or_none()
        for key, act in self.activity.paths.items():
            canon = canonical_key(key)
            if wl is not None and wl.watched_by(key) is not None:
                ok = self._matches(_Row(key=key, activity=act, watched=key), ai=False)
            else:
                ok = (
                    act.stats(segment) is not None
                    and (
                        self.activity.hide_reason(act, segment) is None
                        or self._hl.bypass_noise(canon)
                    )
                    and self._matches(_Row(key=key, activity=act), ai=False)
                )
            last = act.last.timestamp() if act.last else None
            yield canon, ok, None, last
        if wl is not None:
            for path in wl.rows:
                if path not in self.activity.paths:
                    row = _Row(key=path, watched=path)
                    yield canonical_key(path), self._matches(row, ai=False), None, None

    def _redraw_highlights(self, _keys: set[str] | None = None) -> None:
        """Highlights changed (AnnotationFeed, H, X): redraw, keep the cursor."""
        self._dirty = True
        self.refresh_rows()
        self.refresh_bindings()
        self._refresh_inspector()

    def _highlight_rows_snapshot(self) -> list[dict]:
        """Every file row of this view for the AI tools (one per canonical path).

        Live: every path with activity plus the watched files; REVIEW: the
        run's changed / new / deleted files. ``shown`` = passes the lens's
        current filters (a member of a folded group counts as shown).
        """
        wl = self._watchlist_or_none()
        if self.review:
            out = [
                file_snapshot(
                    r.key,
                    shown=self._matches(r),
                    watched=r.watched is not None,
                    review_kind=r.review_kind,
                    scope=self._scope,
                    diff=r.review_diff,
                )
                for r in self._review_rows
            ]
        else:
            shown: set[str] = set()
            for r in self._live_rows():
                if r.group is None and not r.pattern:
                    shown.add(r.key)
                shown.update(m.key for m in r.members)
            paths = dict.fromkeys([*self.activity.paths, *(wl.rows if wl else ())])
            out = [
                file_snapshot(
                    path,
                    shown=path in shown,
                    act=self.activity.paths.get(path),
                    watched=wl is not None and wl.watched_by(path) is not None,
                )
                for path in paths
            ]
        unique: dict[str, dict] = {}
        for row in out:
            unique.setdefault(row["key"], row)
        return list(unique.values())

    def handle_escape(self) -> bool:
        """Esc (MainScreen hook, input closed): clear an applied ``/`` filter,
        else leave the AI filter (the rows stay highlighted).
        """
        try:
            field = self.query_one("#files-input", _LensInput)
        except Exception:
            field = None
        if field is not None and self.screen.focused is field:
            self.close_input(cancel=True)
            return True
        if self._filter:
            self._filter = ""
            self.refresh_rows()
            self.app.notify("Filter cleared", timeout=2)
            return True
        if not self._hl.leave_filter():
            return False
        self._redraw_highlights()
        self.app.notify(
            "AI filter off — the rows stay highlighted", timeout=2, markup=False
        )
        return True

    def action_cycle_highlight_filter(self) -> None:
        """``H``: AI filter off -> set 1 -> ... -> off."""
        notice = self._hl.cycle_filter()
        self._redraw_highlights()
        if notice:
            # The notice holds the set's label (chat agent text): no markup.
            self.app.notify(notice, timeout=3, markup=False)

    def action_clear_highlights(self) -> None:
        """``X``: remove this lens's highlight sets (asks first)."""
        self._hl.confirm_clear(self.app, self._redraw_highlights)

    # -- actions ----------------------------------------------------------------------

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action in ("pull", "pull_all") and self.review:
            return False
        if action in ("toggle_since_mark", "step_mark") and self.review:
            return False
        if action in ("cycle_highlight_filter", "clear_highlights"):
            return self._hl.active
        return True

    def _group_row_hint(self, row: _Row) -> bool:
        """``w``/``u`` on a group row (cache folder, idle ★ fold): say how to
        reach its files instead of acting on the folder.
        """
        if row.group is None:
            return False
        self.app.notify(
            "A group row — ⏎ or → lists its files.", severity="warning", timeout=3
        )
        return True

    def action_toggle_watch(self) -> None:
        row = self.current_row()
        if row is None:
            self.app.notify("No file selected.", severity="warning")
            return
        if self._group_row_hint(row):
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
        if self._group_row_hint(row):
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
                # Watching pulls a first version already: no second pull of
                # the same file on top of it.
                if not wl.is_pulling(path):
                    wl.pull([path])
                return
        self.app.notify("Nothing to pull for this row yet.", severity="warning")

    def action_pull_all(self) -> None:
        self.watchlist.pull_all()

    def action_toggle_since_mark(self) -> None:
        """``A``: everything ↔ since the last mark."""
        if not self._marks:
            self.app.notify(
                "No notes or sections yet — B adds a note, # starts a section.",
                severity="warning",
            )
            return
        self._segment = None if self._segment is not None else len(self._marks)
        self.refresh_rows()

    def action_step_mark(self, delta: int) -> None:
        """``<``/``>``: the segment before / after the viewed one."""
        if not self._marks:
            self.app.notify(
                "No notes or sections yet — B adds a note, # starts a section.",
                severity="warning",
            )
            return
        last = len(self._marks)
        current = last if self._segment is None else self._segment
        self._segment = max(0, min(last, current + delta))
        self.refresh_rows()

    def action_noise_rules(self) -> None:
        """``R``: the live hide / group rule editor."""
        from sandroid.tui.modals.noise_rules_modal import NoiseRulesModal

        self.app.push_screen(
            NoiseRulesModal(self.activity.rules.to_list(), self.apply_noise_rules)
        )

    def apply_noise_rules(self, rules: list[dict], persist: bool = True) -> str | None:
        """Use ``rules`` now (and save them as ``tui.files_noise_rules``).

        Returns an error text when they could not be saved (they still apply).
        """
        self.activity.rules = NoiseRules(rules)
        self._dirty = True
        self.refresh_rows()
        if not persist:
            return None
        try:
            from sandroid.config import update_config

            update_config({"tui.files_noise_rules": self.activity.rules.to_list()})
        except Exception as exc:
            logger.warning(f"Could not save the Files rules: {exc}")
            return str(exc)
        return None

    def action_toggle_noise(self) -> None:
        self.activity.show_all = not self.activity.show_all
        self.app.notify(
            "Showing every path (raw)."
            if self.activity.show_all
            else "Hide / group rules on (R edits them)."
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
        if mode == "filter" and field.value:
            # Reopened: the old filter is selected, typing replaces it.
            from textual.widgets.input import Selection

            field.selection = Selection(0, len(field.value))

    def close_input(self, cancel: bool = False) -> None:
        field = self.query_one("#files-input", _LensInput)
        if cancel and field.mode == "filter" and self._filter:
            self._filter = ""
            self.refresh_rows()
        field.mode = "filter"
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
