"""Timeline lens (lens 5): the session timeline, newest at the bottom.

One full-width, virtual list of every line the session timeline
(``sandroid.core.timeline``, ``<device folder>/timeline.jsonl``) holds:
file events, monitor notes, clock samples, snapshot loads, labels, runs,
Tracking input, screenshots and network flows -- each line one row::

    │  10:42:07.123 +12ms files   modify   app    MODIFY databases/app.db · main
    ── ⟲ world 3 · snapshot/load 'clean' ─────────────────────────────────────
    ▶ 7 'Accept cookies' ──────────────────────────────────────────────────────

**Load and live feed.** On the first activation a thread worker reads the
newest ``TAIL_FIRST`` lines from the file (``tail_lines``); ``Home``/``PgUp``
at the top load the next older page. While the lens is shown a 250 ms timer
polls ``service.tail(after_seq)`` (the writer's in-memory ring); new lines
wait ``HOLD_S`` in a hold so a line that is written a little late (device
time converted to host time) still lands in time order. A line that lands
above the viewport while not following keeps the viewport still (the caption
says "↑ n late lines"). While hidden only a 1 s tick updates the badge
(``⚠`` for dropped lines, a locked or failed timeline).

**Rows.** Separators (world change, epoch change, labels, runs, restarts,
Tracking, interventions) are full-width rows that survive structured filters.
``clock/sample`` lines, ``*/count`` lines and a ``device/lost`` that the same
device's ``device/connect`` follows within 5 s are hidden until ``N``.

**Filter** (``/``): ``src:files,label`` ``-src:clock`` ``kind:modify``
``actor:user`` ``phase:replay`` ``run:<id>`` ``world:3`` ``pkg:x``
``level:warn`` plus bare or quoted words matching the summary. The chip row
shows the parsed query; Esc clears it. In REVIEW scope an implicit
``run:<id>`` chip applies (plus the structural rows inside the run's time
window).

**Inspector** (Enter): Line (envelope, data, follow-ups, enclosing labels),
JSON (the line as written; sensitive lines masked while
``timeline.mask_sensitive`` is on -- ``V`` reveals one after a confirmation,
and the reveal is recorded), Ref (what ``ref`` points to) and Chain (seq,
hash, previous hash, a one-line verify). ``J`` jumps to the source of the
selected line: a pulled file (Files), a flow (Network), a run (Sessions) or
the line it refers to.

Keys (lens-local): ``space`` follow on/off · ``end`` newest + follow ·
``home`` oldest / load more · ``/`` filter · ``N`` hidden rows · ``J`` jump ·
``V`` reveal. The global label keys (``#`` ``+`` ``-`` ``B``) and
``Ctrl+T`` (Tracking) are App bindings and work in every lens.

The timeline core and the Tracking service are imported lazily and may be
missing: the lens then says so and the label keys keep marks in memory.
Thread-safety: workers hand results back with :class:`UiDispatcher` (never
the blocking App thread hop).
"""

from __future__ import annotations

import bisect
import hashlib
import importlib
import json
import logging
import re
import shlex
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

from rich.cells import cell_len, set_cell_size
from rich.segment import Segment
from rich.style import Style
from rich.table import Table
from rich.text import Text
from textual.binding import Binding
from textual.containers import Vertical
from textual.geometry import Size
from textual.scroll_view import ScrollView
from textual.strip import Strip
from textual.widgets import Input, Static

from sandroid.tui.utils.ui_thread import UiDispatcher

from .lens_shell import InspectorContent, is_shown

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from .lens_shell import ScopeChanged

logger = logging.getLogger(__name__)

LENS_ID = "timeline"

#: Lines read from the file on the first activation (and per older page).
TAIL_FIRST = 20_000
#: Rows kept in memory; older ones stay on disk (Home loads them back).
ROW_CAP = 200_000
#: Seconds a live line waits before it is inserted (late lines sort in).
HOLD_S = 0.3
#: Live poll interval while the lens is shown.
POLL_S = 0.25
#: A device/lost followed by device/connect within this many seconds folds.
RECONNECT_FOLD_S = 5.0
#: Strip cache size (rendered rows).
_STRIP_CACHE = 2_000
#: Live (unmasked) line dicts kept for the Inspector.
_LINE_CACHE = 5_000

FILTER_KEYS = ("src", "kind", "actor", "phase", "run", "world", "pkg", "level")


# ---------------------------------------------------------------------------
# lazy core imports (the timeline / Tracking may be missing)
# ---------------------------------------------------------------------------


def timeline_module() -> Any | None:
    """``sandroid.core.timeline`` (or None when it is missing)."""
    try:
        mod = importlib.import_module("sandroid.core.timeline")
    except (ImportError, AttributeError):
        return None
    except Exception:
        logger.debug("timeline import failed", exc_info=True)
        return None
    return mod if hasattr(mod, "get_timeline") else None


def timeline_service() -> Any | None:
    """The process timeline service (None when the core is missing)."""
    mod = timeline_module()
    if mod is None:
        return None
    try:
        return mod.get_timeline()
    except Exception:
        logger.debug("get_timeline failed", exc_info=True)
        return None


def tracking_module() -> Any | None:
    """``sandroid.services.tracking_service`` (or None when it is missing)."""
    try:
        mod = importlib.import_module("sandroid.services.tracking_service")
    except (ImportError, AttributeError):
        return None
    except Exception:
        logger.debug("tracking import failed", exc_info=True)
        return None
    return mod if hasattr(mod, "get_tracking") else None


def should_mask_ui() -> bool:
    """``timeline.mask_sensitive`` for the lens (False without the core)."""
    mod = timeline_module()
    if mod is None:
        return False
    try:
        return bool(mod.should_mask("ui"))
    except Exception:
        return False


def mask_line(line: dict) -> dict:
    mod = timeline_module()
    if mod is None or not line.get("sensitive"):
        return line
    try:
        return mod.mask(line)
    except Exception:
        return {**line, "data": {"_masked": True}}


def label_event_text(event: Any) -> str:
    """``label 7 'x'`` / ``after label 7`` / ``mark 9 'x'`` for a LabelEvent."""
    kind = getattr(event, "kind", "point")
    number = getattr(event, "number", 0)
    name = getattr(event, "name", "") or ""
    if kind == "end":
        return f"end of label {number}" + (f" '{name}'" if name else "")
    word = "mark" if kind == "point" else "label"
    text = f"{word} {number}" + (f" '{name}'" if name else "")
    parent = getattr(event, "parent", None)
    if kind == "start" and parent is not None:
        text += f" (in {parent})"
    return text


# ---------------------------------------------------------------------------
# model
# ---------------------------------------------------------------------------


def parse_instant(value: Any) -> float:
    """The envelope's ``t`` (ISO with offset, or epoch) as epoch seconds."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value).timestamp()
        except ValueError:
            pass
    return 0.0


#: (src, kind) pairs that change the world.
_WORLD = {("snapshot", "load"), ("device", "boot"), ("sandroid", "world")}
#: Data kept on a row for these sources (jumps, label depth, separators).
_KEEP_DATA = frozenset({"label", "net", "run", "tracking", "snapshot", "device"})


def _separator(src: str, kind: str, data: Any) -> str:
    if (src, kind) in _WORLD:
        if src == "snapshot" and isinstance(data, dict) and data.get("ok") is False:
            return ""
        return "world"
    if src == "label":
        return "label"
    if src == "run":
        return "run"
    if src == "tracking":
        return "tracking"
    if src == "sandroid" and kind == "resume":
        return "resume"
    if src == "sandroid" and kind == "intervention":
        return "intervention"
    return ""


class Row(NamedTuple):
    """One timeline line as the lens keeps it (sorted by ``key``)."""

    key: tuple[float, int]
    seq: int
    offset: int | None
    src: str
    kind: str
    actor: str
    phase: str
    run: str | None
    world: int
    epoch: int
    level: str
    #: ``s`` sensitive, ``~`` uncertain clock, ``j`` jumpable.
    flags: str
    summary: str
    sep: str
    ref_of: int | None
    pkg: str | None = None
    #: Coalesced / counted lines: how many events the row stands for.
    n: int | None = None
    ref: dict | None = None
    data: dict | None = None
    dev: str | None = None

    @property
    def t(self) -> float:
        return self.key[0]

    @property
    def sensitive(self) -> bool:
        return "s" in self.flags


def row_from_line(line: dict, offset: int | None = None) -> Row:
    """A :class:`Row` from one timeline line (dict)."""
    t = parse_instant(line.get("t"))
    seq = int(line.get("seq") or 0)
    src = str(line.get("src") or "?")
    kind = str(line.get("kind") or "?")
    data = line.get("data") if isinstance(line.get("data"), dict) else None
    ref = line.get("ref") if isinstance(line.get("ref"), dict) else None
    sensitive = bool(line.get("sensitive"))
    flags = ""
    if sensitive:
        flags += "s"
    try:
        err = float(line.get("t_err_ms") or 0)
    except (TypeError, ValueError):
        err = 0.0
    if line.get("clk", "host") != "host" or err > 100:
        flags += "~"
    n = None
    if data is not None:
        if isinstance(data.get("n"), int) and data["n"] > 1:
            n = data["n"]
        elif kind == "count" and isinstance(data.get("counts"), dict):
            n = sum(v for v in data["counts"].values() if isinstance(v, int))
    jumpable = bool(ref) or (src == "files" and kind in ("pull", "check"))
    if jumpable:
        flags += "j"
    keep = None
    if not sensitive and data is not None:
        if (
            src in _KEEP_DATA
            or (src == "files" and kind in ("pull", "check"))
            or (src == "sandroid" and kind in ("world", "intervention", "resume"))
        ):
            keep = data
    of = ref.get("of") if ref else None
    return Row(
        key=(t, seq),
        seq=seq,
        offset=offset,
        src=src,
        kind=kind,
        actor=str(line.get("actor") or ""),
        phase=str(line.get("phase") or "live"),
        run=line.get("run"),
        world=int(line.get("world") or 0),
        epoch=int(line.get("epoch") or 0),
        level=str(line.get("level") or "info"),
        flags=flags,
        summary=str(line.get("summary") or ""),
        sep=_separator(src, kind, data),
        ref_of=of if isinstance(of, int) else None,
        pkg=line.get("pkg"),
        n=n,
        ref=ref,
        data=keep,
        dev=line.get("dev"),
    )


# ---------------------------------------------------------------------------
# filter grammar
# ---------------------------------------------------------------------------


@dataclass
class Query:
    """A parsed ``/`` filter (see the module docstring)."""

    text: str = ""
    pos: dict[str, set[str]] = field(default_factory=dict)
    neg: dict[str, set[str]] = field(default_factory=dict)
    words: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.pos or self.neg or self.words)


_TERM = re.compile(r"(-?)([a-z]+):(.+)")


def parse_query(text: str) -> Query:
    """Parse the filter grammar; unknown ``key:`` terms are plain words."""
    query = Query(text=text)
    try:
        tokens = shlex.split(text)
    except ValueError:  # an unbalanced quote while typing
        tokens = text.replace('"', " ").split()
    for token in tokens:
        match = _TERM.fullmatch(token)
        if match and match.group(2) in FILTER_KEYS:
            values = {v.strip().lower() for v in match.group(3).split(",") if v.strip()}
            if values:
                target = query.neg if match.group(1) else query.pos
                target.setdefault(match.group(2), set()).update(values)
                continue
        word = token.strip().lower()
        if word:
            query.words.append(word)
    return query


def _field(row: Row, key: str) -> str:
    value = getattr(row, key, None)
    return "" if value is None else str(value).lower()


# ---------------------------------------------------------------------------
# rendering helpers
# ---------------------------------------------------------------------------

_BG_SEL = Style(bgcolor="#11203a")
_ST = {
    "time": Style(color="#8f9bb3"),
    "delta": Style(color="#5b6479"),
    "src": Style(color="#7dd3fc"),
    "kind": Style(color="#a5b4fc"),
    "actor": Style(color="#8f9bb3"),
    "text": Style(color="#e2e8f0"),
    "dim": Style(color="#5b6479"),
    "gutter": Style(color="#facc15"),
    "warn": Style(color="#fb923c", bold=True),
    "error": Style(color="#ef4444", bold=True),
    "clock": Style(color="#a3873f"),
    "masked": Style(color="#94a3b8"),
    "world": Style(color="#f472b6", bold=True),
    "epoch": Style(color="#fbbf24"),
    "label": Style(color="#facc15", bold=True),
    "run": Style(color="#fb7185", bold=True),
    "resume": Style(color="#94a3b8", bold=True),
    "tracking": Style(color="#4ade80", bold=True),
    "intervention": Style(color="#fb923c", bold=True),
    "note": Style(color="#5b6479", italic=True),
}
#: Per line type styling, keyed by ``(src, kind)`` or ``src`` (the pair wins):
#: ``fg`` colours the summary, ``tint`` blends the row background a little
#: towards a colour, ``bold``. Colours are lens theme token names
#: (``LensPalette`` fields), read at render time.
_TYPE_STYLE: dict[tuple[str, str] | str, dict[str, Any]] = {
    # Identity-profile values found by the privacy scan.
    ("privacy", "sent"): {"fg": "warn", "tint": "warn", "bold": True},
    ("privacy", "stored"): {"fg": "accent", "tint": "accent"},
}
#: How far ``tint`` moves the row background towards its colour.
_TINT_AMOUNT = 0.13


def type_style(src: str, kind: str) -> tuple[Style | None, Style | None]:
    """``(summary style, row background)`` of a line type, or ``None``s."""
    spec = _TYPE_STYLE.get((src, kind)) or _TYPE_STYLE.get(src)
    if not spec:
        return None, None
    from textual.color import Color

    from sandroid.tui.themes import lens_palette

    pal = lens_palette()
    fg = getattr(pal, spec["fg"], None) if spec.get("fg") else None
    text = Style(color=fg, bold=bool(spec.get("bold")) or None) if fg else None
    tint = None
    if spec.get("tint"):
        try:
            color = Color.parse(pal.bg).blend(
                Color.parse(getattr(pal, spec["tint"])), _TINT_AMOUNT
            )
            tint = Style(bgcolor=color.hex)
        except Exception:
            tint = None
    return text, tint


_RUN_ICON = {
    "record-start": "● REC",
    "record-stop": "■ REC",
    "record-result": "● REC",
    "play-start": "▷ Play",
    "phase": "▷",
    "play-end": "■ Play done",
}


def format_delta(seconds: float) -> str:
    """``+12ms`` / ``+1.4s`` / ``+3m`` / ``+2h`` (``-`` for a step back)."""
    sign = "-" if seconds < 0 else "+"
    s = abs(seconds)
    if s < 1:
        return f"{sign}{int(s * 1000)}ms"
    if s < 60:
        return f"{sign}{s:.1f}s"
    if s < 3600:
        return f"{sign}{int(s // 60)}m"
    return f"{sign}{int(s // 3600)}h"


def _clock(t: float) -> str:
    when = datetime.fromtimestamp(t)
    return f"{when:%H:%M:%S}.{when.microsecond // 1000:03d}"


def _fit(text: str, width: int) -> str:
    """``text`` cut (with ``…``) or padded to exactly ``width`` cells."""
    if width <= 0:
        return ""
    if cell_len(text) > width:
        return set_cell_size(text, width - 1) + "…"
    return set_cell_size(text, width)


# ---------------------------------------------------------------------------
# widgets
# ---------------------------------------------------------------------------


class _TLInput(Input):
    """The hidden ``/`` filter input; claims Esc (see FilesPanel._LensInput)."""

    BINDINGS = [Binding("escape", "cancel_input", "Cancel", show=False)]

    def check_consume_key(self, key: str, character: str | None) -> bool:
        if key == "escape":
            return True
        return super().check_consume_key(key, character)

    def action_cancel_input(self) -> None:
        for node in self.ancestors:
            if isinstance(node, TimelineLens):
                node.close_filter(clear=True)
                return


class TimelineView(ScrollView, can_focus=True, inherit_bindings=False):
    """Line-API list of the lens's visible rows, with its own row cursor."""

    BINDINGS = [
        Binding("up", "cursor(-1)", "Up", show=False),
        Binding("down", "cursor(1)", "Down", show=False),
        Binding("pageup", "page(-1)", "Page up", show=False),
        Binding("pagedown", "page(1)", "Page down", show=False),
    ]

    DEFAULT_CSS = """
    TimelineView {
        height: 1fr;
        background: #080c18;
        scrollbar-size-vertical: 1;
        overflow-x: hidden;
    }
    """

    def _lens(self) -> TimelineLens | None:
        parent = self.parent
        return parent if isinstance(parent, TimelineLens) else None

    def render_line(self, y: int) -> Strip:
        lens = self._lens()
        width = self.scrollable_content_region.width or self.size.width
        if lens is None:
            return Strip.blank(width)
        return lens.strip_for(int(self.scroll_offset.y) + y, width)

    def action_cursor(self, delta: int) -> None:
        lens = self._lens()
        if lens is not None:
            lens.move_cursor(delta)

    def action_page(self, delta: int) -> None:
        lens = self._lens()
        if lens is not None:
            height = max(1, self.scrollable_content_region.height - 1)
            lens.move_cursor(delta * height, page=True)

    def on_click(self, event) -> None:
        lens = self._lens()
        if lens is None:
            return
        try:
            y = event.get_content_offset(self).y
        except Exception:
            y = getattr(event, "y", 0)
        if y is None:
            return
        lens.click_line(int(self.scroll_offset.y) + int(y))

    def on_mouse_scroll_up(self, _event) -> None:
        lens = self._lens()
        if lens is not None:
            lens.pause_follow()

    def on_resize(self, _event) -> None:
        lens = self._lens()
        if lens is not None:
            lens.view_resized()


class TimelineLens(Vertical):
    """The Timeline lens (id ``timeline-panel``); see the module docstring."""

    can_focus = True

    BINDINGS = [
        Binding("space", "toggle_follow", "Follow", key_display="␣"),
        Binding("end", "newest", "Newest + follow", show=False),
        Binding("home", "oldest", "Oldest / load more", show=False),
        Binding("slash", "filter", "Filter", show=False),
        Binding("N", "toggle_hidden", "Hidden rows (clock, counts)", show=False),
        Binding("J", "jump", "Jump to the line's source", show=False),
        Binding("V", "reveal", "Reveal a masked line…", show=False),
    ]

    DEFAULT_CSS = """
    TimelineLens {
        height: 1fr;
        background: #080c18;
    }
    TimelineLens > #tl-chips {
        height: 1;
        padding: 0 1;
        color: #8f9bb3;
        background: #0b1628;
    }
    TimelineLens > #tl-filter {
        display: none;
        height: 1;
        border: none;
        padding: 0 1;
        background: #0b1628;
    }
    TimelineLens > #tl-filter.-shown {
        display: block;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._rows: list[Row] = []
        self._by_seq: dict[int, Row] = {}
        self._view: list[int] = []
        self._cursor = 0
        self._follow = True
        self._new_below = 0
        self._late_above = 0
        self._show_hidden = False
        self._query = Query()
        self._review_run: str | None = None
        self._review_window: tuple[float, float] | None = None
        self._folded: set[int] = set()
        self._reconnect: dict[int, float] = {}
        self._spans: dict[int, list] = {}
        self._pending: list[Row] = []
        self._lines: OrderedDict[int, dict] = OrderedDict()
        self._strips: OrderedDict[tuple, Strip] = OrderedDict()
        self._last_seq = 0
        self._first_offset = 0
        self._folder: str | None = None
        self._loaded = False
        self._loading = False
        self._gen = 0
        self._revealed: int | None = None
        self._detail: dict[int, dict] = {}
        self._note = ""
        self._ui = UiDispatcher()
        self._poll_timer = None

    # -- compose / mount ---------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static("", id="tl-chips")
        yield TimelineView(id="tl-view")
        yield _TLInput(
            id="tl-filter",
            placeholder='src:files -src:clock actor:user "word"   ⏎ keep · esc clear',
        )

    def on_mount(self) -> None:
        self._ui = UiDispatcher.capture()
        self._poll_timer = self.set_interval(POLL_S, self._poll, pause=True)
        self.set_interval(1.0, self._badge_tick)
        self._update_chips()

    @property
    def view(self) -> TimelineView:
        return self.query_one("#tl-view", TimelineView)

    def focus(self, scroll_visible: bool = True):
        try:
            self.view.focus(scroll_visible)
            return self
        except Exception:
            return super().focus(scroll_visible)

    def _main_screen(self):
        screen = getattr(self, "screen", None)
        return screen if hasattr(screen, "set_lens_caption") else None

    # -- public state (tests, other lenses) ------------------------------------

    @property
    def rows(self) -> list[Row]:
        return self._rows

    @property
    def visible_rows(self) -> list[Row]:
        return [self._rows[i] for i in self._view]

    @property
    def cursor_row(self) -> Row | None:
        if not self._view:
            return None
        self._cursor = max(0, min(self._cursor, len(self._view) - 1))
        return self._rows[self._view[self._cursor]]

    @property
    def following(self) -> bool:
        return self._follow

    @property
    def query_text(self) -> str:
        return self._query.text

    @property
    def late_above(self) -> int:
        return self._late_above

    # -- activation, load --------------------------------------------------------------

    def on_lens_activated(self) -> None:
        if not self._loaded and not self._loading:
            self.reload()
        if self._poll_timer is not None:
            self._poll_timer.resume()
        self._update_caption()

    def _timeline_path(self) -> Path | None:
        mod = timeline_module()
        svc = timeline_service()
        if mod is None or svc is None:
            return None
        try:
            folder = svc.status().folder
        except Exception:
            folder = None
        self._folder = folder
        if not folder:
            return None
        return Path(folder) / getattr(mod, "FILE_NAME", "timeline.jsonl")

    def reload(self) -> None:
        """(Re)read the newest ``TAIL_FIRST`` lines of the active timeline."""
        self._gen += 1
        gen = self._gen
        self._loading = True
        path = self._timeline_path()
        mod = timeline_module()
        if mod is None:
            self._loading = False
            self._loaded = True
            self._note = "Timeline unavailable (the timeline core is not installed)."
            self._apply_rows([], 0)
            return

        def job() -> None:
            rows: list[Row] = []
            first = 0
            if path is not None and path.exists():
                try:
                    lines, first = mod.tail_lines(
                        path, TAIL_FIRST, reader="ui", mask_sensitive=False
                    )
                    rows = [row_from_line(line, off) for off, line in lines]
                    rows.sort(key=lambda r: r.key)
                except Exception:
                    logger.warning("Timeline lens: load failed", exc_info=True)
            self._ui.post(self._load_done, gen, rows, first)

        self._run_job(job, "timeline-load")

    def _run_job(self, fn, name: str) -> None:
        try:
            self.run_worker(fn, name=name, thread=True, exclusive=False)
        except Exception:
            fn()

    def _load_done(self, gen: int, rows: list[Row], first: int) -> None:
        if gen != self._gen:
            return
        self._loading = False
        self._loaded = True
        self._note = "" if self._folder else "No device bound yet — nothing recorded."
        self._apply_rows(rows, first)
        if is_shown(self) and self._poll_timer is not None:
            self._poll_timer.resume()

    def _apply_rows(self, rows: list[Row], first: int) -> None:
        self._revealed = None
        self._rows = rows
        self._by_seq = {r.seq: r for r in rows}
        self._last_seq = max(self._by_seq, default=0)
        self._first_offset = first
        self._pending.clear()
        self._spans.clear()
        for r in rows:
            self._note_label(r)
        self._late_above = 0
        self._new_below = 0
        self._rebuild_view(keep=False)
        if self._follow:
            self._cursor = max(0, len(self._view) - 1)
        self._sync_view(scroll_to_cursor=True, end=self._follow)

    def on_timeline_bound(self) -> None:
        """The active sink changed (``op:"bound"``): read the new file."""
        self._drop_reveal()
        self._loaded = False
        self._lines.clear()
        self._detail.clear()
        if is_shown(self):
            self.reload()

    # -- older pages -------------------------------------------------------------------

    def load_older(self) -> None:
        """``Home``/``PgUp`` at the top: read the page before the first row."""
        if self._loading or self._first_offset <= 0:
            return
        if len(self._rows) >= ROW_CAP:
            self.app.notify(f"{ROW_CAP:,} lines loaded: the cap.", timeout=3)
            return
        mod = timeline_module()
        path = self._timeline_path()
        if mod is None or path is None:
            return
        end = self._first_offset
        known = [r.offset for r in self._rows if r.offset is not None]
        span = (max(known) - min(known)) if len(known) > 1 else 0
        avg = max(64, span // max(1, len(known) - 1)) if span else 256
        start = max(0, end - avg * TAIL_FIRST)
        gen = self._gen
        self._loading = True

        def job() -> None:
            rows: list[Row] = []
            first = start
            try:
                begin = start
                if begin > 0:
                    with path.open("rb") as fh:  # align to a line start
                        fh.seek(begin - 1)
                        if fh.read(1) != b"\n":
                            fh.readline()
                        begin = fh.tell()
                first = begin
                for off, line in mod.read_lines(
                    path, start=begin, end=end, reader="ui", mask_sensitive=False
                ):
                    rows.append(row_from_line(line, off))
            except Exception:
                logger.warning("Timeline lens: older page failed", exc_info=True)
            self._ui.post(self._older_done, gen, rows, first)

        self._run_job(job, "timeline-older")

    def _older_done(self, gen: int, rows: list[Row], first: int) -> None:
        self._loading = False
        if gen != self._gen:
            return
        fresh = [r for r in rows if r.seq not in self._by_seq]
        anchor = self.cursor_row
        self._first_offset = first
        if fresh:
            for r in fresh:
                self._by_seq[r.seq] = r
                self._note_label(r)
            self._rows = sorted(fresh + self._rows, key=lambda r: r.key)
            self._rebuild_view(keep=False)
            if anchor is not None:
                self._select_seq(anchor.seq, quiet=True)
        self._sync_view(scroll_to_cursor=True)
        self.app.notify(f"{len(fresh):,} older lines loaded.", timeout=2)

    # -- live feed ---------------------------------------------------------------------

    def _poll(self) -> None:
        """250 ms while shown: pull new lines from the writer's ring."""
        if not is_shown(self):
            if self._poll_timer is not None:
                self._poll_timer.pause()
            return
        if not self._loaded or self._loading:
            return
        svc = timeline_service()
        if svc is None:
            return
        try:
            folder = svc.status().folder
        except Exception:
            folder = self._folder
        if folder != self._folder:
            self.on_timeline_bound()
            return
        try:
            result = svc.tail(after_seq=self._last_seq)
        except Exception:
            logger.debug("timeline tail failed", exc_info=True)
            return
        if getattr(result, "gap", False):
            self._reload_gap()
            return
        pending = {r.seq for r in self._pending}
        # The ring's file offsets (``TailResult.offsets``, parallel to
        # ``lines``) when the core provides them: a live row then reads its
        # line back like a loaded one once it left the line cache.
        offsets = getattr(result, "offsets", None)
        if not isinstance(offsets, (list, tuple)) or len(offsets) != len(result.lines):
            offsets = None
        for i, line in enumerate(result.lines):
            try:
                seq = int(line.get("seq") or 0)
            except (TypeError, ValueError):
                continue
            if seq <= 0 or seq in self._by_seq or seq in pending:
                continue
            self._lines[seq] = line
            off = offsets[i] if offsets is not None else None
            self._pending.append(
                row_from_line(line, off if isinstance(off, int) and off >= 0 else None)
            )
            pending.add(seq)
            self._last_seq = max(self._last_seq, seq)
        while len(self._lines) > _LINE_CACHE:
            self._lines.popitem(last=False)
        self.release_pending()

    def release_pending(self, now: float | None = None) -> int:
        """Insert held lines older than ``HOLD_S``; returns how many."""
        if not self._pending:
            return 0
        now = time.time() if now is None else now
        ready = [r for r in self._pending if now - r.t >= HOLD_S]
        if not ready:
            return 0
        done = {r.seq for r in ready}
        self._pending = [r for r in self._pending if r.seq not in done]
        self.insert_rows(ready)
        return len(ready)

    def _reload_gap(self) -> None:
        """The ring overran: read the file from the last loaded offset on."""
        mod = timeline_module()
        path = self._timeline_path()
        if mod is None or path is None:
            return
        known = [r.offset for r in self._rows if r.offset is not None]
        start = max(known) if known else 0
        last = self._last_seq
        gen = self._gen
        self._loading = True

        def job() -> None:
            rows: list[Row] = []
            try:
                for off, line in mod.read_lines(
                    path, start=start, reader="ui", mask_sensitive=False
                ):
                    if int(line.get("seq") or 0) > last:
                        rows.append(row_from_line(line, off))
            except Exception:
                logger.warning("Timeline lens: gap reload failed", exc_info=True)
            self._ui.post(self._gap_done, gen, rows)

        self._run_job(job, "timeline-gap")

    def _gap_done(self, gen: int, rows: list[Row]) -> None:
        self._loading = False
        if gen != self._gen:
            return
        rows = [r for r in rows if r.seq not in self._by_seq]
        if rows:
            self._last_seq = max(self._last_seq, *(r.seq for r in rows))
            self.insert_rows(rows)

    def insert_rows(self, new: list[Row]) -> None:
        """Bisect-insert rows; the viewport stays put unless following."""
        new = sorted((r for r in new if r.seq not in self._by_seq), key=lambda r: r.key)
        if not new:
            return
        for r in new:
            self._by_seq[r.seq] = r
            self._note_label(r)
        view = self.view if self.is_mounted else None
        top = int(view.scroll_offset.y) if view is not None else 0
        top_row = self._row_at_display(top)
        cursor = self.cursor_row
        if not self._rows or new[0].key >= self._rows[-1].key:
            for r in new:  # fast path: appended in time order
                self._rows.append(r)
                if self._visible(len(self._rows) - 1):
                    self._view.append(len(self._rows) - 1)
                    if not self._follow:
                        self._new_below += 1
            self._strips.clear()
        else:
            for r in new:
                self._insert_one(r)
            self._strips.clear()
            self._view_seq_cache = None
            if top_row is not None and not self._follow:
                before = self._view_index(top_row.seq)
                late = sum(
                    1
                    for r in new
                    if r.key < top_row.key and self._view_index(r.seq) is not None
                )
                if late:
                    self._late_above += late
                if before is not None and view is not None:
                    offset = self._display_offset()
                    view.scroll_to(y=before + offset, animate=False, immediate=True)
            if cursor is not None:
                self._select_seq(cursor.seq, quiet=True)
        self._enforce_cap()
        if self._follow:
            self._cursor = max(0, len(self._view) - 1)
            self._new_below = 0
        self._sync_view(scroll_to_cursor=self._follow, end=self._follow)

    def _insert_one(self, row: Row) -> None:
        """Bisect-insert one late row and patch the view in place.

        A full rebuild re-evaluated every row (140 ms at 200k rows) for one
        late line; only the new row and its successor (whose epoch separator
        depends on its predecessor) can change visibility.
        """
        pos = bisect.bisect_right(self._rows, row.key, key=lambda x: x.key)
        self._rows.insert(pos, row)
        view = self._view
        k = bisect.bisect_left(view, pos)
        if k < len(view):
            view[k:] = [i + 1 for i in view[k:]]
        for i in (pos, pos + 1):
            if i >= len(self._rows):
                continue
            j = bisect.bisect_left(view, i)
            present = j < len(view) and view[j] == i
            visible = self._visible(i)
            if visible and not present:
                view.insert(j, i)
            elif present and not visible:
                del view[j]

    def _enforce_cap(self) -> None:
        extra = len(self._rows) - ROW_CAP
        if extra <= 0:
            return
        dropped = self._rows[:extra]
        self._rows = self._rows[extra:]
        for r in dropped:
            self._by_seq.pop(r.seq, None)
        firsts = [r.offset for r in self._rows[:64] if r.offset is not None]
        if firsts:
            self._first_offset = min(firsts)
        self._view = [i - extra for i in self._view if i >= extra]
        self._cursor = max(0, self._cursor - sum(1 for _ in dropped))
        self._strips.clear()

    # -- view model --------------------------------------------------------------------

    def _note_label(self, row: Row) -> None:
        """Keep the label spans (number -> [start t, end t, depth])."""
        if row.src == "label" and row.data:
            number = row.data.get("number")
            if not isinstance(number, int):
                return
            if row.kind == "start":
                span = self._spans.setdefault(number, [row.t, None, 0])
                span[0] = row.t
                span[2] = int(row.data.get("depth") or 0)
            elif row.kind == "end":
                span = self._spans.setdefault(number, [row.t, None, 0])
                span[1] = row.t

    def _depth_at(self, t: float) -> int:
        return sum(
            1
            for start, end, _d in self._spans.values()
            if start <= t and (end is None or t < end)
        )

    def _epoch_sep(self, i: int) -> bool:
        if i <= 0:
            return False
        row = self._rows[i]
        return not row.sep and row.epoch > self._rows[i - 1].epoch

    def _hidden_kind(self, i: int) -> bool:
        row = self._rows[i]
        if (row.src, row.kind) == ("clock", "sample") or row.kind == "count":
            return True
        return row.seq in self._folded

    def _visible(self, i: int) -> bool:
        row = self._rows[i]
        if row.src == "device" and row.kind == "connect":
            self._fold_reconnect(i)
        if not self._show_hidden and self._hidden_kind(i):
            return False
        return self._matches(row, bool(row.sep) or self._epoch_sep(i))

    def _fold_reconnect(self, i: int) -> None:
        row = self._rows[i]
        for j in range(i - 1, max(-1, i - 50), -1):
            prev = self._rows[j]
            if row.t - prev.t > RECONNECT_FOLD_S:
                return
            if prev.src == "device" and prev.kind == "lost" and prev.dev == row.dev:
                self._folded.add(row.seq)
                self._reconnect[prev.seq] = row.t - prev.t
                return

    def _matches(self, row: Row, sep: bool) -> bool:
        q = self._query
        if q.words:
            summary = row.summary.lower()
            if not all(w in summary for w in q.words):
                return False
        for key, values in q.neg.items():
            if sep and key not in ("src", "run"):
                # separators survive negative terms too; only an explicit
                # -src: (or a text word) hides them (DESIGN_FINAL §11)
                continue
            if _field(row, key) in values:
                return False
        run = self._review_run
        if run is not None:
            in_run = row.run == run
            if not in_run:
                window = self._review_window
                if not (sep and window and window[0] <= row.t <= window[1]):
                    return False
        for key, values in q.pos.items():
            if sep and key != "run":
                continue  # separators survive structured filters
            if key == "run" and sep:
                window = self._review_window
                if _field(row, key) in values or (
                    window and window[0] <= row.t <= window[1]
                ):
                    continue
                return False
            if _field(row, key) not in values:
                return False
        return True

    def _rebuild_view(self, keep: bool = True) -> None:
        anchor = self.cursor_row if keep else None
        self._folded.clear()
        self._reconnect.clear()
        self._view = [i for i in range(len(self._rows)) if self._visible(i)]
        self._strips.clear()
        self._view_seq_cache = None
        if anchor is not None:
            self._select_seq(anchor.seq, quiet=True)

    def _view_seqs(self) -> set[int]:
        cache = getattr(self, "_view_seq_cache", None)
        if cache is None:
            cache = self._view_seq_cache = {self._rows[i].seq for i in self._view}
        return cache

    def _view_index(self, seq: int) -> int | None:
        row = self._by_seq.get(seq)
        if row is None:
            return None
        pos = bisect.bisect_left(self._rows, row.key, key=lambda x: x.key)
        idx = bisect.bisect_left(self._view, pos)
        if idx < len(self._view) and self._view[idx] == pos:
            return idx
        return None

    def _display_offset(self) -> int:
        """Display lines above the first row (the "older lines" note)."""
        return 1 if self._first_offset > 0 else 0

    def _row_at_display(self, y: int) -> Row | None:
        vi = y - self._display_offset()
        if 0 <= vi < len(self._view):
            return self._rows[self._view[vi]]
        return None

    def _select_seq(self, seq: int, quiet: bool = False) -> bool:
        idx = self._view_index(seq)
        if idx is None:
            return False
        self._cursor = idx
        if not quiet:
            self._cursor_moved()
        return True

    # -- rendering ---------------------------------------------------------------------

    def strip_for(self, y: int, width: int) -> Strip:
        offset = self._display_offset()
        if offset and y == 0:
            approx = ""
            known = [r.offset for r in self._rows if r.offset is not None]
            if len(known) > 1 and max(known) > min(known):
                per = (max(known) - min(known)) / (len(known) - 1)
                approx = f"~{int(self._first_offset / max(per, 1)):,} "
            text = f"— {approx}older lines on disk · Home loads more —"
            return Strip([Segment(_fit(text, width), _ST["note"])], width)
        vi = y - offset
        if not (0 <= vi < len(self._view)):
            if not self._view and y == 0:
                note = self._note or self._empty_text()
                return Strip([Segment(_fit(note, width), _ST["dim"])], width)
            return Strip.blank(width)
        row = self._rows[self._view[vi]]
        revealed = row.seq == self._revealed
        cache_key = (row.seq, width, vi == self._cursor, revealed, vi)
        strip = self._strips.get(cache_key)
        if strip is None:
            strip = self._render_row(vi, width, vi == self._cursor)
            self._strips[cache_key] = strip
            while len(self._strips) > _STRIP_CACHE:
                self._strips.popitem(last=False)
        else:
            self._strips.move_to_end(cache_key)
        return strip

    def _empty_text(self) -> str:
        if self._loading or not self._loaded:
            return "Loading the timeline…"
        if self._rows and not self._query.empty:
            return "No line matches the filter — Esc clears it."
        if self._rows:
            return "Every line is hidden — N shows clock samples and counts."
        return "No timeline lines yet."

    def _render_row(self, vi: int, width: int, selected: bool) -> Strip:
        index = self._view[vi]
        row = self._rows[index]
        typed, tint = type_style(row.src, row.kind)
        bg = _BG_SEL if selected else tint

        def st(name: str) -> Style:
            style = typed if name == "text" and typed is not None else _ST[name]
            return style + bg if bg is not None else style

        segments: list[Segment] = []
        depth = min(self._depth_at(row.t), 3)
        flag, flag_style = " ", "gutter"
        if row.level == "error":
            flag, flag_style = "!", "error"
        elif row.level == "warn":
            flag, flag_style = "!", "warn"
        elif row.sensitive and should_mask_ui() and row.seq != self._revealed:
            flag, flag_style = "▒", "masked"
        elif "~" in row.flags:
            flag, flag_style = "~", "clock"
        # Fixed columns: up to 3 label-depth bars, then the flag, then a gap.
        segments.append(Segment(("│" * depth).ljust(3), st("gutter")))
        segments.append(Segment(flag + " ", st(flag_style)))
        segments.append(Segment(_clock(row.t) + " ", st("time")))
        used = 4 + 1 + 13
        sep = row.sep or ("epoch" if self._epoch_sep(index) else "")
        if sep:
            text = self._separator_text(row, sep)
            body = _fit(f"{text} ", max(0, width - used - 1))
            segments.append(Segment(body, st(sep)))
            fill = width - used - cell_len(body)
            if fill > 0:
                segments.append(Segment("─" * fill, st("dim")))
            return Strip(segments).adjust_cell_length(width, bg)
        if width >= 80:
            prev = self._rows[self._view[vi - 1]] if vi > 0 else None
            delta = format_delta(row.t - prev.t) if prev is not None else ""
            segments.append(Segment(_fit(delta, 6) + " ", st("delta")))
            used += 7
        # Every column ends in a gap: a full-width value ("sandroid",
        # "record-start") must never run into the next one.
        segments.append(Segment(_fit(row.src, 8) + " ", st("src")))
        segments.append(Segment(_fit(row.kind, 11) + " ", st("kind")))
        used += 21
        if width >= 100:
            segments.append(Segment(_fit(row.actor, 6) + " ", st("actor")))
            used += 7
        summary = row.summary
        if row.n:
            summary = f"×{row.n} {summary}"
        if row.seq in self._reconnect:
            summary += f" · reconnected +{self._reconnect[row.seq]:.1f}s"
        if "j" in row.flags:
            summary += " ⇢"
        style = "dim" if row.seq in self._reconnect else "text"
        if row.level in ("warn", "error"):
            style = row.level
        segments.append(Segment(_fit(summary, max(0, width - used)), st(style)))
        return Strip(segments).adjust_cell_length(width, bg)

    def _separator_text(self, row: Row, sep: str) -> str:
        if sep == "world":
            return f"⟲ world {row.world} · {row.summary}"
        if sep == "epoch":
            return f"⏱ epoch {row.epoch} · {row.summary}"
        if sep == "label":
            depth = 0
            if row.data and isinstance(row.data.get("number"), int):
                span = self._spans.get(row.data["number"])
                depth = span[2] if span else 0
            return "  " * depth + row.summary
        if sep == "run":
            return f"{_RUN_ICON.get(row.kind, '▷')} · {row.summary}"
        if sep == "resume":
            return f"⋯ restarted · {row.summary}"
        if sep == "tracking":
            return f"◉ tracking · {row.summary}"
        if sep == "intervention":
            return f"⚑ {row.summary}"
        return row.summary

    # -- view sync, cursor -------------------------------------------------------------

    def _sync_view(self, scroll_to_cursor: bool = False, end: bool = False) -> None:
        if self._revealed is not None:
            row = self.cursor_row
            if row is None or row.seq != self._revealed:
                self._drop_reveal()  # the selection moved (follow, filter, load)
        if not self.is_mounted:
            return
        try:
            view = self.view
        except Exception:
            return
        total = len(self._view) + self._display_offset()
        width = view.scrollable_content_region.width or view.size.width
        view.virtual_size = Size(width, max(total, 1))
        if end:
            height = view.scrollable_content_region.height or view.size.height
            view.scroll_to(y=max(0, total - height), animate=False, immediate=True)
        elif scroll_to_cursor:
            self._scroll_cursor_into_view()
        view.refresh()
        self._update_chips()
        self._update_caption()

    def _scroll_cursor_into_view(self) -> None:
        view = self.view
        height = max(1, view.scrollable_content_region.height or view.size.height)
        y = self._cursor + self._display_offset()
        top = int(view.scroll_offset.y)
        if y < top:
            view.scroll_to(y=y, animate=False, immediate=True)
        elif y >= top + height:
            view.scroll_to(y=y - height + 1, animate=False, immediate=True)

    def view_resized(self) -> None:
        self._strips.clear()
        self._sync_view(scroll_to_cursor=True, end=self._follow)

    def move_cursor(self, delta: int, page: bool = False) -> None:
        if not self._view:
            return
        if delta < 0:
            if self._cursor == 0 and page:
                self.load_older()
            self.pause_follow()
        old = self._cursor
        self._cursor = max(0, min(len(self._view) - 1, self._cursor + delta))
        if self._cursor != old:
            self._cursor_moved()

    def click_line(self, y: int) -> None:
        vi = y - self._display_offset()
        if 0 <= vi < len(self._view):
            if vi < self._cursor:
                self.pause_follow()
            self._cursor = vi
            self._cursor_moved()

    def pause_follow(self) -> None:
        if self._follow:
            self._follow = False
            self._new_below = 0
            self._update_chips()
            self._update_caption()

    def _cursor_moved(self) -> None:
        if self._revealed is not None:
            row = self.cursor_row
            if row is None or row.seq != self._revealed:
                self._drop_reveal()
        self._strips.clear()
        self._sync_view(scroll_to_cursor=True)
        self._follow_inspector()

    # -- chips + caption + badge -------------------------------------------------------

    def chip_text(self) -> str:
        parts: list[str] = []
        q = self._query
        if self._review_run is not None:
            parts.append(f"REVIEW run {self._review_run}")
        for key in FILTER_KEYS:
            if key in q.pos:
                parts.append(f"{key} {','.join(sorted(q.pos[key]))}")
            if key in q.neg:
                parts.append(f"-{key} {','.join(sorted(q.neg[key]))}")
        parts.extend(f'"{w}"' for w in q.words)
        if self._show_hidden:
            parts.append("N all rows")
        parts.append(f"{len(self._view):,} of {len(self._rows):,}")
        return " · ".join(parts)

    def _banner(self) -> str | None:
        svc = timeline_service()
        if svc is None:
            return None
        try:
            status = svc.status()
        except Exception:
            return None
        state = getattr(status, "state", "")
        if state == "locked":
            who = getattr(status, "locked_by", None) or "another Sandroid"
            return (
                f"Timeline locked by {who} (another Sandroid on this folder): "
                "this window records no timeline."
            )
        if state == "failed":
            return "Timeline write failed — this window records no timeline (see log)."
        return None

    def _update_chips(self) -> None:
        try:
            chips = self.query_one("#tl-chips", Static)
        except Exception:
            return
        banner = self._banner()
        text = Text()
        if banner:
            text.append(f"⚠ {banner}  ", style="bold #fb923c")
        text.append(self.chip_text())
        if not self._follow:
            text.append(f"   ‖ paused · {self._new_below} new ↓", style="#fbbf24")
        if self._late_above:
            text.append(f"   ↑ {self._late_above} late lines", style="#a3873f")
        chips.update(text)

    def caption(self) -> tuple[str, str]:
        if self._review_run is not None:
            title = f"REVIEW · run {self._review_run}"
        elif self._follow:
            title = "following"
        else:
            title = f"paused · {self._new_below} new ↓"
        info = f"{len(self._view):,} of {len(self._rows):,} lines · ⏎ inspect"
        if self._late_above:
            info = f"↑ {self._late_above} late lines · " + info
        return title, info

    def _update_caption(self) -> None:
        ms = self._main_screen()
        if ms is None:
            return
        title, info = self.caption()
        try:
            ms.set_lens_caption(LENS_ID, title, info)
        except Exception:
            pass

    def badge(self) -> str | None:
        svc = timeline_service()
        if svc is None:
            return None
        try:
            status = svc.status()
        except Exception:
            return None
        if getattr(status, "state", "") in ("locked", "failed"):
            return "⚠"
        dropped = getattr(status, "dropped", None) or {}
        if any(v for v in dropped.values() if isinstance(v, int)):
            return "⚠"
        return None

    def _badge_tick(self) -> None:
        """1 s, also while hidden: the lens-bar badge only."""
        ms = self._main_screen()
        if ms is not None:
            try:
                ms.set_lens_badge(LENS_ID, self.badge())
            except Exception:
                pass
        if is_shown(self):
            if self._poll_timer is not None:
                self._poll_timer.resume()
            if not self._loaded and not self._loading:
                self.reload()
            self._update_chips()

    def note_locked(self) -> None:
        """``op:"locked"`` doorbell: show the banner now."""
        self._update_chips()
        ms = self._main_screen()
        if ms is not None:
            ms.set_lens_badge(LENS_ID, "⚠")

    # -- scope -------------------------------------------------------------------------

    def on_scope_changed(self, message: ScopeChanged) -> None:
        scope = message.run_id
        if scope is None:
            self._review_run = None
            self._review_window = None
            self._rebuild_view()
            self._sync_view(scroll_to_cursor=True)
            return
        self._review_run = Path(str(scope)).name
        self._review_window = None
        self._rebuild_view()
        self._sync_view(scroll_to_cursor=True)

        def job() -> None:
            window = None
            try:
                from sandroid.core import run_history

                start, end = run_history.run_time_window(scope)
                if start is not None:
                    window = (
                        start.timestamp(),
                        end.timestamp() if end is not None else time.time(),
                    )
            except Exception:
                logger.debug("run window lookup failed", exc_info=True)
            self._ui.post(self._scope_window_done, scope, window)

        self._run_job(job, "timeline-scope")

    def _scope_window_done(self, scope: str, window) -> None:
        if self._review_run != Path(str(scope)).name:
            return
        self._review_window = window
        self._rebuild_view()
        self._sync_view(scroll_to_cursor=True)

    def set_review_window(self, window: tuple[float, float] | None) -> None:
        self._review_window = window
        self._rebuild_view()
        self._sync_view(scroll_to_cursor=True)

    # -- filter ------------------------------------------------------------------------

    def set_filter(self, text: str) -> None:
        if text != self._query.text:
            self._drop_reveal()
        self._query = parse_query(text)
        self._rebuild_view()
        if self._follow:
            self._cursor = max(0, len(self._view) - 1)
        self._sync_view(scroll_to_cursor=True, end=self._follow)

    def action_filter(self) -> None:
        field = self.query_one("#tl-filter", _TLInput)
        field.value = self._query.text
        field.set_class(True, "-shown")
        field.focus()
        field.cursor_position = len(field.value)

    def close_filter(self, clear: bool = False) -> None:
        field = self.query_one("#tl-filter", _TLInput)
        if clear:
            self.set_filter("")
        field.set_class(False, "-shown")
        self.view.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "tl-filter" and event.input.has_class("-shown"):
            event.stop()
            self.set_filter(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "tl-filter":
            event.stop()
            self.set_filter(event.value)
            self.close_filter()

    def handle_escape(self) -> bool:
        """Esc (MainScreen): close the filter input, else clear the filter."""
        try:
            field = self.query_one("#tl-filter", _TLInput)
        except Exception:
            return False
        if field.has_class("-shown"):
            self.close_filter(clear=True)
            return True
        if not self._query.empty:
            self.set_filter("")
            return True
        return False

    # -- actions -----------------------------------------------------------------------

    def action_toggle_follow(self) -> None:
        if self._follow:
            self.pause_follow()
            return
        self.action_newest()

    def action_newest(self) -> None:
        self._follow = True
        self._new_below = 0
        self._late_above = 0
        self.release_pending()
        self._cursor = max(0, len(self._view) - 1)
        self._cursor_moved()
        self._sync_view(end=True)

    def action_oldest(self) -> None:
        self.pause_follow()
        if self._cursor == 0 and self._view:
            self.load_older()
        self._cursor = 0
        self._cursor_moved()

    def action_toggle_hidden(self) -> None:
        self._show_hidden = not self._show_hidden
        self._rebuild_view()
        self._sync_view(scroll_to_cursor=True, end=self._follow)
        self.app.notify(
            "Showing every line (clock samples, counts, reconnects)."
            if self._show_hidden
            else "Clock samples, counts and quick reconnects hidden (N shows them).",
            timeout=3,
        )

    def action_reveal(self) -> None:
        """``V``: show one masked (sensitive) line unmasked, after a confirm."""
        if not should_mask_ui():
            self.app.notify("Masking is off — nothing to reveal.", timeout=3)
            return
        row = self.cursor_row
        if row is None or not row.sensitive:
            self.app.notify("This line is not masked.", timeout=3)
            return
        from sandroid.tui.modals import ConfirmModal

        seq = row.seq

        def done(ok: bool | None) -> None:
            if ok:
                self.reveal(seq)

        self.app.push_screen(
            ConfirmModal(
                title=f"Reveal line #{seq}?",
                message=(
                    "Shows captured secret text on screen; the reveal is recorded."
                ),
                yes_label="Reveal",
                no_label="Cancel",
            ),
            done,
        )

    def reveal(self, seq: int) -> None:
        """Unmask ``seq`` until the selection changes; recorded on the timeline.

        The reveal ends on any selection change (cursor, follow, filter,
        reload, a new sink), not only on a cursor key. Follow is paused
        first: the reveal's own audit line (and any live line) would move
        a following cursor and end the reveal at once.
        """
        if self._follow:
            self.pause_follow()
        self._revealed = seq
        row = self._by_seq.get(seq)
        svc = timeline_service()
        if svc is not None:
            dev = row.dev if row is not None else None
            if not dev:
                try:
                    dev = svc.status().serial
                except Exception:
                    dev = None
            try:
                svc.note_reveal(seq, dev=dev)
            except TypeError:  # an older core without ``dev``
                try:
                    svc.note_reveal(seq)
                except Exception:
                    logger.debug("note_reveal failed", exc_info=True)
            except Exception:
                logger.debug("note_reveal failed", exc_info=True)
        self._detail.pop(seq, None)
        self._strips.clear()
        self.view.refresh()
        ms = self._main_screen()
        if ms is not None and row is not None:
            ms.open_inspector(self._content(row))
            self._load_detail(row)

    @property
    def revealed(self) -> int | None:
        return self._revealed

    def _drop_reveal(self) -> None:
        """End a reveal; an Inspector showing that line is masked again."""
        seq = self._revealed
        if seq is None:
            return
        self._revealed = None
        self._strips.clear()
        ms = self._main_screen()
        if ms is None or not getattr(ms, "inspector_is_open", False):
            return
        row = self._by_seq.get(seq)
        key = getattr(ms.inspector_content, "key", None)
        if row is not None and key == self._inspector_key(row):
            ms.update_inspector(self._content(row))

    def action_jump(self) -> None:
        """``J``: the selected line's source in its own lens."""
        row = self.cursor_row
        if row is None:
            self.app.notify("Nothing to jump to.", timeout=3)
            return
        ok = self.jump(row)
        if ok is None:
            self.app.notify("Nothing to jump to.", timeout=3)
        elif ok is False:
            self.app.notify("Its source is not available any more.", timeout=3)

    def jump(self, row: Row) -> bool | None:
        """Jump for ``row``: True done, False target missing, None no target."""
        ms = self._main_screen()
        ref = row.ref or {}
        data = row.data or {}
        if row.src == "files" and row.kind in ("pull", "check") and ms is not None:
            path = data.get("path")
            if not path:
                return None
            ms.switch_lens("files")
            panel = ms.lens_widget("files")
            reveal = getattr(panel, "reveal", None)
            return bool(reveal(path, version=data.get("version"))) if reveal else False
        if row.src == "net" and ref.get("id") and ms is not None:
            ms.switch_lens("network")
            panel = ms.lens_widget("network")
            reveal = getattr(panel, "reveal_flow", None)
            if reveal is None:
                return False
            return bool(reveal(str(ref["id"]), record=_flow_record(row)))
        if ref.get("run") and ms is not None:
            ms.switch_lens("runs")
            panel = ms.lens_widget("runs")
            select = getattr(panel, "select_run", None)
            return bool(select(str(ref["run"]))) if select else False
        if row.src == "privacy" and ms is not None:
            hop = self._privacy_jump(row, ms)
            if hop is not None:
                return hop
        if row.ref_of is not None:
            if self._select_seq(row.ref_of):
                return True
            if row.ref_of in self._by_seq:
                self.app.notify("That line is hidden by the filter (Esc).", timeout=3)
                return True
            return False
        return None

    def _privacy_jump(self, row: Row, ms: Any) -> bool | None:
        """A ``privacy`` line: the flow (Network) or file (Files) it cites.

        Its ``ref.of`` is the net / pull line of the finding; when that line
        is loaded, its own jump runs (full flow record, file + version).
        Otherwise the flow opens by ``ref.id``, the file by the scan record
        of this line; None falls back to selecting the cited line.
        """
        ref = row.ref or {}
        cited = self._by_seq.get(row.ref_of) if row.ref_of is not None else None
        if cited is not None and cited.src in ("net", "files"):
            done = self.jump(cited)
            if done is not None:
                return done
        if ref.get("lens") == "network" and ref.get("id"):
            ms.switch_lens("network")
            reveal = getattr(ms.lens_widget("network"), "reveal_flow", None)
            return bool(reveal(str(ref["id"]))) if reveal else False
        if ref.get("lens") == "files":
            path, version = _privacy_file_of(row.seq)
            if path:
                ms.switch_lens("files")
                reveal = getattr(ms.lens_widget("files"), "reveal", None)
                return bool(reveal(path, version=version)) if reveal else False
        return None

    def select_seq(self, seq: int) -> bool:
        """Put the cursor on line ``seq`` (False: not loaded or filtered out)."""
        return self._select_seq(seq)

    # -- inspector ---------------------------------------------------------------------

    def inspect_selected(self) -> InspectorContent | None:
        row = self.cursor_row
        if row is None:
            return None
        self._load_detail(row)
        return self._content(row)

    def _inspector_key(self, row: Row) -> tuple:
        return (LENS_ID, self._folder, row.seq)

    def _follow_inspector(self) -> None:
        ms = self._main_screen()
        if ms is None or not getattr(ms, "inspector_is_open", False):
            return
        key = getattr(ms.inspector_content, "key", None)
        if not (isinstance(key, tuple) and key[:1] == (LENS_ID,)):
            return
        row = self.cursor_row
        if row is not None and key[2] != row.seq:
            self._load_detail(row)
            ms.update_inspector(self._content(row))

    def _line_for(self, row: Row) -> dict | None:
        detail = self._detail.get(row.seq)
        if detail and detail.get("line") is not None:
            return detail["line"]
        return self._lines.get(row.seq)

    def _load_detail(self, row: Row) -> None:
        """Read the line, the previous line's hash and the ref facts (worker)."""
        mod = timeline_module()
        folder = self._folder
        prev = self._prev_row(row)
        cached = self._lines.get(row.seq)
        cached_prev = self._lines.get(prev.seq) if prev is not None else None
        path = Path(folder) / getattr(mod, "FILE_NAME", "timeline.jsonl") if (
            mod is not None and folder
        ) else None  # fmt: skip

        by_seq = self._by_seq

        def job() -> None:
            detail: dict[str, Any] = {"line": cached, "prev": cached_prev}
            try:
                if detail["line"] is None and path is not None:
                    if row.offset is not None:
                        detail["line"] = mod.read_line_at(
                            path, row.offset, reader="ui", mask_sensitive=False
                        )
                    else:
                        # A live row without a file offset that left the line
                        # cache: find it by seq (never "loading…" forever).
                        found = _find_by_seq(mod, path, row.seq, by_seq)
                        if found is not None:
                            detail["offset"], detail["line"], prev_line = found
                            if detail["prev"] is None and prev_line is not None:
                                detail["prev"] = prev_line
                if detail["line"] is None:
                    detail["error"] = (
                        "No timeline file." if path is None
                        else f"Line #{row.seq} is not readable from the file."
                    )  # fmt: skip
                if (
                    detail["prev"] is None
                    and prev is not None
                    and path is not None
                    and prev.offset is not None
                ):
                    detail["prev"] = mod.read_line_at(
                        path, prev.offset, reader="ui", mask_sensitive=False
                    )
                detail["ref"] = _ref_facts(detail["line"] or {}, folder)
                detail["verify"] = _verify(mod, detail["line"], detail["prev"])
            except Exception as exc:
                detail["error"] = str(exc)
            self._ui.post(self._detail_done, row.seq, detail)

        self._run_job(job, f"timeline-detail-{row.seq}")

    def _detail_done(self, seq: int, detail: dict) -> None:
        self._detail[seq] = detail
        offset = detail.get("offset")
        row = self._by_seq.get(seq)
        if isinstance(offset, int) and row is not None and row.offset is None:
            self._set_row_offset(row, offset)
        while len(self._detail) > 64:
            self._detail.pop(next(iter(self._detail)))
        ms = self._main_screen()
        if ms is None or not getattr(ms, "inspector_is_open", False):
            return
        key = getattr(ms.inspector_content, "key", None)
        row = self._by_seq.get(seq)
        if row is not None and key == self._inspector_key(row):
            ms.update_inspector(self._content(row))

    def _set_row_offset(self, row: Row, offset: int) -> None:
        """Remember a live row's file offset once it was found by seq."""
        pos = bisect.bisect_left(self._rows, row.key, key=lambda x: x.key)
        if pos < len(self._rows) and self._rows[pos].seq == row.seq:
            fixed = row._replace(offset=offset)
            self._rows[pos] = fixed
            self._by_seq[row.seq] = fixed

    def _prev_row(self, row: Row) -> Row | None:
        return self._by_seq.get(row.seq - 1)

    def _content(self, row: Row) -> InspectorContent:
        line = self._line_for(row)
        detail = self._detail.get(row.seq) or {}
        masked = should_mask_ui() and row.sensitive and row.seq != self._revealed
        shown = mask_line(line) if (line is not None and masked) else line
        title = f"#{row.seq} {row.src}/{row.kind}"
        if line is not None:
            err = line.get("t_err_ms")
            err_text = f" ±{err} ms" if err is not None else ""
            subtitle = (
                f"{line.get('t', '')} · {line.get('clk', 'host')}{err_text} · "
                f"world {row.world} · epoch {row.epoch} · {row.phase}"
            )
        else:
            subtitle = (
                f"{_clock(row.t)} · world {row.world} · epoch {row.epoch} · {row.phase}"
            )
        tabs: list[tuple[str, list]] = [
            ("Line", self._line_tab(row, shown, detail)),
            ("JSON", self._json_tab(shown, masked, detail)),
        ]
        if row.ref or (line or {}).get("ref"):
            tabs.append(("Ref", self._ref_tab(row, detail, masked)))
        tabs.append(("Chain", self._chain_tab(row, line, detail)))
        hints = []
        if "j" in row.flags:
            hints.append("J jump")
        if masked:
            hints.append("V reveal")
        return InspectorContent(
            title=title,
            subtitle=subtitle,
            tabs=tabs,
            footer="  ".join(hints) or None,
            key=self._inspector_key(row),
        )

    def _line_tab(
        self, row: Row, line: dict | None, detail: dict | None = None
    ) -> list:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="#8f9bb3")
        grid.add_column()
        source = line or {}
        for name in (
            "seq", "t", "t_rx", "clk", "t_err_ms", "mono", "world", "epoch",
            "phase", "run", "src", "kind", "actor", "dev", "pkg", "pid", "tid",
            "dev_mono", "dev_wall", "dev_t", "level", "sensitive",
        ):  # fmt: skip
            value = source.get(name, getattr(row, name, None) if not line else None)
            if value is None or value == "":
                continue
            grid.add_row(name, Text(str(value)))
        sections: list = [("Envelope", grid), ("Summary", Text(row.summary))]
        data = source.get("data") if line is not None else row.data
        if isinstance(data, dict) and data:
            kv = Table.grid(padding=(0, 2))
            kv.add_column(style="#8f9bb3")
            kv.add_column()
            for key, value in data.items():
                shown = value if isinstance(value, str) else json.dumps(value)
                kv.add_row(str(key), Text(shown[:400]))
            sections.append(("Data", kv))
        elif line is None:
            text = (detail.get("error") or "not readable") if detail else "loading…"
            sections.append(("Data", Text(text, style="#5b6479")))
        follow = [r for r in self._rows if r.ref_of == row.seq][:20]
        if follow:
            sections.append(
                (
                    "Follow-ups",
                    Text(
                        "\n".join(
                            f"#{r.seq} {r.src}/{r.kind} {r.summary}" for r in follow
                        )
                    ),
                )
            )
        labels = self._enclosing_labels(row.t)
        if labels:
            sections.append(("Inside", Text("\n".join(labels))))
        return sections

    def _enclosing_labels(self, t: float) -> list[str]:
        out = []
        for number, (start, end, depth) in sorted(self._spans.items()):
            if start <= t and (end is None or t < end):
                out.append("  " * depth + f"label {number} · since {_clock(start)}")
        return out

    def _json_tab(self, line: dict | None, masked: bool, detail: dict) -> list:
        if line is None:
            text = detail.get("error") or "loading…"
            return [("", Text(text, style="#5b6479"))]
        from rich.syntax import Syntax

        body = json.dumps(line, indent=2, sort_keys=True, ensure_ascii=False)
        sections: list = [("", Syntax(body, "json", theme="monokai", word_wrap=True))]
        if masked:
            sections.insert(
                0,
                (
                    "",
                    Text(
                        "Sensitive line masked · V reveals it (recorded).",
                        style="#fbbf24",
                    ),
                ),
            )
        return sections

    def _ref_tab(self, row: Row, detail: dict, masked: bool = False) -> list:
        ref = row.ref or (detail.get("line") or {}).get("ref") or {}
        if masked:
            # the masked form, exactly as the JSON tab shows it (ref.raw ...)
            ref = mask_line({"sensitive": True, "ref": dict(ref)}).get("ref") or {}
        sections: list = []
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="#8f9bb3")
        grid.add_column()
        for key, value in ref.items():
            grid.add_row(str(key), Text(str(value)))
        sections.append(("ref", grid))
        of = ref.get("of")
        if isinstance(of, int):
            target = self._by_seq.get(of)
            text = (
                f"#{of} {target.src}/{target.kind} · {target.summary}"
                if target is not None
                else f"#{of} (not loaded)"
            )
            sections.append(("Refers to", Text(text)))
        facts = detail.get("ref")
        if facts:
            for heading, body in facts:
                sections.append((heading, Text(body)))
        elif not detail:
            sections.append(("", Text("checking…", style="#5b6479")))
        return sections

    def _chain_tab(self, row: Row, line: dict | None, detail: dict) -> list:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="#8f9bb3")
        grid.add_column()
        grid.add_row("seq", str(row.seq))
        grid.add_row("h", Text(str((line or {}).get("h", "…"))))
        prev = detail.get("prev")
        grid.add_row(
            "prev h", Text(str(prev.get("h")) if isinstance(prev, dict) else "—")
        )
        grid.add_row("verify", Text(detail.get("verify") or "…"))
        return [("", grid)]


# ---------------------------------------------------------------------------
# worker helpers (no UI)
# ---------------------------------------------------------------------------


def _flow_record(row: Row) -> dict:
    """A flow-log record (``FlowRow.from_record`` shape) from a net line."""
    data = row.data or {}
    ref = row.ref or {}
    dur = data.get("dur_ms")
    end = row.t + (dur / 1000 if isinstance(dur, (int, float)) else 0)
    return {
        "id": ref.get("id"),
        "seq": data.get("flow_seq"),
        "kind": "tls" if row.kind == "tls-fail" else None,
        "method": data.get("method"),
        "host": data.get("host"),
        "path": data.get("path"),
        "status_code": data.get("status"),
        "error": data.get("error"),
        "app": data.get("app") or row.pkg,
        "request_bytes": data.get("req_bytes"),
        "response_bytes": data.get("resp_bytes"),
        "protocol": data.get("protocol"),
        "ts_start": row.t,
        "ts_end": end,
        "tls_reason": data.get("reason"),
    }


def _privacy_file_of(seq: int) -> tuple[str | None, str | None]:
    """``(device path, version)`` of the scan record a ``privacy`` line made."""
    try:
        from sandroid.services import privacy_scan

        hits = privacy_scan.get_privacy_scan_service().hits()
    except Exception:
        return None, None
    for hit in hits:
        if hit.tl_seq == seq and hit.device_path:
            return hit.device_path, hit.source.get("version")
    return None, None


def _find_by_seq(
    mod: Any, path: Path, seq: int, by_seq: dict[int, Row]
) -> tuple[int, dict, dict | None] | None:
    """``(offset, line, previous line)`` of line ``seq``, read from the file.

    Starts at the nearest earlier row with a known offset (the file is in seq
    order), else at 0; ``None`` when the file has no such line.
    """
    start = 0
    for back in range(1, 200_001):
        known = by_seq.get(seq - back)
        if known is not None and known.offset is not None:
            start = known.offset
            break
        if seq - back <= 0:
            break
    for begin in (start, 0) if start else (0,):
        prev: dict | None = None
        for off, line in mod.read_lines(
            path, start=begin, reader="ui", mask_sensitive=False
        ):
            try:
                got = int(line.get("seq") or 0)
            except (TypeError, ValueError):
                continue
            if got == seq:
                return off, line, prev
            if got > seq:
                break
            prev = line if got == seq - 1 else None
    return None


def _ref_facts(line: dict, folder: str | None) -> list[tuple[str, str]]:
    """What a line's ``ref`` points to (file existence + sha256, diff, run)."""
    ref = line.get("ref") if isinstance(line.get("ref"), dict) else None
    if not ref:
        return []
    facts: list[tuple[str, str]] = []
    rel = ref.get("path")
    if rel and folder:
        target = (Path(folder) / str(rel)).resolve()
        if not target.exists():
            facts.append(("File", f"{rel} · missing"))
        else:
            text = f"{rel} · {target.stat().st_size:,} bytes"
            want = ref.get("sha256")
            if want:
                digest = hashlib.sha256(target.read_bytes()).hexdigest()
                text += " · sha256 ok" if digest == want else " · sha256 MISMATCH"
            facts.append(("File", text))
            if line.get("src") == "files" and line.get("kind") == "pull":
                try:
                    from sandroid.core import watchlist_store

                    doc = watchlist_store.version_diff_doc(target.parent)
                except Exception:
                    doc = None
                if isinstance(doc, dict):
                    summary = doc.get("summary") or {
                        k: v for k, v in doc.items() if isinstance(v, (int, str))
                    }
                    facts.append(
                        ("Diff", json.dumps(summary, ensure_ascii=False)[:600])
                    )
    run = ref.get("run")
    if run:
        try:
            from sandroid.core import run_history

            scoped = run_history.resolve_scope(run_history.scope_for_run(str(run)))
        except Exception:
            scoped = None
        if scoped is not None:
            label = getattr(scoped, "label", None) or run
            started = getattr(scoped, "started_at", None)
            facts.append(("Run", f"{label} · started {started}"))
        else:
            facts.append(("Run", f"{run} · not found"))
    return facts


def _verify(mod: Any, line: dict | None, prev: dict | None) -> str:
    """One-line hash check of ``line`` against the previous line's ``h``."""
    if line is None:
        return "line not readable"
    if prev is None or "h" not in prev:
        return "previous line not loaded — not checked"
    canonical = getattr(mod, "canonical", None)
    line_hash = getattr(mod, "line_hash", None)
    if canonical is None or line_hash is None:
        return "no verifier"
    try:
        body = {k: v for k, v in line.items() if k != "h"}
        ok = line_hash(prev["h"], canonical(body)) == line.get("h")
    except Exception as exc:
        return f"not checked ({exc})"
    return "✓ h matches prev h + line" if ok else "✕ h does not match"


__all__ = [
    "LENS_ID",
    "Query",
    "Row",
    "TimelineLens",
    "TimelineView",
    "label_event_text",
    "parse_query",
    "row_from_line",
    "timeline_module",
    "timeline_service",
    "tracking_module",
]
