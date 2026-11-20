"""Timeline lens (lens 5): the session timeline, newest at the bottom.

One full-width, virtual list of every line the session timeline
(``sandroid.core.timeline``, ``<device folder>/timeline.jsonl``) holds:
file events, monitor notes, clock samples, snapshot loads, labels, runs,
Tracking input, screenshots and network flows -- each line one row::

       10:42:07.123 +12ms  file       modify  app    MODIFY databases/app.db · main
       10:42:08.004 +881ms tap                user   tap Login button
       10:42:09.900        snapshot loaded · world 3 · snapshot/load 'clean'
       10:42:10.200        Section 7 'Accept cookies'

**Types.** The type column shows plain words (``tap``, ``typed``, ``screen``,
``screenshot``, ``request``, ``file``, ``clock`` ...) from the module-level
``_TYPE_STYLE`` table, which also colours them from the lens theme tokens
(``LensPalette``): the user's own input is the brightest row on a ``band``
tint with the ``user`` accent on its type word (typed text: the ``typed``
accent and tint), screens get the ``screen`` accent and screenshots the
``shot`` one, requests a muted type word, file / clock / system rows are
dimmed. Warnings and errors keep the ``warn`` / ``bad`` colours.

**Type bar** (top row): every type present with its count, in its colour --
a legend and a filter (click a word, or ``t`` then ←/→ and Space, hides or
shows that type), then the apps present (``pkg:`` filter, one or all). It
combines with the ``/`` query.

**Folding (view only).** Consecutive file rows of the same app less than
``BURST_GAP_S`` apart fold into one row (``file · org.x · 214 changes (88
modify, 61 create …) in cache2, databases``); Enter or a click opens /
closes it. ``z`` (or a click on a section's header row) folds the section
around the cursor into one row (``Section 3 'Login' · 2:14 · 412 lines (12
taps, 300 files, 80 requests)``). Filters apply before folding; the rows, the
Inspector, ``J``/``V`` and the report keep every line.

**Load and live feed.** On the first activation a thread worker reads the
newest ``TAIL_FIRST`` lines from the file (``tail_lines``); ``Home``/``PgUp``
at the top load the next older page. While the lens is shown a 250 ms timer
polls ``service.tail(after_seq)`` (the writer's in-memory ring); new lines
wait ``HOLD_S`` in a hold so a line that is written a little late (device
time converted to host time) still lands in time order. A line that lands
above the viewport while not following keeps the viewport still (the caption
says "1 late lines above"). While hidden only a 1 s tick updates the badge
(``lines dropped``, ``locked`` or ``failed``, in the warning colour).

**Follow** (shared with the Files and Network lenses, ``follow.py``): new
lines appear at the bottom; while ``live`` the view sticks to the newest row;
moving up or clicking a row above the newest stops that (recording goes on),
``End`` resumes -- the chip then says ``scrolled back · 12 new below · End =
live``.

**Rows.** Separators (world change, epoch change, sections and notes, runs,
restarts, Tracking, interventions) are full-width rows that survive
structured filters. ``clock/sample`` lines, ``*/count`` lines and a
``device/lost`` that the same device's ``device/connect`` follows within 5 s
are hidden until ``N``.

**Filter** (``/``): ``src:files,label`` ``-src:clock`` ``kind:modify``
``actor:user`` ``phase:replay`` ``run:<id>`` ``world:3`` ``pkg:x``
``level:warn`` plus bare or quoted words matching the summary. The chip row
shows the parsed query; Esc clears it (then the hidden types). In REVIEW
scope an implicit ``run:<id>`` chip applies (plus the structural rows inside
the run's time window).

**Inspector** (Enter): Line (envelope, data, follow-ups, enclosing labels),
JSON (the line as written; sensitive lines masked while
``timeline.mask_sensitive`` is on -- ``V`` reveals one after a confirmation,
and the reveal is recorded), Ref (what ``ref`` points to) and Chain (seq,
hash, previous hash, a one-line verify). ``J`` jumps to the source of the
selected line: a pulled file (Files), a flow (Network), a run (Sessions) or
the line it refers to.

Keys (lens-local): ``space`` follow on/off · ``end`` newest + follow ·
``home`` oldest / load more · ``/`` filter · ``t`` type bar · ``z`` fold the
section · ``N`` hidden rows · ``J`` jump · ``V`` reveal. The global keys
``#`` (Section) ``+`` (Sub-section) ``-`` (End section) ``B`` (Note) and
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
from textual.widget import Widget
from textual.widgets import Input, Static

from sandroid.tui.themes import lens_palette
from sandroid.tui.utils.ui_thread import UiDispatcher

from .follow import Follow
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
#: Consecutive file rows of one app closer than this (seconds) fold into one
#: row (a "burst"; view only).
BURST_GAP_S = 2.0

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
    """``Section 7 'x'`` / ``Sub-section 8 'y' in Section 7`` / ``End
    section 7 'x'`` / ``Note 9 'x'`` for a LabelEvent.
    """
    kind = getattr(event, "kind", "point")
    number = getattr(event, "number", 0)
    name = getattr(event, "name", "") or ""
    named = f" '{name}'" if name else ""
    sub = bool(getattr(event, "depth", 0))
    if kind == "end":
        return f"End {'sub-section' if sub else 'section'} {number}{named}"
    if kind == "point":
        return f"Note {number}{named}"
    text = f"{'Sub-section' if sub else 'Section'} {number}{named}"
    parent = getattr(event, "parent", None)
    if parent is not None:
        text += f" in Section {parent}"
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
    #: A sensitive line's summary while masked (it quotes typed text).
    masked_summary: str | None = None

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
            or (src == "privacy" and kind in ("sent", "stored"))
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
        masked_summary=(
            data.get("masked_summary")
            if sensitive
            and data is not None
            and isinstance(data.get("masked_summary"), str)
            else None
        ),
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
#: A ``pkg:`` / ``-pkg:`` term in the raw query text (the app filter).
_PKG_TERM = re.compile(r"(?:^|(?<=\s))-?pkg:\S+")


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

#: Style name -> (lens theme token, Rich attributes). ``_ST`` holds the styles
#: built from the running theme's ``LensPalette`` (``_sync_styles`` rebuilds
#: it, and ``_BG_SEL``, when the theme changes).
_ST_SPEC: dict[str, tuple[str, dict[str, Any]]] = {
    "time": ("muted", {}),
    "delta": ("dim", {}),
    "src": ("label", {}),
    "kind": ("muted", {}),
    "actor": ("dim", {}),
    "text": ("text", {}),
    "dim": ("dim", {}),
    "gutter": ("label", {}),
    "warn": ("warn", {"bold": True}),
    "error": ("bad", {"bold": True}),
    "clock": ("muted", {}),
    "masked": ("muted", {"italic": True}),
    "uncertain": ("warn", {}),
    "world": ("accent", {"bold": True}),
    "epoch": ("warn", {}),
    "label": ("title", {"bold": True}),
    "run": ("ok", {"bold": True}),
    "resume": ("muted", {"bold": True}),
    "tracking": ("ok", {"bold": True}),
    "intervention": ("warn", {"bold": True}),
    "note": ("dim", {"italic": True}),
    "fold": ("muted", {}),
}
_ST: dict[str, Style] = {}
_BG_SEL = Style()
#: The palette ``_ST`` was built from (``[palette]``).
_ST_PALETTE: list[Any] = [None]


#: Per line type styling, keyed by ``(src, kind)`` or ``src`` (the pair wins):
#: ``fg`` colours the summary, ``tint`` blends the row background a little
#: towards a colour, ``bold``. Colours are lens theme token names
#: (``LensPalette`` fields), read at render time. The lens also reads:
#: ``name`` the plain word of the type column and the type bar (default: the
#: src), ``word`` the type word's colour, ``bg`` a row background token used
#: as is (no blend), ``dim`` the whole row dimmed, ``kind: False`` an empty
#: kind column (the type word says it all).
_USER_INPUT: dict[str, Any] = {
    "word": "user",
    "fg": "text",
    "bold": True,
    "tint": "user",
    "kind": False,
}
_TYPE_STYLE: dict[tuple[str, str] | str, dict[str, Any]] = {
    # The user's own actions: the brightest rows, on a tint of their accent.
    ("input", "tap"): {"name": "tap", **_USER_INPUT},
    ("input", "long_press"): {"name": "long press", **_USER_INPUT},
    ("input", "swipe"): {"name": "swipe", **_USER_INPUT},
    ("input", "gesture"): {"name": "gesture", **_USER_INPUT},
    ("input", "text"): {
        "name": "typed",
        **_USER_INPUT,
        "word": "typed",
        "tint": "typed",
    },
    ("input", "key"): {"name": "key", **_USER_INPUT},
    ("input", "confirm"): {"name": "confirmed", "word": "muted", "fg": "label"},
    "input": {"name": "input", **_USER_INPUT},
    # What the screen showed: a second accent (screenshots their own).
    "screen": {"name": "screen", "word": "screen"},
    "shot": {"name": "screenshot", "word": "shot"},
    # Network: a muted type word.
    ("net", "flow"): {"name": "request", "word": "muted", "fg": "muted", "kind": False},
    ("net", "tls-fail"): {"name": "TLS failed", "word": "warn", "kind": False},
    "net": {"name": "network", "word": "muted"},
    # Files: the whole row dimmed, except the evidence pulls and checks.
    ("files", "pull"): {"name": "file", "word": "label"},
    ("files", "check"): {"name": "file", "word": "label"},
    "files": {"name": "file", "fg": "dim", "dim": True},
    # Clock and system lines: dimmed.
    "clock": {"name": "clock", "fg": "dim", "dim": True},
    "sandroid": {"name": "system", "fg": "dim", "dim": True},
    "device": {"name": "device", "fg": "dim", "dim": True},
    "monitor": {"name": "monitor", "fg": "dim", "dim": True},
    "tracking": {"name": "tracking", "fg": "dim", "dim": True},
    "snapshot": {"name": "snapshot", "word": "label"},
    "label": {"name": "section"},
    "run": {"name": "run"},
    # Identity-profile values found by the privacy scan.
    ("privacy", "sent"): {"fg": "warn", "tint": "warn", "bold": True},
    ("privacy", "stored"): {"fg": "accent", "tint": "accent"},
}
#: How far ``tint`` moves the row background towards its colour.
_TINT_AMOUNT = 0.13
#: ``(src, kind)`` -> ``type_style`` result for the palette of ``_ST``.
_TYPE_CACHE: dict[tuple[str, str], tuple[Style | None, Style | None]] = {}
#: ``(src, kind)`` -> the spec of ``_TYPE_STYLE`` that applies ({} for none).
_SPEC_CACHE: dict[tuple[str, str], dict[str, Any]] = {}


def _sync_styles() -> None:
    """(Re)build ``_ST`` and ``_BG_SEL`` from the current theme's palette."""
    global _BG_SEL
    pal = lens_palette()
    if _ST_PALETTE[0] is pal and _ST:
        return
    for name, (token, attrs) in _ST_SPEC.items():
        _ST[name] = Style(color=getattr(pal, token), **attrs)
    _BG_SEL = Style(bgcolor=pal.cursor_focus)
    _ST_PALETTE[0] = pal
    _TYPE_CACHE.clear()


def _type_spec(src: str, kind: str) -> dict[str, Any]:
    """The ``_TYPE_STYLE`` entry of a line type (``{}`` when there is none)."""
    key = (src, kind)
    spec = _SPEC_CACHE.get(key)
    if spec is None:
        spec = _TYPE_STYLE.get(key) or _TYPE_STYLE.get(src) or {}
        if len(_SPEC_CACHE) < 4096:
            _SPEC_CACHE[key] = spec
    return spec


def type_word(src: str, kind: str) -> str:
    """The plain word of a line type (``tap``, ``request``, ``file`` ...)."""
    return _type_spec(src, kind).get("name") or src


#: ``(src, kind)`` -> ``type_word`` (the hot path of a view rebuild).
_WORD_CACHE: dict[tuple[str, str], str] = {}


def type_style(src: str, kind: str) -> tuple[Style | None, Style | None]:
    """``(summary style, row background)`` of a line type, or ``None``s."""
    spec = _TYPE_STYLE.get((src, kind)) or _TYPE_STYLE.get(src)
    if not spec:
        return None, None
    pal = lens_palette()
    if _ST_PALETTE[0] is not pal:
        _sync_styles()
    cached = _TYPE_CACHE.get((src, kind))
    if cached is not None:
        return cached
    from textual.color import Color

    fg = getattr(pal, spec["fg"], None) if spec.get("fg") else None
    text = Style(color=fg, bold=bool(spec.get("bold")) or None) if fg else None
    tint = None
    if spec.get("bg"):
        tint = Style(bgcolor=getattr(pal, spec["bg"]))
    elif spec.get("tint"):
        try:
            color = Color.parse(pal.bg).blend(
                Color.parse(getattr(pal, spec["tint"])), _TINT_AMOUNT
            )
            tint = Style(bgcolor=color.hex)
        except Exception:
            tint = None
    _TYPE_CACHE[(src, kind)] = (text, tint)
    return text, tint


def type_word_style(src: str, kind: str) -> Style:
    """The colour of a line type's word (type column, type bar)."""
    _sync_styles()
    spec = _type_spec(src, kind)
    token = spec.get("word") or ("dim" if spec.get("dim") else None)
    if token is None:
        return _ST["src"]
    return Style(color=getattr(lens_palette(), token, None) or None)


_UNINFLECTED = ("ed", "ing", "clock", "system", "network", "input", "privacy")


def _plural(word: str, n: int) -> str:
    """``12 taps`` / ``1 tap`` / ``3 long presses`` / ``2 typed``."""
    if n == 1 or word.endswith(_UNINFLECTED):
        return f"{n:,} {word}"
    if word.endswith(("s", "sh", "ch")):
        return f"{n:,} {word}es"
    return f"{n:,} {word}s"


#: Order of the type bar: the user's actions first, then what they caused.
_TYPE_ORDER = (
    "tap", "long press", "swipe", "gesture", "typed", "key", "input",
    "confirmed", "screen", "screenshot", "request", "TLS failed", "network",
    "privacy", "file", "snapshot", "monitor", "device", "tracking", "system",
    "clock",
)  # fmt: skip
_TYPE_RANK = {word: k for k, word in enumerate(_TYPE_ORDER)}


def _type_order(item: tuple[str, int]) -> tuple[int, str]:
    return _TYPE_RANK.get(item[0], len(_TYPE_ORDER)), item[0]


#: Run separators: the run line's kind in plain words.
_RUN_WORD = {
    "record-start": "recording started",
    "record-stop": "recording stopped",
    "record-result": "recording result",
    "play-start": "replay started",
    "phase": "replay phase",
    "play-end": "replay finished",
}
#: A leading symbol (``▶ ``, ``◉ ``, ``→ ``) of a summary the core wrote.
_LEAD_SYMBOL = re.compile(r"^[^\w'\"(\[#]+\s+")


def _late_text(n: int) -> str:
    """``1 late line above`` / ``3 late lines above``."""
    return f"{n:,} late line{'s' if n != 1 else ''} above"


#: The Chain tab's one-line verify verdicts (coloured ok / bad).
_CHAIN_OK = "h matches prev h + line"
_CHAIN_BAD = "h does NOT match prev h + line"


def _plain_summary(text: str) -> str:
    """``text`` without a leading symbol (rows read as plain words)."""
    return _LEAD_SYMBOL.sub("", text, count=1)


#: What a run line's summary starts with once its symbol is gone
#: (``REC · login``, ``Play done · 3 changed``): the plain word says it.
_RUN_LEAD = re.compile(
    r"^(?:REC(?: stopped)?|Play(?: done| ended)?|recording)(?:\s*·\s*|$)"
)


def _run_failed(row: Row) -> bool:
    """A run line that reports a failure (data, or its level)."""
    data = row.data or {}
    if data.get("failed") or row.level in ("warn", "error"):
        return True
    if data.get("result") in ("diverged", "unchecked"):
        return True  # a Rewind + Replay that did not reach your run
    error = data.get("error")
    return bool(error) and error != "Replay cancelled"


def _run_text(row: Row, summary: str) -> str:
    """``recording started · login`` / ``replay finished · 3 changed`` /
    ``replay failed · <error>``.
    """
    data = row.data or {}
    if data.get("rec_id") or row.kind == "step":
        # Rewind's own lines (core/rewind.py) are plain words already:
        # "rewind started · ...", "step 2 of 5 · ... · by element".
        return summary
    rest = _RUN_LEAD.sub("", summary, count=1).strip()
    word = _RUN_WORD.get(row.kind, "run")
    if _run_failed(row):
        word = "recording failed" if row.kind.startswith("record") else "replay failed"
        error = (row.data or {}).get("error")
        if error and str(error) not in rest:
            rest = f"{rest} · {error}" if rest else str(error)
    return f"{word} · {rest}" if rest else word


_sync_styles()


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


def _unhead(v: int) -> int:
    """The row index of a display entry (``~i`` marks a fold's header row)."""
    return v if v >= 0 else ~v


@dataclass
class _Fold:
    """One folded display row (view only; every member stays a row).

    ``burst``: consecutive file rows of one app (``head`` = the first
    member's seq, ``n`` members). ``section``: a folded section (``head`` =
    its start row's seq, ``n`` = the rows after it, its end row included).
    """

    kind: str
    head: int
    last: int
    n: int
    pkg: str | None = None
    open: bool = False
    number: int | None = None
    #: Lazily counted for the row text (see ``TimelineLens._fold_stats``).
    stats: dict[str, dict[str, int]] | None = None
    stats_n: int = 0
    stats_last: int | None = None


def _folder_of(summary: str) -> str:
    """``cache2`` from ``MODIFY cache2/entries/AB12 · main`` (a files line)."""
    text = summary
    for cut in (" · ", " → "):
        at = text.find(cut)
        if at >= 0:
            text = text[:at]
    parts = text.split(" ")
    k = 0
    while k < len(parts) - 1 and parts[k].isupper():
        k += 1
    path = " ".join(parts[k:])
    if path.startswith("/"):
        return "/" + path[1:].split("/", 1)[0]
    head, _sep, rest = path.partition("/")
    if head.startswith("@") and rest:
        return f"{head}/{rest.split('/', 1)[0]}"
    return head


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
        background: $lens-bg;
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


class TypeBar(Widget, can_focus=True):
    """The type bar: every type present with its count, in its colour (a
    legend and a filter); below it, on its own line, the apps present (one
    or all), so the app filter is always on screen and clickable.

    A click on a word hides / shows that type or picks that app. With the
    keyboard (``t`` in the lens): ←/→ move, Space or Enter toggles, ↓ / ``t``
    / Esc go back to the list.
    """

    BINDINGS = [
        Binding("left", "move(-1)", "Previous type", show=False),
        Binding("right", "move(1)", "Next type", show=False),
        Binding("space", "pick", "Hide / show the type", show=False),
        Binding("enter", "pick", "Hide / show the type", show=False),
        Binding("down", "leave", "Back to the list", show=False),
        Binding("t", "leave", "Back to the list", show=False),
    ]

    DEFAULT_CSS = """
    TypeBar {
        height: auto;
        max-height: 2;
        padding: 0 1;
        background: $lens-panel;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        #: ``(kind, word, count, (src, kind) of a line of that type)``; kind
        #: is ``type`` / ``app`` / ``all``.
        self.items: list[tuple[str, str, int, tuple[str, str] | None]] = []
        self.index = 0
        #: ``(line, x0, x1, item index)`` of the last render.
        self._hits: list[tuple[int, int, int, int]] = []

    def _lens(self) -> TimelineLens | None:
        for node in self.ancestors:
            if isinstance(node, TimelineLens):
                return node
        return None

    def set_items(self, items: list[tuple[str, str, int, Any]]) -> None:
        """``(kind, word, count, style key)`` per item, in display order."""
        current = self.items[self.index] if 0 <= self.index < len(self.items) else None
        self.items = list(items)
        if current is not None:
            for k, item in enumerate(self.items):
                if item[:2] == current[:2]:
                    self.index = k
                    break
        self.index = max(0, min(self.index, len(self.items) - 1))
        self.refresh(layout=True)

    def render(self) -> Text:
        lens = self._lens()
        _sync_styles()
        pal = lens_palette()
        lines = [
            Text(no_wrap=True, overflow="ellipsis"),
            Text(no_wrap=True, overflow="ellipsis"),
        ]
        self._hits = []
        focused = self.has_focus
        sel_bg = Style(bgcolor=pal.cursor_focus)
        for k, (kind, word, count, key) in enumerate(self.items):
            y = 0 if kind == "type" else 1
            text = lines[y]
            if kind == "type":
                hidden = lens is not None and word in lens.hidden_types
                if hidden:
                    style = Style(color=pal.dim, strike=True)
                    count_style = style
                else:
                    style = type_word_style(*key) if key else _ST["src"]
                    count_style = _ST["dim"]
            else:
                picked = lens is not None and lens.app_pick == (
                    None if kind == "all" else word.lower()
                )
                style = (
                    Style(color=pal.title, bold=True)
                    if picked
                    else Style(color=pal.muted)
                )
                count_style = _ST["dim"]
            if text.cell_len:
                text.append(" · ", style=_ST["dim"])
            elif y == 1:
                text.append("app ", style=_ST["dim"])
            x0 = text.cell_len
            for part, part_style in ((word, style), (f" {count:,}", count_style)):
                if focused and k == self.index:
                    part_style = part_style + sel_bg
                text.append(part, style=part_style)
            self._hits.append((y, x0, text.cell_len, k))
        if not self.items:
            lines[0].append("no types yet", style=_ST["dim"])
        if not lines[1].cell_len:
            return lines[0]
        return Text("\n").join(lines)

    def item_at(self, x: int, y: int = 0) -> int | None:
        for line, x0, x1, k in self._hits:
            if line == y and x0 <= x < x1:
                return k
        return None

    def on_click(self, event) -> None:
        try:
            offset = event.get_content_offset(self)
            x, y = offset.x, offset.y
        except Exception:
            x, y = getattr(event, "x", 0), getattr(event, "y", 0)
        k = self.item_at(int(x), int(y)) if x is not None and y is not None else None
        lens = self._lens()
        if k is None or lens is None:
            return
        event.stop()
        self.index = k
        lens.pick_bar_item(self.items[k])
        lens.view.focus()

    def action_move(self, delta: int) -> None:
        if self.items:
            self.index = (self.index + delta) % len(self.items)
            self.refresh()

    def action_pick(self) -> None:
        lens = self._lens()
        if lens is not None and 0 <= self.index < len(self.items):
            lens.pick_bar_item(self.items[self.index])

    def action_leave(self) -> None:
        lens = self._lens()
        if lens is not None:
            lens.view.focus()

    def on_focus(self) -> None:
        self.refresh()

    def on_blur(self) -> None:
        self.refresh()


class TimelineLens(Vertical):
    """The Timeline lens (id ``timeline-panel``); see the module docstring."""

    can_focus = True

    BINDINGS = [
        Binding("space", "toggle_follow", "Live", key_display="␣"),
        Binding("end", "newest", "Newest row, live", show=False),
        Binding("home", "oldest", "Oldest / load more", show=False),
        Binding("slash", "filter", "Filter", show=False),
        Binding("t", "types", "Type bar: hide / show types, pick an app", show=False),
        Binding("z", "fold_section", "Fold / unfold the section", show=False),
        Binding("N", "toggle_hidden", "Hidden rows (clock, counts)", show=False),
        Binding("J", "jump", "Jump to the line's source", show=False),
        Binding("V", "reveal", "Reveal a masked line…", show=False),
    ]

    DEFAULT_CSS = """
    TimelineLens {
        height: 1fr;
        background: $lens-bg;
    }
    TimelineLens > #tl-chips {
        height: 1;
        padding: 0 1;
        color: $lens-muted;
        background: $lens-panel;
    }
    TimelineLens > #tl-filter {
        display: none;
        height: 1;
        border: none;
        padding: 0 1;
        background: $lens-input-bg;
        color: $lens-input-text;
    }
    TimelineLens > #tl-filter.-shown {
        display: block;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._rows: list[Row] = []
        self._by_seq: dict[int, Row] = {}
        #: Row indices that pass the filters (every line, folded or not).
        self._vis: list[int] = []
        #: Display entries: a row index, or ``~i`` for a fold's header row.
        self._view: list[int] = []
        self._folds: dict[int, _Fold] = {}
        #: Seqs of the members shown below an opened burst (indented).
        self._open_members: set[int] = set()
        #: The fold that ends at the newest visible row (live appends).
        self._tail_fold: _Fold | None = None
        #: Opened bursts (their head seq) and folded sections (numbers).
        self._open_bursts: set[int] = set()
        self._folded_sections: set[int] = set()
        self._hidden_types: set[str] = set()
        self._type_counts: dict[str, int] = {}
        self._type_keys: dict[str, tuple[str, str]] = {}
        self._pkg_counts: dict[str, int] = {}
        self._cursor = 0
        self._fs = Follow()
        self._late_above = 0
        self._show_hidden = False
        self._query = Query()
        self._review_run: str | None = None
        self._review_window: tuple[float, float] | None = None
        self._folded: set[int] = set()
        self._reconnect: dict[int, float] = {}
        self._spans: dict[int, list] = {}
        #: Section number -> [start key, end key, name, parent].
        self._span_keys: dict[int, list] = {}
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

    # -- follow state (shared rules: follow.py) ------------------------------------

    @property
    def _follow(self) -> bool:
        return self._fs.live

    @_follow.setter
    def _follow(self, value: bool) -> None:
        if value:
            self._fs.resume()
        else:
            self._fs.stop()

    @property
    def _new_below(self) -> int:
        return self._fs.new_below

    @_new_below.setter
    def _new_below(self, value: int) -> None:
        self._fs.new_below = value

    # -- compose / mount ---------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static("", id="tl-chips")
        yield TypeBar(id="tl-types")
        yield TimelineView(id="tl-view")
        yield _TLInput(
            id="tl-filter",
            placeholder='src:files -src:clock actor:user "word"   Enter keeps · Esc clears',
        )

    def on_mount(self) -> None:
        self._ui = UiDispatcher.capture()
        self._poll_timer = self.set_interval(POLL_S, self._poll, pause=True)
        self.set_interval(1.0, self._badge_tick)
        self._update_chips()
        try:
            self.app.theme_changed_signal.subscribe(self, self._repaint_for_theme)
        except Exception:
            pass

    def _repaint_for_theme(self, _theme: Any = None) -> None:
        """A theme switch: rebuild the styles from the new lens palette."""
        _sync_styles()
        self._strips.clear()
        try:
            self.view.refresh()
            self.query_one("#tl-types", TypeBar).refresh()
        except Exception:
            pass
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
        try:
            screen = self.screen
        except Exception:  # not mounted (NoScreen)
            return None
        return screen if hasattr(screen, "set_lens_caption") else None

    # -- public state (tests, other lenses) ------------------------------------

    @property
    def rows(self) -> list[Row]:
        return self._rows

    @property
    def visible_rows(self) -> list[Row]:
        """Every row the filters let through (folded ones included)."""
        return [self._rows[i] for i in self._vis]

    @property
    def display_rows(self) -> list[Row]:
        """One row per display line (a fold's first row stands for it)."""
        return [self._rows[_unhead(v)] for v in self._view]

    @property
    def cursor_row(self) -> Row | None:
        if not self._view:
            return None
        self._cursor = max(0, min(self._cursor, len(self._view) - 1))
        return self._rows[_unhead(self._view[self._cursor])]

    def _cursor_row_or_none(self) -> Row | None:
        try:
            return self.cursor_row
        except IndexError:
            return None

    @property
    def cursor_fold(self) -> _Fold | None:
        """The fold whose header row the cursor is on (None: a plain row)."""
        if not self._view:
            return None
        self._cursor = max(0, min(self._cursor, len(self._view) - 1))
        v = self._view[self._cursor]
        return self._folds.get(self._rows[~v].seq) if v < 0 else None

    @property
    def following(self) -> bool:
        return self._follow

    @property
    def query_text(self) -> str:
        return self._query.text

    @property
    def late_above(self) -> int:
        return self._late_above

    @property
    def hidden_types(self) -> set[str]:
        return self._hidden_types

    @property
    def type_counts(self) -> dict[str, int]:
        return dict(self._type_counts)

    @property
    def pkg_counts(self) -> dict[str, int]:
        return dict(self._pkg_counts)

    @property
    def app_pick(self) -> str | None:
        """The one package the ``pkg:`` filter picks (None: all apps)."""
        values = self._query.pos.get("pkg")
        if values and len(values) == 1 and not self._query.neg.get("pkg"):
            return next(iter(values))
        return None

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
        self._span_keys.clear()
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
        self._open_bursts.clear()
        self._folded_sections.clear()
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
                i = len(self._rows) - 1
                ok, word, pkg = self._classify(i)
                self._count(word, pkg, 1)
                if ok:
                    self._vis.append(i)
                    self._display_append(i)
                    self._fs.added(1)
            self._strips.clear()
            self._view_seq_cache = None
        else:
            old_last = self._rows[-1].key
            for r in new:
                self._insert_one(r)
            self._strips.clear()
            self._view_seq_cache = None
            if not self._follow:
                self._fs.added(
                    sum(
                        1
                        for r in new
                        if r.key > old_last and self._view_index(r.seq) is not None
                    )
                )
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
        if self._follow and self.is_mounted:
            self._follow_inspector()  # an open Inspector follows the newest

    def _insert_one(self, row: Row) -> None:
        """Bisect-insert one late row and patch the view in place.

        A full rebuild re-evaluated every row (140 ms at 200k rows) for one
        late line; only the new row and its successor (whose epoch separator
        depends on its predecessor) can change visibility.
        """
        pos = bisect.bisect_right(self._rows, row.key, key=lambda x: x.key)
        old_next = self._classify(pos) if pos < len(self._rows) else None
        old_sep = old_next is not None and self._epoch_sep(pos)
        self._rows.insert(pos, row)
        state = self._classify(pos)
        self._count(state[1], state[2], 1)
        changes = [(pos, state[0])]
        if old_next is not None:
            new_next = self._classify(pos + 1)
            self._count(old_next[1], old_next[2], -1)
            self._count(new_next[1], new_next[2], 1)
            changes.append((pos + 1, new_next[0]))
        vis = self._vis
        k = bisect.bisect_left(vis, pos)
        if k < len(vis):
            vis[k:] = [i + 1 for i in vis[k:]]
        # The successor's epoch separator depends on its new predecessor (it
        # may join or split a burst even when it stays visible).
        next_changed = old_next is not None and old_sep != self._epoch_sep(pos + 1)
        for i, visible in changes:
            j = bisect.bisect_left(vis, i)
            present = j < len(vis) and vis[j] == i
            if visible and not present:
                vis.insert(j, i)
                next_changed = next_changed or i != pos
            elif present and not visible:
                del vis[j]
                next_changed = next_changed or i != pos
        self._display_insert(pos, state[0], next_changed)

    def _enforce_cap(self) -> None:
        extra = len(self._rows) - ROW_CAP
        if extra <= 0:
            return
        anchor = self._cursor_row_or_none()
        for i in range(extra):
            _ok, word, pkg = self._classify(i)
            self._count(word, pkg, -1)
        # The first row kept loses its predecessor: an epoch separator there
        # becomes a plain row (counted, filtered like one).
        was = self._classify(extra) if extra < len(self._rows) else None
        dropped = self._rows[:extra]
        self._rows = self._rows[extra:]
        for r in dropped:
            self._by_seq.pop(r.seq, None)
            self._open_members.discard(r.seq)
        firsts = [r.offset for r in self._rows[:64] if r.offset is not None]
        if firsts:
            self._first_offset = min(firsts)
        self._vis = [i - extra for i in self._vis if i >= extra]
        now = self._classify(0) if was is not None else None
        if was is not None and now is not None and was != now:
            self._count(was[1], was[2], -1)
            self._count(now[1], now[2], 1)
            if was[0] != now[0]:
                if now[0]:
                    self._vis.insert(0, 0)
                elif self._vis and self._vis[0] == 0:
                    del self._vis[0]
                self._build_display()
                self._strips.clear()
                if anchor is None or not self._select_seq(anchor.seq, quiet=True):
                    self._cursor = 0
                return
        self._display_drop(extra, dropped)
        if anchor is None or not self._select_seq(anchor.seq, quiet=True):
            self._cursor = 0
        self._strips.clear()

    # -- view model --------------------------------------------------------------------

    def _note_label(self, row: Row) -> None:
        """Keep the label spans (number -> [start t, end t, depth]) and the
        section keys (number -> [start key, end key, name, parent]).
        """
        if row.src == "label" and row.data:
            number = row.data.get("number")
            if not isinstance(number, int):
                return
            keys = self._span_keys.setdefault(number, [None, None, "", None])
            if row.kind == "start":
                span = self._spans.setdefault(number, [row.t, None, 0])
                span[0] = row.t
                span[2] = int(row.data.get("depth") or 0)
                keys[0] = row.key
                keys[2] = str(row.data.get("name") or "")
                keys[3] = row.data.get("parent")
            elif row.kind == "end":
                span = self._spans.setdefault(number, [row.t, None, 0])
                span[1] = row.t
                keys[1] = row.key

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

    def _classify(self, i: int) -> tuple[bool, str | None, str | None]:
        """``(visible, type word counted, package counted)`` of row ``i``.

        The type bar counts what the query lets through (the type filter
        aside); the app list counts what it lets through with no ``pkg:``
        term, so every app stays pickable. Separators are never counted (they
        survive the type filter like any structured filter).
        """
        row = self._rows[i]
        if row.src == "device" and row.kind == "connect":
            self._fold_reconnect(i)
        if not self._show_hidden and self._hidden_kind(i):
            return False, None, None
        sep = bool(row.sep) or self._epoch_sep(i)
        q = self._query
        filtered = bool(q.words or q.pos or q.neg)
        if (filtered or self._review_run is not None) and not self._matches(
            row, sep, ignore_pkg=True
        ):
            return False, None, None
        if sep:
            return True, None, None
        pkg = row.pkg or None
        if filtered and not self._pkg_ok(row):
            return False, None, pkg
        key = (row.src, row.kind)
        word = _WORD_CACHE.get(key)
        if word is None:
            word = type_word(row.src, row.kind)
            _WORD_CACHE[key] = word
            self._type_keys.setdefault(word, key)
        elif word not in self._type_keys:
            self._type_keys[word] = key
        return word not in self._hidden_types, word, pkg

    def _visible(self, i: int) -> bool:
        return self._classify(i)[0]

    def _count(self, word: str | None, pkg: str | None, delta: int) -> None:
        if word is not None:
            n = self._type_counts.get(word, 0) + delta
            if n > 0:
                self._type_counts[word] = n
            else:
                self._type_counts.pop(word, None)
        if pkg is not None:
            n = self._pkg_counts.get(pkg, 0) + delta
            if n > 0:
                self._pkg_counts[pkg] = n
            else:
                self._pkg_counts.pop(pkg, None)

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

    def _matches(self, row: Row, sep: bool, ignore_pkg: bool = False) -> bool:
        q = self._query
        if q.words:
            summary = self._shown_summary(row).lower()
            if not all(w in summary for w in q.words):
                return False
        for key, values in q.neg.items():
            if sep and key not in ("src", "run"):
                # separators survive negative terms too; only an explicit
                # -src: (or a text word) hides them (DESIGN_FINAL §11)
                continue
            if ignore_pkg and key == "pkg":
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
            if ignore_pkg and key == "pkg":
                continue
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

    def _pkg_ok(self, row: Row) -> bool:
        """The ``pkg:`` / ``-pkg:`` terms alone (a non-separator row)."""
        q = self._query
        if not (q.pos.get("pkg") or q.neg.get("pkg")):
            return True
        value = _field(row, "pkg")
        if value in q.neg.get("pkg", ()):
            return False
        pos = q.pos.get("pkg")
        return not pos or value in pos

    def _rebuild_view(self, keep: bool = True) -> None:
        anchor = self.cursor_row if keep else None
        self._folded.clear()
        self._reconnect.clear()
        vis: list[int] = []
        types: dict[str, int] = {}
        pkgs: dict[str, int] = {}
        classify = self._classify
        for i in range(len(self._rows)):
            ok, word, pkg = classify(i)
            if pkg is not None:
                pkgs[pkg] = pkgs.get(pkg, 0) + 1
            if word is not None:
                types[word] = types.get(word, 0) + 1
            if ok:
                vis.append(i)
        self._vis = vis
        self._type_counts = types
        self._pkg_counts = pkgs
        self._build_display()
        self._strips.clear()
        self._view_seq_cache = None
        if anchor is not None:
            self._select_seq(anchor.seq, quiet=True)

    def _view_seqs(self) -> set[int]:
        cache = getattr(self, "_view_seq_cache", None)
        if cache is None:
            cache = self._view_seq_cache = {self._rows[i].seq for i in self._vis}
        return cache

    # -- folding (view only) -------------------------------------------------------

    def _row_pos(self, seq: int) -> int | None:
        """Index of row ``seq`` in ``_rows`` (None when not loaded)."""
        row = self._by_seq.get(seq)
        if row is None:
            return None
        pos = bisect.bisect_left(self._rows, row.key, key=lambda x: x.key)
        if pos < len(self._rows) and self._rows[pos].seq == seq:
            return pos
        return None

    def _vis_pos(self, seq: int) -> int | None:
        """Index of row ``seq`` in ``_vis`` (None when filtered out)."""
        pos = self._row_pos(seq)
        if pos is None:
            return None
        j = bisect.bisect_left(self._vis, pos)
        return j if j < len(self._vis) and self._vis[j] == pos else None

    def _burstable(self, i: int) -> bool:
        """Row ``i`` may join a file burst (a plain files line)."""
        row = self._rows[i]
        return (
            row.src == "files"
            and not row.sep
            and row.level == "info"
            and row.kind not in ("pull", "check")
            and not self._epoch_sep(i)
        )

    def _section_end_pos(self, number: int, lo: int, hi: int) -> int:
        """``_vis`` index after the last row of section ``number`` (in lo..hi)."""
        keys = self._span_keys.get(number)
        end_key = keys[1] if keys else None
        if end_key is None:
            return hi
        end = bisect.bisect_right(self._rows, end_key, key=lambda x: x.key)
        return min(hi, max(lo + 1, bisect.bisect_left(self._vis, end, lo, hi)))

    def _groups(self, lo: int, hi: int) -> list[int]:
        """Display entries for ``_vis[lo:hi]`` (registers the folds)."""
        rows, vis = self._rows, self._vis
        folds = self._folds
        out: list[int] = []
        append = out.append
        gap = BURST_GAP_S
        burstable = self._burstable
        end = len(vis)
        j = lo
        while j < hi:
            i = vis[j]
            row = rows[i]
            if row.sep == "label" and row.kind == "start" and self._folded_sections:
                number = (row.data or {}).get("number")
                if number in self._folded_sections:
                    k = self._section_end_pos(number, j, hi)
                    fold = _Fold(
                        "section",
                        row.seq,
                        rows[vis[k - 1]].seq,
                        k - j - 1,
                        number=number,
                    )
                    folds[row.seq] = fold
                    append(~i)
                    if k >= end:
                        self._tail_fold = fold
                    j = k
                    continue
            if row.src == "files" and burstable(i):
                k = j + 1
                prev = row
                while k < hi:
                    nxt_i = vis[k]
                    nxt = rows[nxt_i]
                    if (
                        nxt.src != "files"
                        or nxt.pkg != row.pkg
                        or nxt.key[0] - prev.key[0] > gap
                        or not burstable(nxt_i)
                    ):
                        break
                    prev = nxt
                    k += 1
                if k - j >= 2:
                    fold = _Fold(
                        "burst",
                        row.seq,
                        prev.seq,
                        k - j,
                        pkg=row.pkg,
                        open=row.seq in self._open_bursts,
                    )
                    folds[row.seq] = fold
                    append(~i)
                    if fold.open:
                        members = vis[j:k]
                        out.extend(members)
                        self._open_members.update(rows[m].seq for m in members)
                    if k >= end:
                        self._tail_fold = fold
                    j = k
                    continue
            append(i)
            if j == end - 1:
                self._tail_fold = None
            j += 1
        return out

    def _build_display(self) -> None:
        """The display entries from ``_vis`` (bursts and folded sections)."""
        self._folds = {}
        self._open_members = set()
        self._tail_fold = None
        self._view = self._groups(0, len(self._vis))

    def _display_append(self, i: int) -> None:
        """Row ``i`` was appended to ``_vis`` (the newest row): extend the
        burst or the open folded section at the end, else add a display row.
        """
        view = self._view
        row = self._rows[i]
        fold = self._tail_fold
        if fold is not None and view:
            if fold.kind == "section":
                keys = self._span_keys.get(fold.number or -1)
                end_key = keys[1] if keys else None
                if end_key is None or row.key <= end_key:
                    fold.n += 1
                    fold.last = row.seq
                    return
            elif fold.kind == "burst":
                last = self._by_seq.get(fold.last)
                if (
                    last is not None
                    and self._burstable(i)
                    and row.pkg == fold.pkg
                    and row.t - last.t <= BURST_GAP_S
                ):
                    fold.n += 1
                    fold.last = row.seq
                    if fold.open:
                        view.append(i)
                        self._open_members.add(row.seq)
                    return
        self._tail_fold = None
        number = (row.data or {}).get("number") if row.sep == "label" else None
        if row.kind == "start" and number in self._folded_sections:
            fold = _Fold("section", row.seq, row.seq, 0, number=number)
            self._folds[row.seq] = fold
            view.append(~i)
            self._tail_fold = fold
            return
        if view and view[-1] >= 0 and self._burstable(i):
            prev_i = view[-1]
            prev = self._rows[prev_i]
            if (
                prev.seq not in self._open_members
                and self._burstable(prev_i)
                and prev.pkg == row.pkg
                and row.t - prev.t <= BURST_GAP_S
            ):
                fold = _Fold(
                    "burst",
                    prev.seq,
                    row.seq,
                    2,
                    pkg=row.pkg,
                    open=prev.seq in self._open_bursts,
                )
                self._folds[prev.seq] = fold
                view[-1] = ~prev_i
                if fold.open:
                    view.extend((prev_i, i))
                    self._open_members.update((prev.seq, row.seq))
                self._tail_fold = fold
                return
        view.append(i)

    def _group_span(self, p: int) -> tuple[int, int, int, int] | None:
        """``(display lo, display hi, vis lo, vis hi)`` of the display group
        holding ``_vis[p]`` (a plain row, a closed fold, or an opened burst
        with its member rows); None when the display does not hold it.
        """
        rows, view = self._rows, self._view
        ri = self._vis[p]
        d = bisect.bisect_right(view, ri, key=_unhead) - 1
        if d < 0:
            return None
        v = view[d]
        fold: _Fold | None = None
        if v >= 0 and rows[v].seq in self._open_members:
            h = d
            while h > 0 and view[h] >= 0:
                h -= 1
            fold = self._folds.get(rows[~view[h]].seq) if view[h] < 0 else None
            d = h
        elif v < 0:
            fold = self._folds.get(rows[~v].seq)
        elif v == ri:
            return d, d + 1, p, p + 1
        if fold is None:
            return None
        lo, hi = self._vis_pos(fold.head), self._vis_pos(fold.last)
        if lo is None or hi is None or not lo <= p <= hi:
            return None
        end = d + 1
        if fold.open:  # its member rows (a row just inserted is not one yet)
            end = bisect.bisect_right(view, self._vis[hi], key=_unhead)
        return d, end, lo, hi + 1

    def _display_insert(self, pos: int, visible: bool, next_changed: bool) -> None:
        """A late row was inserted at row index ``pos``: shift the display
        entries, then regroup only the display groups around it (the one
        before, the one after, and what lies between).
        """
        view = self._view
        k = bisect.bisect_left(view, pos, key=_unhead)
        if k < len(view):
            view[k:] = [v + 1 if v >= 0 else v - 1 for v in view[k:]]
        if not visible and not next_changed:
            return
        vis = self._vis
        if not vis or self._rows[pos].src == "label":
            # A late section row (# / + write theirs at the key press, after
            # the name prompt) moves a section's ends: regroup it all.
            self._build_display()
            return
        before = bisect.bisect_left(vis, pos) - 1
        after = bisect.bisect_right(vis, pos + 1)
        lo = self._group_span(before) if before >= 0 else (0, 0, 0, 0)
        if (
            visible
            and not next_changed
            and lo is not None
            and lo[1] - lo[0] == 1
            and view[lo[0]] < 0
            and lo[2] <= before
            and after < len(vis)
            and after < lo[3]
        ):
            # Inside one closed fold: a section takes it as it is; a burst
            # when the row is a file row of its app within the gap (the
            # common late line in a long burst: no regrouping).
            fold = self._folds.get(self._rows[~view[lo[0]]].seq)
            rows = self._rows
            row = rows[pos]
            if fold is not None and (
                fold.kind == "section"
                or (
                    self._burstable(pos)
                    and (pos + 1 >= len(rows) or self._burstable(pos + 1))
                    and row.pkg == fold.pkg
                    and row.t - rows[vis[before]].t <= BURST_GAP_S
                    and rows[vis[after]].t - row.t <= BURST_GAP_S
                )
            ):
                fold.n += 1
                fold.stats = None
                return
        hi = (
            self._group_span(after)
            if after < len(vis)
            else (len(view), len(view), len(vis), len(vis))
        )
        if lo is None or hi is None or lo[0] > hi[1] or lo[2] > hi[3]:
            self._build_display()
            return
        rows = self._rows
        for v in view[lo[0] : hi[1]]:
            if v >= 0:
                self._open_members.discard(rows[v].seq)
            else:
                self._folds.pop(rows[~v].seq, None)
        view[lo[0] : hi[1]] = self._groups(lo[2], hi[3])

    def _display_drop(self, extra: int, dropped: list[Row]) -> None:
        """The cap dropped the oldest ``extra`` rows: shift the display and
        regroup the fold they cut (if any).
        """
        view = self._view
        d0 = bisect.bisect_left(view, extra, key=_unhead)
        cut: _Fold | None = None
        if d0 > 0 and view[d0 - 1] < 0:
            fold = self._folds.get(dropped[~view[d0 - 1]].seq)
            if fold is not None and fold.last not in {r.seq for r in dropped}:
                cut = fold
        for v in view[:d0]:
            if v < 0:
                self._folds.pop(dropped[~v].seq, None)
        rest = [v - extra if v >= 0 else v + extra for v in view[d0:]]
        if cut is None:
            self._view = rest
            if rest and rest[0] >= 0 and self._rows[rest[0]].seq in self._open_members:
                self._build_display()  # an opened burst lost its header row
            return
        end = self._vis_pos(cut.last)
        if end is None:
            self._view = rest
            self._build_display()
            return
        if cut.kind == "burst" and not cut.open:
            # Its surviving rows still follow one another: the burst just
            # starts later (no regrouping of a burst of 100k rows).
            first = self._vis[0]
            if end >= 1:
                fold = _Fold("burst", self._rows[first].seq, cut.last, end + 1, cut.pkg)
                self._folds[fold.head] = fold
                if self._tail_fold is cut:
                    self._tail_fold = fold
                self._view = [~first, *rest]
            else:
                if self._tail_fold is cut:
                    self._tail_fold = None
                self._view = [first, *rest]
            return
        if cut.open:
            rest = rest[end + 1 :]
        self._view = self._groups(0, end + 1) + rest

    def _fold_stats(self, fold: _Fold) -> dict[str, dict[str, int]]:
        """Counts behind a fold's row text (per kind + folder, or per type);
        counted once and then only for the rows appended since.
        """
        lo = self._vis_pos(fold.head)
        hi = self._vis_pos(fold.last)
        if lo is None or hi is None:
            return fold.stats or {}
        first = lo + 1 if fold.kind == "section" else lo
        start = first
        stats = fold.stats
        if stats is not None and fold.stats_n == fold.n:
            return stats
        if stats is not None and fold.stats_last is not None:
            done = self._vis_pos(fold.stats_last)
            if done is not None and done - first + 1 == fold.stats_n:
                start = done + 1
            else:
                stats = None
        if stats is None:
            stats = {"a": {}, "b": {}, "n": {"lines": 0}}
            fold.stats_n = 0
        rows, vis = self._rows, self._vis
        a, b, lines = stats["a"], stats["b"], stats["n"]
        for j in range(start, hi + 1):
            i = vis[j]
            row = rows[i]
            if fold.kind == "burst":
                a[row.kind] = a.get(row.kind, 0) + 1
                folder = _folder_of(row.summary)
                b[folder] = b.get(folder, 0) + 1
            elif not row.sep and not self._epoch_sep(i):
                # A section counts its lines, not its separators.
                word = type_word(row.src, row.kind)
                a[word] = a.get(word, 0) + 1
                lines["lines"] += 1
        fold.stats = stats
        fold.stats_n = hi - first + 1
        fold.stats_last = fold.last
        return stats

    def _fold_text(self, fold: _Fold) -> str:
        """The folded row's text (``file · org.x · 214 changes …``)."""
        stats = self._fold_stats(fold)
        ranked = sorted(stats.get("a", {}).items(), key=lambda kv: (-kv[1], kv[0]))
        if fold.kind == "burst":
            kinds = ", ".join(f"{n:,} {kind}" for kind, n in ranked[:3])
            if len(ranked) > 3:
                kinds += " …"
            folders = sorted(stats.get("b", {}).items(), key=lambda kv: (-kv[1], kv[0]))
            where = ", ".join(name for name, _n in folders[:3] if name)
            text = "file · "
            if fold.pkg:
                text += f"{fold.pkg} · "
            text += f"{fold.n:,} changes ({kinds})"
            if where:
                text += f" in {where}"
            return text + (" · Enter folds" if fold.open else "")
        keys = self._span_keys.get(fold.number or -1) or [None, None, "", None]
        span = self._spans.get(fold.number or -1)
        head = self._by_seq.get(fold.head)
        start = head.t if head is not None else 0.0
        end = span[1] if span and span[1] is not None else None
        if end is None:
            last = self._by_seq.get(fold.last)
            end = last.t if last is not None else start
        secs = max(0, int(end - start))
        hours, rest = divmod(secs, 3600)
        dur = (
            f"{hours}:{rest // 60:02d}:{rest % 60:02d}"
            if hours
            else f"{rest // 60}:{rest % 60:02d}"
        )
        word = "Sub-section" if span and span[2] else "Section"
        name = f" '{keys[2]}'" if keys[2] else ""
        # The user's actions first (the type bar's order), not the biggest.
        ordered = sorted(stats.get("a", {}).items(), key=_type_order)
        types = ", ".join(_plural(w, n) for w, n in ordered[:3])
        if len(ordered) > 3:
            types += " …"
        n = stats.get("n", {}).get("lines", 0)
        lines = f"{n:,} line{'s' if n != 1 else ''}"
        text = f"{word} {fold.number}{name} · {dur} · {lines}"
        return text + (f" ({types})" if types else "")

    def _header_index(self, fold: _Fold) -> int | None:
        pos = self._row_pos(fold.head)
        if pos is None:
            return None
        d = bisect.bisect_left(self._view, pos, key=_unhead)
        return d if d < len(self._view) and self._view[d] == ~pos else None

    def toggle_fold(self, fold: _Fold) -> None:
        """Open / close a burst; unfold a folded section."""
        if fold.kind == "burst":
            if fold.open:
                self._open_bursts.discard(fold.head)
            else:
                self._open_bursts.add(fold.head)
        else:
            self._folded_sections.discard(fold.number)
        self._build_display()
        if fold.kind == "burst":
            d = self._header_index(self._folds.get(fold.head) or fold)
        else:
            d = self._view_index(fold.head)
        if d is not None:
            self._cursor = d
        self._fold_changed()

    def fold_section(self, number: int) -> bool:
        """Fold section ``number`` into one row (False: its start row is not
        shown). The cursor goes to the folded row.
        """
        keys = self._span_keys.get(number)
        start = self._by_seq_key(keys[0]) if keys and keys[0] else None
        if start is None or self._vis_pos(start.seq) is None:
            return False
        self._folded_sections.add(number)
        self._build_display()
        d = self._view_index(start.seq)
        if d is not None:
            self._cursor = d
        self._fold_changed()
        return True

    def _by_seq_key(self, key: tuple[float, int]) -> Row | None:
        return self._by_seq.get(key[1])

    def _section_at(self, row: Row) -> int | None:
        """The innermost section around ``row`` (its own if it starts one)."""
        best: tuple[int, tuple] | None = None
        for number, (start, end, _name, _parent) in self._span_keys.items():
            if start is None or start > row.key:
                continue
            if end is not None and row.key > end:
                continue
            depth = (self._spans.get(number) or [0, 0, 0])[2]
            rank = (depth, start)
            if best is None or rank > best[1]:
                best = (number, rank)
        return best[0] if best else None

    def _fold_changed(self) -> None:
        if self._follow and self._cursor < len(self._view) - 1:
            self._fs.stop()
        self._strips.clear()
        self._sync_view(scroll_to_cursor=True)
        self._follow_inspector()

    def _view_index(self, seq: int) -> int | None:
        """Display index of row ``seq`` (a fold's header row for a member of
        a closed fold; None when filtered out).
        """
        pos = self._row_pos(seq)
        if pos is None:
            return None
        view = self._view
        d = bisect.bisect_right(view, pos, key=_unhead) - 1
        if d < 0:
            return None
        v = view[d]
        if v == pos or v == ~pos:
            return d
        if v < 0:
            fold = self._folds.get(self._rows[~v].seq)
            last = self._row_pos(fold.last) if fold is not None else None
            if last is not None and last >= pos:
                j = bisect.bisect_left(self._vis, pos)
                if j < len(self._vis) and self._vis[j] == pos:
                    return d
        return None

    def _display_offset(self) -> int:
        """Display lines above the first row (the "older lines" note)."""
        return 1 if self._first_offset > 0 else 0

    def _row_at_display(self, y: int) -> Row | None:
        vi = y - self._display_offset()
        if 0 <= vi < len(self._view):
            return self._rows[_unhead(self._view[vi])]
        return None

    def _select_seq(self, seq: int, quiet: bool = False, expand: bool = False) -> bool:
        """Put the cursor on row ``seq``; ``expand`` opens a fold hiding it."""
        idx = self._view_index(seq)
        if idx is None:
            return False
        v = self._view[idx]
        if expand and v < 0:
            fold = self._folds.get(self._rows[~v].seq)
            if fold is not None and not (fold.kind == "section" and fold.head == seq):
                if fold.kind == "burst":
                    self._open_bursts.add(fold.head)
                else:
                    self._folded_sections.discard(fold.number)
                self._build_display()
                self._strips.clear()
                idx = self._view_index(seq)
                if idx is None:
                    return False
        self._cursor = idx
        if not quiet:
            self._cursor_moved()
        return True

    # -- rendering ---------------------------------------------------------------------

    def strip_for(self, y: int, width: int) -> Strip:
        if _ST_PALETTE[0] is not lens_palette():
            _sync_styles()
            self._strips.clear()
        offset = self._display_offset()
        if offset and y == 0:
            return Strip([Segment(_fit(self._older_note(), width), _ST["note"])], width)
        vi = y - offset
        if not (0 <= vi < len(self._view)):
            if not self._view and y == 0:
                note = self._note or self._empty_text()
                return Strip([Segment(_fit(note, width), _ST["dim"])], width)
            return Strip.blank(width)
        v = self._view[vi]
        selected = vi == self._cursor
        if v < 0:
            fold = self._folds.get(self._rows[~v].seq)
            if fold is None:
                return Strip.blank(width)
            cache_key = ("fold", fold.head, fold.n, fold.open, width, selected, vi)
        else:
            row = self._rows[v]
            revealed = row.seq == self._revealed
            cache_key = (row.seq, width, selected, revealed, vi)
        strip = self._strips.get(cache_key)
        if strip is None:
            if v < 0:
                strip = self._render_fold(vi, fold, width, selected)
            else:
                strip = self._render_row(vi, width, selected)
            self._strips[cache_key] = strip
            while len(self._strips) > _STRIP_CACHE:
                self._strips.popitem(last=False)
        else:
            self._strips.move_to_end(cache_key)
        return strip

    def _older_note(self) -> str:
        """``about 12,000 older lines on disk · Home loads more`` (cached: it
        is on screen in every frame while the top is shown).
        """
        key = (len(self._rows), self._first_offset)
        cached = getattr(self, "_older_cache", None)
        if cached is not None and cached[0] == key:
            return cached[1]
        approx = ""
        known = [r.offset for r in self._rows if r.offset is not None]
        if len(known) > 1 and max(known) > min(known):
            per = (max(known) - min(known)) / (len(known) - 1)
            approx = f"about {int(self._first_offset / max(per, 1)):,} "
        text = f"{approx}older lines on disk · Home loads more"
        self._older_cache = (key, text)
        return text

    def _empty_text(self) -> str:
        if self._loading or not self._loaded:
            return "Loading the timeline…"
        if self._rows and not self._query.empty:
            return "No line matches the filter — Esc clears it."
        if self._rows and self._hidden_types:
            return "Every shown type is hidden — t, then Space shows one again."
        if self._rows:
            return "Every line is hidden — N shows clock samples and counts."
        return "No timeline lines yet."

    def _prev_t(self, vi: int) -> float | None:
        """Time of the display row above ``vi`` (a fold: its last row)."""
        if vi <= 0:
            return None
        v = self._view[vi - 1]
        if v >= 0:
            return self._rows[v].t
        fold = self._folds.get(self._rows[~v].seq)
        last = self._by_seq.get(fold.last) if fold is not None else None
        if last is not None and not fold.open:
            return last.t
        return self._rows[~v].t

    def _gutter(self, row: Row) -> tuple[str, str]:
        """The flag column: ``!`` for a warning / error line (an uncertain
        device time colours the time cell, a masked line says "masked").
        """
        if row.level == "error":
            return "!", "error"
        if row.level == "warn":
            return "!", "warn"
        return " ", "gutter"

    def _masked(self, row: Row) -> bool:
        return row.sensitive and should_mask_ui() and row.seq != self._revealed

    def _shown_summary(self, row: Row) -> str:
        """The summary as shown: a masked line's summary never quotes text."""
        if row.masked_summary and self._masked(row):
            return row.masked_summary
        return row.summary

    def _render_row(self, vi: int, width: int, selected: bool) -> Strip:
        index = self._view[vi]
        row = self._rows[index]
        typed, tint = type_style(row.src, row.kind)
        bg = _BG_SEL if selected else tint
        spec = _type_spec(row.src, row.kind)
        dim = bool(spec.get("dim"))

        def st(name: str) -> Style:
            style = typed if name == "text" and typed is not None else _ST[name]
            if dim and name in ("time", "kind", "actor"):
                style = _ST["dim"]
            return style + bg if bg is not None else style

        segments: list[Segment] = []
        depth = min(self._depth_at(row.t), 3)
        flag, flag_style = self._gutter(row)
        # Fixed columns: up to 3 label-depth bars, then the flag, then a gap.
        segments.append(Segment(("│" * depth).ljust(3), st("gutter")))
        segments.append(Segment(flag + " ", st(flag_style)))
        # An uncertain device time (converted, or a large error) colours the
        # time cell instead of a symbol.
        time_style = st("uncertain") if "~" in row.flags else st("time")
        segments.append(Segment(_clock(row.t) + " ", time_style))
        used = 4 + 1 + 13
        sep = row.sep or ("epoch" if self._epoch_sep(index) else "")
        if sep:
            text = self._separator_text(row, sep)
            body = _fit(text, max(0, width - used))
            if sep == "run" and _run_failed(row):
                unchecked = (row.data or {}).get("result") == "unchecked"
                sep = "warn" if unchecked else "error"
            segments.append(Segment(body, st(sep)))
            return Strip(segments).adjust_cell_length(width, bg)
        if width >= 80:
            prev = self._prev_t(vi)
            delta = format_delta(row.t - prev) if prev is not None else ""
            segments.append(Segment(_fit(delta, 6) + " ", st("delta")))
            used += 7
        # Every column ends in a gap: a full-width value ("screenshot",
        # "record-start") must never run into the next one.
        word_style = type_word_style(row.src, row.kind)
        segments.append(
            Segment(
                _fit(type_word(row.src, row.kind), 10) + " ",
                word_style + bg if bg is not None else word_style,
            )
        )
        kind = "" if spec.get("kind") is False else row.kind.replace("_", " ")
        masked = self._masked(row)
        if masked:
            kind = "masked"
        segments.append(
            Segment(_fit(kind, 11) + " ", st("masked") if masked else st("kind"))
        )
        used += 23
        if width >= 100:
            segments.append(Segment(_fit(row.actor, 6) + " ", st("actor")))
            used += 7
        summary = _plain_summary(self._shown_summary(row))
        if row.seq in self._open_members:
            summary = "  " + summary
        if row.n:
            summary += f" · {row.n:,} times"
        if row.seq in self._reconnect:
            summary += f" · reconnected +{self._reconnect[row.seq]:.1f}s"
        style = "dim" if row.seq in self._reconnect else "text"
        if row.level in ("warn", "error"):
            style = row.level
        text_style = _ST[style] if style != "text" else st("text")
        if style != "text" and bg is not None:
            text_style = text_style + bg
        segments.append(Segment(_fit(summary, max(0, width - used)), text_style))
        return Strip(segments).adjust_cell_length(width, bg)

    def _render_fold(self, vi: int, fold: _Fold, width: int, selected: bool) -> Strip:
        head = self._by_seq.get(fold.head)
        if head is None:
            return Strip.blank(width)
        bg = _BG_SEL if selected else None

        def st(style: Style) -> Style:
            return style + bg if bg is not None else style

        segments: list[Segment] = []
        depth = min(self._depth_at(head.t), 3)
        segments.append(Segment(("│" * depth).ljust(3), st(_ST["gutter"])))
        segments.append(Segment("  ", st(_ST["gutter"])))
        segments.append(Segment(_clock(head.t) + " ", st(_ST["time"])))
        used = 4 + 1 + 13
        text = self._fold_text(fold)
        if fold.kind == "section":
            span = self._spans.get(fold.number or -1)
            indent = "  " * (span[2] if span else 0)
            body = _fit(indent + text, max(0, width - used))
            segments.append(Segment(body, st(_ST["label"])))
            return Strip(segments).adjust_cell_length(width, bg)
        if width >= 80:
            prev = self._prev_t(vi)
            delta = format_delta(head.t - prev) if prev is not None else ""
            segments.append(Segment(_fit(delta, 6) + " ", st(_ST["delta"])))
            used += 7
        word = "file · "
        segments.append(
            Segment(word, st(type_word_style(head.src, head.kind))),
        )
        used += len(word)
        rest = text[len(word) :] if text.startswith(word) else text
        segments.append(Segment(_fit(rest, max(0, width - used)), st(_ST["fold"])))
        return Strip(segments).adjust_cell_length(width, bg)

    def _separator_text(self, row: Row, sep: str) -> str:
        summary = _plain_summary(row.summary)
        if sep == "world":
            if not summary:
                summary = "device booted" if row.src == "device" else "world changed"
            return f"{summary} · world {row.world}"
        if sep == "epoch":
            return f"clock epoch {row.epoch} · {summary}"
        if sep == "label":
            return self._label_text(row, summary)
        if sep == "run":
            return _run_text(row, summary)
        if sep == "resume":
            return f"restarted · {summary}"
        if sep == "tracking":
            if summary.lower().startswith("tracking"):
                return summary
            return f"tracking · {summary}"
        return summary

    def _label_text(self, row: Row, summary: str) -> str:
        """``Section 3 'Login'`` / ``Sub-section 4 'x' in 3`` / ``End section
        3 'Login' · 12.0 s`` / ``Note 5 'text'`` (indented by depth).
        """
        data = row.data or {}
        number = data.get("number")
        if not isinstance(number, int):
            return summary
        keys = self._span_keys.get(number)
        span = self._spans.get(number)
        name = str(data.get("name") or (keys[2] if keys else "") or "")
        named = f" '{name}'" if name else ""
        depth = span[2] if span else int(data.get("depth") or 0)
        indent = "  " * depth
        if row.kind == "point":
            return f"{indent}Note {number}{named}"
        word = "Sub-section" if depth else "Section"
        if row.kind == "end":
            dur = data.get("duration_s")
            took = f" · {dur:.1f} s" if isinstance(dur, (int, float)) else ""
            return f"{indent}End {word.lower()} {number}{named}{took}"
        parent = data.get("parent")
        inside = f" in Section {parent}" if depth and parent is not None else ""
        return f"{indent}{word} {number}{named}{inside}"

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
        """A click: select the row (above the newest one: stop following);
        on a fold it opens / closes, on a section's header row it folds.
        """
        vi = y - self._display_offset()
        if not 0 <= vi < len(self._view):
            return
        if self._fs.clicked(vi, len(self._view) - 1):
            self._update_chips()
            self._update_caption()
        self._cursor = vi
        v = self._view[vi]
        if v < 0:
            fold = self._folds.get(self._rows[~v].seq)
            if fold is not None:
                self.toggle_fold(fold)
                return
        else:
            row = self._rows[v]
            number = (row.data or {}).get("number")
            if row.sep == "label" and row.kind == "start" and isinstance(number, int):
                if self.fold_section(number):
                    return
        self._cursor_moved()

    def pause_follow(self) -> None:
        if self._fs.stop():
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
        if self._hidden_types:
            parts.append("hidden " + ", ".join(sorted(self._hidden_types)))
        if self._show_hidden:
            parts.append("N all rows")
        parts.append(f"{len(self._vis):,} of {len(self._rows):,}")
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
        _sync_styles()
        pal = lens_palette()
        banner = self._banner()
        text = Text()
        if banner:
            text.append(f"{banner}  ", style=Style(color=pal.warn, bold=True))
        text.append(self.chip_text())
        if self._late_above:
            text.append(f"   {_late_text(self._late_above)}", style=_ST["clock"])
        chips.update(text)
        self._update_type_bar()

    def type_bar_items(self) -> list[tuple[str, str, int, tuple[str, str] | None]]:
        """The type bar: ``(kind, word, count, (src, kind))`` per item."""
        items: list[tuple[str, str, int, tuple[str, str] | None]] = []
        for word, n in sorted(self._type_counts.items(), key=_type_order):
            items.append(("type", word, n, self._type_keys.get(word)))
        for word in sorted(self._hidden_types - self._type_counts.keys()):
            items.append(("type", word, 0, self._type_keys.get(word)))
        if self._pkg_counts:
            items.append(("all", "all", sum(self._pkg_counts.values()), None))
            ranked = sorted(self._pkg_counts.items(), key=lambda kv: (-kv[1], kv[0]))
            for pkg, n in ranked:
                items.append(("app", pkg, n, None))
        return items

    def _update_type_bar(self) -> None:
        try:
            bar = self.query_one("#tl-types", TypeBar)
        except Exception:
            return
        bar.set_items(self.type_bar_items())

    def pick_bar_item(self, item: tuple) -> None:
        """A type bar click / Space: hide or show a type, or pick an app."""
        kind, word = item[0], item[1]
        if kind == "type":
            self.toggle_type(word)
        elif kind == "all":
            self.set_app(None)
        else:
            self.set_app(word)

    def toggle_type(self, word: str) -> None:
        """Hide / show every row of type ``word`` (combines with ``/``)."""
        if word in self._hidden_types:
            self._hidden_types.discard(word)
        else:
            self._hidden_types.add(word)
        self._refilter()

    def set_app(self, pkg: str | None) -> None:
        """Only ``pkg``'s rows (None: every app), as the query's ``pkg:``.

        Only the ``pkg:`` / ``-pkg:`` terms are rewritten; the rest of the
        query stays as typed (an unbalanced quote included). An open ``/``
        input shows the new query.
        """
        text = _PKG_TERM.sub(" ", self._query.text).strip()
        text = re.sub(r"[ ]{2,}", " ", text) if '"' not in text else text
        if pkg:
            term = f"pkg:{pkg}"
            text = f"{text} {term}" if text else term
        try:
            field = self.query_one("#tl-filter", _TLInput)
        except Exception:
            field = None
        if field is not None and field.has_class("-shown"):
            with self.prevent(Input.Changed):
                field.value = text
            field.cursor_position = len(text)
        self.set_filter(text)

    def caption(self) -> tuple[str, str]:
        if self._review_run is not None:
            title = f"REVIEW · run {self._review_run}"
        else:
            title = self._fs.text
        info = (
            f"{len(self._vis):,} of {len(self._rows):,} lines · Enter inspects "
            "or opens a fold · z folds the section · click a type to hide it"
        )
        if self._late_above:
            info = f"{_late_text(self._late_above)} · " + info
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
        state = getattr(status, "state", "")
        if state in ("locked", "failed"):
            return state
        dropped = getattr(status, "dropped", None) or {}
        if any(v for v in dropped.values() if isinstance(v, int)):
            return "lines dropped"
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
            ms.set_lens_badge(LENS_ID, "locked")

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
        self._refilter()

    def _refilter(self) -> None:
        """Re-apply the filters (query, hidden types); keeps the selection."""
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
        """Esc (MainScreen): close the filter input, else leave the type bar,
        else clear the filter, else show the hidden types again.
        """
        try:
            field = self.query_one("#tl-filter", _TLInput)
        except Exception:
            return False
        if field.has_class("-shown"):
            self.close_filter(clear=True)
            return True
        try:
            bar = self.query_one("#tl-types", TypeBar)
        except Exception:
            bar = None
        if bar is not None and bar.has_focus:
            self.view.focus()
            return True
        if not self._query.empty:
            self.set_filter("")
            return True
        if self._hidden_types:
            self._hidden_types.clear()
            self._refilter()
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

    def action_types(self) -> None:
        """``t``: the type bar takes the keys (←/→, Space; ``t`` / Esc back)."""
        try:
            bar = self.query_one("#tl-types", TypeBar)
        except Exception:
            return
        self._update_type_bar()
        bar.focus()

    def action_fold_section(self) -> None:
        """``z``: fold the section around the cursor into one row, or unfold
        the folded section the cursor is on.
        """
        fold = self.cursor_fold
        if fold is not None and fold.kind == "section":
            self.toggle_fold(fold)
            return
        row = self.cursor_row
        number = self._section_at(row) if row is not None else None
        if number is None:
            self.app.notify("Not inside a section.", timeout=3)
            return
        if not self.fold_section(number):
            self.app.notify(
                f"Section {number} starts outside the loaded or shown lines.",
                timeout=3,
            )

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
            if self._select_seq(row.ref_of, expand=True):
                if self._cursor < len(self._view) - 1:
                    self.pause_follow()  # the next line must not move it
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
        """Enter: the Inspector for the selected line; on a fold's row it
        opens / closes the fold instead.
        """
        fold = self.cursor_fold
        if fold is not None:
            self.toggle_fold(fold)
            return None
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
        if self.cursor_fold is not None:
            return  # a folded row: the Inspector keeps the last line
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
        grid.add_column(style=lens_palette().muted)
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
        shown = source.get("summary") if line is not None else None
        sections: list = [
            ("Envelope", grid),
            ("Summary", Text(_plain_summary(str(shown or self._shown_summary(row))))),
        ]
        data = source.get("data") if line is not None else row.data
        if isinstance(data, dict) and data:
            kv = Table.grid(padding=(0, 2))
            kv.add_column(style=lens_palette().muted)
            kv.add_column()
            for key, value in data.items():
                shown = value if isinstance(value, str) else json.dumps(value)
                kv.add_row(str(key), Text(shown[:400]))
            sections.append(("Data", kv))
        elif line is None:
            text = (detail.get("error") or "not readable") if detail else "loading…"
            sections.append(("Data", Text(text, style=lens_palette().dim)))
        follow = [r for r in self._rows if r.ref_of == row.seq][:20]
        if follow:
            sections.append(
                (
                    "Follow-ups",
                    Text(
                        "\n".join(
                            f"#{r.seq} {r.src}/{r.kind} {_plain_summary(r.summary)}"
                            for r in follow
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
                word = "Sub-section" if depth else "Section"
                keys = self._span_keys.get(number)
                named = f" '{keys[2]}'" if keys and keys[2] else ""
                out.append(
                    "  " * depth + f"{word} {number}{named} · since {_clock(start)}"
                )
        return out

    def _json_tab(self, line: dict | None, masked: bool, detail: dict) -> list:
        if line is None:
            text = detail.get("error") or "loading…"
            return [("", Text(text, style=lens_palette().dim))]
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
                        style=lens_palette().warn,
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
        grid.add_column(style=lens_palette().muted)
        grid.add_column()
        for key, value in ref.items():
            grid.add_row(str(key), Text(str(value)))
        sections.append(("ref", grid))
        of = ref.get("of")
        if isinstance(of, int):
            target = self._by_seq.get(of)
            text = (
                f"#{of} {target.src}/{target.kind} · "
                f"{_plain_summary(self._shown_summary(target))}"
                if target is not None
                else f"#{of} (not loaded)"
            )
            sections.append(("Refers to", Text(text)))
        facts = detail.get("ref")
        if facts:
            for heading, body in facts:
                if masked and heading == "Marked":
                    continue  # its label can show typed text
                sections.append((heading, Text(body)))
        elif not detail:
            sections.append(("", Text("checking…", style=lens_palette().dim)))
        return sections

    def _chain_tab(self, row: Row, line: dict | None, detail: dict) -> list:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=lens_palette().muted)
        grid.add_column()
        grid.add_row("seq", str(row.seq))
        grid.add_row("h", Text(str((line or {}).get("h", "…"))))
        prev = detail.get("prev")
        grid.add_row(
            "prev h", Text(str(prev.get("h")) if isinstance(prev, dict) else "—")
        )
        verify = detail.get("verify") or "…"
        pal = lens_palette()
        colour = {_CHAIN_OK: pal.ok, _CHAIN_BAD: pal.bad}.get(verify)
        grid.add_row("verify", Text(verify, style=f"bold {colour}" if colour else ""))
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
    data = line.get("data") if isinstance(line.get("data"), dict) else {}
    marked = data.get("marked")
    if isinstance(marked, dict) and marked.get("path") and folder:
        # tracking.mark_screenshots: the copy with the input drawn on it
        target = (Path(folder) / str(marked["path"])).resolve()
        if not target.exists():
            facts.append(("Marked", f"{marked['path']} · missing"))
        else:
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            ok = "sha256 ok" if digest == marked.get("sha256") else "sha256 MISMATCH"
            facts.append(
                (
                    "Marked",
                    f"{marked['path']} · {target.stat().st_size:,} bytes · {ok}",
                )
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
    return _CHAIN_OK if ok else _CHAIN_BAD


__all__ = [
    "LENS_ID",
    "Query",
    "Row",
    "TimelineLens",
    "TimelineView",
    "TypeBar",
    "label_event_text",
    "parse_query",
    "row_from_line",
    "timeline_module",
    "timeline_service",
    "tracking_module",
    "type_style",
    "type_word",
]
