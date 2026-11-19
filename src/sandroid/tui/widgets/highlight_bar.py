"""AI highlight sets in the lens tables: bar, cells, Inspector, counts.

The chat agent groups rows of the Network and Files lenses into *highlight
sets* (:mod:`sandroid.services.row_highlights`, the ``"ai"`` row annotation
source). A lens shows them with

* a row tint (``AnnotationTintMixin`` on its table; the set's colour slot),
* a "Highlight" column (key ``hl``) with the sets' short words in their slot
  colours, only while a set has rows and the lens is wide enough,
* :class:`HighlightBar`, one line at the top while sets exist: label and
  count per set, ``filtering`` / ``partial`` / ``N new since`` in words, and
  the keys (``H filter · X clear``),
* an "AI highlight" section per set in the Inspector Summary,
* the *AI filter* (``H`` cycles off -> set 1 -> ... -> off; Esc leaves it):
  applied inside the lens's own row filter through
  ``registry().passes(lens, key)``, so follow counts see only shown rows.
  While it is on, its rows bypass the OS-noise / path-rule filter (the
  analyst's explicit pick beats a heuristic).

Everything lens-independent lives here so the panels keep small hunks:
:class:`HighlightView` (one per panel) wraps the store, the feed and the
row source; :func:`flow_snapshot` / :func:`file_snapshot` build the row dicts
the AI tools read. No glyphs or symbols: words, theme-token colours, tint.
"""

from __future__ import annotations

import functools
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual.widgets import Static

from sandroid.tui.row_annotations import (
    LENS_FILES,
    AnnotationFeed,
    registry,
    role_color,
    row_tint,
)
from sandroid.tui.themes import lens_palette

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

logger = logging.getLogger(__name__)

#: Width of the "Highlight" column.
HL_WIDTH = 14
#: Minimum lens width for the column (Network / Files).
HL_MIN_WIDTH = {"network": 100, "files": 110}
#: Row tint strength of a highlight (the store uses the same value).
TINT = 0.18
#: Below this width the bar uses the sets' short labels.
BAR_SHORT_BELOW = 120


def highlight_store() -> Any:
    """The process-wide highlight store, or None (not installed / broken)."""
    try:
        from sandroid.services.row_highlights import get_row_highlights
    except ImportError:
        return None
    try:
        return get_row_highlights()
    except Exception:
        logger.debug("highlight store unavailable", exc_info=True)
        return None


@functools.lru_cache(maxsize=4096)
def canonical_key(path: str) -> str:
    """The Files annotation key of a device path (canonical form)."""
    try:
        from sandroid.core.adb_utils import canonical_device_path

        return canonical_device_path(path)
    except Exception:
        return path


def slot_role(slot: int) -> str:
    return f"highlight_{slot}"


def _clip(text: str, width: int) -> str:
    text = text or ""
    if width <= 0 or len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


def _clock(ts: Any) -> str:
    try:
        return time.strftime("%H:%M:%S", time.localtime(float(ts)))
    except (TypeError, ValueError, OverflowError):
        return ""


@dataclass
class SetCounts:
    """Per set, over the rows of the lens's current view."""

    #: Rows of this view in the set.
    present: int = 0
    #: ... of them hidden by the other lens filters (noise, app only, ``/``).
    hidden: int = 0
    #: Rows that arrived after the judgement (not in the set, shown).
    new: int = 0
    #: Rows in the set that changed after the judgement (Files).
    changed: int = 0


class RowKeyMap:
    """Table row key -> annotation key, rebuilt only when the rows change.

    ``rows()`` returns the panel's current row list; the map is rebuilt when
    that list (its identity, length or last key) changed.
    """

    def __init__(
        self,
        rows: Callable[[], list],
        key: Callable[[Any], str],
        value: Callable[[Any], str | None],
    ) -> None:
        self._rows = rows
        self._key = key
        self._value = value
        self._sig: tuple | None = None
        self._map: dict[str, str | None] = {}

    def get(self, row_key: Any) -> str | None:
        try:
            rows = self._rows()
        except Exception:
            return None
        sig = (id(rows), len(rows), self._key(rows[-1]) if rows else None)
        if sig != self._sig:
            self._map = {self._key(r): self._value(r) for r in rows}
            self._sig = sig
        return self._map.get(str(row_key)) if row_key is not None else None


class HighlightView:
    """One lens's view of the highlight store (see the module docstring)."""

    def __init__(self, lens: str, noun: str = "row") -> None:
        self.lens = lens
        #: "flow" / "file": the empty state and the Inspector name rows so.
        self.noun = noun
        self.counts: dict[str, SetCounts] = {}
        #: Rows of the view passing the other filters / also the AI filter.
        self.view_total = 0
        self.view_shown = 0
        self._store: Any = None
        self._rev: Any = None
        self._sets: list = []
        self._filter_id: str | None = None
        self._feed: AnnotationFeed | None = None
        self._source: Callable[[], list[dict]] | None = None

    # -- store reads (cached per store revision) -----------------------------

    @property
    def store(self) -> Any:
        if self._store is None:
            self._store = highlight_store() or False
        return self._store or None

    def _refresh(self) -> None:
        store = self.store
        if store is None:
            self._sets, self._filter_id = [], None
            return
        try:
            rev = store.revision
        except Exception:
            return
        if rev == self._rev:
            return
        try:
            self._sets = list(store.sets(self.lens))
            self._filter_id = store.filter_set(self.lens)
        except Exception:
            logger.debug("highlight store read failed", exc_info=True)
            self._sets, self._filter_id = [], None
        self._rev = rev

    def sets(self) -> list:
        """The lens's sets (copies), by slot."""
        self._refresh()
        return self._sets

    @property
    def active(self) -> bool:
        """The lens has highlight sets (the bar and the H / X keys show)."""
        return bool(self.sets())

    @property
    def has_rows(self) -> bool:
        """A set of the lens has rows (the Highlight column shows)."""
        return any(s.reasons for s in self.sets())

    def filter_id(self) -> str | None:
        """The id of the lens's AI filter set, or None."""
        self._refresh()
        return self._filter_id

    def filter_set(self) -> Any:
        fid = self.filter_id()
        return next((s for s in self._sets if s.id == fid), None)

    def lookup(self, key: str | None) -> tuple:
        """``((set_id, slot, short, reason), ...)`` of one row, by slot."""
        store = self.store
        if store is None or not key:
            return ()
        try:
            return store.lookup(self.lens, key)
        except Exception:
            return ()

    def passes(self, key: str | None) -> bool:
        """The row passes every active annotation filter of the lens."""
        if not key:
            return not registry().filter_predicates(self.lens)
        return registry().passes(self.lens, key)

    def bypass_noise(self, key: str | None) -> bool:
        """The row is in the active AI filter set: noise rules do not hide it."""
        fid = self.filter_id()
        return bool(fid and key and any(e[0] == fid for e in self.lookup(key)))

    def show_column(self, width: int) -> bool:
        """Whether the "Highlight" column fits and has something to say."""
        return width >= HL_MIN_WIDTH.get(self.lens, 100) and self.has_rows

    # -- rendering -------------------------------------------------------------

    def cell(self, key: str | None) -> Text:
        """The Highlight cell: the sets' short words in their slot colours."""
        text = Text(no_wrap=True, overflow="ellipsis")
        for i, (_sid, slot, short, _reason) in enumerate(self.lookup(key)):
            if i:
                text.append(", ", style=lens_palette().dim)
            text.append(short, style=f"bold {role_color(slot_role(slot))}")
        return text

    def inside_cell(self, keys: Iterable[str | None]) -> Text:
        """A group row's cell: ``3 inside`` (highlighted members)."""
        n = sum(1 for k in keys if self.lookup(k))
        if not n:
            return Text("")
        return Text(f"{n} inside", style=lens_palette().muted, no_wrap=True)

    def sections(
        self, key: str | None, *, last_change: float | None = None
    ) -> list[tuple[str, Any]]:
        """Inspector Summary sections, one "AI highlight" per set of the row.

        ``last_change`` (Files: the row's last activity, epoch seconds) adds
        "changed after the AI looked at it" when it is after the judgement.
        """
        hits = self.lookup(key)
        if not hits:
            return []
        pal = lens_palette()
        by_id = {s.id: s for s in self.sets()}
        out: list[tuple[str, Any]] = []
        for sid, slot, short, reason in hits:
            hs = by_id.get(sid)
            text = Text()
            label = getattr(hs, "label", None) or short
            text.append(label, style=f"bold {role_color(slot_role(slot))}")
            if hs is not None and sid == self.filter_id():
                text.append("  filtering", style=pal.muted)
            if hs is not None and not hs.complete:
                text.append("  partial", style=pal.warn)
            if reason:
                who = "AI: " if getattr(hs, "origin", "ai") == "ai" else ""
                text.append(f"\n{who}{reason}")
            basis = (getattr(hs, "basis", None) or {}) if hs is not None else {}
            judged = basis.get("judged_at")
            meta = []
            if judged:
                meta.append(f"judged {_clock(judged)}")
            evaluated = basis.get("evaluated")
            if evaluated:
                meta.append(f"{evaluated} {self.noun}s looked at")
            if meta:
                text.append("\n" + " · ".join(meta), style=pal.dim)
            if judged and last_change and float(last_change) > float(judged):
                text.append("\nchanged after the AI looked at it", style=pal.warn)
            out.append(("AI highlight", text))
        return out

    def measure(
        self,
        items: Iterable[tuple[str | None, bool, int | None, float | None]],
        *,
        live: bool,
        changes: bool = False,
    ) -> None:
        """Count the view's rows per set (bar, caption).

        ``items``: ``(annotation key, passes the other lens filters, seq,
        last change time)`` per row of the view. New since = rows not in the
        set that pass the other filters and came after the judgement
        (``seq > basis.through_seq``, else ``last > basis.judged_at``); only
        live, for sets judged on live rows. ``changes``: also count set rows
        changed after the judgement (Files).
        """
        sets = self.sets()
        counts = {s.id: SetCounts() for s in sets}
        total = shown = 0
        if not sets:
            self.counts, self.view_total, self.view_shown = counts, 0, 0
            return
        plan = [
            (
                s.id,
                counts[s.id],
                (s.basis or {}).get("through_seq"),
                (s.basis or {}).get("judged_at"),
                live and s.scope is None,
            )
            for s in sets
        ]
        for key, ok, seq, last in items:
            hits = {e[0] for e in self.lookup(key)}
            if ok:
                total += 1
                if self.passes(key):
                    shown += 1
            for sid, c, through, judged, fresh in plan:
                if sid in hits:
                    c.present += 1
                    if not ok:
                        c.hidden += 1
                    elif changes and judged and last and last > float(judged):
                        c.changed += 1
                elif ok and fresh:
                    if through is not None and seq is not None:
                        if seq > int(through):
                            c.new += 1
                    elif judged and last and last > float(judged):
                        c.new += 1
        self.counts, self.view_total, self.view_shown = counts, total, shown

    def bar_text(self, width: int = 160, scope: str | None = None) -> Text | None:
        """The bar line (None: no sets)."""
        sets = self.sets()
        if not sets:
            return None
        pal = lens_palette()
        fid = self.filter_id()
        short = width < BAR_SHORT_BELOW
        text = Text(no_wrap=True, overflow="ellipsis")
        text.append("AI highlights", style=f"bold {pal.muted}")
        for hs in sets:
            role = slot_role(hs.slot)
            c = self.counts.get(hs.id, SetCounts())
            label = hs.short if short else _clip(hs.label, 32)
            n = (
                f"{c.present}"
                if c.present >= len(hs.reasons)
                else (f"{c.present} of {len(hs.reasons)}")
            )
            text.append("  ")
            text.append(
                f" {label} {n} ",
                style=f"bold {role_color(role)} on {row_tint(role, TINT)}",
            )
            flags = []
            if hs.id == fid:
                flags.append("filtering")
            if not hs.complete:
                flags.append("partial")
            if c.new:
                flags.append(f"{c.new} new since")
            if c.changed:
                flags.append(f"{c.changed} changed since")
            if c.hidden and hs.id != fid:
                flags.append(f"{c.hidden} hidden by lens filters")
            if self.lens == LENS_FILES and hs.scope != scope:
                flags.append("judged on live" if hs.scope is None else "from a run")
            if flags:
                text.append(" " + ", ".join(flags), style=pal.text)
        text.append("  ·  H filter · X clear", style=pal.dim)
        return text

    def caption_count(self, shown: int, total: int) -> str | None:
        """``AI filter: <label> · 12 of 340`` while the AI filter is on."""
        hs = self.filter_set()
        if hs is None:
            return None
        return f"AI filter: {_clip(hs.label, 40)} · {shown} of {total}"

    def empty_text(self, slash_filter: str = "") -> tuple[str, str] | None:
        """``(head, hint)`` for an empty view under the AI filter, else None."""
        hs = self.filter_set()
        if hs is None:
            return None
        head = f"No highlighted {self.noun} here"
        if slash_filter:
            head = f"No highlighted {self.noun} matches “{slash_filter}”"
        return head, "H or Esc leaves the AI filter"

    # -- actions ---------------------------------------------------------------

    def cycle_filter(self) -> str | None:
        """``H``: off -> set 1 -> ... -> off. Returns the notice text."""
        store = self.store
        sets = self.sets()
        if store is None or not sets:
            return None
        ids = [s.id for s in sets]
        fid = self.filter_id()
        nxt = ids[0] if fid not in ids else None
        if fid in ids and ids.index(fid) + 1 < len(ids):
            nxt = ids[ids.index(fid) + 1]
        try:
            store.set_filter(self.lens, nxt)
        except Exception as exc:
            return f"AI filter: {exc}"
        if nxt is None:
            return "AI filter off — the rows stay highlighted"
        label = next(s.label for s in sets if s.id == nxt)
        return f"AI filter: {label}"

    def leave_filter(self) -> bool:
        """Esc: turn the AI filter off. True when one was on."""
        store = self.store
        if store is None or self.filter_id() is None:
            return False
        try:
            store.set_filter(self.lens, None)
        except Exception:
            return False
        return True

    def confirm_clear(self, app: Any, done: Callable[[], None]) -> None:
        """``X``: ask, then remove the lens's highlight sets."""
        sets = self.sets()
        store = self.store
        if store is None or not sets:
            return
        from sandroid.tui.modals import ConfirmModal

        names = ", ".join(f"“{_clip(s.label, 40)}”" for s in sets)
        n = len(sets)

        def on_result(yes: bool | None) -> None:
            if not yes:
                return
            try:
                store.clear(self.lens)
            except Exception:
                logger.debug("clearing highlights failed", exc_info=True)
            done()

        app.push_screen(
            ConfirmModal(
                title="Clear AI highlights",
                message=(
                    f"Remove {n} highlight set{'s' if n != 1 else ''} of the "
                    f"{self.lens.capitalize()} lens ({names})? The rows stay; "
                    "only the highlights go."
                ),
                yes_label="Clear",
                guard_typing=True,
            ),
            on_result,
        )

    # -- lifecycle -------------------------------------------------------------

    def attach(
        self,
        owner: Any,
        flush: Callable[[set[str] | None], None],
        snapshot: Callable[[], list[dict]],
    ) -> None:
        """On mount (UI thread): redraw feed + row source for the AI tools."""
        from sandroid.tui.utils.ui_thread import UiDispatcher

        try:
            self._feed = AnnotationFeed(owner, self.lens, flush)
            self._feed.attach()
        except Exception:
            logger.debug("highlight feed attach failed", exc_info=True)
        store = self.store
        if store is not None:
            self._source = snapshot
            try:
                store.register_row_source(self.lens, snapshot, UiDispatcher.capture())
            except Exception:
                logger.debug("row source register failed", exc_info=True)

    def detach(self) -> None:
        if self._feed is not None:
            self._feed.detach()
            self._feed = None
        store, source = self.store, self._source
        if store is not None and source is not None:
            try:
                store.unregister_row_source(self.lens, source)
            except Exception:
                pass
        self._source = None


class HighlightBar(Static):
    """One line at the top of a lens while it has AI highlight sets."""

    DEFAULT_CSS = """
    HighlightBar {
        height: 1;
        padding: 0 1;
        display: none;
    }
    HighlightBar.-shown {
        display: block;
    }
    """

    def show_text(self, text: Text | None) -> None:
        self.set_class(text is not None, "-shown")
        self.update(text if text is not None else "")


# --------------------------------------------------------------------------
# row snapshots for the AI tools (``HighlightStore.register_row_source``)
# --------------------------------------------------------------------------


def flow_snapshot(row: Any, shown: bool) -> dict:
    """One Network row (``FlowRow``) for the AI tools; key = flow id."""
    if row.kind == "tls":
        kind = "tls"
    elif row.error:
        kind = "error"
    else:
        kind = "flow"
    flow_dir = getattr(row, "flow_dir", None)
    return {
        "key": row.flow_id,
        "shown": bool(shown),
        "flow_id": row.flow_id,
        "seq": row.seq,
        "method": row.method,
        "url": row.url() if row.kind != "tls" else f"https://{row.host}",
        "host": row.host,
        "path": row.path,
        "status": row.status,
        "app": row.app,
        "req_type": row.req_type,
        "resp_type": row.resp_type,
        "req_bytes": row.req_bytes,
        "resp_bytes": row.resp_bytes,
        "kind": kind,
        "phase": row.phase,
        "time": row.ts,
        "flow_dir": str(flow_dir) if flow_dir is not None else None,
    }


def _processes(act: Any) -> list[str]:
    procs: dict[str, int] = {}
    for name, n in (getattr(act, "processes", None) or {}).items():
        head = str(name).split(" · ", 1)[0]
        procs[head] = procs.get(head, 0) + n
    return [name for name, _n in sorted(procs.items(), key=lambda kv: -kv[1])[:3]]


def file_snapshot(
    path: str,
    *,
    shown: bool,
    act: Any = None,
    watched: bool = False,
    review_kind: str | None = None,
    scope: str | None = None,
) -> dict:
    """One Files row for the AI tools; key = canonical device path.

    ``first`` / ``last`` are epoch seconds (None when unknown).
    """
    from .monitor_view import OPS, app_package

    ops = ""
    if act is not None:
        ops = "".join(
            letter
            for cat, (letter, _c) in OPS.items()
            if cat != "noise" and act.ops.get(cat)
        )
    elif review_kind is not None:
        ops = {"changed": "M", "new": "C", "deleted": "D"}.get(review_kind, "")
    first = getattr(act, "first", None)
    last = getattr(act, "last", None)
    return {
        "key": canonical_key(path),
        "shown": bool(shown),
        "path": path,
        "ops": ops,
        "count": int(getattr(act, "count", 0) or 0),
        "processes": _processes(act) if act is not None else [],
        "first": first.timestamp() if first is not None else None,
        "last": last.timestamp() if last is not None else None,
        "watched": bool(watched),
        "app": app_package(path) or "",
        "review_kind": review_kind,
        "scope": scope,
    }


__all__ = [
    "HL_WIDTH",
    "HighlightBar",
    "HighlightView",
    "RowKeyMap",
    "SetCounts",
    "canonical_key",
    "file_snapshot",
    "flow_snapshot",
    "highlight_store",
]
