"""AI highlight sets in the lens tables: bar, cells, Inspector, counts.

The chat agent groups rows of the Network and Files lenses into *highlight
sets* (:mod:`sandroid.services.row_highlights`, the ``"ai"`` row annotation
source). A lens shows them with

* a row tint (``AnnotationTintMixin`` on its table; the set's colour slot),
* a "Highlight" column (key ``hl``) with the sets' short words in their slot
  colours, only while a set has rows and the lens is wide enough,
* :class:`HighlightBar`, one line at the top while sets exist: label and
  count per set, ``filtering`` / ``scanning`` (a ``classify_rows`` run is
  still filling it) / ``partial`` (stopped, cancelled or out of time) /
  ``N new since`` / ``N not judged`` (rows the lens hid when the set was
  made, so the tools left them out, now in view) in words, and the keys
  (``H filter · X clear``),
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

import contextlib
import functools
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual.markup import escape as escape_markup
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


def _heading_style(pal: Any) -> str:
    """The bar's heading: theme band colours, never the terminal default
    (on light themes an unset background showed as a black box).
    """
    return f"bold {pal.muted} on {pal.band}"


def slot_role(slot: int) -> str:
    return f"highlight_{slot}"


def _clip(text: str, width: int) -> str:
    text = text or ""
    if width <= 0 or len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


def set_state(hs: Any) -> str:
    """``"scanning"``, ``"partial"`` or ``"complete"`` of a highlight set."""
    if getattr(hs, "scanning", False):
        return "scanning"
    return "complete" if getattr(hs, "complete", True) else "partial"


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
    #: Rows now passing the other filters that the lens hid when the set
    #: was made (``basis["not_judged"]``): the tools never looked at them.
    not_judged: int = 0


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

    def ordered(self, key: str | None) -> tuple:
        """:meth:`lookup` with the AI filter set first (it wins the tint too)."""
        hits = self.lookup(key)
        fid = self.filter_id() if hits else None
        if fid is None or len(hits) < 2:
            return hits
        return tuple(sorted(hits, key=lambda e: e[0] != fid))

    def cell(self, key: str | None) -> Text:
        """The Highlight cell: the sets' short words in their slot colours.

        The AI filter set comes first (the set whose colour tints the row).
        """
        text = Text(no_wrap=True, overflow="ellipsis")
        for i, (_sid, slot, short, _reason) in enumerate(self.ordered(key)):
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
        hits = self.ordered(key)
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
            state = set_state(hs) if hs is not None else "complete"
            if state == "scanning":
                text.append("  scanning", style=pal.muted)
            elif state == "partial":
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
                # "rows": the Network count includes TLS-failure rows.
                meta.append(f"{evaluated} rows looked at")
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
        changed after the judgement (Files). Not judged = rows not in the set
        that pass the other filters now and are listed in
        ``basis["not_judged"]`` (hidden when the set was made).
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
                frozenset((s.basis or {}).get("not_judged") or ()),
            )
            for s in sets
        ]
        for key, ok, seq, last in items:
            hits = {e[0] for e in self.lookup(key)}
            if ok:
                total += 1
                if self.passes(key):
                    shown += 1
            for sid, c, through, judged, fresh, unjudged in plan:
                if sid in hits:
                    c.present += 1
                    if not ok:
                        c.hidden += 1
                    elif changes and judged and last and last > float(judged):
                        c.changed += 1
                elif ok and key and key in unjudged:
                    c.not_judged += 1
                elif ok and fresh and key:
                    # Keyless rows (a stdout-only TLS failure the flow log has
                    # not caught up with) are never "new": they cannot join a
                    # set. Keyed TLS failures (``tls_row_key``) count like flows.
                    if through is not None and seq is not None:
                        if seq > int(through):
                            c.new += 1
                    elif judged and last and last > float(judged):
                        c.new += 1
        self.counts, self.view_total, self.view_shown = counts, total, shown
        store = self.store
        if store is not None:
            with contextlib.suppress(Exception):
                store.note_not_judged({sid: c.not_judged for sid, c in counts.items()})

    def bar_text(self, width: int = 160, scope: str | None = None) -> Text | None:
        """The bar line (None: no sets), condensed to fit *width* cells.

        Forms, most verbose first: labels + flags + the key hint; without
        the hint; short labels + flags; ``4 sets:`` with counts only. The
        first that fits wins (the last one is cut with an ellipsis).
        """
        sets = self.sets()
        if not sets:
            return None
        room = max(10, int(width) - 2)  # the bar's own padding
        forms = (
            (False, True, True),
            (False, True, False),
            (True, True, False),
        )
        for short, flags, hint in forms:
            text = self._bar_line(sets, scope, short=short, flags=flags, hint=hint)
            if text.cell_len <= room:
                return text
        return self._bar_counts(sets)

    def _chip(self, text: Text, hs: Any, body: str) -> None:
        role = slot_role(hs.slot)
        text.append(
            f" {body} ", style=f"bold {role_color(role)} on {row_tint(role, TINT)}"
        )

    def _count(self, hs: Any) -> str:
        c = self.counts.get(hs.id, SetCounts())
        n = len(hs.reasons)
        return f"{c.present}" if c.present >= n else f"{c.present} of {n}"

    def _bar_line(
        self, sets: list, scope: str | None, *, short: bool, flags: bool, hint: bool
    ) -> Text:
        pal = lens_palette()
        fid = self.filter_id()
        text = Text(no_wrap=True, overflow="ellipsis")
        text.append(" AI highlights ", style=_heading_style(pal))
        for hs in sets:
            c = self.counts.get(hs.id, SetCounts())
            label = hs.short if short else _clip(hs.label, 32)
            text.append("  ")
            self._chip(text, hs, f"{label} {self._count(hs)}")
            if not flags:
                continue
            words = []
            if hs.id == fid:
                words.append("filtering")
            state = set_state(hs)
            if state != "complete":
                words.append(state)  # "scanning" while running, else "partial"
            if c.new:
                words.append(f"{c.new} new since")
            if c.not_judged:
                words.append(f"{c.not_judged} not judged")
            if c.changed:
                words.append(f"{c.changed} changed since")
            if c.hidden and hs.id != fid:
                words.append(f"{c.hidden} hidden by lens filters")
            if self.lens == LENS_FILES and hs.scope != scope:
                words.append("judged on live" if hs.scope is None else "from a run")
            if words:
                text.append(" " + ", ".join(words), style=pal.text)
        if hint:
            text.append("  ·  H filter · X clear", style=pal.dim)
        return text

    def _bar_counts(self, sets: list) -> Text:
        """The narrowest form: ``AI highlights · 4 sets: 10 8 4 3``."""
        pal = lens_palette()
        fid = self.filter_id()
        text = Text(no_wrap=True, overflow="ellipsis")
        text.append(" AI highlights ", style=_heading_style(pal))
        text.append(
            f"  {len(sets)} set{'s' if len(sets) != 1 else ''}:", style=pal.text
        )
        for hs in sets:
            text.append(" ")
            self._chip(text, hs, self._count(hs))
        if fid is not None:
            text.append(" filtering", style=pal.text)
        return text

    def caption_count(self, shown: int, total: int) -> str | None:
        """``AI filter: <label> · 12 of 340`` while the AI filter is on.

        *total*: the rows the lens would show without the AI filter (the
        footer's base). Plain text: callers that put it into markup (frame
        captions) escape it.
        """
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

        # Labels come from the chat agent: never markup (``[/x]`` would crash).
        names = ", ".join(f"“{escape_markup(_clip(s.label, 40))}”" for s in sets)
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

        last: list[Any] = [None]

        def on_change(keys: set[str] | None) -> None:
            # The registry signal is shared with the other row-annotation
            # sources (the privacy scan): redraw only when the highlight
            # store itself changed (each of its notifies follows a new
            # revision); the other sources redraw through their own feed.
            store = self.store
            rev = getattr(store, "revision", None) if store is not None else None
            if rev is not None and rev == last[0]:
                return
            last[0] = rev
            flush(keys)

        try:
            self._feed = AnnotationFeed(owner, self.lens, on_change)
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


def flow_snapshot(row: Any, shown: bool, scope: str | None = None) -> dict:
    """One Network row (``FlowRow``) for the AI tools; key = flow id.

    TLS failures: key = ``tls_row_key`` of the flow-log record id (None
    while a stdout-only row is not paired yet; the tools pair it with the
    flow log or count it), ``error`` names the failed handshake. ``flow_dir`` is where
    ``details/<id>.json`` lives: the session's flow log live, the run
    bundle's ``network/`` folder in REVIEW (TLS failures have no detail).
    """
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
        "error": (
            row.error or f"TLS handshake failed ({row.reason or 'tls'})"
            if kind == "tls"
            else row.error
        ),
        "scope": scope,
        "phase": row.phase,
        "time": row.ts,
        "flow_dir": str(flow_dir) if flow_dir is not None else None,
    }


def _own_reads(act: Any) -> int:
    """Events of the AI's own device reads (``read_device_files``)."""
    from sandroid.ai.device_files import is_own_read_process

    return sum(
        int(n or 0)
        for name, n in (getattr(act, "processes", None) or {}).items()
        if is_own_read_process(name)
    )


def _processes(act: Any) -> list[str]:
    from sandroid.ai.device_files import is_own_read_process

    procs: dict[str, int] = {}
    for name, n in (getattr(act, "processes", None) or {}).items():
        head = str(name).split(" · ", 1)[0]
        if is_own_read_process(head):
            continue  # the AI's own reads (head / cat / stat / su)
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
    diff: list[str] | str | None = None,
) -> dict:
    """One Files row for the AI tools; key = canonical device path.

    ``first`` / ``last`` are epoch seconds (None when unknown). ``diff``
    (REVIEW: the run's diff lines) becomes ``diff_head``, capped.
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
        "count": max(0, int(getattr(act, "count", 0) or 0) - _own_reads(act)),
        "processes": _processes(act) if act is not None else [],
        "first": first.timestamp() if first is not None else None,
        "last": last.timestamp() if last is not None else None,
        "watched": bool(watched),
        "app": app_package(path) or "",
        "review_kind": review_kind,
        "scope": scope,
        "diff_head": diff_head(diff),
    }


#: ``diff_head`` cap (characters).
DIFF_HEAD_CAP = 1500


def diff_head(diff: list[str] | str | None, cap: int = DIFF_HEAD_CAP) -> str | None:
    """The head of a run's diff for one file (None: no diff)."""
    if not diff:
        return None
    text = diff if isinstance(diff, str) else "\n".join(str(line) for line in diff)
    return text if len(text) <= cap else text[: cap - 1] + "…"


__all__ = [
    "HL_WIDTH",
    "HighlightBar",
    "HighlightView",
    "SetCounts",
    "canonical_key",
    "escape_markup",
    "file_snapshot",
    "flow_snapshot",
    "highlight_store",
]
