"""AI row highlights: named sets of lens rows the chat agent picked.

A *highlight set* (id ``h<n>``) is a group of rows of one lens (Network:
mitm flow ids; Files: canonical device paths) with a short reason per row.
The chat agent creates them (``find_rows`` / ``classify_rows`` /
``highlight_rows``); the lenses show them as a row tint, a "Highlight" column
and a bar. At most one set per lens can be the lens's *AI filter*: only its
rows stay visible.

:class:`HighlightStore` is UI-agnostic (no Textual import) and doubles as the
``"ai"`` :class:`~sandroid.tui.row_annotations.RowAnnotationProvider`, so the
lenses read it through the shared annotation registry and never import this
module for rendering.

Thread safety: every mutation runs under one ``RLock`` and replaces the
per-lens inverted index ``{key: ((set_id, slot, short, reason), ...)}`` as a
whole (copy-on-write), so :meth:`HighlightStore.lookup` and
:meth:`HighlightStore.annotations_for` are lock-free dict reads. The change
signal (``registry().notify``) is sent after the lock is released.

Persistence: per analysis session, ``<session>/ai/highlights.json`` (0600,
written atomically). A mutation snapshots the data under the lock; a
background writer thread writes the newest snapshot per file outside it, so
the UI thread (``H`` / ``X`` / Esc) never waits for an fsync
(:meth:`HighlightStore.flush` waits for pending writes).
:meth:`HighlightStore.bind_folder` switches sessions and bumps the store's
*generation*; mutations that pass ``generation=`` from before the switch
raise :class:`StaleGenerationError` instead of landing in the new session.
A malformed file is moved aside to ``highlights.json.bad`` and the session
starts empty. Without a folder the sets live in memory only.

Row sources: a lens registers a snapshot callable
(:meth:`HighlightStore.register_row_source`); tools call
:meth:`HighlightStore.snapshot_rows` from their helper thread, which runs the
callable on the UI loop through the lens's ``UiDispatcher`` and waits a
bounded time (never ``App.call_from_thread``).
"""

from __future__ import annotations

import atexit
import contextlib
import json
import logging
import re
import threading
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    from sandroid.tui.row_annotations import Annotation, RowAnnotationRegistry

logger = logging.getLogger(__name__)

#: Lens names (equal to ``sandroid.tui.row_annotations.LENS_*``; not imported:
#: importing ``sandroid.tui`` costs about 0.7 s, so this module imports it
#: lazily, only where an annotation or the registry is needed).
LENS_NETWORK = "network"
LENS_FILES = "files"


def registry() -> RowAnnotationRegistry:
    """The process-wide row annotation registry (lazy import)."""
    from sandroid.tui.row_annotations import registry as _registry

    return _registry()


#: Highlight sets per lens (one tint colour slot each).
MAX_SETS_PER_LENS = 4
#: Rows per highlight set.
MAX_KEYS_PER_SET = 5000
#: Lenses that take highlights.
LENSES: tuple[str, ...] = (LENS_NETWORK, LENS_FILES)
#: Text limits.
LABEL_MAX = 60
SHORT_MAX = 14
REASON_MAX = 120
#: Row tint strength of an AI highlight (privacy/user tints use 0.13).
HIGHLIGHT_TINT = 0.18
#: File name under ``<session>/ai/``.
HIGHLIGHTS_FILE = "highlights.json"
#: Schema tag written into the file.
SCHEMA = "sandroid-row-highlights/1"
#: Origins of a set.
ORIGINS = ("structural", "ai", "manual")

_UNBOUND = object()


class HighlightError(ValueError):
    """A highlight request broke a limit or named an unknown set/lens."""


class StaleGenerationError(HighlightError):
    """The store was bound to another session folder since the caller started."""


class _BadFileError(ValueError):
    """A persisted highlights file has the wrong shape."""


@dataclass
class HighlightSet:
    """One named group of highlighted rows of one lens.

    Attributes:
        id: ``"h1"``, ``"h2"``...; never reused within a session folder.
        lens: ``"network"`` or ``"files"``.
        label: The analyst's ask in words (at most 60 characters).
        short: Column/bar label (at most 14 characters).
        slot: Colour slot 1..4, the lowest free one of the lens.
        reasons: Row key -> reason (at most 120 characters).
        origin: ``"structural"``, ``"ai"`` or ``"manual"``.
        query: Classifier criterion or a summary of the ``where`` filter.
        scope: ``None`` = live rows; else the run id it was judged on.
        basis: ``{"judged_at": ts, "through_seq": int | None, "evaluated": n}``.
        complete: False while classifying and after a cancel (partial).
        stats: ``scanned``, ``matched``, ``uncertain``, ``skipped``,
            ``bytes_sent``...
        created_at: Creation time (epoch seconds).
    """

    id: str
    lens: str
    label: str
    short: str
    slot: int
    reasons: dict[str, str] = field(default_factory=dict)
    origin: str = "manual"
    query: str = ""
    scope: str | None = None
    basis: dict = field(default_factory=dict)
    complete: bool = True
    stats: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    #: The store's bind generation when this copy was taken (not persisted).
    generation: int = field(default=0, compare=False)

    def copy(self) -> HighlightSet:
        """A detached copy (own dicts)."""
        return HighlightSet(
            id=self.id,
            lens=self.lens,
            label=self.label,
            short=self.short,
            slot=self.slot,
            reasons=dict(self.reasons),
            origin=self.origin,
            query=self.query,
            scope=self.scope,
            basis=dict(self.basis),
            complete=self.complete,
            stats=dict(self.stats),
            created_at=self.created_at,
            generation=self.generation,
        )

    @property
    def count(self) -> int:
        """Rows in the set."""
        return len(self.reasons)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> HighlightSet:
        """Parse and validate a persisted set.

        Raises:
            ValueError: A missing field or a bad value.
            TypeError: *data* is not an object.
        """

        def need(name: str, kind: Any, default: Any = _UNBOUND) -> Any:
            value = data.get(name, default)
            if value is _UNBOUND:
                raise ValueError(f"set field {name!r} is missing")
            if (isinstance(value, bool) and kind is not bool) or not isinstance(
                value, kind
            ):
                raise ValueError(f"set field {name!r} has the wrong type")
            return value

        if not isinstance(data, dict):
            raise TypeError("a set is not an object")
        set_id = need("id", str)
        if not re.fullmatch(r"h[1-9][0-9]*", set_id):
            raise ValueError(f"bad set id {set_id!r}")
        lens = need("lens", str)
        if lens not in LENSES:
            raise ValueError(f"unknown lens {lens!r}")
        slot = need("slot", int)
        if not 1 <= slot <= MAX_SETS_PER_LENS:
            raise ValueError(f"bad slot {slot!r}")
        reasons = need("reasons", dict, {})
        if len(reasons) > MAX_KEYS_PER_SET or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in reasons.items()
        ):
            raise ValueError("reasons must map strings to strings")
        scope = data.get("scope")
        if scope is not None and not isinstance(scope, str):
            raise ValueError("set field 'scope' has the wrong type")
        complete = need("complete", bool, True)
        created = need("created_at", (int, float), time.time())
        return cls(
            id=set_id,
            lens=lens,
            label=_clip(need("label", str), LABEL_MAX),
            short=_clip(need("short", str), SHORT_MAX),
            slot=slot,
            reasons={k: _clip(v, REASON_MAX) for k, v in reasons.items()},
            origin=need("origin", str, "manual"),
            query=need("query", str, ""),
            scope=scope,
            basis=dict(need("basis", dict, {})),
            complete=complete,
            stats=dict(need("stats", dict, {})),
            created_at=float(created),
        )


def _clip(text: Any, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


#: Filler words :func:`short_label` drops ("all POST requests to api.x").
_FILLER = frozenset(
    {
        "a",
        "all",
        "an",
        "and",
        "any",
        "are",
        "contain",
        "containing",
        "contains",
        "every",
        "file",
        "files",
        "flow",
        "flows",
        "for",
        "from",
        "has",
        "have",
        "highlight",
        "highlights",
        "in",
        "is",
        "of",
        "only",
        "request",
        "requests",
        "row",
        "rows",
        "show",
        "sent",
        "that",
        "the",
        "to",
        "where",
        "which",
        "with",
    }
)


def short_label(label: str) -> str:
    """A 1-3 word column/bar label from a longer one (at most 14 characters).

    Filler words are dropped and the content words kept ("POST requests to
    api.x" -> "POST api.x", "files with personal data" -> "personal data");
    a word that no longer fits is cut with an ellipsis, never silently.
    """
    label = " ".join(str(label or "").split())
    if len(label) <= SHORT_MAX:
        return label
    words = [w for w in label.split() if w.lower().strip(",.:;") not in _FILLER]
    words = words or label.split()
    out = ""
    for word in words[:3]:
        candidate = f"{out} {word}".strip()
        if len(candidate) <= SHORT_MAX:
            out = candidate
            continue
        room = SHORT_MAX - (len(out) + 1 if out else 0)
        if room >= 4 or not out:
            out = (f"{out} " if out else "") + word[: max(1, room - 1)] + "…"
        break
    return out


def normalize_key(lens: str, key: Any) -> str:
    """The annotation key form of *key* for *lens* (files: canonical path)."""
    text = str(key or "").strip()
    if lens == LENS_FILES and text:
        try:
            from sandroid.core.adb_utils import canonical_device_path

            return canonical_device_path(text)
        except Exception:
            return text
    return text


class _RowSource:
    __slots__ = ("dispatcher", "fn")

    def __init__(self, fn: Callable[[], list[dict]], dispatcher: Any) -> None:
        self.fn = fn
        self.dispatcher = dispatcher


class HighlightStore:
    """All highlight sets of the bound session (see the module docstring).

    Also the ``"ai"`` row annotation provider.
    """

    source = "ai"

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sets: dict[str, HighlightSet] = {}
        self._filters: dict[str, str] = {}
        self._next_id = 1
        self._revision = 0
        self._folder: Any = _UNBOUND
        #: lens -> {key: ((set_id, slot, short, reason), ...)}, copy-on-write.
        self._index: dict[str, dict[str, tuple[tuple[str, int, str, str], ...]]] = {}
        self._pred_cache: dict[str, tuple[int, Callable[[str], bool] | None]] = {}
        self._sources: dict[str, list[_RowSource]] = {}
        self._sources_lock = threading.Lock()
        #: Bumps on every session switch (:meth:`bind_folder`).
        self._generation = 0
        #: Background writes: path -> (seq, payload); newest snapshot wins.
        self._write_lock = threading.Lock()
        self._pending_writes: dict[Path, tuple[int, dict]] = {}
        self._written_seq: dict[Path, int] = {}
        self._write_seq = 0
        self._writer: threading.Thread | None = None
        self._writes_idle = threading.Event()
        self._writes_idle.set()

    # -- reads (lock-free where it matters) -----------------------------------

    @property
    def revision(self) -> int:
        """Bumps on every change (monotonic)."""
        return self._revision

    @property
    def generation(self) -> int:
        """Bumps on every session switch (pass it to mutations as ``generation=``)."""
        return self._generation

    @property
    def folder(self) -> Path | None:
        """The bound session folder (``None``: memory only)."""
        folder = self._folder
        return None if folder is _UNBOUND else folder

    @property
    def path(self) -> Path | None:
        """``<folder>/ai/highlights.json`` (``None``: memory only)."""
        folder = self.folder
        return None if folder is None else Path(folder) / "ai" / HIGHLIGHTS_FILE

    def sets(self, lens: str | None = None) -> list[HighlightSet]:
        """Copies of the sets (of *lens*), ordered by lens and slot."""
        with self._lock:
            items = [
                s.copy() for s in self._sets.values() if lens is None or s.lens == lens
            ]
        items.sort(key=lambda s: (LENSES.index(s.lens), s.slot))
        return items

    def get(self, set_id: str) -> HighlightSet | None:
        """A copy of one set, or ``None``."""
        with self._lock:
            hs = self._sets.get(set_id)
            if hs is None:
                return None
            out = hs.copy()
            out.generation = self._generation
            return out

    def filter_set(self, lens: str) -> str | None:
        """The id of the lens's AI filter set, or ``None``."""
        return self._filters.get(lens)

    def lookup(self, lens: str, key: str) -> tuple[tuple[str, int, str, str], ...]:
        """``((set_id, slot, short, reason), ...)`` for one row, by slot."""
        index = self._index.get(lens)
        if not index:
            return ()
        return index.get(key, ())

    def keys(self, set_id: str) -> list[str]:
        """The row keys of one set (``[]`` when unknown)."""
        with self._lock:
            hs = self._sets.get(set_id)
            return list(hs.reasons) if hs is not None else []

    # -- RowAnnotationProvider ------------------------------------------------

    def annotations_for(self, lens: str, key: str) -> list[Annotation]:
        """One annotation per set containing *key* (the filter set first)."""
        entries = self.lookup(lens, key)
        if not entries:
            return []
        from sandroid.tui.row_annotations import PRIORITY_AI, Annotation

        fid = self._filters.get(lens)
        out = [
            Annotation(
                source=self.source,
                label=short,
                colour_role=f"highlight_{slot}",
                reason=reason,
                tint_role=f"highlight_{slot}",
                tint_amount=HIGHLIGHT_TINT,
                priority=PRIORITY_AI + (1 if set_id == fid else 0),
                group=set_id,
            )
            for set_id, slot, short, reason in entries
        ]
        out.sort(key=lambda a: -a.priority)
        return out

    def filter_predicate(self, lens: str) -> Callable[[str], bool] | None:
        """``key in filter set`` while the lens has an AI filter, else ``None``."""
        rev = self._revision
        cached = self._pred_cache.get(lens)
        if cached is not None and cached[0] == rev:
            return cached[1]
        fid = self._filters.get(lens)
        pred: Callable[[str], bool] | None = None
        if fid is not None:
            index = self._index.get(lens) or {}

            def pred(key: str, _index=index, _fid=fid) -> bool:
                return any(e[0] == _fid for e in _index.get(key, ()))

        self._pred_cache[lens] = (rev, pred)
        return pred

    # -- mutations ------------------------------------------------------------

    def create(
        self,
        lens: str,
        label: str,
        *,
        short: str | None = None,
        reasons: Mapping[str, str] | None = None,
        origin: str = "manual",
        query: str = "",
        scope: str | None = None,
        basis: Mapping[str, Any] | None = None,
        complete: bool = True,
        filter: bool = False,
        replace_id: str | None = None,
        generation: int | None = None,
    ) -> HighlightSet:
        """Create a set (or replace *replace_id* in place, keeping its slot).

        The returned copy's ``generation`` is the store's bind generation;
        pass it to later mutations so they fail after a session switch.

        Raises:
            HighlightError: Bad lens, too many sets or keys, unknown
                ``replace_id``.
            StaleGenerationError: *generation* is from before a session switch.
        """
        self._check_lens(lens)
        clean = self._clean_reasons(lens, reasons or {})
        if len(clean) > MAX_KEYS_PER_SET:
            raise HighlightError(
                f"a highlight set holds at most {MAX_KEYS_PER_SET} rows "
                f"({len(clean)} given)"
            )
        label = _clip(label, LABEL_MAX) or "highlight"
        with self._lock:
            self._check_generation(generation)
            old: HighlightSet | None = None
            if replace_id is not None:
                old = self._sets.get(replace_id)
                if old is None:
                    raise HighlightError(f"unknown highlight set {replace_id!r}")
                if old.lens != lens:
                    raise HighlightError(
                        f"highlight set {replace_id!r} belongs to the {old.lens} lens"
                    )
                slot = old.slot
                set_id = old.id
            else:
                used = {s.slot for s in self._sets.values() if s.lens == lens}
                free = [n for n in range(1, MAX_SETS_PER_LENS + 1) if n not in used]
                if not free:
                    names = ", ".join(
                        f"{s.id} ({s.label})"
                        for s in self._sets.values()
                        if s.lens == lens
                    )
                    raise HighlightError(
                        f"the {lens} lens already has {MAX_SETS_PER_LENS} "
                        f"highlight sets ({names}); clear or replace one first"
                    )
                slot = free[0]
                set_id = f"h{self._next_id}"
                self._next_id += 1
            hs = HighlightSet(
                id=set_id,
                lens=lens,
                label=label,
                short=_clip(short, SHORT_MAX) if short else short_label(label),
                slot=slot,
                reasons=clean,
                origin=origin if origin in ORIGINS else "manual",
                query=str(query or ""),
                scope=scope,
                basis=dict(basis or {}),
                complete=bool(complete),
            )
            self._sets[set_id] = hs
            if filter:
                self._filters[lens] = set_id
            self._commit(lens)
            result = hs.copy()
            result.generation = self._generation
        # The list of sets changed (bar, column, filter): redraw the whole lens.
        self._notify(lens, None)
        return result

    def add(
        self,
        set_id: str,
        reasons: Mapping[str, str],
        *,
        generation: int | None = None,
    ) -> int:
        """Add rows (or update their reasons); returns the new total.

        Raises:
            HighlightError: Unknown set, or the set would exceed the key cap.
            StaleGenerationError: *generation* is from before a session switch.
        """
        with self._lock:
            self._check_generation(generation)
            hs = self._require(set_id)
            clean = self._clean_reasons(hs.lens, reasons)
            new = [k for k in clean if k not in hs.reasons]
            if len(hs.reasons) + len(new) > MAX_KEYS_PER_SET:
                raise HighlightError(
                    f"highlight set {set_id} would exceed {MAX_KEYS_PER_SET} rows"
                )
            if not clean:
                return len(hs.reasons)
            hs.reasons.update(clean)
            self._commit(hs.lens)
            total, lens = len(hs.reasons), hs.lens
        self._notify(lens, clean)
        return total

    def remove_keys(
        self, set_id: str, keys: Iterable[str], *, generation: int | None = None
    ) -> int:
        """Drop rows from a set; returns the new total."""
        with self._lock:
            self._check_generation(generation)
            hs = self._require(set_id)
            gone = [
                k
                for k in (normalize_key(hs.lens, key) for key in keys)
                if k in hs.reasons
            ]
            if not gone:
                return len(hs.reasons)
            for k in gone:
                del hs.reasons[k]
            self._commit(hs.lens)
            total, lens = len(hs.reasons), hs.lens
        self._notify(lens, gone)
        return total

    def replace_keys(
        self,
        set_id: str,
        reasons: Mapping[str, str],
        *,
        generation: int | None = None,
    ) -> int:
        """Replace all rows of a set; returns the new total."""
        with self._lock:
            self._check_generation(generation)
            hs = self._require(set_id)
            clean = self._clean_reasons(hs.lens, reasons)
            if len(clean) > MAX_KEYS_PER_SET:
                raise HighlightError(
                    f"a highlight set holds at most {MAX_KEYS_PER_SET} rows"
                )
            changed = set(hs.reasons) | set(clean)
            hs.reasons = clean
            self._commit(hs.lens)
            total, lens = len(clean), hs.lens
        self._notify(lens, changed)
        return total

    def finish(
        self,
        set_id: str,
        *,
        complete: bool,
        stats: Mapping[str, Any] | None = None,
        basis: Mapping[str, Any] | None = None,
        generation: int | None = None,
    ) -> None:
        """Mark a set complete or partial and merge its stats/basis."""
        with self._lock:
            self._check_generation(generation)
            hs = self._require(set_id)
            hs.complete = bool(complete)
            if stats:
                hs.stats.update(stats)
            if basis:
                hs.basis.update(basis)
            self._commit(hs.lens)
            lens = hs.lens
        self._notify(lens, None)

    def update_meta(
        self,
        set_id: str,
        *,
        label: str | None = None,
        short: str | None = None,
        query: str | None = None,
        generation: int | None = None,
    ) -> None:
        """Rename a set (label/short) or change its query text."""
        with self._lock:
            self._check_generation(generation)
            hs = self._require(set_id)
            if label:
                hs.label = _clip(label, LABEL_MAX)
                hs.short = _clip(short, SHORT_MAX) if short else short_label(label)
            elif short:
                hs.short = _clip(short, SHORT_MAX)
            if query is not None:
                hs.query = str(query)
            self._commit(hs.lens)
            lens = hs.lens
        self._notify(lens, None)

    def remove(self, set_id: str, *, generation: int | None = None) -> None:
        """Delete one set (and its filter role).

        Raises:
            HighlightError: Unknown set.
            StaleGenerationError: *generation* is from before a session switch.
        """
        with self._lock:
            self._check_generation(generation)
            hs = self._require(set_id)
            del self._sets[set_id]
            if self._filters.get(hs.lens) == set_id:
                del self._filters[hs.lens]
            self._commit(hs.lens)
            lens = hs.lens
        self._notify(lens, None)

    def clear(self, lens: str | None = None) -> list[str]:
        """Delete every set (of *lens*); returns the removed ids."""
        if lens is not None:
            self._check_lens(lens)
        with self._lock:
            gone = [s for s in self._sets.values() if lens is None or s.lens == lens]
            if not gone:
                return []
            for hs in gone:
                del self._sets[hs.id]
            for name in [lens] if lens is not None else list(self._filters):
                self._filters.pop(name, None)
            self._commit(*(sorted({s.lens for s in gone})))
        self._notify(lens, None)
        return [s.id for s in gone]

    def set_filter(
        self, lens: str, set_id: str | None, *, generation: int | None = None
    ) -> None:
        """Make *set_id* the lens's AI filter (``None``: no filter).

        Raises:
            HighlightError: Bad lens, unknown set, set of another lens.
            StaleGenerationError: *generation* is from before a session switch.
        """
        self._check_lens(lens)
        with self._lock:
            self._check_generation(generation)
            if set_id is None:
                if self._filters.pop(lens, None) is None:
                    return
            else:
                hs = self._require(set_id)
                if hs.lens != lens:
                    raise HighlightError(
                        f"highlight set {set_id!r} belongs to the {hs.lens} lens"
                    )
                if self._filters.get(lens) == set_id:
                    return
                self._filters[lens] = set_id
            self._commit(lens)
        self._notify(lens, None)

    # -- persistence ------------------------------------------------------------

    def bind_folder(self, folder: Path | None) -> None:
        """Switch to the session *folder* (load its file, or start empty).

        The same folder again is a no-op. ``None`` after a folder = no session:
        the sets are dropped and kept in memory only from then on; ``None``
        while never bound keeps the in-memory sets. A real switch bumps
        :attr:`generation`. The new state is built completely before it
        replaces the old one (a bad file never half-applies).
        """
        target = Path(folder).expanduser().absolute() if folder is not None else None
        with self._lock:
            if self._folder is not _UNBOUND and self._folder == target:
                return
            if target is None and self._folder in (_UNBOUND, None):
                self._folder = None
                return
            sets: dict[str, HighlightSet] = {}
            filters: dict[str, str] = {}
            next_id = 1
            if target is not None:
                # Our own pending write of that file must land first.
                self.flush()
                sets, filters, next_id = self._load(target / "ai" / HIGHLIGHTS_FILE)
            self._folder = target
            self._sets = sets
            self._filters = filters
            self._next_id = next_id
            self._generation += 1
            self._rebuild_all()
            self._revision += 1
        self._notify(None, None)

    @staticmethod
    def _parse(data: Any) -> tuple[dict[str, HighlightSet], dict[str, str], int]:
        """Validate a whole file's content (raises :class:`_BadFileError`)."""
        if not isinstance(data, dict):
            raise _BadFileError("not a JSON object")
        raw_sets = data.get("sets", [])
        raw_filters = data.get("filters", {})
        if not isinstance(raw_sets, list) or not isinstance(raw_filters, dict):
            raise _BadFileError("sets must be a list and filters an object")
        sets: dict[str, HighlightSet] = {}
        slots: set[tuple[str, int]] = set()
        for raw in raw_sets:
            try:
                hs = HighlightSet.from_dict(raw)
            except (ValueError, TypeError) as exc:
                raise _BadFileError(str(exc)) from exc
            if hs.id in sets or (hs.lens, hs.slot) in slots:
                raise _BadFileError(f"duplicate set id or slot ({hs.id})")
            slots.add((hs.lens, hs.slot))
            sets[hs.id] = hs
        filters: dict[str, str] = {}
        for lens, sid in raw_filters.items():
            if lens not in LENSES or sid not in sets or sets[sid].lens != lens:
                raise _BadFileError(f"bad filter {lens!r}: {sid!r}")
            filters[lens] = sid
        top = max((_id_number(s) for s in sets), default=0)
        raw_next = data.get("next_id", 1)
        if isinstance(raw_next, bool) or not isinstance(raw_next, int):
            raise _BadFileError("next_id must be an integer")
        return sets, filters, max(raw_next, top + 1)

    def _load(self, path: Path) -> tuple[dict[str, HighlightSet], dict[str, str], int]:
        """``(sets, filters, next_id)`` of *path*; empty when missing or bad.

        A file that is not valid JSON or has the wrong shape is kept as
        ``highlights.json.bad`` (the next save writes a fresh file).
        """
        empty: tuple[dict[str, HighlightSet], dict[str, str], int] = ({}, {}, 1)
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return empty
        except OSError:
            logger.warning("Highlights file %s is unreadable; starting empty", path)
            return empty
        try:
            return self._parse(json.loads(text))
        except (ValueError, TypeError) as exc:
            bad = path.with_name(path.name + ".bad")
            logger.warning(
                "Highlights file %s is malformed (%s); kept as %s, starting empty",
                path,
                exc,
                bad.name,
            )
            with contextlib.suppress(OSError):
                path.replace(bad)
            return empty

    def _snapshot(self) -> dict:
        """Under the lock: the file content of the current state."""
        sets = []
        for hs in self._sets.values():
            data = asdict(hs)
            data.pop("generation", None)
            sets.append(data)
        return {
            "schema": SCHEMA,
            "next_id": self._next_id,
            "filters": dict(self._filters),
            "sets": sets,
        }

    def _queue_write(self) -> None:
        """Under the lock: hand the current state to the writer thread."""
        path = self.path
        if path is None:
            return
        payload = self._snapshot()
        with self._write_lock:
            self._write_seq += 1
            self._pending_writes[path] = (self._write_seq, payload)
            self._writes_idle.clear()
            if self._writer is None:
                self._writer = threading.Thread(
                    target=self._write_loop, name="ai-highlights-writer", daemon=True
                )
                self._writer.start()

    def _write_loop(self) -> None:
        while True:
            with self._write_lock:
                if not self._pending_writes:
                    self._writer = None
                    self._writes_idle.set()
                    return
                path = next(iter(self._pending_writes))
                seq, payload = self._pending_writes.pop(path)
            self._write(path, seq, payload)

    def _write(self, path: Path, seq: int, payload: dict) -> None:
        """Write one snapshot (writer thread; never under the store lock)."""
        if self._written_seq.get(path, 0) > seq:
            return  # a newer snapshot of this file is already on disk
        try:
            from sandroid.ai.results import ensure_private_dir
            from sandroid.config.loader import atomic_write_bytes

            ensure_private_dir(path.parent)
            atomic_write_bytes(
                path,
                json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                mode=0o600,
            )
            self._written_seq[path] = seq
        except Exception:
            logger.warning("Saving highlights to %s failed", path, exc_info=True)

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until every queued write is on disk (True) or *timeout*."""
        if self._writer is threading.current_thread():
            return False
        return self._writes_idle.wait(max(0.0, timeout))

    # -- row sources --------------------------------------------------------------

    def register_row_source(
        self, lens: str, fn: Callable[[], list[dict]], dispatcher: Any
    ) -> None:
        """A lens offers its rows (newest registration wins)."""
        with self._sources_lock:
            sources = self._sources.setdefault(lens, [])
            sources[:] = [s for s in sources if s.fn != fn]
            sources.append(_RowSource(fn, dispatcher))

    def unregister_row_source(self, lens: str, fn: Callable[[], list[dict]]) -> None:
        """Withdraw a lens's row source."""
        with self._sources_lock:
            sources = self._sources.get(lens) or []
            sources[:] = [s for s in sources if s.fn != fn]

    def has_row_source(self, lens: str) -> bool:
        """Whether a lens registered a row source."""
        with self._sources_lock:
            return bool(self._sources.get(lens))

    def snapshot_rows(self, lens: str, timeout: float = 3.0) -> list[dict] | None:
        """The rows of the lens's current view, taken on the UI thread.

        Returns ``None`` when no lens registered, its UI loop is gone or it
        did not answer within *timeout* seconds (callers fall back to the
        flow log / monitor history). Never blocks the UI thread: called on
        it, the source runs directly.
        """
        with self._sources_lock:
            sources = list(self._sources.get(lens) or [])
        if not sources:
            return None
        src = sources[-1]
        dispatcher = src.dispatcher
        on_ui = dispatcher is None or (
            getattr(dispatcher, "_ui_thread", None) == threading.get_ident()
        )
        if on_ui:
            try:
                rows = src.fn()
            except Exception:
                logger.debug("row source of %s failed", lens, exc_info=True)
                return None
            return _copy_rows(rows)
        done = threading.Event()
        box: dict[str, Any] = {}

        def run() -> None:
            try:
                box["rows"] = src.fn()
            except Exception as exc:
                box["error"] = exc
            finally:
                done.set()

        try:
            posted = dispatcher.post(run)
        except Exception:
            posted = False
        if not posted or not done.wait(max(0.0, timeout)):
            return None
        if "error" in box:
            logger.debug("row source of %s failed: %s", lens, box["error"])
            return None
        return _copy_rows(box.get("rows"))

    # -- internals ------------------------------------------------------------------

    @staticmethod
    def _check_lens(lens: str) -> None:
        if lens not in LENSES:
            raise HighlightError(
                f"unknown lens {lens!r}; use one of: {', '.join(LENSES)}"
            )

    def _check_generation(self, generation: int | None) -> None:
        if generation is not None and generation != self._generation:
            raise StaleGenerationError(
                "the analysis session changed; this highlight set belongs to "
                "the previous one"
            )

    def _require(self, set_id: str) -> HighlightSet:
        hs = self._sets.get(set_id)
        if hs is None:
            raise HighlightError(f"unknown highlight set {set_id!r}")
        return hs

    @staticmethod
    def _clean_reasons(lens: str, reasons: Mapping[str, str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for key, reason in reasons.items():
            k = normalize_key(lens, key)
            if k:
                out[k] = _clip(reason, REASON_MAX)
        return out

    def _rebuild_index(self, lens: str) -> None:
        entries: dict[str, list[tuple[str, int, str, str]]] = {}
        for hs in sorted(
            (s for s in self._sets.values() if s.lens == lens), key=lambda s: s.slot
        ):
            for key, reason in hs.reasons.items():
                entries.setdefault(key, []).append((hs.id, hs.slot, hs.short, reason))
        index = dict(self._index)
        index[lens] = {k: tuple(v) for k, v in entries.items()}
        self._index = index

    def _rebuild_all(self) -> None:
        self._index = {}
        for lens in LENSES:
            self._rebuild_index(lens)

    def _commit(self, *lenses: str) -> None:
        """Under the lock: new index, revision, queued file write."""
        for lens in lenses:
            self._rebuild_index(lens)
        self._revision += 1
        self._queue_write()

    @staticmethod
    def _notify(lens: str | None, keys: Iterable[str] | None) -> None:
        try:
            registry().notify(lens, keys)
        except Exception:
            logger.debug("highlight notify failed", exc_info=True)


def _id_number(set_id: str) -> int:
    try:
        return int(str(set_id).lstrip("h"))
    except ValueError:
        return 0


def _copy_rows(rows: Any) -> list[dict] | None:
    if rows is None:
        return None
    out: list[dict] = []
    with contextlib.suppress(TypeError):
        for row in rows:
            if isinstance(row, dict):
                out.append(dict(row))
    return out


_STORE: HighlightStore | None = None
_STORE_LOCK = threading.Lock()


def get_row_highlights() -> HighlightStore:
    """The process-wide store (registered as the ``"ai"`` annotation source).

    On first use it binds to the current analysis session's folder, if any.
    """
    global _STORE
    with _STORE_LOCK:
        if _STORE is not None:
            return _STORE
        store = HighlightStore()
        _STORE = store
    try:
        from sandroid.ai.results import session_root

        root = session_root()
        if root is not None:
            store.bind_folder(root)
    except Exception:
        logger.debug("binding highlights to the session failed", exc_info=True)
    registry().register(store)
    return store


def reset_for_tests() -> None:
    """Drop the singleton and unregister it (test isolation)."""
    global _STORE
    with _STORE_LOCK:
        store, _STORE = _STORE, None
    if store is not None:
        with contextlib.suppress(Exception):
            registry().unregister(store.source)


__all__ = [
    "HIGHLIGHTS_FILE",
    "HIGHLIGHT_TINT",
    "LENSES",
    "MAX_KEYS_PER_SET",
    "MAX_SETS_PER_LENS",
    "HighlightError",
    "HighlightSet",
    "HighlightStore",
    "StaleGenerationError",
    "get_row_highlights",
    "normalize_key",
    "reset_for_tests",
    "short_label",
]
