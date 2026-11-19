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
written atomically after each mutation). :meth:`HighlightStore.bind_folder`
switches sessions; without a folder the sets live in memory only.

Row sources: a lens registers a snapshot callable
(:meth:`HighlightStore.register_row_source`); tools call
:meth:`HighlightStore.snapshot_rows` from their helper thread, which runs the
callable on the UI loop through the lens's ``UiDispatcher`` and waits a
bounded time (never ``App.call_from_thread``).
"""

from __future__ import annotations

import contextlib
import json
import logging
import threading
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sandroid.tui.row_annotations import (
    LENS_FILES,
    LENS_NETWORK,
    PRIORITY_AI,
    Annotation,
    registry,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

logger = logging.getLogger(__name__)

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
        )

    @property
    def count(self) -> int:
        """Rows in the set."""
        return len(self.reasons)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> HighlightSet | None:
        """Parse a persisted set (``None`` when unusable)."""
        try:
            known = {f.name for f in fields(cls)}
            kwargs = {k: v for k, v in data.items() if k in known}
            hs = cls(**kwargs)
        except TypeError:
            return None
        if hs.lens not in LENSES or not isinstance(hs.reasons, dict):
            return None
        hs.reasons = {str(k): _clip(v, REASON_MAX) for k, v in hs.reasons.items()}
        try:
            hs.slot = int(hs.slot)
        except (TypeError, ValueError):
            return None
        hs.basis = dict(hs.basis or {})
        hs.stats = dict(hs.stats or {})
        return hs


def _clip(text: Any, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def short_label(label: str) -> str:
    """A column-sized label from a longer one (whole words when possible)."""
    label = " ".join(str(label or "").split())
    if len(label) <= SHORT_MAX:
        return label
    words: list[str] = []
    for word in label.split():
        candidate = " ".join([*words, word])
        if len(candidate) > SHORT_MAX:
            break
        words.append(word)
    if words:
        return " ".join(words)
    return label[: SHORT_MAX - 1] + "…"


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

    # -- reads (lock-free where it matters) -----------------------------------

    @property
    def revision(self) -> int:
        """Bumps on every change (monotonic)."""
        return self._revision

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
            return hs.copy() if hs is not None else None

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
    ) -> HighlightSet:
        """Create a set (or replace *replace_id* in place, keeping its slot).

        Raises:
            HighlightError: Bad lens, too many sets or keys, unknown
                ``replace_id``.
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
            changed = set(clean) | (set(old.reasons) if old else set())
            self._commit(lens)
            result = hs.copy()
        self._notify(lens, changed)
        return result

    def add(self, set_id: str, reasons: Mapping[str, str]) -> int:
        """Add rows (or update their reasons); returns the new total.

        Raises:
            HighlightError: Unknown set, or the set would exceed the key cap.
        """
        with self._lock:
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

    def remove_keys(self, set_id: str, keys: Iterable[str]) -> int:
        """Drop rows from a set; returns the new total."""
        with self._lock:
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

    def replace_keys(self, set_id: str, reasons: Mapping[str, str]) -> int:
        """Replace all rows of a set; returns the new total."""
        with self._lock:
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
    ) -> None:
        """Mark a set complete or partial and merge its stats/basis."""
        with self._lock:
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
    ) -> None:
        """Rename a set (label/short) or change its query text."""
        with self._lock:
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

    def remove(self, set_id: str) -> None:
        """Delete one set (and its filter role).

        Raises:
            HighlightError: Unknown set.
        """
        with self._lock:
            hs = self._require(set_id)
            del self._sets[set_id]
            if self._filters.get(hs.lens) == set_id:
                del self._filters[hs.lens]
            self._commit(hs.lens)
            lens, keys = hs.lens, list(hs.reasons)
        self._notify(lens, keys)

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

    def set_filter(self, lens: str, set_id: str | None) -> None:
        """Make *set_id* the lens's AI filter (``None``: no filter).

        Raises:
            HighlightError: Bad lens, unknown set, set of another lens.
        """
        self._check_lens(lens)
        with self._lock:
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
        while never bound keeps the in-memory sets.
        """
        target = Path(folder).expanduser().absolute() if folder is not None else None
        with self._lock:
            if self._folder is not _UNBOUND and self._folder == target:
                return
            if target is None and self._folder in (_UNBOUND, None):
                self._folder = None
                return
            self._folder = target
            self._sets = {}
            self._filters = {}
            self._next_id = 1
            if target is not None:
                self._load(target / "ai" / HIGHLIGHTS_FILE)
            self._rebuild_all()
            self._revision += 1
        self._notify(None, None)

    def _load(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            logger.warning("Highlights file %s is unreadable; starting empty", path)
            return
        if not isinstance(data, dict):
            return
        sets: dict[str, HighlightSet] = {}
        slots: dict[str, set[int]] = {}
        for raw in data.get("sets") or []:
            if not isinstance(raw, dict):
                continue
            hs = HighlightSet.from_dict(raw)
            if hs is None or hs.id in sets:
                continue
            used = slots.setdefault(hs.lens, set())
            if hs.slot in used or not 1 <= hs.slot <= MAX_SETS_PER_LENS:
                continue
            used.add(hs.slot)
            sets[hs.id] = hs
        self._sets = sets
        filters = data.get("filters") or {}
        self._filters = {
            lens: sid
            for lens, sid in filters.items()
            if sid in sets and sets[sid].lens == lens
        }
        top = max((_id_number(s) for s in sets), default=0)
        try:
            self._next_id = max(int(data.get("next_id") or 1), top + 1)
        except (TypeError, ValueError):
            self._next_id = top + 1

    def _persist(self) -> None:
        path = self.path
        if path is None:
            return
        payload = {
            "schema": SCHEMA,
            "next_id": self._next_id,
            "filters": dict(self._filters),
            "sets": [asdict(s) for s in self._sets.values()],
        }
        try:
            from sandroid.ai.results import ensure_private_dir
            from sandroid.config.loader import atomic_write_bytes

            ensure_private_dir(path.parent)
            atomic_write_bytes(
                path,
                json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                mode=0o600,
            )
        except Exception:
            logger.warning("Saving highlights to %s failed", path, exc_info=True)

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
        """Under the lock: new index, revision, file."""
        for lens in lenses:
            self._rebuild_index(lens)
        self._revision += 1
        self._persist()

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
    "get_row_highlights",
    "normalize_key",
    "reset_for_tests",
    "short_label",
]
