"""Shared row annotations for the lens tables (Network, Files, ...).

Several sources annotate the same rows: the privacy scan (identity-profile
values in a flow or a file) and AI marks (rows the chat agent judged to match
a question of the user). Each source is a :class:`RowAnnotationProvider`
registered once in the process-wide :func:`registry`; a lens asks the
registry, never the sources, so a new source needs no lens change.

A provider answers, per lens (``"network"``, ``"files"``) and row key (the
mitm flow id, a canonical device path):

* :meth:`~RowAnnotationProvider.annotations_for` -- what to show for the row:
  plain words (``label``), a theme-token colour, a reason for the inspector
  and an optional row tint (theme-token role). No glyphs or symbols: words,
  colour and tint only.
* :meth:`~RowAnnotationProvider.filter_predicate` -- an active filter of the
  source (``None`` = no filter). A lens applies every active predicate inside
  its own row filter, so follow counts ("N new below") only see shown rows.

Change signals: a provider (or anyone) calls :meth:`RowAnnotationRegistry.notify`
from any thread with the lens and the changed keys (``None`` = all). It never
blocks. A lens receives them through an :class:`AnnotationFeed`, which makes
one non-blocking UI hop and flushes at most once per :data:`REFRESH_S`.

Rendering: :class:`AnnotationTintMixin` for a ``DataTable`` tints rows whose
annotations carry a ``tint_role`` (the highest-priority one wins; AI
highlights, asked for explicitly, beat the privacy tint). The tint colour is cached per theme
palette, the per-row lookup per registry revision.

Everything here is UI-agnostic except :class:`AnnotationFeed` (needs a
mounted widget) and :class:`AnnotationTintMixin` (a ``DataTable`` mixin);
both import Textual lazily. Importing this module still runs
``sandroid/tui/__init__`` (about 0.7 s), so a service imports it lazily,
inside the function that needs it.
"""

from __future__ import annotations

import functools
import logging
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from rich.style import Style

logger = logging.getLogger(__name__)

#: Lens names used as registry keys.
LENS_NETWORK = "network"
LENS_FILES = "files"

#: A feed flushes at most once per this many seconds.
REFRESH_S = 1.0
#: A posted UI hop that never ran (its widget unmounted, its timer died)
#: stops blocking new posts after this many seconds.
POST_STALE_S = 5.0

#: Default priorities (higher wins the tint and sorts first).
PRIORITY_PRIVACY = 100
#: AI highlights are asked for explicitly by the user: they win the tint.
PRIORITY_AI = 150

#: Default row tint strength (lens bg blended towards the tint role).
TINT_AMOUNT = 0.13


@dataclass(frozen=True)
class Annotation:
    """One source's note on one row.

    Attributes:
        source: The provider's ``source`` (``"privacy"``, ``"ai"``).
        label: Plain words shown in the row / marks bar (``"Email"``,
            ``"POST to api.example.com"``).
        colour_role: A :class:`~sandroid.tui.themes.LensPalette` role name
            (``"warn"``, ``"accent"``, ``"ok"``, ``"bad"``, ``"title"`` ...)
            for the label.
        reason: Longer text for the inspector ("body has an email address").
        tint_role: Palette role to tint the whole row towards, or ``None``.
        tint_amount: How far the row background blends towards it.
        priority: Higher sorts first and wins the row tint.
        group: The provider's id of the set this note belongs to (an AI mark
            set id, a privacy marker id); free-form.
    """

    source: str
    label: str
    colour_role: str = "accent"
    reason: str = ""
    tint_role: str | None = None
    tint_amount: float = TINT_AMOUNT
    priority: int = 0
    group: str = ""


@runtime_checkable
class RowAnnotationProvider(Protocol):
    """A source of row annotations (see the module docstring)."""

    #: Stable source name (``"privacy"``, ``"ai"``).
    source: str

    @property
    def revision(self) -> int:
        """Bumps whenever any answer of this provider may have changed."""
        ...

    def annotations_for(self, lens: str, key: str) -> list[Annotation]:
        """The notes for row ``key`` of ``lens`` (``[]`` = none). Fast, any thread."""
        ...

    def filter_predicate(self, lens: str) -> Callable[[str], bool] | None:
        """``key -> shown?`` while this source filters ``lens``, else ``None``."""
        ...


class RowAnnotationRegistry:
    """Process-wide set of providers plus a thread-safe change signal."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._providers: dict[str, RowAnnotationProvider] = {}
        self._listeners: list[Callable[[str | None, frozenset[str] | None], None]] = []
        self._own_revision = 0

    # -- providers ---------------------------------------------------------

    def register(self, provider: RowAnnotationProvider) -> None:
        """Add (or replace, by ``source``) a provider; notifies all lenses."""
        with self._lock:
            self._providers[provider.source] = provider
            self._own_revision += 1
        self.notify(None, None)

    def unregister(self, source: str) -> None:
        with self._lock:
            removed = self._providers.pop(source, None)
            self._own_revision += 1
        if removed is not None:
            self.notify(None, None)

    def provider(self, source: str) -> RowAnnotationProvider | None:
        with self._lock:
            return self._providers.get(source)

    def providers(self) -> list[RowAnnotationProvider]:
        with self._lock:
            return list(self._providers.values())

    @property
    def revision(self) -> tuple:
        """Changes whenever any provider's revision or the provider set changes.

        An opaque hashable value: compare with ``==`` only (cache keys).
        """
        revs: list[tuple[str, Any]] = []
        for p in self.providers():
            try:
                revs.append((p.source, p.revision))
            except Exception:
                continue
        return (self._own_revision, tuple(revs))

    # -- queries -----------------------------------------------------------

    def annotations_for(self, lens: str, key: str) -> list[Annotation]:
        """All sources' notes for a row, highest priority first."""
        out: list[Annotation] = []
        for p in self.providers():
            try:
                out.extend(p.annotations_for(lens, key) or ())
            except Exception:
                logger.debug("annotations_for failed (%s)", p.source, exc_info=True)
        out.sort(key=lambda a: -a.priority)
        return out

    def tint_role_for(self, lens: str, key: str) -> str | None:
        """The row tint role of the highest-priority note that has one."""
        tint = self.tint_for(lens, key)
        return tint[0] if tint else None

    def tint_for(self, lens: str, key: str) -> tuple[str, float] | None:
        """``(role, amount)`` of the highest-priority note with a tint."""
        for a in self.annotations_for(lens, key):
            if a.tint_role:
                return (a.tint_role, a.tint_amount)
        return None

    def filter_predicates(self, lens: str) -> list[Callable[[str], bool]]:
        """Every active source filter of ``lens``."""
        preds = []
        for p in self.providers():
            try:
                pred = p.filter_predicate(lens)
            except Exception:
                logger.debug("filter_predicate failed (%s)", p.source, exc_info=True)
                continue
            if pred is not None:
                preds.append(pred)
        return preds

    def passes(self, lens: str, key: str) -> bool:
        """Whether row ``key`` passes every active source filter of ``lens``."""
        for pred in self.filter_predicates(lens):
            try:
                if not pred(key):
                    return False
            except Exception:
                continue
        return True

    # -- change signal -----------------------------------------------------

    def subscribe(
        self, listener: Callable[[str | None, frozenset[str] | None], None]
    ) -> None:
        with self._lock:
            if listener not in self._listeners:
                self._listeners.append(listener)

    def unsubscribe(
        self, listener: Callable[[str | None, frozenset[str] | None], None]
    ) -> None:
        with self._lock:
            try:
                self._listeners.remove(listener)
            except ValueError:
                pass

    def notify(self, lens: str | None, keys: Iterable[str] | None) -> None:
        """Rows changed (any thread, never blocks).

        ``lens=None`` = every lens; ``keys=None`` = every row.
        """
        frozen = None if keys is None else frozenset(str(k) for k in keys)
        with self._lock:
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(lens, frozen)
            except Exception:
                logger.debug("row annotation listener failed", exc_info=True)


_REGISTRY = RowAnnotationRegistry()


def registry() -> RowAnnotationRegistry:
    """The process-wide registry."""
    return _REGISTRY


# --------------------------------------------------------------------------
# UI side
# --------------------------------------------------------------------------


class AnnotationFeed:
    """Changed rows of one lens, flushed on the UI at most once a second.

    ``registry().notify`` may run on any thread; this only queues keys and
    posts one non-blocking UI hop (:class:`UiDispatcher`). On the UI,
    ``flush(keys)`` runs with the changed keys, or with ``None`` for "all".
    A hop that never ran (the owner unmounted while it was pending) stops
    blocking new posts after :data:`POST_STALE_S`.

    Usage::

        def on_mount(self):
            self._marks_feed = AnnotationFeed(self, LENS_NETWORK, self._redraw_marks)
            self._marks_feed.attach()

        def on_unmount(self):
            self._marks_feed.detach()
    """

    def __init__(
        self,
        owner: Any,
        lens: str,
        flush: Callable[[set[str] | None], None],
        *,
        reg: RowAnnotationRegistry | None = None,
        refresh_s: float = REFRESH_S,
    ) -> None:
        from sandroid.tui.utils.ui_thread import UiDispatcher

        self._owner = owner
        self._lens = lens
        self._flush_cb = flush
        self._reg = reg or registry()
        self._refresh_s = refresh_s
        self._lock = threading.Lock()
        self._pending: set[str] = set()
        self._all = False
        self._posted = False
        self._posted_at = 0.0
        self._last = 0.0
        self._ui = UiDispatcher()

    def attach(self) -> None:
        """Start listening (call on the UI thread, e.g. ``on_mount``)."""
        from sandroid.tui.utils.ui_thread import UiDispatcher

        self._ui = UiDispatcher.capture()
        with self._lock:
            self._posted = False
        self._reg.subscribe(self.on_change)

    def detach(self) -> None:
        self._reg.unsubscribe(self.on_change)

    def on_change(self, lens: str | None, keys: frozenset[str] | None) -> None:
        """Any thread: queue the keys, post one UI hop."""
        if lens is not None and lens != self._lens:
            return
        now = time.monotonic()
        with self._lock:
            if keys is None:
                self._all = True
            else:
                self._pending.update(keys)
            if self._posted and now - self._posted_at < POST_STALE_S:
                return
            self._posted = True
            self._posted_at = now
        if not self._ui.post(self._schedule):
            with self._lock:
                self._posted = False

    def _schedule(self) -> None:
        wait = self._last + self._refresh_s - time.monotonic()
        if wait > 0:
            try:
                self._owner.set_timer(wait, self._flush)
                return
            except Exception:
                pass
        self._flush()

    def _flush(self) -> None:
        with self._lock:
            pending, self._pending = self._pending, set()
            everything, self._all = self._all, False
            self._posted = False
        self._last = time.monotonic()
        if not getattr(self._owner, "is_attached", True):
            return
        if everything:
            self._flush_cb(None)
        elif pending:
            self._flush_cb(pending)


@functools.lru_cache(maxsize=64)
def _blend(bg: str, color: str, amount: float) -> str:
    from textual.color import Color

    try:
        return Color.parse(bg).blend(Color.parse(color), amount).hex
    except Exception:
        return bg


@functools.lru_cache(maxsize=64)
def bg_style(color: str) -> Style:
    """A cached Rich background style."""
    from rich.style import Style

    return Style(bgcolor=color)


def role_color(role: str) -> str:
    """A palette role's colour in the running theme (``text`` if unknown)."""
    from sandroid.tui.themes import lens_palette

    pal = lens_palette()
    return str(getattr(pal, role, None) or pal.text)


def row_tint(role: str = "warn", amount: float = TINT_AMOUNT) -> str:
    """The lens background blended a little towards a palette role.

    Cached per palette colours, so a theme change picks up the new tint.
    """
    from sandroid.tui.themes import lens_palette

    pal = lens_palette()
    return _blend(pal.bg, str(getattr(pal, role, None) or pal.warn), amount)


class AnnotationTintMixin:
    """A ``DataTable`` mixin tinting rows by their annotations.

    Set ``annotation_lens`` (``"network"`` / ``"files"``) on the table. The
    tint of a row is the ``tint_role`` of its highest-priority annotation
    (:meth:`RowAnnotationRegistry.tint_for`). Lookups are cached per
    registry revision; colours per theme palette. Override
    :meth:`annotation_key` to map a Textual row key to the annotation key
    (default: the row key's value). After a change, the owner redraws the
    affected rows (``refresh_row`` / ``update_cell``) as for any row change.

    It uses Textual 8.2's private row style hook ``_get_row_style``; the
    cursor row keeps the cursor colour. Compose other row-style mixins by
    making them annotation providers, not by a second override. (Exception:
    the Files table's own ``_get_row_style`` adds the changed-★ tint after
    this one, only where no annotation tints the row.)
    """

    annotation_lens: str = ""

    def annotation_key(self, row_key_value: Any) -> str | None:
        return None if row_key_value is None else str(row_key_value)

    def _annotation_tint(self, key: str) -> tuple[str, float] | None:
        reg = registry()
        rev = reg.revision
        cache = getattr(self, "_annotation_tint_cache", None)
        if cache is None or cache[0] != rev:
            cache = (rev, {})
            self._annotation_tint_cache = cache
        memo: dict[str, tuple[str, float] | None] = cache[1]
        if key not in memo:
            memo[key] = reg.tint_for(self.annotation_lens, key)
        return memo[key]

    def _get_row_style(self, row_index: int, base_style: Style) -> Style:
        style = super()._get_row_style(row_index, base_style)  # type: ignore[misc]
        if row_index < 0 or not self.annotation_lens:
            return style
        try:
            from textual.coordinate import Coordinate

            cell = self.coordinate_to_cell_key(Coordinate(row_index, 0))  # type: ignore[attr-defined]
            key = self.annotation_key(cell.row_key.value)
        except Exception:
            return style
        if not key:
            return style
        tint = self._annotation_tint(key)
        if tint:
            return style + bg_style(row_tint(*tint))
        return style
