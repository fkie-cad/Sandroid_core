"""Shared diff-rendering widget for the Files tab (Watchlist + Diffs).

Both the Watchlist and Diffs sub-tabs render per-file diffs identically —
one widget, one code path. ``DiffView`` takes an already-computed
Rich-markup diff string (or a list of lines — both shapes are produced by
different callers in this codebase, e.g. ``core/file_diff.py``'s
``{file: [diff_lines]}`` shape vs. a pre-joined ``str``) and renders it as a
collapsible entry. Small diffs expand fully inline; large ones show a
truncated preview with a hint to open the full search/export view
(``DiffZoomModal``, ``z``).

This widget does no I/O and knows nothing about *where* diffs come from —
callers (Watchlist auto-pull, Diffs run history) own that.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from textual.widget import Widget
from textual.widgets import Collapsible, RichLog

if TYPE_CHECKING:
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)


class DiffView(Widget):
    """Renders one already-computed diff as a collapsible log entry.

    Bindings:
        z: open the full diff in :class:`DiffZoomModal` (search + export).
           Always works regardless of size — declared explicitly here so it
           is available even while the preview is truncated.

    When several ``DiffView`` widgets are mounted in a list (the Diffs
    sub-tab shows one per changed file), ``z`` must target whichever entry
    is currently focused/expanded, not some global "the diff". This is
    handled by binding ``z`` directly on the (focusable) ``DiffView``
    instance itself and reading ``self._text``/``self._lines`` — i.e. the
    zoom modal is always constructed from *this* instance's own diff data,
    never a shared/singleton reference. Expanding the ``Collapsible`` also
    focuses this instance (see ``on_collapsible_expanded``), so "focused" and
    "expanded" converge on the same widget.
    """

    can_focus = True

    #: Soft UX threshold (not a hard technical cap — file_diff.py already
    #: bails out well before this at pathological sizes). Below this many
    #: lines, an expanded DiffView shows everything inline.
    SOFT_LINE_THRESHOLD = 200

    #: How many lines to show inline once a diff is at/above the threshold.
    PREVIEW_LINES = 50

    DEFAULT_CSS = """
    DiffView {
        layout: vertical;
        height: auto;
        width: 1fr;
    }
    DiffView #diff-log {
        height: auto;
        max-height: 24;
        background: #050811;
        scrollbar-size: 1 1;
    }
    """

    BINDINGS = [
        ("z", "zoom", "Zoom (search/export)"),
    ]

    def __init__(
        self,
        diff: str | list[str],
        *,
        title: str = "diff",
        start_expanded: bool = False,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Args:
        diff: The already-computed Rich-markup diff. Either a single
            newline-joined string or a list of lines — both shapes occur in
            this codebase's diff producers.
        title: Label shown on the collapsible header (e.g. a filename).
        start_expanded: Whether the entry starts expanded (default
            collapsed, matching ``Collapsible``'s own default — a list of
            many diffs should not all burst open at once).
        """
        super().__init__(id=id, classes=classes)
        self.can_focus = True
        if isinstance(diff, str):
            self._text = diff
            self._lines = diff.splitlines()
        else:
            self._lines = list(diff)
            self._text = "\n".join(self._lines)
        self._title = title
        self._start_expanded = start_expanded

    # -- public accessors ---------------------------------------------------

    @property
    def diff_text(self) -> str:
        """The full, untruncated diff text (with markup) owned by THIS entry."""
        return self._text

    @property
    def diff_lines(self) -> list[str]:
        """The full, untruncated diff lines (with markup) owned by THIS entry."""
        return self._lines

    # -- compose / mount -----------------------------------------------------

    def compose(self) -> ComposeResult:
        n = len(self._lines)
        label = f"{self._title} ({n} line{'s' if n != 1 else ''})"
        with Collapsible(
            title=label,
            collapsed=not self._start_expanded,
            id="diff-collapsible",
        ):
            yield RichLog(
                highlight=False,
                markup=True,
                wrap=False,
                id="diff-log",
            )

    def on_mount(self) -> None:
        self._render_body()

    def on_click(self, _event) -> None:
        # Clicking anywhere in this entry (including the Collapsible header)
        # focuses it, so a subsequent `z` unambiguously targets it.
        self.focus()

    def on_collapsible_expanded(self, _event: Collapsible.Expanded) -> None:
        """Expanding an entry also focuses it (see class docstring).

        Collapsible posts ``Expanded``/``Collapsed`` (subclasses of the
        ``Toggled`` base), never ``Toggled`` itself — Textual's naming-
        convention dispatch resolves the handler from the message's own
        concrete class, so the handler must be named for the specific
        subclass (``on_collapsible_expanded``), not the shared base.
        """
        self.focus()

    def _render_body(self) -> None:
        try:
            log = self.query_one("#diff-log", RichLog)
        except Exception:
            return
        log.clear()
        n = len(self._lines)
        if n < self.SOFT_LINE_THRESHOLD:
            for line in self._lines:
                log.write(line)
        else:
            for line in self._lines[: self.PREVIEW_LINES]:
                log.write(line)
            log.write(f"[#5b6479]… diff is {n} lines — press z for full search view[/]")

    # -- actions --------------------------------------------------------

    def action_zoom(self) -> None:
        """Z — open this specific diff in the full search/export modal."""
        from sandroid.tui.modals.diff_zoom_modal import DiffZoomModal

        try:
            self.app.push_screen(DiffZoomModal(diff_text=self._text, title=self._title))
        except Exception as exc:
            logger.warning("Failed to open DiffZoomModal: %s", exc)
