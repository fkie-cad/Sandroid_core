"""Headless Textual Pilot tests for the shared DiffView widget.

DiffView is used by BOTH the Watchlist and Diffs sub-tabs (see its module
docstring) but had zero dedicated test coverage before this file. Covers:
the ~200-line collapsed-vs-preview threshold (right at the boundary), and
that ``z`` opens DiffZoomModal scoped to whichever DiffView instance is
actually focused -- never a shared/stale reference -- when several are
mounted at once (mirrors how DiffsView renders one DiffView per changed
file in a real run).
"""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.widgets import RichLog

from sandroid.tui.modals.diff_zoom_modal import DiffZoomModal
from sandroid.tui.widgets.diff_view import DiffView


class _DiffViewHarness(App):
    """Mounts one DiffView per (title, diff_text) pair, all expanded."""

    def __init__(self, diffs: list[tuple[str, str]]) -> None:
        super().__init__()
        self._diffs = diffs

    def compose(self) -> ComposeResult:
        for title, diff_text in self._diffs:
            yield DiffView(diff=diff_text, title=title, start_expanded=True)


def _numbered_lines(n: int) -> str:
    return "\n".join(f"line {i}" for i in range(n))


@pytest.mark.asyncio
async def test_diff_just_below_threshold_renders_every_line_inline() -> None:
    """199 lines (< SOFT_LINE_THRESHOLD=200): no truncation, no hint line."""
    n = DiffView.SOFT_LINE_THRESHOLD - 1
    app = _DiffViewHarness([("f", _numbered_lines(n))])
    async with app.run_test() as pilot:
        view = app.query_one(DiffView)
        await pilot.pause()

        log = view.query_one("#diff-log", RichLog)
        assert len(log.lines) == n


@pytest.mark.asyncio
async def test_diff_at_threshold_shows_truncated_preview_with_hint() -> None:
    """200 lines (== SOFT_LINE_THRESHOLD): only PREVIEW_LINES shown + 1 hint
    line pointing at 'z' for the full view.
    """
    n = DiffView.SOFT_LINE_THRESHOLD
    app = _DiffViewHarness([("f", _numbered_lines(n))])
    async with app.run_test() as pilot:
        view = app.query_one(DiffView)
        await pilot.pause()

        log = view.query_one("#diff-log", RichLog)
        assert len(log.lines) == DiffView.PREVIEW_LINES + 1
        last_line = str(log.lines[-1].text)
        assert "z for full search view" in last_line
        assert str(n) in last_line


@pytest.mark.asyncio
async def test_collapsible_title_shows_total_line_count_regardless_of_truncation() -> (
    None
):
    n = DiffView.SOFT_LINE_THRESHOLD + 50
    app = _DiffViewHarness([("myfile", _numbered_lines(n))])
    async with app.run_test() as pilot:
        view = app.query_one(DiffView)
        await pilot.pause()

        from textual.widgets import Collapsible

        collapsible = view.query_one("#diff-collapsible", Collapsible)
        assert f"myfile ({n} lines)" == collapsible.title


@pytest.mark.asyncio
async def test_zoom_targets_the_focused_instance_not_a_stale_or_shared_one() -> None:
    """Two DiffViews mounted together -- 'z' must always open a modal built
    from whichever one is actually focused, proving the zoom modal is
    constructed from THIS instance's own diff data (self._text), never a
    shared/singleton reference that could leak the wrong content.
    """
    text_a = "\n".join(f"a-line-{i}" for i in range(5))
    text_b = "\n".join(f"b-line-{i}" for i in range(5))

    app = _DiffViewHarness([("file_a.txt", text_a), ("file_b.txt", text_b)])
    async with app.run_test() as pilot:
        view_a, view_b = list(app.query(DiffView))
        await pilot.pause()

        # Focus the SECOND entry first (deliberately not the first, so this
        # doesn't pass by accident if zoom always grabbed the first widget).
        view_b.focus()
        await pilot.pause()
        await pilot.press("z")
        await pilot.pause()

        modal = app.screen
        assert isinstance(modal, DiffZoomModal)
        assert modal._title == "file_b.txt"
        assert "b-line-0" in modal._plain
        assert "a-line-0" not in modal._plain

        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, DiffZoomModal)

        view_a.focus()
        await pilot.pause()
        await pilot.press("z")
        await pilot.pause()

        modal = app.screen
        assert isinstance(modal, DiffZoomModal)
        assert modal._title == "file_a.txt"
        assert "a-line-0" in modal._plain
        assert "b-line-0" not in modal._plain


@pytest.mark.asyncio
async def test_expanding_collapsible_focuses_this_entry() -> None:
    """Expanding an entry also focuses it (see DiffView's class docstring)
    so a subsequent 'z' unambiguously targets whichever entry the user just
    opened, without a separate click first. Needs a DiffView that starts
    COLLAPSED (unlike the other tests' harness) so toggling it to expanded
    actually changes the reactive value and fires Collapsible.Expanded.
    """
    from textual.widgets import Collapsible

    class _CollapsedHarness(App):
        def compose(self) -> ComposeResult:
            yield DiffView(diff="line one\nline two", title="only")

    app = _CollapsedHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffView)
        await pilot.pause()

        collapsible = view.query_one("#diff-collapsible", Collapsible)
        assert collapsible.collapsed is True  # start_expanded defaults False

        collapsible.collapsed = False
        await pilot.pause()

        assert app.focused is view
