"""Headless Textual Pilot tests for DiffZoomModal (opened by DiffView's 'z').

No dedicated test file existed for this modal before (see DiffView's own new
test file's docstring for the same "zero coverage" note). Covers: markup-
stripped search matching (so pseudo-tags like "[success]" can never be
mistaken for real content), n/N match navigation with wraparound, Escape
exiting search mode before it closes the modal, exporting the full
untruncated markup-stripped diff, and export-failure handling (error
notification, modal stays open).
"""

from __future__ import annotations

import pytest
from textual.app import App
from textual.widgets import Input

from sandroid.tui.modals.diff_zoom_modal import DiffZoomModal


class _ZoomHarness(App):
    """Pushes DiffZoomModal as the app's very first screen.

    No compose() override needed -- App's own default composes an empty
    base screen, which is all this harness needs beneath the modal.
    """

    def __init__(self, diff_text: str, title: str = "diff") -> None:
        super().__init__()
        self._diff_text = diff_text
        self._title = title

    def on_mount(self) -> None:
        self.push_screen(DiffZoomModal(diff_text=self._diff_text, title=self._title))


@pytest.mark.asyncio
async def test_markup_is_stripped_for_both_display_and_matching() -> None:
    diff_text = "[green]CREATE /data/a[/green]\n[red]DELETE /data/b[/red]\nplain line"
    app = _ZoomHarness(diff_text=diff_text, title="t")
    async with app.run_test() as pilot:
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, DiffZoomModal)

        assert modal._plain == "CREATE /data/a\nDELETE /data/b\nplain line"

        modal.action_start_search()
        await pilot.pause()
        search_input = modal.query_one("#zoom-search-input", Input)
        assert search_input.display is True

        # "green"/"red" only ever existed as markup TAG names, never as
        # actual line content -- matching against the stripped text must
        # never see them.
        search_input.value = "green"
        await pilot.pause()
        assert modal._match_lines == []

        search_input.value = "create"  # case-insensitive, matches "CREATE"
        await pilot.pause()
        assert modal._match_lines == [0]


@pytest.mark.asyncio
async def test_next_and_prev_match_navigate_with_wraparound() -> None:
    diff_text = "target one\nno match here\ntarget two\ntarget three"
    app = _ZoomHarness(diff_text=diff_text, title="t")
    async with app.run_test() as pilot:
        await pilot.pause()
        modal = app.screen

        modal.action_start_search()
        await pilot.pause()
        search_input = modal.query_one("#zoom-search-input", Input)
        search_input.value = "target"
        await pilot.pause()

        assert modal._match_lines == [0, 2, 3]
        assert modal._match_cursor == 0

        modal.action_next_match()
        assert modal._match_cursor == 1
        modal.action_next_match()
        assert modal._match_cursor == 2
        modal.action_next_match()  # wraps back to the first match
        assert modal._match_cursor == 0

        modal.action_prev_match()  # wraps backward past the start
        assert modal._match_cursor == 2


@pytest.mark.asyncio
async def test_no_matches_next_match_notifies_without_crashing(monkeypatch) -> None:
    diff_text = "alpha\nbeta\ngamma"
    app = _ZoomHarness(diff_text=diff_text, title="t")
    async with app.run_test() as pilot:
        await pilot.pause()
        modal = app.screen

        modal.action_start_search()
        await pilot.pause()
        modal.query_one("#zoom-search-input", Input).value = "nonexistent"
        await pilot.pause()
        assert modal._match_lines == []

        calls: list[tuple[str, str]] = []
        monkeypatch.setattr(
            app,
            "notify",
            lambda message, **kw: calls.append((message, kw.get("severity"))),
        )

        modal.action_next_match()  # must not raise

        assert calls
        assert calls[-1][1] == "warning"


@pytest.mark.asyncio
async def test_escape_exits_search_mode_before_closing_the_modal() -> None:
    app = _ZoomHarness(diff_text="line one\nline two", title="t")
    async with app.run_test() as pilot:
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, DiffZoomModal)

        modal.action_start_search()
        await pilot.pause()
        search_input = modal.query_one("#zoom-search-input", Input)
        search_input.focus()
        await pilot.pause()
        assert search_input.display is True
        assert search_input.has_focus

        # First Escape: exit search mode only -- modal must stay open.
        await pilot.press("escape")
        await pilot.pause()

        assert search_input.display is False
        assert app.screen is modal

        # Second Escape (search no longer focused): now actually closes it.
        await pilot.press("escape")
        await pilot.pause()

        assert not isinstance(app.screen, DiffZoomModal)


@pytest.mark.asyncio
async def test_export_writes_the_full_untruncated_markup_stripped_diff() -> None:
    lines = [f"[green]line {i}[/green]" for i in range(300)]
    diff_text = "\n".join(lines)
    app = _ZoomHarness(diff_text=diff_text, title="t")
    async with app.run_test() as pilot:
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, DiffZoomModal)

        modal.action_export()
        await pilot.pause()

        path = modal._exported_path
        assert path is not None
        assert path.exists()
        try:
            content = path.read_text(encoding="utf-8")
            assert content == modal._plain  # exactly the full stripped text
            assert "[green]" not in content
            assert "[/green]" not in content
            assert "line 0" in content
            assert "line 299" in content  # nothing truncated off the end
            assert content.count("\n") == 299
        finally:
            path.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_export_failure_notifies_error_and_leaves_modal_open(monkeypatch) -> None:
    app = _ZoomHarness(diff_text="line one\nline two", title="t")
    async with app.run_test() as pilot:
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, DiffZoomModal)

        calls: list[tuple[str, str]] = []
        monkeypatch.setattr(
            app,
            "notify",
            lambda message, **kw: calls.append((message, kw.get("severity"))),
        )

        def _raise() -> None:
            raise OSError("disk full")

        monkeypatch.setattr(modal, "_write_export_file", _raise)

        modal.action_export()
        await pilot.pause()

        assert modal._exported_path is None
        assert calls, "expected an error notification"
        message, severity = calls[-1]
        assert severity == "error"
        assert "disk full" in message
        # Failure must not dismiss the modal.
        assert app.screen is modal
