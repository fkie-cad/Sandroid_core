"""Headless Textual Pilot smoke tests for the Watchlist sub-tab (WatchlistView).

No physical device needed: pulls are exercised by monkeypatching
FileExtractionService.pull_file (class-level, so the real
get_file_extraction_service() singleton picks it up) to write deterministic
local content instead of shelling out to adb. Membership/baseline
persistence go through the real RESULTS_PATH-isolated on-disk modules
(core/watchlist_store.py, ForensicService's watchlist index), mirroring
tests/tui/test_diffs_view.py's approach for run_history.

ForensicService's _spotlight_files is a real, process-wide singleton (like
TaskService in test_monitor_view.py), so an autouse fixture clears it before
and after every test to avoid cross-test leakage.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Input, OptionList

from sandroid.core import watchlist_store
from sandroid.services import get_forensic_service
from sandroid.services.file_extraction_service import (
    ExtractionResult,
    FileExtractionService,
)
from sandroid.tui.widgets.files_panel import FilesPanel
from sandroid.tui.widgets.watchlist_view import RowState, WatchlistView, _compute_diff


@pytest.fixture(autouse=True)
def _isolated_results_path(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    return tmp_path


@pytest.fixture(autouse=True)
def _clean_spotlight_files():
    """Guard the real ForensicService singleton against cross-test leakage."""
    svc = get_forensic_service()
    svc._spotlight_files.clear()
    yield
    svc._spotlight_files.clear()


def _fake_pull_file(content_by_remote_path: dict[str, str]):
    """Class-level FileExtractionService.pull_file replacement.

    Writes deterministic text content for known remote paths instead of
    shelling out to adb; returns a failed ExtractionResult for anything
    else (WAL/journal companions of a plain-text file, most commonly).
    """

    def _pull(self, remote_path, local_path, compute_hash=False):
        if remote_path not in content_by_remote_path:
            return ExtractionResult(
                source_path=remote_path,
                local_path=local_path,
                success=False,
                error="no such file on (fake) device",
            )
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        Path(local_path).write_text(
            content_by_remote_path[remote_path], encoding="utf-8"
        )
        return ExtractionResult(
            source_path=remote_path, local_path=local_path, success=True
        )

    return _pull


class _WatchlistHarness(App):
    """Minimal single-widget host app for WatchlistView."""

    def compose(self) -> ComposeResult:
        yield WatchlistView(id="files-watchlist")


async def _wait_for(pilot, predicate, timeout: float = 3.0) -> None:
    """Poll ``predicate`` with real pauses until true or timeout elapses.

    Pulls run on a genuine background thread (WatchlistView._run_bg), so a
    plain ``await pilot.pause()`` doesn't guarantee the worker has posted
    its result back yet -- mirrors test_diffs_view.py's identical helper.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await pilot.pause(0.02)
    assert predicate(), "condition was not met within timeout"


PATH_A = "/data/data/com.app/config_a"  # extension-less -> txt_diff_paths fallback


@pytest.mark.asyncio
async def test_empty_state_glance_and_list() -> None:
    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()

        assert view.glance_fragment() == "Watchlist — no paths"
        option_list = view.query_one("#watchlist-list", OptionList)
        assert option_list.option_count == 1  # the "no paths yet" placeholder


@pytest.mark.asyncio
async def test_mount_lists_existing_spotlight_files() -> None:
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()

        assert view.glance_fragment() == "Watchlist — 1 path(s)"
        option_list = view.query_one("#watchlist-list", OptionList)
        assert option_list.option_count == 1
        assert view._rows[PATH_A].state == RowState.NEVER_PULLED


@pytest.mark.asyncio
async def test_mount_restores_baseline_only_state_from_a_prior_session() -> None:
    """A path with an on-disk baseline from a previous TUI run (but not yet
    known to *this* process's ForensicService) should show as
    baseline-only, not never-pulled -- see WatchlistView._reload_rows.
    """
    current = watchlist_store.reset_current(PATH_A)
    (current / "config_a").write_text("v1", encoding="utf-8")
    watchlist_store.promote(PATH_A)
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()

        assert view._rows[PATH_A].state == RowState.BASELINE_ONLY


@pytest.mark.asyncio
async def test_mount_restores_full_row_state_from_a_persisted_index() -> None:
    """A restart must restore each row's REAL last-known RowState/detail/
    last_seen/last_pulled from index.json -- not just re-derive BASELINE_ONLY
    from baseline existence like the (older, membership-only) test above.
    Simulates a prior session having already persisted a CHANGED row by
    calling watchlist_store.save_membership directly (bypassing WatchlistView
    entirely), then mounting a fresh view exactly like a TUI restart would.
    """
    watchlist_store.save_membership(
        [PATH_A],
        row_states={
            PATH_A: {
                "state": "changed",
                "detail": "diffed against baseline",
                "last_seen": [1700000000, 42],
                "last_pulled": [1699999999, 41],
            }
        },
        auto_enabled=False,
    )

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()

        # Membership itself must also have come back (via load_watchlist_index).
        assert PATH_A in get_forensic_service().get_spotlight_files()

        row = view._rows[PATH_A]
        assert row.state == RowState.CHANGED
        assert row.detail == "diffed against baseline"
        assert row.last_seen == (1700000000, 42)
        assert row.last_pulled == (1699999999, 41)
        # The glance strip must reflect the restored state, not a fresh
        # "never pulled" placeholder.
        assert "1 changed" in view.glance_fragment()


@pytest.mark.asyncio
async def test_mount_restarts_auto_mode_when_persisted_as_enabled(monkeypatch) -> None:
    """If auto-mode was on when the TUI last exited, a restart must resume
    it automatically -- not silently reset to off.
    """

    class _FakeDeviceManager:
        def on_device_change(self, callback) -> None:
            pass

    def _fake_device_manager() -> _FakeDeviceManager:
        return _FakeDeviceManager()

    monkeypatch.setattr(
        WatchlistView, "_device_manager", staticmethod(_fake_device_manager)
    )
    watchlist_store.save_membership([PATH_A], auto_enabled=True)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()

        assert view._auto_enabled is True
        assert "on" in view._auto_badge()


@pytest.mark.asyncio
async def test_pull_persists_row_state_for_a_later_restart(monkeypatch) -> None:
    """A manual pull must actually persist its outcome (state/last_pulled),
    not just membership -- otherwise a restart right after pulling would
    still show NEVER_PULLED/BASELINE_ONLY instead of the real last state.
    """
    monkeypatch.setattr(
        FileExtractionService, "pull_file", _fake_pull_file({PATH_A: "line one\n"})
    )
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        option_list = view.query_one("#watchlist-list", OptionList)
        option_list.highlighted = 0

        view.action_pull_selected()
        await _wait_for(
            pilot, lambda: view._rows[PATH_A].state != RowState.NEVER_PULLED
        )

        persisted = watchlist_store.load_row_states()
        assert persisted[PATH_A]["state"] == "baseline_only"
        assert persisted[PATH_A]["last_pulled"] is None  # auto-mode never ticked


@pytest.mark.asyncio
async def test_glance_fragment_does_not_pluralize_changed() -> None:
    """'changed' is a past-participle/adjective, not a countable noun -- it
    must never grow an 's' regardless of how many rows are CHANGED (a naive
    f"{n} {word}s" pattern previously produced "2 changeds").
    """
    get_forensic_service().add_spotlight_file(PATH_A)
    get_forensic_service().add_spotlight_file("/data/data/com.app/other")

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()

        for row in view._rows.values():
            row.state = RowState.CHANGED

        fragment = view.glance_fragment()
        assert "2 changed" in fragment
        assert "changeds" not in fragment


@pytest.mark.asyncio
async def test_add_path_via_input_persists_and_updates_list() -> None:
    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()

        add_input = view.query_one("#watchlist-add-input", Input)
        add_input.focus()
        add_input.value = PATH_A
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()

        assert PATH_A in get_forensic_service().get_spotlight_files()
        assert watchlist_store.load_membership() == [PATH_A]
        assert add_input.value == ""
        option_list = view.query_one("#watchlist-list", OptionList)
        assert option_list.option_count == 1


@pytest.mark.asyncio
async def test_escape_in_add_input_clears_and_returns_focus_to_list() -> None:
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()

        add_input = view.query_one("#watchlist-add-input", Input)
        add_input.focus()
        add_input.value = "/some/typed/path"
        await pilot.pause()

        await pilot.press("escape")
        await pilot.pause()

        assert add_input.value == ""
        option_list = view.query_one("#watchlist-list", OptionList)
        assert app.focused is option_list


@pytest.mark.asyncio
async def test_remove_selected_removes_from_service_and_list() -> None:
    get_forensic_service().add_spotlight_file(PATH_A)
    get_forensic_service().add_spotlight_file("/data/data/com.app/other")

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()

        option_list = view.query_one("#watchlist-list", OptionList)
        option_list.highlighted = 0
        removed_path = view._current_path()
        assert removed_path is not None

        view.action_remove_selected()
        await pilot.pause()

        assert removed_path not in get_forensic_service().get_spotlight_files()
        assert removed_path not in watchlist_store.load_membership()
        assert option_list.option_count == 1


@pytest.mark.asyncio
async def test_first_pull_captures_baseline_not_a_diff(monkeypatch) -> None:
    monkeypatch.setattr(
        FileExtractionService, "pull_file", _fake_pull_file({PATH_A: "line one\n"})
    )
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        option_list = view.query_one("#watchlist-list", OptionList)
        option_list.highlighted = 0

        view.action_pull_selected()
        await _wait_for(
            pilot, lambda: view._rows[PATH_A].state != RowState.NEVER_PULLED
        )

        assert view._rows[PATH_A].state == RowState.BASELINE_ONLY
        assert "Baseline captured" in view._rows[PATH_A].detail
        assert watchlist_store.has_baseline(PATH_A) is True


@pytest.mark.asyncio
async def test_second_pull_with_changed_content_shows_diff(monkeypatch) -> None:
    content = {PATH_A: "line one\n"}
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull_file(content))
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        option_list = view.query_one("#watchlist-list", OptionList)
        option_list.highlighted = 0

        view.action_pull_selected()
        await _wait_for(
            pilot, lambda: view._rows[PATH_A].state == RowState.BASELINE_ONLY
        )

        # Device-side content changes before the next pull.
        content[PATH_A] = "line one\nline two\n"
        view.action_pull_selected()
        await _wait_for(pilot, lambda: view._rows[PATH_A].state == RowState.CHANGED)

        info = view._rows[PATH_A]
        assert info.diff_text is not None
        assert "line two" in info.diff_text
        assert "[LINE ADDED]" in info.diff_text
        # The fresh pull must have been promoted to the new baseline.
        previous = watchlist_store.previous_dir(PATH_A)
        assert (previous / "config_a").read_text(encoding="utf-8") == content[PATH_A]


@pytest.mark.asyncio
async def test_second_pull_with_unchanged_content_reports_unchanged(
    monkeypatch,
) -> None:
    content = {PATH_A: "same content\n"}
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull_file(content))
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        option_list = view.query_one("#watchlist-list", OptionList)
        option_list.highlighted = 0

        view.action_pull_selected()
        await _wait_for(
            pilot, lambda: view._rows[PATH_A].state == RowState.BASELINE_ONLY
        )

        view.action_pull_selected()
        await _wait_for(pilot, lambda: view._rows[PATH_A].state == RowState.UNCHANGED)

        assert "No changes" in view._rows[PATH_A].detail


@pytest.mark.asyncio
async def test_pull_failure_marks_row_as_error(monkeypatch) -> None:
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull_file({}))
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        option_list = view.query_one("#watchlist-list", OptionList)
        option_list.highlighted = 0

        view.action_pull_selected()
        await _wait_for(pilot, lambda: view._rows[PATH_A].state == RowState.ERROR)


@pytest.mark.asyncio
async def test_files_panel_mounts_real_watchlist_view_not_stub() -> None:
    """FilesPanel's inner ContentSwitcher must host the real WatchlistView
    (not the old placeholder stub) as a real sub-tab.
    """

    class _FilesHarness(App):
        def compose(self) -> ComposeResult:
            yield FilesPanel(id="files-panel")

    app = _FilesHarness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()

        watchlist = panel.query_one("#files-watchlist")
        assert isinstance(watchlist, WatchlistView)
        assert watchlist.glance_fragment() == "Watchlist — no paths"


class TestComputeDiffDispatch:
    """Unit-level coverage of _compute_diff's extension/magic-header
    dispatch, independent of the Pilot harness above.
    """

    def test_xml_extension_uses_xml_diff(self, tmp_path):
        old_path = tmp_path / "old.xml"
        new_path = tmp_path / "new.xml"
        old_path.write_text("<root><a>1</a></root>", encoding="utf-8")
        new_path.write_text("<root><a>2</a></root>", encoding="utf-8")

        diff, changed = _compute_diff(old_path, new_path)

        assert changed is True
        assert diff.strip() != ""

    def test_extensionless_file_falls_back_to_txt_diff_paths(self, tmp_path):
        old_path = tmp_path / "old_config"
        new_path = tmp_path / "new_config"
        old_path.write_text("alpha\n", encoding="utf-8")
        new_path.write_text("alpha\nbeta\n", encoding="utf-8")

        diff, changed = _compute_diff(old_path, new_path)

        assert changed is True
        assert "[LINE ADDED]" in diff
        assert "beta" in diff

    def test_identical_extensionless_files_report_unchanged(self, tmp_path):
        old_path = tmp_path / "old_config"
        new_path = tmp_path / "new_config"
        old_path.write_text("same\n", encoding="utf-8")
        new_path.write_text("same\n", encoding="utf-8")

        diff, changed = _compute_diff(old_path, new_path)

        assert changed is False
