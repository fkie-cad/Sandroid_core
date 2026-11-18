"""Headless Textual Pilot tests for the watchlist engine (WatchlistView).

``WatchlistView`` is the non-visual watchlist behind the Files lens (the
table/keys live in ``files_panel.py``, tested in test_files_lens.py); these
tests drive its public API directly.

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
from datetime import datetime
from pathlib import Path

import pytest
from textual.app import App, ComposeResult

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
def _no_device_hash(monkeypatch):
    """The pre-pull on-device stat/sha256sum is an adb call: no device here."""
    monkeypatch.setattr(WatchlistView, "_device_facts", staticmethod(lambda p: {}))


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
    """Minimal single-widget host app for the watchlist engine."""

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

        assert view.summary() == ""
        assert view.rows == {}


@pytest.mark.asyncio
async def test_mount_lists_existing_spotlight_files() -> None:
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()

        assert view.summary() == "1 watched"
        assert list(view.rows) == [PATH_A]
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
async def test_a_pull_writes_a_readable_acquisition_record(monkeypatch) -> None:
    """Every version carries acquisition.json: device path, the on-device
    mtime/size/sha256 taken BEFORE the pull, the local sha256 after it, the
    host pull time and the trigger.
    """
    import hashlib
    import json

    monkeypatch.setattr(
        FileExtractionService, "pull_file", _fake_pull_file({PATH_A: "line one\n"})
    )
    digest = hashlib.sha256(b"line one\n").hexdigest()
    seen: list[list[str]] = []

    def _facts(paths):
        seen.append(list(paths))
        return {PATH_A: {"mtime": 1763458927, "size": 9, "sha256": digest}}

    monkeypatch.setattr(WatchlistView, "_device_facts", staticmethod(_facts))
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        view.pull([PATH_A])
        await _wait_for(
            pilot, lambda: view._rows[PATH_A].state != RowState.NEVER_PULLED
        )
        assert seen == [[PATH_A, f"{PATH_A}-wal", f"{PATH_A}-journal"]]
        (version,) = watchlist_store.version_dirs(PATH_A)
        assert version.parent == watchlist_store.files_root() / "com.app" / "config_a"
        assert version.name.startswith("v001_")
        record = json.loads((version / "acquisition.json").read_text())
        assert record["device_path"] == PATH_A
        assert record["device"]["mtime"] == 1763458927
        assert record["device"]["size"] == 9
        assert record["device"]["sha256"] == digest
        assert record["local"] == {"file": "config_a", "size": 9, "sha256": digest}
        assert record["sha256_match"] is True
        assert record["trigger"] == "manual"
        assert record["version"] == version.name
        assert datetime.fromisoformat(record["pulled_at"])
        assert view._rows[PATH_A].version == version.name


@pytest.mark.asyncio
async def test_summary_does_not_pluralize_changed() -> None:
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

        fragment = view.summary()
        assert "2 changed" in fragment
        assert "changeds" not in fragment


@pytest.mark.asyncio
async def test_add_path_persists_and_updates_rows() -> None:
    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()

        assert view.add_path(PATH_A) is True
        await pilot.pause()

        assert PATH_A in get_forensic_service().get_spotlight_files()
        assert watchlist_store.load_membership() == [PATH_A]
        assert list(view.rows) == [PATH_A]
        assert view.is_watched(PATH_A)


@pytest.mark.asyncio
async def test_adding_a_watched_path_again_is_rejected() -> None:
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        assert view.add_path(PATH_A) is False


@pytest.mark.asyncio
async def test_unwatch_removes_from_service_and_rows() -> None:
    get_forensic_service().add_spotlight_file(PATH_A)
    get_forensic_service().add_spotlight_file("/data/data/com.app/other")

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()

        assert view.unwatch(PATH_A) is True
        await pilot.pause()

        assert PATH_A not in get_forensic_service().get_spotlight_files()
        assert PATH_A not in watchlist_store.load_membership()
        assert list(view.rows) == ["/data/data/com.app/other"]


@pytest.mark.asyncio
async def test_pattern_watch_matches_paths_and_unwatch_drops_its_matches() -> None:
    class _Adb:
        @staticmethod
        def send_adb_command(_cmd):
            return "/data/data/com.app/db/a.db\n/data/data/com.app/db/b.db\n", ""

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        view._adb = lambda: _Adb
        await pilot.pause()

        assert view.add_path("/data/data/com.app/db/*") is True
        assert set(view.rows) == {
            "/data/data/com.app/db/a.db",
            "/data/data/com.app/db/b.db",
        }
        assert view.patterns == ["/data/data/com.app/db/*"]
        assert view.watched_by("/data/data/com.app/db/new.db") == (
            "/data/data/com.app/db/*"
        )
        assert watchlist_store.load_patterns() == ["/data/data/com.app/db/*"]

        assert view.unwatch("/data/data/com.app/db/*") is True
        assert view.rows == {}
        assert view.patterns == []


@pytest.mark.asyncio
async def test_only_membership_survives_a_restart(monkeypatch) -> None:
    """Pull facts live in the session (versions in the session results
    folder); a restart restores the ★ membership, and a row whose versions
    are in this session's folder starts as baseline-only.
    """
    monkeypatch.setattr(
        FileExtractionService, "pull_file", _fake_pull_file({PATH_A: "abc\n"})
    )
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        view.add_path("/data/data/com.app/other")
        view.pull([PATH_A])
        await _wait_for(pilot, lambda: view.rows[PATH_A].pulled_at is not None)
        row = view.rows[PATH_A]
        assert row.size == 4
        assert row.sha256 == (
            "edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb"
        )

    get_forensic_service()._spotlight_files.clear()
    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        assert set(view.rows) == {PATH_A, "/data/data/com.app/other"}
        assert view.rows[PATH_A].state is RowState.BASELINE_ONLY
        assert view.rows["/data/data/com.app/other"].state is RowState.NEVER_PULLED


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
        view.pull([PATH_A])
        await _wait_for(
            pilot, lambda: view._rows[PATH_A].state != RowState.NEVER_PULLED
        )

        assert view._rows[PATH_A].state == RowState.BASELINE_ONLY
        assert "First version" in view._rows[PATH_A].detail
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
        view.pull([PATH_A])
        await _wait_for(
            pilot, lambda: view._rows[PATH_A].state == RowState.BASELINE_ONLY
        )

        # Device-side content changes before the next pull.
        content[PATH_A] = "line one\nline two\n"
        view.pull([PATH_A])
        await _wait_for(pilot, lambda: view._rows[PATH_A].state == RowState.CHANGED)

        info = view._rows[PATH_A]
        assert info.diff_text is not None
        assert "line two" in info.diff_text
        assert "[LINE ADDED]" in info.diff_text
        # The fresh pull is the newest version, with its diff next to it.
        previous = watchlist_store.previous_dir(PATH_A)
        assert (previous / "config_a").read_text(encoding="utf-8") == content[PATH_A]
        assert "line two" in watchlist_store.version_diff(previous)
        assert len(watchlist_store.version_dirs(PATH_A)) == 2


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
        view.pull([PATH_A])
        await _wait_for(
            pilot, lambda: view._rows[PATH_A].state == RowState.BASELINE_ONLY
        )

        view.pull([PATH_A])
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
        view.pull([PATH_A])
        await _wait_for(pilot, lambda: view._rows[PATH_A].state == RowState.ERROR)


@pytest.mark.asyncio
async def test_files_panel_hosts_the_watchlist_engine() -> None:
    """The Files lens owns one (hidden) watchlist engine."""

    class _FilesHarness(App):
        def compose(self) -> ComposeResult:
            yield FilesPanel(id="files-panel")

    app = _FilesHarness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()

        watchlist = panel.watchlist
        assert isinstance(watchlist, WatchlistView)
        assert watchlist.display is False
        assert watchlist.summary() == ""


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
