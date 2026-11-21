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

import threading
from datetime import datetime
from pathlib import Path

import pytest
from pilot_helpers import until
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
    """The pre-pull on-device stat/sha256sum is an adb call: no device here.
    Neither for the first-version pull ``add_path`` starts (a test that needs
    content patches its own fake ``pull_file`` over this one).
    """
    monkeypatch.setattr(WatchlistView, "_device_facts", staticmethod(lambda p: {}))
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull_file({}))


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
        await until(pilot, lambda: view._rows[PATH_A].state != RowState.NEVER_PULLED)
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


def _facts_for(content: dict[str, str]):
    """``_device_facts`` fake: mtime/size/sha256 of the fake device files."""
    import hashlib

    def _facts(paths):
        return {
            p: {
                "mtime": 1795001590 + i,
                "size": len(content[p].encode()),
                "sha256": hashlib.sha256(content[p].encode()).hexdigest(),
            }
            for i, p in enumerate(paths)
            if p in content
        }

    return staticmethod(_facts)


@pytest.mark.asyncio
async def test_w_pulls_a_first_version_right_away(monkeypatch) -> None:
    """Watching captures a baseline, so the first change can be diffed."""
    content = {PATH_A: "v1\n"}
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull_file(content))
    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        assert view.add_path(PATH_A) is True
        await until(pilot, lambda: view.rows[PATH_A].state is RowState.BASELINE_ONLY)
        (first,) = watchlist_store.version_dirs(PATH_A)
        assert first.name.startswith("v001_")
        assert watchlist_store.version_record(first)["trigger"] == "watch"

        content[PATH_A] = "v1\nv2\n"
        view.pull([PATH_A])
        await until(pilot, lambda: view.rows[PATH_A].state is RowState.CHANGED)
        newest = watchlist_store.version_dirs(PATH_A)[-1]
        assert "+v2" in watchlist_store.version_diff(newest)


@pytest.mark.asyncio
async def test_a_pattern_pulls_first_versions_of_its_matches(monkeypatch) -> None:
    a, b = "/data/data/com.app/db/a.txt", "/data/data/com.app/db/b.txt"

    class _Adb:
        @staticmethod
        def send_adb_command(_cmd):
            return f"{a}\n{b}\n", ""

    monkeypatch.setattr(
        FileExtractionService, "pull_file", _fake_pull_file({a: "a\n", b: "b\n"})
    )
    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        view._adb = lambda: _Adb
        await pilot.pause()
        assert view.add_path("/data/data/com.app/db/*") is True
        await until(
            pilot,
            lambda: all(view.rows[p].state is RowState.BASELINE_ONLY for p in (a, b)),
        )
        for p in (a, b):
            (version,) = watchlist_store.version_dirs(p)
            assert watchlist_store.version_record(version)["trigger"] == "watch"


@pytest.mark.asyncio
async def test_unchanged_device_hashes_are_a_check_not_a_copy(monkeypatch) -> None:
    """Same on-device sha256 for the file AND its -wal: nothing is pulled,
    one checks.jsonl line is written, version numbers stay put. A change in
    the -wal alone is a new version. Each record names the active mark.
    """
    from sandroid.tui.widgets.lens_shell import Mark

    db = "/data/data/com.app/databases/app.db"
    content = {db: "main\n", f"{db}-wal": "wal one\n"}
    calls: list[str] = []
    fake = _fake_pull_file(content)

    def _pull(self, remote_path, local_path, compute_hash=False):
        calls.append(remote_path)
        return fake(self, remote_path, local_path, compute_hash)

    monkeypatch.setattr(FileExtractionService, "pull_file", _pull)
    monkeypatch.setattr(WatchlistView, "_device_facts", _facts_for(content))
    get_forensic_service().add_spotlight_file(db)
    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        view.marks = [Mark(1, datetime(2026, 1, 1, 10, 0, 0), "tap login")]
        view.pull([db])
        await until(pilot, lambda: view.rows[db].state is RowState.BASELINE_ONLY)
        (v1,) = watchlist_store.version_dirs(db)
        record = watchlist_store.version_record(v1)
        file_set = record["set"]
        assert record["schema_version"] == 2
        assert file_set["members"] == ["app.db", "app.db-wal"]
        assert file_set["match"] is True
        assert record["sha256_match"] is True
        assert file_set["device_sha256"] == file_set["local_sha256"]
        assert file_set["newest_member"] == "app.db-wal"
        assert datetime.fromisoformat(file_set["newest_mtime_iso"]).tzinfo is not None
        assert record["companions"][0]["sha256_match"] is True
        assert record["mark"]["number"] == 1
        assert record["mark"]["name"] == "tap login"
        assert view.rows[db].sha256 == file_set["local_sha256"]

        calls.clear()
        view.pull([db])
        await until(pilot, lambda: view.rows[db].checked_at is not None)
        assert calls == []  # not pulled again
        assert view.rows[db].state is RowState.UNCHANGED
        assert "no change since v001" in view.rows[db].detail
        assert len(watchlist_store.version_dirs(db)) == 1
        (check,) = watchlist_store.version_checks(db)
        assert check["same_as"] == "v001"
        assert check["trigger"] == "manual"
        assert check["note"] == "no change"
        assert set(check["device_sha256"]) == {"app.db", "app.db-wal"}
        assert datetime.fromisoformat(check["at"]).utcoffset() is not None
        assert check["mark"]["name"] == "tap login"

        content[f"{db}-wal"] = "wal two\n"  # a WAL-only write
        view.pull([db])
        await until(pilot, lambda: len(watchlist_store.version_dirs(db)) == 2)
        assert watchlist_store.version_dirs(db)[-1].name.startswith("v002_")


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
        await until(pilot, lambda: view.rows[PATH_A].pulled_at is not None)
        row = view.rows[PATH_A]
        assert row.size == 4
        # The set hash (the file + its -wal/-journal; here the file alone).
        assert row.sha256 == watchlist_store.set_sha256(
            {
                "config_a": "edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb"
            }
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
        await until(pilot, lambda: view._rows[PATH_A].state != RowState.NEVER_PULLED)

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
        await until(pilot, lambda: view._rows[PATH_A].state == RowState.BASELINE_ONLY)

        # Device-side content changes before the next pull.
        content[PATH_A] = "line one\nline two\n"
        view.pull([PATH_A])
        await until(pilot, lambda: view._rows[PATH_A].state == RowState.CHANGED)

        info = view._rows[PATH_A]
        assert info.diff_text is not None
        assert "line two" in info.diff_text
        assert "+line two" in info.diff_text  # plain diff.txt (unified hunks)
        # The fresh pull is the newest version, with its diff next to it.
        previous = watchlist_store.previous_dir(PATH_A)
        assert (previous / "config_a").read_text(encoding="utf-8") == content[PATH_A]
        assert "line two" in watchlist_store.version_diff(previous)
        doc = watchlist_store.version_diff_doc(previous)
        assert doc["kind"] == "text"
        assert doc["changed"] is True
        assert doc["base_version"] == watchlist_store.version_dirs(PATH_A)[0].name
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
        await until(pilot, lambda: view._rows[PATH_A].state == RowState.BASELINE_ONLY)

        view.pull([PATH_A])
        await until(pilot, lambda: view._rows[PATH_A].state == RowState.UNCHANGED)

        # No device hash here (autouse fixture): the identical copy is not
        # kept as a version; one "checked, no change" record instead.
        assert "identical to v001" in view._rows[PATH_A].detail
        assert len(watchlist_store.version_dirs(PATH_A)) == 1
        (check,) = watchlist_store.version_checks(PATH_A)
        assert check["same_as"] == "v001"
        assert check["trigger"] == "manual"
        assert not (watchlist_store.row_dir(PATH_A) / ".current").exists()


@pytest.mark.asyncio
async def test_pull_failure_marks_row_as_error(monkeypatch) -> None:
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull_file({}))
    get_forensic_service().add_spotlight_file(PATH_A)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        view.pull([PATH_A])
        await until(pilot, lambda: view._rows[PATH_A].state == RowState.ERROR)


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


@pytest.mark.asyncio
async def test_two_pulls_of_one_file_at_once_run_one_after_the_other(
    monkeypatch,
) -> None:
    """Two pulls of one path used to share ``.current/``: the second cleared
    it while the first moved it to v001 ("No such file ... .current ->
    v001"). They are serialised now; the second sees the first's version.
    """
    fake = _fake_pull_file({PATH_A: "same\n"})
    active: list[int] = []
    overlap: list[int] = []
    entered: list[int] = []
    # The first pull holds on until the other one is under way: waiting for
    # the file's lock, or (without the lock) pulling alongside it.
    other_started = threading.Event()
    real_lock = watchlist_store.pull_lock

    class _Announcing:
        def __init__(self, lock) -> None:
            self._lock = lock

        def __enter__(self):
            entered.append(1)
            if len(entered) > 1:
                other_started.set()
            return self._lock.__enter__()

        def __exit__(self, *exc):
            return self._lock.__exit__(*exc)

    def _slow_pull(self, remote_path, local_path, compute_hash=False):
        active.append(1)
        if len(active) > 1:
            overlap.append(1)
            other_started.set()
        if remote_path == PATH_A and len(entered) == 1:
            assert other_started.wait(10.0), "the second pull never started"
        try:
            return fake(self, remote_path, local_path, compute_hash)
        finally:
            active.pop()

    monkeypatch.setattr(
        watchlist_store, "pull_lock", lambda path: _Announcing(real_lock(path))
    )
    monkeypatch.setattr(FileExtractionService, "pull_file", _slow_pull)
    get_forensic_service().add_spotlight_file(PATH_A)
    warnings: list[str] = []
    monkeypatch.setattr(
        "sandroid.tui.widgets.watchlist_view.logger.warning",
        lambda msg, *a, **k: warnings.append(str(msg)),
    )
    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        view.pull([PATH_A])
        view.pull([PATH_A])  # e.g. the watch's first version + a manual u
        await until(
            pilot,
            lambda: (
                not view.is_pulling(PATH_A)
                and len(watchlist_store.version_checks(PATH_A)) == 1
            ),
        )
        assert warnings == []
        assert overlap == []  # never two pulls of the file at once
        assert view.rows[PATH_A].state is not RowState.ERROR
        assert len(watchlist_store.version_dirs(PATH_A)) == 1
        (check,) = watchlist_store.version_checks(PATH_A)
        assert check["same_as"] == "v001"


@pytest.mark.asyncio
async def test_pulls_and_checks_are_session_timeline_lines(
    monkeypatch, timeline_sink
) -> None:
    """``files/pull`` points to the version's diff.json (acquisition.json
    for the first) with its sha256; ``files/check`` to checks.jsonl; a
    failed pull is a warning. The diff is never copied into the line.
    """
    import hashlib
    from types import SimpleNamespace

    from sandroid.core.adb import Adb

    service, timeline_path = timeline_sink
    folder = timeline_path.parent
    content = {PATH_A: "v1\n"}
    # The pulls talk to the bound device: every line names it in ``dev``.
    monkeypatch.setattr(Adb, "_target_device", "emulator-test")
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull_file(content))
    monkeypatch.setattr(watchlist_store, "files_root", lambda: folder / "files")
    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        view.marks = [
            SimpleNamespace(
                number=3, name="login", kind="start", seq=17,
                when=datetime(2026, 1, 1, 10, 0, 0),
            )
        ]  # fmt: skip
        assert view.add_path(PATH_A) is True
        await until(pilot, lambda: view.rows[PATH_A].state is RowState.BASELINE_ONLY)
        content[PATH_A] = "v1\nv2\n"
        view.pull([PATH_A])
        await until(pilot, lambda: view.rows[PATH_A].state is RowState.CHANGED)
        view.pull([PATH_A])  # the same bytes again: a check
        await until(pilot, lambda: view.rows[PATH_A].checked_at is not None)
        del content[PATH_A]
        view.pull([PATH_A])
        await until(pilot, lambda: view.rows[PATH_A].state is RowState.ERROR)
    assert service.flush(3.0)
    lines = [x for x in service.tail().lines if x["src"] == "files"]
    first, second, check, failed = lines
    v1, v2 = watchlist_store.version_dirs(PATH_A)
    assert (first["kind"], first["actor"]) == ("pull", "sandroid")
    assert first["data"]["trigger"] == "watch"
    assert first["data"]["changed"] is None
    assert first["ref"]["path"] == f"files/com.app/config_a/{v1.name}/acquisition.json"
    assert first["summary"] == "pulled v001 config_a (first version)"
    assert (second["kind"], second["actor"]) == ("pull", "user")
    assert second["data"]["changed"] is True
    assert second["data"]["version"] == v2.name
    assert second["data"]["ok"] is True
    assert second["data"]["size"] == len(b"v1\nv2\n")
    assert second["data"]["sha256"] == hashlib.sha256(b"v1\nv2\n").hexdigest()
    diff = v2 / "diff.json"
    assert second["ref"] == {
        "path": f"files/com.app/config_a/{v2.name}/diff.json",
        "sha256": hashlib.sha256(diff.read_bytes()).hexdigest(),
        "lens": "files",
    }
    assert "diff" not in second["data"]
    assert second["summary"] == "pulled v002 config_a (changed)"
    assert second["pkg"] == "com.app"
    assert check["kind"] == "check"
    assert check["data"]["same_as"] == "v002"
    assert check["ref"]["path"] == "files/com.app/config_a/checks.jsonl"
    assert (failed["kind"], failed["level"]) == ("pull", "warn")
    assert failed["data"]["ok"] is False
    assert failed["data"]["error"]
    assert {x["dev"] for x in lines} == {"emulator-test"}
    # The acquisition record names the active label with its kind and seq.
    record = watchlist_store.version_record(v2)
    assert record["mark"]["number"] == 3
    assert record["mark"]["kind"] == "start"
    assert record["mark"]["seq"] == 17


def test_pull_and_check_lines_name_the_pulled_device(monkeypatch) -> None:
    """``files/pull`` and ``files/check`` carry ``dev`` (the adb target the
    pull talked to), so they never fall into another device's timeline.
    """
    from sandroid.core import timeline
    from sandroid.core.adb import Adb
    from sandroid.tui.widgets import watchlist_view

    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    with timeline.capture() as lines:
        watchlist_view.timeline_pull(PATH_A, "manual", ok=False, error="boom")
        watchlist_view.timeline_check(PATH_A, "manual", "v001", "no change")
    assert [(x["kind"], x["dev"]) for x in lines] == [
        ("pull", "emulator-5556"),
        ("check", "emulator-5556"),
    ]


@pytest.mark.asyncio
async def test_u_with_no_change_toasts_and_a_failed_pull_leaves_no_folder(
    monkeypatch,
) -> None:
    """N1-B9: a manual pull of one file that found no change said nothing
    (only the Inspector knew); a failed pull of a missing file left an
    empty ``.current/`` behind.
    """
    monkeypatch.setattr(
        FileExtractionService, "pull_file", _fake_pull_file({PATH_A: "same\n"})
    )
    missing = "/data/data/com.app/gone.xml"
    get_forensic_service().add_spotlight_file(PATH_A)
    get_forensic_service().add_spotlight_file(missing)

    app = _WatchlistHarness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        notes: list[str] = []
        monkeypatch.setattr(app, "notify", lambda msg, **kw: notes.append(msg))
        view.pull([PATH_A])
        await until(pilot, lambda: view._rows[PATH_A].state != RowState.NEVER_PULLED)
        (first,) = watchlist_store.version_dirs(PATH_A)
        view.pull([PATH_A])  # the pulled copy is identical: nothing kept
        await until(pilot, lambda: any("no change" in n for n in notes))
        assert f"config_a: no change since {first.name.split('_')[0]}" in notes
        view.pull([missing])
        await until(pilot, lambda: view._rows[missing].state == RowState.ERROR)
        # (row_dir() itself creates the folder: nothing may be inside.)
        assert list(watchlist_store.row_dir(missing).iterdir()) == []
