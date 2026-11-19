"""Auto-pull on change, driven by the file monitor (one detector).

``WatchlistView.note_write`` is fed every create/modify/rename-into the
monitor reports (via the Files lens, ``FileActivity.writes``). For a ★ file
it (re)arms a per-file timer; once writes are quiet for ``AUTO_PULL_QUIET``
seconds the file is pulled (``trigger: "auto"``), versioned and diffed. A
database and its ``-wal``/``-journal`` are one group. The periodic stat-poll
auto mode (``a``) is gone: nothing polls.

The quiet period is shortened for the tests (``AUTO_PULL_QUIET``); pulls go
through a class-level ``FileExtractionService.pull_file`` fake and the
on-device ``stat``/``sha256sum`` through a ``_device_facts`` fake.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

import pytest
from pilot_helpers import settle, until
from textual.app import App, ComposeResult

from sandroid.core import watchlist_store
from sandroid.services import get_forensic_service
from sandroid.services.file_extraction_service import (
    ExtractionResult,
    FileExtractionService,
)
from sandroid.tui.widgets import watchlist_view
from sandroid.tui.widgets.watchlist_view import (
    RowState,
    WatchlistView,
    parse_device_facts,
)

DB = "/data/data/com.app/databases/app.db"
PREFS = "/data/data/com.app/shared_prefs/p.xml"
T0 = datetime(2026, 11, 18, 10, 42, 7)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    svc = get_forensic_service()
    svc._spotlight_files.clear()
    monkeypatch.setattr(watchlist_view, "AUTO_PULL_QUIET", 0.15)
    yield
    svc._spotlight_files.clear()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _fake_pull_file(content: dict[str, str], calls: list[str] | None = None):
    def _pull(self, remote_path, local_path, compute_hash=False):
        if calls is not None:
            calls.append(remote_path)
        if remote_path not in content:
            return ExtractionResult(
                source_path=remote_path,
                local_path=local_path,
                success=False,
                error="no such file on (fake) device",
            )
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        Path(local_path).write_text(content[remote_path], encoding="utf-8")
        return ExtractionResult(
            source_path=remote_path, local_path=local_path, success=True
        )

    return _pull


def _fake_device_facts(content: dict[str, str]):
    def _facts(paths):
        return {
            p: {
                "mtime": 1763458927,
                "size": len(content[p]),
                "sha256": _sha(content[p]),
            }
            for p in paths
            if p in content
        }

    return staticmethod(_facts)


class _Harness(App):
    def compose(self) -> ComposeResult:
        yield WatchlistView(id="files-watchlist")


@pytest.mark.asyncio
async def test_a_write_to_a_watched_file_pulls_it_once_quiet(monkeypatch) -> None:
    content = {PREFS: "<map/>\n"}
    calls: list[str] = []
    monkeypatch.setattr(
        FileExtractionService, "pull_file", _fake_pull_file(content, calls)
    )
    monkeypatch.setattr(WatchlistView, "_device_facts", _fake_device_facts(content))
    get_forensic_service().add_spotlight_file(PREFS)
    app = _Harness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        # A burst of writes (no quiet period in between): each re-arms the
        # one timer, one pull after the last one.
        for _ in range(4):
            assert view.note_write(PREFS, T0)
        assert view.pending_auto == [PREFS]
        assert view.rows[PREFS].state is RowState.SETTLING
        assert calls == []
        await until(pilot, lambda: view.rows[PREFS].state is RowState.BASELINE_ONLY)
        assert calls == [PREFS]
        (version,) = watchlist_store.version_dirs(PREFS)
        record = watchlist_store.version_record(version)
        assert record["trigger"] == "auto"
        assert record["trigger_event_at"] == watchlist_store.iso_tz(T0)
        assert record["trigger_event_at"].startswith("2026-11-18T10:42:07")
        assert record["device"]["sha256"] == _sha("<map/>\n")
        assert record["local"]["sha256"] == _sha("<map/>\n")
        assert record["sha256_match"] is True
        assert record["device_path"] == PREFS
        assert record["package"] == "com.app"
        assert view.pending_auto == []

        # The next change is diffed against the first version.
        content[PREFS] = '<map><string name="k">v</string></map>\n'
        view.note_write(PREFS, T0)
        await until(pilot, lambda: view.rows[PREFS].state is RowState.CHANGED)
        newest = watchlist_store.version_dirs(PREFS)[-1]
        assert newest.name.startswith("v002_")
        assert "k" in (watchlist_store.version_diff(newest) or "")


@pytest.mark.asyncio
async def test_wal_and_journal_writes_pull_the_database_group(monkeypatch) -> None:
    content = {DB: "SQLite format 3\x00 fake", f"{DB}-wal": "wal bytes"}
    calls: list[str] = []
    monkeypatch.setattr(
        FileExtractionService, "pull_file", _fake_pull_file(content, calls)
    )
    monkeypatch.setattr(WatchlistView, "_device_facts", _fake_device_facts(content))
    get_forensic_service().add_spotlight_file(DB)
    app = _Harness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        assert view.note_write(f"{DB}-wal", T0)
        assert view.note_write(f"{DB}-journal", T0)
        assert view.pending_auto == [DB]
        await until(pilot, lambda: view.rows[DB].state is RowState.BASELINE_ONLY)
        assert calls == [DB, f"{DB}-wal", f"{DB}-journal"]
        (version,) = watchlist_store.version_dirs(DB)
        assert sorted(p.name for p in version.iterdir()) == [
            "acquisition.json",
            "app.db",
            "app.db-wal",
        ]
        record = json.loads((version / "acquisition.json").read_text())
        assert [c["device_path"] for c in record["companions"]] == [f"{DB}-wal"]
        assert record["companions"][0]["device"]["sha256"] == _sha("wal bytes")


@pytest.mark.asyncio
async def test_unwatched_paths_are_ignored_and_patterns_adopt_new_files(
    monkeypatch,
) -> None:
    new_file = "/data/data/com.app/files/new.json"
    content = {new_file: "{}"}
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull_file(content))
    monkeypatch.setattr(WatchlistView, "_device_facts", _fake_device_facts(content))
    app = _Harness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        assert view.note_write("/data/data/com.app/files/other", T0) is False
        view._watched_patterns.add("/data/data/com.app/files/*")
        assert view.note_write(new_file, T0) is True
        assert new_file in get_forensic_service().get_spotlight_files()
        assert watchlist_store.load_membership() == [new_file]
        await until(pilot, lambda: view.rows[new_file].state is RowState.BASELINE_ONLY)


@pytest.mark.asyncio
async def test_the_setting_turns_auto_pull_off(monkeypatch) -> None:
    get_forensic_service().add_spotlight_file(PREFS)
    monkeypatch.setattr(
        WatchlistView, "_auto_pull_enabled", staticmethod(lambda: False)
    )
    app = _Harness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        assert view.note_write(PREFS, T0) is False
        assert view.pending_auto == []
        assert view.rows[PREFS].state is RowState.NEVER_PULLED


def test_auto_pull_on_change_defaults_on() -> None:
    from sandroid.config.schema import TUIConfig

    assert TUIConfig().auto_pull_on_change is True
    assert "watchlist_max_versions" not in TUIConfig.model_fields


@pytest.mark.asyncio
async def test_a_manual_pull_cancels_the_pending_auto_pull(monkeypatch) -> None:
    content = {PREFS: "x"}
    calls: list[str] = []
    monkeypatch.setattr(
        FileExtractionService, "pull_file", _fake_pull_file(content, calls)
    )
    monkeypatch.setattr(WatchlistView, "_device_facts", _fake_device_facts(content))
    get_forensic_service().add_spotlight_file(PREFS)
    app = _Harness()
    async with app.run_test() as pilot:
        view = app.query_one(WatchlistView)
        await pilot.pause()
        view.note_write(PREFS, T0)
        view.pull([PREFS])
        assert view.pending_auto == []  # the manual pull disarmed the auto one
        await until(pilot, lambda: view.rows[PREFS].state is RowState.BASELINE_ONLY)
        await settle(pilot)
        assert view.pending_auto == []
        assert calls == [PREFS]  # no second (auto) pull
        record = watchlist_store.version_record(watchlist_store.version_dirs(PREFS)[0])
        assert record["trigger"] == "manual"
        assert record["trigger_event_at"] is None


def test_there_is_no_polling_auto_mode_any_more() -> None:
    for name in ("toggle_auto", "_auto_tick", "_stat_command", "auto_enabled"):
        assert not hasattr(WatchlistView, name)


def test_parse_device_facts_reads_stat_and_sha256sum() -> None:
    digest = "a" * 64
    out = (
        "1763458927 4096 /data/data/com.app/databases/app.db\n"
        "1763458930 12 /data/data/com.app/files/a b.txt\n"
        f"{digest}  /data/data/com.app/databases/app.db\n"
        "garbage line\n"
    )
    facts = parse_device_facts(out)
    assert facts["/data/data/com.app/databases/app.db"] == {
        "mtime": 1763458927,
        "size": 4096,
        "sha256": digest,
    }
    assert facts["/data/data/com.app/files/a b.txt"] == {
        "mtime": 1763458930,
        "size": 12,
    }


def test_reexpansion_of_known_matches_adds_nothing_and_logs_quietly(caplog):
    """Re-expanding a pattern whose matches are all watched is a quiet no-op."""
    import logging

    class _FakeExpandAdb:
        def __init__(self, matches: list[str]):
            self.matches = list(matches)

        def send_adb_command(self, cmd: str) -> tuple[str, str]:
            return "\n".join(self.matches), ""

    svc = get_forensic_service()
    adb = _FakeExpandAdb(["/data/data/com.app/files/a", "/data/data/com.app/files/b"])
    assert svc.add_spotlight_file("/data/data/com.app/files/*", adb=adb) is True
    caplog.clear()
    with caplog.at_level(logging.INFO):
        assert svc.add_spotlight_file("/data/data/com.app/files/*", adb=adb) is False
    assert not [r for r in caplog.records if "already in spotlight" in r.message]
    adb.matches.append("/data/data/com.app/files/c")
    assert svc.add_spotlight_file("/data/data/com.app/files/*", adb=adb) is True
    assert len(svc.get_spotlight_files()) == 3
