"""Unit tests for ForensicService's watchlist membership persistence
(save_watchlist_index/load_watchlist_index).

These are thin delegation tests: the on-disk shape itself is
core/watchlist_store.py's responsibility (see
tests/core/test_watchlist_store.py) -- this file only checks that
ForensicService wires its in-memory _spotlight_files list to that module
correctly, idempotently, and without disturbing add_spotlight_file's
existing dedup/WAL-journal filtering.
"""

from __future__ import annotations

import pytest

from sandroid.core import watchlist_store
from sandroid.services.forensic_service import ForensicService


@pytest.fixture(autouse=True)
def _isolated_results_path(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    return tmp_path


class TestSaveWatchlistIndex:
    def test_save_persists_current_spotlight_files(self):
        service = ForensicService()
        service.add_spotlight_file("/data/data/com.app/a.db")
        service.add_spotlight_file("/data/data/com.app/b.xml")

        service.save_watchlist_index()

        assert watchlist_store.load_membership() == [
            "/data/data/com.app/a.db",
            "/data/data/com.app/b.xml",
        ]

    def test_save_after_remove_reflects_removal(self):
        service = ForensicService()
        service.add_spotlight_file("/data/data/com.app/a.db")
        service.add_spotlight_file("/data/data/com.app/b.db")
        service.save_watchlist_index()

        service.remove_spotlight_file("/data/data/com.app/a.db")
        service.save_watchlist_index()

        assert watchlist_store.load_membership() == ["/data/data/com.app/b.db"]

    def test_save_forwards_patterns_and_writes_one_file_per_package(self):
        """Only membership persists: paths and patterns, grouped by package."""
        service = ForensicService()
        service.add_spotlight_file("/data/data/com.app/a.db")
        service.add_spotlight_file("/data/local/tmp/drop.bin")

        service.save_watchlist_index(patterns=["/data/data/com.other/files/*"])

        assert watchlist_store.load_patterns() == ["/data/data/com.other/files/*"]
        names = sorted(p.name for p in watchlist_store.watchlist_dir().glob("*.json"))
        assert names == ["_device.json", "com.app.json", "com.other.json"]


class TestLoadWatchlistIndex:
    def test_load_restores_membership_into_a_fresh_service(self):
        writer = ForensicService()
        writer.add_spotlight_file("/data/data/com.app/a.db")
        writer.save_watchlist_index()

        reader = ForensicService()
        assert reader.get_spotlight_files() == []

        added = reader.load_watchlist_index()

        assert added == 1
        assert reader.get_spotlight_files() == ["/data/data/com.app/a.db"]

    def test_load_is_idempotent(self):
        writer = ForensicService()
        writer.add_spotlight_file("/data/data/com.app/a.db")
        writer.save_watchlist_index()

        reader = ForensicService()
        first = reader.load_watchlist_index()
        second = reader.load_watchlist_index()

        assert first == 1
        assert second == 0  # already tracked -- nothing new added
        assert reader.get_spotlight_files() == ["/data/data/com.app/a.db"]

    def test_load_merges_into_existing_in_memory_state(self):
        writer = ForensicService()
        writer.add_spotlight_file("/data/data/com.app/persisted.db")
        writer.save_watchlist_index()

        reader = ForensicService()
        reader.add_spotlight_file("/data/data/com.app/added_this_session.db")

        reader.load_watchlist_index()

        assert set(reader.get_spotlight_files()) == {
            "/data/data/com.app/persisted.db",
            "/data/data/com.app/added_this_session.db",
        }

    def test_load_with_no_index_file_is_a_safe_no_op(self):
        service = ForensicService()

        added = service.load_watchlist_index()

        assert added == 0
        assert service.get_spotlight_files() == []


class _ListingAdb:
    """``find`` output for a watched ``databases/*`` pattern."""

    @staticmethod
    def send_adb_command(cmd):
        base = "/data/data/com.app/databases/"
        names = ["a.db", "a.db-wal", "a.db-shm", "b.db-journal", "b.db"]
        return "\n".join(base + n for n in names) + "\n", ""


def test_pattern_skips_every_sqlite_companion_including_shm():
    """N1-B1: ``-shm`` (the WAL index) is neither watched nor pulled on
    its own, like ``-wal``/``-journal``.
    """
    service = ForensicService()
    service.add_spotlight_file("/data/data/com.app/databases/*", adb=_ListingAdb)
    assert service.get_spotlight_files() == [
        "/data/data/com.app/databases/a.db",
        "/data/data/com.app/databases/b.db",
    ]
    assert not service.add_spotlight_file("/data/data/com.app/databases/a.db-shm")
