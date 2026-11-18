"""Unit tests for core/watchlist_store.py (the Files lens watchlist on disk).

Covers the module's contract: ★ membership per package in the user config
directory (readable JSON, corruption-safe), and pulled versions in the
session results folder (``files/<package>/<app path>/vNNN_HH-MM-SS/`` with
the copy, ``diff.txt`` and ``acquisition.json``; never pruned), plus the
storage API the Inspector reads (version_dirs/time/diff/record/file).

The autouse conftest fixture points both directories at the test's tmp_path
(``SDROID_WATCHLIST_DIR``, ``SDROID_FILES_DIR``).
"""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from sandroid.core import watchlist_store


@pytest.fixture(autouse=True)
def _isolated_results_path(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    return tmp_path


class TestLayout:
    def test_app_paths_keep_their_package_and_relative_path(self):
        assert watchlist_store.owner_and_relative(
            "/data/user/0/com.app/databases/app.db"
        ) == ("com.app", "databases/app.db")
        assert watchlist_store.owner_and_relative("/data/user_de/0/com.app/x") == (
            "com.app",
            "@de/x",
        )
        assert watchlist_store.owner_and_relative(
            "/sdcard/Android/data/com.app/files/a.txt"
        ) == ("com.app", "@ext/files/a.txt")
        assert watchlist_store.owner_and_relative("/data/local/tmp/drop.bin") == (
            "_device",
            "data/local/tmp/drop.bin",
        )

    def test_row_dir_is_under_files_package_and_app_path(self, tmp_path):
        directory = watchlist_store.row_dir("/data/data/com.app/databases/app.db")
        root = watchlist_store.files_root()
        assert directory == root / "com.app" / "databases" / "app.db"
        assert directory.is_dir()
        device = watchlist_store.row_dir("/data/local/tmp/drop.bin")
        assert device == root / "_device" / "data" / "local" / "tmp" / "drop.bin"

    def test_dot_dot_components_cannot_climb_out(self):
        directory = watchlist_store.row_dir("/data/data/com.app/files/../../x")
        root = watchlist_store.files_root()
        assert root in directory.parents

    def test_files_root_is_the_session_results_folder(self, tmp_path, monkeypatch):
        monkeypatch.delenv(watchlist_store.FILES_DIR_ENV, raising=False)
        session = tmp_path / "results" / "20261118_101500" / "Emu_A"
        monkeypatch.setenv("RESULTS_PATH", str(session))

        class _Init:
            @staticmethod
            def get_device_path():
                return None

        from sandroid import services

        monkeypatch.setattr(services, "get_initialization_service", lambda: _Init)
        assert watchlist_store.files_root() == session / "files"

        class _Session:
            @staticmethod
            def get_device_path():
                return tmp_path / "session_dev"

        # A Play pins RESULTS_PATH to its bundle; the session folder wins.
        monkeypatch.setattr(services, "get_initialization_service", lambda: _Session)
        assert watchlist_store.files_root() == tmp_path / "session_dev" / "files"


class TestMembershipPersistence:
    def test_save_then_load_round_trip(self):
        paths = ["/data/data/com.app/a.db", "/data/data/com.app/b.xml"]
        watchlist_store.save_membership(paths)
        assert watchlist_store.load_membership() == paths

    def test_one_readable_file_per_package(self):
        watchlist_store.save_membership(
            ["/data/data/com.app/a.db", "/data/local/tmp/x"],
            patterns=["/data/data/com.app/shared_prefs/*"],
        )
        data = json.loads(
            watchlist_store.membership_file("com.app").read_text(encoding="utf-8")
        )
        assert data == {
            "schema_version": watchlist_store.SCHEMA_VERSION,
            "package": "com.app",
            "paths": ["/data/data/com.app/a.db"],
            "patterns": ["/data/data/com.app/shared_prefs/*"],
        }
        device = json.loads(
            watchlist_store.membership_file("_device").read_text(encoding="utf-8")
        )
        assert device["paths"] == ["/data/local/tmp/x"]
        assert watchlist_store.load_patterns() == ["/data/data/com.app/shared_prefs/*"]

    def test_load_missing_returns_empty_list(self):
        assert watchlist_store.load_membership() == []
        assert watchlist_store.load_patterns() == []

    def test_load_corrupt_file_is_skipped_with_a_warning(self, caplog):
        watchlist_store.save_membership(["/data/data/com.ok/a.db"])
        bad = watchlist_store.watchlist_dir() / "com.bad.json"
        bad.write_text("{ not valid json", encoding="utf-8")
        with caplog.at_level("WARNING"):
            loaded = watchlist_store.load_membership()
        assert loaded == ["/data/data/com.ok/a.db"]
        assert any("com.bad.json unreadable" in msg for msg in caplog.messages)

    def test_unwatching_the_last_path_of_a_package_empties_its_file(self):
        watchlist_store.save_membership(["/data/data/com.a/x", "/data/data/com.b/y"])
        watchlist_store.save_membership(["/data/data/com.b/y"])
        assert watchlist_store.load_membership() == ["/data/data/com.b/y"]
        data = json.loads(
            watchlist_store.membership_file("com.a").read_text(encoding="utf-8")
        )
        assert data["paths"] == []

    def test_no_leftover_temp_files_after_save(self):
        watchlist_store.save_membership(["/data/data/com.app/a"])
        assert list(watchlist_store.watchlist_dir().glob(".*.tmp-*")) == []

    def test_default_dir_is_per_user_not_per_session(self, tmp_path, monkeypatch):
        monkeypatch.delenv(watchlist_store.WATCHLIST_DIR_ENV, raising=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
        watchlist_store.save_membership(["/data/data/com.app/a.db"])
        assert watchlist_store.watchlist_dir() == tmp_path / "cfg" / "sandroid" / (
            "watchlists"
        )
        assert (tmp_path / "cfg" / "sandroid" / "watchlists" / "com.app.json").exists()
        # A new session (another results folder) loads the same watches.
        monkeypatch.setenv("RESULTS_PATH", str(tmp_path / "other_session"))
        assert watchlist_store.load_membership() == ["/data/data/com.app/a.db"]

    def test_the_old_per_device_store_is_ignored(self, tmp_path):
        old = watchlist_store.watchlist_dir() / "Emu_A"
        old.mkdir()
        (old / "index.json").write_text(
            json.dumps({"paths": ["/data/data/com.old/x"]}), encoding="utf-8"
        )
        assert watchlist_store.load_membership() == []
        assert (old / "index.json").exists()  # not migrated, not deleted

    def test_override_env_vars_are_not_sandroid_config_variables(self):
        assert not watchlist_store.WATCHLIST_DIR_ENV.startswith("SANDROID_")
        assert not watchlist_store.FILES_DIR_ENV.startswith("SANDROID_")


class TestVersions:
    PATH = "/data/data/com.app/shared_prefs/p.xml"

    def _pull(self, text, diff=None, record=None, when=None):
        current = watchlist_store.reset_current(self.PATH)
        (current / "p.xml").write_text(text, encoding="utf-8")
        return watchlist_store.promote(self.PATH, diff, record, when=when)

    def test_has_baseline_false_before_any_pull(self):
        assert watchlist_store.has_baseline(self.PATH) is False
        assert watchlist_store.version_dirs(self.PATH) == []

    def test_reset_current_clears_stale_leftovers(self):
        current = watchlist_store.reset_current(self.PATH)
        (current / "p.xml").write_text("stale", encoding="utf-8")
        assert list(watchlist_store.reset_current(self.PATH).iterdir()) == []

    def test_each_pull_is_a_numbered_version_with_its_diff_and_record(self):
        t1 = datetime(2026, 11, 18, 10, 42, 7)
        v1 = self._pull("one", record={"trigger": "manual"}, when=t1)
        v2 = self._pull("two", diff="\t[UPDATED] /map text: one → two\n")
        assert v1.name == "v001_10-42-07"
        assert v2.name.startswith("v002_")
        assert watchlist_store.version_dirs(self.PATH) == [v1, v2]
        assert (v1 / "p.xml").read_text(encoding="utf-8") == "one"
        assert watchlist_store.version_diff(v1) is None  # first: nothing before
        assert "one → two" in watchlist_store.version_diff(v2)
        assert watchlist_store.version_record(v1) == {
            "trigger": "manual",
            "version": "v001_10-42-07",
        }
        assert watchlist_store.version_record(v2) is None
        assert watchlist_store.version_file(v2, self.PATH) == v2 / "p.xml"
        assert watchlist_store.previous_dir(self.PATH) == v2
        # The staging folder is gone; only versions remain.
        assert sorted(d.name for d in v1.parent.iterdir()) == [v1.name, v2.name]

    def test_version_time_prefers_the_record(self):
        v1 = self._pull("one", record={"pulled_at": "2026-11-18T10:42:07"})
        assert watchlist_store.version_time(v1) == datetime(2026, 11, 18, 10, 42, 7)
        v2 = self._pull("two", when=datetime(2026, 11, 18, 11, 0, 5))
        when = watchlist_store.version_time(v2)
        assert (when.hour, when.minute, when.second) == (11, 0, 5)

    def test_nothing_is_ever_pruned(self):
        made = [self._pull(f"v{i}", diff="") for i in range(12)]
        assert watchlist_store.version_dirs(self.PATH) == made
        assert made[-1].name.startswith("v012_")

    def test_version_numbers_sort_numerically_past_999(self):
        root = watchlist_store.row_dir(self.PATH)
        (root / "v999_10-00-00").mkdir()
        newer = self._pull("x")
        assert newer.name.startswith("v1000_")
        assert watchlist_store.version_dirs(self.PATH)[-1] == newer
