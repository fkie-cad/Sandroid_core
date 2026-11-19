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


# ---------------------------------------------------------------------------
# diff.json / diff.txt, the file set, checks, marks and the timeline
# ---------------------------------------------------------------------------


def _offset(stamp: str) -> bool:
    """An ISO 8601 timestamp that carries its UTC offset."""
    return datetime.fromisoformat(stamp).utcoffset() is not None


class TestEvidenceRecords:
    PATH = "/data/data/org.mozilla.firefox/files/places.sqlite"

    def _stage(self, version: int, wal: bool = False):
        import shutil

        from file_inspect_samples import make_places

        staging = watchlist_store.reset_current(self.PATH)
        src = make_places(
            staging.parent / f"src{version}" / "places.sqlite", version, wal
        )
        for suffix in ("", "-wal"):
            if (src.parent / f"places.sqlite{suffix}").exists():
                shutil.copyfile(
                    src.parent / f"places.sqlite{suffix}",
                    staging / f"places.sqlite{suffix}",
                )
        shutil.rmtree(src.parent)
        return staging

    def test_iso_tz_always_carries_the_offset(self):
        assert _offset(watchlist_store.iso_tz())
        assert _offset(watchlist_store.iso_tz(datetime(2026, 11, 18, 12, 33, 13)))
        assert _offset(watchlist_store.iso_tz(1795001590))
        naive = watchlist_store.local_naive(
            datetime.fromisoformat(
                watchlist_store.iso_tz(datetime(2026, 1, 2, 3, 4, 5))
            )
        )
        assert naive == datetime(2026, 1, 2, 3, 4, 5)

    def test_set_hash_covers_every_member(self):
        one = watchlist_store.set_sha256({"a.db": "1" * 64})
        two = watchlist_store.set_sha256({"a.db": "1" * 64, "a.db-wal": "2" * 64})
        changed_wal = watchlist_store.set_sha256(
            {"a.db": "1" * 64, "a.db-wal": "3" * 64}
        )
        assert len({one, two, changed_wal}) == 3
        assert two == watchlist_store.set_sha256(
            {"a.db-wal": "2" * 64, "a.db": "1" * 64}
        )

    def test_record_set_reads_new_and_legacy_records(self):
        legacy = {
            "device_path": self.PATH,
            "device": {"sha256": "a" * 64},
            "local": {"file": "places.sqlite", "sha256": "a" * 64},
            "companions": [
                {
                    "device": {"sha256": "b" * 64},
                    "local": {"file": "places.sqlite-wal", "sha256": "b" * 64},
                }
            ],
        }
        expected = {"places.sqlite": "a" * 64, "places.sqlite-wal": "b" * 64}
        assert watchlist_store.record_set(legacy, "device") == expected
        assert watchlist_store.record_set(legacy, "local") == expected
        legacy["companions"][0]["device"]["sha256"] = None
        assert watchlist_store.record_set(legacy, "device") is None  # unknown
        new = {"set": {"device": expected, "local": {}}}
        assert watchlist_store.record_set(new, "device") == expected
        assert watchlist_store.record_set(new, "local") is None
        assert watchlist_store.record_set(None, "device") is None

    def test_keep_version_writes_diff_json_and_a_plain_diff_txt(self):
        self._stage(1)
        first = watchlist_store.keep_version(self.PATH)
        assert first.diff is None
        assert first.text is None
        assert watchlist_store.version_diff_doc(first.dir) is None
        assert sorted(p.name for p in first.dir.iterdir()) == ["places.sqlite"]

        self._stage(3, wal=True)
        kept = watchlist_store.keep_version(self.PATH)
        assert kept.changed
        doc = watchlist_store.version_diff_doc(kept.dir)
        assert doc["schema"] == "sandroid.file_diff"
        assert doc["schema_version"] == 1
        assert doc["engine"]["version"]
        assert doc["engine"]["sandroid"]
        assert doc["version"] == kept.dir.name
        assert doc["base_version"] == first.dir.name
        assert _offset(doc["created_at"])
        new_files = {f["file"]: f for f in doc["compared"]["new"]}
        assert set(new_files) == {"places.sqlite", "places.sqlite-wal"}
        assert new_files["places.sqlite-wal"]["role"] == "-wal"
        assert new_files["places.sqlite-wal"]["sha256"] == watchlist_store.sha256_file(
            kept.dir / "places.sqlite-wal"
        )
        assert [f["file"] for f in doc["compared"]["base"]] == ["places.sqlite"]
        tables = {t["name"]: t for t in doc["tables"]}
        visits = tables["moz_historyvisits"]
        assert visits["primary_key"] == ["id"]
        assert "visit_date" in visits["columns"]
        insert = next(r for r in visits["rows"] if r["op"] == "insert")
        assert insert["values"]["visit_date"] > 10**12
        # The WAL-only title change is in the diff (the -wal was folded in).
        places = tables["moz_places"]
        assert any(
            c["column"] == "title"
            for r in places["rows"]
            if r["op"] == "update"
            for c in r["changes"]
        )

        text = (kept.dir / "diff.txt").read_text(encoding="utf-8")
        assert text == watchlist_store.version_diff(kept.dir) == kept.text
        for tag in ("[success]", "[warning]", "[error]", "[/", "\\["):
            assert tag not in text
        assert "Table moz_historyvisits" in text
        assert "visit_date" in text  # column names
        assert "ms epoch" in text  # readable time hint next to the raw value
        hint = text.split("ms epoch")[0].rsplit("(", 1)[1]
        assert datetime.fromisoformat(hint.rstrip(", ")).utcoffset() is not None
        assert "  ->  " in text  # updates: old -> new

    def test_bytes_changed_but_not_the_content_is_explained(self):
        self._stage(1)
        watchlist_store.keep_version(self.PATH)
        staging = self._stage(1)
        # Same rows, different bytes (a free page): a version, but no change.
        (staging / "places.sqlite").write_bytes(
            (staging / "places.sqlite").read_bytes() + b"\x00" * 4096
        )
        kept = watchlist_store.keep_version(self.PATH)
        assert not kept.changed
        doc = watchlist_store.version_diff_doc(kept.dir)
        assert doc["changed"] is False
        assert "bytes changed" in doc["note"]

    def test_checks_are_appended_not_rewritten(self):
        for n in range(3):
            watchlist_store.append_check(
                self.PATH,
                {"at": watchlist_store.iso_tz(), "same_as": "v001", "n": n},
            )
        checks = watchlist_store.version_checks(self.PATH)
        assert [c["n"] for c in checks] == [0, 1, 2]
        file = watchlist_store.row_dir(self.PATH) / "checks.jsonl"
        assert len(file.read_text(encoding="utf-8").splitlines()) == 3
        # No version folder for a check.
        assert watchlist_store.version_dirs(self.PATH) == []

    def test_mark_entry_names_the_label_kind_and_seq(self):
        when = datetime(2026, 11, 18, 12, 30, 0)
        plain = watchlist_store.mark_entry(1, "open wikipedia", when)
        assert set(plain) == {"number", "name", "at"}
        assert plain["at"].startswith("2026-11-18T12:30:00.000")  # milliseconds
        assert _offset(plain["at"])
        label = watchlist_store.mark_entry(7, "", when, kind="start", seq=42)
        assert (label["kind"], label["seq"], label["name"]) == ("start", 42, "")
        # The old per-topic logs are gone (the session timeline replaces them).
        for name in ("append_mark", "append_timeline", "marks_file", "timeline_file"):
            assert not hasattr(watchlist_store, name)

    def test_readers_tolerate_unknown_fields_and_bad_lines(self, tmp_path):
        file = tmp_path / "evidence.jsonl"
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(
            '{"number": 1, "name": "a", "at": "x", "recorded_at": "x", "new": 1}\n'
            "not json\n",
            encoding="utf-8",
        )
        (mark,) = watchlist_store.read_jsonl(file)
        assert mark["new"] == 1
