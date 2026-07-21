"""Unit tests for core/watchlist_store.py (Watchlist sub-tab's on-disk state).

Covers the load-bearing guarantees called out in the module docstring:
sanitized-path directory naming (including the long-path truncation +
sha256-disambiguation fallback), membership (index.json) save/load
round-trip and corruption-safety, and the previous/current baseline-cache
lifecycle (reset -> has_baseline -> promote).

Every test gets a fresh RESULTS_PATH pointed at a pytest tmp_path via the
autouse fixture below, mirroring tests/core/test_run_history.py.
"""

from __future__ import annotations

import json

import pytest

from sandroid.core import watchlist_store


@pytest.fixture(autouse=True)
def _isolated_results_path(tmp_path, monkeypatch):
    """Point RESULTS_PATH at a throwaway directory for every test."""
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    return tmp_path


class TestSanitizePath:
    def test_short_path_is_percent_encoded_and_reversible_by_inspection(self):
        encoded = watchlist_store.sanitize_path("/data/data/com.app/databases/app.db")
        assert "/" not in encoded
        assert encoded == "%2Fdata%2Fdata%2Fcom.app%2Fdatabases%2Fapp.db"

    def test_different_short_paths_never_collide(self):
        a = watchlist_store.sanitize_path("/data/data/com.app/a.db")
        b = watchlist_store.sanitize_path("/data/data/com.app/b.db")
        assert a != b

    def test_sanitize_path_is_deterministic(self):
        path = "/data/data/com.app/databases/app.db"
        assert watchlist_store.sanitize_path(path) == watchlist_store.sanitize_path(
            path
        )

    def test_long_paths_are_truncated_with_a_disambiguating_suffix(self):
        # Two paths that share a long common prefix (so their percent-encoded
        # forms would share the same first 150 characters after truncation)
        # but differ only near the end -- truncation alone would collide.
        from urllib.parse import quote

        base = "/data/data/" + ("x" * 200) + "/databases/"
        long_a = base + "app_one.db"
        long_b = base + "app_two.db"

        # Sanity-check the premise: the *un*-truncated percent-encoded form
        # really does exceed the threshold, so sanitize_path() below is
        # actually exercising the truncation path, not just short-circuiting.
        assert len(quote(long_a, safe="")) > watchlist_store._MAX_ENCODED_NAME

        encoded_a = watchlist_store.sanitize_path(long_a)
        encoded_b = watchlist_store.sanitize_path(long_b)

        assert "__" in encoded_a  # truncated form carries the hash suffix
        # The returned name must actually be short (truncated), not the full
        # 242-ish character percent-encoded string.
        assert len(encoded_a) < len(quote(long_a, safe=""))
        assert encoded_a != encoded_b

    def test_row_dir_uses_sanitized_name_under_watchlist_dir(self, tmp_path):
        path = "/data/data/com.app/databases/app.db"
        directory = watchlist_store.row_dir(path)

        assert directory.parent == watchlist_store.watchlist_dir()
        assert directory.name == watchlist_store.sanitize_path(path)
        assert directory.exists()


class TestMembershipPersistence:
    def test_save_then_load_round_trip(self):
        paths = ["/data/data/com.app/a.db", "/data/data/com.app/b.xml"]
        watchlist_store.save_membership(paths)

        loaded = watchlist_store.load_membership()

        assert loaded == paths

    def test_load_missing_index_returns_empty_list(self):
        assert watchlist_store.load_membership() == []

    def test_load_corrupt_index_returns_empty_list_and_warns(self, tmp_path, caplog):
        index_path = tmp_path / "spotlight_files" / ".watchlist" / "index.json"
        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_text("{ not valid json", encoding="utf-8")

        with caplog.at_level("WARNING"):
            loaded = watchlist_store.load_membership()

        assert loaded == []
        assert any("index.json unreadable" in msg for msg in caplog.messages)

    def test_save_overwrites_previous_membership(self):
        watchlist_store.save_membership(["/a"])
        watchlist_store.save_membership(["/b", "/c"])

        assert watchlist_store.load_membership() == ["/b", "/c"]

    def test_index_json_matches_documented_shape(self, tmp_path):
        watchlist_store.save_membership(["/a"])

        index_path = tmp_path / "spotlight_files" / ".watchlist" / "index.json"
        with open(index_path, encoding="utf-8") as f:
            data = json.load(f)

        # A plain membership-only save (no row_states/auto_enabled supplied)
        # still writes the v2 fields, just empty/default -- readers never
        # need to distinguish "omitted" from "explicitly empty".
        assert data == {
            "schema_version": watchlist_store.SCHEMA_VERSION,
            "paths": ["/a"],
            "auto_enabled": False,
            "rows": {},
        }

    def test_no_leftover_temp_files_after_save(self, tmp_path):
        watchlist_store.save_membership(["/a"])

        watchlist_dir = tmp_path / "spotlight_files" / ".watchlist"
        leftovers = list(watchlist_dir.glob(".*.tmp-*"))
        assert leftovers == []


class TestRowStatePersistence:
    """Schema v2: each path's last-known pull/auto state + auto_enabled,
    alongside plain membership (see module docstring point 1).
    """

    PATH_A = "/data/data/com.app/a.db"
    PATH_B = "/data/data/com.app/b.xml"

    def test_save_then_load_round_trip_of_full_row_state(self):
        row_states = {
            self.PATH_A: {
                "state": "changed",
                "detail": "diffed against baseline",
                "last_seen": [1700000000, 42],
                "last_pulled": [1700000000, 42],
            },
            self.PATH_B: {
                "state": "baseline_only",
                "detail": "Baseline captured — 1 file, 10 bytes.",
                "last_seen": None,
                "last_pulled": None,
            },
        }
        watchlist_store.save_membership(
            [self.PATH_A, self.PATH_B], row_states=row_states, auto_enabled=True
        )

        assert watchlist_store.load_membership() == [self.PATH_A, self.PATH_B]
        assert watchlist_store.load_row_states() == row_states
        assert watchlist_store.load_auto_enabled() is True

    def test_row_state_for_a_path_no_longer_in_paths_is_dropped(self):
        """A path removed from the watchlist must not resurrect its stale
        row state on the next save -- save_membership only ever writes rows
        for paths still present in the authoritative ``paths`` list.
        """
        row_states = {
            self.PATH_A: {"state": "changed", "last_seen": [1, 2], "last_pulled": None},
            "/some/removed/path": {
                "state": "error",
                "last_seen": None,
                "last_pulled": None,
            },
        }

        watchlist_store.save_membership(
            [self.PATH_A], row_states=row_states, auto_enabled=False
        )

        loaded = watchlist_store.load_row_states()
        assert self.PATH_A in loaded
        assert "/some/removed/path" not in loaded

    def test_load_row_states_missing_index_returns_empty_dict(self):
        assert watchlist_store.load_row_states() == {}

    def test_load_auto_enabled_missing_index_returns_false(self):
        assert watchlist_store.load_auto_enabled() is False

    def test_load_row_states_and_auto_enabled_on_a_v1_only_index_are_safe(
        self, tmp_path
    ):
        """A pre-existing v1 index.json (just "paths", no "rows"/
        "auto_enabled") must not error -- both new accessors fall back to
        their safe empty defaults exactly like a missing file.
        """
        index_path = tmp_path / "spotlight_files" / ".watchlist" / "index.json"
        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_text(
            json.dumps({"schema_version": 1, "paths": [self.PATH_A]}),
            encoding="utf-8",
        )

        assert watchlist_store.load_membership() == [self.PATH_A]
        assert watchlist_store.load_row_states() == {}
        assert watchlist_store.load_auto_enabled() is False

    def test_no_row_states_supplied_persists_membership_only(self):
        """Calling save_membership without row_states (the plain membership-
        only call ForensicService historically made) must not error and
        must yield an empty (not missing) "rows" mapping.
        """
        watchlist_store.save_membership([self.PATH_A])

        assert watchlist_store.load_row_states() == {}
        assert watchlist_store.load_auto_enabled() is False


class TestBaselineCacheLifecycle:
    PATH = "/data/data/com.app/databases/app.db"

    def test_has_baseline_false_before_any_pull(self):
        assert watchlist_store.has_baseline(self.PATH) is False

    def test_reset_current_creates_empty_directory(self):
        current = watchlist_store.reset_current(self.PATH)
        assert current.exists()
        assert list(current.iterdir()) == []

    def test_reset_current_clears_stale_leftovers(self):
        current = watchlist_store.reset_current(self.PATH)
        (current / "app.db").write_text("first pull", encoding="utf-8")
        (current / "app.db-wal").write_text("stale wal", encoding="utf-8")

        current_again = watchlist_store.reset_current(self.PATH)

        assert list(current_again.iterdir()) == []

    def test_promote_makes_current_the_new_previous(self):
        current = watchlist_store.reset_current(self.PATH)
        (current / "app.db").write_text("v1", encoding="utf-8")

        watchlist_store.promote(self.PATH)

        assert watchlist_store.has_baseline(self.PATH) is True
        previous = watchlist_store.previous_dir(self.PATH)
        assert (previous / "app.db").read_text(encoding="utf-8") == "v1"

    def test_second_promote_overwrites_first_baseline(self):
        current = watchlist_store.reset_current(self.PATH)
        (current / "app.db").write_text("v1", encoding="utf-8")
        watchlist_store.promote(self.PATH)

        current = watchlist_store.reset_current(self.PATH)
        (current / "app.db").write_text("v2", encoding="utf-8")
        watchlist_store.promote(self.PATH)

        previous = watchlist_store.previous_dir(self.PATH)
        assert (previous / "app.db").read_text(encoding="utf-8") == "v2"
        # Exactly one file -- v1 must not linger alongside v2.
        assert [f.name for f in previous.iterdir()] == ["app.db"]

    def test_two_different_paths_have_independent_baselines(self):
        path_a = "/data/data/com.app/a.db"
        path_b = "/data/data/com.app/b.db"

        current_a = watchlist_store.reset_current(path_a)
        (current_a / "a.db").write_text("a", encoding="utf-8")
        watchlist_store.promote(path_a)

        assert watchlist_store.has_baseline(path_a) is True
        assert watchlist_store.has_baseline(path_b) is False
