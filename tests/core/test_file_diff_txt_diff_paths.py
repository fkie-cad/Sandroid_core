"""Unit tests for core/file_diff.py's txt_diff_paths (new two-explicit-path
text diff, added for the Watchlist sub-tab's previous/current baseline
cache since the existing txt_diff(txt_file) hardcodes the
RAW_RESULTS_PATH/first_pull/second_pull convention).

The existing txt_diff() and its own caller in ChangedFiles are deliberately
left untouched -- these tests only exercise the new function.
"""

from __future__ import annotations

from sandroid.core import file_diff


def _write(path, lines):
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


class TestTxtDiffPaths:
    def test_added_and_deleted_lines_are_reported(self, tmp_path):
        old_path = tmp_path / "old.txt"
        new_path = tmp_path / "new.txt"
        _write(old_path, ["kept", "removed_line"])
        _write(new_path, ["kept", "added_line"])

        diff = file_diff.txt_diff_paths(str(old_path), str(new_path))

        assert "[LINE DELETED]" in diff
        assert "removed_line" in diff
        assert "[LINE ADDED]" in diff
        assert "added_line" in diff
        assert "kept" not in diff  # unchanged line must not appear at all

    def test_identical_files_produce_empty_diff(self, tmp_path):
        old_path = tmp_path / "old.txt"
        new_path = tmp_path / "new.txt"
        _write(old_path, ["same", "lines"])
        _write(new_path, ["same", "lines"])

        diff = file_diff.txt_diff_paths(str(old_path), str(new_path))

        assert diff == ""

    def test_missing_old_file_returns_error_string_not_raise(self, tmp_path):
        new_path = tmp_path / "new.txt"
        _write(new_path, ["hello"])

        diff = file_diff.txt_diff_paths(
            str(tmp_path / "does_not_exist.txt"), str(new_path)
        )

        assert "Error" in diff

    def test_missing_new_file_returns_error_string_not_raise(self, tmp_path):
        old_path = tmp_path / "old.txt"
        _write(old_path, ["hello"])

        diff = file_diff.txt_diff_paths(str(old_path), str(tmp_path / "gone.txt"))

        assert "Error" in diff

    def test_non_utf8_file_returns_friendly_error_not_raise(self, tmp_path):
        old_path = tmp_path / "old.bin"
        new_path = tmp_path / "new.bin"
        old_path.write_bytes(b"\xff\xfe\x00binary garbage")
        new_path.write_bytes(b"more binary garbage")

        diff = file_diff.txt_diff_paths(str(old_path), str(new_path))

        assert "Error" in diff
        assert "not a text file" in diff

    def test_does_not_touch_existing_txt_diff_signature(self, tmp_path, monkeypatch):
        """txt_diff(txt_file) must keep its original single-argument,
        RAW_RESULTS_PATH-relative contract -- ChangedFiles.return_data()
        calls it unchanged.
        """
        raw_results = tmp_path / "raw" / ""
        (tmp_path / "raw" / "first_pull").mkdir(parents=True)
        (tmp_path / "raw" / "second_pull").mkdir(parents=True)
        _write(tmp_path / "raw" / "first_pull" / "notes.txt", ["a"])
        _write(tmp_path / "raw" / "second_pull" / "notes.txt", ["a", "b"])
        monkeypatch.setenv("RAW_RESULTS_PATH", str(raw_results))

        diff = file_diff.txt_diff("notes.txt")

        assert "[LINE ADDED]" in diff
        assert "b" in diff
