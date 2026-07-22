"""Unit tests for core/run_bundle.py (the run-bundle storage layer).

A run bundle is the single directory holding one Play's manifest, the
recording that produced it, and the raw pull tree. These tests exercise the
public API against a throwaway ``tmp_path`` (both the fake config's
``paths.results_path`` and ``RESULTS_PATH`` point at it, since
``run_history._results_path()`` is config-first): ``create_bundle`` makes the
directory + ``raw/``; ``import_recording`` copies ``recording.txt`` and returns
an absolute path; ``write_manifest`` round-trips through ``run_history``; and
``run_history.delete_run`` removes the whole bundle.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from sandroid.core import run_bundle, run_history


@pytest.fixture(autouse=True)
def _isolated_results_path(tmp_path, monkeypatch):
    """Point run storage (config + RESULTS_PATH) at a throwaway directory."""
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    fake_config = SimpleNamespace(paths=SimpleNamespace(results_path=tmp_path))
    monkeypatch.setattr("sandroid.config.get_config", lambda: fake_config)
    return tmp_path


def _make_record(run_id: str, tmp_path: Path) -> run_history.RunRecord:
    bundle = tmp_path / "runs" / run_id
    return run_history.RunRecord(
        schema_version=run_history.SCHEMA_VERSION,
        run_id=run_id,
        label="Bundle run",
        recorded_at="2026-07-22T10:00:00",
        completed_at="2026-07-22T10:05:00",
        device_name="Pixel_6_Pro_API_31",
        recording_path=str(bundle / "recording.txt"),
        duration=7,
        bundle_dir=str(bundle),
        changed_files=[],
        new_files=[],
        deleted_files=[],
        counts={"changed": 0, "new": 0, "deleted": 0},
    )


class TestCreateBundle:
    def test_create_bundle_makes_run_dir_and_raw(self, tmp_path):
        bundle = run_bundle.create_bundle("20260722_100000_aaaaaa")

        assert bundle == tmp_path / "runs" / "20260722_100000_aaaaaa"
        assert bundle.is_dir()
        assert (bundle / "raw").is_dir()

    def test_create_bundle_is_idempotent(self, tmp_path):
        first = run_bundle.create_bundle("20260722_100000_bbbbbb")
        (first / "raw" / "first_pull").mkdir(parents=True)

        # Re-creating must not wipe existing contents.
        second = run_bundle.create_bundle("20260722_100000_bbbbbb")

        assert second == first
        assert (first / "raw" / "first_pull").is_dir()

    def test_bundle_dir_resolves_under_configured_root(self, tmp_path):
        assert run_bundle.bundle_dir("some_run") == tmp_path / "runs" / "some_run"


class TestImportRecording:
    def test_import_recording_copies_and_returns_absolute_path(self, tmp_path):
        live = tmp_path / "live" / "recording.txt"
        live.parent.mkdir(parents=True)
        live.write_text("12345 dev EV_KEY 1 1\n", encoding="utf-8")

        returned = run_bundle.import_recording("20260722_100000_cccccc", live)

        assert Path(returned).is_absolute()
        dst = tmp_path / "runs" / "20260722_100000_cccccc" / "recording.txt"
        assert Path(returned) == dst.resolve()
        assert dst.read_text(encoding="utf-8") == "12345 dev EV_KEY 1 1\n"

    def test_import_recording_creates_bundle_if_absent(self, tmp_path):
        live = tmp_path / "recording.txt"
        live.write_text("events", encoding="utf-8")

        run_bundle.import_recording("20260722_100000_dddddd", live)

        bundle = tmp_path / "runs" / "20260722_100000_dddddd"
        assert bundle.is_dir()
        assert (bundle / "raw").is_dir()

    def test_import_recording_missing_source_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            run_bundle.import_recording("20260722_100000_eeeeee", tmp_path / "nope.txt")


class TestRawDir:
    def test_raw_dir_absolute_no_trailing_separator(self, tmp_path):
        raw = run_bundle.raw_dir("20260722_100000_ffffff")

        assert Path(raw).is_absolute()
        assert not raw.endswith(os.sep)
        # The engine appends os.sep; consumers then concatenate slot names.
        assert (Path(raw) / "first_pull") == Path(f"{raw}{os.sep}first_pull")
        assert Path(raw).is_dir()
        assert Path(raw).name == "raw"


class TestWriteManifest:
    def test_write_manifest_is_visible_through_run_history(self, tmp_path):
        run_id = "20260722_100000_111111"
        run_bundle.create_bundle(run_id)
        record = _make_record(run_id, tmp_path)

        run_bundle.write_manifest(record)

        index = run_history.load_index(device_name=record.device_name)
        assert [e["run_id"] for e in index] == [run_id]
        loaded = run_history.load_run(run_id)
        assert loaded.bundle_dir == str(tmp_path / "runs" / run_id)

    def test_delete_run_rmtrees_the_bundle(self, tmp_path):
        run_id = "20260722_100000_222222"
        live = tmp_path / "recording.txt"
        live.write_text("events", encoding="utf-8")
        run_bundle.import_recording(run_id, live)
        run_bundle.write_manifest(_make_record(run_id, tmp_path))

        bundle = tmp_path / "runs" / run_id
        assert bundle.is_dir()

        run_history.delete_run(run_id)

        assert not bundle.exists()
        assert run_history.load_index() == []
