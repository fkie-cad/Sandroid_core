"""Unit tests for core/run_history.py (Diffs sub-tab's run persistence).

Covers the load-bearing guarantees called out in the module docstring:
save/load round-trip, device scoping, index rebuild when ``index.json`` is
missing, corrupt-run-file skipping (never crashes the whole rail), delete/
clear-all, label rename independence from the recording-seed label, and the
soft run-count warning flag.

Schema v2 specifics also covered here: the ``bundle_dir`` field + absolute
in-bundle ``recording_path``, the per-run ``runs/<id>/run.json`` directory
layout, ``delete_run`` removing the whole bundle dir (``rmtree``, not a single
file), and the one-time fallback that still surfaces pre-v2 flat
``runs/run_*.json`` files.

Because ``run_history._results_path()`` is now config-first (§11), the autouse
fixture points a *fake config* at a pytest ``tmp_path`` (and sets
``RESULTS_PATH`` too), so runs never leak across tests or touch the real
``./results/`` directory.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from sandroid.core import run_history


@pytest.fixture(autouse=True)
def _isolated_results_path(tmp_path, monkeypatch):
    """Point run storage at a throwaway directory for every test.

    ``_results_path()`` resolves the config first, so a fake config whose
    ``paths.results_path`` is ``tmp_path`` is what makes storage deterministic;
    ``RESULTS_PATH`` is set as well so the env fallback is also isolated if it
    is ever exercised.
    """
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    fake_config = SimpleNamespace(paths=SimpleNamespace(results_path=tmp_path))
    monkeypatch.setattr("sandroid.config.get_config", lambda: fake_config)
    return tmp_path


def _make_record(
    run_id: str | None = None,
    *,
    label: str = "Run 1 · 10:00",
    device_name: str = "Pixel_6_Pro_API_31",
    error: str | None = None,
    changed_files=None,
    new_files=None,
    deleted_files=None,
    bundle_dir: str | None = None,
    recording_path: str | None = None,
) -> run_history.RunRecord:
    run_id = run_id or run_history.new_run_id()
    changed_files = (
        changed_files
        if changed_files is not None
        else [{"/data/data/app/db.sqlite": ["- old", "+ new"]}, "/data/plain.bin"]
    )
    new_files = new_files if new_files is not None else ["/data/new_file.txt"]
    deleted_files = deleted_files if deleted_files is not None else ["/data/gone.txt"]
    bundle_dir = bundle_dir if bundle_dir is not None else f"/abs/results/runs/{run_id}"
    recording_path = (
        recording_path if recording_path is not None else f"{bundle_dir}/recording.txt"
    )
    return run_history.RunRecord(
        schema_version=run_history.SCHEMA_VERSION,
        run_id=run_id,
        label=label,
        recorded_at="2026-07-21T10:00:00",
        completed_at="2026-07-21T10:05:00",
        device_name=device_name,
        recording_path=recording_path,
        duration=42,
        bundle_dir=bundle_dir,
        error=error,
        changed_files=changed_files,
        new_files=new_files,
        deleted_files=deleted_files,
        counts={
            "changed": len(changed_files),
            "new": len(new_files),
            "deleted": len(deleted_files),
        },
    )


class TestSaveLoadRoundTrip:
    def test_save_then_load_run_preserves_native_diff_shape(self):
        """changed_files keeps its {file: [lines]} | str shape through JSON."""
        record = _make_record()
        run_history.save_run(record)

        loaded = run_history.load_run(record.run_id)

        assert loaded.run_id == record.run_id
        assert loaded.label == record.label
        assert loaded.device_name == record.device_name
        assert loaded.changed_files == record.changed_files
        assert isinstance(loaded.changed_files[0], dict)
        assert loaded.changed_files[0]["/data/data/app/db.sqlite"] == ["- old", "+ new"]
        assert isinstance(loaded.changed_files[1], str)
        assert loaded.new_files == record.new_files
        assert loaded.deleted_files == record.deleted_files
        assert loaded.counts == {"changed": 2, "new": 1, "deleted": 1}

    def test_save_populates_index_summary(self):
        record = _make_record(label="my labeled run")
        run_history.save_run(record)

        index = run_history.load_index(device_name=record.device_name)

        assert len(index) == 1
        summary = index[0]
        assert summary["run_id"] == record.run_id
        assert summary["label"] == "my labeled run"
        assert summary["counts"] == {"changed": 2, "new": 1, "deleted": 1}
        # The index is for cheap rail rendering — never the full diff text.
        assert "changed_files" not in summary

    def test_index_sorted_newest_first(self):
        r1 = _make_record(run_id="20260101_000000_aaaaaa")
        r2 = _make_record(run_id="20260101_000001_bbbbbb")
        r3 = _make_record(run_id="20260101_000002_cccccc")
        for r in (r1, r2, r3):
            run_history.save_run(r)

        index = run_history.load_index(device_name=r1.device_name)

        assert [e["run_id"] for e in index] == [r3.run_id, r2.run_id, r1.run_id]

    def test_error_field_round_trips(self):
        record = _make_record(error="Playback failed: boom")
        run_history.save_run(record)

        loaded = run_history.load_run(record.run_id)
        assert loaded.error == "Playback failed: boom"

        index = run_history.load_index(device_name=record.device_name)
        assert index[0]["error"] == "Playback failed: boom"


class TestSchemaV2:
    def test_schema_version_is_2(self):
        assert run_history.SCHEMA_VERSION == 2

        record = _make_record()
        run_history.save_run(record)

        assert run_history.load_run(record.run_id).schema_version == 2

    def test_bundle_dir_and_absolute_recording_path_round_trip(self):
        record = _make_record(
            run_id="20260101_000000_bundle",
            bundle_dir="/abs/results/runs/20260101_000000_bundle",
            recording_path="/abs/results/runs/20260101_000000_bundle/recording.txt",
        )
        run_history.save_run(record)

        loaded = run_history.load_run(record.run_id)
        assert loaded.bundle_dir == "/abs/results/runs/20260101_000000_bundle"
        assert loaded.recording_path == (
            "/abs/results/runs/20260101_000000_bundle/recording.txt"
        )

    def test_run_written_under_per_run_subdir(self, tmp_path):
        record = _make_record()
        run_history.save_run(record)

        # v2 layout: runs/<id>/run.json — not the flat runs/run_<id>.json.
        assert (tmp_path / "runs" / record.run_id / "run.json").exists()
        assert not (tmp_path / "runs" / f"run_{record.run_id}.json").exists()

    def test_bundle_dir_defaults_when_missing_from_disk(self):
        """A record whose JSON lacks bundle_dir loads with the "" default."""
        record = _make_record()
        data = record.to_dict()
        del data["bundle_dir"]

        rebuilt = run_history.RunRecord.from_dict(data)
        assert rebuilt.bundle_dir == ""


class TestDeviceScoping:
    def test_load_index_filters_by_device(self):
        a = _make_record(run_id="20260101_000000_aaaaaa", device_name="device-a")
        b = _make_record(run_id="20260101_000001_bbbbbb", device_name="device-b")
        run_history.save_run(a)
        run_history.save_run(b)

        only_a = run_history.load_index(device_name="device-a")
        only_b = run_history.load_index(device_name="device-b")
        everything = run_history.load_index()

        assert [e["run_id"] for e in only_a] == [a.run_id]
        assert [e["run_id"] for e in only_b] == [b.run_id]
        assert {e["run_id"] for e in everything} == {a.run_id, b.run_id}

    def test_clear_all_scoped_to_device_leaves_other_devices_alone(self):
        a = _make_record(run_id="20260101_000000_aaaaaa", device_name="device-a")
        b = _make_record(run_id="20260101_000001_bbbbbb", device_name="device-b")
        run_history.save_run(a)
        run_history.save_run(b)

        run_history.clear_all(device_name="device-a")

        assert run_history.load_index(device_name="device-a") == []
        assert len(run_history.load_index(device_name="device-b")) == 1
        # The run's bundle must actually be gone, not just de-indexed.
        with pytest.raises(run_history.RunHistoryError):
            run_history.load_run(a.run_id)
        run_history.load_run(b.run_id)  # does not raise

    def test_clear_all_unscoped_removes_everything(self):
        a = _make_record(run_id="20260101_000000_aaaaaa", device_name="device-a")
        b = _make_record(run_id="20260101_000001_bbbbbb", device_name="device-b")
        run_history.save_run(a)
        run_history.save_run(b)

        run_history.clear_all()

        assert run_history.load_index() == []


class TestCorruptionSafety:
    def test_missing_index_is_rebuilt_from_run_files(self, tmp_path):
        record = _make_record()
        run_history.save_run(record)

        index_path = tmp_path / "runs" / "index.json"
        assert index_path.exists()
        index_path.unlink()

        index = run_history.load_index(device_name=record.device_name)

        assert len(index) == 1
        assert index[0]["run_id"] == record.run_id
        # Rebuilding should also persist index.json again for next time.
        assert index_path.exists()

    def test_corrupt_index_json_triggers_rebuild(self, tmp_path):
        record = _make_record()
        run_history.save_run(record)

        index_path = tmp_path / "runs" / "index.json"
        index_path.write_text("{not valid json", encoding="utf-8")

        index = run_history.load_index(device_name=record.device_name)

        assert [e["run_id"] for e in index] == [record.run_id]

    def test_corrupt_run_file_is_skipped_not_fatal(self, tmp_path, caplog):
        good = _make_record(run_id="20260101_000000_good01")
        run_history.save_run(good)

        # Hand-craft a corrupt run.json inside its own bundle dir (bypassing
        # save_run) and drop the index so the next load rebuilds by scanning.
        runs_dir = tmp_path / "runs"
        bad_bundle = runs_dir / "20260101_000001_bad001"
        bad_bundle.mkdir(parents=True, exist_ok=True)
        (bad_bundle / "run.json").write_text("{ this is not json", encoding="utf-8")
        (runs_dir / "index.json").unlink()

        with caplog.at_level("WARNING"):
            index = run_history.load_index(device_name=good.device_name)

        assert [e["run_id"] for e in index] == [good.run_id]
        assert any("corrupt run file" in msg for msg in caplog.messages)

    def test_load_run_missing_raises_run_history_error(self):
        with pytest.raises(run_history.RunHistoryError):
            run_history.load_run("does_not_exist")

    def test_load_run_corrupt_file_raises_run_history_error(self, tmp_path):
        run_id = "20260101_000000_badbad"
        bundle = tmp_path / "runs" / run_id
        bundle.mkdir(parents=True, exist_ok=True)
        (bundle / "run.json").write_text("{ nope", encoding="utf-8")

        with pytest.raises(run_history.RunHistoryError):
            run_history.load_run(run_id)

    def test_no_leftover_temp_files_after_save(self, tmp_path):
        run_history.save_run(_make_record())

        runs_dir = tmp_path / "runs"
        # Temp files may live in runs/ (index) or runs/<id>/ (run.json).
        leftovers = list(runs_dir.glob("**/.*.tmp-*"))
        assert leftovers == []


class TestLegacyLayoutFallback:
    def test_legacy_flat_run_file_is_picked_up_by_rebuild(self, tmp_path):
        """A pre-v2 flat run_*.json (no bundle_dir) still surfaces in the rail."""
        legacy = {
            "schema_version": 1,
            "run_id": "20250101_000000_legacy",
            "label": "Old run",
            "recorded_at": "2025-01-01T00:00:00",
            "completed_at": "2025-01-01T00:01:00",
            "device_name": "device-a",
            "recording_path": "/old/results/raw/recording.txt",
            "duration": 10,
            "changed_files": [],
            "new_files": [],
            "deleted_files": [],
            "counts": {"changed": 0, "new": 0, "deleted": 0},
        }
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir(parents=True, exist_ok=True)
        (runs_dir / "run_20250101_000000_legacy.json").write_text(
            json.dumps(legacy), encoding="utf-8"
        )
        # No index.json yet -> load_index is forced to rebuild by scanning.

        index = run_history.load_index(device_name="device-a")

        assert [e["run_id"] for e in index] == ["20250101_000000_legacy"]

    def test_v2_run_wins_over_stale_legacy_flat_file(self, tmp_path):
        """If both layouts hold the same run id, the v2 bundle entry wins."""
        record = _make_record(run_id="20260101_000000_dupdup", label="v2 label")
        run_history.save_run(record)

        # Stale flat file for the same id with a different label.
        legacy = record.to_dict()
        legacy["label"] = "stale legacy label"
        (tmp_path / "runs" / "run_20260101_000000_dupdup.json").write_text(
            json.dumps(legacy), encoding="utf-8"
        )
        (tmp_path / "runs" / "index.json").unlink()

        index = run_history.load_index(device_name=record.device_name)

        assert len(index) == 1
        assert index[0]["label"] == "v2 label"


class TestDeleteAndRename:
    def test_delete_run_rmtrees_bundle_dir_and_index_entry(self, tmp_path):
        record = _make_record()
        run_history.save_run(record)

        bundle = tmp_path / "runs" / record.run_id
        # Drop extra artifacts alongside run.json to prove rmtree (not unlink).
        (bundle / "recording.txt").write_text("events", encoding="utf-8")
        (bundle / "raw").mkdir(exist_ok=True)

        run_history.delete_run(record.run_id)

        assert run_history.load_index(device_name=record.device_name) == []
        assert not bundle.exists()
        with pytest.raises(run_history.RunHistoryError):
            run_history.load_run(record.run_id)

    def test_delete_run_missing_bundle_is_noop(self):
        # Deleting an unknown run must not raise (guarded rmtree).
        run_history.delete_run("does_not_exist")
        assert run_history.load_index() == []

    def test_update_label_only_touches_that_run(self):
        a = _make_record(run_id="20260101_000000_aaaaaa", label="Run A")
        b = _make_record(run_id="20260101_000001_bbbbbb", label="Run B")
        run_history.save_run(a)
        run_history.save_run(b)

        updated = run_history.update_label(a.run_id, "Renamed A")

        assert updated.label == "Renamed A"
        assert run_history.load_run(a.run_id).label == "Renamed A"
        assert run_history.load_run(b.run_id).label == "Run B"


class TestRunCountWarning:
    def test_is_run_count_high_crosses_threshold(self, monkeypatch):
        monkeypatch.setattr(run_history, "RUN_COUNT_WARNING_THRESHOLD", 2)

        assert run_history.is_run_count_high() is False

        for i in range(3):
            run_history.save_run(_make_record(run_id=f"2026010{i}_000000_run{i:03d}"))

        assert run_history.run_count() == 3
        assert run_history.is_run_count_high() is True


class TestFromDictForwardCompat:
    def test_from_dict_ignores_unknown_keys(self):
        """A future field added to the on-disk shape must not break loading."""
        record = _make_record()
        data = record.to_dict()
        data["some_future_field"] = "ignored"

        rebuilt = run_history.RunRecord.from_dict(data)

        assert rebuilt.run_id == record.run_id
        assert rebuilt.changed_files == record.changed_files

    def test_json_file_matches_from_dict(self, tmp_path):
        record = _make_record()
        run_history.save_run(record)

        run_file = tmp_path / "runs" / record.run_id / "run.json"
        with open(run_file, encoding="utf-8") as f:
            raw = json.load(f)

        rebuilt = run_history.RunRecord.from_dict(raw)
        assert rebuilt == record
