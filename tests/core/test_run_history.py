"""Unit tests for core/run_history.py (Diffs sub-tab's run persistence).

Covers the load-bearing guarantees called out in the module docstring:
save/load round-trip, device scoping, index rebuild when ``index.json`` is
missing, corrupt-run-file skipping (never crashes the whole rail), delete/
clear-all, label rename independence from the recording-seed label, and the
soft run-count warning flag.

Every test gets a fresh ``RESULTS_PATH`` pointed at a pytest ``tmp_path`` via
the autouse fixture below, so runs never leak across tests or touch the real
``./results/`` directory.
"""

from __future__ import annotations

import json

import pytest

from sandroid.core import run_history


@pytest.fixture(autouse=True)
def _isolated_results_path(tmp_path, monkeypatch):
    """Point RESULTS_PATH at a throwaway directory for every test."""
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
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
) -> run_history.RunRecord:
    run_id = run_id or run_history.new_run_id()
    changed_files = (
        changed_files
        if changed_files is not None
        else [{"/data/data/app/db.sqlite": ["- old", "+ new"]}, "/data/plain.bin"]
    )
    new_files = new_files if new_files is not None else ["/data/new_file.txt"]
    deleted_files = deleted_files if deleted_files is not None else ["/data/gone.txt"]
    return run_history.RunRecord(
        schema_version=run_history.SCHEMA_VERSION,
        run_id=run_id,
        label=label,
        recorded_at="2026-07-21T10:00:00",
        completed_at="2026-07-21T10:05:00",
        device_name=device_name,
        recording_path="/tmp/recording.txt",
        duration=42,
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
        # The run file itself must actually be gone, not just de-indexed.
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

        # Hand-craft a corrupt run file directly (bypassing save_run) and
        # drop the index so the next load is forced to rebuild by scanning.
        runs_dir = tmp_path / "runs"
        (runs_dir / "run_20260101_000001_bad0001.json").write_text(
            "{ this is not json", encoding="utf-8"
        )
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
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir(parents=True, exist_ok=True)
        (runs_dir / f"run_{run_id}.json").write_text("{ nope", encoding="utf-8")

        with pytest.raises(run_history.RunHistoryError):
            run_history.load_run(run_id)

    def test_no_leftover_temp_files_after_save(self, tmp_path):
        run_history.save_run(_make_record())

        runs_dir = tmp_path / "runs"
        leftovers = list(runs_dir.glob(".*.tmp-*"))
        assert leftovers == []


class TestDeleteAndRename:
    def test_delete_run_removes_file_and_index_entry(self, tmp_path):
        record = _make_record()
        run_history.save_run(record)

        run_history.delete_run(record.run_id)

        assert run_history.load_index(device_name=record.device_name) == []
        run_file = tmp_path / "runs" / f"run_{record.run_id}.json"
        assert not run_file.exists()
        with pytest.raises(run_history.RunHistoryError):
            run_history.load_run(record.run_id)

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

        run_file = tmp_path / "runs" / f"run_{record.run_id}.json"
        with open(run_file, encoding="utf-8") as f:
            raw = json.load(f)

        rebuilt = run_history.RunRecord.from_dict(raw)
        assert rebuilt == record
