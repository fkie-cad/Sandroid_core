"""Tests for ExportResultsCommand/ImportResultsCommand's run_history rewiring.

Before this fix, ``_collect_export_data`` only ever checked
``hasattr(forensic_service, "get_results")`` -- a method that never existed on
``ForensicService`` in any version of this codebase (verified via git log --
this predates the AnalysisEngine refactor) -- so exports silently contained
no real analysis data, just a timestamp/version shell. These tests assert the
command now surfaces genuine data: the current device's most recent
``run_history`` entry and a live forensic-service state snapshot.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from sandroid.commands.base import CommandContext
from sandroid.commands.io_commands import ExportResultsCommand, ImportResultsCommand
from sandroid.core.run_history import RunRecord


def _make_record(run_id: str = "20260722_120000_ab12cd") -> RunRecord:
    return RunRecord(
        schema_version=2,
        run_id=run_id,
        label="Run 1",
        recorded_at="2026-07-22T12:00:00",
        completed_at="2026-07-22T12:01:00",
        device_name="emulator-5554",
        recording_path="/results/runs/20260722_120000_ab12cd/recording.txt",
        duration=60,
        bundle_dir="/results/runs/20260722_120000_ab12cd",
        changed_files=[{"/sdcard/foo.db": ["- old", "+ new"]}],
        new_files=["/sdcard/new.txt"],
        deleted_files=[],
        counts={"changed": 1, "new": 1, "deleted": 0},
    )


def test_collect_export_data_includes_latest_run(monkeypatch):
    """The most recent run_history entry for the active device is exported."""
    from sandroid.core import run_history

    record = _make_record()
    monkeypatch.setattr(
        run_history,
        "load_index",
        lambda device_name=None: [
            {"run_id": record.run_id, "device_name": device_name}
        ],
    )
    monkeypatch.setattr(run_history, "load_run", lambda run_id: record)

    toolbox = MagicMock()
    toolbox.device_name = "emulator-5554"
    ctx = CommandContext(toolbox=toolbox)

    data = ExportResultsCommand()._collect_export_data(ctx)

    assert data["latest_run"] == record.to_dict()
    assert data["latest_run"]["changed_files"] == [
        {"/sdcard/foo.db": ["- old", "+ new"]}
    ]


def test_collect_export_data_includes_forensic_state():
    """A reachable forensic_service's live state is included."""
    forensic_service = MagicMock()
    forensic_service.get_state_dict.return_value = {"baseline_count": 3}
    ctx = CommandContext(forensic_service=forensic_service)

    data = ExportResultsCommand()._collect_export_data(ctx)

    assert data["forensic_state"] == {"baseline_count": 3}


def test_collect_export_data_no_runs_omits_latest_run(monkeypatch):
    """An empty run_history index doesn't crash and adds no 'latest_run' key."""
    from sandroid.core import run_history

    monkeypatch.setattr(run_history, "load_index", lambda device_name=None: [])

    ctx = CommandContext()
    data = ExportResultsCommand()._collect_export_data(ctx)

    assert "latest_run" not in data
    assert data["version"] == "2.0"


def test_collect_export_data_run_history_failure_is_non_fatal(monkeypatch):
    """A run_history read failure logs and degrades gracefully, never raises."""
    from sandroid.core import run_history

    def _boom(device_name=None):
        raise OSError("disk error")

    monkeypatch.setattr(run_history, "load_index", _boom)

    ctx = CommandContext()
    data = ExportResultsCommand()._collect_export_data(ctx)

    assert "latest_run" not in data


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("latest_run", {"run_id": "x"}),
        ("forensic_state", {"baseline_count": 1}),
    ],
)
def test_apply_import_data_recognizes_new_keys(key, value):
    """latest_run/forensic_state are recognized (counted), not silently dropped."""
    ctx = CommandContext()
    entries = ImportResultsCommand()._apply_import_data(ctx, {key: value})

    assert entries == 1
