"""Regression tests for the phase-2 live-test findings in the TUI recording flow.

Each test reproduces one finding from ``FINDINGS_phase2.md`` (P2-H1, P2-H2,
P2-H5 and the key-collision / stale-Spotlight mediums) without a device:
Textual pilots for the UI parts, plain fakes for the controller parts.
"""

from __future__ import annotations

import os
import threading
import time
from types import SimpleNamespace

import pytest
from textual.app import App, ComposeResult

from sandroid.core import run_history
from sandroid.tui.widgets.diff_view import DiffView
from sandroid.tui.widgets.diffs_view import DiffsView


@pytest.fixture
def results_root(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    fake = SimpleNamespace(paths=SimpleNamespace(results_path=tmp_path))
    monkeypatch.setattr("sandroid.config.get_config", lambda: fake)
    return tmp_path


def _save_run(run_id: str, label: str = "Run A") -> None:
    from sandroid.core.toolbox import Toolbox

    bundle_dir = f"/tmp/sandroid-test/runs/{run_id}"
    run_history.save_run(
        run_history.RunRecord(
            schema_version=run_history.SCHEMA_VERSION,
            run_id=run_id,
            label=label,
            recorded_at="2026-11-16T10:00:00",
            completed_at="2026-11-16T10:05:00",
            device_name=Toolbox.device_name,
            recording_path=f"{bundle_dir}/recording.txt",
            bundle_dir=bundle_dir,
            duration=10,
            error=None,
            changed_files=[{"/data/data/x/databases/bedtime": ["- a", "+ b"]}],
            new_files=[],
            deleted_files=[],
            counts={"changed": 1, "new": 0, "deleted": 0},
        )
    )


class _DiffsHarness(App):
    def compose(self) -> ComposeResult:
        yield DiffsView(id="files-diffs")


async def _wait_for(pilot, predicate, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await pilot.pause(0.02)
    assert predicate(), "condition was not met within timeout"


# ---------------------------------------------------------------------------
# P2-H1: NoActiveAppError when Diffs already lists a run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_state_change_from_worker_thread_rerenders_diffs_without_crash(
    results_root, monkeypatch
) -> None:
    """A STATE_CHANGED event published off the UI thread (snapshot load,
    device poll, recording start, ...) re-renders the selected run's
    DiffView. That mount used to run in the publisher's empty contextvars
    context and crash the whole TUI with NoActiveAppError.
    """
    _save_run("20261116_100000_aaaaaa")
    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await _wait_for(pilot, lambda: view._detail_record is not None)
        await _wait_for(pilot, lambda: len(view.query(DiffView)) == 1)
        monkeypatch.setattr(view, "_is_on_screen", lambda: True)

        callbacks = [cb for _etype, cb in view._event_handlers]
        assert callbacks, "DiffsView must subscribe to STATE_CHANGED"
        worker = threading.Thread(target=callbacks[0], args=(None,))
        worker.start()
        worker.join()
        await pilot.pause(0.2)

        assert app._exception is None
        assert len(view.query(DiffView)) == 1


# ---------------------------------------------------------------------------
# P2-H1: persistence must not depend on UI updates
# ---------------------------------------------------------------------------


def _playback_controller(monkeypatch, tmp_path, **overrides):
    """A RecordingController wired to the lightweight fakes of the monitor
    safety-net tests (no device, engine pipeline neutered).
    """
    # tests/ is not a package; pytest puts this directory on sys.path.
    from test_recording_controller_monitor_safety import _make_controller

    return _make_controller(monkeypatch, tmp_path, **overrides)


def test_run_is_persisted_even_when_every_ui_update_fails(monkeypatch, tmp_path):
    """When the TUI died (or a UI callback raised), call_from_thread raises on
    the playback worker. That used to abort the worker before _persist_run,
    so run.json, sandroid.json and the index entry were never written.
    """

    def broken_call_from_thread(fn, *args):
        raise RuntimeError("App is not running")

    saved: list[str] = []
    controller, _toolbox, _forensic = _playback_controller(
        monkeypatch,
        tmp_path,
        call_from_thread=broken_call_from_thread,
        on_run_saved=saved.append,
        set_replay_indicator=lambda active: None,
    )

    controller._run_playback_analysis()

    runs = list((tmp_path / "runs").glob("*/run.json"))
    assert len(runs) == 1
    index = run_history.load_index()
    assert [e["run_id"] for e in index] == [runs[0].parent.name]
    assert (tmp_path / "sandroid.json").exists()
    assert controller.is_replaying is False


def test_disconnect_guard_failure_does_not_abort_the_replay(monkeypatch, tmp_path):
    def broken_guard(active: bool) -> None:
        raise RuntimeError("no app")

    controller, toolbox, _forensic = _playback_controller(
        monkeypatch, tmp_path, suppress_disconnect_guard=broken_guard
    )
    controller._run_playback_analysis()
    assert toolbox.load_snapshot_calls
    index = run_history.load_index()
    assert len(index) == 1
    assert not index[0].get("error")
