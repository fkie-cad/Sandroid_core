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


# ---------------------------------------------------------------------------
# P2-H1: the replay must be stoppable (Stop, quit, crash)
# ---------------------------------------------------------------------------


@pytest.fixture
def _clean_player_cancel():
    from sandroid.features.player import Player

    Player.clear_cancel()
    yield
    Player.clear_cancel()


def test_player_stops_between_events_when_cancelled(
    tmp_path, monkeypatch, _clean_player_cancel
):
    from sandroid.analysis.engine import FatalStepError
    from sandroid.core.adb import Adb
    from sandroid.features.player import Player

    rec = tmp_path / "recording.txt"
    # 1 event every 200 ms for 10 s: an uncancelled replay would take ~10 s.
    rec.write_text(
        "".join(f"{i * 200}.0 /dev/input/event1 3 53 {i}\n" for i in range(50))
    )
    sent: list[str] = []
    monkeypatch.setattr(
        Adb, "send_adb_command", classmethod(lambda cls, cmd, **kw: sent.append(cmd))
    )
    monkeypatch.setattr("sandroid.core.toolbox.Toolbox.set_action_time", lambda: None)

    errors: list[BaseException] = []

    def replay() -> None:
        try:
            Player(recording_path=str(rec)).perform()
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=replay)
    started = time.monotonic()
    worker.start()
    time.sleep(0.5)
    Player.cancel_all()
    worker.join(timeout=2.0)

    assert not worker.is_alive()
    assert time.monotonic() - started < 2.0
    assert len(sent) < 10
    assert errors
    assert isinstance(errors[0], FatalStepError)


def test_cancelled_player_refuses_to_start(tmp_path, _clean_player_cancel):
    from sandroid.analysis.engine import FatalStepError
    from sandroid.features.player import Player

    rec = tmp_path / "recording.txt"
    rec.write_text("0.0 /dev/input/event1 3 53 1\n")
    Player.cancel_all()
    with pytest.raises(FatalStepError):
        Player(recording_path=str(rec)).perform()


def test_stop_playback_aborts_remaining_runs_and_still_saves(
    monkeypatch, tmp_path, _clean_player_cancel
):
    """Stop during run 1 of 3: no further snapshot loads/replays, partial run
    saved with an error so it stays visible in Diffs.
    """
    from sandroid.features.player import Player

    controller, toolbox, _forensic = _playback_controller(monkeypatch, tmp_path)
    controller._current_number_of_runs = 3
    performed: list[int] = []

    def fake_perform(self, recording_path=None):
        performed.append(1)
        controller.stop_playback()
        if Player.is_cancelled():
            from sandroid.analysis.engine import FatalStepError

            raise FatalStepError("Replay cancelled")

    monkeypatch.setattr(Player, "perform", fake_perform)
    controller._run_playback_analysis()

    assert performed == [1]
    loads_before_first_replay = 1
    assert len(toolbox.load_snapshot_calls) <= loads_before_first_replay + 1
    index = run_history.load_index()
    assert len(index) == 1
    assert "cancelled" in (index[0].get("error") or "").lower()


def test_start_playback_clears_a_previous_cancel(
    monkeypatch, tmp_path, _clean_player_cancel
):
    from sandroid.features.player import Player

    controller, _toolbox, _forensic = _playback_controller(
        monkeypatch, tmp_path, run_worker=lambda fn, **kw: None
    )
    Player.cancel_all()
    assert controller.start_playback() is True
    assert not Player.is_cancelled()


def test_shutdown_services_cancels_running_replays(_clean_player_cancel):
    from sandroid.features.player import Player
    from sandroid.tui import launcher

    task_service = SimpleNamespace(stop_all=lambda: None)
    capture = SimpleNamespace(is_capturing=lambda: False)
    launcher._shutdown_services(lambda: task_service, lambda: capture)
    assert Player.is_cancelled()
