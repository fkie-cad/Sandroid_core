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


class _FakeToolboxBase:
    def load_snapshot(self, tag) -> None:
        pass

    def create_snapshot(self, tag) -> None:
        pass

    def fetch_changed_files(self, fetch_all: bool = False) -> dict:
        return {}


def _playback_controller(monkeypatch, tmp_path, **overrides):
    """A RecordingController wired to the lightweight fakes of the monitor
    safety-net tests (no device, engine pipeline neutered).
    """
    # tests/ is not a package; pytest puts this directory on sys.path.
    from test_recording_controller_monitor_safety import _make_controller

    # Other tests leave SESSION_PATH behind; the legacy sandroid.json goes there.
    monkeypatch.delenv("SESSION_PATH", raising=False)
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


# ---------------------------------------------------------------------------
# P2-H2: Record -> Cancel/Discard must not play
# ---------------------------------------------------------------------------


class _FakeWrapper:
    is_running = True
    event_count = 63
    elapsed_seconds = 4

    def __init__(self) -> None:
        self.stopped = False

    def stop(self) -> int:
        self.stopped = True
        self.is_running = False
        return 4


async def _recording_modal_in_progress(app, pilot, results: list):
    from sandroid.tui.modals.recording_modal import RecordingModal

    modal = RecordingModal()
    await app.push_screen(modal, results.append)
    await pilot.pause()
    wrapper = _FakeWrapper()
    modal._wrapper = wrapper
    modal.is_recording = True
    await pilot.pause()
    return modal, wrapper


@pytest.mark.asyncio
@pytest.mark.parametrize("how", ["enter_on_focused_discard", "click_discard"])
async def test_discard_while_recording_cancels_instead_of_saving(how) -> None:
    """With Discard focused, Enter used to hit the modal's priority
    Enter=Stop & save binding, so the recording was saved and auto-replayed.
    """
    from textual.widgets import Button

    app = App()
    results: list = []
    async with app.run_test() as pilot:
        modal, wrapper = await _recording_modal_in_progress(app, pilot, results)
        if how == "enter_on_focused_discard":
            modal.query_one("#btn-cancel", Button).focus()
            await pilot.pause()
            await pilot.press("enter")
        else:
            await pilot.click("#btn-cancel")
        await pilot.pause()

    assert wrapper.stopped
    assert len(results) == 1
    assert results[0].cancelled is True
    assert results[0].completed is False


@pytest.mark.asyncio
async def test_enter_on_focused_stop_still_saves() -> None:
    from textual.widgets import Button

    app = App()
    results: list = []
    async with app.run_test() as pilot:
        modal, _wrapper = await _recording_modal_in_progress(app, pilot, results)
        modal.query_one("#btn-stop", Button).focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()

    assert results
    assert results[0].completed is True
    assert results[0].cancelled is False


def test_controller_does_not_play_a_cancelled_recording(monkeypatch, tmp_path):
    from sandroid.tui.modals.recording_modal import RecordingResult

    logs: list[str] = []
    pushed: list = []
    controller, _toolbox, _forensic = _playback_controller(
        monkeypatch,
        tmp_path,
        log_info=logs.append,
        push_modal=lambda modal, cb: pushed.append(cb),
    )
    played: list = []
    monkeypatch.setattr(controller, "start_playback", lambda: played.append(1))
    assert controller.start_recording() is True
    pushed[0](RecordingResult(cancelled=True))
    assert played == []
    assert "Recording cancelled" in logs


# ---------------------------------------------------------------------------
# P2-H5: TUI runs carry the connected device's name, not the config default
# ---------------------------------------------------------------------------


@pytest.fixture
def _fresh_device_manager():
    from sandroid.core.device_manager import DeviceManager

    DeviceManager.reset()
    yield DeviceManager.get()
    DeviceManager.reset()


def _active_emulator(dm, avd_name: str = "SanDroid_-_API_35"):
    from sandroid.core.device import Device

    device = Device(serial="emulator-5554", name=avd_name, model="sdk_gphone64")
    device._avd_name_fetched = True
    dm._devices = {device.serial: device}
    dm._active_device = device
    return device


def test_playback_run_records_the_active_device_name(
    monkeypatch, tmp_path, _fresh_device_manager
):
    """Toolbox.device_name kept the hard-coded default when the device was
    activated without passing through the name sync (old build / any path
    that bypasses set_active_device); the run must still be labelled with
    the device it ran on.
    """
    from sandroid.services import get_session_state_service

    _active_emulator(_fresh_device_manager)
    state = get_session_state_service()
    monkeypatch.setattr(state, "_device_name", "Pixel_6_Pro_API_31")

    class _SessionNamedToolbox(_FakeToolboxBase):
        # Like the real Toolbox: device_name is the session state's value.
        @property
        def device_name(self):
            return state.device_name

    controller, _toolbox, _forensic = _playback_controller(
        monkeypatch, tmp_path, toolbox=_SessionNamedToolbox()
    )

    controller._run_playback_analysis()

    index = run_history.load_index()
    assert [e["device_name"] for e in index] == ["SanDroid_-_API_35"]
    assert not index[0].get("error")
    assert state.device_name == "SanDroid_-_API_35"
    import json

    summary = json.loads((tmp_path / "sandroid.json").read_text())
    assert summary["Device Name"] == "SanDroid_-_API_35"


def test_playback_falls_back_to_toolbox_name_without_device(
    monkeypatch, tmp_path, _fresh_device_manager
):
    controller, toolbox, _forensic = _playback_controller(monkeypatch, tmp_path)
    controller._run_playback_analysis()
    assert [e["device_name"] for e in run_history.load_index()] == ["fake-device"]


def test_verify_snapshot_uses_android_avd_home_and_active_avd(
    monkeypatch, tmp_path, _fresh_device_manager
):
    _active_emulator(_fresh_device_manager)
    avd_home = tmp_path / "avdhome"
    (avd_home / "SanDroid_-_API_35.avd" / "snapshots" / "tmp").mkdir(parents=True)
    monkeypatch.setenv("ANDROID_AVD_HOME", str(avd_home))
    controller, toolbox, _forensic = _playback_controller(monkeypatch, tmp_path)
    toolbox.device_name = "Pixel_6_Pro_API_31"
    assert controller._verify_snapshot() is True


def test_verify_snapshot_follows_avd_ini_path_redirect(
    monkeypatch, tmp_path, _fresh_device_manager
):
    _active_emulator(_fresh_device_manager)
    avd_home = tmp_path / "avdhome"
    avd_home.mkdir()
    real_dir = tmp_path / "elsewhere" / "custom.avd"
    (real_dir / "snapshots" / "tmp").mkdir(parents=True)
    (avd_home / "SanDroid_-_API_35.ini").write_text(f"path={real_dir}\n")
    monkeypatch.setenv("ANDROID_AVD_HOME", str(avd_home))
    controller, _toolbox, _forensic = _playback_controller(monkeypatch, tmp_path)
    assert controller._verify_snapshot() is True
