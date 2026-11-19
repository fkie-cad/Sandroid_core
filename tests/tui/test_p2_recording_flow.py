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
    device poll, recording start, ...) re-renders the Runs table. The old
    DiffView mount ran in the publisher's empty contextvars context and
    crashed the whole TUI with NoActiveAppError.
    """
    _save_run("20261116_100000_aaaaaa")
    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        table = view.query_one("#runs-table")
        await _wait_for(pilot, lambda: view._detail_record is not None)
        await _wait_for(pilot, lambda: table.row_count == 1)
        monkeypatch.setattr(view, "_is_on_screen", lambda: True)

        callbacks = [cb for _etype, cb in view._event_handlers]
        assert callbacks, "DiffsView must subscribe to STATE_CHANGED"
        worker = threading.Thread(target=callbacks[0], args=(None,))
        worker.start()
        worker.join()
        await pilot.pause(0.2)

        assert app._exception is None
        assert table.row_count == 1


# ---------------------------------------------------------------------------
# P2-H1: persistence must not depend on UI updates
# ---------------------------------------------------------------------------


class _FakeToolboxBase:
    def load_snapshot(self, tag) -> None:
        pass

    def create_snapshot(self, tag) -> None:
        pass

    def fetch_changed_files(self, fetch_all: bool = False) -> dict:
        # The engine refuses an empty baseline (a failed scan), so the
        # full-filesystem listing is never empty.
        return {"/data/baseline.db": 1} if fetch_all else {}


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


class _RestartingWrapper(_FakeWrapper):
    """The shared getevent is restarting: not running, lease still held."""

    is_running = False
    holds_lease = True

    def stop(self) -> int:
        self.holds_lease = False
        return super().stop()


@pytest.mark.asyncio
async def test_discard_releases_the_lease_while_getevent_restarts() -> None:
    """``_cancel`` gated on ``is_running`` and leaked the getevent lease
    during the stream's restart back-off.
    """
    from sandroid.tui.modals.recording_modal import RecordingModal

    app = App()
    results: list = []
    async with app.run_test() as pilot:
        modal = RecordingModal()
        await app.push_screen(modal, results.append)
        await pilot.pause()
        wrapper = _RestartingWrapper()
        modal._wrapper = wrapper
        modal._cancel()
        await pilot.pause()
    assert wrapper.stopped
    assert results[0].cancelled is True


@pytest.mark.asyncio
async def test_live_events_never_wait_for_the_ui_thread(monkeypatch) -> None:
    """The live display used the blocking ``call_from_thread`` on the shared
    getevent reader; now it posts and returns at once.
    """
    from textual.widgets import Static

    from sandroid.tui.modals.recording_modal import RecordingModal

    app = App()
    async with app.run_test() as pilot:
        modal = RecordingModal()
        await app.push_screen(modal)
        await pilot.pause()
        modal.show_live_events = True

        def forbidden(*_a, **_k):
            raise AssertionError("blocking call_from_thread")

        monkeypatch.setattr(app, "call_from_thread", forbidden)
        took: list[float] = []

        def reader() -> None:
            t0 = time.monotonic()
            for i in range(50):
                modal._on_event(f"/dev/input/event1: 0003 0035 {i:08x}")
            took.append(time.monotonic() - t0)

        t = threading.Thread(target=reader)
        t.start()
        t.join(2.0)
        await pilot.pause()
        await pilot.pause()
        text = str(modal.query_one("#live-events-log", Static).render())
    assert took
    assert took[0] < 0.5
    assert "00000031" in text  # the last line made it to the display


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


# ---------------------------------------------------------------------------
# M: key collisions (Diffs rename, Esc)
# ---------------------------------------------------------------------------


class _DiffsWithGlobalN(App):
    """DiffsView under an app that binds n globally (Install APK), like
    SandroidTUI.
    """

    BINDINGS = [("n", "install_apk", "Install APK")]

    def __init__(self) -> None:
        super().__init__()
        self.install_calls = 0

    def compose(self) -> ComposeResult:
        yield DiffsView(id="files-diffs")

    def action_install_apk(self) -> None:
        self.install_calls += 1


@pytest.mark.asyncio
async def test_n_without_a_focused_run_reaches_the_global_binding(
    results_root,
) -> None:
    _save_run("20261116_100000_aaaaaa", label="Run A")
    app = _DiffsWithGlobalN()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await _wait_for(pilot, lambda: view.query_one("#runs-table").row_count == 1)
        # The lens itself, not its runs table.
        super(DiffsView, view).focus()
        await pilot.pause()
        await pilot.press("n")
        await pilot.pause(0.1)
        assert app.install_calls == 1
        assert type(app.screen).__name__ != "InputModal"


@pytest.mark.asyncio
async def test_rename_needs_explicit_confirm(results_root) -> None:
    """The tester's APK path typed after `n` became the run label at once."""
    from textual.widgets import Input

    run_id = "20261116_100000_aaaaaa"
    _save_run(run_id, label="Run A")
    app = _DiffsWithGlobalN()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await _wait_for(pilot, lambda: view._detail_record is not None)
        view.focus()  # the Runs rail with the run highlighted
        await pilot.pause()
        await pilot.press("n")
        await _wait_for(pilot, lambda: type(app.screen).__name__ == "InputModal")
        app.screen.query_one(Input).value = "/tmp/wikipedia.apk"
        await pilot.press("enter")
        await _wait_for(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        assert run_history.load_run(run_id).label == "Run A"
        assert "apk" in str(app.screen.query("Label").last().render()).lower()
        await pilot.press("n")  # No
        await pilot.pause(0.2)
        assert run_history.load_run(run_id).label == "Run A"

        view.focus()
        await pilot.pause()
        await pilot.press("n")
        await _wait_for(pilot, lambda: type(app.screen).__name__ == "InputModal")
        app.screen.query_one(Input).value = "Bookmark article"
        await pilot.press("enter")
        await _wait_for(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        await pilot.press("y")
        await _wait_for(
            pilot, lambda: run_history.load_run(run_id).label == "Bookmark article"
        )
        assert app.install_calls == 0


def test_escape_on_main_screen_never_opens_quit() -> None:
    from sandroid.tui.controllers.quit_controller import QuitController

    pushed: list = []
    notes: list[str] = []
    screen = SimpleNamespace(
        focused=None, app=SimpleNamespace(notify=lambda msg, **kw: notes.append(msg))
    )
    qc = QuitController(
        push_modal=lambda modal, cb: pushed.append(modal),
        is_main_screen=lambda: True,
        get_current_screen=lambda: screen,
        get_screen_stack=lambda: [object(), screen],
    )
    qc.maybe_quit()
    assert pushed == []
    assert any("q" in n for n in notes)


@pytest.mark.asyncio
async def test_escape_in_a_main_screen_input_leaves_the_input_not_the_app() -> None:
    from textual.widgets import Input

    from sandroid.tui.controllers.quit_controller import QuitController

    class _Harness(App):
        BINDINGS = [("escape", "maybe_quit", "Back")]

        def compose(self) -> ComposeResult:
            yield Input(id="field")

        def on_mount(self) -> None:
            self.pushed: list = []
            self.qc = QuitController(
                push_modal=lambda modal, cb: self.pushed.append(modal),
                is_main_screen=lambda: True,
                get_current_screen=lambda: self.screen,
                get_screen_stack=lambda: self.screen_stack,
            )

        def action_maybe_quit(self) -> None:
            self.qc.maybe_quit()

    app = _Harness()
    async with app.run_test() as pilot:
        app.query_one("#field", Input).focus()
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        assert app.pushed == []
        assert app.focused is None


# ---------------------------------------------------------------------------
# M: stale Spotlight PID / "device is gone" after Record/Play
# ---------------------------------------------------------------------------


class _FakeJobManager:
    def __init__(self) -> None:
        self.device = object()  # a frida Device the snapshot load invalidated
        self.pid = 7875
        self.reset_calls = 0

    def reset_session(self, timeout_per_job: float = 2.0, detach_timeout=2.0):
        self.reset_calls += 1
        self.pid = -1


def _fake_frida_and_spotlight(monkeypatch):
    from sandroid import services

    jm = _FakeJobManager()
    frida_svc = SimpleNamespace(_job_manager=jm, invalidated=0)

    def invalidate() -> None:
        frida_svc.invalidated += 1

    frida_svc.invalidate_frida_device_cache = invalidate
    spot = SimpleNamespace(pid=7875, events=0)
    spot.set_pid = lambda pid: setattr(spot, "pid", pid)

    def publish(*_args, **_kwargs) -> None:
        spot.events += 1

    spot.get_effective_package = lambda: "org.wikipedia"
    spot.publish_state_refresh = publish
    monkeypatch.setattr(services, "get_frida_session_service", lambda: frida_svc)
    monkeypatch.setattr(services, "get_spotlight_service", lambda: spot)
    return jm, frida_svc, spot


def test_playback_drops_frida_handles_and_pid_invalidated_by_the_revert(
    monkeypatch, tmp_path
):
    """Play's snapshot loads kill every app process and the frida device.

    The cached JobManager.device made every later spawn fail with "device is
    gone" until the TUI was restarted, and Spotlight kept the dead PID.
    """
    jm, frida_svc, spot = _fake_frida_and_spotlight(monkeypatch)
    controller, _toolbox, _forensic = _playback_controller(monkeypatch, tmp_path)

    controller._run_playback_analysis()

    assert jm.device is None
    assert jm.reset_calls == 1
    assert frida_svc.invalidated >= 1
    assert spot.pid is None


def test_snapshot_reset_helper_never_raises(monkeypatch):
    from sandroid import services
    from sandroid.tui.controllers.recording_controller import (
        reset_device_handles_after_snapshot_load,
    )

    def boom():
        raise RuntimeError("no service")

    monkeypatch.setattr(services, "get_frida_session_service", boom)
    monkeypatch.setattr(services, "get_spotlight_service", boom)
    reset_device_handles_after_snapshot_load()


@pytest.mark.asyncio
async def test_enter_on_spotlight_with_a_stale_pid_rechecks_and_starts(
    monkeypatch,
) -> None:
    """Enter said 'Already running' for a dead app until the slow poll ran."""
    from sandroid.core.adb import Adb
    from sandroid.tui.widgets.spotlight_panel import SpotlightPanel

    pids: dict[str, int | None] = {"org.wikipedia": None}
    monkeypatch.setattr(
        Adb,
        "get_pid_for_package_name",
        classmethod(lambda cls, pkg, **kw: pids.get(pkg)),
    )
    spot = SimpleNamespace(pid=7875)

    class _Harness(App):
        def compose(self) -> ComposeResult:
            yield SpotlightPanel(id="spotlight-panel")

    started: list[str] = []
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(SpotlightPanel)
        monkeypatch.setattr(panel, "_current_package", lambda: "org.wikipedia")
        monkeypatch.setattr(panel, "_safe_pid", lambda: spot.pid)
        monkeypatch.setattr(panel, "_is_paused", lambda: False)
        fake_spotlight = SimpleNamespace(set_pid=lambda pid: setattr(spot, "pid", pid))
        monkeypatch.setattr(panel, "_spotlight", lambda: fake_spotlight)
        monkeypatch.setattr(
            panel,
            "_run_frida_action",
            lambda work, label, feature: started.append(label),
        )
        panel.action_primary()
        await _wait_for(pilot, lambda: started == ["start"])
        assert spot.pid is None

        # A live app is still reported as running (no second spawn).
        pids["org.wikipedia"] = 4242
        spot.pid = 4242
        started.clear()
        panel.action_primary()
        await pilot.pause(0.3)
        assert started == []
        assert spot.pid == 4242


@pytest.mark.parametrize(
    ("is_lost", "session", "dropped"),
    [(True, object(), True), (False, None, True), (False, object(), False)],
)
def test_drop_stale_frida_device(monkeypatch, is_lost, session, dropped):
    from sandroid import services
    from sandroid.tui.controllers.recording_controller import (
        drop_stale_frida_device,
    )

    jm = SimpleNamespace(
        device=SimpleNamespace(is_lost=is_lost), process_session=session
    )
    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(_job_manager=jm),
    )
    assert drop_stale_frida_device() is dropped
    assert (jm.device is None) is dropped


@pytest.mark.parametrize(("shown", "expected_polls"), [(True, 4), (False, 2)])
def test_spotlight_pid_poll_keeps_running_while_tab_is_hidden(
    monkeypatch, shown, expected_polls
) -> None:
    """Phase-4 5e: a dead attach PID stayed 'running' in the header while idle.

    The poll stopped whenever another tab was shown; now it continues there
    at half the rate.
    """
    from sandroid.tui.widgets.spotlight_panel import SpotlightPanel

    panel = SpotlightPanel(id="spotlight-panel")
    monkeypatch.setattr(panel, "_current_package", lambda: "org.wikipedia")
    monkeypatch.setattr(panel, "_is_active_child", lambda: shown)
    polls: list[str] = []

    def run_worker(work, name=None, **kw):
        polls.append(name)
        panel._poll_inflight = False  # the worker finished

    monkeypatch.setattr(panel, "run_worker", run_worker)

    for _ in range(4):
        panel._poll_running_state()

    assert polls == ["spotlight_pid_poll"] * expected_polls


def test_replay_of_a_recording_gets_a_distinct_run_label(monkeypatch) -> None:
    """Phase 4: a 'p' replay added a second 'Run 1 · 22:58' to the rail."""
    from sandroid.core import run_history
    from sandroid.tui.controllers import recording_controller as rc

    saved: list[dict] = []
    monkeypatch.setattr(
        run_history,
        "load_index",
        lambda device_name=None: [e for e in saved if e["device_name"] == device_name],
    )

    labels = []
    for device in ("emu", "emu", "emu", "other"):
        label = rc._unique_run_label("Run 1 · 22:58", device)
        saved.append({"label": label, "device_name": device})
        labels.append(label)

    assert labels == [
        "Run 1 · 22:58",
        "Run 1 · 22:58 · play 2",
        "Run 1 · 22:58 · play 3",
        "Run 1 · 22:58",  # another device has its own rail
    ]


# ---------------------------------------------------------------------------
# Fix round 3c: labels, phases, flows stored in the run bundle
# ---------------------------------------------------------------------------


def test_manual_play_gets_a_fresh_label_not_the_previous_runs(monkeypatch, tmp_path):
    """M-31: a ``p`` run copied the previous Play's label ("Run 2 · 18:34")."""
    controller, _toolbox, _forensic = _playback_controller(monkeypatch, tmp_path)
    controller._current_recording_label = "Run 2 · 18:34"  # stale seed
    controller._play_label = None  # manual p
    controller._run_playback_analysis()
    controller._play_label = None
    controller._run_playback_analysis()
    labels = sorted(e["label"] for e in run_history.load_index())
    assert all("18:34" not in label for label in labels)
    assert [label.split(" · ")[0] for label in labels] == ["Run 1", "Run 2"]

    # The Play that auto-chains after a Record keeps the Record dialog's label.
    controller._play_label = "Bookmark article"
    controller._run_playback_analysis()
    assert "Bookmark article" in {e["label"] for e in run_history.load_index()}
    assert controller._play_label is None  # used once

    # R4-N3: after renaming that run, p's confirm named the recording by
    # its old label.
    controller._current_recording_label = "Bookmark article"
    run_id = next(
        e["run_id"]
        for e in run_history.load_index()
        if e["label"] == "Bookmark article"
    )
    run_history.update_label(run_id, "R4 renamed")
    assert controller.play_plan()["recording"] == "R4 renamed"


def test_cancelled_record_dialog_keeps_the_previous_recordings_seed(
    monkeypatch, tmp_path
):
    """M-31's cause: Esc in a second Record dialog replaced the seed label of
    the recording that ``p`` still replays.
    """
    from sandroid.tui.modals.recording_modal import RecordingResult

    pushed: list = []
    controller, _toolbox, _forensic = _playback_controller(
        monkeypatch, tmp_path, push_modal=lambda modal, cb: pushed.append(cb)
    )
    monkeypatch.setattr(controller, "start_playback", lambda label=None: True)
    controller.start_recording()
    pushed[-1](
        RecordingResult(
            cancelled=False,
            completed=True,
            label="Run 1 · 18:22",
            number_of_runs=3,
            noise_filter=True,
        )
    )
    controller.start_recording()
    pushed[-1](RecordingResult(cancelled=True))
    assert controller._current_recording_label == "Run 1 · 18:22"
    assert controller._current_number_of_runs == 3
    assert controller._recording_seq == 1


def test_run_labels_count_the_devices_runs_and_use_the_play_start(
    monkeypatch, tmp_path
):
    """R4-N2: the Record dialog proposed "Run 1" in every new session (a
    per-session counter), so two runs were called "Run 1 · …". R4-N4: a
    manual Play's label used the end of its analysis ("Run 4 · 00:21" for a
    Play started at 00:05).
    """
    from sandroid.core import run_history

    pushed: list = []
    controller, _toolbox, _forensic = _playback_controller(
        monkeypatch, tmp_path, push_modal=lambda modal, cb: pushed.append(cb)
    )
    monkeypatch.setattr(run_history, "load_index", lambda device=None: [1, 2, 3])
    controller.start_recording()
    assert controller._current_recording_label.startswith("Run 4 · ")
    assert (
        controller._fresh_run_label("dev", "2026-11-18T00:05:48.1") == "Run 4 · 00:05"
    )


def test_play_reports_phases_and_clears_them_at_the_end(monkeypatch, tmp_path):
    """M-35: the pill/strip get the Play's phase, and None when it is over."""
    phases: list = []
    controller, _toolbox, _forensic = _playback_controller(
        monkeypatch, tmp_path, set_replay_phase=phases.append
    )
    controller._current_number_of_runs = 2
    controller._run_playback_analysis()
    assert phases[0] == "starting"
    for expected in (
        "loading snapshot",
        "baseline scan",
        "replay 1/2",
        "replay 2/2",
        "dry run",
        "analysing",
        "saving",
    ):
        assert expected in phases
    # R4-N5: the pull of the original files right after a snapshot load
    # (before replay 2) read "collecting results".
    second = phases.index("replay 2/2")
    assert phases[second - 1] == "pulling original files"
    assert phases[-1] is None
    # The run records its phase windows (replays + dry run).
    record = run_history.load_run(run_history.load_index()[0]["run_id"])
    assert [(p["kind"], p["run"]) for p in record.phases] == [
        ("replay", 1),
        ("replay", 2),
        ("dry_run", 3),
    ]
    assert all(p["start"] <= p["end"] for p in record.phases)


def test_play_phase_cleared_even_when_the_engine_fails(monkeypatch, tmp_path):
    from sandroid.analysis import engine as engine_mod

    phases: list = []
    replay: list = []
    controller, _toolbox, _forensic = _playback_controller(
        monkeypatch,
        tmp_path,
        set_replay_phase=phases.append,
        set_replay_indicator=replay.append,
    )

    def boom(self):
        raise RuntimeError("adb went away")

    monkeypatch.setattr(engine_mod.AnalysisEngine, "run", boom)
    controller._run_playback_analysis()
    assert replay == [True, False]
    assert phases[-1] is None


def test_play_stores_the_runs_flows_in_its_bundle_under_the_manifest(
    monkeypatch, tmp_path
):
    """H-7: the flows go into <bundle>/network/ before SHA256SUMS is written."""
    import json
    import time as _time

    from sandroid.services import mitmproxy_flow_log

    session = tmp_path / "session" / "mitm_flows"
    session.mkdir(parents=True)
    now = _time.time()
    with open(session / "flows.jsonl", "w", encoding="utf-8") as f:
        for seq, ts in ((1, now + 0.5), (2, now - 3600)):  # in / out of the run
            f.write(
                json.dumps({"seq": seq, "id": f"f{seq}", "ts_start": ts, "ts_end": ts})
                + "\n"
            )
    monkeypatch.setattr(mitmproxy_flow_log, "resolve_flow_dir", lambda: session)
    controller, _toolbox, _forensic = _playback_controller(monkeypatch, tmp_path)
    controller._run_playback_analysis()

    bundle = next((tmp_path / "runs").glob("*/run.json")).parent
    rows = (bundle / "network" / "flows.jsonl").read_text().splitlines()
    assert [json.loads(r)["seq"] for r in rows] == [1]
    meta = json.loads((bundle / "network" / "meta.json").read_text())
    assert meta["count"] == 1
    sums = (bundle / "SHA256SUMS").read_text()
    assert "network/flows.jsonl" in sums
    assert "network/meta.json" in sums


def test_recording_seconds_reads_the_event_stamps(tmp_path):
    from sandroid.tui.controllers.recording_controller import RecordingController

    rec = tmp_path / "recording.txt"
    rec.write_text(
        "1794936192074 /dev/input/event1 0 0 0\n"
        "1794936201188 /dev/input/event1 3 57 7\n"
        "1794936277074 /dev/input/event1 0 0 0\n"
    )
    assert RecordingController.recording_seconds(str(rec)) == 85.0
    assert RecordingController.recording_seconds(str(tmp_path / "none")) is None
    # Record's raw getevent slice (device seconds)
    new = tmp_path / "recording.getevent.txt"
    new.write_text(
        "[   26404.737324] /dev/input/event1: 0003 0039 00000000\n"
        "[   26404.737324] /dev/input/event1: 0000 0000 00000000\n"
        "[   26489.737324] /dev/input/event1: 0003 0039 ffffffff\n"
    )
    assert RecordingController.recording_seconds(str(new)) == pytest.approx(85.0)


def test_recorder_writes_recording_getevent_txt(monkeypatch, tmp_path):
    """Record (modal + chat) writes recording.getevent.txt, never recording.txt."""
    from sandroid.tui.controllers.recording_controller import RecordingController

    monkeypatch.setenv("RAW_RESULTS_PATH", str(tmp_path) + "/")
    controller = RecordingController()
    assert controller.get_recording_path().endswith("/recording.getevent.txt")
    assert controller.has_recording() is False
    (tmp_path / "recording.getevent.txt").write_text("")
    assert controller.has_recording() is True
