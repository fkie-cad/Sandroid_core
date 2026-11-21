"""Regression tests for the phase-2 live-test findings in the TUI recording flow.

Each test reproduces one finding from ``FINDINGS_phase2.md`` (P2-H1, P2-H2,
P2-H5 and the key-collision / stale-Spotlight mediums) without a device:
Textual pilots for the UI parts, plain fakes for the controller parts.
"""

from __future__ import annotations

import os
import threading
from types import SimpleNamespace

import pytest
from pilot_helpers import settle, until
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
        await until(pilot, lambda: view._detail_record is not None)
        await until(pilot, lambda: table.row_count == 1)
        monkeypatch.setattr(view, "_is_on_screen", lambda: True)

        callbacks = [cb for _etype, cb in view._event_handlers]
        assert callbacks, "DiffsView must subscribe to STATE_CHANGED"
        worker = threading.Thread(target=callbacks[0], args=(None,))
        worker.start()
        worker.join()
        await settle(pilot)

        assert app._exception is None
        assert table.row_count == 1


# ---------------------------------------------------------------------------
# P2-H1: persistence must not depend on UI updates
# ---------------------------------------------------------------------------


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
    # 1 event a minute: only a cancel that cuts the wait short ends it soon.
    rec.write_text(
        "".join(
            f"{1000 + i * 60_000}.0 /dev/input/event1 3 53 {i}\n" for i in range(50)
        )
    )
    sent: list[str] = []
    first = threading.Event()

    def send(cls, cmd, **kw):
        sent.append(cmd)
        first.set()

    monkeypatch.setattr(Adb, "send_adb_command", classmethod(send))
    monkeypatch.setattr("sandroid.core.toolbox.Toolbox.set_action_time", lambda: None)

    errors: list[BaseException] = []

    def replay() -> None:
        try:
            Player(recording_path=str(rec)).perform()
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=replay, daemon=True)
    worker.start()
    assert first.wait(10.0)  # the first event is out; now waiting a minute
    Player.cancel_all()
    worker.join(timeout=10.0)

    assert not worker.is_alive()  # the minute's wait was cut short
    assert len(sent) == 1
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
        await until(pilot, lambda: view.query_one("#runs-table").row_count == 1)
        # The lens itself, not its runs table.
        super(DiffsView, view).focus()
        await pilot.pause()
        await pilot.press("n")
        await settle(pilot)
        assert app.install_calls == 1
        assert type(app.screen).__name__ != "InputModal"


@pytest.mark.asyncio
async def test_rename_of_a_path_like_label_needs_explicit_confirm(results_root) -> None:
    """The tester's APK path typed after `n` became the run label at once."""
    from textual.widgets import Input

    run_id = "20261116_100000_aaaaaa"
    _save_run(run_id, label="Run A")
    app = _DiffsWithGlobalN()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await until(pilot, lambda: view._detail_record is not None)
        view.focus()  # the Runs rail with the run highlighted
        await pilot.pause()
        await pilot.press("n")
        await until(pilot, lambda: type(app.screen).__name__ == "InputModal")
        app.screen.query_one(Input).value = "/tmp/wikipedia.apk"
        await pilot.press("enter")
        await until(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        assert run_history.load_run(run_id).label == "Run A"
        assert "apk" in str(app.screen.query("Label").last().render()).lower()
        await pilot.press("n")  # No
        await settle(pilot)
        assert run_history.load_run(run_id).label == "Run A"

        view.focus()
        await pilot.pause()
        await pilot.press("n")
        await until(pilot, lambda: type(app.screen).__name__ == "InputModal")
        app.screen.query_one(Input).value = "Bookmark article"
        # N4-V3: a plain label is applied on Enter (no second Yes/No).
        await pilot.press("enter")
        await until(
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


def test_every_snapshot_load_drops_frida_handles_and_pid(monkeypatch, tmp_path):
    """Play's (and every other) snapshot load kills every app process and the
    frida device. The cached JobManager.device made every later spawn fail
    with "device is gone" until the TUI was restarted, and Spotlight kept the
    dead PID. EmulatorService.load_snapshot now drops both for every caller
    (TUI, Play's engine, AI, headless), not only the TUI paths.
    """
    from sandroid.services import emulator_service as es

    jm, frida_svc, spot = _fake_frida_and_spotlight(monkeypatch)

    class _Adb:
        def send_telnet_command(self, command, serial=None):
            return "OK\n", ""

        def send_adb_command(self, command, serial=None):
            return ("device\n", "") if command == "get-state" else ("", "")

        def get_target_device(self):
            return "emu-1"

    svc = es.EmulatorService()
    svc._get_adb = lambda: _Adb()
    monkeypatch.setattr(svc, "_restore_device_proxy", lambda serial: "none")
    monkeypatch.setattr(svc, "_restore_selinux_permissive", lambda adb, serial: True)
    monkeypatch.setattr(svc, "_record_device_clock", lambda adb, name, serial: None)
    monkeypatch.setattr(es, "_auto_start_frida_after_load", lambda serial: None)
    monkeypatch.setattr(es, "is_active_serial", lambda serial: serial == "emu-1")
    from sandroid.services import proxy_restore

    monkeypatch.setattr(proxy_restore, "restore_proxy_infra", lambda *a, **k: None)

    assert svc.load_snapshot("tmp", serial="emu-1") is True

    assert jm.device is None
    assert jm.reset_calls == 1
    assert frida_svc.invalidated >= 1
    assert spot.pid is None


def test_snapshot_reset_helper_never_raises(monkeypatch):
    from sandroid import services
    from sandroid.services.emulator_service import (
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
        fake_spotlight = SimpleNamespace(
            set_pid=lambda pid, **_kw: setattr(spot, "pid", pid),
            selection_epoch=lambda: 0,
        )
        monkeypatch.setattr(panel, "_spotlight", lambda: fake_spotlight)
        monkeypatch.setattr(
            panel,
            "_run_frida_action",
            lambda work, label, feature: started.append(label),
        )
        panel.action_primary()
        await until(pilot, lambda: started == ["start"])
        assert spot.pid is None

        # A live app is still reported as running (no second spawn).
        pids["org.wikipedia"] = 4242
        spot.pid = 4242
        started.clear()
        panel.action_primary()
        await settle(pilot)
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


# ---------------------------------------------------------------------------
# Fix round 3c: labels, phases, flows stored in the run bundle
# ---------------------------------------------------------------------------


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
