"""Safety round 4: App-lens Kill/Restart guards, quit dialog focus, SELinux
restore on quit, lazily created result folders.

No device: adb is faked (or blocked by the suite's guard).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pilot_helpers import boot, settle, until

SIZE = (200, 50)
PKG = "org.example.app"
SERIAL = "emulator-5554"


def _burst(app, *keys: str) -> None:
    """All keys queued at once, as a terminal delivers fast typing."""
    from textual import events

    app.KEY_SETTLE_SECONDS = 60.0  # never released early by a slow host
    for key in keys:
        app.post_message(events.Key(key, key if len(key) == 1 else None))


def _messages(app) -> list[str]:
    return [n.message for n in app._notifications]


# --------------------------------------------------------------------------
# 1. App lens: K asks first, R is not run inside the stray-typing window
# --------------------------------------------------------------------------


@pytest.fixture
def app_lens(monkeypatch):
    """The App lens with a spotlight app; Kill / Restart only recorded."""
    from sandroid.tui.widgets.spotlight_panel import SpotlightPanel

    ran: list[str] = []
    monkeypatch.setattr(SpotlightPanel, "_current_package", lambda self: PKG)
    monkeypatch.setattr(
        SpotlightPanel, "_run_action_bg", lambda self, work, label: ran.append(label)
    )
    monkeypatch.setattr(
        SpotlightPanel,
        "_run_frida_action",
        lambda self, work, label, feature: ran.append(label),
    )
    return ran


async def test_kill_asks_first_and_a_typed_ahead_y_is_ignored(
    app_lens, monkeypatch
) -> None:
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.modals import ConfirmModal

    # The typed-ahead y always lands inside the arm window, however slow the
    # host; the window's end is simulated below.
    monkeypatch.setattr(ConfirmModal, "ARM_SECONDS", 60.0)
    app = SandroidTUI()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await boot(app, pilot)
        # Focus is on the App lens or one of its section tables (K bubbles up).
        panel = app.screen.query_one("#spotlight-panel")
        assert app.focused is panel or panel in app.focused.ancestors
        _burst(app, "K", "y")
        await settle(pilot)
        modal = app.screen
        assert isinstance(modal, ConfirmModal)
        assert modal.guard_typing
        assert app.focused.id == "no"  # Enter declines
        assert app_lens == []  # the typed-ahead y did not confirm
        modal._opened_at -= 61.0  # the arm window is over
        await pilot.press("y")
        await settle(pilot)
        assert app_lens == ["kill"]
        assert type(app.screen).__name__ == "MainScreen"


async def test_kill_confirm_cancels_on_typing_and_on_enter(app_lens) -> None:
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await boot(app, pilot)
        _burst(app, "K", "x")
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert any("looked like typing" in m for m in _messages(app))
        app.screen._typing_until = 0.0
        await pilot.press("K")
        await settle(pilot)
        await pilot.press("enter")  # No has the focus
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert app_lens == []


async def test_restart_is_not_run_inside_the_stray_typing_window(
    monkeypatch, app_lens
) -> None:
    """``q x R`` in one burst: the quit is cancelled as typing and R, the rest
    of the word, does not restart the app (a notice says so).
    """
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await boot(app, pilot)
        ms = app.screen
        monkeypatch.setattr(app, "exit", lambda *a, **k: app_lens.append("exit"))
        _burst(app, "q", "x", "R")
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert app_lens == []
        assert any("Restart not run" in m for m in _messages(app))
        # Also when the action is reached another way (click on the cell).
        assert ms.typing_guard_active()
        ms.lens_widget().dispatch_action_cell("act-restart")
        assert app_lens == []
        # The window is over: R restarts without a dialog.
        ms._typing_until = 0.0
        await pilot.press("R")
        await settle(pilot)
        assert app_lens == ["restart"]
        assert type(app.screen).__name__ == "MainScreen"


# --------------------------------------------------------------------------
# 2. Quit dialog: Cancel focused (and shown so), Enter still quits
# --------------------------------------------------------------------------


async def test_quit_dialog_focuses_cancel_and_enter_still_quits(monkeypatch) -> None:
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.controllers import quit_controller as qc

    app = SandroidTUI()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        cleaned: list[int] = []
        monkeypatch.setattr(
            app._quit_controller, "force_exit", lambda: cleaned.append(1)
        )
        monkeypatch.setattr(qc.QuitController, "_quit_notes", staticmethod(list))
        await pilot.press("q")
        await settle(pilot)
        modal = app.screen
        assert type(modal).__name__ == "QuitConfirmModal"
        cancel = modal.query_one("#btn-cancel")
        quit_button = modal.query_one("#btn-quit")
        assert app.focused is cancel
        # The highlight is on Cancel, not on Quit.
        assert cancel.styles.background != quit_button.styles.background
        assert str(cancel.styles.text_style) == "bold"
        await pilot.press("enter")
        await until(pilot, lambda: app._exit)
        assert cleaned == [1]
        assert app._exit


# --------------------------------------------------------------------------
# 3. SELinux: the mode found first is restored on quit
# --------------------------------------------------------------------------


class _SelinuxAdb:
    """getenforce answers the mode; setenforce 0/1 sets it; ``gone`` = no device."""

    def __init__(self, mode: str):
        self.mode = mode
        self.gone = False
        self.calls: list[str] = []

    def send_adb_command(self, command: str, serial=None, timeout=30):
        self.calls.append(command)
        if self.gone:
            return "", f"adb: device '{SERIAL}' not found"
        if command == "shell getenforce":
            return self.mode + "\n", ""
        if command.endswith("setenforce 0"):
            self.mode = "Permissive"
        elif command.endswith("setenforce 1"):
            self.mode = "Enforcing"
        return "", ""


@pytest.fixture
def selinux(monkeypatch):
    from sandroid.core.adb import Adb
    from sandroid.services import setup_checks

    monkeypatch.setattr(setup_checks, "_selinux_found", {})
    monkeypatch.setattr(setup_checks, "_selinux_changed", set())
    monkeypatch.setattr(Adb, "get_target_device", classmethod(lambda cls: SERIAL))
    return setup_checks


def test_selinux_changed_at_startup_is_restored_on_quit(selinux, caplog) -> None:
    """Also when a snapshot load brought Enforcing back in between."""
    import logging

    from sandroid.services.emulator_service import EmulatorService

    adb = _SelinuxAdb("Enforcing")
    assert selinux.check_and_set_selinux(adb).passed
    adb.mode = "Enforcing"  # a snapshot saved before startup's setenforce 0
    assert EmulatorService()._restore_selinux_permissive(adb, SERIAL)
    assert adb.mode == "Permissive"
    with caplog.at_level(logging.INFO, logger="sandroid.services.setup_checks"):
        assert selinux.restore_selinux_on_quit(adb) == [SERIAL]
    assert adb.mode == "Enforcing"
    assert "shell setenforce 1" in adb.calls
    (line,) = [
        r.getMessage() for r in caplog.records if "restore on quit" in r.getMessage()
    ]
    assert f"on {SERIAL}: Permissive -> Enforcing" in line
    # Done once: a second quit path does nothing more.
    adb.calls.clear()
    assert selinux.restore_selinux_on_quit(adb) == []
    assert adb.calls == []


def test_selinux_found_permissive_is_left_alone(selinux) -> None:
    adb = _SelinuxAdb("Permissive")
    assert selinux.check_and_set_selinux(adb).passed
    adb.calls.clear()
    assert selinux.restore_selinux_on_quit(adb) == []
    assert adb.calls == []
    assert adb.mode == "Permissive"


def test_selinux_found_permissive_stays_after_a_snapshot_flip(selinux) -> None:
    """Found Permissive; a snapshot made it Enforcing and Sandroid set it back:
    the mode found first is Permissive, so quitting changes nothing.
    """
    from sandroid.services.emulator_service import EmulatorService

    adb = _SelinuxAdb("Permissive")
    assert selinux.check_and_set_selinux(adb).passed
    adb.mode = "Enforcing"
    assert EmulatorService()._restore_selinux_permissive(adb, SERIAL)
    assert selinux.restore_selinux_on_quit(adb) == []
    assert adb.mode == "Permissive"


def test_selinux_restore_skips_a_device_that_is_gone(selinux, caplog) -> None:
    import logging

    adb = _SelinuxAdb("Enforcing")
    assert selinux.check_and_set_selinux(adb).passed
    adb.gone = True
    with caplog.at_level(logging.WARNING):
        assert selinux.restore_selinux_on_quit(adb) == []
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert not any("setenforce 1" in c for c in adb.calls)


class _MarkerAdb(_SelinuxAdb):
    """Also keeps the on-device marker file and a boot id."""

    def __init__(self, mode: str, boot: str = "boot-1"):
        super().__init__(mode)
        self.boot = boot
        self.marker: str | None = None

    def send_adb_command(self, command: str, serial=None, timeout=30):
        from sandroid.services.setup_checks import SELINUX_MARKER

        if SELINUX_MARKER in command and "mkdir" in command:
            self.calls.append(command)
            self.marker = f"Enforcing {self.boot}"
            return "", ""
        if command.startswith("shell 'cat " + SELINUX_MARKER):
            self.calls.append(command)
            return f"{self.marker or ''}\n{self.boot}\n", ""
        if command == f"shell rm -f {SELINUX_MARKER}":
            self.calls.append(command)
            self.marker = None
            return "", ""
        return super().send_adb_command(command, serial, timeout)


def test_selinux_after_a_crash_is_restored_by_the_next_session(selinux) -> None:
    """N4: a crash left Permissive; the next session took Permissive as the
    original state. The on-device marker (same boot) says Enforcing.
    """
    adb = _MarkerAdb("Enforcing")
    assert selinux.check_and_set_selinux(adb).passed
    assert adb.marker == "Enforcing boot-1"
    # Crash: no restore. A new session starts with fresh state.
    selinux._selinux_found.clear()
    selinux._selinux_changed.clear()
    assert selinux.check_and_set_selinux(adb).passed
    assert adb.mode == "Permissive"
    assert selinux.restore_selinux_on_quit(adb) == [SERIAL]
    assert adb.mode == "Enforcing"
    assert adb.marker is None  # removed by the restore


def test_selinux_marker_from_another_boot_is_ignored(selinux) -> None:
    adb = _MarkerAdb("Permissive", boot="boot-2")
    adb.marker = "Enforcing boot-1"
    assert selinux.check_and_set_selinux(adb).passed
    assert selinux.restore_selinux_on_quit(adb) == []
    assert adb.mode == "Permissive"


def test_post_tui_cleanup_restores_selinux(monkeypatch) -> None:
    """A crash skips the quit dialog's restore; run_tui's finally does it."""
    from sandroid.services import setup_checks
    from sandroid.tui import launcher

    called: list[int] = []
    monkeypatch.setattr(
        setup_checks, "restore_selinux_on_quit", lambda: called.append(1) or []
    )
    services = SimpleNamespace(stop_all=lambda: None, is_capturing=lambda: False)
    launcher._shutdown_services(lambda: services, lambda: services, "crash")
    assert called == [1]


def test_quit_cleanup_restores_selinux_before_timeline_close(monkeypatch) -> None:
    from sandroid.services import setup_checks
    from sandroid.tui.controllers import quit_controller as qc

    steps: list[str] = []
    monkeypatch.setattr(qc, "shutdown_network", lambda timeout=0: None)
    monkeypatch.setattr(
        qc, "run_bounded", lambda name, fn, timeout: steps.append(name) or True
    )
    monkeypatch.setattr(setup_checks, "restore_selinux_on_quit", list)
    fake = SimpleNamespace(
        _stop_frida_sessions=lambda: None,
        _cleanup_rest=lambda: steps.append("rest"),
    )
    qc.QuitController.force_exit(fake)
    # The timeline is closed last so the SELinux restore is still recorded.
    assert steps[-1] == "timeline close"
    assert steps.index("rest") < steps.index("SELinux restore")
    assert steps.index("SELinux restore") < steps.index("timeline close")


def test_quit_closes_the_device_clock_shell_before_the_untracked_check(
    monkeypatch,
) -> None:
    """N1-B8: the device clock's persistent "adb shell" was reported as an
    untracked "ADB Command" and force-killed on every quit.
    """
    from sandroid.core import device_clock
    from sandroid.services import setup_checks
    from sandroid.tui.controllers import quit_controller as qc

    steps: list[str] = []
    monkeypatch.setattr(qc, "shutdown_network", lambda timeout=0: None)

    def _run(name, fn, timeout):
        if name == "device clock shells":
            fn()
        steps.append(name)
        return True

    monkeypatch.setattr(qc, "run_bounded", _run)
    monkeypatch.setattr(setup_checks, "restore_selinux_on_quit", list)
    monkeypatch.setattr(device_clock, "close_shells", lambda: steps.append("closed"))
    fake = SimpleNamespace(
        _stop_frida_sessions=lambda: None,
        _cleanup_rest=lambda: steps.append("rest"),  # the untracked check
    )
    qc.QuitController.force_exit(fake)
    assert "closed" in steps
    assert steps.index("closed") < steps.index("rest")


# --------------------------------------------------------------------------
# 4. Result folders are created by their writers, not with the session
# --------------------------------------------------------------------------

_LAZY = (
    "dexray_insight",
    "fritap",
    "forensic_apks",
    "spotlight_files",
    "raw/first_pull",
    "raw/second_pull",
    "raw/noise_pull",
    "raw/new_pull",
    "raw/network_trace_pull",
    "raw/screenshots",
    "raw/spotlight_files",
)


@pytest.fixture
def env(monkeypatch):
    for name in ("SESSION_PATH", "RESULTS_PATH", "RAW_RESULTS_PATH"):
        monkeypatch.delenv(name, raising=False)


def test_a_fresh_device_folder_has_no_empty_subfolders(tmp_path, env) -> None:
    from sandroid.services.initialization_service import InitializationService

    service = InitializationService(base_path=tmp_path)
    service.create_session(timestamp="s1", setup_logging=False)
    device = service.create_device_folder("Pixel")
    assert (device / "raw").is_dir()
    assert [p for p in _LAZY if (device / p).exists()] == []
    # Switching back to it (no clean) creates none either.
    service.switch_device("Pixel")
    assert [p for p in _LAZY if (device / p).exists()] == []


def test_configuration_switch_device_creates_no_empty_subfolders(
    tmp_path, env, monkeypatch
) -> None:
    from pathlib import Path

    from sandroid.services.configuration_service import ConfigurationService

    monkeypatch.chdir(tmp_path)
    service = ConfigurationService()
    device = Path(service.switch_device("Pixel"))
    assert (device / "raw").is_dir()
    assert [p for p in _LAZY if (device / p).exists()] == []


def test_writers_create_their_own_folder_and_readers_take_none_as_empty(
    tmp_path, env, monkeypatch
) -> None:
    from sandroid.analysis.network import Network
    from sandroid.services.file_extraction_service import FileExtractionService
    from sandroid.services.initialization_service import InitializationService

    service = InitializationService(base_path=tmp_path)
    service.create_session(timestamp="s1", setup_logging=False)
    device = service.create_device_folder("Pixel")

    # Readers: a missing folder is empty.
    extraction = FileExtractionService(results_path=str(device) + "/")
    hashes = extraction.calculate_hashes()
    assert hashes["new_file_hashes"] == {}
    assert hashes["changed_file_hashes(old,new)"] == {}
    assert Network.__new__(Network)._run_pcap_paths() == []

    # A writer creates its own folder (and only that one).
    pulled: list[str] = []

    class _Adb:
        def send_adb_command(self, command, serial=None, timeout=30):
            pulled.append(command)
            return "1 file pulled", ""

    monkeypatch.setattr(extraction, "_get_adb", lambda: _Adb())
    extraction.pull_file_legacy("first", "/data/data/x/databases/a.db")
    assert pulled
    assert (device / "raw" / "first_pull" / "data/data/x/databases").is_dir()
    assert [p for p in _LAZY if (device / p).exists()] == ["raw/first_pull"]

    extraction.pull_spotlight_files(["/data/x.db"])
    assert (device / "spotlight_files").is_dir()
