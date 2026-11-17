"""Startup: a missing ``--serial``, the error screen's keys, the exit path.

* the adb check must not call a missing *device* a missing *adb binary*
  (``sandroid -s emulator-5999`` said "ADB not found in PATH");
* the error screen owns its keys (``r`` retried *and* fired Record);
* ``r``/``R``, ``q``/``Q`` both work, ``d`` picks another device;
* quitting a failed start exits non-zero and drops an unused session folder.

All adb traffic goes to an in-process double; the suite-wide conftest blocks
real device access anyway.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from sandroid.services.setup_checks import (
    adb_binary_missing,
    check_adb_availability,
    check_device_connection,
    missing_device_serial,
)
from sandroid.services.setup_service import SetupCheckStatus, SetupService

SIZE = (160, 45)
MISSING = "emulator-5999"
PRESENT = "emulator-5554"


class FakeAdb:
    """adb double: ``emulator-5554`` is attached; ``target`` is the ``-s``."""

    def __init__(self, target: str | None = None, binary_missing: bool = False):
        self.target = target
        self.binary_missing = binary_missing
        self.calls: list[tuple[str, str | None]] = []

    def send_adb_command(self, command, serial=None, timeout=30):
        self.calls.append((command, serial))
        if self.binary_missing:
            return "", "/bin/sh: /opt/sdk/platform-tools/adb: No such file or directory"
        target = self.target if serial is None else serial
        if target and target != PRESENT:
            return "", f"adb: device '{target}' not found"
        if command == "version":
            return "Android Debug Bridge version 1.0.41\nVersion 35.0.2\n", ""
        if command == "devices":
            return (
                f"List of devices attached\n{PRESENT}\tdevice\n"
                "emulator-5556\toffline\n\n",
                "",
            )
        return "", ""


class LegacyAdb:
    """An adb double without the ``serial`` keyword, pinned to a missing serial."""

    def send_adb_command(self, command):
        return "", f"adb: device '{MISSING}' not found"


# --------------------------------------------------------------------------
# setup checks
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("stderr", "serial"),
    [
        (f"adb: device '{MISSING}' not found", MISSING),
        (f"error: device '{MISSING}' not found", MISSING),
        ("error: device not found", ""),
        ("adb: no devices/emulators found", None),
        ("/bin/sh: adb: command not found", None),
        ("", None),
    ],
)
def test_missing_device_serial(stderr, serial) -> None:
    assert missing_device_serial(stderr) == serial


def test_device_error_is_never_a_missing_adb_binary() -> None:
    assert not adb_binary_missing(f"adb: device '{MISSING}' not found")
    assert not adb_binary_missing("error: device not found")
    assert adb_binary_missing("/bin/sh: adb: command not found")
    assert adb_binary_missing("zsh: no such file or directory: /x/adb")
    assert adb_binary_missing("OSError: [Errno 8] Exec format error")


def test_adb_check_runs_untargeted_with_a_missing_serial() -> None:
    adb = FakeAdb(target=MISSING)
    check = check_adb_availability(adb)
    assert check.status is SetupCheckStatus.PASSED
    assert adb.calls[0] == ("version", "")  # no "-s emulator-5999"
    assert check.details["version_info"].startswith("Android Debug Bridge")


def test_adb_check_does_not_blame_adb_for_a_missing_device() -> None:
    """The tester's case: ``adb -s emulator-5999 version`` -> device error."""
    check = check_adb_availability(LegacyAdb())
    assert check.status is SetupCheckStatus.PASSED
    assert "not found in PATH" not in check.message


def test_adb_check_still_reports_a_missing_binary() -> None:
    check = check_adb_availability(FakeAdb(binary_missing=True))
    assert check.status is SetupCheckStatus.FAILED
    assert check.message == "ADB command not found in PATH"


def test_device_check_names_the_missing_serial() -> None:
    check = check_device_connection(FakeAdb(target=MISSING))
    assert check.status is SetupCheckStatus.FAILED
    assert check.message == f"Device '{MISSING}' not found"
    assert check.details["missing_serial"] == MISSING


def test_critical_setup_reports_the_missing_serial_and_the_devices() -> None:
    result = SetupService(adb=FakeAdb(target=MISSING)).check_critical_setup()
    assert not result.success
    assert result.adb_available
    assert not result.device_connected
    assert result.message == f"Device '{MISSING}' not found"
    assert result.missing_serial == MISSING
    assert result.available_devices == [PRESENT, "emulator-5556 (offline)"]
    assert f"Available devices: {PRESENT}, emulator-5556 (offline)" in result.errors
    assert not any("PATH" in e for e in [result.message, *result.errors])


def test_environment_service_tells_a_missing_device_from_missing_adb() -> None:
    from sandroid.services.environment_service import EnvironmentService

    result = EnvironmentService(adb=FakeAdb(target=MISSING)).check_setup()
    assert not result.success
    assert result.adb_available
    assert result.message == f"Device '{MISSING}' not found"


# --------------------------------------------------------------------------
# the error screen
# --------------------------------------------------------------------------


async def _settle(pilot, n: int = 4) -> None:
    for _ in range(n):
        await pilot.pause(0.05)


@pytest.fixture
def startup(monkeypatch):
    """A SandroidTUI on its StartupScreen; init never runs (counted instead)."""
    from sandroid.core.adb import Adb
    from sandroid.core.device_manager import DeviceManager
    from sandroid.tui.screens import startup_screen
    from sandroid.tui.screens.startup_screen import StartupScreen

    # use_device() pins the serial globally: restored after the test.
    monkeypatch.setattr(Adb, "_target_device", None)
    monkeypatch.setattr(DeviceManager, "_preferred_serial", None)
    monkeypatch.setattr(startup_screen, "_startup_failure", None)
    inits: list[int] = []
    monkeypatch.setattr(
        StartupScreen, "_start_init_worker", lambda self: inits.append(1)
    )
    from sandroid.tui.app import SandroidTUI

    config = SimpleNamespace(emulator=SimpleNamespace(serial=MISSING))
    app = SandroidTUI(startup_config=config)
    globals_fired: list[str] = []
    for name in ("record", "play", "show_device_selector", "switch_lens"):
        monkeypatch.setattr(
            app, f"action_{name}", lambda *a, _n=name: globals_fired.append(_n)
        )
    return SimpleNamespace(
        app=app, config=config, inits=inits, globals_fired=globals_fired
    )


ERROR = f"Device '{MISSING}' not found\n  - Available devices: {PRESENT}"


async def _error_screen(app, pilot):
    from sandroid.tui.screens.startup_screen import StartupScreen

    await _settle(pilot)
    screen = app.screen
    assert isinstance(screen, StartupScreen)
    screen._show_error(ERROR, device_problem=True)
    await _settle(pilot)
    return screen


async def test_error_screen_shows_the_device_and_its_keys(startup) -> None:
    app = startup.app
    async with app.run_test(size=SIZE) as pilot:
        screen = await _error_screen(app, pilot)
        error = str(screen.query_one("#startup-error").render())
        hint = str(screen.query_one("#startup-hint").render())
        assert f"Device '{MISSING}' not found" in error
        assert "ADB not found" not in error
        for key_hint in ("r retry", "d pick a device", "q quit"):
            assert key_hint in hint
        screen._show_error("ADB not found in PATH", device_problem=False)
        await _settle(pilot)
        assert "pick a device" not in str(screen.query_one("#startup-hint").render())


@pytest.mark.parametrize("key", ["r", "R"])
async def test_retry_key_does_not_fire_record(startup, key) -> None:
    app = startup.app
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        screen = await _error_screen(app, pilot)
        startup.inits.clear()
        await pilot.press(key)
        await _settle(pilot)
        assert startup.inits == [1]  # retried
        assert not screen.has_error
        assert startup.globals_fired == []
        assert not [n for n in app._notifications if "record" in n.message.lower()]


async def test_global_keys_are_dead_while_the_startup_screen_is_up(startup) -> None:
    app = startup.app
    async with app.run_test(size=SIZE) as pilot:
        await _error_screen(app, pilot)
        for key in ("p", "1", "2", "grave_accent", "question_mark", "escape"):
            await pilot.press(key)
        await _settle(pilot)
        assert startup.globals_fired == []
        assert type(app.screen).__name__ == "StartupScreen"
        assert app.check_action("record", ()) is False
        assert app.return_code is None


@pytest.mark.parametrize("key", ["q", "Q"])
async def test_quit_after_a_failed_start_exits_non_zero(startup, key) -> None:
    from sandroid.tui.screens.startup_screen import (
        EXIT_STARTUP_FAILED,
        startup_failure,
    )

    app = startup.app
    async with app.run_test(size=SIZE) as pilot:
        await _error_screen(app, pilot)
        await pilot.press(key)
        await _settle(pilot)
    assert app.return_code == EXIT_STARTUP_FAILED == 2
    assert startup_failure() == ERROR


async def test_q_while_loading_is_ignored_ctrl_c_aborts(startup) -> None:
    from sandroid.tui.screens.startup_screen import EXIT_STARTUP_ABORTED

    app = startup.app
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        await pilot.press("q")
        await _settle(pilot)
        assert app.return_code is None
        await pilot.press("ctrl+c")
        await _settle(pilot)
    assert app.return_code == EXIT_STARTUP_ABORTED


@pytest.mark.parametrize("key", ["d", "D"])
async def test_d_picks_a_device_pins_it_and_retries(startup, monkeypatch, key) -> None:
    from sandroid.core.adb import Adb
    from sandroid.core.device_manager import DeviceManager
    from sandroid.tui.screens.startup_screen import StartupScreen

    device = SimpleNamespace(
        serial=PRESENT, state="device", is_emulator=True, name="Pixel", model=""
    )
    monkeypatch.setattr(
        StartupScreen,
        "_load_devices",
        lambda self: self.app.call_from_thread(self._show_device_picker, [device]),
    )
    app = startup.app
    async with app.run_test(size=SIZE) as pilot:
        await _error_screen(app, pilot)
        startup.inits.clear()
        await pilot.press(key)
        await _settle(pilot, 8)
        assert type(app.screen).__name__ == "DeviceSelectionModal"
        assert startup.globals_fired == []  # not the app's D (device selector)
        await pilot.press("enter")
        await _settle(pilot, 8)
        assert type(app.screen).__name__ == "StartupScreen"
        assert startup.inits == [1]  # retried with the picked device
        assert startup.config.emulator.serial == PRESENT
        assert Adb.get_target_device() == PRESENT
        assert DeviceManager.preferred_serial() == PRESENT


# --------------------------------------------------------------------------
# exit path: status code + unused session folder
# --------------------------------------------------------------------------


def _session(tmp_path, *, extra: bool = False, pre_existing: bool = False):
    from sandroid.services.initialization_service import InitializationService

    if pre_existing:
        (tmp_path / "20260101_000000").mkdir()
    svc = InitializationService(base_path=tmp_path)
    paths = svc.create_session(timestamp="20260101_000000", setup_logging=True)
    logging.getLogger("sandroid.test").error("startup failed")
    if extra:
        (paths.session_path / "device").mkdir()
    return svc, paths.session_path


def test_unused_session_folder_is_removed(tmp_path) -> None:
    svc, folder = _session(tmp_path)
    assert (folder / "sandroid.log").exists()
    assert svc.discard_unused_session() is True
    assert not folder.exists()
    assert tmp_path.exists()
    root = logging.getLogger()
    assert not any(
        str(folder) in str(getattr(h, "baseFilename", "")) for h in root.handlers
    )


@pytest.mark.parametrize("case", ["extra", "pre_existing"])
def test_used_or_foreign_session_folder_is_kept(tmp_path, case) -> None:
    svc, folder = _session(tmp_path, **{case: True})
    try:
        assert svc.discard_unused_session() is False
        assert folder.exists()
    finally:
        svc.reset()


def test_failed_start_exits_with_its_code_and_discards_the_session(
    monkeypatch, capsys
) -> None:
    import sandroid.tui
    from sandroid.cli_modes import interactive
    from sandroid.tui.screens import startup_screen

    discarded: list[bool] = []
    exits: list[int] = []
    monkeypatch.setattr(sandroid.tui, "run_tui", lambda **kw: 2)
    monkeypatch.setattr(startup_screen, "_startup_failure", ERROR)
    monkeypatch.setattr(
        "sandroid.services.get_initialization_service",
        lambda: SimpleNamespace(discard_unused_session=lambda: discarded.append(True)),
    )
    monkeypatch.setattr(
        interactive,
        "_exit_without_lingering_threads",
        lambda grace=3.0, exit_code=0: exits.append(exit_code),
    )
    summary = []
    monkeypatch.setattr(
        interactive,
        "get_ui_service",
        lambda: SimpleNamespace(print_exit_summary=summary.append),
    )
    config = SimpleNamespace(tui=SimpleNamespace(theme="default"))
    with pytest.raises(SystemExit) as exc:
        interactive._start_tui_mode(config, SimpleNamespace(), lambda: None)
    assert exc.value.code == 2
    assert exits == [2]
    assert discarded == [True]
    assert summary == []  # nothing was analysed: no exit summary
    assert f"Device '{MISSING}' not found" in capsys.readouterr().err
