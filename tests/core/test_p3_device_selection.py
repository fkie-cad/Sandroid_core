"""Phase-3 device selection fixes (N2, adb calls without ``-s``).

A fake adb (a small Python script, not named ``adb`` so the suite's device
guard lets it run) logs every invocation and answers ``devices -l`` from a
state file, so the real CLI/headless/DeviceManager code paths run end to end
without any device:

* ``sandroid -s <missing serial> --headless`` fails fast with exit 1 and
  writes no evidence files, and AndroidFridaManager is never created;
* after the active device drops out of ``adb devices`` (snapshot load during
  the dexray revert) every adb call still carries ``-s <serial>``;
* Frida/AFM device lookups use the selected serial, never "the first/only
  device".
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from sandroid.core.adb import Adb
from sandroid.core.device_manager import DeviceManager

_FAKE_ADB = r"""#!{python}
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
args = sys.argv[1:]
with open(here / "calls.log", "a", encoding="utf-8") as fh:
    fh.write(" ".join(args) + "\n")
serial = None
if len(args) >= 2 and args[0] == "-s":
    serial, args = args[1], args[2:]
listing = (here / "devices.txt").read_text(encoding="utf-8")
online = {{
    line.split()[0]
    for line in listing.splitlines()
    if len(line.split()) >= 2 and line.split()[1] == "device"
}}
if args[:1] == ["devices"]:
    sys.stdout.write("List of devices attached\n" + listing)
    sys.exit(0)
if serial is None and len(online) != 1:
    sys.stderr.write("adb: more than one device/emulator\n")
    sys.exit(1)
if serial is not None and serial not in online:
    sys.stderr.write(f"adb: device '{{serial}}' not found\n")
    sys.exit(1)
answers = {{
    "get-state": "device",
    "get-serialno": serial or "",
    "shell getprop ro.boot.qemu.avd_name": "Pixel_9_2",
    "shell getprop ro.product.model": "sdk_gphone64_arm64",
    "shell getprop ro.boot.qemu": "1",
    # The Devices screen's read-only readiness probe.
    "shell getprop sys.boot_completed; getprop ro.build.version.sdk; "
    "getprop ro.boot.qemu.avd_name; getprop ro.kernel.qemu.avd_name": (
        "1\n35\nPixel_9_2\n"
    ),
}}
sys.stdout.write(answers.get(" ".join(args), "") + "\n")
"""

_ONE_EMU = "emulator-5556 device product:sdk model:sdk device:emu transport_id:1\n"
_TWO_EMUS = (
    _ONE_EMU + "emulator-5554 device product:sdk model:sdk device:emu transport_id:2\n"
)


@pytest.fixture
def fake_adb(tmp_path, monkeypatch):
    """Install the fake adb as ``Adb.ADB_PATH``; returns a small controller."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "fakeadb"
    script.write_text(_FAKE_ADB.format(python=sys.executable), encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    (bindir / "devices.txt").write_text(_ONE_EMU, encoding="utf-8")
    (bindir / "calls.log").write_text("", encoding="utf-8")

    monkeypatch.delenv("ANDROID_SERIAL", raising=False)
    monkeypatch.setattr(Adb, "ADB_PATH", str(script))
    Adb.set_target_device(None)
    DeviceManager.set_preferred_serial(None)
    DeviceManager.reset()

    def set_devices(text: str) -> None:
        (bindir / "devices.txt").write_text(text, encoding="utf-8")

    def calls() -> list[str]:
        text = (bindir / "calls.log").read_text(encoding="utf-8")
        return [line for line in text.splitlines() if line.strip()]

    yield SimpleNamespace(path=script, set_devices=set_devices, calls=calls)

    Adb.set_target_device(None)
    DeviceManager.set_preferred_serial(None)
    DeviceManager.reset()


def _no_session_side_effects(monkeypatch):
    """Keep set_active_device() from touching folders or Frida services."""
    from sandroid.core.toolbox import Toolbox

    monkeypatch.setattr(
        Toolbox, "switch_device_folder", classmethod(lambda cls, name: None)
    )
    monkeypatch.setattr(
        Toolbox, "update_frida_device_serial", classmethod(lambda cls, s: None)
    )


def _restore_cli_globals(monkeypatch):
    """Undo the process-wide state ``sandroid.cli.main`` installs."""
    import logging

    import sandroid.config as config_module
    from sandroid.core.toolbox import Toolbox
    from sandroid.services import get_ui_service

    monkeypatch.setattr(config_module, "_config_instance", None)
    monkeypatch.setattr(
        Toolbox, "config", getattr(Toolbox, "config", None), raising=False
    )
    for key in ("RESULTS_PATH", "RAW_RESULTS_PATH", "SESSION_PATH"):
        if key in os.environ:
            monkeypatch.setenv(key, os.environ[key])
        else:
            monkeypatch.delenv(key, raising=False)
    ui = get_ui_service()
    if hasattr(ui, "get_current_view"):
        monkeypatch.setattr(ui, "set_current_view", lambda view: None)
    for name in ("", "sandroid"):
        log = logging.getLogger(name)
        monkeypatch.setattr(log, "handlers", list(log.handlers))
        monkeypatch.setattr(log, "level", log.level)


# ---------------------------------------------------------------------------
# require_device / fail fast
# ---------------------------------------------------------------------------


def test_require_device_rejects_missing_requested_serial(fake_adb, monkeypatch):
    from sandroid.core.exceptions import DeviceNotAvailableError
    from sandroid.core.initializer import apply_serial_selection, require_device

    _no_session_side_effects(monkeypatch)
    apply_serial_selection("emulator-5999")
    with pytest.raises(DeviceNotAvailableError) as exc:
        require_device()
    msg = str(exc.value)
    assert "emulator-5999 is not connected" in msg
    assert "emulator-5556 (device)" in msg
    # Never fell back to the one device that *is* connected.
    assert DeviceManager.get().active_device is None
    assert all(c.startswith("-s emulator-5999 ") for c in fake_adb.calls())


def test_require_device_rejects_offline_requested_serial(fake_adb, monkeypatch):
    from sandroid.core.exceptions import DeviceNotAvailableError
    from sandroid.core.initializer import apply_serial_selection, require_device

    _no_session_side_effects(monkeypatch)
    fake_adb.set_devices("emulator-5556 offline transport_id:1\n")
    apply_serial_selection("emulator-5556")
    with pytest.raises(DeviceNotAvailableError, match="not online"):
        require_device()


def test_require_device_activates_requested_serial(fake_adb, monkeypatch):
    from sandroid.core.initializer import apply_serial_selection, require_device

    _no_session_side_effects(monkeypatch)
    fake_adb.set_devices(_TWO_EMUS)
    apply_serial_selection("emulator-5554")
    device = require_device()
    assert device.serial == "emulator-5554"
    assert Adb.get_target_device() == "emulator-5554"


def test_require_device_without_any_device(fake_adb, monkeypatch):
    from sandroid.core.exceptions import DeviceNotAvailableError
    from sandroid.core.initializer import require_device

    _no_session_side_effects(monkeypatch)
    fake_adb.set_devices("")
    with pytest.raises(DeviceNotAvailableError, match="No Android device"):
        require_device()


def test_cli_headless_bogus_serial_fails_fast_without_evidence(
    fake_adb, tmp_path, monkeypatch
):
    """N2: ``-s emulator-5999 --headless`` -> exit 1, no files, no AFM."""
    import AndroidFridaManager
    from click.testing import CliRunner

    from sandroid.cli import main

    created = []

    def _no_afm(*args, **kwargs):
        created.append((args, kwargs))
        raise AssertionError("AndroidFridaManager must not be created")

    monkeypatch.setattr(AndroidFridaManager, "FridaManager", _no_afm)
    monkeypatch.setattr(AndroidFridaManager, "JobManager", _no_afm)

    work = tmp_path / "work"
    work.mkdir()
    results = tmp_path / "results"
    (work / "sandroid.toml").write_text(
        "[paths]\n"
        f'results_path = "{results.as_posix()}"\n'
        f'raw_results_path = "{(results / "raw").as_posix()}"\n'
        "[emulator]\n"
        f'adb_path = "{fake_adb.path.as_posix()}"\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(work)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    _restore_cli_globals(monkeypatch)

    res = CliRunner().invoke(
        main, ["-s", "emulator-5999", "--headless", "--mode", "forensic", "-n", "2"]
    )

    assert res.exit_code == 1, res.output
    assert "emulator-5999 is not connected" in res.output
    assert "completed successfully" not in res.output
    assert created == []
    written = [p.name for p in tmp_path.rglob("*") if p.is_file()]
    assert "sandroid.json" not in written
    assert "SHA256SUMS" not in written
    assert all(c.startswith("-s emulator-5999 ") for c in fake_adb.calls())


def test_headless_run_analysis_refuses_without_device(fake_adb, monkeypatch):
    """The API re-checks the device before a run (no evidence for no device)."""
    import asyncio

    from sandroid.api import headless
    from sandroid.api.interfaces import AnalysisMode
    from sandroid.core.exceptions import DeviceNotAvailableError

    _no_session_side_effects(monkeypatch)
    ran = []

    async def fake_forensic(**kwargs):
        ran.append(kwargs)
        return {}

    monkeypatch.setattr(headless, "run_forensic_analysis", fake_forensic)
    fake_adb.set_devices("")
    api = headless.SandroidHeadlessAPI(config=SimpleNamespace())
    api._initialized = True
    with pytest.raises(DeviceNotAvailableError):
        asyncio.run(api.run_analysis(AnalysisMode.FORENSIC))
    assert ran == []


# ---------------------------------------------------------------------------
# Several devices, no pin: ask (TUI) / refuse (headless) before device work
# ---------------------------------------------------------------------------

#: adb arguments that change a device (prep, root, Frida, installs).
_DEVICE_CHANGING = ("root", "setenforce", "frida", "install", "push", "kill")


def _device_changing(calls: list[str]) -> list[str]:
    return [c for c in calls if any(word in c for word in _DEVICE_CHANGING)]


@pytest.fixture
def core_spies(monkeypatch):
    """Record Toolbox.init / prepare_device instead of running them."""
    from sandroid.core import emulator_guard, initializer
    from sandroid.core.toolbox import Toolbox

    spies = SimpleNamespace(inits=[], prepared=[])
    monkeypatch.setattr(
        Toolbox, "config", getattr(Toolbox, "config", None), raising=False
    )
    monkeypatch.setattr(
        Toolbox,
        "init",
        classmethod(lambda cls: spies.inits.append(Adb.get_target_device())),
    )
    monkeypatch.setattr(
        initializer,
        "prepare_device",
        lambda console=None: spies.prepared.append(Adb.get_target_device()),
    )
    monkeypatch.setattr(emulator_guard, "start_memory_guard", lambda config: None)
    _no_session_side_effects(monkeypatch)
    return spies


@pytest.mark.parametrize("prepare", [False, True])
def test_initialize_core_refuses_two_devices_without_a_pin(
    fake_adb, core_spies, prepare
):
    from sandroid.core.exceptions import MultipleDevicesError
    from sandroid.core.initializer import initialize_core

    fake_adb.set_devices(_TWO_EMUS)
    with pytest.raises(MultipleDevicesError) as exc:
        initialize_core(SimpleNamespace(), prepare=prepare)
    assert exc.value.serials == ["emulator-5556", "emulator-5554"]
    assert "emulator-5556, emulator-5554" in str(exc.value)
    assert "--serial" in str(exc.value)
    assert core_spies.inits == []
    assert core_spies.prepared == []
    assert fake_adb.calls() == ["devices"]  # read-only enumeration only
    assert Adb.get_target_device() is None


@pytest.mark.parametrize("how", ["config", "env"])
def test_initialize_core_with_a_pin_skips_the_question(
    fake_adb, core_spies, monkeypatch, how
):
    from sandroid.core.initializer import initialize_core

    fake_adb.set_devices(_TWO_EMUS)
    config = SimpleNamespace(emulator=SimpleNamespace(serial=None))
    if how == "config":
        config.emulator.serial = "emulator-5554"
    else:
        monkeypatch.setenv("ANDROID_SERIAL", "emulator-5554")
    initialize_core(config, prepare=True)
    assert core_spies.prepared == ["emulator-5554"]
    assert core_spies.inits == ["emulator-5554"]


def test_initialize_core_with_one_device_is_unchanged(fake_adb, core_spies):
    from sandroid.core.initializer import initialize_core

    fake_adb.set_devices(_ONE_EMU + "emulator-5554 offline transport_id:2\n")
    initialize_core(SimpleNamespace(), prepare=True)  # offline does not count
    assert core_spies.prepared == ["emulator-5556"]
    assert core_spies.inits == ["emulator-5556"]


def test_auto_select_never_guesses_among_several_devices(fake_adb, monkeypatch):
    """Mid-session too: no silent switch to another emulator after a loss."""
    _no_session_side_effects(monkeypatch)
    third = "emulator-5558 device product:sdk model:sdk device:emu transport_id:3\n"
    fake_adb.set_devices(_TWO_EMUS + third)
    dm = DeviceManager.get()
    dm.refresh_devices()
    assert dm.active_device is None  # used to be emulators[0]

    dm.set_active_device("emulator-5554")
    fake_adb.set_devices(_ONE_EMU + third)  # 5554 drops out (snapshot load)
    dm.refresh_devices()
    assert dm.active_device is None  # not 5556 / 5558: someone else's

    fake_adb.set_devices(_TWO_EMUS + third)  # 5554 is back
    dm.refresh_devices()
    assert dm.active_device.serial == "emulator-5554"


def test_cli_headless_two_devices_without_serial_refuses(
    fake_adb, tmp_path, monkeypatch
):
    """``--headless`` with two devices and no pin: exit 1, list the serials."""
    import AndroidFridaManager
    from click.testing import CliRunner

    from sandroid.cli import main

    def _no_afm(*args, **kwargs):
        raise AssertionError("AndroidFridaManager must not be created")

    monkeypatch.setattr(AndroidFridaManager, "FridaManager", _no_afm)
    monkeypatch.setattr(AndroidFridaManager, "JobManager", _no_afm)
    fake_adb.set_devices(_TWO_EMUS)

    work = tmp_path / "work"
    work.mkdir()
    results = tmp_path / "results"
    (work / "sandroid.toml").write_text(
        "[paths]\n"
        f'results_path = "{results.as_posix()}"\n'
        f'raw_results_path = "{(results / "raw").as_posix()}"\n'
        "[emulator]\n"
        f'adb_path = "{fake_adb.path.as_posix()}"\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(work)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    _restore_cli_globals(monkeypatch)

    res = CliRunner().invoke(main, ["--headless", "--mode", "forensic", "-n", "2"])

    out = " ".join(res.output.split())
    assert res.exit_code == 1, res.output
    assert "More than one device is connected (emulator-5556, emulator-5554)" in out
    assert "--serial" in out
    assert fake_adb.calls() == ["devices"]
    assert _device_changing(fake_adb.calls()) == []


async def test_tui_two_devices_without_pin_asks_before_any_prep(
    fake_adb, core_spies, monkeypatch
):
    """Devices opens before Toolbox.init / setup checks touch a device."""
    from sandroid import services
    from sandroid.core import emulator
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.screens import startup_screen
    from sandroid.tui.screens.devices_screen import DevicesScreen

    monkeypatch.setattr(startup_screen, "_startup_failure", None)
    monkeypatch.setattr(DevicesScreen, "monitor_factory", None)
    monkeypatch.setattr(emulator, "emulator_binary", lambda: None)  # no AVDs
    setup_calls: list[str | None] = []

    class _Setup:
        def check_critical_setup(self):
            setup_calls.append(Adb.get_target_device())
            return SimpleNamespace(
                success=False,
                message="stop here",
                errors=[],
                adb_available=True,
                device_connected=True,
            )

    monkeypatch.setattr(services, "get_setup_service", _Setup)
    fake_adb.set_devices(_TWO_EMUS)
    config = SimpleNamespace(emulator=SimpleNamespace(serial=None))
    app = SandroidTUI(startup_config=config)

    async with app.run_test(size=(160, 45)) as pilot:
        for _ in range(60):
            await pilot.pause(0.05)
            screen = app.screen
            if isinstance(screen, DevicesScreen) and screen.snapshot is not None:
                break
        assert isinstance(app.screen, DevicesScreen)
        assert app.screen.mode == "startup"
        assert {row.serial for row in app.screen.snapshot.devices} == {
            "emulator-5556",
            "emulator-5554",
        }
        await pilot.pause(0.1)
        assert core_spies.inits == []
        assert setup_calls == []
        assert _device_changing(fake_adb.calls()) == []
        assert Adb.get_target_device() is None

        await pilot.press("enter")
        for _ in range(60):
            await pilot.pause(0.05)
            if setup_calls:
                break
        for _ in range(10):
            await pilot.pause(0.05)
        picked = config.emulator.serial
        assert picked in ("emulator-5556", "emulator-5554")
        assert core_spies.inits == [picked]  # prep only after the choice...
        assert setup_calls == [picked]  # ...and only on the chosen device
        assert DeviceManager.preferred_serial() == picked


# ---------------------------------------------------------------------------
# Every adb call carries -s, also across a snapshot-load "disconnect"
# ---------------------------------------------------------------------------


def test_every_adb_call_keeps_serial_across_snapshot_revert(fake_adb, monkeypatch):
    """The 7 phase-3 calls (dexray revert) went out without ``-s``.

    The snapshot load drops the device from ``adb devices`` for ~1 s; the
    DeviceManager used to clear the adb target then. Replays the calls seen in
    the live log (getprop ro.boot.qemu, pidof, ps -A, ps -o, get-state) plus
    the argv builders of fsmon/kprobe/frida helpers.
    """
    from sandroid.core.fsmon import FSMon
    from sandroid.core.initializer import apply_serial_selection
    from sandroid.core.kprobe_tracer import KprobeTracer
    from sandroid.core.proxy_manager import _is_emulator
    from sandroid.services.emulator_service import EmulatorService

    _no_session_side_effects(monkeypatch)
    fake_adb.set_devices(_TWO_EMUS)
    apply_serial_selection("emulator-5556")
    dm = DeviceManager.get()
    dm.refresh_devices()
    assert dm.active_device.serial == "emulator-5556"

    # Snapshot load: the device vanishes from the listing...
    fake_adb.set_devices("emulator-5554 device product:sdk transport_id:2\n")
    dm.refresh_devices()
    assert dm.active_device is None

    # ...and the code running in that window issues its adb calls.
    _is_emulator()
    Adb.send_adb_command("shell getprop ro.boot.qemu")
    Adb.get_pid_for_package_name("org.wikipedia", use_frida_fallback=False)
    EmulatorService()._wait_for_device_ready(Adb, None, timeout=0.3, interval=0.1)

    # Device is back.
    fake_adb.set_devices(_TWO_EMUS)
    dm.refresh_devices()
    assert dm.active_device.serial == "emulator-5556"

    calls = fake_adb.calls()
    assert any("pidof org.wikipedia" in c for c in calls)
    assert any(c.endswith("get-state") for c in calls)
    missing = [c for c in calls if not c.startswith("-s emulator-5556 ")]
    assert missing == [], f"adb calls without -s emulator-5556: {missing}"

    # Raw argv builders (fsmon, kprobe, Adb.base_argv) follow the same target.
    for argv in (
        FSMon._build_adb_cmd("shell", "true"),
        KprobeTracer._build_adb_cmd("shell", "true"),
        Adb.base_argv(),
    ):
        assert argv[1:3] == ["-s", "emulator-5556"], argv


# ---------------------------------------------------------------------------
# Frida / AndroidFridaManager use the selected serial
# ---------------------------------------------------------------------------


def test_selected_serial_falls_back_to_requested(fake_adb):
    assert Adb.selected_serial() is None
    DeviceManager.set_preferred_serial("emulator-5999")
    assert Adb.selected_serial() == "emulator-5999"
    Adb.set_target_device("emulator-5556")
    assert Adb.selected_serial() == "emulator-5556"


def test_toolbox_hands_requested_serial_to_frida_manager(fake_adb, monkeypatch):
    """No active device -> AFM gets the requested serial, not None (auto)."""
    from sandroid import services
    from sandroid.core.toolbox import Toolbox

    monkeypatch.setattr(
        services,
        "get_device_service",
        lambda: SimpleNamespace(get_active_device=lambda: None),
    )
    DeviceManager.set_preferred_serial("emulator-5999")
    assert Toolbox._get_active_device_serial() == "emulator-5999"


def test_frida_device_lookups_use_selected_serial(fake_adb, monkeypatch):
    import frida

    from sandroid.services.frida_device_manager import (
        FridaDeviceManager,
        get_selected_frida_device,
    )

    asked = []

    def fake_get_device(serial, timeout=None):
        asked.append(serial)
        raise frida.InvalidArgumentError(f"device '{serial}' not found")

    def no_usb(*a, **k):
        raise AssertionError("must not fall back to the first USB device")

    monkeypatch.setattr(frida, "get_device", fake_get_device)
    monkeypatch.setattr(frida, "enumerate_devices", list)
    monkeypatch.setattr(frida, "get_usb_device", no_usb)
    from sandroid.core.initializer import apply_serial_selection
    from sandroid.core.toolbox import Toolbox

    _no_session_side_effects(monkeypatch)
    monkeypatch.setattr(
        Toolbox, "get_device_manager", classmethod(lambda cls: DeviceManager.get())
    )
    apply_serial_selection("emulator-5999")
    DeviceManager.get().refresh_devices()  # 5556 is online but not requested

    with pytest.raises(frida.InvalidArgumentError):
        get_selected_frida_device()
    with pytest.raises(frida.InvalidArgumentError):
        FridaDeviceManager().get_device_for_session()
    assert set(asked) == {"emulator-5999"}


def test_tui_reports_missing_requested_serial(fake_adb, monkeypatch):
    """TUI startup: a missing --serial device is shown as an error."""
    from sandroid.tui.controllers.device_controller import DeviceController

    _no_session_side_effects(monkeypatch)
    errors = []
    opened = []
    DeviceManager.set_preferred_serial("emulator-5999")
    controller = DeviceController(
        log_error=errors.append,
        toolbox=SimpleNamespace(get_device_manager=DeviceManager.get),
        open_devices=opened.append,
    )
    assert controller.check_devices_on_startup() is False
    assert DeviceManager.get().active_device is None
    assert opened == ["Requested device emulator-5999 is not available."]
    assert len(errors) == 1
    assert "emulator-5999 is not connected" in errors[0]
    assert "emulator-5556" in errors[0]


def test_fake_adb_is_not_a_real_adb(fake_adb):
    """Sanity: the fake is the only adb these tests run."""
    assert Path(Adb.ADB_PATH).name == "fakeadb"
    assert os.access(Adb.ADB_PATH, os.X_OK)


# ---------------------------------------------------------------------------
# Headless forensic follows [analysis]; metadata records what was used
# ---------------------------------------------------------------------------


def _toolbox_with(analysis: dict):
    from sandroid.config.schema import SandroidConfig

    return SimpleNamespace(
        config=SandroidConfig(analysis=analysis),
        create_snapshot=lambda name: None,
    )


def test_headless_settings_follow_config_with_overrides():
    from sandroid.api.analysis_runners import resolve_analysis_config

    tb = _toolbox_with(
        {
            "capture_network": True,
            "capture_processes": True,
            "avoid_strong_noise_filter": False,
            "show_deleted_files": True,
        }
    )
    ac = resolve_analysis_config(tb, runs=2)
    assert ac.capture_network is True
    assert ac.capture_processes is True
    assert ac.dry_run is True
    assert ac.show_deleted is True
    # Explicit values (API callers) still win.
    ac = resolve_analysis_config(
        tb, runs=2, capture_network=False, monitor_processes=False, dry_run=False
    )
    assert (ac.capture_network, ac.capture_processes, ac.dry_run) == (
        False,
        False,
        False,
    )
    # --avoid-strong-noise-filter ends up in the config -> no dry run.
    tb = _toolbox_with({"avoid_strong_noise_filter": True})
    assert resolve_analysis_config(tb, runs=2).dry_run is False


@pytest.mark.parametrize("recording", [None, "/abs/recording.txt"])
def test_headless_forensic_and_replay_use_config_and_record_it(monkeypatch, recording):
    """Forensic + --import-action: engine and Run Metadata get the same settings."""
    import asyncio

    from sandroid.analysis.engine import AnalysisEngine
    from sandroid.analysis.run_config import RunResult
    from sandroid.api import analysis_runners
    from sandroid.core import run_report

    seen = {}

    def fake_init(self, config, **kwargs):
        seen["run_config"] = config

    monkeypatch.setattr(AnalysisEngine, "__init__", fake_init)
    monkeypatch.setattr(AnalysisEngine, "run", lambda self: RunResult(device_name="d"))
    monkeypatch.setattr(
        run_report,
        "finalize_run",
        lambda *a, **k: (
            seen.setdefault("finalize", k)
            and SimpleNamespace(results_json="x", pdf=None, errors=[])
        ),
    )
    if recording:
        from sandroid.features import player

        monkeypatch.setattr(player, "Player", lambda recording_path: "PLAYER")

    tb = _toolbox_with({"capture_network": True, "capture_processes": True})
    asyncio.run(
        analysis_runners.run_forensic_analysis(
            toolbox=tb,
            runs=2,
            track_deleted=None,
            compute_hashes=None,
            recording_path=recording,
        )
    )
    rc = seen["run_config"]
    assert (rc.network, rc.processes, rc.noise_filter) == (True, True, True)
    used = seen["finalize"]["run_settings"]
    assert used["capture_network"] is True
    assert used["capture_processes"] is True
    assert used["avoid_strong_noise_filter"] is False


def test_cli_headless_passes_unset_flags_as_none(monkeypatch):
    """No --network/--hash/-d on the CLI -> None, so [analysis] applies."""
    import sandroid.api as api_pkg
    from sandroid.cli_modes import headless as mode

    calls = {}

    class _FakeAPI:
        def __init__(self, config=None, config_path=None):
            pass

        async def initialize(self):
            return SimpleNamespace(success=True)

        async def run_analysis(self, **kwargs):
            calls.update(kwargs)
            return {}

        async def shutdown(self):
            return None

    monkeypatch.setattr(api_pkg, "SandroidHeadlessAPI", _FakeAPI)
    mode.run_headless_analysis(
        sandroid_config=object(),
        active_logger=None,
        package=None,
        batch_config=None,
        mode="forensic",
        runs=2,
        network=False,
        hash_files=False,
        show_deleted=False,
        output_file=None,
        recording_path="/abs/recording.txt",
    )
    assert calls["capture_network"] is None
    assert calls["compute_hashes"] is None
    assert calls["track_deleted"] is None


# ---------------------------------------------------------------------------
# sandroid --avd NAME
# ---------------------------------------------------------------------------


@pytest.fixture
def avd_cli(fake_adb, tmp_path, monkeypatch):
    """Run ``sandroid`` with a config, fake emulator backend and fake TUI."""
    from sandroid import cli_modes
    from sandroid.core import emulator

    work = tmp_path / "work"
    work.mkdir()
    results = tmp_path / "results"
    (work / "sandroid.toml").write_text(
        "[paths]\n"
        f'results_path = "{results.as_posix()}"\n'
        f'raw_results_path = "{(results / "raw").as_posix()}"\n'
        "[emulator]\n"
        f'adb_path = "{fake_adb.path.as_posix()}"\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(work)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    _restore_cli_globals(monkeypatch)

    state = SimpleNamespace(booted=[], tui_serial=[], avds=["Pixel_9", "Other"])

    def fake_ensure(avd, *, on_progress=None, **kwargs):
        state.booted.append(avd)
        if on_progress is not None:
            on_progress("booting", 3.0)
        if isinstance(state.result, Exception):
            raise state.result
        return state.result

    state.result = "emulator-5560"
    monkeypatch.setattr(emulator, "ensure_avd_running", fake_ensure)
    monkeypatch.setattr(emulator, "list_avds", lambda *a, **k: list(state.avds))
    monkeypatch.setattr(
        cli_modes,
        "start_interactive_mode",
        lambda cfg, *a, **k: state.tui_serial.append(cfg.emulator.serial),
    )

    def run(args):
        from click.testing import CliRunner

        from sandroid.cli import main

        return CliRunner().invoke(main, args)

    state.run = run
    return state


def test_cli_avd_and_serial_are_mutually_exclusive(avd_cli):
    res = avd_cli.run(["--avd", "Pixel_9", "--serial", "emulator-5554"])

    assert res.exit_code == 2, res.output
    assert "--avd and --serial" in res.output
    assert avd_cli.booted == []
    assert avd_cli.tui_serial == []


def test_cli_avd_boots_and_pins_its_serial_over_android_serial(avd_cli, monkeypatch):
    monkeypatch.setenv("ANDROID_SERIAL", "emulator-5554")

    res = avd_cli.run(["--avd", "Pixel_9"])

    assert res.exit_code == 0, res.output
    assert avd_cli.booted == ["Pixel_9"]
    assert avd_cli.tui_serial == ["emulator-5560"]
    assert "ready as emulator-5560" in res.output


def test_cli_avd_launch_failure_exits_before_any_mode(avd_cli):
    from sandroid.core.exceptions import EmulatorLaunchError

    avd_cli.result = EmulatorLaunchError("crashed during startup (log: /x.log)")

    res = avd_cli.run(["--avd", "Pixel_9"])

    assert res.exit_code == 1, res.output
    assert "Could not start AVD 'Pixel_9'" in res.output
    assert "/x.log" in res.output
    assert avd_cli.tui_serial == []


def test_cli_avd_unknown_name_lists_the_known_ones(avd_cli):
    res = avd_cli.run(["--avd", "Nope"])

    assert res.exit_code == 1, res.output
    assert "Unknown AVD 'Nope'" in res.output
    assert "Pixel_9, Other" in res.output
    assert avd_cli.booted == []
    assert avd_cli.tui_serial == []
