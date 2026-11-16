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
    DeviceManager.set_preferred_serial("emulator-5999")
    controller = DeviceController(
        log_error=errors.append,
        toolbox=SimpleNamespace(get_device_manager=DeviceManager.get),
    )
    monkeypatch.setattr(controller, "offer_avd_start", lambda: None)
    controller.check_devices_on_startup()
    assert DeviceManager.get().active_device is None
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
