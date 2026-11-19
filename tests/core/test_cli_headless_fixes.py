"""Regression tests for the 2.1 CLI / headless / import-robustness fixes.

All device access is faked: ``Adb.send_adb_command`` and the core init steps
are monkeypatched, so nothing here talks to a real adb.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
import threading
from types import SimpleNamespace

import pytest

from sandroid.core.adb import Adb


class _FakeAdb:
    """Scripted ``send_adb_command`` stand-in recording every call."""

    def __init__(self, responses: dict[str, tuple[str, str]]):
        self.responses = responses
        self.calls: list[str] = []

    def send_adb_command(self, command: str, serial=None):
        self.calls.append(command)
        return self.responses.get(command, ("", ""))


# ---------------------------------------------------------------------------
# --install-apk
# ---------------------------------------------------------------------------


def test_install_apk_success_does_not_unpack_return_value(monkeypatch, capsys):
    from sandroid import cli
    from sandroid.core import initializer

    prepared = {}
    monkeypatch.setattr(
        initializer,
        "initialize_core",
        lambda cfg, prepare=False: prepared.setdefault("prepare", prepare),
    )
    monkeypatch.setattr(Adb, "install_apk", classmethod(lambda cls, p: "com.x"))

    cli._run_install_apk(object(), "/tmp/x.apk")  # must not raise / exit

    assert prepared["prepare"] is True  # root + SELinux permissive requested
    assert "installed successfully (com.x)" in capsys.readouterr().out


def test_install_apk_failure_exits_nonzero(monkeypatch):
    from sandroid import cli
    from sandroid.core import initializer
    from sandroid.core.exceptions import APKInstallError

    monkeypatch.setattr(initializer, "initialize_core", lambda cfg, prepare=False: None)

    def _boom(cls, path):
        raise APKInstallError("x.apk", "INSTALL_FAILED_X")

    monkeypatch.setattr(Adb, "install_apk", classmethod(_boom))
    with pytest.raises(SystemExit) as exc:
        cli._run_install_apk(object(), "/tmp/x.apk")
    assert exc.value.code == 1


def test_install_apk_detects_failure_reported_on_stdout(monkeypatch):
    from sandroid.core import adb_packages
    from sandroid.core.exceptions import APKInstallError

    monkeypatch.setattr(adb_packages, "find_aapt_paths", list)
    fake = _FakeAdb({})
    out = (
        "Performing Streamed Install\n"
        "adb: failed to install x.apk: Failed transaction (2147483646)"
    )
    fake.send_adb_command = lambda cmd, serial=None: (out, "")
    with pytest.raises(APKInstallError, match="SELinux"):
        adb_packages.install_apk(fake.send_adb_command, "/tmp/x.apk")


def test_install_apk_without_success_output_is_a_failure(monkeypatch):
    from sandroid.core import adb_packages
    from sandroid.core.exceptions import APKInstallError

    monkeypatch.setattr(adb_packages, "find_aapt_paths", list)
    with pytest.raises(APKInstallError):
        adb_packages.install_apk(lambda cmd: ("", ""), "/tmp/x.apk")


def test_selinux_check_unverifiable_is_a_warning():
    from sandroid.services.setup_checks import check_and_set_selinux

    assert not check_and_set_selinux(_FakeAdb({})).passed


def test_install_apk_success_returns_package(monkeypatch):
    from sandroid.core import adb_packages

    monkeypatch.setattr(adb_packages, "find_aapt_paths", lambda: ["aapt"])
    monkeypatch.setattr(
        adb_packages, "extract_package_name_with_aapt", lambda a, p: "com.ok"
    )
    sent = []

    def send(cmd):
        sent.append(cmd)
        return "Performing Streamed Install\nSuccess\n", ""

    assert adb_packages.install_apk(send, "/tmp/my app.apk") == "com.ok"
    assert "my app.apk" in sent[0]
    assert sent[0] != "install -r /tmp/my app.apk"  # path is quoted


# ---------------------------------------------------------------------------
# Root + SELinux permissive for headless one-shot modes
# ---------------------------------------------------------------------------


def test_selinux_check_falls_back_to_su_and_verifies():
    from sandroid.services.setup_checks import check_and_set_selinux

    fake = _FakeAdb(
        {
            "shell setenforce 0": ("", "setenforce: Permission denied"),
            "shell su 0 setenforce 0": ("", ""),
            "shell getenforce": ("Permissive\n", ""),
        }
    )
    check = check_and_set_selinux(fake)
    assert check.passed
    assert "shell su 0 setenforce 0" in fake.calls


def test_selinux_check_warns_when_still_enforcing():
    from sandroid.services.setup_checks import check_and_set_selinux

    fake = _FakeAdb({"shell getenforce": ("Enforcing\n", "")})
    check = check_and_set_selinux(fake)
    assert not check.passed
    assert "Enforcing" in check.message


class _ModeAdb(_FakeAdb):
    """getenforce answers the device's current mode; setenforce 0 changes it."""

    def __init__(self, mode: str):
        super().__init__({})
        self.mode = mode

    def send_adb_command(self, command: str, serial=None):
        self.calls.append(command)
        if command == "shell getenforce":
            return self.mode + "\n", ""
        if command == "shell setenforce 0":
            self.mode = "Permissive"
        return "", ""


def _selinux_infos(caplog) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelname == "INFO" and "SELinux mode changed" in r.getMessage()
    ]


def test_selinux_change_is_logged_with_reason(caplog):
    """E2E M6: SELinux was found Permissive and no log said who changed it."""
    import logging

    from sandroid.services.setup_checks import check_and_set_selinux

    fake = _ModeAdb("Enforcing")
    with caplog.at_level(logging.INFO, logger="sandroid.services.setup_checks"):
        assert check_and_set_selinux(fake).passed
    (line,) = _selinux_infos(caplog)
    assert "Enforcing -> Permissive" in line
    assert "device preparation" in line
    assert "reason: binder calls from root" in line
    # When it is set: unchanged (still exactly one setenforce 0).
    assert fake.calls.count("shell setenforce 0") == 1

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sandroid.services.setup_checks"):
        assert check_and_set_selinux(_ModeAdb("Permissive")).passed
    assert _selinux_infos(caplog) == []  # no change, no claim of one


def test_snapshot_selinux_restore_is_logged(caplog):
    import logging

    from sandroid.services.emulator_service import EmulatorService

    with caplog.at_level(logging.INFO):
        assert EmulatorService()._restore_selinux_permissive(
            _ModeAdb("Enforcing"), "emulator-5554"
        )
    (line,) = _selinux_infos(caplog)
    assert "on emulator-5554: Enforcing -> Permissive" in line
    assert "snapshot load" in line


def test_root_check_waits_for_device_after_adbd_restart(monkeypatch):
    from sandroid.services import setup_checks

    monkeypatch.setattr(setup_checks.time, "sleep", lambda s: None)
    fake = _FakeAdb(
        {
            "root": ("restarting adbd as root\n", ""),
            "shell id": ("uid=0(root)\n", ""),
        }
    )
    assert setup_checks.check_and_enable_root(fake).passed
    assert fake.calls.index("wait-for-device") < fake.calls.index("shell id")


def test_prepare_device_roots_and_sets_permissive(monkeypatch):
    from sandroid.core import initializer

    fake = _FakeAdb(
        {
            "root": ("adbd is already running as root\n", ""),
            "shell id": ("uid=0(root)\n", ""),
            "shell getenforce": ("Permissive\n", ""),
        }
    )
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        classmethod(lambda cls, c, serial=None: fake.send_adb_command(c)),
    )
    printed = []
    console = SimpleNamespace(print=printed.append)
    assert initializer.prepare_device(console) is True
    assert "shell setenforce 0" in fake.calls
    assert any("SELinux permissive" in p for p in printed)


def test_prepare_device_reports_missing_root(monkeypatch):
    from sandroid.core import initializer

    fake = _FakeAdb({"root": ("", "adbd cannot run as root in production builds")})
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        classmethod(lambda cls, c, serial=None: fake.send_adb_command(c)),
    )
    assert initializer.prepare_device(None) is False
    assert "shell setenforce 0" not in fake.calls


def test_initialize_core_prepare_runs_before_toolbox_init(monkeypatch):
    from sandroid.core import initializer
    from sandroid.core.toolbox import Toolbox

    order = []
    monkeypatch.setattr(Adb, "init", classmethod(lambda cls: order.append("adb")))
    monkeypatch.setattr(Toolbox, "init", classmethod(lambda cls: order.append("tb")))
    monkeypatch.setattr(
        initializer, "prepare_device", lambda console=None: order.append("prep")
    )
    monkeypatch.setattr(initializer, "require_device", lambda: order.append("require"))
    monkeypatch.setattr(Toolbox, "config", None, raising=False)

    initializer.initialize_core(SimpleNamespace(), prepare=True)
    assert order == ["adb", "require", "prep", "tb"]

    order.clear()
    initializer.initialize_core(SimpleNamespace())
    assert order == ["adb", "tb"]

    order.clear()
    initializer.initialize_core(SimpleNamespace(), require=True)
    assert order == ["adb", "require", "tb"]


# ---------------------------------------------------------------------------
# Headless API: config passthrough, forensic mode, batch
# ---------------------------------------------------------------------------


def test_headless_initialize_keeps_supplied_config(monkeypatch):
    from sandroid import services
    from sandroid.api.headless import SandroidHeadlessAPI
    from sandroid.config import ConfigLoader
    from sandroid.core.toolbox import Toolbox

    def _no_reload(*a, **k):
        raise AssertionError("config must not be reloaded")

    monkeypatch.setattr(ConfigLoader, "load", _no_reload)
    monkeypatch.setattr(Adb, "init", classmethod(lambda cls: None))
    monkeypatch.setattr(Toolbox, "init", classmethod(lambda cls: None))
    monkeypatch.setattr(Toolbox, "init_files", classmethod(lambda cls: None))
    monkeypatch.setattr(Toolbox, "config", None, raising=False)
    setup = SimpleNamespace(
        check_critical_setup=lambda: SimpleNamespace(success=True, errors=[])
    )
    monkeypatch.setattr(services, "get_setup_service", lambda: setup)
    monkeypatch.setattr(
        SandroidHeadlessAPI, "is_device_connected", lambda self: _async(True)
    )
    from sandroid.core import initializer

    monkeypatch.setattr(initializer, "require_device", lambda: None)

    cfg = SimpleNamespace(emulator=SimpleNamespace(device_name="My_AVD"))
    api = SandroidHeadlessAPI(config=cfg)
    result = asyncio.run(api.initialize())
    assert result.success, result.error
    assert api.config is cfg
    assert Toolbox.config is cfg


async def _async(value):
    return value


def _device_ok(monkeypatch):
    """Pretend the selected device is connected (run_analysis checks it)."""
    from sandroid.api import headless

    monkeypatch.setattr(
        headless.SandroidHeadlessAPI, "_require_device", staticmethod(lambda: None)
    )


def test_headless_forensic_forwards_capture_network(monkeypatch):
    from sandroid.api import headless
    from sandroid.api.interfaces import AnalysisMode

    seen = {}

    async def fake_forensic(**kwargs):
        seen.update(kwargs)
        return {}

    monkeypatch.setattr(headless, "run_forensic_analysis", fake_forensic)
    _device_ok(monkeypatch)
    api = headless.SandroidHeadlessAPI(config=SimpleNamespace())
    api._initialized = True
    asyncio.run(api.run_analysis(AnalysisMode.FORENSIC, capture_network=True))
    assert seen["capture_network"] is True


def test_cli_headless_forensic_needs_no_package(monkeypatch):
    import sandroid.api as api_pkg
    from sandroid.cli_modes import headless as mode

    calls = {}

    class _FakeAPI:
        def __init__(self, config=None, config_path=None):
            calls["config"] = config

        async def initialize(self):
            return SimpleNamespace(success=True)

        async def run_analysis(self, **kwargs):
            calls["run"] = kwargs
            return {}

        async def shutdown(self):
            return None

    monkeypatch.setattr(api_pkg, "SandroidHeadlessAPI", _FakeAPI)
    cfg = object()
    mode.run_headless_analysis(
        sandroid_config=cfg,
        active_logger=None,
        package=None,
        batch_config=None,
        mode="forensic",
        runs=2,
        network=True,
        hash_files=False,
        show_deleted=False,
        output_file=None,
    )
    assert calls["config"] is cfg
    assert calls["run"]["capture_network"] is True
    assert calls["run"]["package"] is None

    with pytest.raises(SystemExit):
        mode.run_headless_analysis(
            sandroid_config=cfg,
            active_logger=None,
            package=None,
            batch_config=None,
            mode="malware",
            runs=2,
            network=False,
            hash_files=False,
            show_deleted=False,
            output_file=None,
        )


def test_batch_security_uses_apk_path_and_config(monkeypatch, tmp_path):
    from sandroid.api import batch, headless
    from sandroid.api.interfaces import AnalysisMode

    seen = {}

    class _FakeAPI:
        def __init__(self, config_path=None, config=None):
            seen["config"] = config

        async def initialize(self):
            return SimpleNamespace(success=True)

        async def run_analysis(self, **kwargs):
            seen["run"] = kwargs
            return {}

        async def shutdown(self):
            return None

    monkeypatch.setattr(headless, "SandroidHeadlessAPI", _FakeAPI)
    cfg = object()
    res = asyncio.run(
        batch.batch_analyze(
            ["/tmp/a.apk"],
            mode=AnalysisMode.SECURITY,
            output_dir=str(tmp_path),
            config=cfg,
        )
    )
    assert res["/tmp/a.apk"]["status"] == "success"
    assert seen["config"] is cfg
    assert seen["run"]["apk_path"] == "/tmp/a.apk"
    assert "package" not in seen["run"]


# ---------------------------------------------------------------------------
# Import robustness / no sys.argv parsing
# ---------------------------------------------------------------------------


@pytest.fixture
def toolbox_args():
    """Save/restore ``Toolbox.args`` (a metaclass property, so monkeypatch's
    setattr/delattr round-trip can't be used on it).
    """
    from sandroid.core.toolbox import Toolbox

    saved = Toolbox.args, Toolbox.scan_directories
    yield Toolbox
    Toolbox.args, Toolbox.scan_directories = saved


def test_toolbox_init_never_parses_sys_argv(monkeypatch, toolbox_args):
    from sandroid import services

    Toolbox = toolbox_args

    seen = {}

    class _InitService:
        def parse_arguments(self, argv=None):
            raise AssertionError("must not parse sys.argv")

        def initialize_application(self, args=None, device_serial=None):
            seen["args"] = args
            return SimpleNamespace(
                args=SimpleNamespace(),
                logger=None,
                frida_manager=None,
                scan_directories=[],
            )

    monkeypatch.setattr(sys, "argv", ["my_script.py", "--my-own-flag"])
    Toolbox.args = None
    monkeypatch.setattr(services, "get_initialization_service", _InitService)
    monkeypatch.setattr(
        Toolbox, "_get_active_device_serial", classmethod(lambda c: None)
    )
    Toolbox.init()
    assert seen["args"] is None


def test_previously_broken_lazy_imports_resolve():
    from sandroid.core.console import SandroidConsole
    from sandroid.core.ui_request_bus import show_message

    assert SandroidConsole.get() is not None
    assert callable(show_message)
    for mod in (
        "sandroid.commands.snapshot_commands",
        "sandroid.commands.monitoring_commands",
        "sandroid.services.app_selection_flows",
        "sandroid.tui.launcher",
    ):
        src = importlib.util.find_spec(mod).loader.get_source(mod)
        assert "sandroid.core.sandroid_console" not in src
        assert "formatting import SandroidConsole" not in src
        assert "config.loader import get_config" not in src


def test_blocking_dialog_tui_route_never_blocks_ui_thread(monkeypatch):
    from sandroid.core import ui_request_bus
    from sandroid.core.notifications.blocking_dialog import BlockingDialogService

    shown = []
    done = threading.Event()

    def fake_show(title, message, level="info"):
        shown.append((title, level, threading.current_thread()))
        done.set()

    bus = SimpleNamespace(has_active_handler=lambda: True)
    monkeypatch.setattr(ui_request_bus.UIRequestBus, "get", classmethod(lambda c: bus))
    monkeypatch.setattr(ui_request_bus, "show_message", fake_show)

    assert BlockingDialogService._try_tui_dialog("T", "M", None, "warning")
    assert done.wait(2)
    title, level, thread = shown[0]
    assert (title, level) == ("T", "warning")
    assert thread is not threading.main_thread()


# ---------------------------------------------------------------------------
# Device selection: stale offline entries are ignored quietly
# ---------------------------------------------------------------------------


def test_offline_device_is_not_probed(monkeypatch):
    from sandroid.core.device_manager import DeviceManager

    probed = []
    monkeypatch.setattr(
        DeviceManager, "_populate_device_info", lambda self, d: probed.append(d.serial)
    )
    monkeypatch.setattr(DeviceManager, "auto_select_device", lambda self: None)
    out = (
        "List of devices attached\n"
        "emulator-5554 device product:sdk model:sdk transport_id:1\n"
        "emulator-5556 offline transport_id:2\n"
    )
    monkeypatch.setattr(
        Adb, "send_adb_command", classmethod(lambda cls, c, serial=None: (out, ""))
    )
    DeviceManager.reset()
    try:
        devices = DeviceManager.get().refresh_devices()
    finally:
        DeviceManager.reset()
    assert {d.serial for d in devices} == {"emulator-5554", "emulator-5556"}
    assert probed == ["emulator-5554"]


# ---------------------------------------------------------------------------
# TUI: chat panel is optional; CLI: --view is gone
# ---------------------------------------------------------------------------


def test_chat_panel_missing_dependency_yields_placeholder(monkeypatch):
    from textual.widgets import Static

    from sandroid.tui import widgets
    from sandroid.tui.screens.main_screen import MainScreen

    # A None entry in sys.modules makes the import raise ImportError.
    monkeypatch.setitem(sys.modules, "sandroid.tui.widgets.chat_panel", None)
    assert widgets.load_chat_panel_class() is None
    assert widgets.CHAT_PANEL_IMPORT_ERROR
    panel = MainScreen._make_chat_panel()
    assert type(panel) is Static
    assert panel.id == "chat-panel"


def test_cli_has_no_view_option():
    from click.testing import CliRunner

    from sandroid.cli import main

    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "--view" not in result.output


# ---------------------------------------------------------------------------
# Device serial selection (--serial / config / ANDROID_SERIAL)
# ---------------------------------------------------------------------------


@pytest.fixture
def clean_serial(monkeypatch):
    from sandroid.core.device_manager import DeviceManager

    monkeypatch.delenv("ANDROID_SERIAL", raising=False)
    DeviceManager.set_preferred_serial(None)
    DeviceManager.reset()
    Adb.set_target_device(None)
    yield DeviceManager
    DeviceManager.set_preferred_serial(None)
    DeviceManager.reset()
    Adb.set_target_device(None)


_TWO_EMUS = (
    "List of devices attached\n"
    "emulator-5554 device product:sdk model:sdk transport_id:1\n"
    "emulator-5558 device product:sdk model:sdk transport_id:2\n"
)


def test_apply_serial_selection_pins_adb_target(clean_serial, monkeypatch):
    from sandroid.core.initializer import apply_serial_selection

    assert apply_serial_selection(None) is None
    assert Adb.get_target_device() is None

    monkeypatch.setenv("ANDROID_SERIAL", "emulator-5556")
    assert apply_serial_selection(None) == "emulator-5556"
    assert Adb.get_target_device() == "emulator-5556"

    assert apply_serial_selection("emulator-5558") == "emulator-5558"
    assert Adb.get_target_device() == "emulator-5558"
    assert clean_serial.preferred_serial() == "emulator-5558"


def test_auto_select_honours_preferred_serial_and_skips_foreign_probes(
    clean_serial, monkeypatch
):
    device_manager_cls = clean_serial
    probed = []
    monkeypatch.setattr(
        device_manager_cls,
        "_populate_device_info",
        lambda self, d: probed.append(d.serial),
    )
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        classmethod(lambda c, cmd, serial=None: (_TWO_EMUS, "")),
    )
    selected = []
    monkeypatch.setattr(
        device_manager_cls,
        "set_active_device",
        lambda self, s: selected.append(s) or True,
    )
    device_manager_cls.set_preferred_serial("emulator-5558")
    device_manager_cls.get().refresh_devices()
    assert selected == ["emulator-5558"]  # not the first emulator
    assert probed == ["emulator-5558"]  # 5554 belongs to someone else


def test_auto_select_never_falls_back_when_preferred_missing(clean_serial, monkeypatch):
    device_manager_cls = clean_serial
    monkeypatch.setattr(
        device_manager_cls, "_populate_device_info", lambda self, d: None
    )
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        classmethod(lambda c, cmd, serial=None: (_TWO_EMUS, "")),
    )
    monkeypatch.setenv("ANDROID_SERIAL", "emulator-9999")
    dm = device_manager_cls.get()
    dm.refresh_devices(auto_select=False)
    assert dm.auto_select_device() is None


def test_cli_serial_option_and_override():
    from click.testing import CliRunner

    from sandroid.cli import main
    from sandroid.cli_modes.helpers import build_cli_overrides

    assert "--serial" in CliRunner().invoke(main, ["--help"]).output
    values = dict.fromkeys(
        [
            "file",
            "loglevel",
            "number",
            "whitelist",
            "trigdroid",
            "trigdroid_ccf",
        ]
    )
    flags = dict.fromkeys(
        [
            "debug",
            "avoid_strong_noise_filter",
            "network",
            "show_deleted",
            "no_processes",
            "sockets",
            "hash_files",
            "apk",
            "degrade_network",
            "report",
        ],
        False,
    )
    overrides = build_cli_overrides(**values, **flags, serial="emulator-5558")
    assert overrides["emulator"] == {"serial": "emulator-5558"}


# ---------------------------------------------------------------------------
# One results root + run finalisation
# ---------------------------------------------------------------------------


def test_session_folder_uses_configured_results_path(tmp_path, monkeypatch):
    from sandroid.core.toolbox import Toolbox
    from sandroid.services.initialization_service import InitializationService

    cfg = SimpleNamespace(paths=SimpleNamespace(results_path=tmp_path / "res"))
    monkeypatch.setattr(Toolbox, "config", cfg, raising=False)
    for var in ("SESSION_PATH", "RESULTS_PATH", "RAW_RESULTS_PATH"):
        monkeypatch.setenv(var, "")
    paths = InitializationService().create_session(
        timestamp="20260101_000000", setup_logging=False
    )
    assert paths.session_path == (tmp_path / "res" / "20260101_000000").resolve()


def test_set_config_makes_get_config_return_cli_config():
    import sandroid.config as config_mod

    saved = config_mod._config_instance
    try:
        sentinel = SimpleNamespace(paths=SimpleNamespace(results_path="/x"))
        config_mod.set_config(sentinel)
        assert config_mod.get_config() is sentinel
    finally:
        config_mod._config_instance = saved


def test_tui_play_finalizes_run_bundle(tmp_path, monkeypatch):
    from sandroid.core import run_bundle, run_report
    from sandroid.tui.controllers.recording_controller import RecordingController

    seen = {}

    def fake_finalize(result_dir, results, **kwargs):
        seen.update(kwargs, result_dir=result_dir, results=results)
        return run_report.FinalizeOutcome(results_json=tmp_path / "sandroid.json")

    monkeypatch.setattr(run_report, "finalize_run", fake_finalize)
    cfg = SimpleNamespace(report=SimpleNamespace(generate_pdf=True))
    ctl = RecordingController(
        toolbox=SimpleNamespace(config=cfg), call_from_thread=lambda fn, *a: fn(*a)
    )
    result = SimpleNamespace(to_json_dict=lambda: {"Device Name": "x"})
    ctl._finalize_run_bundle(
        run_id="r1", result=result, bundle_dir=str(tmp_path), recorded_at="t0"
    )
    assert seen["result_dir"] == str(tmp_path)
    assert seen["mode"] == "tui-play"
    assert seen["run_id"] == "r1"
    assert seen["generate_pdf"] is True
    assert seen["config"] is cfg

    run_bundle.record_session_bundle(str(tmp_path))
    assert str(tmp_path) in run_bundle.session_bundles()
    # L12: a bundle deleted in the Runs lens is not listed at exit.
    gone = tmp_path / "deleted_run"
    gone.mkdir()
    run_bundle.record_session_bundle(str(gone))
    gone.rmdir()
    assert str(gone) not in run_bundle.session_bundles()


def test_headless_runner_finalizes_into_session_dir(tmp_path, monkeypatch):
    from sandroid.api import analysis_runners
    from sandroid.core import run_report

    seen = {}

    def fake_finalize(result_dir, results, **kwargs):
        seen.update(kwargs, result_dir=result_dir)
        return run_report.FinalizeOutcome(results_json=tmp_path / "x.json")

    monkeypatch.setattr(run_report, "finalize_run", fake_finalize)
    monkeypatch.setenv("SESSION_PATH", str(tmp_path))
    analysis_runners._finalize_headless_run(
        SimpleNamespace(config=None),
        SimpleNamespace(to_json_dict=dict),
        "headless-forensic",
        "t0",
    )
    assert seen["result_dir"] == str(tmp_path)
    assert seen["mode"] == "headless-forensic"
    assert seen["generate_pdf"] is False


def test_exit_helper_hard_exits_only_with_lingering_threads(monkeypatch):
    from sandroid.cli_modes import interactive

    exited = []
    monkeypatch.setattr(interactive, "_stop_capture_children", lambda: None)
    monkeypatch.setattr("os._exit", exited.append)
    monkeypatch.setattr("sandroid.tui.terminal_reset.reset_terminal_hard", lambda: None)
    monkeypatch.setattr("logging.shutdown", lambda: None)
    interactive._exit_without_lingering_threads(grace=0.1)
    assert exited == []

    stop = threading.Event()
    t = threading.Thread(target=stop.wait, name="stuck-reader", daemon=False)
    t.start()
    try:
        interactive._exit_without_lingering_threads(grace=0.1)
        assert exited == [0]
    finally:
        stop.set()
        t.join()


# ---------------------------------------------------------------------------
# Headless output, exit codes, capture-window prompts, --import-action
# ---------------------------------------------------------------------------

#: First lines of the tester's Wikipedia run bundle recording.txt.
RECORDING = """1794847081351 /dev/input/event1 0 0 0
1794847083059 /dev/input/event1 3 57 7
1794847083061 /dev/input/event1 3 53 16322
1794847083074 /dev/input/event1 3 54 30252
"""


def _run_cli_headless(monkeypatch, doc, *, report=False, mode="forensic", **kw):
    """Run the headless CLI mode against a fake API returning ``doc``."""
    import sandroid.api as api_pkg
    from sandroid.cli_modes import headless as cli_headless

    calls = {}

    class _FakeAPI:
        def __init__(self, config=None, config_path=None):
            self.last_run_documentation = None

        async def initialize(self):
            return SimpleNamespace(success=True)

        async def run_analysis(self, **kwargs):
            calls["run"] = kwargs
            self.last_run_documentation = doc
            return {
                "Changed Files": ["/data/a", {"/data/b.db": ["+ x"]}],
                "New Files": ["/data/c"],
                "Action Duration": 60,
                "analysis_type": "forensic",
                "runs": 2,
            }

        async def shutdown(self):
            calls["shutdown"] = True

    monkeypatch.setattr(api_pkg, "SandroidHeadlessAPI", _FakeAPI)
    cfg = SimpleNamespace(report=SimpleNamespace(generate_pdf=report))
    cli_headless.run_headless_analysis(
        sandroid_config=cfg,
        active_logger=None,
        package=None,
        batch_config=None,
        mode=mode,
        runs=2,
        network=False,
        hash_files=False,
        show_deleted=False,
        output_file=None,
        **kw,
    )
    return calls


def test_headless_prints_summary_not_json(monkeypatch, capsys, tmp_path):
    from sandroid.core import run_report

    doc = run_report.FinalizeOutcome(
        results_json=tmp_path / "sandroid.json", pdf=tmp_path / "r.pdf"
    )
    calls = _run_cli_headless(monkeypatch, doc, report=True)
    out = capsys.readouterr().out
    assert '"Changed Files"' not in out  # no JSON dump
    assert "Changed Files: 2" in out
    assert str(tmp_path / "sandroid.json") in out
    assert str(tmp_path / "r.pdf") in out
    assert "completed successfully" in out
    # Forensic runs get the window prompt callback.
    assert callable(calls["run"]["window_notify"])


def test_headless_failed_report_exits_nonzero(monkeypatch, capsys, tmp_path):
    """P2: --report failed with only a WARNING and exit 0."""
    from sandroid.cli_modes import headless as cli_headless
    from sandroid.core import run_report

    doc = run_report.FinalizeOutcome(
        results_json=tmp_path / "sandroid.json",
        errors=["pdf: Flowable too large on page 5"],
    )
    with pytest.raises(SystemExit) as info:
        _run_cli_headless(monkeypatch, doc, report=True)
    assert info.value.code == cli_headless.EXIT_DOCUMENTATION_FAILED
    out = capsys.readouterr().out
    assert "PDF report FAILED: Flowable too large on page 5" in out
    assert "completed successfully" not in out


def test_headless_missing_documentation_exits_nonzero(monkeypatch):
    with pytest.raises(SystemExit) as info:
        _run_cli_headless(monkeypatch, None)
    assert info.value.code == 3


def test_capture_window_action_prompts_each_run(monkeypatch):
    from sandroid.api import analysis_runners
    from sandroid.core.toolbox import Toolbox

    durations = []
    monkeypatch.setattr(Toolbox, "set_action_time", classmethod(lambda cls: None))
    monkeypatch.setattr(
        "sandroid.services.get_action_window_service",
        lambda: SimpleNamespace(set_duration=durations.append),
    )
    lines, slept = [], []
    action = analysis_runners.CaptureWindowAction(
        25, runs=2, notify=lines.append, sleep=slept.append
    )
    action.perform()
    action.perform()
    assert durations == [25, 25]
    assert slept == [10, 10, 5, 10, 10, 5]
    assert "Run 1/2: PERFORM THE ACTION ON THE DEVICE NOW (25 s remaining)" in lines[0]
    assert "Perform the same action in every run" in lines[0]
    assert "Run 1/2: 15 s remaining" in lines[1]
    assert any("Run 2/2: PERFORM THE ACTION" in ln for ln in lines)
    assert lines[-1].startswith("<<< Run 2/2: capture window closed")


def test_forensic_runner_replays_recording(monkeypatch):
    from sandroid.analysis.engine import AnalysisEngine
    from sandroid.api import analysis_runners
    from sandroid.features.player import Player

    captured = {}

    def _init(self, config, **kwargs):
        captured["config"] = config

    canned = SimpleNamespace(to_json_dict=dict)
    monkeypatch.setattr(AnalysisEngine, "__init__", _init)
    monkeypatch.setattr(AnalysisEngine, "run", lambda self: canned)
    monkeypatch.setattr(
        analysis_runners, "_finalize_headless_run", lambda *a, **k: None
    )
    toolbox = SimpleNamespace(create_snapshot=lambda name: None)
    asyncio.run(
        analysis_runners.run_forensic_analysis(
            toolbox=toolbox,
            runs=2,
            track_deleted=False,
            compute_hashes=False,
            recording_path="/abs/recording.txt",
        )
    )
    action = captured["config"].action
    assert isinstance(action, Player)
    assert action._recording_path == "/abs/recording.txt"


def test_resolve_recording(tmp_path):
    from sandroid.cli import resolve_recording

    bundle = tmp_path / "run"
    bundle.mkdir()
    (bundle / "recording.txt").write_text(RECORDING)
    path, err = resolve_recording(str(bundle))
    assert err is None
    assert path == str((bundle / "recording.txt").resolve())

    js = tmp_path / "a.json"
    js.write_text('{"actions": []}')
    path, err = resolve_recording(str(js))
    assert path is None
    assert "JSON action files cannot be replayed" in err

    junk = tmp_path / "junk.txt"
    junk.write_text("hello world\n")
    assert "not a Sandroid recording" in resolve_recording(str(junk))[1]
    assert "No recording found" in resolve_recording(str(tmp_path))[1]


def test_import_action_runs_headless_replay(monkeypatch, tmp_path):
    """P2: --import-action only json.loads'ed the file and replayed nothing."""
    from sandroid import cli, cli_modes

    rec = tmp_path / "recording.txt"
    rec.write_text(RECORDING)
    seen = {}
    monkeypatch.setattr(
        cli_modes, "run_headless_analysis", lambda **kw: seen.update(kw)
    )
    cli._run_import_action(object(), str(rec), runs=3, output_file="o.json")
    assert seen["mode"] == "forensic"
    assert seen["runs"] == 3
    assert seen["recording_path"] == str(rec.resolve())
    assert seen["output_file"] == "o.json"

    js = tmp_path / "a.json"
    js.write_text("[]")
    with pytest.raises(SystemExit) as info:
        cli._run_import_action(object(), str(js))
    assert info.value.code == 1


def test_headless_cli_forwards_recording(monkeypatch, tmp_path):
    from sandroid.core import run_report

    doc = run_report.FinalizeOutcome(results_json=tmp_path / "sandroid.json")
    calls = _run_cli_headless(monkeypatch, doc, recording_path="/abs/rec.txt")
    assert calls["run"]["recording_path"] == "/abs/rec.txt"
    assert "window_notify" not in calls["run"]


def test_headless_api_keeps_run_documentation(monkeypatch):
    from sandroid.api import headless
    from sandroid.api.interfaces import AnalysisMode

    async def fake_forensic(**kwargs):
        kwargs["on_finalized"]("DOC")
        return {}

    monkeypatch.setattr(headless, "run_forensic_analysis", fake_forensic)
    _device_ok(monkeypatch)
    api = headless.SandroidHeadlessAPI(config=SimpleNamespace())
    api._initialized = True
    asyncio.run(api.run_analysis(AnalysisMode.FORENSIC))
    assert api.last_run_documentation == "DOC"


def test_batch_reports_documentation_errors_and_exits_nonzero(monkeypatch, tmp_path):
    import json as _json

    import sandroid.api as api_pkg
    from sandroid.api import batch, headless
    from sandroid.cli_modes import headless as cli_headless
    from sandroid.core import run_report

    class _FakeAPI:
        def __init__(self, config_path=None, config=None):
            self.last_run_documentation = None

        async def initialize(self):
            return SimpleNamespace(success=True)

        async def run_analysis(self, **kwargs):
            self.last_run_documentation = run_report.FinalizeOutcome(
                results_json=tmp_path / "s.json", errors=["pdf: too large"]
            )
            return {}

        async def shutdown(self):
            return None

    monkeypatch.setattr(headless, "SandroidHeadlessAPI", _FakeAPI)
    monkeypatch.setattr(api_pkg, "batch_analyze", batch.batch_analyze)
    cfg_file = tmp_path / "batch.json"
    cfg_file.write_text(
        _json.dumps({"packages": ["a.b"], "output_dir": str(tmp_path / "out")})
    )
    with pytest.raises(SystemExit) as info:
        cli_headless.run_headless_analysis(
            sandroid_config=object(),
            active_logger=None,
            package=None,
            batch_config=str(cfg_file),
            mode="malware",
            runs=2,
            network=False,
            hash_files=False,
            show_deleted=False,
            output_file=None,
        )
    assert info.value.code == cli_headless.EXIT_DOCUMENTATION_FAILED
