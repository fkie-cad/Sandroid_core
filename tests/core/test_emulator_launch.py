"""Emulator launch paths: safe flags, no undrained pipes, verified restart."""

from __future__ import annotations

import subprocess
import sys
import threading

import pytest

from sandroid.core import emulator as emu


@pytest.fixture
def log_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(emu, "EMULATOR_LOG_DIR", tmp_path / "emulogs")
    return tmp_path / "emulogs"


# -- C10: detached emulator output never goes to an undrained pipe ----------


def test_spawn_emulator_writes_output_to_log_not_a_pipe(log_dir):
    """A chatty child must not stall once 64 KiB of stderr pile up."""
    chatty = (
        "import sys\n"
        "for _ in range(4000):\n"
        "    sys.stderr.write('x' * 99 + '\\n')\n"
        "print('DONE', flush=True)\n"
    )
    proc, log_path = emu.spawn_emulator(
        [sys.executable, "-I", "-c", chatty], "My AVD/../x"
    )
    assert proc.stdout is None
    assert proc.stderr is None
    assert proc.wait(timeout=30) == 0  # would hang forever with stderr=PIPE
    assert log_path.parent == log_dir
    assert log_path.name == "My_AVD_.._x.log"
    data = log_path.read_text()
    assert "DONE" in data
    assert data.count("x" * 99) == 4000


def test_check_emulator_startup_reads_errors_from_log(log_dir, monkeypatch):
    monkeypatch.setattr(emu, "_STARTUP_GRACE_PERIOD", 0)
    proc, log_path = emu.spawn_emulator(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys; print('INFO ok'); print('PANIC: Missing AVD', "
            "file=sys.stderr); sys.exit(1)",
        ],
        "Broken",
    )
    proc.wait(timeout=30)
    ok, msg = emu.check_emulator_startup(proc, log_path)
    assert ok is False
    assert msg == "PANIC: Missing AVD"


def test_start_avd_uses_safe_flags_and_log(monkeypatch, log_dir):
    seen = {}

    class _Proc:
        pid = 1

    def fake_spawn(command, avd_name, env=None):
        seen["command"] = command
        return _Proc(), log_dir / "x.log"

    monkeypatch.setattr(emu.Emulator, "detect_emulator_path", lambda: "/sdk/emulator")
    monkeypatch.setattr(emu, "spawn_emulator", fake_spawn)
    monkeypatch.setattr(emu, "check_emulator_startup", lambda p, log=None: (True, ""))
    assert emu.Emulator.start_avd("Pixel") is True
    assert seen["command"][:3] == ["/sdk/emulator", "-avd", "Pixel"]
    assert seen["command"][3:5] == ["-feature", "-Vulkan"]


# -- C5: TUI "start AVD" uses the same safe flags as the CLI ----------------


@pytest.mark.parametrize("headless", [False, True])
def test_tui_start_avd_disables_guest_vulkan(monkeypatch, headless):
    from sandroid.config import android_env
    from sandroid.core.emulator_guard import emulator_launch_args
    from sandroid.tui.controllers import device_controller as dc

    started = threading.Event()
    seen = {}

    def fake_popen(cmd, **kwargs):
        seen["cmd"] = cmd
        started.set()

    monkeypatch.setattr(dc.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(android_env, "find_existing_avd_home", lambda: None)
    controller = dc.DeviceController(toolbox=None)
    monkeypatch.setattr(controller, "start_device_poll", lambda name: None)
    assert controller.start_avd_and_poll(
        "Pixel", headless=headless, emulator_path="/sdk/emulator", sdk_path="/sdk"
    )
    assert started.wait(5)
    cmd = seen["cmd"]
    assert cmd[:3] == ["/sdk/emulator", "-avd", "Pixel"]
    tail = emulator_launch_args(headless=headless)
    assert cmd[-len(tail) :] == tail
    assert ("-no-window" in cmd) is headless


# -- C6: restart relaunches the RUNNING AVD and waits for boot --------------


class _RestartAdb:
    def __init__(self, avd="RunningAVD", boot_after=2):
        self.avd = avd
        self.boot_after = boot_after
        self.commands: list[tuple] = []
        self._boot_polls = 0

    def get_target_device(self):
        return "emulator-5556"

    def get_current_avd_name(self):
        return self.avd

    def send_telnet_command(self, command, serial=None):
        self.commands.append(("telnet", command))
        return "OK", ""

    def send_adb_command(self, command, serial=None):
        self.commands.append((command, serial))
        if command == "get-state":
            return "", "error: device offline"
        if command == "shell getprop sys.boot_completed":
            self._boot_polls += 1
            return ("1" if self._boot_polls >= self.boot_after else ""), ""
        return "", ""


@pytest.fixture
def restart_env(monkeypatch, log_dir):
    from sandroid.services import emulator_service as es

    spawned = []

    class _Proc:
        pid = 99

    def fake_spawn(command, avd_name, env=None):
        spawned.append(command)
        return _Proc(), log_dir / "x.log"

    monkeypatch.setattr(emu, "spawn_emulator", fake_spawn)
    monkeypatch.setattr(emu, "check_emulator_startup", lambda p, log=None: (True, ""))
    monkeypatch.setattr(emu.Emulator, "detect_emulator_path", lambda: "/sdk/emulator")
    monkeypatch.setattr(es.time, "sleep", lambda s: None)
    return es, spawned


def test_restart_relaunches_running_avd_with_safe_flags(restart_env):
    es, spawned = restart_env
    adb = _RestartAdb()
    svc = es.EmulatorService(adb=adb)
    assert svc.restart(boot_timeout=60) is True
    assert spawned == [
        ["/sdk/emulator", "-avd", "RunningAVD", "-feature", "-Vulkan", "-gpu", "host"]
    ]
    assert ("telnet", b"kill") in adb.commands
    assert ("shell getprop sys.boot_completed", "emulator-5556") in adb.commands


def test_restart_reports_failure_when_device_never_boots(restart_env, monkeypatch):
    es, _ = restart_env
    clock = iter(range(0, 10_000, 5))
    monkeypatch.setattr(es.time, "monotonic", lambda: next(clock))
    svc = es.EmulatorService(adb=_RestartAdb(boot_after=10**9))
    assert svc.restart(boot_timeout=30) is False


def test_restart_reports_startup_crash(restart_env, monkeypatch):
    es, _ = restart_env
    monkeypatch.setattr(
        emu, "check_emulator_startup", lambda p, log=None: (False, "PANIC: x")
    )
    assert es.EmulatorService(adb=_RestartAdb()).restart(boot_timeout=60) is False


def test_restart_missing_binary_raises(restart_env, monkeypatch):
    es, _ = restart_env
    monkeypatch.setattr(emu.Emulator, "detect_emulator_path", lambda: None)
    with pytest.raises(RuntimeError, match="not found"):
        es.EmulatorService(adb=_RestartAdb()).restart()


def test_spawn_failure_propagates(log_dir, monkeypatch):
    def boom(*a, **kw):
        raise FileNotFoundError("no emulator")

    monkeypatch.setattr(subprocess, "Popen", boom)
    with pytest.raises(FileNotFoundError):
        emu.spawn_emulator(["/nope/emulator"], "X")
