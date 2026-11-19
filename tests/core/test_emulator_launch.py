"""Emulator launch + lifecycle (core.emulator) with a fake adb.

Covers: detached output never goes to an undrained pipe; launches use an
explicit ``-port`` and the safe flags; crash -> EmulatorLaunchError naming the
log; one retry when the chosen port is grabbed; ``stop_emulator`` sends
``emu kill`` to exactly one serial; ``restart_emulator`` keeps AVD, port and
options; ``wait_until_ready`` needs boot_completed AND the package manager;
EmulatorService / DeviceController delegate with the right serial.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from sandroid.core import emulator as emu
from sandroid.core.emulator import AvdLaunchOptions
from sandroid.core.exceptions import EmulatorLaunchError

_real_sleep = time.sleep  # the env fixture turns time.sleep into a no-op


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


def test_spawn_failure_propagates(log_dir, monkeypatch):
    def boom(*a, **kw):
        raise FileNotFoundError("no emulator")

    monkeypatch.setattr(subprocess, "Popen", boom)
    with pytest.raises(FileNotFoundError):
        emu.spawn_emulator(["/nope/emulator"], "X")


# -- fake adb + launch environment -------------------------------------------


class FakeAdb:
    """adb double: a device table, per-serial boot/pm readiness, AVD names."""

    def __init__(self):
        self.devices: dict[str, str] = {}  # serial -> state
        self.booted: dict[str, bool] = {}
        self.pm_ready: dict[str, bool] = {}
        self.avd: dict[str, str] = {}
        self.calls: list[tuple[str, str | None]] = []
        self.kill_removes = True
        self.target = None

    def add(self, serial, avd="", state="device", booted=True, pm=True):
        self.devices[serial] = state
        self.avd[serial] = avd
        self.booted[serial] = booted
        self.pm_ready[serial] = pm

    def get_target_device(self):
        return self.target

    def send_adb_command(self, command, serial=None, timeout=30):
        self.calls.append((command, serial))
        if command.startswith("devices"):
            lines = ["List of devices attached"]
            lines += [f"{s}\t{st}" for s, st in self.devices.items()]
            return "\n".join(lines) + "\n", ""
        if serial not in self.devices:
            return "", f"error: device '{serial}' not found"
        if command == "shell getprop sys.boot_completed":
            return ("1\n" if self.booted.get(serial) else "\n"), ""
        if command == "shell pm path android":
            if self.pm_ready.get(serial):
                return "package:/system/framework/framework-res.apk\n", ""
            return "", "Error: Could not access the Package Manager."
        if command == "shell getprop ro.boot.qemu.avd_name":
            return self.avd.get(serial, "") + "\n", ""
        return "", ""

    def send_telnet_command(self, command, serial=None):
        self.calls.append((f"telnet {command}", serial))
        if serial not in self.devices:
            return "", f"error: device '{serial}' not found"
        if self.devices[serial] != "device":
            return "", "error: device offline"
        if command == "kill" and self.kill_removes:
            self.devices.pop(serial, None)
        return "OK", ""

    def get_current_avd_name(self, serial=None):
        return self.avd.get(serial) or None


class _Proc:
    def __init__(self, pid=4242, exit_code=None):
        self.pid = pid
        self.exit_code = exit_code
        self.signals: list[str] = []
        self.on_exit = None  # called once the process "exits"

    def poll(self):
        return self.exit_code

    def _exit(self, code):
        self.exit_code = code
        if self.on_exit:
            self.on_exit()

    def terminate(self):
        self.signals.append("TERM")
        self._exit(-15)

    def kill(self):
        self.signals.append("KILL")
        self._exit(-9)

    def wait(self, timeout=None):
        if self.exit_code is None:
            raise subprocess.TimeoutExpired("emulator", timeout)
        return self.exit_code


@pytest.fixture
def env(monkeypatch, tmp_path, log_dir):
    """Fake adb, spawn, binary, ports and clock; isolated prefs + registry."""
    adb = FakeAdb()
    state = {
        "spawned": [],
        "busy": set(),
        "startup": [],
        "on_spawn": None,
        "procs": [],
    }

    def fake_spawn(command, avd_name, env=None):
        state["spawned"].append(command)
        if state["on_spawn"]:
            state["on_spawn"](command)
        proc = _Proc()
        serial = f"emulator-{_port_of(command)}"
        proc.on_exit = lambda: adb.devices.pop(serial, None)  # adb drops it
        state["procs"].append(proc)
        return proc, log_dir / f"{avd_name}.log"

    def fake_startup(process, log_path=None):
        if state["startup"]:
            return state["startup"].pop(0)
        return True, ""

    monkeypatch.setattr(emu, "_adb", lambda a: a if a is not None else adb)
    monkeypatch.setattr(emu, "emulator_binary", lambda: Path("/sdk/emulator"))
    monkeypatch.setattr(emu, "emulator_env", dict)
    monkeypatch.setattr(emu, "spawn_emulator", fake_spawn)
    monkeypatch.setattr(emu, "check_emulator_startup", fake_startup)
    monkeypatch.setattr(emu, "_ports_free", lambda p: p not in state["busy"])
    monkeypatch.setattr(emu.time, "sleep", lambda s: None)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(emu, "_LAUNCHES", {})
    monkeypatch.setattr(emu, "_RESERVED_PORTS", set())
    monkeypatch.setattr(emu, "_STARTING_AVDS", set())
    state["adb"] = adb
    return state


def _port_of(command):
    return int(command[command.index("-port") + 1])


# -- launch -----------------------------------------------------------------


def test_launch_avd_uses_explicit_port_safe_flags_and_registers(env):
    env["adb"].add("emulator-5554", avd="Other")
    launch = emu.launch_avd("Pixel")
    assert env["spawned"] == [
        [
            "/sdk/emulator",
            "-avd",
            "Pixel",
            "-port",
            "5556",
            "-feature",
            "-Vulkan",
            "-gpu",
            "host",
        ]
    ]
    assert launch.serial == "emulator-5556"
    assert launch.port == 5556
    assert emu.get_launch("emulator-5556") is launch
    assert emu.booting_serials() == ["emulator-5556"]


def test_launch_avd_skips_ports_of_our_live_launches(env):
    emu.launch_avd("A")
    second = emu.launch_avd("B")
    assert second.serial == "emulator-5556"


def test_near_simultaneous_launches_never_share_a_port(env):
    """B is started while A's process is still being spawned (A is not in
    the registry yet): A's port is reserved, so B takes the next one.
    """
    second = []

    def start_b_meanwhile(command):
        if _port_of(command) == 5554 and not second:
            second.append(None)
            second[0] = emu.launch_avd("B")

    env["on_spawn"] = start_b_meanwhile
    first = emu.launch_avd("A")
    assert first.port == 5554
    assert second[0].port == 5556
    assert not emu._RESERVED_PORTS


def test_a_running_avd_is_not_launched_twice(env):
    first = emu.launch_avd("Pixel")
    with pytest.raises(EmulatorLaunchError, match="already running"):
        emu.launch_avd("Pixel")
    assert len(env["spawned"]) == 1
    first.process.exit_code = 0  # it exited: may start again
    assert emu.launch_avd("Pixel").port == 5554


def test_launch_avd_crash_raises_with_log_path(env):
    env["startup"] = [(False, "PANIC: Missing AVD")]
    with pytest.raises(EmulatorLaunchError) as info:
        emu.launch_avd("Pixel")
    assert "PANIC: Missing AVD" in str(info.value)
    assert "Pixel.log" in str(info.value)
    assert info.value.log_path.name == "Pixel.log"
    assert emu.booting_serials() == []
    assert len(env["spawned"]) == 1  # port was still free: no retry


def test_launch_avd_retries_once_on_next_port_when_taken(env):
    def grab_port(command):
        env["busy"].add(_port_of(command))  # another session took it

    env["on_spawn"] = grab_port
    env["startup"] = [(False, "ERROR: port in use"), (True, "")]
    launch = emu.launch_avd("Pixel")
    assert [_port_of(c) for c in env["spawned"]] == [5554, 5556]
    assert launch.serial == "emulator-5556"


def test_launch_avd_explicit_port_is_not_retried(env):
    env["on_spawn"] = lambda command: env["busy"].add(_port_of(command))
    env["startup"] = [(False, "ERROR: port in use")]
    with pytest.raises(EmulatorLaunchError):
        emu.launch_avd("Pixel", port=5570)
    assert [_port_of(c) for c in env["spawned"]] == [5570]


def test_launch_avd_without_binary_raises(env, monkeypatch):
    monkeypatch.setattr(emu, "emulator_binary", lambda: None)
    with pytest.raises(EmulatorLaunchError, match="not found"):
        emu.launch_avd("Pixel")
    assert env["spawned"] == []


# -- stop / restart -----------------------------------------------------------


def test_stop_emulator_sends_emu_kill_to_that_serial_only(env, monkeypatch):
    adb = env["adb"]
    adb.add("emulator-5554", avd="Mine")
    adb.add("emulator-5556", avd="TheirSession")
    popen_calls = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: popen_calls.append(a))
    assert emu.stop_emulator("emulator-5554") is True
    telnet = [c for c in adb.calls if c[0].startswith("telnet")]
    assert telnet == [("telnet kill", "emulator-5554")]
    assert "emulator-5556" in adb.devices
    assert popen_calls == []  # no pkill / killall, nothing spawned


def test_stop_emulator_keeps_a_reachable_emulator_s_process_alone(env):
    """The console kill worked: the emulator shuts down on its own (it may
    be saving its quick-boot snapshot) and is never signalled.
    """
    launch = emu.launch_avd("Pixel")
    env["adb"].add(launch.serial, avd="Pixel")
    assert emu.stop_emulator(launch.serial) is True
    assert launch.process.signals == []
    assert launch.cancel.is_set()
    assert emu.get_launch(launch.serial) is None


@pytest.mark.parametrize("listed_as", [None, "offline"])
def test_stop_emulator_terminates_our_launch_adb_cannot_reach(env, listed_as):
    """Stopped before adb lists it (or while it is still offline): ``emu
    kill`` cannot reach it, so our own process is terminated -- otherwise it
    kept booting and was attached later.
    """
    launch = emu.launch_avd("Pixel")
    if listed_as:
        env["adb"].add(launch.serial, state=listed_as)
    assert emu.stop_emulator(launch.serial) is True
    assert launch.process.signals == ["TERM"]
    assert not launch.alive
    assert launch.cancel.is_set()
    assert emu.get_launch(launch.serial) is None
    assert launch.serial not in env["adb"].devices
    assert emu.booting_serials() == []


def test_stop_emulator_kills_our_process_when_term_is_ignored(env):
    launch = emu.launch_avd("Pixel")
    launch.process.terminate = lambda: launch.process.signals.append("TERM")
    assert emu.stop_emulator(launch.serial) is True
    assert launch.process.signals == ["TERM", "KILL"]


def test_stop_emulator_never_signals_someone_else_s_emulator(env):
    env["adb"].add("emulator-5556", state="offline")  # not our launch
    env["adb"].kill_removes = False
    assert emu.stop_emulator("emulator-5556", timeout=0) is False
    assert env["procs"] == []


def test_stop_emulator_refuses_non_emulator_serials(env):
    assert emu.stop_emulator("R58N123ABC") is False
    assert env["adb"].calls == []


def test_stop_emulator_reports_failure_when_serial_stays(env):
    env["adb"].add("emulator-5554")
    env["adb"].kill_removes = False
    assert emu.stop_emulator("emulator-5554", timeout=0) is False


def test_restart_reuses_port_and_launch_options(env):
    adb = env["adb"]
    first = emu.launch_avd(
        "Pixel", AvdLaunchOptions(headless=True, boot="cold"), port=5560
    )
    adb.add(first.serial, avd="Pixel")
    second = emu.restart_emulator(first.serial)
    assert second.serial == first.serial == "emulator-5560"
    command = env["spawned"][-1]
    assert _port_of(command) == 5560
    assert "-no-window" in command
    assert "-no-snapshot-load" in command
    assert ("telnet kill", "emulator-5560") in adb.calls


def test_restart_cancels_the_old_launch_s_boot_waiter(env):
    first = emu.launch_avd("Pixel", port=5560)
    env["adb"].add(first.serial, avd="Pixel")
    second = emu.restart_emulator(first.serial)
    assert first.cancel.is_set()
    assert not second.cancel.is_set()
    assert emu.get_launch("emulator-5560") is second


def test_restart_resolves_avd_before_kill_and_never_wipes(env):
    adb = env["adb"]
    adb.add("emulator-5558", avd="Other")
    launch = emu.restart_emulator("emulator-5558", AvdLaunchOptions(boot="wipe"))
    assert launch.avd == "Other"
    command = env["spawned"][-1]
    assert command[:5] == ["/sdk/emulator", "-avd", "Other", "-port", "5558"]
    assert "-wipe-data" not in command
    names = [c[0] for c in adb.calls]
    assert names.index("shell getprop ro.boot.qemu.avd_name") < names.index(
        "telnet kill"
    )


def test_restart_without_launch_record_uses_remembered_options(env):
    env["adb"].add("emulator-5558", avd="Other")
    emu.remember_launch(
        "Other", AvdLaunchOptions(headless=True, boot="snapshot", snapshot="clean")
    )
    emu.restart_emulator("emulator-5558")
    command = env["spawned"][-1]
    assert command[-2:] == ["-snapshot", "clean"]
    assert "-no-window" in command


def test_restart_fails_cleanly_when_avd_is_unknown(env):
    env["adb"].add("emulator-5558", avd="")
    with pytest.raises(EmulatorLaunchError, match="AVD"):
        emu.restart_emulator("emulator-5558")
    assert not any(c[0].startswith("telnet") for c in env["adb"].calls)


# -- readiness ----------------------------------------------------------------


def test_wait_until_ready_needs_boot_completed_and_package_manager(env):
    adb = env["adb"]
    seen = []
    script = iter(
        [
            lambda: adb.add("emulator-5554", state="offline"),
            lambda: adb.add("emulator-5554", booted=False, pm=False),
            lambda: adb.add("emulator-5554", booted=True, pm=False),
            lambda: adb.add("emulator-5554", booted=True, pm=True),
        ]
    )

    def progress(state, elapsed):
        seen.append(state)
        step = next(script, None)
        if step:
            step()

    assert emu.wait_until_ready("emulator-5554", on_progress=progress) is True
    assert seen == ["absent", "offline", "booting", "booting", "ready"]


def test_wait_until_ready_marks_our_launch_ready(env):
    launch = emu.launch_avd("Pixel")
    env["adb"].add(launch.serial)
    assert emu.booting_serials() == [launch.serial]
    assert emu.wait_until_ready(launch.serial) is True
    assert emu.get_launch(launch.serial).ready is True
    assert emu.booting_serials() == []


def test_wait_until_ready_times_out(env):
    env["adb"].add("emulator-5554", booted=False)
    assert emu.wait_until_ready("emulator-5554", timeout=0) is False


def test_wait_until_ready_stops_when_our_launch_died(env):
    launch = emu.launch_avd("Pixel")
    launch.process.exit_code = 1
    assert emu.wait_until_ready(launch.serial, timeout=10_000) is False


def test_wait_until_ready_honours_cancel(env):
    env["adb"].add("emulator-5554", booted=False)
    cancel = threading.Event()
    cancel.set()
    assert emu.wait_until_ready("emulator-5554", cancel=cancel) is False


def test_ensure_avd_running_reuses_a_running_emulator(env):
    env["adb"].add("emulator-5570", avd="Pixel")
    assert emu.ensure_avd_running("Pixel") == "emulator-5570"
    assert env["spawned"] == []


def test_ensure_avd_running_skips_offline_emulators(env):
    env["adb"].add("emulator-5570", avd="Pixel", state="offline")
    env["on_spawn"] = lambda command: env["adb"].add(
        f"emulator-{_port_of(command)}", avd="Pixel"
    )
    assert emu.ensure_avd_running("Pixel") == "emulator-5554"
    asked = {serial for command, serial in env["adb"].calls if "avd" in command}
    assert "emulator-5570" not in asked


def test_avd_name_console_query_has_a_short_timeout(env, monkeypatch):
    seen = []
    adb = env["adb"]
    adb.add("emulator-5570", avd="")

    def send(command, serial=None, timeout=30):
        seen.append((command, timeout))
        if command == "emu avd name":
            return "Pixel\r\nOK\r\n", ""
        return "", ""

    monkeypatch.setattr(adb, "send_adb_command", send)
    assert emu.avd_name_of("emulator-5570") == "Pixel"
    assert ("emu avd name", emu._ADB_TIMEOUT) in seen
    assert all(timeout <= emu._ADB_TIMEOUT for _command, timeout in seen)


def test_ensure_avd_running_launches_waits_and_remembers(env):
    adb = env["adb"]
    env["on_spawn"] = lambda command: adb.add(
        f"emulator-{_port_of(command)}", avd="Pixel"
    )
    assert emu.ensure_avd_running("Pixel") == "emulator-5554"
    assert emu.load_launch_prefs()["last_avd"] == "Pixel"


def test_ensure_avd_running_raises_when_boot_times_out(env):
    env["on_spawn"] = lambda command: env["adb"].add(
        f"emulator-{_port_of(command)}", avd="Pixel", booted=False
    )
    with pytest.raises(EmulatorLaunchError, match="did not become ready"):
        emu.ensure_avd_running("Pixel", timeout=0)


# -- EmulatorService delegates with an explicit serial ------------------------


def test_service_restart_targets_the_adb_target_serial(env):
    from sandroid.services.emulator_service import EmulatorService

    adb = env["adb"]
    adb.add("emulator-5554", avd="Someone")
    adb.add("emulator-5556", avd="RunningAVD")
    adb.target = "emulator-5556"
    env["on_spawn"] = lambda command: adb.add("emulator-5556", avd="RunningAVD")
    assert EmulatorService(adb=adb).restart(boot_timeout=60) is True
    assert env["spawned"][-1][:5] == [
        "/sdk/emulator",
        "-avd",
        "RunningAVD",
        "-port",
        "5556",
    ]
    assert [c for c in adb.calls if c[0].startswith("telnet")] == [
        ("telnet kill", "emulator-5556")
    ]


def test_service_restart_reports_startup_crash(env):
    from sandroid.services.emulator_service import EmulatorService

    adb = env["adb"]
    adb.add("emulator-5556", avd="RunningAVD")
    adb.target = "emulator-5556"
    env["startup"] = [(False, "PANIC: x")]
    assert EmulatorService(adb=adb).restart(boot_timeout=60) is False


def test_service_restart_missing_binary_raises(env, monkeypatch):
    from sandroid.services.emulator_service import EmulatorService

    monkeypatch.setattr(emu, "emulator_binary", lambda: None)
    adb = env["adb"]
    adb.add("emulator-5556", avd="RunningAVD")
    adb.target = "emulator-5556"
    with pytest.raises(RuntimeError, match="not found"):
        EmulatorService(adb=adb).restart()
    assert adb.devices  # nothing was killed


def test_service_kill_stops_only_the_target(env):
    from sandroid.services.emulator_service import EmulatorService

    adb = env["adb"]
    adb.add("emulator-5554")
    adb.add("emulator-5556")
    adb.target = "emulator-5556"
    assert EmulatorService(adb=adb).kill() is True
    assert list(adb.devices) == ["emulator-5554"]


# -- DeviceController (TUI) goes through launch_avd / restart_emulator ---------


class _Dm:
    def __init__(self, active=None):
        self.active_device = active
        self.switched = []

    def refresh_devices(self, auto_select=True):
        return []

    def set_active_device(self, serial):
        self.switched.append(serial)
        self.active_device = type("D", (), {"serial": serial, "is_emulator": True})()
        return True

    def get_device(self, serial):
        return None


def _controller(dm, logs):
    from sandroid.tui.controllers.device_controller import DeviceController

    class _Toolbox:
        @classmethod
        def get_device_manager(cls):
            return dm

    return DeviceController(
        log_info=logs.append,
        log_warning=logs.append,
        log_error=logs.append,
        toolbox=_Toolbox,
    )


def _inline(controller) -> None:
    """Run the controller's background workers inline (deterministic)."""
    controller._spawn = lambda fn, name: fn()


@pytest.mark.parametrize("headless", [False, True])
def test_tui_start_avd_launches_with_safe_flags_and_attaches(env, headless):
    from sandroid.core.emulator_guard import emulator_launch_args

    adb = env["adb"]
    env["on_spawn"] = lambda command: adb.add(
        f"emulator-{_port_of(command)}", avd="Pixel"
    )
    dm, logs = _Dm(), []
    controller = _controller(dm, logs)
    controller.start_avd("Pixel", emu.AvdLaunchOptions(headless=headless))
    for thread in threading.enumerate():
        if thread.name == "start-avd-Pixel":
            thread.join(10)
    cmd = env["spawned"][0]
    assert cmd[:5] == ["/sdk/emulator", "-avd", "Pixel", "-port", "5554"]
    tail = emulator_launch_args(headless=headless)
    assert cmd[5 : 5 + len(tail)] == tail
    assert ("-no-window" in cmd) is headless
    assert dm.switched == ["emulator-5554"]  # nothing was active: attach
    assert emu.remembered_options("Pixel").headless is headless


def test_tui_boot_does_not_steal_an_active_device(env):
    adb = env["adb"]
    env["on_spawn"] = lambda command: adb.add(
        f"emulator-{_port_of(command)}", avd="Pixel"
    )
    active = type("D", (), {"serial": "R58N123ABC"})()
    dm, logs = _Dm(active=active), []
    controller = _controller(dm, logs)
    _inline(controller)
    controller.start_avd("Pixel", emu.AvdLaunchOptions(boot="cold"))
    assert dm.switched == []
    assert any("switch to it in Devices (D)" in str(m) for m in logs)
    assert "-no-snapshot-load" in env["spawned"][0]


def test_tui_restart_targets_the_given_serial_not_the_global_target(env):
    adb = env["adb"]
    adb.add("emulator-5554", avd="ActiveOne")
    adb.add("emulator-5556", avd="Pixel")
    adb.target = "emulator-5554"
    env["on_spawn"] = lambda command: adb.add("emulator-5556", avd="Pixel")
    dm, logs = _Dm(), []
    controller = _controller(dm, logs)
    _inline(controller)
    controller.restart_emulator("emulator-5556")
    assert [c for c in adb.calls if c[0].startswith("telnet")] == [
        ("telnet kill", "emulator-5556")
    ]
    assert env["spawned"][-1][:5] == [
        "/sdk/emulator",
        "-avd",
        "Pixel",
        "-port",
        "5556",
    ]
    assert "emulator-5554" in adb.devices


def test_tui_launch_failure_is_logged_not_raised(env):
    env["startup"] = [(False, "PANIC: broken")]
    dm, logs = _Dm(), []
    controller = _controller(dm, logs)
    _inline(controller)
    controller.start_avd("Pixel", emu.AvdLaunchOptions())
    assert any("PANIC: broken" in str(m) for m in logs)
    assert dm.switched == []


# -- boot waiters: cancel on stop/restart, keep waiting after the timeout ----


def _wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        _real_sleep(0.01)
    raise AssertionError("condition not reached")


def _join(name, timeout=10.0):
    for thread in threading.enumerate():
        if thread.name == name:
            thread.join(timeout)
            assert not thread.is_alive(), f"{name} still running"


def _ready_recorder(logs):
    from sandroid.tui.controllers.device_controller import DeviceController

    ready = []

    class _Toolbox:
        @classmethod
        def get_device_manager(cls):
            return _Dm()

    controller = DeviceController(
        log_info=logs.append,
        log_warning=logs.append,
        log_error=logs.append,
        toolbox=_Toolbox,
        on_emulator_ready=lambda serial, avd: ready.append((serial, avd)),
    )
    return controller, ready


def test_stop_during_boot_ends_the_boot_waiter_quietly(env, monkeypatch):
    monkeypatch.setattr(emu.time, "sleep", lambda s: _real_sleep(0.005))
    adb = env["adb"]
    env["on_spawn"] = lambda command: adb.add(
        f"emulator-{_port_of(command)}", avd="Pixel", booted=False
    )
    logs = []
    controller, ready = _ready_recorder(logs)
    controller.start_avd("Pixel")
    _wait_for(lambda: emu.get_launch("emulator-5554"))
    assert emu.stop_emulator("emulator-5554") is True
    _join("start-avd-Pixel")
    assert ready == []
    assert not any("booting" in str(m) for m in logs)  # no misleading warning


def test_restart_during_boot_reports_ready_once(env, monkeypatch):
    monkeypatch.setattr(emu.time, "sleep", lambda s: _real_sleep(0.005))
    adb = env["adb"]
    env["on_spawn"] = lambda command: adb.add(
        f"emulator-{_port_of(command)}", avd="Pixel", booted=False
    )
    logs = []
    controller, ready = _ready_recorder(logs)
    controller.start_avd("Pixel")
    first = _wait_for(lambda: emu.get_launch("emulator-5554"))
    controller.restart_emulator("emulator-5554")
    _wait_for(lambda: emu.get_launch("emulator-5554") not in (None, first))
    adb.booted["emulator-5554"] = True
    _join("restart-emulator-emulator-5554")
    _join("start-avd-Pixel")
    assert ready == [("emulator-5554", "Pixel")]
    assert first.cancel.is_set()


def test_slow_boot_is_still_attached_after_the_boot_timeout(env, monkeypatch):
    adb = env["adb"]
    env["on_spawn"] = lambda command: adb.add(
        f"emulator-{_port_of(command)}", avd="Pixel", booted=False
    )
    monkeypatch.setattr(emu, "DEFAULT_BOOT_TIMEOUT", 0.0)
    # Booted a while after the waiter's first timeout.
    monkeypatch.setattr(
        emu.time, "sleep", lambda s: adb.booted.update({"emulator-5554": True})
    )
    dm, logs = _Dm(), []
    controller = _controller(dm, logs)
    _inline(controller)
    controller.start_avd("Pixel")
    assert dm.switched == ["emulator-5554"]
    assert any("still booting" in str(m) for m in logs)
    assert emu.booting_serials() == []


def test_default_attach_never_switches_on_the_ui_thread(env):
    """``call_from_thread`` runs things on the UI thread: the device switch
    (adb work) must not be among them.
    """
    from sandroid.tui.controllers.device_controller import DeviceController

    adb = env["adb"]
    env["on_spawn"] = lambda command: adb.add(
        f"emulator-{_port_of(command)}", avd="Pixel"
    )
    on_ui = threading.local()
    switched_on_ui = []

    def call_from_thread(fn, *args):
        on_ui.active = True
        try:
            return fn(*args)
        finally:
            on_ui.active = False

    dm = _Dm()
    real_set = dm.set_active_device

    def set_active_device(serial):
        switched_on_ui.append(getattr(on_ui, "active", False))
        return real_set(serial)

    dm.set_active_device = set_active_device

    class _Toolbox:
        @classmethod
        def get_device_manager(cls):
            return dm

    controller = DeviceController(toolbox=_Toolbox, call_from_thread=call_from_thread)
    _inline(controller)
    controller.start_avd("Pixel")
    assert switched_on_ui == [False]
