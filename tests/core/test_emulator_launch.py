"""Emulator launch + lifecycle (core.emulator) with a fake adb.

Covers: detached output never goes to an undrained pipe; launches use an
explicit ``-port`` and the safe flags; crash -> EmulatorLaunchError naming the
log; one retry when an auto port is grabbed (never for a pinned / last-used
port); ``stop_emulator`` sends
``emu kill`` to exactly one serial; ``restart_emulator`` keeps AVD, port and
options; ``wait_until_ready`` needs boot_completed AND the package manager;
EmulatorService / DeviceController delegate with the right serial; the
pre-launch / post-stop hooks (order, fail-closed launch, once per launch).
"""

from __future__ import annotations

import json
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
        self.console: dict[str, bool] = {}  # False: ``emu`` fails
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
        if command == "emu avd name":
            if not self.console.get(serial, True) or not self.avd.get(serial):
                return "", "error: could not connect to TCP port"
            return self.avd[serial] + "\r\nOK\r\n", ""
        if command == "shell getprop ro.boot.qemu.avd_name":
            return self.avd.get(serial, "") + "\n", ""
        return "", ""

    def touched(self) -> set[str]:
        """Serials any adb / console command was sent to."""
        return {serial for _command, serial in self.calls if serial}

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
        "locked": set(),  # AVDs whose directory holds a live emulator lock
        "kill_exits": True,  # ``emu kill`` also ends our fake process
        "cmdlines": {},  # serial -> command line of a running emulator
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
    monkeypatch.setattr(emu, "_running_cmdline", lambda s: state["cmdlines"].get(s))
    monkeypatch.setattr(emu, "_ports_free", lambda p: p not in state["busy"])
    monkeypatch.setattr(emu.time, "sleep", lambda s: None)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(emu, "_LAUNCHES", {})
    monkeypatch.setattr(emu, "_RESERVED_PORTS", set())
    monkeypatch.setattr(emu, "_STARTING_AVDS", set())
    monkeypatch.setattr(emu, "_UNFINISHED", [])
    monkeypatch.setattr(emu, "_HOOKS", {"pre_launch": [], "post_stop": []})
    monkeypatch.setattr(
        emu,
        "avd_lock_files",
        lambda name: [Path(f"/avd/{name}.avd/hardware-qemu.ini.lock")]
        if name in state["locked"]
        else [],
    )
    # No pin unless a test sets one (the lab running the suite may export
    # ANDROID_SERIAL).
    from sandroid.core.device_manager import DeviceManager

    monkeypatch.delenv("ANDROID_SERIAL", raising=False)
    monkeypatch.setattr(DeviceManager, "_preferred_serial", None)
    monkeypatch.setattr(emu, "_config_emulator", lambda: None)
    state["adb"] = adb
    original_telnet = adb.send_telnet_command

    def telnet(command, serial=None):
        result = original_telnet(command, serial=serial)
        killed = result == ("OK", "") and adb.kill_removes
        if command == "kill" and killed and state["kill_exits"]:
            for cmd, proc in zip(state["spawned"], state["procs"], strict=True):
                if f"emulator-{_port_of(cmd)}" == serial and proc.exit_code is None:
                    proc._exit(0)
        return result

    adb.send_telnet_command = telnet
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
            "-no-snapshot-save",
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


def test_pinned_port_taken_during_startup_fails_without_fallback(env, monkeypatch):
    """A grabbed pinned port must not fall back to another session's port."""
    monkeypatch.setenv("ANDROID_SERIAL", "emulator-5562")
    env["on_spawn"] = lambda command: env["busy"].add(_port_of(command))
    env["startup"] = [(False, "ERROR: port in use")]
    with pytest.raises(EmulatorLaunchError) as info:
        emu.launch_avd("Pixel")
    assert "Console port 5562 (pinned) is taken" in str(info.value)
    assert "unpin" in str(info.value)
    assert [_port_of(c) for c in env["spawned"]] == [5562]
    assert emu.remembered_port("Pixel") is None
    assert not emu._RESERVED_PORTS


def test_remembered_port_taken_during_startup_fails_without_fallback(env):
    emu._remember_port("Pixel", 5570)
    env["on_spawn"] = lambda command: env["busy"].add(_port_of(command))
    env["startup"] = [(False, "ERROR: port in use")]
    with pytest.raises(EmulatorLaunchError, match=r"5570 \(last used\) is taken"):
        emu.launch_avd("Pixel")
    assert [_port_of(c) for c in env["spawned"]] == [5570]
    assert emu.remembered_port("Pixel") == 5570
    assert not emu._RESERVED_PORTS


def test_pinned_port_crash_with_port_still_free_reports_the_crash(env, monkeypatch):
    monkeypatch.setenv("ANDROID_SERIAL", "emulator-5562")
    env["startup"] = [(False, "PANIC: Missing AVD")]
    with pytest.raises(EmulatorLaunchError, match="crashed during startup"):
        emu.launch_avd("Pixel")
    assert len(env["spawned"]) == 1


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


def test_stop_emulator_escalates_on_our_pid_when_emu_kill_is_ignored(env):
    """``emu kill`` answered OK but qemu kept running: our own launch gets
    SIGTERM (then SIGKILL) on the PID Sandroid started, and the stop works.
    """
    launch = emu.launch_avd("Pixel")
    env["adb"].add(launch.serial, avd="Pixel")
    env["adb"].kill_removes = False  # console says OK, the emulator stays
    assert emu.stop_emulator(launch.serial, timeout=0) is True
    assert launch.process.signals == ["TERM"]
    assert launch.serial not in env["adb"].devices
    assert emu.get_launch(launch.serial) is None


def test_stop_emulator_escalates_to_kill_when_our_pid_ignores_term(env):
    launch = emu.launch_avd("Pixel")
    env["adb"].add(launch.serial, avd="Pixel")
    env["adb"].kill_removes = False
    launch.process.terminate = lambda: launch.process.signals.append("TERM")
    assert emu.stop_emulator(launch.serial, timeout=0) is True
    assert launch.process.signals == ["TERM", "KILL"]


def test_stop_emulator_does_not_kill_by_pid_an_emulator_it_did_not_start(env):
    """A ready emulator Sandroid did not launch ignores ``emu kill``: the
    stop reports failure and nothing is signalled or spawned.
    """
    env["adb"].add("emulator-5556", avd="ByHand")
    env["adb"].kill_removes = False
    assert emu.stop_emulator("emulator-5556", timeout=0) is False
    assert env["procs"] == []
    assert "emulator-5556" in env["adb"].devices


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
    launch = emu.restart_emulator(
        "emulator-5558", AvdLaunchOptions(wipe_once=True, save_on_exit=True)
    )
    assert launch.avd == "Other"
    assert launch.options == AvdLaunchOptions(save_on_exit=True)
    command = env["spawned"][-1]
    assert command[:5] == ["/sdk/emulator", "-avd", "Other", "-port", "5558"]
    assert "-wipe-data" not in command
    names = [c[0] for c in adb.calls]
    assert names.index("emu avd name") < names.index("telnet kill")


def test_restart_without_launch_record_uses_remembered_options(env):
    env["adb"].add("emulator-5558", avd="Other")
    emu.remember_launch(
        "Other", AvdLaunchOptions(headless=True, boot="snapshot", snapshot="clean")
    )
    emu.restart_emulator("emulator-5558")
    command = env["spawned"][-1]
    assert command[-3:] == ["-snapshot", "clean", "-no-snapshot-save"]
    assert "-no-window" in command


_QEMU = "/sdk/emulator/qemu/darwin-aarch64/qemu-system-aarch64"


def test_restart_of_a_foreign_emulator_uses_its_command_line(env):
    env["adb"].add("emulator-5554", avd="Demo")
    emu.remember_launch("Demo", AvdLaunchOptions(headless=True, boot="cold"))
    env["cmdlines"]["emulator-5554"] = [
        _QEMU,
        "-avd",
        "Demo",
        "-port",
        "5554",
        "-feature",
        "-Vulkan",
        "-gpu",
        "host",
        "-no-boot-anim",
        "-no-snapshot-save",
        "-snapshot",
        "clean_8g",
    ]
    launch = emu.restart_emulator("emulator-5554")
    assert launch.options == AvdLaunchOptions(
        boot="snapshot",
        snapshot="clean_8g",
        save_on_exit=False,
        extra_args=("-no-boot-anim",),
    )
    command = env["spawned"][-1]
    assert command[:5] == ["/sdk/emulator", "-avd", "Demo", "-port", "5554"]
    assert "-no-window" not in command  # not the remembered headless/cold
    assert "-no-snapshot-load" not in command
    assert command.count("-gpu") == 1
    assert command.count("-feature") == 1
    # The remembered options of the AVD are left as they were.
    assert emu.remembered_options("Demo") == AvdLaunchOptions(
        headless=True, boot="cold"
    )


def test_restart_falls_back_to_remembered_options_without_a_command_line(env):
    env["adb"].add("emulator-5558", avd="Other")
    env["cmdlines"]["emulator-5558"] = [_QEMU, "-avd", "Someone-else"]
    emu.remember_launch("Other", AvdLaunchOptions(boot="cold"))
    launch = emu.restart_emulator("emulator-5558")
    assert launch.options == AvdLaunchOptions(boot="cold")


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ([], AvdLaunchOptions(save_on_exit=True)),
        (
            ["-no-window", "-no-boot-anim", "-gpu", "swiftshader_indirect"],
            AvdLaunchOptions(headless=True, save_on_exit=True),
        ),
        (["-no-snapshot"], AvdLaunchOptions(boot="cold", save_on_exit=False)),
        (
            ["-no-snapshot-load", "-snapshot", "x"],
            AvdLaunchOptions(boot="cold", save_on_exit=True),
        ),
        (
            ["-wipe-data", "-memory", "4096", "-feature", "-Vulkan,Foo"],
            AvdLaunchOptions(
                save_on_exit=True, extra_args=("-memory", "4096", "-feature", "Foo")
            ),
        ),
    ],
)
def test_options_from_cmdline_maps_back_what_build_writes(args, expected):
    cmdline = [_QEMU, "-avd", "Pixel", "-port", "5560", *args]
    assert emu.options_from_cmdline(cmdline, "Pixel") == expected


def test_options_from_cmdline_reads_at_name_and_rejects_other_avds():
    assert emu.options_from_cmdline([_QEMU, "@Pixel"], "Pixel") is not None
    assert emu.options_from_cmdline([_QEMU, "-avd", "Other"], "Pixel") is None
    assert emu.options_from_cmdline([_QEMU], "Pixel") is None


def test_options_from_cmdline_strips_our_earlier_hook_args():
    cmdline = [_QEMU, "-avd", "Pixel", "-no-snapshot-save", "-sysdir", "/p/sim"]
    opts = emu.options_from_cmdline(cmdline, "Pixel", ("-sysdir", "/p/sim"))
    assert opts.extra_args == ()
    # Someone else's own -sysdir is kept.
    opts = emu.options_from_cmdline(cmdline, "Pixel", ("-sysdir", "/p/other"))
    assert opts.extra_args == ("-sysdir", "/p/sim")


def test_a_launch_remembers_its_hook_args_for_a_later_restart(env):
    emu.register_pre_launch_hook(lambda ctx: ("-sysdir", "/p/sim"))
    emu.launch_avd("Pixel", port=5560)
    assert emu.load_launch_prefs()["avds"]["Pixel"]["hook_args"] == [
        "-sysdir",
        "/p/sim",
    ]
    emu.remember_launch("Pixel", AvdLaunchOptions(headless=True))
    assert emu.load_launch_prefs()["avds"]["Pixel"]["hook_args"] == [
        "-sysdir",
        "/p/sim",
    ]


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
    env["locked"].add("Pixel")
    assert emu.ensure_avd_running("Pixel") == "emulator-5570"
    assert env["spawned"] == []


def test_ensure_avd_running_not_running_launches_without_probing_anyone(env):
    """No lock in its directory: the AVD does not run, so no other
    session's emulator is asked anything (only ``adb devices``).
    """
    adb = env["adb"]
    adb.add("emulator-5554", avd="Other")
    adb.add("emulator-5556", avd="Third")
    adb.add("emulator-5570", avd="Pixel", state="offline")
    env["on_spawn"] = lambda command: adb.add(
        f"emulator-{_port_of(command)}", avd="Pixel"
    )
    serial = emu.ensure_avd_running("Pixel")
    assert serial == "emulator-5558"
    assert adb.touched() == {"emulator-5558"}


def test_ensure_avd_running_asks_only_the_pinned_serial(env, monkeypatch):
    adb = env["adb"]
    adb.add("emulator-5554", avd="Other")
    adb.add("emulator-5562", avd="Pixel")
    env["locked"].add("Pixel")
    monkeypatch.setenv("ANDROID_SERIAL", "emulator-5562")
    assert emu.ensure_avd_running("Pixel") == "emulator-5562"
    assert adb.touched() == {"emulator-5562"}
    assert env["spawned"] == []


def test_ensure_avd_running_asks_the_remembered_port_after_the_pin(env, monkeypatch):
    adb = env["adb"]
    adb.add("emulator-5554", avd="Other")
    adb.add("emulator-5562", avd="Mine")  # pinned, but runs another AVD
    adb.add("emulator-5570", avd="Pixel")
    env["locked"].add("Pixel")
    emu._remember_port("Pixel", 5570)
    monkeypatch.setenv("ANDROID_SERIAL", "emulator-5562")
    assert emu.ensure_avd_running("Pixel") == "emulator-5570"
    asked = [s for c, s in adb.calls if c == "emu avd name"]
    assert asked == ["emulator-5562", "emulator-5570"]
    assert "emulator-5554" not in adb.touched()


def test_ensure_avd_running_uses_our_launch_without_any_probe(env):
    adb = env["adb"]
    adb.add("emulator-5554", avd="Other")
    env["on_spawn"] = lambda command: adb.add(
        f"emulator-{_port_of(command)}", avd="Pixel"
    )
    launch = emu.launch_avd("Pixel")
    adb.calls.clear()
    assert emu.ensure_avd_running("Pixel") == launch.serial
    assert not any(c == "emu avd name" for c, _s in adb.calls)
    assert "emulator-5554" not in adb.touched()


def test_ensure_avd_running_probes_the_rest_only_as_a_last_resort(env, caplog):
    adb = env["adb"]
    adb.add("emulator-5554", avd="Other")
    adb.add("emulator-5570", avd="Pixel")
    adb.add("emulator-5572", avd="Gone", state="offline")
    env["locked"].add("Pixel")
    with caplog.at_level("INFO", logger=emu.logger.name):
        assert emu.ensure_avd_running("Pixel") == "emulator-5570"
    assert "emulator-5554, emulator-5570" in caplog.text
    assert "emulator-5572" not in adb.touched()  # offline: not asked


def test_ensure_avd_running_locked_but_not_found_raises(env):
    env["adb"].add("emulator-5554", avd="Other")
    env["locked"].add("Pixel")
    with pytest.raises(EmulatorLaunchError, match="already running"):
        emu.ensure_avd_running("Pixel")
    assert env["spawned"] == []


# -- AVD name: the console first ---------------------------------------------


def test_avd_name_asks_the_console_first(env):
    adb = env["adb"]
    adb.add("emulator-5570", avd="Pixel", booted=False)
    assert emu.avd_name_of("emulator-5570") == "Pixel"
    assert [c for c, _s in adb.calls] == ["emu avd name"]


def test_avd_name_falls_back_to_the_property_when_the_console_fails(env):
    adb = env["adb"]
    adb.add("emulator-5570", avd="Pixel")
    adb.console["emulator-5570"] = False
    assert emu.avd_name_of("emulator-5570") == "Pixel"
    assert [c for c, _s in adb.calls] == [
        "emu avd name",
        "shell getprop ro.boot.qemu.avd_name",
    ]
    assert adb.touched() == {"emulator-5570"}


# -- console port preference --------------------------------------------------


def test_launch_uses_the_pinned_port_over_first_free(env, monkeypatch):
    monkeypatch.setenv("ANDROID_SERIAL", "emulator-5562")
    launch = emu.launch_avd("Pixel")
    assert launch.serial == "emulator-5562"
    assert emu.remembered_port("Pixel") == 5562


def test_pinned_port_wins_over_the_remembered_port(env, monkeypatch):
    emu._remember_port("Pixel", 5570)
    monkeypatch.setattr(
        "sandroid.core.device_manager.DeviceManager._preferred_serial",
        "emulator-5562",
    )
    assert emu.preferred_console_port("Pixel", set()) == (5562, "pinned")
    assert emu.launch_avd("Pixel").port == 5562


def test_config_serial_counts_as_pin(env, monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(
        emu, "_config_emulator", lambda: SimpleNamespace(serial="emulator-5566")
    )
    assert emu.preferred_console_port("Pixel", set()) == (5566, "pinned")


def test_listed_pinned_port_falls_through_to_the_remembered_port(env, monkeypatch):
    env["adb"].add("emulator-5562", avd="Mine")  # the pin already runs
    emu._remember_port("Pixel", 5570)
    monkeypatch.setenv("ANDROID_SERIAL", "emulator-5562")
    launch = emu.launch_avd("Pixel")
    assert launch.port == 5570
    assert emu.preferred_console_port("Pixel", {5562}) == (5570, "last used")


def test_busy_pinned_and_remembered_ports_fall_through_to_auto(env, monkeypatch):
    env["busy"].update({5562, 5570})  # bound by something adb does not list
    emu._remember_port("Pixel", 5570)
    monkeypatch.setenv("ANDROID_SERIAL", "emulator-5562")
    assert emu.preferred_console_port("Pixel", set()) == (5554, "auto")
    assert emu.launch_avd("Pixel").port == 5554


def test_remembered_port_is_used_without_a_pin(env):
    emu._remember_port("Pixel", 5570)
    assert emu.launch_avd("Pixel").port == 5570


def test_unusable_pins_are_ignored(env):
    for pinned in ("R58N123ABC", "emulator-5590", "emulator-5563"):
        assert emu.preferred_console_port("P", set(), pinned=pinned) == (
            5554,
            "auto",
        )


def test_every_launch_remembers_its_port_and_keeps_the_options(env):
    emu.remember_launch("Pixel", AvdLaunchOptions(headless=True, boot="cold"))
    emu.launch_avd("Pixel", port=5576)
    assert emu.remembered_port("Pixel") == 5576
    assert emu.remembered_options("Pixel") == AvdLaunchOptions(
        headless=True, boot="cold"
    )
    # Changing an option keeps the port.
    emu.remember_launch("Pixel", AvdLaunchOptions(), make_last=False)
    assert emu.remembered_port("Pixel") == 5576


def test_a_port_only_entry_keeps_first_launch_defaults(env, monkeypatch):
    from types import SimpleNamespace

    emu._remember_port("Pixel", 5570)
    monkeypatch.setattr(
        emu, "_config_emulator", lambda: SimpleNamespace(avd_headless=True)
    )
    assert emu.remembered_options("Pixel") == AvdLaunchOptions(headless=True)


def test_restart_keeps_its_port_even_with_a_pin(env, monkeypatch):
    env["adb"].add("emulator-5558", avd="Other")
    monkeypatch.setenv("ANDROID_SERIAL", "emulator-5562")
    assert emu.restart_emulator("emulator-5558").port == 5558


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


# -- launch hooks ---------------------------------------------------------------


def _recorders(events):
    """A (pre-launch, post-stop) hook pair appending to *events*."""

    def pre(ctx):
        events.append(("pre", ctx.port, ctx))
        return ()

    def post(ctx):
        events.append(("post", ctx.port, ctx))

    emu.register_pre_launch_hook(pre)
    emu.register_post_stop_hook(post)
    return pre, post


def _kinds(events):
    return [(kind, port) for kind, port, _ctx in events]


def test_hook_registration_is_ordered_idempotent_and_removable(env):
    class Owner:
        def hook(self, ctx):
            return ()

    owner = Owner()

    def a(ctx):
        return ()

    emu.register_pre_launch_hook(a)
    emu.register_pre_launch_hook(owner.hook)
    emu.register_pre_launch_hook(a)
    emu.register_pre_launch_hook(owner.hook)  # a new but equal bound method
    assert emu._hook_snapshot("pre_launch") == [a, owner.hook]
    emu.unregister_pre_launch_hook(a)
    emu.unregister_pre_launch_hook(a)  # not registered: no-op
    assert emu._hook_snapshot("pre_launch") == [owner.hook]
    emu.register_post_stop_hook(a)
    emu.unregister_post_stop_hook(owner.hook)  # never a post-stop hook
    assert emu._hook_snapshot("post_stop") == [a]
    with pytest.raises(TypeError):
        emu.register_post_stop_hook("not callable")


def test_pre_launch_args_follow_extra_args_and_never_become_options(env):
    import json

    emu.register_pre_launch_hook(lambda ctx: ("-hook-one",))
    emu.register_pre_launch_hook(lambda ctx: ["-hook-two", "value"])
    env["on_spawn"] = lambda cmd: env["adb"].add(
        f"emulator-{_port_of(cmd)}", avd="Pixel"
    )
    opts = AvdLaunchOptions(extra_args=("-extra",))
    serial = emu.ensure_avd_running("Pixel", options=opts)
    command = env["spawned"][0]
    assert command[-4:] == ["-extra", "-hook-one", "-hook-two", "value"]
    launch = emu.get_launch(serial)
    assert launch.options == opts
    assert launch.hook_args == ("-hook-one", "-hook-two", "value")
    # Hook args never become options; they are only kept to strip them from
    # this emulator's command line on a later restart (running_options).
    assert emu.remembered_options("Pixel").extra_args == ()
    entry = emu.load_launch_prefs()["avds"]["Pixel"]
    assert entry["hook_args"] == ["-hook-one", "-hook-two", "value"]
    entry.pop("hook_args")
    text = json.dumps(entry)
    assert "-hook" not in text
    assert "-extra" not in text  # extra_args are not remembered either


def test_pre_launch_hook_sees_the_real_port_and_redirected_avd_dir(
    env, tmp_path, monkeypatch
):
    home = tmp_path / "avdhome"
    home.mkdir()
    elsewhere = tmp_path / "disk" / "Pixel.avd"
    elsewhere.mkdir(parents=True)
    (home / "Pixel.ini").write_text(f"path={elsewhere}\n")
    monkeypatch.setenv("ANDROID_AVD_HOME", str(home))
    emu._remember_port("Pixel", 5570)
    events = []
    _recorders(events)
    opts = AvdLaunchOptions(headless=True)
    launch = emu.launch_avd("Pixel", opts)
    [(kind, port, ctx)] = events
    assert (kind, port) == ("pre", 5570)
    assert ctx == emu.LaunchContext("Pixel", elsewhere, 5570, opts)
    assert launch.context is ctx
    assert _port_of(env["spawned"][0]) == 5570


def test_failing_pre_launch_hook_fails_closed(env):
    events = []
    _recorders(events)

    def broken_patch(ctx):
        raise ValueError("disk full")

    emu.register_pre_launch_hook(broken_patch)
    with pytest.raises(EmulatorLaunchError) as info:
        emu.launch_avd("Pixel")
    assert "broken_patch" in str(info.value)
    assert "ValueError: disk full" in str(info.value)
    assert env["spawned"] == []
    assert not emu._RESERVED_PORTS
    assert not emu._STARTING_AVDS
    assert emu.launches() == []
    # The hook that ran (and the failing one's partial patch) is restored.
    assert _kinds(events) == [("pre", 5554), ("post", 5554)]
    assert events[0][2] is events[1][2]
    emu.unregister_pre_launch_hook(broken_patch)
    assert emu.launch_avd("Pixel").port == 5554  # the port was released


def test_pre_launch_hook_returning_a_string_fails_closed(env):
    emu.register_pre_launch_hook(lambda ctx: "-oops")
    with pytest.raises(EmulatorLaunchError, match="tuple of str"):
        emu.launch_avd("Pixel")
    assert env["spawned"] == []


def test_spawn_failure_restores_what_pre_launch_patched(env, monkeypatch):
    events = []
    _recorders(events)

    def no_binary(command, avd_name, env=None):
        raise FileNotFoundError("emulator vanished")

    monkeypatch.setattr(emu, "spawn_emulator", no_binary)
    with pytest.raises(EmulatorLaunchError, match="Could not start"):
        emu.launch_avd("Pixel")
    assert _kinds(events) == [("pre", 5554), ("post", 5554)]
    assert not emu._RESERVED_PORTS


def test_post_stop_runs_once_after_stop_with_the_launch_context(env):
    events = []
    _recorders(events)
    launch = emu.launch_avd("Pixel")
    env["adb"].add(launch.serial, avd="Pixel")
    assert emu.stop_emulator(launch.serial) is True
    assert _kinds(events) == [("pre", 5554), ("post", 5554)]
    assert events[1][2] is launch.context
    assert emu.stop_emulator(launch.serial) is True  # already gone
    assert emu.reap_exited_launches() == []
    assert len(events) == 2


def test_post_stop_waits_until_a_stopped_emulator_has_exited(env):
    """It left adb but still runs (saving its state): post-stop is due
    once it exited, noticed by the next reap.
    """
    events = []
    _recorders(events)
    env["kill_exits"] = False
    launch = emu.launch_avd("Pixel")
    env["adb"].add(launch.serial, avd="Pixel")
    assert emu.stop_emulator(launch.serial) is True
    assert _kinds(events) == [("pre", 5554)]
    assert [x is launch for x in emu._UNFINISHED] == [True]
    launch.process.exit_code = 0
    assert emu.reap_exited_launches() == [launch]
    assert _kinds(events) == [("pre", 5554), ("post", 5554)]
    assert emu._UNFINISHED == []
    emu.reap_exited_launches()
    assert len(events) == 2


def test_restart_runs_post_stop_before_the_next_pre_launch(env):
    events = []
    _recorders(events)
    first = emu.launch_avd("Pixel", port=5560)
    env["adb"].add(first.serial, avd="Pixel")
    second = emu.restart_emulator(first.serial)
    assert _kinds(events) == [("pre", 5560), ("post", 5560), ("pre", 5560)]
    assert events[1][2] is first.context
    assert events[2][2] is second.context is not first.context


def test_restart_waits_for_the_old_process_before_pre_launch(env, monkeypatch):
    events = []
    _recorders(events)
    env["kill_exits"] = False
    first = emu.launch_avd("Pixel", port=5560)
    env["adb"].add(first.serial, avd="Pixel")
    # It leaves adb on ``emu kill`` but exits only during the port wait.
    monkeypatch.setattr(emu.time, "sleep", lambda s: first.process._exit(0))
    emu.restart_emulator(first.serial)
    assert _kinds(events) == [("pre", 5560), ("post", 5560), ("pre", 5560)]


def test_post_stop_runs_once_when_our_emulator_dies_on_its_own(env):
    events = []
    _recorders(events)
    launch = emu.launch_avd("Pixel")
    launch.process.exit_code = 1
    assert emu.wait_until_ready(launch.serial, timeout=10_000) is False
    assert _kinds(events) == [("pre", 5554), ("post", 5554)]
    assert emu.wait_until_ready(launch.serial, timeout=10_000) is False
    assert emu.stop_emulator(launch.serial) is True
    emu.reap_exited_launches()
    assert len(events) == 2


def test_next_launch_reaps_a_death_nobody_noticed(env):
    events = []
    _recorders(events)
    first = emu.launch_avd("Pixel")
    first.process.exit_code = 1  # died; no boot waiter saw it
    emu.launch_avd("Pixel")
    assert _kinds(events) == [("pre", 5554), ("post", 5554), ("pre", 5554)]


def test_startup_crash_runs_post_stop_before_the_retry(env):
    events = []
    _recorders(events)
    env["on_spawn"] = lambda command: env["busy"].add(_port_of(command))
    env["startup"] = [(False, "ERROR: port in use"), (True, "")]
    launch = emu.launch_avd("Pixel")
    assert _kinds(events) == [("pre", 5554), ("post", 5554), ("pre", 5556)]
    assert launch.context.port == 5556


def test_post_stop_exceptions_are_logged_and_swallowed(env, caplog):
    events = []

    def failing_restore(ctx):
        raise OSError("read-only")

    emu.register_post_stop_hook(failing_restore)
    _recorders(events)
    first = emu.launch_avd("Pixel", port=5560)
    env["adb"].add(first.serial, avd="Pixel")
    with caplog.at_level("WARNING", logger=emu.__name__):
        assert emu.stop_emulator(first.serial) is True
    assert _kinds(events) == [("pre", 5560), ("post", 5560)]
    assert "failing_restore" in caplog.text
    second = emu.launch_avd("Pixel", port=5560)
    env["adb"].add(second.serial, avd="Pixel")
    assert emu.restart_emulator(second.serial).serial == "emulator-5560"


def test_reusing_a_running_avd_runs_no_pre_launch_hook(env):
    events = []
    _recorders(events)
    env["adb"].add("emulator-5570", avd="Pixel")
    env["locked"].add("Pixel")
    assert emu.ensure_avd_running("Pixel") == "emulator-5570"
    assert events == []


def test_stopping_a_foreign_emulator_runs_no_post_stop_hook(env):
    events = []
    _recorders(events)
    env["adb"].add("emulator-5556", avd="Other")
    assert emu.stop_emulator("emulator-5556") is True
    assert events == []


# -- launch hooks: concurrency (real threads) -----------------------------------


def _slow_post_stop(events):
    """A post-stop hook that blocks until ``release`` is set."""
    started, release = threading.Event(), threading.Event()

    def slow_restore(ctx):
        events.append(("post-start", ctx.avd, threading.current_thread().name))
        started.set()
        assert release.wait(10), "test never released the post-stop hook"
        events.append(("post-end", ctx.avd, threading.current_thread().name))

    def pre(ctx):
        events.append(("pre", ctx.avd, threading.current_thread().name))
        return ()

    emu.register_pre_launch_hook(pre)
    emu.register_post_stop_hook(slow_restore)
    return started, release


def _thread(target, name):
    """Run *target* on a real thread; its result/exception lands in a dict."""
    out: dict = {}

    def run():
        try:
            out["value"] = target()
        except BaseException as e:  # handed to the test
            out["error"] = e

    thread = threading.Thread(target=run, name=name, daemon=True)
    thread.start()
    return thread, out


def test_launch_waits_for_a_post_stop_another_thread_is_running(env):
    """A poll's reap is still restoring the dead launch: the next launch's
    pre-launch hooks wait until that restore has finished.
    """
    events = []
    started, release = _slow_post_stop(events)
    first = emu.launch_avd("Pixel")
    first.process.exit_code = 1  # died on its own
    reaper, _ = _thread(emu.reap_exited_launches, "reaper")
    assert started.wait(5)
    launcher, out = _thread(lambda: emu.launch_avd("Pixel"), "launcher")
    _real_sleep(0.2)
    assert [e[0] for e in events] == ["pre", "post-start"]
    assert not first.post_stop_done  # claimed, but not finished
    release.set()
    reaper.join(5)
    launcher.join(5)
    assert "error" not in out, out
    assert [(e[0], e[2]) for e in events] == [
        ("pre", "MainThread"),
        ("post-start", "reaper"),
        ("post-end", "reaper"),
        ("pre", "launcher"),
    ]
    assert first.post_stop_done
    assert out["value"].context is not first.context


def test_launch_fails_closed_when_the_other_post_stop_takes_too_long(env, monkeypatch):
    events = []
    started, release = _slow_post_stop(events)
    monkeypatch.setattr(emu, "POST_STOP_WAIT", 0.1)
    first = emu.launch_avd("Pixel")
    first.process.exit_code = 1
    reaper, _ = _thread(emu.reap_exited_launches, "reaper")
    assert started.wait(5)
    try:
        with pytest.raises(EmulatorLaunchError, match="still running after"):
            emu.launch_avd("Pixel")
        assert len(env["spawned"]) == 1  # no second process
        assert [e[0] for e in events] == ["pre", "post-start"]  # no 2nd pre
        assert not emu._STARTING_AVDS
        assert not emu._RESERVED_PORTS
    finally:
        release.set()
        reaper.join(5)
    assert emu.launch_avd("Pixel").port == 5554  # it works once restored


def test_a_stopping_launch_is_never_out_of_both_registries(env, monkeypatch):
    """Between leaving adb and settling, the stopping launch already blocks a
    new launch of its AVD (it was in neither registry before).
    """
    events = []
    _recorders(events)
    env["kill_exits"] = False
    first = emu.launch_avd("Pixel")
    env["adb"].add(first.serial, avd="Pixel")
    entered, release = threading.Event(), threading.Event()
    settle = emu._settle_stopped

    def held_settle(launch, wait):
        entered.set()
        assert release.wait(10)
        settle(launch, wait)

    monkeypatch.setattr(emu, "_settle_stopped", held_settle)
    stopper, out = _thread(lambda: emu.stop_emulator(first.serial), "stopper")
    assert entered.wait(5)
    try:
        assert emu.get_launch(first.serial) is None
        assert [x is first for x in emu._UNFINISHED] == [True]
        with pytest.raises(EmulatorLaunchError, match="still shutting down"):
            emu.launch_avd("Pixel")
    finally:
        release.set()
        stopper.join(5)
    assert out == {"value": True}
    assert len(env["spawned"]) == 1
    assert _kinds(events) == [("pre", 5554)]


def test_still_exiting_avd_is_refused_then_restored_before_relaunch(env):
    events = []
    _recorders(events)
    env["kill_exits"] = False  # it keeps saving its state after leaving adb
    first = emu.launch_avd("Pixel", AvdLaunchOptions(save_on_exit=True))
    env["adb"].add(first.serial, avd="Pixel")
    assert emu.stop_emulator(first.serial, timeout=0) is True
    with pytest.raises(EmulatorLaunchError, match="still shutting down"):
        emu.launch_avd("Pixel")
    first.process._exit(0)
    second = emu.launch_avd("Pixel")
    assert _kinds(events) == [("pre", 5554), ("post", 5554), ("pre", 5554)]
    assert events[1][2] is first.context
    assert events[2][2] is second.context
    assert emu._UNFINISHED == []


def test_dead_record_on_the_same_port_is_finished_before_pre_launch(env):
    """Another AVD's dead launch on the port: its post-stop (running on a
    reaper thread) finishes before the new launch on that port patches.
    """
    events = []
    started, release = _slow_post_stop(events)
    other = emu.launch_avd("Other", port=5554)
    other.process.exit_code = 1
    reaper, _ = _thread(emu.reap_exited_launches, "reaper")
    assert started.wait(5)
    launcher, out = _thread(lambda: emu.launch_avd("Pixel", port=5554), "launcher")
    _real_sleep(0.2)
    assert [e[0] for e in events] == ["pre", "post-start"]
    release.set()
    reaper.join(5)
    launcher.join(5)
    assert "error" not in out, out
    assert [e[:2] for e in events] == [
        ("pre", "Other"),
        ("post-start", "Other"),
        ("post-end", "Other"),
        ("pre", "Pixel"),
    ]
    assert emu.get_launch("emulator-5554") is out["value"]
    assert other not in emu._UNFINISHED


def test_a_live_record_on_the_same_serial_refuses_the_spawn(env):
    events = []
    _recorders(events)
    first = emu.launch_avd("Other", port=5554)
    with pytest.raises(EmulatorLaunchError, match="still used by our launch"):
        emu._spawn_launch(Path("/sdk/emulator"), "Pixel", 5554, AvdLaunchOptions())
    assert emu.get_launch("emulator-5554") is first
    assert _kinds(events) == [("pre", 5554)]  # no pre-launch for Pixel


def test_any_failure_after_pre_launch_restores_and_releases_the_port(env, monkeypatch):
    events = []
    _recorders(events)

    def broken_spawn(command, avd_name, env=None):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(emu, "spawn_emulator", broken_spawn)
    with pytest.raises(RuntimeError, match="unexpected"):
        emu.launch_avd("Pixel")
    assert _kinds(events) == [("pre", 5554), ("post", 5554)]
    assert not emu._RESERVED_PORTS
    assert not emu._STARTING_AVDS
    assert emu.launches() == []


def test_post_stop_never_runs_before_exit_even_if_registered_late(env):
    """Stopped with no post-stop hooks registered while it still exits: a
    hook registered meanwhile runs once it has exited, never before.
    """
    env["kill_exits"] = False
    launch = emu.launch_avd("Pixel")
    env["adb"].add(launch.serial, avd="Pixel")
    assert emu.stop_emulator(launch.serial) is True
    assert not launch.post_stop_done
    events = []
    emu.register_post_stop_hook(lambda ctx: events.append(ctx))
    assert emu.reap_exited_launches() == []
    assert events == []
    launch.process._exit(0)
    assert emu.reap_exited_launches() == [launch]
    assert events == [launch.context]
    assert launch.post_stop_done


def test_restart_waits_longer_for_a_saving_emulator_and_says_why(env, monkeypatch):
    env["kill_exits"] = False
    monkeypatch.setattr(emu, "RESTART_EXIT_WAIT", 1_000.0)
    monkeypatch.setattr(emu, "RESTART_EXIT_WAIT_SAVING", 0.0)
    first = emu.launch_avd("Pixel", AvdLaunchOptions(save_on_exit=True), port=5560)
    env["adb"].add(first.serial, avd="Pixel")
    with pytest.raises(EmulatorLaunchError) as info:
        emu.restart_emulator(first.serial)
    message = str(info.value)
    assert "has not exited after 0s" in message
    assert "saving its snapshot" in message
    assert "once it has exited" in message
    assert len(env["spawned"]) == 1


def test_restart_exit_timeout_is_configurable(env):
    env["kill_exits"] = False
    first = emu.launch_avd("Pixel", port=5560)
    env["adb"].add(first.serial, avd="Pixel")
    with pytest.raises(EmulatorLaunchError, match="has not exited after 0s"):
        emu.restart_emulator(first.serial, exit_timeout=0)


def test_device_poll_worker_reaps_a_death_off_the_ui_thread(env, monkeypatch):
    """The TUI's device poll worker runs the post-stop hooks of a launch
    that died after it was ready (nobody waits for its boot any more).
    """
    from types import SimpleNamespace

    from sandroid.core.toolbox import Toolbox
    from sandroid.tui.app import SandroidTUI

    events = []
    emu.register_post_stop_hook(
        lambda ctx: events.append((ctx.avd, threading.current_thread().name))
    )
    launch = emu.launch_avd("Pixel")
    emu.mark_ready(launch.serial)
    launch.process.exit_code = 1  # crashed long after its boot
    refreshed = []
    monkeypatch.setattr(
        Toolbox,
        "get_device_manager",
        classmethod(
            lambda cls: SimpleNamespace(refresh_devices=lambda: refreshed.append(1))
        ),
    )
    app = SimpleNamespace(_device_poll_in_flight=True, _device_poll_pending=False)
    worker, out = _thread(
        lambda: SandroidTUI._refresh_devices_bg(app), "device_state_poll"
    )
    worker.join(5)
    assert "error" not in out, out
    assert events == [("Pixel", "device_state_poll")]
    assert refreshed == [1]
    assert app._device_poll_in_flight is False
    assert launch.post_stop_done


def test_exit_reap_finishes_dead_launches_and_leaves_running_ones(env):
    events = []
    _recorders(events)
    dead = emu.launch_avd("Dead", port=5554)
    running = emu.launch_avd("Running", port=5556)
    dead.process.exit_code = 0
    emu._reap_at_exit()
    assert [(e[0], e[2].avd) for e in events[2:]] == [("post", "Dead")]
    assert running.alive
    assert running.process.signals == []
    assert not running.post_stop_done


# -- launch record ------------------------------------------------------------


def test_each_launch_has_its_own_record(env):
    def hook(ctx):
        ctx.record["identity_sim"] = {"profile": "p1"}
        return ()

    emu.register_pre_launch_hook(hook)
    first = emu.launch_avd(
        "Pixel", AvdLaunchOptions(boot="cold"), port=5560, meta={"persona_id": "x"}
    )
    record = emu.launch_record("emulator-5560")
    assert record["launch_id"] == first.launch_id
    assert (record["avd"], record["serial"], record["port"]) == (
        "Pixel",
        "emulator-5560",
        5560,
    )
    assert record["options"]["boot"] == "cold"
    assert record["meta"] == {"persona_id": "x"}
    assert record["hooks"] == {"identity_sim": {"profile": "p1"}}
    assert record["command"][:3] == ["/sdk/emulator", "-avd", "Pixel"]
    assert record["boot_id"] is None
    emu.note_boot("emulator-5560", "boot-1", 12.5)
    emu.note_boot("emulator-5560", "boot-2", 99.0)  # first wins
    record = emu.launch_record("emulator-5560")
    assert (record["boot_id"], record["first_uptime"]) == ("boot-1", 12.5)
    assert emu.launch_record("emulator-5562") is None


def test_a_restart_is_a_new_launch_with_the_same_meta(env):
    first = emu.launch_avd("Pixel", port=5560, meta={"persona_id": "x"})
    env["adb"].add(first.serial, avd="Pixel")
    second = emu.restart_emulator(first.serial)
    assert second.launch_id != first.launch_id
    assert second.meta == {"persona_id": "x"}
    assert emu.launch_record(second.serial)["boot_id"] is None


def test_pre_launch_hooks_see_the_meta_read_only_also_on_a_restart(env):
    seen = []

    def hook(ctx):
        seen.append(json.loads(json.dumps(dict(ctx.meta))))  # as the hook got it
        with pytest.raises(TypeError):
            ctx.meta["persona"] = "other"  # type: ignore[index]
        ctx.meta["profile"]["sim"] = "changed"  # a copy: the record keeps its own
        return ()

    emu.register_pre_launch_hook(hook)
    meta = {"persona": "p1", "profile": {"sim": "a"}}
    first = emu.launch_avd("Pixel", port=5560, meta=meta)
    assert seen[0]["persona"] == "p1"
    assert meta == {"persona": "p1", "profile": {"sim": "a"}}
    assert emu.launch_record(first.serial)["meta"]["profile"] == {"sim": "a"}
    env["adb"].add(first.serial, avd="Pixel")
    emu.restart_emulator(first.serial)
    assert seen[1]["persona"] == "p1"
    assert seen[1]["profile"] == {"sim": "a"}
    assert dict(emu._launch_context("Pixel", 5562, AvdLaunchOptions()).meta) == {}


def test_a_restart_without_our_launch_asks_the_meta_providers(env, monkeypatch):
    calls = []

    def provider(serial, avd):
        calls.append((serial, avd, serial in env["adb"].devices))
        return {"persona_id": "p7", "extra": {"n": 1}}

    def broken(serial, avd):
        raise RuntimeError("boom")

    monkeypatch.setattr(emu, "_RESTART_META", [])
    emu.register_restart_meta(broken)
    emu.register_restart_meta(provider)
    emu.register_restart_meta(provider)  # once
    env["adb"].add("emulator-5560", avd="Pixel")  # not launched by us
    monkeypatch.setattr(emu, "running_options", lambda serial, avd: None)
    launch = emu.restart_emulator("emulator-5560")
    assert calls == [("emulator-5560", "Pixel", True)]  # asked before the kill
    assert launch.meta == {"persona_id": "p7", "extra": {"n": 1}}
    assert emu.launch_record("emulator-5560")["meta"]["persona_id"] == "p7"


def test_a_restart_of_our_live_launch_keeps_its_meta_without_providers(
    env, monkeypatch
):
    monkeypatch.setattr(emu, "_RESTART_META", [])
    asked = []
    emu.register_restart_meta(lambda serial, avd: asked.append(serial) or {"x": 1})
    first = emu.launch_avd("Pixel", port=5560, meta={"persona_id": "mine"})
    env["adb"].add(first.serial, avd="Pixel")
    second = emu.restart_emulator(first.serial)
    assert asked == []
    assert second.meta == {"persona_id": "mine"}


def test_restart_meta_providers_only_add_missing_keys(monkeypatch):
    monkeypatch.setattr(emu, "_RESTART_META", [])
    emu.register_restart_meta(lambda s, a: {"persona_id": "other", "new": True})
    emu.register_restart_meta(lambda s, a: ["not", "a", "dict"])
    emu.register_restart_meta(lambda s, a: None)
    meta = emu._restart_meta("emulator-5560", "Pixel", {"persona_id": "kept"})
    assert meta == {"persona_id": "kept", "new": True}
    with pytest.raises(TypeError):
        emu.register_restart_meta("nope")  # type: ignore[arg-type]


def test_identity_installs_a_restart_meta_provider_for_personas(env, monkeypatch):
    """After a TUI restart (no live launch of ours), a restart of a persona
    emulator still starts the persona: identity's provider names it.
    """
    from sandroid.services import identity as ident
    from sandroid.services import identity_sim as sim

    monkeypatch.setattr(emu, "_RESTART_META", [])
    sim.install_launch_hooks()
    sim.install_launch_hooks()  # idempotent
    assert [sim.restart_meta] == emu._RESTART_META
    personas = {"emulator-5560": "persona-a"}
    service = ident.get_identity_service()
    monkeypatch.setattr(service, "persona_of", lambda s: personas.get(s, ""))
    monkeypatch.setattr(sim, "pre_launch", lambda ctx: ())
    monkeypatch.setattr(emu, "_HOOKS", {"pre_launch": [], "post_stop": []})
    monkeypatch.setattr(emu, "running_options", lambda serial, avd: None)
    env["adb"].add("emulator-5560", avd="Pixel")  # a persona emulator
    env["adb"].add("emulator-5562", avd="Pixel2")  # holds no persona
    persona = emu.restart_emulator("emulator-5560")
    plain = emu.restart_emulator("emulator-5562")
    assert persona.meta == {ident.PERSONA_META_KEY: "persona-a"}
    assert emu.launch_record("emulator-5560")["meta"] == {"persona_id": "persona-a"}
    assert plain.meta == {}
    sim.uninstall_launch_hooks()
    assert emu._RESTART_META == []


def test_a_launch_is_a_timeline_line_with_its_record(env):
    from sandroid.core import timeline

    with timeline.capture() as lines:
        launch = emu.launch_avd("Pixel", port=5560, meta={"persona_id": "x"})
    (line,) = [x for x in lines if (x["src"], x["kind"]) == ("emulator", "launch")]
    assert line["dev"] == "emulator-5560"
    assert line["data"]["launch_id"] == launch.launch_id
    assert "persona x" in line["summary"]
