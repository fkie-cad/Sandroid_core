"""Tests for the emulator launch flags and the host-memory guard."""

from __future__ import annotations

import logging

import pytest

from sandroid.core import emulator_guard as eg

GB = 1024**3


class FakeProc:
    def __init__(self, cmdline, rss, pid=4242):
        self._cmdline = cmdline
        self._rss = rss
        self.pid = pid
        self.killed = False
        self.running = True

    def cmdline(self):
        return self._cmdline

    def memory_info(self):
        return type("M", (), {"rss": self._rss})()

    def is_running(self):
        return self.running

    def kill(self):
        self.killed = True
        self.running = False


SAFE = [
    "qemu-system-aarch64",
    "-avd",
    "X",
    "-port",
    "5556",
    "-feature",
    "-Vulkan",
    "-gpu",
    "host",
]
UNSAFE = ["qemu-system-aarch64", "-avd", "X", "-port", "5556", "-no-boot-anim"]


def _guard(proc, monkeypatch, *, limit_gb=8, action="kill"):
    msgs: list[tuple[str, int]] = []
    adb_calls: list[list[str]] = []
    monkeypatch.setattr(eg, "find_emulator_process", lambda serial: proc)
    monkeypatch.setattr(eg.subprocess, "run", lambda argv, **kw: adb_calls.append(argv))
    monkeypatch.setattr(eg.time, "sleep", lambda s: None)
    g = eg.EmulatorMemoryGuard(
        lambda: "emulator-5556",
        limit_gb=limit_gb,
        action=action,
        adb_path_getter=lambda: "/x/adb",
        notify=lambda m, lvl: msgs.append((m, lvl)),
    )
    return g, msgs, adb_calls


def test_launch_args_disable_vulkan():
    assert eg.emulator_launch_args() == ["-feature", "-Vulkan", "-gpu", "host"]
    assert eg.emulator_launch_args(headless=True)[-1] == "swiftshader_indirect"
    assert eg.vulkan_disabled(eg.emulator_launch_args(headless=True))


@pytest.mark.parametrize(
    ("cmdline", "expected"),
    [
        (["-feature", "-Vulkan"], True),
        (["-feature", "GLDirectMem,-Vulkan"], True),
        (["-feature", "Vulkan"], False),
        (["-no-boot-anim"], False),
    ],
)
def test_vulkan_disabled(cmdline, expected):
    assert eg.vulkan_disabled(cmdline) is expected


def test_console_port():
    assert eg.console_port(["-avd", "A", "-port", "5558"]) == 5558
    # No -port: the emulator auto-assigns the port, it is NOT always 5554.
    assert eg.console_port(["-avd", "A"]) is None


def test_under_limit_safe_flags_is_silent(monkeypatch):
    g, msgs, adb = _guard(FakeProc(SAFE, 2 * GB), monkeypatch)
    assert g.check_once() is None
    assert msgs == []
    assert adb == []


def test_missing_vulkan_flag_warns_once(monkeypatch):
    g, msgs, _ = _guard(FakeProc(UNSAFE, 2 * GB), monkeypatch)
    g.check_once()
    g.check_once()
    warnings = [m for m, lvl in msgs if "-feature -Vulkan" in m]
    assert len(warnings) == 1


def test_near_limit_warns_once(monkeypatch):
    g, msgs, adb = _guard(FakeProc(SAFE, int(6.5 * GB)), monkeypatch)
    g.check_once()
    g.check_once()
    assert len([m for m, lvl in msgs if lvl == logging.WARNING]) == 1
    assert adb == []


def test_over_limit_kills_emulator(monkeypatch):
    proc = FakeProc(SAFE, 9 * GB)
    g, msgs, adb = _guard(proc, monkeypatch)
    assert g.check_once() == "killed"
    assert adb == [["/x/adb", "-s", "emulator-5556", "emu", "kill"]]
    assert proc.killed  # still running after emu kill -> hard kill
    assert any(lvl == logging.ERROR for _, lvl in msgs)


def test_over_limit_warn_action_does_not_kill(monkeypatch):
    proc = FakeProc(SAFE, 9 * GB)
    g, msgs, adb = _guard(proc, monkeypatch, action="warn")
    assert g.check_once() == "over-limit"
    assert adb == []
    assert not proc.killed


def test_limit_zero_disables(monkeypatch):
    proc = FakeProc(SAFE, 50 * GB)
    g, _, adb = _guard(proc, monkeypatch, limit_gb=0)
    assert g.check_once() is None
    assert adb == []


def test_non_emulator_serial_has_no_process():
    assert eg.find_emulator_process("R58M123ABC") is None
    assert eg.find_emulator_process(None) is None


def test_config_defaults():
    from sandroid.config.schema import EmulatorConfig

    cfg = EmulatorConfig()
    assert cfg.max_host_memory_gb == 10.0
    assert cfg.memory_guard_action == "kill"


# -- matching the qemu behind a serial (C4) ---------------------------------


class _Conn:
    def __init__(self, port, status="LISTEN"):
        self.laddr = type("A", (), {"port": port})()
        self.status = status


class _Qemu:
    def __init__(self, pid, cmdline, listen=(), denied=False):
        self.pid = pid
        self.info = {"name": "qemu-system-aarch64", "cmdline": cmdline}
        self._listen = listen
        self._denied = denied

    def net_connections(self, kind="tcp"):
        if self._denied:
            raise PermissionError("denied")
        return [_Conn(p) for p in self._listen] + [_Conn(1, "ESTABLISHED")]


@pytest.fixture
def procs(monkeypatch):
    import psutil

    class _Running(list):
        lsof_calls: list[int]

    running = _Running()
    monkeypatch.setattr(psutil, "process_iter", lambda attrs: list(running))
    monkeypatch.setattr(eg, "_unidentified_serials", set())
    lsof_calls = []

    def _no_lsof(port):
        lsof_calls.append(port)

    monkeypatch.setattr(eg, "_lsof_listener_pids", _no_lsof)
    running.lsof_calls = lsof_calls
    return running


def test_explicit_port_still_matches(procs):
    procs += [
        _Qemu(1, ["qemu", "-avd", "A", "-port", "5556"]),
        _Qemu(2, ["qemu", "-avd", "B", "-port", "5554"]),
    ]
    assert eg.find_emulator_process("emulator-5554").pid == 2


def test_two_auto_port_emulators_match_by_listen_socket(procs):
    """The analyst's AVD listed first must not be taken for emulator-5554."""
    user = _Qemu(111, ["qemu", "-avd", "UserAVD"], listen=(5556, 5557))
    sandbox = _Qemu(222, ["qemu", "-avd", "Sandbox"], listen=(5554, 5555))
    procs += [user, sandbox]
    assert eg.find_emulator_process("emulator-5554") is sandbox
    assert eg.find_emulator_process("emulator-5556") is user
    assert eg.find_emulator_process("emulator-5558") is None


def test_unknown_owner_with_two_emulators_is_not_guessed(procs, caplog):
    procs += [
        _Qemu(111, ["qemu", "-avd", "UserAVD"], denied=True),
        _Qemu(222, ["qemu", "-avd", "Sandbox"], denied=True),
    ]
    with caplog.at_level(logging.WARNING):
        assert eg.find_emulator_process("emulator-5554") is None
        assert eg.find_emulator_process("emulator-5554") is None
    assert len([r for r in caplog.records if "cannot identify" in r.message]) == 1
    assert procs.lsof_calls == [5554, 5554]


def test_lsof_fallback_identifies_owner(procs, monkeypatch):
    procs += [
        _Qemu(111, ["qemu", "-avd", "UserAVD"], denied=True),
        _Qemu(222, ["qemu", "-avd", "Sandbox"], denied=True),
    ]
    monkeypatch.setattr(eg, "_lsof_listener_pids", lambda port: {222})
    assert eg.find_emulator_process("emulator-5554").pid == 222


def test_single_emulator_without_socket_info_is_matched(procs):
    procs.append(_Qemu(7, ["qemu", "-avd", "Only"], denied=True))
    assert eg.find_emulator_process("emulator-5556").pid == 7


def test_single_emulator_on_another_port_is_not_matched(procs):
    procs.append(_Qemu(7, ["qemu", "-avd", "Only"], listen=(5556,)))
    assert eg.find_emulator_process("emulator-5554") is None


def test_guard_never_kills_the_wrong_emulator(procs, monkeypatch):
    """c4 repro: user AVD (14 GB, port 5556) + sandbox (2 GB, port 5554)."""
    user = _Qemu(111, ["qemu", "-avd", "UserAVD"], listen=(5556,))
    sandbox = _Qemu(222, ["qemu", "-avd", "Sandbox", "-feature", "-Vulkan"])
    sandbox._listen = (5554,)
    for proc, rss in ((user, 14 * GB), (sandbox, 2 * GB)):
        proc.cmdline = lambda p=proc: p.info["cmdline"]
        proc.memory_info = lambda r=rss: type("M", (), {"rss": r})()
    procs += [user, sandbox]
    killed = []
    monkeypatch.setattr(eg.subprocess, "run", lambda argv, **kw: killed.append(argv))
    g = eg.EmulatorMemoryGuard(
        lambda: "emulator-5554", limit_gb=10, notify=lambda m, lvl: None
    )
    assert g.check_once() is None
    assert killed == []
