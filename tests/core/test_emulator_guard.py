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


SAFE = ["qemu-system-aarch64", "-avd", "X", "-port", "5556", "-feature", "-Vulkan", "-gpu", "host"]
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
    assert eg.console_port(["-avd", "A"]) == 5554


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
