"""Unit tests for ``FSMon``'s honest PID-mode work (Part A of the fsmon
PID-mode plan):

1. ``run_fsmon_by_pid`` must build its command with ``-B fanotify`` so
   PID-mode attribution is kernel-verified wherever the device supports it.
2. ``fanotify_supported()`` -- a memoized, per-device-serial preflight probe
   run via ``subprocess.run`` (never ``_start_process``, which returns a
   long-lived streaming ``Popen`` meant for the real reader thread):
   - An ENOSYS-style signature in the probe's combined stdout+stderr means
     "unsupported".
   - A clean ``subprocess.TimeoutExpired`` (no signature seen) means
     "supported" -- the probe blocked waiting for a real event on the idle
     probed path, which is what a working fanotify backend does.
   - Memoized per ``Adb.get_target_device()`` serial, not a bare
     process-lifetime bool, so switching the active device never reuses a
     stale verdict.

No device/adb/network involved: ``Adb._build_command``/``_build_adb_cmd``
never actually shell out here -- ``subprocess.run``/``_start_process`` are
monkeypatched.
"""

from __future__ import annotations

import subprocess

import pytest

from sandroid.core.adb import Adb
from sandroid.core.fsmon import FSMon


@pytest.fixture(autouse=True)
def _clean_fanotify_cache():
    """Guard FSMon's class-level memoization cache against cross-test leaks."""
    FSMon._fanotify_cache.clear()
    yield
    FSMon._fanotify_cache.clear()


@pytest.fixture(autouse=True)
def _clean_target_device():
    """Guard Adb's class-level target-device state against cross-test leaks."""
    original = Adb._target_device
    yield
    Adb._target_device = original


# =============================================================================
# run_fsmon_by_pid -- -B fanotify command construction (A1)
# =============================================================================


def test_run_fsmon_by_pid_command_includes_fanotify_flag(monkeypatch):
    captured_cmds = []
    monkeypatch.setattr(
        FSMon, "_start_process", classmethod(lambda cls, cmd: captured_cmds.append(cmd))
    )

    FSMon.run_fsmon_by_pid(1234, "/data/data/com.example.app")

    assert len(captured_cmds) == 1
    cmd = captured_cmds[0]
    assert "-B" in cmd
    b_index = cmd.index("-B")
    assert cmd[b_index + 1] == "fanotify"
    # -p/<pid> must still be present, and in the right order relative to -B.
    assert "-p" in cmd
    p_index = cmd.index("-p")
    assert p_index > b_index
    assert cmd[p_index + 1] == "1234"
    assert cmd[-1] == "/data/data/com.example.app"


def test_run_fsmon_by_pid_uses_default_monitor_path_when_none(monkeypatch):
    captured_cmds = []
    monkeypatch.setattr(
        FSMon, "_start_process", classmethod(lambda cls, cmd: captured_cmds.append(cmd))
    )

    FSMon.run_fsmon_by_pid(5678)

    assert len(captured_cmds) == 1
    assert "-B" in captured_cmds[0]
    assert "fanotify" in captured_cmds[0]


# =============================================================================
# fanotify_supported() -- memoized capability probe (A2)
# =============================================================================


class _FakeCompletedProcess:
    def __init__(self, stdout: str = "", stderr: str = ""):
        self.stdout = stdout
        self.stderr = stderr


def test_fanotify_supported_returns_false_on_enosys_signature(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5554")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: _FakeCompletedProcess(
            stdout="", stderr="fanotify_init: Function not implemented"
        ),
    )

    assert FSMon.fanotify_supported() is False


def test_fanotify_supported_returns_true_on_timeout(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5554")

    def _raise_timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="fsmon", timeout=4)

    monkeypatch.setattr(subprocess, "run", _raise_timeout)

    assert FSMon.fanotify_supported() is True


def test_fanotify_supported_memoizes_per_serial(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5554")
    call_count = {"n": 0}

    def _run(*a, **k):
        call_count["n"] += 1
        return _FakeCompletedProcess(stdout="", stderr="fanotify_init: not implemented")

    monkeypatch.setattr(subprocess, "run", _run)

    assert FSMon.fanotify_supported() is False
    assert FSMon.fanotify_supported() is False
    assert call_count["n"] == 1  # second call served from cache, no new probe


def test_fanotify_supported_binary_missing_is_inconclusive_and_not_cached(monkeypatch):
    """Regression test for a real on-device repro (found during E2E testing):
    probing before the fsmon binary is installed produces a shell-level
    "not found" error, not a real fanotify verdict. That must NOT be cached
    as "supported" -- caching it poisoned every later real call for the same
    serial and let a real PID-mode session spawn against a device that
    actually lacks fanotify, dying immediately instead of falling back.
    """
    monkeypatch.setattr(Adb, "_target_device", "emulator-5554")
    call_count = {"n": 0}

    def _run(*a, **k):
        call_count["n"] += 1
        return _FakeCompletedProcess(
            stdout="", stderr="/data/local/tmp/fsmon-arm64: No such file or directory"
        )

    monkeypatch.setattr(subprocess, "run", _run)

    assert FSMon.fanotify_supported() is False
    assert "emulator-5554" not in FSMon._fanotify_cache  # must not be memoized

    # A later, real probe (e.g. after the binary is installed) must re-probe,
    # not silently reuse an inconclusive verdict from before.
    def _run_real(*a, **k):
        call_count["n"] += 1
        return _FakeCompletedProcess(stdout="", stderr="fanotify_init: not implemented")

    monkeypatch.setattr(subprocess, "run", _run_real)
    assert FSMon.fanotify_supported() is False
    assert call_count["n"] == 2
    assert FSMon._fanotify_cache["emulator-5554"] is False


def test_fanotify_supported_reprobes_for_a_different_serial(monkeypatch):
    call_count = {"n": 0}

    def _run(*a, **k):
        call_count["n"] += 1
        return _FakeCompletedProcess(stdout="", stderr="fanotify_init: not implemented")

    monkeypatch.setattr(subprocess, "run", _run)

    monkeypatch.setattr(Adb, "_target_device", "device-a")
    assert FSMon.fanotify_supported() is False
    assert call_count["n"] == 1

    monkeypatch.setattr(Adb, "_target_device", "device-b")
    assert FSMon.fanotify_supported() is False
    assert call_count["n"] == 2  # different serial -> fresh probe, not cache hit


def test_fanotify_supported_builds_probe_via_build_adb_cmd(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5554")
    captured_cmds = []

    def _run(cmd, **k):
        captured_cmds.append(cmd)
        return _FakeCompletedProcess(stdout="ok")

    monkeypatch.setattr(subprocess, "run", _run)

    FSMon.fanotify_supported()

    assert len(captured_cmds) == 1
    cmd = captured_cmds[0]
    assert "-B" in cmd
    assert "fanotify" in cmd
    assert "-s" in cmd
    assert "emulator-5554" in cmd
