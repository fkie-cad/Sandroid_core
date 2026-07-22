"""Unit tests for ``Adb``'s per-call device-serial targeting.

Covers the shared-global-race fix: passing ``serial=`` to
``Adb.send_adb_command`` / ``_build_command`` / ``send_adb_command_popen`` /
``get_android_version_and_api_level`` / ``send_telnet_command`` /
``get_current_avd_name`` must target that device WITHOUT mutating the shared
``Adb._target_device`` class attribute, while omitting ``serial`` (the
default) must behave exactly as before -- ~150 existing call sites rely on
that default being a no-op.
"""

from __future__ import annotations

import subprocess

import pytest

from sandroid.core.adb import Adb


@pytest.fixture(autouse=True)
def _clean_target(monkeypatch):
    """Isolate the shared ADB target global across tests."""
    Adb.set_target_device(None)
    monkeypatch.setattr(Adb, "ADB_PATH", "adb")
    yield
    Adb.set_target_device(None)


class _FakeCompletedProcess:
    """Stand-in for ``subprocess.CompletedProcess``."""

    def __init__(self, stdout: str = "", stderr: str = ""):
        self.stdout = stdout
        self.stderr = stderr


# ---------------------------------------------------------------------------
# _build_command
# ---------------------------------------------------------------------------


def test_build_command_serial_overrides_without_mutating_global():
    Adb.set_target_device("emulator-5554")

    result = Adb._build_command("shell getprop", serial="emulator-5556")

    assert result == "-s emulator-5556 shell getprop"
    assert Adb.get_target_device() == "emulator-5554"


def test_build_command_falls_back_to_global_when_serial_omitted():
    Adb.set_target_device("emulator-5554")

    assert Adb._build_command("shell getprop") == "-s emulator-5554 shell getprop"


def test_build_command_no_target_no_serial():
    assert Adb._build_command("devices -l") == "devices -l"


# ---------------------------------------------------------------------------
# send_adb_command / send_adb_command_popen
# ---------------------------------------------------------------------------


def test_send_adb_command_serial_targets_without_mutating_global(monkeypatch):
    Adb.set_target_device("emulator-5554")
    captured = {}

    def fake_run(cmd, **_kwargs):
        captured["cmd"] = cmd[0]
        return _FakeCompletedProcess("out", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    stdout, _stderr = Adb.send_adb_command("shell getprop foo", serial="emulator-5556")

    assert "-s emulator-5556" in captured["cmd"]
    assert "-s emulator-5554" not in captured["cmd"]
    assert stdout == "out"
    assert Adb.get_target_device() == "emulator-5554"  # global unaffected


def test_send_adb_command_default_uses_global_target(monkeypatch):
    """Omitting ``serial`` must preserve the pre-existing global-target behavior."""
    Adb.set_target_device("emulator-5554")
    captured = {}

    def fake_run(cmd, **_kwargs):
        captured["cmd"] = cmd[0]
        return _FakeCompletedProcess("out", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    Adb.send_adb_command("shell getprop foo")

    assert "-s emulator-5554" in captured["cmd"]


def test_send_adb_command_popen_serial_overrides_without_mutating_global(monkeypatch):
    Adb.set_target_device("emulator-5554")
    captured = {}

    class _FakePopen:
        def __init__(self, cmd, **_kwargs):
            captured["cmd"] = cmd[0]

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)

    Adb.send_adb_command_popen("shell logcat", serial="emulator-5556")

    assert "-s emulator-5556" in captured["cmd"]
    assert Adb.get_target_device() == "emulator-5554"


# ---------------------------------------------------------------------------
# get_android_version_and_api_level
# ---------------------------------------------------------------------------


def test_get_android_version_and_api_level_serial_does_not_mutate_global(
    monkeypatch,
):
    Adb.set_target_device("emulator-5554")
    calls = []

    def fake_send(command, serial=None):
        calls.append((command, serial))
        if "release" in command:
            return "14\n", ""
        return "34\n", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send)

    info = Adb.get_android_version_and_api_level(serial="emulator-5556")

    assert info == {"android_version": "14", "api_level": "34"}
    assert calls and all(serial == "emulator-5556" for _cmd, serial in calls)
    assert Adb.get_target_device() == "emulator-5554"


def test_get_android_version_and_api_level_default_forwards_no_serial(monkeypatch):
    """Omitting ``serial`` must call send_adb_command exactly as before."""
    calls = []

    def fake_send(command, serial=None):
        calls.append(serial)
        return "14\n", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send)

    Adb.get_android_version_and_api_level()

    assert calls and all(serial is None for serial in calls)


# ---------------------------------------------------------------------------
# send_telnet_command / get_current_avd_name (the extra telnet layer)
# ---------------------------------------------------------------------------


def test_send_telnet_command_serial_does_not_mutate_global(monkeypatch):
    Adb.set_target_device("emulator-5554")
    calls = []

    def fake_send(command, serial=None):
        calls.append((command, serial))
        return "OK\n", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send)

    Adb.send_telnet_command("avd name", serial="emulator-5556")

    assert calls == [("emu avd name", "emulator-5556")]
    assert Adb.get_target_device() == "emulator-5554"


def test_get_current_avd_name_serial_forwards_through_telnet_layer(monkeypatch):
    """serial= must thread through get_current_avd_name -> _get_avd_property ->
    send_telnet_command -> send_adb_command, without touching the global.
    """
    Adb.set_target_device("emulator-5554")
    calls = []

    def fake_send(command, serial=None):
        calls.append((command, serial))
        return "Pixel_6_API_34\n", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send)

    name = Adb.get_current_avd_name(serial="emulator-5556")

    assert name == "Pixel_6_API_34"
    assert calls == [("emu avd name", "emulator-5556")]
    assert Adb.get_target_device() == "emulator-5554"


def test_get_current_avd_name_default_forwards_no_serial(monkeypatch):
    calls = []

    def fake_send(command, serial=None):
        calls.append(serial)
        return "Pixel_6_API_34\n", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send)

    Adb.get_current_avd_name()

    assert calls == [None]
