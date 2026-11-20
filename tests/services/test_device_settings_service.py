"""DeviceSettingsService: ADB only, every call pinned to one device serial.

The service used to try TrigDroid's ``TriggerExecutor`` first. It now issues
the adb / emulator-console commands itself, resolves the serial once per
operation and passes it on every call, and reads the console reply because
``adb emu`` exits 0 even when the console answers ``KO``.
"""

from types import SimpleNamespace

import pytest

from sandroid.core.adb import Adb
from sandroid.services.device_settings_service import DeviceSettingsService


@pytest.fixture
def adb_calls(monkeypatch):
    """Record ``(command, effective serial)`` for every adb call.

    ``.calls`` holds the record; ``.replies`` maps a command prefix to the
    ``(stdout, stderr)`` it gets (default: an ``OK`` reply).

    The effective serial is the explicit ``serial=`` or, without one, what
    :meth:`Adb._build_command` would use (thread pin, then global target).
    """
    calls: list[tuple[str, str | None]] = []
    replies: dict[str, tuple[str, str]] = {}

    def fake_send(command, serial=None, timeout=30):
        effective = serial if serial is not None else Adb.get_target_device()
        calls.append((command, effective))
        for prefix, reply in replies.items():
            if command.startswith(prefix):
                return reply
        return "OK\n", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send)
    monkeypatch.setattr(Adb, "_target_device", "emulator-5554")
    return SimpleNamespace(calls=calls, replies=replies)


def test_no_trigger_executor_left() -> None:
    svc = DeviceSettingsService()
    assert not hasattr(svc, "_trigger_executor")


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        (lambda s: s.set_sensor("light", 3), "emu sensor set light 3"),
        (lambda s: s.set_battery_level(42), "emu power capacity 42"),
        (lambda s: s.set_gps_location(48.1, 11.5), "emu geo fix 11.5 48.1"),
        (lambda s: s.toggle_wifi(False), "shell svc wifi disable"),
        (lambda s: s.toggle_mobile_data(True), "shell svc data enable"),
        (lambda s: s.toggle_bluetooth(True), "shell svc bluetooth enable"),
        (lambda s: s.set_timezone("Europe/Berlin"), "shell su 0 setprop"),
    ],
)
def test_explicit_serial_is_passed_on_every_call(adb_calls, call, expected) -> None:
    svc = DeviceSettingsService(serial="emulator-5556")

    result = call(svc)

    assert result.success, result
    assert adb_calls.calls, "no adb call was made"
    assert adb_calls.calls[0][0].startswith(expected)
    assert {serial for _cmd, serial in adb_calls.calls} == {"emulator-5556"}
    assert Adb._target_device == "emulator-5554"


def test_default_serial_is_resolved_once_per_operation(adb_calls) -> None:
    """A target switch mid-preset must not split the preset across devices."""
    svc = DeviceSettingsService()
    original = Adb.send_adb_command

    def switching_send(command, serial=None, timeout=30):
        out = original(command, serial=serial, timeout=timeout)
        Adb._target_device = "emulator-9999"
        return out

    Adb.send_adb_command = switching_send  # restored by monkeypatch fixture
    try:
        result = svc.apply_preset("de")
    finally:
        Adb.send_adb_command = original

    assert result.success, result
    assert len(adb_calls.calls) > 3
    assert {serial for _cmd, serial in adb_calls.calls} == {"emulator-5554"}


@pytest.mark.parametrize(
    "reply",
    [
        ("KO: bad sensor name\n", ""),
        ("", ""),
        ("", "error: no emulator detected"),
    ],
)
def test_console_reply_without_ok_is_failure(adb_calls, reply) -> None:
    adb_calls.replies["emu "] = reply
    svc = DeviceSettingsService(serial="emulator-5556")

    for result in (
        svc.set_sensor("light", 3),
        svc.set_battery_level(10),
        svc.set_gps_location(1.0, 2.0),
        svc.reset_sensors(),
    ):
        assert not result.success
        assert result.error


def test_console_ok_reply_is_success(adb_calls) -> None:
    adb_calls.replies["emu "] = ("OK\n", "")
    svc = DeviceSettingsService(serial="emulator-5556")

    assert svc.reset_sensors().success
    assert all(cmd.startswith("emu sensor set") for cmd, _ in adb_calls.calls)


def test_root_check_is_cached_per_device(adb_calls) -> None:
    adb_calls.replies["shell which su"] = ("/system/xbin/su\n", "")
    svc = DeviceSettingsService()

    assert svc.check_root_available()
    assert svc.check_root_available()
    Adb._target_device = "emulator-5556"
    assert svc.check_root_available()

    su_calls = [serial for cmd, serial in adb_calls.calls if cmd == "shell which su"]
    assert su_calls == ["emulator-5554", "emulator-5556"]
