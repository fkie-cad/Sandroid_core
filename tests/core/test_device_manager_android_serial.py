"""DeviceManager.auto_select_device honours ANDROID_SERIAL with 2+ devices."""

import pytest

from sandroid.core.device import Device
from sandroid.core.device_manager import DeviceManager


@pytest.fixture
def dm(monkeypatch):
    DeviceManager.reset()
    manager = DeviceManager.get()
    devices = [
        Device(serial="emulator-5554"),
        Device(serial="emulator-5556"),
        Device(serial="emulator-5558", state="offline"),
    ]
    monkeypatch.setattr(manager, "get_devices", lambda: devices)
    selected = []
    monkeypatch.setattr(manager, "set_active_device", selected.append)
    manager.selected = selected
    yield manager
    DeviceManager.reset()


def test_android_serial_selects_matching_device(dm, monkeypatch):
    monkeypatch.setenv("ANDROID_SERIAL", "emulator-5556")
    assert dm.auto_select_device().serial == "emulator-5556"
    assert dm.selected == ["emulator-5556"]


def test_without_android_serial_first_emulator_wins(dm, monkeypatch):
    monkeypatch.delenv("ANDROID_SERIAL", raising=False)
    assert dm.auto_select_device().serial == "emulator-5554"


@pytest.mark.parametrize("serial", ["emulator-5558", "does-not-exist"])
def test_unready_or_unknown_serial_falls_back(dm, monkeypatch, serial):
    monkeypatch.setenv("ANDROID_SERIAL", serial)
    assert dm.auto_select_device().serial == "emulator-5554"
