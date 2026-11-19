"""Unit tests for DeviceController's startup check and device switching.

Covers:
- ``check_devices_on_startup`` enumerating with ``auto_select=False``, taking
  only an unambiguous device and otherwise opening the Devices screen (with
  the reason; a missing ``--serial`` is also reported) -- marshaled onto the
  UI thread, since it runs on a background thread;
- ``switch_device``/``setup_device_results_folder`` reading ``dm.active_device``
  (regression test for the ``get_current_device`` AttributeError, traced to
  commit ``cc40b98``, that was silently swallowed by a broad ``except``).
"""

from __future__ import annotations

import os
import threading

from sandroid.tui.controllers.device_controller import DeviceController


class _FakeDevice:
    def __init__(self, serial: str, state: str = "device", is_emulator: bool = True):
        self.serial = serial
        self.state = state
        self.is_emulator = is_emulator


class _FakeDeviceManager:
    """Minimal stand-in exposing exactly what DeviceController touches."""

    def __init__(self, devices=None, active_device=None, preferred=None):
        self.devices = devices or []
        self.active_device = active_device
        self.preferred = preferred
        self.auto_select_called = 0

    def refresh_devices(self, auto_select: bool = True):
        return self.devices

    def preferred_serial(self):
        return self.preferred

    def auto_select_device(self):
        """Like the real one: the pinned serial, or the only ready device."""
        self.auto_select_called += 1
        ready = [d for d in self.devices if d.state == "device"]
        if self.preferred:
            ready = [d for d in ready if d.serial == self.preferred]
        if len(ready) == 1:
            self.active_device = ready[0]
        return self.active_device

    def set_active_device(self, serial: str) -> bool:
        for device in self.devices:
            if device.serial == serial:
                self.active_device = device
                return True
        return False


def _make_controller(
    dm, push_modal=None, call_from_thread=None, open_devices=None, log_error=None
) -> DeviceController:
    class _FakeToolbox:
        @classmethod
        def get_device_manager(cls):
            return dm

    return DeviceController(
        push_modal=push_modal,
        call_from_thread=call_from_thread,
        toolbox=_FakeToolbox,
        open_devices=open_devices,
        log_error=log_error,
    )


# ---------------------------------------------------------------------------
# check_devices_on_startup
# ---------------------------------------------------------------------------


def test_check_devices_on_startup_refreshes_with_auto_select_false():
    dm = _FakeDeviceManager(devices=[_FakeDevice("emulator-5554")])
    seen = {}
    real_refresh = dm.refresh_devices

    def spy_refresh(auto_select: bool = True):
        seen["auto_select"] = auto_select
        return real_refresh(auto_select=auto_select)

    dm.refresh_devices = spy_refresh
    opened: list = []
    controller = _make_controller(dm, open_devices=opened.append)

    result = controller.check_devices_on_startup()

    assert result is True
    assert seen["auto_select"] is False
    assert dm.auto_select_called == 1  # single device -> selected silently
    assert opened == []


def test_check_devices_on_startup_keeps_an_active_device():
    active = _FakeDevice("emulator-5554")
    dm = _FakeDeviceManager(
        devices=[active, _FakeDevice("emulator-5556")], active_device=active
    )
    opened: list = []
    controller = _make_controller(dm, open_devices=opened.append)

    assert controller.check_devices_on_startup() is True
    assert dm.auto_select_called == 0
    assert opened == []


def test_check_devices_on_startup_no_devices_opens_devices():
    dm = _FakeDeviceManager(devices=[])
    opened: list = []
    controller = _make_controller(dm, open_devices=opened.append)

    assert controller.check_devices_on_startup() is False
    assert len(opened) == 1
    assert "No device connected" in opened[0]


def test_check_devices_on_startup_several_ready_opens_devices():
    dm = _FakeDeviceManager(
        devices=[_FakeDevice("emulator-5554"), _FakeDevice("emulator-5556")]
    )
    opened: list = []
    controller = _make_controller(dm, open_devices=opened.append)

    assert controller.check_devices_on_startup() is False
    assert dm.active_device is None  # never a guess among several
    assert opened == ["Several devices are connected -- choose one."]


def test_check_devices_on_startup_missing_pin_reports_and_opens_devices():
    dm = _FakeDeviceManager(
        devices=[_FakeDevice("emulator-5554")], preferred="emulator-5999"
    )
    opened: list = []
    errors: list = []
    controller = _make_controller(
        dm, open_devices=opened.append, log_error=errors.append
    )

    assert controller.check_devices_on_startup() is False
    assert dm.active_device is None  # no fallback to another device
    assert opened == ["Requested device emulator-5999 is not available."]
    assert any("emulator-5999" in e and "Devices (D)" in e for e in errors)


def test_check_devices_on_startup_marshals_open_devices_off_thread():
    """Off the UI thread, open_devices goes through call_from_thread only."""
    dm = _FakeDeviceManager(devices=[])
    opened: list = []
    marshaled: list = []

    def cft(fn, *args):
        marshaled.append((fn, args))  # never runs it

    controller = _make_controller(dm, call_from_thread=cft, open_devices=opened.append)
    worker = threading.Thread(target=controller.check_devices_on_startup)
    worker.start()
    worker.join(5)

    assert opened == []  # not called directly from the worker
    assert [fn for fn, _ in marshaled] == [opened.append]


# ---------------------------------------------------------------------------
# setup_device_results_folder / switch_device: dm.active_device regression
# ---------------------------------------------------------------------------


def test_setup_device_results_folder_reads_active_device(monkeypatch, tmp_path):
    device = _FakeDevice("emulator-5554", is_emulator=True)
    dm = _FakeDeviceManager(devices=[device], active_device=device)
    controller = _make_controller(dm)

    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))

    result = controller.setup_device_results_folder()

    expected = os.path.join(str(tmp_path), "E_emulator-5554")
    assert result == expected
    assert os.path.isdir(expected)


def test_setup_device_results_folder_no_active_device_returns_none():
    dm = _FakeDeviceManager(devices=[], active_device=None)
    controller = _make_controller(dm)

    assert controller.setup_device_results_folder() is None


def test_switch_device_completes_without_raising(monkeypatch, tmp_path):
    device = _FakeDevice("emulator-5554", is_emulator=True)
    dm = _FakeDeviceManager(devices=[device])
    controller = _make_controller(dm)

    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))

    result = controller.switch_device("emulator-5554")

    assert result is True
    assert dm.active_device is device
    assert os.path.isdir(os.path.join(str(tmp_path), "E_emulator-5554"))
