"""Unit tests for DeviceController's startup-only multi-device picker.

Covers:
- ``check_devices_on_startup`` enumerating with ``auto_select=False``;
- ``_resolve_startup_device_selection``'s 0/1/2+-ready-device and
  active-device-already-set branches, plus the selection/cancel callback;
- that both ``_resolve_startup_device_selection`` and ``offer_avd_start``
  marshal the modal push through ``call_from_thread`` rather than calling
  ``push_modal`` directly -- the latter was verified to raise
  ``RuntimeError: no current event loop in thread`` when invoked straight
  from the background thread ``check_devices_on_startup`` runs on.
- ``switch_device``/``setup_device_results_folder`` reading ``dm.active_device``
  (regression test for the ``get_current_device`` AttributeError, traced to
  commit ``cc40b98``, that was silently swallowed by a broad ``except``).
"""

from __future__ import annotations

import os

from sandroid.config import android_env
from sandroid.tui.controllers.device_controller import AVDInfo, DeviceController


class _FakeDevice:
    def __init__(self, serial: str, state: str = "device", is_emulator: bool = True):
        self.serial = serial
        self.state = state
        self.is_emulator = is_emulator


class _FakeDeviceManager:
    """Minimal stand-in exposing exactly what DeviceController touches."""

    def __init__(self, devices=None, active_device=None):
        self.devices = devices or []
        self.active_device = active_device
        self.auto_select_called = 0

    def refresh_devices(self, auto_select: bool = True):
        return self.devices

    def auto_select_device(self):
        self.auto_select_called += 1

    def set_active_device(self, serial: str) -> bool:
        for device in self.devices:
            if device.serial == serial:
                self.active_device = device
                return True
        return False


def _make_controller(dm, push_modal=None, call_from_thread=None) -> DeviceController:
    class _FakeToolbox:
        @classmethod
        def get_device_manager(cls):
            return dm

    return DeviceController(
        push_modal=push_modal,
        call_from_thread=call_from_thread,
        toolbox=_FakeToolbox,
    )


def _invoking_call_from_thread(calls: list):
    """A call_from_thread fake that immediately runs the marshaled call."""

    def _cft(fn, *args):
        calls.append((fn, args))
        fn(*args)

    return _cft


def _recording_call_from_thread(calls: list):
    """A call_from_thread fake that only records -- never runs the call.

    Used to prove a function is invoked ONLY through call_from_thread: if
    the code under test called it directly too, that would show up as an
    extra invocation despite this fake never executing it.
    """

    def _cft(fn, *args):
        calls.append((fn, args))

    return _cft


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
    controller = _make_controller(dm)

    result = controller.check_devices_on_startup()

    assert result is True
    assert seen["auto_select"] is False
    assert dm.auto_select_called == 1  # single device -> falls back silently


def test_check_devices_on_startup_no_devices_offers_avd_start(monkeypatch):
    dm = _FakeDeviceManager(devices=[])
    controller = _make_controller(dm)

    offered = []
    monkeypatch.setattr(controller, "offer_avd_start", lambda: offered.append(True))

    result = controller.check_devices_on_startup()

    assert result is False
    assert offered == [True]


# ---------------------------------------------------------------------------
# _resolve_startup_device_selection: 0 / 1 / 2+ ready-device branches
# ---------------------------------------------------------------------------


def test_resolve_selection_no_devices_auto_selects():
    dm = _FakeDeviceManager(devices=[])
    controller = _make_controller(dm)

    controller._resolve_startup_device_selection(dm, dm.devices)

    assert dm.auto_select_called == 1


def test_resolve_selection_one_ready_device_auto_selects():
    dm = _FakeDeviceManager(devices=[_FakeDevice("emulator-5554")])
    push_calls: list = []
    controller = _make_controller(dm, push_modal=lambda *a: push_calls.append(a))

    controller._resolve_startup_device_selection(dm, dm.devices)

    assert dm.auto_select_called == 1
    assert push_calls == []


def test_resolve_selection_counts_only_ready_state():
    """One 'device' + one 'offline' is only 1 READY device -> no picker."""
    dm = _FakeDeviceManager(
        devices=[
            _FakeDevice("emulator-5554", state="device"),
            _FakeDevice("emulator-5556", state="offline"),
        ]
    )
    controller = _make_controller(dm)

    controller._resolve_startup_device_selection(dm, dm.devices)

    assert dm.auto_select_called == 1


def test_resolve_selection_skips_entirely_when_already_active():
    dm = _FakeDeviceManager(
        devices=[_FakeDevice("emulator-5554"), _FakeDevice("emulator-5556")],
        active_device=_FakeDevice("emulator-5554"),
    )
    push_calls: list = []
    controller = _make_controller(dm, push_modal=lambda *a: push_calls.append(a))

    controller._resolve_startup_device_selection(dm, dm.devices)

    assert dm.auto_select_called == 0
    assert push_calls == []


def test_resolve_selection_no_push_modal_configured_falls_back():
    dm = _FakeDeviceManager(
        devices=[_FakeDevice("emulator-5554"), _FakeDevice("emulator-5556")]
    )
    controller = _make_controller(dm, push_modal=None)

    controller._resolve_startup_device_selection(dm, dm.devices)

    assert dm.auto_select_called == 1


def test_resolve_selection_two_ready_marshals_via_call_from_thread_only():
    """The modal push must go through call_from_thread, never push_modal directly."""
    dm = _FakeDeviceManager(
        devices=[_FakeDevice("emulator-5554"), _FakeDevice("emulator-5556")]
    )
    push_calls: list = []
    cft_calls: list = []

    controller = _make_controller(
        dm,
        push_modal=lambda *a: push_calls.append(a),
        call_from_thread=_recording_call_from_thread(cft_calls),
    )

    controller._resolve_startup_device_selection(dm, dm.devices)

    assert len(cft_calls) == 1
    assert cft_calls[0][0] is controller._push_modal
    assert push_calls == []  # never invoked directly/synchronously
    assert dm.auto_select_called == 0


# ---------------------------------------------------------------------------
# _resolve_startup_device_selection: the on-selection callback itself
# ---------------------------------------------------------------------------


def test_resolve_selection_choosing_a_device_switches_to_it():
    dm = _FakeDeviceManager(
        devices=[_FakeDevice("emulator-5554"), _FakeDevice("emulator-5556")]
    )
    switch_calls: list = []
    captured = {}

    def fake_push_modal(modal, callback):
        captured["callback"] = callback

    cft_calls: list = []
    controller = _make_controller(
        dm,
        push_modal=fake_push_modal,
        call_from_thread=_invoking_call_from_thread(cft_calls),
    )
    controller.switch_device = lambda serial: switch_calls.append(serial)

    controller._resolve_startup_device_selection(dm, dm.devices)
    captured["callback"]("emulator-5556")

    assert switch_calls == ["emulator-5556"]
    assert dm.auto_select_called == 0


def test_resolve_selection_cancel_falls_back_to_auto_select():
    dm = _FakeDeviceManager(
        devices=[_FakeDevice("emulator-5554"), _FakeDevice("emulator-5556")]
    )
    captured = {}

    def fake_push_modal(modal, callback):
        captured["callback"] = callback

    cft_calls: list = []
    controller = _make_controller(
        dm,
        push_modal=fake_push_modal,
        call_from_thread=_invoking_call_from_thread(cft_calls),
    )

    controller._resolve_startup_device_selection(dm, dm.devices)
    captured["callback"](None)  # modal cancelled

    assert dm.auto_select_called == 1


# ---------------------------------------------------------------------------
# offer_avd_start: same call_from_thread marshaling fix
# ---------------------------------------------------------------------------


def test_offer_avd_start_marshals_via_call_from_thread_only(monkeypatch):
    monkeypatch.setattr(android_env, "find_emulator_path", lambda: "/fake/emulator")
    monkeypatch.setattr(android_env, "find_existing_sdk", lambda: "/fake/sdk")

    dm = _FakeDeviceManager(devices=[])
    push_calls: list = []
    cft_calls: list = []

    controller = _make_controller(
        dm,
        push_modal=lambda *a: push_calls.append(a),
        call_from_thread=_recording_call_from_thread(cft_calls),
    )
    monkeypatch.setattr(
        controller,
        "get_available_avds",
        lambda: [AVDInfo(name="Pixel_6_API_34", android_version="14", api_level="34")],
    )

    controller.offer_avd_start()

    assert len(cft_calls) == 1
    assert cft_calls[0][0] is controller._push_modal
    assert push_calls == []  # never invoked directly/synchronously


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
