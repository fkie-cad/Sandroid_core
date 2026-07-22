"""Unit tests for DeviceManager active-device disconnect handling.

Covers the refresh_devices() disconnect path:
- a vanished active serial nulls the active device, clears the ADB target,
  and fires the change callback once with None;
- a normal refresh (device still listed and ready) does nothing;
- a transient non-ready state (offline) does NOT disconnect (no flapping).

Also covers the shared-global-race fix and the zombie-retry cooldown:
- _populate_device_info() targets via serial=, never touching Adb._target_device
  (its own monkeypatched fake here doesn't exercise the plumbing, so this is
  tested against the real method with send_adb_command mocked instead);
- a device stuck at state="device" with no android_version isn't re-probed
  inside PROBE_RETRY_COOLDOWN_SECONDS, but is re-probed once it elapses;
- refresh_devices(auto_select=False) never auto-selects, even with 2+ ready
  devices and no active device.
"""

import time

import pytest

from sandroid.core.adb import Adb
from sandroid.core.device import Device
from sandroid.core.device_manager import PROBE_RETRY_COOLDOWN_SECONDS, DeviceManager

HEADER = "List of devices attached"

# Captured at import time (before the autouse fixture below ever stubs it
# out), so tests that need the REAL _populate_device_info can restore it.
_REAL_POPULATE_DEVICE_INFO = DeviceManager._populate_device_info


def _devices_output(*lines: str) -> str:
    """Build a fake `adb devices -l` output (header line + device lines)."""
    return "\n".join([HEADER, *lines])


@pytest.fixture(autouse=True)
def _clean_device_manager(monkeypatch):
    """Reset the DeviceManager singleton and ADB target around each test.

    Also stubs _populate_device_info, which would otherwise make real ADB
    calls when a brand-new device is parsed.
    """
    DeviceManager.reset()
    Adb.set_target_device(None)
    monkeypatch.setattr(
        DeviceManager, "_populate_device_info", lambda self, device: None
    )
    yield
    DeviceManager.reset()
    Adb.set_target_device(None)


def _seed_active(dm: DeviceManager, serial: str = "emulator-5554") -> Device:
    """Seed an active emulator device without invoking set_active_device.

    set_active_device() reaches into Toolbox; for these unit tests we set the
    active device and the ADB target directly to isolate refresh_devices().
    """
    device = Device(serial=serial, name=serial, state="device", model="sdk")
    dm._devices = {serial: device}
    dm._active_device = device
    Adb.set_target_device(serial)
    return device


def test_disconnect_fires_change_callback_with_none(monkeypatch):
    """A vanished active serial nulls the device and fires callback(None)."""
    dm = DeviceManager.get()
    _seed_active(dm)

    calls: list = []
    dm.on_device_change(calls.append)

    # New listing no longer contains the active serial (empty device list).
    monkeypatch.setattr(
        Adb, "send_adb_command", lambda command: (_devices_output(), "")
    )

    dm.refresh_devices()

    assert dm.active_device is None
    assert calls == [None]
    assert Adb.get_target_device() is None


def test_normal_refresh_does_not_fire_change_callback(monkeypatch):
    """Active device still listed and ready: no disconnect reaction."""
    dm = DeviceManager.get()
    device = _seed_active(dm)

    calls: list = []
    dm.on_device_change(calls.append)

    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        lambda command: (
            _devices_output(
                "emulator-5554 device product:sdk model:sdk "
                "device:emu transport_id:1"
            ),
            "",
        ),
    )

    dm.refresh_devices()

    assert dm.active_device is device
    assert calls == []
    assert Adb.get_target_device() == "emulator-5554"


def test_transient_offline_does_not_disconnect(monkeypatch):
    """Active device present but offline: not nulled (no flapping)."""
    dm = DeviceManager.get()
    _seed_active(dm)

    calls: list = []
    dm.on_device_change(calls.append)

    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        lambda command: (
            _devices_output("emulator-5554 offline transport_id:1"),
            "",
        ),
    )

    dm.refresh_devices()

    assert dm.active_device is not None
    assert None not in calls
    assert Adb.get_target_device() == "emulator-5554"


def test_adb_timeout_does_not_disconnect(monkeypatch):
    """A 30s ADB timeout (empty output + error) must NOT disconnect.

    Adb.send_adb_command returns ("", "Command timed out after 30 seconds")
    on a timeout. That message has no "error" substring, so without the
    empty-output guard refresh_devices() would parse zero devices and
    spuriously tear down the healthy active device (flapping).
    """
    dm = DeviceManager.get()
    _seed_active(dm)

    calls: list = []
    dm.on_device_change(calls.append)

    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        lambda command: ("", "Command timed out after 30 seconds"),
    )

    dm.refresh_devices()

    assert dm.active_device is not None
    assert None not in calls
    assert Adb.get_target_device() == "emulator-5554"


def test_ready_active_device_with_empty_version_repopulates_and_repaints(monkeypatch):
    """A ready active device missing version/API re-populates and repaints.

    Reproduces the reconnect bug: the device was first seen offline (booting),
    so getprop failed and android_version stayed empty; once it is ready a
    refresh must re-run _populate_device_info and fire a one-off change so the
    glance shows the metadata.
    """
    dm = DeviceManager.get()
    device = _seed_active(dm)
    assert not device.android_version  # precondition: stale/empty metadata

    calls: list = []
    dm.on_device_change(calls.append)

    populated: list = []

    def fake_populate(self, dev):
        populated.append(dev.serial)
        dev.android_version = "16"
        dev.api_level = 36

    monkeypatch.setattr(DeviceManager, "_populate_device_info", fake_populate)
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        lambda command: (
            _devices_output(
                "emulator-5554 device product:sdk model:sdk "
                "device:emu transport_id:1"
            ),
            "",
        ),
    )

    dm.refresh_devices()

    assert populated == ["emulator-5554"]
    assert device.android_version == "16"
    assert device.api_level == 36
    assert calls == [device]  # part-B repaint fired once with the active device


def test_ready_device_with_version_is_not_repopulated(monkeypatch):
    """A ready device that already has version is NOT re-populated (no churn)."""
    dm = DeviceManager.get()
    device = _seed_active(dm)
    device.android_version = "16"
    device.api_level = 36

    calls: list = []
    dm.on_device_change(calls.append)

    populated: list = []
    monkeypatch.setattr(
        DeviceManager,
        "_populate_device_info",
        lambda self, dev: populated.append(dev.serial),
    )
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        lambda command: (
            _devices_output(
                "emulator-5554 device product:sdk model:sdk "
                "device:emu transport_id:1"
            ),
            "",
        ),
    )

    dm.refresh_devices()

    assert populated == []  # guard skips the re-populate
    assert calls == []  # no spurious repaint
    assert device.android_version == "16"


def test_repopulate_non_active_device_does_not_repaint(monkeypatch):
    """A stale non-active device re-populates, but fires no part-B repaint."""
    dm = DeviceManager.get()
    active = _seed_active(dm, serial="emulator-5554")
    active.android_version = "16"
    active.api_level = 36
    # A second device, previously seen offline (empty version), now also listed.
    other = Device(
        serial="emulator-5556", name="emulator-5556", state="offline", model=""
    )
    dm._devices["emulator-5556"] = other

    calls: list = []
    dm.on_device_change(calls.append)

    populated: list = []

    def fake_populate(self, dev):
        populated.append(dev.serial)
        dev.android_version = "16"
        dev.api_level = 36

    monkeypatch.setattr(DeviceManager, "_populate_device_info", fake_populate)
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        lambda command: (
            _devices_output(
                "emulator-5554 device product:sdk model:sdk "
                "device:emu transport_id:1",
                "emulator-5556 device product:sdk model:sdk "
                "device:emu transport_id:2",
            ),
            "",
        ),
    )

    dm.refresh_devices()

    assert populated == ["emulator-5556"]  # only the stale, non-active device
    assert other.android_version == "16"
    assert calls == []  # not the active device -> no part-B repaint
    assert dm.active_device is active


# ---------------------------------------------------------------------------
# Shared-global race: _populate_device_info must never touch Adb._target_device
# ---------------------------------------------------------------------------


def test_populate_device_info_does_not_touch_adb_target_device(monkeypatch):
    """_populate_device_info targets via serial=, leaving the shared global alone.

    Simulates the real race: a concurrent caller has the global target set to
    a DIFFERENT (the real active) device while this device is probed.
    """
    monkeypatch.setattr(
        DeviceManager, "_populate_device_info", _REAL_POPULATE_DEVICE_INFO
    )
    dm = DeviceManager.get()
    device = Device(serial="emulator-5556", name="", state="device", model="")

    Adb.set_target_device("emulator-5554")

    calls: list = []

    def fake_send_adb_command(command, serial=None):
        calls.append((command, serial))
        return "14\n", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send_adb_command)

    dm._populate_device_info(device)

    assert calls and all(serial == "emulator-5556" for _cmd, serial in calls)
    assert Adb.get_target_device() == "emulator-5554"  # untouched throughout
    assert device.android_version == "14"


def test_populate_device_info_root_check_uses_serial_not_global(monkeypatch):
    """_check_root_capability (reached for physical devices) also uses serial=."""
    monkeypatch.setattr(
        DeviceManager, "_populate_device_info", _REAL_POPULATE_DEVICE_INFO
    )
    dm = DeviceManager.get()
    device = Device(serial="R58N123ABC", name="", state="device", model="")

    Adb.set_target_device("emulator-5554")

    calls: list = []

    def fake_send_adb_command(command, serial=None):
        calls.append((command, serial))
        if "getprop" in command:
            return "14\n", ""
        return "uid=0(root)", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send_adb_command)

    dm._populate_device_info(device)

    assert ("shell su -c id", "R58N123ABC") in calls
    assert Adb.get_target_device() == "emulator-5554"


def test_populate_device_info_stamps_last_probe_attempt(monkeypatch):
    monkeypatch.setattr(
        DeviceManager, "_populate_device_info", _REAL_POPULATE_DEVICE_INFO
    )
    monkeypatch.setattr(
        Adb, "send_adb_command", lambda command, serial=None: ("14\n", "")
    )
    dm = DeviceManager.get()
    device = Device(serial="emulator-5556", name="", state="device", model="")
    assert device.last_probe_attempt == 0.0

    before = time.monotonic()
    dm._populate_device_info(device)
    after = time.monotonic()

    assert before <= device.last_probe_attempt <= after


# ---------------------------------------------------------------------------
# Zombie-device retry cooldown
# ---------------------------------------------------------------------------


def test_zombie_device_not_reprobed_within_cooldown(monkeypatch):
    """A device probed moments ago is NOT re-probed again inside the cooldown."""
    dm = DeviceManager.get()
    device = Device(serial="emulator-5554", state="device")
    device.last_probe_attempt = time.monotonic()  # just probed, still zombie
    dm._devices = {"emulator-5554": device}

    populated: list = []
    monkeypatch.setattr(
        DeviceManager,
        "_populate_device_info",
        lambda self, dev: populated.append(dev.serial),
    )
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        lambda command: (
            _devices_output(
                "emulator-5554 device product:sdk model:sdk "
                "device:emu transport_id:1"
            ),
            "",
        ),
    )

    dm.refresh_devices()

    assert populated == []  # still within cooldown


def test_zombie_device_reprobed_after_cooldown_elapses(monkeypatch):
    """Once PROBE_RETRY_COOLDOWN_SECONDS has passed, the device is re-probed."""
    dm = DeviceManager.get()
    device = Device(serial="emulator-5554", state="device")
    device.last_probe_attempt = time.monotonic() - (PROBE_RETRY_COOLDOWN_SECONDS + 1)
    dm._devices = {"emulator-5554": device}

    populated: list = []
    monkeypatch.setattr(
        DeviceManager,
        "_populate_device_info",
        lambda self, dev: populated.append(dev.serial),
    )
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        lambda command: (
            _devices_output(
                "emulator-5554 device product:sdk model:sdk "
                "device:emu transport_id:1"
            ),
            "",
        ),
    )

    dm.refresh_devices()

    assert populated == ["emulator-5554"]


# ---------------------------------------------------------------------------
# Startup-only multi-device picker: refresh_devices(auto_select=False)
# ---------------------------------------------------------------------------


def test_refresh_devices_auto_select_false_leaves_no_active_device(monkeypatch):
    """With 2+ ready devices and auto_select=False, nothing gets auto-selected."""
    dm = DeviceManager.get()
    monkeypatch.setattr(
        DeviceManager, "_populate_device_info", lambda self, device: None
    )
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        lambda command: (
            _devices_output(
                "emulator-5554 device product:sdk model:sdk "
                "device:emu transport_id:1",
                "emulator-5556 device product:sdk model:sdk "
                "device:emu transport_id:2",
            ),
            "",
        ),
    )

    devices = dm.refresh_devices(auto_select=False)

    assert len(devices) == 2
    assert dm.active_device is None


def test_refresh_devices_default_auto_selects_with_no_active_device(monkeypatch):
    """Contrast case: the default (auto_select=True) still auto-selects."""
    dm = DeviceManager.get()
    monkeypatch.setattr(
        DeviceManager, "_populate_device_info", lambda self, device: None
    )
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        lambda command: (
            _devices_output(
                "emulator-5554 device product:sdk model:sdk "
                "device:emu transport_id:1",
            ),
            "",
        ),
    )

    dm.refresh_devices()

    assert dm.active_device is not None
    assert dm.active_device.serial == "emulator-5554"
