"""Proxy state is owned per device serial and released on a device switch."""

from __future__ import annotations

import subprocess
import threading

import pytest

from sandroid.core import adb as adb_mod
from sandroid.core.adb import Adb

OLD, NEW = "emulator-5554", "emulator-5556"


@pytest.fixture
def adb_log(monkeypatch):
    """Capture every adb command line; answer like a device with a proxy set."""
    calls: list[str] = []
    answers = {"settings get global http_proxy": "10.0.2.2:8085\n"}

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        out = next((v for k, v in answers.items() if k in cmd), "")
        if "settings put global http_proxy :0" in cmd:
            answers["settings get global http_proxy"] = ":0\n"
        return subprocess.CompletedProcess(cmd, 0, out, "")

    monkeypatch.setattr(adb_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(Adb, "ADB_PATH", "/x/adb")
    monkeypatch.setattr(Adb, "_target_device", OLD)
    return calls


def test_targeting_pins_only_the_current_thread(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", NEW)
    seen = {}
    with Adb.targeting(OLD):
        assert Adb._build_command("shell id") == f"-s {OLD} shell id"
        assert Adb.get_target_device() == OLD
        t = threading.Thread(target=lambda: seen.update(t=Adb._build_command("x")))
        t.start()
        t.join()
    assert seen["t"] == f"-s {NEW} x"
    assert Adb._build_command("shell id") == f"-s {NEW} shell id"
    with Adb.targeting(None):
        assert Adb.get_target_device() == NEW


def test_device_proxy_is_released_on_the_device_it_was_set_on(adb_log, monkeypatch):
    from sandroid.services.mitmproxy_service import MitmproxyService

    svc = MitmproxyService.__new__(MitmproxyService)
    svc._owned_device_proxy = None
    svc._owned_device_proxy_serial = None
    svc.note_device_proxy("10.0.2.2:8085")  # set while OLD is selected
    assert svc.owned_device_proxy_serial == OLD

    monkeypatch.setattr(Adb, "_target_device", NEW)  # user switched device
    assert svc.release_device_proxy(serial=NEW) is False  # not NEW's proxy
    assert adb_log == []
    assert svc.release_device_proxy() is True
    assert adb_log
    assert all(f"-s {OLD} " in c for c in adb_log)
    assert svc.owned_device_proxy is None


def _focus_with_lane(monkeypatch, serial):
    from sandroid.core.proxy_manager import FocusManager

    monkeypatch.setattr(FocusManager, "_pool_size", property(lambda self: 2))
    fm = FocusManager()
    fm._lanes = {0: "com.example.app", 1: None}
    fm._lane_serials = {0: serial}
    fm._lane_targets = {0: "ours"}
    torn = []
    monkeypatch.setattr(
        fm, "_remove_lane_rules", lambda lane: torn.append(Adb.get_target_device())
    )
    monkeypatch.setattr(
        fm, "_kill_lane_process", lambda port: torn.append(Adb.get_target_device())
    )
    monkeypatch.setattr(fm, "_write_sidecar", lambda: None)
    monkeypatch.setattr(fm, "_remove_from_state", lambda package: None)
    return fm, torn


def test_focus_lanes_are_per_serial_and_released_on_their_device(monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", NEW)
    fm, torn = _focus_with_lane(monkeypatch, OLD)

    # The lane lives on OLD: on NEW the app is not proxied.
    assert fm.lane_for("com.example.app") is None
    with Adb.targeting(OLD):
        assert fm.lane_for("com.example.app") is not None

    assert fm.release_serial(NEW) == 0
    assert fm.release_serial(OLD) == 1
    assert torn == [OLD, OLD]  # torn down on OLD although NEW is selected
    assert fm.focused_apps() == []


def test_device_switch_releases_old_device_proxies(monkeypatch):
    from sandroid.core import device_manager as dm_mod
    from sandroid.core import proxy_manager
    from sandroid.core.device import Device
    from sandroid.core.toolbox import Toolbox
    from sandroid.services import mitmproxy_service

    released = []

    class _Focus:
        def release_serial(self, serial):
            released.append(("lanes", serial, Adb.get_target_device()))
            return 1

    class _Mitm:
        owned_device_proxy = "10.0.2.2:8085"

        def release_device_proxy(self, serial=None):
            released.append(("proxy", serial, Adb.get_target_device()))
            return True

    monkeypatch.setattr(proxy_manager, "_FOCUS_INSTANCE", _Focus())
    monkeypatch.setattr(mitmproxy_service, "_INSTANCE", _Mitm())
    monkeypatch.setattr(Adb, "_target_device", OLD)
    monkeypatch.setattr(Toolbox, "update_frida_device_serial", lambda s: None)
    monkeypatch.setattr(Toolbox, "switch_device_folder", staticmethod(lambda n: None))
    monkeypatch.setattr(dm_mod, "_active_device_name", None)
    monkeypatch.setattr(dm_mod, "_configured_device_name", None)

    manager = dm_mod.DeviceManager()
    old = Device(serial=OLD, name="A", state="device")
    new = Device(serial=NEW, name="B", state="device")
    manager._devices = {OLD: old, NEW: new}
    manager._active_device = old
    assert manager.set_active_device(NEW)

    assert released == [("lanes", OLD, OLD), ("proxy", OLD, OLD)]
    assert Adb._target_device == NEW
