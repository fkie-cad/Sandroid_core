"""The device-prepared step (``core/device_prep.py``) against a fake device.

Nothing runs adb: ``Adb.send_adb_command`` answers from :class:`FakeDevice`,
the settle step is a gate the test controls, and the device clock / timeline
calls only append to the shared event list, so the order of the steps can
be asserted exactly.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from types import SimpleNamespace

import pytest

from sandroid.core import device_clock, device_prep
from sandroid.core import timeline as timeline_mod
from sandroid.core.adb import Adb
from sandroid.core.device import Device
from sandroid.core.device_manager import DeviceManager
from sandroid.services import setup_checks

SERIAL = "emulator-5554"
BOOT_A = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
BOOT_B = "11111111-2222-3333-4444-555555555555"


class FakeDevice:
    """One device as adb sees it; every interesting step appends an event."""

    def __init__(self) -> None:
        self.boot_id = BOOT_A
        self.firstboot = "1763470000123"
        self.uptime = 100.0
        self.transport = 1
        self.state = "device"
        self.listed = True
        self.selinux = "Enforcing"
        self.adbd_root = False
        self.root_refused = False  # a user build: adbd cannot run as root
        self.events: list = []
        self.calls: list[str] = []
        self.settle_gate = threading.Event()
        self.settle_gate.set()

    def settle(self, cancel) -> bool:
        while not self.settle_gate.wait(0.02):
            if cancel():
                return False
        return not cancel()

    def send(self, command: str) -> tuple[str, str]:
        self.calls.append(command)
        if command == "devices -l":
            row = (
                f"{SERIAL}  {self.state} product:sdk model:Pixel "
                f"transport_id:{self.transport}\n"
                if self.listed
                else ""
            )
            return "List of devices attached\n" + row, ""
        if command == device_prep.BOOT_INFO_COMMAND:
            lines = [self.boot_id or "", self.firstboot, f"{self.uptime} 50.00"]
            return "\n".join(lines) + "\n", ""
        if command == "root" and self.root_refused:
            return "", "adbd cannot run as root in production builds"
        if command == "root":
            self.events.append("root")
            if self.adbd_root:
                return "adbd is already running as root\n", ""
            self.adbd_root = True
            self.transport += 1  # adbd restarts: a new adb transport
            return "restarting adbd as root\n", ""
        if command == "shell id":
            return ("uid=0(root)\n" if self.adbd_root else "uid=2000(shell)\n"), ""
        if command == "shell getenforce":
            return self.selinux + "\n", ""
        if command in ("shell setenforce 0", "shell su 0 setenforce 0"):
            self.events.append("setenforce")
            self.selinux = "Permissive"
            return "", ""
        return "", ""


@pytest.fixture
def rig(monkeypatch):
    device_prep.reset(hooks=True)
    fake = FakeDevice()
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        classmethod(lambda cls, c, serial=None, timeout=30: fake.send(c)),
    )
    monkeypatch.setattr(Adb, "_target_device", SERIAL)
    monkeypatch.setattr(
        device_prep, "_settle", lambda serial, cancel: fake.settle(cancel)
    )
    monkeypatch.setattr(device_prep, "REATTACH_MIN_INTERVAL_S", 0.0)
    monkeypatch.setattr(
        device_clock,
        "after_device_connect",
        lambda serial=None, send=None: fake.events.append("connect"),
    )
    monkeypatch.setattr(
        device_clock,
        "after_selinux_step",
        lambda serial=None, wait=None: fake.events.append(("clock-sync", wait)),
    )
    monkeypatch.setattr(
        device_clock,
        "after_device_connect_async",
        lambda serial=None: fake.events.append("connect-async"),
    )
    timeline = SimpleNamespace(
        on_world_change=lambda cause, **kw: fake.events.append(
            ("world", cause, kw.get("dev"), kw.get("src"), kw.get("kind"))
        )
    )
    monkeypatch.setattr(timeline_mod, "get_timeline", lambda: timeline)
    monkeypatch.setattr(setup_checks.time, "sleep", lambda s: None)

    manager = DeviceManager()
    device = Device(
        serial=SERIAL, state="device", root_kind="adb root", transport_id="1"
    )
    manager._devices = {SERIAL: device}
    manager._active_device = device
    monkeypatch.setattr(DeviceManager, "_instance", manager)
    results: list = []

    def listener(dev, result) -> None:
        results.append(result)
        fake.events.append(("listener", result.kind))

    manager.on_device_prepared(listener)
    device_prep.set_enabled(True)
    yield SimpleNamespace(fake=fake, manager=manager, device=device, results=results)
    device_prep.reset(hooks=True)


def _hook(fake: FakeDevice, name: str = "hook"):
    def hook(serial: str, fresh_boot: bool) -> None:
        fake.events.append((name, serial, fresh_boot))

    return hook


def _run(reason: str = "attach") -> None:
    assert device_prep.request_prepare(SERIAL, reason)
    assert device_prep.wait_prepared(SERIAL, 5)


def _since(events: list, start: int) -> list:
    return events[start:]


# ------------------------------------------------------------------- order


def test_first_attach_runs_every_step_in_order(rig):
    device_prep.register_device_prepared_hook(_hook(rig.fake))
    _run()
    assert rig.fake.events == [
        "connect",
        "root",
        "setenforce",
        ("clock-sync", device_prep.CLOCK_SYNC_WAIT_S),
        ("hook", SERIAL, True),
        ("listener", "first"),
    ]
    (result,) = rig.results
    assert result.fresh_boot is True
    assert result.root == "ok"
    assert result.selinux_mode == "Permissive"
    assert result.boot_token == BOOT_A
    # The record is taken after adb root (its adbd restart = transport 2).
    assert device_prep.prepared_transport(SERIAL) == "2"
    assert "Prepared emulator-5554 (attach): root ✓ SELinux Permissive ✓" in (
        result.summary()
    )


def test_a_new_boot_id_is_a_new_world_before_the_clock_step(rig):
    device_prep.register_device_prepared_hook(_hook(rig.fake))
    _run()
    start = len(rig.fake.events)
    rig.fake.boot_id = BOOT_B
    rig.fake.adbd_root = False
    rig.fake.selinux = "Enforcing"
    _run("transport")
    assert _since(rig.fake.events, start) == [
        ("world", "reboot", SERIAL, "device", "boot"),
        "connect",
        "root",
        "setenforce",
        ("clock-sync", device_prep.CLOCK_SYNC_WAIT_S),
        ("hook", SERIAL, True),
        ("listener", "new-world"),
    ]


def test_an_uptime_rewind_is_a_new_world(rig):
    _run()
    rig.fake.uptime = 40.0  # same boot_id: a quickboot from an older state
    rig.fake.transport += 5
    _run("transport")
    assert rig.results[-1].kind == "new-world"
    assert ("world", "reboot", SERIAL, "device", "boot") in rig.fake.events


def test_a_new_transport_in_the_same_boot_is_a_reattach(rig):
    device_prep.register_device_prepared_hook(_hook(rig.fake))
    _run()
    start = len(rig.fake.events)
    rig.fake.transport += 1  # adb reconnect / server restart
    rig.fake.uptime += 30
    _run("transport")
    events = _since(rig.fake.events, start)
    assert ("hook", SERIAL, False) in events
    assert not any(e[0] == "world" for e in events if isinstance(e, tuple))
    assert rig.results[-1].kind == "reattach"
    assert rig.results[-1].fresh_boot is False


def test_reattach_runs_are_rate_limited(rig, monkeypatch):
    monkeypatch.setattr(device_prep, "REATTACH_MIN_INTERVAL_S", 0.3)
    _run()
    rig.fake.transport += 1
    _run("transport")
    t0 = time.monotonic()
    rig.fake.transport += 1
    _run("transport")
    assert rig.results[-1].kind == "reattach"
    assert time.monotonic() - t0 >= 0.25


def test_same_boot_and_transport_is_unchanged(rig):
    device_prep.register_device_prepared_hook(_hook(rig.fake))
    _run()
    start = len(rig.fake.events)
    _run("attach")
    assert _since(rig.fake.events, start) == [("listener", "unchanged")]
    assert rig.results[-1].root_check is rig.results[0].root_check


def test_boot_info_falls_back_to_firstboot():
    adb = SimpleNamespace(
        send_adb_command=lambda c, serial=None: ("\n1763470000123\n12.5 3.0\n", "")
    )
    original = device_prep._adb
    device_prep._adb = lambda: adb
    try:
        assert device_prep._read_boot_info(SERIAL) == ("fb:1763470000123", 12.5)
    finally:
        device_prep._adb = original


def test_an_unknown_boot_is_fresh_without_a_world_change(rig):
    rig.fake.boot_id = ""
    rig.fake.firstboot = ""
    _run()
    rig.fake.transport += 3
    _run("transport")
    assert [r.kind for r in rig.results] == ["first", "first"]
    assert all(r.fresh_boot for r in rig.results)
    assert not any(isinstance(e, tuple) and e[0] == "world" for e in rig.fake.events)


# -------------------------------------------------------------- coalescing


def test_our_own_adb_root_never_loops(rig):
    """The run's adbd restart makes the poll ask again; that is absorbed."""

    def hook(serial: str, fresh_boot: bool) -> None:
        # What refresh_devices does when it sees the new transport mid-run.
        assert device_prep.request_prepare(SERIAL, "transport")

    device_prep.register_device_prepared_hook(hook)
    _run()
    assert rig.fake.events.count("root") == 1
    assert [r.kind for r in rig.results] == ["first"]


def test_a_real_reset_after_the_run_causes_exactly_one_more_run(rig):
    def listener(dev, result) -> None:
        if result.kind == "first":
            rig.fake.transport += 1  # a real reset after the record
            device_prep.request_prepare(SERIAL, "transport")

    rig.manager.on_device_prepared(listener)
    _run()
    assert [r.kind for r in rig.results] == ["first", "reattach"]
    assert not device_prep.is_preparing(SERIAL)


def test_request_prepare_never_blocks(rig):
    rig.fake.settle_gate.clear()
    t0 = time.monotonic()
    assert device_prep.request_prepare(SERIAL, "attach")
    assert time.monotonic() - t0 < 0.5
    assert device_prep.is_preparing(SERIAL)
    deadline = time.monotonic() + 5
    while device_prep.preparing_stage() != (SERIAL, "waiting for the device"):
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert device_prep.wait_prepared(SERIAL, 0.05) is False
    rig.fake.settle_gate.set()
    assert device_prep.wait_prepared(SERIAL, 5)


def test_ensure_prepared_joins_a_run_in_flight(rig):
    rig.fake.settle_gate.clear()
    device_prep.request_prepare(SERIAL, "attach")
    stages: list[str] = []
    box: list = []
    thread = threading.Thread(
        target=lambda: box.append(
            device_prep.ensure_prepared(SERIAL, 5, on_progress=stages.append)
        )
    )
    thread.start()
    time.sleep(0.05)
    rig.fake.settle_gate.set()
    thread.join(5)
    (result,) = box
    assert result.kind == "first"
    assert rig.fake.events.count("root") == 1
    assert "root" in stages
    assert "hooks" in stages


# ------------------------------------------------------------------- abort


def test_losing_the_device_mid_run_aborts_without_hooks(rig):
    device_prep.register_device_prepared_hook(_hook(rig.fake))
    rig.fake.settle_gate.clear()
    device_prep.request_prepare(SERIAL, "attach")
    device_prep.note_detached(SERIAL)
    rig.fake.settle_gate.set()
    assert device_prep.wait_prepared(SERIAL, 5)
    assert device_prep.last_result(SERIAL).kind == "aborted"
    assert rig.fake.events == []  # no clock, root, hooks or listeners
    assert device_prep.prepared_transport(SERIAL) is None


def test_switching_away_mid_run_aborts(rig):
    rig.fake.settle_gate.clear()
    device_prep.request_prepare(SERIAL, "attach")
    rig.manager._active_device = Device(serial="emulator-5556", state="device")
    rig.fake.settle_gate.set()
    assert device_prep.wait_prepared(SERIAL, 5)
    assert device_prep.last_result(SERIAL).kind == "aborted"
    assert "root" not in rig.fake.events


def test_a_non_active_serial_is_never_prepared(rig):
    assert device_prep.request_prepare("emulator-5556", "attach") is False
    assert not device_prep.is_preparing()
    assert device_prep.ensure_prepared("emulator-5556", 1).kind == "ignored"


def test_the_step_is_a_no_op_while_disabled(rig):
    device_prep.set_enabled(False)
    assert device_prep.request_prepare(SERIAL, "attach") is False
    assert device_prep.ensure_prepared(SERIAL, 1).kind == "disabled"
    assert rig.fake.calls == []


def test_ensure_prepared_is_refused_on_the_ui_thread(rig):
    async def on_the_loop():
        return device_prep.ensure_prepared(SERIAL, 1)

    assert asyncio.run(on_the_loop()).kind == "refused"
    assert rig.fake.calls == []


# ------------------------------------------------------------------- root


def test_a_device_without_root_is_warned_about_once(rig, caplog):
    rig.device.root_kind = "none"
    device_prep.register_device_prepared_hook(_hook(rig.fake))
    with caplog.at_level(logging.WARNING, logger="sandroid.core.device_prep"):
        _run()
        rig.fake.boot_id = BOOT_B
        _run("transport")
    assert sum("has no root" in r.getMessage() for r in caplog.records) == 1
    assert "root" not in rig.fake.events
    assert rig.fake.events.count(("hook", SERIAL, True)) == 2
    assert rig.results[-1].root == "none"


def test_su_devices_skip_adb_root(rig):
    rig.device.root_kind = "su"
    _run()
    assert "root" not in rig.fake.calls
    assert "setenforce" in rig.fake.events
    assert rig.results[-1].root == "su"
    assert rig.results[-1].root_check is None


# ------------------------------------------------------------------- hooks


def test_hook_errors_and_timeouts_are_isolated(rig, monkeypatch):
    monkeypatch.setattr(device_prep, "HOOK_TIMEOUT_S", 0.1)
    release = threading.Event()

    def boom(serial, fresh_boot):
        raise RuntimeError("proxy restore failed")

    def exits(serial, fresh_boot):
        raise SystemExit(3)

    def slow(serial, fresh_boot):
        release.wait(5)

    for hook in (boom, exits, slow, _hook(rig.fake, "last")):
        device_prep.register_device_prepared_hook(hook)
    _run()
    release.set()
    result = rig.results[-1]
    assert result.hooks_total == 4
    assert len(result.hook_errors) == 3
    assert "proxy restore failed" in result.hook_errors[0]
    assert "still running" in result.hook_errors[2]
    assert ("last", SERIAL, True) in rig.fake.events
    assert result.has_problems


def test_hooks_run_with_the_adb_target_pinned(rig, monkeypatch):
    monkeypatch.setattr(Adb, "_target_device", "emulator-5556")
    seen: list = []
    device_prep.register_device_prepared_hook(
        lambda serial, fresh: seen.append(Adb.get_target_device())
    )
    _run()
    assert seen == [SERIAL]


def test_register_and_unregister_are_idempotent(rig):
    hook = _hook(rig.fake)
    device_prep.register_device_prepared_hook(hook)
    device_prep.register_device_prepared_hook(hook)
    _run()
    assert rig.fake.events.count(("hook", SERIAL, True)) == 1
    assert device_prep.unregister_device_prepared_hook(hook) is True
    assert device_prep.unregister_device_prepared_hook(hook) is False


def test_the_device_manager_re_exports_the_hook_api():
    from sandroid.core import device_manager

    assert (
        device_manager.register_device_prepared_hook
        is device_prep.register_device_prepared_hook
    )
    assert (
        device_manager.unregister_device_prepared_hook
        is device_prep.unregister_device_prepared_hook
    )


def test_a_hook_that_waits_for_the_step_does_not_deadlock(rig):
    waited: list = []

    def hook(serial, fresh_boot):
        t0 = time.monotonic()
        waited.append(device_prep.wait_prepared(serial, 3))
        waited.append(time.monotonic() - t0)

    device_prep.register_device_prepared_hook(hook)
    _run()
    assert waited[0] is True
    assert waited[1] < 0.5


def test_the_registry_survives_a_device_manager_reset(rig, monkeypatch):
    hook = _hook(rig.fake)
    device_prep.register_device_prepared_hook(hook)
    DeviceManager.reset()
    monkeypatch.setattr(DeviceManager, "_instance", rig.manager)
    _run()
    assert ("hook", SERIAL, True) in rig.fake.events


# -------------------------------------------------------------------- hold


def test_a_snapshot_load_and_its_re_attach_do_not_prepare_again(rig):
    """Owner requirement: a snapshot load (restored boot_id + uptime) and
    the poll's re-attach afterwards run no second preparation or hooks.
    """
    device_prep.register_device_prepared_hook(_hook(rig.fake))
    _run()
    start = len(rig.fake.events)
    with device_prep.hold(SERIAL):
        # The snapshot restores the boot it was saved in and a fresh
        # transport; the re-attach during the load is dropped.
        rig.fake.boot_id = BOOT_B
        rig.fake.uptime = 20.0
        rig.fake.transport += 1
        assert device_prep.request_prepare(SERIAL, "attach") is True
        assert not device_prep.is_preparing(SERIAL)
    _run("attach")  # the poll's re-attach after the load
    events = _since(rig.fake.events, start)
    assert events == [("listener", "held"), ("listener", "unchanged")]
    assert rig.fake.events.count("root") == 1


def test_a_hold_aborts_a_run_in_flight(rig):
    device_prep.register_device_prepared_hook(_hook(rig.fake))
    rig.fake.settle_gate.clear()
    device_prep.request_prepare(SERIAL, "attach")
    with device_prep.hold(SERIAL):
        rig.fake.settle_gate.set()
        assert device_prep.wait_prepared(SERIAL, 5)
    assert device_prep.last_result(SERIAL).kind == "aborted"
    assert rig.fake.events == []


def test_hold_is_a_no_op_while_disabled(rig):
    device_prep.set_enabled(False)
    with device_prep.hold(SERIAL):
        pass
    assert rig.fake.calls == []


# ---------------------------------------------------------- device manager


def test_set_active_device_requests_the_step(rig, monkeypatch):
    from sandroid.core.toolbox import Toolbox

    monkeypatch.setattr(Toolbox, "update_frida_device_serial", lambda s: None)
    monkeypatch.setattr(Toolbox, "switch_device_folder", staticmethod(lambda n: None))
    monkeypatch.setattr(rig.manager, "_sync_session_device_name", lambda d: None)
    monkeypatch.setattr(
        timeline_mod.get_timeline(), "bind", lambda *a, **k: None, raising=False
    )
    requests: list = []
    monkeypatch.setattr(
        device_prep,
        "request_prepare",
        lambda serial, reason, manager=None: requests.append((serial, reason)) or True,
    )
    rig.manager._active_device = None
    assert rig.manager.set_active_device(SERIAL)
    assert requests == [(SERIAL, "attach")]
    assert "connect-async" not in rig.fake.events


def test_set_active_device_only_samples_the_clock_while_disabled(rig, monkeypatch):
    from sandroid.core.toolbox import Toolbox

    device_prep.set_enabled(False)
    monkeypatch.setattr(Toolbox, "update_frida_device_serial", lambda s: None)
    monkeypatch.setattr(Toolbox, "switch_device_folder", staticmethod(lambda n: None))
    monkeypatch.setattr(rig.manager, "_sync_session_device_name", lambda d: None)
    monkeypatch.setattr(
        timeline_mod.get_timeline(), "bind", lambda *a, **k: None, raising=False
    )
    rig.manager._active_device = None
    assert rig.manager.set_active_device(SERIAL)
    assert rig.fake.events == ["connect-async"]
    # A first run afterwards (startup turns the step on) does not sample
    # the device-connect clock again.
    device_prep.set_enabled(True)
    _run("ensure")
    assert "connect" not in rig.fake.events


@pytest.fixture
def requests(rig, monkeypatch):
    seen: list = []
    monkeypatch.setattr(
        device_prep,
        "request_prepare",
        lambda serial, reason, manager=None: seen.append((serial, reason)) or True,
    )
    return seen


def test_refresh_requests_on_offline_to_device(rig, requests):
    rig.fake.state = "offline"
    rig.manager.refresh_devices()
    assert requests == []
    rig.fake.state = "device"
    rig.manager.refresh_devices()
    assert requests == [(SERIAL, "transport")]


def test_refresh_requests_on_a_new_transport_id(rig, requests):
    state = device_prep._state(SERIAL)
    state.record = device_prep._Record(BOOT_A, 100.0, "1")
    rig.manager.refresh_devices()
    assert requests == []  # transport 1 == prepared
    rig.fake.transport = 7
    rig.manager.refresh_devices()
    assert requests == [(SERIAL, "transport")]
    assert rig.device.transport_id == "7"


def test_refresh_requests_after_a_failed_enumeration(rig, requests, monkeypatch):
    original = rig.fake.send
    monkeypatch.setattr(
        rig.fake,
        "send",
        lambda c: ("", "error: protocol fault") if c == "devices -l" else original(c),
    )
    rig.manager.refresh_devices()
    assert requests == []
    monkeypatch.setattr(rig.fake, "send", original)
    rig.manager.refresh_devices()
    assert requests == [(SERIAL, "transport")]
    rig.manager.refresh_devices()
    assert requests == [(SERIAL, "transport")]  # once


def test_a_preparing_device_is_not_lost_within_the_grace(rig, monkeypatch):
    changes: list = []
    rig.manager.on_device_change(changes.append)
    rig.fake.settle_gate.clear()
    device_prep.request_prepare(SERIAL, "attach")
    rig.fake.listed = False  # adb root: adbd restarts
    rig.manager.refresh_devices()
    assert rig.manager.active_device is rig.device
    assert changes == []
    monkeypatch.setattr(device_prep, "LOSS_GRACE_S", 0.0)
    rig.manager.refresh_devices()
    assert rig.manager.active_device is None
    assert changes == [None]
    rig.fake.settle_gate.set()
    assert device_prep.wait_prepared(SERIAL, 5)
    assert device_prep.last_result(SERIAL).kind == "aborted"


def test_note_adb_server_restart_forgets_transports_and_reattaches(rig):
    _run()
    device_prep.note_adb_server_restart()
    assert device_prep.wait_prepared(SERIAL, 5)
    assert rig.results[-1].kind == "reattach"
    assert rig.results[-1].reason == "adb-server"


# ------------------------------------------------------- startup / headless


def test_check_critical_setup_joins_the_run_in_flight(rig):
    from sandroid.services.setup_service import SetupService

    device_prep.set_enabled(False)  # startup turns it on itself
    rig.fake.settle_gate.clear()
    box: list = []
    thread = threading.Thread(
        target=lambda: box.append(SetupService().check_critical_setup())
    )
    thread.start()
    deadline = time.monotonic() + 5
    while not device_prep.is_preparing(SERIAL):
        assert time.monotonic() < deadline
        time.sleep(0.01)
    # Meanwhile a re-attach asks again: coalesced into the same run.
    assert device_prep.request_prepare(SERIAL, "attach")
    rig.fake.settle_gate.set()
    thread.join(10)
    (result,) = box
    assert result.success
    assert rig.fake.calls.count("root") == 1
    assert result.get_check("root").passed
    assert result.get_check("selinux").details["mode"] == "Permissive"
    assert result.selinux_permissive is True
    assert device_prep.is_enabled()


def test_check_critical_setup_keeps_failing_without_adb_root(rig):
    """A su device: the step skips ``adb root``, startup still reports the
    root stage as before (follow-up: accept su at startup).
    """
    from sandroid.services.setup_service import SetupService

    rig.device.root_kind = "su"
    rig.fake.root_refused = True
    result = SetupService().check_critical_setup()
    assert not result.success
    assert result.message == "Device does not support adb root"
    assert "setenforce" in rig.fake.events  # the step still ran SELinux
    assert rig.fake.calls.count("root") == 1  # only the startup check's


def test_initialize_core_prepare_runs_the_hooks_before_toolbox_init(rig, monkeypatch):
    from sandroid.core import initializer
    from sandroid.core.toolbox import Toolbox

    device_prep.set_enabled(False)
    order: list = []
    monkeypatch.setattr(Adb, "init", classmethod(lambda cls: None))
    monkeypatch.setattr(Toolbox, "init", classmethod(lambda cls: order.append("tb")))
    monkeypatch.setattr(Toolbox, "config", None, raising=False)
    # What set_active_device does when the selection picks the device.
    monkeypatch.setattr(
        initializer,
        "apply_serial_selection",
        lambda serial: order.append(
            ("selected", device_prep.request_prepare(SERIAL, "attach"))
        ),
    )
    monkeypatch.setattr(initializer, "require_device", lambda: None)
    monkeypatch.setattr(initializer, "refuse_ambiguous_device", lambda: None)
    device_prep.register_device_prepared_hook(lambda s, f: order.append("hook"))
    printed: list = []
    monkeypatch.setattr(
        "sandroid.core.console.SandroidConsole.get",
        classmethod(lambda cls: SimpleNamespace(print=printed.append)),
    )
    initializer.initialize_core(SimpleNamespace(), prepare=True)
    assert order == [("selected", True), "hook", "tb"]
    assert rig.fake.calls.count("root") == 1
    assert any("SELinux permissive" in p for p in printed)


# ------------------------------------------------------- emulator service


def _service(fake: FakeDevice, monkeypatch):
    from sandroid.services.emulator_service import EmulatorService

    service = EmulatorService()
    adb = SimpleNamespace(
        send_telnet_command=lambda command, serial=None: ("OK\n", ""),
        send_adb_command=lambda command, serial=None: (
            ("device\n", "") if command == "get-state" else fake.send(command)
        ),
        get_target_device=lambda: SERIAL,
    )
    service._get_adb = lambda: adb
    monkeypatch.setattr(service, "_restore_device_proxy", lambda serial: "skipped")
    monkeypatch.setattr(
        service, "_restore_selinux_permissive", lambda adb, serial: True
    )
    monkeypatch.setattr(service, "_record_device_clock", lambda *a: None)
    return service


def test_load_snapshot_then_the_poll_re_attach_prepare_nothing(rig, monkeypatch):
    """Owner requirement: a snapshot load (another boot_id / uptime in RAM,
    a new transport) and the device poll's re-attach run no second
    preparation and no device_prepared hooks.
    """
    from sandroid.services import emulator_service

    device_prep.register_device_prepared_hook(_hook(rig.fake))
    _run()
    start = len(rig.fake.events)
    service = _service(rig.fake, monkeypatch)
    worlds: list = []
    monkeypatch.setattr(
        emulator_service, "_world_change", lambda cause, **kw: worlds.append(cause)
    )

    def wait_ready(adb, serial, timeout=10.0, interval=0.4):
        # The VM state is replaced while the load runs; the poll sees the
        # device drop out and come back and re-attaches it.
        rig.fake.boot_id = BOOT_B
        rig.fake.uptime = 12.0
        rig.fake.transport += 1
        assert device_prep.request_prepare(SERIAL, "attach")  # dropped
        return True

    monkeypatch.setattr(service, "_wait_for_device_ready", wait_ready)
    assert service.load_snapshot("clean", serial=SERIAL) is True
    rig.manager.refresh_devices()  # the poll after the load: same transport
    _run("attach")  # and a later re-attach of the same device
    assert worlds == ["snapshot-load"]
    assert _since(rig.fake.events, start) == [
        ("listener", "held"),
        ("listener", "unchanged"),
    ]
    assert rig.fake.events.count("root") == 1


def test_restart_waits_for_the_step_with_a_single_world_change(rig, monkeypatch):
    import sandroid.core.emulator as emulator_mod
    from sandroid.services import emulator_service

    device_prep.register_device_prepared_hook(_hook(rig.fake))
    _run()
    start = len(rig.fake.events)
    service = _service(rig.fake, monkeypatch)
    worlds: list = []
    monkeypatch.setattr(
        emulator_service, "_world_change", lambda cause, **kw: worlds.append(cause)
    )
    monkeypatch.setattr(emulator_mod, "emulator_binary", lambda: "/bin/emulator")

    def restart_emulator(serial, adb=None):
        rig.fake.boot_id = BOOT_B
        rig.fake.uptime = 15.0
        rig.fake.transport += 1
        rig.fake.adbd_root = False
        rig.fake.selinux = "Enforcing"
        return SimpleNamespace(avd="Pixel", log_path=None)

    monkeypatch.setattr(emulator_mod, "restart_emulator", restart_emulator)
    monkeypatch.setattr(emulator_mod, "wait_until_ready", lambda *a, **kw: True)
    assert service.restart(boot_timeout=1) is True
    # Returned only after the step: the hooks already ran.
    events = _since(rig.fake.events, start)
    assert ("hook", SERIAL, True) in events
    assert [e for e in events if isinstance(e, tuple) and e[0] == "world"] == [
        ("world", "reboot", SERIAL, "device", "boot")
    ]
    assert worlds == []  # no "cold-boot" line of its own
    assert not device_prep.is_preparing(SERIAL)


def test_restart_records_the_cold_boot_itself_while_the_step_is_off(rig, monkeypatch):
    import sandroid.core.emulator as emulator_mod
    from sandroid.services import emulator_service

    device_prep.set_enabled(False)
    service = _service(rig.fake, monkeypatch)
    worlds: list = []
    monkeypatch.setattr(
        emulator_service, "_world_change", lambda cause, **kw: worlds.append(cause)
    )
    monkeypatch.setattr(emulator_mod, "emulator_binary", lambda: "/bin/emulator")
    monkeypatch.setattr(
        emulator_mod,
        "restart_emulator",
        lambda serial, adb=None: SimpleNamespace(avd="Pixel", log_path=None),
    )
    monkeypatch.setattr(emulator_mod, "wait_until_ready", lambda *a, **kw: True)
    assert service.restart(boot_timeout=1) is True
    assert worlds == ["cold-boot"]
