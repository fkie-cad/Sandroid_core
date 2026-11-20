"""Devices screen: pure model, collector pin rule, screen keys, app wiring.

No real adb/emulator: the screen gets a fake ``collect`` and fake actions,
``DevicesScreen.monitor_factory`` is ``None`` (the adb track-devices socket
is blocked under the test guard anyway), and the collector talks to an adb
double.
"""

from __future__ import annotations

import dataclasses
import threading
from types import SimpleNamespace

import pytest
from pilot_helpers import boot, settle, until
from textual.app import App

from sandroid.core import emulator
from sandroid.core.device import AdbDeviceEntry, parse_adb_devices
from sandroid.core.emulator import AvdInfo, AvdLaunchOptions
from sandroid.tui.screens import devices_screen as hub
from sandroid.tui.screens.devices_screen import (
    UNAUTHORIZED_HELP,
    AvdRow,
    DeviceRow,
    DevicesScreen,
    HubSnapshot,
    RowState,
    SerialProbe,
    build_snapshot,
    classify,
    describe_options,
    format_elapsed,
)

SIZE = (140, 40)


@pytest.fixture(autouse=True)
def _no_monitor(monkeypatch):
    monkeypatch.setattr(DevicesScreen, "monitor_factory", None)


class _Launch:
    def __init__(
        self, avd, serial, started_at=0.0, ready=False, alive=True, log_path=None
    ):
        self.avd = avd
        self.serial = serial
        self.started_at = started_at
        self.ready = ready
        self.alive = alive
        self.log_path = log_path
        self.options = AvdLaunchOptions()
        self.cancel = threading.Event()


def _entries(text: str) -> list[AdbDeviceEntry]:
    return parse_adb_devices("List of devices attached\n" + text)


# --------------------------------------------------------------------------
# pure model
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "probe", "booting", "expected"),
    [
        ("device", None, False, RowState.READY),
        ("device", SerialProbe(booted=True), False, RowState.READY),
        ("device", SerialProbe(booted=False), False, RowState.BOOTING),
        # A probe that saw the boot complete wins over our launch record.
        ("device", SerialProbe(booted=True), True, RowState.READY),
        ("device", None, True, RowState.BOOTING),
        ("offline", None, True, RowState.BOOTING),
        ("offline", None, False, RowState.OFFLINE),
        ("unauthorized", None, False, RowState.UNAUTHORIZED),
        ("authorizing", None, False, RowState.UNAUTHORIZED),
        ("no permissions", None, False, RowState.NO_PERMISSIONS),
        ("recovery", None, False, RowState.OTHER),
    ],
)
def test_classify(raw, probe, booting, expected) -> None:
    assert classify(raw, probe, booting) is expected


def test_build_snapshot_classifies_and_marks_active() -> None:
    entries = _entries(
        "emulator-5554\tdevice product:sdk model:Pixel_7 device:x\n"
        "emulator-5556\tdevice\n"
        "R58M\tunauthorized usb:1-1\n"
        "ZX1\tno permissions (missing udev rules?); see [http://x]\n"
    )
    probes = {
        "emulator-5554": SerialProbe(booted=True, api=35),
        "emulator-5556": SerialProbe(booted=False, api=34),
    }
    snap = build_snapshot(
        entries,
        probes,
        {"emulator-5554": "Pixel_7_API_35"},
        [],
        {},
        [],
        "emulator-5554",
        100.0,
    )
    rows = {row.serial: row for row in snap.devices}
    assert rows["emulator-5554"].state is RowState.READY
    assert rows["emulator-5554"].active
    assert rows["emulator-5554"].avd_name == "Pixel_7_API_35"
    assert rows["emulator-5554"].model == "Pixel_7"
    assert rows["emulator-5554"].api == 35
    assert rows["emulator-5554"].is_emulator
    assert rows["emulator-5556"].state is RowState.BOOTING
    assert not rows["emulator-5556"].active
    assert rows["R58M"].state is RowState.UNAUTHORIZED
    assert not rows["R58M"].is_emulator
    assert rows["ZX1"].state is RowState.NO_PERMISSIONS
    assert [r.serial for r in snap.devices] == sorted(rows)


def test_our_launch_not_listed_yet_is_booting_with_elapsed() -> None:
    launch = _Launch("Pixel_7", "emulator-5560", started_at=58.0)
    snap = build_snapshot([], {}, {}, [], {}, [launch], None, 100.0)
    (row,) = snap.devices
    assert row.state is RowState.BOOTING
    assert row.raw_state == "starting"
    assert row.ours
    assert row.is_emulator
    assert row.boot_elapsed == pytest.approx(42.0)
    assert row.avd_name == "Pixel_7"
    assert snap.booting


def test_our_listed_launch_stays_booting_until_ready() -> None:
    entries = _entries("emulator-5560\toffline\n")
    launch = _Launch("Pixel_7", "emulator-5560", started_at=90.0)
    snap = build_snapshot(entries, {}, {}, [], {}, [launch], None, 100.0)
    assert snap.devices[0].state is RowState.BOOTING
    assert snap.devices[0].launch_options is launch.options
    ready = _Launch("Pixel_7", "emulator-5560", ready=True)
    entries = _entries("emulator-5560\tdevice\n")
    snap = build_snapshot(entries, {}, {}, [], {}, [ready], None, 100.0)
    assert snap.devices[0].state is RowState.READY


def test_dead_launch_becomes_a_note_with_its_log() -> None:
    launch = _Launch(
        "Broken", "emulator-5562", started_at=95.0, alive=False, log_path="/l.log"
    )
    snap = build_snapshot([], {}, {}, [], {}, [launch], None, 100.0)
    assert snap.devices == ()
    assert len(snap.notes) == 1
    assert "Broken" in snap.notes[0]
    assert "/l.log" in snap.notes[0]


def test_running_avds_are_not_available_and_options_are_remembered() -> None:
    entries = _entries("emulator-5554\tdevice\n")
    avds = [
        AvdInfo(name="Running_AVD", api_level=35),
        AvdInfo(
            name="Idle_AVD",
            api_level=34,
            tag="google_apis",
            snapshot_count=2,
            snapshots=("default_boot", "s1"),
        ),
        AvdInfo(name="Other_AVD"),
    ]
    prefs = {
        "last_avd": "Idle_AVD",
        "avds": {"Idle_AVD": {"headless": True, "boot": "cold", "snapshot": None}},
    }
    snap = build_snapshot(
        entries, {}, {"emulator-5554": "Running_AVD"}, avds, prefs, [], None, 0.0
    )
    assert [a.name for a in snap.avds] == ["Idle_AVD", "Other_AVD"]
    assert [r.key for r in snap.rows] == [
        "dev:emulator-5554",
        "avd:Idle_AVD",
        "avd:Other_AVD",
    ]
    # Not launched by us: no start options; its AVD's saved ones for R.
    assert snap.devices[0].launch_options is None
    assert snap.devices[0].saved_options == AvdLaunchOptions()
    idle = snap.avds[0]
    assert idle.last_used
    assert idle.options == AvdLaunchOptions(headless=True, boot="cold")
    assert idle.snapshot_count == 2
    assert idle.snapshots == ("default_boot", "s1")
    assert idle.tag == "google_apis"
    assert not snap.avds[1].last_used


def test_locked_avds_are_listed_last_as_running_elsewhere() -> None:
    avds = [AvdInfo(name="Busy_AVD"), AvdInfo(name="Idle_AVD")]
    snap = build_snapshot([], {}, {}, avds, {}, [], None, 0.0, locked_avds={"Busy_AVD"})
    assert [(a.name, a.running_elsewhere) for a in snap.avds] == [
        ("Idle_AVD", False),
        ("Busy_AVD", True),
    ]


def test_unprobed_foreign_devices_are_in_use_not_ready() -> None:
    """Under a pin, someone else's online device is never shown green/ready;
    its AVD stays listed as running elsewhere (lock-based).
    """
    entries = _entries(
        "emulator-5554\tdevice model:sdk_gphone64\n"
        "emulator-5556\toffline\n"
        "emulator-5562\tdevice\n"
    )
    snap = build_snapshot(
        entries,
        {"emulator-5562": SerialProbe(booted=True, api=35)},
        {"emulator-5562": "Mine"},
        [AvdInfo(name="Theirs"), AvdInfo(name="Idle")],
        {},
        [],
        "emulator-5562",
        0.0,
        locked_avds={"Theirs", "Mine"},
        unprobed={"emulator-5554", "emulator-5556"},
        ports={"Idle": (5564, "last used")},
    )
    rows = {row.serial: row for row in snap.devices}
    assert rows["emulator-5554"].state is RowState.UNPROBED
    assert rows["emulator-5554"].state.value == "in use · not probed"
    assert rows["emulator-5556"].state is RowState.OFFLINE  # adb's own word
    assert rows["emulator-5562"].state is RowState.READY
    assert [
        (a.name, a.running_elsewhere, a.port, a.port_reason) for a in snap.avds
    ] == [
        ("Idle", False, 5564, "last used"),
        ("Theirs", True, None, ""),
    ]
    assert hub._STATE_STYLE[RowState.UNPROBED] != hub._STATE_STYLE[RowState.READY]


def test_a_booted_probe_ends_booting_even_if_the_waiter_gave_up() -> None:
    entries = _entries("emulator-5560\tdevice\n")
    launch = _Launch("Pixel_7", "emulator-5560", started_at=0.0)  # not ready
    snap = build_snapshot(
        entries,
        {"emulator-5560": SerialProbe(booted=True)},
        {},
        [],
        {},
        [launch],
        None,
        300.0,  # past the waiter's 240 s
    )
    (row,) = snap.devices
    assert row.state is RowState.READY
    assert row.boot_elapsed is None
    assert not snap.booting


def test_formatting_helpers() -> None:
    assert format_elapsed(None) == ""
    assert format_elapsed(42.7) == "0:42"
    assert format_elapsed(3725) == "1:02:05"
    assert describe_options(AvdLaunchOptions()) == "window · quick boot"
    assert (
        describe_options(
            AvdLaunchOptions(headless=True, boot="snapshot", snapshot="s1")
        )
        == "headless · snapshot s1"
    )
    assert describe_options(
        AvdLaunchOptions(boot="cold", save_on_exit=True, wipe_once=True)
    ) == ("window · cold boot · saves state on exit · wipe data")


# --------------------------------------------------------------------------
# collector: the pin rule
# --------------------------------------------------------------------------


class _FakeAdb:
    def __init__(self, devices: str):
        self.devices = devices
        self.calls: list[tuple[str, str | None]] = []

    def send_adb_command(self, command, serial=None, timeout=30):
        self.calls.append((command, serial))
        if command == "devices -l":
            return "List of devices attached\n" + self.devices, ""
        if "getprop sys.boot_completed" in command:
            return "1\n35\nAVD_" + str(serial)[-4:] + "\n\n", ""
        return "", ""


@pytest.fixture
def collector_env(monkeypatch):
    from sandroid.core.device_manager import DeviceManager

    monkeypatch.setattr(emulator, "launches", list)
    monkeypatch.setattr(emulator, "emulator_binary", lambda: None)
    monkeypatch.setattr(emulator, "load_launch_prefs", lambda: {"avds": {}})
    monkeypatch.setattr(DeviceManager, "_preferred_serial", None)
    monkeypatch.delenv("ANDROID_SERIAL", raising=False)
    dm = SimpleNamespace(active_device=None, get_device=lambda serial: None)
    monkeypatch.setattr(
        "sandroid.core.toolbox.Toolbox.get_device_manager", classmethod(lambda c: dm)
    )
    return DeviceManager


def _probed(adb: _FakeAdb) -> set[str]:
    return {serial for command, serial in adb.calls if command != "devices -l"}


def test_collector_probes_every_device_without_a_pin(collector_env) -> None:
    adb = _FakeAdb("emulator-5554\tdevice\nemulator-5556\tdevice\n")
    snap = hub.HubCollector(adb).collect()
    assert _probed(adb) == {"emulator-5554", "emulator-5556"}
    assert {r.avd_name for r in snap.devices} == {"AVD_5554", "AVD_5556"}
    assert all(r.state is RowState.READY for r in snap.devices)
    # The emulator binary is missing: no AVD list, but a note says why.
    assert snap.avds == ()
    assert any("emulator not found" in n for n in snap.notes)


def test_collector_never_probes_foreign_devices_under_a_pin(collector_env) -> None:
    collector_env.set_preferred_serial("emulator-5556")
    adb = _FakeAdb("emulator-5554\tdevice model:Pixel\nemulator-5556\tdevice\n")
    snap = hub.HubCollector(adb).collect()
    assert _probed(adb) == {"emulator-5556"}
    foreign = next(r for r in snap.devices if r.serial == "emulator-5554")
    assert foreign.model == "Pixel"  # -l info only
    assert foreign.avd_name == ""
    assert foreign.api is None


def test_collector_probes_our_launch_under_a_pin(collector_env, monkeypatch) -> None:
    collector_env.set_preferred_serial("emulator-5556")
    launch = _Launch("Mine", "emulator-5554", ready=True)
    monkeypatch.setattr(emulator, "launches", lambda: [launch])
    adb = _FakeAdb("emulator-5554\tdevice\nemulator-5556\tdevice\n")
    hub.HubCollector(adb).collect()
    assert _probed(adb) == {"emulator-5554", "emulator-5556"}


def test_collector_readiness_is_sticky(collector_env) -> None:
    adb = _FakeAdb("emulator-5554\tdevice\n")
    collector = hub.HubCollector(adb)
    collector.collect()
    adb.calls.clear()
    collector.collect()
    assert _probed(adb) == set()  # booted once -> not probed again
    adb.devices = "emulator-5554\toffline\n"
    collector.collect()
    adb.devices = "emulator-5554\tdevice\n"
    adb.calls.clear()
    collector.collect()
    assert _probed(adb) == {"emulator-5554"}  # it went away: probe again


def test_collector_marks_our_booted_launch_ready(collector_env, monkeypatch) -> None:
    """The boot waiter gives up after 240 s; the hub's probe still ends the
    launch's "booting" state, so auto-selection may take it again.
    """

    class _Alive:
        def poll(self):
            return None

    launch = emulator.EmulatorLaunch(
        "Slow", "emulator-5560", 5560, AvdLaunchOptions(), _Alive(), None, 0.0
    )
    launch.started_at = __import__("time").monotonic()
    monkeypatch.setattr(emulator, "_LAUNCHES", {launch.serial: launch})
    monkeypatch.setattr(emulator, "launches", lambda: [launch])
    assert emulator.booting_serials() == ["emulator-5560"]
    adb = _FakeAdb("emulator-5560\tdevice\n")
    snap = hub.HubCollector(adb).collect()
    assert snap.devices[0].state is RowState.READY
    assert launch.ready
    assert emulator.booting_serials() == []


def test_collector_forgets_avd_names_of_vanished_serials(collector_env) -> None:
    """A later emulator on the same port may run another AVD."""

    class _Adb(_FakeAdb):
        avd = "Old_AVD"

        def send_adb_command(self, command, serial=None, timeout=30):
            self.calls.append((command, serial))
            if command == "devices -l":
                return "List of devices attached\n" + self.devices, ""
            if "getprop sys.boot_completed" in command:
                prop = self.avd if self.avd == "Old_AVD" else ""
                return f"1\n35\n{prop}\n\n", ""
            if command == "emu avd name":
                return f"{self.avd}\r\nOK\r\n", ""
            return "", ""

    adb = _Adb("emulator-5554\tdevice\n")
    collector = hub.HubCollector(adb)
    assert collector.collect().devices[0].avd_name == "Old_AVD"
    adb.devices = "emulator-5554\toffline\n"
    collector.collect()
    adb.devices = ""
    collector.collect()
    adb.avd = "New_AVD"  # its image has no avd_name property
    adb.devices = "emulator-5554\tdevice\n"
    assert collector.collect().devices[0].avd_name == "New_AVD"


def test_collector_reports_locked_avds(collector_env, monkeypatch) -> None:
    monkeypatch.setattr(emulator, "emulator_binary", lambda: "/sdk/emulator")
    monkeypatch.setattr(emulator, "list_avds", lambda timeout=15.0: ["A", "B"])
    monkeypatch.setattr(emulator, "avd_info", lambda name: AvdInfo(name=name))
    monkeypatch.setattr(
        emulator,
        "avd_lock_files",
        lambda name: ["hardware-qemu.ini.lock"] if name == "B" else [],
    )
    snap = hub.HubCollector(_FakeAdb("")).collect()
    assert {(a.name, a.running_elsewhere) for a in snap.avds} == {
        ("A", False),
        ("B", True),
    }


def test_collector_marks_foreign_devices_unprobed_under_a_pin(
    collector_env, monkeypatch
) -> None:
    collector_env.set_preferred_serial("emulator-5562")
    monkeypatch.setattr(emulator, "emulator_binary", lambda: "/sdk/emulator")
    monkeypatch.setattr(emulator, "list_avds", lambda timeout=15.0: ["A", "B"])
    monkeypatch.setattr(emulator, "avd_info", lambda name: AvdInfo(name=name))
    monkeypatch.setattr(
        emulator, "avd_lock_files", lambda name: ["x.lock"] if name == "B" else []
    )
    monkeypatch.setattr(emulator, "_ports_free", lambda port: True)
    adb = _FakeAdb("emulator-5554\tdevice\n")
    snap = hub.HubCollector(adb).collect()
    assert _probed(adb) == set()
    (foreign,) = snap.devices
    assert foreign.state is RowState.UNPROBED
    # The pinned serial is not running: a start of A would take its port.
    assert {(a.name, a.port, a.port_reason) for a in snap.avds} == {
        ("A", 5562, "pinned"),
        ("B", None, ""),
    }


def test_collector_without_a_pin_previews_the_first_free_port(
    collector_env, monkeypatch
) -> None:
    monkeypatch.setattr(emulator, "emulator_binary", lambda: "/sdk/emulator")
    monkeypatch.setattr(emulator, "list_avds", lambda timeout=15.0: ["A"])
    monkeypatch.setattr(emulator, "avd_info", lambda name: AvdInfo(name=name))
    monkeypatch.setattr(emulator, "avd_lock_files", lambda name: [])
    monkeypatch.setattr(emulator, "_ports_free", lambda port: True)
    monkeypatch.setattr(emulator, "_config_emulator", lambda: None)
    snap = hub.HubCollector(_FakeAdb("emulator-5554\tdevice\n")).collect()
    assert [(a.port, a.port_reason) for a in snap.avds] == [(5556, "auto")]


# --------------------------------------------------------------------------
# screen (pilot)
# --------------------------------------------------------------------------


STARTED = AvdLaunchOptions(headless=True, boot="cold")
READY = DeviceRow(
    serial="emulator-5554",
    avd_name="Pixel_7",
    api=35,
    state=RowState.READY,
    is_emulator=True,
    root_kind="adbd root",
    ours=True,
    launch_options=STARTED,
    saved_options=AvdLaunchOptions(),
)
ACTIVE = DeviceRow(
    serial="emulator-5556",
    avd_name="Pixel_8",
    api=34,
    state=RowState.READY,
    is_emulator=True,
    active=True,
    saved_options=AvdLaunchOptions(save_on_exit=True),
)
UNAUTH = DeviceRow(serial="R58M", state=RowState.UNAUTHORIZED, raw_state="unauthorized")
BOOTING = DeviceRow(
    serial="emulator-5558",
    avd_name="Booting_AVD",
    state=RowState.BOOTING,
    raw_state="starting",
    boot_elapsed=12.0,
    is_emulator=True,
    ours=True,
    launch_options=AvdLaunchOptions(),
)
IDLE = AvdRow(
    name="Idle_AVD",
    api=34,
    tag="google_apis",
    snapshot_count=2,
    snapshots=("default_boot", "s1"),
    options=AvdLaunchOptions(headless=True, boot="cold"),
    last_used=True,
)
OTHER = AvdRow(name="Other", options=AvdLaunchOptions())
BUSY_AVD = AvdRow(name="Busy_AVD", options=AvdLaunchOptions(), running_elsewhere=True)


class FakeActions:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def start_avd(self, name, options=None, *, on_done=None):
        self.calls.append(("start_avd", name, options))

    def stop_emulator(self, serial, *, on_done=None):
        self.calls.append(("stop_emulator", serial))
        if on_done:
            on_done(True, "stopped")

    def restart_emulator(self, serial, options=None, *, on_done=None):
        self.calls.append(("restart_emulator", serial))

    def connect(self, address, *, on_done=None):
        self.calls.append(("connect", address))

    def rename_avd(self, old, new, *, on_done=None):
        self.calls.append(("rename_avd", old, new))


class HubApp(App):
    def __init__(self, screen: DevicesScreen) -> None:
        super().__init__()
        self.hub = screen
        self.result = "unset"

    def on_mount(self) -> None:
        self.push_screen(self.hub, self._done)

    def _done(self, result) -> None:
        self.result = result


@pytest.fixture(autouse=True)
def saved(monkeypatch) -> list:
    """Every ``remember_launch`` of the screen: (name, options, make_last)."""
    calls: list = []
    monkeypatch.setattr(
        emulator,
        "remember_launch",
        lambda name, opts, make_last=True: calls.append((name, opts, make_last)),
    )
    return calls


def _hub(devices=(), avds=(), notes=(), actions=None, **kw):
    snap = HubSnapshot(devices=tuple(devices), avds=tuple(avds), notes=tuple(notes))
    collects: list[bool] = []

    def collect(force_avds=False):
        collects.append(force_avds)
        return snap

    screen = DevicesScreen(collect=collect, actions=actions or FakeActions(), **kw)
    screen.collects = collects
    return HubApp(screen), screen


async def _shown(pilot, screen) -> None:
    """The screen applied its first snapshot (collected in a thread worker)."""
    await until(pilot, lambda: screen.snapshot is not None)
    await settle(pilot)


def _box(screen) -> dict:
    """What the launch-options box shows."""
    from textual.widgets import Checkbox, RadioButton, Select

    def checked(widget_id):
        return screen.query_one(f"#{widget_id}", Checkbox).value

    boot = next(
        (
            boot
            for widget_id, boot in hub._BOOT_IDS.items()
            if screen.query_one(f"#{widget_id}", RadioButton).value
        ),
        None,
    )
    select = screen.query_one("#opt-snapshot", Select)
    return {
        "title": str(screen.query_one("#hub-options").border_title),
        "controls": screen.query_one("#opt-row").display,
        "boot": boot,
        "snapshot": select.value if isinstance(select.value, str) else None,
        "headless": checked("opt-headless"),
        "save": checked("opt-save"),
        "wipe": checked("opt-wipe"),
        "editable": not screen.query_one("#opt-headless").disabled,
        "note": str(screen.query_one("#opt-note").render()),
    }


def _command(options) -> list[str]:
    return emulator.build_emulator_command("/sdk/emulator", "AVD", 5560, options)


async def test_enter_on_a_ready_device_dismisses_with_its_serial() -> None:
    app, screen = _hub(devices=[READY, ACTIVE])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        # The cursor starts on the active device; go to the other one.
        assert screen.current_row() == ACTIVE
        await pilot.press("up")
        assert screen.current_row() == READY
        await pilot.press("enter")
        await settle(pilot)
    assert app.result == "emulator-5554"


async def test_enter_on_a_booting_device_does_not_dismiss() -> None:
    app, screen = _hub(devices=[BOOTING])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        await pilot.press("enter")
        await settle(pilot)
        assert app.screen is screen
        assert "booting" in str(screen._state_cell(BOOTING))
        assert "Booting for 0:1" in _box(screen)["note"]
    assert app.result == "unset"


async def test_one_list_running_then_stopped_then_elsewhere() -> None:
    app, screen = _hub(devices=[READY, UNAUTH], avds=[IDLE, BUSY_AVD, OTHER])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        table = screen.query_one("#hub-table")
        assert table.row_count == 5
        assert [r.key for r in screen.snapshot.rows] == [
            READY.key,
            UNAUTH.key,
            IDLE.key,
            BUSY_AVD.key,
            OTHER.key,
        ]
        title = str(screen.query_one("#hub").border_title)
        assert "2 connected" in title
        assert "2 stopped" in title
        assert "1 elsewhere" in title


async def test_options_box_follows_the_cursor() -> None:
    app, screen = _hub(devices=[READY, ACTIVE], avds=[IDLE, OTHER])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        assert screen.current_row() == ACTIVE  # started outside Sandroid
        box = _box(screen)
        assert box["title"] == "Launch options · Pixel_8 · read-only"
        assert box["save"]
        assert not box["editable"]
        assert "Started outside Sandroid" in box["note"]
        await pilot.press("up")  # READY: Sandroid started it headless + cold
        box = _box(screen)
        assert (box["boot"], box["headless"], box["save"]) == ("cold", True, False)
        assert "Started by Sandroid" in box["note"]
        await pilot.press("down", "down")  # IDLE: editable, remembered options
        box = _box(screen)
        assert box["title"] == "Launch options · Idle_AVD"
        assert box["editable"]
        assert (box["boot"], box["headless"], box["save"]) == ("cold", True, False)
        await pilot.press("down")  # OTHER: defaults
        box = _box(screen)
        assert box["title"] == "Launch options · Other"
        assert (box["boot"], box["headless"], box["save"]) == ("normal", False, False)
        assert screen.query_one("#opt-snap").disabled  # no snapshots


async def test_snapshot_select_lists_the_snapshots_in_quick_boot(saved) -> None:
    """Quick boot: the Select lists the AVD's snapshots (disabled) and never
    claims "no snapshots" for an AVD that has some.
    """
    from textual.widgets import Select

    quick = dataclasses.replace(IDLE, options=AvdLaunchOptions())
    app, screen = _hub(avds=[quick, OTHER])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        assert screen.current_row().name == "Idle_AVD"
        select = screen.query_one("#opt-snapshot", Select)
        assert _box(screen)["boot"] == "normal"
        assert select.prompt == "2 snapshots"
        assert [v for _p, v in select._options if v != Select.NULL] == [
            "default_boot",
            "s1",
        ]
        assert select.disabled  # pickable only for a Snapshot boot
        assert not screen.query_one("#opt-snap").disabled
        await pilot.click("#opt-snap")  # Snapshot boot: the Select opens up
        await until(pilot, lambda: _box(screen)["boot"] == "snapshot")
        assert _box(screen)["snapshot"] == "default_boot"
        assert not select.disabled
        assert saved[-1][:2] == (
            "Idle_AVD",
            AvdLaunchOptions(boot="snapshot", snapshot="default_boot"),
        )
        await pilot.press("down")  # OTHER really has none
        await until(pilot, lambda: screen.current_row().name == "Other")
        assert select.prompt == "no snapshots"
        assert select.disabled


async def test_option_keys_persist_per_avd_and_keep_the_focus(saved) -> None:
    app, screen = _hub(avds=[IDLE, OTHER])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        table = screen.query_one("#hub-table")
        assert screen.current_row() == IDLE
        await pilot.press("h")  # headless off
        await pilot.press("s")  # save state on
        await pilot.press("c")  # cold -> quick boot
        await settle(pilot)
        assert screen.focused is table
        box = _box(screen)
        assert (box["boot"], box["headless"], box["save"]) == ("normal", False, True)
        assert saved[-1] == ("Idle_AVD", AvdLaunchOptions(save_on_exit=True), False)
        assert screen.current_row().options == AvdLaunchOptions(save_on_exit=True)
        await pilot.press("down", "c")  # OTHER: cold boot
        await settle(pilot)
        assert saved[-1] == ("Other", AvdLaunchOptions(boot="cold"), False)
        await pilot.press("up")
        assert _box(screen)["save"]  # IDLE kept its own options
        assert all(not opts.wipe_once for _name, opts, _last in saved)


async def test_mouse_toggles_options_and_the_list_keeps_the_focus(saved) -> None:
    app, screen = _hub(avds=[OTHER])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        table = screen.query_one("#hub-table")
        await pilot.click("#opt-save")
        await settle(pilot)
        assert saved == [("Other", AvdLaunchOptions(save_on_exit=True), False)]
        await pilot.click("#opt-cold")
        await settle(pilot)
        assert saved[-1] == (
            "Other",
            AvdLaunchOptions(boot="cold", save_on_exit=True),
            False,
        )
        assert _box(screen)["boot"] == "cold"
        assert screen.focused is table


async def test_enter_starts_with_exactly_the_shown_options(saved) -> None:
    actions = FakeActions()
    app, screen = _hub(avds=[IDLE], actions=actions)
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        await pilot.press("s")  # headless + cold + save state
        await pilot.press("enter")
        await settle(pilot)
        assert app.screen is screen  # stays open, shows the boot
        assert screen._busy == {IDLE.key: "starting…"}
    ((_, name, options),) = actions.calls
    assert name == "Idle_AVD"
    assert options == AvdLaunchOptions(headless=True, boot="cold", save_on_exit=True)
    command = _command(options)
    assert "-no-window" in command
    assert "-no-snapshot-load" in command
    assert "-no-snapshot-save" not in command
    assert "-wipe-data" not in command


async def test_a_snapshot_picked_with_n_is_what_enter_boots(saved) -> None:
    actions = FakeActions()
    app, screen = _hub(avds=[IDLE], actions=actions)
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        await pilot.press("h")  # with a window
        await pilot.press("n")
        await until(pilot, lambda: type(app.screen).__name__ == "SelectionModal")
        app.screen.dismiss("s1")
        await until(pilot, lambda: _box(screen)["boot"] == "snapshot")
        assert app.screen is screen
        box = _box(screen)
        assert (box["boot"], box["snapshot"]) == ("snapshot", "s1")
        assert saved[-1] == (
            "Idle_AVD",
            AvdLaunchOptions(boot="snapshot", snapshot="s1"),
            False,
        )
        await pilot.press("enter")
        await settle(pilot)
    ((_, _, options),) = actions.calls
    command = _command(options)
    assert command[command.index("-snapshot") + 1] == "s1"
    assert "-no-snapshot-save" in command
    assert "-no-snapshot-load" not in command
    assert "-no-window" not in command


async def test_wipe_asks_then_unticks_and_is_never_saved(saved) -> None:
    actions = FakeActions()
    app, screen = _hub(avds=[OTHER], actions=actions)
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        await pilot.press("w")
        await settle(pilot)
        assert _box(screen)["wipe"]
        assert saved == []  # a wipe is never remembered
        await pilot.press("enter")
        await until(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        await pilot.press("n")  # cancel: nothing starts, still ticked
        await until(pilot, lambda: app.screen is screen)
        assert actions.calls == []
        assert _box(screen)["wipe"]
        await pilot.press("enter")
        await until(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        app.screen._opened_at -= app.screen.ARM_SECONDS  # past the typing guard
        await pilot.press("y")
        await until(pilot, lambda: actions.calls)
        await settle(pilot)
        assert app.screen is screen
        assert not _box(screen)["wipe"]  # once
        assert screen._busy == {OTHER.key: "wiping…"}
    ((_, _, options),) = actions.calls
    assert options == AvdLaunchOptions(wipe_once=True)
    assert "-wipe-data" in _command(options)
    assert saved == []


async def test_running_row_is_read_only(saved) -> None:
    app, screen = _hub(devices=[READY])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        for key in ("h", "s", "c", "w"):
            assert not screen.check_action(
                {"h": "headless", "s": "save", "c": "cold", "w": "wipe"}[key], ()
            )
            await pilot.press(key)
        await pilot.click("#opt-save")
        await settle(pilot)
        box = _box(screen)
        assert not box["editable"]
        assert (box["boot"], box["headless"], box["save"]) == ("cold", True, False)
        assert "R restarts with them" in box["note"]
        assert "  h" not in str(screen.query_one("#opt-headless").label)
    assert saved == []


async def test_x_then_y_stops_the_emulator_by_serial() -> None:
    actions = FakeActions()
    app, screen = _hub(devices=[READY], actions=actions)
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        await pilot.press("x")
        await until(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        await pilot.press("y")
        await until(pilot, lambda: app.screen is screen)
        assert screen._busy == {}  # on_done cleared it
        await until(pilot, lambda: screen.collects[-1] is True)  # and refreshed
    assert actions.calls == [("stop_emulator", "emulator-5554")]


async def test_x_then_n_does_not_stop() -> None:
    actions = FakeActions()
    app, screen = _hub(devices=[READY], actions=actions)
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        await pilot.press("x")
        await until(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        await pilot.press("n")
        await until(pilot, lambda: app.screen is screen)
    assert actions.calls == []


async def test_a_physical_device_offers_attach_only() -> None:
    actions = FakeActions()
    phys = DeviceRow(serial="R58M", model="SM_G991B", state=RowState.READY)
    app, screen = _hub(devices=[phys], actions=actions)
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        assert screen.check_action("stop", ()) is False
        assert screen.check_action("attach", ()) is True
        for action in ("start", "cold", "headless", "save", "wipe", "rename"):
            assert screen.check_action(action, ()) is False
        box = _box(screen)
        assert box["title"] == "Device · SM_G991B · R58M"
        assert not box["controls"]
        assert "no launch options" in box["note"]
        await pilot.press("x")
        await settle(pilot)
        assert app.screen is screen
    assert actions.calls == []


async def test_escape_dismisses_with_none() -> None:
    app, screen = _hub(devices=[READY])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        await pilot.press("escape")
        await settle(pilot)
    assert app.result is None


async def test_unauthorized_row_explains_what_to_do() -> None:
    app, screen = _hub(devices=[UNAUTH])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        box = _box(screen)
        assert "Allow USB debugging" in box["note"]
        assert UNAUTHORIZED_HELP.split(":")[0] in box["note"]
        assert not box["controls"]
        await pilot.press("enter")
        await settle(pilot)
        assert app.screen is screen
    assert app.result == "unset"


FOREIGN = DeviceRow(
    serial="emulator-5556",
    model="sdk_gphone64",
    state=RowState.UNPROBED,
    is_emulator=True,
)


async def test_an_unprobed_device_attaches_only_after_a_confirm(
    monkeypatch,
) -> None:
    from sandroid.core.device_manager import DeviceManager

    monkeypatch.setattr(DeviceManager, "_preferred_serial", "emulator-5562")
    app, screen = _hub(devices=[FOREIGN])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        assert str(screen._state_cell(FOREIGN)) == "in use · not probed"
        assert "not probed" in _box(screen)["note"]
        await pilot.press("enter")
        await until(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        assert "emulator-5562" in app.screen.message_text
        await pilot.press("n")
        await until(pilot, lambda: app.screen is screen)
        assert app.result == "unset"
        await pilot.press("enter")
        await until(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        await pilot.press("y")
        await settle(pilot)
    assert app.result == "emulator-5556"


async def test_the_options_box_shows_the_console_port() -> None:
    pinned = AvdRow(
        name="Pinned", options=AvdLaunchOptions(), port=5562, port_reason="pinned"
    )
    app, screen = _hub(devices=[READY], avds=[pinned, OTHER])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)

        def facts() -> str:
            return str(screen.query_one("#opt-facts").render())

        assert "Port: 5554" in facts()  # running: its actual port
        await pilot.press("down")
        await until(pilot, lambda: "Port: 5562 (pinned)" in facts())
        await pilot.press("down")
        await until(pilot, lambda: "Port" not in facts())  # unknown: no line


async def test_footer_keys_follow_the_highlighted_row() -> None:
    app, screen = _hub(devices=[READY], avds=[IDLE])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        table = screen.query_one("#hub-table")

        def footer() -> dict[str, str]:
            return {
                key: b.binding.description
                for key, b in screen.active_bindings.items()
                if b.binding.show
            }

        keys = footer()
        assert keys["enter"] == "Attach"
        assert {"x", "R"} <= set(keys)
        assert not {"c", "n", "h", "s", "w", "e"} & set(keys)
        await pilot.press("down")
        keys = footer()
        assert keys["enter"] == "Start"
        assert {"c", "n", "h", "s", "w", "e"} <= set(keys)
        assert not {"x", "R"} & set(keys)
        assert screen.focused is table


async def test_notes_and_empty_states_render() -> None:
    app, screen = _hub(notes=["adb is not answering: boom"])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        assert "boom" in str(screen.query_one("#hub-notes").render())
        assert "No devices and no AVDs" in str(screen.query_one("#hub-empty").render())
        assert not screen.query_one("#hub-options").display


async def test_escape_closes_an_open_snapshot_list_first() -> None:
    """The app's priority Esc calls action_cancel: it must not close Devices
    while the snapshot list is open (or focused after a click).
    """
    snap_boot = AvdLaunchOptions(boot="snapshot", snapshot="s1")
    app, screen = _hub(avds=[dataclasses.replace(IDLE, options=snap_boot)])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        select = screen.query_one("#opt-snapshot")
        select.focus()
        select.expanded = True
        await settle(pilot)
        screen.action_cancel()
        await settle(pilot)
        assert app.screen is screen
        assert not select.expanded
        assert screen.focused is screen.query_one("#hub-table")
        screen.action_cancel()
        await settle(pilot)
    assert app.result is None


async def test_a_started_avd_keeps_the_cursor_as_its_running_row() -> None:
    app, screen = _hub(avds=[OTHER, IDLE])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        assert screen.current_row() == IDLE
        running = DeviceRow(
            serial="emulator-5560",
            avd_name="Idle_AVD",
            state=RowState.BOOTING,
            is_emulator=True,
            ours=True,
            launch_options=IDLE.options,
        )
        started = HubSnapshot(devices=(running,), avds=(OTHER,), taken_at=1.0)
        # Through the collector, not screen._apply: a booting row starts the
        # 2 s boot poll, which must collect the same world again (a fixed
        # sleep raced under load and the poll put the old snapshot back).
        screen._collect_fn = lambda force_avds=False: started
        screen.request_refresh()
        await until(pilot, lambda: screen.snapshot is started)
        await settle(pilot)
        assert screen.current_row() == running
        assert "read-only" in _box(screen)["title"]


async def test_p_pins_a_snapshot_and_unpins_only_after_a_confirm(
    monkeypatch, tmp_path
) -> None:
    from types import SimpleNamespace

    from sandroid.core import emulator
    from sandroid.core import snapshot_policy as policy
    from sandroid.tui.modals.confirm_modal import ConfirmModal
    from sandroid.tui.modals.selection_modal import SelectionModal

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(
        emulator,
        "avd_snapshots",
        lambda name: [SimpleNamespace(name=n) for n in ("default_boot", "s1")],
    )
    app, screen = _hub(avds=[IDLE])
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        # default_boot is pinned by default: picking it asks before unpinning.
        await pilot.press("p")
        await until(pilot, lambda: isinstance(app.screen, SelectionModal))
        app.screen.dismiss("default_boot")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        app.screen.dismiss(False)
        await settle(pilot)
        assert "default_boot" in policy.pinned("Idle_AVD")
        await pilot.press("p")
        await until(pilot, lambda: isinstance(app.screen, SelectionModal))
        app.screen.dismiss("default_boot")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        app.screen.dismiss(True)
        await settle(pilot)
        assert "default_boot" not in policy.pinned("Idle_AVD")
        # An unpinned one is pinned at once.
        await pilot.press("p")
        await until(pilot, lambda: isinstance(app.screen, SelectionModal))
        app.screen.dismiss("s1")
        await settle(pilot)
        assert app.screen is screen
        assert policy.pinned("Idle_AVD") == {"clean_8g", "s1"}


def test_a_vanished_pinned_snapshot_is_a_hub_note_once(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from sandroid.tui.screens import devices_screen as hub_module

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    info = SimpleNamespace(name="Dev", snapshots=("clean_8g", "tmp"), path=tmp_path)
    assert hub_module._vanished_pin_notes(info) == []
    # An AVD whose folder can't be read lists no snapshots: no false alarm.
    unreadable = SimpleNamespace(name="Dev", snapshots=(), path=None)
    assert hub_module._vanished_pin_notes(unreadable) == []
    info.snapshots = ("tmp",)
    (note,) = hub_module._vanished_pin_notes(info)
    assert "Pinned snapshot 'clean_8g' of Dev is gone" in note
    assert hub_module._vanished_pin_notes(info) == []


# --------------------------------------------------------------------------
# controller launch API
# --------------------------------------------------------------------------


def _controller(**kw):
    from sandroid.tui.controllers.device_controller import DeviceController

    dm = SimpleNamespace(
        active_device=None, refresh_devices=lambda auto_select=True: []
    )
    toolbox = SimpleNamespace(get_device_manager=lambda: dm)
    return DeviceController(toolbox=toolbox, **kw)


@pytest.fixture
def sync_threads(monkeypatch):
    from sandroid.tui.controllers.device_controller import DeviceController

    monkeypatch.setattr(DeviceController, "_spawn", staticmethod(lambda fn, name: fn()))


def test_start_avd_uses_remembered_options_and_reports_ready(
    monkeypatch, sync_threads
) -> None:
    remembered = AvdLaunchOptions(headless=True, boot="cold")
    launched: list = []
    launch = _Launch("A", "emulator-5560")
    launch.options = remembered
    monkeypatch.setattr(emulator, "remembered_options", lambda name: remembered)
    monkeypatch.setattr(
        emulator,
        "launch_avd",
        lambda name, opts: launched.append((name, opts)) or launch,
    )
    monkeypatch.setattr(emulator, "remember_launch", lambda *a, **k: None)
    monkeypatch.setattr(emulator, "wait_until_ready", lambda serial, **kw: True)
    ready: list = []
    done: list = []
    ctl = _controller(on_emulator_ready=lambda s, a: ready.append((s, a)))
    ctl.start_avd("A", on_done=lambda ok, msg: done.append(ok))
    assert launched == [("A", remembered)]
    assert done == [True]
    assert ready == [("emulator-5560", "A")]


def test_stop_emulator_is_per_serial(monkeypatch, sync_threads) -> None:
    stopped: list = []
    monkeypatch.setattr(
        emulator, "stop_emulator", lambda serial: stopped.append(serial) or True
    )
    done: list = []
    _controller().stop_emulator("emulator-5556", on_done=lambda ok, m: done.append(ok))
    assert stopped == ["emulator-5556"]
    assert done == [True]


def test_connect_rejects_a_bogus_address(sync_threads) -> None:
    done: list = []
    _controller().connect("foo; rm -rf /", on_done=lambda ok, m: done.append(ok))
    assert done == [False]


def test_connect_runs_adb_connect_untargeted(monkeypatch, sync_threads) -> None:
    from sandroid.core.adb import Adb

    calls: list = []

    def fake(command, serial=None, timeout=30):
        calls.append((command, serial))
        return "connected to 10.0.0.5:5555", ""

    monkeypatch.setattr(Adb, "send_adb_command", staticmethod(fake))
    done: list = []
    _controller().connect("10.0.0.5:5555", on_done=lambda ok, m: done.append(ok))
    assert calls == [("connect 10.0.0.5:5555", "")]
    assert done == [True]


# --------------------------------------------------------------------------
# app wiring
# --------------------------------------------------------------------------


class FakeAdbTransport:
    """adb as the whole app sees it: a table of booted emulators.

    Replaces ``Adb.send_adb_command`` (the one way Sandroid runs adb), so the
    real DeviceManager, HubCollector and device poll run against it.
    """

    def __init__(self) -> None:
        self.devices: dict[str, str] = {}  # serial -> AVD name
        self.calls: list[tuple[str, str | None]] = []

    def send(self, command, serial=None, timeout=30):
        from sandroid.core.adb import Adb

        self.calls.append((command, serial))
        if command.startswith("devices"):
            rows = "".join(
                f"{s}\tdevice product:sdk model:sdk_gphone64\n" for s in self.devices
            )
            return f"List of devices attached\n{rows}\n", ""
        target = serial or Adb.get_target_device()
        if target not in self.devices:
            return "", f"error: device '{target}' not found"
        avd = self.devices[target]
        replies = {
            "shell getprop sys.boot_completed": "1\n",
            "shell getprop ro.build.version.release": "15\n",
            "shell getprop ro.build.version.sdk": "35\n",
            "shell id -u": "0\n",
            "shell pm path android": "package:/system/framework/framework-res.apk\n",
            "emu avd name": f"{avd}\r\nOK\r\n",
        }
        if command == hub._PROBE_SCRIPT:
            return f"1\n35\n{avd}\n\n", ""
        if "qemu.avd_name" in command:
            return f"{avd}\n", ""
        return replies.get(command, ""), ""


class _NoMonitor:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass


@pytest.fixture
def fake_adb(monkeypatch):
    """Route all adb traffic of the app to a :class:`FakeAdbTransport`."""
    from sandroid.core.adb import Adb
    from sandroid.core.device_manager import DeviceManager
    from sandroid.tui import app as app_module

    transport = FakeAdbTransport()
    monkeypatch.setattr(Adb, "send_adb_command", transport.send)
    monkeypatch.setattr(app_module, "AdbDeviceMonitor", _NoMonitor)
    monkeypatch.setattr(DeviceManager, "_preferred_serial", None)
    monkeypatch.setattr(emulator, "_LAUNCHES", {})
    DeviceManager.reset()
    Adb.set_target_device(None)
    yield transport
    DeviceManager.reset()
    Adb.set_target_device(None)


@pytest.fixture
def tui(monkeypatch, fake_adb):
    monkeypatch.setattr(
        hub.HubCollector, "collect", lambda self, force_avds=False: HubSnapshot()
    )
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


def _hubs(app) -> list:
    return [s for s in app.screen_stack if isinstance(s, DevicesScreen)]


async def test_d_opens_devices_once(tui) -> None:
    app = tui
    async with app.run_test(size=(160, 45)) as pilot:
        await boot(app, pilot)
        await pilot.press("D")
        await settle(pilot)
        assert isinstance(app.screen, DevicesScreen)
        assert app.screen.mode == "session"
        await pilot.press("D")
        await settle(pilot)
        assert len(_hubs(app)) == 1
        await pilot.press("escape")
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"


async def test_d_types_into_a_focused_input(tui) -> None:
    from textual.widgets import Input

    app = tui
    async with app.run_test(size=(160, 45)) as pilot:
        await boot(app, pilot)
        await pilot.press("ctrl+y")
        await settle(pilot)
        assert isinstance(app.focused, Input)
        assert app.check_action("show_devices", ()) is False
        await pilot.press("D")
        await settle(pilot)
        assert _hubs(app) == []
        assert app.focused.value.endswith("D")


async def test_device_poll_keeps_running_under_the_devices_screen(tui) -> None:
    app = tui
    async with app.run_test(size=(160, 45)) as pilot:
        await boot(app, pilot)
        app.open_devices()
        await settle(pilot)
        polled: list = []
        app._refresh_devices_bg = lambda: polled.append(1)
        app._device_poll_in_flight = False
        app._poll_device_state()
        await settle(pilot)
        assert polled == [1]


async def test_emulator_ready_attaches_only_when_nothing_is_active(
    tui, monkeypatch
) -> None:
    app = tui
    async with app.run_test(size=(160, 45), notifications=True) as pilot:
        await boot(app, pilot)
        switched: list = []
        monkeypatch.setattr(
            app, "_perform_device_switch", lambda s, cleanup=False: switched.append(s)
        )
        monkeypatch.setattr(app, "_active_device", lambda: None)
        app._on_emulator_ready("emulator-5560", "A")
        assert switched == ["emulator-5560"]
        other = SimpleNamespace(serial="emulator-5554")
        monkeypatch.setattr(app, "_active_device", lambda: other)
        app._on_emulator_ready("emulator-5562", "B")
        await settle(pilot)
        assert switched == ["emulator-5560"]
        assert any("B is ready" in str(n.message) for n in app._notifications)


async def test_devices_result_switches_without_a_session(tui, monkeypatch) -> None:
    app = tui
    async with app.run_test(size=(160, 45)) as pilot:
        await boot(app, pilot)
        switched: list = []
        monkeypatch.setattr(
            app, "_perform_device_switch", lambda s, cleanup=False: switched.append(s)
        )
        monkeypatch.setattr(app, "_has_active_session", lambda: False)
        current = SimpleNamespace(serial="emulator-5554")
        monkeypatch.setattr(app, "_active_device", lambda: current)
        app._on_devices_result(None)
        app._on_devices_result("emulator-5554")
        assert switched == []
        app._on_devices_result("emulator-5556")
        assert switched == ["emulator-5556"]


# --------------------------------------------------------------------------
# disconnect -> Devices (and back)
# --------------------------------------------------------------------------


@pytest.fixture
def detached(tui, monkeypatch):
    """The app with a fake active device; ``cb()`` is its device-change hook."""
    from sandroid.services import get_device_service, get_frida_session_service
    from sandroid.tui import app as app_module
    from sandroid.tui.controllers import recording_controller

    monkeypatch.setattr(
        get_frida_session_service(), "update_device_serial", lambda serial: None
    )
    monkeypatch.setattr(recording_controller, "drop_stale_frida_device", lambda: 0)
    monkeypatch.setattr(app_module, "DETACHED_DEVICES_DELAY", 0.05)
    app = tui
    for name in ("_auto_start_frida_server", "_warm_kprobe_cache_on_device_change"):
        monkeypatch.setattr(app, name, lambda: None)
    state = SimpleNamespace(device=SimpleNamespace(serial="emulator-5554"))
    monkeypatch.setattr(app, "_active_device", lambda: state.device)
    service = get_device_service()
    hooks: list = []
    register = service.register_device_change_callback

    def capture(callback):
        hooks.append(callback)
        register(callback)

    monkeypatch.setattr(service, "register_device_change_callback", capture)

    def app_hook():
        return next(h for h in hooks if "_register_frida" in h.__qualname__)

    return SimpleNamespace(app=app, cb=app_hook, state=state)


async def test_open_devices_if_detached_only_without_an_active_device(
    detached, monkeypatch
) -> None:
    app = detached.app
    async with app.run_test(size=(160, 45)) as pilot:
        await boot(app, pilot)
        app._open_devices_if_detached()  # the device is back already
        await settle(pilot)
        assert _hubs(app) == []
        detached.state.device = None
        monkeypatch.setattr(app._device_controller, "is_polling", lambda: True)
        app._open_devices_if_detached()  # snapshot load in progress
        await settle(pilot)
        assert _hubs(app) == []
        monkeypatch.setattr(app._device_controller, "is_polling", lambda: False)
        app._open_devices_if_detached()
        await settle(pilot)
        assert len(_hubs(app)) == 1
        assert app.screen.mode == "session"
        assert "disconnected" in app.screen.reason
        app._open_devices_if_detached()  # never a second one
        await settle(pilot)
        assert len(_hubs(app)) == 1


async def test_disconnect_opens_devices_and_reconnect_closes_it(detached) -> None:
    import asyncio

    app = detached.app
    async with app.run_test(size=(160, 45), notifications=True) as pilot:
        await boot(app, pilot)
        callback = detached.cb()
        detached.state.device = None
        # The poll worker reports the disconnect (off the UI thread).
        await asyncio.to_thread(callback, None)
        await until(pilot, lambda: isinstance(app.screen, DevicesScreen))
        assert any("disconnected" in str(n.message) for n in app._notifications)
        # Auto-reconnect (here on the UI thread: no call_from_thread there).
        detached.state.device = SimpleNamespace(serial="emulator-5554")
        callback(detached.state.device)
        await until(pilot, lambda: type(app.screen).__name__ == "MainScreen")
        assert _hubs(app) == []


async def test_quick_reconnect_never_opens_devices(detached) -> None:
    import asyncio

    app = detached.app
    checks: list[int] = []
    check = app._open_devices_if_detached

    def counted() -> None:
        checks.append(1)
        check()

    app._open_devices_if_detached = counted
    async with app.run_test(size=(160, 45)) as pilot:
        await boot(app, pilot)
        callback = detached.cb()
        detached.state.device = None
        await asyncio.to_thread(callback, None)
        detached.state.device = SimpleNamespace(serial="emulator-5554")
        await asyncio.to_thread(callback, detached.state.device)
        await until(pilot, lambda: checks)  # the delayed check ran...
        await settle(pilot)
        assert _hubs(app) == []  # ...and opened nothing


async def test_devices_opened_with_d_stays_open_on_reconnect(detached) -> None:
    app = detached.app
    async with app.run_test(size=(160, 45)) as pilot:
        await boot(app, pilot)
        callback = detached.cb()
        app.open_devices()
        await settle(pilot)
        callback(detached.state.device)
        await settle(pilot)
        assert len(_hubs(app)) == 1


@pytest.mark.parametrize("ticks", range(12))
async def test_a_dismiss_while_mounting_waits_for_the_mount(ticks) -> None:
    """A reconnect / Esc right after the push must not crash the app.

    Popping the screen mid-mount pruned the snapshot Select between its
    compose and its Mount (Select._on_mount: NoMatches for SelectOverlay).
    """
    import asyncio

    results: list = []
    app = App()
    async with app.run_test(size=SIZE) as pilot:
        base = app.screen
        screen = DevicesScreen(
            collect=lambda force_avds=False: HubSnapshot(avds=(IDLE,)),
            actions=FakeActions(),
        )
        app.push_screen(screen, results.append)
        for _ in range(ticks):
            await asyncio.sleep(0)
        screen.dismiss("emulator-5554")
        screen.dismiss(None)  # a second one while mounting is dropped
        await until(pilot, lambda: results)
        await settle(pilot)
        assert results == ["emulator-5554"]
        assert app.screen is base


# --------------------------------------------------------------------------
# guards: stray clicks, double starts, AVDs running elsewhere, restart
# --------------------------------------------------------------------------


async def test_a_single_click_never_starts_an_avd() -> None:
    actions = FakeActions()
    other = AvdRow(name="Other", options=AvdLaunchOptions())
    app, screen = _hub(avds=[IDLE, other], actions=actions)
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        table = screen.query_one("#hub-table")
        assert table.cursor_row == 0  # the screen highlighted IDLE itself
        y = 1  # header, first row
        await pilot.click(table, offset=(1, y))  # exactly the highlighted cell
        await settle(pilot)
        await pilot.click(table, offset=(10, y + 1))  # another row
        await settle(pilot)
        assert table.cursor_row == 1
        assert actions.calls == []
        await pilot.click(table, offset=(10, y + 1))  # second click: start
        await settle(pilot)
        assert actions.calls == [("start_avd", "Other", other.options)]


async def test_a_second_start_while_the_first_runs_is_ignored() -> None:
    actions = FakeActions()
    app, screen = _hub(avds=[IDLE], actions=actions)
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        await pilot.press("enter")
        await settle(pilot)
        await pilot.press("enter")
        await pilot.press("c")
        await settle(pilot)
        assert screen._busy == {IDLE.key: "starting…"}
    assert actions.calls == [("start_avd", "Idle_AVD", IDLE.options)]


async def test_an_avd_running_elsewhere_cannot_be_started_or_renamed(saved) -> None:
    actions = FakeActions()
    app, screen = _hub(avds=[BUSY_AVD], actions=actions)
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        assert screen.current_row() == BUSY_AVD
        for action in ("start", "cold", "snapshot", "headless", "save", "wipe"):
            assert not screen.check_action(action, ())
        assert not screen.check_action("rename", ())
        for key in ("enter", "c", "h", "s", "w", "e"):
            await pilot.press(key)
            await settle(pilot)
            assert app.screen is screen  # no confirm / rename dialog
        box = _box(screen)
        assert "Running elsewhere" in box["note"]
        assert box["title"].endswith("read-only")
        assert not box["editable"]
        assert "running elsewhere" in str(screen._state_cell(BUSY_AVD))
    assert actions.calls == []
    assert saved == []


@pytest.mark.parametrize(("busy", "confirm"), [(False, False), (True, True)])
async def test_restart_of_the_active_device_asks_while_tasks_run(busy, confirm) -> None:
    actions = FakeActions()
    app, screen = _hub(devices=[ACTIVE], actions=actions)
    app._has_active_session = lambda: busy
    async with app.run_test(size=SIZE) as pilot:
        await _shown(pilot, screen)
        await pilot.press("R")
        await settle(pilot)
        if confirm:
            assert type(app.screen).__name__ == "ConfirmModal"
            assert actions.calls == []
            await pilot.press("y")
            await until(pilot, lambda: app.screen is screen)
        assert app.screen is screen
    assert actions.calls == [("restart_emulator", "emulator-5556")]


# --------------------------------------------------------------------------
# the whole app on a fake adb: real DeviceManager, poll and HubCollector
# --------------------------------------------------------------------------


@pytest.fixture
def live_app(fake_adb, monkeypatch):
    from sandroid.core.toolbox import Toolbox
    from sandroid.services import get_device_service, get_frida_session_service
    from sandroid.tui import app as app_module
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.controllers import recording_controller

    monkeypatch.setattr(
        get_frida_session_service(), "update_device_serial", lambda serial: None
    )
    monkeypatch.setattr(recording_controller, "drop_stale_frida_device", lambda: 0)
    monkeypatch.setattr(app_module, "DETACHED_DEVICES_DELAY", 0.05)
    app = SandroidTUI()
    for name in (
        "_auto_start_frida_server",
        "_warm_kprobe_cache_on_device_change",
        "_warm_kprobe_cache_on_startup",
    ):
        monkeypatch.setattr(app, name, lambda: None)
    fake_adb.devices = {"emulator-5554": "Mine"}
    # Startup's core init creates the device manager before the app mounts,
    # so every device-change hook the app registers is attached to it.
    get_device_service().get_device_manager()
    return SimpleNamespace(app=app, adb=fake_adb, dm=Toolbox.get_device_manager)


def _active_serial(live) -> str | None:
    device = live.dm().active_device
    return device.serial if device is not None else None


async def _poll(app, pilot) -> None:
    """One device poll (the 10 s timer / adb track-devices edge)."""
    await until(pilot, lambda: not app._device_poll_in_flight)
    app._poll_device_state()
    await until(pilot, lambda: not app._device_poll_in_flight)
    await settle(pilot)


async def test_lost_device_never_moves_the_session_and_comes_back(
    live_app,
) -> None:
    app, adb = live_app.app, live_app.adb
    async with app.run_test(size=(160, 45), notifications=True) as pilot:
        await boot(app, pilot)
        # First start: the only ready device is attached.
        await until(pilot, lambda: _active_serial(live_app) == "emulator-5554")
        adb.devices["emulator-5556"] = "Theirs"
        await _poll(app, pilot)
        assert _active_serial(live_app) == "emulator-5554"

        del adb.devices["emulator-5554"]  # stopped / crashed
        await _poll(app, pilot)
        assert _active_serial(live_app) is None  # not emulator-5556
        await until(pilot, lambda: isinstance(app.screen, DevicesScreen))
        screen = app.screen
        assert "disconnected" in screen.reason
        # The real collector lists the other device as ready to attach.
        await until(pilot, lambda: screen.snapshot is not None)
        rows = {row.serial: row for row in screen.snapshot.devices}
        assert rows["emulator-5556"].state is RowState.READY
        assert rows["emulator-5556"].avd_name == "Theirs"
        await _poll(app, pilot)  # the poll keeps running under Devices
        assert _active_serial(live_app) is None

        adb.devices["emulator-5554"] = "Mine"  # back (same serial)
        await _poll(app, pilot)
        assert _active_serial(live_app) == "emulator-5554"
        await until(pilot, lambda: not isinstance(app.screen, DevicesScreen))
        assert type(app.screen).__name__ == "MainScreen"


async def test_attaching_from_devices_moves_the_pin(live_app, monkeypatch) -> None:
    from sandroid.core import device_clock
    from sandroid.core.device_manager import DeviceManager

    connected: list[str] = []
    monkeypatch.setattr(device_clock, "after_device_connect_async", connected.append)
    monkeypatch.setattr(DeviceManager, "_preferred_serial", "emulator-5554")
    app, adb = live_app.app, live_app.adb
    adb.devices["emulator-5556"] = "Theirs"
    async with app.run_test(size=(160, 45)) as pilot:
        await boot(app, pilot)
        await until(pilot, lambda: _active_serial(live_app) == "emulator-5554")
        app._on_devices_result("emulator-5556")  # ⏎ on it in Devices
        await until(pilot, lambda: _active_serial(live_app) == "emulator-5556")
        assert DeviceManager.preferred_serial() == "emulator-5556"
        device = live_app.dm().active_device
        assert device.api_level == 35
        assert device.root_kind == "adbd root"
        assert connected[-1] == "emulator-5556"
