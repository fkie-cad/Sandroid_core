"""Devices screen: pure model, collector pin rule, screen keys, app wiring.

No real adb/emulator: the screen gets a fake ``collect`` and fake actions,
``DevicesScreen.monitor_factory`` is ``None`` (the adb track-devices socket
is blocked under the test guard anyway), and the collector talks to an adb
double.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
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
        ("device", SerialProbe(booted=True), True, RowState.BOOTING),
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
        AvdInfo(name="Idle_AVD", api_level=34, tag="google_apis", snapshot_count=2),
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
    idle = snap.avds[0]
    assert idle.last_used
    assert idle.options == AvdLaunchOptions(headless=True, boot="cold")
    assert idle.snapshot_count == 2
    assert idle.tag == "google_apis"
    assert not snap.avds[1].last_used


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


# --------------------------------------------------------------------------
# screen (pilot)
# --------------------------------------------------------------------------


READY = DeviceRow(
    serial="emulator-5554",
    avd_name="Pixel_7",
    api=35,
    state=RowState.READY,
    is_emulator=True,
    root_kind="adbd root",
)
ACTIVE = DeviceRow(
    serial="emulator-5556",
    avd_name="Pixel_8",
    api=34,
    state=RowState.READY,
    is_emulator=True,
    active=True,
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
)
IDLE = AvdRow(
    name="Idle_AVD",
    api=34,
    tag="google_apis",
    snapshot_count=1,
    options=AvdLaunchOptions(headless=True, boot="cold"),
    last_used=True,
)


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


def _hub(devices=(), avds=(), notes=(), actions=None, **kw):
    snap = HubSnapshot(devices=tuple(devices), avds=tuple(avds), notes=tuple(notes))
    collects: list[bool] = []

    def collect(force_avds=False):
        collects.append(force_avds)
        return snap

    screen = DevicesScreen(collect=collect, actions=actions or FakeActions(), **kw)
    screen.collects = collects
    return HubApp(screen), screen


async def _settle(pilot, n: int = 4) -> None:
    for _ in range(n):
        await pilot.pause(0.05)


async def test_enter_on_a_ready_device_dismisses_with_its_serial() -> None:
    app, screen = _hub(devices=[READY, ACTIVE])
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        # The cursor starts on the active device; go to the other one.
        assert screen.current_row() == ACTIVE
        await pilot.press("up")
        assert screen.current_row() == READY
        await pilot.press("enter")
        await _settle(pilot)
    assert app.result == "emulator-5554"


async def test_enter_on_a_booting_device_does_not_dismiss() -> None:
    app, screen = _hub(devices=[BOOTING])
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        await pilot.press("enter")
        await _settle(pilot)
        assert app.screen is screen
        assert "booting" in str(screen._state_cell(BOOTING))
    assert app.result == "unset"


async def test_enter_on_an_avd_starts_it_with_remembered_options() -> None:
    actions = FakeActions()
    app, screen = _hub(avds=[IDLE], actions=actions)
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        # Nothing running: the cursor is on the last-used AVD.
        assert screen.current_row() == IDLE
        await pilot.press("enter")
        await _settle(pilot)
        assert app.screen is screen  # stays open, shows the boot
        assert screen._busy == {IDLE.key: "starting…"}
    assert actions.calls == [("start_avd", "Idle_AVD", IDLE.options)]


async def test_cold_boot_key_overrides_the_boot_mode() -> None:
    actions = FakeActions()
    app, _screen = _hub(
        avds=[IDLE.__class__(name="A", options=AvdLaunchOptions(), last_used=True)],
        actions=actions,
    )
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        await pilot.press("c")
        await _settle(pilot)
    assert actions.calls == [("start_avd", "A", AvdLaunchOptions(boot="cold"))]


async def test_x_then_y_stops_the_emulator_by_serial() -> None:
    actions = FakeActions()
    app, screen = _hub(devices=[READY], actions=actions)
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        await pilot.press("x")
        await _settle(pilot)
        assert type(app.screen).__name__ == "ConfirmModal"
        await pilot.press("y")
        await _settle(pilot)
        assert app.screen is screen
        assert screen._busy == {}  # on_done cleared it
        assert screen.collects[-1] is True  # and refreshed
    assert actions.calls == [("stop_emulator", "emulator-5554")]


async def test_x_then_n_does_not_stop() -> None:
    actions = FakeActions()
    app, _screen = _hub(devices=[READY], actions=actions)
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        await pilot.press("x")
        await _settle(pilot)
        await pilot.press("n")
        await _settle(pilot)
    assert actions.calls == []


async def test_stop_is_not_offered_for_a_physical_device() -> None:
    actions = FakeActions()
    phys = DeviceRow(serial="R58M", state=RowState.READY)
    app, screen = _hub(devices=[phys], actions=actions)
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        assert screen.check_action("stop", ()) is False
        assert screen.check_action("attach", ()) is True
        assert screen.check_action("start", ()) is False
        await pilot.press("x")
        await _settle(pilot)
        assert app.screen is screen
    assert actions.calls == []


async def test_escape_dismisses_with_none() -> None:
    app, _screen = _hub(devices=[READY])
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        await pilot.press("escape")
        await _settle(pilot)
    assert app.result is None


async def test_unauthorized_row_explains_what_to_do() -> None:
    app, screen = _hub(devices=[UNAUTH])
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        detail = str(screen.query_one("#hub-detail").render())
        assert "Allow USB debugging" in detail
        assert UNAUTHORIZED_HELP.split(":")[0] in detail
        await pilot.press("enter")
        await _settle(pilot)
        assert app.screen is screen
    assert app.result == "unset"


async def test_tab_moves_between_the_lists_and_footer_follows() -> None:
    app, screen = _hub(devices=[READY], avds=[IDLE])
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        assert isinstance(screen.current_row(), DeviceRow)
        assert screen.check_action("cold", ()) is False
        await pilot.press("tab")
        await _settle(pilot)
        assert screen.current_row() == IDLE
        assert screen.check_action("cold", ()) is True
        assert screen.check_action("stop", ()) is False


async def test_headless_toggle_is_remembered(monkeypatch) -> None:
    saved: list = []
    monkeypatch.setattr(
        emulator,
        "remember_launch",
        lambda name, opts, make_last=True: saved.append((name, opts, make_last)),
    )
    app, screen = _hub(avds=[IDLE])
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        await pilot.press("h")
        await _settle(pilot)
        assert screen.current_row().options.headless is False
    assert saved == [("Idle_AVD", AvdLaunchOptions(boot="cold"), False)]


async def test_notes_and_empty_states_render() -> None:
    app, screen = _hub(notes=["adb is not answering: boom"])
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        assert "boom" in str(screen.query_one("#hub-notes").render())
        assert "none" in str(screen.query_one("#hub-running-empty").render())


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
    monkeypatch.setattr(emulator, "wait_until_ready", lambda serial: True)
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


async def _boot(app, pilot) -> None:
    await _settle(pilot, 8)
    if type(app.screen).__name__ != "MainScreen":
        await pilot.press("enter")  # first-run welcome modal
        await _settle(pilot, 4)
    assert type(app.screen).__name__ == "MainScreen"


@pytest.fixture
def tui(monkeypatch):
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
        await _boot(app, pilot)
        await pilot.press("D")
        await _settle(pilot)
        assert isinstance(app.screen, DevicesScreen)
        assert app.screen.mode == "session"
        await pilot.press("D")
        await _settle(pilot)
        assert len(_hubs(app)) == 1
        await pilot.press("escape")
        await _settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"


async def test_d_types_into_a_focused_input(tui) -> None:
    from textual.widgets import Input

    app = tui
    async with app.run_test(size=(160, 45)) as pilot:
        await _boot(app, pilot)
        await pilot.press("ctrl+y")
        await _settle(pilot)
        assert isinstance(app.focused, Input)
        assert app.check_action("show_devices", ()) is False
        await pilot.press("D")
        await _settle(pilot)
        assert _hubs(app) == []
        assert app.focused.value.endswith("D")


async def test_device_poll_keeps_running_under_the_devices_screen(tui) -> None:
    app = tui
    async with app.run_test(size=(160, 45)) as pilot:
        await _boot(app, pilot)
        app.open_devices()
        await _settle(pilot)
        polled: list = []
        app._refresh_devices_bg = lambda: polled.append(1)
        app._device_poll_in_flight = False
        app._poll_device_state()
        await _settle(pilot)
        assert polled == [1]


async def test_emulator_ready_attaches_only_when_nothing_is_active(
    tui, monkeypatch
) -> None:
    app = tui
    async with app.run_test(size=(160, 45), notifications=True) as pilot:
        await _boot(app, pilot)
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
        await _settle(pilot)
        assert switched == ["emulator-5560"]
        assert any("B is ready" in str(n.message) for n in app._notifications)


async def test_devices_result_switches_without_a_session(tui, monkeypatch) -> None:
    app = tui
    async with app.run_test(size=(160, 45)) as pilot:
        await _boot(app, pilot)
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
