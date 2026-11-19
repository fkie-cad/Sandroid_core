"""The device clock module (``core/device_clock.py``) with a fake device shell.

A :class:`FakeDevice` answers the clock query (``now at <ns> nsecs`` +
``date +%s.%N``) on a fake host clock: each query's round trip comes from
``rtts``, and a slow query reads the device late in its bracket (asymmetric),
so only the min-RTT query gives the exact offsets. Nothing runs adb.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime

import pytest

from sandroid.core import device_clock, timeline
from sandroid.core.adb import Adb
from sandroid.core.device_clock import ShellDeadError

HOST0 = 1_763_470_000.0
SERIAL = "emu-1"
ISO_MS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}[+-]\d\d:\d\d$")


class FakeDevice:
    """Device clocks against a fake host clock.

    ``behind``: host - device wall (s). ``mono_off``: host - CLOCK_MONOTONIC.
    ``root``: /proc/timer_list readable. ``set_forms``: the ``date -u`` forms
    that work (``"@"`` / ``"mmdd"``); ``su``: whether ``su 0`` works.
    """

    def __init__(self, behind=4500.0, mono=1000.0, root=True) -> None:
        self.behind = behind
        self.mono_off = HOST0 - mono
        self.root = root
        self.set_forms = {"@", "mmdd"}
        self.su = False
        self.host = HOST0
        self.rtts: list[float] = []
        self.queries = 0
        self.commands: list[str] = []

    def query(self, command: str):
        self.commands.append(command)
        if "date -u" in command:
            form = "@" if "date -u @" in command else "mmdd"
            allowed = self.root or (self.su and command.startswith("su 0"))
            if allowed and form in self.set_forms:
                self.behind = 0.0
            self.host += 0.01
            return [], self.host - 0.01, self.host
        self.queries += 1
        rtt = self.rtts.pop(0) if self.rtts else 0.015
        t0 = self.host
        read = t0 + rtt * (0.5 if rtt <= 0.02 else 0.9)  # slow = asymmetric
        lines = []
        if self.root:
            lines.append(f"now at {int(round((read - self.mono_off) * 1e9))} nsecs")
        lines.append(f"{read - self.behind:.9f}")
        self.host = t0 + rtt + 0.001
        return lines, t0, t0 + rtt


class FakeShell:
    def __init__(self, device: FakeDevice, dead: bool = False) -> None:
        self.device, self.dead, self.closed = device, dead, False

    def query(self, command: str):
        if self.dead:
            raise ShellDeadError("shell exited")
        return self.device.query(command)

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    device_clock.reset()
    monkeypatch.setattr(device_clock, "sync_enabled", lambda: True)
    _CAPTURED.clear()
    with timeline.capture():
        timeline.get_timeline()._capture_out = _CAPTURED
        yield
    device_clock.reset()


#: Every session-timeline line of the running test (timeline.capture()).
_CAPTURED: list[dict] = []


@pytest.fixture
def device(monkeypatch) -> FakeDevice:
    dev = FakeDevice()
    monkeypatch.setattr(device_clock, "SHELL_FACTORY", lambda serial: FakeShell(dev))
    monkeypatch.setattr(device_clock, "_now", lambda: dev.host)
    return dev


def _clock_lines() -> list[dict]:
    return [line for line in _CAPTURED if line["src"] == "clock"]


def _lines() -> list[dict]:
    """The recorded samples: each clock line's ``data`` plus its ``kind``."""
    return [{**line["data"], "kind": line["kind"]} for line in _clock_lines()]


# -- measuring ---------------------------------------------------------------


def test_min_rtt_query_wins_and_both_offsets_come_from_its_bracket(device):
    device.rtts = [0.05] * device_clock.WARMUP + [0.10, 0.08, 0.012, 0.09, 0.07]
    sample = device_clock.measure(SERIAL, samples=5)
    assert device.queries == device_clock.WARMUP + 5
    assert sample["method"] == "shell"
    assert sample["samples"] == 5
    assert sample["rtt_ms"] == pytest.approx(12.0)
    assert sample["err_ms"] == pytest.approx(6.0)
    # Only the 12 ms query reads the device at its midpoint: exact offsets.
    assert sample["off_wall"] == pytest.approx(4500.0, abs=1e-4)
    assert sample["off_mono"] == pytest.approx(device.mono_off, abs=1e-4)
    assert sample["mono_note"] is None
    assert ISO_MS.match(sample["host_at"])
    assert ISO_MS.match(sample["device_at"])
    assert device_clock.last_sample(SERIAL) == sample


def test_no_root_records_the_wall_offset_only(device):
    device.root = False
    sample = device_clock.measure(SERIAL)
    assert sample["off_wall"] == pytest.approx(4500.0, abs=1e-4)
    assert sample["off_mono"] is None
    assert sample["dev_mono"] is None
    assert "no root" in sample["mono_note"]
    assert device_clock.to_host_time(SERIAL, 5.0) is None


def test_a_dead_shell_is_reopened_once(monkeypatch, device):
    shells: list[FakeShell] = []

    def factory(serial):
        shells.append(FakeShell(device, dead=not shells))  # the first one dies
        return shells[-1]

    monkeypatch.setattr(device_clock, "SHELL_FACTORY", factory)
    sample = device_clock.measure(SERIAL, samples=3)
    assert len(shells) == 2
    assert shells[0].closed
    assert sample["method"] == "shell"
    # The reopened shell is kept for the next sample.
    device_clock.measure(SERIAL, samples=3)
    assert len(shells) == 2


def test_a_shell_dead_twice_falls_back_to_one_shot_adb(monkeypatch, device):
    monkeypatch.setattr(
        device_clock, "SHELL_FACTORY", lambda serial: FakeShell(device, dead=True)
    )
    sent: list[str] = []

    def send(command):
        sent.append(command)
        lines, _t0, _t1 = device.query(device_clock.QUERY)
        return "\n".join([*lines, "__sandroid_clock__"]) + "\n", ""

    monkeypatch.setattr(device_clock, "_default_send", lambda serial: send)
    sample = device_clock.measure(SERIAL)
    assert sample["method"] == "oneshot"
    assert sample["samples"] == 1
    assert sent
    assert "/proc/timer_list" in sent[0]
    assert sample["off_wall"] == pytest.approx(4500.0, abs=0.05)


def test_no_device_is_none_and_not_retried_within_the_reuse_window(monkeypatch):
    monkeypatch.setattr(
        device_clock, "SHELL_FACTORY", lambda serial: FakeShell(None, dead=True)
    )
    calls: list[str] = []
    monkeypatch.setattr(
        device_clock, "_default_send", lambda s: lambda c: calls.append(c) or ("", "")
    )
    assert device_clock.current(SERIAL) is None
    assert device_clock.current(SERIAL) is None
    assert len(calls) == 1


def test_parse_clocks_reads_timer_list_and_date():
    assert device_clock.parse_clocks(
        ["now at 81234567890123 nsecs", "1763470000.123456789"]
    ) == (pytest.approx(1763470000.1234567), pytest.approx(81234.567890123))
    # A date without %N support: whole seconds, no monotonic clock.
    assert device_clock.parse_clocks(["1763470000.N"]) == (1763470000.0, None)
    assert device_clock.parse_clocks([]) == (None, None)


# -- timeline clock lines and jumps ---------------------------------------------


def test_clock_lines_are_self_describing_timeline_lines(device):
    entry = device_clock.record("device-connect", SERIAL)
    (envelope,) = _clock_lines()
    (line,) = _lines()
    for key in ("reason", "off_wall", "off_mono", "rtt_ms", "err_ms", "jump"):
        assert key in line
    assert "serial" not in line
    assert "host_at" not in line
    assert line["reason"] == "device-connect"
    assert line["jump"] is False
    assert line["kind"] == "sample"
    # The envelope: the sample's host midpoint, its error, the device.
    assert envelope["src"] == "clock"
    assert envelope["dev"] == SERIAL
    assert envelope["clk"] == "host"
    assert envelope["actor"] == "sandroid"
    assert envelope["t"] == entry["host_at"]
    assert ISO_MS.match(envelope["t"])
    assert envelope["t_err_ms"] == pytest.approx(entry["err_ms"], abs=0.05)
    assert envelope["summary"] == "clock · device −75 min ±8 ms (device-connect)"
    assert len(envelope["h"]) == 64


def test_a_move_over_two_seconds_in_either_offset_is_a_jump(device):
    device_clock.record("device-connect", SERIAL)
    device.host += 30
    device.behind += 0.5  # drift: not a jump, a pull sample is not written
    assert device_clock.current(SERIAL) is not None
    assert [x["reason"] for x in _lines()] == ["device-connect"]
    device.host += 30
    device.behind += 3.0  # wall jump: written although only a pull sampled it
    device_clock.current(SERIAL)
    pull = _lines()[-1]
    assert pull["reason"] == "pull"
    assert pull["jump"] is True
    assert pull["kind"] == "jump"
    assert _clock_lines()[-1]["summary"] == "⏱ clock jump · wall −3.5 s"
    assert pull["jump_wall_s"] == pytest.approx(3.5, abs=1e-3)  # further behind
    assert pull["jump_mono_s"] == pytest.approx(0.0, abs=1e-3)
    device.host += 30
    device.mono_off += 5.0  # monotonic jump alone
    line = device_clock.record("periodic", SERIAL)
    assert line["jump"] is True
    assert line["jump_mono_s"] == pytest.approx(5.0)


def test_a_fresh_sample_is_reused_for_pull_bursts(device):
    first = device_clock.current(SERIAL)
    device.host += 5
    assert device_clock.current(SERIAL) == first
    device.host += 6
    assert device_clock.current(SERIAL)["host_at"] != first["host_at"]


# -- snapshot loads, sync -----------------------------------------------------


def test_snapshot_load_with_sync_on_sets_the_clock(device, caplog):
    with caplog.at_level(logging.WARNING, logger="sandroid.core.device_clock"):
        final = device_clock.after_snapshot_load("clean", SERIAL)
    load, sync = _lines()
    assert load["reason"] == "snapshot-load"
    assert load["snapshot"] == "clean"
    assert load["jump"] is True
    assert load["off_wall"] == pytest.approx(4500.0, abs=1e-3)
    assert sync["reason"] == "sync"
    assert sync["jump"] is True
    assert sync["ok"] is True
    assert sync["snapshot"] == "clean"
    assert sync["before_off_wall"] == pytest.approx(4500.0, abs=1e-3)
    assert abs(sync["after_off_wall"]) < 0.01
    assert sync["command"].startswith("date -u @")
    assert (load["kind"], sync["kind"]) == ("jump", "sync")
    assert _clock_lines()[-1]["summary"] == "⏱ clock synced · −75 min → +0.0 s"
    # The wall clock moved, CLOCK_MONOTONIC did not.
    assert sync["off_mono"] == pytest.approx(load["off_mono"], abs=1e-3)
    public = {k: v for k, v in final.items() if k not in ("serial", "host_at")}
    assert public == {k: v for k, v in sync.items() if k != "kind"}
    assert "_host" not in final
    assert caplog.records == []


def test_sync_falls_back_to_the_mmdd_form(device):
    device.set_forms = {"mmdd"}  # an old date without @epoch
    device_clock.after_snapshot_load("clean", SERIAL)
    sync = _lines()[-1]
    assert sync["ok"] is True
    assert re.fullmatch(r"date -u \d{8}\d{4}\.\d\d", sync["command"])


def test_snapshot_load_with_sync_off_only_records(monkeypatch, device, caplog):
    monkeypatch.setattr(device_clock, "sync_enabled", lambda: False)
    with caplog.at_level(logging.WARNING, logger="sandroid.core.device_clock"):
        device_clock.after_snapshot_load("clean", SERIAL)
        device.host += 100
        device_clock.after_snapshot_load("clean", SERIAL)
    assert [x["reason"] for x in _lines()] == ["snapshot-load", "snapshot-load"]
    assert all(x["jump"] for x in _lines())
    assert not any("date -u" in c for c in device.commands)
    warnings = [r.getMessage() for r in caplog.records]
    assert len(warnings) == 1  # once per device
    assert "−75 min off the host" in warnings[0]
    assert "clean" in warnings[0]


def test_a_failed_sync_is_warned_once_and_recording_goes_on(device, caplog):
    device.set_forms = set()  # date refuses every form
    with caplog.at_level(logging.WARNING, logger="sandroid.core.device_clock"):
        device_clock.after_snapshot_load("clean", SERIAL)
        device_clock.after_snapshot_load("clean", SERIAL)
    reasons = [x["reason"] for x in _lines()]
    assert reasons == ["snapshot-load", "sync", "snapshot-load", "sync"]
    assert _lines()[1]["ok"] is False
    assert _lines()[1]["command"] is None
    assert _lines()[1]["after_off_wall"] == pytest.approx(4500.0, abs=0.01)
    messages = [r.getMessage() for r in caplog.records]
    assert sum("Could not set the device clock" in m for m in messages) == 1
    assert sum("off the host" in m for m in messages) == 1


def test_no_sync_when_the_clock_is_already_close(device):
    device.behind = 0.2
    device_clock.after_snapshot_load("clean", SERIAL)
    assert [x["reason"] for x in _lines()] == ["snapshot-load"]


def test_the_snapshot_service_records_after_every_load(monkeypatch, device):
    from sandroid.services.emulator_service import EmulatorService

    class FakeAdb:
        def send_telnet_command(self, command, serial=None):
            return "OK", ""

        def send_adb_command(self, command, serial=None):
            return ("device", "") if command == "get-state" else ("", "")

    monkeypatch.setattr(device_clock, "sync_enabled", lambda: False)
    svc = EmulatorService()
    svc._get_adb = FakeAdb
    monkeypatch.setattr(svc, "_restore_device_proxy", lambda serial: "skipped")
    assert svc.load_snapshot("clean_8g", serial=SERIAL) is True
    (line,) = _lines()
    assert line["reason"] == "snapshot-load"
    assert line["snapshot"] == "clean_8g"


def test_the_setting_defaults_to_on():
    from sandroid.config.schema import EmulatorConfig

    assert EmulatorConfig().sync_clock_after_snapshot is True
    assert (
        EmulatorConfig(sync_clock_after_snapshot=False).sync_clock_after_snapshot
        is False
    )


# -- device monotonic -> host time ---------------------------------------------


def test_to_host_time_uses_the_epoch_that_covers_the_time(device):
    device.rtts = [0.010] * 40
    device_clock.measure(SERIAL, samples=3)  # epoch 1: mono ~1000 s
    off1 = device.mono_off
    device.host += 120  # mono ~1120 s
    device_clock.measure(SERIAL, samples=3)
    # A snapshot load: CLOCK_MONOTONIC back to ~500 s, a new epoch.
    device.host += 30
    device.mono_off = device.host - 500.0
    device_clock.measure(SERIAL, samples=3)
    off2 = device.mono_off
    host, err = device_clock.to_host_time(SERIAL, 1050.0)
    assert host == pytest.approx(1050.0 + off1, abs=1e-3)
    assert err == pytest.approx(5.0)
    assert device_clock.to_host_time(SERIAL, 500.5)[0] == pytest.approx(
        500.5 + off2, abs=1e-3
    )
    # Before the first sample: the first epoch. The newest ends now.
    assert device_clock.to_host_time(SERIAL, 3.0)[0] == pytest.approx(3.0 + off1)
    device.host += 20
    assert device_clock.to_host_time(SERIAL, 515.0)[0] == pytest.approx(515.0 + off2)
    assert device_clock.to_host_time(SERIAL, 9000.0) is None


def test_to_host_time_without_a_sample_is_none():
    assert device_clock.to_host_time("nobody", 1.0) is None


# -- display helpers and the header ----------------------------------------------


def test_format_offset():
    assert device_clock.format_offset(-4500) == "−75 min"
    assert device_clock.format_offset(2.3) == "+2.3 s"
    assert device_clock.format_offset(-5.2 * 3600) == "−5.2 h"
    assert device_clock.format_offset(3 * 86400) == "+3.0 d"
    assert device_clock.device_minus_host({"off_wall": 4500.0}) == -4500.0
    assert device_clock.notable({"off_wall": 1.5})
    assert not device_clock.notable({"off_wall": -0.4})
    assert not device_clock.notable(None)


@pytest.fixture
def target(monkeypatch):
    monkeypatch.setattr(Adb, "get_target_device", classmethod(lambda cls: SERIAL))


def test_header_shows_device_time_only_when_off(device, target):
    from sandroid.tui.widgets.lens_shell import ShellHeader

    header = ShellHeader()
    now = device.host
    assert header.update_device_clock(now) == ""  # no sample yet
    device_clock.measure(SERIAL)
    when = datetime.fromtimestamp(now - 4500.0)
    assert header.update_device_clock(now) == f"device {when:%H:%M:%S} −75 min ⚠"
    device.behind = 0.4
    device_clock.measure(SERIAL)
    assert header.update_device_clock(now) == ""


def test_the_timeline_writer_samples_the_clock_every_clock_every_s(
    monkeypatch, tmp_path
):
    """The periodic sample is the timeline writer's (headless runs too), for
    the active device, every ``timeline.clock_every_s`` (0 = off).
    """
    calls = []
    monkeypatch.setattr(
        device_clock, "record_async", lambda *a, **k: calls.append((a, k))
    )
    service = timeline.TimelineService()
    try:
        assert service.bind(SERIAL, tmp_path / "s" / "d").state == "open"
        service._policy.clock_every_s = 60
        start = service._active.last_clock_tick
        assert service._tick_clock(start + 30) is False
        assert calls == []  # the connect sample is the first one
        assert service._tick_clock(start + 61) is True
        assert calls == [
            (("periodic", SERIAL), {"samples": device_clock.SAMPLES_QUICK})
        ]
        assert service._tick_clock(start + 90) is False
        assert service._tick_clock(start + 122) is True
        service._policy.clock_every_s = 0
        assert service._tick_clock(start + 1000) is False
        assert len(calls) == 2
    finally:
        service.close("test", 2.0)


@pytest.mark.asyncio
async def test_header_device_clock_is_amber_and_hidden_when_close(device, target):
    from textual.app import App, ComposeResult
    from textual.widgets import Static

    from sandroid.tui.widgets.lens_shell import ShellHeader

    class _App(App):
        def compose(self) -> ComposeResult:
            yield ShellHeader()

    async with _App().run_test() as pilot:
        header = pilot.app.query_one(ShellHeader)
        label = header.query_one("#device-clock", Static)
        header.update_device_clock()
        await pilot.pause()
        assert label.styles.display == "none"
        device_clock.measure(SERIAL)
        header.update_device_clock()
        await pilot.pause()
        assert label.has_class("-off")
        assert label.styles.display == "block"
        assert label.styles.color.hex.lower() == "#fbbf24"
        assert "−75 min ⚠" in str(label.render())
