"""The device clock module (``core/device_clock.py``) with a fake device shell.

A :class:`FakeDevice` answers the clock query (``now at <ns> nsecs`` +
``date +%s.%N``) on a fake host clock: each query's round trip comes from
``rtts``, and a slow query reads the device late in its bracket (asymmetric),
so only the min-RTT query gives the exact offsets. Nothing runs adb.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime

import pytest

from sandroid.core import device_clock, timeline
from sandroid.core.adb import Adb
from sandroid.core.device_clock import ShellDeadError

HOST0 = 1_763_470_000.0
SERIAL = "emu-1"
_REAL_SYNC_ENABLED = device_clock.sync_enabled
ISO_MS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}[+-]\d\d:\d\d$")


def _set_epoch_of(command: str) -> float:
    """The epoch a ``date -u @S[.f]`` / ``date -u MMDDhhmmCCYY.ss`` sets."""
    match = re.search(r"date -u @(\d+(?:\.\d+)?)", command)
    if match:
        return float(match.group(1))
    match = re.search(r"date -u (\d{12}\.\d\d)", command)
    return (
        datetime.strptime(match.group(1), "%m%d%H%M%Y.%S")
        .replace(tzinfo=UTC)
        .timestamp()
    )


class FakeDevice:
    """Device clocks against a fake host clock.

    ``behind``: host - device wall (s). ``mono_off``: host - CLOCK_MONOTONIC.
    ``root``: /proc/timer_list readable. ``set_forms``: the ``date -u`` forms
    that work (``"@"`` / ``"mmdd"``); ``su``: whether ``su 0`` works. A
    ``date`` that works sets the wall clock to its epoch (plus the next of
    ``set_errors``, an imprecise landing) when it runs, 5 ms after it was
    sent. ``selinux``: what ``getenforce`` prints.
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
        self.set_errors: list[float] = []
        self.selinux = "Permissive"

    def apply_date(self, command: str, at: float) -> None:
        """Run a ``date -u`` set command at host time ``at``."""
        form = "@" if "date -u @" in command else "mmdd"
        allowed = self.root or (self.su and "su 0 date" in command)
        if not (allowed and form in self.set_forms):
            return
        epoch = _set_epoch_of(command)
        error = self.set_errors.pop(0) if self.set_errors else 0.0
        self.behind = at - (epoch + error)

    def query(self, command: str):
        self.commands.append(command)
        if command.startswith(("getenforce", "echo ")):
            self.host += 0.01
            lines = [self.selinux] if command.startswith("getenforce") else []
            return lines, self.host - 0.01, self.host
        if "date -u" in command:
            self.apply_date(command, self.host + 0.005)
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
    monkeypatch.setattr(
        device_clock, "_sleep", lambda s: setattr(dev, "host", dev.host + s)
    )
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


@pytest.mark.parametrize("root", [True, False])
def test_a_pull_after_a_world_change_never_reuses_the_old_sample(device, root):
    """A snapshot load / cold boot (``begin_epoch``) between two pulls: the
    second pull measures again although the first sample is only 1 s old --
    with or without root (no monotonic epochs without it).
    """
    device.root = root
    first = device_clock.current(SERIAL)
    assert first["off_wall"] == pytest.approx(4500.0, abs=1e-3)
    device.host += 1
    device_clock.begin_epoch(SERIAL)  # the load
    device.behind = 9000.0  # the snapshot's older clock
    second = device_clock.current(SERIAL)
    assert second["off_wall"] == pytest.approx(9000.0, abs=1e-3)
    device.host += 1
    assert device_clock.current(SERIAL) == second  # the new world's: reused


def test_a_failure_before_a_world_change_is_retried(monkeypatch, device):
    monkeypatch.setattr(
        device_clock, "SHELL_FACTORY", lambda serial: FakeShell(device, dead=True)
    )
    monkeypatch.setattr(device_clock, "_default_send", lambda s: lambda c: ("", ""))
    assert device_clock.current(SERIAL) is None
    device.host += 1
    device_clock.begin_epoch(SERIAL)
    monkeypatch.setattr(device_clock, "SHELL_FACTORY", lambda serial: FakeShell(device))
    assert device_clock.current(SERIAL) is not None


def test_a_sample_from_before_a_world_change_does_not_map_wall_times(device):
    device.root = False
    device_clock.measure(SERIAL)
    assert device_clock._current_epoch_sample(SERIAL) is not None
    device.host += 1
    device_clock.begin_epoch(SERIAL)
    assert device_clock._current_epoch_sample(SERIAL) is None
    assert device_clock.last_sample(SERIAL, current_world=True) is None
    assert device_clock.last_sample(SERIAL) is not None  # still the newest
    device_clock.measure(SERIAL)
    assert device_clock._current_epoch_sample(SERIAL) is not None


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
    assert re.fullmatch(r"date -u @\d+\.\d{3}", sync["command"])  # fractional
    assert (load["kind"], sync["kind"]) == ("jump", "sync")
    # The contract the report engine reads: the policy on the trigger line,
    # trigger and sets on the sync line.
    assert load["sync_policy"] is True
    assert "trigger" not in load
    assert "sets" not in load
    assert sync["trigger"] == "snapshot-load"
    assert sync["sets"] == 1
    assert "sync_policy" not in sync
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
    # Each @ form did not apply (offset unchanged): next form, 3 sets. The
    # whole-second form was sent so it landed on the second boundary.
    assert sync["sets"] == 3
    assert abs(sync["after_off_wall"]) <= device_clock.SYNC_TOLERANCE_S


def test_snapshot_load_with_sync_off_only_records(monkeypatch, device, caplog):
    monkeypatch.setattr(device_clock, "sync_enabled", lambda: False)
    with caplog.at_level(logging.WARNING, logger="sandroid.core.device_clock"):
        device_clock.after_snapshot_load("clean", SERIAL)
        device.host += 100
        device_clock.after_snapshot_load("clean", SERIAL)
    assert [x["reason"] for x in _lines()] == ["snapshot-load", "snapshot-load"]
    assert all(x["jump"] for x in _lines())
    assert all(x["sync_policy"] is False for x in _lines())
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
    assert _lines()[1]["sets"] == 6  # 3 forms x (plain, su 0), none applied
    assert _lines()[1]["after_off_wall"] == pytest.approx(4500.0, abs=0.01)
    messages = [r.getMessage() for r in caplog.records]
    assert sum("Could not set the device clock" in m for m in messages) == 1
    assert sum("off the host" in m for m in messages) == 1


def test_no_sync_when_the_clock_is_already_close(device):
    device.behind = 0.2
    device_clock.after_snapshot_load("clean", SERIAL)
    assert [x["reason"] for x in _lines()] == ["snapshot-load"]
    assert _lines()[0]["sync_policy"] is True


def test_the_sync_runs_over_the_persistent_shell_even_with_a_send(monkeypatch, device):
    """The service's adb ``send`` is only the fallback; the target epoch is
    taken while holding the shell lock.
    """
    sent: list[str] = []
    real_set_epoch = device_clock._set_epoch
    locked: list[bool] = []

    def set_epoch(lead, fractional):
        locked.append(device_clock._SHELL_LOCKS[SERIAL].locked())
        return real_set_epoch(lead, fractional)

    monkeypatch.setattr(device_clock, "_set_epoch", set_epoch)
    device_clock.after_snapshot_load(
        "clean", SERIAL, send=lambda c: sent.append(c) or ("", "")
    )
    assert sent == []
    assert sum("date -u @" in c for c in device.commands) == 1
    assert locked == [True]
    assert _lines()[-1]["ok"] is True


def test_a_dead_shell_syncs_one_shot_with_its_own_round_trip(monkeypatch, device):
    """One-shot fallback: the lead is half that path's measured round trip
    (here 200 ms), not the persistent shell's ``err_ms``.
    """
    measure_sample = device_clock.measure(SERIAL)  # shell: err 7.5 ms
    assert measure_sample["err_ms"] == pytest.approx(7.5)
    monkeypatch.setattr(
        device_clock, "SHELL_FACTORY", lambda serial: FakeShell(device, dead=True)
    )
    device_clock.close_shells()
    one_shot: list[tuple[str, float]] = []

    def send(command):
        one_shot.append((command, device.host))
        if "date -u" in command:
            device.apply_date(command, device.host + 0.1)  # one way: 100 ms
        if "/proc/timer_list" in command:
            lines, _t0, _t1 = device.query(device_clock.QUERY)
            return "\n".join(lines) + "\n", ""
        device.host += 0.2
        return "", ""

    monkeypatch.setattr(device_clock, "_default_send", lambda serial: send)
    synced = device_clock.sync(SERIAL, send=send)
    assert synced["ok"] is True
    assert synced["sets"] == 1
    assert abs(synced["off_wall"]) < 0.005
    (date_command, sent_at) = next(x for x in one_shot if "date -u" in x[0])
    assert "date -u @" in date_command
    assert _set_epoch_of(date_command) == pytest.approx(sent_at + 0.1, abs=1e-3)


def test_an_imprecise_landing_gets_one_corrective_retry(device):
    device.set_errors = [0.3]  # the first date lands 300 ms off
    synced = device_clock.sync(SERIAL)
    assert synced["ok"] is True
    assert synced["sets"] == 2
    sets = [c for c in device.commands if "date -u" in c]
    assert len(sets) == 2
    assert all(re.search(r"date -u @\d+\.\d{3}", c) for c in sets)  # same form
    assert not any(c.startswith("su 0") for c in sets)


def test_no_cascade_after_an_applied_but_imprecise_sync(device):
    device.set_errors = [0.3, -0.2]
    synced = device_clock.sync(SERIAL)
    assert synced["ok"] is False
    assert synced["sets"] == 2  # the first set and one retry, nothing more
    assert synced["command"] is not None  # it applied, imprecisely
    assert synced["off_wall"] == pytest.approx(0.2, abs=0.01)
    sets = [c for c in device.commands if "date -u" in c]
    assert len(sets) == 2
    assert not any("su 0" in c or re.search(r"@\d+ ", c + " ") for c in sets)


def test_success_is_within_the_sync_tolerance(device):
    assert device_clock.SYNC_TOLERANCE_S == 0.05
    device.set_errors = [0.04]
    synced = device_clock.sync(SERIAL)
    assert (synced["ok"], synced["sets"]) == (True, 1)
    device.behind = 4500.0
    device.set_errors = [0.07, 0.07]
    synced = device_clock.sync(SERIAL)
    assert (synced["ok"], synced["sets"]) == (False, 2)


def test_su_is_tried_when_the_plain_date_does_not_apply(device):
    device.root = False
    device.su = True
    synced = device_clock.sync(SERIAL)
    assert synced["ok"] is True
    assert synced["sets"] == 4  # 3 plain forms did nothing, then su 0
    assert synced["command"].startswith("su 0 date -u @")


# -- session start (device connect) ---------------------------------------------


@pytest.fixture
def inline_threads(monkeypatch):
    """Run the module's background work on the calling thread."""
    monkeypatch.setattr(
        device_clock, "_background", lambda target, name, *args: target(*args)
    )


def test_device_connect_syncs_a_clock_that_is_off(device):
    final = device_clock.after_device_connect(SERIAL)
    connect, sync = _lines()
    assert connect["reason"] == "device-connect"
    assert connect["sync_policy"] is True
    assert sync["reason"] == "sync"
    assert sync["kind"] == "sync"
    assert sync["trigger"] == "session-start"
    assert sync["ok"] is True
    assert sync["sets"] == 1
    assert sync["before_off_wall"] == pytest.approx(4500.0, abs=1e-3)
    assert abs(sync["after_off_wall"]) <= device_clock.SYNC_TOLERANCE_S
    assert "snapshot" not in sync
    assert final["trigger"] == "session-start"


def test_device_connect_with_a_close_clock_only_records_the_policy(device):
    device.behind = 0.3
    device_clock.after_device_connect(SERIAL)
    (connect,) = _lines()
    assert (connect["reason"], connect["sync_policy"]) == ("device-connect", True)
    assert not any("date -u" in c for c in device.commands)


def test_device_connect_with_the_setting_off_only_records(monkeypatch, device):
    monkeypatch.setattr(device_clock, "sync_enabled", lambda: False)
    device_clock.after_device_connect(SERIAL)
    (connect,) = _lines()
    assert connect["sync_policy"] is False
    assert connect["off_wall"] == pytest.approx(4500.0, abs=1e-3)
    assert not any("date -u" in c for c in device.commands)


def test_the_session_start_sync_waits_for_selinux_permissive(device, inline_threads):
    device.selinux = "Enforcing"
    assert device_clock.after_device_connect(SERIAL) is None
    assert [x["reason"] for x in _lines()] == ["device-connect"]
    assert not any("date -u" in c for c in device.commands)
    device.selinux = "Permissive"  # startup's setenforce 0
    device_clock.after_selinux_step(SERIAL)
    connect, sync = _lines()
    assert (sync["reason"], sync["trigger"], sync["ok"]) == (
        "sync",
        "session-start",
        True,
    )
    device_clock.after_selinux_step(SERIAL)  # once only
    assert len(_lines()) == 2


def test_a_world_change_supersedes_a_waiting_session_start_sync(device, inline_threads):
    device.selinux = "Enforcing"
    device_clock.after_device_connect(SERIAL)
    device_clock.begin_epoch(SERIAL)  # a snapshot load syncs by itself
    device.selinux = "Permissive"
    device_clock.after_selinux_step(SERIAL)
    assert [x["reason"] for x in _lines()] == ["device-connect"]


def test_after_device_connect_async_runs_off_the_caller(monkeypatch):
    started: list[tuple] = []
    monkeypatch.setattr(
        device_clock,
        "_background",
        lambda target, name, *args: started.append((target, name, args)),
    )
    device_clock.after_device_connect_async(SERIAL)
    assert started == [
        (device_clock.after_device_connect, "device-clock-connect", (SERIAL,))
    ]
    started.clear()
    device_clock.after_selinux_step(SERIAL)  # nothing waits: no thread
    assert started == []


def test_set_active_device_starts_the_connect_clock_step(monkeypatch):
    from sandroid.core import device_manager as dm_mod
    from sandroid.core.device import Device
    from sandroid.core.toolbox import Toolbox

    calls: list = []
    monkeypatch.setattr(device_clock, "after_device_connect_async", calls.append)
    monkeypatch.setattr(device_clock, "record_async", lambda *a, **k: calls.append(a))
    monkeypatch.setattr(Adb, "_target_device", None)
    monkeypatch.setattr(Toolbox, "update_frida_device_serial", lambda s: None)
    monkeypatch.setattr(Toolbox, "switch_device_folder", staticmethod(lambda n: None))
    monkeypatch.setattr(timeline.get_timeline(), "bind", lambda *a, **k: None)
    manager = dm_mod.DeviceManager()
    monkeypatch.setattr(manager, "_sync_session_device_name", lambda device: None)
    manager._devices = {SERIAL: Device(serial=SERIAL, name="A", state="device")}
    assert manager.set_active_device(SERIAL) is True
    assert calls == [SERIAL]  # no plain device-connect record any more


def test_the_startup_selinux_step_releases_the_waiting_sync(monkeypatch):
    from sandroid.services.setup_checks import check_and_set_selinux

    calls: list = []
    monkeypatch.setattr(
        device_clock, "after_selinux_step", lambda *a: calls.append("sync")
    )

    class _Adb:
        def send_adb_command(self, command, serial=None):
            calls.append(command)
            return ("Permissive\n", "") if "getenforce" in command else ("", "")

    assert check_and_set_selinux(_Adb()).passed
    assert calls[-1] == "sync"
    assert "shell setenforce 0" in calls[: calls.index("sync")]


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


def test_the_setting_defaults_to_on_and_reads_the_old_name():
    from sandroid.config.schema import EmulatorConfig

    assert EmulatorConfig().sync_device_clock is True
    assert EmulatorConfig(sync_device_clock=False).sync_device_clock is False
    # The deprecated name is still accepted (and readable); the new one wins.
    old = EmulatorConfig(sync_clock_after_snapshot=False)
    assert old.sync_device_clock is False
    assert old.sync_clock_after_snapshot is False
    both = EmulatorConfig(sync_clock_after_snapshot=False, sync_device_clock=True)
    assert both.sync_device_clock is True
    assert "sync_clock_after_snapshot" not in EmulatorConfig().model_dump()


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("case.toml", "[emulator]\nsync_clock_after_snapshot = false\n"),
        ("case.yaml", "emulator:\n  sync_clock_after_snapshot: false\n"),
    ],
)
def test_config_files_with_the_old_name_still_load(tmp_path, monkeypatch, name, text):
    from sandroid.config import ConfigLoader

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.chdir(tmp_path)
    (tmp_path / name).write_text(text)
    config = ConfigLoader().load(config_file=tmp_path / name)
    assert config.emulator.sync_device_clock is False


def test_update_config_takes_the_old_key(monkeypatch):
    import sandroid.config as config_mod
    from sandroid.config.schema import SandroidConfig

    monkeypatch.setattr(config_mod, "_config_instance", SandroidConfig())
    live, _path = config_mod.update_config(
        {"emulator.sync_clock_after_snapshot": False}, persist=False
    )
    assert live.emulator.sync_device_clock is False


def test_sync_enabled_reads_the_new_setting(monkeypatch):
    import sandroid.config as config_mod
    from sandroid.config.schema import SandroidConfig

    config = SandroidConfig()
    monkeypatch.setattr(config_mod, "_config_instance", config)
    # (The autouse fixture pins device_clock.sync_enabled; the real one.)
    assert _REAL_SYNC_ENABLED() is True
    config.emulator.sync_device_clock = False
    assert _REAL_SYNC_ENABLED() is False


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


def test_header_hides_the_stale_offset_after_a_world_change(device, target):
    from sandroid.tui.widgets.lens_shell import ShellHeader

    header = ShellHeader()
    device_clock.measure(SERIAL)
    assert "−75 min" in header.update_device_clock(device.host)
    device.host += 1
    device_clock.begin_epoch(SERIAL)  # a snapshot load: no fresh sample yet
    assert header.update_device_clock(device.host) == ""
    device.behind = 9000.0
    device_clock.measure(SERIAL)
    assert "−150 min" in header.update_device_clock(device.host)


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


def test_a_sample_measured_before_a_world_change_stays_in_the_old_world(
    monkeypatch, device
):
    """A measurement that finishes after ``begin_epoch`` (a snapshot load
    started meanwhile) neither reopens the closed epoch nor becomes the
    newest sample or the jump reference; its line is marked stale.
    """
    device_clock.record("device-connect", SERIAL)
    logged = dict(device_clock._LOGGED)
    last = device_clock.last_sample(SERIAL)
    real_best = device_clock._best

    def best_then_load(*args):
        sample = real_best(*args)
        device.host += 1.0
        device.mono_off += 300.0  # the load moved the clocks
        device_clock.begin_epoch(SERIAL)
        return sample

    monkeypatch.setattr(device_clock, "_best", best_then_load)
    line = device_clock.record("periodic", SERIAL)
    assert line["stale"] is True
    assert line["jump"] is False
    assert logged == device_clock._LOGGED
    assert device_clock.last_sample(SERIAL) == last
    (epoch,) = device_clock._EPOCHS[SERIAL]
    assert "closed_host" in epoch  # still closed: fresh times stay unmapped
    assert device_clock.to_host_time(SERIAL, 5000.0) is None
    # Direct: a late sample from before the barrier is refused.
    with device_clock._LOCK:
        assert not device_clock._add_to_epochs(SERIAL, {
            "off_mono": epoch["off_mono"], "dev_mono": 1.0, "err_ms": 1.0,
            "_host": epoch["closed_host"] - 0.5})  # fmt: skip
