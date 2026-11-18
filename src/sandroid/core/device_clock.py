"""The device clocks against the host clock: measure and record, per device.

Sandroid mixes host times (pull / mark / timeline ``at``) with device times:
the device **wall clock** (file mtimes, values inside app databases) and
the device **CLOCK_MONOTONIC** (getevent, accessibility ``EventTime``,
Frida, ``logcat -v monotonic``, kprobe trace timestamps). Both drift from
the host: a few seconds normally, and by however long a snapshot sat on
disk after a snapshot load (a snapshot restores the guest clocks it was
saved with). This module measures both offsets and writes them down. It
changes the device wall clock only in :func:`sync`, called after a snapshot
load when ``emulator.sync_clock_after_snapshot`` is on; nothing syncs
CLOCK_MONOTONIC, so ``off_mono`` is what maps monotonic timestamps.

**Measuring** (:func:`measure`): one persistent ``adb -s <serial> shell``
per device (opened lazily, reused; a one-shot ``adb shell`` has a 58-107 ms
round trip, the open shell 12-19 ms). Each query writes one line,
``grep -m1 "now at" /proc/timer_list; date +%s.%N``, between host
``time.time()`` t0 and t1: the ``now at <N> nsecs`` line is CLOCK_MONOTONIC
(``ktime_get()``; ``/proc/uptime`` is CLOCK_BOOTTIME and is not used), the
second the wall epoch. After 3 warm-up queries, the query with the smallest
round trip of ``samples`` wins. ``/proc/timer_list`` needs root: without it
only ``off_wall`` is measured (``off_mono`` null, ``mono_note`` says why).
A dead shell is reopened once, then a one-shot ``adb shell`` is used
(``method: "oneshot"``, larger ``err_ms``).

**A sample** is flat and self-describing (one sample = one timeline
record)::

    {"serial": "emulator-5554",
     "host_at": "2026-11-18T15:58:01.042+01:00",    host midpoint (t0+t1)/2
     "device_at": "2026-11-18T14:43:00.919+01:00",  device wall clock then
     "off_wall": 4500.123,    host - device wall (s): host = wall + off_wall;
                              positive = the device clock is behind
     "off_mono": 1763470000.5,  host - device CLOCK_MONOTONIC (s):
                                host_epoch = dev_mono + off_mono
     "dev_mono": 81234.567,   device CLOCK_MONOTONIC then (s)
     "rtt_ms": 14.2,          round trip of the chosen query
     "err_ms": 7.1,           rtt_ms / 2: both offsets are good to this
     "method": "shell",       "shell" (persistent) or "oneshot"
     "samples": 20,           queries compared (after the warm-up)
     "mono_note": null}       why off_mono is null (no root)

The last sample per serial stays in memory: :func:`last_sample` (the header
shows host now - ``off_wall`` as the device time, no adb call) and
:func:`to_host_time` (device monotonic seconds -> host epoch, through the
clock epoch that covers them).

**clock.jsonl** (``<results>/<session>/<device>/clock.jsonl``, next to
``marks.jsonl``): one line per recorded sample (:func:`record`) -- the
sample plus ``reason`` (``device-connect``, ``monitor-start``, ``periodic``,
``pull``, ``snapshot-load``, ``sync``) and ``jump``. ``jump`` (a clock
epoch change) is true for every ``snapshot-load`` and ``sync`` line and
whenever ``off_wall`` or ``off_mono`` moved more than :data:`JUMP_S`
seconds since the previous line of that serial; ``jump_wall_s`` /
``jump_mono_s`` give the moves. A sample that jumped is always written,
whatever took it. ``snapshot`` names the snapshot of a ``snapshot-load`` /
``sync`` line; a ``sync`` line also has ``before_off_wall``,
``after_off_wall``, ``ok`` and ``command``. Times are ISO 8601 with
milliseconds and the UTC offset (:func:`watchlist_store.iso_tz`); the format
grows additively and readers ignore fields they do not know.
"""

from __future__ import annotations

import logging
import math
import queue
import re
import subprocess
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

#: ``clock.jsonl`` in the session's device results folder.
CLOCK_FILE = "clock.jsonl"
#: An offset move above this (seconds) is a clock jump.
JUMP_S = 2.0
#: Wall-clock offsets above this (seconds) are shown and warned about.
NOTABLE_S = 1.0
#: A sample younger than this is reused by :func:`current` (bursts of pulls).
REUSE_S = 10.0
#: Reasons that are clock epoch changes by themselves.
EPOCH_REASONS = frozenset({"snapshot-load", "sync"})
#: Queries per measurement (after :data:`WARMUP` discarded ones): events
#: (connect, snapshot load, sync) / frequent samples (periodic, pulls).
SAMPLES = 20
SAMPLES_QUICK = 5
WARMUP = 3
#: Seconds to wait for a query's answer before the shell counts as dead.
QUERY_TIMEOUT = 2.0

_END = "__sandroid_clock__"
#: One query: CLOCK_MONOTONIC (root), the wall epoch, an end marker.
QUERY = f"grep -m1 'now at' /proc/timer_list 2>/dev/null; date +%s.%N; echo {_END}"
_NO_ROOT = "no root: /proc/timer_list unreadable"
_WALL = re.compile(r"^(\d{9,})(?:\.(\d+))?")
_TIMER_LIST = re.compile(r"now at (\d+) nsecs")

_LOCK = threading.Lock()
#: serial -> the newest sample (any source).
_LAST: dict[str, dict] = {}
#: serial -> (off_wall, off_mono) of the newest clock.jsonl line.
_LOGGED: dict[str, tuple[float, float | None]] = {}
#: serial -> host time.time() of the last failed measurement.
_FAILED: dict[str, float] = {}
#: (topic, serial) already warned about (one warning each per process).
_WARNED: set[tuple[str, str]] = set()
#: serial -> clock epochs of CLOCK_MONOTONIC (see :func:`to_host_time`).
_EPOCHS: dict[str, list[dict]] = {}
#: serial -> the open shell, and the lock that serialises its queries.
_SHELLS: dict[str, Shell] = {}
_SHELL_LOCKS: dict[str, threading.Lock] = {}

Send = Callable[[str], tuple]

#: The host clock (``time.time``; tests replace it with a fake one).
_now: Callable[[], float] = time.time


def _key(serial: str | None) -> str:
    return serial or ""


def _target(serial: str | None) -> str | None:
    if serial:
        return serial
    try:
        from sandroid.core.adb import Adb

        return Adb.get_target_device()
    except Exception:
        return None


def _default_send(serial: str | None) -> Send:
    def send(command: str) -> tuple:
        from sandroid.core.adb import Adb

        return Adb.send_adb_command(command, serial=serial, timeout=10)

    return send


def _iso(epoch: float) -> str:
    from sandroid.core.watchlist_store import iso_tz

    return iso_tz(epoch, "milliseconds")


# ---------------------------------------------------------------------------
# the persistent shell
# ---------------------------------------------------------------------------


class ShellDeadError(Exception):
    """The persistent shell exited, or did not answer in time."""


class Shell:
    """One ``adb -s <serial> shell`` kept open: :meth:`query` writes one
    command line and returns its output lines with host t0 / t1 around it.

    stdin is a pipe (this child is fed commands, it never sees the TUI's
    terminal); stderr is discarded; a reader thread hands stdout lines over
    so a hung device times out instead of blocking.
    """

    def __init__(self, serial: str | None) -> None:
        from sandroid.core.adb import Adb

        self._proc = subprocess.Popen(
            [*Adb.base_argv(serial), "shell"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            errors="replace",
        )
        self._lines: queue.Queue[str | None] = queue.Queue()
        threading.Thread(target=self._read, daemon=True, name="device-clock").start()

    def _read(self) -> None:
        try:
            for line in self._proc.stdout:
                self._lines.put(line)
        except (OSError, ValueError):
            pass
        self._lines.put(None)

    def query(self, command: str) -> tuple[list[str], float, float]:
        """``(lines, t0, t1)`` of one command; raises :class:`ShellDeadError`."""
        try:
            while True:  # drop anything left over from a timed-out query
                self._lines.get_nowait()
        except queue.Empty:
            pass
        lines: list[str] = []
        t0 = time.time()
        try:
            self._proc.stdin.write(command + "\n")
            self._proc.stdin.flush()
        except (OSError, ValueError) as exc:
            raise ShellDeadError(str(exc)) from exc
        deadline = t0 + QUERY_TIMEOUT
        while True:
            try:
                line = self._lines.get(timeout=max(0.01, deadline - time.time()))
            except queue.Empty as exc:
                raise ShellDeadError("no answer") from exc
            if line is None:
                raise ShellDeadError("shell exited")
            line = line.strip()
            if line == _END:
                return lines, t0, time.time()
            if line:
                lines.append(line)

    def close(self) -> None:
        try:
            self._proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            self._proc.kill()
        except OSError:
            pass


#: Opens a :class:`Shell` for a serial (tests replace it with a fake).
SHELL_FACTORY: Callable[[str | None], Shell] = Shell


def _shell(serial: str | None, reopen: bool = False) -> Shell:
    key = _key(serial)
    shell = _SHELLS.pop(key, None) if reopen else _SHELLS.get(key)
    if reopen and shell is not None:
        shell.close()
        shell = None
    if shell is None:
        shell = _SHELLS[key] = SHELL_FACTORY(serial)
    return shell


def close_shells() -> None:
    """Close every persistent shell (they reopen on the next sample)."""
    with _LOCK:
        shells = list(_SHELLS.values())
        _SHELLS.clear()
    for shell in shells:
        shell.close()


# ---------------------------------------------------------------------------
# measuring
# ---------------------------------------------------------------------------


def parse_clocks(lines: list[str]) -> tuple[float | None, float | None]:
    """``(device wall epoch, device CLOCK_MONOTONIC s)`` from a query's
    output lines (``None`` for what is missing).
    """
    wall = mono = None
    for line in lines:
        match = _TIMER_LIST.search(line)
        if match:
            mono = int(match.group(1)) / 1e9
            continue
        match = _WALL.match(line)
        if match and wall is None:
            # ``date`` without %N support prints "1763...N": seconds only.
            fraction = match.group(2) or ""
            wall = float(f"{match.group(1)}.{fraction}" if fraction else match.group(1))
    return wall, mono


def _best(queries: list[tuple[list[str], float, float]], method: str) -> dict | None:
    """The sample of the query with the smallest round trip."""
    usable = []
    for lines, t0, t1 in queries:
        wall, mono = parse_clocks(lines)
        if wall is not None:
            usable.append((t1 - t0, t0, t1, wall, mono))
    if not usable:
        return None
    rtt, t0, t1, wall, mono = min(usable, key=lambda q: q[0])
    host = (t0 + t1) / 2
    return {
        "host_at": _iso(host),
        "device_at": _iso(wall),
        "off_wall": round(host - wall, 6),
        "off_mono": None if mono is None else round(host - mono, 6),
        "dev_mono": None if mono is None else round(mono, 6),
        "rtt_ms": round(rtt * 1000, 2),
        "err_ms": round(rtt * 500, 2),
        "method": method,
        "samples": len(usable),
        "mono_note": _NO_ROOT if mono is None else None,
        "_host": host,
    }


def _shell_queries(serial: str | None, samples: int) -> list | None:
    """``samples`` queries over the persistent shell (after the warm-up),
    reopening it once; ``None`` when it is dead twice.
    """
    for attempt in range(2):
        try:
            shell = _shell(serial, reopen=attempt > 0)
            for _ in range(WARMUP):
                shell.query(QUERY)
            return [shell.query(QUERY) for _ in range(samples)]
        except (ShellDeadError, OSError, ValueError, SystemExit) as exc:
            # (Adb.init() exits when there is no adb at all.)
            logger.debug("device clock: shell for %s failed: %s", serial, exc)
    _SHELLS.pop(_key(serial), None)
    return None


def _oneshot_queries(serial: str | None, send: Send) -> list:
    from sandroid.core.adb_utils import device_shell_command

    try:
        t0 = _now()
        stdout, _stderr = send(device_shell_command(QUERY))
        t1 = _now()
    except (Exception, SystemExit):
        logger.debug("device clock: one-shot adb failed", exc_info=True)
        return []
    lines = [s.strip() for s in str(stdout or "").splitlines()]
    return [([s for s in lines if s and s != _END], t0, t1)]


def measure(
    serial: str | None = None,
    send: Send | None = None,
    samples: int = SAMPLES,
) -> dict | None:
    """One sample of the device clocks (keys in the module docstring), or
    ``None`` (no device / no adb).

    Over the persistent shell (min round trip of ``samples`` queries);
    ``send`` (one adb command -> ``(stdout, stderr)``) forces one one-shot
    query instead. The sample becomes :func:`last_sample` of ``serial``
    (default: the adb target) and feeds the clock epochs. Never raises.
    """
    serial = _target(serial)
    key = _key(serial)
    queries, method = None, "shell"
    if send is None:
        with _LOCK:
            lock = _SHELL_LOCKS.setdefault(key, threading.Lock())
        with lock:
            queries = _shell_queries(serial, samples)
    if queries is None:
        queries, method = (
            _oneshot_queries(serial, send or _default_send(serial)),
            "oneshot",
        )
    best = _best(queries, method)
    with _LOCK:
        if best is None:
            _FAILED[key] = _now()
            return None
        best = {"serial": serial, **best}
        _LAST[key] = best
        _FAILED.pop(key, None)
        _add_to_epochs(key, best)
    return _public(best)


def _public(sample: dict | None) -> dict | None:
    return None if sample is None else {k: v for k, v in sample.items() if k[0] != "_"}


def last_sample(serial: str | None = None) -> dict | None:
    """The newest sample of ``serial`` (default: the adb target), or ``None``.

    No adb call: what a live display uses (device wall time = host now -
    ``off_wall``). A copy, with the keys of the module docstring.
    """
    with _LOCK:
        return _public(_LAST.get(_key(_target(serial))))


# ---------------------------------------------------------------------------
# clock epochs: device CLOCK_MONOTONIC -> host time
# ---------------------------------------------------------------------------


def _add_to_epochs(key: str, sample: dict) -> None:
    """Fold a sample into the serial's monotonic epochs (``_LOCK`` held).

    An epoch is a stretch with one ``off_mono`` (within :data:`JUMP_S`);
    a snapshot load or reboot moves ``off_mono`` and starts the next one.
    """
    off, mono = sample["off_mono"], sample["dev_mono"]
    if off is None:
        return
    epochs = _EPOCHS.setdefault(key, [])
    entry = {"off_mono": off, "err_ms": sample["err_ms"], "mono": mono,
             "host": sample["_host"]}  # fmt: skip
    if epochs and abs(epochs[-1]["off_mono"] - off) <= JUMP_S:
        epochs[-1].update(entry)  # the latest sample tracks the drift
        return
    epochs.append({**entry, "first_mono": mono, "first_host": sample["_host"]})


def to_host_time(serial: str | None, dev_mono_s: float) -> tuple[float, float] | None:
    """``(host epoch, error ms)`` of a device CLOCK_MONOTONIC time (seconds):
    ``dev_mono_s + off_mono`` of the clock epoch that covers it.

    An epoch covers the monotonic times it was sampled in, widened at each
    end by the host time to the neighbouring epoch's sample (when exactly
    the clock jumped in between is unknown); the first epoch is open to the
    past, the newest ends now (a snapshot load can rewind CLOCK_MONOTONIC,
    so a later time of the newest epoch is not ambiguous with an earlier
    epoch's). The newest covering epoch wins. ``None`` without a monotonic
    sample or when no epoch covers the time (e.g. in the future).
    """
    with _LOCK:
        epochs = [dict(e) for e in _EPOCHS.get(_key(_target(serial)), [])]
    for i in range(len(epochs) - 1, -1, -1):
        epoch = epochs[i]
        low = -math.inf
        if i > 0:
            low = epoch["first_mono"] - (epoch["first_host"] - epochs[i - 1]["host"])
        if i < len(epochs) - 1:
            high = epoch["mono"] + (epochs[i + 1]["first_host"] - epoch["host"])
        else:
            high = _now() - epoch["off_mono"] + 1.0
        if low <= dev_mono_s <= high:
            return dev_mono_s + epoch["off_mono"], epoch["err_ms"]
    return None


# ---------------------------------------------------------------------------
# clock.jsonl
# ---------------------------------------------------------------------------


def clock_file() -> Path:
    """``<session results>/clock.jsonl`` (next to ``marks.jsonl``)."""
    from sandroid.core import watchlist_store

    return watchlist_store.files_root().parent / CLOCK_FILE


def _append(entry: dict) -> None:
    from sandroid.core import watchlist_store

    try:
        watchlist_store.append_jsonl(clock_file(), [entry])
    except OSError:
        logger.debug("device clock: clock.jsonl not writable", exc_info=True)


def _moved(new: float | None, old: float | None) -> float | None:
    return None if new is None or old is None else round(new - old, 3)


def _note(sample: dict, reason: str, always: bool, **extra) -> dict | None:
    """Write ``sample`` to clock.jsonl when ``always``, when it is the first
    of its serial, or when it jumped. Returns the line (``None``: skipped).
    """
    key = _key(sample.get("serial"))
    with _LOCK:
        previous = _LOGGED.get(key)
        wall = _moved(sample["off_wall"], previous[0]) if previous else None
        mono = _moved(sample["off_mono"], previous[1]) if previous else None
        moved = any(d is not None and abs(d) > JUMP_S for d in (wall, mono))
        jump = moved or reason in EPOCH_REASONS
        if not (always or jump or previous is None):
            return None
        _LOGGED[key] = (sample["off_wall"], sample["off_mono"])
    entry = {**sample, "reason": reason, "jump": jump}
    if moved:
        entry["jump_wall_s"] = wall
        entry["jump_mono_s"] = mono
    entry.update(extra)
    _append(entry)
    return entry


def current(serial: str | None = None, max_age: float = REUSE_S) -> dict | None:
    """A sample for an evidence record (a pull, a check).

    Reuses the last sample when younger than ``max_age`` seconds (and does
    not retry a failed measurement within that time), else measures
    (:data:`SAMPLES_QUICK`). A fresh sample that jumped is written to
    clock.jsonl (``reason: "pull"``).
    """
    serial = _target(serial)
    now = _now()
    with _LOCK:
        last = _LAST.get(_key(serial))
        failed = _FAILED.get(_key(serial))
    if last is not None and now - last["_host"] < max_age:
        return _public(last)
    if failed is not None and now - failed < max_age:
        return None
    sample = measure(serial, samples=SAMPLES_QUICK)
    if sample is not None:
        _note(sample, "pull", always=False)
    return sample


def record(
    reason: str,
    serial: str | None = None,
    send: Send | None = None,
    samples: int = SAMPLES,
    **extra,
) -> dict | None:
    """Measure now and write the sample to clock.jsonl with ``reason``.

    ``extra`` (e.g. ``snapshot="clean"``) is added to the line. Returns the
    line, ``None`` when the device did not answer.
    """
    sample = measure(serial, send, samples)
    if sample is None:
        return None
    return _note(sample, reason, always=True, **extra)


def record_async(
    reason: str, serial: str | None = None, samples: int = SAMPLES, **extra
) -> None:
    """:func:`record` on a daemon thread (never blocks the caller)."""
    threading.Thread(
        target=record,
        args=(reason, _target(serial)),
        kwargs={"samples": samples, **extra},
        name=f"device-clock-{reason}",
        daemon=True,
    ).start()


def warn_once(topic: str, serial: str | None, message: str) -> bool:
    """Log ``message`` as a WARNING once per ``topic`` and serial."""
    key = (topic, _key(serial))
    with _LOCK:
        if key in _WARNED:
            return False
        _WARNED.add(key)
    logger.warning(message)
    return True


def device_minus_host(sample: dict | None) -> float | None:
    """How far the device wall clock is ahead of the host (s; negative =
    behind) -- ``-off_wall``, the sign people read ("device -75 min", shown with a Unicode minus).
    """
    offset = (sample or {}).get("off_wall")
    return -offset if isinstance(offset, (int, float)) else None


def format_offset(offset_s: float) -> str:
    """``"-75 min"`` / ``"+2.3 s"`` / ``"-5.2 h"`` (with a Unicode minus)."""
    sign = "−" if offset_s < 0 else "+"
    value = abs(offset_s)
    if value < 90:
        text = f"{value:.1f} s"
    elif value < 3 * 3600:
        text = f"{round(value / 60)} min"
    elif value < 48 * 3600:
        text = f"{value / 3600:.1f} h"
    else:
        text = f"{value / 86400:.1f} d"
    return sign + text


def notable(sample: dict | None) -> bool:
    """The wall-clock offset is worth showing (``|off_wall| > NOTABLE_S``)."""
    offset = (sample or {}).get("off_wall")
    return isinstance(offset, (int, float)) and abs(offset) > NOTABLE_S


# ---------------------------------------------------------------------------
# snapshot loads (EmulatorService.load_snapshot)
# ---------------------------------------------------------------------------

#: ``date`` forms that set the wall clock (UTC), most precise first: toybox
#: ``@<epoch>[.fraction]``, then ``MMDDhhmmCCYY.ss`` (every toybox/toolbox).
_SET_FORMS: tuple[Callable[[float], str], ...] = (
    lambda epoch: f"date -u @{epoch:.3f}",
    lambda epoch: f"date -u @{round(epoch)}",
    lambda epoch: "date -u "
    + datetime.fromtimestamp(round(epoch), UTC).strftime("%m%d%H%M%Y.%S"),
)
#: As the adb shell user (root on the analysis AVDs), then through ``su 0``.
_SET_PREFIXES = ("", "su 0 ")


def _run_set(serial: str | None, command: str, send: Send | None) -> None:
    """Run a ``date`` set command: over the persistent shell, else ``send``
    (default a one-shot ``adb shell``). Output is discarded.
    """
    from sandroid.core.adb_utils import device_shell_command

    line = f"{command} >/dev/null 2>&1"
    if send is None:
        with _LOCK:
            lock = _SHELL_LOCKS.setdefault(_key(serial), threading.Lock())
        with lock:
            try:
                _shell(serial).query(f"{line}; echo {_END}")
                return
            except (ShellDeadError, OSError, ValueError, SystemExit):
                _SHELLS.pop(_key(serial), None)
    try:
        (send or _default_send(serial))(device_shell_command(line))
    except (Exception, SystemExit):
        logger.debug("device clock: %r failed", command, exc_info=True)


def sync(serial: str | None = None, send: Send | None = None) -> dict | None:
    """Set the device wall clock to the host clock and measure again.

    Tries each ``date`` form (:data:`_SET_FORMS`, plain then ``su 0``; the
    epoch is host now + half the last round trip) until a re-measurement is
    within :data:`NOTABLE_S`. ``send`` runs the ``date`` commands instead of
    the persistent shell. Returns the last sample with ``ok`` and the
    ``command`` that worked, ``None`` if the device never answered. Writes
    nothing; see :func:`after_snapshot_load`. CLOCK_MONOTONIC is untouched.
    """
    serial = _target(serial)
    after = None
    for prefix in _SET_PREFIXES:
        for form in _SET_FORMS:
            lead = ((last_sample(serial) or {}).get("err_ms") or 0) / 1000
            command = prefix + form(_now() + lead)
            _run_set(serial, command, send)
            after = measure(serial, samples=SAMPLES_QUICK)
            if after is None:
                return None
            if abs(after["off_wall"]) <= NOTABLE_S:
                return {**after, "ok": True, "command": command}
    return None if after is None else {**after, "ok": False, "command": None}


def sync_enabled() -> bool:
    """``emulator.sync_clock_after_snapshot`` of the live config (default on)."""
    try:
        from sandroid.config import get_config

        return bool(get_config().emulator.sync_clock_after_snapshot)
    except Exception:
        return True


def after_snapshot_load(
    name: str, serial: str | None = None, send: Send | None = None
) -> dict | None:
    """Record the clocks after a snapshot load; sync the wall clock if set.

    1. ``reason: "snapshot-load"`` (always ``jump: true``): the restored,
       frozen clocks.
    2. With ``emulator.sync_clock_after_snapshot`` on and the wall clock
       more than :data:`NOTABLE_S` off: :func:`sync`, then a
       ``reason: "sync"`` line (``before_off_wall`` / ``after_off_wall`` /
       ``ok`` / ``command``). A failed sync is warned about once per device
       and the recording goes on.
    3. One WARNING per device when the wall clock is still more than
       :data:`NOTABLE_S` off afterwards.

    Returns the last line written (``None``: the device did not answer).
    """
    serial = _target(serial)
    final = loaded = record("snapshot-load", serial, snapshot=name)
    if loaded is None:
        return None
    if sync_enabled() and notable(loaded):
        synced = sync(serial, send)
        if synced is not None:
            ok = bool(synced.pop("ok"))
            command = synced.pop("command", None)
            final = _note(
                synced,
                "sync",
                always=True,
                before_off_wall=loaded["off_wall"],
                after_off_wall=synced["off_wall"],
                ok=ok,
                command=command,
                snapshot=name,
            ) or {**synced, "ok": ok}
        if synced is None or not final.get("ok"):
            warn_once(
                "sync",
                serial,
                f"Could not set the device clock to host time after loading "
                f"snapshot '{name}' (needs root `date`); recording the offset "
                f"in {CLOCK_FILE} instead.",
            )
    if notable(final):
        warn_once(
            "offset",
            serial,
            f"Device clock is {format_offset(device_minus_host(final))} off the "
            f"host after loading snapshot '{name}'. Device times (file mtimes, "
            f"database values) are on the device clock; the offset is "
            f"recorded in {CLOCK_FILE}.",
        )
    return final


def reset() -> None:
    """Forget every sample and close the shells (tests; a new session)."""
    close_shells()
    with _LOCK:
        _LAST.clear()
        _LOGGED.clear()
        _FAILED.clear()
        _WARNED.clear()
        _EPOCHS.clear()
        _SHELL_LOCKS.clear()


__all__ = [
    "CLOCK_FILE",
    "EPOCH_REASONS",
    "JUMP_S",
    "NOTABLE_S",
    "QUERY",
    "REUSE_S",
    "SAMPLES",
    "SAMPLES_QUICK",
    "SHELL_FACTORY",
    "WARMUP",
    "Shell",
    "ShellDeadError",
    "after_snapshot_load",
    "clock_file",
    "close_shells",
    "current",
    "device_minus_host",
    "format_offset",
    "last_sample",
    "measure",
    "notable",
    "parse_clocks",
    "record",
    "record_async",
    "reset",
    "sync",
    "sync_enabled",
    "to_host_time",
    "warn_once",
]
