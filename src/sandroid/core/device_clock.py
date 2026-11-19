"""The device clocks against the host clock: measure and record, per device.

Sandroid mixes host times (pull / mark / timeline ``at``) with device times:
the device **wall clock** (file mtimes, values inside app databases) and
the device **CLOCK_MONOTONIC** (getevent, accessibility ``EventTime``,
Frida, ``logcat -v monotonic``, kprobe trace timestamps). Both drift from
the host: a few seconds normally, and by however long a snapshot sat on
disk after a snapshot load (a snapshot restores the guest clocks it was
saved with). This module measures both offsets and writes them down. It
changes the device wall clock only in :func:`sync`, called at session start
(:func:`after_device_connect`) and after a snapshot load
(:func:`after_snapshot_load`) when ``emulator.sync_device_clock`` is on;
nothing syncs CLOCK_MONOTONIC, so ``off_mono`` is what maps monotonic
timestamps.

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

**The session timeline** (``core/timeline.py``): one ``clock`` line per
recorded sample (:func:`record`; kind ``sample`` / ``jump`` / ``sync``) --
its ``data`` is the sample (minus ``serial`` and ``host_at``) plus
``reason`` (``device-connect``, ``monitor-start``, ``periodic``, ``pull``,
``snapshot-load``, ``sync``) and ``jump``. ``jump`` (a clock
epoch change) is true for every ``snapshot-load`` and ``sync`` line and
whenever ``off_wall`` or ``off_mono`` moved more than :data:`JUMP_S`
seconds since the previous line of that serial; ``jump_wall_s`` /
``jump_mono_s`` give the moves. A sample that jumped is always written,
whatever took it. ``snapshot`` names the snapshot of a ``snapshot-load`` /
``sync`` line; a ``sync`` line also has ``trigger`` (``snapshot-load`` /
``session-start``), ``before_off_wall``, ``after_off_wall``, ``ok``,
``command`` and ``sets`` (time suggestions and ``date`` commands issued). The ``snapshot-load``
and ``device-connect`` lines carry ``sync_policy`` (the setting then).
Times are ISO 8601 with milliseconds and the UTC offset
(:func:`watchlist_store.iso_tz`); the format grows additively and readers
ignore fields they do not know.

**World changes** (a snapshot load, a cold boot): the timeline calls
:func:`begin_epoch` (a barrier: the newest epoch ends now, so fresh
monotonic times are not mapped with the old offset until the next sample)
and :func:`to_host_time` takes ``near`` (the time the event was received)
to pick, among the epochs that cover a time, the one whose result lies in
``[near - 30 s, near + 1 s]``. A sample measured before the newest
:func:`begin_epoch` of its serial describes the old world: :func:`current`
never reuses it and the header (``last_sample(current_world=True)``) does
not show it. On a resume :func:`seed` restores the last
recorded offsets so the first new sample detects a jump.
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

logger = logging.getLogger(__name__)

#: An offset move above this (seconds) is a clock jump.
JUMP_S = 2.0
#: Wall-clock offsets above this (seconds) are shown and warned about.
NOTABLE_S = 1.0
#: A clock sync succeeded when the wall clock is this close to the host (s).
SYNC_TOLERANCE_S = 0.05
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
#: Drift allowance of a monotonic conversion: ms of error per second away
#: from the epoch's last sample (0.01 ms/s, about 3 ms per 5 min).
DRIFT_MS_PER_S = 0.01
#: The ``near`` window of :func:`to_host_time` (seconds before / after).
NEAR_BEFORE_S = 30.0
NEAR_AFTER_S = 1.0

_END = "__sandroid_clock__"
#: One query: CLOCK_MONOTONIC (root), the wall epoch, an end marker.
QUERY = f"grep -m1 'now at' /proc/timer_list 2>/dev/null; date +%s.%N; echo {_END}"
_NO_ROOT = "no root: /proc/timer_list unreadable"
_WALL = re.compile(r"^(\d{9,})(?:\.(\d+))?")
_TIMER_LIST = re.compile(r"now at (\d+) nsecs")

_LOCK = threading.Lock()
#: serial -> the newest sample (any source).
_LAST: dict[str, dict] = {}
#: serial -> (off_wall, off_mono) of the newest recorded timeline line.
_LOGGED: dict[str, tuple[float, float | None]] = {}
#: serial -> host time.time() of the last failed measurement.
_FAILED: dict[str, float] = {}
#: (topic, serial) already warned about (one warning each per process).
_WARNED: set[tuple[str, str]] = set()
#: serial -> clock epochs of CLOCK_MONOTONIC (see :func:`to_host_time`).
_EPOCHS: dict[str, list[dict]] = {}
#: serial -> host time of the newest world change (:func:`begin_epoch`):
#: samples measured before it are never reused or shown.
_BARRIER: dict[str, float] = {}
#: serials whose session-start sync waits for startup's SELinux step
#: (:func:`after_selinux_step`; SELinux was Enforcing at connect).
_PENDING_SYNC: set[str] = set()
#: serial -> the open shell, and the lock that serialises its queries.
_SHELLS: dict[str, Shell] = {}
_SHELL_LOCKS: dict[str, threading.Lock] = {}

Send = Callable[[str], tuple]

#: The host clock (``time.time``; tests replace it with a fake one).
_now: Callable[[], float] = time.time
#: Waits (``time.sleep``; tests replace it with one that moves the fake clock).
_sleep: Callable[[float], None] = time.sleep


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
            # (Adb.init() raises AdbNotFoundError, an OSError, without adb.)
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
    return _public(_measure(serial, send, samples))


def _measure(
    serial: str | None = None, send: Send | None = None, samples: int = SAMPLES
) -> dict | None:
    """:func:`measure` keeping the internal ``_host`` (the line's time)."""
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
        _FAILED.pop(key, None)
        if _add_to_epochs(key, best):
            _LAST[key] = best
        else:
            # Measured before a world change that began meanwhile: it
            # describes the old world (not the newest sample, no epoch).
            best["_stale"] = True
    return dict(best)


def _public(sample: dict | None) -> dict | None:
    return None if sample is None else {k: v for k, v in sample.items() if k[0] != "_"}


def _in_current_world(key: str, host: float | None) -> bool:
    """``host`` (a sample's or failure's time) is not before the newest
    world change of ``key`` (``_LOCK`` held).
    """
    barrier = _BARRIER.get(key)
    return barrier is None or (host is not None and host >= barrier)


def last_sample(serial: str | None = None, current_world: bool = False) -> dict | None:
    """The newest sample of ``serial`` (default: the adb target), or ``None``.

    No adb call: what a live display uses (device wall time = host now -
    ``off_wall``). A copy, with the keys of the module docstring. With
    ``current_world``, ``None`` while the newest sample is from before the
    latest world change (snapshot load, cold boot): its offset is stale.
    """
    key = _key(_target(serial))
    with _LOCK:
        sample = _LAST.get(key)
        if current_world and sample is not None:
            if not _in_current_world(key, sample.get("_host")):
                return None
        return _public(sample)


# ---------------------------------------------------------------------------
# clock epochs: device CLOCK_MONOTONIC -> host time
# ---------------------------------------------------------------------------


def _add_to_epochs(key: str, sample: dict) -> bool:
    """Fold a sample into the serial's monotonic epochs (``_LOCK`` held).

    An epoch is a stretch with one ``off_mono`` (within :data:`JUMP_S`);
    a snapshot load or reboot moves ``off_mono`` and starts the next one.
    A sample measured before :func:`begin_epoch` closed the newest epoch
    (it finished late) is stale: it never reopens or extends an epoch.
    Returns False for a stale sample.
    """
    epochs = _EPOCHS.setdefault(key, [])
    closes = [e["closed_host"] for e in epochs if "closed_host" in e]
    if key in _BARRIER:
        closes.append(_BARRIER[key])
    if closes and sample.get("_host", math.inf) < max(closes):
        return False
    off, mono = sample["off_mono"], sample["dev_mono"]
    if off is None:
        return True
    entry = {"off_mono": off, "err_ms": sample["err_ms"], "mono": mono,
             "host": sample["_host"]}  # fmt: skip
    if (
        epochs
        and "closed_host" not in epochs[-1]
        and abs(epochs[-1]["off_mono"] - off) <= JUMP_S
    ):
        epochs[-1].update(entry)  # the latest sample tracks the drift
        return True
    epochs.append({**entry, "first_mono": mono, "first_host": sample["_host"]})
    return True


def to_host_time(
    serial: str | None, dev_mono_s: float, near: float | None = None
) -> tuple[float, float] | None:
    """``(host epoch, error ms)`` of a device CLOCK_MONOTONIC time (seconds):
    ``dev_mono_s + off_mono`` of the clock epoch that covers it.

    An epoch covers the monotonic times it was sampled in, widened at each
    end by the host time to the neighbouring epoch's sample (when exactly
    the clock jumped in between is unknown); the first epoch is open to the
    past, the newest ends now (a snapshot load can rewind CLOCK_MONOTONIC,
    so a later time of the newest epoch is not ambiguous with an earlier
    epoch's) or where :func:`begin_epoch` closed it. The newest covering
    epoch wins. ``None`` without a monotonic sample or when no epoch covers
    the time (e.g. in the future).

    With ``near`` (host epoch the event was received at), the newest
    covering epoch whose result lies in ``[near - 30 s, near + 1 s]`` wins
    and ``None`` is returned when there is none.
    """
    hit = _to_host_detail(serial, dev_mono_s, near)
    return None if hit is None else (hit[0], hit[1])


def _to_host_detail(
    serial: str | None, dev_mono_s: float, near: float | None = None
) -> tuple[float, float, float] | None:
    """:func:`to_host_time` plus the monotonic time of the epoch's sample."""
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
        closed = epoch.get("closed_host")
        if closed is not None:
            high = min(high, closed - epoch["off_mono"])
        if not low <= dev_mono_s <= high:
            continue
        host = dev_mono_s + epoch["off_mono"]
        if near is not None and not (
            near - NEAR_BEFORE_S <= host <= near + NEAR_AFTER_S
        ):
            continue
        return host, epoch["err_ms"], epoch["mono"]
    return None


def begin_epoch(serial: str | None) -> None:
    """A world change (snapshot load, cold boot) starts now: close the
    newest monotonic epoch at host now. Until the next sample, fresh
    monotonic times are not mapped with the old offset.
    """
    key = _key(_target(serial))
    with _LOCK:
        now = _now()
        _BARRIER[key] = now
        # A session-start sync still waiting is superseded by the new world
        # (a snapshot load syncs by itself).
        _PENDING_SYNC.discard(key)
        epochs = _EPOCHS.get(key)
        if epochs and "closed_host" not in epochs[-1]:
            epochs[-1]["closed_host"] = now


def seed(
    serial: str, *, off_wall: float, off_mono: float | None, host_t: float
) -> None:
    """After a resume: the last recorded offsets (``host_t`` is when they
    were sampled), so the first new sample is checked for a jump.
    """
    del host_t  # recorded in the line; only the offsets are compared
    with _LOCK:
        _LOGGED[_key(serial)] = (off_wall, off_mono)


def _current_epoch_sample(serial: str | None) -> dict | None:
    """The newest sample if no world change began since it (dev_wall)."""
    key = _key(_target(serial))
    with _LOCK:
        sample = _LAST.get(key)
        epochs = _EPOCHS.get(key)
        if sample is None:
            return None
        if epochs and "closed_host" in epochs[-1]:
            return None
        if not _in_current_world(key, sample.get("_host")):
            return None
        return dict(sample)


# ---------------------------------------------------------------------------
# the session timeline's clock lines
# ---------------------------------------------------------------------------


def _summary(kind: str, entry: dict) -> str:
    offset = device_minus_host(entry)
    shown = format_offset(offset) if offset is not None else "?"
    if kind == "sync":
        before = entry.get("before_off_wall")
        after = entry.get("after_off_wall")
        if isinstance(before, (int, float)) and isinstance(after, (int, float)):
            return (
                f"⏱ clock synced · {format_offset(-before)} → {format_offset(-after)}"
            )
        return f"⏱ clock synced · device {shown}"
    if kind == "jump":
        moved = entry.get("jump_wall_s")
        if isinstance(moved, (int, float)):
            return f"⏱ clock jump · wall {format_offset(-moved)}"
        return f"⏱ clock jump · device {shown} ({entry.get('reason')})"
    err = entry.get("err_ms")
    err_text = f" ±{round(err)} ms" if isinstance(err, (int, float)) else ""
    return f"clock · device {shown}{err_text} ({entry.get('reason')})"


def _append(entry: dict, host: float | None = None) -> None:
    """One ``clock`` line on the session timeline (``t`` = the sample's
    host midpoint). Never raises.
    """
    if entry.get("reason") == "sync":
        kind = "sync"
    elif entry.get("jump"):
        kind = "jump"
    else:
        kind = "sample"
    data = {k: v for k, v in entry.items() if k not in ("serial", "host_at")}
    when = host
    if when is None:
        try:
            when = datetime.fromisoformat(str(entry.get("host_at"))).timestamp()
        except ValueError:
            when = None
    try:
        from sandroid.core import timeline

        timeline.get_timeline().emit(
            "clock",
            kind,
            summary=_summary(kind, entry),
            data=data,
            t=when,
            t_err_ms=entry.get("err_ms"),
            dev=entry.get("serial"),
            actor="sandroid",
        )
    except Exception:
        logger.debug("device clock: timeline line failed", exc_info=True)


def _moved(new: float | None, old: float | None) -> float | None:
    return None if new is None or old is None else round(new - old, 3)


def _note(sample: dict, reason: str, always: bool, **extra) -> dict | None:
    """Write ``sample`` to the session timeline when ``always``, when it is
    the first of its serial, or when it jumped. Returns the entry (public
    keys; ``None``: skipped). ``sample["_host"]`` (if present) is its time.
    """
    host = sample.get("_host")
    stale = bool(sample.get("_stale"))
    sample = _public(sample)
    key = _key(sample.get("serial"))
    if stale:
        # From before a world change that began while it was measured: no
        # jump against the new world's offsets, the reference stays.
        if not always:
            return None
        entry = {**sample, "reason": reason, "jump": False, "stale": True}
        entry.update(extra)
        _append(entry, host)
        return entry
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
    _append(entry, host)
    return entry


def current(serial: str | None = None, max_age: float = REUSE_S) -> dict | None:
    """A sample for an evidence record (a pull, a check).

    Reuses the last sample when younger than ``max_age`` seconds (and does
    not retry a failed measurement within that time), else measures
    (:data:`SAMPLES_QUICK`). Never reuses a sample (or a failure) from
    before the latest world change (:func:`begin_epoch`): after a snapshot
    load or cold boot the offset is measured again. A fresh sample that
    jumped is written to the session timeline (``reason: "pull"``).
    """
    serial = _target(serial)
    key = _key(serial)
    now = _now()
    with _LOCK:
        last = _LAST.get(key)
        if last is not None and not _in_current_world(key, last["_host"]):
            last = None
        failed = _FAILED.get(key)
        if failed is not None and not _in_current_world(key, failed):
            failed = None
    if last is not None and now - last["_host"] < max_age:
        return _public(last)
    if failed is not None and now - failed < max_age:
        return None
    sample = _measure(serial, samples=SAMPLES_QUICK)
    if sample is not None:
        _note(sample, "pull", always=False)
    return _public(sample)


def record(
    reason: str,
    serial: str | None = None,
    send: Send | None = None,
    samples: int = SAMPLES,
    **extra,
) -> dict | None:
    """Measure now and write the sample to the session timeline with ``reason``.

    ``extra`` (e.g. ``snapshot="clean"``) is added to the line. Returns the
    line, ``None`` when the device did not answer.
    """
    sample = _measure(serial, send, samples)
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
# setting the wall clock: session start, snapshot loads
# ---------------------------------------------------------------------------

#: ``date`` forms that set the wall clock (UTC), most precise first: toybox
#: ``@<epoch>.<fraction>``, then whole seconds: ``@<epoch>`` and
#: ``MMDDhhmmCCYY.ss`` (every toybox/toolbox). ``(form, fractional)``: a
#: whole-second form is sent so that it lands on a second boundary.
_SET_FORMS: tuple[tuple[Callable[[float], str], bool], ...] = (
    (lambda epoch: f"date -u @{epoch:.3f}", True),
    (lambda epoch: f"date -u @{round(epoch)}", False),
    (
        lambda epoch: (
            "date -u "
            + datetime.fromtimestamp(round(epoch), UTC).strftime("%m%d%H%M%Y.%S")
        ),
        False,
    ),
)
#: As the adb shell user (root on the analysis AVDs), then through ``su 0``.
_SET_PREFIXES = ("", "su 0 ")


def _shell_lock(key: str) -> threading.Lock:
    with _LOCK:
        return _SHELL_LOCKS.setdefault(key, threading.Lock())


def _set_epoch(lead: float, fractional: bool) -> float:
    """The epoch to set, taken now (just before sending): host now +
    ``lead`` (the one-way trip). A whole-second form waits until host now +
    ``lead`` is a whole second, so the set lands on that second.
    """
    now = _now()
    if fractional:
        return now + lead
    target = math.ceil(now + lead)
    wait = target - lead - now
    if wait > 0:
        _sleep(wait)
    return float(target)


def _shell_lead_s(key: str, shell: Shell) -> float:
    """Half the persistent shell's round trip: from the newest sample it
    measured, else one no-op query timed now (shell lock held).
    """
    with _LOCK:
        last = _LAST.get(key)
    if last is not None and last.get("method") == "shell":
        return (last.get("err_ms") or 0.0) / 1000
    _lines, t0, t1 = shell.query(f"echo {_END}")
    return (t1 - t0) / 2


def _run_set(
    serial: str | None,
    prefix: str,
    form: tuple[Callable[[float], str], bool],
    send: Send | None,
) -> str | None:
    """Run one ``date`` set command: over the persistent shell; only when it
    is dead, one-shot ``adb shell`` through ``send`` (default
    :func:`_default_send`) with the lead from that path's own round trip.
    The target epoch is taken after the shell lock, just before sending.
    Returns the command sent, ``None`` when neither path could send it.
    """
    from sandroid.core.adb_utils import device_shell_command

    make, fractional = form
    key = _key(serial)
    with _shell_lock(key):
        try:
            shell = _shell(serial)
            command = prefix + make(_set_epoch(_shell_lead_s(key, shell), fractional))
            shell.query(f"{command} >/dev/null 2>&1; echo {_END}")
            return command
        except (ShellDeadError, OSError, ValueError, SystemExit) as exc:
            logger.debug("device clock: shell set for %s failed: %s", serial, exc)
            _SHELLS.pop(key, None)
    send = send or _default_send(serial)
    try:
        t0 = _now()
        send(device_shell_command("true"))
        lead = (_now() - t0) / 2
        command = prefix + make(_set_epoch(lead, fractional))
        send(device_shell_command(f"{command} >/dev/null 2>&1"))
        return command
    except (Exception, SystemExit):
        logger.debug("device clock: one-shot set failed", exc_info=True)
        return None


def suggestion_command(host_now: float, off_mono: float) -> str:
    """``cmd time_detector suggest_telephony_time`` with the pair computed
    on the host (integer ms; the device shell's ``$(( ))`` is 32-bit):
    ``unix_epoch_time`` = host now, ``elapsed_realtime`` = the device's
    CLOCK_BOOTTIME then (= CLOCK_MONOTONIC on the emulator: the guest never
    suspends) = host now - ``off_mono``. The pair describes one instant, so
    the adb latency does not matter.
    """
    epoch_ms = round(host_now * 1000)
    elapsed_ms = round((host_now - off_mono) * 1000)
    return (
        "cmd time_detector suggest_telephony_time --slot_index 0 "
        f"--elapsed_realtime {elapsed_ms} --unix_epoch_time {epoch_ms}"
    )


def _run_suggest(serial: str | None, send: Send | None) -> tuple[str | None, bool]:
    """Inject a telephony time suggestion (over the persistent shell, else
    one-shot ``send``) from the current-world sample's ``off_mono``.
    Returns ``(command, injected)``: ``command`` is the command sent
    (``None`` when nothing was sent: no current-world ``off_mono``, i.e. no
    root, or the one-shot send failed), ``injected`` whether the detector
    reported it ``injected`` (``cmd`` missing or failing: ``False``).
    """
    from sandroid.core.adb_utils import device_shell_command

    key = _key(serial)
    lines: list[str] | None = None
    command = None
    with _shell_lock(key):
        sample = last_sample(serial, current_world=True)
        off_mono = (sample or {}).get("off_mono")
        if not isinstance(off_mono, (int, float)):
            return None, False
        try:
            command = suggestion_command(_now(), off_mono)
            lines, _t0, _t1 = _shell(serial).query(f"{command} 2>&1; echo {_END}")
        except (ShellDeadError, OSError, ValueError, SystemExit) as exc:
            logger.debug(
                "device clock: shell suggestion for %s failed: %s", serial, exc
            )
            _SHELLS.pop(key, None)
    if lines is None:
        try:
            command = suggestion_command(_now(), off_mono)
            stdout, _stderr = (send or _default_send(serial))(
                device_shell_command(f"{command} 2>&1")
            )
            lines = str(stdout or "").splitlines()
        except (Exception, SystemExit):
            logger.debug("device clock: one-shot suggestion failed", exc_info=True)
            return None, False
    if any("injected" in line for line in lines):
        return command, True
    logger.debug("device clock: time suggestion not taken: %s", lines)
    return command, False


def sync_method(command: str | None) -> str | None:
    """How a sync set the clock: ``"time_detector"`` (a telephony time
    suggestion; it replaces the stale snapshot suggestion, so it sticks),
    ``"date"`` (Android may re-apply the snapshot's stale time on its next
    time suggestion) or ``None`` (nothing applied).
    """
    if not command:
        return None
    return "time_detector" if command.startswith("cmd time_detector") else "date"


def _applied(before: dict, after: dict) -> bool:
    """The wall offset moved more than the measurements' error: a ``date``
    took effect (whether or not it landed within tolerance).
    """
    err = ((before.get("err_ms") or 0.0) + (after.get("err_ms") or 0.0)) / 1000
    return abs(after["off_wall"] - before["off_wall"]) > SYNC_TOLERANCE_S + err


def sync(serial: str | None = None, send: Send | None = None) -> dict | None:
    """Set the device wall clock to the host clock and measure again.

    Over the persistent shell (``send``: the one-shot fallback when it is
    dead). First a telephony time suggestion (:func:`suggestion_command`;
    with root CLOCK_MONOTONIC only): ``date`` alone does not stick, since
    after a snapshot load time_detector still holds the snapshot's stale
    NITZ suggestion and re-applies it on the next time suggestion. When it
    is not taken (no ``cmd``, ignored below the detector's threshold, off
    by more than :data:`SYNC_TOLERANCE_S`): ``date``, the fractional
    ``date -u @S.fff`` first; the next form / ``su 0``
    only when the previous command evidently did not apply (the offset did
    not move); one corrective retry when it applied but missed
    :data:`SYNC_TOLERANCE_S`. Returns the last sample with ``ok``
    (``|off_wall| <= SYNC_TOLERANCE_S``), the ``command`` that applied and
    ``sets`` (time suggestions the detector took plus ``date`` commands
    issued; a suggestion that ``cmd`` rejected or lacks is not counted),
    ``None`` if the device never answered.
    Writes nothing; see :func:`after_snapshot_load`. CLOCK_MONOTONIC is
    untouched.
    """
    return _public(_sync(serial, send))


def _sync(
    serial: str | None = None, send: Send | None = None, before: dict | None = None
) -> dict | None:
    """:func:`sync` keeping the internal ``_host`` of the last sample;
    ``before`` is the sample the sync starts from (default: measured now).
    """
    serial = _target(serial)
    if before is None:
        before = _measure(serial, samples=SAMPLES_QUICK)
        if before is None:
            return None
    sets, step, landed, retried = 0, 0, None, False
    reference, after = before, None
    # 1. A telephony time suggestion: it also replaces the snapshot's stale
    # NITZ suggestion that time_detector would otherwise re-apply later.
    command, injected = _run_suggest(serial, send)
    if injected:
        sets += 1
        after = _measure(serial, samples=SAMPLES_QUICK)
        if after is None:
            return None
        if abs(after["off_wall"]) <= SYNC_TOLERANCE_S:
            return {**after, "ok": True, "command": command, "sets": sets}
        if _applied(reference, after):
            landed = command
        reference = after  # ignored / imprecise: ``date`` below
    # 2. ``date`` (no root CLOCK_MONOTONIC, no ``cmd``, or not taken).
    steps = [(prefix, form) for prefix in _SET_PREFIXES for form in _SET_FORMS]
    while step < len(steps):
        command = _run_set(serial, *steps[step], send)
        sets += command is not None
        after = _measure(serial, samples=SAMPLES_QUICK)
        if after is None:
            return None
        if abs(after["off_wall"]) <= SYNC_TOLERANCE_S:
            return {**after, "ok": True, "command": command, "sets": sets}
        applied = command is not None and _applied(reference, after)
        if applied:
            landed = command
        if retried:
            break
        reference = after
        if applied:
            retried = True  # landed imprecisely: once more, the same form
        else:
            step += 1  # did not take: the next form / prefix
    if after is None:
        return None
    return {**after, "ok": False, "command": landed, "sets": sets}


def sync_enabled() -> bool:
    """``emulator.sync_device_clock`` of the live config (default on)."""
    try:
        from sandroid.config import get_config

        return bool(get_config().emulator.sync_device_clock)
    except Exception:
        return True


def _sync_and_note(
    serial: str | None,
    before: dict,
    trigger: str,
    send: Send | None,
    where: str,
    **extra,
) -> dict | None:
    """:func:`_sync` from ``before``, then its ``reason: "sync"`` line
    (``trigger``, ``before_off_wall`` / ``after_off_wall`` / ``ok`` /
    ``command`` / ``sets`` / ``set_by``, see :func:`sync_method`). A failed
    sync, and one that only ``date`` applied, is warned about once per
    device.
    Returns the line (``None``: the device did not answer).
    """
    synced = _sync(serial, send, before)
    final = None
    if synced is not None:
        ok = bool(synced.pop("ok"))
        command = synced.pop("command", None)
        sets = synced.pop("sets", 0)
        set_by = sync_method(command)
        final = _note(
            synced,
            "sync",
            always=True,
            trigger=trigger,
            before_off_wall=before["off_wall"],
            after_off_wall=synced["off_wall"],
            ok=ok,
            command=command,
            sets=sets,
            set_by=set_by,
            **extra,
        ) or {**_public(synced), "ok": ok, "set_by": set_by}
        if ok and set_by == "date":
            warn_once(
                "sync-date",
                serial,
                f"Device clock set to host time {where} with `date` (Android's "
                f"time service did not take the suggestion): Android may reset "
                f"it to the snapshot's stale time on its next network-time "
                f"update. Clock jumps are recorded in the session timeline.",
            )
    if final is None or not final.get("ok"):
        warn_once(
            "sync",
            serial,
            f"Could not set the device clock to host time {where} (needs root "
            f"`date`); recording the offset in the session timeline instead.",
        )
    return final


def after_snapshot_load(
    name: str, serial: str | None = None, send: Send | None = None
) -> dict | None:
    """Record the clocks after a snapshot load; sync the wall clock if set.

    1. ``reason: "snapshot-load"`` (always ``jump: true``; ``sync_policy``:
       the setting): the restored, frozen clocks.
    2. With ``emulator.sync_device_clock`` on and the wall clock more than
       :data:`NOTABLE_S` off: :func:`sync`, then a ``reason: "sync"`` line
       (``trigger: "snapshot-load"``, ``before_off_wall`` /
       ``after_off_wall`` / ``ok`` / ``command`` / ``sets``). A failed sync
       is warned about once per device and the recording goes on.
    3. One WARNING per device when the wall clock is still more than
       :data:`NOTABLE_S` off afterwards.

    ``send`` is the one-shot fallback of the ``date`` commands. Returns the
    last line written (``None``: the device did not answer).
    """
    serial = _target(serial)
    policy = sync_enabled()
    final = loaded = record("snapshot-load", serial, snapshot=name, sync_policy=policy)
    if loaded is None:
        return None
    if policy and notable(loaded):
        final = (
            _sync_and_note(
                serial,
                loaded,
                "snapshot-load",
                send,
                f"after loading snapshot '{name}'",
                snapshot=name,
            )
            or final
        )
    if notable(final):
        warn_once(
            "offset",
            serial,
            f"Device clock is {format_offset(device_minus_host(final))} off the "
            f"host after loading snapshot '{name}'. Device times (file mtimes, "
            f"database values) are on the device clock; the offset is "
            f"recorded in the session timeline.",
        )
    return final


def _selinux_enforcing(serial: str | None) -> bool:
    """``getenforce`` says Enforcing (over the persistent shell, else one
    one-shot ``adb shell``). Unknown counts as not Enforcing.
    """
    from sandroid.core.adb_utils import device_shell_command

    key = _key(serial)
    with _shell_lock(key):
        try:
            lines, _t0, _t1 = _shell(serial).query(f"getenforce; echo {_END}")
            return any(line.strip().lower() == "enforcing" for line in lines)
        except (ShellDeadError, OSError, ValueError, SystemExit):
            _SHELLS.pop(key, None)
    try:
        stdout, _stderr = _default_send(serial)(device_shell_command("getenforce"))
    except (Exception, SystemExit):
        return False
    return str(stdout or "").strip().lower() == "enforcing"


def _session_start_sync(
    serial: str | None, before: dict | None = None, send: Send | None = None
) -> dict | None:
    """The pending session-start sync of ``serial`` (once): from ``before``
    or a fresh sample, only while the wall clock is more than
    :data:`NOTABLE_S` off. Returns the ``sync`` line or ``None``.
    """
    key = _key(serial)
    with _LOCK:
        if key not in _PENDING_SYNC:
            return None
        _PENDING_SYNC.discard(key)
    if before is None:
        before = _measure(serial, samples=SAMPLES_QUICK)
        if before is None or before.get("_stale") or not notable(before):
            return None
    return _sync_and_note(serial, before, "session-start", send, "at session start")


def after_device_connect(
    serial: str | None = None, send: Send | None = None
) -> dict | None:
    """Record the clocks when a device is connected; sync the wall clock if set.

    1. ``reason: "device-connect"`` with ``sync_policy`` (the setting),
       always written.
    2. With ``emulator.sync_device_clock`` on and the wall clock more than
       :data:`NOTABLE_S` off (an emulator booted from a snapshot): a
       session-start sync, ``reason: "sync"`` / ``trigger:
       "session-start"``. While SELinux is still Enforcing (root ``date``
       and ``/proc/timer_list`` may be denied) the sync waits for
       :func:`after_selinux_step` (startup's ``setenforce 0``).

    With the setting off it only records. Returns the last line written
    (``None``: the device did not answer, or the sync waits).
    """
    serial = _target(serial)
    policy = sync_enabled()
    connected = record("device-connect", serial, sync_policy=policy)
    if connected is None or not (policy and notable(connected)):
        return connected
    with _LOCK:
        _PENDING_SYNC.add(_key(serial))
    if _selinux_enforcing(serial):
        return None
    return _session_start_sync(serial, connected, send) or connected


def _background(target: Callable, name: str, *args) -> None:
    threading.Thread(target=target, args=args, name=name, daemon=True).start()


def after_device_connect_async(serial: str | None = None) -> None:
    """:func:`after_device_connect` on a daemon thread (never blocks)."""
    _background(after_device_connect, "device-clock-connect", _target(serial))


def after_selinux_step(serial: str | None = None) -> None:
    """Startup's SELinux step is done: run a session-start sync that waited
    for it (on a daemon thread; nothing to do without one).
    """
    with _LOCK:
        if not _PENDING_SYNC:
            return
    _background(_session_start_sync, "device-clock-sync", _target(serial))


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
        _BARRIER.clear()
        _PENDING_SYNC.clear()


__all__ = [
    "DRIFT_MS_PER_S",
    "EPOCH_REASONS",
    "JUMP_S",
    "NOTABLE_S",
    "QUERY",
    "REUSE_S",
    "SAMPLES",
    "SAMPLES_QUICK",
    "SHELL_FACTORY",
    "SYNC_TOLERANCE_S",
    "WARMUP",
    "Shell",
    "ShellDeadError",
    "after_device_connect",
    "after_device_connect_async",
    "after_selinux_step",
    "after_snapshot_load",
    "begin_epoch",
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
    "seed",
    "suggestion_command",
    "sync",
    "sync_enabled",
    "to_host_time",
    "warn_once",
]
