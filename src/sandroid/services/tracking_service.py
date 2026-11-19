"""Tracking v1: what the analyst does on the device, as session-timeline lines.

Tracking turns the device's raw input and UI into ``input``, ``screen``,
``shot`` and ``tracking`` lines (DESIGN_FINAL §4, §12):

* ONE shared ``getevent -t`` reader per device (:class:`GeteventStream`,
  ref-counted; Record leases the same stream). Every raw line is appended to
  ``<timeline folder>/tracking/raw/getevent.txt`` (0600); input lines point
  into it with ``ref.raw = "tracking/raw/getevent.txt#L<a>-L<b>"``.
* :class:`TouchDecoder` decodes multitouch protocol B; at the last finger-up a
  gesture becomes ``input/tap|long_press|swipe|gesture``, EV_KEY of a named
  system key becomes ``input/key``. Times are the kernel event times
  (``dev_mono``, the device CLOCK_MONOTONIC shared with the UI helper).
* At finger-down the UI helper (:mod:`sandroid.core.uihelper`) is asked
  ``node_at`` (and a before-tap screenshot); the input line goes out at UP
  after waiting at most :data:`NODE_WAIT_S` for the element and (usually
  already back) at most :data:`BEFORE_TAP_WAIT_S` for the before-tap capture,
  whose fate it states in ``data.before_shot`` (taken / skipped / late /
  failed / no_helper / off); never for the a11y confirmation. Shots and
  confirmations follow as their own lines with ``ref.of`` = the input seq.
* Helper a11y events give ``input/text`` (coalesced per field; ``sensitive``
  for password fields; the summary never carries the text), ``input/confirm``
  and ``screen/window``; a logcat reader gives ``screen/activity`` when the
  helper cannot.
* Screenshots are stored once per content (sha256) and timeline folder
  under ``tracking/shots/<seq>_<trigger>.png`` (``<sha16>_<trigger>.png``
  while the timeline holds lines back and the seq is not known yet). A
  before-tap capture is taken only when none is in flight and dropped
  (``before_shot: "late"``) when it was captured after the finger-up.
* Privacy: taps (and their shots) while a password field has the focus, on
  a password field or on the keyboard are ``sensitive`` (masked by readers,
  never suppressed); a keyboard key's label is never written.

:class:`NetFlowSource` (independent of the Tracking toggle) turns every
finished mitmproxy flow into one ``net/flow`` / ``net/tls-fail`` line.

Threads: the getevent and helper reader threads only decode and queue; every
device round trip runs on a small daemon lane; :func:`timeline.emit` never
blocks. Nothing here touches the UI.
"""

from __future__ import annotations

import atexit
import contextlib
import hashlib
import logging
import os
import queue
import re
import subprocess
import threading
import time
import uuid
from collections import deque
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from sandroid.core.frames import (  # R1 metric, re-exported
    SAME_MAX_DIFF,
    frame_distance,
    same_screen,
)

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

#: Device file holding the shell pid of OUR getevent (``exec`` keeps the pid).
PIDFILE = "/data/local/tmp/sandroid_getevent.pid"
RAW_DIR = "tracking/raw"
SHOTS_DIR = "tracking/shots"
GETEVENT_FILE = "getevent.txt"
HELPER_FILE = "helper.jsonl"
#: How long the input line waits at UP for the helper's ``node_at``.
NODE_WAIT_S = 0.3
#: An a11y CLICKED within this window after UP confirms the tap.
CONFIRM_WINDOW_MS = 1_000.0
#: Logcat activity lines are only written when no a11y window line came
#: within this many seconds (with a FULL helper).
LOGCAT_GRACE_S = 0.5
#: A screen-change shot claims ``data.unchanged`` only when the pre-change
#: frame was hashed at most this long after the screen event; a later hash
#: may already show the new screen (or a transition frame).
SCREEN_BEFORE_MAX_MS = 300.0
#: A logcat ``screen/activity`` line (``wm_set_resumed_activity``) fires
#: before the new activity draws, under load seconds before: its shot waits
#: this many times ``settle_max_ms`` for the change, at most
#: :data:`LOGCAT_SETTLE_CAP_MS`. A11y window lines are in step with drawing.
LOGCAT_SETTLE_FACTOR = 2.5
LOGCAT_SETTLE_CAP_MS = 8_000.0
#: Full captures a screen-change shot takes at most while it settles: one per
#: distinct new frame (the fallback, stored ``stable:false`` when the wait is
#: cut short). Each one blocks the helper for a PNG encode.
SHOT_FALLBACK_MAX = 2
#: Frame hashes seen recently (``(device s | None, host start, host end,
#: hash)``): the "old screen" references of a screen-change shot.
FRAMES_KEPT = 128
#: An input received this long (host) before a screen event is never "next";
#: one received this long after it always is (a snapshot load can rewind the
#: device clock in between).
INPUT_SKEW_S = 1.0
#: Without a stored before-tap shot, the cached frame closest to an input's
#: finger-down (within this many seconds, before its finger-up) is its
#: before-tap frame: the screen the input acted on.
BEFORE_TAP_FRAME_S = 0.25
#: How long a screen-change decision waits for a before-tap capture.
BEFORE_TAP_WAIT_S = 2.0
#: R1 perceptual "same screen": :mod:`sandroid.core.frames` (one
#: implementation, shared with the report's R4 gap-fill).
#: Device and host lags that differ by more than this are from different
#: clock epochs (snapshot load): only the host lag counts.
CLOCK_SANE_MS = 5_000.0
#: Max points of a swipe path.
PATH_MAX = 32
#: Default MT axis maximum (virtio multitouch).
MT_MAX = 32_767
#: Net doorbell debounce.
NET_DEBOUNCE_S = 0.2
NET_TAGS = ("[FLOW]|", "[TLS_FAIL]|", "[FLOW_ERR]|")
#: getevent restart back-off while a lease is held.
RESTART_BACKOFF_S = (1.0, 2.0, 4.0, 8.0, 10.0)
#: How long a new session's start waits for the previous helper to stop.
HELPER_STOP_WAIT_S = 20.0
#: A new contact after this long without any event of its node closes a
#: gesture whose finger-up was lost (another slot still looks held).
GESTURE_IDLE_S = 10.0
#: After ``SYN_DROPPED`` events are ignored up to the next ``SYN_REPORT``;
#: an event this much later ends that early (the report itself was lost).
DROP_RESYNC_S = 0.5

#: ``[   26404.737324] /dev/input/event1: 0003 0039 00000000``
GE_LINE = re.compile(
    r"^\[\s*(\d+\.\d+)\]\s+(?:(/dev/\S+):\s+)?"
    r"([0-9a-fA-F]{4})\s+([0-9a-fA-F]{4})\s+([0-9a-fA-F]{8})\s*$"
)
#: ``  4553.443  1543  1580 I wm_set_resumed_activity: [0,pkg/.Cls,reason]``
LOGCAT_ACTIVITY = re.compile(
    r"^\s*(\d+\.\d+)\s+\d+\s+\d+\s+\w\s+wm_set_resumed_activity\s*:\s*"
    r"\[\s*\d+\s*,\s*([^,\]/\s]+)/([^,\]\s]+)"
)

EV_SYN, EV_KEY, EV_ABS = 0, 1, 3
SYN_REPORT, SYN_DROPPED = 0, 3
ABS_MT_SLOT, ABS_MT_X, ABS_MT_Y, ABS_MT_TRACKING_ID = 0x2F, 0x35, 0x36, 0x39

#: Named non-character keys. Character keys (a host keyboard typing into the
#: emulator) are NOT written as lines: they would spell out passwords; typed
#: text comes from the helper as ``input/text`` (sensitive when it should be).
KEY_NAMES: dict[int, str] = {
    1: "ESCAPE",
    14: "DEL",
    15: "TAB",
    28: "ENTER",
    102: "HOME",
    113: "MUTE",
    114: "VOLUME_DOWN",
    115: "VOLUME_UP",
    116: "POWER",
    139: "MENU",
    142: "SLEEP",
    143: "WAKEUP",
    158: "BACK",
    172: "HOME",
    212: "CAMERA",
    217: "SEARCH",
    580: "APP_SWITCH",
}


# ---------------------------------------------------------------------------
# getevent decoding
# ---------------------------------------------------------------------------


def parse_getevent(line: str) -> tuple[float, str | None, int, int, int] | None:
    """``(ts_s, device, type, code, value)`` of a ``getevent -t`` line (value
    signed 32 bit), or None for anything else (device listing, garbage).
    """
    m = GE_LINE.match(line.strip())
    if m is None:
        return None
    value = int(m[5], 16)
    if value & 0x80000000:
        value -= 1 << 32
    return float(m[1]), m[2], int(m[3], 16), int(m[4], 16), value


@dataclass
class Gesture:
    """One finger-down .. last-finger-up (or one key press), raw units.

    ``x0/y0`` are the MT values at down (an axis the kernel has not reported
    since the stream started is ``None`` until its first value arrives, which
    then becomes the origin), ``x1/y1`` the last values; ``path`` holds
    ``(x, y, t_s)`` samples of the first pointer with both axes known.
    ``dropped``: the kernel dropped events (``SYN_DROPPED``), or the gesture
    was closed by a new contact; its end is not the real finger-up.
    """

    dev: str
    t_down: float
    line_a: int
    slot: int = 0
    x0: int | None = None
    y0: int | None = None
    x1: int | None = None
    y1: int | None = None
    uncertain: bool = False
    t_up: float | None = None
    line_b: int | None = None
    pointers: int = 1
    path: list[tuple[int, int, float]] = field(default_factory=list)
    key_code: int | None = None
    host_recv: float = 0.0
    gid: int = 0
    dropped: bool = False

    @property
    def xy_known(self) -> bool:
        """Both axes of the origin were seen."""
        return self.x0 is not None and self.y0 is not None


@dataclass
class DecodedEvent:
    """``kind``: ``down`` (first finger), ``end`` (last finger up), ``key``."""

    kind: str
    gesture: Gesture


class _DevState:
    def __init__(self) -> None:
        self.slot = 0
        self.slots: dict[int, dict[str, Any]] = {}
        self.frame_start: int | None = None
        self.downs: dict[int, float] = {}
        self.ups: dict[int, float] = {}
        self.lost: set[int] = set()  # active slots that got a new tracking id
        self.moved: set[int] = set()
        self.active: set[int] = set()
        self.gesture: Gesture | None = None
        self.keys: dict[int, tuple[float, int]] = {}
        self.dropping: float | None = None  # SYN_DROPPED time while skipping
        self.last_ts: float | None = None
        self.stale = False


def _is_btn(code: int) -> bool:
    """``BTN_*`` codes (BTN_TOUCH, BTN_TOOL_*, gamepad, trigger-happy);
    ``KEY_*`` above 0xff (KEY_APPSELECT = 580 ...) are real keys.
    """
    return 0x100 <= code <= 0x15F or 0x2C0 <= code <= 0x2FF


class TouchDecoder:
    """Incremental decoder of all-nodes ``getevent -t`` lines.

    Multitouch protocol B per device node; a gesture opens at the first
    tracking id and closes when no slot is active any more. ``uncertain`` is
    set when X or Y of the pointer was never seen since the stream (re)started
    (the kernel does not repeat unchanged axis values): such an axis is
    ``None``, never 0. One decoder lives as long as its getevent stream (axis
    values seen while Tracking was off still count).

    Lost events: ``SYN_DROPPED`` closes the open gesture (``dropped``) and
    every event up to the next ``SYN_REPORT`` is ignored (at most
    :data:`DROP_RESYNC_S`); all contacts and axis values are forgotten. A new tracking id on a slot that is still
    active (its finger-up was lost) closes the open gesture first, and so
    does a new contact after :data:`GESTURE_IDLE_S` without any event while
    another slot still looks held.
    """

    def __init__(self) -> None:
        self._devs: dict[str, _DevState] = {}
        self._gid = 0

    def reset(self) -> None:
        """Forget everything (the stream restarted)."""
        self._devs.clear()

    def feed(self, line: str, line_no: int = 0) -> list[DecodedEvent]:
        """Decode one raw line; the events it completes."""
        if line.startswith("add device"):
            self.reset()
            return []
        parsed = parse_getevent(line)
        if parsed is None:
            return []
        ts, dev, typ, code, val = parsed
        dev = dev or "-"
        st = self._devs.setdefault(dev, _DevState())
        idle = None if st.last_ts is None else ts - st.last_ts
        st.last_ts = ts
        if st.dropping is not None:
            if typ == EV_SYN and code == SYN_REPORT:
                st.dropping = None
                return []
            if ts - st.dropping < DROP_RESYNC_S:
                return []
            st.dropping = None  # a later frame: the report never came
        if typ == EV_SYN and code == SYN_DROPPED:
            return self._dropped(st, ts, line_no)
        if st.frame_start is None:
            st.frame_start = line_no
        if typ == EV_ABS:
            self._abs(st, ts, code, val, idle)
            return []
        if typ == EV_KEY:
            return self._key(st, dev, ts, code, val, line_no)
        if typ == EV_SYN and code == SYN_REPORT:
            return self._syn(st, dev, ts, line_no)
        return []

    def _dropped(self, st: _DevState, ts: float, line_no: int) -> list[DecodedEvent]:
        out: list[DecodedEvent] = []
        g = st.gesture
        if g is not None:
            g.dropped = g.uncertain = True
            g.t_up = ts
            g.line_b = line_no
            out.append(DecodedEvent("end", g))
        st.gesture = None
        st.dropping = ts
        for s in st.slots.values():
            s.update(tid=-1, x=None, y=None)
        st.active.clear()
        st.downs.clear()
        st.ups.clear()
        st.lost.clear()
        st.moved.clear()
        st.keys.clear()
        st.frame_start = None
        st.stale = False
        return out

    @staticmethod
    def _abs(st: _DevState, ts: float, code: int, val: int, idle: float | None) -> None:
        if code == ABS_MT_SLOT:
            st.slot = val
            return
        s = st.slots.setdefault(st.slot, {"x": None, "y": None, "tid": -1})
        if code == ABS_MT_TRACKING_ID:
            if val >= 0:
                if s["tid"] >= 0 and val != s["tid"] and st.slot in st.active:
                    st.lost.add(st.slot)  # its finger-up never came
                elif (
                    st.gesture is not None
                    and st.slot not in st.active
                    and idle is not None
                    and idle >= GESTURE_IDLE_S
                ):
                    st.stale = True  # another slot looks held for ever
                s["tid"] = val
                st.downs[st.slot] = ts
            elif s["tid"] >= 0:
                s["tid"] = -1
                st.ups[st.slot] = ts
        elif code == ABS_MT_X:
            s["x"] = val
            st.moved.add(st.slot)
        elif code == ABS_MT_Y:
            s["y"] = val
            st.moved.add(st.slot)

    def _key(
        self, st: _DevState, dev: str, ts: float, code: int, val: int, line_no: int
    ) -> list[DecodedEvent]:
        if _is_btn(code):  # BTN_TOUCH on the touch node, ...
            return []
        if val == 1:
            st.keys[code] = (ts, line_no)
            return []
        if val != 0 or code not in st.keys:
            return []
        t_down, line_a = st.keys.pop(code)
        self._gid += 1
        g = Gesture(
            dev=dev,
            t_down=t_down,
            line_a=line_a,
            t_up=ts,
            line_b=line_no,
            key_code=code,
            gid=self._gid,
        )
        return [DecodedEvent("key", g)]

    @staticmethod
    def _track(g: Gesture, s: dict, ts: float) -> None:
        """Follow the gesture's pointer: the first value of an axis unseen
        at down becomes its origin; path samples need both axes.
        """
        if g.x0 is None and s.get("x") is not None:
            g.x0 = s["x"]
        if g.y0 is None and s.get("y") is not None:
            g.y0 = s["y"]
        g.x1 = s["x"] if s.get("x") is not None else g.x1
        g.y1 = s["y"] if s.get("y") is not None else g.y1
        if g.x1 is not None and g.y1 is not None:
            g.path.append((g.x1, g.y1, ts))

    def _close(
        self, st: _DevState, ts: float, line_no: int, out: list[DecodedEvent]
    ) -> None:
        """End the open gesture early (lost finger-up)."""
        g = st.gesture
        if g is None:
            return
        g.dropped = True
        g.t_up = ts
        g.line_b = max(g.line_a, (st.frame_start or line_no) - 1)
        out.append(DecodedEvent("end", g))
        st.gesture = None

    def _syn(
        self, st: _DevState, dev: str, ts: float, line_no: int
    ) -> list[DecodedEvent]:
        out: list[DecodedEvent] = []
        if st.lost or st.stale:
            st.active -= st.lost
            if st.stale:
                st.active.clear()
            if st.gesture is not None and (
                st.stale or st.gesture.slot in st.lost or not st.active
            ):
                st.active.clear()
                self._close(st, ts, line_no, out)
            st.lost.clear()
            st.stale = False
        for slot, t_down in sorted(st.downs.items()):
            s = st.slots.get(slot, {})
            st.active.add(slot)
            if st.gesture is None:
                self._gid += 1
                x, y = s.get("x"), s.get("y")
                st.gesture = Gesture(
                    dev=dev,
                    t_down=t_down,
                    line_a=st.frame_start if st.frame_start is not None else line_no,
                    slot=slot,
                    x0=x,
                    y0=y,
                    x1=x,
                    y1=y,
                    uncertain=x is None or y is None,
                    gid=self._gid,
                )
                if x is not None and y is not None:
                    st.gesture.path.append((x, y, t_down))
                out.append(DecodedEvent("down", st.gesture))
            st.gesture.pointers = max(st.gesture.pointers, len(st.active))
        g = st.gesture
        if g is not None and g.slot in st.moved and g.slot not in st.downs:
            self._track(g, st.slots.get(g.slot, {}), ts)
        for slot in st.ups:
            st.active.discard(slot)
            if g is not None and slot == g.slot:
                s = st.slots.get(slot, {})
                if g.x0 is None and s.get("x") is not None:
                    g.x0 = s["x"]
                if g.y0 is None and s.get("y") is not None:
                    g.y0 = s["y"]
                if s.get("x") is not None:
                    g.x1 = s["x"]
                if s.get("y") is not None:
                    g.y1 = s["y"]
        if g is not None and st.ups and not st.active:
            g.t_up = ts
            g.line_b = line_no
            out.append(DecodedEvent("end", g))
            st.gesture = None
        st.downs.clear()
        st.ups.clear()
        st.moved.clear()
        st.frame_start = None
        return out


@dataclass
class Geometry:
    """Natural screen size, rotation and per-node MT maxima."""

    width: int = 0
    height: int = 0
    rotation: int = 0
    maxima: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def screen(self) -> tuple[int, int]:
        """Screen px in the current rotation."""
        if self.rotation % 2:
            return self.height, self.width
        return self.width, self.height

    def to_px(self, dev: str, x_raw: int, y_raw: int) -> tuple[int, int]:
        """MT raw values of ``dev`` -> screen px in the current rotation."""
        mx, my = self.maxima.get(dev, (MT_MAX, MT_MAX))
        w, h = self.width or 1, self.height or 1
        x = min(max(round(x_raw * w / (mx or MT_MAX)), 0), w - 1)
        y = min(max(round(y_raw * h / (my or MT_MAX)), 0), h - 1)
        rot = self.rotation % 4
        if rot == 1:
            return y, w - 1 - x
        if rot == 2:
            return w - 1 - x, h - 1 - y
        if rot == 3:
            return h - 1 - y, x
        return x, y


def parse_getevent_p(text: str) -> dict[str, tuple[int, int]]:
    """``{device: (max_x, max_y)}`` of every node with MT position axes."""
    out: dict[str, tuple[int, int]] = {}
    dev = None
    mx = my = None
    cur = re.compile(r"^add device \d+:\s*(\S+)")
    axis = re.compile(r"\b(0035|0036)\s*:.*?\bmax\s+(-?\d+)")
    for line in text.splitlines():
        m = cur.match(line.strip())
        if m:
            if dev and mx is not None and my is not None:
                out[dev] = (mx, my)
            dev, mx, my = m[1], None, None
            continue
        a = axis.search(line)
        if a and dev:
            if a[1] == "0035":
                mx = int(a[2])
            else:
                my = int(a[2])
    if dev and mx is not None and my is not None:
        out[dev] = (mx, my)
    return out


def parse_wm_size(text: str) -> tuple[int, int] | None:
    """``wm size``: the override size if any, else the physical size."""
    found: dict[str, tuple[int, int]] = {}
    for line in text.splitlines():
        m = re.match(r"\s*(Physical|Override) size:\s*(\d+)x(\d+)", line)
        if m:
            found[m[1]] = (int(m[2]), int(m[3]))
    return found.get("Override") or found.get("Physical")


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


class _Lane:
    """One daemon worker thread with a FIFO queue (never blocks exit)."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._q: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def submit(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Future:
        fut: Future = Future()
        self._q.put((fut, fn, args, kwargs))
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(
                    target=self._run, name=self._name, daemon=True
                )
                self._thread.start()
        return fut

    def drain(self, timeout: float) -> bool:
        """Wait until everything queued so far ran (True) or ``timeout``."""
        if threading.current_thread() is self._thread:
            return True
        try:
            self.submit(lambda: None).result(timeout)
        except FutureTimeout:
            return False
        return True

    def _run(self) -> None:
        while True:
            fut, fn, args, kwargs = self._q.get()
            if not fut.set_running_or_notify_cancel():
                continue
            try:
                fut.set_result(fn(*args, **kwargs))
            except BaseException as exc:
                logger.debug(f"tracking lane {self._name}: {exc}", exc_info=True)
                fut.set_exception(exc)


def _default_run(argv: list[str], timeout: float = 10.0) -> tuple[int, bytes]:
    try:
        proc = subprocess.run(
            argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug(f"tracking: {argv[:4]} failed: {exc}")
        return -1, b""
    return proc.returncode, proc.stdout or b""


def _base_argv(serial: str) -> list[str]:
    from sandroid.core.adb import Adb

    return Adb.base_argv(serial)


def _config() -> Any:
    """The live ``TrackingConfig`` (read at every trigger)."""
    try:
        from sandroid.config import get_config

        return get_config().tracking
    except Exception:
        from sandroid.config.schema import TrackingConfig

        return TrackingConfig()


def _short_cls(cls: str | None) -> str:
    return (cls or "").rsplit(".", 1)[-1] or "?"


def _short_rid(rid: str | None) -> str | None:
    if not rid:
        return None
    return rid.split(":id/", 1)[-1]


def _clip(text: str, n: int = 60) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _field_name(node: dict) -> str:
    """A field's name that is never its content (hint/desc/rid/class)."""
    for key in ("hint", "desc", "tooltip", "pane"):
        if node.get(key):
            return _clip(node[key], 40)
    return _short_rid(node.get("rid")) or _short_cls(node.get("cls"))


def _private(node: dict) -> bool:
    return bool(node.get("password") or node.get("editable"))


def _node_label(answer: dict, node: dict) -> str | None:
    if _private(node):
        return _field_name(node)
    label = answer.get("label") if answer.get("target") is node else None
    for value in (node.get("text"), node.get("desc"), label):
        if value:
            return _clip(value)
    return _short_rid(node.get("rid"))


def _same_node(a: dict | None, b: dict | None) -> bool:
    if not a or not b:
        return False
    for key in ("rid", "text"):
        if a.get(key) and b.get(key) and a[key] == b[key]:
            return True
    return bool(a.get("bounds")) and a.get("bounds") == b.get("bounds")


def _rel(path: Path, folder: Path) -> str:
    try:
        return os.path.relpath(path, folder).replace(os.sep, "/")
    except ValueError:
        return str(path)


def _emit(src: str, kind: str, **kw: Any) -> int | None:
    from sandroid.core import timeline

    try:
        return timeline.emit(src, kind, **kw)
    except Exception:
        logger.debug("tracking: emit failed", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# the shared getevent reader
# ---------------------------------------------------------------------------


class GeteventStream:
    """The ONE ``getevent -t`` of a device, shared by Tracking and Record.

    Leases are counted: :meth:`TrackingService.getevent` takes one, every
    :meth:`release` gives one back; the last release kills exactly the device
    pid this stream started (never a pattern kill, and only while that pid
    is still a getevent). Every line goes to :attr:`raw_path` (0600) before
    subscribers see ``(line, line_no, host_recv)``; ``line_no`` continues the
    existing file's count. The stream's ONE :class:`TouchDecoder` sees every
    line for the stream's whole life; :meth:`subscribe_events` subscribers get
    what it decodes. Subscribers run on the reader thread and must not block.

    ``registry_lock`` (the service's lock) makes the last :meth:`release`
    and the unregistering atomic against a new lease; a released stream is
    closed for good (:meth:`acquire` refuses it).
    """

    def __init__(
        self,
        serial: str,
        raw_path: Path,
        *,
        popen: Callable[..., Any] = subprocess.Popen,
        run: Callable[..., tuple[int, bytes]] = _default_run,
        argv: list[str] | None = None,
        on_closed: Callable[[GeteventStream], None] | None = None,
        backoff: tuple[float, ...] = RESTART_BACKOFF_S,
        registry_lock: Any = None,
    ) -> None:
        self.serial = serial
        self.raw_path = Path(raw_path)
        self._popen = popen
        self._run = run
        self._argv = argv
        self._on_closed = on_closed
        self._backoff = backoff
        self._registry_lock = registry_lock
        self._lock = threading.Lock()
        self._subs: list[Callable[[str, int, float], None]] = []
        self._esubs: list[Callable[[list[DecodedEvent], float], None]] = []
        self.decoder = TouchDecoder()
        self._closed = False
        self._refs = 0
        self._n = 0
        self._fh: Any = None
        self._proc: Any = None
        self._pid: int | None = None
        self._stop = threading.Event()
        self._reader: threading.Thread | None = None
        self._teardown: threading.Thread | None = None
        self.restarts = 0
        #: Set once a quit/stop is in progress: a getevent that ends is
        #: never respawned again.
        self._no_restart = False

    # -- leases --------------------------------------------------------------

    def acquire(self) -> bool:
        """Take a lease; the first one starts getevent. False on failure or
        once the last lease was released (the stream is closed for good).
        """
        with self._lock:
            if self._closed:
                return False
            self._refs += 1
            if self._refs > 1:
                return True
            try:
                self._open_raw()
                self._spawn()
            except Exception as exc:
                logger.warning(f"Tracking: getevent on {self.serial} failed: {exc}")
                self._refs -= 1
                self._close_raw()
                return False
            self._stop.clear()
            self._reader = threading.Thread(
                target=self._read_loop,
                name=f"getevent-{self.serial}",
                daemon=True,
            )
            self._reader.start()
        return True

    def release(self) -> None:
        """Give one lease back; the last one stops the reader (background).

        The last release closes the stream and unregisters it in one step
        under the registry lock, so a concurrent lease never revives it.
        """
        with self._registry_lock or contextlib.nullcontext():
            with self._lock:
                if self._refs <= 0:
                    return
                self._refs -= 1
                if self._refs:
                    return
                self._closed = True
                self._stop.set()
                proc, pid = self._proc, self._pid
            if self._on_closed is not None:
                self._on_closed(self)
        self._teardown = threading.Thread(
            target=self._kill,
            args=(proc, pid),
            name=f"getevent-stop-{self.serial}",
            daemon=True,
        )
        self._teardown.start()

    def suppress_restarts(self) -> None:
        """No respawn from now on (a quit is in progress): a getevent that
        ends (or is killed) stays ended.
        """
        self._no_restart = True

    def wait_closed(self, timeout: float = 5.0) -> None:
        """Wait for the background teardown of the last release."""
        t = self._teardown
        if t is not None and t is not threading.current_thread():
            t.join(timeout)

    @property
    def leases(self) -> int:
        return self._refs

    @property
    def alive(self) -> bool:
        proc = self._proc
        return self._refs > 0 and proc is not None and proc.poll() is None

    # -- subscribers ---------------------------------------------------------

    def subscribe(self, cb: Callable[[str, int, float], None]) -> Callable[[], None]:
        """Call ``cb(line, line_no, host_recv)`` for every line (reader thread;
        ``cb`` must not block). Returns the unsubscribe function.
        """
        with self._lock:
            self._subs.append(cb)

        def unsubscribe() -> None:
            with self._lock, contextlib.suppress(ValueError):
                self._subs.remove(cb)

        return unsubscribe

    def subscribe_events(
        self, cb: Callable[[list[DecodedEvent], float], None]
    ) -> Callable[[], None]:
        """Call ``cb(events, host_recv)`` for every line the stream's decoder
        turned into events (reader thread; ``cb`` must not block).
        """
        with self._lock:
            self._esubs.append(cb)

        def unsubscribe() -> None:
            with self._lock, contextlib.suppress(ValueError):
                self._esubs.remove(cb)

        return unsubscribe

    def line_no(self) -> int:
        """Lines in :attr:`raw_path` so far (the last line's number)."""
        with self._lock:
            return self._n

    def retarget(self, raw_path: Path) -> bool:
        """Write the raw log to ``raw_path`` from now on (the timeline folder
        changed while a lease kept the stream alive); line numbers continue
        that file's count. True when the path changed.
        """
        raw_path = Path(raw_path)
        with self._lock:
            if raw_path == self.raw_path or self._closed:
                return False
            old_path, old_fh, old_n = self.raw_path, self._fh, self._n
            self.raw_path = raw_path
            try:
                self._open_raw()
            except OSError as exc:
                logger.warning(f"Tracking: cannot write {raw_path}: {exc}")
                self.raw_path, self._fh, self._n = old_path, old_fh, old_n
                return False
            if old_fh is not None:
                with contextlib.suppress(OSError):
                    old_fh.close()
        return True

    # -- internals -----------------------------------------------------------

    def _open_raw(self) -> None:
        self.raw_path.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        last = b"\n"
        if self.raw_path.exists():
            with open(self.raw_path, "rb") as fh:
                while chunk := fh.read(1 << 20):
                    n += chunk.count(b"\n")
                    last = chunk[-1:]
        fd = os.open(self.raw_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with contextlib.suppress(OSError):
            self.raw_path.chmod(0o600)
        self._fh = os.fdopen(fd, "a", encoding="utf-8")
        if last != b"\n":  # a torn last line: close it, it counts
            self._fh.write("\n")
            self._fh.flush()
            n += 1
        self._n = n

    def _close_raw(self) -> None:
        fh, self._fh = self._fh, None
        if fh is not None:
            with contextlib.suppress(OSError):
                fh.close()

    def _spawn(self) -> None:
        argv = self._argv or [
            *_base_argv(self.serial),
            "shell",
            f"echo $$ > {PIDFILE}; exec getevent -t",
        ]
        self._pid = None
        self._proc = self._popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    def _read_pid(self) -> None:
        rc, out = self._run(
            [*_base_argv(self.serial), "shell", f"cat {PIDFILE}"], timeout=5.0
        )
        text = out.decode("utf-8", "replace").strip()
        if rc == 0 and text.isdigit():
            self._pid = int(text)

    def _read_loop(self) -> None:
        attempt = 0
        while not self._stop.is_set():
            proc = self._proc
            first = True
            stdout = getattr(proc, "stdout", None)
            if stdout is not None:
                for raw in iter(stdout.readline, b""):
                    host = time.time()
                    if isinstance(raw, bytes):
                        line = raw.decode("utf-8", "replace")
                    else:
                        line = str(raw)
                    line = line.rstrip("\r\n")
                    if first:
                        first = False
                        attempt = 0
                        threading.Thread(
                            target=self._read_pid, name="getevent-pid", daemon=True
                        ).start()
                    with self._lock:
                        if self._fh is None:
                            break
                        try:
                            self._fh.write(line + "\n")
                            self._fh.flush()
                        except (OSError, ValueError):
                            pass
                        self._n += 1
                        n = self._n
                        subs = list(self._subs)
                        esubs = list(self._esubs)
                    for cb in subs:
                        try:
                            cb(line, n, host)
                        except Exception:
                            logger.debug("getevent subscriber failed", exc_info=True)
                    try:
                        events = self.decoder.feed(line, n)
                    except Exception:
                        logger.debug("getevent decode failed", exc_info=True)
                        events = []
                    if not events:
                        continue
                    for ecb in esubs:
                        try:
                            ecb(events, host)
                        except Exception:
                            logger.debug("getevent subscriber failed", exc_info=True)
            with contextlib.suppress(Exception):
                proc.wait(timeout=1.0)
            with self._lock:
                if self._proc is proc and proc.poll() is not None:
                    self._pid = None  # dead: the pid may be reused
            if self._stop.is_set() or self._no_restart:
                break
            delay = self._backoff[min(attempt, len(self._backoff) - 1)]
            attempt += 1
            logger.info(
                f"Tracking: getevent on {self.serial} ended; restart in {delay:.0f}s"
            )
            if self._stop.wait(delay):
                break
            with self._lock:
                if self._stop.is_set() or self._no_restart:
                    break
                try:
                    self._spawn()
                    self.restarts += 1
                except Exception as exc:
                    logger.debug(f"getevent respawn failed: {exc}")

    def _kill(self, proc: Any, pid: int | None) -> None:
        # Only a pid that is still a getevent: a dead one may have been reused.
        src = str(pid) if pid else f"$(cat {PIDFILE} 2>/dev/null)"
        target = str(pid) if pid else "$p"
        self._run(
            [
                *_base_argv(self.serial),
                "shell",
                f'p={src}; [ -n "$p" ] && grep -q getevent '
                f"/proc/$p/cmdline 2>/dev/null && kill {target} 2>/dev/null; "
                f"rm -f {PIDFILE}",
            ],
            timeout=5.0,
        )
        if proc is not None:
            with contextlib.suppress(Exception):
                proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except Exception:
                with contextlib.suppress(Exception):
                    proc.kill()
        reader = self._reader
        if reader is not None and reader is not threading.current_thread():
            reader.join(2.0)
        with self._lock:
            if self._refs == 0:
                self._close_raw()


# ---------------------------------------------------------------------------
# Tracking
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrackingState:
    """A snapshot for the header / tools."""

    active: bool
    serial: str | None
    mode: str
    helper: str
    since: float | None
    inputs: int
    shots: int
    reason: str | None


@dataclass
class _Pending:
    node: Future | None = None
    shot: Future | None = None
    t0: float = 0.0
    #: ``data.before_shot`` decided at finger-down (``off`` / ``no_helper`` /
    #: ``skipped``); None: a capture was started, its result decides.
    shot_state: str | None = None


@dataclass
class _HelperSession:
    """What one helper's callbacks are bound to: a stale session's events
    are ignored, its status lines still describe that session.
    """

    gen: int
    serial: str
    mode: str
    helper: Any = None
    intervention_on: bool = False


class TrackingService:
    """The Tracking toggle (one device at a time) and the getevent registry.

    Args:
        popen: ``subprocess.Popen`` stand-in for the long-lived readers.
        run: ``run(argv, timeout) -> (rc, stdout bytes)`` for adb one-shots.
        helper_factory: ``(serial, mode, on_event, on_status, raw_log)`` ->
            a :class:`sandroid.core.uihelper.UiHelper`-like object.
        folder_fn: The timeline folder of a serial (tests).
        clock_record: ``(reason, serial)`` -> None (device clock sample).
    """

    def __init__(
        self,
        *,
        popen: Callable[..., Any] = subprocess.Popen,
        run: Callable[..., tuple[int, bytes]] | None = None,
        helper_factory: Callable[..., Any] | None = None,
        folder_fn: Callable[[str], Path] | None = None,
        clock_record: Callable[[str, str], None] | None = None,
    ) -> None:
        self._popen = popen
        self._run = run or _default_run
        self._helper_factory = helper_factory or self._make_helper
        self._folder_fn = folder_fn or self._timeline_folder
        self._clock_record = clock_record or self._record_clock
        self._lock = threading.RLock()
        #: Serialises start()/stop(); never held by state() (the header).
        self._op_lock = threading.Lock()
        self._streams: dict[str, GeteventStream] = {}
        self._closing: dict[str, GeteventStream] = {}
        #: A quit is in progress (:meth:`shutdown`): no new session, no
        #: getevent / helper restart.
        self._quitting = False
        # session state (guarded by _lock)
        self._active = False
        self._serial: str | None = None
        self._folder: Path | None = None
        self._mode = "off"
        self._helper_state = "off"
        self._since: float | None = None
        self._reason: str | None = None
        self._inputs = 0
        self._shots = 0
        self._keys_other = 0
        self._gen = 0
        self._session_gen = 0
        self._stream: GeteventStream | None = None
        self._unsub: Callable[[], None] | None = None
        self._helper: Any = None
        self._helper_stop: threading.Thread | None = None
        self._session: _HelperSession | None = None
        self._logcat: Any = None
        self._bell_handler: Callable[..., None] | None = None
        #: A password field has the input focus (FOCUSED/TEXT_CHANGED).
        self._pw_focus = False
        self._pre_lock = threading.Lock()
        self._pre_inflight = 0
        self._rot_pending = False
        self.geometry = Geometry()
        self._geometry_ready = threading.Event()
        self._pending: dict[int, _Pending] = {}
        self._recent_inputs: deque[dict] = deque(maxlen=64)
        self._recent_clicks: deque[dict] = deque(maxlen=64)
        self._text: dict | None = None
        self._last_screen: tuple | None = None
        self._last_window_host = 0.0
        self._activities: list[dict] = []
        #: Screen-change shot requests not started yet (FIFO), and the one
        #: being settled (``open`` until its frame is captured).
        self._screen_q: deque[dict] = deque()
        self._screen_cur: dict | None = None
        #: ``(device s, host epoch)`` of recent finger-downs and keys: a
        #: screen-change shot taken after the next input is not that screen's.
        self._input_seen: deque[tuple[float, float]] = deque(maxlen=64)
        #: ``(device s, gesture, before-tap capture)`` of recent finger-downs.
        self._downs: deque[tuple[float, Gesture, Future | None]] = deque(maxlen=64)
        #: Screen-change shots not taken, per reason (``late``,
        #: ``superseded``, ``unverified``).
        self._shot_drops: dict[str, int] = {}
        #: Every helper frame hash seen (see :data:`FRAMES_KEPT`).
        self._frames: deque[tuple[float | None, float, float, str]] = deque(
            maxlen=FRAMES_KEPT
        )
        self._label_seen = 0
        #: sha256 -> (ref path, seq) per shots folder (a new session or
        #: device writes into another folder: its own files, its own dedupe).
        self._sha: dict[str, dict[str, tuple[str, int | None]]] = {}
        self._sha_lock = threading.Lock()
        self._ticker: threading.Thread | None = None
        self._tick_stop = threading.Event()
        # lanes
        self._node_lane = _Lane("tracking-node")
        self._pre_lane = _Lane("tracking-pre")
        self._order_lane = _Lane("tracking-order")
        self._shot_lane = _Lane("tracking-shot")
        self._store_lane = _Lane("tracking-store")
        self._probe_lane = _Lane("tracking-probe")
        #: The pre-change frame hash of a screen event, taken at event time.
        self._screen_pre_lane = _Lane("tracking-screen-pre")

    # -- defaults --------------------------------------------------------------

    @staticmethod
    def _make_helper(serial, mode, on_event, on_status, raw_log):
        from sandroid.core.uihelper import Mode, UiHelper

        return UiHelper(
            serial,
            Mode(mode),
            on_event=on_event,
            on_status=on_status,
            raw_log=raw_log,
        )

    @staticmethod
    def _timeline_folder(serial: str) -> Path:
        from sandroid.core import timeline

        try:
            status = timeline.get_timeline().status(serial)
            if status.folder and status.serial == serial:
                return Path(status.folder)
        except Exception:
            pass
        return timeline.timeline_folder()

    @staticmethod
    def _record_clock(reason: str, serial: str) -> None:
        try:
            from sandroid.core import device_clock

            device_clock.record_async(reason, serial)
        except Exception:
            logger.debug("tracking: clock sample failed", exc_info=True)

    @staticmethod
    def _resolve_serial(serial: str | None) -> str | None:
        if serial:
            return serial
        try:
            from sandroid.core import timeline

            active = timeline.get_timeline().active_serial
            if active:
                return active
        except Exception:
            pass
        try:
            from sandroid.core.adb import Adb

            return Adb.get_target_device()
        except Exception:
            return None

    def _adb(self, serial: str, *args: str, timeout: float = 10.0) -> tuple[int, bytes]:
        return self._run([*_base_argv(serial), *args], timeout=timeout)

    # -- the shared getevent ---------------------------------------------------

    def getevent(self, serial: str) -> GeteventStream:
        """Lease the device's ONE getevent reader (call ``release()`` once).

        Raises:
            RuntimeError: getevent could not be started.
        """
        with self._lock:
            closing = self._closing.get(serial)
        if closing is not None:  # never under the lock: up to 5 s
            closing.wait_closed()
            with self._lock:
                if self._closing.get(serial) is closing:
                    del self._closing[serial]
        raw = self._folder_fn(serial) / RAW_DIR / GETEVENT_FILE
        with self._lock:
            stream = self._streams.get(serial)
            if stream is None:
                stream = GeteventStream(
                    serial,
                    raw,
                    popen=self._popen,
                    run=self._run,
                    on_closed=self._stream_closed,
                    registry_lock=self._lock,
                )
                self._streams[serial] = stream
            else:  # kept alive (e.g. by Record) across a session change
                stream.retarget(raw)
            if not stream.acquire():
                if stream.leases == 0:
                    self._streams.pop(serial, None)
                raise RuntimeError(f"getevent could not be started on {serial}")
            if self._quitting:
                stream.suppress_restarts()
            return stream

    def _stream_closed(self, stream: GeteventStream) -> None:
        with self._lock:
            if self._streams.get(stream.serial) is stream:
                del self._streams[stream.serial]
            self._closing[stream.serial] = stream

    # -- toggle ----------------------------------------------------------------

    def is_active(self, serial: str | None = None) -> bool:
        """Tracking on (for ``serial`` when given)."""
        return self._active and (serial is None or serial == self._serial)

    def state(self) -> TrackingState:
        with self._lock:
            return TrackingState(
                active=self._active,
                serial=self._serial,
                mode=self._mode,
                helper=self._helper_state,
                since=self._since,
                inputs=self._inputs,
                shots=self._shots,
                reason=self._reason,
            )

    def toggle(self, serial: str | None = None, *, actor: str = "user") -> bool:
        """Start or stop; the new state."""
        if self._active:
            self.stop(reason="user", actor=actor)
            return False
        return self.start(serial, reason="user", actor=actor)

    @property
    def session_gen(self) -> int | None:
        """The running session's generation (None when off)."""
        with self._lock:
            return self._session_gen if self._active else None

    def start(
        self,
        serial: str | None = None,
        *,
        reason: str = "user",
        actor: str | None = None,
    ) -> bool:
        """Turn Tracking on. Quick: the helper, probes and logcat start on a
        background thread. False without a device or without getevent.
        """
        serial = self._resolve_serial(serial)
        if not serial:
            logger.warning("Tracking: no device")
            return False
        with self._op_lock:
            if self._quitting:
                return False
            with self._lock:
                if self._active:
                    return self._serial == serial
            return self._start(serial, reason, actor) is not None

    def start_session(
        self, serial: str | None = None, *, reason: str, actor: str | None = None
    ) -> int | None:
        """Start Tracking only when it is off: the new session's generation,
        or None (already on, no device, no getevent). For a caller that must
        later stop exactly the session it started (``stop(only_gen=...)``).
        """
        serial = self._resolve_serial(serial)
        if not serial:
            return None
        with self._op_lock:
            if self._quitting:
                return None
            with self._lock:
                if self._active:
                    return None
            return self._start(serial, reason, actor)

    def _start(self, serial: str, reason: str, actor: str | None) -> int | None:
        """``_op_lock`` held, Tracking off. The state lock is never held while
        getevent starts (it may wait for a closing stream).
        """
        cfg = _config()
        folder = self._folder_fn(serial)
        try:
            stream = self.getevent(serial)
        except RuntimeError as exc:
            logger.warning(f"Tracking: {exc}")
            return None
        with self._lock:
            self._gen += 1
            gen = self._session_gen = self._gen
            self._active = True
            self._serial = serial
            self._folder = folder
            self._mode = str(cfg.helper_mode)
            self._helper_state = "off" if self._mode == "off" else "starting"
            self._since = time.time()
            self._reason = reason
            self._inputs = self._shots = self._keys_other = 0
            self.geometry = Geometry()
            self._geometry_ready.clear()
            self._pending.clear()
            self._recent_inputs.clear()
            self._recent_clicks.clear()
            self._text = None
            self._last_screen = None
            self._activities = []
            self._screen_q.clear()
            self._screen_cur = None
            self._input_seen.clear()
            self._downs.clear()
            self._frames.clear()
            self._shot_drops = {}
            self._session = None
            self._pw_focus = False
            self._label_seen = self._timeline_last_seq()
            self._stream = stream
        _emit(
            "tracking",
            "start",
            summary=f"◉ tracking on · {self._mode} helper"
            if self._mode != "off"
            else "◉ tracking on · no helper",
            actor=actor or self._actor("user"),
            data={"mode": self._mode, "helper": self._helper_state, "reason": reason},
            dev=serial,
        )
        self._unsub = stream.subscribe_events(self._on_events)
        self._subscribe_bell()
        self._tick_stop.clear()
        self._ticker = threading.Thread(
            target=self._tick_loop, args=(gen,), name="tracking-tick", daemon=True
        )
        self._ticker.start()
        threading.Thread(
            target=self._bootstrap,
            args=(gen, serial, folder),
            name="tracking-start",
            daemon=True,
        ).start()
        return gen

    def stop(
        self,
        *,
        reason: str = "user",
        actor: str | None = None,
        only_gen: int | None = None,
    ) -> None:
        """Turn Tracking off (pending gestures are written first).

        With ``only_gen``: only when that session is still the running one
        (Record never stops a session the user restarted meanwhile).
        """
        with self._op_lock:
            self._stop(reason, actor, only_gen)

    def _stop(self, reason: str, actor: str | None, only_gen: int | None) -> None:
        with self._lock:
            if not self._active:
                return
            if only_gen is not None and only_gen != self._session_gen:
                return
            self._active = False
            self._gen += 1
            serial = self._serial
            unsub, self._unsub = self._unsub, None
            stream, self._stream = self._stream, None
            helper, self._helper = self._helper, None
            sess, self._session = self._session, None
            logcat, self._logcat = self._logcat, None
        self._tick_stop.set()
        if unsub is not None:
            unsub()
        self._order_lane.drain(1.5)
        self._flush_text()
        self._unsubscribe_bell()
        if logcat is not None:
            with contextlib.suppress(Exception):
                logcat.terminate()
        with self._lock:
            inputs, shots = self._inputs, self._shots
            drops = dict(self._shot_drops)
            since = self._since or time.time()
        dropped = sum(drops.values())
        _emit(
            "tracking",
            "stop",
            summary=f"◎ tracking off · {inputs} inputs, {shots} shots"
            + (f" ({dropped} dropped)" if dropped else ""),
            actor=actor or self._actor("user"),
            data={
                "reason": reason,
                "inputs": inputs,
                "shots": shots,
                "shots_dropped": drops,
                "keys_unnamed": self._keys_other,
                "duration_s": round(time.time() - since, 1),
            },
            dev=serial,
        )
        if stream is not None:
            stream.release()
        if helper is not None:
            self._helper_stop = threading.Thread(
                target=self._stop_helper,
                args=(helper, sess),
                name="tracking-helper-stop",
                daemon=True,
            )
            self._helper_stop.start()

    def manual_shot(self, *, t: float | None = None, actor: str = "user") -> bool:
        """The ``s`` key while Tracking is on: a screenshot line (async)."""
        if not self._active:
            return False
        t = time.time() if t is None else t
        gen = self._gen
        self._pre_lane.submit(self._manual, gen, t, actor)
        return True

    def shutdown(
        self,
        timeout: float = 5.0,
        *,
        reason: str = "exit",
        actor: str | None = "sandroid",
    ) -> None:
        """Quit / process exit: stop Tracking (``tracking/stop`` with
        ``reason``), the helper (its ``intervention`` off line) and every
        getevent, waiting up to ``timeout`` for each.

        From the first call on nothing restarts: no new session, no getevent
        respawn, no helper restart (a quit kills adb processes; a restart
        would race it).
        """
        with self._lock:
            self._quitting = True
            helper = self._helper
            streams = list(self._streams.values()) + list(self._closing.values())
        for stream in streams:
            stream.suppress_restarts()
        suppress = getattr(helper, "suppress_restarts", None)
        if callable(suppress):
            with contextlib.suppress(Exception):
                suppress()
        with contextlib.suppress(Exception):
            self.stop(reason=reason, actor=actor)
        t = self._helper_stop
        if t is not None and t is not threading.current_thread():
            t.join(timeout)
        with self._lock:
            streams = list(self._streams.values()) + list(self._closing.values())
        for stream in streams:
            stream.suppress_restarts()
            while stream.leases:
                stream.release()
            stream.wait_closed(timeout)

    # -- bootstrap (background) --------------------------------------------------

    def _bootstrap(self, gen: int, serial: str, folder: Path) -> None:
        # The previous session's helper must be gone (and a11y restored)
        # before the new one reads ``a11y_before``.
        prev = self._helper_stop
        if prev is not None and prev is not threading.current_thread():
            prev.join(HELPER_STOP_WAIT_S)
        self._clock_record("tracking-start", serial)
        try:
            self._probe_geometry(serial)
        finally:
            self._geometry_ready.set()
        if _config().logcat_screen_backup and self._gen == gen:
            self._start_logcat(gen, serial)
        if self._mode == "off" or self._gen != gen:
            return
        sess = _HelperSession(gen=gen, serial=serial, mode=self._mode)
        helper = self._helper_factory(
            serial,
            self._mode,
            lambda d, host_recv: self._on_helper_event(d, host_recv, sess),
            lambda state, info: self._on_helper_status(state, info, sess),
            folder / RAW_DIR / HELPER_FILE,
        )
        sess.helper = helper
        with self._lock:
            if self._gen != gen:
                return
            self._helper = helper
            self._session = sess
        ok = False
        try:
            ok = bool(helper.start())
        except Exception as exc:
            logger.warning(f"Tracking: UI helper failed to start: {exc}")
        if not ok:
            err = getattr(helper, "last_error", None)
            with self._lock:
                if self._helper is helper:
                    self._helper = None
                    self._session = None
                    if self._helper_state != "busy":
                        self._helper_state = "failed"
            if err != "busy":
                _emit(
                    "tracking",
                    "helper",
                    summary=f"helper failed · {err or 'no connection'}",
                    actor="sandroid",
                    level="warn",
                    data={"helper": "failed", "mode": self._mode, "error": err},
                    dev=serial,
                )
            return
        if self._gen != gen:  # stopped while the helper was starting
            self._stop_helper(helper, sess)
            return
        self._apply_display(getattr(helper, "hello", None))

    def _probe_geometry(self, serial: str) -> None:
        geo = Geometry()
        rc, out = self._adb(serial, "shell", "getevent -p", timeout=10.0)
        if rc == 0:
            geo.maxima = parse_getevent_p(out.decode("utf-8", "replace"))
        rc, out = self._adb(serial, "shell", "wm size", timeout=10.0)
        size = parse_wm_size(out.decode("utf-8", "replace")) if rc == 0 else None
        if size:
            geo.width, geo.height = size
        rc, out = self._adb(
            serial,
            "shell",
            "dumpsys input | grep -m1 SurfaceOrientation",
            timeout=10.0,
        )
        m = re.search(r"SurfaceOrientation:\s*(\d)", out.decode("utf-8", "replace"))
        if m:
            geo.rotation = int(m[1])
        self.geometry = geo

    def _apply_display(self, hello: dict | None) -> None:
        display = (hello or {}).get("display") or {}
        rot = display.get("rotation")
        if isinstance(rot, int):
            geo = self.geometry
            w, h = display.get("w"), display.get("h")
            if (
                not (geo.width and geo.height)
                and isinstance(w, int)
                and isinstance(h, int)
            ):
                geo.width, geo.height = (h, w) if rot % 2 else (w, h)
            geo.rotation = rot

    def _stop_helper(self, helper: Any, sess: _HelperSession | None = None) -> None:
        try:
            helper.stop()
        except Exception:
            logger.debug("tracking: helper stop failed", exc_info=True)
        if sess is not None and sess.intervention_on:
            # no "stopped" status came (fake/old helper)
            self._intervention(False, {}, sess)

    # -- getevent -> input ------------------------------------------------------

    def _on_events(self, events: list[DecodedEvent], host_recv: float) -> None:
        """Reader thread (the stream's decoder): queue, never block."""
        gen = self._gen
        for ev in events:
            g = ev.gesture
            g.host_recv = host_recv
            fut = self._at_down(g) if ev.kind == "down" else None
            if ev.kind in ("down", "key"):
                # after _at_down: an input seen by the shot lane has its
                # before-tap capture registered
                with self._lock:
                    self._input_seen.append((g.t_down, host_recv))
                    if ev.kind == "down":
                        self._downs.append((g.t_down, g, fut))
            if ev.kind != "down":
                self._order_lane.submit(self._finish, gen, g)

    def _helper_up(self) -> Any:
        helper = self._helper
        if helper is None or not getattr(helper, "alive", False):
            return None
        return helper

    def _at_down(self, g: Gesture) -> Future | None:
        """Start the node lookup and the before-tap capture (returned)."""
        helper = self._helper_up()
        if helper is None:
            self._pending[g.gid] = _Pending(
                t0=time.monotonic(),
                shot_state="no_helper" if _config().shot_before_tap else "off",
            )
            return None
        p = _Pending(t0=time.monotonic())
        full = str(getattr(helper, "mode", self._mode)) == "full"
        # An axis never seen is unknown, not 0: no node_at at a made-up spot
        # (the a11y CLICKED can still name the target, see _match).
        if full and g.xy_known and self._geometry_ready.is_set():
            x, y = self.geometry.to_px(g.dev, g.x0, g.y0)
            p.node = self._node_lane.submit(
                helper.node_at, x, y, t_mono_ms=round(g.t_down * 1000.0, 1)
            )
        elif full and g.xy_known:
            p.node = self._node_lane.submit(self._node_late, helper, g)
        if _config().shot_before_tap:
            p.shot = self._pre_shot(helper)
            if p.shot is None:
                p.shot_state = "skipped"  # one was still in flight
        else:
            p.shot_state = "off"
        self._pending[g.gid] = p
        return p.shot

    def _pre_shot(self, helper: Any) -> Future | None:
        """A before-tap capture, unless one is still in flight: fast taps
        would queue captures that land long after their taps.
        """
        with self._pre_lock:
            if self._pre_inflight:
                return None
            self._pre_inflight += 1
        fut = self._pre_lane.submit(self._shot_seen, helper)
        fut.add_done_callback(self._pre_done)
        return fut

    def _pre_done(self, _fut: Future) -> None:
        with self._pre_lock:
            self._pre_inflight = max(0, self._pre_inflight - 1)

    def _node_late(self, helper: Any, g: Gesture) -> dict | None:
        self._geometry_ready.wait(1.0)
        x, y = self.geometry.to_px(g.dev, g.x0, g.y0)
        return helper.node_at(x, y, t_mono_ms=round(g.t_down * 1000.0, 1))

    @staticmethod
    def _actor(default: str) -> str:
        try:
            from sandroid.core import timeline

            return timeline.current_actor(default)
        except Exception:
            return default

    def _input_actor(self) -> str:
        try:
            from sandroid.core import timeline

            phase = timeline.get_timeline().current_phase(self._serial)[0]
        except Exception:
            phase = "live"
        return "replay" if phase == "replay" else "user"

    def _finish(self, gen: int, g: Gesture) -> None:
        """Order lane: classify, wait <= NODE_WAIT_S for node_at, emit."""
        # A gesture queued before stop() is still written; ``gen`` only
        # cancels the after-tap shot of a gesture finished after stop().
        pending = self._pending.pop(g.gid, None)
        cfg = _config()
        serial = self._serial
        raw = f"{RAW_DIR}/{GETEVENT_FILE}#L{g.line_a}-L{g.line_b}"
        dur_ms = round(((g.t_up or g.t_down) - g.t_down) * 1000.0, 1)
        if g.key_code is not None:
            name = KEY_NAMES.get(g.key_code)
            if name is None:
                self._keys_other += 1
                return
            seq = _emit(
                "input",
                "key",
                summary=f"key {name}",
                actor=self._input_actor(),
                clk="dev_mono",
                dev_mono=g.t_down,
                data={
                    "code": g.key_code,
                    "name": name,
                    "dur_ms": dur_ms,
                    "node": g.dev,
                },
                ref={"raw": raw},
                dev=serial,
            )
            if seq is not None:
                with self._lock:
                    self._inputs += 1
            return
        self._geometry_ready.wait(1.0)
        geo = self.geometry
        sw, sh = geo.screen
        known = g.xy_known
        x = y = x1 = y1 = None
        moved = 0.0
        if known:  # never an unseen axis as 0 (position, movement, node_at)
            x, y = geo.to_px(g.dev, g.x0, g.y0)
            x1, y1 = geo.to_px(g.dev, g.x1, g.y1)
            for a, b, _t in [*g.path, (g.x1, g.y1, 0.0)]:
                px, py = geo.to_px(g.dev, a, b)
                moved = max(moved, ((px - x) ** 2 + (py - y) ** 2) ** 0.5)
        if g.pointers > 1:
            kind = "gesture"
        elif moved <= cfg.swipe_slop_px:
            kind = "long_press" if dur_ms >= cfg.long_press_ms else "tap"
        else:
            kind = "swipe"
        data: dict[str, Any] = {
            "x": x,
            "y": y,
            "rx": round(x / sw, 4) if sw and x is not None else None,
            "ry": round(y / sh, 4) if sh and y is not None else None,
            "screen": [sw, sh],
            "rotation": geo.rotation,
            "dur_ms": dur_ms,
            "pointer": g.slot,
            "xy_uncertain": g.uncertain,
            "helper": self._helper_label(),
        }
        if g.dropped:
            data["dropped"] = True  # events were lost: the end is a guess
        t_up = g.t_up if g.t_up is not None else g.t_down
        before_res, data["before_shot"] = self._before_state(pending, cfg, t_up)
        if kind == "gesture":
            data["pointers"] = g.pointers
        if kind == "swipe":
            data["x1"], data["y1"] = x1, y1
            data["path"] = self._path(g, geo)
        target = None
        answer: dict = {}
        pkg = None
        ime = False
        if pending is not None and pending.node is not None:
            try:
                reply = pending.node.result(timeout=NODE_WAIT_S)
                data["node_ms"] = round((time.monotonic() - pending.t0) * 1000.0, 1)
            except FutureTimeout:
                reply = None
                data["node_timeout"] = True
            except Exception:
                reply = None
            if isinstance(reply, dict):
                self._apply_display(reply)
            target, answer = self._target(reply)
            pkg = answer.get("pkg") if answer else None
            ime = self._ime_hit(reply)
        # Privacy: a tap while a password field has the focus, on a password
        # field, or on the keyboard is sensitive (masked by readers, never
        # suppressed); a keyboard key never names its label.
        pw = self._pw_focus or bool(target and target.get("password"))
        sensitive = pw or ime
        if ime:
            data["ime"] = True
            if target is not None:
                target["text"] = target["desc"] = None
                target.pop("label", None)
        data["target"] = target
        if ime:
            summary = f"{kind.replace('_', ' ')} on keyboard" + (
                " (password field)" if pw else ""
            )
        else:
            summary = self._input_summary(kind, data, target, answer)
        seq = _emit(
            "input",
            kind,
            summary=summary,
            actor=self._input_actor(),
            clk="dev_mono",
            dev_mono=g.t_down,
            pkg=pkg,
            data=data,
            ref={"raw": raw},
            sensitive=sensitive,
            dev=serial,
        )
        if seq is None:
            return
        with self._lock:
            self._inputs += 1
        rec = {
            "seq": seq,
            "kind": kind,
            "target": target,
            "down_ms": g.t_down * 1000.0,
            "up_ms": (g.t_up or g.t_down) * 1000.0,
            "host": time.time(),
            "confirmed": False,
            # no node_at was possible at down: the a11y click names it
            "uncertain": g.uncertain and target is None,
            "sensitive": sensitive,
            "ime": ime,
        }
        self._confirm_input(rec)
        before = pending.shot if pending is not None else None
        if before_res is not None:
            self._store_lane.submit(self._before_shot, before_res, seq, kind, sensitive)
        if cfg.shot_after_tap and kind in ("tap", "long_press"):
            self._shot_lane.submit(
                self._after_tap, gen, seq, kind, before, t_up, sensitive
            )

    @staticmethod
    def _path(g: Gesture, geo: Geometry) -> list[list[float]]:
        pts = g.path
        if len(pts) > PATH_MAX:
            step = (len(pts) - 1) / (PATH_MAX - 1)
            pts = [pts[round(i * step)] for i in range(PATH_MAX)]
        out = []
        for a, b, t in pts:
            px, py = geo.to_px(g.dev, a, b)
            out.append([px, py, round((t - g.t_down) * 1000.0, 1)])
        return out

    def _helper_label(self) -> str:
        if self._mode == "off":
            return "off"
        if self._helper_up() is None:
            return self._helper_state
        return self._mode

    @staticmethod
    def _target(reply: dict | None) -> tuple[dict | None, dict]:
        if not reply:
            return None, {}
        for source in ("cached", "live"):
            answer = reply.get(source)
            if isinstance(answer, dict) and answer.get("hit"):
                node = answer.get("target") or answer.get("hit")
                target = {
                    "rid": node.get("rid"),
                    "text": None if _private(node) else node.get("text"),
                    "desc": node.get("desc"),
                    "cls": node.get("cls"),
                    "path": answer.get("path"),
                    "bounds": node.get("bounds"),
                    "source": source,
                }
                for key in ("hint", "password", "editable"):
                    if node.get(key):
                        target[key] = node[key]
                # A node without its own text/desc (a list row) is named by
                # its descendants' label ('Battery / Charged'): kept as
                # ``label``; ``text`` stays the node's own text.
                label = answer.get("label") if answer.get("target") is node else None
                if (
                    isinstance(label, str)
                    and label.strip()
                    and not _private(node)
                    and not node.get("text")
                    and not node.get("desc")
                ):
                    target["label"] = label
                return target, answer
        return None, {}

    @staticmethod
    def _ime_hit(reply: dict | None) -> bool:
        """The touched window is the input method (the keyboard)."""
        for source in ("cached", "live"):
            answer = (reply or {}).get(source)
            if isinstance(answer, dict):
                win = answer.get("window")
                if isinstance(win, dict) and win.get("type") == "ime":
                    return True
        return False

    @staticmethod
    def _input_summary(kind: str, data: dict, target: dict | None, answer: dict) -> str:
        word = kind.replace("_", " ")
        if kind == "gesture":
            return f"gesture · {data.get('pointers', 2)} fingers"
        name = None
        if target is not None:
            node = answer.get("target") or answer.get("hit") or {}
            name = _node_label(answer, node)
        if kind == "swipe":
            dx, dy = data["x1"] - data["x"], data["y1"] - data["y"]
            if abs(dx) > abs(dy):
                way = "right" if dx > 0 else "left"
            else:
                way = "down" if dy > 0 else "up"
            text = f"swipe {way} · {data['x']},{data['y']} → {data['x1']},{data['y1']}"
            return f"{text} on '{name}'" if name else text
        if name:
            return f"{word} '{name}' ({_short_cls(target.get('cls'))})"
        if data.get("x") is None or data.get("y") is None:
            return f"{word} · position unknown"
        return f"{word} at {data['x']},{data['y']}"

    # -- helper events ----------------------------------------------------------

    def _current(self, sess: _HelperSession | None) -> bool:
        """``sess`` is the running session's helper (not a stale one)."""
        if sess is None:
            return True
        return sess.gen == self._gen and self._helper is sess.helper

    def _on_helper_event(
        self, d: dict, host_recv: float, sess: _HelperSession | None = None
    ) -> None:
        """Helper reader thread: bookkeeping and non-blocking emits only."""
        if not self._current(sess):
            return  # a stopped session's helper
        typ = d.get("type")
        if typ == "hello":
            self._apply_display(d)
            return
        if typ != "ev" or not self._active:
            return
        ev = d.get("ev")
        if ev in ("CLICKED", "LONG_CLICKED"):
            self._on_click(d, host_recv)
        elif ev == "TEXT_CHANGED":
            if d.get("password") or (d.get("src") or {}).get("password"):
                self._pw_focus = True
            self._on_text(d, host_recv)
        elif ev == "FOCUSED":
            self._pw_focus = bool(
                d.get("password") or (d.get("src") or {}).get("password")
            )
            self._flush_text()
        elif ev == "WINDOW_STATE_CHANGED":
            self._flush_text()
            self._on_window(d, host_recv)

    # confirm

    def _on_click(self, d: dict, host_recv: float) -> None:
        click = {
            "t_ms": float(d.get("t_mono_ms") or 0.0),
            "ev": d.get("ev"),
            "node": d.get("src") or {"text": d.get("text"), "cls": d.get("cls")},
            "host": host_recv,
            "used": False,
        }
        with self._lock:
            self._recent_clicks.append(click)
            inputs = [r for r in self._recent_inputs if not r["confirmed"]]
        for rec in inputs:
            if self._match(rec, click):
                self._emit_confirm(rec, click)
                return

    @staticmethod
    def _match(rec: dict, click: dict) -> bool:
        if click["used"] or rec["confirmed"]:
            return False
        if rec["kind"] not in ("tap", "long_press"):
            return False
        if (
            not rec["down_ms"] - 50.0
            <= click["t_ms"]
            <= rec["up_ms"] + CONFIRM_WINDOW_MS
        ):
            return False
        if rec["target"] is None and rec.get("uncertain"):
            return True  # position unknown: the click names the target
        return _same_node(rec["target"], click["node"])

    def _confirm_input(self, rec: dict) -> None:
        with self._lock:
            self._recent_inputs.append(rec)
            clicks = list(self._recent_clicks)
        for click in clicks:
            if self._match(rec, click):
                self._emit_confirm(rec, click)
                return

    def _emit_confirm(self, rec: dict, click: dict) -> None:
        with self._lock:
            if rec["confirmed"] or click["used"]:
                return
            rec["confirmed"] = click["used"] = True
        node = click["node"] or {}
        data: dict[str, Any] = {
            "a11y": click["ev"],
            "node": {
                "rid": node.get("rid"),
                "text": None if _private(node) or rec.get("ime") else node.get("text"),
                "cls": node.get("cls"),
            },
        }
        if rec["target"] is None and rec.get("uncertain"):
            # The tap's position was unknown: this is its target.
            data["node"]["bounds"] = node.get("bounds")
            data["target_of_input"] = True
        _emit(
            "input",
            "confirm",
            summary=f"✓ {str(click['ev']).lower().replace('_', ' ')} #{rec['seq']}",
            actor="app",
            clk="dev_mono",
            dev_mono=click["t_ms"] / 1000.0,
            data=data,
            ref={"of": rec["seq"]},
            sensitive=bool(rec.get("sensitive")),
            dev=self._serial,
        )

    # text

    def _on_text(self, d: dict, host_recv: float) -> None:
        src = d.get("src") or {}
        rid = src.get("rid")
        win = d.get("window_id")
        key = (
            (win, rid)
            if rid
            else (win, src.get("cls") or d.get("cls"), str(src.get("bounds")))
        )
        flush = None
        with self._lock:
            cur = self._text
            if cur is not None and cur["key"] != key:
                flush, cur = cur, None
            if cur is None:
                cur = {
                    "key": key,
                    "first_ms": float(d.get("t_mono_ms") or 0.0),
                    "edits": 0,
                    "node": src,
                    "pkg": d.get("pkg"),
                    "cls": src.get("cls") or d.get("cls"),
                    "window_id": win,
                    "password": False,
                    "data_sensitive": False,
                }
            cur["edits"] += 1
            cur["last_ms"] = float(d.get("t_mono_ms") or 0.0)
            cur["host"] = host_recv
            cur["text"] = d.get("text") or ""
            cur["password"] |= bool(d.get("password") or src.get("password"))
            cur["data_sensitive"] |= bool(d.get("data_sensitive"))
            self._text = cur
        if flush is not None:
            self._emit_text(flush)

    def _flush_text(self) -> None:
        with self._lock:
            cur, self._text = self._text, None
        if cur is not None:
            self._emit_text(cur)

    def _emit_text(self, cur: dict) -> None:
        cfg = _config()
        node = cur["node"] or {}
        text = cur.get("text") or ""
        password = bool(cur["password"])
        sensitive = password or bool(cur["data_sensitive"])
        name = _field_name({**node, "cls": cur["cls"]})
        cls = _short_cls(cur["cls"])
        summary = f"typed {len(text)} chars into '{name}' ({cls}{', password' if password else ''})"
        data: dict[str, Any] = {
            "password": password,
            "edits": cur["edits"],
            "len": len(text),
            "dur_ms": round(cur.get("last_ms", 0.0) - cur["first_ms"], 1),
            "target": {
                "rid": node.get("rid"),
                "cls": cur["cls"],
                "hint": node.get("hint"),
                "bounds": node.get("bounds"),
                "window_id": cur["window_id"],
            },
        }
        if cur["data_sensitive"]:
            data["data_sensitive"] = True
        if cfg.capture_text:
            data["text"] = text
        else:
            data["captured"] = False
        _emit(
            "input",
            "text",
            summary=summary,
            actor=self._input_actor(),
            clk="dev_mono",
            dev_mono=cur["first_ms"] / 1000.0,
            pkg=cur.get("pkg"),
            data=data,
            sensitive=sensitive,
            dev=self._serial,
        )
        with self._lock:
            self._inputs += 1

    # screen

    def _on_window(self, d: dict, host_recv: float) -> None:
        pkg, cls, title = d.get("pkg"), d.get("cls"), d.get("text")
        self._last_window_host = host_recv
        self._refresh_rotation()
        self._emit_screen(
            "window",
            pkg=pkg,
            cls=cls,
            title=title,
            window_id=d.get("window_id"),
            via="a11y",
            dev_mono=float(d.get("t_mono_ms") or 0.0) / 1000.0,
            t_evt=host_recv,
        )

    def _emit_screen(
        self, kind: str, *, pkg, cls, title, window_id, via, dev_mono, t_evt=None
    ) -> int | None:
        """``t_evt``: host epoch the event was received at (default: now)."""
        t_evt = time.time() if t_evt is None else float(t_evt)
        key = (pkg, cls, title)
        with self._lock:
            gen = self._gen  # a stop() from here on cancels the shot
            active = self._active
            if key == self._last_screen:
                return None
            self._last_screen = key
        if pkg and cls and cls.startswith(f"{pkg}."):
            shown = f"{pkg}/{cls[len(pkg) :]}"
        else:
            shown = f"{pkg}/{cls}" if pkg else str(cls)
        data = {
            "pkg": pkg,
            "cls": cls,
            "title": title,
            "window_id": window_id,
            "via": via,
        }
        seq = _emit(
            "screen",
            kind,
            summary=f"→ {shown}" + (f" · {_clip(title, 40)}" if title else ""),
            actor="app",
            clk="dev_mono",
            dev_mono=dev_mono,
            pkg=pkg,
            data=data,
            dev=self._serial,
        )
        if seq is not None and active and _config().shot_screen_change:
            self._request_screen_shot(
                gen, seq, pkg, cls, title, dev_mono, t_evt, via=via
            )
        return seq

    def _request_screen_shot(
        self,
        gen: int,
        seq: int,
        pkg: Any,
        cls: Any,
        title: Any,
        dev_mono: float | None = None,
        t_evt: float | None = None,
        *,
        via: str | None = None,
    ) -> None:
        """Queue the screen-change shot of line ``seq`` (any thread).

        The pre-change frame's hash is requested now, at event time; the
        shot waits for a frame that differs from it. An activity line (no
        title) and a window line of the same ``pkg``/``cls`` are one screen:
        they share one capture while it has not been taken yet (each line
        still gets its shot line). A new distinct screen supersedes every
        request whose capture has not started (dropped, counted): its capture
        would start after this event, i.e. show this screen. So no backlog
        builds up on a loaded device; the latest screen wins.
        """
        ident = (pkg, cls)
        t_evt = time.time() if t_evt is None else float(t_evt)
        ev_dev = float(dev_mono) if dev_mono and dev_mono > 0 else None
        with self._lock:
            # Only the latest screen not captured yet can absorb this line.
            last = self._screen_q[-1] if self._screen_q else self._screen_cur
            if (
                last is not None
                and last["open"]
                and not last.get("superseded")
                and last["ident"] == ident
                and not (last["titled"] and title)
            ):
                last["seqs"].append(seq)
                last["titled"] = last["titled"] or bool(title)
                return
            stale = list(self._screen_q)
            self._screen_q.clear()
            cur = self._screen_cur
            if cur is not None and cur["open"] and not cur.get("superseded"):
                stale.append(cur)  # still settling: its capture is not taken
            for old in stale:
                old["superseded"] = True
                old["sup_ev"] = (ev_dev, t_evt)
                if old["before"] is not None:
                    old["before"].cancel()
                if old is not cur:
                    self._drop_locked(old, "superseded")
                # the settling one may still store a fallback captured before
                # this event: its lane counts the drop otherwise
            helper = self._helper_up()
            before = (
                self._screen_pre_lane.submit(self._pre_hash, helper)
                if helper is not None
                else None
            )
            req = {
                "seqs": [seq],
                "ident": ident,
                "titled": bool(title),
                "before": before,
                "open": True,
                "t_evt": t_evt,
                "ev_dev": ev_dev,
                "logcat": via == "logcat",
                "a11y": via == "a11y",
            }
            self._screen_q.append(req)
        self._shot_lane.submit(self._screen_shot, gen, req)

    def _pre_hash(self, helper: Any) -> tuple[Any, float]:
        """Screen-pre lane: the pre-change frame hash and its host start."""
        start = time.time()
        return self._shot_seen(helper, hash_only=True), start

    def _shot_seen(self, helper: Any, **kw: Any) -> Any:
        """``helper.shot(**kw)``; its frame hash is remembered (with the
        device capture time and the host request span) as a possible "old
        screen" reference of later screen-change shots.
        """
        h0 = time.time()
        res = helper.shot(**kw)
        frame = getattr(res, "hash", None) if res is not None else None
        if frame:
            try:
                ms = float(res.t_mono_ms)
            except (AttributeError, TypeError, ValueError):
                ms = 0.0
            dev = ms / 1000.0 if ms > 0 else None
            with self._lock:
                self._frames.append((dev, h0, time.time(), str(frame)))
        return res

    @staticmethod
    def _dev_ok(dev: float | None, h0: float, h1: float, req: dict) -> bool:
        """Device time ``dev`` (taken during the host span ``h0``-``h1``) is
        on the clock of ``req``'s event: mapped with the event's host-device
        offset (late by the event's delivery) it falls into that span.
        """
        ev_dev = req.get("ev_dev")
        if dev is None or ev_dev is None:
            return False
        mapped = dev + (req["t_evt"] - ev_dev)
        return h0 - 0.1 <= mapped <= h1 + INPUT_SKEW_S

    def _input_before(self, req: dict) -> tuple[float, float] | None:
        """The latest input (finger-down or key) before ``req``'s event."""
        ev_dev, t_evt = req.get("ev_dev"), req["t_evt"]
        with self._lock:
            seen = list(self._input_seen)
        last = None
        for dev, host in seen:
            if ev_dev is None:
                before = host <= t_evt
            else:
                before = host <= t_evt - INPUT_SKEW_S or (
                    dev <= ev_dev and host <= t_evt + INPUT_SKEW_S
                )
            if before:
                last = (dev, host)
        return last

    def _old_frames(self, req: dict) -> set[str]:
        """Frame hashes that show the screen before ``req``'s event: the
        latest frame seen before it, and every frame seen between the last
        input before the event and the event (a before-tap shot, settle
        samples; a ripple can make them differ).
        """
        with self._lock:
            frames = list(self._frames)
        pre = []
        for dev, h0, h1, frame in frames:
            ok = self._dev_ok(dev, h0, h1, req)
            if (dev < req["ev_dev"]) if ok else (h1 <= req["t_evt"]):
                pre.append((dev if ok else None, h0, frame))
        if not pre:
            return set()
        old = {pre[-1][2]}
        inp = self._input_before(req)
        if inp is not None:
            for dev, h0, frame in pre:
                if (dev >= inp[0]) if dev is not None else (h0 >= inp[1]):
                    old.add(frame)
        return old

    def _drop_locked(self, req: dict, reason: str) -> None:
        """Lock held: count ``req`` dropped once (``superseded`` when a newer
        screen superseded it, else ``reason``).
        """
        if req.get("dropped"):
            return
        req["dropped"] = True
        self._count_drop_locked(req, "superseded" if req.get("superseded") else reason)

    def _count_drop_locked(self, req: dict, reason: str) -> None:
        """Lock held: the shot lines of ``req`` are not written (``reason``)."""
        n = len(req["seqs"])
        self._shot_drops[reason] = self._shot_drops.get(reason, 0) + n
        logger.debug(f"Tracking: screen shot of #{req['seqs']} dropped ({reason})")

    @staticmethod
    def _lag_ms(req: dict, host: float, dev_ms: float | None = None) -> float:
        """Capture instant - screen event time (ms): the host lag, or the
        device lag when it is larger and from the same clock epoch.
        """
        lag = (host - req["t_evt"]) * 1000.0
        ev_dev = req.get("ev_dev")
        if dev_ms and ev_dev is not None:
            dev_lag = float(dev_ms) - ev_dev * 1000.0
            if abs(dev_lag - lag) <= CLOCK_SANE_MS:
                lag = max(lag, dev_lag)
        return round(lag, 1)

    def _input_after(self, req: dict, until_dev: float | None = None) -> bool:
        """An input (finger-down or key) came after the screen event of
        ``req`` -- and, with ``until_dev``, before that device time (s).

        The device clock orders them (getevent and the a11y/logcat times are
        both CLOCK_MONOTONIC); an input received :data:`INPUT_SKEW_S` before
        the event never counts, one received that long after always does.
        """
        ev_dev, t_evt = req.get("ev_dev"), req["t_evt"]
        with self._lock:
            seen = list(self._input_seen)
        for dev, host in seen:
            if host <= t_evt - INPUT_SKEW_S:
                continue
            if ev_dev is None:
                after = host > t_evt
            else:
                after = dev > ev_dev or host > t_evt + INPUT_SKEW_S
            if after and (until_dev is None or dev < until_dev):
                return True
        return False

    def _input_next(self, req: dict) -> tuple[float, float] | None:
        """The first input after ``req``'s screen event (see
        :meth:`_input_after`): ``(device s, host epoch)``.
        """
        ev_dev, t_evt = req.get("ev_dev"), req["t_evt"]
        with self._lock:
            seen = list(self._input_seen)
        first = None
        for dev, host in seen:
            if host <= t_evt - INPUT_SKEW_S:
                continue
            if ev_dev is None:
                after = host > t_evt
            else:
                after = dev > ev_dev or host > t_evt + INPUT_SKEW_S
            if after and (first is None or dev < first[0]):
                first = (dev, host)
        return first

    def _tap_shot(self, inp: tuple[float, float] | None) -> Any:
        """The before-tap capture of the finger-down ``inp`` when it was
        taken before that finger's up (as :meth:`_before_shot` stores it).
        """
        if inp is None:
            return None
        with self._lock:
            down = next((d for d in self._downs if d[0] == inp[0]), None)
        if down is None or down[2] is None:
            return None
        res = None
        with contextlib.suppress(Exception):
            res = down[2].result(timeout=BEFORE_TAP_WAIT_S)
        if res is None or not getattr(res, "hash", None):
            return None
        return None if self._late(res, down[1].t_up) else res

    def _before_frame(
        self, inp: tuple[float, float]
    ) -> tuple[str, bytes | None] | None:
        """The frame the input ``inp`` acted on, ``(hash, png)``: its stored
        before-tap shot (with its PNG), else the cached frame closest to its
        finger-down (within :data:`BEFORE_TAP_FRAME_S`, before its finger-up;
        no PNG).
        """
        res = self._tap_shot(inp)
        if res is not None:
            return str(res.hash), getattr(res, "png", None) or None
        dev_in, host_in = inp
        with self._lock:
            frames = list(self._frames)
            t_up = next((d[1].t_up for d in self._downs if d[0] == dev_in), None)
        best: tuple[float, str] | None = None
        for dev, h0, h1, frame in frames:
            if dev is None or abs(dev - dev_in) > BEFORE_TAP_FRAME_S:
                continue
            if t_up is not None and dev > t_up:
                continue
            if h1 < host_in - INPUT_SKEW_S or h0 > host_in + INPUT_SKEW_S:
                continue  # another clock epoch (a snapshot load)
            if best is None or abs(dev - dev_in) < best[0]:
                best = (abs(dev - dev_in), frame)
        return (best[1], None) if best else None

    def _prev_screen(self, req: dict) -> str | None:
        """R1: the previous screen of ``req`` -- the before-tap frame of the
        triggering input (the latest input before the event); None without
        one (R3: the app navigated by itself) or without a frame for it.
        ``req["prev_png"]``: that frame's PNG when a before-tap shot holds it.
        """
        if "prev" not in req:
            inp = self._input_before(req)
            got = self._before_frame(inp) if inp is not None else None
            req["prev"], req["prev_png"] = got if got else (None, None)
        return req["prev"]

    def _start_logcat(self, gen: int, serial: str) -> None:
        argv = [
            *_base_argv(serial),
            "logcat",
            "-b",
            "events",
            "-v",
            "monotonic",
            "-T",
            "1",
            "-s",
            "wm_set_resumed_activity",
        ]
        try:
            proc = self._popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            logger.debug(f"tracking: logcat failed: {exc}")
            return
        with self._lock:
            if self._gen != gen:
                with contextlib.suppress(Exception):
                    proc.terminate()
                return
            self._logcat = proc
        threading.Thread(
            target=self._read_logcat,
            args=(gen, proc),
            name="tracking-logcat",
            daemon=True,
        ).start()

    def _read_logcat(self, gen: int, proc: Any) -> None:
        stdout = getattr(proc, "stdout", None)
        if stdout is None:
            return
        for raw in iter(stdout.readline, b""):
            if self._gen != gen:
                break
            line = (
                raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
            )
            self.on_logcat_line(line, time.time())

    def on_logcat_line(self, line: str, host_recv: float) -> None:
        """One ``wm_set_resumed_activity`` line (logcat reader thread)."""
        m = LOGCAT_ACTIVITY.match(line)
        if m is None:
            return
        pkg, cls = m[2], m[3]
        if cls.startswith("."):
            cls = pkg + cls
        act = {"dev_mono": float(m[1]), "pkg": pkg, "cls": cls, "host": host_recv}
        helper = self._helper_up()
        if helper is None or str(getattr(helper, "mode", self._mode)) != "full":
            self._emit_activity(act)
            return
        with self._lock:
            self._activities.append(act)

    def _refresh_rotation(self) -> None:
        """Re-read the rotation after a screen change (one probe at a time):
        the helper's ``display`` (``windows`` reply), else ``dumpsys input``.
        """
        with self._pre_lock:
            if self._rot_pending:
                return
            self._rot_pending = True
        self._probe_lane.submit(self._probe_rotation, self._gen)

    def _probe_rotation(self, gen: int) -> None:
        try:
            if gen != self._gen or not self._serial:
                return
            helper = self._helper_up()
            fn = getattr(helper, "display", None) if helper is not None else None
            disp = None
            if callable(fn):
                with contextlib.suppress(Exception):
                    disp = fn()
            if isinstance(disp, dict) and isinstance(disp.get("rotation"), int):
                self._apply_display({"display": disp})
                return
            rc, out = self._adb(
                self._serial,
                "shell",
                "dumpsys input | grep -m1 SurfaceOrientation",
                timeout=10.0,
            )
            m = re.search(r"SurfaceOrientation:\s*(\d)", out.decode("utf-8", "replace"))
            if rc == 0 and m and gen == self._gen:
                self.geometry.rotation = int(m[1])
        finally:
            with self._pre_lock:
                self._rot_pending = False

    def _emit_activity(self, act: dict) -> None:
        self._refresh_rotation()
        self._emit_screen(
            "activity",
            pkg=act["pkg"],
            cls=act["cls"],
            title=None,
            window_id=None,
            via="logcat",
            dev_mono=act["dev_mono"],
            t_evt=act.get("host"),
        )

    def _check_activities(self, now: float) -> None:
        with self._lock:
            due = [a for a in self._activities if now - a["host"] >= LOGCAT_GRACE_S]
            self._activities = [a for a in self._activities if a not in due]
        for act in due:
            if abs(self._last_window_host - act["host"]) <= LOGCAT_GRACE_S:
                continue
            self._emit_activity(act)

    # -- ticker -------------------------------------------------------------------

    def _tick_loop(self, gen: int) -> None:
        while not self._tick_stop.wait(0.1):
            if self._gen != gen:
                return
            try:
                self.tick(time.time())
            except Exception:
                logger.debug("tracking tick failed", exc_info=True)

    def tick(self, now: float) -> None:
        """Idle text flush, logcat grace checks, pruning (ticker thread)."""
        cfg = _config()
        with self._lock:
            cur = self._text
            idle = cur is not None and (now - cur["host"]) * 1000.0 >= cfg.text_idle_ms
        if idle:
            self._flush_text()
        self._check_activities(now)
        with self._lock:
            while self._recent_clicks and now - self._recent_clicks[0]["host"] > 5.0:
                self._recent_clicks.popleft()
            while self._recent_inputs and now - self._recent_inputs[0]["host"] > 5.0:
                self._recent_inputs.popleft()

    # -- helper status ---------------------------------------------------------------

    def _on_helper_status(
        self, state: str, info: dict, sess: _HelperSession | None = None
    ) -> None:
        serial = sess.serial if sess is not None else self._serial
        mode = info.get("mode", sess.mode if sess is not None else self._mode)
        current = self._current(sess)
        if not current and state not in ("stopped", "down"):
            return  # a stale helper: only its end still counts
        with self._lock:
            if not current:
                pass  # the new session's state is not this helper's
            elif state in ("connected", "restarted"):
                self._helper_state = "connected"
            elif state == "busy":
                self._helper_state = "busy"
            else:
                self._helper_state = state
        # reason: why the host replaced a stale helper process (UiHelper)
        lost = {
            "system_restart": "helper lost · system server restarted · restarting",
            "reconnect_busy": "helper lost · reconnect refused · restarting",
        }.get(info.get("reason"), "helper lost · restarting")
        summary = {
            "connected": f"helper connected · {mode}",
            "restarted": f"helper restarted · attempt {info.get('attempt', '?')}",
            "lost": lost,
            "busy": "helper waiting · another UiAutomation client holds the device",
            "down": "helper down · gave up after repeated deaths",
            "stopped": "helper stopped",
        }.get(state, f"helper {state}")
        data = {
            "helper": state,
            "mode": mode,
            **{
                k: info[k]
                for k in ("pid", "version", "rc", "reason", "attempt", "deaths")
                if k in info
            },
        }
        if "a11y_restored" in info:
            data["a11y_restored"] = info["a11y_restored"]
        _emit(
            "tracking",
            "helper",
            summary=summary,
            actor="sandroid",
            level="warn" if state in ("lost", "down", "busy") else "info",
            data=data,
            dev=serial,
        )
        if state in ("connected", "restarted"):
            self._intervention(True, info, sess)
        elif state in ("down", "stopped"):
            self._intervention(False, info, sess)

    def _intervention(
        self, on: bool, info: dict, sess: _HelperSession | None = None
    ) -> None:
        """One ``sandroid/intervention`` line per change of THIS helper
        session (an old session's "off" is written even after a restart).
        """
        if sess is None:
            sess = self._session
        if sess is None:
            return
        with self._lock:
            if on == sess.intervention_on:
                return
            sess.intervention_on = on
            mode = info.get("mode", sess.mode)
        full = mode == "full"
        what = "a11y_helper" if full else "ui_helper_invisible"
        detail: dict[str, Any] = {"flags": info.get("flags", 1 if full else 2)}
        if full:
            before = info.get("a11y_before") or {}
            detail["accessibility_enabled_before"] = before.get("accessibility_enabled")
        if "a11y_restored" in info:
            detail["a11y_restored"] = info["a11y_restored"]
        _emit(
            "sandroid",
            "intervention",
            summary=(
                f"intervention {'on' if on else 'off'} · "
                + (
                    "accessibility UI helper (detectable)"
                    if full
                    else "invisible UI helper"
                )
            ),
            actor="sandroid",
            data={
                "what": what,
                "state": "on" if on else "off",
                "detectable": full,
                "detail": detail,
            },
            dev=sess.serial,
        )

    # -- doorbell (label shots) -----------------------------------------------------

    @staticmethod
    def _timeline_last_seq() -> int:
        try:
            from sandroid.core import timeline

            return int(timeline.get_timeline().tail(0).last_seq)
        except Exception:
            return 0

    def _subscribe_bell(self) -> None:
        try:
            from sandroid.core.events import EventBus, EventType

            handler = self.on_timeline_event
            EventBus.get().subscribe(EventType.TIMELINE_EVENT, handler)
            self._bell_handler = handler
        except Exception:
            logger.debug("tracking: no doorbell", exc_info=True)

    def _unsubscribe_bell(self) -> None:
        handler, self._bell_handler = self._bell_handler, None
        if handler is None:
            return
        try:
            from sandroid.core.events import EventBus, EventType

            EventBus.get().unsubscribe(EventType.TIMELINE_EVENT, handler)
        except Exception:
            pass

    def on_timeline_event(self, event: Any) -> None:
        """Writer thread doorbell: queue a label shot, never block."""
        payload = getattr(event, "data", event) or {}
        if not self._active or "label" not in (payload.get("srcs") or ()):
            return
        if not _config().shot_label:
            return
        self._shot_lane.submit(self._label_shots, self._gen)

    def _label_shots(self, gen: int) -> None:
        from sandroid.core import timeline

        svc = timeline.get_timeline()
        active = svc.active_serial
        dev = None if active in (None, self._serial) else self._serial
        res = svc.tail(self._label_seen, dev=dev)
        self._label_seen = max(self._label_seen, res.last_seq)
        for line in res.lines:
            if line.get("src") != "label" or self._gen != gen:
                continue
            self._take("label", of=line["seq"], gen=gen)

    # -- shots ----------------------------------------------------------------------

    def _shots_dir(self) -> Path:
        return (self._folder or self._folder_fn(self._serial or "")) / SHOTS_DIR

    def _screencap(self) -> tuple[bytes | None, float, float, str | None]:
        """Fallback capture: ``(png, t_host, cap_ms, error)``."""
        serial = self._serial or ""
        t0 = time.time()
        rc, out = self._adb(serial, "exec-out", "screencap", "-p", timeout=15.0)
        cap = round((time.time() - t0) * 1000.0, 1)
        if rc != 0 or not out.startswith(b"\x89PNG"):
            return None, t0, cap, f"screencap rc={rc}"
        return out, t0, cap, None

    def _capture(self, t: float | None = None) -> dict[str, Any]:
        """Capture now (helper, else screencap): :meth:`_store` keywords,
        plus ``png`` and the helper's frame ``hash`` (``None`` for screencap).
        """
        helper = self._helper_up()
        if helper is not None:
            res = None
            try:
                res = self._shot_seen(helper)
            except Exception as exc:
                logger.debug(f"tracking shot failed: {exc}")
            if res is not None:
                return self._helper_cap(res, t)
        png, t_host, cap, err = self._screencap()
        w, h = self.geometry.screen
        return {"png": png, "via": "screencap", "w": w, "h": h, "cap_ms": cap,
                "dev_mono": None, "t": t if t is not None else t_host,
                "error": err, "hash": None}  # fmt: skip

    @staticmethod
    def _helper_cap(res: Any, t: float | None = None) -> dict[str, Any]:
        """A helper capture as :meth:`_capture` returns it."""
        return {"png": res.png, "via": "helper", "w": res.w, "h": res.h,
                "cap_ms": res.cap_ms, "dev_mono": res.t_mono_ms / 1000.0,
                "t": t, "error": res.error,
                "hash": getattr(res, "hash", None) or None}  # fmt: skip

    def _take(
        self,
        trigger: str,
        *,
        of: int | None,
        gen: int,
        t: float | None = None,
        actor: str = "sandroid",
        extra: dict | None = None,
        sensitive: bool = False,
    ) -> int | None:
        """Capture now (helper, else screencap) and write the shot line."""
        if gen != self._gen:
            return None
        cap = self._capture(t)
        cap.pop("hash", None)
        return self._store(trigger, cap.pop("png"), of=of, actor=actor, extra=extra,
                           sensitive=sensitive, **cap)  # fmt: skip

    def _sink_buffering(self) -> bool:
        """The timeline holds lines back (no session folder yet): a line's
        seq is unknown when it is emitted.
        """
        try:
            from sandroid.core import timeline

            return timeline.get_timeline().status(self._serial).state == "detached"
        except Exception:
            return False

    def _store(
        self,
        trigger: str,
        png: bytes | None,
        *,
        of: int | None,
        via: str,
        w: int,
        h: int,
        cap_ms: float,
        dev_mono: float | None,
        t: float | None,
        actor: str = "sandroid",
        error: str | None = None,
        extra: dict | None = None,
        sensitive: bool = False,
    ) -> int | None:
        """sha256-dedup the PNG into ``tracking/shots`` and emit the line.

        ``sensitive`` (or a focused password field) marks the line; the image
        is still stored (masking is the readers' job).
        """
        sensitive = sensitive or self._pw_focus
        data: dict[str, Any] = {
            "trigger": trigger,
            "w": w,
            "h": h,
            "cap_ms": cap_ms,
            "via": via,
            "dup_of": None,
            **(extra or {}),
        }
        what = {
            "before_tap": "before",
            "after_tap": "after",
        }.get(trigger)
        kind_word = (extra or {}).get("input", "tap")
        if what:
            summary = f"screenshot {what} {kind_word.replace('_', ' ')} #{of}"
        elif of is not None:
            summary = f"screenshot · {trigger.replace('_', ' ')} #{of}"
        else:
            summary = f"screenshot · {trigger}"
        time_kw: dict[str, Any] = {}
        if t is not None:
            time_kw = {"t": t, "clk": "host"}
            if dev_mono is not None:
                data["cap_t_mono_ms"] = round(dev_mono * 1000.0, 1)
        elif dev_mono is not None:
            time_kw = {"clk": "dev_mono", "dev_mono": dev_mono}
        ref: dict[str, Any] = {}
        if of is not None:
            ref["of"] = of
        if png is None:
            data["error"] = error or "no image"
            return self._emit_shot(trigger, summary + " · failed", data, ref, time_kw,
                                   actor, level="warn", sensitive=sensitive)  # fmt: skip
        sha = hashlib.sha256(png).hexdigest()
        ref["sha256"] = sha
        shots = self._shots_dir()
        with self._sha_lock:
            known_shas = self._sha.setdefault(str(shots), {})
            known = known_shas.get(sha)
            if known is not None:
                ref["path"] = known[0]
                data["dup_of"] = known[1]
                same = f"same as #{known[1]}" if known[1] is not None else "same image"
                return self._emit_shot(trigger, f"{summary} ({same})", data, ref,
                                       time_kw, actor, sensitive=sensitive)  # fmt: skip
            incoming = shots / ".incoming"
            incoming.mkdir(parents=True, exist_ok=True)
            tmp = incoming / f"{uuid.uuid4().hex}.png"
            tmp.write_bytes(png)
            if self._sink_buffering():
                # The line is kept back and gets its seq later: a file name
                # that does not depend on it, stored before the line exists.
                name = f"{SHOTS_DIR}/{sha[:16]}_{trigger}.png"
                try:
                    tmp.replace(self._folder_path(shots, name))
                except OSError as exc:
                    logger.warning(f"Tracking: cannot store screenshot {name}: {exc}")
                ref["path"] = name
                seq = self._emit_shot(trigger, summary, data, ref, time_kw, actor,
                                      sensitive=sensitive)  # fmt: skip
                known_shas[sha] = (name, seq)
                return seq
            ref["path"] = f"{SHOTS_DIR}/{{seq}}_{trigger}.png"
            seq = self._emit_shot(trigger, summary, data, ref, time_kw, actor,
                                  sensitive=sensitive)  # fmt: skip
            if seq is None:
                if self._sink_buffering():
                    # Buffered after all (the session closed meanwhile): the
                    # line will be written, so its image must stay.
                    logger.debug(f"Tracking: screenshot kept as {tmp}")
                else:
                    with contextlib.suppress(OSError):
                        tmp.unlink()
                return None
            final = shots / f"{seq}_{trigger}.png"
            try:
                tmp.replace(final)
            except OSError as exc:
                logger.warning(f"Tracking: cannot store screenshot {final}: {exc}")
                return seq
            known_shas[sha] = (f"{SHOTS_DIR}/{seq}_{trigger}.png", seq)
        return seq

    @staticmethod
    def _folder_path(shots: Path, rel: str) -> Path:
        """``rel`` (``tracking/shots/...``) inside the folder of ``shots``."""
        return shots / rel[len(SHOTS_DIR) + 1 :]

    def _emit_shot(self, trigger, summary, data, ref, time_kw, actor, level="info",
                   sensitive=False):  # fmt: skip
        seq = _emit(
            "shot",
            trigger,
            summary=summary,
            actor=actor,
            data=data,
            ref=ref or None,
            level=level,
            sensitive=sensitive,
            dev=self._serial,
            **time_kw,
        )
        if seq is not None:
            with self._lock:
                self._shots += 1
        return seq

    @staticmethod
    def _late(res: Any, t_up: float | None) -> bool:
        """Captured after the finger went up: not a before-tap image."""
        try:
            return t_up is not None and float(res.t_mono_ms) / 1000.0 > t_up
        except (AttributeError, TypeError, ValueError):
            return False

    def _before_state(
        self, pending: _Pending | None, cfg: Any, t_up: float | None
    ) -> tuple[Any, str]:
        """The input line's ``data.before_shot`` and the capture to store:
        ``taken`` (stored, its shot line has ``ref.of`` = the input),
        ``skipped`` (one was still in flight), ``late`` (captured after the
        finger-up, or not back within :data:`BEFORE_TAP_WAIT_S` of it: the
        helper was busy, e.g. with a screen-change sample; dropped, it could
        show the screen after the tap), ``failed`` (the capture errored; a
        ``failed`` shot line when the helper answered), ``no_helper`` (no
        helper at finger-down) or ``off`` (``shot_before_tap`` off).
        """
        if pending is None:  # never seen at finger-down
            return None, "no_helper" if cfg.shot_before_tap else "off"
        if pending.shot_state is not None:
            return None, pending.shot_state
        if pending.shot is None:
            return None, "failed"
        try:
            res = pending.shot.result(timeout=BEFORE_TAP_WAIT_S)
        except FutureTimeout:
            return None, "late"
        except Exception:
            return None, "failed"
        if res is None:
            return None, "failed"
        if self._late(res, t_up):
            logger.debug("Tracking: a before-tap shot was late, dropped")
            return None, "late"
        if not getattr(res, "png", None):
            return res, "failed"
        return res, "taken"

    def _before_shot(
        self, res: Any, of: int, kind: str, sensitive: bool = False
    ) -> None:
        """Store the before-tap capture ``res`` (on time, see
        :meth:`_before_state`) as the shot line of input ``of``.
        """
        self._store("before_tap", res.png, of=of, via="helper", w=res.w, h=res.h,
                    cap_ms=res.cap_ms, dev_mono=res.t_mono_ms / 1000.0, t=None,
                    error=res.error, extra={"input": kind},
                    sensitive=sensitive)  # fmt: skip

    def _settle(self, helper: Any, cfg: Any) -> tuple[str | None, bool, float]:
        """hash_only shots until two match or ``settle_max_ms``:
        ``(last hash, stable, ms waited)``.
        """
        t0 = time.monotonic()
        deadline = t0 + cfg.settle_max_ms / 1000.0
        prev = None
        while time.monotonic() < deadline:
            time.sleep(cfg.settle_interval_ms / 1000.0)
            try:
                r = self._shot_seen(helper, hash_only=True)
            except Exception:
                r = None
            if r is None:
                break
            if prev is not None and r.hash == prev:
                return prev, True, round((time.monotonic() - t0) * 1000.0, 1)
            prev = r.hash
        return prev, False, round((time.monotonic() - t0) * 1000.0, 1)

    def _after_tap(
        self,
        gen: int,
        of: int,
        kind: str,
        before: Future | None,
        t_up: float | None = None,
        sensitive: bool = False,
    ) -> None:
        cfg = _config()
        if gen != self._gen or not cfg.shot_after_tap:
            return
        helper = self._helper_up()
        if helper is None:
            time.sleep(cfg.settle_interval_ms / 1000.0)
            self._take("after_tap", of=of, gen=gen, extra={"input": kind},
                       sensitive=sensitive)  # fmt: skip
            return
        last, stable, waited = self._settle(helper, cfg)
        before_hash = None
        if before is not None:
            with contextlib.suppress(Exception):
                res = before.result(timeout=2.0)
                if res is not None and not self._late(res, t_up):
                    before_hash = res.hash
        if last is not None and last == before_hash:
            return  # the tap changed nothing on screen
        self._take("after_tap", of=of, gen=gen,
                   extra={"input": kind, "stable": stable, "settle_ms": waited},
                   sensitive=sensitive)  # fmt: skip

    def _settle_change(
        self,
        helper: Any,
        cfg: Any,
        old: Callable[[], set[str]],
        abort: Callable[[], bool] | None = None,
        max_ms: float | None = None,
        ready: Callable[[], bool] | None = None,
        fresh: Callable[[str], bool] | None = None,
    ) -> dict[str, Any]:
        """hash_only shots until the frame is none of ``old()`` (the
        pre-change frames, asked again each round: references can arrive
        late) and two consecutive hashes match, or ``max_ms`` (default
        ``settle_max_ms``). Without references only the settling counts.
        ``abort()`` true ends the wait early (the shot is no longer wanted).

        ``ready()`` false: the references are not complete yet (the
        pre-change hash is pending). Samples are taken meanwhile (the helper
        serialises them behind that hash), but the wait cannot end, and
        ``max_ms`` counts from when ``ready()`` turns true.

        Fallback: a frame seen for the first time that is none of ``old()``
        and ``fresh(hash)`` (with references known) is captured in full by
        the very next sample, at most :data:`SHOT_FALLBACK_MAX` per wait. The
        newest such capture is the fallback; a later frame that is old or
        not fresh voids it (the screen went back: it was a transition).

        Returns ``{stable, ms, last, fb, reuse}``: ``last`` the last hash,
        ``fb`` the fallback (``{res, hash, dev, h0, h1}``: the result, its
        hash, device capture time (s) and host request span) or None,
        ``reuse`` true when the wait ended stable on the fallback capture
        itself (no new capture needed).
        """
        t0 = time.monotonic()
        wait_ms = cfg.settle_max_ms if max_ms is None else max_ms
        deadline = None if ready is not None else t0 + wait_ms / 1000.0
        prev: str | None = None
        stable = reuse = full_next = False
        fb: dict[str, Any] | None = None
        captured: set[str] = set()
        n_full = 0
        while deadline is None or time.monotonic() < deadline:
            if deadline is None and ready():  # type: ignore[misc]
                deadline = time.monotonic() + wait_ms / 1000.0
                prev = None  # stability counts from here (see below)
            if not full_next:
                time.sleep(cfg.settle_interval_ms / 1000.0)
            if abort is not None and abort():
                break
            full, full_next = full_next, False
            h0 = time.time()
            try:
                r = self._shot_seen(helper, hash_only=not full)
            except Exception:
                r = None
            h1 = time.time()
            if r is None:
                break
            if deadline is None and ready():  # type: ignore[misc]
                deadline = time.monotonic() + wait_ms / 1000.0
                # Stability counts from here: a frame sampled while the
                # references were pending (e.g. a ripple that the late
                # pre-change hash also saw) must not settle the wait with
                # the first sample after them.
                prev = None
            stable = r.hash == prev
            prev = r.hash
            if deadline is None:
                stable = False  # no decision before the references are in
                continue
            refs = old()
            new = r.hash not in refs
            ok = bool(refs) and new and (fresh is None or fresh(r.hash))
            if refs and not ok:
                fb = None  # the old screen again: the new one has not drawn
            if full:
                n_full += 1
                captured.add(r.hash)
                if ok and getattr(r, "png", None):
                    try:
                        ms = float(r.t_mono_ms)
                    except (AttributeError, TypeError, ValueError):
                        ms = 0.0
                    fb = {"res": r, "hash": r.hash, "h0": h0, "h1": h1,
                          "dev": ms / 1000.0 if ms > 0 else None}  # fmt: skip
            elif ok and r.hash not in captured and n_full < SHOT_FALLBACK_MAX:
                captured.add(r.hash)
                full_next = True  # capture this new frame now
            if stable and new:
                reuse = fb is not None and fb["res"] is r
                break
        return {
            "stable": stable,
            "ms": round((time.monotonic() - t0) * 1000.0, 1),
            "last": prev,
            "fb": fb,
            "reuse": reuse,
        }

    def _screen_shot(self, gen: int, req: dict) -> None:
        """Shot lane: one screen-change request.

        Waits until the frame differs from the old screen and settles, at
        most ``settle_max_ms`` (a logcat activity line, which fires before
        the new activity draws: :data:`LOGCAT_SETTLE_FACTOR` times that).
        The old screen is the pre-change hash taken at event time when it
        was taken within :data:`SCREEN_BEFORE_MAX_MS` of the event; else
        (``data.before_late_ms``) the frames seen before the event
        (:meth:`_old_frames`), and the late hash only when none was seen.

        R1: after an input (the triggering input: the latest finger-down
        or key before the event) the previous screen is that input's
        before-tap frame (:meth:`_prev_screen`). A final frame equal to it
        -- the same hash, or, with the before-tap PNG at hand, perceptually
        the same (:func:`same_screen`: a faded scrollbar or a 1 px nudge
        changes the hash) -- is never stored: dropped, counted
        ``unverified`` -- whether or not the pre-change hash was late
        (R4 then shows the next before-tap). The one exception: an a11y window
        line whose timely pre-change hash equals the final frame keeps it,
        flagged ``data.unchanged``. Otherwise a final frame equal to a
        timely pre-change hash is flagged ``data.unchanged``, and one equal
        to another old-screen frame is dropped (``unverified``). One capture
        serves every line of the request (the later ones are dedup lines);
        ``data.lag_ms`` is capture instant - event time.

        A capture that would start (or, per the helper's device time, was
        taken) after the next input's finger-down, or after a newer screen
        superseded this one, would show the next screen under this one's
        line. A fallback is stored instead, ``data.stable:false`` and
        ``data.fallback``: R2 (:meth:`_fallback_r2`) with a previous
        screen, else (R3, no triggering input) the settle's new frame when
        :meth:`_fallback_ok`. Without one the shot is dropped and counted.
        """
        with self._lock:
            with contextlib.suppress(ValueError):
                self._screen_q.remove(req)
            if req.get("superseded"):
                return  # dropped (and counted) when the newer screen came
            self._screen_cur = req
        try:
            cfg = _config()
            if gen != self._gen or not cfg.shot_screen_change:
                return
            if self._drop_if_late(req, capture=False):
                return
            extra: dict[str, Any] = {}
            helper = self._helper_up()
            before: str | None = None
            timely = False
            last: str | None = None
            fb: dict[str, Any] | None = None
            reuse = False

            def old() -> set[str]:
                """The old-screen references (see above)."""
                if timely:
                    # a logcat line comes before the draw: every frame seen
                    # before it is the old screen too
                    frames = self._old_frames(req) if req.get("logcat") else set()
                    return {before} | frames  # type: ignore[arg-type]
                return self._old_frames(req) or ({before} if before else set())

            def bad(frame: str) -> bool:
                """``frame`` may be the old screen: a reference, or the late
                pre-change hash (either screen). Never a fallback.
                """
                return frame == before or frame in old()

            if helper is not None:
                fut = req["before"]
                t_wait = time.monotonic()
                pending = fut is not None

                def ready() -> bool:
                    """The pre-change hash is in, or given up on (after
                    ``settle_max_ms``).
                    """
                    nonlocal pending, before, timely
                    if not pending:
                        return True
                    if not fut.done() and (
                        time.monotonic() - t_wait < cfg.settle_max_ms / 1000.0
                    ):
                        return False
                    pending = False
                    with contextlib.suppress(Exception):
                        res, start = fut.result(timeout=0)
                        before = getattr(res, "hash", None) or None
                        if before is not None:
                            before_lag = self._lag_ms(
                                req, start, getattr(res, "t_mono_ms", None)
                            )
                            if before_lag > SCREEN_BEFORE_MAX_MS:
                                extra["before_late_ms"] = before_lag
                            else:
                                timely = True
                    return True

                max_ms = float(cfg.settle_max_ms)
                if req.get("logcat"):
                    max_ms = max(
                        max_ms,
                        min(max_ms * LOGCAT_SETTLE_FACTOR, LOGCAT_SETTLE_CAP_MS),
                    )
                st = self._settle_change(
                    helper,
                    cfg,
                    old,
                    abort=lambda: bool(req.get("superseded")) or self._input_after(req),
                    max_ms=max_ms,
                    ready=ready,
                    fresh=lambda frame: frame != before,
                )
                last, fb, reuse = st["last"], st["fb"], st["reuse"]
                extra.update(stable=st["stable"], settle_ms=st["ms"])
            else:
                time.sleep(cfg.settle_interval_ms / 1000.0)
            if gen != self._gen or not _config().shot_screen_change:
                return
            why = self._late_reason(req)
            if why is not None and not (reuse and self._in_time(req, fb)):
                self._store_fallback(gen, req, fb, bad, helper, extra, why)
                return
            with self._lock:
                seqs = list(req["seqs"])
            if reuse and fb is not None:
                # the settled frame is the fallback capture: no new capture
                cap_host = fb["h0"]
                cap = self._helper_cap(fb["res"])
            else:
                cap_host = time.time()
                cap = self._capture()
            png = cap.pop("png")
            frame = cap.pop("hash", None) or last
            dev_s = cap.get("dev_mono")
            if dev_s is not None and self._input_after(req, until_dev=dev_s):
                # the helper took it after the next finger-down (it was busy)
                self._store_fallback(gen, req, fb, bad, helper, extra, "late")
                return
            if helper is not None and frame:
                same = timely and frame == before
                prev = self._prev_screen(req)
                keep = same and req.get("a11y")  # the one R1 exception
                if (
                    (prev is not None and frame == prev and not keep)
                    or (
                        not same
                        and (timely or self._old_frames(req))
                        and frame in old()
                    )
                    or (
                        prev is not None
                        and frame != prev
                        and not keep
                        and same_screen(png, req.get("prev_png"))
                    )
                ):
                    # still the previous screen: the new one has not drawn
                    with self._lock:
                        self._drop_locked(req, "unverified")
                    return
                if same:
                    extra["unchanged"] = True  # the frame never left the old one
            extra["lag_ms"] = self._lag_ms(
                req, cap_host, dev_s * 1000.0 if dev_s is not None else None
            )
            for seq in seqs:
                if gen != self._gen:
                    return
                self._store("screen_change", png, of=seq, extra=extra, **cap)
        finally:
            with self._lock:
                req["open"] = False
                if self._screen_cur is req:
                    self._screen_cur = None

    def _in_time(self, req: dict, fb: dict[str, Any] | None) -> bool:
        """The capture ``fb`` was taken (helper device time) before the
        next input's finger-down, and before the newer screen that
        superseded ``req`` (if any).
        """
        if fb is None or fb["dev"] is None:
            return False
        if self._input_after(req, until_dev=fb["dev"]):
            return False
        sup = req.get("sup_ev")
        if sup is None:
            return True
        ev_dev, t_new = sup
        if fb["h0"] > t_new + INPUT_SKEW_S:
            return False
        if ev_dev is not None:
            return fb["dev"] < ev_dev
        return fb["h1"] <= t_new

    def _fallback_ok(
        self,
        req: dict,
        fb: dict[str, Any],
        bad: Callable[[str], bool],
        helper: Any,
    ) -> bool:
        """R3 (no triggering input): the fallback may stand for ``req``'s
        screen: it is not (now) an old-screen frame, it is :meth:`_in_time`,
        and no frame seen after it is an old-screen frame (one more hash is
        taken to check: a ripple or a transition of the old screen ends back
        on the old screen).
        """
        if bad(fb["hash"]) or not self._in_time(req, fb):
            return False
        if helper is not None:
            with contextlib.suppress(Exception):
                self._shot_seen(helper, hash_only=True)
        with self._lock:
            frames = list(self._frames)
        for dev, h0, h1, frame in frames:
            after = h0 >= fb["h1"] or (
                dev is not None and dev > fb["dev"] and h1 >= fb["h0"]
            )
            if after and bad(frame):
                return False
        return True

    def _fallback_r2(
        self, req: dict, fb: dict[str, Any] | None, prev: str
    ) -> dict[str, Any] | None:
        """R2 (with the previous screen ``prev`` of R1): the fallback of
        ``req``, from frames seen before the next input only (frames after
        it are irrelevant: the screen is expected to change then).

        The window: frames from the screen event to the next input's
        finger-down (or the newer screen event that superseded ``req``),
        then the next input's before-tap capture, taken at its finger-down
        (the last frame before that input). The settle's fallback ``fb`` is
        valid when it differs from ``prev``, is :meth:`_in_time`, was seen
        at least twice in a row or is the last frame of the window, and the
        window never shows ``prev`` after it. Else the before-tap capture,
        when it differs from ``prev``. None: no valid fallback.
        """
        nxt = self._input_next(req)
        sup = req.get("sup_ev")  # (device s | None, host epoch)
        sup_first = sup is not None and (
            nxt is None or (sup[0] < nxt[0] if sup[0] is not None else sup[1] < nxt[1])
        )
        end_dev, end_host = (sup if sup_first else nxt) or (None, None)
        # a newer screen that came first: the next input acted on it
        tap = None if sup_first else self._tap_shot(nxt)
        with self._lock:
            frames = list(self._frames)
        win: list[tuple[float | None, str]] = []
        for dev, h0, h1, frame in frames:
            if self._dev_ok(dev, h0, h1, req) and end_dev is not None:
                ok = req["ev_dev"] <= dev < end_dev
            elif self._dev_ok(dev, h0, h1, req):
                ok = dev >= req["ev_dev"] and (end_host is None or h1 <= end_host)
            else:
                ok = h0 >= req["t_evt"] and (end_host is None or h1 <= end_host)
            if ok:
                win.append((dev, frame))
        seq = [frame for _dev, frame in win]
        if tap is not None:
            seq.append(str(tap.hash))
        if fb is not None and fb["hash"] != prev and self._in_time(req, fb):
            at = next(
                (i for i, w in enumerate(win) if w == (fb["dev"], fb["hash"])),
                None,
            )
            h = fb["hash"]
            if at is not None and prev not in seq[at + 1 :]:
                twice = (at > 0 and seq[at - 1] == h) or (
                    at + 1 < len(seq) and seq[at + 1] == h
                )
                if twice or seq[-1] == h:
                    return fb
        if tap is not None and tap.hash != prev:
            with self._lock:
                spans = [f for f in self._frames if f[3] == tap.hash]
            dev = float(tap.t_mono_ms) / 1000.0
            h0, h1 = next(
                ((f[1], f[2]) for f in spans if f[0] == dev), (time.time(),) * 2
            )
            return {"res": tap, "hash": str(tap.hash), "dev": dev, "h0": h0,
                    "h1": h1, "source": "next_before_tap"}  # fmt: skip
        return None

    def _store_fallback(
        self,
        gen: int,
        req: dict,
        fb: dict[str, Any] | None,
        bad: Callable[[str], bool],
        helper: Any,
        extra: dict[str, Any],
        why: str,
    ) -> None:
        """The wait ended, or the capture came, too late (``why``): store a
        fallback (``data.stable:false``, ``data.fallback``) -- with a
        previous screen (R1) the one :meth:`_fallback_r2` picks, else (R3)
        ``fb`` when :meth:`_fallback_ok` -- or drop the shot (counted
        ``why``).
        """
        prev = self._prev_screen(req) if gen == self._gen else None
        if prev is not None:
            fb = self._fallback_r2(req, fb, prev)
        elif fb is not None and not self._fallback_ok(req, fb, bad, helper):
            fb = None
        if fb is None or gen != self._gen:
            with self._lock:
                self._drop_locked(req, why)
            return
        with self._lock:
            seqs = list(req["seqs"])
        cap = self._helper_cap(fb["res"])
        cap.pop("hash", None)
        png = cap.pop("png")
        data = {**extra, "stable": False, "fallback": True}
        if fb.get("source"):
            data["source"] = fb["source"]
        data["lag_ms"] = self._lag_ms(req, fb["h0"], fb["dev"] * 1000.0)
        for seq in seqs:
            if gen != self._gen:
                return
            self._store("screen_change", png, of=seq, extra=data, **cap)

    def _late_reason(self, req: dict, *, capture: bool = True) -> str | None:
        """``"superseded"`` when a newer screen superseded ``req``, ``"late"``
        when the next input came already, else None. With ``capture`` (the
        capture starts now) the request is closed to new lines either way.
        """
        late = self._input_after(req)
        with self._lock:
            if capture or late:
                req["open"] = False
            if req.get("superseded"):
                return "superseded"
        return "late" if late else None

    def _drop_if_late(self, req: dict, *, capture: bool = True) -> bool:
        """Drop ``req`` (counted once) when :meth:`_late_reason` says so."""
        why = self._late_reason(req, capture=capture)
        if why is None:
            return False
        with self._lock:
            self._drop_locked(req, why)
        return True

    def _manual(self, gen: int, t: float, actor: str) -> None:
        self._take("manual", of=None, gen=gen, t=t, actor=actor)


# ---------------------------------------------------------------------------
# net flows
# ---------------------------------------------------------------------------


def _size(n: Any) -> str:
    try:
        n = float(n or 0)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB"):
        if n < 1024 or unit == "MB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


class NetFlowSource:
    """One ``net/flow`` (or ``net/tls-fail``) line per finished mitmproxy flow.

    :meth:`on_line` (mitmweb's listener thread) only rings a bell; a worker
    thread debounces it (:data:`NET_DEBOUNCE_S`) and reads the new records of
    ``flows.jsonl`` with ``query_flows(since_cursor=...)``.

    Sinks (:meth:`add_sink`, process-wide, e.g. the privacy scan) are called
    on the worker after each ``net/flow`` line with ``(rec, flow_dir, seq)``;
    they must only enqueue.
    """

    _sinks: ClassVar[list[Callable[[dict, Path, int | None], None]]] = []
    _sinks_lock: ClassVar[threading.Lock] = threading.Lock()

    @classmethod
    def add_sink(cls, sink: Callable[[dict, Path, int | None], None]) -> None:
        """Call ``sink(rec, flow_dir, seq)`` after every ``net/flow`` line."""
        with cls._sinks_lock:
            if sink not in cls._sinks:
                cls._sinks.append(sink)

    @classmethod
    def remove_sink(cls, sink: Callable[[dict, Path, int | None], None]) -> None:
        """Undo :meth:`add_sink` (no-op when not added)."""
        with cls._sinks_lock:
            if sink in cls._sinks:
                cls._sinks.remove(sink)

    def __init__(
        self,
        *,
        flow_dir_fn: Callable[[], Path] | None = None,
        folder_fn: Callable[[], Path] | None = None,
        debounce_s: float = NET_DEBOUNCE_S,
    ) -> None:
        self._flow_dir_fn = flow_dir_fn
        self._folder_fn = folder_fn
        self._debounce = debounce_s
        self._bell = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.cursor = 0
        self.emitted = 0

    def _flow_dir(self) -> Path:
        if self._flow_dir_fn is not None:
            return self._flow_dir_fn()
        from sandroid.services.mitmproxy_flow_log import resolve_flow_dir

        return resolve_flow_dir()

    def _folder(self) -> Path:
        if self._folder_fn is not None:
            return self._folder_fn()
        from sandroid.core import timeline

        try:
            status = timeline.get_timeline().status()
            if status.folder:
                return Path(status.folder)
        except Exception:
            pass
        return timeline.timeline_folder()

    def start(self) -> None:
        """Begin after the flows already logged; start the worker."""
        from sandroid.services.mitmproxy_flow_log import read_meta

        try:
            self.cursor = int(read_meta(self._flow_dir()).get("latest_seq") or 0)
        except Exception:
            self.cursor = 0
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="net-flows", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Stop the worker (it writes the flows that arrived meanwhile)."""
        self._stop.set()
        self._bell.set()
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(timeout)

    def on_line(self, line: str) -> None:
        """Mitmweb listener: a doorbell only, never any I/O here."""
        if line.startswith(NET_TAGS):
            self._bell.set()

    def _loop(self) -> None:
        while True:
            self._bell.wait()
            if not self._stop.is_set():
                self._stop.wait(self._debounce)
            self._bell.clear()
            try:
                self.poll()
            except Exception:
                logger.debug("net flows: poll failed", exc_info=True)
            if self._stop.is_set():
                return

    def poll(self) -> int:
        """Write lines for every record after the cursor; how many."""
        from sandroid.services.mitmproxy_flow_log import query_flows, read_meta

        flow_dir = self._flow_dir()
        n = 0
        with self._lock:
            latest = int(read_meta(flow_dir).get("latest_seq") or 0)
            if latest < self.cursor:  # flows were cleared and renumbered
                self.cursor = 0
            while True:
                res = query_flows(flow_dir, since_cursor=self.cursor, limit=2000)
                gap = bool(res.get("gap_before_cursor"))
                if gap:
                    logger.warning(
                        f"net flows: records after #{self.cursor} were trimmed "
                        f"before the timeline saw them (next #{res.get('earliest_available_seq')})"
                    )
                for i, rec in enumerate(res.get("flows") or ()):
                    gap_info = None
                    if gap and i == 0:
                        gap_info = {
                            "after": self.cursor,
                            "earliest": res.get("earliest_available_seq"),
                        }
                    seq = self._emit(rec, flow_dir, gap_info)
                    self._notify_sinks(rec, flow_dir, seq)
                    n += 1
                self.cursor = int(res.get("next_cursor") or self.cursor)
                if not res.get("truncated"):
                    break
        self.emitted += n
        return n

    def _notify_sinks(self, rec: dict, flow_dir: Path, seq: int | None) -> None:
        """Hand a ``net/flow`` record to the sinks (never ``net/tls-fail``).

        ``seq`` None: the line was left out by policy (sinks get None), or
        there is no open timeline at all (sinks are skipped).
        """
        if rec.get("kind") == "tls":
            return
        with self._sinks_lock:
            sinks = list(self._sinks)
        if not sinks:
            return
        if seq is None:
            from sandroid.core import timeline

            try:
                if timeline.get_timeline().status().state not in ("open", "capture"):
                    return
            except Exception:
                return
        for sink in sinks:
            try:
                sink(rec, flow_dir, seq)
            except Exception:
                logger.debug("net flows: sink failed", exc_info=True)

    def _emit(self, rec: dict, flow_dir: Path, gap: dict | None) -> int | None:
        app = rec.get("app") or None
        host = rec.get("host") or "?"
        ref: dict[str, Any] = {"id": rec.get("id"), "lens": "network"}
        level = "info"
        if rec.get("kind") == "tls":
            kind = "tls-fail"
            reason = rec.get("tls_reason") or rec.get("error")
            data: dict[str, Any] = {
                "host": host,
                "reason": reason,
                "app": app,
                "error": rec.get("error"),
                "flow_seq": rec.get("seq"),
            }
            summary = f"TLS fail {host} · {reason}"
        else:
            kind = "flow"
            ref["path"] = _rel(
                flow_dir / "details" / f"{rec.get('id')}.json", self._folder()
            )
            t0, t1 = rec.get("ts_start"), rec.get("ts_end")
            dur = round((t1 - t0) * 1000.0, 1) if t0 and t1 else None
            status = rec.get("status_code")
            data = {
                "method": rec.get("method"),
                "host": host,
                "path": rec.get("path"),
                "status": status,
                "req_bytes": rec.get("request_bytes"),
                "resp_bytes": rec.get("response_bytes"),
                "dur_ms": dur,
                "protocol": rec.get("protocol"),
                "app": app,
                "error": rec.get("error"),
                "flow_seq": rec.get("seq"),
            }
            size = _size(
                (rec.get("request_bytes") or 0) + (rec.get("response_bytes") or 0)
            )
            summary = (
                f"{rec.get('method')} {status if status is not None else 'ERR'} "
                f"{host}{rec.get('path') or ''} · {size}"
            )
            if rec.get("error"):
                level = "warn"
        if gap is not None:
            data["gap"] = gap
            level = "warn"
        return _emit(
            "net",
            kind,
            summary=summary,
            actor="app",
            t=rec.get("ts_start"),
            clk="host",
            pkg=app,
            data=data,
            ref=ref,
            level=level,
        )


# ---------------------------------------------------------------------------
# singleton
# ---------------------------------------------------------------------------

_SERVICE: TrackingService | None = None
_SINGLETON_LOCK = threading.Lock()


def get_tracking() -> TrackingService:
    """The process's Tracking service (created on first use)."""
    global _SERVICE
    with _SINGLETON_LOCK:
        if _SERVICE is None:
            _SERVICE = TrackingService()
            atexit.register(_atexit_stop)
        return _SERVICE


def is_active(serial: str | None = None) -> bool:
    """Tracking on? Cheap (never creates the service)."""
    service = _SERVICE
    return service is not None and service.is_active(serial)


def shutdown_tracking(
    reason: str = "quit", timeout: float = 5.0, actor: str | None = "sandroid"
) -> None:
    """Quit step: stop Tracking (``tracking/stop`` with ``reason``), its
    helper and every getevent, and allow no restart from now on. Touches
    only a service that exists already (none is created on the way out).
    """
    service = _SERVICE
    if service is not None:
        service.shutdown(timeout, reason=reason, actor=actor)


def _atexit_stop() -> None:
    with contextlib.suppress(Exception):
        shutdown_tracking("exit", 5.0)


def reset_for_tests() -> None:
    """Drop the singleton (tests)."""
    global _SERVICE
    with _SINGLETON_LOCK:
        _SERVICE = None


__all__ = [
    "GE_LINE",
    "KEY_NAMES",
    "Geometry",
    "Gesture",
    "GeteventStream",
    "NetFlowSource",
    "TouchDecoder",
    "TrackingService",
    "TrackingState",
    "get_tracking",
    "is_active",
    "parse_getevent",
    "parse_getevent_p",
    "parse_wm_size",
    "shutdown_tracking",
]
