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
  after waiting at most :data:`NODE_WAIT_S` for the element, never for the
  screenshot or the a11y confirmation, which follow as their own lines with
  ``ref.of`` = the input seq.
* Helper a11y events give ``input/text`` (coalesced per field; ``sensitive``
  for password fields; the summary never carries the text), ``input/confirm``
  and ``screen/window``; a logcat reader gives ``screen/activity`` when the
  helper cannot.
* Screenshots are stored once per content (sha256) under
  ``tracking/shots/<seq>_<trigger>.png``.

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
from typing import TYPE_CHECKING, Any

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
#: Max points of a swipe path.
PATH_MAX = 32
#: Default MT axis maximum (virtio multitouch).
MT_MAX = 32_767
#: Net doorbell debounce.
NET_DEBOUNCE_S = 0.2
NET_TAGS = ("[FLOW]|", "[TLS_FAIL]|", "[FLOW_ERR]|")
#: getevent restart back-off while a lease is held.
RESTART_BACKOFF_S = (1.0, 2.0, 4.0, 8.0, 10.0)

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

    ``x0/y0`` are the MT values at down, ``x1/y1`` at up; ``path`` holds
    ``(x, y, t_s)`` samples of the first pointer.
    """

    dev: str
    t_down: float
    line_a: int
    slot: int = 0
    x0: int = 0
    y0: int = 0
    x1: int = 0
    y1: int = 0
    uncertain: bool = False
    t_up: float | None = None
    line_b: int | None = None
    pointers: int = 1
    path: list[tuple[int, int, float]] = field(default_factory=list)
    key_code: int | None = None
    host_recv: float = 0.0
    gid: int = 0


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
        self.moved: set[int] = set()
        self.active: set[int] = set()
        self.gesture: Gesture | None = None
        self.keys: dict[int, tuple[float, int]] = {}


class TouchDecoder:
    """Incremental decoder of all-nodes ``getevent -t`` lines.

    Multitouch protocol B per device node; a gesture opens at the first
    tracking id and closes when no slot is active any more. ``uncertain`` is
    set when X or Y of the pointer was never seen since the stream (re)started
    (the kernel does not repeat unchanged axis values).
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
        if st.frame_start is None:
            st.frame_start = line_no
        if typ == EV_ABS:
            self._abs(st, ts, code, val)
            return []
        if typ == EV_KEY:
            return self._key(st, dev, ts, code, val, line_no)
        if typ == EV_SYN and code == 0:
            return self._syn(st, dev, ts, line_no)
        return []

    @staticmethod
    def _abs(st: _DevState, ts: float, code: int, val: int) -> None:
        if code == ABS_MT_SLOT:
            st.slot = val
            return
        s = st.slots.setdefault(st.slot, {"x": 0, "y": 0, "tid": -1})
        if code == ABS_MT_TRACKING_ID:
            if val >= 0:
                s["tid"] = val
                st.downs[st.slot] = ts
            elif s["tid"] >= 0:
                s["tid"] = -1
                st.ups[st.slot] = ts
        elif code == ABS_MT_X:
            s["x"], s["sx"] = val, True
            st.moved.add(st.slot)
        elif code == ABS_MT_Y:
            s["y"], s["sy"] = val, True
            st.moved.add(st.slot)

    def _key(
        self, st: _DevState, dev: str, ts: float, code: int, val: int, line_no: int
    ) -> list[DecodedEvent]:
        if code >= 0x100:  # BTN_* (BTN_TOUCH on the touch node, ...)
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

    def _syn(
        self, st: _DevState, dev: str, ts: float, line_no: int
    ) -> list[DecodedEvent]:
        out: list[DecodedEvent] = []
        for slot, t_down in sorted(st.downs.items()):
            s = st.slots.get(slot, {})
            st.active.add(slot)
            if st.gesture is None:
                self._gid += 1
                st.gesture = Gesture(
                    dev=dev,
                    t_down=t_down,
                    line_a=st.frame_start if st.frame_start is not None else line_no,
                    slot=slot,
                    x0=s.get("x", 0),
                    y0=s.get("y", 0),
                    x1=s.get("x", 0),
                    y1=s.get("y", 0),
                    uncertain=not (s.get("sx") and s.get("sy")),
                    gid=self._gid,
                )
                st.gesture.path.append((s.get("x", 0), s.get("y", 0), t_down))
                out.append(DecodedEvent("down", st.gesture))
            st.gesture.pointers = max(st.gesture.pointers, len(st.active))
        g = st.gesture
        if g is not None and g.slot in st.moved and g.slot not in st.downs:
            s = st.slots.get(g.slot, {})
            g.x1, g.y1 = s.get("x", g.x1), s.get("y", g.y1)
            g.path.append((g.x1, g.y1, ts))
        for slot in st.ups:
            st.active.discard(slot)
            if g is not None and slot == g.slot:
                s = st.slots.get(slot, {})
                g.x1, g.y1 = s.get("x", g.x1), s.get("y", g.y1)
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
    pid this stream started (never a pattern kill). Every line goes to
    :attr:`raw_path` (0600) before subscribers see ``(line, line_no,
    host_recv)``; ``line_no`` continues the existing file's count.
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
    ) -> None:
        self.serial = serial
        self.raw_path = Path(raw_path)
        self._popen = popen
        self._run = run
        self._argv = argv
        self._on_closed = on_closed
        self._backoff = backoff
        self._lock = threading.Lock()
        self._subs: list[Callable[[str, int, float], None]] = []
        self._refs = 0
        self._n = 0
        self._fh: Any = None
        self._proc: Any = None
        self._pid: int | None = None
        self._stop = threading.Event()
        self._reader: threading.Thread | None = None
        self._teardown: threading.Thread | None = None
        self.restarts = 0

    # -- leases --------------------------------------------------------------

    def acquire(self) -> bool:
        """Take a lease; the first one starts getevent. False on failure."""
        with self._lock:
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
        """Give one lease back; the last one stops the reader (background)."""
        with self._lock:
            if self._refs <= 0:
                return
            self._refs -= 1
            if self._refs:
                return
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

    def line_no(self) -> int:
        """Lines in :attr:`raw_path` so far (the last line's number)."""
        with self._lock:
            return self._n

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
                    for cb in subs:
                        try:
                            cb(line, n, host)
                        except Exception:
                            logger.debug("getevent subscriber failed", exc_info=True)
            with contextlib.suppress(Exception):
                proc.wait(timeout=1.0)
            if self._stop.is_set():
                break
            delay = self._backoff[min(attempt, len(self._backoff) - 1)]
            attempt += 1
            logger.info(
                f"Tracking: getevent on {self.serial} ended; restart in {delay:.0f}s"
            )
            if self._stop.wait(delay):
                break
            with self._lock:
                if self._stop.is_set():
                    break
                try:
                    self._spawn()
                    self.restarts += 1
                except Exception as exc:
                    logger.debug(f"getevent respawn failed: {exc}")

    def _kill(self, proc: Any, pid: int | None) -> None:
        target = str(pid) if pid else f"$(cat {PIDFILE})"
        self._run(
            [
                *_base_argv(self.serial),
                "shell",
                f"kill {target} 2>/dev/null; rm -f {PIDFILE}",
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
        self._streams: dict[str, GeteventStream] = {}
        self._closing: dict[str, GeteventStream] = {}
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
        self._stream: GeteventStream | None = None
        self._unsub: Callable[[], None] | None = None
        self._helper: Any = None
        self._helper_stop: threading.Thread | None = None
        self._intervention_on = False
        self._logcat: Any = None
        self._bell_handler: Callable[..., None] | None = None
        self._decoder = TouchDecoder()
        self.geometry = Geometry()
        self._geometry_ready = threading.Event()
        self._pending: dict[int, _Pending] = {}
        self._recent_inputs: deque[dict] = deque(maxlen=64)
        self._recent_clicks: deque[dict] = deque(maxlen=64)
        self._text: dict | None = None
        self._last_screen: tuple | None = None
        self._last_window_host = 0.0
        self._activities: list[dict] = []
        self._screen_req: dict | None = None
        self._label_seen = 0
        self._sha: dict[str, tuple[str, int]] = {}
        self._sha_lock = threading.Lock()
        self._ticker: threading.Thread | None = None
        self._tick_stop = threading.Event()
        # lanes
        self._node_lane = _Lane("tracking-node")
        self._pre_lane = _Lane("tracking-pre")
        self._order_lane = _Lane("tracking-order")
        self._shot_lane = _Lane("tracking-shot")
        self._store_lane = _Lane("tracking-store")

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
            closing = self._closing.pop(serial, None)
        if closing is not None:
            closing.wait_closed()
        with self._lock:
            stream = self._streams.get(serial)
            if stream is None:
                raw = self._folder_fn(serial) / RAW_DIR / GETEVENT_FILE
                stream = GeteventStream(
                    serial,
                    raw,
                    popen=self._popen,
                    run=self._run,
                    on_closed=self._stream_closed,
                )
                self._streams[serial] = stream
            if not stream.acquire():
                if stream.leases == 0:
                    self._streams.pop(serial, None)
                raise RuntimeError(f"getevent could not be started on {serial}")
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
        with self._lock:
            if self._active:
                return self._serial == serial
            cfg = _config()
            folder = self._folder_fn(serial)
            try:
                stream = self.getevent(serial)
            except RuntimeError as exc:
                logger.warning(f"Tracking: {exc}")
                return False
            self._gen += 1
            gen = self._gen
            self._active = True
            self._serial = serial
            self._folder = folder
            self._mode = str(cfg.helper_mode)
            self._helper_state = "off" if self._mode == "off" else "starting"
            self._since = time.time()
            self._reason = reason
            self._inputs = self._shots = self._keys_other = 0
            self._decoder = TouchDecoder()
            self.geometry = Geometry()
            self._geometry_ready.clear()
            self._pending.clear()
            self._recent_inputs.clear()
            self._recent_clicks.clear()
            self._text = None
            self._last_screen = None
            self._activities = []
            self._screen_req = None
            self._intervention_on = False
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
        self._unsub = stream.subscribe(self._on_getevent)
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
        return True

    def stop(self, *, reason: str = "user", actor: str | None = None) -> None:
        """Turn Tracking off (pending gestures are written first)."""
        with self._lock:
            if not self._active:
                return
            self._active = False
            self._gen += 1
            serial = self._serial
            unsub, self._unsub = self._unsub, None
            stream, self._stream = self._stream, None
            helper, self._helper = self._helper, None
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
            since = self._since or time.time()
        _emit(
            "tracking",
            "stop",
            summary=f"◎ tracking off · {inputs} inputs, {shots} shots",
            actor=actor or self._actor("user"),
            data={
                "reason": reason,
                "inputs": inputs,
                "shots": shots,
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
                args=(helper,),
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

    def shutdown(self, timeout: float = 5.0) -> None:
        """Process exit: stop Tracking and every getevent, bounded."""
        with contextlib.suppress(Exception):
            self.stop(reason="exit", actor="sandroid")
        t = self._helper_stop
        if t is not None:
            t.join(timeout)
        with self._lock:
            streams = list(self._streams.values()) + list(self._closing.values())
        for stream in streams:
            while stream.leases:
                stream.release()
            stream.wait_closed(timeout)

    # -- bootstrap (background) --------------------------------------------------

    def _bootstrap(self, gen: int, serial: str, folder: Path) -> None:
        self._clock_record("tracking-start", serial)
        try:
            self._probe_geometry(serial)
        finally:
            self._geometry_ready.set()
        if _config().logcat_screen_backup and self._gen == gen:
            self._start_logcat(gen, serial)
        if self._mode == "off" or self._gen != gen:
            return
        helper = self._helper_factory(
            serial,
            self._mode,
            self._on_helper_event,
            self._on_helper_status,
            folder / RAW_DIR / HELPER_FILE,
        )
        with self._lock:
            if self._gen != gen:
                return
            self._helper = helper
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
            self._stop_helper(helper)
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

    def _stop_helper(self, helper: Any) -> None:
        try:
            helper.stop()
        except Exception:
            logger.debug("tracking: helper stop failed", exc_info=True)
        if self._intervention_on:  # no "stopped" status came (fake/old helper)
            self._intervention(False, {})

    # -- getevent -> input ------------------------------------------------------

    def _on_getevent(self, line: str, line_no: int, host_recv: float) -> None:
        """Reader thread: decode and queue, never block."""
        for ev in self._decoder.feed(line, line_no):
            g = ev.gesture
            g.host_recv = host_recv
            if ev.kind == "down":
                self._at_down(g)
            else:
                gen = self._gen
                self._order_lane.submit(self._finish, gen, g)

    def _helper_up(self) -> Any:
        helper = self._helper
        if helper is None or not getattr(helper, "alive", False):
            return None
        return helper

    def _at_down(self, g: Gesture) -> None:
        helper = self._helper_up()
        if helper is None:
            return
        p = _Pending(t0=time.monotonic())
        full = str(getattr(helper, "mode", self._mode)) == "full"
        if full and self._geometry_ready.is_set():
            x, y = self.geometry.to_px(g.dev, g.x0, g.y0)
            p.node = self._node_lane.submit(
                helper.node_at, x, y, t_mono_ms=round(g.t_down * 1000.0, 1)
            )
        elif full:
            p.node = self._node_lane.submit(self._node_late, helper, g)
        if _config().shot_before_tap:
            p.shot = self._pre_lane.submit(helper.shot)
        self._pending[g.gid] = p

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
        x, y = geo.to_px(g.dev, g.x0, g.y0)
        x1, y1 = geo.to_px(g.dev, g.x1, g.y1)
        sw, sh = geo.screen
        moved = 0.0
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
            "rx": round(x / sw, 4) if sw else None,
            "ry": round(y / sh, 4) if sh else None,
            "screen": [sw, sh],
            "rotation": geo.rotation,
            "dur_ms": dur_ms,
            "pointer": g.slot,
            "xy_uncertain": g.uncertain,
            "helper": self._helper_label(),
        }
        if kind == "gesture":
            data["pointers"] = g.pointers
        if kind == "swipe":
            data["x1"], data["y1"] = x1, y1
            data["path"] = self._path(g, geo)
        target = None
        answer: dict = {}
        pkg = None
        if pending is not None and pending.node is not None:
            try:
                reply = pending.node.result(timeout=NODE_WAIT_S)
                data["node_ms"] = round((time.monotonic() - pending.t0) * 1000.0, 1)
            except FutureTimeout:
                reply = None
                data["node_timeout"] = True
            except Exception:
                reply = None
            target, answer = self._target(reply)
            pkg = answer.get("pkg") if answer else None
        data["target"] = target
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
        }
        self._confirm_input(rec)
        before = pending.shot if pending is not None else None
        if before is not None:
            self._store_lane.submit(self._before_shot, before, seq, kind)
        if cfg.shot_after_tap and kind in ("tap", "long_press"):
            self._shot_lane.submit(self._after_tap, gen, seq, kind, before)

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
                return target, answer
        return None, {}

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
        return f"{word} at {data['x']},{data['y']}"

    # -- helper events ----------------------------------------------------------

    def _on_helper_event(self, d: dict, host_recv: float) -> None:
        """Helper reader thread: bookkeeping and non-blocking emits only."""
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
            self._on_text(d, host_recv)
        elif ev == "FOCUSED":
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
        _emit(
            "input",
            "confirm",
            summary=f"✓ {str(click['ev']).lower().replace('_', ' ')} #{rec['seq']}",
            actor="app",
            clk="dev_mono",
            dev_mono=click["t_ms"] / 1000.0,
            data={
                "a11y": click["ev"],
                "node": {
                    "rid": node.get("rid"),
                    "text": None if _private(node) else node.get("text"),
                    "cls": node.get("cls"),
                },
            },
            ref={"of": rec["seq"]},
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
        self._emit_screen(
            "window",
            pkg=pkg,
            cls=cls,
            title=title,
            window_id=d.get("window_id"),
            via="a11y",
            dev_mono=float(d.get("t_mono_ms") or 0.0) / 1000.0,
        )

    def _emit_screen(
        self, kind: str, *, pkg, cls, title, window_id, via, dev_mono
    ) -> int | None:
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
            with self._lock:
                first = self._screen_req is None
                self._screen_req = {"seq": seq}
            if first:
                self._shot_lane.submit(self._screen_shot, gen)
        return seq

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

    def _emit_activity(self, act: dict) -> None:
        self._emit_screen(
            "activity",
            pkg=act["pkg"],
            cls=act["cls"],
            title=None,
            window_id=None,
            via="logcat",
            dev_mono=act["dev_mono"],
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

    def _on_helper_status(self, state: str, info: dict) -> None:
        serial = self._serial
        mode = info.get("mode", self._mode)
        with self._lock:
            if state in ("connected", "restarted"):
                self._helper_state = "connected"
            elif state == "busy":
                self._helper_state = "busy"
            else:
                self._helper_state = state
        summary = {
            "connected": f"helper connected · {mode}",
            "restarted": f"helper restarted · attempt {info.get('attempt', '?')}",
            "lost": "helper lost · restarting",
            "busy": "helper waiting · another UiAutomation client holds the device",
            "down": "helper down · gave up after repeated deaths",
            "stopped": "helper stopped",
        }.get(state, f"helper {state}")
        data = {
            "helper": state,
            "mode": mode,
            **{
                k: info[k]
                for k in ("pid", "version", "rc", "attempt", "deaths")
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
            self._intervention(True, info)
        elif state in ("down", "stopped"):
            self._intervention(False, info)

    def _intervention(self, on: bool, info: dict) -> None:
        with self._lock:
            if on == self._intervention_on:
                return
            self._intervention_on = on
            mode = info.get("mode", self._mode)
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
            dev=self._serial,
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

    def _take(
        self,
        trigger: str,
        *,
        of: int | None,
        gen: int,
        t: float | None = None,
        actor: str = "sandroid",
        extra: dict | None = None,
    ) -> int | None:
        """Capture now (helper, else screencap) and write the shot line."""
        if gen != self._gen:
            return None
        helper = self._helper_up()
        if helper is not None:
            res = None
            try:
                res = helper.shot()
            except Exception as exc:
                logger.debug(f"tracking shot failed: {exc}")
            if res is not None:
                return self._store(trigger, res.png, of=of, via="helper", w=res.w, h=res.h,
                                   cap_ms=res.cap_ms, dev_mono=res.t_mono_ms / 1000.0,
                                   t=t, actor=actor, error=res.error, extra=extra)  # fmt: skip
        png, t_host, cap, err = self._screencap()
        w, h = self.geometry.screen
        return self._store(trigger, png, of=of, via="screencap", w=w, h=h, cap_ms=cap,
                           dev_mono=None, t=t if t is not None else t_host,
                           actor=actor, error=err, extra=extra)  # fmt: skip

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
    ) -> int | None:
        """sha256-dedup the PNG into ``tracking/shots`` and emit the line."""
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
                                   actor, level="warn")  # fmt: skip
        sha = hashlib.sha256(png).hexdigest()
        ref["sha256"] = sha
        shots = self._shots_dir()
        with self._sha_lock:
            known = self._sha.get(sha)
            if known is not None:
                ref["path"] = known[0]
                data["dup_of"] = known[1]
                return self._emit_shot(trigger, f"{summary} (same as #{known[1]})", data,
                                       ref, time_kw, actor)  # fmt: skip
            incoming = shots / ".incoming"
            incoming.mkdir(parents=True, exist_ok=True)
            tmp = incoming / f"{uuid.uuid4().hex}.png"
            tmp.write_bytes(png)
            ref["path"] = f"{SHOTS_DIR}/{{seq}}_{trigger}.png"
            seq = self._emit_shot(trigger, summary, data, ref, time_kw, actor)
            if seq is None:
                with contextlib.suppress(OSError):
                    tmp.unlink()
                return None
            final = shots / f"{seq}_{trigger}.png"
            try:
                tmp.replace(final)
            except OSError as exc:
                logger.warning(f"Tracking: cannot store screenshot {final}: {exc}")
                return seq
            self._sha[sha] = (f"{SHOTS_DIR}/{seq}_{trigger}.png", seq)
        return seq

    def _emit_shot(self, trigger, summary, data, ref, time_kw, actor, level="info"):
        seq = _emit(
            "shot",
            trigger,
            summary=summary,
            actor=actor,
            data=data,
            ref=ref or None,
            level=level,
            dev=self._serial,
            **time_kw,
        )
        if seq is not None:
            with self._lock:
                self._shots += 1
        return seq

    def _before_shot(self, fut: Future, of: int, kind: str) -> None:
        try:
            res = fut.result(timeout=10.0)
        except Exception:
            res = None
        if res is None:
            return
        self._store("before_tap", res.png, of=of, via="helper", w=res.w, h=res.h,
                    cap_ms=res.cap_ms, dev_mono=res.t_mono_ms / 1000.0, t=None,
                    error=res.error, extra={"input": kind})  # fmt: skip

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
                r = helper.shot(hash_only=True)
            except Exception:
                r = None
            if r is None:
                break
            if prev is not None and r.hash == prev:
                return prev, True, round((time.monotonic() - t0) * 1000.0, 1)
            prev = r.hash
        return prev, False, round((time.monotonic() - t0) * 1000.0, 1)

    def _after_tap(self, gen: int, of: int, kind: str, before: Future | None) -> None:
        cfg = _config()
        if gen != self._gen or not cfg.shot_after_tap:
            return
        helper = self._helper_up()
        if helper is None:
            time.sleep(cfg.settle_interval_ms / 1000.0)
            self._take("after_tap", of=of, gen=gen, extra={"input": kind})
            return
        last, stable, waited = self._settle(helper, cfg)
        before_hash = None
        if before is not None:
            with contextlib.suppress(Exception):
                res = before.result(timeout=2.0)
                before_hash = res.hash if res is not None else None
        if last is not None and last == before_hash:
            return  # the tap changed nothing on screen
        self._take("after_tap", of=of, gen=gen,
                   extra={"input": kind, "stable": stable, "settle_ms": waited})  # fmt: skip

    def _screen_shot(self, gen: int) -> None:
        cfg = _config()
        helper = self._helper_up()
        if helper is not None:
            self._settle(helper, cfg)
        else:
            time.sleep(cfg.settle_interval_ms / 1000.0)
        with self._lock:
            req, self._screen_req = self._screen_req, None
        if req is None or gen != self._gen or not _config().shot_screen_change:
            return
        self._take("screen_change", of=req["seq"], gen=gen)

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
    """

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
                    self._emit(rec, flow_dir, gap_info)
                    n += 1
                self.cursor = int(res.get("next_cursor") or self.cursor)
                if not res.get("truncated"):
                    break
        self.emitted += n
        return n

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


def _atexit_stop() -> None:
    service = _SERVICE
    if service is not None:
        with contextlib.suppress(Exception):
            service.shutdown(5.0)


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
]
