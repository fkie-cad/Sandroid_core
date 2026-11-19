"""Host side of the Sandroid UI helper (the single UiAutomation connection).

The helper is a dex jar (``tools/uihelper``, built by ``tools/uihelper/build.sh``)
that runs on the device under ``app_process`` over ONE persistent
``adb -s <serial> shell``. It owns the device's only UiAutomation client and
speaks a line protocol: commands on stdin, one JSON object per line on stdout.
Replies echo the request ``id``; everything else (``hello``, ``status``, a11y
``ev``, ``touch``, ``bye`` ...) is unsolicited and goes to ``on_event``. All
helper times are device CLOCK_MONOTONIC milliseconds (the clock of
``getevent -t`` and a11y ``EventTime``).

Two modes:

* :attr:`Mode.FULL` connects with ``FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES``
  (1): events, window/node queries and screenshots. It is detectable: apps see
  ``accessibility_enabled`` = 1 while it is connected, so :meth:`UiHelper.start`
  records the prior state in :attr:`UiHelper.a11y_before` and
  :meth:`UiHelper.stop` puts it back.
* :attr:`Mode.INVISIBLE` connects with ``FLAG_DONT_USE_ACCESSIBILITY`` (2): no
  a11y registration (nothing for apps to see), only :meth:`UiHelper.shot` and
  :meth:`UiHelper.ping`. The a11y queries return ``None`` without a round trip.

Every adb call names the serial (``adb -s``); nothing here uses the global
target device. This module does not write timeline lines: callers (Tracking)
turn :meth:`UiHelper.on_status` transitions and ``a11y_before`` into them.
"""

from __future__ import annotations

import collections
import contextlib
import hashlib
import io
import json
import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

from sandroid.core.adb import Adb
from sandroid.core.adb_utils import quote_host_arg

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

REMOTE_JAR = "/data/local/tmp/sandroid-uihelper.jar"
MAIN_CLASS = "sandroid.uihelper.Main"
HELPER_VERSION = "1.1.0"
PROTOCOL = 2

#: sha256 of ``src/sandroid/assets/uihelper/uihelper.jar`` (printed by build.sh).
JAR_SHA256 = "4f0f7842fa922c003ad691687ba7be2ac8abce6ebbc4b5c6bd50775701b2e5bc"
#: :func:`source_sha256` of ``tools/uihelper/src`` the jar was built from.
SOURCE_SHA256 = "09de116aeb6d4d2798cfab80df54857c08fa4910038d170e244a830f3f1242c9"

#: Device folder for screenshots in flight (each is fetched, then removed).
REMOTE_SHOT_DIR = "/data/local/tmp/sandroid-shots"

#: Rooted images whose adb shell lacks the zygote env (BOOTCLASSPATH etc.) need
#: it imported before app_process can boot the runtime (a no-op otherwise).
#: ``pidof`` lists several PIDs while an app launches (forked zygote64
#: children share the env): use the first one.
ZYGOTE_ENV = (
    'if [ -z "$BOOTCLASSPATH" ]; then ZP=$(pidof zygote64 || pidof zygote); '
    "ZP=${ZP%% *}; "
    "for kv in $(tr '\\0' '\\n' < /proc/$ZP/environ | grep -vE '^ANDROID_SOCKET_'); "
    'do export "$kv"; done; fi'
)

#: Supervisor back-off before a restart, indexed by the number of deaths since
#: the helper last stayed up for :data:`DEATH_WINDOW_S` (the last one repeats).
RESTART_BACKOFF_S = (1.0, 2.0, 4.0, 8.0, 10.0)
#: This many deaths (a failed restart counts) inside :data:`DEATH_WINDOW_S` ->
#: ``down``: no more restarts until the next :meth:`UiHelper.start`.
MAX_DEATHS = 5
DEATH_WINDOW_S = 60.0
#: This many restart attempts in a row that never connected -> ``down``, however
#: long each one took (a restart that hangs until its connect timeout is slower
#: than :data:`DEATH_WINDOW_S` / :data:`MAX_DEATHS`, so the window alone would
#: retry forever).
MAX_FAILED_RESTARTS = 5

#: An error reply naming this exception: the device's system server died under
#: the helper (a Zygote restart, e.g. by the CA injection). The helper's
#: watchdog reconnects UiAutomation in place, so node queries work again, but
#: the process keeps framework handles into the dead system server
#: (``DisplayManagerGlobal``): every ``takeScreenshot()`` fails with this from
#: then on. Only a fresh process recovers, see :meth:`UiHelper._recycle`.
DEAD_SYSTEM = "DeadSystemException"

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_STDERR_TAIL = 50


class Mode(StrEnum):
    """How the helper connects UiAutomation (see the module docstring)."""

    FULL = "full"
    INVISIBLE = "invisible"


@dataclass(frozen=True)
class ShotResult:
    """One ``UiAutomation.takeScreenshot()``.

    Attributes:
        t_mono_ms: Device CLOCK_MONOTONIC (ms) when the capture was taken.
        w: Width in pixels.
        h: Height in pixels.
        hash: crc32 (8 hex digits) over the ARGB_8888 pixel buffer; equal hashes
            mean identical frames.
        cap_ms: Duration of the capture call on the device.
        png: The PNG bytes; ``None`` for ``hash_only`` shots or when the fetch
            failed (then ``error`` says why).
        remote_path: Device path the PNG was written to (removed after fetch).
        error: Why ``png`` is missing although it was asked for, else ``None``.
    """

    t_mono_ms: float
    w: int
    h: int
    hash: str
    cap_ms: float
    png: bytes | None
    remote_path: str | None
    error: str | None = None


# --------------------------------------------------------------------- the jar


def jar_path() -> Path:
    """Path of the packaged helper jar (``sandroid/assets/uihelper/uihelper.jar``)."""
    res = (
        resources.files("sandroid")
        .joinpath("assets")
        .joinpath("uihelper")
        .joinpath("uihelper.jar")
    )
    return Path(str(res))


def source_sha256(root: Path | str) -> str:
    """Fingerprint of the helper's Java sources, identical to build.sh's.

    sha256 over, for every ``*.java`` under ``root`` sorted by its POSIX path
    relative to ``root``: the relative path, NUL, the file bytes, NUL.

    Args:
        root: ``tools/uihelper/src``.

    Returns:
        The hex digest.
    """
    base = Path(root)
    files = sorted((p.relative_to(base).as_posix(), p) for p in base.rglob("*.java"))
    h = hashlib.sha256()
    for rel, path in files:
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_info() -> dict[str, Any]:
    """Version, protocol and hashes of the packaged helper."""
    return {
        "version": HELPER_VERSION,
        "protocol": PROTOCOL,
        "jar_sha256": JAR_SHA256,
        "source_sha256": SOURCE_SHA256,
    }


def _remote_sha256(serial: str, path: str = REMOTE_JAR) -> str:
    out, _ = Adb.send_adb_command(f"shell sha256sum {path}", serial=serial)
    first = (out or "").strip().split()
    return first[0].lower() if first else ""


def _tmp_jar() -> str:
    """Device name a new jar is pushed to before it replaces :data:`REMOTE_JAR`
    (per host process: two Sandroids never write the same file).
    """
    return f"{REMOTE_JAR}.{os.getpid()}.tmp"


def helper_pids(serial: str) -> list[int]:
    """Pids of every helper process running on the device (any version).

    An ``app_process`` keeps its command line (``app_process /
    sandroid.uihelper.Main mode=...``); the ``sh -c`` that execs it is not
    one of them.
    """
    out, _ = Adb.send_adb_command("shell ps -A -o PID,ARGS", serial=serial)
    pids = []
    for line in (out or "").splitlines():
        parts = line.split()
        if (
            len(parts) >= 3
            and parts[0].isdigit()
            and parts[1].rsplit("/", 1)[-1].startswith("app_process")
            and MAIN_CLASS in parts[2:]
        ):
            pids.append(int(parts[0]))
    return pids


def stop_stale_helpers(serial: str, timeout: float = 3.0) -> list[int]:
    """Stop every helper process still running on the device: a helper of
    an older jar (a crashed or older Sandroid) keeps the device's one
    UiAutomation connection, so the new helper could never connect.

    ``kill`` first (the system server drops its UiAutomation when the
    process dies), ``kill -9`` for one still there after ``timeout``.

    Returns:
        The pids that were running.
    """
    pids = helper_pids(serial)
    if not pids:
        return []
    logger.info(f"UI helper: stopping old helper process(es) {pids} on {serial}")
    Adb.send_adb_command(f"shell kill {' '.join(map(str, pids))}", serial=serial)
    end = time.monotonic() + timeout
    while True:
        left = [p for p in helper_pids(serial) if p in pids]
        if not left or time.monotonic() >= end:
            break
        time.sleep(0.1)
    if left:
        Adb.send_adb_command(f"shell kill -9 {' '.join(map(str, left))}", serial=serial)
        time.sleep(0.2)
        left = [p for p in helper_pids(serial) if p in pids]
        if left:
            logger.warning(f"UI helper: cannot stop old helper {left} on {serial}")
    return pids


def ensure_jar(serial: str) -> bool:
    """Make sure the device has exactly the packaged jar at :data:`REMOTE_JAR`.

    Skips the push when the device copy already hashes to :data:`JAR_SHA256`.
    Otherwise (an upgrade, or no jar yet) the packaged jar is pushed to a
    temporary name (:func:`_tmp_jar`), its hash verified and ``chmod 644``;
    every helper process still running (an old jar's) is stopped
    (:func:`stop_stale_helpers`); then the temporary file is renamed over
    :data:`REMOTE_JAR` (``mv``, one rename on the same file system: the device
    holds the old jar or the new one, never a half-written one) and the
    result verified again. A failed push removes the temporary file and
    leaves the old jar in place.

    Args:
        serial: Device serial (every adb call is ``-s serial``).

    Returns:
        True when the device holds the right jar.
    """
    if _remote_sha256(serial) == JAR_SHA256:
        return True
    local = jar_path()
    try:
        if _file_sha256(local) != JAR_SHA256:
            logger.warning(f"UI helper: packaged jar {local} does not match JAR_SHA256")
            return False
    except OSError as exc:
        logger.warning(f"UI helper: packaged jar unreadable: {exc}")
        return False
    tmp = _tmp_jar()
    Adb.send_adb_command(f"shell rm -f {tmp}", serial=serial)
    Adb.send_adb_command(f"push {quote_host_arg(str(local))} {tmp}", serial=serial)
    got = _remote_sha256(serial, tmp)
    if got != JAR_SHA256:
        Adb.send_adb_command(f"shell rm -f {tmp}", serial=serial)
        logger.warning(
            f"UI helper: jar push to {serial} failed verification "
            f"(device sha256 {got or 'missing'})"
        )
        return False
    Adb.send_adb_command(f"shell chmod 644 {tmp}", serial=serial)
    stop_stale_helpers(serial)
    Adb.send_adb_command(f"shell mv -f {tmp} {REMOTE_JAR}", serial=serial)
    got = _remote_sha256(serial)
    if got != JAR_SHA256:
        Adb.send_adb_command(f"shell rm -f {tmp}", serial=serial)
        logger.warning(
            f"UI helper: jar rename on {serial} failed "
            f"(device sha256 {got or 'missing'})"
        )
        return False
    return True


def helper_command(mode: Mode | str, jar: str = REMOTE_JAR) -> str:
    """Device shell command starting the helper (``exec``: it replaces the shell)."""
    m = Mode(mode)
    return (
        f"{ZYGOTE_ENV}; CLASSPATH={jar} exec app_process / {MAIN_CLASS} mode={m.value}"
    )


def _setting(value: str | None) -> str | None:
    v = (value or "").strip()
    return None if v in ("", "null") else v


def _join(t: threading.Thread | None, timeout: float) -> None:
    """Join ``t`` unless it is missing, not started yet, or the caller itself."""
    if t is None or t is threading.current_thread() or t.ident is None:
        return
    t.join(timeout)


def _buffered(stream: Any) -> Any:
    """A buffered view of a pipe end opened with ``bufsize=0``.

    ``readline`` on a raw ``FileIO`` reads one byte per syscall (a 5 MB ``dump``
    line took seconds); :class:`io.BufferedReader` reads in chunks and still
    returns each line as soon as its newline arrived.
    """
    if isinstance(stream, io.RawIOBase):
        return io.BufferedReader(stream, buffer_size=1 << 16)
    return stream


# ---------------------------------------------------------------------- helper


class _Waiter:
    __slots__ = ("event", "reply")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.reply: dict | None = None


class _Gen:
    """One spawned helper process and its per-process state."""

    def __init__(self, n: int, proc: Any, epoch: int = 0) -> None:
        self.n = n
        self.proc = proc
        self.epoch = epoch  # the lifecycle epoch that spawned it (see UiHelper)
        self.hello: dict | None = None
        self.state = threading.Event()  # set on connected / busy / exit
        self.outcome: str | None = None  # "connected" | "busy" | "exit"
        self.status_detail: str | None = None
        self.connected_at: float | None = None
        self.reader: threading.Thread | None = None
        #: Why the host is replacing this process (see UiHelper._recycle).
        self.recycle: str | None = None


class UiHelper:
    r"""One helper process on one device: request/reply plus supervision.

    Args:
        serial: Device serial; every adb call uses ``-s serial``.
        mode: :class:`Mode`.
        on_event: ``(line, host_recv)`` for every unsolicited line (hello,
            status, ev, touch, touch_node, bye ...). Runs on the reader thread.
        on_status: ``(state, info)`` with state ``connected``, ``lost``,
            ``restarted``, ``down``, ``busy`` or ``stopped``. ``lost`` has a
            ``reason`` when the host replaced a stale process:
            ``system_restart`` (see :data:`DEAD_SYSTEM`) or ``reconnect_busy``
            (its in-place reconnect was refused, see :meth:`_recycle`).
        raw_log: Append every stdout line as ``<host_recv>\\t<raw>`` (mode 0600).
        popen: ``subprocess.Popen`` stand-in (tests).
        adb_argv: argv prefix for the persistent shell and the screenshot fetch;
            defaults to ``Adb.base_argv(serial)``.
        sleep: Back-off wait (tests); defaults to an interruptible wait.
        clock: Monotonic seconds for the death window (tests).
    """

    def __init__(
        self,
        serial: str,
        mode: Mode = Mode.FULL,
        *,
        on_event: Callable[[dict, float], None] | None = None,
        on_status: Callable[[str, dict], None] | None = None,
        raw_log: Path | None = None,
        popen: Callable[..., Any] = subprocess.Popen,
        adb_argv: list[str] | None = None,
        sleep: Callable[[float], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not serial:
            raise ValueError("UiHelper needs an explicit device serial")
        self.serial = serial
        self._mode = Mode(mode)
        self._on_event = on_event
        self._on_status = on_status
        self._raw_log_path = Path(raw_log) if raw_log is not None else None
        self._popen = popen
        self._adb_argv = list(adb_argv) if adb_argv else None
        self._sleep = sleep
        self._clock = clock

        #: ``settings get secure`` values before a FULL start (None = unset). A
        #: key whose read failed is missing: the prior state is unknown, and an
        #: unknown state is never "restored".
        self.a11y_before: dict[str, str | None] = {}
        #: Why the last :meth:`start` returned False (``jar``, ``busy``,
        #: ``timeout``, ``exit``, ``cancelled`` or ``spawn: ...``).
        self.last_error: str | None = None
        self.stderr_tail: collections.deque[str] = collections.deque(
            maxlen=_STDERR_TAIL
        )

        self._lock = threading.Lock()
        # Lifecycle: ``_state`` is idle | starting | running | down | stopping.
        # Every start()/stop() bumps ``_epoch`` under ``_lock``; a spawner (start
        # or the supervisor) registers its process only while its epoch is
        # current, so a stale spawner can never leave a helper behind, and
        # ``_cancel_evt`` (one per epoch) wakes a stale back-off at once.
        self._state = "idle"
        self._epoch = 0
        self._cancel_evt = threading.Event()
        self._start_lock = threading.Lock()  # one start() at a time
        self._start_done: threading.Event | None = None
        self._write_lock = threading.Lock()
        self._log_lock = threading.Lock()
        self._waiters: dict[str, _Waiter] = {}
        self._seq = 0
        self._shot_n = 0
        self._shot_dir_ready = False
        self._gen: _Gen | None = None
        self._gen_n = 0
        self._stopping = False
        self._deaths: collections.deque[float] = collections.deque()
        self._consecutive = 0  # deaths since the helper last stayed up
        self._failed_restarts = 0  # restart attempts in a row that never connected
        self._log: IO[str] | None = None
        self._supervisor: threading.Thread | None = None
        #: A quit is in progress: a helper that dies is not restarted.
        self._no_restart = False

    # -- properties -----------------------------------------------------------

    @property
    def mode(self) -> Mode:
        return self._mode

    @property
    def hello(self) -> dict | None:
        g = self._gen
        return g.hello if g else None

    @property
    def alive(self) -> bool:
        g = self._gen
        return (
            g is not None
            and g.outcome == "connected"
            and g.proc.poll() is None
            and self._state == "running"
            and g.epoch == self._epoch
        )

    # -- lifecycle ------------------------------------------------------------

    def start(self, timeout: float = 20.0) -> bool:
        """Push the jar if needed, record the a11y state, spawn and connect.

        A :meth:`stop` meanwhile cancels the start (the in-flight process is
        killed, False is returned). A start during the supervisor's back-off
        takes over: the supervisor's pending restart is cancelled, so only one
        spawner ever runs.

        Returns:
            True once the helper said ``hello`` and ``status connected``. False
            when the jar could not be installed, another UiAutomation client
            holds the device (``on_status("busy")``), nothing connected within
            ``timeout``, or :meth:`stop` cancelled it (see :attr:`last_error`).
        """
        with self._start_lock:
            return self._start(timeout)

    def _start(self, timeout: float) -> bool:
        with self._lock:
            if self.alive:
                return True
            token = self._bump()
            self._state = "starting"
            self._stopping = False
            self._start_done = done = threading.Event()
            self._deaths.clear()
            self._consecutive = 0
            self._failed_restarts = 0
            self.last_error = None
            stale = self._gen
        try:
            if stale is not None and stale.proc.poll() is None:
                self._terminate(stale, 2.0)  # a supervisor restart we took over
            if not ensure_jar(self.serial):
                return self._start_failed(token, "jar", None)
            if self._cancelled(token):
                return self._start_failed(token, "cancelled", None)
            if self._mode is Mode.FULL:
                self.a11y_before = self._read_a11y()
            self._open_log()
            if self._cancelled(token):
                return self._start_failed(token, "cancelled", None)
            outcome = self._spawn(timeout, token)
            with self._lock:
                ok = outcome == "connected" and token == self._epoch
                if ok:
                    self._state = "running"
            if ok:
                done.set()  # before the callback: it may call stop()
                self._status("connected", self._info())
                return True
            if outcome == "cancelled" or self._cancelled(token):
                return self._start_failed(token, "cancelled", None)
            # _spawn set last_error (busy, timeout, exit, spawn: ...)
            return self._start_failed(
                token, None, "busy" if outcome == "busy" else None
            )
        finally:
            done.set()

    def _start_failed(self, token: int, error: str | None, status: str | None) -> bool:
        """Clean up a start that did not connect; a cancelled one is stop()'s.

        The helper may already have flipped ``accessibility_enabled`` before it
        failed, so a FULL start that read the prior state puts it back here.
        """
        if error is not None:
            self.last_error = error
        with self._lock:
            mine = token == self._epoch
        if not mine:
            self.last_error = "cancelled"
            return False  # stop() (or a newer start) owns the cleanup
        g = self._gen
        if g is not None and g.epoch == token and g.proc.poll() is None:
            self._terminate(g, 2.0)
        restored = self._restore_a11y()
        self._close_log()
        with self._lock:
            if token == self._epoch:
                self._state = "idle"
        if self._start_done is not None:
            self._start_done.set()  # before the callback: it may call stop()
        if status is not None:
            self._status(status, {**self._info(), "a11y_restored": restored})
        return False

    def stop(self, timeout: float = 5.0) -> None:
        """Close stdin (the helper disconnects and exits), then clean up.

        Kills the helper by pid (from ``hello``) if it does not exit within
        ``timeout``. Also cancels a :meth:`start` in progress and the
        supervisor (its in-flight restart is killed first). In FULL mode, then
        resets ``accessibility_enabled`` to 0 when it was 0/unset (read
        successfully) before :meth:`start` and is 1 now.
        """
        with self._lock:
            if self._state in ("idle", "stopping"):
                return
            self._bump()
            self._state = "stopping"
            self._stopping = True
            done = self._start_done
            g = self._gen
        if g is not None:
            self._terminate(g, timeout)
            _join(g.reader, 2.0)  # the last lines (bye) reach the raw log
        if done is not None and not done.is_set():
            done.wait(timeout + 5.0)  # a start() in flight: it backs out
        _join(self._supervisor, timeout)
        g2 = self._gen
        if g2 is not None and g2 is not g and g2.proc.poll() is None:
            self._terminate(g2, 2.0)  # spawned while we were stopping
        restored = self._restore_a11y()
        with self._lock:
            self._state = "idle"
        self._close_log()
        self._status("stopped", {**self._info(), "a11y_restored": restored})

    def suppress_restarts(self) -> None:
        """No supervisor restart from now on (a quit is in progress): a
        helper that dies stays dead and writes no ``lost`` status; the
        quit's :meth:`stop` still restores a11y and reports ``stopped``.
        A restart already waiting in its back-off is cancelled.
        """
        with self._lock:
            self._no_restart = True
            self._cancel_evt.set()

    def _bump(self) -> int:
        """New lifecycle epoch (caller holds ``_lock``): cancels the old one."""
        self._epoch += 1
        self._cancel_evt.set()
        self._cancel_evt = threading.Event()
        return self._epoch

    def _cancelled(self, token: int) -> bool:
        with self._lock:
            return token != self._epoch

    # -- queries --------------------------------------------------------------

    def node_at(
        self,
        x: int,
        y: int,
        *,
        t_mono_ms: float | None = None,
        timeout: float = 1.0,
    ) -> dict | None:
        """Element under (x, y), resolved both live and from the snapshot cache.

        Args:
            x: Screen x (px, current rotation).
            y: Screen y.
            t_mono_ms: Device-monotonic instant to resolve the cached answer at
                (e.g. the finger-down time); defaults to now.
            timeout: Seconds to wait for the reply.

        Returns:
            The ``node_at`` reply (keys ``cached`` and ``live``), or None
            (INVISIBLE mode, error or timeout).
        """
        if self._mode is Mode.INVISIBLE:
            return None
        cmd = f"node_at {int(x)} {int(y)} both"
        if t_mono_ms is not None:
            cmd += f" t={float(t_mono_ms):.1f}"
        return self._ok(self.request(cmd, timeout), "node_at")

    def focus(
        self, x: int | None = None, y: int | None = None, *, timeout: float = 1.0
    ) -> dict | None:
        """Read back the field being typed into (``focus`` request).

        ``input``: the input-focused node, refreshed (its ``text`` is the
        value now, also for fields that send no TEXT_CHANGED). With ``x``,
        ``y`` and nothing editable focused: ``node``, the editable node
        under that point (the tapped field), refreshed.

        Returns:
            The reply, or None (INVISIBLE mode, error or timeout).
        """
        if self._mode is Mode.INVISIBLE:
            return None
        cmd = "focus"
        if x is not None and y is not None:
            cmd += f" x={int(x)} y={int(y)}"
        return self._ok(self.request(cmd, timeout), "focus")

    def dump(self, *, max_nodes: int = 50_000, timeout: float = 30.0) -> dict | None:
        """Full tree of every interactive window (``windows[].root``), bounded."""
        if self._mode is Mode.INVISIBLE:
            return None
        return self._ok(
            self.request(f"dump max_nodes={int(max_nodes)}", timeout), "dump"
        )

    def windows(self, timeout: float = 2.0) -> list[dict] | None:
        """Interactive windows, top-most first (no node trees)."""
        if self._mode is Mode.INVISIBLE:
            return None
        r = self._ok(self.request("windows", timeout), "windows")
        if r is None:
            return None
        ws = r.get("windows")
        return ws if isinstance(ws, list) else None

    def display(self, timeout: float = 2.0) -> dict | None:
        """``{w, h, rotation}`` of the display now (``windows`` reply), or None
        (INVISIBLE mode, error or timeout).
        """
        if self._mode is Mode.INVISIBLE:
            return None
        r = self._ok(self.request("windows", timeout), "windows")
        disp = (r or {}).get("display")
        return disp if isinstance(disp, dict) else None

    def shot(
        self, *, hash_only: bool = False, timeout: float = 5.0
    ) -> ShotResult | None:
        """One screenshot via UiAutomation (works in both modes).

        Without ``hash_only`` the helper writes a PNG under
        :data:`REMOTE_SHOT_DIR`, which is fetched with ``adb exec-out cat`` and
        removed. ``hash_only`` returns only the frame hash (no encode, no fetch).

        Returns:
            A :class:`ShotResult`, or None when the helper did not capture
            (not running, error, timeout). A capture whose PNG fetch failed is
            returned with ``png=None`` and ``error`` set.
        """
        if hash_only:
            r = self._ok(self.request("shot hash_only=1", timeout), "shot")
            return self._shot_result(r, None, None, None) if r else None
        if not self.alive:
            return None
        if not self._shot_dir_ready:
            Adb.send_adb_command(
                f"shell mkdir -p {REMOTE_SHOT_DIR}", serial=self.serial
            )
            self._shot_dir_ready = True
        with self._lock:
            self._shot_n += 1
            n = self._shot_n
        path = f"{REMOTE_SHOT_DIR}/{os.getpid()}-{n}.png"
        r = self._ok(self.request(f"shot path={path}", timeout), "shot")
        if r is None:
            self._rm(path)
            return None
        png, err = self._fetch(path, timeout)
        self._rm(path)
        return self._shot_result(r, png, path, err)

    def ping(self, timeout: float = 2.0) -> dict | None:
        """Round trip: ``{t_mono_ms, rtt_ms, host_mid, connected, ...}``.

        ``host_mid`` (host epoch seconds, midway between send and receive) pairs
        with the device ``t_mono_ms`` for a clock offset estimate.
        """
        r = self._ok(self.request("ping", timeout), "pong")
        if r is None:
            return None
        t0 = float(r["_host_send"])
        t1 = float(r["_host_recv"])
        return {
            "t_mono_ms": r.get("t_mono_ms"),
            "rtt_ms": (t1 - t0) * 1e3,
            "host_mid": (t0 + t1) / 2,
            "connected": bool(r.get("connected")),
            "uptime_ms": r.get("uptime_ms"),
            "mode": r.get("mode"),
        }

    def request(self, cmd: str, timeout: float = 5.0) -> dict | None:
        """Send ``cmd`` with a fresh ``id``; the reply, or None on timeout/death.

        The reply gains ``_host_send`` / ``_host_recv`` (host epoch seconds).
        """
        g = self._gen
        if g is None or g.proc.poll() is not None or self._stopping:
            return None
        w = _Waiter()
        with self._lock:
            self._seq += 1
            rid = f"r{self._seq}"
            self._waiters[rid] = w
        t_send = time.time()
        if not self._write(g, f"{cmd} id={rid}"):
            with self._lock:
                self._waiters.pop(rid, None)
            return None
        if not w.event.wait(timeout):
            with self._lock:
                self._waiters.pop(rid, None)
            logger.debug(f"UI helper: no reply to {cmd!r} within {timeout}s")
            return None
        if w.reply is None:
            return None
        w.reply["_host_send"] = t_send
        return w.reply

    # -- internals: process ---------------------------------------------------

    def _argv_prefix(self) -> list[str]:
        if self._adb_argv:
            return list(self._adb_argv)
        return Adb.base_argv(self.serial)

    def _spawn(self, timeout: float, token: int) -> str:
        """Start one helper process and wait for connected/busy/exit.

        ``token`` is the caller's lifecycle epoch: once it is stale (stop() or
        a newer start()), the process is killed and ``cancelled`` returned.
        """
        argv = [*self._argv_prefix(), "shell", helper_command(self._mode)]
        try:
            proc = self._popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
        except (OSError, ValueError) as exc:
            self.last_error = f"spawn: {exc}"
            logger.warning(f"UI helper: cannot start adb shell: {exc}")
            return "exit"
        with self._lock:
            self._gen_n += 1
            g = _Gen(self._gen_n, proc, token)
            current = token == self._epoch
            if current:
                self._gen = g
                self._shot_dir_ready = False
        if not current:
            self._terminate(g, 2.0)  # cancelled while adb shell came up
            return "cancelled"
        g.reader = threading.Thread(
            target=self._read, args=(g,), name="uihelper-reader", daemon=True
        )
        g.reader.start()
        threading.Thread(
            target=self._read_err, args=(g,), name="uihelper-stderr", daemon=True
        ).start()
        if not g.state.wait(timeout):
            if self._cancelled(token):
                self._terminate(g, 2.0)
                return "cancelled"
            self.last_error = "timeout"
            logger.warning(f"UI helper on {self.serial}: no connection in {timeout}s")
            self._terminate(g, 2.0)
            return "timeout"
        if self._cancelled(token):
            self._terminate(g, 2.0)
            return "cancelled"
        if g.outcome != "connected":
            self.last_error = g.outcome
            if g.outcome == "busy":
                logger.warning(
                    f"UI helper on {self.serial}: another UiAutomation client "
                    f"holds the device ({g.status_detail})"
                )
            self._terminate(g, 2.0)
        return g.outcome or "exit"

    def _terminate(self, g: _Gen, timeout: float) -> None:
        proc = g.proc
        with contextlib.suppress(OSError, ValueError, AttributeError):
            proc.stdin.close()  # EOF: the helper disconnects UiAutomation and exits
        try:
            proc.wait(timeout=timeout)
            return
        except subprocess.TimeoutExpired:
            pass
        pid = (g.hello or {}).get("pid")
        if isinstance(pid, int) and pid > 0:
            Adb.send_adb_command(f"shell kill {pid}", serial=self.serial)
        with contextlib.suppress(OSError):
            proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=2.0)

    def _write(self, g: _Gen, line: str) -> bool:
        try:
            with self._write_lock:
                g.proc.stdin.write((line + "\n").encode("utf-8"))
                g.proc.stdin.flush()
            return True
        except (OSError, ValueError, AttributeError):
            return False

    def _read(self, g: _Gen) -> None:
        stream = _buffered(g.proc.stdout)
        try:
            for raw_b in iter(stream.readline, b""):
                host_recv = time.time()
                try:
                    self._handle_line(g, raw_b, host_recv)
                except Exception:  # the reader must survive
                    logger.debug("UI helper: line handler failed", exc_info=True)
        except (OSError, ValueError):
            pass
        self._on_exit(g)

    def _read_err(self, g: _Gen) -> None:
        stream = g.proc.stderr
        if stream is None:
            return
        stream = _buffered(stream)
        try:
            for raw_b in iter(stream.readline, b""):
                line = raw_b.decode("utf-8", "replace").rstrip()
                if line:
                    self.stderr_tail.append(line)
                    logger.debug(f"UI helper stderr: {line}")
        except (OSError, ValueError):
            pass

    def _handle_line(self, g: _Gen, raw_b: bytes, host_recv: float) -> None:
        raw = raw_b.decode("utf-8", "replace").strip()
        if not raw:
            return
        self._log_line(raw, host_recv)
        try:
            d = json.loads(raw)
        except ValueError:
            logger.debug(f"UI helper: non-JSON line {raw[:200]!r}")
            return
        if not isinstance(d, dict):
            return
        typ = d.get("type")
        if typ == "hello":
            g.hello = d
        elif typ == "status" and g.outcome is None:
            state = d.get("state")
            if state in ("connected", "busy"):
                if state == "connected":
                    g.connected_at = self._clock()
                g.outcome = state
                g.status_detail = d.get("detail")
                g.state.set()
        elif typ == "status" and g.outcome == "connected":
            # The helper's watchdog lost UiAutomation and reconnects in place.
            if d.get("state") == "connected":
                self._probe(g)
            elif d.get("state") == "busy":
                # "already registered": a connect that timed out on the
                # helper's side registered anyway (seen while the system
                # server restarted); only the process's death frees it.
                self._recycle(g, "reconnect_busy", str(d.get("detail")))
        elif typ == "error" and DEAD_SYSTEM in str(d.get("error") or ""):
            self._recycle(g, "system_restart", f"{d.get('cmd')}: {d.get('error')}")
        rid = d.get("id")
        if rid is not None:
            with self._lock:
                w = self._waiters.pop(str(rid), None)
            if w is not None:
                d["_host_recv"] = host_recv
                w.reply = d
                w.event.set()
                return
        if self._on_event is not None:
            try:
                self._on_event(d, host_recv)
            except Exception:  # never kill the reader
                logger.debug("UI helper: on_event callback failed", exc_info=True)

    def _on_exit(self, g: _Gen) -> None:
        """The stdout of generation ``g`` ended: the helper process is gone."""
        if g.outcome is None:
            g.outcome = "exit"
            g.state.set()
        with contextlib.suppress(subprocess.TimeoutExpired, OSError):
            g.proc.wait(timeout=2.0)
        with self._lock:
            current = self._gen is g
            if current:
                waiters = list(self._waiters.values())
                self._waiters.clear()
            else:
                waiters = []
        for w in waiters:
            w.event.set()  # reply stays None: the caller gets None at once
        if g.outcome != "connected":
            return  # a spawn that never connected: _spawn's caller handles it
        with self._lock:
            if not current or g.epoch != self._epoch or self._state != "running":
                return
            if self._no_restart:
                return  # quitting: no "lost · restarting", no supervisor
            token = g.epoch
            evt = self._cancel_evt
            if (
                g.connected_at is not None
                and self._clock() - g.connected_at >= DEATH_WINDOW_S
            ):
                self._consecutive = 0  # it had been stable: start the back-off over
        rc = g.proc.poll()
        info = {**self._info(), "rc": rc}
        if g.recycle is not None:
            info["reason"] = g.recycle
        self._status("lost", info)
        with self._lock:
            # Started under the lock: stop() always sees (and joins) a started
            # supervisor, or bumps the epoch first so none starts.
            if token != self._epoch or self._state != "running":
                return
            sup = threading.Thread(
                target=self._supervise,
                args=(token, evt),
                name="uihelper-supervisor",
                daemon=True,
            )
            self._supervisor = sup
            sup.start()

    def _probe(self, g: _Gen) -> None:
        """The helper reconnected UiAutomation in place (its watchdog saw the
        connection drop). When the system server restarted, its process is
        stale (see :data:`DEAD_SYSTEM`): one hash-only shot tells, and its
        error reply recycles the process at once, before a real shot fails.
        Off the reader thread, which must stay free to read that reply.
        """
        if self._gen is not g:
            return
        logger.debug(f"UI helper on {self.serial}: reconnected in place, probing")
        threading.Thread(
            target=self.request,
            args=("shot hash_only=1", 5.0),
            name="uihelper-probe",
            daemon=True,
        ).start()

    def _recycle(self, g: _Gen, reason: str, detail: str) -> None:
        """Replace generation ``g``, stale since its system server restarted
        (``reason`` ``system_restart``) or stuck reconnecting in place
        (``reconnect_busy``).

        Its stdin is closed off the reader thread; the exit then takes the
        usual path (``lost`` with that ``reason``, the supervisor's back-off,
        a fresh process, ``restarted``). Once per process; never while
        stopping or quitting.
        """
        with self._lock:
            if (
                g.recycle is not None
                or self._gen is not g
                or g.epoch != self._epoch
                or self._state != "running"
                or self._no_restart
            ):
                return
            g.recycle = reason
        logger.warning(
            f"UI helper on {self.serial}: stale after a lost UiAutomation "
            f"({reason}: {detail}); restarting the helper"
        )
        threading.Thread(
            target=self._terminate,
            args=(g, 2.0),
            name="uihelper-recycle",
            daemon=True,
        ).start()

    # -- internals: supervision -----------------------------------------------

    def _death(self, token: int, *, failed_restart: bool = False) -> bool | None:
        """Record a death; True when the helper is now ``down``.

        None when ``token`` is stale (a stop()/start() took over: count nothing).
        """
        now = self._clock()
        with self._lock:
            if token != self._epoch:
                return None
            self._consecutive += 1
            if failed_restart:
                self._failed_restarts += 1
            self._deaths.append(now)
            while self._deaths and now - self._deaths[0] > DEATH_WINDOW_S:
                self._deaths.popleft()
            return (
                len(self._deaths) >= MAX_DEATHS
                or self._failed_restarts >= MAX_FAILED_RESTARTS
            )

    def _wait(self, seconds: float, evt: threading.Event) -> bool:
        """Back-off wait; True when this epoch was cancelled meanwhile."""
        if self._sleep is not None:
            self._sleep(seconds)
            return evt.is_set()
        return evt.wait(seconds)

    def _supervise(self, token: int, evt: threading.Event) -> None:
        down = self._death(token)
        if down is None:
            return
        if down:
            self._go_down(token)
            return
        attempt = 0
        while not evt.is_set():
            idx = min(self._consecutive, len(RESTART_BACKOFF_S)) - 1
            if self._wait(RESTART_BACKOFF_S[max(idx, 0)], evt):
                return
            attempt += 1
            # The device may have been reverted (snapshot load): re-check the jar.
            if not ensure_jar(self.serial):
                outcome = "jar"
            elif evt.is_set():
                return
            else:
                outcome = self._spawn(20.0, token)
            if outcome == "cancelled" or evt.is_set() or self._no_restart:
                return  # stop()/start() took over; _spawn killed what it made
            if outcome == "connected":
                with self._lock:
                    if token != self._epoch:
                        return
                    self._failed_restarts = 0
                self._status("restarted", {**self._info(), "attempt": attempt})
                return
            down = self._death(token, failed_restart=True)
            if down is None:
                return
            if down:
                self._go_down(token)
                return

    def _go_down(self, token: int) -> None:
        with self._lock:
            if token != self._epoch:
                return
            self._state = "down"
            g = self._gen
        if g is not None and g.proc.poll() is None:
            self._terminate(g, 2.0)
        restored = self._restore_a11y()
        self._status(
            "down",
            {
                **self._info(),
                "deaths": len(self._deaths),
                "failed_restarts": self._failed_restarts,
                "a11y_restored": restored,
            },
        )

    # -- internals: a11y state ------------------------------------------------

    def _read_a11y(self) -> dict[str, str | None]:
        """``settings get secure`` per key; a failed read leaves the key out.

        ``settings get`` prints ``null`` for an unset key, so empty output means
        the read itself failed (adb error, timeout): the prior state is unknown,
        which must not be mistaken for "unset".
        """
        out: dict[str, str | None] = {}
        for key in ("accessibility_enabled", "enabled_accessibility_services"):
            v, err = Adb.send_adb_command(
                f"shell settings get secure {key}", serial=self.serial
            )
            if not (v or "").strip():
                logger.warning(
                    f"UI helper: cannot read {key} on {self.serial} "
                    f"({(err or 'no output').strip()}); prior state unknown"
                )
                continue
            out[key] = _setting(v)
        return out

    def _restore_a11y(self) -> bool:
        """FULL only: undo accessibility_enabled 0/unset -> 1. True if reset.

        Only when the prior value was actually read: an unknown prior state is
        left alone (it may have been a real a11y service such as TalkBack).
        """
        if self._mode is not Mode.FULL:
            return False
        if "accessibility_enabled" not in self.a11y_before:
            return False
        if self.a11y_before["accessibility_enabled"] not in (None, "0"):
            return False
        now, _ = Adb.send_adb_command(
            "shell settings get secure accessibility_enabled", serial=self.serial
        )
        if _setting(now) != "1":
            return False
        Adb.send_adb_command(
            "shell settings put secure accessibility_enabled 0", serial=self.serial
        )
        logger.info(f"UI helper: reset accessibility_enabled to 0 on {self.serial}")
        return True

    # -- internals: misc ------------------------------------------------------

    def _info(self) -> dict[str, Any]:
        h = self.hello or {}
        return {
            "serial": self.serial,
            "mode": self._mode.value,
            "flags": h.get("flags", 2 if self._mode is Mode.INVISIBLE else 1),
            "pid": h.get("pid"),
            "version": h.get("version"),
            "a11y_before": dict(self.a11y_before),
        }

    def _status(self, state: str, info: dict) -> None:
        logger.debug(f"UI helper {self.serial}: {state}")
        if self._on_status is None:
            return
        try:
            self._on_status(state, info)
        except Exception:  # must not break supervision
            logger.debug("UI helper: on_status callback failed", exc_info=True)

    @staticmethod
    def _ok(reply: dict | None, typ: str) -> dict | None:
        if reply is None:
            return None
        if reply.get("type") != typ:
            logger.debug(f"UI helper: {typ} failed: {reply.get('error')}")
            return None
        return reply

    @staticmethod
    def _shot_result(
        r: dict, png: bytes | None, path: str | None, err: str | None
    ) -> ShotResult:
        return ShotResult(
            t_mono_ms=float(r.get("t_mono_ms") or 0.0),
            w=int(r.get("w") or 0),
            h=int(r.get("h") or 0),
            hash=str(r.get("hash") or ""),
            cap_ms=float(r.get("cap_ms") or 0.0),
            png=png,
            remote_path=path,
            error=err,
        )

    def _fetch(self, path: str, timeout: float) -> tuple[bytes | None, str | None]:
        argv = [*self._argv_prefix(), "exec-out", "cat", path]
        try:
            proc = self._popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            data, err = proc.communicate(timeout=max(timeout, 5.0))
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                proc.kill()
            return None, "fetch timed out"
        except (OSError, ValueError) as exc:
            return None, f"fetch failed: {exc}"
        if not data or not data.startswith(_PNG_MAGIC):
            detail = (err or b"").decode("utf-8", "replace").strip()
            return None, f"fetch failed: {detail or 'not a PNG'}"
        return data, None

    def _rm(self, path: str) -> None:
        Adb.send_adb_command(f"shell rm -f {path}", serial=self.serial)

    def _open_log(self) -> None:
        if self._raw_log_path is None or self._log is not None:
            return
        try:
            self._raw_log_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(
                self._raw_log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
            )
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o600)
            self._log = os.fdopen(fd, "a", encoding="utf-8", buffering=1)
        except OSError as exc:
            logger.warning(
                f"UI helper: cannot open raw log {self._raw_log_path}: {exc}"
            )

    def _close_log(self) -> None:
        with self._log_lock:
            log, self._log = self._log, None
        if log is not None:
            with contextlib.suppress(OSError):
                log.close()

    def _log_line(self, raw: str, host_recv: float) -> None:
        with self._log_lock:
            if self._log is None:
                return
            try:
                self._log.write(f"{host_recv:.6f}\t{raw}\n")
            except (OSError, ValueError):
                pass
