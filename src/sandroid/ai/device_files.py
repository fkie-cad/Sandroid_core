"""Read device files for the Files lens (``read_device_files``) and cache them.

No Textual, no watchlist: this module reads bytes off one device and keeps
what it read in ``<session>/ai/content_cache/``; the Files lens tools
(:func:`sandroid.ai.row_classifier.file_content`) take their content from
there or from a kept watchlist version, whichever is newer.

Read path (:class:`DeviceFileReader`):

* **One device per call.** The serial is fixed when the reader is built and
  every argv is ``Adb.base_argv(serial)`` with that explicit serial; the
  shared ``Adb._target_device`` (``set_target_device`` / ``targeting``) is
  never read or changed afterwards, so a device switch mid-run cannot send
  a read to another device.
* **Root mode**, probed once: ``id -u`` is 0 (adbd root) -> direct; else
  ``su 0 id -u`` (5 s) -> ``su 0 <cmd>``; else ``su -c '<cmd>'``; else no
  root (``/data`` paths come back ``permission_denied``).
* **One batched stat** (``stat -c '%s|%Y|%F|%n'``, 50 paths per call):
  size, mtime, type; error lines become ``gone`` / ``permission_denied``.
* **Capped reads**: ``exec-out head -c N+1`` (binary-safe argv, no host
  shell), and the host kills the stream once it has N+1 bytes. SQLite
  files are copied whole with ``cat`` (main file plus ``-wal``, together at
  most 16 MB). Every read has a timeout (15 s head, 60 s database) and
  stops on the turn's cancel event or the tool deadline.
* **No leases.** Reads change nothing on the device; a held
  :attr:`~sandroid.ai.arbiter.ResourceId.WORLD` lease (snapshot restore,
  emulator restart) makes the tool answer ``busy`` instead.

Cache (``<session>/ai/content_cache/<sha1(path)>/``, folder 0700, files
0600, each written atomically): ``meta.json`` (path, serial, row ``last``,
device mtime and size, ``read_at``, kind, truncated, root mode),
``raw.bin`` (text files; database copies are not kept), ``match.txt`` (the
full decoded text, searched locally, never sent to the model) and
``digest.txt`` (the rendering shown). An entry is stale when the row's
last content change is newer than the one it was read for, the device
mtime or size (of the file, and of a database's ``-wal``) differ, it came
from another serial or root mode, the device state was replaced since (the
session timeline's world count: snapshot loads from the TUI or the AI,
device boots; plus the arbiter's WORLD-lease count), or a bigger cap /
fuller SQLite mode is asked for; at most 64 MB per session, oldest
``read_at`` evicted first (never an entry the running call used). Files that cannot be read (gone, not a regular file,
permission denied, too big, SQLite skipped) get a small *negative* entry
(status + stat), so the lens tools stop calling them missing.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator

logger = logging.getLogger(__name__)

#: Default / largest bytes read per text file.
DEFAULT_BYTES_PER_FILE = 64 * 1024
MAX_BYTES_PER_FILE = 1024 * 1024
#: A SQLite file plus its ``-wal`` larger than this is not copied.
DB_COPY_CAP = 16 * 1024 * 1024
#: Cache size per session (oldest ``read_at`` evicted first).
CACHE_CAP_BYTES = 64 * 1024 * 1024
#: Paths per ``stat`` call, and characters of quoted paths per call (old
#: adbd limits a service string to 4 KB).
STAT_BATCH = 50
STAT_ARGS_CAP = 3000
#: Seconds per ``head`` read / database copy / stat / root probe.
HEAD_TIMEOUT_S = 15.0
DB_TIMEOUT_S = 60.0
STAT_TIMEOUT_S = 20.0
PROBE_TIMEOUT_S = 10.0
SU_PROBE_TIMEOUT_S = 5.0
#: Seconds kept free before the tool's executor deadline.
DEADLINE_MARGIN_S = 5.0
#: Bytes per pipe read.
CHUNK = 64 * 1024
#: File-name endings copied as SQLite databases.
DB_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".db3")
_SQLITE_MAGIC = b"SQLite format 3\x00"

CACHE_DIRNAME = "content_cache"
_META = "meta.json"
_DIGEST = "digest.txt"
_MATCH = "match.txt"
_RAW = "raw.bin"
_DB = "db"
_DB_WAL = "db-wal"

_CACHE_LOCK = threading.Lock()

#: Statuses kept as negative cache entries (nothing to show, do not re-read).
NEGATIVE_STATUSES = (
    "gone",
    "not_regular",
    "permission_denied",
    "too_big",
    "sqlite_skipped",
)
#: Process names of this module's own device reads (exec-out head / cat /
#: stat / su / id): the monitor sees them on the app's files; the AI tool
#: rows leave them out of "by" and the event count.
OWN_READ_PROCESSES = frozenset({"head", "cat", "stat", "su", "id"})


def is_own_read_process(name: Any) -> bool:
    """Whether a monitor event's process NAME is one of our read commands
    (only ever used together with :func:`tool_read_at` and noise ops: a
    ``cat`` / ``su`` that writes, or reads outside our read window, is real
    activity).
    """
    head = str(name or "").split(" · ", 1)[0].strip().lower()
    return head.rsplit("/", 1)[-1] in OWN_READ_PROCESSES


#: Device paths this process read with read_device_files: path -> the read
#: windows ``(serial, t0, t1)`` (host epoch), newest last, a few per path.
_TOOL_READS: dict[str, list[tuple[str | None, float, float]]] = {}
#: Windows kept per path, and the slack around one (event delivery lag).
_TOOL_READ_WINDOWS = 8
TOOL_READ_SLACK_S = 5.0
_TOOL_READS_MAX = 20_000
_TOOL_READS_LOCK = threading.Lock()


def note_tool_read(
    path: str,
    serial: str | None = None,
    t0: float | None = None,
    t1: float | None = None,
) -> None:
    """Remember that read_device_files read *path* on *serial* between *t0*
    and *t1* (its open/access events by head / cat / su then are ours).
    """
    now = time.time()
    window = (serial, now if t0 is None else t0, now if t1 is None else t1)
    with _TOOL_READS_LOCK:
        windows = _TOOL_READS.pop(path, [])
        windows.append(window)
        _TOOL_READS[path] = windows[-_TOOL_READ_WINDOWS:]
        while len(_TOOL_READS) > _TOOL_READS_MAX:
            _TOOL_READS.pop(next(iter(_TOOL_READS)))


def has_tool_reads(path: str) -> bool:
    """Whether read_device_files read *path* at all (cheap; no lock needed
    for a dict membership test).
    """
    return path in _TOOL_READS


def tool_read_windows(
    path: str, serial: str | None = None
) -> list[tuple[float, float]]:
    """The read windows on *path* (with :data:`TOOL_READ_SLACK_S`) on
    *serial*, for checking many events against them in one go.
    """
    with _TOOL_READS_LOCK:
        windows = list(_TOOL_READS.get(path) or [])
    return [
        (t0 - TOOL_READ_SLACK_S, t1 + TOOL_READ_SLACK_S)
        for w_serial, t0, t1 in windows
        if not (serial and w_serial and serial != w_serial)
    ]


def tool_read_at(path: str, t: Any = None, serial: str | None = None) -> bool:
    """Whether read_device_files read *path* at host time *t* (within its
    read window, +- :data:`TOOL_READ_SLACK_S`) on *serial* (when both are
    known). Without *t*: whether the latest read was in the last minute.
    Later events on the path (a ``cat`` copying the prefs away an hour
    later) are not ours.
    """
    with _TOOL_READS_LOCK:
        windows = list(_TOOL_READS.get(path) or [])
    if not windows:
        return False
    when = _as_float(t)
    if when is None:
        when = time.time()
        windows = windows[-1:]
        slack = 60.0
    else:
        slack = TOOL_READ_SLACK_S
    for w_serial, t0, t1 in windows:
        if serial and w_serial and serial != w_serial:
            continue
        if t0 - slack <= when <= t1 + slack:
            return True
    return False


#: (time, serial) of the last :func:`recorded_serial_cached` look-up.
_SERIAL_CACHE: list = [0.0, None]


def recorded_serial_cached(ttl: float = 1.0) -> str | None:
    """:func:`recorded_serial`, re-read at most every *ttl* seconds (for
    per-row callers such as the Files lens row snapshots).
    """
    now = time.monotonic()
    if now - _SERIAL_CACHE[0] > ttl:
        _SERIAL_CACHE[:] = [now, recorded_serial()]
    return _SERIAL_CACHE[1]


#: SQLite companion files whose rows stand for their database.
COMPANION_SUFFIXES = ("-wal", "-shm", "-journal")
#: Bytes of probe / stat output kept.
OUTPUT_CAP = 4 * 1024 * 1024
#: The last device a running file monitor recorded, per session folder (the
#: rows stay that device's after the monitor stops).
_LAST_MONITOR_SERIAL: dict[str, str] = {}
#: Timeline files read for the recording device: path -> (stamp, serial).
_TIMELINE_SERIALS: dict[str, tuple[tuple, str | None]] = {}
#: Bytes of a timeline file's end searched for the recording device.
TIMELINE_TAIL = 256 * 1024


# =============================================================================
# Device and arbiter
# =============================================================================


def world_busy() -> bool:
    """True while someone holds the WORLD lease (snapshot restore, restart).

    A read-only look at the arbiter: nothing is claimed.
    """
    try:
        from sandroid.ai.arbiter import ResourceId, get_arbiter

        return ResourceId.WORLD in get_arbiter().snapshot()
    except Exception:
        logger.debug("arbiter snapshot failed", exc_info=True)
        return False


def _timeline_world(serial: str | None) -> str | None:
    """``<session id>:<world>`` of *serial*'s session-timeline sink.

    The timeline counts every world change: a snapshot load (panel, Rewind,
    the AI tools: ``EmulatorService.load_snapshot``), a device boot (emulator
    restart, Devices hub) and an inferred one (device clock went back); it is
    kept per session and survives a restart. Read-only look at the running
    service (none is created here).
    """
    try:
        from sandroid.core import timeline

        service = timeline._SERVICE
        if service is None:
            return None
        with service._lock:
            sink = service._by_serial.get(serial) if serial else None
            sink = sink or service._active or service._detached
            if sink is None:
                return None
            return f"{sink.session_id}:{sink.world}"
    except Exception:
        logger.debug("timeline world unavailable", exc_info=True)
        return None


def world_token(serial: str | None = None) -> str:
    """Changes whenever the device state may have been replaced: the session
    timeline's world count for *serial* (snapshot loads, boots, from the
    TUI or the AI) plus the arbiter's WORLD-lease count.
    """
    try:
        from sandroid.ai.arbiter import get_arbiter

        epoch = get_arbiter().world_epoch()
    except Exception:
        epoch = -1
    return f"tl:{_timeline_world(serial)};ar:{epoch}"


def monitor_serial() -> str | None:
    """The device the running file monitor records (its ``timeline_serial``)."""
    try:
        from sandroid.tui.controller_registry import get_monitor_controller

        controller = get_monitor_controller()
        if controller is None or not controller.is_running():
            return None
        task = controller._get_task_service().get_task("monitor")
        serial = getattr(getattr(task, "instance", None), "timeline_serial", None)
    except Exception:
        return None
    if not (isinstance(serial, str) and serial):
        return None
    session = _session_key()
    if session is not None:
        _LAST_MONITOR_SERIAL[session] = serial
    return serial


def _session_key() -> str | None:
    try:
        from sandroid.ai.results import session_root

        root = session_root()
    except Exception:
        return None
    return str(root) if root is not None else None


def _timeline_files() -> list[Path]:
    session = _session_key()
    if session is None:
        return []
    root = Path(session)
    files = [root / "timeline.jsonl", *root.glob("*/timeline.jsonl")]
    out = []
    for f in files:
        try:
            out.append((f.stat().st_mtime_ns, f))
        except OSError:
            continue
    return [f for _t, f in sorted(out, reverse=True)]


def _serial_in_timeline(path: Path) -> str | None:
    """The device of the newest file-monitor line (``files`` / ``monitor``)
    in the end of one timeline file (cached while the file is unchanged).
    """
    try:
        st = path.stat()
    except OSError:
        return None
    stamp = (st.st_mtime_ns, st.st_size)
    hit = _TIMELINE_SERIALS.get(str(path))
    if hit is not None and hit[0] == stamp:
        return hit[1]
    serial = None
    try:
        with open(path, "rb") as f:
            f.seek(max(0, st.st_size - TIMELINE_TAIL))
            tail = f.read(TIMELINE_TAIL)
        for raw in reversed(tail.splitlines()):
            if b'"files"' not in raw and b'"monitor"' not in raw:
                continue
            try:
                line = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(line, dict):
                continue
            if line.get("src") in ("files", "monitor") and line.get("dev"):
                serial = str(line["dev"])
                break
    except OSError:
        serial = None
    _TIMELINE_SERIALS[str(path)] = (stamp, serial)
    return serial


def recorded_serial() -> str | None:
    """The device the Files rows were recorded on, when known: the running
    monitor's; else the one a monitor recorded in this session (remembered,
    or the newest file-monitor line of the session's timeline files).
    """
    serial = monitor_serial()
    if serial:
        return serial
    session = _session_key()
    if session is not None and session in _LAST_MONITOR_SERIAL:
        return _LAST_MONITOR_SERIAL[session]
    for path in _timeline_files():
        serial = _serial_in_timeline(path)
        if serial:
            return serial
    return None


def selected_serial() -> str | None:
    try:
        from sandroid.core.adb import Adb

        return Adb.selected_serial()
    except Exception:
        return None


def current_serial() -> str | None:
    """The device whose cache entries count (rows' device, else selected)."""
    return recorded_serial() or selected_serial()


def read_target() -> tuple[str | None, str | None]:
    """``(device to read, device the rows were recorded on or None)``.

    The running monitor's device, else the selected one; the caller refuses
    when the rows were recorded on another device.
    """
    target = monitor_serial() or selected_serial()
    return target, recorded_serial()


def db_base(path: str) -> str | None:
    """``x.db`` for ``x.db-wal`` / ``-shm`` / ``-journal`` (else None)."""
    for suffix in COMPANION_SUFFIXES:
        if path.endswith(suffix) and is_db_name(path[: -len(suffix)]):
            return path[: -len(suffix)]
    return None


# =============================================================================
# Reader
# =============================================================================


@dataclass
class Stat:
    """One path of the batched stat.

    ``error``: ``gone``, ``permission_denied`` or ``error`` (no line for it).
    """

    path: str
    size: int | None = None
    mtime: int | None = None
    ftype: str = ""
    error: str | None = None

    @property
    def regular(self) -> bool:
        return self.error is None and self.ftype.startswith("regular")


@dataclass
class ReadResult:
    """Bytes of one read; ``over`` = more than the cap arrived (killed)."""

    data: bytes
    over: bool = False
    stop: str | None = None  # cancelled / deadline / timeout
    killed: bool = False


class DeviceFileReader:
    """Reads files of ONE device (serial fixed at construction).

    Args:
        serial: The device; every argv starts ``[adb, -s, serial]``.
        run: ``run(argv, timeout) -> (rc, stdout, stderr)`` for the probe and
            stat (tests: fakes); default: a polled stream like the reads
            (cancel, deadline and WORLD stop it too).
        popen: ``subprocess.Popen``-like, for the capped streams.
        should_stop: Returns ``"cancelled"`` / ``"deadline"`` / ``"busy"`` to
            stop a read.
    """

    def __init__(
        self,
        serial: str,
        *,
        run: Callable[[list[str], float], tuple[int, bytes, bytes]] | None = None,
        popen: Callable[..., Any] | None = None,
        should_stop: Callable[[], str | None] | None = None,
    ) -> None:
        from sandroid.core.adb import Adb

        if not serial:
            raise ValueError("a device serial is required")
        self.serial = serial
        self.base = Adb.base_argv(serial)
        self._run = run
        self._popen = popen or subprocess.Popen
        self._should_stop = should_stop or (lambda: None)
        self.mode: str | None = None

    # -- argv ---------------------------------------------------------------

    def _call(self, argv: list[str], timeout: float) -> bytes:
        """Stdout of a short command (probe, stat)."""
        if self._run is not None:
            return self._run(argv, timeout)[1]
        return self._stream(argv, OUTPUT_CAP, timeout).data

    def argv(self, words: list[str]) -> list[str]:
        """``exec-out`` argv for *words* (already quoted for the device shell).

        The device command is ONE argv element: adb 36 escapes every
        argument after ``exec-out`` when there are several, so quotes and
        redirects would reach the command literally. As one string the
        device ``sh`` parses it (quotes, ``2>/dev/null``).
        """
        return [*self.base, "exec-out", self.command(words)]

    def command(self, words: list[str]) -> str:
        """The device shell command line for *words* in the root mode."""
        cmd = " ".join(words)
        if self.mode == "su":
            return f"su 0 {cmd}"
        if self.mode == "su_c":
            # su's own notices (Magisk) must not reach the bytes: redirect
            # outside the quoted command as well.
            return f"su -c {shlex.quote(cmd)} 2>/dev/null"
        return cmd

    def probe_root(self) -> str:
        """``root`` / ``su`` / ``su_c`` / ``none``, probed once."""
        if self.mode is not None:
            return self.mode
        out = self._call([*self.base, "exec-out", "id -u"], PROBE_TIMEOUT_S)
        if out.strip() == b"0":
            self.mode = "root"
            return self.mode
        out = self._call(
            [*self.base, "exec-out", "su 0 id -u 2>/dev/null"], SU_PROBE_TIMEOUT_S
        )
        if out.strip() == b"0":
            self.mode = "su"
            return self.mode
        out = self._call(
            [*self.base, "exec-out", "su -c 'id -u 2>/dev/null' 2>/dev/null"],
            SU_PROBE_TIMEOUT_S,
        )
        self.mode = "su_c" if out.strip() == b"0" else "none"
        return self.mode

    # -- stat ---------------------------------------------------------------

    def stat(self, paths: Iterable[str]) -> dict[str, Stat]:
        """``{path: Stat}`` for *paths*, :data:`STAT_BATCH` per device call."""
        self.probe_root()
        todo = list(dict.fromkeys(paths))
        out: dict[str, Stat] = {}
        for batch in _stat_batches(todo):
            if self._should_stop():
                break
            words = [
                "stat",
                "-c",
                shlex.quote("%s|%Y|%F|%n"),
                *[shlex.quote(p) for p in batch],
                "2>&1",
            ]
            stdout = self._call(self.argv(words), STAT_TIMEOUT_S)
            out.update(parse_stat(stdout.decode("utf-8", "replace"), batch))
        for path in todo:  # a stopped call: the rest is unknown
            out.setdefault(path, Stat(path, error="error"))
        return out

    # -- reads --------------------------------------------------------------

    def head(self, path: str, cap: int, timeout: float = HEAD_TIMEOUT_S) -> ReadResult:
        """At most *cap* + 1 bytes of *path* (``over`` when more existed)."""
        self.probe_root()
        words = ["head", "-c", str(cap + 1), shlex.quote(path), "2>/dev/null"]
        t0 = time.time()
        try:
            return self._stream(self.argv(words), cap, timeout)
        finally:
            note_tool_read(path, self.serial, t0, time.time())

    def cat(self, path: str, cap: int, timeout: float = DB_TIMEOUT_S) -> ReadResult:
        """The whole of *path*, killed beyond *cap* bytes (``over``)."""
        self.probe_root()
        words = ["cat", shlex.quote(path), "2>/dev/null"]
        t0 = time.time()
        try:
            return self._stream(self.argv(words), cap, timeout)
        finally:
            note_tool_read(path, self.serial, t0, time.time())

    def _stream(self, argv: list[str], cap: int, timeout: float) -> ReadResult:
        try:
            proc = self._popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, ValueError) as exc:
            logger.debug("read failed to start: %s", exc)
            return ReadResult(b"", stop="error")
        buf = bytearray()
        done = threading.Event()

        def pump() -> None:
            try:
                stream = proc.stdout
                read = getattr(stream, "read1", None) or stream.read
                while len(buf) <= cap:
                    chunk = read(CHUNK)
                    if not chunk:
                        break
                    buf.extend(chunk)
            except Exception:
                logger.debug("read pipe failed", exc_info=True)
            finally:
                done.set()

        thread = threading.Thread(target=pump, name="device-file-read", daemon=True)
        thread.start()
        end = time.monotonic() + timeout
        stop: str | None = None
        while not done.wait(0.05):
            stop = self._should_stop()
            if stop:
                break
            if time.monotonic() > end:
                stop = "timeout"
                break
        killed = False
        if proc.poll() is None:
            # Over the cap (the pump stopped reading), cancelled or late:
            # the host ends the stream.
            with contextlib.suppress(OSError):
                proc.kill()
            killed = True
        with contextlib.suppress(Exception):
            proc.wait(timeout=2.0)
        thread.join(1.0)
        close = getattr(proc.stdout, "close", None)
        if close is not None:
            with contextlib.suppress(Exception):
                close()
        data = bytes(buf[: cap + 1])
        return ReadResult(data, over=len(data) > cap, stop=stop, killed=killed)


def _stat_batches(paths: list[str]) -> Iterator[list[str]]:
    """At most :data:`STAT_BATCH` paths and :data:`STAT_ARGS_CAP` characters
    of quoted paths per batch (one over-long path is a batch of its own).
    """
    batch: list[str] = []
    size = 0
    for path in paths:
        n = len(shlex.quote(path)) + 1
        if batch and (len(batch) >= STAT_BATCH or size + n > STAT_ARGS_CAP):
            yield batch
            batch, size = [], 0
        batch.append(path)
        size += n
    if batch:
        yield batch


def parse_stat(text: str, paths: list[str]) -> dict[str, Stat]:
    """Parse ``stat -c '%s|%Y|%F|%n' ... 2>&1`` output for *paths*.

    A successful line always wins; an error line names its path exactly
    (``'x.db'`` is not ``'x.db-wal'``), else the longest path it contains.
    """
    wanted = set(paths)
    out: dict[str, Stat] = {}
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line:
            continue
        if line.startswith("stat:"):
            path = _error_path(line, paths)
            if path is None or (path in out and out[path].error is None):
                continue
            low = line.lower()
            if "no such file" in low or "not a directory" in low:
                err = "gone"
            elif "permission denied" in low:
                err = "permission_denied"
            else:
                err = "error"
            out[path] = Stat(path, error=err)
            continue
        parts = line.split("|", 3)
        if len(parts) != 4 or parts[3] not in wanted:
            continue
        try:
            size, mtime = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        out[parts[3]] = Stat(parts[3], size=size, mtime=mtime, ftype=parts[2])
    for path in paths:
        out.setdefault(path, Stat(path, error="error"))
    return out


def _error_path(line: str, paths: list[str]) -> str | None:
    exact = [
        p
        for p in paths
        if f"'{p}'" in line or f"\u2018{p}\u2019" in line or f'"{p}"' in line
    ]
    if exact:
        return max(exact, key=len)
    loose = [p for p in paths if p in line]
    return max(loose, key=len) if loose else None


# =============================================================================
# Cache
# =============================================================================


def cache_root(session: Path | None = None) -> Path | None:
    """``<session>/ai/content_cache`` (not created), or None without a session."""
    if session is None:
        try:
            from sandroid.ai.results import session_root

            session = session_root()
        except Exception:
            session = None
    if session is None:
        return None
    return Path(session) / "ai" / CACHE_DIRNAME


def entry_dir(root: Path, path: str) -> Path:
    return root / hashlib.sha1(path.encode("utf-8")).hexdigest()


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    if hasattr(value, "timestamp"):
        with contextlib.suppress(Exception):
            return float(value.timestamp())
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


_UNSET: Any = object()


@dataclass
class CacheEntry:
    """One cached file (see the module docstring)."""

    path: str
    dir: Path
    meta: dict = field(default_factory=dict)

    @property
    def read_at(self) -> float:
        return _as_float(self.meta.get("read_at")) or 0.0

    @property
    def kind(self) -> str:
        return str(self.meta.get("kind") or "metadata")

    @property
    def status(self) -> str:
        return str(self.meta.get("status") or "read")

    @property
    def negative(self) -> bool:
        """Nothing could be read (gone, permission denied, too big ...)."""
        return self.status in NEGATIVE_STATUSES

    def digest(self) -> str:
        try:
            return (self.dir / _DIGEST).read_text(encoding="utf-8")
        except OSError:
            return ""

    def match(self) -> str:
        try:
            return (self.dir / _MATCH).read_text(encoding="utf-8")
        except OSError:
            return ""

    def valid(
        self,
        *,
        row_last: Any = None,
        serial: str | None = None,
        mtime: int | None = None,
        size: int | None = None,
        wal: Any = _UNSET,
        cap: int | None = None,
        sqlite: str | None = None,
        root_mode: str | None = None,
    ) -> bool:
        """Whether this entry still stands for the device file.

        *row_last*: the row's last content change; *mtime* / *size* / *wal*
        (the ``-wal`` :class:`Stat` or None): the batched stat; *cap* and
        *sqlite*: what the caller wants (a bigger cap for a truncated read,
        ``sample`` after ``tables`` or after a skip, is stale).
        """
        meta = self.meta
        if serial and meta.get("serial") and meta["serial"] != serial:
            return False
        if meta.get("world") and meta["world"] != world_token(meta.get("serial")):
            return False
        if root_mode is not None and meta.get("root_mode") not in (None, root_mode):
            return False
        if mtime is not None and meta.get("mtime") != mtime:
            return False
        if size is not None and meta.get("size") != size:
            return False
        if wal is not _UNSET and meta.get("label") == "sqlite":
            now = _wal_meta(wal)
            if (meta.get("wal_mtime"), meta.get("wal_size") or 0) != now:
                return False
        if cap is not None and meta.get("truncated") and cap > (meta.get("cap") or 0):
            return False
        if sqlite is not None:
            if self.status == "sqlite_skipped" and sqlite != "skip":
                return False
            if (
                meta.get("label") == "sqlite"
                and meta.get("sqlite") == "tables"
                and sqlite == "sample"
            ):
                return False
        last = _as_float(row_last)
        if last is not None:
            seen = _as_float(meta.get("row_last"))
            if seen is None:
                seen = self.read_at
            if last > seen:
                return False
        return True


def _wal_meta(wal: Any) -> tuple[int | None, int]:
    if wal is None or not getattr(wal, "regular", False):
        return None, 0
    return wal.mtime, wal.size or 0


def load_entry(path: str, root: Path | None = None) -> CacheEntry | None:
    """The cache entry of *path* (valid or not), or None."""
    root = root if root is not None else cache_root()
    if root is None:
        return None
    d = entry_dir(root, path)
    try:
        meta = json.loads((d / _META).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(meta, dict) or meta.get("path") != path:
        return None
    return CacheEntry(path, d, meta)


def lookup(
    path: str,
    *,
    row_last: Any = None,
    serial: str | None = None,
    root: Path | None = None,
) -> CacheEntry | None:
    """The VALID cache entry of *path* (row ``last`` and serial checked)."""
    entry = load_entry(path, root)
    if entry is None or not entry.valid(row_last=row_last, serial=serial):
        return None
    return entry


def _ensure_dir(path: Path) -> Path:
    from sandroid.ai.results import ensure_private_dir

    ensure_private_dir(path)
    with contextlib.suppress(OSError):
        path.chmod(0o700)
    return path


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    with contextlib.suppress(OSError):
        tmp.unlink()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        tmp.chmod(0o600)
        tmp.replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def write_entry(
    root: Path,
    path: str,
    meta: dict,
    *,
    digest: str,
    match: str,
    files: dict[str, bytes] | None = None,
) -> CacheEntry:
    """Write (or replace) *path*'s entry; ``meta.json`` goes last."""
    with _CACHE_LOCK:
        _ensure_dir(root)
        d = _ensure_dir(entry_dir(root, path))
        names = {_META, _DIGEST, _MATCH, *(files or {})}
        for name, data in (files or {}).items():
            _atomic_write(d / name, data)
        _atomic_write(d / _DIGEST, digest.encode("utf-8"))
        _atomic_write(d / _MATCH, match.encode("utf-8"))
        meta = {**meta, "path": path}
        _atomic_write(d / _META, json.dumps(meta, ensure_ascii=False).encode("utf-8"))
        for old in d.iterdir():
            if old.name not in names and not old.name.startswith("."):
                with contextlib.suppress(OSError):
                    old.unlink()
    return CacheEntry(path, d, meta)


def _entry_size(d: Path) -> int:
    total = 0
    for f in d.iterdir():
        with contextlib.suppress(OSError):
            total += f.stat().st_size
    return total


def evict(root: Path, cap: int | None = None, keep: Iterable[Path] = ()) -> int:
    """Remove the oldest entries (by ``read_at``) until *root* is within *cap*
    (bytes on disk). Entries in *keep* (the running call's) stay.

    Returns:
        Entries removed.
    """
    with _CACHE_LOCK:
        if not root.is_dir():
            return 0
        cap = CACHE_CAP_BYTES if cap is None else cap
        kept = {Path(k) for k in keep}
        entries: list[tuple[float, int, Path]] = []
        for d in root.iterdir():
            if not d.is_dir():
                continue
            try:
                meta = json.loads((d / _META).read_text(encoding="utf-8"))
                read_at = _as_float(meta.get("read_at")) or 0.0
            except (OSError, ValueError, AttributeError):
                read_at = 0.0
            entries.append((read_at, _entry_size(d), d))
        total = sum(size for _t, size, _d in entries)
        removed = 0
        for _t, size, d in sorted(entries, key=lambda e: e[0]):
            if total <= cap:
                break
            if d in kept:
                continue
            shutil.rmtree(d, ignore_errors=True)
            total -= size
            removed += 1
        return removed


# =============================================================================
# One file
# =============================================================================


@dataclass
class FileOutcome:
    """What reading one file did.

    ``status``: ``read``, ``binary``, ``too_big``, ``permission_denied``,
    ``gone``, ``budget``, ``sqlite_skipped``, ``cancelled``, ``deadline`` or
    ``error``.
    """

    status: str
    bytes_read: int = 0
    entry: CacheEntry | None = None


def is_db_name(path: str) -> bool:
    return path.lower().endswith(DB_SUFFIXES)


def expected_bytes(
    path: str, st: Stat, wal: Stat | None, cap: int, sqlite: str = "sample"
) -> int:
    """Device bytes reading *path* is expected to take (budget check)."""
    size = st.size or 0
    if is_db_name(path):
        if sqlite == "skip":
            return 0
        return size + ((wal.size or 0) if wal is not None and wal.regular else 0)
    return min(size, cap + 1)


def db_too_big(path: str, st: Stat, wal: Stat | None) -> bool:
    """A database (by name) whose main file plus ``-wal`` exceed the copy cap."""
    if not is_db_name(path):
        return False
    return (st.size or 0) + _wal_meta(wal)[1] > DB_COPY_CAP


def _stop_status(stop: str | None) -> str:
    return stop if stop in ("cancelled", "deadline", "busy") else "error"


def _meta(
    reader: Any,
    st: Stat | None,
    wal: Stat | None,
    row_last: Any,
    cap: int,
    sqlite: str,
    world: str | None = None,
) -> dict[str, Any]:
    wal_mtime, wal_size = _wal_meta(wal)
    return {
        "serial": getattr(reader, "serial", None),
        "row_last": _as_float(row_last),
        "mtime": st.mtime if st is not None else None,
        "size": st.size if st is not None else None,
        "wal_mtime": wal_mtime,
        "wal_size": wal_size,
        "read_at": time.time(),
        "root_mode": getattr(reader, "mode", None),
        "world": world if world is not None else world_token(reader.serial),
        "cap": cap,
        "sqlite": sqlite,
    }


def remember_unreadable(
    root: Path,
    reader: Any,
    path: str,
    status: str,
    st: Stat | None,
    *,
    wal: Stat | None = None,
    row_last: Any = None,
    cap: int = DEFAULT_BYTES_PER_FILE,
    sqlite: str = "sample",
    world: str | None = None,
) -> CacheEntry:
    """A negative entry: *path* could not be read (*status*), nothing to show."""
    meta = _meta(reader, st, wal, row_last, cap, sqlite, world)
    meta.update(kind="metadata", label=status, status=status, truncated=False)
    return write_entry(root, path, meta, digest="", match="")


def read_into_cache(
    reader: DeviceFileReader,
    root: Path,
    path: str,
    st: Stat,
    *,
    wal: Stat | None = None,
    row_last: Any = None,
    cap: int = DEFAULT_BYTES_PER_FILE,
    sqlite: str = "sample",
    budget_left: int | None = None,
    world: str | None = None,
) -> FileOutcome:
    """Read one regular file (stat *st*) and write its cache entry.

    Unreadable outcomes (gone, permission denied, too big, SQLite skipped)
    write a negative entry.
    """
    from sandroid.ai.row_classifier import render_content

    def negative(status: str, used: int) -> FileOutcome:
        entry = remember_unreadable(
            root,
            reader,
            path,
            status,
            st,
            wal=wal,
            row_last=row_last,
            cap=cap,
            sqlite=sqlite,
            world=world,
        )
        return FileOutcome(status, used, entry)

    def empty(used: int) -> FileOutcome:
        """Nothing came back for a non-empty file. Only a clear answer is
        remembered: gone, or permission denied (the re-stat says so, or it
        works while there is no root). A transient failure (adb offline, a
        root prompt timing out) is an ``error`` with no entry.
        """
        again = reader.stat([path]).get(path)
        if again is not None and again.error in ("gone", "permission_denied"):
            return negative(again.error, used)
        if again is not None and again.regular and reader.mode == "none":
            return negative("permission_denied", used)
        return FileOutcome("error", used)

    used = 0
    data = b""
    truncated = False
    is_db = is_db_name(path)
    if is_db and sqlite == "skip":
        return negative("sqlite_skipped", used)
    if not is_db:
        got = reader.head(path, cap)
        used += len(got.data)
        if got.stop:
            return FileOutcome(_stop_status(got.stop), used)
        if not got.data and (st.size or 0) > 0:
            return empty(used)
        data = got.data[:cap]
        truncated = got.over or (st.size or 0) > cap
        is_db = data.startswith(_SQLITE_MAGIC)
        if is_db and sqlite == "skip":
            return negative("sqlite_skipped", used)
    meta = _meta(reader, st, wal, row_last, cap, sqlite, world)
    if is_db:
        if wal is None:
            wal = reader.stat([path + "-wal"]).get(path + "-wal")
            meta = _meta(reader, st, wal, row_last, cap, sqlite, world)
        wal_size = _wal_meta(wal)[1]
        total = (st.size or 0) + wal_size
        if total > DB_COPY_CAP:
            return negative("too_big", used)
        if budget_left is not None and used + total > budget_left:
            return FileOutcome("budget", used)
        main = reader.cat(path, DB_COPY_CAP)
        used += len(main.data)
        if main.stop:
            return FileOutcome(_stop_status(main.stop), used)
        if main.over:
            return negative("too_big", used)
        if not main.data.startswith(_SQLITE_MAGIC):
            if not main.data and total:
                return empty(used)
            rendered = render_content(path, main.data[:cap], size=st.size)
            status = "binary" if rendered.kind == "binary" else "read"
            meta.update(
                kind=rendered.kind,
                label=rendered.label,
                truncated=len(main.data) > cap,
                status=status,
            )
            files = {} if rendered.kind == "binary" else {_RAW: main.data[:cap]}
            entry = write_entry(
                root,
                path,
                meta,
                digest=rendered.digest,
                match=rendered.match,
                files=files,
            )
            return FileOutcome(status, used, entry)
        files = {_DB: main.data}
        if wal_size:
            wal_got = reader.cat(path + "-wal", DB_COPY_CAP - len(main.data))
            used += len(wal_got.data)
            if wal_got.stop:
                return FileOutcome(_stop_status(wal_got.stop), used)
            if wal_got.over:
                return negative("too_big", used)
            files[_DB_WAL] = wal_got.data
        with tempfile.TemporaryDirectory(prefix="sandroid-dbread-") as tmp:
            for name, blob in files.items():
                (Path(tmp) / name).write_bytes(blob)
            rendered = render_content(path, db=Path(tmp) / _DB, sqlite=sqlite)
        status = "binary" if rendered.kind == "binary" else "read"
        meta.update(
            kind=rendered.kind, label=rendered.label, truncated=False, status=status
        )
        # The db / -wal copies are not kept: nothing reads them again (the
        # digest and match text are written), and they would eat the cap.
        entry = write_entry(
            root, path, meta, digest=rendered.digest, match=rendered.match
        )
        return FileOutcome(status, used, entry)
    rendered = render_content(path, data, size=st.size)
    status = "binary" if rendered.kind == "binary" else "read"
    meta.update(
        kind=rendered.kind, label=rendered.label, truncated=truncated, status=status
    )
    files = {} if rendered.kind == "binary" else {_RAW: data}
    entry = write_entry(
        root, path, meta, digest=rendered.digest, match=rendered.match, files=files
    )
    return FileOutcome(status, used, entry)


__all__ = [
    "CACHE_CAP_BYTES",
    "DB_COPY_CAP",
    "NEGATIVE_STATUSES",
    "CacheEntry",
    "DeviceFileReader",
    "FileOutcome",
    "Stat",
    "cache_root",
    "current_serial",
    "db_base",
    "evict",
    "load_entry",
    "lookup",
    "parse_stat",
    "read_into_cache",
    "read_target",
    "remember_unreadable",
    "world_busy",
    "write_entry",
]
