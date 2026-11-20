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
device mtime and size, ``read_at``, kind, truncated), ``raw.bin`` (or
``db`` + ``db-wal``), ``match.txt`` (the full decoded text, searched
locally, never sent to the model) and ``digest.txt`` (the reduced
rendering). An entry is stale when the row's ``last`` is newer than the one
it was read for, the device mtime or size differ, or it came from another
serial; at most 64 MB per session, oldest ``read_at`` evicted first.
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
    from collections.abc import Callable, Iterable

logger = logging.getLogger(__name__)

#: Default / largest bytes read per text file.
DEFAULT_BYTES_PER_FILE = 64 * 1024
MAX_BYTES_PER_FILE = 1024 * 1024
#: A SQLite file plus its ``-wal`` larger than this is not copied.
DB_COPY_CAP = 16 * 1024 * 1024
#: Cache size per session (oldest ``read_at`` evicted first).
CACHE_CAP_BYTES = 64 * 1024 * 1024
#: Paths per ``stat`` call.
STAT_BATCH = 50
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


def _default_run(argv: list[str], timeout: float) -> tuple[int, bytes, bytes]:
    try:
        proc = subprocess.run(  # argv, no shell
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return -1, b"", b"timed out"
    except (OSError, ValueError) as exc:
        return -1, b"", str(exc).encode()
    return proc.returncode, proc.stdout or b"", proc.stderr or b""


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
    return serial if isinstance(serial, str) and serial else None


def current_serial() -> str | None:
    """The monitor's device, else ``Adb.selected_serial()`` (read once)."""
    serial = monitor_serial()
    if serial:
        return serial
    try:
        from sandroid.core.adb import Adb

        return Adb.selected_serial()
    except Exception:
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
        run: ``run(argv, timeout) -> (rc, stdout, stderr)`` (tests: fakes).
        popen: ``subprocess.Popen``-like, for the capped streams.
        should_stop: Returns ``"cancelled"`` / ``"deadline"`` to stop a read.
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
        self._run = run or _default_run
        self._popen = popen or subprocess.Popen
        self._should_stop = should_stop or (lambda: None)
        self.mode: str | None = None

    # -- argv ---------------------------------------------------------------

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
        out = self._stdout([*self.base, "exec-out", "id -u"], PROBE_TIMEOUT_S)
        if out.strip() == b"0":
            self.mode = "root"
            return self.mode
        out = self._stdout(
            [*self.base, "exec-out", "su 0 id -u 2>/dev/null"], SU_PROBE_TIMEOUT_S
        )
        if out.strip() == b"0":
            self.mode = "su"
            return self.mode
        out = self._stdout(
            [*self.base, "exec-out", "su -c 'id -u 2>/dev/null' 2>/dev/null"],
            SU_PROBE_TIMEOUT_S,
        )
        self.mode = "su_c" if out.strip() == b"0" else "none"
        return self.mode

    def _stdout(self, argv: list[str], timeout: float) -> bytes:
        return self._run(argv, timeout)[1]

    # -- stat ---------------------------------------------------------------

    def stat(self, paths: Iterable[str]) -> dict[str, Stat]:
        """``{path: Stat}`` for *paths*, :data:`STAT_BATCH` per device call."""
        self.probe_root()
        todo = list(dict.fromkeys(paths))
        out: dict[str, Stat] = {}
        for i in range(0, len(todo), STAT_BATCH):
            if self._should_stop():
                break
            batch = todo[i : i + STAT_BATCH]
            words = [
                "stat",
                "-c",
                shlex.quote("%s|%Y|%F|%n"),
                *[shlex.quote(p) for p in batch],
                "2>&1",
            ]
            _rc, stdout, _err = self._run(self.argv(words), STAT_TIMEOUT_S)
            out.update(parse_stat(stdout.decode("utf-8", "replace"), batch))
        return out

    # -- reads --------------------------------------------------------------

    def head(self, path: str, cap: int, timeout: float = HEAD_TIMEOUT_S) -> ReadResult:
        """At most *cap* + 1 bytes of *path* (``over`` when more existed)."""
        self.probe_root()
        words = ["head", "-c", str(cap + 1), shlex.quote(path), "2>/dev/null"]
        return self._stream(self.argv(words), cap, timeout)

    def cat(self, path: str, cap: int, timeout: float = DB_TIMEOUT_S) -> ReadResult:
        """The whole of *path*, killed beyond *cap* bytes (``over``)."""
        self.probe_root()
        words = ["cat", shlex.quote(path), "2>/dev/null"]
        return self._stream(self.argv(words), cap, timeout)

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
        data = bytes(buf[: cap + 1])
        return ReadResult(data, over=len(data) > cap, stop=stop, killed=killed)


def parse_stat(text: str, paths: list[str]) -> dict[str, Stat]:
    """Parse ``stat -c '%s|%Y|%F|%n' ... 2>&1`` output for *paths*."""
    wanted = set(paths)
    out: dict[str, Stat] = {}
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line:
            continue
        if line.startswith("stat:"):
            path = _quoted_path(line, wanted)
            if path is None:
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


def _quoted_path(line: str, wanted: set[str]) -> str | None:
    for quote in ("'", "‘", '"'):
        start = line.find(quote)
        if start < 0:
            continue
        close = {"'": "'", "‘": "’", '"': '"'}[quote]
        end = line.rfind(close)
        if end > start:
            candidate = line[start + 1 : end]
            if candidate in wanted:
                return candidate
    for path in wanted:
        if path in line:
            return path
    return None


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
    ) -> bool:
        """Whether this entry still stands for the device file."""
        if serial and self.meta.get("serial") and self.meta["serial"] != serial:
            return False
        if mtime is not None and self.meta.get("mtime") != mtime:
            return False
        if size is not None and self.meta.get("size") != size:
            return False
        last = _as_float(row_last)
        if last is not None:
            seen = _as_float(self.meta.get("row_last"))
            if seen is None:
                seen = self.read_at
            if last > seen:
                return False
        return True


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


def evict(root: Path, cap: int = CACHE_CAP_BYTES) -> int:
    """Remove the oldest entries (by ``read_at``) until *root* is within *cap*.

    Returns:
        Entries removed.
    """
    with _CACHE_LOCK:
        if not root.is_dir():
            return 0
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


def expected_bytes(path: str, st: Stat, wal: Stat | None, cap: int) -> int:
    """Device bytes reading *path* is expected to take (budget check)."""
    size = st.size or 0
    if is_db_name(path):
        return size + ((wal.size or 0) if wal is not None and wal.regular else 0)
    return min(size, cap + 1)


def _stop_status(stop: str | None) -> str:
    return stop if stop in ("cancelled", "deadline") else "error"


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
) -> FileOutcome:
    """Read one regular file (stat *st*) and write its cache entry."""
    from sandroid.ai.row_classifier import render_content

    used = 0
    data = b""
    truncated = False
    is_db = is_db_name(path)
    if not is_db:
        got = reader.head(path, cap)
        used += len(got.data)
        if got.stop:
            return FileOutcome(_stop_status(got.stop), used)
        if not got.data and (st.size or 0) > 0:
            return FileOutcome("permission_denied", used)
        data = got.data[:cap]
        truncated = got.over or (st.size or 0) > cap
        is_db = data.startswith(_SQLITE_MAGIC)
    meta: dict[str, Any] = {
        "serial": reader.serial,
        "row_last": _as_float(row_last),
        "mtime": st.mtime,
        "size": st.size,
        "read_at": time.time(),
        "root_mode": reader.mode,
    }
    if is_db:
        if sqlite == "skip":
            return FileOutcome("sqlite_skipped", used)
        if wal is None:
            wal = reader.stat([path + "-wal"]).get(path + "-wal")
        wal_size = (wal.size or 0) if wal is not None and wal.regular else 0
        total = (st.size or 0) + wal_size
        if total > DB_COPY_CAP:
            return FileOutcome("too_big", used)
        if budget_left is not None and used + total > budget_left:
            return FileOutcome("budget", used)
        main = reader.cat(path, DB_COPY_CAP)
        used += len(main.data)
        if main.stop:
            return FileOutcome(_stop_status(main.stop), used)
        if main.over:
            return FileOutcome("too_big", used)
        if not main.data.startswith(_SQLITE_MAGIC):
            if not main.data and total:
                return FileOutcome("permission_denied", used)
            rendered = render_content(path, main.data[:cap], size=st.size)
            meta.update(kind=rendered.kind, label=rendered.label, truncated=False)
            entry = write_entry(
                root, path, meta, digest=rendered.digest, match=rendered.match
            )
            status = "binary" if rendered.kind == "binary" else "read"
            return FileOutcome(status, used, entry)
        files = {_DB: main.data}
        if wal_size:
            wal_got = reader.cat(path + "-wal", DB_COPY_CAP - len(main.data))
            used += len(wal_got.data)
            if wal_got.stop:
                return FileOutcome(_stop_status(wal_got.stop), used)
            if wal_got.over:
                return FileOutcome("too_big", used)
            files[_DB_WAL] = wal_got.data
        with tempfile.TemporaryDirectory(prefix="sandroid-dbread-") as tmp:
            for name, blob in files.items():
                (Path(tmp) / name).write_bytes(blob)
            rendered = render_content(path, db=Path(tmp) / _DB, sqlite=sqlite)
        meta.update(
            kind=rendered.kind, label=rendered.label, truncated=False, wal=wal_size
        )
        entry = write_entry(
            root, path, meta, digest=rendered.digest, match=rendered.match, files=files
        )
        return FileOutcome(
            "binary" if rendered.kind == "binary" else "read", used, entry
        )
    rendered = render_content(path, data, size=st.size)
    meta.update(kind=rendered.kind, label=rendered.label, truncated=truncated)
    files = {} if rendered.kind == "binary" else {_RAW: data}
    entry = write_entry(
        root, path, meta, digest=rendered.digest, match=rendered.match, files=files
    )
    return FileOutcome("binary" if rendered.kind == "binary" else "read", used, entry)


__all__ = [
    "CACHE_CAP_BYTES",
    "DB_COPY_CAP",
    "CacheEntry",
    "DeviceFileReader",
    "FileOutcome",
    "Stat",
    "cache_root",
    "current_serial",
    "evict",
    "load_entry",
    "lookup",
    "parse_stat",
    "read_into_cache",
    "world_busy",
    "write_entry",
]
