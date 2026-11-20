"""Host side of the world helper and a serial-pinned device wrapper.

The helper is a dex jar (``tools/worldhelper``, built by
``tools/worldhelper/build.sh``) that runs under ``app_process`` as root over
ONE ``adb -s <serial> shell`` with zygote's environment imported (see
:data:`sandroid.core.uihelper.ZYGOTE_ENV`). It speaks JSON lines: one
request per stdin line, one reply per stdout line, matched by ``id``. It
seeds contacts, the calendar, the call log and SMS in one JVM and reports
every new row's ``_id`` (the ledger).

:class:`Device` runs every adb call as ``adb -s <serial> ...`` with an
argument list (no host shell). The Prepare pipeline only talks to the device
through it, so tests replace it with a recording stub.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import queue
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

from sandroid.core.adb import Adb
from sandroid.core.uihelper import ZYGOTE_ENV
from sandroid.core.uihelper import source_sha256 as _source_sha256

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

logger = logging.getLogger(__name__)

#: Device folder shared with the identity layer (stamp, helper jar).
DEVICE_DIR = "/data/local/tmp/sandroid"
REMOTE_JAR = f"{DEVICE_DIR}/worldhelper.jar"
MAIN_CLASS = "sandroid.worldhelper.Main"
HELPER_VERSION = "1.0.0"
PROTOCOL = 1

#: sha256 of ``src/sandroid/assets/worldhelper/worldhelper.jar`` (build.sh).
JAR_SHA256 = "42b1ffe54cd6800bf4eb8b07a6f08bb125926f2850e9c4af09f7ea3c2be73dbe"
#: :func:`source_sha256` of ``tools/worldhelper/src`` the jar was built from.
SOURCE_SHA256 = "5d2801d4dce3c211bb05412dfc65724364836c1b7af2ef7838b4942dead1bd65"


class HelperError(RuntimeError):
    """The helper could not start, died, timed out or refused a request."""


# ------------------------------------------------------------------ the jar


def jar_path() -> Path:
    """Path of the packaged helper jar."""
    res = resources.files("sandroid").joinpath(
        "assets", "worldhelper", "worldhelper.jar"
    )
    return Path(str(res))


def source_sha256(root: Path | str) -> str:
    """Fingerprint of the helper's Java sources, identical to build.sh's
    (the same definition as :func:`sandroid.core.uihelper.source_sha256`).
    """
    return _source_sha256(root)


def helper_command(jar: str = REMOTE_JAR) -> str:
    """Device shell command that starts the helper (``exec`` replaces the shell)."""
    return f"{ZYGOTE_ENV}; CLASSPATH={jar} exec app_process / {MAIN_CLASS}"


# --------------------------------------------------------------- the device


@dataclass(frozen=True)
class ShellResult:
    """One adb command: exit code (adb shell protocol v2 passes it on)."""

    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


class Device:
    """Every adb call for one serial, as an argument list (``adb -s serial``).

    Args:
        serial: The device serial (required: never the global target).
        adb_argv: The ``[adb, -s, serial]`` prefix (tests); default
            :meth:`Adb.base_argv` with ``serial``.
    """

    def __init__(self, serial: str, *, adb_argv: Sequence[str] | None = None) -> None:
        if not serial:
            raise ValueError("a device serial is required")
        self.serial = serial
        self._argv = list(adb_argv) if adb_argv else None

    def argv(self) -> list[str]:
        """The adb prefix pinned to :attr:`serial`."""
        return list(self._argv) if self._argv else Adb.base_argv(self.serial)

    def run(self, args: Sequence[str], *, timeout: float = 60) -> ShellResult:
        """Run ``adb -s serial <args>``."""
        try:
            proc = subprocess.run(
                [*self.argv(), *args],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ShellResult(124, "", f"timeout after {timeout:.0f}s")
        except OSError as exc:
            return ShellResult(127, "", str(exc))
        return ShellResult(
            proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
        )

    def shell(
        self, script: str, *, timeout: float = 60, zygote: bool = False
    ) -> ShellResult:
        """Run a device shell script (``zygote``: import zygote's env first,
        which ``content``, ``am``, ``bmgr`` and app_process need under adb root).
        """
        if zygote:
            script = f"{ZYGOTE_ENV}; {script}"
        return self.run(["shell", script], timeout=timeout)

    def push(
        self, sources: Sequence[Path | str], remote: str, *, timeout: float = 600
    ) -> ShellResult:
        """One ``adb push`` of files or folders into ``remote``."""
        return self.run(["push", *map(str, sources), remote], timeout=timeout)

    def popen(self, script: str) -> subprocess.Popen:
        """Start ``adb shell <script>`` with stdin/stdout/stderr pipes."""
        return subprocess.Popen(
            [*self.argv(), "shell", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )

    def helper(self, *, timeout: float = 30) -> HelperClient:
        """Start the world helper (call :func:`ensure_jar` first).

        A helper still running on the device (a killed or timed-out run's)
        is stopped first: it could still be writing rows.
        """
        stop_helpers(self)
        client = HelperClient(
            self.popen(helper_command()),
            kill_remote=lambda pid: self.shell(f"kill -9 {int(pid)}", timeout=15),
        )
        client.start(timeout)
        return client


def helper_pids(device: Device) -> list[int]:
    """Pids of every world helper process on the device.

    ``app_process`` keeps its command line (``app_process /
    sandroid.worldhelper.Main``); the ``sh -c`` that execs it is not one.
    """
    out = device.shell("ps -A -o PID,ARGS", timeout=30).out
    pids = []
    for line in out.splitlines():
        parts = line.split()
        if (
            len(parts) >= 3
            and parts[0].isdigit()
            and parts[1].rsplit("/", 1)[-1].startswith("app_process")
            and MAIN_CLASS in parts[2:]
        ):
            pids.append(int(parts[0]))
    return pids


def stop_helpers(device: Device) -> list[int]:
    """Kill every world helper process on the device; return their pids."""
    pids = helper_pids(device)
    if pids:
        logger.info(f"world helper: stopping helper process(es) {pids}")
        device.shell(f"kill -9 {' '.join(map(str, pids))}", timeout=15)
    return pids


def remote_sha256(device: Device, path: str = REMOTE_JAR) -> str:
    """sha256 of a device file ('' when it is missing)."""
    res = device.shell(f"sha256sum {shlex.quote(path)} 2>/dev/null")
    first = res.out.strip().split()
    return first[0].lower() if first else ""


def ensure_jar(device: Device) -> None:
    """Make sure the device holds exactly the packaged jar at :data:`REMOTE_JAR`.

    Skips the push when the device copy already hashes to :data:`JAR_SHA256`;
    otherwise pushes to a temporary name, verifies it, and renames it over
    the jar (the device never holds a half-written jar).

    Raises:
        HelperError: The packaged jar does not match, or the push failed.
    """
    if remote_sha256(device) == JAR_SHA256:
        return
    local = jar_path()
    try:
        local_sha = hashlib.sha256(local.read_bytes()).hexdigest()
    except OSError as exc:
        raise HelperError(f"packaged world helper unreadable: {exc}") from exc
    if local_sha != JAR_SHA256:
        raise HelperError(f"packaged world helper {local} does not match JAR_SHA256")
    tmp = f"{REMOTE_JAR}.{os.getpid()}.tmp"
    device.shell(f"mkdir -p {DEVICE_DIR} && rm -f {tmp}")
    res = device.push([local], tmp, timeout=120)
    got = remote_sha256(device, tmp)
    if got != JAR_SHA256:
        device.shell(f"rm -f {tmp}")
        raise HelperError(
            f"world helper push failed verification ({got or 'missing'}): "
            f"{(res.err or res.out).strip()[:200]}"
        )
    device.shell(f"chmod 644 {tmp} && mv -f {tmp} {REMOTE_JAR}")
    if remote_sha256(device) != JAR_SHA256:
        raise HelperError("world helper rename failed")


# ---------------------------------------------------------------- the client


class HelperClient:
    """One running helper: synchronous JSON-line requests.

    After EOF, a timeout or a reply that cannot be matched to its request,
    the client is broken: every pending and later request fails at once.

    Args:
        proc: The ``adb shell`` process (stdin/stdout pipes), or any object
            with ``stdin``, ``stdout``, ``stderr``, ``poll``, ``wait``,
            ``kill`` (tests).
        kill_remote: Called with the helper's device pid when it must die
            (a timed-out request may still be writing on the device).
    """

    def __init__(
        self, proc: Any, *, kill_remote: Callable[[int], object] | None = None
    ) -> None:
        self.proc = proc
        self.kill_remote = kill_remote
        self.broken: str | None = None
        self.hello: dict[str, Any] | None = None
        self._lines: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._next = 0
        self._lock = threading.Lock()
        self._stderr: list[str] = []
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        if getattr(proc, "stderr", None) is not None:
            threading.Thread(target=self._read_err, daemon=True).start()

    def _read(self) -> None:
        try:
            for raw in iter(self.proc.stdout.readline, b""):
                text = raw.decode("utf-8", "replace").strip()
                if not text.startswith("{"):
                    if text:
                        logger.debug(f"world helper: {text}")
                    continue
                try:
                    self._lines.put(json.loads(text))
                except ValueError:
                    logger.debug(f"world helper: bad line {text[:200]}")
        except (OSError, ValueError):
            pass
        self.broken = self.broken or "exited"
        self._lines.put(None)  # EOF: wakes a waiting request

    def _read_err(self) -> None:
        with contextlib.suppress(OSError, ValueError):
            for raw in iter(self.proc.stderr.readline, b""):
                self._stderr.append(raw.decode("utf-8", "replace").rstrip())
                del self._stderr[:-50]

    def _died(self, what: str) -> HelperError:
        tail = " | ".join(self._stderr[-5:])
        return HelperError(f"world helper {what}" + (f": {tail}" if tail else ""))

    def start(self, timeout: float = 30) -> dict[str, Any]:
        """Wait for the helper's hello.

        Raises:
            HelperError: No hello in time, or a protocol mismatch.
        """
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                self.close()
                raise self._died("did not start")
            try:
                msg = self._lines.get(timeout=left)
            except queue.Empty:
                continue
            if msg is None:
                raise self._died("exited at start")
            if msg.get("type") == "hello":
                if msg.get("protocol") != PROTOCOL:
                    self.close()
                    raise HelperError(
                        f"world helper protocol {msg.get('protocol')} != {PROTOCOL}"
                    )
                self.hello = msg
                return msg

    def request(self, cmd: str, *, timeout: float = 120, **payload: Any) -> dict:
        """Send one request and wait for its reply.

        Raises:
            HelperError: The helper replied ``ok: false``, died or timed out.
        """
        with self._lock:
            if self.broken:
                raise HelperError(f"world helper unusable ({self.broken}): {cmd}")
            self._next += 1
            rid = self._next
            line = json.dumps({"id": rid, "cmd": cmd, **payload}, ensure_ascii=False)
            try:
                self.proc.stdin.write(line.encode("utf-8") + b"\n")
                self.proc.stdin.flush()
            except (OSError, ValueError) as exc:
                self.broken = "gone"
                raise self._died(f"is gone ({exc})") from exc
            end = time.monotonic() + timeout
            while True:
                left = end - time.monotonic()
                if left <= 0:
                    self.broken = f"{cmd} timed out"
                    self._kill_remote()
                    raise HelperError(f"world helper: {cmd} timed out after {timeout}s")
                try:
                    msg = self._lines.get(timeout=left)
                except queue.Empty:
                    continue
                if msg is None:
                    self.broken = "exited"
                    raise self._died(f"exited during {cmd}")
                if msg.get("id") is None and not msg.get("ok") and "error" in msg:
                    # An error the helper could not tie to a request (bad json):
                    # it can only be ours, so fail now instead of timing out.
                    raise HelperError(f"world helper {cmd}: {msg.get('error')}")
                if msg.get("id") != rid:
                    continue
                if not msg.get("ok"):
                    raise HelperError(f"world helper {cmd}: {msg.get('error')}")
                return msg

    def _kill_remote(self) -> None:
        pid = (self.hello or {}).get("pid")
        if self.kill_remote is not None and isinstance(pid, int) and pid > 0:
            with contextlib.suppress(Exception):
                self.kill_remote(pid)

    def close(self, timeout: float = 5) -> None:
        """Ask the helper to quit, then make sure the process is gone."""
        if self.proc.poll() is None:
            with contextlib.suppress(OSError, ValueError):
                self.proc.stdin.write(b'{"id": 0, "cmd": "quit"}\n')
                self.proc.stdin.flush()
            with contextlib.suppress(OSError, ValueError):
                self.proc.stdin.close()
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._kill_remote()
                with contextlib.suppress(OSError):
                    self.proc.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    self.proc.wait(timeout=2)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def chunked(items: Sequence[Any], size: int) -> list[Sequence[Any]]:
    """Split ``items`` into lists of at most ``size``."""
    return [items[i : i + size] for i in range(0, len(items), size)]
