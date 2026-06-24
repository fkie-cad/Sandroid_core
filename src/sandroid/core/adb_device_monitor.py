r"""Real-time ADB device-change monitor (``host:track-devices``).

The adb server (TCP ``127.0.0.1:5037``) exposes a streaming service,
``host:track-devices``, that holds the connection open and pushes a fresh
device-list block on every connect / disconnect / state change -- the same
mechanism Android Studio and ddmlib consume. Reading it gives near-instant
(sub-second) device-change detection without spawning ``adb devices`` on a
timer.

This module is a self-contained, app-agnostic, unit-testable protocol reader.
It never parses the device list and never diffs state -- it only signals
"the device list changed" via the ``on_change`` callback. The caller re-uses
its own enumeration path (e.g. ``DeviceManager.refresh_devices()``) as the
single source of truth for diffing, metadata, and callbacks.

Wire protocol::

    client -> "%04x" ASCII-hex length + payload   (e.g. "0012host:track-devices")
    server -> 4 bytes "OKAY"                       (or "FAIL" + 4-hex-len + msg)
    server -> repeated blocks, each: 4-hex-digit length + body
              body = "serial\tstate\n..."           (body may be empty -> "0000")

No new dependency: a raw socket, not ``adbutils``.
"""

import logging
import os
import socket
import threading
from collections.abc import Callable

logger = logging.getLogger(__name__)

#: Defaults matching adb's own behaviour when the env vars are unset.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5037

#: Connect timeout (s). create_connection leaves this on the socket, so we
#: always override it with READ_TIMEOUT before the first recv (see _run).
CONNECT_TIMEOUT = 5.0

#: Read timeout (s) -- a liveness ceiling, NOT a per-block deadline. On
#: loopback a dead adb server normally sends RST/FIN so EOF is prompt, but a
#: half-open socket (laptop suspend/resume, adb SIGKILL without teardown) can
#: otherwise wedge a blocking recv forever, silently killing the fast path. A
#: long timeout self-heals it: socket.timeout (an OSError subclass) flows
#: through the per-iteration handler -> reconnect. 300s makes idle churn
#: negligible while bounding fast-path dormancy after a resume to <=5 min.
READ_TIMEOUT = 300.0

#: The track-devices service request payload (length prefix added on send).
REQ = b"host:track-devices"


def _resolve_host(host: str | None) -> str:
    """Resolve the adb server host (best-effort, never raises).

    An explicit ``host`` wins; otherwise ``ANDROID_ADB_SERVER_ADDRESS``, then
    ``ANDROID_ADB_SERVER_HOST``, then the loopback default. A malformed/exotic
    value (e.g. a ``tcp:``-prefixed or unix-socket address) is passed through
    verbatim -- it just leads to a failed connect the backoff loop retries.
    """
    if host is not None:
        return host
    return (
        os.environ.get("ANDROID_ADB_SERVER_ADDRESS")
        or os.environ.get("ANDROID_ADB_SERVER_HOST")
        or DEFAULT_HOST
    )


def _resolve_port(port: int | None) -> int:
    """Resolve the adb server port (best-effort, never raises).

    An explicit ``port`` wins; otherwise ``ANDROID_ADB_SERVER_PORT`` parsed as
    an int, falling back to the default on a malformed value. The resolved
    port is range-checked: a numeric-but-out-of-range value (e.g. 99999) is
    rejected too, because on Linux it raises ``OverflowError`` from connect()
    -- which is NOT in the reader loop's caught tuple and would kill the
    thread. Falling back keeps the "never crash" contract platform-independent.
    """
    if port is None:
        raw = os.environ.get("ANDROID_ADB_SERVER_PORT")
        if not raw:
            return DEFAULT_PORT
        try:
            port = int(raw)
        except ValueError:
            logger.debug(
                "Invalid ANDROID_ADB_SERVER_PORT=%r; falling back to %d",
                raw,
                DEFAULT_PORT,
            )
            return DEFAULT_PORT
    if not 1 <= port <= 65535:
        logger.debug(
            "adb server port out of range (%r); falling back to %d", port, DEFAULT_PORT
        )
        return DEFAULT_PORT
    return port


class AdbDeviceMonitor:
    """Streams ``host:track-devices`` and fires ``on_change`` on every block.

    The monitor runs one daemon reader thread with a reconnect-with-backoff
    loop, so a transient socket/parse error (or an adb-server restart) just
    reconnects rather than killing the only fast-path thread. It is a pure
    "something changed" notifier: it does not parse or diff the device list.
    """

    def __init__(
        self,
        on_change: Callable[[], None],
        *,
        host: str | None = None,
        port: int | None = None,
        connect_fn: Callable[[str, int], object] | None = None,
        backoff_initial: float = 1.0,
        backoff_max: float = 10.0,
    ):
        """Initialize the monitor.

        Args:
            on_change: Called (on the reader thread) once per streamed block.
                Must be cheap and exception-tolerant; a raising callback is
                caught and never kills the loop.
            host: adb server host; ``None`` resolves from env / loopback.
            port: adb server port; ``None`` resolves from env / 5037.
            connect_fn: Injectable factory ``connect_fn(host, port)`` returning
                a socket-like object (``sendall`` / ``recv`` / ``shutdown`` /
                ``close``). Defaults to a real TCP socket. The test seam.
            backoff_initial: Initial reconnect backoff (s). Reset only on a
                successful ``OKAY`` handshake.
            backoff_max: Maximum reconnect backoff (s).
        """
        self._on_change = on_change
        self._host = _resolve_host(host)
        self._port = _resolve_port(port)
        self._connect_fn = connect_fn or self._default_connect
        self._backoff_initial = backoff_initial
        self._backoff_max = backoff_max

        #: Current reconnect backoff. Lives on the instance (not a _run local)
        #: so tests can assert the reset-on-OKAY behaviour. Read/written only
        #: on the reader thread during normal operation.
        self._backoff = backoff_initial

        self._stop_event = threading.Event()
        self._sock_lock = threading.Lock()
        self._sock: object | None = None
        self._thread: threading.Thread | None = None

    @staticmethod
    def _default_connect(host: str, port: int) -> socket.socket:
        """Open a real TCP connection to the adb server."""
        return socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)

    def start(self) -> None:
        """Spawn the daemon reader thread (idempotent against double-start)."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run, name="adb-track-devices", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the reader thread and tear down the socket (idempotent).

        Safe to call on the app thread: it only sets the stop Event, shuts
        down + closes the socket, and joins the reader thread. ``shutdown()``
        reliably wakes a ``recv`` blocked on the reader thread (more robust
        than a bare ``close()``), so the join returns promptly.
        """
        if self._stop_event.is_set():
            return
        self._stop_event.set()
        self._shutdown_sock()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2.0)

    # -- internals --------------------------------------------------------

    def _run(self) -> None:
        """Reconnect-with-backoff loop reading the track-devices stream."""
        self._backoff = self._backoff_initial
        while not self._stop_event.is_set():
            try:
                self._connect_and_stream()
            except (OSError, ConnectionError, ValueError) as exc:
                # Any socket / parse error (incl. socket.timeout and the hex
                # length parse) just reconnects -- never kills the thread.
                if self._stop_event.is_set():
                    break
                logger.debug("adb track-devices stream error: %s", exc)
                self._stop_event.wait(self._backoff)  # interruptible backoff
                self._backoff = min(self._backoff * 2, self._backoff_max)
            finally:
                self._shutdown_sock()

    def _connect_and_stream(self) -> None:
        """Connect, perform the handshake, then stream change blocks."""
        sock = self._connect_fn(self._host, self._port)
        # Store under the lock BEFORE the first recv so stop() can shut it down,
        # and re-check the stop flag under the SAME lock to close the start/stop
        # race: if stop() ran between connect() and here it saw self._sock still
        # None (so it could not shut this socket down), so bail now rather than
        # block in recv for up to READ_TIMEOUT on an orphaned socket. _run's
        # finally closes it; the outer loop then exits on the set stop flag.
        with self._sock_lock:
            self._sock = sock
            if self._stop_event.is_set():
                return
        # Override create_connection's connect timeout (a classic footgun --
        # it otherwise lingers on every recv) and arm the liveness ceiling.
        sock.settimeout(READ_TIMEOUT)
        sock.sendall(b"%04x%s" % (len(REQ), REQ))

        status = self._recv_exactly(sock, 4)
        if status != b"OKAY":
            self._log_handshake_failure(sock, status)
            # Back off WITHOUT resetting (only OKAY resets) and do not
            # immediately reconnect -- prevents a tight loop / log-spam if the
            # server persistently FAILs. Raising routes through _run's handler.
            raise ConnectionError("adb track-devices handshake not OKAY")

        # Successful handshake -- reset backoff and stream blocks.
        self._backoff = self._backoff_initial
        while not self._stop_event.is_set():
            # Length prefix read with the exact-N helper (a bare recv(4) can
            # split); body may be empty ("0000").
            length = int(self._recv_exactly(sock, 4), 16)
            self._recv_exactly(sock, length)
            self._fire_on_change()

    def _log_handshake_failure(self, sock: object, status: bytes) -> None:
        """Log a non-OKAY handshake, reading the FAIL message if present."""
        detail = ""
        if status == b"FAIL":
            try:
                length = int(self._recv_exactly(sock, 4), 16)
                detail = self._recv_exactly(sock, length).decode("utf-8", "replace")
            except (OSError, ConnectionError, ValueError):
                detail = "<unreadable>"
        logger.debug(
            "adb track-devices handshake failed (status=%r): %s", status, detail
        )

    def _fire_on_change(self) -> None:
        """Invoke the change callback, swallowing any exception it raises."""
        try:
            self._on_change()
        except Exception:
            logger.debug("adb track-devices on_change callback raised", exc_info=True)

    @staticmethod
    def _recv_exactly(sock: object, n: int) -> bytes:
        """Read exactly ``n`` bytes, or raise ConnectionError on EOF.

        A zero-length read is VALID (an empty device-list block "0000" or an
        empty FAIL message) and must NOT be treated as EOF -- return before
        touching recv so the empty block still fires ``on_change``.
        """
        if n == 0:
            return b""
        chunks: list[bytes] = []
        remaining = n
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                raise ConnectionError("adb track-devices stream closed (EOF)")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _shutdown_sock(self) -> None:
        """Read+clear the current socket under the lock, then shut it down.

        Shared by stop() and the per-iteration ``finally``. ``shutdown()`` then
        ``close()``, each guarded, since the socket may already be dead and the
        interaction of a bare close() with an in-progress recv is not atomic.
        """
        with self._sock_lock:
            sock = self._sock
            self._sock = None
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
