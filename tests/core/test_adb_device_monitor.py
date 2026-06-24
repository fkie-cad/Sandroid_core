"""Unit tests for AdbDeviceMonitor (host:track-devices reader).

Deterministic, no real adb: an injected ``connect_fn`` returns ``FakeSocket``
objects fed scripted byte chunks. Synchronization uses ``threading.Condition``
(``on_change`` count / ``connect_fn`` call count) — never ``sleep`` to wait for
thread progress. Every monitor is auto-stopped via the ``make_monitor``
fixture so a daemon reader can never outlive a test.
"""

import threading
import time

import pytest

from sandroid.core.adb_device_monitor import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    AdbDeviceMonitor,
)

#: recv() sentinel: return b"" (EOF). Distinct from a zero-length data block.
EOF = object()


def _frame(body: bytes) -> bytes:
    """Build a streamed block: 4-hex-digit length prefix + body."""
    return b"%04x%s" % (len(body), body)


DEVICE_BODY = b"emulator-5554\tdevice\n"
DEVICE_FRAME = _frame(DEVICE_BODY)


class FakeSocket:
    """Socket-like object that serves a scripted list of recv() results.

    Each script item is consumed by successive ``recv`` calls:
    - ``bytes`` -> returned (split to honour the requested ``n``; the
      remainder is held for the next recv, so a frame can be delivered in
      arbitrary chunks);
    - ``EOF`` -> ``recv`` returns ``b""`` (mid-stream EOF);
    - a ``BaseException`` instance -> raised from ``recv`` (e.g.
      ``socket.timeout``).
    Once the script is exhausted, ``recv`` blocks (mirroring a live stream
    awaiting the next change) until ``shutdown``/``close`` wakes it.
    """

    def __init__(self, script):
        self._script = list(script)
        self._pending = b""
        self.sent: list[bytes] = []
        self.timeout_value = None
        self.shutdown_count = 0
        self.close_count = 0
        self._lock = threading.Lock()
        self._wake = threading.Event()

    def settimeout(self, value) -> None:
        self.timeout_value = value

    def sendall(self, data) -> None:
        self.sent.append(data)

    def recv(self, n: int) -> bytes:
        if self._pending:
            chunk, self._pending = self._pending[:n], self._pending[n:]
            return chunk
        if self._script:
            item = self._script.pop(0)
            if isinstance(item, BaseException):
                raise item
            if item is EOF:
                return b""
            if len(item) > n:
                chunk, self._pending = item[:n], item[n:]
                return chunk
            return item
        # Script exhausted: behave like a live stream with no new data —
        # block until stop() shuts the socket down, then surface EOF.
        self._wake.wait(timeout=5.0)
        raise ConnectionError("fake socket closed")

    def shutdown(self, how) -> None:
        with self._lock:
            self.shutdown_count += 1
        self._wake.set()

    def close(self) -> None:
        with self._lock:
            self.close_count += 1
        self._wake.set()


class ConnectFn:
    """Injectable ``connect_fn`` serving a scripted list of sockets.

    Each call pops the next item: a ``FakeSocket`` is returned, a
    ``BaseException`` is raised (e.g. ``ConnectionRefusedError``). Once the
    list is exhausted, every further call raises ``ConnectionRefusedError`` so
    the monitor keeps retrying. Records ``(host, port)`` per call.
    """

    def __init__(self, items):
        self._items = list(items)
        self.calls: list[tuple] = []
        self._cond = threading.Condition()

    def __call__(self, host, port):
        with self._cond:
            self.calls.append((host, port))
            self._cond.notify_all()
            item = (
                self._items.pop(0)
                if self._items
                else ConnectionRefusedError("no more scripted sockets")
            )
        if isinstance(item, BaseException):
            raise item
        return item

    def wait_calls(self, target: int, timeout: float = 3.0) -> bool:
        with self._cond:
            return self._cond.wait_for(
                lambda: len(self.calls) >= target, timeout=timeout
            )


class OnChangeRecorder:
    """Counts on_change invocations; can raise on chosen 1-based call indices."""

    def __init__(self, raise_on=()):
        self.count = 0
        self._raise_on = set(raise_on)
        self._cond = threading.Condition()

    def __call__(self) -> None:
        with self._cond:
            self.count += 1
            n = self.count
            self._cond.notify_all()
        if n in self._raise_on:
            raise RuntimeError(f"boom on call {n}")

    def wait_for(self, target: int, timeout: float = 3.0) -> bool:
        with self._cond:
            return self._cond.wait_for(lambda: self.count >= target, timeout=timeout)


@pytest.fixture
def make_monitor():
    """Factory that builds monitors and auto-stops them on teardown."""
    created: list[AdbDeviceMonitor] = []

    def _make(**kwargs):
        kwargs.setdefault("backoff_initial", 0.01)
        kwargs.setdefault("backoff_max", 0.05)
        monitor = AdbDeviceMonitor(**kwargs)
        created.append(monitor)
        return monitor

    yield _make
    for monitor in created:
        try:
            monitor.stop()
        except Exception:
            pass


# -- handshake + block streaming -----------------------------------------


def test_okay_plus_one_block_fires_once(make_monitor):
    rec = OnChangeRecorder()
    sock = FakeSocket([b"OKAY", DEVICE_FRAME])
    cf = ConnectFn([sock])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert rec.wait_for(1)
    # Give any spurious extra block a chance to (not) arrive.
    assert not rec.wait_for(2, timeout=0.2)
    assert rec.count == 1
    # Lock the wire format: %04x length prefix + the track-devices request.
    assert sock.sent == [b"0012host:track-devices"]


def test_multiple_blocks_one_call_each(make_monitor):
    rec = OnChangeRecorder()
    sock = FakeSocket([b"OKAY", _frame(b"a\tdevice\n"), DEVICE_FRAME, _frame(b"")])
    cf = ConnectFn([sock])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert rec.wait_for(3)
    assert rec.count == 3


def test_zero_length_block_still_fires(make_monitor):
    """A "0000" (empty) block must fire on_change and the loop must continue."""
    rec = OnChangeRecorder()
    # Empty block, then a normal one — proves both the n==0 path fires AND that
    # the read loop survives a zero-length read.
    sock = FakeSocket([b"OKAY", b"0000", DEVICE_FRAME])
    cf = ConnectFn([sock])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert rec.wait_for(2)
    assert rec.count == 2


def test_partial_recv_reassembly(make_monitor):
    """Length prefix split across recvs AND body split -> exactly one call."""
    rec = OnChangeRecorder()
    # "0015" length delivered as "00"+"15"; body delivered in two pieces.
    sock = FakeSocket([b"OKAY", b"00", b"15", b"emulator-5554\t", b"device\n"])
    cf = ConnectFn([sock])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert rec.wait_for(1)
    assert not rec.wait_for(2, timeout=0.2)
    assert rec.count == 1


# -- error / reconnect paths ---------------------------------------------


def _fail_socket() -> "FakeSocket":
    """A FakeSocket that returns a FAIL handshake (16-byte message body)."""
    return FakeSocket([b"FAIL", b"0010", b"unknown service!"])


def test_fail_handshake_never_fires_and_reconnects(make_monitor):
    """FAIL handshake -> never fires, no crash, reconnects (connect >= 2)."""
    rec = OnChangeRecorder()
    cf = ConnectFn([_fail_socket(), _fail_socket()])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert cf.wait_calls(2)
    assert rec.count == 0
    monitor.stop()
    assert rec.count == 0


def test_eof_mid_frame_reconnects(make_monitor):
    """EOF mid-frame (recv -> b"") -> reconnect, no crash, then fires."""
    rec = OnChangeRecorder()
    broken = FakeSocket([b"OKAY", b"0015", b"emulator", EOF])
    good = FakeSocket([b"OKAY", DEVICE_FRAME])
    cf = ConnectFn([broken, good])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert rec.wait_for(1)
    assert cf.wait_calls(2)


def test_on_change_raising_does_not_kill_loop(make_monitor):
    """A raising callback is swallowed; the next block still fires."""
    rec = OnChangeRecorder(raise_on={1})
    sock = FakeSocket([b"OKAY", _frame(b"a\tdevice\n"), DEVICE_FRAME])
    cf = ConnectFn([sock])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert rec.wait_for(2)
    assert rec.count == 2


def test_read_timeout_self_heals(make_monitor):
    """A read timeout (socket.timeout / TimeoutError) -> reconnect, no crash."""
    rec = OnChangeRecorder()
    # socket.timeout is an alias of TimeoutError (an OSError subclass), which is
    # exactly what a recv blocked past READ_TIMEOUT raises on a real socket.
    stalled = FakeSocket([b"OKAY", TimeoutError("timed out")])
    good = FakeSocket([b"OKAY", DEVICE_FRAME])
    cf = ConnectFn([stalled, good])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert rec.wait_for(1)
    assert cf.wait_calls(2)


def test_hex_parse_desync_reconnects(make_monitor):
    """Non-hex length bytes -> ValueError -> reconnect, no crash."""
    rec = OnChangeRecorder()
    garbage = FakeSocket([b"OKAY", b"zzzz", b"junk"])
    good = FakeSocket([b"OKAY", DEVICE_FRAME])
    cf = ConnectFn([garbage, good])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert rec.wait_for(1)
    assert cf.wait_calls(2)


def test_connect_refused_then_succeeds_resets_backoff(make_monitor):
    """Refused N times then OKAY: eventually fires AND backoff resets to initial."""
    rec = OnChangeRecorder()
    cf = ConnectFn(
        [
            ConnectionRefusedError(),
            ConnectionRefusedError(),
            ConnectionRefusedError(),
            FakeSocket([b"OKAY", DEVICE_FRAME]),
        ]
    )
    monitor = make_monitor(
        on_change=rec, connect_fn=cf, backoff_initial=0.01, backoff_max=10.0
    )
    monitor.start()

    assert rec.wait_for(1)
    assert len(cf.calls) >= 4
    # The refusals grew the backoff well above initial; the OKAY must reset it.
    assert monitor._backoff == pytest.approx(0.01)


# -- stop() lifecycle ----------------------------------------------------


def test_stop_joins_and_closes_socket_idempotent(make_monitor):
    rec = OnChangeRecorder()
    sock = FakeSocket([b"OKAY", DEVICE_FRAME])
    cf = ConnectFn([sock])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert rec.wait_for(1)
    monitor.stop()

    assert monitor._thread is not None
    assert not monitor._thread.is_alive()
    assert sock.shutdown_count >= 1
    assert sock.close_count >= 1

    # Idempotent: a second stop() is a no-op and must not raise.
    monitor.stop()


def test_stop_during_backoff_wait_is_prompt(make_monitor):
    """stop() mid-backoff interrupts the wait and joins well under backoff_initial."""
    rec = OnChangeRecorder()
    # Every connect refuses, so the loop stays in the interruptible backoff.
    cf = ConnectFn([ConnectionRefusedError() for _ in range(100)])
    monitor = make_monitor(
        on_change=rec, connect_fn=cf, backoff_initial=5.0, backoff_max=5.0
    )
    monitor.start()

    assert cf.wait_calls(1)
    start = time.monotonic()
    monitor.stop()
    elapsed = time.monotonic() - start

    assert elapsed < 4.0  # well under the 5.0 backoff -> wait was interrupted
    assert not monitor._thread.is_alive()
    assert rec.count == 0


# -- host/port resolution ------------------------------------------------


def test_env_host_and_port_reach_connect_fn(make_monitor, monkeypatch):
    monkeypatch.setenv("ANDROID_ADB_SERVER_ADDRESS", "10.0.0.5")
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "5999")
    monkeypatch.delenv("ANDROID_ADB_SERVER_HOST", raising=False)

    rec = OnChangeRecorder()
    cf = ConnectFn([FakeSocket([b"OKAY", DEVICE_FRAME])])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert rec.wait_for(1)
    assert cf.calls[0] == ("10.0.0.5", 5999)


def test_bad_port_falls_back_to_default(make_monitor, monkeypatch):
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "not-a-number")
    monkeypatch.delenv("ANDROID_ADB_SERVER_ADDRESS", raising=False)
    monkeypatch.delenv("ANDROID_ADB_SERVER_HOST", raising=False)

    rec = OnChangeRecorder()
    cf = ConnectFn([FakeSocket([b"OKAY", DEVICE_FRAME])])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert rec.wait_for(1)
    assert cf.calls[0] == (DEFAULT_HOST, DEFAULT_PORT)


def test_out_of_range_port_falls_back(make_monitor, monkeypatch):
    """A numeric-but-out-of-range port must fall back to the default.

    On Linux such a port raises OverflowError from connect() — not in the
    reader loop's caught tuple — which would otherwise kill the thread.
    """
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "99999")
    monkeypatch.delenv("ANDROID_ADB_SERVER_ADDRESS", raising=False)
    monkeypatch.delenv("ANDROID_ADB_SERVER_HOST", raising=False)

    rec = OnChangeRecorder()
    cf = ConnectFn([FakeSocket([b"OKAY", DEVICE_FRAME])])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert rec.wait_for(1)
    assert cf.calls[0] == (DEFAULT_HOST, DEFAULT_PORT)


def test_malformed_address_retries_without_crash(make_monitor, monkeypatch):
    """A malformed ADDRESS is passed through; a failed connect just retries."""
    monkeypatch.setenv("ANDROID_ADB_SERVER_ADDRESS", "tcp:weird-host")
    monkeypatch.delenv("ANDROID_ADB_SERVER_PORT", raising=False)

    rec = OnChangeRecorder()
    cf = ConnectFn([OSError("nodename nor servname"), OSError("again")])
    monitor = make_monitor(on_change=rec, connect_fn=cf)
    monitor.start()

    assert cf.wait_calls(2)
    assert rec.count == 0
    assert cf.calls[0][0] == "tcp:weird-host"


# -- app-level trailing-debounce (lightweight) ---------------------------


class _FakeApp:
    """Minimal stand-in exercising the app's trailing-debounce contract.

    Mirrors SandroidTUI._poll_device_state / _refresh_devices_bg: a second
    poll arriving while one is in flight sets _device_poll_pending, and the
    in-flight worker's completion re-triggers exactly one trailing poll.
    """

    def __init__(self):
        self._device_poll_in_flight = False
        self._device_poll_pending = False
        self.poll_calls = 0

    def _poll_device_state(self):
        self.poll_calls += 1
        if self._device_poll_in_flight:
            self._device_poll_pending = True
            return
        self._device_poll_in_flight = True

    def _refresh_devices_bg(self):
        try:
            pass
        finally:
            self._device_poll_in_flight = False
            if self._device_poll_pending:
                self._device_poll_pending = False
                self._poll_device_state()


def test_trailing_debounce_reruns_once_after_inflight():
    app = _FakeApp()

    app._poll_device_state()  # first poll: takes the in-flight slot
    assert app._device_poll_in_flight is True
    assert app._device_poll_pending is False

    app._poll_device_state()  # arrives while in flight -> pending
    assert app._device_poll_pending is True

    app._refresh_devices_bg()  # completion clears flag + reruns once
    assert app._device_poll_pending is False
    # 1 initial + 1 (skipped, set pending) + 1 trailing rerun = 3 invocations.
    assert app.poll_calls == 3
