"""Live device screen core: ``core/emulator_grpc`` and the screen service.

No emulator, no adb, no grpcio needed (grpc-only checks use importorskip):
frames are hand-encoded protobuf bytes, discovery files live in tmp_path,
and the service runs against a fake client and a fake device manager.
"""

from __future__ import annotations

import queue
import sys
import threading
import time
import types
from pathlib import Path
from typing import Any

import pytest

from sandroid.config.schema import DeviceScreenConfig, TUIConfig
from sandroid.core import emulator
from sandroid.core import emulator_grpc as egrpc
from sandroid.core.emulator_grpc import support
from sandroid.core.emulator_grpc.support import (
    EmulatorEndpoint,
    RawImage,
    ScreenRpcError,
    find_emulator,
    layout_safe,
    list_emulators,
    parse_image,
    to_native,
)
from sandroid.services import device_screen_service as dss
from sandroid.services.device_screen_service import DeviceScreenService, ScreenState

# ---------------------------------------------------------------------------
# Hand-made protobuf wire encoding (no protobuf runtime)
# ---------------------------------------------------------------------------


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _vfield(no: int, value: int) -> bytes:
    return _varint(no << 3) + _varint(value)


def _lfield(no: int, payload: bytes) -> bytes:
    return _varint((no << 3) | 2) + _varint(len(payload)) + payload


def _dfield(no: int, value: float = 90.0) -> bytes:
    import struct

    return _varint((no << 3) | 1) + struct.pack("<d", value)


def _image_msg(
    width: int,
    height: int,
    pixels: bytes,
    *,
    fmt: int = 2,
    rotation: int | None = 1,
    seq: int = 7,
    ts: int = 1_700_000_000_000_000,
) -> bytes:
    """A serialized ``Image`` (format=1, image=4, seq=5, timestampUs=6)."""
    image_format = _vfield(1, fmt)
    if rotation is not None:
        # Rotation{rotation=1, zAxis=4 (double)}: the double must be skipped.
        image_format += _lfield(2, _vfield(1, rotation) + _dfield(4))
    image_format += _vfield(3, width) + _vfield(4, height) + _vfield(5, 0)
    return (
        _lfield(1, image_format) + _lfield(4, pixels) + _vfield(5, seq) + _vfield(6, ts)
    )


# ---------------------------------------------------------------------------
# parse_image
# ---------------------------------------------------------------------------


def test_parse_image_rgb888_zero_copy() -> None:
    pixels = bytes(range(18))
    raw = _image_msg(3, 2, pixels)
    image = parse_image(raw)
    assert image is not None
    assert (image.width, image.height, image.rotation, image.bpp) == (3, 2, 1, 3)
    assert image.seq == 7
    assert image.ts_us == 1_700_000_000_000_000
    assert isinstance(image.pixels, memoryview)
    assert image.pixels.obj is raw  # a view into the message, not a copy
    assert bytes(image.pixels) == pixels


def test_parse_image_rgba_and_no_rotation() -> None:
    image = parse_image(_image_msg(2, 2, bytes(16), fmt=1, rotation=None))
    assert image is not None
    assert (image.bpp, image.rotation) == (4, 0)


@pytest.mark.parametrize(
    "raw",
    [
        _image_msg(3, 2, b""),  # display inactive: empty image
        _image_msg(3, 2, bytes(17)),  # short buffer
        _image_msg(3, 2, bytes(18), fmt=0),  # PNG
        _image_msg(0, 2, b"x"),  # no width
        _lfield(4, bytes(18)),  # no format at all
    ],
)
def test_parse_image_unusable_returns_none(raw: bytes) -> None:
    assert parse_image(raw) is None


def test_parse_image_malformed_raises_value_error() -> None:
    raw = _image_msg(3, 2, bytes(18))
    with pytest.raises(ValueError):
        parse_image(raw[:-3])  # truncated inside the varint fields
    with pytest.raises(ValueError):
        parse_image(raw[:10])  # length-delimited field past the end
    with pytest.raises(ValueError):
        parse_image(b"\x0b")  # wire type 3 (groups)


def test_parse_image_matches_the_protobuf_runtime() -> None:
    pytest.importorskip("grpc")
    pytest.importorskip("google.protobuf")
    from sandroid.core.emulator_grpc import client
    from sandroid.core.emulator_grpc import emulator_controller_pb2 as pb

    msg = pb.Image(
        format=pb.ImageFormat(
            format=pb.ImageFormat.RGB888,
            width=3,
            height=2,
            rotation=pb.Rotation(rotation=pb.Rotation.LANDSCAPE, zAxis=90.0),
        ),
        image=bytes(range(18)),
        seq=9,
        timestampUs=123,
    )
    raw = msg.SerializeToString()
    fast = parse_image(raw)
    slow = client._image_from_protobuf(raw)
    assert fast is not None
    assert slow is not None
    assert (fast.width, fast.height, fast.rotation, fast.seq, fast.ts_us) == (
        slow.width,
        slow.height,
        slow.rotation,
        slow.seq,
        slow.ts_us,
    )
    assert bytes(fast.pixels) == bytes(slow.pixels)
    endpoint = EmulatorEndpoint(5554, 1, token="s3cr3t")  # noqa: S106
    rep = repr(client.open_client(endpoint))
    assert "s3cr3t" not in rep


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _ini(directory: Path, pid: int, console: int, grpc_port: int, token: str) -> Path:
    path = directory / f"pid_{pid}.ini"
    path.write_text(
        f"port.serial={console}\nport.adb={console + 1}\navd.id=Dev\n"
        f"grpc.port={grpc_port}\ngrpc.token={token}\n"
    )
    return path


@pytest.fixture
def running(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, set[int]]:
    """A discovery dir; only pids in the returned set count as alive."""
    alive: set[int] = set()
    monkeypatch.setattr(support, "_pid_alive", lambda pid: pid in alive)
    return tmp_path, alive


def test_find_emulator_exact_serial(running: tuple[Path, set[int]]) -> None:
    directory, alive = running
    _ini(directory, 101, 5556, 8556, "b")
    _ini(directory, 100, 5554, 8554, "a")
    _ini(directory, 102, 55540, 9999, "c")
    alive.update({100, 101, 102})
    assert find_emulator("emulator-5554", [directory]).grpc_port == 8554
    assert find_emulator("emulator-5556", [directory]).grpc_port == 8556
    for serial in ("emulator-555", "emulator-5558", "5554", "ABC123", ""):
        with pytest.raises(LookupError):
            find_emulator(serial, [directory])


def test_find_emulator_skips_stale_pid_files(running: tuple[Path, set[int]]) -> None:
    directory, alive = running
    _ini(directory, 200, 5554, 8554, "old")  # killed: its file survived
    with pytest.raises(LookupError):
        find_emulator("emulator-5554", [directory])
    _ini(directory, 201, 5554, 8555, "new")
    alive.add(201)
    found = find_emulator("emulator-5554", [directory])
    assert (found.pid, found.grpc_port, found.token) == (201, 8555, "new")


def test_find_emulator_rereads_the_token(running: tuple[Path, set[int]]) -> None:
    directory, alive = running
    path = _ini(directory, 300, 5554, 8554, "first")
    alive.add(300)
    first = find_emulator("emulator-5554", [directory])
    path.write_text(path.read_text().replace("first", "second"))
    second = find_emulator("emulator-5554", [directory])
    assert (first.token, second.token) == ("first", "second")
    assert first.identity != second.identity
    assert "first" not in repr(first)
    assert "first" not in str(first.identity)


def test_list_emulators_skips_broken_files(running: tuple[Path, set[int]]) -> None:
    directory, alive = running
    (directory / "pid_400.ini").write_text("port.serial=5554\n")  # no grpc.port
    (directory / "pid_x.ini").write_text("port.serial=5554\ngrpc.port=1\n")
    (directory / "pid_401.ini").write_text("grpc.port=8554\n")  # no console
    alive.update({400, 401})
    assert list_emulators([directory, directory / "missing"]) == []


def test_pid_alive_rejects_dead_and_foreign_processes() -> None:
    assert not support._pid_alive(0)
    assert not support._pid_alive(2**22 + 12345)  # no such process
    # A live pid that is not an emulator (pid reuse after a kill).
    assert not support._pid_alive(__import__("os").getpid())


def test_layout_safe_and_to_native() -> None:
    assert layout_safe("Hello world 123.,")
    assert not layout_safe("zoo")  # y/z swap on German guests
    assert not layout_safe("a-b")
    assert not layout_safe("Größe")
    assert to_native(10, 20, 0, 1080, 2400) == (10, 20)
    assert to_native(10, 20, 1, 1080, 2400) == (1059, 10)
    assert to_native(10, 20, 2, 1080, 2400) == (1069, 2379)
    assert to_native(10, 20, 3, 1080, 2400) == (20, 2389)


# ---------------------------------------------------------------------------
# Service fakes
# ---------------------------------------------------------------------------

_CANCEL = object()


class FakeStream:
    def __init__(self, width: int, height: int) -> None:
        self.size = (width, height)
        self.q: queue.Queue[Any] = queue.Queue()
        self.bad_messages = 0

    def __iter__(self):
        while True:
            item = self.q.get()
            if item is _CANCEL:
                raise ScreenRpcError("cancelled", "CANCELLED")
            if isinstance(item, ScreenRpcError):
                raise item
            yield item

    def cancel(self) -> None:
        self.q.put(_CANCEL)

    def frame(self, width: int = 4, height: int = 8, rotation: int = 0) -> None:
        self.q.put(RawImage(bytes(width * height * 3), width, height, rotation, 1, 0))


class FakeClient:
    def __init__(self, endpoint: EmulatorEndpoint, status_error: Exception | None):
        self.endpoint = endpoint
        self.status_error = status_error
        self.streams: list[FakeStream] = []
        self.events: list[tuple[Any, ...]] = []
        self.closed = False

    def status(self) -> Any:
        if self.status_error is not None:
            raise self.status_error
        return types.SimpleNamespace(
            native_w=1080, native_h=2400, density=420, version="35.4.9"
        )

    def stream(self, width: int, height: int) -> FakeStream:
        stream = FakeStream(width, height)
        self.streams.append(stream)
        return stream

    def touch(self, x: int, y: int, pressure: int) -> None:
        self.events.append(("touch", x, y, pressure))

    def key(self, name: str, event: str = "keypress") -> None:
        self.events.append(("key", name))

    def paste(self, text: str, settle: float = 0.4) -> None:
        self.events.append(("paste", text))

    def close(self) -> None:
        self.closed = True


class FakeManager:
    def __init__(self, device: Any = None) -> None:
        self.active_device = device
        self.callbacks: list[Any] = []

    def on_device_change(self, callback: Any) -> None:
        self.callbacks.append(callback)

    def switch(self, device: Any) -> None:
        self.active_device = device
        for callback in self.callbacks:
            callback(device)


class FakeSink:
    def __init__(self) -> None:
        self.frames: list[Any] = []
        self.sizes: list[tuple[int, int, int]] = []
        self.states: list[tuple[ScreenState, str]] = []
        self.fail_frames = False

    def push_frame(self, frame: Any) -> None:
        self.frames.append(frame)
        if self.fail_frames:
            raise RuntimeError("sink broke")

    def set_device_size(self, width: int, height: int, rotation: int) -> None:
        self.sizes.append((width, height, rotation))

    def set_state(self, state: ScreenState, detail: str) -> None:
        self.states.append((state, detail))


def _emu(serial: str = "emulator-5554") -> Any:
    return types.SimpleNamespace(serial=serial, is_emulator=True)


def _wait(predicate: Any, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached in time")
        time.sleep(0.005)


class Rig:
    """A service wired to fakes; ``clients`` collects every opened client."""

    def __init__(self, device: Any = None, status_error: Exception | None = None):
        self.manager = FakeManager(device)
        self.clients: list[FakeClient] = []
        self.status_error = status_error
        self.missing: set[str] = set()
        self.tokens: dict[str, str] = {}
        self.sink = FakeSink()
        self.svc = DeviceScreenService(
            finder=self.find, opener=self.open, device_manager=lambda: self.manager
        )

    def find(self, serial: str) -> EmulatorEndpoint:
        if serial in self.missing:
            raise LookupError(f"no endpoint for {serial}")
        port = int(serial.split("-")[1])
        return EmulatorEndpoint(
            port, port + 3000, token=self.tokens.get(serial, "t"), pid=port
        )

    def open(self, endpoint: EmulatorEndpoint) -> FakeClient:
        client = FakeClient(endpoint, self.status_error)
        self.clients.append(client)
        return client

    def start(self, px: tuple[int, int] = (540, 1200)) -> None:
        self.svc.attach(self.sink)
        self.svc.set_visible(True, px)

    def wait_state(self, state: ScreenState) -> None:
        _wait(lambda: self.svc.state is state)

    def live_stream(self) -> FakeStream:
        _wait(lambda: self.clients and self.clients[-1].streams)
        return self.clients[-1].streams[-1]


@pytest.fixture
def rig() -> Any:
    rigs: list[Rig] = []

    def make(device: Any = None, **kw: Any) -> Rig:
        r = Rig(device, **kw)
        rigs.append(r)
        return r

    yield make
    for r in rigs:
        r.svc.close()


# ---------------------------------------------------------------------------
# Service: states
# ---------------------------------------------------------------------------


def test_service_is_cheap_until_used() -> None:
    svc = DeviceScreenService(device_manager=lambda: pytest.fail("not yet"))
    assert svc.state is ScreenState.OFF
    assert svc._link_thread is None
    assert svc._input_thread is None
    svc.close()
    svc.close()  # idempotent


def test_no_extra_when_grpc_cannot_be_imported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "grpc", None)  # import grpc -> ImportError
    monkeypatch.delitem(
        sys.modules, "sandroid.core.emulator_grpc.client", raising=False
    )
    manager = FakeManager(_emu())
    svc = DeviceScreenService(device_manager=lambda: manager)
    sink = FakeSink()
    try:
        svc.attach(sink)
        svc.set_visible(True, (540, 1200))
        _wait(lambda: svc.state is ScreenState.NO_EXTRA)
        assert sink.states[-1][0] is ScreenState.NO_EXTRA
    finally:
        svc.close()


def test_states_follow_the_device(rig: Any) -> None:
    r = rig(None)
    r.start()
    r.wait_state(ScreenState.NO_DEVICE)
    r.manager.switch(types.SimpleNamespace(serial="ABC123", is_emulator=False))
    r.wait_state(ScreenState.PHYSICAL)
    r.missing.add("emulator-5556")
    r.manager.switch(_emu("emulator-5556"))
    r.wait_state(ScreenState.NEEDS_GRPC)
    assert r.svc.serial == "emulator-5556"
    r.svc.set_visible(False, (0, 0))
    r.wait_state(ScreenState.OFF)


def test_live_frames_reach_the_sink(rig: Any) -> None:
    r = rig(_emu())
    r.start((540, 1200))
    stream = r.live_stream()
    assert stream.size == (540, 1200)
    assert r.sink.sizes[-1] == (1080, 2400, 0)  # sent on connect
    stream.frame(4, 8)
    r.wait_state(ScreenState.LIVE)
    _wait(lambda: r.sink.frames)
    frame = r.sink.frames[-1]
    assert frame.pixels.shape == (8, 4, 3)
    assert not frame.pixels.flags.writeable  # a view into the message
    assert (frame.device_w, frame.device_h, frame.rotation) == (1080, 2400, 0)
    # Rotation: device size swaps and the sink hears about it.
    stream.frame(8, 4, rotation=1)
    _wait(lambda: len(r.sink.frames) == 2)
    assert r.sink.sizes[-1] == (2400, 1080, 1)
    assert (r.sink.frames[-1].device_w, r.sink.frames[-1].device_h) == (2400, 1080)


def test_resize_restarts_the_stream_with_a_new_generation(rig: Any) -> None:
    r = rig(_emu())
    r.start((540, 1200))
    first = r.live_stream()
    first.frame()
    _wait(lambda: r.sink.frames)
    gen1 = r.sink.frames[-1].generation
    r.svc.set_visible(True, (540, 1200))  # same size: no restart
    r.svc.set_visible(True, (300, 700))
    _wait(lambda: len(r.clients[-1].streams) == 2)
    second = r.clients[-1].streams[-1]
    assert second.size == (300, 700)
    assert len(r.clients) == 1  # same channel
    second.frame()
    _wait(lambda: len(r.sink.frames) == 2)
    assert r.sink.frames[-1].generation > gen1
    r.svc.set_visible(True, (5000, 5000))  # capped to the device
    _wait(lambda: len(r.clients[-1].streams) == 3)
    assert r.clients[-1].streams[-1].size == (1080, 2400)


def test_sink_errors_never_kill_the_stream(rig: Any) -> None:
    r = rig(_emu())
    r.sink.fail_frames = True
    r.start()
    stream = r.live_stream()
    stream.frame()
    stream.frame()
    _wait(lambda: len(r.sink.frames) == 2)
    assert r.svc._link_thread is not None
    assert r.svc._link_thread.is_alive()


def test_auth_error_is_a_state_not_a_retry_loop(rig: Any) -> None:
    r = rig(_emu(), status_error=ScreenRpcError("auth", "UNAUTHENTICATED"))
    r.start()
    r.wait_state(ScreenState.AUTH_ERROR)
    time.sleep(0.3)
    assert len(r.clients) == 1  # no endless retries on the same endpoint
    assert r.clients[0].closed
    # The emulator restarted with a new token: try again.
    r.status_error = None
    r.tokens["emulator-5554"] = "fresh"
    r.svc.set_visible(False, (0, 0))
    r.svc.set_visible(True, (540, 1200))
    r.live_stream().frame()
    r.wait_state(ScreenState.LIVE)


def test_lost_stream_rediscovers_and_says_gone(rig: Any) -> None:
    r = rig(_emu())
    r.start()
    stream = r.live_stream()
    stream.frame()
    r.wait_state(ScreenState.LIVE)
    r.missing.add("emulator-5554")  # killed: its discovery file is stale
    stream.q.put(ScreenRpcError("unavailable", "UNAVAILABLE"))
    r.wait_state(ScreenState.GONE)
    assert r.clients[0].closed
    assert r.svc.stats["reconnects"] == 1
    # It comes back (new pid/token): reconnect.
    r.missing.clear()
    r.svc.set_visible(True, (541, 1200))  # any wake-up
    _wait(lambda: len(r.clients) == 2)


def test_disconnect_of_the_followed_emulator_is_gone(rig: Any) -> None:
    r = rig(_emu())
    r.start()
    r.live_stream().frame()
    r.wait_state(ScreenState.LIVE)
    r.manager.switch(None)
    r.wait_state(ScreenState.GONE)


# ---------------------------------------------------------------------------
# Service: input
# ---------------------------------------------------------------------------


def _connected(rig: Any) -> Rig:
    r = rig(_emu())
    r.start()
    r.live_stream()
    return r


def test_touch_down_move_up(rig: Any) -> None:
    r = _connected(rig)
    client = r.clients[-1]
    assert r.svc.touch("move", 1, 1) is None  # no finger down: ignored
    assert r.svc.touch("down", 100, 200) is None
    r.svc.touch("move", 110, 210)
    r.svc.touch("up", 120, 220)
    _wait(lambda: len(client.events) == 3)
    assert client.events == [
        ("touch", 100, 200, 1024),
        ("touch", 110, 210, 1024),
        ("touch", 120, 220, 0),
    ]


def test_wheel_is_a_held_drag_released_after_idle(rig: Any) -> None:
    r = _connected(rig)
    client = r.clients[-1]
    assert r.svc.wheel(540, 1200, +1) is None
    _wait(lambda: len(client.events) == 3)  # down, move, then the idle up
    # density 420 -> 64 dp = 168 px; first move adds 8 dp touch slop (21 px)
    assert client.events == [
        ("touch", 540, 1200, 1024),
        ("touch", 540, 1011, 1024),
        ("touch", 540, 1011, 0),
    ]
    client.events.clear()
    r.svc.wheel(540, 1200, -1)
    r.svc.wheel(540, 1200, -1)  # second notch continues the same drag
    _wait(lambda: client.events and client.events[-1][3] == 0)
    downs = [e for e in client.events if e[3] == 1024]
    ups = [e for e in client.events if e[3] == 0]
    assert len(ups) == 1
    assert downs[0][2] == 1200
    assert downs[-1][2] > downs[0][2]


def test_wheel_is_ignored_during_a_real_drag(rig: Any) -> None:
    r = _connected(rig)
    client = r.clients[-1]
    r.svc.touch("down", 10, 10)
    r.svc.wheel(540, 1200, +1)
    r.svc.touch("up", 10, 10)
    _wait(lambda: len(client.events) == 2)
    time.sleep(0.2)
    assert client.events == [("touch", 10, 10, 1024), ("touch", 10, 10, 0)]


def test_locked_policy_refuses_everything_but_lift(rig: Any) -> None:
    r = _connected(rig)
    client = r.clients[-1]
    r.svc.touch("down", 50, 60)
    reason = "input is locked while a replay runs"
    r.svc.set_input_policy(locked=reason, allow_clipboard=True)
    # Locking lifts the held finger.
    _wait(lambda: ("touch", 50, 60, 0) in client.events)
    assert r.svc.touch("down", 1, 1) == reason
    assert r.svc.touch("up", 1, 1) == reason
    assert r.svc.wheel(1, 1, 1) == reason
    assert r.svc.key("GoBack") == reason
    assert r.svc.text("abc") == reason
    assert r.svc.paste("abc") == reason
    assert r.svc.lift() is None
    r.svc.set_input_policy(locked=None, allow_clipboard=True)
    assert r.svc.key("GoHome") is None
    _wait(lambda: client.events[-1] == ("key", "GoHome"))


def test_clipboard_policy(rig: Any) -> None:
    r = _connected(rig)
    client = r.clients[-1]
    r.svc.set_input_policy(locked=None, allow_clipboard=False)
    assert r.svc.paste("hello") == DeviceScreenService.CLIPBOARD_OFF_PASTE
    assert r.svc.text("Größe") == DeviceScreenService.CLIPBOARD_OFF_TEXT
    assert r.svc.text("zap") == DeviceScreenService.CLIPBOARD_OFF_TEXT
    long_safe = "abcdefghij " * 3  # > 24 chars: typed, never pasted
    assert r.svc.text(long_safe) is None
    _wait(lambda: len(client.events) == len(long_safe))
    assert all(e[0] == "key" for e in client.events)
    assert "".join(e[1] for e in client.events) == long_safe
    # With the clipboard: unsafe or long text is pasted, short safe typed.
    r.svc.set_input_policy(locked=None, allow_clipboard=True)
    client.events.clear()
    r.svc.text("Größe")
    r.svc.text(long_safe)
    r.svc.text("ok")
    r.svc.paste("hi")
    _wait(lambda: len(client.events) == 6)
    assert client.events == [
        ("paste", "Größe"),
        ("paste", long_safe),
        ("key", "o"),
        ("key", "k"),
        ("key", "h"),
        ("key", "i"),
    ]


def test_device_switch_lifts_and_bumps_the_generation(rig: Any) -> None:
    r = _connected(rig)
    old = r.clients[-1]
    old.streams[-1].frame()
    _wait(lambda: r.sink.frames)
    gen = r.svc._generation
    r.svc.touch("down", 100, 200)
    _wait(lambda: old.events == [("touch", 100, 200, 1024)])
    r.manager.switch(_emu("emulator-5556"))
    _wait(lambda: old.closed)
    assert old.events[-1] == ("touch", 100, 200, 0)  # the lift reached it first
    assert r.svc._generation > gen
    _wait(lambda: len(r.clients) == 2)
    new = r.clients[-1]
    assert new.endpoint.console_port == 5556
    assert r.svc.serial == "emulator-5556"
    # Input of the old epoch never reaches the new device.
    r.svc.touch("up", 100, 200)  # no finger down any more: ignored
    time.sleep(0.1)
    assert new.events == []


def test_hide_lifts_then_closes_the_channel(rig: Any) -> None:
    r = _connected(rig)
    client = r.clients[-1]
    r.svc.touch("down", 5, 6)
    r.svc.set_visible(False, (0, 0))
    _wait(lambda: client.closed)
    assert client.events == [("touch", 5, 6, 1024), ("touch", 5, 6, 0)]
    r.wait_state(ScreenState.OFF)


def test_close_is_idempotent_and_stops_threads(rig: Any) -> None:
    r = _connected(rig)
    client = r.clients[-1]
    r.svc.close()
    r.svc.close()
    _wait(lambda: client.closed)
    link, inp = r.svc._link_thread, r.svc._input_thread
    assert link is not None
    assert inp is not None
    link.join(2)
    inp.join(2)
    assert not link.is_alive()
    assert not inp.is_alive()
    assert r.svc.touch("down", 1, 1) is None  # a no-op after close


def test_stale_key_repeats_are_dropped(rig: Any) -> None:
    r = _connected(rig)
    client = r.clients[-1]
    block = threading.Event()
    original = client.paste

    def slow_paste(text: str, settle: float = 0.4) -> None:
        block.wait(2)
        original(text)

    client.paste = slow_paste  # type: ignore[method-assign]
    r.svc.text("Größe")  # occupies the input thread
    for _ in range(5):
        r.svc.key("Backspace")
    r.svc.key("Enter")
    time.sleep(DeviceScreenService.STALE_REPEAT_S + 0.1)
    block.set()
    _wait(lambda: client.events and client.events[-1] == ("key", "Enter"))
    assert ("key", "Backspace") not in client.events


# ---------------------------------------------------------------------------
# Launch hook
# ---------------------------------------------------------------------------


def _context(port: int | None = 5554, extra: tuple[str, ...] = ()) -> Any:
    return emulator.LaunchContext(
        avd="Dev",
        avd_dir=Path("/nonexistent/Dev.avd"),
        port=port,
        options=emulator.AvdLaunchOptions(extra_args=extra),
    )


@pytest.fixture
def hook_env(monkeypatch: pytest.MonkeyPatch) -> set[int]:
    """Pretend grpc is installed and config on; returned ports are busy."""
    busy: set[int] = set()
    monkeypatch.setattr(egrpc, "grpc_available", lambda: True)
    monkeypatch.setattr(egrpc, "_grpc_on_launch", lambda: True)
    monkeypatch.setattr(emulator, "_port_bindable", lambda port: port not in busy)
    monkeypatch.setattr(emulator, "_HOOKS", {"pre_launch": [], "post_stop": []})
    return busy


def test_hook_adds_grpc_flags(hook_env: set[int]) -> None:
    context = _context()
    assert egrpc.pre_launch(context) == ("-grpc", "8554", "-grpc-use-token")
    assert context.record[egrpc.RECORD_KEY] == 8554


def test_hook_probes_upward_for_a_free_port(hook_env: set[int]) -> None:
    hook_env.update({8554, 8555})
    assert egrpc.pre_launch(_context()) == ("-grpc", "8556", "-grpc-use-token")
    hook_env.update(range(8554, 8554 + egrpc.GRPC_PORT_PROBES))
    assert egrpc.pre_launch(_context()) == ()


@pytest.mark.parametrize(
    "extra",
    [
        ("-grpc", "8600"),
        ("-no-audio", "-grpc", "8600", "-grpc-use-token"),
        ("-grpc-use-jwt",),
    ],
)
def test_hook_skips_when_grpc_is_already_configured(
    hook_env: set[int], extra: tuple[str, ...]
) -> None:
    assert egrpc.pre_launch(_context(extra=extra)) == ()


def test_hook_skips_without_port_extra_or_config(
    hook_env: set[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert egrpc.pre_launch(_context(port=None)) == ()
    monkeypatch.setattr(egrpc, "grpc_available", lambda: False)
    assert egrpc.pre_launch(_context()) == ()
    monkeypatch.setattr(egrpc, "grpc_available", lambda: True)
    monkeypatch.setattr(egrpc, "_grpc_on_launch", lambda: False)
    assert egrpc.pre_launch(_context()) == ()


def test_hook_reads_the_config_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    from sandroid.config import get_config

    monkeypatch.setattr(egrpc, "grpc_available", lambda: True)
    monkeypatch.setattr(emulator, "_port_bindable", lambda port: True)
    screen = get_config().tui.device_screen
    assert screen.grpc_on_launch is True
    assert egrpc.pre_launch(_context()) != ()
    monkeypatch.setattr(screen, "grpc_on_launch", False)
    assert egrpc.pre_launch(_context()) == ()


def test_grpc_available_finds_specs_without_importing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "grpc", None)
    assert egrpc.grpc_available() is False


def test_hook_never_raises_and_never_aborts_a_launch(
    hook_env: set[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(port: int) -> int:
        raise RuntimeError("port probe broke")

    monkeypatch.setattr(egrpc, "pick_grpc_port", boom)
    assert egrpc.pre_launch(_context()) == ()
    assert egrpc.pre_launch(object()) == ()  # type: ignore[arg-type]
    egrpc.install_launch_hooks()
    egrpc.install_launch_hooks()  # idempotent
    assert emulator._HOOKS["pre_launch"] == [egrpc.pre_launch]
    assert emulator._run_pre_launch_hooks(_context()) == ()  # no EmulatorLaunchError
    egrpc.uninstall_launch_hooks()
    assert emulator._HOOKS["pre_launch"] == []


def test_restart_strips_our_flags_but_keeps_outside_ones(hook_env: set[int]) -> None:
    cmdline = ["emulator", "-avd", "Dev", "-port", "5554"]
    ours = ("-grpc", "8554", "-grpc-use-token")
    # Our launch: the remembered hook args are stripped, the hook adds afresh.
    options = emulator.options_from_cmdline([*cmdline, *ours], "Dev", ours)
    assert options is not None
    assert not egrpc._has_grpc_flag(options.extra_args)
    # Started outside Sandroid with its own -grpc: kept, and the hook skips.
    options = emulator.options_from_cmdline([*cmdline, "-grpc", "9000"], "Dev")
    assert options is not None
    assert "-grpc" in options.extra_args
    context = emulator.LaunchContext(
        avd="Dev", avd_dir=Path("/x"), port=5554, options=options
    )
    assert egrpc.pre_launch(context) == ()


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_device_screen_config_defaults_and_backend() -> None:
    cfg = TUIConfig().device_screen
    assert (cfg.grpc_on_launch, cfg.max_fps, cfg.bezel, cfg.touch_marker) == (
        True,
        60,
        True,
        True,
    )
    assert cfg.backend == "auto"
    assert DeviceScreenConfig(backend="Kitty").backend == "kitty"
    with pytest.raises(ValueError):
        DeviceScreenConfig(backend="vnc")
    with pytest.raises(ValueError):
        DeviceScreenConfig(max_fps=0)


def test_service_module_imports_without_grpc() -> None:
    # The service module and the support module never import grpc themselves.
    assert dss.DeviceScreenService is DeviceScreenService
    assert "grpc" not in support.__dict__
