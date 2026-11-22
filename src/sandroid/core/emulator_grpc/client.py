"""Emulator gRPC client: screen stream and input (needs the ``screen`` extra).

Imports grpcio and protobuf at module level, so import this module lazily
(``sandroid.services.device_screen_service`` does) and treat any import
error as "the extra is not installed".

Only works when the emulator was started with ``-grpc <port>`` (Sandroid
adds ``-grpc <port> -grpc-use-token`` to every emulator it launches); an
emulator without it exposes no endpoint and writes no discovery file.

Transport: pixels inside each gRPC message (``ImageTransport.MMAP`` crashes
emulator 35.4.9 on macOS arm64 and is not used).
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

# Both must be set before grpc is imported (gRPC core reads them at init).
# grpc logs to stderr, where Textual draws its UI: errors arrive as status
# codes, so nothing needs to be printed.
os.environ.setdefault("GRPC_VERBOSITY", "NONE")
# gRPC core's fork handlers are on by default in grpcio wheels. Sandroid
# forks adb/emulator subprocesses all the time: with the handlers on, every
# fork logs, forks run ~2.4x slower (measured 204/s vs 465/s), and a fork
# during stream activity aborted the child before exec ("Check failed:
# wakeup_fd_->ConsumeWakeup().ok()" from an adb call). The children exec
# right away and never use gRPC, so the handlers are not needed.
os.environ.setdefault("GRPC_ENABLE_FORK_SUPPORT", "0")

import grpc
from google.protobuf import empty_pb2

from . import emulator_controller_pb2 as pb
from . import emulator_controller_pb2_grpc as pbg
from .support import (
    EmulatorEndpoint,
    RawImage,
    RpcErrorKind,
    ScreenRpcError,
    parse_image,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

#: Localhost frame stream: lift the 4 MiB receive cap (1080 px RGB888 is
#: 7.9 MB), compression off, no transparent retries (we reconnect).
CHANNEL_OPTIONS = [
    ("grpc.max_receive_message_length", 64 * 1024 * 1024),
    ("grpc.default_compression_algorithm", 0),
    ("grpc.enable_retries", 0),
]

STREAM_METHOD = "/android.emulation.control.EmulatorController/streamScreenshot"

#: Timeout of one input RPC (unary sendTouch is 0.3-1.4 ms on a warm channel).
RPC_TIMEOUT = 2.0
#: Timeout of getStatus (the connect / liveness round trip).
STATUS_TIMEOUT = 5.0

_AUTH_CODES = frozenset(
    {
        grpc.StatusCode.UNAUTHENTICATED,
        grpc.StatusCode.UNIMPLEMENTED,
        grpc.StatusCode.PERMISSION_DENIED,
    }
)
_UNAVAILABLE_CODES = frozenset(
    {grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED}
)


def wrap_rpc_error(exc: grpc.RpcError) -> ScreenRpcError:
    """The grpc-free :class:`ScreenRpcError` for ``exc``."""
    code_fn = getattr(exc, "code", None)
    details_fn = getattr(exc, "details", None)
    code = code_fn() if callable(code_fn) else None
    details = (details_fn() if callable(details_fn) else "") or ""
    kind: RpcErrorKind
    if code in _AUTH_CODES:
        kind = "auth"
    elif code in _UNAVAILABLE_CODES:
        kind = "unavailable"
    elif code == grpc.StatusCode.CANCELLED:
        kind = "cancelled"
    else:
        kind = "other"
    name = code.name if code is not None else type(exc).__name__
    return ScreenRpcError(kind, name, details)


@dataclass(frozen=True)
class DeviceInfo:
    """What ``getStatus`` says about the emulator's display."""

    native_w: int
    native_h: int
    density: int
    version: str


def _image_from_protobuf(buf: bytes | memoryview) -> RawImage | None:
    """Slow fallback decode through the protobuf runtime (copies)."""
    try:
        msg = pb.Image.FromString(bytes(buf))
    except Exception:
        return None
    data = msg.image
    width, height = msg.format.width, msg.format.height
    bpp = {pb.ImageFormat.RGB888: 3, pb.ImageFormat.RGBA8888: 4}.get(msg.format.format)
    if not data or bpp is None or len(data) != width * height * bpp:
        return None
    return RawImage(
        pixels=data,
        width=width,
        height=height,
        rotation=int(msg.format.rotation.rotation) % 4,
        seq=msg.seq,
        ts_us=msg.timestampUs,
        bpp=bpp,
    )


class FrameStream:
    """One ``streamScreenshot`` call: iterate for frames, cancel from any thread.

    The emulator only sends a frame when the display changes. Iteration
    raises :class:`ScreenRpcError` (kind ``cancelled`` after :meth:`cancel`).
    """

    def __init__(self, call: Any) -> None:
        self._call = call
        self.bad_messages = 0

    def __iter__(self) -> Iterator[RawImage]:
        try:
            for raw in self._call:
                try:
                    image = parse_image(raw)
                except ValueError:
                    self.bad_messages += 1
                    image = _image_from_protobuf(raw)
                if image is not None:
                    yield image
        except grpc.RpcError as exc:
            raise wrap_rpc_error(exc) from None

    def cancel(self) -> None:
        """Cancel the call (thread-safe, never blocks)."""
        try:
            self._call.cancel()
        except Exception:
            pass


class EmulatorClient:
    """One channel to one emulator: screen stream + input RPCs.

    Thread-safe (gRPC channels are): the stream thread iterates a
    :class:`FrameStream` while the input thread sends unary RPCs. Every
    RPC failure is raised as :class:`ScreenRpcError`. Input coordinates
    are native portrait px (see ``support.to_native``).
    """

    TOUCH_ID = 1

    def __init__(self, endpoint: EmulatorEndpoint) -> None:
        self.endpoint = endpoint
        self._channel = grpc.insecure_channel(
            f"127.0.0.1:{endpoint.grpc_port}", options=CHANNEL_OPTIONS
        )
        self._md: list[tuple[str, str]] = (
            [("authorization", f"Bearer {endpoint.token}")] if endpoint.token else []
        )
        self._stub = pbg.EmulatorControllerStub(self._channel)
        self._stream = self._channel.unary_stream(
            STREAM_METHOD,
            request_serializer=pb.ImageFormat.SerializeToString,
            response_deserializer=None,  # raw bytes -> parse_image
        )
        self._closed = False
        self._close_lock = threading.Lock()

    def __repr__(self) -> str:
        ep = self.endpoint
        return f"EmulatorClient({ep.serial}, grpc=127.0.0.1:{ep.grpc_port})"

    # -- status / stream ------------------------------------------------
    def status(self) -> DeviceInfo:
        """``getStatus``: native display size and density (connect check)."""
        try:
            st = self._stub.getStatus(
                empty_pb2.Empty(), metadata=self._md, timeout=STATUS_TIMEOUT
            )
        except grpc.RpcError as exc:
            raise wrap_rpc_error(exc) from None
        cfg = {e.key: e.value for e in st.hardwareConfig.entry}

        def _num(key: str, default: int) -> int:
            try:
                return int(cfg.get(key, default))
            except ValueError:
                return default

        return DeviceInfo(
            native_w=_num("hw.lcd.width", 1080),
            native_h=_num("hw.lcd.height", 1920),
            density=_num("hw.lcd.density", 420),
            version=st.version or "",
        )

    def stream(self, width: int, height: int) -> FrameStream:
        """Start a frame stream fitted into ``width`` x ``height`` px.

        Both are set: emulator 35.4.9 ignores one without the other; with
        both it fits the frame into the box keeping the aspect ratio (the
        scaling runs on the host GPU, the client never resizes).
        """
        fmt = pb.ImageFormat(
            format=pb.ImageFormat.RGB888, width=int(width), height=int(height)
        )
        return FrameStream(self._stream(fmt, metadata=self._md))

    # -- input ------------------------------------------------------------
    def touch(self, x: int, y: int, pressure: int) -> None:
        """One touch event at native px (pressure 0 = finger up)."""
        event = pb.Touch(
            x=int(x),
            y=int(y),
            identifier=self.TOUCH_ID,
            pressure=int(pressure),
            touch_major=4 if pressure else 0,
        )
        self._call_unary(self._stub.sendTouch, pb.TouchEvent(touches=[event]))

    def key(self, name: str, event: str = "keypress") -> None:
        """A W3C key name (``GoBack``, ``Enter``, ``a``, ...).

        Args:
            name: Key name.
            event: ``keypress``, ``keydown`` or ``keyup``.
        """
        ev = pb.KeyboardEvent
        kind = {"keydown": ev.keydown, "keyup": ev.keyup}.get(event, ev.keypress)
        self._call_unary(self._stub.sendKey, ev(key=name, eventType=kind))

    def paste(self, text: str, settle: float = 0.4) -> None:
        """Paste through the guest clipboard + Ctrl+V (overwrites it).

        Blocks for the host->guest clipboard sync and the paste to land
        (keys sent right after Ctrl+V overtake it): input thread only.
        """
        self._call_unary(self._stub.setClipboard, pb.ClipData(text=text))
        time.sleep(0.15)
        self.key("Control", "keydown")
        try:
            self.key("v")
        finally:
            self.key("Control", "keyup")
        time.sleep(settle)

    def _call_unary(self, method: Any, request: Any) -> None:
        try:
            method(request, metadata=self._md, timeout=RPC_TIMEOUT)
        except grpc.RpcError as exc:
            raise wrap_rpc_error(exc) from None

    # -- lifecycle --------------------------------------------------------
    def close(self) -> None:
        """Close the channel (idempotent; cancels its open calls)."""
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        try:
            self._channel.close()
        except Exception:
            pass


def open_client(endpoint: EmulatorEndpoint) -> EmulatorClient:
    """A client for ``endpoint`` (no RPC yet; call ``status()`` to check)."""
    return EmulatorClient(endpoint)


__all__ = [
    "CHANNEL_OPTIONS",
    "RPC_TIMEOUT",
    "STATUS_TIMEOUT",
    "DeviceInfo",
    "EmulatorClient",
    "FrameStream",
    "open_client",
    "wrap_rpc_error",
]
