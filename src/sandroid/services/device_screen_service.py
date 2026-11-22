"""Live device screen: the contract between the stream service and the TUI.

The device screen column (Ctrl+G) shows the emulator's screen live and sends
mouse and keyboard input back. Frames and input go over the emulator's gRPC
API (``sandroid.core.emulator_grpc``), which needs the optional ``screen``
extra (grpcio, protobuf) and an emulator started with ``-grpc <port>
-grpc-use-token`` (Sandroid adds both to every emulator it launches).

This module must import without grpcio: everything that needs it is imported
lazily inside the service.

Thread contract:
    * The service's stream thread calls the attached :class:`DeviceScreenSink`.
      Sink methods must not block and must be thread-safe; the TUI sink
      marshals to the UI thread with ``post_message`` (never
      ``call_from_thread``, which deadlocks when the UI thread is waiting).
    * The input methods (``touch``/``wheel``/``key``/``text``/``paste``/
      ``lift``) are called on the UI thread. They only check the input policy
      and enqueue; one ordered input thread sends the RPCs. They never block.
    * ``set_visible`` / ``attach`` / ``set_input_policy`` / ``close`` are
      called on the UI thread and never block (joins happen off-thread).
    * Device switches come from ``DeviceManager.on_device_change`` (UI thread
      or the poll thread). The service registers once, through a weak
      reference, lifts a held touch, stops the old stream and drops frames of
      the old stream by generation.

Coordinates: ``touch``/``wheel`` take device pixels in the CURRENT orientation
(what the user sees, as given by the last ``set_device_size``). The service
converts them to the emulator's native portrait space using the rotation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Literal, Protocol

if TYPE_CHECKING:
    import numpy as np


# ---------------------------------------------------------------------------
# Contract (shared by the service and the TUI; change only together)
# ---------------------------------------------------------------------------


class ScreenState(str, Enum):
    """Where the live screen stands. The TUI shows :func:`status_text`."""

    OFF = "off"  # column hidden / main screen covered: no stream
    NO_EXTRA = "no-extra"  # grpcio/protobuf not installed
    NO_DEVICE = "no-device"  # no active device
    PHYSICAL = "physical"  # active device is not an emulator
    NEEDS_GRPC = "needs-grpc"  # emulator without a gRPC endpoint
    CONNECTING = "connecting"  # endpoint found, connecting / (re)starting
    LIVE = "live"  # frames are arriving
    AUTH_ERROR = "auth-error"  # UNAUTHENTICATED / UNIMPLEMENTED: no retries
    GONE = "gone"  # the emulator went away (killed, switched off)


_STATUS_WORDS: dict[ScreenState, str] = {
    ScreenState.OFF: "off",
    ScreenState.NO_EXTRA: "install sandroid[screen]",
    ScreenState.NO_DEVICE: "no device",
    ScreenState.PHYSICAL: "needs an emulator started by Sandroid",
    ScreenState.NEEDS_GRPC: "needs an emulator started by Sandroid",
    ScreenState.CONNECTING: "connecting",
    ScreenState.LIVE: "live",
    ScreenState.AUTH_ERROR: "emulator refused the connection",
    ScreenState.GONE: "emulator gone",
}


def status_text(state: ScreenState, detail: str = "") -> str:
    """Plain-words status line, e.g. ``"live · 30 fps"`` or ``"emulator gone"``.

    Args:
        state: Current state.
        detail: Optional short suffix (the TUI passes ``"30 fps"`` while live).
    """
    words = _STATUS_WORDS.get(state, str(state.value))
    return f"{words} · {detail}" if detail else words


@dataclass(frozen=True, slots=True)
class ScreenFrame:
    """One screen image from the stream.

    Attributes:
        pixels: ``H x W x 3`` uint8 RGB, rows top-down, already in the current
            orientation; may be a read-only view (do not write to it).
        device_w: Device width in px in the current orientation.
        device_h: Device height in px in the current orientation.
        rotation: 0..3 quarter turns (0 = portrait), from the emulator.
        recv: ``time.monotonic()`` when the host received the frame.
        generation: Stream generation; bumps on every restart / device switch.
    """

    pixels: np.ndarray
    device_w: int
    device_h: int
    rotation: int
    recv: float
    generation: int


class DeviceScreenSink(Protocol):
    """What the service calls (from its stream thread). Must not block."""

    def push_frame(self, frame: ScreenFrame) -> None:
        """A new frame (latest wins; the sink may drop frames)."""
        ...

    def set_device_size(self, width: int, height: int, rotation: int) -> None:
        """Device size in px in the current orientation (on connect/rotation)."""
        ...

    def set_state(self, state: ScreenState, detail: str) -> None:
        """State changed; ``detail`` is a short technical note for the log."""
        ...


TouchAction = Literal["down", "move", "up"]


class DeviceScreenServiceProtocol(Protocol):
    """The live screen service the TUI talks to (UI thread only).

    Input methods return ``None`` when the input was queued, or a short
    plain-words reason when it was refused (shown as a one-line hint), e.g.
    ``"input is locked while a replay runs"``.
    """

    @property
    def state(self) -> ScreenState:
        """Current state."""
        ...

    @property
    def serial(self) -> str | None:
        """Serial the service follows (the active device), or None."""
        ...

    def attach(self, sink: DeviceScreenSink | None) -> None:
        """Attach the one sink (None detaches). Re-sends size and state."""
        ...

    def set_visible(self, visible: bool, panel_px: tuple[int, int]) -> None:
        """Stream only while visible, at ``panel_px`` (screen-rect px, w x h).

        Idempotent; call again with a new size on resize/rotation. Hidden =
        lift any held touch, stop the stream, state OFF.
        """
        ...

    def set_input_policy(self, *, locked: str | None, allow_clipboard: bool) -> None:
        """``locked``: reason all input is refused (replay running), or None.

        ``allow_clipboard=False`` (Tracking/Record active): never touch the
        guest clipboard; text that is not layout-safe is refused.
        """
        ...

    def touch(self, action: TouchAction, x: int, y: int) -> str | None:
        """Live pointer stream in device px (current orientation)."""
        ...

    def wheel(self, x: int, y: int, dy: int) -> str | None:
        """One wheel notch (+1 = content scrolls up / finger moves up).

        The service turns notches into a held drag and lifts it after a short
        idle (no fling), staying clear of the status bar and gesture zones.
        """
        ...

    def key(self, name: str) -> str | None:
        """W3C key name: ``GoBack``, ``GoHome``, ``AppSwitch``, ``Enter``, ..."""
        ...

    def text(self, text: str) -> str | None:
        """Typed text: layout-safe chars as key events, else the clipboard."""
        ...

    def paste(self, text: str) -> str | None:
        """Bracketed paste: the clipboard + Ctrl+V (refused without clipboard)."""
        ...

    def lift(self) -> None:
        """Release any held touch or wheel drag (blur, hide, modal, unmount)."""
        ...

    def close(self) -> None:
        """Stop all threads and the channel (app exit). Idempotent."""
        ...


__all__ = [
    "DeviceScreenServiceProtocol",
    "DeviceScreenSink",
    "ScreenFrame",
    "ScreenState",
    "TouchAction",
    "status_text",
]

# ---------------------------------------------------------------------------
# Implementation (DeviceScreenService) goes below this line.
# ---------------------------------------------------------------------------

import logging
import queue
import threading
import time
import weakref
from collections.abc import Callable, Iterator
from dataclasses import field
from typing import Any

from sandroid.core.emulator_grpc.support import (
    EmulatorEndpoint,
    RawImage,
    ScreenRpcError,
    find_emulator,
    layout_safe,
    to_native,
)

logger = logging.getLogger(__name__)


class _StreamLike(Protocol):
    """What the service needs from a frame stream (``client.FrameStream``)."""

    bad_messages: int

    def __iter__(self) -> Iterator[RawImage]: ...

    def cancel(self) -> None: ...


class _ClientLike(Protocol):
    """What the service needs from a client (``client.EmulatorClient``)."""

    endpoint: EmulatorEndpoint

    def status(self) -> Any: ...

    def stream(self, width: int, height: int) -> _StreamLike: ...

    def touch(self, x: int, y: int, pressure: int) -> None: ...

    def key(self, name: str, event: str = "keypress") -> None: ...

    def paste(self, text: str, settle: float = 0.4) -> None: ...

    def close(self) -> None: ...


Finder = Callable[[str], EmulatorEndpoint]
Opener = Callable[[EmulatorEndpoint], _ClientLike]


def _import_opener() -> Opener:
    """The real client factory; raises when the ``screen`` extra is missing.

    Any failure counts (ImportError, protobuf/grpc version errors), so the
    state becomes NO_EXTRA instead of a crash.
    """
    import numpy

    from sandroid.core.emulator_grpc import client

    return client.open_client


def _default_device_manager() -> Any:
    from sandroid.core.device_manager import DeviceManager

    return DeviceManager.get()


#: Queue sentinel that stops the input thread.
_STOP = object()


@dataclass(slots=True)
class _Item:
    """One queued input action.

    ``client``: the client that was current when it was queued; it gets the
    item even when the link thread retires it right after (its ``close``
    is queued behind). None: the current client (input before connect).
    ``up_native`` / ``close`` always carry their client; ``up_native`` args
    are native px and it is sent even after a device switch (the lift).
    """

    kind: str
    args: tuple[Any, ...] = ()
    t: float = field(default_factory=time.monotonic)
    epoch: int = 0
    client: Any = None


class DeviceScreenService:
    """Live emulator screen + input over gRPC (implements the Protocol above).

    Two daemon threads, started on the first :meth:`attach` /
    :meth:`set_visible` (creating the service is cheap):

    * the link thread follows the active device, connects (the endpoint and
      its token are read fresh from the discovery file on every connect),
      streams frames while visible and calls the sink;
    * the input thread sends queued input in order (moves coalesced to at
      most 120 Hz, 4 ms key pacing, stale key repeats dropped, wheel drags
      released after a short idle) and closes retired channels, so a lift
      queued before a switch still reaches the old emulator.

    Args:
        finder: ``serial -> EmulatorEndpoint`` (default: discovery files).
        opener: ``endpoint -> client`` (default: the gRPC client; when it
            cannot be imported the state is NO_EXTRA).
        device_manager: Returns the DeviceManager (default the singleton).
    """

    MOVE_MIN_DT = 1 / 120  # live touch moves: at most 120 Hz
    REPEAT_KEYS = frozenset(
        {"Backspace", "Delete", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"}
    )
    STALE_REPEAT_S = 0.25  # drop held-key repeats that waited longer than this
    KEY_PACE_S = 0.004  # min gap between typed chars
    BURST_PASTE = 24  # text longer than this goes through the clipboard
    WHEEL_STEP_DP = 64  # finger travel per wheel notch
    WHEEL_IDLE_S = 0.12  # lift this long after the last notch (no fling)
    POLL_S = 2.0  # re-check discovery while waiting for an endpoint
    BACKOFF_MIN_S = 0.5
    BACKOFF_MAX_S = 5.0
    MIN_STREAM_PX = 64
    TOUCH_PRESSURE = 1024

    CLIPBOARD_OFF_PASTE = (
        "paste is off while recording (it would use the device clipboard)"
    )
    CLIPBOARD_OFF_TEXT = (
        "while recording only plain letters, digits, space, dot and comma can be typed"
    )

    def __init__(
        self,
        *,
        finder: Finder | None = None,
        opener: Opener | None = None,
        device_manager: Callable[[], Any] | None = None,
    ) -> None:
        self._finder: Finder = finder or find_emulator
        self._opener: Opener | None = opener
        self._opener_error = ""
        self._device_manager = device_manager or _default_device_manager
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._q: queue.Queue[Any] = queue.Queue()
        self._started = False
        self._closed = False
        self._link_thread: threading.Thread | None = None
        self._input_thread: threading.Thread | None = None
        # What the UI wants.
        self._sink: DeviceScreenSink | None = None
        self._visible = False
        self._panel_px = (540, 1200)
        self._locked: str | None = None
        self._allow_clipboard = True
        # The followed device.
        self._serial: str | None = None
        self._is_emulator = False
        self._epoch = 0  # bumps on every device switch
        self._seen_live = False  # connected to this device at least once
        self._gone = False  # the followed emulator disconnected
        # The connection (link thread).
        self._client: _ClientLike | None = None
        self._client_epoch = -1
        self._stream: _StreamLike | None = None
        self._stream_size: tuple[int, int] | None = None
        self._generation = 0  # bumps on every stream (re)start / cancel
        self._native = (1080, 1920)
        self._density = 420
        self._rotation = 0
        self._dev_size: tuple[int, int] | None = None
        self._state = ScreenState.OFF
        self._detail = ""
        # Input bookkeeping (UI thread, under the lock).
        self._touch: tuple[int, int] | None = None
        self._wheel: list[float] | None = None  # [x, y] of the held wheel drag
        self._wheel_deadline = 0.0
        self._sink_errors = 0
        self._fps_count = 0
        self._fps_t0 = time.monotonic()
        self._stats: dict[str, Any] = {
            "stream_fps": 0.0,
            "stream_frames": 0,
            "reconnects": 0,
            "input_errors": 0,
            "bad_messages": 0,
        }

    # ------------------------------------------------------------------
    # Public API (UI thread)
    # ------------------------------------------------------------------
    @property
    def state(self) -> ScreenState:
        """Current state."""
        return self._state

    @property
    def serial(self) -> str | None:
        """Serial the service follows (the active device), or None."""
        return self._serial

    @property
    def stats(self) -> dict[str, Any]:
        """A copy of ``stream_fps``, ``stream_frames``, ``reconnects``,
        ``input_errors`` and ``bad_messages`` (for the log).
        """
        with self._lock:
            return dict(self._stats)

    def attach(self, sink: DeviceScreenSink | None) -> None:
        """Attach the one sink (None detaches). Re-sends size and state."""
        self._ensure_started()
        with self._lock:
            self._sink = sink
            size = self._dev_size
            rotation = self._rotation
            state, detail = self._state, self._detail
        if sink is None:
            return
        if size is not None:
            self._call_sink(sink.set_device_size, size[0], size[1], rotation)
        self._call_sink(sink.set_state, state, detail)

    def set_visible(self, visible: bool, panel_px: tuple[int, int]) -> None:
        """Stream only while visible, fitted into ``panel_px`` (w x h px)."""
        self._ensure_started()
        with self._lock:
            if self._closed:
                return
            visible = bool(visible)
            was_visible = self._visible
            self._visible = visible
            if visible:
                self._panel_px = (int(panel_px[0]), int(panel_px[1]))
            if not visible:
                if was_visible:
                    self._lift_locked()
                    self._cancel_stream_locked()
            elif (
                self._stream is not None
                and self._stream_size != self._request_size_locked()
            ):
                self._cancel_stream_locked()  # the link thread restarts it
        self._wake.set()

    def set_input_policy(self, *, locked: str | None, allow_clipboard: bool) -> None:
        """Lock all input (reason) and/or keep off the guest clipboard."""
        with self._lock:
            self._locked = locked or None
            self._allow_clipboard = bool(allow_clipboard)
            if self._locked:
                self._lift_locked()

    def touch(self, action: TouchAction, x: int, y: int) -> str | None:
        """Live pointer stream in device px (current orientation)."""
        with self._lock:
            if self._locked:
                return self._locked
            if self._closed:
                return None
            x, y = int(x), int(y)
            if action == "down":
                self._release_wheel_locked()
                if self._touch is not None:  # never leave a finger down
                    self._put_locked("up", *self._touch)
                self._touch = (x, y)
                self._put_locked("down", x, y)
            elif self._touch is None:
                return None
            elif action == "move":
                self._touch = (x, y)
                self._put_locked("move", x, y)
            else:
                self._touch = None
                self._put_locked("up", x, y)
        return None

    def wheel(self, x: int, y: int, dy: int) -> str | None:
        """One wheel notch: a held drag of 64 dp, lifted after a short idle."""
        with self._lock:
            if self._locked:
                return self._locked
            if self._closed or self._touch is not None or not dy:
                return None  # a real drag is in progress
            dens = self._density / 160
            step = self.WHEEL_STEP_DP * dens
            height = (self._dev_size or self._current_native_locked())[1]
            # Stay clear of the status bar and the gesture zone at the bottom
            # (a drag starting there is "notifications" / "go home").
            lo, hi = 0.15 * height, 0.85 * height
            sign = 1 if dy > 0 else -1
            wd = self._wheel
            ny = 0.0
            if wd is not None:
                ny = wd[1] - sign * step
                if not lo <= ny <= hi:  # out of room: lift and press again
                    self._release_wheel_locked()
                    wd = None
            if wd is None:
                # Start under the pointer, moved just enough to leave room
                # for two notches in the drag direction.
                room = 2 * step
                y0 = max(float(y), lo + room) if sign > 0 else min(float(y), hi - room)
                y0 = min(max(y0, lo), hi)
                x0 = float(x)
                self._put_locked("down", int(x0), int(y0))
                slop = 8 * dens  # Android eats the touch slop from the first move
                ny = y0 - sign * (step + slop)
                wd = self._wheel = [x0, y0]
            wd[1] = ny
            self._put_locked("move", int(wd[0]), int(ny))
            self._wheel_deadline = time.monotonic() + self.WHEEL_IDLE_S
        return None

    def key(self, name: str) -> str | None:
        """W3C key name: ``GoBack``, ``GoHome``, ``AppSwitch``, ``Enter``, ..."""
        with self._lock:
            if self._locked:
                return self._locked
            if not self._closed and name:
                self._put_locked("key", str(name))
        return None

    def text(self, text: str) -> str | None:
        """Typed text: layout-safe chars as keys, else the clipboard (if allowed)."""
        with self._lock:
            if self._locked:
                return self._locked
            if not self._allow_clipboard and not layout_safe(text):
                return self.CLIPBOARD_OFF_TEXT
            if not self._closed and text:
                self._put_locked("text", text, self._allow_clipboard)
        return None

    def paste(self, text: str) -> str | None:
        """Bracketed paste (the clipboard + Ctrl+V; refused without clipboard)."""
        with self._lock:
            if self._locked:
                return self._locked
            if not self._allow_clipboard:
                return self.CLIPBOARD_OFF_PASTE
            if not self._closed and text:
                self._put_locked("text", text, True)
        return None

    def lift(self) -> None:
        """Release any held touch or wheel drag."""
        with self._lock:
            if not self._closed:
                self._lift_locked()

    def close(self) -> None:
        """Stop all threads and the channel (idempotent, never blocks)."""
        with self._lock:
            if self._closed:
                return
            self._lift_locked()
            self._closed = True
            self._cancel_stream_locked()
            client, self._client = self._client, None
            self._sink = None
        if client is not None:
            self._q.put(_Item("close", client=client))
        self._q.put(_STOP)
        self._wake.set()

    # ------------------------------------------------------------------
    # Device following
    # ------------------------------------------------------------------
    def _ensure_started(self) -> None:
        with self._lock:
            if self._started or self._closed:
                return
            self._started = True
        try:
            manager = self._device_manager()
            ref = weakref.ref(self)

            def _on_change(device: Any, _ref: Any = ref) -> None:
                svc = _ref()
                if svc is not None:
                    svc._on_device_change(device)

            # No unregister exists: the closure holds only a weak reference.
            manager.on_device_change(_on_change)
            self._on_device_change(manager.active_device)
        except Exception as exc:
            logger.debug(f"device screen: no device manager ({exc})")
        self._link_thread = threading.Thread(
            target=self._run_link, name="device-screen-link", daemon=True
        )
        self._input_thread = threading.Thread(
            target=self._run_input, name="device-screen-input", daemon=True
        )
        self._link_thread.start()
        self._input_thread.start()

    def _on_device_change(self, device: Any) -> None:
        """DeviceManager callback (UI or poll thread; ``None`` = disconnect)."""
        serial = getattr(device, "serial", None) if device is not None else None
        is_emulator = bool(getattr(device, "is_emulator", False)) if serial else False
        with self._lock:
            if self._closed:
                return
            if serial == self._serial and is_emulator == self._is_emulator:
                return  # a metadata refresh of the same device
            self._lift_locked()  # to the client of the device we leave
            self._gone = serial is None and self._is_emulator and self._seen_live
            self._serial = serial
            self._is_emulator = is_emulator
            self._epoch += 1
            self._seen_live = False
            self._cancel_stream_locked()
        self._wake.set()

    # ------------------------------------------------------------------
    # Link thread: connect, stream, states
    # ------------------------------------------------------------------
    def _run_link(self) -> None:
        backoff = self.BACKOFF_MIN_S
        refused: tuple[Any, ...] | None = None  # endpoint that said UNAUTHENTICATED
        while True:
            self._wake.clear()
            with self._lock:
                if self._closed:
                    break
                visible, serial = self._visible, self._serial
                is_emulator, epoch, gone = self._is_emulator, self._epoch, self._gone
                client = self._client if self._client_epoch == epoch else None
            if not visible:
                self._retire_client()
                self._set_state(ScreenState.OFF, "hidden")
                self._wake.wait()
                continue
            opener = self._load_opener()
            if opener is None:
                self._retire_client()
                self._set_state(ScreenState.NO_EXTRA, self._opener_error)
                self._wake.wait()
                continue
            if serial is None:
                self._retire_client()
                if gone:
                    self._set_state(ScreenState.GONE, "device disconnected")
                else:
                    self._set_state(ScreenState.NO_DEVICE, "")
                self._wake.wait()
                continue
            if not is_emulator:
                self._retire_client()
                self._set_state(ScreenState.PHYSICAL, serial)
                self._wake.wait()
                continue
            if client is None:
                self._retire_client()
                client, wait, refused = self._connect(serial, epoch, opener, refused)
                if client is None:
                    if wait is None:
                        wait = backoff
                        backoff = min(backoff * 2, self.BACKOFF_MAX_S)
                    self._wake.wait(wait)
                    continue
                backoff = self.BACKOFF_MIN_S
            outcome = self._stream_once(client, epoch)
            if outcome == "restart":
                backoff = self.BACKOFF_MIN_S
                continue
            self._retire_client()
            if outcome == "auth":
                refused = client.endpoint.identity
                self._set_state(ScreenState.AUTH_ERROR, "stream refused")
                self._wake.wait(self.POLL_S)
                continue
            # lost: the emulator went away or restarted; rediscover it.
            with self._lock:
                self._stats["reconnects"] += 1
            self._set_state(ScreenState.CONNECTING, f"{serial}: stream lost")
            self._wake.wait(backoff)
            backoff = min(backoff * 2, self.BACKOFF_MAX_S)
        self._retire_client()

    def _load_opener(self) -> Opener | None:
        if self._opener is None and not self._opener_error:
            try:
                self._opener = _import_opener()
            except Exception as exc:
                self._opener_error = f"{type(exc).__name__}: {exc}"
                logger.info(f"device screen: the screen extra is missing ({exc})")
        return self._opener

    def _connect(
        self,
        serial: str,
        epoch: int,
        opener: Opener,
        refused: tuple[Any, ...] | None,
    ) -> tuple[_ClientLike | None, float | None, tuple[Any, ...] | None]:
        """Find (fresh token) and open the endpoint; returns (client, wait, refused).

        ``wait`` None means "use the backoff".
        """
        try:
            endpoint = self._finder(serial)
        except Exception as exc:
            with self._lock:
                seen = self._seen_live and self._epoch == epoch
            if seen:
                self._set_state(ScreenState.GONE, f"{serial}: {exc}")
            else:
                self._set_state(ScreenState.NEEDS_GRPC, f"{serial}: {exc}")
            return None, self.POLL_S, refused
        if refused is not None and endpoint.identity == refused:
            return None, self.POLL_S, refused  # same endpoint, same answer
        self._set_state(ScreenState.CONNECTING, f"{serial} grpc :{endpoint.grpc_port}")
        client: _ClientLike | None = None
        try:
            client = opener(endpoint)
            info = client.status()
        except ScreenRpcError as exc:
            if client is not None:
                client.close()
            if exc.kind == "auth":
                self._set_state(ScreenState.AUTH_ERROR, f"{serial}: {exc.code}")
                return None, self.POLL_S, endpoint.identity
            self._set_state(ScreenState.CONNECTING, f"{serial}: {exc.code}")
            return None, None, refused
        except Exception as exc:
            if client is not None:
                client.close()
            self._set_state(ScreenState.CONNECTING, f"{serial}: {type(exc).__name__}")
            return None, None, refused
        with self._lock:
            if self._closed or self._epoch != epoch:
                stale = True
            else:
                stale = False
                self._client = client
                self._client_epoch = epoch
                self._native = (int(info.native_w), int(info.native_h))
                self._density = int(info.density) or 420
                self._seen_live = True
                self._gone = False
                cur = self._current_native_locked()
                self._dev_size = cur
                rotation = self._rotation
                sink = self._sink
        if stale:
            client.close()
            return None, 0.0, None
        if sink is not None:
            self._call_sink(sink.set_device_size, cur[0], cur[1], rotation)
        return client, None, None

    def _stream_once(self, client: _ClientLike, epoch: int) -> str:
        """Stream until cancelled or failed: ``restart`` / ``auth`` / ``lost``."""
        with self._lock:
            if self._closed or not self._visible or self._epoch != epoch:
                return "restart"
            size = self._request_size_locked()
            self._generation += 1
            generation = self._generation
            try:
                stream = client.stream(*size)
            except ScreenRpcError as exc:
                return "auth" if exc.kind == "auth" else "lost"
            except Exception:
                return "lost"
            self._stream = stream
            self._stream_size = size
        try:
            for image in stream:
                if not self._on_image(image, generation, client):
                    return "restart"
            return "lost"  # the server ended the stream
        except ScreenRpcError as exc:
            if exc.kind == "cancelled":
                return "restart"
            if exc.kind == "auth":
                return "auth"
            logger.debug(f"device screen: stream failed ({exc})")
            return "lost"
        except Exception as exc:
            logger.debug(f"device screen: stream failed ({type(exc).__name__}: {exc})")
            return "lost"
        finally:
            with self._lock:
                if self._stream is stream:
                    self._stream = None
                    self._stream_size = None
                self._stats["bad_messages"] += getattr(stream, "bad_messages", 0)
            stream.cancel()

    def _on_image(self, image: RawImage, generation: int, client: _ClientLike) -> bool:
        """Hand one frame to the sink; False when the stream is stale."""
        import numpy as np

        recv = time.monotonic()
        with self._lock:
            if generation != self._generation or self._closed:
                return False
            rotation = image.rotation % 4
            rotated = rotation != self._rotation or self._dev_size is None
            self._rotation = rotation
            dev_w, dev_h = self._current_native_locked()
            self._dev_size = (dev_w, dev_h)
            sink = self._sink
            self._stats["stream_frames"] += 1
            self._fps_count += 1
            if recv - self._fps_t0 >= 1.0:
                self._stats["stream_fps"] = round(
                    self._fps_count / (recv - self._fps_t0), 1
                )
                self._fps_count, self._fps_t0 = 0, recv
            serial = self._serial
        if self._state is not ScreenState.LIVE:
            port = client.endpoint.grpc_port
            self._set_state(
                ScreenState.LIVE, f"{serial} grpc :{port} {image.width}x{image.height}"
            )
        if sink is None:
            return True
        if rotated:
            self._call_sink(sink.set_device_size, dev_w, dev_h, rotation)
        pixels = np.frombuffer(image.pixels, dtype=np.uint8).reshape(
            image.height, image.width, image.bpp
        )
        if image.bpp == 4:
            pixels = pixels[:, :, :3]
        frame = ScreenFrame(
            pixels=pixels,
            device_w=dev_w,
            device_h=dev_h,
            rotation=rotation,
            recv=recv,
            generation=generation,
        )
        self._call_sink(sink.push_frame, frame)
        return True

    def _retire_client(self) -> None:
        """Drop the client; the input thread closes it after queued input."""
        with self._lock:
            client, self._client = self._client, None
            self._client_epoch = -1
        if client is not None:
            self._q.put(_Item("close", client=client))

    def _set_state(self, state: ScreenState, detail: str = "") -> None:
        with self._lock:
            if state == self._state and detail == self._detail:
                return
            changed = state != self._state
            self._state, self._detail = state, detail
            sink = self._sink
        if changed:
            logger.debug(f"device screen: {state.value} ({detail})")
        if sink is not None:
            self._call_sink(sink.set_state, state, detail)

    def _call_sink(self, method: Callable[..., Any], *args: Any) -> None:
        """Call a sink method; its exceptions never reach the threads."""
        try:
            method(*args)
        except Exception as exc:
            self._sink_errors += 1
            if self._sink_errors <= 3:
                logger.warning(
                    f"device screen: sink {getattr(method, '__name__', method)} "
                    f"failed: {type(exc).__name__}: {exc}"
                )

    # ------------------------------------------------------------------
    # Lock-held helpers
    # ------------------------------------------------------------------
    def _current_native_locked(self) -> tuple[int, int]:
        w, h = self._native
        return (h, w) if self._rotation % 2 else (w, h)

    def _request_size_locked(self) -> tuple[int, int]:
        """The stream box: the panel px, capped to the device px."""
        cur_w, cur_h = self._current_native_locked()
        w = min(max(self._panel_px[0], self.MIN_STREAM_PX), cur_w)
        h = min(max(self._panel_px[1], self.MIN_STREAM_PX), cur_h)
        return (w, h)

    def _cancel_stream_locked(self) -> None:
        self._generation += 1  # frames still in flight are dropped
        stream = self._stream
        if stream is not None:
            stream.cancel()

    def _put_locked(self, kind: str, *args: Any) -> None:
        self._q.put(_Item(kind, args, epoch=self._epoch, client=self._client))

    def _release_wheel_locked(self) -> None:
        wd, self._wheel = self._wheel, None
        if wd is not None:
            self._put_locked("up", int(wd[0]), int(wd[1]))

    def _lift_locked(self) -> None:
        """Queue an UP for a held touch / wheel drag, bound to the current client.

        Bound explicitly (native px), so the UP still reaches that emulator
        when the client is retired right after (hide, switch, close): the
        input thread closes a retired client only after it.
        """
        points: list[tuple[int, int]] = []
        if self._wheel is not None:
            points.append((int(self._wheel[0]), int(self._wheel[1])))
        if self._touch is not None:
            points.append(self._touch)
        self._wheel = None
        self._touch = None
        client = self._client
        if client is None:
            return
        for x, y in points:
            nx, ny = to_native(x, y, self._rotation, *self._native)
            self._q.put(_Item("up_native", (nx, ny), client=client))

    # ------------------------------------------------------------------
    # Input thread
    # ------------------------------------------------------------------
    def _run_input(self) -> None:
        pending: Any = None
        last_move = 0.0
        last_key = 0.0
        while True:
            if pending is not None:
                item, pending = pending, None
            else:
                try:
                    item = self._q.get(timeout=self._wheel_wait())
                except queue.Empty:
                    self._wheel_idle_release()
                    continue
            if item is _STOP:
                return
            if item.kind == "move":
                item, pending = self._coalesce_moves(item, last_move)
            elif (
                item.kind == "key"
                and item.args[0] in self.REPEAT_KEYS
                and time.monotonic() - item.t > self.STALE_REPEAT_S
            ):
                continue  # terminal auto-repeat backlog: stop on release
            try:
                last_key = self._send(item, last_key)
            except Exception as exc:
                with self._lock:
                    self._stats["input_errors"] += 1
                logger.debug(f"device screen: input {item.kind} failed ({exc})")
            if item.kind == "move":
                last_move = time.monotonic()

    def _coalesce_moves(self, item: _Item, last_move: float) -> tuple[_Item, Any]:
        """Keep only the newest of consecutive queued moves (<= 120 Hz)."""
        pending: Any = None

        def _drain(current: _Item) -> tuple[_Item, Any]:
            while True:
                try:
                    nxt = self._q.get_nowait()
                except queue.Empty:
                    return current, None
                if nxt is not _STOP and nxt.kind == "move":
                    current = nxt
                    continue
                return current, nxt

        item, pending = _drain(item)
        wait = last_move + self.MOVE_MIN_DT - time.monotonic()
        if wait > 0 and pending is None:
            time.sleep(wait)
            item, pending = _drain(item)  # a newer move may have come
        return item, pending

    def _wheel_wait(self) -> float | None:
        with self._lock:
            if self._wheel is None:
                return None
            return max(0.0, self._wheel_deadline - time.monotonic())

    def _wheel_idle_release(self) -> None:
        """Lift the wheel drag after its idle time (input thread, queue empty)."""
        with self._lock:
            wd = self._wheel
            if wd is None or time.monotonic() < self._wheel_deadline:
                return
            self._wheel = None
            item = _Item(
                "up", (int(wd[0]), int(wd[1])), epoch=self._epoch, client=self._client
            )
        try:
            self._send(item, 0.0)
        except Exception as exc:
            with self._lock:
                self._stats["input_errors"] += 1
            logger.debug(f"device screen: wheel release failed ({exc})")

    def _send(self, item: _Item, last_key: float) -> float:
        """Send one item; returns the time of the last typed key."""
        if item.kind == "close":
            item.client.close()
            return last_key
        if item.kind == "up_native":
            item.client.touch(item.args[0], item.args[1], 0)
            return last_key
        with self._lock:
            if item.epoch != self._epoch:
                return last_key  # for a device we left (lifted separately)
            if self._locked and item.kind != "up":
                return last_key  # queued before the lock
            client = item.client
            if client is None and self._client_epoch == self._epoch:
                client = self._client
            rotation, native = self._rotation, self._native
            allow_clipboard = self._allow_clipboard
        if client is None:
            return last_key
        kind = item.kind
        if kind in ("down", "move", "up"):
            nx, ny = to_native(item.args[0], item.args[1], rotation, *native)
            client.touch(nx, ny, 0 if kind == "up" else self.TOUCH_PRESSURE)
        elif kind == "key":
            client.key(item.args[0])
        elif kind == "text":
            text, allowed = item.args
            return self._type(client, text, allowed and allow_clipboard, last_key)
        return last_key

    def _type(
        self, client: _ClientLike, text: str, allow_clipboard: bool, last_key: float
    ) -> float:
        """Layout-safe text as paced keys; else (and when long) the clipboard.

        The guest maps gRPC key names with its own keyboard layout (German:
        y/z swap), so only :data:`SAFE_CHARS` are typed; without the
        clipboard anything else is dropped (``text()`` already refused it).
        """
        safe = layout_safe(text)
        if allow_clipboard and (len(text) > self.BURST_PASTE or not safe):
            client.paste(text)
            return time.monotonic()
        if not safe:
            return last_key
        for char in text:
            wait = last_key + self.KEY_PACE_S - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            client.key(char)
            last_key = time.monotonic()
        return last_key


__all__ += ["DeviceScreenService"]
