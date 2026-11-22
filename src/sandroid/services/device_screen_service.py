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
