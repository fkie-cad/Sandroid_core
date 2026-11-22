"""The live device screen (Ctrl+G): a phone image you can touch and type on.

:class:`DeviceScreen` is the :class:`~sandroid.services.device_screen_service.
DeviceScreenSink` of the device screen service: the service's stream thread
pushes frames (``push_frame``), the device size and its state; the widget
draws them and sends mouse and keyboard input back through the service.

Backends (chosen by :mod:`sandroid.tui.terminal_graphics` before the app
starts):

* ``iterm``     iTerm2 / WezTerm inline image (OSC 1337, JPEG via Pillow)
* ``kitty``     kitty graphics protocol, one image id replaced in place
* ``sixel``     DEC sixel (216-colour cube)
* ``halfblock`` truecolor half-block cells, drawn by Textual itself

Graphics backends write the image straight to the driver, outside Textual's
compositor. ``SandroidTUI`` overrides ``_display``/``_end_update`` and calls
:meth:`DeviceScreen._after_textual_paint` inside every Textual paint, so the
widget re-emits its image when Textual repainted its cells and hides it when
the widget is covered (modal, toast, another screen). Frames are paced by
acks: every stand-alone frame ends with ``CSI 6n``; the terminal answers once
it parsed the image, the driver hook swallows the answer, so at most one frame
is inside the terminal. After three missing answers the ``max_fps`` cap paces;
about once a second a frame still asks (``ACK_PROBE_S``), and a timely answer
turns ack pacing back on.

Every frame is composited into a phone body (the bezel); the area outside it
is the widget background (``$lens-panel``). Clicks on the bezel do nothing;
drags are clamped to the screen edge. The mouse never takes the focus; keys
go to the phone only while the widget has the focus. Only Ctrl+G gives it the
focus (:meth:`DeviceScreen.focus_from_shortcut`): it is not in the Tab chain.
"""

from __future__ import annotations

import base64
import functools
import io
import math
import re
import sys
import threading
import time
import weakref
import zlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import numpy as np
from PIL import Image
from rich.color import Color
from rich.segment import Segment
from rich.style import Style
from textual.binding import Binding
from textual.containers import Horizontal
from textual.geometry import Region
from textual.message import Message
from textual.strip import Strip
from textual.widget import Widget
from textual.widgets import Static

from sandroid.services.device_screen_service import (
    ScreenFrame,
    ScreenState,
    status_text,
)
from sandroid.tui import terminal_graphics
from sandroid.tui.terminal_graphics import (
    KITTY_DELETE,
    KITTY_IMAGE_ID,
    KITTY_PLACEMENT_ID,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual import events
    from textual.app import ComposeResult
    from textual.timer import Timer

    from sandroid.services.device_screen_service import DeviceScreenServiceProtocol

#: Cursor-position query; its answer acks a frame (ack pacing).
DSR_CPR = "\x1b[6n"
#: An ack that does not come within this many seconds counts as lost.
ACK_TIMEOUT_S = 0.5
#: Lost acks in a row after which the ``max_fps`` cap paces instead.
ACK_FAILS_MAX = 3
#: While the ``max_fps`` cap paces, a frame asks at most this often whether
#: the terminal answers again (an answer within ``ACK_TIMEOUT_S`` re-arms).
ACK_PROBE_S = 1.0
#: Writes waiting in Textual's output queue above which a new frame is
#: dropped (the queue holds 30 writes; a full queue blocks the event loop).
WRITER_BACKLOG_MAX = 4
#: Split a frame into ``WRITE_CHUNK`` writes. Only Windows needs it (Textual
#: chunks there too, #2548); elsewhere every write is one blocking put into
#: the 30-slot writer queue, so a multi-MB frame in 8 KiB pieces would stall
#: the event loop.
CHUNK_WRITES = sys.platform == "win32"
WRITE_CHUNK = 8192
#: JPEG quality for the iTerm2 backend.
JPEG_QUALITY = 80
#: Half-block cell styles kept (an LRU; 6 bits per channel).
STYLE_CACHE_MAX = 65_536
#: How long a refusal reason stays on the status line.
HINT_SECONDS = 3.0
#: Device size until the service reports one (portrait phone).
DEFAULT_DEVICE_SIZE = (1080, 2400)

# ---------------------------------------------------------------------------
# Encoders (all take an H x W x 3 uint8 array)
# ---------------------------------------------------------------------------

_LUT6 = (np.arange(256) * 6 // 256).astype(np.int16)
_SIXEL_PALETTE = b"".join(
    f"#{i};2;{(i // 36) * 20};{((i // 6) % 6) * 20};{(i % 6) * 20}".encode()
    for i in range(216)
)
_SIXEL_RLE = re.compile(rb"([?-~])\1{3,}")


def _sixel_rle(match: Any) -> bytes:
    run = match.group(0)
    return b"!%d%c" % (len(run), run[0])


def encode_sixel(arr: np.ndarray) -> bytes:
    r"""Encode an RGB array as sixel (216-colour cube, no dithering).

    Args:
        arr: ``H x W x 3`` uint8 RGB.

    Returns:
        The DCS sixel sequence (``ESC P ... ESC \\``).
    """
    h, w, _ = arr.shape
    idx = _LUT6[arr[..., 0]] * 36 + _LUT6[arr[..., 1]] * 6 + _LUT6[arr[..., 2]]
    bands = (h + 5) // 6
    pad = bands * 6 - h
    if pad:
        idx = np.vstack([idx, np.full((pad, w), 216, np.int16)])  # no colour
    idx = idx.reshape(bands, 6, w)
    acc = np.zeros((bands, 217, w), np.uint8)
    b_ix = np.arange(bands)[:, None]
    c_ix = np.arange(w)[None, :]
    for row in range(6):
        acc[b_ix, idx[:, row, :], c_ix] |= np.uint8(1 << row)
    present = acc[:, :216, :].any(axis=2)
    acc += 63
    out = [b'\x1bP0;1;0q"1;1;%d;%d' % (w, h), _SIXEL_PALETTE]
    for band in range(bands):
        cols = np.flatnonzero(present[band])
        out.append(b"$".join(b"#%d" % c + acc[band, c].tobytes() for c in cols))
        out.append(b"$-" if band < bands - 1 else b"$")
    return _SIXEL_RLE.sub(_sixel_rle, b"".join(out)) + b"\x1b\\"


def encode_jpeg(arr: np.ndarray, quality: int = JPEG_QUALITY) -> bytes:
    """RGB array -> JPEG bytes (Pillow, 4:2:0)."""
    bio = io.BytesIO()
    Image.fromarray(np.ascontiguousarray(arr)).save(bio, "JPEG", quality=quality)
    return bio.getvalue()


def encode_iterm(arr: np.ndarray, quality: int = JPEG_QUALITY) -> bytes:
    """RGB array -> iTerm2 OSC 1337 inline image (JPEG), cursor not moved."""
    data = encode_jpeg(arr, quality)
    h, w = arr.shape[:2]
    return (
        b"\x1b]1337;File=inline=1;size=%d;width=%dpx;height=%dpx;"
        b"preserveAspectRatio=0;doNotMoveCursor=1:"
        % (len(data), w, h)
        + base64.b64encode(data)
        + b"\x07"
    )


def encode_kitty(arr: np.ndarray) -> bytes:
    """RGB array -> kitty graphics (zlib RGB, 4 KiB chunks, ``q=2`` quiet).

    The image id and placement id stay the same, so every frame replaces
    the previous one in place. ``q=2`` is repeated on every chunk: without
    it some terminals answer each chunk, and the answers arrive as keys.
    """
    h, w = arr.shape[:2]
    payload = base64.b64encode(zlib.compress(np.ascontiguousarray(arr).tobytes(), 1))
    chunks = [payload[i : i + 4096] for i in range(0, len(payload), 4096)] or [b""]
    out = []
    for n, chunk in enumerate(chunks):
        more = 1 if n < len(chunks) - 1 else 0
        if n == 0:
            ctrl = b"a=T,f=24,o=z,s=%d,v=%d,i=%d,p=%d,q=2,C=1,m=%d" % (
                w,
                h,
                KITTY_IMAGE_ID,
                KITTY_PLACEMENT_ID,
                more,
            )
        else:
            ctrl = b"q=2,m=%d" % more
        out.append(b"\x1b_G" + ctrl + b";" + chunk + b"\x1b\\")
    return b"".join(out)


@functools.lru_cache(maxsize=STYLE_CACHE_MAX)
def _cell_style(key: tuple[int, int, int, int, int, int]) -> Style:
    """Half-block style: foreground = top pixel, background = bottom pixel."""
    tr, tg, tb, br, bgr, bb = key
    return Style.from_color(
        color=Color.from_rgb(tr, tg, tb), bgcolor=Color.from_rgb(br, bgr, bb)
    )


def halfblock_strips(
    arr: np.ndarray, cols: int, rows: int, x0: int, y0: int, bg: tuple[int, int, int]
) -> list[Strip]:
    """Render an RGB array (``w`` x ``2*h`` px) as ``rows`` Strips of ▀ cells.

    Args:
        arr: The canvas (one column and two rows of pixels per cell).
        cols: Strip width in cells.
        rows: Number of strips.
        x0: Cell column of the canvas inside the strips.
        y0: Cell row of the canvas inside the strips.
        bg: Background colour around the canvas.
    """
    arr = arr & 0xFC  # 6 bits per channel: far fewer distinct styles
    ih, iw, _ = arr.shape
    if ih % 2:
        arr = np.vstack([arr, np.zeros((1, iw, 3), np.uint8)])
    top, bot = arr[0::2], arr[1::2]
    bgs = Style(bgcolor=Color.from_rgb(*bg))
    strips: list[Strip] = []
    for y in range(rows):
        iy = y - y0
        if iy < 0 or iy >= top.shape[0]:
            strips.append(Strip([Segment(" " * cols, bgs)], cols))
            continue
        segs = [Segment(" " * x0, bgs)] if x0 > 0 else []
        last: tuple[int, int, int, int, int, int] | None = None
        run = 0
        for (tr, tg, tb), (br, bgr, bb) in zip(
            top[iy].tolist(), bot[iy].tolist(), strict=True
        ):
            key = (tr, tg, tb, br, bgr, bb)
            if key == last:
                run += 1
                continue
            if last is not None:
                segs.append(Segment("▀" * run, _cell_style(last)))
            last, run = key, 1
        if last is not None:
            segs.append(Segment("▀" * run, _cell_style(last)))
        rest = cols - max(0, x0) - iw
        if rest > 0:
            segs.append(Segment(" " * rest, bgs))
        strips.append(Strip(segs, cols).crop(0, cols))
    return strips


# ---------------------------------------------------------------------------
# Geometry (cell box, canvas, bezel, screen rectangle)
# ---------------------------------------------------------------------------

#: Bezel thickness, fraction of the screen's short side.
BEZEL_FRAC = 0.045
#: Rounded screen corners, fraction of the short side.
SCREEN_RADIUS_FRAC = 0.075


@dataclass(frozen=True)
class Geometry:
    """Where the phone goes inside the widget, in cells and in pixels.

    Attributes:
        region: Content region (screen cells).
        cell_w: Cell width in px.
        cell_h: Cell height in px.
        dev_w: Device width in the current orientation (touch space).
        dev_h: Device height in the current orientation.
        box_x: Displayed box, cells from the region's left.
        box_y: Displayed box, cells from the region's top.
        box_cols: Box width in cells.
        box_rows: Box height in cells.
        canvas_w: Image written to the terminal (covers the box), px.
        canvas_h: Canvas height, px.
        outer: Device body inside the canvas ``(x, y, w, h)`` px.
        bezel: Bezel thickness px.
        r_outer: Body corner radius px.
        r_screen: Screen corner radius px.
        img_off_x: Screen rectangle inside the canvas, px.
        img_off_y: Screen rectangle inside the canvas, px.
        img_w: Screen rectangle width px (the stream is requested at this).
        img_h: Screen rectangle height px.
        halfblock: One cell = 1 x 2 pixels.
    """

    region: Region
    cell_w: float
    cell_h: float
    dev_w: int
    dev_h: int
    box_x: int
    box_y: int
    box_cols: int
    box_rows: int
    canvas_w: int
    canvas_h: int
    outer: tuple[int, int, int, int]
    bezel: int
    r_outer: int
    r_screen: int
    img_off_x: int
    img_off_y: int
    img_w: int
    img_h: int
    halfblock: bool

    @staticmethod
    def compute(
        region: Region,
        cell_w: float,
        cell_h: float,
        dev_w: int,
        dev_h: int,
        halfblock: bool,
        sixel: bool = False,
        bezel: bool = True,
    ) -> Geometry:
        """Fit the device (plus bezel) into ``region``, centred."""
        dev_w, dev_h = max(1, dev_w), max(1, dev_h)
        if halfblock:  # one cell = 1 x 2 "pixels"; real cell aspect
            bd = 1 if bezel else 0  # a 1 px (column / half row) border
            pix_aspect = cell_w / (cell_h / 2)
            avail_w = max(1, region.width - 2 * bd)
            avail_h = max(1, region.height * 2 - 2 * bd)
            scale = min(avail_w * pix_aspect / dev_w, avail_h / dev_h)
            img_w = max(1, int(dev_w * scale / pix_aspect))
            img_h = max(1, int(dev_h * scale))
            if (img_h + 2 * bd) % 2:
                img_h = max(1, img_h - 1)
            ow, oh = img_w + 2 * bd, img_h + 2 * bd
            box_cols, box_rows = ow, max(1, oh // 2)
            return Geometry(
                region,
                cell_w,
                cell_h,
                dev_w,
                dev_h,
                (region.width - box_cols) // 2,
                (region.height - box_rows) // 2,
                box_cols,
                box_rows,
                ow,
                oh,
                (0, 0, ow, oh),
                bd,
                bd,
                0,
                bd,
                bd,
                img_w,
                img_h,
                True,
            )
        k = BEZEL_FRAC if bezel else 0.0
        short = min(dev_w, dev_h)
        avail_w = region.width * cell_w
        avail_h = region.height * cell_h
        if sixel:  # sixel bands are 6 px; the last one must stay inside
            avail_h -= 6
        scale = max(
            1e-6,
            min(avail_w / (dev_w + 2 * k * short), avail_h / (dev_h + 2 * k * short)),
        )
        img_w = max(1, int(dev_w * scale))
        img_h = max(1, int(dev_h * scale))
        b = round(k * short * scale)
        ow, oh = img_w + 2 * b, img_h + 2 * b
        box_cols = min(region.width, max(1, math.ceil(ow / cell_w - 1e-6)))
        box_rows = min(region.height, max(1, math.ceil(oh / cell_h - 1e-6)))
        canvas_w = max(ow, round(box_cols * cell_w))
        # sixel: no vertical padding (the image must not reach the next row)
        canvas_h = oh if sixel else max(oh, round(box_rows * cell_h))
        ox, oy = (canvas_w - ow) // 2, (canvas_h - oh) // 2
        r_screen = round(SCREEN_RADIUS_FRAC * min(img_w, img_h)) if bezel else 0
        return Geometry(
            region,
            cell_w,
            cell_h,
            dev_w,
            dev_h,
            (region.width - box_cols) // 2,
            (region.height - box_rows) // 2,
            box_cols,
            box_rows,
            canvas_w,
            canvas_h,
            (ox, oy, ow, oh),
            b,
            r_screen + b if bezel else 0,
            r_screen,
            ox + b,
            oy + b,
            img_w,
            img_h,
            False,
        )

    def to_device(self, cx: float, cy: float) -> tuple[float, float, bool]:
        """Region-relative cell coordinates -> device px and an inside flag.

        Points on the bezel or outside are clamped to the screen edge (for
        drags) and flagged ``inside=False`` (presses there are ignored).
        """
        if self.halfblock:
            px = cx - self.box_x
            py = (cy - self.box_y) * 2
        else:
            px = (cx - self.box_x) * self.cell_w
            py = (cy - self.box_y) * self.cell_h
        ux = (px - self.img_off_x) / self.img_w
        uy = (py - self.img_off_y) / self.img_h
        inside = 0 <= ux < 1 and 0 <= uy < 1
        return (
            min(max(ux, 0.0), 0.9999) * self.dev_w,
            min(max(uy, 0.0), 0.9999) * self.dev_h,
            inside,
        )

    @property
    def stream_px(self) -> tuple[int, int]:
        """Stream size to request: the screen rectangle in px.

        Half-block asks for twice the size: downscaling looks better.
        """
        if self.halfblock:
            return self.img_w * 2, self.img_h * 2
        return self.img_w, self.img_h


def preferred_cols(
    rows: int,
    cell_px: tuple[float, float],
    device_size: tuple[int, int],
    *,
    halfblock: bool,
    sixel: bool = False,
    bezel: bool = True,
) -> int:
    """Width in cells that lets the device (plus bezel) fill ``rows`` rows."""
    if rows < 2:
        return 2
    geom = Geometry.compute(
        Region(0, 0, 100_000, rows),
        cell_px[0],
        cell_px[1],
        device_size[0],
        device_size[1],
        halfblock,
        sixel,
        bezel,
    )
    return geom.box_cols


# ---------------------------------------------------------------------------
# Bezel (precomputed once per geometry + background colour)
# ---------------------------------------------------------------------------

BODY_RGB = np.array((22, 22, 26), np.float32)  # device body / bezel
EDGE_RGB = np.array((92, 94, 104), np.float32)  # thin metallic edge
HALF_EDGE_RGB = (78, 80, 90)


def _rr_cover(
    xx: np.ndarray, yy: np.ndarray, x: float, y: float, w: float, h: float, r: float
) -> np.ndarray:
    """Anti-aliased coverage (0..1) of a rounded rectangle at pixel centres."""
    r = max(0.0, min(r, w / 2, h / 2))
    qx = np.abs(xx - (x + w / 2)) - (w / 2 - r)
    qy = np.abs(yy - (y + h / 2)) - (h / 2 - r)
    d = (
        np.hypot(np.maximum(qx, 0), np.maximum(qy, 0))
        + np.minimum(np.maximum(qx, qy), 0)
        - r
    )
    return np.clip(0.5 - d, 0.0, 1.0)


class Bezel:
    """Canvas with the phone body drawn once.

    Per frame only the screen rectangle is overwritten and the four screen
    corners are re-masked (:meth:`mask_corners`).
    """

    def __init__(self, g: Geometry, bg: tuple[int, int, int], enabled: bool) -> None:
        t0 = time.perf_counter()
        height, width = g.canvas_h, g.canvas_w
        bgv = np.array(bg, np.float32)
        self.corners: list[tuple[tuple[slice, slice], np.ndarray, np.ndarray]] = []
        ix, iy, iw, ih = g.img_off_x, g.img_off_y, g.img_w, g.img_h
        if g.halfblock or not enabled:
            canvas = np.empty((height, width, 3), np.uint8)
            canvas[:] = bg
            if g.halfblock and enabled:  # a plain border, corners left bg
                ox, oy, ow, oh = g.outer
                canvas[oy : oy + oh, ox : ox + ow] = HALF_EDGE_RGB
                for cy in (oy, oy + oh - 1):
                    for cx in (ox, ox + ow - 1):
                        canvas[cy, cx] = bg
            canvas[iy : iy + ih, ix : ix + iw] = 0
            self.canvas = canvas
            self.build_ms = (time.perf_counter() - t0) * 1000
            return
        ox, oy, ow, oh = g.outer
        ew = max(1.0, g.bezel * 0.09)  # edge highlight width
        xx = (np.arange(width, dtype=np.float32) + 0.5)[None, :]

        def layers(yy: np.ndarray, cov_y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
            a_body = _rr_cover(xx, cov_y, ox, oy, ow, oh, g.r_outer)
            a_in = _rr_cover(
                xx, cov_y, ox + ew, oy + ew, ow - 2 * ew, oh - 2 * ew, g.r_outer - ew
            )
            # a slight top-lit falloff: the edge reads as a rim, not a stroke
            edge = (
                np.clip(a_body - a_in, 0, 1)
                * 0.85
                * (1.0 - 0.45 * (yy - oy) / max(1, oh))
            )
            a_body, edge = a_body[..., None], edge[..., None]
            base = bgv * (1 - a_body) + BODY_RGB * a_body
            base = base * (1 - edge) + EDGE_RGB * edge
            a_scr = _rr_cover(xx, cov_y, ix, iy, iw, ih, g.r_screen)[..., None]
            return base, a_scr

        # rows inside both straight vertical sections depend on x only
        m0 = min(height, max(0, iy + g.r_screen + 1))
        m1 = max(m0, min(height, iy + ih - g.r_screen - 1))
        rows = (np.arange(height, dtype=np.float32) + 0.5)[:, None]
        base = np.empty((height, width, 3), np.float32)
        a_scr = np.empty((height, width, 1), np.float32)
        for y0, y1, mid in ((0, m0, False), (m0, m1, True), (m1, height, False)):
            if y1 <= y0:
                continue
            yy = rows[y0:y1]
            b_, a_ = layers(yy, yy[:1] if mid else yy)
            base[y0:y1] = b_
            a_scr[y0:y1] = a_
        self.canvas = np.ascontiguousarray(
            (base * (1 - a_scr) + 0.5).astype(np.uint8)  # screen black
        )
        rc = g.r_screen + 2
        if g.r_screen > 0:
            for cy in (iy, iy + ih - rc):
                for cx in (ix, ix + iw - rc):
                    sl = (slice(cy, cy + rc), slice(cx, cx + rc))
                    alpha = a_scr[sl].astype(np.float32)
                    pre = base[sl] * (1 - alpha) + 0.5
                    self.corners.append((sl, alpha, pre.astype(np.float32)))
        self.build_ms = (time.perf_counter() - t0) * 1000

    def mask_corners(self) -> None:
        """Round the screen corners again after a frame was pasted."""
        canvas = self.canvas
        for sl, alpha, pre in self.corners:
            canvas[sl] = (canvas[sl] * alpha + pre).astype(np.uint8)


def _update_touches(update: object, region: Region) -> bool:
    """Whether Textual's paint ``update`` wrote cells inside ``region``."""
    if update is None:
        return False
    spans = getattr(update, "spans", None)
    if spans is not None:  # ChopsUpdate
        x1r, x2r, y1r, y2r = region.x, region.right, region.y, region.bottom
        return any(y1r <= y < y2r and x1 < x2r and x2 > x1r for y, x1, x2 in spans)
    upd_region = getattr(update, "region", None)
    if upd_region is not None:  # LayoutUpdate
        return upd_region.overlaps(region)
    return True


# ---------------------------------------------------------------------------
# Widget
# ---------------------------------------------------------------------------


class DeviceScreen(Widget, can_focus=False):
    """Live device screen (the service's sink) with live touch and keys.

    Args:
        service: The device screen service (None: shows "off", no input).
        cell_px: Cell size in px (tests); default: from the terminal.
        backend: Force a backend (tests); default: :mod:`terminal_graphics`.
        max_fps: Frame cap (ack pacing usually limits first).
        bezel: Draw the phone body.
        touch_marker: Draw a ring where the pointer touches.
        policy: Called before each input (refreshes the input policy).

    ``can_focus`` is False except between :meth:`focus_from_shortcut`
    (Ctrl+G) and the next blur: Tab never lands on the phone.
    """

    DEFAULT_CSS = """
    DeviceScreen {
        background: $lens-panel;
        width: 1fr;
        height: 1fr;
    }
    """
    ALLOW_SELECT = False
    #: The mouse controls the phone without taking the focus.
    FOCUS_ON_CLICK = False
    #: ``focus_takes_text``: printable keys belong to this widget while
    #: it has the focus (no app or lens command may run them).
    takes_text = True
    #: Own ←/→ (``handles_left_right``): the Inspector's priority ←/→ tab
    #: switch leaves them to the phone.
    BINDINGS = [
        Binding("left", "device_key('ArrowLeft')", show=False),
        Binding("right", "device_key('ArrowRight')", show=False),
    ]
    #: Textual key -> W3C key name. Esc is not here: it returns the focus
    #: to the lens (Back is the clickable word under the phone).
    KEYMAP = {
        "f2": "GoHome",
        "f3": "AppSwitch",
        "backspace": "Backspace",
        "delete": "Delete",
        "enter": "Enter",
        "up": "ArrowUp",
        "down": "ArrowDown",
        "left": "ArrowLeft",
        "right": "ArrowRight",
    }

    MARK_RADIUS = 9  # touch ring radius, image px
    MARK_RGB = (255, 64, 160)
    MARK_LINGER_S = 0.15  # the ring stays this long after UP

    class SizeChanged(Message):
        """The device size (orientation) changed: the column re-fits."""

        def __init__(self, width: int, height: int) -> None:
            super().__init__()
            self.width = width
            self.height = height

    class SinkSize(Message, bubble=False):
        """Sink -> UI thread: the device size (from the stream thread)."""

        def __init__(self, width: int, height: int, rotation: int) -> None:
            super().__init__()
            self.width, self.height, self.rotation = width, height, rotation

    class SinkState(Message, bubble=False):
        """Sink -> UI thread: the service state (from the stream thread)."""

        def __init__(self, state: ScreenState, detail: str) -> None:
            super().__init__()
            self.state, self.detail = state, detail
            #: When the service changed state (frames received later are
            #: from the next stream and survive a blank).
            self.at = time.monotonic()

    def __init__(
        self,
        service: DeviceScreenServiceProtocol | None = None,
        *,
        cell_px: tuple[float, float] | None = None,
        backend: str | None = None,
        max_fps: float = 60.0,
        bezel: bool = True,
        touch_marker: bool = True,
        policy: Callable[[], None] | None = None,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self.service = service
        self.policy = policy
        self._cell_px_fixed = cell_px
        self._cell_cache: tuple[float, float] | None = None
        self._geom_retry: Timer | None = None
        self._geom_retries = 0
        caps = terminal_graphics.result()
        if backend is None:
            backend = caps.backend if caps is not None else "halfblock"
            if (
                backend != "halfblock"
                and not terminal_graphics.textual_supports_graphics()
            ):
                backend = "halfblock"
        self.backend = backend
        self.max_fps = max(1.0, float(max_fps or 60.0))
        self.bezel = bezel
        self.touch_marker = touch_marker
        self.dev_w, self.dev_h = DEFAULT_DEVICE_SIZE
        self.rotation = 0
        self.state = ScreenState.OFF
        self.state_detail = ""
        self.status_line: DeviceStatus | None = None
        self.lag_ms = 0.0
        self.stats: dict[str, Any] = {
            "fps": 0.0,
            "encode_ms": 0.0,
            "bytes": 0,
            "frames_in": 0,
            "frames_out": 0,
            "dupes": 0,
            "drops": 0,
            "stalls": 0,
            "reemits": 0,
            "hides": 0,
            "ack_ms": 0.0,
            "probes": 0,
            "rearms": 0,
        }
        self._last_error = ""
        # frame hand-off (any thread -> encode thread)
        self._lock = threading.Lock()
        self._frame: np.ndarray | None = None
        self._frame_recv = 0.0
        self._frame_seq = 0
        self._last_arr: np.ndarray | None = None
        self._generation = -1
        self._frame_dev: tuple[int, int] | None = None
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: Any = None
        # ack pacing (driver input thread <-> encode thread)
        self._ack_cv = threading.Condition()
        self._inflight: list[float] = []
        self._ack_ok = backend != "halfblock"
        self._ack_fail = 0
        self._probe_t = 0.0  # last probe while pacing by max_fps
        # geometry / output (UI thread; read by the encode thread under _lock)
        self._geom: Geometry | None = None
        self._geom_gen = 0
        self._bg: tuple[int, int, int] = (18, 18, 18)
        self._bg_gen = 0
        self._bezel_cache: tuple[tuple, Bezel] | None = None  # encode thread
        self._payload: tuple[int, Geometry, str] | None = None
        self._hb_strips: list[Strip] | None = None
        self._shown = False
        self._blank_seq = 0  # frames up to this _frame_seq were blanked
        self._image_serial: str | None = None  # device of the last LIVE
        self._retry_timer: Any = None
        self._hooked = False
        # visibility towards the service
        self._active = False
        self._sent_visible: tuple[bool, tuple[int, int]] | None = None
        # fps shown on the status line
        self._fps_frames = 0
        self._fps_t0 = time.monotonic()
        # live touch
        self._down: tuple[float, float] | None = None
        self._last_xy: tuple[float, float] = (0.0, 0.0)
        self._mark: tuple[float, float] | None = None
        self._mark_seq = 0
        self._mark_timer: Any = None
        self._hint_until = 0.0
        self._hint = ""

    # -- focus ----------------------------------------------------------------

    def focus_on_click(self) -> bool:
        """Never: the mouse controls the phone without taking the focus."""
        return False

    def focus_from_shortcut(self) -> None:
        """Ctrl+G: take the focus (keys go to the phone until the next blur).

        The widget is focusable only from here to its next blur, so Tab /
        Shift+Tab never move the focus onto the phone.
        """
        self.can_focus = True
        self.focus()

    # -- lifecycle ------------------------------------------------------------

    def on_mount(self) -> None:
        import asyncio

        self._loop = asyncio.get_running_loop()
        app = self.app
        if self.backend != "halfblock" and (
            app.is_headless or not hasattr(app, "register_device_screen")
        ):
            self.backend = "halfblock"
        if self.backend == "halfblock":
            self._ack_ok = False
        else:
            try:
                self._hooked = bool(app.register_device_screen(self))
            except Exception:
                self._hooked = False
            if not self._hooked:
                self.backend = "halfblock"
                self._ack_ok = False
        self._update_bg()
        try:
            app.theme_changed_signal.subscribe(self, self._on_theme_changed)
        except Exception:
            pass
        try:
            # Resize / Show alone are not enough: a column shown by a
            # partial layout may place the widget without either reaching it.
            self.screen.screen_layout_refresh_signal.subscribe(
                self, self._on_screen_layout
            )
        except Exception:
            pass
        self._thread = threading.Thread(
            target=self._encode_loop, daemon=True, name="device-screen-encode"
        )
        self._thread.start()
        self.set_interval(1.0, self._tick_status)
        if self.service is not None:
            try:
                self.service.attach(self)
            except Exception as exc:
                self._last_error = repr(exc)
        self._render_status()

    def on_unmount(self) -> None:
        self.lift()
        self._active = False
        self._stop_geom_retry()
        self._send_visible()
        if self.service is not None:
            try:
                self.service.attach(None)
            except Exception:
                pass
        self._stop.set()
        self._wake.set()
        with self._ack_cv:
            self._ack_cv.notify_all()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)
        self._hide_graphics()
        if self._hooked:
            try:
                self.app.register_device_screen(None)
            except Exception:
                pass
            self._hooked = False

    def on_hide(self) -> None:
        self.lift()
        self._stop_geom_retry()

    def on_show(self) -> None:
        self._geom_retries = 0
        self.call_after_refresh(self._refresh_geom)

    def on_blur(self, _event: events.Blur) -> None:
        self.can_focus = False  # out of the Tab chain until the next Ctrl+G
        self.lift()

    def notify_style_update(self) -> None:
        super().notify_style_update()
        if self.is_mounted:
            self.call_after_refresh(self._update_bg)

    def _on_theme_changed(self, _theme: object) -> None:
        self.call_after_refresh(self._update_bg)

    def _on_screen_layout(self, _screen: object) -> None:
        """After every layout of the screen: the region may have changed."""
        if self._active and self.is_mounted:
            self._refresh_geom()

    # -- visibility (driven by MainScreen) ---------------------------------------

    def set_active(self, active: bool) -> None:
        """Stream only while active (column shown, MainScreen on top)."""
        if active == self._active:
            return
        self._active = active
        if not active:
            self.lift()
            self._stop_geom_retry()
            self._hide_graphics()
            if not self.has_focus:
                self.can_focus = False  # a Ctrl+G that never took
        elif self.is_mounted:
            self._geom_retries = 0
            self._refresh_geom()
        self._send_visible()

    @property
    def is_active(self) -> bool:
        return self._active

    def _send_visible(self) -> None:
        geom = self._geom
        visible = bool(self._active and geom is not None)
        px = geom.stream_px if (visible and geom is not None) else (0, 0)
        if (visible, px) == self._sent_visible:
            return
        self._sent_visible = (visible, px)
        if self.service is None:
            return
        try:
            self.service.set_visible(visible, px)
        except Exception as exc:
            self._last_error = repr(exc)

    # -- sink (service stream thread) ---------------------------------------------

    def push_frame(self, frame: ScreenFrame) -> None:
        """A new frame (thread-safe; latest wins, duplicates are skipped)."""
        if frame.generation < self._generation:
            return  # an old stream (device switch / restart)
        self._generation = frame.generation
        dims = (int(frame.device_w), int(frame.device_h))
        if dims != self._frame_dev:
            self._frame_dev = dims
            self._post(self.SinkSize(dims[0], dims[1], int(frame.rotation)))
        arr = frame.pixels
        prev = self._last_arr
        if (
            prev is not None
            and prev.shape == arr.shape
            and prev.__array_interface__["data"][0]
            != arr.__array_interface__["data"][0]
            and np.array_equal(prev, arr)
        ):
            self.stats["dupes"] += 1
            return
        self._last_arr = arr
        with self._lock:
            self._frame = arr
            self._frame_recv = frame.recv
            self._frame_seq += 1
            self.stats["frames_in"] += 1
        self._wake.set()

    def set_device_size(self, width: int, height: int, rotation: int) -> None:
        """Device size in the current orientation (thread-safe)."""
        self._post(self.SinkSize(int(width), int(height), int(rotation)))

    def set_state(self, state: ScreenState, detail: str) -> None:
        """The service's state changed (thread-safe)."""
        self._post(self.SinkState(state, detail))

    def _post(self, message: Message) -> None:
        try:
            self.post_message(message)
        except Exception:  # unmounted / no app / closed loop
            pass

    def on_device_screen_sink_size(self, message: DeviceScreen.SinkSize) -> None:
        message.stop()
        self.rotation = message.rotation
        self.apply_device_size(message.width, message.height)

    def on_device_screen_sink_state(self, message: DeviceScreen.SinkState) -> None:
        message.stop()
        self.apply_state(message.state, message.detail, at=message.at)

    def apply_device_size(self, width: int, height: int) -> None:
        """Device size in the current orientation (UI thread)."""
        if width <= 0 or height <= 0 or (width, height) == (self.dev_w, self.dev_h):
            return
        self.dev_w, self.dev_h = width, height
        if self._shown:
            # the old image box may be larger than the new one
            self._hide_graphics()
            self.call_later(self._force_repaint)
        self._refresh_geom()
        self.post_message(self.SizeChanged(width, height))

    def apply_state(
        self, state: ScreenState, detail: str = "", at: float | None = None
    ) -> None:
        """The service's state (UI thread): blank the screen unless live.

        CONNECTING keeps the last image only while the service still follows
        the device it came from (a stream restart); after a device switch
        the old device's picture must not look live.

        Args:
            state: The new state.
            detail: The service's technical note.
            at: When the service changed state (``time.monotonic()``);
                a frame received after it belongs to the next stream.
        """
        self.state, self.state_detail = state, detail
        serial = self._service_serial()
        if state is ScreenState.LIVE:
            self._image_serial = serial
        elif state is not ScreenState.CONNECTING or serial != self._image_serial:
            self._blank(at)
        self._render_status()

    def _service_serial(self) -> str | None:
        try:
            return getattr(self.service, "serial", None)
        except Exception:
            return None

    def _blank(self, before: float | None = None) -> None:
        """Drop the image (UI thread).

        ``before``: keep a frame received after this time (the next stream
        is already delivering; its frame is not the stale one).
        """
        with self._lock:
            if (
                before is not None
                and self._frame is not None
                and self._frame_recv > before
            ):
                return
            self._frame = None
            self._frame_seq += 1
            self._blank_seq = self._frame_seq  # frames in the encoder are stale
        self._last_arr = None
        self._payload = None
        if self._hb_strips is not None:
            self._hb_strips = None
            self.refresh()
        if self._shown and self.backend != "halfblock":
            # iTerm2 / sixel pixels stay until Textual rewrites those cells
            # (kitty deletes its image; the repaint is harmless there)
            self.call_later(self._force_repaint)
        self._hide_graphics()

    # -- status line ------------------------------------------------------------

    def _tick_status(self) -> None:
        now = time.monotonic()
        dt = now - self._fps_t0
        if dt > 0:
            self.stats["fps"] = self._fps_frames / dt
        self._fps_frames = 0
        self._fps_t0 = now
        self._render_status()

    def status_words(self) -> str:
        """The plain-words status (``"live · 30 fps"``)."""
        detail = ""
        fps = round(self.stats["fps"])
        if self.state is ScreenState.LIVE and fps > 0:
            detail = f"{fps} fps"
        return status_text(self.state, detail)

    def _render_status(self) -> None:
        line = self.status_line
        if line is None:
            return
        if self._hint and time.monotonic() < self._hint_until:
            line.show(self._hint, hint=True)
        else:
            self._hint = ""
            line.show(self.status_words())

    def show_hint(self, text: str) -> None:
        """Show ``text`` on the status line for a few seconds (a refusal)."""
        self._hint = text
        self._hint_until = time.monotonic() + HINT_SECONDS
        self._render_status()

    # -- geometry ---------------------------------------------------------------

    def cell_px(self) -> tuple[float, float]:
        """Cell size in px (cached; refreshed on resize)."""
        if self._cell_px_fixed is not None:
            return self._cell_px_fixed
        if self._cell_cache is None:
            self._cell_cache = terminal_graphics.current_cell_px()
        return self._cell_cache

    def preferred_cols(self, rows: int) -> int:
        """Width in cells that lets the device (plus bezel) fill ``rows`` rows."""
        return preferred_cols(
            rows,
            self.cell_px(),
            (self.dev_w, self.dev_h),
            halfblock=self.backend == "halfblock",
            sixel=self.backend == "sixel",
            bezel=self.bezel,
        )

    def _current_geom(self) -> Geometry | None:
        region = self.content_region
        if region.width < 2 or region.height < 2:
            return None
        if self.backend == "sixel" and region.bottom >= self.app.size.height:
            # a sixel touching the last row scrolls the terminal
            region = Region(region.x, region.y, region.width, region.height - 1)
        cw, ch = self.cell_px()
        return Geometry.compute(
            region,
            cw,
            ch,
            self.dev_w,
            self.dev_h,
            self.backend == "halfblock",
            self.backend == "sixel",
            self.bezel,
        )

    @property
    def geometry(self) -> Geometry | None:
        """The current geometry (None before the first layout)."""
        return self._geom

    #: While the geometry is None on an active, displayed widget, look again
    #: this often. The geometry is recomputed on Resize, Show, activation,
    #: after every layout of the screen and (graphics backends) every paint;
    #: this is the backstop for a region that was not final at any of them.
    GEOM_RETRY_S = 0.1
    #: Retries per Resize / Show / activation (a column that stays tiny).
    GEOM_RETRY_MAX = 50

    def _refresh_geom(self) -> bool:
        self._update_bg()
        geom = self._current_geom()
        if geom is None:
            self._schedule_geom_retry()
        else:
            self._geom_retries = 0
            self._stop_geom_retry()
        if geom == self._geom:
            return False
        with self._lock:
            self._geom = geom
            self._geom_gen += 1
        self._wake.set()
        self._send_visible()
        return True

    def _retry_geom(self) -> None:
        self._geom_retry = None
        if self.is_mounted:
            self._refresh_geom()

    def _is_displayed(self) -> bool:
        """Shown: no ``display: none`` on this widget or any ancestor."""
        try:
            return all(
                node.display
                for node in self.ancestors_with_self
                if isinstance(node, Widget)
            )
        except Exception:
            return False

    def _schedule_geom_retry(self) -> None:
        """Look again soon -- only while the phone is actually on screen.

        A closed column (``display: none`` on ``#device-col``) has an empty
        region; retrying there would tick for the rest of the session.
        """
        if (
            self._geom_retry is not None
            or self._geom_retries >= self.GEOM_RETRY_MAX
            or not self.is_mounted
            or not self._active
            or not self._is_displayed()
        ):
            return
        self._geom_retries += 1
        self._geom_retry = self.set_timer(self.GEOM_RETRY_S, self._retry_geom)

    def _stop_geom_retry(self) -> None:
        timer, self._geom_retry = self._geom_retry, None
        if timer is not None:
            timer.stop()

    def _update_bg(self) -> None:
        """Background outside the phone body = what Textual paints here."""
        try:
            color = self.rich_style.bgcolor
            bg = tuple(color.get_truecolor()) if color is not None else self._bg
        except Exception:
            return
        if bg != self._bg:
            with self._lock:
                self._bg = bg  # type: ignore[assignment]
                self._bg_gen += 1
            self._wake.set()

    def on_resize(self, _event: events.Resize) -> None:
        self._cell_cache = None
        self._geom_retries = 0
        self._refresh_geom()
        # The compositor places the widget after the Resize: its region
        # (offset, and size on the first layout) is only final then.
        self.call_after_refresh(self._refresh_geom)

    # -- visibility of the graphics --------------------------------------------

    def _is_unobstructed(self) -> bool:
        try:
            app = self.app
            screen = self.screen
            if screen is not app.screen or not self.display or not self.is_mounted:
                return False
            visible = screen._compositor.visible_widgets
            if self not in visible:
                return False
            region = self.content_region
            _mine, my_clip = visible[self]
            if not my_clip.contains_region(region):
                return False  # partly clipped
            ancestors = set(self.ancestors_with_self)
            for widget, (wregion, clip) in visible.items():
                if widget is self:
                    break
                if widget in ancestors:
                    continue
                if wregion.intersection(clip).overlaps(region):
                    return False  # an overlay / toast / tooltip on top
            return True
        except Exception:
            return False

    # -- encode thread ------------------------------------------------------------

    def _encode_loop(self) -> None:
        last = None
        next_t = 0.0
        while not self._stop.is_set():
            self._wake.wait(0.5)
            self._wake.clear()
            if self._stop.is_set():
                break
            if self._ack_ok:
                # back-pressure: wait until the terminal took the last frame,
                # then encode the NEWEST one (nothing queues up anywhere)
                with self._ack_cv:
                    acked = self._ack_cv.wait_for(
                        lambda: not self._inflight or self._stop.is_set(),
                        ACK_TIMEOUT_S,
                    )
                    if not acked:
                        self.stats["stalls"] += 1
                        self._inflight.clear()
                        self._ack_fail += 1
                        if self._ack_fail >= ACK_FAILS_MAX:
                            self._ack_ok = False  # pace by max_fps
            now = time.monotonic()
            if now < next_t:
                time.sleep(next_t - now)
            with self._lock:
                frame, recv, geom = self._frame, self._frame_recv, self._geom
                key = (self._frame_seq, self._geom_gen, self._mark_seq, self._bg_gen)
                gen, bg, mark = self._geom_gen, self._bg, self._mark
            if frame is None or geom is None or key == last:
                continue
            next_t = time.monotonic() + 1.0 / self.max_fps
            t0 = time.perf_counter()
            try:
                payload = self._encode(frame, geom, bg, mark)
            except Exception as exc:
                self._last_error = repr(exc)
                continue
            self.stats["encode_ms"] = (time.perf_counter() - t0) * 1000
            last = key
            loop = self._loop
            if loop is None:
                continue
            try:
                loop.call_soon_threadsafe(
                    self._deliver, gen, geom, payload, recv, key[0]
                )
            except RuntimeError:  # the event loop is closed
                break

    def _composite(
        self,
        frame: np.ndarray,
        g: Geometry,
        bg: tuple[int, int, int],
        mark: tuple[float, float] | None,
    ) -> np.ndarray:
        """Device frame -> canvas with bezel (reused buffer, encode thread)."""
        cache_key = (g, bg, self.bezel)
        if self._bezel_cache is None or self._bezel_cache[0] != cache_key:
            self._bezel_cache = (cache_key, Bezel(g, bg, self.bezel))
        bz = self._bezel_cache[1]
        canvas = bz.canvas
        ix, iy, iw, ih = g.img_off_x, g.img_off_y, g.img_w, g.img_h
        fh, fw = frame.shape[:2]
        if (fw, fh) == (iw, ih):
            canvas[iy : iy + ih, ix : ix + iw] = frame
        elif abs(fw - iw) <= 4 and abs(fh - ih) <= 4:
            # emulator rounding (+-1-2 px): paste centred, no resize
            canvas[iy : iy + ih, ix : ix + iw] = 0
            w, h = min(fw, iw), min(fh, ih)
            sx, sy = (fw - w) // 2, (fh - h) // 2
            dx, dy = ix + (iw - w) // 2, iy + (ih - h) // 2
            canvas[dy : dy + h, dx : dx + w] = frame[sy : sy + h, sx : sx + w]
        else:
            # resize / rotation in progress (always for half-block)
            img = Image.fromarray(np.ascontiguousarray(frame)).resize(
                (iw, ih), Image.BILINEAR
            )
            canvas[iy : iy + ih, ix : ix + iw] = np.asarray(img)
        if mark is not None and self.touch_marker:
            self._draw_mark(canvas, g, mark)
        bz.mask_corners()
        return canvas

    def _draw_mark(
        self, canvas: np.ndarray, g: Geometry, mark: tuple[float, float]
    ) -> None:
        """Instant local feedback: a ring at the touch point."""
        r = max(2.0, self.MARK_RADIUS * (0.25 if g.halfblock else 1.0))
        lw = 1.0 if g.halfblock else 3.0
        x = g.img_off_x + mark[0] * g.img_w / g.dev_w
        y = g.img_off_y + mark[1] * g.img_h / g.dev_h
        outer = r + lw
        x0 = max(g.img_off_x, int(x - outer))
        x1 = min(g.img_off_x + g.img_w, int(x + outer) + 2)
        y0 = max(g.img_off_y, int(y - outer))
        y1 = min(g.img_off_y + g.img_h, int(y + outer) + 2)
        if x0 >= x1 or y0 >= y1:
            return
        yy, xx = np.ogrid[y0:y1, x0:x1]
        dist = np.hypot(xx + 0.5 - x, yy + 0.5 - y)
        canvas[y0:y1, x0:x1][np.abs(dist - r) <= lw / 2] = self.MARK_RGB

    def _set_mark(self, xy: tuple[float, float] | None) -> None:
        if not self.touch_marker and xy is not None:
            return
        with self._lock:
            if xy is None and self._mark is None:
                return
            self._mark = xy
            self._mark_seq += 1
        self._wake.set()

    def _encode(
        self,
        frame: np.ndarray,
        g: Geometry,
        bg: tuple[int, int, int],
        mark: tuple[float, float] | None,
    ) -> list[Strip] | str:
        canvas = self._composite(frame, g, bg, mark)
        if g.halfblock:
            self.stats["bytes"] = 0
            return halfblock_strips(
                canvas, g.region.width, g.region.height, g.box_x, g.box_y, bg
            )
        if self.backend == "iterm":
            data = encode_iterm(canvas)
        elif self.backend == "kitty":
            data = encode_kitty(canvas)
        else:
            data = encode_sixel(canvas)
        self.stats["bytes"] = len(data)
        return data.decode("latin-1")

    # -- output (event loop) --------------------------------------------------------

    def _deliver(
        self, gen: int, geom: Geometry, payload: Any, recv: float, seq: int = 0
    ) -> None:
        if gen != self._geom_gen or not self.is_mounted or not self._active:
            return  # stale geometry / gone / column hidden
        if seq and seq <= self._blank_seq:
            return  # encoded before a blank (emulator gone / device switch)
        self._fps_frames += 1
        self.stats["frames_out"] += 1
        if recv:
            self.lag_ms = (time.monotonic() - recv) * 1000
        if self.backend == "halfblock":
            self._hb_strips = payload
            self.refresh()
            return
        self._payload = (gen, geom, payload)
        if self._is_unobstructed():
            self._emit(new_frame=True)
        elif self._shown:
            self._hide_graphics()

    def _writer_backlog(self) -> int:
        try:
            return int(self.app._driver._writer_thread._queue.qsize())
        except Exception:
            return 0

    def _retry_emit(self) -> None:
        self._retry_timer = None
        if self._payload is not None and self._is_unobstructed():
            self._emit(new_frame=True)

    def _on_ack(self) -> bool:
        """A ``CSI 6n`` answer arrived (driver input thread): ours?

        Only while a frame or probe of ours waits for one; any other answer
        goes on to the app. A timely answer to a probe (``max_fps`` pacing)
        turns ack pacing back on.
        """
        with self._ack_cv:
            if not self._inflight:
                return False
            sent = self._inflight.pop(0)
            waited = time.monotonic() - sent
            self.stats["ack_ms"] = waited * 1000
            if self._ack_ok:
                self._ack_fail = 0
            elif waited <= ACK_TIMEOUT_S:
                self._ack_fail = 0
                self._ack_ok = True
                self.stats["rearms"] += 1
            self._ack_cv.notify_all()
        return True

    def _emit(self, new_frame: bool) -> None:
        """Write the current image.

        ``new_frame``: a stand-alone frame (ack-paced, flushed, dropped when
        Textual's output queue is backed up), as opposed to a re-emit inside
        Textual's own paint.
        """
        if self._payload is None:
            return
        driver = getattr(self.app, "_driver", None)
        if driver is None:
            return
        if new_frame and self._writer_backlog() > WRITER_BACKLOG_MAX:
            self.stats["drops"] += 1
            if self._retry_timer is None:
                self._retry_timer = self.set_timer(0.03, self._retry_emit)
            return
        _gen, g, data = self._payload
        ack = new_frame and self._ack_ok
        now = time.monotonic()
        if ack:
            with self._ack_cv:
                self._inflight.append(now)
        elif new_frame and self._hooked and now - self._probe_t >= ACK_PROBE_S:
            # pacing by max_fps: ask whether the terminal answers again
            ack = True
            self._probe_t = now
            self.stats["probes"] += 1
            with self._ack_cv:
                self._inflight[:] = [now]  # an older probe is long overdue
        x = g.region.x + g.box_x
        y = g.region.y + g.box_y
        seq = f"\x1b7\x1b[{y + 1};{x + 1}H" + data + (DSR_CPR if ack else "") + "\x1b8"
        try:
            if CHUNK_WRITES:  # Windows only, like Textual (#2548)
                for i in range(0, len(seq), WRITE_CHUNK):
                    driver.write(seq[i : i + WRITE_CHUNK])
            else:  # one put: chunks would fill the 30-slot queue and block
                driver.write(seq)
            if new_frame:
                driver.flush()
        except Exception as exc:
            self._last_error = repr(exc)
            return
        self._shown = True

    def _hide_graphics(self) -> None:
        if not self._shown:
            return
        self._shown = False
        self.stats["hides"] += 1
        if self.backend == "kitty":
            try:
                self.app._driver.write(KITTY_DELETE)
            except Exception:
                pass
        # iTerm2 / sixel: Textual has already overwritten the cells

    def _after_textual_paint(self, update: object) -> None:
        """Inside Textual's synchronized update, after its cells were written."""
        if not self.is_mounted:
            return
        geom_changed = self._refresh_geom()
        if not self._active or not self._is_unobstructed():
            if self._shown:
                self._hide_graphics()
                if self.backend != "kitty":
                    # pixels outside the cells Textual rewrote may remain
                    self.app.call_later(self._force_repaint)
            return
        if geom_changed:
            if self._shown:
                self._hide_graphics()
                self.app.call_later(self._force_repaint)
            return  # a new payload is on its way
        if self._payload is None or self._payload[0] != self._geom_gen:
            return
        if not self._shown or _update_touches(update, self.content_region):
            self.stats["reemits"] += 1
            self._emit(new_frame=False)

    def _force_repaint(self) -> None:
        try:
            screen = self.app.screen
            screen._compositor._dirty_regions.add(screen.size.region)
            screen.refresh()
        except Exception as exc:
            self._last_error = repr(exc)

    # -- Textual rendering -------------------------------------------------------

    def render_line(self, y: int) -> Strip:
        width = self.content_region.width or self.size.width
        strips = self._hb_strips
        if self.backend == "halfblock" and strips is not None and y < len(strips):
            return strips[y].crop(0, width)
        return Strip.blank(width, self.rich_style)

    # -- input ------------------------------------------------------------------

    def _refresh_policy(self) -> None:
        if self.policy is not None:
            try:
                self.policy()
            except Exception:
                pass

    def _refused(self, reason: str | None) -> bool:
        if reason:
            self.show_hint(reason)
            return True
        return False

    def _dev_xy(self, event: events.MouseEvent) -> tuple[float, float, bool]:
        g = self._geom
        if g is None:
            return 0.0, 0.0, False
        region = self.content_region
        sx, sy = float(event.pointer_screen_x), float(event.pointer_screen_y)
        if not getattr(getattr(self.app, "_driver", None), "_mouse_pixels", False):
            sx += 0.5  # whole-cell reports: the cell centre
            sy += 0.5
        return g.to_device(sx - region.x, sy - region.y)

    def on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button != 1 or self.service is None:
            return
        x, y, inside = self._dev_xy(event)
        if not inside:
            return  # bezel / background: nothing happens
        event.stop()
        event.prevent_default()
        if self._down is not None:  # a missed UP (released outside the app)
            self.lift()
        self._refresh_policy()
        if self._refused(self.service.touch("down", int(x), int(y))):
            return
        self.capture_mouse()
        self._down = (x, y)
        self._last_xy = (x, y)
        if self._mark_timer is not None:
            self._mark_timer.stop()
            self._mark_timer = None
        self._set_mark((x, y))

    def on_mouse_move(self, event: events.MouseMove) -> None:
        if self._down is None or self.service is None:
            return
        event.stop()
        x, y, _inside = self._dev_xy(event)  # clamped to the edge mid-drag
        if (x, y) != self._last_xy:
            self._last_xy = (x, y)
            # A lock (replay) may start mid-drag: the service lifts the held
            # finger when the policy locks; the drag ends here too.
            self._refresh_policy()
            if self._refused(self.service.touch("move", int(x), int(y))):
                self._release()
                self._set_mark(None)
                return
            self._set_mark((x, y))

    def on_mouse_up(self, event: events.MouseUp) -> None:
        if self._down is None:
            return
        event.stop()
        x, y, _inside = self._dev_xy(event)
        self._release()
        if self.service is not None:
            self.service.touch("up", int(x), int(y))
        # keep the ring briefly so a quick tap is still visible
        self._mark_timer = self.set_timer(
            self.MARK_LINGER_S, lambda: self._set_mark(None)
        )

    def _release(self) -> None:
        self._down = None
        try:
            if self.app.mouse_captured is self:
                self.release_mouse()
        except Exception:
            pass

    def lift(self) -> None:
        """Release a held touch or wheel drag (blur, hide, modal, unmount).

        The service sends the UP itself; the device must never keep a finger
        down.
        """
        if self._down is not None:
            self._release()
            self._set_mark(None)
        if self.service is not None:
            try:
                self.service.lift()
            except Exception:
                pass

    def _wheel(self, event: events.MouseEvent, dy: int) -> None:
        if self.service is None:
            return
        x, y, inside = self._dev_xy(event)
        if not inside:
            return
        event.stop()
        event.prevent_default()
        self._refresh_policy()
        self._refused(self.service.wheel(int(x), int(y), dy))

    def on_mouse_scroll_down(self, event: events.MouseScrollDown) -> None:
        self._wheel(event, 1)

    def on_mouse_scroll_up(self, event: events.MouseScrollUp) -> None:
        self._wheel(event, -1)

    def send_key(self, name: str) -> None:
        """Send one W3C key (``GoBack``, ``GoHome``, ``AppSwitch``, ...)."""
        if self.service is None:
            self.show_hint("the device screen is off")
            return
        self._refresh_policy()
        self._refused(self.service.key(name))

    def action_device_key(self, name: str) -> None:
        self.send_key(name)

    def on_key(self, event: events.Key) -> None:
        """Keys go to the phone while it has the focus."""
        name = self.KEYMAP.get(event.key)
        if name is not None:
            event.stop()
            event.prevent_default()
            self.send_key(name)
            return
        if event.character and event.is_printable:
            event.stop()
            event.prevent_default()
            if self.service is None:
                return
            self._refresh_policy()
            self._refused(self.service.text(event.character))
        # tab, Ctrl+..., other F-keys: the bindings handle them

    def on_paste(self, event: events.Paste) -> None:
        event.stop()
        if not event.text or self.service is None:
            return
        self._refresh_policy()
        self._refused(self.service.paste(event.text))


class DeviceStatus(Static):
    """One plain-words status line under the phone (no markup)."""

    DEFAULT_CSS = """
    DeviceStatus {
        height: 1;
        width: 1fr;
        color: $lens-dim;
        content-align: center middle;
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }
    DeviceStatus.-hint {
        color: $lens-warn;
    }
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("markup", False)
        super().__init__(*args, **kwargs)

    def show(self, text: str, hint: bool = False) -> None:
        """Show ``text`` (``hint``: a refusal, in the warning colour)."""
        self.set_class(hint, "-hint")
        self.update(text)


class DeviceKeyWord(Static):
    """A clickable plain word (Back / Home / Recents)."""

    DEFAULT_CSS = """
    DeviceKeyWord {
        width: auto;
        color: $lens-dim;
    }
    DeviceKeyWord:hover {
        color: $lens-accent;
        text-style: underline;
    }
    """

    def __init__(self, label: str, key_name: str, device: DeviceScreen) -> None:
        super().__init__(label, classes="device-key", markup=False)
        self.key_name = key_name
        self._device = weakref.ref(device)

    def on_click(self, event: events.Click) -> None:
        event.stop()
        device = self._device()
        if device is not None:
            device.send_key(self.key_name)


#: The words under the phone and the keys they send.
DEVICE_KEY_WORDS = (("Back", "GoBack"), ("Home", "GoHome"), ("Recents", "AppSwitch"))


class DeviceKeys(Horizontal):
    """One row of clickable words: Back · Home · Recents."""

    DEFAULT_CSS = """
    DeviceKeys {
        height: 1;
        width: 1fr;
        align: center middle;
    }
    DeviceKeys > .device-sep {
        width: auto;
        color: $lens-muted;
    }
    """

    def __init__(self, device: DeviceScreen, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._device = device

    def compose(self) -> ComposeResult:
        for n, (label, key_name) in enumerate(DEVICE_KEY_WORDS):
            if n:
                yield Static(" · ", classes="device-sep", markup=False)
            yield DeviceKeyWord(label, key_name, self._device)


__all__ = [
    "DEVICE_KEY_WORDS",
    "Bezel",
    "DeviceKeyWord",
    "DeviceKeys",
    "DeviceScreen",
    "DeviceStatus",
    "Geometry",
    "encode_iterm",
    "encode_jpeg",
    "encode_kitty",
    "encode_sixel",
    "halfblock_strips",
    "preferred_cols",
]
