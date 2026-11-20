"""Screenshot image helpers (PNG bytes): R1 "same screen" and markers.

R1, one implementation shared by Tracking (a screen-change shot equal to the
previous screen is dropped) and the report engine (R4: a gap-fill image that
still shows the previous screen is refused); :func:`mark_shot` draws an input
onto a copy of a Tracking screenshot (``tracking.mark_screenshots``). Pure
Pillow, no service state.
"""

from __future__ import annotations

import functools
import io
import logging
import math
from typing import Any

logger = logging.getLogger(__name__)

#: A grayscale thumbnail about this many px wide (an integer box reduction) ...
SAME_THUMB_W = 96
#: ... blurred with this Gaussian radius (thumbnail px) ...
SAME_BLUR = 2.0
#: ... without the outer edge columns (scrollbars) and the top strip
#: (status bar: clock, icons), as fractions of the frame ...
SAME_EDGE = 0.04
SAME_TOP = 0.06
#: ... compared at the best of these shifts (thumbnail px, x and y: about
#: +-11 / +-55 px on a 1080-wide frame -- a content nudge, a scroll offset).
SAME_SHIFT = (1, 5)
#: A frame whose distance to another (mean absolute grey difference, 0-255)
#: is at most this is the same screen. Calibrated on the 88 shots of E2E
#: rounds 1-5 (DESIGN_FINAL §12 R1): same screen and state <= 0.51 (748
#: pairs; round 5 #66 vs #65: 0.07), different screens >= 3.48 (2892 pairs;
#: a blank frame vs a sparse list, >= 4.8 otherwise); synthetic scroll
#: offsets up to 50 px <= 1.28. Near the log-midpoint (1.34), above the
#: scroll offsets: 2.3x below the closest different pair.
SAME_MAX_DIFF = 1.5


@functools.lru_cache(maxsize=4)
def _screen_thumb(png: bytes) -> Any:
    """The blurred grayscale thumbnail :func:`frame_distance` compares
    (:data:`SAME_THUMB_W` .. :data:`SAME_TOP`); None when ``png`` does not
    decode. Cached: a before-tap frame serves every line of its change.
    """
    try:
        from PIL import Image, ImageFilter

        with Image.open(io.BytesIO(png)) as im:
            gray = im.convert("L")
    except Exception:
        return None
    w, h = gray.size
    if w < 16 or h < 16:
        return None
    edge = round(w * SAME_EDGE)
    gray = gray.crop((edge, round(h * SAME_TOP), w - edge, h))
    gray = gray.reduce(max(1, round(w / SAME_THUMB_W)))
    return gray.filter(ImageFilter.GaussianBlur(SAME_BLUR))


def frame_distance(png_a: bytes, png_b: bytes) -> float | None:
    """R1: how far apart two screenshots look -- the mean absolute grey
    difference (0-255) of their thumbnails (:func:`_screen_thumb`) at the
    best alignment within :data:`SAME_SHIFT`. Blur and the shifts absorb what
    changes on a screen that stays put: a scrollbar fading, content moving a
    pixel or two, a small scroll offset; the crop drops the status bar.
    None when either frame does not decode or the sizes differ.
    """
    from PIL import ImageChops, ImageStat

    a, b = _screen_thumb(png_a), _screen_thumb(png_b)
    if a is None or b is None or a.size != b.size:
        return None
    w, h = a.size
    sx, sy = SAME_SHIFT
    best: float | None = None
    for dy in range(-sy, sy + 1):
        for dx in range(-sx, sx + 1):
            box_a = (max(0, dx), max(0, dy), w + min(0, dx), h + min(0, dy))
            box_b = (max(0, -dx), max(0, -dy), w + min(0, -dx), h + min(0, -dy))
            diff = ImageChops.difference(a.crop(box_a), b.crop(box_b))
            mean = float(ImageStat.Stat(diff).mean[0])
            best = mean if best is None else min(best, mean)
    return best


def same_screen(png_a: bytes | None, png_b: bytes | None) -> bool:
    """R1: the two screenshots show the same screen (:func:`frame_distance`
    at most :data:`SAME_MAX_DIFF`). False when either cannot be compared.
    """
    if not png_a or not png_b:
        return False
    try:
        d = frame_distance(png_a, png_b)
    except Exception as exc:
        logger.debug(f"frames: frame distance failed: {exc}")
        return False
    return d is not None and d <= SAME_MAX_DIFF


# ---------------------------------------------------------------------------
# screenshot markers (tracking.mark_screenshots)
# ---------------------------------------------------------------------------

#: Marker colours: the AI highlight slot colours of :mod:`sandroid.tui.themes`
#: (``HIGHLIGHT_DARK``), which no lens theme changes. Tap pink, long press
#: violet, swipe teal, typing lime; every stroke on a dark halo so it reads
#: on light and dark screens alike.
MARK_TAP = "#f472b6"
MARK_LONG_PRESS = "#c084fc"
MARK_SWIPE = "#2dd4bf"
MARK_TEXT = "#a3e635"
MARK_HALO = "#06121f"
#: Typed text in a typing marker's label is clipped to this many characters.
MARK_TEXT_MAX = 40


def _mark_font(size: int) -> Any:
    from PIL import ImageFont

    try:
        return ImageFont.load_default(size=size)
    except (TypeError, OSError):  # Pillow < 10.1 or no FreeType
        return ImageFont.load_default()


def mark_shot(png: bytes, mark: dict[str, Any]) -> bytes | None:
    """A copy of the screenshot ``png`` with the input drawn on it (the
    original is never changed: its sha256 is the evidence).

    ``mark``: ``kind`` (``tap``, ``long_press``, ``swipe``, ``text``),
    ``screen`` (``[w, h]`` the coordinates are in), ``xy`` (the touch
    point), ``bounds`` (``[l, t, r, b]`` of the element or field), ``path``
    (swipe points ``[x, y, ...]``), ``text`` (typed text).

    tap: a ring at the point and a box around the element; long press: a
    double ring and the box; swipe: a line along the path with an arrow
    head; typing: a box around the field with the typed text as a label.

    Returns:
        The marked PNG, or None (nothing to draw, or ``png`` does not decode).
    """
    try:
        from PIL import Image, ImageDraw

        with Image.open(io.BytesIO(png)) as im:
            img = im.convert("RGB")
    except Exception as exc:
        logger.debug(f"frames: cannot mark a shot: {exc}")
        return None
    w, h = img.size
    screen = mark.get("screen") or [w, h]
    try:
        fx, fy = w / float(screen[0]), h / float(screen[1])
    except (TypeError, ValueError, ZeroDivisionError, IndexError):
        fx = fy = 1.0
    unit = max(2, round(min(w, h) / 270))  # 4 px on a 1080 px wide frame
    draw = ImageDraw.Draw(img)
    drawn = False

    def pt(x: Any, y: Any) -> tuple[float, float]:
        return float(x) * fx, float(y) * fy

    def box(b: Any, colour: str) -> tuple[float, float, float, float] | None:
        if not (isinstance(b, (list, tuple)) and len(b) == 4):
            return None
        x0, y0 = pt(b[0], b[1])
        x1, y1 = pt(b[2], b[3])
        if x1 <= x0 or y1 <= y0:
            return None
        rect = (x0, y0, x1, y1)
        draw.rectangle(rect, outline=MARK_HALO, width=unit * 2)
        draw.rectangle(rect, outline=colour, width=unit)
        return rect

    def ring(xy: Any, r: float, colour: str) -> bool:
        if not (isinstance(xy, (list, tuple)) and len(xy) >= 2):
            return False
        if xy[0] is None or xy[1] is None:
            return False
        cx, cy = pt(xy[0], xy[1])
        draw.ellipse(
            (cx - r, cy - r, cx + r, cy + r), outline=MARK_HALO, width=unit * 2
        )
        draw.ellipse((cx - r, cy - r, cx + r, cy + r), outline=colour, width=unit)
        return True

    kind = mark.get("kind")
    radius = 9 * unit
    if kind in ("tap", "long_press"):
        colour = MARK_TAP if kind == "tap" else MARK_LONG_PRESS
        drawn = box(mark.get("bounds"), colour) is not None
        drawn = ring(mark.get("xy"), radius, colour) or drawn
        if kind == "long_press":
            drawn = ring(mark.get("xy"), radius * 1.6, colour) or drawn
    elif kind == "swipe":
        pts = [
            pt(p[0], p[1])
            for p in mark.get("path") or []
            if isinstance(p, (list, tuple)) and len(p) >= 2
        ]
        if len(pts) >= 2:
            draw.line(pts, fill=MARK_HALO, width=unit * 3, joint="curve")
            draw.line(pts, fill=MARK_SWIPE, width=unit, joint="curve")
            (ax, ay), (bx, by) = pts[-2], pts[-1]
            for p in reversed(pts[:-1]):  # the last distinct direction
                if abs(p[0] - bx) + abs(p[1] - by) > unit:
                    ax, ay = p
                    break
            ang = math.atan2(by - ay, bx - ax)
            head = 6 * unit
            wing = [
                (bx - head * math.cos(ang - s), by - head * math.sin(ang - s))
                for s in (0.45, -0.45)
            ]
            draw.polygon([(bx, by), *wing], fill=MARK_SWIPE, outline=MARK_HALO)
            ring(mark.get("xy"), radius * 0.6, MARK_SWIPE)
            drawn = True
    elif kind == "text":
        rect = box(mark.get("bounds"), MARK_TEXT)
        text = " ".join(str(mark.get("text") or "").split())
        if len(text) > MARK_TEXT_MAX:
            text = text[: MARK_TEXT_MAX - 1] + "…"
        if rect is not None and text:
            font = _mark_font(max(12, 7 * unit))
            left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
            tw, th = right - left, bottom - top
            pad = unit * 2
            x = max(0.0, min(rect[0], w - tw - 2 * pad))
            y = rect[1] - th - 2 * pad - unit
            if y < 0:
                y = rect[3] + unit  # no room above: below the field
            draw.rectangle((x, y, x + tw + 2 * pad, y + th + 2 * pad), fill=MARK_HALO)
            draw.text((x + pad - left, y + pad - top), text, fill=MARK_TEXT, font=font)
        drawn = rect is not None
    if not drawn:
        return None
    out = io.BytesIO()
    img.save(out, "PNG", compress_level=1)
    return out.getvalue()
