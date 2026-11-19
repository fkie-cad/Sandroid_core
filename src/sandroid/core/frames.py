"""R1 perceptual "same screen" check between two screenshots (PNG bytes).

One implementation shared by Tracking (R1: a screen-change shot equal to the
previous screen is dropped) and the report engine (R4: a gap-fill image that
still shows the previous screen is refused). Pure Pillow, no service state.
"""

from __future__ import annotations

import functools
import io
import logging
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
