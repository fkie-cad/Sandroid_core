"""Terminal graphics detection for the live device screen (Ctrl+G).

Light on purpose (no numpy, no Textual import at module level): the launcher
calls :func:`detect` once before ``App.run()``, while the terminal still
belongs to us, and the result is cached here for the device screen widget.

Backends, best first:

* ``iterm``     iTerm2 / WezTerm inline images (OSC 1337, JPEG)
* ``kitty``     kitty graphics protocol (one image id, replaced in place)
* ``sixel``     DEC sixel (DA1 attribute 4)
* ``halfblock`` truecolor half-block cells drawn by Textual itself; works
  everywhere, also inside tmux and on Windows

The terminal query (kitty graphics query, XTVERSION, the cell size ``CSI 16t``
and DA1 as the sentinel every terminal answers) runs only on a TTY, takes at
most ~200 ms and restores the tty with ``TCSANOW`` (``TCSAFLUSH`` would throw
away keys typed during startup). Inside tmux no query is sent at all and the
half-block backend is used (tmux passthrough is not supported).
"""

from __future__ import annotations

import os
import re
import sys
import time
from dataclasses import dataclass, field

#: Backends the widget knows, in the order the config names them.
BACKENDS = ("iterm", "kitty", "sixel", "halfblock")
#: kitty image id / placement id the device screen uses (replaced in place).
KITTY_IMAGE_ID = 4242
KITTY_PLACEMENT_ID = 1
#: Deletes the device screen's kitty image (and its placements).
KITTY_DELETE = "\x1b_Ga=d,d=i,i=%d,q=2\x1b\\" % KITTY_IMAGE_ID
#: Total time the pre-run terminal query may take.
QUERY_TIMEOUT_S = 0.2
#: Textual versions whose private paint hooks the graphics backends rely on
#: (``App._display`` / ``_end_update``, the compositor's visible widgets, the
#: driver's writer queue). Other versions get the half-block backend.
GRAPHICS_TEXTUAL_PREFIX = "8.2."


@dataclass
class TermGraphics:
    """What the terminal can show, and the chosen backend.

    Attributes:
        backend: One of :data:`BACKENDS`.
        reason: Plain words for the log ("iTerm2 identified").
        cell_px: Cell size in px ``(w, h)`` from ``CSI 16t``, or None.
        kitty: The kitty graphics query was answered OK (or kitty env).
        sixel: DA1 lists attribute 4.
        iterm: iTerm2 / WezTerm identified.
        tmux: Running inside tmux.
        xtversion: The XTVERSION reply (terminal name and version).
        da1: DA1 attributes.
        queried: Whether the terminal was queried at all.
    """

    backend: str = "halfblock"
    reason: str = ""
    cell_px: tuple[float, float] | None = None
    kitty: bool = False
    sixel: bool = False
    iterm: bool = False
    tmux: bool = False
    xtversion: str = ""
    da1: list[int] = field(default_factory=list)
    queried: bool = False


_RESULT: TermGraphics | None = None


def result() -> TermGraphics | None:
    """The cached :func:`detect` result (None when it never ran)."""
    return _RESULT


def set_result(caps: TermGraphics | None) -> None:
    """Replace the cached result (tests, or a backend forced at runtime)."""
    global _RESULT
    _RESULT = caps


# ---------------------------------------------------------------------------
# tty access (Unix only)
# ---------------------------------------------------------------------------


def query_terminal(queries: str, timeout: float = QUERY_TIMEOUT_S) -> str:
    """Write ``queries`` to the controlling tty, collect the replies.

    Reads until the DA1 reply (the sentinel: terminals answer in order, so
    everything asked before it has arrived too) or until ``timeout``. Must
    run before Textual owns the terminal. Unix only; returns ``""`` on
    Windows or without a controlling tty.

    Args:
        queries: Escape sequences to send (end with DA1, ``CSI c``).
        timeout: Seconds to wait in total.

    Returns:
        The raw replies (latin-1 decoded).
    """
    if os.name == "nt":
        return ""
    import select
    import termios
    import tty

    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        return ""
    buf = b""
    try:
        try:
            old = termios.tcgetattr(fd)
        except termios.error:
            return ""
        try:
            tty.setraw(fd, termios.TCSANOW)
            os.write(fd, queries.encode())
            deadline = time.monotonic() + timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                ready, _, _ = select.select([fd], [], [], left)
                if not ready:
                    break
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                buf += chunk
                if re.search(rb"\x1b\[\?[\d;]*c", buf):
                    break
        finally:
            # TCSANOW: TCSAFLUSH would drop keys typed during startup.
            termios.tcsetattr(fd, termios.TCSANOW, old)
    except Exception:
        return buf.decode("latin-1")
    finally:
        os.close(fd)
    return buf.decode("latin-1")


def tiocgwinsz() -> tuple[int, int, int, int] | None:
    """``(rows, cols, xpixel, ypixel)`` from the kernel (Unix), else None."""
    if os.name == "nt":
        return None
    import fcntl
    import struct
    import termios

    for stream in (sys.__stdout__, sys.__stdin__, sys.__stderr__):
        try:
            data = fcntl.ioctl(stream.fileno(), termios.TIOCGWINSZ, b"\0" * 8)
        except Exception:
            continue
        rows, cols, xpx, ypx = struct.unpack("HHHH", data)
        return rows, cols, xpx, ypx
    return None


def cell_px_from_kernel() -> tuple[float, float] | None:
    """Cell size in px from ``TIOCGWINSZ`` (None when the kernel has none)."""
    size = tiocgwinsz()
    if size and size[0] and size[1] and size[2] and size[3]:
        return size[2] / size[1], size[3] / size[0]
    return None


def current_cell_px(
    queried: tuple[float, float] | None = None,
) -> tuple[float, float]:
    """Best cell size in px now: the ``CSI 16t`` answer, else the kernel's.

    The ``CSI 16t`` answer is exact but taken once at startup; the kernel
    value follows font changes but may include the terminal's inner border
    (xterm: 8.02 x 17.08 for 8 x 17). The query value wins while the two
    agree within 10 %; otherwise (font changed) the floored kernel value.

    Args:
        queried: The startup ``CSI 16t`` value (default: the cached result).

    Returns:
        ``(w, h)`` in px; ``(8.0, 16.0)`` when nothing is known.
    """
    if queried is None and _RESULT is not None:
        queried = _RESULT.cell_px
    kernel = cell_px_from_kernel()
    if queried and (
        not kernel
        or (
            abs(kernel[0] / queried[0] - 1) < 0.1
            and abs(kernel[1] / queried[1] - 1) < 0.1
        )
    ):
        return float(queried[0]), float(queried[1])
    if kernel:
        return float(int(kernel[0])), float(int(kernel[1]))
    return 8.0, 16.0


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def parse_replies(reply: str, caps: TermGraphics) -> None:
    """Fill ``caps`` from the raw terminal replies.

    Args:
        reply: What :func:`query_terminal` returned.
        caps: Updated in place (kitty, xtversion, cell_px, da1, sixel).
    """
    if "\x1b_Gi=31;OK" in reply:
        caps.kitty = True
    match = re.search(r"\x1bP>\|([^\x1b]*)\x1b\\", reply)
    if match:
        caps.xtversion = match.group(1)
    match = re.search(r"\x1b\[6;(\d+);(\d+)t", reply)
    if match and int(match.group(1)) and int(match.group(2)):
        caps.cell_px = (float(match.group(2)), float(match.group(1)))
    match = re.search(r"\x1b\[\?([\d;]*)c", reply)
    if match:
        caps.da1 = [int(x) for x in match.group(1).split(";") if x]
        caps.sixel = 4 in caps.da1[1:]


def choose_backend(caps: TermGraphics, preferred: str = "auto") -> None:
    """Set ``caps.backend`` / ``caps.reason`` from what was detected.

    Args:
        caps: Detection result, updated in place.
        preferred: ``tui.device_screen.backend`` (``auto`` or a backend).
    """
    preferred = (preferred or "auto").strip().lower()
    if preferred in BACKENDS:
        caps.backend, caps.reason = preferred, "set in tui.device_screen.backend"
    elif os.name == "nt":
        caps.backend, caps.reason = "halfblock", "Windows (half-block only)"
    elif caps.tmux:
        caps.backend, caps.reason = "halfblock", "inside tmux (half-block only)"
    elif caps.iterm:
        # iTerm2 3.6 also answers the kitty query, but its kitty mode fell
        # seconds behind under load (prototype measurements).
        caps.backend, caps.reason = "iterm", "iTerm2 / WezTerm identified"
    elif caps.kitty:
        caps.backend, caps.reason = "kitty", "kitty graphics answered"
    elif caps.sixel:
        caps.backend, caps.reason = "sixel", "terminal reports sixel"
    else:
        caps.backend, caps.reason = "halfblock", "no graphics protocol found"


def detect(
    *,
    preferred: str = "auto",
    query: bool = True,
    timeout: float = QUERY_TIMEOUT_S,
) -> TermGraphics:
    """Detect the terminal's graphics support; cache and return the result.

    Called by the launcher before ``App.run()``. Queries the terminal only
    on a TTY, never inside tmux or on Windows, and not when the backend is
    forced to ``halfblock``. Never raises.

    Args:
        preferred: ``tui.device_screen.backend`` (``auto`` or a backend).
        query: Send the terminal query (False: environment only).
        timeout: Seconds the query may take in total.

    Returns:
        The detection result (also kept for :func:`result`).
    """
    caps = TermGraphics()
    try:
        env = os.environ
        caps.tmux = bool(env.get("TMUX"))
        preferred = (preferred or "auto").strip().lower()
        tty_ok = False
        try:
            tty_ok = sys.stdin.isatty() and sys.stdout.isatty()
        except Exception:
            tty_ok = False
        if (
            query
            and tty_ok
            and not caps.tmux
            and os.name != "nt"
            and preferred != "halfblock"
        ):
            queries = (
                "\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\"  # kitty graphics
                "\x1b[>0q"  # XTVERSION
                "\x1b[16t"  # cell size in px
                "\x1b[c"  # DA1 (sentinel)
            )
            parse_replies(query_terminal(queries, timeout), caps)
            caps.queried = True
        name = " ".join(
            (
                env.get("TERM_PROGRAM", ""),
                env.get("LC_TERMINAL", ""),
                caps.xtversion,
            )
        ).lower()
        caps.iterm = (
            "iterm" in name or "wezterm" in name or bool(env.get("WEZTERM_EXECUTABLE"))
        )
        term = env.get("TERM", "")
        if (
            env.get("KITTY_WINDOW_ID") or "kitty" in term or "ghostty" in name
        ) and not caps.tmux:
            caps.kitty = True
        choose_backend(caps, preferred)
    except Exception as exc:  # never break the launch
        caps.backend, caps.reason = "halfblock", f"detection failed: {exc}"
    set_result(caps)
    return caps


def textual_supports_graphics() -> bool:
    """Whether this Textual has the private hooks the graphics backends use.

    Only Textual 8.2.x was verified; any other version, or a missing private
    attribute, means the half-block backend.
    """
    try:
        from importlib.metadata import version

        if not version("textual").startswith(GRAPHICS_TEXTUAL_PREFIX):
            return False
        import inspect

        from textual._compositor import ChopsUpdate, Compositor, LayoutUpdate
        from textual.app import App
        from textual.driver import Driver
        from textual.drivers._writer_thread import WriterThread

        params = list(inspect.signature(App._display).parameters)
        if params != ["self", "screen", "renderable"]:
            return False
        for owner, attr in (
            (App, "_begin_update"),
            (App, "_end_update"),
            (Driver, "process_message"),
            (Compositor, "visible_widgets"),
            (WriterThread, "write"),
        ):
            if not hasattr(owner, attr):
                return False
        return "spans" in inspect.signature(ChopsUpdate.__init__).parameters and (
            "region" in inspect.signature(LayoutUpdate.__init__).parameters
        )
    except Exception:
        return False


def graphics_reset_sequence() -> str:
    """What the terminal reset must also send: deletes a kitty image.

    Empty unless the kitty backend was chosen (other terminals never get a
    kitty escape). Cell based images (iTerm2, sixel) go with the alternate
    screen.
    """
    caps = _RESULT
    if caps is not None and caps.backend == "kitty":
        return KITTY_DELETE
    return ""


__all__ = [
    "BACKENDS",
    "KITTY_DELETE",
    "KITTY_IMAGE_ID",
    "KITTY_PLACEMENT_ID",
    "TermGraphics",
    "cell_px_from_kernel",
    "choose_backend",
    "current_cell_px",
    "detect",
    "graphics_reset_sequence",
    "parse_replies",
    "query_terminal",
    "result",
    "set_result",
    "textual_supports_graphics",
]
