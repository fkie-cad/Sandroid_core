"""The grpc-free half of the emulator gRPC client.

Everything here imports without grpcio/protobuf (and without numpy), so it
is usable and testable without the ``screen`` extra:

* discovery of a running emulator's gRPC endpoint (``pid_<pid>.ini`` files
  the emulator writes when it was started with ``-grpc <port>``),
* :func:`parse_image`, a zero-copy decoder of a serialized ``Image``
  message (the frame stream's payload),
* layout-safe typing (:data:`SAFE_CHARS`) and the rotation mapping of
  touch coordinates (:func:`to_native`),
* :class:`ScreenRpcError`, the grpc-free form of an RPC failure.
"""

from __future__ import annotations

import configparser
import hashlib
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

RpcErrorKind = Literal["auth", "unavailable", "cancelled", "other"]


class ScreenRpcError(Exception):
    """An emulator RPC failed (grpc-free, so callers need not import grpc).

    Attributes:
        kind: ``auth`` (UNAUTHENTICATED / UNIMPLEMENTED / PERMISSION_DENIED:
            retrying cannot help), ``unavailable`` (emulator not reachable,
            deadline exceeded), ``cancelled`` (we cancelled the call) or
            ``other``.
        code: The gRPC status code name, e.g. ``"UNAUTHENTICATED"``.
    """

    def __init__(self, kind: RpcErrorKind, code: str, details: str = "") -> None:
        super().__init__(f"{code}: {details}" if details else code)
        self.kind: RpcErrorKind = kind
        self.code = code
        self.details = details


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discovery_dirs() -> list[Path]:
    """Candidate ``avd/running`` directories for this host OS.

    macOS is verified (emulator log: "Advertising in: ..."). Linux and
    Windows follow the emulator's ConfigDirs::getDiscoveryDirectory
    (``XDG_RUNTIME_DIR``, else ``/run/user/<uid>``; Windows: the temp dir).
    """
    home = Path.home()
    cands: list[Path] = []
    if sys.platform == "darwin":
        cands.append(home / "Library" / "Caches" / "TemporaryItems")
    elif sys.platform.startswith("win"):
        cands.extend(
            Path(os.environ[var]) for var in ("TEMP", "TMP") if os.environ.get(var)
        )
        if os.environ.get("LOCALAPPDATA"):
            cands.append(Path(os.environ["LOCALAPPDATA"]) / "Temp")
    else:
        if os.environ.get("XDG_RUNTIME_DIR"):
            cands.append(Path(os.environ["XDG_RUNTIME_DIR"]))
        getuid = getattr(os, "getuid", None)
        if getuid is not None:
            cands.append(Path(f"/run/user/{getuid()}"))
    # Fallbacks seen in older emulator builds / custom homes.
    if os.environ.get("ANDROID_EMULATOR_HOME"):
        cands.append(Path(os.environ["ANDROID_EMULATOR_HOME"]))
    cands.append(home / ".android")
    out: list[Path] = []
    for cand in cands:
        path = cand / "avd" / "running"
        if path not in out:
            out.append(path)
    return out


def _pid_alive(pid: int) -> bool:
    """True if ``pid`` runs and (when readable) looks like an emulator.

    A discovery file survives ``emu kill``; its pid may even be reused by
    an unrelated process later, hence the process-name check (qemu or
    emulator). Unreadable names count as alive.
    """
    if pid <= 0:
        return False
    try:
        import psutil
    except ImportError:  # pragma: no cover - psutil is a core dependency
        psutil = None  # type: ignore[assignment]
    if psutil is not None:
        try:
            name = psutil.Process(pid).name().lower()
        except psutil.NoSuchProcess:
            return False
        except Exception:
            return True
        return "qemu" in name or "emulator" in name
    if sys.platform.startswith("win"):  # pragma: no cover
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


@dataclass(frozen=True)
class EmulatorEndpoint:
    """A running emulator's gRPC endpoint (from its discovery file).

    The token is per launch: read it again for every connect. It never
    appears in ``repr``.
    """

    console_port: int
    grpc_port: int
    token: str | None = field(default=None, repr=False)
    avd: str | None = None
    pid: int | None = None
    ini_path: Path | None = None

    @property
    def serial(self) -> str:
        """The adb serial, ``emulator-<console port>``."""
        return f"emulator-{self.console_port}"

    @property
    def identity(self) -> tuple[int | None, int, str]:
        """Compares two endpoints (pid, port, token digest) without the token."""
        digest = hashlib.sha256((self.token or "").encode()).hexdigest()[:12]
        return (self.pid, self.grpc_port, digest)


def _read_ini(path: Path) -> dict[str, str]:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    parser.read_string("[x]\n" + path.read_text(errors="replace"))
    return dict(parser["x"])


def list_emulators(dirs: list[Path] | None = None) -> list[EmulatorEndpoint]:
    """All live emulators that advertise a gRPC endpoint.

    Discovery files of dead processes (stale after a kill) are skipped, and
    so are files without ``port.serial`` or ``grpc.port``.

    Args:
        dirs: Directories to scan (default :func:`discovery_dirs`).
    """
    found: list[EmulatorEndpoint] = []
    for directory in discovery_dirs() if dirs is None else dirs:
        if not directory.is_dir():
            continue
        for ini in sorted(directory.glob("pid_*.ini")):
            try:
                pid = int(ini.stem.split("_", 1)[1])
                values = _read_ini(ini)
                console = int(values["port.serial"])
                grpc_port = int(values["grpc.port"])
            except (ValueError, OSError, KeyError, IndexError, configparser.Error):
                continue
            if not _pid_alive(pid):
                continue
            found.append(
                EmulatorEndpoint(
                    console_port=console,
                    grpc_port=grpc_port,
                    token=values.get("grpc.token") or None,
                    avd=values.get("avd.id"),
                    pid=pid,
                    ini_path=ini,
                )
            )
    return found


def serial_console_port(serial: str | None) -> int | None:
    """Console port of an emulator serial (``emulator-5554`` -> 5554), else None."""
    if not serial or not serial.startswith("emulator-"):
        return None
    try:
        return int(serial.split("-", 1)[1])
    except ValueError:
        return None


def find_emulator(serial: str, dirs: list[Path] | None = None) -> EmulatorEndpoint:
    """The gRPC endpoint of exactly ``serial`` (read fresh, token included).

    Args:
        serial: ``emulator-<console port>``; anything else never matches.
        dirs: Directories to scan (default :func:`discovery_dirs`).

    Raises:
        LookupError: No live discovery file for that console port (the
            emulator was started without ``-grpc``, or it is gone).
    """
    port = serial_console_port(serial)
    if port is None:
        raise LookupError(f"{serial!r} is not an emulator serial")
    matches = [ep for ep in list_emulators(dirs) if ep.console_port == port]
    if not matches:
        raise LookupError(
            f"No gRPC endpoint for {serial} (started without -grpc, or gone)"
        )

    def _mtime(ep: EmulatorEndpoint) -> float:
        try:
            return ep.ini_path.stat().st_mtime if ep.ini_path else 0.0
        except OSError:
            return 0.0

    return max(matches, key=_mtime)


# ---------------------------------------------------------------------------
# Frames: zero-copy Image parser
# ---------------------------------------------------------------------------

#: ImageFormat.ImgFormat values -> bytes per pixel (PNG = 0 is not handled).
_BPP = {1: 4, 2: 3}  # RGBA8888, RGB888


@dataclass(frozen=True, slots=True)
class RawImage:
    """One decoded ``Image`` message.

    Attributes:
        pixels: Top-down row-major pixels: a memoryview into the received
            message (zero-copy) or bytes. Read-only.
        width: Image width in px (the requested, scaled size).
        height: Image height in px.
        rotation: 0 portrait, 1 landscape, 2 reverse portrait, 3 reverse
            landscape (the emulator's ``Rotation.SkinRotation``).
        seq: Frame sequence number.
        ts_us: Emulator-side production timestamp (unix us, host clock).
        bpp: 3 (RGB888) or 4 (RGBA8888).
    """

    pixels: memoryview | bytes
    width: int
    height: int
    rotation: int
    seq: int
    ts_us: int
    bpp: int = 3


def _varint(buf: memoryview | bytes, i: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        byte = buf[i]
        i += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _fields(
    buf: memoryview | bytes, i: int, end: int
) -> dict[int, int | tuple[int, int]]:
    """Minimal protobuf wire walk: ``{field_no: int | (start, end)}``."""
    out: dict[int, int | tuple[int, int]] = {}
    while i < end:
        key, i = _varint(buf, i)
        fno, wtype = key >> 3, key & 7
        if wtype == 0:
            out[fno], i = _varint(buf, i)
        elif wtype == 2:
            length, i = _varint(buf, i)
            if i + length > end:
                raise ValueError("length-delimited field past the end")
            out[fno] = (i, i + length)
            i += length
        elif wtype == 1:
            i += 8
        elif wtype == 5:
            i += 4
        else:  # groups: not used by this proto
            raise ValueError(f"unexpected wire type {wtype}")
    if i != end:
        raise ValueError("truncated message")
    return out


def _int(value: int | tuple[int, int] | None) -> int:
    return value if isinstance(value, int) else 0


def _span(value: int | tuple[int, int] | None) -> tuple[int, int] | None:
    return value if isinstance(value, tuple) else None


def parse_image(buf: bytes | memoryview) -> RawImage | None:
    """Decode a serialized ``Image`` without protobuf and without copying.

    The upb protobuf runtime copies a ``bytes`` field on parse AND on every
    attribute access (~1 ms per access at 1080 px); here the pixels are a
    memoryview into the message bytes gRPC already handed over.

    ``Image``: format=1 (ImageFormat), image=4, seq=5, timestampUs=6.
    ``ImageFormat``: format=1, rotation=2 (Rotation{rotation=1}), width=3,
    height=4.

    Returns:
        The image, or None for an empty image (display inactive), a PNG or
        a pixel buffer whose size does not match width x height.

    Raises:
        ValueError: Malformed wire data (the caller may fall back to the
            protobuf runtime).
    """
    try:
        top = _fields(buf, 0, len(buf))
        img = _span(top.get(4))
        fmt = _span(top.get(1))
        if not img or not fmt or img[0] == img[1]:
            return None
        fields = _fields(buf, fmt[0], fmt[1])
        width, height = _int(fields.get(3)), _int(fields.get(4))
        if not width or not height:
            return None
        rotation = 0
        rot_span = _span(fields.get(2))
        if rot_span is not None:
            rotation = _int(_fields(buf, rot_span[0], rot_span[1]).get(1))
        bpp = _BPP.get(_int(fields.get(1)))
    except IndexError as exc:
        raise ValueError(f"truncated message: {exc}") from exc
    if bpp is None or (img[1] - img[0]) != width * height * bpp:
        return None
    return RawImage(
        pixels=memoryview(buf)[img[0] : img[1]],
        width=width,
        height=height,
        rotation=rotation % 4,
        seq=_int(top.get(5)),
        ts_us=_int(top.get(6)),
        bpp=bpp,
    )


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

#: gRPC ``key`` names are translated to evdev with a US layout, but the guest
#: maps evdev with ITS hardware-keyboard layout. On a German guest y/z swap
#: and most symbols come out wrong (tested: "-" -> "ß", "/" -> "-"). Only
#: these characters are the same on US and QWERTZ; everything else goes
#: through the clipboard (when allowed).
SAFE_CHARS = frozenset("abcdefghijklmnopqrstuvwxABCDEFGHIJKLMNOPQRSTUVWX0123456789 .,")


def layout_safe(text: str) -> bool:
    """True if every character types the same on a US and a German guest."""
    return all(c in SAFE_CHARS for c in text)


def to_native(
    x: float, y: float, rotation: int, native_w: int, native_h: int
) -> tuple[int, int]:
    """Current-orientation device px -> the emulator's native portrait px.

    ``sendTouch`` takes native (rotation 0) coordinates; the emulator does
    not rotate them (tested on 35.4.9).
    """
    w, h, r = native_w, native_h, rotation % 4
    if r == 1:  # landscape (+90)
        return int(w - 1 - y), int(x)
    if r == 2:  # reverse portrait
        return int(w - 1 - x), int(h - 1 - y)
    if r == 3:  # reverse landscape (-90), what `adb emu rotate` gives
        return int(y), int(h - 1 - x)
    return int(x), int(y)


__all__ = [
    "SAFE_CHARS",
    "EmulatorEndpoint",
    "RawImage",
    "RpcErrorKind",
    "ScreenRpcError",
    "discovery_dirs",
    "find_emulator",
    "layout_safe",
    "list_emulators",
    "parse_image",
    "serial_console_port",
    "to_native",
]
