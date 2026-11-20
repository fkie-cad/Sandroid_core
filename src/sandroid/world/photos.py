"""Photo files of the world: the download cache and the host-side processing.

The photo pack ships only ``assets/world/photos/manifest.yaml`` plus the ten
authored screenshots (``assets/world/photos/screenshots``). The camera photos
are fetched on demand into ``$XDG_CACHE_HOME/sandroid/world/photos/<id>.jpg``
(:func:`ensure_photos`), each verified by its SHA-256. A folder of
pre-downloaded files can stand in for the download
(``SDROID_WORLD_PHOTOS_DIR``) or be copied into the cache
(:func:`import_photos`).

Processing (:func:`process_photo`) is the mandatory privacy step before a
photo reaches a device: only the pixels of the first frame survive (EXIF
orientation applied), every original metadata block is dropped (EXIF with GPS
and MakerNote, XMP, IPTC, comments, thumbnails, ICC, the MPO second image),
and the JPEG is re-encoded with NEW EXIF: the persona phone's Make/Model, the
capture time in the world's time zone and the world's GPS position.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import email.utils
import hashlib
import io
import logging
import os
import shutil
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sandroid.world.packs import BUILTIN_DIR, photo_cache_dir

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    from sandroid.world.manifest import WorldManifest
    from sandroid.world.packs import PackSet

logger = logging.getLogger(__name__)

#: A local folder of pre-downloaded photo files (named like the manifest's
#: ``file`` basename) that is used in place of the download.
PHOTOS_DIR_ENV = "SDROID_WORLD_PHOTOS_DIR"
#: The authored screenshots shipped in the package (no URL).
SCREENSHOT_DIR = BUILTIN_DIR / "photos" / "screenshots"
#: Generic User-Agent for the downloads (no personal data).
USER_AGENT = "Sandroid-world-photos/1.0 (python-urllib)"
#: Seconds between two requests (at most one per second).
MIN_REQUEST_INTERVAL_S = 1.0
#: Attempts per photo (429 and 5xx are retried, honouring Retry-After).
MAX_ATTEMPTS = 4
#: Longest Retry-After honoured; longer waits fail the photo instead.
MAX_RETRY_AFTER_S = 120.0
#: JPEG quality of the re-encoded photos.
JPEG_QUALITY = 90

# EXIF tags
_MAKE, _MODEL, _ORIENTATION, _DATETIME, _SOFTWARE = (
    0x010F,
    0x0110,
    0x0112,
    0x0132,
    0x0131,
)
_EXIF_IFD, _GPS_IFD = 0x8769, 0x8825


class PhotoError(RuntimeError):
    """A photo could not be fetched, verified or processed."""


# ------------------------------------------------------------------ the cache


@dataclass
class PhotoFetch:
    """Result of :func:`ensure_photos`.

    Attributes:
        paths: Photo id -> a verified local file.
        failed: Photo id -> why it is missing.
        downloaded: Ids fetched over the network in this call.
    """

    paths: dict[str, Path] = field(default_factory=dict)
    failed: dict[str, str] = field(default_factory=dict)
    downloaded: list[str] = field(default_factory=list)


def file_sha256(path: Path) -> str:
    """Return the hex SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _suffix(entry: Mapping[str, Any]) -> str:
    return Path(str(entry.get("file") or "x.jpg")).suffix.lower() or ".jpg"


def cache_name(entry: Mapping[str, Any]) -> str:
    """Return the cache file name of a photo entry: ``<id><ext>``."""
    return f"{entry['id']}{_suffix(entry)}"


def photo_entries(
    manifest: WorldManifest, packs: PackSet | None = None
) -> list[dict[str, Any]]:
    """Return the photo-pack entries the world uses (once each, sorted by id).

    Raises:
        PhotoError: A world photo is not in the photo pack.
    """
    if packs is None:
        from sandroid.world.packs import load_packs

        packs = load_packs()
    pack = packs.photos()
    by_id = {p["id"]: p for p in (pack.data.get("photos") if pack else None) or []}
    out: dict[str, dict[str, Any]] = {}
    for photo in manifest.photos:
        src = photo["source"]
        if src not in by_id:
            raise PhotoError(f"photo {src} is not in the photo pack")
        out[src] = by_id[src]
    return [out[k] for k in sorted(out)]


def _local_candidates(entry: Mapping[str, Any], cache_dir: Path) -> list[Path]:
    name = Path(str(entry.get("file") or "")).name
    out = []
    if not entry.get("url"):
        out.append(SCREENSHOT_DIR / name)
    out.append(cache_dir / cache_name(entry))
    env = os.environ.get(PHOTOS_DIR_ENV)
    if env:
        out += [
            Path(env).expanduser() / name,
            Path(env).expanduser() / cache_name(entry),
        ]
    return out


def ensure_photos(
    entries: Iterable[Mapping[str, Any]],
    cache_dir: Path | None = None,
    *,
    opener: Callable[..., Any] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    min_interval: float = MIN_REQUEST_INTERVAL_S,
    progress: Callable[[str, int, int], None] | None = None,
    download: bool = True,
) -> PhotoFetch:
    """Make every photo available locally, downloading what is missing.

    Lookup per photo: the packaged screenshots (entries without a URL), the
    cache (``<cache_dir>/<id><ext>``), the ``SDROID_WORLD_PHOTOS_DIR`` folder,
    then the photo's URL. Every file is verified against the entry's
    ``sha256``; a mismatching cache file is deleted and fetched again.
    Downloads run one at a time with at most one request per
    ``min_interval`` seconds, a generic User-Agent, 429/5xx retries that
    honour ``Retry-After``, and resume a ``.part`` file with a Range request.

    Args:
        entries: Photo-pack entries (``id``, ``sha256``, ``file``, ``url``).
        cache_dir: The cache; default ``$XDG_CACHE_HOME/sandroid/world/photos``.
        opener: ``urllib.request.urlopen`` stand-in (tests).
        sleep: ``time.sleep`` stand-in (tests).
        clock: ``time.monotonic`` stand-in (tests).
        min_interval: Seconds between two requests.
        progress: Called with ``(id, done, total)`` after each photo.
        download: False only looks locally (a missing photo fails).

    Returns:
        The paths, the failures and what was downloaded.
    """
    cache = Path(cache_dir) if cache_dir else photo_cache_dir()
    items = list(entries)
    result = PhotoFetch()
    fetcher = _Downloader(opener or urllib.request.urlopen, sleep, clock, min_interval)
    for n, entry in enumerate(items, start=1):
        pid = str(entry["id"])
        want = str(entry.get("sha256") or "").lower()
        found = None
        for cand in _local_candidates(entry, cache):
            if cand.is_file():
                if want and file_sha256(cand) == want:
                    found = cand
                    break
                if cand.parent == cache:
                    logger.warning(f"world photos: {cand} fails sha256, fetching again")
                    with contextlib.suppress(OSError):
                        cand.unlink()
        if found is None:
            url = entry.get("url")
            if not url:
                result.failed[pid] = "no local file and no URL"
            elif not want:
                result.failed[pid] = "no sha256 in the photo pack"
            elif not download:
                result.failed[pid] = "not in the cache"
            else:
                try:
                    found = fetcher.fetch(str(url), cache / cache_name(entry), want)
                    result.downloaded.append(pid)
                except PhotoError as exc:
                    result.failed[pid] = str(exc)
        if found is not None:
            result.paths[pid] = found
        if progress:
            progress(pid, n, len(items))
    return result


class _Downloader:
    """Sequential, rate-limited, resumable downloads (one request at a time)."""

    def __init__(
        self,
        opener: Callable[..., Any],
        sleep: Callable[[float], None],
        clock: Callable[[], float],
        min_interval: float,
    ) -> None:
        self.opener = opener
        self.sleep = sleep
        self.clock = clock
        self.min_interval = min_interval
        self.last: float | None = None

    def _pace(self) -> None:
        if self.last is not None:
            wait = self.min_interval - (self.clock() - self.last)
            if wait > 0:
                self.sleep(wait)
        self.last = self.clock()

    def fetch(self, url: str, dest: Path, sha256: str) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        part = dest.with_name(dest.name + ".part")
        error = "no attempt"
        for _attempt in range(MAX_ATTEMPTS):
            have = part.stat().st_size if part.exists() else 0
            headers = {"User-Agent": USER_AGENT}
            if have:
                headers["Range"] = f"bytes={have}-"
            self._pace()
            req = urllib.request.Request(url, headers=headers)
            try:
                with self.opener(req, timeout=60) as resp:
                    status = getattr(resp, "status", 200)
                    mode = "ab" if have and status == 206 else "wb"
                    with open(part, mode) as fh:
                        shutil.copyfileobj(resp, fh, 1 << 20)
            except urllib.error.HTTPError as exc:
                if exc.code == 416 and have:
                    part.unlink()  # the part is complete or bad: start over
                    error = "HTTP 416"
                    continue
                if exc.code == 429 or exc.code >= 500:
                    wait = _retry_after(exc.headers.get("Retry-After"))
                    error = f"HTTP {exc.code}"
                    if wait > MAX_RETRY_AFTER_S:
                        raise PhotoError(f"{error}: Retry-After {wait:.0f}s") from exc
                    self.sleep(max(wait, self.min_interval))
                    continue
                raise PhotoError(f"HTTP {exc.code}") from exc
            except (urllib.error.URLError, OSError) as exc:
                error = f"download failed: {exc}"
                continue  # keep the part: the next attempt resumes it
            got = file_sha256(part)
            if got == sha256:
                part.replace(dest)
                return dest
            part.unlink()
            error = f"sha256 mismatch ({got[:12]})"
        raise PhotoError(error)


def _retry_after(value: str | None) -> float:
    """Seconds from a Retry-After header (seconds or an HTTP date)."""
    if not value:
        return 0.0
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return 0.0
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.UTC)
    return max(0.0, (when - dt.datetime.now(dt.UTC)).total_seconds())


@dataclass
class PhotoImport:
    """Result of :func:`import_photos`.

    Attributes:
        imported: Ids copied into the cache.
        present: Ids already in the cache.
        unknown: Files in the folder that match no photo (by sha256).
    """

    imported: list[str] = field(default_factory=list)
    present: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)


def import_photos(
    folder: Path,
    cache_dir: Path | None = None,
    entries: Iterable[Mapping[str, Any]] | None = None,
) -> PhotoImport:
    """Copy verified photo files from ``folder`` into the cache.

    A file is matched to a photo by its SHA-256, so names do not matter.

    Args:
        folder: A folder of photo files.
        cache_dir: The cache; default ``$XDG_CACHE_HOME/sandroid/world/photos``.
        entries: Photo-pack entries; default every photo of the photo pack.

    Raises:
        PhotoError: ``folder`` is not a directory.
    """
    folder = Path(folder).expanduser()
    if not folder.is_dir():
        raise PhotoError(f"{folder} is not a folder")
    cache = Path(cache_dir) if cache_dir else photo_cache_dir()
    if entries is None:
        from sandroid.world.packs import load_packs

        pack = load_packs().photos()
        entries = (pack.data.get("photos") if pack else None) or []
    by_sha = {str(e["sha256"]).lower(): e for e in entries if e.get("sha256")}
    result = PhotoImport()
    cache.mkdir(parents=True, exist_ok=True)
    for path in sorted(folder.iterdir()):
        if not path.is_file():
            continue
        entry = by_sha.get(file_sha256(path))
        if entry is None:
            result.unknown.append(path.name)
            continue
        dest = cache / cache_name(entry)
        if dest.is_file() and file_sha256(dest) == entry["sha256"]:
            result.present.append(entry["id"])
            continue
        tmp = dest.with_name(dest.name + ".part")
        shutil.copyfile(path, tmp)
        tmp.replace(dest)
        result.imported.append(entry["id"])
    return result


# -------------------------------------------------------------- processing


@dataclass(frozen=True)
class ProcessedPhoto:
    """One photo ready to push.

    Attributes:
        id: The world photo id (``world.photos.<n>``).
        path: The processed local file.
        name: Its device file name.
        remote_dir: Device folder (``DCIM/Camera`` or ``Pictures/Screenshots``,
            relative to ``/sdcard``).
        taken_ms: Capture time (Unix ms, with the sub-second part); the
            file's mtime.
        lat: Latitude written to EXIF (None: no GPS).
        lon: Longitude written to EXIF.
    """

    id: str
    path: Path
    name: str
    remote_dir: str
    taken_ms: int
    lat: float | None
    lon: float | None


def subsecond_ms(photo_id: str) -> int:
    """Return a stable sub-second part (0..999 ms) for a photo id."""
    return int(hashlib.sha256(photo_id.encode()).hexdigest()[:6], 16) % 1000


def is_screenshot(record: Mapping[str, Any]) -> bool:
    """Return whether a world photo record is a screenshot."""
    return (
        record.get("category") == "screenshot_like"
        or _suffix(record) == ".png"
        or str(record.get("source", "")).startswith("ss-")
    )


def device_name(record: Mapping[str, Any], tz: dt.tzinfo, taken_ms: int) -> str:
    """Return the Pixel-style file name of a photo.

    Camera photos: ``PXL_YYYYMMDD_HHMMSSmmm.jpg`` in UTC (as the Pixel camera
    names them). Screenshots: ``Screenshot_YYYYMMDD-HHMMSS.png`` in local time.
    """
    if is_screenshot(record):
        local = dt.datetime.fromtimestamp(taken_ms / 1000, tz)
        return f"Screenshot_{local:%Y%m%d-%H%M%S}.png"
    utc = dt.datetime.fromtimestamp(taken_ms / 1000, dt.UTC)
    return f"PXL_{utc:%Y%m%d_%H%M%S}{taken_ms % 1000:03d}.jpg"


def _rational(value: float, denominator: int) -> Any:
    from PIL.TiffImagePlugin import IFDRational

    frac = Fraction(round(value * denominator), denominator)
    return IFDRational(frac.numerator, frac.denominator)


def _dms(value: float) -> tuple[Any, Any, Any]:
    value = abs(value)
    deg = int(value)
    minutes_f = (value - deg) * 60
    minutes = int(minutes_f)
    seconds = (minutes_f - minutes) * 60
    return _rational(deg, 1), _rational(minutes, 1), _rational(seconds, 10000)


def altitude_m(lat: float, lon: float) -> float:
    """A plausible, stable altitude for a place (same spot -> same value)."""
    key = f"{round(lat, 2):.2f},{round(lon, 2):.2f}".encode()
    return 20.0 + int(hashlib.sha256(key).hexdigest()[:4], 16) % 380 + 0.5


def exif_bytes(
    *,
    make: str,
    model: str,
    taken_ms: int,
    tz: dt.tzinfo,
    lat: float | None,
    lon: float | None,
    size: tuple[int, int],
) -> bytes:
    """Build the EXIF block of a processed photo.

    Make/Model, Orientation 1, DateTime/DateTimeOriginal/DateTimeDigitized
    with OffsetTime* and SubSecTime* in the world's local time, the pixel
    size, and (when ``lat``/``lon`` are given) a GPS IFD with position,
    altitude and the UTC GPS date and time.
    """
    from PIL import Image

    local = dt.datetime.fromtimestamp(taken_ms / 1000, tz)
    stamp = local.strftime("%Y:%m:%d %H:%M:%S")
    off = local.strftime("%z")
    offset = f"{off[:3]}:{off[3:]}" if off else "+00:00"
    sub = f"{taken_ms % 1000:03d}"
    exif = Image.Exif()
    exif[_MAKE] = make
    exif[_MODEL] = model
    exif[_ORIENTATION] = 1
    exif[_DATETIME] = stamp
    exif[_EXIF_IFD] = {
        0x9000: b"0232",  # ExifVersion
        0x9003: stamp,  # DateTimeOriginal
        0x9004: stamp,  # DateTimeDigitized
        0x9010: offset,  # OffsetTime
        0x9011: offset,  # OffsetTimeOriginal
        0x9012: offset,  # OffsetTimeDigitized
        0x9290: sub,  # SubSecTime
        0x9291: sub,  # SubSecTimeOriginal
        0x9292: sub,  # SubSecTimeDigitized
        0xA001: 1,  # ColorSpace sRGB
        0xA002: size[0],  # PixelXDimension
        0xA003: size[1],  # PixelYDimension
    }
    if lat is not None and lon is not None:
        utc = dt.datetime.fromtimestamp(taken_ms / 1000, dt.UTC)
        exif[_GPS_IFD] = {
            0: b"\x02\x02\x00\x00",  # GPSVersionID
            1: "N" if lat >= 0 else "S",
            2: _dms(lat),
            3: "E" if lon >= 0 else "W",
            4: _dms(lon),
            5: 0,  # GPSAltitudeRef: above sea level
            6: _rational(altitude_m(lat, lon), 100),
            7: (
                _rational(utc.hour, 1),
                _rational(utc.minute, 1),
                _rational(utc.second, 1),
            ),
            29: utc.strftime("%Y:%m:%d"),  # GPSDateStamp
        }
    return exif.tobytes()


def _srgb_pixels(im: Any) -> Any:
    """Return the first frame as a fresh RGB image (orientation applied,
    converted to sRGB when it carried another ICC profile, no metadata).
    """
    from PIL import Image, ImageOps

    with contextlib.suppress(EOFError, AttributeError):
        im.seek(0)  # MPO / animated: the first frame only
    im.load()
    icc = im.info.get("icc_profile")
    oriented = ImageOps.exif_transpose(im) or im
    if oriented.mode not in ("RGB", "L", "RGBA", "CMYK", "P", "I;16", "LA"):
        oriented = oriented.convert("RGB")
    if icc and oriented.mode in ("RGB", "CMYK"):
        with contextlib.suppress(Exception):
            from PIL import ImageCms

            src = ImageCms.ImageCmsProfile(io.BytesIO(icc))
            desc = (ImageCms.getProfileDescription(src) or "").lower()
            if "srgb" not in desc:
                oriented = ImageCms.profileToProfile(
                    oriented, src, ImageCms.createProfile("sRGB"), outputMode="RGB"
                )
    if oriented.mode in ("RGBA", "LA", "P"):
        base = Image.new("RGB", oriented.size, (255, 255, 255))
        rgba = oriented.convert("RGBA")
        base.paste(rgba, mask=rgba.getchannel("A"))
        oriented = base
    rgb = oriented.convert("RGB")
    # Rebuild from raw pixels: nothing of im.info (comments, XMP, ICC) rides along.
    return Image.frombytes("RGB", rgb.size, rgb.tobytes())


def process_photo(
    src: Path,
    record: Mapping[str, Any],
    tz: dt.tzinfo,
    out_dir: Path,
    *,
    name: str | None = None,
    taken_ms: int | None = None,
) -> ProcessedPhoto:
    """Strip a photo to its pixels and write it with the world's metadata.

    Camera photos become a JPEG (quality :data:`JPEG_QUALITY`) with the EXIF
    of :func:`exif_bytes` (Make/Model from the record, its time and GPS).
    Screenshots become a PNG with no metadata at all.

    Args:
        src: The original file (verified photo-pack file).
        record: The rendered world photo (``id``, ``ts_ms``, ``lat``, ``lon``,
            ``make``, ``model``, ``category``, ``source``).
        tz: The world's time zone (EXIF local time and offset).
        out_dir: Where the processed file is written.
        name: The device file name; default :func:`device_name`.
        taken_ms: Capture time; default ``ts_ms`` plus :func:`subsecond_ms`.

    Raises:
        PhotoError: The file cannot be read as an image.
    """
    from PIL import Image, UnidentifiedImageError

    if taken_ms is None:
        taken_ms = int(record["ts_ms"]) + subsecond_ms(str(record["id"]))
    shot = is_screenshot(record)
    name = name or device_name(record, tz, taken_ms)
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / name
    try:
        with Image.open(src) as im:
            clean = _srgb_pixels(im)
    except (OSError, UnidentifiedImageError, ValueError) as exc:
        raise PhotoError(f"{src.name}: {exc}") from exc
    lat = lon = None
    if shot:
        clean.save(dest, format="PNG", optimize=False)
    else:
        lat, lon = record.get("lat"), record.get("lon")
        if lat is None or lon is None:
            lat = lon = None
        data = exif_bytes(
            make=str(record.get("make") or "Google"),
            model=str(record.get("model") or "Pixel 8"),
            taken_ms=taken_ms,
            tz=tz,
            lat=lat,
            lon=lon,
            size=clean.size,
        )
        clean.save(dest, format="JPEG", quality=JPEG_QUALITY, exif=data)
    return ProcessedPhoto(
        id=str(record["id"]),
        path=dest,
        name=name,
        remote_dir="Pictures/Screenshots" if shot else "DCIM/Camera",
        taken_ms=taken_ms,
        lat=lat,
        lon=lon,
    )


def plan_names(
    records: Iterable[Mapping[str, Any]], tz: dt.tzinfo
) -> dict[str, tuple[str, int]]:
    """Return photo id -> (unique device name, taken_ms) for a world.

    Two photos that would share a name move one millisecond (camera) or one
    second (screenshot) later until the name is free.
    """
    taken_names: set[str] = set()
    out = {}
    for rec in records:
        ms = int(rec["ts_ms"]) + subsecond_ms(str(rec["id"]))
        step = 1000 if is_screenshot(rec) else 1
        name = device_name(rec, tz, ms)
        while name in taken_names:
            ms += step
            name = device_name(rec, tz, ms)
        taken_names.add(name)
        out[str(rec["id"])] = (name, ms)
    return out
