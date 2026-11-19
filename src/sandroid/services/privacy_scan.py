"""Privacy scan: find identity-profile marker values in flows and pulled files.

An identity profile seeds distinctive canary values on the device
(:mod:`sandroid.core.privacy_markers` turns them into byte patterns). This
service looks for them wherever captured data lands:

* **Network**: every logged mitmproxy flow, live (a sink on
  :class:`~sandroid.services.tracking_service.NetFlowSource`): the URL, each
  request/response header and both bodies (base64-stored bodies are decoded,
  app-level gzip/zlib/zstd is unpacked up to 1 MiB).
* **Files**: every pulled version of a watched file (main file plus its
  ``-wal``/``-journal``), and an end-of-run sweep of the app's data folders.
  While a profile is active the app's ``shared_prefs``, ``databases`` and
  ``no_backup`` folders are auto-watched for this session only.
* **Retro**: when the markers change, the session's existing flows and kept
  versions not yet scanned for that profile are scanned once.

One daemon worker (``privacy-scan``) does every scan; callers only enqueue
(``put_nowait``) and never wait. Results go to ``<timeline folder>/privacy/``:
``hits.jsonl`` (one record per item x marker x transform x part) and
``coverage.jsonl`` (one line per scanned item, which keeps retro scans
idempotent). A finding that is new for its recipient (network) or file
(storage) also writes one ``privacy/sent`` or ``privacy/stored`` line to the
session timeline; it names the marker, never the value.

The records shown are those of the session timeline's folder: the timeline's
``bound`` doorbell (a session started, resumed or switched) makes the
service drop the old session's records at once and read the new folder's on
the worker, with or without an active profile (:meth:`switch_folder`).
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import itertools
import json
import logging
import os
import queue
import re
import threading
import time
import zlib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from sandroid.core.privacy_markers import (
    CONFIDENCES,
    Marker,
    MarkerHit,
    NeedleSet,
    build_needles,
    snippet,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

logger = logging.getLogger(__name__)

#: Version of the scan engine (marker engine + this scanner). A change makes
#: a retro scan redo every item.
ENGINE_VERSION = 1
#: Version of the ``hits.jsonl`` / ``coverage.jsonl`` records.
RECORD_VERSION = 1
#: Folder below the timeline folder, and its files.
FOLDER_NAME = "privacy"
HITS_FILE = "hits.jsonl"
COVERAGE_FILE = "coverage.jsonl"

#: Queued items at most; more are dropped (``queue-full`` in the ledger).
QUEUE_MAX = 5_000
#: Haystacks are scanned in chunks of this size, yielding the GIL between.
CHUNK = 256 * 1024
#: Bytes of one file scanned at most (the record says ``truncated``).
FILE_CAP = 32 * 1024 * 1024
#: App-level compressed bodies are unpacked to at most this many bytes.
DECOMPRESS_CAP = 1024 * 1024
#: A live flow's details file is retried this long (the addon writes it
#: after the flows.jsonl line, non-atomically).
DETAIL_RETRY_S = 2.0
#: Only items younger than this get the detail retry.
DETAIL_FRESH_S = 5.0
#: Offsets kept per record.
MAX_OFFSETS = 8
#: Snippet context per side and the longest match shown (chars).
SNIPPET_WIDTH = 28
SNIPPET_MATCH_MAX = 64
#: App folders auto-watched while a profile is active (session only).
AUTO_WATCH_DIRS = ("shared_prefs/", "databases/", "no_backup/")
#: Minimum seconds between two auto-watch pulls of one file.
AUTO_WATCH_MIN_INTERVAL_S = 10.0

#: Queue priorities (lower first). A session switch goes before any scan.
PRIO_STOP = -2
PRIO_LOAD = -1
PRIO_NET = 0
PRIO_FILE = 1
PRIO_SWEEP = 2
PRIO_RETRO = 3

#: The auto-watch interval clock (tests replace it).
_clock: Callable[[], float] = time.monotonic

_COMPANIONS = ("-wal", "-journal")
_VERSION_DIR_RE = re.compile(r"^v\d+_")
_PLACES_RE = re.compile(r"(?:round|truncate)\(value, (\d+)\)")
_ENCODED_TOKENS = (
    "md5(",
    "sha1(",
    "sha256(",
    "base64",
    "hex(",
    "utf16(",
    "bytes(",
    "e7(",
    "double_",
)
_GENERIC_TOKENS = frozenset(
    {
        "com",
        "org",
        "net",
        "app",
        "apps",
        "android",
        "mobile",
        "www",
        "the",
        "free",
        "pro",
        "lite",
        "beta",
        "debug",
        "release",
        "client",
        "main",
    }
)
_TWO_PART_TLDS = ("co.uk", "com.au", "co.jp", "com.br", "co.in", "co.kr")
_DIRECTION_RANK = {"sent": 0, "stored": 1, "received": 2}


# ---------------------------------------------------------------------------
# public records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HitRecord:
    """One ``hits.jsonl`` record: a marker found in one part of one item.

    Attributes:
        v: Record version (:data:`RECORD_VERSION`).
        at: When the scan ran (epoch s).
        t: When the item happened (flow start / pull time, epoch s).
        fp: Fingerprint of the identity profile scanned for.
        engine: :data:`ENGINE_VERSION`.
        marker_id: The marker's id.
        label: The marker's label, e.g. ``"Advertising ID"``.
        tag: The marker's short display tag.
        kind: The marker's kind.
        transform: How the value was encoded, e.g. ``"sha256(lower(value))"``.
        confidence: Best confidence of the occurrences.
        part: ``url``, ``req.header:<name>``, ``req.body``,
            ``resp.header:<name>``, ``resp.body`` or ``file:<member>``.
        direction: ``sent``, ``received`` or ``stored``.
        count: Occurrences in this part.
        offsets: Byte offsets of the first :data:`MAX_OFFSETS` occurrences.
        snippet: ``(before, match, after)`` of the first occurrence.
        source: ``{"type": "flow", "flow_id", "flow_seq", "net_seq", "host",
            "method", "path", "app"}`` or ``{"type": "file", "device_path",
            "version", "member", "sha256", "pull_seq", "package"}``.
        recipient: ``{"label", "party", "host", "domain"}`` (flows; None for
            files).
        tl_seq: Seq of the ``privacy/*`` timeline line this record caused.
        new: First time for this (marker, transform, direction, domain) in
            the session (flows) / not in the file's previous version (files).
        echo: A response hit whose marker also appeared in the request.
        truncated: The scanned bytes were capped.
        retro: Found by a retro scan.
        encoded: Hashed or encoded (not a plain spelling of the value).
        approx: A coordinate rounded/truncated below its seeded precision.
        decoded: App-level compression unpacked first (``gzip``...), or None.
    """

    v: int
    at: float
    t: float | None
    fp: str
    engine: int
    marker_id: str
    label: str
    tag: str
    kind: str
    transform: str
    confidence: str
    part: str
    direction: str
    count: int
    offsets: tuple[int, ...]
    snippet: tuple[str, str, str]
    source: dict = field(hash=False, compare=False)
    recipient: dict | None = field(default=None, hash=False, compare=False)
    tl_seq: int | None = None
    new: bool = False
    echo: bool = False
    truncated: bool = False
    retro: bool = False
    encoded: bool = False
    approx: bool = False
    decoded: str | None = None

    @property
    def flow_id(self) -> str | None:
        """The flow id of a network record (None for files)."""
        return self.source.get("flow_id") if self.source.get("type") == "flow" else None

    @property
    def device_path(self) -> str | None:
        """The device path of a file record (None for flows)."""
        if self.source.get("type") == "file":
            return self.source.get("device_path")
        return None

    def to_json(self) -> dict:
        """The record as written to ``hits.jsonl``."""
        return {
            "v": self.v,
            "at": self.at,
            "t": self.t,
            "fp": self.fp,
            "engine": self.engine,
            "marker_id": self.marker_id,
            "label": self.label,
            "tag": self.tag,
            "kind": self.kind,
            "transform": self.transform,
            "confidence": self.confidence,
            "part": self.part,
            "direction": self.direction,
            "count": self.count,
            "offsets": list(self.offsets),
            "snippet": list(self.snippet),
            "source": self.source,
            "recipient": self.recipient,
            "tl_seq": self.tl_seq,
            "new": self.new,
            "echo": self.echo,
            "truncated": self.truncated,
            "retro": self.retro,
            "encoded": self.encoded,
            "approx": self.approx,
            "decoded": self.decoded,
        }

    @classmethod
    def from_json(cls, data: dict) -> HitRecord | None:
        """Parse one ``hits.jsonl`` record (None when malformed)."""
        try:
            snip = list(data.get("snippet") or ("", "", ""))[:3]
            snip += [""] * (3 - len(snip))
            return cls(
                v=int(data.get("v") or RECORD_VERSION),
                at=float(data.get("at") or 0.0),
                t=float(data["t"]) if data.get("t") is not None else None,
                fp=str(data.get("fp") or ""),
                engine=int(data.get("engine") or 0),
                marker_id=str(data["marker_id"]),
                label=str(data.get("label") or data["marker_id"]),
                tag=str(data.get("tag") or data.get("label") or ""),
                kind=str(data.get("kind") or "text"),
                transform=str(data.get("transform") or "value"),
                confidence=str(data.get("confidence") or "low"),
                part=str(data.get("part") or ""),
                direction=str(data.get("direction") or ""),
                count=int(data.get("count") or 1),
                offsets=tuple(int(o) for o in data.get("offsets") or ()),
                snippet=(str(snip[0]), str(snip[1]), str(snip[2])),
                source=dict(data.get("source") or {}),
                recipient=data.get("recipient"),
                tl_seq=data.get("tl_seq"),
                new=bool(data.get("new")),
                echo=bool(data.get("echo")),
                truncated=bool(data.get("truncated")),
                retro=bool(data.get("retro")),
                encoded=bool(data.get("encoded")),
                approx=bool(data.get("approx")),
                decoded=data.get("decoded"),
            )
        except (KeyError, TypeError, ValueError):
            return None


@dataclass(frozen=True)
class TagInfo:
    """One marker found in a flow or file, for a row badge.

    Attributes:
        tag: The marker's plain display tag, e.g. ``"Ad ID"``.
        label: The marker's label.
        marker_id: The marker's id.
        party: ``third``, ``first``, ``unknown`` (flows) or ``stored``.
        direction: Strongest direction seen: ``sent``, ``stored``,
            ``received``.
        encoded: Only hashed/encoded forms were found (no plain spelling).
        approx: Only rounded coordinates were found (no exact one).
        confidence: Best confidence.
    """

    tag: str
    label: str
    marker_id: str
    party: str
    direction: str
    encoded: bool
    approx: bool
    confidence: str


@dataclass(frozen=True)
class PrivacySummary:
    """A cheap snapshot for the header indicator.

    Attributes:
        active: Markers are set and the worker runs.
        fingerprint: The active profile's fingerprint.
        values_total: Distinct seeded values (a marker group, e.g. GPS
            latitude + longitude or one contact's fields, counts once).
        values_found: Distinct values with at least one hit (any direction).
        hits_total: Hit records for the active profile.
        last_hit_at: When the newest hit record was made (epoch s).
    """

    active: bool
    fingerprint: str | None
    values_total: int
    values_found: int
    hits_total: int
    last_hit_at: float | None


# ---------------------------------------------------------------------------
# queue items
# ---------------------------------------------------------------------------


@dataclass
class _Item:
    needles: NeedleSet
    fp: str
    submitted: float
    retro: bool = False
    #: The folder generation a retro item was listed for (-1: live item).
    gen: int = -1

    def key(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError


@dataclass
class _FlowItem(_Item):
    rec: dict = field(default_factory=dict)
    flow_dir: Path = Path()
    seq: int | None = None

    def key(self) -> str:
        return f"flow:{self.rec.get('id')}"


@dataclass
class _VersionItem(_Item):
    device_path: str = ""
    version_dir: Path = Path()
    pull_seq: int | None = None
    package: str | None = None

    def key(self) -> str:
        return f"file:{self.device_path}@{self.version_dir.name}"


@dataclass
class _SweepItem(_Item):
    device_path: str = ""
    member: str = ""
    local: Path = Path()
    sweep_id: str = ""
    package: str | None = None
    run_id: str | None = None

    def key(self) -> str:
        return f"sweep:{self.sweep_id}:{self.device_path}:{self.member}"


@dataclass
class _SweepDone(_Item):
    root: Path = Path()

    def key(self) -> str:
        return f"sweep-done:{self.root.name}"


@dataclass
class _LoadItem(_Item):
    """Switch to the session timeline's folder (``folder`` when the timeline
    cannot say) and read its records.
    """

    folder: Path | None = None

    def key(self) -> str:
        return f"load:{self.folder}"


@dataclass
class _Agg:
    """The occurrences of one (marker, transform) in one part."""

    hit: MarkerHit
    snippet: tuple[str, str, str]
    count: int = 0
    offsets: list[int] = field(default_factory=list)
    confidence: str = "low"

    def add(self, hit: MarkerHit, offset: int) -> None:
        self.count += 1
        if len(self.offsets) < MAX_OFFSETS:
            self.offsets.append(offset)
        if CONFIDENCES.index(hit.confidence) < CONFIDENCES.index(self.confidence):
            self.confidence = hit.confidence


# ---------------------------------------------------------------------------
# scanning helpers (pure)
# ---------------------------------------------------------------------------


def _trim_snippet(parts: tuple[str, str, str]) -> tuple[str, str, str]:
    before, match, after = parts
    if len(match) > SNIPPET_MATCH_MAX:
        match = match[: SNIPPET_MATCH_MAX - 3] + "..."
    return before[-SNIPPET_WIDTH:], match, after[:SNIPPET_WIDTH]


def scan_stream(
    needles: NeedleSet, stream: BinaryIO, *, cap: int = FILE_CAP
) -> tuple[dict[tuple[str, str], _Agg], str, int, bool]:
    """Scan ``stream`` in :data:`CHUNK` pieces overlapping by the longest needle.

    Yields the GIL between chunks. A hit is reported once even when it
    straddles a chunk boundary, and a weaker form inside a stronger hit
    counted in the previous chunk stays suppressed (the scan's
    ``_drop_contained`` only sees one buffer).

    Returns:
        ``(aggregates by (marker_id, transform), sha256 of the bytes read,
        bytes read, truncated)``.
    """
    overlap = max(needles.max_needle_len - 1, 0)
    digest = hashlib.sha256()
    aggs: dict[tuple[str, str], _Agg] = {}
    buf = b""
    base = 0
    total = 0
    truncated = False
    eof = False
    # (marker_id, start, end) in stream offsets of counted hits that reach
    # past the last chunk's limit: they contain hits found in the next one.
    carry: list[tuple[str, int, int]] = []
    while not eof:
        want = min(CHUNK, cap - total)
        if want <= 0:
            truncated = bool(stream.read(1))
            eof = True
            chunk = b""
        else:
            chunk = stream.read(want)
            if not chunk:
                eof = True
        if chunk:
            digest.update(chunk)
            total += len(chunk)
            buf += chunk
        if not buf:
            break
        limit = len(buf) if eof else len(buf) - overlap
        if limit <= 0:
            continue
        next_carry: list[tuple[str, int, int]] = []
        for hit in needles.scan(buf):
            if hit.offset >= limit:
                continue
            start, end = base + hit.offset, base + hit.end
            if any(m == hit.marker_id and s <= start and end <= e for m, s, e in carry):
                continue  # inside a stronger hit of the previous chunk
            if hit.end > limit:
                next_carry.append((hit.marker_id, start, end))
            key = (hit.marker_id, hit.transform)
            agg = aggs.get(key)
            if agg is None:
                agg = aggs[key] = _Agg(
                    hit,
                    _trim_snippet(snippet(buf, hit, SNIPPET_WIDTH)),
                    confidence=hit.confidence,
                )
            agg.add(hit, base + hit.offset)
        carry = [c for c in (*carry, *next_carry) if c[2] > base + limit]
        buf = buf[limit:]
        base += limit
        time.sleep(0)  # let the UI thread run between chunks
    return aggs, digest.hexdigest(), total, truncated


def scan_bytes(
    needles: NeedleSet, data: bytes, *, cap: int = FILE_CAP
) -> tuple[dict[tuple[str, str], _Agg], bool]:
    """:func:`scan_stream` over in-memory bytes: ``(aggregates, truncated)``."""
    aggs, _sha, _n, truncated = scan_stream(needles, io.BytesIO(data), cap=cap)
    return aggs, truncated


def _zstd_decompress(raw: bytes, cap: int) -> bytes | None:
    try:  # Python 3.14+
        from compression import zstd  # type: ignore[import-not-found]

        return zstd.ZstdDecompressor().decompress(raw, max_length=cap)
    except ImportError:
        pass
    try:
        import zstandard  # type: ignore[import-not-found]
    except ImportError:
        return None
    reader = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(raw))
    return reader.read(cap)


def unwrap_compressed(
    raw: bytes, cap: int = DECOMPRESS_CAP
) -> tuple[bytes, str | None]:
    """Unpack app-level gzip/zlib/zstd (sniffed by magic) up to ``cap`` bytes.

    Returns:
        ``(bytes to scan, "gzip" | "zlib" | "zstd" | None)``: the input
        unchanged when it is not compressed or does not unpack.
    """
    try:
        if raw[:2] == b"\x1f\x8b":
            out = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw, cap)
            return (out, "gzip") if out else (raw, None)
        if len(raw) >= 2 and raw[0] == 0x78 and (raw[0] * 256 + raw[1]) % 31 == 0:
            out = zlib.decompressobj().decompress(raw, cap)
            return (out, "zlib") if out else (raw, None)
        if raw[:4] == b"\x28\xb5\x2f\xfd":
            out = _zstd_decompress(raw, cap)
            return (out, "zstd") if out else (raw, None)
    except Exception:
        logger.debug("privacy scan: body did not unpack", exc_info=True)
    return raw, None


def body_bytes(body: Any) -> tuple[bytes, bool, str | None]:
    """The bytes of a details-file body record: ``(data, truncated, decoded)``.

    Base64-stored bodies are decoded; app-level compression is unpacked.
    """
    if not isinstance(body, dict):
        return b"", False, None
    content = body.get("content") or ""
    truncated = bool(body.get("truncated"))
    if body.get("encoding") == "base64":
        try:
            raw = base64.b64decode(content, validate=False)
        except (ValueError, TypeError):
            raw = str(content).encode("utf-8", "surrogatepass")
    else:
        raw = str(content).encode("utf-8", "surrogatepass")
    data, decoded = unwrap_compressed(raw)
    if decoded is not None and len(data) >= DECOMPRESS_CAP:
        truncated = True
    return data, truncated, decoded


def is_encoded(transform: str) -> bool:
    """The transform hashes or encodes the value (not a plain spelling)."""
    return any(token in transform for token in _ENCODED_TOKENS)


def is_approx(marker: Marker | None, transform: str) -> bool:
    """A coordinate rounded/truncated to fewer places than it was seeded with."""
    match = _PLACES_RE.search(transform)
    if match is None:
        return False
    places = int(match.group(1))
    value = marker.value.strip() if marker is not None else ""
    decimals = len(value.split(".", 1)[1]) if "." in value else 99
    return places < decimals


def short_transform(transform: str) -> str:
    """``sha256(lower(value))`` -> ``sha256(lower)``; ``value`` -> ``plain``."""
    if transform == "value":
        return "plain"
    return transform.replace("(value)", "").replace("value, ", "")


def part_label(part: str) -> str:
    """``req.body`` -> ``req body``; ``req.header:Cookie`` -> ``req header Cookie``."""
    if part == "url":
        return "URL"
    head, _, name = part.partition(":")
    text = head.replace(".", " ")
    return f"{text} {name}" if name else text


# ---------------------------------------------------------------------------
# recipient / party
# ---------------------------------------------------------------------------


def registrable_domain(host: str) -> str:
    """``api.fittrack.de`` -> ``fittrack.de`` (the Network lens's rule)."""
    try:
        from sandroid.tui.widgets.network_panel import (
            registrable_domain as lens_domain,
        )

        return lens_domain(host)
    except Exception:
        pass
    host = (host or "").lower().rstrip(".")
    parts = host.split(".")
    if len(parts) <= 2 or host.replace(".", "").isdigit():
        return host
    keep = 3 if ".".join(parts[-2:]) in _TWO_PART_TLDS else 2
    return ".".join(parts[-keep:])


_RECIPIENT_FN: Any = None


def _recipient_lookup(host: str) -> tuple[str, bool]:
    """``(label, known)`` for ``host``: the Network lens's ``recipient_of``,
    else Dexray Insight's ``label_for_domain``, else the bare domain.
    """
    global _RECIPIENT_FN
    if _RECIPIENT_FN is None:
        try:
            from sandroid.tui.widgets.network_panel import recipient_of

            _RECIPIENT_FN = recipient_of
        except Exception:
            _RECIPIENT_FN = False
    if _RECIPIENT_FN:
        try:
            label, known = _RECIPIENT_FN(host)
            return str(label), bool(known)
        except Exception:
            pass
    for mod in (
        "dexray_insight.modules.tracker_analysis.databases.tracker_database",
        "dexray_insight.modules.tracker_analysis",
    ):
        try:
            import importlib

            match = importlib.import_module(mod).label_for_domain(host)
        except Exception:
            continue
        if match:
            return str(match[0] if isinstance(match, (tuple, list)) else match), True
        break
    return registrable_domain(host) or "?", False


def _first_party(host: str, package: str | None) -> bool:
    """The host's registrable domain is named after the app's package.

    Whole labels only: the domain's name label (``fittrack`` of
    ``api.fittrack.de``) must equal a non-generic package token
    (``com.fittrack.app``). A substring is not enough: ``com.google.*`` and
    ``google-analytics.com`` or ``com.amazon.*`` and ``amazon-adsystem.com``
    are different recipients.
    """
    if not package:
        return False
    domain = registrable_domain(host)
    name = domain.split(".", 1)[0] if domain else ""
    if len(name) < 3:
        return False
    tokens = {
        t
        for t in package.lower().split(".")
        if len(t) >= 3 and t not in _GENERIC_TOKENS
    }
    return name in tokens


def classify_party(host: str, package: str | None) -> tuple[str, str]:
    """``(recipient label, party)`` of a flow's host.

    ``third`` when Dexray Insight (or the Network lens's table) knows the
    host as a tracker, ad network or vendor (this wins: an app of the same
    vendor still sends to its tracking domain), else ``first`` when the
    registrable domain's name equals a token of the package name
    (``com.fittrack.app`` -> ``fittrack.*``), else ``unknown``.
    """
    label, known = _recipient_lookup(host or "")
    if known:
        return label, "third"
    if _first_party(host or "", package):
        return label, "first"
    return label, "unknown"


# ---------------------------------------------------------------------------
# the service
# ---------------------------------------------------------------------------


class PrivacyScanService:
    """Scans flows and pulled files for identity-profile markers (see module)."""

    def __init__(
        self,
        *,
        folder_fn: Callable[[], Path | None] | None = None,
        flow_dir_fn: Callable[[], Path | None] | None = None,
        queue_max: int = QUEUE_MAX,
    ) -> None:
        """Create the service (the worker starts with the first markers).

        Args:
            folder_fn: The timeline folder records go below (default: the
                session timeline's folder).
            flow_dir_fn: The mitmproxy flow folder a retro scan reads
                (default: the last one a flow came from, else the session's).
            queue_max: Queued items at most.
        """
        self._folder_fn = folder_fn
        self._flow_dir_fn = flow_dir_fn
        self._lock = threading.RLock()
        self._queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=queue_max)
        self._counter = itertools.count()
        self._thread: threading.Thread | None = None
        self._closed = False
        self._idle = threading.Condition()
        self._pending = 0
        self._busy = False
        # markers
        self._fp: str | None = None
        self._markers: dict[str, Marker] = {}
        self._needles: NeedleSet | None = None
        self._value_key: dict[str, str] = {}
        self._retro_request: tuple[NeedleSet, str] | None = None
        self._retro_iter: Iterator[_Item] | None = None
        # records
        self._folder: Path | None = None
        #: The in-memory records were dropped (a session switch); the next
        #: load reads the folder again even when it did not change.
        self._stale = False
        #: Bumped on every folder load: retro items of an older one are
        #: dropped.
        self._gen = 0
        #: Bumped whenever the loaded records change (cheap cache key for
        #: the lenses).
        self.revision = 0
        self._hits: list[HitRecord] = []
        self._by_flow: dict[str, list[HitRecord]] = {}
        self._by_file: dict[str, list[HitRecord]] = {}
        self._covered: set[tuple[str, str, int]] = set()
        #: Canonical device paths with kept versions in this session (pulls
        #: submitted here, and the coverage ledger of a loaded session).
        self._version_paths: set[str] = set()
        self._seen: set[tuple] = set()
        self._emitted: set[tuple] = set()
        self._version_sets: dict[tuple[str, str, str], frozenset] = {}
        self._file_last: dict[str, tuple[str, frozenset, frozenset]] = {}
        self._dropped: deque[str] = deque(maxlen=1_000)
        self.dropped = 0
        self._listeners: list[Callable[[HitRecord], None]] = []
        self._flow_dir: Path | None = None
        self._auto_pulls: dict[str, float] = {}
        # summary counters (read without the lock)
        self._values_total = 0
        self._found_values: set[str] = set()
        self._hits_total = 0
        self._last_hit_at: float | None = None
        self._identity: Any = None

    # -- markers -------------------------------------------------------------

    def set_markers(self, fp: str | None, markers: list[Marker]) -> None:
        """Scan for ``markers`` from now on (``fp`` None / no markers: off).

        A new fingerprint queues a retro scan of the session's flows and kept
        versions not yet scanned for it.
        """
        markers = list(markers or ())
        needles = build_needles(markers) if fp and markers else None
        if needles is not None and not len(needles):
            needles = None
        with self._lock:
            changed = fp != self._fp
            self._fp = fp if needles is not None else None
            self._markers = {m.id: m for m in markers} if needles else {}
            self._needles = needles
            self._value_key = {m.id: (m.group or m.id) for m in self._markers.values()}
            self._values_total = len(set(self._value_key.values()))
            self._recount()
            if needles is not None and changed:
                self._retro_request = (needles, fp)
                self._retro_iter = None
            elif needles is None:
                self._retro_request = None
                self._retro_iter = None
        if needles is not None:
            self._ensure_worker()
            self._kick()

    def _recount(self) -> None:
        """Lock held: summary counters for the active profile."""
        fp = self._fp
        mine = [h for h in self._hits if fp and h.fp == fp]
        self._found_values = {
            self._value_key.get(h.marker_id, h.marker_id) for h in mine
        }
        self._hits_total = len(mine)
        self._last_hit_at = max((h.at for h in mine), default=None)

    def attach_identity(self) -> bool:
        """Follow the identity service's active markers (if it exists)."""
        try:
            from sandroid.services.identity import (  # type: ignore[import-not-found]
                get_identity_service,
            )
        except Exception:
            logger.debug("privacy scan: no identity service", exc_info=True)
            return False
        try:
            service = get_identity_service()
            if self._identity is not service:
                service.add_markers_listener(self._on_identity_markers)
                self._identity = service
            active = service.active_markers(load=False)
        except Exception:
            logger.debug("privacy scan: identity service failed", exc_info=True)
            return False
        if active:
            self.set_markers(active[0], active[1])
            return True
        self.set_markers(None, [])
        # The first read (the session's apply record, else the profile) is
        # file I/O and this runs on the UI thread at startup: read it on a
        # thread; the service notifies its listeners (this one) when it
        # finds markers.
        threading.Thread(
            target=self._load_identity,
            args=(service,),
            name="privacy-identity",
            daemon=True,
        ).start()
        return True

    @staticmethod
    def _load_identity(service: Any) -> None:
        try:
            service.active_markers()
        except Exception:
            logger.debug("privacy scan: identity markers failed", exc_info=True)

    def _on_identity_markers(self, fp: str | None, markers: list[Marker]) -> None:
        try:
            self.set_markers(fp, markers)
        except Exception:
            logger.debug("privacy scan: set_markers failed", exc_info=True)

    @property
    def is_active(self) -> bool:
        """Markers are set (scans happen)."""
        return self._needles is not None and not self._closed

    @property
    def fingerprint(self) -> str | None:
        return self._fp

    def summary(self) -> PrivacySummary:
        """Cheap header snapshot (no I/O, no lock)."""
        thread = self._thread
        return PrivacySummary(
            active=self._needles is not None
            and thread is not None
            and thread.is_alive(),
            fingerprint=self._fp,
            values_total=self._values_total,
            values_found=len(self._found_values),
            hits_total=self._hits_total,
            last_hit_at=self._last_hit_at,
        )

    # -- submit (any thread, never blocks) -----------------------------------

    def _put(self, prio: int, item: _Item) -> bool:
        with self._idle:
            self._pending += 1
        try:
            self._queue.put_nowait((prio, next(self._counter), item))
        except queue.Full:
            with self._idle:
                self._pending -= 1
                self._idle.notify_all()
            self._dropped.append(item.key())
            self.dropped += 1
            return False
        # After the put: an idle worker that just ended (no profile) cannot
        # strand the item.
        self._ensure_worker()
        return True

    def _snapshot(self) -> tuple[NeedleSet, str] | None:
        with self._lock:  # one consistent pair (set_markers writes both)
            needles, fp = self._needles, self._fp
        if needles is None or fp is None or self._closed:
            return None
        return needles, fp

    def submit_flow(self, rec: dict, flow_dir: Path, seq: int | None) -> None:
        """Queue a logged flow (the ``NetFlowSource`` sink)."""
        if not isinstance(rec, dict) or rec.get("kind") == "tls" or not rec.get("id"):
            return
        self._flow_dir = Path(flow_dir)
        snap = self._snapshot()
        if snap is None:
            return
        self._ensure_worker()
        self._put(
            PRIO_NET,
            _FlowItem(
                snap[0],
                snap[1],
                time.monotonic(),
                rec=dict(rec),
                flow_dir=Path(flow_dir),
                seq=seq,
            ),
        )

    def submit_version(
        self,
        device_path: str,
        version_dir: Path,
        pull_seq: int | None,
        *,
        package: str | None = None,
    ) -> None:
        """Queue a kept version (main file + ``-wal``/``-journal``)."""
        with self._lock:
            self._version_paths.add(_canonical(device_path))
        snap = self._snapshot()
        if snap is None:
            return
        if package is None:
            package = _package_of(device_path)
        self._ensure_worker()
        self._put(
            PRIO_FILE,
            _VersionItem(
                snap[0],
                snap[1],
                time.monotonic(),
                device_path=device_path,
                version_dir=Path(version_dir),
                pull_seq=pull_seq,
                package=package,
            ),
        )

    def sweep_app_data(
        self, serial: str | None, package: str, *, run_id: str | None = None
    ) -> None:
        """Pull every file of ``package``'s data folders and scan them.

        Pulls on its own thread (``privacy-sweep``); the scans run on the
        worker, and only files with hits are kept (under
        ``privacy/sweep/``). No-op while no profile is active. ``run_id``:
        the Play the sweep ends; its records carry it (``source.run_id``),
        so the run's views include them although they are found after the
        run's end.
        """
        snap = self._snapshot()
        if snap is None or not package:
            return
        self._ensure_worker()
        threading.Thread(
            target=self._sweep,
            args=(serial, package, snap, run_id),
            name="privacy-sweep",
            daemon=True,
        ).start()

    def _sweep(
        self, serial: str | None, package: str, snap: tuple, run_id: str | None = None
    ) -> None:
        folder = self._privacy_dir()
        if folder is None:
            return
        sweep_id = f"{package}_{time.strftime('%Y-%m-%d_%H-%M-%S')}"
        out = folder / "sweep" / sweep_id
        try:
            from sandroid.core.adb import Adb
            from sandroid.services import get_file_extraction_service

            with Adb.targeting(serial):
                results = get_file_extraction_service().pull_all_for_package(
                    package, output_dir=str(out)
                )
        except Exception:
            logger.warning("privacy scan: app-data sweep failed", exc_info=True)
            return
        from sandroid.core.adb_utils import canonical_device_path

        now = time.monotonic()
        # The app-data roots include aliases of one folder (/data/data/<pkg>
        # and /data/user/0/<pkg>): scan each file once, under its canonical path.
        seen: set[str] = set()
        for result in results:
            if not getattr(result, "success", False):
                continue
            remote = canonical_device_path(str(result.source_path))
            if remote in seen:
                with contextlib.suppress(OSError):
                    Path(result.local_path).unlink()
                continue
            seen.add(remote)
            main = remote
            for suffix in (*_COMPANIONS, "-shm"):
                if remote.endswith(suffix):
                    main = remote[: -len(suffix)]
                    break
            self._put(
                PRIO_SWEEP,
                _SweepItem(
                    snap[0],
                    snap[1],
                    now,
                    device_path=main,
                    member=os.path.basename(remote),
                    local=Path(result.local_path),
                    sweep_id=sweep_id,
                    package=package,
                    run_id=run_id,
                ),
            )
        self._put(PRIO_SWEEP, _SweepDone(snap[0], snap[1], now, root=out))

    # -- auto-watch (session only, never persisted) ---------------------------

    def auto_watch_patterns(self, package: str | None) -> list[str]:
        """The session-only watch patterns for ``package`` (empty: off)."""
        if not package or not self.is_active:
            return []
        return [f"/data/data/{package}/{d}*" for d in AUTO_WATCH_DIRS]

    def auto_watch_covers(self, path: str, package: str | None) -> bool:
        """``path`` is in an auto-watched folder of the monitored app."""
        if not package or not self.is_active or path.endswith("-shm"):
            return False
        try:
            from sandroid.core.watchlist_store import owner_and_relative

            owner, rel = owner_and_relative(path)
        except Exception:
            return False
        return owner == package and rel.startswith(AUTO_WATCH_DIRS)

    def auto_watch_delay(self, path: str) -> float:
        """Seconds until ``path`` may be auto-pulled again; 0 claims the pull."""
        now = _clock()
        with self._lock:
            last = self._auto_pulls.get(path)
            if last is not None and now - last < AUTO_WATCH_MIN_INTERVAL_S:
                return AUTO_WATCH_MIN_INTERVAL_S - (now - last)
            self._auto_pulls[path] = now
        return 0.0

    # -- queries (any thread; snapshots) -------------------------------------

    def hits(self, *, marker_id: str | None = None) -> list[HitRecord]:
        """Every hit record of the loaded session (optionally one marker's)."""
        with self._lock:
            if marker_id is None:
                return list(self._hits)
            return [h for h in self._hits if h.marker_id == marker_id]

    def hits_for_flow(self, flow_id: str) -> list[HitRecord]:
        with self._lock:
            return list(self._by_flow.get(flow_id, ()))

    def hits_for_file(self, device_path: str) -> list[HitRecord]:
        with self._lock:
            return list(self._by_file.get(device_path, ()))

    def hits_between(self, t0: float, t1: float) -> list[HitRecord]:
        """Hits whose item happened in ``[t0, t1]`` (per-run views)."""
        with self._lock:
            return [h for h in self._hits if h.t is not None and t0 <= h.t <= t1]

    def hits_for_run(self, scope: RunScope) -> list[HitRecord]:
        """The loaded session's hits of one run (see :class:`RunScope`)."""
        with self._lock:
            return run_hits(self._hits, scope)

    def has_versions(self, device_path: str) -> bool:
        """``device_path`` (any alias) has kept versions in the loaded
        session (a pull this session, or one in its coverage ledger); no I/O.
        """
        with self._lock:
            return _canonical(device_path) in self._version_paths

    def has_hits(self) -> bool:
        """The loaded session has any hit record (cheap: no copy, no lock)."""
        return bool(self._hits)

    @property
    def folder(self) -> Path | None:
        """The timeline folder whose records are loaded (None: none yet)."""
        return self._folder

    def tags_for_flow(self, flow_id: str) -> list[TagInfo]:
        """One :class:`TagInfo` per marker found in the flow, strongest first."""
        return _tags(self.hits_for_flow(flow_id))

    def tags_for_file(self, device_path: str) -> list[TagInfo]:
        """One :class:`TagInfo` per marker found in the file, strongest first."""
        return _tags(self.hits_for_file(device_path))

    def add_listener(self, cb: Callable[[HitRecord | None], None]) -> None:
        """``cb(record)`` for every new record, on the worker thread.

        ``cb(None)``: the loaded records changed as a whole (a session
        switch dropped or loaded them); redraw everything.
        """
        with self._lock:
            if cb not in self._listeners:
                self._listeners.append(cb)

    def remove_listener(self, cb: Callable[[HitRecord], None]) -> None:
        with self._lock:
            if cb in self._listeners:
                self._listeners.remove(cb)

    def load_session(self, folder: Path) -> None:
        """Read the records of ``folder`` (a session's timeline folder) now,
        on the calling thread (file I/O: not for the UI thread; the TUI
        uses :meth:`switch_folder`).

        Live scans keep writing to the live session's folder and switch the
        view back on their next item.
        """
        self._load(Path(folder))
        self._notify_reset()

    def switch_folder(self, folder: Path | str | None = None) -> None:
        """The session timeline's folder changed (session start, resume, new
        session, device switch) or is first known: show its records.

        Any thread, never blocks, works without an active profile (stored
        findings are shown read-only). A different ``folder`` drops the old
        session's records, summary and flow folder from memory at once; the
        worker then reads the new folder's ``hits.jsonl`` / ``coverage.jsonl``
        (the timeline's active folder; ``folder`` when it cannot say) and
        calls the listeners with ``None``. With a profile active, the new
        session's flows and kept versions are retro-scanned once.

        Args:
            folder: The new timeline folder (the ``bound`` doorbell's
                ``folder``), or None to ask the timeline on the worker.
        """
        if self._closed:
            return
        target = Path(folder) if folder is not None else None
        with self._lock:
            if target is not None and target == self._folder and not self._stale:
                return
            if target is not None and self._folder is not None:
                self._clear_views()
        if target is not None and self._folder is not None:
            self._notify_reset()
        self._put(PRIO_LOAD, _LoadItem(None, "", time.monotonic(), folder=target))  # type: ignore[arg-type]

    def _clear_views(self) -> None:
        """Lock held: drop the loaded session's records (its files stay)."""
        self._stale = True
        self._hits = []
        self._by_flow = {}
        self._by_file = {}
        self._covered = set()
        self._version_paths = set()
        self._seen = set()
        self._emitted = set()
        self._version_sets = {}
        self._file_last = {}
        self._flow_dir = None
        self._auto_pulls = {}
        self._retro_iter = None
        self._recount()
        self.revision += 1

    def _notify_reset(self) -> None:
        """Every listener gets ``None``: the loaded records changed as a whole."""
        with self._lock:
            listeners = list(self._listeners)
        for cb in listeners:
            try:
                cb(None)
            except Exception:
                logger.debug("privacy scan: listener failed", exc_info=True)

    # -- worker ---------------------------------------------------------------

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._closed:
                return
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(
                target=self._run, name="privacy-scan", daemon=True
            )
            self._thread.start()

    def _kick(self) -> None:
        """Wake the worker (a retro request needs no queued item)."""
        with self._idle:
            self._pending += 1
        try:
            self._queue.put_nowait((PRIO_RETRO + 1, next(self._counter), None))
        except queue.Full:
            with self._idle:
                self._pending -= 1

    def close(self, timeout: float = 2.0) -> None:
        """Stop the worker (tests, quit)."""
        self._closed = True
        with contextlib.suppress(queue.Full):
            self._queue.put_nowait((PRIO_STOP, next(self._counter), None))
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until every queued item (and a retro scan) is done."""
        deadline = time.monotonic() + timeout
        with self._idle:
            while self._pending > 0 or self._busy or self._retro_pending():
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self._idle.wait(min(left, 0.05))
        return True

    def _retro_pending(self) -> bool:
        return self._retro_request is not None or self._retro_iter is not None

    def _run(self) -> None:
        while not self._closed:
            item = self._next_item()
            if item is None:
                if self._idle_exit():
                    return
                continue
            try:
                self._process(item)
            except Exception:
                logger.debug("privacy scan: item failed", exc_info=True)
            finally:
                with self._idle:
                    self._busy = False
                    self._idle.notify_all()

    def _idle_exit(self) -> bool:
        """No profile and nothing to do: end the worker (``_ensure_worker``
        starts a new one; submitters put first and ensure after).
        """
        with self._lock:
            if (
                self._needles is not None
                or not self._queue.empty()
                or self._retro_pending()
                or self._thread is not threading.current_thread()
            ):
                return False
            self._thread = None
        with self._idle:
            self._idle.notify_all()
        return True

    def _next_item(self) -> _Item | None:
        with self._lock:
            request = self._retro_request
        if request is not None:
            # Load the session first: the listing reads its coverage.
            self._ensure_folder()
            with self._lock:
                if self._retro_request is request:
                    self._retro_request = None
                    self._retro_iter = self._retro_items(*request)
        retro = self._retro_iter
        try:
            entry = (
                self._queue.get(timeout=0.5)
                if retro is None
                else (self._queue.get_nowait())
            )
        except queue.Empty:
            entry = None
        if entry is not None:
            with self._idle:
                self._pending -= 1
                self._busy = entry[2] is not None
                self._idle.notify_all()
            return entry[2]
        if retro is None:
            return None
        with self._idle:
            self._busy = True
        try:
            return next(retro)
        except StopIteration:
            with self._lock:
                if self._retro_iter is retro:
                    self._retro_iter = None
        except Exception:
            logger.debug("privacy scan: retro listing failed", exc_info=True)
            with self._lock:
                self._retro_iter = None
        with self._idle:
            self._busy = False
            self._idle.notify_all()
        return None

    def _process(self, item: _Item) -> None:
        if isinstance(item, _LoadItem):
            self._switch(item)
            return
        if item.retro and item.gen != self._gen:
            return  # listed for a session that is no longer loaded
        self._ensure_folder()
        self._flush_dropped(item)
        if isinstance(item, _FlowItem):
            self._scan_flow(item)
        elif isinstance(item, _VersionItem):
            self._scan_version(item)
        elif isinstance(item, _SweepItem):
            self._scan_sweep(item)
        elif isinstance(item, _SweepDone):
            _prune_empty_dirs(item.root)

    # -- folder / ledger -------------------------------------------------------

    def _folder_now(self) -> Path | None:
        if self._folder_fn is not None:
            return self._folder_fn()
        return current_timeline_folder()

    def _privacy_dir(self) -> Path | None:
        folder = self._folder_now()
        return folder / FOLDER_NAME if folder is not None else None

    def _ensure_folder(self) -> None:
        """Worker: follow the session timeline's folder (lazy backstop of
        :meth:`switch_folder`).
        """
        folder = self._folder_now()
        if folder is not None and (folder != self._folder or self._stale):
            self._switch_to(folder)

    def _switch(self, item: _LoadItem) -> None:
        """Worker: load the session timeline's folder (see switch_folder)."""
        folder = self._folder_now() or item.folder
        if folder is not None and (folder != self._folder or self._stale):
            self._switch_to(folder)

    def _switch_to(self, folder: Path) -> None:
        """Worker: load ``folder``; after a real switch with a profile active,
        retro-scan the new session; tell the listeners.
        """
        previous = self._folder
        self._load(folder)
        with self._lock:
            needles, fp = self._needles, self._fp
            if (
                needles is not None
                and fp is not None
                and previous is not None
                and previous != folder
            ):
                # The new session's flows and versions not yet scanned for
                # the active profile (idempotent per item: coverage).
                self._retro_request = (needles, fp)
        self._notify_reset()

    def _load(self, folder: Path) -> None:
        privacy = folder / FOLDER_NAME
        hits = [
            rec
            for line in _read_jsonl(privacy / HITS_FILE)
            if (rec := HitRecord.from_json(line)) is not None
        ]
        covered = set()
        version_paths = set()
        for line in _read_jsonl(privacy / COVERAGE_FILE):
            key = str(line.get("key") or "")
            if key.startswith("file:") and "@" in key:
                version_paths.add(_canonical(key[5:].rpartition("@")[0]))
            if line.get("skip") in (None, "unscannable") and key:
                covered.add((key, str(line.get("fp")), line.get("engine")))
        with self._lock:
            if self._folder is not None and folder != self._folder:
                self._flow_dir = None  # the old session's mitmproxy folder
                self._auto_pulls = {}
                self._retro_iter = None
            self._folder = folder
            self._stale = False
            self._gen += 1
            self.revision += 1
            self._hits = []
            self._by_flow = {}
            self._by_file = {}
            self._seen = set()
            self._emitted = set()
            self._version_sets = {}
            self._file_last = {}
            self._covered = covered
            self._version_paths |= version_paths
            for rec in hits:
                self._index(rec)
                key = _novelty_key(rec)
                self._seen.add(key)
                if rec.new:
                    self._emitted.add(key)
            self._recount()

    def _index(self, rec: HitRecord) -> None:
        """Lock held: add ``rec`` to the in-memory views."""
        self._hits.append(rec)
        if rec.flow_id:
            self._by_flow.setdefault(rec.flow_id, []).append(rec)
        if rec.device_path:
            self._by_file.setdefault(rec.device_path, []).append(rec)

    def _is_covered(self, key: str, fp: str) -> bool:
        with self._lock:
            return (key, fp, ENGINE_VERSION) in self._covered

    def _ledger(
        self,
        item: _Item,
        *,
        sha256: str | None = None,
        size: int | None = None,
        truncated: bool = False,
        started: float | None = None,
        n_hits: int = 0,
        skip: str | None = None,
        extra: dict | None = None,
    ) -> None:
        key = item.key()
        line = {
            "v": RECORD_VERSION,
            "at": time.time(),
            "key": key,
            "fp": item.fp,
            "engine": ENGINE_VERSION,
            "sha256": sha256,
            "bytes": size,
            "truncated": truncated,
            "ms": round((time.monotonic() - started) * 1000, 1) if started else None,
            "n_hits": n_hits,
            "skip": skip,
            "retro": item.retro,
        }
        if extra:
            line.update(extra)
        self._append(COVERAGE_FILE, [line])
        if skip in (None, "unscannable"):
            with self._lock:
                self._covered.add((key, item.fp, ENGINE_VERSION))

    def _flush_dropped(self, item: _Item) -> None:
        if not self._dropped:
            return
        lines = []
        while self._dropped:
            try:
                key = self._dropped.popleft()
            except IndexError:
                break
            lines.append(
                {
                    "v": RECORD_VERSION,
                    "at": time.time(),
                    "key": key,
                    "fp": item.fp,
                    "engine": ENGINE_VERSION,
                    "skip": "queue-full",
                }
            )
        self._append(COVERAGE_FILE, lines)

    def _append(self, name: str, lines: list[dict]) -> None:
        if not lines or self._folder is None:
            return
        target = self._folder / FOLDER_NAME / name
        text = "".join(
            json.dumps(x, ensure_ascii=False, default=str) + "\n" for x in lines
        )
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "a", encoding="utf-8") as handle:
                handle.write(text)
        except OSError:
            logger.warning(f"privacy scan: cannot write {target}", exc_info=True)

    # -- network ---------------------------------------------------------------

    def _read_detail(self, item: _FlowItem) -> dict | None:
        from sandroid.services.mitmproxy_flow_log import read_flow_detail

        flow_id = str(item.rec.get("id"))
        fresh = not item.retro and time.monotonic() - item.submitted < DETAIL_FRESH_S
        deadline = time.monotonic() + (DETAIL_RETRY_S if fresh else 0.0)
        while True:
            detail = read_flow_detail(item.flow_dir, flow_id)
            if detail is not None:
                return detail
            if time.monotonic() >= deadline or self._closed:
                return None
            time.sleep(0.1)

    def _flow_parts(self, rec: dict, detail: dict | None) -> list[tuple]:
        """``(part, data, direction, truncated, decoded)`` per scanned part.

        Without a details file only what the ``flows.jsonl`` line has: the
        URL (host, path, query) and its content-type headers.
        """
        url = f"{rec.get('host') or ''}{rec.get('path') or ''}"
        parts: list[tuple] = [
            ("url", url.encode("utf-8", "surrogatepass"), "sent", False, None)
        ]
        if detail is None:
            for key, prefix, direction in (
                ("request_content_type", "req", "sent"),
                ("response_content_type", "resp", "received"),
            ):
                value = rec.get(key)
                if value:
                    data = str(value).encode("utf-8", "surrogatepass")
                    part = f"{prefix}.header:Content-Type"
                    parts.append((part, data, direction, False, None))
            return parts
        for side, direction in (("request", "sent"), ("response", "received")):
            prefix = "req" if side == "request" else "resp"
            for pair in detail.get(f"{side}_headers") or ():
                try:
                    name, value = pair[0], pair[1]
                except (IndexError, TypeError, KeyError):
                    continue
                data = str(value).encode("utf-8", "surrogatepass")
                parts.append((f"{prefix}.header:{name}", data, direction, False, None))
            data, truncated, decoded = body_bytes(detail.get(f"{side}_body"))
            if data:
                parts.append((f"{prefix}.body", data, direction, truncated, decoded))
        return parts

    def _scan_flow(self, item: _FlowItem) -> None:
        if self._is_covered(item.key(), item.fp):
            return
        started = time.monotonic()
        rec = item.rec
        # No details file (dropped by retention, never written): scan what
        # the flows.jsonl line has and mark the flow "partial", so a later
        # retro scan with the details completes it.
        detail = self._read_detail(item)
        host = str(rec.get("host") or "")
        app = rec.get("app") or None
        label, party = classify_party(host, app)
        domain = registrable_domain(host)
        recipient = {"label": label, "party": party, "host": host, "domain": domain}
        source = {
            "type": "flow",
            "flow_id": rec.get("id"),
            "flow_seq": rec.get("seq"),
            "net_seq": item.seq,
            "host": host,
            "method": rec.get("method"),
            "path": rec.get("path"),
            "app": app,
        }
        found: list[tuple] = []
        total_bytes = 0
        any_truncated = False
        for part, data, direction, truncated, decoded in self._flow_parts(rec, detail):
            total_bytes += len(data)
            aggs, capped = scan_bytes(item.needles, data, cap=DECOMPRESS_CAP * 2)
            truncated = truncated or capped
            any_truncated = any_truncated or truncated
            for agg in aggs.values():
                found.append((part, direction, truncated, decoded, agg))
        sent_markers = {
            agg.hit.marker_id for _p, d, _t, _c, agg in found if d == "sent"
        }
        # Parts already recorded for this flow and profile (an earlier
        # partial scan) are not recorded again.
        with self._lock:
            known = {
                (h.part, h.marker_id, h.transform)
                for h in self._by_flow.get(str(rec.get("id")), ())
                if h.fp == item.fp
            }
        records = []
        t = rec.get("ts_start")
        for part, direction, truncated, decoded, agg in found:
            if (part, agg.hit.marker_id, agg.hit.transform) in known:
                continue
            records.append(
                self._record(
                    item,
                    agg,
                    part=part,
                    direction=direction,
                    t=t,
                    source=source,
                    recipient=recipient,
                    novelty=(direction, domain),
                    echo=direction == "received" and agg.hit.marker_id in sent_markers,
                    truncated=truncated,
                    decoded=decoded,
                )
            )
        records = self._emit_lines(
            item, records, lens="network", of=item.seq, ref_id=rec.get("id"), pkg=app
        )
        self._commit(records)
        self._ledger(
            item,
            size=total_bytes,
            truncated=any_truncated,
            started=started,
            n_hits=len(records),
            skip="partial" if detail is None else None,
            extra={"flow_id": rec.get("id")},
        )

    # -- files -----------------------------------------------------------------

    def _scan_members(
        self, needles: NeedleSet, files: list[Path]
    ) -> tuple[list[tuple[str, dict, str, bool]], int, bool, str | None]:
        """Scan each file: ``([(member, aggs, sha, truncated)], bytes, any
        truncated, sha256 of the main file)``.
        """
        out = []
        size = 0
        any_truncated = False
        main_sha = None
        for path in files:
            try:
                with open(path, "rb") as handle:
                    aggs, sha, n, truncated = scan_stream(needles, handle)
            except OSError:
                continue
            if main_sha is None:
                main_sha = sha
            size += n
            any_truncated = any_truncated or truncated
            out.append((path.name, aggs, sha, truncated))
        return out, size, any_truncated, main_sha

    def _version_set(
        self, needles: NeedleSet, fp: str, device_path: str, version_dir: Path
    ) -> frozenset:
        """(marker, transform) pairs in a kept version (cached, scanned once)."""
        key = (device_path, version_dir.name, fp)
        with self._lock:
            cached = self._version_sets.get(key)
        if cached is not None:
            return cached
        scanned, _n, _t, _sha = self._scan_members(
            needles, _version_members(device_path, version_dir)
        )
        found = frozenset(k for _m, aggs, _s, _t2 in scanned for k in aggs)
        with self._lock:
            self._version_sets[key] = found
        return found

    def _scan_version(self, item: _VersionItem) -> None:
        if self._is_covered(item.key(), item.fp):
            return
        started = time.monotonic()
        files = _version_members(item.device_path, item.version_dir)
        if not files:
            self._ledger(item, started=started, skip="unscannable")
            return
        scanned, size, any_truncated, main_sha = self._scan_members(item.needles, files)
        current = frozenset(k for _m, aggs, _s, _t in scanned for k in aggs)
        previous = self._previous_version(item)
        before = (
            self._version_set(item.needles, item.fp, item.device_path, previous)
            if previous is not None
            else self._last_file_set(item.device_path, item.version_dir.name)
        )
        with self._lock:
            self._version_sets[(item.device_path, item.version_dir.name, item.fp)] = (
                current
            )
        self._note_file_set(item.device_path, item.version_dir.name, current)
        t = _version_time(item.version_dir)
        records = []
        for member, aggs, sha, truncated in scanned:
            source = {
                "type": "file",
                "device_path": item.device_path,
                "version": item.version_dir.name,
                "member": member,
                "sha256": sha,
                "pull_seq": item.pull_seq,
                "package": item.package,
            }
            for key, agg in aggs.items():
                records.append(
                    self._record(
                        item,
                        agg,
                        part=f"file:{member}",
                        direction="stored",
                        t=t,
                        source=source,
                        recipient=None,
                        novelty=("stored", item.device_path),
                        new=key not in before,
                        truncated=truncated,
                    )
                )
        records = self._emit_lines(
            item, records, lens="files", of=item.pull_seq, ref_id=None, pkg=item.package
        )
        self._commit(records)
        self._ledger(
            item,
            sha256=main_sha,
            size=size,
            truncated=any_truncated,
            started=started,
            n_hits=len(records),
            extra={"device_path": item.device_path, "version": item.version_dir.name},
        )

    @staticmethod
    def _previous_version(item: _VersionItem) -> Path | None:
        """The kept version just before ``item``'s (its sibling folder)."""
        parent = item.version_dir.parent
        number = _version_number(item.version_dir)
        if not parent.is_dir() or number < 0:
            return None
        older = [
            d
            for d in parent.iterdir()
            if d.is_dir() and 0 <= _version_number(d) < number
        ]
        return max(older, key=_version_number) if older else None

    def _last_file_set(self, device_path: str, scan_id: str) -> frozenset:
        with self._lock:
            entry = self._file_last.get(device_path)
        if entry is None:
            return frozenset()
        sid, before, current = entry
        return before if sid == scan_id else current

    def _note_file_set(self, device_path: str, scan_id: str, found: frozenset) -> None:
        with self._lock:
            entry = self._file_last.get(device_path)
            if entry is not None and entry[0] == scan_id:
                self._file_last[device_path] = (scan_id, entry[1], entry[2] | found)
            else:
                before = entry[2] if entry is not None else frozenset()
                self._file_last[device_path] = (scan_id, before, found)

    def _scan_sweep(self, item: _SweepItem) -> None:
        started = time.monotonic()
        scanned, size, truncated, sha = self._scan_members(item.needles, [item.local])
        aggs = scanned[0][1] if scanned else {}
        if not aggs:
            with contextlib.suppress(OSError):
                item.local.unlink()
            self._ledger(
                item,
                sha256=sha,
                size=size,
                truncated=truncated,
                started=started,
                skip=None if scanned else "unscannable",
            )
            return
        before = self._last_file_set(item.device_path, item.sweep_id)
        self._note_file_set(item.device_path, item.sweep_id, frozenset(aggs))
        source = {
            "type": "file",
            "device_path": item.device_path,
            "version": f"sweep:{item.sweep_id}",
            "member": item.member,
            "sha256": sha,
            "pull_seq": None,
            "package": item.package,
            "local": str(item.local),
        }
        if item.run_id:
            source["run_id"] = item.run_id
        records = [
            self._record(
                item,
                agg,
                part=f"file:{item.member}",
                direction="stored",
                t=time.time(),
                source=source,
                recipient=None,
                novelty=("stored", item.device_path),
                new=key not in before,
                truncated=truncated,
            )
            for key, agg in aggs.items()
        ]
        records = self._emit_lines(
            item, records, lens="files", of=None, ref_id=None, pkg=item.package
        )
        self._commit(records)
        self._ledger(
            item,
            sha256=sha,
            size=size,
            truncated=truncated,
            started=started,
            n_hits=len(records),
        )

    # -- records / timeline --------------------------------------------------

    def _record(
        self,
        item: _Item,
        agg: _Agg,
        *,
        part: str,
        direction: str,
        t: Any,
        source: dict,
        recipient: dict | None,
        novelty: tuple,
        new: bool | None = None,
        echo: bool = False,
        truncated: bool = False,
        decoded: str | None = None,
    ) -> HitRecord:
        hit = agg.hit
        key = (hit.marker_id, hit.transform, *novelty)
        with self._lock:
            if new is None:
                new = key not in self._seen
            self._seen.add(key)
            marker = self._markers.get(hit.marker_id)
        when = float(t) if isinstance(t, (int, float)) else None
        return HitRecord(
            v=RECORD_VERSION,
            at=time.time(),
            t=when,
            fp=item.fp,
            engine=ENGINE_VERSION,
            marker_id=hit.marker_id,
            label=hit.label,
            tag=hit.tag,
            kind=hit.kind,
            transform=hit.transform,
            confidence=agg.confidence,
            part=part,
            direction=direction,
            count=agg.count,
            offsets=tuple(agg.offsets),
            snippet=agg.snippet,
            source=source,
            recipient=recipient,
            new=bool(new),
            echo=echo,
            truncated=truncated,
            retro=item.retro,
            encoded=is_encoded(hit.transform),
            approx=is_approx(marker, hit.transform),
            decoded=decoded,
        )

    def _emit_lines(
        self,
        item: _Item,
        records: list[HitRecord],
        *,
        lens: str,
        of: int | None,
        ref_id: Any,
        pkg: str | None,
    ) -> list[HitRecord]:
        """One ``privacy/sent|stored`` line per new finding (not yet emitted)."""
        out = []
        for rec in records:
            if not rec.new or rec.direction == "received":
                out.append(rec)
                continue
            key = _novelty_key(rec)
            with self._lock:
                if key in self._emitted:
                    out.append(rec)
                    continue
                self._emitted.add(key)
            seq = self._emit_line(rec, lens=lens, of=of, ref_id=ref_id, pkg=pkg)
            out.append(_replace_seq(rec, seq) if seq is not None else rec)
        return out

    def _emit_line(
        self, rec: HitRecord, *, lens: str, of: int | None, ref_id: Any, pkg: str | None
    ) -> int | None:
        ref: dict[str, Any] = {"path": f"{FOLDER_NAME}/{HITS_FILE}", "lens": lens}
        if of is not None:
            ref["of"] = of
        if ref_id is not None:
            ref["id"] = ref_id
        data: dict[str, Any] = {
            "marker_id": rec.marker_id,
            "label": rec.label,
            "tag": rec.tag,
            "transform": rec.transform,
            "confidence": rec.confidence,
            "part": rec.part,
            "direction": rec.direction,
            "count": rec.count,
            "fp": rec.fp,
            "engine": rec.engine,
            "retro": rec.retro,
        }
        if rec.source.get("run_id"):
            data["run_id"] = rec.source["run_id"]
        transform = _transform_words(rec.transform)
        if rec.direction == "sent":
            src = rec.source
            recipient = rec.recipient or {}
            data.update(
                host=src.get("host"),
                method=src.get("method"),
                path=src.get("path"),
                flow_seq=src.get("flow_seq"),
                party=recipient.get("party"),
                recipient=recipient.get("label"),
            )
            summary = (
                f"{rec.label} sent to {src.get('host') or 'an unknown host'}, "
                f"{_part_words(rec.part)}, {transform}"
            )
            kind = "sent"
        else:
            src = rec.source
            data.update(
                path=src.get("device_path"),
                version=src.get("version"),
                member=src.get("member"),
            )
            try:
                from sandroid.core.watchlist_store import owner_and_relative

                where = owner_and_relative(str(src.get("device_path")))[1]
            except Exception:
                where = str(src.get("device_path"))
            summary = f"{rec.label} stored in {where}, {transform}"
            kind = "stored"
        try:
            from sandroid.core.timeline import get_timeline

            return get_timeline().emit(
                "privacy",
                kind,
                summary=summary,
                actor="app",
                level="info",
                t=rec.t,
                data=data,
                ref=ref,
                pkg=pkg,
            )
        except Exception:
            logger.debug("privacy scan: timeline line failed", exc_info=True)
            return None

    def _commit(self, records: list[HitRecord]) -> None:
        if not records:
            return
        self._append(HITS_FILE, [r.to_json() for r in records])
        with self._lock:
            self.revision += 1
            for rec in records:
                self._index(rec)
                if rec.fp == self._fp:
                    self._found_values.add(
                        self._value_key.get(rec.marker_id, rec.marker_id)
                    )
                    self._hits_total += 1
                    self._last_hit_at = rec.at
            listeners = list(self._listeners)
        for rec in records:
            for cb in listeners:
                try:
                    cb(rec)
                except Exception:
                    logger.debug("privacy scan: listener failed", exc_info=True)

    # -- retro -------------------------------------------------------------------

    def _retro_items(self, needles: NeedleSet, fp: str) -> Iterator[_Item]:
        """Items of the session not yet scanned for ``fp`` (lazily, oldest first).

        Each item carries the folder generation it was listed for; after a
        session switch the rest is dropped (``_process``).
        """
        gen = self._gen
        now = time.monotonic()
        if self._flow_dir_fn is not None:
            flow_dir = self._flow_dir_fn()
        else:
            flow_dir = self._flow_dir or _default_flow_dir()
        if flow_dir is not None:
            from sandroid.services.mitmproxy_flow_log import _read_records

            records, _offset = _read_records(flow_dir / "flows.jsonl", 0)
            for rec in records:
                if rec.get("kind") == "tls" or not rec.get("id"):
                    continue
                item = _FlowItem(
                    needles,
                    fp,
                    now,
                    retro=True,
                    gen=gen,
                    rec=rec,
                    flow_dir=flow_dir,
                    seq=None,
                )
                if not self._is_covered(item.key(), fp):
                    yield item
        for version_dir, device_path in _kept_versions():
            item = _VersionItem(
                needles,
                fp,
                now,
                retro=True,
                gen=gen,
                device_path=device_path,
                version_dir=version_dir,
                pull_seq=None,
                package=_package_of(device_path),
            )
            if not self._is_covered(item.key(), fp):
                yield item


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _transform_words(transform: str) -> str:
    """``sha256(lower(value))`` -> ``sha256 of the lower-case value``."""
    try:
        from sandroid.core.report_engine import transform_words

        return transform_words(transform)
    except Exception:
        return short_transform(transform)


def _part_words(part: str) -> str:
    """``req.body`` -> ``request body``, ``url`` -> ``URL``."""
    try:
        from sandroid.core.report_engine import part_words

        return part_words(part)
    except Exception:
        return part_label(part)


@dataclass(frozen=True)
class RunScope:
    """Which findings belong to one run (the run report and the Sessions
    lens Privacy tab both use this one definition).

    A run is the recording it replays plus its Play: a finding belongs to
    the run when its item happened in the recording window (``record-start``
    to ``record-stop``) or in the Play window (Play start to the run's
    completion), or when it carries the run's id (the end-of-run sweep,
    found after the run's end). Overlapping windows are merged.

    Attributes:
        run_id: The run's id (sweep records carry it), or None.
        windows: ``(t0, t1)`` epoch windows, sorted, not overlapping.
    """

    run_id: str | None
    windows: tuple[tuple[float, float], ...] = ()

    def covers(self, rec: HitRecord) -> bool:
        """``rec`` belongs to the run."""
        if self.run_id and rec.source.get("run_id") == self.run_id:
            return True
        t = rec.t
        return t is not None and any(a <= t <= b for a, b in self.windows)


def run_scope(
    run_id: str | None,
    play: tuple[float | None, float | None] | None,
    record: Any = None,
) -> RunScope:
    """The :class:`RunScope` of a run from its Play window and the window of
    the recording it replays (either may be missing or partial).
    """
    windows: list[tuple[float, float]] = []
    for window in (record, play):
        if not isinstance(window, (list, tuple)) or len(window) != 2:
            continue
        a, b = window
        if not isinstance(a, (int, float)):
            continue
        b = b if isinstance(b, (int, float)) else a
        windows.append((float(a), float(max(a, b))))
    windows.sort()
    merged: list[tuple[float, float]] = []
    for a, b in windows:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return RunScope(run_id or None, tuple(merged))


def run_scope_of(summary: Any) -> RunScope | None:
    """The :class:`RunScope` of a run summary / :class:`RunRecord` (its
    ``recorded_at`` / ``completed_at`` Play window and ``record_window``),
    or None without a Play start.
    """

    def get(name: str) -> Any:
        if isinstance(summary, dict):
            return summary.get(name)
        return getattr(summary, name, None)

    def epoch(value: Any) -> float | None:
        if not value:
            return None
        try:
            from datetime import datetime

            dt = datetime.fromisoformat(str(value))
        except (TypeError, ValueError):
            return None
        return (dt if dt.tzinfo else dt.astimezone()).timestamp()

    start = epoch(get("recorded_at"))
    if start is None:
        return None
    end = epoch(get("completed_at"))
    return run_scope(get("run_id"), (start, end), get("record_window"))


def run_hits(records: list[HitRecord], scope: RunScope) -> list[HitRecord]:
    """The records of one run (see :class:`RunScope`)."""
    return [h for h in records if scope.covers(h)]


def read_hits(folder: Path | str) -> tuple[list[HitRecord], bool]:
    """Read a session's stored findings (read-only; file I/O, not on the UI
    thread).

    Args:
        folder: The session's timeline folder.

    Returns:
        ``(records, scanned)``: ``scanned`` means the privacy scan ran in
        that session (its ``coverage.jsonl`` or ``hits.jsonl`` exists).
    """
    privacy = Path(folder) / FOLDER_NAME
    records = [
        rec
        for line in _read_jsonl(privacy / HITS_FILE)
        if (rec := HitRecord.from_json(line)) is not None
    ]
    scanned = bool(records) or (privacy / COVERAGE_FILE).is_file()
    return records, scanned


def current_timeline_folder() -> Path | None:
    """The live session timeline's folder (what the scan writes below)."""
    from sandroid.core import timeline

    try:
        status = timeline.get_timeline().status()
        if status.folder:
            return Path(status.folder)
    except Exception:
        pass
    try:
        return timeline.timeline_folder()
    except Exception:
        return None


def _canonical(device_path: str) -> str:
    try:
        from sandroid.core.adb_utils import canonical_device_path

        return canonical_device_path(device_path)
    except Exception:
        return device_path


def _novelty_key(rec: HitRecord) -> tuple:
    if rec.direction == "stored":
        where = rec.source.get("device_path")
    else:
        where = (rec.recipient or {}).get("domain") or registrable_domain(
            str(rec.source.get("host") or "")
        )
    return (rec.marker_id, rec.transform, rec.direction, where)


def _replace_seq(rec: HitRecord, seq: int) -> HitRecord:
    from dataclasses import replace

    return replace(rec, tl_seq=seq)


def _tags(records: list[HitRecord]) -> list[TagInfo]:
    by_marker: dict[str, list[HitRecord]] = {}
    for rec in records:
        by_marker.setdefault(rec.marker_id, []).append(rec)
    tags = []
    for marker_id, recs in by_marker.items():
        best = min(recs, key=lambda r: CONFIDENCES.index(r.confidence))
        direction = min(
            (r.direction for r in recs), key=lambda d: _DIRECTION_RANK.get(d, 9)
        )
        if direction == "stored":
            party = "stored"
        else:
            party = (recs[0].recipient or {}).get("party") or "unknown"
        tags.append(
            TagInfo(
                tag=best.tag,
                label=best.label,
                marker_id=marker_id,
                party=party,
                direction=direction,
                encoded=all(r.encoded for r in recs),
                approx=all(r.approx for r in recs),
                confidence=best.confidence,
            )
        )
    tags.sort(
        key=lambda g: (
            CONFIDENCES.index(g.confidence),
            _DIRECTION_RANK.get(g.direction, 9),
            g.label.lower(),
        )
    )
    return tags


def _read_jsonl(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _package_of(device_path: str) -> str | None:
    try:
        from sandroid.core.watchlist_store import package_of

        return package_of(device_path)
    except Exception:
        return None


def _version_number(version: Path) -> int:
    match = re.match(r"^v(\d+)_", version.name)
    return int(match.group(1)) if match else -1


def _version_members(device_path: str, version_dir: Path) -> list[Path]:
    """The kept copy of a version: main file, then ``-wal``/``-journal``."""
    from sandroid.core import watchlist_store

    main = watchlist_store.version_file(version_dir, device_path)
    files = [main, *(Path(f"{main}{s}") for s in _COMPANIONS)]
    return [f for f in files if f.is_file()]


def _version_time(version_dir: Path) -> float | None:
    try:
        from sandroid.core.watchlist_store import version_time

        when = version_time(version_dir)
        return when.timestamp() if when is not None else None
    except Exception:
        return None


def _device_path_of(root: Path, row: Path) -> str | None:
    """Undo ``watchlist_store.row_dir`` for a version without a record."""
    try:
        parts = row.relative_to(root).parts
    except ValueError:
        return None
    if not parts:
        return None
    owner, rest = parts[0], "/".join(parts[1:])
    if owner == "_device":
        return "/" + rest
    if rest.startswith("@de/"):
        return f"/data/user_de/0/{owner}/{rest[4:]}"
    if rest.startswith("@ext/"):
        return f"/sdcard/Android/data/{owner}/{rest[5:]}"
    return f"/data/data/{owner}/{rest}"


def _kept_versions() -> Iterator[tuple[Path, str]]:
    """``(version dir, device path)`` of every kept version of the session.

    The device path comes from ``acquisition.json``; versions kept without
    one (the AI pull path) get it from their folder.
    """
    try:
        from sandroid.core import watchlist_store

        root = watchlist_store.files_root()
    except Exception:
        return
    if not root.is_dir():
        return
    found = []
    for current, dirs, _files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in dirs:
            if _VERSION_DIR_RE.match(name):
                found.append(Path(current) / name)
    for version_dir in sorted(found, key=lambda d: (str(d.parent), _version_number(d))):
        record = watchlist_store.version_record(version_dir) or {}
        device_path = record.get("device_path")
        if not (isinstance(device_path, str) and device_path):
            device_path = _device_path_of(root, version_dir.parent)
        if device_path:
            yield version_dir, device_path


def _default_flow_dir() -> Path | None:
    try:
        from sandroid.services.mitmproxy_flow_log import resolve_flow_dir

        flow_dir = resolve_flow_dir()
    except Exception:
        return None
    return flow_dir if flow_dir.is_dir() else None


def _prune_empty_dirs(root: Path) -> None:
    """Remove the empty folders a sweep left (files without hits are gone)."""
    if not root.is_dir():
        return
    for directory in sorted(
        (p for p in root.rglob("*") if p.is_dir()), key=lambda p: -len(p.parts)
    ):
        with contextlib.suppress(OSError):
            directory.rmdir()
    with contextlib.suppress(OSError):
        root.rmdir()


# ---------------------------------------------------------------------------
# singleton + wiring
# ---------------------------------------------------------------------------


def get_privacy_scan_service() -> PrivacyScanService:
    """The process's privacy scan service (``reset_services`` drops it)."""
    from sandroid.services import _get_or_create

    return _get_or_create(PrivacyScanService)


def _net_sink(rec: dict, flow_dir: Path, seq: int | None) -> None:
    """The ``NetFlowSource`` sink: enqueue only."""
    get_privacy_scan_service().submit_flow(rec, flow_dir, seq)


def _on_timeline_event(event: Any) -> None:
    """The timeline doorbell: a ``bound`` (new active timeline folder: a
    session started, resumed or switched, or another device) switches the
    scan's records to that folder. Enqueue only, never blocks.
    """
    payload = getattr(event, "data", event) or {}
    if not isinstance(payload, dict) or payload.get("op") != "bound":
        return
    if payload.get("active") is False:
        return
    try:
        service = _existing_service()
        if service is not None:
            service.switch_folder(payload.get("folder") or None)
    except Exception:
        logger.debug("privacy scan: session switch failed", exc_info=True)


def _existing_service() -> PrivacyScanService | None:
    """The singleton when it exists (the doorbell never creates one)."""
    try:
        from sandroid.services import _service_instances

        return _service_instances.get(PrivacyScanService)
    except Exception:
        return None


def _subscribe_timeline(on: bool) -> None:
    try:
        from sandroid.core.events import EventBus, EventType

        bus = EventBus.get()
        bus.unsubscribe(EventType.TIMELINE_EVENT, _on_timeline_event)
        if on:
            bus.subscribe(EventType.TIMELINE_EVENT, _on_timeline_event)
    except Exception:
        logger.debug("privacy scan: no timeline doorbell", exc_info=True)


def start_privacy_scan() -> PrivacyScanService:
    """TUI startup: scan logged flows, follow the identity profile and the
    session timeline's folder (its stored findings load even with no
    profile active).
    """
    from sandroid.services.tracking_service import NetFlowSource

    service = get_privacy_scan_service()
    NetFlowSource.add_sink(_net_sink)
    _subscribe_timeline(True)
    service.attach_identity()
    service.switch_folder()  # the session the TUI started in (worker reads)
    return service


def stop_privacy_scan() -> None:
    """Undo :func:`start_privacy_scan` and stop the worker."""
    with contextlib.suppress(Exception):
        from sandroid.services.tracking_service import NetFlowSource

        NetFlowSource.remove_sink(_net_sink)
    _subscribe_timeline(False)
    get_privacy_scan_service().close()


def submit_pulled_version(
    device_path: str, version_dir: Path, pull_seq: int | None
) -> None:
    """Pull paths: scan a just-kept version (never raises, never blocks)."""
    try:
        service = get_privacy_scan_service()
        if service.is_active:
            service.submit_version(device_path, version_dir, pull_seq)
    except Exception:
        logger.debug("privacy scan: submit_version failed", exc_info=True)


def sweep_after_run(
    package: str | None = None,
    serial: str | None = None,
    *,
    run_id: str | None = None,
) -> bool:
    """A Play finished: sweep the app's data folders when a profile is active.

    ``package`` defaults to the Spotlight app, ``serial`` to the adb target.
    ``run_id``: the finished run; the sweep's records carry it, so the run's
    Privacy tab includes them although they are found after its end.
    Returns whether a sweep was started (never raises, never blocks).
    """
    try:
        service = get_privacy_scan_service()
        if not service.is_active:
            return False
        if package is None:
            from sandroid.services import get_spotlight_service

            package = get_spotlight_service().get_package_name()
        if not package:
            return False
        if serial is None:
            from sandroid.core.adb import Adb

            serial = Adb.get_target_device()
        service.sweep_app_data(serial, package, run_id=run_id)
        return True
    except Exception:
        logger.debug("privacy scan: sweep after run failed", exc_info=True)
        return False


__all__ = [
    "AUTO_WATCH_DIRS",
    "AUTO_WATCH_MIN_INTERVAL_S",
    "ENGINE_VERSION",
    "HitRecord",
    "PrivacyScanService",
    "PrivacySummary",
    "TagInfo",
    "body_bytes",
    "classify_party",
    "current_timeline_folder",
    "get_privacy_scan_service",
    "is_approx",
    "is_encoded",
    "read_hits",
    "registrable_domain",
    "run_hits",
    "scan_bytes",
    "scan_stream",
    "start_privacy_scan",
    "stop_privacy_scan",
    "submit_pulled_version",
    "sweep_after_run",
    "unwrap_compressed",
]
