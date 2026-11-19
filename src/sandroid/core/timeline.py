"""The session timeline: one append-only, hash-chained JSON Lines file per
device folder (``<results>/<session>/<device>/timeline.jsonl``).

Every source (file monitor, monitor notes, device clock, snapshots, device
connects, record/play phases, labels, later input/screen/shots/net) calls
:func:`emit` (or a helper of :class:`TimelineService`). ``emit`` never
blocks and does no I/O: it validates, applies the policy, routes the line
to the sink of its device, assigns ``seq`` under the service lock and
queues it. One daemon thread (``timeline-writer``) does the rest for every
sink: time conversion (device CLOCK_MONOTONIC -> host), world/epoch/phase
stamping, canonical JSON, the sha256 chain (``h`` spliced in last),
``os.write`` every <=100 ms tick and ``fsync`` at most once a second (and at
once on flush/seal/close). The service lock is never held during file I/O.

Envelope, time model, sources and API: see the session timeline design
(DESIGN_FINAL §2-§8). Readers (:func:`read_lines`, :func:`verify_chain`,
...) work on any file without a service. ``python -m sandroid.core.timeline
verify|seal|tail|labels PATH [--json]`` checks a file from the shell.
"""

from __future__ import annotations

import argparse
import atexit
import bisect
import contextlib
import hashlib
import itertools
import json
import logging
import math
import os
import re
import socket
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger(__name__)

SCHEMA = 1
FILE_NAME = "timeline.jsonl"
LOCK_NAME = ".timeline.lock"
GENESIS_PREFIX = "sandroid-timeline-v1:"
ACTORS = frozenset({"user", "replay", "sandroid", "app", "system", "ai"})
PHASES = ("live", "record", "replay", "dry-run", "setup")
CLOCKS = ("host", "dev_mono", "dev_wall", "none")
LEVELS = ("info", "warn", "error")
MUST_KEEP = frozenset(
    {"label", "sandroid", "clock", "snapshot", "device", "run", "tracking", "input",
     "screen", "shot"}
)  # fmt: skip
ALWAYS_ON = frozenset({"label", "sandroid", "clock", "snapshot", "device", "run"})
#: Must-keep kinds of otherwise bulk sources (evidence pulls/checks).
MUST_KEEP_KINDS = frozenset({("files", "pull"), ("files", "check")})
SUMMARY_MAX = 240
DATA_MAX = 16_384
RING_SIZE = 5_000
DETACHED_CAP = 2_000
TimeLike = float | datetime | None
Reader = Literal["ui", "export", "report", "ai"]

#: Drift allowance of a dev_mono conversion (ms of error per s from the sample).
DRIFT_MS_PER_S = 0.01
#: Writer tick (s) and fsync interval (s) while dirty.
TICK_S = 0.1
FSYNC_S = 1.0
#: Max lines drained from one sink per tick.
BATCH_MAX = 2_000
#: Doorbell: at most this many TIMELINE_EVENT "lines" per second per sink.
DOORBELL_HZ = 4.0
#: The ``near`` window of a dev_mono conversion: [near - 30 s, near + 1 s].
NEAR_BEFORE_S = 30.0
NEAR_AFTER_S = 1.0

_SRC_RE = re.compile(r"^[a-z][a-z0-9_-]{0,15}$")
_KIND_RE = re.compile(r"^[a-z][a-z0-9_-]{0,23}$")
_HEX64 = re.compile(rb"^[0-9a-f]{64}$")
_H_SUFFIX_LEN = 72  # len(',"h":"') + 64 + len('"}')
_ESC = str.maketrans({"\u0085": "\\u0085", "\u2028": "\\u2028", "\u2029": "\\u2029"})
_SURROGATES = re.compile("[\ud800-\udfff]")

#: The writer's file write (tests stall it).
_write: Callable[[int, bytes], int] = os.write
#: The writer's monotonic clock (tests drive the periodic clock sample).
_monotonic: Callable[[], float] = time.monotonic

_ACTOR: ContextVar[str | None] = ContextVar("sandroid_timeline_actor", default=None)

#: Plausible line times (epoch s): 1970 .. 2100. A ``t`` outside (e.g. ms
#: passed as s) is not used: the line falls back to ``t_rx`` (``clk: none``).
T_MIN = 0.0
T_MAX = 4_102_444_800.0
#: Label versions are unique across every timeline file of the process, so a
#: (folder, version) or a bare version never collides after a device switch.
_LABEL_VERSIONS = itertools.count(1)


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _iso(epoch: float) -> str:
    from sandroid.core.watchlist_store import iso_tz

    return iso_tz(epoch, "milliseconds")


def _instant(value: Any) -> float | None:
    """Epoch seconds of an ISO string / datetime / number (None: unknown)."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value) if math.isfinite(value) else None
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value).timestamp()
        except ValueError:
            return None
    return None


def _t_ok(value: Any) -> bool:
    """``value`` is a finite epoch inside [:data:`T_MIN`, :data:`T_MAX`]."""
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and T_MIN <= value <= T_MAX
    )


def _valid_instant(value: Any) -> float | None:
    """:func:`_instant` when it is a plausible line time, else None."""
    try:
        number = _instant(value)
    except (OverflowError, OSError, ValueError):
        return None
    return number if _t_ok(number) else None


def _note_data(fields: dict, key: str, value: Any) -> None:
    """Add ``key`` to the line's ``data`` (wrapping a non-dict ``data``)."""
    data = fields.get("data")
    if data is None:
        fields["data"] = {key: value}
    elif isinstance(data, dict):
        data[key] = value
    else:
        fields["data"] = {"value": data, key: value}


def _clean_str(text: str) -> str:
    return _SURROGATES.sub("�", text) if _SURROGATES.search(text) else text


def _sanitise(value: Any, path: str, nonfinite: list[str]) -> Any:
    """A JSON-safe copy: lone surrogates -> U+FFFD, datetime -> ISO, Path ->
    str, tuple/set -> list, non-finite float -> None (noted in ``nonfinite``).
    """
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        nonfinite.append(path)
        return None
    if isinstance(value, str):
        return _clean_str(value)
    if isinstance(value, datetime):
        return _iso(value.timestamp())
    if isinstance(value, Path):
        return _clean_str(str(value))
    if isinstance(value, Mapping):
        return {
            _clean_str(str(k)): _sanitise(v, f"{path}.{k}" if path else str(k),
                                          nonfinite)
            for k, v in value.items()
        }  # fmt: skip
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else value
        return [_sanitise(v, f"{path}[{i}]", nonfinite) for i, v in enumerate(items)]
    return _clean_str(str(value))


def canonical(line: Mapping) -> bytes:
    """The canonical bytes of ``line`` (without ``h``; no trailing newline)."""
    text = json.dumps(
        line, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    )  # fmt: skip
    return text.translate(_ESC).encode("utf-8")


def line_hash(prev_h: str, payload: bytes) -> str:
    """``sha256(prev_h + payload)`` as hex (``payload`` = canonical bytes)."""
    return hashlib.sha256(prev_h.encode("ascii") + payload).hexdigest()


def genesis(session_id: str) -> str:
    """The chain's starting hash of a session id (stored in the open line)."""
    return hashlib.sha256((GENESIS_PREFIX + session_id).encode("utf-8")).hexdigest()


def _splice(body: bytes, h: str) -> bytes:
    return body[:-1] + b',"h":"' + h.encode("ascii") + b'"}\n'


def _session_id(folder: Path) -> str:
    return f"{folder.parent.name}/{folder.name}"


def timeline_folder() -> Path:
    """The live session's device folder (``watchlist_store.files_root().parent``)."""
    from sandroid.core import watchlist_store

    return watchlist_store.files_root().parent


def session_folder() -> Path | None:
    """The live session's folder (``results/<session>/``), or None.

    In order: the pulled-files override (tests: ``files_root().parent.parent``,
    as :func:`timeline_folder`), the initialization service's session (or
    its device folder's parent), ``$SESSION_PATH``, then ``$RESULTS_PATH``
    while no device folder exists (the initialization service points it at
    the session until a device is chosen). Never ``./results`` or the cwd.
    """
    from sandroid.core import watchlist_store

    try:
        if os.environ.get(watchlist_store.FILES_DIR_ENV):
            return timeline_folder().parent.absolute()
    except Exception:
        pass
    try:
        from sandroid.services import get_initialization_service

        service = get_initialization_service()
        session = service.get_session_path()
        if session:
            return Path(session).expanduser().absolute()
        device_path = service.get_device_path()
        if device_path:
            return Path(device_path).expanduser().absolute().parent
    except Exception:
        logger.debug("timeline: no initialized session", exc_info=True)
    for name in ("SESSION_PATH", "RESULTS_PATH"):
        value = os.environ.get(name)
        if value:
            return Path(value).expanduser().absolute()
    return None


@contextlib.contextmanager
def acting_as(actor: str) -> Iterator[None]:
    """Lines emitted on this thread inside the block default to ``actor``.

    A ContextVar: it does not cross ``call_from_thread`` or Textual thread
    workers; enter it on the thread that emits.
    """
    token = _ACTOR.set(actor if actor in ACTORS else "sandroid")
    try:
        yield
    finally:
        _ACTOR.reset(token)


def current_actor(default: str = "sandroid") -> str:
    """The actor of :func:`acting_as` on this thread, else ``default``."""
    return _ACTOR.get() or default


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------


_FILE_KINDS: dict[str, tuple[str, str, bool]] = {
    # token or label -> (kind, display op, is a directory)
    "FSE_CREATE_FILE": ("create", "CREATE", False),
    "FSE_CREATE_DIR": ("create", "CREATE DIR", True),
    "FSE_CONTENT_MODIFIED": ("modify", "MODIFY", False),
    "FSE_DELETE": ("delete", "DELETE", False),
    "FSE_RENAME": ("rename", "RENAME", False),
    "FSE_STAT_CHANGED": ("attrs", "ATTRS", False),
    "FSE_ATTRIB": ("attrs", "ATTRS", False),
    "FSE_XATTR_MODIFIED": ("attrs", "XATTR", False),
    "FSE_OPEN": ("open", "OPEN", False),
    "FSE_OPEN_WRITE": ("open", "OPEN W", False),
    "FSE_CLOSE": ("close", "CLOSE", False),
    "CREATE": ("create", "CREATE", False),
    "CREATE DIR": ("create", "CREATE DIR", True),
    "MODIFY": ("modify", "MODIFY", False),
    "DELETE": ("delete", "DELETE", False),
    "RENAME": ("rename", "RENAME", False),
    "ATTRS": ("attrs", "ATTRS", False),
    "XATTR": ("attrs", "XATTR", False),
    "OPEN": ("open", "OPEN", False),
    "OPEN W": ("open", "OPEN W", False),
    "CLOSE": ("close", "CLOSE", False),
}


def file_kind(op: str) -> tuple[str, str, bool]:
    """``(kind, display op, is_dir)`` of a monitor FSE token or label."""
    op = (op or "").strip()
    return _FILE_KINDS.get(op) or _FILE_KINDS.get(op.upper()) or ("other", op, False)


def _policy_sections() -> tuple[dict, dict]:
    """``(timeline minus mask_sensitive, tracking)`` of the live config."""
    try:
        from sandroid.config import get_config

        cfg = get_config()
        tl = cfg.timeline.model_dump(mode="json")
        tr = cfg.tracking.model_dump(mode="json")
    except Exception:
        logger.debug("timeline: config unavailable, default policy", exc_info=True)
        from sandroid.config.schema import TimelineConfig, TrackingConfig

        tl = TimelineConfig().model_dump(mode="json")
        tr = TrackingConfig().model_dump(mode="json")
    tl.pop("mask_sensitive", None)
    return tl, tr


class Policy:
    """What is written, counted or dropped (``timeline.*`` config)."""

    def __init__(self, timeline: Mapping | None = None) -> None:
        if timeline is None:
            timeline, _tracking = _policy_sections()
        tl = dict(timeline)
        self.sources: dict[str, bool] = dict(tl.get("sources") or {})
        self.kinds_off = frozenset(tl.get("kinds_off") or ())
        self.count_only = frozenset(tl.get("count_only") or ())
        self.files_attrs = str(tl.get("files_attrs") or "app_dirs")
        self.coalesce_s = (
            max(0.0, float(tl.get("files_modify_coalesce_ms", 1000))) / 1e3
        )
        self.count_window_s = float(tl.get("count_window_s", 5.0))
        self.queue_max = int(tl.get("queue_max", 10_000))
        self.clock_every_s = float(tl.get("clock_every_s", 60))

    def decide(self, src: str, kind: str, *, in_app: bool = False) -> str:
        """``"keep"`` | ``"count"`` | ``"off"`` for a line of ``src``/``kind``."""
        if src in ALWAYS_ON:
            return "keep"
        if not self.sources.get(src, True):
            return "off"
        if f"{src}.{kind}" in self.kinds_off or f"{src}.*" in self.kinds_off:
            return "off"
        if src == "files" and kind == "attrs":
            if self.files_attrs == "lines":
                return "keep"
            if self.files_attrs == "counts":
                return "count"
            return "keep" if in_app else "count"
        if f"{src}.{kind}" in self.count_only or f"{src}.*" in self.count_only:
            return "count"
        return "keep"


# ---------------------------------------------------------------------------
# public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LabelEvent:
    """One label line (start / end / point) as the Labels API sees it."""

    seq: int | None
    number: int
    kind: str
    name: str
    t: float
    parent: int | None
    depth: int
    of: int | None
    ended_by: str | None
    actor: str

    @property
    def when(self) -> datetime:
        """``t`` as a naive local datetime (the Files lens's mark time)."""
        return datetime.fromtimestamp(self.t)


@dataclass(frozen=True)
class SinkStatus:
    """The state of one timeline file (or of the detached buffer)."""

    folder: str | None
    serial: str | None
    session_id: str | None
    state: Literal["detached", "open", "locked", "failed", "closed"]
    lines: int
    bytes: int
    queued: int
    dropped: dict[str, int]
    locked_by: str | None


@dataclass(frozen=True)
class TailResult:
    """Lines from the in-memory ring (``gap``: it overran, reload from file)."""

    lines: list[dict]
    last_seq: int
    gap: bool
    #: File offset of each line in ``lines`` (parallel list; None: no file,
    #: e.g. a capture sink).
    offsets: list[int] | None = None


@dataclass(frozen=True)
class Seal:
    """A checkable seal over ``file[0:bytes]``."""

    path: str
    session_id: str
    seq_first: int
    seq_last: int
    last_h: str
    sha256: str
    bytes: int
    verified: bool
    seal_seq: int | None


@dataclass(frozen=True)
class ChainError:
    """Where and why a chain check failed."""

    offset: int
    seq: int | None
    reason: str


@dataclass(frozen=True)
class VerifyResult:
    """The result of :func:`verify_chain`."""

    ok: bool
    lines: int
    first_seq: int | None
    last_seq: int | None
    last_h: str | None
    session_id: str | None
    bytes_verified: int
    torn: tuple[tuple[int, int], ...]
    errors: tuple[ChainError, ...]


# ---------------------------------------------------------------------------
# internals: queued items, label state, sinks
# ---------------------------------------------------------------------------


@dataclass
class _Item:
    """One emitted line waiting for the writer."""

    fields: dict
    t_rx: float
    mono: float
    seq: int | None = None
    #: Explicit (world, epoch, phase, run) for transition lines.
    state: tuple | None = None
    #: ``(t, n)`` of this line's own transition: its state is re-read from
    #: the transitions at write time (a later-inserted earlier one counts).
    trans: tuple | None = None
    #: Label bookkeeping (to patch seqs on adoption).
    label: LabelEvent | None = None
    bulk: bool = False


class _LabelState:
    """Label numbers, the open stack and the history of one timeline file."""

    def __init__(self) -> None:
        self.next_number = 1
        self.stack: list[LabelEvent] = []
        self.history: list[LabelEvent] = []
        self.version = next(_LABEL_VERSIONS)

    def bump(self) -> None:
        """A new version (unique in the process, see ``_LABEL_VERSIONS``)."""
        self.version = next(_LABEL_VERSIONS)


@dataclass
class _Coalesced:
    first: float
    last: float
    n: int
    kw: dict


class _Sink:
    """One timeline file (or the detached buffer / a capture list)."""

    def __init__(self, folder: Path | None, serial: str | None, *,
                 state: str = "opening", device_name: str | None = None,
                 session_id: str | None = None) -> None:  # fmt: skip
        self.folder = folder
        self.path = folder / FILE_NAME if folder is not None else None
        self.serial = serial
        self.serials: set[str] = {serial} if serial else set()
        self.device_name = device_name
        self.session_id = session_id or (
            _session_id(folder) if folder is not None else None
        )
        self.state = state
        self.locked_by: str | None = None
        self.fd: int | None = None
        self.lock_fd: int | None = None
        self.next_seq = 1
        self.prev_h = genesis(self.session_id or "")
        self.offset = 0
        self.lines = 0
        self.queue: deque[_Item] = deque()
        self.buffer: list[_Item] = []  # must-keep lines while opening
        self.bulk_queued = 0
        self.world = 0
        self.epoch = 0
        self.phase = "live"
        self.run: str | None = None
        #: (t, n, world, epoch, phase, run), sorted by (t, n); the state is
        #: the fold of every transition's delta in t order (see
        #: :meth:`add_transition`).
        self.transitions: list[tuple] = []
        self.trans_delta: dict[int, tuple] = {}
        #: State before the first transition (a resumed file's world/epoch).
        self.base: tuple = (0, 0, "live", None)
        #: The emit-order state at the last transition (its delta's origin).
        self.last_snap: tuple = self.base
        self.last_key: tuple | None = None
        self.trans_n = 0
        self.after_world = False
        #: ``t`` of the newest world change (clock samples before it are stale).
        self.world_t: float | None = None
        self.last_clock_mono: float | None = None
        self.labels = _LabelState()
        self.counts: dict[str, dict[str, int]] = {}
        self.count_pkgs: dict[str, dict[str, dict[str, int]]] = {}
        self.count_t0 = time.time()
        self.counted_total = 0
        self.drops_by_src: dict[str, int] = {}
        self.drops_by_reason: dict[str, int] = {}
        self.drops_t0: float | None = None
        self.dropped_total = 0
        #: Every drop of this file by reason (SinkStatus.dropped).
        self.drops_cumulative: dict[str, int] = {}
        self.ring: deque[tuple[dict, int]] = deque(maxlen=RING_SIZE)
        self.written_seq = 0
        self.fsynced_seq = 0
        self.last_fsync = 0.0
        self.dirty = False
        self.full_fsync = False
        self.fsync_now = False
        self.close_reason: str | None = None
        self.closing = False
        self.opened = threading.Event()
        self.open_mono = time.monotonic()
        self.last_clock_tick = _monotonic()
        self.bell_at = 0.0
        self.bell: dict | None = None
        self.barriers: dict[int, int] = {}  # seq -> end offset (seal)
        self.adopted = 0
        self.no_device = 0

    # -- state stamping ------------------------------------------------------

    def snapshot(self) -> tuple:
        return (self.world, self.epoch, self.phase, self.run)

    def add_transition(self, t: float) -> tuple:
        """Record the change since the last transition at ``t``.

        The delta (world/epoch increments, a phase/run set) is stored, and
        the snapshots from the insertion point on are re-folded in t order,
        so a transition inserted with an earlier ``t`` never leaves later
        ones stale. Returns the state at this transition (t order);
        :attr:`last_key` is its ``(t, n)``.
        """
        self.trans_n += 1
        now = self.snapshot()
        w0, e0, p0, r0 = self.last_snap
        w1, e1, p1, r1 = now
        pr = (p1, r1) if (p1, r1) != (p0, r0) else None
        self.trans_delta[self.trans_n] = (w1 - w0, e1 - e0, pr)
        self.last_snap = now
        key = (t, self.trans_n)
        i = bisect.bisect_left(self.transitions, key)
        self.transitions.insert(i, (*key, *now))
        self._refold(i)
        self.last_key = key
        return self.transitions[i][2:]

    def _refold(self, start: int) -> None:
        state = self.transitions[start - 1][2:] if start > 0 else self.base
        for j in range(start, len(self.transitions)):
            t, n = self.transitions[j][:2]
            dw, de, pr = self.trans_delta[n]
            world, epoch, phase, run = state
            if pr is not None:
                phase, run = pr
            state = (world + dw, epoch + de, phase, run)
            self.transitions[j] = (t, n, *state)

    def note_drop(self, src: str, reason: str) -> None:
        if self.drops_t0 is None:
            self.drops_t0 = time.time()
        self.drops_by_src[src] = self.drops_by_src.get(src, 0) + 1
        self.drops_by_reason[reason] = self.drops_by_reason.get(reason, 0) + 1
        self.drops_cumulative[reason] = self.drops_cumulative.get(reason, 0) + 1
        self.dropped_total += 1


def _must_keep(fields: Mapping) -> bool:
    src = fields["src"]
    return src in MUST_KEEP or (src, fields["kind"]) in MUST_KEEP_KINDS


def _state_at(transitions: list[tuple], t: float,
              base: tuple = (0, 0, "live", None)) -> tuple:  # fmt: skip
    i = bisect.bisect_right(transitions, (t, math.inf))
    if i == 0:
        return base
    return transitions[i - 1][2:]


def _state_of(transitions: list[tuple], key: tuple) -> tuple | None:
    """The state of the transition ``key`` = ``(t, n)`` (None: not found)."""
    i = bisect.bisect_left(transitions, key)
    if i < len(transitions) and transitions[i][:2] == key:
        return transitions[i][2:]
    return None


# ---------------------------------------------------------------------------
# the service
# ---------------------------------------------------------------------------


class Labels:
    """Labels of the active timeline (or of the detached buffer): thread-safe.

    ``#`` = ``start(level="top")``, ``+`` = ``start(level="sub")``, ``-`` =
    ``stop()``, ``B`` = ``point()``; ``level="nest"`` (API/AI) starts under
    the innermost open span. Numbers are one sequence per timeline file.
    """

    def __init__(self, service: TimelineService) -> None:
        self._service = service

    def _state(self) -> _LabelState:
        sink = self._service._label_sink()
        return sink.labels

    @property
    def version(self) -> int:
        """Bumps on every change."""
        with self._service._lock:
            return self._state().version

    def start(self, name: str = "", *, level: Literal["top", "sub", "nest"] = "top",
              t: TimeLike = None, actor: str | None = None,
              source: str = "key") -> LabelEvent | None:  # fmt: skip
        """Start label N (see the class docstring); returns its start event."""
        return self._service._label_start(name, level, t, actor, source)

    def stop(
        self, *, t: TimeLike = None, actor: str | None = None
    ) -> LabelEvent | None:
        """End the innermost open span (``None``: nothing open)."""
        return self._service._label_stop(t, actor)

    def point(self, name: str = "", *, t: TimeLike = None, actor: str | None = None,
              source: str = "key") -> LabelEvent:  # fmt: skip
        """A point label under the innermost open span."""
        return self._service._label_point(name, t, actor, source)

    def end_all(self, ended_by: str, *, t: TimeLike = None,
                actor: str = "sandroid") -> list[LabelEvent]:  # fmt: skip
        """End every open span, innermost first."""
        return self._service._label_end_all(ended_by, t, actor)

    def open_spans(self) -> list[LabelEvent]:
        """The open start events, outer -> inner."""
        with self._service._lock:
            return list(self._state().stack)

    def history(self) -> list[LabelEvent]:
        """Every start/end/point, in seq (emit) order."""
        with self._service._lock:
            return list(self._state().history)

    def boundaries(self) -> list[LabelEvent]:
        """Files projection: top-level start/end and every point, by
        ``(t, end-before-start)``.
        """
        order = {"end": 0, "start": 1, "point": 2}
        with self._service._lock:
            events = [
                e for e in self._state().history
                if e.kind == "point" or e.depth == 0
            ]  # fmt: skip
        return sorted(events, key=lambda e: (e.t, order.get(e.kind, 3)))

    def next_number(self) -> int:
        """The number the next start/point gets."""
        with self._service._lock:
            return self._state().next_number


class TimelineService:
    """The process-wide timeline writer: one sink per device folder."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._written = threading.Condition(self._lock)
        self._kick = threading.Event()
        self._sinks: dict[Path, _Sink] = {}
        self._by_serial: dict[str, _Sink] = {}
        self._active: _Sink | None = None
        self._detached = _Sink(None, None, state="detached")
        self._capture: _Sink | None = None
        self._capture_out: list[dict] | None = None
        self._commands: deque[Callable[[], None]] = deque()
        self._thread: threading.Thread | None = None
        self._stop = False
        self._closed = False
        self._close_reason: str | None = None
        self._ever_bound = False
        self._policy = Policy()
        self._policy_doc = _policy_sections()
        self._coalesce: dict[tuple, _Coalesced] = {}
        #: (dev, path) -> pending coalescer keys of that path (any pid).
        self._coalesce_paths: dict[tuple, set[tuple]] = {}
        self._warned: set[str] = set()
        self._labels = Labels(self)

    # -- binding -------------------------------------------------------------

    def bind(self, serial: str, folder: Path | None = None, *,
             device_name: str | None = None) -> SinkStatus:  # fmt: skip
        """Make ``folder`` (default :func:`timeline_folder`) the active
        timeline for ``serial``. Opens or resumes the file on the writer
        thread and waits for it up to 2 s.
        """
        folder = Path(folder if folder is not None else timeline_folder())
        folder = folder.expanduser().absolute()
        open_new = False
        with self._lock:
            if self._capture is not None:
                return self._status_of(self._capture)
            if self._closed:
                return self._status_of(self._sinks.get(folder) or self._detached)
            sink = self._sinks.get(folder)
            previous = self._active
            if sink is not None and sink.state in ("locked", "failed", "closed"):
                # A locked folder is tried again (the other process may have
                # quit); failed/closed ones are reopened.
                self._sinks.pop(folder, None)
                sink = None
            if previous is not None and previous is not sink:
                self._switch_away(previous, serial)
            if sink is None:
                sink = _Sink(folder, serial, device_name=device_name)
                self._sinks[folder] = sink
                open_new = True
            elif sink.state == "open":
                changed = bool(serial) and serial != sink.serial
                if serial:
                    sink.serials.add(serial)
                    sink.serial = serial
                sink.device_name = device_name or sink.device_name
                self._emit_connect(sink, serial_changed=changed)
            if serial:
                self._by_serial[serial] = sink
                sink.serials.add(serial)
            # Re-activating an already-open sink: no "bound" from the writer,
            # so ring it here (the UI rekeys its marks on folder + version).
            reactivated = not open_new and previous is not sink and sink.state == "open"
            self._active = sink
            self._ever_bound = True
            if open_new:
                self._commands.append(lambda s=sink: self._open_sink(s))
        if reactivated:
            self._doorbell(sink, "bound")
        if open_new:
            self._ensure_thread()
            self._kick.set()
        sink.opened.wait(2.0)
        with self._lock:
            return self._status_of(sink)

    def _switch_away(self, old: _Sink, new_serial: str) -> None:
        """Device switch (lock held): old sink stays open for late lines."""
        if old.state != "open":
            return
        t = time.time()
        self._label_end_all_locked(old, "device_switch", t, "sandroid")
        self._enqueue(old, {
            "src": "device", "kind": "switch", "actor": "sandroid",
            "summary": f"device switch → {new_serial}", "data": {"to": new_serial},
        }, t_rx=t)  # fmt: skip

    def _emit_connect(self, sink: _Sink, *, serial_changed: bool = False) -> None:
        data: dict[str, Any] = {
            "serial": sink.serial,
            "name": sink.device_name,
            "emulator": bool(sink.serial and sink.serial.startswith("emulator-")),
            "folder": str(sink.folder),
        }
        if serial_changed:
            data["serial_changed"] = True
        name = sink.device_name or sink.serial or "device"
        self._enqueue(sink, {
            "src": "device", "kind": "connect", "actor": "sandroid",
            "summary": f"device connected · {name}", "data": data,
        }, t_rx=time.time())  # fmt: skip

    def note_device_lost(self, serial: str) -> None:
        """A ``device/lost`` line on the sink of ``serial``."""
        self.emit("device", "lost", summary=f"device lost · {serial}",
                  data={"serial": serial}, dev=serial, actor="system")  # fmt: skip

    @property
    def active_serial(self) -> str | None:
        """The serial of the active sink (None: detached)."""
        with self._lock:
            return self._active.serial if self._active is not None else None

    # -- routing (lock held) -------------------------------------------------

    def _route(self, dev: str | None) -> _Sink | None:
        """The sink for ``dev``; ``None``: unrouted (counted)."""
        if self._capture is not None:
            return self._capture
        if dev is not None and dev in self._by_serial:
            return self._by_serial[dev]
        if (
            dev is not None
            and self._active is not None
            and dev not in (self._active.serials)
        ):
            self._active.note_drop("unrouted", "unrouted")
            return None
        return self._active if self._active is not None else self._detached

    def _label_sink(self) -> _Sink:
        if self._capture is not None:
            return self._capture
        return self._active if self._active is not None else self._detached

    # -- input ---------------------------------------------------------------

    def emit(self, src: str, kind: str, *, summary: str, actor: str | None = None,
             data: Mapping | None = None, ref: Mapping | None = None,
             t: TimeLike = None, clk: str = "host",
             dev_mono: float | None = None, dev_wall: float | None = None,
             t_err_ms: float | None = None, dev: str | None = None,
             pkg: str | None = None, pid: int | None = None, tid: int | None = None,
             dev_t: str | None = None, replays: Mapping | None = None,
             sensitive: bool = False, level: str = "info") -> int | None:  # fmt: skip
        """Queue one line; any thread, never blocks, no I/O.

        Returns its seq, or ``None`` when it is off by policy, counted,
        dropped, coalesced, detached, or the sink is locked/failed/closed.
        """
        fields = self._fields(src, kind, summary, actor, data, ref, t, clk,
                              dev_mono, dev_wall, t_err_ms, dev, pkg, pid, tid,
                              dev_t, replays, sensitive, level)  # fmt: skip
        if fields is None:
            return None
        return self._submit(fields, in_app=False)

    def _fields(self, src, kind, summary, actor, data, ref, t, clk, dev_mono,
                dev_wall, t_err_ms, dev, pkg, pid, tid, dev_t, replays,
                sensitive, level) -> dict | None:  # fmt: skip
        if not (isinstance(src, str) and _SRC_RE.match(src)):
            self._warn_once(f"src:{src}", f"timeline: invalid src {src!r} ignored")
            return None
        if not (isinstance(kind, str) and _KIND_RE.match(kind)):
            self._warn_once(f"kind:{kind}", f"timeline: invalid kind {kind!r} ignored")
            return None
        nonfinite: list[str] = []
        fields: dict[str, Any] = {
            "src": src,
            "kind": kind,
            "summary": _clean_str(str(summary if summary is not None else "")),
            "actor": actor if actor in ACTORS else (_ACTOR.get() or "sandroid"),
            "level": level if level in LEVELS else "info",
            "clk": clk if clk in CLOCKS else "host",
        }
        if data is not None:
            fields["data"] = _sanitise(data, "", nonfinite)
        if ref is not None:
            fields["ref"] = _sanitise(ref, "", [])
        if replays is not None:
            fields["replays"] = _sanitise(replays, "", [])
        if nonfinite:
            fields.setdefault("data", {})["_nonfinite"] = nonfinite
        if t is not None:
            when = _valid_instant(t)
            if when is not None:
                fields["t"] = when
            else:
                # Unusable (e.g. ms passed as s): received time, flagged.
                if fields["clk"] == "host":
                    fields["clk"] = "none"
                if fields["level"] == "info":
                    fields["level"] = "warn"
                _note_data(fields, "_bad_t", _clean_str(repr(t))[:64])
        for key, value in (("dev_mono", dev_mono), ("dev_wall", dev_wall),
                           ("t_err_ms", t_err_ms)):  # fmt: skip
            if value is not None:
                try:
                    number = _instant(value)
                except (OverflowError, OSError, ValueError):
                    number = None
                if number is not None:
                    fields[key] = number
        if dev_mono is not None and "dev_mono" in fields and clk == "host":
            fields["clk"] = "dev_mono"
        if dev_wall is not None and "dev_wall" in fields and clk == "host":
            fields["clk"] = "dev_wall"
        for key, value in (("dev", dev), ("pkg", pkg), ("dev_t", dev_t)):
            if value is not None:
                fields[key] = _clean_str(str(value))
        for key, value in (("pid", pid), ("tid", tid)):
            if isinstance(value, int) and not isinstance(value, bool):
                fields[key] = value
        if sensitive:
            fields["sensitive"] = True
        return fields

    def _submit(self, fields: dict, *, in_app: bool) -> int | None:
        t_rx = time.time()
        with self._lock:
            if self._closed and self._capture is None:
                return None
            decision = self._policy.decide(fields["src"], fields["kind"], in_app=in_app)
            if decision == "off":
                return None
            sink = self._route(fields.get("dev"))
            if sink is None:
                return None
            if decision == "count":
                self._count(sink, fields)
                return None
            return self._accept(sink, fields, t_rx)

    def _accept(self, sink: _Sink, fields: dict, t_rx: float) -> int | None:
        """Lock held: buffer / refuse / enqueue a kept line."""
        must_keep = _must_keep(fields)
        if sink.state in ("detached", "opening"):
            if not must_keep:
                sink.no_device += 1
                return None
            if len(sink.buffer) >= DETACHED_CAP:
                sink.no_device += 1
                return None
            item = _Item(fields, t_rx, time.monotonic())
            self._bookkeep(sink, item)
            sink.buffer.append(item)
            return None
        if sink.state not in ("open", "capture") or sink.closing:
            return None
        if not must_keep and sink.bulk_queued >= self._policy.queue_max:
            sink.note_drop(fields["src"], "queue-full")
            return None
        if must_keep and self._is_boundary(fields):
            self._flush_counts(sink, t_rx)
        return self._enqueue(sink, fields, t_rx=t_rx)

    @staticmethod
    def _is_boundary(fields: dict) -> bool:
        src, kind = fields["src"], fields["kind"]
        if src in ("label", "run"):
            return True
        if (src, kind) in (("snapshot", "load"), ("device", "boot"),
                           ("sandroid", "world")):  # fmt: skip
            return True
        return src == "clock" and kind in ("jump", "sync")

    def _enqueue(self, sink: _Sink, fields: dict, *, t_rx: float,
                 state: tuple | None = None, label: LabelEvent | None = None,
                 trans: tuple | None = None) -> int | None:  # fmt: skip
        """Lock held: assign the seq and queue the line (or buffer it)."""
        fields.setdefault("actor", "sandroid")
        fields.setdefault("level", "info")
        fields.setdefault("clk", "host")
        item = _Item(fields, t_rx, time.monotonic(), state=state, label=label,
                     trans=trans)  # fmt: skip
        if sink.state in ("detached", "opening"):
            self._bookkeep(sink, item)
            sink.buffer.append(item)
            return None
        if sink.state not in ("open", "capture"):
            return None
        self._bookkeep(sink, item)
        return self._assign(sink, item)

    def _bookkeep(self, sink: _Sink, item: _Item) -> None:
        """Clock lines (lock held, at emit): an epoch on a jump, an inferred
        world change when device CLOCK_MONOTONIC went back.
        """
        fields = item.fields
        if item.state is not None:
            return
        if fields["src"] == "clock":
            data = fields.get("data") or {}
            if not isinstance(data, Mapping):
                return
            mono = data.get("dev_mono")
            t = fields.get("t") or item.t_rx
            if sink.world_t is not None and t < sink.world_t:
                # Measured before the newest world change (emitted late): it
                # describes the old world; it must not clear the barrier, move
                # the rewind reference or count a second change.
                return
            if (
                isinstance(mono, (int, float))
                and sink.last_clock_mono is not None
                and mono < sink.last_clock_mono
                and not sink.after_world
            ):
                # Device CLOCK_MONOTONIC went back: a revert or a reboot.
                before = sink.world
                sink.world += 1
                sink.epoch += 1
                sink.after_world = True
                sink.world_t = t
                state = sink.add_transition(t)
                world = _Item({
                    "src": "sandroid", "kind": "world", "actor": "sandroid",
                    "level": "warn", "clk": "host", "t": t,
                    "summary": "⟲ world change inferred · device clock went back",
                    "data": {"cause": "mono-rewind", "world_before": before},
                    **({"dev": fields["dev"]} if "dev" in fields else {}),
                }, item.t_rx, item.mono, state=state,
                   trans=sink.last_key)  # fmt: skip
                if sink.state in ("detached", "opening"):
                    sink.buffer.append(world)
                else:
                    self._assign(sink, world)
            if isinstance(mono, (int, float)):
                sink.last_clock_mono = mono
            if data.get("jump") and not sink.after_world:
                sink.epoch += 1
                item.state = sink.add_transition(t)
                item.trans = sink.last_key
            sink.after_world = False

    def _assign(self, sink: _Sink, item: _Item) -> int:
        seq = sink.next_seq
        sink.next_seq += 1
        item.seq = seq
        ref = item.fields.get("ref")
        if ref:
            item.fields["ref"] = {
                k: v.replace("{seq}", str(seq)) if isinstance(v, str) else v
                for k, v in ref.items()
            }
        if item.label is not None:
            self._label_assigned(sink, item.label, seq)
        if sink.state == "capture":
            self._finalize_capture(sink, item)
            return seq
        item.bulk = not _must_keep(item.fields)
        if item.bulk:
            sink.bulk_queued += 1
        sink.queue.append(item)
        return seq

    def _count(self, sink: _Sink, fields: dict) -> None:
        if sink.state in ("detached", "opening"):
            sink.no_device += 1
            return
        src, kind = fields["src"], fields["kind"]
        per = sink.counts.setdefault(src, {})
        per[kind] = per.get(kind, 0) + 1
        pkg = fields.get("pkg") or "_none"
        pkgs = sink.count_pkgs.setdefault(src, {}).setdefault(pkg, {})
        pkgs[kind] = pkgs.get(kind, 0) + 1
        sink.counted_total += 1

    def _flush_counts(self, sink: _Sink, now: float) -> None:
        """Lock held: one ``<src>/count`` line per counted source."""
        if not sink.counts:
            sink.count_t0 = now
            return
        window = [_iso(sink.count_t0), _iso(now)]
        for src in sorted(sink.counts):
            counts = sink.counts[src]
            pkgs = sink.count_pkgs.get(src, {})
            ranked = sorted(pkgs.items(), key=lambda kv: -sum(kv[1].values()))
            by_pkg = {p: dict(k) for p, k in ranked[:20]}
            if len(ranked) > 20:
                other: dict[str, int] = {}
                for _p, kinds in ranked[20:]:
                    for k, n in kinds.items():
                        other[k] = other.get(k, 0) + n
                by_pkg["_other"] = other
            total = sum(counts.values())
            detail = ", ".join(f"{k} {n}" for k, n in sorted(counts.items()))
            item = _Item({
                "src": src, "kind": "count", "actor": "system", "level": "info",
                "clk": "host", "t": now, "summary": f"{src} counted · {detail}",
                "data": {"window": window, "counts": dict(counts), "by_pkg": by_pkg,
                         "n": total},
            }, now, time.monotonic(), state=sink.snapshot())  # fmt: skip
            self._assign(sink, item)
        sink.counts.clear()
        sink.count_pkgs.clear()
        sink.count_t0 = now

    def _flush_drops(self, sink: _Sink, now: float) -> None:
        """Lock held: a ``sandroid/dropped`` line for the drops since the last."""
        if sink.drops_t0 is None:
            return
        window = [_iso(sink.drops_t0), _iso(now)]
        n = sum(sink.drops_by_src.values())
        item = _Item({
            "src": "sandroid", "kind": "dropped", "actor": "sandroid",
            "level": "warn", "clk": "host", "t": now,
            "summary": f"{n} timeline lines dropped",
            "data": {"window": window, "by_src": dict(sink.drops_by_src),
                     "reason": dict(sink.drops_by_reason),
                     "cumulative": sink.dropped_total,
                     "queue_max": self._policy.queue_max},
        }, now, time.monotonic())  # fmt: skip
        sink.drops_by_src.clear()
        sink.drops_by_reason.clear()
        sink.drops_t0 = None
        self._assign(sink, item)

    # -- files ---------------------------------------------------------------

    def file_event(self, *, op: str, path: str, t: float, backend: str,
                   new_path: str | None = None, process: str | None = None,
                   pid: int | None = None, tid: int | None = None,
                   dev: str | None = None, app_pkg: str | None = None,
                   app_pids: Collection[int] = ()) -> int | None:  # fmt: skip
        """One file-monitor event (reader thread): kind mapping, the attrs
        rule, ``files.modify`` coalescing. Never blocks.
        """
        from sandroid.core import watchlist_store

        kind, label, is_dir = file_kind(op)
        pkg = None
        if isinstance(path, str) and path.startswith("/"):
            pkg = watchlist_store.package_of(new_path or path)
        in_app = bool(app_pkg) and pkg == app_pkg
        actor = "app" if (pid is not None and pid in app_pids) or in_app else "system"
        data: dict[str, Any] = {"op": label, "path": path, "backend": backend}
        if new_path:
            data["new_path"] = new_path
        if process:
            data["process"] = process
        if is_dir:
            data["dir"] = True
        rel = _app_relative(path)
        summary = f"{label} {rel}"
        if new_path:
            summary += f" → {_app_relative(new_path)}"
        if process:
            summary += f" · {process}"
        fields = self._fields("files", kind, summary, actor, data, None, t, "host",
                              None, None, None, dev, pkg, pid, tid, None, None,
                              False, "info")  # fmt: skip
        if fields is None:
            return None
        t_rx = time.time()
        with self._lock:
            if self._closed and self._capture is None:
                return None
            decision = self._policy.decide("files", kind, in_app=in_app)
            if decision == "off":
                return None
            sink = self._route(fields.get("dev"))
            if sink is None:
                return None
            if decision == "count":
                self._count(sink, fields)
                return None
            key_dev = fields.get("dev") or sink.serial
            # Another op on a path (or rename target) with a pending modify:
            # those modifies first, oldest first.
            if kind != "modify":
                keys = set(self._coalesce_paths.get((key_dev, path), ()))
                if new_path:
                    keys |= self._coalesce_paths.get((key_dev, new_path), set())
                for key in self._by_first(keys):
                    self._emit_coalesced(key)
            window = self._policy.coalesce_s
            when = fields.get("t") or t_rx
            if kind == "modify" and window > 0 and sink.state in ("open", "capture"):
                key = (key_dev, path, pid)
                pending = self._coalesce.get(key)
                if pending is not None:
                    pending.n += 1
                    pending.last = max(pending.last, when)
                    return None
                self._coalesce[key] = _Coalesced(when, when, 1, fields)
                self._coalesce_paths.setdefault((key_dev, path), set()).add(key)
                return None
            return self._accept(sink, fields, t_rx)

    def _emit_coalesced(self, key: tuple) -> None:
        """Lock held: write a pending coalesced modify."""
        pending = self._coalesce.pop(key, None)
        if pending is None:
            return
        keys = self._coalesce_paths.get(key[:2])
        if keys is not None:
            keys.discard(key)
            if not keys:
                del self._coalesce_paths[key[:2]]
        fields = pending.kw
        data = dict(fields.get("data") or {})
        data.update(n=pending.n, first=_iso(pending.first), last=_iso(pending.last))
        fields["data"] = data
        fields["t"] = pending.first
        if pending.n > 1:
            fields["summary"] = f"{fields['summary']} ×{pending.n}"
        sink = self._route(fields.get("dev"))
        if sink is not None:
            self._accept(sink, fields, time.time())

    def _by_first(self, keys: Collection[tuple]) -> list[tuple]:
        """Pending coalescer ``keys`` ordered by their first event."""
        return sorted(
            (k for k in keys if k in self._coalesce),
            key=lambda k: (self._coalesce[k].first, self._coalesce[k].last),
        )

    def _flush_coalescer(self, now: float | None = None) -> None:
        """Lock held: flush expired (``now``) or all (``None``) windows,
        oldest first.
        """
        window = self._policy.coalesce_s
        for key in self._by_first(list(self._coalesce)):
            pending = self._coalesce.get(key)
            if pending is None:
                continue
            if now is None or now - pending.first >= window:
                self._emit_coalesced(key)

    # -- world / phase -------------------------------------------------------

    def on_world_change(self, cause: str, *, src: str = "snapshot", kind: str = "load",
                        summary: str | None = None, t: TimeLike = None,
                        t_err_ms: float | None = None, dev: str | None = None,
                        actor: str | None = None,
                        data: Mapping | None = None) -> int | None:  # fmt: skip
        """The device's state was replaced (snapshot load, cold boot):
        world + 1, epoch + 1 and the device-clock barrier.
        """
        try:
            from sandroid.core import device_clock

            with self._lock:
                serial = dev or (self._active.serial if self._active else None)
            device_clock.begin_epoch(serial)
        except Exception:
            logger.debug("timeline: begin_epoch failed", exc_info=True)
        fields = self._fields(src, kind, summary or f"⟲ {cause}", actor,
                              dict(data or {}), None, t, "host", None, None,
                              t_err_ms, dev, None, None, None, None, None, False,
                              "info")  # fmt: skip
        if fields is None:
            return None
        t_rx = time.time()
        with self._lock:
            if self._closed and self._capture is None:
                return None
            sink = self._route(fields.get("dev"))
            if sink is None:
                return None
            if sink.state in ("open", "capture"):
                self._flush_counts(sink, t_rx)
            fields["data"].setdefault("cause", cause)
            fields["data"]["world_before"] = sink.world
            sink.world += 1
            sink.epoch += 1
            sink.after_world = True
            when = fields.get("t") or t_rx
            sink.world_t = when if sink.world_t is None else max(sink.world_t, when)
            state = sink.add_transition(when)
            return self._enqueue(sink, fields, t_rx=t_rx, state=state,
                                 trans=sink.last_key)  # fmt: skip

    def set_phase(self, phase: str, run: str | None = None, *, kind: str = "phase",
                  summary: str | None = None, t: TimeLike = None,
                  actor: str | None = None, data: Mapping | None = None,
                  ref: Mapping | None = None, replays: Mapping | None = None,
                  dev: str | None = None) -> int | None:  # fmt: skip
        """Write a ``run/<kind>`` line; a transition only if phase/run changed."""
        if phase not in PHASES:
            phase = "live"
        payload = dict(data or {})
        fields = self._fields("run", kind, summary or "", actor, payload, ref, t,
                              "host", None, None, None, dev, None, None, None, None,
                              replays, False, "info")  # fmt: skip
        if fields is None:
            return None
        t_rx = time.time()
        with self._lock:
            if self._closed and self._capture is None:
                return None
            sink = self._route(fields.get("dev"))
            if sink is None:
                return None
            before = sink.phase
            if kind == "phase":
                fields["data"].setdefault("from", before)
                fields["data"].setdefault("to", phase)
            if not fields["summary"]:
                fields["summary"] = f"phase · {before} → {phase}"
            if sink.state in ("open", "capture"):
                self._flush_counts(sink, t_rx)
            state = trans = None
            if (phase, run) != (sink.phase, sink.run):
                sink.phase, sink.run = phase, run
                state = sink.add_transition(fields.get("t") or t_rx)
                trans = sink.last_key
            return self._enqueue(sink, fields, t_rx=t_rx, state=state, trans=trans)

    def current_phase(self, dev: str | None = None) -> tuple[str, str | None]:
        """``(phase, run)`` of the sink of ``dev`` (default: active)."""
        with self._lock:
            sink = self._by_serial.get(dev) if dev else None
            sink = sink or self._label_sink()
            return sink.phase, sink.run

    # -- labels --------------------------------------------------------------

    @property
    def labels(self) -> Labels:
        """Labels of the active sink (or of the detached buffer)."""
        return self._labels

    def _label_line(self, sink: _Sink, event: LabelEvent, data: dict,
                    summary: str) -> None:  # fmt: skip
        fields = {
            "src": "label", "kind": event.kind, "actor": event.actor,
            "level": "info", "clk": "host", "t": event.t, "summary": summary,
            "data": data,
        }  # fmt: skip
        if event.kind == "end" and event.of is not None:
            fields["ref"] = {"of": event.of}
        state = sink.labels
        state.history.append(event)
        state.bump()
        if sink.state in ("open", "capture"):
            self._flush_counts(sink, time.time())
        self._enqueue(sink, fields, t_rx=time.time(), label=event)

    def _label_assigned(self, sink: _Sink, event: LabelEvent, seq: int) -> None:
        """Fill the seq of a label event (and of its end's ``of``)."""
        state = sink.labels
        new = replace(event, seq=seq)
        for i in range(len(state.history) - 1, -1, -1):
            if state.history[i] is event:
                state.history[i] = new
                break
        for i, open_event in enumerate(state.stack):
            if open_event is event:
                state.stack[i] = new

    @staticmethod
    def _name_part(name: str) -> str:
        return f" '{name}'" if name else ""

    def _start_locked(self, sink: _Sink, name: str, parent: int | None, depth: int,
                      t: float, actor: str, source: str) -> LabelEvent:  # fmt: skip
        state = sink.labels
        number = state.next_number
        state.next_number += 1
        event = LabelEvent(None, number, "start", name, t, parent, depth, None,
                           None, actor)  # fmt: skip
        state.stack.append(event)
        summary = f"▶ {number}{self._name_part(name)}"
        if parent is not None:
            summary += f" (in {parent})"
        self._label_line(sink, event, {
            "number": number, "name": name, "parent": parent, "depth": depth,
            "source": source}, summary)  # fmt: skip
        # The stack holds the event object _label_line queued (seq patched).
        return state.stack[-1]

    def _end_locked(self, sink: _Sink, ended_by: str, t: float, actor: str,
                    late: bool = False) -> LabelEvent | None:  # fmt: skip
        state = sink.labels
        if not state.stack:
            return None
        start = state.stack.pop()
        event = LabelEvent(None, start.number, "end", start.name, t, start.parent,
                           start.depth, start.seq, ended_by, actor)  # fmt: skip
        duration = round(max(0.0, t - start.t), 3)
        data: dict[str, Any] = {"number": start.number, "ended_by": ended_by,
                                "duration_s": duration}  # fmt: skip
        if late:
            data["late"] = True
        summary = f"■ {start.number}{self._name_part(start.name)} · {duration:.1f} s"
        self._label_line(sink, event, data, summary)
        return state.history[-1]

    def _label_end_all_locked(self, sink: _Sink, ended_by: str, t: float,
                              actor: str, late: bool = False) -> list[LabelEvent]:  # fmt: skip
        ended = []
        while sink.labels.stack:
            event = self._end_locked(sink, ended_by, t, actor, late)
            if event is not None:
                ended.append(event)
        return ended

    def _label_ok(self) -> _Sink | None:
        if self._closed and self._capture is None:
            return None
        sink = self._label_sink()
        if sink.state in ("locked", "failed", "closed") or sink.closing:
            return None
        return sink

    def _label_start(self, name, level, t, actor, source) -> LabelEvent | None:
        when = _valid_instant(t) or time.time()
        who = actor if actor in ACTORS else current_actor()
        name = _clean_str(name or "")
        with self._lock:
            sink = self._label_ok()
            if sink is None:
                return None
            stack = sink.labels.stack
            if level == "sub" and stack and stack[-1].depth >= 1:
                sibling = stack[-1]
                self._end_locked(sink, "sibling", when, who)
                return self._start_locked(sink, name, sibling.parent, sibling.depth,
                                          when, who, source)  # fmt: skip
            if level in ("sub", "nest") and stack:
                inner = stack[-1]
                return self._start_locked(sink, name, inner.number, inner.depth + 1,
                                          when, who, source)  # fmt: skip
            self._label_end_all_locked(sink, "new_label", when, who)
            return self._start_locked(sink, name, None, 0, when, who, source)

    def _label_stop(self, t, actor) -> LabelEvent | None:
        when = _valid_instant(t) or time.time()
        who = actor if actor in ACTORS else current_actor()
        with self._lock:
            sink = self._label_ok()
            if sink is None:
                return None
            return self._end_locked(sink, "stop", when, who)

    def _label_point(self, name, t, actor, source) -> LabelEvent:
        when = _valid_instant(t) or time.time()
        who = actor if actor in ACTORS else current_actor()
        name = _clean_str(name or "")
        with self._lock:
            sink = self._label_ok() or self._detached
            state = sink.labels
            number = state.next_number
            state.next_number += 1
            parent = state.stack[-1].number if state.stack else None
            event = LabelEvent(None, number, "point", name, when, parent,
                               len(state.stack), None, None, who)  # fmt: skip
            self._label_line(sink, event, {
                "number": number, "name": name, "parent": parent,
                "source": source}, f"◆ {number}{self._name_part(name)}")  # fmt: skip
            return state.history[-1]

    def _label_end_all(self, ended_by, t, actor) -> list[LabelEvent]:
        when = _valid_instant(t) or time.time()
        with self._lock:
            sink = self._label_ok()
            if sink is None:
                return []
            return self._label_end_all_locked(sink, ended_by, when, actor)

    # -- misc sources --------------------------------------------------------

    def note_reveal(self, seq: int, *, dev: str | None = None) -> int | None:
        """The lens revealed masked line ``seq`` (no content is written)."""
        return self.emit("sandroid", "reveal", summary=f"revealed line #{seq}",
                         actor="user", data={"of": seq}, dev=dev)  # fmt: skip

    def reload_policy(self, reason: str = "settings", actor: str | None = None) -> None:
        """Re-read ``timeline.*``/``tracking.*``; a ``sandroid/policy`` line
        with the ``changed`` diff on every open sink. A Settings save that
        changes no policy value writes no line.
        """
        tl, tr = _policy_sections()
        with self._lock:
            old_tl, old_tr = self._policy_doc
            changed: dict[str, list] = {}
            for prefix, old, new in (
                ("timeline", old_tl, tl),
                ("tracking", old_tr, tr),
            ):
                for key in sorted(set(old) | set(new)):
                    if old.get(key) != new.get(key):
                        changed[f"{prefix}.{key}"] = [old.get(key), new.get(key)]
            self._policy = Policy(tl)
            self._policy_doc = (tl, tr)
            if reason == "settings" and not changed:
                return
            for sink in self._open_sinks():
                self._emit_policy(sink, reason, actor, changed)

    def _open_sinks(self) -> list[_Sink]:
        if self._capture is not None:
            return [self._capture]
        return [s for s in self._sinks.values() if s.state == "open" and not s.closing]

    def _emit_policy(self, sink: _Sink, reason: str, actor: str | None,
                     changed: dict | None = None) -> None:  # fmt: skip
        tl, tr = self._policy_doc
        who = actor if actor in ACTORS else current_actor()
        detail = f" · {len(changed)} changed" if changed else ""
        self._enqueue(sink, {
            "src": "sandroid", "kind": "policy", "actor": who,
            "summary": f"timeline policy ({reason}){detail}",
            "data": {"reason": reason, "by": who, "changed": changed or {},
                     "timeline": tl, "tracking": tr},
        }, t_rx=time.time())  # fmt: skip

    # -- the writer ----------------------------------------------------------

    def _ensure_thread(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop = self._closed
            self._thread = threading.Thread(
                target=self._run, name="timeline-writer", daemon=True
            )
            self._thread.start()

    def _run(self) -> None:
        while True:
            self._kick.wait(TICK_S)
            self._kick.clear()
            try:
                if self._tick():
                    return
            except Exception:  # never raise out of the loop
                logger.warning("timeline writer: tick failed", exc_info=True)

    def _tick(self) -> bool:
        """One writer pass; True when the thread should end."""
        while True:
            with self._lock:
                command = self._commands.popleft() if self._commands else None
            if command is None:
                break
            command()
        now = time.time()
        with self._lock:
            self._flush_coalescer(now)
            for sink in list(self._sinks.values()):
                if sink.state != "open" or sink.closing:
                    continue
                if now - sink.count_t0 >= self._policy.count_window_s:
                    self._flush_counts(sink, now)
                    if sink.drops_t0 is not None:
                        self._flush_drops(sink, now)
            sinks = [s for s in self._sinks.values() if s.state == "open"]
        for sink in sinks:
            self._write_sink(sink)
        self._tick_clock()
        with self._lock:
            done = (
                self._stop
                and not self._commands
                and all(
                    s.state not in ("open", "opening") for s in self._sinks.values()
                )
            )
            if done:
                self._thread = None
            return done

    def _tick_clock(self, now_mono: float | None = None) -> bool:
        """Every ``clock_every_s``: a periodic device-clock sample of the
        active sink's serial (off by 0). True when one was started.
        """
        every = self._policy.clock_every_s
        now_mono = _monotonic() if now_mono is None else now_mono
        with self._lock:
            sink = self._active
            if every <= 0 or sink is None or sink.state != "open" or not sink.serial:
                return False
            if now_mono - sink.last_clock_tick < every:
                return False
            sink.last_clock_tick = now_mono
            serial = sink.serial
        try:
            from sandroid.core import device_clock

            device_clock.record_async(
                "periodic", serial, samples=device_clock.SAMPLES_QUICK
            )
        except Exception:
            logger.debug("timeline: periodic clock sample failed", exc_info=True)
        return True

    def _write_sink(self, sink: _Sink) -> None:
        """Drain, finalize and write one sink's queue (no lock during I/O)."""
        with self._lock:
            batch = []
            while sink.queue and len(batch) < BATCH_MAX:
                item = sink.queue.popleft()
                if item.bulk:
                    sink.bulk_queued -= 1
                batch.append(item)
            transitions = list(sink.transitions)
            want_fsync = sink.fsync_now
            full = sink.full_fsync
            closing = sink.closing and not sink.queue
            prev_h, offset = sink.prev_h, sink.offset
        buf = bytearray()
        finished: list[tuple[dict, int]] = []
        ends: dict[int, int] = {}
        for item in batch:
            # Never raises: one bad item cannot lose the batch or leave a gap.
            line, raw, prev_h = _finalize_safe(sink, item, transitions, prev_h,
                                               offset)  # fmt: skip
            finished.append((line, offset))
            buf += raw
            offset += len(raw)
            ends[item.seq] = offset
        if buf and sink.fd is not None:
            try:
                view = memoryview(bytes(buf))
                while view:
                    n = _write(sink.fd, view)
                    view = view[n:]
            except OSError as exc:
                self._fail(sink, exc)
                return
        now = time.monotonic()
        do_sync = (buf or sink.dirty) and (
            want_fsync or closing or now - sink.last_fsync >= FSYNC_S
        )
        if sink.fd is not None and (do_sync or (want_fsync and not buf)):
            try:
                _fsync(sink.fd, full=full or closing)
            except OSError as exc:
                self._fail(sink, exc)
                return
        with self._lock:
            sink.prev_h, sink.offset = prev_h, offset
            for line, line_offset in finished:
                sink.ring.append((line, line_offset))
            sink.lines += len(finished)
            if finished:
                sink.written_seq = finished[-1][0]["seq"]
                self._ring_bell(sink, finished)
            for seq, end in ends.items():
                if seq in sink.barriers:
                    sink.barriers[seq] = end
            if buf:
                sink.dirty = True
            if do_sync or want_fsync:
                sink.dirty = False
                sink.last_fsync = now
                sink.fsynced_seq = sink.written_seq
                if not sink.queue:
                    sink.fsync_now = False
                    sink.full_fsync = False
            finish = closing and not sink.queue and not batch
            if finish:
                sink.state = "closed"
            elif closing and not sink.queue:
                self._kick.set()
            self._written.notify_all()
        self._publish_bell(sink)
        if finish:
            self._release(sink)
            self._doorbell(sink, "closed")

    def _fail(self, sink: _Sink, exc: OSError) -> None:
        with self._lock:
            sink.state = "failed"
            sink.queue.clear()
            sink.bulk_queued = 0
            self._written.notify_all()
        logger.warning("Session timeline %s: write failed (%s); no more lines "
                       "are recorded there", sink.path, exc)  # fmt: skip
        self._release(sink)

    @staticmethod
    def _release(sink: _Sink) -> None:
        for name in ("fd", "lock_fd"):
            fd = getattr(sink, name)
            if fd is None:
                continue
            setattr(sink, name, None)
            if name == "lock_fd":
                _unlock(fd)
            try:
                os.close(fd)
            except OSError:
                pass

    # -- doorbell ------------------------------------------------------------

    def _ring_bell(self, sink: _Sink, finished: list[tuple[dict, int]]) -> None:
        bell = sink.bell or {"first_seq": finished[0][0]["seq"], "srcs": set()}
        bell["last_seq"] = finished[-1][0]["seq"]
        bell["srcs"].update(line["src"] for line, _o in finished)
        sink.bell = bell

    def _publish_bell(self, sink: _Sink) -> None:
        with self._lock:
            bell = sink.bell
            if bell is None or time.monotonic() - sink.bell_at < 1.0 / DOORBELL_HZ:
                return
            sink.bell = None
            sink.bell_at = time.monotonic()
            payload = self._bell_payload(sink, "lines")
        payload.update(first_seq=bell["first_seq"], last_seq=bell["last_seq"],
                       srcs=sorted(bell["srcs"]))  # fmt: skip
        _publish(payload)

    def _bell_payload(self, sink: _Sink, op: str) -> dict:
        """The doorbell envelope (lock held or taken): ``op``, ``dev``,
        ``folder``, ``session_id``, ``labels_version`` (unique in the
        process), ``active`` (``sink`` is the active one now), ``first_seq``,
        ``last_seq``, ``srcs``.
        """
        with self._lock:
            return {
                "op": op, "dev": sink.serial, "folder": str(sink.folder),
                "session_id": sink.session_id,
                "labels_version": sink.labels.version,
                "active": self._active is sink,
                "first_seq": None, "last_seq": sink.written_seq or None,
                "srcs": [],
            }  # fmt: skip

    def _doorbell(self, sink: _Sink, op: str) -> None:
        _publish(self._bell_payload(sink, op))

    # -- open / resume -------------------------------------------------------

    def _open_sink(self, sink: _Sink) -> None:
        """Writer thread: lock, open or resume, then register (lock taken)."""
        try:
            self._open_sink_io(sink)
        except OSError as exc:
            with self._lock:
                sink.state = "failed"
            logger.warning("Session timeline %s: cannot open (%s)", sink.path, exc)
            self._release(sink)
            self._doorbell(sink, "bound")  # every active change rings "bound"
        finally:
            sink.opened.set()

    def _open_sink_io(self, sink: _Sink) -> None:
        folder = sink.folder
        if folder is None or sink.path is None:
            raise OSError("timeline sink without a folder")
        folder.mkdir(parents=True, exist_ok=True)
        lock_fd, holder = _try_lock(folder / LOCK_NAME, sink.serial)
        if lock_fd is None:
            with self._lock:
                sink.state = "locked"
                sink.locked_by = holder
                sink.buffer.clear()
            self._warn_once(
                f"locked:{folder}:{holder}",
                f"Timeline locked by {holder or 'another process'} (another "
                "Sandroid on this folder): this window records no timeline.",
            )
            self._doorbell(sink, "locked")
            # The active sink changed all the same (to one without a file).
            self._doorbell(sink, "bound")
            return
        sink.lock_fd = lock_fd
        fd = os.open(sink.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        sink.fd = fd
        with contextlib.suppress(OSError):
            sink.path.chmod(0o600)
        size = os.fstat(fd).st_size
        resume = _scan_for_resume(sink.path) if size > 0 else None
        if resume is not None and resume["newline"]:
            # Close the last line: a torn fragment (declared in the resume
            # line) or a complete line that only lacked its newline (adopted).
            os.write(fd, b"\n")
            resume["size"] += 1
        if resume is not None and resume.get("clock") and sink.serial:
            _seed_clock(sink.serial, resume["clock"])
        with self._lock:
            self._register(sink, resume)
        self._doorbell(sink, "bound")
        self._kick.set()

    def _register(self, sink: _Sink, resume: dict | None) -> None:
        """Lock held: the first lines of an opened sink, then the adopted ones."""
        now = time.time()
        detached = self._detached
        adopt = detached.buffer
        detached.buffer = []
        adopt = sorted(adopt + sink.buffer, key=lambda i: i.t_rx)
        sink.buffer = []
        no_device = detached.no_device + sink.no_device
        detached.no_device = sink.no_device = 0
        # Labels made while detached/opening are rebuilt from their lines.
        sink.labels = _LabelState()
        detached.labels = _LabelState()
        sink.state = "open"
        tl, _tr = self._policy_doc
        if resume is None:
            sink.prev_h = genesis(sink.session_id or "")
            sink.offset = 0
            self._enqueue(sink, {
                "src": "sandroid", "kind": "open", "actor": "sandroid",
                "summary": f"timeline opened · {sink.session_id}",
                "data": {"session_id": sink.session_id,
                         "genesis": genesis(sink.session_id or ""), "schema": SCHEMA,
                         "folder": str(sink.folder), "serial": sink.serial,
                         "device_name": sink.device_name, "sandroid": _version(),
                         "pid": os.getpid(), "host": socket.gethostname(),
                         "tz": time.strftime("%z"),
                         "detached": {"adopted": len(adopt), "dropped": no_device}},
            }, t_rx=now)  # fmt: skip
            self._emit_policy(sink, "open", "sandroid")
        else:
            sink.next_seq = resume["last_seq"] + 1
            sink.prev_h = resume["last_h"]
            sink.offset = resume["size"]
            sink.written_seq = sink.fsynced_seq = resume["last_seq"]
            sink.world, sink.epoch = resume["world"], resume["epoch"]
            sink.base = sink.last_snap = (sink.world, sink.epoch, "live", None)
            self._restore_labels(sink, resume["labels"])
            gap = resume.get("last_t")
            level = "info" if resume["verified"] and not resume["torn"] else "warn"
            extra = {}
            if resume.get("adopted") is not None:
                # The last line lacked only its newline: adopted, not torn.
                extra["adopted_tail"] = resume["adopted"]
            self._enqueue(sink, {
                "src": "sandroid", "kind": "resume", "actor": "sandroid",
                "level": level,
                "summary": f"timeline resumed after seq {resume['last_seq']}",
                "data": {"prev_seq": resume["last_seq"], "prev_h": resume["last_h"],
                         "verified": resume["verified"], "torn": resume["torn"],
                         "unclean": resume["unclean"], "pid": os.getpid(),
                         "gap_s": round(now - gap, 3) if gap else None, **extra},
            }, t_rx=now)  # fmt: skip
            self._emit_policy(sink, "resume", "sandroid")
            if sink.labels.stack:
                self._label_end_all_locked(sink, "close", now, "sandroid", late=True)
        if no_device:
            sink.drops_by_reason["no-device"] = (
                sink.drops_by_reason.get("no-device", 0) + no_device
            )
            sink.drops_by_src["_detached"] = no_device
            sink.drops_cumulative["no-device"] = (
                sink.drops_cumulative.get("no-device", 0) + no_device
            )
            sink.dropped_total += no_device
            sink.drops_t0 = sink.drops_t0 or now
        self._adopt(sink, adopt)
        if sink.folder is not None and sink.folder != self._root_folder():
            self._emit_connect(sink)
        sink.last_clock_tick = _monotonic()
        if self._closed:
            # close() ran while this sink was still opening: close it now.
            self._flush_coalescer(None)
            self._close_sink_locked(sink, self._close_reason or "quit", time.time())
            self._kick.set()

    def _restore_labels(self, sink: _Sink, events: list[LabelEvent]) -> None:
        state = sink.labels
        for event in events:
            state.history.append(event)
            state.next_number = max(state.next_number, event.number + 1)
            if event.kind == "start":
                state.stack.append(event)
            elif event.kind == "end":
                state.stack = [s for s in state.stack if s.number != event.number]
        state.bump()

    def _adopt(self, sink: _Sink, items: list[_Item]) -> None:
        """Lock held: write buffered must-keep lines into ``sink``,
        renumbering their labels after the file's own.
        """
        offset = sink.labels.next_number - 1
        starts: dict[int, int] = {}
        for item in items:
            event = item.label
            if event is not None:
                number = event.number + offset
                parent = event.parent + offset if event.parent is not None else None
                data = dict(item.fields.get("data") or {})
                data["number"] = number
                if "parent" in data:
                    data["parent"] = parent
                item.fields["data"] = data
                item.fields["summary"] = _renumber(item.fields["summary"], event, number,
                                                   parent)  # fmt: skip
                of = starts.get(number) if event.kind == "end" else None
                if of is not None:
                    item.fields["ref"] = {"of": of}
                new = replace(event, number=number, parent=parent, of=of)
                sink.labels.history.append(new)
                sink.labels.next_number = max(sink.labels.next_number, number + 1)
                if event.kind == "start":
                    sink.labels.stack.append(new)
                elif event.kind == "end":
                    sink.labels.stack = [
                        s for s in sink.labels.stack if s.number != number
                    ]
                item.label = new
            if item.fields["src"] == "clock":
                item.state = item.trans = None
                self._bookkeep(sink, item)
            elif item.state is not None:
                # A world/phase change while detached: rebase it on this file.
                _world, _epoch, phase, run = item.state
                when = item.fields.get("t") or item.t_rx
                if item.fields["src"] == "run":
                    sink.phase, sink.run = phase, run
                else:
                    sink.world += 1
                    sink.epoch += 1
                    sink.after_world = True
                    sink.world_t = when
                item.state = sink.add_transition(when)
                item.trans = sink.last_key
            seq = self._assign(sink, item)
            if event is not None and event.kind == "start":
                starts[item.label.number] = seq
            sink.adopted += 1
        sink.labels.bump()

    def _root_folder(self) -> Path | None:
        """The session folder (``<session>/timeline.jsonl`` holds the lines
        made while no device was ever bound). Never the shared ``results/``
        or the working directory: None when the session is unknown.
        """
        return session_folder()

    # -- control -------------------------------------------------------------

    def flush(self, timeout: float = 1.0) -> bool:
        """Everything emitted so far written and fsynced (False: timed out)."""
        with self._lock:
            if self._capture is not None:
                self._flush_coalescer(None)
                return True
            self._flush_coalescer(None)
            targets = []
            for sink in self._sinks.values():
                if sink.state == "open":
                    targets.append((sink, sink.next_seq - 1))
                    sink.fsync_now = True
            if not targets:
                return True
        self._kick.set()
        deadline = time.monotonic() + timeout
        with self._lock:
            while True:
                pending = [
                    s for s, target in targets
                    if s.state == "open" and s.fsynced_seq < target
                ]  # fmt: skip
                if not pending:
                    return True
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self._kick.set()
                self._written.wait(min(left, TICK_S))

    def close(self, reason: str = "quit", timeout: float = 2.0) -> bool:
        """Close every sink (idempotent, bounded): flush counts and the
        coalescer, end open labels (``close``), ``sandroid/close``, fsync,
        unlock. False when the writer did not finish in time.
        """
        return self._close(reason, timeout, fallback=True)

    def _close(self, reason: str, timeout: float, *, fallback: bool) -> bool:
        now = time.time()
        with self._lock:
            if self._capture is not None:
                return True
            first = not self._closed
            self._closed = True
            if first:
                self._flush_coalescer(None)
                if fallback and not self._ever_bound:
                    self._bind_root_fallback()
                self._close_reason = reason
                for sink in list(self._sinks.values()):
                    self._close_sink_locked(sink, reason, now)
            self._stop = True
            thread = self._thread
            # A sink still opening is closed by _register when it opens.
            pending = [
                s for s in self._sinks.values() if s.state in ("open", "opening")
            ]  # fmt: skip
            if not pending:
                return True
        if thread is None or not thread.is_alive():
            self._ensure_thread()
        self._kick.set()
        deadline = time.monotonic() + timeout
        with self._lock:
            while any(
                s.state in ("open", "opening") for s in self._sinks.values()
            ):  # fmt: skip
                left = deadline - time.monotonic()
                if left <= 0:
                    logger.warning("Session timeline: close did not finish in "
                                   "%.1fs; the next start repairs it", timeout)  # fmt: skip
                    return False
                self._kick.set()
                self._written.wait(min(left, TICK_S))
        return True

    def _close_sink_locked(self, sink: _Sink, reason: str, now: float) -> None:
        """Lock held: counts, drops, open labels and the ``sandroid/close``
        line of one open sink; the writer then finishes it.
        """
        if sink.state != "open" or sink.closing:
            return
        self._flush_counts(sink, now)
        if sink.drops_t0 is not None:
            self._flush_drops(sink, now)
        ended = self._label_end_all_locked(sink, "close", now, "sandroid")
        self._enqueue(sink, {
            "src": "sandroid", "kind": "close", "actor": "sandroid",
            "summary": f"timeline closed ({reason})",
            "data": {"reason": reason, "lines": sink.next_seq,
                     "bytes": None, "dropped_total": sink.dropped_total,
                     "counted_total": sink.counted_total,
                     "labels_closed": [e.number for e in ended]},
        }, t_rx=now)  # fmt: skip
        sink.closing = True
        sink.close_reason = reason
        sink.full_fsync = True

    def _bind_root_fallback(self) -> None:
        """Lock held: buffered user/ai lines with no device ever bound go to
        ``<session>/timeline.jsonl`` (dev null), written synchronously.
        """
        keep = [i for i in self._detached.buffer if i.fields["actor"] in ("user", "ai")]
        root = self._root_folder()
        if not keep or root is None:
            return
        self._detached.buffer = keep
        sink = _Sink(root, None, session_id=f"{root.name}/-")
        self._sinks[root] = sink
        try:
            self._open_sink_io(sink)
        except OSError as exc:
            logger.warning("Session timeline: root fallback failed (%s)", exc)
            sink.state = "failed"
            self._release(sink)
            return
        sink.opened.set()

    # -- readers -------------------------------------------------------------

    def tail(self, after_seq: int = 0, *, dev: str | None = None,
             limit: int = RING_SIZE) -> TailResult:  # fmt: skip
        """Written lines with seq > ``after_seq`` from the in-memory ring
        (unmasked); ``gap`` when the ring no longer holds ``after_seq + 1``.
        """
        with self._lock:
            sink = self._by_serial.get(dev) if dev else (self._capture or self._active)
            if sink is None:
                return TailResult([], after_seq, False)
            ring = list(sink.ring)
            last = sink.written_seq
            has_file = sink.path is not None
        if not ring:
            return TailResult([], max(after_seq, last), False,
                              [] if has_file else None)  # fmt: skip
        first = ring[0][0]["seq"]
        gap = after_seq + 1 < first and after_seq < last
        pairs = [(line, o) for line, o in ring if line["seq"] > after_seq][:limit]
        lines = [line for line, _o in pairs]
        offsets = [o for _line, o in pairs] if has_file else None
        last_seq = lines[-1]["seq"] if lines else max(after_seq, last)
        return TailResult(lines, last_seq, gap, offsets)

    def seal(self, *, by: str, dev: str | None = None, report: str | None = None,
             timeout: float = 5.0) -> Seal | None:  # fmt: skip
        """Barrier through the writer, then sha256 + verify of ``file[0:bytes]``
        and a ``sandroid/seal`` line. ``None``: no open file or timed out.
        """
        with self._lock:
            sink = self._by_serial.get(dev) if dev else self._active
            if sink is None or sink.state != "open" or sink.path is None:
                return None
            self._flush_coalescer(None)
            target = sink.next_seq - 1
            sink.barriers[target] = sink.offset if sink.written_seq >= target else -1
            sink.fsync_now = True
            sink.full_fsync = True
        self._kick.set()
        deadline = time.monotonic() + timeout
        with self._lock:
            while sink.barriers.get(target, -1) < 0 or sink.fsynced_seq < target:
                if sink.state != "open":
                    return None
                left = deadline - time.monotonic()
                if left <= 0:
                    sink.barriers.pop(target, None)
                    return None
                self._kick.set()
                self._written.wait(min(left, TICK_S))
            end = sink.barriers.pop(target, sink.offset)
            path, session_id = sink.path, sink.session_id or ""
        digest = _sha256_prefix(path, end)
        result = verify_chain(path, upto=end)
        seal_seq = self.emit("sandroid", "seal", summary=f"timeline sealed · {by}",
                             data={"seq_first": result.first_seq,
                                   "seq_last": result.last_seq,
                                   "last_h": result.last_h, "sha256": digest,
                                   "bytes": end, "by": by, "report": report},
                             dev=sink.serial)  # fmt: skip
        return Seal(str(path), session_id, result.first_seq or 0,
                    result.last_seq or 0, result.last_h or "", digest, end,
                    result.ok, seal_seq)  # fmt: skip

    def status(self, dev: str | None = None) -> SinkStatus:
        """The state of the sink of ``dev`` (default: the active one)."""
        with self._lock:
            sink = self._by_serial.get(dev) if dev else None
            return self._status_of(sink or self._label_sink())

    @staticmethod
    def _status_of(sink: _Sink) -> SinkStatus:
        state = sink.state
        if state in ("opening", "capture"):
            state = "detached" if state == "opening" else "open"
        dropped = dict(sink.drops_cumulative)
        if sink.no_device:
            dropped["no-device"] = dropped.get("no-device", 0) + sink.no_device
        return SinkStatus(
            folder=str(sink.folder) if sink.folder is not None else None,
            serial=sink.serial,
            session_id=sink.session_id,
            state=state,  # type: ignore[arg-type]
            lines=sink.lines,
            bytes=sink.offset,
            queued=len(sink.queue) + len(sink.buffer),
            dropped=dropped,
            locked_by=sink.locked_by,
        )

    # -- capture (tests) -----------------------------------------------------

    def _finalize_capture(self, sink: _Sink, item: _Item) -> None:
        line, _raw, sink.prev_h = _finalize_safe(sink, item, sink.transitions,
                                                 sink.prev_h, sink.offset)  # fmt: skip
        sink.offset += len(_raw)
        sink.lines += 1
        sink.written_seq = line["seq"]
        sink.ring.append((line, 0))
        if self._capture_out is not None:
            self._capture_out.append(line)

    def _warn_once(self, key: str, message: str) -> None:
        if key in self._warned:
            return
        self._warned.add(key)
        logger.warning(message)


# ---------------------------------------------------------------------------
# finalizing one line (writer thread / capture)
# ---------------------------------------------------------------------------


def _convert_time(fields: dict, t_rx: float,
                  serial: str | None = None) -> tuple[float, str, float | None]:  # fmt: skip
    """``(t, clk, t_err_ms)`` per the time model (§3); ``serial``: the
    sink's device when the line names none.
    """
    clk = fields.get("clk", "host")
    src_err = fields.get("t_err_ms")
    dev = fields.get("dev") or serial
    if clk == "dev_mono" and "dev_mono" in fields:
        try:
            from sandroid.core import device_clock

            hit = device_clock._to_host_detail(dev, fields["dev_mono"], near=t_rx)
        except Exception:
            hit = None
        if hit is not None:
            host, err, mono = hit
            total = err + DRIFT_MS_PER_S * abs(fields["dev_mono"] - mono)
            return host, "dev_mono", total + (src_err or 0.0)
        return t_rx, "none", None
    if clk == "dev_wall" and "dev_wall" in fields:
        try:
            from sandroid.core import device_clock

            sample = device_clock._current_epoch_sample(dev)
        except Exception:
            sample = None
        if sample is not None:
            return (fields["dev_wall"] + sample["off_wall"], "dev_wall",
                    (sample.get("err_ms") or 0.0) + (src_err or 0.0))  # fmt: skip
        return t_rx, "none", None
    if clk == "none":
        return t_rx, "none", None
    t = fields.get("t")
    if t is None:
        return t_rx, "host", None
    return t, "host", src_err


def _finalize(sink: _Sink, item: _Item, transitions: list[tuple], prev_h: str,
              offset: int) -> tuple[dict, bytes, str]:  # fmt: skip
    fields = item.fields
    t, clk, t_err = _convert_time(fields, item.t_rx, sink.serial)
    bad_t = None
    if not _t_ok(t):
        # A converted time outside the plausible range: the received time.
        bad_t = repr(t)[:64]
        t, clk, t_err = item.t_rx, "none", None
    state = _state_of(transitions, item.trans) if item.trans is not None else None
    world, epoch, phase, run = (
        state or item.state or _state_at(transitions, t, sink.base)
    )
    line: dict[str, Any] = {
        "v": SCHEMA,
        "seq": item.seq,
        "t": _iso(t),
        "t_rx": _iso(item.t_rx),
        "clk": clk,
        "mono": round(item.mono - sink.open_mono, 3),
        "world": world,
        "epoch": epoch,
        "phase": phase,
        "run": run,
        "src": fields["src"],
        "kind": fields["kind"],
        "actor": fields.get("actor", "sandroid"),
        "dev": fields.get("dev", sink.serial),
        "level": fields.get("level", "info"),
    }
    if t_err is not None:
        line["t_err_ms"] = round(t_err, 1)
    for key in ("pkg", "pid", "tid", "dev_t"):
        if key in fields:
            line[key] = fields[key]
    if "dev_mono" in fields:
        line["dev_mono"] = round(fields["dev_mono"], 6)
    if "dev_wall" in fields:
        line["dev_wall"] = fields["dev_wall"]
    summary = fields.get("summary") or ""
    if len(summary) > SUMMARY_MAX:
        summary = summary[: SUMMARY_MAX - 1] + "…"
    line["summary"] = summary
    data = fields.get("data")
    if bad_t is not None:
        line["level"] = "error" if line["level"] == "error" else "warn"
        if data is None:
            data = {"_bad_t": bad_t}
        elif isinstance(data, Mapping):
            data = {**data, "_bad_t": bad_t}
        else:
            data = {"value": data, "_bad_t": bad_t}
    if data is not None:
        if fields["src"] == "sandroid" and fields["kind"] == "close":
            data = {**data, "bytes": offset}
        size = len(canonical(data))
        if size > DATA_MAX:
            data = {"_truncated": True, "_bytes": size, "keys": sorted(data)}
            line["level"] = "warn"
        line["data"] = data
    for key in ("ref", "replays"):
        if fields.get(key):
            line[key] = fields[key]
    if fields.get("sensitive"):
        line["sensitive"] = True
    body = canonical(line)
    h = line_hash(prev_h, body)
    line["h"] = h
    return line, _splice(body, h), h


def _finalize_safe(sink: _Sink, item: _Item, transitions: list[tuple],
                   prev_h: str, offset: int) -> tuple[dict, bytes, str]:  # fmt: skip
    """:func:`_finalize`, never raising: a line that cannot be finalized is
    written as a ``level: "error"`` line with the same seq, src and kind
    (``clk: "none"``, ``data._finalize_error``) so the chain has no gap.
    """
    try:
        return _finalize(sink, item, transitions, prev_h, offset)
    except Exception as exc:
        logger.warning("timeline: line %s (%s/%s) could not be written as "
                       "emitted: %s", item.seq, item.fields.get("src"),
                       item.fields.get("kind"), exc)  # fmt: skip
        error = _clean_str(f"{type(exc).__name__}: {exc}")[:500]
    fields = item.fields
    try:
        state = item.state or _state_at(transitions, item.t_rx, sink.base)
        world, epoch, phase, run = state
        line: dict[str, Any] = {
            "v": SCHEMA, "seq": item.seq, "t": _iso(item.t_rx),
            "t_rx": _iso(item.t_rx), "clk": "none",
            "mono": round(item.mono - sink.open_mono, 3),
            "world": int(world), "epoch": int(epoch),
            "phase": str(phase), "run": None if run is None else str(run),
            "src": str(fields.get("src") or "sandroid"),
            "kind": str(fields.get("kind") or "error"),
            "actor": str(fields.get("actor") or "sandroid"),
            "dev": None if fields.get("dev", sink.serial) is None
            else str(fields.get("dev", sink.serial)),
            "level": "error",
            "summary": _clean_str(str(fields.get("summary") or ""))[:SUMMARY_MAX],
            "data": {"_finalize_error": error},
        }  # fmt: skip
        if fields.get("sensitive"):
            line["sensitive"] = True
        body = canonical(line)
    except Exception:
        line = {
            "v": SCHEMA, "seq": item.seq, "t": _iso(item.t_rx),
            "t_rx": _iso(item.t_rx), "clk": "none", "mono": 0.0, "world": 0,
            "epoch": 0, "phase": "live", "run": None, "src": "sandroid",
            "kind": "error", "actor": "sandroid", "dev": None, "level": "error",
            "summary": "a timeline line could not be written",
            "data": {"_finalize_error": error},
        }  # fmt: skip
        body = canonical(line)
    h = line_hash(prev_h, body)
    line["h"] = h
    return line, _splice(body, h), h


def _renumber(summary: str, event: LabelEvent, number: int, parent: int | None) -> str:
    out = summary.replace(f"{_label_glyph(event.kind)} {event.number}",
                          f"{_label_glyph(event.kind)} {number}", 1)  # fmt: skip
    if event.parent is not None and parent is not None:
        out = out.replace(f"(in {event.parent})", f"(in {parent})")
    return out


def _label_glyph(kind: str) -> str:
    return {"start": "▶", "end": "■", "point": "◆"}.get(kind, "")


# ---------------------------------------------------------------------------
# OS helpers
# ---------------------------------------------------------------------------


def _fsync(fd: int, *, full: bool = False) -> None:
    if full and sys.platform == "darwin":
        import fcntl

        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return
        except OSError:
            pass
    os.fsync(fd)


def _try_lock(path: Path, serial: str | None) -> tuple[int | None, str | None]:
    """``(fd, None)`` holding the lock, or ``(None, "PID n on host")``."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.name == "nt":  # pragma: no cover - Windows
            import msvcrt

            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        holder = None
        try:
            info = json.loads(Path(path).read_text(encoding="utf-8") or "{}")
            holder = f"PID {info.get('pid')} on {info.get('host')}"
        except (OSError, ValueError):
            holder = None
        os.close(fd)
        return None, holder
    info = json.dumps({"pid": os.getpid(), "host": socket.gethostname(),
                       "started": _iso(time.time()), "serial": serial})  # fmt: skip
    try:
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, info.encode("utf-8"))
    except OSError:
        pass
    return fd, None


def _unlock(fd: int) -> None:
    try:
        if os.name == "nt":  # pragma: no cover - Windows
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass


def _version() -> str:
    try:
        from sandroid import __version__

        return str(__version__)
    except Exception:
        return "unknown"


def _publish(payload: dict) -> None:
    """``TIMELINE_EVENT`` (a doorbell, no lines) when anyone listens."""
    try:
        from sandroid.core.events import Event, EventBus, EventType

        bus = EventBus.get()
        if bus.has_subscribers(EventType.TIMELINE_EVENT):
            bus.publish(Event(EventType.TIMELINE_EVENT, payload, source="timeline"))
    except Exception:
        logger.debug("timeline: doorbell failed", exc_info=True)


def _seed_clock(serial: str, line: dict) -> None:
    data = line.get("data") or {}
    try:
        from sandroid.core import device_clock

        off_wall = data.get("off_wall")
        if isinstance(off_wall, (int, float)):
            device_clock.seed(serial, off_wall=off_wall, off_mono=data.get("off_mono"),
                              host_t=_instant(line.get("t")) or time.time())  # fmt: skip
    except Exception:
        logger.debug("timeline: clock seed failed", exc_info=True)


def _app_relative(path: str) -> str:
    """``/data/data/<pkg>/x`` -> ``x`` (``@de/`` / ``@ext/`` markers)."""
    from sandroid.core import watchlist_store

    for regex, marker in watchlist_store._APP_ROOTS:
        match = regex.match(path or "")
        if match:
            rest = path[match.end() :]
            return marker + rest if rest else path
    return path or ""


# ---------------------------------------------------------------------------
# resume scan
# ---------------------------------------------------------------------------

_PREFILTER = (b'"src":"label"', b'"src":"snapshot"', b'"src":"device"',
              b'"src":"clock"', b'"src":"run"', b'"src":"sandroid"')  # fmt: skip


def _split_h(raw: bytes) -> tuple[bytes, str] | None:
    """``(canonical body, h)`` of a written line (no newline), or None."""
    if len(raw) < _H_SUFFIX_LEN + 2 or not raw.endswith(b'"}'):
        return None
    if raw[-_H_SUFFIX_LEN : -_H_SUFFIX_LEN + 6] != b',"h":"':
        return None
    h = raw[-66:-2]
    if not _HEX64.match(h):
        return None
    return raw[:-_H_SUFFIX_LEN] + b"}", h.decode("ascii")


def _parse(raw: bytes) -> dict | None:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


def _chains(raw: bytes, prev_raw: bytes | None) -> bool:
    """``raw`` is a complete line chained onto ``prev_raw`` (None: ``raw``
    is the first line, checked against the genesis of its own session).
    """
    split, obj = _split_h(raw), _parse(raw)
    if split is None or obj is None or not isinstance(obj.get("seq"), int):
        return False
    if prev_raw is None:
        session = (obj.get("data") or {}).get("session_id")
        if obj.get("seq") != 1 or not isinstance(session, str):
            return False
        prev_h = genesis(session)
    else:
        prev_split, prev = _split_h(prev_raw), _parse(prev_raw)
        prev_seq = prev.get("seq") if prev is not None else None
        if prev_split is None or not isinstance(prev_seq, int):
            return False
        if obj["seq"] != prev_seq + 1:
            return False
        prev_h = prev_split[1]
    return line_hash(prev_h, split[0]) == split[1]


def _scan_for_resume(path: Path) -> dict:
    r"""What a resume needs from an existing file (see §6.3).

    The labels (the full history) and the highest world/epoch need every
    line, so the file is read whole (one sequential read; ~0.8 s for
    150 MB), not backwards.

    The tail: a final fragment without a newline that is a complete line
    chaining onto the last one (a crash right before its ``\n``) is adopted
    (``newline``: the opener appends the ``\n``). Any other fragment is
    torn: closed with a newline and declared in the resume line. A final
    newline-terminated line without a valid ``h`` suffix (a torn fragment
    closed by an earlier resume that crashed before its resume line) is
    declared torn as well.
    """
    data = path.read_bytes()
    size = len(data)
    torn = None
    newline = False
    adopted = None
    end = data.rfind(b"\n") + 1
    lines = data[:end].split(b"\n")[:-1] if end else []
    if end < size:
        fragment = data[end:]
        if _chains(fragment, lines[-1] if lines else None):
            adopted = end
            lines.append(fragment)
        else:
            torn = {"offset": end, "bytes": len(fragment),
                    "sha256": hashlib.sha256(fragment).hexdigest()}  # fmt: skip
        newline = True
    elif len(lines) >= 2 and _split_h(lines[-1]) is None and _parse(lines[-2]):
        fragment = lines[-1]
        torn = {"offset": end - len(fragment) - 1, "bytes": len(fragment),
                "sha256": hashlib.sha256(fragment).hexdigest()}  # fmt: skip
        lines.pop()
    first = _parse(lines[0]) if lines else None
    session = ((first or {}).get("data") or {}).get("session_id")
    gen = genesis(session) if isinstance(session, str) else ""
    last = None
    verified = False
    walked = 0
    for i in range(len(lines) - 1, max(-1, len(lines) - 66), -1):
        parsed = _parse(lines[i])
        split = _split_h(lines[i])
        if parsed is None or split is None or not isinstance(parsed.get("seq"), int):
            walked += 1
            continue
        body, h = split
        prev = gen
        if i > 0:
            prev_split = _split_h(lines[i - 1])
            prev = prev_split[1] if prev_split else ""
        verified = walked == 0 and line_hash(prev, body) == h
        last = parsed
        break
    if last is None:
        raise OSError(f"{path}: no readable timeline line to resume from")
    world = epoch = 0
    labels: list[LabelEvent] = []
    clock = None
    for raw in lines:
        if not any(marker in raw for marker in _PREFILTER):
            continue
        obj = _parse(raw)
        if obj is None:
            continue
        world = max(world, int(obj.get("world") or 0))
        epoch = max(epoch, int(obj.get("epoch") or 0))
        if obj.get("src") == "clock":
            clock = obj
        elif obj.get("src") == "label":
            event = _label_from_line(obj)
            if event is not None:
                labels.append(event)
    return {
        "last_seq": last["seq"],
        "last_h": last.get("h", ""),
        "last_t": _instant(last.get("t")),
        "verified": verified,
        "torn": torn,
        "newline": newline,
        "adopted": adopted,
        "unclean": not (last.get("src") == "sandroid" and last.get("kind") == "close"),
        "size": size,
        "world": world,
        "epoch": epoch,
        "labels": labels,
        "clock": clock,
    }


def _label_from_line(obj: dict) -> LabelEvent | None:
    data = obj.get("data") or {}
    number = data.get("number")
    if not isinstance(number, int) or obj.get("kind") not in ("start", "end", "point"):
        return None
    return LabelEvent(
        seq=obj.get("seq"),
        number=number,
        kind=obj["kind"],
        name=str(data.get("name") or ""),
        t=_instant(obj.get("t")) or 0.0,
        parent=data.get("parent"),
        depth=int(data.get("depth") or 0),
        of=(obj.get("ref") or {}).get("of"),
        ended_by=data.get("ended_by"),
        actor=str(obj.get("actor") or "sandroid"),
    )


# ---------------------------------------------------------------------------
# module-level readers
# ---------------------------------------------------------------------------


def should_mask(reader: Reader = "ui") -> bool:
    """``ui``/``export``/``report``: ``timeline.mask_sensitive``; ``ai``:
    ``ai.mask_sensitive``.
    """
    try:
        from sandroid.config import get_config

        cfg = get_config()
        if reader == "ai":
            return bool(cfg.ai.mask_sensitive)
        return bool(cfg.timeline.mask_sensitive)
    except Exception:
        from sandroid.config.schema import AI_MASK_SENSITIVE_DEFAULT

        return AI_MASK_SENSITIVE_DEFAULT if reader == "ai" else False


def mask(line: dict) -> dict:
    """A sensitive line with its content hidden (the envelope and summary stay)."""
    if not line.get("sensitive"):
        return line
    out = dict(line)
    data = line.get("data")
    if isinstance(data, Mapping):
        out["data"] = {"_masked": True, "keys": sorted(data)}
    ref = line.get("ref")
    if isinstance(ref, Mapping) and "raw" in ref:
        out["ref"] = {**ref, "raw": "•••"}
    return out


def _masker(reader: Reader, mask_sensitive: bool | None) -> Callable[[dict], dict]:
    on = should_mask(reader) if mask_sensitive is None else mask_sensitive
    return mask if on else (lambda line: line)


def read_lines(path: Path, *, start: int = 0, end: int | None = None,
               reader: Reader = "ui", mask_sensitive: bool | None = None
               ) -> Iterator[tuple[int, dict]]:  # fmt: skip
    r"""``(offset, line)`` of every parsable line in ``[start, end)``; splits
    on ``b"\n"`` only and skips unparsable (torn) fragments.
    """
    apply = _masker(reader, mask_sensitive)
    with open(path, "rb") as handle:
        handle.seek(start)
        offset = start
        remaining = None if end is None else max(0, end - start)
        for raw in handle:
            if remaining is not None:
                if remaining <= 0:
                    break
                raw = raw[:remaining]
                remaining -= len(raw)
            length = len(raw)
            if raw.endswith(b"\n"):
                obj = _parse(raw[:-1])
                if obj is not None:
                    yield offset, apply(obj)
            offset += length


def read_line_at(path: Path, offset: int, *, reader: Reader = "ui",
                 mask_sensitive: bool | None = None) -> dict | None:  # fmt: skip
    """The line that starts at ``offset`` (None: not a complete line)."""
    try:
        with open(path, "rb") as handle:
            handle.seek(offset)
            raw = handle.readline()
    except OSError:
        return None
    if not raw.endswith(b"\n"):
        return None
    obj = _parse(raw[:-1])
    return None if obj is None else _masker(reader, mask_sensitive)(obj)


def tail_lines(path: Path, max_lines: int = 20_000, *, reader: Reader = "ui",
               mask_sensitive: bool | None = None
               ) -> tuple[list[tuple[int, dict]], int]:  # fmt: skip
    """The last ``max_lines`` lines as ``(offset, line)`` plus the offset the
    first returned line starts at (0 when the whole file was read).
    """
    apply = _masker(reader, mask_sensitive)
    with open(path, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        pos = size
        chunk = b""
        while pos > 0 and chunk.count(b"\n") <= max_lines:
            step = min(65_536, pos)
            pos -= step
            handle.seek(pos)
            chunk = handle.read(step) + chunk
    end = chunk.rfind(b"\n") + 1
    body = chunk[:end]
    base = pos
    if pos > 0:
        cut = body.find(b"\n") + 1
        body = body[cut:]
        base = pos + cut
    rows: list[tuple[int, dict]] = []
    offset = base
    for raw in body.split(b"\n")[:-1]:
        obj = _parse(raw)
        if obj is not None:
            rows.append((offset, apply(obj)))
        offset += len(raw) + 1
    rows = rows[-max_lines:]
    return rows, rows[0][0] if rows else base


def _sha256_prefix(path: Path, end: int) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        left = end
        while left > 0:
            block = handle.read(min(1 << 20, left))
            if not block:
                break
            digest.update(block)
            left -= len(block)
    return digest.hexdigest()


def _no_dup_keys(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def verify_chain(path: Path, *, upto: int | None = None,
                 strict: bool = False) -> VerifyResult:  # fmt: skip
    """Check the hash chain of ``file[0:upto]`` byte-exactly.

    Every line must end in ``,"h":"<64 hex>"}`` with ``h = sha256(prev_h +
    body)``, seqs are contiguous from 1, ``v == 1``, line 1 is
    ``sandroid/open`` with the genesis of its session id, every ``resume``
    names the chain's ``prev_h``. An unparsable line is accepted only when the
    next line is a ``resume`` declaring exactly its offset, length and sha256
    (a torn tail). ``strict`` also requires canonical bodies.
    """
    path = Path(path)
    errors: list[ChainError] = []
    torn: list[tuple[int, int]] = []
    lines = 0
    first_seq = last_seq = None
    last_h = session = None
    prev_h: str | None = None
    prev_seq: int | None = None
    offset = 0
    verified_to = 0
    pending: tuple[int, bytes] | None = None
    with open(path, "rb") as handle:
        data = handle.read() if upto is None else handle.read(upto)
    for raw in data.split(b"\n")[:-1]:
        here = offset
        offset += len(raw) + 1
        split = _split_h(raw)
        obj = None
        if split is not None:
            try:
                obj = json.loads(
                    split[0].decode("utf-8"), object_pairs_hook=_no_dup_keys
                )
            except (UnicodeDecodeError, ValueError) as exc:
                if "duplicate key" in str(exc):
                    # Keep the chain going from its h; the line is broken.
                    errors.append(ChainError(here, None, str(exc)))
                    prev_h = split[1]
                    prev_seq = (prev_seq or 0) + 1
                    lines += 1
                    verified_to = offset
                    continue
                obj = None
        if split is None or not isinstance(obj, dict):
            if pending is not None:
                errors.append(ChainError(pending[0], None, "unparsable line"))
            pending = (here, raw)
            continue
        body, h = split
        seq = obj.get("seq")
        if pending is not None:
            declared = (obj.get("data") or {}).get("torn") or {}
            frag_off, frag = pending
            if (
                obj.get("src") == "sandroid" and obj.get("kind") == "resume"
                and declared.get("offset") == frag_off
                and declared.get("bytes") == len(frag)
                and declared.get("sha256") == hashlib.sha256(frag).hexdigest()
            ):  # fmt: skip
                torn.append((frag_off, len(frag)))
            else:
                errors.append(ChainError(frag_off, None, "unparsable line"))
            pending = None
        if prev_h is None:
            data_ = obj.get("data") or {}
            session = data_.get("session_id")
            if obj.get("src") != "sandroid" or obj.get("kind") != "open":
                errors.append(ChainError(here, seq, "first line is not sandroid/open"))
                prev_h = ""
            elif not isinstance(session, str) or data_.get("genesis") != genesis(
                session
            ):
                errors.append(ChainError(here, seq, "genesis does not match session"))
                prev_h = data_.get("genesis") or ""
            else:
                prev_h = genesis(session)
            if seq != 1:
                errors.append(ChainError(here, seq, "first seq is not 1"))
        elif not isinstance(seq, int) or seq != (prev_seq or 0) + 1:
            errors.append(ChainError(here, seq, f"seq gap after {prev_seq}"))
        if obj.get("v") != SCHEMA:
            errors.append(ChainError(here, seq, "unknown schema version"))
        if line_hash(prev_h, body) != h:
            errors.append(ChainError(here, seq, "hash mismatch"))
        if obj.get("src") == "sandroid" and obj.get("kind") == "resume":
            if (obj.get("data") or {}).get("prev_h") != prev_h:
                errors.append(ChainError(here, seq, "resume prev_h does not match"))
        if strict:
            plain = {k: v for k, v in obj.items() if k != "h"}
            try:
                same = canonical(plain) == body
            except ValueError:
                same = False
            if not same:
                errors.append(ChainError(here, seq, "not canonical"))
        prev_h = h
        prev_seq = seq if isinstance(seq, int) else prev_seq
        lines += 1
        first_seq = seq if first_seq is None else first_seq
        last_seq, last_h = seq, h
        verified_to = offset
    if pending is not None:
        errors.append(ChainError(pending[0], None, "unparsable line"))
    tail = len(data) - (data.rfind(b"\n") + 1)
    if tail:
        torn.append((len(data) - tail, tail))
    return VerifyResult(
        ok=not errors and lines > 0,
        lines=lines,
        first_seq=first_seq,
        last_seq=last_seq,
        last_h=last_h,
        session_id=session,
        bytes_verified=verified_to,
        torn=tuple(torn),
        errors=tuple(errors),
    )


def seal_file(path: Path) -> Seal:
    """A read-only seal of a closed file (CLI, offline reports)."""
    path = Path(path)
    size = path.stat().st_size
    end = size
    with open(path, "rb") as handle:
        data = handle.read()
    end = data.rfind(b"\n") + 1
    result = verify_chain(path, upto=end)
    return Seal(str(path), result.session_id or "", result.first_seq or 0,
                result.last_seq or 0, result.last_h or "", _sha256_prefix(path, end),
                end, result.ok, None)  # fmt: skip


def active_label(marks: Sequence, when: datetime) -> Any | None:
    """The innermost start open at ``when``, else the latest point at or
    before ``when``, else None (an end is never returned). Duck-typed:
    ``.when/.kind/.number``; a missing ``.kind`` means ``"point"``.
    """
    from sandroid.core.watchlist_store import local_naive

    at = local_naive(when)

    def _when(mark: Any) -> datetime | None:
        value = getattr(mark, "when", None)
        return local_naive(value) if isinstance(value, datetime) else None

    ended: set[Any] = set()
    open_starts: list[Any] = []
    point = None
    for mark in sorted(
        (m for m in marks if _when(m) is not None and _when(m) <= at),
        key=lambda m: (_when(m), 0 if getattr(m, "kind", "point") == "end" else 1),
    ):
        kind = getattr(mark, "kind", None) or "point"
        if kind == "start":
            open_starts.append(mark)
        elif kind == "end":
            ended.add(getattr(mark, "number", None))
            open_starts = [m for m in open_starts if m.number not in ended]
        else:
            point = mark
    if open_starts:
        return open_starts[-1]
    return point


# ---------------------------------------------------------------------------
# the singleton
# ---------------------------------------------------------------------------

_SERVICE: TimelineService | None = None
_SINGLETON_LOCK = threading.Lock()
_ATEXIT = {"registered": False}


def get_timeline() -> TimelineService:
    """The process's timeline service (created on first use; registers the
    ``atexit`` close and the config update listener).
    """
    global _SERVICE
    with _SINGLETON_LOCK:
        if _SERVICE is None:
            _SERVICE = TimelineService()
            if not _ATEXIT["registered"]:
                _ATEXIT["registered"] = True
                atexit.register(_atexit_close)
            try:
                from sandroid.config import add_update_listener

                add_update_listener(_on_config_update)
            except Exception:
                logger.debug("timeline: no config listener", exc_info=True)
        return _SERVICE


def _atexit_reason() -> str:
    """``"crash"`` when an uncaught exception ended the interpreter (Python
    sets ``sys.last_exc``/``sys.last_value`` before ``atexit`` runs), else
    ``"exit"``. A ``SystemExit`` code is not visible here: the TUI launcher
    closes the timeline itself with ``"crash"`` for a non-zero exit.
    """
    import sys

    crashed = getattr(sys, "last_exc", None) or getattr(sys, "last_value", None)
    return "crash" if crashed is not None else "exit"


def _atexit_close() -> None:
    service = _SERVICE
    if service is not None:
        try:
            service.close(_atexit_reason(), 2.0)
        except Exception:
            pass


def _on_config_update(keys: frozenset[str]) -> None:
    service = _SERVICE
    if service is None:
        return
    if any(k.startswith(("timeline.", "tracking.")) for k in keys):
        service.reload_policy("settings")


def emit(src: str, kind: str, **kw: Any) -> int | None:
    """:meth:`TimelineService.emit` on the singleton."""
    return get_timeline().emit(src, kind, **kw)


def flush_timeline(timeout: float = 1.0) -> bool:
    """Flush the singleton (True when there is none)."""
    service = _SERVICE
    return True if service is None else service.flush(timeout)


def close_timeline(reason: str = "quit", timeout: float = 2.0) -> bool:
    """Close the singleton (idempotent, bounded; True when there is none)."""
    service = _SERVICE
    return True if service is None else service.close(reason, timeout)


def reset_for_tests() -> None:
    """Close the sinks (no root fallback), join the writer <=1 s, drop the
    singleton.
    """
    global _SERVICE
    with _SINGLETON_LOCK:
        service, _SERVICE = _SERVICE, None
    if service is None:
        return
    try:
        with service._lock:
            service._capture = None
            service._capture_out = None
            service._detached.buffer.clear()
        service._close("test-reset", 1.0, fallback=False)
    except Exception:
        logger.debug("timeline: reset close failed", exc_info=True)
    thread = service._thread
    if thread is not None:
        service._kick.set()
        thread.join(1.0)
    for sink in list(service._sinks.values()):
        service._release(sink)
    try:
        from sandroid.config import remove_update_listener

        remove_update_listener(_on_config_update)
    except Exception:
        pass


@contextlib.contextmanager
def capture() -> Iterator[list[dict]]:
    """Tests: a synchronous in-memory sink. Every emit is stamped (with
    ``h``) at once and appended to the yielded list; no file, no thread.
    """
    service = get_timeline()
    out: list[dict] = []
    with service._lock:
        sink = _Sink(None, None, state="capture", session_id="capture/-")
        service._capture = sink
        service._capture_out = out
    try:
        yield out
    finally:
        with service._lock:
            service._flush_coalescer(None)
            service._capture = None
            service._capture_out = None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _labels_of(path: Path) -> list[dict]:
    out = []
    for _offset, line in read_lines(path, mask_sensitive=False):
        if line.get("src") == "label":
            data = line.get("data") or {}
            out.append({"seq": line.get("seq"), "t": line.get("t"),
                        "kind": line.get("kind"), "number": data.get("number"),
                        "name": data.get("name"), "parent": data.get("parent"),
                        "ended_by": data.get("ended_by")})  # fmt: skip
    return out


def main(argv: list[str] | None = None) -> int:
    """``python -m sandroid.core.timeline verify|seal|tail|labels PATH``.

    Exit codes: 0 ok, 1 broken chain, 2 unreadable.
    """
    parser = argparse.ArgumentParser(prog="python -m sandroid.core.timeline")
    parser.add_argument("command", choices=("verify", "seal", "tail", "labels"))
    parser.add_argument("path", type=Path)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("-n", type=int, default=20, help="tail: number of lines")
    parser.add_argument("--reveal", action="store_true", help="tail: do not mask")
    args = parser.parse_args(argv)
    path: Path = args.path
    if path.is_dir():
        path = path / FILE_NAME
    try:
        if args.command == "verify":
            result = verify_chain(path, strict=True)
            if args.json:
                print(json.dumps({
                    "ok": result.ok, "lines": result.lines,
                    "first_seq": result.first_seq, "last_seq": result.last_seq,
                    "last_h": result.last_h, "session_id": result.session_id,
                    "bytes_verified": result.bytes_verified,
                    "torn": [list(t) for t in result.torn],
                    "errors": [e.__dict__ for e in result.errors]}))  # fmt: skip
            else:
                state = "OK" if result.ok else "BROKEN"
                print(f"{state}: {result.lines} lines, seq {result.first_seq}-"
                      f"{result.last_seq}, {result.bytes_verified} bytes")  # fmt: skip
                for error in result.errors:
                    print(f"  offset {error.offset} seq {error.seq}: {error.reason}")
            return 0 if result.ok else 1
        if args.command == "seal":
            seal = seal_file(path)
            if args.json:
                print(json.dumps(seal.__dict__))
            else:
                print(f"{'OK' if seal.verified else 'BROKEN'}: sha256 {seal.sha256} "
                      f"over {seal.bytes} bytes, seq {seal.seq_first}-{seal.seq_last}, "
                      f"last h {seal.last_h}")  # fmt: skip
            return 0 if seal.verified else 1
        if args.command == "tail":
            rows, _first = tail_lines(
                path, max(1, args.n), reader="export",
                mask_sensitive=False if args.reveal else None,
            )  # fmt: skip
            for _offset, line in rows:
                if args.json:
                    print(json.dumps(line, ensure_ascii=False))
                else:
                    print(f"{line.get('seq'):>7} {line.get('t')} {line.get('src')}/"
                          f"{line.get('kind')} {line.get('actor')} "
                          f"{line.get('summary')}")  # fmt: skip
            return 0
        labels = _labels_of(path)
        if args.json:
            print(json.dumps(labels, ensure_ascii=False))
        else:
            for label in labels:
                print(f"{label['seq']:>7} {label['t']} {label['kind']:<5} "
                      f"{label['number']} {label['name'] or ''}")  # fmt: skip
        return 0
    except (OSError, UnicodeDecodeError) as exc:
        print(f"unreadable: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "ACTORS",
    "ALWAYS_ON",
    "CLOCKS",
    "DATA_MAX",
    "DETACHED_CAP",
    "FILE_NAME",
    "GENESIS_PREFIX",
    "LEVELS",
    "LOCK_NAME",
    "MUST_KEEP",
    "MUST_KEEP_KINDS",
    "PHASES",
    "RING_SIZE",
    "SCHEMA",
    "SUMMARY_MAX",
    "ChainError",
    "LabelEvent",
    "Labels",
    "Policy",
    "Reader",
    "Seal",
    "SinkStatus",
    "TailResult",
    "TimeLike",
    "TimelineService",
    "VerifyResult",
    "acting_as",
    "active_label",
    "canonical",
    "capture",
    "close_timeline",
    "current_actor",
    "emit",
    "file_kind",
    "flush_timeline",
    "genesis",
    "get_timeline",
    "line_hash",
    "main",
    "mask",
    "read_line_at",
    "read_lines",
    "reset_for_tests",
    "seal_file",
    "should_mask",
    "tail_lines",
    "timeline_folder",
    "verify_chain",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
