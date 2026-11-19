"""In-memory fakes of ``sandroid.core.timeline`` and the Tracking service.

WP2 (the Timeline lens) is built in parallel with the real timeline core
(WP1) and Tracking (WP4); these fakes implement the frozen API subset the TUI
uses (DESIGN_FINAL §5 / §12) so the lens, the label keys and the header can
be tested without them:

* :class:`FakeLabels` -- the real label semantics (``#`` closes the stack,
  ``+`` sub / sibling, ``-`` innermost, point, ``nest``, ``boundaries()``).
* :class:`FakeTimeline` -- ``labels``, ``tail()``, ``status()``,
  ``note_reveal()``, ``emit()`` and a ``lines`` ring.
* :func:`make_module` -- a module object with the module-level readers
  (``tail_lines``, ``read_line_at``, ``read_lines``, ``mask``,
  ``should_mask`` ...) over a synthetic ``timeline.jsonl`` (plain JSON lines;
  the hash chain is irrelevant to the lens).
* :class:`FakeTracking` / :func:`make_tracking_module`.
* :func:`install_fakes` (also as the ``install_fakes`` pytest fixture) puts
  both into ``sys.modules`` for one test.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import types
from dataclasses import dataclass, field
from datetime import UTC, datetime, timezone
from pathlib import Path
from typing import Any

import pytest

FILE_NAME = "timeline.jsonl"
SERIAL = "emulator-test"


# --------------------------------------------------------------------------
# dataclasses (mirror DESIGN_FINAL §5)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LabelEvent:
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


@dataclass(frozen=True)
class SinkStatus:
    folder: str | None
    serial: str | None
    session_id: str | None
    state: str
    lines: int
    bytes: int
    queued: int
    dropped: dict = field(default_factory=dict)
    locked_by: str | None = None


@dataclass(frozen=True)
class TailResult:
    lines: list
    last_seq: int
    gap: bool
    #: File offsets parallel to ``lines`` (``None``: the core has none yet).
    offsets: list | None = None


# --------------------------------------------------------------------------
# synthetic lines
# --------------------------------------------------------------------------


def iso(t: float) -> str:
    """``t`` (epoch s) as the envelope's ISO form (ms + offset)."""
    return (
        datetime.fromtimestamp(t, tz=UTC)
        .astimezone()
        .isoformat(timespec="milliseconds")
    )


def make_line(
    seq: int,
    t: float,
    src: str = "files",
    kind: str = "modify",
    summary: str = "",
    **extra: Any,
) -> dict:
    """One envelope-v1 line (every required field; ``extra`` overrides)."""
    line = {
        "v": 1,
        "seq": seq,
        "t": iso(t),
        "t_rx": iso(t),
        "clk": "host",
        "mono": round(t % 10_000, 3),
        "world": 0,
        "epoch": 0,
        "phase": "live",
        "run": None,
        "src": src,
        "kind": kind,
        "actor": "app" if src == "files" else "sandroid",
        "dev": SERIAL,
        "summary": summary or f"{kind.upper()} databases/app.db · main",
        "level": "info",
    }
    line.update(extra)
    line["h"] = hashlib.sha256(f"{seq}".encode()).hexdigest()
    return line


def write_lines(path: Path, lines: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as fh:
        for line in lines:
            fh.write(json.dumps(line, sort_keys=True).encode() + b"\n")


# --------------------------------------------------------------------------
# labels
# --------------------------------------------------------------------------


def _epoch(t: Any) -> float:
    if t is None:
        return time.time()
    if isinstance(t, datetime):
        return t.timestamp()
    return float(t)


class FakeLabels:
    """In-memory ``Labels`` with the §7 semantics."""

    def __init__(self, service: FakeTimeline | None = None) -> None:
        self._service = service
        self._history: list[LabelEvent] = []
        self._stack: list[LabelEvent] = []
        self._number = 0
        self.version = 0
        self.calls: list[tuple[str, dict]] = []

    def _seq(self, kind: str, summary: str, data: dict, t: float) -> int | None:
        if self._service is None:
            return None
        return self._service.emit("label", kind, summary=summary, data=data, t=t)

    def _end(self, span: LabelEvent, ended_by: str, t: float, actor: str) -> None:
        seq = self._seq(
            "end",
            f"■ {span.number} '{span.name}'",
            {"number": span.number, "ended_by": ended_by},
            t,
        )
        event = LabelEvent(
            seq, span.number, "end", span.name, t, span.parent, span.depth,
            span.seq, ended_by, actor,
        )  # fmt: skip
        self._history.append(event)
        self._stack.remove(span)

    def start(
        self,
        name: str = "",
        *,
        level: str = "top",
        t: Any = None,
        actor: str | None = None,
        source: str = "key",
    ) -> LabelEvent | None:
        self.calls.append(
            ("start", {"name": name, "level": level, "t": t, "actor": actor})
        )
        when = _epoch(t)
        actor = actor or "sandroid"  # the core's default outside acting_as
        parent: int | None = None
        depth = 0
        if level == "nest" and self._stack:
            inner = self._stack[-1]
            parent, depth = inner.number, inner.depth + 1
        elif level == "sub" and self._stack:
            inner = self._stack[-1]
            if inner.depth >= 1:
                self._end(inner, "sibling", when, actor)
                parent, depth = inner.parent, inner.depth
            else:
                parent, depth = inner.number, 1
        else:
            for span in reversed(list(self._stack)):
                self._end(span, "new_label", when, actor)
        self._number += 1
        seq = self._seq(
            "start",
            f"▶ {self._number} '{name}'",
            {"number": self._number, "name": name, "parent": parent, "depth": depth},
            when,
        )
        event = LabelEvent(
            seq, self._number, "start", name, when, parent, depth, None, None, actor
        )
        self._history.append(event)
        self._stack.append(event)
        self.version += 1
        return event

    def stop(self, *, t: Any = None, actor: str | None = None) -> LabelEvent | None:
        self.calls.append(("stop", {"t": t, "actor": actor}))
        if not self._stack:
            return None
        self._end(self._stack[-1], "stop", _epoch(t), actor or "sandroid")
        self.version += 1
        return self._history[-1]

    def point(
        self,
        name: str = "",
        *,
        t: Any = None,
        actor: str | None = None,
        source: str = "key",
    ) -> LabelEvent:
        self.calls.append(
            ("point", {"name": name, "t": t, "source": source, "actor": actor})
        )
        when = _epoch(t)
        self._number += 1
        inner = self._stack[-1] if self._stack else None
        seq = self._seq(
            "point",
            f"◆ {self._number} '{name}'",
            {"number": self._number, "name": name},
            when,
        )
        event = LabelEvent(
            seq,
            self._number,
            "point",
            name,
            when,
            inner.number if inner else None,
            len(self._stack),
            None,
            None,
            actor or "sandroid",
        )
        self._history.append(event)
        self.version += 1
        return event

    def end_all(
        self, ended_by: str, *, t: Any = None, actor: str = "sandroid"
    ) -> list[LabelEvent]:
        out = []
        for span in reversed(list(self._stack)):
            self._end(span, ended_by, _epoch(t), actor)
            out.append(self._history[-1])
        if out:
            self.version += 1
        return out

    def open_spans(self) -> list[LabelEvent]:
        return list(self._stack)

    def history(self) -> list[LabelEvent]:
        return list(self._history)

    def boundaries(self) -> list[LabelEvent]:
        picked = [
            e
            for e in self._history
            if e.kind == "point" or (e.kind in ("start", "end") and e.depth == 0)
        ]
        return sorted(picked, key=lambda e: (e.t, 0 if e.kind == "end" else 1))

    def next_number(self) -> int:
        return self._number + 1


# --------------------------------------------------------------------------
# service
# --------------------------------------------------------------------------


class FakeTimeline:
    """The ``TimelineService`` subset the TUI uses."""

    def __init__(self, folder: Path | None, first_seq: int = 1) -> None:
        self.folder = folder
        self.lines: list[dict] = []
        self.next_seq = first_seq
        self.state = "open"
        self.locked_by: str | None = None
        self.dropped: dict[str, int] = {}
        self.reveals: list[int] = []
        self.reveal_devs: list[str | None] = []
        self.gap_once = False
        self.tail_calls = 0
        self.active_serial: str | None = SERIAL
        self.labels = FakeLabels(self)
        #: Append every emitted line to ``folder/timeline.jsonl`` (the writer).
        self.write_through = False
        #: ``tail()`` returns the ring's file offsets (``TailResult.offsets``).
        self.ring_offsets = False
        self.offsets: dict[int, int] = {}

    def emit(self, src: str, kind: str, *, summary: str = "", **kw: Any) -> int:
        seq = self.next_seq
        self.next_seq += 1
        t = _epoch(kw.pop("t", None))
        extra = {k: v for k, v in kw.items() if v is not None}
        line = make_line(seq, t, src, kind, summary, **extra)
        self.lines.append(line)
        if self.write_through and self.folder is not None:
            path = Path(self.folder) / FILE_NAME
            self.offsets[seq] = path.stat().st_size if path.exists() else 0
            write_lines(path, [line])
        return seq

    def tail(
        self, after_seq: int = 0, *, dev: str | None = None, limit: int = 5000
    ) -> TailResult:
        self.tail_calls += 1
        lines = [dict(line) for line in self.lines if line["seq"] > after_seq]
        gap, self.gap_once = self.gap_once, False
        last = self.lines[-1]["seq"] if self.lines else after_seq
        lines = lines[:limit]
        offsets = None
        if self.ring_offsets:
            offsets = [self.offsets.get(line["seq"]) for line in lines]
        return TailResult(lines, last, gap, offsets)

    def status(self, dev: str | None = None) -> SinkStatus:
        return SinkStatus(
            folder=str(self.folder) if self.folder else None,
            serial=SERIAL,
            session_id="session/dev",
            state=self.state,
            lines=len(self.lines),
            bytes=0,
            queued=0,
            dropped=dict(self.dropped),
            locked_by=self.locked_by,
        )

    def note_reveal(self, seq: int, *, dev: str | None = None) -> int:
        self.reveals.append(seq)
        self.reveal_devs.append(dev)
        return self.emit("sandroid", "reveal", summary=f"revealed #{seq}")

    def reset_for_tests(self) -> None:
        return None


# --------------------------------------------------------------------------
# module
# --------------------------------------------------------------------------


def mask(line: dict) -> dict:
    if not line.get("sensitive"):
        return line
    out = dict(line)
    data = line.get("data")
    if isinstance(data, dict):
        out["data"] = {"_masked": True, "keys": sorted(data)}
    ref = line.get("ref")
    if isinstance(ref, dict) and "raw" in ref:
        out["ref"] = {**ref, "raw": "•••"}
    return out


def make_module(service: FakeTimeline) -> types.ModuleType:
    mod = types.ModuleType("sandroid.core.timeline")
    mod.FILE_NAME = FILE_NAME
    mod.RING_SIZE = 5000
    mod.MASK = False  # tests flip this
    mod.LabelEvent = LabelEvent
    mod.SinkStatus = SinkStatus
    mod.TailResult = TailResult
    mod.get_timeline = lambda: service
    mod.reset_for_tests = service.reset_for_tests
    mod.mask = mask

    def should_mask(reader: str = "ui") -> bool:
        return bool(mod.MASK)

    def _apply(line: dict, reader: str, mask_sensitive: bool | None) -> dict:
        masked = should_mask(reader) if mask_sensitive is None else mask_sensitive
        return mask(line) if masked else line

    def read_lines(path, *, start=0, end=None, reader="ui", mask_sensitive=None):
        data = Path(path).read_bytes()
        stop = len(data) if end is None else end
        offset = start
        while offset < stop:
            nl = data.find(b"\n", offset)
            if nl < 0 or nl >= stop:
                break
            raw = data[offset:nl]
            if raw:
                yield offset, _apply(json.loads(raw), reader, mask_sensitive)
            offset = nl + 1

    def read_line_at(path, offset, *, reader="ui", mask_sensitive=None):
        with Path(path).open("rb") as fh:
            fh.seek(offset)
            raw = fh.readline()
        if not raw.strip():
            return None
        return _apply(json.loads(raw), reader, mask_sensitive)

    def tail_lines(path, max_lines=20_000, *, reader="ui", mask_sensitive=None):
        path = Path(path)
        if not path.exists():
            return [], 0
        data = path.read_bytes()
        ends = []
        pos = data.find(b"\n")
        while pos >= 0:
            ends.append(pos)
            pos = data.find(b"\n", pos + 1)
        keep = ends[-max_lines:] if max_lines else ends
        rows = []
        first = 0
        for i, end in enumerate(keep):
            idx = len(ends) - len(keep) + i
            begin = ends[idx - 1] + 1 if idx > 0 else 0
            if i == 0:
                first = begin
            rows.append(
                (begin, _apply(json.loads(data[begin:end]), reader, mask_sensitive))
            )
        return rows, first

    def canonical(line: dict) -> bytes:
        return json.dumps(
            line, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()

    def line_hash(prev_h: str, payload: bytes) -> str:
        return hashlib.sha256(prev_h.encode("ascii") + payload).hexdigest()

    def active_label(marks, when):
        best = None
        for mark in marks:
            if getattr(mark, "when", None) is not None and mark.when <= when:
                best = mark
        return best

    mod.should_mask = should_mask
    mod.read_lines = read_lines
    mod.read_line_at = read_line_at
    mod.tail_lines = tail_lines
    mod.canonical = canonical
    mod.line_hash = line_hash
    mod.active_label = active_label
    mod.timeline_folder = lambda: service.folder
    return mod


# --------------------------------------------------------------------------
# tracking
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TrackingState:
    active: bool
    serial: str | None
    mode: str
    helper: str
    since: float | None
    inputs: int
    shots: int
    reason: str | None


class FakeTracking:
    def __init__(self) -> None:
        self.active = False
        self.toggles: list[str] = []

    def toggle(self, serial: str | None = None, *, actor: str = "user") -> bool:
        self.toggles.append(actor)
        self.active = not self.active
        return self.active

    def is_active(self, serial: str | None = None) -> bool:
        return self.active

    def state(self) -> TrackingState:
        return TrackingState(
            self.active, SERIAL, "full", "connected" if self.active else "down",
            None, 0, 0, None,
        )  # fmt: skip


def make_tracking_module(tracking: FakeTracking) -> types.ModuleType:
    mod = types.ModuleType("sandroid.services.tracking_service")
    mod.get_tracking = lambda: tracking
    mod.is_active = lambda serial=None: tracking.active
    mod.TrackingState = TrackingState
    return mod


# --------------------------------------------------------------------------
# install
# --------------------------------------------------------------------------


@dataclass
class Fakes:
    service: FakeTimeline
    module: types.ModuleType
    tracking: FakeTracking
    tracking_module: types.ModuleType
    path: Path

    @property
    def labels(self) -> FakeLabels:
        return self.service.labels


def install(
    monkeypatch, root: Path, lines: list[dict] | None = None, *, tracking: bool = True
) -> Fakes:
    """Install the fakes for one test (``monkeypatch`` undoes it)."""
    folder = root / "session" / "dev"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / FILE_NAME
    if lines:
        write_lines(path, lines)
    else:
        path.touch()
    first = (lines[-1]["seq"] + 1) if lines else 1
    service = FakeTimeline(folder, first_seq=first)
    module = make_module(service)
    fake_tracking = FakeTracking()
    tracking_module = make_tracking_module(fake_tracking)
    monkeypatch.setitem(sys.modules, "sandroid.core.timeline", module)
    import sandroid.core
    import sandroid.services

    monkeypatch.setattr(sandroid.core, "timeline", module, raising=False)
    if tracking:
        monkeypatch.setitem(
            sys.modules, "sandroid.services.tracking_service", tracking_module
        )
        monkeypatch.setattr(
            sandroid.services, "tracking_service", tracking_module, raising=False
        )
    else:
        monkeypatch.setitem(sys.modules, "sandroid.services.tracking_service", None)
    return Fakes(service, module, fake_tracking, tracking_module, path)


@pytest.fixture
def install_fakes(monkeypatch, tmp_path):
    """``install_fakes(lines=None, tracking=True) -> Fakes`` for one test."""

    def _install(lines: list[dict] | None = None, *, tracking: bool = True) -> Fakes:
        return install(monkeypatch, tmp_path, lines, tracking=tracking)

    return _install
