"""JSON-first report engine: build ``report.json`` from the sealed timeline.

A report is a plain JSON document (schema :data:`SCHEMA`) that the renderers
in :mod:`sandroid.core.report_render` turn into Markdown and PDF. The document
is self-contained: every rendered value (transcript steps, coverage sentences,
legacy result tables, the seal) is stored in it, so a PDF or Markdown file can
be regenerated from ``report.json`` alone.

Inputs, and nothing else:

* the session timeline, read **only** through
  ``sandroid.core.timeline.read_lines(path, end=seal.bytes, reader="report")``;
* the files its lines reference (screenshots via ``ref.path``);
* the run bundle's results JSON (``sandroid.json``) for the legacy **results**
  section.

The section plan (:data:`SECTION_PLAN`) is an ordered tuple of
:class:`SectionSpec`; :class:`ReportOptions.sections` selects and orders
sections by id, so a template is just another tuple of ids. Every section is
built in isolation: a builder that raises becomes an ``error`` block and the
other sections are unaffected.

Block types (``sections[].blocks[].type``): ``text`` (``level`` info/warn/
error), ``heading``, ``kv``, ``table``, ``list``, ``image``,
``transcript_step`` and ``error``.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import logging
import os
import re
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from .run_report import (
    DEFAULT_RESULTS_NAME,
    RUN_ERRORS_KEY,
    RUN_METADATA_KEY,
    iso_now,
    sanitize_results,
    sha256_file,
)

logger = logging.getLogger(__name__)

SCHEMA = "sandroid-report/1"

#: Module that provides the timeline readers (imported lazily so the report
#: engine works, without a transcript, where the timeline is unavailable).
TIMELINE_MODULE = "sandroid.core.timeline"
TIMELINE_FILE_NAME = "timeline.jsonl"

ALL_TRIGGERS: frozenset[str] = frozenset(
    {"before_tap", "after_tap", "screen_change", "label", "manual"}
)
INPUT_KINDS: frozenset[str] = frozenset(
    {"tap", "long_press", "swipe", "key", "text", "gesture"}
)
#: Items listed per effect kind (files / network) under a step.
TOP_EFFECTS = 10
#: Line numbers (seqs) listed per effect item.
MAX_ITEM_SEQS = 5
#: Step errors listed in the run-errors banner.
MAX_BANNER_STEP_ERRORS = 12
#: Rows of the Filtered Noise table (the full list is in the results JSON).
MAX_FILTERED_NOISE_ROWS = 150
#: Shown in the results notes; the renderers shorten at these limits.
MAX_LINE_CHARS = 400
MAX_DIFF_LINES_TOTAL = 200

#: Keys in the results JSON that are not artefact lists.
_NON_ARTEFACT_KEYS = {
    "Device Name",
    "Emulator relative action timestamp",
    "Action Duration",
    "Other Data",
    RUN_METADATA_KEY,
    RUN_ERRORS_KEY,
}


# ---------------------------------------------------------------------------
# Public data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReportScope:
    """What part of the timeline a report covers.

    ``session``: the whole sealed file. ``run``: the run's record window
    (``seq_range`` from ``play-start.replays``) for the transcript, else its
    ``play-start..play-end`` time ``window`` (host epoch seconds).
    """

    kind: Literal["session", "run"] = "session"
    run_id: str | None = None
    window: tuple[float, float] | None = None
    seq_range: tuple[int, int] | None = None


@dataclass(frozen=True)
class ReportOptions:
    """Report knobs; the defaults match ``ReportConfig``'s defaults."""

    sections: tuple[str, ...] | None = None  # None = SECTION_PLAN order
    mask_sensitive: bool | None = None  # None = should_mask("report")
    effects_window_s: float = 2.0
    shot_triggers: frozenset[str] = ALL_TRIGGERS
    include_screenshots: bool = True
    #: Extra sentences for the coverage section (timeline unavailable, ...).
    coverage_notes: tuple[str, ...] = ()


@dataclass
class LabelSpan:
    """One label (``start``..``end``) or point, rebuilt from label lines."""

    number: int
    name: str
    kind: str  # "span" | "point"
    parent: int | None
    depth: int
    seq: int
    t: str
    ts: float
    end_t: str | None = None
    end_ts: float | None = None
    end_seq: int | None = None
    ended_by: str | None = None
    duration_s: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "name": self.name,
            "kind": self.kind,
            "parent": self.parent,
            "depth": self.depth,
            "seq": self.seq,
            "t_start": self.t,
            "t_end": self.end_t,
            "ended_by": self.ended_by,
            "duration_s": self.duration_s,
        }


@dataclass
class ReportContext:
    """Everything a section builder may use (built once per report)."""

    scope: ReportScope
    options: ReportOptions
    masked: bool
    generated_at: str
    seal: dict[str, Any] | None = None
    timeline_path: Path | None = None
    timeline_dir: Path | None = None
    #: Every sealed line, sorted by ``(instant(t), seq)``; ``_ts`` added.
    lines: list[dict[str, Any]] = field(default_factory=list)
    #: The lines inside the report scope.
    scoped: list[dict[str, Any]] = field(default_factory=list)
    by_src: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    labels: list[LabelSpan] = field(default_factory=list)
    #: :class:`_LabelIndex` of ``labels`` (built on first use).
    label_index: Any = None
    #: ``(first, last)`` instant of the scope (``None`` without lines).
    span: tuple[float, float] | None = None
    bundle: dict[str, Any] | None = None
    bundle_path: Path | None = None
    bundle_sha256: str | None = None
    bundle_error: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SectionSpec:
    """One report section: ``builder(ctx) -> {"blocks": [...]}``.

    ``requires_src``: when none of these sources has a line in scope the
    builder is skipped and the section states that instead.
    """

    id: str
    title: str
    builder: Callable[[ReportContext], dict]
    requires_src: frozenset[str] = frozenset()


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _timeline_module() -> Any | None:
    """``sandroid.core.timeline`` (or a test fake in ``sys.modules``)."""
    try:
        return importlib.import_module(TIMELINE_MODULE)
    except ImportError:
        return None


def _ts(value: Any) -> float | None:
    """Instant of an ISO-8601 string / epoch number (``None`` if unparsable)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.timestamp()


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="milliseconds")


def _clock(value: Any, *, ms: bool = False) -> str:
    """``HH:MM:SS`` (``.mmm``) of an ISO timestamp, in its own UTC offset."""
    if value is None:
        return "?"
    try:
        dt = (
            datetime.fromtimestamp(value).astimezone()
            if isinstance(value, (int, float))
            else datetime.fromisoformat(str(value))
        )
    except (ValueError, OSError, OverflowError):
        return str(value)
    if ms:
        return dt.strftime("%H:%M:%S.%f")[:-3]
    return dt.strftime("%H:%M:%S")


def seal_to_dict(seal: Any) -> dict[str, Any] | None:
    """A :class:`~sandroid.core.timeline.Seal` (or mapping) as a plain dict."""
    if seal is None:
        return None
    if is_dataclass(seal) and not isinstance(seal, type):
        return asdict(seal)
    if isinstance(seal, Mapping):
        return dict(seal)
    return {k: v for k, v in vars(seal).items() if not k.startswith("_")}


def scope_to_dict(scope: ReportScope) -> dict[str, Any]:
    window = list(scope.window) if scope.window else None
    return {
        "kind": scope.kind,
        "run_id": scope.run_id,
        "window": window,
        "window_iso": [_iso(w) for w in window] if window else None,
        "seq_range": list(scope.seq_range) if scope.seq_range else None,
    }


def scope_from_dict(data: Mapping[str, Any] | None) -> ReportScope:
    if not isinstance(data, Mapping):
        return ReportScope()
    window = data.get("window")
    seq_range = data.get("seq_range")
    return ReportScope(
        kind="run" if data.get("kind") == "run" else "session",
        run_id=data.get("run_id"),
        window=tuple(window) if window and len(window) == 2 else None,  # type: ignore[arg-type]
        seq_range=tuple(seq_range) if seq_range and len(seq_range) == 2 else None,  # type: ignore[arg-type]
    )


def _short_id(rid: Any) -> str | None:
    if not rid:
        return None
    return str(rid).rsplit(":id/", 1)[-1]


def _short_cls(cls: Any) -> str | None:
    if not cls:
        return None
    return str(cls).rsplit(".", 1)[-1]


def element_name(target: Mapping[str, Any] | None) -> str | None:
    """Element name: ``text`` > ``desc`` > ``label`` (a row without own
    text, named by its descendants) > short ``rid`` > short ``cls``.
    """
    if not isinstance(target, Mapping):
        return None
    for key in ("text", "desc", "label"):
        value = target.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    web = target.get("web")
    if isinstance(web, Mapping) and isinstance(web.get("field"), str):
        if web["field"].strip():
            return web["field"].strip()  # a web form control's label
    return _short_id(target.get("rid")) or _short_cls(target.get("cls"))


def _data(line: Mapping[str, Any]) -> dict[str, Any]:
    data = line.get("data")
    return data if isinstance(data, dict) else {}


def _ref(line: Mapping[str, Any]) -> dict[str, Any]:
    ref = line.get("ref")
    return ref if isinstance(ref, dict) else {}


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _text(text: str, level: str = "info") -> dict[str, Any]:
    return {"type": "text", "level": level, "text": text}


def _heading(text: str, level: int = 2, **extra: Any) -> dict[str, Any]:
    return {"type": "heading", "level": level, "text": text, **extra}


# ---------------------------------------------------------------------------
# Results JSON (bundle)
# ---------------------------------------------------------------------------


def find_results_json(result_dir: str | os.PathLike[str]) -> Path:
    """Locate the results JSON inside a result folder.

    Prefers ``sandroid.json``; otherwise the newest top-level ``*.json`` that
    looks like a Sandroid result (has a ``"Device Name"`` key).

    Raises:
        FileNotFoundError: If no results JSON is found.
    """
    root = Path(result_dir)
    preferred = root / DEFAULT_RESULTS_NAME
    if preferred.is_file():
        return preferred
    candidates = sorted(
        root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    for cand in candidates:
        try:
            data = json.loads(cand.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and "Device Name" in data:
            return cand
    raise FileNotFoundError(f"No Sandroid results JSON found in {root}")


def _load_bundle(
    ctx: ReportContext, bundle_dir: Path | None, results_json: Path | None
) -> None:
    if bundle_dir is None and results_json is None:
        return
    try:
        path = (
            Path(results_json)
            if results_json is not None
            else find_results_json(Path(bundle_dir))  # type: ignore[arg-type]
        )
        data = json.loads(path.read_bytes())
        if not isinstance(data, dict):
            raise TypeError("the results JSON is not an object")
        ctx.bundle = sanitize_results(data)
        ctx.bundle_path = path
        ctx.bundle_sha256 = sha256_file(path)
    except Exception as exc:
        logger.warning("Report: results JSON unavailable: %s", exc)
        ctx.bundle_error = f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Timeline loading and scoping
# ---------------------------------------------------------------------------


def _sort_key(line: Mapping[str, Any]) -> tuple[float, int]:
    ts = line.get("_ts")
    return (ts if ts is not None else float("inf"), int(line.get("seq") or 0))


def _load_lines(ctx: ReportContext, timeline: Path) -> None:
    tl = _timeline_module()
    if tl is None:
        ctx.notes.append(
            "The session timeline reader is not available in this installation, "
            "so the transcript and the coverage below are not derived from it."
        )
        return
    end = (ctx.seal or {}).get("bytes")
    if ctx.seal is None:
        ctx.notes.append(
            f"The timeline {timeline} was read without a seal; lines appended "
            "while the report was built may be included."
        )
    out: list[dict[str, Any]] = []
    for _offset, line in tl.read_lines(
        timeline, end=end, reader="report", mask_sensitive=False
    ):
        if not isinstance(line, dict):
            continue
        if ctx.masked and line.get("sensitive"):
            line = tl.mask(line)
        line = dict(line)
        line["_ts"] = _ts(line.get("t")) or _ts(line.get("t_rx"))
        out.append(line)
    out.sort(key=_sort_key)
    ctx.lines = out


def _in(line: Mapping[str, Any], scope: ReportScope) -> bool:
    seq = line.get("seq")
    if scope.seq_range and isinstance(seq, int):
        a, b = scope.seq_range
        if a <= seq <= b:
            return True
    if scope.window:
        ts = line.get("_ts")
        if ts is not None and scope.window[0] <= ts <= scope.window[1]:
            return True
    return False


def _apply_scope(ctx: ReportContext) -> None:
    scope = ctx.scope
    if scope.kind == "run" and not (scope.window or scope.seq_range):
        ctx.notes.append(
            f"Run {scope.run_id} was not found in the timeline (no play-start "
            "line); the whole sealed timeline is reported."
        )
    if scope.kind == "session" or not (scope.window or scope.seq_range):
        ctx.scoped = list(ctx.lines)
    else:
        ctx.scoped = [line for line in ctx.lines if _in(line, scope)]
    by_src: dict[str, list[dict[str, Any]]] = {}
    for line in ctx.scoped:
        by_src.setdefault(str(line.get("src")), []).append(line)
    ctx.by_src = by_src
    stamps = [ln["_ts"] for ln in ctx.scoped if ln.get("_ts") is not None]
    if scope.window and scope.kind == "run":
        stamps += list(scope.window)
    ctx.span = (min(stamps), max(stamps)) if stamps else None


def _transcript_lines(ctx: ReportContext) -> list[dict[str, Any]]:
    """Lines whose interactions the transcript shows (record window first)."""
    scope = ctx.scope
    if scope.kind != "run" or not (scope.window or scope.seq_range):
        return ctx.scoped
    if scope.seq_range:
        a, b = scope.seq_range
        return [
            ln
            for ln in ctx.lines
            if isinstance(ln.get("seq"), int) and a <= ln["seq"] <= b
        ]
    w0, w1 = scope.window  # type: ignore[misc]
    return [
        ln for ln in ctx.lines if ln.get("_ts") is not None and w0 <= ln["_ts"] <= w1
    ]


def _build_labels(lines: Iterable[Mapping[str, Any]]) -> list[LabelSpan]:
    spans: dict[int, LabelSpan] = {}
    order: list[LabelSpan] = []
    for line in lines:
        if line.get("src") != "label":
            continue
        data = _data(line)
        number = data.get("number")
        if not isinstance(number, int):
            continue
        kind = line.get("kind")
        if kind in ("start", "point"):
            span = LabelSpan(
                number=number,
                name=str(data.get("name") or ""),
                kind="span" if kind == "start" else "point",
                parent=data.get("parent"),
                depth=int(data.get("depth") or 0),
                seq=int(line.get("seq") or 0),
                t=str(line.get("t")),
                ts=line.get("_ts") or 0.0,
            )
            spans[number] = span
            order.append(span)
        elif kind == "end" and number in spans:
            span = spans[number]
            span.end_t = str(line.get("t"))
            span.end_ts = line.get("_ts")
            span.end_seq = line.get("seq")
            span.ended_by = data.get("ended_by")
            span.duration_s = data.get("duration_s")
    # Points report their parent's depth + 1 for nesting.
    for span in order:
        if span.kind == "point" and span.parent in spans:
            span.depth = spans[span.parent].depth + 1
    return order


class _LabelIndex:
    """The innermost open span per stretch between span boundaries.

    A sweep over the sorted start/end keys ``(ts, seq)``: between two
    consecutive keys the set of open spans is constant, so a lookup is one
    bisect (instead of a scan of every span per line).
    """

    def __init__(self, labels: list[LabelSpan]) -> None:
        self.labels = labels
        self.by_number = {s.number: s for s in labels}
        events: list[tuple[tuple[float, int], int, int]] = []
        spans = [s for s in labels if s.kind == "span"]
        for i, s in enumerate(spans):
            events.append(((s.ts, s.seq), 1, i))
            if s.end_ts is not None:
                events.append(((s.end_ts, s.end_seq or 0), 0, i))
        events.sort(key=lambda e: e[0])
        self.keys: list[tuple[float, int]] = []
        self.inner: list[LabelSpan | None] = []
        open_now: set[int] = set()
        j = 0
        while j < len(events):
            key = events[j][0]
            while j < len(events) and events[j][0] == key:
                _key, is_start, i = events[j]
                if is_start:
                    open_now.add(i)
                else:
                    open_now.discard(i)
                j += 1
            # A span that starts and ends at the same key is never open.
            live = [
                spans[i]
                for i in open_now
                if spans[i].end_ts is None
                or (spans[i].end_ts, spans[i].end_seq or 0) > key
            ]
            self.keys.append(key)
            self.inner.append(
                max(live, key=lambda s: (s.depth, s.ts, s.seq)) if live else None
            )

    def path(self, ts: float, seq: int) -> list[int]:
        i = bisect_right(self.keys, (ts, seq)) - 1
        inner = self.inner[i] if i >= 0 else None
        if inner is None:
            return []
        path = [inner.number]
        parent = inner.parent
        while parent is not None and parent in self.by_number and len(path) < 32:
            path.insert(0, parent)
            parent = self.by_number[parent].parent
        return path


def _label_path(ctx: ReportContext, ts: float, seq: int) -> list[int]:
    """Label numbers (outer -> inner) of the spans open at ``(ts, seq)``."""
    index = ctx.label_index
    if index is None or index.labels is not ctx.labels:
        index = ctx.label_index = _LabelIndex(ctx.labels)
    return index.path(ts, seq)


# ---------------------------------------------------------------------------
# Section: overview
# ---------------------------------------------------------------------------


def _first(ctx: ReportContext, src: str, kind: str) -> dict[str, Any] | None:
    for line in ctx.lines:
        if line.get("src") == src and line.get("kind") == kind:
            return line
    return None


def _device_info(ctx: ReportContext) -> tuple[str | None, str | None]:
    serial = name = None
    opened = _first(ctx, "sandroid", "open")
    if opened:
        serial = _data(opened).get("serial")
        name = _data(opened).get("device_name")
    for line in ctx.lines:
        if line.get("src") == "device" and line.get("kind") == "connect":
            serial = _data(line).get("serial") or serial
            name = _data(line).get("name") or name
    return serial, name


def _run_errors_blocks(data: Mapping[str, Any], results_name: str) -> list[dict]:
    """Prominent warning when the run aborted or lost steps."""
    errors = data.get(RUN_ERRORS_KEY)
    if not isinstance(errors, dict) or not errors:
        return []
    status = str(errors.get("status") or "completed with errors")
    steps = errors.get("steps") or []
    blocks = [
        _text(
            f"RUN {status.upper()} - the results below may be incomplete. "
            'Do not read missing entries as "nothing happened".',
            "error",
        )
    ]
    if errors.get("fatal"):
        blocks.append(_text(f"Fatal: {errors['fatal']}", "error"))
    items = []
    for step in steps[:MAX_BANNER_STEP_ERRORS]:
        if not isinstance(step, dict):
            step = {"error": step}
        where = " ".join(
            str(x)
            for x in (
                step.get("step"),
                f"(run {step['run']})" if step.get("run") else None,
            )
            if x
        )
        items.append(f"{where or 'step'}: {step.get('error')}")
    if len(steps) > MAX_BANNER_STEP_ERRORS:
        items.append(
            f"… {len(steps) - MAX_BANNER_STEP_ERRORS} more step error(s) in "
            f'{results_name} ("{RUN_ERRORS_KEY}").'
        )
    if items:
        blocks.append({"type": "list", "level": "error", "items": items})
    return blocks


def _run_metadata_rows(ctx: ReportContext) -> list[list[Any]]:
    data = ctx.bundle or {}
    md = data.get(RUN_METADATA_KEY) or {}
    host = md.get("host") or {}
    dev = md.get("device") or {}
    tools = host.get("tool_versions") or {}
    tool_str = ", ".join(f"{k} {v}" for k, v in tools.items() if v) or None
    android = dev.get("android_version")
    if android and dev.get("api_level") is not None:
        android = f"{android} (API level {dev.get('api_level')})"
    duration = data.get("Action Duration")
    return [
        ["Analysis started", md.get("started_at")],
        ["Analysis ended", md.get("ended_at")],
        ["Action duration", f"{duration} s" if duration is not None else None],
        [
            "Emulator action timestamp",
            data.get("Emulator relative action timestamp"),
        ],
        [
            "Run ID / mode",
            " / ".join(str(x) for x in (md.get("run_id"), md.get("mode")) if x) or None,
        ],
        ["Run status", md.get("run_status")],
        ["Device name", data.get("Device Name")],
        ["Device serial", dev.get("serial")],
        ["AVD name", dev.get("avd_name")],
        ["Device model", dev.get("model")],
        ["Android version", android],
        ["Security patch level", dev.get("security_patch")],
        ["Build fingerprint", dev.get("build_fingerprint")],
        ["Sandroid version", host.get("sandroid_version")],
        ["Host OS", host.get("host_os")],
        ["Host name", host.get("host_name")],
        [
            "Python",
            " ".join(
                x
                for x in (
                    host.get("python_implementation"),
                    host.get("python_version"),
                )
                if x
            )
            or None,
        ],
        ["Tool versions", tool_str],
        ["Results file", ctx.bundle_path.name if ctx.bundle_path else None],
        ["Results file SHA-256", ctx.bundle_sha256],
    ]


def build_overview(ctx: ReportContext) -> dict:
    """Report facts, scope, counts and the legacy run metadata."""
    blocks: list[dict] = []
    if ctx.bundle is not None:
        blocks += _run_errors_blocks(
            ctx.bundle, ctx.bundle_path.name if ctx.bundle_path else "results"
        )
    scope = ctx.scope
    serial, device_name = _device_info(ctx)
    counts = Counter(str(ln.get("src")) for ln in ctx.scoped)
    inputs = [ln for ln in ctx.by_src.get("input", []) if ln.get("kind") in INPUT_KINDS]
    spans = [s for s in ctx.labels if s.kind == "span"]
    points = [s for s in ctx.labels if s.kind == "point"]
    rows: list[list[Any]] = [
        ["Report generated", ctx.generated_at],
        [
            "Scope",
            "the whole session timeline"
            if scope.kind == "session"
            else f"run {scope.run_id}",
        ],
    ]
    if ctx.span:
        rows.append(["Report window", f"{_iso(ctx.span[0])} – {_iso(ctx.span[1])}"])
    if scope.seq_range:
        rows.append(
            [
                "Recorded interactions",
                f"timeline lines {scope.seq_range[0]}–{scope.seq_range[1]} "
                "(the recording this run replayed)",
            ]
        )
    rows += [
        ["Session", (ctx.seal or {}).get("session_id") or _session_id(ctx)],
        ["Device", " · ".join(x for x in (device_name, serial) if x) or None],
        ["Timeline", str(ctx.timeline_path) if ctx.timeline_path else None],
        [
            "Timeline lines in scope",
            f"{len(ctx.scoped)}"
            + (
                " (" + ", ".join(f"{src} {n}" for src, n in counts.most_common()) + ")"
                if counts
                else ""
            ),
        ],
        ["Labels", f"{_plural(len(spans), 'label')}, {_plural(len(points), 'mark')}"],
        [
            "Interactions",
            f"{_plural(len(inputs), 'input')}, "
            f"{_plural(len(ctx.by_src.get('screen', [])), 'screen change')}, "
            f"{_plural(len(ctx.by_src.get('shot', [])), 'screenshot')}",
        ],
        [
            "Sensitive values",
            "masked" if ctx.masked else "shown in clear (masking is off)",
        ],
    ]
    blocks.append({"type": "kv", "rows": rows})
    if ctx.bundle is not None:
        blocks.append(_heading("Run metadata", 2))
        blocks.append(
            {
                "type": "kv",
                "rows": _run_metadata_rows(ctx),
                "mono_keys": ["Build fingerprint", "Results file SHA-256"],
            }
        )
        if not ctx.bundle.get(RUN_METADATA_KEY):
            blocks.append(
                _text(
                    "Run metadata (timestamps, device build, tool versions) was "
                    "not recorded in this results file; it was produced by an "
                    "older Sandroid version. Values shown as “–” are unknown."
                )
            )
    elif ctx.bundle_error:
        blocks.append(
            _text(f"No results file was available: {ctx.bundle_error}", "warn")
        )
    return {"blocks": blocks}


def _session_id(ctx: ReportContext) -> str | None:
    opened = _first(ctx, "sandroid", "open")
    return _data(opened).get("session_id") if opened else None


# ---------------------------------------------------------------------------
# Section: coverage / validity
# ---------------------------------------------------------------------------


def _overlaps(ctx: ReportContext, t0: float | None, t1: float | None) -> bool:
    if ctx.scope.kind == "session" or ctx.span is None:
        return True
    lo, hi = ctx.span
    start = t0 if t0 is not None else float("-inf")
    end = t1 if t1 is not None else float("inf")
    return start <= hi and end >= lo


def _until(line: Mapping[str, Any] | None) -> str:
    return _clock(line.get("t")) if line else "the end of the sealed timeline"


def _intervals(
    lines: Iterable[Mapping[str, Any]],
    key: Callable[[Mapping[str, Any]], str | None],
    is_on: Callable[[Mapping[str, Any]], bool],
) -> list[tuple[Mapping[str, Any], Mapping[str, Any] | None]]:
    """Pair on/off lines per ``key`` into ``(start, end-or-None)`` intervals."""
    open_: dict[str, Mapping[str, Any]] = {}
    out: list[tuple[Mapping[str, Any], Mapping[str, Any] | None]] = []
    for line in lines:
        k = key(line)
        if k is None:
            continue
        if is_on(line):
            open_.setdefault(k, line)
        elif k in open_:
            out.append((open_.pop(k), line))
    out.extend((start, None) for start in open_.values())
    out.sort(key=lambda pair: _sort_key(pair[0]))
    return out


def _shots_dropped(stop: Mapping[str, Any] | None) -> tuple[int, int]:
    """Screen-change shots Tracking dropped (``tracking/stop``
    ``data.shots_dropped``; DESIGN_FINAL §12): ``(late or superseded,
    unverified)``. They were never stored, so no step shows an image of a
    later screen (late, superseded) or of the previous one (unverified: the
    new screen had not drawn within the wait).
    """
    counts = _data(stop).get("shots_dropped") if stop else None
    if not isinstance(counts, Mapping):
        return 0, 0
    later = unverified = 0
    for reason, n in counts.items():
        if not isinstance(n, int):
            continue
        if reason == "unverified":
            unverified += n
        else:
            later += n
    return later, unverified


def _cov_tracking(ctx: ReportContext) -> list[str]:
    lines = [ln for ln in ctx.lines if ln.get("src") == "tracking"]
    spans = _intervals(
        [ln for ln in lines if ln.get("kind") in ("start", "stop")],
        key=lambda ln: "tracking",
        is_on=lambda ln: ln.get("kind") == "start",
    )
    items = []
    for start, end in spans:
        if not _overlaps(ctx, start.get("_ts"), end.get("_ts") if end else None):
            continue
        d = _data(start)
        detail = ", ".join(
            x
            for x in (
                f"mode {d['mode']}" if d.get("mode") else None,
                f"started by {d['reason']}" if d.get("reason") else None,
            )
            if x
        )
        items.append(
            f"Tracking was on from {_clock(start.get('t'))} to {_until(end)}"
            + (f" ({detail})." if detail else ".")
        )
        dropped, unverified = _shots_dropped(end)
        if dropped:
            items.append(
                f"{_plural(dropped, 'screen-change screenshot')} "
                f"{'was' if dropped == 1 else 'were'} not taken: the next input "
                "or a newer screen came first, so the image would have shown "
                "a later screen."
            )
        if unverified:
            items.append(
                f"{_plural(unverified, 'screen-change screenshot')} "
                f"{'was' if unverified == 1 else 'were'} not kept: the device "
                "still showed the previous screen when the wait ended, so the "
                "image would not have shown the new one."
            )
    if not items:
        items.append(
            "Tracking was off for the whole report window: no taps, typed text, "
            "screen changes or screenshots were recorded."
            if not spans
            else "Tracking was off during the report window."
        )
    for line in lines:
        if line.get("kind") != "helper" or not _overlaps(
            ctx, line.get("_ts"), line.get("_ts")
        ):
            continue
        state = _data(line).get("helper") or "changed"
        items.append(f"The UI helper was {state} at {_clock(line.get('t'))}.")
    return items


_INTERVENTION_NAMES = {
    "a11y_helper": "The accessibility UI helper",
    "ui_helper_invisible": "The invisible UI helper",
    "frida": "Frida instrumentation",
    "proxy": "The traffic proxy",
    "bypass": "A detection bypass",
    "ca": "The injected CA certificate",
}


def _cov_interventions(ctx: ReportContext) -> list[str]:
    lines = [
        ln
        for ln in ctx.lines
        if ln.get("src") == "sandroid" and ln.get("kind") == "intervention"
    ]
    items = []
    for start, end in _intervals(
        lines,
        key=lambda ln: str(_data(ln).get("what") or "?"),
        is_on=lambda ln: _data(ln).get("state") == "on",
    ):
        if not _overlaps(ctx, start.get("_ts"), end.get("_ts") if end else None):
            continue
        d = _data(start)
        what = str(d.get("what") or "?")
        name = _INTERVENTION_NAMES.get(what, f"Intervention '{what}'")
        detect = (
            "the app can detect it"
            if d.get("detectable")
            else "it is not detectable by the app"
        )
        items.append(
            f"{name} was active from {_clock(start.get('t'))} to {_until(end)}; "
            f"{detect}."
        )
    return items or [
        "No interventions (UI helper, Frida, proxy, bypass, CA) were recorded."
    ]


_SHOT_POLICY = {
    "shot_before_tap": "Screenshots before taps",
    "shot_after_tap": "Screenshots after taps",
    "shot_screen_change": "Screenshots on screen changes",
    "shot_label": "Screenshots at labels",
}


def _policy_conditions(line: Mapping[str, Any]) -> dict[str, str]:
    """``{condition key: sentence stem}`` holding under one policy line."""
    d = _data(line)
    timeline = d.get("timeline") if isinstance(d.get("timeline"), dict) else {}
    tracking = d.get("tracking") if isinstance(d.get("tracking"), dict) else {}
    out: dict[str, str] = {}
    for src, on in (timeline.get("sources") or {}).items():
        if on is False:
            out[f"source:{src}"] = f"Recording of {src} lines was off"
    for item in timeline.get("kinds_off") or []:
        out[f"off:{item}"] = f"Recording of {item} lines was off"
    for item in timeline.get("count_only") or []:
        out[f"count:{item}"] = f"{item} lines were stored as counts only"
    attrs = timeline.get("files_attrs")
    if attrs == "counts":
        out["attrs"] = "File attribute changes were stored as counts only"
    elif attrs == "app_dirs":
        out["attrs"] = (
            "File attribute changes outside the app's data folders were stored "
            "as counts only"
        )
    coalesce = timeline.get("files_modify_coalesce_ms")
    if isinstance(coalesce, (int, float)) and coalesce > 0:
        out[f"coalesce:{coalesce}"] = (
            f"File modifications were coalesced within {coalesce:g} ms windows"
        )
    for key, label in _SHOT_POLICY.items():
        if tracking.get(key) is False:
            out[key] = f"{label} were off"
    if tracking.get("capture_text") is False:
        out["capture_text"] = "Typed text was not captured"
    mode = tracking.get("helper_mode")
    if mode and mode != "full":
        out[f"helper:{mode}"] = f"The UI helper mode was '{mode}'"
    return out


def _cov_policy(ctx: ReportContext) -> list[str]:
    policies = [
        ln
        for ln in ctx.lines
        if ln.get("src") == "sandroid" and ln.get("kind") == "policy"
    ]
    if not policies:
        return [
            "No recording-policy line was found; which sources were recorded is "
            "unknown."
        ]
    items: list[str] = []
    active: dict[str, tuple[str, Mapping[str, Any]]] = {}
    closed: list[tuple[str, Mapping[str, Any], Mapping[str, Any] | None]] = []
    for line in policies:
        now = _policy_conditions(line)
        for key in list(active):
            if key not in now:
                stem, start = active.pop(key)
                closed.append((stem, start, line))
        for key, stem in now.items():
            active.setdefault(key, (stem, line))
    closed.extend((stem, start, None) for stem, start in active.values())
    closed.sort(key=lambda c: _sort_key(c[1]))
    first = policies[0]
    for stem, start, end in closed:
        if not _overlaps(ctx, start.get("_ts"), end.get("_ts") if end else None):
            continue
        if start is first and end is None:
            items.append(f"{stem} for the whole timeline.")
        else:
            items.append(f"{stem} from {_clock(start.get('t'))} to {_until(end)}.")
    for line in policies:
        changed = _data(line).get("changed")
        if not isinstance(changed, dict) or not changed:
            continue
        if not _overlaps(ctx, line.get("_ts"), line.get("_ts")):
            continue
        d = _data(line)
        parts = []
        for key, pair in changed.items():
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                parts.append(f"{key} {pair[0]!r} → {pair[1]!r}")
            else:
                parts.append(str(key))
        who = d.get("by") or line.get("actor")
        items.append(
            f"The policy changed at {_clock(line.get('t'))} "
            f"({d.get('reason') or 'change'}{', by ' + str(who) if who else ''}): "
            + "; ".join(parts)
            + "."
        )
    return items or ["All sources were recorded in full during the report window."]


def _cov_dropped(ctx: ReportContext) -> list[str]:
    by_src: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    for line in ctx.scoped:
        if line.get("src") != "sandroid" or line.get("kind") != "dropped":
            continue
        d = _data(line)
        for key, n in (d.get("by_src") or {}).items():
            by_src[str(key)] += int(n or 0)
        for key, n in (d.get("reason") or {}).items():
            reasons[str(key)] += int(n or 0)
    items = []
    total = sum(by_src.values()) or sum(reasons.values())
    if total:
        detail = ", ".join(f"{k}: {n}" for k, n in by_src.most_common())
        why = ", ".join(f"{k}: {n}" for k, n in reasons.most_common())
        items.append(
            f"{_plural(total, 'bulk line')} were dropped and are missing from the "
            f"timeline ({detail or 'by source unknown'}"
            + (f"; reasons {why}" if why else "")
            + ")."
        )
    opened = _first(ctx, "sandroid", "open")
    detached = _data(opened).get("detached") if opened else None
    if isinstance(detached, dict) and detached.get("dropped"):
        items.append(
            f"{_plural(int(detached['dropped']), 'line')} emitted before a device "
            "was connected could not be kept."
        )
    return items or ["No lines were dropped."]


def _cov_integrity(ctx: ReportContext) -> list[str]:
    items = []
    for line in ctx.lines:
        if line.get("src") != "sandroid" or line.get("kind") != "resume":
            continue
        d = _data(line)
        how = "an unclean shutdown" if d.get("unclean") else "a clean close"
        gap = d.get("gap_s")
        gap_txt = f", {gap:g} s later" if isinstance(gap, (int, float)) else ""
        items.append(
            f"The timeline was resumed at {_clock(line.get('t'))} after {how}{gap_txt}."
        )
        torn = d.get("torn")
        if isinstance(torn, dict):
            items.append(
                f"A torn fragment of {torn.get('bytes')} bytes at offset "
                f"{torn.get('offset')} was left by the interruption; it is "
                "declared in the resume line and skipped by readers."
            )
        if d.get("verified") is False:
            items.append(
                "The last line before that resume could not be verified against "
                "the hash chain."
            )
    if ctx.seal:
        if ctx.seal.get("verified"):
            items.append(
                f"The hash chain verified up to the seal (lines "
                f"{ctx.seal.get('seq_first')}–{ctx.seal.get('seq_last')})."
            )
        else:
            items.append("The hash chain did NOT verify up to the seal.")
    return items or ["The timeline was written in one piece (no resume)."]


def _cov_clock(ctx: ReportContext) -> list[str]:
    lines = ctx.scoped
    if not lines:
        return [
            "No timeline lines are in scope.",
            *_clock_sync_sentences(ctx.lines),
            CLOCK_CAVEAT,
        ]
    n = len(lines)
    none = sum(1 for ln in lines if ln.get("clk") == "none")
    dev = sum(1 for ln in lines if ln.get("clk") in ("dev_mono", "dev_wall"))
    errs = [
        float(ln["t_err_ms"])
        for ln in lines
        if isinstance(ln.get("t_err_ms"), (int, float))
    ]
    items = [
        f"{none} of {n} lines have no reliable event time (clk none); their time "
        "is when Sandroid received them."
        if none
        else f"All {n} lines have a known time source."
    ]
    if dev:
        items.append(f"{_plural(dev, 'line')} were timed from the device clock.")
    if errs:
        items.append(f"The largest stated time uncertainty is ±{max(errs):.1f} ms.")
    worlds = sorted(
        {ln.get("world") for ln in lines if isinstance(ln.get("world"), int)}
    )
    epochs = sorted(
        {ln.get("epoch") for ln in lines if isinstance(ln.get("epoch"), int)}
    )
    loads = sum(
        1
        for ln in lines
        if ln.get("src") == "snapshot"
        and ln.get("kind") == "load"
        and _data(ln).get("ok")
    )
    boots = sum(
        1 for ln in lines if ln.get("src") == "device" and ln.get("kind") == "boot"
    )
    rewinds = sum(
        1 for ln in lines if ln.get("src") == "sandroid" and ln.get("kind") == "world"
    )
    jumps = sum(
        1 for ln in lines if ln.get("src") == "clock" and ln.get("kind") == "jump"
    )
    if worlds:
        items.append(
            f"The device state changed {loads + boots + rewinds} time(s) "
            f"(snapshot loads {loads}, cold boots {boots}, inferred clock rewinds "
            f"{rewinds}); world {worlds[0]}–{worlds[-1]}, "
            f"{_plural(len(epochs), 'clock epoch')}, "
            f"{_plural(jumps, 'clock jump')}."
        )
    items += _clock_sync_sentences(ctx.lines)
    items.append(CLOCK_CAVEAT)
    return items


#: The method caveat on device times, stated in every report.
CLOCK_CAVEAT = (
    "File and database timestamps are device-clock values; after a snapshot "
    "reset device wall times can repeat, so such a value may not map to a "
    "single real time. Every clock jump and sync is recorded in the timeline."
)

#: ``clock`` sample reasons that carry ``data.sync_policy`` (the effective
#: ``emulator.sync_device_clock`` setting at that moment).
_SYNC_TRIGGER_REASONS = ("snapshot-load", "device-connect")


def _clock_sync_sentences(lines: list[dict]) -> list[str]:
    """Whether the device clock was synced to host time (whole session).

    The policy comes from ``data.sync_policy`` on the trigger samples
    (``snapshot-load``, ``device-connect``); a sync is a ``clock/sync`` line
    (``data.trigger`` ``session-start`` | ``snapshot-load``, ``ok``, ``sets``).
    Timelines written before the policy was recorded have neither field: a
    sync line there was always a snapshot-load sync.
    """
    clock = [ln for ln in lines if ln.get("src") == "clock"]
    policy = [
        _data(ln)["sync_policy"]
        for ln in clock
        if _data(ln).get("reason") in _SYNC_TRIGGER_REASONS
        and isinstance(_data(ln).get("sync_policy"), bool)
    ]
    syncs = [ln for ln in clock if ln.get("kind") == "sync"]
    failed = sum(1 for ln in syncs if not _data(ln).get("ok"))
    at_start = sum(1 for ln in syncs if _data(ln).get("trigger") == "session-start")
    after_load = len(syncs) - at_start
    stem = "Device clock synced to host at session start and after snapshot loads"
    if policy:
        if all(policy):
            answer = "yes"
        elif not any(policy):
            answer = "no"
        else:
            answer = "partly (the setting changed during the session)"
        items = [f"{stem}: {answer}."]
    elif syncs:
        items = [
            f"{stem}: after snapshot loads (this timeline does not record the "
            "setting itself)."
        ]
    else:
        items = [f"{stem}: not recorded in this timeline."]
    if syncs:
        detail = (
            f"{_plural(len(syncs), 'clock sync')} "
            f"({at_start} at session start, {after_load} after snapshot loads)"
        )
        if failed:
            detail += f", {failed} failed (the offset was recorded instead)"
        items.append(detail + ".")
    elif policy and any(policy):
        items.append(
            "No sync was needed: the device clock was within 1 s of the host each time."
        )
    return items


def _cov_masking(ctx: ReportContext) -> list[str]:
    n = sum(1 for ln in ctx.scoped if ln.get("sensitive"))
    if ctx.masked:
        return [
            f"Sensitive values are masked in this report "
            f"({_plural(n, 'sensitive line')})."
        ]
    return [
        "Sensitive values such as typed passwords are shown in clear "
        f"({_plural(n, 'sensitive line')}); set timeline.mask_sensitive to mask "
        "them."
    ]


_COVERAGE_PARTS: tuple[tuple[str, Callable[[ReportContext], list[str]]], ...] = (
    ("Tracking", _cov_tracking),
    ("Interventions", _cov_interventions),
    ("Recording policy", _cov_policy),
    ("Dropped lines", _cov_dropped),
    ("Timeline integrity", _cov_integrity),
    ("Clock quality", _cov_clock),
    ("Masking", _cov_masking),
)


def build_coverage(ctx: ReportContext) -> dict:
    """What was and was not recorded, in plain sentences."""
    blocks: list[dict] = [_text(note, "warn") for note in ctx.notes]
    if not ctx.lines:
        blocks.append(
            _text(
                "No session timeline lines were available, so what was recorded "
                "during the analysis cannot be stated.",
                "warn",
            )
        )
        blocks.append(_heading("Clock quality", 2))
        blocks.append({"type": "list", "items": [CLOCK_CAVEAT]})
        blocks.append(_heading("Masking", 2))
        blocks.append({"type": "list", "items": _cov_masking(ctx)})
        return {"blocks": blocks}
    for title, part in _COVERAGE_PARTS:
        blocks.append(_heading(title, 2))
        try:
            blocks.append({"type": "list", "items": part(ctx)})
        except Exception as exc:
            logger.error("Coverage part %r failed: %s", title, exc, exc_info=True)
            blocks.append({"type": "error", "error": f"{type(exc).__name__}: {exc}"})
    return {"blocks": blocks}


# ---------------------------------------------------------------------------
# Section: privacy (identity-profile values leaving the device)
# ---------------------------------------------------------------------------
#
# Built from the privacy scan's finding store (``privacy/hits.jsonl`` of the
# timeline folder: every hit, also a repeat of one seen in an earlier run of
# the session) within the run's scope (:class:`~sandroid.services.
# privacy_scan.RunScope`: the recording it replays, its Play and its sweep),
# and the ``identity/applied`` line that names how many values were seeded.
# The ``privacy/sent|stored`` timeline lines are written once per finding
# per session, so they are only the fallback for a folder without the store.

#: Evidence rows listed at most (the timeline keeps every line).
MAX_PRIVACY_EVIDENCE = 60

_HASH_NAMES = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")
_CALL_RE = re.compile(r"^([a-z0-9_]+)\((.*)\)$")
_PLACES_RE = re.compile(r"^value,\s*(\d+)$")
_WRAP_WORDS = {
    "base64": "base64 of {}",
    "base64url": "URL-safe base64 of {}",
    "hex": "hex of {}",
    "utf16": "UTF-16 of {}",
    "url": "URL-encoded {}",
}
_VALUE_WORDS = {
    "value": "the value",
    "bytes": "the raw bytes of the value",
    "strip_dashes": "the value without dashes",
    "strip_separators": "the value without separators",
    "dashes": "the value with dashes",
    "colons": "the value with colons",
    "digits": "the digits of the value",
    "intl_00": "the number with 00 instead of the plus sign",
    "e7": "the value times ten million",
    "double_le": "a binary double (little-endian)",
    "double_be": "a binary double (big-endian)",
}
_PARTY_WORDS = {"third": "third party", "first": "first party"}


def _describe_transform(transform: str) -> str:
    text = (transform or "value").strip()
    if text in _VALUE_WORDS:
        return _VALUE_WORDS[text]
    match = _CALL_RE.match(text)
    if match is None:
        return text
    name, inner = match.group(1), match.group(2)
    places = _PLACES_RE.match(inner)
    if places is not None and name in ("round", "truncate"):
        verb = "rounded" if name == "round" else "cut"
        return f"{verb} to {places.group(1)} decimals"
    if name in _VALUE_WORDS and inner == "value":
        return _VALUE_WORDS[name]
    described = _describe_transform(inner)
    if name in ("lower", "upper"):
        case = "lower-case" if name == "lower" else "upper-case"
        if described.startswith("the "):
            return f"the {case} {described[4:]}"
        return f"{described}, {case}"
    if name in _WRAP_WORDS:
        return _WRAP_WORDS[name].format(described)
    return f"{name} of {described}"


def transform_words(transform: str) -> str:
    """How a value was encoded, in words: ``sha256(lower(value))`` ->
    ``sha256 of the lower-case value``, ``value`` -> ``as is``,
    ``round(value, 4)`` -> ``rounded to 4 decimals``.
    """
    words = _describe_transform(transform)
    return "as is" if words == "the value" else words


def encoding_class(transform: str) -> str:
    """``hashed``, ``rounded``, ``encoded`` or ``as is`` (strongest first)."""
    text = transform or "value"
    if any(f"{name}(" in text for name in _HASH_NAMES):
        return "hashed"
    if any(tok in text for tok in ("round(", "truncate(", "e7(")):
        return "rounded"
    if any(
        tok in text for tok in ("base64", "hex(", "utf16(", "url(", "bytes(", "double_")
    ):
        return "encoded"
    return "as is"


def part_words(part: str) -> str:
    """``req.body`` -> ``request body``, ``req.header:Cookie`` -> ``header
    Cookie``, ``url`` -> ``URL``, ``file:x.db-wal`` -> ``file x.db-wal``.
    """
    head, _, name = (part or "").partition(":")
    words = {
        "url": "URL",
        "req.header": "header",
        "resp.header": "response header",
        "req.body": "request body",
        "resp.body": "response body",
        "file": "file",
    }.get(head, head.replace(".", " "))
    return f"{words} {name}".strip()


def _applied_markers(ctx: ReportContext) -> int | None:
    """Values the identity profile seeded (the last ``identity/applied``
    line up to the end of the scope), or None without one.
    """
    end = ctx.span[1] if ctx.span else None
    count = None
    for line in ctx.lines:
        if line.get("src") != "identity" or line.get("kind") != "applied":
            continue
        if end is not None and line.get("_ts") is not None and line["_ts"] > end:
            break
        d = _data(line)
        if isinstance(d.get("markers"), int):
            count = d["markers"]
        elif isinstance(d.get("values"), dict):
            count = len(d["values"])
    return count


def _has_finding_store(ctx: ReportContext) -> bool:
    """The timeline folder has the privacy scan's finding store."""
    if ctx.timeline_dir is None:
        return False
    try:
        from sandroid.services import privacy_scan

        folder = ctx.timeline_dir / privacy_scan.FOLDER_NAME
        return (folder / privacy_scan.HITS_FILE).is_file() or (
            folder / privacy_scan.COVERAGE_FILE
        ).is_file()
    except Exception:
        return False


def _privacy_first(lines: list[dict[str, Any]]) -> dict[tuple, dict[str, Any]]:
    """First line per (value, recipient or file, transform), in time order."""
    first: dict[tuple, dict[str, Any]] = {}
    for line in lines:
        d = _data(line)
        if line.get("kind") == "sent":
            where = str(d.get("recipient") or d.get("host") or "unknown")
        else:
            where = str(d.get("path") or "unknown")
        key = (str(d.get("label") or d.get("marker_id") or "?"), where)
        first.setdefault((*key, str(d.get("transform") or "value")), line)
    return first


def _run_scope(ctx: ReportContext) -> Any:
    """The privacy :class:`RunScope` of a run report (None: whole session).

    The Play window is the scope's ``window``; the recording it replays is
    the time span of the ``seq_range`` lines (``record-start`` to
    ``record-stop``).
    """
    from sandroid.services.privacy_scan import run_scope

    scope = ctx.scope
    if scope.kind != "run" or not (scope.window or scope.seq_range):
        return None
    record = None
    if scope.seq_range:
        a, b = scope.seq_range
        stamps = [
            ln["_ts"]
            for ln in ctx.lines
            if isinstance(ln.get("seq"), int)
            and a <= ln["seq"] <= b
            and ln.get("_ts") is not None
        ]
        if stamps:
            record = (min(stamps), max(stamps))
    return run_scope(scope.run_id, scope.window, record)


def _hit_line(hit: Any) -> dict[str, Any]:
    """A hit record in the shape of its ``privacy/*`` line (for the tables)."""
    src = hit.source or {}
    rcpt = hit.recipient or {}
    data: dict[str, Any] = {
        "marker_id": hit.marker_id,
        "label": hit.label,
        "transform": hit.transform,
        "part": hit.part,
    }
    if hit.direction == "sent":
        data.update(
            host=src.get("host"),
            recipient=rcpt.get("label"),
            party=rcpt.get("party"),
        )
    else:
        data["path"] = src.get("device_path")
    return {
        "src": "privacy",
        "kind": hit.direction,
        "t": hit.t,
        "_ts": hit.t,
        "seq": hit.tl_seq,
        "data": data,
    }


def _privacy_lines(ctx: ReportContext) -> list[dict[str, Any]]:
    """The scope's findings as line-shaped dicts: every hit of the finding
    store in the scope, else (no store) the scope's ``privacy/*`` lines.
    """
    store = None
    if ctx.timeline_dir is not None:
        try:
            from sandroid.services import privacy_scan

            path = ctx.timeline_dir / privacy_scan.FOLDER_NAME
            if (path / privacy_scan.HITS_FILE).is_file():
                store, _scanned = privacy_scan.read_hits(ctx.timeline_dir)
        except Exception:
            logger.debug("Report: privacy findings unreadable", exc_info=True)
            store = None
    if store is None:
        return [
            ln for ln in ctx.by_src.get("privacy", []) if not _data(ln).get("_masked")
        ]
    scope = _run_scope(ctx)
    return sorted(
        (
            _hit_line(hit)
            for hit in store
            if hit.direction in ("sent", "stored")
            and (scope is None or scope.covers(hit))
        ),
        key=_sort_key,
    )


def build_privacy(ctx: ReportContext) -> dict:
    """Which identity-profile values left the device, to whom and how."""
    lines = _privacy_lines(ctx)
    if not lines and not ctx.by_src.get("privacy") and not _has_finding_store(ctx):
        return {
            "blocks": [
                _text(
                    ctx.notes[0]
                    if ctx.notes
                    else "Nothing to show: the report scope has no privacy lines "
                    "(was an identity profile active?)."
                )
            ]
        }
    sent = [ln for ln in lines if ln.get("kind") == "sent"]
    stored = [ln for ln in lines if ln.get("kind") == "stored"]
    blocks: list[dict] = []
    total = _applied_markers(ctx)
    values = sorted({str(_data(ln).get("label") or "?") for ln in sent})
    recipients: dict[str, str] = {}
    for line in sent:
        d = _data(line)
        name = str(d.get("recipient") or d.get("host") or "unknown")
        if recipients.get(name) != "third":
            recipients[name] = str(d.get("party") or "unknown")
    if sent:
        first = sent[0]
        of = f" of {total}" if total is not None else ""
        third = sum(1 for p in recipients.values() if p == "third")
        line_no = f" (line {first['seq']})" if first.get("seq") is not None else ""
        text = (
            f"{len(values)}{of} profile value{'s' if len(values) != 1 else ''} "
            f"left the device to {_plural(len(recipients), 'recipient')}, the "
            f"first at {_clock(first.get('t'))}{line_no}."
        )
        if third:
            text += f" {third} of the recipients are known third parties."
    else:
        text = "No profile value left the device in this report's scope."
    stored_values = {str(_data(ln).get("label") or "?") for ln in stored}
    if stored_values:
        text += (
            f" {_plural(len(stored_values), 'value')} "
            f"{'was' if len(stored_values) == 1 else 'were'} written to app storage."
        )
    text += (
        " Values are matched as seeded canaries (plain, hashed, encoded or "
        "rounded); a blank cell means the value was not seen going there."
    )
    blocks.append(_text(text))
    if not sent and not stored:
        return {"blocks": blocks}
    first = _privacy_first(sent + stored)
    if sent:
        seen: dict[tuple[str, str], set[str]] = {}
        for (label, where, transform), line in first.items():
            if line.get("kind") == "sent":
                seen.setdefault((where, label), set()).add(encoding_class(transform))
        order = ("as is", "encoded", "hashed", "rounded")
        rows = []
        for name in sorted(recipients, key=lambda n: (recipients[n] != "third", n)):
            party = _PARTY_WORDS.get(recipients[name], "unknown party")
            cells = [
                ", ".join(c for c in order if c in seen.get((name, value), ()))
                for value in values
            ]
            rows.append([f"{name} ({party})", *cells])
        blocks.append(_heading("Recipients and values", 2))
        blocks.append(
            {"type": "table", "columns": ["Recipient", *values], "rows": rows}
        )
    evidence = sorted(first.values(), key=_sort_key)
    rows = []
    for line in evidence[:MAX_PRIVACY_EVIDENCE]:
        d = _data(line)
        if line.get("kind") == "sent":
            where = str(d.get("recipient") or d.get("host") or "unknown")
            host = str(d.get("host") or "")
        else:
            where, host = "stored on the device", str(d.get("path") or "")
        rows.append(
            [
                str(d.get("label") or "?"),
                where,
                host,
                part_words(str(d.get("part") or "")),
                transform_words(str(d.get("transform") or "value")),
                _clock(line.get("t")),
                str(line["seq"]) if line.get("seq") is not None else "",
            ]
        )
    blocks.append(
        _heading("Evidence (first finding per value, recipient and encoding)", 2)
    )
    blocks.append(
        {
            "type": "table",
            "columns": ["Value", "Recipient", "Host or file", "Where", "Encoding",
                        "First seen", "Line"],
            "rows": rows,
            "mono_cols": [6],
        }
    )  # fmt: skip
    if len(evidence) > MAX_PRIVACY_EVIDENCE:
        more = len(evidence) - MAX_PRIVACY_EVIDENCE
        blocks.append(
            _text(f"{more} more findings are in the timeline (privacy lines).")
        )
    return {"blocks": blocks}


# ---------------------------------------------------------------------------
# Section: transcript
# ---------------------------------------------------------------------------


def _shot_trigger(line: Mapping[str, Any]) -> str:
    return str(_data(line).get("trigger") or line.get("kind") or "")


def _image_block(ctx: ReportContext, line: Mapping[str, Any]) -> dict[str, Any]:
    ref = _ref(line)
    d = _data(line)
    trigger = _shot_trigger(line)
    block: dict[str, Any] = {
        "type": "image",
        "seq": line.get("seq"),
        "of": ref.get("of"),
        "trigger": trigger,
        "t": line.get("t"),
        "path": None,
        "sha256": ref.get("sha256"),
        "w": d.get("w"),
        "h": d.get("h"),
        "dup_of": d.get("dup_of"),
        "caption": f"{trigger.replace('_', ' ')} · #{line.get('seq')}",
    }
    rel = ref.get("path")
    if rel and ctx.timeline_dir is not None:
        block["path"] = os.path.normpath(str(ctx.timeline_dir / str(rel)))
    elif rel:
        block["path"] = str(rel)
    if not rel or d.get("error"):
        block["error"] = str(d.get("error") or "no screenshot file")
    return block


class _Shots:
    """Shot lines indexed by ``ref.of``, filtered by the report options."""

    def __init__(self, ctx: ReportContext, lines: Iterable[Mapping[str, Any]]):
        self.ctx = ctx
        self.by_of: dict[int, list[Mapping[str, Any]]] = {}
        self.manual: list[Mapping[str, Any]] = []
        self.hidden = 0
        for line in lines:
            if line.get("src") != "shot":
                continue
            trigger = _shot_trigger(line)
            if (
                not ctx.options.include_screenshots
                or trigger not in ctx.options.shot_triggers
            ):
                self.hidden += 1
                continue
            of = _ref(line).get("of")
            if trigger == "manual" or not isinstance(of, int):
                self.manual.append(line)
            else:
                self.by_of.setdefault(of, []).append(line)

    def for_seq(self, seq: Any) -> list[dict[str, Any]]:
        if not isinstance(seq, int):
            return []
        return [_image_block(self.ctx, ln) for ln in self.by_of.get(seq, [])]


#: R4: the caption of a screen step whose next before-tap shot still shows
#: the previous screen (the new one had not drawn when the user went on).
GAP_FILL_REFUSED = "no screenshot: the new screen had not drawn before the next input"


def _png_of(block: Mapping[str, Any]) -> bytes | None:
    path = block.get("path")
    if not path or block.get("error"):
        return None
    try:
        return Path(str(path)).read_bytes()
    except OSError:
        return None


def _same_shot(ctx: ReportContext, a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    """Two shot lines show the same screen: equal sha256, else R1's
    perceptual :func:`sandroid.core.frames.same_screen` on their files.
    """
    sha_a, sha_b = _ref(a).get("sha256"), _ref(b).get("sha256")
    if sha_a and sha_a == sha_b:
        return True
    from .frames import same_screen

    return same_screen(_png_of(_image_block(ctx, a)), _png_of(_image_block(ctx, b)))


def _gap_fill(
    ctx: ReportContext,
    step: dict[str, Any],
    events: list[Mapping[str, Any]],
    start: int,
    before_tap: Mapping[int, Mapping[str, Any]],
    prev: Mapping[str, Any] | None = None,
) -> None:
    """R4: a screen step without a screen-change shot shows the NEXT
    input's before-tap shot (taken at its finger-down: the screen it acted
    on), unless another screen line comes first (``events[start:]`` follow
    the step). The block is marked
    ``source: next_before_tap`` (``report.json`` stays self-contained).

    ``prev``: the before-tap shot of the step's triggering input (R1: the
    previous screen). A next before-tap shot that is the previous screen
    (same sha256, or perceptually the same) is no image of the new screen:
    the step gets none and ``shot_note`` :data:`GAP_FILL_REFUSED`.
    """
    if (
        not ctx.options.include_screenshots
        or "screen_change" not in ctx.options.shot_triggers
        or any(s.get("trigger") == "screen_change" for s in step["shots"])
    ):
        return
    for j in range(start, len(events)):
        ln = events[j]
        if ln.get("src") == "screen":
            return
        if ln.get("src") == "input" and ln.get("kind") in INPUT_KINDS:
            shot = before_tap.get(ln.get("seq"))  # type: ignore[arg-type]
            if shot is not None and prev is not None and _same_shot(ctx, prev, shot):
                step["shot_note"] = GAP_FILL_REFUSED
            elif shot is not None:
                block = _image_block(ctx, shot)
                block["source"] = "next_before_tap"
                block["for"] = step.get("seq")
                block["caption"] = f"screen at next input #{ln.get('seq')}"
                step["shots"] = [*step["shots"], block]
            return


class _Effects:
    """App file events and network flows, searchable by time."""

    def __init__(self, lines: Iterable[Mapping[str, Any]]):
        self.lines = [
            ln
            for ln in lines
            if ln.get("_ts") is not None
            and (
                (
                    ln.get("src") == "files"
                    and ln.get("actor") == "app"
                    and ln.get("kind") not in ("count", "pull", "check")
                )
                or (ln.get("src") == "net" and ln.get("kind") in ("flow", "tls-fail"))
                or (ln.get("src") == "privacy" and ln.get("kind") in ("sent", "stored"))
            )
        ]
        self.stamps = [ln["_ts"] for ln in self.lines]

    def window(self, t0: float, t1: float) -> dict[str, Any] | None:
        lo = bisect_left(self.stamps, t0)
        hi = bisect_left(self.stamps, t1)
        picked = self.lines[lo:hi]
        if not picked:
            return None
        files = [ln for ln in picked if ln.get("src") == "files"]
        net = [ln for ln in picked if ln.get("src") == "net"]
        privacy = [ln for ln in picked if ln.get("src") == "privacy"]
        out: dict[str, Any] = {
            "window": [_iso(t0), _iso(t1)],
            "window_s": round(t1 - t0, 3),
        }
        if files:
            per_path: dict[str, dict[str, Any]] = {}
            for ln in files:
                d = _data(ln)
                path = str(d.get("path") or ln.get("summary") or "?")
                item = per_path.setdefault(
                    path, {"path": path, "n": 0, "kinds": Counter(), "seqs": []}
                )
                item["n"] += int(d.get("n") or 1)
                item["kinds"][str(ln.get("kind"))] += 1
                if len(item["seqs"]) < MAX_ITEM_SEQS:
                    item["seqs"].append(ln.get("seq"))
            top = sorted(per_path.values(), key=lambda i: -i["n"])[:TOP_EFFECTS]
            out["files"] = {
                "count": len(files),
                "by_kind": dict(Counter(str(ln.get("kind")) for ln in files)),
                "paths": len(per_path),
                "top": [{**i, "kinds": dict(i["kinds"])} for i in top],
            }
        if net:
            out["net"] = {
                "count": len(net),
                "by_kind": dict(Counter(str(ln.get("kind")) for ln in net)),
                "top": [
                    {
                        "seq": ln.get("seq"),
                        "kind": ln.get("kind"),
                        "method": _data(ln).get("method"),
                        "host": _data(ln).get("host"),
                        "path": _data(ln).get("path"),
                        "status": _data(ln).get("status"),
                        "error": _data(ln).get("error") or _data(ln).get("reason"),
                    }
                    for ln in net[:TOP_EFFECTS]
                ],
            }
        if privacy:
            out["privacy"] = {
                "count": len(privacy),
                "by_kind": dict(Counter(str(ln.get("kind")) for ln in privacy)),
                "top": [
                    {
                        "seq": ln.get("seq"),
                        "kind": ln.get("kind"),
                        "label": _data(ln).get("label"),
                        "to": _data(ln).get("recipient")
                        or _data(ln).get("host")
                        or _data(ln).get("path"),
                        "encoding": encoding_class(str(_data(ln).get("transform"))),
                    }
                    for ln in privacy[:TOP_EFFECTS]
                ],
            }
        return out


def _screen_of(line: Mapping[str, Any]) -> dict[str, Any] | None:
    d = _data(line)
    if not d or d.get("_masked"):
        return {"summary": line.get("summary")}
    return {
        "pkg": d.get("pkg") or line.get("pkg"),
        "cls": d.get("cls"),
        "title": d.get("title"),
        "via": d.get("via"),
    }


def _step(
    ctx: ReportContext,
    line: Mapping[str, Any],
    *,
    screen: dict[str, Any] | None,
    shots: _Shots,
    confirmed: set[int],
    label: list[int],
) -> dict[str, Any]:
    d = _data(line)
    src, kind = line.get("src"), line.get("kind")
    step: dict[str, Any] = {
        "type": "transcript_step",
        "seq": line.get("seq"),
        "t": line.get("t"),
        "src": src,
        "kind": kind,
        "actor": line.get("actor"),
        "clk": line.get("clk"),
        "t_err_ms": line.get("t_err_ms"),
        "summary": line.get("summary"),
        "level": line.get("level") or "info",
        "label": label,
        "element": None,
        "screen": screen,
        "shots": [],
        "effects": None,
    }
    if line.get("sensitive"):
        step["sensitive"] = True
    masked = bool(d.get("_masked"))
    if masked:
        step["masked"] = True
    if src == "input":
        target = d.get("target") if isinstance(d.get("target"), dict) else None
        step["element"] = element_name(target)
        if target:
            step["target"] = {
                k: target.get(k)
                for k in ("text", "desc", "label", "rid", "cls", "bounds", "source")
                if target.get(k) is not None
            }
            step["element_class"] = _short_cls(target.get("cls"))
        if isinstance(d.get("x"), (int, float)) and isinstance(
            d.get("y"), (int, float)
        ):
            step["xy"] = [d["x"], d["y"]]
        if isinstance(d.get("x1"), (int, float)):
            step["to_xy"] = [d.get("x1"), d.get("y1")]
        if kind == "key":
            step["element"] = step["element"] or d.get("name")
            step["key"] = d.get("name")
        if kind == "text":
            step["password"] = bool(d.get("password"))
            step["text"] = None if masked else d.get("text")
            step["text_masked"] = masked
        if d.get("dur_ms") is not None:
            step["dur_ms"] = d.get("dur_ms")
        step["confirmed"] = line.get("seq") in confirmed
    elif src == "screen":
        step["screen"] = _screen_of(line)
    elif src == "label":
        step["element"] = str(d.get("name") or "")
        step["mark"] = d.get("number")
    if src == "shot":
        step["shots"] = [_image_block(ctx, line)]
    else:
        step["shots"] = shots.for_seq(line.get("seq"))
    return step


def build_transcript(ctx: ReportContext) -> dict:
    """Interactions grouped by labels, with screenshots and effects."""
    lines = _transcript_lines(ctx)
    shots = _Shots(ctx, lines)
    effects = _Effects(ctx.lines)
    confirmed = {
        _ref(ln).get("of")
        for ln in lines
        if ln.get("src") == "input" and ln.get("kind") == "confirm"
    }
    screens = [
        ln
        for ln in ctx.lines
        if ln.get("src") == "screen" and ln.get("_ts") is not None
    ]
    screen_ts = [ln["_ts"] for ln in screens]

    def screen_at(ts: float, seq: int) -> dict[str, Any] | None:
        i = bisect_left(screen_ts, ts)
        while i < len(screens) and screen_ts[i] == ts and screens[i]["seq"] <= seq:
            i += 1
        return _screen_of(screens[i - 1]) if i > 0 else None

    manual = {id(ln) for ln in shots.manual}
    events: list[Mapping[str, Any]] = []
    for ln in lines:
        src, kind = ln.get("src"), ln.get("kind")
        if (
            (src == "input" and kind in INPUT_KINDS)
            or src == "screen"
            or (src == "label" and kind in ("start", "point"))
            or id(ln) in manual
        ):
            events.append(ln)
    input_ts = [
        ln["_ts"]
        for ln in events
        if ln.get("src") == "input" and ln.get("_ts") is not None
    ]
    before_tap = {
        _ref(ln).get("of"): ln
        for ln in lines
        if ln.get("src") == "shot"
        and _shot_trigger(ln) == "before_tap"
        and isinstance(_ref(ln).get("of"), int)
    }
    by_number = {s.number: s for s in ctx.labels}
    blocks: list[dict[str, Any]] = []
    n_steps = 0
    current: list[int] | None = None
    shown_heading: set[int] = set()

    def heading_for(path: list[int], *, start: bool) -> None:
        if not path:
            blocks.append(_heading("Unlabelled", 2, label=None))
            return
        span = by_number[path[-1]]
        times = _clock(span.t)
        if span.end_t:
            times += f"–{_clock(span.end_t)}"
        if span.duration_s is not None:
            times += f" · {span.duration_s:g} s"
        name = f" '{span.name}'" if span.name else ""
        text = f"Label {span.number}{name}"
        if not start and span.number in shown_heading:
            text += " (continued)"
        head = _heading(
            text,
            2 + min(span.depth, 3),
            label=span.as_dict(),
            times=times,
            path=path,
        )
        label_shots = shots.for_seq(span.seq)
        if label_shots and start:
            head["shots"] = label_shots
        blocks.append(head)
        shown_heading.add(span.number)

    trigger_shot: Mapping[str, Any] | None = None
    for i, ln in enumerate(events):
        ts, seq = ln.get("_ts") or 0.0, int(ln.get("seq") or 0)
        if ln.get("src") == "label" and ln.get("kind") == "start":
            data = _data(ln)
            number = data.get("number")
            if number in by_number:
                path = _label_path(ctx, ts, seq) or [number]
                heading_for(path, start=True)
                current = path
            continue
        path = _label_path(ctx, ts, seq)  # a point belongs to its parent span
        if path != current:
            heading_for(path, start=False)
            current = path
        step = _step(
            ctx,
            ln,
            screen=screen_at(ts, seq) if ln.get("src") != "screen" else None,
            shots=shots,
            confirmed=confirmed,
            label=path,
        )
        if ln.get("src") == "screen":
            _gap_fill(ctx, step, events, i + 1, before_tap, trigger_shot)
        elif ln.get("src") == "input" and ln.get("kind") in INPUT_KINDS:
            # R1: the latest input before a screen line triggered it; its
            # before-tap shot is the previous screen
            trigger_shot = before_tap.get(seq)
        if ln.get("src") == "input":
            nxt = bisect_left(input_ts, ts)
            while nxt < len(input_ts) and input_ts[nxt] <= ts:
                nxt += 1
            end = ts + float(ctx.options.effects_window_s)
            if nxt < len(input_ts):
                end = min(end, input_ts[nxt])
            if end > ts:
                step["effects"] = effects.window(ts, end)
        blocks.append(step)
        n_steps += 1
    intro = _transcript_intro(ctx, lines, n_steps, shots)
    return {"blocks": intro + blocks}


def _transcript_intro(
    ctx: ReportContext, lines: list[dict[str, Any]], n_steps: int, shots: _Shots
) -> list[dict]:
    stamps = [ln["_ts"] for ln in lines if ln.get("_ts") is not None]
    where = f"between {_clock(min(stamps))} and {_clock(max(stamps))}" if stamps else ""
    which = (
        "the recording this run replayed"
        if ctx.scope.seq_range
        else "the report window"
    )
    text = (
        f"{_plural(n_steps, 'step')} in {which} {where}. Effects are the app's "
        f"file events and network flows within {ctx.options.effects_window_s:g} s "
        "after each input (up to the next input)."
    ).replace("  ", " ")
    blocks = [_text(text)]
    if not ctx.options.include_screenshots:
        blocks.append(_text("Screenshots are not included (include_screenshots off)."))
    elif ctx.options.shot_triggers != ALL_TRIGGERS:
        triggers = ", ".join(sorted(ctx.options.shot_triggers)) or "none"
        blocks.append(_text(f"Screenshots shown for triggers: {triggers}."))
    if shots.hidden and ctx.options.include_screenshots:
        blocks.append(
            _text(
                f"{_plural(shots.hidden, 'screenshot')} hidden by the trigger filter."
            )
        )
    return blocks


# ---------------------------------------------------------------------------
# Section: results (port of the legacy PDF sections)
# ---------------------------------------------------------------------------


def _flatten(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(value, list):
        yield prefix, ", ".join(str(v) for v in value) if value else "[]"
    else:
        yield prefix, value


def _parse_pkg_hashes(entries: Iterable[Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for row in entries:
        pkg, sep, digest = str(row).partition(": ")
        out[pkg] = digest if sep else ""
    return out


def _other(data: Mapping[str, Any]) -> dict[str, Any]:
    other = data.get("Other Data")
    return other if isinstance(other, dict) else {}


def _list_other(data: Mapping[str, Any], key: str) -> list[Any] | None:
    value = _other(data).get(key)
    if value is None:
        return None
    if isinstance(value, list) and value and isinstance(value[0], list):
        merged: list[Any] = []
        for sub in value:
            merged.extend(sub)
        return merged
    return value if isinstance(value, list) else [value]


def _last_dict(data: Mapping[str, Any], key: str) -> dict[str, Any] | None:
    value = _other(data).get(key)
    if isinstance(value, list):
        value = value[-1] if value else None
    return value if isinstance(value, dict) else None


def _hash_lines(sha256: Any, md5: Any) -> list[str]:
    parts = []
    if sha256:
        parts.append(f"SHA-256: {sha256}")
    if md5:
        parts.append(f"MD5: {md5}")
    return parts or ["n/a"]


def _hash_table(columns: list[str], rows: list[list[Any]]) -> dict[str, Any]:
    return {
        "type": "table",
        "columns": columns,
        "rows": rows,
        "widths": [30, 175, None],
        "mono_cols": [2],
    }


def _res_summary(data: Mapping[str, Any], name: str) -> list[dict]:
    rows: list[list[Any]] = []
    total = 0
    for section, value in data.items():
        if section in _NON_ARTEFACT_KEYS:
            continue
        count = len(value) if isinstance(value, (list, dict)) else 0
        rows.append([section, count])
        total += count
    hashes = _last_dict(data, "Artifact Hashes")
    if hashes is not None:
        n_new = len(hashes.get("new_file_hashes") or {})
        n_changed = len(hashes.get("changed_file_hashes(old,new)") or {})
        rows.append(["Hashes of files created during action", n_new])
        rows.append(["Before/after hashes of changed files", n_changed])
        total += n_new + n_changed
    apks = _list_other(data, "APK Hashes")
    if apks is not None:
        rows.append(["APK hashes", len(apks)])
        total += len(apks)
    rows.append(["Total number of artifacts found", total])
    return [{"type": "kv", "rows": rows, "highlight_last": True, "align": "right"}]


def _res_settings(data: Mapping[str, Any], name: str) -> list[dict]:
    md = data.get(RUN_METADATA_KEY) or {}
    settings = md.get("settings") or {}
    if not settings:
        return []
    rows = [[k, v] for k, v in _flatten(settings)]
    return [
        {
            "type": "table",
            "columns": ["Setting", "Value"],
            "rows": rows,
            "widths": [200, None],
        }
    ]


def _res_changed_files(data: Mapping[str, Any], name: str) -> list[dict]:
    entries = data.get("Changed Files") or []
    if not entries:
        return [_text("No entries.")]
    rows = []
    for num, item in enumerate(entries, 1):
        if isinstance(item, dict) and item:
            file_name = next(iter(item))
            changes = item[file_name]
        else:
            file_name, changes = item, []
        if isinstance(changes, str):
            changes = [changes]
        lines: list[str] = []
        for block in changes or []:
            lines.extend(str(block).strip("\n").splitlines())
        rows.append([num, str(file_name), [ln.strip() for ln in lines if ln.strip()]])
    return [
        {
            "type": "table",
            "columns": ["No.", "File", "Changes"],
            "rows": rows,
            "widths": [30, 190, None],
            "see_also": f"{name} / raw/",
        }
    ]


def _res_general(key: str) -> Callable[[Mapping[str, Any], str], list[dict]]:
    def build(data: Mapping[str, Any], name: str) -> list[dict]:
        entries = data.get(key) or []
        if not entries:
            return [_text("No entries.")]
        return [
            {
                "type": "table",
                "columns": ["No.", "Entry"],
                "rows": [[i, str(e)] for i, e in enumerate(entries, 1)],
                "widths": [30, None],
                "see_also": name,
            }
        ]

    return build


def _res_apks(data: Mapping[str, Any], name: str) -> list[dict]:
    apks = _list_other(data, "APK Hashes") or []
    sha_map = _parse_pkg_hashes(_list_other(data, "APK Hashes SHA-256") or [])
    if not apks:
        return [_text("No entries.")]
    rows = [
        [num, pkg, _hash_lines(sha_map.get(pkg), md5)]
        for num, (pkg, md5) in enumerate(_parse_pkg_hashes(apks).items(), 1)
    ]
    return [_hash_table(["No.", "Package", "Hashes"], rows)]


def _res_new_hashes(data: Mapping[str, Any], name: str) -> list[dict]:
    hashes = _last_dict(data, "Artifact Hashes") or {}
    md5s = hashes.get("new_file_hashes") or {}
    shas = hashes.get("new_file_hashes_sha256") or {}
    if not md5s and not shas:
        return [_text("No entries.")]
    rows = [
        [num, file, _hash_lines(shas.get(file), md5s.get(file))]
        for num, file in enumerate(sorted(set(md5s) | set(shas)), 1)
    ]
    return [_hash_table(["No.", "File", "Hashes"], rows)]


def _res_changed_hashes(data: Mapping[str, Any], name: str) -> list[dict]:
    hashes = _last_dict(data, "Artifact Hashes") or {}
    md5s = hashes.get("changed_file_hashes(old,new)") or {}
    shas = hashes.get("changed_file_hashes_sha256(old,new)") or {}
    if not md5s and not shas:
        return [_text("No entries.")]
    rows = []
    for num, file in enumerate(sorted(set(md5s) | set(shas)), 1):
        md5_pair = [*list(md5s.get(file) or [None, None]), None, None]
        sha_pair = [*list(shas.get(file) or [None, None]), None, None]
        rows.append(
            [
                num,
                file,
                _hash_lines(sha_pair[0], md5_pair[0]),
                _hash_lines(sha_pair[1], md5_pair[1]),
            ]
        )
    return [
        {
            "type": "table",
            "columns": ["No.", "File", "Before action", "After action"],
            "rows": rows,
            "widths": [25, 120, None, None],
            "mono_cols": [2, 3],
        }
    ]


def _res_filtered_noise(data: Mapping[str, Any], name: str) -> list[dict]:
    report = _last_dict(data, "Filtered Noise") or {}
    sections = {k: v for k, v in report.items() if isinstance(v, dict)}
    total = sum(len(v) for v in sections.values())
    counts = ", ".join(f"{k}: {len(v)}" for k, v in sections.items())
    enabled = "on" if report.get("enabled") else "off"
    blocks = [
        _text(
            f"{total} entr{'y' if total == 1 else 'ies'} hidden from the results "
            f"above ({counts or 'none'}; system noise filter {enabled}). "
            + str(report.get("note") or "")
        )
    ]
    if not total:
        return blocks
    rows = []
    for section, hidden in sections.items():
        for path, reason in hidden.items():
            if len(rows) >= MAX_FILTERED_NOISE_ROWS:
                break
            rows.append([section, str(path), str(reason)])
    blocks.append(
        {
            "type": "table",
            "columns": ["Section", "Path / entry", "Reason"],
            "rows": rows,
            "widths": [90, None, 170],
        }
    )
    if total > len(rows):
        more = total - len(rows)
        blocks.append(
            _text(
                f"{more} more entr{'y' if more == 1 else 'ies'} in {name} "
                "(Other Data → Filtered Noise)."
            )
        )
    return blocks


_GENERAL_SECTIONS = (
    ("New Files", "New Files"),
    ("Deleted Files", "Deleted Files"),
    ("Processes", "Processes"),
    ("Listening Sockets", "Listening Sockets"),
    ("Network", "Network (DNS names)"),
    ("Network IP:Port (send/recv)", "Network IP:Port (send/recv)"),
)


def results_plan(
    data: Mapping[str, Any],
) -> list[tuple[str, Callable[[Mapping[str, Any], str], list[dict]]]]:
    """Ordered ``(title, builder)`` list of the legacy results sections."""
    plan: list[tuple[str, Callable[[Mapping[str, Any], str], list[dict]]]] = [
        ("Summary", _res_summary),
        ("Analysis settings", _res_settings),
    ]
    if "Changed Files" in data:
        plan.append(("Changed Files", _res_changed_files))
    for key, title in _GENERAL_SECTIONS:
        if key in data:
            plan.append((title, _res_general(key)))
    if "APK Hashes" in _other(data):
        plan.append(("APKs & Hashes", _res_apks))
    if "Artifact Hashes" in _other(data):
        plan.append(("Hashes of new files", _res_new_hashes))
        plan.append(
            ("Hashes of changed files (before / after action)", _res_changed_hashes)
        )
    if _last_dict(data, "Filtered Noise") is not None:
        plan.append(("Filtered Noise", _res_filtered_noise))
    return plan


def build_results(ctx: ReportContext) -> dict:
    """The legacy result tables, built from the bundle's results JSON."""
    if ctx.bundle is None:
        reason = ctx.bundle_error or "this report has no run bundle"
        return {"blocks": [_text(f"No analysis results: {reason}.")]}
    data = ctx.bundle
    name = ctx.bundle_path.name if ctx.bundle_path else DEFAULT_RESULTS_NAME
    blocks: list[dict] = []
    for title, builder in results_plan(data):
        try:
            sub = builder(data, name)
        except Exception as exc:
            logger.error("Results part %r failed: %s", title, exc, exc_info=True)
            sub = [{"type": "error", "error": f"{type(exc).__name__}: {exc}"}]
        if sub:
            blocks.append(_heading(title, 2))
            blocks.extend(sub)
    blocks.append(
        _text(
            "File hashes are given as SHA-256 (MD5 retained for compatibility). A "
            "manifest of all files in the result folder (manifest.json, SHA256SUMS) "
            "is written at the end of each run; its SHA-256 is recorded in the "
            "Sandroid log. Long diffs continue over several rows; lines over "
            f"{MAX_LINE_CHARS} characters and diffs over {MAX_DIFF_LINES_TOTAL} "
            f"lines are shortened where shown. The complete data is in {name}."
        )
    )
    return {"blocks": blocks}


# ---------------------------------------------------------------------------
# Section: seal
# ---------------------------------------------------------------------------


def build_seal(ctx: ReportContext) -> dict:
    """The timeline seal this report was built from."""
    seal = ctx.seal
    if not seal:
        reason = (
            "no session timeline was available"
            if ctx.timeline_path is None
            else "the timeline was read without a seal"
        )
        return {"blocks": [_text(f"This report is not sealed: {reason}.", "warn")]}
    rows = [
        ["Timeline file", seal.get("path") or (str(ctx.timeline_path) or None)],
        ["Session", seal.get("session_id")],
        ["Lines", f"{seal.get('seq_first')}–{seal.get('seq_last')}"],
        ["Last line hash", seal.get("last_h")],
        ["File SHA-256", seal.get("sha256")],
        ["Bytes covered", seal.get("bytes")],
        ["Chain verified", "yes" if seal.get("verified") else "NO"],
        ["Seal line", seal.get("seal_seq")],
    ]
    return {
        "blocks": [
            {
                "type": "kv",
                "rows": rows,
                "mono_keys": ["Last line hash", "File SHA-256"],
            },
            _text(
                f"The SHA-256 covers bytes 0–{seal.get('bytes')} of the timeline "
                "file, which is append-only, so the seal stays checkable while the "
                "file grows. Verify it with: python -m sandroid.core.timeline "
                "verify <timeline file>."
            ),
        ]
    }


# ---------------------------------------------------------------------------
# Plan, build, write
# ---------------------------------------------------------------------------

SECTION_PLAN: tuple[SectionSpec, ...] = (
    SectionSpec("overview", "Overview", build_overview),
    SectionSpec("coverage", "Coverage and validity", build_coverage),
    SectionSpec(
        "privacy",
        "Identity data leaving the device",
        build_privacy,
    ),
    SectionSpec(
        "transcript",
        "Interaction transcript",
        build_transcript,
        requires_src=frozenset({"input", "screen", "shot", "label"}),
    ),
    SectionSpec("results", "Analysis results", build_results),
    SectionSpec("seal", "Timeline seal", build_seal),
)


def _plan(sections: tuple[str, ...] | None) -> list[SectionSpec]:
    if sections is None:
        return list(SECTION_PLAN)
    known = {spec.id: spec for spec in SECTION_PLAN}
    plan = []
    for sid in sections:
        if sid in known:
            plan.append(known[sid])
        else:
            logger.warning("Report: unknown section id %r ignored", sid)
    return plan


def _run_section(spec: SectionSpec, ctx: ReportContext) -> dict[str, Any]:
    try:
        if spec.requires_src and not any(ctx.by_src.get(s) for s in spec.requires_src):
            why = (
                ctx.notes[0]
                if ctx.notes
                else (
                    "Nothing to show: the report scope has no "
                    + ", ".join(sorted(spec.requires_src))
                    + " lines (was Tracking on?)."
                )
            )
            blocks = [_text(why)]
        else:
            blocks = list((spec.builder(ctx) or {}).get("blocks") or [])
    except Exception as exc:
        logger.error("Report section %r failed: %s", spec.id, exc, exc_info=True)
        blocks = [{"type": "error", "error": f"{type(exc).__name__}: {exc}"}]
    return {"id": spec.id, "title": spec.title, "blocks": blocks}


def _version() -> str:
    from sandroid._version import __version__

    return __version__


def build_report(
    *,
    timeline: Path | None,
    seal: Any | None,
    scope: ReportScope,
    bundle_dir: Path | None,
    options: ReportOptions = ReportOptions(),  # noqa: B008 - frozen dataclass
    results_json: Path | None = None,
) -> dict:
    """Build the ``report.json`` document.

    Args:
        timeline: The session ``timeline.jsonl`` (``None``: no transcript).
        seal: Its :class:`~sandroid.core.timeline.Seal` (or the seal as a
            mapping); lines are read only up to ``seal.bytes``.
        scope: Session or run scope (see :func:`scope_for_run`).
        bundle_dir: Result folder holding the results JSON (``sandroid.json``)
            for the legacy results section; ``None`` to omit it.
        options: Report options (sections, masking, effects, screenshots).
        results_json: Explicit results JSON instead of searching
            ``bundle_dir``.

    Returns:
        The report document (JSON-serialisable). Never raises for a defect in
        one section; that section holds an ``error`` block instead.
    """
    tl = _timeline_module()
    if options.mask_sensitive is not None:
        masked = bool(options.mask_sensitive)
    else:
        try:
            masked = bool(tl.should_mask("report")) if tl is not None else False
        except Exception:
            masked = False
    ctx = ReportContext(
        scope=scope,
        options=options,
        masked=masked,
        generated_at=iso_now(),
        seal=seal_to_dict(seal),
        notes=list(options.coverage_notes),
    )
    if timeline is not None:
        ctx.timeline_path = Path(timeline)
        ctx.timeline_dir = Path(timeline).resolve().parent
        try:
            _load_lines(ctx, Path(timeline))
        except Exception as exc:
            logger.error("Report: timeline unreadable: %s", exc, exc_info=True)
            ctx.notes.append(
                f"The session timeline {timeline} could not be read: {exc}"
            )
            ctx.lines = []
    elif not ctx.notes:
        ctx.notes.append("No session timeline was available for this report.")
    _apply_scope(ctx)
    ctx.labels = _build_labels(ctx.lines)
    _load_bundle(ctx, bundle_dir, results_json)
    sections = [_run_section(spec, ctx) for spec in _plan(options.sections)]
    device = (ctx.bundle or {}).get("Device Name") or _device_info(ctx)[1]
    return {
        "schema": SCHEMA,
        "generated_at": ctx.generated_at,
        "generator": f"Sandroid {_version()}",
        "title": "Sandroid Forensic Report",
        "device": device,
        "scope": scope_to_dict(scope),
        "seal": ctx.seal,
        "timeline": {
            "path": str(ctx.timeline_path) if ctx.timeline_path else None,
            "session_id": (ctx.seal or {}).get("session_id") or _session_id(ctx),
            "available": bool(ctx.lines),
            "lines": len(ctx.lines),
            "lines_in_scope": len(ctx.scoped),
        },
        "masking": {
            "sensitive_masked": ctx.masked,
            "sensitive_lines": sum(1 for ln in ctx.scoped if ln.get("sensitive")),
        },
        "source": {
            "results_json": ctx.bundle_path.name if ctx.bundle_path else None,
            "results_sha256": ctx.bundle_sha256,
        },
        "options": {
            "sections": [s["id"] for s in sections],
            "effects_window_s": options.effects_window_s,
            "shot_triggers": sorted(options.shot_triggers),
            "include_screenshots": options.include_screenshots,
        },
        "sections": sections,
    }


def scope_for_run(
    timeline: Path, run_id: str, *, end: int | None = None
) -> ReportScope:
    """Run scope from the run's ``play-start``/``play-end`` lines.

    ``seq_range`` comes from ``play-start.replays.seq_range`` (the record
    window), ``window`` from ``play-start`` to ``play-end`` (or the last
    sealed line while the run is still being finalised). A run that is not in
    the timeline gets an empty run scope (the report then says so).
    """
    tl = _timeline_module()
    if tl is None:
        return ReportScope(kind="run", run_id=run_id)
    start: Mapping[str, Any] | None = None
    stop: Mapping[str, Any] | None = None
    last_ts: float | None = None
    for _off, line in tl.read_lines(
        Path(timeline), end=end, reader="report", mask_sensitive=False
    ):
        ts = _ts(line.get("t"))
        if ts is not None:
            last_ts = ts if last_ts is None else max(last_ts, ts)
        if line.get("src") != "run":
            continue
        kind = line.get("kind")
        if kind == "play-start":
            bundle = str(_data(line).get("bundle") or "")
            if line.get("run") == run_id or bundle.rstrip("/").endswith(
                f"runs/{run_id}"
            ):
                start, stop = line, None
        elif kind == "play-end" and start is not None:
            ref = _ref(line)
            if ref.get("run") == run_id or ref.get("of") == start.get("seq"):
                stop = line
    if start is None:
        return ReportScope(kind="run", run_id=run_id)
    t0 = _ts(start.get("t"))
    t1 = _ts(stop.get("t")) if stop is not None else last_ts
    window = (t0, max(t1, t0)) if t0 is not None and t1 is not None else None
    seq_range = None
    replays = start.get("replays")
    if isinstance(replays, dict):
        rng = replays.get("seq_range")
        if (
            isinstance(rng, (list, tuple))
            and len(rng) == 2
            and all(isinstance(x, int) for x in rng)
        ):
            seq_range = (int(rng[0]), int(rng[1]))
    return ReportScope(kind="run", run_id=run_id, window=window, seq_range=seq_range)


def report_options_from_config(config: Any = None, **overrides: Any) -> ReportOptions:
    """:class:`ReportOptions` from ``config.report`` (missing fields: defaults)."""
    if config is None:
        try:
            from sandroid.config import get_config

            config = get_config()
        except Exception:
            config = None
    report = getattr(config, "report", None)
    triggers = getattr(report, "shot_triggers", None)
    values: dict[str, Any] = {
        "effects_window_s": float(getattr(report, "effects_window_s", 2.0) or 0.0),
        "shot_triggers": frozenset(triggers) if triggers is not None else ALL_TRIGGERS,
        "include_screenshots": bool(getattr(report, "include_screenshots", True)),
    }
    values.update(overrides)
    return ReportOptions(**values)


def report_formats(config: Any = None) -> tuple[str, ...]:
    """``config.report.formats`` (default ``("pdf", "md")``)."""
    report = getattr(config, "report", None)
    formats = getattr(report, "formats", None)
    if not formats:
        return ("pdf", "md")
    return tuple(str(f).lower() for f in formats)


#: Step keys that carry a sensitive line's content (masked on a re-render).
_SENSITIVE_STEP_KEYS = ("target", "element", "element_class", "xy", "to_xy", "key")


def _mask_copied(node: Any) -> int:
    """Mask every ``sensitive`` transcript step under ``node`` in place (as
    :func:`_step` does for a masked line); returns how many were masked.
    """
    count = 0
    if isinstance(node, dict):
        if node.get("sensitive") and node.get("type") == "transcript_step":
            for key in _SENSITIVE_STEP_KEYS:
                node.pop(key, None)
            node["element"] = None
            if "text" in node or node.get("kind") == "text":
                node["text"] = None
                node["text_masked"] = True
            if node.get("src") == "screen":
                node["screen"] = {"summary": node.get("summary")}
            node["masked"] = True
            count += 1
        for value in node.values():
            count += _mask_copied(value)
    elif isinstance(node, list):
        for value in node:
            count += _mask_copied(value)
    return count


def _unverified_copy(doc: dict, reason: str) -> None:
    """The copied seal section and integrity sentences: the chain was not
    re-checked now (they stated the original report's result).
    """
    seal = doc.get("seal")
    if isinstance(seal, dict):
        doc["seal"] = {
            **seal,
            "verified": None,
            "verified_originally": seal.get("verified"),
        }
    note = f"Not re-checked: {reason.rstrip('.')}."
    for section in doc.get("sections") or []:
        if not isinstance(section, dict):
            continue
        for block in section.get("blocks") or []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "kv":
                for row in block.get("rows") or []:
                    if isinstance(row, list) and row and row[0] == "Chain verified":
                        was = row[1] if len(row) > 1 else None
                        row[1:] = [f"not re-checked (was {was!s} originally)"]
            elif block.get("type") == "list" and section.get("id") == "coverage":
                block["items"] = [
                    f"{item} (as of the original report; not re-checked)"
                    if isinstance(item, str) and item.startswith("The hash chain")
                    else item
                    for item in block.get("items") or []
                ]
        if section.get("id") == "seal":
            section.setdefault("blocks", []).insert(0, _text(note, "warn"))


def annotate_rerender(
    doc: dict, reason: str, *, mask_sensitive: bool | None = None
) -> dict:
    """Mark a report copied from an earlier ``report.json``.

    Used when the timeline can no longer be read (missing or changed): the
    coverage section then states that the data was not re-derived, the seal
    no longer claims a verified chain (it was not re-checked) and the
    current masking setting (``mask_sensitive``; None:
    ``should_mask("report")``) is applied to the copied transcript.
    """
    doc = copy.deepcopy(doc)
    if mask_sensitive is None:
        tl = _timeline_module()
        try:
            mask_sensitive = bool(tl.should_mask("report")) if tl else False
        except Exception:
            mask_sensitive = False
    masking = doc.get("masking") if isinstance(doc.get("masking"), dict) else {}
    was_masked = bool(masking.get("sensitive_masked"))
    mask_note = ""
    if mask_sensitive and not was_masked:
        n = _mask_copied(doc.get("sections") or [])
        doc["masking"] = {**masking, "sensitive_masked": True, "masked_on_copy": n}
        mask_note = (
            f" Sensitive values were masked in this copy ({_plural(n, 'step')}), "
            "as timeline.mask_sensitive is now on."
        )
    elif was_masked and not mask_sensitive:
        mask_note = (
            " Sensitive values stay masked: the original report masked them and "
            "the timeline cannot be re-read."
        )
    _unverified_copy(doc, reason)
    original = doc.get("generated_at")
    doc["regenerated"] = {
        "from": "report.json",
        "reason": reason,
        "original_generated_at": original,
    }
    doc["generated_at"] = iso_now()
    timeline = doc.setdefault("timeline", {})
    if isinstance(timeline, dict):
        timeline["available"] = False
    note = _text(
        f"{reason.rstrip('.')}. The transcript and the coverage below could not be "
        "re-derived from the timeline; they are copied from the original "
        f"report.json (generated {original}). The hash chain was not "
        f"re-checked.{mask_note}",
        "warn",
    )
    sections = doc.setdefault("sections", [])
    for section in sections:
        if section.get("id") == "coverage":
            section.setdefault("blocks", []).insert(0, note)
            break
    else:
        sections.insert(
            0, {"id": "coverage", "title": "Coverage and validity", "blocks": [note]}
        )
    return doc


def _relativize(doc: dict, out_dir: Path) -> dict:
    """Copy of ``doc`` with absolute image paths made relative to ``out_dir``."""
    out = copy.deepcopy(doc)
    base = Path(out_dir).resolve()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") == "image" and node.get("path"):
                path = Path(str(node["path"]))
                if path.is_absolute():
                    try:
                        node["path"] = Path(os.path.relpath(path, base)).as_posix()
                    except ValueError:  # other drive (Windows)
                        node["path"] = path.as_posix()
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(out)
    return out


def write_report(
    doc: dict,
    out_dir: Path,
    *,
    stem: str = "report",
    formats: Iterable[str] = ("json", "md", "pdf"),
) -> dict[str, Path]:
    """Write ``<stem>.json`` and render ``<stem>.md`` / ``<stem>.pdf`` from it.

    Image paths become relative to ``out_dir``. The renderers get the JSON
    exactly as written (round-tripped), never the timeline. Existing files
    are replaced; callers that must not overwrite choose a free ``stem``.

    Returns:
        ``{format: path}`` of the written files.
    """
    from . import report_render

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    fmts = [str(f).lower() for f in formats]
    text = json.dumps(
        _relativize(doc, out_dir), indent=2, ensure_ascii=False, default=str
    )
    data = json.loads(text)
    written: dict[str, Path] = {}
    if "json" in fmts:
        path = out_dir / f"{stem}.json"
        path.write_text(text + "\n", encoding="utf-8", errors="backslashreplace")
        written["json"] = path
    if "md" in fmts:
        path = out_dir / f"{stem}.md"
        path.write_text(
            report_render.render_markdown(data, base_dir=out_dir),
            encoding="utf-8",
            errors="backslashreplace",
        )
        written["md"] = path
    if "pdf" in fmts:
        written["pdf"] = report_render.render_pdf(
            data, out_dir / f"{stem}.pdf", base_dir=out_dir
        )
    return written


def sha256_prefix(path: Path, n_bytes: int) -> str:
    """SHA-256 of the first ``n_bytes`` of ``path``."""
    digest = hashlib.sha256()
    remaining = int(n_bytes)
    with open(path, "rb") as fh:
        while remaining > 0:
            chunk = fh.read(min(1 << 20, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


__all__ = [
    "ALL_TRIGGERS",
    "SCHEMA",
    "SECTION_PLAN",
    "ReportContext",
    "ReportOptions",
    "ReportScope",
    "SectionSpec",
    "annotate_rerender",
    "build_report",
    "element_name",
    "find_results_json",
    "report_formats",
    "report_options_from_config",
    "scope_for_run",
    "seal_to_dict",
    "sha256_prefix",
    "write_report",
]
