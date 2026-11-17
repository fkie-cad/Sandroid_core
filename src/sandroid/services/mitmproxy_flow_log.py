"""Reader for Sandroid's structured mitmproxy flow log.

The writer side lives in :mod:`sandroid.services.mitmproxy_service`'s
embedded mitmweb addon (``_ADDON_SOURCE``) -- this module has no dependency
on mitmproxy's own package or on a live mitmweb process being up; it is
plain JSON/file reading, safe to call whether or not mitmweb is running.

Storage layout (mirrors the addon's own resolution -- see
:func:`resolve_flow_dir` for why this two-line resolution is deliberately
duplicated rather than shared)::

    <raw_results>/mitm_flows/
        flows.jsonl             # append-only, one JSON record per line
        details/<flow_id>.json  # full headers + capped body, one per flow
        meta.json                # {"earliest_seq", "latest_seq",
                                  #  "total_flows_lifetime", "generation"}

Cursor cache: :func:`query_flows` keeps a process-local
``{log_path: (last_seq_seen, byte_offset, generation)}`` cache so a
``since_cursor`` call that has already caught up to the cached high-water
mark seeks straight to the cached byte offset instead of rescanning the
whole file. A cached entry is only trusted when the file's current
``generation`` (from ``meta.json``) still matches the generation recorded
when the cache was populated -- a retention trim is the only thing that ever
rewrites existing records' byte offsets, and it is the only thing that bumps
``generation``, so a generation mismatch is proof the cached offset would
now seek to garbage or a misaligned record. Any other mismatch (first call
in this process, or a cursor behind the cached high-water mark) forces a
full bounded scan and repopulates the cache.
"""

from __future__ import annotations

import base64
import json
import logging
import uuid
from pathlib import Path
from typing import Any

import dateutil.parser

logger = logging.getLogger(__name__)

#: Hard ceiling on rows any single query can return, regardless of the
#: caller-requested `limit` -- mirrors host_files.read_host_file's own
#: hard-cap-regardless-of-request pattern.
HARD_LIMIT_CAP = 2000

#: {str(flows.jsonl path): (last_seq_seen, byte_offset, generation)}.
_CURSOR_CACHE: dict[str, tuple[int, int, int]] = {}

_META_DEFAULTS: dict[str, Any] = {
    "earliest_seq": None,
    "latest_seq": 0,
    "total_flows_lifetime": 0,
    "generation": 0,
}

_DETAIL_PARTS = {
    "all",
    "request",
    "response",
    "request_headers",
    "response_headers",
    "request_body",
    "response_body",
}


def resolve_flow_dir() -> Path:
    """Resolve ``<raw_results>/mitm_flows`` fresh, independently of the addon.

    Deliberately re-resolved on every call (never cached) -- the session's
    raw-results path can change across a device switch, mirroring
    ``ai/tools/_host_paths.py``'s "never cache the session-dependent root"
    convention. Duplicates ``mitmproxy_service.py``'s own two-line
    resolution rather than sharing an import: that module must resolve this
    path *before* spawning mitmweb, and importing from ``ai/tools`` into
    ``services`` would be a backwards dependency that doesn't exist anywhere
    else in this codebase.
    """
    from sandroid.services import get_configuration_service

    raw_root = Path(get_configuration_service().get_raw_results_path())
    return raw_root.expanduser().resolve() / "mitm_flows"


def _log_path(flow_dir: Path) -> Path:
    return flow_dir / "flows.jsonl"


def _details_dir(flow_dir: Path) -> Path:
    return flow_dir / "details"


def _meta_path(flow_dir: Path) -> Path:
    return flow_dir / "meta.json"


def read_meta(flow_dir: Path) -> dict[str, Any]:
    """Best-effort ``meta.json`` read; missing/corrupt falls back to defaults."""
    data: Any = {}
    try:
        with open(_meta_path(flow_dir), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {**_META_DEFAULTS, **data}


def _write_meta_atomic(flow_dir: Path, meta: dict[str, Any]) -> None:
    """Write ``meta.json`` atomically (temp file + rename), same as the addon."""
    flow_dir.mkdir(parents=True, exist_ok=True)
    path = _meta_path(flow_dir)
    tmp_path = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex[:8]}")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(meta, f)
    tmp_path.replace(path)


def _read_records(
    log_path: Path, start_offset: int
) -> tuple[list[dict[str, Any]], int]:
    """Read complete JSON records starting at ``start_offset``.

    Returns ``(records, new_offset)`` where ``new_offset`` points just past
    the last *complete* line read. A trailing line with no newline yet (the
    addon mid-write) is silently dropped and NOT counted as consumed, so a
    caller resuming from ``new_offset`` picks it up once it's complete
    rather than skipping it.

    Operates on raw bytes (not decoded text) so the returned offset is a
    real byte offset regardless of any non-ASCII content in a record.
    Missing/unreadable files return ``([], start_offset)`` unchanged.
    """
    try:
        with open(log_path, "rb") as f:
            f.seek(start_offset)
            data = f.read()
    except OSError:
        return [], start_offset

    if not data:
        return [], start_offset

    lines = data.split(b"\n")
    if not data.endswith(b"\n"):
        incomplete = lines.pop()
        consumed = len(data) - len(incomplete)
    else:
        if lines and lines[-1] == b"":
            lines.pop()
        consumed = len(data)

    records: list[dict[str, Any]] = []
    for raw_line in lines:
        if not raw_line:
            continue
        try:
            records.append(json.loads(raw_line.decode("utf-8", "ignore")))
        except ValueError:
            continue
    return records, start_offset + consumed


def _flows_since_cursor(
    log_path: Path, since_cursor: int, generation: int
) -> tuple[list[dict[str, Any]], bool]:
    """Return (records with seq > since_cursor, whether the cache was hit).

    See the module docstring for the cache-hit/generation-mismatch rule.
    """
    cache_key = str(log_path)
    cached = _CURSOR_CACHE.get(cache_key)
    if cached is not None and cached[0] == since_cursor and cached[2] == generation:
        _, cached_offset, _ = cached
        new_records, new_offset = _read_records(log_path, cached_offset)
        candidates = [r for r in new_records if r.get("seq", 0) > since_cursor]
        last_seq = new_records[-1]["seq"] if new_records else since_cursor
        _CURSOR_CACHE[cache_key] = (last_seq, new_offset, generation)
        return candidates, True

    all_records, eof_offset = _read_records(log_path, 0)
    last_seq = all_records[-1]["seq"] if all_records else 0
    _CURSOR_CACHE[cache_key] = (last_seq, eof_offset, generation)
    candidates = [r for r in all_records if r.get("seq", 0) > since_cursor]
    return candidates, False


def _parse_time(value: str) -> float:
    """Parse an ISO 8601 (or otherwise dateutil-parseable) timestamp.

    Raises ``ValueError`` (dateutil's ``ParserError`` is a subclass) for an
    unparseable string -- callers (``ai/tools/flow_query.py``) turn that
    into a clean ``ToolExecutionError``.
    """
    return dateutil.parser.parse(value).timestamp()


def query_flows(
    flow_dir: Path,
    *,
    since_cursor: int | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 200,
    app_filter: str | None = None,
) -> dict[str, Any]:
    """Select a bounded slice of captured flows.

    Exactly one selection mode applies, in this precedence order:
    ``since_cursor`` (given -- ``0`` counts as given, unlike an omitted
    argument) > ``start_time``/``end_time`` (either given) > "most recent
    `limit` flows" (neither given).

    Args:
        flow_dir: The session's ``<raw_results>/mitm_flows`` directory (see
            :func:`resolve_flow_dir`).
        since_cursor: Return flows with ``seq`` greater than this value.
        start_time: ISO 8601 inclusive lower bound on ``ts_end``.
        end_time: ISO 8601 exclusive upper bound on ``ts_end``.
        limit: Max rows returned. Clamped to ``[1, HARD_LIMIT_CAP]``
            regardless of what is requested.
        app_filter: Only include flows whose ``app`` field equals this.

    Returns:
        ``{"flows": [...], "count", "next_cursor", "truncated",
        "earliest_available_seq", "gap_before_cursor", "mode"}``.
    """
    log_path = _log_path(flow_dir)
    meta = read_meta(flow_dir)
    earliest_seq = meta.get("earliest_seq")
    generation = meta.get("generation", 0)

    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 200
    limit = max(1, min(limit, HARD_LIMIT_CAP))

    if since_cursor is not None:
        mode = "since_cursor"
        candidates, _cache_hit = _flows_since_cursor(log_path, since_cursor, generation)
    elif start_time is not None or end_time is not None:
        mode = "time_range"
        start_epoch = _parse_time(start_time) if start_time is not None else None
        end_epoch = _parse_time(end_time) if end_time is not None else None
        all_records, _ = _read_records(log_path, 0)
        candidates = [
            r
            for r in all_records
            if (start_epoch is None or r.get("ts_end", 0) >= start_epoch)
            and (end_epoch is None or r.get("ts_end", 0) < end_epoch)
        ]
    else:
        mode = "last_n"
        candidates, _ = _read_records(log_path, 0)

    if app_filter is not None:
        filtered = [r for r in candidates if r.get("app") == app_filter]
    else:
        filtered = candidates

    total_matched = len(filtered)
    if mode == "last_n":
        result = filtered[-limit:]
    else:
        result = filtered[:limit]
    truncated = total_matched > limit

    if mode == "since_cursor":
        if truncated:
            next_cursor = result[-1]["seq"]
        else:
            # Not truncated: every candidate matching the cursor was
            # considered (app_filter only drops rows, never adds scan work),
            # so it's safe to advance all the way to the true high-water
            # mark of everything scanned -- this is what lets a repeat
            # since_cursor call hit the cache fast path even when filtering
            # by app.
            next_cursor = candidates[-1]["seq"] if candidates else since_cursor
    else:
        next_cursor = result[-1]["seq"] if result else meta.get("latest_seq", 0)

    gap_before_cursor = (
        mode == "since_cursor"
        and earliest_seq is not None
        and since_cursor is not None
        # since_cursor == earliest_seq - 1 means "everything from
        # earliest_seq onward" was asked for and all of it is present --
        # only a strictly smaller cursor actually skips over missing seqs.
        and since_cursor < earliest_seq - 1
    )

    return {
        "flows": result,
        "count": len(result),
        "next_cursor": next_cursor,
        "truncated": truncated,
        "earliest_available_seq": earliest_seq,
        "gap_before_cursor": gap_before_cursor,
        "mode": mode,
    }


def _further_truncate_body(body: dict[str, Any], max_body_bytes: int) -> dict[str, Any]:
    """Further-truncate an already-capped body; never retrieves more.

    ``max_body_bytes`` can only shrink what was captured at write time (see
    ``mitmproxy_service.py``'s ``_ADDON_SOURCE``) -- there is no later
    re-cap opportunity since the live flow object no longer exists.
    """
    bytes_read = body.get("bytes_read", 0)
    if max_body_bytes >= bytes_read:
        return body

    encoding = body.get("encoding", "utf-8")
    content = body.get("content", "")
    if encoding == "base64":
        raw = base64.b64decode(content)[:max_body_bytes]
        new_content = base64.b64encode(raw).decode("ascii")
        new_encoding = "base64"
    else:
        raw = content.encode("utf-8")[:max_body_bytes]
        try:
            new_content = raw.decode("utf-8")
            new_encoding = "utf-8"
        except UnicodeDecodeError:
            new_content = base64.b64encode(raw).decode("ascii")
            new_encoding = "base64"

    return {
        **body,
        "content": new_content,
        "encoding": new_encoding,
        "truncated": True,
        "bytes_read": len(raw),
    }


def read_flow_detail(
    flow_dir: Path,
    flow_id: str,
    *,
    part: str = "all",
    max_body_bytes: int | None = None,
) -> dict[str, Any] | None:
    """Read one flow's captured headers/body, optionally further-capped.

    Args:
        flow_dir: The session's ``mitm_flows`` directory.
        flow_id: The flow's ``id`` (from a ``query_flows`` record).
        part: One of ``all``/``request``/``response``/``request_headers``/
            ``response_headers``/``request_body``/``response_body``.
            Falls back to ``"all"`` for an unrecognized value.
        max_body_bytes: Further-truncate each body to at most this many
            bytes. ``None`` (the default) leaves bodies exactly as captured.

    Returns:
        The requested shape, or ``None`` if ``flow_id`` is unknown (never
        captured, its detail file was already dropped by retention, or it
        isn't a bare filename component -- see the confinement check below).
        Callers (``ai/tools/flow_query.py``) turn ``None`` into a clean
        ``ToolExecutionError`` rather than letting a raw file error leak.
    """
    # flow_id is caller-supplied (ultimately model-supplied) and gets joined
    # straight into a filesystem path -- unlike every other host-path-facing
    # tool, there is no resolve_confined_host_path() call here, since flow_id
    # is meant to be an opaque id, not a path. A bare filename component is
    # the only shape a real flow id (mitmproxy's UUID) ever has, so reject
    # anything else outright: Path(...).name strips any leading directory
    # part, so a value containing "/" or an absolute path never matches back
    # against the original string. The is_relative_to check is a second,
    # independent guard against the same class of escape.
    details_dir = _details_dir(flow_dir).resolve()
    if not flow_id or Path(flow_id).name != flow_id:
        return None
    detail_path = (details_dir / f"{flow_id}.json").resolve()
    if not detail_path.is_relative_to(details_dir):
        return None
    try:
        with open(detail_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None

    if max_body_bytes is not None:
        for key in ("request_body", "response_body"):
            body = data.get(key)
            if isinstance(body, dict):
                data[key] = _further_truncate_body(body, max_body_bytes)

    if part not in _DETAIL_PARTS:
        part = "all"
    if part == "all":
        return data
    if part == "request":
        return {
            "id": data.get("id"),
            "request_headers": data.get("request_headers", []),
            "request_body": data.get("request_body"),
        }
    if part == "response":
        return {
            "id": data.get("id"),
            "response_headers": data.get("response_headers", []),
            "response_body": data.get("response_body"),
            "error": data.get("error"),
        }
    return {"id": data.get("id"), part: data.get(part)}


def clear_flows(flow_dir: Path) -> int:
    """Delete every stored flow record, preserving ``latest_seq``.

    Deletes ``flows.jsonl`` and every ``details/*.json`` file, then rewrites
    ``meta.json`` with ``earliest_seq`` reset to ``None`` -- but
    ``latest_seq`` is deliberately left exactly as it was. That preserved
    value is what the addon's ``_resume_seq`` falls back to the next time it
    loads with no ``flows.jsonl`` tail to read, whether that's because
    mitmweb was restarted right after this clear or was never running
    during it. Resetting ``latest_seq`` here would let a stale cached
    ``since_cursor`` from before the clear collide with new post-clear
    flows.

    Returns:
        The number of flow records that were cleared (0 if none/missing).
    """
    log_path = _log_path(flow_dir)
    details_dir = _details_dir(flow_dir)

    records, _ = _read_records(log_path, 0)
    cleared_count = len(records)

    try:
        log_path.unlink(missing_ok=True)
    except OSError:
        logger.warning("Could not remove %s", log_path)

    if details_dir.is_dir():
        for detail_file in details_dir.glob("*.json"):
            try:
                detail_file.unlink()
            except OSError:
                logger.warning("Could not remove %s", detail_file)

    meta = read_meta(flow_dir)
    meta["earliest_seq"] = None
    _write_meta_atomic(flow_dir, meta)

    # The file this cache entry pointed at no longer exists (or was just
    # recreated at offset 0) -- a stale entry would otherwise wrongly report
    # a cache hit (generation is unchanged by a clear) and seek into
    # whatever gets written next.
    _CURSOR_CACHE.pop(str(log_path), None)

    return cleared_count


# --------------------------------------------------------------------------
# Run bundles: a run's own copy of its flows
# --------------------------------------------------------------------------

#: Name of the summary written next to a run's exported ``flows.jsonl``.
RUN_FLOWS_META = "meta.json"
#: At most this many flows are copied into one run bundle.
EXPORT_MAX_FLOWS = 5000
#: At most this many bytes of ``details/*.json`` are copied into one bundle
#: (each detail is already body-capped by the addon,
#: ``mitmproxy.max_captured_body_bytes``); later flows keep their row only.
EXPORT_MAX_DETAIL_BYTES = 64 * 1024 * 1024


def _record_time(rec: dict[str, Any], key: str) -> float | None:
    value = rec.get(key)
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def export_run_flows(
    flow_dir: Path | None,
    dest_dir: Path,
    start: float,
    end: float,
    phases: Any = (),
    *,
    mitm_running: bool | None = None,
    margin: float = 2.0,
    max_flows: int = EXPORT_MAX_FLOWS,
    max_detail_bytes: int = EXPORT_MAX_DETAIL_BYTES,
) -> dict[str, Any]:
    """Copy the flows of one run into its bundle (``<bundle>/network/``).

    The session's flow log (``<raw_results>/mitm_flows``) is per session; a
    run reviewed from a later session could not see its flows, and they were
    not covered by the run's ``SHA256SUMS``. At run finalisation (before the
    hash manifest is written) the records whose ``ts_end`` lies in
    ``[start - margin, end + margin]`` are written to
    ``dest_dir/flows.jsonl`` -- each tagged with the ``"phase"`` its
    ``ts_start`` falls in (``run_history.phase_of``: ``"replay N"``,
    ``"dry run"``, ``"setup"``) -- together with their ``details/<id>.json``
    (headers + already capped bodies). TLS failure records (``kind: "tls"``)
    are copied as well. ``meta.json`` summarises the export, also when no
    flow was captured, so REVIEW can say so instead of guessing.

    Bounded: at most ``max_flows`` rows and ``max_detail_bytes`` of detail
    files (``meta.json`` notes any truncation).

    Args:
        flow_dir: The session's ``mitm_flows`` directory (None: no flow log).
        dest_dir: Target folder inside the run bundle.
        start: Run start (epoch seconds).
        end: Run end (epoch seconds).
        phases: The run's phase windows (``RunRecord.phases``).
        mitm_running: Whether mitmproxy ran during the run (None: unknown).
        margin: Seconds added on both sides of the window.
        max_flows: Row cap.
        max_detail_bytes: Byte cap for copied detail files.

    Returns:
        The ``meta.json`` content.
    """
    import shutil

    from sandroid.core.run_history import phase_of

    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    lo, hi = start - margin, end + margin
    records: list[dict[str, Any]] = []
    log_present = False
    if flow_dir is not None and _log_path(flow_dir).is_file():
        log_present = True
        all_records, _ = _read_records(_log_path(flow_dir), 0)
        for rec in all_records:
            ts = _record_time(rec, "ts_end")
            if ts is None:
                ts = _record_time(rec, "ts_start")
            if ts is not None and lo <= ts <= hi:
                records.append(rec)
    truncated = len(records) > max_flows
    records = records[:max_flows]

    per_phase: dict[str, int] = {}
    detail_bytes = 0
    details_skipped = 0
    details_src = _details_dir(flow_dir).resolve() if flow_dir is not None else None
    details_dst = dest_dir / "details"
    with open(_log_path(dest_dir), "w", encoding="utf-8") as out:
        for rec in records:
            ts = _record_time(rec, "ts_start") or _record_time(rec, "ts_end")
            phase = phase_of(ts, phases)
            row = {**rec, "phase": phase} if phase else dict(rec)
            per_phase[phase or "unknown"] = per_phase.get(phase or "unknown", 0) + 1
            out.write(json.dumps(row, default=str) + "\n")
            flow_id = rec.get("id")
            if (
                details_src is None
                or rec.get("kind") == "tls"
                or not isinstance(flow_id, str)
                or not flow_id
                or Path(flow_id).name != flow_id
            ):
                continue
            src = (details_src / f"{flow_id}.json").resolve()
            if not src.is_relative_to(details_src) or not src.is_file():
                continue
            try:
                size = src.stat().st_size
            except OSError:
                continue
            if detail_bytes + size > max_detail_bytes:
                details_skipped += 1
                continue
            details_dst.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copyfile(src, details_dst / src.name)
                detail_bytes += size
            except OSError:
                details_skipped += 1

    meta = {
        "schema": "sandroid-run-flows/1",
        "source": str(flow_dir) if flow_dir is not None else None,
        "flow_log_present": log_present,
        "mitm_running": mitm_running,
        "window": [lo, hi],
        "count": len(records),
        "truncated": truncated,
        "per_phase": per_phase,
        "details_bytes": detail_bytes,
        "details_skipped": details_skipped,
    }
    with open(dest_dir / RUN_FLOWS_META, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return meta


def read_run_flows(
    bundle_network_dir: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]] | None:
    """``(records, meta)`` stored in a run bundle, or None (none stored).

    ``records`` are capped at :data:`HARD_LIMIT_CAP` (newest kept), like any
    other query.
    """
    meta_path = Path(bundle_network_dir) / RUN_FLOWS_META
    if not meta_path.is_file():
        return None
    try:
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, ValueError):
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    records, _ = _read_records(_log_path(Path(bundle_network_dir)), 0)
    return records[-HARD_LIMIT_CAP:], meta


__all__ = [
    "EXPORT_MAX_FLOWS",
    "HARD_LIMIT_CAP",
    "RUN_FLOWS_META",
    "clear_flows",
    "export_run_flows",
    "query_flows",
    "read_flow_detail",
    "read_meta",
    "read_run_flows",
    "resolve_flow_dir",
]
