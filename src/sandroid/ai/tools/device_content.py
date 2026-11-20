"""AI-chat tool ``read_device_files``: read Files lens rows' content off the device.

Toolset ``lenses``. The Files lens tools (``find_rows`` ``content_contains``,
``classify_rows``, ``get_rows``) only see local content: a kept watchlist
version or what this tool read. It selects rows exactly like ``find_rows``
(``where``, ``scope``, ``keys``), reads each file from the ONE device it
pinned at the start (:mod:`sandroid.ai.device_files`) and caches the result
in ``<session>/ai/content_cache/``. It returns counts, never content: the
content reaches the model only through the Files digests (reduced, capped).

``REVERSIBLE`` with ``can_remember_choice``: it pulls app-private data to show
it to a remote model, so the analyst approves it (once, or "allow always"),
like ``pull_path``. It claims no device lease and writes nothing on the
device or in the watchlist; while a WORLD lease is held (snapshot restore,
emulator restart) it answers ``busy``.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from sandroid.ai.tools.registry import RiskTier, ToolError, sandroid_tool

logger = logging.getLogger(__name__)

MAX_KEYS = 500
DEFAULT_MAX_FILES = 100
MAX_FILES = 300
DEFAULT_TOTAL_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
#: Keys listed in a result.
MAX_KEYS_READ = 50
MAX_SKIPPED_KEYS = 10
SQLITE_MODES = ("sample", "tables", "skip")
SKIP_REASONS = (
    "binary",
    "too_big",
    "permission_denied",
    "gone",
    "not_regular",
    "review_row",
    "budget",
    "sqlite_skipped",
    "cancelled",
    "error",
)


def _audit(summary: str, data: dict) -> None:
    """One ``ai/files_read`` line on the session timeline."""
    try:
        from sandroid.core import timeline

        timeline.emit("ai", "files_read", summary=summary, actor="ai", data=data)
    except Exception:
        logger.debug("files_read timeline line failed", exc_info=True)


def _int_arg(value: Any, name: str, default: int, low: int, high: int) -> int:
    from sandroid.ai.tools.lens_rows import _invalid

    if value is None:
        return default
    try:
        value = int(value)
    except (TypeError, ValueError) as exc:
        raise _invalid(f"{name} must be an integer") from exc
    if not low <= value <= high:
        raise _invalid(f"{name} must be between {low} and {high}")
    return value


def _watchlist_fresh(path: str, row_last: Any) -> bool:
    """A kept watchlist version at least as new as the row's last write."""
    try:
        from sandroid.core import watchlist_store

        versions = watchlist_store.version_dirs(path)
        if not versions:
            return False
        when = watchlist_store.version_time(versions[-1])
    except Exception:
        return False
    from sandroid.ai.device_files import _as_float

    last = _as_float(row_last)
    if last is None:
        return True
    return when is not None and when.timestamp() >= last


_DESCRIPTION = (
    "Read the content of Files lens rows from the device into the session's "
    "local content cache, so find_rows content_contains, classify_rows and "
    "get_rows can use it (they never read the device themselves). Select rows "
    "like find_rows: where (same fields), scope, or keys. Reads text heads "
    "(64 KB per file by default), decodes gzip/ABX/prefs/JSON and samples "
    "SQLite databases (<=16 MB with their WAL); binary files keep only their "
    "size and type. Review rows are skipped. Returns counts (read, cached, "
    "skipped by reason), never content. Ctrl+X stops it (partial; what was "
    "read stays cached)."
)


@sandroid_tool(
    name="read_device_files",
    description=_DESCRIPTION,
    parameters={
        "type": "object",
        "properties": {
            "keys": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Only these Files row keys (device paths), <=500.",
            },
            "where": {
                "type": "object",
                "description": (
                    "Row filter, the same fields as find_rows on the files "
                    "lens: path_glob[], ops, process, app, watched, "
                    "min_count, text, content_contains, regex."
                ),
            },
            "scope": {
                "type": "string",
                "enum": ["shown", "all"],
                "description": (
                    "shown (default): the rows the Files lens shows; all: "
                    "also the rows its filters hide."
                ),
                "default": "shown",
            },
            "only_missing": {
                "type": "boolean",
                "description": (
                    "Skip files whose kept watchlist version is as new as the "
                    "row's last write (default true). Valid cache entries "
                    "(same device mtime and size) are never read again "
                    "unless refresh."
                ),
                "default": True,
            },
            "max_files": {
                "type": "integer",
                "description": "Device reads at most (default 100, <=300).",
                "default": DEFAULT_MAX_FILES,
            },
            "max_bytes_per_file": {
                "type": "integer",
                "description": "Bytes per text file (default 65536, <=1048576).",
                "default": 65536,
            },
            "max_total_bytes": {
                "type": "integer",
                "description": "Device bytes in all (default 8 MB, <=32 MB).",
                "default": DEFAULT_TOTAL_BYTES,
            },
            "sqlite": {
                "type": "string",
                "enum": list(SQLITE_MODES),
                "description": (
                    "sample (default): tables, row counts and 3 sample rows "
                    "of up to 10 tables; tables: names and counts; skip."
                ),
                "default": "sample",
            },
            "refresh": {
                "type": "boolean",
                "description": "Read again even when the cache is valid.",
                "default": False,
            },
        },
    },
    risk=RiskTier.REVERSIBLE,
    category="lens_rows",
    can_remember_choice=True,
)
def read_device_files(
    keys: list[str] | None = None,
    where: dict | None = None,
    scope: str = "shown",
    only_missing: bool = True,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes_per_file: int = 65536,
    max_total_bytes: int = DEFAULT_TOTAL_BYTES,
    sqlite: str = "sample",
    refresh: bool = False,
) -> dict[str, Any]:
    """Read Files rows' content from the device; see the tool description."""
    from sandroid.ai import device_files as df
    from sandroid.ai.loop import (
        current_run_context,
        report_tool_progress,
        tool_time_remaining,
    )
    from sandroid.ai.tools.lens_rows import (
        _as_list,
        _check_scope,
        _collect,
        _Details,
        _filter,
        _invalid,
        _scoped,
        compile_where,
    )
    from sandroid.services.row_highlights import normalize_key

    scope = _check_scope(scope)
    max_files = _int_arg(max_files, "max_files", DEFAULT_MAX_FILES, 1, MAX_FILES)
    per_file = _int_arg(
        max_bytes_per_file,
        "max_bytes_per_file",
        df.DEFAULT_BYTES_PER_FILE,
        1,
        df.MAX_BYTES_PER_FILE,
    )
    total_cap = _int_arg(
        max_total_bytes, "max_total_bytes", DEFAULT_TOTAL_BYTES, 1, MAX_TOTAL_BYTES
    )
    if sqlite not in SQLITE_MODES:
        raise _invalid(f"sqlite must be one of {', '.join(SQLITE_MODES)}")
    if where is not None and not isinstance(where, dict):
        raise _invalid("where must be an object")
    key_list = [normalize_key("files", k) for k in _as_list(keys)]
    if len(key_list) > MAX_KEYS:
        raise _invalid(f"at most {MAX_KEYS} keys")

    if df.world_busy():
        raise ToolError(
            "busy",
            "a snapshot restore or emulator restart is running; the device "
            "cannot be read now",
            retryable=True,
            hint="Try again when it has finished.",
        )
    root = df.cache_root()
    if root is None:
        raise ToolError(
            "tool_failed",
            "no analysis session is open, so there is nowhere to keep the content",
            hint="Open or start a session first.",
        )

    preds, where_summary = compile_where("files", where, _Details())
    got = _collect("files")
    rows = _scoped(got.rows, scope)
    unknown: list[str] = []
    if key_list:
        by_key = {r["key"]: r for r in rows}
        unknown = [k for k in key_list if k not in by_key]
        rows = [by_key[k] for k in dict.fromkeys(key_list) if k in by_key]
    matched = _filter(rows, preds)

    skipped = dict.fromkeys(SKIP_REASONS, 0)
    skipped_keys: dict[str, list[str]] = {}

    def skip(reason: str, key: str) -> None:
        skipped[reason] += 1
        listed = skipped_keys.setdefault(reason, [])
        if len(listed) < MAX_SKIPPED_KEYS:
            listed.append(key)

    candidates = []
    for row in matched:
        if row.get("scope") is not None:
            skip("review_row", row["key"])
        else:
            candidates.append(row)

    result: dict[str, Any] = {
        "serial": None,
        "candidates": len(matched),
        "read": 0,
        "cached": 0,
        "bytes_read": 0,
        "partial": False,
        "stop_reason": None,
    }
    if where_summary:
        result["where"] = where_summary
    if unknown:
        result["unknown_keys"] = unknown[:MAX_SKIPPED_KEYS]
    keys_read: list[str] = []

    if candidates:
        serial = df.current_serial()
        if not serial:
            raise ToolError(
                "no_device",
                "no device is selected, so there is nothing to read from",
                hint="Select a device (or start the file monitor) first.",
            )
        result["serial"] = serial
        ctx = current_run_context()
        cancel = getattr(ctx, "cancel_event", None)
        left = tool_time_remaining()
        deadline = (
            None
            if left is None
            else time.monotonic() + max(0.0, left - df.DEADLINE_MARGIN_S)
        )

        def should_stop() -> str | None:
            if cancel is not None and cancel.is_set():
                return "cancelled"
            if deadline is not None and time.monotonic() > deadline:
                return "deadline"
            return None

        _read_rows(
            df.DeviceFileReader(serial, should_stop=should_stop),
            root,
            candidates,
            result,
            skip,
            keys_read,
            should_stop=should_stop,
            progress=report_tool_progress,
            only_missing=bool(only_missing),
            refresh=bool(refresh),
            max_files=max_files,
            per_file=per_file,
            total_cap=total_cap,
            sqlite=sqlite,
        )
        try:
            df.evict(root)
        except Exception:
            logger.debug("content cache eviction failed", exc_info=True)

    if skipped["budget"] and result["stop_reason"] is None:
        result["stop_reason"] = "budget"
    result["partial"] = result["stop_reason"] is not None
    result["skipped"] = skipped
    result["keys_read"] = keys_read[:MAX_KEYS_READ]
    if len(keys_read) > MAX_KEYS_READ:
        result["keys_read_truncated"] = len(keys_read) - MAX_KEYS_READ
    result["skipped_keys"] = skipped_keys
    noted = ", ".join(f"{k} {v}" for k, v in skipped.items() if v)
    on = f" from {result['serial']}" if result["serial"] else ""
    summary = (
        f"Read {result['read']} of {len(matched)} files{on} "
        f"({result['cached']} already local"
        + (f"; skipped: {noted}" if noted else "")
        + (f"; stopped early: {result['stop_reason']}" if result["partial"] else "")
        + ")"
    )
    if result["read"] or result["cached"]:
        summary += "; find_rows content_contains / classify_rows now see them"
    result = {"summary": summary, **result}
    _audit(
        summary + (f": {where_summary}" if where_summary else ""),
        {
            "serial": result["serial"],
            "where": where_summary,
            "keys": len(key_list),
            "candidates": len(matched),
            "read": result["read"],
            "cached": result["cached"],
            "bytes_read": result["bytes_read"],
            "skipped": {k: v for k, v in skipped.items() if v},
            "partial": result["partial"],
            "stop_reason": result["stop_reason"],
        },
    )
    return result


def _is_local(entry: Any, serial: str, st: Any, last: Any, only_missing: bool) -> bool:
    """A valid cache entry (same device mtime/size/serial, no later write),
    or with *only_missing* a kept watchlist version as new as the row.
    """
    if entry is not None and entry.valid(
        row_last=last, serial=serial, mtime=st.mtime, size=st.size
    ):
        return True
    return only_missing and _watchlist_fresh(st.path, last)


def _read_rows(
    reader: Any,
    root: Any,
    candidates: list[dict],
    result: dict[str, Any],
    skip: Any,
    keys_read: list[str],
    *,
    should_stop: Any,
    progress: Any,
    only_missing: bool,
    refresh: bool,
    max_files: int,
    per_file: int,
    total_cap: int,
    sqlite: str,
) -> None:
    """Stat every candidate once, then read them one by one (in place)."""
    from sandroid.ai import device_files as df

    total = len(candidates)
    progress(0, total, note="reading", force=True)
    paths = [str(r["key"]) for r in candidates]
    wals = [p + "-wal" for p in paths if df.is_db_name(p)]
    stats = reader.stat(paths + wals)
    reads = 0
    for i, row in enumerate(candidates):
        path = str(row["key"])
        stop = should_stop()
        if stop:
            result["stop_reason"] = stop
            for rest in candidates[i:]:
                skip("cancelled", str(rest["key"]))
            break
        st = stats.get(path) or df.Stat(path, error="error")
        if st.error:
            skip(st.error, path)
        elif not st.regular:
            skip("not_regular", path)
        else:
            last = row.get("last")
            if not refresh and _is_local(
                df.load_entry(path, root), reader.serial, st, last, only_missing
            ):
                result["cached"] += 1
            elif reads >= max_files:
                skip("budget", path)
                result["stop_reason"] = "max_files"
            else:
                wal = stats.get(path + "-wal")
                need = df.expected_bytes(path, st, wal, per_file)
                left = total_cap - result["bytes_read"]
                if need > left:
                    skip("budget", path)
                else:
                    try:
                        outcome = df.read_into_cache(
                            reader,
                            root,
                            path,
                            st,
                            wal=wal,
                            row_last=last,
                            cap=per_file,
                            sqlite=sqlite,
                            budget_left=left,
                        )
                    except Exception:
                        logger.warning("reading %s failed", path, exc_info=True)
                        outcome = df.FileOutcome("error")
                    reads += 1
                    result["bytes_read"] += outcome.bytes_read
                    if outcome.status == "read":
                        result["read"] += 1
                        keys_read.append(path)
                    elif outcome.status in ("cancelled", "deadline"):
                        result["stop_reason"] = outcome.status
                        for rest in candidates[i:]:
                            skip("cancelled", str(rest["key"]))
                        break
                    else:
                        skip(outcome.status, path)
        progress(i + 1, total, note="reading")
    progress(total, total, note="read", force=True)


__all__ = ["read_device_files"]
