"""Tool-result store (R-ids) and model-facing result shaping.

Every tool result is stored in full as ``<session>/ai/results/R<n>.json``
(``{id, tool, args, agent_id, ts, sha256, bytes, result}``) and the model sees
a capped view of it:

- at or below the ingest cap (``ai.context.result_cap_tokens``, default 8000
  tokens) the result itself plus ``"_rid": "R17"``;
- above it, a *selected preview*: head and tail of the text, hits for
  keywords/errors/IOCs/package names, and the structure (type, row count,
  keys/columns, top grouped counts), always with
  ``{"truncated": true, "result_id": ..., "bytes": ..., "hint": ...}``.

A per-turn budget (``ai.context.turn_result_budget_tokens``, default 25000)
limits the result tokens one assistant message's calls may add; past it,
results come back as a compact preview.

R-ids are session-global (subagents share the store). With no analysis session
the store keeps records in memory only. Directories are created lazily on the
first write (mode 0700, files 0600), so an unused session folder can still be
discarded.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import math
import os
import re
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

#: Characters per token used for every local estimate.
CHARS_PER_TOKEN = 3.5

#: Default ingest cap, tokens (``ai.context.result_cap_tokens``).
DEFAULT_RESULT_CAP_TOKENS = 8000

#: Default per-assistant-message result budget, tokens.
DEFAULT_TURN_RESULT_BUDGET_TOKENS = 25000

#: Size of the compact preview used once the turn budget is spent, tokens.
COMPACT_PREVIEW_TOKENS = 600

#: Results up to this size are always inlined (a preview would be larger).
SMALL_RESULT_TOKENS = 200

_RID_RE = re.compile(r"^R([1-9][0-9]*)$")
_RID_FILE_RE = re.compile(r"^R([1-9][0-9]*)\.json$")


def estimate_tokens(text: str) -> int:
    """Estimate the token count of *text* (``chars / 3.5``, rounded up)."""
    return math.ceil(len(text) / CHARS_PER_TOKEN)


def _tokens_to_chars(tokens: float) -> int:
    return max(0, int(tokens * CHARS_PER_TOKEN))


def _ai_context_setting(name: str, default: int) -> int:
    """Read ``ai.context.<name>`` (or ``ai.<name>``) from config, else *default*."""
    try:
        from sandroid.config import get_config

        ai = get_config().ai
    except Exception:
        return default
    for holder in (getattr(ai, "context", None), ai):
        value = getattr(holder, name, None) if holder is not None else None
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return default


def result_cap_tokens() -> int:
    """Return the configured ingest cap in tokens (default 8000)."""
    return _ai_context_setting("result_cap_tokens", DEFAULT_RESULT_CAP_TOKENS)


def turn_result_budget_tokens() -> int:
    """Return the configured per-turn result budget in tokens (default 25000)."""
    return _ai_context_setting(
        "turn_result_budget_tokens", DEFAULT_TURN_RESULT_BUDGET_TOKENS
    )


# ---------------------------------------------------------------------------
# Session root
# ---------------------------------------------------------------------------


def session_root() -> Path | None:
    """Return the analysis-session folder the AI files live under, or ``None``.

    Uses ``SessionPaths.session_path`` from the initialization service, which
    survives device switches. Callers fix the value when a thread opens and
    pass it on; ``None`` means in-memory mode (no files). Nothing is created
    here.
    """
    try:
        from sandroid.services import get_initialization_service

        session = get_initialization_service().get_current_session()
    except Exception:
        logger.debug("ai.results: no initialization service", exc_info=True)
        return None
    path = getattr(session, "session_path", None) if session else None
    if not path:
        return None
    return Path(path).expanduser().absolute()


def ensure_private_dir(path: Path) -> Path:
    """Create *path* (and parents) and force mode 0700 on the created leaves.

    Args:
        path: Directory to create.

    Returns:
        *path*.
    """
    missing: list[Path] = []
    probe = path
    while not probe.exists():
        missing.append(probe)
        if probe.parent == probe:
            break
        probe = probe.parent
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    for created in missing:
        with contextlib.suppress(OSError):
            created.chmod(0o700)
    return path


def result_text(result: Any) -> str:
    """Canonical full text of a result (what ``read_result`` pages through).

    Strings are kept as is; anything else is indented JSON (``default=str``).
    """
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, indent=1, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(result)


# ---------------------------------------------------------------------------
# Result store
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StoredResult:
    """What :meth:`ResultStore.put` returns.

    Attributes:
        id: The R-id (``"R17"``).
        bytes: UTF-8 size of the canonical result text.
        sha256: Hex digest of the canonical result text.
        path: File the record was written to (``None`` in memory mode).
    """

    id: str
    bytes: int
    sha256: str
    path: Path | None = None


class ResultStore:
    """Session-global store of full tool results, addressed by R-id.

    Thread-safe. Records are written once with ``O_EXCL`` (never overwritten);
    on reopen the counter continues at ``max(existing) + 1``. With
    ``root=None`` records live in memory only.
    """

    def __init__(self, root: Path | None) -> None:
        """Create a store under ``<root>/ai/results`` (``None``: in memory).

        Args:
            root: Session root as returned by :func:`session_root`, fixed when
                the thread opened.
        """
        self.root = Path(root) if root is not None else None
        self._lock = threading.Lock()
        self._memory: dict[str, dict] = {}
        self._next = self._scan_next()

    @property
    def persistent(self) -> bool:
        """Whether records are written to disk."""
        return self.root is not None

    @property
    def results_dir(self) -> Path | None:
        """``<root>/ai/results`` (may not exist yet), or ``None``."""
        return self.root / "ai" / "results" if self.root is not None else None

    def _scan_next(self) -> int:
        folder = self.results_dir
        highest = 0
        if folder is not None and folder.is_dir():
            for entry in folder.iterdir():
                m = _RID_FILE_RE.match(entry.name)
                if m:
                    highest = max(highest, int(m.group(1)))
        return highest + 1

    def put(
        self,
        tool: str,
        args: Any,
        result: Any,
        *,
        agent_id: str | None = None,
    ) -> StoredResult:
        """Store a full result and return its new R-id.

        Args:
            tool: Tool name (the inner name for ``call_tool``).
            args: The validated arguments.
            result: The tool's return value (anything JSON-able via
                ``default=str``).
            agent_id: Owner agent (``"orchestrator"`` or a subagent id).

        Returns:
            The :class:`StoredResult`.
        """
        text = result_text(result)
        raw = text.encode("utf-8", errors="replace")
        digest = hashlib.sha256(raw).hexdigest()
        record = {
            "id": "",
            "tool": tool,
            "args": args,
            "agent_id": agent_id,
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "sha256": digest,
            "bytes": len(raw),
            "result": result,
        }
        with self._lock:
            if self.results_dir is None:
                rid = f"R{self._next}"
                self._next += 1
                record["id"] = rid
                self._memory[rid] = record
                return StoredResult(rid, len(raw), digest)
            folder = ensure_private_dir(self.results_dir)
            while True:
                rid = f"R{self._next}"
                self._next += 1
                record["id"] = rid
                path = folder / f"{rid}.json"
                try:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    continue  # another store/process took it; try the next id
                break
        payload = json.dumps(record, ensure_ascii=False, default=str)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        return StoredResult(rid, len(raw), digest, path)

    def get(self, rid: str) -> dict | None:
        """Return the full record for *rid*, or ``None`` if unknown."""
        if not isinstance(rid, str) or not _RID_RE.match(rid.strip()):
            return None
        rid = rid.strip()
        with self._lock:
            if rid in self._memory:
                return self._memory[rid]
        folder = self.results_dir
        if folder is None:
            return None
        try:
            return json.loads((folder / f"{rid}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def ids(self) -> list[str]:
        """Return every stored R-id, ascending."""
        with self._lock:
            found = set(self._memory)
        folder = self.results_dir
        if folder is not None and folder.is_dir():
            for entry in folder.iterdir():
                if _RID_FILE_RE.match(entry.name):
                    found.add(entry.name[:-5])
        return sorted(found, key=lambda r: int(r[1:]))


_stores: dict[str, ResultStore] = {}
_stores_lock = threading.Lock()


def get_result_store(root: Path | None) -> ResultStore:
    """Return the shared store for a session root (one per root per process).

    Subagents and the main thread of the same session therefore share R-ids.
    ``None`` gives the process-wide in-memory store.
    """
    key = str(Path(root).absolute()) if root is not None else ""
    with _stores_lock:
        store = _stores.get(key)
        if store is None:
            store = ResultStore(Path(key) if key else None)
            _stores[key] = store
        return store


def reset_for_tests() -> None:
    """Forget every cached store (test isolation)."""
    with _stores_lock:
        _stores.clear()


# ---------------------------------------------------------------------------
# Shaping
# ---------------------------------------------------------------------------


class TurnBudget:
    """Result-token budget for one assistant message's tool calls."""

    def __init__(self, total_tokens: int | None = None) -> None:
        """Create a budget (default: the configured per-turn budget)."""
        self.total = (
            total_tokens if total_tokens is not None else turn_result_budget_tokens()
        )
        self.spent = 0
        self._lock = threading.Lock()

    @property
    def remaining(self) -> int:
        """Tokens still available this turn."""
        return max(0, self.total - self.spent)

    def consume(self, tokens: int) -> None:
        """Record *tokens* as spent."""
        with self._lock:
            self.spent += max(0, tokens)


_ERROR_RE = re.compile(
    r"\b(error|errors|exception|failed|failure|fatal|denied|crash(?:ed)?|"
    r"traceback|refused|timeout|timed out|warning)\b",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>\\]+")
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_PACKAGE_RE = re.compile(r"\b[a-z][a-z0-9_]*(?:\.[a-zA-Z0-9_]+){2,}\b")
_MAX_WALK_LINES = 200_000
_MAX_GROUP_ROWS = 50_000
_LINE_CHARS = 240


def _flatten_lines(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(location, text)`` lines of a result, strings split per line."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _flatten_lines(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list | tuple):
        for i, item in enumerate(value):
            yield from _flatten_lines(item, f"{path}[{i}]")
    elif isinstance(value, str):
        lines = value.splitlines() or [""]
        if len(lines) == 1:
            yield path, lines[0]
        else:
            for n, line in enumerate(lines, 1):
                yield f"{path}:{n}" if path else f"line {n}", line
    else:
        yield path, str(value)


def iter_result_lines(result: Any) -> Iterator[tuple[str, str]]:
    """Yield at most 200k ``(location, text)`` lines of *result*."""
    for count, item in enumerate(_flatten_lines(result)):
        if count >= _MAX_WALK_LINES:
            return
        yield item


def _clip(text: str, limit: int = _LINE_CHARS) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _type_name(value: Any) -> str:
    if isinstance(value, dict):
        return f"object[{len(value)} keys]"
    if isinstance(value, list | tuple):
        return f"array[{len(value)}]"
    if isinstance(value, str):
        return f"string[{len(value)} chars]"
    if value is None:
        return "null"
    return type(value).__name__


def _groupable(value: Any) -> bool:
    return isinstance(value, str | int | bool) and value != ""


def _rows_summary(rows: list, max_columns: int = 8) -> dict:
    """Row count, columns and top grouped counts of a list of rows.

    Columns and grouping candidates come from the first 500 rows (a column
    whose sampled values are all distinct, e.g. ids or timestamps, is not a
    grouping); the counts then cover up to 50,000 rows.
    """
    summary: dict[str, Any] = {"rows": len(rows)}
    sample = [r for r in rows[:500] if isinstance(r, dict)]
    if not sample:
        kinds = Counter(_type_name(r).split("[")[0] for r in rows[:500])
        summary["item_types"] = dict(kinds.most_common(5))
        return summary
    columns = Counter(k for r in sample for k in r)
    summary["columns"] = [k for k, _ in columns.most_common(40)]
    candidates = []
    for column, _ in columns.most_common():
        values = [r[column] for r in sample if _groupable(r.get(column))]
        distinct = len({_clip(str(v), 80) for v in values})
        if len(values) >= 2 and distinct < len(values) and distinct <= 50:
            candidates.append(column)
        if len(candidates) >= max_columns:
            break
    if not candidates:
        return summary
    counted = rows[:_MAX_GROUP_ROWS]
    groups: dict[str, list] = {}
    for column in candidates:
        counts = Counter(
            _clip(str(r[column]), 80)
            for r in counted
            if isinstance(r, dict) and _groupable(r.get(column))
        )
        groups[column] = [[v, n] for v, n in counts.most_common(5)]
        groups[column].append(["(distinct)", len(counts)])
    summary["top_values"] = groups
    if len(counted) < len(rows):
        summary["top_values_rows"] = len(counted)
    return summary


def describe_structure(result: Any) -> dict:
    """Return a compact structural summary of *result*.

    Type, key listing with value types/sizes (objects), row count, columns and
    top-N grouped counts (lists, and the largest list inside an object), line
    count (strings).
    """
    info: dict[str, Any] = {"type": _type_name(result)}
    if isinstance(result, str):
        info["lines"] = result.count("\n") + 1
    elif isinstance(result, list | tuple):
        info.update(_rows_summary(list(result)))
    elif isinstance(result, dict):
        keys: dict[str, Any] = {}
        for key, value in list(result.items())[:60]:
            if isinstance(value, str) and len(value) > 120:
                keys[str(key)] = _type_name(value)
            elif isinstance(value, str | int | float | bool) or value is None:
                keys[str(key)] = value
            else:
                keys[str(key)] = _type_name(value)
        info["keys"] = keys
        lists = [(k, v) for k, v in result.items() if isinstance(v, list | tuple) and v]
        if lists:
            key, rows = max(lists, key=lambda kv: len(kv[1]))
            info["largest_array"] = {"key": str(key), **_rows_summary(list(rows))}
    return info


def find_hits(
    result: Any,
    keywords: Iterable[str] = (),
    *,
    max_lines: int = 12,
    max_items: int = 20,
) -> dict:
    """Collect keyword/error lines and unique URLs, IPs and package names."""
    words = [w.lower() for w in keywords if w and w.strip()]
    keyword_lines: list[str] = []
    error_lines: list[str] = []
    urls: dict[str, None] = {}
    ips: dict[str, None] = {}
    packages: dict[str, None] = {}
    for location, line in iter_result_lines(result):
        if not line:
            continue
        lowered = line.lower()
        entry = f"{location}: {_clip(line)}" if location else _clip(line)
        if (
            words
            and len(keyword_lines) < max_lines
            and any(w in lowered for w in words)
        ):
            keyword_lines.append(entry)
        elif len(error_lines) < max_lines and _ERROR_RE.search(line):
            error_lines.append(entry)
        if len(urls) < max_items:
            for m in _URL_RE.findall(line):
                urls.setdefault(_clip(m, 200), None)
        if len(ips) < max_items:
            for m in _IPV4_RE.findall(line):
                ips.setdefault(m, None)
        if len(packages) < max_items and "." in line:
            for m in _PACKAGE_RE.findall(line):
                if not m[-1].isdigit():
                    packages.setdefault(m, None)
    hits: dict[str, Any] = {}
    for name, values in (
        ("keyword_lines", keyword_lines),
        ("error_lines", error_lines),
        ("urls", list(urls)[:max_items]),
        ("ips", list(ips)[:max_items]),
        ("packages", list(packages)[:max_items]),
    ):
        if values:
            hits[name] = values
    return hits


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _hint(rid: str) -> str:
    return (
        f"Full result stored as {rid}. Use read_result('{rid}', grep='<regex>') "
        f"to search it or read_result('{rid}', offset=<n>) to page through it."
    )


def build_preview(
    result: Any,
    rid: str,
    *,
    cap_tokens: int,
    keywords: Iterable[str] = (),
    compact: bool = False,
    reason: str | None = None,
) -> dict:
    """Build the selected preview of an oversized result.

    Budget split (scaled to *cap_tokens*): head ~19% (1.5k of 8k), tail ~25%
    (2k of 8k), hits and structure the rest. The serialised preview is
    shrunk until it fits *cap_tokens*.

    Args:
        result: The full result.
        rid: Its R-id.
        cap_tokens: Upper bound for the serialised preview.
        keywords: Extra terms whose lines are surfaced (e.g. the target
            package).
        compact: Head, structure and a few hits only (turn budget spent).
        reason: Optional explanation added to the preview.

    Returns:
        The preview dict (always contains ``truncated``, ``result_id``,
        ``bytes`` and ``hint``).
    """
    text = result_text(result)
    size = len(text.encode("utf-8", errors="replace"))
    if compact:
        head_chars, tail_chars, max_lines, max_items = (
            _tokens_to_chars(min(cap_tokens, COMPACT_PREVIEW_TOKENS) * 0.4),
            0,
            3,
            5,
        )
    else:
        head_chars = _tokens_to_chars(cap_tokens * 0.19)
        tail_chars = _tokens_to_chars(cap_tokens * 0.25)
        max_lines, max_items = 12, 20
    preview: dict[str, Any] = {
        "truncated": True,
        "result_id": rid,
        "bytes": size,
        "est_tokens": estimate_tokens(text),
        "structure": describe_structure(result),
        "hits": find_hits(result, keywords, max_lines=max_lines, max_items=max_items),
        "head": text[:head_chars],
    }
    if tail_chars and len(text) > head_chars:
        preview["tail"] = text[max(head_chars, len(text) - tail_chars) :]
    if reason:
        preview["reason"] = reason
    preview["hint"] = _hint(rid)
    limit = min(cap_tokens, COMPACT_PREVIEW_TOKENS) if compact else cap_tokens
    return _fit(preview, limit)


def _fit(preview: dict, cap_tokens: int) -> dict:
    """Shrink *preview* step by step until it serialises within *cap_tokens*."""
    for _ in range(12):
        if estimate_tokens(_dumps(preview)) <= cap_tokens:
            return preview
        hits = preview.get("hits") or {}
        longest = max(hits, key=lambda k: len(_dumps(hits[k])), default=None)
        if longest is not None and len(hits[longest]) > 2:
            hits[longest] = hits[longest][: len(hits[longest]) // 2]
            continue
        structure = preview.get("structure") or {}
        for key in ("keys", "largest_array", "top_values", "columns"):
            if key in structure:
                structure.pop(key)
                break
        else:
            for part in ("tail", "head"):
                if preview.get(part):
                    preview[part] = preview[part][: len(preview[part]) // 2]
            preview["hits"] = {}
    return preview


def shape_result(
    result: Any,
    rid: str,
    *,
    cap_tokens: int | None = None,
    budget: TurnBudget | None = None,
    keywords: Iterable[str] = (),
) -> str:
    """Return the model-facing tool-result content for a stored result.

    Args:
        result: The full result (already stored under *rid*).
        rid: Its R-id.
        cap_tokens: Ingest cap (default: configured, 8000).
        budget: Per-turn budget; consumed by what is returned. Once the
            remaining budget cannot take the full result or preview, a
            compact preview is returned instead.
        keywords: Extra terms surfaced in previews.

    Returns:
        A JSON string: the result plus ``"_rid"`` (objects) or
        ``{"result": ..., "_rid": ...}`` (anything else) when small enough,
        otherwise a preview from :func:`build_preview`.
    """
    cap = cap_tokens if cap_tokens is not None else result_cap_tokens()
    available = budget.remaining if budget is not None else math.inf
    if isinstance(result, dict) and "_rid" not in result:
        inline: Any = {**result, "_rid": rid}
    else:
        inline = {"result": result, "_rid": rid}
    content = _dumps(inline)
    tokens = estimate_tokens(content)
    # A tiny result is cheaper than any preview of it, budget or not.
    fits_budget = tokens <= available or tokens <= SMALL_RESULT_TOKENS
    if tokens > cap or not fits_budget:
        over_budget = tokens <= cap
        preview = None
        if not over_budget:
            preview = build_preview(result, rid, cap_tokens=cap, keywords=keywords)
            if estimate_tokens(_dumps(preview)) > available:
                preview = None
        if preview is None:
            preview = build_preview(
                result,
                rid,
                cap_tokens=cap,
                keywords=keywords,
                compact=True,
                reason="tool-result budget for this turn is used up",
            )
        content = _dumps(preview)
        tokens = estimate_tokens(content)
    if budget is not None:
        budget.consume(tokens)
    return content


def read_stored_result(
    store: ResultStore,
    rid: str,
    *,
    offset: int = 0,
    length: int | None = None,
    grep: str | None = None,
    cap_tokens: int | None = None,
) -> dict:
    """Read part of a stored result, capped at the ingest cap.

    Args:
        store: The session's result store.
        rid: R-id to read.
        offset: Character offset into the canonical text (no *grep*).
        length: Characters to return (default and maximum: the cap).
        grep: Regex (case-insensitive; invalid regex = literal) selecting
            matching lines, each with its location.
        cap_tokens: Ingest cap (default: configured).

    Returns:
        A dict with the slice or matches and paging information, or an
        ``{"error": {...}}`` payload when *rid* is unknown.
    """
    cap = cap_tokens if cap_tokens is not None else result_cap_tokens()
    max_chars = _tokens_to_chars(cap * 0.9)
    record = store.get(rid)
    if record is None:
        known = store.ids()
        return {
            "error": {
                "code": "invalid_arguments",
                "message": f"no stored result {rid!r}",
                "retryable": False,
                "hint": (
                    f"Known ids: {known[0]}..{known[-1]}"
                    if known
                    else "No results yet."
                ),
            }
        }
    result = record.get("result")
    base = {"result_id": record.get("id", rid), "tool": record.get("tool")}
    if grep:
        try:
            pattern = re.compile(grep, re.IGNORECASE)
        except re.error:
            pattern = re.compile(re.escape(grep), re.IGNORECASE)
        matches: list[str] = []
        total = 0
        used = 0
        for location, line in iter_result_lines(result):
            if not pattern.search(line):
                continue
            total += 1
            entry = f"{location}: {_clip(line, 400)}" if location else _clip(line, 400)
            if used + len(entry) > max_chars:
                continue
            matches.append(entry)
            used += len(entry) + 4
        return {
            **base,
            "grep": grep,
            "match_count": total,
            "matches": matches,
            "truncated": len(matches) < total,
        }
    text = result_text(result)
    try:
        start = max(0, int(offset or 0))
    except (TypeError, ValueError):
        start = 0
    try:
        want = int(length) if length is not None else max_chars
    except (TypeError, ValueError):
        want = max_chars
    want = max(1, min(want, max_chars))
    chunk = text[start : start + want]
    end = start + len(chunk)
    return {
        **base,
        "offset": start,
        "length": len(chunk),
        "total_chars": len(text),
        "next_offset": end if end < len(text) else None,
        "content": chunk,
    }
