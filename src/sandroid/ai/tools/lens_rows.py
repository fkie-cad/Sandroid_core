"""AI-chat tools that find, classify, highlight and filter lens rows.

Toolset ``lenses``. Five tools, all ``READ_ONLY`` (they only change what the
Network and Files lenses show) and without a device resource:

* ``find_rows`` -- deterministic ``where`` predicates over the lens rows; with
  ``apply`` it creates (or extends) a highlight set or an AI filter itself, so
  key lists never travel through the model.
* ``classify_rows`` -- judgement queries ("personal data"): the batched model
  classifier of :mod:`sandroid.ai.row_classifier`, run through the chat
  session's client (non-reserved gateway slots), rows lighting up per batch.
* ``highlight_rows`` / ``clear_highlights`` -- manual set edits.
* ``get_rows`` (deferred) -- compact digests for spot checks.

``classify_rows``, ``highlight_rows`` and ``clear_highlights`` (and
``find_rows`` with ``apply``) change the analyst's view: orchestrator only.

Rows come from the lens itself (its registered row source, so keys and the
``shown`` flag are exactly what the lens has) and, without a lens, from the
session flow log (Network) or the monitor's event history (Files).
"""

from __future__ import annotations

import contextlib
import fnmatch
import logging
import re
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from sandroid.ai.tools.registry import RiskTier, ToolError, sandroid_tool
from sandroid.services.row_highlights import (
    LENSES,
    MAX_KEYS_PER_SET,
    HighlightError,
    StaleGenerationError,
    get_row_highlights,
    normalize_key,
)

logger = logging.getLogger(__name__)

#: Keys returned by ``find_rows``.
MAX_RETURNED_KEYS = 50
#: Hard limit of rows one ``classify_rows`` call may send.
HARD_MAX_ROWS = 2000
#: ``keys`` accepted by the tools.
MAX_KEYS_ARG = 2000
MAX_HIGHLIGHT_KEYS = 500
MAX_GET_KEYS = 20
MAX_GET_LIMIT = 50
#: Sampled reasons in a ``classify_rows`` result.
MAX_SAMPLES = 12
#: Verdicts in a ``classify_rows`` result (the set keeps all matches).
MAX_VERDICTS = 200
#: Characters of a body / file content a ``where`` predicate looks at.
HAYSTACK_CAP = 64 * 1024
#: Seconds one regex may spend on one row (windowed search).
REGEX_ROW_BUDGET_S = 0.25
#: ``kind`` values of Network rows (stdout TLS rows have no flow id).
NETWORK_KINDS = ("flow", "error")
#: Notes when the highlight set went away during a call.
NOTE_CLEARED = "set was cleared by the analyst during the scan"
NOTE_SWITCHED = (
    "the analysis session changed during the scan; nothing was highlighted in "
    "the new session"
)

_OP_LETTERS = (
    ("CREATE", "C"),
    ("DELETE", "D"),
    ("MOVE", "R"),
    ("RENAME", "R"),
    ("MODIFY", "M"),
    ("WRITE", "M"),
    ("ATTRIB", "A"),
)

_LENS_PROP = {
    "type": "string",
    "enum": list(LENSES),
    "description": "network (HTTP flows) or files (file-system rows).",
}

_WHERE_PROP = {
    "type": "object",
    "description": (
        "Row filter, all fields ANDed. Network: method[], host_glob[], "
        "path_glob[], url_regex, status (e.g. [200, '4xx']), "
        "content_type_glob, app, min_bytes, max_bytes, kind "
        "(flow/error), text, body_contains, header_contains. Files: "
        "path_glob[], ops (letters CMDRA), process, app, watched, min_count, "
        "review_kind (changed/new/deleted), text, content_contains (local "
        "copies only). regex=true makes text/*_contains regular expressions."
    ),
}

_SCOPE_PROP = {
    "type": "string",
    "enum": ["all", "shown"],
    "description": "all rows of the lens view (default) or only the rows shown now.",
    "default": "all",
}

_LABEL_PROP = {
    "type": "string",
    "description": "The ask in a few words (<=60 chars), shown in the lens.",
}

_HID_PROP = {
    "type": "string",
    "description": "Existing highlight set id (h<n>) to extend instead of a new one.",
}

# =============================================================================
# Helpers
# =============================================================================


def _invalid(message: str, hint: str | None = None, **details: Any) -> ToolError:
    return ToolError("invalid_arguments", message, hint=hint, details=details or None)


def _in_subagent() -> bool:
    """True when the call runs in a subagent's turn (fails closed)."""
    try:
        from sandroid.ai.loop import (
            ORCHESTRATOR_ID,
            _current_owner_id,
            current_run_context,
        )

        ctx = current_run_context()
        owner = _current_owner_id.get()
    except Exception:
        return True
    if ctx is not None:
        return getattr(ctx, "agent_id", None) != ORCHESTRATOR_ID
    if owner is None:
        return False  # not an AI turn (direct call, test)
    return owner != ORCHESTRATOR_ID


def _require_orchestrator(name: str) -> None:
    if _in_subagent():
        raise ToolError(
            "denied",
            f"{name} changes the analyst's lens view and runs only in the main chat",
            hint="Report the rows (keys and reasons) back instead.",
        )


def _store():
    store = get_row_highlights()
    try:
        from sandroid.ai.results import session_root

        root = session_root()
        if root is not None:
            store.bind_folder(root)
    except Exception:
        logger.debug("binding highlights failed", exc_info=True)
    return store


def _check_lens(lens: Any) -> str:
    if lens not in LENSES:
        raise _invalid(f"lens must be one of {', '.join(LENSES)}, got {lens!r}")
    return str(lens)


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list | tuple | set):
        return list(value)
    return [value]


def _audit(summary: str, data: dict) -> None:
    """One ``ai/highlight`` line on the session timeline."""
    try:
        from sandroid.core import timeline

        timeline.emit("ai", "highlight", summary=summary, actor="ai", data=data)
    except Exception:
        logger.debug("highlight timeline line failed", exc_info=True)


# =============================================================================
# Row sources
# =============================================================================


def _normalize_row(lens: str, row: Mapping[str, Any]) -> dict | None:
    """A copy with ``key`` set to the annotation key (``None``: not taggable)."""
    out = dict(row)
    if lens == "network":
        fid = row.get("flow_id")
        if not fid or row.get("kind") == "tls":
            return None  # TLS failure rows have no flow id in the lens
        out["key"] = str(fid)
    else:
        path = str(row.get("path") or row.get("key") or "")
        if not path or path.endswith("/") or "*" in path or path[0] == "\u2605":
            return None  # group ("dir/"), idle fold ("★ idle") and pattern rows
        out["key"] = normalize_key(lens, path)
        out.setdefault("path", path)
    out["shown"] = bool(row.get("shown", True))
    return out


def _flow_log_rows() -> list[dict]:
    from sandroid.services import mitmproxy_flow_log as flow_log

    try:
        flow_dir = flow_log.resolve_flow_dir()
        records = flow_log.query_flows(flow_dir, limit=flow_log.HARD_LIMIT_CAP)["flows"]
    except Exception:
        logger.debug("flow log rows unavailable", exc_info=True)
        return []
    rows = []
    for rec in records:
        fid = rec.get("id")
        if not fid or rec.get("kind") == "tls":
            continue  # the lens shows TLS failures without a flow id
        kind = rec.get("kind") or ("error" if rec.get("error") else "flow")
        host = rec.get("host") or "?"
        path = rec.get("path") or ""
        rows.append(
            {
                "key": str(fid),
                "shown": True,
                "flow_id": str(fid),
                "seq": rec.get("seq"),
                "method": rec.get("method"),
                "url": f"{host}{path}",
                "host": host,
                "path": path,
                "status": rec.get("status_code"),
                "app": rec.get("app"),
                "req_type": rec.get("request_content_type"),
                "resp_type": rec.get("response_content_type"),
                "req_bytes": rec.get("request_bytes"),
                "resp_bytes": rec.get("response_bytes"),
                "kind": kind,
                "phase": rec.get("phase"),
                "time": rec.get("ts_end"),
                "error": rec.get("error"),
                "flow_dir": str(flow_dir),
            }
        )
    return rows


def _op_letter(event_type: Any) -> str:
    name = str(event_type or "").upper()
    for token, letter in _OP_LETTERS:
        if token in name:
            return letter
    return "A"


def _monitor_rows() -> list[dict]:
    """Files rows from the monitor's event history (one per canonical path)."""
    try:
        from sandroid.tui.controller_registry import get_monitor_controller

        controller = get_monitor_controller()
        if controller is None:
            return []
        events = controller.get_recent_events(limit=2000).get("events") or []
    except Exception:
        logger.debug("monitor rows unavailable", exc_info=True)
        return []
    try:
        from sandroid.core.watchlist_store import package_of
    except Exception:  # pragma: no cover - import guard

        def package_of(_p: str) -> str | None:
            return None

    rows: dict[str, dict] = {}
    for ev in events:
        raw = ev.get("path")
        if not raw:
            continue
        key = normalize_key("files", raw)
        row = rows.get(key)
        ts = ev.get("timestamp")
        if row is None:
            try:
                app = package_of(key)
            except Exception:
                app = None
            row = rows[key] = {
                "key": key,
                "shown": True,
                "path": key,
                "ops": "",
                "count": 0,
                "processes": [],
                "first": ts,
                "last": ts,
                "watched": False,
                "app": app,
                "review_kind": None,
                "scope": None,
            }
        letter = _op_letter(ev.get("event_type"))
        if letter not in row["ops"]:
            row["ops"] += letter
        row["count"] += 1
        proc = ev.get("process")
        if proc and proc not in row["processes"] and len(row["processes"]) < 3:
            row["processes"].append(proc)
        row["last"] = ts
    return list(rows.values())


def collect_rows(lens: str) -> tuple[list[dict], str]:
    """``(rows, source)``: the lens's rows (``lens``) or a fallback."""
    snap = _store().snapshot_rows(lens)
    if snap is not None:
        rows = [r for r in (_normalize_row(lens, x) for x in snap) if r is not None]
        return rows, "lens"
    if lens == "network":
        raw, source = _flow_log_rows(), "flow_log"
    else:
        raw, source = _monitor_rows(), "monitor"
    rows = [r for r in (_normalize_row(lens, x) for x in raw) if r is not None]
    return rows, source


# =============================================================================
# Content (tool thread)
# =============================================================================


class _Details:
    """Per-call cache of flow details (Network) and local file content."""

    def __init__(self) -> None:
        self._flows: dict[str, Any] = {}
        self._files: dict[str, tuple[str | None, str]] = {}
        self._default_dir: Path | None = None

    def flow(self, row: Mapping[str, Any]) -> dict | None:
        fid = str(row.get("flow_id") or row.get("key") or "")
        if fid in self._flows:
            return self._flows[fid]
        from sandroid.services import mitmproxy_flow_log as flow_log

        detail = None
        dirs: list[Path] = []
        if row.get("flow_dir"):
            dirs.append(Path(str(row["flow_dir"])))
        if self._default_dir is None:
            try:
                self._default_dir = flow_log.resolve_flow_dir()
            except Exception:
                self._default_dir = Path("/nonexistent")
        dirs.append(self._default_dir)
        for flow_dir in dirs:
            try:
                detail = flow_log.read_flow_detail(flow_dir, fid)
            except Exception:
                detail = None
            if detail is not None:
                break
        self._flows[fid] = detail
        return detail

    def file(self, key: str) -> tuple[str | None, str]:
        if key not in self._files:
            from sandroid.ai.row_classifier import local_file_content

            self._files[key] = local_file_content(key)
        return self._files[key]


def _flow_text(detail: Mapping[str, Any] | None, *, bodies: bool) -> str:
    """Bodies or headers of a flow, each body capped at :data:`HAYSTACK_CAP`."""
    if not detail:
        return ""
    parts: list[str] = []
    if bodies:
        for side in ("request_body", "response_body"):
            body = detail.get(side)
            if isinstance(body, dict) and body.get("encoding") != "base64":
                parts.append(str(body.get("content") or "")[:HAYSTACK_CAP])
    else:
        for side in ("request_headers", "response_headers"):
            for item in detail.get(side) or []:
                with contextlib.suppress(TypeError, IndexError):
                    parts.append(f"{item[0]}: {item[1]}")
    return "\n".join(parts)[: 2 * HAYSTACK_CAP]


# =============================================================================
# where
# =============================================================================

_NETWORK_WHERE = frozenset(
    {
        "method",
        "host_glob",
        "path_glob",
        "url_regex",
        "status",
        "content_type_glob",
        "app",
        "min_bytes",
        "max_bytes",
        "kind",
        "text",
        "body_contains",
        "header_contains",
        "regex",
    }
)
_FILES_WHERE = frozenset(
    {
        "path_glob",
        "ops",
        "process",
        "app",
        "watched",
        "min_count",
        "review_kind",
        "text",
        "content_contains",
        "regex",
    }
)

Predicate = Callable[[dict], bool]


def _compile_regex(text: str, field: str) -> re.Pattern[str]:
    """A guarded regex (``read_result``'s ReDoS rules), or invalid_arguments."""
    from sandroid.ai.results import _grep_pattern

    try:
        re.compile(text)
    except re.error as exc:
        raise _invalid(
            f"where.{field} is not a valid regular expression: {exc}",
            hint="Fix the pattern, or drop regex=true for a literal search.",
        ) from exc
    pattern = _grep_pattern(text)
    if isinstance(pattern, str):
        raise _invalid(
            f"where.{field} was refused: {pattern}",
            hint="Use a simpler pattern or a literal (regex=false).",
        )
    return pattern


def _matcher(value: Any, regex: bool, field: str) -> Callable[[str], bool]:
    """Case-insensitive literal or guarded regex test of one row's text.

    The text is capped at :data:`HAYSTACK_CAP`; a regex searches it in
    bounded windows with a per-row time budget.
    """
    text = str(value)
    if regex:
        from sandroid.ai.results import _grep_line

        pattern = _compile_regex(text, field)

        def search(s: str | None) -> bool:
            hay = (s or "")[:HAYSTACK_CAP]
            return _grep_line(pattern, hay, time.monotonic() + REGEX_ROW_BUDGET_S)

        return search
    low = text.lower()
    return lambda s: low in (s or "")[:HAYSTACK_CAP].lower()


def _int(value: Any, field: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise _invalid(f"where.{field} must be an integer") from exc


def _status_ok(status: Any, specs: list) -> bool:
    s = "" if status is None else str(status)
    for spec in specs:
        spec = str(spec).strip().lower()
        if spec.endswith("xx") and len(spec) == 3:
            if s[:1] == spec[0]:
                return True
        elif s == spec:
            return True
    return False


def _glob_any(value: str, patterns: list[str]) -> bool:
    value = (value or "").lower()
    return any(fnmatch.fnmatchcase(value, str(p).lower()) for p in patterns)


_GLOB_CHARS = re.compile(r"[*?\[]")


def canonical_glob(pattern: str) -> str:
    """*pattern* with its literal directory prefix in canonical form.

    ``/data/user/0/com.x/*.db`` -> ``/data/data/com.x/*.db`` and
    ``/storage/emulated/0/Down*`` -> ``/sdcard/Down*``, so globs match the
    canonical Files keys.
    """
    pattern = str(pattern)
    if not pattern.startswith("/"):
        return pattern
    m = _GLOB_CHARS.search(pattern)
    literal = pattern if m is None else pattern[: m.start()]
    cut = literal.rfind("/")
    head, rest = pattern[: cut + 1], pattern[cut + 1 :]
    if not head.strip("/"):
        return pattern
    canon = normalize_key("files", head)
    if m is None and not rest:
        return canon  # a plain directory or file path
    return canon.rstrip("/") + "/" + rest


def _path_glob_any(path: str, patterns: list[str]) -> bool:
    for p in patterns:
        p = str(p)
        if fnmatch.fnmatchcase(path, p):
            return True
        if not p.startswith(("/", "*")) and fnmatch.fnmatchcase(path, "*/" + p):
            return True
    return False


def network_haystack(row: Mapping[str, Any]) -> str:
    """What the lens's ``/`` filter looks at, roughly."""
    return " ".join(
        str(row.get(k) or "")
        for k in (
            "method",
            "url",
            "host",
            "path",
            "status",
            "app",
            "req_type",
            "resp_type",
            "error",
        )
    )


def compile_where(
    lens: str, where: Mapping[str, Any] | None, details: _Details
) -> tuple[list[Predicate], str]:
    """``(predicates, summary)``; cheap predicates first, content last.

    Raises:
        ToolError: Unknown field or a bad value.
    """
    where = dict(where or {})
    allowed = _NETWORK_WHERE if lens == "network" else _FILES_WHERE
    unknown = sorted(set(where) - allowed)
    if unknown:
        raise _invalid(
            f"unknown where field(s) for the {lens} lens: {', '.join(unknown)}",
            hint=f"Allowed: {', '.join(sorted(allowed))}.",
        )
    regex = bool(where.pop("regex", False))
    cheap: list[Predicate] = []
    costly: list[Predicate] = []
    summary: list[str] = []
    for field, value in where.items():
        if value is None or value == [] or value == "":
            continue
        summary.append(f"{field}={value}")
        if lens == "network":
            _network_pred(field, value, regex, details, cheap, costly)
        else:
            _files_pred(field, value, regex, details, cheap, costly)
    return cheap + costly, ", ".join(summary)


def _network_pred(
    field: str,
    value: Any,
    regex: bool,
    details: _Details,
    cheap: list[Predicate],
    costly: list[Predicate],
) -> None:
    if field == "method":
        methods = {str(m).upper() for m in _as_list(value)}
        cheap.append(lambda r: str(r.get("method") or "").upper() in methods)
    elif field == "host_glob":
        pats = [str(p) for p in _as_list(value)]
        cheap.append(lambda r: _glob_any(str(r.get("host") or ""), pats))
    elif field == "path_glob":
        pats = [str(p) for p in _as_list(value)]
        cheap.append(lambda r: _path_glob_any(str(r.get("path") or ""), pats))
    elif field == "url_regex":
        m = _matcher(value, True, field)
        cheap.append(
            lambda r: m(str(r.get("url") or f"{r.get('host')}{r.get('path')}"))
        )
    elif field == "status":
        specs = _as_list(value)
        cheap.append(lambda r: _status_ok(r.get("status"), specs))
    elif field == "content_type_glob":
        pats = [str(p) for p in _as_list(value)]
        cheap.append(
            lambda r: _glob_any(str(r.get("req_type") or ""), pats)
            or _glob_any(str(r.get("resp_type") or ""), pats)
        )
    elif field == "app":
        pats = [str(p) for p in _as_list(value)]
        cheap.append(lambda r: _glob_any(str(r.get("app") or ""), pats))
    elif field in ("min_bytes", "max_bytes"):
        limit = _int(value, field)

        def size(r: dict) -> int:
            total = 0
            for k in ("req_bytes", "resp_bytes"):
                with contextlib.suppress(TypeError, ValueError):
                    total += int(r.get(k) or 0)
            return total

        if field == "min_bytes":
            cheap.append(lambda r: size(r) >= limit)
        else:
            cheap.append(lambda r: size(r) <= limit)
    elif field == "kind":
        kinds = {str(k).lower() for k in _as_list(value)}
        bad = sorted(kinds - set(NETWORK_KINDS))
        if bad:
            raise _invalid(
                f"where.kind must be one of {', '.join(NETWORK_KINDS)} "
                f"(got {', '.join(bad)})",
                hint="TLS failure rows have no flow id and cannot be highlighted.",
            )
        cheap.append(lambda r: str(r.get("kind") or "flow").lower() in kinds)
    elif field == "text":
        m = _matcher(value, regex, field)
        cheap.append(lambda r: m(network_haystack(r)))
    elif field == "body_contains":
        m = _matcher(value, regex, field)
        costly.append(lambda r: m(_flow_text(details.flow(r), bodies=True)))
    elif field == "header_contains":
        m = _matcher(value, regex, field)
        costly.append(lambda r: m(_flow_text(details.flow(r), bodies=False)))


def _files_pred(
    field: str,
    value: Any,
    regex: bool,
    details: _Details,
    cheap: list[Predicate],
    costly: list[Predicate],
) -> None:
    if field == "path_glob":
        pats = [canonical_glob(str(p)) for p in _as_list(value)]
        cheap.append(lambda r: _path_glob_any(str(r.get("key") or ""), pats))
    elif field == "ops":
        letters = {c for c in str(value).upper() if c.isalpha()}
        cheap.append(lambda r: bool(letters & set(str(r.get("ops") or "").upper())))
    elif field == "process":
        m = _matcher(value, regex, field)
        cheap.append(lambda r: any(m(str(p)) for p in r.get("processes") or []))
    elif field == "app":
        pats = [str(p) for p in _as_list(value)]
        cheap.append(lambda r: _glob_any(str(r.get("app") or ""), pats))
    elif field == "watched":
        want = bool(value)
        cheap.append(lambda r: bool(r.get("watched")) == want)
    elif field == "min_count":
        limit = _int(value, field)
        cheap.append(lambda r: int(r.get("count") or 0) >= limit)
    elif field == "review_kind":
        kinds = {str(k).lower() for k in _as_list(value)}
        cheap.append(lambda r: str(r.get("review_kind") or "").lower() in kinds)
    elif field == "text":
        m = _matcher(value, regex, field)
        cheap.append(
            lambda r: m(
                " ".join(
                    [str(r.get("key") or ""), str(r.get("app") or "")]
                    + [str(p) for p in r.get("processes") or []]
                )
            )
        )
    elif field == "content_contains":
        m = _matcher(value, regex, field)
        costly.append(
            lambda r: m((details.file(str(r.get("key")))[0] or "")[:HAYSTACK_CAP])
        )


def _filter(rows: list[dict], preds: list[Predicate]) -> list[dict]:
    out = []
    for row in rows:
        try:
            if all(p(row) for p in preds):
                out.append(row)
        except Exception:
            logger.debug("where predicate failed on %s", row.get("key"), exc_info=True)
    return out


def _scoped(rows: list[dict], scope: str) -> list[dict]:
    if scope not in ("all", "shown"):
        raise _invalid("scope must be 'all' or 'shown'")
    return rows if scope == "all" else [r for r in rows if r.get("shown")]


def _row_line(lens: str, row: Mapping[str, Any]) -> str:
    from sandroid.ai.row_classifier import files_summary, network_summary

    return network_summary(row) if lens == "network" else files_summary(row)


def _basis(
    lens: str, rows: list[dict], evaluated: int, at: float | None = None
) -> dict:
    """``{"judged_at", "through_seq", "evaluated"}`` for "N new since".

    *rows* must be ALL scoped rows of the view (not only the candidates):
    a row that existed when the rows were collected (*at*) is never "new".
    """
    seqs = []
    for r in rows:
        with contextlib.suppress(TypeError, ValueError):
            if r.get("seq") is not None:
                seqs.append(int(r["seq"]))
    return {
        "judged_at": time.time() if at is None else at,
        "through_seq": max(seqs) if lens == "network" and seqs else None,
        "evaluated": evaluated,
    }


def _hidden(rows_by_key: Mapping[str, dict], keys: list[str]) -> int:
    return sum(1 for k in keys if not rows_by_key.get(k, {}).get("shown", True))


def _create_set(
    store: Any,
    lens: str,
    label: str,
    *,
    reasons: Mapping[str, str],
    origin: str,
    query: str,
    scope: str | None,
    basis: dict,
    complete: bool,
    filter: bool,
    generation: int | None = None,
) -> str:
    try:
        hs = store.create(
            lens,
            label,
            reasons=reasons,
            origin=origin,
            query=query,
            scope=scope,
            basis=basis,
            complete=complete,
            filter=filter,
            generation=generation,
        )
    except StaleGenerationError as exc:
        raise ToolError(
            "tool_failed", NOTE_SWITCHED, retryable=True, hint="Run it again."
        ) from exc
    except HighlightError as exc:
        raise _invalid(
            str(exc),
            hint="clear_highlights(highlight_id=...) or pass highlight_id to extend one.",
        ) from exc
    return hs.id


def _add_capped(
    store: Any, set_id: str, reasons: Mapping[str, str], generation: int | None
) -> int:
    """Add rows up to the set's cap; returns how many new rows did not fit.

    Raises:
        HighlightError: The set is gone (or the session switched).
    """
    hs = store.get(set_id)
    if hs is None:
        raise HighlightError(f"unknown highlight set {set_id!r}")
    room = MAX_KEYS_PER_SET - hs.count
    new = [k for k in reasons if k not in hs.reasons]
    dropped = max(0, len(new) - max(0, room))
    if dropped:
        skip = set(new[len(new) - dropped :])
        reasons = {k: v for k, v in reasons.items() if k not in skip}
    if reasons:
        store.add(set_id, reasons, generation=generation)
    return dropped


def _set_lost(store: Any, set_id: str | None, generation: int) -> str:
    """The note for a set that a mutation could not reach."""
    if store.generation != generation:
        return NOTE_SWITCHED
    if set_id is not None and store.get(set_id) is not None:
        return f"highlight set {set_id} could not be updated"
    return NOTE_CLEARED


def _existing_set(store: Any, lens: str, set_id: str) -> Any:
    hs = store.get(set_id)
    if hs is None:
        raise _invalid(f"unknown highlight set {set_id!r}")
    if hs.lens != lens:
        raise _invalid(f"highlight set {set_id} belongs to the {hs.lens} lens")
    return hs


# =============================================================================
# find_rows
# =============================================================================


@sandroid_tool(
    name="find_rows",
    description=(
        "Find rows of the Network or Files lens with deterministic 'where' "
        "filters (fields, globs, literal text; no model). With apply="
        "highlight or filter it highlights the matches in the lens itself "
        "(or shows only them); never copy keys around. Returns N of M, "
        "hidden_by_lens_filters and at most 50 keys. Use classify_rows when "
        "matching needs judgement."
    ),
    parameters={
        "type": "object",
        "properties": {
            "lens": _LENS_PROP,
            "where": _WHERE_PROP,
            "scope": _SCOPE_PROP,
            "apply": {
                "type": "string",
                "enum": ["none", "highlight", "filter"],
                "description": (
                    "none (default) only reports; highlight tints the matches; "
                    "filter shows only them (the lens's AI filter)."
                ),
                "default": "none",
            },
            "label": _LABEL_PROP,
            "highlight_id": _HID_PROP,
        },
        "required": ["lens"],
    },
    risk=RiskTier.READ_ONLY,
    category="lens_rows",
)
def find_rows(
    lens: str,
    where: dict | None = None,
    scope: str = "all",
    apply: str = "none",
    label: str | None = None,
    highlight_id: str | None = None,
) -> dict[str, Any]:
    """Structural row search; see the tool description."""
    lens = _check_lens(lens)
    if apply not in ("none", "highlight", "filter"):
        raise _invalid("apply must be none, highlight or filter")
    if apply != "none":
        _require_orchestrator("find_rows with apply")
    if where is not None and not isinstance(where, dict):
        raise _invalid("where must be an object")
    details = _Details()
    preds, summary = compile_where(lens, where, details)
    rows, source = collect_rows(lens)
    collected_at = time.time()
    scoped = _scoped(rows, scope)
    matches = _filter(scoped, preds)
    by_key = {r["key"]: r for r in scoped}
    keys = [r["key"] for r in matches]
    result: dict[str, Any] = {
        "lens": lens,
        "source": source,
        "scanned": len(scoped),
        "matched": len(matches),
        "hidden_by_lens_filters": _hidden(by_key, keys),
        "summary": f"{len(matches)} of {len(scoped)} {lens} rows match"
        + (f" ({summary})" if summary else ""),
    }
    if apply != "none" and len(matches) > MAX_KEYS_PER_SET and not highlight_id:
        raise _invalid(
            f"{len(matches)} of {len(scoped)} {lens} rows match; a highlight set "
            f"holds at most {MAX_KEYS_PER_SET} rows",
            hint="Narrow `where` (e.g. host_glob, method, status, app, path_glob) "
            "so fewer rows match, then apply again.",
            matched=len(matches),
        )
    if apply != "none" and matches:
        store = _store()
        gen = store.generation
        reason = f"matches {summary}" if summary else "matched by find_rows"
        reasons = dict.fromkeys(keys, reason)
        set_id: str | None
        dropped = 0
        if highlight_id:
            hs = _existing_set(store, lens, highlight_id)
            set_id = hs.id
            try:
                dropped = _add_capped(store, set_id, reasons, gen)
                if apply == "filter":
                    store.set_filter(lens, set_id, generation=gen)
            except HighlightError:
                result["note"] = _set_lost(store, set_id, gen)
                set_id = None
        else:
            set_id = _create_set(
                store,
                lens,
                label or summary or "found rows",
                reasons=reasons,
                origin="structural",
                query=summary,
                scope=matches[0].get("scope"),
                basis=_basis(lens, scoped, len(scoped), collected_at),
                complete=True,
                filter=apply == "filter",
                generation=gen,
            )
        result["highlight_id"] = set_id
        result["mode"] = apply
        if set_id is not None:
            result["summary"] = (
                f"{'Filtered to' if apply == 'filter' else 'Highlighted'} "
                f"{len(matches) - dropped} of {len(scoped)} {lens} rows ({set_id})"
            )
            if dropped:
                result["truncated_by_cap"] = dropped
                result["summary"] += (
                    f"; {dropped} matching rows not added: a highlight set holds "
                    f"at most {MAX_KEYS_PER_SET} rows"
                )
            _audit(
                f"{result['summary']}: {label or summary}",
                {
                    "lens": lens,
                    "set": set_id,
                    "matched": len(matches),
                    "where": summary,
                },
            )
    elif apply != "none":
        result["highlight_id"] = None
        result["note"] = "nothing matched; no highlight set was created"
    result["keys"] = keys[:MAX_RETURNED_KEYS]
    if len(keys) > MAX_RETURNED_KEYS:
        result["keys_truncated"] = True
    return result


# =============================================================================
# classify_rows
# =============================================================================


def _row_classify_cfg() -> Any:
    try:
        from sandroid.ai.session import _live_ai_config

        return getattr(_live_ai_config(), "row_classify", None)
    except Exception:
        return None


def _cfg(name: str, default: int) -> int:
    cfg = _row_classify_cfg()
    try:
        return int(getattr(cfg, name, default))
    except (TypeError, ValueError):
        return default


def classifier_client() -> Any:
    """The chat session's client behind a non-reserved gateway slot, or None.

    Reuses the session's client (so ``ai.allow_remote`` was already checked
    when the chat opened); never builds a new one from config.
    """
    from sandroid.ai.agents import get_agent_manager
    from sandroid.ai.loop import current_run_context

    manager = get_agent_manager()
    parent = manager.parent_for(current_run_context())
    client = getattr(parent, "client", None)
    if client is None:
        return None
    return manager.gateway_client(client, reserved=False)


@sandroid_tool(
    name="classify_rows",
    description=(
        "Judge Network/Files lens rows against a criterion that needs "
        "judgement (personal data, tracking, credentials) with batched model "
        "calls, and highlight (or filter to) the matches live. Put the "
        "structural part into 'where' first. Rows are compact digests (auth "
        "values reduced, bodies capped). Returns N of M, partial, "
        "hidden_by_lens_filters, sampled reasons and bytes_sent. Ctrl+X stops "
        "it and keeps a partial set."
    ),
    parameters={
        "type": "object",
        "properties": {
            "lens": _LENS_PROP,
            "query": {
                "type": "string",
                "description": "The criterion, e.g. 'contains personal data'.",
            },
            "where": _WHERE_PROP,
            "keys": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Only these row keys (<=2000).",
            },
            "scope": _SCOPE_PROP,
            "apply": {
                "type": "string",
                "enum": ["highlight", "filter", "none"],
                "description": "highlight (default), filter (show only matches) or none.",
                "default": "highlight",
            },
            "label": _LABEL_PROP,
            "highlight_id": _HID_PROP,
            "max_rows": {
                "type": "integer",
                "description": "Refuse when more rows remain (default 1000, at most 2000).",
            },
        },
        "required": ["lens", "query"],
    },
    risk=RiskTier.READ_ONLY,
    category="lens_rows",
)
def classify_rows(
    lens: str,
    query: str,
    where: dict | None = None,
    keys: list[str] | None = None,
    scope: str = "all",
    apply: str = "highlight",
    label: str | None = None,
    highlight_id: str | None = None,
    max_rows: int | None = None,
) -> dict[str, Any]:
    """Semantic row classification; see the tool description."""
    from sandroid.ai import row_classifier as rc
    from sandroid.ai.loop import (
        current_run_context,
        report_tool_progress,
        tool_time_remaining,
    )

    _require_orchestrator("classify_rows")
    lens = _check_lens(lens)
    query = " ".join(str(query or "").split())
    if not query:
        raise _invalid("query must describe what a matching row is")
    if apply not in ("highlight", "filter", "none"):
        raise _invalid("apply must be highlight, filter or none")
    if where is not None and not isinstance(where, dict):
        raise _invalid("where must be an object")
    limit = _cfg("max_rows", 1000) if max_rows is None else max_rows
    try:
        limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise _invalid("max_rows must be an integer") from exc
    if not 1 <= limit <= HARD_MAX_ROWS:
        raise _invalid(f"max_rows must be between 1 and {HARD_MAX_ROWS}")
    key_list = [normalize_key(lens, k) for k in _as_list(keys)]
    if len(key_list) > MAX_KEYS_ARG:
        raise _invalid(f"at most {MAX_KEYS_ARG} keys")

    details = _Details()
    preds, where_summary = compile_where(lens, where, details)
    rows, source = collect_rows(lens)
    collected_at = time.time()
    scoped = _scoped(rows, scope)
    by_key = {r["key"]: r for r in scoped}
    unknown: list[str] = []
    if key_list:
        unknown = [k for k in key_list if k not in by_key]
        wanted = set(key_list)
        scoped_sel = [r for r in scoped if r["key"] in wanted]
    else:
        scoped_sel = scoped
    candidates = _filter(scoped_sel, preds)
    if len(candidates) > limit:
        raise _invalid(
            f"{len(candidates)} rows remain after the filters (of {len(scoped)}); "
            f"the limit is {limit}",
            hint=f"narrow with where, or raise max_rows to at most {HARD_MAX_ROWS}",
            candidates=len(candidates),
            rows=len(scoped),
        )
    store = _store()
    gen = store.generation
    existing = _existing_set(store, lens, highlight_id) if highlight_id else None

    base: dict[str, Any] = {
        "lens": lens,
        "query": query,
        "source": source,
        "rows_in_view": len(scoped),
        "candidates": len(candidates),
    }
    if where_summary:
        base["where"] = where_summary
    if unknown:
        base["unknown_keys"] = unknown[:MAX_RETURNED_KEYS]
    if not candidates:
        base.update(
            scanned=0,
            matched=0,
            uncertain=0,
            partial=False,
            hidden_by_lens_filters=0,
            highlight_id=None,
            summary=f"0 of 0 {lens} rows to classify (nothing left after the filters)",
        )
        return base

    client = classifier_client()
    if client is None:
        raise ToolError(
            "tool_failed",
            "no chat model session is available for the classifier",
            hint="Use find_rows, or get_rows plus highlight_rows for a few rows.",
        )

    mask = rc.mask_enabled()
    digests: list[rc.Digest] = []
    for row in candidates:
        if lens == "network":
            digests.append(rc.network_digest(row, detail=details.flow(row), mask=mask))
        else:
            digests.append(
                rc.files_digest(row, mask=mask, content=details.file(row["key"]))
            )
    metadata_only = sum(1 for d in digests if d.kind == "metadata")
    binary_only = sum(1 for d in digests if d.kind == "binary")

    set_id: str | None = None
    created = False
    if apply != "none":
        if existing is not None:
            set_id = existing.id
            try:
                store.finish(set_id, complete=False, generation=gen)
            except HighlightError as exc:
                raise _invalid(str(exc)) from exc
        else:
            set_id = _create_set(
                store,
                lens,
                label or query,
                reasons={},
                origin="ai",
                query=query + (f" where {where_summary}" if where_summary else ""),
                scope=candidates[0].get("scope"),
                basis=_basis(lens, scoped, 0, collected_at),
                complete=False,
                filter=False,
                generation=gen,
            )
            created = True

    ctx = current_run_context()
    cancel = getattr(ctx, "cancel_event", None)
    left = tool_time_remaining()
    deadline = None if left is None else time.monotonic() + left
    total = len(digests)
    report_tool_progress(0, total, matched=0, note="classifying", force=True)
    state: dict[str, Any] = {"set_id": set_id, "note": None, "cap_dropped": 0}
    classifier: rc.RowClassifier | None = None

    def lose_set() -> None:
        if state["note"] is None:
            state["note"] = _set_lost(store, state["set_id"], gen)
        state["set_id"] = None

    def on_batch(batch: rc.BatchResult, outcome: rc.ClassifyOutcome) -> None:
        if store.generation != gen:
            # The analyst switched sessions: drop the remaining batches.
            lose_set()
            if classifier is not None:
                classifier.halt("session_switched")
        sid = state["set_id"]
        if sid is not None:
            found = {v.key: v.reason for v in batch.verdicts if v.match is True}
            if found:
                try:
                    state["cap_dropped"] += _add_capped(store, sid, found, gen)
                except HighlightError:
                    lose_set()
        report_tool_progress(
            outcome.scanned, total, matched=len(outcome.matched), note="classifying"
        )

    classifier = rc.RowClassifier(
        client,
        lens=lens,
        criterion=query,
        concurrency=_cfg("concurrency", rc.DEFAULT_CONCURRENCY),
        batch_rows=_cfg("batch_rows", rc.DEFAULT_BATCH_ROWS),
        batch_tokens=_cfg("batch_tokens", rc.DEFAULT_BATCH_TOKENS),
        max_tokens=_cfg("max_tokens", rc.DEFAULT_MAX_TOKENS),
        cancel_event=cancel,
        deadline=deadline,
        on_batch=on_batch,
    )
    outcome = classifier.run(digests)
    report_tool_progress(
        outcome.scanned,
        total,
        matched=len(outcome.matched),
        note="classified",
        force=True,
    )

    matched_keys = [v.key for v in outcome.matched]
    stats = {
        "scanned": outcome.scanned,
        "matched": len(matched_keys),
        "uncertain": len(outcome.uncertain),
        "errors": outcome.errors,
        "unknown_ids": outcome.unknown_ids,
        "metadata_only": metadata_only,
        "bytes_sent": outcome.bytes_sent,
        "candidates": total,
    }
    if state["cap_dropped"]:
        stats["truncated_by_cap"] = state["cap_dropped"]
    judged_nothing = outcome.scanned == 0 and outcome.errors > 0
    if state["set_id"] is not None:
        sid = state["set_id"]
        try:
            current = store.get(sid)
            if store.generation != gen or current is None:
                lose_set()
            elif created and (not current.reasons or judged_nothing):
                store.remove(sid, generation=gen)  # nothing to show
                state["set_id"] = None
            else:
                store.finish(
                    sid,
                    complete=not outcome.partial,
                    stats=stats,
                    basis=_basis(lens, scoped, outcome.scanned, collected_at),
                    generation=gen,
                )
                if apply == "filter":
                    store.set_filter(lens, sid, generation=gen)
        except HighlightError:
            lose_set()
    set_id = state["set_id"]

    error_text = (
        f"backend error: {outcome.error}"
        if outcome.error
        else "the model's replies were not the required JSON"
    )
    if judged_nothing:
        _audit(
            f"classify_rows failed ({error_text}): {query}",
            {"lens": lens, "query": query, "errors": outcome.errors},
        )
        raise ToolError(
            "backend_error",
            f"none of the {total} {lens} rows could be judged "
            f"({outcome.errors} errored; {error_text})",
            retryable=True,
            hint="Try again later or with fewer rows (where / max_rows); "
            "find_rows needs no model.",
            details={
                "stop_reason": outcome.stop_reason,
                "errors": outcome.errors,
                "requests": outcome.requests,
                "bytes_sent": outcome.bytes_sent,
            },
        )

    hidden = _hidden(by_key, matched_keys)
    stopped = f", stopped early ({outcome.stop_reason})" if outcome.stop_reason else ""
    verb = "Filtered to" if apply == "filter" else "Highlighted"
    if apply == "none" or set_id is None:
        verb = "Found"
    summary = (
        f"{verb} {len(matched_keys)} of {outcome.scanned} {lens} rows "
        f"(candidates {total}; {hidden} hidden by your lens filters; "
        f"{metadata_only} judged from metadata only{stopped})"
    )
    if outcome.errors:
        summary += f"; {outcome.errors} rows could not be judged ({error_text})"
    if outcome.unknown_ids:
        summary += f"; the model named {outcome.unknown_ids} unknown row id(s)"
    if state["cap_dropped"]:
        summary += (
            f"; {state['cap_dropped']} matches not added: a highlight set holds "
            f"at most {MAX_KEYS_PER_SET} rows"
        )
    if state["note"]:
        summary += f"; {state['note']}"
    samples = [
        {
            "key": v.key,
            "row": _row_line(lens, by_key.get(v.key, {"key": v.key})),
            "reason": v.reason,
        }
        for v in outcome.matched[:MAX_SAMPLES]
    ]
    verdicts = [
        {"key": v.key, "match": v.match, "reason": v.reason} for v in outcome.verdicts
    ]
    base.update(
        summary=summary,
        highlight_id=set_id,
        mode=apply,
        scanned=outcome.scanned,
        matched=len(matched_keys),
        uncertain=len(outcome.uncertain),
        partial=outcome.partial,
        stop_reason=outcome.stop_reason,
        hidden_by_lens_filters=hidden,
        judged_on_metadata_only=metadata_only,
        binary_only=binary_only,
        skipped={
            "errors": outcome.errors,
            "not_reached": total - outcome.scanned - outcome.errors,
            "unknown_ids": outcome.unknown_ids,
        },
        bytes_sent=outcome.bytes_sent,
        model_tokens=outcome.model_tokens,
        requests=outcome.requests,
        samples=samples,
        verdicts=verdicts[:MAX_VERDICTS],
    )
    if outcome.error:
        base["backend_error"] = outcome.error
    if len(verdicts) > MAX_VERDICTS:
        base["verdicts_truncated"] = len(verdicts) - MAX_VERDICTS
    if state["cap_dropped"]:
        base["truncated_by_cap"] = state["cap_dropped"]
    if state["note"]:
        base["note"] = state["note"]
    _audit(
        f"{summary}: {query}" + (f" ({set_id})" if set_id else ""),
        {
            "lens": lens,
            "set": set_id,
            "query": query,
            "matched": len(matched_keys),
            "scanned": outcome.scanned,
            "errors": outcome.errors,
            "partial": outcome.partial,
            "bytes_sent": outcome.bytes_sent,
        },
    )
    return base


# =============================================================================
# highlight_rows / clear_highlights
# =============================================================================


@sandroid_tool(
    name="highlight_rows",
    description=(
        "Add, remove or replace rows of a highlight set by key, or switch a "
        "set between highlight and filter (mode). Without highlight_id it "
        "creates a set (label and keys needed). Keys the lens does not have "
        "are returned, not stored. For many rows use find_rows/classify_rows "
        "with apply instead."
    ),
    parameters={
        "type": "object",
        "properties": {
            "lens": _LENS_PROP,
            "keys": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Row keys (flow ids / device paths), at most 500.",
            },
            "label": _LABEL_PROP,
            "reasons": {
                "type": "object",
                "description": "Optional {key: short reason} per row.",
            },
            "mode": {
                "type": "string",
                "enum": ["highlight", "filter"],
                "description": "highlight tints rows; filter shows only this set's rows.",
            },
            "highlight_id": {
                "type": "string",
                "description": "Set to change (h<n>); omit to create one.",
            },
            "action": {
                "type": "string",
                "enum": ["add", "remove", "replace"],
                "description": "What to do with keys (default add).",
                "default": "add",
            },
        },
        "required": ["lens"],
    },
    risk=RiskTier.READ_ONLY,
    category="lens_rows",
)
def highlight_rows(
    lens: str,
    keys: list[str] | None = None,
    label: str | None = None,
    reasons: dict | None = None,
    mode: str | None = None,
    highlight_id: str | None = None,
    action: str = "add",
) -> dict[str, Any]:
    """Manual highlight edits; see the tool description."""
    _require_orchestrator("highlight_rows")
    lens = _check_lens(lens)
    if action not in ("add", "remove", "replace"):
        raise _invalid("action must be add, remove or replace")
    if mode not in (None, "highlight", "filter"):
        raise _invalid("mode must be highlight or filter")
    key_list = [normalize_key(lens, k) for k in _as_list(keys) if str(k).strip()]
    if len(key_list) > MAX_HIGHLIGHT_KEYS:
        raise _invalid(
            f"at most {MAX_HIGHLIGHT_KEYS} keys per call",
            hint="Use find_rows or classify_rows with apply for many rows.",
        )
    if action in ("remove", "replace") and not highlight_id:
        raise _invalid(
            f"action={action} needs highlight_id (the set to change)",
            hint="Omit action (add) to create a set, or pass highlight_id.",
        )
    if action in ("remove", "replace") and not key_list:
        raise _invalid(f"action={action} needs keys")
    if reasons is not None and not isinstance(reasons, dict):
        raise _invalid("reasons must be an object {key: reason}")
    reason_map = {
        normalize_key(lens, k): str(v) for k, v in dict(reasons or {}).items()
    }
    store = _store()
    gen = store.generation
    existing = _existing_set(store, lens, highlight_id) if highlight_id else None
    if existing is None and not key_list:
        raise _invalid("give keys (and a label) to create a highlight set")

    unknown: list[str] = []
    known = key_list
    by_key: dict[str, dict] = {}
    if action == "remove" and existing is not None:
        known = [k for k in key_list if k in existing.reasons]
        unknown = [k for k in key_list if k not in existing.reasons]
    elif key_list:
        rows, _source = collect_rows(lens)
        by_key = {r["key"]: r for r in rows}
        known = [k for k in key_list if k in by_key]
        unknown = [k for k in key_list if k not in by_key]
    applied = {k: reason_map.get(k) or "picked by the assistant" for k in known}
    if action in ("remove", "replace") and not known:
        where_ = f"set {highlight_id}" if action == "remove" else "the lens"
        raise _invalid(
            f"none of the keys is in {where_}; nothing was changed "
            f"(action={action} would apply 0 rows)",
            hint="Copy keys exactly from find_rows / get_rows.",
            unknown_keys=unknown[:MAX_RETURNED_KEYS],
            unknown_count=len(unknown),
        )

    note: str | None = None
    dropped = 0
    set_id: str | None
    try:
        if existing is None:
            if not applied:
                return {
                    "highlight_id": None,
                    "applied": 0,
                    "unknown_keys": unknown[:MAX_RETURNED_KEYS],
                    "unknown_count": len(unknown),
                    "total": 0,
                    "hidden_by_lens_filters": 0,
                    "note": "none of the keys is a row of the lens; nothing created",
                }
            set_id = _create_set(
                store,
                lens,
                label or "picked rows",
                reasons=applied,
                origin="manual",
                query="",
                scope=None,
                basis=_basis(lens, list(by_key.values()), len(applied)),
                complete=True,
                filter=mode == "filter",
                generation=gen,
            )
            total = len(applied)
        else:
            set_id = existing.id
            if action == "remove":
                total = store.remove_keys(set_id, known, generation=gen)
            elif action == "replace":
                total = store.replace_keys(set_id, applied, generation=gen)
            else:
                if applied:
                    dropped = _add_capped(store, set_id, applied, gen)
                current = store.get(set_id)
                total = current.count if current is not None else 0
            if label:
                store.update_meta(set_id, label=label, generation=gen)
            if mode == "filter":
                store.set_filter(lens, set_id, generation=gen)
            elif mode == "highlight" and store.filter_set(lens) == set_id:
                store.set_filter(lens, None, generation=gen)
    except HighlightError as exc:
        if store.generation == gen and (
            existing is None or store.get(existing.id) is not None
        ):
            raise _invalid(str(exc)) from exc
        note = _set_lost(store, existing.id if existing else None, gen)
        set_id, total = None, 0

    hidden = _hidden(by_key, list(applied)) if by_key else 0
    result: dict[str, Any] = {
        "highlight_id": set_id,
        "applied": len(known) - dropped,
        "action": action if existing is not None else "create",
        "mode": (
            "filter"
            if set_id is not None and store.filter_set(lens) == set_id
            else "highlight"
        ),
        "total": total,
        "unknown_keys": unknown[:MAX_RETURNED_KEYS],
        "unknown_count": len(unknown),
        "hidden_by_lens_filters": hidden,
    }
    if dropped:
        result["truncated_by_cap"] = dropped
        result["summary"] = (
            f"{dropped} rows not added: a highlight set holds at most "
            f"{MAX_KEYS_PER_SET} rows"
        )
    if note:
        result["note"] = note
        return result
    _audit(
        f"highlight_rows {result['action']} {set_id}: {result['applied']} row(s)",
        {"lens": lens, "set": set_id, "action": result["action"], "total": total},
    )
    return result


@sandroid_tool(
    name="clear_highlights",
    description=(
        "Remove highlight sets and their AI filter from the Network/Files "
        "lens: one set by highlight_id, every set of one lens, or all."
    ),
    parameters={
        "type": "object",
        "properties": {
            "lens": {
                "type": "string",
                "enum": list(LENSES),
                "description": "Only this lens (omit: both lenses).",
            },
            "highlight_id": {
                "type": "string",
                "description": "Only this set (h<n>).",
            },
        },
        "required": [],
    },
    risk=RiskTier.READ_ONLY,
    category="lens_rows",
)
def clear_highlights(
    lens: str | None = None, highlight_id: str | None = None
) -> dict[str, Any]:
    """Remove highlight sets; see the tool description."""
    _require_orchestrator("clear_highlights")
    store = _store()
    if highlight_id:
        hs = store.get(highlight_id)
        if hs is None:
            raise _invalid(f"unknown highlight set {highlight_id!r}")
        if lens is not None and hs.lens != lens:
            raise _invalid(
                f"highlight set {highlight_id} belongs to the {hs.lens} lens"
            )
        store.remove(highlight_id)
        cleared = [highlight_id]
    else:
        if lens is not None:
            _check_lens(lens)
        cleared = store.clear(lens)
    if cleared:
        _audit(
            f"cleared highlights {', '.join(cleared)}",
            {"lens": lens, "cleared": cleared},
        )
    return {"cleared": cleared, "remaining": [s.id for s in store.sets()]}


# =============================================================================
# get_rows
# =============================================================================


@sandroid_tool(
    name="get_rows",
    description=(
        "Read compact digests of Network/Files lens rows (summary, capped "
        "headers/bodies or local file content) to check matches or handle a "
        "few rows yourself: by keys (<=20) or a page (cursor, limit<=50)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "lens": _LENS_PROP,
            "keys": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Row keys to read (<=20).",
            },
            "cursor": {
                "type": "integer",
                "description": "Row offset of the page (from next_cursor).",
                "default": 0,
            },
            "limit": {
                "type": "integer",
                "description": "Rows per page (<=50, default 20).",
                "default": 20,
            },
            "include_content": {
                "type": "boolean",
                "description": "Include headers/bodies or file content (default true).",
                "default": True,
            },
            "max_bytes": {
                "type": "integer",
                "description": "Digest bytes per row (default 2000, at most 4000).",
                "default": 2000,
            },
        },
        "required": ["lens"],
    },
    risk=RiskTier.READ_ONLY,
    category="lens_rows",
)
def get_rows(
    lens: str,
    keys: list[str] | None = None,
    cursor: int = 0,
    limit: int = 20,
    include_content: bool = True,
    max_bytes: int = 2000,
) -> dict[str, Any]:
    """Row digests; see the tool description."""
    from sandroid.ai import row_classifier as rc

    lens = _check_lens(lens)
    key_list = [normalize_key(lens, k) for k in _as_list(keys)]
    if len(key_list) > MAX_GET_KEYS:
        raise _invalid(f"at most {MAX_GET_KEYS} keys per call")
    try:
        cursor = max(0, int(cursor or 0))
        limit = max(1, min(int(limit or 20), MAX_GET_LIMIT))
        max_bytes = max(200, min(int(max_bytes or 2000), 4000))
    except (TypeError, ValueError) as exc:
        raise _invalid("cursor, limit and max_bytes must be integers") from exc
    rows, source = collect_rows(lens)
    by_key = {r["key"]: r for r in rows}
    unknown: list[str] = []
    if key_list:
        page = [by_key[k] for k in key_list if k in by_key]
        unknown = [k for k in key_list if k not in by_key]
        next_cursor = None
    else:
        page = rows[cursor : cursor + limit]
        next_cursor = cursor + limit if cursor + limit < len(rows) else None
    mask = rc.mask_enabled()
    details = _Details()
    out = []
    for row in page:
        item: dict[str, Any] = {
            "key": row["key"],
            "shown": row.get("shown", True),
            "row": _row_line(lens, row),
        }
        if include_content:
            if lens == "network":
                digest = rc.network_digest(
                    row, detail=details.flow(row), mask=mask, row_cap=max_bytes
                )
            else:
                digest = rc.files_digest(
                    row, mask=mask, row_cap=max_bytes, content=details.file(row["key"])
                )
            item["digest"] = digest.text
            item["content"] = digest.kind
        hl = _store().lookup(lens, row["key"])
        if hl:
            item["highlights"] = [e[0] for e in hl]
        out.append(item)
    result: dict[str, Any] = {
        "lens": lens,
        "source": source,
        "total": len(rows),
        "rows": out,
        "next_cursor": next_cursor,
    }
    if unknown:
        result["unknown_keys"] = unknown
    return result


__all__ = [
    "classifier_client",
    "classify_rows",
    "clear_highlights",
    "collect_rows",
    "compile_where",
    "find_rows",
    "get_rows",
    "highlight_rows",
]
