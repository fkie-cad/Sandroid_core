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
``shown`` flag are exactly what the lens has) and, without a lens (or a
live Network lens that never polled), from the session flow log (Network)
or the monitor's event history (Files); there ``shown`` follows the lens's
noise rule only (``shown_basis`` says so).

Scope: by default (``scope="shown"``) the tools see exactly the rows the
lens's own filters let through: TLS-failure rows included (key
``tls_row_key``: the flow-log record id ``tls-<seq>`` namespaced by its flow
dir), rows hidden by the lens filters (OS noise, app only, ``/``, review
phases) left out. The AI filter is not a lens filter here: a new query or
an extend of the filter set sees every row the other filters let through.
Every result counts the matching rows the lens hides
(``hidden_by_lens_filters``; with a body/content predicate only the cheap
part is checked on them: ``hidden_not_searched``) and says how to include
them: ``scope="all"`` is the explicit opt-in. Sets record the hidden rows
they did not judge (``basis["not_judged"]``) for the bar's "N not judged".

A stdout-only TLS failure (the lens's ``t<n>`` row, no key yet) is paired
here with its flow-log record (same host, within 10 s, nearest first), so
it is a row even while the Network lens is hidden and does not poll. The
records the hidden lens has not loaded (``seq`` above its snapshot's
``polled_through``) are added from the flow log, as fallback rows.
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
    MAX_NOT_JUDGED,
    HighlightError,
    StaleGenerationError,
    get_row_highlights,
    normalize_key,
    tls_row_key,
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
#: ``kind`` values of Network rows (TLS failures: key ``tls_row_key``).
NETWORK_KINDS = ("flow", "error", "tls")
#: Seconds between a stdout TLS line and its flow-log record (pairing).
TLS_PAIR_WINDOW_S = 10.0
#: A stdout-only TLS row younger than this may still reach the flow log.
TLS_YOUNG_S = 15.0
#: ``shown_basis`` of rows that do not come from the lens itself.
SHOWN_BASIS_FALLBACK = "noise rule only (lens not open)"
#: Flow-log rows newer than a hidden lens's last poll, at most (the lens's
#: own ``MAX_ROWS``).
MAX_ROWS_AFTER = 2000
#: ``scope`` values; the first is the default.
SCOPES = ("shown", "all")
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
        "(flow/error/tls: tls = TLS handshake failed), text, body_contains, "
        "header_contains. Files: "
        "path_glob[], ops (letters CMDRA), process, app, watched, min_count, "
        "review_kind (changed/new/deleted), text, content_contains (local "
        "copies only). regex=true makes text/*_contains regular expressions."
    ),
}

_SCOPE_PROP = {
    "type": "string",
    "enum": list(SCOPES),
    "description": (
        "shown (default): the rows the lens filters let through, TLS "
        "failures included (an AI filter does not narrow it). all: also the "
        "rows the lens filters hide (OS noise, app only, /, phases); only "
        "when the analyst asks for them."
    ),
    "default": "shown",
}

_LABEL_PROP = {
    "type": "string",
    "description": "The ask in a few words (<=60 chars), shown in the lens.",
}

_SHORT_PROP = {
    "type": "string",
    "description": (
        "A 1-3 word label (<=14 chars) for the lens column and bar, e.g. "
        "'personal data', 'POST api.x', 'email'. Pass it; the automatic one "
        "is a guess."
    ),
}

_REGEX_PROP = {
    "type": "boolean",
    "description": "Alias of where.regex (text/*_contains as regular expressions).",
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
        if not fid:
            # A stdout-only TLS failure the flow log has not caught up with
            # (the lens's ``t<n>`` row): no stable key yet.
            return None
        out["key"] = str(fid)
    else:
        path = str(row.get("path") or row.get("key") or "")
        if not path or path.endswith("/") or "*" in path or path[0] == "\u2605":
            return None  # group ("dir/"), idle fold ("★ idle") and pattern rows
        out["key"] = normalize_key(lens, path)
        out.setdefault("path", path)
    out["shown"] = bool(row.get("shown", True))
    return out


def _spotlight_package() -> str | None:
    try:
        from sandroid.services import get_spotlight_service

        app = get_spotlight_service().get_app_tuple()
    except Exception:
        return None
    return app[0] if app else None


def _filter_bypass(lens: str) -> Callable[[str], bool]:
    """Rows of the lens's active AI filter set beat the noise rules (as in
    the lens, ``HighlightView.bypass_noise``).
    """
    store = get_row_highlights()
    fid = store.filter_set(lens)
    if not fid:
        return lambda _key: False
    return lambda key: any(e[0] == fid for e in store.lookup(lens, key))


def _network_noise() -> Callable[[dict], bool]:
    """The Network lens's OS-noise rule (``network_panel.is_noise``) on a row."""
    try:
        from sandroid.tui.widgets.network_panel import is_noise
    except Exception:  # pragma: no cover - import guard
        return lambda _row: False
    focus = _spotlight_package()
    bypass = _filter_bypass("network")

    def noisy(row: dict) -> bool:
        return is_noise(
            str(row.get("host") or "?"),
            str(row.get("path") or ""),
            str(row.get("app") or ""),
            focus,
        ) and not bypass(str(row.get("key") or ""))

    return noisy


def _files_noise() -> Callable[[str], bool]:
    """The Files lens's hide rules (``NoiseRules.hidden_by``) on a key."""
    try:
        from sandroid.tui.widgets.monitor_view import NoiseRules

        rules = NoiseRules.from_config()
    except Exception:
        logger.debug("files noise rules unavailable", exc_info=True)
        return lambda _key: False
    bypass = _filter_bypass("files")
    return lambda key: rules.hidden_by(key) is not None and not bypass(key)


def _flow_log_rows() -> list[dict]:
    """The newest flow-log records as rows (the lens never polled)."""
    from sandroid.services import mitmproxy_flow_log as flow_log

    try:
        flow_dir = flow_log.resolve_flow_dir()
        records = flow_log.query_flows(flow_dir, limit=flow_log.HARD_LIMIT_CAP)["flows"]
    except Exception:
        logger.debug("flow log rows unavailable", exc_info=True)
        return []
    return _records_as_rows(records, flow_dir)


def _flow_log_rows_after(flow_dir: Path, seq: int) -> list[dict]:
    """Flow-log records with a ``seq`` above *seq* as rows: what a hidden
    Network lens (it does not poll) has not loaded yet. Read like the
    lens's poll: at most :data:`MAX_ROWS_AFTER` records, the newest kept.
    """
    from sandroid.services import mitmproxy_flow_log as flow_log

    records: list[dict] = []
    cursor = seq
    try:
        for _ in range(5):
            res = flow_log.query_flows(
                flow_dir, since_cursor=cursor, limit=flow_log.HARD_LIMIT_CAP
            )
            records.extend(res["flows"])
            cursor = res["next_cursor"]
            # Page to the end (the log keeps at most a few pages): the
            # newest rows are the ones the analyst asks about.
            if not res["truncated"]:
                break
    except Exception:
        logger.debug("newer flow log rows unavailable", exc_info=True)
        return []
    return _records_as_rows(records[-MAX_ROWS_AFTER:], flow_dir)


def _records_as_rows(records: list[dict], flow_dir: Path) -> list[dict]:
    """Flow-log records as rows; ``shown`` follows the lens's noise rule."""
    rows = []
    for rec in records:
        if rec.get("kind") == "tls":
            row = _flow_log_tls_row(rec, flow_dir)
            if row is not None:
                rows.append(row)
            continue
        fid = rec.get("id")
        if not fid:
            continue
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
    if rows:
        noisy = _network_noise()
        for row in rows:
            row["shown"] = not noisy(row)
    return rows


def _flow_log_tls_row(rec: Mapping[str, Any], flow_dir: Path) -> dict | None:
    """A TLS-failure record as a row, keyed like the lens (``tls_row_key``)."""
    seq = rec.get("seq")
    fid = tls_row_key(
        flow_dir, rec.get("id") or (f"tls-{seq}" if seq is not None else None)
    )
    if not fid:
        return None
    host = rec.get("host") or "?"
    reason = rec.get("tls_reason") or "tls"
    return {
        "key": str(fid),
        "shown": True,
        "flow_id": str(fid),
        "seq": seq,
        "method": "TLS",
        "url": f"https://{host}",
        "host": host,
        "path": "",
        "status": None,
        "app": rec.get("app"),
        "req_type": None,
        "resp_type": None,
        "req_bytes": 0,
        "resp_bytes": None,
        "kind": "tls",
        "phase": rec.get("phase"),
        "time": rec.get("ts_end"),
        "error": rec.get("error") or f"TLS handshake failed ({reason})",
        "flow_dir": str(flow_dir),
    }


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
    noisy = _files_noise()
    for row in rows.values():
        row["shown"] = not noisy(row["key"])
    return list(rows.values())


def _max_seq(raw: list[dict]) -> int | None:
    seqs = []
    for r in raw:
        with contextlib.suppress(TypeError, ValueError):
            if r.get("seq") is not None:
                seqs.append(int(r["seq"]))
    return max(seqs) if seqs else None


class _Collected:
    """The rows of one call (see :func:`_collect`)."""

    __slots__ = ("max_seq", "newer", "rows", "source", "unkeyed", "unkeyed_old")

    def __init__(
        self,
        rows: list[dict],
        source: str,
        max_seq: int | None,
        unkeyed: int,
        unkeyed_old: int = 0,
        newer: int = 0,
    ) -> None:
        self.rows = rows
        self.source = source
        self.max_seq = max_seq
        #: Shown stdout-only TLS failures young enough to reach the flow log.
        self.unkeyed = unkeyed
        #: ... older ones (or in review): they cannot be highlighted.
        self.unkeyed_old = unkeyed_old
        #: Rows added from the flow log after the lens's last poll.
        self.newer = newer


def _tls_records(flow_dir: Path, rows: list[dict]) -> list[dict]:
    """The flow log's TLS-failure records around *rows*' times."""
    from datetime import datetime

    from sandroid.services import mitmproxy_flow_log as flow_log

    times = [float(r.get("time") or 0.0) for r in rows]
    start = datetime.fromtimestamp(min(times) - TLS_PAIR_WINDOW_S - 1.0)
    end = datetime.fromtimestamp(max(times) + TLS_PAIR_WINDOW_S + 1.0)
    try:
        res = flow_log.query_flows(
            flow_dir,
            start_time=start.isoformat(),
            end_time=end.isoformat(),
            limit=flow_log.HARD_LIMIT_CAP,
        )
    except Exception:
        logger.debug("TLS records unavailable", exc_info=True)
        return []
    return [r for r in res["flows"] if r.get("kind") == "tls"]


def _pair_unkeyed_tls(raw: list[dict]) -> None:
    """Give stdout-only TLS rows (key None) their flow-log key, in place.

    The lens pairs them only when it polls, and it polls only while shown;
    the tools pair them here (tool thread) the same way: a record of the
    same host within :data:`TLS_PAIR_WINDOW_S` seconds that no row of the
    view has yet, one record per row, nearest first. The key is the one the
    lens adopts on its next poll (``tls_row_key``), so the tint matches then.
    """
    pending = [
        r
        for r in raw
        if not r.get("flow_id") and r.get("kind") == "tls" and r.get("time")
    ]
    if not pending:
        return
    from sandroid.services import mitmproxy_flow_log as flow_log

    taken = {str(r["flow_id"]) for r in raw if r.get("flow_id")}
    by_dir: dict[str, list[dict]] = {}
    for row in pending:
        flow_dir = row.get("flow_dir")
        if not flow_dir:
            try:
                flow_dir = str(flow_log.resolve_flow_dir())
            except Exception:
                continue
        by_dir.setdefault(str(flow_dir), []).append(row)
    for flow_dir, rows in by_dir.items():
        candidates = []
        for rec in _tls_records(Path(flow_dir), rows):
            seq = rec.get("seq")
            key = tls_row_key(
                flow_dir, rec.get("id") or (f"tls-{seq}" if seq is not None else None)
            )
            if key and key not in taken:
                candidates.append((key, rec))
        pairs = []
        for i, row in enumerate(rows):
            for j, (_key, rec) in enumerate(candidates):
                if str(rec.get("host") or "?") != str(row.get("host") or "?"):
                    continue
                with contextlib.suppress(TypeError, ValueError):
                    ts = float(rec.get("ts_end") or rec.get("ts_start") or 0.0)
                    gap = abs(ts - float(row["time"]))
                    if gap <= TLS_PAIR_WINDOW_S:
                        pairs.append((gap, i, j))
        used_rows: set[int] = set()
        used_recs: set[int] = set()
        for _gap, i, j in sorted(pairs):
            if i in used_rows or j in used_recs:
                continue
            used_rows.add(i)
            used_recs.add(j)
            key, rec = candidates[j]
            rows[i].update(key=key, flow_id=key, seq=rec.get("seq"))
            taken.add(key)


def _collect(lens: str) -> _Collected:
    """The rows of the view; ``max_seq`` counts every row of it, also the
    ones the tools cannot take (a TLS failure not in the flow log yet).
    """
    snap = _store().snapshot_rows(lens)
    newer = 0
    if lens == "network" and snap is not None and _snapshot_dir_is_stale(snap):
        # A hidden live lens kept the old device's / session's flow dir:
        # its rows are not this view any more.
        snap = None
    if snap is not None:
        raw, source = list(snap), "lens"
    elif lens == "network":
        raw, source = _flow_log_rows(), "flow_log"
    else:
        # The Files lens ingests every monitor batch, shown or not: its
        # snapshot is never behind.
        raw, source = _monitor_rows(), "monitor"
    if lens == "network":
        _pair_unkeyed_tls(raw)
        if snap is not None:
            newer = _add_unpolled(raw, snap)
    rows = []
    young = old = 0
    now = time.time()
    for x in raw:
        row = _normalize_row(lens, x)
        if row is not None:
            rows.append(row)
        elif lens == "network" and x.get("shown", True):
            try:
                age = now - float(x.get("time") or 0.0)
            except (TypeError, ValueError):
                age = TLS_YOUNG_S + 1
            if x.get("scope") is None and age <= TLS_YOUNG_S:
                young += 1
            else:
                old += 1
    return _Collected(
        rows, source, _max_seq(raw) if lens == "network" else None, young, old, newer
    )


def _snapshot_dir_is_stale(snap: Any) -> bool:
    """A live lens snapshot whose flow dir is not the current one (it was
    hidden across a device or session switch and never polled since).
    """
    if getattr(snap, "polled_through", None) is None:
        return False  # REVIEW (its own bundle) or a source that does not say
    flow_dir = getattr(snap, "flow_dir", None)
    if not flow_dir:
        return False
    try:
        from sandroid.services import mitmproxy_flow_log as flow_log

        current = flow_log.resolve_flow_dir()
        return Path(str(flow_dir)).resolve() != Path(str(current)).resolve()
    except Exception:
        return False


def _add_unpolled(raw: list[dict], snap: Any) -> int:
    """Add the flow-log rows a hidden live Network lens has not loaded yet.

    The lens polls only while it is shown, so its snapshot ends at its
    last poll (``polled_through``). The newer records come in here (tool
    thread, never a UI poll) as the fallback's rows: same keys, ``shown``
    by the noise rule only. Run after :func:`_pair_unkeyed_tls`, so a TLS
    record a stdout row of the lens has paired with is not added twice.
    Returns how many rows were added.
    """
    through = getattr(snap, "polled_through", None)
    flow_dir = getattr(snap, "flow_dir", None)
    if through is None or not flow_dir:
        return 0  # REVIEW, or a source that does not say
    try:
        through = int(through)
    except (TypeError, ValueError):
        return 0
    taken = {str(r["flow_id"]) for r in raw if r.get("flow_id")}
    added = [
        r
        for r in _flow_log_rows_after(Path(str(flow_dir)), through)
        if r["key"] not in taken
    ]
    raw.extend(added)
    return len(added)


def collect_rows(lens: str) -> tuple[list[dict], str]:
    """``(rows, source)``: every row of the lens view (shown or not)."""
    got = _collect(lens)
    return got.rows, got.source


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
        if row.get("kind") == "tls":
            return None  # a failed handshake has no headers or bodies
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


class _Costly:
    """A content predicate (bodies, headers, file content): read per row, so
    the hidden rows of ``scope="shown"`` are never searched with it.
    """

    __slots__ = ("fn",)

    def __init__(self, fn: Predicate) -> None:
        self.fn = fn

    def __call__(self, row: dict) -> bool:
        return self.fn(row)


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


_WHERE_NAMES = {
    "method": "method",
    "host_glob": "host",
    "path_glob": "path",
    "status": "status",
    "content_type_glob": "content type",
    "app": "app",
    "kind": "kind",
    "ops": "ops",
    "process": "process",
    "review_kind": "review",
}
_WHERE_TEXT = {
    "text": "text",
    "body_contains": "body",
    "header_contains": "headers",
    "content_contains": "content",
}


def _where_words(field: str, value: Any, regex: bool) -> str:
    """One ``where`` field in plain words: ``method POST or GET``."""
    items = " or ".join(str(v) for v in _as_list(value))
    if field in _WHERE_TEXT:
        verb = "matches" if regex else "contains"
        return f"{_WHERE_TEXT[field]} {verb} “{items}”"
    if field == "url_regex":
        return f"URL matches “{items}”"
    if field == "min_bytes":
        return f"at least {items} bytes"
    if field == "max_bytes":
        return f"at most {items} bytes"
    if field == "min_count":
        return f"at least {items} events"
    if field == "watched":
        return "watched" if value else "not watched"
    if field == "method":
        items = items.upper()
    return f"{_WHERE_NAMES.get(field, field)} {items}"


def _with_regex_alias(where: Any, regex: bool | None) -> dict | None:
    """``where`` plus a top-level ``regex`` (a common model slip) as where.regex."""
    if where is not None and not isinstance(where, dict):
        raise _invalid("where must be an object")
    if regex is None:
        return where
    out = dict(where or {})
    out.setdefault("regex", bool(regex))
    return out


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
        summary.append(_where_words(field, value, regex))
        if lens == "network":
            _network_pred(field, value, regex, details, cheap, costly)
        else:
            _files_pred(field, value, regex, details, cheap, costly)
    return cheap + [_Costly(p) for p in costly], ", ".join(summary)


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
                hint="tls = the TLS handshake with mitmproxy failed (pinning).",
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


def _check_scope(scope: Any) -> str:
    if scope is None:
        return SCOPES[0]
    if scope not in SCOPES:
        raise _invalid(
            "scope must be 'shown' (the rows the lens shows, default) or 'all'"
        )
    return str(scope)


def _scoped(rows: list[dict], scope: str) -> list[dict]:
    return rows if scope == "all" else [r for r in rows if r.get("shown")]


class _Matched:
    """The rows of one ``where`` (see :func:`_match`)."""

    __slots__ = ("hidden", "matches", "not_searched")

    def __init__(
        self, matches: list[dict], hidden: list[dict], not_searched: bool
    ) -> None:
        #: Matches in scope (the rows the call lists, judges or applies).
        self.matches = matches
        #: Matches the lens hides: with scope="all" a subset of ``matches``;
        #: with "shown" left out (not judged) and only counted.
        self.hidden = hidden
        #: scope="shown" with a content predicate: ``hidden`` passed only the
        #: cheap predicates (their bodies / content were not read).
        self.not_searched = not_searched

    def hidden_fields(self) -> dict[str, Any]:
        """``hidden_by_lens_filters`` (or ``hidden_not_searched``) for a result."""
        if self.not_searched and self.hidden:
            return {
                "hidden_by_lens_filters": None,
                "hidden_not_searched": len(self.hidden),
            }
        return {"hidden_by_lens_filters": len(self.hidden)}


def _match(rows: list[dict], preds: list[Predicate], scope: str) -> _Matched:
    """Match *rows* against *preds*.

    ``scope="all"``: every row, fully. ``"shown"``: the shown rows fully;
    the hidden ones only to count them, with the cheap (structural)
    predicates alone: reading every hidden flow's body (or file) just to
    count it is too expensive.
    """
    if scope == "all":
        every = _filter(rows, preds)
        return _Matched(every, [r for r in every if not r.get("shown")], False)
    cheap = [p for p in preds if not isinstance(p, _Costly)]
    costly = len(cheap) != len(preds)
    matches = _filter([r for r in rows if r.get("shown")], preds)
    hidden = _filter([r for r in rows if not r.get("shown")], cheap)
    return _Matched(matches, hidden, costly)


def _hidden_hint(
    lens: str,
    hidden: int,
    scope: str,
    *,
    judged: bool = True,
    searched: bool = True,
) -> str:
    """How to include the *hidden* rows the lens filters hide (words)."""
    what = "OS noise, app only, the / filter or review phases"
    if lens == "files":
        what = "hide rules, the / filter or the app filter"
    if scope == "all":
        return (
            f"{hidden} of them are hidden in the lens ({what}); the analyst "
            "sees them only with those filters off"
        )
    if not searched:
        verb = "fit the other conditions (their bodies or content were not searched)"
    else:
        verb = "match" if judged else "fit the filters and were not judged"
    return (
        f"{hidden} more {lens} rows {verb} but are hidden by the lens "
        f"filters ({what}); pass scope='all' to include them"
    )


def _add_unkeyed(result: dict, got: _Collected) -> None:
    """Say so when shown TLS failures could not be listed (no key), and
    where ``shown`` came from when the rows are not the lens's own.
    """
    if got.source != "lens":
        result["shown_basis"] = SHOWN_BASIS_FALLBACK
    elif got.newer:
        result["shown_basis"] = (
            f"the lens; {got.newer} newer row(s) it has not loaded yet (it "
            "is not shown): noise rule only"
        )
    if got.unkeyed:
        n = got.unkeyed
        result["not_in_flow_log_yet"] = n
        result["not_in_flow_log_yet_hint"] = (
            f"{n} TLS-failure row(s) the lens shows arrived seconds ago and "
            "are not in the flow log yet; run the tool again in a moment"
        )
    if got.unkeyed_old:
        n = got.unkeyed_old
        result["not_in_flow_log"] = n
        result["not_in_flow_log_hint"] = (
            f"{n} TLS-failure row(s) the lens shows cannot be highlighted "
            "(not in the flow log); do not retry for them"
        )


def _not_judged(matched: _Matched, scope: str) -> dict[str, Any]:
    """The basis fields for "N not judged": rows hidden, so left out."""
    keys = [] if scope == "all" else [r["key"] for r in matched.hidden]
    return {"scope": scope, "not_judged": keys[:MAX_NOT_JUDGED]}


def _row_line(lens: str, row: Mapping[str, Any]) -> str:
    from sandroid.ai.row_classifier import files_summary, network_summary

    return network_summary(row) if lens == "network" else files_summary(row)


def _basis(
    lens: str,
    rows: list[dict],
    evaluated: int,
    at: float | None = None,
    through: int | None = None,
) -> dict:
    """``{"judged_at", "through_seq", "evaluated"}`` for "N new since".

    *rows* must be ALL scoped rows of the view (not only the candidates):
    a row that existed when the rows were collected (*at*) is never "new".
    """
    seqs = [] if through is None else [through]
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
    short: str | None = None,
    reasons: Mapping[str, str],
    origin: str,
    query: str,
    scope: str | None,
    basis: dict,
    complete: bool,
    filter: bool,
    generation: int | None = None,
    scanning: bool = False,
) -> str:
    try:
        hs = store.create(
            lens,
            label,
            short=short or None,
            reasons=reasons,
            origin=origin,
            query=query,
            scope=scope,
            basis=basis,
            complete=complete,
            filter=filter,
            generation=generation,
            scanning=scanning,
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


def _end_scan(store: Any, set_id: str | None, created: bool, generation: int) -> None:
    """After a failed classifier run: drop an empty new set, else mark the
    set partial (never left ``scanning``). Best effort.
    """
    if set_id is None:
        return
    try:
        hs = store.get(set_id)
        if hs is None:
            return
        if created and not hs.reasons:
            store.remove(set_id, generation=generation)
        else:
            store.finish(set_id, complete=False, generation=generation)
    except HighlightError:
        logger.debug("ending the scan of %s failed", set_id, exc_info=True)


def _merged_not_judged(
    hs: Any, unjudged: Mapping[str, Any], judged: Mapping[str, Any]
) -> dict[str, Any]:
    """An existing set's ``not_judged`` after another run: rows looked at
    now (*judged*) leave it, the rows this run left out join it.
    """
    keep = [k for k in (hs.basis or {}).get("not_judged") or () if k not in judged]
    keys = list(dict.fromkeys([*keep, *unjudged["not_judged"]]))
    return {"scope": unjudged["scope"], "not_judged": keys[:MAX_NOT_JUDGED]}


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
        "filters (fields, globs, literal text; no model). Sees exactly the "
        "rows the lens shows (TLS-failure rows included); scope='all' adds "
        "the rows its filters hide. With apply=highlight or filter it "
        "highlights the matches in the lens itself (or shows only them); "
        "never copy keys around. Returns N of M, hidden_by_lens_filters "
        "(matching rows the lens hides, with a hint) and at most 50 keys. "
        "Use classify_rows when matching needs judgement. With apply, pass "
        "label (the ask) and short (1-3 words for the lens column, e.g. "
        "'POST api.x')."
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
            "short": _SHORT_PROP,
            "highlight_id": _HID_PROP,
            "regex": _REGEX_PROP,
        },
        "required": ["lens"],
    },
    risk=RiskTier.READ_ONLY,
    category="lens_rows",
)
def find_rows(
    lens: str,
    where: dict | None = None,
    scope: str = "shown",
    apply: str = "none",
    label: str | None = None,
    highlight_id: str | None = None,
    short: str | None = None,
    regex: bool | None = None,
) -> dict[str, Any]:
    """Structural row search; see the tool description."""
    lens = _check_lens(lens)
    scope = _check_scope(scope)
    if apply not in ("none", "highlight", "filter"):
        raise _invalid("apply must be none, highlight or filter")
    if apply != "none":
        _require_orchestrator("find_rows with apply")
    where = _with_regex_alias(where, regex)
    details = _Details()
    preds, summary = compile_where(lens, where, details)
    got = _collect(lens)
    rows, source, max_seq = got.rows, got.source, got.max_seq
    collected_at = time.time()
    scoped = _scoped(rows, scope)
    # The hidden matches are counted, never listed (scope="shown"), so the
    # model learns they exist and how to get them.
    matched = _match(rows, preds, scope)
    matches = matched.matches
    hidden = len(matched.hidden)
    keys = [r["key"] for r in matches]
    result: dict[str, Any] = {
        "lens": lens,
        "source": source,
        "scope": scope,
        "scanned": len(scoped),
        "matched": len(matches),
        **matched.hidden_fields(),
        "summary": f"{len(matches)} of {len(scoped)} {lens} rows match"
        + (f" ({summary})" if summary else ""),
    }
    if hidden:
        result["hidden_hint"] = _hidden_hint(
            lens, hidden, scope, searched=not matched.not_searched
        )
    _add_unkeyed(result, got)
    if apply != "none" and len(matches) > MAX_KEYS_PER_SET and not highlight_id:
        raise _invalid(
            f"{len(matches)} of {len(scoped)} {lens} rows match; a highlight set "
            f"holds at most {MAX_KEYS_PER_SET} rows",
            hint="Narrow `where` (e.g. host_glob, method, status, app, path_glob) "
            "so fewer rows match, then apply again.",
            matched=len(matches),
        )
    if apply != "none" and highlight_id:
        _extend_set(
            result,
            lens,
            highlight_id,
            apply,
            keys,
            matched,
            scope,
            summary,
            label,
            judged={r["key"] for r in scoped},
        )
    elif apply != "none" and matches:
        store = _store()
        gen = store.generation
        reason = f"matches {summary}" if summary else "matched by find_rows"
        basis = _basis(lens, scoped, len(scoped), collected_at, max_seq)
        basis.update(_not_judged(matched, scope))
        set_id = _create_set(
            store,
            lens,
            label or summary or "found rows",
            short=short,
            reasons=dict.fromkeys(keys, reason),
            origin="structural",
            query=summary,
            scope=matches[0].get("scope"),
            basis=basis,
            complete=True,
            filter=apply == "filter",
            generation=gen,
        )
        result["highlight_id"] = set_id
        result["mode"] = apply
        result["summary"] = (
            f"{'Filtered to' if apply == 'filter' else 'Highlighted'} "
            f"{len(matches)} of {len(scoped)} {lens} rows ({set_id})"
        )
        _audit(
            f"{result['summary']}: {label or summary}",
            {"lens": lens, "set": set_id, "matched": len(matches), "where": summary},
        )
    elif apply != "none":
        result["highlight_id"] = None
        result["note"] = "nothing matched; no highlight set was created"
    result["keys"] = keys[:MAX_RETURNED_KEYS]
    if len(keys) > MAX_RETURNED_KEYS:
        result["keys_truncated"] = True
    return result


def _extend_set(
    result: dict[str, Any],
    lens: str,
    highlight_id: str,
    apply: str,
    keys: list[str],
    matched: _Matched,
    scope: str,
    summary: str,
    label: str | None,
    *,
    judged: set[str],
) -> None:
    """``find_rows(highlight_id=...)``: add the new matches to the set (and
    make it the AI filter for apply=filter). Never "no set was created":
    the set stays, also when nothing new matched.
    """
    store = _store()
    gen = store.generation
    hs = _existing_set(store, lens, highlight_id)
    set_id: str | None = hs.id
    reason = f"matches {summary}" if summary else "matched by find_rows"
    new = [k for k in keys if k not in hs.reasons]
    dropped = 0
    # Rows looked at now (*judged*) leave the "not judged" list; hidden
    # matches join it.
    unjudged = list(
        dict.fromkeys(
            [k for k in hs.basis.get("not_judged") or () if k not in judged]
            + _not_judged(matched, scope)["not_judged"]
        )
    )[:MAX_NOT_JUDGED]
    try:
        if new:
            dropped = _add_capped(store, hs.id, dict.fromkeys(new, reason), gen)
        if unjudged != list(hs.basis.get("not_judged") or ()):
            store.update_meta(hs.id, basis={"not_judged": unjudged}, generation=gen)
        if apply == "filter":
            store.set_filter(lens, hs.id, generation=gen)
    except HighlightError:
        result["note"] = _set_lost(store, hs.id, gen)
        set_id = None
    result["highlight_id"] = set_id
    result["mode"] = apply
    if set_id is None:
        return
    added = len(new) - dropped
    current = store.get(set_id)
    total = current.count if current is not None else hs.count + added
    if added:
        verb = "Filtered to" if apply == "filter" else "Highlighted"
        result["summary"] = (
            f"{verb} {added} more {lens} rows in {set_id} ({total} in the set)"
        )
    else:
        result["note"] = (
            f"no new rows: every match is already in {set_id}"
            if keys
            else f"no new rows: nothing matched; {set_id} is unchanged"
        )
        result["summary"] = f"no new rows for {set_id} ({total} in the set" + (
            ", now the AI filter)" if apply == "filter" else ")"
        )
    if dropped:
        result["truncated_by_cap"] = dropped
        result["summary"] += (
            f"; {dropped} matching rows not added: a highlight set holds "
            f"at most {MAX_KEYS_PER_SET} rows"
        )
    _audit(
        f"{result['summary']}: {label or summary}",
        {"lens": lens, "set": set_id, "matched": len(keys), "where": summary},
    )


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
        "structural part into 'where' first. Judges exactly the rows the lens "
        "shows (TLS failures included); scope='all' adds the rows its filters "
        "hide. Rows are compact digests (auth values reduced, bodies capped). "
        "Returns N of M, partial, hidden_by_lens_filters (with a hint), "
        "sampled reasons and bytes_sent. Ctrl+X stops it (partial set). Pass "
        "label (the ask) and short (1-3 words, e.g. 'personal data')."
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
            "short": _SHORT_PROP,
            "highlight_id": _HID_PROP,
            "regex": _REGEX_PROP,
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
    scope: str = "shown",
    apply: str = "highlight",
    label: str | None = None,
    highlight_id: str | None = None,
    max_rows: int | None = None,
    short: str | None = None,
    regex: bool | None = None,
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
    scope = _check_scope(scope)
    query = " ".join(str(query or "").split())
    if not query:
        raise _invalid("query must describe what a matching row is")
    if apply not in ("highlight", "filter", "none"):
        raise _invalid("apply must be highlight, filter or none")
    where = _with_regex_alias(where, regex)
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
    got = _collect(lens)
    rows, source, max_seq = got.rows, got.source, got.max_seq
    collected_at = time.time()
    scoped = _scoped(rows, scope)
    all_by_key = {r["key"]: r for r in rows}
    by_key = {r["key"]: r for r in scoped}
    unknown: list[str] = []
    hidden_keys: list[str] = []
    selected = rows
    if key_list:
        unknown = [k for k in key_list if k not in all_by_key]
        hidden_keys = [k for k in key_list if k in all_by_key and k not in by_key]
        wanted = set(key_list)
        selected = [r for r in rows if r["key"] in wanted]
    # Rows the lens hides that fit where/keys: never judged with
    # scope="shown", but counted (hidden_by_lens_filters) with a hint, and
    # recorded in the set's basis ("N not judged" in the bar).
    fitting = _match(selected, preds, scope)
    candidates = fitting.matches
    hidden_unjudged = 0 if scope == "all" else len(fitting.hidden)
    unjudged_basis = _not_judged(fitting, scope)
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
    base["scope"] = scope
    if where_summary:
        base["where"] = where_summary
    if unknown:
        base["unknown_keys"] = unknown[:MAX_RETURNED_KEYS]
    if hidden_keys:
        base["hidden_keys"] = hidden_keys[:MAX_RETURNED_KEYS]
    _add_unkeyed(base, got)
    not_searched = fitting.not_searched and hidden_unjudged > 0
    if not candidates:
        base.update(
            scanned=0,
            matched=0,
            uncertain=0,
            partial=False,
            **(fitting.hidden_fields() if scope != "all" else {}),
            highlight_id=None,
            summary=f"0 of 0 {lens} rows to classify (nothing left after the filters)",
        )
        base.setdefault("hidden_by_lens_filters", 0)
        if hidden_unjudged:
            base["hidden_hint"] = _hidden_hint(
                lens, hidden_unjudged, scope, judged=False, searched=not not_searched
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

    created = False
    total = len(digests)
    state: dict[str, Any] = {"set_id": None, "note": None, "cap_dropped": 0}
    if apply != "none":
        if existing is not None:
            try:
                store.start_scan(existing.id, generation=gen)
            except HighlightError as exc:
                raise _invalid(str(exc)) from exc
            state["set_id"] = existing.id
        else:
            basis = _basis(lens, scoped, 0, collected_at, max_seq)
            basis.update(unjudged_basis)
            state["set_id"] = _create_set(
                store,
                lens,
                label or query,
                short=short,
                reasons={},
                origin="ai",
                query=query + (f" where {where_summary}" if where_summary else ""),
                scope=candidates[0].get("scope"),
                basis=basis,
                complete=False,
                filter=False,
                generation=gen,
                scanning=True,
            )
            created = True
    # From here on the set is "scanning": every way out ends the scan.
    scan_id: str | None = state["set_id"]
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

    try:
        ctx = current_run_context()
        cancel = getattr(ctx, "cancel_event", None)
        left = tool_time_remaining()
        deadline = None if left is None else time.monotonic() + left
        report_tool_progress(0, total, matched=0, note="classifying", force=True)
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
                    basis = _basis(lens, scoped, outcome.scanned, collected_at, max_seq)
                    if existing is not None:
                        basis.update(
                            _merged_not_judged(current, unjudged_basis, by_key)
                        )
                    else:
                        basis.update(unjudged_basis)
                    store.finish(
                        sid,
                        complete=not outcome.partial,
                        stats=stats,
                        basis=basis,
                        generation=gen,
                    )
                    if apply == "filter":
                        store.set_filter(lens, sid, generation=gen)
            except HighlightError:
                lose_set()
    finally:
        # Never leave a set "scanning" behind (an error in the run, in a
        # store call, or before it): partial now, or gone when new and empty.
        if scan_id is not None and store.generation == gen:
            left_over = store.get(scan_id)
            if left_over is not None and left_over.scanning:
                _end_scan(store, scan_id, created, gen)
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

    # scope="all": matches the lens hides; "shown": rows it hides that fit
    # where/keys and were left out (the same field, see the hint).
    hidden = _hidden(all_by_key, matched_keys) if scope == "all" else hidden_unjudged
    stopped = f", stopped early ({outcome.stop_reason})" if outcome.stop_reason else ""
    verb = "Filtered to" if apply == "filter" else "Highlighted"
    if apply == "none" or set_id is None:
        verb = "Found"
    if scope == "all":
        hidden_words = f"{hidden} of them hidden by your lens filters"
    elif not_searched:
        hidden_words = (
            f"{hidden} more hidden by your lens filters, content not searched, "
            "not judged"
        )
    else:
        hidden_words = f"{hidden} more hidden by your lens filters, not judged"
    summary = (
        f"{verb} {len(matched_keys)} of {outcome.scanned} {lens} rows "
        f"(candidates {total}; {hidden_words}; "
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
        hidden_by_lens_filters=None if not_searched else hidden,
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
    if not_searched:
        base["hidden_not_searched"] = hidden
    if hidden:
        base["hidden_hint"] = _hidden_hint(
            lens, hidden, scope, judged=scope == "all", searched=not not_searched
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
        "creates a set (label, short and keys; short = 1-3 words for the lens "
        "column). Keys the lens does not have are returned, not stored. For "
        "many rows use find_rows/classify_rows with apply instead."
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
            "short": _SHORT_PROP,
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
    short: str | None = None,
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
                short=short,
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
            if label or short:
                store.update_meta(set_id, label=label, short=short, generation=gen)
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
        "few rows yourself: by keys (<=20) or a page (cursor, limit<=50). "
        "Pages hold the rows the lens shows (scope='all' adds hidden ones)."
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
            "scope": _SCOPE_PROP,
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
    scope: str = "shown",
) -> dict[str, Any]:
    """Row digests; see the tool description."""
    from sandroid.ai import row_classifier as rc

    lens = _check_lens(lens)
    scope = _check_scope(scope)
    key_list = [normalize_key(lens, k) for k in _as_list(keys)]
    if len(key_list) > MAX_GET_KEYS:
        raise _invalid(f"at most {MAX_GET_KEYS} keys per call")
    try:
        cursor = max(0, int(cursor or 0))
        limit = max(1, min(int(limit or 20), MAX_GET_LIMIT))
        max_bytes = max(200, min(int(max_bytes or 2000), 4000))
    except (TypeError, ValueError) as exc:
        raise _invalid("cursor, limit and max_bytes must be integers") from exc
    got = _collect(lens)
    rows, source = _scoped(got.rows, scope), got.source
    all_by_key = {r["key"]: r for r in got.rows}
    by_key = {r["key"]: r for r in rows}
    unknown: list[str] = []
    hidden_keys: list[str] = []
    if key_list:
        page = [by_key[k] for k in key_list if k in by_key]
        unknown = [k for k in key_list if k not in all_by_key]
        hidden_keys = [k for k in key_list if k in all_by_key and k not in by_key]
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
    hidden = sum(1 for r in got.rows if not r.get("shown"))
    result: dict[str, Any] = {
        "lens": lens,
        "source": source,
        "scope": scope,
        "total": len(rows),
        "rows": out,
        "next_cursor": next_cursor,
        "hidden_by_lens_filters": hidden,
    }
    if hidden:
        result["hidden_hint"] = (
            f"{hidden} more {lens} rows are hidden by the lens filters; "
            "pass scope='all' to page through them too"
            if scope == "shown"
            else f"{hidden} of these rows are hidden in the lens (shown: false)"
        )
    if hidden_keys:
        result["hidden_keys"] = hidden_keys
    if unknown:
        result["unknown_keys"] = unknown
    _add_unkeyed(result, got)
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
