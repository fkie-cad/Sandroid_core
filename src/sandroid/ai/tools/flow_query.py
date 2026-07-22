"""AI-chat tools for reading and clearing Sandroid's captured mitmproxy flows.

Backed entirely by :mod:`sandroid.services.mitmproxy_flow_log` -- a plain
JSON/file reader with no dependency on mitmproxy's own package or on a live
mitmweb process, reading the structured log the embedded addon in
:mod:`sandroid.services.mitmproxy_service` builds (see that module's
``_ADDON_SOURCE`` for the writer side).

Importing this module registers all three tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). ``category="flow_query"`` -- a data
domain/shape distinct from ``network_control``/``network_query``, the same
reasoning :mod:`sandroid.ai.tools.host_files` used for its own category
rather than joining ``file_transfer.py``. None of the three tools claim a
:class:`~sandroid.ai.arbiter.ResourceId`: all are pure file reads/deletes,
no device or proxy state involved.
"""

from typing import Any

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools.registry import RiskTier, sandroid_tool

#: Hard ceiling on `get_captured_flows`'s `limit`, regardless of what is
#: requested -- mirrors host_files.read_host_file's own hard-cap pattern.
_MAX_LIMIT = 2000

_DETAIL_PART_DESCRIPTION = (
    "One of: all (default), request, response, request_headers, "
    "response_headers, request_body, response_body."
)


@sandroid_tool(
    name="get_captured_flows",
    description=(
        "List captured mitmproxy flows as compact summaries (method, "
        "host+path, status, size, attributed app, timestamps, an 'id' for "
        "drill-down via get_flow_detail). Exactly one selection mode "
        "applies, in this order: (1) since_cursor -- flows completed after "
        "that seq (pass a prior call's next_cursor for 'what's new'; 0 "
        "means 'from the very start'); (2) start_time/end_time -- flows "
        "completed within that window (inclusive start, exclusive end); "
        "(3) neither given -- the most recent `limit` flows. `limit` "
        "always caps rows returned (default 200, hard-capped at 2000). No "
        "bodies or full headers here -- use get_flow_detail for those."
    ),
    parameters={
        "type": "object",
        "properties": {
            "since_cursor": {
                "type": "integer",
                "description": (
                    "Return flows with seq greater than this value. Pass 0 "
                    "to mean 'from the very start' -- distinct from "
                    "omitting the argument entirely."
                ),
            },
            "start_time": {
                "type": "string",
                "description": (
                    "ISO 8601 timestamp; inclusive lower bound on when a "
                    "flow completed."
                ),
            },
            "end_time": {
                "type": "string",
                "description": (
                    "ISO 8601 timestamp; exclusive upper bound on when a "
                    "flow completed."
                ),
            },
            "limit": {
                "type": "integer",
                "description": "Max rows to return. Default 200, hard-capped at 2000.",
                "default": 200,
            },
            "app_filter": {
                "type": "string",
                "description": "Only include flows attributed to this package.",
            },
        },
        "required": [],
    },
    risk=RiskTier.READ_ONLY,
    category="flow_query",
)
def get_captured_flows(
    since_cursor: int | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 200,
    app_filter: str | None = None,
) -> dict[str, Any]:
    """List captured flows as compact summaries.

    Real integration point:
    :func:`sandroid.services.mitmproxy_flow_log.resolve_flow_dir` +
    :func:`sandroid.services.mitmproxy_flow_log.query_flows` -- see that
    function's own docstring for the cursor-cache/generation-invalidation
    mechanics that make repeated ``since_cursor`` polling cheap.

    Returns:
        ``{"flows": [...], "count", "next_cursor", "truncated",
        "earliest_available_seq", "gap_before_cursor", "mode"}``.

    Raises:
        ToolExecutionError: *start_time*/*end_time* is not a parseable
            timestamp.
    """
    from sandroid.services import mitmproxy_flow_log as flow_log

    try:
        limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise ToolExecutionError(f"limit must be an integer, got {limit!r}") from exc
    limit = max(1, min(limit, _MAX_LIMIT))

    flow_dir = flow_log.resolve_flow_dir()
    try:
        return flow_log.query_flows(
            flow_dir,
            since_cursor=since_cursor,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            app_filter=app_filter,
        )
    except (ValueError, OverflowError) as exc:
        raise ToolExecutionError(f"invalid query: {exc}") from exc


@sandroid_tool(
    name="get_flow_detail",
    description=(
        "Get one flow's full request/response headers and capped body. "
        "Use the 'id' field from get_captured_flows as flow_id. `part` "
        f"limits what's fetched -- {_DETAIL_PART_DESCRIPTION} Bodies were "
        "captured at most mitmproxy.max_captured_body_bytes bytes AT "
        "RECORD TIME -- a larger max_body_bytes here cannot retrieve more "
        "than was actually captured, only further truncate it."
    ),
    parameters={
        "type": "object",
        "properties": {
            "flow_id": {
                "type": "string",
                "description": "The flow's 'id' field, from get_captured_flows.",
            },
            "part": {
                "type": "string",
                "description": _DETAIL_PART_DESCRIPTION,
                "default": "all",
            },
            "max_body_bytes": {
                "type": "integer",
                "description": (
                    "Further-truncate the captured body to at most this "
                    "many bytes. Cannot retrieve more than was captured."
                ),
                "default": 65536,
            },
        },
        "required": ["flow_id"],
    },
    risk=RiskTier.READ_ONLY,
    category="flow_query",
)
def get_flow_detail(
    flow_id: str, part: str = "all", max_body_bytes: int = 65536
) -> dict[str, Any]:
    """Drill down into one flow's captured headers/body.

    Real integration point:
    :func:`sandroid.services.mitmproxy_flow_log.read_flow_detail`.

    Raises:
        ToolExecutionError: *flow_id* is unknown, or its detail file was
            already dropped by retention trimming.
    """
    from sandroid.services import mitmproxy_flow_log as flow_log

    flow_dir = flow_log.resolve_flow_dir()
    detail = flow_log.read_flow_detail(
        flow_dir, flow_id, part=part, max_body_bytes=max_body_bytes
    )
    if detail is None:
        raise ToolExecutionError(
            f"flow_id {flow_id!r} not found (unknown, or its details were "
            "already dropped by retention trimming)"
        )
    return detail


@sandroid_tool(
    name="clear_captured_flows",
    description=(
        "Delete all stored flow records (flows.jsonl and every detail "
        "file). Does NOT restart mitmproxy or reset the flow sequence "
        "counter -- new flows continue from where numbering left off, "
        "avoiding cursor collisions with anything captured before the "
        "clear."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.REVERSIBLE,
    category="flow_query",
)
def clear_captured_flows() -> dict[str, Any]:
    """Delete every stored flow record, preserving the seq counter.

    Real integration point:
    :func:`sandroid.services.mitmproxy_flow_log.clear_flows` -- see its
    docstring for why ``latest_seq`` is deliberately preserved in
    ``meta.json`` rather than reset.

    Returns:
        ``{"success": True, "cleared_count": int}``.
    """
    from sandroid.services import mitmproxy_flow_log as flow_log

    flow_dir = flow_log.resolve_flow_dir()
    cleared_count = flow_log.clear_flows(flow_dir)
    return {"success": True, "cleared_count": cleared_count}
