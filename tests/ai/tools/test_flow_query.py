"""Unit tests for sandroid.ai.tools.flow_query.

``get_captured_flows``/``get_flow_detail``/``clear_captured_flows`` all
lazily import ``sandroid.services.mitmproxy_flow_log`` inside each tool's
own function body (mirroring ``session_control.py``'s documented
convention), so tests monkeypatch functions directly on
``sandroid.services.mitmproxy_flow_log`` rather than on ``flow_query``
itself. Most tests here are thin pass-through/shape checks (the real
selection/cursor-cache logic is ``mitmproxy_flow_log.py``'s own
responsibility, covered by ``tests/services/test_mitmproxy_flow_log.py``);
``clear_captured_flows``'s ``latest_seq``-preservation regression uses the
real reader module against real files under ``tmp_path`` instead, since
that end-to-end on-disk behavior is the whole point of the test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools import flow_query
from sandroid.services import mitmproxy_flow_log

# =============================================================================
# get_captured_flows
# =============================================================================


def test_get_captured_flows_passes_arguments_through(monkeypatch):
    captured: dict = {}

    def fake_query_flows(flow_dir, **kwargs):
        captured["flow_dir"] = flow_dir
        captured.update(kwargs)
        return {
            "flows": [],
            "count": 0,
            "next_cursor": 5,
            "truncated": False,
            "earliest_available_seq": 1,
            "gap_before_cursor": False,
            "mode": "since_cursor",
        }

    monkeypatch.setattr(
        mitmproxy_flow_log, "resolve_flow_dir", lambda: Path("/fake/mitm_flows")
    )
    monkeypatch.setattr(mitmproxy_flow_log, "query_flows", fake_query_flows)

    result = flow_query.get_captured_flows(
        since_cursor=5, limit=50, app_filter="com.example"
    )

    assert captured["flow_dir"] == Path("/fake/mitm_flows")
    assert captured["since_cursor"] == 5
    assert captured["limit"] == 50
    assert captured["app_filter"] == "com.example"
    assert result["next_cursor"] == 5


def test_get_captured_flows_since_cursor_zero_is_passed_through_not_dropped(
    monkeypatch,
):
    """since_cursor=0 must reach query_flows as 0, not None."""
    captured: dict = {}

    def fake_query_flows(flow_dir, **kwargs):
        captured.update(kwargs)
        return {
            "flows": [],
            "count": 0,
            "next_cursor": 0,
            "truncated": False,
            "earliest_available_seq": None,
            "gap_before_cursor": False,
            "mode": "since_cursor",
        }

    monkeypatch.setattr(
        mitmproxy_flow_log, "resolve_flow_dir", lambda: Path("/fake/mitm_flows")
    )
    monkeypatch.setattr(mitmproxy_flow_log, "query_flows", fake_query_flows)

    flow_query.get_captured_flows(since_cursor=0)

    assert captured["since_cursor"] == 0


def test_get_captured_flows_limit_hard_capped_at_2000(monkeypatch):
    captured: dict = {}

    def fake_query_flows(flow_dir, **kwargs):
        captured.update(kwargs)
        return {
            "flows": [],
            "count": 0,
            "next_cursor": 0,
            "truncated": False,
            "earliest_available_seq": None,
            "gap_before_cursor": False,
            "mode": "last_n",
        }

    monkeypatch.setattr(
        mitmproxy_flow_log, "resolve_flow_dir", lambda: Path("/fake/mitm_flows")
    )
    monkeypatch.setattr(mitmproxy_flow_log, "query_flows", fake_query_flows)

    flow_query.get_captured_flows(limit=999_999)

    assert captured["limit"] == 2000


def test_get_captured_flows_rejects_non_integer_limit(monkeypatch):
    monkeypatch.setattr(
        mitmproxy_flow_log, "resolve_flow_dir", lambda: Path("/fake/mitm_flows")
    )

    with pytest.raises(ToolExecutionError, match="integer"):
        flow_query.get_captured_flows(limit="not-a-number")


def test_get_captured_flows_wraps_bad_time_as_tool_execution_error(monkeypatch):
    def raising_query_flows(flow_dir, **kwargs):
        raise ValueError("could not parse time")

    monkeypatch.setattr(
        mitmproxy_flow_log, "resolve_flow_dir", lambda: Path("/fake/mitm_flows")
    )
    monkeypatch.setattr(mitmproxy_flow_log, "query_flows", raising_query_flows)

    with pytest.raises(ToolExecutionError, match="invalid query"):
        flow_query.get_captured_flows(start_time="not-a-timestamp")


# =============================================================================
# get_flow_detail
# =============================================================================


def test_get_flow_detail_passes_arguments_through_and_returns_detail(monkeypatch):
    captured: dict = {}

    def fake_read_flow_detail(flow_dir, flow_id, *, part, max_body_bytes):
        captured["flow_dir"] = flow_dir
        captured["flow_id"] = flow_id
        captured["part"] = part
        captured["max_body_bytes"] = max_body_bytes
        return {"id": flow_id, "request_headers": []}

    monkeypatch.setattr(
        mitmproxy_flow_log, "resolve_flow_dir", lambda: Path("/fake/mitm_flows")
    )
    monkeypatch.setattr(mitmproxy_flow_log, "read_flow_detail", fake_read_flow_detail)

    result = flow_query.get_flow_detail("flow-123", part="request", max_body_bytes=10)

    assert captured == {
        "flow_dir": Path("/fake/mitm_flows"),
        "flow_id": "flow-123",
        "part": "request",
        "max_body_bytes": 10,
    }
    assert result == {"id": "flow-123", "request_headers": []}


def test_get_flow_detail_raises_for_unknown_flow_id(monkeypatch):
    monkeypatch.setattr(
        mitmproxy_flow_log, "resolve_flow_dir", lambda: Path("/fake/mitm_flows")
    )
    monkeypatch.setattr(mitmproxy_flow_log, "read_flow_detail", lambda *a, **kw: None)

    with pytest.raises(ToolExecutionError, match="not found"):
        flow_query.get_flow_detail("no-such-flow")


# =============================================================================
# clear_captured_flows
# =============================================================================


def test_clear_captured_flows_returns_success_shape(monkeypatch):
    monkeypatch.setattr(
        mitmproxy_flow_log, "resolve_flow_dir", lambda: Path("/fake/mitm_flows")
    )
    monkeypatch.setattr(mitmproxy_flow_log, "clear_flows", lambda flow_dir: 7)

    result = flow_query.clear_captured_flows()

    assert result == {"success": True, "cleared_count": 7}


def test_clear_captured_flows_preserves_latest_seq_in_meta(tmp_path, monkeypatch):
    """Regression: clear_captured_flows must not reset the seq counter --
    a stale cached since_cursor from before the clear must never collide
    with a post-clear flow's seq. Exercises the REAL reader module against
    real files on disk (only path resolution is mocked), since this
    end-to-end on-disk behavior is the whole point of the test.
    """
    flow_dir = tmp_path / "mitm_flows"
    flow_dir.mkdir(parents=True)
    (flow_dir / "flows.jsonl").write_text(
        '{"seq": 1, "id": "a"}\n{"seq": 2, "id": "b"}\n'
    )
    details_dir = flow_dir / "details"
    details_dir.mkdir()
    (details_dir / "a.json").write_text("{}")
    (details_dir / "b.json").write_text("{}")
    (flow_dir / "meta.json").write_text(
        json.dumps(
            {
                "earliest_seq": 1,
                "latest_seq": 2,
                "total_flows_lifetime": 2,
                "generation": 0,
            }
        )
    )

    monkeypatch.setattr(mitmproxy_flow_log, "resolve_flow_dir", lambda: flow_dir)

    result = flow_query.clear_captured_flows()

    assert result == {"success": True, "cleared_count": 2}
    assert not (flow_dir / "flows.jsonl").exists()
    assert list(details_dir.glob("*.json")) == []

    meta = json.loads((flow_dir / "meta.json").read_text())
    assert meta["latest_seq"] == 2  # preserved, NOT reset to 0
    assert meta["earliest_seq"] is None
