"""Unit tests for sandroid.services.mitmproxy_flow_log.

Pure file/JSON reader tests -- no mitmweb process, no mitmproxy package
dependency. Flow records and meta.json are written directly to disk with
small helpers below, mirroring exactly the shape
mitmproxy_service.py's ``_ADDON_SOURCE`` writes (see
tests/services/test_mitmproxy_addon_flow_log.py for the writer side).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from sandroid.services import mitmproxy_flow_log as flow_log


@pytest.fixture(autouse=True)
def _reset_cursor_cache():
    """Isolate every test from any other test's cache entries.

    Not strictly necessary (tmp_path gives each test a distinct cache key
    already), but explicit resetting makes cache-behavior tests' intent
    unambiguous.
    """
    flow_log._CURSOR_CACHE.clear()
    yield
    flow_log._CURSOR_CACHE.clear()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _record(seq: int, *, ts_end: float = 1000.0, app: str = "", **overrides) -> dict:
    record = {
        "seq": seq,
        "id": f"flow-{seq}",
        "ts_start": ts_end - 1,
        "ts_end": ts_end,
        "protocol": "HTTP/1.1",
        "method": "GET",
        "host": "example.com",
        "path": "/",
        "status_code": 200,
        "error": None,
        "request_bytes": 0,
        "response_bytes": 0,
        "app": app,
        "request_content_type": None,
        "response_content_type": None,
    }
    record.update(overrides)
    return record


def _write_flow(flow_dir, seq: int, **overrides) -> dict:
    flow_dir.mkdir(parents=True, exist_ok=True)
    record = _record(seq, **overrides)
    with open(flow_dir / "flows.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return record


def _write_flows_bulk(flow_dir, records: list[dict]) -> None:
    flow_dir.mkdir(parents=True, exist_ok=True)
    text = "\n".join(json.dumps(r) for r in records) + "\n"
    (flow_dir / "flows.jsonl").write_text(text, encoding="utf-8")


def _write_meta(flow_dir, **fields) -> None:
    flow_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "earliest_seq": None,
        "latest_seq": 0,
        "total_flows_lifetime": 0,
        "generation": 0,
    }
    meta.update(fields)
    with open(flow_dir / "meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f)


def _write_detail(flow_dir, flow_id: str, detail: dict) -> None:
    details_dir = flow_dir / "details"
    details_dir.mkdir(parents=True, exist_ok=True)
    with open(details_dir / f"{flow_id}.json", "w", encoding="utf-8") as f:
        json.dump(detail, f)


# =============================================================================
# query_flows -- since_cursor mode
# =============================================================================


def test_since_cursor_advances_across_calls(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    for seq in (1, 2, 3):
        _write_flow(flow_dir, seq)
    _write_meta(flow_dir, earliest_seq=1, latest_seq=3)

    first = flow_log.query_flows(flow_dir, since_cursor=0)
    assert [f["seq"] for f in first["flows"]] == [1, 2, 3]
    assert first["next_cursor"] == 3

    _write_flow(flow_dir, 4)
    _write_meta(flow_dir, earliest_seq=1, latest_seq=4)

    second = flow_log.query_flows(flow_dir, since_cursor=first["next_cursor"])
    assert [f["seq"] for f in second["flows"]] == [4]
    assert second["next_cursor"] == 4


def test_since_cursor_zero_returns_from_the_very_start(tmp_path):
    """since_cursor=0 must be treated as "given", not falsy/omitted."""
    flow_dir = tmp_path / "mitm_flows"
    _write_flow(flow_dir, 1)
    _write_meta(flow_dir, earliest_seq=1, latest_seq=1)

    result = flow_log.query_flows(flow_dir, since_cursor=0)

    assert result["mode"] == "since_cursor"
    assert [f["seq"] for f in result["flows"]] == [1]


def test_no_new_flows_returns_empty_with_same_cursor(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    _write_flow(flow_dir, 1)
    _write_meta(flow_dir, earliest_seq=1, latest_seq=1)

    result = flow_log.query_flows(flow_dir, since_cursor=1)

    assert result["flows"] == []
    assert result["count"] == 0
    assert result["next_cursor"] == 1
    assert result["truncated"] is False


def test_gap_reported_when_cursor_predates_earliest_available(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    for seq in (50, 51, 52):
        _write_flow(flow_dir, seq)
    _write_meta(flow_dir, earliest_seq=50, latest_seq=52)

    result = flow_log.query_flows(flow_dir, since_cursor=10)

    assert result["gap_before_cursor"] is True
    assert result["earliest_available_seq"] == 50


def test_no_gap_reported_when_cursor_is_current(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    _write_flow(flow_dir, 1)
    _write_meta(flow_dir, earliest_seq=1, latest_seq=1)

    result = flow_log.query_flows(flow_dir, since_cursor=1)

    assert result["gap_before_cursor"] is False


def test_no_gap_reported_at_exact_retention_boundary(tmp_path):
    # since_cursor == earliest_seq - 1 asks for everything from earliest_seq
    # onward, which is exactly what's retained -- nothing was actually
    # dropped, so this must NOT be reported as a gap (regression for an
    # off-by-one: earliest_seq - 1 is the boundary, not earliest_seq itself).
    flow_dir = tmp_path / "mitm_flows"
    for seq in (50, 51, 52):
        _write_flow(flow_dir, seq)
    _write_meta(flow_dir, earliest_seq=50, latest_seq=52)

    result = flow_log.query_flows(flow_dir, since_cursor=49)

    assert result["gap_before_cursor"] is False


def test_gap_reported_one_past_the_retention_boundary(tmp_path):
    # since_cursor == earliest_seq - 2 skips exactly one retained-but-older
    # seq that's already gone -- a genuine gap, one step past the boundary
    # tested above.
    flow_dir = tmp_path / "mitm_flows"
    for seq in (50, 51, 52):
        _write_flow(flow_dir, seq)
    _write_meta(flow_dir, earliest_seq=50, latest_seq=52)

    result = flow_log.query_flows(flow_dir, since_cursor=48)

    assert result["gap_before_cursor"] is True


# =============================================================================
# query_flows -- time_range mode
# =============================================================================


def test_time_range_is_inclusive_start_exclusive_end(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    _write_flow(flow_dir, 1, ts_end=100.0)
    _write_flow(flow_dir, 2, ts_end=200.0)
    _write_flow(flow_dir, 3, ts_end=300.0)
    _write_meta(flow_dir, earliest_seq=1, latest_seq=3)

    result = flow_log.query_flows(
        flow_dir, start_time=_iso(100.0), end_time=_iso(300.0)
    )

    assert [f["seq"] for f in result["flows"]] == [1, 2]
    assert result["mode"] == "time_range"


def test_time_range_with_only_start_time_is_open_ended(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    _write_flow(flow_dir, 1, ts_end=100.0)
    _write_flow(flow_dir, 2, ts_end=200.0)
    _write_meta(flow_dir, earliest_seq=1, latest_seq=2)

    result = flow_log.query_flows(flow_dir, start_time=_iso(150.0))

    assert [f["seq"] for f in result["flows"]] == [2]


# =============================================================================
# query_flows -- last_n mode (neither cursor nor time range given)
# =============================================================================


def test_last_n_mode_returns_most_recent_flows(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    for seq in range(1, 6):
        _write_flow(flow_dir, seq)
    _write_meta(flow_dir, earliest_seq=1, latest_seq=5)

    result = flow_log.query_flows(flow_dir, limit=2)

    assert result["mode"] == "last_n"
    assert [f["seq"] for f in result["flows"]] == [4, 5]
    assert result["truncated"] is True


def test_hard_limit_cap_enforced_even_if_larger_limit_requested(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    records = [_record(seq) for seq in range(1, 2501)]
    _write_flows_bulk(flow_dir, records)
    _write_meta(flow_dir, earliest_seq=1, latest_seq=2500)

    result = flow_log.query_flows(flow_dir, limit=999_999)

    assert result["count"] == flow_log.HARD_LIMIT_CAP
    assert len(result["flows"]) == flow_log.HARD_LIMIT_CAP
    assert result["truncated"] is True


# =============================================================================
# query_flows -- app_filter
# =============================================================================


def test_app_filter_only_includes_matching_flows(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    _write_flow(flow_dir, 1, app="com.a")
    _write_flow(flow_dir, 2, app="com.b")
    _write_flow(flow_dir, 3, app="com.a")
    _write_meta(flow_dir, earliest_seq=1, latest_seq=3)

    result = flow_log.query_flows(flow_dir, since_cursor=0, app_filter="com.a")

    assert [f["seq"] for f in result["flows"]] == [1, 3]


# =============================================================================
# Cursor cache
# =============================================================================


def test_cursor_cache_hit_avoids_a_full_rescan(tmp_path, monkeypatch):
    flow_dir = tmp_path / "mitm_flows"
    for seq in (1, 2, 3):
        _write_flow(flow_dir, seq)
    _write_meta(flow_dir, earliest_seq=1, latest_seq=3)

    calls: list[int] = []
    real_read_records = flow_log._read_records

    def spy(log_path, start_offset):
        calls.append(start_offset)
        return real_read_records(log_path, start_offset)

    monkeypatch.setattr(flow_log, "_read_records", spy)

    first = flow_log.query_flows(flow_dir, since_cursor=0)
    assert calls == [0]  # first call in this process: full scan from 0

    second = flow_log.query_flows(flow_dir, since_cursor=first["next_cursor"])
    assert second["flows"] == []
    # Cache hit: the second call must seek to a nonzero cached offset, not
    # rescan from the start of the file again.
    assert calls[-1] != 0


def test_cursor_cache_invalidated_after_generation_bump(tmp_path, monkeypatch):
    """Regression: a retention trim bumps `generation` and rewrites every
    surviving record's byte offset. A cache hit that ignored this would
    seek to a stale, wrong offset in the rewritten file.
    """
    flow_dir = tmp_path / "mitm_flows"
    for seq in (1, 2, 3):
        _write_flow(flow_dir, seq)
    _write_meta(flow_dir, earliest_seq=1, latest_seq=3, generation=0)

    calls: list[int] = []
    real_read_records = flow_log._read_records

    def spy(log_path, start_offset):
        calls.append(start_offset)
        return real_read_records(log_path, start_offset)

    monkeypatch.setattr(flow_log, "_read_records", spy)

    first = flow_log.query_flows(flow_dir, since_cursor=0)
    assert first["next_cursor"] == 3

    # Simulate a retention trim: rewrite flows.jsonl (dropping seq 1, 2) and
    # bump generation -- this moves seq 3's byte offset.
    _write_flows_bulk(flow_dir, [_record(3)])
    _write_meta(flow_dir, earliest_seq=3, latest_seq=3, generation=1)

    calls.clear()
    second = flow_log.query_flows(flow_dir, since_cursor=3)

    # Must have forced a full rescan (offset 0), not trusted the stale
    # cached offset from before the trim.
    assert calls == [0]
    assert second["flows"] == []
    assert second["next_cursor"] == 3


# =============================================================================
# read_flow_detail
# =============================================================================


def _sample_detail(flow_id: str) -> dict:
    return {
        "id": flow_id,
        "request_headers": [["Host", "example.com"]],
        "response_headers": [["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"]],
        "request_body": {
            "content": "",
            "encoding": "utf-8",
            "truncated": False,
            "size_bytes": 0,
            "bytes_read": 0,
        },
        "response_body": {
            "content": "0123456789",
            "encoding": "utf-8",
            "truncated": False,
            "size_bytes": 10,
            "bytes_read": 10,
        },
        "error": None,
    }


def test_read_flow_detail_returns_all_fields_by_default(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    _write_detail(flow_dir, "flow-1", _sample_detail("flow-1"))

    detail = flow_log.read_flow_detail(flow_dir, "flow-1")

    assert detail["id"] == "flow-1"
    assert detail["response_body"]["content"] == "0123456789"


def test_read_flow_detail_further_truncates_body_below_captured_size(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    _write_detail(flow_dir, "flow-1", _sample_detail("flow-1"))

    detail = flow_log.read_flow_detail(flow_dir, "flow-1", max_body_bytes=4)

    body = detail["response_body"]
    assert body["truncated"] is True
    assert body["bytes_read"] == 4
    assert body["content"] == "0123"
    assert body["size_bytes"] == 10  # true captured size is unchanged


def test_read_flow_detail_max_body_bytes_cannot_retrieve_more_than_captured(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    _write_detail(flow_dir, "flow-1", _sample_detail("flow-1"))

    detail = flow_log.read_flow_detail(flow_dir, "flow-1", max_body_bytes=999_999)

    assert detail["response_body"]["bytes_read"] == 10
    assert detail["response_body"]["content"] == "0123456789"


def test_read_flow_detail_returns_none_for_unknown_flow_id(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    flow_dir.mkdir(parents=True)

    assert flow_log.read_flow_detail(flow_dir, "no-such-flow") is None


def test_read_flow_detail_rejects_relative_path_traversal(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    flow_dir.mkdir(parents=True)
    secret = tmp_path / "secret.json"
    with open(secret, "w", encoding="utf-8") as f:
        json.dump({"super": "secret data"}, f)

    assert flow_log.read_flow_detail(flow_dir, "../secret") is None


def test_read_flow_detail_rejects_absolute_path_override(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    flow_dir.mkdir(parents=True)
    secret = tmp_path / "secret.json"
    with open(secret, "w", encoding="utf-8") as f:
        json.dump({"super": "secret data"}, f)

    assert flow_log.read_flow_detail(flow_dir, str(tmp_path / "secret")) is None


def test_read_flow_detail_rejects_flow_id_containing_slash(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    _write_detail(flow_dir, "flow-1", _sample_detail("flow-1"))

    assert flow_log.read_flow_detail(flow_dir, "details/flow-1") is None


def test_read_flow_detail_still_reads_a_legitimate_flow_id(tmp_path):
    # Regression guard for the confinement fix above: a normal, real
    # (mitmproxy-UUID-shaped) flow_id must still resolve correctly.
    flow_dir = tmp_path / "mitm_flows"
    _write_detail(flow_dir, "6ba7b810-9dad-11d1-80b4-00c04fd430c8", _sample_detail("x"))

    detail = flow_log.read_flow_detail(flow_dir, "6ba7b810-9dad-11d1-80b4-00c04fd430c8")

    assert detail is not None
    assert detail["id"] == "x"


def test_read_flow_detail_part_headers_only_excludes_body(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    _write_detail(flow_dir, "flow-1", _sample_detail("flow-1"))

    detail = flow_log.read_flow_detail(flow_dir, "flow-1", part="request_headers")

    assert detail == {"id": "flow-1", "request_headers": [["Host", "example.com"]]}
    assert "request_body" not in detail
    assert "response_body" not in detail


def test_read_flow_detail_part_response_includes_headers_and_body(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    _write_detail(flow_dir, "flow-1", _sample_detail("flow-1"))

    detail = flow_log.read_flow_detail(flow_dir, "flow-1", part="response")

    assert detail["response_headers"] == [["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"]]
    assert detail["response_body"]["content"] == "0123456789"
    assert "request_headers" not in detail


# =============================================================================
# clear_flows
# =============================================================================


def test_clear_flows_preserves_latest_seq_resets_earliest_seq(tmp_path):
    flow_dir = tmp_path / "mitm_flows"
    _write_flow(flow_dir, 1)
    _write_flow(flow_dir, 2)
    _write_detail(flow_dir, "flow-1", _sample_detail("flow-1"))
    _write_detail(flow_dir, "flow-2", _sample_detail("flow-2"))
    _write_meta(flow_dir, earliest_seq=1, latest_seq=2, total_flows_lifetime=2)

    cleared_count = flow_log.clear_flows(flow_dir)

    assert cleared_count == 2
    assert not (flow_dir / "flows.jsonl").exists()
    assert list((flow_dir / "details").glob("*.json")) == []

    meta = flow_log.read_meta(flow_dir)
    assert meta["latest_seq"] == 2
    assert meta["earliest_seq"] is None
    assert meta["total_flows_lifetime"] == 2


def test_clear_flows_on_empty_dir_returns_zero(tmp_path):
    flow_dir = tmp_path / "mitm_flows"

    assert flow_log.clear_flows(flow_dir) == 0
