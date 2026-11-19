"""Tests for sandroid.ai.tools.lens_rows (the AI row highlight tools).

Rows come from a temporary session flow log (the no-lens fallback), from fake
lens row sources, or from a fake monitor controller. The classifier's model is
a scripted fake client behind a real gateway; nothing touches a device or the
network.
"""

from __future__ import annotations

import json
import re
import threading

import pytest

from sandroid.ai import agents, loop
from sandroid.ai.agents import Gateway, GatewayClient
from sandroid.ai.client import StreamChunk, StreamError, Usage
from sandroid.ai.loop import RunContext
from sandroid.ai.tools import lens_rows
from sandroid.ai.tools.registry import RiskTier, ToolError, get_tool_registry
from sandroid.ai.tools.toolsets import LONG_TIMEOUT_S, TOOLSET_TABLE
from sandroid.services import mitmproxy_flow_log
from sandroid.services import row_highlights as rh

# -- fixtures ---------------------------------------------------------------------------


def _record(seq, fid, method, host, path, status, **extra):
    rec = {
        "seq": seq,
        "id": fid,
        "ts_start": 1000.0 + seq,
        "ts_end": 1000.5 + seq,
        "method": method,
        "host": host,
        "path": path,
        "status_code": status,
        "error": None,
        "request_bytes": extra.pop("request_bytes", 10),
        "response_bytes": extra.pop("response_bytes", 100),
        "app": extra.pop("app", "com.example"),
        "request_content_type": extra.pop("req_type", None),
        "response_content_type": extra.pop("resp_type", None),
    }
    rec.update(extra)
    return rec


def _body(content, encoding="utf-8", size=None):
    return {
        "content": content,
        "encoding": encoding,
        "truncated": False,
        "size_bytes": size if size is not None else len(content),
        "bytes_read": len(content),
    }


@pytest.fixture
def flow_dir(tmp_path, monkeypatch):
    d = tmp_path / "mitm_flows"
    (d / "details").mkdir(parents=True)
    records = [
        _record(
            1,
            "a1",
            "POST",
            "api.example.com",
            "/v1/track?imei=3567",
            200,
            req_type="application/json",
            resp_type="application/json",
            request_bytes=300,
        ),
        _record(
            2,
            "a2",
            "GET",
            "cdn.example.org",
            "/img.png",
            200,
            resp_type="image/png",
            response_bytes=34000,
        ),
        _record(
            3,
            "a3",
            "POST",
            "other.net",
            "/login",
            401,
            req_type="application/x-www-form-urlencoded",
            app="com.other",
        ),
        _record(4, "tls-4", "TLS", "pinned.example.com", "", None, kind="tls"),
    ]
    with open(d / "flows.jsonl", "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    details = {
        "a1": {
            "id": "a1",
            "request_headers": [
                ["Authorization", "Bearer s3cr3t"],
                ["Content-Type", "application/json"],
            ],
            "response_headers": [["Content-Type", "application/json"]],
            "request_body": _body(json.dumps({"email": "alice@example.com"})),
            "response_body": _body('{"ok": true}'),
        },
        "a2": {
            "id": "a2",
            "request_headers": [["Accept", "image/*"]],
            "response_headers": [["Content-Type", "image/png"]],
            "request_body": _body(""),
            "response_body": _body("iVBORw0KGgo=", "base64", 34000),
        },
        "a3": {
            "id": "a3",
            "request_headers": [["Content-Type", "application/x-www-form-urlencoded"]],
            "response_headers": [],
            "request_body": _body("user=bob&pass=hunter2"),
            "response_body": _body("denied"),
        },
    }
    for fid, detail in details.items():
        (d / "details" / f"{fid}.json").write_text(json.dumps(detail))
    monkeypatch.setattr(mitmproxy_flow_log, "resolve_flow_dir", lambda: d)
    mitmproxy_flow_log._CURSOR_CACHE.clear()
    return d


@pytest.fixture
def store(tmp_path, monkeypatch):
    """A fresh singleton store bound to a temp session folder."""
    session = tmp_path / "session"
    monkeypatch.setattr("sandroid.ai.results.session_root", lambda: session)
    monkeypatch.setattr("sandroid.core.timeline.emit", lambda *a, **k: None)
    rh.reset_for_tests()
    instance = rh.get_row_highlights()
    yield instance
    rh.reset_for_tests()


def _as_subagent():
    return loop._current_run_context.set(RunContext(agent_id="a-re-abcdef"))


# -- table / exposure ---------------------------------------------------------------------


def test_toolset_entries_and_risk():
    for name in ("find_rows", "classify_rows", "highlight_rows", "clear_highlights"):
        assert TOOLSET_TABLE[name].core is True
        assert TOOLSET_TABLE[name].toolset == "lenses"
    assert TOOLSET_TABLE["get_rows"].core is False
    assert TOOLSET_TABLE["classify_rows"].timeout_s >= LONG_TIMEOUT_S
    reg = get_tool_registry()
    for name in (
        "find_rows",
        "classify_rows",
        "highlight_rows",
        "clear_highlights",
        "get_rows",
    ):
        spec = reg.get_spec(name)
        assert spec.risk == RiskTier.READ_ONLY
        assert not spec.resources


def test_orchestrator_only_tools_are_hidden_from_subagents():
    reg = get_tool_registry()
    names = {s.name for s in reg.specs() if agents.RESEARCHER.allows(s)}
    assert {"find_rows", "get_rows"} <= names
    assert not names & {"classify_rows", "highlight_rows", "clear_highlights"}
    assert {"classify_rows", "highlight_rows", "clear_highlights"} <= (
        agents.ORCHESTRATOR_ONLY_TOOL_NAMES
    )


def test_mutating_tools_refuse_in_a_subagent(store, flow_dir):
    token = _as_subagent()
    try:
        for call in (
            lambda: lens_rows.highlight_rows("network", keys=["a1"], label="x"),
            lambda: lens_rows.clear_highlights(),
            lambda: lens_rows.classify_rows("network", "pii"),
            lambda: lens_rows.find_rows(
                "network", {"method": ["POST"]}, apply="filter"
            ),
        ):
            with pytest.raises(ToolError) as err:
                call()
            assert err.value.code == "denied"
        # Reading is fine.
        assert lens_rows.find_rows("network", {"method": ["POST"]})["matched"] == 2
    finally:
        loop._current_run_context.reset(token)
    assert store.sets() == []


# -- find_rows: where predicates ------------------------------------------------------------


@pytest.mark.parametrize(
    ("where", "expected"),
    [
        ({"method": ["post"]}, ["a1", "a3"]),
        ({"method": "GET"}, ["a2"]),
        ({"host_glob": ["*.example.com"]}, ["a1"]),
        ({"path_glob": ["/v1/*"]}, ["a1"]),
        ({"path_glob": ["img.png"]}, ["a2"]),
        ({"url_regex": r"track\?imei=\d+"}, ["a1"]),
        ({"status": "4xx"}, ["a3"]),
        ({"status": [200]}, ["a1", "a2"]),
        ({"content_type_glob": "*json*"}, ["a1"]),
        ({"app": "com.other"}, ["a3"]),
        ({"min_bytes": 1000}, ["a2"]),
        ({"max_bytes": 110}, ["a3"]),
        ({"kind": "flow"}, ["a1", "a2", "a3"]),
        ({"text": "OTHER.NET"}, ["a3"]),
        ({"body_contains": "alice@"}, ["a1"]),
        ({"body_contains": "hunter2", "method": ["POST"]}, ["a3"]),
        ({"header_contains": "authorization"}, ["a1"]),
        ({"body_contains": r"pass=\w+", "regex": True}, ["a3"]),
    ],
)
def test_find_rows_network_predicates(store, flow_dir, where, expected):
    result = lens_rows.find_rows("network", where)
    assert result["source"] == "flow_log"
    assert result["keys"] == expected
    assert result["scanned"] == 3  # the TLS failure row (no flow id in the lens)
    assert result["matched"] == len(expected)
    assert f"{len(expected)} of 3 network rows" in result["summary"]
    assert "highlight_id" not in result


def test_find_rows_rejects_unknown_fields_and_bad_regex(store, flow_dir):
    with pytest.raises(ToolError) as err:
        lens_rows.find_rows("network", {"verb": "POST"})
    assert err.value.code == "invalid_arguments"
    with pytest.raises(ToolError):
        lens_rows.find_rows("network", {"url_regex": "("})
    with pytest.raises(ToolError):
        lens_rows.find_rows("files", {"method": ["GET"]})
    with pytest.raises(ToolError):
        lens_rows.find_rows("timeline", {})


def test_find_rows_apply_creates_extends_and_filters(store, flow_dir):
    result = lens_rows.find_rows(
        "network", {"method": ["POST"]}, apply="highlight", label="POST requests"
    )
    hid = result["highlight_id"]
    hs = store.get(hid)
    assert hs.origin == "structural"
    assert hs.label == "POST requests"
    assert set(hs.reasons) == {"a1", "a3"}
    assert hs.basis["through_seq"] == 3
    assert store.filter_set("network") is None
    assert "Highlighted 2 of 3" in result["summary"]
    more = lens_rows.find_rows(
        "network", {"method": ["GET"]}, apply="filter", highlight_id=hid
    )
    assert more["highlight_id"] == hid
    assert set(store.keys(hid)) == {"a1", "a3", "a2"}
    assert store.filter_set("network") == hid
    # Session persistence: <session>/ai/highlights.json
    path = store.path
    assert path is not None
    assert store.flush()
    assert path.is_file()
    nothing = lens_rows.find_rows("network", {"method": ["PUT"]}, apply="highlight")
    assert nothing["highlight_id"] is None
    assert len(store.sets("network")) == 1


def test_find_rows_reports_full_limit_error(store, flow_dir):
    for i in range(rh.MAX_SETS_PER_LENS):
        store.create("network", f"s{i}")
    with pytest.raises(ToolError) as err:
        lens_rows.find_rows("network", {"method": ["GET"]}, apply="highlight")
    assert err.value.code == "invalid_arguments"
    assert "clear_highlights" in err.value.hint


# -- lens row sources --------------------------------------------------------------------------


def test_lens_source_wins_and_counts_hidden_rows(store, flow_dir):
    rows = [
        {"key": "f1", "flow_id": "a1", "shown": True, "method": "POST", "host": "h"},
        {"key": "f3", "flow_id": "a3", "shown": False, "method": "POST", "host": "h"},
        {"key": "t1", "flow_id": None, "shown": True, "method": "TLS", "host": "h"},
    ]
    store.register_row_source("network", lambda: rows, None)
    result = lens_rows.find_rows("network", {"method": ["POST"]})
    assert result["source"] == "lens"
    assert result["keys"] == ["a1", "a3"]  # flow ids; the stdout TLS row is skipped
    assert result["hidden_by_lens_filters"] == 1
    shown = lens_rows.find_rows("network", {"method": ["POST"]}, scope="shown")
    assert shown["keys"] == ["a1"]
    # Bodies are still read through the flow log by flow id.
    assert lens_rows.find_rows("network", {"body_contains": "alice"})["keys"] == ["a1"]


FILE_ROWS = [
    {
        "key": "/data/user/0/com.x/shared_prefs/p.xml",
        "path": "/data/user/0/com.x/shared_prefs/p.xml",
        "shown": True,
        "ops": "CM",
        "count": 5,
        "processes": ["com.x"],
        "watched": True,
        "app": "com.x",
        "review_kind": None,
    },
    {
        "key": "/data/data/com.x/databases/c.db",
        "path": "/data/data/com.x/databases/c.db",
        "shown": False,
        "ops": "D",
        "count": 1,
        "processes": ["android.process.acore"],
        "watched": False,
        "app": "com.x",
        "review_kind": "deleted",
    },
    {
        "key": "/data/data/com.x/cache/",
        "path": "/data/data/com.x/cache/",
        "shown": True,
    },
    {"key": "★ idle", "path": "★ idle", "shown": True},
]


@pytest.mark.parametrize(
    ("where", "expected"),
    [
        ({"path_glob": ["*.xml"]}, ["/data/data/com.x/shared_prefs/p.xml"]),
        ({"path_glob": ["databases/*"]}, ["/data/data/com.x/databases/c.db"]),
        ({"ops": "d"}, ["/data/data/com.x/databases/c.db"]),
        ({"process": "acore"}, ["/data/data/com.x/databases/c.db"]),
        ({"watched": True}, ["/data/data/com.x/shared_prefs/p.xml"]),
        ({"min_count": 2}, ["/data/data/com.x/shared_prefs/p.xml"]),
        ({"review_kind": ["deleted"]}, ["/data/data/com.x/databases/c.db"]),
        ({"app": "com.*", "text": "prefs"}, ["/data/data/com.x/shared_prefs/p.xml"]),
    ],
)
def test_find_rows_files_predicates(store, where, expected):
    store.register_row_source("files", lambda: FILE_ROWS, None)
    result = lens_rows.find_rows("files", where)
    assert result["keys"] == expected
    assert result["scanned"] == 2  # group and fold rows are not rows here


def test_files_content_contains_reads_local_copies(store, monkeypatch):
    from sandroid.ai import row_classifier

    store.register_row_source("files", lambda: FILE_ROWS, None)
    monkeypatch.setattr(
        row_classifier,
        "local_file_content",
        lambda key: ("content: email" if key.endswith(".xml") else None, "content"),
    )
    result = lens_rows.find_rows("files", {"content_contains": "EMAIL"})
    assert result["keys"] == ["/data/data/com.x/shared_prefs/p.xml"]


def test_files_fallback_from_the_monitor_history(store, monkeypatch):
    events = [
        {
            "path": "/data/user/0/com.x/a.xml",
            "event_type": "CREATE",
            "process": "p1",
            "timestamp": 1,
        },
        {
            "path": "/data/data/com.x/a.xml",
            "event_type": "MODIFY",
            "process": "p2",
            "timestamp": 2,
        },
        {
            "path": "/sdcard/b.txt",
            "event_type": "DELETE",
            "process": "p1",
            "timestamp": 3,
        },
    ]

    class FakeController:
        def get_recent_events(self, since_seq=None, limit=200):
            return {"events": events}

    monkeypatch.setattr(
        "sandroid.tui.controller_registry.get_monitor_controller", FakeController
    )
    rows, source = lens_rows.collect_rows("files")
    assert source == "monitor"
    by_key = {r["key"]: r for r in rows}
    assert set(by_key) == {"/data/data/com.x/a.xml", "/sdcard/b.txt"}
    a = by_key["/data/data/com.x/a.xml"]
    assert (a["ops"], a["count"], a["processes"]) == ("CM", 2, ["p1", "p2"])
    assert (a["first"], a["last"]) == (1, 2)


# -- classify_rows -------------------------------------------------------------------------------

_KEY_RE = re.compile(r'<row id="([^"]*)">')


class PiiClient:
    """Matches rows whose digest mentions an email or a password."""

    model = "fake"

    def __init__(self, cancel_after: threading.Event | None = None):
        self.calls: list = []
        self.lock = threading.Lock()
        self.cancel_after = cancel_after

    def stream(self, messages, tools=None, *, cancel_event=None, **kwargs):
        with self.lock:
            self.calls.append(messages)
        content = messages[1]["content"]
        matches = []
        for block in content.split("<row id=")[1:]:
            rid = json.loads(block.split(">", 1)[0])
            if "@" in block or "pass=" in block:
                matches.append({"id": rid, "reason": "body holds personal data"})
        if self.cancel_after is not None:
            self.cancel_after.set()
        yield StreamChunk("text", text=json.dumps({"matches": matches}))
        yield StreamChunk("done", usage=Usage(prompt_tokens=50, completion_tokens=5))


@pytest.fixture
def run_ctx():
    """An orchestrator run context with an event list, inside a tool call."""
    events: list = []
    ctx = RunContext(sink=events.append)
    t1 = loop._current_run_context.set(ctx)
    t2 = loop._current_call.set(("call-1", ctx))
    yield ctx, events
    loop._current_call.reset(t2)
    loop._current_run_context.reset(t1)


def _use_client(monkeypatch, client, gateway=None):
    gateway = gateway or Gateway(4)
    monkeypatch.setattr(
        lens_rows,
        "classifier_client",
        lambda: GatewayClient(client, gateway, reserved=False),
    )
    return gateway


def test_classify_rows_highlights_live_and_reports(
    store, flow_dir, run_ctx, monkeypatch
):
    ctx, events = run_ctx
    client = PiiClient()
    gateway = _use_client(monkeypatch, client)
    added: list[dict] = []
    real_add = store.add

    def spy_add(set_id, reasons, **kw):
        added.append(dict(reasons))
        return real_add(set_id, reasons, **kw)

    monkeypatch.setattr(store, "add", spy_add)
    result = lens_rows.classify_rows(
        "network", "personal data", where={"kind": ["flow"]}, apply="filter"
    )
    hid = result["highlight_id"]
    assert result["matched"] == 2
    assert result["scanned"] == 3
    assert result["candidates"] == 3
    assert result["partial"] is False
    assert result["hidden_by_lens_filters"] == 0
    assert result["bytes_sent"] > 0
    assert result["model_tokens"] == 55
    assert "Filtered to 2 of 3 network rows" in result["summary"]
    assert {s["key"] for s in result["samples"]} == {"a1", "a3"}
    assert result["samples"][0]["row"].startswith("POST api.example.com/v1/track")
    assert added  # rows were added per batch, not at the end
    hs = store.get(hid)
    assert hs.origin == "ai"
    assert hs.complete is True
    assert hs.stats["bytes_sent"] == result["bytes_sent"]
    assert set(hs.reasons) == {"a1", "a3"}
    assert store.filter_set("network") == hid
    # Secrets never reach the model.
    sent = json.dumps(client.calls)
    assert "s3cr3t" not in sent
    assert "[Bearer, 13 chars]" in sent
    assert "[binary 33 kB image/png]" in sent
    assert gateway.peak_agents_in_use <= 3
    progress = [e for e in events if e.type == "tool_progress"]
    assert progress[0].payload["call_id"] == "call-1"
    assert progress[0].payload["done"] == 0
    assert progress[-1].payload == {
        "call_id": "call-1",
        "done": 3,
        "total": 3,
        "matched": 2,
        "note": "classified",
    }


def test_classify_rows_with_no_match_drops_the_empty_set(
    store, flow_dir, run_ctx, monkeypatch
):
    _use_client(monkeypatch, PiiClient())
    result = lens_rows.classify_rows("network", "tracking", where={"method": ["GET"]})
    assert result["matched"] == 0
    assert result["highlight_id"] is None
    assert store.sets() == []


def test_classify_rows_limits(store, flow_dir, run_ctx, monkeypatch):
    _use_client(monkeypatch, PiiClient())
    with pytest.raises(ToolError) as err:
        lens_rows.classify_rows("network", "pii", max_rows=2)
    assert err.value.code == "invalid_arguments"
    assert "narrow with where" in err.value.hint
    assert err.value.details["candidates"] == 3
    with pytest.raises(ToolError):
        lens_rows.classify_rows("network", "pii", max_rows=5000)
    with pytest.raises(ToolError):
        lens_rows.classify_rows("network", "  ")
    nothing = lens_rows.classify_rows("network", "pii", where={"method": ["PUT"]})
    assert nothing["scanned"] == 0
    assert nothing["highlight_id"] is None


def test_classify_rows_cancel_keeps_a_partial_set(
    store, flow_dir, run_ctx, monkeypatch
):
    ctx, _events = run_ctx
    _use_client(monkeypatch, PiiClient(cancel_after=ctx.cancel_event))

    class Cfg:
        concurrency = 1
        batch_rows = 1
        batch_tokens = 24000
        max_rows = 1000
        max_tokens = 4096

    monkeypatch.setattr(lens_rows, "_row_classify_cfg", lambda: Cfg)
    result = lens_rows.classify_rows("network", "personal data", keys=["a1", "a3"])
    assert result["partial"] is True
    assert result["stop_reason"] == "cancelled"
    assert result["scanned"] == 1
    hs = store.get(result["highlight_id"])
    assert hs.complete is False
    assert set(hs.reasons) == {"a1"}


def test_classify_rows_reports_unknown_keys_and_needs_a_client(
    store, flow_dir, run_ctx, monkeypatch
):
    monkeypatch.setattr(lens_rows, "classifier_client", lambda: None)
    with pytest.raises(ToolError) as err:
        lens_rows.classify_rows("network", "pii", keys=["a1"])
    assert err.value.code == "tool_failed"
    _use_client(monkeypatch, PiiClient())
    result = lens_rows.classify_rows("network", "pii", keys=["a1", "zz"], apply="none")
    assert result["unknown_keys"] == ["zz"]
    assert result["highlight_id"] is None
    assert result["matched"] == 1
    assert result["verdicts"] == [
        {"key": "a1", "match": True, "reason": "body holds personal data"}
    ]


def test_classifier_client_uses_the_session_client_unreserved(monkeypatch):
    class Session:
        thread_id = "t-1"
        client = object()

    manager = agents.AgentManager()
    manager.attach_parent(Session)
    monkeypatch.setattr(agents, "get_agent_manager", lambda: manager)
    token = loop._current_run_context.set(RunContext(thread_id="t-1"))
    try:
        client = lens_rows.classifier_client()
    finally:
        loop._current_run_context.reset(token)
    assert isinstance(client, GatewayClient)
    assert client.inner is Session.client
    assert client.reserved is False
    assert lens_rows.classifier_client() is None  # no run context


# -- highlight_rows / clear_highlights -----------------------------------------------------------


def test_highlight_rows_create_add_remove_replace_and_mode(store, flow_dir):
    created = lens_rows.highlight_rows(
        "network",
        keys=["a1", "nope"],
        label="picked",
        reasons={"a1": "has an email"},
    )
    hid = created["highlight_id"]
    assert created["action"] == "create"
    assert created["unknown_keys"] == ["nope"]
    assert store.get(hid).reasons == {"a1": "has an email"}
    added = lens_rows.highlight_rows("network", keys=["a2"], highlight_id=hid)
    assert added["total"] == 2
    removed = lens_rows.highlight_rows(
        "network", keys=["a1"], highlight_id=hid, action="remove"
    )
    assert removed["total"] == 1
    replaced = lens_rows.highlight_rows(
        "network", keys=["a3"], highlight_id=hid, action="replace", mode="filter"
    )
    assert replaced["total"] == 1
    assert replaced["mode"] == "filter"
    assert store.filter_set("network") == hid
    back = lens_rows.highlight_rows("network", highlight_id=hid, mode="highlight")
    assert back["mode"] == "highlight"
    assert store.filter_set("network") is None
    with pytest.raises(ToolError):
        lens_rows.highlight_rows("network", label="nothing")
    with pytest.raises(ToolError):
        lens_rows.highlight_rows("files", keys=["/x"], highlight_id=hid)
    unknown_only = lens_rows.highlight_rows("network", keys=["zz"], label="x")
    assert unknown_only["highlight_id"] is None
    assert unknown_only["unknown_count"] == 1


def test_clear_highlights(store, flow_dir):
    a = store.create("network", "a", reasons={"a1": ""})
    store.create("network", "b", reasons={"a2": ""})
    c = store.create("files", "c", reasons={"/sdcard/x": ""})
    assert lens_rows.clear_highlights(highlight_id=a.id)["cleared"] == [a.id]
    assert lens_rows.clear_highlights(lens="network")["remaining"] == [c.id]
    assert lens_rows.clear_highlights()["cleared"] == [c.id]
    with pytest.raises(ToolError):
        lens_rows.clear_highlights(highlight_id="h99")


# -- get_rows --------------------------------------------------------------------------------------


def test_get_rows_pages_and_reads_keys(store, flow_dir):
    hs = store.create("network", "x", reasons={"a1": ""})
    page = lens_rows.get_rows("network", limit=2)
    assert [r["key"] for r in page["rows"]] == ["a1", "a2"]
    assert page["next_cursor"] == 2
    assert page["total"] == 3
    assert page["rows"][0]["highlights"] == [hs.id]
    assert "[Bearer, 13 chars]" in page["rows"][0]["digest"]
    assert page["rows"][1]["content"] == "binary"
    last = lens_rows.get_rows("network", cursor=2, limit=50, include_content=False)
    assert last["next_cursor"] is None
    assert "digest" not in last["rows"][0]
    picked = lens_rows.get_rows("network", keys=["a3", "zz"])
    assert [r["key"] for r in picked["rows"]] == ["a3"]
    assert picked["unknown_keys"] == ["zz"]
    assert "user=bob; pass=hunter2" in picked["rows"][0]["digest"]
    with pytest.raises(ToolError):
        lens_rows.get_rows("network", keys=[f"k{i}" for i in range(21)])


# -- live state + session binding --------------------------------------------------------------


def test_live_state_line(store):
    from sandroid.ai.context import _describe_lens_highlights

    assert _describe_lens_highlights() is None
    store.create("network", "POST api.x", reasons={"a1": "", "a2": ""})
    hs = store.create(
        "files", "personal data", reasons={"/sdcard/x": ""}, complete=False
    )
    store.set_filter("files", hs.id)
    assert _describe_lens_highlights() == (
        'Lens highlights: Network "POST api.x" highlight 2 (h1); '
        'Files "personal data" filter 1, partial (h2).'
    )


def test_chat_session_binds_the_store_to_its_folder(store, tmp_path):
    from sandroid.ai.session import _bind_row_highlights

    other = tmp_path / "other-session"
    _bind_row_highlights(other)
    assert store.folder == other.absolute()


# -- verifier findings: backend errors -------------------------------------------------------


class _Cfg:
    concurrency = 1
    batch_rows = 1
    batch_tokens = 24000
    max_rows = 1000
    max_tokens = 4096


class ErrClient:
    """Fails every request (or only rows whose digest contains ``fail_on``)."""

    model = "fake"

    def __init__(self, message="HTTP 429 rate limited", fail_on=None):
        self.message = message
        self.fail_on = fail_on
        self.calls = 0
        self.ok = PiiClient()

    def stream(self, messages, tools=None, **kwargs):
        self.calls += 1
        if self.fail_on is None or self.fail_on in messages[1]["content"]:
            yield StreamChunk("error", error=StreamError("http", self.message))
            return
        yield from self.ok.stream(messages, tools, **kwargs)


@pytest.fixture
def one_row_batches(monkeypatch):
    from sandroid.ai import row_classifier

    monkeypatch.setattr(row_classifier, "TRANSPORT_RETRY_S", 0.0)
    monkeypatch.setattr(lens_rows, "_row_classify_cfg", lambda: _Cfg)


def test_classify_rows_backend_failure_is_an_error_not_zero_found(
    store, flow_dir, run_ctx, monkeypatch, one_row_batches
):
    client = ErrClient()
    _use_client(monkeypatch, client)
    with pytest.raises(ToolError) as err:
        lens_rows.classify_rows("network", "personal data", where={"kind": ["flow"]})
    assert err.value.code == "backend_error"
    assert "HTTP 429 rate limited" in err.value.message
    assert "none of the 3 network rows could be judged" in err.value.message
    assert err.value.details["stop_reason"] == "backend_error"
    assert client.calls == 3  # 1st batch twice, 2nd once: three in a row stop it
    assert store.sets() == []  # no empty "complete" set left behind


def test_classify_rows_reports_rows_it_could_not_judge(
    store, flow_dir, run_ctx, monkeypatch, one_row_batches
):
    _use_client(monkeypatch, ErrClient("HTTP 500 boom", fail_on="other.net"))
    result = lens_rows.classify_rows(
        "network", "personal data", where={"kind": ["flow"]}
    )
    assert result["scanned"] == 2  # the errored row is not "scanned"
    assert result["skipped"] == {"errors": 1, "not_reached": 0, "unknown_ids": 0}
    assert result["partial"] is True
    assert result["backend_error"] == "HTTP 500 boom"
    assert "1 rows could not be judged (backend error: HTTP 500 boom)" in (
        result["summary"]
    )
    hs = store.get(result["highlight_id"])
    assert hs.complete is False
    assert hs.stats["errors"] == 1
    assert set(hs.reasons) == {"a1"}


# -- verifier findings: the set goes away mid-run ----------------------------------------------


def test_classify_rows_survives_the_analyst_clearing_the_set(
    store, flow_dir, run_ctx, monkeypatch
):
    class ClearingClient(PiiClient):
        def stream(self, messages, tools=None, **kw):
            store.clear("network")  # the analyst pressed X
            yield from super().stream(messages, tools, **kw)

    _use_client(monkeypatch, ClearingClient())
    result = lens_rows.classify_rows(
        "network", "personal data", where={"kind": ["flow"]}
    )
    assert result["highlight_id"] is None
    assert result["note"] == lens_rows.NOTE_CLEARED
    assert result["matched"] == 2  # the stats survive
    assert result["scanned"] == 3
    assert {v["key"] for v in result["verdicts"]} == {"a1", "a3"}
    assert "cleared by the analyst" in result["summary"]
    assert store.sets() == []


def test_find_and_highlight_rows_survive_a_cleared_set(store, flow_dir, monkeypatch):
    hid = lens_rows.find_rows("network", {"method": ["POST"]}, apply="highlight")[
        "highlight_id"
    ]
    real_add = store.add

    def add_after_clear(set_id, reasons, **kw):
        store.clear("network")
        return real_add(set_id, reasons, **kw)

    monkeypatch.setattr(store, "add", add_after_clear)
    found = lens_rows.find_rows(
        "network", {"method": ["GET"]}, apply="filter", highlight_id=hid
    )
    assert found["highlight_id"] is None
    assert found["note"] == lens_rows.NOTE_CLEARED
    assert found["matched"] == 1
    hid2 = store.create("network", "again", reasons={"a1": ""}).id
    picked = lens_rows.highlight_rows("network", keys=["a2"], highlight_id=hid2)
    assert picked["highlight_id"] is None
    assert picked["note"] == lens_rows.NOTE_CLEARED


def test_classify_rows_stops_on_a_session_switch(
    store, flow_dir, run_ctx, monkeypatch, tmp_path, one_row_batches
):
    other = tmp_path / "other_session"
    prepared = rh.HighlightStore()
    prepared.bind_folder(other)
    prepared.create("network", "unrelated", reasons={"zzz": "old"})
    assert prepared.flush()

    class SwitchingClient(PiiClient):
        def stream(self, messages, tools=None, **kw):
            if not self.calls:
                store.bind_folder(other)  # the analyst opened another session
            yield from super().stream(messages, tools, **kw)

    client = SwitchingClient()
    _use_client(monkeypatch, client)
    result = lens_rows.classify_rows(
        "network", "personal data", where={"kind": ["flow"]}
    )
    assert result["stop_reason"] == "session_switched"
    assert result["partial"] is True
    assert result["highlight_id"] is None
    assert result["note"] == lens_rows.NOTE_SWITCHED
    assert len(client.calls) == 1  # the remaining batches were dropped
    assert result["matched"] == 1
    assert result["scanned"] == 1
    # The new session's h1 is untouched, in memory and on disk.
    assert [(s.id, s.label, list(s.reasons)) for s in store.sets()] == [
        ("h1", "unrelated", ["zzz"])
    ]
    assert store.flush()
    data = json.loads((other / "ai" / "highlights.json").read_text())
    assert [(s["id"], s["label"], list(s["reasons"])) for s in data["sets"]] == [
        ("h1", "unrelated", ["zzz"])
    ]


# -- verifier findings: "N new since" basis ----------------------------------------------------


def test_classify_rows_new_since_basis_covers_every_row_of_the_view(
    store, flow_dir, run_ctx, monkeypatch
):
    from sandroid.tui.widgets.highlight_bar import HighlightView

    _use_client(monkeypatch, PiiClient())
    # Only a1 (seq 1) is a candidate; a2 and a3 already existed.
    result = lens_rows.classify_rows(
        "network", "personal data", where={"host_glob": ["api.*"]}
    )
    hs = store.get(result["highlight_id"])
    assert hs.basis["through_seq"] == 3
    view = HighlightView("network")
    rows = [("a1", True, 1, 1001.5), ("a2", True, 2, 1002.5), ("a3", True, 3, 1003.5)]
    view.measure(iter(rows), live=True)
    assert view.counts[hs.id].new == 0
    view.measure(iter([*rows, ("a9", True, 4, 1004.5)]), live=True)
    assert view.counts[hs.id].new == 1


# -- verifier findings: where -------------------------------------------------------------------


def test_where_regex_is_guarded_and_bad_regex_is_explained(store, flow_dir):
    with pytest.raises(ToolError) as err:
        lens_rows.find_rows("network", {"body_contains": "(a+)+$", "regex": True})
    assert err.value.code == "invalid_arguments"
    assert "refused" in err.value.message
    with pytest.raises(ToolError) as err:
        lens_rows.find_rows("network", {"text": "([a-z]", "regex": True})
    assert "not a valid regular expression" in err.value.message
    assert "regex=true" in err.value.hint
    ok = lens_rows.find_rows("network", {"body_contains": r"pass=\w+", "regex": True})
    assert ok["keys"] == ["a3"]


def test_where_haystack_is_capped(store, monkeypatch):
    from sandroid.ai import row_classifier

    store.register_row_source("files", lambda: FILE_ROWS, None)
    big = "x" * (lens_rows.HAYSTACK_CAP + 10) + "needle"
    monkeypatch.setattr(
        row_classifier,
        "local_file_content",
        lambda key: (big if key.endswith(".xml") else "needle", "content"),
    )
    for regex in (False, True):
        result = lens_rows.find_rows(
            "files", {"content_contains": "needle", "regex": regex}
        )
        assert result["keys"] == ["/data/data/com.x/databases/c.db"]


def test_tls_rows_are_never_rows_of_the_tools(store, flow_dir):
    with pytest.raises(ToolError) as err:
        lens_rows.find_rows("network", {"kind": ["tls"]})
    assert "flow, error" in err.value.message
    assert "tls" not in lens_rows._WHERE_PROP["description"]
    rows, source = lens_rows.collect_rows("network")
    assert source == "flow_log"
    assert "tls-4" not in {r["key"] for r in rows}
    lens = [{"flow_id": "x1", "kind": "tls", "shown": True, "host": "h"}]
    store.register_row_source("network", lambda: lens, None)
    assert lens_rows.collect_rows("network") == ([], "lens")


@pytest.mark.parametrize(
    ("pattern", "canonical"),
    [
        ("/data/user/0/com.x/shared_prefs/*", "/data/data/com.x/shared_prefs/*"),
        ("/storage/emulated/0/Down*", "/sdcard/Down*"),
        ("/data/user/0/com.x/a.xml", "/data/data/com.x/a.xml"),
        ("/data/data/com.x/*.db", "/data/data/com.x/*.db"),
        ("*.xml", "*.xml"),
        ("databases/*", "databases/*"),
    ],
)
def test_path_glob_takes_the_canonical_form(pattern, canonical):
    assert lens_rows.canonical_glob(pattern) == canonical


def test_files_path_glob_matches_alias_paths(store):
    store.register_row_source("files", lambda: FILE_ROWS, None)
    result = lens_rows.find_rows(
        "files", {"path_glob": ["/data/user/0/com.x/shared_prefs/*"]}
    )
    assert result["keys"] == ["/data/data/com.x/shared_prefs/p.xml"]


# -- verifier findings: highlight_rows edge cases and caps ---------------------------------------


def test_highlight_rows_refuses_remove_and_replace_that_change_nothing(store, flow_dir):
    for action in ("remove", "replace"):
        with pytest.raises(ToolError) as err:
            lens_rows.highlight_rows("network", keys=["a1"], action=action)
        assert "needs highlight_id" in err.value.message
    assert store.sets() == []
    hid = lens_rows.highlight_rows("network", keys=["a1", "a3"], label="x")[
        "highlight_id"
    ]
    with pytest.raises(ToolError) as err:
        lens_rows.highlight_rows(
            "network", keys=["nope"], highlight_id=hid, action="replace"
        )
    assert err.value.details["unknown_keys"] == ["nope"]
    with pytest.raises(ToolError) as err:
        lens_rows.highlight_rows(
            "network", keys=["a2"], highlight_id=hid, action="remove"
        )
    assert err.value.details["unknown_keys"] == ["a2"]
    with pytest.raises(ToolError):
        lens_rows.highlight_rows("network", highlight_id=hid, action="replace")
    assert sorted(store.keys(hid)) == ["a1", "a3"]  # nothing was wiped


def test_the_row_cap_is_reported_not_silent(store, flow_dir, monkeypatch):
    monkeypatch.setattr(rh, "MAX_KEYS_PER_SET", 2)
    monkeypatch.setattr(lens_rows, "MAX_KEYS_PER_SET", 2)
    with pytest.raises(ToolError) as err:
        lens_rows.find_rows("network", {"kind": ["flow"]}, apply="highlight")
    assert "holds at most 2 rows" in err.value.message
    assert "Narrow `where`" in err.value.hint
    assert store.sets() == []
    hid = lens_rows.highlight_rows("network", keys=["a1"], label="x")["highlight_id"]
    added = lens_rows.highlight_rows("network", keys=["a2", "a3"], highlight_id=hid)
    assert added["total"] == 2
    assert added["truncated_by_cap"] == 1
    assert "1 rows not added" in added["summary"]
    store.remove_keys(hid, ["a2"])
    found = lens_rows.find_rows(
        "network", {"kind": ["flow"]}, apply="highlight", highlight_id=hid
    )
    assert found["truncated_by_cap"] == 1
    assert "1 matching rows not added" in found["summary"]
    assert len(store.keys(hid)) == 2


def test_classify_rows_reports_the_cap_in_summary_and_stats(
    store, flow_dir, run_ctx, monkeypatch
):
    monkeypatch.setattr(rh, "MAX_KEYS_PER_SET", 2)
    monkeypatch.setattr(lens_rows, "MAX_KEYS_PER_SET", 2)
    hid = store.create("network", "full", reasons={"zz": "", "a2": ""}).id
    _use_client(monkeypatch, PiiClient())
    result = lens_rows.classify_rows("network", "pii", highlight_id=hid)
    assert result["truncated_by_cap"] == 2
    assert "2 matches not added" in result["summary"]
    assert store.get(hid).stats["truncated_by_cap"] == 2


# -- verifier findings: bounded result --------------------------------------------------------------


def test_classify_rows_result_holds_at_most_max_verdicts(
    store, flow_dir, run_ctx, monkeypatch
):
    from sandroid.ai.results import ResultStore, shape_result

    monkeypatch.setattr(lens_rows, "MAX_VERDICTS", 1)
    _use_client(monkeypatch, PiiClient())
    result = lens_rows.classify_rows("network", "personal data")
    assert len(result["verdicts"]) == 1
    assert result["verdicts_truncated"] == 1
    assert len(store.keys(result["highlight_id"])) == 2  # the set has all
    # The result still goes through the result store and its preview.
    stored = ResultStore(None).put("classify_rows", {}, result)
    shaped = json.loads(shape_result(result, stored.id, cap_tokens=50))
    assert shaped.get("_rid") == stored.id or stored.id in json.dumps(shaped)


# -- E2E findings ----------------------------------------------------------------------------------


def test_where_summary_and_reasons_are_plain_words(store, flow_dir):
    result = lens_rows.find_rows(
        "network",
        {"method": ["post"], "host_glob": ["api.*", "other.*"], "body_contains": "@"},
        apply="highlight",
    )
    hs = store.get(result["highlight_id"])
    assert hs.query == "method POST, host api.* or other.*, body contains “@”"
    assert hs.reasons["a1"] == "matches " + hs.query
    assert "[" not in result["summary"]
    assert lens_rows._where_words("status", [200, "4xx"], False) == "status 200 or 4xx"
    assert lens_rows._where_words("text", "a.b", True) == "text matches “a.b”"
    assert lens_rows._where_words("min_bytes", 10, False) == "at least 10 bytes"
    assert lens_rows._where_words("watched", False, False) == "not watched"


def test_regex_outside_where_is_accepted_as_an_alias(
    store, flow_dir, run_ctx, monkeypatch
):
    found = lens_rows.find_rows("network", {"body_contains": r"pass=\w+"}, regex=True)
    assert found["keys"] == ["a3"]
    _use_client(monkeypatch, PiiClient())
    result = lens_rows.classify_rows(
        "network", "pii", where={"text": r"other\.net"}, regex=True, apply="none"
    )
    assert result["candidates"] == 1
    for name in ("find_rows", "classify_rows"):
        spec = get_tool_registry().get_spec(name)
        assert "regex" in spec.parameters["properties"]
        assert "short" in spec.parameters["properties"]
    assert (
        "short"
        in get_tool_registry().get_spec("highlight_rows").parameters["properties"]
    )


def test_tools_take_a_short_label(store, flow_dir, run_ctx, monkeypatch):
    a = lens_rows.find_rows(
        "network", {"method": ["POST"]}, apply="highlight", short="POST api"
    )
    assert store.get(a["highlight_id"]).short == "POST api"
    _use_client(monkeypatch, PiiClient())
    b = lens_rows.classify_rows("network", "personal data", short="personal")
    assert store.get(b["highlight_id"]).short == "personal"
    c = lens_rows.highlight_rows("network", keys=["a2"], label="x", short="cdn")
    assert store.get(c["highlight_id"]).short == "cdn"
    lens_rows.highlight_rows("network", highlight_id=c["highlight_id"], short="img")
    assert store.get(c["highlight_id"]).short == "img"
    # Without one, filler words are dropped from the label.
    d = lens_rows.find_rows(
        "network",
        {"status": "4xx"},
        apply="highlight",
        label="all requests to other.net",
    )
    assert store.get(d["highlight_id"]).short == "other.net"


def test_new_since_basis_counts_rows_the_tools_cannot_take(store):
    rows = [
        {"key": "f1", "flow_id": "a1", "seq": 1, "shown": True, "method": "POST"},
        {"key": None, "flow_id": None, "seq": 7, "shown": True, "kind": "tls"},
    ]
    store.register_row_source("network", lambda: rows, None)
    result = lens_rows.find_rows("network", {"method": ["POST"]}, apply="highlight")
    assert result["scanned"] == 1
    assert store.get(result["highlight_id"]).basis["through_seq"] == 7
