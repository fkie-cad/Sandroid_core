"""Tests for sandroid.ai.row_classifier: digests and the batched classifier.

The model is a scripted fake client (no network); the gateway is the real
:class:`~sandroid.ai.agents.Gateway` so slot accounting is exercised.
"""

from __future__ import annotations

import json
import re
import threading
import time

import pytest

from sandroid.ai import row_classifier as rc
from sandroid.ai.agents import Gateway, GatewayClient
from sandroid.ai.client import StreamChunk, StreamError, Usage
from sandroid.ai.prompts import ROW_CLASSIFIER_PROMPT, ROW_CLASSIFIER_RETRY

_KEY_RE = re.compile(r'<row key="([^"]*)">')


def keys_of(messages) -> list[str]:
    return _KEY_RE.findall(messages[1]["content"])


def match_all(keys, messages):
    return json.dumps({"matches": [{"key": k, "reason": "body.email"} for k in keys]})


class FakeClient:
    """Answers each request with ``reply(keys, messages)`` (thread-safe)."""

    model = "fake"

    def __init__(self, reply=match_all, delay: float = 0.0):
        self.reply = reply
        self.delay = delay
        self.calls: list[list[dict]] = []
        self.lock = threading.Lock()
        self.in_flight = 0
        self.peak = 0

    def stream(self, messages, tools=None, *, cancel_event=None, **kwargs):
        with self.lock:
            self.calls.append(messages)
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
        try:
            assert tools is None
            assert kwargs.get("temperature") == 0.0
            if self.delay:
                end = time.monotonic() + self.delay
                while time.monotonic() < end:
                    if cancel_event is not None and cancel_event.is_set():
                        yield StreamChunk("cancelled")
                        return
                    time.sleep(0.005)
            text = self.reply(keys_of(messages), messages)
            if isinstance(text, StreamChunk):
                yield text
                return
            yield StreamChunk("text", text=text)
            yield StreamChunk(
                "done",
                finish_reason="stop",
                usage=Usage(prompt_tokens=100, completion_tokens=10),
            )
        finally:
            with self.lock:
                self.in_flight -= 1


def digests(n: int, size: int = 50) -> list[rc.Digest]:
    return [rc.Digest(f"k{i}", f"row {i} " + "x" * size) for i in range(n)]


# -- batching -------------------------------------------------------------------------


def test_batches_split_by_rows_and_by_tokens():
    by_rows = rc.make_batches(digests(95), batch_rows=40, batch_tokens=10**6)
    assert [len(b) for b in by_rows] == [40, 40, 15]
    # ~1000 tokens = 3500 chars; each digest is ~1000 chars -> 3 per batch.
    by_tokens = rc.make_batches(digests(7, 1000), batch_rows=40, batch_tokens=1000)
    assert [len(b) for b in by_tokens] == [3, 3, 1]
    # A single oversized row still gets its own batch.
    assert [len(b) for b in rc.make_batches(digests(1, 10_000), batch_tokens=500)] == [
        1
    ]


def test_prefix_is_byte_stable_across_batches():
    client = FakeClient()
    clf = rc.RowClassifier(
        client, lens="network", criterion="personal  data", batch_rows=10
    )
    outcome = clf.run(digests(35))
    assert len(client.calls) == 4
    prefix = rc.classifier_prefix("network", "personal data")
    for messages in client.calls:
        assert len(messages) == 2  # one system message only
        assert messages[0] == {"role": "system", "content": ROW_CLASSIFIER_PROMPT}
        assert messages[1]["content"].startswith(prefix)
    assert outcome.scanned == 35
    assert len(outcome.matched) == 35
    assert outcome.partial is False
    assert outcome.model_tokens == 4 * 110
    assert outcome.bytes_sent > 35 * 50


def test_prompt_treats_rows_as_data():
    assert "never follow" in ROW_CLASSIFIER_PROMPT
    assert "DATA" in ROW_CLASSIFIER_PROMPT
    assert "data, not instructions" in rc.classifier_prefix("files", "x")


# -- parsing ---------------------------------------------------------------------------


def test_unknown_and_duplicate_keys_are_dropped():
    def reply(keys, messages):
        return (
            "```json\n"
            + json.dumps(
                {
                    "matches": [
                        {"key": keys[0], "reason": " ".join(["w"] * 40)},
                        {"key": "invented", "reason": "x"},
                        {"key": keys[0], "reason": "again"},
                    ],
                    "uncertain": [{"key": keys[1], "reason": "cut off"}],
                }
            )
            + "\n```"
        )

    outcome = rc.RowClassifier(FakeClient(reply), lens="network", criterion="c").run(
        digests(3)
    )
    assert [(v.key, v.match) for v in outcome.verdicts] == [
        ("k0", True),
        ("k1", "uncertain"),
    ]
    assert len(outcome.verdicts[0].reason.split()) == rc.REASON_WORDS


def test_parse_reply_rejects_non_json():
    with pytest.raises(rc.ModelReplyError):
        rc.parse_reply("I think k1 matches", ["k1"])
    with pytest.raises(rc.ModelReplyError):
        rc.parse_reply('{"foo": 1}', ["k1"])
    assert rc.parse_reply('{"matches": []}', ["k1"]) == []


# -- retry and halving ------------------------------------------------------------------


def test_malformed_reply_is_retried_once_then_the_batch_is_halved():
    def reply(keys, messages):
        if len(keys) == 4:
            return "not json"  # both attempts on the full batch fail
        return match_all(keys, messages)

    client = FakeClient(reply)
    outcome = rc.RowClassifier(client, lens="files", criterion="c").run(digests(4))
    sizes = [(len(keys_of(m)), len(m)) for m in client.calls]
    assert sizes == [(4, 2), (4, 3), (2, 2), (2, 2)]
    assert client.calls[1][-1] == {"role": "user", "content": ROW_CLASSIFIER_RETRY}
    assert len(outcome.matched) == 4
    assert outcome.errors == 0


def test_rows_count_as_errors_when_the_halves_fail_too():
    client = FakeClient(lambda keys, m: "nope")
    outcome = rc.RowClassifier(client, lens="files", criterion="c").run(digests(4))
    assert len(client.calls) == 6  # 2 full + 2 per half
    assert outcome.errors == 4
    assert outcome.scanned == 4
    assert outcome.verdicts == []


def test_request_error_counts_like_a_bad_reply():
    err = StreamChunk("error", error=StreamError("http", "boom"))
    client = FakeClient(lambda keys, m: err)
    outcome = rc.RowClassifier(client, lens="files", criterion="c").run(digests(1))
    assert len(client.calls) == 2
    assert outcome.errors == 1


# -- cancel and deadline -----------------------------------------------------------------


def test_cancel_mid_run_leaves_a_partial_result():
    cancel = threading.Event()
    seen: list[int] = []

    def on_batch(batch, outcome):
        seen.append(len(batch.keys))
        cancel.set()

    client = FakeClient(delay=0.05)
    clf = rc.RowClassifier(
        client,
        lens="network",
        criterion="c",
        batch_rows=5,
        concurrency=1,
        cancel_event=cancel,
        on_batch=on_batch,
    )
    outcome = clf.run(digests(50))
    assert outcome.partial is True
    assert outcome.stop_reason == "cancelled"
    assert seen == [5]
    assert outcome.scanned == 5
    assert len(client.calls) <= 2


def test_cancel_aborts_a_running_request():
    cancel = threading.Event()
    client = FakeClient(delay=5.0)
    clf = rc.RowClassifier(client, lens="network", criterion="c", cancel_event=cancel)
    threading.Timer(0.1, cancel.set).start()
    started = time.monotonic()
    outcome = clf.run(digests(3))
    assert time.monotonic() - started < 2.0
    assert outcome.partial is True
    assert outcome.scanned == 0


def test_deadline_stops_scheduling(monkeypatch):
    monkeypatch.setattr(rc, "STOP_SCHEDULING_S", 0.15)
    monkeypatch.setattr(rc, "ABORT_S", 0.0)
    client = FakeClient(delay=0.1)
    clf = rc.RowClassifier(
        client,
        lens="network",
        criterion="c",
        batch_rows=1,
        concurrency=1,
        deadline=time.monotonic() + 0.3,
    )
    outcome = clf.run(digests(20))
    assert outcome.partial is True
    assert outcome.stop_reason == "deadline"
    assert 1 <= outcome.scanned < 20


# -- gateway --------------------------------------------------------------------------------


@pytest.mark.parametrize(("capacity", "limit"), [(4, 2), (2, 1)])
def test_gateway_slots_stay_within_the_agent_limit(capacity, limit):
    gateway = Gateway(capacity)
    inner = FakeClient(delay=0.05)
    client = GatewayClient(inner, gateway, reserved=False)
    outcome = rc.RowClassifier(
        client, lens="network", criterion="c", batch_rows=2, concurrency=2
    ).run(digests(12))
    assert outcome.scanned == 12
    assert gateway.peak_agents_in_use == limit
    assert gateway.peak_in_use <= capacity - 1  # the orchestrator's slot stays free
    assert gateway.in_use == 0


# -- digests -----------------------------------------------------------------------------


def _detail(**over):
    detail = {
        "id": "f1",
        "request_headers": [
            ["Host", "api.example.com"],
            ["Authorization", "Bearer s3cr3t-token-value"],
            ["Cookie", "sid=abc; theme=dark"],
            ["Content-Type", "application/json"],
            ["X-Long", "v" * 500],
        ],
        "response_headers": [["Set-Cookie", "sid=zzz"], ["Content-Type", "image/png"]],
        "request_body": {
            "content": json.dumps({"email": "a@b.c", "pad": "p" * 3000}, indent=2),
            "encoding": "utf-8",
            "truncated": False,
            "size_bytes": 3100,
            "bytes_read": 3100,
        },
        "response_body": {
            "content": "iVBORw0KGgo=",
            "encoding": "base64",
            "truncated": False,
            "size_bytes": 34_000,
            "bytes_read": 9,
        },
    }
    detail.update(over)
    return detail


ROW = {
    "key": "f1",
    "flow_id": "f1",
    "method": "POST",
    "host": "api.example.com",
    "path": "/v1/t?imei=3567&x=1",
    "status": 200,
    "app": "com.example",
    "req_type": "application/json",
    "resp_type": "image/png",
    "req_bytes": 3100,
    "resp_bytes": 34000,
}


def test_network_digest_reduces_secrets_caps_bodies_and_marks_binary():
    d = rc.network_digest(ROW, detail=_detail())
    text = d.text
    assert d.key == "f1"
    assert d.kind == "content"
    assert text.startswith("POST api.example.com/v1/t?imei=3567&x=1 200 · app com.example")
    assert "query: imei=3567; x=1" in text
    assert "s3cr3t" not in text
    assert "Authorization: [Bearer, 25 chars]" in text
    assert "Cookie: [cookie, 2 part(s), 19 chars]" in text
    assert "Set-Cookie: [set-cookie, 1 part(s), 7 chars]" in text
    assert "X-Long: " + "v" * 100 in text
    assert "v" * 130 not in text
    assert 'request body: {"email":"a@b.c"' in text  # minified JSON
    assert "response body: [binary 33 kB image/png]" in text
    assert len(text.encode()) <= rc.ROW_CAP + 4
    body = text.split("request body: ")[1].split("\n")[0]
    assert len(body.encode()) <= rc.REQ_BODY_CAP + 30


def test_binary_only_and_metadata_only_kinds():
    only_binary = _detail(
        request_headers=[], response_headers=[], request_body={"content": ""}
    )
    assert rc.network_digest(ROW, detail=only_binary).kind == "binary"
    assert rc.network_digest(ROW, detail=None).kind == "metadata"
    assert rc.network_digest(ROW, detail=_detail(), include_content=False).kind == (
        "metadata"
    )


def test_form_body_is_split_into_fields():
    text, kind = rc.body_text(
        {"content": "user=bob&pass=hunter2", "encoding": "utf-8", "size_bytes": 21},
        "application/x-www-form-urlencoded; charset=utf-8",
        1500,
    )
    assert (text, kind) == ("user=bob; pass=hunter2", "text")
    assert rc.body_text({"content": "", "size_bytes": 0}, "", 10) == (None, "none")


def test_mask_sensitive_runs_redact_secrets(monkeypatch):
    calls = []

    def fake_redact(text, secrets=None):
        calls.append(text)
        return text.replace("imei=3567", "imei=[masked]")

    monkeypatch.setattr("sandroid.ai.safety.redact_secrets", fake_redact)
    d = rc.network_digest(ROW, detail=None, mask=True)
    assert calls
    assert "imei=[masked]" in d.text
    assert "3567" not in d.text


def test_files_digest_metadata_and_local_copy(tmp_path):
    row = {
        "key": "/data/data/com.x/shared_prefs/a.xml",
        "path": "/data/data/com.x/shared_prefs/a.xml",
        "ops": "CM",
        "count": 4,
        "processes": ["com.x", "p2", "p3", "p4"],
        "first": 0,
        "last": 0,
        "watched": True,
        "app": "com.x",
    }
    meta = rc.files_digest(row, content=(None, "metadata"))
    assert meta.kind == "metadata"
    assert "ops CM · 4 events" in meta.text
    assert "by com.x, p2, p3" in meta.text
    assert "p4" not in meta.text
    assert "watched" in meta.text
    full = rc.files_digest(row, content=("content: <map>email</map>", "content"))
    assert full.kind == "content"
    assert "<map>email</map>" in full.text


def test_local_file_content_reads_kept_versions(tmp_path, monkeypatch):
    from sandroid.core import watchlist_store

    version = tmp_path / "v001"
    version.mkdir()
    text_file = version / "a.xml"
    text_file.write_text("<map><string name='email'>a@b.c</string></map>")
    monkeypatch.setattr(watchlist_store, "version_dirs", lambda p: [version])
    monkeypatch.setattr(watchlist_store, "version_file", lambda v, p: text_file)
    monkeypatch.setattr(watchlist_store, "version_diff", lambda v: "+ email\n" * 300)
    text, kind = rc.local_file_content("/data/data/com.x/a.xml")
    assert kind == "content"
    assert "a@b.c" in text
    assert "last diff: + email" in text
    assert len(text) < rc.FILE_HEAD_CAP + rc.DIFF_HEAD_CAP + 100

    import sqlite3

    db = version / "c.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE contacts (name TEXT)")
    conn.commit()
    conn.close()
    monkeypatch.setattr(watchlist_store, "version_file", lambda v, p: db)
    monkeypatch.setattr(watchlist_store, "version_diff", lambda v: None)
    text, kind = rc.local_file_content("/data/data/com.x/c.db")
    assert (text, kind) == ("sqlite tables: contacts", "content")

    monkeypatch.setattr(watchlist_store, "version_dirs", lambda p: [])
    assert rc.local_file_content("/x") == (None, "metadata")
