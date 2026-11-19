"""Unit tests for sandroid.ai.client (OpenAICompatClient + legacy OpenAIClient).

Builds real requests.Response objects backed by a real urllib3.HTTPResponse
(requests.post is monkeypatched to return one, never touching the network) so
these tests exercise requests' actual charset-guessing/decoding pipeline, not
a hand-rolled shortcut -- this is how a real encoding bug was actually caught
against a live backend: a mock built from plain Python strings can't
reproduce it, since the bug is specifically in how raw bytes get decoded.
The typed-stream tests further down use a small FakeResponse instead (no
network either), since they test retry/cancel/finish logic, not decoding.
"""

import io
import json
import threading

import pytest
import requests
import urllib3

from sandroid.ai.client import (
    ClientOptions,
    ModelProfile,
    OpenAIClient,
    OpenAICompatClient,
    Usage,
    match_profile,
    resolve_profile,
)


def _sse_response(
    body: bytes, content_type: str = "text/event-stream"
) -> requests.Response:
    """Build a real requests.Response the same way requests itself does from
    a urllib3 HTTPResponse, so .iter_lines() exercises requests' real
    encoding-detection/decoding logic.
    """
    raw = urllib3.HTTPResponse(
        body=io.BytesIO(body),
        status=200,
        headers={"Content-Type": content_type},
        preload_content=False,
    )
    response = requests.Response()
    response.status_code = 200
    response.raw = raw
    response.headers = urllib3.response.HTTPHeaderDict({"Content-Type": content_type})
    response.encoding = requests.utils.get_encoding_from_headers(response.headers)
    return response


def test_utf8_content_survives_a_charset_less_content_type(monkeypatch):
    """Regression test for a real bug found via a live backend: a server
    that sends `Content-Type: text/event-stream` with no charset param
    (common -- SSE has no standard charset param) makes `requests` guess
    ISO-8859-1 for any `text/*` content-type, silently corrupting any
    multi-byte UTF-8 character (emoji, accents, non-Latin scripts) once
    decoded. Only a real requests.Response reproduces this; a hand-mocked
    event list of plain Python strings can't.
    """
    payload = json.dumps({"choices": [{"delta": {"content": "⚠️ done"}}]})
    body = f"data: {payload}\n\ndata: [DONE]\n\n".encode()
    response = _sse_response(body)

    monkeypatch.setattr(requests, "post", lambda *a, **kw: response)

    client = OpenAIClient("https://example.invalid/v1", "key", "model")
    events = list(client.chat([{"role": "user", "content": "hi"}]))

    text_deltas = [e["content"] for e in events if e["type"] == "text_delta"]
    assert text_deltas == ["⚠️ done"]
    assert events[-1] == {"type": "done"}


def test_tool_call_delta_fragments_forwarded_unmodified(monkeypatch):
    """Sanity check that the client forwards tool-call fragments as-is and
    doesn't attempt to assemble them (that's loop.py's job).
    """
    chunk1 = json.dumps(
        {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_1",
                                "function": {"name": "get_status", "arguments": '{"l'},
                            }
                        ]
                    }
                }
            ]
        }
    )
    chunk2 = json.dumps(
        {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "function": {"arguments": 'imit": 3}'}}
                        ]
                    }
                }
            ]
        }
    )
    body = f"data: {chunk1}\n\ndata: {chunk2}\n\ndata: [DONE]\n\n".encode()
    response = _sse_response(body)
    monkeypatch.setattr(requests, "post", lambda *a, **kw: response)

    client = OpenAIClient("https://example.invalid/v1", "key", "model")
    events = list(client.chat([{"role": "user", "content": "hi"}]))

    deltas = [e for e in events if e["type"] == "tool_call_delta"]
    assert deltas[0]["arguments_fragment"] == '{"l'
    assert deltas[1]["arguments_fragment"] == 'imit": 3}'


def test_non_2xx_response_yields_error_event(monkeypatch):
    def raise_401(*a, **kw):
        resp = requests.Response()
        resp.status_code = 401
        resp.raw = urllib3.HTTPResponse(body=io.BytesIO(b'{"error": "bad key"}'))
        return resp

    monkeypatch.setattr(requests, "post", raise_401)

    client = OpenAIClient("https://example.invalid/v1", "bad-key", "model")
    events = list(client.chat([{"role": "user", "content": "hi"}]))

    assert len(events) == 1
    assert events[0]["type"] == "error"


# =============================================================================
# OpenAICompatClient: typed stream, retries, profiles, payload
# =============================================================================

BASE = "https://example.invalid/v1"
DEEPSEEK = "deepseek-ai/DeepSeek-V4.1-Flash"
HI = [{"role": "user", "content": "hi"}]


class FakeResponse:
    """Minimal stand-in for a streamed requests.Response.

    ``lines`` may contain an Exception instance, raised when reached.
    """

    def __init__(self, status=200, lines=(), headers=None, text=""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text
        self.encoding = None
        self.closed = False
        self._lines = list(lines)

    def iter_lines(self, decode_unicode=False):
        for line in self._lines:
            if isinstance(line, Exception):
                raise line
            yield line

    def close(self):
        self.closed = True


def _data(obj) -> str:
    return "data: " + json.dumps(obj)


def _delta(finish=None, **delta) -> str:
    return _data({"choices": [{"delta": delta, "finish_reason": finish}]})


class _Poster:
    """Scripted ``requests.post``: returns/raises one item per call."""

    def __init__(self, *items):
        self.items = list(items)
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append(kwargs)
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _client(monkeypatch, *items, model="m", **opts):
    poster = _Poster(*items)
    monkeypatch.setattr(requests, "post", poster)
    client = OpenAICompatClient(BASE, "secret-key-123", model, **opts)
    sleeps = []

    def fake_sleep(delay, cancel_event):
        sleeps.append(delay)
        return False

    client._sleep = fake_sleep
    return client, poster, sleeps


def test_usage_only_chunk_with_empty_choices_yields_usage(monkeypatch):
    usage = {
        "prompt_tokens": 120,
        "completion_tokens": 30,
        "completion_tokens_details": {"reasoning_tokens": 12},
    }
    resp = FakeResponse(
        lines=[
            _delta(content="ok"),
            _delta(finish="stop"),
            _data({"choices": [], "usage": usage}),
            "data: [DONE]",
        ]
    )
    client, _, _ = _client(monkeypatch, resp, model=DEEPSEEK)
    chunks = list(client.stream(HI))

    usage_chunks = [c for c in chunks if c.kind == "usage"]
    assert len(usage_chunks) == 1
    assert usage_chunks[0].usage == Usage(
        prompt_tokens=120, completion_tokens=30, reasoning_tokens=12, total_tokens=150
    )
    assert chunks[-1].kind == "done"
    assert chunks[-1].finish_reason == "stop"
    assert chunks[-1].usage.prompt_tokens == 120
    assert resp.closed


def test_retry_after_honoured_before_first_byte(monkeypatch):
    busy = FakeResponse(status=429, headers={"Retry-After": "3"}, text="slow down")
    ok = FakeResponse(lines=[_delta(content="hi"), _delta(finish="stop")])
    client, poster, sleeps = _client(monkeypatch, busy, ok)

    chunks = list(client.stream(HI))

    assert [c.kind for c in chunks] == ["retry", "text", "done"]
    assert chunks[0].retry.attempt == 1
    assert chunks[0].retry.delay_s == 3.0
    assert chunks[0].retry.reason == "HTTP 429"
    assert sleeps == [3.0]
    assert len(poster.calls) == 2
    assert busy.closed
    assert ok.closed


def test_connect_errors_back_off_then_give_up(monkeypatch):
    err = requests.exceptions.ConnectionError("refused secret-key-123")
    client, poster, sleeps = _client(monkeypatch, *[err] * 5)

    chunks = list(client.stream(HI))

    assert [c.kind for c in chunks] == ["retry"] * 4 + ["error"]
    assert len(poster.calls) == 5
    for delay, base in zip(sleeps, (1, 2, 4, 8), strict=True):
        assert base <= delay <= base * 1.25
    error = chunks[-1].error
    assert error.kind == "connect"
    assert "secret-key-123" not in error.message
    assert error.message.startswith("AI backend request failed")


def test_retry_max_from_options(monkeypatch):
    client, poster, _ = _client(
        monkeypatch,
        FakeResponse(status=503),
        FakeResponse(status=503),
        options=ClientOptions(retry_max=1),
    )
    chunks = list(client.stream(HI))
    assert [c.kind for c in chunks] == ["retry", "error"]
    assert chunks[-1].error.status == 503
    assert chunks[-1].error.retryable


def test_non_retryable_status_reports_server_message(monkeypatch):
    bad = FakeResponse(
        status=400,
        text=json.dumps({"error": {"message": "tool_choice required unsupported"}}),
    )
    client, poster, _ = _client(monkeypatch, bad)
    chunks = list(client.stream(HI))
    assert [c.kind for c in chunks] == ["error"]
    assert chunks[0].error.kind == "http"
    assert chunks[0].error.status == 400
    assert "tool_choice required unsupported" in chunks[0].error.message
    assert len(poster.calls) == 1


def test_no_retry_after_first_content_drop_is_interrupted(monkeypatch):
    resp = FakeResponse(
        lines=[
            _delta(reasoning_content="thinking"),
            _delta(content="partial "),
            _delta(content="answer"),
            requests.exceptions.ChunkedEncodingError("connection reset"),
        ]
    )
    client, poster, sleeps = _client(monkeypatch, resp, FakeResponse())
    chunks = list(client.stream(HI))

    assert len(poster.calls) == 1
    assert sleeps == []
    assert chunks[-1].kind == "error"
    error = chunks[-1].error
    assert error.kind == "interrupted"
    assert error.retryable
    assert error.partial_text == "partial answer"
    assert error.partial_reasoning == "thinking"
    assert resp.closed


def test_drop_before_any_content_is_retried(monkeypatch):
    dropped = FakeResponse(
        lines=[
            _delta(role="assistant"),
            requests.exceptions.ChunkedEncodingError("reset"),
        ]
    )
    ok = FakeResponse(lines=[_delta(content="x"), "data: [DONE]"])
    client, poster, _ = _client(monkeypatch, dropped, ok)
    chunks = list(client.stream(HI))
    assert [c.kind for c in chunks] == ["retry", "text", "done"]


def test_eof_without_finish_after_content_is_interrupted(monkeypatch):
    resp = FakeResponse(lines=[_delta(content="half")])
    client, _, _ = _client(monkeypatch, resp)
    chunks = list(client.stream(HI))
    assert chunks[-1].kind == "error"
    assert chunks[-1].error.kind == "interrupted"
    assert chunks[-1].error.partial_text == "half"


@pytest.mark.parametrize("reason", ["length", "content_filter", "tool_calls"])
def test_finish_reason_surfaced(monkeypatch, reason):
    resp = FakeResponse(lines=[_delta(content="x"), _delta(finish=reason)])
    client, _, _ = _client(monkeypatch, resp)
    chunks = list(client.stream(HI))
    assert chunks[-1].kind == "done"
    assert chunks[-1].finish_reason == reason


def test_in_stream_error_object_is_a_server_error(monkeypatch):
    resp = FakeResponse(
        lines=[_delta(content="a"), _data({"error": {"message": "overloaded"}})]
    )
    client, _, _ = _client(monkeypatch, resp)
    chunks = list(client.stream(HI))
    assert chunks[-1].kind == "error"
    assert chunks[-1].error.kind == "server"
    assert "overloaded" in chunks[-1].error.message
    assert chunks[-1].error.partial_text == "a"


def test_closing_generator_early_closes_response(monkeypatch):
    resp = FakeResponse(lines=[_delta(content="a"), _delta(content="b")] * 5)
    client, _, _ = _client(monkeypatch, resp)
    gen = client.stream(HI)
    assert next(gen).text == "a"
    gen.close()
    assert resp.closed


def test_cancel_event_ends_stream_with_cancelled(monkeypatch):
    cancel = threading.Event()
    resp = FakeResponse(lines=[_delta(content="a"), _delta(content="b")])
    client, _, _ = _client(monkeypatch, resp)
    chunks = []
    for chunk in client.stream(HI, cancel_event=cancel):
        chunks.append(chunk)
        cancel.set()
    assert [c.kind for c in chunks] == ["text", "cancelled"]
    assert resp.closed


def test_cancel_during_retry_wait(monkeypatch):
    client, poster, _ = _client(monkeypatch, FakeResponse(status=502))
    client._sleep = lambda delay, ev: True  # cancelled while waiting
    chunks = list(client.stream(HI))
    assert [c.kind for c in chunks] == ["retry", "cancelled"]
    assert len(poster.calls) == 1


def test_think_tags_split_across_chunks(monkeypatch):
    resp = FakeResponse(
        lines=[
            _delta(content="<thi"),
            _delta(content="nk>step one</th"),
            _delta(content="ink>Answer <b>"),
            _delta(finish="stop"),
        ]
    )
    client, _, _ = _client(monkeypatch, resp, model="MiniMax-M2.5")
    chunks = list(client.stream(HI))
    reasoning = "".join(c.text for c in chunks if c.kind == "reasoning")
    text = "".join(c.text for c in chunks if c.kind == "text")
    assert reasoning == "step one"
    assert text == "Answer <b>"


def test_think_tags_untouched_when_profile_disables_them(monkeypatch):
    resp = FakeResponse(lines=[_delta(content="<think>x</think>y"), "data: [DONE]"])
    client, _, _ = _client(monkeypatch, resp, model=DEEPSEEK)
    text = "".join(c.text for c in client.stream(HI) if c.kind == "text")
    assert text == "<think>x</think>y"


def test_tool_call_fragments_are_typed(monkeypatch):
    call = {"index": 0, "id": "c1", "function": {"name": "f", "arguments": '{"a'}}
    resp = FakeResponse(
        lines=[
            _delta(tool_calls=[call]),
            _delta(tool_calls=[{"index": 0, "function": {"arguments": '": 1}'}}]),
            _delta(finish="tool_calls"),
        ]
    )
    client, _, _ = _client(monkeypatch, resp)
    calls = [c.tool_call for c in client.stream(HI) if c.kind == "tool_call"]
    assert [(c.index, c.id, c.name) for c in calls] == [(0, "c1", "f"), (0, None, None)]
    assert "".join(c.arguments_fragment for c in calls) == '{"a": 1}'


# -- profiles -------------------------------------------------------------------


def test_profile_glob_matching():
    deepseek = match_profile(DEEPSEEK)
    assert deepseek.name == "deepseek-v4"
    assert deepseek.context_window == 262_144
    assert deepseek.system_mode == "multi"
    assert deepseek.echo_reasoning == "all"
    assert deepseek.stream_usage is True
    assert deepseek.forced_tool_choice is False
    assert deepseek.tool_choice_none is True
    assert deepseek.native_tool_search is False
    assert match_profile("deepseek-v4-pro").name == "deepseek-v4"

    for unknown in ("MiniMax-M2.5", "qwen2.5:14b", None):
        profile = match_profile(unknown)
        assert profile.name == "default"
        assert profile.system_mode == "first_only"
        assert profile.think_tags is True
        assert profile.echo_reasoning == "turn"
        assert profile.context_window == 32_768


def test_resolve_profile_applies_config_overrides():
    from types import SimpleNamespace

    cfg = SimpleNamespace(
        profile="deepseek-v4",
        profile_overrides={"stream_usage": False, "bogus": 1},
        context_window=100_000,
    )
    profile = resolve_profile("MiniMax-M2.5", cfg)
    assert profile.name == "deepseek-v4"
    assert profile.stream_usage is False
    assert profile.context_window == 100_000
    assert resolve_profile(DEEPSEEK, None) == match_profile(DEEPSEEK)
    unknown = resolve_profile("x", SimpleNamespace(profile="nope"))
    assert unknown.name == "default"


# -- request payload ----------------------------------------------------------------


def test_payload_for_deepseek_profile():
    client = OpenAICompatClient(
        BASE,
        "k",
        DEEPSEEK,
        options=ClientOptions(
            max_tokens=4096,
            temperature=0.3,
            top_p=0.9,
            tool_choice="auto",
            extra_body={"chat_template_kwargs": {"thinking": True}},
        ),
    )
    messages = [
        {"role": "system", "content": "static"},
        {"role": "user", "content": "q"},
        {"role": "assistant", "content": "a", "reasoning_content": "r"},
        {"role": "system", "content": "ambient"},
        {"role": "user", "content": "q2"},
    ]
    tools = [{"type": "function", "function": {"name": "f", "parameters": {}}}]
    payload = client.build_request(messages, tools)

    assert payload["model"] == DEEPSEEK
    assert payload["stream"] is True
    assert payload["stream_options"] == {"include_usage": True}
    assert payload["messages"] == messages  # multi: passed through as is
    assert payload["messages"][2]["reasoning_content"] == "r"
    assert payload["tools"] == tools
    assert payload["tool_choice"] == "auto"
    assert payload["max_tokens"] == 4096
    assert payload["temperature"] == 0.3
    assert payload["top_p"] == 0.9
    assert payload["chat_template_kwargs"] == {"thinking": True}
    assert "parallel_tool_calls" not in payload

    # Per-call values win; forced choices are dropped, "none" is kept.
    assert client.build_request(messages, tools, tool_choice="none")["tool_choice"] == (
        "none"
    )
    assert "tool_choice" not in client.build_request(
        messages, tools, tool_choice="required"
    )
    named = {"type": "function", "function": {"name": "f"}}
    assert "tool_choice" not in client.build_request(messages, tools, tool_choice=named)
    # No tools -> no tool_choice.
    assert "tool_choice" not in client.build_request(messages, None)
    assert client.build_request(messages, None, max_tokens=7)["max_tokens"] == 7


def test_payload_defaults_send_nothing_optional():
    payload = OpenAICompatClient(BASE, "k", "local-model").build_request(HI)
    assert payload == {"model": "local-model", "messages": HI, "stream": True}


def test_first_only_profile_merges_system_messages_without_mutating():
    messages = [
        {"role": "system", "content": "static"},
        {"role": "user", "content": "q"},
        {"role": "system", "content": "ambient"},
        {"role": "user", "content": "q2"},
    ]
    snapshot = json.loads(json.dumps(messages))
    client = OpenAICompatClient(BASE, "k", "MiniMax-M2.5")
    sent = client.build_request(messages)["messages"]
    assert sent == [
        {"role": "system", "content": "static\n\nambient"},
        {"role": "user", "content": "q"},
        {"role": "user", "content": "q2"},
    ]
    assert messages == snapshot


def test_profile_max_output_caps_max_tokens():
    client = OpenAICompatClient(
        BASE,
        "k",
        "m",
        options=ClientOptions(max_tokens=100_000),
        profile=ModelProfile(max_output=8192),
    )
    assert client.build_request(HI)["max_tokens"] == 8192


def test_timeouts_and_auth_header_sent(monkeypatch):
    resp = FakeResponse(lines=["data: [DONE]"])
    client, poster, _ = _client(
        monkeypatch,
        resp,
        options=ClientOptions(connect_timeout_s=3, read_timeout_s=45),
    )
    list(client.stream(HI))
    call = poster.calls[0]
    assert call["timeout"] == (3, 45)
    assert call["stream"] is True
    assert call["headers"]["Authorization"] == "Bearer secret-key-123"
    assert "secret-key-123" not in repr(client)


def test_options_from_ai_config():
    from sandroid.config.schema import AIConfig

    cfg = AIConfig(
        max_tokens=2048,
        temperature=0.1,
        tool_choice="auto",
        extra_body={"x": 1},
        request_timeout=(5, 60),
        retry_max=2,
    )
    opts = ClientOptions.from_ai_config(cfg)
    assert opts == ClientOptions(
        max_tokens=2048,
        temperature=0.1,
        tool_choice="auto",
        extra_body={"x": 1},
        connect_timeout_s=5.0,
        read_timeout_s=60.0,
        retry_max=2,
    )
    assert ClientOptions.from_ai_config(None) == ClientOptions()


def test_build_client_uses_config_options(monkeypatch):
    from sandroid.ai.safety import AISettings, build_client
    from sandroid.config.schema import AIConfig

    settings = AISettings(
        base_url="http://localhost:8000/v1", api_key="k", model=DEEPSEEK
    )
    client = build_client(settings, AIConfig(retry_max=1, context_window=200_000))
    assert isinstance(client, OpenAIClient)
    assert isinstance(client, OpenAICompatClient)
    assert client.options.retry_max == 1
    assert client.profile.name == "deepseek-v4"
    assert client.profile.context_window == 200_000


def test_usage_from_dict_tolerates_missing_and_cached():
    assert Usage.from_dict({}) == Usage()
    usage = Usage.from_dict(
        {
            "prompt_tokens": 10,
            "completion_tokens": 2,
            "total_tokens": 12,
            "prompt_tokens_details": {"cached_tokens": 8},
        }
    )
    assert usage.cached_tokens == 8
    assert usage.as_dict()["total_tokens"] == 12


# -- legacy adapter ---------------------------------------------------------------


def test_legacy_chat_adapter_maps_typed_chunks(monkeypatch):
    resp = FakeResponse(
        lines=[
            _delta(reasoning_content="r"),
            _delta(content="t"),
            _delta(finish="stop"),
            _data({"choices": [], "usage": {"prompt_tokens": 5}}),
            "data: [DONE]",
        ]
    )
    monkeypatch.setattr(requests, "post", lambda *a, **kw: resp)
    events = list(OpenAIClient(BASE, "k", DEEPSEEK).chat(HI))
    assert [e["type"] for e in events] == [
        "reasoning_delta",
        "text_delta",
        "usage",
        "done",
    ]
    assert events[2]["usage"]["prompt_tokens"] == 5
    assert events[-1] == {"type": "done"}


def test_legacy_client_does_not_retry_by_default(monkeypatch):
    poster = _Poster(requests.exceptions.ConnectionError("down"))
    monkeypatch.setattr(requests, "post", poster)
    events = list(OpenAIClient(BASE, "k", "m").chat(HI))
    assert [e["type"] for e in events] == ["error"]
    assert len(poster.calls) == 1


# -- health -------------------------------------------------------------------------


def test_health_lists_models_and_pings(monkeypatch):
    class _Json(FakeResponse):
        def json(self):
            return {
                "data": [
                    {"id": DEEPSEEK, "max_input_tokens": 262144},
                    {"id": "other"},
                ]
            }

    monkeypatch.setattr(requests, "get", lambda url, **kw: _Json())
    poster = _Poster(FakeResponse(status=200))
    monkeypatch.setattr(requests, "post", poster)

    report = OpenAICompatClient(BASE, "k", DEEPSEEK).health()
    assert report.ok
    assert report.models_ok
    assert report.model_listed is True
    assert report.max_input_tokens == 262144
    assert report.ping_ok is True
    assert report.ping_ms is not None
    sent = poster.calls[0]["json"]
    assert sent["max_tokens"] == 1
    assert sent["stream"] is False
    assert "stream_options" not in sent


def test_health_reports_failures_redacted(monkeypatch):
    def boom(url, **kw):
        raise requests.exceptions.ConnectionError("no route; key=secret-key-123")

    monkeypatch.setattr(requests, "get", boom)
    monkeypatch.setattr(requests, "post", boom)
    report = OpenAICompatClient(BASE, "secret-key-123", "m").health()
    assert not report.ok
    assert report.models_ok is False
    assert report.model_listed is None
    assert report.ping_ok is False
    assert "secret-key-123" not in report.error
