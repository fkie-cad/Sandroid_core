"""Unit tests for sandroid.ai.client.OpenAIClient's SSE parsing.

Builds real requests.Response objects backed by a real urllib3.HTTPResponse
(requests.post is monkeypatched to return one, never touching the network) so
these tests exercise requests' actual charset-guessing/decoding pipeline, not
a hand-rolled shortcut -- this is how a real encoding bug was actually caught
against a live backend: a mock built from plain Python strings can't
reproduce it, since the bug is specifically in how raw bytes get decoded.
"""

import io
import json

import requests
import urllib3

from sandroid.ai.client import OpenAIClient


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
