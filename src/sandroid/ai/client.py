"""Streaming OpenAI-compatible chat-completions client.

Works against any OpenAI-compatible endpoint -- OpenAI itself, or a
self-hosted/gateway-fronted backend such as Ollama, vLLM, LM Studio, or an
internal gateway. Uses ``requests`` (already a core Sandroid dependency) with
``stream=True``, parsing Server-Sent Events by hand -- no extra HTTP
dependency needed just for SSE.

Emits a normalized, dict-based "ChatEvent" for each meaningful piece of the
stream:

- ``{"type": "text_delta", "content": str}`` -- a fragment of the assistant's
  visible reply.
- ``{"type": "reasoning_delta", "content": str}`` -- optional: some backends
  (e.g. reasoning models) stream a nonstandard ``reasoning_content`` field
  before real ``content``. Treated as purely optional/pass-through -- never
  required, never assumed present.
- ``{"type": "tool_call_delta", "index": int, "id": str | None,
  "name": str | None, "arguments_fragment": str}`` -- one incremental
  fragment of one tool call's arguments, keyed by ``index``. Fragments must
  be accumulated by the caller (see :mod:`sandroid.ai.loop`) -- this client
  does not attempt to parse or assemble them; it only forwards what the
  backend sent, chunk by chunk.
- ``{"type": "done"}`` -- the stream ended normally (``data: [DONE]`` or
  natural EOF). This is the signal the caller uses to treat any
  accumulated tool-call fragments as complete and ready to dispatch.
- ``{"type": "error", "message": str}`` -- a connection failure or non-2xx
  response, surfaced as a clean event rather than a raw exception or a
  confusing stream-parse failure.

Note: assembling fragments into a *complete* tool call (what the task
describes as a ``tool_call_done`` event) is deliberately done one layer up,
in :func:`sandroid.ai.loop.run_agent_turn` -- this client only knows about
one HTTP response stream, not about a multi-turn tool-calling protocol.
"""

import json
import logging
from collections.abc import Iterator

import requests

logger = logging.getLogger(__name__)

#: Default request timeout (connect, read) in seconds. Generous on the read
#: side since a streaming response can legitimately sit idle between chunks
#: while the backend is "thinking" (especially reasoning models).
_REQUEST_TIMEOUT = (10, 120)


class OpenAIClient:
    """A minimal streaming client for OpenAI-compatible chat-completions APIs."""

    def __init__(self, base_url: str, api_key: str, model: str):
        """Initialize the client.

        Args:
            base_url: Base URL of the OpenAI-compatible API, e.g.
                ``https://api.openai.com/v1`` (the ``/chat/completions``
                suffix is appended automatically; a trailing slash is
                tolerated).
            api_key: API key sent as ``Authorization: Bearer <api_key>``.
            model: Model name to request.
        """
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        stream: bool = True,
    ) -> Iterator[dict]:
        """Stream a chat completion, yielding normalized ChatEvent dicts.

        Args:
            messages: Chat-completions-style message list.
            tools: Optional ``tools=[...]`` schema (see
                :meth:`sandroid.ai.tools.registry.ToolRegistry.openai_tools_schema`).
            stream: Whether to request a streamed response. The event
                vocabulary above assumes ``True``; non-streaming use is not
                a supported path for this client (Sandroid's chat feature is
                streaming-first).

        Yields:
            ChatEvent dicts, always ending in exactly one of ``done`` or
            ``error`` (never both, and no events after either).
        """
        payload: dict = {"model": self._model, "messages": messages, "stream": stream}
        if tools:
            payload["tools"] = tools
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        try:
            response = requests.post(
                f"{self._base_url}/chat/completions",
                json=payload,
                headers=headers,
                stream=True,
                timeout=_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            # SSE bodies are always UTF-8; `requests` falls back to
            # ISO-8859-1 whenever a server's Content-Type omits a charset
            # (many OpenAI-compatible gateways do, since text/event-stream
            # has no standard charset param), which silently corrupts any
            # multi-byte character (emoji, accents, non-Latin scripts) once
            # `iter_lines(decode_unicode=True)` decodes with the wrong
            # encoding below. Force it rather than trust the guess.
            response.encoding = "utf-8"
        except requests.exceptions.RequestException as exc:
            yield {"type": "error", "message": f"AI backend request failed: {exc}"}
            return

        try:
            yield from self._iter_sse_events(response)
        except requests.exceptions.RequestException as exc:
            yield {"type": "error", "message": f"AI backend stream interrupted: {exc}"}
            return

        yield {"type": "done"}

    def _iter_sse_events(self, response: requests.Response) -> Iterator[dict]:
        """Parse ``data: {...}`` SSE lines from a streamed response."""
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue  # blank line: SSE event separator, nothing to do
            if line.startswith(":"):
                continue  # SSE keep-alive comment line
            if not line.startswith("data:"):
                continue
            data = line[len("data:") :].strip()
            if data == "[DONE]":
                return
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                logger.debug("Skipping unparsable SSE data line: %r", data)
                continue
            yield from self._events_from_chunk(chunk)

    @staticmethod
    def _events_from_chunk(chunk: dict) -> Iterator[dict]:
        """Turn one parsed SSE JSON chunk into zero or more ChatEvents."""
        choices = chunk.get("choices") or []
        if not choices:
            return
        delta = choices[0].get("delta") or {}

        reasoning = delta.get("reasoning_content")
        if reasoning:
            yield {"type": "reasoning_delta", "content": reasoning}

        content = delta.get("content")
        if content:
            yield {"type": "text_delta", "content": content}

        for tool_call in delta.get("tool_calls") or []:
            function = tool_call.get("function") or {}
            yield {
                "type": "tool_call_delta",
                "index": tool_call.get("index", 0),
                "id": tool_call.get("id"),
                "name": function.get("name"),
                "arguments_fragment": function.get("arguments", ""),
            }
