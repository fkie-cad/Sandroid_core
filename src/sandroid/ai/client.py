"""Streaming OpenAI-compatible chat-completions transport.

Works against any OpenAI-compatible endpoint (OpenAI, vLLM, Ollama, LM Studio,
an internal gateway). Uses ``requests`` with ``stream=True`` and parses
Server-Sent Events by hand, so no extra HTTP dependency is needed.

Two layers live here:

- :class:`OpenAICompatClient` -- the transport used by the runtime. It sends
  one request per :meth:`~OpenAICompatClient.stream` call and yields typed
  :class:`StreamChunk` objects (``reasoning``, ``text``, ``tool_call``,
  ``usage``, ``retry``) that always end in exactly one terminal chunk:
  ``done`` (with ``finish_reason`` and the final :class:`Usage`), ``error``
  (with a :class:`StreamError`) or ``cancelled``.

  - Retries connect errors and HTTP 408/429/5xx *before the first content
    byte* only (exponential backoff 1/2/4/8 s plus jitter, ``Retry-After``
    honoured), each announced by a ``retry`` chunk.
  - A drop after content started becomes ``error(kind="interrupted")`` with
    the partial text and reasoning preserved.
  - Request parameters come from :class:`ClientOptions` (built from
    ``config.ai`` with :meth:`ClientOptions.from_ai_config`), model quirks
    from :class:`ModelProfile` (see :func:`resolve_profile`).
  - Messages are passed through untouched except for per-profile
    normalisation (``system_mode="first_only"`` merges all system messages
    into the first one). Echoing ``reasoning_content`` is the caller's job.

- :class:`OpenAIClient` -- the legacy adapter with the first-generation
  dict-event API (``chat()`` yielding ``text_delta`` / ``reasoning_delta`` /
  ``tool_call_delta`` / ``done`` / ``error`` dicts) still used by
  :mod:`sandroid.ai.loop`. It is an :class:`OpenAICompatClient` subclass.
"""

from __future__ import annotations

import email.utils
import fnmatch
import json
import logging
import random
import time
from contextlib import closing
from dataclasses import asdict, dataclass, field, fields, replace
from typing import TYPE_CHECKING, Any, Literal

import requests

if TYPE_CHECKING:
    import threading
    from collections.abc import Callable, Iterator

logger = logging.getLogger(__name__)

SystemMode = Literal["multi", "first_only"]
EchoReasoning = Literal["all", "turn", "none"]
ChunkKind = Literal[
    "reasoning",
    "text",
    "tool_call",
    "usage",
    "retry",
    "done",
    "error",
    "cancelled",
]
ErrorKind = Literal["connect", "http", "server", "interrupted"]

#: HTTP statuses retried before the first content byte.
RETRYABLE_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
#: Backoff base delays per retry attempt (seconds); the last one repeats.
_BACKOFF_S = (1.0, 2.0, 4.0, 8.0)
#: Longest error-body excerpt kept in an error message.
_ERROR_BODY_MAX = 600


# =============================================================================
# Model profiles
# =============================================================================


@dataclass(frozen=True)
class ModelProfile:
    """What a model/backend supports, matched by glob on the model name.

    Attributes:
        name: Profile name (``ai.profile`` selects one by this name).
        context_window: Total context window in tokens.
        max_output: Upper bound for ``max_tokens`` (``None`` = no cap).
        system_mode: ``multi`` sends every system message as is;
            ``first_only`` merges them into the first one (the model only
            reads the first system message).
        reasoning_field: Delta field that carries reasoning text.
        think_tags: Move inline ``<think>...</think>`` text into reasoning.
        echo_reasoning: Which assistant ``reasoning_content`` the caller
            should send back: ``all``, only the current ``turn``, or ``none``.
        stream_usage: Send ``stream_options.include_usage``.
        parallel_tool_calls: Value for ``parallel_tool_calls`` (``None`` =
            do not send the field).
        forced_tool_choice: Backend accepts ``tool_choice="required"`` or a
            named function. When False such values are dropped.
        tool_choice_none: Backend accepts ``tool_choice="none"``.
        native_tool_search: Reserved for vLLM ``defer_loading`` support.
    """

    name: str = "default"
    context_window: int = 32_768
    max_output: int | None = None
    system_mode: SystemMode = "first_only"
    reasoning_field: str = "reasoning_content"
    think_tags: bool = True
    echo_reasoning: EchoReasoning = "turn"
    stream_usage: bool = False
    parallel_tool_calls: bool | None = None
    forced_tool_choice: bool = False
    tool_choice_none: bool = True
    native_tool_search: bool = False


#: The conservative profile used for any model no glob matches (MiniMax too).
DEFAULT_PROFILE = ModelProfile()

#: Built-in profiles: ``(globs, profile)``. Globs match case-insensitively
#: against the full model name (``org/model`` included). First match wins.
BUILTIN_PROFILES: tuple[tuple[tuple[str, ...], ModelProfile], ...] = (
    (
        ("*deepseek-v4*",),
        ModelProfile(
            name="deepseek-v4",
            context_window=262_144,
            max_output=None,
            system_mode="multi",
            reasoning_field="reasoning_content",
            think_tags=False,
            echo_reasoning="all",
            stream_usage=True,
            parallel_tool_calls=None,
            forced_tool_choice=False,
            tool_choice_none=True,
            native_tool_search=False,
        ),
    ),
)

_PROFILE_FIELDS = frozenset(f.name for f in fields(ModelProfile)) - {"name"}


def builtin_profile(name: str) -> ModelProfile | None:
    """Return the built-in profile called ``name`` (``"default"`` included)."""
    if name == DEFAULT_PROFILE.name:
        return DEFAULT_PROFILE
    for _globs, profile in BUILTIN_PROFILES:
        if profile.name == name:
            return profile
    return None


def match_profile(model: str | None) -> ModelProfile:
    """Return the first built-in profile whose glob matches ``model``."""
    lowered = (model or "").lower()
    for globs, profile in BUILTIN_PROFILES:
        if any(fnmatch.fnmatchcase(lowered, g.lower()) for g in globs):
            return profile
    return DEFAULT_PROFILE


def resolve_profile(model: str | None, ai_cfg: Any = None) -> ModelProfile:
    """Pick the profile for ``model`` and apply ``config.ai`` overrides.

    Args:
        model: Model name as sent in requests.
        ai_cfg: An ``AIConfig``-like object (duck-typed; ``None`` = no
            overrides). Reads ``profile`` (a built-in profile name that
            replaces glob matching), ``profile_overrides`` (field -> value)
            and ``context_window``.

    Returns:
        The resolved, frozen profile.
    """
    profile = match_profile(model)
    forced = getattr(ai_cfg, "profile", None)
    if forced:
        chosen = builtin_profile(str(forced))
        if chosen is None:
            logger.warning("Unknown ai.profile %r; using %s", forced, profile.name)
        else:
            profile = chosen
    overrides = dict(getattr(ai_cfg, "profile_overrides", None) or {})
    unknown = set(overrides) - _PROFILE_FIELDS
    if unknown:
        logger.warning("Ignoring unknown ai.profile_overrides keys: %s", unknown)
    changes = {k: v for k, v in overrides.items() if k in _PROFILE_FIELDS}
    window = getattr(ai_cfg, "context_window", None)
    if window:
        changes["context_window"] = int(window)
    return replace(profile, **changes) if changes else profile


# =============================================================================
# Options, chunks, results
# =============================================================================


@dataclass(frozen=True)
class ClientOptions:
    """Request parameters and transport policy (from ``config.ai``).

    ``None`` means "do not send the field" (the server default applies).
    """

    max_tokens: int | None = None
    temperature: float | None = None
    top_p: float | None = None
    tool_choice: str | None = None
    extra_body: dict[str, Any] = field(default_factory=dict)
    connect_timeout_s: float = 10.0
    read_timeout_s: float = 120.0
    retry_max: int = 4
    retry_after_cap_s: float = 60.0

    @classmethod
    def from_ai_config(cls, ai_cfg: Any) -> ClientOptions:
        """Build options from an ``AIConfig``-like object (missing = default)."""
        default = cls()
        timeout = getattr(ai_cfg, "request_timeout", None)
        connect, read = default.connect_timeout_s, default.read_timeout_s
        if timeout:
            connect, read = float(timeout[0]), float(timeout[1])
        retry_max = getattr(ai_cfg, "retry_max", None)
        return cls(
            max_tokens=getattr(ai_cfg, "max_tokens", None),
            temperature=getattr(ai_cfg, "temperature", None),
            top_p=getattr(ai_cfg, "top_p", None),
            tool_choice=getattr(ai_cfg, "tool_choice", None),
            extra_body=dict(getattr(ai_cfg, "extra_body", None) or {}),
            connect_timeout_s=connect,
            read_timeout_s=read,
            retry_max=default.retry_max if retry_max is None else int(retry_max),
        )


@dataclass(frozen=True)
class Usage:
    """Token usage of one request as reported by the server.

    ``cached_tokens`` is ``None`` when the server does not report it.
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0
    cached_tokens: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> Usage:
        """Parse an OpenAI ``usage`` object, tolerating missing fields."""

        def _int(value: Any) -> int:
            try:
                return int(value or 0)
            except (TypeError, ValueError):
                return 0

        details = data.get("completion_tokens_details") or {}
        prompt_details = data.get("prompt_tokens_details") or {}
        prompt = _int(data.get("prompt_tokens"))
        completion = _int(data.get("completion_tokens"))
        cached = prompt_details.get("cached_tokens")
        return cls(
            prompt_tokens=prompt,
            completion_tokens=completion,
            reasoning_tokens=_int(details.get("reasoning_tokens")),
            total_tokens=_int(data.get("total_tokens")) or prompt + completion,
            cached_tokens=None if cached is None else _int(cached),
        )

    def as_dict(self) -> dict[str, Any]:
        """Plain-dict form (for events and persistence)."""
        return asdict(self)


@dataclass(frozen=True)
class ToolCallDelta:
    """One streamed fragment of one tool call, keyed by ``index``.

    Fragments are accumulated by the caller; the transport never assembles
    or parses tool-call arguments.
    """

    index: int
    id: str | None
    name: str | None
    arguments_fragment: str


@dataclass(frozen=True)
class RetryInfo:
    """A retry about to happen (``attempt`` counts from 1)."""

    attempt: int
    max_attempts: int
    delay_s: float
    reason: str


@dataclass(frozen=True)
class StreamError:
    """A terminal transport error (message already secret-redacted).

    Attributes:
        kind: ``connect`` (no usable connection, retries exhausted),
            ``http`` (non-2xx status), ``server`` (an ``error`` object in the
            stream) or ``interrupted`` (dropped after content started).
        message: User-facing, redacted text.
        status: HTTP status, if any.
        retryable: Whether the caller may sensibly retry / continue.
        partial_text: Visible text streamed before the failure.
        partial_reasoning: Reasoning text streamed before the failure.
    """

    kind: ErrorKind
    message: str
    status: int | None = None
    retryable: bool = False
    partial_text: str = ""
    partial_reasoning: str = ""


@dataclass(frozen=True)
class StreamChunk:
    """One typed item of a streamed response.

    Only the attribute(s) belonging to ``kind`` are set: ``text`` for
    ``reasoning``/``text``; ``tool_call``; ``usage`` (also on ``done``);
    ``retry``; ``finish_reason`` on ``done`` (``stop``, ``tool_calls``,
    ``length``, ``content_filter`` or ``None``); ``error``.
    """

    kind: ChunkKind
    text: str = ""
    tool_call: ToolCallDelta | None = None
    usage: Usage | None = None
    retry: RetryInfo | None = None
    finish_reason: str | None = None
    error: StreamError | None = None

    @property
    def terminal(self) -> bool:
        """True for ``done``, ``error`` and ``cancelled``."""
        return self.kind in ("done", "error", "cancelled")


@dataclass(frozen=True)
class HealthReport:
    """Result of :meth:`OpenAICompatClient.health`.

    Attributes:
        ok: ``GET /models`` worked and (if requested) the ping answered.
        models_ok: ``GET /models`` answered 2xx with a model list.
        model_listed: The configured model is in the list (``None`` if the
            list could not be read).
        max_input_tokens: The model's ``max_input_tokens`` (or
            ``max_model_len``) as listed, if present.
        ping_ok: The 1-token ping answered 2xx (``None`` if not run).
        ping_ms: Ping latency in milliseconds.
        models: Listed model ids.
        error: Redacted error text of the first failure.
    """

    ok: bool
    models_ok: bool
    model_listed: bool | None = None
    max_input_tokens: int | None = None
    ping_ok: bool | None = None
    ping_ms: float | None = None
    models: tuple[str, ...] = ()
    error: str | None = None


@dataclass
class _Retry:
    """Internal: one attempt failed in a retryable way."""

    reason: str
    error: StreamError
    retry_after: float | None = None


@dataclass
class _StreamState:
    """Internal per-attempt accumulation."""

    content_started: bool = False
    finish_reason: str | None = None
    usage: Usage | None = None
    text: list[str] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)


class _ThinkSplitter:
    """Split inline ``<think>...</think>`` text into reasoning and text.

    Tags may be cut across stream chunks, so a trailing partial tag is held
    back until the next fragment (or :meth:`flush`) decides it.
    """

    OPEN = "<think>"
    CLOSE = "</think>"

    def __init__(self) -> None:
        self.in_think = False
        self._buf = ""

    def feed(self, text: str) -> list[tuple[str, str]]:
        """Return ``(kind, text)`` pieces (kind ``reasoning`` or ``text``)."""
        self._buf += text
        out: list[tuple[str, str]] = []
        while self._buf:
            tag = self.CLOSE if self.in_think else self.OPEN
            kind = "reasoning" if self.in_think else "text"
            idx = self._buf.find(tag)
            if idx >= 0:
                if idx:
                    out.append((kind, self._buf[:idx]))
                self._buf = self._buf[idx + len(tag) :]
                self.in_think = not self.in_think
                continue
            hold = 0
            for k in range(min(len(self._buf), len(tag) - 1), 0, -1):
                if self._buf.endswith(tag[:k]):
                    hold = k
                    break
            cut = len(self._buf) - hold
            if cut:
                out.append((kind, self._buf[:cut]))
            self._buf = self._buf[cut:]
            break
        return out

    def flush(self) -> list[tuple[str, str]]:
        """Release any held-back text."""
        if not self._buf:
            return []
        out = [("reasoning" if self.in_think else "text", self._buf)]
        self._buf = ""
        return out


def _parse_retry_after(value: str | None) -> float | None:
    """Seconds from a ``Retry-After`` header (delta-seconds or HTTP date)."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    return max(0.0, when.timestamp() - time.time())


# =============================================================================
# Transport
# =============================================================================


class OpenAICompatClient:
    """Streaming client for OpenAI-compatible ``/chat/completions``.

    Thread-safe for concurrent :meth:`stream` calls (no per-request state is
    kept on the instance).
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        *,
        options: ClientOptions | None = None,
        profile: ModelProfile | None = None,
    ):
        """Initialize the client.

        Args:
            base_url: Base URL, e.g. ``https://api.openai.com/v1``
                (``/chat/completions`` is appended; a trailing slash is ok).
            api_key: Sent as ``Authorization: Bearer <api_key>``.
            model: Model name to request.
            options: Request parameters and retry policy. Defaults to
                :class:`ClientOptions` defaults (no global config read).
            profile: Model profile. Defaults to :func:`match_profile`.
        """
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._options = options if options is not None else ClientOptions()
        self._profile = profile if profile is not None else match_profile(model)
        #: Sleep hook used between retries (tests replace it). Receives the
        #: delay and the cancel event; returns True when cancelled.
        self._sleep: Callable[[float, threading.Event | None], bool] = (
            _interruptible_sleep
        )

    @classmethod
    def from_config(cls, settings: Any, ai_cfg: Any = None) -> OpenAICompatClient:
        """Build a client from resolved settings plus ``config.ai`` options.

        Args:
            settings: An :class:`~sandroid.ai.safety.AISettings` (or anything
                with ``base_url``, ``api_key`` and ``model``). Policy checks
                are the caller's job (see :func:`sandroid.ai.safety.build_client`).
            ai_cfg: ``AIConfig``-like object for options and profile
                overrides; ``None`` uses defaults.
        """
        return cls(
            settings.base_url,
            settings.api_key,
            settings.model,
            options=ClientOptions.from_ai_config(ai_cfg),
            profile=resolve_profile(settings.model, ai_cfg),
        )

    # -- properties -----------------------------------------------------------

    @property
    def model(self) -> str:
        """The requested model name."""
        return self._model

    @property
    def base_url(self) -> str:
        """The base URL without a trailing slash."""
        return self._base_url

    @property
    def profile(self) -> ModelProfile:
        """The model profile in effect."""
        return self._profile

    @property
    def options(self) -> ClientOptions:
        """The request options in effect."""
        return self._options

    def __repr__(self) -> str:
        # Never expose the API key (e.g. in a traceback's locals or a log line).
        return (
            f"{type(self).__name__}(base_url={self._base_url!r}, "
            f"model={self._model!r}, profile={self._profile.name!r})"
        )

    # -- request assembly -------------------------------------------------------

    def prepare_messages(self, messages: list[dict]) -> list[dict]:
        """Apply the profile's message normalisation (never mutates input).

        ``first_only`` merges every system message's text into the first
        system message (joined by blank lines) and drops the others. All
        other messages, including ``reasoning_content`` on assistant
        messages, pass through untouched.
        """
        out = list(messages)
        if self._profile.system_mode != "first_only":
            return out
        system_idx = [i for i, m in enumerate(out) if m.get("role") == "system"]
        if len(system_idx) < 2:
            return out
        parts = []
        for i in system_idx:
            content = out[i].get("content")
            if content:
                parts.append(content if isinstance(content, str) else str(content))
        first = system_idx[0]
        merged = dict(out[first], content="\n\n".join(parts))
        drop = set(system_idx[1:])
        return [merged if i == first else m for i, m in enumerate(out) if i not in drop]

    def build_request(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        *,
        tool_choice: str | dict | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        top_p: float | None = None,
        extra_body: dict[str, Any] | None = None,
        stream: bool = True,
    ) -> dict[str, Any]:
        """Build the JSON payload (per-call arguments win over options).

        ``tool_choice`` values the profile does not support are dropped
        (forced choices unless ``forced_tool_choice``; ``"none"`` unless
        ``tool_choice_none``), and ``tool_choice`` is only sent with tools.
        ``extra_body`` (options, then per call) is merged last.
        """
        opts = self._options
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": self.prepare_messages(messages),
            "stream": stream,
        }
        if stream and self._profile.stream_usage:
            payload["stream_options"] = {"include_usage": True}
        if tools:
            payload["tools"] = tools
            choice = tool_choice if tool_choice is not None else opts.tool_choice
            if choice is not None and self._tool_choice_supported(choice):
                payload["tool_choice"] = choice
            if self._profile.parallel_tool_calls is not None:
                payload["parallel_tool_calls"] = self._profile.parallel_tool_calls
        limit = max_tokens if max_tokens is not None else opts.max_tokens
        if limit is not None and self._profile.max_output:
            limit = min(limit, self._profile.max_output)
        if limit is not None:
            payload["max_tokens"] = int(limit)
        temp = temperature if temperature is not None else opts.temperature
        if temp is not None:
            payload["temperature"] = temp
        nucleus = top_p if top_p is not None else opts.top_p
        if nucleus is not None:
            payload["top_p"] = nucleus
        payload.update(opts.extra_body)
        if extra_body:
            payload.update(extra_body)
        return payload

    def _tool_choice_supported(self, choice: str | dict) -> bool:
        if choice == "none":
            supported = self._profile.tool_choice_none
        elif choice == "auto":
            supported = True
        else:  # "required" or {"type": "function", ...}
            supported = self._profile.forced_tool_choice
        if not supported:
            logger.debug(
                "Dropping tool_choice=%r (profile %s)", choice, self._profile.name
            )
        return supported

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    def _timeout(self) -> tuple[float, float]:
        return (self._options.connect_timeout_s, self._options.read_timeout_s)

    def _redact(self, text: str) -> str:
        from sandroid.ai.safety import redact_secrets

        return redact_secrets(text, [self._api_key] if self._api_key else [])

    # -- streaming --------------------------------------------------------------

    def stream(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        *,
        tool_choice: str | dict | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        top_p: float | None = None,
        extra_body: dict[str, Any] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> Iterator[StreamChunk]:
        """Stream one chat completion as typed chunks.

        Args:
            messages: Chat-completions message list (not mutated).
            tools: ``tools=[...]`` schema, or ``None``.
            tool_choice: Per-call ``tool_choice`` (e.g. ``"none"`` for
                wrap-up requests); overrides ``options.tool_choice``.
            max_tokens: Per-call output limit.
            temperature: Per-call temperature.
            top_p: Per-call nucleus sampling value.
            extra_body: Extra payload keys, merged last.
            cancel_event: Checked between stream lines and during retry
                waits; when set the stream ends with a ``cancelled`` chunk.

        Yields:
            Chunks ending in exactly one terminal chunk (``done``, ``error``
            or ``cancelled``). Closing the generator early (cancel) closes
            the HTTP response.
        """
        payload = self.build_request(
            messages,
            tools,
            tool_choice=tool_choice,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            extra_body=extra_body,
        )
        retry_max = max(0, self._options.retry_max)
        attempt = 0
        while True:
            if cancel_event is not None and cancel_event.is_set():
                yield StreamChunk(kind="cancelled")
                return
            outcome = yield from self._attempt(payload, cancel_event)
            if outcome is None:
                return
            if attempt >= retry_max:
                yield StreamChunk(kind="error", error=outcome.error)
                return
            attempt += 1
            delay = self._retry_delay(attempt, outcome.retry_after)
            yield StreamChunk(
                kind="retry",
                retry=RetryInfo(
                    attempt=attempt,
                    max_attempts=retry_max,
                    delay_s=delay,
                    reason=outcome.reason,
                ),
            )
            if self._sleep(delay, cancel_event):
                yield StreamChunk(kind="cancelled")
                return

    def _retry_delay(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(retry_after, self._options.retry_after_cap_s)
        base = _BACKOFF_S[min(attempt, len(_BACKOFF_S)) - 1]
        return base + random.uniform(0.0, base * 0.25)  # noqa: S311 (jitter)

    def _attempt(
        self, payload: dict, cancel_event: threading.Event | None
    ) -> Iterator[StreamChunk]:
        """One HTTP attempt. Returns a :class:`_Retry` or ``None`` (terminal
        chunk already yielded) as the generator's return value.
        """
        try:
            response = requests.post(
                f"{self._base_url}/chat/completions",
                json=payload,
                headers=self._headers(),
                stream=True,
                timeout=self._timeout(),
            )
        except requests.exceptions.ConnectionError as exc:
            msg = self._redact(f"AI backend request failed: {exc}")
            err = StreamError(kind="connect", message=msg, retryable=True)
            return _Retry(reason=f"connect: {type(exc).__name__}", error=err)
        except requests.exceptions.RequestException as exc:
            msg = self._redact(f"AI backend request failed: {exc}")
            yield StreamChunk(
                kind="error",
                error=StreamError(
                    kind="connect",
                    message=msg,
                    retryable=isinstance(exc, requests.exceptions.Timeout),
                ),
            )
            return None

        with closing(response):
            status = response.status_code or 0
            if not 200 <= status < 300:
                err = StreamError(
                    kind="http",
                    message=self._redact(
                        f"AI backend request failed: HTTP {status}"
                        f"{self._error_body(response)}"
                    ),
                    status=status,
                    retryable=status in RETRYABLE_STATUSES,
                )
                if status in RETRYABLE_STATUSES:
                    retry_after = _parse_retry_after(
                        (response.headers or {}).get("Retry-After")
                    )
                    return _Retry(
                        reason=f"HTTP {status}", error=err, retry_after=retry_after
                    )
                yield StreamChunk(kind="error", error=err)
                return None

            # SSE bodies are UTF-8; `requests` guesses ISO-8859-1 for text/*
            # without a charset, which corrupts multi-byte characters.
            response.encoding = "utf-8"
            state = _StreamState()
            splitter = _ThinkSplitter() if self._profile.think_tags else None
            saw_done = False
            try:
                for line in response.iter_lines(decode_unicode=True):
                    if cancel_event is not None and cancel_event.is_set():
                        yield StreamChunk(kind="cancelled")
                        return None
                    if not line or line.startswith(":"):
                        continue  # event separator / keep-alive comment
                    if not line.startswith("data:"):
                        continue
                    data = line[len("data:") :].strip()
                    if data == "[DONE]":
                        saw_done = True
                        break
                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError:
                        logger.debug("Skipping unparsable SSE data line: %r", data)
                        continue
                    if not isinstance(chunk, dict):
                        continue
                    if chunk.get("error") and not chunk.get("choices"):
                        yield StreamChunk(
                            kind="error",
                            error=self._server_error(chunk["error"], state),
                        )
                        return None
                    yield from self._chunks_from(chunk, state, splitter)
            except requests.exceptions.RequestException as exc:
                if not state.content_started:
                    msg = self._redact(f"AI backend stream dropped: {exc}")
                    err = StreamError(kind="connect", message=msg, retryable=True)
                    return _Retry(reason=f"stream: {type(exc).__name__}", error=err)
                yield from self._flush(splitter, state)
                yield StreamChunk(
                    kind="error",
                    error=self._interrupted(
                        f"AI backend stream interrupted: {exc}", state
                    ),
                )
                return None

            yield from self._flush(splitter, state)
            if not saw_done and state.finish_reason is None:
                if not state.content_started:
                    err = StreamError(
                        kind="connect",
                        message="AI backend returned an empty stream",
                        retryable=True,
                    )
                    return _Retry(reason="empty stream", error=err)
                yield StreamChunk(
                    kind="error",
                    error=self._interrupted(
                        "AI backend stream interrupted: ended without a finish",
                        state,
                    ),
                )
                return None
            yield StreamChunk(
                kind="done", finish_reason=state.finish_reason, usage=state.usage
            )
            return None

    def _interrupted(self, text: str, state: _StreamState) -> StreamError:
        return StreamError(
            kind="interrupted",
            message=self._redact(text),
            retryable=True,
            partial_text="".join(state.text),
            partial_reasoning="".join(state.reasoning),
        )

    def _server_error(self, error: Any, state: _StreamState) -> StreamError:
        if isinstance(error, dict):
            detail = error.get("message") or json.dumps(error, default=str)
        else:
            detail = str(error)
        return StreamError(
            kind="server",
            message=self._redact(f"AI backend error: {detail}"[:_ERROR_BODY_MAX]),
            partial_text="".join(state.text),
            partial_reasoning="".join(state.reasoning),
        )

    @staticmethod
    def _error_body(response: requests.Response) -> str:
        try:
            body = (response.text or "").strip()
        except Exception:
            return ""
        if not body:
            return ""
        try:
            parsed = json.loads(body)
            err = parsed.get("error") if isinstance(parsed, dict) else None
            if isinstance(err, dict) and err.get("message"):
                body = str(err["message"])
            elif isinstance(err, str):
                body = err
        except (json.JSONDecodeError, AttributeError):
            pass
        return f": {body[:_ERROR_BODY_MAX]}"

    def _emit_piece(self, kind: str, text: str, state: _StreamState) -> StreamChunk:
        state.content_started = True
        (state.reasoning if kind == "reasoning" else state.text).append(text)
        return StreamChunk(kind=kind, text=text)  # type: ignore[arg-type]

    def _flush(
        self, splitter: _ThinkSplitter | None, state: _StreamState
    ) -> Iterator[StreamChunk]:
        if splitter is not None:
            for kind, text in splitter.flush():
                yield self._emit_piece(kind, text, state)

    def _chunks_from(
        self,
        chunk: dict,
        state: _StreamState,
        splitter: _ThinkSplitter | None,
    ) -> Iterator[StreamChunk]:
        """Turn one parsed SSE JSON object into zero or more chunks."""
        choices = chunk.get("choices") or []
        if choices and isinstance(choices[0], dict):
            choice = choices[0]
            delta = choice.get("delta") or {}
            for name in dict.fromkeys(
                (self._profile.reasoning_field, "reasoning_content", "reasoning")
            ):
                reasoning = delta.get(name)
                if isinstance(reasoning, str) and reasoning:
                    yield self._emit_piece("reasoning", reasoning, state)
                    break
            content = delta.get("content")
            if isinstance(content, str) and content:
                if splitter is None:
                    yield self._emit_piece("text", content, state)
                else:
                    for kind, text in splitter.feed(content):
                        yield self._emit_piece(kind, text, state)
            for call in delta.get("tool_calls") or []:
                function = call.get("function") or {}
                state.content_started = True
                yield StreamChunk(
                    kind="tool_call",
                    tool_call=ToolCallDelta(
                        index=call.get("index", 0),
                        id=call.get("id"),
                        name=function.get("name"),
                        arguments_fragment=function.get("arguments") or "",
                    ),
                )
            if choice.get("finish_reason"):
                state.finish_reason = choice["finish_reason"]
        # Usage may arrive on a chunk with empty `choices` (include_usage).
        usage = chunk.get("usage")
        if isinstance(usage, dict):
            state.usage = Usage.from_dict(usage)
            yield StreamChunk(kind="usage", usage=state.usage)

    # -- health -----------------------------------------------------------------

    def health(self, ping: bool = True) -> HealthReport:
        """Check the backend: ``GET /models`` plus an optional 1-token ping.

        Never raises; failures are reported (redacted) in the result.
        """
        models: tuple[str, ...] = ()
        listed: bool | None = None
        max_input: int | None = None
        error: str | None = None
        models_ok = False
        try:
            with closing(
                requests.get(
                    f"{self._base_url}/models",
                    headers=self._headers(),
                    timeout=self._timeout(),
                )
            ) as resp:
                if 200 <= (resp.status_code or 0) < 300:
                    entries = (resp.json() or {}).get("data") or []
                    models = tuple(
                        str(e.get("id")) for e in entries if isinstance(e, dict)
                    )
                    models_ok = True
                    listed = self._model in models
                    for entry in entries:
                        if isinstance(entry, dict) and entry.get("id") == self._model:
                            raw = entry.get("max_input_tokens") or entry.get(
                                "max_model_len"
                            )
                            max_input = int(raw) if raw else None
                else:
                    error = f"GET /models: HTTP {resp.status_code}"
        except (requests.exceptions.RequestException, ValueError) as exc:
            error = f"GET /models failed: {exc}"

        ping_ok: bool | None = None
        ping_ms: float | None = None
        if ping:
            payload = self.build_request(
                [{"role": "user", "content": "ping"}], max_tokens=1, stream=False
            )
            started = time.monotonic()
            try:
                with closing(
                    requests.post(
                        f"{self._base_url}/chat/completions",
                        json=payload,
                        headers=self._headers(),
                        timeout=self._timeout(),
                    )
                ) as resp:
                    ping_ms = (time.monotonic() - started) * 1000.0
                    ping_ok = 200 <= (resp.status_code or 0) < 300
                    if not ping_ok and error is None:
                        error = f"ping: HTTP {resp.status_code}{self._error_body(resp)}"
            except requests.exceptions.RequestException as exc:
                ping_ok = False
                if error is None:
                    error = f"ping failed: {exc}"
        return HealthReport(
            ok=models_ok and ping_ok is not False,
            models_ok=models_ok,
            model_listed=listed,
            max_input_tokens=max_input,
            ping_ok=ping_ok,
            ping_ms=ping_ms,
            models=models,
            error=self._redact(error) if error else None,
        )


def _interruptible_sleep(delay: float, cancel_event: threading.Event | None) -> bool:
    """Sleep ``delay`` seconds; return True early if ``cancel_event`` fires."""
    if cancel_event is None:
        time.sleep(delay)
        return False
    return cancel_event.wait(delay)


# =============================================================================
# Legacy adapter (first-generation dict events)
# =============================================================================


class OpenAIClient(OpenAICompatClient):
    """Legacy dict-event API over :class:`OpenAICompatClient`.

    Kept until the runtime cut-over: :mod:`sandroid.ai.loop` consumes
    :meth:`chat`. Unless ``options`` are given, retries are off, matching
    the first-generation behaviour.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        *,
        options: ClientOptions | None = None,
        profile: ModelProfile | None = None,
    ):
        """See :class:`OpenAICompatClient`; default ``options`` retry 0 times."""
        super().__init__(
            base_url,
            api_key,
            model,
            options=options if options is not None else ClientOptions(retry_max=0),
            profile=profile,
        )

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        stream: bool = True,
    ) -> Iterator[dict]:
        """Stream a chat completion as first-generation ChatEvent dicts.

        Yields ``reasoning_delta``/``text_delta`` (``content``),
        ``tool_call_delta`` (``index``, ``id``, ``name``,
        ``arguments_fragment``), informational ``usage``/``retry`` dicts, and
        ends in exactly one ``{"type": "done"}`` or
        ``{"type": "error", "message": str}``.

        Args:
            messages: Chat-completions message list.
            tools: Optional tools schema.
            stream: Ignored (always streams); kept for compatibility.
        """
        del stream
        for chunk in self.stream(messages, tools):
            kind = chunk.kind
            if kind == "reasoning":
                yield {"type": "reasoning_delta", "content": chunk.text}
            elif kind == "text":
                yield {"type": "text_delta", "content": chunk.text}
            elif kind == "tool_call" and chunk.tool_call is not None:
                call = chunk.tool_call
                yield {
                    "type": "tool_call_delta",
                    "index": call.index,
                    "id": call.id,
                    "name": call.name,
                    "arguments_fragment": call.arguments_fragment,
                }
            elif kind == "usage" and chunk.usage is not None:
                yield {"type": "usage", "usage": chunk.usage.as_dict()}
            elif kind == "retry" and chunk.retry is not None:
                yield {"type": "retry", **asdict(chunk.retry)}
            elif kind == "done":
                yield {"type": "done"}
            elif kind == "error" and chunk.error is not None:
                yield {"type": "error", "message": chunk.error.message}
            elif kind == "cancelled":
                yield {"type": "error", "message": "AI request cancelled"}


__all__ = [
    "BUILTIN_PROFILES",
    "DEFAULT_PROFILE",
    "RETRYABLE_STATUSES",
    "ClientOptions",
    "HealthReport",
    "ModelProfile",
    "OpenAIClient",
    "OpenAICompatClient",
    "RetryInfo",
    "StreamChunk",
    "StreamError",
    "ToolCallDelta",
    "Usage",
    "builtin_profile",
    "match_profile",
    "resolve_profile",
]
