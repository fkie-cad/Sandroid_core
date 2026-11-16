"""Safety defaults for Sandroid's EXPERIMENTAL AI Chat feature.

One small module owning every "is it safe to talk to the model?" decision, so
the TUI chat panel, background subtasks, and the MCP startup path all apply
the same rules:

- **Off unless explicitly configured.** :func:`get_ai_settings` reads
  ``config.ai`` (which the config loader also fills from ``SANDROID_AI__*``
  environment variables). There are no built-in defaults for the endpoint,
  key, or model -- all three must be set, or the feature stays disabled.
- **Localhost-only by default.** Device and app data (tool results, live
  session state, file contents the analyst lets the model read) is sent to
  ``ai.base_url``. Unless ``ai.allow_remote = true`` is set, only a loopback
  endpoint (``localhost``/``127.0.0.0/8``/``::1``) is accepted -- e.g. a local
  Ollama or vLLM server. Anything else is refused *before* a request is made.
- **Transparency.** :func:`egress_notice_lines` renders the "where does my
  data go" notice shown in the Chat panel before the first message.
- **Secrets.** :func:`redact_secrets` scrubs the configured API key (plus
  common token shapes) from any text that may end up in a log, transcript, or
  error message. The key is read preferably from the ``SANDROID_AI__API_KEY``
  environment variable; :func:`api_key_source` reports whether it instead sits
  in a plaintext config file so the UI can warn about it.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

#: Environment variable the config loader maps onto ``config.ai.api_key``
#: (``SANDROID_`` prefix + ``__`` nesting, see ``sandroid.config.loader``).
API_KEY_ENV_VAR = "SANDROID_AI__API_KEY"

#: Recommended local, OpenAI-compatible endpoints (shown in notices/help).
LOCAL_ENDPOINT_EXAMPLES = (
    "http://localhost:11434/v1 (Ollama)",
    "http://localhost:8000/v1 (vLLM)",
)

#: Placeholder substituted for anything secret.
REDACTED = "***"

_SENTINEL: Any = object()


def is_loopback_url(url: str | None) -> bool:
    """Return whether ``url``'s host is a loopback address.

    Accepts ``localhost`` (and ``*.localhost``), any ``127.0.0.0/8`` address
    and ``::1``. Private/LAN addresses (``10.x``, ``192.168.x``) are NOT
    loopback -- data sent there leaves the analyst's machine, so they need an
    explicit ``ai.allow_remote = true`` like any other remote host.
    """
    if not url:
        return False
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    host = host.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class AISettings:
    """A resolved snapshot of the AI connection settings.

    Attributes:
        base_url: OpenAI-compatible base URL, or ``None`` if unset.
        api_key: API key, or ``None`` if unset. Excluded from ``repr``.
        model: Model name, or ``None`` if unset.
        allow_remote: Whether a non-loopback ``base_url`` is permitted.
    """

    base_url: str | None = None
    api_key: str | None = field(default=None, repr=False)
    model: str | None = None
    allow_remote: bool = False

    @property
    def missing_fields(self) -> list[str]:
        """Names of the required ``ai.*`` settings that are not set."""
        return [
            name
            for name in ("base_url", "api_key", "model")
            if not (getattr(self, name) or "").strip()
        ]

    @property
    def is_configured(self) -> bool:
        """All three connection settings are present (says nothing about policy)."""
        return not self.missing_fields

    @property
    def is_local(self) -> bool:
        """The endpoint is on this machine (loopback)."""
        return is_loopback_url(self.base_url)

    @property
    def endpoint_display(self) -> str:
        """``base_url`` with any embedded credentials/query stripped, for display."""
        if not self.base_url:
            return "(not set)"
        try:
            parts = urlsplit(self.base_url)
        except ValueError:
            return redact_secrets(self.base_url)
        host = parts.hostname or ""
        if ":" in host:  # IPv6 literal
            host = f"[{host}]"
        try:
            port = f":{parts.port}" if parts.port else ""
        except ValueError:
            port = ""
        return f"{parts.scheme}://{host}{port}{parts.path}"

    @property
    def problem(self) -> str | None:
        """A user-facing reason the feature cannot be used, or ``None`` if ready."""
        if not self.is_configured:
            missing = ", ".join(f"ai.{name}" for name in self.missing_fields)
            return (
                f"AI Chat is not configured (missing: {missing}). It is an "
                "experimental, opt-in feature and stays off until ai.base_url, "
                "ai.model and the API key (preferably via the "
                f"{API_KEY_ENV_VAR} environment variable) are set."
            )
        scheme = urlsplit(self.base_url or "").scheme.lower()
        if scheme not in ("http", "https"):
            return "ai.base_url must be an http:// or https:// URL."
        if not self.is_local and not self.allow_remote:
            return (
                f"AI endpoint {self.endpoint_display} is not on this machine. "
                "Device and app data would leave the host, so remote endpoints "
                "are refused by default. Use a local OpenAI-compatible server "
                f"(e.g. {LOCAL_ENDPOINT_EXAMPLES[0]}) or set "
                "ai.allow_remote = true to opt in explicitly."
            )
        return None

    @property
    def is_ready(self) -> bool:
        """Configured AND permitted by the egress policy."""
        return self.problem is None


def get_ai_settings(ai_cfg: Any = _SENTINEL) -> AISettings:
    """Resolve :class:`AISettings` from ``config.ai``.

    Args:
        ai_cfg: An ``AIConfig``-like object (duck-typed). Defaults to the live
            ``Toolbox.config.ai``; ``None`` or a missing config yields an
            unconfigured snapshot rather than raising.
    """
    if ai_cfg is _SENTINEL:
        try:
            from sandroid.core.toolbox import Toolbox

            ai_cfg = getattr(getattr(Toolbox, "config", None), "ai", None)
        except Exception:
            ai_cfg = None

    def _str(name: str) -> str | None:
        value = getattr(ai_cfg, name, None)
        if value is None:
            return None
        value = str(value).strip()
        return value or None

    return AISettings(
        base_url=_str("base_url"),
        api_key=_str("api_key"),
        model=_str("model"),
        allow_remote=getattr(ai_cfg, "allow_remote", False) is True,
    )


def api_key_source(settings: AISettings) -> str | None:
    """Where the API key came from: ``"env"``, ``"config"`` or ``None`` (unset)."""
    if not settings.api_key:
        return None
    env_value = (os.environ.get(API_KEY_ENV_VAR) or "").strip()
    return "env" if env_value and env_value == settings.api_key else "config"


def egress_notice_lines(settings: AISettings) -> list[str]:
    """Plain-text lines of the data-egress notice shown before the first message.

    Plain text (no markup) so every caller can style/escape it as it needs.
    """
    lines = [
        (
            "AI Chat is EXPERIMENTAL. Model output can be wrong -- verify every "
            "finding before relying on it."
        ),
    ]
    if not settings.is_configured:
        lines.append(settings.problem or "")
        lines.append(
            "Recommended: a local OpenAI-compatible server, e.g. "
            + " or ".join(LOCAL_ENDPOINT_EXAMPLES)
            + "."
        )
        return lines

    where = "LOCAL (this machine)" if settings.is_local else "REMOTE"
    lines.append(
        f"Your prompts plus device and app data (tool results, live session "
        f"state, file contents you let it read) are sent to {where} endpoint "
        f"{settings.endpoint_display}, model '{settings.model}'."
    )
    if settings.is_local:
        lines.append(
            "Data stays on this host as long as that server does not forward it."
        )
    elif settings.allow_remote:
        lines.append(
            "ai.allow_remote = true: data LEAVES this machine. Prefer a local "
            "endpoint (" + " or ".join(LOCAL_ENDPOINT_EXAMPLES) + ") for "
            "real case data."
        )
    else:
        lines.append(settings.problem or "")
    if api_key_source(settings) == "config":
        lines.append(
            "Warning: the API key is stored in plaintext in your config file. "
            f"Prefer the {API_KEY_ENV_VAR} environment variable."
        )
    lines.append(
        "Device-changing tools always ask for your confirmation; read-only "
        "queries run automatically."
    )
    return lines


# -- secret redaction ---------------------------------------------------------

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Authorization headers / bearer tokens.
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{4,}"), rf"\1 {REDACTED}"),
    # OpenAI-style keys (sk-..., sk-proj-...).
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"), f"sk-{REDACTED}"),
    # Credentials embedded in a URL: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), rf"\1{REDACTED}@"),
    # key=value style secrets in query strings / log lines.
    (
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password)"
            r"(\s*[=:]\s*)(['\"]?)[^\s&'\",;]+"
        ),
        rf"\1\2\3{REDACTED}",
    ),
)


def _known_secrets() -> list[str]:
    """Secrets known to this process: the configured key and its env var."""
    secrets: list[str] = []
    try:
        key = get_ai_settings().api_key
    except Exception:
        key = None
    if key:
        secrets.append(key)
    env_key = (os.environ.get(API_KEY_ENV_VAR) or "").strip()
    if env_key:
        secrets.append(env_key)
    return secrets


def redact_secrets(
    text: Any, secrets: list[str] | tuple[str, ...] | None = None
) -> str:
    """Return ``text`` (stringified) with API keys and token-like values masked.

    Args:
        text: Anything; converted with ``str()``.
        secrets: Exact secret strings to mask in addition to the regex
            patterns. Defaults to the currently configured API key (and the
            ``SANDROID_AI__API_KEY`` environment value). Secrets shorter than
            4 characters are ignored (masking e.g. ``"k"`` would mangle text).
    """
    out = "" if text is None else str(text)
    candidates = list(secrets) if secrets is not None else _known_secrets()
    # Longest first so a key that contains another key is masked whole.
    for secret in sorted(
        {s for s in candidates if s and len(s) >= 4}, key=len, reverse=True
    ):
        out = out.replace(secret, REDACTED)
    for pattern, replacement in _SECRET_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def build_client(settings: AISettings | None = None):
    """Build an :class:`~sandroid.ai.client.OpenAIClient` if policy allows it.

    Raises:
        AIClientError: With :attr:`AISettings.problem` as the message when
            the feature is unconfigured or the endpoint is refused.
    """
    from sandroid.ai.client import OpenAIClient
    from sandroid.ai.errors import AIClientError

    settings = settings if settings is not None else get_ai_settings()
    problem = settings.problem
    if problem is not None:
        raise AIClientError(problem)
    return OpenAIClient(
        settings.base_url,  # type: ignore[arg-type]
        settings.api_key,  # type: ignore[arg-type]
        settings.model,  # type: ignore[arg-type]
    )
