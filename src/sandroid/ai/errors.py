"""Exception types for the Sandroid AI package.

Kept intentionally small and flat -- every module in ``sandroid.ai`` raises one
of these two rather than letting provider-specific or protocol-specific
exceptions (``requests`` errors, MCP transport errors, etc.) leak to callers.
"""


class AIClientError(Exception):
    """Raised for AI-backend connection/protocol failures.

    Covers connection failures and non-2xx responses from the configured
    OpenAI-compatible endpoint that cannot be cleanly surfaced as a streamed
    ``error`` ``ChatEvent`` (see :mod:`sandroid.ai.client`), plus MCP-manager
    misuse (e.g. calling a tool before :meth:`MCPClientManager.start` has run).
    """


class ToolExecutionError(Exception):
    """Raised when a tool dispatch fails.

    Covers both an unknown tool name (see :meth:`ToolRegistry.dispatch`) and,
    optionally, tool implementations that want to surface a clean, user-facing
    failure message rather than letting an arbitrary exception type propagate.
    """
