"""Sandroid AI package.

The building blocks behind Sandroid's AI chat (see
``docs/development/ai_foundations.rst``)::

    transport   client.py        OpenAICompatClient (typed stream()), ModelProfile
    runtime     loop.py          AgentEvent, RunContext, run_turn(), ToolExecutor
                session.py       AgentSession (one thread), ConversationStore
                compaction.py    TokenMeter, masking, summary compaction
                results.py       ResultStore (R-ids), preview shaping
    tools       tools/           registry, toolsets, tool_search/call_tool/read_result
    policy      tool_permissions.py  rules, modes, ApprovalBroker
    agents      agents.py        AgentProfile, AgentManager, spawn_agent & co.

Public surface::

    from sandroid.ai import (
        AgentSession,             # session.AgentSession.open_new(...) / .resume(...)
        get_agent_manager,        # agents.get_agent_manager() -> AgentManager
        OpenAICompatClient,       # client.OpenAICompatClient(base_url, api_key, model)
        AIClientError,            # errors.AIClientError -- backend/policy failures
        ToolExecutionError,       # errors.ToolExecutionError -- tool dispatch failure
        get_tool_registry,        # tools.registry.get_tool_registry() -> ToolRegistry
        get_mcp_client_manager,   # mcp_client.get_mcp_client_manager() -> MCPClientManager
        MCPClientManager,
        bridge_mcp_tools,         # registers mcp:<server>:<tool> tools (call once,
                                  # after get_mcp_client_manager().start())
    )

``AgentSession``, ``get_agent_manager`` and ``OpenAICompatClient`` are loaded
on first access, so ``import sandroid.ai`` stays cheap.

Import-time side effects (deliberate): importing this package registers every
native tool into the :class:`~sandroid.ai.tools.registry.ToolRegistry`
singleton. The agent tools (``spawn_agent`` & co.) are registered lazily by
:func:`sandroid.ai.agents.orchestrator_extra_tools`. MCP tools need a
connected :class:`~sandroid.ai.mcp_client.MCPClientManager` (an app-lifecycle
concern), so the caller explicitly runs::

    sandroid.ai.get_mcp_client_manager().start()
    sandroid.ai.bridge_mcp_tools()

``start()`` is a no-op unless the AI chat is configured and permitted (see
:mod:`sandroid.ai.safety`) and at least one MCP server is enabled. The ``mcp``
package is imported lazily, so ``import sandroid.ai`` works without it.
"""

from typing import Any

from sandroid.ai.errors import AIClientError, ToolExecutionError
from sandroid.ai.mcp_client import MCPClientManager, get_mcp_client_manager
from sandroid.ai.tools import (  # also imports every native tool module
    bridge_mcp_tools,
    get_tool_registry,
)

_LAZY = {
    "AgentSession": ("sandroid.ai.session", "AgentSession"),
    "get_agent_manager": ("sandroid.ai.agents", "get_agent_manager"),
    "OpenAICompatClient": ("sandroid.ai.client", "OpenAICompatClient"),
}


def __getattr__(name: str) -> Any:
    """Load the heavier public names on first access."""
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module 'sandroid.ai' has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(target[0]), target[1])
    globals()[name] = value
    return value


__all__ = [
    "AIClientError",
    "AgentSession",
    "MCPClientManager",
    "OpenAICompatClient",
    "ToolExecutionError",
    "bridge_mcp_tools",
    "get_agent_manager",
    "get_mcp_client_manager",
    "get_tool_registry",
]
