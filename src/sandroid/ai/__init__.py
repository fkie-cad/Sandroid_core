"""Sandroid AI package.

An OpenAI-compatible streaming chat client, a hand-rolled tool-calling loop,
and a merged native + MCP tool registry -- the building blocks behind
Sandroid's Chat tab.

Public surface (the contract downstream code -- including the TUI chat
panel -- should build against)::

    from sandroid.ai import (
        run_agent_turn,          # loop.run_agent_turn(messages, tools, client,
                                  #     cancel_event, on_event=None, max_iterations=8) -> str
                                  # Drives one full streaming + tool-calling turn to
                                  # completion. Mutates `messages` in place (appends
                                  # assistant/tool messages). Streams ChatEvent dicts to
                                  # `on_event` as they arrive; returns the final text.

        OpenAIClient,             # client.OpenAIClient(base_url, api_key, model)
                                  # .chat(messages, tools=None, stream=True) -> Iterator[dict]
                                  # Streaming client for any OpenAI-compatible endpoint.

        AIClientError,            # errors.AIClientError -- backend connection/protocol failures
        ToolExecutionError,       # errors.ToolExecutionError -- unknown tool / tool dispatch failure

        get_tool_registry,        # tools.registry.get_tool_registry() -> ToolRegistry
                                  # The ToolRegistry singleton. .openai_tools_schema() for the
                                  # full tools=[...] param; .subset(names) for a narrower view;
                                  # .dispatch(name, arguments) to invoke one; .register(spec) to
                                  # add a new ToolSpec (or use the @sandroid_tool decorator, see
                                  # sandroid.ai.tools).

        get_mcp_client_manager,   # mcp_client.get_mcp_client_manager() -> MCPClientManager
                                  # The MCP manager singleton. Call .start() once (app startup,
                                  # e.g. TUI on_mount) to connect every enabled config.mcp.servers
                                  # entry; call .stop() once on shutdown (e.g. TUI on_unmount).
                                  # NOT started automatically by importing this package.

        MCPClientManager,         # mcp_client.MCPClientManager -- the class itself, if a caller
                                  # needs the type (e.g. for a test double).

        bridge_mcp_tools,         # tools.bridge_mcp_tools() -> None
                                  # Registers every tool from every connected MCP server into
                                  # the ToolRegistry as "mcp:<server>:<tool>". Call once, after
                                  # get_mcp_client_manager().start() has connected. NOT called
                                  # automatically by importing this package.
    )

Import-time side effects (deliberate, see each module's own docstring for
why): importing this package eagerly registers every native tool (via
:mod:`sandroid.ai.tools.app_query` and :mod:`sandroid.ai.tools.device_query`)
into the :class:`~sandroid.ai.tools.registry.ToolRegistry` singleton. So a
bare ``import sandroid.ai`` is enough to populate the native tools, and never
touches config or spawns a subprocess.

MCP tools are the one thing NOT populated at import time: they require a
connected :class:`~sandroid.ai.mcp_client.MCPClientManager`, which needs
``config.mcp.servers`` (an app-lifecycle concern, not an import-time one).
The caller must explicitly::

    sandroid.ai.get_mcp_client_manager().start()
    sandroid.ai.bridge_mcp_tools()

before ``mcp:sandroid-dummy:*``-style tools appear in the registry.
"""

from sandroid.ai import subtasks  # side-effect: registers the two spawn tools
from sandroid.ai.client import OpenAIClient
from sandroid.ai.errors import AIClientError, ToolExecutionError
from sandroid.ai.loop import run_agent_turn
from sandroid.ai.mcp_client import MCPClientManager, get_mcp_client_manager
from sandroid.ai.subtasks import get_subtask_manager
from sandroid.ai.tools import (  # also imports app_query, device_query
    bridge_mcp_tools,
    get_tool_registry,
)

__all__ = [
    "AIClientError",
    "MCPClientManager",
    "OpenAIClient",
    "ToolExecutionError",
    "bridge_mcp_tools",
    "get_mcp_client_manager",
    "get_subtask_manager",
    "get_tool_registry",
    "run_agent_turn",
]
