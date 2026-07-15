"""Sandroid AI package.

An OpenAI-compatible streaming chat client, a hand-rolled tool-calling loop,
a merged native + MCP tool registry, and a subagent ("agent-as-tool")
mechanism -- the building blocks behind Sandroid's Chat tab.

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

        SUBAGENT_TEMPLATES,       # subagents.SUBAGENT_TEMPLATES: dict[str, SubagentTemplate]
                                  # Available subagent templates (currently: "device-inspector").
        SubagentTemplate,         # subagents.SubagentTemplate dataclass (name, system_prompt,
                                  # tool_names) -- for defining new templates later.
    )

Import-time side effects (deliberate, see each module's own docstring for
why): importing this package eagerly registers every native tool (via
:mod:`sandroid.ai.tools.dummy_tools`) AND one orchestrator-facing tool per
subagent template (via :func:`sandroid.ai.subagents.register_subagent_tools`)
into the :class:`~sandroid.ai.tools.registry.ToolRegistry` singleton. So a
bare ``import sandroid.ai`` is enough to populate native + subagent tools,
and never touches config or spawns a subprocess.

MCP tools are the one thing NOT populated at import time: they require a
connected :class:`~sandroid.ai.mcp_client.MCPClientManager`, which needs
``config.mcp.servers`` (an app-lifecycle concern, not an import-time one).
The caller must explicitly::

    sandroid.ai.get_mcp_client_manager().start()
    sandroid.ai.bridge_mcp_tools()

before ``mcp:sandroid-dummy:*``-style tools appear in the registry.
"""

from sandroid.ai.client import OpenAIClient
from sandroid.ai.errors import AIClientError, ToolExecutionError
from sandroid.ai.loop import run_agent_turn
from sandroid.ai.mcp_client import MCPClientManager, get_mcp_client_manager
from sandroid.ai.subagents import (
    SUBAGENT_TEMPLATES,
    SubagentTemplate,
    register_subagent_tools,
)
from sandroid.ai.tools import (  # also imports dummy_tools
    bridge_mcp_tools,
    get_tool_registry,
)

register_subagent_tools()

__all__ = [
    "SUBAGENT_TEMPLATES",
    "AIClientError",
    "MCPClientManager",
    "OpenAIClient",
    "SubagentTemplate",
    "ToolExecutionError",
    "bridge_mcp_tools",
    "get_mcp_client_manager",
    "get_tool_registry",
    "run_agent_turn",
]
