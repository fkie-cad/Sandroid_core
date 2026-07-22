"""Bridges tools from connected MCP servers into the ToolRegistry.

Each discovered tool is registered as ``mcp:<server>:<tool>`` with a dispatch
closure that calls back into :class:`~sandroid.ai.mcp_client.MCPClientManager`.
MCP's ``inputSchema`` and the registry's ``parameters`` field are both plain
JSON Schema, so it's passed straight through -- no translation needed beyond
the key rename.

Not called automatically anywhere -- this is an explicit app-lifecycle action
for whoever starts the MCP manager (see :func:`sandroid.ai.tools.bridge_mcp_tools`,
re-exported from this module), since it requires the manager to already be
started/connected.
"""

import json
import logging

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.mcp_client import MCPClientManager, get_mcp_client_manager
from sandroid.ai.tools.registry import ToolRegistry, ToolSpec, get_tool_registry

logger = logging.getLogger(__name__)


def bridge_mcp_tools() -> None:
    """Register every tool from every connected MCP server into the ToolRegistry.

    Call once, after :meth:`MCPClientManager.start` has connected to the
    configured servers. Safe to call again later (e.g. after reconnecting) --
    re-registering a tool name just overwrites the previous entry.
    """
    manager = get_mcp_client_manager()
    registry = get_tool_registry()
    for server_name, tools in manager.list_all_tools().items():
        for tool in tools:
            _register_one(registry, manager, server_name, tool)


def _register_one(
    registry: ToolRegistry, manager: MCPClientManager, server_name: str, tool
) -> None:
    qualified_name = f"mcp:{server_name}:{tool.name}"

    def dispatch(**arguments):
        result = manager.call_tool(server_name, tool.name, arguments)
        return _unwrap_call_tool_result(qualified_name, result)

    registry.register(
        ToolSpec(
            name=qualified_name,
            description=tool.description or "",
            parameters=tool.inputSchema,
            func=dispatch,
            category="mcp",
        )
    )


def _unwrap_call_tool_result(qualified_name: str, result):
    """Extract a JSON-friendly value from an MCP ``CallToolResult``.

    Verified against the real bundled dummy server + installed ``mcp==1.28.1``:
    ``result.content`` is a list of content blocks (``TextContent`` in every
    case exercised here, exposing ``.text``); ``result.structuredContent`` is
    populated inconsistently across return types (present for scalar returns,
    absent for plain-dict returns from a ``FastMCP`` tool without an explicit
    output schema) so it is not relied upon. Instead: take the first content
    block's text, try ``json.loads`` on it (recovers dict-shaped tool results
    like ``sample_forensic_lookup``), and fall back to the raw string
    (recovers scalar results like ``reverse_string``).

    Raises:
        ToolExecutionError: If the MCP server reported ``isError``.
    """
    if getattr(result, "isError", False):
        message = _first_text(result) or "MCP tool call failed"
        raise ToolExecutionError(f"{qualified_name}: {message}")

    text = _first_text(result)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _first_text(result) -> str | None:
    content = getattr(result, "content", None) or []
    for block in content:
        text = getattr(block, "text", None)
        if text is not None:
            return text
    return None
