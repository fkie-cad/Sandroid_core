"""Native + MCP tool registration for the Sandroid AI package.

Importing this package eagerly registers all native tools (side effect of
importing :mod:`sandroid.ai.tools.app_query` and
:mod:`sandroid.ai.tools.device_query`). It does NOT start the MCP client or
bridge MCP tools -- that is an app-lifecycle action for the caller (start
:class:`~sandroid.ai.mcp_client.MCPClientManager`, then call
:func:`bridge_mcp_tools` once), since it requires a running, connected
manager to have anything to bridge.
"""

from sandroid.ai.tools import (
    app_query,
    device_query,
)
from sandroid.ai.tools.mcp_bridge import bridge_mcp_tools
from sandroid.ai.tools.registry import (
    RiskTier,
    ToolRegistry,
    ToolSpec,
    get_tool_registry,
    sandroid_tool,
)

__all__ = [
    "RiskTier",
    "ToolRegistry",
    "ToolSpec",
    "bridge_mcp_tools",
    "get_tool_registry",
    "sandroid_tool",
]
