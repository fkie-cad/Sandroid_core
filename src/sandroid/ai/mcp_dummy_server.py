"""Bundled dummy MCP server.

Its purpose is narrower than Sandroid's native tools (see
:mod:`sandroid.ai.tools.app_query` and :mod:`sandroid.ai.tools.device_query`):
it exists to demonstrate that Sandroid can consume a genuinely *external* MCP
tool server, not to host Sandroid's own capabilities. Unlike those native
tools, which now dispatch to real ADB/device queries, everything here is
deliberately fabricated -- tools are framed in an "external service" style, a
trivial deterministic tool plus a fabricated third-party-style threat-intel
lookup.

Built on the official ``mcp`` package's ``mcp.server.fastmcp.FastMCP``, which
ships in the base ``mcp`` distribution (no extra needed).

Runnable standalone::

    python -m sandroid.ai.mcp_dummy_server

Sandroid itself launches this the same way, via
``StdioServerParameters(command=sys.executable, args=["-m", "sandroid.ai.mcp_dummy_server"])``
(see :mod:`sandroid.ai.mcp_client`) -- using ``sys.executable`` guarantees the
same interpreter/venv is used, no PATH hunting required.
"""

from mcp.server.fastmcp import FastMCP

mcp_app = FastMCP("sandroid-dummy")


@mcp_app.tool()
def reverse_string(text: str) -> str:
    """Reverse the given text.

    Trivial and deterministic on purpose: it proves the
    request -> MCP -> tool -> result round-trip with zero ambiguity.
    """
    return text[::-1]


@mcp_app.tool()
def sample_forensic_lookup(indicator: str) -> dict:
    """Look up a fabricated IOC/threat-intel match for the given indicator.

    Thematically previews a plausible *real* external MCP integration later
    (a third-party threat-intel service) -- exactly the case MCP is for. All
    data returned here is fabricated sample data.
    """
    return {
        "indicator": indicator,
        "match": "sample-malware-family-X",
        "confidence": 0.42,
        "source": "sandroid-dummy-mcp (fabricated sample data)",
    }


if __name__ == "__main__":
    mcp_app.run(transport="stdio")
