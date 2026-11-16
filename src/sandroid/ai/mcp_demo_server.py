"""DEMO / TEST FIXTURE MCP server -- returns FAKE data only.

This is NOT a threat-intelligence source. It exists solely to demonstrate and
test that Sandroid can consume tools from an external MCP server (the stdio
round-trip, tool listing, and the ``mcp:<server>:<tool>`` bridge). Every
result it returns is fabricated and says so in-band, so that neither the model
nor an analyst can mistake it for a real finding.

It is **disabled by default** -- ``config.mcp.servers`` is empty out of the
box. To try the MCP pipeline, opt in explicitly::

    [[mcp.servers]]
    name = "sandroid-demo-fake-data"
    command = "python"            # the interpreter Sandroid runs in
    args = ["-m", "sandroid.ai.mcp_demo_server"]

Runnable standalone::

    python -m sandroid.ai.mcp_demo_server

Requires the optional ``mcp`` package (``pip install mcp``).
"""

import sys

#: Marker carried by every result of this server.
FAKE_DATA_NOTICE = (
    "FAKE DEMO DATA from the Sandroid MCP test fixture -- not real threat "
    "intelligence; never report it as a finding."
)

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - exercised only without mcp installed
    sys.stderr.write(
        "sandroid.ai.mcp_demo_server needs the 'mcp' package: pip install mcp\n"
    )
    raise

mcp_app = FastMCP("sandroid-demo-fake-data")


@mcp_app.tool()
def demo_reverse_string(text: str) -> str:
    """[DEMO FIXTURE] Reverse the given text (MCP round-trip test only)."""
    return text[::-1]


@mcp_app.tool()
def demo_fake_ioc_lookup(indicator: str) -> dict:
    """[DEMO FIXTURE - FAKE DATA] Return a fabricated IOC match for testing.

    Not a real threat-intel lookup: the result is hard-coded sample data and
    is labelled as such in every field that could be mistaken for a finding.
    """
    return {
        "FAKE_DEMO_DATA": True,
        "notice": FAKE_DATA_NOTICE,
        "indicator": indicator,
        "match": "FAKE-DEMO-family (not real)",
        "confidence": 0.0,
        "source": "sandroid-demo-fake-data (MCP test fixture)",
    }


if __name__ == "__main__":
    mcp_app.run(transport="stdio")
