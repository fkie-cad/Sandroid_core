"""Real, ADB-backed network-query tools for the Sandroid AI chat.

Every tool here dispatches to a genuinely existing
:class:`~sandroid.core.adb.Adb` classmethod -- no ``"note": "SAMPLE DATA"``
markers, this is real device data.

Importing this module registers both tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). Both tools in this module are
``RiskTier.READ_ONLY`` and ``category="network_query"``.
"""

from typing import Any

from sandroid.ai.tools.registry import RiskTier, sandroid_tool
from sandroid.core.adb import Adb


@sandroid_tool(
    name="list_connections",
    description=(
        "List the device's active TCP socket connections (parsed from "
        "/proc/net/tcp and /proc/net/tcp6): local/remote address and port, "
        "connection state, and the owning uid/package name where it could "
        "be resolved."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="network_query",
)
def list_connections() -> dict[str, Any]:
    """Return the device's current TCP socket table.

    Real integration point: :meth:`sandroid.core.adb.Adb.list_connections`.

    Returns:
        ``{"connections": [...], "count": len(...)}`` -- ``connections`` is
        the raw list of dicts returned by ``Adb.list_connections`` (each with
        ``protocol``, ``local_address``, ``local_port``, ``remote_address``,
        ``remote_port``, ``state``, ``uid``, and ``package_name``).
    """
    connections = Adb.list_connections()
    return {"connections": connections, "count": len(connections)}


@sandroid_tool(
    name="get_network_info",
    description=(
        "Get the device's network interfaces and their IPv4 addresses "
        "(e.g. 'wlan0', 'lo')."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="network_query",
)
def get_network_info() -> dict[str, Any]:
    """Return the device's network interfaces and addresses.

    Real integration point: :meth:`sandroid.core.adb.Adb.get_network_info`,
    whose ``list[tuple[str, str]]`` return shape is converted into a list of
    ``{"interface": ..., "ip": ...}`` dicts for a stable, self-describing
    tool-result schema.

    Returns:
        ``{"interfaces": [{"interface": ..., "ip": ...}, ...], "count": len(...)}``.
    """
    interfaces = [{"interface": name, "ip": ip} for name, ip in Adb.get_network_info()]
    return {"interfaces": interfaces, "count": len(interfaces)}
