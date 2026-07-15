"""Native, in-process placeholder tools.

These are plain first-party Python functions -- no subprocess, no MCP, no
protocol overhead -- standing in for capabilities Sandroid will always own
itself once the real Toolbox integration lands (emulator status, installed
packages, running background tasks). Every result includes a
``"note": "SAMPLE DATA"`` marker so the LLM (and anyone reading a transcript)
never mistakes fabricated demo data for a real finding.

Contrast with :mod:`sandroid.ai.mcp_dummy_server`, whose whole purpose is the
opposite: proving Sandroid can consume a genuinely *external* MCP tool
server, not hosting Sandroid's own capabilities.

Importing this module registers all three tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator).
"""

from sandroid.ai.tools.registry import sandroid_tool


@sandroid_tool(
    name="get_emulator_status",
    description=(
        "Get the current status of the running Android emulator "
        "(state, API level, device name, uptime)."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)
def get_emulator_status() -> dict:
    """Return a fabricated emulator status.

    Real integration point: :class:`sandroid.services.emulator_service.EmulatorService`.
    """
    return {
        "state": "running",
        "api_level": 34,
        "device_name": "emulator-5554",
        "uptime_seconds": 1234,
        "note": "SAMPLE DATA",
    }


@sandroid_tool(
    name="list_installed_packages",
    description="List installed package names on the target device (sample data).",
    parameters={
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Maximum number of packages to return.",
                "default": 10,
            },
        },
        "required": [],
    },
)
def list_installed_packages(limit: int = 10) -> dict:
    """Return a fabricated list of installed package names.

    Real integration point: ``adb shell pm list packages -3`` via
    :class:`sandroid.core.adb.Adb`.
    """
    packages = [f"com.example.app{i}" for i in range(1, limit + 1)]
    return {"packages": packages, "count": len(packages), "note": "SAMPLE DATA"}


@sandroid_tool(
    name="get_running_background_tasks",
    description=(
        "List Sandroid background tasks currently running "
        "(e.g. FriTap, network capture, chat -- sample data)."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)
def get_running_background_tasks() -> dict:
    """Return fabricated task names shaped like the real ``Toolbox.get_running_tasks()``.

    Real integration point: :meth:`sandroid.core.toolbox.Toolbox.get_running_tasks`,
    which returns a ``list[str]`` of task names -- this deliberately previews that
    exact shape.
    """
    return {
        "tasks": ["fritap", "network-capture", "chat"],
        "note": "SAMPLE DATA",
    }
