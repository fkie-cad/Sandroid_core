"""Memory analysis commands.

Commands for memory dumping and analysis using Frida.
"""

import logging

from sandroid.services import get_spotlight_service

from .base import (
    CommandCategory,
    CommandContext,
    CommandResult,
    RequiresSpotlightApp,
)

logger = logging.getLogger(__name__)


class MemoryDumpCommand(RequiresSpotlightApp):
    """Command to dump memory of the spotlight application.

    Uses Fridump to extract memory from the running application.
    Requires Frida server to be running on the device.
    """

    key = "d"
    name = "Memory Dump"
    description = "Dump memory of spotlight app using Fridump"
    category = CommandCategory.ANALYSIS
    views = ["forensic", "malware", "security"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check preconditions for memory dump.

        Requires:
        - A spotlight app to be selected (from parent class)
        - Frida server to be running

        Args:
            ctx: Command context

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        # Check spotlight app first (parent class)
        can_exec, reason = super().can_execute(ctx)
        if not can_exec:
            return can_exec, reason

        # Check Frida server is running
        frida_running = False

        # Try service-based check first
        try:
            from sandroid.services import get_frida_session_service

            frida_service = get_frida_session_service()
            frida_manager = frida_service.get_frida_manager()
            if frida_manager:
                frida_running = frida_manager.is_frida_server_running()
        except Exception:
            pass

        # Fallback to toolbox check
        if not frida_running and ctx.toolbox:
            if hasattr(ctx.toolbox, "frida_manager") and ctx.toolbox.frida_manager:
                frida_running = ctx.toolbox.frida_manager.is_frida_server_running()

        if not frida_running:
            return (
                False,
                "Frida server not running. Press 'f' to start Frida first.",
            )

        return True, ""

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute memory dump of the spotlight application."""
        try:
            from sandroid.core.fridump import Fridump

            # Get spotlight app info - use context if available
            if ctx.spotlight_service:
                spotlight_app = ctx.spotlight_service.get_app_tuple()
                pid = ctx.spotlight_service.get_pid()
            else:
                spotlight = get_spotlight_service()
                spotlight_app = spotlight.get_app_tuple()
                pid = spotlight.get_pid()

            if not spotlight_app or spotlight_app[0] is None:
                return CommandResult(
                    success=False,
                    message="No spotlight app selected",
                    error="Select an app first with 'c'",
                )

            package_name = spotlight_app[0]

            if pid is None:
                # Try to get PID from ADB
                if ctx.adb:
                    pid = ctx.adb.get_pid_for_package_name(package_name)
                if pid is None:
                    return CommandResult(
                        success=False,
                        message="Could not get app PID",
                        error=f"App {package_name} may not be running",
                    )

            logger.info(f"Starting memory dump for {package_name} (PID: {pid})")

            # Perform memory dump
            Fridump.dump_memory(pid=pid, process_name=package_name)

            import os

            subdirectory = package_name.replace(".", "-")
            output_directory = os.path.join(os.getcwd(), "dump", subdirectory)

            return CommandResult(
                success=True,
                message=f"Memory dump completed for {package_name}",
                data={
                    "package": package_name,
                    "pid": pid,
                    "output_dir": output_directory,
                },
            )

        except ImportError as e:
            logger.error(f"Fridump import error: {e}")
            return CommandResult(
                success=False,
                message="Fridump not available",
                error="Memory dump functionality requires Frida",
            )
        except Exception as e:
            logger.exception(f"Memory dump failed: {e}")
            return CommandResult(
                success=False, message="Memory dump failed", error=str(e)
            )


def register_commands(registry) -> None:
    """Register memory analysis commands."""
    registry.register(MemoryDumpCommand())
