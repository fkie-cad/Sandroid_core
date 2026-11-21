"""Frida server management commands."""

import logging

from .base import CommandCategory, CommandContext, CommandHandler, CommandResult

logger = logging.getLogger(__name__)


class FridaServerCommand(CommandHandler):
    """Command to install and start Frida server on the device.

    This command checks if Frida server is already running. If not,
    it installs and starts the server. If already running, it shows
    an informational message to the user.
    """

    key = "f"
    name = "Frida Server"
    description = "Install and start Frida server on device"
    category = CommandCategory.FRIDA
    views = ["forensic", "malware", "security"]

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute the Frida server command.

        Args:
            ctx: Command context with access to toolbox and frida_manager

        Returns:
            CommandResult indicating success/failure of the operation
        """
        # Verify toolbox is available
        if ctx.toolbox is None:
            logger.error("Toolbox not available in command context")
            return CommandResult(
                success=False,
                message="Toolbox not available",
                error="Command context missing toolbox reference",
            )

        # Verify frida_manager is available
        if (
            not hasattr(ctx.toolbox, "frida_manager")
            or ctx.toolbox.frida_manager is None
        ):
            logger.error("Frida manager not available in toolbox")
            return CommandResult(
                success=False,
                message="Frida manager not available",
                error="Toolbox does not have a frida_manager configured",
            )

        try:
            # Check if Frida server is already running
            if ctx.toolbox.frida_manager.is_frida_server_running():
                # A toast, not a dead-end dialog that has to be closed (N6-V8).
                return CommandResult(
                    success=True,
                    message="frida-server is already running: nothing to start",
                    data={"frida_status": "already_running", "toast": True},
                )

            # Frida not running - install (only if missing/outdated) and start
            from sandroid.core.frida_manager import ensure_frida_server_started

            logger.info("Starting Frida server on device")
            started = ensure_frida_server_started(ctx.toolbox.frida_manager)

            if not started:
                logger.error("Frida server failed to start")
                return CommandResult(
                    success=False,
                    message="Frida server failed to start",
                    error=(
                        "run_frida_server() reported the server is not reachable. "
                        "Check the log / `adb logcat` for an ART/SIGABRT tombstone."
                    ),
                )

            logger.info("Frida server started successfully")
            return CommandResult(
                success=True,
                message="Frida server started successfully",
                data={"frida_status": "started"},
            )

        except Exception as e:
            from sandroid.core.frida_manager import describe_frida_install_error

            error_msg = (
                f"Error managing Frida server: {describe_frida_install_error(e)}"
            )
            logger.exception(error_msg)
            return CommandResult(
                success=False,
                message="Failed to start Frida server",
                error=error_msg,
            )


def register_commands(registry) -> None:
    """Register all Frida commands."""
    registry.register(FridaServerCommand())
