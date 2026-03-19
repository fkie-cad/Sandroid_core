"""Frida server management commands."""

import logging

from sandroid.services import get_ui_service

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
                logger.info("Frida server is already running")

                # Show info message to user
                get_ui_service().show_blocking_info(
                    title="Frida Already Running",
                    message="Frida server is already running on the device.",
                    action_hint="No action needed - Frida is ready to use",
                )

                return CommandResult(
                    success=True,
                    message="Frida server is already running",
                    data={"frida_status": "already_running"},
                )

            # Frida not running - install and start it
            logger.info("Installing Frida server on device")
            ctx.toolbox.frida_manager.install_frida_server()

            logger.info("Starting Frida server on device")
            ctx.toolbox.frida_manager.run_frida_server()

            logger.info("Frida server started successfully")
            return CommandResult(
                success=True,
                message="Frida server installed and started successfully",
                data={"frida_status": "started"},
            )

        except Exception as e:
            error_msg = f"Error managing Frida server: {e!s}"
            logger.exception(error_msg)
            return CommandResult(
                success=False,
                message="Failed to start Frida server",
                error=error_msg,
            )


def register_commands(registry) -> None:
    """Register all Frida commands."""
    registry.register(FridaServerCommand())
