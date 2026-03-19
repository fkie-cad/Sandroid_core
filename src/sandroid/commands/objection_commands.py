"""Objection commands for mobile security testing.

Objection is a runtime mobile exploration toolkit, powered by Frida,
built to help assess the security posture of mobile applications
without requiring a jailbroken or rooted device.

This module provides command handlers for launching and interacting
with Objection sessions for the spotlight application.
"""

import logging
import shutil

from sandroid.services import get_objection_service, get_spotlight_service

from .base import (
    CommandCategory,
    CommandContext,
    CommandHandler,
    CommandResult,
    RequiresSpotlightApp,
)

logger = logging.getLogger(__name__)


class ObjectionCommand(RequiresSpotlightApp):
    """Command to open an Objection terminal for the spotlight app.

    Objection is a mobile security testing framework built on top of Frida
    that provides a REPL interface for exploring and testing mobile applications.
    It can be used to:
    - Bypass SSL pinning
    - Dump keychain/keystore data
    - Explore the file system
    - Hook methods and modify return values
    - And much more

    Prerequisites:
        - A spotlight app must be selected (uses RequiresSpotlightApp)
        - Frida server must be running on the device
        - The 'objection' command must be available in PATH
    """

    key = "b"
    name = "Objection Terminal"
    description = "Open Objection shell for spotlight app"
    category = CommandCategory.SECURITY
    views = ["security"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if Objection can be executed.

        Validates:
        1. A spotlight app is selected (via parent class)
        2. Frida server is running on the device
        3. The objection binary is available in PATH

        Args:
            ctx: Command context with toolbox access

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        # First check parent class (RequiresSpotlightApp)
        can_exec, reason = super().can_execute(ctx)
        if not can_exec:
            return can_exec, reason

        # Check if objection binary is available
        if not shutil.which("objection"):
            return (
                False,
                "Objection not found in PATH. Install with: pip install objection",
            )

        # Check if Frida server is running
        if ctx.toolbox and hasattr(ctx.toolbox, "frida_manager"):
            if ctx.toolbox.frida_manager is not None:
                if not ctx.toolbox.frida_manager.is_frida_server_running():
                    return (
                        False,
                        "Frida server not running. Press 'f' to start Frida first.",
                    )

        return True, ""

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute the Objection terminal command.

        Validates the spotlight app and returns data for the TUI layer
        to show the ObjectionModal and launch ObjectionTerminalScreen.
        No subprocess is started here -- the TUI action_objection handler
        manages the terminal screen lifecycle on the main thread.

        Args:
            ctx: Command context with toolbox and spotlight app info

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

        try:
            # Get the spotlight application package name
            spotlight_app = get_spotlight_service().get_app_tuple()
            if not spotlight_app or spotlight_app[0] is None:
                return CommandResult(
                    success=False,
                    message="No spotlight app selected",
                    error="Spotlight application is not set",
                )

            package_name = spotlight_app[0]
            logger.info(f"Objection ready for package: {package_name}")

            return CommandResult(
                success=True,
                message=f"Objection ready for {package_name}",
                data={
                    "package_name": package_name,
                    "action": "show_objection_modal",
                },
            )

        except Exception as e:
            error_msg = f"Error preparing Objection terminal: {e!s}"
            logger.exception(error_msg)
            return CommandResult(
                success=False,
                message="Objection launch failed",
                error=error_msg,
                data={"error_type": type(e).__name__},
            )


class ObjectionResumeCommand(CommandHandler):
    """Command to resume a minimized Objection session."""

    key = "O"
    name = "Resume Objection Session"
    description = "Resume minimized Objection terminal"
    category = CommandCategory.SECURITY
    views = ["security"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if there's an Objection session to resume."""
        session = get_objection_service().get_session()
        if session is None:
            return False, "No Objection session to resume. Press 'b' to start one."
        return True, ""

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Resume the minimized Objection session."""
        try:
            session = get_objection_service().get_session()
            if session is None:
                return CommandResult(
                    success=False,
                    message="No Objection session available",
                    error="Start an Objection session first with 'b'",
                )

            # Check if session is still valid
            if hasattr(session, "pty_process"):
                # ObjectionTerminalScreen -- check PTY state
                if (
                    session.pty_process is not None
                    and not session.pty_process.is_running()
                ):
                    get_objection_service().clear()
                    return CommandResult(
                        success=False,
                        message="Objection session has ended",
                        error="The previous session terminated. Start a new one with 'b'",
                    )
            elif hasattr(session, "poll"):
                # Legacy Popen fallback (safety net)
                if session.poll() is not None:
                    get_objection_service().clear()
                    return CommandResult(
                        success=False,
                        message="Objection session has ended",
                        error="The previous session terminated. Start a new one with 'b'",
                    )

            return CommandResult(
                success=True,
                message="Objection session ready to resume",
                data={"has_session": True},
            )

        except Exception as e:
            logger.exception(f"Error resuming Objection session: {e}")
            return CommandResult(
                success=False,
                message="Failed to resume Objection",
                error=str(e),
            )


def register_commands(registry) -> None:
    """Register all objection commands.

    Args:
        registry: CommandRegistry instance to register commands with
    """
    registry.register(ObjectionCommand())
    registry.register(ObjectionResumeCommand())
