"""Capture commands for screenshots and screen recording."""

import logging

from sandroid.services import get_emulator_service

from .base import CommandCategory, CommandContext, CommandHandler, CommandResult

logger = logging.getLogger(__name__)


class ScreenshotCommand(CommandHandler):
    """Command handler for taking device screenshots."""

    key = "s"
    name = "Take Screenshot"
    description = "Capture the current screen and save to results"
    category = CommandCategory.CAPTURE
    views = ["forensic", "malware", "security"]

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute screenshot capture.

        Prompts for optional filename, then captures the screen.
        Uses TUI input modal in TUI mode, otherwise uses safe_input.

        Args:
            ctx: Command context with toolbox and UI access

        Returns:
            CommandResult indicating success/failure
        """
        if not ctx.toolbox:
            return CommandResult(
                success=False,
                message="Toolbox not available",
                error="No toolbox in context",
            )

        # Get optional filename from user
        filename: str | None = None

        try:
            if ctx.is_tui_mode and ctx.request_input:
                # TUI mode - use async input modal
                filename = ctx.request_input(
                    title="Screenshot Filename",
                    message="Enter filename (leave blank for timestamp):",
                    default="screenshot_name.png",
                )
            else:
                # Rich console mode - use safe_input
                logger.info("Enter screenshot filename (leave blank for timestamp):")
                filename = ctx.toolbox.safe_input("Filename: ")
        except Exception as e:
            logger.warning(f"Error getting filename input: {e}")
            # Continue with default timestamp filename

        # Empty string means use timestamp
        if filename is not None and filename.strip() == "":
            filename = None

        # Take the screenshot
        try:
            result_path = ctx.toolbox.take_screenshot(filename)

            if result_path:
                return CommandResult(
                    success=True,
                    message=f"Screenshot saved to: {result_path}",
                    data={"screenshot_path": result_path},
                )
            return CommandResult(
                success=False,
                message="Failed to capture screenshot",
                error="Screenshot capture returned None",
            )
        except Exception as e:
            logger.exception("Error taking screenshot")
            return CommandResult(
                success=False, message=f"Screenshot failed: {e!s}", error=str(e)
            )


class ScreenRecordingCommand(CommandHandler):
    """Command handler for toggling screen recording.

    This is a toggle command - pressing 'g' starts recording,
    pressing 'g' again stops it.
    """

    key = "g"
    name = "Screen Recording"
    description = "Start/stop screen recording"
    category = CommandCategory.CAPTURE
    views = ["forensic", "malware", "security"]

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Toggle screen recording on/off.

        If recording is not running, prompts for filename and starts recording.
        If recording is running, stops it.

        Args:
            ctx: Command context with toolbox and UI access

        Returns:
            CommandResult indicating success/failure
        """
        if not ctx.toolbox:
            return CommandResult(
                success=False,
                message="Toolbox not available",
                error="No toolbox in context",
            )

        # Check if recording is already running
        if get_emulator_service().is_recording():
            return await self._stop_recording(ctx)
        return await self._start_recording(ctx)

    async def _start_recording(self, ctx: CommandContext) -> CommandResult:
        """Start screen recording after prompting for filename.

        In TUI mode, shows a status modal that user can dismiss to stop recording.
        In Rich console mode, starts recording and returns (user presses 'g' again to stop).

        Args:
            ctx: Command context

        Returns:
            CommandResult for the start operation
        """
        # Get optional filename from user
        filename: str | None = None

        try:
            if ctx.is_tui_mode and ctx.request_input:
                # TUI mode - use input modal
                filename = ctx.request_input(
                    title="Screen Recording Filename",
                    message="Enter filename (leave blank for timestamp):",
                    default="recording_name.webm",
                )
            else:
                # Rich console mode - use safe_input
                logger.info("Enter recording filename (leave blank for timestamp):")
                filename = ctx.toolbox.safe_input("Filename: ")
        except Exception as e:
            logger.warning(f"Error getting filename input: {e}")
            # Continue with default timestamp filename

        # Empty string means use timestamp
        if filename is not None and filename.strip() == "":
            filename = None

        # Start the recording
        try:
            emulator_service = get_emulator_service()
            success = emulator_service.start_recording(filename)

            if not success:
                return CommandResult(
                    success=False,
                    message="Failed to start screen recording",
                    error="start_screen_recording returned False",
                )

            recording_file = emulator_service.get_recording_file()

            # In TUI mode, show the recording modal (blocks until user stops)
            if ctx.is_tui_mode:
                try:
                    from sandroid.core.ui_request_bus import request_modal
                    from sandroid.tui.modals import ScreenRecordingModal

                    # Show modal - blocks until user dismisses
                    result = request_modal(
                        ScreenRecordingModal,
                        output_file=recording_file or "",
                    )

                    # Modal dismissed - stop recording
                    emulator_service.stop_recording()

                    return CommandResult(
                        success=True,
                        message=f"Screen recording saved to: {recording_file}",
                        data={"recording_file": recording_file, "action": "stopped"},
                    )
                except ImportError:
                    logger.debug(
                        "ScreenRecordingModal not available, using simple mode"
                    )
                except Exception as e:
                    logger.warning(f"Error showing recording modal: {e}")
                    # Fall through to simple mode

            # Non-TUI mode or modal failed: just return started status
            return CommandResult(
                success=True,
                message=f"Started screen recording: {recording_file}",
                data={"recording_file": recording_file, "action": "started"},
            )

        except Exception as e:
            logger.exception("Error starting screen recording")
            return CommandResult(
                success=False, message=f"Failed to start recording: {e!s}", error=str(e)
            )

    async def _stop_recording(self, ctx: CommandContext) -> CommandResult:
        """Stop the current screen recording.

        Args:
            ctx: Command context

        Returns:
            CommandResult for the stop operation
        """
        try:
            # Get the filename before stopping (for the message)
            emulator_service = get_emulator_service()
            recording_file = emulator_service.get_recording_file()

            success = emulator_service.stop_recording()

            if success:
                return CommandResult(
                    success=True,
                    message=f"Screen recording saved to: {recording_file}",
                    data={"recording_file": recording_file, "action": "stopped"},
                )
            return CommandResult(
                success=False,
                message="Failed to stop screen recording",
                error="stop_screen_recording returned False",
            )
        except Exception as e:
            logger.exception("Error stopping screen recording")
            return CommandResult(
                success=False, message=f"Failed to stop recording: {e!s}", error=str(e)
            )


def register_commands(registry) -> None:
    """Register all capture commands.

    Args:
        registry: CommandRegistry instance to register commands with
    """
    registry.register(ScreenshotCommand())
    registry.register(ScreenRecordingCommand())
