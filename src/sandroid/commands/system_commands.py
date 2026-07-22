"""System commands for quit and info."""

import logging

from .base import CommandCategory, CommandContext, CommandHandler, CommandResult

logger = logging.getLogger(__name__)


class QuitCommand(CommandHandler):
    """Command to exit the application."""

    key = "q"
    name = "Quit"
    description = "Exit the application"
    category = CommandCategory.SYSTEM
    views = []  # Available in all views

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Signal the application to exit.

        The legacy ``do_next`` loop that read ``action_queue.finished`` is gone;
        actual quitting is owned by the TUI (``app.action_quit`` / the ``q``
        binding). This handler just reports the intent via ``data``.

        Args:
            ctx: Command context

        Returns:
            CommandResult indicating the quit was initiated
        """
        logger.info("Quit command executed - signaling application exit")

        return CommandResult(
            success=True,
            message="Exiting application...",
            data={"action": "quit"},
            should_return_to_menu=False,
        )


class DeviceInfoCommand(CommandHandler):
    """Command to display device information."""

    key = "e"
    name = "Device Info"
    description = "Display device information"
    category = CommandCategory.SYSTEM
    views = ["forensic", "malware", "security"]

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Display information about the connected device.

        Gathers device info via DeviceService.get_device_info() and
        returns it in CommandResult.data for DeviceInfoModal display.

        Args:
            ctx: Command context with access to toolbox

        Returns:
            CommandResult with device info for modal display
        """
        logger.debug("Device info command executed")

        try:
            from sandroid.services import get_device_service

            device_service = get_device_service()
            info = device_service.get_device_info()

            return CommandResult(
                success=True,
                message="Device information displayed",
                data={
                    "action": "device_info",
                    "show_device_info_modal": True,
                    "device_info": info,
                },
                should_return_to_menu=True,
            )
        except Exception as e:
            logger.error(f"Error displaying device info: {e}")
            # Fallback: try to get basic info via ADB
            return await self._show_basic_info(ctx)

    async def _show_basic_info(self, ctx: CommandContext) -> CommandResult:
        """Show basic emulator info when toolbox is not available.

        Args:
            ctx: Command context with potential ADB access

        Returns:
            CommandResult with basic emulator information
        """
        info_parts = []

        if ctx.adb is not None:
            try:
                # Try to get basic info via ADB
                if hasattr(ctx.adb, "get_current_avd_name"):
                    avd_name = ctx.adb.get_current_avd_name()
                    if avd_name:
                        info_parts.append(f"AVD Name: {avd_name}")

                if hasattr(ctx.adb, "get_android_version_and_api_level"):
                    android_info = ctx.adb.get_android_version_and_api_level()
                    if android_info:
                        info_parts.append(f"Android: {android_info}")

                if hasattr(ctx.adb, "get_device_time"):
                    device_time = ctx.adb.get_device_time()
                    if device_time:
                        info_parts.append(f"Device Time: {device_time}")

            except Exception as e:
                logger.warning(f"Could not get ADB info: {e}")

        if info_parts:
            info_message = " | ".join(info_parts)
            logger.info(f"Emulator Info: {info_message}")
            return CommandResult(
                success=True,
                message=info_message,
                data={"info": info_parts},
                should_return_to_menu=True,
            )
        logger.warning("No emulator information available")
        return CommandResult(
            success=False,
            message="No emulator information available",
            error="Neither toolbox nor ADB available for info retrieval",
            should_return_to_menu=True,
        )


class DeviceSettingsCommand(CommandHandler):
    """Command to open device environment settings modal."""

    key = "E"
    name = "Device Settings"
    description = "Configure device environment settings"
    category = CommandCategory.SYSTEM
    views = ["forensic", "malware", "security"]

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Open the device settings modal.

        Checks emulator/root capabilities and passes them to the modal.

        Args:
            ctx: Command context

        Returns:
            CommandResult with modal display data
        """
        logger.debug("Device settings command executed")

        is_emulator = False
        has_root = False

        try:
            from sandroid.services import get_device_service

            device_service = get_device_service()
            is_emulator = device_service.is_emulator_device()
        except Exception as e:
            logger.debug(f"Could not check emulator status: {e}")

        try:
            from sandroid.services import get_device_settings_service

            settings_service = get_device_settings_service()
            has_root = settings_service.check_root_available()
        except Exception as e:
            logger.debug(f"Could not check root status: {e}")

        return CommandResult(
            success=True,
            message="Opening device settings",
            data={
                "show_device_settings_modal": True,
                "is_emulator": is_emulator,
                "has_root": has_root,
            },
            should_return_to_menu=True,
        )


# Backward-compatible alias
EmulatorInfoCommand = DeviceInfoCommand


def register_commands(registry) -> None:
    """Register all system commands.

    Args:
        registry: CommandRegistry instance to register commands with
    """
    registry.register(QuitCommand())
    registry.register(DeviceInfoCommand())
    registry.register(DeviceSettingsCommand())
