"""Device management commands.

Commands for selecting and managing connected Android devices.
"""

import logging

from .base import (
    CommandCategory,
    CommandContext,
    CommandHandler,
    CommandResult,
)

logger = logging.getLogger(__name__)


class DeviceSelectorCommand(CommandHandler):
    """Command to select or switch the active Android device.

    This command shows a list of connected devices and allows
    the user to select which one to use for analysis.
    """

    key = "D"
    name = "Select Device"
    description = "Switch to a different connected device"
    category = CommandCategory.SYSTEM
    views = []  # Available in all views

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Show device selector and switch device."""
        try:
            from sandroid.services import get_device_service

            device_service = get_device_service()

            # Get list of connected devices
            devices = device_service.get_connected_devices()

            if not devices:
                return CommandResult(
                    success=False,
                    message="No devices connected",
                    error="Connect a device or start an emulator first",
                )

            if len(devices) == 1:
                # Only one device, auto-select it
                device = devices[0]
                device_service.set_active_device(device.serial)
                return CommandResult(
                    success=True,
                    message=f"Using device: {device.name or device.serial}",
                    data={"device": device.serial},
                )

            # Multiple devices - use selection modal in TUI or prompt in CLI
            if ctx.is_tui_mode and ctx.request_selection:
                options = {d.serial: d.name or d.serial for d in devices}
                selected = await ctx.request_selection(
                    title="Select Device",
                    options=options,
                    message="Choose a device for analysis:",
                )
                if selected:
                    device_service.set_active_device(selected)
                    return CommandResult(
                        success=True,
                        message=f"Switched to device: {selected}",
                        data={"device": selected},
                    )
                return CommandResult(
                    success=False, message="Device selection cancelled"
                )
            # CLI mode - just list devices and use first
            device_list = ", ".join(d.serial for d in devices)
            return CommandResult(
                success=True,
                message=f"Multiple devices available: {device_list}. Using: {devices[0].serial}",
                data={
                    "devices": [d.serial for d in devices],
                    "selected": devices[0].serial,
                },
            )

        except ImportError:
            # Fallback to ADB direct
            if ctx.adb:
                try:
                    stdout, stderr = ctx.adb.send_adb_command("devices")
                    if stderr:
                        logger.warning(f"ADB devices command warning: {stderr}")
                    return CommandResult(
                        success=True,
                        message=f"Connected devices:\n{stdout}",
                        data={"raw_output": stdout, "stderr": stderr},
                    )
                except Exception as e:
                    return CommandResult(
                        success=False, message="Failed to list devices", error=str(e)
                    )
            return CommandResult(
                success=False,
                message="Device service not available",
                error="Could not access device management",
            )
        except Exception as e:
            logger.exception(f"Error in device selection: {e}")
            return CommandResult(
                success=False, message="Device selection failed", error=str(e)
            )


def register_commands(registry) -> None:
    """Register device management commands."""
    registry.register(DeviceSelectorCommand())
