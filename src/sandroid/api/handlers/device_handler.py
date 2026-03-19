"""Device handler — snapshots, screenshots, screen recording, proxy, settings."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from sandroid.api.helpers import safe_command
from sandroid.api.interfaces import CommandResult

if TYPE_CHECKING:
    from sandroid.api.headless import SandroidHeadlessAPI

logger = logging.getLogger(__name__)


class DeviceHandler:
    """Handles device-level operations: snapshots, screenshots, proxy, settings."""

    def __init__(self, api: SandroidHeadlessAPI) -> None:
        self._api = api

    # -- Proxy ---------------------------------------------------------------

    @safe_command("Failed to set proxy")
    async def set_proxy(self, ip: str, port: str) -> CommandResult:
        """Set HTTP proxy on the connected device."""
        from sandroid.services import get_proxy_service

        proxy_service = get_proxy_service()
        if proxy_service.set_proxy(ip, port):
            return CommandResult(
                success=True,
                message=f"Proxy set to {ip}:{port}",
                data={"ip": ip, "port": port},
            )
        return CommandResult(
            success=False,
            message=f"Failed to set proxy to {ip}:{port}",
        )

    @safe_command("Failed to clear proxy")
    async def clear_proxy(self) -> CommandResult:
        """Clear HTTP proxy settings on the device."""
        from sandroid.services import get_proxy_service

        proxy_service = get_proxy_service()
        if proxy_service.clear_proxy():
            return CommandResult(success=True, message="Proxy cleared")
        return CommandResult(success=False, message="Failed to clear proxy")

    @safe_command("Failed to get proxy settings")
    async def get_proxy_settings(self) -> CommandResult:
        """Get current HTTP proxy settings from the device."""
        from sandroid.services import get_proxy_service

        proxy_service = get_proxy_service()
        settings = proxy_service.get_proxy_settings()
        return CommandResult(
            success=True,
            message=str(settings),
            data={
                "ip": settings.ip,
                "port": settings.port,
                "enabled": settings.enabled,
            },
        )

    # -- Device Settings -----------------------------------------------------

    @safe_command("Failed to configure device settings")
    async def configure_device_settings(
        self,
        settings: dict[str, Any] | None = None,
        preset: str | None = None,
        settings_file: str | None = None,
    ) -> CommandResult:
        """Configure device environment settings."""
        from sandroid.services.device_settings_service import (
            DeviceSettingsService,
            validate_settings_dict,
        )

        svc = DeviceSettingsService()

        if settings_file:
            import json as json_mod

            try:
                with open(settings_file) as f:
                    settings = json_mod.load(f)
            except FileNotFoundError:
                return CommandResult(
                    success=False,
                    message=f"Settings file not found: {settings_file}",
                    error="File does not exist",
                )

        if settings:
            errors = validate_settings_dict(settings)
            if errors:
                return CommandResult(
                    success=False,
                    message="Settings validation failed",
                    error="; ".join(errors),
                    data={"validation_errors": errors},
                )
            results = svc.apply_settings_dict(settings)
        elif preset:
            results = [svc.apply_preset(preset)]
        else:
            return CommandResult(
                success=False,
                message="Provide settings dict, preset, or settings_file",
            )

        success_count = sum(1 for r in results if r.success)
        fail_count = sum(1 for r in results if not r.success)
        messages = [r.message for r in results]

        if fail_count == 0:
            return CommandResult(
                success=True,
                message=f"All {success_count} settings applied",
                data={"results": messages},
            )
        return CommandResult(
            success=False,
            message=f"{success_count} succeeded, {fail_count} failed",
            data={"results": messages},
            error="; ".join(r.message for r in results if not r.success),
        )

    # -- Screenshots ---------------------------------------------------------

    @safe_command("Failed to take screenshot")
    async def take_screenshot(self, filename: str | None = None) -> CommandResult:
        """Take a screenshot of the device screen."""
        import os
        from datetime import datetime

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"screenshot_{timestamp}.png"

        raw_path = os.getenv("RAW_RESULTS_PATH", ".")
        screenshots_dir = os.path.join(raw_path, "screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)
        screenshot_path = os.path.join(screenshots_dir, filename)

        _stdout, stderr = self._api._adb.send_telnet_command(
            f"screenrecord screenshot {screenshot_path}"
        )
        if stderr:
            return CommandResult(
                success=False,
                message="Screenshot failed",
                error=stderr,
            )

        return CommandResult(
            success=True,
            message=f"Screenshot saved: {screenshot_path}",
            data={"path": screenshot_path},
        )

    # -- Snapshots -----------------------------------------------------------

    @safe_command("Failed to create snapshot")
    async def create_snapshot(self, name: str | None = None) -> CommandResult:
        """Create an emulator snapshot."""
        from datetime import datetime

        if not name:
            name = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        self._api._toolbox.create_snapshot(name.encode())
        return CommandResult(
            success=True,
            message=f"Snapshot created: {name}",
            data={"snapshot": name, "action": "created"},
        )

    @safe_command("Failed to load snapshot")
    async def load_snapshot(self, name: str) -> CommandResult:
        """Load an emulator snapshot."""
        self._api._toolbox.load_snapshot(name.encode())
        return CommandResult(
            success=True,
            message=f"Snapshot loaded: {name}",
            data={"snapshot": name, "action": "loaded"},
        )

    @safe_command("Failed to list snapshots")
    async def list_snapshots(self) -> CommandResult:
        """List available emulator snapshots."""
        snapshots = self._api._adb.get_avd_snapshots() or []
        return CommandResult(
            success=True,
            message=f"Found {len(snapshots)} snapshots",
            data={"snapshots": snapshots},
        )

    # -- Screen Recording ----------------------------------------------------

    @safe_command("Failed to start screen recording")
    async def start_screen_recording(
        self, filename: str | None = None
    ) -> CommandResult:
        """Start screen recording on the device."""
        from sandroid.services import get_emulator_service

        emulator_service = get_emulator_service()
        emulator_service.toggle_recording()

        return CommandResult(
            success=True,
            message="Screen recording started",
            data={"filename": filename},
        )

    @safe_command("Failed to stop screen recording")
    async def stop_screen_recording(self) -> CommandResult:
        """Stop screen recording on the device."""
        from sandroid.services import get_emulator_service

        emulator_service = get_emulator_service()
        emulator_service.toggle_recording()

        return CommandResult(
            success=True,
            message="Screen recording stopped",
        )
