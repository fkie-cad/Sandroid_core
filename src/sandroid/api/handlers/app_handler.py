"""App handler — APK install, spotlight app management, app listing."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sandroid.api.helpers import safe_command
from sandroid.api.interfaces import CommandResult

if TYPE_CHECKING:
    from sandroid.api.headless import SandroidHeadlessAPI

logger = logging.getLogger(__name__)


class AppHandler:
    """Handles application-level operations: install, spotlight, listing."""

    def __init__(self, api: SandroidHeadlessAPI) -> None:
        self._api = api

    @safe_command("Failed to install APK")
    async def install_apk(
        self, apk_path: str, set_as_spotlight: bool = False
    ) -> CommandResult:
        """Install an APK on the connected device."""
        from pathlib import Path

        path = Path(apk_path)
        if not path.exists():
            return CommandResult(
                success=False,
                message=f"APK file not found: {apk_path}",
                error="File does not exist",
            )

        _stdout, stderr = self._api._adb.install_apk(str(path))
        if stderr and "success" not in stderr.lower():
            return CommandResult(
                success=False,
                message="APK installation failed",
                error=stderr,
            )

        result_data = {"apk_path": str(path)}

        if set_as_spotlight:
            logger.info("APK installed, set_as_spotlight requested")

        return CommandResult(
            success=True,
            message=f"APK installed: {path.name}",
            data=result_data,
        )

    async def get_spotlight_app(self) -> str | None:
        """Get the current spotlight application package name."""
        from sandroid.services import get_spotlight_service

        spotlight = get_spotlight_service()
        return spotlight.get_effective_package()

    @safe_command("Failed to set spotlight app")
    async def set_spotlight_app(
        self,
        package_name: str,
        mode: str = "attach",
    ) -> CommandResult:
        """Set the spotlight application."""
        from sandroid.services import get_spotlight_service

        spotlight = get_spotlight_service()

        if mode == "spawn":
            spotlight.set_spawn_app(package_name, auto_resume=True)
        else:
            spotlight.set_app(package_name)

        self._api._spotlight_app = package_name
        return CommandResult(
            success=True,
            message=f"Spotlight set to {package_name} ({mode} mode)",
        )

    async def get_installed_apps(self) -> list[str]:
        """Get list of installed applications on device."""
        packages = self._api._adb.get_installed_packages()
        return [pkg.get("package", "") for pkg in packages if pkg.get("package")]
