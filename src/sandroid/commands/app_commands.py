"""App management commands for installation and spotlight selection."""

import logging
from pathlib import Path

from sandroid.services import (
    get_app_selection_service,
    get_spotlight_service,
    get_ui_service,
)

from .base import CommandCategory, CommandContext, CommandHandler, CommandResult

logger = logging.getLogger(__name__)


class InstallApkCommand(CommandHandler):
    """Command to install an APK from local file or search online repositories.

    This command provides two installation methods:
    1. Local file: If a valid file path is provided, installs directly
    2. Online search: If input is not a file, searches online APK repositories

    After successful installation, offers to select the app as the spotlight app.
    """

    key = "n"
    name = "Install APK"
    description = "Install an APK from file or search online"
    category = CommandCategory.APP
    views = ["forensic", "malware"]

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute the APK installation command.

        Prompts user for a file path or search term, then either:
        - Installs the APK directly if it's a local file
        - Searches online repositories and lets user select a version

        Args:
            ctx: Command context with toolbox and UI access

        Returns:
            CommandResult indicating success/failure of installation
        """
        from sandroid.core.adb import Adb
        from sandroid.core.apk_downloader import ApkDownloader
        from sandroid.core.exceptions import (
            APKDownloadError,
            APKNotFoundError,
            APKVersionNotFoundError,
        )

        # Get path or search term from user
        path_or_search: str = ""

        try:
            if ctx.is_tui_mode and ctx.request_input:
                # TUI mode - use async input modal
                path_or_search = ctx.request_input(
                    title="Install APK",
                    message="Enter APK path or package name to search:",
                )
            else:
                # Rich console mode - use safe_input
                logger.info("Enter APK file path or package name to search online:")
                if ctx.toolbox:
                    path_or_search = ctx.toolbox.safe_input("Path or search: ")
                else:
                    path_or_search = input("Path or search: ")
        except Exception as e:
            logger.warning(f"Error getting input: {e}")
            return CommandResult(
                success=False,
                message="Input cancelled or failed",
                error=str(e),
            )

        if not path_or_search or path_or_search.strip() == "":
            return CommandResult(
                success=False,
                message="No input provided - installation cancelled",
            )

        path_or_search = path_or_search.strip()
        installed_package: str | None = None

        # Check if it's a local file
        if Path(path_or_search).is_file():
            # Local APK file installation
            try:
                logger.info(f"Installing local APK: {path_or_search}")
                installed_package = Adb.install_apk(path_or_search)

                if installed_package:
                    logger.info(f"Successfully installed: {installed_package}")
                else:
                    logger.warning(
                        "APK installed but package name could not be determined"
                    )

            except Exception as e:
                logger.exception("Error installing local APK")
                return CommandResult(
                    success=False,
                    message=f"Failed to install APK: {e!s}",
                    error=str(e),
                )
        else:
            # Online search and install
            try:
                logger.info(f"Searching online for: {path_or_search}")
                downloader = ApkDownloader()

                # Search returns versions, user selects one
                if ctx.is_tui_mode:
                    # For TUI mode, use the simple method without interactive prompts
                    try:
                        versions = downloader.get_versions_only(path_or_search)
                        if not versions:
                            raise APKNotFoundError(path_or_search)

                        # Build version options for selection
                        version_options = []
                        for v in versions:
                            version_str = v.get("file", {}).get("vername", "Unknown")
                            name = v.get("name", path_or_search)
                            added = v.get("added", "")
                            version_options.append(f"{name} [{version_str}] ({added})")

                        # Request selection from user
                        if ctx.request_selection:
                            selected_idx = ctx.request_selection(
                                title="Select Version",
                                options=version_options,
                                message="Choose a version to install:",
                            )

                            if selected_idx is None or selected_idx < 0:
                                return CommandResult(
                                    success=False,
                                    message="Installation cancelled - no version selected",
                                )

                            app_id = versions[selected_idx]["id"]
                            logger.info(
                                f"Installing version: {version_options[selected_idx]}"
                            )

                            # Use the simple install method for TUI
                            installed_package = downloader.install_app_id_simple(app_id)
                        else:
                            # Fallback if no selection function available
                            app_id = versions[0]["id"]
                            installed_package = downloader.install_app_id_simple(app_id)

                    except APKNotFoundError:
                        raise
                    except Exception as e:
                        logger.error(f"TUI install error: {e}")
                        raise
                else:
                    # Rich console mode - use the interactive search method
                    app_id = downloader.search_for_name(path_or_search)
                    downloader.install_app_id(app_id)
                    installed_package = path_or_search  # May not be exact package name

            except APKNotFoundError as e:
                logger.error(f"Package not found: {e.package_name}")
                return CommandResult(
                    success=False,
                    message=f"Package '{e.package_name}' not found in APK repositories",
                    error=str(e),
                )

            except APKVersionNotFoundError as e:
                logger.error(f"Version not found: {e}")
                available = (
                    ", ".join(e.available_versions[:5])
                    if e.available_versions
                    else "none"
                )
                return CommandResult(
                    success=False,
                    message=f"Version '{e.version}' not found. Available: {available}",
                    error=str(e),
                )

            except APKDownloadError as e:
                logger.error(f"Download error: {e}")
                return CommandResult(
                    success=False,
                    message=f"Download failed: {e!s}",
                    error=str(e),
                )

            except Exception as e:
                logger.exception("Error during online APK installation")
                return CommandResult(
                    success=False,
                    message=f"Installation failed: {e!s}",
                    error=str(e),
                )

        # Update package cache with newly installed package
        if installed_package:
            try:
                get_app_selection_service().add_package_to_cache(installed_package)
            except Exception:
                pass

        # Offer to select it as the spotlight app
        if installed_package and ctx.toolbox:
            await self._offer_set_spotlight(ctx, installed_package)

        return CommandResult(
            success=True,
            message=f"APK installed successfully: {installed_package or 'unknown package'}",
            data={"package_name": installed_package},
        )

    async def _offer_set_spotlight(
        self, ctx: CommandContext, package_name: str
    ) -> None:
        """Offer to select the installed app as the spotlight app.

        Args:
            ctx: Command context
            package_name: Name of the installed package
        """
        try:
            set_spotlight = False

            if ctx.is_tui_mode and ctx.request_confirm:
                set_spotlight = ctx.request_confirm(
                    title="Set as Spotlight App?",
                    message=f"Set '{package_name}' as the spotlight app?",
                )
            else:
                # Rich console mode
                logger.info(f"Set '{package_name}' as spotlight app? (y/N): ")
                if ctx.toolbox:
                    response = ctx.toolbox.safe_input("").lower()
                else:
                    response = input("").lower()
                set_spotlight = response in ("y", "yes")

            if set_spotlight:
                get_spotlight_service().set_app(package_name)
                logger.info(f"Spotlight app set to: {package_name}")

        except Exception as e:
            logger.warning(f"Could not set spotlight app: {e}")


class SetSpotlightAttachCommand(CommandHandler):
    """``c``: make the foreground app the spotlight app (with its PID).

    The spotlight is a selection only; tools later attach to the running app
    (or start it when it is not running).
    """

    key = "c"
    name = "Use Foreground App"
    description = "Make the foreground app the spotlight app"
    category = CommandCategory.APP
    views = ["forensic", "malware", "security"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if command can execute by verifying device connection.

        Args:
            ctx: Command context

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        try:
            from sandroid.core.adb import Adb

            focused_app = Adb.get_focused_app()
            if focused_app is None:
                return (
                    False,
                    "No device connected or no app in focus. "
                    "Make sure an Android device/emulator is running.",
                )
            return (True, "")
        except Exception as e:
            logger.debug(f"can_execute check failed: {e}")
            return (
                False,
                "No device connected or no app in focus. "
                "Make sure an Android device/emulator is running.",
            )

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Make the currently focused app the spotlight app.

        Gets the focused app from the device and retrieves its PID.

        Args:
            ctx: Command context with toolbox access

        Returns:
            CommandResult indicating success/failure
        """
        from sandroid.core.adb import Adb

        if not ctx.toolbox:
            return CommandResult(
                success=False,
                message="Toolbox not available",
                error="No toolbox in context",
            )

        try:
            # Get the currently focused app
            focused_app = Adb.get_focused_app()

            if not focused_app or focused_app[0] is None:
                logger.warning("No focused app found on device")
                return CommandResult(
                    success=False,
                    message="No focused app found. Make sure an app is in the foreground.",
                    error="get_focused_app returned None",
                )

            package_name, activity_name = focused_app
            logger.info(f"Focused app: {package_name}/{activity_name}")

            # Get PID for the package
            pid = Adb.get_pid_for_package_name(package_name)

            if pid is None:
                logger.warning(f"Could not get PID for {package_name}")
                # Continue anyway - PID is optional for some operations
                get_ui_service().show_blocking_warning(
                    title="PID Not Found",
                    message=f"Could not find PID for '{package_name}'.\n"
                    f"The app may not be running. Some Frida operations may not work.",
                    action_hint="Try launching the app first",
                )
            else:
                logger.debug(f"PID for {package_name}: {pid}")

            # Set the spotlight application with all info including PID
            # Note: Must use set_app() with pid parameter, NOT set_app_from_tuple()
            # followed by set_pid(), as that would overwrite the PID
            get_spotlight_service().set_app(
                package_name=package_name,
                activity_name=activity_name,
                pid=pid,
            )

            state = f"pid {pid}" if pid else "not running"
            result_message = f"Spotlight: {package_name} ({state})"

            logger.debug(result_message)

            return CommandResult(
                success=True,
                message=result_message,
                data={
                    "package_name": package_name,
                    "activity_name": activity_name,
                    "pid": pid,
                },
            )

        except Exception as e:
            logger.exception("Error setting the foreground app as spotlight app")
            return CommandResult(
                success=False,
                message=f"Failed to set spotlight app: {e!s}",
                error=str(e),
            )


class SetSpotlightSpawnCommand(CommandHandler):
    """``⇧C``: pick the spotlight app from the installed apps (fuzzy search).

    A selection only: nothing is started or restarted. The PID is looked up
    quietly, so the header shows "running pid N" or "not running".
    """

    key = "C"
    name = "Pick an App…"
    description = "Pick the spotlight app from the installed apps"
    category = CommandCategory.APP
    views = ["forensic", "malware", "security"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if command can execute by verifying toolbox and device connection.

        Args:
            ctx: Command context

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        if not ctx.toolbox:
            return (False, "Toolbox not available")

        try:
            from sandroid.core.adb import Adb

            stdout, _stderr = Adb.send_adb_command("devices")
            # Check if any device is connected (more than just the header line)
            lines = [
                line.strip() for line in stdout.strip().split("\n") if line.strip()
            ]
            # First line is "List of devices attached", so we need at least 2 lines
            if len(lines) < 2:
                return (
                    False,
                    "No device connected. Make sure an Android device/emulator is running.",
                )
            return (True, "")
        except Exception as e:
            logger.debug(f"can_execute check failed: {e}")
            return (
                False,
                "No device connected. Make sure an Android device/emulator is running.",
            )

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Pick the spotlight app using fuzzy search.

        Shows available apps and allows fuzzy search filtering. How the app
        is started is chosen per action in the spotlight panel (Start /
        Restart / Attach / Start-paused) or by each tool.

        Args:
            ctx: Command context with toolbox access

        Returns:
            CommandResult indicating success/failure
        """
        if not ctx.toolbox:
            return CommandResult(
                success=False,
                message="Toolbox not available",
                error="No toolbox in context",
            )

        try:
            # Use fuzzy search to select an app
            # This method handles both TUI and Rich console modes
            app_selection = get_app_selection_service()
            package_name = app_selection.select_app_with_fuzzy_search()

            if not package_name:
                logger.info("App selection cancelled")
                return CommandResult(
                    success=False,
                    message="App selection cancelled",
                )

            logger.info(f"Picked spotlight app: {package_name}")

            # A selection only; the explicit lookup's result (also "none",
            # which clears a stale PID) is the PID.
            from sandroid.core.adb import Adb

            try:
                pid = Adb.get_pid_for_package_name(
                    package_name, use_frida_fallback=False, quiet=True
                )
            except Exception:
                pid = None
            spotlight = get_spotlight_service()
            spotlight.set_app(package_name, pid=pid)

            if pid:
                result_message = f"Spotlight: {package_name} — running pid {pid}"
            else:
                result_message = (
                    f"Spotlight: {package_name} — not running · ␣ starts it"
                )

            logger.debug(result_message)

            return CommandResult(
                success=True,
                message=result_message,
                data={
                    "package_name": package_name,
                    "pid": pid,
                },
            )

        except Exception as e:
            logger.exception("Error picking the spotlight app")
            return CommandResult(
                success=False,
                message=f"Failed to set the spotlight app: {e!s}",
                error=str(e),
            )


def register_commands(registry) -> None:
    """Register all app commands.

    Args:
        registry: CommandRegistry instance to register commands with
    """
    registry.register(InstallApkCommand())
    registry.register(SetSpotlightAttachCommand())
    registry.register(SetSpotlightSpawnCommand())
