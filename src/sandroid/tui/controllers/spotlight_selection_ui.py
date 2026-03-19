"""Spotlight Selection UI for interactive app targeting.

This module provides console-based and TUI-based interactive UI for selecting
the spotlight application (ATTACH or SPAWN mode). It handles all user-facing
rendering and input for spotlight selection, delegating state changes back to
the SpotlightService.

Extracted from SpotlightService to follow Single Responsibility Principle:
- SpotlightService owns state and business logic
- SpotlightSelectionUI owns interactive rendering and user input

Usage:
    from sandroid.tui.controllers.spotlight_selection_ui import SpotlightSelectionUI

    ui = SpotlightSelectionUI(spotlight_service)
    success = ui.ensure_app_for_tools("FriTap", adb=adb)
"""

import logging
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class SpotlightServiceProtocol(Protocol):
    """Protocol for the SpotlightService dependency.

    Defines the minimal interface that SpotlightSelectionUI needs
    from SpotlightService, enabling loose coupling and testability.
    """

    def has_app(self) -> bool:
        """Check if a spotlight app is currently set."""
        ...

    def set_app(
        self,
        package_name: str,
        activity_name: str | None = None,
        pid: int | None = None,
        mode: Any = None,
    ) -> None:
        """Set the spotlight application."""
        ...

    def set_spawn_mode(self, mode: bool | str) -> None:
        """Set the spawn mode."""
        ...

    def set_spawn_app(
        self,
        package_name: str,
        auto_resume: bool = True,
    ) -> None:
        """Set the app to spawn with Frida hooks."""
        ...


class SpotlightSelectionUI:
    """Interactive UI for spotlight application selection.

    Provides both CLI (Rich console) and TUI (modal dialog) interfaces
    for selecting the target application and mode (ATTACH or SPAWN).

    The UI class does not own any spotlight state -- it reads user input
    and delegates all state mutations to the SpotlightService.

    Attributes:
        _service: The SpotlightService to delegate state changes to.

    Example:
        service = SpotlightService()
        ui = SpotlightSelectionUI(service)

        # Prompt user if no app is set
        if ui.ensure_app_for_tools("FriTap", adb=Adb):
            print("App selected, ready to proceed")
    """

    def __init__(self, service: SpotlightServiceProtocol) -> None:
        """Initialize the SpotlightSelectionUI.

        Args:
            service: SpotlightService instance for state delegation.
        """
        self._service = service
        self._logger = logger

    # =========================================================================
    # Public Entry Point
    # =========================================================================

    def ensure_app_for_tools(
        self,
        tool_name: str = "this tool",
        adb: Any | None = None,
    ) -> bool:
        """Ensure a spotlight app is set, prompting user to select if not.

        This is the unified entry point for tools that require a spotlight
        application. Shows a UI asking the user to choose ATTACH or SPAWN
        mode if no app is set.

        Supports both CLI mode (Rich console) and TUI mode (modal dialogs).

        Args:
            tool_name: Name of the tool requiring spotlight (for display).
            adb: Optional ADB interface for dependency injection.

        Returns:
            True if spotlight is now set, False if user cancelled.
        """
        # Check if spotlight is already set
        if self._service.has_app():
            return True

        # Get ADB interface
        if adb is None:
            from sandroid.core.adb import Adb

            adb = Adb

        # Check if TUI mode is active
        from sandroid.core.ui_request_bus import UIRequestBus

        bus = UIRequestBus.get()
        if bus.has_active_handler():
            return self._ensure_spotlight_tui(tool_name, adb)

        # CLI mode - use Rich console
        return self._ensure_spotlight_cli(tool_name, adb)

    # =========================================================================
    # CLI Mode (Rich Console)
    # =========================================================================

    def _ensure_spotlight_cli(self, tool_name: str, adb: Any) -> bool:
        """CLI-mode spotlight selection using Rich console.

        Displays a box with ATTACH and SPAWN options and reads a single
        keypress to determine the user's choice.

        Args:
            tool_name: Name of the tool requiring spotlight.
            adb: ADB interface.

        Returns:
            True if spotlight is now set, False if user cancelled.
        """
        import click

        from sandroid.core.console import SandroidConsole
        from sandroid.tui.utils.box_renderer import make_box_line

        console = SandroidConsole.get()

        # Display mode selection box
        BOX_WIDTH = 70

        _box_line = make_box_line(BOX_WIDTH)

        console.print()
        console.print(f"[primary]{'=' * BOX_WIDTH}[/primary]")
        console.print(
            _box_line(f"[bold]Spotlight Application Required for {tool_name}[/bold]")
        )
        console.print(f"[primary]{'=' * BOX_WIDTH}[/primary]")
        console.print(
            _box_line("[accent]Choose how to target the application:[/accent]")
        )
        console.print(_box_line(""))
        console.print(
            _box_line(
                "[warning]\\[A][/warning] ATTACH mode - Hook into currently running app",
                align="left",
            )
        )
        console.print(
            _box_line(
                "    [dim]Use if app is already open on device[/dim]", align="left"
            )
        )
        console.print(_box_line(""))
        console.print(
            _box_line(
                "[warning]\\[S][/warning] SPAWN mode - Launch app fresh with hooks",
                align="left",
            )
        )
        console.print(
            _box_line(
                "    [dim]Use for clean analysis from app startup[/dim]", align="left"
            )
        )
        console.print(f"[primary]{'=' * BOX_WIDTH}[/primary]")
        console.print(
            _box_line(
                "[success]\\[A/S][/success] Select mode    [error]\\[Esc/Q][/error] Cancel",
                align="left",
            )
        )
        console.print(f"[primary]{'=' * BOX_WIDTH}[/primary]")

        console.print("\n[success]> Select mode:[/success] ", end="")

        try:
            choice = click.getchar().lower()
            console.print(f"[accent]{choice}[/accent]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[warning]Cancelled[/warning]")
            return False

        if choice in ("\x1b", "q"):  # ESC or Q
            console.print("[warning]Cancelled[/warning]")
            return False

        if choice == "a":
            return self._handle_attach_mode_cli(adb, console)

        if choice == "s":
            return self._handle_spawn_mode_cli(console)

        console.print(f"[error]Invalid choice: {choice}[/error]")
        return False

    def _handle_attach_mode_cli(self, adb: Any, console: Any) -> bool:
        """Handle ATTACH mode selection in CLI mode.

        Reads the currently focused app from the device via ADB and sets
        the spotlight in ATTACH mode.

        Args:
            adb: ADB interface.
            console: Rich console instance.

        Returns:
            True if spotlight was set successfully.
        """
        from sandroid.core.enums import SpawnMode

        focused_app = adb.get_focused_app()
        if not focused_app or focused_app[0] is None:
            console.print(
                "[error]No valid app is currently focused on the device.[/error]"
            )
            console.print(
                "[warning]Please open an app on the device and try again.[/warning]"
            )
            return False

        spotlight_name = focused_app[0]
        spotlight_pid = adb.get_pid_for_package_name(spotlight_name)

        if not spotlight_pid:
            console.print(f"[error]Could not get PID for {spotlight_name}[/error]")
            return False

        # Set spotlight via service methods
        self._service.set_app(
            package_name=spotlight_name,
            activity_name=focused_app[1] if len(focused_app) > 1 else None,
            pid=spotlight_pid,
            mode=SpawnMode.ATTACH,
        )
        self._service.set_spawn_mode(False)

        console.print("\n[success]Spotlight set in ATTACH mode:[/success]")
        console.print(f"  Package: [warning]{spotlight_name}[/warning]")
        console.print(f"  PID: [warning]{spotlight_pid}[/warning]")
        return True

    def _handle_spawn_mode_cli(self, console: Any) -> bool:
        """Handle SPAWN mode selection in CLI mode.

        Launches the fuzzy app selection UI and asks the user about
        auto-resume preference.

        Args:
            console: Rich console instance.

        Returns:
            True if spotlight was set successfully.
        """
        import click

        from sandroid.services import get_app_selection_service

        console.print("\n[primary]Select an application to spawn...[/primary]")

        app_selection = get_app_selection_service()
        selected_package = app_selection.select_app_with_fuzzy_search()
        if not selected_package:
            console.print("[warning]No app selected[/warning]")
            return False

        # Ask about auto-resume
        console.print("\n[primary]Auto-resume spawned app?[/primary]")
        console.print(
            "[accent]\\[Y][/accent] = App starts immediately after spawn (recommended)"
        )
        console.print("[accent]\\[N][/accent] = App stays paused, resume manually")
        console.print("\n[success]> Press y or n (Enter = yes):[/success] ", end="")

        try:
            resume_choice = click.getchar().lower()
            console.print(f"[accent]{resume_choice}[/accent]")
        except (KeyboardInterrupt, EOFError):
            resume_choice = "y"

        auto_resume = resume_choice != "n"

        # Set spotlight via service methods
        self._service.set_spawn_app(selected_package, auto_resume=auto_resume)

        resume_status = "enabled" if auto_resume else "disabled"
        console.print("\n[success]Spotlight set in SPAWN mode:[/success]")
        console.print(f"  Package: [warning]{selected_package}[/warning]")
        console.print(f"  Auto-resume: [warning]{resume_status}[/warning]")
        return True

    # =========================================================================
    # TUI Mode (Modal Dialogs)
    # =========================================================================

    def _ensure_spotlight_tui(self, tool_name: str, adb: Any) -> bool:
        """TUI-compatible spotlight selection using UIRequestBus.

        Shows modal dialogs for mode selection and app selection.

        Args:
            tool_name: Name of the tool requiring spotlight.
            adb: ADB interface.

        Returns:
            True if spotlight is now set, False if user cancelled.
        """
        from sandroid.core.ui_request_bus import request_selection

        # Ask user to choose ATTACH or SPAWN mode
        choice = request_selection(
            title=f"Spotlight Required for {tool_name}",
            options=[
                "ATTACH - Hook into currently running app",
                "SPAWN - Launch app fresh with hooks",
            ],
            message="No spotlight application set. Choose how to target:",
        )

        if choice is None:
            self._logger.info("Spotlight selection cancelled")
            return False

        if "ATTACH" in choice:
            return self._handle_attach_mode_tui(adb)

        # SPAWN MODE
        return self._handle_spawn_mode_tui()

    def _handle_attach_mode_tui(self, adb: Any) -> bool:
        """Handle ATTACH mode selection in TUI mode.

        Uses UIRequestBus modals to show errors and confirmations.

        Args:
            adb: ADB interface.

        Returns:
            True if spotlight was set successfully.
        """
        from sandroid.core.enums import SpawnMode
        from sandroid.core.ui_request_bus import show_error, show_info

        focused_app = adb.get_focused_app()
        if not focused_app or focused_app[0] is None:
            show_error(
                "No Focused App",
                "No valid app is currently focused on the device.\n"
                "This could be stale window manager data.\n"
                "Please open an app on the device and try again.",
            )
            return False

        spotlight_name = focused_app[0]
        spotlight_pid = adb.get_pid_for_package_name(spotlight_name)

        if not spotlight_pid:
            show_error("PID Error", f"Could not get PID for {spotlight_name}")
            return False

        # Set spotlight via service methods
        self._service.set_app(
            package_name=spotlight_name,
            activity_name=focused_app[1] if len(focused_app) > 1 else None,
            pid=spotlight_pid,
            mode=SpawnMode.ATTACH,
        )
        self._service.set_spawn_mode(False)

        show_info(
            "Spotlight Set (ATTACH)",
            f"Package: {spotlight_name}\nPID: {spotlight_pid}",
        )
        return True

    def _handle_spawn_mode_tui(self) -> bool:
        """Handle SPAWN mode selection in TUI mode.

        Uses UIRequestBus modals for app selection and auto-resume
        confirmation.

        Returns:
            True if spotlight was set successfully.
        """
        from sandroid.core.ui_request_bus import request_confirm, show_info
        from sandroid.services import get_app_selection_service

        app_selection = get_app_selection_service()
        selected_package = app_selection.select_app_with_fuzzy_search()
        if not selected_package:
            self._logger.info("No app selected")
            return False

        # Ask about auto-resume
        auto_resume = request_confirm(
            title="Auto-Resume Spawned App?",
            message="Auto-resume makes the app start immediately after spawn.\n"
            "Recommended for most use cases.\n\n"
            "Enable auto-resume?",
        )

        # Set spotlight via service methods
        self._service.set_spawn_app(selected_package, auto_resume=auto_resume)

        resume_status = "enabled" if auto_resume else "disabled"
        show_info(
            "Spotlight Set (SPAWN)",
            f"Package: {selected_package}\nAuto-resume: {resume_status}",
        )
        return True


__all__ = [
    "SpotlightSelectionUI",
    "SpotlightServiceProtocol",
]
