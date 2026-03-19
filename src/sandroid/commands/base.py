"""Base classes for the Command system.

This module defines the core abstractions for the Command pattern:
- CommandHandler: Abstract base class for all command handlers
- CommandContext: Shared context passed to all commands
- CommandResult: Standard result returned by commands
- CommandCategory: Enum for categorizing commands

Usage:
    from sandroid.commands.base import CommandHandler, CommandContext, CommandResult

    class ScreenshotCommand(CommandHandler):
        key = "s"
        name = "Take Screenshot"
        category = CommandCategory.CAPTURE

        async def execute(self, ctx: CommandContext) -> CommandResult:
            # Implementation here
            return CommandResult(success=True, message="Screenshot saved")
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional, Protocol

if TYPE_CHECKING:
    from sandroid.services import ForensicService, SpotlightService, TaskService


class CommandCategory(str, Enum):
    """Categories for organizing commands."""

    FORENSIC = "forensic"
    CAPTURE = "capture"
    APP = "app"
    FRIDA = "frida"
    ANALYSIS = "analysis"
    NETWORK = "network"
    INSTRUMENTATION = "instrumentation"
    MONITORING = "monitoring"
    SECURITY = "security"
    FUNCTIONALITY = "functionality"
    IO = "io"
    SYSTEM = "system"


@dataclass
class CommandResult:
    """Result of executing a command.

    Attributes:
        success: Whether the command executed successfully
        message: Human-readable result message
        data: Optional structured data from the command
        error: Optional error message if command failed
        should_return_to_menu: Whether to return to interactive menu after execution
    """

    success: bool
    message: str
    data: dict[str, Any] | None = None
    error: str | None = None
    should_return_to_menu: bool = True


class UIBusProtocol(Protocol):
    """Protocol for UI request bus operations."""

    def has_active_handler(self) -> bool:
        """Check if TUI mode is active."""
        ...


class AdbProtocol(Protocol):
    """Protocol for ADB operations."""

    @staticmethod
    def send_adb_command(command: str) -> tuple:
        """Send an ADB command."""
        ...

    @staticmethod
    def get_focused_app() -> tuple | None:
        """Get the currently focused app."""
        ...

    @staticmethod
    def get_pid_for_package_name(package: str) -> int | None:
        """Get PID for a package."""
        ...

    @staticmethod
    def get_installed_packages() -> list[str]:
        """Get list of installed packages."""
        ...


class ToolboxProtocol(Protocol):
    """Protocol for Toolbox operations (for backwards compatibility)."""

    @staticmethod
    def get_spotlight_files() -> list[str]:
        """Get spotlight files."""
        ...

    @staticmethod
    def take_screenshot(filename: str | None = None) -> bool:
        """Take a screenshot."""
        ...

    @staticmethod
    def show_blocking_warning(title: str, message: str, action_hint: str = "") -> None:
        """Show a blocking warning."""
        ...


@dataclass
class CommandContext:
    """Context passed to all command handlers.

    This provides access to all services and utilities that commands
    may need, without requiring direct dependencies.

    Attributes:
        task_service: Background task management
        forensic_service: Forensic analysis state
        spotlight_service: App selection and monitoring
        adb: ADB interface
        toolbox: Legacy Toolbox for backwards compatibility
        ui_bus: UI request bus for modals/prompts
        config: Application configuration
        is_tui_mode: Whether running in TUI mode
        action_queue: Reference to ActionQ for queue management
        logger: Logger instance
    """

    # Services (new architecture)
    task_service: Optional["TaskService"] = None
    forensic_service: Optional["ForensicService"] = None
    spotlight_service: Optional["SpotlightService"] = None

    # Utilities
    adb: Any | None = None  # Adb class
    toolbox: Any | None = None  # Toolbox class (for backwards compatibility)
    ui_bus: Any | None = None  # UIRequestBus
    config: Any | None = None  # SandroidConfig

    # Runtime state
    is_tui_mode: bool = False
    action_queue: Any | None = None  # ActionQ instance

    # Helpers
    logger: Any | None = None

    # Request functions (shortcuts for common UI operations)
    request_input: Callable | None = None
    request_confirm: Callable | None = None
    request_selection: Callable | None = None

    def get_results_path(self) -> str:
        """Get the results path from config or environment."""
        import os

        return os.getenv("RESULTS_PATH", "./results/")


class CommandHandler(ABC):
    """Abstract base class for all command handlers.

    Each command handler is responsible for a single keyboard shortcut
    and its associated functionality. Handlers should be stateless and
    derive all required state from the CommandContext.

    Class Attributes:
        key: Keyboard shortcut for this command (single character)
        name: Human-readable command name
        description: Detailed description of what the command does
        category: Category for organizing in menus
        views: Which views this command is available in (empty = all)

    Example:
        class ScreenshotCommand(CommandHandler):
            key = "s"
            name = "Take Screenshot"
            description = "Capture the current screen and save to results"
            category = CommandCategory.CAPTURE

            async def execute(self, ctx: CommandContext) -> CommandResult:
                filename = await self._get_filename(ctx)
                ctx.toolbox.take_screenshot(filename)
                return CommandResult(
                    success=True,
                    message=f"Screenshot saved: {filename}"
                )
    """

    # Class attributes to be overridden by subclasses
    key: str = ""
    name: str = ""
    description: str = ""
    category: CommandCategory = CommandCategory.SYSTEM
    views: list[str] = []  # Empty means available in all views

    # Set to True for commands with blocking I/O (like Frida) that conflict with asyncio.run()
    # These commands will have execute_blocking() called directly instead of through asyncio
    is_blocking_io: bool = False

    def execute_blocking(self, ctx: "CommandContext") -> "CommandResult":
        """Execute command synchronously for blocking I/O operations.

        Override this method for commands that have blocking I/O which conflicts
        with asyncio.run() (e.g., Frida operations). This method is called directly
        from worker threads without an asyncio event loop wrapper.

        By default, this raises NotImplementedError. Commands with is_blocking_io=True
        MUST override this method.

        Args:
            ctx: Command context with access to all services

        Returns:
            CommandResult indicating success/failure and any data
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} has is_blocking_io=True but doesn't implement execute_blocking()"
        )

    @abstractmethod
    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Execute the command.

        Args:
            ctx: Command context with access to all services

        Returns:
            CommandResult indicating success/failure and any data
        """
        ...

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if the command can be executed in current state.

        Override this method to add preconditions. Default implementation
        always returns True.

        Args:
            ctx: Command context with current state

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        return True, ""

    def _validate_service(
        self,
        ctx: CommandContext,
        service_name: str,
        service_attr: str,
    ) -> tuple[bool, str]:
        """Validate a service dependency.

        Args:
            ctx: Command context
            service_name: Display name for error messages (e.g., "Task service")
            service_attr: Attribute name on ctx (e.g., "task_service")

        Returns:
            Tuple of (valid, error_message)
        """
        service = getattr(ctx, service_attr, None)
        if service is None:
            return (False, f"{service_name} not available")
        return (True, "")

    def _validate_task_service(self, ctx: CommandContext) -> tuple[bool, str]:
        """Validate task_service availability.

        Args:
            ctx: Command context

        Returns:
            Tuple of (valid, error_message)
        """
        return self._validate_service(ctx, "Task service", "task_service")

    def _validate_forensic_service(self, ctx: CommandContext) -> tuple[bool, str]:
        """Validate forensic_service availability.

        Args:
            ctx: Command context

        Returns:
            Tuple of (valid, error_message)
        """
        return self._validate_service(ctx, "Forensic service", "forensic_service")

    def get_menu_label(self) -> str:
        """Get the label to display in menus.

        Returns:
            Formatted menu label with key and name
        """
        return f"[{self.key}] {self.name}"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} key='{self.key}' name='{self.name}'>"


class RequiresSpotlightApp(CommandHandler):
    """Mixin for commands that require a spotlight app to be set.

    Use this as a base class for commands that operate on the
    currently selected spotlight application.

    Example:
        class AttachToAppCommand(RequiresSpotlightApp):
            key = "a"
            name = "Attach to App"

            async def execute(self, ctx: CommandContext) -> CommandResult:
                # Guaranteed to have spotlight app set
                ...
    """

    _NO_APP_MSG = "No spotlight app selected. Press 'c' to select an app first."

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check that a spotlight app is set."""
        if ctx.spotlight_service:
            if not ctx.spotlight_service.has_app():
                return False, self._NO_APP_MSG
            return True, ""

        # Fallback to singleton spotlight service
        from sandroid.services import get_spotlight_service

        app = get_spotlight_service().get_app_tuple()
        if not app or app[0] is None:
            return False, self._NO_APP_MSG
        return True, ""


class RequiresFrida(CommandHandler):
    """Mixin for commands that require Frida to be running.

    Use this as a base class for commands that need Frida server
    to be active on the device.

    Example:
        class InjectScriptCommand(RequiresFrida):
            key = "i"
            name = "Inject Script"

            async def execute(self, ctx: CommandContext) -> CommandResult:
                # Guaranteed to have Frida running
                ...
    """

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check that Frida server is running."""
        if ctx.toolbox and hasattr(ctx.toolbox, "frida_manager"):
            if not ctx.toolbox.frida_manager.is_frida_server_running():
                return (
                    False,
                    "Frida server not running. Press 'f' to start Frida first.",
                )
        return True, ""


class ToggleCommand(CommandHandler):
    """Base class for commands that toggle a running task.

    Use this for commands that start a background task when pressed
    and stop it when pressed again (like screen recording).

    Subclasses must implement:
        - get_task_name(): Return the task identifier
        - start_task(): Start the background task
        - stop_task(): Stop the background task
    """

    @abstractmethod
    def get_task_name(self) -> str:
        """Get the task name for this toggle command."""
        ...

    @abstractmethod
    async def start_task(self, ctx: CommandContext) -> CommandResult:
        """Start the background task."""
        ...

    @abstractmethod
    async def stop_task(self, ctx: CommandContext) -> CommandResult:
        """Stop the background task."""
        ...

    def is_task_running(self, ctx: CommandContext) -> bool:
        """Check if the task is currently running."""
        task_name = self.get_task_name()
        if ctx.task_service:
            return ctx.task_service.is_running(task_name)
        return False

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Toggle the task on/off."""
        if self.is_task_running(ctx):
            return await self.stop_task(ctx)
        return await self.start_task(ctx)


__all__ = [
    "CommandCategory",
    "CommandContext",
    "CommandHandler",
    "CommandResult",
    "RequiresFrida",
    "RequiresSpotlightApp",
    "ToggleCommand",
]
