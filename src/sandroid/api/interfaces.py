"""Abstract API interfaces for Sandroid.

These interfaces define the contract between UI layers and core functionality,
enabling multiple UI implementations (TUI, REST API, headless) while keeping
the core logic UI-agnostic.

Usage:
    from sandroid.api.interfaces import SandroidAPI, CommandResult

    class TuiAdapter(SandroidAPI):
        '''TUI-specific implementation'''
        async def execute_command(self, key: str) -> CommandResult:
            ...

    class RestAdapter(SandroidAPI):
        '''REST API implementation'''
        async def execute_command(self, key: str) -> CommandResult:
            ...
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Protocol


class AnalysisStateEnum(str, Enum):
    """Possible analysis states."""

    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


class AnalysisMode(str, Enum):
    """Available analysis modes for headless operation.

    Each mode focuses on different aspects of Android app analysis:
    - FORENSIC: File system changes, spotlight tracking, evidence collection
    - MALWARE: TrigDroid triggers, behavioral monitoring, network capture
    - NETWORK: Headless network capture and PCAP analysis
    - SECURITY: Static APK analysis, vulnerability scanning
    """

    FORENSIC = "forensic"
    MALWARE = "malware"
    NETWORK = "network"
    SECURITY = "security"


@dataclass
class CommandResult:
    """Result of executing a command.

    Attributes:
        success: Whether the command executed successfully
        message: Human-readable result message
        data: Optional structured data from the command
        error: Optional error message if command failed
    """

    success: bool
    message: str
    data: dict[str, Any] | None = None
    error: str | None = None


@dataclass
class MenuItem:
    """Represents a menu item.

    Attributes:
        key: Keyboard shortcut for this item
        name: Display name
        description: Optional description
        enabled: Whether the item can be selected
        category: Menu category for grouping
    """

    key: str
    name: str
    description: str = ""
    enabled: bool = True
    category: str = "general"


@dataclass
class MenuState:
    """Current state of the menu system.

    Attributes:
        items: Available menu items
        spotlight_app: Currently selected app (if any)
        running_tasks: List of running background task names
        analysis_state: Current analysis state
    """

    items: list[MenuItem]
    spotlight_app: str | None = None
    running_tasks: list[str] = field(default_factory=list)
    analysis_state: AnalysisStateEnum = AnalysisStateEnum.IDLE


@dataclass
class AnalysisConfig:
    """Configuration for an analysis run.

    Attributes:
        number_of_runs: Number of analysis runs to perform
        monitor_network: Whether to capture network traffic
        monitor_processes: Whether to monitor processes
        monitor_sockets: Whether to monitor sockets
        show_deleted: Whether to show deleted files
        take_screenshots: Whether to take screenshots
        screenshot_interval: Interval between screenshots (seconds)
        hash_files: Whether to compute file hashes
        pull_apk: Whether to pull APK files
        dry_run: Whether this is a dry run (noise detection)
        whitelist: Optional path to a whitelist file whose listed paths are
            excluded from analysis (``None`` disables whitelisting)
        capture_window: Seconds to wait for filesystem changes before
            scanning, for a pure forensic run with no driving action (e.g.
            ``AnalysisMode.FORENSIC``, which passes ``action=None``). Ignored
            for action-driven runs (Trigdroid/Player), which measure their
            own real elapsed duration instead. 60s matches this API's
            existing headless network-capture default (``cli.py --duration``).
    """

    number_of_runs: int = 2
    monitor_network: bool = False
    monitor_processes: bool = True
    monitor_sockets: bool = False
    show_deleted: bool = False
    take_screenshots: bool = False
    screenshot_interval: int = 3
    hash_files: bool = False
    pull_apk: bool = False
    dry_run: bool = False
    whitelist: str | None = None
    capture_window: int = 60


@dataclass
class AnalysisState:
    """Current state of an analysis run.

    Attributes:
        state: Current analysis state enum
        run_number: Current run number (1-based)
        total_runs: Total number of runs configured
        progress_message: Human-readable progress message
        started_at: When the analysis started
        spotlight_app: App being analyzed
        changed_files_count: Number of changed files detected
        error: Error message if state is ERROR
    """

    state: AnalysisStateEnum
    run_number: int = 0
    total_runs: int = 0
    progress_message: str = ""
    started_at: datetime | None = None
    spotlight_app: str | None = None
    changed_files_count: int = 0
    error: str | None = None


class EventHandler(Protocol):
    """Protocol for event handlers."""

    def __call__(self, event: Any) -> None:
        """Handle an event."""
        ...


class SandroidAPI(ABC):
    """Abstract interface for Sandroid operations.

    This interface defines the contract that UI layers use to interact
    with Sandroid's core functionality. Implementations of this interface
    can be created for different UI modes:

    - TUI (Textual): Interactive terminal interface
    - REST API: HTTP-based remote control
    - Headless: Batch/automated execution
    - CLI: Traditional command-line interface

    Thread Safety:
        Implementations should be thread-safe for concurrent access.

    Example:
        class MySandroidAdapter(SandroidAPI):
            async def execute_command(self, key: str) -> CommandResult:
                # Implementation here
                pass

        api = MySandroidAdapter(config)
        result = await api.execute_command("s")  # Take screenshot
        if result.success:
            print(f"Screenshot saved: {result.data['path']}")
    """

    # =========================================================================
    # Menu State
    # =========================================================================

    @abstractmethod
    async def get_menu_state(self) -> MenuState:
        """Get the current menu state.

        Returns:
            MenuState with available items and current context
        """
        ...

    @abstractmethod
    async def get_available_commands(self) -> list[MenuItem]:
        """Get list of available commands.

        Returns:
            List of MenuItem objects representing available commands
        """
        ...

    # =========================================================================
    # Command Execution
    # =========================================================================

    @abstractmethod
    async def execute_command(self, command_key: str) -> CommandResult:
        """Execute a command by its keyboard shortcut.

        Args:
            command_key: Single character command key (e.g., 's' for screenshot)

        Returns:
            CommandResult with success status and any data
        """
        ...

    @abstractmethod
    async def can_execute_command(self, command_key: str) -> tuple[bool, str]:
        """Check if a command can be executed.

        Args:
            command_key: Single character command key

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        ...

    # =========================================================================
    # Analysis Control
    # =========================================================================

    @abstractmethod
    async def get_analysis_state(self) -> AnalysisState:
        """Get the current analysis state.

        Returns:
            AnalysisState with current progress and status
        """
        ...

    @abstractmethod
    async def start_analysis(self, config: AnalysisConfig) -> CommandResult:
        """Start an analysis run.

        Args:
            config: Analysis configuration

        Returns:
            CommandResult indicating success/failure
        """
        ...

    @abstractmethod
    async def stop_analysis(self) -> CommandResult:
        """Stop the current analysis run.

        Returns:
            CommandResult indicating success/failure
        """
        ...

    @abstractmethod
    async def pause_analysis(self) -> CommandResult:
        """Pause the current analysis run.

        Returns:
            CommandResult indicating success/failure
        """
        ...

    @abstractmethod
    async def resume_analysis(self) -> CommandResult:
        """Resume a paused analysis run.

        Returns:
            CommandResult indicating success/failure
        """
        ...

    # =========================================================================
    # Spotlight App Management
    # =========================================================================

    @abstractmethod
    async def get_spotlight_app(self) -> str | None:
        """Get the current spotlight application package name.

        Returns:
            Package name or None if not set
        """
        ...

    @abstractmethod
    async def set_spotlight_app(
        self,
        package_name: str,
        mode: str = "attach",
    ) -> CommandResult:
        """Set the spotlight application.

        Args:
            package_name: Android package name to monitor
            mode: Either "attach" or "spawn"

        Returns:
            CommandResult indicating success/failure
        """
        ...

    @abstractmethod
    async def get_installed_apps(self) -> list[str]:
        """Get list of installed applications on device.

        Returns:
            List of package names
        """
        ...

    # =========================================================================
    # Background Tasks
    # =========================================================================

    @abstractmethod
    async def get_running_tasks(self) -> dict[str, dict[str, Any]]:
        """Get status of all running background tasks.

        Returns:
            Dictionary mapping task names to their status info
        """
        ...

    @abstractmethod
    async def stop_task(self, task_name: str) -> CommandResult:
        """Stop a specific background task.

        Args:
            task_name: Name of the task to stop

        Returns:
            CommandResult indicating success/failure
        """
        ...

    @abstractmethod
    async def stop_all_tasks(self) -> CommandResult:
        """Stop all running background tasks.

        Returns:
            CommandResult with list of stopped tasks
        """
        ...

    # =========================================================================
    # Forensic Operations
    # =========================================================================

    @abstractmethod
    async def get_spotlight_files(self) -> list[str]:
        """Get list of spotlight files being tracked.

        Returns:
            List of file paths
        """
        ...

    @abstractmethod
    async def add_spotlight_file(self, file_path: str) -> CommandResult:
        """Add a file to spotlight tracking.

        Args:
            file_path: Path on device to track

        Returns:
            CommandResult indicating success/failure
        """
        ...

    @abstractmethod
    async def remove_spotlight_file(self, file_path: str) -> CommandResult:
        """Remove a file from spotlight tracking.

        Args:
            file_path: Path to remove from tracking

        Returns:
            CommandResult indicating success/failure
        """
        ...

    @abstractmethod
    async def pull_spotlight_files(self) -> CommandResult:
        """Pull all spotlight files from device.

        Returns:
            CommandResult with list of pulled files
        """
        ...

    # =========================================================================
    # Event Subscription
    # =========================================================================

    @abstractmethod
    def subscribe_events(
        self,
        handler: Callable[[Any], None],
    ) -> Callable[[], None]:
        """Subscribe to all events.

        Args:
            handler: Function to call when events occur

        Returns:
            Unsubscribe function to call when done
        """
        ...

    @abstractmethod
    def subscribe_event_type(
        self,
        event_type: type,
        handler: Callable[[Any], None],
    ) -> Callable[[], None]:
        """Subscribe to specific event type.

        Args:
            event_type: Type of events to receive
            handler: Function to call when events occur

        Returns:
            Unsubscribe function to call when done
        """
        ...

    # =========================================================================
    # Device Information
    # =========================================================================

    @abstractmethod
    async def get_device_info(self) -> dict[str, Any]:
        """Get information about the connected device.

        Returns:
            Dictionary with device information (model, android version, etc.)
        """
        ...

    @abstractmethod
    async def is_device_connected(self) -> bool:
        """Check if a device is connected.

        Returns:
            True if device is connected and responsive
        """
        ...

    # =========================================================================
    # Lifecycle
    # =========================================================================

    @abstractmethod
    async def initialize(self) -> CommandResult:
        """Initialize the API and connect to services.

        Returns:
            CommandResult indicating success/failure
        """
        ...

    @abstractmethod
    async def shutdown(self) -> CommandResult:
        """Shutdown the API and cleanup resources.

        Returns:
            CommandResult indicating success/failure
        """
        ...


__all__ = [
    "AnalysisConfig",
    "AnalysisMode",
    "AnalysisState",
    "AnalysisStateEnum",
    "CommandResult",
    "EventHandler",
    "MenuItem",
    "MenuState",
    "SandroidAPI",
]
