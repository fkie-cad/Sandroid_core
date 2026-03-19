"""Typed event dataclasses for the Sandroid event system.

This module provides strongly-typed event classes that complement the
generic Event/EventType system in __init__.py. These typed events provide
better IDE support, documentation, and type safety.

The typed events map to EventType values and can be converted to/from
the generic Event class for use with the existing EventBus.

Usage:
    from sandroid.core.events.events import SpotlightAppChanged, CommandExecuted
    from sandroid.core.events import EventBus, Event, EventType

    # Publish a typed event
    event = SpotlightAppChanged(
        package_name="com.example.app",
        previous_package="com.old.app"
    )
    EventBus.get().publish(event.to_event())

    # Or use the convenience method
    SpotlightAppChanged(package_name="com.example.app").publish()
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Import the base Event and EventBus from the existing module
from . import Event, EventBus, EventType


@dataclass
class TypedEvent:
    """Base class for all typed events.

    Provides common functionality for converting to generic Event
    and publishing to the EventBus.
    """

    timestamp: datetime = field(default_factory=datetime.now)
    source: str | None = None

    @property
    def event_type(self) -> EventType:
        """Return the EventType for this event. Override in subclasses."""
        raise NotImplementedError("Subclasses must define event_type")

    def to_dict(self) -> dict[str, Any]:
        """Convert event data to dictionary. Override for custom serialization."""
        return {
            k: v
            for k, v in self.__dict__.items()
            if k not in ("timestamp", "source") and not k.startswith("_")
        }

    def to_event(self) -> Event:
        """Convert to generic Event for use with EventBus."""
        return Event(
            type=self.event_type,
            data=self.to_dict(),
            timestamp=self.timestamp,
            source=self.source,
        )

    def publish(self) -> None:
        """Publish this event to the EventBus."""
        EventBus.get().publish(self.to_event())


# =============================================================================
# Spotlight/App Selection Events
# =============================================================================


@dataclass
class SpotlightAppChanged(TypedEvent):
    """Published when the spotlight application is changed.

    Attributes:
        package_name: The new spotlight application package name
        previous_package: The previous spotlight application (if any)
        mode: 'attach' or 'spawn'
        pid: Process ID if known
    """

    package_name: str = ""
    previous_package: str | None = None
    mode: str = "attach"  # 'attach' or 'spawn'
    pid: int | None = None

    @property
    def event_type(self) -> EventType:
        return EventType.STATE_CHANGED


@dataclass
class SpotlightFileAdded(TypedEvent):
    """Published when a file is added to spotlight tracking.

    Attributes:
        file_path: Path of the file added
        total_files: Total number of spotlight files after addition
    """

    file_path: str = ""
    total_files: int = 0

    @property
    def event_type(self) -> EventType:
        return EventType.STATE_CHANGED


@dataclass
class SpotlightFileRemoved(TypedEvent):
    """Published when a file is removed from spotlight tracking.

    Attributes:
        file_path: Path of the file removed
        total_files: Total number of spotlight files after removal
    """

    file_path: str = ""
    total_files: int = 0

    @property
    def event_type(self) -> EventType:
        return EventType.STATE_CHANGED


# =============================================================================
# Snapshot Events
# =============================================================================


@dataclass
class SnapshotCreated(TypedEvent):
    """Published when a forensic snapshot is created.

    Attributes:
        name: Name of the snapshot
        path: Filesystem path to the snapshot
        file_count: Number of files in the snapshot
        baseline_hash: Hash of the baseline state
    """

    name: str = ""
    path: str = ""
    file_count: int = 0
    baseline_hash: str = ""

    @property
    def event_type(self) -> EventType:
        return EventType.STATE_CHANGED


@dataclass
class SnapshotLoaded(TypedEvent):
    """Published when a forensic snapshot is loaded.

    Attributes:
        name: Name of the loaded snapshot
        baseline_count: Number of files in the loaded baseline
    """

    name: str = ""
    baseline_count: int = 0

    @property
    def event_type(self) -> EventType:
        return EventType.STATE_CHANGED


# =============================================================================
# Task Lifecycle Events
# =============================================================================


@dataclass
class TaskStarted(TypedEvent):
    """Published when a background task starts.

    Attributes:
        task_name: Internal name of the task (e.g., 'fritap', 'dexray-intercept')
        display_name: Human-readable name
        task_type: Type category (e.g., 'network', 'instrumentation', 'capture')
        target_app: Target application package name (if applicable)
        target_pid: Target process PID (if applicable)
    """

    task_name: str = ""
    display_name: str = ""
    task_type: str = ""
    target_app: str | None = None
    target_pid: int | None = None

    @property
    def event_type(self) -> EventType:
        return EventType.TASK_STARTED


@dataclass
class TaskStopped(TypedEvent):
    """Published when a background task stops.

    Attributes:
        task_name: Internal name of the task
        display_name: Human-readable name
        success: Whether the task completed successfully
        duration_seconds: How long the task ran
        reason: Reason for stopping (if not success)
    """

    task_name: str = ""
    display_name: str = ""
    success: bool = True
    duration_seconds: float = 0.0
    reason: str = ""

    @property
    def event_type(self) -> EventType:
        return EventType.TASK_STOPPED


@dataclass
class TaskOutput(TypedEvent):
    """Published when a background task produces output.

    Attributes:
        task_name: Name of the task producing output
        message: The output message
        level: Log level ('info', 'warning', 'error', 'debug')
        data: Optional additional structured data
    """

    task_name: str = ""
    message: str = ""
    level: str = "info"
    data: dict[str, Any] | None = None

    @property
    def event_type(self) -> EventType:
        return EventType.TASK_OUTPUT


@dataclass
class TaskError(TypedEvent):
    """Published when a background task encounters an error.

    Attributes:
        task_name: Name of the task with error
        error_message: Error description
        error_type: Type/class of the error
        recoverable: Whether the task can recover
        stack_trace: Optional stack trace for debugging
    """

    task_name: str = ""
    error_message: str = ""
    error_type: str = ""
    recoverable: bool = False
    stack_trace: str | None = None

    @property
    def event_type(self) -> EventType:
        return EventType.TASK_ERROR


# =============================================================================
# Command Execution Events
# =============================================================================


@dataclass
class CommandExecuted(TypedEvent):
    """Published when a command is executed.

    Attributes:
        command_key: Keyboard shortcut for the command
        command_name: Human-readable command name
        category: Command category (e.g., 'forensic', 'network', 'analysis')
        success: Whether the command succeeded
        message: Result message
        duration_ms: Execution time in milliseconds
        data: Optional result data
    """

    command_key: str = ""
    command_name: str = ""
    category: str = ""
    success: bool = True
    message: str = ""
    duration_ms: int = 0
    data: dict[str, Any] | None = None

    @property
    def event_type(self) -> EventType:
        return EventType.STATE_CHANGED


@dataclass
class CommandFailed(TypedEvent):
    """Published when a command fails to execute.

    Attributes:
        command_key: Keyboard shortcut for the command
        command_name: Human-readable command name
        error: Error description
        reason: Reason code (e.g., 'precondition_failed', 'execution_error')
    """

    command_key: str = ""
    command_name: str = ""
    error: str = ""
    reason: str = ""

    @property
    def event_type(self) -> EventType:
        return EventType.TASK_ERROR


# =============================================================================
# Analysis Events
# =============================================================================


@dataclass
class AnalysisStarted(TypedEvent):
    """Published when an analysis run starts.

    Attributes:
        run_number: Current run number
        total_runs: Total number of runs planned
        modules: List of modules being run
    """

    run_number: int = 0
    total_runs: int = 0
    modules: list[str] = field(default_factory=list)

    @property
    def event_type(self) -> EventType:
        return EventType.STATE_CHANGED


@dataclass
class AnalysisCompleted(TypedEvent):
    """Published when an analysis run completes.

    Attributes:
        run_number: Completed run number
        total_runs: Total number of runs
        files_changed: Number of changed files detected
        new_files: Number of new files detected
        duration_seconds: Analysis duration
    """

    run_number: int = 0
    total_runs: int = 0
    files_changed: int = 0
    new_files: int = 0
    duration_seconds: float = 0.0

    @property
    def event_type(self) -> EventType:
        return EventType.STATE_CHANGED


@dataclass
class AnalysisStateChanged(TypedEvent):
    """Published when the overall analysis state changes.

    Attributes:
        state: New state ('idle', 'running', 'paused', 'completed')
        previous_state: Previous state
        run_number: Current run number (if applicable)
    """

    state: str = "idle"
    previous_state: str | None = None
    run_number: int | None = None

    @property
    def event_type(self) -> EventType:
        return EventType.STATE_CHANGED


# =============================================================================
# Hook/Instrumentation Events
# =============================================================================


@dataclass
class HookTriggered(TypedEvent):
    """Published when a Frida hook is triggered.

    Attributes:
        hook_name: Name of the triggered hook
        module: Module containing the hook (e.g., 'crypto', 'network')
        method: Method/function that was hooked
        arguments: Captured arguments (if any)
        return_value: Captured return value (if any)
        call_stack: Optional call stack information
    """

    hook_name: str = ""
    module: str = ""
    method: str = ""
    arguments: list[Any] | None = None
    return_value: Any | None = None
    call_stack: list[str] | None = None

    @property
    def event_type(self) -> EventType:
        return EventType.HOOK_TRIGGERED


# =============================================================================
# File System Events
# =============================================================================


@dataclass
class FileChanged(TypedEvent):
    """Published when a file change is detected.

    Attributes:
        file_path: Path of the changed file
        change_type: Type of change ('modified', 'created', 'deleted')
        old_hash: Previous file hash (for modifications)
        new_hash: New file hash
        size_delta: Change in file size (bytes)
    """

    file_path: str = ""
    change_type: str = "modified"
    old_hash: str | None = None
    new_hash: str | None = None
    size_delta: int = 0

    @property
    def event_type(self) -> EventType:
        return EventType.FILE_CHANGED


# =============================================================================
# Network Events
# =============================================================================


@dataclass
class NetworkEvent(TypedEvent):
    """Published when network activity is detected.

    Attributes:
        event_type_name: Type of network event ('connection', 'request', 'response')
        protocol: Protocol (e.g., 'tcp', 'udp', 'http', 'https')
        source_ip: Source IP address
        dest_ip: Destination IP address
        dest_port: Destination port
        data_size: Size of data transferred
        url: URL if applicable (for HTTP/HTTPS)
    """

    event_type_name: str = ""
    protocol: str = ""
    source_ip: str = ""
    dest_ip: str = ""
    dest_port: int = 0
    data_size: int = 0
    url: str | None = None

    @property
    def event_type(self) -> EventType:
        return EventType.NETWORK_EVENT


# =============================================================================
# UI Events
# =============================================================================


@dataclass
class MenuRefreshRequested(TypedEvent):
    """Published when the menu display should be refreshed.

    Attributes:
        reason: Why refresh is needed
        partial: Whether this is a partial refresh
        sections: Specific sections to refresh (if partial)
    """

    reason: str = ""
    partial: bool = False
    sections: list[str] = field(default_factory=list)

    @property
    def event_type(self) -> EventType:
        return EventType.MENU_REFRESH


@dataclass
class NotificationEvent(TypedEvent):
    """Published for user-facing notifications.

    Attributes:
        title: Notification title
        message: Notification message
        level: Notification level ('info', 'warning', 'error', 'success')
        duration_ms: How long to display (0 for persistent)
        action: Optional action identifier
    """

    title: str = ""
    message: str = ""
    level: str = "info"
    duration_ms: int = 3000
    action: str | None = None

    @property
    def event_type(self) -> EventType:
        return EventType.NOTIFICATION


# =============================================================================
# System Events
# =============================================================================


@dataclass
class AppStarting(TypedEvent):
    """Published when the Sandroid application is starting.

    Attributes:
        version: Application version
        config_path: Path to configuration file
        mode: Startup mode ('cli', 'tui', 'api')
    """

    version: str = ""
    config_path: str = ""
    mode: str = "cli"

    @property
    def event_type(self) -> EventType:
        return EventType.APP_STARTING


@dataclass
class AppShuttingDown(TypedEvent):
    """Published when the Sandroid application is shutting down.

    Attributes:
        reason: Reason for shutdown ('user_request', 'error', 'signal')
        running_tasks: List of tasks that were running
        cleanup_status: Status of cleanup operations
    """

    reason: str = "user_request"
    running_tasks: list[str] = field(default_factory=list)
    cleanup_status: str = "complete"

    @property
    def event_type(self) -> EventType:
        return EventType.APP_SHUTTING_DOWN


# =============================================================================
# Event Factory Functions
# =============================================================================


def create_task_output(task_name: str, message: str, level: str = "info") -> TaskOutput:
    """Convenience function to create and publish a task output event.

    Args:
        task_name: Name of the task
        message: Output message
        level: Log level

    Returns:
        The created TaskOutput event
    """
    event = TaskOutput(
        task_name=task_name, message=message, level=level, source=task_name
    )
    return event


def create_notification(
    message: str,
    title: str = "",
    level: str = "info",
    duration_ms: int = 3000,
) -> NotificationEvent:
    """Convenience function to create a notification event.

    Args:
        message: Notification message
        title: Optional title
        level: Notification level
        duration_ms: Display duration

    Returns:
        The created NotificationEvent
    """
    return NotificationEvent(
        title=title, message=message, level=level, duration_ms=duration_ms
    )


__all__ = [
    "AnalysisCompleted",
    # Analysis events
    "AnalysisStarted",
    "AnalysisStateChanged",
    "AppShuttingDown",
    # System events
    "AppStarting",
    # Command events
    "CommandExecuted",
    "CommandFailed",
    # File events
    "FileChanged",
    # Instrumentation events
    "HookTriggered",
    # UI events
    "MenuRefreshRequested",
    # Network events
    "NetworkEvent",
    "NotificationEvent",
    # Snapshot events
    "SnapshotCreated",
    "SnapshotLoaded",
    # Spotlight events
    "SpotlightAppChanged",
    "SpotlightFileAdded",
    "SpotlightFileRemoved",
    "TaskError",
    "TaskOutput",
    # Task events
    "TaskStarted",
    "TaskStopped",
    # Base class
    "TypedEvent",
    "create_notification",
    # Factory functions
    "create_task_output",
]
