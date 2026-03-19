"""Enums for Sandroid.

This module provides type-safe enumerations for commonly used string literals
throughout the codebase, improving type safety and IDE autocompletion.

Usage:
    from sandroid.core.enums import ViewMode, SpawnMode, TaskState

    # View management
    current_view = ViewMode.FORENSIC
    if view == ViewMode.MALWARE:
        ...

    # Spawn mode handling
    mode = SpawnMode.SPAWN if spawn_enabled else SpawnMode.ATTACH

    # Task state tracking
    task.state = TaskState.RUNNING
"""

from enum import Enum


class ViewMode(str, Enum):
    """UI view modes for display filtering.

    The default interactive menu cycles through three views:
    FORENSIC, MALWARE, and SECURITY.

    Additional view modes are defined for potential future use or
    custom integrations but are not part of the default cycle.

    Attributes:
        FORENSIC: Forensic analysis view (file changes, artifacts) - DEFAULT CYCLE
        MALWARE: Malware analysis view (behavioral analysis) - DEFAULT CYCLE
        SECURITY: Security testing view (vulnerability checks) - DEFAULT CYCLE
        NETWORK: Network analysis view (traffic, connections) - reserved
        PROCESSES: Process monitoring view - reserved
        FILES: File system view - reserved
        ANALYSIS: Analysis results view - reserved
    """

    FORENSIC = "forensic"
    MALWARE = "malware"
    SECURITY = "security"
    NETWORK = "network"
    PROCESSES = "processes"
    FILES = "files"
    ANALYSIS = "analysis"

    def __str__(self) -> str:
        """Return the string value for string comparisons."""
        return self.value


class SpawnMode(str, Enum):
    """Frida application spawn/attach modes.

    Controls how Frida connects to the target application.

    Attributes:
        SPAWN: Launch the application with Frida instrumentation from start.
               Allows hooking early initialization code.
        ATTACH: Connect to an already-running application.
                Faster but misses early code execution.
    """

    SPAWN = "spawn"
    ATTACH = "attach"

    def __str__(self) -> str:
        """Return the string value for string comparisons."""
        return self.value

    @property
    def is_spawn(self) -> bool:
        """Check if this is spawn mode."""
        return self == SpawnMode.SPAWN

    @property
    def is_attach(self) -> bool:
        """Check if this is attach mode."""
        return self == SpawnMode.ATTACH


class TaskState(str, Enum):
    """Background task execution states.

    Tracks the lifecycle state of background tasks.

    Attributes:
        PENDING: Task is queued but not yet started
        RUNNING: Task is currently executing
        PAUSED: Task is temporarily paused
        STOPPED: Task has been manually stopped
        COMPLETED: Task finished successfully
        ERROR: Task encountered an error
    """

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    COMPLETED = "completed"
    ERROR = "error"

    def __str__(self) -> str:
        """Return the string value for string comparisons."""
        return self.value

    @property
    def is_active(self) -> bool:
        """Check if this state represents an active task."""
        return self in (TaskState.PENDING, TaskState.RUNNING, TaskState.PAUSED)

    @property
    def is_terminal(self) -> bool:
        """Check if this state represents a terminal (finished) state."""
        return self in (TaskState.STOPPED, TaskState.COMPLETED, TaskState.ERROR)


class LogLevel(str, Enum):
    """Logging levels for application output.

    Attributes:
        DEBUG: Detailed debugging information
        INFO: General informational messages
        WARNING: Warning messages for potential issues
        ERROR: Error messages for failures
        CRITICAL: Critical errors requiring immediate attention
    """

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

    def __str__(self) -> str:
        """Return the string value."""
        return self.value


class AnalysisType(str, Enum):
    """Types of analysis that can be performed.

    Attributes:
        STATIC: Static analysis (no execution)
        DYNAMIC: Dynamic analysis (with execution)
        FORENSIC: Forensic artifact analysis
        NETWORK: Network traffic analysis
        BEHAVIORAL: Behavioral analysis
    """

    STATIC = "static"
    DYNAMIC = "dynamic"
    FORENSIC = "forensic"
    NETWORK = "network"
    BEHAVIORAL = "behavioral"

    def __str__(self) -> str:
        """Return the string value."""
        return self.value


__all__ = [
    "AnalysisType",
    "LogLevel",
    "SpawnMode",
    "TaskState",
    "ViewMode",
]
