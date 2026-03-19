"""Action Window Service for Sandroid.

This service manages the action timing state during forensic analysis,
including the action time window, run counters, and dry run state.

The "action window" is the time period during which file changes are
tracked during an analysis run. It's defined by:
- action_time: Start timestamp of the action
- action_duration: How long the action window lasts

Extracted from Toolbox class to follow Single Responsibility Principle.

Usage:
    from sandroid.services import get_action_window_service
    from sandroid.services.action_window_service import ActionWindowService

    # Get service
    action_service = get_action_window_service()

    # Set action time from device
    action_service.set_action_time_from_device()

    # Set duration
    action_service.set_duration(30)

    # Check window
    start = action_service.get_action_time()
    end = start + action_service.get_duration()

    # Run management
    action_service.increase_run_counter()
    run_num = action_service.get_run_counter()
"""

import logging
import threading
from typing import Any, Protocol

from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)


class AdbProtocol(Protocol):
    """Protocol for ADB dependency injection."""

    @staticmethod
    def send_adb_command(command: str) -> tuple[str, str]:
        """Send an ADB command and return stdout, stderr."""
        ...


class ActionWindowService:
    """Service for managing action window timing during forensic analysis.

    The action window defines the time period during which file changes
    are monitored and attributed to a specific analysis action.

    This service manages:
    - Action time: The start timestamp of the current action window
    - Action duration: The length of the action window in seconds
    - Run counter: Number of analysis runs performed
    - Dry run state: Whether a dry run (baseline) is in progress
    - Changed files cache: Cached results of file change detection

    Thread Safety:
        This service is thread-safe. All state operations are protected by locks.

    Example:
        # During analysis setup
        service = ActionWindowService()
        service.set_action_time_from_device()
        service.set_duration(30)

        # Start a dry run (baseline capture)
        service.start_dry_run()
        # ... perform baseline operations ...

        # Start actual analysis runs
        for run in range(3):
            service.increase_run_counter()
            service.set_action_time_from_device()
            # ... perform analysis ...
            changed = service.get_changed_files_cached()
    """

    def __init__(
        self,
        adb: AdbProtocol | None = None,
        event_bus: EventBusProtocol | None = None,
    ):
        """Initialize ActionWindowService.

        Args:
            adb: Optional ADB interface for device time fetching.
                 If None, will import from sandroid.core.adb when needed.
            event_bus: Optional event bus for state change notifications.
        """
        self._adb = adb
        self._event_bus = event_bus
        self._logger = logger
        self._lock = threading.Lock()

        # Action window state
        self._action_time: int = 0
        self._action_duration: int = 0

        # Cache state
        self._filesystem_checked: bool = False
        self._changed_files_cache: dict[str, str] = {}

        # Run state
        self._is_dry_run: bool = False
        self._run_counter: int = 0

    def _get_adb(self) -> AdbProtocol:
        """Get ADB interface, importing if not injected.

        Returns:
            ADB interface for device communication.
        """
        if self._adb is not None:
            return self._adb
        from sandroid.core.adb import Adb

        return Adb

    # =========================================================================
    # Action Time Methods
    # =========================================================================

    def set_action_time_from_device(self) -> int:
        """Set action time by fetching current time from the device.

        Fetches the current Unix timestamp from the Android device/emulator
        using 'adb shell date +%s' and stores it as the action time.

        Also resets the filesystem check flag so that file changes will be
        re-fetched on the next query.

        Returns:
            The action time that was set.

        Raises:
            SystemExit: If the device time cannot be fetched.
        """
        adb = self._get_adb()
        output, error = adb.send_adb_command("shell date +%s")

        if error:
            self._logger.critical(f"Could not grab time from emulator: {error.strip()}")
            raise SystemExit(1)

        with self._lock:
            self._action_time = int(output.strip())
            self._filesystem_checked = False
            self._changed_files_cache = {}

        self._logger.debug(f"Action time set to {self._action_time}")
        return self._action_time

    def set_action_time(self, timestamp: int) -> None:
        """Set action time to a specific timestamp.

        Args:
            timestamp: Unix timestamp to set as action time.
        """
        with self._lock:
            self._action_time = timestamp
            self._filesystem_checked = False
            self._changed_files_cache = {}

    def get_action_time(self) -> int:
        """Get the current action time.

        Returns:
            Unix timestamp of the action start time.
        """
        with self._lock:
            return self._action_time

    # =========================================================================
    # Action Duration Methods
    # =========================================================================

    def set_duration(self, seconds: int, force: bool = False) -> None:
        """Set the action duration.

        By default, the duration can only be set once (when it's 0).
        Use force=True to override an existing duration.

        Args:
            seconds: Duration in seconds.
            force: If True, override existing duration.
        """
        with self._lock:
            if self._action_duration == 0 or force:
                self._action_duration = seconds
                self._logger.debug(f"Action duration set to {seconds}s")

    def get_duration(self) -> int:
        """Get the action duration.

        Returns:
            Duration in seconds.
        """
        with self._lock:
            return self._action_duration

    def get_action_window(self) -> tuple[int, int]:
        """Get the action window as (start_time, end_time).

        Returns:
            Tuple of (action_time, action_time + duration).
        """
        with self._lock:
            return (self._action_time, self._action_time + self._action_duration)

    # =========================================================================
    # Dry Run State Methods
    # =========================================================================

    def start_dry_run(self) -> None:
        """Mark the start of a dry run (baseline capture).

        A dry run captures the baseline state before actual analysis runs.
        Files that change during the dry run are considered "noise" and
        excluded from later analysis.
        """
        with self._lock:
            self._is_dry_run = True
        self._logger.debug("Dry run started")

    def end_dry_run(self) -> None:
        """Mark the end of a dry run."""
        with self._lock:
            self._is_dry_run = False
        self._logger.debug("Dry run ended")

    def is_dry_run(self) -> bool:
        """Check if a dry run is in progress.

        Returns:
            True if currently in dry run mode.
        """
        with self._lock:
            return self._is_dry_run

    # =========================================================================
    # Run Counter Methods
    # =========================================================================

    def get_run_counter(self) -> int:
        """Get the current run counter.

        Returns:
            Number of analysis runs completed.
        """
        with self._lock:
            return self._run_counter

    def increase_run_counter(self) -> int:
        """Increment the run counter by one.

        Returns:
            The new run counter value.
        """
        with self._lock:
            self._run_counter += 1
            return self._run_counter

    def reset_run_counter(self) -> None:
        """Reset the run counter to zero."""
        with self._lock:
            self._run_counter = 0

    # =========================================================================
    # Cache Methods
    # =========================================================================

    def is_filesystem_checked(self) -> bool:
        """Check if filesystem has been checked for this action time.

        Returns:
            True if filesystem was already checked.
        """
        with self._lock:
            return self._filesystem_checked

    def set_filesystem_checked(self, checked: bool = True) -> None:
        """Set the filesystem checked flag.

        Args:
            checked: Whether filesystem has been checked.
        """
        with self._lock:
            self._filesystem_checked = checked

    def get_changed_files_cache(self) -> dict[str, str]:
        """Get the cached changed files dictionary.

        Returns:
            Dictionary of file paths to change info, or empty if not cached.
        """
        with self._lock:
            return self._changed_files_cache.copy()

    def set_changed_files_cache(self, files: dict[str, str]) -> None:
        """Set the changed files cache.

        Args:
            files: Dictionary of file paths to change info.
        """
        with self._lock:
            self._changed_files_cache = files.copy()
            self._filesystem_checked = True

    def clear_cache(self) -> None:
        """Clear the changed files cache and reset filesystem checked flag."""
        with self._lock:
            self._changed_files_cache = {}
            self._filesystem_checked = False

    # =========================================================================
    # Reset Methods
    # =========================================================================

    def reset(self) -> None:
        """Reset all state to initial values.

        Useful when starting a new analysis session.
        """
        with self._lock:
            self._action_time = 0
            self._action_duration = 0
            self._filesystem_checked = False
            self._changed_files_cache = {}
            self._is_dry_run = False
            self._run_counter = 0
        self._logger.debug("Action window service reset")

    # =========================================================================
    # State Export Methods
    # =========================================================================

    def get_state_dict(self) -> dict[str, Any]:
        """Get complete service state as a dictionary.

        Useful for debugging, logging, and API responses.

        Returns:
            Dictionary containing all service state.
        """
        with self._lock:
            return {
                "action_time": self._action_time,
                "action_duration": self._action_duration,
                "action_window_end": self._action_time + self._action_duration,
                "filesystem_checked": self._filesystem_checked,
                "cached_files_count": len(self._changed_files_cache),
                "is_dry_run": self._is_dry_run,
                "run_counter": self._run_counter,
            }


__all__ = [
    "ActionWindowService",
    "AdbProtocol",
]
