"""Spotlight Application Service for Sandroid.

This service manages the "spotlight" application - the app currently being
monitored/analyzed. It handles app selection, spawn vs attach modes, and
maintains the current target state.

Extracted from Toolbox class to follow Single Responsibility Principle.

Usage:
    from sandroid.services import get_spotlight_service
    from sandroid.services.spotlight_service import SpotlightService

    # Get service
    spotlight = get_spotlight_service()

    # Set spotlight app
    spotlight.set_app(package_name="com.example.app", pid=12345)

    # Check current app
    if spotlight.has_app():
        pkg = spotlight.get_package_name()

    # Spawn mode
    spotlight.set_spawn_mode(package_name="com.example.app", auto_resume=True)
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from sandroid.core.enums import SpawnMode
from sandroid.services.protocols import EventBusProtocol

# Import config with fallback for standalone usage
try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

logger = logging.getLogger(__name__)


@dataclass
class SpotlightApp:
    """Represents the currently spotlighted application.

    Attributes:
        package_name: Android package name (e.g., "com.example.app")
        activity_name: Current activity name (if known)
        pid: Process ID (if known)
        mode: SpawnMode enum (ATTACH or SPAWN)
        set_at: When the spotlight was set
    """

    package_name: str
    activity_name: str | None = None
    pid: int | None = None
    mode: SpawnMode = SpawnMode.ATTACH
    set_at: datetime = field(default_factory=datetime.now)


class JobManagerProtocol(Protocol):
    """Protocol for JobManager dependency injection."""

    def spawn_paused(self, package_name: str) -> int:
        """Spawn an app in paused state."""
        ...

    def resume_app(self) -> bool:
        """Resume a paused app."""
        ...

    def is_paused(self) -> bool:
        """Check if an app is paused."""
        ...


class SpotlightService:
    """Service for managing the spotlight application.

    The spotlight application is the app currently being monitored or analyzed.
    This service tracks which app is selected, supports both SpawnMode.ATTACH
    (connecting to a running app) and SpawnMode.SPAWN (launching app with hooks).

    State Variables (migrated from Toolbox):
        - _spotlight_application: tuple or None -- the selected app
        - _spotlight_application_pid: int or None -- PID of attached process
        - _spawn_mode: bool -- whether in spawn mode
        - _spotlight_spawn_application: str or None -- spawn target
        - _auto_resume_after_spawn: bool -- auto-resume flag
        - _spotlight_files: list -- file watchlist for forensics
        - _spotlight_pull_one: dict or None -- first pull state
        - _spotlight_pull_two: dict or None -- second pull state

    Thread Safety:
        Operations are thread-safe for basic get/set operations.

    Example:
        service = SpotlightService()

        # Attach to running app
        service.set_app("com.example.app", pid=12345, mode=SpawnMode.ATTACH)

        # Or use spawn mode
        service.set_spawn_app("com.example.app", auto_resume=True)

        # Query state
        if service.is_spawn_mode():
            pkg = service.get_spawn_package()
        else:
            app = service.get_app()
    """

    def __init__(
        self,
        event_bus: EventBusProtocol | None = None,
        job_manager_factory: Any | None = None,
    ):
        """Initialize the SpotlightService.

        Args:
            event_bus: Optional EventBus for publishing state change events.
            job_manager_factory: Optional factory callable to get JobManager instance.
                                 If not provided, will use Toolbox.get_frida_job_manager().
        """
        self._current_app: SpotlightApp | None = None
        self._spawn_package: str | None = None
        # PID for a spawn-selected app (Shift+C), which has no _current_app.
        # Lets the live running-state indicator surface a PID even before an
        # attach record exists. Kept in sync by set_pid().
        self._spawn_pid: int | None = None
        self._spawn_mode: bool = False
        self._auto_resume: bool = True
        self._event_bus = event_bus
        self._job_manager_factory = job_manager_factory
        self._logger = logger

        # Toolbox-migrated state variables
        self._spotlight_application: tuple | None = None
        self._spotlight_application_pid: int | None = None
        self._spotlight_spawn_application: str | None = None
        self._auto_resume_after_spawn: bool = True
        self._spotlight_files: list = []
        self._spotlight_pull_one: dict | None = None
        self._spotlight_pull_two: dict | None = None

    # =========================================================================
    # App State (Attach Mode)
    # =========================================================================

    def set_app(
        self,
        package_name: str,
        activity_name: str | None = None,
        pid: int | None = None,
        mode: SpawnMode | str = SpawnMode.ATTACH,
    ) -> None:
        """Set the spotlight application.

        Args:
            package_name: Android package name
            activity_name: Activity name (optional)
            pid: Process ID (optional)
            mode: SpawnMode.ATTACH or SpawnMode.SPAWN (accepts string for backwards compatibility)
        """
        # Convert string to SpawnMode for backwards compatibility
        if isinstance(mode, str):
            mode = SpawnMode(mode)
        previous = self._current_app
        self._current_app = SpotlightApp(
            package_name=package_name,
            activity_name=activity_name,
            pid=pid,
            mode=mode,
        )
        self._logger.debug(
            f"Set spotlight app: {package_name}"
            + (f" (PID: {pid})" if pid else "")
            + f" [{mode} mode]"
        )

        self._publish_app_changed(
            package_name=package_name,
            previous_package=previous.package_name if previous else None,
            mode=mode.value,  # Pass string value for event serialization
            pid=pid,
        )

    def set_app_from_tuple(self, app_tuple: tuple[str, str]) -> None:
        """Set spotlight app from (package_name, activity_name) tuple.

        This matches the format returned by Adb.get_focused_app().

        Args:
            app_tuple: (package_name, activity_name) tuple
        """
        package_name, activity_name = app_tuple
        self.set_app(package_name=package_name, activity_name=activity_name)

    def get_app(self) -> SpotlightApp | None:
        """Get the current spotlight application.

        Returns:
            SpotlightApp instance or None if not set
        """
        return self._current_app

    def get_package_name(self) -> str | None:
        """Get the current spotlight package name.

        Returns:
            Package name string or None
        """
        return self._current_app.package_name if self._current_app else None

    def get_activity_name(self) -> str | None:
        """Get the current spotlight activity name.

        Returns:
            Activity name string or None
        """
        return self._current_app.activity_name if self._current_app else None

    def get_pid(self) -> int | None:
        """Get the current spotlight process ID.

        Works for both attach-selected apps (``_current_app``) and
        spawn-selected apps (only ``_spawn_package`` set).

        Returns:
            PID integer or None
        """
        if self._current_app:
            return self._current_app.pid
        return self._spawn_pid

    def set_pid(self, pid: int | None) -> None:
        """Update the PID of the current spotlight app.

        Works whether the app was attach-selected (``_current_app``) or
        spawn-selected (only ``_spawn_package`` set). Pass ``None`` to clear
        the PID (e.g. after the app is killed).

        Deliberately **non-publishing** (A5): it does not emit
        ``STATE_CHANGED``. The panel's running-state poll calls this from a
        worker thread on every tick; publishing here would create a
        poll -> event -> refresh feedback loop.

        Args:
            pid: New process ID, or None to clear it.
        """
        if self._current_app:
            self._current_app.pid = pid
        self._spawn_pid = pid
        if pid:
            self._logger.debug(f"Updated spotlight PID to {pid}")
        else:
            self._logger.debug("Cleared spotlight PID")

    def has_app(self) -> bool:
        """Check if a spotlight app is currently set.

        Returns:
            True if an app is set (in either attach or spawn mode)
        """
        return self._current_app is not None or self._spawn_package is not None

    def get_app_tuple(self) -> tuple[str, str] | None:
        """Get the spotlight app as (package_name, activity_name) tuple.

        For backwards compatibility with code expecting this format.
        Handles both attach mode (via _current_app) and spawn mode (via _spawn_package).

        Returns:
            Tuple of (package_name, activity_name) or None
        """
        # Handle spawn mode first
        if self._spawn_mode and self._spawn_package:
            return (self._spawn_package, "")

        # Fall back to attach mode
        if not self._current_app:
            return None
        return (self._current_app.package_name, self._current_app.activity_name or "")

    # =========================================================================
    # Spawn Mode
    # =========================================================================

    def set_spawn_app(
        self,
        package_name: str,
        auto_resume: bool = True,
    ) -> None:
        """Set the app to spawn with Frida hooks.

        Enables spawn mode where the app is launched fresh with
        hooks attached from the start.

        Args:
            package_name: Package name to spawn
            auto_resume: Whether to auto-resume after hooks load
        """
        previous = self._spawn_package
        self._spawn_package = package_name
        self._spawn_pid = None  # New spawn target -> any prior PID is stale
        self._spawn_mode = True
        self._auto_resume = auto_resume

        self._logger.info(f"Set spawn app: {package_name} (auto_resume: {auto_resume})")

        self._publish_app_changed(
            package_name=package_name,
            previous_package=previous,
            mode=SpawnMode.SPAWN.value,
            pid=None,
        )

    def get_spawn_package(self) -> str | None:
        """Get the package name configured for spawn mode.

        Returns:
            Package name string or None
        """
        return self._spawn_package

    def is_spawn_mode(self) -> bool:
        """Check if spawn mode is active.

        Returns:
            True if spawn mode is enabled
        """
        return self._spawn_mode

    def set_spawn_mode(self, mode: bool | str) -> None:
        """Set the spawn mode for the next Frida operation.

        Args:
            mode: Either a boolean (True=spawn, False=attach) for simple usage,
                  or one of 'multi_tool', 'single_tool', 'late_attach', 'attach'
                  for advanced control:
                - True or 'single_tool': Spawn with one primary tool, auto-resume
                  after hooks loaded
                - False or 'attach' or 'late_attach': Attach to running app
                - 'multi_tool': Spawn paused, load multiple tools, then resume
        """
        # Handle boolean for backward compatibility
        if isinstance(mode, bool):
            self._spawn_mode = mode
            self._auto_resume = True
            mode_str = "SPAWN" if mode else "ATTACH"
            self._logger.debug(f"Spotlight mode set to: {mode_str}")
            return

        # Handle string modes
        if mode == "multi_tool":
            self._spawn_mode = True
            self._auto_resume = False
        elif mode == "single_tool":
            self._spawn_mode = True
            self._auto_resume = True
        elif mode in ("late_attach", "attach"):
            self._spawn_mode = False
            self._auto_resume = True
        else:
            self._logger.warning(
                f"Unknown spawn mode: {mode}, defaulting to single_tool"
            )
            self._spawn_mode = True
            self._auto_resume = True

        self._logger.info(
            f"Spawn mode set to: {mode} (spawn={self._spawn_mode}, "
            f"auto_resume={self._auto_resume})"
        )

    def get_auto_resume(self) -> bool:
        """Check if auto-resume after spawn is enabled.

        Returns:
            True if auto-resume is enabled
        """
        return self._auto_resume

    def set_auto_resume(self, enabled: bool) -> None:
        """Enable or disable auto-resume after spawn.

        Args:
            enabled: True to enable auto-resume
        """
        self._auto_resume = enabled
        self._logger.info(f"Auto-resume {'enabled' if enabled else 'disabled'}")

    def get_spawn_mode_string(self) -> str:
        """Get the current spawn mode setting as a descriptive string.

        Returns:
            One of: 'multi_tool', 'single_tool', 'late_attach'
        """
        if self._spawn_mode and not self._auto_resume:
            return "multi_tool"
        if self._spawn_mode:
            return "single_tool"
        return "late_attach"

    # =========================================================================
    # Spawn App Paused (Multi-Tool Loading)
    # =========================================================================

    def _get_job_manager(self) -> JobManagerProtocol | None:
        """Get the JobManager instance.

        Uses the factory if provided, otherwise falls back to Toolbox.

        Returns:
            JobManager instance or None
        """
        if self._job_manager_factory is not None:
            return self._job_manager_factory()

        # Fallback to Toolbox for backwards compatibility
        try:
            from sandroid.core.toolbox import Toolbox

            return Toolbox.get_frida_job_manager()
        except Exception as e:
            self._logger.error(f"Failed to get JobManager: {e}")
            return None

    def spawn_app_paused(self, package_name: str) -> tuple[Any | None, int]:
        """Spawn an app in paused state for multi-tool loading.

        Use this when you want to load multiple Frida tools (FriTap, TrigDroid
        bypass, etc.) before the app starts executing. The app will remain
        paused until resume_paused_app() is called.

        Args:
            package_name: The package name of the app to spawn.

        Returns:
            Tuple of (JobManager instance, process ID) or (None, -1) on failure.
        """
        try:
            job_manager = self._get_job_manager()
            if job_manager is None:
                self._logger.error("No JobManager available")
                return None, -1

            pid = job_manager.spawn_paused(package_name)
            self._spawn_mode = True
            self._auto_resume = False
            self._spawn_package = package_name

            self._logger.info(
                f"Spawned {package_name} (PID {pid}) in paused state "
                "for multi-tool loading"
            )
            return job_manager, pid
        except Exception as e:
            self._logger.error(f"Failed to spawn {package_name} paused: {e}")
            return None, -1

    def resume_paused_app(self) -> bool:
        """Resume a paused app after tools have been loaded.

        Call this after loading all desired Frida tools to start app execution.

        Returns:
            True if app was resumed successfully, False otherwise.
        """
        job_manager = self._get_job_manager()
        if job_manager is None:
            self._logger.warning("No JobManager available to resume app")
            return False

        result = job_manager.resume_app()
        if result:
            self._auto_resume = True  # Reset to default
            self._logger.info(f"Resumed app {self._spawn_package}")
        return result

    def is_app_paused(self) -> bool:
        """Check if there's a paused app waiting to be resumed.

        Returns:
            True if an app is paused, False otherwise.
        """
        job_manager = self._get_job_manager()
        if job_manager is None:
            return False
        return job_manager.is_paused()

    # =========================================================================
    # Toolbox-Compatible State Accessors (migrated from Toolbox class vars)
    # =========================================================================

    def get_application(self) -> tuple | None:
        """Get the spotlight application tuple.

        Returns:
            A tuple (package_name, activity_name) or None.
        """
        return self._spotlight_application

    def set_application(self, spotlight_application: tuple | None) -> None:
        """Set the spotlight application tuple.

        Args:
            spotlight_application: Tuple from Adb.get_focused_app() or None.
        """
        self._spotlight_application = spotlight_application

    def get_application_pid(self) -> int | None:
        """Get the PID of the spotlight application.

        Returns:
            The PID as int or None.
        """
        return self._spotlight_application_pid

    def set_application_pid(self, pid: int | None) -> None:
        """Set the PID of the spotlight application.

        Args:
            pid: The PID of the spotlight application.
        """
        self._spotlight_application_pid = pid

    def reset_application(self) -> None:
        """Reset the spotlight application and its PID to None.

        Also resets spawn mode and spawn application.
        """
        self._spotlight_application = None
        self._spotlight_application_pid = None
        self._spawn_mode = False
        self._spawn_pid = None
        self._spotlight_spawn_application = None

    def set_spawn_application(self, package_name: str) -> None:
        """Set the application to be spawned when using Frida-based tools.

        Enables spawn mode automatically.

        Args:
            package_name: The package name of the app to spawn.
        """
        self._spotlight_spawn_application = package_name
        self._spawn_mode = True

    def get_spawn_application(self) -> str | None:
        """Get the package name of the app to be spawned.

        Returns:
            The package name or None.
        """
        return self._spotlight_spawn_application

    def set_auto_resume_after_spawn(self, enabled: bool) -> None:
        """Set whether spawned apps should be auto-resumed.

        Args:
            enabled: True to auto-resume, False to leave paused.
        """
        self._auto_resume_after_spawn = enabled

    def get_auto_resume_after_spawn(self) -> bool:
        """Get whether auto-resume after spawn is enabled.

        Returns:
            True if auto-resume is enabled.
        """
        return self._auto_resume_after_spawn

    def get_spotlight_files(self) -> list:
        """Get the list of spotlight files for monitoring.

        Returns:
            List of file paths.
        """
        return self._spotlight_files

    def set_spotlight_files(self, files: list) -> None:
        """Set the spotlight files list.

        Args:
            files: List of file paths.
        """
        self._spotlight_files = files

    def remove_spotlight_file(self, file_path: str | None = None) -> None:
        """Remove a file from the spotlight files list.

        Args:
            file_path: Path to remove, or None to remove the only file.
        """
        if len(self._spotlight_files) == 1 and file_path is None:
            removed = self._spotlight_files.pop()
            self._logger.debug(f"Removed the only spotlight file: {removed}")
        elif file_path and file_path in self._spotlight_files:
            self._spotlight_files.remove(file_path)
            self._logger.debug(f"Removed spotlight file: {file_path}")
        else:
            self._logger.warning(
                "File not found in spotlight files or no file specified."
            )

    def get_spotlight_pull_one(self) -> dict | None:
        """Get the first pull state.

        Returns:
            Dict or None.
        """
        return self._spotlight_pull_one

    def set_spotlight_pull_one(self, value: dict | None) -> None:
        """Set the first pull state.

        Args:
            value: Dict or None.
        """
        self._spotlight_pull_one = value

    def get_spotlight_pull_two(self) -> dict | None:
        """Get the second pull state.

        Returns:
            Dict or None.
        """
        return self._spotlight_pull_two

    def set_spotlight_pull_two(self, value: dict | None) -> None:
        """Set the second pull state.

        Args:
            value: Dict or None.
        """
        self._spotlight_pull_two = value

    @staticmethod
    def _get_spotlight_data_path_template() -> str:
        """Get the spotlight data path template from config with fallback.

        Returns:
            Path template string with {app} placeholder.
        """
        try:
            if get_config is not None:
                return get_config().device_paths.spotlight_data_path
        except Exception:
            pass
        return "/data/data/{app}"

    def get_spotlighted_app_data_path(self) -> str | None:
        """Get the /data/data/<package> path for the spotlight application.

        Handles both spawn mode and attach mode.

        Returns:
            The data path string, or None if no app is set.
        """
        template = self._get_spotlight_data_path_template()
        if self._spawn_mode and self._spotlight_spawn_application:
            return template.format(app=self._spotlight_spawn_application)
        if not self._spotlight_application:
            self._logger.warning("No spotlight application is set.")
            return None
        return template.format(app=self._spotlight_application[0])

    # =========================================================================
    # Reset
    # =========================================================================

    def reset(self) -> None:
        """Reset all spotlight state.

        Clears the current app, spawn configuration, and mode.
        """
        previous_pkg = self.get_effective_package()
        self._current_app = None
        self._spawn_package = None
        self._spawn_pid = None
        self._spawn_mode = False
        self._auto_resume = True

        # Reset Toolbox-migrated state
        self._spotlight_application = None
        self._spotlight_application_pid = None
        self._spotlight_spawn_application = None
        self._auto_resume_after_spawn = True
        self._spotlight_files = []
        self._spotlight_pull_one = None
        self._spotlight_pull_two = None

        self._logger.info("Reset spotlight application")

        if previous_pkg:
            self._publish_app_changed(
                package_name="",
                previous_package=previous_pkg,
                mode=SpawnMode.ATTACH.value,
                pid=None,
            )

    # =========================================================================
    # Effective State (combines attach and spawn)
    # =========================================================================

    def get_effective_package(self) -> str | None:
        """Get the effective package name (spawn or attach).

        Returns the spawn package if in spawn mode, otherwise
        returns the attached app's package name.

        Returns:
            Package name string or None
        """
        if self._spawn_mode and self._spawn_package:
            return self._spawn_package
        return self.get_package_name()

    def get_effective_mode(self) -> SpawnMode:
        """Get the effective mode.

        Returns:
            SpawnMode.SPAWN if spawn mode active, otherwise SpawnMode.ATTACH
        """
        return SpawnMode.SPAWN if self._spawn_mode else SpawnMode.ATTACH

    def get_state_dict(self) -> dict[str, Any]:
        """Get the complete spotlight state as a dictionary.

        Useful for serialization and debugging.

        Returns:
            Dictionary with all spotlight state
        """
        return {
            "has_app": self.has_app(),
            "package_name": self.get_effective_package(),
            "activity_name": self.get_activity_name(),
            "pid": self.get_pid(),
            "mode": self.get_effective_mode(),
            "spawn_mode": self._spawn_mode,
            "spawn_package": self._spawn_package,
            "auto_resume": self._auto_resume,
            "set_at": (
                self._current_app.set_at.isoformat() if self._current_app else None
            ),
            # Toolbox-migrated state
            "spotlight_application": self._spotlight_application,
            "spotlight_application_pid": self._spotlight_application_pid,
            "spotlight_spawn_application": self._spotlight_spawn_application,
            "auto_resume_after_spawn": self._auto_resume_after_spawn,
            "spotlight_files": self._spotlight_files.copy(),
            "spotlight_pull_one": self._spotlight_pull_one,
            "spotlight_pull_two": self._spotlight_pull_two,
        }

    # =========================================================================
    # Event Publishing (Private)
    # =========================================================================

    def _publish_app_changed(
        self,
        package_name: str,
        previous_package: str | None,
        mode: str,
        pid: int | None,
    ) -> None:
        """Publish a spotlight app changed event."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={
                    "change_type": "spotlight_app",
                    "package_name": package_name,
                    "previous_package": previous_package,
                    "mode": mode,
                    "pid": pid,
                },
                source="spotlight_service",
            )
        )

    # =========================================================================
    # Interactive Spotlight Selection (delegated to SpotlightSelectionUI)
    # =========================================================================

    def ensure_app_for_tools(
        self,
        tool_name: str = "this tool",
        adb: Any | None = None,
    ) -> bool:
        """Ensure a spotlight app is set, prompting user to select if not.

        This is the unified entry point for tools that require a spotlight application.
        Shows a UI asking user to choose ATTACH or SPAWN mode if no app is set.

        Supports both CLI mode (Rich console) and TUI mode (modal dialogs).

        Args:
            tool_name: Name of the tool requiring spotlight (for display)
            adb: Optional ADB interface for dependency injection

        Returns:
            True if spotlight is now set, False if user cancelled
        """
        from sandroid.tui.controllers.spotlight_selection_ui import (
            SpotlightSelectionUI,
        )

        ui = SpotlightSelectionUI(self)
        return ui.ensure_app_for_tools(tool_name=tool_name, adb=adb)


__all__ = [
    "SpotlightApp",
    "SpotlightService",
]
