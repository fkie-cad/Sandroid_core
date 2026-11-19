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
    spotlight.set_spawn_app("com.example.app", auto_resume=True)
"""

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from sandroid.core.adb_utils import validate_package_name
from sandroid.core.enums import SpawnMode
from sandroid.services.protocols import EventBusProtocol

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

    State Variables:
        - _current_app: SpotlightApp or None -- the attach-selected app
        - _spawn_package: str or None -- the spawn target
        - _spawn_pid: int or None -- PID of a spawn-selected app
        - _spawn_mode: bool -- whether in spawn mode
        - _auto_resume: bool -- auto-resume after a spawn

    This service is the single source of truth for the spotlight app;
    read it with :meth:`get_effective_package`. The file watchlist lives in
    ``ForensicService``.

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
        # Guards the multi-attribute state below so concurrent callers (e.g.
        # async subtasks plus the orchestrator) can't read/write a torn
        # combination of _current_app/_spawn_* fields. An RLock, NOT a plain
        # Lock: composite methods like reset()/get_state_dict() call the
        # (also-locked) get_effective_package(), which would self-deadlock
        # under a non-reentrant lock. Event publishing always happens OUTSIDE
        # this lock (repo convention: snapshot under lock, publish after).
        self._lock = threading.RLock()
        self._current_app: SpotlightApp | None = None
        self._spawn_package: str | None = None
        # PID for a spawn-selected app (Shift+C), which has no _current_app.
        # Lets the live running-state indicator surface a PID even before an
        # attach record exists. Kept in sync by set_pid().
        self._spawn_pid: int | None = None
        self._spawn_mode: bool = False
        self._auto_resume: bool = True
        #: Why the last spawn_app_paused() failed (None after a success).
        self.last_spawn_error: str | None = None
        #: Package Sandroid is restarting (⇧R) right now, else None.
        self._restarting: str | None = None
        self._event_bus = event_bus
        self._job_manager_factory = job_manager_factory
        self._logger = logger

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

        Leaves spawn mode: the spawn target, its PID and the auto-resume flag
        are reset, so the effective package is *package_name* afterwards.

        Args:
            package_name: Android package name
            activity_name: Activity name (optional)
            pid: Process ID (optional)
            mode: SpawnMode.ATTACH or SpawnMode.SPAWN (accepts string for backwards compatibility)

        Raises:
            ValueError: *package_name* is not a valid Android package name.
                The spotlight package is embedded in many device commands
                (pidof, force-stop, proxy lanes), so it is validated here.
        """
        validate_package_name(package_name)
        # Convert string to SpawnMode for backwards compatibility
        if isinstance(mode, str):
            mode = SpawnMode(mode)
        with self._lock:
            previous = self._current_app
            self._current_app = SpotlightApp(
                package_name=package_name,
                activity_name=activity_name,
                pid=pid,
                mode=mode,
            )
            self._spawn_package = None
            self._spawn_pid = None
            self._spawn_mode = False
            self._auto_resume = True
            previous_package = previous.package_name if previous else None
        self._logger.debug(
            f"Set spotlight app: {package_name}"
            + (f" (PID: {pid})" if pid else "")
            + f" [{mode} mode]"
        )

        self._publish_app_changed(
            package_name=package_name,
            previous_package=previous_package,
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

        Ignores an attach record that is not the effective package (spawn
        mode on another app).

        Returns:
            Activity name string or None
        """
        with self._lock:
            app = self._effective_current_app()
            return app.activity_name if app else None

    def get_pid(self) -> int | None:
        """Get the current spotlight process ID.

        Works for both attach-selected apps (``_current_app``) and
        spawn-selected apps (only ``_spawn_package`` set). An attach record
        that is not the effective package is ignored.

        Returns:
            PID integer or None
        """
        with self._lock:
            app = self._effective_current_app()
            if app:
                return app.pid
            return self._spawn_pid

    def _effective_current_app(self) -> SpotlightApp | None:
        """The attach record, if it belongs to the effective package.

        Returns:
            ``_current_app``, or None when it is unset or describes another
            app than :meth:`get_effective_package`.
        """
        with self._lock:
            app = self._current_app
            if app and app.package_name == self.get_effective_package():
                return app
            return None

    def set_pid(self, pid: int | None) -> None:
        """Update the PID of the current spotlight app.

        Works whether the app was attach-selected (``_current_app``) or
        spawn-selected (only ``_spawn_package`` set). Pass ``None`` to clear
        the PID (e.g. after the app is killed). An attach record that is not
        the effective package is left alone.

        Deliberately **non-publishing** (A5): it does not emit
        ``STATE_CHANGED``. The panel's running-state poll calls this from a
        worker thread on every tick; publishing here would create a
        poll -> event -> refresh feedback loop.

        Args:
            pid: New process ID, or None to clear it.
        """
        with self._lock:
            app = self._effective_current_app()
            if app:
                app.pid = pid
            self._spawn_pid = pid
        if pid:
            self._logger.debug(f"Updated spotlight PID to {pid}")
        else:
            self._logger.debug("Cleared spotlight PID")

    def announce_pid(self, pid: int | None, package: str | None = None) -> bool:
        """Set the PID after a lifecycle change (spawn, respawn, process death).

        Unlike :meth:`set_pid` this publishes ``STATE_CHANGED`` so the
        Spotlight panel shows the new PID at once (dexray/friTap spawns used
        to leave the pre-spawn PID on screen). Only for one-off lifecycle
        events -- never from a poll (see :meth:`set_pid`).

        Args:
            pid: The new process ID, or None if the process is gone.
            package: The package the PID belongs to. When given and it is not
                the spotlight package, nothing is changed.

        Returns:
            True if the PID changed.
        """
        effective = self.get_effective_package()
        if package and effective and package != effective:
            return False
        if self.get_pid() == pid:
            return False
        self.set_pid(pid)
        self._publish_pid(effective, pid)
        return True

    def _publish_pid(self, package: str | None, pid: int | None) -> None:
        """Publish ``STATE_CHANGED`` (``spotlight_pid``) for the header/panel.

        Falls back to the process-wide EventBus: the shared instance
        (``get_spotlight_service``) is built without one, so every
        ``announce_pid`` was silent and the header kept a dead PID until
        the lifecycle action ended (13-28 s during ⇧R).
        """
        bus = self._event_bus
        try:
            from sandroid.core.events import Event, EventBus, EventType

            if bus is None:
                bus = EventBus.get()
            bus.publish(
                Event(
                    type=EventType.STATE_CHANGED,
                    data={
                        "change_type": "spotlight_pid",
                        "package_name": package,
                        "pid": pid,
                        "restarting": self._restarting is not None,
                    },
                    source="spotlight_service",
                )
            )
        except Exception as e:
            self._logger.debug(f"spotlight PID publish failed: {e}")

    def begin_restart(self, package: str) -> None:
        """Sandroid killed ``package`` to restart it (⇧R): no PID until the
        new one is known (:meth:`announce_pid`); the header says
        "restarting…" meanwhile. Lasts until :meth:`end_restart`.
        """
        self._restarting = package
        self.set_pid(None)
        self._publish_pid(package, None)

    def end_restart(self) -> None:
        """The restart action is over (success or failure)."""
        if self._restarting is None:
            return
        package, self._restarting = self._restarting, None
        self._publish_pid(package, self.get_pid())

    def is_restarting(self, package: str | None = None) -> bool:
        """True while Sandroid restarts ``package`` (any package if None)."""
        if self._restarting is None:
            return False
        return package is None or package == self._restarting

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
        with self._lock:
            # Handle spawn mode first
            if self._spawn_mode and self._spawn_package:
                return (self._spawn_package, "")

            # Fall back to attach mode
            if not self._current_app:
                return None
            return (
                self._current_app.package_name,
                self._current_app.activity_name or "",
            )

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

        Raises:
            ValueError: *package_name* is not a valid Android package name.
        """
        validate_package_name(package_name)
        previous = self._select_spawn_package(package_name, auto_resume, keep_pid=True)

        self._logger.info(f"Set spawn app: {package_name} (auto_resume: {auto_resume})")

        self._publish_app_changed(
            package_name=package_name,
            previous_package=previous,
            mode=SpawnMode.SPAWN.value,
            pid=None,
        )

    def _select_spawn_package(
        self, package_name: str, auto_resume: bool, *, keep_pid: bool = False
    ) -> str | None:
        """Make *package_name* the spawn target (spawn mode on).

        Shared by :meth:`set_spawn_app` and :meth:`spawn_app_paused`. The
        spawn PID is reset and an attach record of another package is
        dropped. An attach record of the same package keeps its activity; it
        keeps its PID only with *keep_pid* (a ⇧C re-pick of the running app,
        so Space still re-checks the PID instead of killing it by a spawn).

        Args:
            package_name: Package name to spawn.
            auto_resume: Whether to auto-resume after hooks load.
            keep_pid: Keep a same-package attach record's PID. False when a
                new process was just spawned (that PID is stale).

        Returns:
            The previous spawn package, or None.
        """
        with self._lock:
            previous = self._spawn_package
            if self._current_app and self._current_app.package_name != package_name:
                self._current_app = None
            elif self._current_app and not keep_pid:
                self._current_app.pid = None
            self._spawn_package = package_name
            self._spawn_pid = None
            self._spawn_mode = True
            self._auto_resume = auto_resume
        return previous

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
        # debug: the UI that toggles it already reports the new state.
        self._logger.debug(f"Auto-resume {'enabled' if enabled else 'disabled'}")

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
                self.last_spawn_error = "No JobManager available"
                self._logger.error("No JobManager available")
                return None, -1

            pid = job_manager.spawn_paused(package_name)
            self.last_spawn_error = None
            self._select_spawn_package(package_name, auto_resume=False)
            # Still paused: a running file monitor follows the new process
            # before its first instruction (gap-free).
            self.notify_spawned(pid, package_name)

            self._logger.info(
                f"Spawned {package_name} (PID {pid}) in paused state "
                "for multi-tool loading"
            )
            return job_manager, pid
        except Exception as e:
            self.last_spawn_error = str(e)
            self._logger.error(f"Failed to spawn {package_name} paused: {e}")
            return None, -1

    # Spawn hand-off: called synchronously on the spawning thread while the
    # new process is still paused (before any resume), so a listener can
    # finish its work -- the file monitor adds the PID to its trace scope --
    # before the app runs its first instruction.
    _spawn_listeners: list[Callable[[int, str], None]] = []

    @classmethod
    def add_spawn_listener(cls, listener: Callable[[int, str], None]) -> None:
        """Call ``listener(pid, package)`` for every paused spawn."""
        if listener not in cls._spawn_listeners:
            cls._spawn_listeners.append(listener)

    @classmethod
    def remove_spawn_listener(cls, listener: Callable[[int, str], None]) -> None:
        if listener in cls._spawn_listeners:
            cls._spawn_listeners.remove(listener)

    def notify_spawned(self, pid: Any, package: str | None) -> None:
        """Hand a freshly spawned, still paused PID to the spawn listeners."""
        if not isinstance(pid, int) or pid <= 0 or not package:
            return
        for listener in list(self._spawn_listeners):
            try:
                listener(pid, package)
            except Exception as e:
                self._logger.debug(f"Spawn listener failed: {e}")

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
    # Reset
    # =========================================================================

    def reset(self) -> None:
        """Reset all spotlight state.

        Clears the current app, spawn configuration, and mode.
        """
        with self._lock:
            previous_pkg = self.get_effective_package()
            self._current_app = None
            self._spawn_package = None
            self._spawn_pid = None
            self._spawn_mode = False
            self._auto_resume = True

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
        with self._lock:
            if self._spawn_mode and self._spawn_package:
                return self._spawn_package
            return self.get_package_name()

    def get_effective_mode(self) -> SpawnMode:
        """Get the effective mode.

        Returns:
            SpawnMode.SPAWN if spawn mode active, otherwise SpawnMode.ATTACH
        """
        with self._lock:
            return SpawnMode.SPAWN if self._spawn_mode else SpawnMode.ATTACH

    def get_state_dict(self) -> dict[str, Any]:
        """Get the complete spotlight state as a dictionary.

        Useful for serialization and debugging.

        Returns:
            Dictionary with all spotlight state
        """
        with self._lock:
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
