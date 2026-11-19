"""Spotlight Application Service for Sandroid.

This service manages the "spotlight" application - the app currently being
monitored/analyzed. It holds a single *selection* (package, plus PID and
activity when known) and no spawn/attach mode: how a tool gets the app's
process is decided per call by :mod:`sandroid.services.app_start`.

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

    # Run state (cached PID + JobManager flag, no ADB)
    spotlight.get_run_state()  # "running" | "paused" | "not_running" | ...
"""

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from sandroid.core.adb_utils import validate_package_name
from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)

#: ``set_app(pid=...)`` default: keep the PID of a re-picked same package.
#: An explicit ``pid=None`` clears it (⇧C after a lookup found nothing).
_UNSET: Any = object()


@dataclass
class SpotlightApp:
    """Represents the currently spotlighted application.

    Attributes:
        package_name: Android package name (e.g., "com.example.app")
        activity_name: Current activity name (if known)
        pid: Process ID (if known)
        set_at: When the spotlight was set
    """

    package_name: str
    activity_name: str | None = None
    pid: int | None = None
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
    """Service for managing the spotlight application (one selection).

    The spotlight application is the app currently being monitored or
    analyzed: one :class:`SpotlightApp` record (package, activity, PID,
    set_at). There is no spawn/attach mode. Whether a Frida tool joins,
    attaches to, spawns or (with consent) restarts the app is decided per
    call by :func:`sandroid.services.app_start.resolve_start`.

    This service is the single source of truth for the spotlight app;
    read it with :meth:`get_effective_package`. The file watchlist lives in
    ``ForensicService``.

    Thread Safety:
        Operations are thread-safe for basic get/set operations.

    Example:
        service = SpotlightService()
        service.set_app("com.example.app", pid=12345)
        service.get_run_state()  # "running"
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
        # Guards the record so concurrent callers (async subtasks plus the
        # orchestrator) never read a torn state. An RLock: composite methods
        # like get_state_dict() call other locked getters. Event publishing
        # always happens OUTSIDE this lock (snapshot under lock, publish after).
        self._lock = threading.RLock()
        self._current_app: SpotlightApp | None = None
        #: Why the last spawn_app_paused() failed (None after a success).
        self.last_spawn_error: str | None = None
        #: Package Sandroid is restarting (⇧R) right now, else None.
        self._restarting: str | None = None
        self._event_bus = event_bus
        self._job_manager_factory = job_manager_factory
        self._logger = logger

    # =========================================================================
    # The selection
    # =========================================================================

    def set_app(
        self,
        package_name: str,
        activity_name: str | None = None,
        pid: Any = _UNSET,
    ) -> None:
        """Select ``package_name`` as the spotlight app.

        Re-selecting the same package without a ``pid`` keeps the known PID
        (and the activity when none is given), so a re-pick of the running
        app does not forget its process. An explicit ``pid=None`` clears it.

        Args:
            package_name: Android package name
            activity_name: Activity name (optional)
            pid: Process ID; omit to keep a same-package PID, None to clear.

        Raises:
            ValueError: *package_name* is not a valid Android package name.
                The spotlight package is embedded in many device commands
                (pidof, force-stop, proxy lanes), so it is validated here.
        """
        validate_package_name(package_name)
        with self._lock:
            previous = self._current_app
            same = previous is not None and previous.package_name == package_name
            if pid is _UNSET:
                pid = previous.pid if same else None
            if activity_name is None and same:
                activity_name = previous.activity_name
            self._current_app = SpotlightApp(
                package_name=package_name,
                activity_name=activity_name,
                pid=pid,
            )
            previous_package = previous.package_name if previous else None
        self._logger.debug(
            f"Set spotlight app: {package_name}" + (f" (PID: {pid})" if pid else "")
        )

        self._publish_app_changed(
            package_name=package_name,
            previous_package=previous_package,
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
        app = self._current_app
        return app.package_name if app else None

    def get_activity_name(self) -> str | None:
        """Get the current spotlight activity name.

        Returns:
            Activity name string or None
        """
        app = self._current_app
        return app.activity_name if app else None

    def get_pid(self) -> int | None:
        """Get the cached PID of the spotlight app (no ADB).

        Returns:
            PID integer or None
        """
        app = self._current_app
        return app.pid if app else None

    def set_pid(self, pid: int | None) -> None:
        """Update the cached PID of the current spotlight app.

        Pass ``None`` to clear the PID (e.g. after the app is killed).

        Deliberately **non-publishing** (A5): it does not emit
        ``STATE_CHANGED``. The panel's running-state poll calls this from a
        worker thread on every tick; publishing here would create a
        poll -> event -> refresh feedback loop.

        Args:
            pid: New process ID, or None to clear it.
        """
        with self._lock:
            if self._current_app:
                self._current_app.pid = pid
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
            True if an app is selected
        """
        return self._current_app is not None

    def get_app_tuple(self) -> tuple[str, str] | None:
        """Get the spotlight app as (package_name, activity_name) tuple.

        For backwards compatibility with code expecting this format.

        Returns:
            Tuple of (package_name, activity_name) or None
        """
        app = self._current_app
        if not app:
            return None
        return (app.package_name, app.activity_name or "")

    def get_run_state(self) -> str:
        """``"running"``, ``"paused"``, ``"not_running"`` or ``"restarting"``.

        Cheap: the cached PID plus the JobManager's paused flag, no ADB.
        Returns ``"not_running"`` without an app too.
        """
        if self.is_restarting():
            return "restarting"
        pid = self.get_pid()
        if pid and self.is_app_paused():
            return "paused"
        if pid:
            return "running"
        if self.is_app_paused():
            return "paused"  # a held, still-unnamed spawn (no pidof yet)
        return "not_running"

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
            # A new process: another package replaces the record; the same
            # package keeps its activity but not its old PID.
            with self._lock:
                app = self._current_app
                if app is None or app.package_name != package_name:
                    self._current_app = SpotlightApp(package_name=package_name)
                else:
                    app.pid = None
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
            self._logger.info(f"Resumed app {self.get_package_name()}")
        return result

    def is_app_paused(self) -> bool:
        """True if the JobManager holds the *spotlight app* paused.

        Package-scoped: a paused spawn of another package does not count.
        On an attach session AFM's ``package_name`` is the PID, so the
        cached PID is compared too.

        Returns:
            True if the spotlight app is paused, False otherwise.
        """
        job_manager = self._get_job_manager()
        if job_manager is None:
            return False
        try:
            if not job_manager.is_paused():
                return False
        except Exception:
            return False
        package = self.get_package_name()
        target = getattr(job_manager, "package_name", None)
        if not isinstance(target, (str, int)) or target in ("", None):
            return True  # a test double / unknown target: trust the flag
        if isinstance(target, int):
            return target == self.get_pid()
        return target == package

    # =========================================================================
    # Reset
    # =========================================================================

    def reset(self) -> None:
        """Reset all spotlight state.

        Clears the selection (leaves any running app alone).
        """
        with self._lock:
            previous_pkg = self.get_effective_package()
            self._current_app = None

        self._logger.info("Reset spotlight application")

        if previous_pkg:
            self._publish_app_changed(
                package_name="",
                previous_package=previous_pkg,
                pid=None,
            )

    # =========================================================================
    # Effective State
    # =========================================================================

    def get_effective_package(self) -> str | None:
        """The spotlight package (alias of :meth:`get_package_name`).

        Returns:
            Package name string or None
        """
        return self.get_package_name()

    def get_state_dict(self) -> dict[str, Any]:
        """Get the complete spotlight state as a dictionary.

        Returns:
            ``{has_app, package_name, activity_name, pid, state, running,
            paused, set_at}``; ``state`` is :meth:`get_run_state`.
        """
        with self._lock:
            app = self._current_app
            state = self.get_run_state() if app else "not_running"
            return {
                "has_app": app is not None,
                "package_name": app.package_name if app else None,
                "activity_name": app.activity_name if app else None,
                "pid": app.pid if app else None,
                "state": state,
                "running": state in ("running", "paused"),
                "paused": state == "paused",
                "set_at": app.set_at.isoformat() if app else None,
            }

    # =========================================================================
    # Event Publishing (Private)
    # =========================================================================

    def _publish_app_changed(
        self,
        package_name: str,
        previous_package: str | None,
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
                    "pid": pid,
                },
                source="spotlight_service",
            )
        )


__all__ = [
    "SpotlightApp",
    "SpotlightService",
]
