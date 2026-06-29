"""Frida Session Service for Sandroid.

This service manages Frida sessions, JobManager coordination, and hook registration.
Extracted from Toolbox class to follow Single Responsibility Principle.

Usage:
    from sandroid.services import get_frida_session_service
    from sandroid.services.frida_session_service import FridaSessionService

    # Using service locator
    frida_service = get_frida_session_service()

    # Check session status
    if frida_service.has_active_session():
        info = frida_service.get_session_info()

    # Spawn app paused for multi-tool loading
    job_manager, pid = frida_service.spawn_paused("com.example.app")
    # ... load tools ...
    frida_service.resume_app()
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from sandroid.services.frida_device_manager import FridaDeviceManager
from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)


@dataclass
class FridaJobInfo:
    """Information about a running Frida job.

    Attributes:
        job_id: Unique identifier for the job
        name: Human-readable name
        target_package: Package being instrumented
        target_pid: Process ID
        hooks: List of registered hooks
        started_at: When the job started
    """

    job_id: str
    name: str
    target_package: str | None = None
    target_pid: int | None = None
    hooks: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)


class SpotlightServiceProtocol(Protocol):
    """Protocol for SpotlightService dependency injection."""

    def set_spawn_app(self, package: str, auto_resume: bool = True) -> None:
        """Set spawn app configuration."""
        ...

    def set_spawn_mode(self, enabled: bool) -> None:
        """Set spawn mode."""
        ...

    def set_auto_resume(self, enabled: bool) -> None:
        """Set auto-resume setting."""
        ...

    def is_spawn_mode(self) -> bool:
        """Check if in spawn mode."""
        ...

    def get_auto_resume(self) -> bool:
        """Get auto-resume setting."""
        ...

    def get_spawn_package(self) -> str | None:
        """Get spawn package name."""
        ...


class FridaSessionService:
    """Service for managing Frida sessions and job coordination.

    This service handles:
    - JobManager lifecycle and access
    - Session state tracking
    - Hook registration and conflict detection
    - Spawn/attach mode management
    - Multi-tool spawn coordination
    - Frida device caching for TUI thread safety

    Thread Safety:
        All operations are thread-safe through internal locking.
        Frida device initialization happens on the main thread to avoid
        hangs from Frida's signal handler requirements.

    Example:
        service = FridaSessionService()

        # Get JobManager
        job_manager = service.get_job_manager()

        # Check for hook conflicts
        conflicts = service.check_hook_conflicts(["crypto", "network"])

        # Spawn for multi-tool loading
        jm, pid = service.spawn_paused("com.example.app")
        # ... load tools ...
        service.resume_app()
    """

    def __init__(
        self,
        event_bus: EventBusProtocol | None = None,
        spotlight_service: SpotlightServiceProtocol | None = None,
    ):
        """Initialize the FridaSessionService.

        Args:
            event_bus: Optional EventBus for publishing events.
            spotlight_service: Optional SpotlightService for app state.
        """
        # Reentrant: get_job_manager() holds this lock while bootstrapping the
        # DeviceManager, which calls back into update_device_serial() (which
        # also takes this lock) on the same thread. A plain Lock self-deadlocks
        # there; an RLock makes that — and any other reentrant path — safe.
        self._lock = threading.RLock()
        self._event_bus = event_bus
        self._spotlight_service = spotlight_service
        self._logger = logger

        # Lazy-initialized managers
        self._job_manager = None
        self._frida_manager = None
        self._device_serial: str | None = None

        # State migrated from Toolbox (09-03)
        self._frida_job_manager_ref: Any = (
            None  # JobManager instance for running Frida scripts
        )
        self._malware_monitor_running: bool = False  # Whether malware monitor is active

        # Frida device cache for TUI thread safety
        # Frida's Python bindings require main thread for signal handlers
        self._cached_frida_device: Any = None
        self._cached_device_serial: str | None = None
        self._frida_device_lock = threading.Lock()

        # FridaDeviceManager for consolidated device lookup logic
        self._device_manager = FridaDeviceManager(parent_logger=self._logger)

    # =========================================================================
    # Spotlight Service Property (consolidates 8 repeated access patterns)
    # =========================================================================

    # =========================================================================
    # Spotlight Service Access (consolidates 8 repeated access patterns)
    # =========================================================================

    def _get_spotlight_service(self):
        """Get SpotlightService, using injected or global.

        All spotlight access goes through this single method, consolidating
        the 8 repeated access patterns into one place.
        """
        if self._spotlight_service is not None:
            return self._spotlight_service

        try:
            from sandroid.services import get_spotlight_service

            return get_spotlight_service()
        except ImportError:
            return None

    @property
    def _spotlight(self) -> Any | None:
        """Convenience property for accessing the SpotlightService.

        Delegates to _get_spotlight_service() so that tests patching
        _get_spotlight_service still work correctly.
        """
        return self._get_spotlight_service()

    # =========================================================================
    # JobManager Delegate Helper (replaces 6 identical lock-check blocks)
    # =========================================================================

    def _job_manager_call(self, method_name: str, default: Any, *args, **kwargs) -> Any:
        """Call a method on the JobManager with lock and null-check.

        Replaces the repeated pattern of:
            with self._lock:
                if self._job_manager is None:
                    return default
                try:
                    return self._job_manager.method()
                except Exception:
                    return default

        Args:
            method_name: Name of the JobManager method to call.
            default: Value to return if JobManager is None or call fails.
            *args: Positional arguments for the method.
            **kwargs: Keyword arguments for the method.

        Returns:
            Result of the method call, or default on failure.
        """
        with self._lock:
            if self._job_manager is None:
                return default
            try:
                method = getattr(self._job_manager, method_name)
                return method(*args, **kwargs)
            except Exception:
                return default

    # =========================================================================
    # JobManager Access
    # =========================================================================

    def get_job_manager(self):
        """Get or create the JobManager instance.

        Returns:
            JobManager instance for Frida job coordination.
        """
        # Resolve the device serial BEFORE taking _lock. On first access
        # _get_device_serial_from_manager() bootstraps the DeviceManager, which
        # re-enters update_device_serial() (also guarded by _lock) on this same
        # thread. Doing it outside the lock keeps the reentrant chain from ever
        # contending (and the RLock above covers any path we missed).
        resolved_serial = self._device_serial
        if resolved_serial is None:
            resolved_serial = self._get_device_serial_from_manager()

        with self._lock:
            if self._job_manager is None:
                # The bootstrap above may have set _device_serial via
                # update_device_serial(); prefer it, else the resolved value.
                device_serial = self._device_serial or resolved_serial

                try:
                    from AndroidFridaManager import JobManager

                    self._job_manager = JobManager(device_serial=device_serial)
                    self._logger.debug("JobManager initialized")
                except ImportError as e:
                    self._logger.error(f"Failed to import JobManager: {e}")
                    raise
                except RuntimeError as e:
                    self._logger.error(
                        f"{e}\n"
                        "Hint: Start an AVD with 'sandroid-config avd start' "
                        "or connect a physical device via USB."
                    )
                    raise

            return self._job_manager

    def get_frida_manager(self):
        """Get or create the FridaManager instance.

        Returns:
            FridaManager instance for Frida operations.
        """
        with self._lock:
            if self._frida_manager is None:
                try:
                    from AndroidFridaManager import FridaManager

                    self._frida_manager = FridaManager(
                        verbose=True,
                        frida_install_dst="/data/local/tmp/",
                        device_serial=self._device_serial,
                    )
                    self._logger.debug("FridaManager initialized")
                except ImportError as e:
                    self._logger.error(f"Failed to import FridaManager: {e}")
                    raise
                except RuntimeError as e:
                    self._logger.error(
                        f"{e}\n"
                        "Hint: Start an AVD with 'sandroid-config avd start' "
                        "or connect a physical device via USB."
                    )
                    raise

            return self._frida_manager

    def set_frida_manager(self, frida_manager: Any) -> None:
        """Set an externally-created FridaManager instance.

        Call this to share the FridaManager created during initialization,
        avoiding a duplicate instantiation.

        Args:
            frida_manager: FridaManager instance to use.
        """
        with self._lock:
            self._frida_manager = frida_manager
            if frida_manager is not None:
                self._device_serial = getattr(
                    frida_manager, "device_serial", self._device_serial
                )
                self._logger.debug("FridaManager set from external source")

    def update_device_serial(self, serial: str) -> None:
        """Update the device serial for Frida operations.

        Call this when the active device changes.

        Args:
            serial: Device serial to target.
        """
        with self._lock:
            # Skip if serial unchanged -- avoids redundant ADB.find() in setter
            if serial == self._device_serial:
                return

            self._device_serial = serial

            if self._frida_manager is not None:
                try:
                    self._frida_manager.device_serial = serial
                    self._logger.debug(f"Updated FridaManager device: {serial}")
                except Exception as e:
                    self._logger.warning(f"Failed to update FridaManager device: {e}")

            if self._job_manager is not None:
                try:
                    self._job_manager.device_serial = serial
                    self._logger.debug(f"Updated JobManager device: {serial}")
                except Exception as e:
                    self._logger.warning(f"Failed to update JobManager device: {e}")

        # Invalidate Frida device cache when device changes
        self.invalidate_frida_device_cache()

    # =========================================================================
    # Frida Device Caching (Thread Safety for TUI)
    # Uses FridaDeviceManager for device lookup, but keeps caching logic here
    # so that tests can patch _init_frida_device_on_main_thread on the service.
    # =========================================================================

    def invalidate_frida_device_cache(self) -> None:
        """Invalidate cached Frida device.

        Call this when the active device changes (e.g., via Shift+D in TUI).
        The next call to get_frida_device() will re-initialize on the main thread.
        """
        with self._frida_device_lock:
            self._cached_frida_device = None
            self._cached_device_serial = None
            self._logger.debug("Invalidated Frida device cache")

    def _init_frida_device_on_main_thread(self, device_serial: str) -> Any:
        """Initialize Frida device - MUST be called from main thread.

        Frida's Python bindings have main thread requirements:
        - Signal handler installation (Python only allows on main thread)
        - Thread-local state in Frida's C bindings
        - USB/ADB communication

        Uses FridaDeviceManager.lookup_device_by_serial to consolidate the
        duplicated get_device -> enumerate fallback pattern.

        Args:
            device_serial: The device serial to connect to.

        Returns:
            Frida device object or None if initialization fails.
        """
        try:
            self._logger.debug(
                f"Initializing Frida device on main thread: {device_serial}"
            )
            device = self._device_manager.lookup_device_by_serial(device_serial)
            if device is None:
                self._logger.error(f"Frida device '{device_serial}' not found")
                return None
            self._logger.debug(
                f"Frida device initialized: {device.name} ({device_serial})"
            )
            return device
        except Exception as e:
            self._logger.error(f"Failed to initialize Frida device: {e}")
            return None

    def get_frida_device(
        self, device_serial: str | None = None, app: Any = None
    ) -> Any:
        """Get cached Frida device or initialize on main thread.

        IMPORTANT: For TUI mode, the device MUST be pre-initialized before the
        TUI event loop starts (in cli.py). If called from a worker thread without
        a cached device, this method returns None to avoid deadlock.

        The call_from_thread approach was removed because it causes deadlock:
        - Worker thread holds _frida_device_lock
        - Calls app.call_from_thread() to init on main thread
        - Main thread may be blocked/busy with Textual event loop
        - Result: DEADLOCK

        Args:
            device_serial: The device serial. If None, uses current active device.
            app: Ignored (kept for API compatibility). Previously used for
                 call_from_thread which caused deadlocks.

        Returns:
            Cached Frida device, or None if not available.
        """
        # Get device serial if not provided
        if device_serial is None:
            device_serial = self._device_serial
            if device_serial is None:
                device_serial = self._get_device_serial_from_manager()

        if device_serial is None:
            self._logger.error("No device serial available for Frida device")
            return None

        with self._frida_device_lock:
            # Return cached device if serial matches
            if (
                self._cached_frida_device is not None
                and self._cached_device_serial == device_serial
            ):
                self._logger.debug(f"Using cached Frida device: {device_serial}")
                return self._cached_frida_device

            # Need to initialize - check if we're on main thread
            if threading.current_thread() is threading.main_thread():
                # On main thread - safe to initialize directly
                self._logger.debug("Initializing Frida device directly (main thread)")
                self._cached_frida_device = self._init_frida_device_on_main_thread(
                    device_serial
                )
                self._cached_device_serial = device_serial
                return self._cached_frida_device
            # Worker thread and no cached device - NOT safe to init
            # Would cause deadlock with Textual event loop
            self._logger.warning(
                "Frida device not pre-initialized. Cannot init from worker thread. "
                "FriTap may not work. Restart sandroid with a connected device."
            )
            return None

    # =========================================================================
    # Frida Job Manager (migrated from Toolbox)
    # =========================================================================

    def get_frida_job_manager_ref(self) -> Any:
        """Get the raw Frida JobManager reference (migrated from Toolbox._frida_job_manager).

        Returns:
            The Frida JobManager instance, or None if not set.
        """
        with self._lock:
            return self._frida_job_manager_ref

    def set_frida_job_manager_ref(self, value: Any) -> None:
        """Set the raw Frida JobManager reference.

        Args:
            value: The JobManager instance.
        """
        with self._lock:
            self._frida_job_manager_ref = value

    # =========================================================================
    # Malware Monitor State (migrated from Toolbox)
    # =========================================================================

    @property
    def malware_monitor_running(self) -> bool:
        """Check if the malware monitor is currently running.

        Returns:
            True if the malware monitor is active.
        """
        with self._lock:
            return self._malware_monitor_running

    @malware_monitor_running.setter
    def malware_monitor_running(self, value: bool) -> None:
        """Set the malware monitor running state.

        Args:
            value: True to mark as running, False to mark as stopped.
        """
        with self._lock:
            self._malware_monitor_running = value
            self._logger.debug(f"Malware monitor running: {value}")

    # =========================================================================
    # Resume Spawned Process (migrated from Toolbox)
    # =========================================================================

    def resume_spawned_process(self, device: Any, pid: int) -> None:
        """Resume a spawned process after hooks, with 1s sleep for Java.perform stability.

        Moved from Toolbox.resume_spawned_process_after_hooks() to keep business
        logic in the service layer.

        Args:
            device: Frida device object.
            pid: Process ID to resume.
        """
        import time

        # Defensive: a worker thread without a pre-cached frida device gets
        # None from get_frida_device(); resuming through None would AttributeError
        # mid-spawn. Nothing to resume without a device — bail quietly.
        if device is None:
            self._logger.warning(
                "resume_spawned_process: no frida device; cannot resume pid %s",
                pid,
            )
            return

        # Idempotency guard (A2): ``is_paused()`` is the single source of truth
        # for whether a resume is needed. ``JobManager.start_job`` already
        # resumes the first job of a freshly spawned session, so callers that
        # unconditionally call this after a tool loads (friTap, MalwareMonitor)
        # would otherwise issue a second, redundant ``device.resume`` on an
        # already-running process. Skip when nothing is paused.
        if not self.is_paused():
            self._logger.debug(
                f"Process {pid} is not paused; skipping resume (already running)"
            )
            return

        spotlight = self._spotlight
        auto_resume = True
        if spotlight:
            auto_resume = spotlight.get_auto_resume()

        if auto_resume:
            self._logger.debug(f"Resuming spawned process {pid}")
            device.resume(pid)
            time.sleep(1)  # CRITICAL: Prevents Java.perform from silently failing
            # device.resume() bypasses JobManager.resume_app() (used directly
            # here to keep the ProcessNotFoundError anti-Frida diagnostic), so
            # clear the paused flag ourselves — otherwise is_paused() would
            # stay True and later live bundle ops would wrongly rebuild-merge.
            jm = self._job_manager
            if jm is not None:
                jm.mark_resumed()
        else:
            self._logger.info(
                f"Process {pid} remains PAUSED. Resume manually when ready."
            )

    # =========================================================================
    # Session State (uses _job_manager_call helper)
    # =========================================================================

    def has_active_session(self) -> bool:
        """Check if there's an active Frida session.

        Returns:
            True if a Frida session is active.
        """
        return self._job_manager_call("has_active_session", False)

    def get_session_info(self) -> dict[str, Any] | None:
        """Get current Frida session information.

        Returns:
            Dictionary with session info, or None if no session.
        """
        return self._job_manager_call("get_session_info", None)

    def get_running_jobs(self) -> list[dict[str, Any]]:
        """Get information about running Frida jobs.

        Returns:
            List of dictionaries containing job information.
        """
        return self._job_manager_call("get_running_jobs_info", [])

    def is_paused(self) -> bool:
        """Check if there's a paused app waiting to be resumed.

        Returns:
            True if an app is paused.
        """
        return self._job_manager_call("is_paused", False)

    # =========================================================================
    # Hook Management (uses _job_manager_call helper)
    # =========================================================================

    def check_hook_conflicts(self, hooks: list[str]) -> dict[str, str]:
        """Check for potential hook conflicts before registering.

        Args:
            hooks: List of hook targets to check.

        Returns:
            Dictionary mapping conflicting hooks to their owning job IDs.
        """
        return self._job_manager_call("check_hook_conflicts", {}, hooks)

    def register_hooks(self, job_id: str, hooks: list[str]) -> list[str]:
        """Register hooks for a Frida job.

        Args:
            job_id: UUID of the job registering hooks.
            hooks: List of hook targets.

        Returns:
            List of conflicting hooks that were already registered.
        """
        with self._lock:
            if self._job_manager is None:
                return []
            try:
                return self._job_manager.register_hooks(job_id, hooks)
            except Exception as e:
                self._logger.error(f"Failed to register hooks: {e}")
                return []

    def unregister_hooks(self, job_id: str) -> None:
        """Unregister hooks for a Frida job.

        Args:
            job_id: UUID of the job whose hooks should be unregistered.
        """
        with self._lock:
            if self._job_manager is None:
                return
            try:
                self._job_manager.unregister_hooks(job_id)
            except Exception as e:
                self._logger.warning(f"Failed to unregister hooks: {e}")

    # =========================================================================
    # Unified Session Management (get_session_for_spotlight)
    # =========================================================================

    def get_session_for_spotlight(self) -> tuple[Any, str, dict[str, Any]]:
        """Returns appropriate Frida session based on current mode (spawn/attach).

        This is the unified abstraction layer for all Frida-based tools.
        Supports multi-device environments by using the active device from DeviceManager.

        Returns:
            A tuple of (session, mode, app_info) where:
                - session: Frida session object
                - mode: "spawn" or "attach"
                - app_info: dict with package_name, pid, mode, device

        Raises:
            ValueError: If no spotlight app is set or app is not running
            frida.ProcessNotFoundError: If target process not found
            frida.ServerNotRunningError: If Frida server not running
            Exception: For other Frida-related errors
        """
        import frida

        spotlight = self._spotlight
        if spotlight is None:
            raise ValueError("SpotlightService not available")

        try:
            # Get Frida device based on active device selection (multi-device support)
            device = self._device_manager.get_device_for_session()

            spawn_package = spotlight.get_spawn_package()
            if spotlight.is_spawn_mode() and spawn_package:
                return self._spawn_session(device, spawn_package, spotlight)

            return self._attach_session(device, spotlight)

        except frida.ProcessNotFoundError as e:
            self._logger.error(f"Process not found: {e}")
            raise
        except frida.ServerNotRunningError:
            self._logger.error("Frida server is not running. Press 'f' to start it.")
            raise
        except Exception as e:
            self._log_session_error(e)
            raise

    def _spawn_session(
        self, device: Any, spawn_package: str, spotlight: Any
    ) -> tuple[Any, str, dict[str, Any]]:
        """Spawn an application and attach to it (paused).

        Args:
            device: Frida device object.
            spawn_package: Package name to spawn.
            spotlight: SpotlightService instance.

        Returns:
            Tuple of (session, "spawn", app_info).
        """
        self._logger.info(f"Spawning application: {spawn_package}")

        # Spawn the application (starts paused)
        pid = device.spawn([spawn_package])
        self._logger.debug(f"Spawned process with PID: {pid}")

        # Attach to the spawned process
        session = device.attach(pid)
        self._logger.debug("Attached to spawned process")

        # Don't resume yet - let the caller resume AFTER installing hooks
        self._logger.debug(
            f"Process spawned and attached but PAUSED. "
            f"Will be resumed after hooks are installed (auto-resume: {spotlight.get_auto_resume()})"
        )

        app_info = {
            "package_name": spawn_package,
            "pid": pid,
            "mode": "spawn",
            "device": device,
        }

        self._logger.info(
            f"Successfully spawned and attached to {spawn_package} (PID: {pid})"
        )

        return session, "spawn", app_info

    def _attach_session(
        self, device: Any, spotlight: Any
    ) -> tuple[Any, str, dict[str, Any]]:
        """Attach to a running application.

        Args:
            device: Frida device object.
            spotlight: SpotlightService instance.

        Returns:
            Tuple of (session, "attach", app_info).

        Raises:
            ValueError: If no app is set or app is not running.
        """
        app_tuple = spotlight.get_app_tuple()
        if not app_tuple:
            raise ValueError(
                "No spotlight application set. Press 'c' to set current app or 'C' to select spawn app."
            )

        package_name = app_tuple[0]
        self._logger.info(f"Attaching to running application: {package_name}")

        # Get PID if not already set
        current_pid = spotlight.get_pid()
        if not current_pid:
            pid = self._get_pid_for_package(package_name)
            if not pid:
                raise ValueError(
                    f"Application {package_name} is not running. "
                    f"Start it first or use spawn mode (Shift+C)."
                )
            spotlight.set_pid(pid)
        else:
            pid = current_pid

        # Attach to running process using PID (not package name)
        # Using PID is more reliable than package name
        self._logger.debug(f"Attaching to {package_name} with PID {pid}")
        session = device.attach(pid)
        self._logger.debug(f"Attached to running process (PID: {pid})")

        app_info = {
            "package_name": package_name,
            "pid": pid,
            "mode": "attach",
            "device": device,
        }

        self._logger.info(f"Successfully attached to {package_name} (PID: {pid})")

        return session, "attach", app_info

    def _log_session_error(self, error: Exception) -> None:
        """Log detailed error information for Frida session failures.

        Args:
            error: The exception that occurred.
        """
        error_msg = str(error).lower()

        # Handle specific "front-door activity" error in spawn mode
        if "front-door" in error_msg or "unable to find" in error_msg:
            self._logger.error(f"Error setting up Frida session: {error}")
            self._logger.error("")
            self._logger.error("This error typically occurs when:")
            self._logger.error("  1. The app has no launchable main activity")
            self._logger.error("  2. The package name is incorrect")
            self._logger.error("  3. The app cannot be launched directly")
            self._logger.error("")
            self._logger.error("Suggestions:")
            self._logger.error("  - Verify the package name is correct")
            self._logger.error(
                "  - Try using ATTACH mode instead (press 'c' after launching the app manually)"
            )
            self._logger.error("  - Check if the app appears in the launcher")
            self._logger.error("  - For system services, use attach mode only")
        else:
            self._logger.error(f"Error setting up Frida session: {error}")

    def _get_frida_device(self) -> Any:
        """Get the appropriate Frida device based on active device selection.

        Returns:
            Frida device object

        Raises:
            frida.InvalidArgumentError: If device not found
        """
        return self._device_manager.get_device_for_session()

    def _get_pid_for_package(self, package_name: str) -> int | None:
        """Get PID for a package name via ADB.

        Args:
            package_name: The package name to look up

        Returns:
            PID if found, None otherwise
        """
        try:
            from sandroid.core.adb import Adb

            return Adb.get_pid_for_package_name(package_name)
        except Exception as e:
            self._logger.warning(f"Failed to get PID for {package_name}: {e}")
            return None

    # =========================================================================
    # Spawn/Attach Mode
    # =========================================================================

    def spawn_paused(self, package_name: str) -> tuple[Any, int]:
        """Spawn an app in paused state for multi-tool loading.

        Use this when you want to load multiple Frida tools before
        the app starts executing.

        Args:
            package_name: The package name of the app to spawn.

        Returns:
            Tuple of (JobManager instance, process ID) or (None, -1) on failure.
        """
        try:
            job_manager = self.get_job_manager()
            pid = job_manager.spawn_paused(package_name)

            # Update SpotlightService if available
            spotlight = self._spotlight
            if spotlight:
                spotlight.set_spawn_app(package_name, auto_resume=False)

            self._logger.info(f"Spawned {package_name} (PID {pid}) in paused state")
            self._publish_spawn_event(package_name, pid)
            return job_manager, pid

        except Exception as e:
            self._logger.error(f"Failed to spawn {package_name} paused: {e}")
            return None, -1

    def resume_app(self) -> bool:
        """Resume a paused app after tools have been loaded.

        Returns:
            True if app was resumed successfully.
        """
        with self._lock:
            if self._job_manager is None:
                self._logger.warning("No JobManager available to resume app")
                return False

        try:
            result = self._job_manager.resume_app()

            if result:
                spotlight = self._spotlight
                if spotlight:
                    spotlight.set_auto_resume(True)
                    package = spotlight.get_spawn_package()
                    self._logger.info(f"Resumed app {package}")

            return result

        except Exception as e:
            self._logger.error(f"Failed to resume app: {e}")
            return False

    def get_spawn_mode(self) -> str:
        """Get the current spawn mode setting.

        Returns:
            One of: 'multi_tool', 'single_tool', 'late_attach'
        """
        spotlight = self._spotlight
        if spotlight is None:
            return "single_tool"

        is_spawn = spotlight.is_spawn_mode()
        auto_resume = spotlight.get_auto_resume()

        if is_spawn and not auto_resume:
            return "multi_tool"
        if is_spawn:
            return "single_tool"
        return "late_attach"

    def set_spawn_mode(self, mode) -> None:
        """Set the spawn mode for the next Frida operation.

        Args:
            mode: Either a boolean (True=spawn, False=attach) or one of:
                - 'multi_tool': Spawn paused, load multiple tools, then resume
                - 'single_tool': Spawn with one primary tool, auto-resume
                - 'late_attach' or 'attach': Attach to running app
        """
        spotlight = self._spotlight
        if spotlight is None:
            self._logger.warning("SpotlightService not available")
            return

        # Handle boolean for backward compatibility
        if isinstance(mode, bool):
            spotlight.set_spawn_mode(mode)
            spotlight.set_auto_resume(True)
            mode_str = "SPAWN" if mode else "ATTACH"
            self._logger.debug(f"Spawn mode set to: {mode_str}")
            return

        # Handle string modes
        if mode == "multi_tool":
            spotlight.set_spawn_mode(True)
            spotlight.set_auto_resume(False)
        elif mode == "single_tool":
            spotlight.set_spawn_mode(True)
            spotlight.set_auto_resume(True)
        elif mode in ("late_attach", "attach"):
            spotlight.set_spawn_mode(False)
            spotlight.set_auto_resume(True)
        else:
            self._logger.warning(f"Unknown spawn mode: {mode}, using single_tool")
            spotlight.set_spawn_mode(True)
            spotlight.set_auto_resume(True)

    # =========================================================================
    # Session Management
    # =========================================================================

    def reset_session(self) -> None:
        """Reset the Frida session state.

        Stops all jobs, clears hook registry, and resets session state.
        """
        with self._lock:
            if self._job_manager is not None:
                try:
                    self._job_manager.reset_session()
                    self._logger.info("Frida session reset")
                except Exception as e:
                    self._logger.error(f"Failed to reset session: {e}")

    def reset(self) -> None:
        """Reset the service state (useful for testing)."""
        with self._lock:
            self._job_manager = None
            self._frida_manager = None
            self._device_serial = None
            self._frida_job_manager_ref = None
            self._malware_monitor_running = False

    def get_state_dict(self) -> dict[str, Any]:
        """Get service state as a dictionary for debugging/API.

        Returns:
            Dictionary with service state.
        """
        with self._lock:
            return {
                "has_job_manager": self._job_manager is not None,
                "has_frida_manager": self._frida_manager is not None,
                "device_serial": self._device_serial,
                "frida_job_manager_set": self._frida_job_manager_ref is not None,
                "malware_monitor_running": self._malware_monitor_running,
            }

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _get_device_serial_from_manager(self) -> str | None:
        """Get device serial from DeviceManager if available.

        Returns:
            Device serial string or None if DeviceManager not ready.
        """
        try:
            from sandroid.core.toolbox import Toolbox

            dm = Toolbox.get_device_manager()
            if dm and dm.active_device:
                return dm.active_device.serial
        except Exception:
            pass  # DeviceManager not ready yet
        return None

    def _publish_spawn_event(self, package: str, pid: int) -> None:
        """Publish spawn event."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={
                    "action": "app_spawned",
                    "package": package,
                    "pid": pid,
                },
                source="frida_session_service",
            )
        )


# Exports
__all__ = [
    "FridaJobInfo",
    "FridaSessionService",
]
