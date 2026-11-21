"""Initialization Service for Sandroid.

This service orchestrates application startup without CLI coupling,
managing session creation, folder structure, and logging setup.

Extracted from Toolbox class to follow Single Responsibility Principle.

Usage:
    from sandroid.services import get_initialization_service
    from sandroid.services.initialization_service import InitializationService

    # Get service
    init_service = get_initialization_service()

    # Create a session
    session = init_service.create_session()

    # Create device folder structure
    init_service.create_device_folder("Pixel_6_Pro")

    # Full application initialization (for Toolbox delegation)
    result = init_service.initialize_application(args=parsed_args)
"""

import argparse
import contextlib
import datetime
import logging
import os
import re
import shutil
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from sandroid.services.protocols import EventBusProtocol

# Import config with fallback for standalone usage
try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

logger = logging.getLogger(__name__)


@dataclass
class SessionPaths:
    """Represents the paths for a Sandroid session.

    Attributes:
        session_path: Root path for the session (e.g., results/20251202_180000/)
        device_path: Current device-specific path (None until device selected)
        raw_path: Path for raw data (under device_path)
        log_file: Path to the session log file
        error_log_file: Path to the error-only log file
        timestamp: Session creation timestamp
        created: Whether this process created ``session_path`` (False when
            the folder already existed)
    """

    session_path: Path
    device_path: Path | None = None
    raw_path: Path | None = None
    log_file: Path | None = None
    error_log_file: Path | None = None
    timestamp: str = ""
    created: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "session_path": str(self.session_path),
            "device_path": str(self.device_path) if self.device_path else None,
            "raw_path": str(self.raw_path) if self.raw_path else None,
            "log_file": str(self.log_file) if self.log_file else None,
            "error_log_file": str(self.error_log_file) if self.error_log_file else None,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class SessionChange:
    """One change of the active analysis session (see
    :meth:`InitializationService.on_session_change`).

    Attributes:
        kind: ``"new"`` (a session folder this process created), ``"resume"``
            (an existing session folder was opened again) or ``"closed"``
            (no session any more: ``new_path`` is None). A switch from one
            session to another is a ``new`` / ``resume`` whose ``old_path``
            is set.
        old_id: Folder name of the previous session (``YYYYmmdd_HHMMSS``),
            or None.
        old_path: Absolute folder of the previous session, or None.
        new_id: Folder name of the now active session, or None.
        new_path: Absolute folder of the now active session, or None.
    """

    kind: Literal["new", "resume", "closed"]
    old_id: str | None
    old_path: Path | None
    new_id: str | None
    new_path: Path | None


#: A session-change listener (:meth:`InitializationService.on_session_change`).
SessionChangeListener = Callable[[SessionChange], None]


def _session_key(paths: "SessionPaths | None") -> Path | None:
    if paths is None:
        return None
    return Path(paths.session_path).expanduser().absolute()


@dataclass
class FolderStructure:
    """Configuration for folder structure creation.

    Attributes:
        raw_folders: Folders under raw/ (created by their writers)
        result_folders: Folders at device level (created by their writers)
        tool_folders: Tool-specific folders (created by their writers)
    """

    raw_folders: list[str] = field(
        default_factory=lambda: [
            "first_pull",
            "second_pull",
            "noise_pull",
            "new_pull",
            "network_trace_pull",
            "screenshots",
            "spotlight_files",
        ]
    )
    result_folders: list[str] = field(
        default_factory=lambda: [
            "spotlight_files",
            "forensic_apks",
        ]
    )
    tool_folders: list[str] = field(
        default_factory=lambda: [
            "fritap",
            "dexray_insight",
        ]
    )


class InitializationService:
    """Service for orchestrating application startup.

    This service manages:
    - Session folder creation with timestamps
    - Device-specific folder structure
    - File logging setup
    - Environment variable management

    Thread Safety:
        This service is thread-safe. All operations are protected by locks.

    Example:
        # Basic usage
        service = InitializationService()

        # Create a new session
        paths = service.create_session()
        print(f"Session created at: {paths.session_path}")

        # Create device folder when device is selected
        device_path = service.create_device_folder("Pixel_6_Pro")
        print(f"Device folder at: {device_path}")
    """

    def __init__(
        self,
        base_path: str | Path | None = None,
        folder_structure: FolderStructure | None = None,
        event_bus: EventBusProtocol | None = None,
    ):
        """Initialize InitializationService.

        Args:
            base_path: Base directory for results. Default (None): the
                configured ``paths.results_path`` (resolved when a session is
                created), falling back to ``./results``. Session folders and
                run bundles (``<results_path>/runs/``) thus share one root.
            folder_structure: Custom folder structure configuration.
            event_bus: Optional event bus for state change notifications.
        """
        self._event_bus = event_bus
        self._logger = logger
        self._lock = threading.RLock()
        self._explicit_base_path = base_path is not None
        self._base_path = Path(base_path) if base_path is not None else Path("results")
        self._folder_structure = folder_structure or FolderStructure()
        self._current_session: SessionPaths | None = None
        self._file_handler: logging.FileHandler | None = None
        self._error_handler: logging.FileHandler | None = None
        # Session-change signal: listeners, the changes recorded under
        # ``_lock`` and the lock's nesting depth (only touched while holding
        # ``_lock``), so listeners run after the OUTERMOST release.
        self._listeners: list[SessionChangeListener] = []
        self._listeners_lock = threading.Lock()
        self._pending_changes: list[SessionChange] = []
        self._lock_depth = 0

    @staticmethod
    def _configured_results_root() -> Path:
        """Return the absolute configured results root (``paths.results_path``).

        Prefers the config the CLI loaded (``Toolbox.config``), then the
        ``get_config()`` singleton, then ``./results``.
        """
        configured = None
        try:
            from sandroid.core.toolbox import Toolbox

            cfg = getattr(Toolbox, "config", None)
            if cfg is None:
                from sandroid.config import get_config

                cfg = get_config()
            configured = cfg.paths.results_path
        except Exception as e:  # config unavailable -> default below
            logger.debug(f"Configured results_path unavailable: {e}")
        return Path(configured or "results").expanduser().resolve()

    # ------------------------------------------------------------------
    # Session-change signal
    # ------------------------------------------------------------------

    def on_session_change(self, callback: SessionChangeListener) -> Callable[[], None]:
        """Call ``callback(change)`` whenever the active analysis session
        changes; returns a function that unsubscribes it (idempotent).

        Fires once per real change -- a new session, a resumed (existing)
        session folder, a switch from one session to another, or the
        session closing (:meth:`reset`) -- never when the same session folder
        is selected again. ``change`` is a :class:`SessionChange` with the
        old and new session id (folder name) and absolute folder.

        Thread: the callback runs synchronously on the thread that changed
        the session (at startup the main thread, later possibly a worker),
        after this service's lock is released; it may call back into the
        service. It must not block on the UI thread (marshal UI work with
        ``call_from_thread`` / ``call_later`` yourself) and should be quick.
        A raising callback is logged and does not stop the others.
        Listeners are kept per service instance.

        Subscribing does not replay the current session: read
        :meth:`get_current_session` right after subscribing (the startup
        ``new`` usually fires before UI code subscribes). ``closed`` also
        fires from :meth:`cleanup` at shutdown. Changes from two threads at
        once may arrive out of order; compare with
        :meth:`get_current_session` when it matters. Every way to start or
        resume a session (a future New / Resume UI) must go through
        :meth:`create_session` (``timestamp=`` the folder name) so it fires.
        """
        with self._listeners_lock:
            self._listeners.append(callback)

        def unsubscribe() -> None:
            with self._listeners_lock, contextlib.suppress(ValueError):
                self._listeners.remove(callback)

        return unsubscribe

    @contextlib.contextmanager
    def _changing(self) -> Iterator[None]:
        """``self._lock``, plus: the session changes recorded inside go to the
        listeners once the outermost holder released the lock.
        """
        pending: list[SessionChange] = []
        try:
            with self._lock:
                self._lock_depth += 1
                try:
                    yield
                finally:
                    self._lock_depth -= 1
                    if self._lock_depth == 0:
                        pending, self._pending_changes = self._pending_changes, []
        finally:
            for change in pending:
                self._fire(change)

    def _record_change(
        self, old: "SessionPaths | None", new: "SessionPaths | None"
    ) -> None:
        """Note the switch ``old`` -> ``new`` (caller holds ``_lock``); the
        same folder again is no change.
        """
        old_path, new_path = _session_key(old), _session_key(new)
        if old_path == new_path:
            return
        if new is None:
            kind = "closed"
        else:
            kind = "new" if new.created else "resume"
        self._pending_changes.append(
            SessionChange(
                kind=kind,
                old_id=old_path.name if old_path else None,
                old_path=old_path,
                new_id=new_path.name if new_path else None,
                new_path=new_path,
            )
        )

    def _fire(self, change: SessionChange) -> None:
        with self._listeners_lock:
            listeners = list(self._listeners)
        for callback in listeners:
            try:
                callback(change)
            except Exception:
                self._logger.warning("Session change listener failed", exc_info=True)

    def create_session(
        self,
        timestamp: str | None = None,
        setup_logging: bool = True,
    ) -> SessionPaths:
        """Create a new session with timestamped folder.

        Creates a session folder structure:
            results/YYYYMMDD_HHMMSS/
            ├── sandroid.log
            └── sandroid_error.log

        Args:
            timestamp: Optional custom timestamp (default: current time).
            setup_logging: Whether to set up file logging (default: True).

        Returns:
            SessionPaths instance with created paths.
        """
        with self._changing():
            # Generate timestamp
            if timestamp is None:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

            # Create session path (under the configured results_path)
            if not self._explicit_base_path:
                self._base_path = self._configured_results_root()
            session_path = self._base_path / timestamp
            existed = session_path.exists()
            session_path.mkdir(parents=True, exist_ok=True)

            # Create session paths object
            log_file = session_path / "sandroid.log"
            error_log_file = session_path / "sandroid_error.log"
            paths = SessionPaths(
                session_path=session_path,
                log_file=log_file,
                error_log_file=error_log_file,
                timestamp=timestamp,
                created=not existed,
            )

            # Update environment variables for backwards compatibility
            os.environ["SESSION_PATH"] = str(session_path) + "/"
            os.environ["RESULTS_PATH"] = str(session_path) + "/"
            os.environ["RAW_RESULTS_PATH"] = str(session_path) + "/raw/"

            # Set up file logging if requested
            if setup_logging:
                self.setup_file_logging(log_file)
                self.setup_error_logging(error_log_file)

            self._record_change(self._current_session, paths)
            self._current_session = paths
            self._logger.debug(f"Session initialized: {session_path}")

            return paths

    def setup_file_logging(
        self,
        log_file_path: str | Path,
        log_level: int = logging.DEBUG,
        log_format: str | None = None,
    ) -> logging.FileHandler:
        """Set up file logging to the specified path.

        This adds a file handler to the root logger so all logs go to the file.

        Args:
            log_file_path: Path to log file.
            log_level: Logging level for the file handler.
            log_format: Custom log format string.

        Returns:
            The created FileHandler.
        """
        with self._lock:
            root_logger = logging.getLogger()

            # Remove any existing file handlers to avoid duplicates
            for handler in root_logger.handlers[:]:
                if isinstance(handler, logging.FileHandler):
                    handler.close()
                    root_logger.removeHandler(handler)

            # Create new file handler
            log_path = Path(log_file_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(str(log_path))
            file_handler.setLevel(log_level)

            # Set format
            if log_format is None:
                log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            formatter = logging.Formatter(log_format)
            file_handler.setFormatter(formatter)

            root_logger.addHandler(file_handler)
            self._file_handler = file_handler

            self._logger.debug(f"File logging set up: {log_path}")
            return file_handler

    def setup_error_logging(
        self,
        log_file_path: str | Path,
    ) -> logging.FileHandler:
        """Set up error-only file logging.

        This adds a file handler that only captures WARNING and above.

        Args:
            log_file_path: Path to error log file.

        Returns:
            The created FileHandler.
        """
        log_path = Path(log_file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        error_handler = logging.FileHandler(str(log_path))
        error_handler.setLevel(logging.WARNING)  # Only WARNING and ERROR

        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        formatter = logging.Formatter(log_format)
        error_handler.setFormatter(formatter)

        root_logger = logging.getLogger()
        root_logger.addHandler(error_handler)
        self._error_handler = error_handler

        self._logger.debug(f"Error logging set up: {log_path}")
        return error_handler

    def create_device_folder(
        self,
        device_name: str,
        clean_existing: bool = True,
    ) -> Path:
        """Create device-specific folder structure.

        Creates the standard folder structure for a device:
            <session>/device_name/
            ├── raw/
            │   ├── first_pull/
            │   ├── second_pull/
            │   └── ...
            ├── spotlight_files/
            ├── forensic_apks/
            ├── fritap/
            └── dexray_insight/

        Args:
            device_name: Device name (will be sanitized for filesystem).
            clean_existing: Whether to remove existing folders (default: True).

        Returns:
            Path to the device folder.

        Raises:
            RuntimeError: If no session has been created.
        """
        with self._lock:
            if self._current_session is None:
                raise RuntimeError("No session created. Call create_session() first.")

            # Sanitize device name for filesystem
            safe_name = self._sanitize_name(device_name)

            # Create device path
            device_path = self._current_session.session_path / safe_name
            raw_path = device_path / "raw"

            # Only the device and raw folders: the subfolders are created by
            # whatever writes into them (no empty folders in every session).
            raw_path.mkdir(parents=True, exist_ok=True)
            if clean_existing:
                for parent, folders in (
                    (raw_path, self._folder_structure.raw_folders),
                    (device_path, self._folder_structure.result_folders),
                ):
                    for folder in folders:
                        if (parent / folder).is_dir():
                            shutil.rmtree(parent / folder)

            # Update session paths
            self._current_session.device_path = device_path
            self._current_session.raw_path = raw_path

            # Update environment variables for backwards compatibility
            os.environ["RESULTS_PATH"] = os.path.join(str(device_path), "")
            os.environ["RAW_RESULTS_PATH"] = os.path.join(str(raw_path), "")

            self._logger.info(f"Created device folder: {device_path}")
            return device_path

    def switch_device(self, device_name: str) -> Path:
        """Switch to a device-specific folder.

        Creates the folder structure if it doesn't exist.

        Args:
            device_name: Device name to switch to.

        Returns:
            Path to the device folder.

        Raises:
            RuntimeError: If no session has been created.
        """
        return self.create_device_folder(device_name, clean_existing=False)

    def get_session_path(self) -> Path | None:
        """Get the current session root path.

        Returns:
            Path to session folder or None if no session.
        """
        with self._lock:
            if self._current_session:
                return self._current_session.session_path
            return None

    def get_device_path(self) -> Path | None:
        """Get the current device folder path.

        Returns:
            Path to device folder or None if no device selected.
        """
        with self._lock:
            if self._current_session:
                return self._current_session.device_path
            return None

    def get_raw_path(self) -> Path | None:
        """Get the current raw data path.

        Returns:
            Path to raw folder or None if no device selected.
        """
        with self._lock:
            if self._current_session:
                return self._current_session.raw_path
            return None

    def get_current_session(self) -> SessionPaths | None:
        """Get the current session information.

        Returns:
            SessionPaths instance or None if no session.
        """
        with self._lock:
            return self._current_session

    def get_subfolder_path(
        self,
        subfolder: str,
        create: bool = True,
    ) -> Path | None:
        """Get path to a subfolder in the current device folder.

        Args:
            subfolder: Name of the subfolder (e.g., "screenshots").
            create: Whether to create the folder if it doesn't exist.

        Returns:
            Path to the subfolder or None if no device selected.
        """
        with self._lock:
            if not self._current_session or not self._current_session.device_path:
                return None

            # Check if it's a raw subfolder
            if subfolder in self._folder_structure.raw_folders:
                folder_path = self._current_session.raw_path / subfolder
            else:
                folder_path = self._current_session.device_path / subfolder

            if create and not folder_path.exists():
                folder_path.mkdir(parents=True, exist_ok=True)

            return folder_path

    def get_state_dict(self) -> dict[str, Any]:
        """Get service state as a dictionary.

        Useful for API responses and debugging.

        Returns:
            Dictionary with service state.
        """
        with self._lock:
            return {
                "has_session": self._current_session is not None,
                "session": (
                    self._current_session.to_dict() if self._current_session else None
                ),
                "base_path": str(self._base_path),
                "folder_structure": {
                    "raw_folders": self._folder_structure.raw_folders,
                    "result_folders": self._folder_structure.result_folders,
                    "tool_folders": self._folder_structure.tool_folders,
                },
            }

    def reset(self) -> None:
        """Reset service state.

        Clears the current session. Does NOT delete folders.
        """
        with self._changing():
            root_logger = logging.getLogger()

            # Close file handler if open
            if self._file_handler:
                self._file_handler.close()
                if self._file_handler in root_logger.handlers:
                    root_logger.removeHandler(self._file_handler)
                self._file_handler = None

            # Close error handler if open
            if self._error_handler:
                self._error_handler.close()
                if self._error_handler in root_logger.handlers:
                    root_logger.removeHandler(self._error_handler)
                self._error_handler = None

            self._record_change(self._current_session, None)
            self._current_session = None
            self._logger.debug("Initialization service reset")

    def discard_unused_session(self) -> bool:
        """Remove this run's session folder if the run never used it.

        For a start that never got going (the TUI quit from its startup error
        screen): the folder is removed only if this process created it and it
        holds nothing but the session's own ``sandroid.log`` /
        ``sandroid_error.log`` -- no device folder, no results, nothing else.
        The file log handlers are closed first. Anything else is left alone.

        Returns:
            True if the folder was removed.
        """
        with self._changing():
            paths = self._current_session
            if paths is None or not paths.created:
                return False
            folder = paths.session_path
            own_logs = {p.name for p in (paths.log_file, paths.error_log_file) if p}
            try:
                entries = list(folder.iterdir())
            except OSError:
                return False
            for entry in entries:
                if entry.name not in own_logs or not entry.is_file():
                    return False
            self.reset()  # closes and detaches the file log handlers
            try:
                for entry in entries:
                    entry.unlink(missing_ok=True)
                folder.rmdir()
            except OSError as e:
                logger.debug(f"Could not remove unused session folder {folder}: {e}")
                return False
            return True

    def cleanup(self) -> None:
        """Clean up resources.

        Should be called when shutting down to ensure proper cleanup.
        """
        self.reset()

    @staticmethod
    def _sanitize_name(name: str) -> str:
        """Sanitize a name for filesystem safety.

        Replaces non-alphanumeric chars (except - and _) with _.

        Args:
            name: Name to sanitize.

        Returns:
            Sanitized name.
        """
        return re.sub(r"[^\w\-]", "_", name)

    # ==================== Application-Level Initialization ====================

    @staticmethod
    def _get_frida_install_dir(default: str = "/data/local/tmp/") -> str:
        """Read Frida install directory from config with fallback.

        Args:
            default: Fallback value if config unavailable.

        Returns:
            The configured Frida install directory.
        """
        try:
            if get_config is not None:
                return get_config().device_paths.frida_install_dir
        except Exception:
            pass
        return default

    @staticmethod
    def _get_scan_directories(
        default: list[str] | None = None,
    ) -> list[str]:
        """Read scan directories from config with fallback.

        Args:
            default: Fallback value if config unavailable.

        Returns:
            List of directories to scan.
        """
        if default is None:
            default = ["/data", "/storage", "/sdcard"]
        try:
            if get_config is not None:
                return list(get_config().device_paths.scan_directories)
        except Exception:
            pass
        return default

    def initialize_application(
        self,
        args: argparse.Namespace | None = None,
        device_serial: str | None = None,
        frida_install_dst: str = "/data/local/tmp/",
        scan_directories: list[str] | None = None,
    ) -> "InitializationResult":
        """Initialize the full Sandroid application.

        This method coordinates the complete application startup:
        1. Creates session folder structure
        2. Sets up file logging
        3. Creates argument namespace if not provided
        4. Initializes logger with appropriate level
        5. Creates FridaManager instance
        6. Sets scan directories

        This method is designed to be called from Toolbox.init() for delegation
        while maintaining backwards compatibility.

        Args:
            args: Pre-parsed argument namespace (from CLI or test). If None,
                  a default namespace is created.
            device_serial: Device serial for FridaManager. If None, auto-select.
            frida_install_dst: Destination path for Frida server on device.
            scan_directories: Directories to scan for forensic analysis.
                             Defaults to ["/data", "/storage", "/sdcard"].

        Returns:
            InitializationResult with all initialized components.

        Example:
            service = InitializationService()
            result = service.initialize_application(args=parsed_args)

            # Use results to set Toolbox class variables
            Toolbox.args = result.args
            Toolbox.logger = result.logger
            Toolbox.frida_manager = result.frida_manager
            Toolbox.scan_directories = result.scan_directories
        """
        with self._changing():
            # Step 1: Create session (or reuse existing one)
            # A session may already exist if auto_select_device() was called
            # during device discovery, which triggers switch_device_folder()
            # and sets up the device path. Creating a new session here would
            # reset device_path to None and cause tools like friTap to write
            # results to the session root instead of the device directory.
            if self._current_session is not None:
                session_paths = self._current_session
                # Ensure logging is set up even when reusing session
                if not self._file_handler:
                    if session_paths.log_file:
                        self.setup_file_logging(session_paths.log_file)
                    if session_paths.error_log_file:
                        self.setup_error_logging(session_paths.error_log_file)
                self._logger.debug(
                    "Reusing existing session (device_path=%s)",
                    session_paths.device_path,
                )
            else:
                session_paths = self.create_session(setup_logging=True)

            # Step 2: Create or use provided args
            if args is None:
                args = self._create_default_args()

            # Step 3: Initialize logger with appropriate level
            app_logger = self._initialize_app_logger(args)

            # Step 4: Create FridaManager (use config-driven install dir)
            effective_frida_dst = self._get_frida_install_dir(frida_install_dst)
            frida_manager = self._create_frida_manager(
                device_serial=device_serial,
                frida_install_dst=effective_frida_dst,
            )

            # Step 5: Set scan directories (use config-driven directories)
            if scan_directories is None:
                scan_directories = self._get_scan_directories()

            # Share FridaManager with FridaSessionService to avoid duplicate instantiation
            if frida_manager is not None:
                try:
                    from sandroid.services import get_frida_session_service

                    get_frida_session_service().set_frida_manager(frida_manager)
                except (ImportError, AttributeError) as e:
                    self._logger.debug(
                        f"Could not share FridaManager with FridaSessionService: {e}"
                    )

            self._logger.info("Application initialization complete")

            return InitializationResult(
                session_paths=session_paths,
                args=args,
                logger=app_logger,
                frida_manager=frida_manager,
                scan_directories=scan_directories,
            )

    def _create_default_args(self) -> argparse.Namespace:
        """Create default argument namespace for non-CLI usage.

        Returns:
            argparse.Namespace with default values matching CLI defaults.
        """
        session_path = os.environ.get("RESULTS_PATH", "results/")
        return argparse.Namespace(
            file=f"{session_path}sandroid.json",
            loglevel="INFO",
            number_of_runs=2,
            avoid_strong_noise_filter=False,
            network=False,
            show_deleted=False,
            processes=True,
            sockets=False,
            hash=False,
            apk=False,
            degrade_network=False,
            whitelist=None,
            iterative=False,
            report=True,
            debug=False,
        )

    def _initialize_app_logger(
        self,
        args: argparse.Namespace,
    ) -> logging.Logger:
        """Initialize and return an application logger.

        Args:
            args: Argument namespace with loglevel attribute.

        Returns:
            Configured Logger instance.
        """
        app_logger = logging.getLogger("sandroid.core.toolbox")

        # Set log level from args
        log_level = getattr(args, "loglevel", "INFO")
        if isinstance(log_level, str):
            log_level = getattr(logging, log_level.upper(), logging.INFO)
        app_logger.setLevel(log_level)

        return app_logger

    def _create_frida_manager(
        self,
        device_serial: str | None = None,
        frida_install_dst: str = "/data/local/tmp/",
    ) -> Any:
        """Create and return a FridaManager instance.

        Args:
            device_serial: Device serial to use. If None, auto-select.
            frida_install_dst: Destination path for Frida server on device.

        Returns:
            FridaManager instance, or None if import fails.
        """
        try:
            from AndroidFridaManager import FridaManager

            from sandroid.core.frida_manager import install_zygote_pid_fix

            install_zygote_pid_fix()
            return FridaManager(
                verbose=True,
                frida_install_dst=frida_install_dst,
                device_serial=device_serial,
            )
        except ImportError:
            self._logger.warning(
                "AndroidFridaManager not available. FridaManager will be None."
            )
            return None
        except RuntimeError as e:
            self._logger.error(
                f"{e}\n"
                "Hint: Start an AVD in the Devices screen (press D) or with "
                "'sandroid --avd NAME', "
                "or connect a physical device via USB."
            )
            return None


@dataclass
class InitializationResult:
    """Result of application initialization.

    Contains all components initialized by initialize_application()
    for use by the calling code (e.g., Toolbox class variables).

    Attributes:
        session_paths: Session folder structure paths
        args: Parsed argument namespace
        logger: Configured logger instance
        frida_manager: FridaManager instance (may be None if import failed)
        scan_directories: List of directories to scan for forensic analysis
    """

    session_paths: SessionPaths
    args: argparse.Namespace
    logger: logging.Logger
    frida_manager: Any  # FridaManager type not available at import time
    scan_directories: list[str]


__all__ = [
    "FolderStructure",
    "InitializationResult",
    "InitializationService",
    "SessionPaths",
]
