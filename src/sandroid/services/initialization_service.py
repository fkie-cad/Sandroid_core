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
import datetime
import logging
import os
import re
import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
    """

    session_path: Path
    device_path: Path | None = None
    raw_path: Path | None = None
    log_file: Path | None = None
    error_log_file: Path | None = None
    timestamp: str = ""

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


@dataclass
class FolderStructure:
    """Configuration for folder structure creation.

    Attributes:
        raw_folders: Folders to create under raw/
        result_folders: Folders to create at device level
        tool_folders: Tool-specific folders
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
        base_path: str | Path = "results",
        folder_structure: FolderStructure | None = None,
        event_bus: EventBusProtocol | None = None,
    ):
        """Initialize InitializationService.

        Args:
            base_path: Base directory for results (default: "results").
            folder_structure: Custom folder structure configuration.
            event_bus: Optional event bus for state change notifications.
        """
        self._event_bus = event_bus
        self._logger = logger
        self._lock = threading.RLock()
        self._base_path = Path(base_path)
        self._folder_structure = folder_structure or FolderStructure()
        self._current_session: SessionPaths | None = None
        self._file_handler: logging.FileHandler | None = None
        self._error_handler: logging.FileHandler | None = None

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
        with self._lock:
            # Generate timestamp
            if timestamp is None:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

            # Create session path
            session_path = self._base_path / timestamp
            session_path.mkdir(parents=True, exist_ok=True)

            # Create session paths object
            log_file = session_path / "sandroid.log"
            error_log_file = session_path / "sandroid_error.log"
            paths = SessionPaths(
                session_path=session_path,
                log_file=log_file,
                error_log_file=error_log_file,
                timestamp=timestamp,
            )

            # Update environment variables for backwards compatibility
            os.environ["SESSION_PATH"] = str(session_path) + "/"
            os.environ["RESULTS_PATH"] = str(session_path) + "/"
            os.environ["RAW_RESULTS_PATH"] = str(session_path) + "/raw/"

            # Set up file logging if requested
            if setup_logging:
                self.setup_file_logging(log_file)
                self.setup_error_logging(error_log_file)

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

            # Create raw subfolders
            for folder in self._folder_structure.raw_folders:
                folder_path = raw_path / folder
                if clean_existing and folder_path.is_dir():
                    shutil.rmtree(folder_path)
                folder_path.mkdir(parents=True, exist_ok=True)

            # Create result subfolders
            for folder in self._folder_structure.result_folders:
                folder_path = device_path / folder
                if clean_existing and folder_path.is_dir():
                    shutil.rmtree(folder_path)
                folder_path.mkdir(parents=True, exist_ok=True)

            # Create tool-specific folders (don't clean these)
            for folder in self._folder_structure.tool_folders:
                folder_path = device_path / folder
                folder_path.mkdir(parents=True, exist_ok=True)

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
        with self._lock:
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

            self._current_session = None
            self._logger.debug("Initialization service reset")

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
        with self._lock:
            # Step 1: Create session (or reuse existing one)
            # A session may already exist if auto_select_device() was called
            # during device discovery, which triggers switch_device_folder()
            # and sets up the device path. Creating a new session here would
            # reset device_path to None and cause tools like FriTap to write
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
            screenshot=0,
            trigdroid=None,
            trigdroid_ccf=None,
            hash=False,
            apk=False,
            degrade_network=False,
            whitelist=None,
            iterative=False,
            report=True,
            ai=False,
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
                "Hint: Start an AVD with 'sandroid-config avd start' "
                "or connect a physical device via USB."
            )
            return None

    def get_argument_parser(self) -> argparse.ArgumentParser:
        """Get the standard Sandroid argument parser.

        This returns a configured ArgumentParser with all standard Sandroid
        options. Useful for CLI tools or testing.

        Returns:
            Configured ArgumentParser.
        """
        parser = argparse.ArgumentParser(
            description="Find forensic artefacts for any action on an AVD"
        )
        parser.add_argument(
            "-f",
            "--file",
            type=str,
            metavar="FILENAME",
            help="Save output to the specified file, default is sandroid.json",
            default=f"{os.getenv('RESULTS_PATH', 'results/')}sandroid.json",
        )
        parser.add_argument(
            "-ll",
            "--loglevel",
            type=str,
            metavar="LOGLEVEL",
            help="Set the log level. The logging file sandroid.log will always contain an expanded DEBUG level log.",
            default="INFO",
        )
        parser.add_argument(
            "-n",
            "--number_of_runs",
            type=int,
            metavar="NUMBER",
            help="Run action n times (Minimum and default is 2)",
            default=2,
        )
        parser.add_argument(
            "--avoid_strong_noise_filter",
            action="store_true",
            help='Don\'t use a "Dry Run". This will catch more noise and disable intra file noise detection.',
        )
        parser.add_argument(
            "--network",
            action="store_true",
            help="Capture traffic and show connections. Connections are not necessarily in chronological order. Each connection will only show up once, even if it was made multiple times. For better results, it is recommended to use at least -n 3 and to leave the strong noise filter on",
        )
        parser.add_argument(
            "-d",
            "--show_deleted",
            action="store_true",
            help="Perform additional full filesystem checks to reveal deleted files",
        )
        parser.add_argument(
            "--no-processes",
            action="store_false",
            dest="processes",
            help="Do not monitor active processes during the action",
        )
        parser.add_argument(
            "--sockets",
            action="store_true",
            dest="sockets",
            help="Monitor listening sockets during the action",
        )
        parser.add_argument(
            "--screenshot",
            type=int,
            metavar="INTERVAL",
            help="Take a screenshot each INTERVAL seconds",
            default=0,
        )
        parser.add_argument(
            "--trigdroid",
            type=str,
            metavar="PACKAGE NAME",
            help="Use the TrigDroid(tm) tool to execute malware triggers in package PACKAGE NAME",
        )
        parser.add_argument(
            "--trigdroid_ccf",
            type=str,
            metavar="{I,D}",
            help="Use the TrigDroid(tm) CCF utility to create a Trigdroid config file. I for interactive mode, D to create the default config file",
        )
        parser.add_argument(
            "--hash",
            action="store_true",
            help="Create before/after md5 hashes of all changed and new files and save them to hashes.json",
        )
        parser.add_argument(
            "--apk",
            action="store_true",
            help="List all APKs from the emulator and their hashes in the output file",
        )
        parser.add_argument(
            "--degrade_network",
            action="store_true",
            help="Lower the emulators network speed and network latency to simulate and 'UMTS/3G' connection. For more fine grained control, use the emulator console",
        )
        parser.add_argument(
            "--whitelist",
            type=str,
            metavar="FILE",
            help="Entries in the whitelist will be excluded from any outputs. Separate paths by commas, wildcards are supported",
        )
        parser.add_argument(
            "--iterative",
            action="store_true",
            help="Enable iterative analysis of new apk files",
        )
        parser.add_argument(
            "--report",
            action="store_true",
            default=True,
            help="Enable generation of a report file(pdf)",
        )
        parser.add_argument(
            "--ai",
            action="store_true",
            default=False,
            help="Use AI to summarize the action and generate a report",
        )
        parser.add_argument(
            "--debug",
            action="store_true",
            default=False,
            help="Enable debug/verbose mode (shows detailed hook installation and internal messages from dexray-intercept)",
        )
        return parser

    def parse_arguments(self, argv: list[str] | None = None) -> argparse.Namespace:
        """Parse command-line arguments.

        Args:
            argv: Command-line arguments to parse. If None, uses sys.argv.

        Returns:
            Parsed argument namespace.
        """
        parser = self.get_argument_parser()
        return parser.parse_args(argv)


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
