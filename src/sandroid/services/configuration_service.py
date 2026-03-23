"""Configuration Service for Sandroid.

This service manages application configuration, session setup, and path management.
Extracted from Toolbox class to follow Single Responsibility Principle.

Usage:
    from sandroid.services import get_configuration_service
    from sandroid.services.configuration_service import ConfigurationService

    # Using service locator
    config_service = get_configuration_service()

    # Or with dependency injection (for testing)
    config_service = ConfigurationService()
    config_service.initialize(args)

    # Get paths
    session_path = config_service.get_session_path()
    results_path = config_service.get_results_path()
"""

import argparse
import datetime
import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any

from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)


@dataclass
class SessionConfig:
    """Configuration for a Sandroid analysis session.

    Attributes:
        session_path: Root path for session data (e.g., results/YYYYMMDD_HHMMSS/)
        results_path: Path for device-specific results
        raw_results_path: Path for raw analysis data
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        output_file: Path to output JSON file
        device_name: Name of the target device/emulator
        timestamp: Session start timestamp
    """

    session_path: str
    results_path: str
    raw_results_path: str
    log_level: str = "INFO"
    output_file: str = "sandroid.json"
    device_name: str | None = None
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)


class ConfigurationService:
    """Service for managing application configuration and session setup.

    This service handles:
    - Session folder creation and management
    - Path configuration (results, raw, screenshots, etc.)
    - Logging setup
    - Configuration state tracking

    Thread Safety:
        All operations are thread-safe through internal locking.

    Example:
        service = ConfigurationService()

        # Initialize a new session
        service.initialize_session()

        # Get paths
        results = service.get_results_path()
        raw = service.get_raw_results_path()

        # Switch device context
        service.switch_device("Pixel_6_Pro_API_31")
    """

    # Standard folder structure for device-specific results
    FOLDERS_FOR_RAW = [
        "first_pull",
        "second_pull",
        "noise_pull",
        "new_pull",
        "network_trace_pull",
        "screenshots",
        "spotlight_files",
    ]
    FOLDERS_FOR_RESULT = ["spotlight_files", "forensic_apks"]
    TOOL_FOLDERS = ["fritap", "dexray_insight"]

    def __init__(self, event_bus: EventBusProtocol | None = None):
        """Initialize the ConfigurationService.

        Args:
            event_bus: Optional EventBus for publishing configuration events.
                      If not provided, events will not be published.
        """
        self._lock = threading.Lock()
        self._event_bus = event_bus
        self._logger = logger

        # Session state
        self._session_config: SessionConfig | None = None
        self._initialized = False
        self._args: argparse.Namespace | None = None

        # Default paths (can be overridden by environment)
        self._default_device_name = "Pixel_6_Pro_API_31"
        self._default_emulator_path = ""

    def initialize_session(
        self, args: argparse.Namespace | None = None
    ) -> SessionConfig:
        """Initialize a new analysis session with timestamped folder structure.

        Creates the session folder hierarchy:
            results/YYYYMMDD_HHMMSS/
            ├── sandroid.log
            ├── sandroid.json
            └── <device_name>/  (created by switch_device)
                ├── raw/
                └── ...

        Args:
            args: Optional parsed command-line arguments

        Returns:
            SessionConfig with paths and settings
        """
        with self._lock:
            if self._initialized:
                self._logger.debug(
                    "Session already initialized, returning existing config"
                )
                return self._session_config

            self._args = args

            # Create session folder with timestamp
            session_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            session_path = f"results/{session_timestamp}/"

            # Create session folder
            os.makedirs(session_path, exist_ok=True)

            # Set environment variables for backwards compatibility
            os.environ["SESSION_PATH"] = session_path
            os.environ["RESULTS_PATH"] = session_path
            os.environ["RAW_RESULTS_PATH"] = f"{session_path}raw/"

            # Determine log level and output file
            log_level = "INFO"
            output_file = f"{session_path}sandroid.json"

            if args:
                log_level = getattr(args, "loglevel", "INFO")
                if hasattr(args, "file") and args.file:
                    output_file = args.file

            # Create session config
            self._session_config = SessionConfig(
                session_path=session_path,
                results_path=session_path,
                raw_results_path=f"{session_path}raw/",
                log_level=log_level,
                output_file=output_file,
                timestamp=datetime.datetime.now(),
            )

            # Set up file logging
            self._setup_file_logging(f"{session_path}sandroid.log")

            self._initialized = True
            self._logger.info(f"Session initialized: {session_path}")

            # Publish event
            self._publish_session_initialized()

            return self._session_config

    def switch_device(self, device_name: str) -> str:
        """Switch to device-specific folder structure.

        Creates device-specific folders under the session:
            results/YYYYMMDD_HHMMSS/device_name/
            ├── raw/
            │   ├── first_pull/
            │   ├── second_pull/
            │   └── ...
            └── ...

        Args:
            device_name: Name of the device (e.g., "Pixel_6_Pro_API_31" or "emulator-5554")

        Returns:
            Path to device results folder
        """
        if not self._initialized:
            self._logger.warning("Session not initialized, initializing now")
            self.initialize_session()

        with self._lock:
            session_path = self._session_config.session_path
            device_path = os.path.join(session_path, device_name)
            raw_path = os.path.join(device_path, "raw")

            # Create folder structure
            os.makedirs(device_path, exist_ok=True)
            os.makedirs(raw_path, exist_ok=True)

            # Create all subfolders: raw subfolders, result subfolders, tool folders
            for parent, folders in [
                (raw_path, self.FOLDERS_FOR_RAW),
                (device_path, self.FOLDERS_FOR_RESULT),
                (device_path, self.TOOL_FOLDERS),
            ]:
                for folder in folders:
                    os.makedirs(os.path.join(parent, folder), exist_ok=True)

            # Update environment variables
            os.environ["RESULTS_PATH"] = os.path.join(device_path, "")
            os.environ["RAW_RESULTS_PATH"] = os.path.join(raw_path, "")

            # Update session config
            self._session_config.results_path = os.path.join(device_path, "")
            self._session_config.raw_results_path = os.path.join(raw_path, "")
            self._session_config.device_name = device_name

            self._logger.info(f"Switched to device folder: {device_path}")

            return device_path

    def get_session_path(self) -> str:
        """Get the root session path.

        Returns:
            Session path (e.g., "results/YYYYMMDD_HHMMSS/")
        """
        if not self._initialized:
            return os.getenv("SESSION_PATH", "results/")
        return self._session_config.session_path

    def get_results_path(self) -> str:
        """Get the current results path (device-specific if switched).

        Returns:
            Results path
        """
        if not self._initialized:
            return os.getenv("RESULTS_PATH", "results/")
        return self._session_config.results_path

    def get_raw_results_path(self) -> str:
        """Get the current raw results path.

        Returns:
            Raw results path
        """
        if not self._initialized:
            return os.getenv("RAW_RESULTS_PATH", "results/raw/")
        return self._session_config.raw_results_path

    def get_screenshots_path(self) -> str:
        """Get the path for screenshots.

        Returns:
            Screenshots folder path
        """
        raw_path = self.get_raw_results_path()
        screenshots_path = os.path.join(raw_path, "screenshots")
        os.makedirs(screenshots_path, exist_ok=True)
        return screenshots_path

    def get_spotlight_files_path(self) -> str:
        """Get the path for spotlight files.

        Returns:
            Spotlight files folder path
        """
        results_path = self.get_results_path()
        spotlight_path = os.path.join(results_path, "spotlight_files")
        os.makedirs(spotlight_path, exist_ok=True)
        return spotlight_path

    def get_log_level(self) -> str:
        """Get the current log level.

        Returns:
            Log level string (DEBUG, INFO, WARNING, ERROR)
        """
        if self._args and hasattr(self._args, "loglevel"):
            return self._args.loglevel
        if self._session_config:
            return self._session_config.log_level
        return "INFO"

    def get_output_file(self) -> str:
        """Get the output JSON file path.

        Returns:
            Path to output file
        """
        if self._session_config:
            return self._session_config.output_file
        return os.getenv("RESULTS_PATH", "results/") + "sandroid.json"

    def get_device_name(self) -> str:
        """Get the current device name.

        Returns:
            Device name or default if not set
        """
        if self._session_config and self._session_config.device_name:
            return self._session_config.device_name
        return self._default_device_name

    def get_emulator_path(self) -> str:
        """Get the Android emulator executable path.

        Returns:
            Path to emulator executable
        """
        if self._default_emulator_path:
            return os.path.expanduser(self._default_emulator_path)
        return ""

    def get_args(self) -> argparse.Namespace | None:
        """Get the parsed command-line arguments.

        Returns:
            Parsed arguments or None if not initialized
        """
        return self._args

    def is_initialized(self) -> bool:
        """Check if session has been initialized.

        Returns:
            True if initialized
        """
        return self._initialized

    def get_session_config(self) -> SessionConfig | None:
        """Get the full session configuration.

        Returns:
            SessionConfig or None if not initialized
        """
        return self._session_config

    def reset(self) -> None:
        """Reset the service state (useful for testing).

        Clears all state but does not delete files.
        """
        with self._lock:
            self._session_config = None
            self._initialized = False
            self._args = None

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _setup_file_logging(self, log_file_path: str) -> None:
        """Set up file logging to the session folder.

        Args:
            log_file_path: Path to log file
        """
        root_logger = logging.getLogger()

        # Remove any existing file handlers to avoid duplicates
        for handler in root_logger.handlers[:]:
            if isinstance(handler, logging.FileHandler):
                handler.close()
                root_logger.removeHandler(handler)

        # Add new file handler
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setLevel(logging.DEBUG)  # File always gets DEBUG

        # Use same format as console but without colors
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

        self._logger.debug(f"File logging configured: {log_file_path}")

    def _publish_session_initialized(self) -> None:
        """Publish a session initialized event."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={
                    "state": "session_initialized",
                    "session_path": self._session_config.session_path,
                },
                source="configuration_service",
            )
        )


# Backwards compatibility: Expose SessionConfig at module level
__all__ = [
    "ConfigurationService",
    "SessionConfig",
]
