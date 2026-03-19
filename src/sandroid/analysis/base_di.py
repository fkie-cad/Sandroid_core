"""Base class for dependency-injected data gathering modules.

This module provides a modern base class for analysis modules that
supports dependency injection for better testability and SOLID compliance.

The DataGatherBase class bridges the gap between the legacy DataGather pattern
(which uses static Toolbox access) and a modern DI-based approach where
dependencies are explicitly passed to constructors.

Key Benefits:
    - Explicit dependencies make testing easier (mock injection)
    - Follows Dependency Inversion Principle (depend on abstractions)
    - Maintains backwards compatibility with existing codebase
    - Gradual migration path from legacy to modern patterns

Usage:
    class MyAnalysis(DataGatherBase):
        def __init__(self, forensic_service=None, adb=None, **kwargs):
            super().__init__(forensic_service=forensic_service, adb=adb, **kwargs)

        def gather(self) -> None:
            # Use self.forensic_service, self.adb, etc.
            adb = self._get_adb()
            stdout, stderr = adb.send_adb_command("shell ls /data")
            pass

        def return_data(self) -> Dict[str, Any]:
            return self._data

Example with full DI:
    # In production code
    from sandroid.core.adb import Adb
    from sandroid.core.toolbox import Toolbox

    analysis = MyAnalysis(
        forensic_service=ForensicServiceImpl(),
        adb=Adb,
        config=my_config,
        logger=logging.getLogger("my_analysis")
    )
    analysis.gather()
    data = analysis.return_data()

Example in tests:
    # Easy mocking for unit tests
    mock_adb = Mock()
    mock_adb.send_adb_command.return_value = ("output", "")

    analysis = MyAnalysis(adb=mock_adb)
    analysis.gather()

    mock_adb.send_adb_command.assert_called_with("shell ls /data")
"""

import logging
import os
from abc import abstractmethod
from typing import Any, Protocol

try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

from .interfaces import DataGatherer, DataProvider


def _get_display_value(field: str, default):
    """Read a display config value with fallback."""
    try:
        if get_config is not None:
            return getattr(get_config().display, field, default)
    except Exception:
        pass
    return default


class AdbProtocol(Protocol):
    """Protocol for ADB dependency.

    This protocol defines the interface that ADB implementations must satisfy.
    It allows for type-safe dependency injection while enabling easy mocking
    in tests.

    The static methods mirror the Adb class interface to maintain compatibility.
    """

    @staticmethod
    def send_adb_command(command: str) -> tuple[str, str]:
        """Send an ADB command and return stdout and stderr.

        Args:
            command: The ADB command to execute

        Returns:
            Tuple of (stdout, stderr) strings
        """
        ...

    @staticmethod
    def send_adb_command_popen(command: str):
        """Execute an ADB command using subprocess.Popen.

        Args:
            command: The ADB command to execute

        Returns:
            The Popen object representing the running process
        """
        ...


class ForensicServiceProtocol(Protocol):
    """Protocol for ForensicService dependency.

    This protocol defines the interface for forensic-related services
    that provide baseline, noise files, and timing information.

    Implementations can be the legacy Toolbox static methods or
    a proper service class for better testability.
    """

    def get_baseline(self) -> dict[str, str]:
        """Get the baseline file listing.

        The baseline represents the initial state of files on the device
        before any analysis actions are performed.

        Returns:
            Dictionary mapping file paths to their metadata (e.g., hash, mtime)
        """
        ...

    def get_noise_files(self) -> dict[str, str]:
        """Get the list of noise files to filter out.

        Noise files are files that change regardless of analysis actions,
        such as log files, cache files, etc.

        Returns:
            Dictionary mapping noise file paths to their metadata
        """
        ...

    def get_action_time(self) -> int:
        """Get the timestamp when the current analysis action started.

        Returns:
            Unix timestamp of action start time
        """
        ...

    def fetch_changed_files(self) -> list[str]:
        """Fetch the list of files that have changed.

        Returns:
            List of file paths that have been modified
        """
        ...


class ConfigProtocol(Protocol):
    """Protocol for configuration dependency.

    This protocol defines a generic configuration interface that can be
    satisfied by various configuration implementations (dict, dataclass, etc.).
    """

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key.

        Args:
            key: The configuration key
            default: Default value if key is not found

        Returns:
            The configuration value or default
        """
        ...


class DataGatherBase(DataGatherer, DataProvider):
    """Base class for data gathering modules with dependency injection.

    This class provides a foundation for analysis modules that need
    access to services like ForensicService, ADB, and configuration.
    It implements both DataGatherer and DataProvider interfaces from
    the segregated interface hierarchy.

    Design Philosophy:
        - Dependencies are injected via constructor (Dependency Inversion)
        - Fallback to global/static instances for backwards compatibility
        - Helper methods abstract away the DI vs legacy access patterns
        - Subclasses focus on gathering logic, not infrastructure

    Subclasses should:
        1. Call super().__init__() with required dependencies
        2. Implement gather() to collect data
        3. Implement return_data() to return collected data
        4. Use helper methods like _get_adb(), _get_baseline() etc.

    Attributes:
        forensic_service: ForensicService instance for file tracking
        adb: ADB interface for device communication
        config: Configuration object
        logger: Logger instance (protected as _logger for subclass access)

    Example:
        class FileMonitor(DataGatherBase):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self._files = []

            def gather(self) -> None:
                baseline = self._get_baseline()
                adb = self._get_adb()
                # ... gather files using adb and baseline
                self._files = [...]
                self._store_data("files", self._files)

            def return_data(self) -> Dict[str, Any]:
                return self._data
    """

    def __init__(
        self,
        forensic_service: ForensicServiceProtocol | None = None,
        adb: AdbProtocol | None = None,
        config: ConfigProtocol | dict[str, Any] | None = None,
        logger: logging.Logger | None = None,
        **kwargs,
    ):
        """Initialize with dependencies.

        All dependencies are optional and will fall back to global/static
        instances if not provided. This enables gradual migration from
        legacy code while supporting full DI in new code and tests.

        Args:
            forensic_service: ForensicService for file tracking. If None,
                falls back to Toolbox static methods.
            adb: ADB interface for device communication. If None, falls
                back to the global Adb class.
            config: Configuration object. Can be a dict or any object
                implementing ConfigProtocol.
            logger: Logger instance. If None, creates a logger named
                after the subclass.
            **kwargs: Additional arguments for subclasses to extend.
                This allows subclasses to add their own constructor
                parameters while still calling super().__init__().
        """
        self.forensic_service = forensic_service
        self.adb = adb
        self.config = config
        self._logger = logger or logging.getLogger(self.__class__.__name__)
        self._data: dict[str, Any] = {}

    @property
    def logger(self) -> logging.Logger:
        """Get the logger instance.

        Provides read-only access to the logger for subclasses.

        Returns:
            The logger instance for this module
        """
        return self._logger

    @abstractmethod
    def gather(self) -> None:
        """Gather data from the device/analysis.

        Implementations should collect data and store it using _store_data()
        or directly in self._data. This method should NOT return data;
        use return_data() for that.

        Raises:
            NotImplementedError: If not implemented in subclass
        """
        ...

    @abstractmethod
    def return_data(self) -> dict[str, Any]:
        """Return collected data.

        Returns the data collected by gather(). The structure of the
        returned dictionary is implementation-specific.

        Returns:
            Dictionary containing the gathered data

        Raises:
            NotImplementedError: If not implemented in subclass
        """
        ...

    # =========================================================================
    # Helper methods for dependency access with fallback
    # =========================================================================

    def _get_adb(self):
        """Get ADB interface, falling back to global if not injected.

        This method provides transparent access to ADB functionality
        whether or not ADB was explicitly injected.

        Returns:
            The ADB interface (injected or global Adb class)
        """
        if self.adb is not None:
            return self.adb
        # Fallback to global Adb class
        from sandroid.core.adb import Adb

        return Adb

    def _get_forensic_service(self) -> ForensicServiceProtocol | None:
        """Get ForensicService if available.

        Unlike other helper methods, this doesn't have a direct fallback
        since ForensicService is a higher-level abstraction. Individual
        methods like _get_baseline() provide their own fallbacks.

        Returns:
            The forensic service if injected, None otherwise
        """
        return self.forensic_service

    def _get_with_fallback(
        self, method: str, toolbox_attr: str, default: Any = None
    ) -> Any:
        """Get a value using the 3-tier fallback: injected service -> singleton -> Toolbox.

        This helper centralises the repeated pattern of trying the injected
        forensic service first, then the singleton, and finally the legacy
        Toolbox static attribute.

        Args:
            method: Name of the method to call on the forensic service
                (e.g., ``"get_baseline"``).
            toolbox_attr: Name of the Toolbox class attribute used as the
                final fallback (e.g., ``"baseline"``).
            default: Value returned when all fallbacks are exhausted.

        Returns:
            The value from the first tier that produces a truthy result,
            or *default*.
        """
        # Tier 1: injected forensic service
        fs = self._get_forensic_service()
        if fs is not None:
            return getattr(fs, method)()

        # Tier 2: ForensicService singleton
        from sandroid.services import get_forensic_service

        singleton_fs = get_forensic_service()
        result = getattr(singleton_fs, method)()
        if result:
            return result

        # Tier 3: Toolbox static attribute (legacy)
        from sandroid.core.toolbox import Toolbox

        return getattr(Toolbox, toolbox_attr, default)

    def _get_baseline(self) -> dict[str, str]:
        """Get baseline from forensic service or Toolbox.

        The baseline represents the initial state of files on the device
        before analysis actions. Used to detect new and changed files.

        Returns:
            Dictionary mapping file paths to their metadata
        """
        return self._get_with_fallback("get_baseline", "baseline", {})

    def _get_noise_files(self) -> dict[str, str]:
        """Get noise files from forensic service or Toolbox.

        Noise files are files that change regardless of analysis actions,
        such as system logs, caches, etc. These should be filtered from
        analysis results.

        Returns:
            Dictionary mapping noise file paths to their metadata
        """
        return self._get_with_fallback("get_noise_files", "noise_files", {})

    def _get_action_time(self) -> int:
        """Get action time from forensic service or Toolbox.

        The action time is the Unix timestamp when the current analysis
        action started. Used to filter file changes to the relevant time window.

        Returns:
            Unix timestamp of action start time
        """
        return self._get_with_fallback("get_action_time", "action_time", 0)

    def _fetch_changed_files(self) -> list[str]:
        """Fetch changed files from forensic service or Toolbox.

        Gets the list of files that have changed since the baseline
        was established.

        Returns:
            List of file paths that have been modified
        """
        fs = self._get_forensic_service()
        if fs is not None:
            return fs.fetch_changed_files()
        # Fallback to ForensicService singleton, then Toolbox static method
        from sandroid.services import get_forensic_service

        singleton_fs = get_forensic_service()
        # Note: We don't check if empty because an empty result is valid
        # (no files changed). The singleton is preferred over Toolbox.
        return singleton_fs.fetch_changed_files()

    # =========================================================================
    # Data storage helpers
    # =========================================================================

    def _store_data(self, key: str, value: Any) -> None:
        """Store a value in the internal data dictionary.

        Convenience method for storing gathered data. The data stored
        here will be accessible via return_data().

        Args:
            key: The key to store the data under
            value: The value to store
        """
        self._data[key] = value

    def _get_stored_data(self, key: str, default: Any = None) -> Any:
        """Retrieve a value from the internal data dictionary.

        Args:
            key: The key to retrieve
            default: Default value if key is not found

        Returns:
            The stored value or default
        """
        return self._data.get(key, default)

    def _clear_data(self) -> None:
        """Clear all stored data.

        Useful when re-running gather() or resetting state.
        """
        self._data.clear()

    # =========================================================================
    # Configuration helpers
    # =========================================================================

    def _get_config_value(self, key: str, default: Any = None) -> Any:
        """Get a configuration value.

        Handles both dict-like and ConfigProtocol configurations.

        Args:
            key: The configuration key
            default: Default value if key is not found

        Returns:
            The configuration value or default
        """
        if self.config is None:
            return default

        if isinstance(self.config, dict):
            return self.config.get(key, default)

        if hasattr(self.config, "get"):
            return self.config.get(key, default)

        # Try attribute access as fallback
        return getattr(self.config, key, default)

    # =========================================================================
    # Environment and path helpers
    # =========================================================================

    def _get_env_path(self, config_key: str, env_var: str, default: str) -> str:
        """Get a path from config, falling back to an environment variable.

        Args:
            config_key: Key to look up in the config object.
            env_var: Environment variable name used as fallback.
            default: Default value if neither config nor env var is set.

        Returns:
            The resolved path string.
        """
        path = self._get_config_value(config_key)
        if path:
            return path
        return os.getenv(env_var, default)

    def _get_results_path(self) -> str:
        """Get the results path from config or environment.

        Returns:
            The path where results should be stored
        """
        return self._get_env_path("results_path", "RESULTS_PATH", "./results/")

    def _get_raw_results_path(self) -> str:
        """Get the raw results path from config or environment.

        Returns:
            The path where raw results (pulled files) should be stored
        """
        return self._get_env_path(
            "raw_results_path", "RAW_RESULTS_PATH", "./results/raw/"
        )

    def _build_pull_path(
        self,
        pull_type: str,
        device_path: str,
        base_folder: str | None = None,
    ) -> str:
        """Build a local file path for a pulled device file.

        This is a utility method to standardize the construction of local paths
        where files pulled from the device are stored. The pattern is:
            {base_folder}{pull_type}_pull/{device_path_without_leading_slash}

        Args:
            pull_type: Type of pull - "first", "second", "noise", "new", or a number
            device_path: The path of the file on the device (e.g., "/data/app/file.db")
            base_folder: Base folder for results. If None, uses _get_raw_results_path()

        Returns:
            Local file system path where the pulled file should be stored

        Example:
            >>> self._build_pull_path("first", "/data/data/com.app/db.sqlite")
            '/results/raw/first_pull/data/data/com.app/db.sqlite'

            >>> self._build_pull_path("second", "/system/build.prop")
            '/results/raw/second_pull/system/build.prop'

            >>> self._build_pull_path("1", "/data/app.db", base_folder="/custom/")
            '/custom/1_pull/data/app.db'
        """
        if base_folder is None:
            base_folder = self._get_raw_results_path()

        # Ensure base_folder ends with separator for consistent concatenation
        if base_folder and not base_folder.endswith(os.sep):
            base_folder = base_folder + os.sep

        # Build the pull directory name
        pull_dir = f"{pull_type}_pull"

        # Strip leading slash from device path to make it relative
        relative_device_path = device_path.lstrip("/")

        return os.path.join(f"{base_folder}{pull_dir}", relative_device_path)

    # =========================================================================
    # Logging helpers
    # =========================================================================

    def _log_debug(self, message: str, *args, **kwargs) -> None:
        """Log a debug message.

        Args:
            message: The message to log
            *args: Positional arguments for formatting
            **kwargs: Keyword arguments for formatting
        """
        self._logger.debug(message, *args, **kwargs)

    def _log_info(self, message: str, *args, **kwargs) -> None:
        """Log an info message.

        Args:
            message: The message to log
            *args: Positional arguments for formatting
            **kwargs: Keyword arguments for formatting
        """
        self._logger.info(message, *args, **kwargs)

    def _log_warning(self, message: str, *args, **kwargs) -> None:
        """Log a warning message.

        Args:
            message: The message to log
            *args: Positional arguments for formatting
            **kwargs: Keyword arguments for formatting
        """
        self._logger.warning(message, *args, **kwargs)

    def _log_error(self, message: str, *args, **kwargs) -> None:
        """Log an error message.

        Args:
            message: The message to log
            *args: Positional arguments for formatting
            **kwargs: Keyword arguments for formatting
        """
        self._logger.error(message, *args, **kwargs)

    # =========================================================================
    # ADB command helpers
    # =========================================================================

    def _send_adb_command(self, command: str) -> tuple[str, str]:
        """Send an ADB command and return the result.

        Convenience method that handles getting the ADB interface
        and executing the command.

        Args:
            command: The ADB command to execute

        Returns:
            Tuple of (stdout, stderr) strings
        """
        adb = self._get_adb()
        return adb.send_adb_command(command)

    def _send_shell_command(self, command: str) -> tuple[str, str]:
        """Send an ADB shell command and return the result.

        Convenience method that prepends 'shell' to the command.

        Args:
            command: The shell command to execute (without 'shell' prefix)

        Returns:
            Tuple of (stdout, stderr) strings
        """
        return self._send_adb_command(f"shell {command}")

    def _send_shell_command_checked(
        self,
        command: str,
        action_description: str,
        log_level: str = "error",
        raise_on_error: bool = False,
    ) -> tuple[str | None, str | None]:
        """Send an ADB shell command with automatic error handling.

        This utility method handles the common pattern of sending an ADB command
        and checking stderr for errors, with configurable logging and error behavior.

        Args:
            command: The shell command to execute (without 'shell' prefix)
            action_description: Human-readable description for error messages
                               (e.g., "set SELinux permissive", "list files")
            log_level: Logging level for errors: "error", "warning", "debug", "info"
            raise_on_error: If True, raises RuntimeError on stderr; if False, returns (None, stderr)

        Returns:
            Tuple of (stdout, stderr). If raise_on_error is False and stderr is present,
            returns (None, stderr) to indicate failure. Otherwise returns (stdout, None)
            on success.

        Raises:
            RuntimeError: If raise_on_error is True and stderr is present

        Example:
            # Log error but continue
            stdout, err = self._send_shell_command_checked(
                "ls /data/data",
                "list app directories",
                log_level="warning"
            )
            if err:
                return []  # Handle failure

            # Raise on error (stderr still captured for context)
            stdout, stderr = self._send_shell_command_checked(
                "setenforce 0",
                "disable SELinux",
                raise_on_error=True
            )
            if stderr:
                self._log_warning(f"SELinux command warning: {stderr}")
        """
        stdout, stderr = self._send_shell_command(command)

        if stderr:
            message = f"Failed to {action_description}: {stderr}"

            # Log at appropriate level
            if log_level == "error":
                self._log_error(message)
            elif log_level == "warning":
                self._log_warning(message)
            elif log_level == "debug":
                self._log_debug(message)
            else:
                self._log_info(message)

            if raise_on_error:
                raise RuntimeError(message)

            return None, stderr

        return stdout, None

    # =========================================================================
    # File filtering helpers
    # =========================================================================

    def _filter_noise(self, files: list[str]) -> list[str]:
        """Filter out noise files from a list of files.

        Uses the noise files from the forensic service or Toolbox
        to filter out files that change regardless of analysis actions.

        Args:
            files: List of file paths to filter

        Returns:
            List of file paths with noise files removed
        """
        noise = self._get_noise_files()
        return [f for f in files if f not in noise]

    def _filter_baseline(self, files: list[str]) -> tuple[list[str], list[str]]:
        """Separate files into new and changed based on baseline.

        Args:
            files: List of file paths to categorize

        Returns:
            Tuple of (new_files, changed_files) where:
                - new_files: files not in baseline
                - changed_files: files that exist in baseline
        """
        baseline = self._get_baseline()
        new_files = []
        changed_files = []

        for file in files:
            if file in baseline:
                changed_files.append(file)
            else:
                new_files.append(file)

        return new_files, changed_files

    # =========================================================================
    # Toolbox compatibility helpers
    # =========================================================================

    def _get_toolbox(self):
        """Get reference to Toolbox for legacy compatibility.

        This method provides access to the Toolbox class for operations
        that haven't been abstracted into protocols yet. Use sparingly
        and prefer the specific helper methods when possible.

        Returns:
            The Toolbox class
        """
        from sandroid.core.toolbox import Toolbox

        return Toolbox

    def _exclude_whitelist(self, files: list[str]) -> list[str]:
        """Apply whitelist filtering to files.

        The whitelist contains file patterns that should be excluded
        from analysis results.

        Args:
            files: List of file paths to filter

        Returns:
            List of file paths with whitelisted files removed
        """
        fs = self._get_forensic_service()
        if fs:
            return fs.exclude_whitelist(files)
        # Fallback: return all files if no service available
        return files

    def _highlight_timestamps(self, text: str, color: str = "") -> str:
        """Highlight timestamps in text using Toolbox formatting.

        Args:
            text: The text to process
            color: The color to use for highlighting

        Returns:
            Text with timestamps highlighted
        """
        toolbox = self._get_toolbox()
        return toolbox.highlight_timestamps(text, color)

    def _truncate(self, text: str) -> str:
        """Truncate text using Toolbox truncation settings.

        Args:
            text: The text to truncate

        Returns:
            Truncated text
        """
        toolbox = self._get_toolbox()
        return toolbox.truncate(text)

    def _pull_file(self, pull_type: str, file_path: str) -> bool:
        """Pull a file from the device using Toolbox.

        Args:
            pull_type: The type of pull (e.g., "new", "first", "second")
            file_path: The device path of the file to pull

        Returns:
            True if successful, False otherwise
        """
        toolbox = self._get_toolbox()
        return toolbox.pull_file(pull_type, file_path)

    # =========================================================================
    # Output formatting helpers (for pretty_print template pattern)
    # =========================================================================

    # Default separator width (108 characters)
    _DEFAULT_SECTION_SEPARATOR_WIDTH = 108

    @property
    def _SECTION_SEPARATOR(self) -> str:
        """Get section separator string, reading width from config."""
        width = _get_display_value(
            "section_separator_width", self._DEFAULT_SECTION_SEPARATOR_WIDTH
        )
        return "\u2014" * width

    def _format_section_header(self, title: str, color: str = "info") -> str:
        """Create a formatted section header for output display.

        Creates a consistent header format used by analysis modules:
            [color bold]
            —————————————————TITLE=(description)——————————————————————————————————————————————————
            [/color bold][color]

        Args:
            title: The section title (e.g., "CHANGED_FILES=(changed in all runs)")
            color: Rich color tag to use (e.g., "info", "success", "primary", "accent")

        Returns:
            Formatted header string

        Example:
            header = self._format_section_header(
                "CHANGED_FILES=(changed in all runs)",
                color="info"
            )
        """
        return (
            f"[{color} bold]"
            f"\n—————————————————{title}——————————————————————————————————————————————————\n"
            f"[/{color} bold][{color}]"
        )

    def _format_section_footer(self, color: str = "bold") -> str:
        """Create a formatted section footer for output display.

        Creates a consistent footer format used by analysis modules:
            [bold]
            ———————————————————————————————————————————————————————————————————————————————————————————————————————
            [/bold]

        Args:
            color: Rich style to use for the footer (default: "bold")

        Returns:
            Formatted footer string
        """
        return f"[{color}]{self._SECTION_SEPARATOR}\n[/{color}]"

    def _format_entry(
        self, entry: str, color: str = "", highlight_timestamps: bool = True
    ) -> str:
        """Format a single entry for output display.

        Applies optional timestamp highlighting and color formatting to an entry.

        Args:
            entry: The entry text to format
            color: Rich color tag to use for the entry (empty for no color)
            highlight_timestamps: Whether to highlight timestamps in the entry

        Returns:
            Formatted entry string
        """
        if highlight_timestamps:
            entry = self._highlight_timestamps(entry, color)
        return entry

    def _build_pretty_output(
        self,
        title: str,
        entries: list[str],
        color: str = "info",
        highlight_timestamps: bool = True,
    ) -> str:
        """Build a complete pretty-printed output section.

        This is a template method that creates consistently formatted output
        for analysis modules. It combines header, formatted entries, and footer.

        Args:
            title: Section title for the header
            entries: List of entries to display
            color: Rich color tag (e.g., "info", "success", "primary", "accent")
            highlight_timestamps: Whether to highlight timestamps in entries

        Returns:
            Complete formatted output string

        Example:
            output = self._build_pretty_output(
                title="NEW_FILES=(created in second run)",
                entries=["file1.txt", "file2.db"],
                color="success",
                highlight_timestamps=True
            )
        """
        result = self._format_section_header(title, color)

        for entry in entries:
            result += self._format_entry(entry, color, highlight_timestamps) + "\n"

        result += self._format_section_footer()
        return result


# Type alias for backwards compatibility with code expecting the old name
DataGatherDI = DataGatherBase


__all__ = [
    "AdbProtocol",
    "ConfigProtocol",
    "DataGatherBase",
    "DataGatherDI",  # Alias
    "ForensicServiceProtocol",
]
