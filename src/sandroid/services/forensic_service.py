"""Forensic Analysis Service for Sandroid.

This service manages forensic analysis state including file baselines,
noise detection, spotlight file tracking, and file change detection.

Extracted from Toolbox class to follow Single Responsibility Principle.

Usage:
    from sandroid.services import get_forensic_service
    from sandroid.services.forensic_service import ForensicService

    # Get service
    forensic = get_forensic_service()

    # Manage baseline
    forensic.set_baseline(file_dict)

    # Track files
    forensic.add_spotlight_file("/data/data/com.app/databases/app.db")

    # Exclude whitelist
    filtered = forensic.exclude_whitelist(file_list)
"""

import fnmatch
import logging
import os
from collections.abc import Callable
from typing import Any

import dateutil.parser as dp

from sandroid.services.forensic_service_types import (
    AdbProtocol,
    Snapshot,
    TimelineEntry,
)
from sandroid.services.forensic_timeline import ForensicTimeline
from sandroid.services.forensic_utils import (
    DIR_PATTERN,
    TIME_PATTERN,
    get_parent_db_path,
    is_wal_or_journal,
)
from sandroid.services.protocols import EventBusProtocol

# Import config with fallback for standalone usage
try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

logger = logging.getLogger(__name__)


class ForensicService:
    """Service for forensic analysis state management.

    This service manages:
    - File baselines (known-good state)
    - Noise files (files that change normally)
    - Spotlight files (files to monitor closely)
    - Whitelist filtering
    - Timeline tracking (delegated to ForensicTimeline)

    Thread Safety:
        Basic operations are thread-safe. File operations should
        be performed from a single thread.

    Example:
        service = ForensicService()

        # Set baseline
        service.set_baseline({"/data/app.db": "hash123"})

        # Track spotlight files
        service.add_spotlight_file("/data/data/com.app/databases/app.db")

        # Get monitored files
        files = service.get_spotlight_files()
    """

    # Default directories to scan for changes (kept as fallback)
    _DEFAULT_SCAN_DIRECTORIES = ["/data", "/storage", "/sdcard"]

    @classmethod
    def _get_scan_directories(cls) -> list[str]:
        """Get scan directories from config with fallback.

        Returns:
            List of directory paths to scan.
        """
        try:
            if get_config is not None:
                return list(get_config().device_paths.scan_directories)
        except Exception:
            pass
        return cls._DEFAULT_SCAN_DIRECTORIES.copy()

    # Keep class-level alias for backwards compatibility
    DEFAULT_SCAN_DIRECTORIES = _DEFAULT_SCAN_DIRECTORIES

    def __init__(
        self,
        event_bus: EventBusProtocol | None = None,
        results_path: str | None = None,
        adb: AdbProtocol | None = None,
        timeline_callback: Callable[[str, str, int, str, bool], None] | None = None,
    ):
        """Initialize the ForensicService.

        Args:
            event_bus: Optional EventBus for publishing events.
            results_path: Base path for results (defaults to RESULTS_PATH env).
            adb: Optional ADB protocol implementation for device communication.
                 If not provided, falls back to sandroid.core.adb.Adb.
            timeline_callback: Optional callback for adding timeline entries
                to external systems (e.g., Toolbox shadow timestamp list).
                Signature: (dir, filename, timestamp, color, fetch_all) -> None
        """
        self._baseline: dict[str, str] = {}
        self._noise_files: dict[str, str] = {}
        self._spotlight_files: list[str] = []
        self._whitelist_patterns: list[str] | None = None
        self._whitelist_path: str | None = None
        self._changed_files_cache: dict[str, int] = {}
        self._cache_valid: bool = False

        # Action window tracking
        self._action_time: int = 0
        self._action_duration: int = 0

        # Timeline management (delegated)
        self._timeline = ForensicTimeline()

        # Migrated from Toolbox (09-02 Task 2)
        self._noise_processes: list = []
        self._other_output_data_collector: dict = {}

        self._scan_directories = self._get_scan_directories()
        self._event_bus = event_bus
        self._results_path = results_path or os.getenv("RESULTS_PATH", "./results/")
        self._logger = logger
        self._adb = adb
        self._timeline_callback = timeline_callback

    # =========================================================================
    # Baseline Management
    # =========================================================================

    def set_baseline(self, baseline: dict[str, str]) -> None:
        """Set the baseline filesystem state.

        The baseline represents the "known good" state before
        any analysis actions are performed.

        Args:
            baseline: Dictionary mapping file paths to hashes/timestamps.
        """
        self._baseline = baseline.copy()
        self._logger.info(f"Set baseline with {len(baseline)} files")

    def get_baseline(self) -> dict[str, str]:
        """Get the current baseline (copy)."""
        return self._baseline.copy()

    def clear_baseline(self) -> None:
        """Clear the baseline."""
        self._baseline.clear()
        self._logger.info("Cleared baseline")

    def is_in_baseline(self, file_path: str) -> bool:
        """Check if a file is in the baseline."""
        return file_path in self._baseline

    # =========================================================================
    # Noise Files Management
    # =========================================================================

    def set_noise_files(self, noise: dict[str, str]) -> None:
        """Set the noise files (files that change normally).

        Args:
            noise: Dictionary mapping file paths to hashes/timestamps.
        """
        self._noise_files = noise.copy()
        self._logger.info(f"Set noise files: {len(noise)} files")

    def get_noise_files(self) -> dict[str, str]:
        """Get the current noise files (copy)."""
        return self._noise_files.copy()

    def add_noise_file(self, file_path: str, hash_value: str = "") -> None:
        """Add a file to the noise list."""
        self._noise_files[file_path] = hash_value

    def is_noise_file(self, file_path: str) -> bool:
        """Check if a file is in the noise list."""
        return file_path in self._noise_files

    # =========================================================================
    # Spotlight Files Management
    # =========================================================================

    def add_spotlight_file(
        self, file_path: str, adb: AdbProtocol | None = None
    ) -> bool:
        """Add a file to spotlight monitoring.

        Supports wildcards (*) to add multiple files matching a pattern.
        When using wildcards, requires an ADB instance to query the device.

        Args:
            file_path: Path to monitor, or pattern with wildcards.
            adb: Optional ADB instance for wildcard expansion.

        Returns:
            True if file(s) were added, False otherwise.
        """
        if not file_path:
            self._logger.warning("Cannot add empty file path to spotlight files")
            return False

        if "*" in file_path:
            return self._add_spotlight_files_by_pattern(file_path, adb)

        return self._add_single_spotlight_file(file_path)

    def _add_spotlight_files_by_pattern(
        self, file_path: str, adb: AdbProtocol | None = None
    ) -> bool:
        """Add multiple files matching a wildcard pattern.

        Args:
            file_path: Pattern with wildcards (e.g., /data/data/com.app/*).
            adb: ADB instance for querying device filesystem.

        Returns:
            True if any files were added, False otherwise.
        """
        if adb is None:
            self._logger.warning("Cannot expand wildcard pattern without ADB instance")
            return False

        added_count = 0
        is_recursive = file_path.endswith("/*")
        search_path = file_path[:-2] if is_recursive else file_path

        if is_recursive:
            cmd = f"shell find {search_path} -type f"
        else:
            cmd = f"shell ls -1A {search_path}"

        stdout, stderr = adb.send_adb_command(cmd)

        if stderr:
            self._logger.error(f"Error listing files: {stderr}")
            return False

        for matched_file in stdout.strip().split("\n"):
            if not matched_file or matched_file.isspace():
                continue

            if is_wal_or_journal(matched_file):
                self._logger.debug(f"Skipping WAL or journal file: {matched_file}")
                continue

            if is_recursive and matched_file.endswith("/"):
                continue

            self._add_single_spotlight_file(matched_file.strip())
            added_count += 1

        self._logger.info(
            f"Added {added_count} files matching pattern '{file_path}' to spotlight files"
        )
        return added_count > 0

    def _add_single_spotlight_file(self, file_path: str) -> bool:
        """Add a single file to spotlight files.

        Args:
            file_path: Path to the file to add.

        Returns:
            True if the file was added, False otherwise.
        """
        if is_wal_or_journal(file_path):
            self._logger.debug(f"Skipping WAL/journal file: {file_path}")
            return False

        if file_path in self._spotlight_files:
            self._logger.info(f"File '{file_path}' is already in spotlight files")
            return False

        self._spotlight_files.append(file_path)
        self._logger.info(f"Added '{file_path}' to spotlight files")
        return True

    def add_spotlight_files(self, file_paths: list[str]) -> int:
        """Add multiple files to spotlight monitoring.

        Args:
            file_paths: List of paths to monitor.

        Returns:
            Number of files actually added.
        """
        added = 0
        for path in file_paths:
            if self.add_spotlight_file(path):
                added += 1
        return added

    def remove_spotlight_file(self, file_path: str) -> bool:
        """Remove a file from spotlight monitoring. Returns True if removed."""
        if file_path in self._spotlight_files:
            self._spotlight_files.remove(file_path)
            self._logger.info(f"Removed spotlight file: {file_path}")
            return True
        return False

    def get_spotlight_files(self) -> list[str]:
        """Get all spotlight files (copy)."""
        return self._spotlight_files.copy()

    def clear_spotlight_files(self) -> None:
        """Clear all spotlight files."""
        self._spotlight_files.clear()
        self._logger.info("Cleared spotlight files")

    def has_spotlight_files(self) -> bool:
        """Check if any spotlight files are configured."""
        return len(self._spotlight_files) > 0

    # =========================================================================
    # Whitelist Management
    # =========================================================================

    def set_whitelist_path(self, path: str) -> None:
        """Set the whitelist file path.

        Args:
            path: Path to whitelist file.
        """
        self._whitelist_path = path
        self._whitelist_patterns = None  # Force reload
        self._logger.info(f"Set whitelist path: {path}")

    def load_whitelist(self) -> list[str]:
        """Load whitelist patterns from file.

        Returns:
            List of whitelist patterns.
        """
        if self._whitelist_patterns is not None:
            return self._whitelist_patterns

        if not self._whitelist_path or not os.path.exists(self._whitelist_path):
            self._whitelist_patterns = []
            return self._whitelist_patterns

        try:
            with open(self._whitelist_path, encoding="utf-8") as f:
                patterns = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
            self._whitelist_patterns = patterns
            self._logger.debug(f"Loaded {len(patterns)} whitelist patterns")
        except Exception as e:
            self._logger.error(f"Error loading whitelist: {e}")
            self._whitelist_patterns = []

        return self._whitelist_patterns

    def exclude_whitelist(self, file_list: list[str]) -> list[str]:
        """Filter a file list by excluding whitelist matches.

        Args:
            file_list: List of file paths to filter.

        Returns:
            Filtered list with whitelist matches removed.
        """
        patterns = self.load_whitelist()
        if not patterns:
            return file_list

        result = []
        for file_path in file_list:
            matched = any(fnmatch.fnmatch(file_path, p) for p in patterns)
            if not matched:
                result.append(file_path)

        excluded_count = len(file_list) - len(result)
        if excluded_count > 0:
            self._logger.debug(f"Excluded {excluded_count} files via whitelist")

        return result

    def is_whitelisted(self, file_path: str) -> bool:
        """Check if a file matches the whitelist.

        Args:
            file_path: Path to check.

        Returns:
            True if file matches a whitelist pattern.
        """
        patterns = self.load_whitelist()
        return any(fnmatch.fnmatch(file_path, p) for p in patterns)

    # =========================================================================
    # Action Window Tracking
    # =========================================================================

    def set_action_window(self, action_time: int, duration: int = 0) -> None:
        """Set the action time window for change detection.

        Args:
            action_time: Start time (Unix timestamp).
            duration: Duration in seconds.
        """
        self._action_time = action_time
        self._action_duration = duration
        self._timeline.action_time = action_time
        self._cache_valid = False  # Invalidate cache
        self._logger.debug(f"Set action window: {action_time} + {duration}s")

    def get_action_time(self) -> int:
        """Get the current action start time (Unix timestamp)."""
        return self._action_time

    def get_action_duration(self) -> int:
        """Get the current action duration in seconds."""
        return self._action_duration

    # =========================================================================
    # Timeline Management (delegates to ForensicTimeline)
    # =========================================================================

    def add_timeline_entry(
        self,
        timestamp: int,
        file_path: str,
        change_type: str = "modified",
    ) -> None:
        """Add an entry to the forensic timeline.

        Args:
            timestamp: Unix timestamp of the event.
            file_path: Path to the affected file.
            change_type: Type of change.
        """
        self._timeline.add_entry(timestamp, file_path, change_type)

    def get_timeline(self) -> list[TimelineEntry]:
        """Get timeline entries sorted by timestamp."""
        return self._timeline.get_entries()

    def clear_timeline(self) -> None:
        """Clear all timeline entries."""
        self._timeline.clear_entries()

    def add_to_shadow_ts_list(
        self,
        current_dir: str,
        filename: str,
        seconds_timestamp: int,
        color: str = "#1A535C",
        fetch_all: bool = False,
    ) -> None:
        """Add a file change entry to the shadow timestamp list.

        Args:
            current_dir: The directory containing the file.
            filename: The name of the file that changed.
            seconds_timestamp: The change time in Unix seconds.
            color: Color for timeline visualization.
            fetch_all: If True, the entry is not added (baseline scans).
        """
        self._timeline.add_shadow_entry(
            current_dir, filename, seconds_timestamp, color, fetch_all
        )

    def get_shadow_ts_list(self) -> list[dict[str, Any]]:
        """Get the shadow timestamp list for timeline generation."""
        return self._timeline.get_shadow_ts_list()

    def clear_shadow_ts_list(self) -> None:
        """Clear the shadow timestamp list."""
        self._timeline.clear_shadow_ts_list()

    # =========================================================================
    # Cache Management
    # =========================================================================

    def set_changed_files_cache(self, files: dict[str, str]) -> None:
        """Set the changed files cache."""
        self._changed_files_cache = files.copy()
        self._cache_valid = True

    def get_changed_files_cache(self) -> dict[str, str]:
        """Get cached changed files (copy)."""
        return self._changed_files_cache.copy()

    def is_cache_valid(self) -> bool:
        """Check if the changed files cache is valid."""
        return self._cache_valid

    def invalidate_cache(self) -> None:
        """Invalidate the changed files cache."""
        self._cache_valid = False

    # =========================================================================
    # Scan Configuration
    # =========================================================================

    def set_scan_directories(self, directories: list[str]) -> None:
        """Set directories to scan for file changes."""
        self._scan_directories = directories.copy()

    def get_scan_directories(self) -> list[str]:
        """Get directories configured for scanning."""
        return self._scan_directories.copy()

    # =========================================================================
    # Changed Files Detection
    # =========================================================================

    def _get_adb(self) -> AdbProtocol:
        """Get ADB instance, falling back to global Adb if not injected.

        Returns:
            ADB protocol implementation.
        """
        if self._adb is not None:
            return self._adb
        from sandroid.core.adb import Adb

        return Adb

    def fetch_changed_files(self, fetch_all: bool = False) -> dict[str, int]:
        """Fetch changed files from the AVD filesystem.

        Scans the configured directories on the device and returns files
        that have been modified within the action time window.

        Args:
            fetch_all: If True, fetch all files regardless of action time.

        Returns:
            Dictionary mapping file paths to their change timestamps.
        """
        if self._cache_valid and not fetch_all:
            self._logger.debug("Reading filesystem timestamps from cache")
            return self._changed_files_cache.copy()

        return self._fetch_changed_files_impl(fetch_all)

    def _build_scan_command(self) -> str:
        """Build the ADB shell command for scanning filesystem timestamps.

        Returns:
            The ADB shell command string.
        """
        dirs = " ".join(self._scan_directories)
        return f"shell ls {dirs} -ltRAp --full-time"

    def _parse_filesystem_listing(self, filesystem: str) -> list[tuple[str, str, int]]:
        """Parse the raw filesystem listing into structured file entries.

        Parses the output of `ls -ltRAp --full-time` and extracts file paths
        with their timestamps. Skips directories, symlinks, and unparseable lines.

        Args:
            filesystem: Raw output from the `ls` command.

        Returns:
            List of (directory, filename, timestamp_seconds) tuples.
        """
        entries: list[tuple[str, str, int]] = []
        current_dir = ""

        for line in filesystem.splitlines():
            match = TIME_PATTERN.search(line)

            if match is None:
                dir_match = DIR_PATTERN.search(line)
                if dir_match is not None:
                    current_dir = dir_match.string[0:-1] + "/"
                continue

            # Skip directories and symlinks
            if line[-1] == "/" or " -> " in line:
                continue

            words = list(filter(None, line.split(" ")))
            if len(words) < 9:
                continue

            filename = words[8]
            timestamp_str = f"{words[5]} {words[6]} {words[7]}"

            try:
                parsed_ts = dp.parse(timestamp_str)
            except (ValueError, TypeError) as e:
                self._logger.debug(f"Could not parse timestamp '{timestamp_str}': {e}")
                continue

            seconds_timestamp = int(round(parsed_ts.timestamp()))
            entries.append((current_dir, filename, seconds_timestamp))

        return entries

    def _filter_by_action_window(
        self,
        entries: list[tuple[str, str, int]],
        fetch_all: bool,
    ) -> dict[str, int]:
        """Filter parsed entries by the action time window.

        Retains files whose timestamps fall within [action_time, action_time + duration],
        or all files if fetch_all is True. Also invokes the timeline callback
        and records timeline entries.

        Args:
            entries: Parsed filesystem entries from _parse_filesystem_listing.
            fetch_all: If True, include all files regardless of timing.

        Returns:
            Dictionary mapping file paths to their change timestamps.
        """
        changed_files: dict[str, int] = {}
        window_start = self._action_time
        window_end = self._action_time + self._action_duration

        for current_dir, filename, seconds_timestamp in entries:
            in_window = window_start <= seconds_timestamp <= window_end
            if not (in_window or fetch_all):
                continue

            file_path = current_dir + filename
            changed_files[file_path] = seconds_timestamp

            if self._timeline_callback is not None:
                self._timeline_callback(
                    current_dir, filename, seconds_timestamp, "#1A535C", fetch_all
                )

            if not fetch_all:
                self.add_timeline_entry(seconds_timestamp, file_path, "modified")

        return changed_files

    def _group_wal_journal_files(self, changed_files: dict[str, int]) -> dict[str, int]:
        """Include parent database files when WAL/journal companions are found.

        When a -wal or -journal file changes, the parent SQLite database
        should also be included in the results to ensure complete extraction.

        Args:
            changed_files: Dictionary of changed files to augment.

        Returns:
            The same dictionary with parent DB entries added (mutated in-place
            and returned for chaining convenience).
        """
        additions: dict[str, int] = {}
        for file_path, timestamp in changed_files.items():
            parent_db = get_parent_db_path(file_path)
            if parent_db is not None:
                additions[parent_db] = timestamp

        changed_files.update(additions)
        return changed_files

    def _filter_user0_duplicates(self, changed_files: dict[str, int]) -> dict[str, int]:
        """Filter out /data/user/0/ duplicates and reverse order.

        The /data/user/0/ path is a symlink to /data/data/ on Android,
        so files appearing under both paths are duplicates.

        Args:
            changed_files: Dictionary of changed files.

        Returns:
            Filtered dictionary with /data/user/0/ entries removed,
            in reversed insertion order.
        """
        result: dict[str, int] = {}
        for changed_file, changed_time in reversed(changed_files.items()):
            if not changed_file.startswith("/data/user/0/"):
                result[changed_file] = changed_time
        return result

    def _fetch_changed_files_impl(self, fetch_all: bool = False) -> dict[str, int]:
        """Internal implementation for fetching changed files.

        Orchestrates the pipeline: scan -> parse -> filter -> group -> deduplicate.

        Args:
            fetch_all: Whether to fetch all files or only those within action window.

        Returns:
            Dictionary mapping file paths to their change timestamps.
        """
        self._logger.info("Reading filesystem timestamps")

        adb = self._get_adb()
        command = self._build_scan_command()
        filesystem, errors = adb.send_adb_command(command)

        if errors:
            self._logger.error("Errors from subprocess on phone: " + errors)

        entries = self._parse_filesystem_listing(filesystem)
        changed_files = self._filter_by_action_window(entries, fetch_all)
        self._group_wal_journal_files(changed_files)
        result = self._filter_user0_duplicates(changed_files)

        if not fetch_all:
            self._changed_files_cache = result
            self._cache_valid = True

        return result

    # =========================================================================
    # Toolbox-Migrated State (09-02 Task 2)
    # =========================================================================
    # These properties provide direct-reference access for metaclass delegation.
    # External files (device_manager.py, trigdroid.py, actionQ.py, factory.py)
    # access these via Toolbox.attr which delegates through _ToolboxMeta.

    @property
    def noise_processes(self) -> list:
        """Noise processes list (direct reference for Toolbox delegation)."""
        return self._noise_processes

    @noise_processes.setter
    def noise_processes(self, value: list) -> None:
        self._noise_processes = value

    @property
    def other_output_data_collector(self) -> dict:
        """Output data collector (direct reference for Toolbox delegation)."""
        return self._other_output_data_collector

    @other_output_data_collector.setter
    def other_output_data_collector(self, value: dict) -> None:
        self._other_output_data_collector = value

    @property
    def noise_files_ref(self) -> dict[str, str]:
        """Noise files dict (direct reference). For copies, use get_noise_files()."""
        return self._noise_files

    @noise_files_ref.setter
    def noise_files_ref(self, value: dict[str, str]) -> None:
        self._noise_files = value

    @property
    def baseline_ref(self) -> dict[str, str]:
        """Baseline dict (direct reference). For copies, use get_baseline()."""
        return self._baseline

    @baseline_ref.setter
    def baseline_ref(self, value: dict[str, str]) -> None:
        self._baseline = value

    @property
    def timestamps_shadow_dict_list(self) -> list[dict[str, Any]]:
        """Shadow timestamp list (direct reference for Toolbox delegation)."""
        return self._timeline.shadow_ts_list_ref

    @timestamps_shadow_dict_list.setter
    def timestamps_shadow_dict_list(self, value: list[dict[str, Any]]) -> None:
        self._timeline.shadow_ts_list_ref = value

    @property
    def file_paths_whitelist(self) -> str | None:
        """Whitelist file path (for Toolbox delegation)."""
        return self._whitelist_path

    @file_paths_whitelist.setter
    def file_paths_whitelist(self, value: str | None) -> None:
        self._whitelist_path = value
        self._whitelist_patterns = None  # Force reload

    # =========================================================================
    # State Export
    # =========================================================================

    def get_state_dict(self) -> dict[str, Any]:
        """Get complete service state as dictionary for debugging."""
        return {
            "baseline_count": len(self._baseline),
            "noise_files_count": len(self._noise_files),
            "spotlight_files": self._spotlight_files.copy(),
            "spotlight_files_count": len(self._spotlight_files),
            "whitelist_path": self._whitelist_path,
            "whitelist_patterns_count": len(self._whitelist_patterns or []),
            "timeline_entries_count": len(self._timeline.get_entries()),
            "shadow_ts_list_count": len(self._timeline.get_shadow_ts_list()),
            "action_time": self._action_time,
            "action_duration": self._action_duration,
            "cache_valid": self._cache_valid,
            "scan_directories": self._scan_directories,
            "noise_processes_count": len(self._noise_processes),
            "other_output_data_collector_keys": list(
                self._other_output_data_collector.keys()
            ),
        }

    def reset(self) -> None:
        """Reset all forensic state."""
        self._baseline.clear()
        self._noise_files.clear()
        self._spotlight_files.clear()
        self._whitelist_patterns = None
        self._changed_files_cache.clear()
        self._cache_valid = False
        self._action_time = 0
        self._action_duration = 0
        self._noise_processes.clear()
        self._other_output_data_collector.clear()
        self._timeline.reset()
        self._logger.info("Reset forensic service state")


__all__ = [
    "ForensicService",
    "Snapshot",
    "TimelineEntry",
]
