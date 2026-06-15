"""File Extraction Service for Sandroid.

This service handles pulling files from the Android device to the local
filesystem, computing file hashes, and managing file extraction operations.

Extracted from Toolbox class to follow Single Responsibility Principle.

Usage:
    from sandroid.services import get_file_extraction_service
    from sandroid.services.file_extraction_service import FileExtractionService

    # Get service
    extraction = get_file_extraction_service()

    # Pull a single file
    result = extraction.pull_file("/data/data/com.app/databases/app.db", "/tmp/app.db")

    # Pull multiple spotlight files
    results = extraction.pull_spotlight_files(["/data/test1.db", "/data/test2.db"])

    # Compute hash of local file
    hash_value = extraction.compute_hash("/tmp/app.db")
"""

import hashlib
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from sandroid.services.protocols import EventBusProtocol

# Import config with fallback for standalone usage
try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

logger = logging.getLogger(__name__)


@dataclass
class ExtractionResult:
    """Result of a file extraction operation.

    Attributes:
        source_path: Path of the file on the Android device
        local_path: Path where the file was saved locally
        success: Whether the extraction was successful
        error: Error message if extraction failed, None otherwise
        hash_sha256: SHA-256 hash of the extracted file, None if not computed
    """

    source_path: str
    local_path: str
    success: bool
    error: str | None = None
    hash_sha256: str | None = None


class AdbProtocol(Protocol):
    """Protocol for ADB dependency injection."""

    @staticmethod
    def send_adb_command(command: str) -> tuple[str, str]:
        """Send an ADB command and return (stdout, stderr)."""
        ...

    @staticmethod
    def pull_file(remote_path, local_path) -> tuple[str, str]:
        """Pull a file from the device (paths are shell-quoted internally)."""
        ...


def is_sqlite_file(file_path: str) -> bool:
    r"""Check if a file is a SQLite database by reading its magic header.

    SQLite databases have a distinctive 16-byte header starting with
    "SQLite format 3\\x00". This function reads the header to determine
    if a file is a SQLite database, regardless of its file extension.

    Args:
        file_path: The full path to the file to check.

    Returns:
        True if the file is a SQLite database, False otherwise.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
            return header.startswith(b"SQLite format 3\x00")
    except (FileNotFoundError, PermissionError, OSError) as e:
        logger.debug(f"Could not read file header for {file_path}: {e}")
        return False


class FileExtractionService:
    """Service for extracting files from Android devices.

    This service manages:
    - Pulling individual files from device
    - Pulling multiple spotlight files with hierarchy preservation
    - Pulling all files for a specific package
    - Computing file hashes (SHA-256)
    - Handling SQLite WAL and journal files

    Thread Safety:
        File operations should be performed from a single thread.
        Hash computation is thread-safe.

    Example:
        # With dependency injection (for testing)
        from unittest.mock import Mock
        mock_adb = Mock()
        service = FileExtractionService(adb=mock_adb)

        # Using default Adb class
        service = FileExtractionService()
        result = service.pull_file("/data/app.db", "/tmp/app.db")
    """

    # Default app data paths on Android (kept as fallback)
    _DEFAULT_APP_DATA_PATHS = [
        "/data/data/{package}",
        "/data/user/0/{package}",
        "/sdcard/Android/data/{package}",
    ]

    @classmethod
    def _get_app_data_paths(cls) -> list[str]:
        """Get app data paths from config with fallback.

        Returns:
            List of app data path templates with {package} placeholder.
        """
        try:
            if get_config is not None:
                return list(get_config().device_paths.app_data_paths)
        except Exception:
            pass
        return cls._DEFAULT_APP_DATA_PATHS.copy()

    # Keep class-level alias for backwards compatibility
    APP_DATA_PATHS = _DEFAULT_APP_DATA_PATHS

    # File extensions that typically have WAL/journal files
    SQLITE_EXTENSIONS = (".db", ".sqlite", ".sqlite3", ".db3")

    def __init__(
        self,
        adb: AdbProtocol | None = None,
        event_bus: EventBusProtocol | None = None,
        results_path: str | None = None,
    ):
        """Initialize the FileExtractionService.

        Args:
            adb: Optional ADB interface for dependency injection.
                 If not provided, uses the global Adb class.
            event_bus: Optional EventBus for publishing events.
            results_path: Base path for results (defaults to RESULTS_PATH env).
        """
        self._adb = adb
        self._event_bus = event_bus
        self._results_path = results_path or os.getenv("RESULTS_PATH", "./results/")
        self._logger = logger

    def _get_adb(self) -> AdbProtocol:
        """Get the ADB interface.

        Returns:
            The injected ADB interface or the global Adb class.
        """
        if self._adb is not None:
            return self._adb

        # Fall back to global Adb class
        from sandroid.core.adb import Adb

        return Adb

    # =========================================================================
    # File Pulling Operations
    # =========================================================================

    def pull_file(
        self,
        remote_path: str,
        local_path: str,
        compute_hash: bool = False,
    ) -> ExtractionResult:
        """Pull a single file from the Android device.

        Args:
            remote_path: Path of the file on the Android device.
            local_path: Path where the file should be saved locally.
            compute_hash: Whether to compute SHA-256 hash after extraction.

        Returns:
            ExtractionResult with details about the operation.
        """
        # Ensure parent directory exists
        local_dir = Path(local_path).parent
        local_dir.mkdir(parents=True, exist_ok=True)

        adb = self._get_adb()
        output, error = adb.pull_file(remote_path, local_path)

        # Check for common errors in combined output
        combined = str(output) + str(error)

        adb_error = self._detect_pull_error(combined, remote_path)
        if adb_error is not None:
            return ExtractionResult(
                source_path=remote_path,
                local_path=local_path,
                success=False,
                error=adb_error,
            )

        # Verify file was created
        if not os.path.exists(local_path):
            self._logger.error(f"File not created after pull: {local_path}")
            return ExtractionResult(
                source_path=remote_path,
                local_path=local_path,
                success=False,
                error="File not created after pull",
            )

        self._logger.info(f"Pulled {remote_path} to {local_path}")

        # Compute hash if requested
        hash_value = None
        if compute_hash:
            hash_value = self.compute_hash(local_path)

        return ExtractionResult(
            source_path=remote_path,
            local_path=local_path,
            success=True,
            hash_sha256=hash_value,
        )

    def pull_spotlight_files(
        self,
        files: list[str],
        output_dir: str | None = None,
        description: str | None = None,
        preserve_hierarchy: bool = True,
        compute_hash: bool = False,
        pull_sqlite_companions: bool = True,
    ) -> list[ExtractionResult]:
        """Pull multiple spotlight files from the device.

        Creates a timestamped subdirectory for the extraction. For SQLite
        database files, also pulls associated WAL and journal files.

        Args:
            files: List of file paths on the device to pull.
            output_dir: Base directory for output. Defaults to
                        RESULTS_PATH/spotlight_files.
            description: Optional description for the subdirectory name.
            preserve_hierarchy: Whether to preserve directory hierarchy
                                when multiple files are pulled.
            compute_hash: Whether to compute SHA-256 hashes.
            pull_sqlite_companions: Whether to pull WAL/journal files
                                    for SQLite databases.

        Returns:
            List of ExtractionResult for each file pulled.
        """
        if not files:
            self._logger.warning("No files provided to pull_spotlight_files")
            return []

        # Filter out WAL/journal files if they're handled separately
        from sandroid.services.forensic_utils import is_wal_or_journal

        filtered_files = [f for f in files if not is_wal_or_journal(f)]

        # Set up output directory
        base_dir = (
            Path(output_dir)
            if output_dir
            else Path(self._results_path) / "spotlight_files"
        )
        base_dir.mkdir(parents=True, exist_ok=True)

        # Create timestamped subdirectory
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        if description:
            pull_dir = base_dir / f"{timestamp}_{description.replace(' ', '_')}"
        else:
            pull_dir = base_dir / timestamp
        pull_dir.mkdir(parents=True, exist_ok=True)

        self._logger.info(
            f"Pulling {len(filtered_files)} spotlight files to {pull_dir}"
        )

        results = []
        for file_path in filtered_files:
            # Determine target path
            remote_path = Path(file_path.lstrip("/"))
            if preserve_hierarchy and len(filtered_files) > 1:
                target = pull_dir / remote_path
            else:
                target = pull_dir / remote_path.name

            # Pull the main file
            result = self.pull_file(
                remote_path=file_path,
                local_path=str(target),
                compute_hash=compute_hash,
            )
            results.append(result)

            # For SQLite files, pull companion files
            if pull_sqlite_companions and result.success:
                if is_sqlite_file(str(target)):
                    self._pull_sqlite_companions(
                        file_path,
                        str(target),
                        results,
                        compute_hash,
                    )

        self._logger.info(
            f"Pulled {sum(1 for r in results if r.success)}/{len(results)} files successfully"
        )
        return results

    def _pull_sqlite_companions(
        self,
        remote_base: str,
        local_base: str,
        results: list[ExtractionResult],
        compute_hash: bool,
    ) -> None:
        """Pull WAL and journal files for a SQLite database.

        Args:
            remote_base: Base path on device (without -wal/-journal suffix).
            local_base: Base local path.
            results: List to append results to.
            compute_hash: Whether to compute hashes.
        """
        for suffix in ("-wal", "-journal"):
            remote_companion = f"{remote_base}{suffix}"
            local_companion = f"{local_base}{suffix}"

            # Try to pull the companion file (don't log errors for missing)
            result = self._pull_file_silent(
                remote_path=remote_companion,
                local_path=local_companion,
                compute_hash=compute_hash,
            )

            if result.success:
                self._logger.info(f"Pulled SQLite companion: {remote_companion}")
                results.append(result)

    def _pull_file_silent(
        self,
        remote_path: str,
        local_path: str,
        compute_hash: bool = False,
    ) -> ExtractionResult:
        """Pull a file without logging errors for missing files.

        Used for optional companion files like WAL/journal.

        Args:
            remote_path: Path on device.
            local_path: Local destination.
            compute_hash: Whether to compute hash.

        Returns:
            ExtractionResult.
        """
        local_dir = Path(local_path).parent
        local_dir.mkdir(parents=True, exist_ok=True)

        adb = self._get_adb()
        output, error = adb.pull_file(remote_path, local_path)

        # Check if file exists
        from sandroid.core.adb_utils import detect_adb_pull_error

        pull_err = detect_adb_pull_error(output, error)
        if pull_err:
            return ExtractionResult(
                source_path=remote_path,
                local_path=local_path,
                success=False,
                error=pull_err,
            )

        if not os.path.exists(local_path):
            return ExtractionResult(
                source_path=remote_path,
                local_path=local_path,
                success=False,
                error="File not created",
            )

        hash_value = None
        if compute_hash:
            hash_value = self.compute_hash(local_path)

        return ExtractionResult(
            source_path=remote_path,
            local_path=local_path,
            success=True,
            hash_sha256=hash_value,
        )

    def pull_all_for_package(
        self,
        package: str,
        output_dir: str | None = None,
        compute_hash: bool = False,
    ) -> list[ExtractionResult]:
        """Pull all accessible files for a specific package.

        Searches common app data locations and pulls all files found.

        Args:
            package: The package name (e.g., "com.example.app").
            output_dir: Base directory for output. Defaults to
                        RESULTS_PATH/package_files/{package}.
            compute_hash: Whether to compute SHA-256 hashes.

        Returns:
            List of ExtractionResult for each file pulled.
        """
        if not package:
            self._logger.error("No package name provided")
            return []

        # Set up output directory
        base_dir = (
            Path(output_dir)
            if output_dir
            else Path(self._results_path) / "package_files" / package
        )
        base_dir.mkdir(parents=True, exist_ok=True)

        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        pull_dir = base_dir / timestamp
        pull_dir.mkdir(parents=True, exist_ok=True)

        self._logger.info(f"Pulling all files for package {package} to {pull_dir}")

        results = []
        adb = self._get_adb()

        for path_template in self._get_app_data_paths():
            app_path = path_template.format(package=package)

            # List files in this directory
            output, error = adb.send_adb_command(
                f"shell find {app_path} -type f 2>/dev/null"
            )

            if not output or "No such file" in str(output) or error:
                continue

            files = [f.strip() for f in output.strip().split("\n") if f.strip()]
            self._logger.info(f"Found {len(files)} files in {app_path}")

            for file_path in files:
                # Determine target path (preserve hierarchy under the app path)
                relative_path = file_path.replace(app_path, "").lstrip("/")
                target = (
                    pull_dir / app_path.lstrip("/").replace("/", "_") / relative_path
                )

                result = self.pull_file(
                    remote_path=file_path,
                    local_path=str(target),
                    compute_hash=compute_hash,
                )
                results.append(result)

                # Pull SQLite companions
                if result.success and is_sqlite_file(str(target)):
                    self._pull_sqlite_companions(
                        file_path,
                        str(target),
                        results,
                        compute_hash,
                    )

        self._logger.info(
            f"Pulled {sum(1 for r in results if r.success)}/{len(results)} files for {package}"
        )
        return results

    def _detect_pull_error(self, combined_output: str, remote_path: str) -> str | None:
        """Detect common ADB pull errors from combined stdout/stderr.

        Args:
            combined_output: Combined stdout + stderr from ADB pull command.
            remote_path: The remote path being pulled (for log messages).

        Returns:
            Error message string if an error was detected, None otherwise.
        """
        from sandroid.core.adb_utils import detect_adb_pull_error

        err = detect_adb_pull_error(combined_output, "")
        if err:
            self._logger.warning(f"ADB pull error for {remote_path}: {err}")
        return err

    # =========================================================================
    # Hash Computation
    # =========================================================================

    def compute_hash(self, file_path: str, algorithm: str = "sha256") -> str:
        """Compute the hash of a local file.

        Args:
            file_path: Path to the local file.
            algorithm: Hash algorithm to use ("sha256", "md5", "sha1").

        Returns:
            Hexadecimal hash string, or empty string if file cannot be read.
        """
        if not os.path.exists(file_path):
            self._logger.warning(f"Cannot compute hash: file not found: {file_path}")
            return ""

        try:
            hasher = hashlib.new(algorithm)
            with open(file_path, "rb") as f:
                # Read in chunks for large files
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            self._logger.error(f"Error computing hash for {file_path}: {e}")
            return ""

    def compute_hashes_batch(
        self,
        file_paths: list[str],
        algorithm: str = "sha256",
    ) -> dict[str, str]:
        """Compute hashes for multiple files.

        Args:
            file_paths: List of local file paths.
            algorithm: Hash algorithm to use.

        Returns:
            Dictionary mapping file paths to their hash values.
        """
        results = {}
        for file_path in file_paths:
            results[file_path] = self.compute_hash(file_path, algorithm)
        return results

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def get_results_path(self) -> str:
        """Get the configured results path.

        Returns:
            The base results path.
        """
        return self._results_path

    def set_results_path(self, path: str) -> None:
        """Set the base results path.

        Args:
            path: New results path.
        """
        self._results_path = path
        self._logger.info(f"Set results path to: {path}")

    def file_exists_on_device(self, remote_path: str) -> bool:
        """Check if a file exists on the device.

        Args:
            remote_path: Path on the device to check.

        Returns:
            True if file exists, False otherwise.
        """
        adb = self._get_adb()
        output, _error = adb.send_adb_command(
            f"shell test -f {remote_path} && echo EXISTS"
        )

        return "EXISTS" in str(output)

    def get_file_size_on_device(self, remote_path: str) -> int:
        """Get the size of a file on the device.

        Args:
            remote_path: Path on the device.

        Returns:
            File size in bytes, or -1 if file not found.
        """
        adb = self._get_adb()
        output, _error = adb.send_adb_command(
            f"shell stat -c %s {remote_path} 2>/dev/null"
        )

        try:
            return int(output.strip())
        except (ValueError, AttributeError):
            return -1

    def pull_file_legacy(self, number: str, file_to_pull: str) -> None:
        """Pull a file from the emulator preserving directory structure.

        Legacy API compatible with Toolbox.pull_file signature.
        Creates a target directory based on RAW_RESULTS_PATH and the pull ID.

        Args:
            number: The pull id, used as the folder name (e.g., "first", "second", "noise").
            file_to_pull: The file path on the emulator to pull.
        """
        raw_results = os.getenv("RAW_RESULTS_PATH", "")

        # Create the target directory structure if it doesn't exist
        target_dir = os.path.join(
            f"{raw_results}{number}_pull",
            os.path.dirname(file_to_pull.lstrip("/")),
        )
        os.makedirs(target_dir, exist_ok=True)

        # Build the full target path
        target_path = os.path.join(
            f"{raw_results}{number}_pull",
            file_to_pull.lstrip("/"),
        )

        # Pull the file
        adb = self._get_adb()
        output, error = adb.pull_file(file_to_pull, target_path)

        # Handle common errors
        from sandroid.core.adb_utils import detect_adb_pull_error

        pull_err = detect_adb_pull_error(output, error)
        if pull_err:
            self._logger.warning(f"Pull error for {file_to_pull}: {pull_err}")

    # =========================================================================
    # Hash Calculation for Analysis Results
    # =========================================================================

    def calculate_hashes(self) -> dict[str, Any]:
        """Calculate MD5 hashes for new and changed files from forensic analysis.

        Processes files from analysis snapshots:
        - new_pull: Newly created files
        - first_pull: Files before changes
        - second_pull: Files after changes

        Filters out noise files that naturally change during analysis.

        Returns:
            Dictionary with structure:
            {
                "new_file_hashes": {filename: md5_hash, ...},
                "changed_file_hashes(old,new)": {filename: [old_hash, new_hash], ...}
            }
        """
        self._logger.info("Calculating Hashes")

        base_folder = Path(os.getenv("RAW_RESULTS_PATH", ""))
        hashes: dict[str, Any] = {}
        new_file_hashes: dict[str, str] = {}  # path : hash
        change_file_hashes: dict[str, list] = {}  # path : [old_hash, new_hash]

        new_pull = base_folder / "new_pull"
        noise_pull = base_folder / "noise_pull"
        first_pull = base_folder / "first_pull"
        second_pull = base_folder / "second_pull"

        # Build set of noise files to exclude
        noise_files = (
            {f.name for f in noise_pull.iterdir()} if noise_pull.exists() else set()
        )

        # Process newly created files
        if new_pull.exists():
            for file_path in new_pull.iterdir():
                if file_path.name in noise_files:
                    continue
                data = file_path.read_bytes()
                self._logger.debug(f"Hashing {file_path.name}")
                new_file_hashes[file_path.name] = hashlib.md5(data).hexdigest()

        # Process old versions of changed files
        if first_pull.exists():
            for file_path in first_pull.iterdir():
                if file_path.name in noise_files:
                    continue
                data = file_path.read_bytes()
                self._logger.debug(f"Hashing old version of {file_path.name}")
                change_file_hashes[file_path.name] = [
                    hashlib.md5(data).hexdigest(),
                    "n/a",
                ]

        # Process new versions of changed files
        if second_pull.exists():
            for file_path in second_pull.iterdir():
                if file_path.name in noise_files:
                    continue
                data = file_path.read_bytes()
                self._logger.debug(f"Hashing new version of {file_path.name}")
                if file_path.name in change_file_hashes:
                    change_file_hashes[file_path.name][1] = hashlib.md5(
                        data
                    ).hexdigest()
                else:
                    change_file_hashes[file_path.name] = [
                        "n/a",
                        hashlib.md5(data).hexdigest(),
                    ]

        hashes["new_file_hashes"] = new_file_hashes
        hashes["changed_file_hashes(old,new)"] = change_file_hashes

        return hashes

    def pull_and_hash_apks(self) -> dict[str, Any]:
        """Pull APKs from the emulator and calculate their MD5 hashes.

        Queries all packages on the device, pulls each APK, computes its hash,
        and deletes the local copy after hashing.

        Returns:
            Dictionary with structure:
            {
                "apk_hashes": ["com.package: hash1", "com.package2: hash2", ...]
            }
        """
        self._logger.info("Pulling and hashing APKs")

        base_folder = Path(os.getenv("RAW_RESULTS_PATH", ""))
        list_of_all_packages = []
        names_and_hashes = []

        adb = self._get_adb()

        # Get list of all packages on device
        stdout, stderr = adb.send_adb_command("shell pm list packages")
        for package in stdout.split("\n"):
            if package:
                # Remove "package:" prefix
                list_of_all_packages.append(package[8:])

        # For each package: pull it, get its hash, delete it
        for package in list_of_all_packages:
            package_path, _stderr = adb.send_adb_command("shell pm path " + package)
            # Remove "package:" prefix and trailing newline
            package_path = package_path[8:-1]
            apk_file = base_folder / f"{package}.apk"

            adb.pull_file(package_path, apk_file)

            if apk_file.exists():
                data = apk_file.read_bytes()
                self._logger.debug(f"Hashing apk {package}")
                names_and_hashes.append(f"{package}: {hashlib.md5(data).hexdigest()}")
                apk_file.unlink()
            else:
                self._logger.error(
                    f"Something went wrong looking for a package: {package}"
                )
                names_and_hashes.append(f"{package}: n/a")

        return {"apk_hashes": names_and_hashes}

    # =========================================================================
    # Action Export
    # =========================================================================

    def export_action(
        self,
        snapshot_name: str = "tmp",
        device_name: str = "",
        user_input_callback=None,
    ) -> bool:
        """Export a snapshot and recording as an action archive.

        Creates a .action archive containing the snapshot and recording.txt file.
        This allows actions to be exported and replayed on other emulators.

        Args:
            snapshot_name: Name of the snapshot to export (default: "tmp").
            device_name: Name of the Android device (for snapshot path).
            user_input_callback: Optional callback to get user input for action name.
                                 If None, uses safe_input from UIService.

        Returns:
            True if export was successful, False otherwise.
        """
        import shutil

        raw_results_path = os.getenv("RAW_RESULTS_PATH", "")
        recording_path = os.path.join(raw_results_path, "recording.txt")
        snapshot_path = os.path.join(
            os.path.expanduser("~"),
            ".android",
            "avd",
            f"{device_name}.avd",
            "snapshots",
            snapshot_name,
        )

        self._logger.debug(f'Exporting snapshot "{snapshot_name}"')

        # Check if recording exists
        if not os.path.exists(recording_path):
            self._logger.error("No recording currently loaded")
            return False

        # Check if snapshot exists
        if not os.path.exists(snapshot_path):
            self._logger.error(
                "No snapshot exists, a snapshot has to be part of the export"
            )
            return False

        # Get action name from user
        if user_input_callback:
            action_name = user_input_callback("Name your action for export: ")
        else:
            # Try to get from UIService
            try:
                from sandroid.services import get_ui_service

                action_name = get_ui_service().safe_input(
                    "Name your action for export: "
                )
            except ImportError:
                action_name = input("Name your action for export: ").strip()

        if not action_name:
            self._logger.error("No action name provided")
            return False

        # Check if action already exists
        if os.path.exists(f"{action_name}.action"):
            self._logger.error(
                "An action with this name already exists, choose a different name"
            )
            return False

        try:
            # Copy snapshot directory
            shutil.copytree(snapshot_path, action_name)

            # Copy recording file
            shutil.copy(recording_path, action_name)

            # Create archive
            shutil.make_archive(action_name, "zip", action_name)

            # Rename to .action
            os.rename(f"{action_name}.zip", f"{action_name}.action")

            # Clean up temp directory
            shutil.rmtree(action_name)

            self._logger.info("Action successfully exported.")
            return True

        except Exception as e:
            self._logger.error(f"Failed to export action: {e}")
            # Clean up on failure
            if os.path.exists(action_name):
                shutil.rmtree(action_name, ignore_errors=True)
            if os.path.exists(f"{action_name}.zip"):
                os.remove(f"{action_name}.zip")
            return False


__all__ = [
    "ExtractionResult",
    "FileExtractionService",
    "is_sqlite_file",
]
