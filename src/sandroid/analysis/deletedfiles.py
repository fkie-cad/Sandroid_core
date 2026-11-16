"""Module for gathering and processing information on deleted files.

This module provides the DeletedFiles class which detects files that have been
deleted from the Android device by comparing the current filesystem state against
a baseline.
"""

from __future__ import annotations

from logging import getLogger
from typing import Any

from .base_di import DataGatherBase
from .filters import filter_noise_files, intersect_file_lists

logger = getLogger(__name__)


class DeletedFiles(DataGatherBase):
    """Class for gathering and processing information on deleted files.

    Inherits from :class:`DataGatherBase` and provides methods to gather, process,
    and display information about deleted files.

    This class supports dependency injection for testing while maintaining
    backward compatibility. When instantiated without arguments, it uses
    the default Toolbox-based services via the base class.

    Example usage (backward compatible):
        >>> deleted = DeletedFiles()
        >>> deleted.gather()
        >>> data = deleted.return_data()

    Example usage (with dependency injection for testing):
        >>> mock_service = MockForensicService()
        >>> deleted = DeletedFiles(forensic_service=mock_service)
        >>> deleted.gather()
    """

    # Class-level storage for deleted files across multiple runs
    # Note: This is shared across all instances for backward compatibility
    deletedFileListList: list[list[str]] = []

    def __init__(self, **kwargs) -> None:
        """Initialize the DeletedFiles instance.

        :param kwargs: Optional dependencies for injection (forensic_service, adb, etc.)
            When not provided, uses the default Toolbox-based services via base class.
        """
        super().__init__(**kwargs)
        # Files deleted during the dry run (no app action): background cleanup
        # such as Play Store cache logs, subtracted from the results.
        self.noise_deleted_files: set[str] = set()

    def _fetch_all_files(self) -> dict[str, Any]:
        """Fetch all current files from the device.

        :returns: Dictionary of all current files on the device.
        :rtype: dict
        """
        return self._get_toolbox().fetch_changed_files(fetch_all=True)

    def gather(self) -> None:
        """Gather information on deleted files.

        This method pulls the entire filesystem and compares it to the baseline
        to identify deleted files.
        """
        logger.debug(
            "Gathering information on deleted files, pulling entire filesystem and comparing to baseline"
        )

        deletedFiles: list[str] = []
        allFiles = self._fetch_all_files()
        baseline = self._get_baseline()

        if len(baseline) == 0:
            logger.error("Baseline is empty. Baseline is not supposed to be empty.")

        for file in baseline:  # Get deleted files
            if file not in allFiles:
                deletedFiles.append(file)
                # Only a candidate: most vanish from the result after the
                # cross-run intersection and noise subtraction, so keep the
                # per-file detail at DEBUG (the engine logs the final count).
                logger.debug("Deleted-file candidate: %s", file)
        if self._get_toolbox().is_dry_run():
            self.noise_deleted_files.update(deletedFiles)
        else:
            self.deletedFileListList.append(deletedFiles)
        logger.debug(
            "%d deleted-file candidate(s) in this %s (before noise filtering)",
            len(deletedFiles),
            "dry run" if self._get_toolbox().is_dry_run() else "run",
        )

    def return_data(self) -> dict[str, list[str]]:
        """Return processed data on deleted files.

        :returns: A dictionary containing the list of deleted files.
        :rtype: dict
        """
        return {"Deleted Files": self.process_data()}

    def pretty_print(self) -> str:
        """Pretty print the list of deleted files.

        :returns: A formatted string with the list of deleted files highlighted.
        :rtype: str
        """
        deletedFiles = self.process_data()
        result = (
            "[success bold]"
            "\n—————————————————DELETED_FILES=(compared to baseline)—————————————————————————————————————————————————\n"
            "[/success bold][success]"
        )
        for entry in deletedFiles:
            result = result + self._highlight_timestamps(entry, "[success]") + "\n"
        result = result + (
            "[bold]"
            "———————————————————————————————————————————————————————————————————————————————————————————————————————\n"
            "[/bold]"
        )
        return result

    def process_data(self) -> list[str]:
        """Process the gathered data to filter out noise and identify consistently deleted files.

        :returns: A list of files that have been consistently deleted across all pulls.
        :rtype: list
        """
        # Use shared filter utilities to reduce code duplication
        files_from_all_pulls = intersect_file_lists(self.deletedFileListList)
        files_from_all_pulls = [
            f for f in files_from_all_pulls if f not in self.noise_deleted_files
        ]
        files_from_all_pulls = filter_noise_files(
            files_from_all_pulls,
            self._get_noise_files(),
            preserve_sqlite_xml=True,
        )
        files_from_all_pulls = self._exclude_whitelist(files_from_all_pulls)
        return self._apply_system_noise(files_from_all_pulls)
