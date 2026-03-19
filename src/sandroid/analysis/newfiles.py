import os
from logging import getLogger

from sandroid.core.events.events import FileChanged

from .base_di import DataGatherBase
from .filters import filter_noise_files, intersect_file_lists
from .static_analysis import StaticAnalysis

logger = getLogger(__name__)


class NewFiles(DataGatherBase):
    """Handles the gathering and processing of new files detected in the system.

    This class supports dependency injection for testing purposes while maintaining
    backwards compatibility with the existing Toolbox-based implementation.

    Args:
        **kwargs: Keyword arguments passed to DataGatherBase, including:
            forensic_service: Optional service for forensic operations
            adb: Optional service for ADB operations
            config: Optional configuration object
            logger: Optional logger instance
    """

    # Class-level storage for backwards compatibility
    # Note: Instance-level _new_file_list_list is preferred for new code
    newFileListList: list[list[str]] = []

    def __init__(self, **kwargs) -> None:
        """Initialize NewFiles with optional dependency injection.

        Args:
            **kwargs: Keyword arguments passed to DataGatherBase
        """
        super().__init__(**kwargs)
        # Instance-level list for better isolation in tests
        self._new_file_list_list: list[list[str]] = []
        # Track whether we're using shared class state (backwards compat) or instance state
        self._use_instance_state = (
            self.forensic_service is not None or self.adb is not None
        )

    def _get_new_file_list_list(self) -> list[list[str]]:
        """Get the appropriate new file list list based on usage mode."""
        if self._use_instance_state:
            return self._new_file_list_list
        return NewFiles.newFileListList

    def _append_new_files(self, new_files: list[str]) -> None:
        """Append new files to the appropriate list based on usage mode."""
        if self._use_instance_state:
            self._new_file_list_list.append(new_files)
        else:
            NewFiles.newFileListList.append(new_files)

    def gather(self) -> None:
        """Gathers new files by comparing the current file list with the baseline."""
        new_files: list[str] = []
        changed_files = self._fetch_changed_files()
        baseline = self._get_baseline()

        if len(baseline) == 0:
            logger.error("Baseline is empty. Baseline is not supposed to be empty.")

        logger.debug("Scanning for new files")
        for file in changed_files:  # Get new files
            if file not in baseline:  # File is a new file
                new_files.append(file)
                # Publish event for newly detected file
                FileChanged(
                    file_path=file, change_type="created", source="newfiles"
                ).publish()
        self._append_new_files(new_files)
        logger.debug(str(len(new_files)) + " New files discovered")
        logger.debug("New files found in this run: " + str(new_files))

        logger.debug("Pulling unknown new files")
        for file in new_files:
            # Create the target path where the file should be stored
            target_path = os.path.join(
                f"{os.getenv('RAW_RESULTS_PATH')}new_pull", file.lstrip("/")
            )

            # Check if the file already exists at this path
            if not os.path.exists(target_path):
                self._pull_file("new", file)

            # check for new apk files to auto analyse with asam might implement double check to check signature bytes of potential apks.
            args = self._get_toolbox().args
            if (
                file.lower().endswith(".apk")
                and args is not None
                and getattr(args, "interative", False) is True
            ):
                asam = StaticAnalysis()
                asam.gather()
                asam.pretty_print()

    def return_data(self) -> dict[str, list[str]]:
        """Returns the processed data of new files.

        :returns: Dictionary containing the new files.
        :rtype: dict
        """
        return {"New Files": self.process_data()}

    def pretty_print(self) -> str:
        """Returns a formatted string of the new files for display.

        :returns: Formatted string of new files.
        :rtype: str
        """
        true_new_files = self.process_data()
        result = (
            "[success bold]"
            "\n—————————————————CREATED_FILES=(created in second run)—————————————————————————————————————————————————\n"
            "[/success bold][success]"
        )
        for entry in true_new_files:
            result = result + self._highlight_timestamps(entry, "[success]") + "\n"
        result = result + (
            "[bold]"
            "———————————————————————————————————————————————————————————————————————————————————————————————————————\n"
            "[/bold]"
        )
        return result

    def process_data(self) -> list[str]:
        """Processes the gathered data to filter out noise and identify true new files.
        Also keeps files in directories that consistently have new files across runs.
        Only includes files from the second run for the directory consistency logic.

        :returns: List of true new files.
        :rtype: list
        """
        new_file_list_list = self._get_new_file_list_list()

        # Get files that appear in all runs (using shared filter utilities)
        files_from_all_pulls = intersect_file_lists(new_file_list_list)
        noise = self._get_noise_files()

        # New logic: Find directories that consistently have new files
        consistent_dirs: set = set()
        dir_counts: dict[str, int] = {}

        # Count how many runs each directory appears in
        for file_list in new_file_list_list:
            # Extract directories from this run's file list
            dirs_in_run: set = set()
            for file_path in file_list:
                directory = os.path.dirname(file_path)
                dirs_in_run.add(directory)

            # Update counts for each directory
            for directory in dirs_in_run:
                dir_counts[directory] = dir_counts.get(directory, 0) + 1

        # Directories that appear in all runs
        num_runs = len(new_file_list_list)
        for directory, count in dir_counts.items():
            if count == num_runs:
                consistent_dirs.add(directory)

        logger.debug(f"Directories with new files in every run: {consistent_dirs}")

        # Combine the original list with files from consistent directories
        # (but only from the second run)
        true_new_files: set = set(files_from_all_pulls)

        # Only use files from the second run (index 1)
        if len(new_file_list_list) > 1:  # Make sure there is a second run
            second_run_files = new_file_list_list[1]
            for file_path in second_run_files:
                directory = os.path.dirname(file_path)
                if directory in consistent_dirs:
                    true_new_files.add(file_path)

        # Apply noise filtering using shared utilities
        true_new_files_list = filter_noise_files(
            list(true_new_files),
            noise,
            preserve_sqlite_xml=True,
        )

        logger.debug(
            "Searching for and if necessary deleting new files that were wrongly pulled"
        )

        # Clean up files that shouldn't be there
        for root, dirs, files in os.walk(f"{os.getenv('RAW_RESULTS_PATH')}new_pull"):
            for file_name in files:
                # Reconstruct the relative path from the pull directory
                rel_path = os.path.join(root, file_name).replace(
                    f"{os.getenv('RAW_RESULTS_PATH')}new_pull/", ""
                )
                # Convert to device path format for comparison
                device_path = "/" + rel_path
                if device_path not in true_new_files_list:
                    os.remove(os.path.join(root, file_name))

        true_new_files_list = self._exclude_whitelist(true_new_files_list)
        return true_new_files_list

    """This is old, not quite OOP translated code that was supposed to detect if a new file was created but in a different directory each run.
    I am skipping this special case for now, but I'll leave the code here just in case

    def process_data(self):
        new_dirs_list_list = []
        for newFileList in self.newFileListList:
            new_dirs_list = []
            for newFile in newFileList:
                dirs = newFile.split("/")
                dirs.pop()  # <-------------------------- ADD ANOTHER POP HERE TO MAKE DETECTION CATCH MORE CASES (keep same number here and in test below)
                directory = '/'.join(dirs)
                new_dirs_list.append(directory)
            new_dirs_list_list.append(new_dirs_list)
        dir_whitelist = new_dirs_list_list[0]
        for dirList in new_dirs_list_list:
            dir_whitelist = list(set(dir_whitelist) & set(dirList))
        true_new_files = []
        for newFile in newFileListList[1]:  # new files in second run
            dirs = newFile.split("/")
            dirs.pop()
            directory = '/'.join(dirs)
            if directory in dir_whitelist and newFile not in noise:
                true_new_files.append(newFile)

        for file in fileListList[1]:
            if file not in true_new_files and file not in files_from_all_pulls:
                noise.update({file: ""})
    """
