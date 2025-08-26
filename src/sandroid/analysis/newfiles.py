import os
from logging import getLogger

from sandroid.core.toolbox import Toolbox

from .datagather import DataGather
from .static_analysis import StaticAnalysis

logger = getLogger(__name__)


class Bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class NewFiles(DataGather):
    """Handles the gathering and processing of new files detected in the system."""

    newFileListList = []

    def gather(self):
        """Gathers new files by comparing the current file list with the baseline."""
        newFiles = []
        changedFiles = Toolbox.fetch_changed_files()

        if len(Toolbox.baseline) == 0:
            logger.error("Baseline is empty. Baseline is not supposed to be empty.")

        logger.debug("Scanning for new files")
        for file in changedFiles:  # Get new files
            if file not in Toolbox.baseline:  # File is a new file
                newFiles.append(file)
        self.newFileListList.append(newFiles)
        logger.debug(str(len(newFiles)) + " New files discovered")
        logger.debug("New files found in this run: " + str(newFiles))

        logger.debug("Pulling unknown new files")
        for file in newFiles:
            # Create the target path where the file should be stored
            target_path = os.path.join(
                f"{os.getenv('RAW_RESULTS_PATH')}new_pull", file.lstrip("/")
            )

            # Check if the file already exists at this path
            if not os.path.exists(target_path):
                Toolbox.pull_file("new", file)

            # check for new apk files to auto analyse with asam might implement double check to check signature bytes of potential apks.
            if file.lower().endswith(".apk") and Toolbox.args.interative is True:
                asam = StaticAnalysis()
                asam.gather()
                asam.pretty_print()

    def return_data(self):
        """Returns the processed data of new files.

        :returns: Dictionary containing the new files.
        :rtype: dict
        """
        return {"New Files": self.process_data()}

    def pretty_print(self):
        """Returns a formatted string of the new files for display.

        :returns: Formatted string of new files.
        :rtype: str
        """
        true_new_files = self.process_data()
        result = (
            Bcolors.OKGREEN
            + Bcolors.BOLD
            + "\n—————————————————CREATED_FILES=(created in second run)—————————————————————————————————————————————————\n"
            + Bcolors.ENDC
            + Bcolors.OKGREEN
        )
        for entry in true_new_files:
            result = (
                result + Toolbox.highlight_timestamps(entry, Bcolors.OKGREEN) + "\n"
            )
        result = result + (
            Bcolors.BOLD
            + "———————————————————————————————————————————————————————————————————————————————————————————————————————\n"
            + Bcolors.ENDC
        )
        return result

    def process_data(self):
        """Processes the gathered data to filter out noise and identify true new files.
        Also keeps files in directories that consistently have new files across runs.
        Only includes files from the second run for the directory consistency logic.

        :returns: List of true new files.
        :rtype: list
        """
        # Get files that appear in all runs (original logic)
        files_from_all_pulls = self.newFileListList[0]
        noise = Toolbox.noise_files
        for fileList in self.newFileListList:
            files_from_all_pulls = list(set(files_from_all_pulls) & set(fileList))

        # New logic: Find directories that consistently have new files
        consistent_dirs = set()
        dir_counts = {}

        # Count how many runs each directory appears in
        for fileList in self.newFileListList:
            # Extract directories from this run's file list
            dirs_in_run = set()
            for file_path in fileList:
                directory = os.path.dirname(file_path)
                dirs_in_run.add(directory)

            # Update counts for each directory
            for directory in dirs_in_run:
                dir_counts[directory] = dir_counts.get(directory, 0) + 1

        # Directories that appear in all runs
        num_runs = len(self.newFileListList)
        for directory, count in dir_counts.items():
            if count == num_runs:
                consistent_dirs.add(directory)

        logger.debug(f"Directories with new files in every run: {consistent_dirs}")

        # Combine the original list with files from consistent directories
        # (but only from the second run)
        true_new_files = set(files_from_all_pulls)

        # Only use files from the second run (index 1)
        if len(self.newFileListList) > 1:  # Make sure there is a second run
            second_run_files = self.newFileListList[1]
            for file_path in second_run_files:
                directory = os.path.dirname(file_path)
                if directory in consistent_dirs:
                    true_new_files.add(file_path)

        # Apply noise filtering
        true_new_files = [
            x
            for x in true_new_files
            if x not in noise or x.endswith(".db") or x.endswith(".xml")
        ]

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
                if device_path not in true_new_files:
                    os.remove(os.path.join(root, file_name))

        true_new_files = Toolbox.exclude_whitelist(true_new_files)
        return true_new_files

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
