import os
from logging import getLogger

from sandroid.core import file_diff
from sandroid.core.toolbox import Toolbox

from .datagather import DataGather

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


class ChangedFiles(DataGather):
    """A class to gather and process changed files, inheriting from DataGather.

    **Attributes:**

    - **fileListList** (*list*): List of lists containing changed files.
    - **logger** (*Logger*): Logger instance for logging information.

    **Methods:**

    - **gather()**: Gathers changed files and filters out new files.
    - **return_data()**: Returns a dictionary with the changed files and their diffs.
    - **pretty_print()**: Returns a formatted string of the changed files and their diffs.
    - **process_data()**: Processes the gathered data to filter out noise and whitelist files.
    """

    fileListList = []

    def gather(self):
        """Gathers changed files and filters out new files.

        **Raises:**

        - **FileNotFoundError**: If a file is not found during processing.
        """
        logger.debug(
            "ChangedFiles object gathering data. Going to have "
            + str(len(self.fileListList) + 1)
            + " dataset(s)"
        )
        if Toolbox.is_dry_run():
            Toolbox.noise_files = Toolbox.fetch_changed_files()
        else:
            # self.fileListList.append(Toolbox.fetch_changed_files())
            # Filter out new files real quick
            changed_and_new = Toolbox.fetch_changed_files()
            changed_files = []
            for file in changed_and_new:
                if file in Toolbox.baseline:
                    changed_files.append(file)
            self.fileListList.append(changed_files)

    def return_data(self):
        """Returns a dictionary with the changed files and their diffs.

        **Returns:**

        - **dict**: A dictionary with the key "Changed Files" and a list of changed files and their diffs.
        """
        base_folder = os.getenv("RAW_RESULTS_PATH")
        result = []
        files_from_all_pulls = self.process_data()

        for file in files_from_all_pulls:
            try:
                if file[-3:] == ".db":
                    path_to_file_first_pull = os.path.join(
                        f"{base_folder}first_pull", file.lstrip("/")
                    )
                    path_to_file_second_pull = os.path.join(
                        f"{base_folder}second_pull", file.lstrip("/")
                    )
                    path_to_file_noise_pull = os.path.join(
                        f"{base_folder}noise_pull", file.lstrip("/")
                    )
                    diff = file_diff.db_diff(
                        path_to_file_first_pull,
                        path_to_file_second_pull,
                        path_to_file_noise_pull,
                    )
                    if "ITS ALL NOISE" not in diff:
                        result.append({file: diff.splitlines()})
                elif file[-4:] == ".xml":
                    diff = file_diff.xml_diff(
                        f"{base_folder}first_pull/{file}",
                        f"{base_folder}second_pull/{file}",
                        f"{base_folder}noise_pull/{file}",
                    )
                    if "ITS ALL NOISE" not in diff:
                        result.append({file: diff.splitlines()})
                elif file[-4:] == ".txt":
                    diff = file_diff.txt_diff(file)
                    if "ITS ALL NOISE" not in diff:
                        result.append({file: diff.splitlines()})
                else:
                    result.append(file)
            except FileNotFoundError:
                result.append(file)
        return {"Changed Files": result}

    def pretty_print(self):
        """Returns a formatted string of the changed files and their diffs.

        **Returns:**

        - **str**: A formatted string of the changed files and their diffs.
        """
        base_folder = os.getenv("RAW_RESULTS_PATH")
        files_from_all_pulls = self.process_data()
        result = (
            Bcolors.OKBLUE
            + Bcolors.BOLD
            + "\n—————————————————CHANGED_FILES=(changed in all runs)——————————————————————————————————————————————————\n"
            + Bcolors.ENDC
            + Bcolors.OKBLUE
        )
        for file in files_from_all_pulls:
            try:
                if file[-3:] == ".db":
                    path_to_file_first_pull = os.path.join(
                        f"{base_folder}first_pull", file.lstrip("/")
                    )
                    path_to_file_second_pull = os.path.join(
                        f"{base_folder}second_pull", file.lstrip("/")
                    )
                    path_to_file_noise_pull = os.path.join(
                        f"{base_folder}noise_pull", file.lstrip("/")
                    )
                    diff = file_diff.db_diff(
                        path_to_file_first_pull,
                        path_to_file_second_pull,
                        path_to_file_noise_pull,
                    )
                    diff = (
                        Toolbox.highlight_timestamps(
                            Toolbox.truncate(diff), Bcolors.OKCYAN
                        )
                        + Bcolors.OKBLUE
                        + "\n"
                    )
                    if "ITS ALL NOISE" not in diff:
                        result = result + (Bcolors.OKCYAN + file + "\n")
                        result = result + diff
                elif file[-4:] == ".xml":
                    diff = (
                        Toolbox.highlight_timestamps(
                            Toolbox.truncate(
                                file_diff.xml_diff(
                                    f"{base_folder}first_pull/{file}",
                                    f"{base_folder}second_pull/{file}",
                                    f"{base_folder}noise_pull/{file}",
                                )
                            ),
                            Bcolors.OKCYAN,
                        )
                        + Bcolors.OKBLUE
                        + "\n"
                    )
                    if "ITS ALL NOISE" not in diff:
                        result = result + (Bcolors.OKCYAN + file + "\n")
                        result = result + diff
                elif file[-4:] == ".txt":
                    diff = (
                        Toolbox.highlight_timestamps(
                            Toolbox.truncate(file_diff.txt_diff(file)), Bcolors.OKCYAN
                        )
                        + Bcolors.OKBLUE
                        + "\n"
                    )
                    if "ITS ALL NOISE" not in diff:
                        result = result + (Bcolors.OKCYAN + file + "\n")
                        result = result + diff
                else:
                    result = (
                        result
                        + Toolbox.highlight_timestamps(
                            Toolbox.truncate(file), Bcolors.OKBLUE
                        )
                        + "\n"
                    )
            except FileNotFoundError:
                result = (
                    result
                    + "Changed but could not be pulled for intra file change detection (see warnings or errors during pull above): "
                    + file
                    + "\n"
                )
        result = result + (
            Bcolors.BOLD
            + "———————————————————————————————————————————————————————————————————————————————————————————————————————\n"
            + Bcolors.ENDC
        )
        return result

    def process_data(self):
        """Processes the gathered data to filter out noise and whitelist files.

        **Returns:**

        - **list**: A list of files that are in all lists and not in the noise list.
        """
        # intersect the first list with all other lists, leaving only the files that are in all lists
        files_from_all_pulls = self.fileListList[0]
        noise = Toolbox.noise_files
        for fileList in self.fileListList:
            files_from_all_pulls = list(set(files_from_all_pulls) & set(fileList))
        files_from_all_pulls = [
            x
            for x in files_from_all_pulls
            if x not in noise or x.endswith(".db") or x.endswith(".xml")
        ]  # filter noise from files, ignore .db and .xml files

        files_from_all_pulls = Toolbox.exclude_whitelist(files_from_all_pulls)
        return files_from_all_pulls
