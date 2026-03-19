import os
from logging import getLogger
from typing import Any

from sandroid.core import file_diff
from sandroid.core.events.events import FileChanged
from sandroid.core.toolbox import Toolbox

from .base_di import AdbProtocol, DataGatherBase, ForensicServiceProtocol
from .filters import filter_noise_files, intersect_file_lists

logger = getLogger(__name__)


class ChangedFiles(DataGatherBase):
    """A class to gather and process changed files, inheriting from DataGatherBase.

    This class supports optional dependency injection for testing while maintaining
    backwards compatibility with the existing Toolbox-based approach.

    **Attributes:**

    - **fileListList** (*list*): List of lists containing changed files.
    - **logger** (*Logger*): Logger instance for logging information.
    - **forensic_service** (*Optional[ForensicServiceProtocol]*): Injected forensic service for testing.
    - **adb** (*Optional[AdbProtocol]*): Injected ADB interface for testing.

    **Methods:**

    - **gather()**: Gathers changed files and filters out new files.
    - **return_data()**: Returns a dictionary with the changed files and their diffs.
    - **pretty_print()**: Returns a formatted string of the changed files and their diffs.
    - **process_data()**: Processes the gathered data to filter out noise and whitelist files.

    **Example (backwards compatible - no changes needed):**

        changed_files = ChangedFiles()
        changed_files.gather()
        data = changed_files.return_data()

    **Example (with dependency injection for testing):**

        mock_forensic_service = Mock()
        mock_forensic_service.get_baseline.return_value = {"/data/file.db": "hash1"}
        mock_forensic_service.get_noise_files.return_value = {}

        changed_files = ChangedFiles(forensic_service=mock_forensic_service)
        changed_files.gather()
    """

    fileListList: list[list[str]] = []

    def __init__(
        self,
        forensic_service: ForensicServiceProtocol | None = None,
        adb: AdbProtocol | None = None,
        **kwargs,
    ) -> None:
        """Initialize ChangedFiles with optional dependency injection.

        Args:
            forensic_service: Optional forensic service for file tracking.
                If None, falls back to Toolbox static methods/attributes.
            adb: Optional ADB interface for device communication.
                If None, falls back to global Adb class.
            **kwargs: Additional arguments passed to DataGatherBase.
        """
        super().__init__(forensic_service=forensic_service, adb=adb, **kwargs)
        # Reset fileListList for each instance to avoid state leakage
        self.fileListList = []

    def gather(self) -> None:
        """Gathers changed files and filters out new files.

        **Raises:**

        - **FileNotFoundError**: If a file is not found during processing.
        """
        logger.debug(
            "ChangedFiles object gathering data. Going to have "
            + str(len(self.fileListList) + 1)
            + " dataset(s)"
        )
        if self._get_toolbox().is_dry_run():
            self._get_toolbox().noise_files = self._fetch_changed_files()
        else:
            # Filter out new files real quick
            changed_and_new = self._fetch_changed_files()
            baseline = self._get_baseline()
            changed_files = []
            for file in changed_and_new:
                if file in baseline:
                    changed_files.append(file)
                    # Publish event for each changed file detected
                    FileChanged(
                        file_path=file, change_type="modified", source="changedfiles"
                    ).publish()
            self.fileListList.append(changed_files)

    def return_data(self) -> dict[str, list[Any]]:
        """Returns a dictionary with the changed files and their diffs.

        **Returns:**

        - **dict**: A dictionary with the key "Changed Files" and a list of changed files and their diffs.
        """
        base_folder = self._get_raw_results_path()
        result = []
        files_from_all_pulls = self.process_data()

        for file in files_from_all_pulls:
            try:
                path_to_file_first_pull = os.path.join(
                    f"{base_folder}first_pull", file.lstrip("/")
                )
                path_to_file_second_pull = os.path.join(
                    f"{base_folder}second_pull", file.lstrip("/")
                )
                path_to_file_noise_pull = os.path.join(
                    f"{base_folder}noise_pull", file.lstrip("/")
                )
                if file_diff.is_sqlite_file(path_to_file_first_pull):
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

    def pretty_print(self) -> str:
        """Returns a formatted string of the changed files and their diffs.

        **Returns:**

        - **str**: A formatted string of the changed files and their diffs.
        """
        base_folder = self._get_raw_results_path()
        files_from_all_pulls = self.process_data()
        result = (
            "[info bold]"
            "\n—————————————————CHANGED_FILES=(changed in all runs)——————————————————————————————————————————————————\n"
            "[/info bold][info]"
        )
        for file in files_from_all_pulls:
            try:
                path_to_file_first_pull = os.path.join(
                    f"{base_folder}first_pull", file.lstrip("/")
                )
                path_to_file_second_pull = os.path.join(
                    f"{base_folder}second_pull", file.lstrip("/")
                )
                path_to_file_noise_pull = os.path.join(
                    f"{base_folder}noise_pull", file.lstrip("/")
                )
                if file_diff.is_sqlite_file(path_to_file_first_pull):
                    diff = file_diff.db_diff(
                        path_to_file_first_pull,
                        path_to_file_second_pull,
                        path_to_file_noise_pull,
                    )
                    diff = (
                        Toolbox.highlight_timestamps(Toolbox.truncate(diff), "accent")
                        + "[info]"
                        + "\n"
                    )
                    if "ITS ALL NOISE" not in diff:
                        result = result + ("[accent]" + file + "\n")
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
                            "accent",
                        )
                        + "[info]"
                        + "\n"
                    )
                    if "ITS ALL NOISE" not in diff:
                        result = result + ("[accent]" + file + "\n")
                        result = result + diff
                elif file[-4:] == ".txt":
                    diff = (
                        Toolbox.highlight_timestamps(
                            Toolbox.truncate(file_diff.txt_diff(file)), "accent"
                        )
                        + "[info]"
                        + "\n"
                    )
                    if "ITS ALL NOISE" not in diff:
                        result = result + ("[accent]" + file + "\n")
                        result = result + diff
                else:
                    result = (
                        result
                        + Toolbox.highlight_timestamps(Toolbox.truncate(file), "info")
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
            "[bold]"
            "———————————————————————————————————————————————————————————————————————————————————————————————————————\n"
            "[/bold]"
        )
        return result

    def process_data(self) -> list[str]:
        """Processes the gathered data to filter out noise and whitelist files.

        **Returns:**

        - **list**: A list of files that are in all lists and not in the noise list.
        """
        # Use shared filter utilities to reduce code duplication
        files_from_all_pulls = intersect_file_lists(self.fileListList)
        files_from_all_pulls = filter_noise_files(
            files_from_all_pulls,
            self._get_noise_files(),
            preserve_sqlite_xml=True,
        )
        files_from_all_pulls = self._exclude_whitelist(files_from_all_pulls)
        return files_from_all_pulls
