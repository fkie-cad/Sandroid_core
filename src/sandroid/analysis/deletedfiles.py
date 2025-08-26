from logging import getLogger

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


class DeletedFiles(DataGather):
    """Class for gathering and processing information on deleted files.

    Inherits from :class:`DataGather` and provides methods to gather, process, and display information about deleted files.
    """

    deletedFileListList = []

    def gather(self):
        """Gather information on deleted files.

        This method pulls the entire filesystem and compares it to the baseline to identify deleted files.
        """
        logger.info(
            "Gathering information on deleted files, pulling entire filesystem and comparing to baseline"
        )

        deletedFiles = []
        allFiles = Toolbox.fetch_changed_files(fetch_all=True)

        if len(Toolbox.baseline) == 0:
            logger.error("Baseline is empty. Baseline is not supposed to be empty.")

        for file in Toolbox.baseline:  # Get deleted files
            if file not in allFiles:
                deletedFiles.append(file)
        self.deletedFileListList.append(deletedFiles)
        logger.debug(str(len(deletedFiles)) + " Files were detected as deleted")

    def return_data(self):
        """Return processed data on deleted files.

        :returns: A dictionary containing the list of deleted files.
        :rtype: dict
        """
        return {"Deleted Files": self.process_data()}

    def pretty_print(self):
        """Pretty print the list of deleted files.

        :returns: A formatted string with the list of deleted files highlighted.
        :rtype: str
        """
        deletedFiles = self.process_data()
        result = (
            Bcolors.OKGREEN
            + Bcolors.BOLD
            + "\n—————————————————DELETED_FILES=(compared to baseline)—————————————————————————————————————————————————\n"
            + Bcolors.ENDC
            + Bcolors.OKGREEN
        )
        for entry in deletedFiles:
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
        """Process the gathered data to filter out noise and identify consistently deleted files.

        :returns: A list of files that have been consistently deleted across all pulls.
        :rtype: list
        """
        # intersect the first list with all other lists, leaving only the files that are in all lists
        files_from_all_pulls = self.deletedFileListList[0]
        noise = Toolbox.noise_files
        for fileList in self.deletedFileListList:
            files_from_all_pulls = list(set(files_from_all_pulls) & set(fileList))
        files_from_all_pulls = [
            x
            for x in files_from_all_pulls
            if x not in noise or x.endswith(".db") or x.endswith(".xml")
        ]  # filter noise from files, ignore .db and .xml files

        files_from_all_pulls = Toolbox.exclude_whitelist(files_from_all_pulls)
        return files_from_all_pulls
