import threading
import time
from logging import getLogger

from sandroid.core.adb import Adb
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


class Processes(DataGather):
    """Handles the gathering and processing of active processes during an action."""

    run_process_lists = {}
    final_processes_list = []
    run_counter = 0
    performed_diff = False

    def gather(self):
        """Starts a new thread to capture process data."""
        logger.info("Collecting information on active processes during action")
        t1 = threading.Thread(target=self.process_capture_thread, args=())
        t1.start()

    def return_data(self):
        """Returns the processed data of active processes.

        :returns: Dictionary containing the processes that were active.
        :rtype: dict
        """
        if len(self.final_processes_list) == 0:
            self.process_processes()
        return {"Processes": self.final_processes_list}

    def pretty_print(self):
        """Returns a formatted string of the active processes for display.

        :returns: Formatted string of active processes.
        :rtype: str
        """
        if not self.performed_diff:
            self.process_processes()
        raw_output = self.final_processes_list

        result = (
            Bcolors.HEADER
            + Bcolors.BOLD
            + "\n—————————————————PROCESSES=(active at some point in each run, not in dry run)——————————————————————————\n"
            + Bcolors.ENDC
            + Bcolors.HEADER
        )
        for entry in raw_output:
            result += entry + "\n"
        result = result + (
            Bcolors.BOLD
            + "———————————————————————————————————————————————————————————————————————————————————————————————————————\n"
            + Bcolors.ENDC
        )

        return result

    def process_capture_thread(self):
        """Captures the list of active processes over the duration of an action."""
        runtime = Toolbox.get_action_duration()
        process_list = []
        for i in range(runtime):
            stdout, stderr = Adb.send_adb_command("shell ps -Ao NAME")
            process_list = list(
                set(stdout.splitlines()[1:] + process_list)
            )  # Join new-found processes with the process list so far without duplicates
            logger.debug("Found " + str(len(process_list)) + " processes so far")
            time.sleep(1)

        if Toolbox.is_dry_run():
            Toolbox.noise_processes = process_list
        else:
            self.run_process_lists[self.run_counter] = process_list
            self.run_counter += 1

    def process_processes(self):
        """Processes the collected process lists to filter out noise and identify true active processes."""
        noise = Toolbox.noise_processes

        logger.debug("Processing collected process lists")

        result = []

        # check for processes that are in at least one run, but NOT in noise
        for process_list in self.run_process_lists.values():
            for process in process_list:
                if process not in result:
                    result.append(process)

        for process in result:
            if process not in noise:
                self.final_processes_list.append(process)

        logger.debug(self.final_processes_list)
        self.performed_diff = True
