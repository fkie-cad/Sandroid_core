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


class Sockets(DataGather):
    """Handles the gathering and processing of listening sockets during an action."""

    run_sockets_lists = {}
    final_sockets_list = []
    noise_sockets = []
    run_counter = 0
    performed_diff = False

    def gather(self):
        """Collects information on listening sockets during an action."""
        logger.info("Collecting information on listening sockets during action")
        t1 = threading.Thread(target=self.socket_capture_thread, args=())
        t1.start()

    def return_data(self):
        """Returns the processed data of listening sockets.

        :returns: Dictionary containing the listening sockets.
        :rtype: dict
        """
        if not self.performed_diff:
            self.process_sockets()
        return {"Listening Sockets": self.final_sockets_list}

    def pretty_print(self):
        """Returns a formatted string of the listening sockets for display.

        :returns: Formatted string of listening sockets.
        :rtype: str
        """
        if not self.performed_diff:
            self.process_sockets()
        raw_output = self.final_sockets_list

        result = (
            Bcolors.OKCYAN
            + Bcolors.BOLD
            + "\n—————————————————LISTENING SOCKETS=(listening at some point in each run, not in dry run)——————————————\n"
            + Bcolors.ENDC
            + Bcolors.OKCYAN
        )
        for entry in raw_output:
            result += entry + "\n"
        result = result + (
            Bcolors.BOLD
            + "———————————————————————————————————————————————————————————————————————————————————————————————————————\n"
            + Bcolors.ENDC
        )

        return result

    def socket_capture_thread(self):
        """Function meant to be used as a thread to create list of listening sockets over the duration of an action."""
        runtime = Toolbox.get_action_duration()
        socket_list = []
        for i in range(runtime):
            stdout, stderr = Adb.send_adb_command("shell netstat -tulp")
            stdout = stdout.splitlines()[1:]
            detected_listening = []
            for socket in stdout:
                if "LISTEN" in socket:
                    detected_listening.append(socket)
            socket_list = list(
                set(detected_listening + socket_list)
            )  # Join new-found sockets with the socket list so far without duplicates
            logger.debug("Found " + str(len(socket_list)) + " listening sockets so far")
            time.sleep(1)

        if Toolbox.is_dry_run():
            self.noise_sockets = socket_list
        else:
            self.run_sockets_lists[self.run_counter] = socket_list
            self.run_counter += 1

    def process_sockets(self):
        """Processes the collected socket lists to filter out noise and identify true listening sockets."""
        noise = self.noise_sockets

        logger.debug("Processing collected listening sockets lists")

        result = []

        # The check works like this:
        # 1. Search for matching port numbers first
        # 2. If a run was missing the port number but DID contain the same Program Name, it is still counted as a match

        # pre-processing data
        port_numbers_and_names_dict_list = []
        program_names_list_list = []
        for socket_list in self.run_sockets_lists.values():
            port_and_name_dict = {}
            for line in socket_list:
                parts = line.split()
                port = parts[3].split(":")[-1]
                if "/" in parts[-1]:
                    program = parts[-1].split("/")[1]
                    port_and_name_dict[port] = program
                else:
                    port_and_name_dict[port] = ""

            port_numbers_and_names_dict_list.append(port_and_name_dict)

        # Get all keys from all dictionaries
        all_keys = set().union(*[d.keys() for d in port_numbers_and_names_dict_list])
        # Initialize the result dictionary
        result = {}

        # Check each key
        for key in all_keys:
            # If the key is in all dictionaries or its value is in all dictionaries
            if all(
                key in d
                or (
                    key in port_numbers_and_names_dict_list[0]
                    and port_numbers_and_names_dict_list[0][key] in d.values()
                )
                for d in port_numbers_and_names_dict_list
            ):
                # Add the key and its value from the first dictionary to the result
                result[key] = port_numbers_and_names_dict_list[0][key]

        noise_adjusted_result = {}
        for key in result.keys():
            if str(key) not in str(noise):
                noise_adjusted_result[key] = result[key]

        # Generate final socket list
        for port in noise_adjusted_result:
            self.final_sockets_list.append(
                "Port " + str(port) + " used by " + noise_adjusted_result[port]
            )

        self.performed_diff = True
