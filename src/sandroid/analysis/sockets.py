import threading
import time
from logging import getLogger
from typing import Any

from sandroid.core.events.events import NetworkEvent, TaskOutput

from .base_di import DataGatherBase

logger = getLogger(__name__)


class Sockets(DataGatherBase):
    """Handles the gathering and processing of listening sockets during an action."""

    def __init__(self, **kwargs: Any) -> None:
        """Initialize the Sockets data gatherer.

        Args:
            **kwargs: Arguments passed to DataGatherBase including:
                - forensic_service: ForensicService for file tracking
                - adb: ADB interface for device communication
                - config: Configuration object
                - logger: Logger instance
        """
        super().__init__(**kwargs)
        self.run_sockets_lists: dict[int, list[str]] = {}
        self.final_sockets_list: list[str] = []
        self.noise_sockets: list[str] = []
        self.run_counter: int = 0
        self.performed_diff: bool = False

    def gather(self) -> None:
        """Start listening socket collection in a background thread.

        Initiates a thread that continuously monitors listening sockets on
        the device over the configured action duration. Socket data is
        collected via ADB shell netstat commands.
        """
        logger.info("Collecting information on listening sockets during action")
        t1 = threading.Thread(target=self.socket_capture_thread, args=())
        t1.start()

    def return_data(self) -> dict[str, list[str]]:
        """Return the processed list of listening sockets.

        Processes the collected data if not already done, filtering out
        baseline noise sockets captured during the dry run.

        Returns:
            A dictionary with key "Listening Sockets" containing a list of
            formatted strings describing port numbers and associated programs.
        """
        if not self.performed_diff:
            self.process_sockets()
        return {"Listening Sockets": self.final_sockets_list}

    def pretty_print(self) -> str:
        """Return a Rich-formatted string of listening sockets for display.

        Formats the socket list with Rich markup for terminal display.
        Processes the data if not already done.

        Returns:
            A Rich-formatted string containing the list of listening sockets
            that were not present in the baseline dry run.
        """
        if not self.performed_diff:
            self.process_sockets()
        raw_output = self.final_sockets_list

        result = (
            "[accent bold]"
            "\n—————————————————LISTENING SOCKETS=(listening at some point in each run, not in dry run)——————————————\n"
            "[/accent bold]"
            "[accent]"
        )
        for entry in raw_output:
            result += entry + "\n"
        result = result + (
            "[/accent]"
            "[accent bold]"
            "———————————————————————————————————————————————————————————————————————————————————————————————————————\n"
            "[/accent bold]"
        )

        return result

    def socket_capture_thread(self) -> None:
        """Capture listening sockets over the action duration.

        This method is designed to run in a background thread. It polls the
        device every second via ADB netstat command to get TCP/UDP listening
        sockets, building a cumulative set of all sockets seen during the
        capture period.

        During dry runs, the captured sockets are stored as baseline noise.
        During normal runs, sockets are stored per run for later comparison.
        """
        runtime = self._get_toolbox().get_action_duration()
        socket_list = []
        for i in range(runtime):
            stdout, _stderr = self._send_adb_command("shell netstat -tulp")
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

        if self._get_toolbox().is_dry_run():
            self.noise_sockets = socket_list
        else:
            self.run_sockets_lists[self.run_counter] = socket_list
            self.run_counter += 1

    def process_sockets(self) -> None:
        """Process collected data to identify application-specific listening sockets.

        Filters out baseline noise sockets captured during the dry run, using
        a two-step matching process:
        1. Match by port number across all runs.
        2. If port is missing but program name matches, still count as a match.

        Sets performed_diff flag and publishes TaskOutput with summary.
        Also publishes NetworkEvent for each identified listening socket.
        """
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

        # Publish summary event
        count = len(self.final_sockets_list)
        TaskOutput(
            task_name="sockets",
            message=f"Found {count} active listening sockets",
            level="info",
            source="sockets",
        ).publish()

        # Publish individual network events for each listening socket
        for port, program in noise_adjusted_result.items():
            NetworkEvent(
                event_type_name="listening",
                protocol="tcp",  # netstat -tulp captures tcp listening sockets
                dest_ip="0.0.0.0",  # listening sockets bind locally
                dest_port=int(port) if port.isdigit() else 0,
                source="sockets",
                data_size=0,
            ).publish()
            logger.debug(
                f"Published NetworkEvent for listening socket on port {port} ({program})"
            )
