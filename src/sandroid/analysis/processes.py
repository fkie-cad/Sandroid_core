import threading
import time
from logging import getLogger
from typing import Any

from sandroid.core.events.events import TaskOutput

from .base_di import DataGatherBase

logger = getLogger(__name__)


class Processes(DataGatherBase):
    """Handles the gathering and processing of active processes during an action."""

    def __init__(self, **kwargs: Any) -> None:
        """Initialize the Processes data gatherer.

        Args:
            **kwargs: Arguments passed to DataGatherBase including:
                - forensic_service: ForensicService for file tracking
                - adb: ADB interface for device communication
                - config: Configuration object
                - logger: Logger instance
        """
        super().__init__(**kwargs)
        self.run_process_lists: dict[int, list[str]] = {}
        self.final_processes_list: list[str] = []
        self.run_counter: int = 0
        self.performed_diff: bool = False

    def gather(self) -> None:
        """Start process data collection in a background thread.

        Initiates a thread that continuously captures the list of active
        processes on the device over the configured action duration. Process
        data is collected via ADB shell commands.
        """
        logger.info("Collecting information on active processes during action")
        t1 = threading.Thread(target=self.process_capture_thread, args=())
        t1.start()

    def return_data(self) -> dict[str, list[str]]:
        """Return the processed list of active processes.

        Processes the collected data if not already done, filtering out
        baseline noise processes captured during the dry run.

        Returns:
            A dictionary with key "Processes" containing a list of process
            names that were active during the capture but not in the baseline.
        """
        if len(self.final_processes_list) == 0:
            self.process_processes()
        return {"Processes": self.final_processes_list}

    def pretty_print(self) -> str:
        """Return a Rich-formatted string of active processes for display.

        Formats the process list with Rich markup for terminal display.
        Processes the data if not already done.

        Returns:
            A Rich-formatted string containing the list of active processes
            that were not present in the baseline dry run.
        """
        if not self.performed_diff:
            self.process_processes()
        raw_output = self.final_processes_list

        result = (
            "[primary bold]"
            "\n—————————————————PROCESSES=(active at some point in each run, not in dry run)——————————————————————————\n"
            "[/primary bold]"
            "[primary]"
        )
        for entry in raw_output:
            result += entry + "\n"
        result = result + (
            "[primary bold]"
            "———————————————————————————————————————————————————————————————————————————————————————————————————————\n"
            "[/primary bold]"
        )

        return result

    def process_capture_thread(self) -> None:
        """Capture active processes over the action duration.

        This method is designed to run in a background thread. It polls the
        device every second via ADB to get the current process list, building
        a cumulative set of all processes seen during the capture period.

        During dry runs, the captured processes are stored as baseline noise.
        During normal runs, processes are stored per run for later comparison.
        Publishes TaskOutput events to report capture progress.
        """
        toolbox = self._get_toolbox()
        runtime = toolbox.get_action_duration()
        process_list = []
        for i in range(runtime):
            stdout, _stderr = self._send_adb_command("shell ps -Ao NAME")
            process_list = list(
                set(stdout.splitlines()[1:] + process_list)
            )  # Join new-found processes with the process list so far without duplicates
            logger.debug("Found " + str(len(process_list)) + " processes so far")
            time.sleep(1)

        if toolbox.is_dry_run():
            toolbox.noise_processes = process_list
            TaskOutput(
                task_name="processes",
                message=f"Dry run: captured {len(process_list)} baseline processes",
                level="info",
                source="processes",
            ).publish()
        else:
            self.run_process_lists[self.run_counter] = process_list
            self.run_counter += 1
            TaskOutput(
                task_name="processes",
                message=f"Run {self.run_counter}: captured {len(process_list)} processes",
                level="info",
                source="processes",
            ).publish()

    def process_processes(self) -> None:
        """Process collected data to identify application-specific processes.

        Filters out baseline noise processes captured during the dry run,
        leaving only processes that appeared during the actual capture runs.
        Sets performed_diff flag and publishes TaskOutput with summary.
        """
        toolbox = self._get_toolbox()
        noise = toolbox.noise_processes

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

        # Publish summary of processed results
        total_collected = len(result)
        filtered_count = len(self.final_processes_list)
        noise_filtered = total_collected - filtered_count
        TaskOutput(
            task_name="processes",
            message=f"Found {filtered_count} unique processes (filtered {noise_filtered} noise processes)",
            level="info",
            source="processes",
        ).publish()
