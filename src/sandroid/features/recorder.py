"""Event recorder based on adb-event-record by Tzutalin.

Source: https://github.com/tzutalin/adb-event-record
Modified to fit the needs of this project.
"""

import math
import os
import re
import time
from logging import getLogger

from sandroid.core.adb import Adb

from .functionality import Functionality

logger = getLogger(__name__)


class Recorder(Functionality):
    """Records touch/input events from an Android device via ``adb shell getevent``.

    Events are written to a timestamped text file for later replay by :class:`Player`.

    Attributes:
        EVENT_LINE_RE: Pattern matching raw getevent output lines.
    """

    EVENT_LINE_RE = re.compile(r"(\S+): (\S+) (\S+) (\S+)$")

    def __init__(self) -> None:
        """Initialize with the output file path derived from RAW_RESULTS_PATH."""
        self.output_file_name = f"{os.getenv('RAW_RESULTS_PATH')}recording.txt"
        self.output_file = None

    def perform(self) -> None:
        """Capture device events and write them to a file.

        Raises:
            RuntimeError: If the recording file cannot be opened or written to.
        """
        raw_path = os.getenv("RAW_RESULTS_PATH", "")
        if raw_path:
            os.makedirs(raw_path, exist_ok=True)

        try:
            self.output_file = open(self.output_file_name, "w", encoding="utf-8")
        except (FileNotFoundError, PermissionError, OSError) as e:
            error_msg = f"Failed to open recording file '{self.output_file_name}': {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e

        logger.info("Start recording, press Ctrl+C to stop")
        adb = Adb.send_adb_command_popen("shell getevent")

        start_time = time.time()
        self.write_dummy_event()

        while adb.poll() is None:
            try:
                line = adb.stdout.readline().decode("utf-8", "replace").strip()
                match = self.EVENT_LINE_RE.match(line)
                if match is not None:
                    dev, etype, ecode, data = match.groups()
                    self.write_event(dev, etype, ecode, data)

            except KeyboardInterrupt:
                self.write_dummy_event()
                end_time = time.time()
                duration = math.ceil(end_time - start_time)
                print("")
                break
            if len(line) == 0:
                break

        try:
            self.output_file.close()
        except OSError as e:
            logger.warning(
                f"Error closing recording file '{self.output_file_name}': {e}"
            )

        logger.info(f"End of recording. Recording took {duration} Seconds.")
        logger.info(f"Saved recording to file {self.output_file_name}.")

    def write_event(self, dev: str, etype: str, ecode: str, data: str) -> None:
        """Write an input event to the output file.

        Args:
            dev: Device identifier (e.g. /dev/input/event1).
            etype: Event type in hex.
            ecode: Event code in hex.
            data: Event data in hex.

        Raises:
            RuntimeError: If writing to the recording file fails.
        """
        millis = int(round(time.time() * 1000))
        etype_int, ecode_int, data_int = int(etype, 16), int(ecode, 16), int(data, 16)
        line = f"{millis} {dev} {etype_int} {ecode_int} {data_int}\n"
        logger.debug(line.strip())
        try:
            self.output_file.write(line)
        except OSError as e:
            error_msg = f"Failed to write event to recording file '{self.output_file_name}': {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e

    def write_dummy_event(self) -> None:
        """Write a dummy synchronization event to the output file."""
        self.write_event("/dev/input/event1", "0", "0", "0")
