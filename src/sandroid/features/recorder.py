"""This code is an excerpt from "adb-event-record" by Tzutalin.
(https://github.com/tzutalin/adb-event-record)
The excerpt was modified to fit the needs of this project
"""

import math
import os
import re
import time
from logging import getLogger

from sandroid.core.adb import Adb
from sandroid.core.toolbox import Toolbox

from .functionality import Functionality

logger = getLogger(__name__)


class Recorder(Functionality):
    """Represents a recorder functionality for capturing events.

    This class handles recording events based on input data.

    :cvar EVENT_LINE_RE: Regular expression pattern for parsing event lines.
    :type EVENT_LINE_RE: re.Pattern
    """

    EVENT_LINE_RE = re.compile(r"(\S+): (\S+) (\S+) (\S+)$")

    def __init__(self):
        """Initialize the Recorder instance."""
        self.output_file_name = f"{os.getenv('RAW_RESULTS_PATH')}recording.txt"
        self.output_file = None
        # self.logger = Toolbox.logger_factory("recorder")

    def perform(self):
        """This method captures events and writes them to a file."""
        if Toolbox.args.ai:
            Toolbox.toggle_screen_record()
        self.output_file = open(self.output_file_name, "w")
        logger.info("Start recording, press Ctrl+C to stop")
        record_command = "shell getevent"
        adb = Adb.send_adb_command_popen(record_command)

        start_time = time.time()
        self.write_dummy_event()

        while adb.poll() is None:
            try:
                line = adb.stdout.readline().decode("utf-8", "replace").strip()
                match = Recorder.EVENT_LINE_RE.match(line.strip())
                if match is not None:
                    dev, etype, ecode, data = match.groups()
                    self.write_event(dev, etype, ecode, data)

            except KeyboardInterrupt:
                # Add a dummy event at the end of the recording
                self.write_dummy_event()
                end_time = time.time()
                duration = math.ceil(end_time - start_time)
                print("")
                break
            if len(line) == 0:
                break

        self.output_file.close()
        logger.info(f"End of recording. Recording took {duration} Seconds.")
        logger.info(f"Saved recording to file {self.output_file_name}.")

        if Toolbox.args.ai:
            Toolbox.toggle_screen_record()

    def write_event(self, dev, etype, ecode, data):
        """Write an input event to the output file.

        :param dev: Device identifier.
        :type dev: str
        :param etype: Event type.
        :type etype: str
        :param ecode: Event code.
        :type ecode: str
        :param data: Event data.
        :type data: str
        """
        millis = int(round(time.time() * 1000))
        etype, ecode, data = int(etype, 16), int(ecode, 16), int(data, 16)
        rline = "%s %s %s %s %s\n" % (millis, dev, etype, ecode, data)
        logger.debug(rline.strip())
        self.output_file.write(rline)

    def write_dummy_event(self):
        """Write a dummy event to the output file."""
        self.write_event("/dev/input/event1", "0", "0", "0")
