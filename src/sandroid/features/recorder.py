"""This code is an excerpt from "adb-event-record" by Tzutalin.
(https://github.com/tzutalin/adb-event-record)
The excerpt was modified to fit the needs of this project
"""

import math
import os
import re
import threading
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
        self.ui_dump_file_name = f"{os.getenv('RAW_RESULTS_PATH')}ui_dumps.txt"
        self.output_file = None
        self.dump_lock = threading.Lock()
        self.dump_threads = []
        # self.logger = Toolbox.logger_factory("recorder")

    def perform(self):
        """This method captures events and writes them to a file."""
        if Toolbox.args.ai:
            Toolbox.toggle_screen_record()
        self.output_file = open(self.output_file_name, "w")
        if Toolbox.args.ai:
            self.dump_ui_hierarchy()
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
                    if (
                        Toolbox.args.ai
                        and dev == "/dev/input/event3"
                        and ecode == "0039"
                        and data == "00000000"
                    ):
                        dump_thread = threading.Thread(target=self.dump_ui_hierarchy)
                        dump_thread.start()
                        self.dump_threads.append(dump_thread)

            except KeyboardInterrupt:
                # Add a dummy event at the end of the recording
                self.write_dummy_event()
                print("")
                break
            if len(line) == 0:
                break

        self.output_file.close()
        for thread in self.dump_threads:
            thread.join()
        duration = math.ceil(time.time() - start_time)
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

    def dump_ui_hierarchy(self):
        """Dump current UI hierarchy and append it to ui_dumps.txt."""
        timestamp = int(round(time.time() * 1000))
        if not self.dump_lock.acquire(blocking=False):
            logger.warning("UI dump skipped: another dump is already in progress.")
            return

        try:
            dump_text = "UI dump failed"
            try:
                _, stderr = Adb.send_adb_command("shell uiautomator dump /sdcard/window_dump.xml")
                stdout, stderr2 = Adb.send_adb_command("shell cat /sdcard/window_dump.xml")
                dump_text_candidate = stdout.strip()
                if dump_text_candidate:
                    dump_text = dump_text_candidate
                    logger.info("UI dump successful")
                else:
                    logger.error(
                        "UI dump failed, no output received. Stderr: %s, %s", stderr, stderr2
                    )
            except Exception as exc:  # pragma: no cover - best effort
                logger.error(f"UI dump failed with exception: {exc}")

            if dump_text != "UI dump failed":
                try:
                    with open(self.ui_dump_file_name, "a", encoding="utf-8") as f:
                        f.write(f"{timestamp}\n")
                        f.write(dump_text)
                        f.write("\n---\n")
                except Exception as exc:  # pragma: no cover - best effort
                    logger.error(
                        f"Failed to write UI dump to {self.ui_dump_file_name}: {exc}"
                    )
        finally:
            self.dump_lock.release()
