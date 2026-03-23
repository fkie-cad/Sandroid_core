"""Event player based on adb-event-record by Tzutalin.

Source: https://github.com/tzutalin/adb-event-record
Modified to fit the needs of this project.
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


class Player(Functionality):
    """Replays previously recorded touch/input events on an Android device.

    Reads events from a recording file produced by :class:`Recorder` and
    sends them to the device via ``adb shell sendevent``, preserving the
    original timing between events.

    Attributes:
        STORE_LINE_RE: Pattern matching stored event lines (timestamp, device, type, code, data).
    """

    STORE_LINE_RE = re.compile(r"(\S+) (\S+) (\S+) (\S+) (\S+)$")

    def perform(self) -> None:
        """Replay recorded actions from the recording file.

        Raises:
            RuntimeError: If the recording file cannot be opened.
        """
        Toolbox.set_action_time()
        start_time = int(round(time.time()))
        logger.info("Start playing")

        last_ts = None
        recording_file = f"{os.getenv('RAW_RESULTS_PATH')}recording.txt"

        # TODO: Improve replay of swiping motions
        try:
            with open(recording_file, encoding="utf-8") as fp:
                for line in fp:
                    match = self.STORE_LINE_RE.match(line.strip())
                    if match is None:
                        logger.warning(
                            f"Skipping malformed line in recording: {line.strip()}"
                        )
                        continue

                    ts, dev, etype, ecode, data = match.groups()
                    ts = float(ts)

                    if last_ts and (ts - last_ts) > 0:
                        delta_second = (ts - last_ts) / 1000
                        time.sleep(delta_second)

                    last_ts = ts

                    Adb.send_adb_command(
                        f"shell sendevent {dev} {etype} {ecode} {data}"
                    )
        except FileNotFoundError as e:
            error_msg = f"Recording file not found: {recording_file}. Run 'record' first to create a recording."
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e
        except PermissionError as e:
            error_msg = f"Permission denied reading recording file: {recording_file}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e
        except OSError as e:
            error_msg = f"Failed to open recording file '{recording_file}': {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e

        logger.info("Stop playing")
        action_duration = math.ceil(time.time() - start_time)
        Toolbox.set_action_duration(action_duration)
        logger.debug(f"Set action duration to {action_duration} seconds")
