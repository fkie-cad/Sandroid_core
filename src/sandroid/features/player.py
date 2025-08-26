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


class Player(Functionality):
    """Represents a player functionality for performing actions.

    This class handles replaying actions based on recorded data.

    :cvar STORE_LINE_RE: Regular expression pattern for parsing stored data lines.
    :type STORE_LINE_RE: re.Pattern

    :cvar logger: Logger instance for logging messages related to player functionality.
    :type logger: logging.Logger
    """

    STORE_LINE_RE = re.compile(r"(\S+) (\S+) (\S+) (\S+) (\S+)$")

    def perform(self):
        """Perform the player action.

        This method replays recorded actions based on stored data.
        """
        # replay action
        Toolbox.set_action_time()
        start_time = int(round(time.time()))
        logger.info("Start playing")
        last_ts = None
        # TODO: Improve replay of swiping motions
        with open(f"{os.getenv('RAW_RESULTS_PATH')}recording.txt") as fp:
            for line in fp:
                match = self.STORE_LINE_RE.match(line.strip())
                ts, dev, etype, ecode, data = match.groups()
                ts = float(ts)

                if last_ts and (ts - last_ts) > 0:
                    delta_second = (ts - last_ts) / 1000
                    # if delta_second > 100: # Skip small sleep times for a slight speed up of swiping motions
                    time.sleep(delta_second)

                last_ts = ts

                cmds = "shell sendevent " + dev + " " + etype + " " + ecode + " " + data
                Adb.send_adb_command(cmds)

        logger.info("Stop playing")
        # Measure it here, because it sometimes plays slower than it was recorded
        action_duration = math.ceil(time.time() - start_time)
        Toolbox.set_action_duration(action_duration)
        logger.debug(f"Set action duration to {action_duration} seconds")


if __name__ == "__main__":
    p = Player()
    p.perform()
