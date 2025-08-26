import os
import threading
import time
from datetime import datetime
from logging import getLogger
from queue import Queue

from sandroid.core.adb import Adb
from sandroid.core.toolbox import Toolbox

from .functionality import Functionality

logger = getLogger(__name__)


class Screenshot(Functionality):
    """This class provides functionality for capturing screenshots.

    Methods:
        - :meth:`perform`: Starts the screenshot thread.
        - :meth:`set_action`: Sets the current screenshot action.
        - :meth:`get_action`: Retrieves the current screenshot action.
        - :meth:`screenshot_thread`: Captures screenshots at regular intervals.
        - :meth:`stop`: Stops the screenshot thread.
        - :meth:`generate_name`: Generates a unique screenshot filename.

    """

    actions = Queue()
    finished = False
    interval = Toolbox.args.screenshot

    def __init__(self):
        """Initialize the Screenshot functionality.

        A thread is created but not started. The thread is reused throughout the life of this class instance
        """
        self.thread = threading.Thread(target=self.screenshot_thread)
        self.thread.daemon = True

    def perform(self):
        """Start the screenshot thread."""
        self.actions.put("startup")
        self.thread.start()
        logger.info("Screenshot thread started")

    def set_action(self, action):
        """Set the current screenshot action.

        :param action: The screenshot action.
        :type action: Anything that can reasonably be converted to a String
        """
        action = str(action)
        self.actions.put(action)
        logger.debug("Screenshot name updated to: " + self.generate_name())

    def get_action(self):
        """Retrieve the current screenshot action.

        :returns: The current screenshot action.
        :rtype: str
        """
        return self.actions.queue[-1]

    def screenshot_thread(self):
        """Capture screenshots at regular intervals. Meant to be run as a Thread."""
        while not self.finished:
            name = self.generate_name()
            stdout, stderr = Adb.send_telnet_command(
                f"screenrecord screenshot {os.getenv('RAW_RESULTS_PATH')}screenshots/{name}"
            )
            if not stderr:
                logger.debug("Screenshot saved: " + name)
            time.sleep(self.interval)

    def stop(self):
        """Stop the screenshot thread."""
        self.finished = True
        logger.debug("Ending Screenshot thread")

    def generate_name(self):
        """Generate a unique screenshot filename.

        :returns: The generated screenshot filename.
        :rtype: str
        """
        timestring = datetime.now().strftime("%Y-%d-%m--%H-%M-%S-")
        return timestring + self.get_action() + ".png"


if __name__ == "__main__":
    pass
