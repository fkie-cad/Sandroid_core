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
    """Captures screenshots at regular intervals via telnet commands to the emulator.

    Uses a daemon thread to periodically take screenshots and save them
    to the session's raw results directory.

    Attributes:
        actions: Queue of action labels used in screenshot filenames.
        finished: Flag to signal the screenshot thread to stop.
        interval: Seconds between screenshots, from Toolbox.args.screenshot.
    """

    actions: Queue = Queue()
    finished: bool = False
    interval: int = Toolbox.args.screenshot

    def __init__(self) -> None:
        """Initialize with a daemon thread (not yet started)."""
        self.thread = threading.Thread(target=self.screenshot_thread)
        self.thread.daemon = True

    def perform(self) -> None:
        """Start the screenshot thread."""
        self.actions.put("startup")
        self.thread.start()
        logger.info("Screenshot thread started")

    def set_action(self, action: object) -> None:
        """Set the current screenshot action label.

        Args:
            action: The action label; will be converted to string.
        """
        self.actions.put(str(action))
        logger.debug(f"Screenshot name updated to: {self.generate_name()}")

    def get_action(self) -> str:
        """Return the most recent action label without removing it from the queue."""
        return self.actions.queue[-1]

    def screenshot_thread(self) -> None:
        """Capture screenshots at regular intervals. Runs as a daemon thread."""
        raw_path = os.getenv("RAW_RESULTS_PATH", "")
        screenshots_dir = (
            os.path.join(raw_path, "screenshots") if raw_path else "screenshots"
        )
        os.makedirs(screenshots_dir, exist_ok=True)

        while not self.finished:
            name = self.generate_name()
            screenshot_path = os.path.join(screenshots_dir, name)
            _stdout, stderr = Adb.send_telnet_command(
                f"screenrecord screenshot {screenshot_path}"
            )
            if stderr:
                logger.warning(f"Screenshot failed: {stderr}")
            else:
                logger.debug(f"Screenshot saved: {screenshot_path}")
            time.sleep(self.interval)

    def stop(self) -> None:
        """Stop the screenshot thread."""
        self.finished = True
        logger.debug("Ending Screenshot thread")

    def generate_name(self) -> str:
        """Generate a timestamped screenshot filename using the current action label."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_")
        return f"{timestamp}{self.get_action()}.png"
