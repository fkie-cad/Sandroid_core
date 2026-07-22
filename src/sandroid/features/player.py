"""Event player based on adb-event-record by Tzutalin.

Source: https://github.com/tzutalin/adb-event-record
Modified to fit the needs of this project.
"""

import math
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

    def __init__(self, recording_path: str | None = None) -> None:
        """Initialize the player.

        Args:
            recording_path: Absolute path to the ``recording.txt`` to replay.
                This is how the recording is supplied and is immune to the
                device-switch re-derivation bug (see module notes). May be
                left ``None`` here and passed to :meth:`perform` instead, but
                one of the two must provide a path.
        """
        self._recording_path = recording_path

    def _resolve_recording_path(self, override: str | None) -> str:
        """Resolve the recording path from the explicit args only.

        Resolution order: the explicit ``perform`` argument, then the value
        passed to the constructor. The recording path is never derived from
        the process-global ``RAW_RESULTS_PATH`` env var — doing so is exactly
        the device-switch orphaning bug this design removes.

        Args:
            override: Explicit path passed to :meth:`perform`, if any.

        Returns:
            The recording file path to read.

        Raises:
            RuntimeError: If no recording path was supplied to either the
                constructor or :meth:`perform`.
        """
        path = override or self._recording_path
        if not path:
            raise RuntimeError(
                "Player has no recording path: pass recording_path to the "
                "constructor or to perform()."
            )
        return str(path)

    def perform(self, recording_path: str | None = None) -> None:
        """Replay recorded actions from the recording file.

        Args:
            recording_path: Absolute path to the recording to replay. Takes
                precedence over the constructor value.

        Raises:
            RuntimeError: If no recording path was supplied, or if the
                recording file cannot be opened.
        """
        Toolbox.set_action_time()
        start_time = int(round(time.time()))
        logger.info("Start playing")

        last_ts = None
        recording_file = self._resolve_recording_path(recording_path)

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
