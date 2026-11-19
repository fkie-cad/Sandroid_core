"""Event player based on adb-event-record by Tzutalin.

Source: https://github.com/tzutalin/adb-event-record
Modified to fit the needs of this project.
"""

import math
import re
import threading
import time
from logging import getLogger

from sandroid.core.adb import Adb
from sandroid.core.toolbox import Toolbox

from .functionality import Functionality

logger = getLogger(__name__)

#: One recorded input event, either format:
#:
#: * ``recording.getevent.txt`` (raw ``getevent -t``):
#:   ``[   26404.737324] /dev/input/event1: 0003 0039 ffffffff`` -- device
#:   seconds, hex type/code/value;
#: * legacy ``recording.txt``: ``<epoch ms> <device> <type> <code> <value>``
#:   (decimal).
STORE_LINE_RE = re.compile(
    r"\[\s*(?P<gts>\d+\.\d+)\]\s+(?P<gdev>/dev/\S+):\s+"
    r"(?P<gtype>[0-9a-fA-F]{4})\s+(?P<gcode>[0-9a-fA-F]{4})\s+"
    r"(?P<gvalue>[0-9a-fA-F]{8})\s*$"
    r"|(?P<ts>\S+) (?P<dev>\S+) (?P<type>\S+) (?P<code>\S+) (?P<value>\S+)$"
)


def parse_store_line(line: str) -> tuple[float, str, str, str, str] | None:
    """``(ts_ms, device, type, code, value)`` of a recording line, or None.

    getevent lines are converted exactly like the legacy recorder did
    (``int(hex, 16)``, unsigned) so both formats yield the same ``sendevent``
    arguments; ``ts_ms`` is device seconds x 1000 there and host epoch ms in
    legacy lines (the player only uses differences).
    """
    m = STORE_LINE_RE.match(line.strip())
    if m is None:
        return None
    if m["gts"] is not None:
        return (
            float(m["gts"]) * 1000.0,
            m["gdev"],
            str(int(m["gtype"], 16)),
            str(int(m["gcode"], 16)),
            str(int(m["gvalue"], 16)),
        )
    try:
        ts = float(m["ts"])
    except ValueError:
        return None
    return ts, m["dev"], m["type"], m["code"], m["value"]


#: Process-wide "stop replaying" flag. Set by :meth:`Player.cancel_all` (TUI
#: stop/quit) and checked before every event and during every inter-event
#: wait, so a replay stops within one event instead of tapping on for minutes.
_cancel_event = threading.Event()


def _raise_cancelled() -> None:
    """Abort the current replay so the analysis engine stops the whole run.

    Raises the engine's ``FatalStepError`` (imported lazily: the engine
    imports this module) so the remaining steps, including the next
    iteration's snapshot load and replay, are skipped.
    """
    try:
        from sandroid.analysis.engine import FatalStepError
    except Exception:  # pragma: no cover - engine always importable
        FatalStepError = RuntimeError
    raise FatalStepError("Replay cancelled")


#: ``adb shell date`` attempts before a replay (or dry run) gives up: right
#: after a snapshot load adb can still report "device still authorizing".
ACTION_TIME_ATTEMPTS = 6
#: Wait between those attempts (seconds; a cancel ends it at once).
ACTION_TIME_RETRY_S = 1.5


def set_action_time_after_load(toolbox: object = None) -> None:
    """Set the action time from the device, retrying while adb is not ready.

    Retries :class:`~sandroid.core.exceptions.DeviceTimeError` up to
    :data:`ACTION_TIME_ATTEMPTS` times, :data:`ACTION_TIME_RETRY_S` apart (a
    cancel stops the wait). Still failing, it raises the engine's
    ``FatalStepError`` so the run (Play) ends cleanly with that error instead
    of continuing with a stale action window.

    Args:
        toolbox: Object with ``set_action_time()`` (default: :class:`Toolbox`).
    """
    from sandroid.core.exceptions import DeviceTimeError

    box = toolbox if toolbox is not None else Toolbox
    last: Exception | None = None
    for attempt in range(1, ACTION_TIME_ATTEMPTS + 1):
        try:
            box.set_action_time()
            return
        except DeviceTimeError as exc:
            last = exc
            logger.warning(
                f"Device time not readable (attempt {attempt}/"
                f"{ACTION_TIME_ATTEMPTS}): {exc}"
            )
        if attempt < ACTION_TIME_ATTEMPTS and _cancel_event.wait(ACTION_TIME_RETRY_S):
            _raise_cancelled()
    try:
        from sandroid.analysis.engine import FatalStepError
    except Exception:  # pragma: no cover - engine always importable
        FatalStepError = RuntimeError
    raise FatalStepError(f"Device not ready, replay aborted: {last}") from last


class Player(Functionality):
    """Replays previously recorded touch/input events on an Android device.

    Reads events from a recording (``recording.getevent.txt`` written by
    Record, or a legacy ``recording.txt``) and sends them to the device via ``adb shell sendevent``, preserving the
    original timing between events.

    Attributes:
        STORE_LINE_RE: Pattern matching a stored event line of either format
            (see :func:`parse_store_line`).
    """

    STORE_LINE_RE = STORE_LINE_RE

    @staticmethod
    def cancel_all() -> None:
        """Stop every running replay as soon as possible (thread-safe)."""
        _cancel_event.set()

    @staticmethod
    def clear_cancel() -> None:
        """Allow replays again; call before starting a new playback."""
        _cancel_event.clear()

    @staticmethod
    def is_cancelled() -> bool:
        """Whether :meth:`cancel_all` was called since the last clear."""
        return _cancel_event.is_set()

    def __init__(self, recording_path: str | None = None) -> None:
        """Initialize the player.

        Args:
            recording_path: Absolute path to the recording to replay
                (``recording.getevent.txt`` or a legacy ``recording.txt``).
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
            FatalStepError: If :meth:`cancel_all` was called before or
                during the replay, or the device time stayed unreadable
                (see :func:`set_action_time_after_load`).
        """
        if _cancel_event.is_set():
            _raise_cancelled()
        set_action_time_after_load()
        start_time = int(round(time.time()))
        logger.info("Start playing")

        last_ts = None
        recording_file = self._resolve_recording_path(recording_path)

        # TODO: Improve replay of swiping motions
        try:
            with open(recording_file, encoding="utf-8") as fp:
                for line in fp:
                    parsed = parse_store_line(line)
                    if parsed is None:
                        if line.strip():
                            logger.warning(
                                f"Skipping malformed line in recording: {line.strip()}"
                            )
                        continue

                    ts, dev, etype, ecode, data = parsed

                    if last_ts and (ts - last_ts) > 0:
                        delta_second = (ts - last_ts) / 1000
                        # Interruptible sleep: returns early on cancel.
                        _cancel_event.wait(delta_second)

                    last_ts = ts
                    if _cancel_event.is_set():
                        logger.info("Replay cancelled")
                        _raise_cancelled()

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
