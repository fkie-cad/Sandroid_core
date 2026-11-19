"""Recording (Record) on top of Tracking's shared getevent reader.

Record does not spawn its own ``getevent`` any more: it leases the device's
ONE ``getevent -t`` stream from :mod:`sandroid.services.tracking_service`
(and starts Tracking first when ``tracking.auto_on_record`` is on). At stop it
copies the raw event lines it saw verbatim to the output file
(``recording.getevent.txt``): ``[   s.us] /dev/input/eventN: tttt cccc vvvvvvvv``
lines, the format :class:`sandroid.features.player.Player` replays.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


def _serial() -> str | None:
    try:
        from sandroid.core import timeline

        serial = timeline.get_timeline().active_serial
        if serial:
            return serial
    except Exception:
        pass
    try:
        from sandroid.core.adb import Adb

        return Adb.get_target_device()
    except Exception:
        return None


class RecordingWrapper:
    """Non-blocking Record: a lease on the shared getevent stream.

    Provides:
    - Event counting and elapsed time tracking
    - Callbacks for live event display (``/dev/input/eventN: tttt cccc vvvvvvvv``)
    - Clean termination support (writes the raw slice at :meth:`stop`)
    """

    def __init__(
        self,
        output_file: str,
        on_event: Callable[[str], None] | None = None,
        on_count_update: Callable[[int], None] | None = None,
        *,
        serial: str | None = None,
    ):
        """Initialize the recording wrapper.

        Args:
            output_file: Path of the ``recording.getevent.txt`` to write.
            on_event: Optional callback for each event line (for live display).
            on_count_update: Optional callback when the event count changes.
            serial: Device serial (default: the timeline's / ADB's device).
        """
        self.output_file_path = output_file
        self.on_event = on_event
        self.on_count_update = on_count_update
        self._serial = serial

        self._stream: Any = None
        self._unsubscribe: Callable[[], None] | None = None
        self._started_tracking = False
        self._line_start = 0
        self._stopped = False
        self._event_count = 0
        self._start_time: float | None = None
        self._duration = 0
        self._lock = threading.Lock()

    @property
    def event_count(self) -> int:
        """Get the current event count."""
        with self._lock:
            return self._event_count

    @property
    def elapsed_seconds(self) -> int:
        """Get elapsed recording time in seconds."""
        if self._start_time is None:
            return 0
        if self._stopped:
            return self._duration
        return int(time.time() - self._start_time)

    @property
    def is_running(self) -> bool:
        """Check if recording is active."""
        stream = self._stream
        return stream is not None and not self._stopped and bool(stream.alive)

    def start(self) -> bool:
        """Lease the shared getevent stream (Tracking first, if configured).

        Returns:
            True if recording started successfully, False otherwise.
        """
        if self._stream is not None:
            logger.warning("Recording already in progress")
            return False
        serial = self._serial or _serial()
        if not serial:
            logger.error("Failed to start recording: no device")
            return False
        output_dir = os.path.dirname(self.output_file_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        try:
            from sandroid.config import get_config
            from sandroid.services.tracking_service import get_tracking

            tracking = get_tracking()
            if get_config().tracking.auto_on_record and not tracking.is_active():
                self._started_tracking = tracking.start(serial, reason="record")
            stream = tracking.getevent(serial)
        except Exception as e:
            logger.error(f"Failed to start recording: {e}")
            self._stop_own_tracking()
            return False
        self._serial = serial
        self._stream = stream
        self._line_start = stream.line_no() + 1
        self._unsubscribe = stream.subscribe(self._on_line)
        self._start_time = time.time()
        self._stopped = False
        self._event_count = 0
        logger.info("Recording started")
        return True

    def stop(self) -> int:
        """Stop recording, write the raw slice, and return the duration.

        Returns:
            Duration of recording in seconds.
        """
        if self._stopped:
            return self._duration

        # Measure first: once ``_stopped`` is set, ``elapsed_seconds`` returns
        # the (still 0) ``_duration`` -- which made every recording report
        # "N events, 0s".
        self._duration = self.elapsed_seconds
        self._stopped = True

        stream, self._stream = self._stream, None
        if stream is None:
            return self._duration
        try:
            line_end = stream.line_no()
            if self._unsubscribe is not None:
                self._unsubscribe()
                self._unsubscribe = None
            write_slice(
                stream.raw_path, self._line_start, line_end, self.output_file_path
            )
            logger.debug(
                f"Recording stopped: {self._event_count} events, {self._duration}s"
            )
        except Exception as e:
            logger.error(f"Error stopping recording: {e}")
        finally:
            stream.release()
            self._stop_own_tracking()
        return self._duration

    def _stop_own_tracking(self) -> None:
        if not self._started_tracking:
            return
        self._started_tracking = False
        try:
            from sandroid.services.tracking_service import get_tracking

            get_tracking().stop(reason="record")
        except Exception:
            logger.debug("Stopping Record's Tracking failed", exc_info=True)

    def _on_line(self, line: str, line_no: int, host_recv: float) -> None:
        """Reader thread: count event lines, feed the live display."""
        from sandroid.services.tracking_service import GE_LINE

        if line_no < self._line_start or self._stopped:
            return
        if GE_LINE.match(line.strip()) is None:
            return
        with self._lock:
            self._event_count += 1
            count = self._event_count
        if self.on_count_update:
            try:
                self.on_count_update(count)
            except Exception:
                pass
        if self.on_event:
            try:
                self.on_event(line.split("]", 1)[-1].strip())
            except Exception:
                pass

    def __del__(self):
        """Ensure recording is stopped on garbage collection."""
        if not self._stopped and self._stream is not None:
            self.stop()


def write_slice(raw_path: Any, first: int, last: int, output: str) -> int:
    """Copy the event lines ``first..last`` (1-based, inclusive) of the raw
    getevent file verbatim to ``output``; device-listing lines that getevent
    prints when it (re)starts are dropped. Returns the number of lines.
    """
    from sandroid.services.tracking_service import GE_LINE

    out: list[str] = []
    if last >= first:
        with open(raw_path, encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                if n < first:
                    continue
                if n > last:
                    break
                if GE_LINE.match(line.strip()):
                    out.append(line if line.endswith("\n") else line + "\n")
    tmp = Path(f"{output}.part")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.writelines(out)
    tmp.replace(output)
    return len(out)
