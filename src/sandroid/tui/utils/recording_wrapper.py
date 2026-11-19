"""Recording (Record) on top of Tracking's shared getevent reader.

Record does not spawn its own ``getevent`` any more: it leases the device's
ONE ``getevent -t`` stream from :mod:`sandroid.services.tracking_service`
(and starts Tracking first when ``tracking.auto_on_record`` is on). It keeps
the raw event lines it sees verbatim and writes them at stop to the output
file (``recording.getevent.txt``): ``[   s.us] /dev/input/eventN: tttt cccc
vvvvvvvv`` lines, the format :class:`sandroid.features.player.Player` replays.

Like the old recorder's dummy start/stop events, the file begins and ends
with a marker line (``EV_SYN 0 0`` on the touch node, harmless when
replayed) stamped with the device time of the record start and stop
instants: Play waits from the record start to the first touch and keeps the
trailing pause, and ``recording_seconds`` is the record length. The device
time is the host time plus the device clock offset, estimated from the lines
themselves (kernel time minus host receive time, the tightest one) or, with
no event line, from the last :mod:`sandroid.core.device_clock` sample.

Nothing here blocks the shared reader: the live-display callbacks run on
Record's own dispatcher thread.
"""

from __future__ import annotations

import collections
import contextlib
import logging
import os
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

#: Where a recording without any touch line puts its markers.
DEFAULT_MARKER_NODE = "/dev/input/event1"
#: Live lines kept for a slow display (older ones are dropped).
LIVE_BACKLOG = 200


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


def marker_line(dev_s: float, node: str) -> str:
    """A ``getevent -t`` ``EV_SYN SYN_REPORT 0`` line at device time ``dev_s``."""
    return f"[{dev_s:15.6f}] {node}: 0000 0000 00000000"


class _Dispatcher:
    """Runs the live-display callbacks off the getevent reader thread.

    Lines queue in a bounded deque (a slow UI loses the oldest, never stalls
    the reader); the count is coalesced to its latest value.
    """

    def __init__(
        self,
        on_event: Callable[[str], None] | None,
        on_count: Callable[[int], None] | None,
    ) -> None:
        self._on_event = on_event
        self._on_count = on_count
        self._lines: collections.deque[str] = collections.deque(maxlen=LIVE_BACKLOG)
        self._count: int | None = None
        self._lock = threading.Lock()
        self._bell = threading.Event()
        self._stop = False
        self._thread = threading.Thread(
            target=self._run, name="record-display", daemon=True
        )
        self._thread.start()

    def post(self, line: str | None, count: int) -> None:
        """Reader thread: queue only."""
        with self._lock:
            if line is not None and self._on_event is not None:
                self._lines.append(line)
            self._count = count
        self._bell.set()

    def close(self) -> None:
        """Stop after the queued callbacks (never waits for them)."""
        self._stop = True
        self._bell.set()

    def _run(self) -> None:
        while True:
            self._bell.wait()
            self._bell.clear()
            with self._lock:
                lines = list(self._lines)
                self._lines.clear()
                count, self._count = self._count, None
            for line in lines:
                if self._on_event is not None:
                    try:
                        self._on_event(line)
                    except Exception:
                        pass
            if count is not None and self._on_count is not None:
                try:
                    self._on_count(count)
                except Exception:
                    pass
            if self._stop:
                return


class RecordingWrapper:
    """Non-blocking Record: a lease on the shared getevent stream.

    Provides:
    - Event counting and elapsed time tracking
    - Callbacks for live event display (``/dev/input/eventN: tttt cccc vvvvvvvv``)
    - Clean termination support (writes the recording at :meth:`stop`)
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
            on_event: Optional callback for each event line (live display);
                runs on Record's dispatcher thread, never the reader's.
            on_count_update: Optional callback with the event count (same
                thread, coalesced). Pollers can read :attr:`event_count`.
            serial: Device serial (default: the timeline's / ADB's device).
        """
        self.output_file_path = output_file
        self.on_event = on_event
        self.on_count_update = on_count_update
        self._serial = serial

        self._stream: Any = None
        self._unsubscribe: Callable[[], None] | None = None
        self._tracking_gen: int | None = None
        self._line_start: int | None = None
        self._stopped = False
        self._event_count = 0
        self._start_time: float | None = None
        self._stop_time: float | None = None
        self._duration = 0
        self._lines: list[tuple[int, str]] = []
        self._offset: float | None = None  # device mono - host epoch (s)
        self._touch_node: str | None = None
        self._dispatcher: _Dispatcher | None = None
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

    @property
    def holds_lease(self) -> bool:
        """The getevent lease is held (also while the stream restarts)."""
        return self._stream is not None

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
                self._tracking_gen = tracking.start_session(serial, reason="record")
            stream = tracking.getevent(serial)
        except Exception as e:
            logger.error(f"Failed to start recording: {e}")
            self._stop_own_tracking()
            return False
        self._serial = serial
        self._lines = []
        self._offset = None
        self._touch_node = None
        self._stopped = False
        self._event_count = 0
        if self.on_event is not None or self.on_count_update is not None:
            self._dispatcher = _Dispatcher(self.on_event, self.on_count_update)
        self._stream = stream
        self._line_start = None
        self._start_time = time.time()
        # Subscribe first, then fix the first line: every line after it is
        # delivered to us (lines that raced in are sorted out by number).
        self._unsubscribe = stream.subscribe(self._on_line)
        with self._lock:
            self._line_start = stream.line_no() + 1
            self._lines = [x for x in self._lines if x[0] >= self._line_start]
            self._event_count = len(self._lines)
        logger.info("Recording started")
        return True

    def stop(self) -> int:
        """Stop recording, write the recording, and return the duration.

        Returns:
            Duration of recording in seconds.
        """
        if self._stopped:
            return self._duration

        # Measure first: once ``_stopped`` is set, ``elapsed_seconds`` returns
        # the (still 0) ``_duration`` -- which made every recording report
        # "N events, 0s".
        self._stop_time = time.time()
        self._duration = self.elapsed_seconds
        self._stopped = True

        stream, self._stream = self._stream, None
        if self._dispatcher is not None:
            self._dispatcher.close()
            self._dispatcher = None
        if stream is None:
            return self._duration
        try:
            if self._unsubscribe is not None:
                self._unsubscribe()
                self._unsubscribe = None
            n = self._write()
            logger.debug(f"Recording stopped: {n} lines, {self._duration}s")
        except Exception as e:
            logger.error(f"Error stopping recording: {e}")
        finally:
            stream.release()
            self._stop_own_tracking()
        return self._duration

    def _stop_own_tracking(self) -> None:
        gen, self._tracking_gen = self._tracking_gen, None
        if gen is None:
            return
        try:
            from sandroid.services.tracking_service import get_tracking

            # Only the session Record started: never one the user restarted.
            get_tracking().stop(reason="record", only_gen=gen)
        except Exception:
            logger.debug("Stopping Record's Tracking failed", exc_info=True)

    def _on_line(self, line: str, line_no: int, host_recv: float) -> None:
        """Reader thread: keep event lines, feed the live display. Never
        blocks (the display callbacks run on the dispatcher thread).
        """
        from sandroid.services.tracking_service import parse_getevent

        if self._stopped:
            return
        parsed = parse_getevent(line)
        if parsed is None:
            return
        ts, node, typ, code, _val = parsed
        with self._lock:
            start = self._line_start
            if start is not None and line_no < start:
                return
            self._lines.append((line_no, line))
            self._event_count += 1
            count = self._event_count
            off = ts - host_recv  # <= the true offset (receive comes later)
            if self._offset is None or off > self._offset:
                self._offset = off
            if self._touch_node is None and typ == 3 and code in (0x35, 0x36, 0x39):
                self._touch_node = node
        dispatcher = self._dispatcher
        if dispatcher is not None:
            dispatcher.post(line.split("]", 1)[-1].strip(), count)

    def _clock_offset(self) -> float | None:
        """Device CLOCK_MONOTONIC minus host epoch, seconds."""
        with self._lock:
            if self._offset is not None:
                return self._offset
        try:
            from sandroid.core import device_clock

            # Only a sample of the current world: one from before a snapshot
            # load / cold boot has the old CLOCK_MONOTONIC offset.
            sample = device_clock.last_sample(self._serial, current_world=True)
            off = (sample or {}).get("off_mono")  # host = dev_mono + off_mono
            if isinstance(off, (int, float)):
                return -float(off)
        except Exception:
            logger.debug("Record: no device clock sample", exc_info=True)
        return None

    def _marker_node(self) -> str:
        if self._touch_node:
            return self._touch_node
        try:
            from sandroid.services.tracking_service import get_tracking

            nodes = sorted(get_tracking().geometry.maxima)
            if nodes:
                return nodes[0]
        except Exception:
            pass
        return DEFAULT_MARKER_NODE

    def _write(self) -> int:
        """The kept lines between the start and stop markers (atomic)."""
        from sandroid.services.tracking_service import parse_getevent

        with self._lock:
            start = self._line_start or 0
            lines = [line for n, line in self._lines if n >= start]
        out = [line if line.endswith("\n") else line + "\n" for line in lines]
        off = self._clock_offset()
        if off is not None and self._start_time is not None:
            stamps = [p[0] for p in map(parse_getevent, lines) if p is not None]
            t0 = self._start_time + off
            t1 = (self._stop_time or time.time()) + off
            if stamps:  # the estimate never reorders the events
                t0, t1 = min(t0, stamps[0]), max(t1, stamps[-1])
            node = self._marker_node()
            out = [marker_line(t0, node) + "\n", *out, marker_line(t1, node) + "\n"]
        else:
            logger.warning(
                "Record: device time unknown, no start/stop markers "
                "(Play starts at the first touch)"
            )
        tmp = Path(f"{self.output_file_path}.part")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.writelines(out)
        tmp.replace(self.output_file_path)
        return len(out)

    def __del__(self):
        """Ensure recording is stopped on garbage collection."""
        with contextlib.suppress(Exception):
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
