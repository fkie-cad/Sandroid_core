"""Recording process wrapper for TUI integration.

Non-blocking wrapper around `adb shell getevent` for recording input events
in the TUI without blocking the main thread.
"""

import logging
import os
import re
import threading
import time
from collections.abc import Callable

from sandroid.core.adb import Adb

logger = logging.getLogger(__name__)


class RecordingWrapper:
    """Non-blocking wrapper for ADB getevent recording.

    Provides:
    - Non-blocking event capture via background thread
    - Event counting and elapsed time tracking
    - Callbacks for live event display
    - Clean termination support
    """

    EVENT_LINE_RE = re.compile(r"(\S+): (\S+) (\S+) (\S+)$")

    def __init__(
        self,
        output_file: str,
        on_event: Callable[[str], None] | None = None,
        on_count_update: Callable[[int], None] | None = None,
    ):
        """Initialize the recording wrapper.

        Args:
            output_file: Path to save recording.txt
            on_event: Optional callback for each event line (for live display)
            on_count_update: Optional callback when event count changes
        """
        self.output_file_path = output_file
        self.on_event = on_event
        self.on_count_update = on_count_update

        self._process: object | None = None
        self._output_file: object | None = None
        self._reader_thread: threading.Thread | None = None
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
        return (
            self._process is not None
            and self._process.poll() is None
            and not self._stopped
        )

    def start(self) -> bool:
        """Start recording in background thread.

        Returns:
            True if recording started successfully, False otherwise.
        """
        if self._process is not None:
            logger.warning("Recording already in progress")
            return False

        # Ensure the directory exists before opening the file
        output_dir = os.path.dirname(self.output_file_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Open output file
        try:
            self._output_file = open(self.output_file_path, "w")
        except OSError as e:
            logger.error(f"Failed to open output file '{self.output_file_path}': {e}")
            return False

        try:
            # Start ADB getevent process
            self._process = Adb.send_adb_command_popen("shell getevent")

            if self._process is None:
                logger.error("Failed to start ADB getevent")
                self._output_file.close()
                return False

            self._start_time = time.time()
            self._stopped = False
            self._event_count = 0

            # Write initial dummy event
            self._write_dummy_event()

            # Start reader thread
            self._reader_thread = threading.Thread(
                target=self._read_events, daemon=True
            )
            self._reader_thread.start()

            logger.info("Recording started")
            return True

        except Exception as e:
            logger.error(f"Failed to start recording: {e}")
            if self._output_file and not self._output_file.closed:
                self._output_file.close()
            return False

    def stop(self) -> int:
        """Stop recording and return duration.

        Returns:
            Duration of recording in seconds.
        """
        if self._stopped:
            return self._duration

        self._stopped = True
        self._duration = self.elapsed_seconds

        try:
            # Write final dummy event
            if self._output_file and not self._output_file.closed:
                self._write_dummy_event()

            # Terminate ADB process
            if self._process and self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=2)
                except Exception:
                    self._process.kill()
                    self._process.wait(timeout=1)

            # Close output file
            if self._output_file and not self._output_file.closed:
                self._output_file.close()

            # Wait for reader thread
            if self._reader_thread and self._reader_thread.is_alive():
                self._reader_thread.join(timeout=1)

            logger.info(
                f"Recording stopped: {self._event_count} events, {self._duration}s"
            )

        except Exception as e:
            logger.error(f"Error stopping recording: {e}")

        return self._duration

    def _read_events(self) -> None:
        """Background thread to read events from ADB process."""
        try:
            while not self._stopped and self._process.poll() is None:
                try:
                    line = (
                        self._process.stdout.readline()
                        .decode("utf-8", "replace")
                        .strip()
                    )

                    if not line:
                        continue

                    match = self.EVENT_LINE_RE.match(line)
                    if match is not None:
                        dev, etype, ecode, data = match.groups()
                        self._write_event(dev, etype, ecode, data)

                        # Call live event callback if provided
                        if self.on_event:
                            try:
                                self.on_event(line)
                            except Exception:
                                pass

                except Exception as e:
                    if not self._stopped:
                        logger.debug(f"Error reading event: {e}")
                    break

        except Exception as e:
            logger.error(f"Reader thread error: {e}")

    def _write_event(self, dev: str, etype: str, ecode: str, data: str) -> None:
        """Write an input event to the output file.

        Args:
            dev: Device identifier (e.g., /dev/input/event1)
            etype: Event type (hex string)
            ecode: Event code (hex string)
            data: Event data (hex string)
        """
        if self._output_file is None or self._output_file.closed:
            return

        try:
            millis = int(round(time.time() * 1000))
            etype_int = int(etype, 16)
            ecode_int = int(ecode, 16)
            data_int = int(data, 16)

            rline = f"{millis} {dev} {etype_int} {ecode_int} {data_int}\n"
            self._output_file.write(rline)
            self._output_file.flush()

            with self._lock:
                self._event_count += 1
                count = self._event_count

            # Call count update callback if provided
            if self.on_count_update:
                try:
                    self.on_count_update(count)
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Error writing event: {e}")

    def _write_dummy_event(self) -> None:
        """Write a dummy event to mark recording boundaries."""
        self._write_event("/dev/input/event1", "0", "0", "0")

    def __del__(self):
        """Ensure recording is stopped on garbage collection."""
        if not self._stopped:
            self.stop()
