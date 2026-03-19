"""Output buffer service for background task output.

Manages a bounded, thread-safe ring buffer of output lines produced by
background tasks.  Supports filtering by task name, legacy tuple-based
access, and event publishing on new output.

Usage::

    from sandroid.services.output_buffer_service import OutputBufferService

    buffer = OutputBufferService(max_lines=50)
    buffer.add_output("SSL handshake", task_name="fritap")
    recent = buffer.get_recent_output(5)
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)


@dataclass
class OutputLine:
    """Represents a single line of background task output.

    Attributes:
        message: The output message text.
        task_name: Name of the task that produced the output.
        timestamp: When the output was generated.
        level: Output level (``'info'``, ``'warning'``, ``'error'``, ``'debug'``).
    """

    message: str
    task_name: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)
    level: str = "info"


class OutputBufferService:
    """Thread-safe bounded output buffer for background task messages.

    Example::

        service = OutputBufferService(max_lines=50)
        service.add_output("Hook triggered", task_name="fritap")
        lines = service.get_recent_output(5)
    """

    def __init__(
        self,
        event_bus: EventBusProtocol | None = None,
        max_lines: int = 50,
    ) -> None:
        """Initialize the OutputBufferService.

        Args:
            event_bus: Optional EventBus for publishing TASK_OUTPUT events.
            max_lines: Maximum number of output lines to buffer (default 50).
        """
        self._lock = threading.Lock()
        self._event_bus = event_bus
        self._logger = logger
        self._buffer: list[OutputLine] = []
        self._max_lines = max_lines

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def add_output(
        self,
        message: str,
        task_name: str | None = None,
        timestamp: datetime | None = None,
        level: str = "info",
    ) -> None:
        """Add an output line to the buffer.

        If the buffer exceeds *max_lines*, the oldest entries are removed.

        Args:
            message: The output message text.
            task_name: Name of the task producing the output (optional).
            timestamp: When the output occurred (defaults to now).
            level: Output level.
        """
        output_line = OutputLine(
            message=message,
            task_name=task_name,
            timestamp=timestamp or datetime.now(),
            level=level,
        )

        with self._lock:
            self._buffer.append(output_line)
            while len(self._buffer) > self._max_lines:
                self._buffer.pop(0)

        self._logger.debug(
            f"Added output: [{task_name or 'system'}] {message[:50]}..."
            if len(message) > 50
            else f"Added output: [{task_name or 'system'}] {message}"
        )

    def get_recent_output(self, count: int | None = None) -> list[OutputLine]:
        """Get recent output lines from the buffer.

        Args:
            count: Number of recent lines to retrieve.  If ``None``, returns
                all lines.

        Returns:
            List of :class:`OutputLine` entries, most recent last.
        """
        with self._lock:
            if count is None:
                return self._buffer.copy()
            return self._buffer[-count:]

    def get_output_by_task(self, task_name: str) -> list[OutputLine]:
        """Get output lines filtered by task name.

        Args:
            task_name: Name of the task to filter by.

        Returns:
            List of :class:`OutputLine` entries from the specified task.
        """
        with self._lock:
            return [line for line in self._buffer if line.task_name == task_name]

    def clear_output(self) -> int:
        """Clear the output buffer.

        Returns:
            Number of lines that were cleared.
        """
        with self._lock:
            count = len(self._buffer)
            self._buffer.clear()
            self._logger.info(f"Cleared {count} output lines from buffer")
            return count

    def get_output_count(self) -> int:
        """Get the current number of output lines in the buffer.

        Returns:
            Number of output lines currently buffered.
        """
        with self._lock:
            return len(self._buffer)

    def set_max_output_lines(self, max_lines: int) -> None:
        """Set the maximum number of output lines to buffer.

        Args:
            max_lines: New maximum buffer size.
        """
        with self._lock:
            self._max_lines = max_lines
            while len(self._buffer) > max_lines:
                self._buffer.pop(0)

    # ------------------------------------------------------------------
    # Legacy compatibility helpers
    # ------------------------------------------------------------------

    def buffer_background_output(self, task_name: str, message: str) -> None:
        """Buffer output from a background task for display in menu.

        Legacy API compatible with ``Toolbox.buffer_background_output`` signature.
        Adds the output to the buffer and emits a ``TASK_OUTPUT`` event.

        Args:
            task_name: Name of the background task producing the output.
            message: The message/output to buffer.
        """
        timestamp = datetime.now()
        self.add_output(message=message, task_name=task_name, timestamp=timestamp)

        if self._event_bus is not None:
            from sandroid.core.events import Event, EventType

            self._event_bus.publish(
                Event(
                    type=EventType.TASK_OUTPUT,
                    data={
                        "task_name": task_name,
                        "message": message,
                        "timestamp": timestamp.strftime("%H:%M:%S"),
                    },
                    source=task_name,
                )
            )

    def get_recent_background_output(
        self, count: int = 5
    ) -> list[tuple[str, str, str]]:
        """Get the most recent background output lines in legacy format.

        Legacy API compatible with ``Toolbox.get_recent_background_output``.

        Args:
            count: Number of recent lines to return (default 5).

        Returns:
            List of ``(timestamp, task_name, message)`` tuples.
        """
        recent = self.get_recent_output(count)
        return [
            (line.timestamp.strftime("%H:%M:%S"), line.task_name or "", line.message)
            for line in recent
        ]

    # ------------------------------------------------------------------
    # State helpers
    # ------------------------------------------------------------------

    def get_state_dict(self) -> dict[str, Any]:
        """Return buffer state as a dictionary."""
        with self._lock:
            return {
                "output_buffer_count": len(self._buffer),
                "output_max_lines": self._max_lines,
            }

    def reset(self) -> None:
        """Clear all buffered output."""
        with self._lock:
            self._buffer.clear()


__all__ = [
    "OutputBufferService",
    "OutputLine",
]
