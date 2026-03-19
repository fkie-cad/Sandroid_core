"""Network Capture Service for Sandroid.

This service manages the state of network capture operations such as tcpdump,
Frida-based network interception, or other packet capture tools.

Extracted from Toolbox class to follow Single Responsibility Principle.
The NetworkCaptureService is responsible ONLY for capture state management,
NOT the actual capture implementation.

Usage:
    from sandroid.services import get_network_capture_service
    from sandroid.services.network_capture_service import NetworkCaptureService

    # Using service locator
    service = get_network_capture_service()

    # Or with dependency injection
    service = NetworkCaptureService(event_bus=EventBus.get())

    # Start capture (state only - actual capture handled elsewhere)
    service.start_capture("capture_20240115_120000.pcap")

    # Check status
    if service.is_capturing():
        filename = service.get_capture_file()
        print(f"Capturing to: {filename}")

    # Stop capture
    stopped_file = service.stop_capture()
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)


@dataclass
class CaptureSession:
    """Represents an active network capture session.

    Attributes:
        output_file: Path to the capture output file
        started_at: Timestamp when capture was started
        capture_type: Type of capture (e.g., "tcpdump", "fritap", "pcapdroid")
        target_app: Target application package name (if applicable)
        interface: Network interface being captured (if applicable)
        metadata: Additional capture-specific metadata
    """

    output_file: str
    started_at: datetime = field(default_factory=datetime.now)
    capture_type: str | None = None
    target_app: str | None = None
    interface: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class NetworkCaptureService:
    """Service for managing network capture state.

    This service tracks whether network capture is active and manages
    the capture output file path. It does NOT implement the actual
    capture logic - that is handled by capture implementations
    (tcpdump, FriTap, etc.).

    Thread Safety:
        All operations are thread-safe through internal locking.

    Example:
        service = NetworkCaptureService(event_bus=EventBus.get())

        # Start capture
        if service.start_capture("/tmp/capture.pcap"):
            print("Capture started")

        # Query status
        if service.is_capturing():
            print(f"Capturing to: {service.get_capture_file()}")

        # Stop capture
        filename = service.stop_capture()
        if filename:
            print(f"Capture saved to: {filename}")
    """

    def __init__(self, event_bus: EventBusProtocol | None = None):
        """Initialize the NetworkCaptureService.

        Args:
            event_bus: Optional EventBus for publishing capture lifecycle events.
                      If not provided, events will not be published.
        """
        self._session: CaptureSession | None = None
        self._lock = threading.Lock()
        self._event_bus = event_bus
        self._logger = logger

    def start_capture(
        self,
        output_file: str,
        capture_type: str | None = None,
        target_app: str | None = None,
        interface: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Start tracking a network capture session.

        This marks the capture as active and stores the output file path.
        The actual capture implementation should be started separately.

        Args:
            output_file: Path where capture will be saved
            capture_type: Type of capture (e.g., "tcpdump", "fritap")
            target_app: Target application package name (if app-specific)
            interface: Network interface being captured
            metadata: Additional capture-specific metadata

        Returns:
            True if capture started successfully, False if already capturing
        """
        with self._lock:
            if self._session is not None:
                self._logger.warning(
                    f"Capture already in progress to: {self._session.output_file}"
                )
                return False

            self._session = CaptureSession(
                output_file=output_file,
                started_at=datetime.now(),
                capture_type=capture_type,
                target_app=target_app,
                interface=interface,
                metadata=metadata or {},
            )

            self._logger.info(
                f"Network capture started: {output_file}"
                + (f" (type: {capture_type})" if capture_type else "")
                + (f" targeting {target_app}" if target_app else "")
            )

        # Publish event outside lock
        self._publish_capture_started()
        return True

    def stop_capture(self) -> str | None:
        """Stop tracking the network capture session.

        This marks the capture as inactive and returns the output file path.
        The actual capture implementation should be stopped separately.

        Returns:
            The capture output file path, or None if no capture was active
        """
        with self._lock:
            if self._session is None:
                self._logger.warning("No capture in progress to stop")
                return None

            session = self._session
            output_file = session.output_file
            self._session = None

            self._logger.info(f"Network capture stopped: {output_file}")

        # Publish event outside lock
        self._publish_capture_stopped(session)
        return output_file

    def is_capturing(self) -> bool:
        """Check if network capture is currently active.

        Returns:
            True if capture is in progress, False otherwise
        """
        with self._lock:
            return self._session is not None

    def get_capture_file(self) -> str | None:
        """Get the current capture output file path.

        Returns:
            The capture output file path, or None if not capturing
        """
        with self._lock:
            return self._session.output_file if self._session else None

    def get_session(self) -> CaptureSession | None:
        """Get the current capture session.

        Returns a copy to prevent external mutation.

        Returns:
            CaptureSession instance or None if not capturing
        """
        with self._lock:
            if self._session is None:
                return None
            # Return a new instance with the same data
            return CaptureSession(
                output_file=self._session.output_file,
                started_at=self._session.started_at,
                capture_type=self._session.capture_type,
                target_app=self._session.target_app,
                interface=self._session.interface,
                metadata=dict(self._session.metadata),
            )

    def get_capture_type(self) -> str | None:
        """Get the type of the current capture.

        Returns:
            The capture type (e.g., "tcpdump", "fritap") or None if not capturing
        """
        with self._lock:
            return self._session.capture_type if self._session else None

    def get_target_app(self) -> str | None:
        """Get the target application of the current capture.

        Returns:
            The target app package name or None if not capturing or no target
        """
        with self._lock:
            return self._session.target_app if self._session else None

    def get_duration_seconds(self) -> float | None:
        """Get the duration of the current capture in seconds.

        Returns:
            Duration in seconds, or None if not capturing
        """
        with self._lock:
            if self._session is None:
                return None
            return (datetime.now() - self._session.started_at).total_seconds()

    def get_status(self) -> dict[str, Any]:
        """Get detailed status of the current capture.

        Returns:
            Dictionary with capture status information:
            {
                "capturing": bool,
                "output_file": str | None,
                "capture_type": str | None,
                "target_app": str | None,
                "interface": str | None,
                "started_at": datetime | None,
                "duration_seconds": float | None,
                "metadata": dict
            }
        """
        with self._lock:
            if self._session is None:
                return {
                    "capturing": False,
                    "output_file": None,
                    "capture_type": None,
                    "target_app": None,
                    "interface": None,
                    "started_at": None,
                    "duration_seconds": None,
                    "metadata": {},
                }

            now = datetime.now()
            return {
                "capturing": True,
                "output_file": self._session.output_file,
                "capture_type": self._session.capture_type,
                "target_app": self._session.target_app,
                "interface": self._session.interface,
                "started_at": self._session.started_at,
                "duration_seconds": (now - self._session.started_at).total_seconds(),
                "metadata": dict(self._session.metadata),
            }

    def get_status_string(self) -> str:
        """Get a formatted string showing capture status for UI display.

        Returns:
            Formatted string like "[green]o[/green] Capturing: capture.pcap (45s)"
            or empty string if not capturing
        """
        with self._lock:
            if self._session is None:
                return ""

            duration = (datetime.now() - self._session.started_at).total_seconds()
            parts = [f"[green]o[/green] Capturing: {self._session.output_file}"]

            if self._session.capture_type:
                parts.append(f"({self._session.capture_type})")

            parts.append(f"[{int(duration)}s]")

            if self._session.target_app:
                parts.append(f"-> {self._session.target_app}")

            return " ".join(parts)

    def update_metadata(self, key: str, value: Any) -> bool:
        """Update metadata for the current capture session.

        Args:
            key: Metadata key to update
            value: Value to set

        Returns:
            True if metadata was updated, False if no capture is active
        """
        with self._lock:
            if self._session is None:
                return False
            self._session.metadata[key] = value
            return True

    def reset(self) -> str | None:
        """Force reset the capture state.

        Use this for cleanup when the capture process has crashed or
        been terminated externally. Returns the filename that was
        being captured to.

        Returns:
            The capture output file path that was reset, or None if not capturing
        """
        with self._lock:
            if self._session is None:
                return None

            output_file = self._session.output_file
            self._session = None
            self._logger.warning(f"Network capture state reset (was: {output_file})")
            return output_file

    # =========================================================================
    # Event Publishing (Private)
    # =========================================================================

    def _publish_capture_started(self) -> None:
        """Publish a capture started event."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        with self._lock:
            if self._session is None:
                return
            data = {
                "output_file": self._session.output_file,
                "capture_type": self._session.capture_type,
                "target_app": self._session.target_app,
                "interface": self._session.interface,
            }

        self._event_bus.publish(
            Event(
                type=EventType.NETWORK_EVENT,
                data={
                    "action": "capture_started",
                    **data,
                },
                source="network_capture_service",
            )
        )

    def _publish_capture_stopped(self, session: CaptureSession) -> None:
        """Publish a capture stopped event."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        duration = (datetime.now() - session.started_at).total_seconds()
        self._event_bus.publish(
            Event(
                type=EventType.NETWORK_EVENT,
                data={
                    "action": "capture_stopped",
                    "output_file": session.output_file,
                    "capture_type": session.capture_type,
                    "target_app": session.target_app,
                    "duration_seconds": duration,
                },
                source="network_capture_service",
            )
        )


# Backwards compatibility: Expose CaptureSession at module level
__all__ = [
    "CaptureSession",
    "NetworkCaptureService",
]
