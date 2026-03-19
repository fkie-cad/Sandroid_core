"""Forensic APK Service for Sandroid.

This service manages IOC-matched APKs that have been pulled from devices
during forensic scanning for further analysis or emulator installation.

Extracted from Toolbox class to follow Single Responsibility Principle.

Usage:
    from sandroid.services import get_forensic_apk_service
    from sandroid.services.forensic_apk_service import ForensicAPKService, ForensicAPK

    # Get service
    apk_service = get_forensic_apk_service()

    # Add a forensic APK
    apk = ForensicAPK(
        package_name="com.suspicious.app",
        source_device="emulator-5554",
        source_device_name="Pixel 6 Pro",
        local_path="/results/apks/suspicious.apk",
        ioc_matches=["hash:abc123"],
        severity="high"
    )
    apk_service.add(apk)

    # Query APKs
    all_apks = apk_service.get_all()
    device_apks = apk_service.get_by_device("emulator-5554")
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)


@dataclass
class ForensicAPK:
    """Represents a forensic evidence APK pulled from a device.

    These are APKs that matched IOC indicators during forensic scanning
    and were pulled for further analysis or installation to an emulator.

    Attributes:
        package_name: Android package name (e.g., "com.suspicious.app")
        source_device: Device serial it was pulled from
        source_device_name: Display name of source device
        local_path: Local filesystem path to the APK file
        pull_timestamp: When the APK was pulled from the device
        ioc_matches: List of IOC indicator values that matched
        severity: Highest severity level: "critical", "high", "medium", "low"
        file_hash: MD5 hash of the APK file
    """

    package_name: str
    source_device: str
    source_device_name: str = ""
    local_path: str = ""
    pull_timestamp: datetime = field(default_factory=datetime.now)
    ioc_matches: list[str] = field(default_factory=list)
    severity: str = "unknown"
    file_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization.

        Returns:
            Dictionary representation of the APK.
        """
        return {
            "package_name": self.package_name,
            "source_device": self.source_device,
            "source_device_name": self.source_device_name,
            "local_path": self.local_path,
            "pull_timestamp": self.pull_timestamp.isoformat(),
            "ioc_matches": self.ioc_matches,
            "severity": self.severity,
            "file_hash": self.file_hash,
        }


class ForensicAPKService:
    """Service for managing forensic evidence APKs.

    This service manages APKs that were pulled from devices after matching
    IOC (Indicators of Compromise) indicators during forensic scanning.

    Thread Safety:
        This service is thread-safe. All operations are protected by locks.

    Attributes:
        event_bus: Optional event bus for publishing state changes

    Example:
        # Basic usage
        service = ForensicAPKService()

        apk = ForensicAPK(
            package_name="com.suspicious.app",
            source_device="emulator-5554",
            source_device_name="Pixel 6 Pro",
            local_path="/results/apks/suspicious.apk",
            ioc_matches=["hash:abc123"],
            severity="high"
        )
        service.add(apk)

        # Query
        if service.has_apks():
            for apk in service.get_all():
                print(f"{apk.package_name}: {apk.severity}")
    """

    def __init__(self, event_bus: EventBusProtocol | None = None):
        """Initialize ForensicAPKService.

        Args:
            event_bus: Optional event bus for state change notifications.
        """
        self._event_bus = event_bus
        self._logger = logger
        self._lock = threading.RLock()
        self._apks: list[ForensicAPK] = []
        self._install_warned: bool = False

    def add(self, apk: ForensicAPK) -> None:
        """Add a forensic APK to tracking.

        Args:
            apk: ForensicAPK instance to track.
        """
        with self._lock:
            self._apks.append(apk)

        self._logger.info(
            f"Tracked forensic APK: {apk.package_name} from {apk.source_device_name}"
        )
        self._publish_apk_added(apk)

    def get_all(self) -> list[ForensicAPK]:
        """Get all tracked forensic APKs.

        Returns:
            Copy of the list of ForensicAPK instances.
        """
        with self._lock:
            return self._apks.copy()

    def get_by_device(self, device_serial: str) -> list[ForensicAPK]:
        """Get forensic APKs pulled from a specific device.

        Args:
            device_serial: Device serial to filter by.

        Returns:
            List of ForensicAPK instances from that device.
        """
        with self._lock:
            return [apk for apk in self._apks if apk.source_device == device_serial]

    def get_by_package(self, package_name: str) -> list[ForensicAPK]:
        """Get forensic APKs by package name.

        Args:
            package_name: Package name to filter by.

        Returns:
            List of ForensicAPK instances with that package name.
        """
        with self._lock:
            return [apk for apk in self._apks if apk.package_name == package_name]

    def get_by_severity(self, severity: str) -> list[ForensicAPK]:
        """Get forensic APKs by severity level.

        Args:
            severity: Severity level to filter by.

        Returns:
            List of ForensicAPK instances with that severity.
        """
        with self._lock:
            return [apk for apk in self._apks if apk.severity == severity]

    def remove(self, package_name: str, source_device: str | None = None) -> bool:
        """Remove a forensic APK from tracking.

        Args:
            package_name: Package name of the APK.
            source_device: Device serial it was pulled from (optional).
                          If None, removes first match by package name.

        Returns:
            True if found and removed, False otherwise.
        """
        with self._lock:
            for i, apk in enumerate(self._apks):
                if apk.package_name == package_name:
                    if source_device is None or apk.source_device == source_device:
                        removed = self._apks.pop(i)
                        self._logger.info(
                            f"Removed forensic APK: {removed.package_name}"
                        )
                        return True
        return False

    def clear(self) -> None:
        """Clear all tracked forensic APKs."""
        with self._lock:
            count = len(self._apks)
            self._apks.clear()
            self._install_warned = False

        self._logger.info(f"Cleared {count} forensic APKs")

    def has_apks(self) -> bool:
        """Check if any forensic APKs are tracked.

        Returns:
            True if at least one forensic APK is tracked.
        """
        with self._lock:
            return len(self._apks) > 0

    def count(self) -> int:
        """Get the number of tracked APKs.

        Returns:
            Number of forensic APKs.
        """
        with self._lock:
            return len(self._apks)

    def get_install_warned(self) -> bool:
        """Check if the install warning has been shown.

        The install warning is shown once when user attempts to install
        a suspicious APK to the emulator.

        Returns:
            True if warning was already shown.
        """
        with self._lock:
            return self._install_warned

    def set_install_warned(self, warned: bool = True) -> None:
        """Set the install warning flag.

        Args:
            warned: Whether warning has been shown.
        """
        with self._lock:
            self._install_warned = warned

    def get_severity_counts(self) -> dict[str, int]:
        """Get count of APKs by severity level.

        Returns:
            Dictionary mapping severity to count.
        """
        with self._lock:
            counts: dict[str, int] = {}
            for apk in self._apks:
                counts[apk.severity] = counts.get(apk.severity, 0) + 1
            return counts

    def get_state_dict(self) -> dict[str, Any]:
        """Get service state as a dictionary.

        Useful for API responses and debugging.

        Returns:
            Dictionary with service state.
        """
        with self._lock:
            return {
                "apk_count": len(self._apks),
                "install_warned": self._install_warned,
                "severity_counts": self.get_severity_counts(),
                "apks": [apk.to_dict() for apk in self._apks],
            }

    def reset(self) -> None:
        """Reset service state.

        Clears all APKs and flags. Useful for testing.
        """
        with self._lock:
            self._apks.clear()
            self._install_warned = False

    def _publish_apk_added(self, apk: ForensicAPK) -> None:
        """Publish event when APK is added."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={
                    "component": "forensic_apk",
                    "action": "added",
                    "package_name": apk.package_name,
                    "source_device": apk.source_device,
                    "severity": apk.severity,
                },
                source="forensic_apk_service",
            )
        )


__all__ = ["ForensicAPK", "ForensicAPKService"]
