"""Data types for the forensic analysis service.

This module contains shared dataclasses and protocols used by ForensicService
and its extracted components (ForensicTimeline, forensic_utils).

Usage:
    from sandroid.services.forensic_service_types import TimelineEntry, Snapshot
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol


@dataclass
class TimelineEntry:
    """Represents an entry in the forensic timeline.

    Attributes:
        timestamp: Unix timestamp of the event.
        relative_time: Time relative to action start (e.g., "+5s").
        file_path: Path to the affected file.
        change_type: Type of change ("modified", "created", "deleted").
        color: Color code for display.
    """

    timestamp: int
    relative_time: str
    file_path: str
    change_type: str = "modified"
    color: str = ""


@dataclass
class Snapshot:
    """Represents a forensic snapshot.

    Attributes:
        name: Snapshot identifier.
        path: Path to snapshot directory.
        file_count: Number of files in snapshot.
        created_at: When the snapshot was created.
        baseline_hash: Hash of the baseline state.
    """

    name: str
    path: str = ""
    file_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    baseline_hash: str = ""


class AdbProtocol(Protocol):
    """Protocol for ADB dependency injection."""

    @staticmethod
    def send_adb_command(command: str) -> tuple:
        """Send an ADB command.

        Returns:
            Tuple of (stdout, stderr).
        """
        ...


__all__ = [
    "AdbProtocol",
    "Snapshot",
    "TimelineEntry",
]
