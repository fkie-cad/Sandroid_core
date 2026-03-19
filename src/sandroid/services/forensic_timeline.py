"""Forensic Timeline Management.

This module provides the ForensicTimeline class, which manages timeline entries
and shadow timestamp lists for forensic analysis sessions.

Extracted from ForensicService to follow the Single Responsibility Principle.

Usage:
    from sandroid.services.forensic_timeline import ForensicTimeline

    timeline = ForensicTimeline()
    timeline.add_entry(1704067200, "/data/test.db", "modified")
    entries = timeline.get_entries()
"""

import logging
from typing import Any

from sandroid.services.forensic_service_types import TimelineEntry

logger = logging.getLogger(__name__)


class ForensicTimeline:
    """Manages forensic timeline entries and shadow timestamp tracking.

    This class handles:
    - Timeline entries with relative time calculation
    - Shadow timestamp list for timeline visualization
    - Timeline sorting and retrieval

    Example:
        timeline = ForensicTimeline()
        timeline.set_action_time(1704067200)
        timeline.add_entry(1704067205, "/data/test.db")
        entries = timeline.get_entries()
        assert entries[0].relative_time == "+5s"
    """

    def __init__(self) -> None:
        """Initialize the ForensicTimeline."""
        self._entries: list[TimelineEntry] = []
        self._shadow_ts_list: list[dict[str, Any]] = []
        self._action_time: int = 0

    @property
    def action_time(self) -> int:
        """Get the current action start time.

        Returns:
            Unix timestamp of action start.
        """
        return self._action_time

    @action_time.setter
    def action_time(self, value: int) -> None:
        """Set the action start time.

        Args:
            value: Unix timestamp of action start.
        """
        self._action_time = value

    def add_entry(
        self,
        timestamp: int,
        file_path: str,
        change_type: str = "modified",
    ) -> None:
        """Add an entry to the forensic timeline.

        Calculates relative time from the action start time automatically.

        Args:
            timestamp: Unix timestamp of the event.
            file_path: Path to the affected file.
            change_type: Type of change (e.g., "modified", "created", "deleted").
        """
        relative = self._calculate_relative_time(timestamp)
        entry = TimelineEntry(
            timestamp=timestamp,
            relative_time=relative,
            file_path=file_path,
            change_type=change_type,
        )
        self._entries.append(entry)

    def _calculate_relative_time(self, timestamp: int) -> str:
        """Calculate the relative time string from the action start.

        Args:
            timestamp: Unix timestamp of the event.

        Returns:
            Relative time string (e.g., "+5s", "-3s", or "").
        """
        if self._action_time <= 0:
            return ""
        delta = timestamp - self._action_time
        return f"+{delta}s" if delta >= 0 else f"{delta}s"

    def get_entries(self) -> list[TimelineEntry]:
        """Get timeline entries sorted by timestamp.

        Returns:
            List of TimelineEntry sorted by ascending timestamp.
        """
        return sorted(self._entries, key=lambda e: e.timestamp)

    def clear_entries(self) -> None:
        """Clear all timeline entries."""
        self._entries.clear()

    def add_shadow_entry(
        self,
        current_dir: str,
        filename: str,
        seconds_timestamp: int,
        color: str = "#1A535C",
        fetch_all: bool = False,
    ) -> None:
        """Add a file change entry to the shadow timestamp list.

        Creates timeline entries in the format expected by the timeline
        generation system. Each entry contains detailed information about
        file changes relative to the action start time.

        Args:
            current_dir: The directory containing the file.
            filename: The name of the file that changed.
            seconds_timestamp: The change time in Unix seconds.
            color: Color for timeline visualization.
            fetch_all: If True, the entry is not added (baseline scans).
        """
        if fetch_all:
            return

        entry = {
            "id": current_dir + filename,
            "name": filename,
            "action_base_time": self._action_time,
            "file_change_time": seconds_timestamp,
            "seconds_after_start": seconds_timestamp - self._action_time,
            "timeline_color": color,
        }
        self._shadow_ts_list.append(entry)

    def get_shadow_ts_list(self) -> list[dict[str, Any]]:
        """Get the shadow timestamp list (copy).

        Returns:
            Copy of the shadow timestamp list.
        """
        return self._shadow_ts_list.copy()

    @property
    def shadow_ts_list_ref(self) -> list[dict[str, Any]]:
        """Get the shadow timestamp list (direct reference).

        Used by metaclass property delegation for backward compatibility.

        Returns:
            Direct reference to the internal shadow timestamp list.
        """
        return self._shadow_ts_list

    @shadow_ts_list_ref.setter
    def shadow_ts_list_ref(self, value: list[dict[str, Any]]) -> None:
        """Set the shadow timestamp list by reference.

        Args:
            value: New shadow timestamp list.
        """
        self._shadow_ts_list = value

    def clear_shadow_ts_list(self) -> None:
        """Clear the shadow timestamp list."""
        self._shadow_ts_list.clear()

    def reset(self) -> None:
        """Reset all timeline state."""
        self._entries.clear()
        self._shadow_ts_list.clear()
        self._action_time = 0


__all__ = [
    "ForensicTimeline",
]
