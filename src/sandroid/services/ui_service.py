"""UI State Service for Sandroid.

This service manages UI-related state extracted from Toolbox, including
view management, background output buffering, warning flags, and tool usage tracking.

Extracted from Toolbox class to follow Single Responsibility Principle.

The heavy rendering and dialog logic has been further extracted into:
  - :mod:`sandroid.core.notifications.blocking_dialog` -- blocking dialogs
  - :mod:`sandroid.services.output_buffer_service` -- output ring buffer
  - :mod:`sandroid.services.renderers` -- emulator info / exit summary / boxes

This module retains view cycling, warning flags, and backward-compatible
delegation methods so that existing callers do not need to change.

Usage:
    from sandroid.services import get_ui_service
    from sandroid.services.ui_service import UIService

    # Get service
    ui_service = get_ui_service()

    # View management
    current_view = ui_service.get_current_view()
    next_view = ui_service.cycle_view()
    ui_service.set_current_view("network")

    # Output buffer management
    ui_service.add_output("Hook triggered", task_name="fritap")
    recent = ui_service.get_recent_output(10)

    # Tool tracking
    ui_service.track_tool_used("sqldiff", "/data/data/com.app/databases/app.db")
    tools = ui_service.get_tools_used()
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sandroid.core.enums import ViewMode
from sandroid.core.notifications.blocking_dialog import BlockingDialogService
from sandroid.services.output_buffer_service import OutputBufferService, OutputLine
from sandroid.services.protocols import EventBusProtocol
from sandroid.services.renderers import (
    BoxRenderer,
    EmulatorInfoRenderer,
    ExitSummaryRenderer,
)

logger = logging.getLogger(__name__)


@dataclass
class ToolUsage:
    """Represents usage of an analysis tool on a file.

    Attributes:
        tool_name: Name of the tool used (e.g., "sqldiff", "xxd")
        file_path: Path to the file the tool was used on
        used_at: When the tool was used
        count: Number of times tool was used on this file
    """

    tool_name: str
    file_path: str
    used_at: datetime = field(default_factory=datetime.now)
    count: int = 1


class UIService:
    """Service for managing UI-related state.

    This service handles view cycling, output buffering for background tasks,
    one-time warning flags, and tracking of tools used during analysis.

    Thread Safety:
        All operations are thread-safe through internal locking.

    Example:
        service = UIService()

        # View management
        service.set_current_view("forensic")
        next_view = service.cycle_view()  # Returns "malware" (next in cycle)

        # Output buffering
        service.add_output("SSL handshake intercepted", task_name="fritap")
        lines = service.get_recent_output(5)

        # Tool tracking
        service.track_tool_used("sqldiff", "/data/data/com.app/db.sqlite")
    """

    # Default view cycle order (the three implemented interactive views)
    DEFAULT_VIEW_CYCLE = [
        ViewMode.FORENSIC,
        ViewMode.MALWARE,
        ViewMode.SECURITY,
    ]

    def __init__(
        self,
        event_bus: EventBusProtocol | None = None,
        view_cycle: list[str | ViewMode] | None = None,
        max_output_lines: int = 50,
    ):
        """Initialize the UIService.

        Args:
            event_bus: Optional EventBus for publishing state change events.
            view_cycle: Optional list of views to cycle through. Defaults to
                       [ViewMode.FORENSIC, ViewMode.MALWARE, ViewMode.SECURITY].
            max_output_lines: Maximum number of output lines to buffer (default 50).
        """
        self._lock = threading.Lock()
        self._event_bus = event_bus
        self._logger = logger

        # View state
        self._view_cycle = view_cycle or self.DEFAULT_VIEW_CYCLE.copy()
        self._current_view = (
            self._view_cycle[0] if self._view_cycle else ViewMode.FORENSIC
        )

        # Warning flags
        self._forensic_install_warned = False
        self._exit_summary_printed = False

        # Tool usage tracking (legacy -- kept for backward compat)
        self._tools_used: dict[str, dict[str, ToolUsage]] = {}

        # Delegates
        self._output_buffer = OutputBufferService(
            event_bus=event_bus, max_lines=max_output_lines
        )
        self._dialog = BlockingDialogService()

    # =========================================================================
    # View Management
    # =========================================================================

    def get_current_view(self) -> str | ViewMode:
        """Get the currently active view.

        Returns:
            The current view (e.g., ViewMode.FORENSIC, ViewMode.NETWORK).
        """
        with self._lock:
            return self._current_view

    def set_current_view(self, view: str | ViewMode) -> bool:
        """Set the current view.

        Args:
            view: View to set as current (ViewMode or string).

        Returns:
            True if view was valid and set, False if view is not in cycle.
        """
        if isinstance(view, str):
            try:
                view = ViewMode(view)
            except ValueError:
                pass

        with self._lock:
            if view not in self._view_cycle:
                self._logger.warning(
                    f"Attempted to set invalid view '{view}'. "
                    f"Valid views: {self._view_cycle}"
                )
                return False

            previous_view = self._current_view
            self._current_view = view
            self._logger.debug(f"View changed from '{previous_view}' to '{view}'")

        self._publish_view_changed(view, previous_view)
        return True

    def cycle_view(self) -> str | ViewMode:
        """Cycle to the next view in the view cycle.

        Returns:
            The new current view after cycling.
        """
        with self._lock:
            if not self._view_cycle:
                return self._current_view

            current_index = self._view_cycle.index(self._current_view)
            next_index = (current_index + 1) % len(self._view_cycle)
            previous_view = self._current_view
            self._current_view = self._view_cycle[next_index]
            new_view = self._current_view

            self._logger.debug(f"Cycled view from '{previous_view}' to '{new_view}'")

        self._publish_view_changed(new_view, previous_view)
        return new_view

    def get_view_options(self) -> list[str | ViewMode]:
        """Get the list of valid views in cycle order.

        Returns:
            List of views that can be cycled through.
        """
        with self._lock:
            return self._view_cycle.copy()

    def set_view_cycle(self, views: list[str | ViewMode]) -> None:
        """Set the view cycle order.

        Args:
            views: List of views in the desired cycle order.
        """
        with self._lock:
            self._view_cycle = views.copy()
            if self._current_view not in self._view_cycle and self._view_cycle:
                self._current_view = self._view_cycle[0]

    # =========================================================================
    # Output Buffer Management  (delegates to OutputBufferService)
    # =========================================================================

    def add_output(
        self,
        message: str,
        task_name: str | None = None,
        timestamp: datetime | None = None,
        level: str = "info",
    ) -> None:
        """Add an output line to the buffer."""
        self._output_buffer.add_output(
            message=message, task_name=task_name, timestamp=timestamp, level=level
        )

    def get_recent_output(self, count: int | None = None) -> list[OutputLine]:
        """Get recent output lines from the buffer."""
        return self._output_buffer.get_recent_output(count)

    def get_output_by_task(self, task_name: str) -> list[OutputLine]:
        """Get output lines filtered by task name."""
        return self._output_buffer.get_output_by_task(task_name)

    def clear_output(self) -> int:
        """Clear the output buffer."""
        return self._output_buffer.clear_output()

    def get_output_count(self) -> int:
        """Get the current number of output lines in the buffer."""
        return self._output_buffer.get_output_count()

    def set_max_output_lines(self, max_lines: int) -> None:
        """Set the maximum number of output lines to buffer."""
        self._output_buffer.set_max_output_lines(max_lines)

    def buffer_background_output(self, task_name: str, message: str) -> None:
        """Buffer output from a background task for display in menu."""
        self._output_buffer.buffer_background_output(task_name, message)

    def get_recent_background_output(
        self, count: int = 5
    ) -> list[tuple[str, str, str]]:
        """Get the most recent background output lines in legacy format."""
        return self._output_buffer.get_recent_background_output(count)

    # =========================================================================
    # Warning Flags
    # =========================================================================

    def is_forensic_install_warned(self) -> bool:
        """Check if the forensic install warning has been shown."""
        with self._lock:
            return self._forensic_install_warned

    def set_forensic_install_warned(self, warned: bool = True) -> None:
        """Set the forensic install warning flag."""
        with self._lock:
            self._forensic_install_warned = warned
            if warned:
                self._logger.debug("Forensic install warning flag set")

    # =========================================================================
    # Tool Usage Tracking  (legacy -- kept for backward compat)
    # =========================================================================

    def track_tool_used(self, tool_name: str, file_path: str) -> None:
        """Track that a tool was used on a specific file."""
        with self._lock:
            if tool_name not in self._tools_used:
                self._tools_used[tool_name] = {}
            if file_path in self._tools_used[tool_name]:
                self._tools_used[tool_name][file_path].count += 1
                self._tools_used[tool_name][file_path].used_at = datetime.now()
            else:
                self._tools_used[tool_name][file_path] = ToolUsage(
                    tool_name=tool_name, file_path=file_path
                )
        self._logger.debug(f"Tracked tool usage: {tool_name} on {file_path}")

    def get_tools_used(self) -> dict[str, dict[str, ToolUsage]]:
        """Get all tracked tool usage."""
        with self._lock:
            return {tool: dict(files) for tool, files in self._tools_used.items()}

    def get_tool_files(self, tool_name: str) -> list[str]:
        """Get list of files a specific tool was used on."""
        with self._lock:
            if tool_name not in self._tools_used:
                return []
            return list(self._tools_used[tool_name].keys())

    def was_tool_used(self, tool_name: str, file_path: str | None = None) -> bool:
        """Check if a tool was used, optionally on a specific file."""
        with self._lock:
            if tool_name not in self._tools_used:
                return False
            if file_path is None:
                return bool(self._tools_used[tool_name])
            return file_path in self._tools_used[tool_name]

    def clear_tool_tracking(self) -> int:
        """Clear all tool usage tracking."""
        with self._lock:
            count = sum(len(files) for files in self._tools_used.values())
            self._tools_used.clear()
            self._logger.info(f"Cleared {count} tool usage entries")
            return count

    # =========================================================================
    # State Management
    # =========================================================================

    def get_state_dict(self) -> dict[str, Any]:
        """Get the complete UI state as a dictionary."""
        with self._lock:
            state = {
                "current_view": self._current_view,
                "view_cycle": self._view_cycle.copy(),
                "forensic_install_warned": self._forensic_install_warned,
                "tools_used": {
                    tool: {
                        path: {
                            "used_at": usage.used_at.isoformat(),
                            "count": usage.count,
                        }
                        for path, usage in files.items()
                    }
                    for tool, files in self._tools_used.items()
                },
                "tools_count": sum(len(f) for f in self._tools_used.values()),
            }

        # Merge output buffer state (its own lock)
        state.update(self._output_buffer.get_state_dict())
        return state

    def reset(self) -> None:
        """Reset all UI state to defaults."""
        with self._lock:
            previous_view = self._current_view
            self._current_view = (
                self._view_cycle[0] if self._view_cycle else ViewMode.FORENSIC
            )
            self._forensic_install_warned = False
            self._tools_used.clear()

        self._output_buffer.reset()
        self._logger.info("Reset UI service state")

        if previous_view != self._current_view:
            self._publish_view_changed(self._current_view, previous_view)

    # =========================================================================
    # Blocking Dialogs  (delegates to BlockingDialogService)
    # =========================================================================

    def show_blocking_warning(
        self,
        title: str,
        message: str,
        action_hint: str | None = None,
        action_key: str | None = None,
    ) -> str | None:
        """Display a warning modal that requires user acknowledgment."""
        return self._dialog.show_warning(
            title=title, message=message, action_hint=action_hint, action_key=action_key
        )

    def show_blocking_error(
        self,
        title: str,
        message: str,
        action_hint: str | None = None,
        action_key: str | None = None,
    ) -> str | None:
        """Display an error modal that requires user acknowledgment."""
        return self._dialog.show_error(
            title=title, message=message, action_hint=action_hint, action_key=action_key
        )

    def show_blocking_info(
        self,
        title: str,
        message: str,
        action_hint: str | None = None,
        action_key: str | None = None,
    ) -> str | None:
        """Display an info modal that requires user acknowledgment."""
        return self._dialog.show_info(
            title=title, message=message, action_hint=action_hint, action_key=action_key
        )

    # =========================================================================
    # Input Handling  (delegates to BlockingDialogService)
    # =========================================================================

    def safe_input(self, prompt: str = "") -> str:
        """Safely read input from stdin with buffer flushing."""
        return self._dialog.safe_input(prompt)

    # =========================================================================
    # Box Rendering  (delegates to BoxRenderer)
    # =========================================================================

    def create_colored_box(
        self, text: str, title: str, border_color: str = "cyan"
    ) -> str:
        """Create a bordered box with colored borders and a title section."""
        return BoxRenderer.create_colored_box(text, title, border_color)

    def create_ascii_box(self, text: str, title: str) -> str:
        """Create an ASCII box with a title."""
        return BoxRenderer.create_ascii_box(text, title)

    # =========================================================================
    # Emulator Information Display  (delegates to EmulatorInfoRenderer)
    # =========================================================================

    def print_emulator_information(self, emulator_info: dict[str, Any]) -> None:
        """Display emulator/device information in a formatted Rich Panel."""
        EmulatorInfoRenderer.print_emulator_information(emulator_info)

    # =========================================================================
    # Exit Summary  (delegates to ExitSummaryRenderer)
    # =========================================================================

    def print_exit_summary(self, tools_used: dict[str, Any] | None = None) -> None:
        """Print summary of results folder and generated files on exit."""
        if self._exit_summary_printed:
            return
        self._exit_summary_printed = True
        ExitSummaryRenderer.print_exit_summary(tools_used or self.get_tools_used())

    # =========================================================================
    # Event Publishing (Private)
    # =========================================================================

    def _publish_view_changed(
        self,
        new_view: str,
        previous_view: str,
    ) -> None:
        """Publish a view changed event."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={
                    "change_type": "view_changed",
                    "view": new_view,
                    "previous_view": previous_view,
                },
                source="ui_service",
            )
        )


__all__ = [
    "OutputLine",
    "ToolUsage",
    "UIService",
]
