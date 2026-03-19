"""Activity Log Adapter for Sandroid TUI.

This module provides the :class:`ActivityLogAdapter` which wraps the
``ActivityLog`` widget with safe logging methods. Each method silently
catches exceptions so that logging never crashes the application.

Before this extraction, six nearly-identical helper methods lived in
``SandroidTUI``.  The adapter centralises them in one place.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from textual.app import App

    from sandroid.tui.widgets import ActivityLog

logger = logging.getLogger(__name__)


class ActivityLogAdapter:
    """Safe wrapper around the ActivityLog widget.

    All public methods query the widget by its CSS id and delegate to the
    corresponding ``ActivityLog`` method.  If the widget is not mounted yet
    (or the query fails for any reason), the call is silently ignored so
    that controller code never needs to guard against missing widgets.

    Args:
        app: The Textual ``App`` instance used to query widgets.
        widget_id: CSS selector for the activity log widget.
    """

    def __init__(self, app: App, widget_id: str = "#activity-log") -> None:
        self._app = app
        self._widget_id = widget_id

    def _get_log(self) -> ActivityLog | None:
        """Retrieve the ActivityLog widget.

        First tries the fast ``app.query_one`` path (works when the active
        screen owns the widget).  If that fails — e.g. because a modal is
        pushed on top — falls back to iterating ``screen_stack``, matching
        the pattern used by ``action_copy_log`` in ``app.py``.
        """
        try:
            from sandroid.tui.widgets import ActivityLog

            # Fast path: current screen owns the widget
            try:
                return self._app.query_one(self._widget_id, ActivityLog)
            except Exception:
                pass

            # Fallback: widget may be on a non-active screen (modal on top)
            for screen in self._app.screen_stack:
                try:
                    return screen.query_one(self._widget_id, ActivityLog)
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def _delegate(self, method_name: str, *args) -> None:
        """Call *method_name* on the ActivityLog widget if it is mounted."""
        log = self._get_log()
        if log is not None:
            try:
                getattr(log, method_name)(*args)
            except Exception:
                logger.debug("ActivityLog.%s() failed", method_name, exc_info=True)

    # -- Level-specific helpers -------------------------------------------

    def log_info(self, message: str) -> None:
        """Log an info-level message to the activity log."""
        self._delegate("log_info", message)

    def log_warning(self, message: str) -> None:
        """Log a warning-level message to the activity log."""
        self._delegate("log_warning", message)

    def log_error(self, message: str) -> None:
        """Log an error-level message to the activity log."""
        self._delegate("log_error", message)

    def log_success(self, message: str) -> None:
        """Log a success-level message to the activity log."""
        self._delegate("log_success", message)

    # -- Extended helpers --------------------------------------------------

    def log_message(self, message: str, source: str) -> None:
        """Log a message with source tag to activity log."""
        self._delegate("log_message", message, source)

    def log_task_started(self, name: str, description: str) -> None:
        """Log task started to activity log."""
        self._delegate("log_task_started", name, description)

    def log_task_stopped(self, name: str) -> None:
        """Log task stopped to activity log."""
        self._delegate("log_task_stopped", name)

    def scroll_to_bottom(self) -> None:
        """Scroll activity log to bottom."""
        log = self._get_log()
        if log is not None:
            log.scroll_end(animate=False)
