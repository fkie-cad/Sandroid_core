"""Base notification handler interface.

This module defines the abstract base class that all notification handlers
must implement. This ensures consistency across different frontends.

Future Implementation:
    When implementing Phase 2, all handlers should inherit from NotificationHandler
    and implement the required methods.
"""

from abc import ABC, abstractmethod
from typing import Optional


# TODO: Implement in Phase 2
class NotificationHandler(ABC):
    """Abstract base class for notification handlers.

    All frontend-specific handlers (Terminal, Web, GUI) should inherit from
    this class and implement the required methods.

    Methods to implement:
        - display_info(title, message, action_hint)
        - display_warning(title, message, action_hint)
        - display_error(title, message, action_hint)
        - display_modal(title, message, level, action_hint)
        - wait_for_acknowledgment()
        - clear_notifications()
    """

    @abstractmethod
    def display_warning(
        self, title: str, message: str, action_hint: Optional[str] = None
    ):
        """Display a warning notification.

        Args:
            title: Warning title
            message: Warning message
            action_hint: Optional hint about what action to take
        """
        pass

    @abstractmethod
    def display_error(
        self, title: str, message: str, action_hint: Optional[str] = None
    ):
        """Display an error notification.

        Args:
            title: Error title
            message: Error message
            action_hint: Optional hint about what action to take
        """
        pass

    @abstractmethod
    def display_info(
        self, title: str, message: str, action_hint: Optional[str] = None
    ):
        """Display an informational notification.

        Args:
            title: Info title
            message: Info message
            action_hint: Optional hint about what action to take
        """
        pass

    @abstractmethod
    def wait_for_acknowledgment(self):
        """Wait for user to acknowledge the notification.

        For terminal: Wait for Enter key
        For web: Wait for button click
        For GUI: Wait for dialog close
        """
        pass
