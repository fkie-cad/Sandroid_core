"""GUI notification handler for future desktop interface.

This module will handle notifications for a desktop GUI interface.

Status: STUB - To be implemented when GUI interface is developed

Future Implementation:
    - Native desktop notifications (Windows, macOS, Linux)
    - Qt/GTK/tkinter dialog boxes
    - System tray notifications
    - Modal dialog management
"""

from .base import NotificationHandler


class GUINotificationHandler(NotificationHandler):
    """Desktop GUI notification handler.

    Displays notifications via native desktop UI elements such as Qt/GTK
    dialog boxes, system tray popups, and modal windows.

    This handler is a placeholder for future implementation when a desktop
    GUI interface is developed for Sandroid.

    Planned features:
        - Qt/GTK/tkinter dialog boxes for modal notifications
        - System tray integration for non-blocking notifications
        - Native platform notification APIs (macOS, Windows, Linux)
        - Notification sound support
    """

    def __init__(self, main_window=None):
        """Initialize the GUI notification handler.

        Args:
            main_window: Reference to the main application window (Qt/GTK widget).
        """
        self.main_window = main_window

    def display_warning(self, title: str, message: str, action_hint: str | None = None):
        """Display a warning notification via a GUI dialog.

        Should show a warning-level dialog box with an appropriate icon
        and optional action hint.

        Args:
            title: Warning title for the dialog window.
            message: Warning message body.
            action_hint: Optional hint about what action to take.
        """
        raise NotImplementedError(
            "GUINotificationHandler.display_warning() requires a GUI toolkit "
            "(Qt/GTK/tkinter). Implement when desktop GUI interface is developed."
        )

    def display_error(self, title: str, message: str, action_hint: str | None = None):
        """Display an error notification via a GUI dialog.

        Should show a critical/error-level dialog box with an appropriate
        icon and optional action hint.

        Args:
            title: Error title for the dialog window.
            message: Error message body.
            action_hint: Optional hint about what action to take.
        """
        raise NotImplementedError(
            "GUINotificationHandler.display_error() requires a GUI toolkit "
            "(Qt/GTK/tkinter). Implement when desktop GUI interface is developed."
        )

    def display_info(self, title: str, message: str, action_hint: str | None = None):
        """Display an informational notification via a GUI dialog.

        Should show an info-level dialog box with an appropriate icon
        and optional action hint.

        Args:
            title: Info title for the dialog window.
            message: Info message body.
            action_hint: Optional hint about what action to take.
        """
        raise NotImplementedError(
            "GUINotificationHandler.display_info() requires a GUI toolkit "
            "(Qt/GTK/tkinter). Implement when desktop GUI interface is developed."
        )

    def wait_for_acknowledgment(self):
        """Wait for user to acknowledge the notification by closing the dialog.

        In a GUI context, acknowledgment is typically handled by the dialog's
        exec() or run() method blocking until the user clicks OK or closes
        the window.
        """
        raise NotImplementedError(
            "GUINotificationHandler.wait_for_acknowledgment() requires a GUI toolkit "
            "(Qt/GTK/tkinter). Implement when desktop GUI interface is developed."
        )
