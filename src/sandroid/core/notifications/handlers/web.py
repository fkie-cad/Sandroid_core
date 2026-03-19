"""Web notification handler for future web interface.

This module will handle notifications for the web-based interface using WebSockets.

Status: STUB - To be implemented when web interface is developed

Future Implementation:
    - WebSocket connection management
    - JSON message serialization
    - Browser notification API integration
    - Real-time notification push to connected clients
"""

from .base import NotificationHandler


class WebNotificationHandler(NotificationHandler):
    """WebSocket-based notification handler for web interfaces.

    Sends notifications to connected web clients via WebSocket messages
    using JSON serialization.

    This handler is a placeholder for future implementation when a web
    interface is developed for Sandroid.

    Planned features:
        - WebSocket connection management
        - JSON message serialization with notification types and levels
        - Notification queue for multiple connected clients
        - Session management and client tracking
        - Browser Notification API integration
    """

    def __init__(self, websocket_manager=None):
        """Initialize the web notification handler.

        Args:
            websocket_manager: WebSocket connection manager for broadcasting
                messages to connected clients.
        """
        self.websocket_manager = websocket_manager

    def display_warning(self, title: str, message: str, action_hint: str | None = None):
        """Send a warning notification to connected web clients.

        Should serialize the warning as a JSON payload and broadcast it
        to all connected WebSocket clients.

        Args:
            title: Warning title.
            message: Warning message body.
            action_hint: Optional hint about what action to take.
        """
        raise NotImplementedError(
            "WebNotificationHandler.display_warning() requires a WebSocket manager. "
            "Implement when web interface is developed."
        )

    def display_error(self, title: str, message: str, action_hint: str | None = None):
        """Send an error notification to connected web clients.

        Should serialize the error as a JSON payload and broadcast it
        to all connected WebSocket clients.

        Args:
            title: Error title.
            message: Error message body.
            action_hint: Optional hint about what action to take.
        """
        raise NotImplementedError(
            "WebNotificationHandler.display_error() requires a WebSocket manager. "
            "Implement when web interface is developed."
        )

    def display_info(self, title: str, message: str, action_hint: str | None = None):
        """Send an informational notification to connected web clients.

        Should serialize the info as a JSON payload and broadcast it
        to all connected WebSocket clients.

        Args:
            title: Info title.
            message: Info message body.
            action_hint: Optional hint about what action to take.
        """
        raise NotImplementedError(
            "WebNotificationHandler.display_info() requires a WebSocket manager. "
            "Implement when web interface is developed."
        )

    def wait_for_acknowledgment(self):
        """Wait for a connected web client to acknowledge the notification.

        Should create an asyncio Future and wait for any client to send
        an acknowledgment message via WebSocket. The notification ID should
        be used to correlate acknowledgments with pending notifications.
        """
        raise NotImplementedError(
            "WebNotificationHandler.wait_for_acknowledgment() requires a WebSocket "
            "manager. Implement when web interface is developed."
        )
