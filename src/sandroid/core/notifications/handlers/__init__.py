"""Notification handlers for different frontends.

This package contains handlers for displaying notifications across
different user interfaces.

Available Handlers:
    - NotificationHandler: Abstract base class (implemented in base.py)
    - WebNotificationHandler: WebSocket-based notifications (stub)
    - GUINotificationHandler: Desktop GUI notifications (stub)
"""

from .base import NotificationHandler
from .gui import GUINotificationHandler
from .web import WebNotificationHandler

__all__ = [
    "NotificationHandler",
    "GUINotificationHandler",
    "WebNotificationHandler",
]
