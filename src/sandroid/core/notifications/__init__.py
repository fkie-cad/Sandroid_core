"""Notification system for Sandroid.

This module provides a frontend-agnostic notification system that can be used
across multiple interfaces (CLI, Web, GUI).

Current Status:
    - Phase 1: Modal notifications implemented via Toolbox methods
    - Phase 2: Full abstraction layer (future implementation)

Usage (Current - Phase 1):
    from sandroid.core.toolbox import Toolbox

    # Display blocking warning
    Toolbox.show_blocking_warning(
        title="Frida Server Required",
        message="No frida server is running.",
        action_hint="Press [f] to install and start Frida server"
    )

    # Display blocking error
    Toolbox.show_blocking_error(
        title="Operation Failed",
        message="Failed to install APK: Permission denied"
    )

Future Usage (Phase 2 - When Web Interface is Implemented):
    from sandroid.core.notifications import notify

    # Non-blocking notification
    notify.warning("Frida server stopped")

    # Blocking modal
    notify.modal_warning(
        title="Spotlight App Required",
        message="Please set a spotlight application first"
    )

Architecture:
    - NotificationManager: Central singleton for managing notifications
    - NotificationHandler: Abstract base for frontend-specific handlers
    - TerminalHandler: CLI/terminal-based notifications (current)
    - WebHandler: WebSocket-based notifications (future)
    - GUIHandler: Desktop GUI notifications (future)

Future Enhancements:
    - Message queue for async notifications
    - Notification history and logging
    - User preferences for notification behavior
    - Multiple handler registration
    - Notification routing and filtering
"""

# TODO: Implement Phase 2 - Full notification abstraction layer
# TODO: Add NotificationManager singleton
# TODO: Add handler registration system
# TODO: Add notification types and message structures

__version__ = "1.0.0-phase1"
__all__ = []  # Will be populated in Phase 2

# Phase 1: Use Toolbox methods directly
# Phase 2: Export NotificationManager and notify API
