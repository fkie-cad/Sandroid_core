"""Objection Service for Sandroid.

This service manages Objection security testing sessions.
Extracted from Toolbox class to follow Single Responsibility Principle.

Usage:
    from sandroid.services import get_objection_service
    from sandroid.services.objection_service import ObjectionService

    # Using service locator
    objection_service = get_objection_service()

    # Store a minimized session
    objection_service.set_session(terminal_screen)

    # Check and retrieve
    if objection_service.has_session():
        session = objection_service.get_session()
"""

import logging
import threading
from typing import Any

from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)


class ObjectionService:
    """Service for managing Objection security testing sessions.

    This service handles:
    - Storing minimized Objection terminal sessions
    - Session lifecycle management
    - Session state queries

    Thread Safety:
        All operations are thread-safe through internal locking.

    Example:
        service = ObjectionService()

        # Store a minimized session
        service.set_session(my_objection_screen)

        # Check if session exists
        if service.has_session():
            screen = service.get_session()
            # Resume the session...

        # Clear when done
        service.clear()
    """

    def __init__(self, event_bus: EventBusProtocol | None = None):
        """Initialize the ObjectionService.

        Args:
            event_bus: Optional EventBus for publishing events.
        """
        self._lock = threading.Lock()
        self._event_bus = event_bus
        self._logger = logger

        # Session storage
        self._session: Any = None

    def set_session(self, session: Any) -> None:
        """Store a reference to a minimized Objection terminal screen.

        Args:
            session: The ObjectionTerminalScreen instance to store.
        """
        with self._lock:
            self._session = session
            self._logger.debug("Objection session stored (minimized)")

        self._publish_session_event("session_stored")

    def get_session(self) -> Any | None:
        """Get the stored Objection session.

        Returns:
            The ObjectionTerminalScreen instance, or None if no session is stored.
        """
        with self._lock:
            return self._session

    def clear(self) -> None:
        """Clear the stored Objection session reference."""
        with self._lock:
            self._session = None
            self._logger.debug("Objection session cleared")

        self._publish_session_event("session_cleared")

    def has_session(self) -> bool:
        """Check if there's a stored Objection session.

        Returns:
            True if an Objection session is stored.
        """
        with self._lock:
            return self._session is not None

    def reset(self) -> None:
        """Reset the service state (useful for testing)."""
        with self._lock:
            self._session = None

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _publish_session_event(self, action: str) -> None:
        """Publish Objection session event."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={"action": action, "has_session": self.has_session()},
                source="objection_service",
            )
        )


# Exports
__all__ = [
    "ObjectionService",
]
