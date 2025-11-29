"""Event system for Sandroid.

This module provides a lightweight, thread-safe pub/sub event system for decoupling
components and enabling multi-UI support (CLI, Web, TUI).

The event system allows background tasks, analysis modules, and other components
to emit events that can be consumed by different UI handlers without tight coupling.

Usage:
    from sandroid.core.events import EventBus, Event, EventType

    # Subscribe to events
    def on_task_output(event: Event):
        print(f"Task output: {event.data['message']}")

    EventBus.get().subscribe(EventType.TASK_OUTPUT, on_task_output)

    # Publish events
    EventBus.get().publish(Event(
        type=EventType.TASK_OUTPUT,
        data={"task_name": "dexray-intercept", "message": "Hook triggered"},
        source="malwaremonitor"
    ))

Event Types:
    - TASK_OUTPUT: Output from a background task
    - TASK_STARTED: A background task has started
    - TASK_STOPPED: A background task has stopped
    - TASK_ERROR: An error occurred in a background task
    - NOTIFICATION: User-facing notification
    - STATE_CHANGED: Application state has changed
    - HOOK_TRIGGERED: A Frida hook was triggered
    - MENU_REFRESH: Request to refresh the menu display

Architecture:
    - EventBus: Singleton for managing subscriptions and publishing events
    - Event: Dataclass representing an event with type, data, timestamp, and source
    - EventType: Enum of supported event types
    - EventHandler: Type alias for event handler functions
"""

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of events that can be published through the EventBus."""

    # Background task lifecycle events
    TASK_OUTPUT = auto()  # Output/message from a background task
    TASK_STARTED = auto()  # A background task has started
    TASK_STOPPED = auto()  # A background task has stopped
    TASK_ERROR = auto()  # An error occurred in a background task

    # UI events
    NOTIFICATION = auto()  # User-facing notification message
    STATE_CHANGED = auto()  # Application state has changed
    MENU_REFRESH = auto()  # Request to refresh the menu display

    # Analysis events
    HOOK_TRIGGERED = auto()  # A Frida hook was triggered
    FILE_CHANGED = auto()  # A file change was detected
    NETWORK_EVENT = auto()  # Network activity was detected

    # System events
    APP_STARTING = auto()  # Application is starting up
    APP_SHUTTING_DOWN = auto()  # Application is shutting down


@dataclass
class Event:
    """Represents an event in the Sandroid event system.

    Attributes:
        type: The type of event (from EventType enum)
        data: Optional dictionary containing event-specific data
        timestamp: When the event occurred (auto-generated if not provided)
        source: Optional identifier of the event source (e.g., "malwaremonitor", "fritap")
    """

    type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    source: str | None = None


# Type alias for event handler functions
EventHandler = Callable[[Event], None]


class EventBus:
    """Thread-safe singleton event bus for pub/sub communication.

    The EventBus provides a central hub for publishing and subscribing to events.
    It is implemented as a singleton to ensure all components share the same bus.

    Thread Safety:
        All operations are thread-safe, allowing events to be published from
        background threads and consumed by the main thread or vice versa.

    Example:
        # Get the singleton instance
        bus = EventBus.get()

        # Subscribe to events
        bus.subscribe(EventType.TASK_OUTPUT, my_handler)

        # Publish an event
        bus.publish(Event(
            type=EventType.TASK_OUTPUT,
            data={"message": "Hello from background task"}
        ))

        # Unsubscribe when done
        bus.unsubscribe(EventType.TASK_OUTPUT, my_handler)
    """

    _instance: Optional["EventBus"] = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self):
        """Initialize the EventBus. Should only be called via get()."""
        self._handlers: dict[EventType, list[EventHandler]] = {}
        self._handlers_lock = threading.Lock()
        self._event_history: list[Event] = []
        self._history_max_size = 100

    @classmethod
    def get(cls) -> "EventBus":
        """Get the singleton EventBus instance.

        Returns:
            The singleton EventBus instance
        """
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance (useful for testing).

        This clears all handlers and event history.
        """
        with cls._lock:
            cls._instance = None

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Subscribe a handler to an event type.

        Args:
            event_type: The type of event to subscribe to
            handler: The function to call when the event is published

        Note:
            The same handler can be subscribed to multiple event types.
            Subscribing the same handler twice to the same event type will
            result in it being called twice.
        """
        with self._handlers_lock:
            if event_type not in self._handlers:
                self._handlers[event_type] = []
            self._handlers[event_type].append(handler)
            logger.debug(f"Handler subscribed to {event_type.name}")

    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> bool:
        """Unsubscribe a handler from an event type.

        Args:
            event_type: The type of event to unsubscribe from
            handler: The handler function to remove

        Returns:
            True if the handler was found and removed, False otherwise
        """
        with self._handlers_lock:
            if event_type in self._handlers and handler in self._handlers[event_type]:
                self._handlers[event_type].remove(handler)
                logger.debug(f"Handler unsubscribed from {event_type.name}")
                return True
            return False

    def publish(self, event: Event) -> None:
        """Publish an event to all subscribed handlers.

        Args:
            event: The event to publish

        Note:
            Handlers are called synchronously in the order they were subscribed.
            Exceptions in handlers are caught and logged, but do not prevent
            other handlers from being called.
        """
        # Store in history
        self._event_history.append(event)
        if len(self._event_history) > self._history_max_size:
            self._event_history = self._event_history[-self._history_max_size :]

        # Get handlers snapshot under lock
        with self._handlers_lock:
            handlers = list(self._handlers.get(event.type, []))

        # Call handlers outside lock to prevent deadlocks
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Error in event handler for {event.type.name}: {e}")

    def get_history(
        self, event_type: EventType | None = None, count: int = 10
    ) -> list[Event]:
        """Get recent events from history.

        Args:
            event_type: Optional filter by event type. If None, returns all events.
            count: Maximum number of events to return

        Returns:
            List of recent events, newest first
        """
        if event_type is None:
            return list(reversed(self._event_history[-count:]))
        filtered = [e for e in self._event_history if e.type == event_type]
        return list(reversed(filtered[-count:]))

    def clear_history(self) -> None:
        """Clear the event history."""
        self._event_history = []

    def has_subscribers(self, event_type: EventType) -> bool:
        """Check if an event type has any subscribers.

        Args:
            event_type: The event type to check

        Returns:
            True if there are subscribers, False otherwise
        """
        with self._handlers_lock:
            return bool(self._handlers.get(event_type))


# Convenience functions for common operations
def publish(
    event_type: EventType, data: dict[str, Any] = None, source: str = None
) -> None:
    """Convenience function to publish an event.

    Args:
        event_type: The type of event to publish
        data: Optional event data dictionary
        source: Optional source identifier
    """
    EventBus.get().publish(Event(type=event_type, data=data or {}, source=source))


def subscribe(event_type: EventType, handler: EventHandler) -> None:
    """Convenience function to subscribe to an event type.

    Args:
        event_type: The type of event to subscribe to
        handler: The handler function
    """
    EventBus.get().subscribe(event_type, handler)


def unsubscribe(event_type: EventType, handler: EventHandler) -> bool:
    """Convenience function to unsubscribe from an event type.

    Args:
        event_type: The type of event to unsubscribe from
        handler: The handler function

    Returns:
        True if successfully unsubscribed, False otherwise
    """
    return EventBus.get().unsubscribe(event_type, handler)


__version__ = "1.0.0"
__all__ = [
    "Event",
    "EventBus",
    "EventHandler",
    "EventType",
    "publish",
    "subscribe",
    "unsubscribe",
]
