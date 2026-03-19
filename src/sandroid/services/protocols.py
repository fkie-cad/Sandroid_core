"""Shared protocols for Sandroid services.

This module contains protocol definitions shared across multiple service files
to avoid code duplication and ensure consistent interfaces.

Usage:
    from sandroid.services.protocols import EventBusProtocol
"""

from typing import Any, Protocol


class EventBusProtocol(Protocol):
    """Protocol for EventBus dependency injection."""

    def publish(self, event: Any) -> None:
        """Publish an event."""
        ...


__all__ = [
    "EventBusProtocol",
]
