"""UI Request Bus for decoupling business logic from UI rendering.

This module provides an abstraction layer between business logic and UI components.
Business logic publishes UI requests (dialogs, inputs, selections) and the active
UI handler (TUI or Rich) renders them appropriately.

Architecture:
    Business Logic --> UIRequestBus --> Handler (TUI ModalManager or Rich)
                                    <-- Result returned via Future
"""

import asyncio
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)


class UIRequestType(Enum):
    """Types of UI requests that can be made."""

    INPUT = auto()  # Text input dialog
    SELECTION = auto()  # Select from list (single)
    MULTI_SELECT = auto()  # Select multiple items
    TOGGLE_CONFIG = auto()  # Toggle options config (switches)
    CONFIRM = auto()  # Yes/No confirmation
    MESSAGE = auto()  # Info/Warning/Error message
    CUSTOM_MODAL = auto()  # Custom modal class with kwargs
    PUSH_SCREEN = auto()  # Push a full screen (not modal)


@dataclass
class UIRequest:
    """A request for UI interaction.

    Attributes:
        request_type: The type of UI interaction needed
        title: Dialog title
        message: Optional description or prompt
        options: List of options for selection dialogs
        default: Default value for input dialogs
        metadata: Additional data for specialized handling
        future: asyncio.Future for async result handling
        result_event: threading.Event for synchronous waiting
        result: The result value set by the handler
    """

    request_type: UIRequestType
    title: str
    message: str = ""
    options: list[Any] = field(default_factory=list)
    default: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)
    future: asyncio.Future | None = None
    result_event: threading.Event | None = field(default=None)
    result: Any = field(default=None)


class UIRequestBus:
    """Singleton bus for routing UI requests to the appropriate handler.

    The bus supports both synchronous and asynchronous request patterns:
    - Synchronous: Used by background threads, blocks until handler sets result
    - Asynchronous: Used by async code, returns a Future

    Usage:
        # Register handlers
        bus = UIRequestBus.get()
        bus.set_handler("tui", tui_modal_manager.handle)
        bus.set_handler("rich", rich_handler.handle)

        # Set active handler
        bus.set_active("tui")

        # Make requests (from business logic)
        result = request_selection("Select App", apps)
    """

    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self._handlers: dict[str, Callable[[UIRequest], Any]] = {}
        self._active_handler: str | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._shutting_down = False
        self._pending_requests: list[UIRequest] = []

    @classmethod
    def get(cls) -> "UIRequestBus":
        """Get the singleton instance of UIRequestBus."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance (for testing)."""
        with cls._lock:
            cls._instance = None

    def set_handler(self, name: str, handler: Callable[[UIRequest], Any]) -> None:
        """Register a UI handler.

        Args:
            name: Handler identifier (e.g., "tui", "rich")
            handler: Callable that processes UIRequest and sets result
        """
        self._handlers[name] = handler
        logger.debug(f"Registered UI handler: {name}")

    def remove_handler(self, name: str) -> None:
        """Remove a registered handler.

        Args:
            name: Handler identifier to remove
        """
        if name in self._handlers:
            del self._handlers[name]
            if self._active_handler == name:
                self._active_handler = None
            logger.debug(f"Removed UI handler: {name}")

    def set_active(self, name: str) -> None:
        """Set the active handler for processing requests.

        Args:
            name: Handler identifier to activate
        """
        if name not in self._handlers:
            logger.warning(
                f"Handler '{name}' not registered, will be set when registered"
            )
        self._active_handler = name
        logger.debug(f"Active UI handler set to: {name}")

    def get_active(self) -> str | None:
        """Get the name of the active handler."""
        return self._active_handler

    def shutdown(self) -> None:
        """Shutdown the bus and cancel all pending requests.

        This should be called when the UI is exiting to unblock any
        threads waiting on UI requests.
        """
        logger.debug("UIRequestBus shutting down, releasing pending requests")
        self._shutting_down = True

        for request in list(self._pending_requests):
            if request.result_event:
                request.result = None
                request.result_event.set()

        self._pending_requests.clear()

    def is_shutting_down(self) -> bool:
        """Check if the bus is shutting down."""
        return self._shutting_down

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Set the event loop for async operations.

        Args:
            loop: The asyncio event loop to use
        """
        self._loop = loop

    def request(self, request: UIRequest, timeout: float = 300.0) -> Any:
        """Send a UI request and wait for result (synchronous).

        This method is thread-safe and can be called from background threads.
        It blocks until the handler sets the result or timeout expires.

        Args:
            request: The UI request to process
            timeout: Maximum time to wait in seconds (default: 300s / 5 minutes)

        Returns:
            The result from the UI handler, or None if timeout/shutdown

        Raises:
            RuntimeError: If no active handler is available
        """
        # Check if shutting down
        if self._shutting_down:
            logger.debug("UIRequestBus is shutting down, returning None")
            return None

        if not self._active_handler or self._active_handler not in self._handlers:
            raise RuntimeError(
                f"No active UI handler available. "
                f"Active: {self._active_handler}, Registered: {list(self._handlers.keys())}"
            )

        handler = self._handlers[self._active_handler]

        # Create event for synchronous waiting
        request.result_event = threading.Event()

        # Track pending request for cleanup
        self._pending_requests.append(request)

        try:
            # Call handler (may be async, may use call_from_thread)
            handler(request)

            # Wait for result with timeout
            if not request.result_event.wait(timeout=timeout):
                logger.warning(
                    f"UI request timed out after {timeout}s: {request.title}"
                )
                return None

            # Check if shutdown was triggered during wait
            if self._shutting_down:
                logger.debug("UIRequestBus shutdown during request, returning None")
                return None

            return request.result
        finally:
            # Remove from pending requests
            if request in self._pending_requests:
                self._pending_requests.remove(request)

    async def request_async(self, request: UIRequest) -> Any:
        """Send a UI request asynchronously.

        Args:
            request: The UI request to process

        Returns:
            The result from the UI handler

        Raises:
            RuntimeError: If no active handler is available
        """
        if not self._active_handler or self._active_handler not in self._handlers:
            raise RuntimeError(
                f"No active UI handler available. "
                f"Active: {self._active_handler}, Registered: {list(self._handlers.keys())}"
            )

        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                self._loop = asyncio.get_event_loop()

        request.future = self._loop.create_future()

        handler = self._handlers[self._active_handler]
        handler(request)

        return await request.future

    def has_active_handler(self) -> bool:
        """Check if an active handler is available."""
        return (
            self._active_handler is not None and self._active_handler in self._handlers
        )


def set_result(request: UIRequest, result: Any) -> None:
    """Helper to set the result on a UIRequest.

    This should be called by handlers when the UI interaction is complete.

    Args:
        request: The request to set result on
        result: The result value
    """
    request.result = result

    # Signal synchronous waiters
    if request.result_event is not None:
        request.result_event.set()

    # Resolve async futures
    if request.future is not None and not request.future.done():
        try:
            request.future.set_result(result)
        except Exception as e:
            logger.error(f"Error setting future result: {e}")


# Convenience functions for business logic
def request_input(title: str, message: str = "", default: str = "") -> str | None:
    """Request text input from user.

    Args:
        title: Dialog title
        message: Optional prompt message
        default: Default value

    Returns:
        User input string, or None if cancelled
    """
    bus = UIRequestBus.get()
    if not bus.has_active_handler():
        logger.warning("No UI handler active, returning None")
        return None

    return bus.request(
        UIRequest(
            request_type=UIRequestType.INPUT,
            title=title,
            message=message,
            default=default,
        )
    )


def request_selection(title: str, options: list[Any], message: str = "") -> Any | None:
    """Request single selection from a list.

    Args:
        title: Dialog title
        options: List of options to choose from
        message: Optional prompt message

    Returns:
        Selected option, or None if cancelled
    """
    bus = UIRequestBus.get()
    if not bus.has_active_handler():
        logger.warning("No UI handler active, returning None")
        return None

    return bus.request(
        UIRequest(
            request_type=UIRequestType.SELECTION,
            title=title,
            message=message,
            options=options,
        )
    )


def request_multi_select(
    title: str, options: list[Any], message: str = "", selected: list[Any] | None = None
) -> list[Any] | None:
    """Request multiple selections from a list.

    Args:
        title: Dialog title
        options: List of options to choose from
        message: Optional prompt message
        selected: Pre-selected options

    Returns:
        List of selected options, or None if cancelled
    """
    bus = UIRequestBus.get()
    if not bus.has_active_handler():
        logger.warning("No UI handler active, returning None")
        return None

    return bus.request(
        UIRequest(
            request_type=UIRequestType.MULTI_SELECT,
            title=title,
            message=message,
            options=options,
            default=selected or [],
        )
    )


def request_toggle_config(
    title: str, options: dict[str, bool], message: str = "", theme: str = ""
) -> dict[str, bool] | None:
    """Request toggle configuration (multiple on/off switches).

    Args:
        title: Dialog title
        options: Dict of {option_name: current_value (bool)}
        message: Optional prompt message
        theme: Optional theme override (e.g., "frida" for green borders)

    Returns:
        Dict with updated values, or None if cancelled
    """
    bus = UIRequestBus.get()
    if not bus.has_active_handler():
        logger.warning("No UI handler active, returning None")
        return None

    return bus.request(
        UIRequest(
            request_type=UIRequestType.TOGGLE_CONFIG,
            title=title,
            message=message,
            options=[options],  # Wrap in list for dataclass default
            metadata={"theme": theme} if theme else {},
        )
    )


def request_confirm(title: str, message: str = "") -> bool:
    """Request yes/no confirmation.

    Args:
        title: Dialog title
        message: Optional prompt message

    Returns:
        True if confirmed, False otherwise
    """
    bus = UIRequestBus.get()
    if not bus.has_active_handler():
        logger.warning("No UI handler active, returning False")
        return False

    return bus.request(
        UIRequest(
            request_type=UIRequestType.CONFIRM,
            title=title,
            message=message,
        )
    )


def show_message(title: str, message: str, level: str = "info") -> None:
    """Show an info/warning/error message.

    Args:
        title: Dialog title
        message: The message to display
        level: Message level ("info", "warning", "error")
    """
    bus = UIRequestBus.get()
    if not bus.has_active_handler():
        logger.warning(
            f"No UI handler active, logging message: [{level}] {title}: {message}"
        )
        return

    bus.request(
        UIRequest(
            request_type=UIRequestType.MESSAGE,
            title=title,
            message=message,
            metadata={"level": level},
        )
    )


def show_warning(title: str, message: str) -> None:
    """Show a warning message.

    Args:
        title: Dialog title
        message: The warning message
    """
    show_message(title, message, level="warning")


def show_error(title: str, message: str) -> None:
    """Show an error message.

    Args:
        title: Dialog title
        message: The error message
    """
    show_message(title, message, level="error")


def show_info(title: str, message: str) -> None:
    """Show an info message.

    Args:
        title: Dialog title
        message: The info message
    """
    show_message(title, message, level="info")


def request_modal(modal_class: type, **kwargs) -> Any:
    """Request a custom modal to be shown.

    This allows showing custom modal classes (like ObjectionModal, TrigDroidModal)
    through the UI request bus. The modal class will be instantiated with the
    provided kwargs.

    Args:
        modal_class: The modal class to instantiate (must be a ModalScreen subclass)
        **kwargs: Keyword arguments to pass to the modal constructor

    Returns:
        The result from the modal, or None if cancelled or no handler active
    """
    bus = UIRequestBus.get()
    if not bus.has_active_handler():
        logger.warning("No UI handler active, returning None")
        return None

    return bus.request(
        UIRequest(
            request_type=UIRequestType.CUSTOM_MODAL,
            title=modal_class.__name__,  # Use class name as title for logging
            metadata={"modal_class": modal_class, "kwargs": kwargs},
        )
    )


def push_screen(screen_class: type, **kwargs) -> bool:
    """Request a full screen to be pushed onto the app.

    This allows pushing full screens (like ObjectionTerminalScreen) through
    the UI request bus. Unlike modals, screens don't block for a return value.

    Args:
        screen_class: The screen class to instantiate (must be a Screen subclass)
        **kwargs: Keyword arguments to pass to the screen constructor

    Returns:
        True if the screen was pushed successfully, False if no handler active
    """
    bus = UIRequestBus.get()
    if not bus.has_active_handler():
        logger.warning("No UI handler active, cannot push screen")
        return False

    return bus.request(
        UIRequest(
            request_type=UIRequestType.PUSH_SCREEN,
            title=screen_class.__name__,
            metadata={"screen_class": screen_class, "kwargs": kwargs},
        )
    )
