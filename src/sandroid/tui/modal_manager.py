"""Modal manager connecting UIRequestBus to Textual modals.

This module provides the bridge between the UIRequestBus abstraction
and Textual's modal screens. When TUI mode is active, UI requests
are routed here and displayed as native Textual modals.
"""

import logging
from typing import TYPE_CHECKING, Optional

from sandroid.core.ui_request_bus import (
    UIRequest,
    UIRequestBus,
    UIRequestType,
    set_result,
)

from .modals import (
    ConfirmModal,
    FridaToggleConfigModal,
    InputModal,
    MessageModal,
    SelectionModal,
    ToggleConfigModal,
)

if TYPE_CHECKING:
    from textual.app import App
    from textual.screen import ModalScreen

logger = logging.getLogger(__name__)


class ModalManager:
    """Manages modal dialogs for the TUI.

    This class:
    - Registers as a handler on the UIRequestBus
    - Receives UI requests from business logic
    - Creates and shows appropriate Textual modals
    - Returns results back through the bus

    Usage:
        # In your TUI app's on_mount or __init__:
        self.modal_manager = ModalManager(self)

        # The manager automatically registers with UIRequestBus
        # and handles incoming UI requests
    """

    _instance: "ModalManager | None" = None

    def __init__(self, app: "App"):
        """Initialize the modal manager.

        Args:
            app: The Textual App instance
        """
        self.app = app
        self._pending_request: UIRequest | None = None
        ModalManager._instance = self
        self._register_handler()

    @classmethod
    def get_app(cls) -> "App | None":
        """Get the Textual App instance.

        Returns:
            The app instance, or None if not initialized
        """
        return cls._instance.app if cls._instance else None

    def _register_handler(self) -> None:
        """Register as the TUI handler on the UIRequestBus."""
        bus = UIRequestBus.get()
        bus.set_handler("tui", self._handle_request)
        # Don't auto-activate - let the app control this
        logger.debug("ModalManager registered as TUI handler")

    def activate(self) -> None:
        """Activate this handler on the UIRequestBus."""
        bus = UIRequestBus.get()
        bus.set_active("tui")
        logger.debug("ModalManager activated")

    def deactivate(self) -> None:
        """Deactivate this handler."""
        bus = UIRequestBus.get()
        if bus.get_active() == "tui":
            bus.set_active(None)
        logger.debug("ModalManager deactivated")

    def _handle_request(self, request: UIRequest) -> None:
        """Handle a UI request by showing appropriate modal.

        This method is called from the UIRequestBus. It may be called
        from a background thread or from the main Textual thread,
        so we check which thread we're on before deciding how to
        show the modal.

        Args:
            request: The UI request to handle
        """
        import threading

        self._pending_request = request

        # Check if we're on the main thread
        main_thread_id = threading.main_thread().ident
        current_thread_id = threading.current_thread().ident

        try:
            if current_thread_id == main_thread_id:
                # Already on main thread, call directly or use call_later
                try:
                    self._show_modal(request)
                except Exception:
                    # If direct call fails, schedule for later
                    self.app.call_later(self._show_modal, request)
            else:
                # Background thread, use call_from_thread
                self.app.call_from_thread(self._show_modal, request)
        except Exception as e:
            logger.error(f"Error showing modal: {e}")
            # Ensure we don't leave the caller hanging
            set_result(request, None)

    def _show_modal(self, request: UIRequest) -> None:
        """Show the appropriate modal or screen for the request.

        This runs on the main Textual thread.

        Args:
            request: The UI request to handle
        """
        # Handle PUSH_SCREEN differently - screens don't dismiss with result
        if request.request_type == UIRequestType.PUSH_SCREEN:
            screen_class = request.metadata.get("screen_class")
            kwargs = request.metadata.get("kwargs", {})
            if screen_class:
                try:
                    screen = screen_class(**kwargs)
                    self.app.push_screen(screen)
                    set_result(request, True)
                except Exception as e:
                    logger.error(f"Error pushing screen: {e}")
                    set_result(request, False)
            else:
                logger.warning("PUSH_SCREEN request missing screen_class in metadata")
                set_result(request, False)
            return

        modal = self._create_modal(request)
        if modal:
            self.app.push_screen(
                modal, callback=lambda result: self._on_modal_dismissed(request, result)
            )
        else:
            logger.warning(f"No modal created for request type: {request.request_type}")
            set_result(request, None)

    def _create_modal(self, request: UIRequest) -> Optional["ModalScreen"]:
        """Create the appropriate modal for the request type.

        Args:
            request: The UI request

        Returns:
            A ModalScreen instance, or None if type is unknown
        """
        rtype = request.request_type

        if rtype == UIRequestType.INPUT:
            return InputModal(
                title=request.title,
                message=request.message,
                default=str(request.default or ""),
            )

        if rtype in (UIRequestType.SELECTION, UIRequestType.MULTI_SELECT):
            return SelectionModal(
                title=request.title,
                options=request.options,
                message=request.message,
            )

        if rtype == UIRequestType.TOGGLE_CONFIG:
            options_dict = request.options[0] if request.options else {}
            is_frida = request.metadata.get("theme") == "frida"
            modal_cls = FridaToggleConfigModal if is_frida else ToggleConfigModal
            return modal_cls(
                title=request.title,
                options=options_dict,
                message=request.message,
            )

        if rtype == UIRequestType.CONFIRM:
            return ConfirmModal(
                title=request.title,
                message=request.message,
            )

        if rtype == UIRequestType.MESSAGE:
            return MessageModal(
                title=request.title,
                message=request.message,
                level=request.metadata.get("level", "info"),
            )

        if rtype == UIRequestType.CUSTOM_MODAL:
            modal_class = request.metadata.get("modal_class")
            kwargs = request.metadata.get("kwargs", {})
            if modal_class:
                return modal_class(**kwargs)
            logger.warning("CUSTOM_MODAL request missing modal_class in metadata")
            return None

        logger.warning(f"Unknown request type: {rtype}")
        return None

    def _on_modal_dismissed(self, request: UIRequest, result) -> None:
        """Handle modal dismissal.

        Args:
            request: The original UI request
            result: The result from the modal
        """
        self._pending_request = None
        set_result(request, result)

    def has_pending_modal(self) -> bool:
        """Check if there's a pending modal request."""
        return self._pending_request is not None
