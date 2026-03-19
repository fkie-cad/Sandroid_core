"""Objection Resume Controller for TUI.

This controller manages objection session resumption, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Resume minimized objection terminal sessions
- Push stored session screen back onto the screen stack
- Handle missing/invalid session states

Usage:
    from sandroid.tui.controllers import ObjectionResumeController

    controller = ObjectionResumeController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        log_error=activity_log.log_error,
        push_modal=app.push_screen,
    )

    controller.resume_session()
"""

import logging
from collections.abc import Callable

logger = logging.getLogger(__name__)


class ObjectionResumeController:
    """Controller for objection session resumption.

    This controller handles resuming minimized objection terminal sessions,
    decoupled from the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of objection logic from UI rendering
    - Reusable session management across different UI modes

    Note:
        The push_modal callback is used to push the session screen
        (equivalent to app.push_screen). When called with a single
        argument (the session), it pushes the screen without a callback.

    Example:
        controller = ObjectionResumeController(
            log_info=print,
            log_warning=lambda msg: print(f"WARN: {msg}"),
            log_error=lambda msg: print(f"ERR: {msg}"),
            push_modal=lambda screen: None,
        )

        controller.resume_session()
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_warning: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        push_modal: Callable[..., None] | None = None,
    ):
        """Initialize ObjectionResumeController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI.
            log_warning: Callback for warning-level logging to UI.
            log_error: Callback for error-level logging to UI.
            push_modal: Callback to push a screen (accepts single screen arg).
        """
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_error = log_error or self._default_log
        self._push_modal = push_modal

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def resume_session(self) -> None:
        """Resume a minimized objection terminal session.

        Checks for an active objection session via ObjectionService.
        If found, pushes the stored session screen and calls resume().
        """
        from sandroid.services import get_objection_service

        objection_service = get_objection_service()

        if not objection_service.has_session():
            self._log_warning(
                "No objection session to resume. Start one with 'b' first."
            )
            return

        session = objection_service.get_session()
        if session:
            if self._push_modal:
                self._push_modal(session)
            session.resume()
            self._log_info("Resumed objection session")
        else:
            self._log_error("Failed to resume objection session")


__all__ = [
    "ObjectionResumeController",
]
