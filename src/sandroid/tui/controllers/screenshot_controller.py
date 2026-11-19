"""Screenshot Controller for TUI.

This controller manages screenshot operations, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Show screenshot modal for filename input
- Take screenshot via EmulatorService
- Log screenshot success/failure

Usage:
    from sandroid.tui.controllers import ScreenshotController

    controller = ScreenshotController(
        log_info=activity_log.log_info,
        log_error=activity_log.log_error,
        log_success=activity_log.log_success,
        push_modal=app.push_screen,
    )

    controller.show_screenshot_modal()
"""

import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class ScreenshotController:
    """Controller for screenshot operations.

    This controller handles all screenshot-related operations, decoupled from
    the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of screenshot logic from UI rendering
    - Reusable screenshot management across different UI modes

    Example:
        controller = ScreenshotController(
            log_info=print,
            log_error=lambda msg: print(f"ERR: {msg}"),
            log_success=lambda msg: print(f"OK: {msg}"),
            push_modal=lambda modal, cb: cb(None),
        )

        controller.show_screenshot_modal()
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        log_success: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
    ):
        """Initialize ScreenshotController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI.
            log_error: Callback for error-level logging to UI.
            log_success: Callback for success-level logging to UI.
            push_modal: Callback to push a modal screen with result callback.
        """
        self._log_info = log_info or self._default_log
        self._log_error = log_error or self._default_log
        self._log_success = log_success or self._default_log
        self._push_modal = push_modal

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def show_screenshot_modal(self) -> None:
        """Show screenshot modal for filename input.

        Opens the ScreenshotModal and handles the result callback by
        taking a screenshot via EmulatorService. While Tracking is on, ``s``
        instead records a ``shot/manual`` timeline line at once (the capture
        runs on a Tracking worker thread; t = the key press).
        """
        import time

        try:
            from sandroid.services import tracking_service
        except Exception:  # pragma: no cover - tracking always importable
            tracking_service = None
        if tracking_service is not None and tracking_service.is_active():
            pressed = time.time()
            if tracking_service.get_tracking().manual_shot(t=pressed):
                self._log_success("Screenshot recorded (Tracking)")
                return

        from sandroid.tui.modals import ScreenshotModal, ScreenshotResult

        def on_screenshot_result(result: ScreenshotResult | None) -> None:
            # Esc / Cancel dismisses the modal with None (SandroidModal's
            # action_cancel) -- a cancel, not an error.
            if result is None or result.cancelled:
                self._log_info("Screenshot cancelled")
                return

            try:
                from sandroid.services import get_emulator_service

                path = get_emulator_service().take_screenshot(result.filename)
                if path:
                    self._log_success(f"Screenshot saved to {path}")
                else:
                    self._log_error(
                        "Screenshot failed - no image was captured "
                        "(is a device connected?)"
                    )
            except Exception as e:
                self._log_error(f"Screenshot error: {type(e).__name__}: {e}")

        if self._push_modal:
            self._push_modal(ScreenshotModal(), on_screenshot_result)


__all__ = [
    "ScreenshotController",
]
