"""Proxy Controller for TUI.

This controller manages proxy settings, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Show the proxy settings modal
- Handle the modal result (proxy settings applied / CA injected)
- Refresh status bar after proxy changes

Usage:
    from sandroid.tui.controllers import ProxyController

    controller = ProxyController(
        log_info=activity_log.log_info,
        log_success=activity_log.log_success,
        push_modal=app.push_screen,
        refresh_status_bar=lambda: main_screen.refresh_status_bar(),
    )

    controller.show_proxy_modal()
"""

import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class ProxyController:
    """Controller for proxy configuration operations.

    This controller handles all proxy-related operations, decoupled from
    the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of proxy logic from UI rendering
    - Reusable proxy management across different UI modes

    Example:
        controller = ProxyController(
            log_info=print,
            log_success=lambda msg: print(f"OK: {msg}"),
            push_modal=lambda modal, cb: cb(None),
            refresh_status_bar=lambda: None,
        )

        controller.show_proxy_modal()
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_success: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        refresh_status_bar: Callable[[], None] | None = None,
    ):
        """Initialize ProxyController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI.
            log_success: Callback for success-level logging to UI.
            push_modal: Callback to push a modal screen with result callback.
            refresh_status_bar: Callback to refresh the status bar widget.
        """
        self._log_info = log_info or self._default_log
        self._log_success = log_success or self._default_log
        self._push_modal = push_modal
        self._refresh_status_bar = refresh_status_bar

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def show_proxy_modal(self) -> None:
        """Show the proxy settings modal.

        Opens the ProxyModal and handles its result. The modal applies the
        Device Proxy and App Proxies together (``"applied"``) and keeps a
        separate CA-injection action (``"inject_ca"``).
        """
        from sandroid.tui.modals import ProxyModal, ProxyModalResult

        def on_proxy_result(result: ProxyModalResult) -> None:
            if result is None or result.cancelled:
                self._log_info("Proxy settings unchanged")
                return

            if result.action == "inject_ca":
                self._log_success("CA certificate injected into Zygote")
            elif result.proxy_config is not None:
                self._log_success(
                    f"Proxy settings applied — device at "
                    f"{result.proxy_config.address}"
                )
            else:
                self._log_success("Proxy settings applied")

            if self._refresh_status_bar:
                self._refresh_status_bar()

        if self._push_modal:
            self._push_modal(ProxyModal(), on_proxy_result)


__all__ = [
    "ProxyController",
]
