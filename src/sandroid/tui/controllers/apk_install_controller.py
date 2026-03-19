"""APK Install Controller for TUI.

This controller manages APK installation and post-install setup,
extracted from the monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Show APK install modal
- Handle install result (success, cancel, error)
- Chain spotlight setup and auto-resume modals after install

Usage:
    from sandroid.tui.controllers import APKInstallController

    controller = APKInstallController(
        log_info=activity_log.log_info,
        log_error=activity_log.log_error,
        log_success=activity_log.log_success,
        push_modal=app.push_screen,
    )

    controller.show_install_modal()
"""

import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class APKInstallController:
    """Controller for APK installation and post-install setup.

    This controller handles the full APK installation flow including
    a 3-modal chain: install -> spotlight setup -> auto-resume. Each
    step is decoupled from the TUI via callback injection.

    Example:
        controller = APKInstallController(
            log_info=print,
            log_error=lambda msg: print(f"ERR: {msg}"),
            log_success=lambda msg: print(f"OK: {msg}"),
            push_modal=lambda modal, cb: cb(None),
        )

        controller.show_install_modal()
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        log_success: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        force_ui_refresh: Callable[[], None] | None = None,
    ):
        """Initialize APKInstallController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI.
            log_error: Callback for error-level logging to UI.
            log_success: Callback for success-level logging to UI.
            push_modal: Callback to push a modal screen with result callback.
            force_ui_refresh: Callback to refresh UI after state changes.
        """
        self._log_info = log_info or self._default_log
        self._log_error = log_error or self._default_log
        self._log_success = log_success or self._default_log
        self._push_modal = push_modal
        self._force_ui_refresh = force_ui_refresh

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def show_install_modal(self) -> None:
        """Show APK installation modal.

        Opens the APKInstallModal and handles the result callback.
        On successful install, chains to spotlight setup modal.
        """
        from sandroid.tui.modals import APKInstallModal, APKInstallResult

        def on_apk_result(result: APKInstallResult) -> None:
            try:
                if result.cancelled:
                    self._log_info("APK installation cancelled")
                    return

                if result.installed_package:
                    self._log_success(f"APK installed: {result.installed_package}")
                    from sandroid.core.actionQ import ActionQ

                    ActionQ.recently_installed_package = result.installed_package
                    self._offer_spotlight_setup(result.installed_package)

                elif result.error:
                    self._log_error(f"Installation failed: {result.error}")
            except Exception:
                pass

        if self._push_modal:
            self._push_modal(APKInstallModal(), on_apk_result)

    def _offer_spotlight_setup(self, package_name: str) -> None:
        """Offer to set installed package as spotlight spawn app.

        Args:
            package_name: The package name of the installed APK.
        """
        from sandroid.tui.modals import ConfirmModal

        def on_confirm(confirmed: bool) -> None:
            try:
                if confirmed:
                    from sandroid.services import get_spotlight_service

                    get_spotlight_service().set_spawn_app(package_name)
                    self._log_success(f"Spotlight spawn app set: {package_name}")
                    if self._force_ui_refresh:
                        self._force_ui_refresh()
                    self._offer_auto_resume()
                else:
                    self._log_info("Spotlight setup skipped")
            except Exception:
                pass

        if self._push_modal:
            self._push_modal(
                ConfirmModal(
                    title="Set Spotlight App",
                    message=f"Set {package_name} as spotlight app?",
                ),
                on_confirm,
            )

    def _offer_auto_resume(self) -> None:
        """Offer to enable auto-resume for spotlight app."""
        from sandroid.tui.modals import ConfirmModal

        def on_confirm(confirmed: bool) -> None:
            try:
                from sandroid.services import get_spotlight_service

                get_spotlight_service().set_auto_resume(confirmed)
                status = "enabled" if confirmed else "disabled"
                self._log_info(f"Auto-resume: {status}")
                if self._force_ui_refresh:
                    self._force_ui_refresh()
            except Exception:
                pass

        if self._push_modal:
            self._push_modal(
                ConfirmModal(
                    title="Auto-Resume",
                    message="Auto-resume app after spawn? (recommended)",
                ),
                on_confirm,
            )


__all__ = [
    "APKInstallController",
]
