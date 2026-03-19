"""TrigDroid Controller for TUI.

This controller manages TrigDroid bypass operations, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Start/stop TrigDroid bypass
- Configure bypass options (SSL unpinning, root detection, etc.)
- Handle spawn vs attach modes

Usage:
    from sandroid.tui.controllers import TrigDroidController

    controller = TrigDroidController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        push_modal=app.push_screen,
        force_ui_refresh=app._force_ui_refresh,
    )

    # Show TrigDroid configuration modal
    controller.show_trigdroid_modal()
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TrigDroidConfig:
    """Configuration for TrigDroid bypass."""

    mode: Any  # SpawnMode enum
    package_name: str
    ssl_unpinning: bool = False
    root_detection_bypass: bool = False
    emulator_detection_bypass: bool = False
    frida_detection_bypass: bool = False
    debug_detection_bypass: bool = False
    cancelled: bool = False


class TrigDroidController:
    """Controller for TrigDroid bypass operations.

    This controller handles all TrigDroid-related operations, decoupled from
    the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of TrigDroid logic from UI rendering
    - Reusable TrigDroid management across different UI modes

    Example:
        controller = TrigDroidController(
            log_info=print,
            log_warning=lambda msg: print(f"WARN: {msg}"),
            push_modal=lambda modal, cb: cb(None),
            force_ui_refresh=lambda: None,
        )

        # Show TrigDroid modal or toggle
        controller.toggle_trigdroid()
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_warning: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        log_success: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        force_ui_refresh: Callable[[], None] | None = None,
    ):
        """Initialize TrigDroidController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI
            log_warning: Callback for warning-level logging to UI
            log_error: Callback for error-level logging to UI
            log_success: Callback for success-level logging to UI
            push_modal: Callback to push a modal screen with result callback
            force_ui_refresh: Callback to force UI refresh after state changes
        """
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_error = log_error or self._default_log
        self._log_success = log_success or self._default_log
        self._push_modal = push_modal
        self._force_ui_refresh = force_ui_refresh

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def _get_task_service(self) -> Any:
        """Get task service instance."""
        from sandroid.services import get_task_service

        return get_task_service()

    def _get_spotlight_service(self) -> Any:
        """Get spotlight service instance."""
        from sandroid.services import get_spotlight_service

        return get_spotlight_service()

    # =========================================================================
    # TrigDroid Status
    # =========================================================================

    def is_running(self) -> bool:
        """Check if TrigDroid bypass is currently running.

        Returns:
            True if TrigDroid bypass is active
        """
        return self._get_task_service().is_running("trigdroid_bypass")

    def get_package_name(self) -> str | None:
        """Get the current package name for TrigDroid.

        Returns:
            Package name if available, None otherwise
        """
        spotlight = self._get_spotlight_service()

        if spotlight.is_spawn_mode():
            return spotlight.get_spawn_package()
        spotlight_app = spotlight.get_app_tuple()
        return spotlight_app[0] if spotlight_app else None

    def has_target_app(self) -> bool:
        """Check if a target app is available for TrigDroid.

        Returns:
            True if a target app is set
        """
        return self.get_package_name() is not None

    # =========================================================================
    # TrigDroid Operations
    # =========================================================================

    def toggle_trigdroid(self) -> bool:
        """Toggle TrigDroid bypass - stop if running, show modal if not.

        Returns:
            True if action was successful
        """
        if self.is_running():
            return self.stop()
        return self.show_trigdroid_modal()

    def stop(self) -> bool:
        """Stop TrigDroid bypass if running.

        Returns:
            True if TrigDroid was stopped
        """
        if not self.is_running():
            return False

        self._get_task_service().stop("trigdroid_bypass")
        self._log_info("TrigDroid bypass stopped")

        if self._force_ui_refresh:
            self._force_ui_refresh()

        return True

    def show_trigdroid_modal(self) -> bool:
        """Show TrigDroid configuration modal.

        Returns:
            True if modal was shown
        """
        from sandroid.tui.modals import SpawnMode, TrigDroidModal

        # Check if target app is available
        package_name = self.get_package_name()
        if not package_name:
            self._log_warning("No APK installed. Please install an APK first (n key)")
            return False

        if not self._push_modal:
            self._log_error("Cannot show modal - push_modal not configured")
            return False

        spotlight = self._get_spotlight_service()
        mode = SpawnMode.SPAWN if spotlight.is_spawn_mode() else SpawnMode.ATTACH

        def on_trigdroid_result(result: TrigDroidConfig) -> None:
            if result is None or result.cancelled:
                self._log_info("TrigDroid configuration cancelled")
                return

            # Build list of enabled bypasses for logging
            enabled_bypasses = self._get_enabled_bypasses(result)

            if enabled_bypasses:
                self._log_info(
                    f"TrigDroid starting with: {', '.join(enabled_bypasses)}"
                )
            else:
                self._log_info("TrigDroid starting with no bypasses enabled")

            # Start TrigDroid with the configuration
            self._start_with_config(result)

        self._push_modal(
            TrigDroidModal(mode=mode, package_name=package_name),
            on_trigdroid_result,
        )
        return True

    def _get_enabled_bypasses(self, config: TrigDroidConfig) -> list[str]:
        """Get list of enabled bypass names from config.

        Args:
            config: TrigDroid configuration

        Returns:
            List of enabled bypass names
        """
        bypass_flags = [
            (config.ssl_unpinning, "SSL Unpinning"),
            (config.root_detection_bypass, "Root Detection"),
            (config.emulator_detection_bypass, "Emulator Detection"),
            (config.frida_detection_bypass, "Frida Detection"),
            (config.debug_detection_bypass, "Debug Detection"),
        ]
        return [name for flag, name in bypass_flags if flag]

    def _start_with_config(self, config: TrigDroidConfig) -> bool:
        """Start TrigDroid Bypass with the given configuration.

        Args:
            config: TrigDroid configuration with bypass settings

        Returns:
            True if TrigDroid was started successfully
        """
        from sandroid.analysis.trigdroid_bypass import TrigDroidBypass
        from sandroid.tui.modals import SpawnMode

        try:
            bypass_mapping = [
                (config.ssl_unpinning, "ssl_unpinning"),
                (config.root_detection_bypass, "root_detection"),
                (config.emulator_detection_bypass, "emulator_detection"),
                (config.frida_detection_bypass, "frida_detection"),
                (config.debug_detection_bypass, "debug_detection"),
            ]
            bypass_config: dict[str, Any] = {
                key: {"enabled": True} for flag, key in bypass_mapping if flag
            }
            bypass_config["spawn_mode"] = config.mode == SpawnMode.SPAWN

            # Create and start TrigDroidBypass directly
            trigdroid_bypass = TrigDroidBypass()

            if trigdroid_bypass.start(config=bypass_config):
                self._log_success(f"TrigDroid Bypass started on {config.package_name}")

                if self._force_ui_refresh:
                    self._force_ui_refresh()

                return True
            self._log_error("Failed to start TrigDroid Bypass")
            return False

        except Exception as e:
            self._log_error(f"Failed to start TrigDroid: {e}")
            return False

    def start_with_defaults(self, package_name: str, spawn_mode: bool = False) -> bool:
        """Start TrigDroid with default bypass settings.

        Args:
            package_name: Target package name
            spawn_mode: Whether to use spawn mode

        Returns:
            True if TrigDroid was started successfully
        """
        from sandroid.tui.modals import SpawnMode

        config = TrigDroidConfig(
            mode=SpawnMode.SPAWN if spawn_mode else SpawnMode.ATTACH,
            package_name=package_name,
            ssl_unpinning=True,
            root_detection_bypass=True,
            emulator_detection_bypass=True,
            frida_detection_bypass=spawn_mode,  # Only in spawn mode
            debug_detection_bypass=True,
        )

        return self._start_with_config(config)


__all__ = [
    "TrigDroidConfig",
    "TrigDroidController",
]
