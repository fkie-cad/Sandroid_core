"""Settings Controller for TUI.

Manages settings business logic: theme preview/revert, config persistence,
and runtime log level changes.
"""

import logging
from typing import TYPE_CHECKING, Any

from sandroid.config import ConfigLoader, SandroidConfig, reset_config_cache
from sandroid.tui.themes import THEMES, get_theme

if TYPE_CHECKING:
    from sandroid.tui.app import SandroidTUI

logger = logging.getLogger(__name__)


class SettingsController:
    """Controller for settings business logic.

    Separates settings operations from the UI layer for testability.
    """

    def __init__(self, app: "SandroidTUI") -> None:
        """Initialize the settings controller.

        Args:
            app: The TUI application instance for theme operations.
        """
        self._app = app
        self._original_theme_name: str | None = None

    def preview_theme(self, name: str) -> None:
        """Apply a theme preview without saving.

        Stores the original theme on first call so it can be reverted.

        Args:
            name: Theme name to preview.
        """
        if name not in THEMES:
            return

        # Store original theme on first preview call
        if self._original_theme_name is None:
            self._original_theme_name = self._app._sandroid_theme_name

        theme = get_theme(name)
        self._app._sandroid_theme = theme
        self._app._sandroid_theme_name = name
        self._app._apply_theme(theme)

    def revert_theme_preview(self) -> None:
        """Revert to the original theme before any previews."""
        if self._original_theme_name is not None:
            theme = get_theme(self._original_theme_name)
            self._app._sandroid_theme = theme
            self._app._sandroid_theme_name = self._original_theme_name
            self._app._apply_theme(theme)
            self._original_theme_name = None

    def save(self, pending: dict[str, Any]) -> SandroidConfig:
        """Apply pending changes to config and persist.

        Args:
            pending: Dict mapping dotted config keys to new values.
                     Keys use the format "section.field" (e.g., "frida.server_port")
                     or just "field" for top-level settings (e.g., "log_level").

        Returns:
            Updated SandroidConfig instance.
        """
        loader = ConfigLoader()
        config = loader.load()

        for key, value in pending.items():
            self._apply_setting(config, key, value)

        loader.detect_and_save(config)
        reset_config_cache()

        # Apply runtime effects
        if "log_level" in pending:
            self.apply_log_level(pending["log_level"])

        # Theme preview already applied - clear original so revert is skipped
        self._original_theme_name = None

        return config

    def _apply_setting(self, config: SandroidConfig, key: str, value: Any) -> None:
        """Apply a single setting to the config object.

        Args:
            config: Config to modify.
            key: Dotted key path (e.g., "frida.server_port" or "log_level").
            value: New value.
        """
        parts = key.split(".")
        if len(parts) == 1:
            # Top-level setting
            if hasattr(config, parts[0]):
                setattr(config, parts[0], value)
        elif len(parts) == 2:
            # Nested setting (e.g., "frida.server_port")
            section = getattr(config, parts[0], None)
            if section is not None and hasattr(section, parts[1]):
                setattr(section, parts[1], value)

    def apply_log_level(self, new_level: str) -> None:
        """Change the runtime log level.

        Updates the root logger and all non-file handlers so the change
        takes effect immediately in the TUI activity log.

        Args:
            new_level: Log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        """
        level = getattr(logging, new_level.upper(), logging.INFO)
        root = logging.getLogger()
        root.setLevel(level)
        from sandroid.core.events import TUILoggingHandler

        for handler in root.handlers:
            # File handlers stay at DEBUG, TUI handler stays at INFO
            if isinstance(handler, (logging.FileHandler, TUILoggingHandler)):
                continue
            handler.setLevel(level)
        logger.info(f"Log level changed to {new_level.upper()}")
