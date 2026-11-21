"""Settings Controller for TUI.

Manages settings business logic: theme preview/revert, config persistence,
and runtime log level changes.
"""

import logging
from typing import TYPE_CHECKING, Any

from sandroid.config import SandroidConfig, update_config
from sandroid.tui.themes import THEMES, get_theme, get_theme_css_path

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
        self._app._apply_theme(theme, get_theme_css_path(name))

    def revert_theme_preview(self) -> None:
        """Revert to the original theme before any previews."""
        if self._original_theme_name is not None:
            theme = get_theme(self._original_theme_name)
            self._app._sandroid_theme = theme
            self._app._sandroid_theme_name = self._original_theme_name
            self._app._apply_theme(theme, get_theme_css_path(self._original_theme_name))
            self._original_theme_name = None

    def save(self, pending: dict[str, Any]) -> SandroidConfig:
        """Apply pending changes to config and persist.

        Args:
            pending: Dict mapping dotted config keys to new values.
                     Keys use the format "section.field" (e.g., "frida.server_port")
                     or just "field" for top-level settings (e.g., "log_level").

        The changes are validated against the whole *live* config first
        (``get_config()``, which carries ``--config`` / ``--environment`` /
        CLI-flag overrides) and applied to it in place -- the config is NOT
        re-loaded from disk, so e.g. ``--network`` or a ``--config`` results
        path survive a save. Only the changed keys are written, to the config
        file actually in use (the ``--config`` file when given).

        Returns:
            The live (updated) SandroidConfig instance.

        Raises:
            sandroid.config.ConfigUpdateError: If a value is invalid (e.g.
                ``analysis.number_of_runs = 1``). Nothing is applied or written.
        """
        config, _saved_path = update_config(pending)

        # Apply runtime effects
        if "log_level" in pending:
            self.apply_log_level(pending["log_level"])

        # Theme preview already applied - clear original so revert is skipped
        self._original_theme_name = None

        return config

    def apply_log_level(self, new_level: str) -> None:
        """Change the runtime log level.

        Updates the root logger and all non-file handlers so the change
        takes effect immediately in the TUI activity log.

        Args:
            new_level: Log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        """
        level = getattr(logging, new_level.upper(), logging.INFO)
        root = logging.getLogger()
        changed = root.level != level
        root.setLevel(level)
        from sandroid.core.events import TUILoggingHandler

        for handler in root.handlers:
            # File handlers stay at DEBUG, TUI handler stays at INFO
            if isinstance(handler, (logging.FileHandler, TUILoggingHandler)):
                continue
            handler.setLevel(level)
        if changed:
            # Settings re-stages the unchanged level on every save: say so
            # only when it really changed.
            logger.info(f"Log level changed to {new_level.upper()}")
