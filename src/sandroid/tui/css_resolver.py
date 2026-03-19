"""CSS resolution utilities for Sandroid TUI.

This module handles loading and resolving CSS files for the TUI application.
It supports:
- Explicit custom CSS paths
- Config-based CSS paths
- Theme-specific CSS files
- Default fallback CSS

The resolution order is:
1. Explicit ``custom_css_path`` parameter
2. ``tui.custom_css_path`` from Sandroid config
3. Theme-specific CSS based on ``tui.theme`` in config
4. Default ``styles.tcss``
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Path to default CSS file
DEFAULT_CSS_PATH = Path(__file__).parent / "styles.tcss"


def load_css_content(css_path: Path) -> str:
    """Load CSS content from a file.

    Args:
        css_path: Path to the CSS file.

    Returns:
        CSS content as string, or empty string if file doesn't exist.
    """
    try:
        if css_path.exists():
            return css_path.read_text(encoding="utf-8")
    except Exception as e:
        logger.warning(f"Failed to load CSS from {css_path}: {e}")
    return ""


def get_css_path_from_config() -> Path | None:
    """Get custom CSS path from Sandroid config.

    Returns:
        Path to custom CSS file if configured, None otherwise.
    """
    try:
        from sandroid.config.loader import ConfigLoader

        loader = ConfigLoader()
        config = loader.load()
        if config.tui.custom_css_path:
            custom_path = Path(config.tui.custom_css_path).expanduser()
            if custom_path.exists():
                return custom_path
            logger.warning(
                f"Custom CSS path configured but file not found: {custom_path}"
            )
    except Exception as e:
        logger.debug(f"Could not load TUI config: {e}")
    return None


def resolve_css_path(
    custom_css_path: Path | str | None,
    sandroid_config=None,
) -> Path:
    """Resolve which CSS file to use.

    Priority:
    1. Explicit *custom_css_path* parameter
    2. Path from Sandroid config (``tui.custom_css_path``)
    3. Theme-specific CSS based on configured theme (``tui.theme``)
    4. Default ``styles.tcss``

    Args:
        custom_css_path: Explicitly provided custom CSS path.
        sandroid_config: Loaded SandroidConfig instance (optional).

    Returns:
        Path to the CSS file to use.
    """
    from sandroid.tui.themes import get_theme_css_path

    # 1. Check explicit parameter
    if custom_css_path:
        path = Path(custom_css_path).expanduser()
        if path.exists():
            logger.debug(f"Using custom CSS from parameter: {path}")
            return path
        logger.warning(f"Custom CSS path not found: {path}, falling back")

    # 2. Check config for custom_css_path
    config_path = get_css_path_from_config()
    if config_path:
        logger.debug(f"Using custom CSS from config: {config_path}")
        return config_path

    # 3. Check config for theme and use theme-specific CSS
    try:
        if sandroid_config and hasattr(sandroid_config, "tui"):
            theme_name = sandroid_config.tui.theme
            if theme_name and theme_name != "default":
                theme_css = get_theme_css_path(theme_name)
                if theme_css.exists():
                    logger.debug(f"Using theme CSS: {theme_css}")
                    return theme_css
    except Exception as e:
        logger.debug(f"Could not load theme CSS from config: {e}")

    # 4. Use default
    logger.debug(f"Using default CSS: {DEFAULT_CSS_PATH}")
    return DEFAULT_CSS_PATH
