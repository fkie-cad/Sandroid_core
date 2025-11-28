"""Theme configuration for Sandroid terminal output.

This module provides terminal-independent color theming using Rich.
Users can select from preset themes via configuration.
"""

from typing import Dict, List

from rich.style import Style
from rich.theme import Theme


# Theme presets with semantic color mappings
# Each preset defines colors for different UI elements
THEME_PRESETS: Dict[str, Dict[str, str]] = {
    "default": {
        # Primary UI colors
        "primary": "cyan",
        "secondary": "bright_magenta",
        "accent": "magenta",
        # Status colors
        "success": "green",
        "warning": "yellow",
        "error": "red",
        "info": "blue",
        # Logo
        "logo": "bright_green",
        # Menu elements
        "menu.key": "bright_magenta bold",
        "menu.key.bracket": "bright_magenta",
        "menu.section": "cyan",
        "menu.text": "white",
        # Status indicators
        "status.running": "green",
        "status.stopped": "red",
        "status.pending": "yellow",
        "status.notset": "yellow",
        # Mode indicators
        "mode.spawn": "cyan",
        "mode.attach": "green",
        # Box/Panel styling
        "box.border": "cyan",
        "box.title": "magenta",
    },
    "dark": {
        # Primary UI colors - brighter for dark backgrounds
        "primary": "bright_blue",
        "secondary": "bright_cyan",
        "accent": "bright_magenta",
        # Status colors
        "success": "bright_green",
        "warning": "bright_yellow",
        "error": "bright_red",
        "info": "bright_blue",
        # Logo
        "logo": "bright_cyan",
        # Menu elements
        "menu.key": "bright_cyan bold",
        "menu.key.bracket": "bright_cyan",
        "menu.section": "bright_blue",
        "menu.text": "bright_white",
        # Status indicators
        "status.running": "bright_green",
        "status.stopped": "bright_red",
        "status.pending": "bright_yellow",
        "status.notset": "bright_yellow",
        # Mode indicators
        "mode.spawn": "bright_cyan",
        "mode.attach": "bright_green",
        # Box/Panel styling
        "box.border": "bright_blue",
        "box.title": "bright_magenta",
    },
    "light": {
        # Primary UI colors - darker for light backgrounds
        "primary": "blue",
        "secondary": "magenta",
        "accent": "purple4",
        # Status colors
        "success": "green4",
        "warning": "orange3",
        "error": "red3",
        "info": "blue",
        # Logo
        "logo": "green",
        # Menu elements
        "menu.key": "magenta bold",
        "menu.key.bracket": "magenta",
        "menu.section": "blue",
        "menu.text": "black",
        # Status indicators
        "status.running": "green4",
        "status.stopped": "red3",
        "status.pending": "orange3",
        "status.notset": "orange3",
        # Mode indicators
        "mode.spawn": "blue",
        "mode.attach": "green4",
        # Box/Panel styling
        "box.border": "blue",
        "box.title": "purple4",
    },
    "high_contrast": {
        # Primary UI colors - maximum contrast
        "primary": "bright_white",
        "secondary": "bright_cyan",
        "accent": "bright_magenta",
        # Status colors
        "success": "bright_green",
        "warning": "bright_yellow",
        "error": "bright_red",
        "info": "bright_cyan",
        # Logo
        "logo": "bright_white",
        # Menu elements
        "menu.key": "bright_white bold",
        "menu.key.bracket": "bright_white",
        "menu.section": "bright_cyan",
        "menu.text": "bright_white",
        # Status indicators
        "status.running": "bright_green",
        "status.stopped": "bright_red",
        "status.pending": "bright_yellow",
        "status.notset": "bright_yellow",
        # Mode indicators
        "mode.spawn": "bright_cyan",
        "mode.attach": "bright_green",
        # Box/Panel styling
        "box.border": "bright_cyan",
        "box.title": "bright_magenta",
    },
}


def create_rich_theme(preset_name: str = "default") -> Theme:
    """Create a Rich Theme from a preset name.

    Args:
        preset_name: Name of the theme preset (default, dark, light, high_contrast)

    Returns:
        Rich Theme object configured with the preset's colors
    """
    colors = THEME_PRESETS.get(preset_name, THEME_PRESETS["default"])
    return Theme({name: Style.parse(style) for name, style in colors.items()})


def get_preset_names() -> List[str]:
    """Return list of available theme preset names.

    Returns:
        List of preset names that can be used with create_rich_theme()
    """
    return list(THEME_PRESETS.keys())


def get_preset_colors(preset_name: str = "default") -> Dict[str, str]:
    """Get the color definitions for a specific preset.

    Args:
        preset_name: Name of the theme preset

    Returns:
        Dictionary mapping style names to color definitions
    """
    return THEME_PRESETS.get(preset_name, THEME_PRESETS["default"]).copy()
