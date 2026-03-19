"""Theme definitions and CSS files for Sandroid TUI.

This module provides 8 color themes for the TUI interface:
- 4 standard themes: default, dark, light, high_contrast
- 4 new themes: cyberpunk, nord, dracula, solarized

Themes can be cycled at runtime with multiple keybindings:
- Ctrl+T (may be captured by some terminals)
- Shift+T (uppercase T)
- F6 (function key)
- ] (next theme) / [ (previous theme)

Each theme has a corresponding CSS file in this directory.
"""

from dataclasses import dataclass
from pathlib import Path

# Directory containing theme CSS files
THEMES_DIR = Path(__file__).parent

# Parent directory for default theme CSS
PARENT_DIR = THEMES_DIR.parent


@dataclass
class Theme:
    """TUI theme definition.

    Contains all color values used throughout the TUI interface.
    Colors are specified as hex strings (e.g., "#FF00FF").
    """

    name: str  # Internal identifier
    display_name: str  # Human-readable name
    is_dark: bool  # Whether this is a dark theme

    # Primary colors
    primary: str  # Main accent color (headers, titles)
    secondary: str  # Secondary accent color
    accent: str  # Highlight/active color

    # Background colors
    background: str  # Main background
    surface: str  # Elevated surface (panels, modals)

    # Status colors
    error: str  # Error messages
    warning: str  # Warning messages
    success: str  # Success messages

    # Text colors
    text: str  # Primary text
    text_muted: str  # Secondary/dimmed text

    # UI element colors
    key_color: str = "#ff00ff"  # Menu key brackets color (magenta by default)
    border_color: str = "#333333"  # Border/divider color

    # Additional colors for views
    forensic_color: str = "#4CAF50"  # Green for forensic view
    malware_color: str = "#FF5252"  # Red for malware view
    security_color: str = "#FFC107"  # Yellow for security view

    # Logo colors
    logo_color: str = "#00ff00"  # Main logo color (bright green by default)
    logo_text_color: str = "#ffffff"  # "Sandroid" text in logo (white by default)


# ========== Fixed Semantic Colors ==========
# These colors do NOT change with theme - they provide consistent status recognition
# across all themes, like traffic lights (green=go, red=stop).
# This ensures users can instantly recognize states regardless of active theme.

FIXED_COLORS = {
    # Status indicators - universally recognizable
    "running": "#00ff00",  # Bright shiny green - active/running state
    "stopped": "#ff5555",  # Bright red - stopped/inactive state
    "error": "#ff5555",  # Bright red - error state (same as stopped)
    "warning_status": "#ffaa00",  # Bright amber - warning/caution state
    # Mode indicators - matching Rich console mode colors
    # SPAWN = cyan (cold/fresh - launching new process)
    # ATTACH = green (connected/live - attached to running process)
    "spawn_mode": "#00ffff",  # Bright cyan - spawn mode
    "attach_mode": "#00ff00",  # Bright green - attach mode (same as running)
}


# ========== Theme Definitions ==========

# Default theme: Midnight Cyan
DEFAULT_THEME = Theme(
    name="default",
    display_name="Midnight Cyan",
    is_dark=True,
    primary="#38bdf8",  # section_title - bright cyan
    secondary="#7dd3fc",  # header_text - softer cyan
    accent="#00ff00",  # bright/shiny green for running states
    background="#050811",  # almost-black, slightly blue
    surface="#080c18",  # panel_background - slightly lighter
    error="#fb7185",  # log_error - soft red
    warning="#facc15",  # log_warn - soft yellow
    success="#00ff00",  # bright/shiny green for success/running
    text="#e5e9f0",  # text_primary - light grey
    text_muted="#8f9bb3",  # text_secondary - muted grey-blue
    key_color="#ff00ff",  # magenta keys (classic terminal look)
    border_color="#111827",  # subtle border
    forensic_color="#2dd4bf",  # teal/mint green (distinct from running green)
    malware_color="#fb7185",  # soft red
    security_color="#facc15",  # soft yellow
    logo_color="#00ff00",  # bright green logo
    logo_text_color="#ffffff",  # white "Sandroid" text
)

DARK_THEME = Theme(
    name="dark",
    display_name="Dark",
    is_dark=True,
    primary="#BB86FC",  # Purple - Material Design
    secondary="#3700B3",  # Deep purple
    accent="#03DAC6",  # Teal accent
    background="#000000",  # Pure black
    surface="#121212",  # Dark surface
    error="#CF6679",  # Pink error
    warning="#FFB74D",  # Orange warning
    success="#81C784",  # Green success
    text="#E0E0E0",  # Light grey text
    text_muted="#757575",  # Medium grey
    key_color="#03DAC6",  # Teal keys (Material teal)
    border_color="#333333",  # Dark border
    forensic_color="#81C784",  # Green
    malware_color="#CF6679",  # Pink
    security_color="#FFB74D",  # Orange
    logo_color="#03DAC6",  # Teal logo
    logo_text_color="#BB86FC",  # Purple "Sandroid" text
)

LIGHT_THEME = Theme(
    name="light",
    display_name="Light",
    is_dark=False,
    primary="#1976D2",  # Blue
    secondary="#0D47A1",  # Dark blue
    accent="#00BFA5",  # Teal accent
    background="#FAFAFA",  # Off-white
    surface="#FFFFFF",  # White
    error="#D32F2F",  # Red
    warning="#F57C00",  # Orange
    success="#388E3C",  # Green
    text="#212121",  # Dark grey
    text_muted="#757575",  # Medium grey
    key_color="#0D47A1",  # Dark blue keys
    border_color="#E0E0E0",  # Light border
    forensic_color="#388E3C",  # Green
    malware_color="#D32F2F",  # Red
    security_color="#F57C00",  # Orange
    logo_color="#1976D2",  # Blue logo
    logo_text_color="#0D47A1",  # Dark blue "Sandroid" text
)

HIGH_CONTRAST_THEME = Theme(
    name="high_contrast",
    display_name="High Contrast",
    is_dark=True,
    primary="#FFFF00",  # Yellow headers
    secondary="#00FFFF",  # Cyan
    accent="#FF00FF",  # Magenta
    background="#000000",  # Pure black
    surface="#000000",  # Pure black
    error="#FF0000",  # Pure red
    warning="#FFFF00",  # Yellow
    success="#00FF00",  # Pure green
    text="#FFFFFF",  # Pure white
    text_muted="#CCCCCC",  # Light grey
    key_color="#00FFFF",  # Cyan keys (high visibility)
    border_color="#FFFFFF",  # White border
    forensic_color="#00FF00",  # Green
    malware_color="#FF0000",  # Red
    security_color="#FFFF00",  # Yellow
    logo_color="#00FF00",  # Bright green logo
    logo_text_color="#FFFF00",  # Yellow "Sandroid" text
)

CYBERPUNK_THEME = Theme(
    name="cyberpunk",
    display_name="Cyberpunk/Neon",
    is_dark=True,
    primary="#FF00FF",  # Magenta headers
    secondary="#00FFFF",  # Cyan
    accent="#FFFF00",  # Yellow
    background="#0D0221",  # Deep purple-black
    surface="#1A0A2E",  # Dark purple
    error="#FF3366",  # Hot pink
    warning="#FF9900",  # Orange
    success="#00FF9F",  # Neon green
    text="#F0F0F0",  # Off-white
    text_muted="#8B8B8B",  # Grey
    key_color="#00FFFF",  # Cyan keys (neon look)
    border_color="#FF00FF",  # Magenta border
    forensic_color="#00FF9F",  # Neon green
    malware_color="#FF3366",  # Hot pink
    security_color="#FFFF00",  # Yellow
    logo_color="#FF00FF",  # Magenta logo
    logo_text_color="#00FFFF",  # Cyan "Sandroid" text
)

NORD_THEME = Theme(
    name="nord",
    display_name="Nord/Arctic",
    is_dark=True,
    primary="#88C0D0",  # Frost blue headers
    secondary="#81A1C1",  # Storm blue
    accent="#A3BE8C",  # Aurora green
    background="#2E3440",  # Polar night
    surface="#3B4252",  # Polar night lighter
    error="#BF616A",  # Aurora red
    warning="#EBCB8B",  # Aurora yellow
    success="#A3BE8C",  # Aurora green
    text="#ECEFF4",  # Snow storm
    text_muted="#4C566A",  # Polar night lightest
    key_color="#B48EAD",  # Aurora purple keys (Nord aurora)
    border_color="#4C566A",  # Polar night border
    forensic_color="#A3BE8C",  # Aurora green
    malware_color="#BF616A",  # Aurora red
    security_color="#EBCB8B",  # Aurora yellow
    logo_color="#88C0D0",  # Frost blue logo
    logo_text_color="#ECEFF4",  # Snow white "Sandroid" text
)

DRACULA_THEME = Theme(
    name="dracula",
    display_name="Dracula",
    is_dark=True,
    primary="#BD93F9",  # Purple headers
    secondary="#6272A4",  # Comment blue
    accent="#50FA7B",  # Green
    background="#282A36",  # Background
    surface="#44475A",  # Current line
    error="#FF5555",  # Red
    warning="#FFB86C",  # Orange
    success="#50FA7B",  # Green
    text="#F8F8F2",  # Foreground
    text_muted="#6272A4",  # Comment
    key_color="#FF79C6",  # Pink keys (Dracula pink)
    border_color="#6272A4",  # Comment border
    forensic_color="#50FA7B",  # Green
    malware_color="#FF5555",  # Red
    security_color="#FFB86C",  # Orange
    logo_color="#BD93F9",  # Purple logo
    logo_text_color="#50FA7B",  # Green "Sandroid" text
)

SOLARIZED_THEME = Theme(
    name="solarized",
    display_name="Solarized Dark",
    is_dark=True,
    primary="#268BD2",  # Blue headers
    secondary="#2AA198",  # Cyan
    accent="#859900",  # Green
    background="#002B36",  # Base03
    surface="#073642",  # Base02
    error="#DC322F",  # Red
    warning="#B58900",  # Yellow
    success="#859900",  # Green
    text="#839496",  # Base0
    text_muted="#586E75",  # Base01
    key_color="#D33682",  # Magenta keys (Solarized magenta)
    border_color="#586E75",  # Base01 border
    forensic_color="#859900",  # Green
    malware_color="#DC322F",  # Red
    security_color="#B58900",  # Yellow
    logo_color="#2AA198",  # Cyan logo
    logo_text_color="#268BD2",  # Blue "Sandroid" text
)

# Theme registry
THEMES: dict[str, Theme] = {
    "default": DEFAULT_THEME,
    "dark": DARK_THEME,
    "light": LIGHT_THEME,
    "high_contrast": HIGH_CONTRAST_THEME,
    "cyberpunk": CYBERPUNK_THEME,
    "nord": NORD_THEME,
    "dracula": DRACULA_THEME,
    "solarized": SOLARIZED_THEME,
}

# Theme cycling order
THEME_ORDER = [
    "default",
    "dark",
    "light",
    "high_contrast",
    "cyberpunk",
    "nord",
    "dracula",
    "solarized",
]


# ========== Theme Functions ==========


def get_theme(name: str) -> Theme:
    """Get a theme by name.

    Args:
        name: Theme identifier

    Returns:
        Theme instance, or default if not found
    """
    return THEMES.get(name, DEFAULT_THEME)


def get_next_theme(current: str) -> str:
    """Get the next theme in the cycle.

    Args:
        current: Current theme name

    Returns:
        Name of the next theme
    """
    try:
        idx = THEME_ORDER.index(current)
        return THEME_ORDER[(idx + 1) % len(THEME_ORDER)]
    except ValueError:
        return THEME_ORDER[0]


def get_previous_theme(current: str) -> str:
    """Get the previous theme in the cycle.

    Args:
        current: Current theme name

    Returns:
        Name of the previous theme
    """
    try:
        idx = THEME_ORDER.index(current)
        return THEME_ORDER[(idx - 1) % len(THEME_ORDER)]
    except ValueError:
        return THEME_ORDER[-1]


def get_all_themes() -> dict[str, Theme]:
    """Get all available themes.

    Returns:
        Dict mapping theme names to Theme instances
    """
    return THEMES.copy()


def theme_to_css_vars(theme: Theme) -> str:
    """Convert theme to Textual CSS variable definitions.

    Args:
        theme: Theme to convert

    Returns:
        CSS string with variable definitions
    """
    return f"""
$primary: {theme.primary};
$secondary: {theme.secondary};
$accent: {theme.accent};
$background: {theme.background};
$surface: {theme.surface};
$error: {theme.error};
$warning: {theme.warning};
$success: {theme.success};
$text: {theme.text};
$text-muted: {theme.text_muted};
$forensic-color: {theme.forensic_color};
$malware-color: {theme.malware_color};
$security-color: {theme.security_color};
$logo-color: {theme.logo_color};
$logo-text-color: {theme.logo_text_color};
"""


# ========== CSS Path Functions ==========


def get_theme_css_path(theme_name: str) -> Path:
    """Get the path to a theme's CSS file.

    Args:
        theme_name: Name of the theme (default, dark, light, etc.)

    Returns:
        Path to the theme's CSS file
    """
    if theme_name == "default":
        # Default theme uses the main styles.tcss
        return PARENT_DIR / "styles.tcss"

    css_file = THEMES_DIR / f"{theme_name}.tcss"
    if css_file.exists():
        return css_file

    # Fall back to default if theme CSS doesn't exist
    return PARENT_DIR / "styles.tcss"


def get_available_theme_css_files() -> dict[str, Path]:
    """Get all available theme CSS files.

    Returns:
        Dict mapping theme names to their CSS file paths
    """
    themes = {
        "default": PARENT_DIR / "styles.tcss",
    }

    # Add all .tcss files in themes directory
    for css_file in THEMES_DIR.glob("*.tcss"):
        theme_name = css_file.stem
        themes[theme_name] = css_file

    return themes


# ========== Exports ==========
__all__ = [
    "CYBERPUNK_THEME",
    "DARK_THEME",
    "DEFAULT_THEME",
    "DRACULA_THEME",
    "FIXED_COLORS",
    "HIGH_CONTRAST_THEME",
    "LIGHT_THEME",
    "NORD_THEME",
    "PARENT_DIR",
    "SOLARIZED_THEME",
    "THEMES",
    "THEMES_DIR",
    "THEME_ORDER",
    "Theme",
    "get_all_themes",
    "get_available_theme_css_files",
    "get_next_theme",
    "get_previous_theme",
    "get_theme",
    "get_theme_css_path",
    "theme_to_css_vars",
]
