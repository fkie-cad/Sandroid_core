"""Centralized Rich console management for Sandroid.

This module provides a singleton console with theme support for
consistent, terminal-independent color rendering throughout Sandroid.
"""

from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from sandroid.config.theme import create_rich_theme

# Sandroid ASCII logo (without color codes - colors applied via theme)
SANDROID_LOGO = """⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢷⣤⣤⣴⣶⣶⣦⣤⣤⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀
⠀⠀⠀⠀⣼⣿⣿⣉⣹⣿⣿⣿⣿⣏⣉⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀
⣠⣄⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀
⣿⣿⡇⢸⣿⣿⣿Sandroid⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀
⠻⠟⠁⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠈⠻⠟⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠉⣿⣿⣿⡏⠉⠉⢹⣿⣿⣿⠉⠉⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⢀⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"""


class SandroidConsole:
    """Singleton console manager with theme support for Sandroid.

    This class provides a centralized Rich Console instance with
    theme-aware styling for all terminal output in Sandroid.

    Usage:
        # Initialize once at startup (typically in cli.py)
        SandroidConsole.initialize("dark")

        # Get console anywhere in the codebase
        console = SandroidConsole.get()
        console.print("[success]Operation completed![/success]")

        # Or use helper methods
        SandroidConsole.print_logo()
    """

    _console: Console | None = None
    _preset: str = "default"
    _startup_messages: list = []  # Buffer for startup log messages

    @classmethod
    def initialize(cls, preset: str = "default") -> Console:
        """Initialize the console with a theme preset.

        Args:
            preset: Theme preset name (default, dark, light, high_contrast)

        Returns:
            Configured Rich Console instance
        """
        cls._preset = preset
        theme = create_rich_theme(preset)
        cls._console = Console(theme=theme)
        return cls._console

    @classmethod
    def get(cls) -> Console:
        """Get the initialized console, or create with defaults.

        Returns:
            Rich Console instance (creates one with default theme if needed)
        """
        if cls._console is None:
            cls.initialize()
        return cls._console

    @classmethod
    def get_preset(cls) -> str:
        """Get the current theme preset name.

        Returns:
            Current preset name
        """
        return cls._preset

    @classmethod
    def print_logo(cls) -> None:
        """Print the Sandroid logo with theme colors.

        The 'Sandroid' text within the logo uses default terminal color,
        while the rest of the logo uses the theme's logo color.
        """
        console = cls.get()
        # Split logo at "Sandroid" to apply different styling
        # Line with Sandroid: ⣿⣿⡇⢸⣿⣿⣿Sandroid⣿⣿⣿⡇⢸⣿⣿...
        for line in SANDROID_LOGO.splitlines():
            if "Sandroid" in line:
                # Split around "Sandroid" and style differently
                before, after = line.split("Sandroid", 1)
                console.print(
                    f"[logo]{before}[/logo][default]Sandroid[/default][logo]{after}[/logo]"
                )
            else:
                console.print(f"[logo]{line}[/logo]")

    @classmethod
    def add_startup_message(cls, message: str) -> None:
        """Buffer a startup message to display after the menu.

        Args:
            message: The formatted message to buffer
        """
        cls._startup_messages.append(message)

    @classmethod
    def get_startup_messages(cls) -> list:
        """Get all buffered startup messages.

        Returns:
            List of buffered messages
        """
        return cls._startup_messages.copy()

    @classmethod
    def clear_startup_messages(cls) -> None:
        """Clear all buffered startup messages."""
        cls._startup_messages.clear()

    @classmethod
    def print_startup_messages(cls) -> None:
        """Print all buffered startup messages and clear the buffer."""
        if cls._startup_messages:
            console = cls.get()
            console.print()  # Blank line before messages
            for msg in cls._startup_messages:
                console.print(msg)
            cls._startup_messages.clear()

    @classmethod
    def print_section_header(cls, title: str) -> None:
        """Print a section header with theme styling.

        Args:
            title: Section title text
        """
        console = cls.get()
        console.print(f"    [menu.section]=== {title} ===[/menu.section]")

    @classmethod
    def print_menu_item(
        cls, key: str, description: str, suffix: str = "", prefix: str = "    * "
    ) -> None:
        """Print a menu item with highlighted shortcut key.

        Args:
            key: The shortcut key (single character)
            description: Description text after the key
            suffix: Optional suffix text (e.g., mode indicator)
            prefix: Line prefix (default: "    * ")
        """
        console = cls.get()
        suffix_part = f" [accent]{suffix}[/accent]" if suffix else ""
        console.print(
            f"{prefix}[menu.key.bracket][[/menu.key.bracket]"
            f"[menu.key]{key}[/menu.key]"
            f"[menu.key.bracket]][/menu.key.bracket]"
            f"[menu.text]{description}[/menu.text]{suffix_part}"
        )

    @classmethod
    def print_status(cls, label: str, value: str, is_active: bool = True) -> None:
        """Print a status line with appropriate coloring.

        Args:
            label: Status label (e.g., "Frida Server")
            value: Status value (e.g., "Running", "Not set")
            is_active: True for running/active status, False for stopped/inactive
        """
        console = cls.get()
        style = "status.running" if is_active else "status.stopped"
        console.print(f"{label}: [[{style}]{value}[/{style}]]")

    @classmethod
    def print_panel(
        cls,
        content: str,
        title: str = "",
        border_style: str = "cyan",
        title_style: str = "magenta",
        expand: bool = False,
    ) -> None:
        """Print content in a Rich Panel with theme styling.

        Args:
            content: Panel content (can include Rich markup)
            title: Optional panel title
            border_style: Direct color string for border (e.g., "cyan", "blue")
            title_style: Direct color string for title (e.g., "magenta", "bold white")
            expand: Whether to expand panel to full terminal width (default: False)
        """
        console = cls.get()
        panel = Panel(
            Text.from_markup(content),
            title=f"[{title_style}]{title}[/{title_style}]" if title else None,
            border_style=border_style,
            expand=expand,
        )
        console.print(panel)

    @classmethod
    def clear(cls) -> None:
        """Clear the terminal screen."""
        console = cls.get()
        console.clear()

    @classmethod
    def print(cls, *args, **kwargs) -> None:
        """Convenience method to print via the themed console.

        Accepts same arguments as rich.console.Console.print()
        """
        console = cls.get()
        console.print(*args, **kwargs)


def get_logo() -> str:
    """Get the raw Sandroid logo text (without styling).

    Returns:
        Logo as plain text string
    """
    return SANDROID_LOGO
