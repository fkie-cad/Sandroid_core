"""Theme management CLI commands for Sandroid.

Provides the ``theme`` Click group with subcommands:
- ``list``  -- list available TUI themes
- ``set``   -- change the active theme
- ``show``  -- display the currently active theme
"""

import sys

import click
from rich.table import Table

from sandroid.config.loader import ConfigLoader
from sandroid.config.schema import SandroidConfig

from .helpers import (
    THEME_REGISTRY,
    VALID_THEME_IDS,
    _detect_and_save_config,
    console,
    get_theme_display_name,
)


@click.group()
def theme():
    """TUI theme management commands."""


@theme.command("list")
def theme_list():
    """List available TUI themes."""
    console.print("[bold blue]Available TUI Themes[/bold blue]\n")

    themes_table = Table()
    themes_table.add_column("Theme ID", style="cyan")
    themes_table.add_column("Display Name", style="magenta")
    themes_table.add_column("Description", style="dim")

    for name, display, desc in THEME_REGISTRY:
        themes_table.add_row(name, display, desc)

    console.print(themes_table)

    # Show current theme
    try:
        loader = ConfigLoader()
        config = loader.load()
        current = config.tui.theme
        display = get_theme_display_name(current)
        console.print(
            f"\n[bold green]Current theme:[/bold green] {display} ({current})"
        )
    except Exception:
        pass

    console.print(
        "\n[dim]Use 'sandroid-config theme set <theme_id>' to change theme[/dim]"
    )


@theme.command("set")
@click.argument("theme_name")
def theme_set(theme_name: str):
    """Set the TUI theme.

    THEME_NAME: One of: default, dark, light, high_contrast, cyberpunk, nord, dracula, solarized
    """
    theme_name = theme_name.lower()
    if theme_name not in VALID_THEME_IDS:
        console.print(f"[red]Invalid theme: {theme_name}[/red]")
        console.print(f"Valid themes: {', '.join(sorted(VALID_THEME_IDS))}")
        sys.exit(1)

    loader = ConfigLoader()

    try:
        # Load existing config
        try:
            current_config = loader.load()
        except FileNotFoundError:
            current_config = SandroidConfig()

        # Update TUI theme
        config_dict = current_config.dict()
        if "tui" not in config_dict:
            config_dict["tui"] = {}
        config_dict["tui"]["theme"] = theme_name

        # Validate and save
        updated_config = SandroidConfig(**config_dict)
        saved_path = _detect_and_save_config(loader, updated_config)

        display = get_theme_display_name(theme_name)
        console.print(
            f"[green]\u2713[/green] Theme set to: [bold]{display}[/bold] ({theme_name})"
        )
        console.print(f"[dim]Configuration saved to: {saved_path}[/dim]")
        console.print(
            "\n[yellow]Restart Sandroid TUI for full CSS theme to take effect.[/yellow]"
        )

    except Exception as e:
        console.print(f"[red]Failed to update theme: {e}[/red]")
        sys.exit(1)


@theme.command("show")
def theme_show():
    """Show current TUI theme."""
    try:
        loader = ConfigLoader()
        config = loader.load()

        current = config.tui.theme
        display = get_theme_display_name(current)

        console.print("[bold blue]Current TUI Theme[/bold blue]\n")
        console.print(f"  Theme: [bold magenta]{display}[/bold magenta] ({current})")

        if config.tui.custom_css_path:
            console.print(f"  Custom CSS: {config.tui.custom_css_path}")
        if config.tui.logo_color:
            console.print(f"  Logo Color: {config.tui.logo_color}")
        if config.tui.logo_text_color:
            console.print(f"  Logo Text Color: {config.tui.logo_text_color}")

    except Exception as e:
        console.print(f"[red]Failed to load configuration: {e}[/red]")
        sys.exit(1)
