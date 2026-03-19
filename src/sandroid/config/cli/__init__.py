"""Configuration management CLI for Sandroid.

This package replaces the former monolithic ``cli.py`` module.  The public
entry point is the :func:`main` Click group which is registered as the
``sandroid-config`` console script.

Subgroups are registered from their own modules:
- ``avd``   -- :mod:`.avd_commands`
- ``theme`` -- :mod:`.theme_commands`
- ``ioc``   -- :mod:`.ioc_commands`

The standalone ``devices`` command lives in :mod:`.device_commands`.
"""

import sys
from pathlib import Path

import click
from rich.prompt import Confirm, Prompt
from rich.table import Table

from sandroid.config.loader import ConfigLoader
from sandroid.config.schema import SandroidConfig

from .avd_commands import avd
from .device_commands import devices_list
from .helpers import (
    THEME_REGISTRY,
    _parse_value,
    _show_config_format,
    _show_config_rich,
    console,
    get_theme_display_name,
)
from .ioc_commands import ioc
from .theme_commands import theme

# ---------------------------------------------------------------------------
# Main Click group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option()
def main():
    """Sandroid configuration management."""


# Register subgroups and standalone commands
main.add_command(avd)
main.add_command(theme)
main.add_command(ioc)
main.add_command(devices_list)


# Re-export for backward compatibility (some code may import ``sandroid_config``
# or ``main`` from this module).
sandroid_config = main


# ---------------------------------------------------------------------------
# init command  (broken into helper functions for readability)
# ---------------------------------------------------------------------------


def _setup_avd_config() -> dict:
    """Run the interactive AVD setup wizard.

    Returns:
        Dictionary of AVD-related config keys/values (may be empty).
    """
    from sandroid.config.android_env import setup_android_environment

    console.print()
    android_env = setup_android_environment(skip_setup=False)

    android_config: dict = {}

    if android_env.get("sdk_path"):
        android_config["sdk_path"] = str(android_env["sdk_path"])

    if android_env.get("adb_path"):
        android_config["adb_path"] = str(android_env["adb_path"])

    if android_env.get("emulator_path"):
        android_config["android_emulator_path"] = str(android_env["emulator_path"])

    if android_env.get("avd_home"):
        android_config["avd_home"] = str(android_env["avd_home"])

    if android_env.get("selected_avd"):
        android_config["selected_avd"] = android_env["selected_avd"]
        android_config["device_name"] = android_env["selected_avd"]

        headless = not Confirm.ask(
            f"Start AVD '{android_env['selected_avd']}' with UI by default?",
            default=True,
        )
        android_config["avd_headless"] = headless

        auto_start = Confirm.ask(
            "Automatically start AVD when Sandroid needs it?", default=False
        )
        android_config["avd_auto_start"] = auto_start

    return android_config


def _setup_tui_config() -> dict:
    """Run the interactive TUI theme setup wizard.

    Returns:
        Dictionary of TUI-related config keys/values (may be empty).
    """
    console.print()
    console.print("[bold blue]TUI (Terminal User Interface) Settings[/bold blue]")
    console.print()

    # Show available themes
    themes_table = Table(title="Available TUI Themes")
    themes_table.add_column("Index", style="cyan")
    themes_table.add_column("Theme", style="magenta")
    themes_table.add_column("Description", style="dim")

    for i, (name, display, desc) in enumerate(THEME_REGISTRY, 1):
        themes_table.add_row(str(i), display, desc)

    console.print(themes_table)
    console.print()

    theme_choice = Prompt.ask(
        "Choose TUI theme",
        choices=[str(i) for i in range(1, len(THEME_REGISTRY) + 1)],
        default="1",
    )
    selected_theme = THEME_REGISTRY[int(theme_choice) - 1][0]
    tui_config: dict = {"theme": selected_theme}

    console.print(
        f"[green]\u2713[/green] Selected theme: {THEME_REGISTRY[int(theme_choice) - 1][1]}"
    )

    # Ask about custom logo colors (optional)
    if Confirm.ask("Customize logo colors?", default=False):
        logo_color = Prompt.ask("Logo color (hex, e.g., #00ff00)", default="")
        if logo_color:
            tui_config["logo_color"] = logo_color

        logo_text_color = Prompt.ask(
            "'Sandroid' text color (hex, e.g., #ffffff)", default=""
        )
        if logo_text_color:
            tui_config["logo_text_color"] = logo_text_color

    return tui_config


def _setup_mvt_config() -> dict:
    """Run the interactive MVT / IOC setup wizard.

    Returns:
        Dictionary of MVT-related config keys/values (may be empty).
    """
    console.print()
    console.print("[bold blue]MVT (Mobile Verification Toolkit) Settings[/bold blue]")
    console.print()
    console.print(
        "[dim]MVT is a forensic tool for detecting signs of compromise on mobile devices.[/dim]"
    )
    console.print(
        "[dim]It uses STIX2 IOC (Indicators of Compromise) files for detection.[/dim]"
    )
    console.print()

    mvt_config: dict = {}

    if Confirm.ask("Enable MVT forensic evidence scanning?", default=False):
        mvt_config["enabled"] = True

        console.print()
        console.print("[bold]IOC (Indicators of Compromise) Configuration[/bold]")
        console.print()
        console.print("IOC sources:")
        console.print("  1. Local file/directory path")
        console.print("  2. URL to download IOCs (e.g., Amnesty International)")
        console.print("  3. Skip for now (configure later with 'sandroid-config ioc')")
        console.print()

        ioc_choice = Prompt.ask(
            "Choose IOC source", choices=["1", "2", "3"], default="3"
        )

        if ioc_choice == "1":
            ioc_path = Prompt.ask("Path to STIX2 IOC file or directory", default="")
            if ioc_path:
                mvt_config["ioc_path"] = ioc_path
                console.print(f"[green]\u2713[/green] IOC path set: {ioc_path}")

        elif ioc_choice == "2":
            console.print()
            console.print("[dim]Common IOC sources:[/dim]")
            console.print(
                "  \u2022 Amnesty International: https://github.com/AmnestyTech/investigations"
            )
            console.print("  \u2022 Custom URL to a STIX2 JSON file")
            console.print()

            ioc_url = Prompt.ask("URL to STIX2 IOC file", default="")
            if ioc_url:
                mvt_config["ioc_url"] = ioc_url

                auto_update = Confirm.ask(
                    "Automatically update IOCs before each scan?", default=False
                )
                mvt_config["auto_update_iocs"] = auto_update
                console.print("[green]\u2713[/green] IOC URL configured")

        # Ask about scan options
        if mvt_config.get("ioc_path") or mvt_config.get("ioc_url"):
            console.print()
            console.print("[bold]Scan Options[/bold]")

            mvt_config["scan_sms"] = Confirm.ask("Scan SMS messages?", default=True)
            mvt_config["scan_calls"] = Confirm.ask("Scan call logs?", default=True)
            mvt_config["scan_apps"] = Confirm.ask("Scan installed apps?", default=True)
            mvt_config["scan_files"] = Confirm.ask("Scan filesystem?", default=True)
    else:
        console.print(
            "[dim]MVT can be enabled later with 'sandroid-config set mvt.enabled true'[/dim]"
        )

    return mvt_config


def _assemble_and_save_config(
    loader: ConfigLoader,
    android_config: dict,
    tui_config: dict,
    mvt_config: dict,
    config_path: Path | None,
    fmt: str,
) -> Path:
    """Merge sub-configs into a SandroidConfig and persist it.

    Returns:
        The path the configuration was written to.
    """
    base_config = SandroidConfig()
    config_dict = base_config.dict()

    if android_config:
        emulator_dict = config_dict["emulator"]
        emulator_dict.update(android_config)
        config_dict["emulator"] = emulator_dict

    if tui_config:
        tui_dict = config_dict.get("tui", {})
        tui_dict.update(tui_config)
        config_dict["tui"] = tui_dict

    if mvt_config:
        mvt_dict = config_dict.get("mvt", {})
        mvt_dict.update(mvt_config)
        config_dict["mvt"] = mvt_dict

    final_config = SandroidConfig(**config_dict)
    return loader.save_config(final_config, config_path, fmt)


@main.command()
@click.option(
    "--format",
    type=click.Choice(["toml", "yaml", "json"]),
    default="toml",
    help="Configuration file format (default: toml)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file path (defaults to user config directory)",
)
@click.option("--force", is_flag=True, help="Overwrite existing configuration file")
@click.option(
    "--skip-avd-setup",
    is_flag=True,
    help="Skip Android Virtual Device setup during initialization",
)
@click.option(
    "--skip-tui-setup",
    is_flag=True,
    help="Skip TUI theme setup during initialization",
)
@click.option(
    "--skip-mvt-setup",
    is_flag=True,
    help="Skip MVT (Mobile Verification Toolkit) IOC setup during initialization",
)
def init(
    format: str,
    output: str | None,
    force: bool,
    skip_avd_setup: bool,
    skip_tui_setup: bool,
    skip_mvt_setup: bool,
):
    """Initialize a new Sandroid configuration file with Android environment setup."""
    from sandroid.config.android_env import find_emulator_path, find_existing_sdk

    from .avd_commands import _start_avd

    loader = ConfigLoader()

    # Determine output path
    config_path = Path(output) if output else None

    # Check if file exists
    if config_path and config_path.exists() and not force:
        console.print(f"[red]Configuration file already exists: {config_path}")
        console.print("Use --force to overwrite or choose a different path.")
        sys.exit(1)

    console.print("[bold blue]Initializing Sandroid configuration...[/bold blue]")

    try:
        # ---- AVD setup ----
        android_config: dict = {}
        if not skip_avd_setup:
            android_config = _setup_avd_config()

        # ---- TUI setup ----
        tui_config: dict = {}
        if not skip_tui_setup:
            tui_config = _setup_tui_config()

        # ---- MVT setup ----
        mvt_config: dict = {}
        if not skip_mvt_setup:
            mvt_config = _setup_mvt_config()

        # ---- Assemble & save ----
        created_path = _assemble_and_save_config(
            loader, android_config, tui_config, mvt_config, config_path, format
        )

        # ---- Summary ----
        console.print(
            "\n[bold green]\u2713 Configuration created successfully![/bold green]"
        )
        console.print(f"Location: [cyan]{created_path}[/cyan]")

        if android_config.get("selected_avd"):
            console.print(
                f"Configured AVD: [green]{android_config['selected_avd']}[/green]"
            )

        if tui_config.get("theme"):
            theme_display = get_theme_display_name(tui_config["theme"])
            console.print(f"TUI Theme: [green]{theme_display}[/green]")

        if mvt_config.get("enabled"):
            console.print("MVT: [green]Enabled[/green]")
            if mvt_config.get("ioc_path"):
                console.print(f"  IOC Path: [cyan]{mvt_config['ioc_path']}[/cyan]")
            elif mvt_config.get("ioc_url"):
                console.print(f"  IOC URL: [cyan]{mvt_config['ioc_url']}[/cyan]")
            else:
                console.print(
                    "  IOC: [yellow]Not configured (use 'sandroid-config ioc')[/yellow]"
                )

        # Ask if user wants to start the AVD now
        if android_config.get("selected_avd") and Confirm.ask(
            f"\nStart AVD '{android_config['selected_avd']}' now?", default=False
        ):
            android_env = {
                "emulator_path": android_config.get("android_emulator_path")
                or find_emulator_path(),
                "sdk_path": android_config.get("sdk_path") or find_existing_sdk(),
                "avd_home": android_config.get("avd_home"),
            }
            _start_avd(
                android_config["selected_avd"],
                android_config.get("avd_headless", False),
                android_env,
            )

        console.print("\n[bold blue]Next steps:[/bold blue]")
        console.print(
            "\u2022 Use [cyan]sandroid-config show[/cyan] to view your configuration"
        )
        console.print(
            "\u2022 Use [cyan]sandroid-config theme[/cyan] to change TUI theme"
        )
        console.print(
            "\u2022 Use [cyan]sandroid-config avd list[/cyan] to see available AVDs"
        )
        console.print(
            "\u2022 Use [cyan]sandroid-config avd start[/cyan] to start your configured AVD"
        )
        console.print(
            "\u2022 Use [cyan]sandroid-config ioc[/cyan] to manage IOC files for MVT"
        )
        console.print(
            "\u2022 Run [cyan]sandroid -i[/cyan] to start Sandroid in TUI mode"
        )

    except KeyboardInterrupt:
        console.print("\n[yellow]Setup cancelled by user.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Failed to create configuration: {e}[/red]")
        sys.exit(1)


# ---------------------------------------------------------------------------
# show / validate / paths / set / get commands
# ---------------------------------------------------------------------------


@main.command()
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Configuration file path"
)
@click.option("--environment", "-e", help="Environment name")
@click.option(
    "--format",
    type=click.Choice(["rich", "toml", "yaml", "json"]),
    default="rich",
    help="Output format",
)
def show(config: str | None, environment: str | None, format: str):
    """Show current configuration."""
    loader = ConfigLoader()

    try:
        sandroid_config = loader.load(config_file=config, environment=environment)

        if format == "rich":
            _show_config_rich(sandroid_config)
        else:
            _show_config_format(sandroid_config, format)
    except Exception as e:
        console.print(f"[red]Failed to load configuration: {e}")
        sys.exit(1)


@main.command()
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Configuration file path"
)
@click.option("--environment", "-e", help="Environment name")
def validate(config: str | None, environment: str | None):
    """Validate configuration file."""
    loader = ConfigLoader()

    try:
        sandroid_config = loader.load(config_file=config, environment=environment)
        console.print("[green]\u2713 Configuration is valid!")

        # Show summary
        table = Table(title="Configuration Summary")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="magenta")

        table.add_row("Environment", sandroid_config.environment)
        table.add_row("Log Level", sandroid_config.log_level.value)
        table.add_row("Output File", str(sandroid_config.output_file))
        table.add_row("Device Name", sandroid_config.emulator.device_name)
        table.add_row("Results Path", str(sandroid_config.paths.results_path))

        console.print(table)
    except Exception as e:
        console.print(f"[red]\u2717 Configuration validation failed: {e}")
        sys.exit(1)


@main.command()
def paths():
    """Show configuration file search paths."""
    loader = ConfigLoader()

    console.print("[bold]Configuration Search Paths[/bold]\n")

    for i, path in enumerate(loader._config_dirs, 1):
        exists = "\u2713" if path.exists() else "\u2717"
        style = "green" if path.exists() else "dim"
        console.print(f"{i}. [{style}]{exists} {path}[/{style}]")

    console.print("\n[bold]Discovered Configuration Files[/bold]\n")

    if loader._config_files:
        for config_file in loader._config_files:
            console.print(f"\u2022 [green]{config_file}[/green]")
    else:
        console.print("[dim]No configuration files found.[/dim]")

    console.print("\nUse 'sandroid-config init' to create a default configuration.")


@main.command("set")
@click.option(
    "-k",
    "--key",
    required=True,
    help="Configuration key (e.g., emulator.device_name)",
)
@click.option("-v", "--value", required=True, help="Value to set")
@click.option("--config", "-c", type=click.Path(), help="Configuration file path")
@click.option(
    "--format",
    type=click.Choice(["toml", "yaml", "json"]),
    default="toml",
    help="Configuration file format (default: toml)",
)
def set_config(key: str, value: str, config: str | None, format: str):
    """Set a configuration value.

    Example: sandroid-config set -k emulator.device_name -v Pixel_6
    """
    loader = ConfigLoader()

    try:
        # Load existing config or create default
        try:
            current_config = loader.load(config_file=config)
        except FileNotFoundError:
            current_config = SandroidConfig()

        # Parse the key path (e.g., "emulator.device_name")
        keys = key.split(".")
        config_dict = current_config.dict()

        # Navigate to the nested location
        current = config_dict
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]

        # Parse value
        parsed_value = _parse_value(value)
        current[keys[-1]] = parsed_value

        # Validate the updated configuration
        updated_config = SandroidConfig(**config_dict)

        # Save the configuration
        saved_path = loader.save_config(updated_config, config, format)

        console.print(f"[green]\u2713 Updated {key} = {parsed_value}")
        console.print(f"Configuration saved to: {saved_path}")
    except Exception as e:
        console.print(f"[red]Failed to update configuration: {e}")
        sys.exit(1)


@main.command("get")
@click.option(
    "-k",
    "--key",
    required=True,
    help="Configuration key (e.g., emulator.device_name)",
)
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Configuration file path"
)
@click.option("--environment", "-e", help="Environment name")
def get_config(key: str, config: str | None, environment: str | None):
    """Get a configuration value.

    Example: sandroid-config get -k emulator.device_name
    """
    loader = ConfigLoader()

    try:
        sandroid_config = loader.load(config_file=config, environment=environment)

        # Parse the key path
        keys = key.split(".")
        config_dict = sandroid_config.dict()

        # Navigate to the value
        current = config_dict
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                console.print(f"[red]Configuration key not found: {key}")
                sys.exit(1)

        console.print(f"{key} = {current}")
    except Exception as e:
        console.print(f"[red]Failed to get configuration value: {e}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Module entry-point guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()


# Public API -- keep ``from sandroid.config.cli import main`` working.
__all__ = ["main", "sandroid_config"]
