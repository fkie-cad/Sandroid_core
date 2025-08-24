"""Configuration management CLI for Sandroid."""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from .loader import ConfigLoader
from .schema import SandroidConfig

console = Console()


@click.group()
@click.version_option()
def main():
    """Sandroid configuration management."""


@main.command()
@click.option(
    "--format",
    type=click.Choice(["yaml", "toml", "json"]),
    default="yaml",
    help="Configuration file format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file path (defaults to user config directory)",
)
@click.option("--force", is_flag=True, help="Overwrite existing configuration file")
def init(format: str, output: str | None, force: bool):
    """Initialize a new Sandroid configuration file."""
    loader = ConfigLoader()

    # Determine output path
    if output:
        config_path = Path(output)
    else:
        config_path = None

    # Check if file exists
    if config_path and config_path.exists() and not force:
        console.print(f"[red]Configuration file already exists: {config_path}")
        console.print("Use --force to overwrite or choose a different path.")
        sys.exit(1)

    try:
        created_path = loader.create_default_config(config_path)
        console.print(f"[green]✓ Created default configuration: {created_path}")
        console.print("\nEdit this file to customize your Sandroid settings.")
        console.print("Use 'sandroid-config show' to view the current configuration.")
    except Exception as e:
        console.print(f"[red]Failed to create configuration: {e}")
        sys.exit(1)


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
        elif format == "toml":
            _show_config_format(sandroid_config, "toml")
        elif format == "yaml":
            _show_config_format(sandroid_config, "yaml")
        elif format == "json":
            _show_config_format(sandroid_config, "json")
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
        console.print("[green]✓ Configuration is valid!")

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
        console.print(f"[red]✗ Configuration validation failed: {e}")
        sys.exit(1)


@main.command()
def paths():
    """Show configuration file search paths."""
    loader = ConfigLoader()

    console.print("[bold]Configuration Search Paths[/bold]\n")

    for i, path in enumerate(loader._config_dirs, 1):
        exists = "✓" if path.exists() else "✗"
        style = "green" if path.exists() else "dim"
        console.print(f"{i}. [{style}]{exists} {path}[/{style}]")

    console.print("\n[bold]Discovered Configuration Files[/bold]\n")

    if loader._config_files:
        for config_file in loader._config_files:
            console.print(f"• [green]{config_file}[/green]")
    else:
        console.print("[dim]No configuration files found.[/dim]")

    console.print("\nUse 'sandroid-config init' to create a default configuration.")


@main.command()
@click.argument("key")
@click.argument("value")
@click.option("--config", "-c", type=click.Path(), help="Configuration file path")
@click.option(
    "--format",
    type=click.Choice(["yaml", "toml", "json"]),
    default="yaml",
    help="Configuration file format",
)
def set(key: str, value: str, config: str | None, format: str):
    """Set a configuration value."""
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

        console.print(f"[green]✓ Updated {key} = {parsed_value}")
        console.print(f"Configuration saved to: {saved_path}")
    except Exception as e:
        console.print(f"[red]Failed to update configuration: {e}")
        sys.exit(1)


@main.command()
@click.argument("key")
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Configuration file path"
)
@click.option("--environment", "-e", help="Environment name")
def get(key: str, config: str | None, environment: str | None):
    """Get a configuration value."""
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


def _show_config_rich(config: SandroidConfig):
    """Show configuration using rich formatting."""
    console.print("[bold blue]Sandroid Configuration[/bold blue]\n")

    # Core Settings
    table = Table(title="Core Settings")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Environment", config.environment)
    table.add_row("Log Level", config.log_level.value)
    table.add_row("Output File", str(config.output_file))
    if config.whitelist_file:
        table.add_row("Whitelist File", str(config.whitelist_file))

    console.print(table)

    # Emulator Settings
    table = Table(title="Emulator Settings")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Device Name", config.emulator.device_name)
    table.add_row("Emulator Path", str(config.emulator.android_emulator_path))
    if config.emulator.sdk_path:
        table.add_row("SDK Path", str(config.emulator.sdk_path))
    if config.emulator.adb_path:
        table.add_row("ADB Path", str(config.emulator.adb_path))

    console.print(table)

    # Analysis Settings
    table = Table(title="Analysis Settings")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Number of Runs", str(config.analysis.number_of_runs))
    table.add_row(
        "Strong Noise Filter", str(not config.analysis.avoid_strong_noise_filter)
    )
    table.add_row("Monitor Processes", str(config.analysis.monitor_processes))
    table.add_row("Monitor Sockets", str(config.analysis.monitor_sockets))
    table.add_row("Monitor Network", str(config.analysis.monitor_network))
    table.add_row("Show Deleted Files", str(config.analysis.show_deleted_files))
    table.add_row("Hash Files", str(config.analysis.hash_files))
    table.add_row("List APKs", str(config.analysis.list_apks))
    if config.analysis.screenshot_interval:
        table.add_row("Screenshot Interval", f"{config.analysis.screenshot_interval}s")

    console.print(table)


def _show_config_format(config: SandroidConfig, format: str):
    """Show configuration in specified format with syntax highlighting."""
    loader = ConfigLoader()

    # Create temporary file to get formatted output
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=f".{format}", delete=False) as f:
        temp_path = Path(f.name)

    try:
        saved_path = loader.save_config(config, temp_path, format)
        with open(saved_path) as f:
            content = f.read()

        syntax = Syntax(content, format, theme="monokai", line_numbers=True)
        console.print(syntax)
    finally:
        temp_path.unlink(missing_ok=True)


def _parse_value(value: str):
    """Parse string value to appropriate type."""
    # Boolean values
    if value.lower() in ("true", "yes", "1", "on"):
        return True
    if value.lower() in ("false", "no", "0", "off"):
        return False

    # Numeric values
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        pass

    return value


if __name__ == "__main__":
    main()
