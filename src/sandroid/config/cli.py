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
@click.option(
    "--skip-avd-setup",
    is_flag=True,
    help="Skip Android Virtual Device setup during initialization",
)
def init(format: str, output: str | None, force: bool, skip_avd_setup: bool):
    """Initialize a new Sandroid configuration file with Android environment setup."""
    from rich.prompt import Confirm

    from .android_env import setup_android_environment

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

    # Create base configuration
    console.print("[bold blue]🔧 Initializing Sandroid configuration...[/bold blue]")

    try:
        # Set up Android environment if not skipped
        android_config = {}

        if not skip_avd_setup:
            console.print()
            android_env = setup_android_environment(skip_setup=False)

            # Convert environment detection results to configuration
            if android_env.get("sdk_path"):
                android_config["sdk_path"] = str(android_env["sdk_path"])

            if android_env.get("adb_path"):
                android_config["adb_path"] = str(android_env["adb_path"])

            if android_env.get("emulator_path"):
                android_config["android_emulator_path"] = str(
                    android_env["emulator_path"]
                )

            if android_env.get("avd_home"):
                android_config["avd_home"] = str(android_env["avd_home"])

            if android_env.get("selected_avd"):
                android_config["selected_avd"] = android_env["selected_avd"]
                android_config["device_name"] = android_env[
                    "selected_avd"
                ]  # Update device_name too

                # Ask about headless mode
                if android_env.get("selected_avd"):
                    headless = not Confirm.ask(
                        f"Start AVD '{android_env['selected_avd']}' with UI by default?",
                        default=True,
                    )
                    android_config["avd_headless"] = headless

                    # Ask about auto-start
                    auto_start = Confirm.ask(
                        "Automatically start AVD when Sandroid needs it?", default=False
                    )
                    android_config["avd_auto_start"] = auto_start

        # Create configuration with Android settings
        base_config = SandroidConfig()

        if android_config:
            # Update emulator config with detected/configured values
            emulator_dict = base_config.emulator.dict()
            emulator_dict.update(android_config)

            # Create new config with updated emulator settings
            config_dict = base_config.dict()
            config_dict["emulator"] = emulator_dict
            base_config = SandroidConfig(**config_dict)

        # Save the configuration
        created_path = loader.save_config(base_config, config_path, format)

        console.print(
            "\n[bold green]✅ Configuration created successfully![/bold green]"
        )
        console.print(f"📍 Location: [cyan]{created_path}[/cyan]")

        if android_config.get("selected_avd"):
            console.print(
                f"📱 Configured AVD: [green]{android_config['selected_avd']}[/green]"
            )

            # Ask if user wants to start the AVD now
            if Confirm.ask(
                f"\n🚀 Start AVD '{android_config['selected_avd']}' now?", default=False
            ):
                _start_avd(
                    android_config["selected_avd"],
                    android_config.get("avd_headless", False),
                    android_env,
                )

        console.print("\n[bold blue]Next steps:[/bold blue]")
        console.print(
            "• Use [cyan]sandroid-config show[/cyan] to view your configuration"
        )
        console.print(
            "• Use [cyan]sandroid-config avd list[/cyan] to see available AVDs"
        )
        console.print(
            "• Use [cyan]sandroid-config avd start[/cyan] to start your configured AVD"
        )
        console.print("• Run [cyan]sandroid[/cyan] to begin Android forensic analysis")

    except KeyboardInterrupt:
        console.print("\n[yellow]Setup cancelled by user.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Failed to create configuration: {e}[/red]")
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
    if config.emulator.avd_home:
        table.add_row("AVD Home", str(config.emulator.avd_home))
    if config.emulator.selected_avd:
        table.add_row("Selected AVD", config.emulator.selected_avd)
    table.add_row("AVD Headless", str(config.emulator.avd_headless))
    table.add_row("AVD Auto-Start", str(config.emulator.avd_auto_start))

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


# ============ AVD Management Commands ============


@main.group()
def avd():
    """Android Virtual Device management commands."""


@avd.command("list")
def avd_list():
    """List available Android Virtual Devices."""
    from .android_env import find_emulator_path, find_existing_sdk, list_available_avds

    console.print("[bold blue]📱 Available Android Virtual Devices[/bold blue]")

    try:
        emulator_path = find_emulator_path()
        sdk_path = find_existing_sdk()

        if not emulator_path:
            console.print("[red]❌ Android emulator not found in PATH or SDK[/red]")
            console.print("Use 'sandroid-config init' to configure Android environment")
            return

        avds = list_available_avds(emulator_path, sdk_path)

        if not avds:
            console.print("[yellow]⚠️  No AVDs found[/yellow]")
            console.print("Create one with: [cyan]sandroid-config avd create[/cyan]")
            return

        # Show AVDs in table
        table = Table(title=f"Found {len(avds)} AVDs")
        table.add_column("AVD Name", style="cyan")
        table.add_column("Status", style="magenta")

        for avd in avds:
            status = "Available"  # Could be enhanced to check if running
            table.add_row(avd, status)

        console.print(table)

        # Show current configuration
        try:
            loader = ConfigLoader()
            config = loader.load()
            if config.emulator.selected_avd:
                console.print(
                    f"\n[bold green]Current Sandroid AVD:[/bold green] {config.emulator.selected_avd}"
                )
            else:
                console.print("\n[yellow]No AVD configured for Sandroid[/yellow]")
                console.print(
                    "Configure with: [cyan]sandroid-config set emulator.selected_avd AVD_NAME[/cyan]"
                )
        except Exception:
            pass

    except Exception as e:
        console.print(f"[red]Error listing AVDs: {e}[/red]")


@avd.command("start")
@click.option("--headless", is_flag=True, help="Start AVD in headless mode (no UI)")
@click.option("--avd-name", help="Specific AVD name to start (overrides config)")
def avd_start(headless: bool, avd_name: str | None):
    """Start the configured Android Virtual Device."""
    try:
        loader = ConfigLoader()
        config = loader.load()

        # Determine which AVD to start
        target_avd = avd_name or config.emulator.selected_avd

        if not target_avd:
            console.print("[red]❌ No AVD specified[/red]")
            console.print(
                "Either configure one with 'sandroid-config init' or specify --avd-name"
            )
            return

        # Use headless from config if not overridden
        use_headless = headless or config.emulator.avd_headless

        console.print(f"[bold blue]🚀 Starting AVD '{target_avd}'...[/bold blue]")

        android_env = {
            "emulator_path": config.emulator.android_emulator_path,
            "sdk_path": config.emulator.sdk_path,
            "avd_home": config.emulator.avd_home,
        }

        success = _start_avd(target_avd, use_headless, android_env)

        if success:
            console.print(f"[green]✅ AVD '{target_avd}' started successfully[/green]")
            console.print("\n[bold blue]Next steps:[/bold blue]")
            console.print("• Check device with: [cyan]adb devices[/cyan]")
            console.print("• Run Sandroid analysis: [cyan]sandroid[/cyan]")
        else:
            console.print(f"[red]❌ Failed to start AVD '{target_avd}'[/red]")

    except Exception as e:
        console.print(f"[red]Error starting AVD: {e}[/red]")


@avd.command("stop")
@click.option("--avd-name", help="Specific AVD name to stop")
def avd_stop(avd_name: str | None):
    """Stop running Android Virtual Devices."""
    import shutil

    from .android_env import run_cmd

    try:
        # Find adb
        adb_path = shutil.which("adb")
        if not adb_path:
            loader = ConfigLoader()
            config = loader.load()
            if config.emulator.adb_path:
                adb_path = str(config.emulator.adb_path)

        if not adb_path:
            console.print("[red]❌ ADB not found[/red]")
            return

        console.print("[bold blue]🛑 Stopping AVDs...[/bold blue]")

        # Get running devices
        code, stdout, stderr = run_cmd([adb_path, "devices"])
        if code != 0:
            console.print(f"[red]Error getting device list: {stderr}[/red]")
            return

        # Kill emulator processes
        import os

        if os.name == "nt":  # Windows
            code, _, _ = run_cmd(["taskkill", "/f", "/im", "emulator.exe"])
        else:  # Unix-like
            code, _, _ = run_cmd(["pkill", "-f", "emulator"])

        if code == 0:
            console.print("[green]✅ Stopped running AVDs[/green]")
        else:
            console.print("[yellow]⚠️  No running AVDs found to stop[/yellow]")

    except Exception as e:
        console.print(f"[red]Error stopping AVDs: {e}[/red]")


@avd.command("create")
@click.option("--name", default="sandroid", help="AVD name to create")
@click.option("--api-level", default="34", help="Android API level")
@click.option("--force", is_flag=True, help="Recreate AVD if it already exists")
def avd_create(name: str, api_level: str, force: bool):
    """Create a new Android Virtual Device."""
    console.print(f"[bold blue]📱 Creating AVD '{name}' (API {api_level})[/bold blue]")
    console.print("[yellow]⚠️  AVD creation requires a full Android SDK setup.[/yellow]")
    console.print(
        "This is a complex process that may require downloading system images."
    )
    console.print("Consider using the existing create_avd.py script for full setup:")
    console.print("  [cyan]python deploy/create_avd.py[/cyan]")


# ============ Helper Functions ============


def _start_avd(avd_name: str, headless: bool, android_env: dict) -> bool:
    """Start an Android Virtual Device.

    Args:
        avd_name: Name of AVD to start
        headless: Whether to start in headless mode
        android_env: Dictionary with Android environment paths

    Returns:
        True if AVD started successfully
    """
    import os
    import subprocess

    from .android_env import run_cmd

    try:
        emulator_path = android_env.get("emulator_path")
        if not emulator_path:
            console.print("[red]Emulator path not configured[/red]")
            return False

        # Build command
        cmd = [str(emulator_path), "-avd", avd_name]

        if headless:
            cmd.extend(["-no-window", "-no-boot-anim", "-gpu", "swiftshader_indirect"])

        # Set up environment
        env = os.environ.copy()
        if android_env.get("sdk_path"):
            env["ANDROID_SDK_ROOT"] = str(android_env["sdk_path"])
            env["ANDROID_HOME"] = str(android_env["sdk_path"])
        if android_env.get("avd_home"):
            env["ANDROID_AVD_HOME"] = str(android_env["avd_home"])

        console.print(f"[dim]Command: {' '.join(cmd)}[/dim]")

        # Start emulator in background
        process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        console.print(f"[green]✓[/green] AVD '{avd_name}' starting in background...")
        console.print(f"[dim]Process ID: {process.pid}[/dim]")

        if headless:
            console.print("[dim]Running in headless mode (no UI)[/dim]")
        else:
            console.print("[dim]Running with UI[/dim]")

        return True

    except Exception as e:
        console.print(f"[red]Failed to start AVD: {e}[/red]")
        return False


if __name__ == "__main__":
    main()
