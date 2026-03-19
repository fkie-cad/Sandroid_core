"""IOC (Indicators of Compromise) management CLI commands for Sandroid.

Provides the ``ioc`` Click group with subcommands:
- ``show``     -- show current IOC configuration
- ``set-path`` -- set IOC file/directory path
- ``set-url``  -- set IOC download URL
- ``download`` -- download IOC files from configured URL
- ``validate`` -- validate configured IOC files
"""

import sys
from pathlib import Path

import click
from rich.table import Table

from sandroid.config.loader import ConfigLoader
from sandroid.config.schema import SandroidConfig

from .helpers import _detect_and_save_config, console


@click.group()
def ioc():
    """IOC (Indicators of Compromise) management for MVT forensic scanning."""


@ioc.command("show")
def ioc_show():
    """Show current IOC configuration."""
    try:
        loader = ConfigLoader()
        config = loader.load()

        console.print("[bold blue]MVT IOC Configuration[/bold blue]\n")

        table = Table()
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="magenta")

        table.add_row("MVT Enabled", str(config.mvt.enabled))

        if config.mvt.ioc_path:
            path_exists = Path(config.mvt.ioc_path).exists()
            status = (
                "[green]\u2713 exists[/green]"
                if path_exists
                else "[red]\u2717 not found[/red]"
            )
            table.add_row("IOC Path", f"{config.mvt.ioc_path} {status}")
        else:
            table.add_row("IOC Path", "[dim]Not configured[/dim]")

        if config.mvt.ioc_url:
            table.add_row("IOC URL", str(config.mvt.ioc_url))
        else:
            table.add_row("IOC URL", "[dim]Not configured[/dim]")

        table.add_row("Auto-update IOCs", str(config.mvt.auto_update_iocs))
        table.add_row("Scan SMS", str(config.mvt.scan_sms))
        table.add_row("Scan Calls", str(config.mvt.scan_calls))
        table.add_row("Scan Apps", str(config.mvt.scan_apps))
        table.add_row("Scan Files", str(config.mvt.scan_files))
        table.add_row("Output Format", config.mvt.output_format)

        console.print(table)

        if not config.mvt.enabled:
            console.print("\n[yellow]MVT is disabled.[/yellow]")
            console.print(
                "Enable with: [cyan]sandroid-config set mvt.enabled true[/cyan]"
            )

        if not config.mvt.ioc_path and not config.mvt.ioc_url:
            console.print("\n[yellow]No IOC source configured.[/yellow]")
            console.print(
                "Configure with: [cyan]sandroid-config ioc set-path <path>[/cyan]"
            )
            console.print(
                "            or: [cyan]sandroid-config ioc set-url <url>[/cyan]"
            )

    except Exception as e:
        console.print(f"[red]Failed to load configuration: {e}[/red]")
        sys.exit(1)


@ioc.command("set-path")
@click.argument("path")
def ioc_set_path(path: str):
    """Set IOC file or directory path.

    PATH: Path to STIX2 IOC file or directory containing IOC files.
    """
    from rich.prompt import Confirm

    loader = ConfigLoader()

    try:
        # Expand and validate path
        ioc_path = Path(path).expanduser()

        if not ioc_path.exists():
            console.print(f"[yellow]Warning: Path does not exist: {ioc_path}[/yellow]")
            if not Confirm.ask("Set path anyway?", default=False):
                return

        # Load existing config
        try:
            current_config = loader.load()
        except FileNotFoundError:
            current_config = SandroidConfig()

        # Update MVT config
        config_dict = current_config.dict()
        if "mvt" not in config_dict:
            config_dict["mvt"] = {}
        config_dict["mvt"]["ioc_path"] = str(ioc_path)
        config_dict["mvt"]["enabled"] = True  # Auto-enable when setting IOC path

        # Validate and save
        updated_config = SandroidConfig(**config_dict)
        saved_path = _detect_and_save_config(loader, updated_config)

        console.print(f"[green]\u2713[/green] IOC path set: [cyan]{ioc_path}[/cyan]")
        console.print("[green]\u2713[/green] MVT enabled")
        console.print(f"[dim]Configuration saved to: {saved_path}[/dim]")

    except Exception as e:
        console.print(f"[red]Failed to set IOC path: {e}[/red]")
        sys.exit(1)


@ioc.command("set-url")
@click.argument("url")
@click.option(
    "--auto-update", is_flag=True, help="Automatically update IOCs before scanning"
)
def ioc_set_url(url: str, auto_update: bool):
    """Set IOC download URL.

    URL: URL to STIX2 IOC file (e.g., from Amnesty International).
    """
    loader = ConfigLoader()

    try:
        # Validate URL format
        if not url.startswith(("http://", "https://")):
            console.print("[red]URL must start with http:// or https://[/red]")
            sys.exit(1)

        # Load existing config
        try:
            current_config = loader.load()
        except FileNotFoundError:
            current_config = SandroidConfig()

        # Update MVT config
        config_dict = current_config.dict()
        if "mvt" not in config_dict:
            config_dict["mvt"] = {}
        config_dict["mvt"]["ioc_url"] = url
        config_dict["mvt"]["auto_update_iocs"] = auto_update
        config_dict["mvt"]["enabled"] = True  # Auto-enable when setting IOC URL

        # Validate and save
        updated_config = SandroidConfig(**config_dict)
        saved_path = _detect_and_save_config(loader, updated_config)

        console.print(f"[green]\u2713[/green] IOC URL set: [cyan]{url}[/cyan]")
        if auto_update:
            console.print("[green]\u2713[/green] Auto-update enabled")
        console.print("[green]\u2713[/green] MVT enabled")
        console.print(f"[dim]Configuration saved to: {saved_path}[/dim]")

    except Exception as e:
        console.print(f"[red]Failed to set IOC URL: {e}[/red]")
        sys.exit(1)


@ioc.command("download")
@click.option(
    "--output", "-o", type=click.Path(), help="Output directory for IOC files"
)
def ioc_download(output: str | None):
    """Download IOC files from configured URL."""
    import json
    import urllib.request

    loader = ConfigLoader()

    try:
        config = loader.load()

        if not config.mvt.ioc_url:
            console.print("[red]No IOC URL configured.[/red]")
            console.print(
                "Set one with: [cyan]sandroid-config ioc set-url <url>[/cyan]"
            )
            sys.exit(1)

        # Determine output path
        if output:
            output_path = Path(output).expanduser()
        else:
            output_path = config.paths.cache_path / "ioc"

        output_path.mkdir(parents=True, exist_ok=True)

        console.print(
            f"[bold blue]Downloading IOCs from {config.mvt.ioc_url}...[/bold blue]"
        )

        try:
            # Download IOC file
            with urllib.request.urlopen(config.mvt.ioc_url, timeout=30) as response:  # nosec B310
                content = response.read()

            # Determine filename
            filename = "indicators.json"
            if "/" in config.mvt.ioc_url:
                url_filename = config.mvt.ioc_url.split("/")[-1]
                if url_filename.endswith(".json"):
                    filename = url_filename

            output_file = output_path / filename

            # Validate JSON
            try:
                json.loads(content)
            except json.JSONDecodeError:
                console.print(
                    "[yellow]Warning: Downloaded content is not valid JSON[/yellow]"
                )

            # Save file
            with open(output_file, "wb") as f:
                f.write(content)

            console.print(
                f"[green]\u2713[/green] Downloaded IOC file: [cyan]{output_file}[/cyan]"
            )
            console.print(f"[dim]Size: {len(content)} bytes[/dim]")

            # Update config to use downloaded file
            config_dict = config.dict()
            config_dict["mvt"]["ioc_path"] = str(output_file)

            updated_config = SandroidConfig(**config_dict)
            _detect_and_save_config(loader, updated_config)

            console.print("[green]\u2713[/green] IOC path updated in configuration")

        except urllib.error.URLError as e:
            console.print(f"[red]Failed to download IOCs: {e}[/red]")
            sys.exit(1)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@ioc.command("validate")
def ioc_validate():
    """Validate configured IOC file(s)."""
    import json

    loader = ConfigLoader()

    try:
        config = loader.load()

        if not config.mvt.ioc_path:
            console.print("[yellow]No IOC path configured.[/yellow]")
            console.print(
                "Set one with: [cyan]sandroid-config ioc set-path <path>[/cyan]"
            )
            return

        ioc_path = Path(config.mvt.ioc_path)

        if not ioc_path.exists():
            console.print(f"[red]IOC path does not exist: {ioc_path}[/red]")
            sys.exit(1)

        console.print(f"[bold blue]Validating IOC files at {ioc_path}...[/bold blue]")

        # Get list of files to validate
        if ioc_path.is_file():
            files = [ioc_path]
        else:
            files = list(ioc_path.glob("*.json"))

        if not files:
            console.print("[yellow]No JSON files found.[/yellow]")
            return

        valid_count = 0
        invalid_count = 0

        for f in files:
            try:
                with open(f) as fp:
                    data = json.load(fp)

                # Basic STIX2 validation
                if isinstance(data, dict):
                    if "type" in data or "objects" in data:
                        console.print(f"[green]\u2713[/green] {f.name} - Valid STIX2")
                        valid_count += 1
                    else:
                        console.print(
                            f"[yellow]?[/yellow] {f.name} - Valid JSON but not STIX2"
                        )
                        invalid_count += 1
                elif isinstance(data, list):
                    console.print(
                        f"[green]\u2713[/green] {f.name} - Valid JSON array ({len(data)} items)"
                    )
                    valid_count += 1
                else:
                    console.print(
                        f"[yellow]?[/yellow] {f.name} - Unexpected JSON structure"
                    )
                    invalid_count += 1

            except json.JSONDecodeError as e:
                console.print(f"[red]\u2717[/red] {f.name} - Invalid JSON: {e}")
                invalid_count += 1
            except Exception as e:
                console.print(f"[red]\u2717[/red] {f.name} - Error: {e}")
                invalid_count += 1

        console.print()
        console.print(
            f"Valid: [green]{valid_count}[/green], Invalid: [red]{invalid_count}[/red]"
        )

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
