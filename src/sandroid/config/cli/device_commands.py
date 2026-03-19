"""Device listing CLI command for Sandroid.

Provides the ``devices`` command that lists all connected Android
devices and emulators via ADB / DeviceManager.
"""

import click
from rich.table import Table

from .helpers import console


@click.command("devices")
def devices_list():
    """List all connected Android devices and emulators."""
    from sandroid.core.device_manager import DeviceManager

    console.print("[bold blue]Connected Android Devices[/bold blue]")

    try:
        dm = DeviceManager.get()
        devices = dm.refresh_devices()

        if not devices:
            console.print("[yellow]! No devices connected[/yellow]")
            console.print("Start an emulator: [cyan]sandroid-config avd start[/cyan]")
            console.print("Or connect a physical device via USB/ADB")
            return

        # Count device types
        emulators = [d for d in devices if d.is_emulator]
        physical = [d for d in devices if d.is_physical]

        title = f"Found {len(devices)} device(s)"
        if emulators and physical:
            title += f" ({len(emulators)} emulator(s), {len(physical)} physical)"
        elif emulators:
            title += f" ({len(emulators)} emulator(s))"
        elif physical:
            title += f" ({len(physical)} physical)"

        table = Table(title=title)
        table.add_column("Serial", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Type", style="yellow")
        table.add_column("Android", style="dim")
        table.add_column("API", style="dim")
        table.add_column("State", style="magenta")

        for device in devices:
            type_style = (
                "[blue]Emulator[/blue]"
                if device.is_emulator
                else "[magenta]Physical[/magenta]"
            )

            # Format state with color
            state_styles = {
                "device": "[green]online[/green]",
                "offline": "[red]offline[/red]",
                "unauthorized": "[yellow]unauthorized[/yellow]",
            }
            state_display = state_styles.get(device.state, f"[dim]{device.state}[/dim]")

            table.add_row(
                device.serial,
                device.name or "[dim]unknown[/dim]",
                type_style,
                device.android_version or "[dim]?[/dim]",
                str(device.api_level) if device.api_level else "[dim]?[/dim]",
                state_display,
            )

        console.print(table)

        # Show active device if set
        active = dm.active_device
        if active:
            console.print(f"\n[bold green]Active device:[/bold green] {active.serial}")
            if active.name:
                console.print(f"[dim]Name: {active.name}[/dim]")

    except Exception as e:
        console.print(f"[red]Error listing devices: {e}[/red]")
        console.print("[dim]Make sure ADB is running and in PATH[/dim]")
