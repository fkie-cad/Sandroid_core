"""AVD (Android Virtual Device) management CLI commands for Sandroid.

Provides the ``avd`` Click group with subcommands:
- ``list``   -- list available AVDs
- ``rename`` -- rename an existing AVD
- ``start``  -- start an AVD (interactive or direct)
- ``stop``   -- stop running AVDs
- ``create`` -- create a new AVD (stub)
"""

import logging
from pathlib import Path

import click
from rich.prompt import Confirm, Prompt
from rich.table import Table

from sandroid.config.loader import ConfigLoader
from sandroid.config.schema import SandroidConfig

from .helpers import console

# ---------------------------------------------------------------------------
# Click group
# ---------------------------------------------------------------------------


@click.group()
def avd():
    """Android Virtual Device management commands."""


# ---------------------------------------------------------------------------
# avd list
# ---------------------------------------------------------------------------


@avd.command("list")
def avd_list():
    """List available Android Virtual Devices."""
    from sandroid.config.android_env import (
        find_emulator_path,
        find_existing_sdk,
        get_avd_info,
        list_available_avds,
    )

    console.print("[bold blue]Available Android Virtual Devices[/bold blue]")

    try:
        emulator_path = find_emulator_path()
        sdk_path = find_existing_sdk()

        if not emulator_path:
            console.print("[red]\u2717 Android emulator not found in PATH or SDK[/red]")
            console.print("Use 'sandroid-config init' to configure Android environment")
            return

        avds = list_available_avds(emulator_path, sdk_path)

        if not avds:
            console.print("[yellow]! No AVDs found[/yellow]")
            console.print("Create one with: [cyan]sandroid-config avd create[/cyan]")
            return

        # Get running emulators to check which AVDs are active
        running_avd_names: set[str] = set()
        try:
            from sandroid.core.device_manager import DeviceManager

            dm = DeviceManager.get()
            dm.refresh_devices()
            running_emulators = dm.get_emulators()
            running_avd_names = {e.name for e in running_emulators if e.name}
        except Exception:
            pass

        # Show AVDs in table with Android version
        table = Table(title=f"Found {len(avds)} AVDs")
        table.add_column("AVD Name", style="cyan")
        table.add_column("Android", style="green")
        table.add_column("API", style="yellow")
        table.add_column("Device", style="dim")
        table.add_column("Running", justify="center")
        table.add_column("Status", style="magenta")

        for avd_item in avds:
            info = get_avd_info(avd_item)
            is_running = avd_item in running_avd_names
            running_indicator = (
                "[green]\u2713[/green]" if is_running else "[dim]\u2717[/dim]"
            )
            status = "Running" if is_running else "Available"
            table.add_row(
                avd_item,
                info["android_version"],
                info["api_level"],
                info["device_name"],
                running_indicator,
                status,
            )

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
        except Exception as e:
            logging.debug(f"Failed to load config for AVD display: {e}")

    except Exception as e:
        console.print(f"[red]Error listing AVDs: {e}[/red]")


# ---------------------------------------------------------------------------
# avd rename
# ---------------------------------------------------------------------------


@avd.command("rename")
def avd_rename():
    """Rename an Android Virtual Device."""
    from sandroid.config.android_env import (
        find_emulator_path,
        find_existing_sdk,
        get_avd_info,
        list_available_avds,
        rename_avd,
    )

    console.print("[bold blue]Rename Android Virtual Device[/bold blue]\n")

    try:
        emulator_path = find_emulator_path()
        sdk_path = find_existing_sdk()

        if not emulator_path:
            console.print("[red]\u2717 Android emulator not found[/red]")
            return

        avds = list_available_avds(emulator_path, sdk_path)

        if not avds:
            console.print("[yellow]No AVDs found to rename[/yellow]")
            return

        # Show available AVDs with numbers
        console.print("[cyan]Available AVDs:[/cyan]")
        for i, avd_name in enumerate(avds, 1):
            info = get_avd_info(avd_name)
            console.print(f"  [{i}] {avd_name} (Android {info['android_version']})")

        console.print()

        # Ask which AVD to rename
        choice = Prompt.ask(
            "Select AVD to rename (number or name)",
            default="",
        )

        if not choice:
            console.print("[yellow]Cancelled[/yellow]")
            return

        # Resolve selection
        selected_avd = None
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(avds):
                selected_avd = avds[idx]
        elif choice in avds:
            selected_avd = choice

        if not selected_avd:
            console.print(f"[red]Invalid selection: {choice}[/red]")
            return

        console.print(f"\nSelected: [cyan]{selected_avd}[/cyan]")

        # Ask for new name
        new_name = Prompt.ask("Enter new name for the AVD")

        if not new_name:
            console.print("[yellow]Cancelled[/yellow]")
            return

        new_name = new_name.strip()

        # Check if new name already exists
        if new_name in avds:
            console.print(f"[red]\u2717 AVD '{new_name}' already exists[/red]")
            return

        # Confirm rename
        if not Confirm.ask(f"Rename '{selected_avd}' to '{new_name}'?"):
            console.print("[yellow]Cancelled[/yellow]")
            return

        # Perform rename
        console.print("\n[dim]Renaming AVD...[/dim]")
        success, message = rename_avd(selected_avd, new_name)

        if success:
            console.print(f"[green]\u2713 {message}[/green]")

            # Check if this was the configured AVD and offer to update config
            try:
                loader = ConfigLoader()
                config = loader.load()
                if config.emulator.selected_avd == selected_avd:
                    if Confirm.ask(f"\nUpdate Sandroid config to use '{new_name}'?"):
                        _, _saved_path = loader.load_and_update_section(
                            "emulator", {"selected_avd": new_name}
                        )
                        console.print(
                            f"[green]\u2713 Config updated to use '{new_name}'[/green]"
                        )
            except Exception:
                pass  # Config update is optional
        else:
            console.print(f"[red]\u2717 {message}[/red]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


# ---------------------------------------------------------------------------
# avd start
# ---------------------------------------------------------------------------


@avd.command("start")
@click.option("--headless", is_flag=True, help="Start AVD in headless mode (no UI)")
@click.option("--avd-name", help="Specific AVD name to start (skips interactive menu)")
@click.option(
    "--use-config", is_flag=True, help="Use configured AVD without interactive menu"
)
@click.option(
    "--boot-mode",
    type=click.Choice(["default", "cold", "snapshot", "wipe"]),
    default=None,
    help="Boot mode: default (last snapshot), cold (no snapshot), snapshot (specific), wipe (factory reset)",
)
@click.option(
    "--snapshot",
    "snapshot_name",
    help="Snapshot name to load (requires --boot-mode=snapshot)",
)
def avd_start(
    headless: bool,
    avd_name: str | None,
    use_config: bool,
    boot_mode: str | None,
    snapshot_name: str | None,
):
    """Start an Android Virtual Device.

    By default, shows an interactive menu to select which AVD to start.
    Use --avd-name to start a specific AVD directly.
    Use --use-config to start the configured default AVD without menu.

    Boot modes:

      default  - Boot with the last saved snapshot (default behavior)

      cold     - Boot without loading any snapshot (cold boot)

      snapshot - Boot from a specific snapshot (use --snapshot to specify)

      wipe     - Factory reset, wipes all user data (requires confirmation)

    Examples:
      sandroid-config avd start

      sandroid-config avd start --boot-mode=cold

      sandroid-config avd start --boot-mode=snapshot --snapshot=my_snapshot

      sandroid-config avd start --boot-mode=wipe
    """
    from sandroid.config.android_env import (
        find_emulator_path,
        find_existing_sdk,
        get_avd_info,
        list_available_avds,
    )

    try:
        loader = ConfigLoader()
        try:
            config = loader.load()
        except FileNotFoundError:
            config = SandroidConfig()

        # Determine which AVD to start
        target_avd = None
        if avd_name:
            target_avd = avd_name
        elif use_config:
            target_avd = config.emulator.selected_avd
            if not target_avd:
                console.print(
                    "[red]No AVD configured. Use --avd-name or run interactive mode.[/red]"
                )
                return

        # Show interactive selection by default
        if not target_avd:
            console.print("[bold blue]Select an AVD to start[/bold blue]\n")

            emulator_path = find_emulator_path()
            sdk_path = find_existing_sdk()

            if not emulator_path:
                console.print("[red]\u2717 Android emulator not found[/red]")
                console.print(
                    "Configure with 'sandroid-config init' or install Android SDK"
                )
                return

            avds = list_available_avds(emulator_path, sdk_path)

            if not avds:
                console.print("[yellow]No AVDs found[/yellow]")
                console.print(
                    "Create one with: [cyan]sandroid-config avd create[/cyan]"
                )
                console.print("Or use Android Studio to create an AVD")
                return

            # Show AVDs with details in a table
            table = Table(title=f"Available AVDs ({len(avds)})")
            table.add_column("#", style="cyan", no_wrap=True)
            table.add_column("AVD Name", style="magenta")
            table.add_column("Android", style="green")
            table.add_column("API", style="yellow")
            table.add_column("Device", style="dim")

            for i, avd_item in enumerate(avds, 1):
                info = get_avd_info(avd_item)
                table.add_row(
                    str(i),
                    avd_item,
                    info["android_version"],
                    info["api_level"],
                    info["device_name"],
                )

            console.print(table)
            console.print()

            # Interactive selection
            while True:
                choice = Prompt.ask(
                    f"Select AVD to start [1-{len(avds)}] or 'q' to quit",
                    default="1",
                )

                if choice.lower() == "q":
                    console.print("[yellow]Cancelled[/yellow]")
                    return

                try:
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(avds):
                        target_avd = avds[choice_num - 1]
                        break
                    console.print(
                        f"[red]Please enter a number between 1 and {len(avds)}[/red]"
                    )
                except ValueError:
                    console.print(
                        "[red]Please enter a valid number or 'q' to quit[/red]"
                    )

            # Ask about headless mode if not specified
            if not headless:
                headless = not Confirm.ask(
                    f"Start '{target_avd}' with UI?",
                    default=True,
                )

            # Boot mode selection (if not specified via CLI)
            if boot_mode is None:
                boot_mode, snapshot_name = _show_boot_mode_selection(target_avd)

            # Offer to save as default
            if Confirm.ask(f"Save '{target_avd}' as default AVD?", default=False):
                try:
                    _, saved_path = loader.load_and_update_section(
                        "emulator",
                        {
                            "selected_avd": target_avd,
                            "device_name": target_avd,
                            "avd_headless": headless,
                        },
                    )
                    console.print(
                        f"[green]\u2713[/green] Saved as default AVD in {saved_path}"
                    )
                except Exception as e:
                    console.print(f"[yellow]Could not save config: {e}[/yellow]")

        # Use headless from config if not overridden
        use_headless = headless or config.emulator.avd_headless

        # Default boot_mode if not set
        if boot_mode is None:
            boot_mode = "default"

        # Validate snapshot mode
        if boot_mode == "snapshot" and not snapshot_name:
            console.print(
                "[red]Error: --snapshot required when using --boot-mode=snapshot[/red]"
            )
            return

        # Confirm wipe data (destructive operation)
        if boot_mode == "wipe":
            console.print("\n[bold red]\u26a0 WARNING: Factory Reset[/bold red]")
            console.print(
                "This will [red]permanently delete all user data[/red] on this AVD."
            )
            if not Confirm.ask("Are you sure you want to continue?", default=False):
                console.print("[yellow]Cancelled[/yellow]")
                return

        # Show boot mode info
        boot_mode_desc = {
            "default": "with default snapshot",
            "cold": "cold boot (no snapshot)",
            "snapshot": f"with snapshot '{snapshot_name}'",
            "wipe": "factory reset (wiping all data)",
        }
        console.print(
            f"\n[bold blue]Starting AVD '{target_avd}' {boot_mode_desc.get(boot_mode, '')}...[/bold blue]"
        )

        android_env = {
            "emulator_path": config.emulator.android_emulator_path
            or find_emulator_path(),
            "sdk_path": config.emulator.sdk_path or find_existing_sdk(),
            "avd_home": config.emulator.avd_home,
        }

        success = _start_avd(
            target_avd, use_headless, android_env, boot_mode, snapshot_name
        )

        if success:
            console.print(
                f"[green]\u2713 AVD '{target_avd}' started successfully[/green]"
            )
            console.print("\n[bold blue]Next steps:[/bold blue]")
            console.print("  Check device with: [cyan]adb devices[/cyan]")
            console.print("  Run Sandroid analysis: [cyan]sandroid[/cyan]")
        else:
            console.print(f"[red]\u2717 Failed to start AVD '{target_avd}'[/red]")

    except Exception as e:
        console.print(f"[red]Error starting AVD: {e}[/red]")


# ---------------------------------------------------------------------------
# avd stop
# ---------------------------------------------------------------------------


@avd.command("stop")
@click.option("--avd-name", help="Specific AVD name to stop")
def avd_stop(avd_name: str | None):
    """Stop running Android Virtual Devices."""
    import os
    import shutil
    import subprocess

    try:
        # Find adb
        adb_path = shutil.which("adb")
        if not adb_path:
            loader = ConfigLoader()
            config = loader.load()
            if config.emulator.adb_path:
                adb_path = str(config.emulator.adb_path)

        if not adb_path:
            console.print("[red]\u2717 ADB not found[/red]")
            return

        console.print("[bold blue]Stopping AVDs...[/bold blue]")

        # Kill emulator processes directly (not via run_cmd, which
        # only allows whitelisted Android SDK commands)
        if os.name == "nt":
            result = subprocess.run(
                ["taskkill", "/f", "/im", "emulator.exe"],
                capture_output=True,
                check=False,
            )
        else:
            result = subprocess.run(
                ["pkill", "-f", "emulator"],
                capture_output=True,
                check=False,
            )

        if result.returncode == 0:
            console.print("[green]\u2713 Stopped running AVDs[/green]")
        else:
            console.print("[yellow]! No running AVDs found to stop[/yellow]")

    except Exception as e:
        console.print(f"[red]Error stopping AVDs: {e}[/red]")


# ---------------------------------------------------------------------------
# avd create (stub)
# ---------------------------------------------------------------------------


@avd.command("create")
@click.option("--name", default="sandroid", help="AVD name to create")
@click.option("--api-level", default="34", help="Android API level")
@click.option("--force", is_flag=True, help="Recreate AVD if it already exists")
def avd_create(name: str, api_level: str, force: bool):
    """Create a new Android Virtual Device."""
    console.print(f"[bold blue]Creating AVD '{name}' (API {api_level})[/bold blue]")
    console.print("[yellow]! AVD creation requires a full Android SDK setup.[/yellow]")
    console.print(
        "This is a complex process that may require downloading system images."
    )
    console.print("Consider using the existing create_avd.py script for full setup:")
    console.print("  [cyan]python deploy/create_avd.py[/cyan]")


# ---------------------------------------------------------------------------
# Private helpers (AVD-specific, not shared)
# ---------------------------------------------------------------------------


def _show_boot_mode_selection(avd_name: str) -> tuple[str, str | None]:
    """Show interactive boot mode selection.

    Args:
        avd_name: Name of the AVD to show snapshots for

    Returns:
        Tuple of (boot_mode, snapshot_name or None)
    """
    from sandroid.config.android_env import get_avd_snapshots_from_filesystem

    console.print("\n[bold blue]Select Boot Mode[/bold blue]")
    console.print()

    # Get available snapshots
    snapshots = get_avd_snapshots_from_filesystem(avd_name)
    has_snapshots = len(snapshots) > 0

    # Show options
    console.print("  [1] [cyan]Default Snapshot[/cyan] - Boot with last saved state")
    console.print("  [2] [cyan]Cold Boot[/cyan] - Start without loading any snapshot")
    if has_snapshots:
        console.print(
            f"  [3] [cyan]Specific Snapshot[/cyan] - Choose from {len(snapshots)} available"
        )
        console.print("  [4] [red]Factory Reset[/red] - Wipe all data (irreversible!)")
        max_choice = 4
    else:
        console.print("  [3] [red]Factory Reset[/red] - Wipe all data (irreversible!)")
        max_choice = 3

    console.print()
    choice = Prompt.ask(f"Select boot mode [1-{max_choice}]", default="1")

    try:
        choice_num = int(choice)
    except ValueError:
        choice_num = 1

    if choice_num == 1:
        return "default", None
    if choice_num == 2:
        return "cold", None

    # When snapshots exist: 3=snapshot, 4=wipe
    # When no snapshots:    3=wipe
    if has_snapshots:
        if choice_num == 3:
            return _show_snapshot_selection(snapshots)
        if choice_num == 4:
            return "wipe", None
    elif choice_num == 3:
        return "wipe", None

    return "default", None


def _show_snapshot_selection(snapshots: list) -> tuple[str, str | None]:
    """Show interactive snapshot selection.

    Args:
        snapshots: List of SnapshotInfo objects

    Returns:
        Tuple of (boot_mode, snapshot_name)
    """
    console.print("\n[bold blue]Available Snapshots[/bold blue]")

    table = Table()
    table.add_column("#", style="cyan", no_wrap=True)
    table.add_column("Name", style="magenta")
    table.add_column("Size", style="green")
    table.add_column("Modified", style="dim")

    for i, snap in enumerate(snapshots, 1):
        table.add_row(
            str(i),
            snap.name,
            f"{snap.size_mb:.0f} MB" if snap.size_mb > 0 else "-",
            snap.modified_date,
        )

    console.print(table)
    console.print()

    choice = Prompt.ask(f"Select snapshot [1-{len(snapshots)}]", default="1")

    try:
        choice_num = int(choice)
        if 1 <= choice_num <= len(snapshots):
            return "snapshot", snapshots[choice_num - 1].name
    except ValueError:
        pass

    # Default to first snapshot
    return "snapshot", snapshots[0].name


def _start_avd(
    avd_name: str,
    headless: bool,
    android_env: dict,
    boot_mode: str = "default",
    snapshot_name: str | None = None,
) -> bool:
    """Start an Android Virtual Device.

    Args:
        avd_name: Name of AVD to start
        headless: Whether to start in headless mode
        android_env: Dictionary with Android environment paths
        boot_mode: Boot mode ("default", "cold", "snapshot", "wipe")
        snapshot_name: Snapshot name for "snapshot" boot mode

    Returns:
        True if AVD started successfully
    """
    import os
    import subprocess

    try:
        emulator_path = android_env.get("emulator_path")
        if not emulator_path:
            console.print("[red]Emulator path not configured[/red]")
            return False

        # Validate emulator executable path
        emulator_name = Path(emulator_path).name
        if emulator_name not in {"emulator", "emulator.exe"}:
            console.print(f"[red]Invalid emulator executable: {emulator_name}[/red]")
            return False

        # Validate AVD name (prevent command injection)
        if (
            not avd_name
            or not avd_name.replace("_", "").replace("-", "").replace(".", "").isalnum()
        ):
            console.print(f"[red]Invalid AVD name: {avd_name}[/red]")
            return False

        # Validate snapshot name if provided (prevent command injection)
        if (
            snapshot_name
            and not snapshot_name.replace("_", "")
            .replace("-", "")
            .replace(".", "")
            .isalnum()
        ):
            console.print(f"[red]Invalid snapshot name: {snapshot_name}[/red]")
            return False

        # Build command with validated inputs
        cmd = [str(emulator_path), "-avd", avd_name]

        # Add boot mode flags
        if boot_mode == "cold":
            cmd.append("-no-snapshot-load")
        elif boot_mode == "wipe":
            cmd.append("-wipe-data")
        elif boot_mode == "snapshot" and snapshot_name:
            cmd.extend(["-snapshot", snapshot_name])

        # Only allow specific safe emulator arguments
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

        # Start emulator in background with validated command
        process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

        console.print(f"[green]>[/green] AVD '{avd_name}' starting in background...")
        console.print(f"[dim]Process ID: {process.pid}[/dim]")

        if headless:
            console.print("[dim]Running in headless mode (no UI)[/dim]")
        else:
            console.print("[dim]Running with UI[/dim]")

        # Verify emulator process survives initial startup
        from sandroid.core.emulator import check_emulator_startup

        ok, error_msg = check_emulator_startup(process)
        if not ok:
            console.print(f"[red]Emulator startup failed: {error_msg}[/red]")
            return False

        return True

    except Exception as e:
        console.print(f"[red]Failed to start AVD: {e}[/red]")
        return False
