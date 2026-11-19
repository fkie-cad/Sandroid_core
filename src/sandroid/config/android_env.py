"""Android SDK/adb/emulator path detection for ``sandroid-config init``.

Discovery itself lives in :mod:`sandroid.core.emulator` (the one
emulator/AVD backend); this module only reports what it found and asks for
missing paths. AVDs are picked and started in the TUI's Devices screen.
"""

import os
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt

from sandroid.core.emulator import (
    adb_binary,
    avd_home,
    emulator_binary,
    looks_like_sdk,
    sdk_root,
)

console = Console()


def validate_path(
    path_str: str, description: str, must_exist: bool = True
) -> Path | None:
    """Validate and return Path object, with user-friendly error messages."""
    if not path_str or not path_str.strip():
        return None

    try:
        path = Path(path_str).expanduser().resolve()

        if must_exist and not path.exists():
            console.print(f"[red]Error: {description} not found at {path}[/red]")
            return None

        if must_exist and path.is_file() and not os.access(path, os.X_OK):
            console.print(
                f"[yellow]Warning: {description} at {path} is not executable[/yellow]"
            )

        return path

    except Exception as e:
        console.print(f"[red]Error: Invalid path '{path_str}': {e}[/red]")
        return None


def detect_android_environment() -> dict[str, Any]:
    """Detect the Android SDK, adb, emulator and AVD home paths.

    Returns:
        Dict with ``sdk_path``, ``adb_path``, ``emulator_path``, ``avd_home``
        (each a ``Path`` or ``None``) and ``environment_ready``.
    """
    console.print("[bold blue]Detecting Android development environment...[/bold blue]")

    found = {
        "sdk_path": ("Android SDK", sdk_root()),
        "adb_path": ("ADB", adb_binary()),
        "emulator_path": ("Android Emulator", emulator_binary()),
        "avd_home": ("AVD Home", avd_home()),
    }
    environment: dict[str, Any] = {}
    for key, (label, path) in found.items():
        environment[key] = path
        if path:
            console.print(f"[green]✓[/green] Found {label}: {path}")
        else:
            console.print(f"[yellow]![/yellow] {label} not found")
    environment["environment_ready"] = all(path for _label, path in found.values())
    return environment


def prompt_for_missing_paths(environment: dict[str, Any]) -> dict[str, Any]:
    """Prompt user to provide paths for missing Android tools."""
    console.print("\n[bold yellow]Configuring missing Android tools...[/bold yellow]")

    updated_env = environment.copy()

    # SDK Path
    if not updated_env["sdk_path"]:
        console.print("\n[bold]Android SDK not found.[/bold]")
        console.print(
            "The Android SDK contains platform-tools (adb) and emulator tools."
        )

        path_input = Prompt.ask(
            "Enter Android SDK path (or press Enter to skip)", default=""
        )

        if path_input:
            sdk_path = validate_path(path_input, "Android SDK", must_exist=True)
            if sdk_path and looks_like_sdk(sdk_path):
                updated_env["sdk_path"] = sdk_path
                console.print(f"[green]✓[/green] SDK configured: {sdk_path}")
            else:
                console.print(
                    "[red]Invalid SDK path - continuing without SDK configuration[/red]"
                )

    # ADB Path
    if not updated_env["adb_path"]:
        console.print("\n[bold]ADB (Android Debug Bridge) not found.[/bold]")
        console.print("ADB is required for device communication.")

        path_input = Prompt.ask(
            "Enter ADB executable path (or press Enter to skip)", default=""
        )

        if path_input:
            adb_path = validate_path(path_input, "ADB executable", must_exist=True)
            if adb_path:
                updated_env["adb_path"] = adb_path
                console.print(f"[green]✓[/green] ADB configured: {adb_path}")

    # Emulator Path
    if not updated_env["emulator_path"]:
        console.print("\n[bold]Android Emulator not found.[/bold]")
        console.print("The emulator is required to run Android Virtual Devices.")

        path_input = Prompt.ask(
            "Enter emulator executable path (or press Enter to skip)", default=""
        )

        if path_input:
            emulator_path = validate_path(
                path_input, "Emulator executable", must_exist=True
            )
            if emulator_path:
                updated_env["emulator_path"] = emulator_path
                console.print(f"[green]✓[/green] Emulator configured: {emulator_path}")

    # AVD Home
    if not updated_env["avd_home"]:
        console.print("\n[bold]AVD Home directory not found.[/bold]")
        console.print("This directory contains your Android Virtual Devices.")

        default_avd_home = str(Path("~/.android/avd").expanduser())
        path_input = Prompt.ask("Enter AVD Home directory", default=default_avd_home)

        if path_input:
            avd_home = validate_path(path_input, "AVD Home directory", must_exist=False)
            if avd_home:
                # Create directory if it doesn't exist
                avd_home.mkdir(parents=True, exist_ok=True)
                updated_env["avd_home"] = avd_home
                console.print(f"[green]✓[/green] AVD Home configured: {avd_home}")

    return updated_env


def print_missing_tools_warning(environment: dict[str, Any]):
    """Print warning about missing Android tools and their impact."""
    missing_tools = []

    if not environment.get("sdk_path"):
        missing_tools.append("Android SDK")
    if not environment.get("adb_path"):
        missing_tools.append("ADB")
    if not environment.get("emulator_path"):
        missing_tools.append("Android Emulator")
    if not environment.get("avd_home"):
        missing_tools.append("AVD Home")

    if missing_tools:
        console.print(
            f"\n[bold yellow]! Missing Android tools: {', '.join(missing_tools)}[/bold yellow]"
        )
        console.print("\n[bold]Impact on Sandroid functionality:[/bold]")

        if "ADB" in missing_tools:
            console.print("  • Device communication will fail")
            console.print("  • File system analysis unavailable")

        if "Android Emulator" in missing_tools:
            console.print("  • Cannot start/manage Android Virtual Devices")
            console.print("  • AVD automation unavailable")

        if "AVD Home" in missing_tools:
            console.print("  • No access to virtual devices")

        console.print("\n[bold blue]To configure later, use:[/bold blue]")
        console.print("  sandroid-config set emulator.adb_path /path/to/adb")
        console.print(
            "  sandroid-config set emulator.android_emulator_path /path/to/emulator"
        )
        console.print("  sandroid-config set emulator.sdk_path /path/to/sdk")
        console.print("  sandroid-config set emulator.avd_home /path/to/avd")


def setup_android_environment(interactive: bool = True) -> dict[str, Any]:
    """Detect the Android tool paths, asking for missing ones if *interactive*.

    Args:
        interactive: Prompt for paths that could not be detected.

    Returns:
        Dict as returned by :func:`detect_android_environment`.
    """
    environment = detect_android_environment()
    if environment["environment_ready"]:
        console.print(
            "\n[bold green]✓ Android development environment looks good![/bold green]"
        )
        return environment
    if interactive:
        environment = prompt_for_missing_paths(environment)
    print_missing_tools_warning(environment)
    return environment
