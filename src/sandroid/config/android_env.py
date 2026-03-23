"""Android environment detection and management for Sandroid configuration."""

import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()


@dataclass
class SnapshotInfo:
    """Information about an AVD snapshot.

    Attributes:
        name: Snapshot folder name (e.g., "default_boot", "snap_2024-07-09")
        path: Full path to the snapshot directory
        size_mb: Approximate size based on ram.bin file
        modified_date: Last modified date from filesystem
        mtime: Raw modification timestamp for sorting (0.0 if unknown)
    """

    name: str
    path: Path
    size_mb: float
    modified_date: str
    mtime: float = 0.0


def is_windows() -> bool:
    """Check if running on Windows."""
    return platform.system().lower().startswith("win")


def is_macos() -> bool:
    """Check if running on macOS."""
    return platform.system().lower() == "darwin"


def is_linux() -> bool:
    """Check if running on Linux."""
    return platform.system().lower() == "linux"


def run_cmd(
    cmd: list[str], env=None, input_text: str | None = None
) -> tuple[int, str, str]:
    """Run command and return exit code, stdout, stderr.

    Only executes commands from a whitelist of known safe Android SDK tools.
    """
    if not cmd:
        return 1, "", "Empty command provided"

    # Whitelist of allowed commands for Android environment detection
    allowed_commands = {
        "emulator",
        "emulator.exe",
        "adb",
        "adb.exe",
        "sdkmanager",
        "sdkmanager.bat",
        "avdmanager",
        "avdmanager.bat",
    }

    command_name = Path(cmd[0]).name
    if command_name not in allowed_commands:
        return (
            1,
            "",
            f"Command '{command_name}' not in allowed list: {', '.join(allowed_commands)}",
        )

    try:
        input_bytes = input_text.encode() if input_text else None
        res = subprocess.run(
            cmd, input=input_bytes, env=env, capture_output=True, check=False
        )
        stdout = res.stdout.decode(errors="replace")
        stderr = res.stderr.decode(errors="replace")
        return res.returncode, stdout, stderr
    except FileNotFoundError:
        return 127, "", f"Executable not found: {cmd[0]}"
    except Exception as e:
        return 1, "", f"{e.__class__.__name__}: {e}"


def looks_like_sdk(path: str | Path) -> bool:
    """Check if the given path looks like a valid Android SDK root."""
    path = Path(path)
    if not path.is_dir():
        return False
    critical = ["platform-tools", "cmdline-tools"]
    return any((path / c).is_dir() for c in critical)


def find_existing_sdk() -> Path | None:
    """Try to detect the Android SDK root from environment vars and known locations."""
    # 1. Check environment variables first
    for var in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        sdk = os.environ.get(var)
        if sdk and looks_like_sdk(sdk):
            return Path(sdk)

    # 2. Check common defaults per OS
    candidates = []
    if is_macos():
        candidates += [
            Path("~/Library/Android/sdk").expanduser(),
            Path("~/Library/Android").expanduser(),
        ]
    elif is_linux():
        candidates += [
            Path("~/Android/Sdk").expanduser(),
            Path("~/Android/sdk").expanduser(),
            Path("~/android-sdk").expanduser(),
        ]
    elif is_windows():
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        appdata = os.environ.get("APPDATA", "")
        if local_appdata:
            candidates.append(Path(local_appdata) / "Android" / "Sdk")
        if appdata:
            candidates.append(Path(appdata) / "Android" / "Sdk")

    # 3. Check if sdkmanager is on PATH
    sm = shutil.which("sdkmanager") or shutil.which("sdkmanager.bat")
    if sm:
        possible_sdk = Path(sm).parent.parent.parent
        if looks_like_sdk(possible_sdk):
            return possible_sdk

    # 4. Validate candidates
    for c in candidates:
        if looks_like_sdk(c):
            return c
        # Check if <c>/sdk exists instead (common on macOS)
        sub = c / "sdk"
        if looks_like_sdk(sub):
            return sub

    return None


def find_existing_avd_home() -> Path | None:
    """Find existing Android AVD home directory."""
    avd_home = os.environ.get("ANDROID_AVD_HOME")
    if avd_home and Path(avd_home).is_dir():
        return Path(avd_home)

    default = Path("~/.android/avd").expanduser()
    if default.is_dir():
        return default

    return None


def _find_sdk_tool(tool_name: str, sdk_subdir: str) -> Path | None:
    """Find an Android SDK tool by name, checking PATH first then SDK locations.

    Args:
        tool_name: Name of the tool executable (e.g., "adb", "emulator")
        sdk_subdir: SDK subdirectory containing the tool (e.g., "platform-tools", "emulator")

    Returns:
        Path to the tool executable, or None if not found
    """
    found_in_path = shutil.which(tool_name)
    if found_in_path:
        return Path(found_in_path)

    sdk_path = find_existing_sdk()
    if sdk_path:
        exe_name = f"{tool_name}.exe" if is_windows() else tool_name
        tool_in_sdk = sdk_path / sdk_subdir / exe_name
        if tool_in_sdk.exists():
            return tool_in_sdk

    return None


def find_adb_path() -> Path | None:
    """Find ADB executable path."""
    return _find_sdk_tool("adb", "platform-tools")


def find_emulator_path() -> Path | None:
    """Find Android emulator executable path."""
    return _find_sdk_tool("emulator", "emulator")


def validate_avd_name(name: str) -> bool:
    """Validate AVD name according to Android requirements."""
    if not name or not name.strip():
        return False

    # AVD names should be ASCII alphanumeric with underscores and hyphens
    if not re.match(r"^[A-Za-z0-9_\-]+$", name):
        console.print(
            f"[red]Invalid AVD name '{name}' - use only letters, numbers, underscores, and hyphens[/red]"
        )
        return False

    # Avoid reserved names and overly long names
    if len(name) > 50:
        console.print(f"[red]AVD name '{name}' too long - maximum 50 characters[/red]")
        return False

    reserved_names = {
        "con",
        "prn",
        "aux",
        "nul",
        "com1",
        "com2",
        "com3",
        "com4",
        "lpt1",
        "lpt2",
    }
    if name.lower() in reserved_names:
        console.print(
            f"[red]AVD name '{name}' is reserved - choose a different name[/red]"
        )
        return False

    return True


def validate_api_level(api_str: str) -> int | None:
    """Validate and return Android API level."""
    try:
        api_level = int(api_str)
        if api_level < 21:
            console.print(
                f"[yellow]Warning: API level {api_level} is very old and may not work properly[/yellow]"
            )
        elif api_level > 36:
            console.print(
                f"[yellow]Warning: API level {api_level} may not be available yet[/yellow]"
            )
        return api_level
    except ValueError:
        console.print(f"[red]Invalid API level '{api_str}' - must be a number[/red]")
        return None


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


def list_available_avds(
    emulator_path: Path | None = None, sdk_path: Path | None = None
) -> list[str]:
    """List available Android Virtual Devices."""
    if not emulator_path:
        emulator_path = find_emulator_path()

    if not emulator_path or not emulator_path.exists():
        return []

    # Set up environment
    env = os.environ.copy()
    if sdk_path:
        env["ANDROID_SDK_ROOT"] = str(sdk_path)
        env["ANDROID_HOME"] = str(sdk_path)

    # Run emulator -list-avds
    code, stdout, stderr = run_cmd([str(emulator_path), "-list-avds"], env=env)

    if code != 0:
        console.print(f"[yellow]Warning: Could not list AVDs: {stderr}[/yellow]")
        return []

    # Parse AVD names from output
    avds = []
    for line in stdout.strip().split("\n"):
        avd_name = line.strip()
        if avd_name and not avd_name.startswith("INFO"):
            avds.append(avd_name)

    return avds


# API level to Android version mapping
API_TO_ANDROID_VERSION = {
    36: "16",
    35: "15",
    34: "14",
    33: "13",
    32: "12L",
    31: "12",
    30: "11",
    29: "10",
    28: "9 (Pie)",
    27: "8.1 (Oreo)",
    26: "8.0 (Oreo)",
    25: "7.1 (Nougat)",
    24: "7.0 (Nougat)",
    23: "6.0 (Marshmallow)",
    22: "5.1 (Lollipop)",
    21: "5.0 (Lollipop)",
}


def get_avd_info(avd_name: str) -> dict[str, str]:
    """Get detailed information about an AVD.

    Reads the AVD's .ini file to resolve the actual .avd directory path
    (which may differ from {name}.avd) and extract a fallback API level
    from the target= field. Then reads config.ini for full details.

    Args:
        avd_name: Name of the AVD

    Returns:
        Dictionary with AVD info including android_version, api_level, device_name
    """
    info = {
        "android_version": "Unknown",
        "api_level": "?",
        "device_name": "",
    }

    # Find AVD home directory
    avd_home = find_existing_avd_home()
    if not avd_home:
        return info

    # Try to read the .ini file first to get actual AVD path and target
    ini_path = avd_home / f"{avd_name}.ini"
    avd_dir = avd_home / f"{avd_name}.avd"  # default
    target_api = None

    if ini_path.exists():
        try:
            ini_content = ini_path.read_text(encoding="utf-8")
            # Follow path= redirect to actual .avd directory
            path_match = re.search(r"^path\s*=\s*(.+)$", ini_content, re.MULTILINE)
            if path_match:
                redirected = Path(path_match.group(1).strip())
                if redirected.is_dir():
                    avd_dir = redirected
            # Extract target as fallback for API level
            target_match = re.search(
                r"^target\s*=\s*android-(\d+)$", ini_content, re.MULTILINE
            )
            if target_match:
                target_api = int(target_match.group(1))
        except (OSError, ValueError):
            pass

    # Read config.ini from the resolved AVD directory
    config_path = avd_dir / "config.ini"
    if config_path.exists():
        try:
            config_content = config_path.read_text(encoding="utf-8")

            # Parse image.sysdir.1 to get API level
            # Example: image.sysdir.1 = system-images/android-34/google_apis/arm64-v8a/
            sysdir_match = re.search(
                r"image\.sysdir\.1\s*=\s*.*android-(\d+)", config_content
            )
            if sysdir_match:
                api_level = int(sysdir_match.group(1))
                info["api_level"] = str(api_level)
                info["android_version"] = API_TO_ANDROID_VERSION.get(
                    api_level, f"API {api_level}"
                )

            # Get device name
            device_match = re.search(r"hw\.device\.name\s*=\s*(.+)", config_content)
            if device_match:
                info["device_name"] = device_match.group(1).strip()

        except (OSError, ValueError):
            pass

    # Fallback: use target= from .ini if config.ini didn't yield an API level
    if info["api_level"] == "?" and target_api is not None:
        info["api_level"] = str(target_api)
        info["android_version"] = API_TO_ANDROID_VERSION.get(
            target_api, f"API {target_api}"
        )

    return info


def get_avd_snapshots_from_filesystem(avd_name: str) -> list[SnapshotInfo]:
    """Get list of snapshots for an AVD by scanning the filesystem.

    This works for AVDs that are not currently running (unlike telnet-based listing).

    Args:
        avd_name: Name of the AVD

    Returns:
        List of SnapshotInfo objects for available snapshots, sorted by modified date
        (newest first), with default_boot always at the top if present.
    """
    snapshots: list[SnapshotInfo] = []

    avd_home = find_existing_avd_home()
    if not avd_home:
        return snapshots

    snapshots_dir = avd_home / f"{avd_name}.avd" / "snapshots"
    if not snapshots_dir.exists():
        return snapshots

    for snapshot_path in snapshots_dir.iterdir():
        if not snapshot_path.is_dir():
            continue

        # Check for valid snapshot (has snapshot.pb or hardware.ini)
        has_snapshot_pb = (snapshot_path / "snapshot.pb").exists()
        has_hardware_ini = (snapshot_path / "hardware.ini").exists()

        if not (has_snapshot_pb or has_hardware_ini):
            continue

        # Calculate size from ram.bin if it exists
        ram_bin = snapshot_path / "ram.bin"
        size_mb = 0.0
        if ram_bin.exists():
            try:
                size_mb = ram_bin.stat().st_size / (1024 * 1024)
            except OSError:
                pass

        # Get modified date and raw mtime for sorting
        mtime = 0.0
        modified_date = "Unknown"
        try:
            mtime = snapshot_path.stat().st_mtime
            modified_date = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
        except OSError:
            pass

        snapshots.append(
            SnapshotInfo(
                name=snapshot_path.name,
                path=snapshot_path,
                size_mb=size_mb,
                modified_date=modified_date,
                mtime=mtime,
            )
        )

    # Sort: default_boot first, then newest first by mtime
    snapshots.sort(
        key=lambda s: (
            s.name != "default_boot",  # default_boot first (False < True)
            -s.mtime,  # newest first
        )
    )

    return snapshots


def rename_avd(old_name: str, new_name: str) -> tuple[bool, str]:
    """Rename an AVD.

    Args:
        old_name: Current name of the AVD
        new_name: New name for the AVD

    Returns:
        Tuple of (success, message)
    """
    # Find AVD home directory
    avd_home = find_existing_avd_home()
    if not avd_home:
        return False, "AVD home directory not found"

    # Check source files exist
    old_ini = avd_home / f"{old_name}.ini"
    old_avd_dir = avd_home / f"{old_name}.avd"

    if not old_ini.exists():
        return False, f"AVD '{old_name}' not found (missing .ini file)"

    if not old_avd_dir.exists():
        return False, f"AVD '{old_name}' not found (missing .avd directory)"

    # Check target doesn't exist
    new_ini = avd_home / f"{new_name}.ini"
    new_avd_dir = avd_home / f"{new_name}.avd"

    if new_ini.exists() or new_avd_dir.exists():
        return False, f"AVD '{new_name}' already exists"

    # Validate new name (alphanumeric, underscores, hyphens)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", new_name):
        return (
            False,
            "Invalid AVD name. Use letters, numbers, underscores, and hyphens. Must start with a letter.",
        )

    try:
        # Rename the .ini file
        old_ini.rename(new_ini)

        # Rename the .avd directory
        old_avd_dir.rename(new_avd_dir)

        # Update the path inside the .ini file
        ini_content = new_ini.read_text()
        ini_content = ini_content.replace(f"{old_name}.avd", f"{new_name}.avd")
        new_ini.write_text(ini_content)

        return True, f"Successfully renamed '{old_name}' to '{new_name}'"

    except PermissionError:
        return False, "Permission denied. Make sure the AVD is not running."
    except Exception as e:
        return False, f"Error renaming AVD: {e}"


def detect_android_environment() -> dict[str, Any]:
    """Detect current Android development environment setup."""
    console.print("[bold blue]Detecting Android development environment...[/bold blue]")

    environment = {
        "sdk_path": None,
        "adb_path": None,
        "emulator_path": None,
        "avd_home": None,
        "available_avds": [],
        "environment_ready": False,
    }

    # Detect SDK
    sdk_path = find_existing_sdk()
    if sdk_path:
        console.print(f"[green]✓[/green] Found Android SDK: {sdk_path}")
        environment["sdk_path"] = sdk_path
    else:
        console.print("[yellow]![/yellow] Android SDK not detected")

    # Detect ADB
    adb_path = find_adb_path()
    if adb_path:
        console.print(f"[green]✓[/green] Found ADB: {adb_path}")
        environment["adb_path"] = adb_path
    else:
        console.print("[yellow]![/yellow] ADB not found in PATH or SDK")

    # Detect Emulator
    emulator_path = find_emulator_path()
    if emulator_path:
        console.print(f"[green]✓[/green] Found Android Emulator: {emulator_path}")
        environment["emulator_path"] = emulator_path
    else:
        console.print("[yellow]![/yellow] Android Emulator not found")

    # Detect AVD Home
    avd_home = find_existing_avd_home()
    if avd_home:
        console.print(f"[green]✓[/green] Found AVD Home: {avd_home}")
        environment["avd_home"] = avd_home

        # List available AVDs
        avds = list_available_avds(emulator_path, sdk_path)
        if avds:
            console.print(f"[green]✓[/green] Found {len(avds)} AVDs: {', '.join(avds)}")
            environment["available_avds"] = avds
        else:
            console.print("[yellow]![/yellow] No AVDs found")
    else:
        console.print("[yellow]![/yellow] AVD Home directory not found")

    # Check if environment is ready
    environment["environment_ready"] = all(
        (
            environment["sdk_path"],
            environment["adb_path"],
            environment["emulator_path"],
            environment["avd_home"],
        )
    )

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


def select_or_create_avd(environment: dict[str, Any]) -> tuple[str | None, bool]:
    """Let user select existing AVD or create new one.

    Returns:
        Tuple of (selected_avd_name, should_create_new)
    """
    avds = environment.get("available_avds", [])

    if avds:
        console.print(f"\n[bold blue]Found {len(avds)} existing AVDs[/bold blue]")

        # Show AVDs in a table
        table = Table(title="Available Android Virtual Devices")
        table.add_column("Index", style="cyan", no_wrap=True)
        table.add_column("AVD Name", style="magenta")

        for i, avd in enumerate(avds, 1):
            table.add_row(str(i), avd)

        console.print(table)

        # Add options for selection
        options = [f"{i}. {avd}" for i, avd in enumerate(avds, 1)]
        options.append(f"{len(avds) + 1}. Create new 'sandroid' AVD")
        options.append(f"{len(avds) + 2}. Skip AVD configuration")

        console.print("\n[bold]Choose an option:[/bold]")
        for option in options:
            console.print(f"  {option}")

        while True:
            choice = Prompt.ask(f"Enter choice [1-{len(options)}]", default="1")

            try:
                choice_num = int(choice)
                if 1 <= choice_num <= len(avds):
                    selected_avd = avds[choice_num - 1]
                    console.print(f"[green]✓[/green] Selected AVD: {selected_avd}")
                    return selected_avd, False
                if choice_num == len(avds) + 1:
                    return "sandroid", True
                if choice_num == len(avds) + 2:
                    console.print("[yellow]Skipping AVD configuration[/yellow]")
                    return None, False
                console.print("[red]Invalid choice, please try again[/red]")
            except ValueError:
                console.print("[red]Please enter a number[/red]")

    else:
        console.print("\n[bold yellow]No existing AVDs found[/bold yellow]")

        if Confirm.ask("Create new 'sandroid' AVD?", default=True):
            return "sandroid", True
        return None, False


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


def setup_android_environment(skip_setup: bool = False) -> dict[str, Any]:
    """Complete Android environment setup workflow.

    Args:
        skip_setup: If True, only detect environment without user prompts

    Returns:
        Dictionary with Android environment configuration
    """
    if skip_setup:
        console.print("[yellow]Skipping Android environment setup[/yellow]")
        return detect_android_environment()

    # Detect current environment
    environment = detect_android_environment()

    # If environment is already complete, just confirm with user
    if environment["environment_ready"]:
        console.print(
            "\n[bold green]✓ Android development environment looks good![/bold green]"
        )

        if environment["available_avds"]:
            selected_avd, should_create = select_or_create_avd(environment)
            environment["selected_avd"] = selected_avd
            environment["should_create_avd"] = should_create

        return environment

    # Prompt for missing paths
    environment = prompt_for_missing_paths(environment)

    # Refresh AVD list after configuration
    if environment.get("emulator_path") and environment.get("sdk_path"):
        environment["available_avds"] = list_available_avds(
            environment["emulator_path"], environment["sdk_path"]
        )

    # Select or create AVD
    if environment.get("available_avds") or environment.get("avd_home"):
        selected_avd, should_create = select_or_create_avd(environment)
        environment["selected_avd"] = selected_avd
        environment["should_create_avd"] = should_create

    # Print warnings for any remaining missing tools
    print_missing_tools_warning(environment)

    return environment
