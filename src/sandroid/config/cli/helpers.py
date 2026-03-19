"""Shared helpers and constants for the Sandroid config CLI.

This module eliminates DRY violations by centralizing:
- THEME_REGISTRY: single source of truth for theme metadata
- _detect_and_save_config(): shared config format-detect-and-save logic
- _parse_value(): string-to-typed-value conversion
- _show_config_rich() / _show_config_format(): config display helpers
- console: shared Rich Console instance
"""

from pathlib import Path

from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from sandroid.config.loader import ConfigLoader
from sandroid.config.schema import SandroidConfig

console = Console()

# ---------------------------------------------------------------------------
# Single source of truth for theme metadata.
# Replaces 4 duplicated theme_names dicts / theme_options lists.
# ---------------------------------------------------------------------------
THEME_REGISTRY: list[tuple[str, str, str]] = [
    ("default", "Midnight Cyan", "Dark blue/cyan theme (default)"),
    ("dark", "Dark", "Material Design dark theme"),
    ("light", "Light", "Clean light theme"),
    ("high_contrast", "High Contrast", "Maximum contrast for accessibility"),
    ("cyberpunk", "Cyberpunk/Neon", "Neon colors on dark purple"),
    ("nord", "Nord/Arctic", "Arctic, north-bluish colors"),
    ("dracula", "Dracula", "Popular dark purple/green theme"),
    ("solarized", "Solarized Dark", "Classic Solarized color scheme"),
]

VALID_THEME_IDS: set[str] = {t[0] for t in THEME_REGISTRY}


def get_theme_display_name(theme_id: str) -> str:
    """Return the human-readable display name for a theme id."""
    for tid, display, _ in THEME_REGISTRY:
        if tid == theme_id:
            return display
    return theme_id


# ---------------------------------------------------------------------------
# Config format-detect-and-save helper (eliminates 6 copy-paste blocks).
# ---------------------------------------------------------------------------


def _detect_and_save_config(
    loader: ConfigLoader,
    updated_config: SandroidConfig,
    config_path: str | Path | None = None,
) -> Path:
    """Detect the existing config format and save the updated config.

    If *config_path* is given it is used directly.  Otherwise the first
    discovered config file from *loader* is used.  The format is inferred
    from the file extension (defaulting to TOML).

    Args:
        loader: A ConfigLoader instance (already initialised).
        updated_config: The validated SandroidConfig to persist.
        config_path: Optional explicit path to write to.

    Returns:
        The Path the config was written to.
    """
    return loader.detect_and_save(updated_config, config_path)


# ---------------------------------------------------------------------------
# Value parsing
# ---------------------------------------------------------------------------


def _parse_value(value: str) -> str | int | float | bool:
    """Parse a string value to an appropriate Python type.

    Handles booleans, integers, floats, and falls back to str.
    """
    if value.lower() in ("true", "yes", "1", "on"):
        return True
    if value.lower() in ("false", "no", "0", "off"):
        return False

    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        pass

    return value


# ---------------------------------------------------------------------------
# Config display helpers
# ---------------------------------------------------------------------------


def _show_config_rich(config: SandroidConfig) -> None:
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
    if config.emulator.android_emulator_path:
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

    # TUI Settings
    table = Table(title="TUI Settings")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="magenta")

    theme_display = get_theme_display_name(config.tui.theme)
    table.add_row("Theme", f"{theme_display} ({config.tui.theme})")

    if config.tui.custom_css_path:
        table.add_row("Custom CSS", str(config.tui.custom_css_path))
    if config.tui.logo_color:
        table.add_row("Logo Color", config.tui.logo_color)
    if config.tui.logo_text_color:
        table.add_row("Logo Text Color", config.tui.logo_text_color)

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


def _show_config_format(config: SandroidConfig, fmt: str) -> None:
    """Show configuration in specified format with syntax highlighting."""
    import tempfile

    loader = ConfigLoader()
    temp_path = Path(tempfile.mktemp(suffix=f".{fmt}"))

    try:
        loader.save_config(config, temp_path, fmt)
        content = temp_path.read_text(encoding="utf-8")
        syntax = Syntax(content, fmt, theme="monokai", line_numbers=True)
        console.print(syntax)
    finally:
        temp_path.unlink(missing_ok=True)
