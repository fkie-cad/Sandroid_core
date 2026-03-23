"""Headless device settings CLI mode.

Applies device environment configuration (GPS, timezone, locale, sensors,
battery, network) from a JSON file or country preset without the TUI.
"""

import json
import logging
import sys

logger = logging.getLogger(__name__)


def run_device_settings_headless(
    sandroid_config,
    settings_file: str | None = None,
    preset: str | None = None,
) -> None:
    """Apply device settings in headless mode.

    Initializes the device connection, then applies settings from a JSON
    file and/or a country preset. If both are provided, the file is used
    (which may itself contain a preset key).

    Args:
        sandroid_config: Loaded SandroidConfig instance.
        settings_file: Path to JSON settings file.
        preset: Country preset code (e.g., "de", "us").
    """
    from sandroid.core.console import SandroidConsole
    from sandroid.core.initializer import initialize_core
    from sandroid.services.device_settings_service import (
        DeviceSettingsService,
        validate_settings_dict,
    )

    console = SandroidConsole.get()
    initialize_core(sandroid_config)
    svc = DeviceSettingsService()

    if settings_file:
        try:
            with open(settings_file, encoding="utf-8") as f:
                settings = json.load(f)
        except json.JSONDecodeError as e:
            console.print(f"[error]Invalid JSON in {settings_file}: {e}[/error]")
            sys.exit(1)
        except FileNotFoundError:
            console.print(f"[error]File not found: {settings_file}[/error]")
            sys.exit(1)

        errors = validate_settings_dict(settings)
        if errors:
            console.print("[error]Settings validation failed:[/error]")
            for err in errors:
                console.print(f"  [warning]- {err}[/warning]")
            sys.exit(1)

        results = svc.apply_settings_dict(settings)
    elif preset:
        results = [svc.apply_preset(preset)]
    else:
        console.print("[error]Provide --device-settings FILE or --preset CODE[/error]")
        sys.exit(1)

    # Print summary
    success_count = sum(1 for r in results if r.success)
    fail_count = sum(1 for r in results if not r.success)

    for r in results:
        if r.success:
            console.print(f"  [success]{r.message}[/success]")
        else:
            console.print(f"  [error]{r.message}[/error]")
            if r.error:
                console.print(f"    [dim]{r.error}[/dim]")

    if fail_count == 0:
        console.print(
            f"\n[success]All {success_count} settings applied successfully[/success]"
        )
    else:
        console.print(
            f"\n[warning]{success_count} succeeded, {fail_count} failed[/warning]"
        )
        sys.exit(1)
