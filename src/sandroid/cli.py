"""Main CLI entry point for Sandroid.

This module defines the Click command interface and dispatches to the
appropriate mode handler in ``sandroid.cli_modes``. It is intentionally
kept thin: Click decorators, config loading, and mode dispatch.
"""

import logging
import os
import sys

import click

from sandroid.services import get_ui_service

from ._version import __version__
from .cli_modes.helpers import build_cli_overrides, setup_logging
from .core.console import SandroidConsole

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Backward-compatible re-exports (tests and external code may import these
# from sandroid.cli instead of sandroid.cli_modes)
# ---------------------------------------------------------------------------


def pretty_logo() -> None:
    """Display the Sandroid ASCII art logo in the terminal."""
    SandroidConsole.print_logo()


# Lazy re-exports for mode dispatchers to avoid importing heavy modules at
# module level (fritap, headless API, etc.).  The canonical location is now
# ``sandroid.cli_modes.<module>``.
def __getattr__(name: str):
    _reexports = {
        "start_interactive_mode": ".cli_modes.interactive",
        "run_analysis": ".cli_modes.analysis",
        "run_fritap_headless": ".cli_modes.fritap",
        "run_dexray_headless": ".cli_modes.dexray",
        "run_fridump_headless": ".cli_modes.fridump",
        "run_network_headless": ".cli_modes.network",
        "run_headless_analysis": ".cli_modes.headless",
    }
    if name in _reexports:
        import importlib

        mod = importlib.import_module(_reexports[name], package=__package__)
        attr = getattr(mod, name)
        # Cache on the module so __getattr__ is only called once per name
        globals()[name] = attr
        return attr
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ---------------------------------------------------------------------------
# Click command definition
# ---------------------------------------------------------------------------


@click.command()
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Configuration file path"
)
@click.option(
    "--environment", "-e", help="Environment name (development, testing, production)"
)
@click.option(
    "--file", "-f", type=click.Path(), help="Save output to the specified file"
)
@click.option(
    "--loglevel",
    "-ll",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    help="Set the log level",
)
@click.option(
    "--number",
    "-n",
    type=click.IntRange(min=2),
    help="Run action n times (Minimum is 2)",
)
@click.option(
    "--avoid-strong-noise-filter",
    is_flag=True,
    help="Don't use a 'Dry Run'. This will catch more noise and disable intra file noise detection",
)
@click.option("--network", is_flag=True, help="Capture traffic and show connections")
@click.option(
    "--show-deleted",
    "-d",
    is_flag=True,
    help="Perform additional full filesystem checks to reveal deleted files",
)
@click.option(
    "--no-processes",
    is_flag=True,
    help="Do not monitor active processes during the action",
)
@click.option(
    "--sockets", is_flag=True, help="Monitor listening sockets during the action"
)
@click.option(
    "--screenshot",
    type=click.IntRange(min=1),
    metavar="INTERVAL",
    help="Take a screenshot each INTERVAL seconds",
)
@click.option(
    "--trigdroid",
    metavar="PACKAGE_NAME",
    help="Use the TrigDroid tool to execute malware triggers in package PACKAGE_NAME",
)
@click.option(
    "--trigdroid-ccf",
    type=click.Choice(["I", "D"]),
    help="Use the TrigDroid CCF utility. I for interactive mode, D to create the default config file",
)
@click.option(
    "--hash",
    is_flag=True,
    help="Create before/after md5 hashes of all changed and new files",
)
@click.option(
    "--apk", is_flag=True, help="List all APKs from the emulator and their hashes"
)
@click.option(
    "--degrade-network",
    is_flag=True,
    help="Lower the emulator's network speed and latency to simulate UMTS/3G",
)
@click.option(
    "--whitelist",
    type=click.Path(exists=True),
    metavar="FILE",
    help="Entries in the whitelist will be excluded from any outputs",
)
@click.option("--ai", is_flag=True, help="Enable AI-powered analysis and summarization")
@click.option("--report", is_flag=True, help="Generate PDF report")
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug/verbose mode",
)
@click.option(
    "--log",
    is_flag=True,
    help="Show log messages in terminal (useful for debugging TUI issues)",
)
@click.option(
    "--interactive", "-i", is_flag=True, help="Start in legacy Rich interactive mode"
)
@click.option(
    "--fresh",
    is_flag=True,
    help="Start as if running for the first time (reset welcome screen)",
)
@click.option(
    "--view",
    type=click.Choice(["forensic", "malware", "security"]),
    default=None,
    help="Set the initial view mode (forensic, malware, or security). Default: from config or forensic",
)
@click.option(
    "--headless",
    is_flag=True,
    help="Run in headless mode without interactive UI. Requires --trigdroid or --batch.",
)
@click.option(
    "--batch",
    type=click.Path(exists=True),
    metavar="CONFIG_FILE",
    help="Batch processing config JSON file with package list and options.",
)
@click.option(
    "--mode",
    type=click.Choice(["forensic", "malware", "security", "network"]),
    default="malware",
    help="Analysis mode for headless operation. Default: malware",
)
@click.option(
    "--dexray",
    type=str,
    metavar="PACKAGE",
    default=None,
    help="Start dexray-intercept malware monitoring for PACKAGE (headless mode). Runs until Ctrl+C.",
)
@click.option(
    "--dexray-hooks",
    type=str,
    metavar="HOOKS",
    default=None,
    help="Comma-separated hook groups for dexray (default: all). Options: aes,web,socket,filesystem,database,dex,java_dex",
)
@click.option(
    "--dexray-fritap",
    is_flag=True,
    help="Enable built-in FriTap during dexray monitoring",
)
@click.option(
    "--proxy",
    type=str,
    metavar="IP:PORT",
    default=None,
    help="Set HTTP proxy on device (headless mode). Use --proxy-clear to remove.",
)
@click.option(
    "--proxy-clear",
    is_flag=True,
    help="Clear HTTP proxy settings on device (headless mode)",
)
@click.option(
    "--install-apk",
    type=click.Path(exists=True),
    metavar="PATH",
    default=None,
    help="Install APK on device (headless mode)",
)
@click.option(
    "--import-action",
    type=click.Path(exists=True),
    metavar="PATH",
    default=None,
    help="Import action recording file (headless mode)",
)
@click.option(
    "--device-settings",
    type=click.Path(exists=True),
    metavar="FILE",
    default=None,
    help="Apply device settings from JSON file (headless mode)",
)
@click.option(
    "--preset",
    type=str,
    metavar="CODE",
    default=None,
    help="Apply country preset to device (e.g., de, us, ru, cn)",
)
@click.option(
    "--fritap",
    type=str,
    metavar="PACKAGE",
    default=None,
    help="Start FriTap SSL/TLS key extraction for PACKAGE (headless mode). Runs until Ctrl+C.",
)
@click.option(
    "--fridump",
    type=str,
    metavar="PACKAGE",
    default=None,
    help="Dump memory of PACKAGE using Fridump (headless mode). App must be running.",
)
@click.option(
    "--duration",
    type=click.IntRange(min=5),
    default=60,
    help="Network capture duration in seconds (headless network mode only). Default: 60",
)
@click.option(
    "--with-fritap",
    type=str,
    metavar="PACKAGE",
    default=None,
    help="Combine network capture with FriTap SSL keylog for PACKAGE (headless network mode only)",
)
@click.version_option(version=__version__, prog_name="sandroid")
def main(
    config: str | None,
    environment: str | None,
    file: str | None,
    loglevel: str | None,
    number: int | None,
    avoid_strong_noise_filter: bool,
    network: bool,
    show_deleted: bool,
    no_processes: bool,
    sockets: bool,
    screenshot: int | None,
    trigdroid: str | None,
    trigdroid_ccf: str | None,
    hash: bool,
    apk: bool,
    degrade_network: bool,
    whitelist: str | None,
    ai: bool,
    report: bool,
    debug: bool,
    log: bool,
    interactive: bool,
    fresh: bool,
    view: str | None,
    headless: bool,
    batch: str | None,
    mode: str,
    dexray: str | None,
    dexray_hooks: str | None,
    dexray_fritap: bool,
    proxy: str | None,
    proxy_clear: bool,
    install_apk: str | None,
    import_action: str | None,
    device_settings: str | None,
    preset: str | None,
    fritap: str | None,
    fridump: str | None,
    duration: int,
    with_fritap: str | None,
) -> None:
    """Sandroid: Extract forensic and malware artifacts from Android Virtual Devices.

    Main entry point for the Sandroid CLI application. Handles configuration
    loading, logging setup, and dispatches to the appropriate execution mode:

    1. Default mode: Textual TUI (when running just 'sandroid')
    2. Legacy Rich mode (-i flag): Classic Rich-based interactive menu
    3. Automated analysis: Command-line driven analysis with --trigdroid
    4. Headless mode (--headless): Programmatic API-based analysis
    """
    # Initialize console with default theme (re-initialized with config theme later)
    SandroidConsole.initialize()
    console = SandroidConsole.get()

    # --- Fresh start: remove welcome marker so first-run screen appears ---
    if fresh:
        from sandroid.tui.app import SandroidTUI

        marker = SandroidTUI._get_user_config_dir() / ".tui_welcome_shown"
        if marker.exists():
            marker.unlink()
            logger.debug("Removed welcome marker: %s", marker)

    # --- Configuration bootstrap -------------------------------------------
    from .config import ConfigLoader

    try:
        loader = ConfigLoader()
        if not loader._config_files:
            console.print("[error]Error: No configuration found![/error]")
            console.print(
                "[warning]Please run 'sandroid-config init' first to set up Sandroid.[/warning]"
            )
            console.print("This will create the necessary configuration files.")
            sys.exit(1)
    except Exception:
        console.print("[error]Error: Configuration system not available![/error]")
        console.print(
            "[warning]Please run 'sandroid-config init' first to set up Sandroid.[/warning]"
        )
        sys.exit(1)

    # --- Import heavy modules (lazy, so --version stays fast) ---------------
    try:
        import argparse

        from .core.actionQ import ActionQ
        from .core.adb import Adb
        from .core.AI_processing import AIProcessing
        from .core.pdf_report import PDFReport
        from .core.toolbox import Toolbox

        # Build legacy argparse namespace expected by Toolbox / ActionQ
        mock_args = argparse.Namespace(
            screenshot=screenshot,
            number_of_runs=number if number else 2,
            avoid_strong_noise_filter=avoid_strong_noise_filter,
            network=network,
            show_deleted=show_deleted,
            processes=not no_processes,
            sockets=sockets,
            trigdroid=trigdroid,
            trigdroid_ccf=trigdroid_ccf,
            hash=locals()["hash"],  # Avoid collision with builtin hash()
            apk=apk,
            degrade_network=degrade_network,
            whitelist=whitelist,
            file=file if file else "sandroid.json",
            loglevel=loglevel if loglevel else "INFO",
            ai=ai,
            report=report,
            debug=debug,
        )
        Toolbox.args = mock_args

    except ImportError as e:
        console.print(f"[error]Error: Could not import analysis modules: {e}[/error]")
        console.print("[warning]This indicates a packaging issue.[/warning]")
        console.print("Try reinstalling with: pip install --upgrade sandroid")
        sys.exit(1)

    # --- Load config with CLI overrides ------------------------------------
    try:
        cli_overrides = build_cli_overrides(
            file=file,
            debug=debug,
            loglevel=loglevel,
            number=number,
            whitelist=whitelist,
            avoid_strong_noise_filter=avoid_strong_noise_filter,
            network=network,
            show_deleted=show_deleted,
            no_processes=no_processes,
            sockets=sockets,
            screenshot=screenshot,
            hash_files=locals()["hash"],
            apk=apk,
            degrade_network=degrade_network,
            trigdroid=trigdroid,
            trigdroid_ccf=trigdroid_ccf,
            ai=ai,
            report=report,
        )

        sandroid_config = loader.load(
            config_file=config, environment=environment, cli_overrides=cli_overrides
        )

        # Re-initialize console with the configured theme preset
        SandroidConsole.initialize(sandroid_config.theme.preset)
        console = SandroidConsole.get()

        # Set the initial view mode
        initial_view = (
            view if view is not None else sandroid_config.analysis.default_view
        )
        get_ui_service().set_current_view(initial_view)

        # Determine if we're using TUI mode
        use_tui = not interactive

        # Setup logging
        active_logger = setup_logging(
            sandroid_config,
            tui_mode=use_tui,
            show_terminal_log=log,
        )

        # Setup environment variables for legacy code
        os.environ["RESULTS_PATH"] = str(sandroid_config.paths.results_path)
        os.environ["RAW_RESULTS_PATH"] = str(sandroid_config.paths.raw_results_path)

        # --- Mode dispatch -------------------------------------------------
        from .cli_modes import (
            run_analysis,
            run_dexray_headless,
            run_fridump_headless,
            run_fritap_headless,
            run_headless_analysis,
            run_network_headless,
            start_interactive_mode,
        )

        if device_settings or preset:
            from .cli_modes.device_settings import run_device_settings_headless

            run_device_settings_headless(
                sandroid_config,
                settings_file=device_settings,
                preset=preset,
            )
        elif dexray:
            run_dexray_headless(
                sandroid_config=sandroid_config,
                active_logger=active_logger,
                package=dexray,
                output_file=file,
                hook_groups=dexray_hooks,
                enable_fritap=dexray_fritap,
            )
        elif proxy:
            _run_proxy_command(sandroid_config, proxy=proxy)
        elif proxy_clear:
            _run_proxy_command(sandroid_config, clear=True)
        elif install_apk:
            _run_install_apk(sandroid_config, install_apk)
        elif import_action:
            _run_import_action(sandroid_config, import_action)
        elif fridump:
            run_fridump_headless(
                sandroid_config=sandroid_config,
                active_logger=active_logger,
                package=fridump,
            )
        elif fritap:
            run_fritap_headless(
                sandroid_config=sandroid_config,
                active_logger=active_logger,
                package=fritap,
                output_file=file,
            )
        elif headless and mode == "network":
            run_network_headless(
                sandroid_config=sandroid_config,
                active_logger=active_logger,
                duration=duration,
                with_fritap=with_fritap,
                output_file=file,
            )
        elif headless or batch:
            run_headless_analysis(
                sandroid_config=sandroid_config,
                active_logger=active_logger,
                package=trigdroid,
                batch_config=batch,
                mode=mode,
                runs=number or 2,
                network=network,
                hash_files=locals()["hash"],
                show_deleted=show_deleted,
                output_file=file,
            )
        elif bool(trigdroid):
            # Automated analysis with --trigdroid flag
            if sandroid_config.log_level.value != "DEBUG":
                os.system("cls" if os.name == "nt" else "clear")  # nosec S605
            SandroidConsole.print_logo()
            run_analysis(
                sandroid_config,
                active_logger,
                Toolbox,
                Adb,
                ActionQ,
                AIProcessing,
                PDFReport,
            )
        else:
            # Default: TUI mode (or legacy Rich mode with -i)
            start_interactive_mode(
                sandroid_config,
                active_logger,
                Toolbox,
                Adb,
                use_tui=use_tui,
                show_terminal_log=log,
            )

    except Exception as e:
        console.print(f"[error]Error: {e}[/error]")
        sys.exit(1)


def _run_proxy_command(
    sandroid_config,
    proxy: str | None = None,
    clear: bool = False,
) -> None:
    """Execute proxy set/clear in headless mode."""
    from .core.initializer import initialize_core
    from .services import get_proxy_service

    console = SandroidConsole.get()
    initialize_core(sandroid_config)
    proxy_service = get_proxy_service()

    if clear:
        if proxy_service.clear_proxy():
            console.print("[success]Proxy cleared[/success]")
        else:
            console.print("[error]Failed to clear proxy[/error]")
            sys.exit(1)
    elif proxy:
        if ":" not in proxy:
            console.print("[error]Proxy must be in IP:PORT format[/error]")
            sys.exit(1)
        ip, port = proxy.rsplit(":", 1)
        if proxy_service.set_proxy(ip, port):
            console.print(f"[success]Proxy set to {ip}:{port}[/success]")
        else:
            console.print(f"[error]Failed to set proxy to {ip}:{port}[/error]")
            sys.exit(1)


def _run_install_apk(sandroid_config, apk_path: str) -> None:
    """Install APK on device in headless mode."""
    from .core.adb import Adb
    from .core.initializer import initialize_core

    console = SandroidConsole.get()
    initialize_core(sandroid_config)

    console.print(f"[accent]Installing APK: {apk_path}[/accent]")
    _stdout, stderr = Adb.install_apk(apk_path)
    if stderr and "success" not in stderr.lower():
        console.print(f"[error]APK install failed: {stderr}[/error]")
        sys.exit(1)
    console.print("[success]APK installed successfully[/success]")


def _run_import_action(sandroid_config, action_path: str) -> None:
    """Import an action file in headless mode."""
    import json

    from .core.initializer import initialize_core

    console = SandroidConsole.get()
    initialize_core(sandroid_config)

    try:
        with open(action_path, encoding="utf-8") as f:
            action_data = json.load(f)
        console.print(f"[success]Action imported from: {action_path}[/success]")
        console.print(
            f"[dim]Actions loaded: {len(action_data) if isinstance(action_data, list) else 'N/A'}[/dim]"
        )
    except (json.JSONDecodeError, FileNotFoundError) as e:
        console.print(f"[error]Failed to import action: {e}[/error]")
        sys.exit(1)


if __name__ == "__main__":
    main()
