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
    "--serial",
    "-s",
    metavar="SERIAL",
    default=None,
    help=(
        "ADB serial of the device to use (e.g. emulator-5556). Default: "
        "$ANDROID_SERIAL, then config emulator.serial, then auto-select "
        "(prefers emulators)."
    ),
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
    hidden=True,  # not functional with the current TrigDroid API -- see main()
    help="(Unsupported) TrigDroid CCF utility",
)
@click.option(
    "--hash",
    is_flag=True,
    help="Create before/after MD5 + SHA-256 hashes of all changed and new files",
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
@click.option("--report", is_flag=True, help="Generate PDF report")
@click.option(
    "--report-from",
    type=click.Path(exists=True, file_okay=False),
    metavar="DIR",
    default=None,
    help="(Re)generate the PDF report from an existing results folder and exit "
    "(no device needed)",
)
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
    "--fresh",
    is_flag=True,
    help="Start as if running for the first time (reset welcome screen)",
)
@click.option(
    "--headless",
    is_flag=True,
    help=(
        "Run in headless mode without interactive UI. Malware/security modes "
        "need --trigdroid PACKAGE (or --batch); forensic mode needs no package."
    ),
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
    help=(
        "Replay a TUI recording headless: PATH is a run bundle's recording.txt "
        "(or the bundle folder). Runs a forensic analysis that replays it in "
        "every run (-n, --report, --network, ... apply)."
    ),
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
    serial: str | None,
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
    report: bool,
    debug: bool,
    log: bool,
    fresh: bool,
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
    report_from: str | None = None,
) -> None:
    r"""Sandroid: Extract forensic and malware artifacts from Android Virtual Devices.

    Main entry point for the Sandroid CLI application. Handles configuration
    loading, logging setup, and dispatches to the appropriate execution mode:

    \b
    1. Default mode: Textual TUI (when running just 'sandroid')
    2. Automated analysis: Command-line driven analysis with --trigdroid
    3. Headless mode (--headless): Programmatic API-based analysis
    """
    # Initialize console with default theme (re-initialized with config theme later)
    SandroidConsole.initialize()
    console = SandroidConsole.get()

    # --trigdroid-ccf is kept (hidden) only so old scripts get a clear error
    # instead of "no such option": the TrigDroid CCF utility has no
    # equivalent in the current TrigDroid API, so it never did anything.
    if trigdroid_ccf:
        raise click.UsageError(
            "--trigdroid-ccf is not supported in Sandroid 2.x (the TrigDroid "
            "CCF utility is not available with the current TrigDroid API). "
            "Configure TrigDroid via the [trigdroid] section of the config "
            "file instead (sandroid-config show / set)."
        )

    # --- Offline report generation (no config/device needed) ---------------
    if report_from:
        from .cli_modes.report import run_report_from

        sys.exit(run_report_from(report_from))

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
        # An explicit --config file, an --environment config or SANDROID_*
        # environment variables are all valid configuration sources on their
        # own -- only refuse when there is none at all.
        has_config_source = bool(
            loader._config_files
            or config
            or environment
            or loader.load_environment_vars()
        )
        if not has_config_source:
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
            report=report,
            serial=serial,
        )

        sandroid_config = loader.load(
            config_file=config, environment=environment, cli_overrides=cli_overrides
        )

        # Device selection precedence: --serial > $ANDROID_SERIAL > config.
        if not serial and os.environ.get("ANDROID_SERIAL"):
            sandroid_config.emulator.serial = os.environ["ANDROID_SERIAL"]

        # Make get_config() (run history/bundles, services) return this exact
        # config instead of re-loading defaults from disk.
        from .config import set_config

        set_config(sandroid_config, source_file=config)

        # Re-initialize console with the configured theme preset
        SandroidConsole.initialize(sandroid_config.theme.preset)
        console = SandroidConsole.get()

        # View modes were removed from the UI (the --view flag is gone); the
        # remaining view-aware lookups (ActionQ key dispatch) use the config
        # default.
        get_ui_service().set_current_view(sandroid_config.analysis.default_view)

        # Setup logging (the Textual TUI is the only interactive UI)
        active_logger = setup_logging(
            sandroid_config,
            tui_mode=True,
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
            _run_import_action(
                sandroid_config,
                import_action,
                active_logger=active_logger,
                runs=number or sandroid_config.analysis.number_of_runs,
                network=network,
                hash_files=locals()["hash"],
                show_deleted=show_deleted,
                output_file=file,
            )
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
                runs=number or sandroid_config.analysis.number_of_runs,
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
                PDFReport,
            )
        else:
            # Default: Textual TUI
            start_interactive_mode(
                sandroid_config,
                active_logger,
                Toolbox,
                Adb,
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
    initialize_core(sandroid_config, prepare=True)
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
    from .core.exceptions import APKInstallError
    from .core.initializer import initialize_core

    console = SandroidConsole.get()
    # pm install from the adb-root context needs SELinux permissive, otherwise
    # it fails with "Failed transaction (2147483646)".
    initialize_core(sandroid_config, prepare=True)

    console.print(f"[accent]Installing APK: {apk_path}[/accent]")
    try:
        # Returns the package name (or None if aapt couldn't determine it);
        # raises APKInstallError on failure.
        package_name = Adb.install_apk(apk_path)
    except APKInstallError as e:
        console.print(f"[error]APK install failed: {e}[/error]")
        sys.exit(1)
    suffix = f" ({package_name})" if package_name else ""
    console.print(f"[success]APK installed successfully{suffix}[/success]")


def resolve_recording(action_path: str) -> tuple[str | None, str | None]:
    """Validate an ``--import-action`` argument.

    Accepts a ``recording.txt`` (``<timestamp> <device> <type> <code> <value>``
    lines as written by the TUI recorder) or a run bundle folder containing
    one.

    Returns:
        ``(absolute recording path, None)`` or ``(None, error message)``.
    """
    from pathlib import Path

    from .features.player import Player

    path = Path(action_path)
    if path.is_dir():
        path = path / "recording.txt"
    if not path.is_file():
        return None, f"No recording found: {path}"
    try:
        lines = [
            ln.strip()
            for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
    except (OSError, UnicodeDecodeError) as e:
        return None, f"Cannot read {path}: {e}"
    if not lines:
        return None, f"Recording is empty: {path}"
    if lines[0].startswith(("{", "[")):
        return None, (
            f"{path} is a JSON file. JSON action files cannot be replayed; pass "
            "a recording.txt from a run bundle (or the bundle folder) instead."
        )
    bad = [ln for ln in lines if not Player.STORE_LINE_RE.match(ln)]
    if bad:
        return None, (
            f"{path} is not a Sandroid recording ({len(bad)} of {len(lines)} "
            f"lines are not '<timestamp> <device> <type> <code> <value>'; "
            f"first: {bad[0][:80]!r})"
        )
    return str(path.resolve()), None


def _run_import_action(
    sandroid_config,
    action_path: str,
    *,
    active_logger=None,
    runs: int = 2,
    network: bool = False,
    hash_files: bool = False,
    show_deleted: bool = False,
    output_file: str | None = None,
) -> None:
    """Replay a recording headless as a forensic analysis (``--import-action``).

    The recording is replayed via the Player in every run, starting from the
    device's current state (a ``tmp`` snapshot is taken first), so start the
    device in the state the recording expects (same app screen).
    """
    from .cli_modes import run_headless_analysis

    console = SandroidConsole.get()
    recording, error = resolve_recording(action_path)
    if error:
        console.print(f"[error]Cannot import action: {error}[/error]")
        sys.exit(1)
    run_headless_analysis(
        sandroid_config=sandroid_config,
        active_logger=active_logger,
        package=None,
        batch_config=None,
        mode="forensic",
        runs=runs,
        network=network,
        hash_files=hash_files,
        show_deleted=show_deleted,
        output_file=output_file,
        recording_path=recording,
    )


if __name__ == "__main__":
    main()
