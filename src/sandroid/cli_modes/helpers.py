"""CLI helper utilities for Sandroid.

Contains the logging setup and CLI-override builder functions used
by the main Click entry point.
"""

import logging

from rich.logging import RichHandler

from sandroid.config import SandroidConfig
from sandroid.core.console import SandroidConsole


def setup_logging(
    config: SandroidConfig, tui_mode: bool = False, show_terminal_log: bool = False
) -> logging.Logger:
    """Configure and initialize the logging system with appropriate handlers.

    Sets up logging based on the application mode. In TUI mode, logs are routed
    through the EventBus to the ActivityLog widget. In Rich mode (or when
    --log flag is set), logs are displayed in the terminal with Rich formatting.

    Note:
        File logging is NOT configured here. It is set up later by
        Toolbox.init_files() after the timestamped session folder is created,
        ensuring logs go to results/YYYYMMDD_HHMMSS/sandroid.log.

    Args:
        config: Sandroid configuration containing log level and other settings.
        tui_mode: If True, route logs to EventBus for TUI display instead of
            console output (default: False).
        show_terminal_log: If True, show logs in terminal even in TUI mode.

    Returns:
        Configured logger instance for the 'sandroid' namespace.
    """
    console = SandroidConsole.get()
    handlers: list[logging.Handler] = []

    if tui_mode and not show_terminal_log:
        from sandroid.core.events import TUILoggingHandler, set_tui_mode

        set_tui_mode(True)
        tui_handler = TUILoggingHandler()
        tui_handler.setLevel(logging.INFO)
        tui_handler.setFormatter(logging.Formatter("%(message)s"))
        handlers.append(tui_handler)
    else:
        handlers.append(RichHandler(console=console, rich_tracebacks=True))

    logging.basicConfig(
        level=config.log_level.value,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
        force=True,
    )

    return logging.getLogger("sandroid")


def build_cli_overrides(
    *,
    file: str | None,
    debug: bool,
    loglevel: str | None,
    number: int | None,
    whitelist: str | None,
    avoid_strong_noise_filter: bool,
    network: bool,
    show_deleted: bool,
    no_processes: bool,
    sockets: bool,
    screenshot: int | None,
    hash_files: bool,
    apk: bool,
    degrade_network: bool,
    trigdroid: str | None,
    trigdroid_ccf: str | None,
    report: bool,
) -> dict:
    """Translate Click parameters into the nested override dict for ConfigLoader.

    Args:
        file: Output file path.
        debug: Whether debug mode is enabled.
        loglevel: Explicit log level override.
        number: Number of analysis runs.
        whitelist: Path to whitelist file.
        avoid_strong_noise_filter: Disable dry-run noise filter.
        network: Enable network monitoring.
        show_deleted: Show deleted files.
        no_processes: Disable process monitoring.
        sockets: Enable socket monitoring.
        screenshot: Screenshot interval in seconds.
        hash_files: Enable file hashing.
        apk: List APKs from emulator.
        degrade_network: Simulate degraded network.
        trigdroid: TrigDroid package name.
        trigdroid_ccf: TrigDroid CCF mode.
        report: Generate PDF report.

    Returns:
        Dictionary of CLI overrides for ``ConfigLoader.load(cli_overrides=...)``.
    """
    cli_overrides: dict = {}

    if file:
        cli_overrides["output_file"] = file
    if debug and not loglevel:
        cli_overrides["log_level"] = "DEBUG"
    elif loglevel:
        cli_overrides["log_level"] = loglevel
    if whitelist:
        cli_overrides["whitelist_file"] = whitelist

    # Analysis settings
    analysis_overrides: dict = {}
    if number:
        analysis_overrides["number_of_runs"] = number
    if avoid_strong_noise_filter:
        analysis_overrides["avoid_strong_noise_filter"] = True
    if network:
        analysis_overrides["monitor_network"] = True
    if show_deleted:
        analysis_overrides["show_deleted_files"] = True
    if no_processes:
        analysis_overrides["monitor_processes"] = False
    if sockets:
        analysis_overrides["monitor_sockets"] = True
    if screenshot:
        analysis_overrides["screenshot_interval"] = screenshot
    if hash_files:
        analysis_overrides["hash_files"] = True
    if apk:
        analysis_overrides["list_apks"] = True
    if degrade_network:
        analysis_overrides["degrade_network"] = True
    if analysis_overrides:
        cli_overrides["analysis"] = analysis_overrides

    # TrigDroid settings
    if trigdroid or trigdroid_ccf:
        trigdroid_overrides: dict = {"enabled": True}
        if trigdroid:
            trigdroid_overrides["package_name"] = trigdroid
        if trigdroid_ccf:
            trigdroid_overrides["config_mode"] = trigdroid_ccf
        cli_overrides["trigdroid"] = trigdroid_overrides

    if report:
        cli_overrides["report"] = {"generate_pdf": True}

    return cli_overrides
