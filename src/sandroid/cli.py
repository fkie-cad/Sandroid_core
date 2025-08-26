"""Main CLI entry point for Sandroid."""

import logging
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click
from colorama import Fore, Style
from rich.console import Console
from rich.logging import RichHandler

# Import version first (no dependencies)
from ._version import __version__

# Import SandroidConfig for type hints (used in function signatures)
from .config import SandroidConfig

# Type hints for heavy modules (runtime imports are lazy in main())
if TYPE_CHECKING:
    from .core.actionQ import ActionQ
    from .core.adb import Adb
    from .core.AI_processing import AIProcessing
    from .core.pdf_report import PDFReport
    from .core.toolbox import Toolbox


console = Console()


def setup_logging(config: SandroidConfig) -> logging.Logger:
    """Setup logging with Rich handler."""
    # Configure root logger
    logging.basicConfig(
        level=config.log_level.value,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )

    # Setup file logging
    log_file = config.paths.results_path / "sandroid.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)

    logger = logging.getLogger("sandroid")
    logger.addHandler(file_handler)

    return logger


def pretty_logo():
    """Print the Sandroid logo."""
    green = "\033[92m"
    clear = "\033[0m"

    print(f"""
{green}⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀{clear}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀
{green}⠀⠀⠀⠀⠀⠙⢷⣤⣤⣴⣶⣶⣦⣤⣤⡾⠋⠀⠀⠀⠀⠀⠀{clear}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀
{green}⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀{clear}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀
{green}⠀⠀⠀⠀⣼⣿⣿⣉⣹⣿⣿⣿⣿⣏⣉⣿⣿⣧⠀⠀⠀⠀⠀{clear}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀
{green}⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀{clear}⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀
{green}⣠⣄⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣠⣄⠀{clear}⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀
{green}⣿⣿⡇⢸⣿⣿⣿{clear}Sandroid{green}⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀{clear}⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀
{green}⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀{clear}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀
{green}⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀{clear}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀
{green}⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀{clear}⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀
{green}⠻⠟⠁⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠈⠻⠟⠀{clear}⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{green}⠀⠀⠀⠀⠉⠉⣿⣿⣿⡏⠉⠉⢹⣿⣿⣿⠉⠉⠀⠀⠀⠀⠀{clear}⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{green}⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀{clear}⠀⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{green}⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀{clear}⢀⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{green}⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀{clear}⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀""")


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
@click.option("--interactive", "-i", is_flag=True, help="Start in interactive mode")
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
    interactive: bool,
):
    """Sandroid: Extract forensic artifacts from Android Virtual Devices."""
    # Lazy imports - only load heavy modules when actually running (not for --version)
    from .config import ConfigLoader, SandroidConfig

    # Check if user has run sandroid-config init
    try:
        loader = ConfigLoader()
        # Try to load config to see if it's been initialized
        config_files = loader._config_files
        if not config_files:
            console.print("[red]Error: No configuration found!")
            console.print(
                "[yellow]Please run 'sandroid-config init' first to set up Sandroid."
            )
            console.print("This will create the necessary configuration files.")
            sys.exit(1)
    except Exception:
        console.print("[red]Error: Configuration system not available!")
        console.print(
            "[yellow]Please run 'sandroid-config init' first to set up Sandroid."
        )
        sys.exit(1)

    # Import analysis modules from modern package structure
    try:
        # Initialize Toolbox args with CLI parameters
        import argparse

        from .core.actionQ import (
            ActionQ,  # Direct import to avoid circular dependencies
        )
        from .core.adb import Adb
        from .core.AI_processing import AIProcessing
        from .core.pdf_report import PDFReport
        from .core.toolbox import Toolbox

        mock_args = argparse.Namespace()
        mock_args.screenshot = screenshot
        mock_args.number_of_runs = number if number else 2
        mock_args.avoid_strong_noise_filter = avoid_strong_noise_filter
        mock_args.network = network
        mock_args.show_deleted = show_deleted
        mock_args.no_processes = no_processes
        mock_args.sockets = sockets
        mock_args.trigdroid = trigdroid
        mock_args.trigdroid_ccf = trigdroid_ccf
        mock_args.hash = locals()["hash"]  # Avoid collision with builtin hash()
        mock_args.apk = apk
        mock_args.degrade_network = degrade_network
        mock_args.whitelist = whitelist
        mock_args.file = file if file else "sandroid.json"
        mock_args.loglevel = loglevel if loglevel else "INFO"
        mock_args.ai = ai
        mock_args.report = report

        # Set the args to satisfy dependencies
        Toolbox.args = mock_args

    except ImportError as e:
        console.print(f"[red]Error: Could not import analysis modules: {e}")
        console.print("[yellow]This indicates a packaging issue.")
        console.print("Try reinstalling with: pip install --upgrade sandroid")
        sys.exit(1)

    try:
        # We already have the loader from the config check above

        # Build CLI overrides
        cli_overrides = {}
        if file:
            cli_overrides["output_file"] = file
        if loglevel:
            cli_overrides["log_level"] = loglevel
        if number:
            cli_overrides["analysis"] = {"number_of_runs": number}
        if whitelist:
            cli_overrides["whitelist_file"] = whitelist

        # Analysis settings
        analysis_overrides = {}
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
        if hash:
            analysis_overrides["hash_files"] = True
        if apk:
            analysis_overrides["list_apks"] = True
        if degrade_network:
            analysis_overrides["degrade_network"] = True

        if analysis_overrides:
            cli_overrides["analysis"] = analysis_overrides

        # TrigDroid settings
        if trigdroid or trigdroid_ccf:
            trigdroid_overrides = {"enabled": True}
            if trigdroid:
                trigdroid_overrides["package_name"] = trigdroid
            if trigdroid_ccf:
                trigdroid_overrides["config_mode"] = trigdroid_ccf
            cli_overrides["trigdroid"] = trigdroid_overrides

        # AI settings
        if ai:
            cli_overrides["ai"] = {"enabled": True}

        # Report settings
        if report:
            cli_overrides["report"] = {"generate_pdf": True}

        # Load the configuration
        sandroid_config = loader.load(
            config_file=config, environment=environment, cli_overrides=cli_overrides
        )

        # Setup logging
        logger = setup_logging(sandroid_config)

        # Clear screen if not debug
        if sandroid_config.log_level != "DEBUG":
            os.system("cls" if os.name == "nt" else "clear")  # nosec S605 # Safe terminal clear command

        # Show logo
        pretty_logo()

        # Setup environment variables for legacy code
        os.environ["RESULTS_PATH"] = str(sandroid_config.paths.results_path)
        os.environ["RAW_RESULTS_PATH"] = str(sandroid_config.paths.raw_results_path)

        if interactive:
            # Start interactive mode
            start_interactive_mode(sandroid_config, logger, Toolbox, Adb)
        else:
            # Run analysis
            run_analysis(
                sandroid_config, logger, Toolbox, Adb, ActionQ, AIProcessing, PDFReport
            )

    except Exception as e:
        console.print(f"[red]Error: {e}")
        sys.exit(1)


def start_interactive_mode(
    config: SandroidConfig, logger: logging.Logger, Toolbox, Adb
):
    """Start interactive menu mode."""
    # Import and initialize legacy components
    Toolbox.config = config  # Pass config to legacy code
    Toolbox.init()
    Adb.init()
    Toolbox.check_setup()

    # TODO: Implement interactive menu using rich/click
    console.print("[yellow]Interactive mode not yet implemented in the new CLI.")
    console.print("Please use the legacy ./sandroid script for interactive mode.")
    console.print("Run 'sandroid --help' for command-line options.")


def run_analysis(
    config: SandroidConfig,
    logger: logging.Logger,
    Toolbox,
    Adb,
    ActionQ,
    AIProcessing,
    PDFReport,
):
    """Run forensic analysis."""
    try:
        # Initialize legacy components with new config
        Toolbox.config = config  # Pass config to legacy code
        Toolbox.init()
        Adb.init()
        Toolbox.check_setup()

        # Create and assemble action queue
        q = ActionQ()
        q.assembleQ()

        # Process action queue
        while not q.finished:
            q.do_next()

        # Handle AI summarization if enabled
        action = ""
        if config.ai.enabled:
            recording_path = config.paths.raw_results_path / "recording.webm"
            if recording_path.exists():
                action = AIProcessing.summarize_video(str(recording_path))

        # Finalize
        Toolbox.wrap_up()

        # Write results
        output_file = config.paths.results_path / config.output_file.name
        with open(output_file, "w") as fd:
            fd.write(q.get_data())

        # Display results
        if config.ai.enabled and action:
            print(
                Fore.GREEN
                + Style.BRIGHT
                + f"Sandroid Results for the action: {action}"
                + Style.RESET_ALL
            )

        print(q.get_pretty_print())

        # Generate PDF report if enabled
        if config.report.generate_pdf:
            pdf_path = config.paths.results_path / "Sandroid_Forensic_Report.pdf"
            PDFReport(str(pdf_path), str(output_file))
            logger.info(f"PDF report generated: {pdf_path}")

        logger.info("Analysis completed successfully")

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise


if __name__ == "__main__":
    main()
