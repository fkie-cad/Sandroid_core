"""Automated forensic analysis mode dispatcher for Sandroid.

Handles the non-interactive, command-line driven analysis workflow
(e.g., triggered by --trigdroid flags).
"""

import logging
import sys

from sandroid.config import SandroidConfig
from sandroid.core.console import SandroidConsole
from sandroid.services import get_setup_service, get_task_service, get_ui_service

logger = logging.getLogger(__name__)


def run_analysis(
    config: SandroidConfig,
    active_logger: logging.Logger,
    Toolbox,
    Adb,
    ActionQ,
    PDFReport,
) -> None:
    """Execute automated forensic analysis workflow.

    Performs a complete forensic analysis cycle including initialization,
    action queue processing, result generation, and optional PDF report
    creation. This is the primary entry point for non-interactive,
    command-line driven analysis.

    Args:
        config: Sandroid configuration containing analysis parameters,
            paths, and report options.
        active_logger: Configured logger instance for status and error messages.
        Toolbox: The Toolbox class for core utility operations.
        Adb: The Adb class for Android Debug Bridge operations.
        ActionQ: The ActionQ class for managing analysis operations.
        PDFReport: The PDFReport class for generating PDF reports.

    Raises:
        SystemExit: If environment validation fails.
        Exception: Re-raised if analysis fails for any reason.
    """
    try:
        from sandroid.core.initializer import initialize_core

        initialize_core(config)

        # Critical environment validation only (deferred checks not needed
        # for non-interactive mode)
        setup_result = get_setup_service().check_critical_setup()
        if not setup_result.success:
            logger.critical(f"Setup validation failed: {setup_result.message}")
            for error in setup_result.errors:
                logger.error(f"  - {error}")
            sys.exit(1)

        # Assemble and process action queue
        q = ActionQ()
        q.assembleQ()
        while not q.finished:
            q.do_next()

        Toolbox.wrap_up()

        # Write results
        console = SandroidConsole.get()
        output_file = config.paths.results_path / config.output_file.name
        _write_results(q, output_file, config, console)

        print(q.get_pretty_print())

        # Generate PDF report if enabled
        if config.report.generate_pdf:
            pdf_path = config.paths.results_path / "Sandroid_Forensic_Report.pdf"
            PDFReport(str(pdf_path), str(output_file))
            logger.info(f"PDF report generated: {pdf_path}")

        logger.info("Analysis completed successfully")
        get_task_service().stop_all()
        get_ui_service().print_exit_summary(Toolbox.get_tools_used())

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise


def _write_results(q, output_file, config, console) -> None:
    """Write analysis results to file with error handling.

    Args:
        q: ActionQ instance containing gathered data.
        output_file: Path to write results to.
        config: Sandroid configuration.
        console: SandroidConsole instance.
    """
    try:
        with open(output_file, "w", encoding="utf-8") as fd:
            fd.write(q.get_data())
    except FileNotFoundError:
        logger.error(f"Results directory does not exist: {config.paths.results_path}")
        console.print(
            f"[error]Cannot write results: directory {config.paths.results_path} not found[/error]"
        )
    except PermissionError:
        logger.error(f"Permission denied writing results file: {output_file}")
        console.print(
            f"[error]Cannot write results: permission denied for {output_file}[/error]"
        )
    except OSError as e:
        logger.error(f"Failed to write results to {output_file}: {e}")
        console.print(f"[error]Failed to write results: {e}[/error]")
