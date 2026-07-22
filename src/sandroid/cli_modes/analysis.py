"""Automated forensic analysis mode dispatcher for Sandroid.

Handles the non-interactive, command-line driven analysis workflow
(e.g., triggered by --trigdroid flags).
"""

import json
import logging
import sys

from sandroid.config import SandroidConfig
from sandroid.core.console import SandroidConsole
from sandroid.core.json_utils import json_encoder
from sandroid.services import (
    get_setup_service,
    get_spotlight_service,
    get_task_service,
    get_ui_service,
)

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
    unified-engine execution, result generation, and optional PDF report
    creation. This is the primary entry point for non-interactive,
    command-line driven analysis (the ``--trigdroid`` path).

    The legacy ``ActionQ.assembleQ()``/``do_next()`` pump is gone; this
    reaches the same :class:`~sandroid.analysis.engine.AnalysisEngine` the TUI
    and headless paths use. The pre-analysis setup ``assembleQ`` performed
    (TrigDroid CCF, network degradation, spotlight spawn app, and the initial
    ``tmp`` snapshot) is replicated here, gated on the same options as before,
    because the engine's first step reverts to that snapshot.

    Args:
        config: Sandroid configuration containing analysis parameters,
            paths, and report options.
        active_logger: Configured logger instance for status and error messages.
        Toolbox: The Toolbox class for core utility operations.
        Adb: The Adb class for Android Debug Bridge operations.
        ActionQ: The ActionQ class (retained for signature compatibility; the
            unified engine no longer uses it).
        PDFReport: The PDFReport class for generating PDF reports.

    Raises:
        SystemExit: If environment validation fails.
        Exception: Re-raised if analysis fails for any reason.
    """
    try:
        from sandroid.analysis.engine import AnalysisEngine
        from sandroid.analysis.run_config import RunConfig
        from sandroid.core.initializer import initialize_core
        from sandroid.features.trigdroid import Trigdroid

        initialize_core(config)

        # Critical environment validation only (deferred checks not needed
        # for non-interactive mode)
        setup_result = get_setup_service().check_critical_setup()
        if not setup_result.success:
            logger.critical(f"Setup validation failed: {setup_result.message}")
            for error in setup_result.errors:
                logger.error(f"  - {error}")
            sys.exit(1)

        # --- Pre-analysis setup (replicates legacy ActionQ.assembleQ) --------
        # TrigDroid CCF runs (and exits) before anything else. run_ccf() reads
        # Toolbox.args.trigdroid_ccf, which cli.py still populates.
        if config.trigdroid.config_mode:
            Trigdroid().run_ccf()

        # Point the spotlight at the target package in spawn mode.
        if config.trigdroid.package_name:
            get_spotlight_service().set_spawn_app(
                config.trigdroid.package_name, auto_resume=True
            )
            logger.info(
                "SpotlightService initialized with package: "
                f"{config.trigdroid.package_name}"
            )

        # The engine's first step reverts to the ``tmp`` snapshot, so it must
        # exist before the run starts.
        Toolbox.create_snapshot(b"tmp")

        # Optional network degradation (copied verbatim from legacy assembleQ).
        if config.analysis.degrade_network:
            Adb.send_telnet_command("network delay umts")
            Adb.send_telnet_command("network speed umts")
        else:
            Adb.send_telnet_command("network delay none")
            Adb.send_telnet_command("network speed full")

        # --- Run the unified analysis engine ---------------------------------
        run_config = RunConfig.from_sandroid_config(config, action=Trigdroid())
        # Identity pin: CLI has no run bundle, so leave the env pointing at the
        # existing session dir (empty paths => the engine leaves RESULTS_PATH /
        # RAW_RESULTS_PATH untouched, keeping PDF screenshots + timeline
        # consistent).
        run_config.results_path = ""
        run_config.raw_results_path = ""

        result = AnalysisEngine(run_config).run()

        # Write results
        console = SandroidConsole.get()
        output_file = config.paths.results_path / config.output_file.name
        results_json = json.dumps(result.to_json_dict(), indent=4, default=json_encoder)
        _write_results(results_json, output_file, config, console)

        print(result.pretty_print())

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


def _write_results(results_json, output_file, config, console) -> None:
    """Write serialized analysis results to file with error handling.

    Args:
        results_json: Serialized JSON string of the analysis results.
        output_file: Path to write results to.
        config: Sandroid configuration.
        console: SandroidConsole instance.
    """
    try:
        with open(output_file, "w", encoding="utf-8") as fd:
            fd.write(results_json)
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
