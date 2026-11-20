"""Automated forensic analysis mode dispatcher for Sandroid.

Handles the non-interactive, command-line driven analysis workflow
(``sandroid --package PKG``).
"""

import json
import logging
import os
import shutil
import sys
from pathlib import Path

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
    package: str | None = None,
) -> None:
    """Execute automated forensic analysis workflow.

    Performs a complete forensic analysis cycle including initialization,
    unified-engine execution, result generation, and the report
    (``report.json``/``report.md``, optional PDF). This is the primary entry
    point for non-interactive, command-line driven analysis (the ``--package``
    path). It performs no scripted action: there are no trigger actions
    until device playbooks land.

    The legacy ``ActionQ.assembleQ()``/``do_next()`` pump is gone; this
    reaches the same :class:`~sandroid.analysis.engine.AnalysisEngine` the TUI
    and headless paths use. The pre-analysis setup ``assembleQ`` performed
    (network degradation, spotlight app, and the initial ``tmp`` snapshot) is
    replicated here, gated on the same options as before,
    because the engine's first step reverts to that snapshot.

    Args:
        config: Sandroid configuration containing analysis parameters,
            paths, and report options.
        active_logger: Configured logger instance for status and error messages.
        Toolbox: The Toolbox class for core utility operations.
        Adb: The Adb class for Android Debug Bridge operations.
        ActionQ: The ActionQ class (retained for signature compatibility; the
            unified engine no longer uses it). The report is written by
            :func:`sandroid.core.run_report.finalize_run`; the PDF only when
            ``config.report.generate_pdf`` is set.
        package: Target app package (``--package``); the spotlight is
            pointed at it so the engine protects it from noise filtering.

    Raises:
        SystemExit: If environment validation fails.
        Exception: Re-raised if analysis fails for any reason.
    """
    try:
        from sandroid.analysis.engine import AnalysisEngine
        from sandroid.analysis.run_config import RunConfig
        from sandroid.core.initializer import initialize_core

        initialize_core(config, require=True)

        # Critical environment validation only (deferred checks not needed
        # for non-interactive mode)
        setup_result = get_setup_service().check_critical_setup()
        if not setup_result.success:
            logger.critical(f"Setup validation failed: {setup_result.message}")
            for error in setup_result.errors:
                logger.error(f"  - {error}")
            sys.exit(1)

        # --- Pre-analysis setup (replicates legacy ActionQ.assembleQ) --------
        # Point the spotlight at the target package.
        if package:
            get_spotlight_service().set_app(package)
            logger.info(f"SpotlightService initialized with package: {package}")

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
        run_config = RunConfig.from_sandroid_config(config)
        # Identity pin: CLI has no run bundle, so leave the env pointing at the
        # existing session dir (empty paths => the engine leaves RESULTS_PATH /
        # RAW_RESULTS_PATH untouched, keeping the raw pulls and the session
        # timeline in the same session folder).
        run_config.results_path = ""
        run_config.raw_results_path = ""

        from sandroid.core.run_report import (
            describe_run_settings,
            finalize_run,
            iso_now,
        )

        started_at = iso_now()
        result = AnalysisEngine(run_config).run()
        ended_at = iso_now()

        # Write results JSON (+ run metadata), optional PDF and the evidence
        # manifest via the shared finalisation step.
        console = SandroidConsole.get()
        # The session folder (where the raw pulls, screenshots and logs of
        # this run live), like the headless path -- not the base results
        # directory shared by every session.
        result_dir = Path(
            os.environ.get("SESSION_PATH") or str(config.paths.results_path)
        )
        output_file = result_dir / config.output_file.name
        documentation_failed = False
        try:
            outcome = finalize_run(
                result_dir,
                result.to_json_dict(),
                output_name=config.output_file.name,
                adb=Adb,
                config=config,
                started_at=started_at,
                ended_at=ended_at,
                mode="cli-malware",
                generate_pdf=config.report.generate_pdf,
                run_settings=describe_run_settings(run_config),
            )
            final_json = _deliver_to_requested_path(
                outcome.results_json, config.output_file
            )
            console.print(f"[success]Results: {final_json}[/success]")
            if outcome.report_json is not None:
                console.print(f"[success]Report: {outcome.report_json}[/success]")
            if outcome.markdown is not None:
                console.print(f"[success]Markdown: {outcome.markdown}[/success]")
            if outcome.pdf is not None:
                console.print(f"[success]PDF report: {outcome.pdf}[/success]")
            for err in outcome.errors:
                documentation_failed = True
                console.print(f"{err}", style="error", soft_wrap=True, markup=False)
        except OSError:
            # Fall back to the plain writer for its user-facing error messages.
            results_json = json.dumps(
                result.to_json_dict(), indent=4, default=json_encoder
            )
            _write_results(results_json, output_file, config, console)

        print(result.pretty_print())

        run_errors = result.run_errors()
        if run_errors:
            # A failed/partial run must not look like a clean one (exit 3).
            documentation_failed = True
            _print_run_errors(console, run_errors)
        else:
            logger.info("Analysis completed successfully")
        get_task_service().stop_all()
        get_ui_service().print_exit_summary(Toolbox.get_tools_used())
        if documentation_failed:
            # A requested PDF report or the evidence manifest is missing:
            # scripts must be able to tell (same code as --headless).
            sys.exit(3)

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise


def _print_run_errors(console, run_errors: dict) -> None:
    """Print a run's fatal/per-step errors verbatim (no markup)."""
    console.print(
        f"Analysis {run_errors.get('status', 'completed with errors')}: the "
        "results may be incomplete (see 'Run Errors' in the results JSON).",
        style="error",
        soft_wrap=True,
        markup=False,
    )
    if run_errors.get("fatal"):
        console.print(f"  fatal: {run_errors['fatal']}", style="error", markup=False)
    for step in run_errors.get("steps") or []:
        console.print(
            f"  {step.get('step')} (run {step.get('run')}): {step.get('error')}",
            style="error",
            soft_wrap=True,
            markup=False,
        )


def _deliver_to_requested_path(written: Path, requested: Path | str) -> Path:
    """Also place the results JSON at the full ``-f`` path, if it has a folder.

    The run's results (and evidence manifest) live in the session folder,
    which only uses the ``-f`` *file name*; a ``-f some/dir/out.json`` used to
    silently drop ``some/dir``. A bare file name keeps the old behaviour.

    Returns:
        The path the user should look at.
    """
    requested = Path(requested).expanduser()
    if requested.parent == Path() or not Path(written).exists():
        return Path(written)
    target = requested if requested.is_absolute() else Path.cwd() / requested
    if target.resolve() != Path(written).resolve():
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(written, target)
    return target


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
