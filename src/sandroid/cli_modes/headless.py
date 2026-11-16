"""Headless/batch analysis mode dispatcher for Sandroid.

Provides programmatic access to Sandroid's analysis capabilities
without requiring interactive UI, supporting both single-package
and batch processing modes.
"""

import asyncio
import json
import logging
import sys

from sandroid.config import SandroidConfig
from sandroid.core.console import SandroidConsole

logger = logging.getLogger(__name__)

#: Exit code when the analysis ran but its documentation (results JSON, a
#: requested PDF report or the evidence manifest) could not be written.
EXIT_DOCUMENTATION_FAILED = 3

_MISSING = object()

#: Result keys counted in the end-of-run summary.
_SUMMARY_KEYS = (
    "Changed Files",
    "New Files",
    "Deleted Files",
    "Processes",
    "Listening Sockets",
    "Network",
    "Network IP:Port (send/recv)",
)


def run_headless_analysis(
    sandroid_config: SandroidConfig,
    active_logger: logging.Logger,
    package: str | None,
    batch_config: str | None,
    mode: str,
    runs: int,
    network: bool,
    hash_files: bool,
    show_deleted: bool,
    output_file: str | None,
    recording_path: str | None = None,
) -> None:
    """Execute analysis using the headless API.

    Supports both single-package analysis and batch processing of multiple
    packages without requiring interactive UI.

    The full results are written to the session folder (and to
    ``output_file`` if given); the console only shows a short summary with
    the result paths. Exit codes: 0 success, 1 analysis failed,
    :data:`EXIT_DOCUMENTATION_FAILED` (3) if the analysis ran but the
    results JSON, a requested PDF report or the evidence manifest could not
    be written. Security mode without ``output_file`` prints its JSON to
    stdout (it has no result folder).

    Args:
        sandroid_config: Loaded Sandroid configuration.
        active_logger: Configured logger instance.
        package: Single package name for analysis (used if batch_config is None).
        batch_config: Path to batch processing JSON config file.
        mode: Analysis mode ('forensic', 'malware', or 'security').
        runs: Number of analysis runs.
        network: Enable network capture.
        hash_files: Compute file hashes.
        show_deleted: Track deleted files.
        output_file: Output file path for results.
        recording_path: ``recording.txt`` to replay in every run (forensic
            mode, ``--import-action``) instead of a manual capture window.

    Raises:
        SystemExit: If required parameters are missing or analysis fails.
    """
    from sandroid.api import AnalysisMode

    console = SandroidConsole.get()

    try:
        analysis_mode = AnalysisMode(mode)
    except ValueError:
        console.print(
            f"[error]Invalid mode: {mode}. Use: forensic, malware, security[/error]"
        )
        sys.exit(1)

    if batch_config:
        asyncio.run(
            _run_batch_analysis(
                console=console,
                sandroid_config=sandroid_config,
                batch_config=batch_config,
                analysis_mode=analysis_mode,
                runs=runs,
                network=network,
            )
        )
    else:
        asyncio.run(
            _run_single_analysis(
                console=console,
                sandroid_config=sandroid_config,
                package=package,
                analysis_mode=analysis_mode,
                runs=runs,
                network=network,
                hash_files=hash_files,
                show_deleted=show_deleted,
                output_file=output_file,
                recording_path=recording_path,
            )
        )


def _plain(console, text: str, style: str | None = None) -> None:
    """Print verbatim (no markup, no wrapping) so paths stay parseable."""
    console.print(text, style=style, soft_wrap=True, markup=False, highlight=False)


def _count(value) -> int:
    return len(value) if isinstance(value, (list, dict)) else 0


def _print_summary(
    console, sandroid_config, analysis_mode, results, doc, output_file
) -> int:
    """Print a short end-of-run summary and return the exit code."""
    from sandroid.api import AnalysisMode

    rc = 0
    runs = results.get("runs") if isinstance(results, dict) else None
    title = f"Headless {analysis_mode.value} analysis finished"
    if runs:
        title += f" ({runs} runs)"
    console.print(f"[accent]{title}[/accent]")
    if isinstance(results, dict) and any(k in results for k in _SUMMARY_KEYS):
        counts = ", ".join(
            f"{key}: {_count(results.get(key))}"
            for key in _SUMMARY_KEYS
            if key in results
        )
        _plain(console, f"  {counts}")
        if results.get("Action Duration") is not None:
            console.print(f"  Action duration: {results.get('Action Duration')} s")
    run_errors = results.get("Run Errors") if isinstance(results, dict) else None
    if isinstance(run_errors, dict) and run_errors:
        # An aborted run or a lost step must not look like a clean run.
        _plain(
            console,
            f"  Run {run_errors.get('status', 'completed with errors')}: results "
            "may be incomplete (see 'Run Errors' in the results JSON)",
            "error",
        )
        if run_errors.get("fatal"):
            _plain(console, f"    fatal: {run_errors['fatal']}", "error")
        for step in run_errors.get("steps") or []:
            _plain(
                console,
                f"    {step.get('step')} (run {step.get('run')}): {step.get('error')}",
                "error",
            )
        rc = EXIT_DOCUMENTATION_FAILED

    report_requested = bool(
        getattr(getattr(sandroid_config, "report", None), "generate_pdf", False)
    )
    if doc is not _MISSING and analysis_mode != AnalysisMode.SECURITY:
        if doc is None:
            _plain(
                console,
                "  Results JSON / evidence documentation could not be written "
                "(see log)",
                "error",
            )
            rc = EXIT_DOCUMENTATION_FAILED
        else:
            _plain(console, f"  Results: {doc.results_json}")
            pdf_errors = [e for e in doc.errors if e.startswith("pdf:")]
            if doc.pdf is not None:
                _plain(console, f"  PDF report: {doc.pdf}")
            elif report_requested:
                reason = pdf_errors[0][4:].strip() if pdf_errors else "unknown"
                _plain(console, f"  PDF report FAILED: {reason}", "error")
                rc = EXIT_DOCUMENTATION_FAILED
            if doc.manifest is not None:
                _plain(
                    console,
                    f"  Evidence manifest: {doc.manifest.sha256sums_path} "
                    f"(SHA-256 {doc.manifest.sha256sums_sha256})",
                )
            for err in doc.errors:
                if not err.startswith("pdf:"):
                    _plain(console, f"  {err}", "error")
                    rc = EXIT_DOCUMENTATION_FAILED
    if output_file:
        _plain(console, f"  Results also saved to: {output_file}")
    return rc


async def _run_single_analysis(
    console,
    sandroid_config: SandroidConfig,
    package: str | None,
    analysis_mode,
    runs: int,
    network: bool,
    hash_files: bool,
    show_deleted: bool,
    output_file: str | None,
    recording_path: str | None = None,
) -> None:
    """Run analysis on a single package.

    Args:
        console: SandroidConsole instance.
        sandroid_config: Loaded Sandroid configuration.
        package: Target package name.
        analysis_mode: AnalysisMode enum value.
        runs: Number of analysis runs.
        network: Enable network capture.
        hash_files: Compute file hashes.
        show_deleted: Track deleted files.
        output_file: Output file path for results.
        recording_path: Recording to replay (forensic mode only).
    """
    from sandroid.api import AnalysisMode, SandroidHeadlessAPI

    # Forensic mode observes the whole device during a capture window and
    # needs no target package; malware (TrigDroid) and security (APK/package
    # static analysis) do.
    if not package and analysis_mode != AnalysisMode.FORENSIC:
        console.print(
            f"[error]--headless --mode {analysis_mode.value} requires "
            "--trigdroid <package> (or --batch <config>)[/error]"
        )
        sys.exit(1)

    target = f" for: {package}" if package else ""
    console.print(
        f"[accent]Starting headless {analysis_mode.value} analysis{target}[/accent]"
    )

    # Hand the CLI-resolved config (incl. --config/--environment/overrides)
    # to the API so initialize() does not reload a different one.
    api = SandroidHeadlessAPI(config=sandroid_config)

    result = await api.initialize()
    if not result.success:
        console.print(f"[error]Initialization failed: {result.error}[/error]")
        sys.exit(1)

    def _window_prompt(message: str) -> None:
        _plain(console, message, "warning")

    extra = {}
    if analysis_mode == AnalysisMode.FORENSIC:
        if recording_path:
            extra["recording_path"] = recording_path
            console.print(f"[accent]Replaying recording: {recording_path}[/accent]")
        else:
            extra["window_notify"] = _window_prompt

    rc = 0
    try:
        # For SECURITY mode, package is interpreted as apk_path
        # (can be a local file path or an installed package name)
        if analysis_mode == AnalysisMode.SECURITY:
            results = await api.run_analysis(
                mode=analysis_mode,
                apk_path=package,
                runs=runs,
                capture_network=network or None,
                compute_hashes=hash_files or None,
                track_deleted=show_deleted or None,
                output_file=output_file,
            )
        else:
            results = await api.run_analysis(
                mode=analysis_mode,
                package=package,
                runs=runs,
                capture_network=network or None,
                compute_hashes=hash_files or None,
                track_deleted=show_deleted or None,
                output_file=output_file,
                **extra,
            )

        if analysis_mode == AnalysisMode.SECURITY and not output_file:
            # No result folder in security mode: stdout is the only output.
            print(json.dumps(results, indent=2, default=str))
        doc = getattr(api, "last_run_documentation", _MISSING)
        rc = _print_summary(
            console, sandroid_config, analysis_mode, results, doc, output_file
        )
        if rc:
            console.print(
                "[error]Headless analysis finished, but the run had errors or "
                f"its documentation is incomplete (exit code {rc})[/error]"
            )
        else:
            console.print("[success]Headless analysis completed successfully[/success]")

    except Exception as e:
        console.print(f"[error]Analysis failed: {e}[/error]")
        logger.exception("Headless analysis error")
        sys.exit(1)
    finally:
        await api.shutdown()
    if rc:
        sys.exit(rc)


async def _run_batch_analysis(
    console,
    sandroid_config: SandroidConfig,
    batch_config: str,
    analysis_mode,
    runs: int,
    network: bool,
) -> None:
    """Run batch analysis from config file.

    Args:
        console: SandroidConsole instance.
        sandroid_config: Loaded Sandroid configuration.
        batch_config: Path to batch config JSON file.
        analysis_mode: AnalysisMode enum value.
        runs: Number of analysis runs.
        network: Enable network capture.
    """
    from sandroid.api import AnalysisMode, batch_analyze

    console.print(f"[accent]Loading batch config from: {batch_config}[/accent]")

    try:
        with open(batch_config, encoding="utf-8") as f:
            batch_cfg = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        console.print(f"[error]Failed to load batch config: {e}[/error]")
        sys.exit(1)

    packages = batch_cfg.get("packages", [])
    if not packages:
        console.print("[error]Batch config must contain 'packages' list[/error]")
        sys.exit(1)

    batch_mode = AnalysisMode(batch_cfg.get("mode", analysis_mode.value))
    batch_runs = batch_cfg.get("runs", runs)
    batch_network = batch_cfg.get("capture_network", network or None)
    output_dir = batch_cfg.get("output_dir", "batch_results")

    console.print(
        f"[accent]Starting batch analysis of {len(packages)} packages[/accent]"
    )
    console.print(
        f"[dim]Mode: {batch_mode.value}, Runs: {batch_runs}, Output: {output_dir}[/dim]"
    )

    results = await batch_analyze(
        packages=packages,
        mode=batch_mode,
        runs=batch_runs,
        capture_network=batch_network,
        output_dir=output_dir,
        config=sandroid_config,
    )

    # Summary
    success_count = sum(1 for r in results.values() if r.get("status") == "success")
    error_count = len(results) - success_count

    console.print("\n[success]Batch analysis complete:[/success]")
    console.print(f"  [success]Success: {success_count}[/success]")
    if error_count > 0:
        console.print(f"  [error]Errors: {error_count}[/error]")

    doc_failures = 0
    for pkg, result in results.items():
        status = result.get("status")
        doc_errors = result.get("documentation_errors") or []
        if status == "success" and not doc_errors:
            console.print(f"  [success]{pkg}: OK[/success]")
        elif status == "success":
            doc_failures += 1
            _plain(console, f"  {pkg}: analysed, but {'; '.join(doc_errors)}", "error")
        else:
            _plain(console, f"  {pkg}: {result.get('error', 'Unknown error')}", "error")

    if error_count:
        sys.exit(1)
    if doc_failures:
        sys.exit(EXIT_DOCUMENTATION_FAILED)
