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
) -> None:
    """Execute analysis using the headless API.

    Supports both single-package analysis and batch processing of multiple
    packages without requiring interactive UI.

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
            )
        )


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
    """
    from sandroid.api import AnalysisMode, SandroidHeadlessAPI

    if not package:
        console.print(
            "[error]--headless requires --trigdroid <package> or --batch <config>[/error]"
        )
        sys.exit(1)

    console.print(
        f"[accent]Starting headless {analysis_mode.value} analysis for: {package}[/accent]"
    )

    api = SandroidHeadlessAPI(config_path=None)
    api._config = sandroid_config

    result = await api.initialize()
    if not result.success:
        console.print(f"[error]Initialization failed: {result.error}[/error]")
        sys.exit(1)

    try:
        # For SECURITY mode, package is interpreted as apk_path
        # (can be a local file path or an installed package name)
        if analysis_mode == AnalysisMode.SECURITY:
            results = await api.run_analysis(
                mode=analysis_mode,
                apk_path=package,
                runs=runs,
                capture_network=network,
                compute_hashes=hash_files,
                track_deleted=show_deleted,
                output_file=output_file,
            )
        else:
            results = await api.run_analysis(
                mode=analysis_mode,
                package=package,
                runs=runs,
                capture_network=network,
                compute_hashes=hash_files,
                track_deleted=show_deleted,
                output_file=output_file,
            )

        if output_file:
            console.print(f"[success]Results saved to: {output_file}[/success]")
        else:
            print(json.dumps(results, indent=2, default=str))

        console.print("[success]Headless analysis completed successfully[/success]")

    except Exception as e:
        console.print(f"[error]Analysis failed: {e}[/error]")
        logger.exception("Headless analysis error")
        sys.exit(1)
    finally:
        await api.shutdown()


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
        with open(batch_config) as f:
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
    batch_network = batch_cfg.get("capture_network", network)
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
    )

    # Summary
    success_count = sum(1 for r in results.values() if r.get("status") == "success")
    error_count = len(results) - success_count

    console.print("\n[success]Batch analysis complete:[/success]")
    console.print(f"  [success]Success: {success_count}[/success]")
    if error_count > 0:
        console.print(f"  [error]Errors: {error_count}[/error]")

    for pkg, result in results.items():
        status = result.get("status")
        if status == "success":
            console.print(f"  [success]{pkg}: OK[/success]")
        else:
            console.print(
                f"  [error]{pkg}: {result.get('error', 'Unknown error')}[/error]"
            )
