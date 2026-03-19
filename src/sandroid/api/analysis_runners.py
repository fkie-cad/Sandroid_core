"""Analysis runner functions for the Sandroid Headless API.

Provides the internal implementations for each analysis mode
(malware, forensic, security). These functions are used by
SandroidHeadlessAPI.run_analysis() to delegate actual work.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sandroid.core.adb import Adb
    from sandroid.core.toolbox import Toolbox

logger = logging.getLogger(__name__)

# Type alias for the run-progress callback
RunSetter = Callable[[int], None] | None


async def run_malware_analysis(
    toolbox: type[Toolbox],
    package: str,
    runs: int,
    capture_network: bool,
    compute_hashes: bool,
    current_run_setter: RunSetter = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Run TrigDroid-based malware analysis.

    This function:
    1. Sets the spotlight application to the target package
    2. Creates a snapshot for clean-state restoration
    3. Executes TrigDroid malware triggers
    4. Monitors file system changes
    5. Optionally captures network traffic
    6. Returns comprehensive behavioral results

    Args:
        toolbox: The Toolbox class reference.
        package: Target malware package name.
        runs: Number of analysis runs.
        capture_network: Enable network capture.
        compute_hashes: Compute file hashes.
        current_run_setter: Optional callback to update current run number.
        **kwargs: Additional mode-specific options.

    Returns:
        Dictionary with malware analysis results.
    """
    import argparse

    from sandroid.core.actionQ import ActionQ
    from sandroid.services import get_spotlight_service

    # Set spotlight application
    spotlight = get_spotlight_service()
    spotlight.set_spawn_app(package, auto_resume=True)

    # Create ActionQ and configure for TrigDroid analysis
    action_q = ActionQ()

    # Configure via Toolbox.args (legacy interface)
    args = argparse.Namespace()
    args.trigdroid = package
    args.number_of_runs = runs
    args.network = capture_network
    args.hash = compute_hashes
    args.show_deleted = kwargs.get("track_deleted", False)
    args.processes = kwargs.get("monitor_processes", True)
    args.sockets = kwargs.get("monitor_sockets", False)
    args.screenshot = kwargs.get("screenshot_interval")
    args.avoid_strong_noise_filter = kwargs.get("skip_noise_filter", False)
    args.degrade_network = kwargs.get("degrade_network", False)
    args.file = kwargs.get("output_file", "sandroid.json")
    args.loglevel = kwargs.get("log_level", "INFO")
    args.apk = False
    args.whitelist = None
    args.trigdroid_ccf = None
    args.debug = kwargs.get("debug", False)
    args.ai = False
    args.report = False

    toolbox.args = args

    # Assemble the automated queue
    action_q.assembleQ()

    # Process the queue
    current_run = 0
    while not action_q.finished:
        action_q.do_next()
        current_run = min(current_run + 1, runs)
        if current_run_setter:
            current_run_setter(current_run)

    # Get results
    results_json = action_q.get_data()
    return json.loads(results_json)


async def run_forensic_analysis(
    toolbox: type[Toolbox],
    runs: int,
    track_deleted: bool,
    compute_hashes: bool,
    current_run_setter: RunSetter = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Run forensic file system analysis.

    This function:
    1. Establishes a baseline of the file system
    2. Runs multiple analysis cycles to detect noise
    3. Tracks new, modified, and optionally deleted files
    4. Returns file system change data

    Args:
        toolbox: The Toolbox class reference.
        runs: Number of analysis runs.
        track_deleted: Track deleted files.
        compute_hashes: Compute file hashes.
        current_run_setter: Optional callback to update current run number.
        **kwargs: Additional mode-specific options.

    Returns:
        Dictionary with forensic analysis results.
    """
    from sandroid.services import get_forensic_service

    forensic = get_forensic_service()

    # Set baseline
    baseline = toolbox.fetch_changed_files(fetch_all=True)
    forensic.set_baseline(baseline)

    # Import analysis modules
    from sandroid.analysis.changedfiles import ChangedFiles
    from sandroid.analysis.newfiles import NewFiles

    changed_files = ChangedFiles()
    new_files = NewFiles()

    results: dict[str, Any] = {
        "device_name": toolbox.device_name,
        "analysis_type": "forensic",
        "runs": runs,
        "changed_files": [],
        "new_files": [],
    }

    # Run analysis cycles
    for run in range(runs):
        if current_run_setter:
            current_run_setter(run + 1)
        logger.info(f"Forensic analysis run {run + 1}/{runs}")

        # Gather data
        changed_files.gather()
        new_files.gather()

        # Load snapshot between runs to restore clean state
        if run < runs - 1:
            toolbox.load_snapshot(b"tmp")

    # Collect results
    results.update(changed_files.return_data())
    results.update(new_files.return_data())

    if track_deleted:
        from sandroid.analysis.deletedfiles import DeletedFiles

        deleted_files = DeletedFiles()
        deleted_files.gather()
        results.update(deleted_files.return_data())

    if compute_hashes:
        toolbox.calculate_hashes()

    return results


async def run_security_analysis(
    adb: Adb | None,
    toolbox: type[Toolbox] | None,
    apk_path: str,
    **kwargs: Any,
) -> dict[str, Any]:
    """Run static security analysis on an APK.

    This function performs static analysis including:
    - Manifest analysis
    - Permission analysis
    - Code quality checks
    - Vulnerability scanning

    Supports two modes:
    1. Local APK: When apk_path is a path to a local .apk file
    2. Device APK: When apk_path is a package name (pulls from device)

    Args:
        adb: ADB interface for device communication.
        toolbox: The Toolbox class reference (needed for device APK mode).
        apk_path: Path to local APK file or package name of installed app.
        **kwargs: Additional mode-specific options.

    Returns:
        Dictionary with security analysis results.
    """
    from pathlib import Path

    from sandroid.analysis.static_analysis import StaticAnalysis
    from sandroid.services import get_forensic_service

    forensic = get_forensic_service()

    # Check if apk_path is a local file or a package name
    local_path = Path(apk_path)
    if local_path.exists() and local_path.suffix.lower() == ".apk":
        # Local APK file - analyze directly without device interaction
        logger.info(f"Running security analysis on local APK: {apk_path}")
        analyzer = StaticAnalysis(
            apk_path=str(local_path),
            forensic_service=forensic,
            adb=adb,
        )
    else:
        # Package name - set spotlight and pull from device
        logger.info(f"Running security analysis on installed package: {apk_path}")
        from sandroid.services import get_spotlight_service

        spotlight = get_spotlight_service()
        spotlight.set_app(apk_path)

        # Also set on Toolbox for StaticAnalysis compatibility
        if toolbox:
            toolbox.set_spotlight_application(apk_path)

        analyzer = StaticAnalysis(
            forensic_service=forensic,
            adb=adb,
        )

    # Run analysis (non-interactive for headless mode).
    # return_data() includes error information when gather() fails.
    analyzer.gather(interactive=False)
    return analyzer.return_data()
