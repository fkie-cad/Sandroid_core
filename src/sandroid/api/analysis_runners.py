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


def _apply_network_degradation(degrade: bool) -> None:
    """Replicate legacy ``assembleQ`` network shaping (``actionQ.py:92-97``).

    Args:
        degrade: When ``True`` simulate a UMTS/3G link; otherwise reset the
            emulated network to full speed / no delay.
    """
    from sandroid.core.adb import Adb

    if degrade:
        Adb.send_telnet_command("network delay umts")
        Adb.send_telnet_command("network speed umts")
    else:
        Adb.send_telnet_command("network delay none")
        Adb.send_telnet_command("network speed full")


def _make_progress_adapter(
    current_run_setter: RunSetter, runs: int
) -> Callable[[Any], None]:
    """Adapt the engine's ``ProgressUpdate`` callback to ``current_run_setter``.

    The engine emits a ``ProgressUpdate`` per run boundary; the headless API
    only wants the clamped 1-based run number. Setup (``run_number == 0``) and
    the dry run (``run_number > runs``) are folded into the run range.

    Args:
        current_run_setter: The headless run-number callback (or ``None``).
        runs: Total configured runs (upper clamp).

    Returns:
        A callable accepting a ``ProgressUpdate``.
    """

    def _progress(update: Any) -> None:
        if current_run_setter is not None and update.run_number >= 1:
            current_run_setter(min(update.run_number, runs))

    return _progress


async def run_malware_analysis(
    toolbox: type[Toolbox],
    package: str,
    runs: int,
    capture_network: bool,
    compute_hashes: bool,
    current_run_setter: RunSetter = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Run TrigDroid-based malware analysis via the unified engine.

    This function:
    1. Sets the spotlight application to the target package (spawn mode)
    2. Optionally runs the TrigDroid CCF utility (only when explicitly
       requested via ``trigdroid_ccf``; it exits the process)
    3. Creates the ``tmp`` snapshot the engine reverts to on its first step
    4. Optionally degrades the emulated network
    5. Executes the unified :class:`~sandroid.analysis.engine.AnalysisEngine`
       with a ``Trigdroid`` action and returns the JSON-safe result dict

    Args:
        toolbox: The Toolbox class reference.
        package: Target malware package name.
        runs: Number of analysis runs.
        capture_network: Enable network capture.
        compute_hashes: Compute file hashes.
        current_run_setter: Optional callback to update current run number.
        **kwargs: Additional mode-specific options (``track_deleted``,
            ``monitor_processes``, ``monitor_sockets``, ``screenshot_interval``,
            ``skip_noise_filter``, ``degrade_network``, ``pull_apk``,
            ``whitelist``, ``trigdroid_ccf``).

    Returns:
        Dictionary with malware analysis results.
    """
    from sandroid.analysis.engine import AnalysisEngine
    from sandroid.analysis.run_config import RunConfig
    from sandroid.api.interfaces import AnalysisConfig
    from sandroid.core.json_utils import json_encoder
    from sandroid.features.trigdroid import Trigdroid
    from sandroid.services import get_spotlight_service

    # 1. Point the spotlight at the target package in spawn mode.
    get_spotlight_service().set_spawn_app(package, auto_resume=True)

    # 2. Optional TrigDroid CCF (guarded; never part of a normal run). run_ccf()
    #    reads Toolbox.args.trigdroid_ccf and exits the process, so it is only
    #    reached when explicitly requested — legacy hard-coded this to None.
    ccf_mode = kwargs.get("trigdroid_ccf")
    if ccf_mode:
        from types import SimpleNamespace

        toolbox.args = SimpleNamespace(trigdroid_ccf=ccf_mode)
        Trigdroid().run_ccf()

    # 3. The engine's first step reverts to the ``tmp`` snapshot.
    toolbox.create_snapshot(b"tmp")

    # 4. Optional network degradation (replicates legacy assembleQ).
    _apply_network_degradation(kwargs.get("degrade_network", False))

    # 5. Build the typed config and run the unified engine.
    screenshot_interval = kwargs.get("screenshot_interval")
    ac = AnalysisConfig(
        number_of_runs=runs,
        capture_network=capture_network,
        capture_processes=kwargs.get("monitor_processes", True),
        capture_sockets=kwargs.get("monitor_sockets", False),
        show_deleted=kwargs.get("track_deleted", False),
        take_screenshots=screenshot_interval is not None,
        screenshot_interval=screenshot_interval or 3,
        hash_files=compute_hashes,
        pull_apk=kwargs.get("pull_apk", False),
        dry_run=not kwargs.get("skip_noise_filter", False),
        whitelist=kwargs.get("whitelist"),
    )
    run_config = RunConfig.from_analysis_config(
        ac, action=Trigdroid(), whitelist=ac.whitelist
    )
    # Identity pin: headless has no run bundle, so run against the existing
    # session dir (empty paths leave RESULTS_PATH / RAW_RESULTS_PATH untouched).
    run_config.results_path = ""
    run_config.raw_results_path = ""

    result = AnalysisEngine(
        run_config, progress=_make_progress_adapter(current_run_setter, runs)
    ).run()

    # Normalize to a JSON-safe dict (sets -> lists, etc.), matching the legacy
    # ``json.loads(action_q.get_data())`` return type.
    return json.loads(json.dumps(result.to_json_dict(), default=json_encoder))


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
        Dictionary with forensic analysis results in the unified
        ``RunResult.to_json_dict()`` shape, plus the legacy ``analysis_type``
        and ``runs`` metadata keys.
    """
    from sandroid.analysis.engine import AnalysisEngine
    from sandroid.analysis.run_config import RunConfig
    from sandroid.api.interfaces import AnalysisConfig
    from sandroid.core.json_utils import json_encoder

    # The engine reverts to the ``tmp`` snapshot on its first step (and between
    # runs), so it must exist before the run starts.
    toolbox.create_snapshot(b"tmp")

    screenshot_interval = kwargs.get("screenshot_interval")
    ac = AnalysisConfig(
        number_of_runs=runs,
        capture_network=kwargs.get("capture_network", False),
        capture_processes=kwargs.get("monitor_processes", False),
        capture_sockets=kwargs.get("monitor_sockets", False),
        show_deleted=track_deleted,
        take_screenshots=screenshot_interval is not None,
        screenshot_interval=screenshot_interval or 3,
        hash_files=compute_hashes,
        pull_apk=kwargs.get("pull_apk", False),
        dry_run=kwargs.get("dry_run", False),
        whitelist=kwargs.get("whitelist"),
        capture_window=kwargs.get("capture_window", 60),
    )
    # Pure forensic run: no action (``action=None``) — the engine opens a
    # capture window instead of performing/replaying anything.
    run_config = RunConfig.from_analysis_config(ac, action=None, whitelist=ac.whitelist)
    # Identity pin (headless has no run bundle -> run against the session dir).
    run_config.results_path = ""
    run_config.raw_results_path = ""

    result = AnalysisEngine(
        run_config, progress=_make_progress_adapter(current_run_setter, runs)
    ).run()

    data = json.loads(json.dumps(result.to_json_dict(), default=json_encoder))
    # Preserve the two metadata keys the legacy implementation returned so API
    # consumers do not regress.
    data["analysis_type"] = "forensic"
    data["runs"] = runs
    return data


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
