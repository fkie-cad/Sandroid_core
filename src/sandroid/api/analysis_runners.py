"""Analysis runner functions for the Sandroid Headless API.

Provides the internal implementations for each analysis mode
(malware, forensic, security). These functions are used by
SandroidHeadlessAPI.run_analysis() to delegate actual work.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sandroid.core.adb import Adb
    from sandroid.core.toolbox import Toolbox

logger = logging.getLogger(__name__)

# Type alias for the run-progress callback
RunSetter = Callable[[int], None] | None

#: Seconds between "N s remaining" prompts during a capture window.
PROMPT_INTERVAL = 10


class CaptureWindowAction:
    """Action of a headless forensic run: a timed window for the user.

    Mirrors the engine's action-less capture window (set the action time,
    fix the duration, wait) but tells the user *when* to interact: each
    :meth:`perform` (one per run) announces "Run k/N: perform the action on
    the device now (W s remaining)" and counts down every
    :data:`PROMPT_INTERVAL` seconds.

    Args:
        window: Window length in seconds.
        runs: Number of runs (for the "k/N" label).
        notify: Receives each prompt line (default: ``logger.info``).
        sleep: Injectable sleep (tests).
    """

    def __init__(
        self,
        window: int,
        runs: int,
        notify: Callable[[str], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.window = max(int(window or 0), 0)
        self.runs = runs
        self.notify = notify or logger.info
        self.sleep = sleep
        self.performed = 0

    def perform(self) -> None:
        from sandroid.core.toolbox import Toolbox
        from sandroid.services import get_action_window_service

        self.performed += 1
        Toolbox.set_action_time()
        get_action_window_service().set_duration(self.window)
        run = f"Run {self.performed}/{self.runs}"
        if self.window <= 0:
            self.notify(f"{run}: capture window is 0 s, nothing to wait for.")
            return
        hint = (
            " Perform the same action in every run."
            if self.runs > 1 and self.performed == 1
            else ""
        )
        self.notify(
            f">>> {run}: PERFORM THE ACTION ON THE DEVICE NOW "
            f"({self.window} s remaining).{hint}"
        )
        remaining = self.window
        while remaining > 0:
            step = min(PROMPT_INTERVAL, remaining)
            self.sleep(step)
            remaining -= step
            if remaining > 0:
                self.notify(f"    {run}: {remaining} s remaining")
        self.notify(f"<<< {run}: capture window closed, collecting results...")


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


def _analysis_section(toolbox: Any) -> tuple[Any, Any]:
    """``(config, config.analysis)`` of the run (Toolbox config, else global)."""
    cfg = getattr(toolbox, "config", None)
    analysis = getattr(cfg, "analysis", None)
    if analysis is None:
        try:
            from sandroid.config import get_config

            cfg = cfg if cfg is not None else get_config()
            analysis = get_config().analysis
        except Exception:
            analysis = None
    return cfg, analysis


def resolve_analysis_config(
    toolbox: Any,
    *,
    runs: int,
    capture_network: bool | None = None,
    compute_hashes: bool | None = None,
    track_deleted: bool | None = None,
    **kwargs: Any,
):
    """Build the headless :class:`AnalysisConfig` from the ``[analysis]`` config.

    Every toggle the caller leaves at ``None`` (or does not pass) follows the
    user's ``[analysis]`` configuration, which already contains the CLI flags
    (``--network``, ``--no-processes``, ``--avoid-strong-noise-filter``, ...)
    as overrides -- the same rule the TUI applies (``RunConfig.for_playback``).
    Previously headless runs hard-coded network/processes/dry run *off*
    while the run metadata (a dump of the config) claimed they were on.

    Keyword options: ``monitor_processes``, ``monitor_sockets``, ``dry_run``
    (or the inverse ``skip_noise_filter``), ``pull_apk``, ``whitelist``,
    ``capture_window``.
    """
    from sandroid.api.interfaces import AnalysisConfig

    cfg, analysis = _analysis_section(toolbox)

    def pick(value: Any, attr: str, default: bool) -> bool:
        if value is not None:
            return bool(value)
        return bool(getattr(analysis, attr, default)) if analysis else default

    dry_run = kwargs.get("dry_run")
    if dry_run is None and kwargs.get("skip_noise_filter") is not None:
        dry_run = not kwargs["skip_noise_filter"]
    if dry_run is None:
        dry_run = not pick(None, "avoid_strong_noise_filter", False)
    whitelist = kwargs.get("whitelist")
    if whitelist is None:
        wl_file = getattr(cfg, "whitelist_file", None)
        whitelist = str(wl_file) if wl_file else None
    return AnalysisConfig(
        number_of_runs=runs,
        capture_network=pick(capture_network, "capture_network", False),
        capture_processes=pick(
            kwargs.get("monitor_processes"), "capture_processes", True
        ),
        capture_sockets=pick(kwargs.get("monitor_sockets"), "capture_sockets", False),
        show_deleted=pick(track_deleted, "show_deleted_files", False),
        hash_files=pick(compute_hashes, "hash_files", False),
        pull_apk=pick(kwargs.get("pull_apk"), "list_apks", False),
        dry_run=bool(dry_run),
        whitelist=whitelist,
        capture_window=kwargs.get("capture_window", 60),
    )


def _degrade_network_setting(toolbox: Any, value: bool | None) -> bool:
    if value is not None:
        return bool(value)
    _cfg, analysis = _analysis_section(toolbox)
    return bool(getattr(analysis, "degrade_network", False)) if analysis else False


def _finalize_headless_run(
    toolbox: Any,
    result: Any,
    mode: str,
    started_at: str,
    on_finalized: Callable[[Any], None] | None = None,
    run_config: Any = None,
) -> Any:
    """Write results JSON + metadata, optional PDF and manifest for a run.

    Headless runs have no run bundle; they write into the session folder
    (``SESSION_PATH``, created by ``Toolbox.init_files()``), falling back to
    the configured ``paths.results_path``. Never raises: the analysis result
    is still returned to the API caller if documentation fails.

    Returns:
        The :class:`~sandroid.core.run_report.FinalizeOutcome`, or ``None``
        if even the results JSON could not be written. The same value is
        passed to ``on_finalized`` (the headless API keeps it as
        ``last_run_documentation`` so the CLI can report failures).
    """
    import os

    from sandroid.core import run_report
    from sandroid.core.adb import Adb

    cfg = getattr(toolbox, "config", None)
    result_dir = (
        str(run_config.results_path)
        if run_config is not None and getattr(run_config, "results_path", "")
        else None
    ) or (
        os.environ.get("SESSION_PATH")
        or str(getattr(getattr(cfg, "paths", None), "results_path", "results"))
    )
    outcome = None
    try:
        outcome = run_report.finalize_run(
            result_dir,
            result.to_json_dict(),
            adb=Adb,
            config=cfg,
            started_at=started_at,
            mode=mode,
            generate_pdf=bool(
                getattr(getattr(cfg, "report", None), "generate_pdf", False)
            ),
            run_settings=(
                run_report.describe_run_settings(run_config)
                if run_config is not None
                else None
            ),
        )
        logger.info(f"Run documentation written: {outcome.results_json}")
        report_json = getattr(outcome, "report_json", None)
        if report_json is not None:
            logger.info(f"Report JSON: {report_json}")
        if outcome.pdf is not None:
            logger.info(f"PDF report: {outcome.pdf}")
        for err in outcome.errors:
            logger.error(f"Run finalisation issue: {err}")
    except Exception as e:
        logger.error(f"Could not write run documentation: {e}", exc_info=True)
    if on_finalized is not None:
        on_finalized(outcome)
    return outcome


def _pin_result_dir(run_config: Any, result_dir: str | None) -> None:
    """Point the run at its result folder.

    Without ``result_dir`` (a single headless run) the paths stay empty: an
    identity pin, so the run uses the existing session dir. ``--batch``
    passes a per-package folder so every package gets its own raw pulls,
    results JSON and evidence manifest.
    """
    import os

    if result_dir:
        run_config.results_path = str(result_dir)
        run_config.raw_results_path = os.path.join(str(result_dir), "raw")
    else:
        run_config.results_path = ""
        run_config.raw_results_path = ""


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
    capture_network: bool | None,
    compute_hashes: bool | None,
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
            ``monitor_processes``, ``monitor_sockets``, ``skip_noise_filter``,
            ``degrade_network``, ``pull_apk``, ``whitelist``, ``trigdroid_ccf``).

    Returns:
        Dictionary with malware analysis results.
    """
    from sandroid.analysis.engine import AnalysisEngine
    from sandroid.analysis.run_config import RunConfig
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
    _apply_network_degradation(
        _degrade_network_setting(toolbox, kwargs.get("degrade_network"))
    )

    # 5. Build the typed config (unset toggles follow [analysis]) and run the
    #    unified engine.
    options = {k: v for k, v in kwargs.items() if k != "track_deleted"}
    ac = resolve_analysis_config(
        toolbox,
        runs=runs,
        capture_network=capture_network,
        compute_hashes=compute_hashes,
        track_deleted=kwargs.get("track_deleted"),
        **options,
    )
    run_config = RunConfig.from_analysis_config(
        ac, action=Trigdroid(), whitelist=ac.whitelist
    )
    _pin_result_dir(run_config, kwargs.get("result_dir"))

    from sandroid.core.run_report import iso_now

    started_at = iso_now()
    result = AnalysisEngine(
        run_config, progress=_make_progress_adapter(current_run_setter, runs)
    ).run()
    _finalize_headless_run(
        toolbox,
        result,
        "headless-malware",
        started_at,
        on_finalized=kwargs.get("on_finalized"),
        run_config=run_config,
    )

    # Normalize to a JSON-safe dict (sets -> lists, etc.), matching the legacy
    # ``json.loads(action_q.get_data())`` return type.
    return json.loads(json.dumps(result.to_json_dict(), default=json_encoder))


async def run_forensic_analysis(
    toolbox: type[Toolbox],
    runs: int,
    track_deleted: bool | None,
    compute_hashes: bool | None,
    current_run_setter: RunSetter = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Run forensic file system analysis.

    This function:
    1. Establishes a baseline of the file system
    2. Runs multiple analysis cycles to detect noise
    3. Tracks new, modified, and optionally deleted files
    4. Returns file system change data

    Without a recording each run opens a capture window of
    ``capture_window`` seconds (default 60) in which the user performs the
    action; :class:`CaptureWindowAction` prompts for it (``window_notify``
    receives the prompt lines). With ``recording_path`` (a ``recording.txt``
    from a run bundle) every run replays that recording via the
    :class:`~sandroid.features.player.Player` instead.

    Args:
        toolbox: The Toolbox class reference.
        runs: Number of analysis runs.
        track_deleted: Track deleted files.
        compute_hashes: Compute file hashes.
        current_run_setter: Optional callback to update current run number.
        **kwargs: Additional mode-specific options (``capture_window``,
            ``window_notify``, ``recording_path``, ``on_finalized``, ...).

    Returns:
        Dictionary with forensic analysis results in the unified
        ``RunResult.to_json_dict()`` shape, plus the legacy ``analysis_type``
        and ``runs`` metadata keys.
    """
    from sandroid.analysis.engine import AnalysisEngine
    from sandroid.analysis.run_config import RunConfig
    from sandroid.core.json_utils import json_encoder

    # The engine reverts to the ``tmp`` snapshot on its first step (and between
    # runs), so it must exist before the run starts.
    toolbox.create_snapshot(b"tmp")

    # Unset toggles follow [analysis] (incl. CLI overrides), like the TUI.
    options = {k: v for k, v in kwargs.items() if k != "capture_network"}
    ac = resolve_analysis_config(
        toolbox,
        runs=runs,
        capture_network=kwargs.get("capture_network"),
        compute_hashes=compute_hashes,
        track_deleted=track_deleted,
        **options,
    )
    recording_path = kwargs.get("recording_path")
    if recording_path:
        # Replay an imported recording (``--import-action``) in every run.
        from sandroid.features.player import Player

        action: Any = Player(recording_path=str(recording_path))
    else:
        # Pure forensic run: a prompted capture window per run.
        action = CaptureWindowAction(
            ac.capture_window, runs, notify=kwargs.get("window_notify")
        )
    run_config = RunConfig.from_analysis_config(
        ac, action=action, whitelist=ac.whitelist
    )
    _pin_result_dir(run_config, kwargs.get("result_dir"))

    from sandroid.core.run_report import iso_now

    started_at = iso_now()
    result = AnalysisEngine(
        run_config, progress=_make_progress_adapter(current_run_setter, runs)
    ).run()
    _finalize_headless_run(
        toolbox,
        result,
        "headless-replay" if recording_path else "headless-forensic",
        started_at,
        on_finalized=kwargs.get("on_finalized"),
        run_config=run_config,
    )

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
