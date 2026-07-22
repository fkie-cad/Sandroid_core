"""Unified, headless-safe analysis engine.

This module replaces the dead ``core/actionQ.py`` ``match``/``isinstance`` state
machine with two small pieces:

* A closed family of polymorphic :class:`Step` subclasses -- each carries a
  typed payload and a ``run(ctx)`` method, so dispatch is ordinary polymorphism
  on real types rather than string tokens.
* :class:`AnalysisPlan`, whose :meth:`AnalysisPlan.build` is a **pure** function
  that turns a :class:`~sandroid.analysis.run_config.RunConfig` plus a set of
  gatherer instances into an ordered ``list[Step]`` -- the thing
  ``assembleQ_for_runs`` never was (untestable, device-coupled).

:class:`AnalysisEngine` executes a plan. It is headless-safe (no Textual
import) and runnable from a Textual worker thread. It reproduces the legacy
``do_next`` behaviour (load-snapshot / baseline / action / gather /
first-second-noise pulls / dry-run noise subtraction) while adding:

* per-step error isolation (non-fatal -> :class:`StepError`; fatal ->
  :class:`FatalStepError` -> partial :class:`RunResult`),
* a device-stability guard evaluated at the start of each path-sensitive step,
* progress callbacks + ``AnalysisStarted``/``AnalysisCompleted`` events tagged
  ``source="analysis_engine"`` so a TUI subscriber can tell engine completions
  apart from ``static_analysis``'s,
* an env-path pin (``RAW_RESULTS_PATH``/``RESULTS_PATH``) that wraps the whole
  run **including** result materialization, so every existing env-reader
  (sqlite/xml/txt diffs, new-file pulls, hashing) works unchanged, and
* a ``wrap_up``-equivalent finalize (``--hash``/``--apk``/timeline) producing
  the exact list-wrapped ``Other Data`` shape.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, ClassVar

from sandroid.analysis.run_config import ProgressUpdate, RunResult, StepError
from sandroid.core.events.events import AnalysisCompleted, AnalysisStarted

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from sandroid.analysis.base_di import DataGatherBase
    from sandroid.analysis.run_config import RunConfig
    from sandroid.features.functionality import Functionality

logger = logging.getLogger(__name__)

#: Source tag on engine-published analysis events (disambiguates them from the
#: ``AnalysisCompleted`` that ``analysis/static_analysis.py`` also publishes).
EVENT_SOURCE = "analysis_engine"

#: Snapshot slot name the engine loads/reverts to (mirrors legacy ``b"tmp"``).
_SNAPSHOT_NAME = b"tmp"


class FatalStepError(Exception):
    """A step failure that must abort the run (but still return a partial result).

    Raised for conditions that make continuing meaningless or unsafe -- e.g. a
    failed snapshot load, or the active device changing mid-run
    (device-stability guard). The engine catches it, records
    :attr:`RunResult.error`, and returns the partially-populated result rather
    than continuing to read paths that may now point at the wrong device.
    """


# ===========================================================================
# Step model
# ===========================================================================


class EngineContext:
    """Mutable per-run context threaded into every :meth:`Step.run`.

    Carries the resolved services/toolbox/config and the 1-based
    ``run_number`` of the step currently executing (updated by the engine as it
    iterates the plan). ``screenshot`` holds the active automated-screenshot
    instance between :class:`StartScreenshotStep` and :class:`StopScreenshotStep`.

    Attributes:
        config: The run configuration.
        toolbox: Toolbox-like object (real ``Toolbox`` class or an injected
            fake) used for snapshot/pull/fetch/finalize operations.
        forensic_service: Forensic service for baseline/whitelist state.
        action_window_service: Action-window service for timing/dry-run state.
        run_number: 1-based index of the run currently executing.
        screenshot: The active screenshot capturer, if any.
    """

    def __init__(
        self,
        *,
        config: RunConfig,
        toolbox: Any,
        forensic_service: Any,
        action_window_service: Any,
    ) -> None:
        self.config = config
        self.toolbox = toolbox
        self.forensic_service = forensic_service
        self.action_window_service = action_window_service
        self.run_number: int = 0
        self.screenshot: Any = None


class Step:
    """Base class for a single ordered analysis step.

    Subclasses set :attr:`kind` (a stable string used for plan assertions and
    progress labels) and :attr:`path_sensitive` (whether the device-stability
    guard must be evaluated before the step runs), carry any typed payload, and
    implement :meth:`run`.
    """

    #: Stable step-kind identifier (used by the plan tests + progress labels).
    kind: ClassVar[str] = "step"
    #: Whether the engine evaluates the device-stability guard before this step.
    path_sensitive: ClassVar[bool] = False

    def __init__(self, run_number: int = 0) -> None:
        """Initialize the step.

        Args:
            run_number: 1-based index of the run this step belongs to (0 for
                pre-analysis setup steps).
        """
        self.run_number = run_number

    def run(self, ctx: EngineContext) -> None:
        """Execute the step against ``ctx``.

        Args:
            ctx: The per-run engine context.

        Raises:
            NotImplementedError: Always, in the base class.
        """
        raise NotImplementedError

    @property
    def label(self) -> str:
        """Human-readable label for progress and error reporting."""
        return self.kind

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"{type(self).__name__}(run={self.run_number})"


class LoadSnapshotStep(Step):
    """Revert the emulator to the ``tmp`` snapshot (legacy ``load_snapshot``)."""

    kind = "load_snapshot"
    path_sensitive = True

    def run(self, ctx: EngineContext) -> None:
        ctx.toolbox.load_snapshot(_SNAPSHOT_NAME)


class BaselineStep(Step):
    """Capture the pre-action filesystem baseline (legacy ``baseline``)."""

    kind = "baseline"
    path_sensitive = True

    def run(self, ctx: EngineContext) -> None:
        ctx.forensic_service.set_baseline(
            ctx.toolbox.fetch_changed_files(fetch_all=True)
        )


class ActionStep(Step):
    """Perform the run's action, or set an action-less capture window.

    When :attr:`action` is a :class:`~sandroid.features.functionality.Functionality`
    (a ``Player`` for playback, or ``Trigdroid``), it is performed and is
    responsible for setting the action time/duration itself. When ``action`` is
    ``None`` (a pure forensic run with no recording), the engine opens a capture
    window of ``config.capture_window`` seconds instead.
    """

    kind = "action"
    path_sensitive = False

    def __init__(self, action: Functionality | None, run_number: int = 0) -> None:
        """Initialize the action step.

        Args:
            action: The functionality to perform, or ``None`` for an action-less
                forensic capture window.
            run_number: 1-based run index.
        """
        super().__init__(run_number)
        self.action = action

    def run(self, ctx: EngineContext) -> None:
        if self.action is not None:
            self.action.perform()
            return
        # Action-less forensic run: open a fixed capture window so
        # processes/sockets and the changed-files scan have a duration to work
        # against (Risk 5). Duration is set once (subsequent runs reuse it).
        window = int(ctx.config.capture_window or 0)
        ctx.toolbox.set_action_time()
        ctx.action_window_service.set_duration(window)
        if window > 0:
            time.sleep(window)


class StartCaptureStep(Step):
    """Start a background capture gatherer (network / processes / sockets).

    For these gatherers ``gather()`` *starts* a capture thread rather than
    collecting synchronously; the results are read later via ``return_data()``.
    """

    kind = "start_capture"
    path_sensitive = True

    def __init__(self, gatherer: DataGatherBase, run_number: int = 0) -> None:
        """Initialize with the gatherer whose capture is being started.

        Args:
            gatherer: The capture gatherer instance.
            run_number: 1-based run index.
        """
        super().__init__(run_number)
        self.gatherer = gatherer

    def run(self, ctx: EngineContext) -> None:
        self.gatherer.gather()

    @property
    def label(self) -> str:
        return f"{self.kind}:{type(self.gatherer).__name__}"


class StopCaptureStep(Step):
    """Stop a background capture gatherer.

    Only :class:`~sandroid.analysis.network.Network` has a real ``stop()`` (this
    fixes its legacy never-stopped leak). ``Processes``/``Sockets`` self-
    terminate after ``action_duration`` seconds and expose no ``stop()``, so the
    step is a no-op for them and their results are read from ``return_data()``
    after the loop.
    """

    kind = "stop_capture"
    path_sensitive = False

    def __init__(self, gatherer: DataGatherBase, run_number: int = 0) -> None:
        """Initialize with the gatherer whose capture is being stopped.

        Args:
            gatherer: The capture gatherer instance.
            run_number: 1-based run index.
        """
        super().__init__(run_number)
        self.gatherer = gatherer

    def run(self, ctx: EngineContext) -> None:
        stop = getattr(self.gatherer, "stop", None)
        if callable(stop):
            stop()

    @property
    def label(self) -> str:
        return f"{self.kind}:{type(self.gatherer).__name__}"


class GatherStep(Step):
    """Collect a synchronous gatherer's data (changed / new / deleted files)."""

    kind = "gather"
    path_sensitive = True

    def __init__(self, gatherer: DataGatherBase, run_number: int = 0) -> None:
        """Initialize with the gatherer to collect from.

        Args:
            gatherer: The data-gatherer instance.
            run_number: 1-based run index.
        """
        super().__init__(run_number)
        self.gatherer = gatherer

    def run(self, ctx: EngineContext) -> None:
        # ChangedFiles/NewFiles fetch through DataGatherBase._fetch_changed_files,
        # which calls forensic_service.fetch_changed_files() directly and so
        # never passes through Toolbox._fetch_changed_files -- the only place
        # that syncs the service's action-time window. Without this, the
        # gatherer scans against whatever window a *previous* run's PullStep
        # last synced (or (0, 0) on the very first run), silently reporting
        # empty results while the correctly-windowed Pull that follows still
        # pulls real file content.
        ctx.forensic_service.set_action_window(
            ctx.action_window_service.get_action_time(),
            ctx.action_window_service.get_duration(),
        )
        self.gatherer.gather()

    @property
    def label(self) -> str:
        return f"{self.kind}:{type(self.gatherer).__name__}"


class PullStep(Step):
    """Pull the changed files into a numbered pull slot.

    Mirrors legacy ``pull0``/``pull1``/``pull_dry_run``: for the ``"first"`` and
    ``"second"`` slots only files present in the baseline are pulled (they are
    the intra-file-diff candidates); the ``"noise"`` slot pulls every changed
    file with no baseline filter. The env pin makes the files land inside the
    run bundle's ``raw/<slot>_pull/`` tree.
    """

    kind = "pull"
    path_sensitive = True

    def __init__(
        self, slot: str, source: DataGatherBase | None = None, run_number: int = 0
    ) -> None:
        """Initialize the pull step.

        Args:
            slot: Pull slot name -- ``"first"``, ``"second"`` or ``"noise"``.
            source: The changed-files gatherer this pull corresponds to (kept
                for provenance; the pull itself reads the toolbox cache).
            run_number: 1-based run index.
        """
        super().__init__(run_number)
        self.slot = slot
        self.source = source

    def run(self, ctx: EngineContext) -> None:
        changed = ctx.toolbox.fetch_changed_files()
        files = list(changed.keys()) if isinstance(changed, dict) else list(changed)
        if self.slot == "noise":
            for file in files:
                ctx.toolbox.pull_file("noise", file)
            return
        baseline = ctx.forensic_service.get_baseline()
        for file in files:
            if file in baseline:
                ctx.toolbox.pull_file(self.slot, file)

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.slot}"


class DryRunBeginStep(Step):
    """Begin the noise-measurement dry run (legacy ``init_dry_run``)."""

    kind = "dry_run_begin"
    path_sensitive = True

    def run(self, ctx: EngineContext) -> None:
        ctx.action_window_service.start_dry_run()
        # Reset the action time to "now" on the device for the noise window.
        ctx.toolbox.set_action_time()


class DryRunSleepStep(Step):
    """Sleep for the action duration while noise captures run (``dry_run_sleep``)."""

    kind = "dry_run_sleep"
    path_sensitive = False

    def run(self, ctx: EngineContext) -> None:
        duration = int(ctx.action_window_service.get_duration() or 0)
        if duration > 0:
            time.sleep(duration)


class DryRunEndStep(Step):
    """End the dry run (clears the dry-run flag before result materialization)."""

    kind = "dry_run_end"
    path_sensitive = False

    def run(self, ctx: EngineContext) -> None:
        ctx.action_window_service.end_dry_run()


class StartScreenshotStep(Step):
    """Start automated periodic screenshots (best-effort, guarded).

    Restores the automated-screenshot parity the legacy ``update_photographer``
    provided. Kept deliberately simple: any failure (headless environment, no
    emulator screenshot support, import error) is logged and swallowed so it
    never aborts the analysis.
    """

    kind = "start_screenshot"
    path_sensitive = False

    def run(self, ctx: EngineContext) -> None:
        try:
            from sandroid.features.screenshot import Screenshot

            shot = Screenshot()
            interval = ctx.config.screenshot_interval
            if interval:
                shot.interval = int(interval)
            shot.perform()
            ctx.screenshot = shot
        except Exception as exc:
            logger.warning("Automated screenshots unavailable: %s", exc)


class StopScreenshotStep(Step):
    """Stop automated periodic screenshots started by :class:`StartScreenshotStep`."""

    kind = "stop_screenshot"
    path_sensitive = False

    def run(self, ctx: EngineContext) -> None:
        shot = ctx.screenshot
        if shot is None:
            return
        try:
            shot.stop()
        except Exception as exc:
            logger.warning("Failed to stop automated screenshots: %s", exc)
        finally:
            ctx.screenshot = None


# ===========================================================================
# Plan builder (pure)
# ===========================================================================


class AnalysisPlan:
    """Pure builder that turns a config + gatherers into an ordered step list."""

    #: Ordered (gatherer-key, config-flag-attr) pairs for the capture gatherers.
    _CAPTURE_ORDER: ClassVar[tuple[tuple[str, str], ...]] = (
        ("network", "network"),
        ("processes", "processes"),
        ("sockets", "sockets"),
    )

    @staticmethod
    def _resolve_action(config: RunConfig) -> Functionality | None:
        """Resolve the run's action from the config.

        Resolution order: an explicit ``config.action`` wins; otherwise a
        ``config.recording_path`` means playback and a ``Player`` bound to that
        absolute path is built here (``run_config`` never imports ``Player``);
        otherwise ``None`` for a pure forensic (action-less) run.

        Args:
            config: The run configuration.

        Returns:
            The resolved functionality, or ``None`` for an action-less run.
        """
        if config.action is not None:
            return config.action
        if config.recording_path:
            from sandroid.features.player import Player

            return Player(recording_path=config.recording_path)
        return None

    @staticmethod
    def _capture_steps(
        gatherers: Mapping[str, DataGatherBase],
        config: RunConfig,
        run_number: int,
        *,
        start: bool,
    ) -> list[Step]:
        """Build the ordered start/stop capture steps enabled for this run."""
        steps: list[Step] = []
        for key, flag in AnalysisPlan._CAPTURE_ORDER:
            if getattr(config, flag) and key in gatherers:
                cls = StartCaptureStep if start else StopCaptureStep
                steps.append(cls(gatherers[key], run_number=run_number))
        return steps

    @staticmethod
    def build(config: RunConfig, gatherers: Mapping[str, DataGatherBase]) -> list[Step]:
        """Build the ordered analysis plan.

        Reproduces the legacy ``assembleQ_for_runs`` ordering exactly, plus the
        N=1 special case (a single run still yields real ``first``/``second``
        diffs) and the optional dry-run noise pass.

        Args:
            config: The run configuration.
            gatherers: Mapping of gatherer keys (``"changed_files"``,
                ``"new_files"``, and -- when enabled -- ``"deleted_files"``,
                ``"network"``, ``"processes"``, ``"sockets"``) to the single
                shared instance the engine created for each.

        Returns:
            The ordered list of :class:`Step` objects. No device I/O happens
            here (building a ``Player`` only stores its path).
        """
        steps: list[Step] = []
        total = config.number_of_runs
        action = AnalysisPlan._resolve_action(config)

        cf = gatherers["changed_files"]
        nf = gatherers["new_files"]
        df = gatherers.get("deleted_files")
        want_deleted = config.show_deleted and df is not None

        # ---- Pre-analysis ----
        steps.append(LoadSnapshotStep(run_number=0))
        steps.append(BaselineStep(run_number=0))
        if config.screenshot_interval:
            steps.append(StartScreenshotStep(run_number=0))

        if total <= 1:
            # ---- N=1 special case: single run yields both pulls ----
            rn = 1
            steps.append(ActionStep(action, run_number=rn))
            steps.append(GatherStep(cf, run_number=rn))
            steps.append(GatherStep(nf, run_number=rn))
            if want_deleted:
                steps.append(GatherStep(df, run_number=rn))
            steps.append(PullStep("second", cf, run_number=rn))
            steps.append(LoadSnapshotStep(run_number=rn))
            steps.append(PullStep("first", cf, run_number=rn))
        else:
            # ---- Run 0 (== legacy pull0) ----
            rn = 1
            steps.append(ActionStep(action, run_number=rn))
            steps.append(GatherStep(cf, run_number=rn))
            steps.append(GatherStep(nf, run_number=rn))
            if want_deleted:
                steps.append(GatherStep(df, run_number=rn))
            steps.append(LoadSnapshotStep(run_number=rn))
            steps.append(PullStep("first", cf, run_number=rn))

            # ---- Runs 1..N-1 ----
            for run_index in range(1, total):
                rn = run_index + 1
                steps += AnalysisPlan._capture_steps(gatherers, config, rn, start=True)
                steps.append(ActionStep(action, run_number=rn))
                steps += AnalysisPlan._capture_steps(gatherers, config, rn, start=False)
                steps.append(GatherStep(cf, run_number=rn))
                steps.append(GatherStep(nf, run_number=rn))
                if want_deleted:
                    steps.append(GatherStep(df, run_number=rn))
                if run_index == 1:
                    steps.append(PullStep("second", cf, run_number=rn))
                steps.append(LoadSnapshotStep(run_number=rn))

        # ---- Dry run (noise measurement) ----
        if config.noise_filter:
            rn = total + 1
            steps.append(DryRunBeginStep(run_number=rn))
            steps += AnalysisPlan._capture_steps(gatherers, config, rn, start=True)
            steps.append(DryRunSleepStep(run_number=rn))
            steps += AnalysisPlan._capture_steps(gatherers, config, rn, start=False)
            steps.append(GatherStep(cf, run_number=rn))
            steps.append(PullStep("noise", cf, run_number=rn))
            steps.append(DryRunEndStep(run_number=rn))

        if config.screenshot_interval:
            steps.append(StopScreenshotStep(run_number=total + 2))

        return steps


# ===========================================================================
# Env-path pin
# ===========================================================================


@contextmanager
def _pinned_env(config: RunConfig) -> Iterator[None]:
    """Pin ``RAW_RESULTS_PATH``/``RESULTS_PATH`` to the run's bundle dirs.

    Every existing env-reader (sqlite/xml/txt diffs, new-file pulls,
    ``calculate_hashes``) reads these globals at call time, so pinning them for
    the run's duration lets them all work unchanged. A **trailing separator is
    mandatory**: consumers concatenate ``f"{base}first_pull"`` with no separator
    of their own, so a missing sep silently breaks every diff.

    Empty path fields (CLI/headless, which have no run bundle) leave the current
    env value untouched -- the pin is then effectively identity, so post-run
    readers keep pointing at the existing session dir.

    Args:
        config: The run configuration supplying the (possibly empty) paths.

    Yields:
        None. Restores both variables to their prior values on exit.
    """
    saved = {
        "RAW_RESULTS_PATH": os.environ.get("RAW_RESULTS_PATH"),
        "RESULTS_PATH": os.environ.get("RESULTS_PATH"),
    }
    try:
        if config.raw_results_path:
            os.environ["RAW_RESULTS_PATH"] = (
                str(config.raw_results_path).rstrip(os.sep) + os.sep
            )
        if config.results_path:
            os.environ["RESULTS_PATH"] = (
                str(config.results_path).rstrip(os.sep) + os.sep
            )
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


# ===========================================================================
# Engine
# ===========================================================================


class AnalysisEngine:
    """Executes an :class:`AnalysisPlan`, producing a :class:`RunResult`.

    Headless-safe (no Textual import) and runnable from a Textual worker thread.
    Services/toolbox are resolved from the constructor arguments or the process
    singletons; gatherers are created **exactly once** and the same instance is
    threaded into every step that references it (load-bearing for the multi-run
    intersection and the toolbox-level dry-run noise contract).
    """

    def __init__(
        self,
        config: RunConfig,
        *,
        progress: Any = None,
        forensic_service: Any = None,
        action_window_service: Any = None,
        toolbox: Any = None,
        gatherer_classes: Mapping[str, type] | None = None,
    ) -> None:
        """Initialize the engine.

        Args:
            config: The run configuration.
            progress: Optional callable invoked with a
                :class:`~sandroid.analysis.run_config.ProgressUpdate` at each run
                boundary.
            forensic_service: Forensic service; defaults to the singleton.
            action_window_service: Action-window service; defaults to the
                singleton.
            toolbox: Toolbox-like object; defaults to the real ``Toolbox`` class.
            gatherer_classes: Optional override mapping of gatherer keys to
                classes (test/DI hook). Defaults to the real gatherer classes.
        """
        self.config = config
        self._progress = progress
        self._forensic_arg = forensic_service
        self._action_window_arg = action_window_service
        self._toolbox_arg = toolbox
        self._gatherer_classes_arg = gatherer_classes

        # Resolved lazily in run() so construction stays cheap/side-effect-free.
        self.forensic_service: Any = None
        self.action_window_service: Any = None
        self.toolbox: Any = None
        self.adb: Any = None
        self.gatherers: dict[str, DataGatherBase] = {}
        self._expected_device: str = ""

    # ---- resolution helpers ------------------------------------------------

    def _resolve_services(self) -> None:
        """Resolve services/toolbox/adb from constructor args or singletons."""
        if self._forensic_arg is not None:
            self.forensic_service = self._forensic_arg
        else:
            from sandroid.services import get_forensic_service

            self.forensic_service = get_forensic_service()

        if self._action_window_arg is not None:
            self.action_window_service = self._action_window_arg
        else:
            from sandroid.services import get_action_window_service

            self.action_window_service = get_action_window_service()

        if self._toolbox_arg is not None:
            self.toolbox = self._toolbox_arg
        else:
            from sandroid.core.toolbox import Toolbox

            self.toolbox = Toolbox

        from sandroid.core.adb import Adb

        self.adb = Adb

    def _default_gatherer_classes(self) -> dict[str, type]:
        """Return the default (production) gatherer class map."""
        from sandroid.analysis.changedfiles import ChangedFiles
        from sandroid.analysis.deletedfiles import DeletedFiles
        from sandroid.analysis.network import Network
        from sandroid.analysis.newfiles import NewFiles
        from sandroid.analysis.processes import Processes
        from sandroid.analysis.sockets import Sockets

        return {
            "changed_files": ChangedFiles,
            "new_files": NewFiles,
            "deleted_files": DeletedFiles,
            "network": Network,
            "processes": Processes,
            "sockets": Sockets,
        }

    def _build_gatherers(self) -> dict[str, DataGatherBase]:
        """Create every enabled gatherer exactly once.

        Injects ``forensic_service`` (so ``NewFiles`` uses instance state, not
        class state) and ``adb``. Critically does **not** pass a ``config``
        carrying ``raw_results_path``/``results_path`` -- ``base_di`` prefers
        such a config over the pinned env, which would silently defeat the pin.
        """
        classes = self._gatherer_classes_arg or self._default_gatherer_classes()
        kwargs: dict[str, Any] = {
            "forensic_service": self.forensic_service,
            "adb": self.adb,
        }
        gatherers: dict[str, DataGatherBase] = {
            "changed_files": classes["changed_files"](**kwargs),
            "new_files": classes["new_files"](**kwargs),
        }
        if self.config.show_deleted:
            gatherers["deleted_files"] = classes["deleted_files"](**kwargs)
        if self.config.network:
            gatherers["network"] = classes["network"](**kwargs)
        if self.config.processes:
            gatherers["processes"] = classes["processes"](**kwargs)
        if self.config.sockets:
            gatherers["sockets"] = classes["sockets"](**kwargs)
        return gatherers

    def _reset_accumulators(self) -> None:
        """Reset cross-analysis accumulators once per ``run()`` (not per replay).

        Resets the class-level accumulators the gatherers share
        (``NewFiles``/``DeletedFiles``/``Network``) and the toolbox-level
        ``Other Data`` collector + shadow-timestamp list, so a second analysis
        in the same process does not serve a stale earlier run's ``[0]``-indexed
        entries. Resetting between the N replays would defeat the intersection
        filter, so it happens strictly once here.

        Also force-resets ``action_window_service``'s duration. ``set_duration``
        is deliberately set-once-per-analysis (unforced) so replay runs 2..N
        within *this* analysis don't each override the window the first replay
        established -- but with no reset between *separate* top-level
        analyses, ``ActionWindowService`` is a process-wide singleton, so a
        second analysis in the same TUI session (or headless process) would
        otherwise silently reuse the first analysis's measured duration for
        its own changed-files window (a real bug found via review, distinct
        from the accumulators above but the same "stale prior analysis"
        class).

        Also clears ``forensic_service``'s whitelist path and dry-run noise
        caches (``noise_files``/``noise_processes``) for the same reason:
        ``ForensicService`` is the same process-wide singleton, and
        ``ChangedFiles``/``Processes`` apply whatever noise cache is
        currently set UNCONDITIONALLY in ``process_data()`` even when *this*
        analysis has ``noise_filter=False`` and never ran its own dry run --
        so a prior analysis's noise/whitelist would otherwise silently leak
        into this one's results. ``_apply_whitelist()`` (called right after
        this) re-sets the path if *this* analysis actually configured one.
        Deliberately NOT reset here: ``forensic_service``'s baseline (about
        to be overwritten by ``BaselineStep`` regardless) and its
        ``spotlight_files`` watchlist (persistent user configuration that
        must survive across analyses, not per-analysis state).
        """
        from sandroid.analysis.deletedfiles import DeletedFiles
        from sandroid.analysis.network import Network
        from sandroid.analysis.newfiles import NewFiles

        NewFiles.newFileListList = []
        DeletedFiles.deletedFileListList = []
        Network.internal_run_counter = 1
        Network.dns_requests = set()
        Network.performed_diff = False

        self.action_window_service.set_duration(0, force=True)

        try:
            self.forensic_service.set_whitelist_path("")
        except Exception as exc:
            logger.debug("Could not reset forensic service whitelist: %s", exc)

        try:
            self.toolbox.other_output_data_collector = {}
            self.toolbox._timestamps_shadow_dict_list = []
            self.toolbox.noise_files = {}
            self.toolbox.noise_processes = []
        except Exception as exc:
            logger.debug("Could not reset toolbox accumulators: %s", exc)

    # ---- device-stability guard -------------------------------------------

    def _current_device(self) -> str:
        """Best-effort read of the currently-active device name."""
        return str(getattr(self.toolbox, "device_name", "") or "")

    def _guard_device(self) -> None:
        """Raise :class:`FatalStepError` if the active device changed mid-run.

        Evaluated at the start of every path-sensitive step: a device switch
        from another thread re-points the process-global result paths inside a
        TOCTOU window, so a pull/diff/gather that ran afterwards would read the
        wrong (fresh, empty) folder. The recording itself is immune (absolute
        path), but path-sensitive steps must fail fast.
        """
        if not self._expected_device:
            return
        current = self._current_device()
        if current and current != self._expected_device:
            raise FatalStepError(
                f"Active device changed mid-run "
                f"({self._expected_device!r} -> {current!r}); aborting to avoid "
                f"reading the wrong result path."
            )

    # ---- progress + events -------------------------------------------------

    def _emit_progress(self, run_number: int, label: str, message: str = "") -> None:
        """Invoke the progress callback if one was supplied."""
        if self._progress is None:
            return
        try:
            self._progress(
                ProgressUpdate(
                    run_number=run_number,
                    total_runs=self.config.number_of_runs,
                    label=label,
                    message=message,
                )
            )
        except Exception as exc:
            logger.debug("Progress callback raised: %s", exc)

    def _run_boundary(self, run_number: int) -> None:
        """Handle crossing into a new run: progress + ``AnalysisStarted`` event."""
        total = self.config.number_of_runs
        if run_number == 0:
            label = "Setup"
        elif 1 <= run_number <= total:
            label = f"Run {run_number}/{total}"
        else:
            label = "Dry run"
        self._emit_progress(run_number, label)

        if 1 <= run_number <= total:
            AnalysisStarted(
                run_number=run_number,
                total_runs=total,
                modules=[type(g).__name__ for g in self.gatherers.values()],
                source=EVENT_SOURCE,
            ).publish()

    def _publish_completed(self, result: RunResult) -> None:
        """Publish the terminal ``AnalysisCompleted`` event (with real counts)."""
        AnalysisCompleted(
            run_number=self.config.number_of_runs,
            total_runs=self.config.number_of_runs,
            files_changed=_safe_len(result.changed_files),
            new_files=_safe_len(result.new_files),
            duration_seconds=float(result.action_duration or 0),
            source=EVENT_SOURCE,
        ).publish()

    # ---- main entry point --------------------------------------------------

    def run(self) -> RunResult:
        """Execute the analysis and return a :class:`RunResult`.

        The env pin wraps the entire body -- step loop, result materialization
        (``return_data`` diffs read the env) **and** the finalize -- so it is
        restored only after everything that reads ``RAW_RESULTS_PATH`` has run.

        Returns:
            The materialized (possibly partial, if a fatal step aborted) result.
        """
        self._resolve_services()
        self._expected_device = self.config.device_name or self._current_device()
        result = RunResult(device_name=self._expected_device)

        with _pinned_env(self.config):
            self.gatherers = self._build_gatherers()
            self._reset_accumulators()
            self._apply_whitelist()

            ctx = EngineContext(
                config=self.config,
                toolbox=self.toolbox,
                forensic_service=self.forensic_service,
                action_window_service=self.action_window_service,
            )
            plan = AnalysisPlan.build(self.config, self.gatherers)
            self._execute_plan(plan, ctx, result)

            self._materialize(result)
            self._finalize(result)

        self._publish_completed(result)
        return result

    def _apply_whitelist(self) -> None:
        """Point the forensic service at the whitelist file (before gathering).

        ``config.whitelist`` is a *path string* (despite its ``list[str]``
        annotation). Setting it here means the exclusion applies when the
        gatherers' ``process_data`` runs during materialization.
        """
        if not self.config.whitelist:
            return
        try:
            self.forensic_service.set_whitelist_path(self.config.whitelist)
        except Exception as exc:
            logger.warning("Could not set whitelist path: %s", exc)

    def _execute_plan(
        self, plan: list[Step], ctx: EngineContext, result: RunResult
    ) -> None:
        """Run the plan with per-step error isolation + run-boundary events."""
        last_run: int | None = None
        for step in plan:
            if step.run_number != last_run:
                self._run_boundary(step.run_number)
                last_run = step.run_number
            ctx.run_number = step.run_number
            try:
                if step.path_sensitive:
                    self._guard_device()
                step.run(ctx)
            except FatalStepError as exc:
                result.error = str(exc)
                logger.error("Fatal step %s: %s", step.label, exc)
                break
            except Exception as exc:
                result.per_step_errors.append(
                    StepError(
                        label=step.label,
                        run_number=step.run_number,
                        error=str(exc),
                    )
                )
                logger.warning("Step %s failed: %s", step.label, exc)

    # ---- result materialization -------------------------------------------

    def _materialize(self, result: RunResult) -> None:
        """Populate ``result`` from the gatherers' ``return_data``/``pretty_print``.

        Runs inside the env pin so ``ChangedFiles.return_data`` (which computes
        the sqlite/xml/txt diffs by reading the pulled files) resolves paths
        correctly. Native shapes are preserved verbatim.
        """
        result.action_time = int(self.action_window_service.get_action_time() or 0)
        result.action_duration = int(self.action_window_service.get_duration() or 0)

        cf = self.gatherers.get("changed_files")
        nf = self.gatherers.get("new_files")
        df = self.gatherers.get("deleted_files")
        pr = self.gatherers.get("processes")
        sk = self.gatherers.get("sockets")
        nw = self.gatherers.get("network")

        result.changed_files = self._safe_return(cf, "Changed Files", [])
        result.new_files = self._safe_return(nf, "New Files", [])
        if df is not None:
            result.deleted_files = self._safe_return(df, "Deleted Files", [])
        if pr is not None:
            result.processes = self._safe_return(pr, "Processes", [])
        if sk is not None:
            result.sockets = self._safe_return(sk, "Listening Sockets", [])
        if nw is not None:
            result.network_dns = self._safe_return(nw, "Network", [])
            result.network_targets = self._safe_return(
                nw, "Network IP:Port (send/recv)", []
            )

        # Pretty text follows the legacy first-seen order.
        ordered = [cf, nf, df, nw, pr, sk]
        parts: list[str] = []
        for gatherer in ordered:
            if gatherer is None:
                continue
            try:
                parts.append(gatherer.pretty_print())
            except Exception as exc:
                logger.warning(
                    "pretty_print failed for %s: %s",
                    type(gatherer).__name__,
                    exc,
                )
        result.pretty_text = "".join(parts)

    def _safe_return(
        self, gatherer: DataGatherBase | None, key: str, default: Any
    ) -> Any:
        """Read one key from a gatherer's ``return_data``, isolating failures."""
        if gatherer is None:
            return default
        try:
            data = gatherer.return_data()
        except Exception as exc:
            logger.warning(
                "return_data failed for %s: %s", type(gatherer).__name__, exc
            )
            return default
        if isinstance(data, dict):
            return data.get(key, default)
        return default

    # ---- finalize (Other Data / hashes / apks / timeline) ------------------

    def _finalize(self, result: RunResult) -> None:
        """Run the ``wrap_up``-equivalent finalize, inside the env pin.

        Populates the list-wrapped ``Other Data`` mapping via the existing
        toolbox helpers (so the ``[0]``-indexed ``pdf_report``/
        ``timeline_generator`` key contract keeps holding), then copies the
        collector into ``result.other_data``.
        """
        if self.config.hash_files:
            try:
                self.toolbox.calculate_hashes()
            except Exception as exc:
                logger.warning("calculate_hashes failed: %s", exc)

        if self.config.pull_apk:
            try:
                self.toolbox.pull_and_hash_apks()
            except Exception as exc:
                logger.warning("pull_and_hash_apks failed: %s", exc)

        try:
            self.toolbox.submit_other_data(
                "Timeline Data", self.toolbox._timestamps_shadow_dict_list
            )
        except Exception as exc:
            logger.warning("Timeline submit failed: %s", exc)

        try:
            collector = self.toolbox.other_output_data_collector
            result.other_data = dict(collector) if collector else {}
        except Exception as exc:
            logger.debug("Could not read Other Data collector: %s", exc)
            result.other_data = {}


def _safe_len(value: Any) -> int:
    """Length of ``value`` if it has one, else 0."""
    try:
        return len(value)
    except TypeError:
        return 0


__all__ = [
    "ActionStep",
    "AnalysisEngine",
    "AnalysisPlan",
    "BaselineStep",
    "DryRunBeginStep",
    "DryRunEndStep",
    "DryRunSleepStep",
    "EngineContext",
    "FatalStepError",
    "GatherStep",
    "LoadSnapshotStep",
    "PullStep",
    "StartCaptureStep",
    "StartScreenshotStep",
    "Step",
    "StopCaptureStep",
    "StopScreenshotStep",
]
