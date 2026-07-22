"""Typed analysis run configuration and result containers.

This module defines the small, UI-agnostic dataclasses that replace the three
argparse-style ``Namespace`` objects the legacy analysis paths passed around
(``cli.py`` mock args, ``api/analysis_runners.py`` mock args, and
``api/interfaces.AnalysisConfig``). They are consumed by the unified
``AnalysisEngine`` (defined in ``analysis/engine.py`` -- a separate phase).

Nothing here imports Textual, the engine, ``Player``, or any device layer, so
the containers stay headless-safe and cheap to unit test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sandroid.api.interfaces import AnalysisConfig
    from sandroid.config.schema import SandroidConfig
    from sandroid.core.run_history import RunRecord
    from sandroid.features.functionality import Functionality

__all__ = [
    "ProgressUpdate",
    "RunConfig",
    "RunResult",
    "StepError",
]


@dataclass
class StepError:
    """A single non-fatal error captured during one analysis step.

    The engine wraps every ``step.run(ctx)`` call: a non-fatal failure is
    recorded here and appended to ``RunResult.per_step_errors`` while later
    steps continue.

    Attributes:
        label: Human-readable name of the step that failed.
        run_number: 1-based index of the run in which the error occurred.
        error: The error message.
    """

    label: str
    run_number: int
    error: str


@dataclass
class ProgressUpdate:
    """A progress notification emitted at run boundaries by the engine.

    The engine invokes an optional ``progress(ProgressUpdate(...))`` callback so
    both the TUI (which drops its ``[n/6]`` strings and subscribes) and the
    headless ``current_run_setter`` adapter observe the same events.

    Attributes:
        run_number: 1-based index of the run currently executing.
        total_runs: Total number of runs configured for the analysis.
        label: Short label for the current phase/step.
        message: Optional human-readable detail message.
    """

    run_number: int
    total_runs: int
    label: str
    message: str = ""


@dataclass
class RunConfig:
    """Typed configuration for a single analysis (one ``engine.run()``).

    Replaces the legacy argparse ``Namespace`` objects. Construct via one of the
    classmethod factories rather than by hand where possible.

    Notes:
        ``recording_path`` set together with ``action is None`` is the engine's
        signal for a *playback* analysis: the engine builds the ``Player``
        itself (this module never imports ``Player``, whose signature is being
        changed by a parallel phase).

        ``raw_results_path`` is bundle-local for the TUI Record->Play flow; the
        engine pins ``RAW_RESULTS_PATH``/``RESULTS_PATH`` to it (with a trailing
        separator) for the run's duration so every existing env-reader works
        unchanged.

        ``whitelist`` carries the path to a whitelist *file* at runtime (the
        value handed to ``ForensicService.set_whitelist_path``); the
        ``list[str]`` annotation follows the phase-1 spec but the engine treats
        it as a path string.

    Attributes:
        number_of_runs: Number of analysis runs to perform.
        noise_filter: Whether to run the dry-run noise-subtraction pass.
        network: Capture network traffic.
        processes: Monitor active processes during the action.
        sockets: Monitor listening sockets.
        show_deleted: Perform full-filesystem deleted-file detection.
        hash_files: Compute before/after MD5 hashes of changed/new files.
        pull_apk: Pull APKs from the device and hash them.
        whitelist: Path to a whitelist file (annotated ``list[str] | None`` per
            spec; see notes).
        screenshot_interval: Seconds between automated screenshots, or ``None``.
        action: The ``Functionality`` to perform each run (``Player`` /
            ``Trigdroid``), or ``None`` for a pure forensic run.
        recording_path: Absolute path to a recording; when set with
            ``action is None`` the engine treats the run as playback.
        capture_window: Capture duration (seconds) for action-less forensic
            runs, where there is no action to derive a duration from.
        results_path: Results root for the run (env-pinned by the engine).
        raw_results_path: Raw-results dir for the run (bundle-local; env-pinned).
        device_name: Active device name captured at run start (device-stability
            guard).
    """

    number_of_runs: int = 2
    noise_filter: bool = True
    network: bool = False
    processes: bool = True
    sockets: bool = False
    show_deleted: bool = False
    hash_files: bool = False
    pull_apk: bool = False
    whitelist: list[str] | None = None
    screenshot_interval: int | None = None
    action: Functionality | None = None
    recording_path: str | None = None
    capture_window: int = 0
    results_path: str = ""
    raw_results_path: str = ""
    device_name: str = ""

    @classmethod
    def from_sandroid_config(
        cls,
        cfg: SandroidConfig,
        *,
        action: Functionality | None = None,
        recording_path: str | None = None,
    ) -> RunConfig:
        """Build a ``RunConfig`` from the real ``SandroidConfig`` (CLI path).

        Args:
            cfg: The loaded Sandroid configuration.
            action: Optional functionality to perform each run (e.g. Trigdroid).
            recording_path: Optional absolute recording path.

        Returns:
            A populated ``RunConfig``.
        """
        analysis = cfg.analysis
        whitelist_file = cfg.whitelist_file
        return cls(
            number_of_runs=analysis.number_of_runs,
            noise_filter=not analysis.avoid_strong_noise_filter,
            network=analysis.monitor_network,
            processes=analysis.monitor_processes,
            sockets=analysis.monitor_sockets,
            show_deleted=analysis.show_deleted_files,
            hash_files=analysis.hash_files,
            pull_apk=analysis.list_apks,
            whitelist=str(whitelist_file) if whitelist_file else None,
            screenshot_interval=analysis.screenshot_interval,
            action=action,
            recording_path=recording_path,
            results_path=str(cfg.paths.results_path),
            raw_results_path=str(cfg.paths.raw_results_path),
            device_name=cfg.emulator.device_name,
        )

    @classmethod
    def from_analysis_config(
        cls,
        ac: AnalysisConfig,
        *,
        action: Functionality | None = None,
        whitelist: list[str] | None = None,
        recording_path: str | None = None,
    ) -> RunConfig:
        """Build a ``RunConfig`` from an API ``AnalysisConfig`` (headless path).

        ``whitelist`` is accepted as a separate parameter rather than read
        from ``ac.whitelist`` directly so callers can override it independently
        of the rest of ``ac`` (both current call sites pass ``ac.whitelist``
        through explicitly).

        Args:
            ac: The headless analysis configuration.
            action: Optional functionality to perform each run (e.g. Trigdroid).
            whitelist: Optional whitelist-file path (see ``RunConfig`` notes).
            recording_path: Optional absolute recording path.

        Returns:
            A populated ``RunConfig``.
        """
        return cls(
            number_of_runs=ac.number_of_runs,
            noise_filter=ac.dry_run,
            network=ac.monitor_network,
            processes=ac.monitor_processes,
            sockets=ac.monitor_sockets,
            show_deleted=ac.show_deleted,
            hash_files=ac.hash_files,
            pull_apk=ac.pull_apk,
            whitelist=whitelist,
            screenshot_interval=(
                ac.screenshot_interval if ac.take_screenshots else None
            ),
            capture_window=ac.capture_window,
            action=action,
            recording_path=recording_path,
        )

    @classmethod
    def for_playback(
        cls,
        *,
        recording_path: str,
        number_of_runs: int = 2,
        noise_filter: bool = True,
        show_deleted: bool = True,
        network: bool = False,
        processes: bool = False,
        sockets: bool = False,
        hash_files: bool = False,
    ) -> RunConfig:
        """Build a ``RunConfig`` for a TUI Record->Play playback analysis.

        ``action`` is deliberately left ``None``: the engine interprets
        "``recording_path`` set + ``action`` ``None``" as a playback and builds
        the ``Player`` itself. This module never imports or constructs
        ``Player`` (its signature is being changed by a parallel phase).

        Args:
            recording_path: Absolute path to the recording to replay.
            number_of_runs: Number of replays (TUI default 2).
            noise_filter: Whether to run the dry-run noise pass (TUI default on).
            show_deleted: Detect deleted files (default on for playback).
            network: Capture network traffic.
            processes: Monitor processes.
            sockets: Monitor listening sockets.
            hash_files: Compute file hashes.

        Returns:
            A populated ``RunConfig`` with ``action=None``.
        """
        return cls(
            number_of_runs=number_of_runs,
            noise_filter=noise_filter,
            network=network,
            processes=processes,
            sockets=sockets,
            show_deleted=show_deleted,
            hash_files=hash_files,
            action=None,
            recording_path=recording_path,
        )


@dataclass
class RunResult:
    """The materialized result of one analysis, preserving legacy shapes.

    ``changed_files`` is copied verbatim from
    ``ChangedFiles.return_data()["Changed Files"]`` -- the native
    ``{file: [diff_lines]} | str`` shape -- so real inline diffs survive into
    ``to_run_record``.

    ``other_data`` must already be **list-wrapped** exactly as the legacy
    ``Toolbox.submit_other_data`` produced it: each sub-value is a list, e.g.
    ``{"Artifact Hashes": [hashes], "APK Hashes": [apks],
    "Timeline Data": [timeline]}``. Consumers (``pdf_report``,
    ``timeline_generator``) index ``[0]`` into these, so the engine populates
    ``other_data`` in that wrapped form and ``to_json_dict`` passes it through
    unchanged.

    Attributes:
        device_name: Device the analysis ran against.
        action_time: Emulator-relative action timestamp.
        action_duration: Duration of the action (seconds).
        changed_files: Native ``{file: [diff_lines]} | str`` changed-files shape.
        new_files: New file paths.
        deleted_files: Deleted file paths.
        processes: Process lines captured during the action.
        sockets: Listening-socket lines captured during the action.
        network_dns: Unique DNS domain names queried ("Network").
        network_targets: Unique IP:port targets ("Network IP:Port (send/recv)").
        other_data: List-wrapped "Other Data" mapping (see above).
        pretty_text: Concatenated ``pretty_print`` text from the gatherers.
        per_step_errors: Non-fatal per-step errors captured during the run.
        error: Fatal error message if the run aborted with a partial result.
    """

    device_name: str
    action_time: int = 0
    action_duration: int = 0
    changed_files: Any = field(default_factory=list)
    new_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    sockets: list[str] = field(default_factory=list)
    network_dns: list[str] = field(default_factory=list)
    network_targets: list[str] = field(default_factory=list)
    other_data: dict[str, Any] = field(default_factory=dict)
    pretty_text: str = ""
    per_step_errors: list[StepError] = field(default_factory=list)
    error: str | None = None

    def to_json_dict(self) -> dict[str, Any]:
        """Reproduce the exact legacy ``ActionQ.get_data()`` key set.

        The keys and their sources mirror ``actionQ.py:get_data`` plus each
        gatherer's ``return_data`` key. ``Other Data`` is emitted with its
        already-list-wrapped shape (see the class docstring).

        Returns:
            Dict with the legacy keys: ``"Device Name"``,
            ``"Emulator relative action timestamp"``, ``"Action Duration"``,
            ``"Changed Files"``, ``"New Files"``, ``"Deleted Files"``,
            ``"Processes"``, ``"Listening Sockets"``, ``"Network"``,
            ``"Network IP:Port (send/recv)"``, and ``"Other Data"``.
        """
        return {
            "Device Name": self.device_name,
            "Emulator relative action timestamp": self.action_time,
            "Action Duration": self.action_duration,
            "Changed Files": self.changed_files,
            "New Files": self.new_files,
            "Deleted Files": self.deleted_files,
            "Processes": self.processes,
            "Listening Sockets": self.sockets,
            "Network": self.network_dns,
            "Network IP:Port (send/recv)": self.network_targets,
            "Other Data": self.other_data,
        }

    def pretty_print(self) -> str:
        """Return the concatenated pretty-print text.

        The engine fills ``pretty_text`` by concatenating each gatherer's own
        ``pretty_print()`` output.

        Returns:
            The pretty-printed analysis summary.
        """
        return self.pretty_text

    def to_run_record(
        self,
        *,
        run_id: str,
        label: str,
        recording_path: str,
        bundle_dir: str,
        recorded_at: str,
        completed_at: str,
        duration: int,
    ) -> RunRecord:
        """Convert this result into a persisted ``run_history.RunRecord`` (v2).

        ``run_history`` is imported lazily so this module stays decoupled from
        the parallel phase adding ``bundle_dir`` + bumping ``SCHEMA_VERSION``.

        Args:
            run_id: Unique run identifier.
            label: User-facing run label.
            recording_path: Absolute in-bundle recording path.
            bundle_dir: Directory of the run bundle.
            recorded_at: ISO timestamp when recording started.
            completed_at: ISO timestamp when the analysis completed.
            duration: Total run duration (seconds).

        Returns:
            A v2-shaped ``RunRecord`` preserving the native diff shapes.
        """
        from sandroid.core.run_history import RunRecord

        return RunRecord(
            schema_version=2,
            run_id=run_id,
            label=label,
            recorded_at=recorded_at,
            completed_at=completed_at,
            device_name=self.device_name,
            recording_path=recording_path,
            bundle_dir=bundle_dir,
            duration=duration,
            error=self.error,
            changed_files=self.changed_files,
            new_files=self.new_files,
            deleted_files=self.deleted_files,
            counts={
                "changed": len(self.changed_files),
                "new": len(self.new_files),
                "deleted": len(self.deleted_files),
            },
        )
