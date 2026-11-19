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
    "RUN_ERRORS_KEY",
    "ProgressUpdate",
    "RunConfig",
    "RunResult",
    "StepError",
]


#: Results-JSON key holding a run's fatal/per-step errors (absent when clean).
RUN_ERRORS_KEY = "Run Errors"


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
        phase: Short phase name for a status indicator (``"loading
            snapshot"``, ``"replay 1/2"``, ``"settle"``, ``"collecting"``,
            ``"dry run"``, ``"analysing"``); empty for plain run boundaries.
    """

    run_number: int
    total_runs: int
    label: str
    message: str = ""
    phase: str = ""


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
        system_noise_filter: Hide the curated system/GMS noise paths
            (``None`` -> ``analysis.system_noise_filter``).
        noise_patterns: Extra noise globs (``None`` -> ``analysis.noise_patterns``).
        protected_packages: Packages never filtered as noise, in addition to
            the spotlight app (``None`` -> ``analysis.protected_packages``).
        run_id: The run's id (the TUI Play sets it to its bundle's id); the
            engine stamps it on the session timeline's phase lines
            (``None`` -> a fresh :func:`run_history.new_run_id`).
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
    action: Functionality | None = None
    recording_path: str | None = None
    capture_window: int = 0
    results_path: str = ""
    raw_results_path: str = ""
    device_name: str = ""
    system_noise_filter: bool | None = None
    noise_patterns: list[str] | None = None
    protected_packages: list[str] | None = None
    run_id: str | None = None

    def noise_settings(self) -> tuple[bool, list[str], list[str]]:
        """Resolve ``(enabled, extra_patterns, protected_packages)``.

        Fields left at ``None`` follow the user's ``[analysis]`` config; if
        that cannot be loaded the filter stays on with no extras.
        """
        enabled, patterns, protected = True, [], []
        try:
            from sandroid.config import get_config

            cfg = get_config()
            analysis = cfg.analysis
            enabled = bool(getattr(analysis, "system_noise_filter", True))
            patterns = list(getattr(analysis, "noise_patterns", None) or [])
            protected = list(getattr(analysis, "protected_packages", None) or [])
            trig_pkg = getattr(getattr(cfg, "trigdroid", None), "package_name", None)
            if isinstance(trig_pkg, str) and trig_pkg:
                protected.append(trig_pkg)
        except Exception:  # config is optional here
            pass
        if self.system_noise_filter is not None:
            enabled = bool(self.system_noise_filter)
        if self.noise_patterns is not None:
            patterns = list(self.noise_patterns)
        if self.protected_packages is not None:
            protected = list(self.protected_packages)
        return enabled, patterns, protected

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
            network=analysis.capture_network,
            processes=analysis.capture_processes,
            sockets=analysis.capture_sockets,
            show_deleted=analysis.show_deleted_files,
            hash_files=analysis.hash_files,
            pull_apk=analysis.list_apks,
            whitelist=str(whitelist_file) if whitelist_file else None,
            action=action,
            recording_path=recording_path,
            results_path=str(cfg.paths.results_path),
            raw_results_path=str(cfg.paths.raw_results_path),
            # The connected device's real (AVD/model) name once one is
            # active; the config value is only a fallback.
            device_name=_connected_device_name() or cfg.emulator.device_name,
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
            network=ac.capture_network,
            processes=ac.capture_processes,
            sockets=ac.capture_sockets,
            show_deleted=ac.show_deleted,
            hash_files=ac.hash_files,
            pull_apk=ac.pull_apk,
            whitelist=whitelist,
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
        show_deleted: bool | None = None,
        network: bool | None = None,
        processes: bool | None = None,
        sockets: bool | None = None,
        hash_files: bool | None = None,
        pull_apk: bool | None = None,
    ) -> RunConfig:
        """Build a ``RunConfig`` for a TUI Record->Play playback analysis.

        ``action`` is deliberately left ``None``: the engine interprets
        "``recording_path`` set + ``action`` ``None``" as a playback and builds
        the ``Player`` itself. This module never imports or constructs
        ``Player`` (its signature is being changed by a parallel phase).

        Capture/finalize toggles left at ``None`` follow the user's
        ``[analysis]`` configuration (the TUI Settings screen edits exactly
        these keys), so enabling e.g. "capture network" there takes effect for
        Record->Play too. Previously they were hard-coded off, silently
        ignoring the settings. ``show_deleted`` stays on unless explicitly
        disabled (playback default).

        Args:
            recording_path: Absolute path to the recording to replay.
            number_of_runs: Number of replays (TUI default 2).
            noise_filter: Whether to run the dry-run noise pass (TUI default on).
            show_deleted: Detect deleted files (default on for playback).
            network: Capture network traffic (``None`` -> config).
            processes: Monitor processes (``None`` -> config).
            sockets: Monitor listening sockets (``None`` -> config).
            hash_files: Compute file hashes (``None`` -> config).
            pull_apk: Pull and hash APKs (``None`` -> config).

        Returns:
            A populated ``RunConfig`` with ``action=None``.
        """
        defaults = _analysis_toggle_defaults()

        def pick(value: bool | None, key: str) -> bool:
            return defaults[key] if value is None else bool(value)

        return cls(
            number_of_runs=number_of_runs,
            noise_filter=noise_filter,
            network=pick(network, "network"),
            processes=pick(processes, "processes"),
            sockets=pick(sockets, "sockets"),
            show_deleted=True if show_deleted is None else bool(show_deleted),
            hash_files=pick(hash_files, "hash_files"),
            pull_apk=pick(pull_apk, "pull_apk"),
            action=None,
            recording_path=recording_path,
        )


def _connected_device_name() -> str | None:
    """Real name of the active device (AVD/model), or None if none is active."""
    try:
        from sandroid.core.device_manager import active_device_name

        return active_device_name()
    except Exception:
        return None


def _analysis_toggle_defaults() -> dict[str, bool]:
    """Read the capture/finalize toggles from the user's ``[analysis]`` config.

    Falls back to "all off" if the configuration cannot be loaded, which is
    the previous hard-coded playback behaviour.
    """
    fallback = {
        "network": False,
        "processes": False,
        "sockets": False,
        "hash_files": False,
        "pull_apk": False,
    }
    try:
        from sandroid.config import get_config

        analysis = get_config().analysis
        return {
            "network": bool(analysis.capture_network),
            "processes": bool(analysis.capture_processes),
            "sockets": bool(analysis.capture_sockets),
            "hash_files": bool(analysis.hash_files),
            "pull_apk": bool(analysis.list_apks),
        }
    except Exception:
        return fallback


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
    "Timeline Data": [timeline]}``. The report engine
    (:mod:`sandroid.core.report_engine`) unwraps these into ``report.json``, so
    the engine populates ``other_data`` in that wrapped form and
    ``to_json_dict`` passes it through unchanged.

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
        phases: Wall-clock windows of the run's phases, oldest first:
            ``{"kind": "replay" | "dry_run", "run": n, "start": epoch,
            "end": epoch}``. A replay window covers the input replay plus its
            settle time; the dry run window is its noise capture. Used to tag
            network flows by phase (REVIEW scope).
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
    phases: list[dict[str, Any]] = field(default_factory=list)

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
            # Only present when something went wrong, so a clean run keeps
            # the legacy key set.
            **({RUN_ERRORS_KEY: errors} if (errors := self.run_errors()) else {}),
        }

    def run_errors(self) -> dict[str, Any] | None:
        """The fatal and per-step errors of this run, or ``None`` if clean.

        Stored as ``"Run Errors"`` in the results JSON (and the run metadata)
        and shown as a banner on the PDF's first page: a run that aborted or
        lost a step must never look like a clean "nothing found" run.
        """
        if not self.error and not self.per_step_errors:
            return None
        return {
            "status": "aborted" if self.error else "completed with errors",
            "fatal": self.error,
            "steps": [
                {"step": e.label, "run": e.run_number, "error": e.error}
                for e in self.per_step_errors
            ],
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
            phases=[dict(p) for p in self.phases],
        )
