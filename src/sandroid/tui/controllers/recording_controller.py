"""Recording Controller for TUI.

This controller manages recording and playback operations, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Start/stop input event recording
- Playback recorded events
- Analysis of file system changes during playback
- Export recording to various formats

Usage:
    from sandroid.tui.controllers import RecordingController

    controller = RecordingController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        push_modal=app.push_screen,
        run_worker=app.run_worker,
        call_from_thread=app.call_from_thread,
    )

    # Start recording
    controller.start_recording()

    # Start playback
    controller.start_playback()
"""

import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PlaybackResult:
    """Result of playback analysis."""

    changed_files: list[str]
    new_files: list[str]
    deleted_files: list[str]
    duration: int
    error: str | None = None


@dataclass
class RecordingResult:
    """Result of a recording session."""

    completed: bool
    cancelled: bool
    event_count: int
    duration: float
    file_path: str | None = None


class RecordingController:
    """Controller for recording and playback operations.

    This controller handles all recording-related operations, decoupled from
    the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of recording logic from UI rendering
    - Reusable recording management across different UI modes

    Thread Safety:
        Playback operations run in worker threads.
        Progress callbacks are invoked via call_from_thread.

    Example:
        controller = RecordingController(
            log_info=print,
            log_warning=lambda msg: print(f"WARN: {msg}"),
            push_modal=lambda modal, cb: cb(None),
            run_worker=lambda fn, **kw: fn(),
            call_from_thread=lambda fn, *args: fn(*args),
        )

        # Start recording
        controller.start_recording()

        # Start playback and analysis
        controller.start_playback()
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_warning: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        log_success: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        run_worker: Callable[..., None] | None = None,
        call_from_thread: Callable[..., None] | None = None,
        force_ui_refresh: Callable[[], None] | None = None,
        toolbox: Any | None = None,
        on_run_saved: Callable[[str], None] | None = None,
        on_monitor_stopped_for_playback: Callable[[], None] | None = None,
        on_monitor_resume_available: Callable[[Any], None] | None = None,
        set_recording_indicator: Callable[[bool], None] | None = None,
        set_replay_indicator: Callable[[bool], None] | None = None,
        suppress_disconnect_guard: Callable[[bool], None] | None = None,
    ):
        """Initialize RecordingController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI
            log_warning: Callback for warning-level logging to UI
            log_error: Callback for error-level logging to UI
            log_success: Callback for success-level logging to UI
            push_modal: Callback to push a modal screen with result callback
            run_worker: Callback to run function in worker thread
            call_from_thread: Callback to execute function on main thread
            force_ui_refresh: Callback to force UI refresh after state changes
            toolbox: Optional Toolbox reference (defaults to imported Toolbox)
            on_run_saved: Callback invoked (via call_from_thread, so always on
                the main thread) with the new run's ``run_id`` once
                ``_run_playback_analysis`` has persisted a RunRecord. Wired by
                app.py to DiffsView.on_new_run for the gated auto-select/
                unread-marker behaviour; safe to leave unset (e.g. in tests).
            on_monitor_stopped_for_playback: Callback invoked (via
                call_from_thread) the moment the Play safety-net force-stops
                a running monitor session, right before ``load_snapshot``.
                Takes no arguments — it only needs to tell the UI "show the
                inline notice", nothing more. See
                ``_stop_monitor_before_revert``. Safe to leave unset.
            on_monitor_resume_available: Callback invoked (via
                call_from_thread) once ``_run_playback_analysis`` finishes
                (success or failure — the offer is orthogonal to whether the
                diff analysis itself errored), but *only* if monitor was
                actually auto-stopped by this run. Receives the
                ``MonitorConfig`` monitor was running with beforehand (may carry
                a now-stale ``target_pid`` in PID-mode — re-resolving it is
                ``MonitorController.resume_after_playback``'s job, not this
                controller's). Wired by app.py to MonitorView's one-click
                "Resume monitoring" offer; safe to leave unset.
            set_recording_indicator: Callback invoked with the modal's own
                ``is_recording`` transitions (forwarded straight through to
                ``RecordingModal``'s ``on_recording_active_changed``) so a UI
                mode indicator (e.g. the status bar's "● RECORDING" row) can
                track real capture start/stop rather than the modal merely
                being open. Safe to leave unset.
            set_replay_indicator: Callback invoked with ``True``/``False``
                (via call_from_thread) around ``_run_playback_analysis``'s
                ``AnalysisEngine(...).run()`` call, so a UI mode indicator
                (e.g. "● REPLAYING") can track the auto-chained/manual replay
                that otherwise has no visible indication beyond Activity Log
                lines. Safe to leave unset.
            suppress_disconnect_guard: Callback invoked with ``True``/
                ``False`` around every disruptive snapshot revert this
                controller performs (forwarded to ``RecordingModal`` for its
                own pre-recording snapshot, and wrapped directly here around
                ``_run_playback_analysis``'s engine run, which covers every
                ``LoadSnapshotStep`` across all replay iterations) — stops
                the transient ADB-transport blip a snapshot save/load causes
                from tripping a false "Device disconnected" toast. Safe to
                leave unset.
        """
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_error = log_error or self._default_log
        self._log_success = log_success or self._default_log
        self._push_modal = push_modal
        self._run_worker = run_worker
        self._call_from_thread = call_from_thread or (lambda fn, *args: fn(*args))
        self._force_ui_refresh = force_ui_refresh
        self._toolbox = toolbox
        self._on_run_saved = on_run_saved
        self._on_monitor_stopped_for_playback = on_monitor_stopped_for_playback
        self._on_monitor_resume_available = on_monitor_resume_available
        self._set_recording_indicator = set_recording_indicator
        self._set_replay_indicator = set_replay_indicator
        self._suppress_disconnect_guard = suppress_disconnect_guard
        # Recording-session bookkeeping for the settings-seed flow (see
        # start_recording()): a monotonic counter for the "Run N" default
        # name, the label seed, and the replay-count/dry-run settings that
        # every subsequent Play of the current recording defaults to (until a
        # fresh Record replaces them). Chosen in the combined Record-settings
        # form (idea B) and forwarded live via ``on_settings_chosen``.
        self._recording_seq = 0
        self._current_recording_label: str | None = None
        self._current_number_of_runs = 2
        self._current_noise_filter = True

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def _get_toolbox(self) -> Any:
        """Get Toolbox reference."""
        if self._toolbox:
            return self._toolbox
        from sandroid.core.toolbox import Toolbox

        return Toolbox

    def _get_task_service(self) -> Any:
        """Get task service instance."""
        from sandroid.services import get_task_service

        return get_task_service()

    def _get_forensic_service(self) -> Any:
        """Get forensic service instance."""
        from sandroid.services import get_forensic_service

        return get_forensic_service()

    def _get_action_window_service(self) -> Any:
        """Get action-window service instance."""
        from sandroid.services import get_action_window_service

        return get_action_window_service()

    # =========================================================================
    # Recording Operations
    # =========================================================================

    def is_recording(self) -> bool:
        """Check if recording is currently in progress.

        Returns:
            True if recording is active
        """
        return self._get_task_service().is_running("recording")

    def start_recording(self) -> bool:
        """Start input event recording.

        Shows recording modal that captures input events from the device.
        Creates a snapshot before recording starts.

        The modal is pushed with ``auto_start=True`` — see ``RecordingModal``
        — which shows the combined Record-settings form (idea B: name +
        replays + dry-run) *immediately*, before anything else happens.
        Recording itself (the pre-snapshot and ``RecordingWrapper`` start)
        only begins once that form is resolved (Save or Cancel — Cancel just
        keeps the auto-generated defaults, it does not abort). The chosen
        name (or the auto-generated default if left blank/Escaped) seeds the
        default label for *every subsequent Play of this same recording* — it
        is not a one-time identity — and the replay-count/dry-run choices seed
        both the auto-chained playback and every later manual Play. A per-run
        rename (DiffsView's ``n`` key) only edits that one run's saved label
        and never touches this seed.

        On a completed Stop the recording **auto-chains straight into
        playback** with those settings (idea B), so Record → interact → Stop
        lands the user on the Diff panel with results; pressing ``p`` still
        re-plays the current recording manually with the same settings.

        Returns:
            True if recording was started successfully
        """
        from sandroid.tui.modals import RecordingModal, RecordingResult

        # Check if already recording
        if self.is_recording():
            self._log_warning("Recording already in progress. Stop it first.")
            return False

        if not self._push_modal:
            self._log_error("Cannot show recording modal - push_modal not configured")
            return False

        self._recording_seq += 1
        default_label = f"Run {self._recording_seq} · {time.strftime('%H:%M')}"
        # Seed sane fallbacks immediately, in case the live callback below
        # never fires for some reason (e.g. the modal is torn down early).
        self._current_recording_label = default_label

        def on_settings_chosen(
            label: str, number_of_runs: int, noise_filter: bool
        ) -> None:
            # Fires the moment the non-blocking Record-settings form is
            # dismissed — well before the recording session itself ends
            # (Stop/dismiss). Seeds every subsequent Play of this recording.
            self._current_recording_label = label
            self._current_number_of_runs = number_of_runs
            self._current_noise_filter = noise_filter

        def on_recording_result(result: RecordingResult) -> None:
            if result is None or result.cancelled:
                self._log_info("Recording cancelled")
                return

            if result.completed:
                # Belt-and-suspenders: keep the seeds in sync even if
                # on_settings_chosen was somehow never wired/fired.
                if getattr(result, "label", ""):
                    self._current_recording_label = result.label
                self._current_number_of_runs = getattr(
                    result, "number_of_runs", self._current_number_of_runs
                )
                self._current_noise_filter = getattr(
                    result, "noise_filter", self._current_noise_filter
                )
                self._log_success(
                    f"Recording saved: {result.event_count} events, {result.duration}s"
                )
                # Auto-chain (idea B): Record → interact → Stop flows straight
                # into playback with the chosen settings, landing the user on
                # the Diff panel with results.
                self.start_playback()

        self._log_info("Opening recording modal...")
        self._push_modal(
            RecordingModal(
                auto_start=True,
                default_label=default_label,
                default_number_of_runs=self._current_number_of_runs,
                default_noise_filter=self._current_noise_filter,
                on_settings_chosen=on_settings_chosen,
                on_recording_active_changed=self._set_recording_indicator,
                suppress_disconnect_guard=self._suppress_disconnect_guard,
            ),
            on_recording_result,
        )
        return True

    # =========================================================================
    # Playback Operations
    # =========================================================================

    def has_recording(self) -> bool:
        """Check if a recording file exists.

        Returns:
            True if recording file exists
        """
        raw_results_path = os.getenv("RAW_RESULTS_PATH", "./")
        recording_file = os.path.join(raw_results_path, "recording.txt")
        return os.path.exists(recording_file)

    def get_recording_path(self) -> str:
        """Get the path to the recording file.

        Returns:
            Path to recording file
        """
        raw_results_path = os.getenv("RAW_RESULTS_PATH", "./")
        return os.path.join(raw_results_path, "recording.txt")

    def start_playback(self) -> bool:
        """Start playback and analysis.

        Replays recorded input events and analyzes file system changes.
        Shows progress in activity log and summary modal at end.

        Returns:
            True if playback was started successfully
        """
        import functools

        # Check if recording exists
        recording_file = self.get_recording_path()
        logger.debug(f"Looking for recording at: {recording_file}")

        if not os.path.exists(recording_file):
            self._log_warning(
                f"No recording found at {recording_file}. Press [r] to record first."
            )
            return False

        # Check if snapshot exists - but don't block if we can't verify
        snapshot_verified = self._verify_snapshot()
        if not snapshot_verified:
            self._log_warning(
                "Could not verify snapshot path - proceeding anyway (recording created it)"
            )

        self._log_info("Starting playback analysis...")

        # Run playback in worker thread (non-blocking)
        if self._run_worker:
            self._run_worker(
                functools.partial(self._run_playback_analysis),
                name="playback_analysis",
                exclusive=True,
                thread=True,
            )
        else:
            # Fallback to synchronous execution
            self._run_playback_analysis()

        return True

    def _verify_snapshot(self) -> bool:
        """Verify that a snapshot exists for playback.

        Returns:
            True if snapshot was verified
        """
        try:
            toolbox = self._get_toolbox()
            device_name = toolbox.device_name
            snapshot_path = os.path.join(
                os.path.expanduser("~"),
                ".android",
                "avd",
                f"{device_name}.avd",
                "snapshots",
                "tmp",
            )

            logger.debug(f"Looking for snapshot at: {snapshot_path}")

            if os.path.exists(snapshot_path):
                return True

            # Try alternative path patterns
            alt_snapshot_path = os.path.join(
                os.path.expanduser("~"),
                ".android",
                "avd",
                f"{device_name}.avd",
                "snapshots",
                "default_boot",
            )
            if os.path.exists(alt_snapshot_path):
                self._log_info("Using default_boot snapshot")
                return True

        except Exception as e:
            logger.debug(f"Error checking snapshot path: {e}")

        return False

    def _stop_monitor_before_revert(self) -> Any | None:
        """Safety net: monitor's live ``adb shell`` session cannot survive
        Play's snapshot revert (``EmulatorService.load_snapshot()`` is a bare
        telnet command + ``sleep(2)``, zero adb-reconnect logic anywhere) and
        would otherwise silently die with no indication. Stop it cleanly
        *before* the revert instead, so its disappearance is explained rather
        than mysterious.

        True no-op when monitor isn't running: the ``is_running`` guard below
        means nothing else in this method executes (no stop call, no
        callback, no log line) — verified by a dedicated test.

        Calls ``TaskService.stop("monitor")`` directly rather than
        ``MonitorController.stop()``: the latter also calls
        ``_force_ui_refresh`` — a real Textual UI touch that is not safe to
        invoke un-marshaled from this worker thread. ``TaskService.stop()``
        itself is plain locking + ``MonitorProcessWrapper.stop()``
        (``process.terminate()``/``wait()``, no widget access) and is safe to
        call from any thread. Task-service state still gets cleaned up
        correctly and on the main thread shortly after: killing the process
        makes monitor's own output-reader thread notice ``process.poll()`` go
        non-None on its next iteration, which triggers
        ``MonitorController._monitor_ended`` via its own ``call_from_thread`` —
        the existing teardown path, unmodified by this change.

        Returns:
            The ``MonitorConfig`` monitor was running with (so a later "Resume
            monitoring" action can re-fork it), or ``None`` if monitor wasn't
            running, or if it was but the config couldn't be recovered.
        """
        try:
            task_service = self._get_task_service()
            if not task_service.is_running("monitor"):
                return None

            task = task_service.get_task("monitor")
            config = getattr(getattr(task, "instance", None), "config", None)

            task_service.stop("monitor")

            self._call_from_thread(
                self._log_warning,
                "monitor stopped — won't survive Play's snapshot revert.",
            )
            if self._on_monitor_stopped_for_playback:
                self._call_from_thread(self._on_monitor_stopped_for_playback)

            return config
        except Exception as e:
            logger.debug(f"monitor auto-stop safety check failed: {e}", exc_info=True)
            return None

    def _run_playback_analysis(self) -> None:
        """Execute the playback analysis via the unified ``AnalysisEngine``.

        Runs in a worker thread. Builds a self-contained *run bundle*
        (``core/run_bundle.py``) for this Play, copies the live recording into
        it up-front (so it is addressed by absolute path and immune to a
        mid-flow device switch re-pointing ``RAW_RESULTS_PATH``), then hands a
        :class:`~sandroid.analysis.run_config.RunConfig` to
        :class:`~sandroid.analysis.engine.AnalysisEngine`. The engine performs
        the whole load-snapshot / baseline / play / gather / first-second-noise
        pull / dry-run pipeline (replacing the old hand-rolled ``[n/6]`` body)
        and returns a :class:`~sandroid.analysis.run_config.RunResult` whose
        *native* diff shapes (``{file: [diff_lines]} | str``) are persisted
        verbatim into the :class:`~sandroid.core.run_history.RunRecord`.

        A fatal step (e.g. a mid-run device switch) makes the engine return a
        partial ``RunResult(error=...)`` rather than raising; that partial
        result is persisted too, so a failed run stays visible in Diffs with
        its error message. The monitor Play-safety-net (stop-before-revert +
        resume offer) is preserved around the engine run, as are the Replay
        UI indicator and the disconnect-guard suppression (both bracket the
        actual ``AnalysisEngine(...).run()`` call — see the ``try/finally``
        below).
        """
        from sandroid.analysis.engine import AnalysisEngine
        from sandroid.analysis.run_config import RunConfig
        from sandroid.core import run_bundle, run_history

        toolbox = self._get_toolbox()
        device_name = getattr(toolbox, "device_name", None) or "unknown"
        recorded_at = datetime.now().isoformat()
        run_id = run_history.new_run_id()
        result: Any = None
        error: str | None = None
        abs_rec = self.get_recording_path()
        monitor_config_for_resume: Any = None

        try:
            # Safety net (see _stop_monitor_before_revert's docstring): monitor
            # cannot survive the snapshot revert the engine's first step does,
            # so stop it cleanly *before* handing off to the engine rather than
            # let it silently die. True no-op if monitor isn't running.
            monitor_config_for_resume = self._stop_monitor_before_revert()

            # Build the run bundle and copy the live recording into it up-front
            # so every later step reads it by absolute path.
            run_bundle.create_bundle(run_id)
            abs_rec = run_bundle.import_recording(run_id, self.get_recording_path())

            config = RunConfig.for_playback(
                recording_path=abs_rec,
                number_of_runs=self._current_number_of_runs,
                noise_filter=self._current_noise_filter,
            )
            config.raw_results_path = run_bundle.raw_dir(run_id)
            config.results_path = str(run_bundle.bundle_dir(run_id))
            config.device_name = device_name

            # Bracket the actual engine run with the Replay indicator and the
            # disconnect-guard suppression: the engine's LoadSnapshotStep
            # reverts the emulator (once per bracketed step, across every
            # replay iteration), which transiently disrupts the ADB
            # transport and would otherwise trip a false "Device
            # disconnected" toast. Both the "arm" and the "disarm" calls live
            # inside this try/finally (not just the disarm) so a raise from
            # either arm call still reaches the finally instead of leaving
            # the indicator/guard stuck on — the finally's own calls are
            # idempotent when the matching arm never ran.
            try:
                if self._set_replay_indicator:
                    self._call_from_thread(self._set_replay_indicator, True)
                if self._suppress_disconnect_guard:
                    self._suppress_disconnect_guard(True)
                result = AnalysisEngine(
                    config,
                    progress=self._emit_progress,
                    toolbox=toolbox,
                    forensic_service=self._get_forensic_service(),
                    action_window_service=self._get_action_window_service(),
                ).run()
                # The engine returns a partial RunResult(error=...) for a
                # fatal step instead of raising, so surface that as this
                # run's error.
                error = result.error
            finally:
                if self._suppress_disconnect_guard:
                    self._suppress_disconnect_guard(False)
                if self._set_replay_indicator:
                    self._call_from_thread(self._set_replay_indicator, False)
        except Exception as e:
            error = f"Playback failed: {e}"
            self._call_from_thread(self._log_error, error)

        # Persist regardless of a mid-pipeline error, so a failed/partial run
        # is still visible in Diffs (with its error message) instead of
        # silently vanishing — this is exactly why RunRecord.error exists.
        self._call_from_thread(self._log_info, "Saving results...")
        saved_run_id = self._persist_run(
            run_id=run_id,
            result=result,
            recording_path=abs_rec,
            bundle_dir=str(run_bundle.bundle_dir(run_id)),
            device_name=device_name,
            recorded_at=recorded_at,
            error=error,
        )

        if error is None and result is not None:
            self._call_from_thread(
                self._log_success,
                f"Analysis complete: {len(result.changed_files)} changed, "
                f"{len(result.new_files)} new, "
                f"{len(result.deleted_files)} deleted files",
            )

        if saved_run_id and self._on_run_saved:
            self._call_from_thread(self._on_run_saved, saved_run_id)

        # Offer to resume monitoring once Play is fully done — regardless of
        # success/error above, since resuming monitor is orthogonal to whether
        # the diff analysis itself errored. Only fires if monitor was actually
        # auto-stopped for *this* run (monitor_config_for_resume is None both
        # when monitor wasn't running to begin with, and in the true-no-op
        # case covered by _stop_monitor_before_revert).
        if monitor_config_for_resume is not None and self._on_monitor_resume_available:
            self._call_from_thread(
                self._on_monitor_resume_available, monitor_config_for_resume
            )

    def _emit_progress(self, update: Any) -> None:
        """Marshal an engine ``ProgressUpdate`` to a UI-thread log line.

        Replaces the old hand-rolled ``[n/6]`` step strings — the engine now
        drives progress at run boundaries via ``AnalysisEngine(progress=...)``.
        Invoked on the playback worker thread, so the log write is marshaled to
        the UI thread via ``call_from_thread``.
        """
        label = getattr(update, "label", "") or ""
        message = getattr(update, "message", "") or ""
        line = f"{label}: {message}" if message else label
        if not line:
            return
        self._call_from_thread(self._log_info, line)

    def _persist_run(
        self,
        *,
        run_id: str,
        result: Any,
        recording_path: str,
        bundle_dir: str,
        device_name: str,
        recorded_at: str,
        error: str | None,
    ) -> str | None:
        """Persist this Play's run-bundle manifest (a :class:`RunRecord`).

        Returns the new ``run_id`` on success, or ``None`` if saving failed
        (logged, never raised — a persistence failure must not crash the
        playback worker thread). When ``result`` is a
        :class:`~sandroid.analysis.run_config.RunResult` its native diff shapes
        are preserved via ``to_run_record``; when it is ``None`` (an exception
        aborted the run before the engine returned) a minimal error-only record
        is written so the failed run still appears in Diffs.

        Also (still) writes the legacy ``RESULTS_PATH/sandroid.json`` summary
        for anything outside the TUI that reads it.
        """
        from sandroid.core import run_bundle, run_history

        completed_at = datetime.now().isoformat()
        label = self._current_recording_label or f"Run · {time.strftime('%H:%M')}"

        if result is not None:
            duration = int(getattr(result, "action_duration", 0) or 0)
            record = result.to_run_record(
                run_id=run_id,
                label=label,
                recording_path=recording_path,
                bundle_dir=bundle_dir,
                recorded_at=recorded_at,
                completed_at=completed_at,
                duration=duration,
            )
            # to_run_record already copies result.error; keep any wrapping
            # error (e.g. a bundle/import failure) if one was recorded.
            if error is not None:
                record.error = error
        else:
            duration = 0
            record = run_history.RunRecord(
                schema_version=run_history.SCHEMA_VERSION,
                run_id=run_id,
                label=label,
                recorded_at=recorded_at,
                completed_at=completed_at,
                device_name=device_name,
                recording_path=recording_path,
                bundle_dir=bundle_dir,
                duration=duration,
                error=error,
                changed_files=[],
                new_files=[],
                deleted_files=[],
                counts={"changed": 0, "new": 0, "deleted": 0},
            )

        saved_run_id: str | None = run_id
        try:
            run_bundle.write_manifest(record)
        except Exception as e:
            self._call_from_thread(
                self._log_warning,
                f"Could not save run history: {e}",
            )
            saved_run_id = None

        # Legacy summary file some external tooling may still read.
        try:
            import json

            results_path = os.getenv("RESULTS_PATH", "./")
            output_file = os.path.join(results_path, "sandroid.json")
            data = {
                "Device Name": device_name,
                "Action Duration": duration,
            }
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            self._call_from_thread(
                self._log_info,
                f"[warning]Could not save legacy results summary: {e}[/warning]",
            )

        return saved_run_id

    # =========================================================================
    # Export Operations
    # =========================================================================

    def show_export_modal(self) -> bool:
        """Export recorded action.

        Shows export modal with component selection.

        Returns:
            True if export modal was shown
        """
        from sandroid.tui.modals import ExportModal, ExportResult

        if not self._push_modal:
            self._log_error("Cannot show export modal - push_modal not configured")
            return False

        def on_export_result(result: ExportResult) -> None:
            if result is None or result.cancelled:
                self._log_info("Export cancelled")
                return

            if result.success:
                self._log_success(f"Exported to: {result.export_path}")
            elif result.error:
                self._log_error(f"Export failed: {result.error}")

        self._log_info("Opening export modal...")
        self._push_modal(ExportModal(), on_export_result)
        return True


__all__ = [
    "PlaybackResult",
    "RecordingController",
    "RecordingResult",
]
