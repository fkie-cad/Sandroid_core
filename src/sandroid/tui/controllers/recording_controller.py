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
        # Recording-session bookkeeping for the label-seed flow (see
        # start_recording()): a monotonic counter for the "Run N" default
        # name, and the label seed that every subsequent Play of the current
        # recording defaults to (until a fresh Record replaces it).
        self._recording_seq = 0
        self._current_recording_label: str | None = None

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

        Recording itself starts immediately and non-blockingly (the modal is
        pushed with ``auto_start=True`` — see ``RecordingModal``), and a
        "Label this run" prompt pops right after: recording captures *device*
        interaction, not TUI input, so stacking that prompt on top blocks
        nothing time-sensitive. The chosen label (or the auto-generated
        default if the user leaves it blank/Escapes) seeds the default label
        for *every subsequent Play of this same recording* — it is not a
        one-time identity. A later per-run rename (DiffsView's ``n`` key)
        only edits that one run's saved label and never touches this seed.

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
        # Seed a sane fallback immediately, in case the live callback below
        # never fires for some reason (e.g. the modal is torn down early).
        self._current_recording_label = default_label

        def on_label_chosen(label: str) -> None:
            # Fires the moment the non-blocking label prompt is dismissed —
            # well before the recording session itself ends (Stop/dismiss).
            self._current_recording_label = label

        def on_recording_result(result: RecordingResult) -> None:
            if result is None or result.cancelled:
                self._log_info("Recording cancelled")
                return

            if result.completed:
                # Belt-and-suspenders: keep the seed in sync even if
                # on_label_chosen was somehow never wired/fired.
                if getattr(result, "label", ""):
                    self._current_recording_label = result.label
                self._log_success(
                    f"Recording saved: {result.event_count} events, {result.duration}s"
                )

        self._log_info("Opening recording modal...")
        self._push_modal(
            RecordingModal(
                auto_start=True,
                default_label=default_label,
                on_label_chosen=on_label_chosen,
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
        """Execute playback analysis pipeline (runs in worker thread).

        Keeps the *native* result shapes from each analyzer instead of
        flattening them to bare filenames — ``changed_files`` stays
        ``ChangedFiles.return_data()``'s ``{file: [diff_lines]} | str`` list
        (real diff text for diffed sqlite/xml/txt files, a bare path for
        everything else), all the way through to the persisted
        :class:`~sandroid.core.run_history.RunRecord`. The old
        ``_extract_file_names()``/``_flatten_file_list()`` helpers that threw
        the diff text away are gone. ``DeletedFiles`` is now gathered too
        (previously only the CLI's ``ActionQ``/headless
        ``api/analysis_runners.py`` path called it — never this TUI Play
        path), mirroring the same gather-order those callers use: Changed,
        then New, then Deleted, all via ``.gather()`` + ``.return_data()``.
        """
        from sandroid.analysis.changedfiles import ChangedFiles
        from sandroid.analysis.deletedfiles import DeletedFiles
        from sandroid.analysis.newfiles import NewFiles
        from sandroid.features.player import Player

        changed_files_data: list[Any] = []
        new_files_data: list[str] = []
        deleted_files_data: list[str] = []
        duration = 0
        error: str | None = None
        toolbox = self._get_toolbox()
        recorded_at = datetime.now().isoformat()
        monitor_config_for_resume: Any = None

        try:
            # Safety net (see _stop_monitor_before_revert's docstring): monitor
            # cannot survive the snapshot revert about to happen in Step 1,
            # so stop it cleanly right before that call rather than let it
            # silently die. True no-op if monitor isn't running.
            monitor_config_for_resume = self._stop_monitor_before_revert()

            # Step 1: Load snapshot
            self._call_from_thread(self._log_info, "[1/6] Loading snapshot...")
            toolbox.load_snapshot(b"tmp")

            # Step 2: Create baseline
            self._call_from_thread(self._log_info, "[2/6] Creating baseline...")
            forensic = self._get_forensic_service()
            forensic.set_baseline(toolbox.fetch_changed_files(fetch_all=True))

            # Step 3: Play recording
            self._call_from_thread(self._log_info, "[3/6] Playing recording...")
            player = Player()
            player.perform()
            duration = self._get_forensic_service().get_action_duration()

            # Step 4: Analyze changed files (native shape kept — see docstring)
            self._call_from_thread(self._log_info, "[4/6] Analyzing changed files...")
            changed_files_obj = ChangedFiles()
            changed_files_obj.gather()
            changed_files_data = changed_files_obj.return_data().get(
                "Changed Files", []
            )

            # Step 5: Analyze new files
            self._call_from_thread(self._log_info, "[5/6] Analyzing new files...")
            new_files_obj = NewFiles()
            new_files_obj.gather()
            new_files_data = new_files_obj.return_data().get("New Files", [])

            # Step 6: Analyze deleted files (newly wired into the TUI Play path)
            self._call_from_thread(self._log_info, "[6/6] Analyzing deleted files...")
            deleted_files_obj = DeletedFiles()
            deleted_files_obj.gather()
            deleted_files_data = deleted_files_obj.return_data().get(
                "Deleted Files", []
            )

        except Exception as e:
            error = f"Playback failed: {e}"
            self._call_from_thread(self._log_error, error)

        # Persist regardless of a mid-pipeline error, so a failed/partial run
        # is still visible in Diffs (with its error message) instead of
        # silently vanishing — this is exactly why RunRecord.error exists.
        self._call_from_thread(self._log_info, "Saving results...")
        run_id = self._save_playback_results(
            changed_files_data,
            new_files_data,
            deleted_files_data,
            duration,
            recorded_at,
            error,
        )

        if error is None:
            self._call_from_thread(
                self._log_success,
                f"Analysis complete: {len(changed_files_data)} changed, "
                f"{len(new_files_data)} new, {len(deleted_files_data)} deleted files",
            )

        if run_id and self._on_run_saved:
            self._call_from_thread(self._on_run_saved, run_id)

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

    def _save_playback_results(
        self,
        changed_files: list[Any],
        new_files: list[str],
        deleted_files: list[str],
        duration: int,
        recorded_at: str,
        error: str | None,
    ) -> str | None:
        """Persist this Play as a :class:`RunRecord` (run_history.py).

        Returns the new ``run_id`` on success, or ``None`` if saving failed
        (logged, never raised — a persistence failure must not crash the
        playback worker thread).

        Also (still) writes the legacy ``RESULTS_PATH/sandroid.json`` summary
        for anything outside the TUI that reads it.
        """
        from sandroid.core import run_history

        toolbox = self._get_toolbox()
        device_name = getattr(toolbox, "device_name", None) or "unknown"
        run_id = run_history.new_run_id()
        label = self._current_recording_label or f"Run · {time.strftime('%H:%M')}"

        record = run_history.RunRecord(
            schema_version=run_history.SCHEMA_VERSION,
            run_id=run_id,
            label=label,
            recorded_at=recorded_at,
            completed_at=datetime.now().isoformat(),
            device_name=device_name,
            recording_path=self.get_recording_path(),
            duration=duration,
            error=error,
            changed_files=changed_files,
            new_files=new_files,
            deleted_files=deleted_files,
            counts={
                "changed": len(changed_files),
                "new": len(new_files),
                "deleted": len(deleted_files),
            },
        )

        try:
            run_history.save_run(record)
        except Exception as e:
            self._call_from_thread(
                self._log_warning,
                f"Could not save run history: {e}",
            )
            run_id = None

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

        return run_id

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
