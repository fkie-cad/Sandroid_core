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
from collections.abc import Callable
from dataclasses import dataclass
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

        def on_recording_result(result: RecordingResult) -> None:
            if result is None or result.cancelled:
                self._log_info("Recording cancelled")
                return

            if result.completed:
                self._log_success(
                    f"Recording saved: {result.event_count} events, {result.duration}s"
                )

        self._log_info("Opening recording modal...")
        self._push_modal(RecordingModal(), on_recording_result)
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

    def _run_playback_analysis(self) -> None:
        """Execute playback analysis pipeline (runs in worker thread)."""
        from sandroid.analysis.changedfiles import ChangedFiles
        from sandroid.analysis.newfiles import NewFiles
        from sandroid.features.player import Player

        changed_files_data = []
        new_files_data = []
        duration = 0
        toolbox = self._get_toolbox()

        try:
            # Step 1: Load snapshot
            self._call_from_thread(self._log_info, "[1/5] Loading snapshot...")
            toolbox.load_snapshot(b"tmp")

            # Step 2: Create baseline
            self._call_from_thread(self._log_info, "[2/5] Creating baseline...")
            forensic = self._get_forensic_service()
            forensic.set_baseline(toolbox.fetch_changed_files(fetch_all=True))

            # Step 3: Play recording
            self._call_from_thread(self._log_info, "[3/5] Playing recording...")
            player = Player()
            player.perform()
            duration = self._get_forensic_service().get_action_duration()

            # Step 4: Analyze changed files
            self._call_from_thread(self._log_info, "[4/5] Analyzing changed files...")
            changed_files_obj = ChangedFiles()
            changed_files_obj.gather()
            changed_files_result = changed_files_obj.return_data().get(
                "Changed Files", []
            )
            changed_files_data = self._extract_file_names(changed_files_result)

            # Step 5: Analyze new files
            self._call_from_thread(self._log_info, "[5/5] Analyzing new files...")
            new_files_obj = NewFiles()
            new_files_obj.gather()
            new_files_result = new_files_obj.return_data().get("New Files", [])
            new_files_data = self._flatten_file_list(new_files_result)

            # Save results
            self._call_from_thread(self._log_info, "Saving results...")
            self._save_playback_results()

            # Show summary modal on main thread
            self._call_from_thread(
                self._show_analysis_summary,
                changed_files_data,
                new_files_data,
                [],
                duration,
            )

        except Exception as e:
            error_msg = f"Playback failed: {e}"
            self._call_from_thread(self._log_error, error_msg)

    def _extract_file_names(self, file_list: list[Any]) -> list[str]:
        """Extract file names from analysis result.

        Args:
            file_list: List of file entries (dicts or strings)

        Returns:
            List of file names
        """
        result = []
        for item in file_list:
            if isinstance(item, dict):
                result.extend(item.keys())
            elif isinstance(item, str):
                result.append(item)
        return result

    def _flatten_file_list(self, file_list: list[Any]) -> list[str]:
        """Flatten nested file list.

        Args:
            file_list: List that may contain nested lists

        Returns:
            Flattened list of file names
        """
        result = []
        for item in file_list:
            if isinstance(item, list):
                result.extend(item)
            elif isinstance(item, str):
                result.append(item)
        return result

    def _save_playback_results(self) -> None:
        """Save playback results to file."""
        import json

        try:
            results_path = os.getenv("RESULTS_PATH", "./")
            output_file = f"{results_path}sandroid.json"
            toolbox = self._get_toolbox()

            data = {
                "Device Name": toolbox.device_name,
                "Action Duration": self._get_forensic_service().get_action_duration(),
            }

            with open(output_file, "w") as f:
                json.dump(data, f, indent=4)

        except Exception as e:
            self._call_from_thread(
                self._log_info,
                f"[warning]Could not save results: {e}[/warning]",
            )

    def _show_analysis_summary(
        self,
        changed_files: list[str],
        new_files: list[str],
        deleted_files: list[str],
        duration: int,
    ) -> None:
        """Show the analysis summary modal."""
        from sandroid.tui.modals import (
            AnalysisData,
            AnalysisSummaryModal,
            AnalysisSummaryResult,
        )

        self._log_success(
            f"Analysis complete: {len(changed_files)} changed, "
            f"{len(new_files)} new, {len(deleted_files)} deleted files"
        )

        data = AnalysisData(
            changed_files=changed_files,
            new_files=new_files,
            deleted_files=deleted_files,
            duration=duration,
        )

        def on_summary_result(result: AnalysisSummaryResult) -> None:
            if (
                result is not None
                and result.action == "exported"
                and result.export_path
            ):
                logger.info(f"Analysis results exported to: {result.export_path}")

        if self._push_modal:
            self._push_modal(AnalysisSummaryModal(data=data), on_summary_result)

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
