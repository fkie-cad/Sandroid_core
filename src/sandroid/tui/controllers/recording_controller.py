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
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def reset_device_handles_after_snapshot_load() -> None:
    """Forget device state that an emulator snapshot load has invalidated.

    Loading a snapshot kills every app process and the emulator's frida
    device object. Afterwards the cached ``JobManager.device`` raised
    "device is gone" on every spawn until the TUI was restarted, and
    Spotlight kept showing the dead PID. Drops the job manager's session
    and device handle (it re-creates the handle lazily on the next spawn),
    the frida device cache and the Spotlight PID, then publishes
    ``STATE_CHANGED`` so the panels refresh. Never raises; call it from a
    worker thread (the session reset may wait on frida for a few seconds).
    """
    from sandroid import services

    try:
        frida_svc = services.get_frida_session_service()
        jm = getattr(frida_svc, "_job_manager", None)
        if jm is not None:
            try:
                jm.reset_session(timeout_per_job=1.0, detach_timeout=1.0)
            except Exception:
                logger.debug(
                    "JobManager reset after snapshot load failed", exc_info=True
                )
            jm.device = None
        frida_svc.invalidate_frida_device_cache()
    except Exception:
        logger.debug("Could not reset frida state after snapshot load", exc_info=True)
    try:
        services.get_spotlight_service().set_pid(None)
    except Exception:
        logger.debug("Could not clear the Spotlight PID", exc_info=True)
    try:
        from sandroid.core.events import Event, EventBus, EventType

        EventBus.get().publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={"change_type": "snapshot_loaded"},
                source="recording_controller",
            )
        )
    except Exception:
        logger.debug("Could not publish the snapshot-load refresh", exc_info=True)


def drop_stale_frida_device() -> bool:
    """Drop the job manager's frida device handle if it can no longer work.

    For device (re)connects: after an emulator restart the serial is the
    same, so nothing else refreshes ``JobManager.device`` and every spawn
    fails with "device is gone". The handle is dropped when frida reports
    it lost, or when no process session uses it; the job manager re-creates
    it on the next spawn. Never raises.

    Returns:
        True if a handle was dropped.
    """
    try:
        from sandroid import services

        jm = getattr(services.get_frida_session_service(), "_job_manager", None)
        device = getattr(jm, "device", None)
        if device is None:
            return False
        lost = bool(getattr(device, "is_lost", False))
        if lost or getattr(jm, "process_session", None) is None:
            jm.device = None
            return True
    except Exception:
        logger.debug("Could not check the frida device handle", exc_info=True)
    return False


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
        set_replay_phase: Callable[[str | None], None] | None = None,
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
            set_replay_phase: Callback invoked (via call_from_thread) with
                the running Play's phase (``"loading snapshot"``,
                ``"replay 1/2"``, ``"settle 8s"``, ``"collecting results"``,
                ``"dry run"``, ``"analysing"``, ``"saving"``) and with
                ``None`` once the Play is over (success, error or cancel), so
                the header pill / status strip can show where a 5-10 minute
                Play is. Safe to leave unset.
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
        # Wrapped: every indicator change is also a run/record-start or
        # run/record-stop line on the session timeline (modal and chat).
        self._set_recording_indicator = self._timeline_indicator(
            set_recording_indicator
        )
        #: How the current recording was started ("modal" | "chat").
        self._record_via = "modal"
        #: Session-timeline seqs of the open recording's start, and of the
        #: last recording's (start, stop) -- a Play replays that range.
        self._tl_record_start: int | None = None
        self._tl_recording = False
        self._tl_record_stop: int | None = None
        self._tl_record_range: list[int] | None = None
        #: A record-start was written that has no record-result yet (Esc on
        #: the Record-settings form never started one: no result line).
        self._tl_result_due = False
        self._set_replay_indicator = set_replay_indicator
        self._suppress_disconnect_guard = suppress_disconnect_guard
        self._set_replay_phase = set_replay_phase
        # Label of the run the current Play will save: the recording's label
        # for the Play that auto-chains after a Record, None (= a fresh
        # "Run N · HH:MM") for a manual ``p`` / AI replay -- a manual Play
        # used to copy the previous run's label (M-31).
        self._play_label: str | None = None
        #: Run id of the Play that ran right after the recording (named in
        #: the Record dialog); ``p``'s confirm names the recording by that
        #: run's *current* label, so a rename shows up there.
        self._recording_run_id: str | None = None
        # Whether mitmproxy ran when the current Play started (recorded with
        # the run's flows).
        self._mitm_at_start: bool | None = None
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
        # AI-chat replay state (see start_playback_chat/_run_playback_analysis):
        # `_is_replaying` fixes get_replay_status() -- `TaskService.is_running(
        # "playback_analysis")` would always read False, since that name is only
        # ever a Textual `run_worker` name, never registered with TaskService.
        # `_replay_owner_id` is the resource-arbiter owner id (see
        # sandroid.ai.loop._current_owner_id) that claimed ResourceId.WORLD for
        # the in-flight replay, stashed here at kickoff time so
        # `_run_playback_analysis`'s completion path (which runs on a DETACHED
        # worker thread that outlives the tool call's own synchronous dispatch)
        # can release that lease itself once the replay actually finishes. Both
        # are None/False for a manual/keybinding-triggered replay (no AI owner,
        # nothing was ever claimed) -- see `_release_replay_world_lease`.
        self._is_replaying = False
        self._replay_owner_id: str | None = None

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def _ui(self, fn: Callable[..., Any], *args: Any) -> None:
        """Run a UI callback on the main thread; never raise.

        ``App.call_from_thread`` re-raises whatever the callback raised and
        raises itself once the app has stopped (crash or quit). On the
        playback worker that used to abort the thread before the run was
        persisted, so a UI problem lost the analysis results (P2-H1). UI
        updates are best-effort; persistence must never depend on them.
        """
        try:
            self._call_from_thread(fn, *args)
        except Exception:
            logger.debug("UI update %r failed (ignored)", fn, exc_info=True)

    @staticmethod
    def _guarded(fn: Callable[..., Any], *args: Any) -> None:
        """Call ``fn(*args)`` directly, logging instead of raising."""
        try:
            fn(*args)
        except Exception:
            logger.debug("Callback %r failed (ignored)", fn, exc_info=True)

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

    @property
    def is_replaying(self) -> bool:
        """Whether a replay (Play) is currently in progress.

        Backed by ``self._is_replaying`` -- set/cleared around
        ``_run_playback_analysis``'s engine run (see that method), NOT
        ``TaskService.is_running("playback_analysis")``: that name is only
        ever a Textual ``run_worker`` name, never registered with
        ``TaskService``, so that check would always read False.
        """
        return self._is_replaying

    @property
    def current_recording_label(self) -> str | None:
        """The active (or most recently completed) recording's label.

        ``None`` before any recording has ever been started this session.
        """
        return self._current_recording_label

    def start_recording(self) -> bool:
        """Start input event recording.

        Shows recording modal that captures input events from the device.
        Creates a snapshot before recording starts.

        The modal is pushed with ``auto_start=True`` — see ``RecordingModal``
        — which shows the combined Record-settings form (idea B: name +
        replays + dry-run) *immediately*, before anything else happens.
        Recording itself (the pre-snapshot and ``RecordingWrapper`` start)
        only begins once that form is confirmed (Cancel/Esc there aborts the
        recording -- reported as "Recording cancelled"). The chosen
        name (or the auto-generated default if left blank) seeds the
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

        previous = (
            self._recording_seq,
            self._current_recording_label,
            self._current_number_of_runs,
            self._current_noise_filter,
        )
        self._recording_seq += 1
        # Numbered like a manual Play (this device's next run), not per
        # session: the session counter restarted at "Run 1" every launch.
        # (Toolbox.device_name: no adb call on the UI thread.)
        default_label = self._fresh_run_label(
            getattr(self._get_toolbox(), "device_name", None)
        )
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
            self._timeline_record_result(
                events=getattr(result, "event_count", 0) if result else 0,
                duration_s=getattr(result, "duration", 0) if result else 0,
                completed=bool(getattr(result, "completed", False)),
                cancelled=result is None or bool(result.cancelled),
            )
            if result is None or result.cancelled:
                # The earlier recording (if any) is still the one ``p``
                # replays: keep its seeds instead of the cancelled dialog's.
                (
                    self._recording_seq,
                    self._current_recording_label,
                    self._current_number_of_runs,
                    self._current_noise_filter,
                ) = previous
                self._log_info("Recording cancelled")
                return

            if result.completed:
                self._recording_run_id = None  # a new recording
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
                # the Diff panel with results. This Play's run carries the
                # label chosen in the Record dialog.
                self.start_playback(label=self._current_recording_label)

        self._record_via = "modal"
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

    def start_recording_chat(
        self, label: str, number_of_runs: int = 2, noise_filter: bool = True
    ) -> dict[str, Any]:
        """Start a recording from the AI chat -- no modal, no auto-chained replay.

        Headless counterpart to :meth:`start_recording` for the AI
        tool-dispatch thread (confirmed to be a background worker thread,
        never Textual's main thread -- see ``chat_panel.py``'s
        ``run_worker(..., thread=True)``). There is deliberately no
        ``RecordingModal`` here: the AI is expected to have already asked
        the analyst for *label* in chat before calling this, and tells them
        in chat when to perform the action and when to stop -- the modal's
        job is replaced by the chat turn itself. Record and replay are
        separate tool calls, never auto-chained in code (unlike
        :meth:`start_recording`'s modal-driven "Stop -> auto-play"): the LLM
        decides when to call :meth:`start_playback_chat`, typically right
        after stopping but it may wait if asked to.

        Threading discipline: every call here that touches a UI callback
        (``_log_info``/``_log_success``/``_set_recording_indicator``/
        ``_suppress_disconnect_guard``) is wrapped in
        ``self._call_from_thread(...)``. The ADB-blocking calls
        (``Toolbox.create_snapshot``, ``RecordingWrapper.start()``) are
        deliberately NOT wrapped -- that dance in ``RecordingModal`` exists
        only to avoid freezing the Textual UI thread, which is not a
        concern here since the tool-dispatch thread is already off the main
        thread (wrapping them would instead freeze the UI thread for the
        duration of the ADB call, the opposite of what's needed).

        Args:
            label: Human-readable name for this run. Seeds the default
                label for every subsequent Play of this recording, same as
                the modal's chosen name.
            number_of_runs: Replay-repeat count seeded for a later Play.
            noise_filter: Dry-run noise-filter toggle seeded for a later
                Play.

        Returns:
            ``{"success": False, "message": str}`` if a recording is already
            in progress, the snapshot failed, or the recorder failed to
            start; ``{"success": True, "label": str}`` once recording has
            actually started.
        """
        if self.is_recording():
            return {"success": False, "message": "Recording already in progress"}

        self._recording_seq += 1
        self._recording_run_id = None
        self._current_recording_label = label or f"Run {self._recording_seq}"
        self._current_number_of_runs = number_of_runs
        self._current_noise_filter = noise_filter

        if self._suppress_disconnect_guard:
            self._ui(self._suppress_disconnect_guard, True)
        try:
            self._get_toolbox().create_snapshot(b"tmp")
        except Exception as e:
            if self._suppress_disconnect_guard:
                self._ui(self._suppress_disconnect_guard, False)
            return {"success": False, "message": f"Failed to create snapshot: {e}"}
        if self._suppress_disconnect_guard:
            self._ui(self._suppress_disconnect_guard, False)

        from sandroid.tui.utils.recording_wrapper import RecordingWrapper

        wrapper = RecordingWrapper(output_file=self.get_recording_path())
        if not wrapper.start():
            return {"success": False, "message": "Failed to start recording"}

        self._get_task_service().register(
            name="recording",
            display_name="Recording",
            instance=wrapper,
            stop_callback=wrapper.stop,
        )
        if self._set_recording_indicator:
            self._record_via = "chat"
            self._ui(self._set_recording_indicator, True)
        self._ui(
            self._log_info,
            f"[AI] Recording '{self._current_recording_label}' started",
        )
        return {"success": True, "label": self._current_recording_label}

    def stop_recording_chat(self) -> dict[str, Any]:
        """Stop the current chat-triggered (or modal-driven) recording.

        Headless counterpart to Stop for the AI tool-dispatch thread. Does
        NOT auto-chain into playback -- call :meth:`start_playback_chat`
        separately once the analyst says they're done (or immediately, if
        that's the default the LLM has been told to use).

        Returns:
            ``{"success": False, "message": str}`` if nothing was
            recording, else ``{"success": True, "event_count": int,
            "duration": float, "label": str | None}``.
        """
        if not self.is_recording():
            return {"success": False, "message": "No recording in progress"}

        task = self._get_task_service().get_task("recording")
        wrapper = task.instance if task else None
        event_count = wrapper.event_count if wrapper else 0
        self._get_task_service().stop("recording")
        duration = wrapper.elapsed_seconds if wrapper else 0

        if self._set_recording_indicator:
            self._ui(self._set_recording_indicator, False)
        self._timeline_record_result(
            events=event_count, duration_s=duration, completed=True, cancelled=False
        )
        self._ui(
            self._log_success,
            f"[AI] Recording stopped: {event_count} events, {duration}s",
        )
        return {
            "success": True,
            "event_count": event_count,
            "duration": duration,
            "label": self._current_recording_label,
        }

    # =========================================================================
    # Playback Operations
    # =========================================================================

    def has_recording(self) -> bool:
        """Check if a recording file exists.

        Returns:
            True if recording file exists
        """
        return os.path.exists(self.get_recording_path())

    def get_recording_path(self) -> str:
        """Get the path to the recording file.

        Record writes ``recording.getevent.txt`` (a raw ``getevent -t``
        slice); the legacy ``recording.txt`` is never written any more.

        Returns:
            Path to recording file
        """
        from sandroid.core.run_bundle import RECORDING_FILENAME

        raw_results_path = os.getenv("RAW_RESULTS_PATH", "./")
        return os.path.join(raw_results_path, RECORDING_FILENAME)

    def start_playback(self, label: str | None = None) -> bool:
        """Start playback and analysis.

        Replays recorded input events and analyzes file system changes.
        Shows progress in activity log and summary modal at end.

        Args:
            label: Label of the run this Play saves. ``None`` (manual ``p``,
                AI replay) gives the run a fresh default label
                (``"Run N · HH:MM"``); the auto-chained Play after a Record
                passes the label chosen in the Record dialog.

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
            # Expected whenever the host-side AVD dir isn't where we guess
            # (custom ANDROID_AVD_HOME, AVD name != device name, ...); the
            # engine loads the snapshot via the emulator console anyway.
            logger.debug(
                "Could not verify snapshot path - proceeding anyway "
                "(recording created it)"
            )

        self._log_info("Starting playback analysis...")
        self._play_label = label or None

        # A previous Stop/quit left the process-wide cancel flag set.
        from sandroid.features.player import Player

        Player.clear_cancel()

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

    @staticmethod
    def recording_seconds(path: str) -> float | None:
        """Length of a recording (first to last input event), or None.

        Both formats: raw ``getevent -t`` lines (``recording.getevent.txt``)
        and legacy ``<epoch ms> <device> <type> <code> <value>`` lines.
        """
        from sandroid.features.player import parse_store_line

        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                stamps = [
                    parsed[0]
                    for parsed in (parse_store_line(line) for line in f)
                    if parsed is not None
                ]
        except OSError:
            return None
        if len(stamps) < 2:
            return None
        return max(0.0, (stamps[-1] - stamps[0]) / 1000.0)

    def play_plan(self) -> dict[str, Any]:
        """What ``p`` is about to do, for its confirm dialog.

        ``{"recording": label, "number_of_runs", "noise_filter", "seconds":
        recording length or None, "estimate": rough total seconds or None}``.
        The estimate is (replays + dry run) x (recording + settle + ~150 s)
        + ~180 s. Per replay window: snapshot load + network reset (45-120 s)
        and the result collection pull (85-110 s); once: the baseline scan
        (90-160 s) and the analysis -- as measured on the emulator (a Play of
        an 80 s recording with 2 replays took 13-16 min, not the 6 min the
        old ~35 s per window promised).
        """
        seconds = self.recording_seconds(self.get_recording_path())
        windows = self._current_number_of_runs + (
            1 if self._current_noise_filter else 0
        )
        estimate = None
        if seconds is not None:
            from sandroid.analysis.engine import _replay_settle_seconds

            settle = _replay_settle_seconds(None)
            estimate = windows * (seconds + settle + 150) + 180
        label = self._current_recording_label
        if self._recording_run_id:
            try:
                from sandroid.core import run_history

                label = run_history.load_run(self._recording_run_id).label or label
            except Exception:
                pass
        return {
            "recording": label,
            "number_of_runs": self._current_number_of_runs,
            "noise_filter": self._current_noise_filter,
            "seconds": seconds,
            "estimate": estimate,
        }

    def stop_playback(self) -> bool:
        """Stop the running replay (Play) as soon as possible.

        Sets the process-wide :class:`~sandroid.features.player.Player`
        cancel flag: the replay stops before its next input event, the
        engine skips the remaining runs, and the partial run is still saved
        (with a "Replay cancelled" error) by :meth:`_run_playback_analysis`.
        Call from the UI thread; a no-op when nothing is replaying.

        Returns:
            True if a replay was running and has been asked to stop.
        """
        from sandroid.features.player import Player

        if not self._is_replaying:
            return False
        Player.cancel_all()
        self._guarded(self._log_warning, "Stopping replay...")
        return True

    def start_playback_chat(
        self,
        number_of_runs: int | None = None,
        noise_filter: bool | None = None,
        owner_id: str | None = None,
    ) -> dict[str, Any]:
        """Start a replay from the AI chat.

        Headless counterpart to Play for the AI tool-dispatch thread.
        :meth:`start_playback` itself only pushes one ``run_worker(...,
        thread=True)`` call -- cheap, but ``run_worker`` is a Textual API
        that must be invoked from the main thread same as any other, so
        that one call is wrapped in ``self._call_from_thread(...)`` here.
        The actual replay work (:meth:`_run_playback_analysis`) then runs on
        ITS OWN worker thread exactly as it does for a manual/keybinding
        Play -- unaffected by which thread kicked it off.

        *owner_id* is the resource-arbiter owner id that claimed
        ``ResourceId.WORLD`` for this call (see
        ``ai/tools/recording_control.py``'s ``start_replay``, which reads it
        from ``sandroid.ai.loop._current_owner_id`` before calling this --
        the same pattern ``enable_app_proxy`` already uses to capture an
        owner id for later-attributed release). It is stashed on
        ``self._replay_owner_id`` ONLY once every early-return check has
        passed and the worker is actually about to be kicked off -- never
        earlier -- so a rejected call (no recording / already recording)
        never leaves a stale owner id lying around for a future unrelated
        replay to pick up. :meth:`_run_playback_analysis` releases the
        matching ``WORLD`` lease itself once the replay actually finishes
        (see :meth:`_release_replay_world_lease`) -- this is a deliberately
        held-across-the-async-worker lease, unlike every other AI tool's
        claim/release, which happens within one synchronous dispatch.

        Args:
            number_of_runs: Override the seeded replay-repeat count for
                this Play (and future ones, until the next Record). ``None``
                keeps the current seed.
            noise_filter: Override the seeded dry-run/noise-filter toggle.
                ``None`` keeps the current seed.
            owner_id: The AI resource-arbiter owner id that claimed
                ``ResourceId.WORLD`` for this replay, or ``None`` for a
                manual/keybinding-triggered call (nothing was claimed, so
                nothing needs releasing later).

        Returns:
            ``{"success": False, "message": str}`` if there is no recording
            to replay, or one is still in progress; otherwise
            ``{"success": True, "number_of_runs": int, "noise_filter":
            bool}`` once the replay worker has been kicked off -- the
            worker itself runs in the background, poll
            ``get_replay_status()`` for completion.
        """
        if not self.has_recording():
            return {"success": False, "message": "No recording found — record first"}
        if self.is_recording():
            return {
                "success": False,
                "message": "Stop the current recording before replaying",
            }

        if number_of_runs is not None:
            self._current_number_of_runs = number_of_runs
        if noise_filter is not None:
            self._current_noise_filter = noise_filter

        self._replay_owner_id = owner_id
        self._call_from_thread(self.start_playback)
        return {
            "success": True,
            "number_of_runs": self._current_number_of_runs,
            "noise_filter": self._current_noise_filter,
        }

    @staticmethod
    def _active_device_name() -> str | None:
        """Name of the active device (AVD name for emulators), or None.

        Also records it in the session state (``Toolbox.device_name``) when
        that still holds another value, e.g. the hard-coded default.
        """
        try:
            from sandroid.core.device_manager import (
                DeviceManager,
                resolve_device_name,
            )

            dm = DeviceManager.get()
            device = dm.active_device
            if device is None:
                return None
            if device.is_emulator:
                dm.get_avd_name_for_device(device)  # cached after the first call
            name = resolve_device_name(device)
            if name:
                DeviceManager._sync_session_device_name(device)
            return name or None
        except Exception:
            logger.debug("Could not resolve the active device name", exc_info=True)
            return None

    def _current_device_name(self) -> str:
        """Device name a run is recorded under.

        Resolved from the active device at run time rather than trusting
        ``Toolbox.device_name`` alone: that value starts as the hard-coded
        session default (``Pixel_6_Pro_API_31``) and was not updated on
        every activation path, so runs, sandroid.json and the PDF named the
        wrong device (P2-H5). Falls back to ``Toolbox.device_name`` without
        a device, and whenever the session does not agree with the resolved
        name: the engine aborts a run whose ``Toolbox.device_name`` differs
        from the configured one ("device changed mid-run").
        """
        toolbox = self._get_toolbox()
        fallback = getattr(toolbox, "device_name", None) or "unknown"
        name = self._active_device_name()
        if name and getattr(toolbox, "device_name", None) == name:
            return name
        return fallback

    @staticmethod
    def _avd_dir(avd_name: str) -> str | None:
        """Host directory of ``avd_name`` (honours ANDROID_AVD_HOME and the
        ``path=`` redirect in ``<avd>.ini``), or None if not found.
        """
        try:
            from sandroid.config.android_env import find_existing_avd_home

            home = find_existing_avd_home()
        except Exception:
            home = None
        if home is None:
            home = Path("~/.android/avd").expanduser()
        ini = home / f"{avd_name}.ini"
        try:
            for line in ini.read_text(encoding="utf-8").splitlines():
                key, _, value = line.partition("=")
                if key.strip() == "path" and Path(value.strip()).is_dir():
                    return value.strip()
        except OSError:
            pass
        default = home / f"{avd_name}.avd"
        return str(default) if default.is_dir() else None

    def _verify_snapshot(self) -> bool:
        """Verify that a snapshot exists for playback.

        Returns:
            True if snapshot was verified
        """
        try:
            toolbox = self._get_toolbox()
            name = self._active_device_name() or getattr(toolbox, "device_name", "")
            avd_dir = self._avd_dir(name) if name else None
            if avd_dir is None:
                return False
            snapshot_path = os.path.join(avd_dir, "snapshots", "tmp")
            logger.debug(f"Looking for snapshot at: {snapshot_path}")
            if os.path.exists(snapshot_path):
                return True
            if os.path.exists(os.path.join(avd_dir, "snapshots", "default_boot")):
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

            self._ui(
                self._log_warning,
                "monitor stopped — won't survive Play's snapshot revert.",
            )
            if self._on_monitor_stopped_for_playback:
                self._ui(self._on_monitor_stopped_for_playback)

            return config
        except Exception as e:
            logger.debug(f"monitor auto-stop safety check failed: {e}", exc_info=True)
            return None

    def _release_replay_world_lease(self) -> None:
        """Release the AI-triggered replay's held ``ResourceId.WORLD`` lease, if any.

        ``start_replay`` (``ai/tools/recording_control.py``) claims
        ``ResourceId.WORLD`` at tool-dispatch time but declares
        ``releases=frozenset()`` -- deliberately NOT auto-released when the
        tool call itself returns, since ``start_playback_chat`` only kicks
        off a detached background worker (:meth:`_run_playback_analysis`)
        and returns immediately, long before the replay (and its
        snapshot-reverting ``LoadSnapshotStep``, repeated across every
        replay iteration) is actually done. This is the other half of that
        deferred-release pattern: called from :meth:`_run_playback_analysis`'s
        outermost ``finally`` (success, an engine-reported error, or an
        earlier pre-engine setup failure all release the SAME lease exactly
        once).

        Guarded by ``self._replay_owner_id`` so a manual/keybinding-triggered
        replay (no AI owner -- ``start_playback()`` called directly, never
        through ``start_playback_chat``) never touches the arbiter at all.
        Clears ``self._replay_owner_id`` unconditionally afterward so a
        second, unrelated replay (AI- or manually-triggered) never re-releases
        a stale id.
        """
        owner = self._replay_owner_id
        self._replay_owner_id = None
        if not owner:
            return
        try:
            from sandroid.ai.arbiter import ResourceId, get_arbiter

            get_arbiter().release_resources(owner, frozenset({ResourceId.WORLD}))
        except Exception:
            logger.debug("Failed to release replay WORLD lease", exc_info=True)

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

        AI-chat replay tracking (Part D): ``self._is_replaying`` is set here
        and cleared in the OUTERMOST ``finally`` below -- deliberately
        wrapping the WHOLE pre-engine setup (monitor safety-net + run-bundle
        creation) as well as the engine run itself, not just the inner
        try/finally that brackets ``AnalysisEngine(...).run()``. A failure
        in that pre-engine setup (e.g. ``run_bundle.create_bundle``/
        ``import_recording`` raising) would otherwise skip the inner
        try/finally entirely and leak the replay's held ``ResourceId.WORLD``
        lease (see :meth:`_release_replay_world_lease`) forever, since no
        other code path ever releases it for an AI-triggered replay.
        """
        from sandroid.analysis.engine import AnalysisEngine
        from sandroid.analysis.run_config import RunConfig
        from sandroid.core import run_bundle, run_history

        toolbox = self._get_toolbox()
        device_name = self._current_device_name()
        recorded_at = datetime.now().isoformat()
        run_id = run_history.new_run_id()
        play_start = self._timeline_play_start(run_id)
        result: Any = None
        error: str | None = None
        abs_rec = self.get_recording_path()
        monitor_config_for_resume: Any = None

        self._is_replaying = True
        self._mitm_at_start = self._mitm_running()
        try:
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
                config.run_id = run_id
                # Recorded in the run metadata as the settings actually used.
                self._last_run_config = config

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
                        self._ui(self._set_replay_indicator, True)
                    self._report_phase("starting")
                    if self._suppress_disconnect_guard:
                        self._guarded(self._suppress_disconnect_guard, True)
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
                    # The engine's snapshot loads killed every app process
                    # and the frida device handle; drop both so the next
                    # spawn and the Spotlight PID start fresh.
                    reset_device_handles_after_snapshot_load()
                    if self._suppress_disconnect_guard:
                        self._guarded(self._suppress_disconnect_guard, False)
                    if self._set_replay_indicator:
                        self._ui(self._set_replay_indicator, False)
            except Exception as e:
                error = f"Playback failed: {e}"
                self._ui(self._log_error, error)
        finally:
            self._is_replaying = False
            self._release_replay_world_lease()

        # Persist regardless of a mid-pipeline error, so a failed/partial run
        # is still visible in Diffs (with its error message) instead of
        # silently vanishing — this is exactly why RunRecord.error exists.
        # Every UI touch goes through _ui(), which never raises, so a dead or
        # broken UI can no longer skip this step (P2-H1).
        self._ui(self._log_info, "Saving results...")
        if self._set_replay_phase:
            self._ui(self._set_replay_phase, "saving")
        try:
            saved_run_id = self._persist_run(
                run_id=run_id,
                result=result,
                recording_path=abs_rec,
                bundle_dir=str(run_bundle.bundle_dir(run_id)),
                device_name=device_name,
                recorded_at=recorded_at,
                error=error,
            )
        except Exception as e:
            logger.exception("Persisting run %s failed", run_id)
            self._ui(self._log_error, f"Could not save run {run_id}: {e}")
            saved_run_id = None
        finally:
            self._play_label = None
            if self._set_replay_phase:
                self._ui(self._set_replay_phase, None)
        self._timeline_play_end(run_id, play_start, result, error, saved_run_id)

        if error == "Replay cancelled":
            self._ui(self._log_warning, "Replay stopped; the partial run was saved.")
        elif error is None and result is not None:
            self._ui(
                self._log_success,
                f"Analysis complete: {len(result.changed_files)} changed, "
                f"{len(result.new_files)} new, "
                f"{len(result.deleted_files)} deleted files",
            )

        if saved_run_id and self._on_run_saved:
            self._ui(self._on_run_saved, saved_run_id)

        # Offer to resume monitoring once Play is fully done — regardless of
        # success/error above, since resuming monitor is orthogonal to whether
        # the diff analysis itself errored. Only fires if monitor was actually
        # auto-stopped for *this* run (monitor_config_for_resume is None both
        # when monitor wasn't running to begin with, and in the true-no-op
        # case covered by _stop_monitor_before_revert).
        if monitor_config_for_resume is not None and self._on_monitor_resume_available:
            self._ui(self._on_monitor_resume_available, monitor_config_for_resume)

    # -- session timeline (run/* lines) ---------------------------------------

    def _timeline_indicator(
        self, original: Callable[[bool], None] | None
    ) -> Callable[[bool], None]:
        """``set_recording_indicator`` that also writes record-start/stop."""

        def indicator(active: bool) -> None:
            try:
                self._timeline_record(bool(active))
            except Exception:
                logger.debug("timeline: record line failed", exc_info=True)
            if original is not None:
                original(active)

        return indicator

    def _timeline_actor(self) -> str:
        return "ai" if self._record_via == "chat" else "user"

    def _timeline_record(self, active: bool) -> None:
        from sandroid.core.timeline import get_timeline

        service = get_timeline()
        if active and not self._tl_recording:
            label = self._current_recording_label or ""
            self._tl_recording = True
            self._tl_result_due = True
            self._tl_record_start = service.set_phase(
                "record",
                None,
                kind="record-start",
                summary=f"● REC · {label}" if label else "● REC",
                actor=self._timeline_actor(),
                data={
                    "label": label,
                    "number_of_runs": self._current_number_of_runs,
                    "via": self._record_via,
                },
            )
        elif not active and self._tl_recording:
            start = self._tl_record_start
            self._tl_recording = False
            self._tl_record_stop = service.set_phase(
                "live",
                None,
                kind="record-stop",
                summary="■ REC stopped",
                actor=self._timeline_actor(),
                ref={"of": start} if start is not None else None,
            )
            if start is not None and self._tl_record_stop is not None:
                self._tl_record_range = [start, self._tl_record_stop]

    def _timeline_record_result(
        self, *, events: Any, duration_s: Any, completed: bool, cancelled: bool
    ) -> None:
        """``run/record-result`` (after the recording stopped); nothing when
        no ``record-start`` was written (cancelled before Record started).
        """
        try:
            if not self._tl_result_due:
                return
            self._tl_result_due = False
            from sandroid.core.timeline import get_timeline

            state = "cancelled" if cancelled else f"{events} events, {duration_s} s"
            stop = self._tl_record_stop
            get_timeline().emit(
                "run",
                "record-result",
                summary=f"recording · {state}",
                actor=self._timeline_actor(),
                data={
                    "events": events,
                    "duration_s": duration_s,
                    "completed": completed,
                    "cancelled": cancelled,
                },
                ref={"of": stop} if stop is not None else None,
            )
        except Exception:
            logger.debug("timeline: record-result line failed", exc_info=True)
        finally:
            self._record_via = "modal"
            self._tl_record_stop = None

    def _timeline_play_start(self, run_id: str) -> int | None:
        """``run/play-start``: the Play's run id becomes the timeline's run."""
        try:
            from sandroid.core.timeline import get_timeline

            label = self._play_label or ""
            seq_range = self._tl_record_range
            return get_timeline().set_phase(
                "live",
                run_id,
                kind="play-start",
                summary=f"▷ Play · {label}" if label else f"▷ Play · {run_id}",
                data={
                    "label": label or None,
                    "number_of_runs": self._current_number_of_runs,
                    "noise_filter": self._current_noise_filter,
                    "bundle": f"runs/{run_id}",
                },
                replays=(
                    {"run": None, "seq_range": list(seq_range)} if seq_range else None
                ),
            )
        except Exception:
            logger.debug("timeline: play-start line failed", exc_info=True)
            return None

    def _timeline_play_end(
        self,
        run_id: str,
        play_start: int | None,
        result: Any,
        error: str | None,
        saved_run_id: str | None,
    ) -> None:
        """``run/play-end``: back to live, no run."""
        try:
            from sandroid.core.timeline import get_timeline

            def _count(name: str) -> int | None:
                value = getattr(result, name, None)
                try:
                    return len(value) if value is not None else None
                except TypeError:
                    return None

            changed = _count("changed_files")
            ref = {"run": run_id, "lens": "runs"}
            if play_start is not None:
                ref["of"] = play_start
            summary = "■ Play done" if error is None else f"■ Play ended · {error}"
            if error is None and changed is not None:
                summary += f" · {changed} changed"
            get_timeline().set_phase(
                "live",
                None,
                kind="play-end",
                summary=summary,
                data={
                    "error": error,
                    "saved": saved_run_id is not None,
                    "changed": changed,
                    "new": _count("new_files"),
                    "deleted": _count("deleted_files"),
                },
                ref=ref,
            )
        except Exception:
            logger.debug("timeline: play-end line failed", exc_info=True)

    def _emit_progress(self, update: Any) -> None:
        """Marshal an engine ``ProgressUpdate`` to a UI-thread log line.

        Replaces the old hand-rolled ``[n/6]`` step strings — the engine now
        drives progress at run boundaries via ``AnalysisEngine(progress=...)``.
        Invoked on the playback worker thread, so the log write is marshaled to
        the UI thread via ``call_from_thread``.
        """
        phase = getattr(update, "phase", "") or ""
        if phase:
            self._report_phase(phase)
            return
        label = getattr(update, "label", "") or ""
        message = getattr(update, "message", "") or ""
        line = f"{label}: {message}" if message else label
        if not line:
            return
        self._ui(self._log_info, line)

    def _report_phase(self, phase: str | None) -> None:
        """Tell the UI which phase the Play is in (None: the Play is over)."""
        if phase:
            self._ui(self._log_info, f"Play · {phase}")
        if self._set_replay_phase:
            self._ui(self._set_replay_phase, phase)

    @staticmethod
    def _mitm_running() -> bool | None:
        """Whether the embedded mitmproxy runs (None: unknown)."""
        try:
            from sandroid.services.mitmproxy_service import peek_mitmproxy_service

            service = peek_mitmproxy_service()
            return bool(service is not None and service.is_running())
        except Exception:
            return None

    def _fresh_run_label(
        self, device_name: str | None, started_at: str | None = None
    ) -> str:
        """``"Run N · HH:MM"`` (N = this device's next run).

        ``HH:MM`` is ``started_at`` (the Play's start, ISO) when given, so the
        label agrees with the run's "When" -- not the end of its analysis.
        """
        from sandroid.core import run_history

        try:
            n = len(run_history.load_index(device_name)) + 1
        except Exception:
            n = 1
        hhmm = time.strftime("%H:%M")
        if started_at:
            try:
                hhmm = datetime.fromisoformat(started_at).strftime("%H:%M")
            except ValueError:
                pass
        return f"Run {n} · {hhmm}"

    def _export_run_flows(
        self,
        *,
        bundle_dir: str,
        recorded_at: str,
        completed_at: str,
        phases: Any,
    ) -> None:
        """Copy the run's mitmproxy flows into ``<bundle>/network/``.

        Runs before the bundle's hash manifest is written, so the flows are
        covered by ``SHA256SUMS`` and a later session can review them (the
        session's flow log is per session). Never raises.
        """
        try:
            from sandroid.core import run_history
            from sandroid.services import mitmproxy_flow_log

            start = datetime.fromisoformat(recorded_at).timestamp()
            end = datetime.fromisoformat(completed_at).timestamp()
            try:
                flow_dir = mitmproxy_flow_log.resolve_flow_dir()
            except Exception:
                flow_dir = None
            running = self._mitm_running()
            if self._mitm_at_start or running:
                mitm = True
            elif self._mitm_at_start is None and running is None:
                mitm = None
            else:
                mitm = False
            meta = mitmproxy_flow_log.export_run_flows(
                flow_dir,
                Path(bundle_dir) / run_history.NETWORK_DIR_NAME,
                start,
                end,
                phases,
                mitm_running=mitm,
            )
            if meta.get("count"):
                logger.info(
                    "Stored %d mitmproxy flow(s) in the run bundle", meta["count"]
                )
        except Exception:
            logger.warning(
                "Could not store the run's flows in its bundle", exc_info=True
            )

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
        label = _unique_run_label(
            self._play_label or self._fresh_run_label(device_name, recorded_at),
            device_name,
        )
        if self._play_label:
            self._recording_run_id = run_id

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
            self._ui(
                self._log_warning,
                f"Could not save run history: {e}",
            )
            saved_run_id = None

        # Full results JSON (+ run metadata), optional PDF and the evidence
        # hash manifest, written into the run bundle -- the same finalisation
        # the CLI and headless API use. The run's mitmproxy flows go into the
        # bundle first, so the manifest covers them.
        if result is not None:
            self._export_run_flows(
                bundle_dir=bundle_dir,
                recorded_at=recorded_at,
                completed_at=completed_at,
                phases=record.phases,
            )
            self._finalize_run_bundle(
                run_id=run_id,
                result=result,
                bundle_dir=bundle_dir,
                recorded_at=recorded_at,
            )

        try:
            from sandroid.core import run_bundle as _rb

            _rb.record_session_bundle(bundle_dir)
        except Exception:
            logger.debug("Could not register run bundle for exit summary")

        # Legacy session-level summary: a pointer to where the data really is.
        try:
            import json

            results_path = os.getenv("SESSION_PATH") or os.getenv("RESULTS_PATH", "./")
            output_file = os.path.join(results_path, "sandroid.json")
            data = {
                "Device Name": device_name,
                "Action Duration": duration,
                "Run ID": run_id,
                "Run Bundle": bundle_dir,
                "Results": os.path.join(bundle_dir, "sandroid.json"),
            }
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            self._ui(
                self._log_info,
                f"[warning]Could not save legacy results summary: {e}[/warning]",
            )

        return saved_run_id

    def _finalize_run_bundle(
        self, *, run_id: str, result: Any, bundle_dir: str, recorded_at: str
    ) -> None:
        """Write results JSON, optional PDF and manifest into the run bundle.

        Never raises (runs on the playback worker thread); problems are
        logged to the activity log.
        """
        try:
            from sandroid.core import run_report
            from sandroid.core.adb import Adb

            cfg = getattr(self._get_toolbox(), "config", None)
            generate_pdf = bool(
                getattr(getattr(cfg, "report", None), "generate_pdf", False)
            )
            run_config = getattr(self, "_last_run_config", None)
            outcome = run_report.finalize_run(
                bundle_dir,
                result.to_json_dict(),
                adb=Adb,
                config=cfg,
                started_at=recorded_at,
                run_id=run_id,
                mode="tui-play",
                generate_pdf=generate_pdf,
                run_settings=(
                    run_report.describe_run_settings(run_config)
                    if run_config is not None
                    else None
                ),
            )
            if outcome.pdf is not None:
                self._ui(self._log_success, f"PDF report: {outcome.pdf}")
            for err in outcome.errors:
                self._ui(self._log_warning, f"Report finalisation issue: {err}")
        except Exception as e:
            logger.exception("finalize_run failed")
            self._ui(self._log_warning, f"Could not write run report files: {e}")

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


def _unique_run_label(label: str, device_name: str | None) -> str:
    """``label``, or ``"<label> · play N"`` if a run of it is already saved.

    The recording's label seeds every Play of it, so a ``p`` replay showed
    up as a second, indistinguishable "Run 1 · 22:58" in the Runs rail.
    """
    from sandroid.core import run_history

    try:
        taken = {e.get("label") for e in run_history.load_index(device_name)}
    except Exception:
        return label
    if label not in taken:
        return label
    n = 2
    while f"{label} · play {n}" in taken:
        n += 1
    return f"{label} · play {n}"
