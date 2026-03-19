"""Network Capture Controller for TUI.

This controller manages network capture start/stop operations, extracted from
the monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Toggle network capture on/off
- Show configuration modal for capture setup
- Start capture in background worker thread
- Stop capture with safe task removal
- Track capture state via service layer

Usage:
    from sandroid.tui.controllers import NetworkCaptureController

    controller = NetworkCaptureController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        log_error=activity_log.log_error,
        log_success=activity_log.log_success,
        push_modal=app.push_screen,
        run_worker=app.run_worker,
        call_from_thread=app.call_from_thread,
    )

    # Toggle capture or show modal
    controller.toggle_or_show_modal()
"""

import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class NetworkCaptureController:
    """Controller for network capture operations.

    This controller handles all network capture operations, decoupled from
    the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of capture logic from UI rendering
    - Reusable capture management across different UI modes

    Thread Safety:
        Capture start/stop operations run in worker threads.
        UI callbacks are invoked via call_from_thread.

    Example:
        controller = NetworkCaptureController(
            log_info=print,
            log_warning=lambda msg: print(f"WARN: {msg}"),
            log_error=lambda msg: print(f"ERROR: {msg}"),
            log_success=lambda msg: print(f"OK: {msg}"),
            push_modal=lambda modal, cb: cb(None),
            run_worker=lambda fn, **kw: fn(),
            call_from_thread=lambda fn, *args: fn(*args),
        )

        # Toggle capture or show configuration modal
        controller.toggle_or_show_modal()
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
    ):
        """Initialize NetworkCaptureController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI.
            log_warning: Callback for warning-level logging to UI.
            log_error: Callback for error-level logging to UI.
            log_success: Callback for success-level logging to UI.
            push_modal: Callback to push a modal screen with result callback.
            run_worker: Callback to run function in worker thread.
            call_from_thread: Callback to execute function on main thread.
        """
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_error = log_error or self._default_log
        self._log_success = log_success or self._default_log
        self._push_modal = push_modal
        self._run_worker = run_worker
        self._call_from_thread = call_from_thread or (lambda fn, *args: fn(*args))

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    # =========================================================================
    # Public API
    # =========================================================================

    def toggle_or_show_modal(self) -> None:
        """Toggle network capture or show configuration modal.

        Behavior:
        - If capturing: stop immediately (no modal needed, status visible in menu)
        - If not capturing: show modal to configure output path and start
        """
        from sandroid.services import get_network_capture_service, get_task_service

        # Check current capture state
        network_service = get_network_capture_service()
        task_service = get_task_service()
        is_capturing = network_service.is_capturing() or task_service.is_running(
            "network"
        )

        if is_capturing:
            # Stop directly without modal - user can see status in menu/activity log
            self.stop_capture()
            return

        # Not capturing - show modal to configure and start
        from sandroid.tui.modals import NetworkCaptureModal, NetworkCaptureResult

        # Generate default path from session results folder
        default_path = None
        try:
            from sandroid.analysis.network import Network

            network = Network()
            default_path = network.get_expected_capture_path()
        except Exception:
            pass

        def on_capture_result(result: NetworkCaptureResult) -> None:
            if result is None or result.cancelled:
                return

            if result.action == "start":
                self.start_capture(result.output_path)

        if self._push_modal:
            self._push_modal(
                NetworkCaptureModal(
                    is_capturing=False,
                    current_file=None,
                    default_path=default_path,
                ),
                on_capture_result,
            )

    def start_capture(self, output_path: Any = None) -> None:
        """Start network capture in background worker.

        Args:
            output_path: Optional output path for capture file.
        """
        import functools

        # Log immediately on main thread BEFORE spawning worker
        self._log_info("Starting network capture...")

        if self._run_worker:
            self._run_worker(
                functools.partial(self._start_capture_worker, output_path),
                name="network_capture_start",
                exclusive=False,
                thread=True,
            )

    def stop_capture(self) -> None:
        """Stop network capture in a background worker.

        IMPORTANT: We do NOT force UI refresh here because it makes
        blocking ADB calls. The TaskStopped event published by
        network.stop() will trigger UI updates via the event system.
        """
        from sandroid.services import get_network_capture_service, get_task_service

        capture_file = get_network_capture_service().get_capture_file()
        self._log_info(f"Stopping network capture ({capture_file or 'capture'})...")

        # Check if capture is running before spawning worker
        task_service = get_task_service()
        if not task_service.is_running("network"):
            self._log_warning("No network capture running")
            return

        # Get the network instance to pass to worker
        task = task_service.get_task("network")
        if not task or not task.instance:
            self._log_warning("Network capture task not found")
            return

        network_instance = task.instance

        # Remove from task service immediately (no lock, no events, no blocking)
        # -- bypasses public API intentionally to avoid deadlock.
        # TODO: consider adding public API for non-blocking task removal
        task_service._tasks.pop("network", None)

        # Spawn worker IMMEDIATELY - the event system will update UI
        # when TaskStopped is published
        if self._run_worker:
            self._run_worker(
                lambda: self._stop_capture_worker(network_instance, capture_file),
                name="network_capture_stop",
                exclusive=False,
                thread=True,
            )

    # =========================================================================
    # Worker Methods (run in background threads)
    # =========================================================================

    def _start_capture_worker(self, output_path: Any = None) -> None:
        """Worker thread for starting network capture.

        IMPORTANT: task_service.register() triggers synchronous event handlers
        that use call_from_thread(), which can block. We must call our UI
        callback BEFORE register() to ensure it gets through.

        Args:
            output_path: Optional output path for capture file.
        """
        try:
            from sandroid.analysis.network import Network

            # Create Network instance
            network = Network()

            # Get capture file path
            capture_file = network.get_expected_capture_path()

            # Start capture (spawns background thread, returns immediately)
            network.gather()

            # IMPORTANT: Call UI callback BEFORE task_service.register()
            # because register() triggers synchronous event handlers that block
            self._call_from_thread(self._on_capture_started, capture_file)

            # Register with task service (this may block due to event handlers)
            from sandroid.services import get_task_service

            get_task_service().register(
                name="network",
                display_name="Network Capture",
                instance=network,
                stop_callback=network.stop,
            )

        except Exception as e:
            # Capture exception message to avoid closure issues
            error_msg = str(e)
            self._call_from_thread(self._on_capture_failed, error_msg)

    def _stop_capture_worker(self, network_instance: Any, capture_file: str) -> None:
        """Worker thread that actually stops the network capture.

        This calls network.stop() which:
        1. Sends blocking ADB "network capture stop" command
        2. Publishes TaskStopped event (triggers UI update via event system)

        Args:
            network_instance: The Network instance to stop.
            capture_file: Path to the capture file.
        """
        try:
            # Call stop() directly - this sends ADB command and publishes events
            network_instance.stop()
            # No need to call_from_thread here - TaskStopped event handles UI
        except Exception as e:
            # Just log to Python logger, don't try to update UI from worker
            logger.error(f"Error stopping capture: {e}")

    # =========================================================================
    # UI Callbacks (run on main thread via call_from_thread)
    # =========================================================================

    def _on_capture_started(self, capture_file: str) -> None:
        """Handle successful network capture start (runs on main thread).

        Note: We don't force UI refresh because it makes blocking ADB calls.
        The TaskStarted event from task_service.register() updates the UI.

        Args:
            capture_file: Path to the capture file.
        """
        self._log_success(f"Network capture started: {capture_file}")

    def _on_capture_failed(self, error_msg: str) -> None:
        """Handle network capture failure (runs on main thread).

        Args:
            error_msg: Description of the failure.
        """
        self._log_error(f"Network capture failed: {error_msg}")


__all__ = [
    "NetworkCaptureController",
]
