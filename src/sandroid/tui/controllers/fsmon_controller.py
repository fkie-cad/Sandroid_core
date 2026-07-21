"""FSMon Controller for TUI.

This controller manages FSMon filesystem monitoring operations, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Start/stop FSMon monitoring
- Configure monitoring paths and PIDs
- Process and display filesystem events
- Handle monitoring lifecycle
- Publish live events to the Files tab's Monitor sub-tab via the EventBus

Usage:
    from sandroid.tui.controllers import FSMonController

    controller = FSMonController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        push_modal=app.push_screen,
        call_from_thread=app.call_from_thread,
        force_ui_refresh=app._force_ui_refresh,
    )

    # Start FSMon monitoring
    controller.start_fsmon()
"""

import logging
import re
import threading
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from rich.markup import escape

logger = logging.getLogger(__name__)


@dataclass
class FSMonConfig:
    """Configuration for FSMon monitoring."""

    mode: str = "path"  # "pid" or "path"
    target_path: str = "/data/"
    target_pid: int | None = None
    app_name: str = ""
    cancelled: bool = False


# Regex to strip ANSI escape sequences and carriage returns from PTY output.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\r")

# Shared color rules for fsmon event colorization.
# Used by both the controller (activity log) and the Files tab's Monitor
# sub-tab (tui/widgets/monitor_view.py).
FSMON_COLOR_RULES: list[tuple[tuple[str, ...], str]] = [
    (("CREATE", "WRITE", "MODIFY"), "green"),
    (("DELETE", "REMOVE", "UNLINK"), "red"),
    (("RENAME", "MOVE"), "yellow"),
    (("OPEN", "ACCESS", "READ"), "cyan"),
]


def colorize_fsmon_line(line: str, max_width: int = 0) -> str:
    """Apply color markup to an fsmon output line.

    Escapes raw content first to prevent Rich markup interpretation,
    then wraps in color tags based on filesystem event keywords.

    Args:
        line: Raw fsmon output line.
        max_width: Truncate to this width before escaping. 0 means no truncation.

    Returns:
        Escaped and optionally colorized Rich markup string.
    """
    truncated = line[:max_width] if max_width > 0 else line
    escaped = escape(truncated)
    for keywords, color in FSMON_COLOR_RULES:
        if any(kw in line for kw in keywords):
            return f"[{color}]{escaped}[/{color}]"
    return escaped


def _publish_fsmon_event(message: str) -> None:
    """Publish an fsmon TASK_OUTPUT event to the EventBus.

    Mirrors ``analysis/fritap.py``'s ``_publish_fritap_event`` — the Monitor
    sub-tab (``tui/widgets/monitor_view.py``) subscribes to
    ``EventType.TASK_OUTPUT`` filtered by ``source == "fsmon"``, the same
    idiom ``FriTapPanel`` uses for ``source == "fritap"``. Lazy import
    (matches every other EventBus/TaskService touch in this controller, e.g.
    ``_get_task_service``) to avoid a module-level dependency on the core
    event system.

    Args:
        message: Already-colorized (``colorize_fsmon_line``) Rich markup
            message for the line.
    """
    try:
        from sandroid.core.events import Event, EventBus, EventType

        EventBus.get().publish(
            Event(
                type=EventType.TASK_OUTPUT,
                data={"task_name": "FSMon", "message": message},
                source="fsmon",
            )
        )
    except Exception:
        logger.debug("Failed to publish fsmon EventBus event", exc_info=True)


class FSMonController:
    """Controller for FSMon filesystem monitoring.

    This controller handles all FSMon-related operations, decoupled from
    the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of FSMon logic from UI rendering
    - Reusable FSMon management across different UI modes

    Thread Safety:
        FSMon output reading runs in background threads.
        Log callbacks are invoked via call_from_thread.

    Example:
        controller = FSMonController(
            log_info=print,
            log_warning=lambda msg: print(f"WARN: {msg}"),
            push_modal=lambda modal, cb: cb(None),
            call_from_thread=lambda fn, *args: fn(*args),
            force_ui_refresh=lambda: None,
        )

        # Start FSMon
        controller.start_fsmon()
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_warning: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        log_success: Callable[[str], None] | None = None,
        log_message: Callable[[str, str], None] | None = None,
        log_task_started: Callable[[str, str], None] | None = None,
        log_task_stopped: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        call_from_thread: Callable[..., None] | None = None,
        force_ui_refresh: Callable[[], None] | None = None,
        get_current_view: Callable[[], str] | None = None,
        open_files_tab: Callable[[], None] | None = None,
    ):
        """Initialize FSMonController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI
            log_warning: Callback for warning-level logging to UI
            log_error: Callback for error-level logging to UI
            log_success: Callback for success-level logging to UI
            log_message: Callback for generic message logging (message, source)
            log_task_started: Callback when task starts (name, description)
            log_task_stopped: Callback when task stops (name)
            push_modal: Callback to push a modal screen with result callback
            call_from_thread: Callback to execute function on main thread
            force_ui_refresh: Callback to force UI refresh after state changes
            get_current_view: Callback to get current view mode
            open_files_tab: Callback to switch the TUI to the Files tab's
                Monitor sub-tab, invoked once fsmon has actually *started*
                (after ``_start_fsmon`` registers with TaskService) — not
                merely when the config modal opens. Mirrors friTap's
                ``h`` key -> ``MainScreen.open_fritap_tab()`` jump
                (``app.py``'s ``action_action_key``). Injected rather than
                importing ``app.py``/``MainScreen`` directly here, same
                reasoning as every other UI callback on this controller.
        """
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_error = log_error or self._default_log
        self._log_success = log_success or self._default_log
        self._log_message = log_message
        self._log_task_started = log_task_started
        self._log_task_stopped = log_task_stopped
        self._push_modal = push_modal
        self._call_from_thread = call_from_thread or (lambda fn, *args: fn(*args))
        self._force_ui_refresh = force_ui_refresh
        self._get_current_view = get_current_view
        self._open_files_tab = open_files_tab

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def _get_task_service(self) -> Any:
        """Get task service instance."""
        from sandroid.services import get_task_service

        return get_task_service()

    # =========================================================================
    # FSMon Status
    # =========================================================================

    def is_running(self) -> bool:
        """Check if FSMon is currently running.

        Returns:
            True if FSMon is active
        """
        return self._get_task_service().is_running("fsmon")

    def can_start(self) -> tuple[bool, str]:
        """Check if FSMon can be started.

        Returns:
            Tuple of (can_start, reason_if_not)
        """
        if self.is_running():
            return (
                False,
                "FSMon is already running. Press 'o' to stop it.",
            )

        return True, ""

    # =========================================================================
    # FSMon Operations
    # =========================================================================

    def show_config_modal(self) -> bool:
        """Show FSMon configuration modal.

        Returns:
            True if modal was shown
        """
        from sandroid.tui.modals import FSMonConfigModal

        can_start, reason = self.can_start()

        if not can_start:
            # Already running -> toggle it off (mirrors the old
            # already-running-in-background-mode behavior; there is no
            # observer modal to restore anymore, Monitor is the only
            # display surface).
            if self.is_running():
                return self.stop()
            self._log_warning(reason)
            return False

        if not self._push_modal:
            self._log_error("Cannot show config modal - push_modal not configured")
            return False

        def on_config(config: FSMonConfig) -> None:
            if config is None or config.cancelled:
                return
            self._start_fsmon(config)

        self._push_modal(FSMonConfigModal(), on_config)
        return True

    def _get_buffer_interval(self) -> float:
        """Read fsmon_buffer_interval from config.

        Returns:
            Interval in seconds (minimum 0.01 when set to 0).
        """
        try:
            from sandroid.config.loader import ConfigLoader

            loader = ConfigLoader()
            config = loader.load()
            interval = config.tui.fsmon_buffer_interval
            return max(interval, 0.01) if interval > 0 else 0.01
        except Exception:
            return 0.15

    def _start_fsmon(self, config: FSMonConfig) -> bool:
        """Start FSMon with the given configuration.

        Args:
            config: FSMonConfig from the configuration modal

        Returns:
            True if FSMon was started successfully
        """
        from sandroid.core.fsmon import FSMon
        from sandroid.tui.utils import FSMonWrapper

        self._log_info("Installing/checking fsmon binary...")

        # Check and install fsmon binary
        try:
            FSMon.check_and_install_fsmon()
        except Exception as e:
            self._log_error(f"Failed to install fsmon: {e}")
            return False

        # Start fsmon based on mode
        try:
            if config.mode == "pid" and config.target_pid:
                process = FSMon.run_fsmon_by_pid(config.target_pid, config.target_path)
                mode_desc = f"PID {config.target_pid}"
            else:
                process = FSMon.run_fsmon_by_path(config.target_path)
                mode_desc = f"path {config.target_path}"

            if self._log_task_started:
                self._log_task_started("FSMon", mode_desc)
            else:
                self._log_info(f"FSMon started monitoring {mode_desc}")

            # Create wrapper to manage the process
            fsmon_wrapper = FSMonWrapper(process, config)

            # Register as background task
            self._get_task_service().register(
                name="fsmon",
                display_name="FSMon",
                instance=fsmon_wrapper,
                stop_callback=fsmon_wrapper.stop,
                app_name=config.app_name if config.app_name else config.target_path,
            )

            # Start output reader thread
            self._start_output_reader(fsmon_wrapper)

            # fsmon actually STARTED (not just the config modal opening) —
            # jump to the Files tab's Monitor sub-tab so the live stream is
            # immediately visible, mirroring "h" (friTap) ->
            # MainScreen.open_fritap_tab(). This whole call chain runs on the
            # main thread already (originates from FSMonConfigModal's
            # push_modal dismiss callback — same reasoning as the
            # log_task_started call above needing no call_from_thread), so
            # invoke directly rather than via self._call_from_thread (which
            # asserts it is being called from a DIFFERENT thread than the
            # app's own and would raise here).
            if self._open_files_tab:
                try:
                    self._open_files_tab()
                except Exception:
                    logger.debug(
                        "Failed to open Files tab after fsmon start", exc_info=True
                    )

            return True

        except Exception as e:
            self._log_error(f"Failed to start fsmon: {e}")
            return False

    def _start_output_reader(self, fsmon_wrapper: Any) -> None:
        """Start a thread to read fsmon output with batched UI delivery.

        Instead of calling ``call_from_thread`` for every single fsmon line
        (which floods Textual's event loop at high event rates), the reader
        thread accumulates lines in a thread-safe deque and flushes them to
        the main thread in a single batch every ``flush_interval`` seconds.

        Args:
            fsmon_wrapper: FSMonWrapper instance
        """
        import time

        line_buffer: deque[str] = deque(maxlen=2000)
        flush_interval = self._get_buffer_interval()

        def flush_to_ui() -> None:
            """Send accumulated lines to main thread in one batch."""
            if not line_buffer:
                return
            batch = list(line_buffer)
            line_buffer.clear()
            try:
                self._call_from_thread(self._log_fsmon_output_batch, batch)
            except Exception:
                logger.debug("Failed to flush fsmon batch to UI", exc_info=True)

        def read_output():
            """Read fsmon output in background thread."""
            logger.info("fsmon output reader thread started")
            process = fsmon_wrapper.process
            last_flush = 0.0  # ensure first line triggers immediate flush
            first_line = True

            while process.poll() is None:
                try:
                    line = process.stdout.readline()
                except Exception:
                    break
                if line:
                    line_str = _ANSI_RE.sub("", line).strip()
                    if first_line:
                        logger.info("fsmon reader: first output line received")
                        first_line = False
                    if line_str:
                        line_buffer.append(line_str)
                        now = time.monotonic()
                        if now - last_flush >= flush_interval:
                            flush_to_ui()
                            last_flush = now
                else:
                    time.sleep(0.01)

            # Final flush of remaining lines
            flush_to_ui()

            # Drain remaining buffered output after process exits
            try:
                for line in process.stdout:
                    line_str = _ANSI_RE.sub("", line).strip()
                    if line_str:
                        line_buffer.append(line_str)
                flush_to_ui()
            except Exception:
                logger.debug("Failed to drain fsmon output", exc_info=True)

            # Log process exit diagnostics
            exit_code = process.poll()
            logger.info("fsmon process exited with code %s", exit_code)
            if exit_code is not None and exit_code != 0:
                try:
                    self._call_from_thread(
                        self._log_warning,
                        f"fsmon process exited unexpectedly (code {exit_code})",
                    )
                except Exception:
                    logger.debug("Failed to log fsmon exit warning", exc_info=True)

            # Process ended
            try:
                self._call_from_thread(self._fsmon_ended)
            except Exception:
                logger.debug("Failed to signal fsmon ended", exc_info=True)

        thread = threading.Thread(target=read_output, daemon=True)
        thread.start()

    def _log_fsmon_output_batch(self, lines: list[str]) -> None:
        """Process a batch of fsmon output lines (called from main thread).

        This replaces per-line ``_log_fsmon_output`` to avoid flooding
        Textual's event loop. One ``call_from_thread`` delivers the entire
        batch instead of one message per event.

        Args:
            lines: Batch of output lines from the reader thread
        """
        for line in lines:
            # Stream every line to the EventBus (additive — alongside, not
            # instead of, the activity-log routing below) so the
            # Files tab's Monitor sub-tab (tui/widgets/monitor_view.py) gets
            # the full live stream, not just the throttled last-5-per-batch
            # slice the activity log gets below. Reuses colorize_fsmon_line
            # so Monitor's colors stay identical to the activity log's.
            try:
                _publish_fsmon_event(colorize_fsmon_line(line))
            except Exception:
                logger.debug("Failed to publish fsmon line to EventBus", exc_info=True)

        # Route last few lines to activity log (throttled to avoid flooding)
        if lines:
            for line in lines[-5:]:
                try:
                    if self._log_message:
                        self._log_message(colorize_fsmon_line(line), "FSMon")
                    else:
                        self._log_info(f"[FSMon] {escape(line)}")
                except Exception:
                    logger.debug(
                        "Failed to log FSMon output to activity log",
                        exc_info=True,
                    )

    def _log_fsmon_error(self, error: str) -> None:
        """Log fsmon error to activity log.

        Args:
            error: Error message
        """
        self._log_error(f"FSMon error: {error}")

    def _fsmon_ended(self) -> None:
        """Handle fsmon process ending."""
        if self._log_task_stopped:
            self._log_task_stopped("FSMon")
        else:
            self._log_info("FSMon stopped")

        # Unregister background task
        task_service = self._get_task_service()
        if task_service.is_running("fsmon"):
            task_service.unregister("fsmon")

        # Update UI
        if self._force_ui_refresh:
            self._force_ui_refresh()

    def stop(self) -> bool:
        """Stop FSMon if running.

        Returns:
            True if FSMon was stopped
        """
        if not self.is_running():
            return False

        self._get_task_service().stop("fsmon")
        self._log_info("FSMon stopped")

        if self._force_ui_refresh:
            self._force_ui_refresh()

        return True

    # =========================================================================
    # Resume after Play's snapshot-revert safety stop
    # =========================================================================

    def resume_after_playback(self, config: "FSMonConfig | None") -> bool:
        """Re-fork fsmon after Play's snapshot revert auto-stopped it.

        Called from the main thread (this is a direct handler for
        MonitorView's "Resume monitoring" button — see ``app.py``'s
        ``resume_fsmon_after_playback``), with the ``FSMonConfig`` fsmon was
        running with just before ``RecordingController._stop_fsmon_before_
        revert`` stopped it.

        In PID-mode, ``config.target_pid`` is almost always stale by the
        time Play finishes: the target app typically relaunches with a new
        PID during replay. This re-resolves the PID from ``config.app_name``
        (``Adb.get_pid_for_package_name``) before re-forking rather than
        trusting the stored one. If the app can no longer be found running,
        it falls back to path-mode (when ``config.target_path`` is
        available) instead of silently forking against a dead PID; if
        neither a fresh PID nor a path is available, it refuses to start at
        all and logs an explicit reason rather than failing silently.

        Reuses ``_start_fsmon`` for the actual (re-)start rather than
        duplicating its binary-check/register/output-reader/open-files-tab
        sequence.

        Args:
            config: The FSMonConfig fsmon was running with before the
                Play-triggered auto-stop. ``None`` (e.g. if it couldn't be
                recovered at stop time) is handled explicitly, not silently.

        Returns:
            True if fsmon was successfully re-forked.
        """
        if config is None:
            self._log_warning(
                "Cannot resume monitoring: no prior FSMon configuration available."
            )
            return False

        if self.is_running():
            self._log_warning("FSMon is already running.")
            return False

        resolved = config
        if config.mode == "pid":
            new_pid = None
            if config.app_name:
                try:
                    from sandroid.core.adb import Adb

                    new_pid = Adb.get_pid_for_package_name(
                        config.app_name, use_frida_fallback=False, quiet=True
                    )
                except Exception:
                    logger.debug("PID re-resolution failed", exc_info=True)
                    new_pid = None

            if new_pid:
                resolved = FSMonConfig(
                    mode="pid",
                    target_path=config.target_path,
                    target_pid=new_pid,
                    app_name=config.app_name,
                )
            elif config.target_path:
                self._log_warning(
                    f"{config.app_name or 'Target app'} is no longer running — "
                    f"resuming in path mode ({config.target_path}) instead of "
                    "PID mode."
                )
                resolved = FSMonConfig(
                    mode="path",
                    target_path=config.target_path,
                    target_pid=None,
                    app_name=config.app_name,
                )
            else:
                self._log_warning(
                    f"Could not resume monitoring: {config.app_name or 'the target app'} "
                    "is no longer running and no path fallback was configured. "
                    "Start FSMon manually with 'o'."
                )
                return False

        return self._start_fsmon(resolved)


__all__ = [
    "FSMON_COLOR_RULES",
    "FSMonConfig",
    "FSMonController",
    "colorize_fsmon_line",
]
