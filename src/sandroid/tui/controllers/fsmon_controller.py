"""FSMon Controller for TUI.

This controller manages FSMon filesystem monitoring operations, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Start/stop FSMon monitoring
- Configure monitoring paths and PIDs
- Process and display filesystem events
- Handle monitoring lifecycle
- Observer modal with minimize/restore support

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
# Used by both the controller (activity log) and the observer modal (RichLog).
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
        show_minimized_bar: Callable[[str, str], None] | None = None,
        hide_minimized_bar: Callable[[], None] | None = None,
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
            show_minimized_bar: Callback to show minimized indicator (task_name, description)
            hide_minimized_bar: Callback to hide minimized indicator
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
        self._show_minimized_bar = show_minimized_bar
        self._hide_minimized_bar = hide_minimized_bar

        # Observer state
        self._display_mode: str | None = None  # "observer" | "background" | None
        self._observer_minimized: bool = False
        self._observer_buffer: deque[str] = deque(maxlen=self._get_max_lines())
        self._observer_modal: Any = None
        self._observer_config: Any = None

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
        # Check if already running
        if self.is_running():
            # If observer is minimized, allow restore
            if self._observer_minimized:
                return True, "restore"
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

        # Handle restore case
        if can_start and reason == "restore":
            self._restore_observer()
            return True

        if not can_start:
            # Toggle: stop if running in background mode
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
            self._handle_post_config(config)

        self._push_modal(FSMonConfigModal(), on_config)
        return True

    def _handle_post_config(self, config: FSMonConfig) -> None:
        """Handle post-config flow: check display mode preference."""
        display_mode = self._get_saved_display_mode()

        if display_mode == "ask":
            self._show_display_choice(config)
        elif display_mode == "observer":
            self._start_fsmon_with_mode(config, "observer")
        else:
            self._start_fsmon_with_mode(config, "background")

    def _get_saved_display_mode(self) -> str:
        """Read fsmon_display_mode from config.

        Returns:
            "ask", "observer", or "background"
        """
        try:
            from sandroid.config.loader import ConfigLoader

            loader = ConfigLoader()
            config = loader.load()
            return config.tui.fsmon_display_mode
        except Exception:
            return "ask"

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

    def _get_max_lines(self) -> int:
        """Read fsmon_max_lines from config.

        Returns:
            Maximum lines for observer buffer.
        """
        try:
            from sandroid.config.loader import ConfigLoader

            loader = ConfigLoader()
            config = loader.load()
            return config.tui.fsmon_max_lines
        except Exception:
            return 500

    def _show_display_choice(self, config: FSMonConfig) -> None:
        """Show the display choice modal.

        Args:
            config: FSMon configuration from the config modal
        """
        from sandroid.tui.modals.fsmon_display_choice_modal import (
            FSMonDisplayChoice,
            FSMonDisplayChoiceModal,
        )

        def on_choice(choice: FSMonDisplayChoice) -> None:
            if choice is None or choice.cancelled:
                return

            if choice.remember_choice:
                self._save_display_preference(choice.display_mode)

            self._start_fsmon_with_mode(config, choice.display_mode)

        if self._push_modal:
            self._push_modal(FSMonDisplayChoiceModal(), on_choice)

    def _save_display_preference(self, mode: str) -> None:
        """Save display mode preference to config file.

        Args:
            mode: "observer" or "background"
        """
        try:
            from sandroid.config.loader import ConfigLoader

            loader = ConfigLoader()
            loader.load_and_update_section("tui", {"fsmon_display_mode": mode})
            self._log_info(f"FSMon display preference saved: {mode}")
        except Exception as e:
            logger.debug(f"Failed to save display preference: {e}")

    def _start_fsmon_with_mode(self, config: FSMonConfig, display_mode: str) -> None:
        """Start fsmon and route output based on display mode.

        Args:
            config: FSMon configuration
            display_mode: "observer" or "background"
        """
        self._display_mode = display_mode
        self._observer_minimized = False
        self._observer_buffer.clear()
        self._observer_modal = None
        self._observer_config = config

        started = self._start_fsmon(config)
        if started and display_mode == "observer":
            self._open_observer_modal(config)

    def _open_observer_modal(self, config: FSMonConfig) -> None:
        """Open the observer modal for live output.

        Args:
            config: FSMon configuration
        """
        from sandroid.tui.modals.fsmon_modal import FSMonRunningModal

        modal = FSMonRunningModal(config)
        self._observer_modal = modal
        self._push_observer(modal)

    def _restore_observer(self) -> None:
        """Restore minimized observer modal with buffered output."""
        if not self._observer_config:
            return

        from sandroid.tui.modals.fsmon_modal import FSMonRunningModal

        modal = FSMonRunningModal(self._observer_config)
        modal.load_buffer(list(self._observer_buffer))
        self._observer_modal = modal
        self._observer_minimized = False

        if self._hide_minimized_bar:
            self._hide_minimized_bar()

        self._push_observer(modal)

    def _push_observer(self, modal: Any) -> None:
        """Push an observer modal with the standard dismiss handler.

        Args:
            modal: FSMonRunningModal instance to push
        """
        config = self._observer_config

        def on_dismiss(result: str) -> None:
            self._observer_modal = None
            if result == "stop":
                self.stop()
            elif result == "minimize":
                self._observer_minimized = True
                self._log_info("FSMon observer minimized - press 'o' to restore")
                if self._show_minimized_bar and config:
                    desc = config.target_path
                    if config.app_name:
                        desc = f"{config.app_name} ({config.target_path})"
                    self._show_minimized_bar("FSMon", desc)
                if self._force_ui_refresh:
                    self._force_ui_refresh()

        if self._push_modal:
            self._push_modal(modal, on_dismiss)

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
            # Buffer when in observer mode (for restore after minimize)
            if self._display_mode == "observer":
                self._observer_buffer.append(line)

            # Route to observer modal if active
            if self._observer_modal is not None:
                try:
                    self._observer_modal.add_output(line)
                except Exception:
                    pass

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

        # Clear observer state
        self._clear_observer_state()

        # Update UI
        if self._force_ui_refresh:
            self._force_ui_refresh()

    def _clear_observer_state(self) -> None:
        """Clear all observer-related state."""
        self._display_mode = None
        self._observer_minimized = False
        self._observer_buffer.clear()
        self._observer_modal = None
        self._observer_config = None
        if self._hide_minimized_bar:
            self._hide_minimized_bar()

    def stop(self) -> bool:
        """Stop FSMon if running.

        Returns:
            True if FSMon was stopped
        """
        if not self.is_running():
            return False

        self._get_task_service().stop("fsmon")
        self._log_info("FSMon stopped")

        # Clear observer state
        self._clear_observer_state()

        if self._force_ui_refresh:
            self._force_ui_refresh()

        return True


__all__ = [
    "FSMON_COLOR_RULES",
    "FSMonConfig",
    "FSMonController",
    "colorize_fsmon_line",
]
