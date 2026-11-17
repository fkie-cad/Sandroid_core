"""Quit Controller for TUI.

This controller manages quit/exit orchestration, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Handle quit requests (Ctrl+C, 'q' key)
- Handle ESC key (maybe_quit logic)
- Manage exit cleanup

Usage:
    from sandroid.tui.controllers import QuitController

    controller = QuitController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        push_modal=app.push_screen,
        get_running_tasks=task_service.get_running_tasks,
        stop_task=task_service.stop,
        is_main_screen=lambda: isinstance(app.screen, MainScreen),
        get_screen_stack=lambda: app.screen_stack,
        get_current_screen=lambda: app.screen,
        pop_screen=app.pop_screen,
        exit_app=app.exit,
    )

    # Handle quit request
    controller.request_quit()
"""

import logging
import os
import sys
import threading
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Bounded cleanup + exit watchdog (shared by every quit path)
# ---------------------------------------------------------------------------
#
# Quitting used to hang after a friTap stop whose agent could not unload: the
# dialog's exit skipped the cleanup, a non-daemon Frida thread blocked the
# interpreter, no key worked any more and mitmweb plus the device proxy were
# left behind. Now every quit path (dialog, Ctrl+C, Ctrl+Q, SIGTERM/SIGHUP)
# goes through SandroidTUI.exit -> QuitController.force_exit, every cleanup
# step is time-boxed, and a watchdog makes the process exit even when the
# Textual loop itself is stuck -- after tearing down mitmweb and the device
# proxy. The watchdog only hard-exits when the launcher enabled it (never in
# tests or embedders).

#: Seconds a quit may take (cleanup + Textual shutdown) before the watchdog
#: tears down mitmweb / the device proxy and exits the process.
EXIT_DEADLINE = 20.0
#: Seconds the post-TUI part (exit summary, thread joins) may take.
POST_RUN_DEADLINE = 30.0

_hard_exit = {"enabled": False, "armed": False, "code": 0}
_app_returned = threading.Event()
_watchdog_lock = threading.Lock()


def run_bounded(name: str, fn: Callable[[], Any], timeout: float) -> bool:
    """Run ``fn`` on a daemon thread; give up waiting after ``timeout`` s.

    Returns True when ``fn`` finished (successfully or with an exception,
    which is logged) in time. A step that hangs is left behind on its daemon
    thread, which cannot block the interpreter's exit.
    """
    done = threading.Event()

    def _run() -> None:
        try:
            fn()
        except Exception as exc:
            logger.debug("Quit step %r failed: %s", name, exc, exc_info=True)
        finally:
            done.set()

    threading.Thread(target=_run, name=f"quit-{name}", daemon=True).start()
    if done.wait(timeout):
        return True
    logger.warning("Quit: %s did not finish within %.0fs; going on", name, timeout)
    return False


def shutdown_network(timeout: float = 4.0) -> None:
    """Clear the device proxy we set and stop mitmweb (time-boxed).

    Touches only an mitmproxy service that exists already (no new one is
    created on the way out).
    """
    try:
        from sandroid.services import mitmproxy_service as ms
    except Exception:
        return
    svc = ms._INSTANCE
    if svc is None:
        return
    run_bounded("mitmproxy", lambda: svc.shutdown(timeout=min(2.0, timeout)), timeout)


def emergency_cleanup() -> None:
    """Last-resort teardown before a forced exit (any thread, time-boxed)."""
    try:
        from sandroid.core.ui_request_bus import UIRequestBus

        UIRequestBus.get().shutdown()
    except Exception:
        pass
    shutdown_network(timeout=5.0)


def enable_hard_exit(enabled: bool = True) -> None:
    """Let the exit watchdog end the process (the TUI launcher calls this)."""
    _hard_exit["enabled"] = enabled
    _hard_exit["armed"] = False
    _app_returned.clear()


def mark_app_returned() -> None:
    """``App.run()`` returned: the watchdog moves on to its post-run deadline."""
    _app_returned.set()


def _force_process_exit(code: int, why: str) -> None:
    logger.warning("%s; forcing exit", why)
    emergency_cleanup()
    try:
        from sandroid.tui.terminal_reset import reset_terminal_hard

        reset_terminal_hard()
    except Exception:
        pass
    try:
        sys.stderr.write(f"\n[Sandroid] {why}; exited after cleanup.\n")
        sys.stdout.flush()
        sys.stderr.flush()
        logging.shutdown()
    finally:
        os._exit(code)


def arm_exit_watchdog(exit_code: int = 0) -> bool:
    """Start the exit watchdog (idempotent; no-op unless enabled).

    If ``App.run()`` has not returned ``EXIT_DEADLINE`` seconds after the quit
    began -- a stuck UI loop, a cleanup step that blocks the loop -- mitmweb
    and the device proxy are torn down and the process exits. Once the app
    returned, the rest (exit summary, joining helper threads) gets
    ``POST_RUN_DEADLINE`` seconds.

    Returns True when a watchdog is (now) running.
    """
    with _watchdog_lock:
        if not _hard_exit["enabled"]:
            return False
        _hard_exit["code"] = exit_code
        if _hard_exit["armed"]:
            return True
        _hard_exit["armed"] = True

    def _watch() -> None:
        if not _app_returned.wait(EXIT_DEADLINE):
            _force_process_exit(
                int(_hard_exit["code"] or 0),
                f"Quit did not finish within {EXIT_DEADLINE:.0f}s",
            )
            return
        threading.Event().wait(POST_RUN_DEADLINE)
        _force_process_exit(
            int(_hard_exit["code"] or 0),
            f"Shutdown did not finish within {POST_RUN_DEADLINE:.0f}s after the UI closed",
        )

    threading.Thread(target=_watch, name="sandroid-exit-watchdog", daemon=True).start()
    return True


class QuitController:
    """Controller for quit/exit orchestration.

    This controller handles all quit-related operations, decoupled from
    the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of quit logic from UI rendering
    - Reusable quit management across different UI modes

    Example:
        controller = QuitController(
            log_info=print,
            log_warning=lambda msg: print(f"WARN: {msg}"),
            push_modal=lambda modal, cb: cb(True),
            get_running_tasks=lambda: [],
            stop_task=lambda name: None,
            is_main_screen=lambda: True,
            get_screen_stack=lambda: [],
            get_current_screen=lambda: None,
            pop_screen=lambda: None,
            exit_app=lambda: None,
        )

        # Handle quit request
        controller.request_quit()
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_warning: Callable[[str], None] | None = None,
        log_task_stopped: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        get_running_tasks: Callable[[], list[str]] | None = None,
        get_task: Callable[[str], Any] | None = None,
        stop_task: Callable[[str], None] | None = None,
        is_main_screen: Callable[[], bool] | None = None,
        get_screen_stack: Callable[[], list[Any]] | None = None,
        get_current_screen: Callable[[], Any] | None = None,
        pop_screen: Callable[[], None] | None = None,
        exit_app: Callable[[], None] | None = None,
        force_ui_refresh: Callable[[], None] | None = None,
    ):
        """Initialize QuitController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI
            log_warning: Callback for warning-level logging to UI
            log_task_stopped: Callback for logging task stopped
            push_modal: Callback to push a modal screen with result callback
            get_running_tasks: Callback to get list of running task names
            get_task: Callback to get task by name
            stop_task: Callback to stop a task by name
            is_main_screen: Callback to check if current screen is MainScreen
            get_screen_stack: Callback to get the screen stack
            get_current_screen: Callback to get current screen
            pop_screen: Callback to pop current screen
            exit_app: Callback to exit the application
            force_ui_refresh: Callback to force UI refresh
        """
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_task_stopped = log_task_stopped
        self._push_modal = push_modal
        self._get_running_tasks = get_running_tasks or (list)
        self._get_task = get_task
        self._stop_task = stop_task
        self._is_main_screen = is_main_screen or (lambda: True)
        self._get_screen_stack = get_screen_stack or (list)
        self._get_current_screen = get_current_screen
        self._pop_screen = pop_screen
        self._exit_app = exit_app
        self._force_ui_refresh = force_ui_refresh

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def _detect_and_stop_untracked_frida_jobs(self) -> list[str]:
        """Detect and stop untracked Frida jobs.

        This handles the case where FriTap registration failed but the job
        is still running. Uses background_tracker to detect orphaned jobs.

        Returns:
            List of stopped job names, empty if nothing was stopped.
        """
        stopped_jobs = []

        try:
            from sandroid.core.background_tracker import get_background_tracker

            tracker = get_background_tracker()
            report = tracker.detect_untracked_work()

            if report.untracked_frida_jobs:
                # Found untracked Frida jobs - stop them
                for job in report.untracked_frida_jobs:
                    self._log_warning(f"Stopping untracked {job.name}")
                    stopped_jobs.append(job.name)

                # Use tracker's cleanup
                tracker.force_cleanup(report)

                # Log to activity log
                for job_name in stopped_jobs:
                    if self._log_task_stopped:
                        self._log_task_stopped(job_name)

        except Exception as e:
            logger.debug(f"Error checking for untracked Frida jobs: {e}")

        return stopped_jobs

    def request_quit(self) -> None:
        """Show quit confirmation dialog or stop running tasks.

        Called by 'q' key and Ctrl+C.
        - If background tasks are running (esp. monitor), stops them first
        - If untracked Frida jobs are detected, stops them first
        - Otherwise shows quit confirmation
        """
        running_tasks = self._get_running_tasks()

        # Check for untracked Frida jobs even if TaskService shows nothing
        # This handles the case where FriTap registration failed silently
        if not running_tasks:
            untracked_jobs = self._detect_and_stop_untracked_frida_jobs()
            if untracked_jobs:
                # Stopped untracked jobs - refresh UI and return
                if self._force_ui_refresh:
                    self._force_ui_refresh()
                return

        if running_tasks:
            # Stop running tasks instead of quitting
            for task_name in running_tasks:
                try:
                    display_name = task_name
                    if self._get_task:
                        task = self._get_task(task_name)
                        if task:
                            display_name = (
                                task.display_name
                                if hasattr(task, "display_name")
                                else task_name
                            )

                    if self._stop_task:
                        self._stop_task(task_name)

                    if self._log_task_stopped:
                        self._log_task_stopped(display_name)

                except Exception as e:
                    logger.warning(f"Error stopping task {task_name}: {e}")

            # Update UI after stopping tasks
            if self._force_ui_refresh:
                self._force_ui_refresh()
            return

        # No running tasks, show quit confirmation
        self._show_quit_confirmation()

    def maybe_quit(self) -> None:
        """Handle ESC: close the top modal/overlay, or leave a focused input.

        Since the ESC binding has priority=True, we capture ESC before modals can.
        So we need to manually dismiss modals when they're open.

        On the main screen Esc never opens the Quit dialog (q / Ctrl+C do):
        pressed in a panel it used to pop "Quit?" when the user only meant to
        close something (P2 key collision). A focused text input is left
        instead; otherwise a short hint names the quit key.
        """
        from textual.screen import ModalScreen

        is_debug = logger.isEnabledFor(logging.DEBUG)
        if is_debug:
            logger.debug(">>> QuitController.maybe_quit TRIGGERED <<<")
            screen_stack = self._get_screen_stack()
            logger.debug(f"    screen_stack length: {len(screen_stack)}")
            if self._get_current_screen:
                current = self._get_current_screen()
                logger.debug(f"    current screen type: {type(current).__name__}")

        try:
            current_screen = (
                self._get_current_screen() if self._get_current_screen else None
            )

            # IMPORTANT: Check for MainScreen FIRST to prevent accidentally popping it
            # The screen stack includes [DefaultScreen, MainScreen, ...modals...]
            # We never want to pop MainScreen as that would leave a blank screen
            if self._is_main_screen():
                if is_debug:
                    logger.debug("    On MainScreen: Esc never opens Quit")
                self._escape_on_main_screen(current_screen)
                return

            # If there's a modal/overlay screen on top of MainScreen, dismiss it
            screen_stack = self._get_screen_stack()
            if len(screen_stack) > 1 and current_screen is not None:
                if is_debug:
                    logger.debug(
                        f"    Modal/overlay detected: {type(current_screen).__name__}"
                    )

                if isinstance(current_screen, ModalScreen):
                    if is_debug:
                        logger.debug("    Dismissing ModalScreen via action_cancel")
                    # Call the modal's cancel action if it exists, otherwise dismiss
                    if hasattr(current_screen, "action_cancel"):
                        current_screen.action_cancel()
                    elif hasattr(current_screen, "action_dismiss"):
                        current_screen.action_dismiss()
                    else:
                        current_screen.dismiss(None)
                else:
                    # Non-modal overlay screen (like HelpScreen), pop it
                    if is_debug:
                        logger.debug("    Popping overlay screen")
                    if self._pop_screen:
                        self._pop_screen()
                return

            # Fallback - shouldn't normally reach here
            if is_debug:
                logger.warning(
                    f"    Unexpected state: screen={type(current_screen).__name__ if current_screen else 'None'}, "
                    f"stack_len={len(screen_stack)}"
                )

        except Exception as e:
            logger.error(f"!!! Exception in maybe_quit: {e}", exc_info=True)

    @staticmethod
    def _escape_on_main_screen(screen: Any) -> None:
        """Esc on the main screen: close the side slot / log drawer, leave a
        focused input, else hint at ``q``.

        The screen's own ``handle_escape`` (MainScreen) runs first: it closes
        an open Inspector / AI chat, then the log drawer, and declines (False)
        when a text input outside the side slot has focus.
        """
        handle = getattr(screen, "handle_escape", None)
        if handle is not None:
            try:
                if handle():
                    return
            except Exception:
                logger.debug("Esc: screen.handle_escape failed", exc_info=True)
        focused = getattr(screen, "focused", None)
        try:
            from textual.widgets import Input, TextArea

            if isinstance(focused, Input | TextArea):
                screen.set_focus(None)
                return
        except Exception:
            logger.debug("Esc: could not leave the focused input", exc_info=True)
        try:
            screen.app.notify(
                "Esc closes dialogs and inputs. Press q to quit.", timeout=3
            )
        except Exception:
            pass

    def _show_quit_confirmation(self) -> None:
        """Show the quit confirmation modal."""
        from sandroid.tui.modals import QuitConfirmModal

        if not self._push_modal:
            # No modal callback, just exit
            if self._exit_app:
                self._exit_app()
            return

        def on_quit_result(confirmed: bool) -> None:
            if confirmed and self._exit_app:
                self._exit_app()

        self._push_modal(QuitConfirmModal(notes=self._quit_notes()), on_quit_result)

    @staticmethod
    def _quit_notes() -> list[str]:
        """What quitting will tear down (shown in the confirm dialog)."""
        notes: list[str] = []
        try:
            from sandroid.services import mitmproxy_service as ms

            svc = ms._INSTANCE
            if svc is not None and svc.is_running():
                notes.append("stops mitmweb")
            if svc is not None and svc.owned_device_proxy:
                notes.append("clears the device proxy")
        except Exception:
            pass
        try:
            from sandroid.services import get_task_service

            if get_task_service().is_running("fritap"):
                notes.append("stops friTap")
        except Exception:
            pass
        return notes

    def force_exit(self) -> None:
        """Exit the application, cleaning up any active sessions.

        Performs cleanup of objection sessions, background tasks,
        workers, and other resources before exiting.
        """
        from sandroid.services import get_task_service

        # Shutdown UIRequestBus first to release any blocked threads
        try:
            from sandroid.core.ui_request_bus import UIRequestBus

            bus = UIRequestBus.get()
            bus.shutdown()
            logger.info("UIRequestBus shutdown complete")
        except Exception as e:
            logger.debug(f"Error shutting down UIRequestBus: {e}")

        # The device must not stay pointed at a mitmweb that is about to die,
        # and mitmweb must not outlive Sandroid: first, and time-boxed.
        shutdown_network(timeout=5.0)

        # Stop all background tasks (FriTap, network capture, etc.). A friTap
        # agent that cannot unload must not hold the quit up.
        logger.info("Stopping all background tasks before exit")
        run_bounded("background tasks", lambda: get_task_service().stop_all(), 8.0)

        run_bounded("frida sessions", self._stop_frida_sessions, 6.0)
        self._cleanup_rest()

    @staticmethod
    def _stop_frida_sessions() -> None:
        """Stop Frida jobs not registered with the TaskService, then detach."""
        # Ensure Frida sessions are cleaned up even if not registered with TaskService
        try:
            from sandroid.services import get_frida_session_service

            frida_service = get_frida_session_service()

            if frida_service.has_active_session():
                logger.info("Stopping unregistered Frida jobs before exit")
                job_manager = frida_service.get_job_manager()

                # Stop all jobs with timeout to prevent hanging
                try:
                    results = job_manager.stop_jobs(timeout_per_job=2.0)
                    timed_out = [jid for jid, ok in results.items() if not ok]
                    if timed_out:
                        logger.warning(
                            f"Frida jobs timed out during cleanup: {timed_out}"
                        )
                except Exception as e:
                    logger.debug(f"Error stopping Frida jobs: {e}")

                # Detach from app with timeout
                try:
                    job_manager.detach_from_app(timeout=2.0)
                    logger.info("Frida session cleanup complete")
                except Exception as e:
                    logger.debug(f"Error detaching from app: {e}")
        except Exception as e:
            logger.debug(f"Error cleaning up Frida sessions: {e}")

    @staticmethod
    def _cleanup_rest() -> None:
        """Network capture, Objection, untracked work (each time-boxed)."""
        from sandroid.services import (
            get_network_capture_service,
            get_objection_service,
        )

        # Stop network capture if running
        def _stop_capture() -> None:
            if get_network_capture_service().is_capturing():
                logger.info("Stopping network capture before exit")
                from sandroid.analysis.network import Network

                Network().stop()

        run_bounded("network capture", _stop_capture, 4.0)

        # Clean up any active objection session
        try:
            objection_service = get_objection_service()
            if objection_service.has_session():
                logger.info("Cleaning up objection session before exit")
                session = objection_service.get_session()
                if session:
                    session._stop_reader = True
                    session._cleanup()
                objection_service.clear()
        except Exception as e:
            logger.debug(f"Error cleaning up objection session: {e}")

        # FINAL STEP: Detect and cleanup untracked background work
        try:
            from sandroid.core.background_tracker import get_background_tracker

            tracker = get_background_tracker()
            report = tracker.detect_untracked_work()

            if report.has_untracked_work:
                # Log the report for debugging
                logger.warning(report.format_report())

                # Force cleanup
                cleaned = tracker.force_cleanup(report)

                # Notify user via console (TUI may be shutting down)
                print("\n" + "=" * 60)
                print("WARNING: Detected untracked background tasks during exit!")
                print("=" * 60)
                print(report.format_report())
                print("\nForce-stopped:")
                for item in cleaned:
                    print(f"  - {item}")
                print("=" * 60)
                print("Please report this issue for investigation.\n")
        except Exception as e:
            logger.debug(f"Error in untracked work detection: {e}")


__all__ = [
    "QuitController",
]
