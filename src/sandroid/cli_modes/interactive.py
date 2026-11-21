"""Interactive mode dispatcher for Sandroid.

Launches the Textual TUI, which is now the only interactive UI. The legacy
Rich-based interactive menu (and its ``ActionQ.do_next`` pump) has been retired.
"""

import logging
import sys

from sandroid.config import SandroidConfig
from sandroid.services import get_task_service, get_ui_service

logger = logging.getLogger(__name__)


def start_interactive_mode(
    config: SandroidConfig,
    active_logger: logging.Logger,
    Toolbox,
    Adb,
    show_terminal_log: bool = False,
) -> None:
    """Initialize and start the Textual TUI interface.

    Core initialization (Toolbox/Adb, environment validation) is deferred to
    the TUI's StartupScreen for instant visual feedback.

    Args:
        config: Sandroid configuration containing paths, analysis settings,
            and UI preferences.
        active_logger: Configured logger instance for status and error messages.
        Toolbox: The Toolbox class (not instance) for the exit summary.
        Adb: The Adb class (not instance) for Android Debug Bridge operations.
        show_terminal_log: If True, display log messages in terminal even when
            running in TUI mode (default: False).

    Raises:
        SystemExit: If the Textual TUI is unavailable.
    """
    from sandroid.core.actionQ import ActionQ

    _start_tui_mode(config, Toolbox, ActionQ)


def _stop_capture_children() -> None:
    """Terminate leftover host-side capture helpers (``adb ... tcpdump``)."""
    try:
        import psutil
    except ImportError:
        return
    try:
        from sandroid.core.background_tracker import child_processes

        children = child_processes()
    except Exception:
        return
    victims = []
    for child in children:
        try:
            cmd = " ".join(child.cmdline()).lower()
        except Exception:
            continue
        if "tcpdump" in cmd:
            victims.append(child)
    for child in victims:
        try:
            child.terminate()
        except Exception:
            pass
    try:
        psutil.wait_procs(victims, timeout=2)
    except Exception:
        pass


def _quit_checked_untracked_work() -> bool:
    """The TUI's quit already ran the untracked-work check (and cleanup)."""
    try:
        from sandroid.tui.controllers.quit_controller import untracked_check_done

        return untracked_check_done()
    except Exception:
        return False


def _check_untracked_work_after_tui() -> None:
    """The exit's untracked-work check, unless the quit ran the same one."""
    if _quit_checked_untracked_work():
        logger.debug("Untracked-work check already done by the quit; skipped")
        return
    try:
        from sandroid.core.background_tracker import get_background_tracker

        tracker = get_background_tracker()
        report = tracker.detect_untracked_work()

        if report.has_untracked_work:
            logger.warning("Detected untracked background work on exit")
            logger.warning(report.format_report())

            # Force cleanup
            cleaned = tracker.force_cleanup(report)
            for item in cleaned:
                logger.info(f"Cleanup: {item}")
    except Exception as e:
        logger.debug(f"Error in background work detection: {e}")


def _exit_without_lingering_threads(grace: float = 3.0, exit_code: int = 0) -> None:
    """Make sure the process actually exits after the TUI is closed.

    Background helpers (friTap, tcpdump readers, Frida/MCP clients, ...) can
    leave non-daemon threads behind; the interpreter then waits for them
    forever after "Session Complete" is printed. Give them ``grace`` seconds
    to finish, then log what is still alive and hard-exit with ``exit_code``.
    """
    import os
    import threading
    import time

    if not _quit_checked_untracked_work():
        # The quit's untracked-work check force-stopped capture helpers
        # already; this scan costs as much again (N5-B4).
        _stop_capture_children()

    deadline = time.monotonic() + grace
    for thread in threading.enumerate():
        if thread is threading.main_thread() or thread.daemon:
            continue
        started = time.monotonic()
        thread.join(max(0.0, deadline - started))
        if time.monotonic() - started >= 0.5:
            logger.info(
                "Exit: waited %.1fs for thread %r",
                time.monotonic() - started,
                thread.name,
            )

    lingering = [
        t
        for t in threading.enumerate()
        if t is not threading.main_thread() and t.is_alive() and not t.daemon
    ]
    if not lingering:
        return
    logger.warning(
        "Forcing exit; %d background thread(s) did not stop: %s",
        len(lingering),
        ", ".join(t.name for t in lingering),
    )
    # os._exit skips atexit, where mitmweb used to be stopped: it was left
    # running (orphaned) with the device proxy still pointing at it.
    try:
        from sandroid.tui.controllers.quit_controller import shutdown_network

        shutdown_network(timeout=4.0)
    except Exception:
        pass
    try:
        # os._exit skips atexit handlers: restore the terminal ourselves.
        from sandroid.tui.terminal_reset import reset_terminal_hard

        reset_terminal_hard()
    except Exception:
        pass
    try:
        sys.stdout.flush()
        sys.stderr.flush()
        logging.shutdown()
    finally:
        os._exit(exit_code)


def _end_failed_startup(exit_code: int) -> None:
    """The TUI quit from its startup screen (start failed or was aborted).

    Nothing was analysed: no exit summary. After a failed start
    (``EXIT_STARTUP_FAILED``) the error is repeated on the terminal and this
    run's session folder is removed if it holds nothing but its own logs.
    Exits the process with ``exit_code``.
    """
    from sandroid.tui.screens.startup_screen import (
        EXIT_STARTUP_FAILED,
        startup_failure,
    )

    get_task_service().stop_all()
    if exit_code == EXIT_STARTUP_FAILED:
        error = startup_failure()
        if error:
            print(f"Sandroid did not start: {error}", file=sys.stderr)
        try:
            from sandroid.services import get_initialization_service

            get_initialization_service().discard_unused_session()
        except Exception as e:
            logger.debug(f"Could not discard the unused session folder: {e}")
    _exit_without_lingering_threads(exit_code=exit_code)
    sys.exit(exit_code)


def _start_tui_mode(config: SandroidConfig, Toolbox, ActionQ) -> None:
    """Launch the Textual TUI interface.

    Args:
        config: Sandroid configuration.
        Toolbox: The Toolbox class for exit summary.
        ActionQ: The (slimmed) ActionQ class the TUI menu dispatch uses.
    """
    try:
        from sandroid.tui import run_tui

        # Create the interactive shell the TUI menu/palette dispatch uses.
        action_q = ActionQ()

        # Get TUI theme from config
        tui_theme = config.tui.theme if hasattr(config, "tui") else "default"

        # Run the TUI directly (no fork -- fork corrupts Frida's GLib context)
        # Pass config for deferred initialization in StartupScreen
        exit_code = run_tui(
            action_queue=action_q,
            initial_theme=tui_theme,
            startup_config=config,
        )
        from sandroid.tui.screens.startup_screen import (
            EXIT_STARTUP_ABORTED,
            EXIT_STARTUP_FAILED,
        )

        if exit_code in (EXIT_STARTUP_FAILED, EXIT_STARTUP_ABORTED):
            _end_failed_startup(exit_code)

        # After TUI exits, stop background tasks and print summary (time-
        # boxed: a friTap agent that cannot unload must not hang the exit)
        from sandroid.tui.controllers.quit_controller import run_bounded

        run_bounded("background tasks", lambda: get_task_service().stop_all(), 8.0)

        # Check for untracked background work on exit (once per process)
        _check_untracked_work_after_tui()

        logger.info("Analysis completed successfully")
        import time

        started = time.monotonic()
        get_ui_service().print_exit_summary(Toolbox.get_tools_used())
        if time.monotonic() - started >= 0.5:
            logger.info("Exit: summary took %.1fs", time.monotonic() - started)
        _exit_without_lingering_threads(exit_code=exit_code or 0)
        if exit_code:
            sys.exit(exit_code)

    except ImportError as e:
        logger.critical(f"Textual TUI is not available: {e}")
        sys.exit(1)
