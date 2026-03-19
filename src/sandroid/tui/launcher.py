"""TUI launcher functions for Sandroid.

This module provides the top-level entry points for running the Sandroid TUI:

- :func:`run_tui` -- run the TUI directly (registers signal handlers and
  performs cleanup on exit).
- :func:`run_tui_guarded` -- fork a guardian process that ensures terminal
  cleanup even after hard crashes or SIGKILL.

Both functions accept the same parameters and return an exit code.
"""

from __future__ import annotations

import atexit
import logging
import signal
from typing import TYPE_CHECKING

from sandroid.tui.terminal_reset import reset_terminal, reset_terminal_hard

if TYPE_CHECKING:
    from pathlib import Path

    from sandroid.config import SandroidConfig
    from sandroid.core.actionQ import ActionQ

logger = logging.getLogger(__name__)


def _cleanup_with_timeout(func, timeout: float = 2.0) -> None:
    """Run a cleanup function with timeout to prevent hangs.

    Args:
        func: Callable to execute.
        timeout: Maximum time to wait in seconds.
    """
    import threading

    thread = threading.Thread(target=func, daemon=True)
    thread.start()
    thread.join(timeout=timeout)


def run_tui(
    action_queue: ActionQ | None = None,
    initial_theme: str = "default",
    custom_css_path: Path | str | None = None,
    startup_config: SandroidConfig | None = None,
):
    """Run the Sandroid TUI application.

    Args:
        action_queue: Optional ActionQ instance for executing menu actions.
        initial_theme: Name of the initial theme to use.
        custom_css_path: Optional path to custom CSS file. If None, uses config or default.
        startup_config: Optional SandroidConfig for deferred initialization.
            When provided, the TUI shows a StartupScreen and runs init in background.

    Returns:
        The exit code from the TUI application.
    """
    from sandroid.services import get_network_capture_service, get_task_service
    from sandroid.tui.app import SandroidTUI

    # Register hard terminal reset for any exit path (crash, SIGTERM, etc.)
    # This replaces the guardian process (os.fork) approach which corrupted
    # Frida's GLib context. atexit handles normal exit, exceptions, and
    # most signals except SIGKILL.
    atexit.register(reset_terminal_hard)
    logger.debug("atexit registered")

    # Load config to check for immediate exit preference
    try:
        from sandroid.config.loader import get_config

        logger.debug("importing config")

        config = get_config()
        logger.debug("config loaded")
        immediate_exit = config.tui.immediate_exit_on_ctrl_c
    except Exception:
        logger.debug("config load failed, using default")
        immediate_exit = False

    logger.debug("creating SandroidTUI instance")
    app = SandroidTUI(
        action_queue=action_queue,
        initial_theme=initial_theme,
        custom_css_path=custom_css_path,
        startup_config=startup_config,
    )

    # Setup signal handler for graceful termination
    def signal_handler(signum, frame):
        """Handle termination signals gracefully."""
        reset_terminal()
        app.exit()

    # Register signal handlers for external termination
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)

    # SIGINT handling: respect config for Ctrl+C behavior
    # If immediate_exit_on_ctrl_c is True, handle SIGINT for immediate exit
    # If False (default), let Textual handle Ctrl+C via binding (shows confirmation dialog)
    if immediate_exit:
        signal.signal(signal.SIGINT, signal_handler)

    try:
        logger.debug("starting TUI app.run()")
        return app.run()
    finally:
        reset_terminal()
        _shutdown_services(get_task_service, get_network_capture_service)


def _shutdown_services(get_task_service, get_network_capture_service) -> None:
    """Run all post-TUI cleanup steps."""
    _cleanup_with_timeout(_shutdown_ui_bus, timeout=2.0)
    _cleanup_with_timeout(lambda: get_task_service().stop_all(), timeout=2.0)
    _cleanup_with_timeout(
        lambda: _stop_network_capture(get_network_capture_service), timeout=3.0
    )
    _reset_tui_mode()


def _shutdown_ui_bus() -> None:
    """Shutdown UIRequestBus to release blocked threads."""
    try:
        from sandroid.core.ui_request_bus import UIRequestBus

        UIRequestBus.get().shutdown()
    except Exception:
        pass


def _stop_network_capture(get_network_capture_service) -> None:
    """Stop network capture if still running."""
    try:
        if get_network_capture_service().is_capturing():
            from sandroid.analysis.network import Network

            Network().stop()
    except Exception:
        pass


def _reset_tui_mode() -> None:
    """Reset TUI mode flag."""
    try:
        from sandroid.core.events import set_tui_mode

        set_tui_mode(False)
    except ImportError:
        pass


def run_tui_guarded(
    action_queue: ActionQ | None = None,
    initial_theme: str = "default",
    custom_css_path: Path | str | None = None,
):
    """Run the TUI with a guardian process that ensures terminal cleanup.

    This function forks a child process to run the actual TUI. The parent
    process waits for the child and always resets the terminal when the
    child exits, regardless of how it terminated (normal exit, signal, crash).

    This handles the case where the TUI is killed with SIGKILL or crashes
    hard, leaving the terminal in a corrupted state with mouse tracking
    enabled.

    Args:
        action_queue: Optional ActionQ instance for executing menu actions.
        initial_theme: Name of the initial theme to use.
        custom_css_path: Optional path to custom CSS file.

    Returns:
        The exit code from the TUI application.
    """
    import os

    pid = os.fork()

    if pid == 0:
        # Child process: run the actual TUI
        try:
            exit_code = run_tui(
                action_queue=action_queue,
                initial_theme=initial_theme,
                custom_css_path=custom_css_path,
            )
            os._exit(exit_code if exit_code is not None else 0)
        except SystemExit as e:
            os._exit(e.code if isinstance(e.code, int) else 0)
        except Exception:
            os._exit(1)
    else:
        return _guardian_wait(pid)


def _guardian_wait(child_pid: int) -> int:
    """Wait for the TUI child process and ensure terminal cleanup.

    Args:
        child_pid: PID of the child process running the TUI.

    Returns:
        Exit code to propagate to the caller.
    """
    import os

    try:
        _, status = os.waitpid(child_pid, 0)

        if os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            reset_terminal_hard()
            print(
                f"\n\033[33m[Sandroid] TUI terminated by signal {sig}. "
                "Terminal has been reset.\033[0m"
            )
            return 128 + sig

        if os.WIFEXITED(status):
            exit_code = os.WEXITSTATUS(status)
            if exit_code != 0:
                reset_terminal_hard()
                print(
                    f"\n\033[33m[Sandroid] TUI exited with code {exit_code}. "
                    "Terminal has been reset.\033[0m"
                )
            return exit_code

        reset_terminal_hard()
        return 1
    except Exception:
        reset_terminal_hard()
        return 1
