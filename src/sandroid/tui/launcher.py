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
        The exit code from the TUI application (``App.return_code``; 0 on a
        normal quit, non-zero e.g. after quitting a failed startup).
    """
    from sandroid.services import get_network_capture_service, get_task_service
    from sandroid.tui.app import SandroidTUI

    # Register hard terminal reset for any exit path (crash, SIGTERM, etc.)
    # This replaces the guardian process (os.fork) approach which corrupted
    # Frida's GLib context. atexit handles normal exit, exceptions, and
    # most signals except SIGKILL.
    atexit.register(reset_terminal_hard)
    logger.debug("atexit registered")

    # Check the immediate-exit preference on the already-loaded config (the
    # CLI's startup_config, else whatever Toolbox holds); only load from disk
    # as a last resort.
    try:
        config = startup_config
        if config is None:
            from sandroid.core.toolbox import Toolbox

            config = getattr(Toolbox, "config", None)
        if config is None:
            from sandroid.config import ConfigLoader

            config = ConfigLoader().load()
        immediate_exit = bool(config.tui.immediate_exit_on_ctrl_c)
    except Exception:
        logger.debug("config load failed, using default", exc_info=True)
        immediate_exit = False

    logger.debug("creating SandroidTUI instance")
    app = SandroidTUI(
        action_queue=action_queue,
        initial_theme=initial_theme,
        custom_css_path=custom_css_path,
        startup_config=startup_config,
    )

    from sandroid.tui.controllers.quit_controller import (
        arm_exit_watchdog,
        enable_hard_exit,
        mark_app_returned,
    )

    # A quit that cannot finish (stuck UI loop, hung cleanup) ends the process
    # after tearing down mitmweb and the device proxy.
    enable_hard_exit(True)

    # Setup signal handler for graceful termination
    def signal_handler(signum, frame):
        """Handle termination signals gracefully (same cleanup as q -> y)."""
        reset_terminal()
        arm_exit_watchdog()
        app.exit()

    # Register signal handlers for external termination
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal_handler)

    # SIGINT handling: respect config for Ctrl+C behavior
    # If immediate_exit_on_ctrl_c is True, handle SIGINT for immediate exit
    # If False (default), let Textual handle Ctrl+C via binding (shows confirmation dialog)
    if immediate_exit:
        signal.signal(signal.SIGINT, signal_handler)

    # The timeline's close reason when the quit itself did not close it: an
    # app.run() that raised (e.g. SystemExit from a worker) or returned a
    # non-zero code is a crash, never a "quit".
    close_reason = "crash"
    try:
        logger.debug("starting TUI app.run()")
        app.run()
        rc = app.return_code or 0
        close_reason = exit_close_reason(rc)
        return rc
    finally:
        mark_app_returned()
        reset_terminal()
        _shutdown_services(get_task_service, get_network_capture_service, close_reason)


def exit_close_reason(code: object) -> str:
    """The timeline close reason for a process exit code: ``"exit"`` for
    0/None, ``"crash"`` otherwise (a normal quit closes it as ``"quit"``
    before this).
    """
    return "exit" if code in (0, None) else "crash"


def _shutdown_services(
    get_task_service, get_network_capture_service, close_reason: str = "exit"
) -> None:
    """Run all post-TUI cleanup steps."""
    # First: stop any replay still tapping on the device. Its worker thread
    # outlives the app (crash or quit) and used to keep replaying for minutes.
    _cleanup_with_timeout(_cancel_replays, timeout=1.0)
    _cleanup_with_timeout(_shutdown_ui_bus, timeout=2.0)
    # Idempotent: a no-op when the quit already stopped mitmweb.
    _cleanup_with_timeout(_shutdown_network, timeout=5.0)
    _cleanup_with_timeout(lambda: get_task_service().stop_all(), timeout=2.0)
    _cleanup_with_timeout(
        lambda: _stop_network_capture(get_network_capture_service), timeout=3.0
    )
    # SELinux back to the mode found (a no-op after a clean quit restored
    # it): a crash must not leave the device Permissive.
    _cleanup_with_timeout(_restore_selinux, timeout=5.0)
    # The session timeline last (idempotent: a no-op after the quit closed it).
    _cleanup_with_timeout(lambda: _close_timeline(close_reason), timeout=2.0)
    _reset_tui_mode()


def _restore_selinux() -> None:
    from sandroid.services.setup_checks import restore_selinux_on_quit

    restore_selinux_on_quit()


def _close_timeline(reason: str = "exit") -> None:
    from sandroid.core.timeline import close_timeline

    close_timeline(reason, 1.5)


def _shutdown_network() -> None:
    """Clear our device proxy and stop mitmweb (if still up)."""
    try:
        from sandroid.tui.controllers.quit_controller import shutdown_network

        shutdown_network(timeout=4.0)
    except Exception:
        pass


def _cancel_replays() -> None:
    """Make every running Player replay stop at its next event."""
    try:
        from sandroid.features.player import Player

        Player.cancel_all()
    except Exception:
        pass


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

    if not hasattr(os, "fork"):
        # Windows doesn't support fork; fall back to running TUI directly
        logger.warning(
            "Guardian process not available on this platform, running TUI directly"
        )
        return run_tui(
            action_queue=action_queue,
            initial_theme=initial_theme,
            custom_css_path=custom_css_path,
        )

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
