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
        run_tui(
            action_queue=action_q,
            initial_theme=tui_theme,
            startup_config=config,
        )

        # After TUI exits, stop background tasks and print summary
        get_task_service().stop_all()

        # Check for untracked background work on exit
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

        logger.info("Analysis completed successfully")
        get_ui_service().print_exit_summary(Toolbox.get_tools_used())

    except ImportError as e:
        logger.critical(f"Textual TUI is not available: {e}")
        sys.exit(1)
