"""Interactive mode dispatcher for Sandroid.

Handles both the Textual TUI and classic Rich-based interactive menu modes.
"""

import logging
import sys

from sandroid.config import SandroidConfig
from sandroid.core.console import SandroidConsole
from sandroid.services import get_setup_service, get_task_service, get_ui_service

logger = logging.getLogger(__name__)


def start_interactive_mode(
    config: SandroidConfig,
    active_logger: logging.Logger,
    Toolbox,
    Adb,
    use_tui: bool = True,
    show_terminal_log: bool = False,
) -> None:
    """Initialize and start the interactive menu interface.

    Handles initialization of core components (Toolbox, Adb) and launches
    either the Textual TUI or classic Rich-based menu based on configuration.
    Performs environment validation before starting and provides graceful
    fallback from TUI to Rich mode if TUI initialization fails.

    The function performs these steps:
    1. Display logo (Rich mode only, for immediate visual feedback)
    2. Initialize Adb and Toolbox components
    3. Validate environment setup via SetupService
    4. Launch appropriate UI mode (TUI or Rich)
    5. Handle cleanup and exit summary on completion

    Args:
        config: Sandroid configuration containing paths, analysis settings,
            and UI preferences.
        active_logger: Configured logger instance for status and error messages.
        Toolbox: The Toolbox class (not instance) for core utility initialization.
        Adb: The Adb class (not instance) for Android Debug Bridge operations.
        use_tui: If True, launch Textual TUI interface. If False, use classic
            Rich-based menu (default: True).
        show_terminal_log: If True, display log messages in terminal even when
            running in TUI mode (default: False).

    Raises:
        SystemExit: If environment validation fails (missing ADB, emulator, etc.).

    Example:
        >>> from sandroid.core.toolbox import Toolbox
        >>> from sandroid.core.adb import Adb
        >>> start_interactive_mode(config, active_logger, Toolbox, Adb, use_tui=True)
    """
    from sandroid.core.actionQ import ActionQ

    # Show logo early for Rich mode to provide immediate visual feedback
    # before blocking operations (check_setup does multiple ADB commands)
    if not use_tui:
        import os

        os.system("cls" if os.name == "nt" else "clear")  # nosec S605
        SandroidConsole.print_logo()
        SandroidConsole.get().print("[dim]Initializing...[/dim]")

    console = SandroidConsole.get()

    if use_tui:
        # TUI mode: defer initialization to StartupScreen for instant visual feedback
        _start_tui_mode(config, Toolbox, ActionQ, console)
    else:
        # Rich mode: run initialization synchronously before showing menu
        _init_or_exit(config)
        _start_rich_interactive_mode(ActionQ, console)


def _start_tui_mode(config: SandroidConfig, Toolbox, ActionQ, console) -> None:
    """Launch the Textual TUI interface with fallback to Rich mode.

    Args:
        config: Sandroid configuration.
        Toolbox: The Toolbox class for exit summary.
        ActionQ: The ActionQ class for fallback Rich mode.
        console: SandroidConsole instance.
    """
    try:
        from sandroid.tui import run_tui

        # Create action queue for the TUI to use
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
        logger.warning(f"Textual TUI not available: {e}. Falling back to Rich mode.")
        console.print(
            "[warning]TUI not available, falling back to Rich mode...[/warning]"
        )
        # Fall back to classic Rich mode (need to init since TUI didn't do it)
        _fallback_init_and_rich(config, ActionQ, console)
    except Exception as e:
        logger.exception(f"TUI failed to start: {e}")
        console.print(f"\n[bold red]TUI Error:[/bold red] {e}")
        console.print("[yellow]Falling back to Rich mode...[/yellow]\n")
        import time

        time.sleep(2)  # Give user time to see the error
        _fallback_init_and_rich(config, ActionQ, console)


def _init_or_exit(config: SandroidConfig) -> None:
    """Run core initialization and critical setup checks, exiting on failure."""
    from sandroid.core.initializer import initialize_core

    initialize_core(config)
    setup_result = get_setup_service().check_critical_setup()
    if not setup_result.success:
        logger.critical(f"Setup validation failed: {setup_result.message}")
        for error in setup_result.errors:
            logger.error(f"  - {error}")
        sys.exit(1)


def _fallback_init_and_rich(config: SandroidConfig, ActionQ, console) -> None:
    """Initialize core (if not yet done) and start Rich mode as fallback."""
    try:
        _init_or_exit(config)
    except SystemExit:
        raise
    except Exception as e:
        logger.error(f"Fallback initialization failed: {e}")
        sys.exit(1)
    _start_rich_interactive_mode(ActionQ, console)


def _start_rich_interactive_mode(ActionQ, console) -> None:
    """Launch the classic Rich-based interactive menu loop.

    Creates an ActionQ instance and runs the interactive menu loop until
    the user exits. This is the fallback UI mode when TUI is not available
    or when --rich-mode is explicitly requested.

    Note:
        The Sandroid logo should be displayed before calling this function
        to provide immediate visual feedback during initialization.

    Args:
        ActionQ: The ActionQ class (not instance) for creating the action queue
            that manages menu operations and user interactions.
        console: SandroidConsole instance for Rich-formatted terminal output.
    """
    import threading

    console.print(
        "[success bold]Starting Sandroid interactive mode (Rich)...[/success bold]"
    )

    # Run deferred setup checks in background thread for faster startup
    def _run_deferred_checks() -> None:
        try:
            get_setup_service().check_deferred_setup(publish_event=False)
            logger.debug("Rich mode: deferred setup checks completed")
        except Exception as e:
            logger.warning(f"Rich mode: deferred setup checks failed: {e}")

    threading.Thread(target=_run_deferred_checks, daemon=True).start()

    action_q = ActionQ()
    action_q.q.append("interactive")

    while not action_q.finished:
        action_q.do_next()
