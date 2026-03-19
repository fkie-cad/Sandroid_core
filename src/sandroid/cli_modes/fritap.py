"""Headless FriTap mode dispatcher for Sandroid.

Runs FriTap SSL/TLS key extraction in headless mode until interrupted.
"""

import logging
import signal
import sys

from sandroid.config import SandroidConfig
from sandroid.core.console import SandroidConsole
from sandroid.services import get_task_service

logger = logging.getLogger(__name__)


def run_fritap_headless(
    sandroid_config: SandroidConfig,
    active_logger: logging.Logger,
    package: str,
    output_file: str | None,
) -> None:
    """Run FriTap in headless mode until interrupted.

    Starts FriTap SSL/TLS key extraction and runs until Ctrl+C is pressed.
    This enables long-running key capture for traffic analysis.

    Args:
        sandroid_config: Loaded Sandroid configuration.
        active_logger: Configured logger instance.
        package: Target package name for FriTap.
        output_file: Optional output file path for keylog.

    Raises:
        SystemExit: On initialization failure.
    """
    from sandroid.analysis.fritap import FriTap
    from sandroid.core.adb import Adb
    from sandroid.core.initializer import EscalatingSignalHandler, initialize_core
    from sandroid.services import get_spotlight_service

    console = SandroidConsole.get()
    initialize_core(sandroid_config)

    # Route friTap logger output to terminal (it only has file handlers by default)
    fritap_logger = logging.getLogger("friTap")
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("[friTap] %(message)s"))
    fritap_logger.addHandler(console_handler)
    fritap_logger.setLevel(logging.INFO)

    # Detect whether to attach or spawn
    spotlight = get_spotlight_service()
    pid = Adb.get_pid_for_package_name(package)
    if pid:
        logger.info(f"App {package} is running (PID: {pid}), using attach mode")
        spotlight.set_app(package, pid=pid)
    else:
        logger.info(f"App {package} not running, using spawn mode")
        spotlight.set_spawn_app(package, auto_resume=True)

    fritap = FriTap()
    fritap.print_to_console = True
    if output_file:
        fritap.keylog_path = output_file

    # Use a mutable container so the signal handler can reference fritap.stop
    # after it becomes available (fritap must be started first)
    cleanup_ref: list = [None]

    def _cleanup() -> None:
        if cleanup_ref[0] is not None:
            cleanup_ref[0]()

    signal_handler = EscalatingSignalHandler(
        console=console,
        cleanup_callback=_cleanup,
        first_message="Received interrupt, stopping FriTap...",
    )
    signal_handler.install()

    try:
        console.print(f"[accent]Starting FriTap for: {package}[/accent]")
        success = fritap.start(interactive=False)

        if not success:
            console.print("[error]FriTap startup cancelled or failed[/error]")
            sys.exit(1)

        # Now that fritap is running, wire up the cleanup callback
        cleanup_ref[0] = fritap.stop

        try:
            get_task_service().register(
                name="fritap",
                display_name="FriTap",
                instance=fritap,
                stop_callback=fritap.stop,
                app_name=fritap.app_package,
                target_pid=fritap.process_id,
            )
        except Exception as e:
            logger.debug(f"Task registration note: {e}")

        console.print(
            f"[success]FriTap started for {fritap.app_package} "
            f"(PID: {fritap.process_id})[/success]"
        )

        output_files = _get_output_files(fritap)
        if output_files:
            console.print(f"[dim]Output files: {', '.join(output_files)}[/dim]")

        console.print("[dim]Press Ctrl+C to stop (press twice to force exit)...[/dim]")
        console.print(
            "[dim]Waiting for SSL/TLS hooks to load (friTap messages will appear)...[/dim]"
        )

        # Block until signal received; the FriTap job thread keeps itself alive
        try:
            signal.pause()
        except KeyboardInterrupt:
            pass

    except RuntimeError as e:
        console.print(f"[error]FriTap error: {e}[/error]")
        logger.exception("FriTap startup error")
        sys.exit(1)
    except Exception as e:
        console.print(f"[error]Unexpected error: {e}[/error]")
        logger.exception("FriTap headless error")
        sys.exit(1)
    finally:
        console.print("[dim]Stopping FriTap...[/dim]")
        try:
            fritap.stop()
            console.print("[success]FriTap stopped successfully[/success]")

            output_files = _get_output_files(fritap)
            if output_files:
                console.print(
                    f"[success]Output saved to: {', '.join(output_files)}[/success]"
                )
        except Exception as e:
            console.print(f"[warning]Error during FriTap stop: {e}[/warning]")

        fritap_logger.removeHandler(console_handler)
        get_task_service().stop_all()


def _get_output_files(fritap) -> list[str]:
    """Collect output file paths from a FriTap instance.

    Args:
        fritap: FriTap instance to inspect.

    Returns:
        List of output file path strings.
    """
    paths = []
    for attr in ("keylog_path", "json_output_path"):
        value = getattr(fritap, attr, None)
        if value:
            paths.append(str(value))
    return paths
