"""Headless dexray-intercept mode dispatcher for Sandroid.

Runs MalwareMonitor (dexray-intercept) in headless mode until interrupted.
"""

import logging
import signal
import sys

from sandroid.config import SandroidConfig
from sandroid.core.console import SandroidConsole
from sandroid.services import get_task_service

logger = logging.getLogger(__name__)

# Mapping from CLI hook group names to MalwareMonitor hook_config keys
HOOK_GROUP_MAP = {
    "aes": "aes_hooks",
    "web": "web_hooks",
    "socket": "socket_hooks",
    "filesystem": "file_system_hooks",
    "database": "database_hooks",
    "dex": "dex_unpacking_hooks",
    "java_dex": "java_dex_unpacking_hooks",
}


def run_dexray_headless(
    sandroid_config: SandroidConfig,
    active_logger: logging.Logger,
    package: str,
    output_file: str | None,
    hook_groups: str | None = None,
    enable_fritap: bool = False,
) -> None:
    """Run dexray-intercept (MalwareMonitor) in headless mode until interrupted.

    Starts malware monitoring with Frida-based hooks and runs until Ctrl+C
    is pressed.  This enables long-running instrumentation for automated
    malware analysis.

    Args:
        sandroid_config: Loaded Sandroid configuration.
        active_logger: Configured logger instance.
        package: Target package name for monitoring.
        output_file: Optional output file path for results.
        hook_groups: Optional comma-separated hook group names
            (e.g. "aes,socket,filesystem").  When *None*, the
            MalwareMonitor defaults are used.
        enable_fritap: Enable FriTap TLS key extraction alongside
            dexray-intercept hooks.

    Raises:
        SystemExit: On initialization failure.
    """
    from sandroid.analysis.malwaremonitor import MalwareMonitor
    from sandroid.core.adb import Adb
    from sandroid.core.initializer import EscalatingSignalHandler, initialize_core
    from sandroid.services import get_spotlight_service

    console = SandroidConsole.get()
    initialize_core(sandroid_config)

    # Route dexray_intercept logger output to terminal
    dexray_logger = logging.getLogger("dexray_intercept")
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("[dexray] %(message)s"))
    dexray_logger.addHandler(console_handler)
    dexray_logger.setLevel(logging.INFO)

    # Detect whether to attach or spawn
    spotlight = get_spotlight_service()
    pid = Adb.get_pid_for_package_name(package)
    if pid:
        logger.info(f"App {package} is running (PID: {pid}), using attach mode")
        spotlight.set_app(package, pid=pid)
    else:
        logger.info(f"App {package} not running, using spawn mode")
        spotlight.set_spawn_app(package, auto_resume=True)

    # Build custom hook_config if hook_groups were specified
    custom_hook_config = None
    if hook_groups:
        custom_hook_config = _build_hook_config(hook_groups, console)

    # Create MalwareMonitor with the requested settings
    monitor_kwargs: dict = {"enable_fritap": enable_fritap}
    monitor = MalwareMonitor(**monitor_kwargs)

    # Apply custom hook config (overrides defaults) if provided
    if custom_hook_config is not None:
        monitor.hook_config = custom_hook_config

    # Use a mutable container so the signal handler can reference monitor.stop
    # after it becomes available (monitor must be started first)
    cleanup_ref: list = [None]

    def _cleanup() -> None:
        if cleanup_ref[0] is not None:
            cleanup_ref[0]()

    signal_handler = EscalatingSignalHandler(
        console=console,
        cleanup_callback=_cleanup,
        first_message="Received interrupt, stopping dexray-intercept...",
    )
    signal_handler.install()

    try:
        console.print(f"[accent]Starting dexray-intercept for: {package}[/accent]")
        success = monitor.start_monitoring()

        if not success:
            console.print("[error]dexray-intercept startup cancelled or failed[/error]")
            sys.exit(1)

        # Now that monitor is running, wire up the cleanup callback
        cleanup_ref[0] = monitor.stop_monitoring

        try:
            get_task_service().register(
                name="dexray-intercept",
                display_name="Malware Monitor (Dexray)",
                instance=monitor,
                stop_callback=monitor.stop_monitoring,
                app_name=monitor.app_package,
                target_pid=getattr(monitor, "_app_pid", None),
            )
        except Exception as e:
            logger.debug(f"Task registration note: {e}")

        console.print(
            f"[success]dexray-intercept started for {monitor.app_package} "
            f"(PID: {getattr(monitor, '_app_pid', '?')})[/success]"
        )

        _print_active_hooks(monitor, console)

        if enable_fritap:
            console.print("[dim]FriTap TLS key extraction enabled[/dim]")

        console.print("[dim]Press Ctrl+C to stop (press twice to force exit)...[/dim]")
        console.print(
            "[dim]Waiting for hooks to load (dexray messages will appear)...[/dim]"
        )

        # Block until signal received; the dexray job thread keeps itself alive
        try:
            signal.pause()
        except KeyboardInterrupt:
            pass

    except RuntimeError as e:
        console.print(f"[error]dexray-intercept error: {e}[/error]")
        logger.exception("dexray-intercept startup error")
        sys.exit(1)
    except Exception as e:
        console.print(f"[error]Unexpected error: {e}[/error]")
        logger.exception("dexray-intercept headless error")
        sys.exit(1)
    finally:
        console.print("[dim]Stopping dexray-intercept...[/dim]")
        try:
            monitor.stop_monitoring()
            console.print("[success]dexray-intercept stopped successfully[/success]")

            # Report results summary
            results = monitor.return_data()
            if results:
                console.print("[success]Results collected and exported[/success]")
            else:
                console.print("[dim]No results collected[/dim]")
        except Exception as e:
            console.print(f"[warning]Error during dexray-intercept stop: {e}[/warning]")

        dexray_logger.removeHandler(console_handler)
        get_task_service().stop_all()


def _build_hook_config(hook_groups: str, console: SandroidConsole) -> dict:
    """Build a hook_config dict from a comma-separated hook group string.

    All hook categories start disabled, then only the requested groups are
    enabled.  Unknown group names are logged as warnings.

    Args:
        hook_groups: Comma-separated hook group names.
        console: Console instance for user feedback.

    Returns:
        A hook_config dictionary suitable for ``MalwareMonitor.hook_config``.
    """
    # Start with all hooks disabled
    hook_config = dict.fromkeys(HOOK_GROUP_MAP.values(), False)

    requested = [g.strip().lower() for g in hook_groups.split(",") if g.strip()]

    for group in requested:
        config_key = HOOK_GROUP_MAP.get(group)
        if config_key:
            hook_config[config_key] = True
        else:
            valid_names = ", ".join(sorted(HOOK_GROUP_MAP.keys()))
            console.print(
                f"[warning]Unknown hook group '{group}'. "
                f"Valid groups: {valid_names}[/warning]"
            )
            logger.warning(
                f"Unknown hook group '{group}', ignoring. Valid: {valid_names}"
            )

    enabled = [g for g in requested if g in HOOK_GROUP_MAP]
    if enabled:
        console.print(f"[dim]Custom hook groups enabled: {', '.join(enabled)}[/dim]")
    else:
        console.print(
            "[warning]No valid hook groups specified, "
            "all hooks will be disabled[/warning]"
        )

    return hook_config


def _print_active_hooks(monitor, console: SandroidConsole) -> None:
    """Print which hook categories are active on the running monitor.

    Args:
        monitor: Running MalwareMonitor instance.
        console: Console instance for output.
    """
    active = [
        name
        for name, key in HOOK_GROUP_MAP.items()
        if monitor.hook_config.get(key, False)
    ]
    if active:
        console.print(f"[dim]Active hook groups: {', '.join(active)}[/dim]")
