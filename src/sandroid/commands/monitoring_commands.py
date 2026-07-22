"""Monitoring commands for Monitor filesystem monitoring."""

import logging
import threading

from .base import (
    CommandCategory,
    CommandContext,
    CommandResult,
    ToggleCommand,
)

# Import config with fallback for standalone usage
try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

logger = logging.getLogger(__name__)


class MonitorCommand(ToggleCommand):
    """Command handler for toggling Monitor filesystem monitoring.

    Monitor monitors file system changes in real-time on the Android device.
    This is a toggle command - pressing 'o' starts monitoring,
    pressing 'o' again stops it.

    The command supports two monitoring modes:
    1. Path-based monitoring: Monitor all file changes in a specified path
    2. PID-based monitoring: Monitor file changes made by a specific process

    By default, it monitors the /data/ path. If a spotlight app is selected
    and running, it can monitor that app's PID specifically.
    """

    key = "o"
    name = "Monitor"
    description = "Start/stop filesystem monitoring"
    category = CommandCategory.MONITORING
    views = ["forensic", "malware"]

    # Default monitoring path (kept as fallback)
    _DEFAULT_MONITOR_PATH = "/data/"

    @staticmethod
    def _get_monitor_path() -> str:
        """Get default monitor path from config with fallback.

        Returns:
            Default filesystem path for monitoring.
        """
        try:
            if get_config is not None:
                return get_config().device_paths.default_monitor_path
        except Exception:
            pass
        return "/data/"

    # Keep class-level alias for backwards compatibility
    DEFAULT_MONITOR_PATH = _DEFAULT_MONITOR_PATH

    def get_task_name(self) -> str:
        """Get the task name for the filesystem monitor.

        Returns:
            Task identifier string "monitor"
        """
        return "monitor"

    async def start_task(self, ctx: CommandContext) -> CommandResult:
        """Start Monitor filesystem monitoring.

        Checks and installs Monitor binary if needed, then starts monitoring.
        Can monitor either a path or a specific PID if a spotlight app is set.

        Args:
            ctx: Command context with services and utilities

        Returns:
            CommandResult indicating success/failure of starting Monitor
        """
        try:
            from sandroid.core.fsmon import FSMon
        except ImportError as e:
            logger.error(f"Failed to import the monitor backend: {e}")
            return CommandResult(
                success=False,
                message="Monitor module not available",
                error=f"Import error: {e}",
            )

        # Check and install Monitor binary on device
        try:
            logger.info("Checking Monitor binary on device...")
            FSMon.check_and_install_fsmon()
        except Exception as e:
            logger.error(f"Failed to install Monitor: {e}")
            return CommandResult(
                success=False,
                message="Failed to install Monitor binary on device",
                error=str(e),
            )

        # Determine monitoring mode (path or PID)
        monitor_path = self._get_monitor_path()
        target_pid: int | None = None
        app_name: str | None = None

        # Check if we have a spotlight app to monitor by PID
        if ctx.spotlight_service and ctx.spotlight_service.has_app():
            spotlight_app = ctx.spotlight_service.get_app()
            if spotlight_app and spotlight_app.package_name:
                app_name = spotlight_app.package_name
                # Try to get the PID for the app
                if ctx.adb:
                    try:
                        pid = ctx.adb.get_pid_for_package_name(app_name)
                        if pid:
                            target_pid = pid
                            logger.info(f"Found PID {pid} for spotlight app {app_name}")
                    except Exception as e:
                        logger.warning(
                            f"Could not get PID for {app_name}: {e}, "
                            "falling back to path monitoring"
                        )
        else:
            # Fallback to spotlight service
            try:
                from sandroid.services import get_spotlight_service

                spotlight = get_spotlight_service().get_app_tuple()
                if spotlight and spotlight[0]:
                    app_name = spotlight[0]
                    if ctx.adb:
                        pid = ctx.adb.get_pid_for_package_name(app_name)
                        if pid:
                            target_pid = pid
            except Exception as e:
                logger.debug(f"Could not get spotlight from spotlight_service: {e}")

        # Ask user for monitoring mode if TUI is available
        if ctx.is_tui_mode and ctx.request_selection and target_pid:
            try:
                options = [
                    f"Monitor by PID ({target_pid} - {app_name})",
                    f"Monitor by path ({monitor_path})",
                ]
                choice = await ctx.request_selection(
                    title="Monitoring Mode",
                    prompt="Select monitoring mode:",
                    options=options,
                )
                if choice is not None:
                    if choice == 1:  # Path monitoring selected
                        target_pid = None
            except Exception as e:
                logger.warning(f"Could not get user selection: {e}")
                # Continue with default (PID if available)

        # Start Monitor process
        try:
            if target_pid:
                logger.info(
                    f"Starting Monitor monitoring PID {target_pid} ({app_name})"
                )
                monitor_process = FSMon.run_fsmon_by_pid(target_pid, monitor_path)
            else:
                logger.info(f"Starting Monitor monitoring path: {monitor_path}")
                monitor_process = FSMon.run_fsmon_by_path(monitor_path)

            if monitor_process is None:
                return CommandResult(
                    success=False,
                    message="Failed to start Monitor process",
                    error="Monitor returned None",
                )

            # Create stop callback that terminates the process
            def stop_monitor():
                """Stop the Monitor subprocess."""
                try:
                    if monitor_process.poll() is None:  # Process still running
                        monitor_process.terminate()
                        try:
                            monitor_process.wait(timeout=5)
                        except Exception:
                            monitor_process.kill()
                        logger.info("Monitor process terminated")
                except Exception as e:
                    logger.error(f"Error stopping Monitor: {e}")

            # Register with task service
            if ctx.task_service:
                ctx.task_service.register(
                    name=self.get_task_name(),
                    display_name="Monitor",
                    instance=monitor_process,
                    stop_callback=stop_monitor,
                    app_name=app_name,
                    target_pid=target_pid,
                )

            # Start rich output reader for non-TUI mode
            if not ctx.is_tui_mode:
                self._start_rich_output_reader(monitor_process)

            # Build success message
            if target_pid:
                message = f"Monitor started monitoring PID {target_pid}"
                if app_name:
                    message += f" ({app_name})"
            else:
                message = f"Monitor started monitoring path: {monitor_path}"

            return CommandResult(
                success=True,
                message=message,
                data={
                    "action": "started",
                    "monitor_path": monitor_path,
                    "target_pid": target_pid,
                    "app_name": app_name,
                    "process_pid": monitor_process.pid,
                },
            )

        except Exception as e:
            logger.exception("Error starting Monitor")
            return CommandResult(
                success=False, message=f"Failed to start Monitor: {e!s}", error=str(e)
            )

    def _start_rich_output_reader(self, process) -> None:
        """Start a daemon thread that prints monitor output to the Rich console.

        Used in non-TUI (Rich) mode where there is no Textual event loop.
        Reads lines from the process stdout, strips ANSI escape codes from
        PTY output, colorizes them, and prints to the SandroidConsole.

        Args:
            process: The monitor subprocess.Popen instance.
        """
        from sandroid.tui.controllers.monitor_controller import (
            _ANSI_RE,
            colorize_monitor_line,
        )

        def _reader():
            try:
                from sandroid.core.sandroid_console import SandroidConsole
            except Exception:
                logger.debug("SandroidConsole not available for rich output")
                return

            while process.poll() is None:
                try:
                    line = process.stdout.readline()
                except Exception:
                    break
                if line:
                    line_str = _ANSI_RE.sub("", line).strip()
                    if line_str:
                        try:
                            SandroidConsole.print(colorize_monitor_line(line_str))
                        except Exception:
                            logger.debug("Failed to print monitor line", exc_info=True)

            # Drain remaining output
            try:
                for line in process.stdout:
                    line_str = _ANSI_RE.sub("", line).strip()
                    if line_str:
                        try:
                            SandroidConsole.print(colorize_monitor_line(line_str))
                        except Exception:
                            pass
            except Exception:
                pass

        thread = threading.Thread(
            target=_reader, daemon=True, name="monitor-rich-reader"
        )
        thread.start()

    async def stop_task(self, ctx: CommandContext) -> CommandResult:
        """Stop Monitor filesystem monitoring.

        Stops the running Monitor process via the task service.

        Args:
            ctx: Command context with services

        Returns:
            CommandResult indicating success/failure of stopping Monitor
        """
        if not ctx.task_service:
            return CommandResult(
                success=False,
                message="Task service not available",
                error="No task_service in context",
            )

        task_name = self.get_task_name()

        # Get task info before stopping for the message
        task = ctx.task_service.get_task(task_name)
        task_data: dict = {"action": "stopped"}
        if task:
            if task.app_name:
                task_data["app_name"] = task.app_name
            if task.target_pid:
                task_data["target_pid"] = task.target_pid

        try:
            success = ctx.task_service.stop(task_name)
        except Exception as e:
            logger.exception("Error stopping Monitor via task service")
            return CommandResult(
                success=False, message=f"Error stopping Monitor: {e!s}", error=str(e)
            )

        if not success:
            return CommandResult(
                success=False,
                message="Failed to stop Monitor",
                error="Task service stop() returned False",
            )

        # Build descriptive stop message
        message = "Monitor stopped"
        if task_data.get("target_pid"):
            pid_info = f"PID {task_data['target_pid']}"
            if task_data.get("app_name"):
                pid_info += f" - {task_data['app_name']}"
            message += f" (was monitoring {pid_info})"

        return CommandResult(success=True, message=message, data=task_data)

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if Monitor can be executed.

        Verifies that required services are available.

        Args:
            ctx: Command context

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        # Always validate task_service - needed for register/stop
        valid, msg = self._validate_task_service(ctx)
        if not valid:
            return (False, msg)

        # For stopping, task_service is sufficient
        if self.is_task_running(ctx):
            return True, ""

        # For starting, we need ADB access
        if not ctx.adb and not ctx.toolbox:
            return False, "ADB access required to start Monitor"

        return True, ""


def register_commands(registry) -> None:
    """Register all monitoring commands.

    Args:
        registry: CommandRegistry instance to register commands with
    """
    registry.register(MonitorCommand())
