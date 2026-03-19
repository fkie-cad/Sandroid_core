"""Monitoring commands for FSMon filesystem monitoring."""

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


class FSMonCommand(ToggleCommand):
    """Command handler for toggling FSMon filesystem monitoring.

    FSMon monitors file system changes in real-time on the Android device.
    This is a toggle command - pressing 'o' starts monitoring,
    pressing 'o' again stops it.

    The command supports two monitoring modes:
    1. Path-based monitoring: Monitor all file changes in a specified path
    2. PID-based monitoring: Monitor file changes made by a specific process

    By default, it monitors the /data/ path. If a spotlight app is selected
    and running, it can monitor that app's PID specifically.
    """

    key = "o"
    name = "FSMon"
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
        """Get the task name for FSMon.

        Returns:
            Task identifier string "fsmon"
        """
        return "fsmon"

    async def start_task(self, ctx: CommandContext) -> CommandResult:
        """Start FSMon filesystem monitoring.

        Checks and installs FSMon binary if needed, then starts monitoring.
        Can monitor either a path or a specific PID if a spotlight app is set.

        Args:
            ctx: Command context with services and utilities

        Returns:
            CommandResult indicating success/failure of starting FSMon
        """
        try:
            from sandroid.core.fsmon import FSMon
        except ImportError as e:
            logger.error(f"Failed to import FSMon: {e}")
            return CommandResult(
                success=False,
                message="FSMon module not available",
                error=f"Import error: {e}",
            )

        # Check and install FSMon binary on device
        try:
            logger.info("Checking FSMon binary on device...")
            FSMon.check_and_install_fsmon()
        except Exception as e:
            logger.error(f"Failed to install FSMon: {e}")
            return CommandResult(
                success=False,
                message="Failed to install FSMon binary on device",
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
                    title="FSMon Monitoring Mode",
                    prompt="Select monitoring mode:",
                    options=options,
                )
                if choice is not None:
                    if choice == 1:  # Path monitoring selected
                        target_pid = None
            except Exception as e:
                logger.warning(f"Could not get user selection: {e}")
                # Continue with default (PID if available)

        # Start FSMon process
        try:
            if target_pid:
                logger.info(f"Starting FSMon monitoring PID {target_pid} ({app_name})")
                fsmon_process = FSMon.run_fsmon_by_pid(target_pid, monitor_path)
            else:
                logger.info(f"Starting FSMon monitoring path: {monitor_path}")
                fsmon_process = FSMon.run_fsmon_by_path(monitor_path)

            if fsmon_process is None:
                return CommandResult(
                    success=False,
                    message="Failed to start FSMon process",
                    error="FSMon returned None",
                )

            # Create stop callback that terminates the process
            def stop_fsmon():
                """Stop the FSMon subprocess."""
                try:
                    if fsmon_process.poll() is None:  # Process still running
                        fsmon_process.terminate()
                        try:
                            fsmon_process.wait(timeout=5)
                        except Exception:
                            fsmon_process.kill()
                        logger.info("FSMon process terminated")
                except Exception as e:
                    logger.error(f"Error stopping FSMon: {e}")

            # Register with task service
            if ctx.task_service:
                ctx.task_service.register(
                    name=self.get_task_name(),
                    display_name="FSMon",
                    instance=fsmon_process,
                    stop_callback=stop_fsmon,
                    app_name=app_name,
                    target_pid=target_pid,
                )

            # Start rich output reader for non-TUI mode
            if not ctx.is_tui_mode:
                self._start_rich_output_reader(fsmon_process)

            # Build success message
            if target_pid:
                message = f"FSMon started monitoring PID {target_pid}"
                if app_name:
                    message += f" ({app_name})"
            else:
                message = f"FSMon started monitoring path: {monitor_path}"

            return CommandResult(
                success=True,
                message=message,
                data={
                    "action": "started",
                    "monitor_path": monitor_path,
                    "target_pid": target_pid,
                    "app_name": app_name,
                    "process_pid": fsmon_process.pid,
                },
            )

        except Exception as e:
            logger.exception("Error starting FSMon")
            return CommandResult(
                success=False, message=f"Failed to start FSMon: {e!s}", error=str(e)
            )

    def _start_rich_output_reader(self, process) -> None:
        """Start a daemon thread that prints fsmon output to the Rich console.

        Used in non-TUI (Rich) mode where there is no Textual event loop.
        Reads lines from the process stdout, strips ANSI escape codes from
        PTY output, colorizes them, and prints to the SandroidConsole.

        Args:
            process: The fsmon subprocess.Popen instance.
        """
        from sandroid.tui.controllers.fsmon_controller import (
            _ANSI_RE,
            colorize_fsmon_line,
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
                            SandroidConsole.print(colorize_fsmon_line(line_str))
                        except Exception:
                            logger.debug("Failed to print fsmon line", exc_info=True)

            # Drain remaining output
            try:
                for line in process.stdout:
                    line_str = _ANSI_RE.sub("", line).strip()
                    if line_str:
                        try:
                            SandroidConsole.print(colorize_fsmon_line(line_str))
                        except Exception:
                            pass
            except Exception:
                pass

        thread = threading.Thread(target=_reader, daemon=True, name="fsmon-rich-reader")
        thread.start()

    async def stop_task(self, ctx: CommandContext) -> CommandResult:
        """Stop FSMon filesystem monitoring.

        Stops the running FSMon process via the task service.

        Args:
            ctx: Command context with services

        Returns:
            CommandResult indicating success/failure of stopping FSMon
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
            logger.exception("Error stopping FSMon via task service")
            return CommandResult(
                success=False, message=f"Error stopping FSMon: {e!s}", error=str(e)
            )

        if not success:
            return CommandResult(
                success=False,
                message="Failed to stop FSMon",
                error="Task service stop() returned False",
            )

        # Build descriptive stop message
        message = "FSMon stopped"
        if task_data.get("target_pid"):
            pid_info = f"PID {task_data['target_pid']}"
            if task_data.get("app_name"):
                pid_info += f" - {task_data['app_name']}"
            message += f" (was monitoring {pid_info})"

        return CommandResult(success=True, message=message, data=task_data)

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if FSMon can be executed.

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
            return False, "ADB access required to start FSMon"

        return True, ""


def register_commands(registry) -> None:
    """Register all monitoring commands.

    Args:
        registry: CommandRegistry instance to register commands with
    """
    registry.register(FSMonCommand())
