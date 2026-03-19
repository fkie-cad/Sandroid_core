"""Instrumentation commands for malware monitoring and hook configuration."""

import logging

from sandroid.services import get_spotlight_service, get_task_service

from .base import (
    CommandCategory,
    CommandContext,
    CommandHandler,
    CommandResult,
    RequiresFrida,
)

logger = logging.getLogger(__name__)

# Task names used by the monitoring system
_MONITOR_TASK_NAMES = ("dexray-intercept", "malwaremonitor")


def _find_active_monitor_task(task_service) -> tuple[str | None, str | None]:
    """Find the active monitoring task name and associated app name.

    Args:
        task_service: TaskService instance to query

    Returns:
        Tuple of (task_name, app_name) or (None, None) if not running
    """
    for name in _MONITOR_TASK_NAMES:
        if task_service.is_running(name):
            task = task_service.get_task(name)
            app_name = task.app_name if task else None
            return name, app_name
    return None, None


class MalwareMonitorCommand(CommandHandler):
    """Command to start/stop Dexray-Intercept malware monitoring.

    This is a toggle command - pressing 'm' starts monitoring if not running,
    and stops it if already running. The MalwareMonitor provides dynamic
    instrumentation hooks using dexray-intercept for malware analysis.
    """

    key = "m"
    name = "Malware Monitor"
    description = "Start/stop Dexray-Intercept malware monitoring"
    category = CommandCategory.INSTRUMENTATION
    views = ["malware"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if malware monitoring can be executed.

        Args:
            ctx: Command context

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        # Validate task_service for task registration/checking
        valid, msg = self._validate_task_service(ctx)
        if not valid:
            return (False, msg)

        # Validate toolbox for Frida check
        if not ctx.toolbox:
            return (False, "Toolbox not available")

        return (True, "")

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Toggle malware monitoring on/off.

        If monitoring is not running, creates and starts a MalwareMonitor instance.
        If monitoring is running, stops it and collects results.

        Args:
            ctx: Command context with access to toolbox and task_service

        Returns:
            CommandResult indicating success/failure
        """
        # Check if monitoring is already running
        is_running = self._is_monitor_running(ctx)

        if is_running:
            return await self._stop_monitoring(ctx)
        return await self._start_monitoring(ctx)

    def _is_monitor_running(self, ctx: CommandContext) -> bool:
        """Check if malware monitoring is currently running.

        Args:
            ctx: Command context

        Returns:
            True if monitoring is running, False otherwise
        """
        task_service = ctx.task_service or get_task_service()
        task_name, _ = _find_active_monitor_task(task_service)
        return task_name is not None

    async def _start_monitoring(self, ctx: CommandContext) -> CommandResult:
        """Start malware monitoring.

        Args:
            ctx: Command context

        Returns:
            CommandResult for the start operation
        """
        try:
            from sandroid.analysis.malwaremonitor import MalwareMonitor

            if not ctx.toolbox:
                return CommandResult(
                    success=False,
                    message="Toolbox not available",
                    error="No toolbox in context",
                )

            # Check if Frida server is running (required for monitoring)
            if hasattr(ctx.toolbox, "frida_manager"):
                if not ctx.toolbox.frida_manager.is_frida_server_running():
                    return CommandResult(
                        success=False,
                        message="Frida server not running",
                        error="Press 'f' to start Frida server first",
                    )

            # Get debug mode from toolbox args
            debug_mode = False
            if hasattr(ctx.toolbox, "args") and ctx.toolbox.args:
                debug_mode = getattr(ctx.toolbox.args, "debug", False)

            # Get spotlight files for path filtering
            spotlight_files = []
            if ctx.forensic_service:
                spotlight_files = ctx.forensic_service.get_spotlight_files()

            # Create MalwareMonitor instance
            monitor = MalwareMonitor(
                path_filters=spotlight_files,
                debug_mode=debug_mode,
            )

            # Start monitoring (will show interactive config if TTY)
            if not monitor.start_monitoring():
                return CommandResult(
                    success=False,
                    message="Failed to start malware monitoring",
                    error="MalwareMonitor.start_monitoring() returned False",
                )

            # Get spotlight app info for task registration
            app_name = None
            app_pid = None

            spotlight = get_spotlight_service()
            spotlight_app = spotlight.get_app_tuple()
            if spotlight_app:
                app_name = spotlight_app[0]
                app_pid = spotlight.get_pid()

            # Register as background task
            task_service = ctx.task_service or get_task_service()
            task_service.register(
                name="dexray-intercept",
                display_name="Dexray-Intercept",
                instance=monitor,
                stop_callback=monitor.stop_monitoring,
                app_name=app_name,
                target_pid=app_pid,
            )

            return CommandResult(
                success=True,
                message=f"Malware monitoring started for {app_name or 'spotlight app'}",
                data={
                    "action": "started",
                    "app_name": app_name,
                    "app_pid": app_pid,
                },
            )

        except ImportError as e:
            logger.error(f"Failed to import MalwareMonitor: {e}")
            return CommandResult(
                success=False,
                message="Dexray-intercept not available",
                error=str(e),
            )
        except Exception as e:
            logger.exception("Error starting malware monitoring")
            return CommandResult(
                success=False,
                message=f"Failed to start monitoring: {e!s}",
                error=str(e),
            )

    async def _stop_monitoring(self, ctx: CommandContext) -> CommandResult:
        """Stop malware monitoring.

        Args:
            ctx: Command context

        Returns:
            CommandResult for the stop operation
        """
        try:
            task_service = ctx.task_service or get_task_service()
            task_name, app_name = _find_active_monitor_task(task_service)

            if not task_name:
                return CommandResult(
                    success=False,
                    message="Malware monitoring is not running",
                    error="No active monitoring task found",
                )

            # Stop the task
            success = task_service.stop(task_name)

            # Reset spotlight application if in spawn mode
            spotlight = get_spotlight_service()
            if spotlight.is_spawn_mode():
                spotlight.reset()

            if success:
                return CommandResult(
                    success=True,
                    message=f"Malware monitoring stopped for {app_name or 'app'}",
                    data={
                        "action": "stopped",
                        "app_name": app_name,
                    },
                )
            return CommandResult(
                success=False,
                message="Failed to stop malware monitoring",
                error="stop_task returned False",
            )

        except Exception as e:
            logger.exception("Error stopping malware monitoring")
            return CommandResult(
                success=False,
                message=f"Failed to stop monitoring: {e!s}",
                error=str(e),
            )


class ReconfigureHooksCommand(RequiresFrida):
    """Command to reconfigure Frida hooks on the spotlight app.

    This command stops the current dexray-intercept session, allows the user
    to reconfigure hook settings, and restarts monitoring with the new configuration.
    Only available when dexray-intercept is already running.
    """

    key = "k"
    name = "Reconfigure Hooks"
    description = "Reconfigure Frida hooks on spotlight app"
    category = CommandCategory.INSTRUMENTATION
    views = ["malware", "security"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check that Frida server is running and dexray-intercept is active.

        Args:
            ctx: Command context

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        # First check Frida requirement from parent class
        can_exec, reason = super().can_execute(ctx)
        if not can_exec:
            return can_exec, reason

        # Validate task_service for checking running tasks
        valid, msg = self._validate_task_service(ctx)
        if not valid:
            return (False, msg)

        # Check if dexray-intercept is running
        task_name, _ = _find_active_monitor_task(ctx.task_service)
        if not task_name:
            return False, "Dexray-intercept not running. Press 'm' to start it first."

        return True, ""

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Reconfigure Frida hooks by stopping and restarting monitoring.

        This method:
        1. Gets the current monitoring instance and app info
        2. Stops the current monitoring
        3. Creates a new MalwareMonitor (which shows interactive config)
        4. Starts the new monitoring with reconfigured hooks

        Args:
            ctx: Command context with access to toolbox and task_service

        Returns:
            CommandResult indicating success/failure
        """
        try:
            from sandroid.analysis.malwaremonitor import MalwareMonitor

            if not ctx.toolbox:
                return CommandResult(
                    success=False,
                    message="Toolbox not available",
                    error="No toolbox in context",
                )

            # Get current task info before stopping
            task_service = ctx.task_service or get_task_service()
            task_name, current_app = _find_active_monitor_task(task_service)

            if not task_name:
                return CommandResult(
                    success=False,
                    message="Dexray-intercept is not running",
                    error="Start monitoring first with 'm'",
                )

            logger.info("Reconfiguring dexray-intercept hooks...")

            # Stop current monitoring
            logger.info("Stopping current monitoring...")
            task_service.stop(task_name)

            # Get debug mode from toolbox args
            debug_mode = False
            if hasattr(ctx.toolbox, "args") and ctx.toolbox.args:
                debug_mode = getattr(ctx.toolbox.args, "debug", False)

            # Get spotlight files for path filtering
            spotlight_files = []
            if ctx.forensic_service:
                spotlight_files = ctx.forensic_service.get_spotlight_files()

            # Create new MalwareMonitor (will show interactive config menu)
            logger.info("Please configure new hook settings...")
            monitor = MalwareMonitor(
                path_filters=spotlight_files,
                debug_mode=debug_mode,
            )

            # Start monitoring with new configuration
            if not monitor.start_monitoring():
                return CommandResult(
                    success=False,
                    message="Failed to restart monitoring with new configuration",
                    error="MalwareMonitor.start_monitoring() returned False",
                )

            # Get updated spotlight app info
            app_name = current_app
            app_pid = None

            spotlight = get_spotlight_service()
            spotlight_app = spotlight.get_app_tuple()
            if spotlight_app:
                app_name = spotlight_app[0]
                app_pid = spotlight.get_pid()

            # Register as background task
            task_service = ctx.task_service or get_task_service()
            task_service.register(
                name="dexray-intercept",
                display_name="Dexray-Intercept",
                instance=monitor,
                stop_callback=monitor.stop_monitoring,
                app_name=app_name,
                target_pid=app_pid,
            )

            logger.info("Hooks reconfigured and monitoring restarted.")

            return CommandResult(
                success=True,
                message=f"Hooks reconfigured for {app_name or 'spotlight app'}",
                data={
                    "action": "reconfigured",
                    "app_name": app_name,
                    "app_pid": app_pid,
                },
            )

        except ImportError as e:
            logger.error(f"Failed to import MalwareMonitor: {e}")
            return CommandResult(
                success=False,
                message="Dexray-intercept not available",
                error=str(e),
            )
        except Exception as e:
            logger.exception("Error reconfiguring hooks")
            return CommandResult(
                success=False,
                message=f"Failed to reconfigure hooks: {e!s}",
                error=str(e),
            )


def register_commands(registry) -> None:
    """Register all instrumentation commands.

    Args:
        registry: The CommandRegistry to register commands with
    """
    registry.register(MalwareMonitorCommand())
    registry.register(ReconfigureHooksCommand())
