"""Background Task Service for Sandroid.

This service manages the lifecycle of background tasks such as FriTap,
Dexray-Intercept, network capture, and other long-running operations.

Extracted from Toolbox class to follow Single Responsibility Principle.
The TaskService is responsible ONLY for task lifecycle management.

Usage:
    from sandroid.services import get_task_service
    from sandroid.services.task_service import TaskService

    # Using service locator
    task_service = get_task_service()

    # Or with dependency injection
    task_service = TaskService(event_bus=EventBus.get())

    # Register a task
    task_service.register(
        name="fritap",
        display_name="FriTap",
        instance=fritap_instance,
        stop_callback=fritap_instance.stop,
        app_name="com.example.app"
    )

    # Check status
    if task_service.is_running("fritap"):
        task_service.stop("fritap")
"""

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)


@dataclass
class BackgroundTask:
    """Represents a running background task.

    Attributes:
        name: Internal identifier (e.g., "fritap", "dexray-intercept")
        display_name: Human-readable name (e.g., "FriTap", "Dexray-Intercept")
        instance: The actual tool/process instance
        stop_callback: Function to call when stopping the task
        started_at: Timestamp when the task was started
        started_by: Name of parent task that started this one (for dependencies)
        app_name: Target application package name (if applicable)
        target_pid: Target process PID (if applicable)
    """

    name: str
    display_name: str
    instance: Any
    stop_callback: Callable[[], None]
    started_at: datetime = field(default_factory=datetime.now)
    started_by: str | None = None
    app_name: str | None = None
    target_pid: int | None = None


class TaskService:
    """Service for managing background task lifecycle.

    This service handles registration, tracking, and stopping of
    background tasks. It publishes events when tasks start/stop
    and provides status information for UI display.

    Thread Safety:
        All operations are thread-safe through internal locking.

    Example:
        service = TaskService(event_bus=EventBus.get())

        # Register a task
        service.register(
            name="network",
            display_name="Network Capture",
            instance=tcpdump_process,
            stop_callback=lambda: tcpdump_process.terminate()
        )

        # Query status
        running = service.get_running()  # ["network"]
        status = service.get_status_string()  # "● Network Capture"

        # Stop task
        service.stop("network")
    """

    def __init__(self, event_bus: EventBusProtocol | None = None):
        """Initialize the TaskService.

        Args:
            event_bus: Optional EventBus for publishing task lifecycle events.
                      If not provided, events will not be published.
        """
        self._tasks: dict[str, BackgroundTask] = {}
        self._lock = threading.Lock()
        self._event_bus = event_bus
        self._logger = logger

    def register(
        self,
        name: str,
        display_name: str,
        instance: Any,
        stop_callback: Callable[[], None],
        started_by: str | None = None,
        app_name: str | None = None,
        target_pid: int | None = None,
    ) -> None:
        """Register a new background task.

        Args:
            name: Internal task identifier (must be unique)
            display_name: Human-readable name for UI display
            instance: The actual tool/process instance
            stop_callback: Function to call when stopping
            started_by: Name of parent task (for dependency tracking)
            app_name: Target application package name
            target_pid: Target process PID

        Raises:
            ValueError: If a task with this name is already registered
        """
        with self._lock:
            if name in self._tasks:
                self._logger.warning(
                    f"Task '{name}' is already registered, overwriting"
                )

            task = BackgroundTask(
                name=name,
                display_name=display_name,
                instance=instance,
                stop_callback=stop_callback,
                started_at=datetime.now(),
                started_by=started_by,
                app_name=app_name,
                target_pid=target_pid,
            )
            self._tasks[name] = task

            self._logger.debug(
                f"Registered background task: {display_name}"
                + (f" (PID: {target_pid})" if target_pid else "")
                + (f" targeting {app_name}" if app_name else "")
            )

        # Publish event outside lock
        self._publish_task_started(task)

    def unregister(self, name: str) -> bool:
        """Unregister a task (remove from tracking).

        This should be called after the task has been stopped.
        Does NOT stop the task - use stop() for that.

        Args:
            name: Task identifier to unregister

        Returns:
            True if task was found and unregistered, False otherwise
        """
        with self._lock:
            if name not in self._tasks:
                return False

            task = self._tasks.pop(name)
            self._logger.debug(f"Unregistered background task: {task.display_name}")

        # Publish event outside lock
        self._publish_task_stopped(task, success=True)
        return True

    def update_display(self, name: str, display_name: str) -> bool:
        """Update a task's display name in-place.

        Fires a TASK_UPDATED event (not Started/Stopped) so the activity
        log can announce the change without implying a restart.
        """
        with self._lock:
            task = self._tasks.get(name)
            if task is None:
                return False
            task.display_name = display_name
        self._publish_task_updated(task)
        return True

    def is_running(self, name: str) -> bool:
        """Check if a specific task is currently running.

        Args:
            name: Task identifier to check

        Returns:
            True if task is registered and running
        """
        with self._lock:
            return name in self._tasks

    def get_running(self) -> list[str]:
        """Get list of all running task names.

        Returns:
            List of task identifiers that are currently running
        """
        with self._lock:
            return list(self._tasks.keys())

    def get_running_tasks(self) -> list[BackgroundTask]:
        """Get list of all running background task objects.

        Returns:
            List of BackgroundTask instances currently running.
        """
        with self._lock:
            return list(self._tasks.values())

    def get_task(self, name: str) -> BackgroundTask | None:
        """Get a specific background task by name.

        Args:
            name: Task identifier

        Returns:
            BackgroundTask instance or None if not found
        """
        with self._lock:
            return self._tasks.get(name)

    def get_tasks_started_by(self, parent_name: str) -> list[str]:
        """Get tasks that were started by a specific parent task.

        Used for dependency tracking - when stopping a parent task,
        you may want to also stop child tasks.

        Args:
            parent_name: Name of the parent task

        Returns:
            List of task names that were started by the parent
        """
        with self._lock:
            return [
                name
                for name, task in self._tasks.items()
                if task.started_by == parent_name
            ]

    def stop(self, name: str) -> bool:
        """Stop a specific task.

        Calls the task's stop_callback and unregisters it.
        Does NOT prompt about dependent tasks - use stop_with_prompt() for that.

        Args:
            name: Task identifier to stop

        Returns:
            True if task was found and stopped successfully
        """
        with self._lock:
            if name not in self._tasks:
                return False
            task = self._tasks[name]

        # Stop callback outside lock to prevent deadlocks
        success = True
        try:
            task.stop_callback()
            self._logger.debug(f"Stopped background task: {task.display_name}")
        except Exception as e:
            self._logger.error(f"Error stopping task {task.display_name}: {e}")
            success = False

        # Unregister regardless of stop success
        with self._lock:
            if name in self._tasks:
                self._tasks.pop(name)

        self._publish_task_stopped(task, success=success)
        return success

    def stop_with_dependencies(self, name: str) -> list[str]:
        """Stop a task and all tasks that depend on it.

        Args:
            name: Task identifier to stop

        Returns:
            List of task names that were stopped (including the named task)
        """
        stopped = []

        # First stop child tasks
        children = self.get_tasks_started_by(name)
        for child_name in children:
            if self.stop(child_name):
                stopped.append(child_name)

        # Then stop the parent
        if self.stop(name):
            stopped.append(name)

        return stopped

    def stop_with_prompt(
        self,
        name: str,
        console: Any = None,
        prompt_func: Callable[[], str] | None = None,
    ) -> bool:
        """Stop a task and prompt the user about dependent tasks.

        This method provides interactive prompting when stopping a task that
        has dependent tasks (tasks that were started by this one).

        Args:
            name: Task identifier to stop
            console: Console instance for output (optional, lazy loaded if None)
            prompt_func: Function to get user input, returns single char.
                        Default uses click.getchar().

        Returns:
            True if the main task was stopped, False if not found
        """
        task = self.get_task(name)
        if task is None:
            return False

        # Lazy load console if not provided
        if console is None:
            try:
                from sandroid.core.console import SandroidConsole

                console = SandroidConsole.get()
            except ImportError:
                # Fallback to print
                console = None

        # Default prompt function uses click
        if prompt_func is None:
            try:
                import click

                def prompt_func():
                    return click.getchar().lower()

            except ImportError:

                def prompt_func():
                    return input().lower()[:1] if input() else "y"

        # Find tasks started by this one
        dependent_tasks = self.get_tasks_started_by(name)

        # Stop the main task
        try:
            task.stop_callback()
        except Exception as e:
            self._logger.error(f"Error stopping {task.display_name}: {e}")

        self.unregister(name)
        if console:
            console.print(f"[success]✓ {task.display_name} stopped[/success]")

        # Prompt for dependent tasks
        if dependent_tasks:
            for dep_name in dependent_tasks:
                dep_task = self.get_task(dep_name)
                if dep_task:
                    if console:
                        console.print(
                            f"\n[warning]{dep_task.display_name} was started with {task.display_name}.[/warning]"
                        )
                        console.print(
                            f"Stop {dep_task.display_name} too? [primary]\\[Y/n][/primary] ",
                            end="",
                        )

                    choice = prompt_func()
                    if console:
                        console.print(choice)

                    if choice != "n":
                        try:
                            dep_task.stop_callback()
                            self.unregister(dep_name)
                            if console:
                                console.print(
                                    f"[success]✓ {dep_task.display_name} stopped[/success]"
                                )
                        except Exception as e:
                            self._logger.error(
                                f"Error stopping {dep_task.display_name}: {e}"
                            )

        return True

    def stop_all(self) -> list[str]:
        """Stop all running background tasks.

        Used during application shutdown.

        Returns:
            List of task names that were stopped
        """
        stopped = []
        task_names = self.get_running()

        for name in task_names:
            if self.stop(name):
                stopped.append(name)

        return stopped

    def get_status(self) -> dict[str, dict[str, Any]]:
        """Get detailed status of all running tasks.

        Returns:
            Dictionary mapping task names to status info:
            {
                "fritap": {
                    "display_name": "FriTap",
                    "started_at": datetime,
                    "app_name": "com.example.app",
                    "target_pid": 12345,
                    "running_seconds": 120.5
                }
            }
        """
        now = datetime.now()
        with self._lock:
            return {
                name: {
                    "display_name": task.display_name,
                    "started_at": task.started_at,
                    "app_name": task.app_name,
                    "target_pid": task.target_pid,
                    "started_by": task.started_by,
                    "running_seconds": (now - task.started_at).total_seconds(),
                }
                for name, task in self._tasks.items()
            }

    def get_status_string(self) -> str:
        """Get a formatted string showing running tasks for menu display.

        Returns:
            Formatted string like "● FriTap (12345) | ● Network"
            or empty string if no tasks running
        """
        with self._lock:
            if not self._tasks:
                return ""

            parts = []
            for task in self._tasks.values():
                if task.target_pid:
                    parts.append(
                        f"[success]●[/success] {task.display_name} ([warning]{task.target_pid}[/warning])"
                    )
                else:
                    parts.append(f"[success]●[/success] {task.display_name}")

            return " | ".join(parts)

    def get_count(self) -> int:
        """Get the number of running tasks.

        Returns:
            Number of currently running tasks
        """
        with self._lock:
            return len(self._tasks)

    # =========================================================================
    # Event Publishing (Private)
    # =========================================================================

    def _publish_task_started(self, task: BackgroundTask) -> None:
        """Publish a TASK_STARTED event."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.TASK_STARTED,
                data={
                    "task_name": task.name,
                    "display_name": task.display_name,
                    "app_name": task.app_name,
                    "target_pid": task.target_pid,
                },
                source="task_service",
            )
        )

    def _publish_task_updated(self, task: BackgroundTask) -> None:
        """Publish a TASK_UPDATED event (display changed, task still running)."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.TASK_UPDATED,
                data={
                    "task_name": task.name,
                    "display_name": task.display_name,
                },
                source="task_service",
            )
        )

    def _publish_task_stopped(self, task: BackgroundTask, success: bool) -> None:
        """Publish a TASK_STOPPED event."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        duration = (datetime.now() - task.started_at).total_seconds()
        self._event_bus.publish(
            Event(
                type=EventType.TASK_STOPPED,
                data={
                    "task_name": task.name,
                    "display_name": task.display_name,
                    "success": success,
                    "duration_seconds": duration,
                },
                source="task_service",
            )
        )


# Backwards compatibility: Expose BackgroundTask at module level
__all__ = [
    "BackgroundTask",
    "TaskService",
]
