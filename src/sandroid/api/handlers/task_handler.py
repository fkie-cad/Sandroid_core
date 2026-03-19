"""Task handler — background task management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sandroid.api.interfaces import CommandResult

if TYPE_CHECKING:
    from sandroid.api.headless import SandroidHeadlessAPI


class TaskHandler:
    """Handles background task management operations."""

    def __init__(self, api: SandroidHeadlessAPI) -> None:
        self._api = api

    async def get_running_tasks(self) -> dict[str, dict[str, Any]]:
        """Get status of all running background tasks."""
        from sandroid.services import get_task_service

        return get_task_service().get_status()

    async def stop_task(self, task_name: str) -> CommandResult:
        """Stop a specific background task."""
        from sandroid.services import get_task_service

        task_service = get_task_service()

        if not task_service.is_running(task_name):
            return CommandResult(
                success=False,
                message=f"Task '{task_name}' is not running",
            )

        task_service.stop(task_name)
        return CommandResult(
            success=True,
            message=f"Stopped task: {task_name}",
        )

    async def stop_all_tasks(self) -> CommandResult:
        """Stop all running background tasks."""
        from sandroid.services import get_task_service

        task_service = get_task_service()
        running = task_service.get_running()
        task_service.stop_all()

        return CommandResult(
            success=True,
            message=f"Stopped {len(running)} tasks",
            data={"stopped_tasks": running},
        )
