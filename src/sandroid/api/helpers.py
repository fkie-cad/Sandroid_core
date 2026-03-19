"""Shared helpers for the Sandroid API layer.

Provides a ``safe_command`` decorator that standardises the
try / except → ``CommandResult`` pattern used across handlers,
and a ``resolve_target_package`` utility for package resolution.
"""

from __future__ import annotations

import functools
import inspect
import logging
from collections.abc import Callable
from typing import Any, TypeVar

from .interfaces import CommandResult

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def safe_command(action_label: str) -> Callable[[F], F]:
    """Decorator that wraps a handler method in try/except → CommandResult.

    On exception the decorator logs ``action_label`` and returns a
    ``CommandResult(success=False, …)`` so that every handler method
    does not need its own boilerplate.

    Works with both sync and async methods.

    Args:
        action_label: Human-readable label used in log messages and the
            ``message`` field of the failure ``CommandResult``
            (e.g. ``"Failed to take screenshot"``).

    Example::

        class DeviceHandler:
            @safe_command("Failed to take screenshot")
            async def take_screenshot(self, filename=None):
                ...
                return CommandResult(success=True, message="OK")
    """

    def decorator(fn: F) -> F:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> CommandResult:
                try:
                    return await fn(*args, **kwargs)
                except Exception as e:
                    logger.exception(action_label)
                    return CommandResult(
                        success=False,
                        message=action_label,
                        error=str(e),
                    )

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> CommandResult:
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                logger.exception(action_label)
                return CommandResult(
                    success=False,
                    message=action_label,
                    error=str(e),
                )

        return sync_wrapper  # type: ignore[return-value]

    return decorator


def resolve_target_package(
    package: str | None,
    spotlight_app: str | None,
) -> str | None:
    """Resolve a target package name from explicit arg or spotlight state.

    Resolution order:
    1. ``package`` argument (if given)
    2. ``spotlight_app`` stored on the API
    3. ``SpotlightService.get_effective_package()``

    Returns:
        The resolved package name, or ``None`` if nothing found.
    """
    if package:
        return package
    if spotlight_app:
        return spotlight_app

    try:
        from sandroid.services import get_spotlight_service

        spotlight = get_spotlight_service()
        return spotlight.get_effective_package()
    except Exception:
        return None
