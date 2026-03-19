"""Decorators for the Sandroid API layer.

Provides reusable decorators that enforce common preconditions
across API methods, reducing repetitive guard clauses.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


def require_initialized(method: F) -> F:
    """Decorator that enforces API initialization before method execution.

    Checks that ``self._initialized`` is True before allowing the
    decorated method to proceed.  Works with both sync and async methods.

    Raises:
        RuntimeError: If the API instance has not been initialized.

    Example::

        class MyAPI:
            _initialized: bool = False

            @require_initialized
            async def do_work(self) -> str:
                return "ok"
    """

    @functools.wraps(method)
    async def async_wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        if not getattr(self, "_initialized", False):
            raise RuntimeError("API not initialized. Call initialize() first.")
        return await method(self, *args, **kwargs)

    @functools.wraps(method)
    def sync_wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        if not getattr(self, "_initialized", False):
            raise RuntimeError("API not initialized. Call initialize() first.")
        return method(self, *args, **kwargs)

    import inspect

    if inspect.iscoroutinefunction(method):
        return async_wrapper  # type: ignore[return-value]
    return sync_wrapper  # type: ignore[return-value]
