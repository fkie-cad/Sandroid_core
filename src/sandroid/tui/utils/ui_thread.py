"""Non-blocking hand-off from background threads to the Textual UI thread.

Background threads (EventBus publishers, the mitmweb reader, Frida message
callbacks, worker threads) must never touch widgets directly, and must not
use ``App.call_from_thread`` while they may hold a lock the UI needs (it
blocks until the UI ran the callback -- a deadlock waiting to happen). The
widgets therefore schedule work with ``loop.call_soon_threadsafe``.

A bare loop callback runs in the *scheduling thread's* ``contextvars``
context, which lacks Textual's ``active_app``: any ``set_timer`` /
``call_later`` made from it failed later with ``LookupError: <ContextVar
name='active_app'>`` ("Task exception was never retrieved"), once per mitmweb
line during live traffic. :class:`UiDispatcher` captures the UI context once,
on the UI thread, and runs every callback in it; an exception in a callback
is logged once (per callback and exception type) instead of flooding the log
with tracebacks.

Usage (in a widget)::

    def on_mount(self) -> None:
        self._ui = UiDispatcher.capture()

    def _on_line_from_thread(self, line: str) -> None:
        self._ui.post(self._append_line, line)
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import threading
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


class UiDispatcher:
    """Runs callables on the UI event loop, in the UI's contextvars context."""

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop | None = None,
        context: contextvars.Context | None = None,
    ) -> None:
        self.loop = loop
        self.context = context
        self._reported: set[tuple[str, str]] = set()
        self._ui_thread = threading.get_ident() if loop is not None else None

    @classmethod
    def capture(cls) -> UiDispatcher:
        """Bind to the running loop and the current (UI) context.

        Call on the UI thread (``on_mount``). Outside a running loop the
        dispatcher is inert: :meth:`post` returns False.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return cls()
        return cls(loop, contextvars.copy_context())

    @property
    def bound(self) -> bool:
        loop = self.loop
        return loop is not None and not loop.is_closed()

    def post(self, fn: Callable[..., Any], *args: Any) -> bool:
        """Schedule ``fn(*args)`` on the UI loop (any thread, never blocks).

        Returns False when there is no live loop (not mounted, shutting down).
        """
        loop = self.loop
        if loop is None or loop.is_closed():
            return False
        try:
            loop.call_soon_threadsafe(self._run, fn, args, context=self.context)
        except RuntimeError:  # loop closed between the check and the call
            return False
        return True

    def call(self, fn: Callable[..., Any], *args: Any) -> None:
        """Run ``fn(*args)`` now when already on the UI thread, else post it."""
        if self._ui_thread is not None and threading.get_ident() == self._ui_thread:
            self._run(fn, args)
        else:
            self.post(fn, *args)

    def _run(self, fn: Callable[..., Any], args: tuple) -> None:
        try:
            fn(*args)
        except Exception as exc:
            name = getattr(fn, "__qualname__", repr(fn))
            key = (name, type(exc).__name__)
            if key in self._reported:
                logger.debug("UI callback %s failed again: %s", name, exc)
                return
            self._reported.add(key)
            logger.warning("UI callback %s failed: %s", name, exc, exc_info=True)


def in_app_context() -> bool:
    """True when Textual's ``active_app`` is set in the current context.

    ``set_timer`` / ``call_later`` / ``call_after_refresh`` need it; code that
    can be reached from a bare loop callback checks this first and posts
    through the widget's message queue (``call_later`` is thread-safe and
    needs no context) instead.
    """
    try:
        from textual._context import active_app

        active_app.get()
    except LookupError:
        return False
    except Exception:  # pragma: no cover - textual internals moved
        return True
    return True


__all__ = ["UiDispatcher", "in_app_context"]
