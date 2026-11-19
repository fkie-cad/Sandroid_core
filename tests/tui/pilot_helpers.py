"""Shared waits for pilot-driven TUI tests: by condition, never by a fixed sleep.

``settle(pilot)``
    Let the app finish what it is doing: pause until every message queue of
    the app and the visible screen is empty (bounded).
``until(pilot, cond, timeout=10)``
    Poll ``cond`` with short pauses; fail with the condition's source on
    timeout. Returns the first truthy value.
``boot(app, pilot)``
    Wait until the startup screen is gone and ``MainScreen`` is on top
    (dismissing the first-run welcome modal); returns the ``MainScreen``.

A test that really needs time to pass (an arm or debounce window) backdates
the window or patches the module/class constant instead of sleeping.
"""

from __future__ import annotations

import inspect
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

POLL = 0.01
SETTLE_ROUNDS = 25


def _quiet(app) -> bool:
    """No message or call_next callback is waiting anywhere on screen."""
    try:
        pumps = [app, *app.screen.walk_children(with_self=True)]
    except Exception:
        return True
    for pump in pumps:
        if pump._next_callbacks:
            return False
        try:
            if pump.message_queue_size:
                return False
        except Exception:
            continue
    return True


async def settle(pilot, rounds: int = SETTLE_ROUNDS) -> None:
    """Pause until the app's message queues are idle (at most ``rounds``)."""
    await pilot.pause()
    for _ in range(rounds):
        await pilot.pause()
        if _quiet(pilot.app):
            return


def _describe(cond: Callable[[], Any]) -> str:
    try:
        return inspect.getsource(cond).strip()
    except (OSError, TypeError):
        return repr(cond)


async def until(
    pilot,
    cond: Callable[[], Any],
    timeout: float = 10.0,
    msg: str | None = None,
) -> Any:
    """Poll ``cond`` until it is truthy; fail clearly after ``timeout``."""
    deadline = time.monotonic() + timeout
    while True:
        value = cond()
        if value:
            return value
        if time.monotonic() >= deadline:
            break
        await pilot.pause(POLL)
    value = cond()
    if value:
        return value
    raise AssertionError(
        f"{msg or 'condition not met'} within {timeout:g}s: {_describe(cond)}"
    )


def _on_main(app) -> bool:
    return type(app.screen).__name__ == "MainScreen"


def _main_in_stack(app) -> bool:
    names = [type(s).__name__ for s in app.screen_stack]
    return "MainScreen" in names and "StartupScreen" not in names


async def boot(app, pilot):
    """Startup screen gone, welcome modal dismissed, ``MainScreen`` on top."""
    await until(pilot, lambda: _main_in_stack(app), msg="MainScreen never came up")
    # The welcome modal is pushed by a call_later after the switch.
    await settle(pilot)
    if not _on_main(app):
        await pilot.press("enter")  # first-run welcome modal
        await until(pilot, lambda: _on_main(app), msg="welcome modal stayed up")
        await settle(pilot)
    assert _on_main(app)
    return app.screen
