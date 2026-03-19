"""TUI Callback Bundle for controller initialisation.

This module defines :class:`TUICallbackBundle`, a dataclass that bundles all
the callbacks that TUI controllers commonly need. Instead of passing 6-8
individual keyword arguments to every controller constructor, the app builds
one bundle and unpacks the relevant subset for each controller.

The bundle is intentionally *not* a god-object: controllers still receive
only the callbacks they declare in their ``__init__`` signature. The bundle
simply acts as a single source of truth to avoid repeating
``log_info=self._log_info, log_warning=self._log_warning, ...`` fourteen
times.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True)
class TUICallbackBundle:
    """Immutable bundle of UI callbacks provided by the TUI app.

    Every field is a callable that maps to one of the recurring callback
    parameters accepted by the various ``*Controller.__init__`` methods.

    The ``frozen=True`` flag guarantees that the bundle cannot be mutated
    after creation, which makes it safe to share across controllers.
    """

    # Activity-log level helpers
    log_info: Callable[[str], None]
    log_warning: Callable[[str], None]
    log_error: Callable[[str], None]
    log_success: Callable[[str], None]
    log_message: Callable[[str, str], None]
    log_task_started: Callable[[str, str], None]
    log_task_stopped: Callable[[str], None]

    # Screen / modal management
    push_modal: Callable[..., Any]

    # Worker / thread helpers
    run_worker: Callable[..., Any]
    call_from_thread: Callable[..., Any]

    # UI refresh
    force_ui_refresh: Callable[[], None]
    refresh_status_bar: Callable[[], None]

    # View state
    get_current_view: Callable[[], str]
    scroll_to_bottom: Callable[[], None]
