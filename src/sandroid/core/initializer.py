"""Shared core initialization utilities for Sandroid.

Provides a single entry point for the 3-step core init sequence
(Toolbox.config, Adb.init, Toolbox.init) and a reusable escalating
signal handler for graceful shutdown in headless modes.
"""

import logging
import signal
import sys
from collections.abc import Callable
from typing import Any

from sandroid.config import SandroidConfig

logger = logging.getLogger(__name__)


def initialize_core(config: SandroidConfig) -> None:
    """Initialize the Sandroid core subsystems in the required order.

    Performs the 3-step initialization sequence that must happen before
    any Sandroid functionality can be used:
    1. Set the configuration on Toolbox
    2. Initialize Adb (must be first, as DeviceManager depends on it)
    3. Initialize Toolbox (uses DeviceManager which needs Adb)

    Args:
        config: Loaded Sandroid configuration instance.

    Example:
        >>> from sandroid.config import ConfigLoader
        >>> config = ConfigLoader().load()
        >>> initialize_core(config)
    """
    from sandroid.core.adb import Adb
    from sandroid.core.toolbox import Toolbox

    Toolbox.config = config
    # IMPORTANT: Adb.init() must come before Toolbox.init() because
    # Toolbox.init() uses DeviceManager which depends on Adb being initialized
    Adb.init()
    Toolbox.init()


class EscalatingSignalHandler:
    """Signal handler that escalates through graceful -> forced -> immediate exit.

    Implements a 3-level interrupt pattern for headless modes:
    - 1st Ctrl+C: Raises KeyboardInterrupt for graceful shutdown
    - 2nd Ctrl+C: Calls an optional cleanup callback, then forces sys.exit(1)
    - 3rd Ctrl+C: Immediate force exit with sys.exit(1)

    Args:
        console: SandroidConsole instance for user-facing messages.
        cleanup_callback: Optional callable invoked on the 2nd interrupt
            to perform forced cleanup (e.g., stopping a running capture).
            Exceptions from this callback are silently ignored.
        first_message: Message shown on first interrupt.
        second_message: Message shown on second interrupt.
        third_message: Message shown on third interrupt.

    Example:
        >>> handler = EscalatingSignalHandler(
        ...     console=console,
        ...     cleanup_callback=lambda: fritap.stop(),
        ...     first_message="Received interrupt, stopping FriTap...",
        ... )
        >>> handler.install()
    """

    def __init__(
        self,
        console: Any,
        cleanup_callback: Callable[[], None] | None = None,
        first_message: str = "Received interrupt, stopping...",
        second_message: str = "Second interrupt - forcing shutdown...",
        third_message: str = "Force exit!",
    ) -> None:
        self._console = console
        self._cleanup_callback = cleanup_callback
        self._first_message = first_message
        self._second_message = second_message
        self._third_message = third_message
        self._interrupt_count = 0

    def _handle_signal(self, sig: int, frame: Any) -> None:
        """Handle an incoming signal with escalating behavior."""
        self._interrupt_count += 1
        if self._interrupt_count == 1:
            self._console.print(f"\n[warning]{self._first_message}[/warning]")
            # First interrupt: raise KeyboardInterrupt for graceful exit
            raise KeyboardInterrupt
        if self._interrupt_count == 2:
            self._console.print(f"\n[warning]{self._second_message}[/warning]")
            if self._cleanup_callback is not None:
                try:
                    self._cleanup_callback()
                except Exception:
                    pass
            sys.exit(1)
        else:
            self._console.print(f"\n[error]{self._third_message}[/error]")
            sys.exit(1)

    def install(self) -> None:
        """Register this handler for SIGINT and SIGTERM."""
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
