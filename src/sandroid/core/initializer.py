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


def apply_serial_selection(serial: str | None = None) -> str | None:
    """Pin all adb traffic to an explicitly requested device.

    ``serial`` (``--serial`` / config ``emulator.serial``) wins over the
    ``ANDROID_SERIAL`` environment variable. The serial is set as the adb
    target right away (so even pre-selection calls such as ``adb root`` use
    ``-s``) and handed to the DeviceManager so auto-selection picks it.

    Returns:
        The serial in effect, or None for automatic selection.
    """
    import os

    from sandroid.core.adb import Adb
    from sandroid.core.device_manager import DeviceManager

    wanted = serial or os.environ.get("ANDROID_SERIAL") or None
    DeviceManager.set_preferred_serial(serial or None)
    if wanted:
        Adb.set_target_device(wanted)
        logger.info(f"Using device {wanted} (explicitly selected)")
    return wanted


def prepare_device(console: Any | None = None) -> bool:
    """Ensure ``adb root`` and SELinux permissive mode on the active device.

    On ``adb root``-capable emulators the SELinux policy still denies many
    binder calls made from the root/su context unless the device is set to
    permissive -- ``pm install`` then fails with ``Failed transaction
    (2147483646)`` and Frida reports ``access: jailed``. The TUI/interactive
    startup gets this via ``SetupService.check_critical_setup()``; every
    one-shot headless path must do it as well, which is what this helper is
    for.

    Never raises and never exits: a device without root still works for
    the operations that don't need it, so failures are only reported.

    Args:
        console: Optional SandroidConsole for user-facing status lines.

    Returns:
        True if root is available and SELinux is permissive.
    """
    from sandroid.core.adb import Adb
    from sandroid.services.setup_checks import (
        check_and_enable_root,
        check_and_set_selinux,
    )

    def _say(markup: str, plain: str, level: int) -> None:
        logger.log(level, plain)
        if console is not None:
            console.print(markup)

    root = check_and_enable_root(Adb)
    if not root.passed:
        _say(
            f"[warning]Root not available: {root.message}. Operations that "
            "need root (APK install, Frida) may fail.[/warning]",
            f"Root not available: {root.message}",
            logging.WARNING,
        )
        return False

    selinux = check_and_set_selinux(Adb)
    if not selinux.passed:
        _say(
            f"[warning]{selinux.message}[/warning]",
            selinux.message,
            logging.WARNING,
        )
        return False

    _say(
        "[dim]Device prepared: adb root enabled, SELinux permissive[/dim]",
        "Device prepared: adb root enabled, SELinux permissive",
        logging.INFO,
    )
    return True


def initialize_core(config: SandroidConfig, prepare: bool = False) -> None:
    """Initialize the Sandroid core subsystems in the required order.

    Performs the 3-step initialization sequence that must happen before
    any Sandroid functionality can be used:
    1. Set the configuration on Toolbox
    2. Initialize Adb (must be first, as DeviceManager depends on it)
    3. Initialize Toolbox (uses DeviceManager which needs Adb)

    Args:
        config: Loaded Sandroid configuration instance.
        prepare: Also run :func:`prepare_device` (adb root + SELinux
            permissive) between the Adb and Toolbox init steps. Headless
            one-shot modes that install packages or use Frida need this.

    Example:
        >>> from sandroid.config import ConfigLoader
        >>> config = ConfigLoader().load()
        >>> initialize_core(config)
    """
    from sandroid.core.adb import Adb
    from sandroid.core.toolbox import Toolbox

    Toolbox.config = config
    emulator_cfg = getattr(config, "emulator", None)
    adb_path = getattr(emulator_cfg, "adb_path", None)
    if adb_path and not Adb.ADB_PATH:
        Adb.ADB_PATH = str(adb_path)  # configured adb wins over PATH lookup
    # IMPORTANT: Adb.init() must come before Toolbox.init() because
    # Toolbox.init() uses DeviceManager which depends on Adb being initialized
    Adb.init()
    apply_serial_selection(getattr(emulator_cfg, "serial", None))
    if prepare:
        # Before Toolbox.init(): that step creates the FridaManager, which
        # should already see a rooted, permissive device.
        from sandroid.core.console import SandroidConsole

        prepare_device(SandroidConsole.get())
    Toolbox.init()
    try:
        from sandroid.core.emulator_guard import start_memory_guard

        start_memory_guard(config)
    except Exception:  # the guard is a safety net, never block startup
        logging.getLogger(__name__).debug("memory guard not started", exc_info=True)


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
