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


def refuse_ambiguous_device() -> None:
    """Refuse to guess when several devices are online and none is pinned.

    Read-only: lists ``adb devices`` (untargeted) and nothing else. With an
    explicit pin (``--serial`` / ``emulator.serial`` / ``ANDROID_SERIAL``, or
    an adb target already chosen) or fewer than two online devices it
    returns; otherwise it raises before any device is prepared.

    Raises:
        MultipleDevicesError: Two or more devices in state ``device`` and no
            explicit selection.
    """
    from sandroid.core.adb import Adb
    from sandroid.core.exceptions import MultipleDevicesError
    from sandroid.services.setup_checks import list_adb_devices

    if Adb.selected_serial():
        return
    online = [serial for serial, state in list_adb_devices(Adb) if state == "device"]
    if len(online) > 1:
        logger.error(
            "More than one device is connected (%s) and none was selected",
            ", ".join(online),
        )
        raise MultipleDevicesError(online)


def describe_device_problem(dm: Any = None) -> str | None:
    """Why no usable device is selected, or None if one is.

    With an explicitly requested serial (``--serial`` / config
    ``emulator.serial`` / ``ANDROID_SERIAL``) that serial must be listed by
    ``adb devices`` in state ``device``; there is no fallback to another
    device. Without one, a device must have been (auto-)selected.

    Uses the DeviceManager's last enumeration; call ``refresh_devices()``
    first for a fresh answer.
    """
    from sandroid.core.device_manager import DeviceManager

    dm = dm or DeviceManager.get()
    wanted = DeviceManager.preferred_serial()
    devices = dm.get_devices()
    listing = ", ".join(f"{d.serial} ({d.state})" for d in devices) or "none"
    if wanted:
        device = dm.get_device(wanted)
        if device is None:
            return (
                f"Requested device {wanted} is not connected (adb devices: {listing})"
            )
        if device.state != "device":
            return (
                f"Requested device {wanted} is not online (state: "
                f"{device.state}; adb devices: {listing})"
            )
        active = dm.active_device
        if active is not None and active.serial != wanted:
            return (
                f"Requested device {wanted} is not the active device ({active.serial})"
            )
        return None
    if dm.active_device is None:
        return (
            "No Android device selected (adb devices: "
            f"{listing}). Start an emulator or pass --serial."
        )
    return None


def require_device() -> Any:
    """Enumerate devices and make sure the selected one is usable.

    Activates the requested serial if needed, so ``Adb``/Frida/the run
    metadata all refer to it.

    Returns:
        The active :class:`~sandroid.core.device.Device`.

    Raises:
        DeviceNotAvailableError: The requested serial is not connected or not
            online, or no device is available at all.
    """
    from sandroid.core.device_manager import DeviceManager
    from sandroid.core.exceptions import DeviceNotAvailableError

    dm = DeviceManager.get()
    dm.refresh_devices()
    wanted = DeviceManager.preferred_serial()
    if wanted:
        device = dm.get_device(wanted)
        active = dm.active_device
        if (
            device is not None
            and device.state == "device"
            and (active is None or active.serial != wanted)
        ):
            dm.set_active_device(wanted)
    problem = describe_device_problem(dm)
    if problem:
        logger.error(problem)
        raise DeviceNotAvailableError(problem)
    return dm.active_device


def prepare_device(console: Any | None = None) -> bool:
    """Ensure ``adb root`` and SELinux permissive mode on the active device.

    On ``adb root``-capable emulators the SELinux policy still denies many
    binder calls made from the root/su context unless the device is set to
    permissive -- ``pm install`` then fails with ``Failed transaction
    (2147483646)`` and Frida reports ``access: jailed``. The TUI/interactive
    startup gets this via ``SetupService.check_critical_setup()``; every
    one-shot headless path must do it as well, which is what this helper is
    for. Both run the device-prepared step (``core/device_prep.py``) for the
    active device -- the same step a later attach or reboot runs -- and
    report its result; without an active device the checks run directly.

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

    root = selinux = None
    prep = _run_device_prep()
    if prep is not None:
        root, selinux = prep.root_check, prep.selinux_check
    if root is None:
        # Not prepared, or the step skipped ``adb root`` (su / no-root
        # device): the check says whether root is usable, as before.
        root = check_and_enable_root(Adb)
    if not root.passed:
        _say(
            f"[warning]Root not available: {root.message}. Operations that "
            "need root (APK install, Frida) may fail.[/warning]",
            f"Root not available: {root.message}",
            logging.WARNING,
        )
        return False

    if selinux is None:
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


def _run_device_prep() -> Any:
    """The device-prepared step for the active device (turned on for the
    session), or None without an active device / when it did not prepare.
    """
    try:
        from sandroid.core import device_prep
        from sandroid.core.device_manager import DeviceManager

        manager = DeviceManager._instance
        active = manager.active_device if manager is not None else None
        if active is None:
            return None
        device_prep.set_enabled(True)
        prep = device_prep.ensure_prepared(active.serial)
    except Exception as e:
        logger.warning(f"Device preparation failed: {e}")
        return None
    return prep if prep.prepared else None


def ensure_frida_server(console: Any | None = None) -> bool:
    """Headless Frida modes: honour ``frida.server_auto_start`` and say why.

    Starts frida-server when it is not running and auto-start is enabled.
    Reports the result (including the failure reason) on *console*. Never
    raises.

    Returns:
        True if frida-server is running afterwards.
    """
    from sandroid.core.frida_manager import (
        auto_start_frida_server,
        frida_server_auto_start_enabled,
    )

    ok, reason = auto_start_frida_server()
    if ok:
        logger.info(f"Frida: {reason}")
        if console is not None and reason != "frida-server already running":
            console.print(f"[dim]{reason}[/dim]")
        return True
    if not frida_server_auto_start_enabled():
        msg = (
            "frida-server is not running and frida.server_auto_start is "
            "disabled; start it first (TUI: f)"
        )
    else:
        msg = f"frida-server could not be started: {reason}"
    logger.error(msg)
    if console is not None:
        console.print(f"[error]{msg}[/error]")
    return False


def initialize_core(
    config: SandroidConfig, prepare: bool = False, require: bool | None = None
) -> None:
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
        require: Fail fast with :class:`DeviceNotAvailableError` unless a
            device is usable (see :func:`require_device`): an explicitly
            requested serial must be connected and online, otherwise some
            device must be selected. Defaults to ``prepare`` (every headless
            one-shot mode); the TUI passes nothing and reports the problem
            itself, since it can start an emulator.

    Raises:
        DeviceNotAvailableError: With ``require`` and no usable device. Raised
            before ``Toolbox.init()``, so no FridaManager is created for (and
            no device work reaches) another device.
        MultipleDevicesError: Always (whatever ``require`` says) when two or
            more devices are online and none is pinned; see
            :func:`refuse_ambiguous_device`. Also raised before
            ``Toolbox.init()``.

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
    if prepare:
        # The device-prepared step is on before a device is selected: the
        # selection starts it (off this thread) and prepare_device() below
        # joins it, so hooks (proxy restore) run before Toolbox.init().
        from sandroid.core import device_prep

        device_prep.set_enabled(True)
    apply_serial_selection(getattr(emulator_cfg, "serial", None))
    # Never guess among several devices: the next steps (adb root, SELinux
    # permissive, FridaManager / frida-server) change the device.
    refuse_ambiguous_device()
    if prepare if require is None else require:
        require_device()
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
