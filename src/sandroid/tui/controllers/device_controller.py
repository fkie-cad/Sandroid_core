"""Device Controller for TUI.

This controller manages device/AVD lifecycle operations, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Device detection on startup (else the Devices screen opens)
- Non-blocking AVD start / emulator stop, restart, rename and adb connect
  for the Devices screen
- Device switching with session management
- Results folder setup per device

Usage:
    from sandroid.tui.controllers import DeviceController

    controller = DeviceController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        push_modal=app.push_screen,
        refresh_ui=app.refresh_ui,
    )

    # Check for devices on startup
    controller.check_devices_on_startup()

    # Start an AVD with its remembered launch options
    controller.start_avd("Pixel_6_Pro_API_31")
"""

import logging
import os
import re
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Optional, Protocol

if TYPE_CHECKING:
    from sandroid.core.device_manager import Device

logger = logging.getLogger(__name__)

#: ``host[:port]`` accepted by :meth:`DeviceController.connect`.
_ADDRESS_RE = re.compile(
    r"[A-Za-z0-9._\-]+(?::\d{1,5})?|\[[0-9A-Fa-f:]+\](?::\d{1,5})?"
)


class DeviceManagerProtocol(Protocol):
    """Protocol for device manager operations."""

    @property
    def active_device(self) -> Optional["Device"]:
        """Get the currently active device."""
        ...

    def refresh_devices(self, *, auto_select: bool = True) -> list:
        """Refresh and return list of connected devices."""
        ...

    def set_active_device(self, serial: str) -> bool:
        """Set the active device by serial."""
        ...

    def auto_select_device(self) -> Optional["Device"]:
        """Automatically select a device (only when unambiguous)."""
        ...

    def get_device(self, serial: str) -> Optional["Device"]:
        """Get a device by serial number."""
        ...


class ToolboxProtocol(Protocol):
    """Protocol for Toolbox operations."""

    @classmethod
    def get_device_manager(cls) -> DeviceManagerProtocol:
        """Get device manager instance."""
        ...


class DeviceController:
    """Controller for device/AVD lifecycle management.

    This controller handles all device-related operations, decoupled from
    the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of device logic from UI rendering
    - Reusable device management across different UI modes

    Thread Safety:
        Device operations that spawn background processes are thread-safe.
        Callbacks are invoked on the caller's thread.

    Example:
        controller = DeviceController(
            log_info=print,
            log_warning=lambda msg: print(f"WARN: {msg}"),
            push_modal=lambda modal, cb: cb(None),
            refresh_ui=lambda: None,
        )

        # Check startup devices
        controller.check_devices_on_startup()

        # Start an AVD (non-blocking; attached once booted)
        controller.start_avd("Pixel_6")
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_warning: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        refresh_ui: Callable[[], None] | None = None,
        toolbox: Any | None = None,
        call_from_thread: Callable[..., Any] | None = None,
        on_emulator_ready: Callable[[str, str], Any] | None = None,
        open_devices: Callable[[str], Any] | None = None,
    ):
        """Initialize DeviceController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI
            log_warning: Callback for warning-level logging to UI
            log_error: Callback for error-level logging to UI
            push_modal: Callback to push a modal screen with result callback
            refresh_ui: Callback to force UI refresh after state changes
            toolbox: Optional Toolbox reference (defaults to imported Toolbox)
            call_from_thread: Callback to marshal a function call onto the
                UI thread (Textual's ``App.call_from_thread``). Required
                whenever a modal is pushed from a background thread --
                ``push_modal`` (Textual's ``push_screen``) calls
                ``asyncio.get_running_loop()`` internally, which raises if
                invoked directly off-thread. Defaults to calling the
                function immediately (safe for tests / already-UI-thread
                callers).
            on_emulator_ready: UI-thread callback ``(serial, avd_name)`` once
                an emulator Sandroid launched has booted (the app decides
                whether to attach it). Defaults to attaching it when no
                device is active.
            open_devices: UI-thread callback ``(reason)`` that opens the
                Devices screen.
        """
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_error = log_error or self._default_log
        self._push_modal = push_modal
        self._refresh_ui = refresh_ui
        self._toolbox = toolbox
        self._call_from_thread = call_from_thread or (lambda fn, *args: fn(*args))
        self._polling_active = False
        self._on_emulator_ready = on_emulator_ready
        self._open_devices = open_devices

    def _default_log(self, message: str) -> None:
        """Default logging when no callback provided."""
        logger.info(message)

    def _get_toolbox(self) -> Any:
        """Get Toolbox reference."""
        if self._toolbox:
            return self._toolbox
        from sandroid.core.toolbox import Toolbox

        return Toolbox

    def _get_device_manager(self) -> DeviceManagerProtocol:
        """Get device manager from Toolbox."""
        return self._get_toolbox().get_device_manager()

    def _ui(self, fn: Callable[..., Any] | None, *args: Any) -> None:
        """Run *fn* on the UI thread (marshaled when called off it)."""
        if fn is None:
            return
        try:
            if threading.current_thread() is threading.main_thread():
                fn(*args)
            else:
                self._call_from_thread(fn, *args)
        except Exception:
            logger.debug("Could not report to the UI", exc_info=True)

    @staticmethod
    def _spawn(fn: Callable[[], Any], name: str) -> None:
        threading.Thread(target=fn, name=name, daemon=True).start()

    # =========================================================================
    # Device Detection
    # =========================================================================

    def check_devices_on_startup(self, open_devices: bool = True) -> bool:
        """Make sure the session has a device; otherwise open Devices.

        Selects only an unambiguous device (``auto_select_device``: the
        requested ``--serial``, the only ready one, or the previous one --
        never a guess among several). Normally the StartupScreen already
        resolved this; when nothing is active (none connected, several, or
        the requested one missing) the Devices screen opens.

        Args:
            open_devices: Open the Devices screen when nothing is active.

        Returns:
            True if a device is active afterwards.
        """
        try:
            dm = self._get_device_manager()
            devices = dm.refresh_devices(auto_select=False)
            if dm.active_device is None:
                dm.auto_select_device()
            if dm.active_device is not None:
                logger.debug(f"Found {len(devices)} device(s) on startup")
                return True

            explicit = getattr(dm, "preferred_serial", lambda: None)()
            ready = [d for d in devices if getattr(d, "state", "") == "device"]
            if explicit:
                self._report_requested_device_missing(dm, explicit)
                reason = f"Requested device {explicit} is not available."
            elif len(ready) > 1:
                reason = "Several devices are connected -- choose one."
            elif devices:
                reason = "No device is ready (see its state below)."
            else:
                reason = "No device connected -- start an AVD or connect one."
            logger.info(f"No device selected on startup: {reason}")
            if open_devices:
                self.open_devices(reason)
            return False
        except Exception as e:
            logger.error(f"Error checking devices on startup: {e}")
            self._ui(self._log_error, f"Error checking devices: {e}")
            return False

    def _report_requested_device_missing(self, dm: Any, serial: str) -> None:
        """Say clearly that the requested ``--serial`` device is unusable.

        Nothing is selected instead (no silent fallback to another device);
        the user can start the AVD or pick a device in Devices.
        """
        try:
            from sandroid.core.initializer import describe_device_problem

            problem = describe_device_problem(dm)
        except Exception:
            problem = None
        problem = problem or f"Requested device {serial} is not connected"
        msg = (
            f"{problem}. No device selected -- nothing will run on another "
            "device. Start it, or choose one in Devices (D)."
        )
        logger.error(msg)
        self._ui(self._log_error, msg)

    def has_active_session(self) -> bool:
        """Check if there's an active analysis session.

        Returns:
            True if there are running tasks or spotlight app set
        """
        try:
            from sandroid.services import get_spotlight_service, get_task_service

            return bool(
                get_task_service().get_running() or get_spotlight_service().has_app()
            )
        except Exception as e:
            logger.debug(f"Error checking active session: {e}")
            return False

    # =========================================================================
    # Emulator launch
    # =========================================================================

    def _launch_and_watch(
        self,
        avd_name: str | None,
        options: Any,
        restart_serial: str | None = None,
        on_launched: Callable[[bool, str], Any] | None = None,
    ) -> Any:
        """Worker: launch (or restart) an emulator, wait for its boot, attach.

        Runs on a background thread; every UI call is marshaled through
        ``call_from_thread``. Once booted, ``on_emulator_ready`` decides what
        happens (default: it becomes the active device only if no device is
        active).

        Args:
            avd_name: AVD to launch (ignored with *restart_serial*).
            options: :class:`~sandroid.core.emulator.AvdLaunchOptions`.
            restart_serial: Restart this emulator (same AVD, same port)
                instead of launching *avd_name*.
            on_launched: UI-thread callback ``(ok, message)`` once the
                emulator process started (or failed to).

        Returns:
            The :class:`~sandroid.core.emulator.EmulatorLaunch`, or ``None``
            when the launch failed.
        """
        from sandroid.core import emulator
        from sandroid.core.exceptions import EmulatorLaunchError

        ui = self._call_from_thread

        def say(fn: Callable[..., Any] | None, *args: Any) -> None:
            if fn is None:
                return
            try:
                ui(fn, *args)
            except Exception:
                logger.debug("Could not report to the UI", exc_info=True)

        try:
            if restart_serial:
                launch = emulator.restart_emulator(restart_serial, options)
            else:
                launch = emulator.launch_avd(avd_name, options)
        except EmulatorLaunchError as e:
            say(self._log_error, f"Failed to start AVD: {e}")
            say(on_launched, False, str(e))
            return None
        except Exception as e:
            logger.exception("Emulator launch failed")
            say(self._log_error, f"Failed to start AVD: {type(e).__name__}: {e}")
            say(on_launched, False, f"{type(e).__name__}: {e}")
            return None
        emulator.remember_launch(launch.avd, launch.options)
        verb = "restarting" if restart_serial else "starting"
        msg = f"AVD '{launch.avd}' {verb} as {launch.serial} ({launch.options.boot})"
        say(self._log_info, msg + "...")
        say(on_launched, True, msg)

        if not self._wait_for_boot(launch, say):
            return launch
        try:
            self._get_device_manager().refresh_devices(auto_select=False)
        except Exception:
            logger.debug("Device refresh after boot failed", exc_info=True)
        if self._stale(launch):
            return launch
        if self._on_emulator_ready is not None:
            say(self._on_emulator_ready, launch.serial, launch.avd)
        else:
            self._attach_if_idle(launch.serial, launch.avd)
        return launch

    @staticmethod
    def _stale(launch: Any) -> bool:
        """True once *launch* was stopped/restarted (its serial may be reused)."""
        from sandroid.core import emulator

        current = emulator.get_launch(launch.serial)
        return launch.cancel.is_set() or (current is not None and current is not launch)

    def _wait_for_boot(self, launch: Any, say: Callable[..., None]) -> bool:
        """Worker: wait until *launch* is ready; False if it never will be.

        Waits the usual boot timeout, then -- if the emulator still runs --
        says so once and keeps waiting (up to the age after which a launch
        no longer counts as booting), so a slow boot is still attached when
        nothing else is active. Gives up quietly when the launch was stopped
        or restarted meanwhile.
        """
        from sandroid.core import emulator

        def ready(timeout: float) -> bool:
            return emulator.wait_until_ready(
                launch.serial, timeout=timeout, cancel=launch.cancel
            )

        if ready(emulator.DEFAULT_BOOT_TIMEOUT):
            return not self._stale(launch)
        if self._stale(launch):
            return False
        log = f" (log: {launch.log_path})" if launch.log_path else ""
        if not launch.alive:
            say(
                self._log_warning,
                f"AVD '{launch.avd}' ({launch.serial}) exited while booting{log}.",
            )
            return False
        say(
            self._log_warning,
            f"AVD '{launch.avd}' ({launch.serial}) is still booting after "
            f"{emulator.DEFAULT_BOOT_TIMEOUT:g}s{log}; it is used once it is "
            "ready (see Devices, D).",
        )
        remaining = emulator.BOOTING_MAX_AGE - emulator.DEFAULT_BOOT_TIMEOUT
        if ready(max(0.0, remaining)) and not self._stale(launch):
            return True
        if not self._stale(launch):
            say(
                self._log_warning,
                f"AVD '{launch.avd}' ({launch.serial}) did not finish booting{log}.",
            )
        return False

    def _attach_if_idle(self, serial: str, avd_name: str) -> None:
        """Worker thread: make a freshly booted emulator active if none is.

        The default ``on_emulator_ready``. Runs off the UI thread (the switch
        talks to adb); log lines and the refresh are marshaled.
        """
        try:
            dm = self._get_device_manager()
            active = dm.active_device
            if active is None:
                if self.switch_device(serial, cleanup=False):
                    return
            elif active.serial == serial:
                from sandroid.core import device_prep

                device_prep.request_prepare(serial, "ready", manager=dm)
                self._ui(self._log_info, f"AVD '{avd_name}' ({serial}) is ready")
                self._ui(self._refresh_ui)
                return
            self._ui(
                self._log_info,
                f"AVD '{avd_name}' ({serial}) is ready -- switch to it in Devices (D)",
            )
        except Exception as e:
            logger.error(f"Error attaching {serial}: {e}")

    # =========================================================================
    # Disconnect-detection suppression
    # =========================================================================

    def is_polling(self) -> bool:
        """Whether disconnect detection is suppressed (snapshot save/load).

        Returns:
            True while :meth:`suppress_disconnect_detection` is active.
        """
        return self._polling_active

    def suppress_disconnect_detection(self, active: bool) -> None:
        """Suppress the periodic device-disconnect poll during a known-
        disruptive ADB operation (snapshot save/load).

        Reverting VM state genuinely disrupts the ADB transport for a window
        (offline -> unauthorized -> occasionally a duplicate listing before
        it settles), which the app's poll loop (``SandroidTUI.
        _poll_device_state()``) can otherwise misread as a real device
        disconnect and stop all running tasks. ``_poll_device_state()`` and
        the post-disconnect Devices screen check :meth:`is_polling`.

        Callers must pair every ``True`` with a ``False`` (e.g. via
        ``try/finally``), so normal disconnect detection resumes even if the
        wrapped operation raises.

        Args:
            active: True to suppress polling (about to revert VM state);
                False to resume normal disconnect detection.
        """
        self._polling_active = active

    # =========================================================================
    # Device Switching
    # =========================================================================

    def switch_device(self, serial: str, cleanup: bool = True) -> bool:
        """Switch to a different device.

        Safe to call from a worker thread (ADB work stays there; log lines
        and the UI refresh are marshaled onto the UI thread).

        Args:
            serial: Serial number of device to switch to
            cleanup: Whether to stop running tasks before switching

        Returns:
            True if switch was successful
        """
        try:
            if cleanup and self.has_active_session():
                self.stop_all_tasks()

            dm = self._get_device_manager()
            success = dm.set_active_device(serial)

            if success:
                self._ui(self._log_info, f"Switched to device: {serial}")
                self.setup_device_results_folder()
                self._ui(self._refresh_ui)

            return success

        except Exception as e:
            logger.error(f"Error switching device: {e}")
            self._ui(self._log_error, f"Failed to switch device: {e}")
            return False

    def stop_all_tasks(self) -> None:
        """Stop all running background tasks."""
        try:
            from sandroid.services import get_task_service

            task_service = get_task_service()
            # get_running() returns a list[str] of task names — snapshot it
            # with list() since stop() mutates the underlying task registry.
            # (Calling .keys() here was a latent bug: list has no .keys(),
            # so the AttributeError was swallowed and NO task was stopped.)
            for task_name in list(task_service.get_running()):
                task_service.stop(task_name)
                self._ui(self._log_info, f"Stopped task: {task_name}")

        except Exception as e:
            logger.error(f"Error stopping tasks: {e}")

    def setup_device_results_folder(self) -> str | None:
        """Create device-specific results folder.

        Returns:
            Path to results folder, or None if setup failed
        """
        try:
            dm = self._get_device_manager()
            current = dm.active_device

            if not current:
                return None

            # Determine prefix based on device type
            prefix = "E_" if current.is_emulator else "P_"

            # Get base results path
            base_path = os.getenv("RESULTS_PATH", "./results/")

            # Create device-specific folder
            device_id = current.serial.replace(":", "_")
            device_folder = os.path.join(base_path, f"{prefix}{device_id}")

            os.makedirs(device_folder, exist_ok=True)

            logger.debug(f"Set up results folder: {device_folder}")
            return device_folder

        except Exception as e:
            logger.error(f"Error setting up results folder: {e}")
            return None

    # =========================================================================
    # Devices screen actions (all non-blocking; results via ``on_done``)
    # =========================================================================

    def _done(
        self, on_done: Callable[[bool, str], Any] | None, ok: bool, message: str
    ) -> None:
        """Worker thread: log *message* and report it to ``on_done`` (UI)."""
        self._ui(self._log_info if ok else self._log_error, message)
        self._ui(on_done, ok, message)

    def start_avd(
        self,
        name: str,
        options: Any = None,
        *,
        on_done: Callable[[bool, str], Any] | None = None,
    ) -> None:
        """Launch AVD *name* in the background, then wait for its boot.

        Args:
            name: AVD name.
            options: :class:`~sandroid.core.emulator.AvdLaunchOptions`
                (default: the options remembered for *name*). They are
                remembered for the next launch (a wipe as a normal boot).
            on_done: UI-thread callback ``(ok, message)`` once the emulator
                process started (not booted) or failed to start.
        """

        def worker() -> None:
            from sandroid.core import emulator

            opts = options if options is not None else emulator.remembered_options(name)
            self._launch_and_watch(name, opts, on_launched=on_done)

        self._spawn(worker, f"start-avd-{name}")

    def stop_emulator(
        self, serial: str, *, on_done: Callable[[bool, str], Any] | None = None
    ) -> None:
        """Stop emulator *serial* (``adb -s <serial> emu kill``, never pkill).

        Args:
            serial: Emulator serial.
            on_done: UI-thread callback ``(ok, message)`` once it is gone (or
                still listed after the timeout).
        """

        def worker() -> None:
            from sandroid.core import emulator

            try:
                ok = emulator.stop_emulator(serial)
            except Exception as e:
                logger.exception(f"Stopping {serial} failed")
                self._done(on_done, False, f"Could not stop {serial}: {e}")
                return
            if ok:
                self._done(on_done, True, f"Emulator {serial} stopped")
            else:
                self._done(on_done, False, f"Emulator {serial} did not stop")

        self._spawn(worker, f"stop-emulator-{serial}")

    def restart_emulator(
        self,
        serial: str,
        options: Any = None,
        *,
        on_done: Callable[[bool, str], Any] | None = None,
    ) -> None:
        """Restart emulator *serial*: same AVD, same port (so same serial).

        Args:
            serial: Emulator serial.
            options: Launch options (default: those it was launched with, else
                the remembered ones; a wipe becomes a normal boot).
            on_done: UI-thread callback ``(ok, message)`` once the relaunched
                process started or the restart failed.
        """

        def worker() -> None:
            self._launch_and_watch(
                None, options, restart_serial=serial, on_launched=on_done
            )

        self._spawn(worker, f"restart-emulator-{serial}")

    def connect(
        self, address: str, *, on_done: Callable[[bool, str], Any] | None = None
    ) -> None:
        """``adb connect`` *address* (``host[:port]``, port 5555 by default).

        Args:
            address: Network address of the device.
            on_done: UI-thread callback ``(ok, message)``.
        """
        address = (address or "").strip()
        if not _ADDRESS_RE.fullmatch(address):
            self._done(on_done, False, f"Not a host[:port] address: {address!r}")
            return

        def worker() -> None:
            from sandroid.core.adb import Adb

            out, err = Adb.send_adb_command(f"connect {address}", serial="", timeout=20)
            text = " ".join(f"{out} {err}".split())
            ok = "connected to" in text.lower() and not any(
                word in text.lower() for word in ("failed", "unable", "cannot")
            )
            self._done(
                on_done,
                ok,
                (text or f"Connected to {address}")
                if ok
                else f"adb connect {address} failed: {text or 'no answer'}",
            )

        self._spawn(worker, f"adb-connect-{address}")

    def rename_avd(
        self,
        old: str,
        new: str,
        *,
        on_done: Callable[[bool, str], Any] | None = None,
    ) -> None:
        """Rename stopped AVD *old* to *new* (moves its remembered options).

        Args:
            old: Current AVD name.
            new: New AVD name.
            on_done: UI-thread callback ``(ok, message)``.
        """

        def worker() -> None:
            from sandroid.core import emulator

            try:
                ok, message = emulator.rename_avd(old, new)
            except Exception as e:
                ok, message = False, f"{type(e).__name__}: {e}"
            self._done(on_done, ok, message or f"Renamed '{old}' to '{new}'")

        self._spawn(worker, f"rename-avd-{old}")

    def open_devices(self, reason: str = "") -> None:
        """Open the Devices screen (thread-safe; no-op without the callback)."""
        self._ui(self._open_devices, reason)

    # =========================================================================
    # Device Switch with Confirmation
    # =========================================================================

    def show_device_switch_confirmation(
        self,
        target_serial: str,
        current_serial: str,
        on_confirm: Callable[[str, bool], None] | None = None,
    ) -> bool:
        """Show confirmation modal for device switch during active session.

        Args:
            target_serial: Serial of the device to switch to
            current_serial: Serial of the current device
            on_confirm: Callback when confirmed (target_serial, cleanup)

        Returns:
            True if modal was shown
        """
        if not self._push_modal:
            self._log_error("Cannot show confirmation - push_modal not configured")
            return False

        try:
            from sandroid.services import get_spotlight_service, get_task_service
            from sandroid.tui.modals import (
                DeviceSwitchConfirmModal,
                DeviceSwitchContext,
                DeviceSwitchResult,
            )

            dm = self._get_device_manager()

            # Get device info
            current_device = dm.get_device(current_serial) if current_serial else None
            target_device = dm.get_device(target_serial)

            from_name = current_device.display_name if current_device else "None"
            to_name = target_device.display_name if target_device else target_serial

            # Get running tasks
            task_service = get_task_service()
            running_task_names = task_service.get_running()
            task_names = []
            for task_name in running_task_names:
                task = task_service.get_task(task_name)
                if task:
                    task_names.append(task.display_name)
                else:
                    task_names.append(task_name)

            # Get spotlight app info
            spotlight = get_spotlight_service()
            spotlight_name = spotlight.get_effective_package() or ""
            has_spotlight = bool(spotlight_name)

            # Check for snapshots (only relevant for emulators)
            has_snapshots = current_device.is_emulator if current_device else False

            context = DeviceSwitchContext(
                from_device=from_name,
                to_device=to_name,
                to_serial=target_serial,
                has_spotlight=has_spotlight,
                spotlight_app=spotlight_name,
                running_tasks=task_names,
                has_snapshots=has_snapshots,
            )

            def on_switch_result(result: DeviceSwitchResult) -> None:
                """Handle confirmation result."""
                if result.confirmed:
                    if on_confirm:
                        on_confirm(result.target_serial, True)
                    else:
                        self.switch_device(result.target_serial, cleanup=True)

            self._push_modal(
                DeviceSwitchConfirmModal(context=context), on_switch_result
            )
            return True

        except Exception as e:
            logger.error(f"Error showing device switch confirmation: {e}")
            self._log_error(f"Error showing confirmation: {e}")
            return False


__all__ = [
    "DeviceController",
]
