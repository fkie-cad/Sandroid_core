"""Device Controller for TUI.

This controller manages device/AVD lifecycle operations, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Device detection and connection checking
- AVD selection and startup
- Device polling for availability
- Device switching with session management
- Results folder setup per device

Usage:
    from sandroid.tui.controllers import DeviceController

    controller = DeviceController(
        log_info=activity_log.log_info,
        log_warning=activity_log.log_warning,
        push_modal=app.push_screen,
        schedule_timer=app.set_timer,
        refresh_ui=app.refresh_ui,
    )

    # Check for devices on startup
    controller.check_devices_on_startup()

    # Start an AVD
    controller.start_avd("Pixel_6_Pro_API_31", headless=True)
"""

import logging
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional, Protocol

if TYPE_CHECKING:
    from sandroid.core.device_manager import Device

logger = logging.getLogger(__name__)


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


@dataclass
class AVDInfo:
    """Information about an Android Virtual Device."""

    name: str
    android_version: str = "Unknown"
    api_level: str = "?"
    device_name: str = ""


@dataclass
class DeviceInfo:
    """Information about a connected device."""

    serial: str
    display_name: str
    is_emulator: bool
    api_level: str | None = None


@dataclass
class DevicePollResult:
    """Result of device polling operation."""

    found: bool
    device: DeviceInfo | None = None
    message: str = ""


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
            schedule_timer=lambda secs, fn: fn(),
            refresh_ui=lambda: None,
        )

        # Check startup devices
        controller.check_devices_on_startup()

        # Start AVD with polling
        controller.start_avd_and_poll("Pixel_6", headless=True)
    """

    def __init__(
        self,
        log_info: Callable[[str], None] | None = None,
        log_warning: Callable[[str], None] | None = None,
        log_error: Callable[[str], None] | None = None,
        push_modal: Callable[[Any, Callable], None] | None = None,
        schedule_timer: Callable[[float, Callable], None] | None = None,
        refresh_ui: Callable[[], None] | None = None,
        toolbox: Any | None = None,
        call_from_thread: Callable[..., Any] | None = None,
    ):
        """Initialize DeviceController with UI callbacks.

        Args:
            log_info: Callback for info-level logging to UI
            log_warning: Callback for warning-level logging to UI
            log_error: Callback for error-level logging to UI
            push_modal: Callback to push a modal screen with result callback
            schedule_timer: Callback to schedule a timed function call
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
        """
        self._log_info = log_info or self._default_log
        self._log_warning = log_warning or self._default_log
        self._log_error = log_error or self._default_log
        self._push_modal = push_modal
        self._schedule_timer = schedule_timer
        self._refresh_ui = refresh_ui
        self._toolbox = toolbox
        self._call_from_thread = call_from_thread or (lambda fn, *args: fn(*args))
        self._polling_active = False

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

    # =========================================================================
    # Device Detection
    # =========================================================================

    def check_devices_on_startup(self) -> bool:
        """Check for connected devices on startup.

        Enumerates without auto-selecting (``auto_select=False``) so that,
        when 2+ devices are ready, a picker can be offered before any device
        is silently selected -- see ``_resolve_startup_device_selection``.

        Returns:
            True if devices are available, False if no devices found
        """
        try:
            dm = self._get_device_manager()
            devices = dm.refresh_devices(auto_select=False)

            if devices:
                logger.debug(f"Found {len(devices)} device(s) on startup")
                self._resolve_startup_device_selection(dm, devices)
                return True

            # No devices connected - offer to start an AVD
            logger.info("No devices connected on startup")
            explicit = getattr(dm, "preferred_serial", lambda: None)()
            if explicit:
                self._report_requested_device_missing(dm, explicit)
            self.offer_avd_start()
            return False
        except Exception as e:
            logger.error(f"Error checking devices on startup: {e}")
            self._log_error(f"Error checking devices: {e}")
            return False

    def _report_requested_device_missing(self, dm: Any, serial: str) -> None:
        """Say clearly that the requested ``--serial`` device is unusable.

        Nothing is selected instead (no silent fallback to another device);
        the user can start the AVD or pick a device with the selector.
        """
        try:
            from sandroid.core.initializer import describe_device_problem

            problem = describe_device_problem(dm)
        except Exception:
            problem = None
        problem = problem or f"Requested device {serial} is not connected"
        msg = (
            f"{problem}. No device selected -- nothing will run on another "
            "device. Start it, or choose one with the device selector."
        )
        logger.error(msg)
        try:
            self._call_from_thread(self._log_error, msg)
        except Exception:
            logger.debug("Could not show the device error in the UI", exc_info=True)

    def _resolve_startup_device_selection(self, dm: Any, devices: list) -> None:
        """Resolve device selection at startup, prompting when 2+ are ready.

        With fewer than 2 ready (``state == "device"``) devices, or when a
        device is already active, falls back to the existing silent
        ``auto_select_device()``. With 2+ ready devices, pushes the existing
        ``DeviceSelectionModal`` so the user picks explicitly instead of
        silently landing on ``emulators[0]``.

        This is deliberately startup-only. Normally the StartupScreen already
        asked (``initialize_core`` refuses to guess among 2+ devices), so a
        device is active here. ``auto_select_device()`` never picks one of
        several devices either, so a cancelled picker leaves the session
        without a device (press D to choose) rather than on a guessed one.

        Args:
            dm: The device manager instance.
            devices: The freshly refreshed device list.
        """
        try:
            if dm.active_device is not None:
                return

            ready_devices = [d for d in devices if d.state == "device"]
            explicit = getattr(dm, "preferred_serial", lambda: None)()
            if explicit or len(ready_devices) < 2 or not self._push_modal:
                # auto_select_device() honours --serial / ANDROID_SERIAL and
                # never falls back to another device.
                dm.auto_select_device()
                if explicit and dm.active_device is None:
                    self._report_requested_device_missing(dm, explicit)
                return

            from sandroid.tui.modals import DeviceSelectionModal

            def on_selected(serial: str | None) -> None:
                if serial:
                    self.switch_device(serial)
                else:
                    dm.auto_select_device()

            modal = DeviceSelectionModal(devices=devices, current_serial=None)
            # Runs off a raw background thread (check_devices_on_startup's
            # caller) -- push_modal (Textual's push_screen) calls
            # asyncio.get_running_loop() internally and raises if invoked
            # directly off-thread, so this must marshal onto the UI thread.
            self._call_from_thread(self._push_modal, modal, on_selected)

        except Exception as e:
            logger.exception(f"Error resolving startup device selection: {e}")
            try:
                dm.auto_select_device()
            except Exception:
                pass

    def get_connected_devices(self) -> list[DeviceInfo]:
        """Get list of currently connected devices.

        Returns:
            List of DeviceInfo objects for connected devices
        """
        try:
            dm = self._get_device_manager()
            devices = dm.refresh_devices()

            return [
                DeviceInfo(
                    serial=d.serial,
                    display_name=d.display_name,
                    is_emulator=d.is_emulator,
                    api_level=getattr(d, "api_level", None),
                )
                for d in devices
            ]
        except Exception as e:
            logger.error(f"Error getting connected devices: {e}")
            return []

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
    # AVD Management
    # =========================================================================

    def get_available_avds(self) -> list[AVDInfo]:
        """Get list of available AVDs.

        Returns:
            List of AVDInfo objects for available AVDs
        """
        try:
            from sandroid.core.emulator import avd_info, emulator_binary, list_avds

            if emulator_binary() is None:
                logger.warning("No emulator path found")
                return []

            avds = []
            for name in list_avds():
                info = avd_info(name)
                avds.append(
                    AVDInfo(
                        name=name,
                        android_version=info.android_version,
                        api_level=str(info.api_level) if info.api_level else "?",
                        device_name=info.device_name,
                    )
                )
            return avds
        except Exception as e:
            logger.error(f"Error getting available AVDs: {e}")
            return []

    def offer_avd_start(self) -> None:
        """Show AVD selection when no devices are connected.

        This method retrieves available AVDs and pushes a selection modal
        if the push_modal callback is configured.
        """
        try:
            from sandroid.core.emulator import emulator_binary

            if emulator_binary() is None:
                self._log_warning(
                    "No Android device connected. Run 'sandroid-config init' to configure AVD."
                )
                return

            avds = self.get_available_avds()

            if not avds:
                self._log_warning(
                    "No Android device or AVD available. Create an AVD in Android Studio."
                )
                return

            if not self._push_modal:
                self._log_info(f"No devices connected. {len(avds)} AVD(s) available.")
                return

            # Push AVD selection modal
            from sandroid.tui.modals import AVDInfo as ModalAVDInfo
            from sandroid.tui.modals import (
                AVDSelectionModal,
                AVDSelectionResult,
            )

            modal_avds = [
                ModalAVDInfo(
                    name=avd.name,
                    android_version=avd.android_version,
                    api_level=avd.api_level,
                    device_name=avd.device_name,
                )
                for avd in avds
            ]

            def on_avd_selected(result: AVDSelectionResult) -> None:
                if result.cancelled:
                    self._log_info(
                        "No AVD started. Connect a device or run 'sandroid-config avd start'."
                    )
                    return

                self.start_avd_and_poll(
                    result.selected_avd,
                    headless=result.headless,
                    save_as_default=result.save_as_default,
                )

            # check_devices_on_startup (this method's only caller) runs off a
            # raw background thread -- push_modal (Textual's push_screen)
            # calls asyncio.get_running_loop() internally and raises if
            # invoked directly off-thread, so this must marshal onto the UI
            # thread (matching _resolve_startup_device_selection).
            self._call_from_thread(
                self._push_modal, AVDSelectionModal(avds=modal_avds), on_avd_selected
            )

        except Exception as e:
            logger.exception(f"Error offering AVD start: {e}")
            self._log_error(f"Error showing AVD selection: {e}")

    def start_avd_and_poll(
        self,
        avd_name: str,
        headless: bool = False,
        save_as_default: bool = False,
        emulator_path: str | None = None,
        sdk_path: str | None = None,
    ) -> bool:
        """Start an AVD in the background and attach it once it has booted.

        Launches through :func:`sandroid.core.emulator.launch_avd` (explicit
        port, safe flags, log file), remembers the options and waits for
        exactly that serial to boot (see :meth:`_launch_and_watch`).

        Args:
            avd_name: Name of AVD to start
            headless: Whether to start in headless mode
            save_as_default: Whether to save this AVD as default
            emulator_path: Ignored (kept for compatibility; the emulator is
                resolved by :func:`sandroid.core.emulator.emulator_binary`).
            sdk_path: Ignored (kept for compatibility).

        Returns:
            True if AVD start was initiated successfully
        """
        from sandroid.core.emulator import AvdLaunchOptions

        mode_str = "headless" if headless else "with UI"
        self._log_info(f"Starting AVD '{avd_name}' ({mode_str})...")
        opts = AvdLaunchOptions(headless=headless)
        thread = threading.Thread(
            target=self._launch_and_watch,
            args=(avd_name, opts),
            name=f"start-avd-{avd_name}",
            daemon=True,
        )
        thread.start()
        if save_as_default:
            self.save_avd_as_default(avd_name, headless)
        return True

    def _launch_and_watch(
        self,
        avd_name: str | None,
        options: Any,
        restart_serial: str | None = None,
        notify: Callable[[str], Any] | None = None,
        call_from_thread: Callable[..., Any] | None = None,
    ) -> Any:
        """Worker: launch (or restart) an emulator, wait for its boot, attach.

        Runs on a background thread; every UI call is marshaled through
        ``call_from_thread``. Once booted, the emulator becomes the active
        device only if no device is active.

        Args:
            avd_name: AVD to launch (ignored with *restart_serial*).
            options: :class:`~sandroid.core.emulator.AvdLaunchOptions`.
            restart_serial: Restart this emulator (same AVD, same port)
                instead of launching *avd_name*.
            notify: Optional toast callback (UI thread).
            call_from_thread: Marshals onto the UI thread (default: the
                controller's).

        Returns:
            The :class:`~sandroid.core.emulator.EmulatorLaunch`, or ``None``
            when the launch failed.
        """
        from sandroid.core import emulator
        from sandroid.core.exceptions import EmulatorLaunchError

        ui = call_from_thread or self._call_from_thread

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
            return None
        except Exception as e:
            logger.exception("Emulator launch failed")
            say(self._log_error, f"Failed to start AVD: {type(e).__name__}: {e}")
            return None
        emulator.remember_launch(launch.avd, launch.options)
        verb = "restarting" if restart_serial else "starting"
        msg = f"AVD '{launch.avd}' {verb} as {launch.serial} ({launch.options.boot})"
        say(self._log_info, msg + "...")
        say(notify, msg + "...")

        if not emulator.wait_until_ready(launch.serial):
            log = f" (log: {launch.log_path})" if launch.log_path else ""
            say(
                self._log_warning,
                f"AVD '{launch.avd}' ({launch.serial}) did not finish booting{log}. "
                "Press 'D' to refresh the device list when it is ready.",
            )
            return launch
        try:
            self._get_device_manager().refresh_devices(auto_select=False)
        except Exception:
            logger.debug("Device refresh after boot failed", exc_info=True)
        say(self._attach_if_idle, launch.serial, launch.avd)
        return launch

    def _attach_if_idle(self, serial: str, avd_name: str) -> None:
        """UI thread: make a freshly booted emulator active if none is."""
        try:
            dm = self._get_device_manager()
            active = dm.active_device
            if active is None:
                if self.switch_device(serial, cleanup=False):
                    return
            elif active.serial == serial:
                self._log_info(f"AVD '{avd_name}' ({serial}) is ready")
                if self._refresh_ui:
                    self._refresh_ui()
                return
            self._log_info(
                f"AVD '{avd_name}' ({serial}) is ready -- press D to switch to it"
            )
        except Exception as e:
            logger.error(f"Error attaching {serial}: {e}")

    def save_avd_as_default(self, avd_name: str, headless: bool = False) -> bool:
        """Save AVD as default in config.

        Args:
            avd_name: Name of AVD to save
            headless: Whether to save headless mode preference

        Returns:
            True if saved successfully
        """
        try:
            from sandroid.config.loader import ConfigLoader

            loader = ConfigLoader()
            loader.load_and_update_section(
                "emulator",
                {
                    "selected_avd": avd_name,
                    "device_name": avd_name,
                    "avd_headless": headless,
                },
            )
            self._log_info(f"Saved '{avd_name}' as default AVD")
            return True

        except Exception as e:
            logger.debug(f"Failed to save AVD as default: {e}")
            return False

    # =========================================================================
    # Device Polling
    # =========================================================================

    def start_device_poll(
        self,
        avd_name: str,
        attempts: int = 0,
        max_attempts: int = 30,
        interval_seconds: float = 2.0,
    ) -> None:
        """Poll for device to appear after starting AVD.

        Args:
            avd_name: Name of AVD being started (for logging)
            attempts: Current attempt count
            max_attempts: Maximum poll attempts (default 30 = 60 seconds)
            interval_seconds: Seconds between poll attempts
        """
        self._polling_active = True

        try:
            dm = self._get_device_manager()
            devices = dm.refresh_devices()

            if devices:
                # Device appeared!
                self._polling_active = False
                device = devices[0]
                type_tag = "[E]" if device.is_emulator else "[P]"
                self._log_info(f"Device connected: {type_tag} {device.display_name}")

                # Force UI refresh
                if self._refresh_ui:
                    self._refresh_ui()
                return

            if attempts >= max_attempts:
                self._polling_active = False
                self._log_warning(
                    "AVD taking longer than expected to start. "
                    "Press 'D' to refresh device list when ready."
                )
                return

            # Schedule next poll
            if self._schedule_timer:
                self._schedule_timer(
                    interval_seconds,
                    lambda: self.start_device_poll(
                        avd_name, attempts + 1, max_attempts, interval_seconds
                    ),
                )
            else:
                # No timer available, poll synchronously (for testing)
                import time

                time.sleep(interval_seconds)
                self.start_device_poll(
                    avd_name, attempts + 1, max_attempts, interval_seconds
                )

        except Exception as e:
            self._polling_active = False
            logger.error(f"Error polling for device: {e}")

    def is_polling(self) -> bool:
        """Check if device polling is currently active.

        Returns:
            True if polling for device
        """
        return self._polling_active

    def stop_polling(self) -> None:
        """Stop any active device polling."""
        self._polling_active = False

    def suppress_disconnect_detection(self, active: bool) -> None:
        """Suppress the periodic device-disconnect poll during a known-
        disruptive ADB operation (snapshot save/load).

        Reverting VM state genuinely disrupts the ADB transport for a window
        (offline -> unauthorized -> occasionally a duplicate listing before
        it settles), which the app's poll loop (``SandroidTUI.
        _poll_device_state()``) can otherwise misread as a real device
        disconnect and stop all running tasks. Reuses the exact
        ``_polling_active`` flag :meth:`is_polling` already exposes for the
        AVD-boot poll -- ``_poll_device_state()`` already checks it, so no
        new plumbing is needed in the app's poll loop, just this call.

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
                self._log_info(f"Switched to device: {serial}")
                self.setup_device_results_folder()

                if self._refresh_ui:
                    self._refresh_ui()

            return success

        except Exception as e:
            logger.error(f"Error switching device: {e}")
            self._log_error(f"Failed to switch device: {e}")
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
                self._log_info(f"Stopped task: {task_name}")

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
    # Boot Mode Operations
    # =========================================================================

    @staticmethod
    def _boot_options(boot_mode: str, snapshot_name: str | None, headless: bool) -> Any:
        """``AvdLaunchOptions`` for a modal boot mode (``default`` = normal)."""
        from sandroid.core.emulator import AvdLaunchOptions

        boot = {"default": "normal"}.get(boot_mode, boot_mode)
        if boot not in ("normal", "cold", "snapshot", "wipe"):
            boot = "normal"
        return AvdLaunchOptions(
            headless=headless,
            boot=boot,
            snapshot=snapshot_name if boot == "snapshot" else None,
        )

    def _run_background(
        self, fn: Callable[[], Any], name: str, run_worker: Callable | None
    ) -> None:
        if run_worker:
            run_worker(fn, name=name, thread=True)
        else:
            threading.Thread(target=fn, name=name, daemon=True).start()

    def start_avd_with_boot_mode(
        self,
        avd_name: str,
        boot_mode: str,
        snapshot_name: str | None = None,
        run_worker: Callable | None = None,
        call_from_thread: Callable | None = None,
        notify: Callable | None = None,
    ) -> bool:
        """Start an AVD with the specified boot mode.

        Headless follows the AVD's remembered options; the launch goes
        through :func:`sandroid.core.emulator.launch_avd`.

        Args:
            avd_name: Name of the AVD to start
            boot_mode: Boot mode ("default", "cold", "snapshot", "wipe")
            snapshot_name: Snapshot name for "snapshot" boot mode
            run_worker: Callback to run in worker thread
            call_from_thread: Callback to execute on main thread
            notify: Callback for notifications

        Returns:
            True if start was initiated
        """

        def start_avd_worker() -> None:
            from sandroid.core.emulator import remembered_options

            headless = remembered_options(avd_name).headless
            opts = self._boot_options(boot_mode, snapshot_name, headless)
            self._launch_and_watch(
                avd_name, opts, notify=notify, call_from_thread=call_from_thread
            )

        self._run_background(start_avd_worker, "start_avd", run_worker)
        return True

    def restart_emulator_with_boot_mode(
        self,
        serial: str,
        boot_mode: str,
        snapshot_name: str | None = None,
        run_worker: Callable | None = None,
        call_from_thread: Callable | None = None,
        notify: Callable | None = None,
    ) -> bool:
        """Restart emulator *serial* with the specified boot mode.

        Stops exactly that emulator (``adb -s <serial> emu kill``) and
        relaunches its AVD on the same port, so the serial stays the same
        (see :func:`sandroid.core.emulator.restart_emulator`).

        Args:
            serial: Serial number of the emulator
            boot_mode: Boot mode ("default", "cold", "snapshot", "wipe")
            snapshot_name: Snapshot name for "snapshot" boot mode
            run_worker: Callback to run in worker thread
            call_from_thread: Callback to execute on main thread
            notify: Callback for notifications

        Returns:
            True if restart was initiated
        """

        def restart_worker() -> None:
            from sandroid.core.emulator import (
                avd_name_of,
                get_launch,
                remembered_options,
            )

            launch = get_launch(serial)
            if launch is not None:
                headless = launch.options.headless
            else:
                avd = avd_name_of(serial)
                headless = remembered_options(avd).headless if avd else False
            opts = self._boot_options(boot_mode, snapshot_name, headless)
            self._launch_and_watch(
                None,
                opts,
                restart_serial=serial,
                notify=notify,
                call_from_thread=call_from_thread,
            )

        self._run_background(restart_worker, "restart_emulator", run_worker)
        return True

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
    "AVDInfo",
    "DeviceController",
    "DeviceInfo",
    "DevicePollResult",
]
