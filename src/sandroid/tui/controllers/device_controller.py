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
import subprocess
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
        """Automatically select a device, preferring emulators."""
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
            self.offer_avd_start()
            return False
        except Exception as e:
            logger.error(f"Error checking devices on startup: {e}")
            self._log_error(f"Error checking devices: {e}")
            return False

    def _resolve_startup_device_selection(self, dm: Any, devices: list) -> None:
        """Resolve device selection at startup, prompting when 2+ are ready.

        With fewer than 2 ready (``state == "device"``) devices, or when a
        device is already active, falls back to the existing silent
        ``auto_select_device()``. With 2+ ready devices, pushes the existing
        ``DeviceSelectionModal`` so the user picks explicitly instead of
        silently landing on ``emulators[0]``.

        This is deliberately startup-only: any later mid-session auto-select
        (e.g. after a disconnect leaves 2+ devices) keeps today's silent
        behavior and is untouched by this method. The session is never left
        device-less just because the picker was cancelled or unavailable.

        Args:
            dm: The device manager instance.
            devices: The freshly refreshed device list.
        """
        try:
            if dm.active_device is not None:
                return

            ready_devices = [d for d in devices if d.state == "device"]
            if len(ready_devices) < 2 or not self._push_modal:
                dm.auto_select_device()
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
            from sandroid.config.android_env import (
                find_emulator_path,
                find_existing_sdk,
                get_avd_info,
                list_available_avds,
            )

            emulator_path = find_emulator_path()
            sdk_path = find_existing_sdk()

            if not emulator_path:
                logger.warning("No emulator path found")
                return []

            avd_names = list_available_avds(emulator_path, sdk_path)

            avds = []
            for name in avd_names:
                info = get_avd_info(name)
                avds.append(
                    AVDInfo(
                        name=name,
                        android_version=info.get("android_version", "Unknown"),
                        api_level=info.get("api_level", "?"),
                        device_name=info.get("device_name", ""),
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
            from sandroid.config.android_env import (
                find_emulator_path,
                find_existing_sdk,
            )

            emulator_path = find_emulator_path()
            sdk_path = find_existing_sdk()

            if not emulator_path:
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
                    emulator_path=emulator_path,
                    sdk_path=sdk_path,
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
        """Start an AVD and poll for it to become available.

        Args:
            avd_name: Name of AVD to start
            headless: Whether to start in headless mode
            save_as_default: Whether to save this AVD as default
            emulator_path: Path to emulator (auto-detected if not provided)
            sdk_path: Path to SDK (auto-detected if not provided)

        Returns:
            True if AVD start was initiated successfully
        """
        try:
            from sandroid.config.android_env import (
                find_emulator_path,
                find_existing_avd_home,
                find_existing_sdk,
            )

            if not emulator_path:
                emulator_path = find_emulator_path()
            if not sdk_path:
                sdk_path = find_existing_sdk()

            if not emulator_path:
                self._log_error("Cannot start AVD: Emulator not found")
                return False

            mode_str = "headless" if headless else "with UI"
            self._log_info(f"Starting AVD '{avd_name}' ({mode_str})...")

            # Build command
            cmd = [str(emulator_path), "-avd", avd_name]
            if headless:
                cmd.extend(
                    ["-no-window", "-no-boot-anim", "-gpu", "swiftshader_indirect"]
                )

            # Set up environment
            env = os.environ.copy()
            avd_home = find_existing_avd_home()
            if avd_home:
                env["ANDROID_AVD_HOME"] = str(avd_home)
            if sdk_path:
                env["ANDROID_SDK_ROOT"] = str(sdk_path)

            # Start emulator in background thread
            def start_emulator():
                try:
                    subprocess.Popen(
                        cmd,
                        env=env,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                except FileNotFoundError as e:
                    logger.error(
                        f"Emulator executable not found for AVD '{avd_name}': {e}. "
                        "Check ANDROID_SDK_ROOT and emulator installation."
                    )
                except OSError as e:
                    logger.error(f"OS error starting AVD '{avd_name}': {e}")
                except subprocess.SubprocessError as e:
                    logger.error(f"Subprocess error starting AVD '{avd_name}': {e}")
                except Exception as e:
                    logger.error(
                        f"Unexpected error starting AVD '{avd_name}': "
                        f"{type(e).__name__}: {e}"
                    )

            thread = threading.Thread(target=start_emulator, daemon=True)
            thread.start()

            # Save as default if requested
            if save_as_default:
                self.save_avd_as_default(avd_name, headless)

            # Start polling for device
            self.start_device_poll(avd_name)

            return True

        except Exception as e:
            logger.exception(f"Error starting AVD: {e}")
            self._log_error(f"Failed to start AVD: {e}")
            return False

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
        from sandroid.core.emulator import Emulator

        def start_avd_worker():
            """Worker function to start AVD in background."""
            try:
                success = Emulator.start_avd(
                    avd_name,
                    boot_mode=boot_mode,
                    snapshot_name=snapshot_name,
                )

                if success:
                    if call_from_thread and notify:
                        call_from_thread(
                            notify,
                            f"AVD '{avd_name}' starting ({boot_mode} mode)...",
                        )
                    self._log_info(f"AVD '{avd_name}' starting ({boot_mode} mode)...")
                else:
                    self._log_error(f"Failed to start AVD '{avd_name}'")
            except Exception as e:
                self._log_error(f"Error starting AVD: {e}")

        if run_worker:
            run_worker(start_avd_worker, name="start_avd", thread=True)
        else:
            # Run in thread if no worker provided
            thread = threading.Thread(target=start_avd_worker, daemon=True)
            thread.start()

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
        """Restart an emulator with the specified boot mode.

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
        import time

        from sandroid.core.adb import Adb
        from sandroid.core.emulator import Emulator

        def restart_worker():
            """Worker function to restart emulator in background."""
            try:
                dm = self._get_device_manager()
                device = dm.get_device(serial)
                if not device:
                    self._log_error(f"Device '{serial}' not found")
                    return

                avd_name = device.name or device.model

                # Kill the emulator
                self._log_info(f"Stopping emulator '{avd_name}'...")
                Adb.send_telnet_command("kill")

                # Wait for emulator to stop
                time.sleep(3)

                # Start with new boot mode
                self._log_info(f"Starting '{avd_name}' with {boot_mode} mode...")
                success = Emulator.start_avd(
                    avd_name,
                    boot_mode=boot_mode,
                    snapshot_name=snapshot_name,
                )

                if success:
                    self._log_info(f"AVD '{avd_name}' restarting ({boot_mode} mode)...")
                else:
                    self._log_error(f"Failed to restart AVD '{avd_name}'")
            except Exception as e:
                self._log_error(f"Error restarting emulator: {e}")

        if run_worker:
            run_worker(restart_worker, name="restart_emulator", thread=True)
        else:
            thread = threading.Thread(target=restart_worker, daemon=True)
            thread.start()

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
            app = spotlight.get_app_tuple()
            spawn_app = spotlight.get_spawn_package()
            has_spotlight = bool(app or spawn_app)
            spotlight_name = ""
            if spawn_app:
                spotlight_name = spawn_app
            elif app and isinstance(app, tuple):
                spotlight_name = app[0]
            elif app:
                spotlight_name = str(app)

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
