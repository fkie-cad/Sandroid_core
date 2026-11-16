"""Device manager for multi-device support.

This module provides the DeviceManager singleton that handles device enumeration,
selection, and switching with proper state management.
"""

import logging
import re
import threading
import time
from collections.abc import Callable

from .device import Device, DeviceCapability

logger = logging.getLogger(__name__)

#: Minimum interval between re-probe attempts on a device that is present and
#: "ready" but still failed to answer getprop (a flickering/zombie serial).
#: Without this, a device that never actually finishes booting would be
#: re-probed on every single refresh cycle indefinitely.
PROBE_RETRY_COOLDOWN_SECONDS = 30.0

#: Name of the connected/active device as recorded in runs and reports (AVD
#: name for emulators, model for physical devices), or ``None`` while no
#: device has been activated -- then config ``emulator.device_name`` is used.
_active_device_name: str | None = None
#: Session device name before the first device was activated (the config
#: value), restored by :meth:`DeviceManager.reset`.
_configured_device_name: str | None = None


def resolve_device_name(device: Device) -> str | None:
    """The name runs/reports should carry for ``device``.

    Emulators: the AVD name (``ro.boot.qemu.avd_name`` / ``emu avd name``,
    already stored in ``device.name`` by :meth:`DeviceManager.
    get_avd_name_for_device`); if that is unknown (``name`` is just the
    serial) the model. Physical devices: the model (``Pixel 6 Pro``), then
    the product name. Whitespace/slashes become ``_`` so the value is also a
    safe folder name.
    """
    if device.is_emulator:
        name = device.name if device.name and device.name != device.serial else ""
        name = name or device.model
    else:
        name = device.model or device.name
    name = re.sub(r"[\s/\\]+", "_", (name or "").strip())
    return name or None


def active_device_name() -> str | None:
    """Name of the active device (see :func:`resolve_device_name`) or None."""
    return _active_device_name


class DeviceManager:
    """Manages connected Android devices and device switching.

    Provides:
    - Device enumeration (emulators + physical devices)
    - Device type detection
    - Active device tracking
    - Device switching with state reset
    - Capability checking for feature gating

    Uses singleton pattern for global access.
    """

    _instance: "DeviceManager | None" = None

    #: Serial requested via ``--serial`` / config ``emulator.serial`` (set by
    #: ``initialize_core``). ``ANDROID_SERIAL`` is the fallback; see
    #: :meth:`preferred_serial`.
    _preferred_serial: str | None = None

    @classmethod
    def set_preferred_serial(cls, serial: str | None) -> None:
        """Pin device selection to ``serial`` (None = automatic selection)."""
        cls._preferred_serial = serial or None

    @classmethod
    def preferred_serial(cls) -> str | None:
        """Explicitly requested device serial, if any.

        Precedence: ``--serial`` / config ``emulator.serial`` (via
        :meth:`set_preferred_serial`), then the ``ANDROID_SERIAL`` environment
        variable adb itself honours.
        """
        import os

        return cls._preferred_serial or os.environ.get("ANDROID_SERIAL") or None

    def __init__(self):
        """Initialize the device manager."""
        self._devices: dict[str, Device] = {}
        self._active_device: Device | None = None
        self._on_device_change_callbacks: list[Callable[[Device], None]] = []
        self._on_devices_updated_callbacks: list[Callable[[list[Device]], None]] = []
        # Serializes refresh_devices() across background poll threads; must be
        # reentrant (a callback chain may re-enter on the same thread).
        self._lock = threading.RLock()

    @classmethod
    def get(cls) -> "DeviceManager":
        """Get the singleton instance.

        Returns:
            The DeviceManager singleton
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance (primarily for testing).

        Also forgets the recorded device name and restores the configured
        one in the session state (see ``_sync_session_device_name``).
        """
        global _active_device_name, _configured_device_name
        cls._instance = None
        if _active_device_name is not None and _configured_device_name is not None:
            try:
                from sandroid.services import get_session_state_service

                get_session_state_service().device_name = _configured_device_name
            except Exception:
                pass
        _active_device_name = None
        _configured_device_name = None

    def refresh_devices(self, *, auto_select: bool = True) -> list[Device]:
        """Refresh the list of connected devices from ADB.

        Parses the output of `adb devices -l` to enumerate all connected devices.

        Args:
            auto_select: Whether to auto-select a device when there is no
                active device (default: True, preserving prior behavior).
                Pass False to enumerate without ever auto-selecting -- used
                by the startup-only multi-device picker so it can offer a
                choice before anything is silently selected.

        Returns:
            List of Device objects
        """
        from .adb import Adb

        # The ADB enumeration + parsing + state mutation must be serialized
        # across background poll threads, so it runs under the lock. The
        # callbacks and auto-select are deliberately deferred until AFTER the
        # lock is released (see the deadlock-avoidance note below).
        device_lost = False
        need_auto_select = False
        # Set to the active Device when its android_version/api_level get
        # (re)populated this pass without a disconnect or auto-select, so the
        # post-lock notify section can fire a one-off repaint (see part B below).
        active_metadata_device: Device | None = None

        with self._lock:
            output, error = Adb.send_adb_command("devices -l")

            # Bail on a FAILED enumeration so a transient ADB error or 30s
            # timeout is never misread as "all devices gone" (which would
            # spuriously disconnect a healthy active device — flapping). A
            # timeout returns ("", "Command timed out after 30 seconds"),
            # whose message has no "error" substring, so we also bail whenever
            # there is an error AND no output. A *successful* enumeration always
            # carries the "List of devices attached" header, so a genuine empty
            # device list still has non-empty output and proceeds normally.
            if error and ("error" in error.lower() or not output.strip()):
                logger.warning(f"Skipping device refresh — ADB failed: {error}")
                # Returning from within `with` releases the lock correctly.
                return list(self._devices.values())

            new_devices: dict[str, Device] = {}
            # With an explicitly pinned serial (--serial / ANDROID_SERIAL) in a
            # shared multi-emulator lab, never probe other people's devices.
            pinned = self.preferred_serial()

            # Parse "adb devices -l" output
            # Format: serial state [key:value ...]
            # Example: emulator-5554 device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64 device:emu64xa transport_id:1
            for line in output.strip().split("\n")[
                1:
            ]:  # Skip header "List of devices attached"
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 2:
                    continue

                serial = parts[0]
                state = parts[1]

                # Parse additional device info
                model = ""
                product = ""
                device_name = ""
                transport_id = ""

                for part in parts[2:]:
                    if ":" in part:
                        key, value = part.split(":", 1)
                        if key == "model":
                            model = value
                        elif key == "product":
                            product = value
                        elif key == "device":
                            device_name = value
                        elif key == "transport_id":
                            transport_id = value

                # Check if device already exists
                if serial in self._devices:
                    device = self._devices[serial]
                    device.state = state
                    # Update model/name if we got new info
                    if model and not device.model:
                        device.model = model
                    if product and not device.name:
                        device.name = product
                    # A device first seen while offline/booting couldn't answer
                    # getprop, so its android_version/api_level are still empty.
                    # Re-read them once it is ready. Idempotent: skips as soon as
                    # android_version is set, so there is no per-refresh ADB churn
                    # on a healthy device. Gated by a cooldown so a flickering
                    # zombie serial (present but never actually answers) isn't
                    # re-probed on every single refresh cycle indefinitely.
                    if (
                        state == "device"
                        and not device.android_version
                        and (not pinned or serial == pinned)
                    ):
                        since_last_attempt = (
                            time.monotonic() - device.last_probe_attempt
                        )
                        if since_last_attempt >= PROBE_RETRY_COOLDOWN_SECONDS:
                            self._populate_device_info(device)
                            if device is self._active_device and device.android_version:
                                active_metadata_device = device
                else:
                    device = Device(
                        serial=serial,
                        name=product or device_name or "",
                        state=state,
                        model=model,
                    )
                    # Populate additional info for new devices -- but only
                    # for ready ones. Stale/offline/unauthorized entries (e.g.
                    # a dead "emulator-5556 offline" left in adbd) can't answer
                    # getprop and would just spam warnings; they are probed by
                    # the existing-device branch above once they turn ready.
                    if state == "device" and (not pinned or serial == pinned):
                        self._populate_device_info(device)
                    else:
                        logger.debug(
                            "Ignoring not-ready device %s (state: %s)", serial, state
                        )

                new_devices[serial] = device

            # Disconnect trigger: the active serial is ABSENT from the new
            # listing. This is intentionally absent-only -- a killed emulator
            # drops out of `adb devices` entirely, whereas offline/unauthorized
            # transitions during a normal boot keep the serial present and must
            # NOT null the device (broadening to "present but state != device"
            # would flap on every boot). We may note a lingering non-ready
            # state but never act on it.
            if self._active_device and self._active_device.serial not in new_devices:
                logger.warning(
                    f"Active device {self._active_device.serial} disconnected"
                )
                self._active_device = None
                # Clear the ADB target so later `adb -s <dead-serial>` calls
                # don't block on the 30s transport timeout.
                Adb.set_target_device(None)
                device_lost = True
            elif (
                self._active_device
                and new_devices[self._active_device.serial].state != "device"
            ):
                logger.debug(
                    "Active device %s present but in non-ready state %r; "
                    "not acting (avoids boot flapping)",
                    self._active_device.serial,
                    new_devices[self._active_device.serial].state,
                )

            self._devices = new_devices

            # Auto-select if there are devices but no active device (unless the
            # caller opted out, e.g. the startup picker choosing among 2+).
            need_auto_select = (
                auto_select and not self._active_device and len(self._devices) > 0
            )

        # DEADLOCK AVOIDANCE: enumerate/mutate under the lock above, then
        # notify/auto-select OUTSIDE it. The app's registered change handler
        # calls Textual's blocking call_from_thread; if these callbacks fired
        # while holding the lock, a UI-thread refresh_devices() (e.g.
        # action_show_device_selector) waiting on the lock would deadlock the
        # event loop.

        # Notify list listeners.
        for callback in self._on_devices_updated_callbacks:
            try:
                callback(list(self._devices.values()))
            except Exception as e:
                logger.warning(f"Device update callback failed: {e}")

        # Notify change listeners of the disconnect (active device -> None).
        if device_lost:
            for callback in self._on_device_change_callbacks:
                try:
                    callback(None)
                except Exception as e:
                    logger.warning(f"Device change callback failed: {e}")
        elif active_metadata_device is not None:
            # The still-active device just had its android_version/api_level
            # (re)populated after a reconnect/boot — no disconnect and no
            # auto-select fired, so fire a one-off change to repaint the glance.
            # Fires at most once per reconnect (the guard above is false once the
            # version is set), and is mutually exclusive with device_lost.
            for callback in self._on_device_change_callbacks:
                try:
                    callback(active_metadata_device)
                except Exception as e:
                    logger.warning(f"Device change callback failed: {e}")

        if need_auto_select:
            self.auto_select_device()

        return list(self._devices.values())

    def _populate_device_info(self, device: Device) -> None:
        """Populate additional device information via ADB.

        Targets this specific device per-call (via ``serial=``) instead of
        mutating the shared ``Adb._target_device`` global, so a concurrent
        caller targeting a different (e.g. the real active) device is never
        affected by this probe -- this can run against ANY device, not just
        the active one, from a background poll thread.

        Note: AVD name retrieval is SKIPPED here because it uses a slow telnet
        connection (5-30s per emulator). Use get_avd_name_for_device() lazily
        when the name is actually needed.

        Args:
            device: The device to populate info for
        """
        from .adb import Adb

        # Stamped unconditionally at entry (covers both the cooldown-gated
        # existing-device probe and the unconditional new-device probe) so a
        # failed probe is never retried before PROBE_RETRY_COOLDOWN_SECONDS.
        device.last_probe_attempt = time.monotonic()

        try:
            # Get Android version (fast ~95ms)
            version_info = Adb.get_android_version_and_api_level(serial=device.serial)
            if version_info:
                device.android_version = version_info.get("android_version", "")
                api_str = version_info.get("api_level", "0")
                device.api_level = int(api_str) if api_str else 0

            # For emulators, use serial as placeholder name
            # AVD name retrieval is INTENTIONALLY SKIPPED - it's 5-30s blocker!
            # The slow telnet call (adb emu avd name) will be made lazily via
            # get_avd_name_for_device() only when user actually needs the name
            if device.is_emulator and not device.name:
                # Use a friendly format of the serial as placeholder
                device.name = device.serial  # e.g., "emulator-5554"

            # For physical devices, check root capability (fast)
            if device.is_physical:
                self._check_root_capability(device)

        except Exception as e:
            logger.debug(f"Failed to populate device info for {device.serial}: {e}")

    def get_avd_name_for_device(self, device: Device) -> str:
        """Get AVD name for an emulator device, fetching lazily if needed.

        This method should be used when the actual AVD name is needed (e.g., for
        display in device selection UI). It makes the slow telnet call only once
        per device and caches the result.

        Args:
            device: The emulator device to get AVD name for

        Returns:
            The AVD name if available, otherwise the serial number
        """
        from .adb import Adb

        # Only fetch for emulators that haven't had their AVD name fetched yet
        if device.is_emulator and not getattr(device, "_avd_name_fetched", False):
            try:
                # Fast path: the emulator exports its AVD name as a system
                # property (API 31+: ro.boot.qemu.avd_name, older images:
                # ro.kernel.qemu.avd_name) -- one adb round-trip instead of
                # the 5-30 s telnet console call below.
                avd_name = None
                for prop in ("ro.boot.qemu.avd_name", "ro.kernel.qemu.avd_name"):
                    out, _err = Adb.send_adb_command(
                        f"shell getprop {prop}", serial=device.serial
                    )
                    avd_name = (out or "").strip() or None
                    if avd_name:
                        break
                if not avd_name:
                    avd_name = Adb.get_current_avd_name(serial=device.serial)
                if avd_name:
                    device.name = avd_name
                    device._avd_name_fetched = True
                    logger.debug(f"Fetched AVD name for {device.serial}: {avd_name}")
            except Exception as e:
                logger.debug(f"Could not fetch AVD name for {device.serial}: {e}")

        return device.name

    def _check_root_capability(self, device: Device) -> None:
        """Check if a physical device has root access.

        Args:
            device: The device to check
        """
        from .adb import Adb

        try:
            stdout, _stderr = Adb.send_adb_command(
                "shell su -c id", serial=device.serial
            )
            if stdout and "uid=0" in stdout:
                device.add_capability(DeviceCapability.ADB_ROOT)
                logger.debug(f"Device {device.serial} has root access")
        except Exception:
            pass

    def get_device(self, serial: str) -> Device | None:
        """Get a device by serial number.

        Args:
            serial: The device serial number

        Returns:
            Device if found, None otherwise
        """
        return self._devices.get(serial)

    def get_devices(self) -> list[Device]:
        """Get all connected devices.

        Returns:
            List of all Device objects
        """
        return list(self._devices.values())

    def get_emulators(self) -> list[Device]:
        """Get all connected emulators.

        Returns:
            List of emulator Device objects
        """
        return [d for d in self._devices.values() if d.is_emulator]

    def get_physical_devices(self) -> list[Device]:
        """Get all connected physical devices.

        Returns:
            List of physical Device objects
        """
        return [d for d in self._devices.values() if d.is_physical]

    @property
    def active_device(self) -> Device | None:
        """Get the currently active device.

        Returns:
            The active Device or None
        """
        return self._active_device

    @property
    def device_count(self) -> int:
        """Get the number of connected devices.

        Returns:
            Number of devices
        """
        return len(self._devices)

    def set_active_device(self, serial: str) -> bool:
        """Set the active device by serial number.

        This will reset all device-specific state (spotlight app, running tasks)
        when switching to a different device.

        Args:
            serial: Serial number of the device to activate

        Returns:
            True if successful, False otherwise
        """
        from .adb import Adb

        device = self._devices.get(serial)
        if not device:
            logger.error(f"Device {serial} not found")
            return False

        if device.state != "device":
            logger.error(f"Device {serial} is not ready (state: {device.state})")
            return False

        # Reset state if switching to a different device
        if self._active_device and self._active_device.serial != serial:
            self._reset_device_state()

        self._active_device = device

        # Configure ADB to target this device
        Adb.set_target_device(serial)

        # Update FridaManager to target this device for status checks and operations
        try:
            from .toolbox import Toolbox

            Toolbox.update_frida_device_serial(serial)
        except Exception as e:
            logger.debug(f"Could not update Frida device serial: {e}")

        # Fetch AVD name for emulators (replaces product name with user-given name)
        if device.is_emulator:
            self.get_avd_name_for_device(device)
        self._sync_session_device_name(device)

        # Switch to device-specific results folder
        try:
            from .toolbox import Toolbox

            Toolbox.switch_device_folder(device.short_name)
        except Exception as e:
            logger.debug(f"Could not switch device folder: {e}")

        logger.info(f"Switched to device: {device.display_name}")

        # Notify listeners
        for callback in self._on_device_change_callbacks:
            try:
                callback(device)
            except Exception as e:
                logger.warning(f"Device change callback failed: {e}")

        return True

    @staticmethod
    def _sync_session_device_name(device: Device) -> None:
        """Record the connected device's real name for runs and reports.

        ``Toolbox.device_name`` used to stay at config ``emulator.device_name``
        (default ``Pixel_6_Pro_API_31``) whatever was connected, so run.json /
        sandroid.json / reports named the wrong device and the snapshot-path
        check looked in the wrong AVD folder.
        """
        global _active_device_name, _configured_device_name
        name = resolve_device_name(device)
        if not name:
            return
        try:
            from sandroid.services import get_session_state_service

            state = get_session_state_service()
            if _active_device_name is None:
                _configured_device_name = state.device_name
            _active_device_name = name
            state.device_name = name
        except Exception as e:
            logger.debug(f"Could not record device name {name!r}: {e}")

    def _reset_device_state(self) -> None:
        """Reset all device-specific state when switching devices.

        This clears:
        - Spotlight application
        - Running background tasks
        - Cached file information
        """
        try:
            from sandroid.services import get_spotlight_service, get_task_service

            from .toolbox import Toolbox

            # Stop all background tasks
            get_task_service().stop_all()

            # Reset spotlight application
            get_spotlight_service().reset()

            # Clear caches
            Toolbox.changed_files_cache = {}
            Toolbox._timestamps_shadow_dict_list = []

            logger.info("Device state has been reset")

        except Exception as e:
            logger.error(f"Failed to reset device state: {e}")

    def check_capability(self, capability: DeviceCapability) -> bool:
        """Check if the active device has a specific capability.

        Args:
            capability: The capability to check

        Returns:
            True if active device has the capability, False otherwise
        """
        if not self._active_device:
            return False
        return self._active_device.has_capability(capability)

    def is_emulator(self) -> bool:
        """Check if the active device is an emulator.

        Returns:
            True if active device is an emulator, False if physical or no device
        """
        if not self._active_device:
            return False
        return self._active_device.is_emulator

    def is_physical_device(self) -> bool:
        """Check if the active device is a physical device.

        Returns:
            True if active device is a physical device, False if emulator or no device
        """
        if not self._active_device:
            return False
        return self._active_device.is_physical

    def require_capability(
        self, capability: DeviceCapability, action_name: str
    ) -> bool:
        """Check capability and log warning if missing.

        Args:
            capability: The required capability
            action_name: Name of the action requiring this capability

        Returns:
            True if capability is available, False otherwise
        """
        if not self.check_capability(capability):
            if self._active_device:
                logger.warning(
                    f"Action '{action_name}' requires {capability.name} "
                    f"which is not available on {self._active_device.display_name}"
                )
            else:
                logger.warning(f"No active device for action '{action_name}'")
            return False
        return True

    def on_device_change(self, callback: Callable[[Device], None]) -> None:
        """Register a callback for device change events.

        The callback will be called with the new Device when the active device changes.

        Args:
            callback: Function to call with the new Device
        """
        self._on_device_change_callbacks.append(callback)

    def on_devices_updated(self, callback: Callable[[list[Device]], None]) -> None:
        """Register a callback for device list updates.

        The callback will be called with the list of all devices when the device
        list is refreshed.

        Args:
            callback: Function to call with the device list
        """
        self._on_devices_updated_callbacks.append(callback)

    def auto_select_device(self) -> Device | None:
        """Automatically select a device, preferring emulators over physical devices.

        Selection priority:
        1. If only one device is connected, select it
        2. If multiple devices, prefer emulators (they have root access by default)
        3. If multiple emulators, select the first one
        4. If only physical devices, don't auto-select (user should choose)

        Returns:
            The selected Device, or None if no suitable device found
        """
        devices = self.get_devices()

        if len(devices) == 0:
            logger.warning("No devices connected")
            return None

        # Filter to only devices in ready state
        ready_devices = [d for d in devices if d.state == "device"]

        # An explicitly requested serial (--serial / config / ANDROID_SERIAL)
        # wins; never silently fall back to a different device.
        wanted = self.preferred_serial()
        if wanted:
            match = next((d for d in ready_devices if d.serial == wanted), None)
            if match is None:
                state = self._devices[wanted].state if wanted in self._devices else None
                logger.warning(
                    f"Requested device {wanted} is not ready"
                    + (f" (state: {state})" if state else " (not connected)")
                )
                return None
            self.set_active_device(match.serial)
            return match

        if len(ready_devices) == 0:
            logger.warning("No devices in ready state")
            return None

        if len(ready_devices) == 1:
            self.set_active_device(ready_devices[0].serial)
            return ready_devices[0]

        # Multiple devices connected - prefer emulators
        emulators = [d for d in ready_devices if d.is_emulator]
        physical = [d for d in ready_devices if d.is_physical]

        if emulators:
            # Select first emulator (they have root by default, better for Sandroid)
            selected = emulators[0]
            logger.info(
                f"Multiple devices connected ({len(ready_devices)}). "
                f"Auto-selecting emulator: {selected.display_name}"
            )
            if physical:
                logger.info(
                    f"Physical device(s) also connected: "
                    f"{', '.join(d.short_name for d in physical)}. "
                    "Use device selector to switch if needed."
                )
            self.set_active_device(selected.serial)
            return selected

        # Only physical devices - don't auto-select, user should choose
        logger.info(
            f"Multiple physical devices connected ({len(physical)}). "
            "Use device selector to choose one. "
            "Note: Physical devices require root access for full Sandroid functionality."
        )

        return None

    def has_devices(self) -> bool:
        """Check if any devices are connected.

        Returns:
            True if at least one device is connected
        """
        return len(self._devices) > 0

    def has_active_device(self) -> bool:
        """Check if an active device is selected.

        Returns:
            True if an active device is selected
        """
        return self._active_device is not None

    def verify_active_device(self) -> bool:
        """Verify the active device is still connected and responsive.

        This method should be called when ADB commands fail to check if the
        device was disconnected. It refreshes the device list and returns
        whether the active device is still available.

        Returns:
            True if active device is still connected, False if disconnected
        """
        if not self._active_device:
            return False

        old_serial = self._active_device.serial
        self.refresh_devices()

        # Check if the device is still connected
        if self._active_device and self._active_device.serial == old_serial:
            return True

        logger.warning(f"Active device {old_serial} is no longer available")
        return False

    def handle_device_error(self, error: Exception) -> bool:
        """Handle an ADB error that might indicate device disconnection.

        Call this when an ADB command fails unexpectedly. It will check if
        the device is still connected and attempt to recover.

        Args:
            error: The exception that occurred

        Returns:
            True if the device is still available, False if it was disconnected
        """
        error_str = str(error).lower()

        # Check for common disconnection error patterns
        disconnect_patterns = [
            "device not found",
            "device offline",
            "no devices",
            "connection refused",
            "closed",
            "broken pipe",
            "transport",
        ]

        is_disconnect = any(pattern in error_str for pattern in disconnect_patterns)

        if is_disconnect:
            logger.warning(f"Device may have disconnected: {error}")
            return self.verify_active_device()

        # Not a disconnection error, device is probably still connected
        return self.has_active_device()

    def ensure_device_selected(self) -> bool:
        """Ensure a device is selected, refreshing if necessary.

        This is useful for recovery scenarios where the device list might
        have changed. It will refresh devices and auto-select if possible.

        Returns:
            True if a device is now selected, False otherwise
        """
        if self._active_device:
            return True

        # Try to refresh and auto-select
        self.refresh_devices()
        return self._active_device is not None
