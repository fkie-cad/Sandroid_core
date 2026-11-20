"""Device manager for multi-device support.

This module provides the DeviceManager singleton that handles device enumeration,
selection, and switching with proper state management.
"""

import logging
import re
import threading
import time
from collections.abc import Callable

from . import device_prep
from .device import Device, DeviceCapability, parse_adb_devices

# The device-prepared hook API lives in ``core/device_prep.py``; re-exported
# here (``DeviceManager`` owns the attach/reconnect path that triggers it).
from .device_prep import (
    register_device_prepared_hook,
    unregister_device_prepared_hook,
)

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
        # Last serial made active; auto-select may return to it after a
        # disconnect even when other devices are online (never to another).
        self._last_active_serial: str | None = None
        self._ambiguous_serials: tuple[str, ...] = ()
        self._on_device_change_callbacks: list[Callable[[Device], None]] = []
        self._on_devices_updated_callbacks: list[Callable[[list[Device]], None]] = []
        self._on_device_prepared_callbacks: list[Callable[[Device, object], None]] = []
        # The active device is missing from `adb devices` while it is being
        # prepared (``adb root`` restarts adbd) since this monotonic time.
        self._prep_absent_since: float | None = None
        # The last enumeration failed: the next good one re-prepares.
        self._enum_bailed = False
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
                when the caller resolves the selection itself (startup
                check, Devices screen) before anything is silently selected.

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
        # The device-prepared step (core/device_prep.py) is consulted here,
        # never under the lock: whether it runs for the active serial and the
        # adb transport it last prepared.
        active_before = self._active_device
        prep_serial = active_before.serial if active_before else None
        prep_busy = bool(prep_serial and device_prep.is_preparing(prep_serial))
        prep_transport = (
            device_prep.prepared_transport(prep_serial) if prep_serial else None
        )
        # Set to the active serial when its adb transport changed (offline ->
        # device, a new transport_id, back after a failed enumeration): the
        # device-prepared step is requested after the lock is released.
        reprepare: str | None = None
        lost_serial: str | None = None

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
                self._enum_bailed = True
                # Returning from within `with` releases the lock correctly.
                return list(self._devices.values())

            new_devices: dict[str, Device] = {}
            # With an explicitly pinned serial (--serial / ANDROID_SERIAL) in a
            # shared multi-emulator lab, never probe other people's devices.
            pinned = self.preferred_serial()

            for entry in parse_adb_devices(output):
                serial = entry.serial
                state = entry.state
                model = entry.props.get("model", "")
                product = entry.props.get("product", "")
                device_name = entry.props.get("device", "")
                transport_id = entry.props.get("transport_id", "")

                # Check if device already exists
                if serial in self._devices:
                    device = self._devices[serial]
                    if (
                        serial == prep_serial
                        and device is self._active_device
                        and state == "device"
                        and (
                            device.state != "device"
                            or self._enum_bailed
                            or (
                                transport_id
                                and prep_transport is not None
                                and transport_id != prep_transport
                            )
                        )
                    ):
                        reprepare = serial
                    device.state = state
                    device.transport_id = transport_id
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
                        transport_id=transport_id,
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
            self._enum_bailed = False
            missing = (
                self._active_device is not None
                and self._active_device.serial not in new_devices
            )
            if missing and self._within_prep_grace(prep_busy, prep_serial):
                # Being prepared: ``adb root`` restarts adbd, so the device
                # drops out of `adb devices` for a moment. Not lost (yet).
                self._active_device.state = "offline"
                new_devices[self._active_device.serial] = self._active_device
                missing = False
            elif not missing:
                self._prep_absent_since = None
            if missing:
                logger.warning(
                    f"Active device {self._active_device.serial} disconnected"
                )
                lost_serial = self._active_device.serial
                self._active_device = None
                self._prep_absent_since = None
                try:
                    from .timeline import get_timeline

                    get_timeline().note_device_lost(lost_serial)
                except Exception:
                    logger.debug("timeline: device/lost failed", exc_info=True)
                # Keep the ADB target on the lost serial. A snapshot load
                # drops the device from `adb devices` for about a second;
                # clearing the target sent the calls in that window without
                # `-s`, so adb picked whatever other device was attached (or
                # failed with "more than one device"). `adb -s <gone-serial>`
                # fails fast with "device not found", which is what we want.
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
            # caller opted out, e.g. the startup check choosing among 2+).
            need_auto_select = (
                auto_select and not self._active_device and len(self._devices) > 0
            )

        # DEADLOCK AVOIDANCE: enumerate/mutate under the lock above, then
        # notify/auto-select OUTSIDE it. The app's registered change handler
        # calls Textual's blocking call_from_thread; if these callbacks fired
        # while holding the lock, a UI-thread refresh_devices() waiting on
        # the lock would deadlock the event loop.

        if lost_serial:
            device_prep.note_detached(lost_serial)
        elif reprepare and self._active_device is not None:
            device_prep.request_prepare(reprepare, "transport", manager=self)

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

    def _within_prep_grace(self, prep_busy: bool, serial: str | None) -> bool:
        """Lock held: the active serial is missing while being prepared, for
        at most :data:`device_prep.LOSS_GRACE_S` seconds.
        """
        if not prep_busy or self._active_device is None:
            return False
        if self._active_device.serial != serial:
            return False
        now = time.monotonic()
        if self._prep_absent_since is None:
            self._prep_absent_since = now
        return now - self._prep_absent_since < device_prep.LOSS_GRACE_S

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

            self._probe_root_kind(device)

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
        # Only fetch for emulators that haven't had their AVD name fetched yet
        if device.is_emulator and not getattr(device, "_avd_name_fetched", False):
            try:
                from .adb import Adb
                from .emulator import avd_name_of

                avd_name = avd_name_of(device.serial, Adb)
                if avd_name:
                    device.name = avd_name
                    device._avd_name_fetched = True
                    logger.debug(f"Fetched AVD name for {device.serial}: {avd_name}")
            except Exception as e:
                logger.debug(f"Could not fetch AVD name for {device.serial}: {e}")

        return device.name

    def _probe_root_kind(self, device: Device) -> None:
        """Set ``device.root_kind`` (and ``ADB_ROOT`` when root is usable).

        Emulators: adbd running as root (``id -u`` = 0) -> ``"adbd root"``;
        else a userdebug/eng build -> ``"adb root"``; else a working ``su``
        (Magisk on a user-build image) -> ``"su"``; else ``"none"``.
        Physical devices: a working ``su`` -> ``"su"``, else ``"none"``.

        Args:
            device: The device to probe (targeted via ``serial=``).
        """
        from .adb import Adb

        if not device.is_emulator:
            self._check_root_capability(device)
            return
        kind = "none"
        try:
            uid, _err = Adb.send_adb_command("shell id -u", serial=device.serial)
            if (uid or "").strip() == "0":
                kind = "adbd root"
            else:
                build, _err = Adb.send_adb_command(
                    "shell getprop ro.build.type", serial=device.serial
                )
                if (build or "").strip() in ("userdebug", "eng"):
                    kind = "adb root"
                elif self._su_works(device.serial):
                    kind = "su"
        except Exception:
            pass
        device.root_kind = kind
        if kind != "none":
            device.add_capability(DeviceCapability.ADB_ROOT)

    #: Seconds the ``su`` probe may take (a root manager may show a prompt).
    SU_PROBE_TIMEOUT = 5.0

    @classmethod
    def _su_works(cls, serial: str) -> bool:
        """True if ``su -c id`` gives uid 0 on *serial* (short timeout)."""
        from .adb import Adb

        try:
            stdout, _stderr = Adb.send_adb_command(
                "shell su -c id", serial=serial, timeout=cls.SU_PROBE_TIMEOUT
            )
        except Exception:
            return False
        return bool(stdout) and "uid=0" in stdout

    def _check_root_capability(self, device: Device) -> None:
        """Check if a physical device has root access (``su``).

        Args:
            device: The device to check
        """
        device.root_kind = "none"
        if self._su_works(device.serial):
            device.root_kind = "su"
            device.add_capability(DeviceCapability.ADB_ROOT)
            logger.debug(f"Device {device.serial} has root access")

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

        # A pin (--serial / ANDROID_SERIAL) follows the device the user
        # attaches: otherwise the new device is never probed (the pin rule
        # skips other serials), and reconnects would wait for the old one.
        pinned = self.preferred_serial()
        if pinned and pinned != serial:
            logger.info(f"Device pin moves from {pinned} to {serial}")
            DeviceManager.set_preferred_serial(serial)
        if (
            not device.android_version
            and time.monotonic() - device.last_probe_attempt
            >= PROBE_RETRY_COOLDOWN_SECONDS
        ):
            self._populate_device_info(device)  # never probed (pinned out)

        # Reset state if switching to a different device
        if self._active_device and self._active_device.serial != serial:
            previous = self._active_device.serial
            device_prep.note_detached(previous)
            self._reset_device_state(previous_serial=previous)

        self._active_device = device
        self._last_active_serial = serial

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

        # The session timeline of this device folder (opened or resumed; a
        # previous device's timeline stays open for its late lines).
        try:
            from .timeline import get_timeline

            get_timeline().bind(serial, device_name=device.display_name)
        except Exception as e:
            logger.debug(f"Could not bind the session timeline: {e}")

        # The device-prepared step (off-thread): boot check, device-clock
        # connect sample, adb root + SELinux Permissive, device_prepared
        # hooks, then the on_device_prepared listeners (Frida / app work).
        # While it is off (paths that never prepare devices) only the
        # device-clock connect sample runs, as before.
        if not device_prep.request_prepare(serial, "attach", manager=self):
            device_prep.connect_clock_only(serial)

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

    def _reset_device_state(self, previous_serial: str | None = None) -> None:
        """Reset all device-specific state when switching devices.

        This clears:
        - The device proxy and app-proxy lanes Sandroid set on the previous
          device (released ON that device, explicitly by serial)
        - Spotlight application
        - Running background tasks
        - Cached file information
        """
        if previous_serial:
            from .adb import Adb

            # Pin to the old device: the global target may already point at
            # the new one.
            with Adb.targeting(previous_serial):
                self._release_proxies_on(previous_serial)
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

            # The identity profile state is per device: read it again.
            from sandroid.services.identity import get_identity_service

            get_identity_service().forget()

            logger.info("Device state has been reset")

        except Exception as e:
            logger.error(f"Failed to reset device state: {e}")

    @staticmethod
    def _release_proxies_on(serial: str) -> None:
        """Undo the proxy state Sandroid owns on *serial* (best effort).

        Without this a device switch left the old device pointed at our
        mitmproxy (and its per-app iptables lanes/gost running), and the later
        cleanup ran against the NEW device. Only already-created singletons
        are touched -- nothing is instantiated just to find nothing to do.
        """
        try:
            from sandroid.core import proxy_manager

            focus = proxy_manager._FOCUS_INSTANCE
            if focus is not None:
                released = focus.release_serial(serial)
                if released:
                    logger.info(f"Released {released} app-proxy lane(s) on {serial}")
        except Exception as e:
            logger.warning(f"Could not release app-proxy lanes on {serial}: {e}")
        try:
            from sandroid.services import mitmproxy_service

            service = mitmproxy_service._INSTANCE
            if service is not None and service.owned_device_proxy:
                service.release_device_proxy(serial=serial)
        except Exception as e:
            logger.warning(f"Could not release the device proxy on {serial}: {e}")

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

    def on_device_change(self, callback: Callable[[Device], None]) -> None:
        """Register a callback for device change events.

        The callback will be called with the new Device when the active device changes.

        Args:
            callback: Function to call with the new Device
        """
        self._on_device_change_callbacks.append(callback)

    def on_device_prepared(self, callback: Callable[[Device, object], None]) -> None:
        """Register a callback for "the active device is prepared".

        Called as ``callback(device, result)`` (``result``: a
        :class:`~sandroid.core.device_prep.PrepResult`) on the prepare
        worker thread, after root/SELinux and the ``device_prepared`` hooks
        -- the point from which Frida and app work may touch the device.
        Also fired after a run that failed (``result.kind == "failed"``:
        the work goes on, as before the step existed), once after a
        snapshot load that re-attached it (``"held"``), and for a run that
        found the device already prepared when the listeners have not seen
        that yet (``"unchanged"``, e.g. switched away and back); never for
        an aborted run. Marshal UI work to the UI thread.

        Args:
            callback: Function to call with the device and the result
        """
        self._on_device_prepared_callbacks.append(callback)

    def remove_device_prepared_listener(
        self, callback: Callable[[Device, object], None]
    ) -> bool:
        """Unregister an :meth:`on_device_prepared` callback.

        Returns:
            False when it was not registered.
        """
        try:
            self._on_device_prepared_callbacks.remove(callback)
        except ValueError:
            return False
        return True

    def _fire_device_prepared(self, device: Device | None, result: object) -> None:
        """Call the :meth:`on_device_prepared` listeners (never raises)."""
        for callback in list(self._on_device_prepared_callbacks):
            try:
                callback(device, result)
            except Exception as e:
                logger.warning(f"Device prepared callback failed: {e}")

    def on_devices_updated(self, callback: Callable[[list[Device]], None]) -> None:
        """Register a callback for device list updates.

        The callback will be called with the list of all devices when the device
        list is refreshed.

        Args:
            callback: Function to call with the device list
        """
        self._on_devices_updated_callbacks.append(callback)

    def auto_select_device(self) -> Device | None:
        """Automatically select a device -- only when the choice is unambiguous.

        Selection priority:
        1. An explicitly requested serial (``--serial`` / config /
           ``ANDROID_SERIAL``; it follows the device the user attaches), and
           never another device
        2. Once this session had a device: only that device, when it is
           back (reconnect after a snapshot load / emulator restart) --
           never another one, even if it is the only one ready
        3. Before that (first start): the only ready device
        4. Otherwise don't select: the user must choose (``--serial`` or the
           Devices screen). Picking "the first emulator" once prepared and
           hooked another session's emulator.

        Returns:
            The selected Device, or None if no suitable device found
        """
        devices = self.get_devices()

        if len(devices) == 0:
            logger.warning("No devices connected")
            return None

        # Filter to only devices in ready state. An emulator Sandroid itself
        # launched is "device" long before it has booted; it is attached when
        # its boot completes, not here.
        try:
            from .emulator import booting_serials

            booting = set(booting_serials())
        except Exception:
            booting = set()
        ready_devices = [
            d for d in devices if d.state == "device" and d.serial not in booting
        ]

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

        # Once the session had a device, only that device is taken back
        # (reconnect after a snapshot load / emulator restart / replug).
        # Moving the session to whatever else is online -- even the only
        # ready device -- is the user's call (the Devices screen opens).
        if self._last_active_serial is not None:
            previous = next(
                (d for d in ready_devices if d.serial == self._last_active_serial),
                None,
            )
            if previous is not None:
                logger.info(
                    f"Reconnected to the previous device: {previous.display_name}"
                )
                self.set_active_device(previous.serial)
                return previous
            logger.debug(
                f"Previous device {self._last_active_serial} is not back; not "
                "selecting another one"
            )
            return None

        if len(ready_devices) == 0:
            logger.warning("No devices in ready state")
            return None

        if len(ready_devices) == 1:
            self.set_active_device(ready_devices[0].serial)
            return ready_devices[0]

        serials = tuple(d.serial for d in ready_devices)
        # The device poll lands here every few seconds: say it once per set.
        log = logger.debug if serials == self._ambiguous_serials else logger.warning
        self._ambiguous_serials = serials
        log(
            f"More than one device is connected ({', '.join(serials)}); not "
            "selecting one. Choose one in Devices (D) or with --serial."
        )
        return None

    def has_active_device(self) -> bool:
        """Check if an active device is selected.

        Returns:
            True if an active device is selected
        """
        return self._active_device is not None
