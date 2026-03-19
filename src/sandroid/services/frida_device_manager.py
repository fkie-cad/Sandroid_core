"""Frida Device Manager for thread-safe device caching and lookup.

Extracted from FridaSessionService to consolidate duplicated device
lookup code and provide a single place for device caching logic.

Usage:
    manager = FridaDeviceManager()
    device = manager.get_device(serial)
    manager.invalidate_cache()
"""

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)


class FridaDeviceManager:
    """Thread-safe Frida device caching and lookup.

    Consolidates the duplicated device lookup pattern (get_device -> enumerate
    fallback) that previously existed in both _init_frida_device_on_main_thread()
    and _get_frida_device().

    Thread Safety:
        All cache operations are protected by an internal lock.
        Device initialization MUST happen on the main thread due to
        Frida's signal handler requirements.
    """

    def __init__(self, parent_logger: logging.Logger | None = None) -> None:
        self._lock = threading.Lock()
        self._cached_device: Any = None
        self._cached_serial: str | None = None
        self._logger = parent_logger or logger

    def invalidate_cache(self) -> None:
        """Invalidate the cached Frida device.

        Call this when the active device changes (e.g., via Shift+D in TUI).
        """
        with self._lock:
            self._cached_device = None
            self._cached_serial = None
            self._logger.debug("Invalidated Frida device cache")

    def lookup_device_by_serial(self, device_serial: str) -> Any:
        """Look up a Frida device by serial, with enumerate fallback.

        This consolidates the duplicated pattern that was in both
        _init_frida_device_on_main_thread and _get_frida_device.

        Args:
            device_serial: The device serial to find.

        Returns:
            Frida device object, or None if not found.
        """
        import frida

        try:
            return frida.get_device(device_serial)
        except frida.InvalidArgumentError:
            # Fallback: enumerate and find by ID
            for d in frida.enumerate_devices():
                if d.id == device_serial:
                    return d
            self._logger.warning(f"Frida device '{device_serial}' not found")
            return None

    def init_on_main_thread(self, device_serial: str) -> Any:
        """Initialize Frida device - MUST be called from main thread.

        Frida's Python bindings require main thread for signal handlers,
        thread-local state in C bindings, and USB/ADB communication.

        Args:
            device_serial: The device serial to connect to.

        Returns:
            Frida device object or None if initialization fails.
        """
        try:
            self._logger.debug(
                f"Initializing Frida device on main thread: {device_serial}"
            )
            device = self.lookup_device_by_serial(device_serial)
            if device is None:
                self._logger.error(f"Frida device '{device_serial}' not found")
                return None
            self._logger.debug(
                f"Frida device initialized: {device.name} ({device_serial})"
            )
            return device
        except Exception as e:
            self._logger.error(f"Failed to initialize Frida device: {e}")
            return None

    def get_cached_or_init(self, device_serial: str, app: Any = None) -> Any:
        """Get cached Frida device or initialize on main thread.

        IMPORTANT: For TUI mode, the device MUST be pre-initialized before the
        TUI event loop starts. If called from a worker thread without a cached
        device, returns None to avoid deadlock.

        Args:
            device_serial: The device serial.
            app: Ignored (kept for API compatibility).

        Returns:
            Cached Frida device, or None if not available.
        """
        with self._lock:
            # Return cached device if serial matches
            if self._cached_device is not None and self._cached_serial == device_serial:
                self._logger.debug(f"Using cached Frida device: {device_serial}")
                return self._cached_device

            # Need to initialize - check if we're on main thread
            if threading.current_thread() is threading.main_thread():
                self._logger.debug("Initializing Frida device directly (main thread)")
                self._cached_device = self.init_on_main_thread(device_serial)
                self._cached_serial = device_serial
                return self._cached_device
            self._logger.warning(
                "Frida device not pre-initialized. Cannot init from worker thread. "
                "FriTap may not work. Restart sandroid with a connected device."
            )
            return None

    def get_device_for_session(self) -> Any:
        """Get Frida device for session operations (spawn/attach).

        Tries DeviceManager for multi-device support, falls back to USB.

        Returns:
            Frida device object.

        Raises:
            frida.InvalidArgumentError: If device not found.
        """
        import frida

        # Try DeviceManager for multi-device support
        try:
            from sandroid.core.toolbox import Toolbox

            dm = Toolbox.get_device_manager()
            if dm and dm.active_device:
                device_serial = dm.active_device.serial
                device = self.lookup_device_by_serial(device_serial)
                if device is not None:
                    return device
                self._logger.warning(
                    f"Frida device '{device_serial}' not found, falling back to USB device"
                )
        except Exception:
            pass

        # Default fallback to USB device
        return frida.get_usb_device()


__all__ = ["FridaDeviceManager"]
