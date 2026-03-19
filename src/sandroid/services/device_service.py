"""Device Service for Sandroid.

This service manages device-related state and configuration, including
device name, emulator path, and the device manager reference.

Extracted from Toolbox class to follow Single Responsibility Principle.

Usage:
    from sandroid.services import get_device_service
    from sandroid.services.device_service import DeviceService

    # Using service locator
    device_service = get_device_service()

    # Or with dependency injection
    device_service = DeviceService(event_bus=EventBus.get())

    # Get device info
    name = device_service.get_device_name()
    path = device_service.get_emulator_path()

    # Check device type
    if device_service.is_emulator_device():
        print("Running on emulator")
"""

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional, Protocol

from sandroid.services.protocols import EventBusProtocol

if TYPE_CHECKING:
    from sandroid.core.device_manager import Device, DeviceCapability

logger = logging.getLogger(__name__)


@dataclass
class DeviceState:
    """Represents the current device configuration state.

    Attributes:
        device_name: Name of the Android device/emulator (e.g., "Pixel_6_Pro_API_31")
        android_emulator_path: Path to the Android emulator executable
        updated_at: When the device state was last updated
    """

    device_name: str = "Pixel_6_Pro_API_31"
    android_emulator_path: str = ""
    updated_at: datetime = field(default_factory=datetime.now)


class DeviceManagerProtocol(Protocol):
    """Protocol for DeviceManager dependency injection."""

    @property
    def active_device(self) -> Optional["Device"]:
        """Get the currently active device."""
        ...

    def refresh_devices(self) -> None:
        """Refresh the list of available devices."""
        ...

    def on_device_change(self, callback: Callable[[Optional["Device"]], None]) -> None:
        """Register a callback for device change events."""
        ...

    def check_capability(self, capability: "DeviceCapability") -> bool:
        """Check if the active device has a specific capability."""
        ...


class DeviceService:
    """Service for managing device-related state and configuration.

    This service handles:
    - Device name configuration
    - Android emulator path management
    - Device manager reference and initialization
    - Device type checking (emulator vs physical)

    Thread Safety:
        Basic get/set operations are thread-safe.

    Example:
        service = DeviceService()

        # Get device configuration
        name = service.get_device_name()
        path = service.get_emulator_path()

        # Check device type
        if service.is_emulator_device():
            # Running on emulator
            pass
        elif service.is_physical_device():
            # Running on physical device
            pass

        # Update device name
        service.set_device_name("Pixel_8_Pro_API_34")
    """

    def __init__(self, event_bus: EventBusProtocol | None = None):
        """Initialize the DeviceService.

        Args:
            event_bus: Optional EventBus for publishing state change events.
        """
        self._state = DeviceState()
        self._device_manager: DeviceManagerProtocol | None = None
        self._event_bus = event_bus
        self._logger = logger
        self._on_device_change_callback: Callable[[Device | None], None] | None = None

    # =========================================================================
    # Device Name
    # =========================================================================

    def get_device_name(self) -> str:
        """Get the current device name.

        Returns:
            The device name string (e.g., "Pixel_6_Pro_API_31")
        """
        return self._state.device_name

    def set_device_name(self, device_name: str) -> None:
        """Set the device name.

        Args:
            device_name: The new device name
        """
        previous = self._state.device_name
        self._state.device_name = device_name
        self._state.updated_at = datetime.now()

        self._logger.info(f"Set device name: {device_name}")

        self._publish_state_changed(
            change_type="device_name",
            previous_value=previous,
            new_value=device_name,
        )

    # =========================================================================
    # Android Emulator Path
    # =========================================================================

    def get_emulator_path(self) -> str:
        """Get the Android emulator executable path.

        Returns:
            The path to the Android emulator (may include ~)
        """
        return self._state.android_emulator_path

    def get_expanded_emulator_path(self) -> str:
        """Get the expanded Android emulator executable path.

        Returns:
            The fully expanded path to the Android emulator
        """
        if self._state.android_emulator_path:
            return os.path.expanduser(self._state.android_emulator_path)
        return ""

    def set_emulator_path(self, path: str) -> None:
        """Set the Android emulator executable path.

        Args:
            path: Path to the Android emulator executable
        """
        previous = self._state.android_emulator_path
        self._state.android_emulator_path = path
        self._state.updated_at = datetime.now()

        self._logger.info(f"Set emulator path: {path}")

        self._publish_state_changed(
            change_type="emulator_path",
            previous_value=previous,
            new_value=path,
        )

    # =========================================================================
    # Device Manager
    # =========================================================================

    def get_device_manager(self) -> "DeviceManagerProtocol":
        """Get the device manager instance.

        On first access, automatically refreshes devices and auto-selects
        if only one device is connected.

        Returns:
            The DeviceManager instance
        """
        if self._device_manager is None:
            from sandroid.core.device_manager import DeviceManager

            self._device_manager = DeviceManager.get()

            # Register callback for device changes if provided
            if self._on_device_change_callback:
                self._device_manager.on_device_change(self._on_device_change_callback)

            # Auto-refresh devices on first access
            self._device_manager.refresh_devices()

        return self._device_manager

    def set_device_manager(self, device_manager: DeviceManagerProtocol) -> None:
        """Set the device manager instance (primarily for testing).

        Args:
            device_manager: The DeviceManager instance to use
        """
        self._device_manager = device_manager
        self._logger.info("Device manager set manually")

    def has_device_manager(self) -> bool:
        """Check if a device manager has been initialized.

        Returns:
            True if the device manager has been created
        """
        return self._device_manager is not None

    def register_device_change_callback(
        self, callback: Callable[[Optional["Device"]], None]
    ) -> None:
        """Register a callback for device change events.

        The callback will be invoked whenever the active device changes.

        Args:
            callback: Function to call with the new device (or None)
        """
        self._on_device_change_callback = callback

        # If device manager already exists, register immediately
        if self._device_manager is not None:
            self._device_manager.on_device_change(callback)

    # =========================================================================
    # Active Device
    # =========================================================================

    def get_active_device(self) -> Optional["Device"]:
        """Get the currently active device.

        Returns:
            The active Device or None if no device selected
        """
        return self.get_device_manager().active_device

    def check_capability(self, capability: "DeviceCapability") -> bool:
        """Check if the active device has a specific capability.

        Args:
            capability: The DeviceCapability to check

        Returns:
            True if the capability is available
        """
        return self.get_device_manager().check_capability(capability)

    # =========================================================================
    # Device Type Checking
    # =========================================================================

    def is_emulator_device(self) -> bool:
        """Check if the active device is an emulator.

        Returns:
            True if emulator, False if physical or no device
        """
        device = self.get_active_device()
        return device.is_emulator if device else False

    def is_physical_device(self) -> bool:
        """Check if the active device is a physical device.

        Returns:
            True if physical device, False if emulator or no device
        """
        device = self.get_active_device()
        return device.is_physical if device else False

    def has_active_device(self) -> bool:
        """Check if there is an active device.

        Returns:
            True if a device is selected
        """
        return self.get_active_device() is not None

    # =========================================================================
    # Reset
    # =========================================================================

    def reset(self) -> None:
        """Reset all device state to defaults.

        Clears the device manager reference and resets configuration
        to default values.
        """
        previous_name = self._state.device_name
        previous_path = self._state.android_emulator_path

        self._state = DeviceState()
        self._device_manager = None
        self._on_device_change_callback = None

        self._logger.info("Reset device service state")

        self._publish_state_changed(
            change_type="reset",
            previous_value={
                "device_name": previous_name,
                "emulator_path": previous_path,
            },
            new_value={
                "device_name": self._state.device_name,
                "emulator_path": self._state.android_emulator_path,
            },
        )

    # =========================================================================
    # State Dictionary
    # =========================================================================

    def get_state_dict(self) -> dict[str, Any]:
        """Get the complete device state as a dictionary.

        Useful for serialization and debugging.

        Returns:
            Dictionary with all device state
        """
        device = self.get_active_device() if self._device_manager else None

        return {
            "device_name": self._state.device_name,
            "android_emulator_path": self._state.android_emulator_path,
            "expanded_emulator_path": self.get_expanded_emulator_path(),
            "has_device_manager": self._device_manager is not None,
            "has_active_device": device is not None,
            "active_device_serial": device.serial if device else None,
            "is_emulator": device.is_emulator if device else None,
            "is_physical": device.is_physical if device else None,
            "updated_at": self._state.updated_at.isoformat(),
        }

    # =========================================================================
    # Emulator Information
    # =========================================================================

    def get_emulator_info(self) -> dict[str, Any]:
        """Get comprehensive information about the connected emulator/device.

        Gathers device information including:
        - Emulator ID and path
        - Device time and locale
        - Android version and API level
        - Network interfaces
        - Available snapshots

        Returns:
            Dictionary containing emulator information with keys:
            - emulator_id: AVD name
            - emulator_path: Path to AVD configuration
            - device_time: Current device time
            - device_locale: Device locale setting
            - android_version: Android version string
            - api_level: Android API level
            - network_interfaces: List of (interface, ip) tuples
            - snapshots: List of snapshot dictionaries with 'tag' and 'date'
        """
        from sandroid.core.adb import Adb

        emulator_id = Adb.get_current_avd_name()
        emulator_path = Adb.get_current_avd_path()
        device_time = Adb.get_device_time()
        device_locale = Adb.get_device_locale()
        android_info = Adb.get_android_version_and_api_level()
        network_info = Adb.get_network_info()
        snapshots = Adb.get_avd_snapshots()

        return {
            "emulator_id": emulator_id,
            "emulator_path": emulator_path,
            "device_time": device_time,
            "device_locale": device_locale,
            "android_version": android_info.get("android_version", "Unknown"),
            "api_level": android_info.get("api_level", "Unknown"),
            "network_interfaces": network_info,
            "snapshots": snapshots,
        }

    def get_device_info(self) -> dict[str, Any]:
        """Get comprehensive device information, adapting to device type.

        Returns a unified dict with common fields for both emulator and
        physical devices, plus device-type-specific fields.

        Common fields: device_type, device_serial, device_time,
            device_locale, android_version, api_level, geo_location,
            network_interfaces
        Emulator-only: device_name (AVD name), device_path, snapshots
        Physical-only: device_name (model), device_brand, device_model

        Returns:
            Dictionary containing device information.
        """
        from sandroid.core.adb import Adb

        is_emulator = self.is_emulator_device()

        # Common fields
        device_time = Adb.get_device_time()
        device_locale = Adb.get_device_locale()
        android_info = Adb.get_android_version_and_api_level() or {}
        network_info = Adb.get_network_info()
        geo_location = Adb.get_geo_location()

        device = self.get_active_device()
        serial = device.serial if device else None

        info: dict[str, Any] = {
            "device_type": "emulator" if is_emulator else "physical",
            "device_serial": serial,
            "device_time": device_time,
            "device_locale": device_locale,
            "android_version": android_info.get("android_version", "Unknown"),
            "api_level": android_info.get("api_level", "Unknown"),
            "geo_location": geo_location,
            "network_interfaces": network_info,
            "is_emulator": is_emulator,
        }

        if is_emulator:
            info["device_name"] = Adb.get_current_avd_name()
            info["device_path"] = Adb.get_current_avd_path()
            info["snapshots"] = Adb.get_avd_snapshots()
        else:
            model = Adb.get_device_model()
            brand = Adb.get_device_brand()
            info["device_name"] = model or "Unknown"
            info["device_brand"] = brand
            info["device_model"] = model

        return info

    # =========================================================================
    # Event Publishing (Private)
    # =========================================================================

    def _publish_state_changed(
        self,
        change_type: str,
        previous_value: Any,
        new_value: Any,
    ) -> None:
        """Publish a state changed event."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={
                    "change_type": f"device_{change_type}",
                    "previous_value": previous_value,
                    "new_value": new_value,
                },
                source="device_service",
            )
        )


# Module-level singleton instance
_device_service: DeviceService | None = None


def get_device_service() -> DeviceService:
    """Get or create the DeviceService singleton.

    Returns:
        DeviceService instance
    """
    global _device_service
    if _device_service is None:
        from sandroid.core.events import EventBus

        _device_service = DeviceService(event_bus=EventBus.get())
    return _device_service


def reset_device_service() -> None:
    """Reset the DeviceService singleton (useful for testing).

    Clears the cached service instance.
    """
    global _device_service
    _device_service = None


__all__ = [
    "DeviceService",
    "DeviceState",
    "get_device_service",
    "reset_device_service",
]
