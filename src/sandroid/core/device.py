"""Device abstraction for multi-device support.

This module provides classes for representing Android devices (emulators and physical)
with automatic type detection and capability management.
"""

from dataclasses import dataclass, field
from enum import Enum, auto


class DeviceType(Enum):
    """Type of Android device."""

    EMULATOR = auto()
    PHYSICAL = auto()
    UNKNOWN = auto()


class DeviceCapability(Enum):
    """Capabilities available on a device.

    These are used to gate features that only work on certain device types.
    For example, snapshots only work on emulators.
    """

    SNAPSHOTS = auto()  # AVD snapshot save/load
    EMULATOR_CONTROLS = auto()  # Telnet commands, restart emulator
    NETWORK_CAPTURE = auto()  # Built-in emulator network capture
    FRIDA = auto()  # Frida instrumentation
    ADB_ROOT = auto()  # Can run as root via ADB
    FILE_SYSTEM_ACCESS = auto()  # Full filesystem access


@dataclass
class Device:
    """Represents a connected Android device.

    Attributes:
        serial: ADB serial number (e.g., "emulator-5554" or "XXXXXXXX")
        name: Human-readable name (e.g., "Pixel_6_Pro_API_31" or AVD name)
        device_type: Whether this is an emulator or physical device
        state: Current ADB state (device, offline, unauthorized)
        model: Device model name from ro.product.model
        android_version: Android version string
        api_level: Android API level
        capabilities: Set of available capabilities
    """

    serial: str
    name: str = ""
    device_type: DeviceType | None = None
    state: str = "device"
    model: str = ""
    android_version: str = ""
    api_level: int = 0
    capabilities: set[DeviceCapability] = field(default_factory=set)

    def __post_init__(self):
        """Detect device type and capabilities based on serial pattern."""
        if self.device_type is None:
            self.device_type = self._detect_type()
        if not self.capabilities:
            self.capabilities = self._get_default_capabilities()

    def _detect_type(self) -> DeviceType:
        """Detect device type from serial number pattern.

        Emulators use pattern: emulator-XXXX (e.g., emulator-5554)
        Physical devices use alphanumeric serials or IP:PORT
        """
        if self.serial.startswith("emulator-"):
            return DeviceType.EMULATOR
        return DeviceType.PHYSICAL

    def _get_default_capabilities(self) -> set[DeviceCapability]:
        """Get default capabilities based on device type."""
        common = {
            DeviceCapability.FRIDA,
            DeviceCapability.FILE_SYSTEM_ACCESS,
        }

        if self.device_type == DeviceType.EMULATOR:
            return common | {
                DeviceCapability.SNAPSHOTS,
                DeviceCapability.EMULATOR_CONTROLS,
                DeviceCapability.NETWORK_CAPTURE,
                DeviceCapability.ADB_ROOT,
            }
        # Physical devices have restricted capabilities
        return common

    @property
    def is_emulator(self) -> bool:
        """Check if this device is an emulator."""
        return self.device_type == DeviceType.EMULATOR

    @property
    def is_physical(self) -> bool:
        """Check if this device is a physical device."""
        return self.device_type == DeviceType.PHYSICAL

    def has_capability(self, capability: DeviceCapability) -> bool:
        """Check if device has a specific capability.

        Args:
            capability: The capability to check

        Returns:
            True if device has the capability
        """
        return capability in self.capabilities

    def add_capability(self, capability: DeviceCapability) -> None:
        """Add a capability to this device.

        Args:
            capability: The capability to add
        """
        self.capabilities.add(capability)

    def remove_capability(self, capability: DeviceCapability) -> None:
        """Remove a capability from this device.

        Args:
            capability: The capability to remove
        """
        self.capabilities.discard(capability)

    @property
    def display_name(self) -> str:
        """Get a human-readable display name for the device.

        Returns:
            String like "[E] Pixel_6_Pro_API_31" or "[P] Samsung Galaxy S21"
        """
        type_indicator = "[E]" if self.is_emulator else "[P]"
        name = self.name or self.model or self.serial
        return f"{type_indicator} {name}"

    @property
    def short_name(self) -> str:
        """Get a short name for status bar display.

        Returns:
            The device name, model, or truncated serial
        """
        return self.name or self.model or self.serial[:12]

    def __hash__(self) -> int:
        """Hash based on serial number."""
        return hash(self.serial)

    def __eq__(self, other) -> bool:
        """Compare devices by serial number."""
        if isinstance(other, Device):
            return self.serial == other.serial
        return False

    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"Device(serial={self.serial!r}, type={self.device_type.name}, name={self.name!r})"
