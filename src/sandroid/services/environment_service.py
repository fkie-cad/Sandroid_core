"""Environment Service for Sandroid.

This service manages environment validation, binary availability checks,
and host network configuration detection.

Extracted from Toolbox class to follow Single Responsibility Principle.

Usage:
    from sandroid.services import get_environment_service
    from sandroid.services.environment_service import EnvironmentService

    # Get service
    env = get_environment_service()

    # Check setup (returns result, no sys.exit)
    result = env.check_setup()
    if not result.success:
        print(f"Setup failed: {result.message}")

    # Check individual components
    if env.is_sqldiff_available():
        # SQLite diffing available
        pass

    # Get host IP for proxy configuration
    host_ip = env.get_host_ip()
"""

import logging
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)


@dataclass
class SetupResult:
    """Result of environment setup validation.

    Attributes:
        success: Whether setup validation passed
        message: Human-readable status message
        adb_available: Whether ADB connection works
        root_available: Whether ADB root access is available
        selinux_permissive: Whether SELinux is in permissive mode
        sqldiff_available: Whether sqldiff binary is available
        objection_available: Whether objection binary is available
        device_serial: Connected device serial if available
        errors: List of error messages
        warnings: List of warning messages
    """

    success: bool = True
    message: str = ""
    adb_available: bool = False
    root_available: bool = False
    selinux_permissive: bool = False
    sqldiff_available: bool = False
    objection_available: bool = False
    device_serial: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=datetime.now)


class AdbProtocol(Protocol):
    """Protocol for ADB dependency injection."""

    @staticmethod
    def send_adb_command(command: str) -> tuple[str, str]:
        """Send an ADB command and return (stdout, stderr)."""
        ...


class EmulatorProtocol(Protocol):
    """Protocol for Emulator dependency injection."""

    @staticmethod
    def list_available_avds() -> list[str]:
        """List available Android Virtual Devices."""
        ...

    @staticmethod
    def start_avd(avd_name: str) -> bool:
        """Start an Android Virtual Device."""
        ...


class EnvironmentService:
    """Service for environment validation and configuration.

    This service manages:
    - ADB connection validation
    - Root access checking
    - SELinux permissive mode verification
    - Binary availability (sqldiff, objection)
    - Host IP detection for proxy configuration

    Thread Safety:
        This service is thread-safe. All methods can be called from any thread.

    Attributes:
        adb: ADB interface (injected or uses global Adb)
        emulator: Emulator interface (injected or uses global Emulator)
        event_bus: Optional event bus for publishing state changes

    Example:
        # Basic usage
        env = EnvironmentService()
        result = env.check_setup()
        if not result.success:
            raise InitializationError(result.message)

        # With dependency injection (testing)
        mock_adb = Mock()
        mock_adb.send_adb_command.return_value = ("", "")
        env = EnvironmentService(adb=mock_adb)
    """

    def __init__(
        self,
        adb: AdbProtocol | None = None,
        emulator: EmulatorProtocol | None = None,
        event_bus: EventBusProtocol | None = None,
    ):
        """Initialize EnvironmentService.

        Args:
            adb: ADB interface for device communication.
                 If None, uses global Adb class.
            emulator: Emulator interface for AVD management.
                      If None, uses global Emulator class.
            event_bus: Optional event bus for state change notifications.
        """
        self._adb = adb
        self._emulator = emulator
        self._event_bus = event_bus
        self._logger = logger
        self._last_result: SetupResult | None = None

    def _get_adb(self) -> AdbProtocol:
        """Get ADB interface, falling back to global if not injected."""
        if self._adb is not None:
            return self._adb
        from sandroid.core.adb import Adb

        return Adb

    def _get_emulator(self) -> EmulatorProtocol:
        """Get Emulator interface, falling back to global if not injected."""
        if self._emulator is not None:
            return self._emulator
        from sandroid.core.emulator import Emulator

        return Emulator

    def check_setup(self, auto_start_emulator: bool = False) -> SetupResult:
        """Validate the environment setup.

        Checks ADB connection, root access, SELinux mode, and binary availability.
        Unlike the legacy Toolbox.check_setup(), this method returns a result
        object instead of calling sys.exit().

        Args:
            auto_start_emulator: If True and no device found, attempt to start
                                 an available emulator automatically.

        Returns:
            SetupResult with validation details.
        """
        result = SetupResult()
        adb = self._get_adb()

        # Check ADB connection
        stdout, stderr = adb.send_adb_command("shell ls /data")

        if "not found" in stderr:
            result.success = False
            result.adb_available = False
            result.message = "ADB not found in PATH"
            result.errors.append("Could not find adb command")
            self._last_result = result
            return result

        if "no devices/emulators found" in stderr:
            result.adb_available = True  # ADB exists but no device
            result.message = (
                "No devices/emulators connected. "
                "Connect a device via USB or start an AVD with: sandroid-config avd start"
            )

            if auto_start_emulator:
                emulator = self._get_emulator()
                available = emulator.list_available_avds()
                if available:
                    result.warnings.append(
                        f"Found {len(available)} available emulators: {available}"
                    )
                else:
                    result.success = False
                    result.errors.append("No available emulators found")
            else:
                result.success = False

            self._last_result = result
            return result

        result.adb_available = True

        # Handle permission denied
        if "Permission denied" in stderr:
            result.warnings.append("Permission denied, attempting adb root")
            adb.send_adb_command("root")
            time.sleep(2)

        # Check root access
        stdout, stderr = adb.send_adb_command("root")
        if "adbd cannot run as root" in stderr:
            result.root_available = False
            result.success = False
            result.message = "Device does not support adb root"
            result.errors.append(
                "Device does not support adb root. Please ensure the device is rooted."
            )
            self._last_result = result
            return result

        result.root_available = True
        self._logger.info("adb root enabled successfully")

        # Check SELinux permissive mode
        stdout, stderr = adb.send_adb_command("shell setenforce 0")
        if stderr:
            result.selinux_permissive = False
            result.warnings.append(
                f"Failed to set SELinux permissive: {stderr.strip()}"
            )
            self._logger.warning(f"Failed to set SELinux to permissive mode: {stderr}")
        else:
            result.selinux_permissive = True
            self._logger.info("SELinux set to permissive mode")

        # Check optional binaries
        result.sqldiff_available = self.is_sqldiff_available()
        result.objection_available = self.is_objection_available()

        if not result.sqldiff_available:
            result.warnings.append("sqldiff not found - database comparison limited")
        if not result.objection_available:
            result.warnings.append(
                "objection not found - interactive exploration limited"
            )

        # Get device serial if available
        stdout, stderr = adb.send_adb_command("get-serialno")
        if stdout and not stderr:
            result.device_serial = stdout.strip()

        result.success = True
        result.message = "Environment setup validated successfully"
        self._last_result = result

        # Publish event if bus available
        self._publish_setup_completed(result)

        return result

    def validate_adb_connection(self) -> bool:
        """Check if ADB can connect to a device.

        Returns:
            True if ADB connection works.
        """
        adb = self._get_adb()
        stdout, stderr = adb.send_adb_command("shell echo test")
        return "test" in stdout and "error" not in stderr.lower()

    def check_root_access(self) -> bool:
        """Check if ADB root access is available.

        Returns:
            True if device supports adb root.
        """
        adb = self._get_adb()
        _stdout, stderr = adb.send_adb_command("root")
        return "cannot run as root" not in stderr

    def check_selinux_permissive(self) -> bool:
        """Attempt to set SELinux to permissive mode.

        Returns:
            True if SELinux was set to permissive successfully.
        """
        adb = self._get_adb()
        _stdout, stderr = adb.send_adb_command("shell setenforce 0")
        return not stderr

    def is_sqldiff_available(self) -> bool:
        """Check if the sqldiff binary is available in PATH.

        sqldiff is used for comparing SQLite databases.

        Returns:
            True if sqldiff is available.
        """
        available = shutil.which("sqldiff") is not None
        if not available:
            self._logger.debug("sqldiff binary not found - database comparison limited")
        return available

    def is_objection_available(self) -> bool:
        """Check if the objection tool is available in PATH.

        objection is used for interactive mobile app exploration via Frida.

        Returns:
            True if objection is available.
        """
        available = shutil.which("objection") is not None
        if not available:
            self._logger.debug(
                "objection tool not found - install with 'pip install objection'"
            )
        return available

    def get_host_ip(self) -> str:
        """Get the host machine's IP address (delegated to SetupService).

        Returns the IP that's likely accessible from the Android device.

        Returns:
            Host IP address string.
        """
        from sandroid.services import get_setup_service

        return get_setup_service().get_host_ip()

    def get_available_emulators(self) -> list[str]:
        """Get list of available Android Virtual Devices.

        Returns:
            List of AVD names.
        """
        emulator = self._get_emulator()
        return emulator.list_available_avds()

    def start_emulator(self, avd_name: str) -> bool:
        """Start an Android Virtual Device.

        Args:
            avd_name: Name of the AVD to start.

        Returns:
            True if emulator started successfully.
        """
        emulator = self._get_emulator()
        result = emulator.start_avd(avd_name)
        if result:
            self._logger.info(f"Emulator '{avd_name}' started successfully")
        else:
            self._logger.error(f"Failed to start emulator '{avd_name}'")
        return result

    def get_last_result(self) -> SetupResult | None:
        """Get the result of the last check_setup() call.

        Returns:
            Last SetupResult or None if never checked.
        """
        return self._last_result

    def get_status_dict(self) -> dict[str, Any]:
        """Get current environment status as a dictionary.

        Useful for API responses and debugging.

        Returns:
            Dictionary with environment status.
        """
        result = self._last_result
        return {
            "checked": result is not None,
            "success": result.success if result else None,
            "adb_available": result.adb_available if result else None,
            "root_available": result.root_available if result else None,
            "selinux_permissive": result.selinux_permissive if result else None,
            "sqldiff_available": self.is_sqldiff_available(),
            "objection_available": self.is_objection_available(),
            "device_serial": result.device_serial if result else None,
            "host_ip": self.get_host_ip(),
            "errors": result.errors if result else [],
            "warnings": result.warnings if result else [],
        }

    def reset(self) -> None:
        """Reset service state.

        Clears cached results. Useful for testing.
        """
        self._last_result = None

    def _publish_setup_completed(self, result: SetupResult) -> None:
        """Publish event when setup check completes."""
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={
                    "component": "environment",
                    "success": result.success,
                    "device_serial": result.device_serial,
                    "warnings_count": len(result.warnings),
                    "errors_count": len(result.errors),
                },
                source="environment_service",
            )
        )


__all__ = ["EnvironmentService", "SetupResult"]
