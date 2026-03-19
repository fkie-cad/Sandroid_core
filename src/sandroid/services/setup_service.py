"""Setup Service for Sandroid.

This service manages environment validation and setup requirements checking.
It extracts the setup validation logic from the monolithic Toolbox class.

Follows Single Responsibility Principle - only handles setup validation.
Supports Dependency Inversion - accepts Adb as a dependency for testing.

Usage:
    from sandroid.services import get_setup_service
    from sandroid.services.setup_service import SetupService, SetupResult

    # Get service (singleton)
    setup = get_setup_service()

    # Validate environment (returns result, no sys.exit)
    result = setup.check_setup()
    if not result.success:
        print(f"Setup failed: {result.message}")
        for error in result.errors:
            print(f"  - {error}")

    # Individual checks
    if setup.is_sqldiff_available():
        # SQLite diffing available
        pass

    if setup.validate_adb_connection():
        # ADB connected
        pass

    # Get host IP for proxy configuration
    host_ip = setup.get_host_ip()
"""

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from threading import Lock
from typing import Any, Protocol

from sandroid.services.protocols import EventBusProtocol

logger = logging.getLogger(__name__)


class SetupCheckStatus(Enum):
    """Status of an individual setup check."""

    NOT_CHECKED = auto()
    PASSED = auto()
    FAILED = auto()
    WARNING = auto()
    SKIPPED = auto()


@dataclass
class SetupCheckResult:
    """Result of a single setup check.

    Attributes:
        name: Check identifier (e.g., 'adb', 'root', 'selinux')
        display_name: Human-readable check name
        status: Check status (passed, failed, warning, etc.)
        message: Detailed message about the check result
        details: Additional details dictionary
    """

    name: str
    display_name: str
    status: SetupCheckStatus = SetupCheckStatus.NOT_CHECKED
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        """Check if this check passed."""
        return self.status == SetupCheckStatus.PASSED

    @property
    def failed(self) -> bool:
        """Check if this check failed."""
        return self.status == SetupCheckStatus.FAILED


@dataclass
class SetupResult:
    """Result of environment setup validation.

    This dataclass holds all validation results without calling sys.exit(),
    allowing the caller to decide how to handle failures.

    Attributes:
        success: Whether setup validation passed (all critical checks passed)
        message: Human-readable status message
        adb_available: Whether ADB command is available in PATH
        device_connected: Whether a device/emulator is connected
        root_available: Whether ADB root access is available
        selinux_permissive: Whether SELinux is in permissive mode
        sqldiff_available: Whether sqldiff binary is available
        objection_available: Whether objection binary is available
        frida_available: Whether frida is available
        device_serial: Connected device serial if available
        android_version: Android version if detected
        api_level: Android API level if detected
        errors: List of error messages (critical failures)
        warnings: List of warning messages (non-critical issues)
        checks: List of individual check results
        checked_at: Timestamp of the validation
    """

    success: bool = True
    message: str = ""
    adb_available: bool = False
    device_connected: bool = False
    root_available: bool = False
    selinux_permissive: bool = False
    sqldiff_available: bool = False
    objection_available: bool = False
    frida_available: bool = False
    device_serial: str | None = None
    android_version: str | None = None
    api_level: int | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks: list[SetupCheckResult] = field(default_factory=list)
    checked_at: datetime = field(default_factory=datetime.now)

    def get_check(self, name: str) -> SetupCheckResult | None:
        """Get a specific check result by name.

        Args:
            name: Check identifier

        Returns:
            SetupCheckResult or None if not found
        """
        for check in self.checks:
            if check.name == name:
                return check
        return None

    def add_error(self, message: str) -> None:
        """Add an error message.

        Args:
            message: Error message to add
        """
        if message not in self.errors:
            self.errors.append(message)

    def add_warning(self, message: str) -> None:
        """Add a warning message.

        Args:
            message: Warning message to add
        """
        if message not in self.warnings:
            self.warnings.append(message)

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary for serialization.

        Returns:
            Dictionary representation of the result
        """
        return {
            "success": self.success,
            "message": self.message,
            "adb_available": self.adb_available,
            "device_connected": self.device_connected,
            "root_available": self.root_available,
            "selinux_permissive": self.selinux_permissive,
            "sqldiff_available": self.sqldiff_available,
            "objection_available": self.objection_available,
            "frida_available": self.frida_available,
            "device_serial": self.device_serial,
            "android_version": self.android_version,
            "api_level": self.api_level,
            "errors": self.errors.copy(),
            "warnings": self.warnings.copy(),
            "checks": [
                {
                    "name": c.name,
                    "display_name": c.display_name,
                    "status": c.status.name,
                    "message": c.message,
                    "details": c.details,
                }
                for c in self.checks
            ],
            "checked_at": self.checked_at.isoformat(),
        }


class AdbProtocol(Protocol):
    """Protocol for ADB dependency injection.

    Defines the interface required for ADB operations.
    """

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


class SetupService:
    """Service for environment setup validation.

    This service validates that the environment is correctly configured
    for Sandroid operation, including ADB connection, root access,
    SELinux mode, and required binary availability.

    Unlike the legacy Toolbox.check_setup(), this service:
    - Returns results instead of calling sys.exit()
    - Supports dependency injection for testing
    - Provides individual check methods
    - Follows Single Responsibility Principle

    Thread Safety:
        This service is thread-safe. All state modifications use locks.

    Attributes:
        adb: ADB interface (injected or uses global Adb)
        emulator: Emulator interface (injected or uses global Emulator)
        event_bus: Optional event bus for publishing state changes

    Example:
        # Basic usage
        setup = SetupService()
        result = setup.check_setup()
        if not result.success:
            raise InitializationError(result.message)

        # With dependency injection (testing)
        mock_adb = Mock()
        mock_adb.send_adb_command.return_value = ("", "")
        setup = SetupService(adb=mock_adb)

        # Individual checks
        if setup.check_root_access():
            print("Root access available")
    """

    def __init__(
        self,
        adb: AdbProtocol | None = None,
        emulator: EmulatorProtocol | None = None,
        event_bus: EventBusProtocol | None = None,
    ):
        """Initialize SetupService.

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
        self._lock = Lock()

    def _get_adb(self) -> AdbProtocol:
        """Get ADB interface, falling back to global if not injected.

        Returns:
            ADB interface for sending commands.
        """
        if self._adb is not None:
            return self._adb
        from sandroid.core.adb import Adb

        return Adb

    def _get_emulator(self) -> EmulatorProtocol:
        """Get Emulator interface, falling back to global if not injected.

        Returns:
            Emulator interface for AVD management.
        """
        if self._emulator is not None:
            return self._emulator
        from sandroid.core.emulator import Emulator

        return Emulator

    # ==================== Full Setup Validation ====================

    def check_setup(
        self,
        auto_start_emulator: bool = False,
        enable_root: bool = True,
        set_selinux_permissive: bool = True,
    ) -> SetupResult:
        """Validate the environment setup.

        Performs all setup validation checks and returns a comprehensive result.
        Unlike Toolbox.check_setup(), this method returns a result object
        instead of calling sys.exit().

        Args:
            auto_start_emulator: If True and no device found, attempt to start
                                 an available emulator automatically.
            enable_root: If True, attempt to enable adb root.
            set_selinux_permissive: If True, attempt to set SELinux permissive.

        Returns:
            SetupResult with validation details.
        """
        with self._lock:
            result = self._run_critical_checks(
                enable_root=enable_root,
                set_selinux_permissive=set_selinux_permissive,
                auto_start_emulator=auto_start_emulator,
            )

            if not result.success:
                self._last_result = result
                return result

            adb = self._get_adb()

            # Non-critical tool checks
            self._run_tool_checks(result)

            # Get Android version info
            android_info = self._get_android_info(adb)
            result.android_version = android_info.get("version")
            result.api_level = android_info.get("api_level")

            # All critical checks passed
            result.message = "Environment setup validated successfully"
            self._last_result = result

            # Publish event
            self._publish_setup_completed(result)

            return result

    def check_critical_setup(
        self,
        enable_root: bool = True,
        set_selinux_permissive: bool = True,
    ) -> SetupResult:
        """Validate only critical setup requirements for fast startup.

        Performs only the blocking checks needed before showing UI:
        - ADB availability
        - Device connection
        - Root access
        - SELinux permissive

        Non-critical checks (sqldiff, objection, frida, android info) are
        deferred to check_deferred_setup() which can run in background.

        Args:
            enable_root: If True, attempt to enable adb root.
            set_selinux_permissive: If True, attempt to set SELinux permissive.

        Returns:
            SetupResult with critical validation details only.
        """
        with self._lock:
            result = self._run_critical_checks(
                enable_root=enable_root,
                set_selinux_permissive=set_selinux_permissive,
                auto_start_emulator=False,
            )

            if result.success:
                result.message = "Critical setup validated (tool checks deferred)"
                # Mark tool availability as not yet checked
                result.sqldiff_available = False
                result.objection_available = False
                result.frida_available = False

            self._last_result = result
            return result

    # ==================== Critical Checks (Stage Methods) ====================

    def _run_critical_checks(
        self,
        enable_root: bool,
        set_selinux_permissive: bool,
        auto_start_emulator: bool = False,
    ) -> SetupResult:
        """Run the critical (blocking) setup checks.

        Delegates each check to the setup_checks module and orchestrates
        the overall flow with early returns on critical failures.

        Args:
            enable_root: If True, attempt to enable adb root.
            set_selinux_permissive: If True, attempt to set SELinux permissive.
            auto_start_emulator: If True, attempt to start an emulator on failure.

        Returns:
            SetupResult with critical check details. success=True if all passed.
        """
        result = SetupResult()
        adb = self._get_adb()

        # Stage 1: ADB availability
        if not self._check_adb_stage(result, adb):
            return result

        # Stage 2: Device connection
        if not self._check_device_stage(result, adb, auto_start_emulator):
            return result

        # Stage 3: Root access
        self._check_root_stage(result, adb, enable_root)
        if not result.success:
            return result

        # Stage 4: SELinux permissive mode
        self._check_selinux_stage(result, adb, set_selinux_permissive)

        result.success = True
        return result

    def _check_adb_stage(self, result: SetupResult, adb: AdbProtocol) -> bool:
        """Run the ADB availability check stage.

        Args:
            result: SetupResult to update
            adb: ADB interface

        Returns:
            True if ADB is available, False otherwise
        """
        from sandroid.services.setup_checks import check_adb_availability

        adb_check = check_adb_availability(adb)
        result.checks.append(adb_check)
        result.adb_available = adb_check.passed

        if not adb_check.passed:
            result.success = False
            result.message = "ADB not found in PATH"
            result.add_error(adb_check.message)
            return False
        return True

    def _check_device_stage(
        self,
        result: SetupResult,
        adb: AdbProtocol,
        auto_start_emulator: bool,
    ) -> bool:
        """Run the device connection check stage.

        Args:
            result: SetupResult to update
            adb: ADB interface
            auto_start_emulator: If True, report available emulators on failure

        Returns:
            True if a device is connected, False otherwise
        """
        from sandroid.services.device_info import get_device_serial
        from sandroid.services.setup_checks import check_device_connection

        device_check = check_device_connection(adb)
        result.checks.append(device_check)
        device_connected = device_check.passed or (
            device_check.status == SetupCheckStatus.WARNING
            and device_check.details.get("needs_root")
        )
        result.device_connected = device_connected

        if not device_connected:
            if auto_start_emulator:
                emulator = self._get_emulator()
                available = emulator.list_available_avds()
                if available:
                    result.add_warning(
                        f"Found {len(available)} available emulators: {available}"
                    )
                    device_check.details["available_emulators"] = available
                else:
                    result.add_error("No available emulators found")

            result.success = False
            result.message = (
                "No devices/emulators connected. "
                "Connect a device via USB or start an AVD with: sandroid-config avd start"
            )
            return False

        result.device_serial = get_device_serial(adb)
        return True

    def _check_root_stage(
        self, result: SetupResult, adb: AdbProtocol, enable_root: bool
    ) -> None:
        """Run the root access check stage.

        Args:
            result: SetupResult to update
            adb: ADB interface
            enable_root: If True, attempt to enable root; otherwise skip
        """
        from sandroid.services.setup_checks import (
            check_and_enable_root,
            make_skipped_check,
        )

        if enable_root:
            root_check = check_and_enable_root(adb)
            result.checks.append(root_check)
            result.root_available = root_check.passed

            if not root_check.passed:
                result.success = False
                result.message = "Device does not support adb root"
                result.add_error(root_check.message)
        else:
            root_check = make_skipped_check("root", "Root Access")
            result.checks.append(root_check)

    def _check_selinux_stage(
        self, result: SetupResult, adb: AdbProtocol, set_selinux_permissive: bool
    ) -> None:
        """Run the SELinux check stage.

        Args:
            result: SetupResult to update
            adb: ADB interface
            set_selinux_permissive: If True, attempt to set permissive; otherwise skip
        """
        from sandroid.services.setup_checks import (
            check_and_set_selinux,
            make_skipped_check,
        )

        if set_selinux_permissive:
            selinux_check = check_and_set_selinux(adb)
            result.checks.append(selinux_check)
            result.selinux_permissive = selinux_check.passed

            if not selinux_check.passed:
                result.add_warning(selinux_check.message)
        else:
            selinux_check = make_skipped_check("selinux", "SELinux Permissive")
            result.checks.append(selinux_check)

    # ==================== Tool Checks ====================

    def _run_tool_checks(self, result: SetupResult) -> None:
        """Run non-critical tool availability checks.

        Mutates the result in place, adding check results and warnings.

        Args:
            result: SetupResult to update with tool check results.
        """
        sqldiff_check = self._check_sqldiff()
        result.checks.append(sqldiff_check)
        result.sqldiff_available = sqldiff_check.passed
        if not sqldiff_check.passed:
            result.add_warning(sqldiff_check.message)

        objection_check = self._check_objection()
        result.checks.append(objection_check)
        result.objection_available = objection_check.passed
        if not objection_check.passed:
            result.add_warning(objection_check.message)

        frida_check = self._check_frida()
        result.checks.append(frida_check)
        result.frida_available = frida_check.passed
        if not frida_check.passed:
            result.add_warning(frida_check.message)

    def check_deferred_setup(self, publish_event: bool = True) -> SetupResult:
        """Run deferred (non-critical) setup checks in background.

        Performs slower checks that don't need to complete before showing UI:
        - sqldiff availability
        - objection availability
        - frida availability (slow import)
        - Android version/API level

        This method should be called from a background thread after UI is visible.

        Args:
            publish_event: If True, publish TOOL_AVAILABILITY_UPDATED event when done.

        Returns:
            SetupResult with deferred check results merged into existing result.
        """
        with self._lock:
            result = (
                self._last_result if self._last_result is not None else SetupResult()
            )
            adb = self._get_adb()

            # Remove any stale tool checks before re-running
            tool_check_names = {"sqldiff", "objection", "frida"}
            result.checks = [c for c in result.checks if c.name not in tool_check_names]

            self._run_tool_checks(result)

            # Get Android version info
            android_info = self._get_android_info(adb)
            result.android_version = android_info.get("version")
            result.api_level = android_info.get("api_level")

            if result.success:
                result.message = "Environment setup validated successfully"

            self._last_result = result

            if publish_event:
                self._publish_tool_availability(result)

            return result

    # ==================== Delegate Methods to Extracted Modules ====================

    def _check_adb_availability(self, adb: AdbProtocol) -> SetupCheckResult:
        """Check if ADB is available in PATH.

        Args:
            adb: ADB interface to use

        Returns:
            SetupCheckResult with check status
        """
        from sandroid.services.setup_checks import check_adb_availability

        return check_adb_availability(adb)

    def _check_device_connection(self, adb: AdbProtocol) -> SetupCheckResult:
        """Check if a device/emulator is connected.

        Args:
            adb: ADB interface to use

        Returns:
            SetupCheckResult with check status
        """
        from sandroid.services.setup_checks import check_device_connection

        return check_device_connection(adb)

    def _check_and_enable_root(self, adb: AdbProtocol) -> SetupCheckResult:
        """Check and enable ADB root access.

        Args:
            adb: ADB interface to use

        Returns:
            SetupCheckResult with check status
        """
        from sandroid.services.setup_checks import check_and_enable_root

        return check_and_enable_root(adb)

    def _check_and_set_selinux(self, adb: AdbProtocol) -> SetupCheckResult:
        """Check and set SELinux to permissive mode.

        Args:
            adb: ADB interface to use

        Returns:
            SetupCheckResult with check status
        """
        from sandroid.services.setup_checks import check_and_set_selinux

        return check_and_set_selinux(adb)

    def _check_sqldiff(self) -> SetupCheckResult:
        """Check if sqldiff binary is available.

        Returns:
            SetupCheckResult with check status
        """
        from sandroid.services.setup_checks import check_sqldiff

        return check_sqldiff()

    def _check_objection(self) -> SetupCheckResult:
        """Check if objection tool is available.

        Returns:
            SetupCheckResult with check status
        """
        from sandroid.services.setup_checks import check_objection

        return check_objection()

    def _check_frida(self) -> SetupCheckResult:
        """Check if frida is available.

        Returns:
            SetupCheckResult with check status
        """
        from sandroid.services.setup_checks import check_frida

        return check_frida()

    def _get_device_serial(self, adb: AdbProtocol) -> str | None:
        """Get the connected device serial number.

        Args:
            adb: ADB interface to use

        Returns:
            Device serial or None
        """
        from sandroid.services.device_info import get_device_serial

        return get_device_serial(adb)

    def _get_android_info(self, adb: AdbProtocol) -> dict[str, Any]:
        """Get Android version and API level.

        Args:
            adb: ADB interface to use

        Returns:
            Dictionary with version and api_level
        """
        from sandroid.services.device_info import get_android_info

        return get_android_info(adb)

    # ==================== Individual Check Methods ====================

    def validate_adb_connection(self) -> bool:
        """Check if ADB can connect to a device.

        Returns:
            True if ADB connection works.
        """
        adb = self._get_adb()
        try:
            stdout, stderr = adb.send_adb_command("shell echo test")
            return "test" in stdout and "error" not in stderr.lower()
        except (OSError, RuntimeError, AttributeError, subprocess.SubprocessError):
            return False

    def check_root_access(self) -> bool:
        """Check if ADB root access is available.

        Note: This checks but does not enable root.

        Returns:
            True if device supports adb root.
        """
        adb = self._get_adb()
        try:
            _stdout, stderr = adb.send_adb_command("root")
            return "cannot run as root" not in stderr
        except (OSError, RuntimeError, AttributeError, subprocess.SubprocessError):
            return False

    def check_selinux_permissive(self) -> bool:
        """Check if SELinux is in permissive mode.

        Returns:
            True if SELinux is permissive.
        """
        adb = self._get_adb()
        try:
            stdout, _stderr = adb.send_adb_command("shell getenforce")
            return "permissive" in stdout.lower()
        except (OSError, RuntimeError, AttributeError, subprocess.SubprocessError):
            return False

    def is_sqldiff_available(self) -> bool:
        """Check if the sqldiff binary is available in PATH.

        sqldiff is used for comparing SQLite databases.

        Returns:
            True if sqldiff is available.
        """
        return shutil.which("sqldiff") is not None

    def is_objection_available(self) -> bool:
        """Check if the objection tool is available in PATH.

        objection is used for interactive mobile app exploration via Frida.

        Returns:
            True if objection is available.
        """
        return shutil.which("objection") is not None

    def is_frida_available(self) -> bool:
        """Check if Frida is installed.

        Returns:
            True if Frida is available.
        """
        try:
            import frida

            return True
        except ImportError:
            return False

    def get_host_ip(self) -> str:
        """Get the host machine's IP address.

        Uses multiple strategies to find a non-loopback IP:
        1. Connect to external server (doesn't actually send data)
        2. Use hostname resolution
        3. Extended hostname lookup

        Falls back to 127.0.0.1 if all methods fail.

        Returns:
            Host IP address string.
        """
        from sandroid.services.device_info import get_host_ip

        return get_host_ip()

    # ==================== Emulator Management ====================

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

    # ==================== State Management ====================

    def get_last_result(self) -> SetupResult | None:
        """Get the result of the last check_setup() call.

        Returns:
            Last SetupResult or None if never checked.
        """
        with self._lock:
            return self._last_result

    def get_status_dict(self) -> dict[str, Any]:
        """Get current setup status as a dictionary.

        Useful for API responses and debugging.

        Returns:
            Dictionary with setup status.
        """
        with self._lock:
            result = self._last_result
            return {
                "checked": result is not None,
                "success": result.success if result else None,
                "adb_available": result.adb_available if result else None,
                "device_connected": result.device_connected if result else None,
                "root_available": result.root_available if result else None,
                "selinux_permissive": result.selinux_permissive if result else None,
                "sqldiff_available": self.is_sqldiff_available(),
                "objection_available": self.is_objection_available(),
                "frida_available": self.is_frida_available(),
                "device_serial": result.device_serial if result else None,
                "android_version": result.android_version if result else None,
                "api_level": result.api_level if result else None,
                "host_ip": self.get_host_ip(),
                "errors": result.errors if result else [],
                "warnings": result.warnings if result else [],
            }

    def reset(self) -> None:
        """Reset service state.

        Clears cached results. Useful for testing.
        """
        with self._lock:
            self._last_result = None

    # ==================== Event Publishing ====================

    def _publish_setup_completed(self, result: SetupResult) -> None:
        """Publish event when setup check completes.

        Args:
            result: The setup result to publish
        """
        if self._event_bus is None:
            return

        from sandroid.core.events import Event, EventType

        self._event_bus.publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={
                    "component": "setup",
                    "success": result.success,
                    "device_serial": result.device_serial,
                    "android_version": result.android_version,
                    "api_level": result.api_level,
                    "warnings_count": len(result.warnings),
                    "errors_count": len(result.errors),
                },
                source="setup_service",
            )
        )

    def _publish_tool_availability(self, result: SetupResult) -> None:
        """Publish event when deferred tool checks complete.

        Args:
            result: The setup result with tool availability info
        """
        from sandroid.core.events import Event, EventBus, EventType

        EventBus.get().publish(
            Event(
                type=EventType.TOOL_AVAILABILITY_UPDATED,
                data={
                    "sqldiff_available": result.sqldiff_available,
                    "objection_available": result.objection_available,
                    "frida_available": result.frida_available,
                    "android_version": result.android_version,
                    "api_level": result.api_level,
                },
                source="setup_service",
            )
        )
        logger.debug("Published TOOL_AVAILABILITY_UPDATED event")


__all__ = [
    "SetupCheckResult",
    "SetupCheckStatus",
    "SetupResult",
    "SetupService",
]
