"""Setup check functions for Sandroid environment validation.

This module contains the individual check functions extracted from SetupService.
Each function validates one aspect of the environment and returns a SetupCheckResult.

All functions accept their dependencies as parameters (no global state),
making them easy to test in isolation.

Usage:
    from sandroid.services.setup_checks import check_adb_availability, check_frida

    result = check_adb_availability(adb)
    if result.passed:
        print("ADB is available")
"""

import logging
import shutil
import time
from typing import Any

from sandroid.services.setup_service import SetupCheckResult, SetupCheckStatus

logger = logging.getLogger(__name__)


def _make_check(
    name: str,
    display_name: str,
    status: SetupCheckStatus = SetupCheckStatus.NOT_CHECKED,
    message: str = "",
    details: dict[str, Any] | None = None,
) -> SetupCheckResult:
    """Create a SetupCheckResult with the given parameters.

    Standardizes result creation across all check functions.

    Args:
        name: Check identifier (e.g., 'adb', 'root', 'selinux')
        display_name: Human-readable check name
        status: Check status
        message: Detailed message about the check result
        details: Additional details dictionary

    Returns:
        SetupCheckResult with the provided fields
    """
    return SetupCheckResult(
        name=name,
        display_name=display_name,
        status=status,
        message=message,
        details=details or {},
    )


def make_skipped_check(name: str, display_name: str) -> SetupCheckResult:
    """Create a skipped SetupCheckResult.

    Args:
        name: Check identifier
        display_name: Human-readable check name

    Returns:
        SetupCheckResult with SKIPPED status
    """
    return _make_check(
        name=name,
        display_name=display_name,
        status=SetupCheckStatus.SKIPPED,
        message=f"{display_name} check skipped",
    )


def check_adb_availability(adb: Any) -> SetupCheckResult:
    """Check if ADB is available in PATH.

    Args:
        adb: ADB interface with send_adb_command method

    Returns:
        SetupCheckResult with check status
    """
    check = _make_check(name="adb", display_name="ADB Availability")

    try:
        stdout, stderr = adb.send_adb_command("version")

        if "not found" in stderr.lower():
            check.status = SetupCheckStatus.FAILED
            check.message = "ADB command not found in PATH"
            return check

        check.status = SetupCheckStatus.PASSED
        check.message = "ADB is available"

        if stdout:
            lines = stdout.strip().split("\n")
            if lines:
                check.details["version_info"] = lines[0]

    except Exception as e:
        check.status = SetupCheckStatus.FAILED
        check.message = f"Error checking ADB: {e!s}"

    return check


def check_device_connection(adb: Any) -> SetupCheckResult:
    """Check if a device/emulator is connected.

    Args:
        adb: ADB interface with send_adb_command method

    Returns:
        SetupCheckResult with check status
    """
    check = _make_check(name="device", display_name="Device Connection")

    try:
        _stdout, stderr = adb.send_adb_command("shell ls /data")

        if "no devices/emulators found" in stderr.lower():
            check.status = SetupCheckStatus.FAILED
            check.message = "No devices or emulators connected"
            return check

        if "device offline" in stderr.lower():
            check.status = SetupCheckStatus.FAILED
            check.message = "Device is offline"
            return check

        if "permission denied" in stderr.lower():
            check.status = SetupCheckStatus.WARNING
            check.message = "Device connected but permission denied (need root)"
            check.details["needs_root"] = True
            return check

        check.status = SetupCheckStatus.PASSED
        check.message = "Device connected"

    except Exception as e:
        check.status = SetupCheckStatus.FAILED
        check.message = f"Error checking device: {e!s}"

    return check


def check_and_enable_root(adb: Any) -> SetupCheckResult:
    """Check and enable ADB root access.

    Args:
        adb: ADB interface with send_adb_command method

    Returns:
        SetupCheckResult with check status
    """
    check = _make_check(name="root", display_name="Root Access")

    try:
        stdout, stderr = adb.send_adb_command("root")

        if "adbd cannot run as root" in stderr:
            check.status = SetupCheckStatus.FAILED
            check.message = (
                "Device does not support adb root. Please ensure the device is rooted."
            )
            return check

        if "restarting" in stdout.lower():
            time.sleep(0.5)

        stdout, stderr = adb.send_adb_command("shell id")
        if "uid=0" in stdout:
            check.status = SetupCheckStatus.PASSED
            check.message = "ADB root enabled successfully"
        else:
            check.status = SetupCheckStatus.PASSED
            check.message = "ADB root command accepted"

    except Exception as e:
        check.status = SetupCheckStatus.FAILED
        check.message = f"Error enabling root: {e!s}"

    return check


def check_and_set_selinux(adb: Any) -> SetupCheckResult:
    """Check and set SELinux to permissive mode.

    Args:
        adb: ADB interface with send_adb_command method

    Returns:
        SetupCheckResult with check status
    """
    check = _make_check(name="selinux", display_name="SELinux Permissive")

    try:
        stdout, stderr = adb.send_adb_command("shell setenforce 0")

        if stderr:
            check.status = SetupCheckStatus.WARNING
            check.message = f"Failed to set SELinux permissive: {stderr.strip()}"
            return check

        stdout, stderr = adb.send_adb_command("shell getenforce")
        if "permissive" in stdout.lower():
            check.status = SetupCheckStatus.PASSED
            check.message = "SELinux set to permissive mode"
        else:
            check.status = SetupCheckStatus.PASSED
            check.message = "SELinux setenforce command accepted"

    except Exception as e:
        check.status = SetupCheckStatus.WARNING
        check.message = f"Error setting SELinux: {e!s}"

    return check


def check_sqldiff() -> SetupCheckResult:
    """Check if sqldiff binary is available.

    Returns:
        SetupCheckResult with check status
    """
    path = shutil.which("sqldiff")
    if path:
        return _make_check(
            name="sqldiff",
            display_name="sqldiff Binary",
            status=SetupCheckStatus.PASSED,
            message=f"sqldiff found at {path}",
            details={"path": path},
        )
    return _make_check(
        name="sqldiff",
        display_name="sqldiff Binary",
        status=SetupCheckStatus.WARNING,
        message=(
            "sqldiff not found in PATH. "
            "Database comparison functionality will be limited. "
            "Install sqlite3-tools to enable full database diffing."
        ),
    )


def check_objection() -> SetupCheckResult:
    """Check if objection tool is available.

    Returns:
        SetupCheckResult with check status
    """
    path = shutil.which("objection")
    if path:
        return _make_check(
            name="objection",
            display_name="objection Tool",
            status=SetupCheckStatus.PASSED,
            message=f"objection found at {path}",
            details={"path": path},
        )
    return _make_check(
        name="objection",
        display_name="objection Tool",
        status=SetupCheckStatus.WARNING,
        message=(
            "objection not found in PATH. "
            "Interactive app exploration will be limited. "
            "Install with: pip install objection"
        ),
    )


def check_frida() -> SetupCheckResult:
    """Check if frida is available.

    Returns:
        SetupCheckResult with check status
    """
    try:
        import frida

        return _make_check(
            name="frida",
            display_name="Frida Framework",
            status=SetupCheckStatus.PASSED,
            message=f"Frida version {frida.__version__} available",
            details={"version": frida.__version__},
        )
    except ImportError:
        return _make_check(
            name="frida",
            display_name="Frida Framework",
            status=SetupCheckStatus.WARNING,
            message=(
                "Frida not installed. "
                "Dynamic instrumentation will be unavailable. "
                "Install with: pip install frida frida-tools"
            ),
        )


__all__ = [
    "check_adb_availability",
    "check_and_enable_root",
    "check_and_set_selinux",
    "check_device_connection",
    "check_frida",
    "check_objection",
    "check_sqldiff",
    "make_skipped_check",
]
