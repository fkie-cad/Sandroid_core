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
import re
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


#: adb's "no such device" errors: ``adb: device 'emulator-5999' not found``
#: (newer adb) and ``error: device 'X' not found`` / ``error: device not
#: found`` (older adb). Group 1 is the serial when adb names one.
_DEVICE_NOT_FOUND_RE = re.compile(
    r"device\s+'([^']*)'\s+not\s+found|\bdevice\s+not\s+found", re.IGNORECASE
)

#: What a shell / the OS prints when the adb *binary* cannot be run. Only
#: these mean "adb is missing" -- a bare "not found" in adb's own stderr is
#: usually about a device (see ``_DEVICE_NOT_FOUND_RE``).
_ADB_MISSING_MARKERS = (
    "command not found",
    "no such file or directory",
    "is not recognized as an internal or external command",
    "oserror:",
)


def missing_device_serial(stderr: str | None) -> str | None:
    """The serial adb could not find, if ``stderr`` is a "device not found" error.

    Returns:
        The serial named by adb (``""`` when adb did not name one), or None
        when ``stderr`` is not a device-not-found error.
    """
    match = _DEVICE_NOT_FOUND_RE.search(stderr or "")
    if match is None:
        return None
    return match.group(1) or ""


def adb_binary_missing(stderr: str | None) -> bool:
    """True if ``stderr`` says the adb executable itself could not be run.

    Device errors (``adb: device 'X' not found``) are never reported as a
    missing binary.
    """
    text = (stderr or "").lower()
    if not text or missing_device_serial(text) is not None:
        return False
    return any(marker in text for marker in _ADB_MISSING_MARKERS)


def _send_untargeted(adb: Any, command: str) -> tuple[str, str]:
    """Run a host-side adb command without the ``-s <serial>`` target.

    ``adb version`` / ``adb devices`` do not need a device; with a pinned
    serial that does not exist, adb would otherwise fail them with
    "device '<serial>' not found". Falls back to a plain call for adb
    doubles whose ``send_adb_command`` takes no ``serial`` argument.
    """
    try:
        return adb.send_adb_command(command, serial="")
    except TypeError:
        return adb.send_adb_command(command)


def list_adb_devices(adb: Any) -> list[tuple[str, str]]:
    """``[(serial, state)]`` from ``adb devices`` (empty on any failure)."""
    try:
        stdout, _stderr = _send_untargeted(adb, "devices")
    except Exception:
        return []
    devices: list[tuple[str, str]] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("list of devices", "*")):
            continue
        parts = line.split()
        if len(parts) >= 2:
            devices.append((parts[0], parts[1]))
    return devices


def check_adb_availability(adb: Any) -> SetupCheckResult:
    """Check if ADB is available in PATH.

    Runs ``adb version`` without the device target, so a pinned serial that
    is not connected (``-s emulator-5999``) is not mistaken for a missing adb
    binary; the device stage reports that one.

    Args:
        adb: ADB interface with send_adb_command method

    Returns:
        SetupCheckResult with check status
    """
    check = _make_check(name="adb", display_name="ADB Availability")

    try:
        stdout, stderr = _send_untargeted(adb, "version")

        if adb_binary_missing(stderr):
            check.status = SetupCheckStatus.FAILED
            check.message = "ADB command not found in PATH"
            check.details["stderr"] = (stderr or "").strip()
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
        SetupCheckResult with check status. When the targeted serial does not
        exist, ``details["missing_serial"]`` holds it (``""`` if adb did not
        name it).
    """
    check = _make_check(name="device", display_name="Device Connection")

    try:
        _stdout, stderr = adb.send_adb_command("shell ls /data")

        if "no devices/emulators found" in stderr.lower():
            check.status = SetupCheckStatus.FAILED
            check.message = "No devices or emulators connected"
            return check

        missing = missing_device_serial(stderr)
        if missing is not None:
            check.status = SetupCheckStatus.FAILED
            check.message = (
                f"Device '{missing}' not found" if missing else "Device not found"
            )
            check.details["missing_serial"] = missing
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
            # adbd restarts as root; wait until the device is reachable again
            # so the follow-up commands (id, setenforce) don't race it.
            time.sleep(0.5)
            adb.send_adb_command("wait-for-device")

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


#: Why Sandroid switches SELinux to Permissive.
SELINUX_PERMISSIVE_REASON = (
    "binder calls from root (APK install, Frida) are denied under Enforcing"
)


def log_selinux_change(
    before: str | None, after: str | None, when: str, serial: str | None = None
) -> None:
    """Log, at INFO, an SELinux mode change Sandroid made, with the reason.

    Nothing is logged when the mode did not change. ``before`` may be None
    when it was not read; ``when`` names the occasion (e.g. "startup").
    """
    old = (before or "").strip().capitalize()
    new = (after or "").strip().capitalize()
    if not new or old == new:
        return
    device = f" on {serial}" if serial else ""
    logger.info(
        "SELinux mode changed%s: %s -> %s (setenforce 0, %s; reason: %s)",
        device,
        old or "unknown",
        new,
        when,
        SELINUX_PERMISSIVE_REASON,
    )


def check_and_set_selinux(adb: Any) -> SetupCheckResult:
    """Check and set SELinux to permissive mode.

    Args:
        adb: ADB interface with send_adb_command method

    Returns:
        SetupCheckResult with check status
    """
    check = _make_check(name="selinux", display_name="SELinux Permissive")

    try:
        before, _ = adb.send_adb_command("shell getenforce")
        _stdout, stderr = adb.send_adb_command("shell setenforce 0")
        if stderr:
            # adbd not running as root (e.g. Magisk-rooted device): retry
            # through su before giving up.
            logger.debug(f"setenforce 0 failed ({stderr.strip()}), retrying via su")
            _stdout, su_stderr = adb.send_adb_command("shell su 0 setenforce 0")
            if su_stderr:
                stderr = f"{stderr.strip()}; su: {su_stderr.strip()}"
            else:
                stderr = ""

        stdout, _ = adb.send_adb_command("shell getenforce")
        mode = (stdout or "").strip()
        check.details["mode"] = mode
        log_selinux_change(before, mode, "device preparation")
        if "permissive" in mode.lower():
            check.status = SetupCheckStatus.PASSED
            check.message = "SELinux set to permissive mode"
        elif stderr:
            check.status = SetupCheckStatus.WARNING
            check.message = f"Failed to set SELinux permissive: {stderr.strip()}"
        elif mode:
            check.status = SetupCheckStatus.WARNING
            check.message = (
                f"SELinux is still {mode} after setenforce 0 "
                "(binder calls from root, e.g. APK install or Frida, may be denied)"
            )
        else:
            check.status = SetupCheckStatus.WARNING
            check.message = "Could not verify SELinux mode (getenforce gave no output)"

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
    "SELINUX_PERMISSIVE_REASON",
    "adb_binary_missing",
    "check_adb_availability",
    "check_and_enable_root",
    "check_and_set_selinux",
    "check_device_connection",
    "check_frida",
    "check_objection",
    "check_sqldiff",
    "list_adb_devices",
    "log_selinux_change",
    "make_skipped_check",
    "missing_device_serial",
]
