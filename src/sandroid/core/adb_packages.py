"""ADB package management operations.

Provides functions for installing, uninstalling, and querying APK packages
on an Android device.  All functions accept callables for ADB communication
so they can be mixed into the ``Adb`` class without circular imports.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from logging import getLogger
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from sandroid.core.adb_utils import is_adb_error_actionable

logger = getLogger(__name__)


# ---------------------------------------------------------------------------
# aapt helpers
# ---------------------------------------------------------------------------


def find_aapt_paths() -> list[str]:
    """Find all candidate aapt executable paths.

    Checks PATH first, then falls back to Android SDK build-tools.

    Returns:
        List of candidate aapt paths to try.
    """
    candidates = ["aapt"]  # Try PATH first

    android_home = os.environ.get("ANDROID_HOME") or os.path.expanduser("~/Android/Sdk")
    build_tools_dir = os.path.join(android_home, "build-tools")
    if os.path.exists(build_tools_dir):
        versions = sorted(
            [
                d
                for d in os.listdir(build_tools_dir)
                if os.path.isdir(os.path.join(build_tools_dir, d))
            ],
            reverse=True,
        )
        for version in versions:
            candidates.append(os.path.join(build_tools_dir, version, "aapt"))

    return candidates


def extract_package_name_with_aapt(aapt_path: str, apk_path: str) -> str | None:
    """Extract package name from an APK using a specific aapt binary.

    Args:
        aapt_path: Path to the aapt executable.
        apk_path: Path to the APK file.

    Returns:
        The package name if extraction succeeds, None otherwise.
    """
    try:
        result = subprocess.run(
            [aapt_path, "dump", "badging", apk_path],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            match = re.search(r"package: name='([^']+)'", result.stdout)
            if match:
                return match.group(1)
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        logger.debug(f"aapt at '{aapt_path}' not available for package name extraction")

    return None


# ---------------------------------------------------------------------------
# Package install / uninstall
# ---------------------------------------------------------------------------


def install_apk(
    send_command: Callable[[str], tuple[str, str]],
    apk_path: str,
) -> str | None:
    """Install an APK file on the device and return the package name.

    Installs the APK using the ``-r`` flag to allow replacement of existing
    installations.  After installation, attempts to extract the package name
    using ``aapt``.

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).
        apk_path: The file system path to the APK file to install.

    Returns:
        The package name of the installed APK, or *None* if the package name
        could not be determined.

    Raises:
        APKInstallError: If the APK installation fails.
    """
    from sandroid.core.exceptions import APKInstallError

    apk_file = os.path.basename(apk_path)
    logger.info(f"Installing local APK {apk_file}")

    stdout, stderr = send_command(f"install -r {apk_path}")

    if stderr:
        stderr_lower = stderr.lower()
        if "failed" in stderr_lower or "error" in stderr_lower:
            if "INSTALL_FAILED_NO_MATCHING_ABIS" in stderr:
                reason = "APK architecture not compatible with device (wrong CPU type)"
            elif "INSTALL_FAILED_" in stderr:
                match = re.search(r"INSTALL_FAILED_\w+", stderr)
                reason = match.group(0) if match else stderr.strip()
            else:
                reason = stderr.strip()
            logger.error(f"APK installation failed: {reason}")
            raise APKInstallError(apk_file, reason)

    if "Success" not in stdout:
        logger.warning(f"APK installation status unclear: {stdout}")

    for aapt_path in find_aapt_paths():
        package_name = extract_package_name_with_aapt(aapt_path, apk_path)
        if package_name:
            logger.info(f"Installed package: {package_name}")
            return package_name

    logger.warning("Could not determine package name of installed APK")
    return None


def uninstall_apk(
    send_command: Callable[[str], tuple[str, str]],
    package_name: str,
) -> bool:
    """Uninstall a package from the device.

    Checks if the package is installed before attempting uninstallation.

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).
        package_name: The fully qualified package name to uninstall.

    Returns:
        True if the package was successfully uninstalled or was not installed,
        False if an error occurred.
    """
    if not is_package_installed(send_command, package_name):
        logger.info(f"Package {package_name} not installed, nothing to uninstall")
        return True

    logger.info(f"Uninstalling package {package_name}")
    stdout, stderr = send_command(f"shell pm uninstall {package_name}")

    if "Success" in stdout:
        logger.info(f"Successfully uninstalled {package_name}")
        return True

    if stderr and is_adb_error_actionable(stderr):
        logger.warning(f"Failed to uninstall {package_name}: {stderr}")
        return False
    if stderr:
        logger.debug(f"Uninstall info for {package_name}: {stderr}")

    if not is_package_installed(send_command, package_name):
        logger.info(f"Package {package_name} is no longer installed")
        return True

    logger.warning(f"Uninstall status unclear for {package_name}")
    return False


# ---------------------------------------------------------------------------
# Package queries
# ---------------------------------------------------------------------------


def is_package_installed(
    send_command: Callable[[str], tuple[str, str]],
    package_name: str,
) -> bool:
    """Check if a package is installed on the device.

    Uses ``pm path`` which returns the APK path if installed, empty if not.

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).
        package_name: Package name to check.

    Returns:
        True if package is installed, False otherwise.
    """
    output, stderr = send_command(f"shell pm path {package_name}")
    if stderr and is_adb_error_actionable(stderr):
        logger.warning(f"ADB pm path error for '{package_name}': {stderr}")

    stripped_output = output.strip() if output else ""
    is_installed = stripped_output.startswith("package:")

    logger.debug(f"Package install check: '{package_name}' -> installed={is_installed}")
    if stripped_output:
        logger.debug(f"  pm path output: {stripped_output[:100]}")
    return is_installed


def get_installed_packages(
    send_command: Callable[[str], tuple[str, str]],
    user_only: bool = False,
) -> list[dict[str, str | bool | None]]:
    """Get a list of installed packages along with their installation dates.

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).
        user_only: If True, only return user-installed (third-party) apps.

    Returns:
        A list of dictionaries with ``'package_name'``, ``'install_date'``,
        and ``'is_user_app'`` keys.
    """
    if user_only:
        output, error = send_command("shell pm list packages -3")
    else:
        output, error = send_command("shell pm list packages")

    if error:
        logger.error(f"Error getting installed packages: {error}")
        return []

    packages = []
    package_pattern = re.compile(r"package:(.+)")

    for line in output.strip().split("\n"):
        match = package_pattern.search(line)
        if match:
            package_name = match.group(1)

            detail_output, detail_error = send_command(
                f"shell dumpsys package {package_name} | grep firstInstallTime"
            )
            install_date = None

            if not detail_error and detail_output:
                install_match = re.search(r"firstInstallTime=(.+)", detail_output)
                if install_match:
                    install_date = install_match.group(1)

            packages.append(
                {
                    "package_name": package_name,
                    "install_date": install_date,
                    "is_user_app": user_only,
                }
            )

    return packages


def get_focused_app(
    send_command: Callable[[str], tuple[str, str]],
    max_retries: int = 3,
    retry_delay: float = 0.2,
) -> tuple[str | None, str | None]:
    """Retrieve the package name and activity of the currently focused app.

    Queries the window manager via ``dumpsys window`` to determine which app
    currently has focus.  Validates that the app is actually installed before
    returning.

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).
        max_retries: Maximum number of retry attempts (default: 3).
        retry_delay: Delay in seconds between retries (default: 0.2).

    Returns:
        ``(package_name, activity_name)`` or ``(None, None)``.
    """
    for attempt in range(max_retries):
        if attempt > 0:
            logger.debug(
                f"Retry attempt {attempt + 1}/{max_retries} for get_focused_app"
            )
            time.sleep(retry_delay)

        output = send_command("shell dumpsys window")[0]

        candidates = []
        for line in output.split("\n"):
            if "mCurrentFocus" in line or "mFocusedApp" in line:
                match = re.search(r"([^ ]+)/([^ ]+)\}", line)
                if match:
                    pkg = match.group(1)
                    activity = match.group(2)
                    candidates.append((pkg, activity, line.strip()))

        logger.debug(
            f"Found {len(candidates)} focused app candidates from dumpsys window"
        )

        for pkg, activity, source_line in candidates:
            logger.debug(f"Checking candidate: {pkg} from line: {source_line[:80]}...")

            if not is_package_installed(send_command, pkg):
                logger.warning(
                    f"Focused app '{pkg}' is not installed on device. "
                    "This may be stale window manager data. Skipping."
                )
                continue

            logger.debug(f"Package '{pkg}' is installed, returning as focused app")
            return pkg, activity

        logger.debug(
            f"No valid focused app found on attempt {attempt + 1}/{max_retries}"
        )

    logger.warning(f"No valid focused app found after {max_retries} attempts")
    return None, None
