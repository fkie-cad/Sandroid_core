"""Device information retrieval for Sandroid.

This module contains functions for querying device properties and host
network information, extracted from SetupService.

All functions accept their dependencies as parameters (no global state).

Usage:
    from sandroid.services.device_info import get_android_info, get_host_ip

    info = get_android_info(adb)
    host_ip = get_host_ip()
"""

import logging
import socket
from typing import Any

logger = logging.getLogger(__name__)


def get_device_serial(adb: Any) -> str | None:
    """Get the connected device serial number.

    Args:
        adb: ADB interface with send_adb_command method

    Returns:
        Device serial or None
    """
    try:
        stdout, stderr = adb.send_adb_command("get-serialno")
        if stdout and not stderr:
            return stdout.strip()
    except Exception:
        pass
    return None


def get_android_info(adb: Any) -> dict[str, Any]:
    """Get Android version and API level from the connected device.

    Args:
        adb: ADB interface with send_adb_command method

    Returns:
        Dictionary with 'version' and 'api_level' keys (if available)
    """
    info: dict[str, Any] = {}

    try:
        stdout, stderr = adb.send_adb_command("shell getprop ro.build.version.release")
        if stderr:
            logger.warning(f"ADB getprop version warning: {stderr}")
        if stdout:
            info["version"] = stdout.strip()

        stdout, stderr = adb.send_adb_command("shell getprop ro.build.version.sdk")
        if stderr:
            logger.warning(f"ADB getprop sdk warning: {stderr}")
        if stdout:
            try:
                info["api_level"] = int(stdout.strip())
            except ValueError:
                pass
    except Exception:
        pass

    return info


def get_host_ip() -> str:
    """Get the host machine's IP address.

    Uses multiple strategies to find a non-loopback IP:
    1. Connect to external server (doesn't actually send data)
    2. Use hostname resolution
    3. Extended hostname lookup

    Falls back to 127.0.0.1 if all methods fail.

    Returns:
        Host IP address string.
    """
    # Strategy 1: Create a socket connection to find the default interface
    try:
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_socket.connect(("8.8.8.8", 80))
        host_ip = temp_socket.getsockname()[0]
        temp_socket.close()
        return host_ip
    except (OSError, IndexError):
        logger.debug("Failed to get IP via external connection")

    # Strategy 2: Try hostname resolution
    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        if not host_ip.startswith("127."):
            return host_ip
    except socket.gaierror:
        logger.debug("Failed to get IP from hostname")

    # Strategy 3: Extended hostname lookup
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith("127."):
                return ip
    except socket.gaierror:
        logger.debug("Failed extended hostname lookup")

    # Fallback
    logger.warning("Could not determine host IP, using localhost")
    return "127.0.0.1"


__all__ = [
    "get_android_info",
    "get_device_serial",
    "get_host_ip",
]
