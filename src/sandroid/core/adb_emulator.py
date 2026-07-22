"""ADB emulator-specific operations.

Provides functions for interacting with the Android emulator via telnet
console commands, including geo-location, sensor control, snapshot
management, and network capture.
"""

from __future__ import annotations

import re
import threading
from logging import getLogger
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from sandroid.core.adb_utils import is_adb_error_actionable

logger = getLogger(__name__)

#: Serializes ALL telnet-console traffic. The emulator console is a single
#: stateful connection, and with async subtasks more than one thread can now
#: reach for it at once; interleaved commands corrupt each other's responses.
#: A plain ``Lock`` (not ``RLock``) is correct because no telnet command runs
#: another telnet command while inside ``send_telnet_command`` -- its body
#: only calls ``send_command`` (an ADB, not telnet, round-trip), so the lock
#: is never re-entered on the same thread.
_TELNET_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Telnet command helpers
# ---------------------------------------------------------------------------


def send_telnet_command(
    send_command: Callable[[str], tuple[str, str]],
    command: str | bytes,
) -> tuple[str, str]:
    """Send a telnet command to the Android emulator console.

    Uses ADB's ``emu`` command to send telnet commands to the emulator. All
    telnet traffic is serialized through :data:`_TELNET_LOCK` so concurrent
    callers (e.g. async subtasks) can't interleave commands on the single
    stateful emulator console.

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).
        command: The telnet command to execute.

    Returns:
        A tuple of (stdout, stderr).
    """
    with _TELNET_LOCK:
        if isinstance(command, bytes):
            command = command.decode("utf-8")
        stdout, stderr = send_command("emu " + command)
        if stderr and is_adb_error_actionable(stderr):
            logger.error(f'Telnet command "{command}" failed: {stderr.strip()}')
        elif stderr:
            logger.debug(f'Telnet command "{command}" info: {stderr.strip()}')
        return stdout, stderr


def _get_avd_property(
    send_telnet: Callable[[str], tuple[str, str]],
    avd_command: str,
    label: str,
) -> str | None:
    """Query an AVD property via the telnet console.

    Args:
        send_telnet: Callable that sends a telnet command.
        avd_command: The telnet sub-command (e.g., ``"avd name"``).
        label: Human-readable label for error messages.

    Returns:
        The property value, or *None* if it cannot be determined.
    """
    stdout, stderr = send_telnet(avd_command)

    if stderr:
        logger.error(f"Failed to get {label}: {stderr}")
        return None

    if stdout:
        lines = stdout.strip().split("\n")
        if lines:
            return lines[0].strip()

    return None


# ---------------------------------------------------------------------------
# AVD info
# ---------------------------------------------------------------------------


def get_current_avd_name(
    send_telnet: Callable[[str], tuple[str, str]],
) -> str | None:
    """Get the name of the currently running AVD.

    Returns:
        The AVD name (e.g., ``'Pixel_6_API_34'``), or *None*.
    """
    return _get_avd_property(send_telnet, "avd name", "AVD name")


def get_current_avd_path(
    send_telnet: Callable[[str], tuple[str, str]],
) -> str | None:
    """Get the file system path of the currently running AVD.

    Returns:
        The AVD path, or *None*.
    """
    return _get_avd_property(send_telnet, "avd path", "AVD path")


def get_avd_snapshots(
    send_telnet: Callable[[str], tuple[str, str]],
) -> list[dict[str, str]]:
    """Get a list of snapshots for the currently running AVD.

    Args:
        send_telnet: Callable that sends a telnet command.

    Returns:
        A list of dictionaries with ``'id'``, ``'tag'``, ``'size'``,
        ``'date'``, and ``'clock'`` keys.
    """
    stdout, stderr = send_telnet("avd snapshot list")

    if stderr:
        logger.error(f"Failed to get AVD snapshots: {stderr}")
        return []

    snapshots = []

    if stdout:
        lines = stdout.strip().split("\n")
        for line in lines[2:]:
            if line.strip() and not line.startswith("OK"):
                try:
                    parts = line.split(None, 1)
                    if len(parts) < 2:
                        continue

                    id_value = parts[0]
                    remaining = parts[1].strip()

                    tag_size_split = re.search(r"(.*?)\s{2,}(\d+M)", remaining)
                    if not tag_size_split:
                        continue

                    tag = tag_size_split.group(1).strip()
                    size = tag_size_split.group(2)

                    remaining = remaining[tag_size_split.end() :].strip()
                    date_clock_split = re.search(
                        r"([\d-]+ [\d:]+)\s+([\d:\.]+)", remaining
                    )

                    if date_clock_split:
                        date = date_clock_split.group(1)
                        clock = date_clock_split.group(2)
                    else:
                        date = remaining
                        clock = ""

                    snapshots.append(
                        {
                            "id": id_value,
                            "tag": tag,
                            "size": size,
                            "date": date,
                            "clock": clock,
                        }
                    )
                except Exception as e:
                    logger.warning(f"Error parsing snapshot line '{line}': {e!s}")

    return snapshots


# ---------------------------------------------------------------------------
# Geo / Sensor control
# ---------------------------------------------------------------------------


def set_geo_fix(
    send_telnet: Callable[[str], tuple[str, str]],
    lon: float,
    lat: float,
) -> tuple[str, str]:
    """Set GPS coordinates on the emulator via telnet.

    Args:
        send_telnet: Callable that sends a telnet command.
        lon: Longitude value.
        lat: Latitude value.

    Returns:
        A tuple of (stdout, stderr).
    """
    logger.debug(f"Setting geo fix: lon={lon}, lat={lat}")
    stdout, stderr = send_telnet(f"geo fix {lon} {lat}")
    if stderr:
        logger.error(f"Failed to set geo fix: {stderr}")
    return stdout, stderr


def set_sensor_value(
    send_telnet: Callable[[str], tuple[str, str]],
    sensor: str,
    values: str,
) -> tuple[str, str]:
    """Set a sensor value on the emulator via telnet.

    Args:
        send_telnet: Callable that sends a telnet command.
        sensor: Sensor name (e.g., ``'acceleration'``).
        values: Colon-separated sensor values (e.g., ``'0:9.8:0'``).

    Returns:
        A tuple of (stdout, stderr).
    """
    logger.debug(f"Setting sensor '{sensor}' to values: {values}")
    stdout, stderr = send_telnet(f"sensor set {sensor} {values}")
    if stderr:
        logger.error(f"Failed to set sensor value: {stderr}")
    return stdout, stderr


def get_geo_location(
    send_command: Callable[[str], tuple[str, str]],
) -> dict | None:
    """Retrieve the last known geo location from the device.

    Parses ``dumpsys location`` output.

    Returns:
        Dictionary with ``'latitude'``, ``'longitude'``, ``'provider'``,
        and ``'accuracy'`` keys, or *None*.
    """
    stdout, stderr = send_command("shell dumpsys location")

    if stderr:
        logger.error(f"Failed to get geo location: {stderr}")
        return None

    if not stdout:
        return None

    match = re.search(
        r"last location=Location\[(\w+)\s+([-\d.]+),([-\d.]+)\s*(?:hAcc=([\d.]+))?",
        stdout,
    )
    if match:
        return {
            "latitude": float(match.group(2)),
            "longitude": float(match.group(3)),
            "provider": match.group(1),
            "accuracy": float(match.group(4)) if match.group(4) else None,
        }

    return None


def get_network_info(
    send_command: Callable[[str], tuple[str, str]],
) -> list[tuple[str, str]]:
    """Get network interface information from the device.

    Parses ``ifconfig`` output.

    Returns:
        A list of ``(interface_name, ipv4_address)`` tuples.
    """
    output = send_command("shell ifconfig")[0]
    interfaces = re.findall(
        r"(\w+)(?:\s+Link encap.+?\n)?\s+inet addr:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        output,
        re.DOTALL,
    )
    return interfaces


# ---------------------------------------------------------------------------
# Network capture
# ---------------------------------------------------------------------------


def start_network_capture(
    send_telnet: Callable[[str], tuple[str, str]],
    filename: str,
) -> bool:
    """Start capturing network packets from the emulator.

    Args:
        send_telnet: Callable that sends a telnet command.
        filename: File path for the pcap capture.

    Returns:
        True if capture started successfully, False otherwise.
    """
    if not filename:
        logger.error("Filename cannot be empty for network capture")
        return False

    stdout, stderr = send_telnet(f"network capture start {filename}")

    if stderr:
        logger.error(f"Failed to start network capture: {stderr}")
        return False

    if "OK" in stdout:
        logger.info(f"Network capture started, saving to: {filename}")
        return True
    logger.warning(f"Unexpected response when starting network capture: {stdout}")
    return False


def stop_network_capture(
    send_telnet: Callable[[str], tuple[str, str]],
) -> bool:
    """Stop the currently running network capture.

    Args:
        send_telnet: Callable that sends a telnet command.

    Returns:
        True if capture stopped successfully, False otherwise.
    """
    stdout, stderr = send_telnet("network capture stop")

    if stderr:
        logger.error(f"Failed to stop network capture: {stderr}")
        return False

    if "OK" in stdout:
        logger.info("Network capture stopped")
        return True
    logger.warning(f"Unexpected response when stopping network capture: {stdout}")
    return False
