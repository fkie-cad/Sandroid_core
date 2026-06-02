"""ADB process identification.

Provides functions for finding the PID of a running Android package,
with multiple fallback strategies.
"""

from __future__ import annotations

from logging import getLogger
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from sandroid.core.adb_utils import is_adb_error_actionable

logger = getLogger(__name__)


# ---------------------------------------------------------------------------
# Individual PID-lookup strategies
# ---------------------------------------------------------------------------


def _try_pidof(
    send_command: Callable[[str], tuple[str, str]],
    package_name: str,
) -> int | None:
    """Strategy 1: Use the ``pidof`` shell command (fast, not always available).

    Args:
        send_command: Callable that sends an ADB command.
        package_name: Fully qualified package name.

    Returns:
        The PID if found, *None* otherwise.
    """
    output, stderr = send_command(f"shell pidof {package_name}")
    if stderr and is_adb_error_actionable(stderr):
        logger.warning(f"pidof command warning for {package_name}: {stderr}")
    logger.debug(f"pidof output: '{output}', stderr: '{stderr}'")

    if output and output.strip():
        try:
            pid = int(output.strip().split()[0])
            logger.debug(f"Found PID {pid} for {package_name} via pidof")
            return pid
        except (ValueError, IndexError) as e:
            logger.debug(f"pidof parsing failed: {e}")
    return None


def _try_ps_a(
    send_command: Callable[[str], tuple[str, str]],
    package_name: str,
) -> int | None:
    """Strategy 2: Parse ``ps -A`` output (more reliable across versions).

    Args:
        send_command: Callable that sends an ADB command.
        package_name: Fully qualified package name.

    Returns:
        The PID if found, *None* otherwise.
    """
    logger.debug(f"Trying ps -A fallback for {package_name}")
    output, _stderr = send_command("shell ps -A")
    logger.debug(f"ps -A output length: {len(output) if output else 0} chars")

    if output:
        for line in output.strip().split("\n"):
            if package_name in line:
                logger.debug(f"Found matching line: '{line}'")
                parts = line.split()
                logger.debug(f"Line parts: {parts}")
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1])
                        logger.debug(f"Found PID {pid} for {package_name} via ps -A")
                        return pid
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Failed to parse PID from parts: {e}")
                        continue
    return None


def _try_ps_o(
    send_command: Callable[[str], tuple[str, str]],
    package_name: str,
) -> int | None:
    """Strategy 3: Parse ``ps -o PID,NAME`` output (alternative format).

    Args:
        send_command: Callable that sends an ADB command.
        package_name: Fully qualified package name.

    Returns:
        The PID if found, *None* otherwise.
    """
    logger.debug(f"Trying ps -o PID,NAME fallback for {package_name}")
    output, _stderr = send_command("shell ps -o PID,NAME")

    if output:
        for line in output.strip().split("\n"):
            if package_name in line:
                logger.debug(f"Found matching line in ps -o: '{line}'")
                parts = line.split()
                if len(parts) >= 1:
                    try:
                        pid = int(parts[0])
                        logger.debug(f"Found PID {pid} for {package_name} via ps -o")
                        return pid
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Failed to parse PID from ps -o: {e}")
                        continue
    return None


def _try_frida(package_name: str) -> int | None:
    """Strategy 4: Use Frida's ``enumerate_processes`` (last resort).

    Args:
        package_name: Fully qualified package name.

    Returns:
        The PID if found, *None* otherwise.
    """
    logger.debug(
        f"All ADB methods failed, trying Frida as last resort for {package_name}"
    )
    try:
        import frida

        device = frida.get_usb_device()
        processes = device.enumerate_processes()
        for proc in processes:
            if proc.name == package_name or package_name in proc.name:
                logger.info(
                    f"Found PID {proc.pid} for {package_name} via Frida (last resort)"
                )
                return proc.pid
        logger.debug(f"Frida didn't find process {package_name}")
    except Exception as e:
        logger.debug(f"Frida PID lookup failed: {e}")
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_pid_for_package_name(
    send_command: Callable[[str], tuple[str, str]],
    package_name: str,
    use_frida_fallback: bool = True,
    quiet: bool = False,
) -> int | None:
    """Get the process ID (PID) for a given package name.

    Tries multiple methods in order of preference:

    1. ``pidof`` command -- fast and standard on most Android versions
    2. ``ps -A`` command -- more compatible across Android versions
    3. ``ps -o PID,NAME`` -- alternative format for some Android versions
    4. Frida ``enumerate_processes`` -- last resort, requires Frida

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).
        package_name: The fully qualified package name.
        use_frida_fallback: When True (default), fall back to Frida's
            ``enumerate_processes`` if the ADB strategies all fail. Set to
            False for latency-sensitive hot paths (e.g. a periodic
            running-state poll) where the Frida round-trip is too heavy.
        quiet: When True, a final miss is logged at debug instead of warning.
            Set this for paths where "not running" is an expected, frequent
            outcome (e.g. the running-state poll on a stopped app) so the log
            isn't spammed with misleading warnings.

    Returns:
        The process ID if found, *None* otherwise.
    """
    strategies = [
        lambda: _try_pidof(send_command, package_name),
        lambda: _try_ps_a(send_command, package_name),
        lambda: _try_ps_o(send_command, package_name),
    ]
    if use_frida_fallback:
        strategies.append(lambda: _try_frida(package_name))

    for strategy in strategies:
        pid = strategy()
        if pid is not None:
            return pid

    if quiet:
        logger.debug(f"No PID for package {package_name} (not running)")
    else:
        logger.warning(
            f"Could not find PID for package {package_name} using any method"
        )
    return None
