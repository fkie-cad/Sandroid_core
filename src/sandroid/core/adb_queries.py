"""ADB device property queries.

Provides functions that query device properties via ``getprop`` and other
shell commands.  All functions accept a *send_command* callable so they can
be used as mix-in helpers on the ``Adb`` class without circular imports.
"""

from __future__ import annotations

from logging import getLogger
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

logger = getLogger(__name__)


# ---------------------------------------------------------------------------
# Declarative getprop helper
# ---------------------------------------------------------------------------


def _getprop(
    send_command: Callable[[str], tuple[str, str]],
    prop_name: str,
) -> str | None:
    """Get a system property value via ``getprop``.

    Args:
        send_command: Callable that sends an ADB command and returns
            (stdout, stderr).
        prop_name: The property name (e.g., ``'ro.product.model'``).

    Returns:
        The property value, or *None* if an error occurs.
    """
    stdout, stderr = send_command(f"shell getprop {prop_name}")
    if stderr:
        logger.error(f"Failed to get property {prop_name}: {stderr}")
        return None
    return stdout.strip() if stdout else None


def get_device_model(send_command: Callable[[str], tuple[str, str]]) -> str | None:
    """Retrieve the device model name.

    Queries the ``ro.product.model`` system property.

    Returns:
        The device model as a string (e.g., ``'Pixel 6 Pro'``),
        or *None* if an error occurs.
    """
    return _getprop(send_command, "ro.product.model")


def get_device_brand(send_command: Callable[[str], tuple[str, str]]) -> str | None:
    """Retrieve the device brand name.

    Queries the ``ro.product.brand`` system property.

    Returns:
        The device brand as a string (e.g., ``'google'``),
        or *None* if an error occurs.
    """
    return _getprop(send_command, "ro.product.brand")


def get_device_locale(send_command: Callable[[str], tuple[str, str]]) -> str | None:
    """Retrieve the locale setting of the connected device.

    Queries the ``ro.product.locale`` system property.

    Returns:
        The device locale as a string (e.g., ``'en-US'``),
        or *None* if an error occurs or the property is not set.
    """
    return _getprop(send_command, "ro.product.locale")


def get_android_version_and_api_level(
    send_command: Callable[[str], tuple[str, str]],
) -> dict[str, str | None] | None:
    """Retrieve the Android version and API level of the connected device.

    Queries ``ro.build.version.release`` and ``ro.build.version.sdk``.

    Returns:
        A dictionary with keys ``'android_version'`` and ``'api_level'``,
        or *None* if an error occurs.
    """
    version_stdout, version_stderr = send_command(
        "shell getprop ro.build.version.release"
    )
    api_level_stdout, api_level_stderr = send_command(
        "shell getprop ro.build.version.sdk"
    )

    if version_stderr or api_level_stderr:
        logger.error(
            "Failed to get Android version or API level: "
            f"{version_stderr or api_level_stderr}"
        )
        return None

    return {
        "android_version": version_stdout.strip() if version_stdout else None,
        "api_level": api_level_stdout.strip() if api_level_stdout else None,
    }


def get_device_time(
    send_command: Callable[[str], tuple[str, str]],
) -> str | None:
    """Retrieve the current date and time from the connected device.

    Executes the ``date`` command on the device.

    Returns:
        The current date/time string, or *None* if an error occurs.
    """
    stdout, stderr = send_command("shell date")
    if stderr:
        logger.error(f"Failed to get device time: {stderr}")
        return None
    return stdout.strip()
