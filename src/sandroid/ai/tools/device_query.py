"""Real, ADB-backed device-query tools for the Sandroid AI chat.

Every tool here dispatches to a genuinely existing :class:`~sandroid.core.adb.Adb`
classmethod or
:class:`~sandroid.services.device_settings_service.DeviceSettingsService`
accessor -- no ``"note": "SAMPLE DATA"`` markers, this is real device data.

Importing this module registers both tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). Both tools in this module are
``RiskTier.READ_ONLY`` and ``category="device_query"``.
"""

import logging

from sandroid.ai.tools.registry import RiskTier, sandroid_tool
from sandroid.core.adb import Adb

logger = logging.getLogger(__name__)

_MAGISK_PACKAGE_NAME = "com.topjohnwu.magisk"


def _safe_getprop(prop_name: str) -> str | None:
    """Call ``Adb._getprop`` without letting one bad property fail the tool.

    ``Adb._getprop`` already returns ``None`` on an ADB-reported error, but a
    lower-level failure (e.g. the ADB subprocess itself failing to start)
    could still raise -- this wrapper makes sure one missing/erroring
    property doesn't take out the other fields in the same tool call.
    """
    try:
        return Adb._getprop(prop_name)
    except Exception as exc:
        logger.debug("getprop %s failed: %s", prop_name, exc)
        return None


@sandroid_tool(
    name="get_build_and_patch_info",
    description=(
        "Get the device's build fingerprint, build tags, and Android "
        "security patch level -- useful for anti-emulator/anti-detection "
        "reasoning."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="device_query",
)
def get_build_and_patch_info() -> dict[str, str | None]:
    """Return build fingerprint/tags/security-patch getprop values.

    Real integration point: :meth:`sandroid.core.adb.Adb._getprop`.

    Returns:
        ``{"fingerprint": ..., "tags": ..., "security_patch": ...}``. Any
        field can be ``None`` if that single ``getprop`` call comes back
        empty or fails -- a missing field never fails the whole tool.
    """
    return {
        "fingerprint": _safe_getprop("ro.build.fingerprint"),
        "tags": _safe_getprop("ro.build.tags"),
        "security_patch": _safe_getprop("ro.build.version.security_patch"),
    }


@sandroid_tool(
    name="check_root_and_magisk",
    description=(
        "Check whether root (su) is available on the device and whether "
        "Magisk is installed."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="device_query",
)
def check_root_and_magisk() -> dict[str, bool]:
    """Report root availability and Magisk-package presence.

    Real integration points:
    :meth:`sandroid.services.device_settings_service.DeviceSettingsService.check_root_available`
    (cached) and :meth:`sandroid.core.adb.Adb._is_package_installed` for
    ``com.topjohnwu.magisk``.

    Returns:
        ``{"root_available": bool, "magisk_installed": bool}``.
    """
    # Lazy import (matches the convention in `ai/tools/_shared.py` and
    # `ai/context.py`): keeps this module import-cheap and lets tests
    # monkeypatch `get_device_settings_service` on the module it lives on.
    from sandroid.services import get_device_settings_service

    root_available = get_device_settings_service().check_root_available()
    magisk_installed = Adb._is_package_installed(_MAGISK_PACKAGE_NAME)
    return {"root_available": root_available, "magisk_installed": magisk_installed}
