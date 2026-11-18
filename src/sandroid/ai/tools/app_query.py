"""Real, ADB-backed app-query tools for the Sandroid AI chat.

Thin wrappers: the logic lives in :mod:`sandroid.services.app_info_service`
(shared with the App lens, which must never import from ``ai``). This module
only adds tool-input handling (package-name resolution/validation, string
boolean coercion) and maps service errors to :class:`ToolExecutionError`.

Importing this module registers all six tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). All tools in this module are
``RiskTier.READ_ONLY`` and ``category="app_query"``.

``list_exported_components`` pulls the app's real APK(s) and decodes the
manifest via ``androguard``: ``dumpsys package <pkg>`` carries no
exported/permission/intent-filter data (see
:mod:`sandroid.services.component_info_parser`).
"""

import logging
from typing import Any

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools._shared import (
    PACKAGE_NAME_PARAM,
    resolve_package_name,
    validate_package_name,
)
from sandroid.ai.tools.registry import RiskTier, sandroid_tool
from sandroid.core.adb import Adb
from sandroid.services import app_info_service

logger = logging.getLogger(__name__)

# androguard availability flag (``None`` when the static-analysis extra is
# missing); tests patch it to simulate the missing dependency.
APK = app_info_service.androguard_apk_class()


@sandroid_tool(
    name="get_foreground_app",
    description=(
        "Get the package and activity name currently focused/foreground on the device."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="app_query",
)
def get_foreground_app() -> dict[str, str | None]:
    """Return the currently focused package/activity.

    Real integration point: :meth:`sandroid.core.adb.Adb.get_focused_app`.

    Returns:
        ``{"package": ..., "activity": ...}``, both ``None`` if no focused
        app could be determined.
    """
    package, activity = Adb.get_focused_app()
    return {"package": package, "activity": activity}


@sandroid_tool(
    name="is_package_installed",
    description="Check whether a package is installed on the device.",
    parameters={
        "type": "object",
        "properties": {
            "package_name": {
                "type": "string",
                "description": "Fully qualified package name to check.",
            },
        },
        "required": ["package_name"],
    },
    risk=RiskTier.READ_ONLY,
    category="app_query",
)
def is_package_installed(package_name: str) -> dict[str, bool]:
    """Check package installation via ``pm path``.

    Real integration point: :meth:`sandroid.core.adb.Adb._is_package_installed`
    (a public classmethod despite the leading underscore).

    Args:
        package_name: Fully qualified package name to check.

    Returns:
        ``{"installed": bool}``.
    """
    package_name = validate_package_name(package_name)
    return {"installed": Adb._is_package_installed(package_name)}


@sandroid_tool(
    name="list_installed_packages",
    description=(
        "List installed packages on the device along with their install "
        "date. Defaults to user-installed (third-party) apps only; pass "
        "include_system=true to also include system packages."
    ),
    parameters={
        "type": "object",
        "properties": {
            "include_system": {
                "type": "boolean",
                "description": (
                    "Include system packages as well as user-installed ones. "
                    "Defaults to false (user apps only)."
                ),
                "default": False,
            },
        },
        "required": [],
    },
    risk=RiskTier.READ_ONLY,
    category="app_query",
)
def list_installed_packages(include_system: bool = False) -> dict[str, Any]:
    """List installed packages, defaulting to user-installed only.

    Delegates to :func:`sandroid.services.app_info_service.list_installed_packages`
    (``Adb.get_installed_packages``; N+1 adb round trips, hence opt-in
    ``include_system``).

    Args:
        include_system: Whether to also include system packages. Arguments
            arrive as whatever ``json.loads`` produced, so a model emitting
            the string ``"false"`` is a real, observed failure mode (``not
            "false"`` is ``False``); the common string spellings are coerced.

    Returns:
        ``{"packages": [...], "count": len(...)}``.
    """
    if isinstance(include_system, str):
        include_system = include_system.strip().lower() in ("true", "1", "yes")
    packages = app_info_service.list_installed_packages(include_system=include_system)
    return {"packages": packages, "count": len(packages)}


@sandroid_tool(
    name="get_package_pid",
    description=(
        "Get the running process ID (PID) for a package, if it is currently "
        "running. Omit package_name to use the analyst's current spotlight "
        "app."
    ),
    parameters={
        "type": "object",
        "properties": {"package_name": PACKAGE_NAME_PARAM},
        "required": [],
    },
    risk=RiskTier.READ_ONLY,
    category="app_query",
)
def get_package_pid(package_name: str | None = None) -> dict[str, Any]:
    """Look up a package's running PID, without the Frida enumeration fallback.

    Delegates to :func:`sandroid.services.app_info_service.get_package_pid`
    (always ``use_frida_fallback=False``: Frida enumeration is heavy and
    unsafe to trigger cold from the chat worker thread).

    Args:
        package_name: Fully qualified package name, or ``None`` for the
            current spotlight app.

    Returns:
        ``{"package_name": pkg, "pid": pid_or_none}``.
    """
    pkg = resolve_package_name(package_name)
    return {"package_name": pkg, "pid": app_info_service.get_package_pid(pkg)}


@sandroid_tool(
    name="get_package_details",
    description=(
        "Get detailed package info for an installed app: version, uid, "
        "target/min SDK, APK path, data directory, install date/source, "
        "requested permissions, and signing info. Omit package_name to use "
        "the analyst's current spotlight app."
    ),
    parameters={
        "type": "object",
        "properties": {"package_name": PACKAGE_NAME_PARAM},
        "required": [],
    },
    risk=RiskTier.READ_ONLY,
    category="app_query",
)
def get_package_details(package_name: str | None = None) -> dict[str, Any]:
    """Return extended package info parsed from ``dumpsys package <pkg>``.

    Delegates to :func:`sandroid.services.app_info_service.get_package_details`.

    Args:
        package_name: Fully qualified package name, or ``None`` for the
            current spotlight app.

    Returns:
        The parser's field dict (``version_name``, ``version_code``,
        ``target_sdk``, ``min_sdk``, ``apk_path``, ``data_dir``,
        ``install_date``, ``uid``, ``requested_permissions``,
        ``install_source``, ``signing_info``) plus ``package_name``.
    """
    return app_info_service.get_package_details(resolve_package_name(package_name))


def _pull_and_parse_manifests(pkg: str) -> list[dict[str, Any]]:
    """Pull *pkg*'s APK(s) and parse each manifest (see the service).

    Raises:
        ToolExecutionError: ``androguard`` is not installed -- raised rather
            than returning an empty list, which would look exactly like
            "no exported components".
    """
    if APK is None:
        raise ToolExecutionError(
            "listing exported components requires the 'androguard' package "
            "(install the 'sandroid[static-analysis]' extra) -- it is not "
            "available in this environment"
        )
    try:
        return app_info_service.pull_and_parse_manifests(pkg)
    except app_info_service.AndroguardUnavailableError as exc:
        raise ToolExecutionError(str(exc)) from exc


@sandroid_tool(
    name="list_exported_components",
    description=(
        "Enumerate a package's exported activities/services/receivers/"
        "providers, with their guarding permissions and intent-filters -- "
        "the core pentest attack-surface signal. Omit package_name to use "
        "the analyst's current spotlight app."
    ),
    parameters={
        "type": "object",
        "properties": {"package_name": PACKAGE_NAME_PARAM},
        "required": [],
    },
    risk=RiskTier.READ_ONLY,
    category="app_query",
)
def list_exported_components(package_name: str | None = None) -> dict[str, Any]:
    """Enumerate exported components parsed from the app's real manifest.

    Delegates to :func:`_pull_and_parse_manifests` +
    :func:`sandroid.services.app_info_service.summarize_exported_components`.

    Args:
        package_name: Fully qualified package name, or ``None`` for the
            current spotlight app.

    Returns:
        ``{"package_name": pkg, "components": {...},
        "exported_without_permission_count": n}`` -- the count covers every
        exported component with no guarding permission (providers: neither
        read nor write permission).
    """
    pkg = resolve_package_name(package_name)
    summary = app_info_service.summarize_exported_components(
        _pull_and_parse_manifests(pkg)
    )
    return {"package_name": pkg, **summary}
