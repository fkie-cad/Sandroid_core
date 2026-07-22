"""Real, ADB-backed app-query tools for the Sandroid AI chat.

Every tool here dispatches to a genuinely existing :class:`~sandroid.core.adb.Adb`
classmethod (or a thin new parser over its raw ``dumpsys package`` output) --
no ``"note": "SAMPLE DATA"`` markers, this is real device data.

Importing this module registers all six tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). All tools in this module are
``RiskTier.READ_ONLY`` and ``category="app_query"``.

``list_exported_components`` is the one exception to "thin parser over raw
``dumpsys`` output": real ``dumpsys package <pkg>`` output does not contain
exported/permission/intent-filter data at all (verified against a live
emulator -- see :mod:`sandroid.services.component_info_parser`'s module
docstring for the full story), so that tool instead pulls the app's real
APK(s) off the device and decodes the manifest locally via ``androguard``.
"""

import logging
import os
import shlex
import subprocess
import tempfile
from typing import Any

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools._shared import (
    PACKAGE_NAME_PARAM,
    parse_pm_path_output,
    resolve_package_name,
)
from sandroid.ai.tools.registry import RiskTier, sandroid_tool
from sandroid.core.adb import Adb
from sandroid.services.component_info_parser import (
    merge_component_info,
    parse_component_info,
    parse_extended_package_info,
)

logger = logging.getLogger(__name__)

# androguard is a real dependency here (declared directly in the
# `static-analysis` extra, and already a transitive dependency of
# `dexray-insight`), but stays optional at runtime -- mirrors
# `sandroid.analysis.static_analysis`'s handling of `dexray_insight` itself,
# so a `pip install sandroid` without extras doesn't break this whole module
# (all six tools share this import) just because it can't enumerate exported
# components.
try:
    from androguard.core.apk import APK
    from androguard.util import set_log as _set_androguard_log
    from lxml import etree

    try:
        # androguard's own default loguru sink is DEBUG-level and dumps
        # megabytes of AXML-parsing internals per APK loaded -- silence it.
        # Guarded because loguru raises if some other import path already
        # reconfigured the default sink first.
        _set_androguard_log("ERROR")
    except Exception:
        pass
except ImportError:  # pragma: no cover - exercised via ANDROGUARD_AVAILABLE
    APK = None
    etree = None

# `Adb.send_adb_command`'s blanket 30s timeout is too short for pulling a
# real installed APK -- verified on a live emulator: WhatsApp's base.apk
# alone (139MB) took ~52s to pull. Use the streaming Popen variant with this
# much more generous timeout instead, just for the pull step.
_APK_PULL_TIMEOUT_SECONDS = 180


@sandroid_tool(
    name="get_foreground_app",
    description=(
        "Get the package and activity name currently focused/foreground on "
        "the device."
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

    Real integration point: :meth:`sandroid.core.adb.Adb.get_installed_packages`.
    Deliberately defaults to ``user_only=True`` (opt-in ``include_system``,
    never the other way round) since the underlying call is N+1 ADB round
    trips (one ``dumpsys package`` per package).

    Args:
        include_system: Whether to also include system packages. Tool-call
            arguments arrive as whatever ``json.loads`` produced from the
            model's raw JSON text with no schema validation in between (see
            ``ToolRegistry.dispatch``), so a model that emits a JSON string
            (``"false"``) instead of a real JSON boolean for this
            ``"type": "boolean"`` parameter is a real, observed failure mode
            -- verified against a live device: ``not "false"`` is ``False``
            in Python (any non-empty string is truthy), which would silently
            *include* system packages while the caller asked to exclude
            them. Coerce the common string spellings defensively rather than
            let that invert silently.

    Returns:
        ``{"packages": [...], "count": len(...)}`` -- ``packages`` is the raw
        list of dicts returned by ``Adb.get_installed_packages``.
    """
    if isinstance(include_system, str):
        include_system = include_system.strip().lower() in ("true", "1", "yes")
    packages = Adb.get_installed_packages(user_only=not include_system)
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

    Real integration point: :meth:`sandroid.core.adb.Adb.get_pid_for_package_name`.
    Always calls it with ``use_frida_fallback=False`` explicitly -- the
    default (``True``) spawns Frida device enumeration, which is heavy and
    unsafe to trigger cold from the chat worker thread.

    Args:
        package_name: Fully qualified package name, or ``None`` to resolve
            the current spotlight app via
            :func:`sandroid.ai.tools._shared.resolve_package_name`.

    Returns:
        ``{"package_name": pkg, "pid": pid_or_none}``.
    """
    pkg = resolve_package_name(package_name)
    pid = Adb.get_pid_for_package_name(pkg, use_frida_fallback=False)
    return {"package_name": pkg, "pid": pid}


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

    Real integration point: ``Adb.send_adb_command`` +
    :func:`sandroid.services.component_info_parser.parse_extended_package_info`.

    Args:
        package_name: Fully qualified package name, or ``None`` to resolve
            the current spotlight app.

    Returns:
        The parser's field dict (``version_name``, ``version_code``,
        ``target_sdk``, ``min_sdk``, ``apk_path``, ``data_dir``,
        ``install_date``, ``uid``, ``requested_permissions``,
        ``install_source``, ``signing_info``) merged with
        ``{"package_name": pkg}``.
    """
    pkg = resolve_package_name(package_name)
    stdout, _stderr = Adb.send_adb_command(f"shell dumpsys package {shlex.quote(pkg)}")
    details = parse_extended_package_info(stdout or "")
    return {**details, "package_name": pkg}


def _pull_and_parse_manifests(pkg: str) -> list[dict[str, Any]]:
    """Pull *pkg*'s real APK(s) off the device and parse each one's manifest.

    Real integration point: ``Adb.send_adb_command`` for both ``pm path``
    and ``pull``, then ``androguard.core.apk.APK`` to decode
    ``AndroidManifest.xml`` (and read the effective ``targetSdkVersion``),
    then :func:`sandroid.services.component_info_parser.parse_component_info`
    per split. This is the fix for the confirmed bug: real
    ``dumpsys package <pkg>`` output has no exported/permission/intent-filter
    data at all, so that can no longer be the data source -- see
    :mod:`sandroid.services.component_info_parser`'s module docstring.

    Splits are pulled to a temporary directory that is cleaned up
    unconditionally. A split that fails to pull or fails to parse (corrupt
    transfer, resource-only split with no manifest) is skipped with a
    logged warning rather than aborting the whole enumeration -- one bad
    split shouldn't hide every other component.

    Args:
        pkg: Fully qualified package name, already resolved.

    Returns:
        One :func:`parse_component_info` result per successfully parsed
        split (``base.apk`` first, matching ``pm path``'s own ordering --
        verified on a real device). Empty if the package has no APK paths
        (e.g. not installed).

    Raises:
        ToolExecutionError: ``androguard`` is not installed in this
            environment (the ``sandroid[static-analysis]`` extra was not
            installed) -- raised rather than silently returning an empty
            component list, since that would look exactly like the
            false-negative bug this replaces.
    """
    if APK is None:
        raise ToolExecutionError(
            "listing exported components requires the 'androguard' package "
            "(install the 'sandroid[static-analysis]' extra) -- it is not "
            "available in this environment"
        )

    stdout, _stderr = Adb.send_adb_command(f"shell pm path {shlex.quote(pkg)}")
    device_paths = parse_pm_path_output(stdout)
    if not device_paths:
        return []

    infos: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="sandroid_component_info_") as tmp_dir:
        for index, device_path in enumerate(device_paths):
            local_path = os.path.join(tmp_dir, f"split_{index}.apk")
            process = Adb.send_adb_command_popen(
                f"pull {shlex.quote(device_path)} {shlex.quote(local_path)}"
            )
            try:
                _pull_stdout, pull_stderr = process.communicate(
                    timeout=_APK_PULL_TIMEOUT_SECONDS
                )
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                logger.warning(
                    "list_exported_components: pulling %s timed out after %ss, "
                    "skipping",
                    device_path,
                    _APK_PULL_TIMEOUT_SECONDS,
                )
                continue
            if not os.path.exists(local_path):
                logger.warning(
                    "list_exported_components: failed to pull %s (%s), skipping",
                    device_path,
                    pull_stderr,
                )
                continue

            try:
                apk = APK(local_path)
                manifest_xml = etree.tostring(apk.get_android_manifest_xml()).decode(
                    "utf-8"
                )
                target_sdk = apk.get_effective_target_sdk_version()
            except Exception as exc:
                logger.warning(
                    "list_exported_components: failed to parse manifest from "
                    "%s (%s), skipping",
                    device_path,
                    exc,
                )
                continue

            infos.append(parse_component_info(manifest_xml, target_sdk))

    return infos


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

    Real integration point: :func:`_pull_and_parse_manifests` (``pm path`` +
    ``pull`` + ``androguard``) +
    :func:`sandroid.services.component_info_parser.merge_component_info`.

    Args:
        package_name: Fully qualified package name, or ``None`` to resolve
            the current spotlight app.

    Returns:
        ``{"package_name": pkg, "components": {...}, "exported_without_permission_count": n}``.
        ``components`` is passed straight through from
        ``merge_component_info``. The count covers every component (across
        all four types) that is ``exported`` and has no guarding permission:
        for activities/services/receivers that means ``permission is None``;
        for providers (which have no single ``permission`` field) it means
        both ``read_permission`` and ``write_permission`` are ``None``.
    """
    pkg = resolve_package_name(package_name)
    infos = _pull_and_parse_manifests(pkg)
    components = merge_component_info(infos)["components"]

    exported_without_permission_count = 0
    for component_list in components.values():
        for component in component_list:
            if not component.get("exported"):
                continue
            if "permission" in component:
                is_guarded = component.get("permission") is not None
            else:
                is_guarded = (
                    component.get("read_permission") is not None
                    or component.get("write_permission") is not None
                )
            if not is_guarded:
                exported_without_permission_count += 1

    return {
        "package_name": pkg,
        "components": components,
        "exported_without_permission_count": exported_without_permission_count,
    }
