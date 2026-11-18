"""App-info data layer for the App lens (and the AI ``app_query`` tools).

Everything the App lens needs to know about one installed package lives here,
UI-free and ``ai``-free, so the TUI never imports from :mod:`sandroid.ai`:

* **Package facts** (moved from ``ai/tools/app_query.py``):
  :func:`get_package_details`, :func:`list_installed_packages`,
  :func:`get_package_pid`, :func:`pull_and_parse_manifests` +
  :func:`summarize_exported_components`.
* **Runtime facts** (adb only, never raise, every result carries a reason):
  :func:`get_permission_state` (``dumpsys package``), :func:`get_appops`
  (``cmd appops get`` with a ``dumpsys appops`` fallback),
  :func:`get_data_footprint` (``du``/``ls`` of the app's data dirs, root
  aware) and :func:`get_running_services` (``dumpsys activity services``).
* **Static facts** with a shared, APK-keyed cache (:class:`ApkCache`):
  :func:`get_static_overview` pulls the APK(s) once, decodes them with
  androguard and stores ``overview.json`` under ``<root>/apk/<sha256>/``.
  ``<root>/insight/`` is handed to Dexray Insight 2.x as its own analysis
  cache. Only APK-derived data is ever written there; grants, AppOps and
  sizes belong to the analysis session.
* **Suspected defences**: :func:`suspect_defences` is a pure function over
  the cached static facts (and Insight results when present).

Device targeting: every device-facing function takes ``serial``. Pass the
active device's serial captured on the UI thread; it is forwarded as the
per-call ``serial=`` override of :meth:`Adb.send_adb_command` (never the
shared global), and ``None`` keeps the current global target.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import shlex
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sandroid.core.adb import Adb
from sandroid.core.adb_utils import device_shell_command, is_valid_package_name

if TYPE_CHECKING:
    from collections.abc import Iterator

from sandroid.services.component_info_parser import (
    merge_component_info,
    parse_component_info,
    parse_extended_package_info,
)

logger = logging.getLogger(__name__)

#: ``Adb.send_adb_command``'s 30s default is too short for pulling a real
#: APK (WhatsApp's 139MB base.apk took ~52s on a live emulator).
APK_PULL_TIMEOUT_SECONDS = 180

#: Bumped whenever the overview.json layout changes; older entries rebuild.
OVERVIEW_SCHEMA = 1

#: Status every :class:`SuspectedDefence` carries until verified dynamically.
STATIC_STATUS = "suspected (static)"


class AndroguardUnavailableError(RuntimeError):
    """Raised when an operation needs androguard and it is not installed."""


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------


class _DictMixin:
    """``to_dict()`` for the result dataclasses (JSON-ready for the UI)."""

    def to_dict(self) -> dict[str, Any]:
        """Return the dataclass as a plain, JSON-serialisable dict."""
        return asdict(self)  # type: ignore[call-overload]


_ANDROGUARD: tuple[Any, Any, Any] | None = None


def _androguard() -> tuple[Any, Any, Any]:
    """Import androguard lazily; return ``(APK, etree, AXMLPrinter)`` or Nones.

    Lazy so importing this module (the TUI does) stays cheap. androguard's
    default loguru sink is DEBUG level and dumps megabytes per APK, so it is
    silenced once here.
    """
    global _ANDROGUARD
    if _ANDROGUARD is None:
        try:
            from androguard.core.apk import APK
            from androguard.core.axml import AXMLPrinter
            from lxml import etree

            try:
                from androguard.util import set_log

                set_log("ERROR")
            except Exception:
                pass
            _ANDROGUARD = (APK, etree, AXMLPrinter)
        except ImportError:
            _ANDROGUARD = (None, None, None)
    return _ANDROGUARD


def androguard_available() -> bool:
    """True if androguard (the ``static-analysis`` extra) is importable."""
    return _androguard()[0] is not None


def androguard_apk_class() -> Any:
    """Return ``androguard.core.apk.APK``, or ``None`` when unavailable."""
    return _androguard()[0]


def _adb(command: str, serial: str | None, timeout: float | None = None) -> str:
    """Run an adb command, returning stdout plus stderr (never raises).

    ``serial`` is only forwarded when given, so callers (and tests) that
    replace ``Adb.send_adb_command`` with a one-argument stand-in keep working.
    """
    kwargs: dict[str, Any] = {}
    if serial is not None:
        kwargs["serial"] = serial
    if timeout is not None:
        kwargs["timeout"] = timeout
    try:
        stdout, stderr = Adb.send_adb_command(command, **kwargs)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("adb command failed: %s (%s)", command, exc)
        return ""
    out = stdout or ""
    if stderr:
        out += ("\n" if out and not out.endswith("\n") else "") + stderr
    return out


def _adb_stdout(command: str, serial: str | None) -> str:
    """Like :func:`_adb` but return stdout only."""
    kwargs: dict[str, Any] = {"serial": serial} if serial is not None else {}
    try:
        stdout, _stderr = Adb.send_adb_command(command, **kwargs)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("adb command failed: %s (%s)", command, exc)
        return ""
    return stdout or ""


def _bad_package_reason(package: str) -> str | None:
    """Reason string when *package* is not a valid package name, else None."""
    if not is_valid_package_name(package):
        return f"invalid package name {package!r}"
    return None


def _utc_now() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def _indent(line: str) -> int:
    """Number of leading spaces of *line*."""
    return len(line) - len(line.lstrip(" "))


# ---------------------------------------------------------------------------
# Package facts (moved from ai/tools/app_query.py)
# ---------------------------------------------------------------------------


def parse_pm_path_output(stdout: str) -> list[str]:
    """Parse ``pm path <pkg>`` output into a list of on-device APK paths.

    Real output is one ``package:/absolute/path/to/*.apk`` line per APK
    (``base.apk`` plus any installed splits).

    Args:
        stdout: Raw stdout from ``adb shell pm path <pkg>``.

    Returns:
        The on-device APK paths in the order ``pm path`` printed them; empty
        if there are no ``package:`` lines (e.g. not installed).
    """
    paths = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if line.startswith("package:"):
            paths.append(line[len("package:") :])
    return paths


def get_package_details(package: str, serial: str | None = None) -> dict[str, Any]:
    """Return extended package info parsed from ``dumpsys package <pkg>``.

    Args:
        package: Fully qualified package name.
        serial: Device serial (per-call override); ``None`` = global target.

    Returns:
        :func:`parse_extended_package_info`'s fields merged with
        ``{"package_name": package}``.
    """
    stdout = _adb_stdout(f"shell dumpsys package {shlex.quote(package)}", serial)
    details = parse_extended_package_info(stdout)
    return {**details, "package_name": package}


def list_installed_packages(
    include_system: bool = False, serial: str | None = None
) -> list[dict[str, Any]]:
    """List installed packages (user-installed only unless *include_system*).

    Args:
        include_system: Also include system packages (N+1 adb round trips).
        serial: Device serial; ``None`` = global target.

    Returns:
        :meth:`Adb.get_installed_packages`'s list of dicts.
    """
    with Adb.targeting(serial):
        return Adb.get_installed_packages(user_only=not include_system)


def get_package_pid(package: str, serial: str | None = None) -> int | None:
    """Return the running PID of *package* (no Frida enumeration fallback).

    Args:
        package: Fully qualified package name.
        serial: Device serial; ``None`` = global target.

    Returns:
        The PID, or ``None`` if the package is not running.
    """
    with Adb.targeting(serial):
        return Adb.get_pid_for_package_name(package, use_frida_fallback=False)


def _pull_apks(
    package: str, dest_dir: str, serial: str | None = None
) -> list[tuple[str, str]]:
    """Pull every APK split of *package* into *dest_dir*.

    A split that fails or times out is skipped with a warning.

    Returns:
        ``(device_path, local_path)`` per pulled split, ``base.apk`` first.
    """
    device_paths = parse_pm_path_output(
        _adb_stdout(f"shell pm path {shlex.quote(package)}", serial)
    )
    pulled: list[tuple[str, str]] = []
    for index, device_path in enumerate(device_paths):
        local_path = os.path.join(dest_dir, f"split_{index}.apk")
        command = f"pull {shlex.quote(device_path)} {shlex.quote(local_path)}"
        process = (
            Adb.send_adb_command_popen(command, serial=serial)
            if serial is not None
            else Adb.send_adb_command_popen(command)
        )
        try:
            _out, pull_stderr = process.communicate(timeout=APK_PULL_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            logger.warning(
                "pulling %s timed out after %ss, skipping",
                device_path,
                APK_PULL_TIMEOUT_SECONDS,
            )
            continue
        if not os.path.exists(local_path):
            logger.warning("failed to pull %s (%s), skipping", device_path, pull_stderr)
            continue
        pulled.append((device_path, local_path))
    return pulled


def _manifest_component_info(apk: Any) -> dict[str, Any]:
    """Run :func:`parse_component_info` on an androguard ``APK`` object."""
    _APK, etree, _printer = _androguard()
    manifest_xml = etree.tostring(apk.get_android_manifest_xml()).decode("utf-8")
    return parse_component_info(manifest_xml, apk.get_effective_target_sdk_version())


def pull_and_parse_manifests(
    package: str, serial: str | None = None
) -> list[dict[str, Any]]:
    """Pull *package*'s APK(s) and parse each manifest's components.

    ``dumpsys package`` carries no exported/permission/intent-filter data
    (see :mod:`sandroid.services.component_info_parser`), so the manifest is
    decoded from the real APK via androguard. Splits are pulled into a
    temporary directory that is always removed; a split that fails to pull
    or parse is skipped.

    Args:
        package: Fully qualified package name, already validated.
        serial: Device serial; ``None`` = global target.

    Returns:
        One :func:`parse_component_info` result per parsed split (base first).

    Raises:
        AndroguardUnavailableError: androguard is not installed.
    """
    APK = androguard_apk_class()
    if APK is None:
        raise AndroguardUnavailableError(
            "listing exported components requires the 'androguard' package "
            "(install the 'sandroid[static-analysis]' extra) -- it is not "
            "available in this environment"
        )
    infos: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="sandroid_component_info_") as tmp_dir:
        for device_path, local_path in _pull_apks(package, tmp_dir, serial):
            try:
                infos.append(_manifest_component_info(APK(local_path)))
            except Exception as exc:
                logger.warning(
                    "failed to parse manifest from %s (%s), skipping",
                    device_path,
                    exc,
                )
    return infos


def summarize_exported_components(infos: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge per-split component infos and count unguarded exported ones.

    Args:
        infos: :func:`parse_component_info` results, ``base.apk`` first.

    Returns:
        ``{"components": {...}, "exported_without_permission_count": n}``.
        A component counts when it is exported and unguarded: no
        ``permission`` for activities/services/receivers, neither read nor
        write permission for providers.
    """
    components = merge_component_info(infos)["components"]
    count = 0
    for component_list in components.values():
        for component in component_list:
            if not component.get("exported"):
                continue
            if "permission" in component:
                guarded = component.get("permission") is not None
            else:
                guarded = (
                    component.get("read_permission") is not None
                    or component.get("write_permission") is not None
                )
            if not guarded:
                count += 1
    return {"components": components, "exported_without_permission_count": count}


# ---------------------------------------------------------------------------
# Permission grant state (dumpsys package)
# ---------------------------------------------------------------------------

#: Base protection levels by numeric value (``PermissionInfo.PROTECTION_*``).
_PROTECTION_BY_VALUE = {
    0: "normal",
    1: "dangerous",
    2: "signature",
    3: "signatureOrSystem",
    4: "internal",
}


@dataclass
class PermissionGrant(_DictMixin):
    """One permission of a package and its grant state.

    Attributes:
        name: Permission name.
        requested: Listed under ``requested permissions:``.
        kind: ``"runtime"``, ``"install"`` or ``"requested"`` (requested but
            in neither grant section, e.g. not defined on this platform).
        granted: Grant state, ``None`` when dumpsys does not say.
        flags: Runtime permission flags (``USER_SET``, ``USER_FIXED`` ...).
        restricted: Hard/soft restricted (``restricted=true``).
        protection: Base protection level (``dangerous``/``normal``/
            ``signature``...) or ``None`` when unknown.
        protection_source: Where *protection* came from: ``"dumpsys"``,
            ``"manifest"``, ``"pm"``, ``"runtime-section"`` or ``None``.
    """

    name: str
    requested: bool = False
    kind: str = "requested"
    granted: bool | None = None
    flags: list[str] = field(default_factory=list)
    restricted: bool = False
    protection: str | None = None
    protection_source: str | None = None


@dataclass
class PermissionState(_DictMixin):
    """All permissions of one package; ``ok`` False means see ``reason``."""

    package: str
    permissions: list[PermissionGrant] = field(default_factory=list)
    declared: dict[str, str] = field(default_factory=dict)
    ok: bool = True
    reason: str | None = None


_PERM_LINE_RE = re.compile(r"^([A-Za-z0-9_.\-]+)(?::\s*(.*))?$")
_GRANTED_RE = re.compile(r"granted=(true|false)")
_FLAGS_RE = re.compile(r"flags=\[\s*([^\]]*)\]")
_PROT_RE = re.compile(r"prot=([A-Za-z|]+)")


def normalize_protection(value: Any) -> str | None:
    """Reduce a protection level (``"dangerous|instant"``, ``"0x2"``) to its base.

    Args:
        value: A protection string or hex/int value.

    Returns:
        ``"normal"``, ``"dangerous"``, ``"signature"``... or ``None``.
    """
    if value is None:
        return None
    if isinstance(value, int):
        return _PROTECTION_BY_VALUE.get(value & 0xF)
    text = str(value).strip()
    if not text or text == "None":
        return None
    if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", text):
        return _PROTECTION_BY_VALUE.get(int(text, 0) & 0xF)
    base = text.split("|")[0].strip()
    return base or None


def _section(lines: list[str], start: int) -> list[str]:
    """Return the non-blank lines indented deeper than ``lines[start]``."""
    header_indent = _indent(lines[start])
    body = []
    for line in lines[start + 1 :]:
        if not line.strip():
            continue
        if _indent(line) <= header_indent:
            break
        body.append(line.strip())
    return body


def _package_block(lines: list[str], package: str) -> list[str]:
    """Lines of the first ``Package [<package>]`` block (or ``[]``)."""
    marker = f"Package [{package}]"
    for index, line in enumerate(lines):
        if line.strip().startswith(marker):
            indent = _indent(line)
            block = [line]
            for follow in lines[index + 1 :]:
                if follow.strip() and _indent(follow) <= indent:
                    break
                block.append(follow)
            return block
    return []


def parse_dangerous_permissions(pm_output: str) -> set[str]:
    """Parse ``pm list permissions -g -d`` into the set of dangerous names."""
    found = set()
    for line in (pm_output or "").splitlines():
        line = line.strip()
        if line.startswith("permission:"):
            found.add(line[len("permission:") :].strip())
    return found


def parse_permission_state(
    dumpsys_output: str,
    package: str,
    *,
    dangerous: set[str] | None = None,
    manifest_protection: dict[str, str] | None = None,
) -> PermissionState:
    """Parse grant state out of ``dumpsys package <pkg>`` text (API 30-36).

    Reads ``requested permissions:`` (``X`` or ``X: restricted=true``),
    ``install permissions:`` (``X: granted=true``), the first user's
    ``runtime permissions:`` (``X: granted=false, flags=[ USER_SET|... ]``),
    ``declared permissions:`` and the top-level ``Permission [X]`` blocks'
    ``prot=`` values.

    Args:
        dumpsys_output: Raw ``dumpsys package <pkg>`` stdout.
        package: The package the dump is for.
        dangerous: Optional set from :func:`parse_dangerous_permissions`.
        manifest_protection: Optional ``{perm: protection}`` from the cached
            static overview (androguard).

    Returns:
        A :class:`PermissionState`; ``ok`` is False with a reason when the
        package block is missing.
    """
    lines = (dumpsys_output or "").splitlines()
    state = PermissionState(package=package)
    block = _package_block(lines, package)
    if not block:
        state.ok = False
        stripped = (dumpsys_output or "").strip()
        state.reason = (
            "package not found in dumpsys output"
            if stripped
            else "empty dumpsys output (device offline?)"
        )
        return state

    # App-declared permissions in the top-level "Permissions:" section.
    declared: dict[str, str] = {}
    for index, line in enumerate(lines):
        match = re.match(r"\s*Permission \[([^\]]+)\]", line)
        if not match:
            continue
        for body_line in _section(lines, index):
            prot = _PROT_RE.search(body_line)
            if prot:
                declared[match.group(1)] = normalize_protection(prot.group(1)) or ""
                break

    grants: dict[str, PermissionGrant] = {}

    def grant(name: str) -> PermissionGrant:
        if name not in grants:
            grants[name] = PermissionGrant(name=name)
        return grants[name]

    runtime_seen = False
    for index, line in enumerate(block):
        header = line.strip()
        if header == "requested permissions:":
            for entry in _section(block, index):
                match = _PERM_LINE_RE.match(entry)
                if not match:
                    continue
                item = grant(match.group(1))
                item.requested = True
                if "restricted=true" in (match.group(2) or ""):
                    item.restricted = True
        elif header in ("install permissions:", "runtime permissions:"):
            if header == "runtime permissions:":
                if runtime_seen:  # only the first (primary) user
                    continue
                runtime_seen = True
            kind = header.split()[0]
            for entry in _section(block, index):
                match = _PERM_LINE_RE.match(entry)
                if not match:
                    continue
                item = grant(match.group(1))
                attrs = match.group(2) or ""
                item.kind = kind
                granted = _GRANTED_RE.search(attrs)
                item.granted = granted.group(1) == "true" if granted else None
                flags = _FLAGS_RE.search(attrs)
                if flags:
                    item.flags = [f for f in flags.group(1).split("|") if f.strip()]
                    item.flags = [f.strip() for f in item.flags]
                if "RESTRICTION" in attrs:
                    item.restricted = True
        elif header == "declared permissions:":
            for entry in _section(block, index):
                match = _PERM_LINE_RE.match(entry)
                prot = _PROT_RE.search(entry)
                if match and prot:
                    declared.setdefault(
                        match.group(1), normalize_protection(prot.group(1)) or ""
                    )

    dangerous = dangerous or set()
    manifest_protection = manifest_protection or {}
    for item in grants.values():
        if declared.get(item.name):
            item.protection, item.protection_source = declared[item.name], "dumpsys"
        elif normalize_protection(manifest_protection.get(item.name)):
            item.protection = normalize_protection(manifest_protection[item.name])
            item.protection_source = "manifest"
        elif item.name in dangerous:
            item.protection, item.protection_source = "dangerous", "pm"
        elif item.kind == "runtime":
            item.protection, item.protection_source = "dangerous", "runtime-section"

    state.declared = {k: v for k, v in declared.items() if v}
    state.permissions = sorted(grants.values(), key=lambda g: g.name)
    return state


def get_permission_state(
    package: str,
    serial: str | None = None,
    *,
    manifest_protection: dict[str, str] | None = None,
    dumpsys_output: str | None = None,
) -> PermissionState:
    """Read *package*'s permission grant state from the device (never raises).

    Args:
        package: Fully qualified package name.
        serial: Device serial; ``None`` = global target.
        manifest_protection: Optional ``{perm: protection}`` from
            :attr:`StaticOverview.overview` ``["permission_protection"]``.
        dumpsys_output: Reuse an already fetched ``dumpsys package`` dump.

    Returns:
        A :class:`PermissionState`.
    """
    reason = _bad_package_reason(package)
    if reason:
        return PermissionState(package=package, ok=False, reason=reason)
    try:
        if dumpsys_output is None:
            dumpsys_output = _adb_stdout(
                f"shell dumpsys package {shlex.quote(package)}", serial
            )
        dangerous = parse_dangerous_permissions(
            _adb_stdout("shell pm list permissions -g -d", serial)
        )
        return parse_permission_state(
            dumpsys_output,
            package,
            dangerous=dangerous,
            manifest_protection=manifest_protection,
        )
    except Exception as exc:
        logger.debug("permission state failed for %s: %s", package, exc)
        return PermissionState(package=package, ok=False, reason=str(exc))


# ---------------------------------------------------------------------------
# AppOps
# ---------------------------------------------------------------------------

#: AppOps op name -> the runtime permission it shadows. Ops absent here
#: (READ_CLIPBOARD, TOAST_WINDOW, ...) have no matching permission.
OP_PERMISSIONS = {
    "COARSE_LOCATION": "android.permission.ACCESS_COARSE_LOCATION",
    "FINE_LOCATION": "android.permission.ACCESS_FINE_LOCATION",
    "CAMERA": "android.permission.CAMERA",
    "RECORD_AUDIO": "android.permission.RECORD_AUDIO",
    "READ_CONTACTS": "android.permission.READ_CONTACTS",
    "WRITE_CONTACTS": "android.permission.WRITE_CONTACTS",
    "READ_CALENDAR": "android.permission.READ_CALENDAR",
    "WRITE_CALENDAR": "android.permission.WRITE_CALENDAR",
    "READ_CALL_LOG": "android.permission.READ_CALL_LOG",
    "WRITE_CALL_LOG": "android.permission.WRITE_CALL_LOG",
    "READ_SMS": "android.permission.READ_SMS",
    "RECEIVE_SMS": "android.permission.RECEIVE_SMS",
    "SEND_SMS": "android.permission.SEND_SMS",
    "READ_PHONE_STATE": "android.permission.READ_PHONE_STATE",
    "CALL_PHONE": "android.permission.CALL_PHONE",
    "BODY_SENSORS": "android.permission.BODY_SENSORS",
    "READ_EXTERNAL_STORAGE": "android.permission.READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE": "android.permission.WRITE_EXTERNAL_STORAGE",
    "READ_MEDIA_IMAGES": "android.permission.READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO": "android.permission.READ_MEDIA_VIDEO",
    "READ_MEDIA_AUDIO": "android.permission.READ_MEDIA_AUDIO",
    "ACCESS_MEDIA_LOCATION": "android.permission.ACCESS_MEDIA_LOCATION",
    "ACTIVITY_RECOGNITION": "android.permission.ACTIVITY_RECOGNITION",
    "POST_NOTIFICATION": "android.permission.POST_NOTIFICATIONS",
    "SYSTEM_ALERT_WINDOW": "android.permission.SYSTEM_ALERT_WINDOW",
    "BLUETOOTH_SCAN": "android.permission.BLUETOOTH_SCAN",
    "BLUETOOTH_CONNECT": "android.permission.BLUETOOTH_CONNECT",
    "NEARBY_WIFI_DEVICES": "android.permission.NEARBY_WIFI_DEVICES",
}

_FG_STATES = {"top", "fg", "fgsvc", "pers", "fgs"}
_BG_STATES = {"bg", "cch", "cached"}


@dataclass
class AppOpEntry(_DictMixin):
    """One AppOps op of a package.

    Times are kept both raw (as printed) and as "seconds ago" when parsable.

    Attributes:
        op: Op name (``CAMERA``, ``READ_CLIPBOARD`` ...).
        mode: ``allow``/``ignore``/``deny``/``foreground``/``default``/...
        scope: ``"package"`` or ``"uid"`` (uid-level mode).
        permission: Matching runtime permission, ``None`` if the op has none.
        last_access / last_access_ago_s: Last access (raw text / seconds ago).
        last_reject / last_reject_ago_s: Last rejection.
        duration / duration_s: Last access duration.
        running: The op is currently running (e.g. camera open).
        access_states / reject_states: Process states of the accesses, e.g.
            ``["fg-s", "top-s"]`` (only in the dumpsys-style format).
        foreground / background: Derived from the access states; ``None``
            when the format carries no state.
    """

    op: str
    mode: str | None = None
    scope: str = "package"
    permission: str | None = None
    last_access: str | None = None
    last_access_ago_s: float | None = None
    last_reject: str | None = None
    last_reject_ago_s: float | None = None
    duration: str | None = None
    duration_s: float | None = None
    running: bool = False
    access_states: list[str] = field(default_factory=list)
    reject_states: list[str] = field(default_factory=list)
    foreground: bool | None = None
    background: bool | None = None


@dataclass
class AppOpsState(_DictMixin):
    """All AppOps of one package; ``source`` names the command parsed."""

    package: str
    ops: list[AppOpEntry] = field(default_factory=list)
    source: str | None = None
    ok: bool = True
    reason: str | None = None


_DURATION_TOKEN_RE = re.compile(r"(\d+)(ms|d|h|m|s)")
_DURATION_FULL_RE = re.compile(r"[+-]?(?:\d+(?:ms|d|h|m|s))+")
_DURATION_UNITS = {"d": 86400.0, "h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}

_OP_NAME = r"[A-Z][A-Z0-9_]+"
_SEMI_OP_RE = re.compile(rf"^(?:Uid mode:\s*)?({_OP_NAME}):\s*([a-z_]+)(.*)$")
_UID_OP_RE = re.compile(rf"^({_OP_NAME}):\s*mode=([a-z_]+)")
_BLOCK_OP_RE = re.compile(rf"^({_OP_NAME})\s*\(([a-z_]+)[^)]*\):\s*$")
_EVENT_RE = re.compile(
    r"^(Access|Reject):\s*\[([^\]]*)\]\s*(.*?)\s*(?:\(([^)]*)\))?"
    r"(?:\s*duration=(\S+))?\s*$"
)


def parse_android_duration(text: str | None) -> float | None:
    """Parse ``TimeUtils.formatDuration`` text (``+1d2h3m4s5ms``) to seconds.

    The sign is dropped (``-5m`` and ``+5m`` both mean five minutes); ``0``
    is zero. Returns ``None`` for anything else.
    """
    if text is None:
        return None
    text = text.strip().removesuffix("ago").strip()
    if text in ("0", "+0", "-0"):
        return 0.0
    if not _DURATION_FULL_RE.fullmatch(text):
        return None
    return round(
        sum(int(n) * _DURATION_UNITS[u] for n, u in _DURATION_TOKEN_RE.findall(text)),
        3,
    )


def _apply_semicolon_fields(entry: AppOpEntry, rest: str) -> None:
    """Fill time fields from ``; time=+5m ago; rejectTime=...; duration=...``."""
    if "(running)" in rest:
        entry.running = True
    for part in rest.split(";"):
        part = part.replace("(running)", "").strip()
        if "=" not in part:
            continue
        key, value = (s.strip() for s in part.split("=", 1))
        if key == "time":
            entry.last_access = value
            entry.last_access_ago_s = parse_android_duration(value)
        elif key == "rejectTime":
            entry.last_reject = value
            entry.last_reject_ago_s = parse_android_duration(value)
        elif key == "duration":
            entry.duration = value
            entry.duration_s = parse_android_duration(value)


def _apply_event(entry: AppOpEntry, match: re.Match[str]) -> None:
    """Merge one ``Access:``/``Reject:`` line, keeping the most recent."""
    kind, state, stamp, relative, duration = match.groups()
    state = state.strip()
    ago = parse_android_duration(relative)
    raw = (stamp or "").strip() or (relative or "").strip() or None
    if kind == "Access":
        if state and state not in entry.access_states:
            entry.access_states.append(state)
        newer = entry.last_access is None or (
            ago is not None
            and (entry.last_access_ago_s is None or ago < entry.last_access_ago_s)
        )
        if newer:
            entry.last_access, entry.last_access_ago_s = raw, ago
            if duration:
                entry.duration = duration
                entry.duration_s = parse_android_duration(duration)
    else:
        if state and state not in entry.reject_states:
            entry.reject_states.append(state)
        newer = entry.last_reject is None or (
            ago is not None
            and (entry.last_reject_ago_s is None or ago < entry.last_reject_ago_s)
        )
        if newer:
            entry.last_reject, entry.last_reject_ago_s = raw, ago


def _derive_fg_bg(entry: AppOpEntry) -> None:
    """Set foreground/background from the access states, if any."""
    if not entry.access_states:
        return
    bases = {s.split("-")[0] for s in entry.access_states}
    entry.foreground = bool(bases & _FG_STATES)
    entry.background = bool(bases & _BG_STATES)


def parse_appops(text: str) -> list[AppOpEntry]:
    """Parse AppOps output in every format seen on API 30-36.

    Handles, in one pass:

    * ``cmd appops get`` lines: ``CAMERA: allow; time=+5m3s ago;
      rejectTime=+1h ago; duration=+2s``, ``(running)`` and the
      ``Uid mode: OP: mode`` prefix;
    * the block format of newer builds and ``dumpsys appops --package``:
      ``CAMERA (allow):`` followed by ``Access: [fg-s] 2026-01-02 10:00:00.000
      (-5m3s) duration=+2s`` / ``Reject: [bg-s]...`` lines, optionally grouped
      in ``null=[ ... ]`` attribution tags;
    * dumpsys uid-level ``OP: mode=allow`` lines.

    Unknown lines are ignored; ops without a matching permission (e.g.
    ``READ_CLIPBOARD``) are kept.

    Args:
        text: Raw command output.

    Returns:
        One :class:`AppOpEntry` per (scope, op), in first-seen order.
    """
    entries: dict[tuple[str, str], AppOpEntry] = {}
    current: AppOpEntry | None = None

    def get(op: str, scope: str) -> AppOpEntry:
        key = (scope, op)
        if key not in entries:
            entries[key] = AppOpEntry(
                op=op, scope=scope, permission=OP_PERMISSIONS.get(op)
            )
        return entries[key]

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        event = _EVENT_RE.match(line)
        if event:
            if current is not None:
                _apply_event(current, event)
            continue
        block = _BLOCK_OP_RE.match(line)
        if block:
            current = get(block.group(1), "package")
            current.mode = block.group(2)
            continue
        uid_op = _UID_OP_RE.match(line)
        if uid_op:
            entry = get(uid_op.group(1), "uid")
            entry.mode = uid_op.group(2)
            current = None
            continue
        semi = _SEMI_OP_RE.match(line)
        if semi:
            scope = "uid" if line.startswith("Uid mode:") else "package"
            entry = get(semi.group(1), scope)
            entry.mode = semi.group(2)
            _apply_semicolon_fields(entry, semi.group(3))
            current = entry
            continue
    for entry in entries.values():
        _derive_fg_bg(entry)
    return list(entries.values())


_APPOPS_ERROR_HINTS = ("unknown package", "error:", "exception", "not found")


def get_appops(package: str, serial: str | None = None) -> AppOpsState:
    """Read *package*'s AppOps (never raises).

    Tries ``cmd appops get <pkg>`` and falls back to
    ``dumpsys appops --package <pkg>`` when that yields nothing parsable.

    Args:
        package: Fully qualified package name.
        serial: Device serial; ``None`` = global target.

    Returns:
        An :class:`AppOpsState`.
    """
    reason = _bad_package_reason(package)
    if reason:
        return AppOpsState(package=package, ok=False, reason=reason)
    quoted = shlex.quote(package)
    last_output = ""
    try:
        for source, command in (
            ("cmd appops get", f"shell cmd appops get {quoted}"),
            ("dumpsys appops", f"shell dumpsys appops --package {quoted}"),
        ):
            output = _adb(command, serial)
            last_output = output
            ops = parse_appops(output)
            if ops:
                return AppOpsState(package=package, ops=ops, source=source)
            if "no operations" in output.lower():
                return AppOpsState(package=package, source=source)
    except Exception as exc:
        logger.debug("appops failed for %s: %s", package, exc)
        return AppOpsState(package=package, ok=False, reason=str(exc))
    low = last_output.lower()
    if not last_output.strip():
        why = "no AppOps output (device offline?)"
    elif any(hint in low for hint in _APPOPS_ERROR_HINTS):
        why = last_output.strip().splitlines()[0][:200]
    else:
        why = "AppOps output not recognised"
    return AppOpsState(package=package, ok=False, reason=why)


# ---------------------------------------------------------------------------
# Data footprint
# ---------------------------------------------------------------------------

_FOOTPRINT_SEP = "@@SANDROID_SEP@@"
_DB_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")


@dataclass
class DataFootprint(_DictMixin):
    """On-device storage used by a package.

    Attributes:
        private_dir / external_dir: The measured paths.
        private_kb / external_kb: ``du -sk`` sizes, ``None`` if unknown.
        private_reason / external_reason: Why a size is missing or partial.
        shared_prefs_count: ``*.xml`` files in ``shared_prefs``.
        databases_count: Databases (``-journal``/``-wal``/``-shm`` excluded).
        root_method: ``"adb root"``, ``"su -c"``, ``"su 0"`` or ``None``.
        reason: Overall reason when nothing could be measured.
    """

    package: str
    private_dir: str = ""
    private_kb: int | None = None
    private_reason: str | None = None
    external_dir: str = ""
    external_kb: int | None = None
    external_reason: str | None = None
    shared_prefs_count: int | None = None
    databases_count: int | None = None
    root_method: str | None = None
    reason: str | None = None


def _root_wrap(script: str, method: str | None) -> str:
    """Wrap a device shell script for the given root method."""
    if method == "su -c":
        return "su -c " + shlex.quote(script)
    if method == "su 0":
        return "su 0 sh -c " + shlex.quote(script)
    return script


def detect_root_method(serial: str | None = None) -> str | None:
    """Return how to run device commands as root, or ``None`` if impossible.

    Prefers an already-root adb shell (``adb root``), then ``su -c`` (Magisk
    style), then ``su 0`` (AOSP userdebug). Never runs ``adb root`` itself
    (that restarts adbd).
    """
    for method in (None, "su -c", "su 0"):
        output = _adb(device_shell_command(_root_wrap("id", method)), serial)
        if "uid=0" in output:
            return method or "adb root"
    return None


def _classify_error(text: str) -> str:
    """Short reason for a failed ``du``/``ls`` chunk."""
    low = text.lower()
    if "no such file" in low:
        return "absent"
    if "permission denied" in low:
        return "permission denied (root required)"
    if not text.strip():
        return "no output"
    return text.strip().splitlines()[0][:120]


def _parse_du(chunk: str) -> tuple[int | None, str | None]:
    """Parse one ``du -sk`` chunk to ``(kb, reason)``."""
    size = None
    for line in chunk.splitlines():
        match = re.match(r"^\s*(\d+)\s+/", line)
        if match:
            size = int(match.group(1))
    if size is None:
        return None, _classify_error(chunk)
    if "permission denied" in chunk.lower():
        return size, "partial (some entries unreadable)"
    return size, None


def _count_entries(chunk: str, *, kind: str) -> int | None:
    """Count files in one ``ls -1`` chunk (``None`` when unreadable)."""
    low = chunk.lower()
    if "permission denied" in low:
        return None
    if "no such file" in low:
        return 0
    names = [n.strip() for n in chunk.splitlines() if n.strip()]
    if kind == "prefs":
        return sum(1 for n in names if n.endswith(".xml"))
    return sum(1 for n in names if not n.endswith(_DB_SIDECAR_SUFFIXES))


def footprint_script(package: str) -> str:
    """Device shell script measuring *package*'s data dirs (paths quoted)."""
    private = shlex.quote(f"/data/data/{package}")
    external = shlex.quote(f"/sdcard/Android/data/{package}")
    prefs = shlex.quote(f"/data/data/{package}/shared_prefs")
    dbs = shlex.quote(f"/data/data/{package}/databases")
    sep = f"; echo {_FOOTPRINT_SEP}; "
    return sep.join(
        [
            f"du -sk {private} 2>&1",
            f"du -sk {external} 2>&1",
            f"ls -1 {prefs} 2>&1",
            f"ls -1 {dbs} 2>&1",
        ]
    )


def parse_footprint_output(
    output: str, package: str, root_method: str | None = None
) -> DataFootprint:
    """Parse :func:`footprint_script` output into a :class:`DataFootprint`."""
    result = DataFootprint(
        package=package,
        private_dir=f"/data/data/{package}",
        external_dir=f"/sdcard/Android/data/{package}",
        root_method=root_method,
    )
    chunks = (output or "").split(_FOOTPRINT_SEP)
    if len(chunks) < 4:
        result.reason = "unexpected output" if output.strip() else "no output"
        return result
    private, external, prefs, dbs = (c.strip("\n") for c in chunks[:4])
    result.private_kb, result.private_reason = _parse_du(private)
    result.external_kb, result.external_reason = _parse_du(external)
    result.shared_prefs_count = _count_entries(prefs, kind="prefs")
    result.databases_count = _count_entries(dbs, kind="dbs")
    if root_method is None and result.private_kb is None:
        result.private_reason = "root required (enable adb root)"
    return result


def get_data_footprint(package: str, serial: str | None = None) -> DataFootprint:
    """Measure *package*'s private and external data (never raises).

    Private data (``/data/data/<pkg>``) needs root; without it only the
    external size is filled and the private fields carry a reason.

    Args:
        package: Fully qualified package name.
        serial: Device serial; ``None`` = global target.

    Returns:
        A :class:`DataFootprint`.
    """
    reason = _bad_package_reason(package)
    if reason:
        return DataFootprint(package=package, reason=reason)
    try:
        method = detect_root_method(serial)
        wrap = None if method in (None, "adb root") else method
        script = _root_wrap(footprint_script(package), wrap)
        output = _adb(device_shell_command(script), serial)
        return parse_footprint_output(output, package, method)
    except Exception as exc:
        logger.debug("footprint failed for %s: %s", package, exc)
        return DataFootprint(package=package, reason=str(exc))


# ---------------------------------------------------------------------------
# Running / foreground services
# ---------------------------------------------------------------------------

#: ``ServiceInfo.FOREGROUND_SERVICE_TYPE_*`` bits.
FGS_TYPE_BITS = {
    0x1: "dataSync",
    0x2: "mediaPlayback",
    0x4: "phoneCall",
    0x8: "location",
    0x10: "connectedDevice",
    0x20: "mediaProjection",
    0x40: "camera",
    0x80: "microphone",
    0x100: "health",
    0x200: "remoteMessaging",
    0x400: "systemExempted",
    0x800: "shortService",
    0x1000: "fileManagement",
    0x2000: "mediaProcessing",
    0x40000000: "specialUse",
}


@dataclass
class RunningService(_DictMixin):
    """One service record of the package.

    Attributes:
        component: ``pkg/.ClassName``.
        user: Android user id.
        foreground: ``isForeground=true``.
        foreground_id: Notification id of the foreground service.
        types: Decoded foreground-service types (``["location"]``).
        types_raw: The raw type value as printed.
        process: Hosting process name.
        pid: Hosting process PID if shown.
        created: ``createTime`` as printed (``-5m2s``).
    """

    component: str
    user: int | None = None
    foreground: bool = False
    foreground_id: int | None = None
    types: list[str] = field(default_factory=list)
    types_raw: str | None = None
    process: str | None = None
    pid: int | None = None
    created: str | None = None


@dataclass
class ServicesState(_DictMixin):
    """Running services of a package (``foreground`` is the FGS subset)."""

    package: str
    services: list[RunningService] = field(default_factory=list)
    ok: bool = True
    reason: str | None = None

    @property
    def foreground(self) -> list[RunningService]:
        """The foreground services."""
        return [s for s in self.services if s.foreground]


_SERVICE_RECORD_RE = re.compile(r"\*\s*ServiceRecord\{\S+\s+u(\d+)\s+([^\s}]+)")
_FG_RE = re.compile(r"isForeground=(true|false)")
_FG_ID_RE = re.compile(r"foregroundId=(-?\d+)")
_FG_TYPES_RE = re.compile(r"(?:\btypes|foregroundServiceType)=(\S+)")
_PROC_RE = re.compile(r"app=ProcessRecord\{\S+\s+(\d+):([^/\s}]+)")
_CREATE_RE = re.compile(r"createTime=(\S+)")


def decode_fgs_types(raw: str | None) -> list[str]:
    """Decode a foreground-service type value (``0x00000048``/``8``/labels)."""
    if not raw:
        return []
    text = raw.strip().rstrip(",")
    try:
        value = int(text, 16) if not text.isdigit() else int(text)
    except ValueError:
        return [t for t in re.split(r"[|,]", text) if t and t != "none"]
    if value in (0xFFFFFFFF, -1):
        return ["manifest"]
    if value == 0:
        return []
    names = [name for bit, name in FGS_TYPE_BITS.items() if value & bit]
    unknown = value & ~sum(FGS_TYPE_BITS)
    if unknown:
        names.append(f"0x{unknown:x}")
    return names


def parse_services(text: str, package: str) -> list[RunningService]:
    """Parse ``dumpsys activity services <pkg>`` into service records.

    Args:
        text: Raw dumpsys output.
        package: Records of other packages are dropped.

    Returns:
        The package's :class:`RunningService` records.
    """
    services: list[RunningService] = []
    current: RunningService | None = None
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        record = _SERVICE_RECORD_RE.search(line)
        if record:
            component = record.group(2)
            current = None
            if component.split("/")[0] == package:
                current = RunningService(component=component, user=int(record.group(1)))
                services.append(current)
            continue
        if current is None:
            continue
        fg = _FG_RE.search(line)
        if fg:
            current.foreground = fg.group(1) == "true"
            fg_id = _FG_ID_RE.search(line)
            if fg_id:
                current.foreground_id = int(fg_id.group(1))
        types = _FG_TYPES_RE.search(line)
        if types and ("isForeground" in line or "foregroundServiceType" in line):
            current.types_raw = types.group(1)
            current.types = decode_fgs_types(types.group(1))
        proc = _PROC_RE.search(line)
        if proc:
            current.pid, current.process = int(proc.group(1)), proc.group(2)
        create = _CREATE_RE.search(line)
        if create and current.created is None:
            current.created = create.group(1)
    return services


def get_running_services(package: str, serial: str | None = None) -> ServicesState:
    """Read *package*'s running services and foreground types (never raises).

    Args:
        package: Fully qualified package name.
        serial: Device serial; ``None`` = global target.

    Returns:
        A :class:`ServicesState`.
    """
    reason = _bad_package_reason(package)
    if reason:
        return ServicesState(package=package, ok=False, reason=reason)
    try:
        output = _adb(f"shell dumpsys activity services {shlex.quote(package)}", serial)
    except Exception as exc:
        logger.debug("services failed for %s: %s", package, exc)
        return ServicesState(package=package, ok=False, reason=str(exc))
    if not output.strip():
        return ServicesState(
            package=package, ok=False, reason="no dumpsys output (device offline?)"
        )
    return ServicesState(package=package, services=parse_services(output, package))


# ---------------------------------------------------------------------------
# Shared static cache
# ---------------------------------------------------------------------------


def default_apk_cache_root() -> Path:
    """Configured ``paths.apk_cache_path``, else ``~/.cache/sandroid/apk_cache``."""
    try:
        from sandroid.config import get_config

        configured = getattr(get_config().paths, "apk_cache_path", None)
        if configured:
            return Path(configured).expanduser()
    except Exception as exc:
        logger.debug("apk cache path from config unavailable: %s", exc)
    return Path("~/.cache/sandroid/apk_cache").expanduser()


def sha256_file(path: str | os.PathLike[str]) -> str:
    """SHA-256 hex digest of a local file (streamed)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compute_apk_key(split_sha256s: list[str]) -> str:
    """Cache key for an app from the sha256 of each installed split.

    One split (plain APK): the key is that sha256. Several splits: the key is
    the sha256 of the sorted per-split hex digests joined by newlines.

    Args:
        split_sha256s: Lower-case hex sha256 of every installed split.

    Returns:
        The key (64 hex chars).

    Raises:
        ValueError: *split_sha256s* is empty.
    """
    hashes = sorted(h.lower() for h in split_sha256s)
    if not hashes:
        raise ValueError("no split hashes")
    if len(hashes) == 1:
        return hashes[0]
    return hashlib.sha256("\n".join(hashes).encode("ascii")).hexdigest()


def parse_sha256sum_output(output: str) -> dict[str, str]:
    """Parse ``sha256sum <paths>`` output into ``{path: hex}``."""
    found = {}
    for line in (output or "").splitlines():
        match = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+)$", line.strip())
        if match:
            found[match.group(2).strip()] = match.group(1).lower()
    return found


def device_split_hashes(
    package: str, serial: str | None = None
) -> list[tuple[str, str]] | None:
    """Hash every installed split of *package* on the device.

    Returns:
        ``[(device_path, sha256), ...]`` (``pm path`` order), or ``None``
        when the package has no APK path or a split could not be hashed.
    """
    paths = parse_pm_path_output(
        _adb_stdout(f"shell pm path {shlex.quote(package)}", serial)
    )
    if not paths:
        return None
    command = "sha256sum " + " ".join(shlex.quote(p) for p in paths)
    # Hashing a few hundred MB of splits can exceed adb's 30s default.
    output = _adb(device_shell_command(command), serial, timeout=120)
    hashes = parse_sha256sum_output(output)
    if not all(p in hashes for p in paths):
        return None
    return [(p, hashes[p]) for p in paths]


class CacheLockTimeoutError(RuntimeError):
    """Raised when an entry's lock file could not be acquired in time."""


class ApkCache:
    """Shared, APK-keyed cache of static facts.

    Layout under ``root`` (shareable, e.g. a team share)::

        <root>/insight/                  Dexray Insight 2.x's own cache_dir
        <root>/apk/<key>/meta.json       splits, package, version, tools,
                                         created_at, Insight result info
        <root>/apk/<key>/overview.json   androguard-derived facts

    ``<key>`` is :func:`compute_apk_key`. Writes are atomic (temp file +
    ``os.replace``) and serialised per entry by a ``.lock`` file. Only
    APK-derived data belongs here, never device/runtime facts.

    Args:
        root: Cache root; defaults to :func:`default_apk_cache_root`.
        enabled: ``False`` makes every read miss and every write a no-op
            (the per-run "don't cache" switch).
        lock_timeout: Seconds to wait for an entry lock.
        stale_lock_after: A lock older than this is considered abandoned.
    """

    def __init__(
        self,
        root: str | os.PathLike[str] | None = None,
        *,
        enabled: bool = True,
        lock_timeout: float = 10.0,
        stale_lock_after: float = 120.0,
    ) -> None:
        self.root = Path(root).expanduser() if root else default_apk_cache_root()
        self.enabled = enabled
        self.lock_timeout = lock_timeout
        self.stale_lock_after = stale_lock_after

    @property
    def insight_dir(self) -> Path:
        """Directory handed to Dexray Insight as its analysis ``cache_dir``."""
        return self.root / "insight"

    @property
    def apk_dir(self) -> Path:
        """Parent of the per-APK entries."""
        return self.root / "apk"

    def entry_dir(self, key: str) -> Path:
        """Directory of one entry (key validated as 64 hex chars)."""
        if not re.fullmatch(r"[0-9a-f]{64}", key or ""):
            raise ValueError(f"invalid apk cache key {key!r}")
        return self.apk_dir / key

    # -- reading -------------------------------------------------------------

    def _read_json(self, key: str, name: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        try:
            with open(self.entry_dir(key) / name, encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    def read_meta(self, key: str) -> dict[str, Any] | None:
        """Return the entry's meta.json, or ``None`` on miss/disabled."""
        return self._read_json(key, "meta.json")

    def read_overview(self, key: str) -> dict[str, Any] | None:
        """Return the entry's overview.json if current, else ``None``."""
        data = self._read_json(key, "overview.json")
        if data is None or data.get("schema") != OVERVIEW_SCHEMA:
            return None
        return data

    def find(
        self, package: str, version_code: int | str | None = None
    ) -> list[tuple[str, dict[str, Any]]]:
        """Entries recorded for *package* (newest first), without hashing.

        Args:
            package: Package name to match.
            version_code: Optionally require this versionCode.

        Returns:
            ``[(key, meta), ...]`` sorted by ``updated_at`` descending.
        """
        if not self.enabled or not self.apk_dir.is_dir():
            return []
        found = []
        for entry in self.apk_dir.iterdir():
            meta = self._read_json(entry.name, "meta.json") if entry.is_dir() else None
            if not meta or meta.get("package") != package:
                continue
            if version_code is not None and str(meta.get("version_code")) != str(
                version_code
            ):
                continue
            found.append((entry.name, meta))
        found.sort(key=lambda kv: kv[1].get("updated_at") or "", reverse=True)
        return found

    # -- writing -------------------------------------------------------------

    @contextlib.contextmanager
    def _locked(self, key: str) -> Iterator[Path]:
        """Hold the entry's ``.lock`` file (O_EXCL create; stale locks broken)."""
        entry = self.entry_dir(key)
        entry.mkdir(parents=True, exist_ok=True)
        lock = entry / ".lock"
        deadline = time.monotonic() + self.lock_timeout
        while True:
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                with os.fdopen(fd, "w") as handle:
                    handle.write(f"{os.getpid()} {_utc_now()}\n")
                break
            except FileExistsError:
                try:
                    if time.time() - lock.stat().st_mtime > self.stale_lock_after:
                        lock.unlink(missing_ok=True)
                        continue
                except OSError:
                    continue
                if time.monotonic() > deadline:
                    raise CacheLockTimeoutError(f"lock busy: {lock}") from None
                time.sleep(0.05)
        try:
            yield entry
        finally:
            with contextlib.suppress(OSError):
                lock.unlink()

    @staticmethod
    def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
        """Write JSON via a temp file in the same dir + ``os.replace``."""
        fd, tmp = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True, default=str)
                handle.flush()
                os.fsync(handle.fileno())
            Path(tmp).replace(path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def write_entry(
        self,
        key: str,
        *,
        overview: dict[str, Any] | None = None,
        meta_updates: dict[str, Any] | None = None,
    ) -> bool:
        """Create/update an entry; meta.json is merged, overview replaced.

        Never raises; returns ``False`` when disabled or the write failed.

        Args:
            key: Entry key.
            overview: New overview.json content (``None`` keeps the old one).
            meta_updates: Top-level fields merged into meta.json
                (``created_at`` is kept, ``updated_at`` refreshed).
        """
        if not self.enabled:
            return False
        try:
            with self._locked(key) as entry:
                meta = self._read_json(key, "meta.json") or {}
                meta.update(meta_updates or {})
                meta["key"] = key
                meta.setdefault("created_at", _utc_now())
                meta["updated_at"] = _utc_now()
                if overview is not None:
                    self._atomic_write_json(entry / "overview.json", overview)
                self._atomic_write_json(entry / "meta.json", meta)
            return True
        except Exception as exc:
            logger.warning("apk cache write failed for %s: %s", key, exc)
            return False


# ---------------------------------------------------------------------------
# Static overview (androguard) + Insight results
# ---------------------------------------------------------------------------


def tool_versions() -> dict[str, str | None]:
    """Versions of the tools that produced cached facts."""
    from importlib import metadata

    versions: dict[str, str | None] = {}
    for dist in ("sandroid", "androguard", "dexray-insight"):
        try:
            versions[dist] = metadata.version(dist)
        except Exception:
            versions[dist] = None
    return versions


def _resolve_nsc_xml(apk: Any) -> tuple[Any, str | None]:
    """Find and decode the app's network security config, if any.

    Returns:
        ``(lxml root or None, path inside the APK or None)``.
    """
    _APK, _etree, AXMLPrinter = _androguard()
    attr = apk.get_attribute_value("application", "networkSecurityConfig")
    candidates: list[str] = []
    if attr:
        ref = str(attr).lstrip("@")
        if re.fullmatch(r"(0x)?[0-9a-fA-F]{8}", ref):
            with contextlib.suppress(Exception):
                resources = apk.get_android_resources()
                for _cfg, value in resources.get_resolved_res_configs(int(ref, 16)):
                    if value:
                        candidates.append(str(value))
        else:
            candidates.append(f"res/xml/{ref.split('/')[-1]}.xml")
    if not candidates:
        candidates = [
            f
            for f in apk.get_files()
            if f.startswith("res/xml/") and "network_security" in f
        ]
    for path in candidates:
        try:
            data = apk.get_file(path)
            if data:
                return AXMLPrinter(data).get_xml_obj(), path
        except Exception:
            continue
    return None, None


def _nsc_facts(apk: Any, target_sdk: int | None) -> dict[str, Any]:
    """Pin-sets, cleartext and user-CA trust from the APK's NSC + manifest."""
    android_ns = "{http://schemas.android.com/apk/res/android}"
    facts: dict[str, Any] = {
        "present": False,
        "path": None,
        "uses_cleartext_traffic": None,
        "cleartext_base": None,
        "cleartext_domains": [],
        "pin_sets": [],
        "trust_user_ca": False,
        "trust_user_ca_debug_only": False,
        "bundled_ca": False,
        "override_pins": False,
        "reason": None,
    }
    attr = apk.get_attribute_value("application", "usesCleartextTraffic")
    if attr is not None:
        facts["uses_cleartext_traffic"] = str(attr).lower() == "true"
    try:
        root, path = _resolve_nsc_xml(apk)
    except Exception as exc:
        facts["reason"] = f"NSC unreadable: {exc}"
        return facts
    if root is None:
        # Platform defaults: user CAs trusted only below targetSdk 24.
        facts["trust_user_ca"] = target_sdk is not None and target_sdk < 24
        return facts
    facts["present"], facts["path"] = True, path

    def attr_of(element: Any, name: str) -> str | None:
        return element.get(name) or element.get(f"{android_ns}{name}")

    def trust(scope: Any, debug: bool) -> None:
        for cert in scope.iter("certificates"):
            src = (attr_of(cert, "src") or "").lower()
            if src == "user":
                facts["trust_user_ca_debug_only" if debug else "trust_user_ca"] = True
            elif src.startswith("@"):
                facts["bundled_ca"] = True
            if (attr_of(cert, "overridePins") or "").lower() == "true":
                facts["override_pins"] = True

    for base in root.iter("base-config"):
        value = attr_of(base, "cleartextTrafficPermitted")
        if value is not None:
            facts["cleartext_base"] = value.lower() == "true"
        trust(base, debug=False)
    for overrides in root.iter("debug-overrides"):
        trust(overrides, debug=True)
    for domain_cfg in root.iter("domain-config"):
        domains = [(d.text or "").strip() for d in domain_cfg.findall("domain")]
        if (attr_of(domain_cfg, "cleartextTrafficPermitted") or "").lower() == "true":
            facts["cleartext_domains"].extend(domains)
        trust(domain_cfg, debug=False)
        for pin_set in domain_cfg.findall("pin-set"):
            facts["pin_sets"].append(
                {
                    "domains": domains,
                    "pins": len(pin_set.findall("pin")),
                    "expiration": attr_of(pin_set, "expiration"),
                }
            )
    if not any(True for _ in root.iter("base-config")):
        facts["trust_user_ca"] = facts["trust_user_ca"] or (
            target_sdk is not None and target_sdk < 24
        )
    return facts


def _signer_facts(apk: Any) -> dict[str, Any]:
    """Signing schemes and certificate fingerprints."""
    facts: dict[str, Any] = {"schemes": [], "certificates": []}
    for scheme, check in (
        ("v1", "is_signed_v1"),
        ("v2", "is_signed_v2"),
        ("v3", "is_signed_v3"),
    ):
        with contextlib.suppress(Exception):
            if getattr(apk, check)():
                facts["schemes"].append(scheme)
    try:
        certificates = apk.get_certificates()
    except Exception:
        certificates = []
    for cert in certificates:
        entry: dict[str, Any] = {}
        for key, getter in (
            ("subject", lambda c: c.subject.human_friendly),
            ("issuer", lambda c: c.issuer.human_friendly),
            ("sha256", lambda c: c.sha256_fingerprint.replace(" ", "").lower()),
            ("sha1", lambda c: c.sha1_fingerprint.replace(" ", "").lower()),
            ("serial", lambda c: str(c.serial_number)),
            ("not_after", lambda c: str(c.not_valid_after)),
        ):
            try:
                entry[key] = getter(cert)
            except Exception:
                entry[key] = None
        facts["certificates"].append(entry)
    return facts


def _deep_links(components: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """BROWSABLE intent-filter data entries (deep/app links)."""
    links = []
    for activity in components.get("activities", []):
        for intent_filter in activity.get("intent_filters", []):
            if "android.intent.category.BROWSABLE" not in intent_filter.get(
                "categories", []
            ):
                continue
            for data in intent_filter.get("data", []):
                if data.get("scheme") or data.get("host"):
                    links.append(
                        {
                            "component": activity.get("name"),
                            "exported": activity.get("exported"),
                            **data,
                        }
                    )
    return links


def _permission_protection(apk: Any) -> tuple[dict[str, str], dict[str, str]]:
    """``({requested: protection}, {declared: protection})`` from androguard."""
    requested: dict[str, str] = {}
    with contextlib.suppress(Exception):
        for name, details in apk.get_details_permissions().items():
            label = details[1] if len(details) > 1 else ""
            if "Unknown permission" in str(label):
                continue
            prot = normalize_protection(details[0] if details else None)
            if prot:
                requested[name] = prot
    declared: dict[str, str] = {}
    with contextlib.suppress(Exception):
        for name, details in apk.get_declared_permissions_details().items():
            prot = normalize_protection(details.get("protectionLevel"))
            if prot:
                declared[name] = prot
    return requested, declared


def build_apk_overview(apk_paths: list[str]) -> dict[str, Any]:
    """Decode local APK split(s) into the overview.json dict.

    Args:
        apk_paths: Local APK files, ``base.apk`` first.

    Returns:
        The overview dict (``schema``, ``package``, ``version_name``,
        ``version_code``, ``min_sdk``, ``target_sdk``, ``debuggable``,
        ``allow_backup``, ``components``, ``exported_without_permission_count``,
        ``deep_links``, ``permissions``, ``permission_protection``,
        ``declared_permissions``, ``nsc``, ``native_libs``,
        ``native_lib_paths``, ``abis``, ``signer``, ``splits``, ``errors``).

    Raises:
        AndroguardUnavailableError: androguard is not installed.
    """
    APK = androguard_apk_class()
    if APK is None:
        raise AndroguardUnavailableError("androguard is not installed")
    overview: dict[str, Any] = {"schema": OVERVIEW_SCHEMA, "errors": [], "splits": []}
    infos: list[dict[str, Any]] = []
    lib_paths: set[str] = set()
    base: Any = None
    for path in apk_paths:
        try:
            apk = APK(path)
        except Exception as exc:
            overview["errors"].append(f"{os.path.basename(path)}: {exc}")
            continue
        if base is None:
            base = apk
        split_name = None
        with contextlib.suppress(Exception):
            split_name = apk.get_attribute_value("manifest", "split")
        overview["splits"].append({"file": os.path.basename(path), "split": split_name})
        with contextlib.suppress(Exception):
            infos.append(_manifest_component_info(apk))
        with contextlib.suppress(Exception):
            lib_paths.update(
                f for f in apk.get_files() if f.startswith("lib/") and f.endswith(".so")
            )
    if base is None:
        return overview

    def safe(call: str, *args: Any) -> Any:
        try:
            return getattr(base, call)(*args)
        except Exception:
            return None

    def safe_int(call: str) -> int | None:
        value = safe(call)
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    target_sdk = safe_int("get_effective_target_sdk_version")
    overview.update(
        {
            "package": safe("get_package"),
            "version_name": safe("get_androidversion_name"),
            "version_code": safe_int("get_androidversion_code"),
            "min_sdk": safe_int("get_min_sdk_version"),
            "target_sdk": target_sdk,
            "debuggable": str(
                safe("get_attribute_value", "application", "debuggable")
            ).lower()
            == "true",
            "allow_backup": str(
                safe("get_attribute_value", "application", "allowBackup")
            ).lower()
            != "false",
        }
    )
    summary = summarize_exported_components(infos)
    overview["components"] = summary["components"]
    overview["exported_without_permission_count"] = summary[
        "exported_without_permission_count"
    ]
    overview["deep_links"] = _deep_links(summary["components"])
    requested_prot, declared_prot = _permission_protection(base)
    overview["permissions"] = sorted(safe("get_permissions") or [])
    overview["permission_protection"] = requested_prot
    overview["declared_permissions"] = declared_prot
    try:
        overview["nsc"] = _nsc_facts(base, target_sdk)
    except Exception as exc:
        overview["nsc"] = {"present": False, "reason": f"NSC unreadable: {exc}"}
    overview["native_lib_paths"] = sorted(lib_paths)
    overview["native_libs"] = sorted({os.path.basename(p) for p in lib_paths})
    overview["abis"] = sorted({p.split("/")[1] for p in lib_paths if p.count("/") >= 2})
    overview["signer"] = _signer_facts(base)
    return overview


@dataclass
class StaticOverview(_DictMixin):
    """Cached static facts of one installed app.

    Attributes:
        package: Package name.
        key: Cache key (see :func:`compute_apk_key`), ``None`` if unknown.
        overview: overview.json content (see :func:`build_apk_overview`).
        meta: meta.json content.
        insight: Insight results (full result JSON when the recorded file
            still exists, else the summary kept in meta.json), or ``None``.
        from_cache: The overview came from the cache (no pull).
        ok / reason: ``ok`` False means nothing usable; see ``reason``.
    """

    package: str
    key: str | None = None
    overview: dict[str, Any] | None = None
    meta: dict[str, Any] | None = None
    insight: dict[str, Any] | None = None
    from_cache: bool = False
    ok: bool = True
    reason: str | None = None


def load_insight_results(meta: dict[str, Any] | None) -> dict[str, Any] | None:
    """Insight results recorded in *meta* (full file if present, else summary)."""
    info = (meta or {}).get("insight") or {}
    result_file = info.get("result_file")
    if result_file and os.path.isfile(result_file):
        try:
            with open(result_file, encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
    summary = info.get("summary")
    return summary if isinstance(summary, dict) else None


def get_static_overview(
    package: str,
    serial: str | None = None,
    *,
    use_cache: bool = True,
    cache: ApkCache | None = None,
    allow_pull: bool = True,
) -> StaticOverview:
    """Static facts of an installed app, from the cache or a fresh pull.

    Hashes the installed split(s) on the device (``sha256sum``, no pull);
    on a cache hit returns immediately. Otherwise (and if *allow_pull*)
    pulls the split(s), decodes them with androguard and stores the result.

    Args:
        package: Fully qualified package name.
        serial: Device serial; ``None`` = global target.
        use_cache: ``False`` = neither read nor write the cache this run.
        cache: Cache to use; defaults to ``ApkCache()``.
        allow_pull: ``False`` = cache lookup only (cheap; for first paint).

    Returns:
        A :class:`StaticOverview` (never raises).
    """
    reason = _bad_package_reason(package)
    if reason:
        return StaticOverview(package=package, ok=False, reason=reason)
    cache = cache or ApkCache(enabled=use_cache)
    if not use_cache and cache.enabled:
        cache = ApkCache(cache.root, enabled=False)
    result = StaticOverview(package=package)
    try:
        hashes = device_split_hashes(package, serial)
        if hashes:
            result.key = compute_apk_key([h for _p, h in hashes])
            result.meta = cache.read_meta(result.key)
            result.overview = cache.read_overview(result.key)
            result.insight = load_insight_results(result.meta)
            if result.overview is not None:
                result.from_cache = True
                return result
        if not allow_pull:
            result.ok = False
            result.reason = (
                "not cached yet" if hashes else "could not hash APK on device"
            )
            return result
        if not androguard_available():
            result.ok = False
            result.reason = "androguard is not installed (static-analysis extra)"
            return result
        with tempfile.TemporaryDirectory(prefix="sandroid_app_lens_") as tmp_dir:
            pulled = _pull_apks(package, tmp_dir, serial)
            if not pulled:
                result.ok = False
                result.reason = "package not installed or APK pull failed"
                return result
            local_hashes = [sha256_file(local) for _d, local in pulled]
            if hashes and len(pulled) != len(hashes):
                result.ok = False
                result.reason = "only some splits could be pulled"
            key = compute_apk_key(local_hashes)
            overview = build_apk_overview([local for _d, local in pulled])
            splits = [
                {
                    "path": device_path,
                    "name": os.path.basename(device_path),
                    "sha256": digest,
                    "size": os.path.getsize(local),
                }
                for (device_path, local), digest in zip(
                    pulled, local_hashes, strict=True
                )
            ]
        result.key, result.overview = key, overview
        if result.ok:
            cache.write_entry(
                key,
                overview=overview,
                meta_updates={
                    "package": overview.get("package") or package,
                    "version_name": overview.get("version_name"),
                    "version_code": overview.get("version_code"),
                    "splits": splits,
                    "tool_versions": tool_versions(),
                },
            )
            result.meta = cache.read_meta(key)
            result.insight = load_insight_results(result.meta)
        return result
    except Exception as exc:
        logger.warning("static overview failed for %s: %s", package, exc)
        result.ok = False
        result.reason = str(exc)
        return result


def _insight_summary(results: dict[str, Any]) -> dict[str, Any]:
    """The small, defence-relevant subset of Insight results kept in meta.json."""
    apkid = results.get("apkid_analysis") or {}
    if isinstance(apkid, dict):
        apkid = {k: v for k, v in apkid.items() if k != "raw_output"}
    libraries = results.get("library_detection") or {}
    detected = (
        libraries.get("detected_libraries", []) if isinstance(libraries, dict) else []
    )
    keep = ("name", "package_name", "category", "version", "confidence", "vendor")
    overview = results.get("apk_overview") or {}
    return {
        "apkid_analysis": apkid,
        "library_detection": {
            "detected_libraries": [
                {k: lib.get(k) for k in keep}
                for lib in detected
                if isinstance(lib, dict)
            ]
        },
        "detected_protections": results.get("detected_protections"),
        "tracker_analysis": {
            "detected_protections": (results.get("tracker_analysis") or {}).get(
                "detected_protections"
            )
        },
        "apk_overview": {
            "native_libs": overview.get("native_libs", []),
            "cross_platform_framework": overview.get("cross_platform_framework"),
        },
    }


def record_insight_result(
    split_sha256s: list[str],
    analysis_results: dict[str, Any],
    *,
    result_file: str | None = None,
    security_result_file: str | None = None,
    insight_version: str | None = None,
    insight_cache_dir: str | None = None,
    package: str | None = None,
    cache: ApkCache | None = None,
) -> str | None:
    """Record a Dexray Insight run in the APK cache's meta.json.

    Args:
        split_sha256s: sha256 of every split of the analysed app.
        analysis_results: Insight's main result dict.
        result_file / security_result_file: Paths of the written JSON files.
        insight_version: Insight version string.
        insight_cache_dir: The cache dir Insight was given (if any).
        package: Package name if not derivable from the results.
        cache: Cache to use; defaults to ``ApkCache()``.

    Returns:
        The entry key, or ``None`` when nothing was recorded (never raises).
    """
    try:
        cache = cache or ApkCache()
        if not cache.enabled or not split_sha256s:
            return None
        key = compute_apk_key(split_sha256s)
        general = ((analysis_results or {}).get("apk_overview") or {}).get(
            "general_info"
        ) or {}
        updates: dict[str, Any] = {
            "insight": {
                "result_file": os.path.abspath(result_file) if result_file else None,
                "security_result_file": (
                    os.path.abspath(security_result_file)
                    if security_result_file
                    else None
                ),
                "version": insight_version,
                "cache_dir": insight_cache_dir,
                "recorded_at": _utc_now(),
                "summary": _insight_summary(analysis_results or {}),
            }
        }
        existing = cache.read_meta(key) or {}
        if not existing.get("package"):
            updates["package"] = general.get("package_name") or package
        if not existing.get("version_name"):
            updates["version_name"] = general.get("android_version_name")
            updates["version_code"] = general.get("android_version_code")
        if "splits" not in existing:
            updates["splits"] = [{"sha256": h} for h in split_sha256s]
        updates["tool_versions"] = {
            **(existing.get("tool_versions") or {}),
            **tool_versions(),
        }
        return key if cache.write_entry(key, meta_updates=updates) else None
    except Exception as exc:
        logger.warning("recording Insight result in apk cache failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Suspected defences
# ---------------------------------------------------------------------------


@dataclass
class SuspectedDefence(_DictMixin):
    """A protection the app probably has, from static facts only.

    Attributes:
        id: Stable id (``"root:rootbeer"``) for dedup/UI keys.
        category: ``root``/``integrity``/``debug``/``emulator``/``frida``/
            ``rasp``/``packer``/``obfuscator``/``tls_stack``/``pinning``/
            ``cleartext``/``user_ca``.
        title: Short label.
        evidence: Human-readable evidence strings.
        routes: Suggested keys: ``h`` friTap, ``b1``..``b6`` bypass digits
            (b1 ssl, b2 root, b3 frida, b4 debug, b5 integrity, b6
            emulator), ``v`` verify.
        hint: One-line advice for the route.
        source: ``apkid``/``library``/``native_libs``/``nsc``/
            ``insight_protections``/``files``.
        weakness: True for facts that *ease* analysis (cleartext, user CA).
        status: Always ``"suspected (static)"``.
    """

    id: str
    category: str
    title: str
    evidence: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    hint: str = ""
    source: str = ""
    weakness: bool = False
    status: str = STATIC_STATUS


_ALL_BYPASSES = ["b2", "b3", "b4", "b5", "b6"]

#: (needle in lower-cased library name/package, id, category, title, routes, hint)
PROTECTION_LIBRARIES: tuple[
    tuple[tuple[str, ...], str, str, str, list[str], str], ...
] = (
    (("rootbeer",), "rootbeer", "root", "RootBeer", ["b2"], "Root checks; b2."),
    (
        ("jailmonkey",),
        "jailmonkey",
        "root",
        "JailMonkey",
        ["b2"],
        "RN root/debug checks; b2 (native su probes may need more).",
    ),
    (
        ("pairip",),
        "pairip",
        "integrity",
        "PairIP license check",
        ["b5"],
        "Play license/integrity gate; b5.",
    ),
    (
        ("play integrity", "play.core.integrity", "playintegrity", "integrity api"),
        "play_integrity",
        "integrity",
        "Play Integrity",
        ["b5"],
        "Server-verified verdict; b5 only hides the client side.",
    ),
    (
        ("safetynet",),
        "safetynet",
        "integrity",
        "SafetyNet",
        ["b5"],
        "Attestation; b5.",
    ),
    (
        ("freerasp", "talsec"),
        "freerasp",
        "rasp",
        "freeRASP (Talsec)",
        _ALL_BYPASSES,
        "RASP: root, hook, debug, emulator and tamper checks.",
    ),
    (
        ("promon",),
        "promon",
        "rasp",
        "Promon SHIELD",
        _ALL_BYPASSES,
        "Native RASP; expect several detections at once.",
    ),
    (
        ("dexguard", "guardsquare"),
        "dexguard",
        "rasp",
        "DexGuard",
        _ALL_BYPASSES + ["v"],
        "Obfuscation + RASP checks.",
    ),
    (
        ("appdome",),
        "appdome",
        "rasp",
        "Appdome",
        _ALL_BYPASSES,
        "Injected RASP; several detections at once.",
    ),
    (("trustkit",), "trustkit", "pinning", "TrustKit", ["b1"], "Pinning; b1."),
)

#: Native-lib basename prefix -> (id, category, title, routes, hint).
NATIVE_TLS_LIBS: tuple[tuple[str, str, str, str, list[str], str], ...] = (
    (
        "libflutter",
        "flutter_tls",
        "tls_stack",
        "Flutter (own BoringSSL)",
        ["h"],
        "TLS lives inside libflutter.so: b1 cannot reach it and friTap may "
        "miss it (stripped symbols); try h, expect pattern-based hooks.",
    ),
    (
        "libnss3",
        "nss_tls",
        "tls_stack",
        "NSS (own CA store)",
        ["h"],
        "NSS ignores the Android trust store: use friTap (h), not b1.",
    ),
    (
        "libcronet",
        "cronet_tls",
        "tls_stack",
        "Cronet (Chromium net stack)",
        ["h", "b1"],
        "Own BoringSSL; keys via h, cert checks may still hit b1.",
    ),
    (
        "libconscrypt",
        "conscrypt_tls",
        "tls_stack",
        "Bundled Conscrypt",
        ["b1", "h"],
        "App-bundled Conscrypt provider; b1 usually works, h for keys.",
    ),
    (
        "libssl",
        "openssl_tls",
        "tls_stack",
        "Bundled OpenSSL/BoringSSL",
        ["h"],
        "Native TLS outside the platform stack; friTap (h).",
    ),
    (
        "libcrypto",
        "openssl_tls",
        "tls_stack",
        "Bundled OpenSSL/BoringSSL",
        ["h"],
        "Native TLS outside the platform stack; friTap (h).",
    ),
)

#: Native-lib basename prefix -> library protection id (file-only evidence).
NATIVE_PROTECTION_LIBS = {
    "libpairipcore": "pairip",
}

_APKID_CATEGORIES = {
    "anti_vm": ("emulator", "Emulator detection", ["b6"], "Emulator checks; b6."),
    "anti_debug": ("debug", "Debugger detection", ["b4"], "Debug checks; b4."),
    "packer": (
        "packer",
        "Packer",
        ["v"],
        "Packed code: static facts may be incomplete; verify dynamically.",
    ),
    "obfuscator": (
        "obfuscator",
        "Obfuscator",
        ["v"],
        "Obfuscated: names are unreliable; verify dynamically.",
    ),
    "anti_disassembly": (
        "obfuscator",
        "Anti-disassembly",
        ["v"],
        "Anti-disassembly tricks; verify dynamically.",
    ),
}

#: Keyword in an Insight protection's category/name -> routes.
_PROTECTION_KEYWORD_ROUTES = (
    (("root", "jailbreak"), "root", ["b2"]),
    (
        ("integrity", "attestation", "safetynet", "license", "pairip"),
        "integrity",
        ["b5"],
    ),
    (("frida", "hook", "instrument", "xposed"), "frida", ["b3"]),
    (("debug",), "debug", ["b4"]),
    (("emulator", "anti_vm", "virtual"), "emulator", ["b6"]),
    (("pinning", "ssl", "tls", "certificate"), "pinning", ["b1"]),
    (("rasp", "tamper"), "rasp", _ALL_BYPASSES),
)


def _iter_apkid_matches(apkid: Any) -> Iterator[tuple[str, str, str]]:
    """Yield ``(filename, category, match)`` from Insight's apkid_analysis."""
    if not isinstance(apkid, dict):
        return
    for file_entry in apkid.get("files") or []:
        if not isinstance(file_entry, dict):
            continue
        filename = str(file_entry.get("filename", "?")).split("!")[-1]
        for category, matches in (file_entry.get("matches") or {}).items():
            for match in matches or []:
                yield filename, category, str(match)


def _library_entries(insight: dict[str, Any]) -> list[dict[str, Any]]:
    """Detected libraries from Insight results (both 1.x and 2.x shapes)."""
    libraries = insight.get("library_detection")
    if isinstance(libraries, dict):
        libraries = libraries.get("detected_libraries")
    return [lib for lib in libraries or [] if isinstance(lib, dict)]


def _protection_entries(raw: Any) -> list[dict[str, Any]]:
    """Normalise Insight ``detected_protections`` (list/dict/strings)."""
    if isinstance(raw, dict):
        if isinstance(raw.get("protections"), list):
            raw = raw["protections"]
        else:
            raw = [
                {"name": k, **(v if isinstance(v, dict) else {"evidence": v})}
                for k, v in raw.items()
            ]
    entries = []
    for item in raw or []:
        if isinstance(item, str):
            entries.append({"name": item})
        elif isinstance(item, dict):
            entries.append(item)
    return entries


#: Insight ``defeats`` values (Sandroid's bypass categories) -> route keys.
DEFEAT_ROUTES = {
    "ssl": "b1",
    "root": "b2",
    "frida": "b3",
    "debug": "b4",
    "integrity": "b5",
    "emulator": "b6",
}


def _slug(text: str) -> str:
    """Lower-case id fragment."""
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _protection_defence(item: dict[str, Any]) -> SuspectedDefence:
    """Turn one Insight ``detected_protections`` entry into a defence.

    Routes come from ``defeats`` when present, else from keywords in the
    category/name. Entries naming a known protection library reuse that
    library's id, so library detection and Insight merge into one row.
    """
    name = str(item.get("name") or item.get("protection") or item.get("type") or "?")
    category_text = str(item.get("category") or item.get("type") or name).lower()
    cat, routes = "rasp", ["v"]
    for keywords, kw_cat, kw_routes in _PROTECTION_KEYWORD_ROUTES:
        if any(k in category_text or k in name.lower() for k in keywords):
            cat, routes = kw_cat, list(kw_routes)
            break
    defeats = item.get("defeats")
    if isinstance(defeats, list) and defeats:
        mapped = [DEFEAT_ROUTES[d] for d in defeats if d in DEFEAT_ROUTES]
        if mapped:
            routes = sorted(set(mapped))
            if len(mapped) > 2:
                cat = "rasp"
    defence_id = f"insight:{_slug(str(item.get('id') or name))}"
    lowered = name.lower()
    for needles, lib_id, lib_cat, _title, _routes, _hint in PROTECTION_LIBRARIES:
        if any(n in lowered for n in needles):
            defence_id, cat = f"lib:{lib_id}", lib_cat
            break
    evidence_lines: list[str] = []
    evidence = item.get("evidence")
    if isinstance(evidence, list):
        evidence_lines += [f"Insight: {e}" for e in evidence[:5]]
    elif evidence:
        evidence_lines.append(f"Insight: {evidence}")
    for key, label in (("matched_classes", "class"), ("matched_libs", "native lib")):
        values = item.get(key)
        if isinstance(values, list):
            evidence_lines += [f"Insight {label}: {v}" for v in values[:3]]
    if not evidence_lines:
        evidence_lines.append(f"Insight detected {name}")
    if item.get("confidence"):
        evidence_lines.append(f"Insight confidence: {item['confidence']}")
    return SuspectedDefence(
        id=defence_id,
        category=cat,
        title=name,
        evidence=evidence_lines,
        routes=routes,
        hint=str(item.get("description") or ""),
        source="insight_protections",
    )


def suspect_defences(
    overview: dict[str, Any] | None, insight: dict[str, Any] | None = None
) -> list[SuspectedDefence]:
    """Derive suspected defences from cached static facts (pure function).

    Sources: APKiD categories (anti_vm/anti_debug/packer/obfuscator),
    Insight library detection matched against :data:`PROTECTION_LIBRARIES`,
    native libs (TLS stacks, PairIP core), the network security config
    (pin-sets, cleartext, user-CA trust) and Insight ``detected_protections``
    when present.

    Args:
        overview: overview.json dict (may be ``None``).
        insight: Insight result dict, a ``{"main": ...}`` cache payload or the
            meta.json summary (may be ``None``).

    Returns:
        Deduplicated :class:`SuspectedDefence` list, defences before
        weaknesses.
    """
    overview = overview or {}
    insight = insight or {}
    if isinstance(insight.get("main"), dict):
        insight = insight["main"]
    found: dict[str, SuspectedDefence] = {}

    def add(item: SuspectedDefence) -> None:
        if item.id in found:
            existing = found[item.id]
            for line in item.evidence:
                if line not in existing.evidence:
                    existing.evidence.append(line)
            for route in item.routes:
                if route not in existing.routes:
                    existing.routes.append(route)
        else:
            found[item.id] = item

    # APKiD
    for filename, category, match in _iter_apkid_matches(insight.get("apkid_analysis")):
        spec = _APKID_CATEGORIES.get(category)
        if not spec:
            continue
        cat, title, routes, hint = spec
        add(
            SuspectedDefence(
                id=f"apkid:{category}",
                category=cat,
                title=title,
                evidence=[f"APKiD {category}: {match} ({filename})"],
                routes=list(routes),
                hint=hint,
                source="apkid",
            )
        )

    # Library detection
    for lib in _library_entries(insight):
        haystack = " ".join(
            str(lib.get(k) or "") for k in ("name", "package_name", "vendor")
        ).lower()
        for needles, lib_id, cat, title, routes, hint in PROTECTION_LIBRARIES:
            if any(n in haystack for n in needles):
                label = lib.get("name") or lib.get("package_name")
                add(
                    SuspectedDefence(
                        id=f"lib:{lib_id}",
                        category=cat,
                        title=title,
                        evidence=[f"library detected: {label}"],
                        routes=list(routes),
                        hint=hint,
                        source="library",
                    )
                )

    # Native libraries (overview first, Insight's list as fallback)
    native = list(overview.get("native_libs") or [])
    insight_native = (insight.get("apk_overview") or {}).get("native_libs") or []
    native += [os.path.basename(str(p)) for p in insight_native]
    for lib in sorted(set(native)):
        for prefix, lib_id, cat, title, routes, hint in NATIVE_TLS_LIBS:
            if lib.startswith(prefix):
                add(
                    SuspectedDefence(
                        id=f"native:{lib_id}",
                        category=cat,
                        title=title,
                        evidence=[f"native lib {lib}"],
                        routes=list(routes),
                        hint=hint,
                        source="native_libs",
                    )
                )
        for prefix, lib_id in NATIVE_PROTECTION_LIBS.items():
            if lib.startswith(prefix):
                spec = next(p for p in PROTECTION_LIBRARIES if p[1] == lib_id)
                add(
                    SuspectedDefence(
                        id=f"lib:{lib_id}",
                        category=spec[2],
                        title=spec[3],
                        evidence=[f"native lib {lib}"],
                        routes=list(spec[4]),
                        hint=spec[5],
                        source="native_libs",
                    )
                )

    # Network security config
    nsc = overview.get("nsc") or {}
    if nsc.get("pin_sets"):
        domains = sorted({d for p in nsc["pin_sets"] for d in p.get("domains", [])})
        add(
            SuspectedDefence(
                id="nsc:pinning",
                category="pinning",
                title="NSC certificate pinning",
                evidence=[f"pin-set for {', '.join(domains) or '?'}"],
                routes=["b1", "h"],
                hint="Platform pinning via NSC; b1 covers it, h as fallback.",
                source="nsc",
            )
        )
    cleartext = []
    if nsc.get("cleartext_base"):
        cleartext.append("base-config cleartextTrafficPermitted=true")
    if nsc.get("cleartext_domains"):
        cleartext.append("cleartext for " + ", ".join(nsc["cleartext_domains"]))
    if nsc.get("uses_cleartext_traffic"):
        cleartext.append('android:usesCleartextTraffic="true"')
    if cleartext:
        add(
            SuspectedDefence(
                id="nsc:cleartext",
                category="cleartext",
                title="Cleartext traffic allowed",
                evidence=cleartext,
                hint="Some traffic may be readable in the proxy without a CA.",
                source="nsc",
                weakness=True,
            )
        )
    if nsc.get("trust_user_ca"):
        add(
            SuspectedDefence(
                id="nsc:user_ca",
                category="user_ca",
                title="User CAs trusted",
                evidence=[
                    (
                        "NSC trusts user certificates"
                        if nsc.get("present")
                        else "targetSdk < 24: user CAs trusted by default"
                    )
                ],
                hint="A user-installed proxy CA is enough; no system CA needed.",
                source="nsc",
                weakness=True,
            )
        )

    # Insight detected_protections: tracker_analysis.detected_protections in
    # Insight >= 2.0 (id, name, category, defeats, confidence,
    # matched_classes, matched_libs); a top-level key is honoured too.
    tracker = insight.get("tracker_analysis")
    raw_protections = _protection_entries(insight.get("detected_protections"))
    if isinstance(tracker, dict):
        raw_protections += _protection_entries(tracker.get("detected_protections"))
    for item in raw_protections:
        add(_protection_defence(item))

    return sorted(found.values(), key=lambda d: (d.weakness, d.category, d.id))


# ---------------------------------------------------------------------------
# Facade
# ---------------------------------------------------------------------------


class AppInfoService:
    """Serial- and cache-bound facade the App lens calls (off the UI thread).

    Args:
        serial: Device serial captured on the UI thread (``None`` = global).
        use_cache: Per-run "don't cache" switch for static facts.
        cache_root: Override the cache root (default: config).
    """

    def __init__(
        self,
        serial: str | None = None,
        *,
        use_cache: bool = True,
        cache_root: str | os.PathLike[str] | None = None,
    ) -> None:
        self.serial = serial
        self.use_cache = use_cache
        self.cache = ApkCache(cache_root, enabled=use_cache)

    def details(self, package: str) -> dict[str, Any]:
        """See :func:`get_package_details`."""
        return get_package_details(package, self.serial)

    def permissions(
        self, package: str, overview: dict[str, Any] | None = None
    ) -> PermissionState:
        """See :func:`get_permission_state`; *overview* adds manifest levels."""
        protection = (overview or {}).get("permission_protection")
        return get_permission_state(
            package, self.serial, manifest_protection=protection
        )

    def appops(self, package: str) -> AppOpsState:
        """See :func:`get_appops`."""
        return get_appops(package, self.serial)

    def footprint(self, package: str) -> DataFootprint:
        """See :func:`get_data_footprint`."""
        return get_data_footprint(package, self.serial)

    def services(self, package: str) -> ServicesState:
        """See :func:`get_running_services`."""
        return get_running_services(package, self.serial)

    def static_overview(
        self, package: str, *, allow_pull: bool = True
    ) -> StaticOverview:
        """See :func:`get_static_overview`."""
        return get_static_overview(
            package,
            self.serial,
            use_cache=self.use_cache,
            cache=self.cache,
            allow_pull=allow_pull,
        )

    @staticmethod
    def defences(static: StaticOverview) -> list[SuspectedDefence]:
        """See :func:`suspect_defences`."""
        return suspect_defences(static.overview, static.insight)
