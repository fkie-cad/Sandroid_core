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
import fnmatch
import hashlib
import json
import logging
import os
import re
import shlex
import subprocess
import tempfile
import threading
import time
import uuid
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
OVERVIEW_SCHEMA = 2

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


def _adb_raw(command: str, serial: str | None) -> tuple[str, str]:
    """Run adb returning ``(stdout, stderr)``; exceptions propagate.

    Used by the functions the AI tools wrap, which keep their original
    error behaviour (a failing adb layer raises into the tool dispatcher).
    """
    if serial is None:
        return Adb.send_adb_command(command)
    return Adb.send_adb_command(command, serial=serial)


def _bad_package_reason(package: str) -> str | None:
    """Reason string when *package* is not a valid package name, else None."""
    if not is_valid_package_name(package):
        return f"invalid package name {package!r}"
    return None


def _utc_now() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def _as_dict(value: Any) -> dict[str, Any]:
    """*value* if it is a dict, else ``{}`` (shared JSON is untrusted)."""
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    """*value* if it is a list, else ``[]`` (shared JSON is untrusted)."""
    return value if isinstance(value, list) else []


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
    stdout, _stderr = _adb_raw(f"shell dumpsys package {shlex.quote(package)}", serial)
    details = parse_extended_package_info(stdout or "")
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
    stdout, _stderr = _adb_raw(f"shell pm path {shlex.quote(package)}", serial)
    device_paths = parse_pm_path_output(stdout)
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
        restricted: Hard/soft restricted (``restricted=true`` or the
            ``APPLY_RESTRICTION`` flag; ``RESTRICTION_*_EXEMPT`` flags mean
            the opposite and are ignored).
        protection: Base protection level (``dangerous``/``normal``/
            ``signature``...) or ``None`` when unknown.
        protection_source: Where *protection* came from: ``"dumpsys"``,
            ``"manifest"``, ``"pm"``, ``"runtime-section"`` or ``None``.
        revoked / revoked_reason: ``granted=true`` but effectively denied
            (``REVOKED_COMPAT`` flag, or a uid AppOps mode ignore/deny via
            :func:`apply_appops_revocations`).
    """

    name: str
    requested: bool = False
    kind: str = "requested"
    granted: bool | None = None
    flags: list[str] = field(default_factory=list)
    restricted: bool = False
    protection: str | None = None
    protection_source: str | None = None
    revoked: bool = False
    revoked_reason: str | None = None

    @property
    def effective_granted(self) -> bool | None:
        """``granted`` unless the grant is revoked (``REVOKED_COMPAT``/AppOps)."""
        return False if self.granted and self.revoked else self.granted


@dataclass
class PermissionState(_DictMixin):
    """All permissions of one package; ``ok`` False means see ``reason``.

    ``shared_user`` names the shared uid (``android.uid.system``) whose
    ``SharedUser`` block holds the grants of a shared-uid package.
    """

    package: str
    permissions: list[PermissionGrant] = field(default_factory=list)
    declared: dict[str, str] = field(default_factory=dict)
    shared_user: str | None = None
    ok: bool = True
    reason: str | None = None


_PERM_LINE_RE = re.compile(r"^([^\s:]+)(?::\s*(.*))?$")
_SHARED_USER_RE = re.compile(r"sharedUser=SharedUserSetting\{\S+\s+([^/\s}]+)")
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
    return _named_block(lines, f"Package [{package}]")


def _named_block(lines: list[str], marker: str) -> list[str]:
    """Lines of the first block whose header starts with *marker* (or ``[]``)."""
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

    def apply_sections(section_block: list[str], *, requested: bool) -> None:
        runtime_seen = False
        for index, line in enumerate(section_block):
            header = line.strip()
            if header == "requested permissions:" and requested:
                for entry in _section(section_block, index):
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
                for entry in _section(section_block, index):
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
                        item.flags = [
                            f.strip() for f in flags.group(1).split("|") if f.strip()
                        ]
                    if "APPLY_RESTRICTION" in item.flags:
                        item.restricted = True
            elif header == "declared permissions:":
                for entry in _section(section_block, index):
                    match = _PERM_LINE_RE.match(entry)
                    prot = _PROT_RE.search(entry)
                    if match and prot:
                        declared.setdefault(
                            match.group(1), normalize_protection(prot.group(1)) or ""
                        )

    apply_sections(block, requested=True)
    # Shared-uid packages (e.g. android.uid.system): the uid's grants live in
    # "Shared users:" -> "SharedUser [<name>]" -> "User 0:" -> runtime/install.
    shared = _SHARED_USER_RE.search("\n".join(block))
    if shared:
        state.shared_user = shared.group(1)
        shared_block = _named_block(lines, f"SharedUser [{state.shared_user}]")
        apply_sections(shared_block, requested=False)

    for item in grants.values():
        if item.granted and "REVOKED_COMPAT" in item.flags:
            item.revoked = True
            item.revoked_reason = "REVOKED_COMPAT (legacy app: AppOps denies it)"

    dangerous = dangerous or set()
    manifest_protection = _as_dict(manifest_protection)
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


def apply_appops_revocations(state: PermissionState, appops: Any) -> PermissionState:
    """Mark granted permissions whose AppOps uid mode is ignore/deny as revoked.

    A ``granted=true`` runtime permission is still effectively denied when
    its op is ignored/denied at uid level (``REVOKED_COMPAT`` and the like).
    Idempotent; tolerates a missing or failed :class:`AppOpsState`.

    Args:
        state: Parsed permission state (mutated in place).
        appops: An :class:`AppOpsState` (or anything with ``ops``).

    Returns:
        *state*.
    """
    by_perm: dict[str, list[Any]] = {}
    for op in getattr(appops, "ops", None) or []:
        if getattr(op, "permission", None):
            by_perm.setdefault(op.permission, []).append(op)
    for item in state.permissions:
        if not item.granted or item.revoked:
            continue
        for op in by_perm.get(item.name, []):
            if op.uid_mode in ("ignore", "deny"):
                item.revoked = True
                item.revoked_reason = f"AppOps {op.op} uid mode {op.uid_mode}"
                break
    return state


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

_FG_STATES = {"top", "fg", "fgsvc", "fgsvcl", "pers", "fgs"}

#: AppOps op names in op-code order (``AppOpsManager.OP_*``). AOSP prints
#: each uid/package block sorted by op code, so in ``cmd appops get`` an op
#: whose code is not above the highest one seen starts a new (package) block.
#: Verified against a real API 35 dump: 533 uid/package blocks of
#: ``dumpsys appops`` (17.8k adjacent op pairs) are all in this order.
_OP_ORDER_TEXT = (
    "COARSE_LOCATION FINE_LOCATION GPS VIBRATE READ_CONTACTS WRITE_CONTACTS "
    "READ_CALL_LOG WRITE_CALL_LOG READ_CALENDAR WRITE_CALENDAR WIFI_SCAN "
    "POST_NOTIFICATION NEIGHBORING_CELLS CALL_PHONE READ_SMS WRITE_SMS "
    "RECEIVE_SMS RECEIVE_EMERGENCY_BROADCAST RECEIVE_MMS RECEIVE_WAP_PUSH "
    "SEND_SMS READ_ICC_SMS WRITE_ICC_SMS WRITE_SETTINGS SYSTEM_ALERT_WINDOW "
    "ACCESS_NOTIFICATIONS CAMERA RECORD_AUDIO PLAY_AUDIO READ_CLIPBOARD "
    "WRITE_CLIPBOARD TAKE_MEDIA_BUTTONS TAKE_AUDIO_FOCUS AUDIO_MASTER_VOLUME "
    "AUDIO_VOICE_VOLUME AUDIO_RING_VOLUME AUDIO_MEDIA_VOLUME AUDIO_ALARM_VOLUME "
    "AUDIO_NOTIFICATION_VOLUME AUDIO_BLUETOOTH_VOLUME WAKE_LOCK "
    "MONITOR_LOCATION MONITOR_HIGH_POWER_LOCATION GET_USAGE_STATS "
    "MUTE_MICROPHONE TOAST_WINDOW PROJECT_MEDIA ACTIVATE_VPN WRITE_WALLPAPER "
    "ASSIST_STRUCTURE ASSIST_SCREENSHOT READ_PHONE_STATE ADD_VOICEMAIL USE_SIP "
    "PROCESS_OUTGOING_CALLS USE_FINGERPRINT BODY_SENSORS READ_CELL_BROADCASTS "
    "MOCK_LOCATION READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE TURN_SCREEN_ON "
    "GET_ACCOUNTS RUN_IN_BACKGROUND AUDIO_ACCESSIBILITY_VOLUME "
    "READ_PHONE_NUMBERS REQUEST_INSTALL_PACKAGES PICTURE_IN_PICTURE "
    "INSTANT_APP_START_FOREGROUND ANSWER_PHONE_CALLS RUN_ANY_IN_BACKGROUND "
    "CHANGE_WIFI_STATE REQUEST_DELETE_PACKAGES BIND_ACCESSIBILITY_SERVICE "
    "ACCEPT_HANDOVER MANAGE_IPSEC_TUNNELS START_FOREGROUND BLUETOOTH_SCAN "
    "USE_BIOMETRIC ACTIVITY_RECOGNITION SMS_FINANCIAL_TRANSACTIONS "
    "READ_MEDIA_AUDIO WRITE_MEDIA_AUDIO READ_MEDIA_VIDEO WRITE_MEDIA_VIDEO "
    "READ_MEDIA_IMAGES WRITE_MEDIA_IMAGES LEGACY_STORAGE ACCESS_ACCESSIBILITY "
    "READ_DEVICE_IDENTIFIERS ACCESS_MEDIA_LOCATION QUERY_ALL_PACKAGES "
    "MANAGE_EXTERNAL_STORAGE INTERACT_ACROSS_PROFILES ACTIVATE_PLATFORM_VPN "
    "LOADER_USAGE_STATS DEPRECATED_1 AUTO_REVOKE_PERMISSIONS_IF_UNUSED "
    "AUTO_REVOKE_MANAGED_BY_INSTALLER NO_ISOLATED_STORAGE PHONE_CALL_MICROPHONE "
    "PHONE_CALL_CAMERA RECORD_AUDIO_HOTWORD MANAGE_ONGOING_CALLS "
    "MANAGE_CREDENTIALS USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER RECORD_AUDIO_OUTPUT "
    "SCHEDULE_EXACT_ALARM FINE_LOCATION_SOURCE COARSE_LOCATION_SOURCE "
    "MANAGE_MEDIA BLUETOOTH_CONNECT UWB_RANGING ACTIVITY_RECOGNITION_SOURCE "
    "BLUETOOTH_ADVERTISE RECORD_INCOMING_PHONE_AUDIO NEARBY_WIFI_DEVICES "
    "ESTABLISH_VPN_SERVICE ESTABLISH_VPN_MANAGER ACCESS_RESTRICTED_SETTINGS "
    "RECEIVE_AMBIENT_TRIGGER_AUDIO RECEIVE_EXPLICIT_USER_INTERACTION_AUDIO "
    "RUN_USER_INITIATED_JOBS READ_MEDIA_VISUAL_USER_SELECTED "
    "SYSTEM_EXEMPT_FROM_SUSPENSION SYSTEM_EXEMPT_FROM_DISMISSIBLE_NOTIFICATIONS "
    "READ_WRITE_HEALTH_DATA FOREGROUND_SERVICE_SPECIAL_USE "
    "SYSTEM_EXEMPT_FROM_POWER_RESTRICTIONS SYSTEM_EXEMPT_FROM_HIBERNATION "
    "SYSTEM_EXEMPT_FROM_ACTIVITY_BG_START_RESTRICTION "
    "CAPTURE_CONSENTLESS_BUGREPORT_ON_USERDEBUG_BUILD "
    "BODY_SENSORS_WRIST_TEMPERATURE USE_FULL_SCREEN_INTENT CAMERA_SANDBOXED "
    "RECORD_AUDIO_SANDBOXED RECEIVE_SANDBOX_TRIGGER_AUDIO "
    "RECEIVE_SANDBOXED_DETECTION_TRAINING_DATA CREATE_ACCESSIBILITY_OVERLAY "
    "MEDIA_ROUTING_CONTROL ENABLE_MOBILE_DATA_BY_USER RESERVED_FOR_TESTING "
    "RAPID_CLEAR_NOTIFICATIONS_BY_LISTENER_IMPORTANCE "
    "READ_SYSTEM_GRAMMATICAL_GENDER RUN_BACKUP_JOBS ARCHIVE_ICON_OVERLAY "
    "UNARCHIVAL_CONFIRMATION EMERGENCY_LOCATION RECEIVE_SENSITIVE_NOTIFICATIONS"
)
_OP_ORDER = _OP_ORDER_TEXT.split()
_OP_CODE = {name: code for code, name in enumerate(_OP_ORDER)}
_BG_STATES = {"bg", "cch", "cached"}


@dataclass
class AppOpEntry(_DictMixin):
    """One AppOps op of a package (uid- and package-level state merged).

    Times are kept both raw (as printed) and as "seconds ago" when parsable.

    Attributes:
        op: Op name (``CAMERA``, ``READ_CLIPBOARD`` ...).
        mode: Effective mode: the uid-level mode when one is set (it wins in
            ``AppOpsService.checkOperation``), else the package mode.
        uid_mode: Uid-level mode, ``None`` if not set.
        package_mode: Package-level mode, ``None`` if not printed.
        permission: Matching runtime permission, ``None`` if the op has none.
        last_access / last_access_ago_s: Last access (raw text / seconds ago).
        last_reject / last_reject_ago_s: Last rejection.
        duration / duration_s: Last access duration.
        running: The op is currently running (e.g. camera open).
        access_states / reject_states: Process states of the accesses, e.g.
            ``["fg-s", "top-s"]`` (only in the dumpsys-style format).
        foreground / background: Derived from the access states; ``None``
            when the format carries no state.
        proxy_packages: Packages that accessed the op on this app's behalf
            (``proxy[uid=..., pkg=...]``).
    """

    op: str
    mode: str | None = None
    uid_mode: str | None = None
    package_mode: str | None = None
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
    proxy_packages: list[str] = field(default_factory=list)


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
_SEMI_OP_RE = re.compile(rf"^(Uid mode:\s*)?({_OP_NAME}):\s*([a-z_]+)(.*)$")
_UID_OP_RE = re.compile(rf"^({_OP_NAME}):\s*mode=([a-z_]+)")
_BLOCK_OP_RE = re.compile(rf"^({_OP_NAME})\s*\(([a-z_]+)[^)]*\):\s*$")
_EVENT_RE = re.compile(
    r"^(Access|Reject):\s*\[([^\]]*)\]\s*(.*?)\s*(?:\(([^)]*)\))?"
    r"(?:\s*duration=(\S+))?(?:\s*proxy\[([^\]]*)\])?\s*$"
)
_PROXY_PKG_RE = re.compile(r"pkg=([^,\]\s]+)")


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
    kind, state, stamp, relative, duration, proxy = match.groups()
    state = state.strip()
    ago = parse_android_duration(relative)
    raw = (stamp or "").strip() or (relative or "").strip() or None
    if proxy:
        proxy_pkg = _PROXY_PKG_RE.search(proxy)
        if proxy_pkg and proxy_pkg.group(1) not in entry.proxy_packages:
            entry.proxy_packages.append(proxy_pkg.group(1))
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
      rejectTime=+1h ago; duration=+2s`` and ``(running)``. AOSP prints
      ``Uid mode: `` once, before the FIRST uid-level op only; the following
      uid ops carry no prefix. They are kept in uid scope until a line
      carries time fields (uid entries never do) or an op name repeats.
      Blocks are sorted by op code, so an op whose code is not above the
      previous uid op also starts the package block. A package op printed
      without time fields and with a higher code right after the uid block
      stays ambiguous, which is why :func:`get_appops` prefers
      ``dumpsys appops --package``.
    * the block format of ``dumpsys appops --package`` (and newer builds):
      ``CAMERA (allow):`` followed by ``Access: [fg-s] 2026-01-02
      10:00:00.000 (-5m3s) duration=+2s proxy[uid=1000, pkg=x, ...]`` /
      ``Reject: [bg-s]...`` lines, optionally grouped in ``null=[ ... ]``
      attribution tags, plus uid-level ``OP: mode=allow`` lines.

    Unknown lines are ignored; ops without a matching permission (e.g.
    ``READ_CLIPBOARD``) are kept.

    Args:
        text: Raw command output.

    Returns:
        One :class:`AppOpEntry` per op (first-seen order), with ``uid_mode``,
        ``package_mode`` and the effective ``mode``.
    """
    entries: dict[str, AppOpEntry] = {}
    current: AppOpEntry | None = None
    uid_block: set[str] | None = None  # ops seen in the current uid block
    last_uid_code = -1  # highest known op code in the uid block (-1 = none)

    def get(op: str) -> AppOpEntry:
        if op not in entries:
            entries[op] = AppOpEntry(op=op, permission=OP_PERMISSIONS.get(op))
        return entries[op]

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        event = _EVENT_RE.match(line)
        if event:
            if current is not None:
                _apply_event(current, event)
            continue
        if line.startswith("Running start at:"):
            if current is not None:
                current.running = True
            continue
        block = _BLOCK_OP_RE.match(line)
        if block:
            uid_block = None
            current = get(block.group(1))
            current.package_mode = block.group(2)
            continue
        uid_op = _UID_OP_RE.match(line)
        if uid_op:
            get(uid_op.group(1)).uid_mode = uid_op.group(2)
            current = None
            continue
        semi = _SEMI_OP_RE.match(line)
        if not semi:
            continue
        prefix, op, mode, rest = semi.groups()
        code = _OP_CODE.get(op, -1)
        if prefix:
            uid_block = set()
            last_uid_code = -1
        elif uid_block is not None and (
            "=" in rest
            or "(running)" in rest
            or op in uid_block
            or (code >= 0 and last_uid_code >= 0 and code <= last_uid_code)
        ):
            uid_block = None  # first package-level line
        entry = get(op)
        if uid_block is not None:
            uid_block.add(op)
            last_uid_code = max(last_uid_code, code)  # unknown ops keep it
            entry.uid_mode = mode
            current = None
        else:
            entry.package_mode = mode
            _apply_semicolon_fields(entry, rest)
            current = entry
    for entry in entries.values():
        entry.mode = entry.uid_mode or entry.package_mode
        _derive_fg_bg(entry)
    return list(entries.values())


_APPOPS_ERROR_HINTS = ("unknown package", "error:", "exception", "not found")


def get_appops(package: str, serial: str | None = None) -> AppOpsState:
    """Read *package*'s AppOps (never raises).

    Prefers ``dumpsys appops --package <pkg>`` (uid vs package scope is
    unambiguous there) and falls back to ``cmd appops get <pkg>``.

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
            ("dumpsys appops", f"shell dumpsys appops --package {quoted}"),
            ("cmd appops get", f"shell cmd appops get {quoted}"),
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

#: ``du`` over a large app's data can take far longer than adb's 30s default.
FOOTPRINT_TIMEOUT_SECONDS = 120
_DB_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")


@dataclass
class DataFootprint(_DictMixin):
    """On-device storage used by a package.

    Android keeps two private stores per user: credential-encrypted (CE,
    ``/data/user/0/<pkg>`` == ``/data/data/<pkg>``) and device-encrypted
    (DE, ``/data/user_de/0/<pkg>``, used e.g. by Settings as its dataDir).
    Both are measured, plus external storage.

    Attributes:
        private_dir / private_kb / private_reason: CE store (``du -sk``).
        de_dir / de_kb / de_reason: DE store.
        private_total_kb: CE + DE (known parts), ``None`` if neither known.
        data_dir: The package's actual ``dataDir`` from ``dumpsys package``.
        external_dir / external_kb / external_reason: External storage.
        shared_prefs_count: ``*.xml`` files in ``shared_prefs`` (CE + DE).
        databases_count: Databases in CE + DE (``-journal``/``-wal``/``-shm``
            excluded).
        root_method: ``"adb root"``, ``"su -c"``, ``"su 0"`` or ``None``.
        reason: Overall reason when nothing could be measured.
    """

    package: str
    private_dir: str = ""
    private_kb: int | None = None
    private_reason: str | None = None
    de_dir: str = ""
    de_kb: int | None = None
    de_reason: str | None = None
    private_total_kb: int | None = None
    data_dir: str | None = None
    external_dir: str = ""
    external_kb: int | None = None
    external_reason: str | None = None
    shared_prefs_count: int | None = None
    databases_count: int | None = None
    root_method: str | None = None
    reason: str | None = None


def _footprint_paths(package: str) -> dict[str, str]:
    """CE, DE and external directories of *package* (user 0)."""
    return {
        "private_dir": f"/data/data/{package}",
        "de_dir": f"/data/user_de/0/{package}",
        "external_dir": f"/sdcard/Android/data/{package}",
    }


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


def _sum_known(*values: int | None) -> int | None:
    """Sum of the non-None values, ``None`` if all are None."""
    known = [v for v in values if v is not None]
    return sum(known) if known else None


def footprint_script(package: str) -> str:
    """Device shell script measuring *package*'s data dirs (paths quoted).

    Seven chunks separated by a marker: du CE, du DE, du external, then
    ``ls`` of CE shared_prefs, CE databases, DE shared_prefs, DE databases.
    """
    paths = _footprint_paths(package)
    ce, de, ext = (
        shlex.quote(paths[k]) for k in ("private_dir", "de_dir", "external_dir")
    )
    sep = f"; echo {_FOOTPRINT_SEP}; "
    return sep.join(
        [
            f"du -sk {ce} 2>&1",
            f"du -sk {de} 2>&1",
            f"du -sk {ext} 2>&1",
            f"ls -1 {ce}/shared_prefs 2>&1",
            f"ls -1 {ce}/databases 2>&1",
            f"ls -1 {de}/shared_prefs 2>&1",
            f"ls -1 {de}/databases 2>&1",
        ]
    )


def parse_footprint_output(
    output: str,
    package: str,
    root_method: str | None = None,
    data_dir: str | None = None,
) -> DataFootprint:
    """Parse :func:`footprint_script` output into a :class:`DataFootprint`."""
    result = DataFootprint(
        package=package,
        root_method=root_method,
        data_dir=data_dir,
        **_footprint_paths(package),
    )
    chunks = (output or "").split(_FOOTPRINT_SEP)
    if len(chunks) < 7:
        result.reason = "unexpected output" if output.strip() else "no output"
        return result
    ce, de, ext, ce_prefs, ce_dbs, de_prefs, de_dbs = (
        c.strip("\n") for c in chunks[:7]
    )
    result.private_kb, result.private_reason = _parse_du(ce)
    result.de_kb, result.de_reason = _parse_du(de)
    result.external_kb, result.external_reason = _parse_du(ext)
    result.shared_prefs_count = _sum_known(
        _count_entries(ce_prefs, kind="prefs"), _count_entries(de_prefs, kind="prefs")
    )
    result.databases_count = _sum_known(
        _count_entries(ce_dbs, kind="dbs"), _count_entries(de_dbs, kind="dbs")
    )
    if root_method is None:
        # Unprivileged toybox du can print "Permission denied" plus a tiny
        # size of the top dir itself -- never report that as the app's size.
        result.private_kb = result.de_kb = None
        result.private_reason = result.de_reason = "root required (enable adb root)"
        result.shared_prefs_count = result.databases_count = None
    result.private_total_kb = _sum_known(result.private_kb, result.de_kb)
    return result


def _data_dir(package: str, serial: str | None) -> str | None:
    """The package's ``dataDir`` (first user) from ``dumpsys package``."""
    command = f"dumpsys package {shlex.quote(package)} | grep dataDir="
    match = re.search(
        r"dataDir=(\S+)", _adb_stdout(device_shell_command(command), serial)
    )
    return match.group(1) if match else None


def get_data_footprint(
    package: str, serial: str | None = None, *, data_dir: str | None = None
) -> DataFootprint:
    """Measure *package*'s CE, DE and external data (never raises).

    Private data needs root; without it only the external size is filled and
    the private fields carry a reason.

    Args:
        package: Fully qualified package name.
        serial: Device serial; ``None`` = global target.
        data_dir: The package's ``dataDir`` if already known (e.g. from
            :func:`get_package_details`); fetched otherwise.

    Returns:
        A :class:`DataFootprint`.
    """
    reason = _bad_package_reason(package)
    if reason:
        return DataFootprint(package=package, reason=reason)
    try:
        if data_dir is None:
            data_dir = _data_dir(package, serial)
        method = detect_root_method(serial)
        wrap = None if method in (None, "adb root") else method
        script = _root_wrap(footprint_script(package), wrap)
        output = _adb(
            device_shell_command(script), serial, timeout=FOOTPRINT_TIMEOUT_SECONDS
        )
        if _FOOTPRINT_SEP not in output and "timed out" in output.lower():
            return DataFootprint(
                package=package,
                root_method=method,
                data_dir=data_dir,
                reason=f"timed out after {FOOTPRINT_TIMEOUT_SECONDS}s (du)",
                **_footprint_paths(package),
            )
        return parse_footprint_output(output, package, method, data_dir)
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
    """Decode a foreground-service type value.

    AOSP prints ``types=%08X`` (zero-padded hex, no ``0x``); ``0x``-prefixed
    hex and label strings (``location|camera``) are accepted too. Numeric
    values are ALWAYS read as hex.
    """
    if not raw:
        return []
    text = raw.strip().rstrip(",")
    hex_digits = text[2:] if text.lower().startswith("0x") else text
    if not re.fullmatch(r"[0-9a-fA-F]+", hex_digits or "-"):
        return [t for t in re.split(r"[|,]", text) if t and t != "none"]
    value = int(hex_digits, 16)
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
    """Cache key from the sha256 of each split that is part of the key.

    One hash (plain APK): the key is that sha256. Several: the key is the
    sha256 of the sorted hex digests joined by newlines. Use
    :func:`apk_key_for` to drop per-device config splits first.

    Args:
        split_sha256s: Lower-case hex sha256 digests.

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


def is_config_split(path_or_name: str) -> bool:
    """True for a per-device config split (``split_config.<abi|dpi|lang>``)."""
    return os.path.basename(path_or_name).startswith("split_config.")


def apk_key_for(splits: list[tuple[str, str]]) -> str:
    """Cache key for ``[(device_path_or_name, sha256), ...]``.

    Per-device config splits (ABI/density/locale) are excluded, so the same
    app installed on two devices shares one entry.

    Raises:
        ValueError: *splits* is empty.
    """
    kept = [sha for name, sha in splits if not is_config_split(name)]
    return compute_apk_key(kept or [sha for _name, sha in splits])


def parse_sha256sum_output(output: str) -> dict[str, str]:
    """Parse ``sha256sum <paths>`` output into ``{path: hex}``."""
    found = {}
    for line in (output or "").splitlines():
        match = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+)$", line.strip())
        if match:
            found[match.group(2).strip()] = match.group(1).lower()
    return found


#: ``(serial, package, identity) -> [(device_path, sha256), ...]`` so a
#: cache-only lookup (``allow_pull=False``) does not re-hash on every call.
_SPLIT_HASH_MEMO: dict[tuple[str | None, str, str], list[tuple[str, str]]] = {}
_SPLIT_HASH_MEMO_LOCK = threading.Lock()


def _package_identity(package: str, serial: str | None) -> str | None:
    """``versionCode``/``lastUpdateTime`` lines of the install (cheap)."""
    command = (
        f"dumpsys package {shlex.quote(package)} "
        "| grep -E 'versionCode=|lastUpdateTime='"
    )
    output = _adb_stdout(device_shell_command(command), serial)
    lines = sorted({line.strip() for line in output.splitlines() if line.strip()})
    return "\n".join(lines) or None


def device_split_hashes(
    package: str, serial: str | None = None, *, use_memo: bool = True
) -> list[tuple[str, str]] | None:
    """Hash every installed split of *package* on the device.

    Memoized per (serial, package, versionCode + lastUpdateTime): a repeat
    call for an unchanged install costs one cheap ``dumpsys | grep``.

    Returns:
        ``[(device_path, sha256), ...]`` (``pm path`` order), or ``None``
        when the package has no APK path or a split could not be hashed.
    """
    identity = _package_identity(package, serial) if use_memo else None
    memo_key = (serial, package, identity or "")
    if identity:
        with _SPLIT_HASH_MEMO_LOCK:
            if memo_key in _SPLIT_HASH_MEMO:
                return list(_SPLIT_HASH_MEMO[memo_key])
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
    result = [(p, hashes[p]) for p in paths]
    if identity:
        with _SPLIT_HASH_MEMO_LOCK:
            _SPLIT_HASH_MEMO[memo_key] = result
    return list(result)


class CacheLockTimeoutError(RuntimeError):
    """Raised when an entry's lock file could not be acquired in time."""


def _androguard_version() -> str | None:
    """Installed androguard version (cached facts from another are stale)."""
    return tool_versions().get("androguard")


class ApkCache:
    """Shared, APK-keyed cache of static facts.

    Layout under ``root`` (shareable, e.g. a team share)::

        <root>/insight/                  Dexray Insight 2.x's own cache_dir
        <root>/apk/<key>/meta.json       splits, package, version, tools,
                                         created_at, Insight summary
        <root>/apk/<key>/overview.json   androguard-derived facts

    ``<key>`` is :func:`apk_key_for` (config splits excluded). Writes are
    atomic (temp file created 0o666 under the umask + ``os.replace``) and
    serialised per entry by a token-owned ``.lock`` file. Only APK-derived
    data belongs here, never device/runtime facts, and no local paths.

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
        if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key):
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
        """Return the entry's overview.json if current, else ``None``.

        An entry built with a different androguard version than the one
        installed here is stale (a miss); without androguard any version is
        accepted, since it could not be rebuilt anyway.
        """
        data = self._read_json(key, "overview.json")
        if data is None or data.get("schema") != OVERVIEW_SCHEMA:
            return None
        current = _androguard_version()
        if current and data.get("androguard_version") != current:
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
        if not self.enabled:
            return []
        try:
            entries = list(self.apk_dir.iterdir())
        except OSError:
            return []
        found = []
        for entry in entries:
            try:
                meta = self.read_meta(entry.name)
            except ValueError:  # not a key-shaped directory
                continue
            if not meta or meta.get("package") != package:
                continue
            if version_code is not None and str(meta.get("version_code")) != str(
                version_code
            ):
                continue
            found.append((entry.name, meta))
        found.sort(key=lambda kv: str(kv[1].get("updated_at") or ""), reverse=True)
        return found

    # -- writing -------------------------------------------------------------

    @staticmethod
    def _try_create_lock(lock: Path, token: str) -> bool:
        """Create *lock* exclusively holding *token*; False if it exists."""
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o666)
        except FileExistsError:
            return False
        with os.fdopen(fd, "w") as handle:
            handle.write(token)
        return True

    def _break_if_stale(self, lock: Path) -> None:
        """Remove an abandoned lock without racing a fresh owner.

        The stale lock is first moved aside with an atomic rename (only one
        breaker can win); if what was moved turns out to be fresh -- a new
        owner took the lock between stat and rename -- it is linked back.
        """
        try:
            age = time.time() - lock.stat().st_mtime
        except OSError:
            return  # released meanwhile, or a share hiccup: caller sleeps
        if age <= self.stale_lock_after:
            return
        grave = lock.with_name(f".lock.stale.{uuid.uuid4().hex}")
        try:
            os.rename(lock, grave)
        except OSError:
            return  # another breaker won, or the owner released it
        try:
            fresh = time.time() - grave.stat().st_mtime <= self.stale_lock_after
        except OSError:
            fresh = False
        if fresh:
            with contextlib.suppress(OSError):
                os.link(grave, lock)
        with contextlib.suppress(OSError):
            grave.unlink()

    @staticmethod
    def _release(lock: Path, token: str) -> None:
        """Unlink *lock* only if it still holds our token."""
        try:
            if lock.read_text().strip() != token:
                logger.warning("apk cache lock %s was taken over; left as is", lock)
                return
            lock.unlink()
        except OSError:
            pass

    @contextlib.contextmanager
    def _locked(self, key: str) -> Iterator[Path]:
        """Hold the entry's ``.lock`` file until the block ends.

        Raises:
            CacheLockTimeoutError: Not acquired within ``lock_timeout``.
        """
        entry = self.entry_dir(key)
        entry.mkdir(parents=True, exist_ok=True)
        lock = entry / ".lock"
        token = f"{os.getpid()}:{threading.get_ident()}:{uuid.uuid4().hex}"
        deadline = time.monotonic() + self.lock_timeout
        while not self._try_create_lock(lock, token):
            self._break_if_stale(lock)
            if time.monotonic() > deadline:
                raise CacheLockTimeoutError(f"lock busy: {lock}")
            time.sleep(0.05)
        try:
            yield entry
        finally:
            self._release(lock, token)

    @staticmethod
    def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
        """Write JSON via a temp file in the same dir + ``os.replace``."""
        # Created 0o666 so the kernel applies the umask/ACLs of the share
        # (mkstemp's 0600 would make entries unreadable for the team, and
        # reading the umask via os.umask() races other threads).
        tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
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


_TOOL_VERSIONS: dict[str, str | None] | None = None


def tool_versions() -> dict[str, str | None]:
    """Versions of the tools that produced cached facts (looked up once)."""
    global _TOOL_VERSIONS
    if _TOOL_VERSIONS is None:
        from importlib import metadata

        versions: dict[str, str | None] = {}
        for dist in ("sandroid", "androguard", "dexray-insight"):
            try:
                versions[dist] = metadata.version(dist)
            except Exception:
                versions[dist] = None
        _TOOL_VERSIONS = versions
    return dict(_TOOL_VERSIONS)


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


def _nsc_facts(
    apk: Any, target_sdk: int | None, debuggable: bool = False
) -> dict[str, Any]:
    """Effective pinning, cleartext and user-CA trust from NSC + manifest.

    Platform rules applied: an NSC overrides ``usesCleartextTraffic`` (API
    24+, i.e. every device Sandroid targets); without an explicit value
    cleartext defaults to permitted below targetSdk 28; user CAs are trusted
    by default below targetSdk 24 (also for a base-config without
    trust-anchors); ``debug-overrides`` only apply when the app is
    debuggable.
    """
    android_ns = "{http://schemas.android.com/apk/res/android}"
    known = target_sdk is not None
    default_user_ca = known and target_sdk < 24
    default_cleartext = (target_sdk < 28) if known else None
    facts: dict[str, Any] = {
        "present": False,
        "path": None,
        "uses_cleartext_traffic": None,
        "cleartext_base": None,
        "cleartext_effective": None,
        "cleartext_source": None,
        "cleartext_domains": [],
        "pin_sets": [],
        "trust_user_ca": default_user_ca,
        "trust_user_ca_source": (
            f"platform default (targetSdk {target_sdk})" if default_user_ca else None
        ),
        "trust_user_ca_domains": [],
        "trust_user_ca_debug_only": False,
        "debug_overrides_active": False,
        "bundled_ca": False,
        "override_pins": False,
        "override_pins_scopes": [],
        "reason": None,
    }
    attr = apk.get_attribute_value("application", "usesCleartextTraffic")
    if attr is not None:
        facts["uses_cleartext_traffic"] = str(attr).lower() == "true"
    try:
        root, path = _resolve_nsc_xml(apk)
    except Exception as exc:
        root, path = None, None
        facts["reason"] = f"NSC unreadable: {exc}"
    if root is None:
        if facts["uses_cleartext_traffic"] is not None:
            facts["cleartext_effective"] = facts["uses_cleartext_traffic"]
            facts["cleartext_source"] = "android:usesCleartextTraffic"
        else:
            facts["cleartext_effective"] = default_cleartext
            facts["cleartext_source"] = f"platform default (targetSdk {target_sdk})"
        return facts
    facts["present"], facts["path"] = True, path

    def attr_of(element: Any, name: str) -> str | None:
        return element.get(name) or element.get(f"{android_ns}{name}")

    def anchors(scope: Any) -> list[Any] | None:
        """Direct ``trust-anchors/certificates``; None without trust-anchors."""
        if scope.find("trust-anchors") is None:
            return None
        return scope.findall("trust-anchors/certificates")

    def scan(certs: list[Any], scope_name: str) -> bool:
        """Record bundled CAs / overridePins; return True if user CAs trusted."""
        user = False
        for cert in certs:
            src = (attr_of(cert, "src") or "").lower()
            if src == "user":
                user = True
            elif src.startswith("@"):
                facts["bundled_ca"] = True
            if (attr_of(cert, "overridePins") or "").lower() == "true":
                facts["override_pins"] = True
                if scope_name not in facts["override_pins_scopes"]:
                    facts["override_pins_scopes"].append(scope_name)
        return user

    base = root.find("base-config")
    facts["cleartext_effective"] = default_cleartext
    facts["cleartext_source"] = f"NSC default (targetSdk {target_sdk})"
    if base is not None:
        value = attr_of(base, "cleartextTrafficPermitted")
        if value is not None:
            facts["cleartext_base"] = value.lower() == "true"
            facts["cleartext_effective"] = facts["cleartext_base"]
            facts["cleartext_source"] = "NSC base-config"
        certs = anchors(base)
        if certs is not None:
            facts["trust_user_ca"] = scan(certs, "base-config")
            facts["trust_user_ca_source"] = "NSC base-config"
    for domain_cfg in root.iter("domain-config"):
        domains = [(d.text or "").strip() for d in domain_cfg.findall("domain")]
        if (attr_of(domain_cfg, "cleartextTrafficPermitted") or "").lower() == "true":
            facts["cleartext_domains"].extend(domains)
        certs = anchors(domain_cfg)
        if certs is not None and scan(certs, ", ".join(domains) or "domain-config"):
            facts["trust_user_ca_domains"].extend(domains)
        for pin_set in domain_cfg.findall("pin-set"):
            facts["pin_sets"].append(
                {
                    "domains": domains,
                    "pins": len(pin_set.findall("pin")),
                    "expiration": attr_of(pin_set, "expiration"),
                }
            )
    overrides = root.find("debug-overrides")
    if overrides is not None:
        certs = anchors(overrides) or []
        if debuggable:
            facts["debug_overrides_active"] = True
            if scan(certs, "debug-overrides"):
                facts["trust_user_ca"] = True
                facts["trust_user_ca_source"] = "NSC debug-overrides (debuggable app)"
        elif any((attr_of(c, "src") or "").lower() == "user" for c in certs):
            facts["trust_user_ca_debug_only"] = True
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
        try:
            infos.append(_manifest_component_info(apk))
        except Exception as exc:
            overview["errors"].append(f"{os.path.basename(path)} manifest: {exc}")
        with contextlib.suppress(Exception):
            lib_paths.update(
                f for f in apk.get_files() if f.startswith("lib/") and f.endswith(".so")
            )
    overview["androguard_version"] = _androguard_version()
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
        overview["nsc"] = _nsc_facts(base, target_sdk, overview["debuggable"])
    except Exception as exc:
        overview["nsc"] = {"present": False, "reason": f"NSC unreadable: {exc}"}
    by_abi: dict[str, set[str]] = {}
    for lib in lib_paths:
        parts = lib.split("/")
        if len(parts) >= 3:
            by_abi.setdefault(parts[1], set()).add(parts[-1])
    overview["native_lib_paths"] = sorted(lib_paths)
    overview["native_libs"] = sorted({os.path.basename(p) for p in lib_paths})
    # Libs come from whichever ABI split was pulled; the cache key ignores
    # config splits, so they are recorded per ABI.
    overview["native_libs_by_abi"] = {abi: sorted(libs) for abi, libs in by_abi.items()}
    overview["abis"] = sorted(by_abi)
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
        insight: The Insight summary recorded in meta.json, or ``None``.
        trackers: Insight ``tracker_analysis.detected_trackers`` (name,
            category, version, website, network_domains/network_signature,
            confidence, detection_method), ``[]`` without an Insight run.
        protections: Insight protection SDKs (id, name, category, defeats,
            confidence, evidence, matched_classes, matched_libs).
        from_cache: The overview came from the cache (no pull).
        ok / reason: ``ok`` False means nothing usable; see ``reason``.
    """

    package: str
    key: str | None = None
    overview: dict[str, Any] | None = None
    meta: dict[str, Any] | None = None
    insight: dict[str, Any] | None = None
    trackers: list[dict[str, Any]] = field(default_factory=list)
    protections: list[dict[str, Any]] = field(default_factory=list)
    from_cache: bool = False
    ok: bool = True
    reason: str | None = None

    def set_insight(self, insight: dict[str, Any] | None) -> None:
        """Set :attr:`insight` and the tracker/protection lists derived from it."""
        self.insight = insight
        self.trackers = insight_trackers(insight)
        self.protections = insight_protections(insight)


def load_insight_results(meta: dict[str, Any] | None) -> dict[str, Any] | None:
    """The Insight summary recorded in *meta*, or ``None``.

    Never opens a path named in meta.json: a shared meta is untrusted input.
    """
    info = meta.get("insight") if isinstance(meta, dict) else None
    summary = info.get("summary") if isinstance(info, dict) else None
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
            result.key = apk_key_for(hashes)
            result.meta = cache.read_meta(result.key)
            result.overview = cache.read_overview(result.key)
            result.set_insight(load_insight_results(result.meta))
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
            key = apk_key_for(
                [
                    (d, digest)
                    for (d, _l), digest in zip(pulled, local_hashes, strict=True)
                ]
            )
            overview = build_apk_overview([local for _d, local in pulled])
            splits = [
                {
                    "name": os.path.basename(device_path),
                    "sha256": digest,
                    "size": os.path.getsize(local),
                    "config": is_config_split(device_path),
                }
                for (device_path, local), digest in zip(
                    pulled, local_hashes, strict=True
                )
            ]
        result.key, result.overview = key, overview
        decode_failed = not overview.get("package") or bool(overview.get("errors"))
        if decode_failed:
            # Never cache a failed/partial decode: it would be served forever.
            errors = "; ".join(str(e) for e in overview.get("errors") or [])
            result.reason = f"not cached: APK decode incomplete ({errors or 'no base'})"
            if not overview.get("package"):
                result.ok = False
        if result.ok and not decode_failed:
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
            result.set_insight(load_insight_results(result.meta))
        return result
    except Exception as exc:
        logger.warning("static overview failed for %s: %s", package, exc)
        result.ok = False
        result.reason = str(exc)
        return result


_ABS_POSIX_PATH_RE = re.compile(r"(?<![\w.:/~])/(?:[^\s/:'\"!]+/)+[^\s/:'\"!]*")
_ABS_WIN_PATH_RE = re.compile(r"\b[A-Za-z]:\\(?:[^\s\\:'\"!]+\\)+[^\s\\:'\"!]*")

_TRACKER_KEEP = (
    "name",
    "category",
    "version",
    "website",
    "network_domains",
    "network_signature",
    "confidence",
    "detection_method",
)
_PROTECTION_KEEP = (
    "id",
    "name",
    "category",
    "description",
    "website",
    "defeats",
    "confidence",
    "evidence",
    "matched_classes",
    "matched_libs",
)


def scrub_paths(value: Any) -> Any:
    """Replace absolute host paths inside *value* by their basename.

    Shared meta.json must not leak ``/Users/<name>/...`` or session paths.
    Applied recursively to dicts/lists; relative paths (``lib/arm64/x.so``)
    and URLs are left alone.
    """
    if isinstance(value, dict):
        return {k: scrub_paths(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub_paths(v) for v in value]
    if isinstance(value, str):
        value = _ABS_POSIX_PATH_RE.sub(lambda m: m.group(0).rsplit("/", 1)[-1], value)
        return _ABS_WIN_PATH_RE.sub(lambda m: m.group(0).rsplit("\\", 1)[-1], value)
    return value


def _pick(items: Any, keep: tuple[str, ...]) -> list[dict[str, Any]]:
    """Keep only *keep* keys (present ones) of each dict in *items*."""
    return [
        {k: item[k] for k in keep if k in item}
        for item in _as_list(items)
        if isinstance(item, dict)
    ]


def _insight_summary(results: dict[str, Any]) -> dict[str, Any]:
    """The small, lens-relevant subset of Insight results kept in meta.json.

    APKiD file names are reduced to the part after ``!`` (the entry inside
    the APK) and every other absolute path is scrubbed (:func:`scrub_paths`).
    """
    apkid = _as_dict(results.get("apkid_analysis"))
    apkid = {k: v for k, v in apkid.items() if k != "raw_output"}
    if isinstance(apkid.get("files"), list):
        apkid["files"] = [
            (
                {
                    **f,
                    "filename": os.path.basename(
                        str(f.get("filename", "")).rsplit("!", 1)[-1]
                    ),
                }
                if isinstance(f, dict)
                else f
            )
            for f in apkid["files"]
        ]
    keep = ("name", "package_name", "category", "version", "confidence", "vendor")
    overview = _as_dict(results.get("apk_overview"))
    tracker = _as_dict(results.get("tracker_analysis"))
    return scrub_paths(
        {
            "apkid_analysis": apkid,
            "library_detection": {
                "detected_libraries": _pick(_library_entries(results), keep)
            },
            "detected_protections": results.get("detected_protections"),
            "tracker_analysis": {
                "detected_trackers": _pick(
                    tracker.get("detected_trackers"), _TRACKER_KEEP
                ),
                "detected_protections": _pick(
                    tracker.get("detected_protections"), _PROTECTION_KEEP
                ),
            },
            "apk_overview": {
                "native_libs": overview.get("native_libs", []),
                "cross_platform_framework": overview.get("cross_platform_framework"),
            },
        }
    )


def insight_trackers(insight: Any) -> list[dict[str, Any]]:
    """Detected trackers from Insight results or the cached summary."""
    tracker = _as_dict(_as_dict(insight).get("tracker_analysis"))
    return _pick(tracker.get("detected_trackers"), _TRACKER_KEEP)


def insight_protections(insight: Any) -> list[dict[str, Any]]:
    """Detected protection SDKs from Insight results or the cached summary."""
    insight = _as_dict(insight)
    tracker = _as_dict(insight.get("tracker_analysis"))
    return _pick(tracker.get("detected_protections"), _PROTECTION_KEEP) + _pick(
        insight.get("detected_protections"), _PROTECTION_KEEP
    )


def record_insight_result(
    split_sha256s: list[str],
    analysis_results: dict[str, Any],
    *,
    result_file: str | None = None,
    security_result_file: str | None = None,
    insight_version: str | None = None,
    insight_cache_used: bool = False,
    apk_md5: str | None = None,
    package: str | None = None,
    cache: ApkCache | None = None,
) -> str | None:
    """Record a Dexray Insight run in the APK cache's meta.json.

    Only cache-relative references are stored (file basenames, the analysed
    APK's md5 -- Insight's own cache key under ``<root>/insight/``), never
    absolute local paths, which would leak home/session paths on a share.

    Args:
        split_sha256s: sha256 of every key split (config splits excluded,
            see :func:`apk_key_for`).
        analysis_results: Insight's main result dict.
        result_file / security_result_file: The written JSON files (only
            their basenames are kept).
        insight_version: Insight version string.
        insight_cache_used: Insight was given ``<root>/insight/``.
        apk_md5: md5 of the analysed APK (Insight's cache key).
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
        general = _as_dict(
            _as_dict(_as_dict(analysis_results).get("apk_overview")).get("general_info")
        )
        updates: dict[str, Any] = {
            "insight": {
                "result_name": os.path.basename(result_file) if result_file else None,
                "security_result_name": (
                    os.path.basename(security_result_file)
                    if security_result_file
                    else None
                ),
                "version": insight_version,
                "cache": "insight" if insight_cache_used else None,
                "apk_md5": apk_md5,
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
            **_as_dict(existing.get("tool_versions")),
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
        id: Stable id (``"lib:rootbeer"``) for dedup/UI keys.
        category: ``root``/``integrity``/``debug``/``emulator``/``frida``/
            ``rasp``/``packer``/``obfuscator``/``tls_stack``/``crypto_lib``/
            ``pinning``/``cleartext``/``user_ca``.
        title: Short label.
        evidence: Human-readable evidence strings.
        routes: Suggested keys, primary first: ``h`` friTap, ``b1``..``b6``
            bypass digits (b1 ssl, b2 root, b3 frida, b4 debug, b5
            integrity, b6 emulator), ``v`` verify.
        hint: One-line advice for the route.
        source: ``apkid``/``library``/``native_libs``/``nsc``/
            ``insight_protections``.
        weakness: True for facts that *ease* analysis (cleartext, user CA).
        confidence: ``"low"``/``"medium"``/``"high"``.
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
    confidence: str = "medium"
    status: str = STATIC_STATUS


_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

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


#: (basename glob, id, category, title, routes, hint) -- exact basenames:
#: ``libssl.so`` matches, ``libssl_helper.so`` does not.
NATIVE_TLS_LIBS: tuple[tuple[str, str, str, str, list[str], str], ...] = (
    (
        "libflutter.so",
        "flutter_tls",
        "tls_stack",
        "Flutter (own BoringSSL)",
        ["h"],
        "TLS lives inside libflutter.so: b1 cannot reach it and friTap may "
        "miss it (stripped symbols); try h, expect pattern-based hooks.",
    ),
    (
        "libnss3.so",
        "nss_tls",
        "tls_stack",
        "NSS (own CA store)",
        ["h"],
        "NSS ignores the Android trust store: use friTap (h), not b1.",
    ),
    (
        "libcronet*.so",
        "cronet_tls",
        "tls_stack",
        "Cronet (Chromium net stack)",
        ["h", "b1"],
        "Own BoringSSL; keys via h, cert checks may still hit b1.",
    ),
    (
        "libconscrypt*.so",
        "conscrypt_tls",
        "tls_stack",
        "Bundled Conscrypt",
        ["b1", "h"],
        "App-bundled Conscrypt provider; b1 usually works, h for keys.",
    ),
    (
        "libssl.so",
        "openssl_tls",
        "tls_stack",
        "Bundled OpenSSL/BoringSSL",
        ["h"],
        "Native TLS outside the platform stack; friTap (h).",
    ),
)

#: Exact native-lib basename -> library protection id (file-only evidence).
NATIVE_PROTECTION_LIBS = {
    "libpairipcore.so": "pairip",
}

#: APKiD category -> (category, title, routes, hint). anti_vm/anti_debug are
#: handled separately (they fire on GMS/Firebase code).
_APKID_CATEGORIES = {
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

#: APKiD check categories that commonly fire on Google/AndroidX code.
_APKID_CHECKS = {
    "anti_vm": ("emulator", "Emulator checks", "b6"),
    "anti_debug": ("debug", "Debugger checks", "b4"),
}

#: Package prefixes whose anti-VM/anti-debug code is benign library noise.
_BENIGN_CODE_PREFIXES = ("com.google.", "androidx.", "com.google.firebase.")

_CLASS_REF_RE = re.compile(r"L([A-Za-z_$][\w$]*(?:/[\w$]+)+);")
_DOTTED_CLASS_RE = re.compile(r"\b([a-z][\w$]*(?:\.[a-z_$][\w$]*)+\.[A-Z][\w$]*)")

#: Keyword in an Insight protection's category/name -> (category, routes).
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


def _confidence(value: Any, default: str = "medium") -> str:
    """Normalise a confidence (``"high"``, ``0.93``) to low/medium/high."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "high" if value >= 0.9 else "medium" if value >= 0.6 else "low"
    text = str(value or "").strip().lower()
    return text if text in _CONFIDENCE_RANK else default


def _iter_apkid_matches(apkid: Any) -> Iterator[tuple[str, str, str]]:
    """Yield ``(filename, category, match)`` from Insight's apkid_analysis."""
    for file_entry in _as_list(_as_dict(apkid).get("files")):
        if not isinstance(file_entry, dict):
            continue
        filename = str(file_entry.get("filename", "?")).split("!")[-1]
        for category, matches in _as_dict(file_entry.get("matches")).items():
            for match in _as_list(matches):
                yield filename, str(category), str(match)


def _code_locations(match: str) -> list[str]:
    """Dotted class names an APKiD match string points at (often none)."""
    found = [m.replace("/", ".") for m in _CLASS_REF_RE.findall(match)]
    found += _DOTTED_CLASS_RE.findall(match)
    return found


def _library_entries(insight: dict[str, Any]) -> list[dict[str, Any]]:
    """Detected libraries from Insight results (both 1.x and 2.x shapes)."""
    libraries = insight.get("library_detection")
    if isinstance(libraries, dict):
        libraries = libraries.get("detected_libraries")
    return [lib for lib in _as_list(libraries) if isinstance(lib, dict)]


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
    for item in _as_list(raw):
        if isinstance(item, str):
            entries.append({"name": item})
        elif isinstance(item, dict):
            entries.append(item)
    return entries


def _protection_defence(item: dict[str, Any]) -> SuspectedDefence:
    """Turn one Insight ``detected_protections`` entry into a defence.

    Routes come from ``defeats`` when present, else from keywords in the
    category/name. ``evidence`` of ``"sdk_present"`` means the SDK is only
    bundled (may not be enforced, low confidence); ``"entry_point"`` means
    its checks are referenced. Entries naming a known protection library
    reuse that library's id, so library detection and Insight merge.
    """
    name = str(item.get("name") or item.get("protection") or item.get("type") or "?")
    category_text = str(item.get("category") or item.get("type") or name).lower()
    cat, routes = "rasp", ["v"]
    for keywords, kw_cat, kw_routes in _PROTECTION_KEYWORD_ROUTES:
        if any(k in category_text or k in name.lower() for k in keywords):
            cat, routes = kw_cat, list(kw_routes)
            break
    defeats = [d for d in _as_list(item.get("defeats")) if d in DEFEAT_ROUTES]
    if defeats:
        routes = sorted({DEFEAT_ROUTES[d] for d in defeats})
        if len(routes) > 2:
            cat = "rasp"
    defence_id = f"insight:{_slug(str(item.get('id') or name))}"
    lowered = name.lower()
    for needles, lib_id, lib_cat, _title, _routes, _hint in PROTECTION_LIBRARIES:
        if any(n in lowered for n in needles):
            defence_id, cat = f"lib:{lib_id}", lib_cat
            break
    confidence = _confidence(item.get("confidence"))
    hint = str(item.get("description") or "")
    evidence_lines: list[str] = []
    evidence = item.get("evidence")
    if evidence == "sdk_present":
        evidence_lines.append("Insight: SDK present, may not be enforced")
        confidence = "low"
        hint = ("SDK present, may not be enforced. " + hint).strip()
    elif evidence == "entry_point":
        evidence_lines.append("Insight: entry point referenced (likely enforced)")
    elif isinstance(evidence, list):
        evidence_lines += [f"Insight: {e}" for e in evidence[:5]]
    elif evidence:
        evidence_lines.append(f"Insight: {evidence}")
    for key, label in (("matched_classes", "class"), ("matched_libs", "native lib")):
        evidence_lines += [f"Insight {label}: {v}" for v in _as_list(item.get(key))[:3]]
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
        hint=hint,
        source="insight_protections",
        confidence=confidence,
    )


def _apkid_defences(insight: dict[str, Any]) -> list[SuspectedDefence]:
    """APKiD categories; anti_vm/anti_debug are low-confidence by default."""
    grouped: dict[str, list[tuple[str, str]]] = {}
    for filename, category, match in _iter_apkid_matches(insight.get("apkid_analysis")):
        grouped.setdefault(category, []).append((filename, match))
    out = []
    for category, hits in grouped.items():
        evidence = [f"APKiD {category}: {m} ({f})" for f, m in hits]
        if category in _APKID_CHECKS:
            cat, title, route = _APKID_CHECKS[category]
            outside = [
                loc
                for _f, m in hits
                for loc in _code_locations(m)
                if not loc.startswith(_BENIGN_CODE_PREFIXES)
            ]
            if outside:
                evidence.append(f"in app code: {', '.join(sorted(set(outside)))}")
                out.append(
                    SuspectedDefence(
                        id=f"apkid:{category}",
                        category=cat,
                        title=title,
                        evidence=evidence,
                        routes=[route],
                        hint=f"Checks outside Google/AndroidX code; {route}.",
                        source="apkid",
                        confidence="medium",
                    )
                )
            else:
                out.append(
                    SuspectedDefence(
                        id=f"apkid:{category}",
                        category=cat,
                        title=f"{title} (common, likely benign)",
                        evidence=evidence,
                        routes=["v", route],
                        hint=(
                            "APKiD flags this in GMS/Firebase code too; likely "
                            f"benign -- verify before arming {route}."
                        ),
                        source="apkid",
                        confidence="low",
                    )
                )
        elif category in _APKID_CATEGORIES:
            cat, title, routes, hint = _APKID_CATEGORIES[category]
            out.append(
                SuspectedDefence(
                    id=f"apkid:{category}",
                    category=cat,
                    title=title,
                    evidence=evidence,
                    routes=list(routes),
                    hint=hint,
                    source="apkid",
                )
            )
    return out


def _library_defences(insight: dict[str, Any]) -> list[SuspectedDefence]:
    """Insight library detection matched against :data:`PROTECTION_LIBRARIES`."""
    out = []
    for lib in _library_entries(insight):
        haystack = " ".join(
            str(lib.get(k) or "") for k in ("name", "package_name", "vendor")
        ).lower()
        for needles, lib_id, cat, title, routes, hint in PROTECTION_LIBRARIES:
            if any(n in haystack for n in needles):
                label = lib.get("name") or lib.get("package_name")
                out.append(
                    SuspectedDefence(
                        id=f"lib:{lib_id}",
                        category=cat,
                        title=title,
                        evidence=[f"library detected: {label}"],
                        routes=list(routes),
                        hint=hint,
                        source="library",
                        confidence=_confidence(lib.get("confidence")),
                    )
                )
    return out


def _native_defences(
    overview: dict[str, Any], insight: dict[str, Any]
) -> list[SuspectedDefence]:
    """TLS stacks and protection SDKs from exact native-lib basenames."""
    native = {os.path.basename(str(p)) for p in _as_list(overview.get("native_libs"))}
    insight_overview = _as_dict(insight.get("apk_overview"))
    native |= {
        os.path.basename(str(p)) for p in _as_list(insight_overview.get("native_libs"))
    }
    out = []
    for pattern, lib_id, cat, title, routes, hint in NATIVE_TLS_LIBS:
        hits = sorted(n for n in native if fnmatch.fnmatchcase(n, pattern))
        if not hits:
            continue
        if lib_id == "openssl_tls" and "libcrypto.so" in native:
            hits.append("libcrypto.so")
        out.append(
            SuspectedDefence(
                id=f"native:{lib_id}",
                category=cat,
                title=title,
                evidence=[f"native lib {n}" for n in hits],
                routes=list(routes),
                hint=hint,
                source="native_libs",
            )
        )
    if "libcrypto.so" in native and "libssl.so" not in native:
        out.append(
            SuspectedDefence(
                id="native:crypto_lib",
                category="crypto_lib",
                title="Bundled crypto library",
                evidence=["native lib libcrypto.so (no libssl.so)"],
                hint="Crypto lib, TLS not implied.",
                source="native_libs",
                confidence="low",
            )
        )
    for basename, lib_id in NATIVE_PROTECTION_LIBS.items():
        if basename in native:
            spec = next(p for p in PROTECTION_LIBRARIES if p[1] == lib_id)
            out.append(
                SuspectedDefence(
                    id=f"lib:{lib_id}",
                    category=spec[2],
                    title=spec[3],
                    evidence=[f"native lib {basename}"],
                    routes=list(spec[4]),
                    hint=spec[5],
                    source="native_libs",
                    confidence="high",
                )
            )
    return out


def _nsc_defences(overview: dict[str, Any]) -> list[SuspectedDefence]:
    """Pinning, effective cleartext and (scoped) user-CA trust from the NSC."""
    nsc = _as_dict(overview.get("nsc"))
    out = []
    pin_sets = [p for p in _as_list(nsc.get("pin_sets")) if isinstance(p, dict)]
    if pin_sets:
        domains = sorted({str(d) for p in pin_sets for d in _as_list(p.get("domains"))})
        evidence = [f"pin-set for {', '.join(domains) or '?'}"]
        hint = "Platform pinning via NSC; b1 covers it, h as fallback."
        scopes = [str(s) for s in _as_list(nsc.get("override_pins_scopes"))]
        if nsc.get("override_pins"):
            evidence.append(
                f"overridePins=true on {', '.join(scopes) or 'trust anchors'}: "
                "those CAs bypass the pins"
            )
            hint += " A CA in an overridePins anchor skips pinning."
        out.append(
            SuspectedDefence(
                id="nsc:pinning",
                category="pinning",
                title="NSC certificate pinning",
                evidence=evidence,
                routes=["b1", "h"],
                hint=hint,
                source="nsc",
                confidence="high",
            )
        )
    cleartext = []
    if nsc.get("cleartext_effective"):
        cleartext.append(f"cleartext permitted ({nsc.get('cleartext_source')})")
    domains = [str(d) for d in _as_list(nsc.get("cleartext_domains"))]
    if domains:
        cleartext.append("cleartext for " + ", ".join(domains))
    if cleartext and nsc.get("present") and nsc.get("uses_cleartext_traffic"):
        cleartext.append("android:usesCleartextTraffic ignored (NSC present)")
    if cleartext:
        out.append(
            SuspectedDefence(
                id="nsc:cleartext",
                category="cleartext",
                title="Cleartext traffic allowed",
                evidence=cleartext,
                hint="Some traffic may be readable in the proxy without a CA.",
                source="nsc",
                weakness=True,
                confidence="high",
            )
        )
    if nsc.get("trust_user_ca"):
        out.append(
            SuspectedDefence(
                id="nsc:user_ca",
                category="user_ca",
                title="User CAs trusted",
                evidence=[f"user CAs trusted ({nsc.get('trust_user_ca_source')})"],
                hint="A user-installed proxy CA is enough; no system CA needed.",
                source="nsc",
                weakness=True,
                confidence="high",
            )
        )
    scoped = [str(d) for d in _as_list(nsc.get("trust_user_ca_domains"))]
    if scoped:
        out.append(
            SuspectedDefence(
                id="nsc:user_ca_scoped",
                category="user_ca",
                title="User CAs trusted for some domains",
                evidence=["domain-config trusts user CAs: " + ", ".join(scoped)],
                hint="A user CA works only for these domains.",
                source="nsc",
                weakness=True,
                confidence="high",
            )
        )
    return out


def suspect_defences(
    overview: dict[str, Any] | None, insight: dict[str, Any] | None = None
) -> list[SuspectedDefence]:
    """Derive suspected defences from cached static facts (pure function).

    Sources: APKiD categories, Insight library detection matched against
    :data:`PROTECTION_LIBRARIES`, exact native-lib basenames (TLS stacks,
    PairIP core), the network security config and Insight
    ``tracker_analysis.detected_protections`` (or a top-level
    ``detected_protections``) when present. Malformed input (wrong JSON
    types from a shared cache) is tolerated: a failing source is skipped.

    Args:
        overview: overview.json dict (may be ``None``).
        insight: Insight result dict, a ``{"main": ...}`` cache payload or the
            meta.json summary (may be ``None``).

    Returns:
        Deduplicated :class:`SuspectedDefence` list, defences before
        weaknesses.
    """
    overview = _as_dict(overview)
    insight = _as_dict(insight)
    if isinstance(insight.get("main"), dict):
        insight = insight["main"]
    found: dict[str, SuspectedDefence] = {}

    def add(item: SuspectedDefence) -> None:
        existing = found.get(item.id)
        if existing is None:
            found[item.id] = item
            return
        for line in item.evidence:
            if line not in existing.evidence:
                existing.evidence.append(line)
        for route in item.routes:
            if route not in existing.routes:
                existing.routes.append(route)
        if _CONFIDENCE_RANK.get(item.confidence, 1) > _CONFIDENCE_RANK.get(
            existing.confidence, 1
        ):
            existing.confidence = item.confidence

    def protections() -> list[SuspectedDefence]:
        raw = _protection_entries(insight.get("detected_protections"))
        tracker = _as_dict(insight.get("tracker_analysis"))
        raw += _protection_entries(tracker.get("detected_protections"))
        return [_protection_defence(item) for item in raw]

    sources = (
        lambda: _apkid_defences(insight),
        lambda: _library_defences(insight),
        lambda: _native_defences(overview, insight),
        lambda: _nsc_defences(overview),
        protections,
    )
    for source in sources:
        try:
            for item in source():
                add(item)
        except Exception as exc:  # malformed shared JSON
            logger.debug("defence source skipped: %s", exc)
    return sorted(found.values(), key=lambda d: (d.weakness, d.category, d.id))


# ---------------------------------------------------------------------------
# Facade
# ---------------------------------------------------------------------------


@dataclass
class Fact(_DictMixin):
    """A single facade result: ``value`` when ``ok``, else ``reason``."""

    value: Any = None
    ok: bool = True
    reason: str | None = None


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

    def details(self, package: str) -> Fact:
        """Package details (``value``: :func:`get_package_details` dict).

        Never raises; ``ok`` is False when adb failed or the package is not
        in the dump (unlike the AI tool, which keeps its original contract).
        """
        reason = _bad_package_reason(package)
        if reason:
            return Fact(ok=False, reason=reason)
        try:
            stdout, stderr = _adb_raw(
                f"shell dumpsys package {shlex.quote(package)}", self.serial
            )
        except Exception as exc:
            return Fact(ok=False, reason=str(exc))
        if f"Package [{package}]" not in (stdout or ""):
            why = (stderr or "").strip() or "package not found (device offline?)"
            return Fact(ok=False, reason=why[:200])
        details = parse_extended_package_info(stdout)
        return Fact(value={**details, "package_name": package})

    def pid(self, package: str) -> Fact:
        """Running PID (``value`` None = not running). Never raises."""
        reason = _bad_package_reason(package)
        if reason:
            return Fact(ok=False, reason=reason)
        try:
            return Fact(value=get_package_pid(package, self.serial))
        except Exception as exc:
            return Fact(ok=False, reason=str(exc))

    def installed(self, include_system: bool = False) -> Fact:
        """Installed packages (``value``: list of dicts). Never raises."""
        try:
            return Fact(value=list_installed_packages(include_system, self.serial))
        except Exception as exc:
            return Fact(ok=False, reason=str(exc))

    def permissions(
        self, package: str, overview: dict[str, Any] | None = None
    ) -> PermissionState:
        """See :func:`get_permission_state`; *overview* adds manifest levels."""
        protection = _as_dict(_as_dict(overview).get("permission_protection"))
        return get_permission_state(
            package, self.serial, manifest_protection=protection
        )

    def appops(self, package: str) -> AppOpsState:
        """See :func:`get_appops`."""
        return get_appops(package, self.serial)

    def footprint(self, package: str, data_dir: str | None = None) -> DataFootprint:
        """See :func:`get_data_footprint`."""
        return get_data_footprint(package, self.serial, data_dir=data_dir)

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
