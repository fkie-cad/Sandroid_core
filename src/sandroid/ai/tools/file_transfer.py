"""Host<->device file-transfer tools for the Sandroid AI chat.

Importing this module registers all four tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). All tools in this module share
``category="file_transfer"``:

- ``pull_path`` -- ``RiskTier.REVERSIBLE``, ``can_remember_choice=True``.
- ``pull_apk`` -- ``RiskTier.REVERSIBLE``, ``can_remember_choice=True``.
- ``pull_app_data`` -- ``RiskTier.REVERSIBLE``, ``can_remember_choice=True``.
- ``push_path`` -- ``RiskTier.CONSEQUENTIAL``, ``can_remember_choice=False``.

**Pull vs. push risk asymmetry**: pulling copies a device file to a host
location this module itself computes (or the confined data-share/session
tree) -- the exposure is bounded and roughly constant regardless of *which*
device path is named, so an "allow always" choice is safe to persist.
``push_path`` picks a specific, potentially destructive *device*
destination (an arbitrary path is overwritten) -- that risk lives in the
argument, not the tool's identity, so it can never be persisted (same
reasoning as ``install_apk``/``kill_process``'s pid path).

**Host-path confinement**: ``pull_path``'s/``pull_apk``'s destinations are
always tool-computed (never a raw model-supplied host path) -- the model
only ever supplies a *filename hint*, reduced to ``os.path.basename(...)``
first, so it can name a file but never redirect where it lands or escape
via ``../``. ``push_path``'s *source* (``local_path``, read off the host) is
the one place this module accepts a real model-supplied host path, so it is
resolved through :func:`sandroid.ai.tools._host_paths.resolve_confined_host_path`
before anything is read from disk.

**Destination-path construction (review-caught bug, fixed here)**:
``ConfigurationService.get_raw_results_path()`` (see
:mod:`sandroid.services.configuration_service`)
returns a *relative* string by construction (e.g. ``"results/raw/"``).
Passing that relative string straight into ``resolve_confined_host_path``
would anchor it against ``ai_data_share`` (that function's fallback anchor
for any relative input), not the session's own raw-results directory --
silently misfiling every pulled file under ``~/Sandroid/ai_share/...``
instead of the intended session folder. :func:`_raw_results_root` resolves
that path to **absolute** first -- mirroring exactly how
:func:`sandroid.ai.tools._host_paths._allowed_roots` resolves its own
``session_raw_results`` entry -- and only the absolute result is ever passed
to ``resolve_confined_host_path``. Both ``pull_path`` and ``pull_apk`` build
their destinations through this one helper, so the fix lives in a single
place rather than two independent copies.

**``pull_apk`` vs. ``pull_and_hash_apks``**:
``FileExtractionService.pull_and_hash_apks`` (see
:mod:`sandroid.services.file_extraction_service`) unconditionally pulls
**every** installed package and deletes each local file after hashing -- it
has one existing caller (``Toolbox.pull_and_hash_apks``, the whole-device
"APK Hashes" report) whose behavior must not change. ``pull_apk`` is a
deliberately separate, small pipeline: ``pm path <pkg>`` (parsed via
:func:`sandroid.ai.tools._shared.parse_pm_path_output`) then
``FileExtractionService.pull_file`` per split, with the pulled files kept on
disk.

**Timeout note**: all four tools transfer files that can be large -- a
single installed APK, an app's entire data directory, an arbitrary device
file the model doesn't know the size of ahead of time.
:mod:`sandroid.ai.tools.app_query` already documents a real, live-emulator
139MB APK pull taking ~52s, well past ``Adb.send_adb_command``'s hardcoded
30-second timeout (``adb.py:147``) -- and uses the streaming
``Adb.send_adb_command_popen`` primitive with a generous
``communicate(timeout=...)`` instead, for exactly this reason. This module
reuses that same approach throughout, via :func:`_run_transfer_command` and
the :class:`_LongTimeoutAdb` shim (see their docstrings for how each of the
four tools gets it): none of the four bottom out in the bare 30s default.

**Injection hardening**: ``FileExtractionService.pull_file``'s internal
``f"pull {remote_path} {local_path}"`` is unquoted and is not modified here
(confirmed scope: fix at new call sites only). Only
``remote_path`` (the device-side path) is ``shlex.quote()``-d before being
passed in -- ``local_path`` (the destination) is *also* used internally for
plain filesystem calls (``Path(local_path).parent.mkdir(...)``,
``os.path.exists(local_path)``), so quoting it would corrupt those checks
without adding any real safety. Instead, the *basename* fragment that feeds
into ``local_path`` (``local_filename`` or ``remote_path``'s own basename in
``pull_path``; each split's device-side basename in ``pull_apk``) is
sanitized down to a safe charset (:func:`_sanitize_basename`) before it is
ever joined into a destination path -- this is what actually closes the
host-side injection: a single ``shlex.quote()`` would have protected the
``pull``'s shell-command embedding but *broken* the plain-Python
``Path``/``os.path.exists`` uses of the same string (review-caught bug,
fixed here). ``push_path`` does not
call :meth:`sandroid.core.adb.Adb.push_file` directly -- confirmed by
reading it, that classmethod already ``shlex.quote()``-s both of its
arguments internally, but it bottoms out in ``Adb.send_adb_command``'s
hardcoded 30s timeout with no override point, which the timeout note above
requires avoiding. Instead, ``push_path`` builds the equivalent ``adb push``
command itself over :func:`_run_transfer_command`, quoting both paths and
detecting success/failure the same way ``Adb.push_file`` does.
"""

import logging
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools._host_paths import resolve_confined_host_path
from sandroid.ai.tools._shared import (
    PACKAGE_NAME_PARAM,
    parse_pm_path_output,
    resolve_package_name,
    validate_package_name,
)
from sandroid.ai.tools.registry import RiskTier, sandroid_tool
from sandroid.core.adb import Adb
from sandroid.services.file_extraction_service import (
    ExtractionResult,
    FileExtractionService,
)

logger = logging.getLogger(__name__)

#: Mirrors app_query.py's own ``_APK_PULL_TIMEOUT_SECONDS`` -- verified on a
#: live emulator, a single 139MB APK took ~52s to pull, well past
#: ``Adb.send_adb_command``'s hardcoded 30s timeout. Every device<->host
#: transfer this module makes (pulls *and* pushes) can be arbitrarily large,
#: so all of them go through ``_run_transfer_command``/``_LongTimeoutAdb``
#: below instead of accepting the 30s default.
_TRANSFER_TIMEOUT_SECONDS = 180

#: Characters allowed in a sanitized destination basename. Deliberately an
#: *allowlist* (not a denylist of shell metacharacters) -- the same string
#: this module builds from ends up embedded in a ``shell=True`` command
#: string (``FileExtractionService.pull_file``'s internal
#: ``f"pull {remote_path} {local_path}"``) *and* used in plain Python
#: ``Path``/``os.path.exists`` calls, so there is no single quoting scheme
#: that is simultaneously correct for both -- validating against a safe
#: charset up front is (see the module docstring's injection-hardening
#: section for the review finding that motivated this).
_UNSAFE_BASENAME_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]")


def _sanitize_basename(basename: str) -> str:
    """Reduce a caller-influenced basename to a safe, host-injection-free charset.

    Strips every character outside ``[A-Za-z0-9._-]`` -- this removes shell
    metacharacters (``;``, backticks, ``$``, ``|``, ``&``, ``#``, quotes,
    whitespace, path separators, etc.) regardless of which of the three
    contexts (shell command string, argv list, plain ``Path`` operation) the
    result is later used in, rather than trying to quote correctly for each
    one individually.

    Args:
        basename: A filename fragment, expected to already be a bare
            basename (no directory components) -- callers strip those with
            :func:`os.path.basename` first.

    Returns:
        The sanitized basename, or ``"pulled_file"`` if sanitizing left
        nothing behind (e.g. *basename* was empty or entirely made of
        disallowed characters).
    """
    sanitized = _UNSAFE_BASENAME_CHARS_RE.sub("", basename)
    return sanitized or "pulled_file"


def _run_transfer_command(command: str) -> tuple[str, str]:
    """Run one top-level ``adb`` command (``push``/``pull``) with a long timeout.

    Reuses :meth:`sandroid.core.adb.Adb.send_adb_command_popen` -- the same
    streaming-``Popen`` primitive :mod:`sandroid.ai.tools.app_query` already
    uses to work around ``Adb.send_adb_command``'s hardcoded 30-second
    timeout for exactly this kind of large transfer -- but applies the
    timeout to ``Popen.communicate()`` instead, so a slow device or large
    file gets :data:`_TRANSFER_TIMEOUT_SECONDS` instead of 30.

    Args:
        command: Full ``adb``-level command, e.g. ``"pull /remote /local"``
            or ``"push /local /remote"`` -- already ``shlex.quote()``-d by
            the caller where needed; this function does no quoting of its
            own.

    Returns:
        A ``(stdout, stderr)`` tuple, decoded to ``str`` (``send_adb_command_popen``'s
        ``Popen`` has no ``text=True``, so ``communicate()`` normally returns
        ``bytes``). On timeout, the process is killed and ``("", "transfer
        timed out after <N>s")`` is returned instead of raising -- callers
        treat this like any other ADB failure string.
    """
    process = Adb.send_adb_command_popen(command)
    try:
        raw_stdout, raw_stderr = process.communicate(timeout=_TRANSFER_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        logger.warning(
            "file_transfer: command timed out after %ss: %s",
            _TRANSFER_TIMEOUT_SECONDS,
            command,
        )
        return "", f"transfer timed out after {_TRANSFER_TIMEOUT_SECONDS}s"

    stdout = (
        raw_stdout.decode("utf-8", "replace")
        if isinstance(raw_stdout, bytes)
        else (raw_stdout or "")
    )
    stderr = (
        raw_stderr.decode("utf-8", "replace")
        if isinstance(raw_stderr, bytes)
        else (raw_stderr or "")
    )
    return stdout, stderr.strip()


class _LongTimeoutAdb:
    """``FileExtractionService``'s ``AdbProtocol`` seam, wired to the long timeout.

    ``FileExtractionService.pull_file``/``.pull_all_for_package`` both
    bottom out in ``self._get_adb().send_adb_command(...)`` -- the global
    :class:`~sandroid.core.adb.Adb` class by default, whose
    ``send_adb_command`` hardcodes a 30-second timeout with no override.
    Rather than touch that already-shipped core code, this module drops a
    small object satisfying the same single-method ``AdbProtocol`` (see
    ``file_extraction_service.AdbProtocol``) into ``FileExtractionService``'s
    existing dependency-injection constructor parameter, backed by
    :func:`_run_transfer_command` instead.
    """

    @staticmethod
    def send_adb_command(command: str) -> tuple[str, str]:
        """Satisfy ``AdbProtocol`` by delegating to the long-timeout runner."""
        return _run_transfer_command(command)


def _long_timeout_extraction_service() -> FileExtractionService:
    """Build a ``FileExtractionService`` whose pulls don't cap out at 30s.

    A fresh instance rather than the process-wide
    :func:`sandroid.services.get_file_extraction_service` singleton -- the
    singleton's ``Adb``-backed default has no timeout override, and mutating
    its ``_adb`` after the fact would reach into shared, possibly
    concurrently used state. ``FileExtractionService``'s own docstring
    already documents ``adb=`` dependency injection as its supported
    extension point (e.g. for tests), so this is not a new pattern -- just a
    new use of an existing one.

    Returns:
        A ``FileExtractionService`` instance backed by
        :class:`_LongTimeoutAdb`.
    """
    return FileExtractionService(adb=_LongTimeoutAdb())


def _raw_results_root() -> Path:
    """Resolve the session's raw-results directory to an absolute path.

    **Review-caught bug, fixed here**:
    ``ConfigurationService.get_raw_results_path()`` (see
    :mod:`sandroid.services.configuration_service`)
    returns a *relative* string by construction (e.g. ``"results/raw/"``).
    Passing that relative string straight into
    :func:`~sandroid.ai.tools._host_paths.resolve_confined_host_path` would
    anchor it against ``ai_data_share`` (that function's fallback anchor for
    any relative input), not the session's own raw-results directory --
    silently misfiling every pulled file under ``~/Sandroid/ai_share/...``
    instead of the intended session folder. Resolving to an absolute path
    *here*, before any confinement call, mirrors exactly how
    ``_host_paths._allowed_roots()`` resolves its own ``session_raw_results``
    entry.

    Returns:
        The absolute, expanded raw-results directory path (may not exist on
        disk yet if no analysis session has been started -- in which case
        the caller's later ``resolve_confined_host_path`` call will
        correctly reject the computed destination as unavailable).
    """
    from sandroid.services import get_configuration_service

    raw_results_path = get_configuration_service().get_raw_results_path()
    return Path(raw_results_path).expanduser().resolve()


def _pull_result_dict(remote_path: str, result: ExtractionResult) -> dict[str, Any]:
    """Shape one ``ExtractionResult`` into this module's tool-result schema.

    Takes *remote_path* as a separate argument rather than reading
    ``result.source_path`` so callers can pass the original, unquoted device
    path the model gave -- ``result.source_path`` reflects whatever string
    was actually handed to ``FileExtractionService.pull_file``, which may be
    ``shlex.quote()``-d.

    Args:
        remote_path: The original (unquoted) device path.
        result: The extraction outcome for that path.

    Returns:
        ``{"remote_path", "local_path", "success", "error", "hash_sha256"}``.
    """
    return {
        "remote_path": remote_path,
        "local_path": result.local_path,
        "success": result.success,
        "error": result.error,
        "hash_sha256": result.hash_sha256,
    }


@sandroid_tool(
    name="pull_path",
    description=(
        "Pull a file from the device to the host. The destination is "
        "always tool-computed under this session's raw-results directory "
        "(ai_pulls/<timestamp>_<filename>) -- the model cannot choose where "
        "on the host it lands, only optionally hint at a filename."
    ),
    parameters={
        "type": "object",
        "properties": {
            "remote_path": {
                "type": "string",
                "description": "Path to the file on the device to pull.",
            },
            "local_filename": {
                "type": "string",
                "description": (
                    "Optional filename hint for the saved file (e.g. "
                    "'config.xml'). Any directory component is stripped -- "
                    "this can only name the file, never redirect where it "
                    "is saved or escape via '../'. Defaults to remote_path's "
                    "own basename."
                ),
            },
        },
        "required": ["remote_path"],
    },
    risk=RiskTier.REVERSIBLE,
    category="file_transfer",
    can_remember_choice=True,
)
def pull_path(remote_path: str, local_filename: str | None = None) -> dict[str, Any]:
    """Pull one device file to a tool-computed, timestamped host path.

    Real integration point:
    :meth:`~sandroid.services.file_extraction_service.FileExtractionService.pull_file`,
    called against a locally constructed service instance backed by
    :class:`_LongTimeoutAdb` instead of the default 30s-capped ``Adb``
    (see the module docstring's timeout note).

    ``can_remember_choice=True``: the destination is always this module's
    own confined session tree, so the exposure is bounded and roughly
    constant regardless of which device path is named (see the module
    docstring's pull-vs-push risk rationale).

    Args:
        remote_path: Path to the file on the device to pull.
        local_filename: Optional filename hint, reduced to
            ``os.path.basename(...)`` first (a filename hint, never a path)
            so it cannot smuggle a directory or a ``../`` escape into the
            destination, then further sanitized by :func:`_sanitize_basename`
            down to a safe charset (host-injection hardening, review-caught
            bug fixed here). Defaults to ``remote_path``'s own basename.

    Returns:
        ``{"remote_path": str, "local_path": str, "success": bool,
        "error": str | None, "hash_sha256": str | None}``.

    Raises:
        ToolExecutionError: *remote_path* is empty, or the computed
            destination falls outside every allowed host root (raised by
            ``resolve_confined_host_path`` -- in practice this only happens
            if no analysis session has been started yet, since the
            destination always lives under the session's own raw-results
            directory).
    """
    if not remote_path:
        raise ToolExecutionError("remote_path must not be empty")

    if local_filename:
        basename = os.path.basename(local_filename)
    else:
        basename = os.path.basename(remote_path.rstrip("/"))
    basename = _sanitize_basename(basename)

    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    destination = _raw_results_root() / "ai_pulls" / f"{timestamp}_{basename}"
    confined_destination = resolve_confined_host_path(str(destination))

    result = _long_timeout_extraction_service().pull_file(
        remote_path=shlex.quote(remote_path),
        local_path=str(confined_destination),
        compute_hash=True,
    )
    return _pull_result_dict(remote_path, result)


@sandroid_tool(
    name="push_path",
    description=(
        "Push a file from the analyst's host machine to the device. The "
        "host source path must resolve within an allowed host directory -- "
        "a bare filename is resolved against the AI data-share folder; call "
        "list_allowed_host_paths to see what else is reachable."
    ),
    parameters={
        "type": "object",
        "properties": {
            "local_path": {
                "type": "string",
                "description": (
                    "Path to the file on the host to push. A bare filename "
                    "(e.g. 'payload.bin') is resolved against the AI "
                    "data-share folder; an absolute path must fall within "
                    "an allowed host root."
                ),
            },
            "remote_path": {
                "type": "string",
                "description": "Destination path on the device.",
            },
        },
        "required": ["local_path", "remote_path"],
    },
    risk=RiskTier.CONSEQUENTIAL,
    category="file_transfer",
    can_remember_choice=False,
)
def push_path(local_path: str, remote_path: str) -> dict[str, Any]:
    """Push a confined host file onto the device.

    Real integration point: an ``adb push`` run over
    :func:`_run_transfer_command`, deliberately *not*
    :meth:`sandroid.core.adb.Adb.push_file` -- confirmed by reading it, that
    classmethod already ``shlex.quote()``-s both arguments internally, but
    its command execution bottoms out in ``Adb.send_adb_command``'s
    hardcoded 30-second timeout with no override, which the module
    docstring's timeout note requires avoiding for a potentially large
    pushed file. This function instead builds the equivalent command
    directly, quoting both paths the same way ``Adb.push_file`` does, and
    detects success/failure with the same substring checks
    (``"error"``/``"no such file"``/``"failed to copy"``/``"permission
    denied"``).

    *local_path* (the host source) is resolved through
    :func:`sandroid.ai.tools._host_paths.resolve_confined_host_path` before
    it is ever read -- reachable sources are the data-share folder, past
    pulls, or configured extra roots.

    ``can_remember_choice=False``: *which* device path gets overwritten and
    *which* host file's bytes reach the device both vary per call -- the
    same argument-dependent-risk reasoning as ``install_apk``.

    Args:
        local_path: Path to the file on the host, resolved through the
            confined host-path allowlist.
        remote_path: Destination path on the device.

    Returns:
        ``{"pushed": bool, "local_path": str, "remote_path": str,
        "message": str}``.

    Raises:
        ToolExecutionError: *remote_path* is empty, or *local_path* falls
            outside every allowed host directory (raised by
            ``resolve_confined_host_path``).
    """
    if not remote_path:
        raise ToolExecutionError("remote_path must not be empty")

    resolved_local = resolve_confined_host_path(local_path)
    stdout, stderr = _run_transfer_command(
        f"push {shlex.quote(str(resolved_local))} {shlex.quote(remote_path)}"
    )
    combined = f"{stdout} {stderr}".strip()
    lowered = combined.lower()
    failed = (
        "error" in lowered
        or "no such file" in lowered
        or "failed to copy" in lowered
        or "permission denied" in lowered
    )
    message = combined or (
        "push failed" if failed else f"Pushed {resolved_local} to {remote_path}"
    )
    return {
        "pushed": not failed,
        "local_path": str(resolved_local),
        "remote_path": remote_path,
        "message": message,
    }


@sandroid_tool(
    name="pull_apk",
    description=(
        "Pull an installed package's APK file(s) from the device to the "
        "host, computing a SHA-256 hash of each. Handles split APKs (base "
        "plus any config/feature splits) -- pulls every split 'pm path' "
        "reports. Omit package_name to use the analyst's current spotlight "
        "app."
    ),
    parameters={
        "type": "object",
        "properties": {"package_name": PACKAGE_NAME_PARAM},
        "required": [],
    },
    risk=RiskTier.REVERSIBLE,
    category="file_transfer",
    can_remember_choice=True,
)
def pull_apk(package_name: str | None = None) -> dict[str, Any]:
    """Pull every split APK of a package, hashing each on arrival.

    Real integration point: ``pm path <pkg>`` (parsed via
    :func:`sandroid.ai.tools._shared.parse_pm_path_output`) then
    ``FileExtractionService.pull_file`` per split, against a locally
    constructed, long-timeout service instance (see the module docstring's
    timeout note) -- deliberately *not*
    ``FileExtractionService.pull_and_hash_apks``, which unconditionally
    pulls **every** installed package and deletes each local file after
    hashing (it has one existing caller, ``Toolbox.pull_and_hash_apks``,
    used for the standard whole-device "APK Hashes" report, whose behavior
    must not change).

    **Destination-path construction (review-caught bug, fixed here)**: see
    :func:`_raw_results_root`'s docstring -- the destination directory is
    resolved to an **absolute** path first, before any confinement check,
    so it lands under the session's own raw-results tree rather than being
    silently misanchored to ``ai_data_share``.

    Args:
        package_name: Fully qualified package name, or ``None`` to resolve
            the current spotlight app.

    Returns:
        ``{"package_name": str, "destination_dir": str, "splits": [...],
        "success": bool}`` -- ``splits`` is one
        ``{"remote_path", "local_path", "success", "error", "hash_sha256"}``
        dict per split (see :func:`pull_path`'s return shape), in the order
        ``pm path`` printed them. ``success`` is ``True`` only if every
        split pulled successfully.

    Raises:
        ToolExecutionError: *package_name* does not match Android's package
            identifier format (see
            :func:`sandroid.ai.tools._shared.validate_package_name`), or the
            package has no APK paths reported by ``pm path`` (not
            installed).
    """
    pkg = validate_package_name(resolve_package_name(package_name))

    stdout, _stderr = Adb.send_adb_command(f"shell pm path {shlex.quote(pkg)}")
    device_paths = parse_pm_path_output(stdout)
    if not device_paths:
        raise ToolExecutionError(f"package {pkg!r} has no APK paths (not installed?)")

    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    destination_dir = _raw_results_root() / "ai_pulls" / "apks" / f"{pkg}_{timestamp}"

    service = _long_timeout_extraction_service()
    splits: list[dict[str, Any]] = []
    for device_path in device_paths:
        destination = destination_dir / _sanitize_basename(
            os.path.basename(device_path)
        )
        confined_destination = resolve_confined_host_path(str(destination))
        result = service.pull_file(
            remote_path=shlex.quote(device_path),
            local_path=str(confined_destination),
            compute_hash=True,
        )
        splits.append(_pull_result_dict(device_path, result))

    return {
        "package_name": pkg,
        "destination_dir": str(destination_dir),
        "splits": splits,
        "success": all(split["success"] for split in splits),
    }


@sandroid_tool(
    name="pull_app_data",
    description=(
        "Pull all accessible files from a package's app-data directories "
        "(e.g. /data/data/<pkg>, /data/user/0/<pkg>, "
        "/sdcard/Android/data/<pkg>) to the host. Omit package_name to use "
        "the analyst's current spotlight app."
    ),
    parameters={
        "type": "object",
        "properties": {"package_name": PACKAGE_NAME_PARAM},
        "required": [],
    },
    risk=RiskTier.REVERSIBLE,
    category="file_transfer",
    can_remember_choice=True,
)
def pull_app_data(package_name: str | None = None) -> dict[str, Any]:
    """Pull every accessible file under a package's app-data directories.

    Real integration point: ``FileExtractionService.pull_all_for_package``,
    called against a locally constructed, long-timeout service instance (see
    the module docstring's timeout note). Its own ``output_dir`` default
    (``<results_path>/package_files/<pkg>/<timestamp>/``) is never
    model-exposed, so unlike ``pull_path``/``pull_apk`` this needs no
    separate ``resolve_confined_host_path`` call -- there is no
    model-supplied destination fragment to confine.

    Args:
        package_name: Fully qualified package name, or ``None`` to resolve
            the current spotlight app.

    Returns:
        ``{"package_name": str, "files": [...], "count": int, "success":
        bool}`` -- ``files`` is one
        ``{"remote_path", "local_path", "success", "error", "hash_sha256"}``
        dict per file found (see :func:`pull_path`'s return shape).
        ``success`` is ``True`` only if every discovered file pulled
        successfully (vacuously ``True`` if no files were found).

    Raises:
        ToolExecutionError: *package_name* does not match Android's package
            identifier format (see
            :func:`sandroid.ai.tools._shared.validate_package_name`) --
            validated here, before *pkg* ever reaches
            ``pull_all_for_package``'s internal ``shell=True`` ``find``
            command and plain-Python ``Path`` join (review-caught bug,
            fixed here: previously reached both completely unsanitized).
    """
    pkg = validate_package_name(resolve_package_name(package_name))
    results = _long_timeout_extraction_service().pull_all_for_package(pkg)
    files = [_pull_result_dict(result.source_path, result) for result in results]
    return {
        "package_name": pkg,
        "files": files,
        "count": len(files),
        "success": all(f["success"] for f in files),
    }
