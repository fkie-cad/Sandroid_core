"""Confined host-filesystem tools for the Sandroid AI chat.

Every tool here reads from the analyst's host machine, never the Android
device -- ``list_host_dir``/``read_host_file`` resolve their ``path``
argument through
:func:`sandroid.ai.tools._host_paths.resolve_confined_host_path`, so a
model-supplied path outside the configured allowlist of host roots is always
rejected before any filesystem access happens. ``list_allowed_host_paths``
lets the model introspect that allowlist directly instead of guessing or
learning it one rejection at a time.

Importing this module registers all three tools into the
:class:`~sandroid.ai.tools.registry.ToolRegistry` singleton as a side effect
(see the ``@sandroid_tool`` decorator). All three tools in this module are
``RiskTier.READ_ONLY`` and ``category="host_files"``.
"""

import base64
import os
from datetime import datetime, timezone
from typing import Any

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools._host_paths import _allowed_roots, resolve_confined_host_path
from sandroid.ai.tools.registry import RiskTier, sandroid_tool

#: Hard ceiling on how many bytes `read_host_file` will ever read, regardless
#: of what its `max_bytes` argument asks for.
_MAX_READ_BYTES = 1024 * 1024  # 1 MiB

_HOST_PATH_PARAM_DESCRIPTION = (
    "Host filesystem path. Absolute, or relative to the AI's data-share "
    "folder (the 'ai_data_share' root) if not absolute. Must resolve inside "
    "one of the host roots the AI is currently allowed to access -- call "
    "list_allowed_host_paths to see them."
)


@sandroid_tool(
    name="list_host_dir",
    description=(
        "List the entries of a directory on the analyst's host machine. "
        "Confined to an explicit allowlist of host roots (the AI data-share "
        "folder, the current analysis session's results/raw-results "
        "directories, the cache directory, and any configured extra roots) "
        "-- a path outside every allowed root is rejected."
    ),
    parameters={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": _HOST_PATH_PARAM_DESCRIPTION,
            },
        },
        "required": ["path"],
    },
    risk=RiskTier.READ_ONLY,
    category="host_files",
)
def list_host_dir(path: str) -> dict[str, Any]:
    """List a confined host directory's entries.

    Real integration point:
    :func:`sandroid.ai.tools._host_paths.resolve_confined_host_path` for
    confinement, then a plain :func:`os.scandir` over the resolved path.

    Args:
        path: Host directory to list -- absolute, or relative to
            ``ai_data_share`` if not absolute.

    Returns:
        ``{"path": str, "entries": [...], "count": int}``. Each entry is
        normally ``{"name": str, "is_dir": bool, "is_symlink": bool,
        "size_bytes": int | None, "modified_time": str}`` -- ``size_bytes``
        is ``None`` for directories, and ``modified_time`` is an ISO 8601
        UTC timestamp. An entry that could not be ``stat()``-ed (e.g. a
        broken symlink) instead carries ``{"name": str, "error": str}`` and
        no other fields, so one bad entry doesn't fail the whole listing.

    Raises:
        ToolExecutionError: *path* falls outside every allowed host root,
            or does not resolve to an existing directory.
    """
    resolved = resolve_confined_host_path(path)
    if not resolved.is_dir():
        raise ToolExecutionError(f"host path {path!r} is not a directory")

    entries: list[dict[str, Any]] = []
    with os.scandir(resolved) as scandir_it:
        raw_entries = sorted(scandir_it, key=lambda e: e.name)
    for entry in raw_entries:
        try:
            stat_result = entry.stat(follow_symlinks=False)
            is_dir = entry.is_dir(follow_symlinks=False)
            entries.append(
                {
                    "name": entry.name,
                    "is_dir": is_dir,
                    "is_symlink": entry.is_symlink(),
                    "size_bytes": None if is_dir else stat_result.st_size,
                    "modified_time": datetime.fromtimestamp(
                        stat_result.st_mtime, tz=timezone.utc
                    ).isoformat(),
                }
            )
        except OSError as exc:
            entries.append({"name": entry.name, "error": str(exc)})

    return {"path": str(resolved), "entries": entries, "count": len(entries)}


@sandroid_tool(
    name="read_host_file",
    description=(
        "Read a file's contents from the analyst's host machine. Confined "
        "to the same host-root allowlist as list_host_dir. Reads at most "
        "max_bytes (default 65536), hard-capped at 1 MiB regardless of what "
        "is requested; the response reports whether the content was "
        "truncated and the file's true on-disk size. Content is returned as "
        "UTF-8 text when possible, otherwise base64-encoded."
    ),
    parameters={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": _HOST_PATH_PARAM_DESCRIPTION,
            },
            "max_bytes": {
                "type": "integer",
                "description": (
                    "Maximum number of bytes to read. Defaults to 65536 (64 "
                    "KiB). Hard-capped at 1048576 (1 MiB) even if a higher "
                    "value is given."
                ),
                "default": 65536,
            },
        },
        "required": ["path"],
    },
    risk=RiskTier.READ_ONLY,
    category="host_files",
)
def read_host_file(path: str, max_bytes: int = 65536) -> dict[str, Any]:
    """Read a confined host file's contents, truncated to a byte ceiling.

    Real integration point:
    :func:`sandroid.ai.tools._host_paths.resolve_confined_host_path` for
    confinement, then a plain binary read of at most
    ``min(max_bytes, 1 MiB)`` bytes.

    Args:
        path: Host file to read -- absolute, or relative to
            ``ai_data_share`` if not absolute.
        max_bytes: Maximum number of bytes to read. Silently clamped down to
            a hard 1 MiB ceiling if higher -- there is no way to request
            more than that regardless of this argument.

    Returns:
        ``{"path": str, "content": str, "encoding": "utf-8" | "base64",
        "truncated": bool, "size_bytes": int, "bytes_read": int}``.
        ``size_bytes`` is the file's true on-disk size, not the (possibly
        smaller) number of bytes actually read. ``content`` is decoded as
        UTF-8 when possible; if the bytes read are not valid UTF-8 (e.g. a
        binary file, or a truncation that happened to split a multi-byte
        character), ``content`` is base64-encoded instead and ``encoding``
        reports that.

    Raises:
        ToolExecutionError: *path* falls outside every allowed host root,
            does not resolve to an existing file, resolves to a directory,
            or *max_bytes* is not a positive integer.
    """
    resolved = resolve_confined_host_path(path)
    if not resolved.exists():
        raise ToolExecutionError(f"host path {path!r} does not exist")
    if resolved.is_dir():
        raise ToolExecutionError(
            f"host path {path!r} is a directory, not a file -- use "
            "list_host_dir instead"
        )

    try:
        max_bytes = int(max_bytes)
    except (TypeError, ValueError) as exc:
        raise ToolExecutionError(
            f"max_bytes must be an integer, got {max_bytes!r}"
        ) from exc
    if max_bytes <= 0:
        raise ToolExecutionError(f"max_bytes must be positive, got {max_bytes!r}")

    effective_max = min(max_bytes, _MAX_READ_BYTES)
    size_bytes = resolved.stat().st_size

    with open(resolved, "rb") as fh:
        raw = fh.read(effective_max)

    truncated = size_bytes > len(raw)
    try:
        content = raw.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        content = base64.b64encode(raw).decode("ascii")
        encoding = "base64"

    return {
        "path": str(resolved),
        "content": content,
        "encoding": encoding,
        "truncated": truncated,
        "size_bytes": size_bytes,
        "bytes_read": len(raw),
    }


@sandroid_tool(
    name="list_allowed_host_paths",
    description=(
        "List every host directory the AI's file tools (list_host_dir, "
        "read_host_file, and any host-writing tools) are currently allowed "
        "to access, with an availability flag and reason for any root "
        "that's currently unreachable. Call this to find out what's "
        "reachable before guessing a path, or after a path was rejected."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    risk=RiskTier.READ_ONLY,
    category="host_files",
)
def list_allowed_host_paths() -> dict[str, Any]:
    """List every host root the AI's file tools may currently resolve into.

    Real integration point:
    :func:`sandroid.ai.tools._host_paths._allowed_roots`, called fresh on
    every invocation (see that function's own docstring for why it is never
    cached -- the session/device can change mid-chat).

    Returns:
        ``{"roots": [...]}`` where each entry is a plain-JSON-serializable
        copy of one of ``_allowed_roots()``'s dicts --
        ``{"label": str, "path": str | None, "available": bool, "reason":
        str | None}`` -- with each ``Path`` stringified (or left ``None`` if
        that root's computation failed).
    """
    roots = [
        {
            "label": root["label"],
            "path": str(root["path"]) if root["path"] is not None else None,
            "available": root["available"],
            "reason": root["reason"],
        }
        for root in _allowed_roots()
    ]
    return {"roots": roots}
