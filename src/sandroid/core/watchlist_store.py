"""On-disk state of the Files lens watchlist: ★ membership + pulled versions.

Two different lifetimes, two places:

1. **Membership** (what is ★ watched) persists across sessions, per package,
   in the user config directory -- one small, readable JSON file per app::

       ~/.config/sandroid/watchlists/<package>.json     (or $XDG_CONFIG_HOME)
       ~/.config/sandroid/watchlists/_device.json       paths outside an app dir

       {"schema_version": 3, "package": "com.app",
        "paths": ["/data/data/com.app/databases/app.db"],
        "patterns": ["/data/data/com.app/shared_prefs/*"]}

   Nothing else is persisted there (no pull state, no auto mode). The older
   per-device store (``watchlists/<device>/index.json`` + versions) is
   ignored -- it is neither read nor migrated nor deleted.

2. **Pulled versions** are evidence of *this* session and live in the
   session results folder, readable, and are never pruned::

       <session results>/files/<package>/<app-relative path>/v001_10-42-07/
           app.db  app.db-wal                 the pulled copy (+ db companions)
           diff.txt                           diff against the version before
           acquisition.json                   device path, device mtime/size,
                                              on-device + local sha256, pull
                                              time, trigger (manual/auto)

   ``<app-relative path>`` keeps the device layout below the app's data
   directory (``databases/app.db``); the device-encrypted and external app
   directories get an ``@de/`` / ``@ext/`` marker as in the lens. Files
   outside an app directory go under ``files/_device/<absolute path>/``. The
   session results folder is the initialization service's device folder
   (``results/<session>/<device>/``, not a running Play's bundle), else
   ``$RESULTS_PATH``.

Storage API used by the lens and the Inspector (keep names/semantics):
:func:`version_dirs` (oldest → newest), :func:`version_time`,
:func:`version_diff` (diff text vs the previous version, ``None`` for the
first), :func:`version_record` (``acquisition.json``) and
:func:`version_file` (the local copy of the main file in a version).

A pull goes ``reset_current`` (staging ``.current/``) → pull into it →
diff against :func:`previous_dir` if :func:`has_baseline` → :func:`promote`
(renames the staging directory to the next ``vNNN_HH-MM-SS``).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import uuid
from datetime import datetime
from pathlib import Path

from sandroid.core.adb_utils import canonical_device_path

logger = logging.getLogger(__name__)

#: Membership file schema (v3: per package, paths + patterns only).
SCHEMA_VERSION = 3

#: Overrides the membership directory (tests point it at a temp directory).
WATCHLIST_DIR_ENV = "SDROID_WATCHLIST_DIR"
#: Overrides the pulled-versions root (``<session results>/files``).
FILES_DIR_ENV = "SDROID_FILES_DIR"

#: Owner name for files that are not inside an app's data directory.
DEVICE_OWNER = "_device"

_DIFF_FILE = "diff.txt"
_RECORD_FILE = "acquisition.json"
_STAGING = ".current"
_VERSION_RE = re.compile(r"^v(\d+)_(\d{2})-(\d{2})-(\d{2})$")

#: ``(regex, marker)``: app data roots and the marker kept for the
#: app-relative path (same convention as the Files lens).
_APP_ROOTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^/data/(?:data|user/\d+)/([^/]+)(?:/|$)"), ""),
    (re.compile(r"^/data/user_de/\d+/([^/]+)(?:/|$)"), "@de/"),
    (
        re.compile(r"^/(?:sdcard|storage/emulated/\d+)/Android/data/([^/]+)(?:/|$)"),
        "@ext/",
    ),
)


# ---------------------------------------------------------------------------
# layout
# ---------------------------------------------------------------------------


def owner_and_relative(path: str) -> tuple[str, str]:
    """``(package, app-relative path)`` of a device path.

    ``/data/data/com.app/databases/app.db`` -> ``("com.app", "databases/app.db")``,
    ``/data/user_de/0/com.app/x`` -> ``("com.app", "@de/x")``,
    ``/data/local/tmp/x`` -> ``("_device", "data/local/tmp/x")``.
    """
    path = canonical_device_path(path)
    for regex, marker in _APP_ROOTS:
        match = regex.match(path)
        if match:
            rest = path[match.end() :].strip("/")
            return match.group(1), marker + rest if rest else marker + "_root"
    return DEVICE_OWNER, path.strip("/") or "_root"


def package_of(path: str) -> str | None:
    """The package whose data directory holds ``path`` (``None`` otherwise)."""
    owner, _rel = owner_and_relative(path)
    return None if owner == DEVICE_OWNER else owner


def _safe_parts(relative: str) -> list[str]:
    """Path components that cannot climb out of the files root."""
    out = []
    for part in relative.split("/"):
        if part in ("", ".", ".."):
            part = f"_{part}" if part else "_"
        out.append(part)
    return out


def session_results_dir() -> Path:
    """The live session's results folder (``results/<session>/<device>/``).

    The initialization service's device folder wins (a running Play pins
    ``RESULTS_PATH`` to its bundle; pulls belong to the session), then
    ``$RESULTS_PATH``, then ``./results``.
    """
    try:
        from sandroid.services import get_initialization_service

        device_path = get_initialization_service().get_device_path()
        if device_path:
            return Path(device_path).expanduser()
    except Exception:
        logger.debug("watchlist_store: no initialized session", exc_info=True)
    env_value = os.environ.get("RESULTS_PATH")
    return Path(env_value).expanduser() if env_value else Path("./results")


def files_root() -> Path:
    """Root of the pulled versions: ``<session results>/files``."""
    override = os.environ.get(FILES_DIR_ENV)
    if override:
        return Path(override).expanduser()
    return session_results_dir() / "files"


def row_dir(path: str) -> Path:
    """The folder holding every pulled version of ``path`` (created)."""
    owner, relative = owner_and_relative(path)
    directory = files_root().joinpath(owner, *_safe_parts(relative))
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _main_name(path: str) -> str:
    return os.path.basename(path.rstrip("/")) or "pulled_file"


# ---------------------------------------------------------------------------
# versions (read API)
# ---------------------------------------------------------------------------


def _version_number(version: Path) -> int | None:
    match = _VERSION_RE.match(version.name)
    return int(match.group(1)) if match else None


def version_dirs(path: str) -> list[Path]:
    """Every pulled version of ``path``, oldest first (``vNNN_HH-MM-SS/``)."""
    owner, relative = owner_and_relative(path)
    root = files_root().joinpath(owner, *_safe_parts(relative))
    if not root.is_dir():
        return []
    found = [
        (number, d)
        for d in root.iterdir()
        if d.is_dir() and (number := _version_number(d)) is not None
    ]
    return [d for _n, d in sorted(found, key=lambda pair: pair[0])]


def version_record(version: Path) -> dict | None:
    """The version's ``acquisition.json`` (``None`` if missing/unreadable)."""
    try:
        data = json.loads((version / _RECORD_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def version_time(version: Path) -> datetime | None:
    """When a version was pulled (host local time).

    From ``acquisition.json``'s ``pulled_at``; else the ``HH-MM-SS`` of the
    folder name on the folder's modification date.
    """
    record = version_record(version) or {}
    stamp = record.get("pulled_at")
    if isinstance(stamp, str):
        try:
            return datetime.fromisoformat(stamp)
        except ValueError:
            pass
    match = _VERSION_RE.match(version.name)
    if match is None:
        return None
    try:
        day = datetime.fromtimestamp(version.stat().st_mtime)
    except OSError:
        return None
    hour, minute, second = (int(match.group(i)) for i in (2, 3, 4))
    return day.replace(hour=hour, minute=minute, second=second, microsecond=0)


def version_diff(version: Path) -> str | None:
    """The diff stored with a version (against the version before it).

    ``None`` for the first version (nothing to diff against) or when no diff
    was stored; ``""`` when the pull found no change.
    """
    try:
        return (version / _DIFF_FILE).read_text(encoding="utf-8")
    except OSError:
        return None


def version_file(version: Path, path: str) -> Path:
    """The local copy of ``path``'s main file inside ``version``."""
    record = version_record(version) or {}
    name = (record.get("local") or {}).get("file") if record else None
    return version / (name if isinstance(name, str) and name else _main_name(path))


def previous_dir(path: str) -> Path:
    """The newest version of ``path`` (a non-existent folder if none)."""
    dirs = version_dirs(path)
    return dirs[-1] if dirs else row_dir(path) / "v000_none"


def has_baseline(path: str) -> bool:
    """True once a version exists to diff the next pull against."""
    return bool(version_dirs(path))


# ---------------------------------------------------------------------------
# versions (write API)
# ---------------------------------------------------------------------------


def reset_current(path: str) -> Path:
    """Clear and recreate the staging folder (``.current/``) for a pull."""
    directory = row_dir(path) / _STAGING
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def promote(
    path: str,
    diff_text: str | None = None,
    record: dict | None = None,
    when: datetime | None = None,
) -> Path:
    """Keep the staged pull as the next version of ``path``.

    The staging folder becomes ``vNNN_HH-MM-SS/`` (numbered after the newest
    version); ``diff_text`` (the diff against the version before; ``None``
    for the first pull) goes to ``diff.txt`` and ``record`` to
    ``acquisition.json`` (``"version"`` is filled in). Nothing is ever pruned.
    Returns the new version folder.
    """
    staging = row_dir(path) / _STAGING
    staging.mkdir(parents=True, exist_ok=True)
    root = staging.parent
    existing = version_dirs(path)
    number = (_version_number(existing[-1]) or 0) + 1 if existing else 1
    stamp = (when or datetime.now()).strftime("%H-%M-%S")
    target = root / f"v{number:03d}_{stamp}"
    while target.exists():
        number += 1
        target = root / f"v{number:03d}_{stamp}"
    if diff_text is not None:
        (staging / _DIFF_FILE).write_text(diff_text, encoding="utf-8")
    if record is not None:
        payload = dict(record)
        payload["version"] = target.name
        _atomic_write_json(staging / _RECORD_FILE, payload)
    staging.replace(target)
    return target


# ---------------------------------------------------------------------------
# membership (per package, in the user config directory)
# ---------------------------------------------------------------------------


def _user_dir() -> Path:
    """Sandroid's per-user directory (``$XDG_CONFIG_HOME/sandroid`` or
    ``~/.config/sandroid``).
    """
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "sandroid"


def watchlist_dir() -> Path:
    """The membership directory (``<user dir>/watchlists/``, created)."""
    override = os.environ.get(WATCHLIST_DIR_ENV)
    directory = Path(override).expanduser() if override else _user_dir() / "watchlists"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def membership_file(owner: str) -> Path:
    """``<watchlists>/<package>.json`` (``_device.json`` outside app dirs)."""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in owner)
    return watchlist_dir() / f"{safe.strip('.') or DEVICE_OWNER}.json"


def _atomic_write_json(path: Path, data) -> None:
    """Write ``data`` as JSON to ``path`` atomically (same-directory temp + replace)."""
    tmp_path = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex[:8]}")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    tmp_path.replace(path)


def _membership_files() -> list[Path]:
    return sorted(
        p for p in watchlist_dir().glob("*.json") if not p.name.startswith(".")
    )


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning(f"watchlist_store: {path.name} unreadable ({exc})")
        return {}
    return data if isinstance(data, dict) else {}


def save_membership(paths: list[str], patterns: list[str] | None = None) -> None:
    """Persist the ★ paths and patterns, one file per package.

    A package that no longer has any watch keeps its file with empty lists
    (nothing in the user's config directory is deleted behind their back).
    """
    grouped: dict[str, dict[str, list[str]]] = {}
    for kind, items in (("paths", paths), ("patterns", patterns or [])):
        for item in items:
            if not isinstance(item, str) or not item:
                continue
            owner, _rel = owner_and_relative(item)
            entry = grouped.setdefault(owner, {"paths": [], "patterns": []})
            if item not in entry[kind]:
                entry[kind].append(item)
    owners = set(grouped)
    for existing in _membership_files():
        owner = str(_read(existing).get("package") or existing.stem)
        if owner not in owners and existing == membership_file(owner):
            grouped[owner] = {"paths": [], "patterns": []}
    for owner, entry in grouped.items():
        _atomic_write_json(
            membership_file(owner),
            {
                "schema_version": SCHEMA_VERSION,
                "package": owner,
                "paths": entry["paths"],
                "patterns": entry["patterns"],
            },
        )


def _load(kind: str) -> list[str]:
    out: list[str] = []
    for path in _membership_files():
        items = _read(path).get(kind)
        if not isinstance(items, list):
            continue
        out.extend(i for i in items if isinstance(i, str) and i not in out)
    return out


def load_membership() -> list[str]:
    """Every persisted ★ path (all packages); ``[]`` when none/unreadable."""
    return _load("paths")


def load_patterns() -> list[str]:
    """Every persisted ★ wildcard pattern (all packages)."""
    return _load("patterns")


__all__ = [
    "DEVICE_OWNER",
    "FILES_DIR_ENV",
    "SCHEMA_VERSION",
    "WATCHLIST_DIR_ENV",
    "files_root",
    "has_baseline",
    "load_membership",
    "load_patterns",
    "membership_file",
    "owner_and_relative",
    "package_of",
    "previous_dir",
    "promote",
    "reset_current",
    "row_dir",
    "save_membership",
    "session_results_dir",
    "version_diff",
    "version_dirs",
    "version_file",
    "version_record",
    "version_time",
    "watchlist_dir",
]
