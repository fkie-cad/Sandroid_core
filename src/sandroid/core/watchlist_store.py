"""Watchlist sub-tab's on-disk state: membership persistence + the local
pull baseline cache.

Two related but distinct things live under one directory -- the stable
per-device :func:`watchlist_dir` (``~/.config/sandroid/watchlists/<device>/``,
so watches and pull history survive a restart; it used to be the per-session
``RESULTS_PATH/spotlight_files/.watchlist/``) -- because the Watchlist sub-tab
(``tui/widgets/watchlist_view.py``) has neither of the two persistence
conventions already established elsewhere in this app: Play's ``runs/``
(``core/run_history.py``) or the ``first_pull``/``second_pull`` snapshot-
folder pair ``ChangedFiles.return_data()`` uses.

1. **Membership + per-row state** (``index.json``): the list of watched
   paths themselves, PLUS (as of schema v2) each path's last-known
   ``RowState``/``detail``/``last_seen``/``last_pulled`` and whether
   auto-mode itself was on. ``ForensicService._spotlight_files`` is
   in-memory only, so without persisting at least the path list the whole
   watchlist evaporates on every TUI restart -- and without the per-row
   state too, a restart would silently forget which paths had already been
   pulled/changed and show every row as freshly NEVER_PULLED. see
   ``tui/widgets/watchlist_view.py``'s ``_RowInfo`` for the in-memory shape
   this mirrors. ``ForensicService`` owns *when* to call
   :func:`save_membership`/:func:`load_membership` (after a mutation / on
   startup, see its ``save_watchlist_index``/``load_watchlist_index``
   methods); ``WatchlistView`` owns the per-row state itself (this module
   only owns the on-disk shape, and exposes :func:`load_row_states`/
   :func:`load_auto_enabled` directly since that state doesn't belong to
   ``ForensicService``). Mirrors how ``core/run_history.py`` is the sole
   owner of the ``runs/`` on-disk shape while ``RecordingController``
   decides when to call it.

2. **Per-path pull history** (``<sanitized-path>/{current,versions/<ts>}``):
   ``current`` is the staging area of the pull in progress; every pull is
   then kept as ``versions/<timestamp>/`` together with ``diff.txt`` (its
   diff against the version before), bounded to the newest N
   (``tui.watchlist_max_versions``). Callers (``WatchlistView``) are expected
   to: clear+recreate ``current`` via :func:`reset_current`, pull the fresh
   copy into it, diff against :func:`previous_dir` (the newest version) if
   :func:`has_baseline` is True, then call :func:`promote` (with the diff)
   to keep the pull as a new version.

Sanitized directory naming (:func:`sanitize_path`): device paths contain
``/``, which can't be a literal path component, so each watched path's cache
directory name is ``urllib.parse.quote(path, safe="")`` -- percent-encoding
is reversible and keeps the directory name legible for debugging (e.g.
``%2Fdata%2Fdata%2Fcom.app%2Fdatabases%2Fapp.db``). Pathologically long
paths (encoded length over ``_MAX_ENCODED_NAME``, comfortably clear of
common 255-byte filename limits) are truncated and disambiguated with a
short sha256 suffix instead, so two long-but-different paths that happen to
share the same truncated prefix can never collide on disk.

Every JSON write in this module goes through :func:`_atomic_write_json`
(temp file in the same directory + ``Path.replace``), the same crash-safety
convention ``run_history.py`` uses.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

logger = logging.getLogger(__name__)

#: Bumped if index.json's on-disk shape changes incompatibly. v2 added the
#: "rows" (per-path state) and "auto_enabled" fields alongside "paths" --
#: readers of a v1 file (which has neither key) still work unchanged since
#: every accessor below treats a missing key as "nothing persisted yet".
SCHEMA_VERSION = 2

#: Encoded names longer than this get truncated + sha256-disambiguated (see
#: module docstring) to stay well clear of common (255-byte) filename limits.
_MAX_ENCODED_NAME = 200
_TRUNCATED_PREFIX_LEN = 150


def sanitize_path(path: str) -> str:
    """Deterministic, collision-safe directory name for a watched *path*.

    See the module docstring for the full reasoning. Short paths (the
    overwhelming common case) just get percent-encoded; pathologically long
    ones are truncated and disambiguated with a sha256 suffix so truncation
    itself can never cause two different paths to collide.
    """
    encoded = quote(path, safe="")
    if len(encoded) <= _MAX_ENCODED_NAME:
        return encoded
    digest = hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
    return f"{encoded[:_TRUNCATED_PREFIX_LEN]}__{digest}"


def _results_path() -> Path:
    return Path(os.environ.get("RESULTS_PATH", "./results/")).expanduser()


#: Overrides the watchlist root (tests point it at a temp directory).
WATCHLIST_DIR_ENV = "SDROID_WATCHLIST_DIR"


def _user_dir() -> Path:
    """Sandroid's per-user directory (``$XDG_CONFIG_HOME/sandroid`` or
    ``~/.config/sandroid``) -- where the welcome marker, the AI tool
    permissions and the keybindings already live.
    """
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "sandroid"


def device_key() -> str:
    """The device the watchlist belongs to: the session's device folder name
    (``RESULTS_PATH`` ends in ``<session>/<device>/``), e.g. the AVD name.
    """
    name = _results_path().resolve().name if os.environ.get("RESULTS_PATH") else ""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    return safe.strip("._") or "default"


def watchlist_dir() -> Path:
    """The shared root for both membership (``index.json``) and baselines.

    Stable across sessions (M4): ``<user dir>/watchlists/<device>/``, so the
    watched files, their pull history and auto-pull state survive a restart
    (the per-session results folder is new on every start). Paths inside are
    absolute device paths, so one device's file covers all of its apps.
    """
    override = os.environ.get(WATCHLIST_DIR_ENV)
    if override:
        directory = Path(override).expanduser()
    else:
        directory = _user_dir() / "watchlists" / device_key()
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _index_path() -> Path:
    return watchlist_dir() / "index.json"


def row_dir(path: str) -> Path:
    """The per-watched-path baseline-cache directory."""
    directory = watchlist_dir() / sanitize_path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


#: Pulled versions kept per path when the caller passes no limit.
DEFAULT_MAX_VERSIONS = 10

_STAMP_FORMAT = "%Y%m%dT%H%M%S_%f"
_DIFF_FILE = "diff.txt"


def _versions_root(path: str) -> Path:
    return row_dir(path) / "versions"


def version_dirs(path: str) -> list[Path]:
    """Every kept pull of *path*, oldest first (``versions/<timestamp>/``).

    A pre-versioning ``previous/`` baseline counts as the oldest version.
    """
    root = _versions_root(path)
    dirs = (
        sorted(
            (d for d in root.iterdir() if d.is_dir() and not d.name.startswith(".")),
            key=lambda d: d.name,
        )
        if root.is_dir()
        else []
    )
    legacy = row_dir(path) / "previous"
    if legacy.is_dir() and any(legacy.iterdir()):
        dirs.insert(0, legacy)
    return dirs


def version_time(version: Path) -> datetime | None:
    """When a version was pulled (``None`` for the legacy ``previous/``)."""
    try:
        # Local wall-clock stamp, like the ISO "pulled_at" next to it.
        return datetime.strptime(version.name, _STAMP_FORMAT)  # noqa: DTZ007
    except ValueError:
        return None


def version_diff(version: Path) -> str | None:
    """The diff stored with a version (against the version before it)."""
    try:
        return (version / _DIFF_FILE).read_text(encoding="utf-8")
    except OSError:
        return None


#: Acquisition record a pull may keep next to its copy (see version_record).
_RECORD_FILES = ("record.json", "acquisition.json", "pull.json")


def version_file(version: Path, path: str) -> Path:
    """The local copy of *path*'s main file inside one kept version.

    Pulls store it under the device file's basename (``WatchlistView``);
    companions (``-wal``/``-journal``) and ``diff.txt`` sit next to it.
    """
    name = os.path.basename(path.rstrip("/")) or "pulled_file"
    candidate = version / name
    if candidate.exists():
        return candidate
    others = [
        f
        for f in (version.iterdir() if version.is_dir() else ())
        if f.is_file()
        and f.name != _DIFF_FILE
        and f.name not in _RECORD_FILES
        and not f.name.endswith(("-wal", "-journal", "-shm"))
    ]
    return others[0] if len(others) == 1 else candidate


def version_record(version: Path) -> dict | None:
    """The acquisition record of a version (device path, device mtime/size/
    sha256, local sha256, ``pulled_at``, ``trigger`` manual/auto), or None
    when the pull kept none (versions from before records existed).
    """
    for name in _RECORD_FILES:
        try:
            data = json.loads((version / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            return data
    return None


def previous_dir(path: str) -> Path:
    """The most recent kept pull of *path* (may not exist yet).

    Before versioning this was the single ``previous/`` baseline; it is now
    the newest ``versions/<timestamp>/`` directory, so the next pull diffs
    against it exactly as before.
    """
    dirs = version_dirs(path)
    return dirs[-1] if dirs else row_dir(path) / "previous"


def reset_current(path: str) -> Path:
    """Clear and recreate the ``current`` pull directory for *path*.

    Call this right before pulling a fresh copy. Clearing first guards
    against a stale companion file (e.g. a ``-wal`` that no longer exists
    on-device) leaking into this pull's diff from a previous pull's
    leftovers.
    """
    directory = row_dir(path) / "current"
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def has_baseline(path: str) -> bool:
    """True once a previous pull exists to diff the next one against."""
    return bool(version_dirs(path))


def promote(
    path: str,
    diff_text: str | None = None,
    keep: int = DEFAULT_MAX_VERSIONS,
) -> Path:
    """Keep the freshly-pulled ``current`` as a new version of *path*.

    Every pull becomes ``versions/<timestamp>/`` (the file plus its SQLite
    companions) with ``diff_text`` -- the diff against the version before
    it -- stored next to it, so neither old content nor what changed is lost
    on the next pull or a restart (M3). Only the newest ``keep`` versions
    are kept. Returns the new version directory.
    """
    current = row_dir(path) / "current"
    root = _versions_root(path)
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now()
    target = root / stamp.strftime(_STAMP_FORMAT)
    while target.exists():  # two pulls within one microsecond
        stamp = stamp.replace(microsecond=(stamp.microsecond + 1) % 1_000_000)
        target = root / stamp.strftime(_STAMP_FORMAT)
    staging = root / f".{target.name}.partial"
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(current, staging)
    if diff_text is not None:
        (staging / _DIFF_FILE).write_text(diff_text, encoding="utf-8")
    staging.replace(target)
    prune(path, keep)
    return target


def prune(path: str, keep: int = DEFAULT_MAX_VERSIONS) -> None:
    """Delete all but the newest ``keep`` (at least 2) versions of *path*."""
    dirs = version_dirs(path)
    for old in dirs[: max(0, len(dirs) - max(2, int(keep)))]:
        shutil.rmtree(old, ignore_errors=True)


def _atomic_write_json(path: Path, data) -> None:
    """Write ``data`` as JSON to ``path`` atomically (same-directory temp + replace)."""
    tmp_path = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex[:8]}")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp_path.replace(path)


def _load_index_data() -> dict:
    """Read + parse ``index.json`` once; ``{}`` on missing/corrupt file.

    Shared by :func:`load_membership`/:func:`load_row_states`/
    :func:`load_auto_enabled` so all three agree on what "unreadable" means
    (same warning, same safe-empty fallback) without each re-implementing
    the try/except.
    """
    path = _index_path()
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        logger.warning(f"watchlist_store: index.json unreadable ({exc})")
        return {}


def save_membership(
    paths: list[str],
    row_states: dict[str, dict] | None = None,
    auto_enabled: bool = False,
    patterns: list[str] | None = None,
) -> None:
    """Persist the watched-path list AND (as of schema v2) each path's
    last-known pull/auto state to ``index.json``.

    Args:
        paths: the watched-path list itself (unchanged meaning from v1).
        row_states: optional ``{path: {"state", "detail", "last_seen",
            "last_pulled"}}`` mirroring ``WatchlistView._RowInfo``'s
            in-memory shape (see ``WatchlistView._row_states_payload``) --
            ``last_seen``/``last_pulled`` are ``(mtime, size)`` tuples there
            but must already be plain lists (or ``None``) here, since JSON
            has no tuple type. Only entries whose path is also in ``paths``
            are written -- a stale row for an already-removed path is
            silently dropped rather than resurrected on the next load.
        auto_enabled: whether Watchlist's auto-mode was on at save time.
        patterns: watched wildcard patterns (the Files lens pins them and
            auto-mode re-expands them); see :func:`load_patterns`.
    """
    rows_payload: dict[str, dict] = {}
    for path in paths:
        info = (row_states or {}).get(path)
        if not info:
            continue
        rows_payload[path] = {
            "state": info.get("state", "never_pulled"),
            "detail": info.get("detail", ""),
            "last_seen": info.get("last_seen"),
            "last_pulled": info.get("last_pulled"),
        }
        if info.get("pull"):
            # Last successful pull: {"at", "size", "sha256"} (optional key).
            rows_payload[path]["pull"] = info["pull"]
    data = {
        "schema_version": SCHEMA_VERSION,
        "paths": list(paths),
        "auto_enabled": bool(auto_enabled),
        "rows": rows_payload,
    }
    kept_patterns = [p for p in (patterns or []) if isinstance(p, str)]
    if kept_patterns:
        data["patterns"] = kept_patterns  # optional key, see load_patterns()
    _atomic_write_json(_index_path(), data)


def load_membership() -> list[str]:
    """Load the persisted watched-path list.

    A missing or corrupt ``index.json`` is treated the same way
    ``run_history.py`` treats a corrupt run file: log a warning and fall
    back to an empty list rather than raising -- a fresh/empty watchlist is
    a safe default, and callers (``ForensicService.load_watchlist_index``)
    merge this into whatever is already tracked rather than replacing it
    outright.
    """
    paths = _load_index_data().get("paths")
    if not isinstance(paths, list):
        return []
    return [p for p in paths if isinstance(p, str)]


def load_row_states() -> dict[str, dict]:
    """Load each watched path's persisted per-row state.

    Returns ``{path: {"state", "detail", "last_seen", "last_pulled"}}`` --
    ``last_seen``/``last_pulled`` are plain 2-element lists (or ``None``)
    exactly as written by :func:`save_membership`; callers wanting the
    in-memory tuple shape convert them back (see ``WatchlistView.
    _restore_persisted_rows``).

    A missing/corrupt index, or a v1 file predating this field entirely,
    both yield ``{}`` -- exactly as safe a default as :func:`load_membership`
    returning ``[]``, since a caller merging this in just restores nothing.
    """
    rows = _load_index_data().get("rows")
    if not isinstance(rows, dict):
        return {}
    return {
        path: payload
        for path, payload in rows.items()
        if isinstance(path, str) and isinstance(payload, dict)
    }


def load_patterns() -> list[str]:
    """The watched wildcard patterns (``[]`` for a missing/older index)."""
    patterns = _load_index_data().get("patterns")
    if not isinstance(patterns, list):
        return []
    return [p for p in patterns if isinstance(p, str)]


def load_auto_enabled() -> bool:
    """Whether Watchlist's auto-mode was on the last time the index was saved.

    ``False`` (auto-mode's own default) for a missing/corrupt index or a v1
    file predating this field.
    """
    return bool(_load_index_data().get("auto_enabled", False))


__all__ = [
    "DEFAULT_MAX_VERSIONS",
    "SCHEMA_VERSION",
    "WATCHLIST_DIR_ENV",
    "device_key",
    "has_baseline",
    "load_auto_enabled",
    "load_membership",
    "load_patterns",
    "load_row_states",
    "previous_dir",
    "promote",
    "prune",
    "reset_current",
    "row_dir",
    "sanitize_path",
    "save_membership",
    "version_diff",
    "version_dirs",
    "version_file",
    "version_record",
    "version_time",
    "watchlist_dir",
]
