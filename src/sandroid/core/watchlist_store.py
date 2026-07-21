"""Watchlist sub-tab's on-disk state: membership persistence + the local
pull baseline cache.

Two related but distinct things live under one directory,
``RESULTS_PATH/spotlight_files/.watchlist/``, because the Watchlist sub-tab
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

2. **Per-path baseline cache** (``<sanitized-path>/{previous,current}``):
   each watched path gets its own ``previous``/``current`` pull directory so
   a fresh manual pull can be diffed against whatever was pulled last time.
   ``previous`` holds the last-promoted baseline; ``current`` holds the most
   recent pull. Callers (``WatchlistView``) are expected to: clear+recreate
   ``current`` via :func:`reset_current`, pull the fresh copy into it, diff
   against :func:`previous_dir` if :func:`has_baseline` is True, then call
   :func:`promote` to make the fresh pull the new baseline for next time.

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


def watchlist_dir() -> Path:
    """The shared root for both membership (``index.json``) and baselines."""
    directory = _results_path() / "spotlight_files" / ".watchlist"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _index_path() -> Path:
    return watchlist_dir() / "index.json"


def row_dir(path: str) -> Path:
    """The per-watched-path baseline-cache directory."""
    directory = watchlist_dir() / sanitize_path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def previous_dir(path: str) -> Path:
    """The last-promoted baseline pull for *path* (may not exist yet)."""
    return row_dir(path) / "previous"


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
    directory = previous_dir(path)
    return directory.exists() and any(directory.iterdir())


def promote(path: str) -> None:
    """Make the freshly-pulled ``current`` the new ``previous`` baseline.

    Call after diffing (or after the very first pull, which has nothing to
    diff against yet but still needs to seed a baseline for next time).
    """
    current = row_dir(path) / "current"
    previous = previous_dir(path)
    if previous.exists():
        shutil.rmtree(previous)
    shutil.copytree(current, previous)


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
    _atomic_write_json(
        _index_path(),
        {
            "schema_version": SCHEMA_VERSION,
            "paths": list(paths),
            "auto_enabled": bool(auto_enabled),
            "rows": rows_payload,
        },
    )


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


def load_auto_enabled() -> bool:
    """Whether Watchlist's auto-mode was on the last time the index was saved.

    ``False`` (auto-mode's own default) for a missing/corrupt index or a v1
    file predating this field.
    """
    return bool(_load_index_data().get("auto_enabled", False))


__all__ = [
    "SCHEMA_VERSION",
    "has_baseline",
    "load_auto_enabled",
    "load_membership",
    "load_row_states",
    "previous_dir",
    "promote",
    "reset_current",
    "row_dir",
    "sanitize_path",
    "save_membership",
    "watchlist_dir",
]
