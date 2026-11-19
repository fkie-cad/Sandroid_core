"""The Spotlight-Files watchlist behind the Files lens (non-visual).

``WatchlistView`` is a hidden child widget of the Files lens
(:class:`~sandroid.tui.widgets.files_panel.FilesPanel`): it owns the
``ForensicService`` spotlight-file watchlist -- add/remove (paths and
wildcard patterns), pull one/all, membership persistence -- and every pull
diffs the fresh copy against the previous version (``core/file_diff.py``, the
same engine behind :class:`~sandroid.tui.widgets.diff_view.DiffView`). It
draws nothing: whenever its rows change it posts :class:`WatchlistView.Changed`
and the lens re-renders its table (watched files carry ★ and are pinned on
top) and the Inspector. It is a widget only so it can own timers and thread
workers.

**Storage** (``core/watchlist_store.py``): the ★ membership persists per
package in the user config directory; every pull is a new version folder in
the *session results folder* (``files/<package>/<app path>/vNNN_HH-MM-SS/``)
with the copy, ``diff.json`` (structured, canonical) + ``diff.txt`` (plain
text rendered from it) and ``acquisition.json`` (device path; per member --
the file and its ``-wal``/``-journal`` -- the device mtime + size, the sha256
computed on the device before the pull and the local sha256 after it; the
combined set hash; pull time, trigger and the active mark). Nothing is
pruned. A pull whose on-device hashes equal the newest version's keeps no
copy: it is one line in ``checks.jsonl`` (shown as "checked, no change").

**Baseline**: ``w``/``n`` pull a first version of every newly watched file
right away (``trigger: "watch"``), so the first change can be diffed. Watches
persist across sessions but versions do not: when the file monitor starts,
every watched file of the monitored app is pulled once per session
(``trigger: "session-start"``, at most ``SESSION_BASELINE_CAP``). Every
acquisition record and check carries the ``device_clock`` sample of its pull
(``core/device_clock.py``).

**Auto-pull on change** (``tui.auto_pull_on_change``, default on): there is
ONE change detector, the file monitor. The lens hands every write it sees
(create / modify / rename-into, ``FileActivity.writes``) to
:meth:`WatchlistView.note_write`; for a ★ file this (re)arms a per-file
timer, and once writes have been quiet for ``AUTO_PULL_QUIET`` seconds the
file is pulled, versioned and diffed (``trigger: "auto"``). A database and
its ``-wal``/``-journal`` are one group: the monitor folds companion writes
onto the database row, and a pull always takes the companions along. A write
to a file that only a ★ *pattern* covers adds that file to the watchlist
first. There is no polling: with the monitor off nothing is tracked, and the
lens says so. ``u``/``U`` pull by hand (``trigger: "manual"``).

**Naming note** (also in ``spotlight_controller.py``): "Spotlight" is
overloaded in this codebase. This module is about the *forensic* Spotlight
Files watchlist (``ForensicService._spotlight_files``) -- it is unrelated to
the *Frida* spotlight app-under-test (``spotlight_panel.py``/
``SpotlightService``, keys ``c``/``Shift+C``).
"""

from __future__ import annotations

import fnmatch
import functools
import hashlib
import logging
import os
import shlex
import threading
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

from textual.message import Message
from textual.widget import Widget

from sandroid.core import file_diff, watchlist_store
from sandroid.core.adb_utils import (
    canonical_device_path,
    device_shell_command,
    watch_path_problem,
)
from sandroid.services import get_file_extraction_service, get_forensic_service
from sandroid.services.file_extraction_service import is_sqlite_file

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

#: Seconds without a new write before a ★ file is auto-pulled.
AUTO_PULL_QUIET = 1.5
#: At most this many watched files get a ``session-start`` pull.
SESSION_BASELINE_CAP = 50


class RowState(Enum):
    """Per-row pull/diff state (in memory, this session only)."""

    NEVER_PULLED = "never_pulled"  #: ○ gray -- never pulled at all
    BASELINE_ONLY = "baseline_only"  #: ✓ gray -- one pull, nothing to diff against yet
    UNCHANGED = "unchanged"  #: ✓ gray -- diffed against baseline, no changes
    CHANGED = "changed"  #: ◆ yellow -- diffed against baseline, real changes
    ERROR = "error"  #: ✕ red -- last pull failed
    #: ◇ dim-yellow -- the monitor saw a write; the auto-pull waits for the
    #: writes to go quiet (``AUTO_PULL_QUIET``).
    SETTLING = "settling"


@dataclass
class _RowInfo:
    """In-memory state for one watched path."""

    path: str
    state: RowState = RowState.NEVER_PULLED
    detail: str = ""  # short status line shown in the Inspector
    diff_text: str | None = None  # last computed diff, if state is CHANGED
    # -- last successful pull (shown in the Inspector) ---------------------
    pulled_at: str | None = None  #: ISO timestamp
    size: int | None = None  #: bytes of the file + its -wal/-journal
    #: combined sha256 of the local copy's set (file + -wal/-journal; see
    #: ``watchlist_store.set_sha256``)
    sha256: str | None = None
    version: str | None = None  #: name of the version folder
    checked_at: str | None = None  #: last "checked, no change" (ISO)
    #: ``device_clock`` sample of the last pull / check (``off_wall`` etc.)
    device_clock: dict | None = None


#: SQLite files that belong to a database: pulled with it (a WAL-mode write
#: only touches ``-wal`` until a checkpoint). ``-shm`` is left out on
#: purpose: it changes on every read.
SQLITE_COMPANIONS = watchlist_store.SQLITE_COMPANIONS


def device_set_of(
    path: str, basename: str, device: dict[str, dict]
) -> dict[str, str] | None:
    """``{file name: sha256}`` of the file and the companions present on the
    device, from ``_device_facts``; ``None`` when a hash is missing (no
    comparison with the newest version is possible then).
    """
    out: dict[str, str] = {}
    for suffix in ("", *SQLITE_COMPANIONS):
        entry = device.get(path + suffix)
        if entry is None:
            if not suffix:
                return None  # the file itself must be there
            continue
        sha = entry.get("sha256")
        if not sha:
            return None
        out[basename + suffix] = sha
    return out


def _set_summary(
    path: str,
    basename: str,
    device: dict[str, dict],
    main_local: dict,
    companions: list[dict],
) -> dict:
    """The ``set`` block of an acquisition record (file + -wal/-journal)."""
    local = {
        e["file"]: e["sha256"]
        for e in [main_local, *(c["local"] for c in companions)]
        if e.get("sha256")
    }
    device_members = device_set_of(path, basename, device)
    mismatched = sorted(
        name
        for name, sha in local.items()
        if device_members and device_members.get(name) not in (None, sha)
    )
    missing = sorted(set(device_members or {}) - set(local))
    newest_member, newest = None, None
    for suffix in ("", *SQLITE_COMPANIONS):
        mtime = (device.get(path + suffix) or {}).get("mtime")
        if isinstance(mtime, int) and (newest is None or mtime > newest):
            newest_member, newest = basename + suffix, mtime
    sizes = [main_local.get("size"), *(c["local"].get("size") for c in companions)]
    return {
        "hash": "sha256 over the sorted '<file name> <sha256>' lines of the members",
        "members": sorted(local),
        "device": device_members or {},
        "local": local,
        "device_sha256": (
            watchlist_store.set_sha256(device_members) if device_members else None
        ),
        "local_sha256": watchlist_store.set_sha256(local) if local else None,
        "match": None if not device_members else not (mismatched or missing),
        "mismatched": mismatched,
        "missing_locally": missing,
        "size": sum(s for s in sizes if isinstance(s, int)),
        "newest_member": newest_member,
        "newest_mtime": newest,
        "newest_mtime_iso": watchlist_store.iso_tz(newest) if newest else None,
    }


def _timeline_rel(target: Path) -> str:
    """``target`` relative to the session timeline's folder."""
    from sandroid.core.timeline import timeline_folder

    try:
        return os.path.relpath(target, timeline_folder())
    except ValueError:  # another drive (Windows)
        return str(target)


def _pull_serial() -> str | None:
    """The device a pull on this thread talks to (the adb target, pinned
    per thread by ``Adb.targeting``): the ``dev`` of its timeline line.
    """
    try:
        from sandroid.core.adb import Adb

        return Adb.get_target_device()
    except Exception:
        return None


def _says_missing(error: str) -> bool:
    """An adb pull error that means the file is not there."""
    text = (error or "").lower()
    # "File not found on device" is detect_adb_pull_error's word for adb's
    # "failed to stat remote object"; "device 'x' not found" is not a file.
    return any(w in text for w in ("no such file", "does not exist", "file not found"))


def timeline_pull(
    path: str,
    trigger: str,
    *,
    ok: bool,
    version: Path | None = None,
    file_set: dict | None = None,
    changed: bool | None = None,
    error: str | None = None,
) -> int | None:
    """A ``files/pull`` session-timeline line (never raises).

    ``ref`` points to the version's ``diff.json`` (``acquisition.json`` for
    the first version) with its sha256; the diff itself is never copied.
    """
    try:
        from sandroid.core.timeline import get_timeline

        _owner, rel = watchlist_store.owner_and_relative(path)
        basename = os.path.basename(path.rstrip("/")) or "pulled_file"
        file_set = file_set or {}
        data: dict = {
            "path": path,
            "version": version.name if version is not None else None,
            "size": file_set.get("size"),
            "sha256": (file_set.get("local") or {}).get(basename),
            "set_sha256": file_set.get("local_sha256"),
            "changed": changed,
            "trigger": trigger,
            "ok": ok,
        }
        ref = None
        if version is not None:
            doc = version / "diff.json"
            if not doc.is_file():
                doc = version / "acquisition.json"
            ref = {"path": _timeline_rel(doc), "lens": "files"}
            sha = watchlist_store.sha256_file(doc) if doc.is_file() else None
            if sha:
                ref["sha256"] = sha
        if ok and version is not None:
            short = version.name.split("_", 1)[0]
            if changed is None:
                state = "first version"
            else:
                state = "changed" if changed else "no content change"
            summary = f"◆ {short} {rel} ({state})"
        else:
            data["error"] = (error or "pull failed")[:500]
            summary = f"pull failed · {rel}"
        return get_timeline().emit(
            "files",
            "pull",
            summary=summary,
            actor="user" if trigger == "manual" else "sandroid",
            data=data,
            ref=ref,
            pkg=watchlist_store.package_of(path),
            level="info" if ok else "warn",
            dev=_pull_serial(),
        )
    except Exception:
        logger.debug("timeline: files/pull line failed", exc_info=True)
        return None


def timeline_check(path: str, trigger: str, same_as: str, note: str) -> int | None:
    """A ``files/check`` session-timeline line: a pull found no change."""
    try:
        from sandroid.core.timeline import get_timeline

        _owner, rel = watchlist_store.owner_and_relative(path)
        checks = watchlist_store.row_dir(path) / "checks.jsonl"
        return get_timeline().emit(
            "files",
            "check",
            summary=f"◇ {rel} unchanged (same as {same_as})",
            actor="user" if trigger == "manual" else "sandroid",
            data={"path": path, "same_as": same_as, "trigger": trigger, "note": note},
            ref={"path": _timeline_rel(checks), "lens": "files"},
            pkg=watchlist_store.package_of(path),
            dev=_pull_serial(),
        )
    except Exception:
        logger.debug("timeline: files/check line failed", exc_info=True)
        return None


def _file_facts(path: Path) -> tuple[int | None, str | None]:
    """``(size, sha256)`` of a pulled file, ``(None, None)`` if unreadable."""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 16), b""):
                digest.update(chunk)
        return path.stat().st_size, digest.hexdigest()
    except OSError:
        return None, None


def _compute_diff(previous_main: Path, current_main: Path) -> tuple[str, bool]:
    """Diff *current_main* against *previous_main*.

    Thin delegator to :func:`sandroid.core.file_diff.diff_files` with
    ``file_extraction_service.is_sqlite_file`` (an uncached magic-header
    read; ``file_diff``'s own cache is keyed by path and must not be used for
    a staging folder that is reused). Returns ``(diff_text, changed)``.
    """
    return file_diff.diff_files(previous_main, current_main, is_sqlite_file)


def parse_device_facts(stdout: str) -> dict[str, dict]:
    """Parse ``stat -c '%Y %s %n'`` + ``sha256sum`` output per path.

    Returns ``{path: {"mtime": int, "size": int, "sha256": str}}`` with the
    keys that were found (a missing companion simply has no entry).
    """
    facts: dict[str, dict] = {}
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        head, _sep, rest = line.partition(" ")
        if len(head) == 64 and all(c in "0123456789abcdef" for c in head.lower()):
            name = rest.lstrip(" *")
            if name:
                facts.setdefault(name, {})["sha256"] = head.lower()
            continue
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            entry = facts.setdefault(parts[2], {})
            entry["mtime"] = int(parts[0])
            entry["size"] = int(parts[1])
    return facts


class WatchlistView(Widget):
    """Non-visual watchlist engine of the Files lens (see module docstring).

    Public API used by the lens: ``rows``/``patterns``/``watched_by``
    (state), ``add_path``/``remove_path``/``unwatch``/``pull``/``pull_all``/
    ``note_write`` (mutations), ``summary`` (text). Every state change posts
    :class:`WatchlistView.Changed`.
    """

    can_focus = False

    DEFAULT_CSS = """
    WatchlistView {
        display: none;
    }
    """

    class Changed(Message):
        """The watchlist rows changed (bubbles to the Files lens)."""

        def __init__(self, paths: frozenset[str] | None = None) -> None:
            super().__init__()
            #: The paths whose row changed, or None for "anything".
            self.paths = paths

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        #: path -> _RowInfo, keyed the same way ForensicService keys them.
        self._rows: dict[str, _RowInfo] = {}
        #: Patterns (containing "*") the user added; ForensicService only
        #: keeps the expanded literal matches.
        self._watched_patterns: set[str] = set()
        #: path -> (timer, first write time) of a pending auto-pull.
        self._auto_timers: dict[str, tuple[object, datetime]] = {}
        #: Paths with a pull in flight (a write meanwhile re-arms the timer).
        self._pulling: set[str] = set()
        #: Paths that got their ``session-start`` pull in this session.
        self._session_baselined: set[str] = set()
        #: The monitored app (from the monitor start): its privacy auto-watch.
        self._monitored_package: str | None = None
        #: The session's marks (``lens_shell.Mark``), kept current by the
        #: Files lens: each kept version records the mark it was pulled in.
        self.marks: list = []

    def compose(self):
        return ()

    def on_mount(self) -> None:
        try:
            get_forensic_service().load_watchlist_index()
        except Exception:
            logger.debug(
                "Watchlist: failed to load persisted membership", exc_info=True
            )
        try:
            self._watched_patterns = set(watchlist_store.load_patterns())
        except Exception:
            logger.debug("Watchlist: failed to load patterns", exc_info=True)
        self._reload_rows()

    def on_unmount(self) -> None:
        for timer, _when in self._auto_timers.values():
            self._stop_timer(timer)
        self._auto_timers.clear()

    # -- public state ---------------------------------------------------------

    @property
    def rows(self) -> dict[str, _RowInfo]:
        """Row state per watched path (do not mutate)."""
        return self._rows

    @property
    def patterns(self) -> list[str]:
        return sorted(self._watched_patterns)

    @property
    def has_watches(self) -> bool:
        return bool(self._rows or self._watched_patterns)

    @property
    def privacy_watching(self) -> bool:
        """An identity profile auto-watches the monitored app's data folders
        (session only, never persisted; see ``services/privacy_scan.py``).
        """
        return bool(self._privacy_patterns())

    def _privacy_patterns(self) -> list[str]:
        try:
            from sandroid.services.privacy_scan import get_privacy_scan_service

            service = get_privacy_scan_service()
            return service.auto_watch_patterns(self._monitored_package)
        except Exception:
            return []

    def _privacy_covers(self, path: str) -> bool:
        try:
            from sandroid.services.privacy_scan import get_privacy_scan_service

            service = get_privacy_scan_service()
            return service.auto_watch_covers(path, self._monitored_package)
        except Exception:
            return False

    def watched_by(self, path: str) -> str | None:
        """The literal path or pattern that watches ``path``, else None."""
        if path in self._rows:
            return path
        path = canonical_device_path(path)
        if path in self._rows:
            return path
        for pattern in sorted(self._watched_patterns):
            if self._pattern_matches(pattern, path):
                return pattern
        return None

    def is_watched(self, path: str) -> bool:
        return self.watched_by(path) is not None

    def summary(self) -> str:
        """``"3 watched · 1 changed"`` (empty when nothing is watched)."""
        total = len(self._rows) + len(self._watched_patterns)
        if total == 0:
            return ""
        text = f"{total} watched"
        # "changed" is an adjective here -- it never takes an "s".
        changed = sum(1 for r in self._rows.values() if r.state is RowState.CHANGED)
        if changed:
            text += f" · {changed} changed"
        return text

    def reload(self) -> None:
        """Resync with ForensicService (paths may be watched elsewhere)."""
        self._reload_rows()

    # -- services (lazy) ------------------------------------------------------

    @staticmethod
    def _adb():
        from sandroid.core.adb import Adb

        return Adb

    @staticmethod
    def _auto_pull_enabled() -> bool:
        """``tui.auto_pull_on_change`` of the live config (default on)."""
        try:
            from sandroid.config import get_config

            return bool(get_config().tui.auto_pull_on_change)
        except Exception:
            return True

    # -- row bookkeeping ------------------------------------------------------

    def _persist_index(self) -> None:
        """Persist the ★ membership (paths + patterns), per package."""
        get_forensic_service().save_watchlist_index(
            patterns=sorted(self._watched_patterns)
        )

    def _reload_rows(self) -> None:
        """Resync ``self._rows`` from ForensicService without losing state."""
        paths = get_forensic_service().get_spotlight_files()
        for path in paths:
            if path in self._rows:
                continue
            info = _RowInfo(path=path)
            versions = watchlist_store.version_dirs(path)
            if versions:
                # Pulled earlier in this session (the versions live in the
                # session results folder).
                info.state = RowState.BASELINE_ONLY
                info.detail = f"{len(versions)} version(s) in this session."
                info.version = versions[-1].name
            self._rows[path] = info
        for path in list(self._rows):
            if path not in paths:
                del self._rows[path]
        self._changed()

    def _changed(self, paths=None) -> None:
        """Tell the lens the rows changed (``paths``: which ones, or all)."""
        try:
            self.post_message(
                self.Changed(frozenset(paths) if paths is not None else None)
            )
        except Exception:
            pass

    # -- add / remove -----------------------------------------------------

    @staticmethod
    def _pattern_matches(pattern: str, path: str) -> bool:
        if pattern.endswith("/*") and path.startswith(pattern[:-1]):
            return True  # "dir/*" expands recursively (find -type f)
        return fnmatch.fnmatchcase(path, pattern)

    def add_path(self, path: str, *, pull_first: bool = True) -> bool:
        """Watch a path or wildcard pattern; False (with a toast) if rejected.

        ``pull_first=False``: no first-version pull (Rewind pulls the file
        itself, tagged as its After).
        """
        forensic = get_forensic_service()
        problem = watch_path_problem(path)
        if problem is not None:
            self._notify(problem, "warning")
            return False
        # One key per file: /data/user/0/<pkg>/x is /data/data/<pkg>/x.
        path = canonical_device_path(path)
        if "*" in path and path in self._watched_patterns:
            self._notify(f"Already watching: {path}", "warning")
            return False
        before = set(self._rows)
        # add_spotlight_file() expands a wildcard through a device listing.
        added = forensic.add_spotlight_file(path, adb=self._adb())
        if "*" in path:
            # Remember (and persist) the pattern even when it matches nothing
            # yet: the lens pins it, and monitor writes add new matches.
            self._watched_patterns.add(path)
        elif not added:
            self._notify(f"Already watching or invalid: {path}", "warning")
            return False
        self._persist_index()
        self._reload_rows()
        baseline = (
            self._pull_baselines(sorted(set(self._rows) - before)) if pull_first else 0
        )
        tail = ""
        if baseline == 1:
            tail = " — pulling a first version"
        elif baseline:
            tail = f" — pulling first versions of {baseline} files"
        self._notify(f"Watching {path}{tail}")
        return True

    def _pull_baselines(self, paths: list[str]) -> int:
        """Pull a first version (v001) of newly watched files right away, so
        the first change after watching can be diffed. Files that already
        have versions in this session are left alone. Returns how many.
        """
        todo = [p for p in paths if not watchlist_store.has_baseline(p)]
        if todo:
            self._start_pull(todo, trigger="watch")
        return len(todo)

    def pull_session_baselines(self, package: str | None = None) -> int:
        """Pull every watched file once per session (``trigger:
        "session-start"``), so the first change after a restart has a
        version to diff against (watches persist across sessions, pulled
        versions do not).

        Called when the file monitor starts. ``package``: only that app's
        files (the monitored app); ``None``: all. Files already pulled for
        this reason, or with a pull in flight, are skipped; a file whose
        on-device hashes equal its newest version this session only gets a
        ``checks.jsonl`` line (the usual no-change path). At most
        :data:`SESSION_BASELINE_CAP` files; the rest are named in a log
        warning. Runs on the pull worker. Returns how many were started.
        """
        self._monitored_package = package
        todo = [
            p
            for p in sorted(self._rows)
            if p not in self._session_baselined
            and p not in self._pulling
            and (package is None or watchlist_store.package_of(p) == package)
        ]
        if len(todo) > SESSION_BASELINE_CAP:
            rest = todo[SESSION_BASELINE_CAP:]
            todo = todo[:SESSION_BASELINE_CAP]
            logger.warning(
                f"Watchlist: session-start baseline limited to "
                f"{SESSION_BASELINE_CAP} files; not pulled: {', '.join(rest)}"
            )
        if todo:
            self._session_baselined.update(todo)
            logger.info(f"Watchlist: pulling session baselines of {len(todo)} files")
            self._start_pull(todo, trigger="session-start")
        return len(todo)

    def remove_path(self, path: str) -> bool:
        """Unwatch a literal path (its pulled versions stay on disk)."""
        forensic = get_forensic_service()
        if not forensic.remove_spotlight_file(path):
            return False
        self._persist_index()
        self._rows.pop(path, None)
        self._cancel_auto(path)
        self._reload_rows()
        return True

    def unwatch(self, path: str) -> bool:
        """Unwatch a literal path, or a pattern together with its matches."""
        if path in self._watched_patterns:
            self._watched_patterns.discard(path)
            for match in [p for p in self._rows if self._pattern_matches(path, p)]:
                if not self._from_watched_pattern(match):
                    get_forensic_service().remove_spotlight_file(match)
                    self._rows.pop(match, None)
                    self._cancel_auto(match)
            self._persist_index()
            self._reload_rows()
            self._notify(f"Stopped watching {path}")
            return True
        if self.remove_path(path):
            self._notify(f"Stopped watching {path}")
            return True
        return False

    def _from_watched_pattern(self, path: str) -> bool:
        """Whether ``path`` is covered by one of the watched wildcard patterns."""
        return any(self._pattern_matches(p, path) for p in self._watched_patterns)

    # -- auto-pull on change (driven by the file monitor) -------------------

    def note_write(self, path: str, when: datetime | None = None) -> bool:
        """The monitor saw a write to ``path``: arm its debounced auto-pull.

        Only ★ files count (a file a ★ pattern covers is added first); a
        database's ``-wal``/``-journal`` count for the database. Every write
        re-arms the per-file timer, so the pull happens once the writes have
        been quiet for ``AUTO_PULL_QUIET`` seconds. Returns True if a pull
        is now pending.
        """
        if not self._auto_pull_enabled():
            return False
        from .monitor_view import split_companion

        path = split_companion(canonical_device_path(path))[0]
        when = when or datetime.now()
        if path not in self._rows:
            pattern = self.watched_by(path)
            if pattern is None and self._privacy_covers(path):
                # Privacy auto-watch: pulled like a ★ file, but no row and
                # nothing persisted.
                timer, first = self._auto_timers.pop(path, (None, when))
                self._stop_timer(timer)
                self._auto_timers[path] = (self._start_timer(path), first)
                return True
            if pattern is None or pattern == path:
                return False
            if not get_forensic_service().add_spotlight_file(path):
                return False
            self._persist_index()
            self._reload_rows()
            if path not in self._rows:
                return False
        timer, first = self._auto_timers.pop(path, (None, when))
        self._stop_timer(timer)
        new_timer = self._start_timer(path)
        self._auto_timers[path] = (new_timer, first)
        info = self._rows[path]
        if info.state is not RowState.SETTLING:
            info.state = RowState.SETTLING
            info.detail = f"Write seen {when:%H:%M:%S} — pulling when it settles…"
            self._changed([path])
        return True

    @property
    def pending_auto(self) -> list[str]:
        """Paths with an armed auto-pull (tests, caption)."""
        return sorted(self._auto_timers)

    def _start_timer(self, path: str, delay: float = AUTO_PULL_QUIET):
        try:
            return self.set_timer(delay, functools.partial(self.fire_auto_pull, path))
        except Exception:
            return None  # not mounted (unit tests drive fire_auto_pull)

    @staticmethod
    def _stop_timer(timer) -> None:
        if timer is not None:
            try:
                timer.stop()
            except Exception:
                pass

    def _cancel_auto(self, path: str) -> None:
        timer, _when = self._auto_timers.pop(path, (None, None))
        self._stop_timer(timer)

    def fire_auto_pull(self, path: str) -> None:
        """The writes to ``path`` went quiet: pull it (``trigger: auto``)."""
        entry = self._auto_timers.pop(path, None)
        privacy = path not in self._rows and self._privacy_covers(path)
        if entry is None or (path not in self._rows and not privacy):
            return
        _timer, first = entry
        if path in self._pulling:
            # A pull is still running: try again after another quiet period.
            self._auto_timers[path] = (self._start_timer(path), first)
            return
        if privacy:
            from sandroid.services.privacy_scan import get_privacy_scan_service

            wait = get_privacy_scan_service().auto_watch_delay(path)
            if wait > 0:  # at most one pull per AUTO_WATCH_MIN_INTERVAL_S
                self._auto_timers[path] = (self._start_timer(path, wait), first)
                return
        self._start_pull(
            [path], trigger="privacy" if privacy else "auto", event_time=first
        )

    # -- pull / diff --------------------------------------------------------

    def is_pulling(self, path: str) -> bool:
        """A pull of ``path`` was started and has not reported back yet."""
        return path in self._pulling

    def pull(self, paths: list[str]) -> None:
        """Pull (and diff) these watched paths on a worker thread."""
        paths = [p for p in paths if p in self._rows]
        if not paths:
            self._notify("Nothing watched to pull.", "warning")
            return
        self._start_pull(paths)

    def pull_all(self) -> None:
        paths = sorted(self._rows)
        if not paths:
            self._notify("No watched files to pull.", "warning")
            return
        self._start_pull(paths)

    def _start_pull(
        self,
        paths: list[str],
        trigger: str = "manual",
        event_time: datetime | None = None,
    ) -> None:
        for path in paths:
            self._cancel_auto(path)
            self._pulling.add(path)
        self._run_bg(
            functools.partial(self._pull_worker, list(paths), trigger, event_time),
            "watchlist_pull",
        )

    def _pull_worker(
        self,
        paths: list[str],
        trigger: str = "manual",
        event_time: datetime | None = None,
    ) -> None:
        for path in paths:
            try:
                # One pull of a file at a time (see watchlist_store.pull_lock).
                with watchlist_store.pull_lock(path):
                    self._pull_and_diff_one(path, trigger, event_time)
            except Exception as exc:
                logger.warning(f"Watchlist pull failed for {path}: {exc}")
                timeline_pull(path, trigger, ok=False, error=str(exc))
                self._post(
                    self._apply_pull_result, path, RowState.ERROR, str(exc), None
                )

    @staticmethod
    def _device_facts(paths: list[str]) -> dict[str, dict]:
        """mtime, size and sha256 of ``paths`` ON THE DEVICE (one adb call).

        Runs ``stat`` + ``sha256sum`` in one device shell (as root: adbd runs
        as root on the analysis AVDs, the same requirement as pulling
        ``/data/data``). Every path is quoted for the device shell and the
        whole command once more for the host shell. A missing companion just
        has no entry; any failure returns ``{}`` (the record says so).
        """
        quoted = " ".join(shlex.quote(p) for p in paths)
        script = (
            f"stat -c '%Y %s %n' {quoted} 2>/dev/null; sha256sum {quoted} 2>/dev/null"
        )
        try:
            from sandroid.core.adb_utils import quiet_adb_warnings

            with quiet_adb_warnings():
                stdout, _stderr = WatchlistView._adb().send_adb_command(
                    device_shell_command(script)
                )
        except Exception:
            logger.debug("Watchlist: device stat/sha256sum failed", exc_info=True)
            return {}
        return parse_device_facts(stdout if isinstance(stdout, str) else "")

    @staticmethod
    def _device_clock() -> dict | None:
        """The device clock sample recorded with a pull (``device_clock``:
        ``off_wall``, ``off_mono``, ``rtt_ms``, ...; a sample younger than
        10 s is reused, see :func:`sandroid.core.device_clock.current`).
        """
        try:
            from sandroid.core import device_clock

            return device_clock.current()
        except Exception:
            logger.debug("Watchlist: device clock sample failed", exc_info=True)
            return None

    def pull_role(self, path: str, role: str, rec_id: str, run: int) -> tuple:
        """Pull ``path`` for a recording's ``role`` (Before / After / After
        (replay)); blocking, for a worker thread. Returns ``(version, error)``:
        the version folder name that holds the content (a new one, or the
        newest one when nothing changed), ``"absent"`` when the file is not
        on the device, ``None`` with the error otherwise.
        """
        self._post(self._pulling.add, path)
        tag = {"role": role, "rec_id": rec_id, "run": run}
        try:
            with watchlist_store.pull_lock(path):
                outcome = self._pull_and_diff_one(path, f"rewind-{role}", None, tag)
        except Exception as exc:
            logger.warning(f"Watchlist pull failed for {path}: {exc}")
            timeline_pull(path, f"rewind-{role}", ok=False, error=str(exc))
            self._post(self._apply_pull_result, path, RowState.ERROR, str(exc), None)
            return None, str(exc)
        return outcome

    def _pull_and_diff_one(
        self,
        path: str,
        trigger: str = "manual",
        event_time: datetime | None = None,
        rewind: dict | None = None,
    ) -> tuple[str | None, str | None]:
        """Runs on a background thread (see ``_run_bg``).

        Device facts (stat + sha256sum of the file and its ``-wal`` /
        ``-journal``) first. When they equal the newest version's, nothing is
        pulled: one line goes to ``checks.jsonl`` (version numbers count only
        real changes). Otherwise the pull (+ SQLite companions) into the
        staging folder, and -- unless the copy is byte-identical to the newest
        version -- the new version folder with ``acquisition.json``,
        ``diff.json`` and ``diff.txt`` (:func:`watchlist_store.keep_version`).
        Never touches widgets; reports via ``_post``. ``rewind`` (role,
        rec_id, run) tags the version / check for a recording. Returns
        ``(version name, error)`` as :meth:`pull_role`.
        """
        fx = get_file_extraction_service()
        basename = os.path.basename(path.rstrip("/")) or "pulled_file"
        companions = [f"{path}{s}" for s in SQLITE_COMPANIONS]
        device = self._device_facts([path, *companions])
        clock = self._device_clock()
        mark = self._active_mark(event_time or datetime.now())
        dirs = watchlist_store.version_dirs(path)
        latest = dirs[-1] if dirs else None
        device_set = device_set_of(path, basename, device)
        if latest is not None and device_set is not None:
            known = watchlist_store.record_set(
                watchlist_store.version_record(latest), "device"
            )
            if known == device_set:
                self._record_check(
                    path, latest, trigger, event_time, device_set, mark,
                    "no change", clock, rewind,
                )  # fmt: skip
                return latest.name, None

        current = watchlist_store.reset_current(path)
        current_main = current / basename
        result = fx.pull_file(path, str(current_main))
        if not result.success:
            error = result.error or "Pull failed"
            if rewind is not None and (
                _says_missing(error) or (device and path not in device)
            ):
                # Not on the device (a new file at the start point, a
                # deleted one after): a fact of the role, not an error.
                # Empty facts alone prove nothing: they are also what a
                # failed stat (device gone, adb hiccup) returns.
                watchlist_store.discard_current(path)
                timeline_pull(path, trigger, ok=True, error="not on the device")
                self._post(self._pulling.discard, path)
                return "absent", None
            timeline_pull(path, trigger, ok=False, error=result.error)
            self._post(
                self._apply_pull_result,
                path,
                RowState.ERROR,
                error,
                None,
            )
            return None, error

        pulled_companions: list[str] = []
        if is_sqlite_file(str(current_main)) or any(c in device for c in companions):
            from sandroid.core.adb_utils import quiet_adb_warnings

            # Not a warning when one is missing (WAL mode has no -journal).
            with quiet_adb_warnings():
                for companion in companions:
                    local = f"{current_main}{companion[len(path) :]}"
                    if fx.pull_file(companion, local).success:
                        pulled_companions.append(companion)

        pulled_at = datetime.now()
        record = self._acquisition_record(
            path, current, basename, device, pulled_companions, pulled_at,
            trigger, event_time, mark, clock,
        )  # fmt: skip
        if rewind is not None:
            record["rewind"] = rewind
        file_set = record["set"]
        facts = (file_set["size"], file_set["local_sha256"])
        if latest is not None:
            known_local = watchlist_store.record_set(
                watchlist_store.version_record(latest), "local"
            )
            if known_local is not None and known_local == file_set["local"]:
                # No device hash to compare first (no root?): the copy says it.
                watchlist_store.discard_current(path)
                self._record_check(
                    path, latest, trigger, event_time, device_set or {}, mark,
                    "no change (the pulled copy is identical)", clock, rewind,
                )  # fmt: skip
                return latest.name, None

        kept = watchlist_store.keep_version(path, record, pulled_at)
        pull_seq = timeline_pull(
            path,
            trigger,
            ok=True,
            version=kept.dir,
            file_set=file_set,
            changed=None if latest is None else bool(kept.changed),
        )
        from sandroid.services.privacy_scan import submit_pulled_version

        submit_pulled_version(path, kept.dir, pull_seq)
        if latest is None:
            self._post(
                self._apply_pull_result,
                path,
                RowState.BASELINE_ONLY,
                self._baseline_message(kept.dir),
                None,
                facts,
                kept.dir.name,
                clock,
            )
            return kept.dir.name, None
        changed = kept.changed
        self._post(
            self._apply_pull_result,
            path,
            RowState.CHANGED if changed else RowState.UNCHANGED,
            None
            if changed
            else "Bytes changed (kept as a version), but no change in the content.",
            kept.text if changed else None,
            facts,
            kept.dir.name,
            clock,
        )
        return kept.dir.name, None

    def _record_check(
        self,
        path: str,
        latest: Path,
        trigger: str,
        event_time: datetime | None,
        device_set: dict[str, str],
        mark: dict | None,
        note: str,
        clock: dict | None = None,
        rewind: dict | None = None,
    ) -> None:
        """A pull found no change: one ``checks.jsonl`` line, no version."""
        same_as = latest.name.split("_", 1)[0]
        check = {
            "at": watchlist_store.iso_tz(),
            "trigger": trigger,
            "event_at": watchlist_store.iso_tz(event_time) if event_time else None,
            "device_sha256": device_set,
            "same_as": same_as,
            "note": note,
            "mark": mark,
            "device_clock": clock,
        }
        if rewind is not None:
            check["rewind"] = {**rewind, "version": latest.name}
        entry = watchlist_store.append_check(path, check)
        timeline_check(path, trigger, same_as, note)
        self._post(self._apply_check_result, path, latest.name, entry)

    def _active_mark(self, when: datetime) -> dict | None:
        """The label ``when`` falls in: the innermost open label, else the
        latest point label before it (``None``: none).
        """
        from sandroid.core.timeline import active_label

        active = active_label(list(self.marks), when)
        if active is None:
            return None
        return watchlist_store.mark_entry(
            active.number,
            getattr(active, "name", ""),
            active.when,
            kind=getattr(active, "kind", None) or "point",
            seq=getattr(active, "seq", None),
        )

    @staticmethod
    def _acquisition_record(
        path: str,
        current: Path,
        basename: str,
        device: dict[str, dict],
        companions: list[str],
        pulled_at: datetime,
        trigger: str,
        event_time: datetime | None,
        mark: dict | None = None,
        clock: dict | None = None,
    ) -> dict:
        """The ``acquisition.json`` of one pull (see ``watchlist_store``).

        Per member (the file, and its pulled ``-wal``/``-journal``): the
        device's mtime/size/sha256 and the local copy's size/sha256. ``set``
        sums them up: the members' hashes on each side, one combined hash per
        side (:func:`watchlist_store.set_sha256`), which members differ, the
        total size and the newest device mtime -- the WAL is often the only
        member that changed. ``sha256_match`` is the verdict for the whole
        set. ``device_clock`` is the device clock sample of the pull (host -
        device offsets, see :mod:`sandroid.core.device_clock`): device times
        here (``mtime``) are on the device clock.
        """

        def _device_entry(device_path: str) -> dict:
            entry = device.get(device_path) or {}
            mtime = entry.get("mtime")
            return {
                "mtime": mtime,
                "mtime_iso": (
                    watchlist_store.iso_tz(mtime) if isinstance(mtime, int) else None
                ),
                "size": entry.get("size"),
                "sha256": entry.get("sha256"),
            }

        def _local_entry(name: str) -> dict:
            size, sha = _file_facts(current / name)
            return {"file": name, "size": size, "sha256": sha}

        def _match(dev: dict, loc: dict) -> bool | None:
            return (dev["sha256"] == loc["sha256"]) if dev["sha256"] else None

        main_device = _device_entry(path)
        main_local = _local_entry(basename)
        companion_entries = []
        for companion in companions:
            dev = _device_entry(companion)
            loc = _local_entry(basename + companion[len(path) :])
            companion_entries.append(
                {
                    "device_path": companion,
                    "device": dev,
                    "local": loc,
                    "sha256_match": _match(dev, loc),
                }
            )
        file_set = _set_summary(path, basename, device, main_local, companion_entries)
        return {
            "schema_version": 2,
            "device_path": path,
            "package": watchlist_store.package_of(path),
            "device": main_device,
            "local": main_local,
            "sha256_match": file_set["match"],
            "companions": companion_entries,
            "set": file_set,
            "pulled_at": watchlist_store.iso_tz(pulled_at),
            "trigger": trigger,
            "trigger_event_at": (
                watchlist_store.iso_tz(event_time) if event_time else None
            ),
            "mark": mark,
            "device_clock": clock,
            "note": (
                None
                if main_device["sha256"]
                else "no on-device sha256 (sha256sum failed: no root or no device)"
            ),
        }

    @staticmethod
    def _baseline_message(version: Path) -> str:
        files = [
            f
            for f in version.iterdir()
            if f.is_file() and f.name not in watchlist_store.META_FILES
        ]
        total_bytes = sum(f.stat().st_size for f in files)
        plural = "s" if len(files) != 1 else ""
        return f"First version — {len(files)} file{plural}, {total_bytes} bytes."

    def _apply_check_result(self, path: str, version: str, entry: dict) -> None:
        """Main-thread callback: a pull found no change (nothing was kept)."""
        self._pulling.discard(path)
        info = self._rows.get(path)
        if info is None:
            return
        at = str(entry.get("at") or "")
        info.state = (
            RowState.SETTLING if path in self._auto_timers else RowState.UNCHANGED
        )
        info.checked_at = at
        info.device_clock = entry.get("device_clock") or info.device_clock
        info.diff_text = None
        info.version = version
        clock = at[11:19] if len(at) >= 19 else at
        info.detail = (
            f"Checked {clock}: no change since {entry.get('same_as') or version} "
            "(on-device sha256 of the file and its -wal/-journal identical); "
            "not pulled again."
        )
        if "identical" in str(entry.get("note") or ""):
            info.detail = (
                f"Checked {clock}: the pulled copy is identical to "
                f"{entry.get('same_as') or version}, so it was not kept."
            )
        self._changed([path])

    def _apply_pull_result(
        self,
        path: str,
        state: RowState,
        detail: str | None,
        diff_text: str | None,
        facts: tuple[int | None, str | None] | None = None,
        version: str | None = None,
        clock: dict | None = None,
    ) -> None:
        """Main-thread callback (via ``_post``) applying one pull's outcome."""
        self._pulling.discard(path)
        info = self._rows.get(path)
        if info is None:
            return  # removed from the watchlist while the pull was in flight
        if path in self._auto_timers and state is not RowState.ERROR:
            # Written again while pulling: the pending auto-pull follows.
            state_after = RowState.SETTLING
        else:
            state_after = state
        info.state = state_after
        info.detail = detail or ""
        if state is not RowState.ERROR:
            info.diff_text = diff_text
            info.pulled_at = datetime.now().isoformat(timespec="seconds")
            if facts is not None:
                info.size, info.sha256 = facts
            info.version = version or info.version
            info.device_clock = clock or info.device_clock
            # A path watched elsewhere (``l``, the AI tools) is remembered too.
            self._persist_index()
        self._changed([path])

    # -- thread marshalling (mirrors DiffsView's _run_bg/_post exactly) -----

    def _run_bg(self, fn, name: str) -> None:
        """Run ``fn`` on a worker thread, or inline if no app context exists."""
        if self._run_worker_available():
            self.run_worker(fn, name=name, exclusive=False, thread=True)
        else:
            fn()

    def _run_worker_available(self) -> bool:
        try:
            return bool(self.is_running)
        except Exception:
            return False

    def _post(self, fn, *args) -> None:
        """Run ``fn(*args)`` on the Textual main thread (``call_from_thread``)."""
        if threading.current_thread() is threading.main_thread():
            fn(*args)
            return
        try:
            self.app.call_from_thread(fn, *args)
        except Exception:
            logger.debug(
                "WatchlistView: call_from_thread marshal failed", exc_info=True
            )

    def _notify(self, message: str, severity: str = "information") -> None:
        try:
            self.app.notify(message, severity=severity)
        except Exception:
            pass


__all__ = [
    "AUTO_PULL_QUIET",
    "SESSION_BASELINE_CAP",
    "RowState",
    "WatchlistView",
    "parse_device_facts",
]
