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
with the copy, ``diff.txt`` and ``acquisition.json`` (device path, device
mtime + size, the sha256 computed on the device before the pull, the local
sha256 after it, the pull time and the trigger). Nothing is pruned.

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
    size: int | None = None  #: bytes of the main file
    sha256: str | None = None  #: of the main file (local copy)
    version: str | None = None  #: name of the version folder


#: SQLite files that belong to a database: pulled with it (a WAL-mode write
#: only touches ``-wal`` until a checkpoint). ``-shm`` is left out on
#: purpose: it changes on every read.
SQLITE_COMPANIONS = ("-wal", "-journal")


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

    def add_path(self, path: str) -> bool:
        """Watch a path or wildcard pattern; False (with a toast) if rejected."""
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
        self._notify(f"Watching {path}")
        return True

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

    def _start_timer(self, path: str):
        try:
            return self.set_timer(
                AUTO_PULL_QUIET, functools.partial(self.fire_auto_pull, path)
            )
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
        if entry is None or path not in self._rows:
            return
        _timer, first = entry
        if path in self._pulling:
            # A pull is still running: try again after another quiet period.
            self._auto_timers[path] = (self._start_timer(path), first)
            return
        self._start_pull([path], trigger="auto", event_time=first)

    # -- pull / diff --------------------------------------------------------

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
                self._pull_and_diff_one(path, trigger, event_time)
            except Exception as exc:
                logger.warning(f"Watchlist pull failed for {path}: {exc}")
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

    def _pull_and_diff_one(
        self,
        path: str,
        trigger: str = "manual",
        event_time: datetime | None = None,
    ) -> None:
        """Runs on a background thread (see ``_run_bg``).

        Device facts (stat + sha256sum) first, then the pull (+ SQLite
        companions) into the staging folder, the diff against the newest
        version, and finally the new version folder with ``diff.txt`` and
        ``acquisition.json``. Never touches widgets; reports via ``_post``.
        """
        fx = get_file_extraction_service()
        had_previous = watchlist_store.has_baseline(path)
        basename = os.path.basename(path.rstrip("/")) or "pulled_file"
        companions = [f"{path}{s}" for s in SQLITE_COMPANIONS]
        device = self._device_facts([path, *companions])
        current = watchlist_store.reset_current(path)
        current_main = current / basename

        result = fx.pull_file(path, str(current_main))
        if not result.success:
            self._post(
                self._apply_pull_result,
                path,
                RowState.ERROR,
                result.error or "Pull failed",
                None,
            )
            return

        pulled_companions: list[str] = []
        if is_sqlite_file(str(current_main)) or any(c in device for c in companions):
            from sandroid.core.adb_utils import quiet_adb_warnings

            # Not a warning when one is missing (WAL mode has no -journal).
            with quiet_adb_warnings():
                for companion in companions:
                    local = f"{current_main}{companion[len(path) :]}"
                    if fx.pull_file(companion, local).success:
                        pulled_companions.append(companion)

        facts = _file_facts(current_main)
        pulled_at = datetime.now()
        record = self._acquisition_record(
            path, current, basename, device, pulled_companions, pulled_at,
            trigger, event_time,
        )  # fmt: skip
        if not had_previous:
            version = watchlist_store.promote(path, None, record, when=pulled_at)
            self._post(
                self._apply_pull_result,
                path,
                RowState.BASELINE_ONLY,
                self._baseline_message(version),
                None,
                facts,
                version.name,
            )
            return

        previous_main = watchlist_store.version_file(
            watchlist_store.previous_dir(path), path
        )
        diff_text, changed = _compute_diff(previous_main, current_main)
        version = watchlist_store.promote(
            path, diff_text if changed else "", record, when=pulled_at
        )
        self._post(
            self._apply_pull_result,
            path,
            RowState.CHANGED if changed else RowState.UNCHANGED,
            None if changed else "No changes since the version before.",
            diff_text if changed else None,
            facts,
            version.name,
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
    ) -> dict:
        """The ``acquisition.json`` of one pull (see ``watchlist_store``)."""

        def _device_entry(device_path: str) -> dict:
            entry = device.get(device_path) or {}
            mtime = entry.get("mtime")
            return {
                "mtime": mtime,
                "mtime_iso": (
                    datetime.fromtimestamp(mtime).isoformat(timespec="seconds")
                    if isinstance(mtime, int)
                    else None
                ),
                "size": entry.get("size"),
                "sha256": entry.get("sha256"),
            }

        def _local_entry(name: str) -> dict:
            size, sha = _file_facts(current / name)
            return {"file": name, "size": size, "sha256": sha}

        main_device = _device_entry(path)
        main_local = _local_entry(basename)
        device_sha, local_sha = main_device["sha256"], main_local["sha256"]
        return {
            "schema_version": 1,
            "device_path": path,
            "package": watchlist_store.package_of(path),
            "device": main_device,
            "local": main_local,
            "sha256_match": (device_sha == local_sha) if device_sha else None,
            "companions": [
                {
                    "device_path": companion,
                    "device": _device_entry(companion),
                    "local": _local_entry(basename + companion[len(path) :]),
                }
                for companion in companions
            ],
            "pulled_at": pulled_at.isoformat(timespec="seconds"),
            "trigger": trigger,
            "trigger_event_at": (
                event_time.isoformat(timespec="seconds") if event_time else None
            ),
            "note": (
                None
                if device_sha
                else "no on-device sha256 (sha256sum failed: no root or no device)"
            ),
        }

    @staticmethod
    def _baseline_message(version: Path) -> str:
        files = [
            f
            for f in version.iterdir()
            if f.is_file() and f.name not in ("acquisition.json", "diff.txt")
        ]
        total_bytes = sum(f.stat().st_size for f in files)
        plural = "s" if len(files) != 1 else ""
        return f"First version — {len(files)} file{plural}, {total_bytes} bytes."

    def _apply_pull_result(
        self,
        path: str,
        state: RowState,
        detail: str | None,
        diff_text: str | None,
        facts: tuple[int | None, str | None] | None = None,
        version: str | None = None,
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


__all__ = ["AUTO_PULL_QUIET", "RowState", "WatchlistView", "parse_device_facts"]
