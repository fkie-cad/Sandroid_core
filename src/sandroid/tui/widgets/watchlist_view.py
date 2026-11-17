"""The Spotlight-Files watchlist behind the Files lens (non-visual).

``WatchlistView`` is a hidden child widget of the Files lens
(:class:`~sandroid.tui.widgets.files_panel.FilesPanel`): it owns the
``ForensicService`` spotlight-file watchlist -- add/remove (paths and
wildcard patterns), pull one/all, auto-pull mode, persistence -- and every
pull diffs the fresh copy against the previous pull (``core/file_diff.py``,
the same engine behind :class:`~sandroid.tui.widgets.diff_view.DiffView`).
It draws nothing: whenever its rows change it posts
:class:`WatchlistView.Changed`, and the lens re-renders its table (watched
files carry ★ and are pinned on top) and the Inspector. It is a widget only
so it can own timers and thread workers.

**Naming note** (also in ``spotlight_controller.py``): "Spotlight" is
overloaded in this codebase. This module is about the *forensic* Spotlight
Files watchlist (``ForensicService._spotlight_files``) -- it is unrelated to
the *Frida* spotlight app-under-test (``spotlight_panel.py``/
``SpotlightService``, keys ``c``/``Shift+C``).

**Auto mode** (``a`` key, off by default; header badge ``auto ○ off`` /
``auto ● on · every Ns``): a visibility-gated ``set_interval`` poll mirrors
``SnapshotsPanel``'s ``_is_on_screen()``/``_refresh_if_visible()`` pattern,
(see ``_is_watchlist_visible``) — it only does real work while the Files
lens is on screen. Each tick issues one batched
``adb shell "stat -c '%n %Y %s' <path>..."`` call (see ``_stat_command``)
covering every watched path, keyed back to the right row by the ``%n``
(filename) field so one bad path's stderr text can't misalign the batch.
Two signatures per path — ``last_seen`` (updated every tick) vs
``last_pulled`` (updated only on an actual pull) — define "changed"
(``last_seen != last_pulled``); ``_evaluate_auto_pull`` debounces (the
signature must be unchanged across two consecutive ticks) and rate-limits
(a per-file minimum interval) before triggering the real pull, which reuses
the exact same ``_start_pull``/``_pull_worker``/``_apply_pull_result`` path
the manual ``u``/``U`` pulls use — no separate pull-and-diff
implementation. Adaptive backoff (5s -> 10s -> 20s -> 30s after consecutive
no-change ticks, reset to 5s the instant any path changes) avoids hammering
a quiet device. Wildcard entries (containing ``*``) are re-expanded on a
slower, decoupled ~30s timer by calling ``ForensicService.add_spotlight_file``
again (its own dedup makes repeat calls a no-op for already-known matches,
so this only ever *adds* newly-created matches). A full-batch adb failure
(device offline/disconnected) pauses auto-mode with an explicit badge and
resumes automatically via ``DeviceManager.on_device_change`` (see
``_ensure_device_change_subscription``) rather than a second polling loop;
a per-path failure inside an otherwise-successful batch only marks that one
row ``RowState.ERROR`` and never pauses the whole mechanism.
"""

from __future__ import annotations

import fnmatch
import functools
import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

from textual.message import Message
from textual.widget import Widget

from sandroid.core import file_diff, watchlist_store
from sandroid.core.adb_utils import device_shell_arg
from sandroid.services import get_file_extraction_service, get_forensic_service
from sandroid.services.file_extraction_service import is_sqlite_file

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

#: Auto-mode's adaptive backoff ladder (seconds). Resets to index 0 the
#: instant any watched path shows a metadata change; otherwise advances one
#: step per consecutive no-change tick and sticks at the last step.
_AUTO_BACKOFF_STEPS: tuple[float, ...] = (5.0, 10.0, 20.0, 30.0)

#: Minimum time (seconds) between two auto-triggered pulls of the SAME path
#: -- the rate-limit half of the debounce gate (the other half is "stable
#: across two consecutive ticks", see _evaluate_auto_pull). Within the
#: plan's 15-30s range; a busy WAL file would otherwise trigger a pull on
#: nearly every tick.
_AUTO_PULL_MIN_INTERVAL = 20.0

#: How often wildcard entries (patterns containing "*") get re-expanded to
#: catch newly-created matching files. Deliberately slower than, and
#: decoupled from, the per-tick stat poll -- expansion needs its own adb
#: round-trip (find/ls) per pattern, so it doesn't need per-tick freshness.
_WILDCARD_REEXPAND_INTERVAL = 30.0

#: Substrings indicating the WHOLE batched stat call failed because the
#: device is unreachable (vs. a normal per-path "no such file"/"permission
#: denied" stat error, which never contains any of these). Mirrors
#: core/device_manager.py's DeviceManager.handle_device_error
#: disconnect_patterns list for consistency with how the rest of the app
#: already recognizes a dead/absent device, plus Adb.send_adb_command's own
#: hardcoded "Command timed out after 30 seconds" message.
_DEVICE_ERROR_PATTERNS: tuple[str, ...] = (
    "device not found",
    "device offline",
    "no devices",
    "no device",
    "connection refused",
    "closed",
    "broken pipe",
    "transport",
    "timed out",
)


class RowState(Enum):
    """Per-row pull/diff state.

    Started deliberately small (Watchlist CRUD migration, no auto-mode yet)
    as a real enum rather than ad hoc strings/booleans specifically so a
    later task could extend it without redesigning this field -- ``SETTLING``
    below is that extension, added for auto-mode's debounce window (the full
    plan's CHECKING/NEW/DELETED states remain future extensions this enum
    can still absorb the same way).
    """

    NEVER_PULLED = "never_pulled"  #: ○ gray -- never pulled at all
    BASELINE_ONLY = "baseline_only"  #: ✓ gray -- one pull, nothing to diff against yet
    UNCHANGED = "unchanged"  #: ✓ gray -- diffed against baseline, no changes
    CHANGED = "changed"  #: ◆ yellow -- diffed against baseline, real changes
    ERROR = "error"  #: ✕ red -- last pull failed
    #: ◇ dim-yellow -- auto-mode detected a metadata change but is still
    #: debouncing (waiting for stability across ticks and/or the per-file
    #: rate limit) before actually triggering a pull. Added for auto-mode
    #: (this state is otherwise unreachable via manual pull/remove), using
    #: the extensibility this enum was deliberately built for.
    SETTLING = "settling"


#: RowState -> (glyph, Rich-markup color). Colors match this app's existing
#: semantic palette (see monitor_controller.MONITOR_EVENT_INFO / diffs_view.py's
#: category colors): gray for "nothing new to look at", yellow for
#: "changed", red for "error", dim-yellow for "changed but still settling".
_GLYPH: dict[RowState, tuple[str, str]] = {
    RowState.NEVER_PULLED: ("○", "#5b6479"),
    RowState.BASELINE_ONLY: ("✓", "#5b6479"),
    RowState.UNCHANGED: ("✓", "#5b6479"),
    RowState.CHANGED: ("◆", "#facc15"),
    RowState.ERROR: ("✕", "#ef4444"),
    RowState.SETTLING: ("◇", "#a3873f"),
}


@dataclass
class _RowInfo:
    """In-memory state for one watched path (not persisted directly)."""

    path: str
    state: RowState = RowState.NEVER_PULLED
    detail: str = ""  # short status line shown under the row / in the header
    diff_text: str | None = None  # last computed diff, if state is CHANGED
    # -- auto-mode bookkeeping (in-memory only; see module docstring's Auto
    # mode section). watchlist_store's on-disk previous/current cache is
    # already the durable record of pulled *content* -- these tuples are
    # just the cheap (mtime, size) metadata signal driving *when* to pull.
    last_seen: tuple[int, int] | None = None  #: updated on every auto-tick
    last_pulled: tuple[int, int] | None = None  #: updated only after a real pull
    # -- last successful pull (shown in the Inspector; persisted) ---------
    pulled_at: str | None = None  #: ISO timestamp
    size: int | None = None  #: bytes of the main file
    sha256: str | None = None  #: of the main file


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

    Thin delegator to the shared :func:`sandroid.core.file_diff.diff_files`
    -- promoted there (from what used to be this function's own body) so the
    AI chat's ``get_file_diff`` tool
    (:mod:`sandroid.ai.tools.monitor_control`) can reuse the exact same
    extension/magic-header dispatch instead of a second, drifting copy. Kept
    as a thin same-signature wrapper here (rather than deleting it and
    updating the one call site directly) purely because existing tests
    (``tests/tui/test_watchlist_view.py``) import it directly by this name.

    Deliberately passes ``file_extraction_service.is_sqlite_file`` (a plain,
    uncached magic-header read) rather than ``file_diff.is_sqlite_file`` --
    see :func:`sandroid.core.file_diff.diff_files`'s own docstring for why:
    that module keeps a process-lifetime cache keyed by path string with no
    invalidation, which is safe for ``ChangedFiles``' one-shot-per-Play
    timestamped pull directories but NOT for Watchlist's fixed
    ``current``/``previous`` paths, which get overwritten on every manual
    pull -- a cached answer from pull #1 would silently outlive whatever
    pull #2 actually wrote to that same path.

    Returns:
        ``(diff_text, changed)`` -- see ``diff_files``'s own docstring.
    """
    return file_diff.diff_files(previous_main, current_main, is_sqlite_file)


class WatchlistView(Widget):
    """Non-visual watchlist engine of the Files lens (see module docstring).

    Public API used by the lens: ``rows``/``patterns``/``is_watched`` (state),
    ``add_path``/``remove_path``/``unwatch``/``pull``/``pull_all``/
    ``toggle_auto`` (mutations), ``summary``/``auto_badge`` (text). Every
    state change posts :class:`WatchlistView.Changed`.
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
        #: path -> _RowInfo, keyed the same way ForensicService keys them
        #: (the literal device path/already-expanded wildcard match).
        self._rows: dict[str, _RowInfo] = {}

        # -- auto-mode state (see module docstring's Auto mode section) ----
        self._auto_enabled: bool = False
        #: None while running normally; a short human reason (e.g. "device
        #: offline") while paused. Distinct from _auto_enabled so toggling
        #: auto off/on again is a clean reset, not just "unpause".
        self._auto_paused_reason: str | None = None
        self._auto_backoff_idx: int = 0
        self._auto_interval: float = _AUTO_BACKOFF_STEPS[0]
        self._auto_timer = None  # Textual Timer handle for the stat poll
        self._auto_tick_inflight: bool = False
        #: path -> monotonic time of the last AUTO-triggered pull (manual
        #: pulls via u/U don't touch this -- only auto-mode is rate-limited).
        self._last_auto_pull_at: dict[str, float] = {}
        #: paths with an auto-triggered pull currently in flight, so a
        #: still-settling path already mid-pull isn't re-triggered.
        self._auto_pull_inflight: set[str] = set()

        # -- wildcard patterns (persisted; re-expanded on a slower timer) --
        #: Patterns (containing "*") the user added. ForensicService only
        #: keeps the already-expanded literal matches, so the pattern itself
        #: is remembered (and persisted) here -- the lens pins it as a row
        #: and auto-mode re-expands it to catch newly created files.
        self._watched_patterns: set[str] = set()
        self._wildcard_timer = None
        self._wildcard_tick_inflight: bool = False

        # -- device-reconnect subscription (auto-resume after offline) ----
        self._device_change_subscribed: bool = False

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
        self._restore_persisted_rows()
        self._reload_rows()

    def on_unmount(self) -> None:
        # Auto mode is off by default and only starts timers when the user
        # toggles it on (see _start_auto_mode) -- this is defensive cleanup.
        self._cancel_auto_timer()
        self._cancel_wildcard_timer()

    # -- public state ---------------------------------------------------------

    @property
    def rows(self) -> dict[str, _RowInfo]:
        """Row state per watched path (do not mutate)."""
        return self._rows

    @property
    def patterns(self) -> list[str]:
        return sorted(self._watched_patterns)

    @property
    def auto_enabled(self) -> bool:
        return self._auto_enabled

    def watched_by(self, path: str) -> str | None:
        """The literal path or pattern that watches ``path``, else None."""
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

    def auto_badge(self) -> str:
        return self._auto_badge()

    def reload(self) -> None:
        """Resync with ForensicService (paths may be watched elsewhere)."""
        self._reload_rows()

    # -- services (lazy) ------------------------------------------------------

    @staticmethod
    def _adb():
        from sandroid.core.adb import Adb

        return Adb

    @staticmethod
    def _device_manager():
        """The live ``DeviceManager`` (via ``DeviceService``), lazily resolved.

        A separate seam from ``_adb()`` so tests can monkeypatch just this
        one method to inject a fake manager (recording ``on_device_change``
        callbacks) without touching the real device-manager singleton --
        see ``_ensure_device_change_subscription``.
        """
        from sandroid.services import get_device_service

        return get_device_service().get_device_manager()

    # -- row bookkeeping ------------------------------------------------------

    def _restore_persisted_rows(self) -> None:
        """Rebuild ``self._rows`` (and auto-mode's own enablement) from
        ``index.json``'s persisted per-path state -- called once from
        ``on_mount``, BEFORE ``_reload_rows()`` runs.

        Ordering matters: ``_reload_rows()`` only ever builds a fresh
        ``_RowInfo`` for a path that ISN'T already present in ``self._rows``
        (see its own ``if path in self._rows: continue`` guard below), so
        populating ``self._rows`` here first -- with the REAL last-known
        state -- is what makes a restart actually restore rows instead of
        falling back to ``_reload_rows()``'s own NEVER_PULLED/BASELINE_ONLY
        heuristic (which only knows about baseline existence, not the full
        RowState/last_seen/last_pulled history).
        """
        try:
            row_states = watchlist_store.load_row_states()
            auto_enabled = watchlist_store.load_auto_enabled()
        except Exception:
            logger.debug("Watchlist: failed to load persisted row state", exc_info=True)
            return
        known_paths = set(get_forensic_service().get_spotlight_files())
        for path, payload in row_states.items():
            if path not in known_paths:
                continue  # stale entry for a path no longer in the watchlist
            try:
                state = RowState(payload.get("state"))
            except ValueError:
                state = RowState.NEVER_PULLED
            last_seen = payload.get("last_seen")
            last_pulled = payload.get("last_pulled")
            pull = payload.get("pull") or {}
            self._rows[path] = _RowInfo(
                path=path,
                state=state,
                detail=payload.get("detail") or "",
                last_seen=tuple(last_seen) if last_seen else None,
                last_pulled=tuple(last_pulled) if last_pulled else None,
                pulled_at=pull.get("at"),
                size=pull.get("size"),
                sha256=pull.get("sha256"),
            )
        if auto_enabled:
            self._start_auto_mode()

    def _row_states_payload(self) -> dict[str, dict]:
        """``self._rows`` -> the plain-JSON-safe shape ``watchlist_store.
        save_membership`` expects (see its docstring): tuples become
        2-element lists (or ``None``), since JSON has no tuple type.
        """
        payload: dict[str, dict] = {}
        for path, info in self._rows.items():
            payload[path] = {
                "state": info.state.value,
                "detail": info.detail,
                "last_seen": list(info.last_seen) if info.last_seen else None,
                "last_pulled": list(info.last_pulled) if info.last_pulled else None,
                "pull": (
                    {"at": info.pulled_at, "size": info.size, "sha256": info.sha256}
                    if info.pulled_at
                    else None
                ),
            }
        return payload

    def _persist_index(self) -> None:
        """Persist membership + every row's last-known pull/auto state.

        The single call site all mutation paths (add/remove/pull/auto-tick/
        auto-toggle/wildcard-reexpand) funnel through, so index.json never
        drifts from ``self._rows``. ``ForensicService.save_watchlist_index``
        already best-effort-catches and logs on failure (mirrors the
        pre-existing membership-only save), so callers here don't need
        their own try/except.
        """
        get_forensic_service().save_watchlist_index(
            row_states=self._row_states_payload(),
            auto_enabled=self._auto_enabled,
            patterns=sorted(self._watched_patterns),
        )

    def _reload_rows(self) -> None:
        """Resync ``self._rows`` from ForensicService (mount / tab-activation /
        after a mutation) without losing already-known pull state.
        """
        paths = get_forensic_service().get_spotlight_files()
        for path in paths:
            if path in self._rows:
                continue
            if watchlist_store.has_baseline(path):
                # A baseline from a prior TUI session already exists on
                # disk even though this row is new to *this* process --
                # reflect that honestly instead of claiming never-pulled.
                self._rows[path] = _RowInfo(
                    path=path,
                    state=RowState.BASELINE_ONLY,
                    detail="Baseline from a previous session.",
                )
            else:
                self._rows[path] = _RowInfo(path=path)
        for path in list(self._rows):
            if path not in paths:
                del self._rows[path]
        self._rebuild_list()

    def _changed(self, paths=None) -> None:
        """Tell the lens the rows changed (``paths``: which ones, or all)."""
        try:
            self.post_message(
                self.Changed(frozenset(paths) if paths is not None else None)
            )
        except Exception:
            pass

    # Old names, kept for the many call sites below.
    def _rebuild_list(self) -> None:
        self._changed()

    _update_header = _rebuild_list

    def _auto_badge(self) -> str:
        """Auto-mode status badge shown in the header (see module docstring)."""
        if not self._auto_enabled:
            return "[dim]auto ○ off[/dim]"
        if self._auto_paused_reason:
            return f"[#fb7185]auto ● on ({self._auto_paused_reason})[/]"
        return f"[#4ade80]auto ● on[/] · every {int(self._auto_interval)}s"

    # -- add / remove -----------------------------------------------------

    @staticmethod
    def _pattern_matches(pattern: str, path: str) -> bool:
        if pattern.endswith("/*") and path.startswith(pattern[:-1]):
            return True  # "dir/*" expands recursively (find -type f)
        return fnmatch.fnmatchcase(path, pattern)

    def add_path(self, path: str) -> bool:
        """Watch a path or wildcard pattern; False (with a toast) if rejected."""
        return self._add_path(path)

    def _add_path(self, path: str) -> bool:
        forensic = get_forensic_service()
        if "*" in path and path in self._watched_patterns:
            self._notify(f"Already watching: {path}", "warning")
            return False
        # add_spotlight_file() itself branches on "*" to expand wildcards
        # (_add_spotlight_files_by_pattern) -- passing an adb instance is
        # harmless for the plain path, since that branch never touches it.
        added = forensic.add_spotlight_file(path, adb=self._adb())
        if "*" in path:
            # Remember (and persist) the pattern even when it matches nothing
            # yet: the lens pins it, auto-mode re-expands it.
            self._watched_patterns.add(path)
        elif not added:
            self._notify(f"Already watching or invalid: {path}", "warning")
            return False
        self._persist_index()
        self._reload_rows()
        self._notify(f"Watching {path}")
        return True

    def remove_path(self, path: str) -> bool:
        """Unwatch a literal path (its pulled baseline stays on disk)."""
        forensic = get_forensic_service()
        if not forensic.remove_spotlight_file(path):
            return False
        self._persist_index()
        self._rows.pop(path, None)
        # Best-effort cleanup of auto-mode's per-path bookkeeping.
        self._last_auto_pull_at.pop(path, None)
        self._auto_pull_inflight.discard(path)
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
            self._persist_index()
            self._reload_rows()
            self._notify(f"Stopped watching {path}")
            return True
        if self.remove_path(path):
            self._notify(f"Stopped watching {path}")
            return True
        return False

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

    def _start_pull(self, paths: list[str]) -> None:
        self._run_bg(
            functools.partial(self._pull_worker, list(paths)), "watchlist_pull"
        )

    def _pull_worker(self, paths: list[str]) -> None:
        for path in paths:
            try:
                self._pull_and_diff_one(path)
            except Exception as exc:
                logger.warning(f"Watchlist pull failed for {path}: {exc}")
                self._post(
                    self._apply_pull_result, path, RowState.ERROR, str(exc), None
                )

    def _pull_and_diff_one(self, path: str) -> None:
        """Runs on a background thread (see ``_run_bg``).

        Pulls the fresh copy, diffs against the stored baseline (if any),
        then promotes the fresh pull to be the new baseline. Never touches
        widgets directly from this thread -- reports back via ``_post``.
        """
        fx = get_file_extraction_service()
        had_previous = watchlist_store.has_baseline(path)
        current = watchlist_store.reset_current(path)
        basename = os.path.basename(path.rstrip("/")) or "pulled_file"
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

        # SQLite companions (-wal/-journal), best-effort -- mirrors
        # FileExtractionService._pull_sqlite_companions, but pulled directly
        # here (rather than reaching into that private method) so the
        # destination stays inside our own current/ cache directory.
        if is_sqlite_file(str(current_main)):
            for suffix in ("-wal", "-journal"):
                fx.pull_file(f"{path}{suffix}", f"{current_main}{suffix}")

        facts = _file_facts(current_main)
        if not had_previous:
            detail = self._baseline_message(current)
            watchlist_store.promote(path)
            self._post(
                self._apply_pull_result,
                path,
                RowState.BASELINE_ONLY,
                detail,
                None,
                facts,
            )
            return

        previous_main = watchlist_store.previous_dir(path) / basename
        diff_text, changed = _compute_diff(previous_main, current_main)
        watchlist_store.promote(path)
        if changed:
            self._post(
                self._apply_pull_result,
                path,
                RowState.CHANGED,
                None,
                diff_text,
                facts,
            )
        else:
            self._post(
                self._apply_pull_result,
                path,
                RowState.UNCHANGED,
                "No changes since last pull.",
                None,
                facts,
            )

    @staticmethod
    def _baseline_message(current: Path) -> str:
        files = [f for f in current.iterdir() if f.is_file()]
        total_bytes = sum(f.stat().st_size for f in files)
        plural = "s" if len(files) != 1 else ""
        return f"Baseline captured — {len(files)} file{plural}, {total_bytes} bytes."

    def _apply_pull_result(
        self,
        path: str,
        state: RowState,
        detail: str | None,
        diff_text: str | None,
        facts: tuple[int | None, str | None] | None = None,
    ) -> None:
        """Main-thread callback (via ``_post``) applying one pull's outcome.

        Shared by BOTH manual pulls (p/P) and auto-mode's debounced pulls --
        ``_evaluate_auto_pull`` triggers a pull by calling ``_start_pull``
        exactly like the manual actions do, so this is the one place a
        pull's outcome gets applied, never duplicated.
        """
        # Auto-mode's in-flight guard must clear regardless of outcome (incl.
        # the "row removed mid-flight" early-return below), or a removed-
        # then-re-added path could get stuck never-auto-pullable again.
        self._auto_pull_inflight.discard(path)
        info = self._rows.get(path)
        if info is None:
            return  # removed from the watchlist while the pull was in flight
        info.state = state
        info.detail = detail or ""
        info.diff_text = diff_text
        if state != RowState.ERROR:
            # The freshly-pulled content now matches whatever on-device
            # (mtime, size) we most recently observed (if auto-mode has
            # ticked this path at least once) -- this is what auto-mode's
            # "changed" (last_seen != last_pulled) is measured against going
            # forward. If auto-mode never ticked this path yet, last_seen is
            # still None here; the next tick reconciles it instead.
            info.last_pulled = info.last_seen
            info.pulled_at = datetime.now().isoformat(timespec="seconds")
            if facts is not None:
                info.size, info.sha256 = facts
        self._persist_index()
        self._changed([path])

    # -- auto mode: visibility, toggle, timer lifecycle ---------------------
    #
    # See the module docstring's "Auto mode" section for the full design.
    # Off by default; `a` toggles it (a focus-scoped shadow of the global
    # `a`=Analyze binding, the same established precedent as d/p/n above).

    def _is_watchlist_visible(self) -> bool:
        """True only while the Files lens is on screen (this widget itself is
        always ``display: none``, so ask about its parent).
        """
        from .lens_shell import is_shown

        parent = self.parent
        return parent is not None and is_shown(parent)

    def toggle_auto(self) -> None:
        self.action_toggle_auto()

    def action_toggle_auto(self) -> None:
        if self._auto_enabled:
            self._stop_auto_mode()
            self._notify("Auto mode off.")
        else:
            self._start_auto_mode()
            self._notify(f"Auto mode on — checking every {int(self._auto_interval)}s.")
        self._update_header()
        self._persist_index()

    def _start_auto_mode(self) -> None:
        self._auto_enabled = True
        self._auto_paused_reason = None
        self._auto_backoff_idx = 0
        self._ensure_device_change_subscription()
        self._reschedule_auto_timer()
        self._reschedule_wildcard_timer()

    def _stop_auto_mode(self) -> None:
        self._auto_enabled = False
        self._auto_paused_reason = None
        self._cancel_auto_timer()
        self._cancel_wildcard_timer()

    def _reschedule_auto_timer(self) -> None:
        """(Re)start the stat-poll timer at the current backoff interval.

        Textual's ``Timer`` has no "change the interval" API, so a backoff
        step change stops the old timer and starts a fresh one -- cheap and
        infrequent (at most once per tick).
        """
        self._cancel_auto_timer()
        if not self._auto_enabled or self._auto_paused_reason is not None:
            return
        self._auto_interval = _AUTO_BACKOFF_STEPS[self._auto_backoff_idx]
        self._auto_timer = self.set_interval(self._auto_interval, self._auto_tick)

    def _cancel_auto_timer(self) -> None:
        if self._auto_timer is not None:
            try:
                self._auto_timer.stop()
            except Exception:
                pass
            self._auto_timer = None

    def _reschedule_wildcard_timer(self) -> None:
        self._cancel_wildcard_timer()
        if not self._auto_enabled or self._auto_paused_reason is not None:
            return
        self._wildcard_timer = self.set_interval(
            _WILDCARD_REEXPAND_INTERVAL, self._wildcard_tick
        )

    def _cancel_wildcard_timer(self) -> None:
        if self._wildcard_timer is not None:
            try:
                self._wildcard_timer.stop()
            except Exception:
                pass
            self._wildcard_timer = None

    # -- auto mode: per-tick stat poll ---------------------------------------

    def _auto_tick(self) -> None:
        """Timer tick (main thread): no-op unless actually worth polling."""
        if not self._auto_enabled or self._auto_paused_reason is not None:
            return
        if not self._is_watchlist_visible():
            return
        paths = sorted(self._rows)
        if not paths:
            return
        if self._auto_tick_inflight:
            return  # a previous batch is still in flight -- never overlap
        self._auto_tick_inflight = True
        self._run_bg(
            functools.partial(self._auto_tick_worker, paths), "watchlist_auto_tick"
        )

    def _auto_tick_worker(self, paths: list[str]) -> None:
        """Runs on a worker thread (see ``_run_bg``): the blocking adb call."""
        try:
            stdout, stderr = self._stat_command(paths)
        except Exception as exc:
            stdout, stderr = "", str(exc)
        self._post(self._apply_auto_tick_result, paths, stdout, stderr)

    @staticmethod
    def _stat_command(paths: list[str]) -> tuple[str, str]:
        """Batched ``adb shell stat`` call for one auto-mode tick.

        A separate seam from ``_adb()`` so tests can monkeypatch just this
        one (static)method to drive the debounce/backoff state machine with
        canned ``(stdout, stderr)`` tuples, without touching the real
        Adb/subprocess machinery.

        QUOTING: ``Adb.send_adb_command`` runs the whole string through the
        HOST shell (``shell=True``) and ``adb shell`` then hands it to the
        DEVICE shell, so every word -- the ``'%n %Y %s'`` format and each
        path -- is quoted for both shells via ``device_shell_arg``. Paths
        come from device listings (wildcard expansion), so a filename like
        ``$(cmd)`` must never be interpreted by either shell; a double-quoted
        host wrapper would still expand it on the host.
        ``%n`` (filename) is included specifically so a per-path failure (an
        unreadable/deleted path writes to stderr, not stdout) can't silently
        shift every subsequent path's (mtime, size) into the wrong row.
        """
        quoted_paths = " ".join(device_shell_arg(p) for p in paths)
        return WatchlistView._adb().send_adb_command(
            f"shell stat -c {device_shell_arg('%n %Y %s')} {quoted_paths}"
        )

    @staticmethod
    def _parse_stat_output(stdout: str) -> dict[str, tuple[int, int]]:
        """Parse ``stat -c '%n %Y %s'`` lines into ``{path: (mtime, size)}``.

        Uses ``rsplit(None, 2)`` rather than a plain split so a path
        containing spaces isn't shredded -- the LAST two whitespace-
        separated tokens are always the numeric mtime/size; whatever
        precedes them is the filename (``%n``), however many spaces it has.
        """
        result: dict[str, tuple[int, int]] = {}
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.rsplit(None, 2)
            if len(parts) != 3:
                continue
            name, mtime_str, size_str = parts
            try:
                result[name] = (int(mtime_str), int(size_str))
            except ValueError:
                continue
        return result

    @staticmethod
    def _looks_like_device_error(stderr: str) -> bool:
        """True if *stderr* suggests the WHOLE batch failed (device gone),
        as opposed to a normal per-path stat error (e.g. "No such file or
        directory" for one missing path, which contains none of these).
        """
        blob = (stderr or "").lower()
        return any(pattern in blob for pattern in _DEVICE_ERROR_PATTERNS)

    @staticmethod
    def _stat_error_detail(path: str, stderr: str) -> str:
        """Best-effort per-path error line extracted from the batch's stderr."""
        for line in (stderr or "").splitlines():
            if path in line:
                return line.strip()
        return "stat failed (see logs)"

    def _apply_auto_tick_result(
        self, requested: list[str], stdout: str, stderr: str
    ) -> None:
        """Main-thread callback (via ``_post``) applying one tick's results."""
        self._auto_tick_inflight = False
        if not self._auto_enabled or self._auto_paused_reason is not None:
            return  # toggled off / already paused while the batch was in flight

        parsed = self._parse_stat_output(stdout)
        if requested and not parsed and self._looks_like_device_error(stderr):
            # The WHOLE batch came back empty AND stderr looks like a dead
            # device (not just "no such file" on one path) -- pause rather
            # than mark every row an error, per point 7 of the auto-mode spec.
            self._enter_offline_pause()
            return

        any_change = False
        dropped = False
        for path in requested:
            row = self._rows.get(path)
            if row is None:
                continue  # removed from the watchlist while the batch was in flight
            if path not in parsed and self._vanished_expansion(path, stderr):
                # A transient file a watched wildcard once matched (e.g. an
                # app's offline cache) is gone: drop it quietly instead of
                # stat-erroring on it every tick. Re-expansion re-adds it if
                # it comes back.
                self._drop_row(path)
                dropped = True
                continue
            if path not in parsed:
                # Isolated per-path failure (permission denied, gone, etc.)
                # -- mark just this row and keep polling the rest.
                row.state = RowState.ERROR
                row.detail = self._stat_error_detail(path, stderr)
                continue
            new_sig = parsed[path]
            previously_seen = row.last_seen
            row.last_seen = new_sig
            if previously_seen != new_sig:
                any_change = True
            self._evaluate_auto_pull(row, previously_seen, new_sig)

        self._advance_backoff(any_change)
        if any_change or dropped:
            # Persist the freshly-observed last_seen signatures -- gated on
            # any_change (rather than every idle tick) to avoid a disk write
            # every 5-30s while nothing on-device is actually happening.
            # last_pulled/state changes from an actual pull are already
            # persisted separately by _apply_pull_result.
            self._persist_index()
        self._rebuild_list()

    def _from_watched_pattern(self, path: str) -> bool:
        """Whether ``path`` is covered by one of the watched wildcard patterns."""
        return any(self._pattern_matches(p, path) for p in self._watched_patterns)

    def _vanished_expansion(self, path: str, stderr: str) -> bool:
        """A wildcard-expanded path whose stat says it no longer exists."""
        if not self._from_watched_pattern(path):
            return False
        return "no such file" in self._stat_error_detail(path, stderr).lower()

    def _drop_row(self, path: str) -> None:
        """Forget a vanished wildcard expansion (logged once, at DEBUG)."""
        try:
            get_forensic_service().remove_spotlight_file(path)
        except Exception:
            logger.debug("Watchlist: could not unwatch %s", path, exc_info=True)
        self._rows.pop(path, None)
        self._last_auto_pull_at.pop(path, None)
        self._auto_pull_inflight.discard(path)
        logger.debug("Watchlist: %s vanished; dropped (wildcard expansion)", path)

    def _evaluate_auto_pull(
        self,
        row: _RowInfo,
        previously_seen: tuple[int, int] | None,
        new_sig: tuple[int, int],
    ) -> None:
        """Debounce + rate-limit gate deciding whether *row* gets auto-pulled.

        "changed" (needs an eventual pull) = ``last_seen != last_pulled``.
        Never pulls immediately: the signature must be unchanged across two
        consecutive ticks (``previously_seen == new_sig``) AND a per-file
        rate limit must have elapsed since the last auto-pull -- a busy WAL
        file flips on nearly every tick and would otherwise trigger a pull
        storm. Reuses ``_start_pull`` (the exact same manual pull-and-diff
        path) rather than a separate auto-pull implementation.
        """
        if row.last_pulled == new_sig:
            return  # matches what we already have -- nothing pending
        stable = previously_seen is not None and previously_seen == new_sig
        if not stable:
            row.state = RowState.SETTLING
            row.detail = "Change detected — waiting for it to settle…"
            return
        last_pull_at = self._last_auto_pull_at.get(row.path, 0.0)
        if time.monotonic() - last_pull_at < _AUTO_PULL_MIN_INTERVAL:
            row.state = RowState.SETTLING
            row.detail = "Change detected — waiting for the pull rate limit…"
            return
        if row.path in self._auto_pull_inflight:
            return
        self._auto_pull_inflight.add(row.path)
        self._last_auto_pull_at[row.path] = time.monotonic()
        self._start_pull([row.path])

    def _advance_backoff(self, any_change: bool) -> None:
        """Adaptive backoff: reset to 5s on any change, else step up (capped)."""
        if any_change:
            if self._auto_backoff_idx != 0:
                self._auto_backoff_idx = 0
                self._reschedule_auto_timer()
            return
        if self._auto_backoff_idx < len(_AUTO_BACKOFF_STEPS) - 1:
            self._auto_backoff_idx += 1
            self._reschedule_auto_timer()

    # -- auto mode: offline pause + device-reconnect auto-resume ------------

    def _enter_offline_pause(self) -> None:
        if self._auto_paused_reason == "device offline":
            return
        self._auto_paused_reason = "device offline"
        self._cancel_auto_timer()
        self._cancel_wildcard_timer()
        self._update_header()
        self._notify(
            "Auto mode paused — device offline. Resumes automatically on reconnect.",
            "warning",
        )

    def _ensure_device_change_subscription(self) -> None:
        """Subscribe once (per widget instance) to device reconnect/disconnect.

        Registers directly on ``DeviceManager`` (via ``_device_manager()``)
        rather than through ``DeviceService.register_device_change_callback``
        -- that wrapper holds only a SINGLE callback slot and would silently
        clobber app.py's existing Frida device-change callback. DeviceManager
        itself supports multiple subscribers (a plain appended list), so this
        widget can safely add its own without disturbing that one.

        There is no unsubscribe API on ``DeviceManager.on_device_change`` (it
        never removes callbacks), so this guards with
        ``_device_change_subscribed`` to register at most once per instance
        rather than growing the list on every auto-mode toggle.
        """
        if self._device_change_subscribed:
            return
        try:
            manager = self._device_manager()
            manager.on_device_change(self._handle_device_change_event)
            self._device_change_subscribed = True
        except Exception:
            logger.debug(
                "Watchlist: could not subscribe to device changes", exc_info=True
            )

    def _handle_device_change_event(self, device) -> None:
        """``DeviceManager.on_device_change`` callback -- may fire on any
        thread (a background poll worker, the adb-track-devices monitor
        thread, etc.), so marshal to the main thread before touching any
        timer/widget state.
        """
        self._post(self._on_device_reconnect, device)

    def _on_device_reconnect(self, device) -> None:
        """Main-thread handler for a device-change event.

        ``device`` is the real ``Device`` on a (re)connect/ready transition,
        or ``None`` on disconnect (see ``DeviceManager.refresh_devices``) --
        only the non-None case resumes a paused auto-mode; a disconnect
        while already paused is a no-op (there's nothing to pause further).
        """
        if device is None:
            return
        if not self._auto_enabled or self._auto_paused_reason is None:
            return
        self._auto_paused_reason = None
        self._auto_backoff_idx = 0
        self._reschedule_auto_timer()
        self._reschedule_wildcard_timer()
        self._update_header()
        self._notify("Device reconnected — auto mode resumed.")

    # -- wildcard re-expansion (slower, decoupled ~30s cadence) --------------

    def _wildcard_tick(self) -> None:
        if not self._auto_enabled or self._auto_paused_reason is not None:
            return
        if not self._is_watchlist_visible():
            return
        if not self._watched_patterns:
            return
        if self._wildcard_tick_inflight:
            return
        self._wildcard_tick_inflight = True
        self._run_bg(
            functools.partial(
                self._wildcard_tick_worker, sorted(self._watched_patterns)
            ),
            "watchlist_wildcard_reexpand",
        )

    def _wildcard_tick_worker(self, patterns: list[str]) -> None:
        """Runs on a worker thread: re-run each pattern's expansion.

        Reuses ``ForensicService.add_spotlight_file`` unchanged -- its
        existing dedup (``_add_single_spotlight_file``) makes a repeat call
        a no-op for already-known matches, so this only ever adds files
        newly created since the pattern was last expanded.
        """
        forensic = get_forensic_service()
        any_added = False
        for pattern in patterns:
            try:
                if forensic.add_spotlight_file(pattern, adb=self._adb()):
                    any_added = True
            except Exception:
                logger.debug(
                    "Watchlist wildcard re-expansion failed for %s",
                    pattern,
                    exc_info=True,
                )
        self._post(self._apply_wildcard_tick_result, any_added)

    def _apply_wildcard_tick_result(self, any_added: bool) -> None:
        self._wildcard_tick_inflight = False
        if not any_added:
            return
        try:
            self._persist_index()
        except Exception:
            logger.debug(
                "Watchlist: failed to persist membership after wildcard re-expansion",
                exc_info=True,
            )
        self._reload_rows()
        self._notify("Watchlist: new file(s) matched a watched pattern.")

    # -- thread marshalling (mirrors DiffsView's _run_bg/_post exactly) -----

    def _run_bg(self, fn, name: str) -> None:
        """Run ``fn`` on a worker thread, or inline if no app context exists.

        The inline fallback lets pull/remove/add be exercised directly in
        unit tests without a full Textual ``Pilot`` harness, exactly like
        ``DiffsView._run_bg``.
        """
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
        """Run ``fn(*args)`` on the Textual main thread.

        Deliberately ``call_from_thread`` (blocking), not the
        ``loop.call_soon_threadsafe`` idiom the Files lens uses for its
        EventBus callbacks -- ``fn`` here posts messages and starts timers,
        which needs Textual's ``active_app`` contextvar set (the same
        pattern as ``DiffsView._post``).
        """
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


__all__ = ["RowState", "WatchlistView"]
