"""Watchlist sub-tab: the Spotlight-Files CRUD/pull/diff replacement for
``SpotlightFilesModal``.

Lists ``ForensicService``'s spotlight-file watchlist in an ``OptionList``,
with an always-visible inline ``Input`` (never a modal) for adding new
paths/wildcard patterns, row actions to remove/pull, and — new behavior the
old modal never had — every pull now diffs the fresh copy against whatever
was pulled last time for that path, rendered inline via the shared
:class:`~sandroid.tui.widgets.diff_view.DiffView`.

**Naming note** (also in ``spotlight_controller.py``): "Spotlight" is
overloaded in this codebase. This view is about the *forensic* Spotlight
Files watchlist (``ForensicService._spotlight_files``, this module) — it is
unrelated to the *Frida* spotlight app-under-test
(``spotlight_panel.py``/``SpotlightService``, keys ``c``/``Shift+C``).

**Inline "add path" Input and Escape** (the one real gotcha in this view):
Textual's App-level ``escape`` binding (``priority=True``, wired to
``QuitController.maybe_quit``) is checked *before* any descendant's own
bindings, and ``QuitController.maybe_quit`` shows the quit-confirmation
unconditionally whenever the current screen is ``MainScreen`` (see
``quit_controller.py``'s ``_is_main_screen()`` check) — it does not look at
what's focused. A plain ``Input`` living directly on ``MainScreen`` (as this
one does; it's not inside a modal) would therefore have Escape hijacked by
the quit-confirmation instead of blurring the input, exactly the opposite
of what the plan asks for ("Escape closes/cancels the input and returns
focus to the list").

The fix (verified empirically against Textual's actual dispatch order, not
assumed — see ``_AddPathInput`` below): a widget that overrides
``check_consume_key`` to also claim ``"escape"`` (Input's default only
claims printable characters) gets that key filtered out of *every*
ancestor's binding map for that keypress, including the App's — this is the
exact same mechanism that already lets a focused Input "eat" a bound letter
key so typing doesn't also trigger some ancestor's shortcut. Once the
priority phase finds nothing, the key is forwarded to the focused widget's
own (non-priority) ``BINDINGS``, which are never filtered from the widget's
*own* map. So ``_AddPathInput`` declares its own non-priority ``escape``
binding and handles it itself — cleanly intercepting Escape while it has
focus, without touching any global app code. This is independent of plain
Tab, which is unclaimed at the ``FilesPanel`` level (sub-tab cycling is
driven externally via Shift+Left/Right, not Tab — see ``FilesPanel``'s class
docstring) and would blur this Input via normal focus traversal regardless;
Escape is needed here specifically for the App-level priority-escape hijack
described above, not as a substitute for Tab.

Key scoping note (same non-priority-binding-on-a-focused-ancestor mechanism
``SnapshotsPanel``/``DiffsView`` already use elsewhere in this app): ``d``
(remove), ``p``/``P`` (pull one/all) shadow the GLOBAL ``d``=Dump Memory and
``p``=Play bindings only while this view has focus — SnapshotsPanel already
shadows ``d`` for its own delete action, so this isn't a new precedent.
``n`` (focus the add-input) shadows the global ``n``=Install APK binding,
the same precedent DiffsView already uses for its own (differently-meaning)
``n``=rename. ``a`` (toggle auto-mode, see below) shadows the global
``a``=Analyze (``app.py``'s ``static_analysis`` binding,
``Binding("a", ..., id="static_analysis")``) the same way — Analyze is
irrelevant while Watchlist has focus, so this is the same already-
established, previously-verified-safe kind of shadow as ``d``/``p``/``n``
above, not a new one.

**Auto mode** (``a`` key, off by default; header badge ``auto ○ off`` /
``auto ● on · every Ns``): a visibility-gated ``set_interval`` poll mirrors
``SnapshotsPanel``'s ``_is_on_screen()``/``_refresh_if_visible()`` pattern,
extended one ``ContentSwitcher`` level deeper for the Files tab's own inner
switcher (see ``_is_watchlist_visible``) — it only does real work while the
Files tab is the active outer tab AND Watchlist is the active inner
sub-view. Each tick issues one batched
``adb shell "stat -c '%n %Y %s' <path>..."`` call (see ``_stat_command``)
covering every watched path, keyed back to the right row by the ``%n``
(filename) field so one bad path's stderr text can't misalign the batch.
Two signatures per path — ``last_seen`` (updated every tick) vs
``last_pulled`` (updated only on an actual pull) — define "changed"
(``last_seen != last_pulled``); ``_evaluate_auto_pull`` debounces (the
signature must be unchanged across two consecutive ticks) and rate-limits
(a per-file minimum interval) before triggering the real pull, which reuses
the exact same ``_start_pull``/``_pull_worker``/``_apply_pull_result`` path
the manual ``p``/``P`` actions already use — no separate pull-and-diff
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

import functools
import logging
import os
import shlex
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import ContentSwitcher, Input, OptionList, Static
from textual.widgets.option_list import Option

from sandroid.core import file_diff, watchlist_store
from sandroid.services import get_file_extraction_service, get_forensic_service
from sandroid.services.file_extraction_service import is_sqlite_file

from .diff_view import DiffView
from .files_panel import FilesSubViewBase

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

#: id used for the OptionList's single disabled placeholder row when the
#: watchlist is empty -- never a real path, so selection handlers can
#: cheaply ignore it (mirrors DiffsView's ``_EMPTY_OPTION_ID``).
_EMPTY_OPTION_ID = "__no_paths__"

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
#: semantic palette (see fsmon_controller.FSMON_EVENT_INFO / diffs_view.py's
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


def _compute_diff(previous_main: Path, current_main: Path) -> tuple[str, bool]:
    """Diff *current_main* against *previous_main*.

    Uses the SAME extension/magic-header dispatch
    ``ChangedFiles.return_data()`` uses (``core/changedfiles.py``):
    ``is_sqlite_file`` -> ``db_diff``, ``.xml`` -> ``xml_diff``. Deliberately
    **widened** from that dispatch's ``.txt``-only text fallback to *any*
    other file (via the new ``file_diff.txt_diff_paths``) -- curated
    Watchlist paths are frequently extension-less config/log files, and
    ChangedFiles' own "no dispatch match -> no diff at all" behavior would
    make the diffing feature nearly useless for exactly the files people are
    most likely to hand-add here. This is the one deliberate deviation from
    a literal reading of "the SAME dispatch logic".

    Also deliberately uses ``file_extraction_service.is_sqlite_file`` (a
    plain, uncached magic-header read) rather than ``file_diff.is_sqlite_file``:
    that module keeps a process-lifetime cache keyed by path string with no
    invalidation, which is safe for ``ChangedFiles``' one-shot-per-Play
    timestamped pull directories but NOT for Watchlist's fixed
    ``current``/``previous`` paths, which get overwritten on every manual
    pull -- a cached answer from pull #1 would silently outlive whatever
    pull #2 actually wrote to that same path.

    Returns:
        ``(diff_text, changed)`` -- ``changed`` is False when the
        underlying diff function reports "no change(s)" in its own words
        (its established convention), so the caller can show a plain
        "unchanged" message instead of an empty/no-op ``DiffView``.
    """
    prev_str, cur_str = str(previous_main), str(current_main)
    if is_sqlite_file(prev_str):
        diff = file_diff.db_diff(prev_str, cur_str, "")
    elif previous_main.suffix.lower() == ".xml":
        diff = file_diff.xml_diff(prev_str, cur_str, "")
    else:
        diff = file_diff.txt_diff_paths(prev_str, cur_str)
    changed = bool(diff.strip()) and "no change" not in diff.lower()
    return diff, changed


class _AddPathInput(Input):
    """Inline "add a watched path" input -- see module docstring for why
    Escape needs special handling here instead of a WatchlistView-level
    binding.
    """

    BINDINGS = [Binding("escape", "cancel_input", "Cancel", show=False)]

    def check_consume_key(self, key: str, character: str | None) -> bool:
        if key == "escape":
            return True
        return super().check_consume_key(key, character)

    def action_cancel_input(self) -> None:
        self.value = ""
        try:
            self.screen.query_one("#watchlist-list", OptionList).focus()
        except Exception:
            pass


class WatchlistView(FilesSubViewBase):
    """Files tab sub-view: Spotlight-Files watchlist CRUD + pull/diff.

    Bindings (when the list has focus):
        d: remove the selected path (shadows global ``d``=Dump Memory --
           see module docstring; SnapshotsPanel already shadows this key).
        p: pull the selected path and diff it against its stored baseline
           (shadows global ``p``=Play while this view has focus).
        P: pull every watched path (Shift+P).
        n: focus the inline add-path input (shadows global ``n``=Install
           APK, the same precedent DiffsView already uses for ``n``=rename).
        a: toggle auto-mode (shadows global ``a``=Analyze while this view
           has focus -- see module docstring's Auto mode section).
    """

    _LABEL = "Watchlist"

    can_focus = True

    BINDINGS = [
        ("d", "remove_selected", "Remove"),
        ("p", "pull_selected", "Pull"),
        ("P", "pull_all", "Pull all"),
        ("n", "focus_add", "Add path"),
        ("a", "toggle_auto", "Auto mode"),
    ]

    DEFAULT_CSS = """
    WatchlistView {
        layout: vertical;
        padding: 0;
    }
    WatchlistView #watchlist-header {
        height: 1;
        color: #93a4c3;
        padding: 0 1;
    }
    WatchlistView #watchlist-list {
        height: 10;
        background: #050811;
        border-bottom: solid #1f2937;
    }
    WatchlistView #watchlist-scroll {
        height: 1fr;
        padding: 0 1;
    }
    WatchlistView #watchlist-add-row {
        height: 3;
        border-top: solid #1f2937;
        padding: 0 1;
    }
    WatchlistView #watchlist-add-label {
        width: 6;
        padding: 1 1 0 0;
        color: #8f9bb3;
    }
    WatchlistView #watchlist-add-input {
        width: 1fr;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        #: path -> _RowInfo, keyed the same way ForensicService keys them
        #: (the literal device path/already-expanded wildcard match).
        self._rows: dict[str, _RowInfo] = {}
        self._selected_path: str | None = None

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
        #: pulls via p/P don't touch this -- only auto-mode is rate-limited).
        self._last_auto_pull_at: dict[str, float] = {}
        #: paths with an auto-triggered pull currently in flight, so a
        #: still-settling path already mid-pull isn't re-triggered.
        self._auto_pull_inflight: set[str] = set()

        # -- wildcard re-expansion state (slower, decoupled timer) --------
        #: Patterns (containing "*") the user has added via the inline
        #: input. ForensicService only keeps the already-expanded literal
        #: matches (see _add_spotlight_files_by_pattern) -- the pattern
        #: string itself is otherwise discarded after the first expansion,
        #: so this view has to remember it to re-run expansion later.
        self._watched_patterns: set[str] = set()
        self._wildcard_timer = None
        self._wildcard_tick_inflight: bool = False

        # -- device-reconnect subscription (auto-resume after offline) ----
        self._device_change_subscribed: bool = False

    # -- compose / mount ---------------------------------------------------

    def compose(self):
        yield Static(self._render_header(), id="watchlist-header")
        yield OptionList(id="watchlist-list")
        with VerticalScroll(id="watchlist-scroll"):
            yield Static("[dim]No path selected.[/dim]", id="watchlist-empty")
        with Horizontal(id="watchlist-add-row"):
            yield Static("Add:", id="watchlist-add-label")
            yield _AddPathInput(
                placeholder="/data/data/<pkg>/databases/*  (Enter=add · Esc=back to list)",
                id="watchlist-add-input",
            )

    def on_mount(self) -> None:
        try:
            get_forensic_service().load_watchlist_index()
        except Exception:
            logger.debug(
                "Watchlist: failed to load persisted membership", exc_info=True
            )
        self._restore_persisted_rows()
        self._reload_rows()

    def on_unmount(self) -> None:
        # Auto mode is off by default and only starts timers when the user
        # toggles it on (see _start_auto_mode) -- this is defensive cleanup
        # mirroring SnapshotsPanel/FilesPanel's on_unmount, not undoing work
        # that unconditionally happened on mount.
        self._cancel_auto_timer()
        self._cancel_wildcard_timer()

    # -- focus forwarding ----------------------------------------------------

    def focus(self, scroll_visible: bool = True):
        """Delegate focus to the list, or the add-input when empty.

        Mirrors the old ``SpotlightFilesModal``'s own on-mount focus choice
        (list when there's something to select, the add field otherwise).
        """
        try:
            if self._rows:
                self.query_one("#watchlist-list", OptionList).focus(scroll_visible)
            else:
                self.query_one("#watchlist-add-input", Input).focus(scroll_visible)
            return self
        except Exception:
            pass
        return super().focus(scroll_visible)

    # -- FilesPanel hooks ----------------------------------------------------

    def on_activated(self) -> None:
        """Called by ``FilesPanel._select_subtab`` when Watchlist becomes active."""
        self._reload_rows()

    def glance_fragment(self) -> str:
        total = len(self._rows)
        if total == 0:
            base = "Watchlist — no paths"
        else:
            changed = sum(1 for r in self._rows.values() if r.state is RowState.CHANGED)
            if changed:
                # "changed" is a past-participle/adjective here (as many rows
                # ARE changed), not a countable noun -- it never takes an "s"
                # regardless of count (matches _render_header's phrasing).
                base = f"Watchlist — {total} path(s) · {changed} changed"
            else:
                base = f"Watchlist — {total} path(s)"
        if self._auto_enabled:
            if self._auto_paused_reason:
                return f"{base} · auto paused ({self._auto_paused_reason})"
            return f"{base} · auto on"
        return base

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
            self._rows[path] = _RowInfo(
                path=path,
                state=state,
                detail=payload.get("detail") or "",
                last_seen=tuple(last_seen) if last_seen else None,
                last_pulled=tuple(last_pulled) if last_pulled else None,
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
            row_states=self._row_states_payload(), auto_enabled=self._auto_enabled
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

    def _current_path(self) -> str | None:
        try:
            option_list = self.query_one("#watchlist-list", OptionList)
            idx = option_list.highlighted
            if idx is None:
                return None
            option = option_list.get_option_at_index(idx)
            if option is None or option.id == _EMPTY_OPTION_ID:
                return None
            return option.id
        except Exception:
            return None

    # -- rail/list rendering --------------------------------------------------

    def _row_label(self, path: str) -> str:
        info = self._rows.get(path)
        state = info.state if info else RowState.NEVER_PULLED
        glyph, color = _GLYPH[state]
        display = path
        if len(display) > 62:
            display = "…" + display[-61:]
        detail = info.detail if info else ""
        suffix = f"  [dim]{detail}[/dim]" if detail else ""
        return f"[{color}]{glyph}[/{color}] {display}{suffix}"

    def _rebuild_list(self) -> None:
        try:
            option_list = self.query_one("#watchlist-list", OptionList)
        except Exception:
            return
        previously_selected = self._selected_path
        option_list.clear_options()
        paths = sorted(self._rows)
        if not paths:
            option_list.add_option(
                Option(
                    "[dim]No paths watched yet — add one below[/dim]",
                    id=_EMPTY_OPTION_ID,
                )
            )
        else:
            for path in paths:
                option_list.add_option(Option(self._row_label(path), id=path))
        if previously_selected in self._rows:
            try:
                option_list.highlighted = paths.index(previously_selected)
            except Exception:
                pass
        self._update_header()

    def _update_header(self) -> None:
        try:
            self.query_one("#watchlist-header", Static).update(self._render_header())
        except Exception:
            pass

    def _render_header(self) -> str:
        hint = "[dim]p=pull  P=pull all  d=remove  n=add path  a=auto[/dim]"
        badge = self._auto_badge()
        total = len(self._rows)
        if total == 0:
            return f"No paths watched yet.   {badge}   {hint}"
        summary = f"{total} path(s) watched"
        changed = sum(1 for r in self._rows.values() if r.state is RowState.CHANGED)
        if changed:
            summary += f"  ·  [#facc15]{changed} changed[/]"
        return f"{summary}   {badge}   {hint}"

    def _auto_badge(self) -> str:
        """Auto-mode status badge shown in the header (see module docstring)."""
        if not self._auto_enabled:
            return "[dim]auto ○ off[/dim]"
        if self._auto_paused_reason:
            return f"[#fb7185]auto ● on ({self._auto_paused_reason})[/]"
        return f"[#4ade80]auto ● on[/] · every {int(self._auto_interval)}s"

    # -- detail rendering --------------------------------------------------

    def _render_detail(self, path: str | None) -> None:
        try:
            scroll = self.query_one("#watchlist-scroll", VerticalScroll)
        except Exception:
            return
        scroll.remove_children()
        if path is None:
            scroll.mount(Static("[dim]No path selected.[/dim]"))
            return
        info = self._rows.get(path)
        if info is None or info.state == RowState.NEVER_PULLED:
            scroll.mount(
                Static(f"[b]{path}[/b]\n[dim]Never pulled — press p to pull.[/dim]")
            )
            return
        if info.state == RowState.CHANGED and info.diff_text is not None:
            scroll.mount(Static(f"[b]{path}[/b]"))
            scroll.mount(DiffView(diff=info.diff_text, title=path, start_expanded=True))
            return
        scroll.mount(Static(f"[b]{path}[/b]\n{info.detail}"))

    # -- OptionList events ----------------------------------------------------

    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted
    ) -> None:
        if event.option_list.id != "watchlist-list":
            return
        path = event.option_id
        if not path or path == _EMPTY_OPTION_ID:
            self._selected_path = None
            self._render_detail(None)
            return
        self._selected_path = path
        self._render_detail(path)

    # -- Input events ----------------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "watchlist-add-input":
            return
        path = event.value.strip()
        if not path:
            return
        self._add_path(path)
        event.input.value = ""

    # -- add / remove -----------------------------------------------------

    def _add_path(self, path: str) -> None:
        forensic = get_forensic_service()
        # add_spotlight_file() itself branches on "*" to expand wildcards
        # (_add_spotlight_files_by_pattern) -- reused as-is; passing an adb
        # instance is harmless for the plain, non-wildcard path too, since
        # that branch never touches it.
        added = forensic.add_spotlight_file(path, adb=self._adb())
        if not added:
            self._notify(f"Already watching, invalid, or no matches: {path}", "warning")
            return
        if "*" in path:
            # ForensicService only keeps the already-expanded literal matches
            # (see _add_spotlight_files_by_pattern) -- the pattern string
            # itself would otherwise be lost, so remember it here for
            # auto-mode's wildcard re-expansion timer (see module docstring).
            self._watched_patterns.add(path)
        self._persist_index()
        self._reload_rows()
        self._notify(f"Added to watchlist: {path}")

    def action_remove_selected(self) -> None:
        path = self._current_path()
        if not path:
            self._notify("No path selected to remove.", "warning")
            return
        forensic = get_forensic_service()
        if not forensic.remove_spotlight_file(path):
            return
        self._persist_index()
        self._rows.pop(path, None)
        # Best-effort cleanup of auto-mode's per-path bookkeeping -- not
        # load-bearing (an unknown path in these dicts is harmless), just
        # avoids unbounded growth across many add/remove cycles in one
        # long-lived session.
        self._last_auto_pull_at.pop(path, None)
        self._auto_pull_inflight.discard(path)
        if self._selected_path == path:
            self._selected_path = None
        self._reload_rows()
        self._render_detail(self._selected_path)
        self._notify(f"Removed from watchlist: {path}")

    def action_focus_add(self) -> None:
        try:
            self.query_one("#watchlist-add-input", Input).focus()
        except Exception:
            pass

    # -- pull / diff --------------------------------------------------------

    def action_pull_selected(self) -> None:
        path = self._current_path()
        if not path:
            self._notify("No path selected to pull.", "warning")
            return
        self._start_pull([path])

    def action_pull_all(self) -> None:
        paths = sorted(self._rows)
        if not paths:
            self._notify("No paths to pull.", "warning")
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

        if not had_previous:
            detail = self._baseline_message(current)
            watchlist_store.promote(path)
            self._post(
                self._apply_pull_result, path, RowState.BASELINE_ONLY, detail, None
            )
            return

        previous_main = watchlist_store.previous_dir(path) / basename
        diff_text, changed = _compute_diff(previous_main, current_main)
        watchlist_store.promote(path)
        if changed:
            self._post(self._apply_pull_result, path, RowState.CHANGED, None, diff_text)
        else:
            self._post(
                self._apply_pull_result,
                path,
                RowState.UNCHANGED,
                "No changes since last pull.",
                None,
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
        self._persist_index()
        self._rebuild_list()
        if path == self._selected_path:
            self._render_detail(path)

    # -- auto mode: visibility, toggle, timer lifecycle ---------------------
    #
    # See the module docstring's "Auto mode" section for the full design.
    # Off by default; `a` toggles it (a focus-scoped shadow of the global
    # `a`=Analyze binding, the same established precedent as d/p/n above).

    def _is_watchlist_visible(self) -> bool:
        """True only while the Files tab is on screen AND Watchlist is its
        active inner sub-view.

        Mirrors SnapshotsPanel's ``_is_on_screen()``, extended one
        ``ContentSwitcher`` level deeper for the Files tab's own inner
        switcher. Uses ``self.screen.query_one`` (not ``self.app.query_one``)
        -- widgets must reach ancestors via the screen, not the app's default
        screen, to avoid a silent ``NoMatches`` (see FilesPanel/SnapshotsPanel
        for the same convention).
        """
        try:
            outer = self.screen.query_one("#tool-body", ContentSwitcher)
            if outer.current != "files-panel":
                return False
            inner = self.screen.query_one("#files-body", ContentSwitcher)
            return inner.current == "files-watchlist"
        except Exception:
            return False

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

        QUOTING: the same ``shell "..."`` wrapping ``proxy_manager.py``'s
        ``_device_tcp_reachable``/``mitmproxy_service.py`` already use.
        ``Adb.send_adb_command`` runs the whole string through the HOST
        shell (``shell=True``), which would otherwise split
        ``'%n %Y %s'`` back into three bare words before ``adb`` ever sees
        them. Wrapping the entire remote command in one double-quoted
        argument makes the host shell hand it to ``adb`` intact, for the
        DEVICE's shell to interpret the inner single quotes correctly.
        ``%n`` (filename) is included specifically so a per-path failure (an
        unreadable/deleted path writes to stderr, not stdout) can't silently
        shift every subsequent path's (mtime, size) into the wrong row.
        """
        quoted_paths = " ".join(shlex.quote(p) for p in paths)
        inner = f"stat -c '%n %Y %s' {quoted_paths}"
        return WatchlistView._adb().send_adb_command(f'shell "{inner}"')

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
        for path in requested:
            row = self._rows.get(path)
            if row is None:
                continue  # removed from the watchlist while the batch was in flight
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
        if any_change:
            # Persist the freshly-observed last_seen signatures -- gated on
            # any_change (rather than every idle tick) to avoid a disk write
            # every 5-30s while nothing on-device is actually happening.
            # last_pulled/state changes from an actual pull are already
            # persisted separately by _apply_pull_result.
            self._persist_index()
        self._rebuild_list()
        if self._selected_path:
            self._render_detail(self._selected_path)

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
            "Auto mode paused — device offline. Resumes automatically " "on reconnect.",
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
                "Watchlist: failed to persist membership after "
                "wildcard re-expansion",
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
        ``loop.call_soon_threadsafe`` idiom ``FilesPanel``/``MonitorView``
        use for their EventBus callbacks -- ``fn`` here mounts brand-new
        widgets (``DiffView``), which needs Textual's ``active_app``
        contextvar set. See ``DiffsView._post``'s docstring for the full
        reasoning; this is the identical pattern for the identical reason.
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
