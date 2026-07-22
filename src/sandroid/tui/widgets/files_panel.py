"""TUI panel for the "Files" tab — unifying fsmon, the Spotlight-Files
watchlist, and Play's Changed/New/Deleted diffing under one home.

This module is the **Foundation** slice of a larger plan (see the
architecture doc this was built from): the outer tab wiring, the inner
sub-tab switcher (``Monitor | Watchlist | Diffs``), and the shared glance
strip. ``MonitorView`` (fsmon's live event stream), ``WatchlistView`` (the
Spotlight-Files watchlist's CRUD/pull/diff), and ``DiffsView`` (Play's
run-history) are all *real* implementations and live in their own modules —
``tui/widgets/monitor_view.py``, ``tui/widgets/watchlist_view.py``, and
``tui/widgets/diffs_view.py`` respectively — split out because each is
substantial and each depends on other subsystems (fsmon's EventBus stream;
``ForensicService``/``FileExtractionService``/``core/watchlist_store.py``;
``DiffView``/``core/run_history.py``). All three are imported lazily inside
``FilesPanel.compose()`` to avoid a circular import (each in turn imports
:class:`FilesSubViewBase` from this module).

Mirrors :class:`SnapshotsPanel` (visibility-gated polling via
``_is_on_screen()``) and :class:`FriTapPanel`/:class:`SpotlightPanel` (the
thread-safe EventBus idiom: capture the running loop in ``on_mount`` and
marshal callbacks with ``loop.call_soon_threadsafe`` — never
``call_from_thread``, which would deadlock a caller on a background thread).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import ContentSwitcher, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)

# Inner sub-tab clickable id -> inner ContentSwitcher child id. Routed from
# FilesPanel.on_click (mirrors MainScreen's outer-tab click routing).
_SUBTAB_TO_PANEL = {
    "files-tab-monitor": "files-monitor",
    "files-tab-watchlist": "files-watchlist",
    "files-tab-diffs": "files-diffs",
}

# Cycling order for Shift+Left/Right while the inner level is active.
_SUBTAB_ORDER = ["files-monitor", "files-watchlist", "files-diffs"]

# How often the glance strip re-renders while the Files tab is on screen.
# Cheap by design (glance_fragment() must not do I/O), so this can be quick.
_GLANCE_INTERVAL = 3.0


class FilesSubViewBase(Widget):
    """Shared base for the three Files sub-tab views (Monitor/Watchlist/Diffs).

    Each real sub-view (``MonitorView`` on fsmon, ``WatchlistView`` on the
    Spotlight-Files watchlist, ``DiffsView`` on Play's run history) overrides
    ``compose()``/``glance_fragment()`` fully; this base's own
    ``compose()``/``glance_fragment()`` only exist as a minimal, safe default
    for any *future* sub-view added before it grows real behavior — every
    current sub-view already replaces both. ``glance_fragment()`` is
    load-bearing regardless of which implementation backs it: FilesPanel's
    shared glance-strip plumbing calls it on whatever is mounted, so it must
    always return something, never raise.
    """

    can_focus = True

    DEFAULT_CSS = """
    FilesSubViewBase {
        layout: vertical;
        height: 1fr;
        background: #050811;
        padding: 0 1;
    }
    FilesSubViewBase .files-subview-placeholder {
        color: #5b6479;
    }
    """

    #: Overridden per sub-view; drives both the placeholder body text and
    #: the default glance fragment label.
    _LABEL = "Files"

    def compose(self) -> ComposeResult:
        yield Static(
            f"{self._LABEL} — coming soon",
            classes="files-subview-placeholder",
        )

    def glance_fragment(self) -> str:
        """One-line glance summary for FilesPanel's shared strip (default)."""
        return f"{self._LABEL} —"


class FilesPanel(Widget):
    """Outer "Files" tab: inner Monitor/Watchlist/Diffs switcher + glance strip.

    Owns no bindings of its own — sub-tab cycling and the active-level
    highlight are driven externally by ``MainScreen.shift_nav_level``/
    ``cycle_active_level`` (Shift+Up/Down/Left/Right), via ``cycle_subtab``/
    ``set_subtab_bar_active`` below (the duck-typed contract
    ``NetworkPanel`` also implements). See ``_ToolPanel``'s class docstring
    (``tui/screens/main_screen.py``) for the full navigation scheme.

    This frees plain ``Tab``/``Shift+Tab`` back up for normal Textual focus
    traversal inside this panel — each sub-view still stays effectively
    single-focus (arrow-key list/log navigation, matching every other panel
    in this app), so nothing inside actually relies on Tab traversal today.
    Any sub-view with its own internal focus-traversal need must use Escape
    to return focus instead of Tab. Watchlist's inline "add path" Input is
    exactly this case (see ``watchlist_view.py``'s module docstring for why
    plain Escape handling needs a small trick there, not just a BINDINGS
    entry).
    """

    can_focus = True

    DEFAULT_CSS = """
    FilesPanel {
        layout: vertical;
        height: 1fr;
        background: #080c18;
    }
    FilesPanel > #files-tabbar {
        height: 1;
        background: #0a1124;
        padding: 0 0 0 1;
    }
    FilesPanel > #files-tabbar.-level-active {
        border-bottom: solid #38bdf8;
    }
    FilesPanel .files-subtab {
        width: auto;
        padding: 0 2;
        margin: 0 1 0 0;
        color: #8f9bb3;
        background: #11203a;
    }
    FilesPanel .files-subtab:hover {
        color: #cbd5e1;
        background: #1f2937;
    }
    FilesPanel .files-subtab.-active {
        color: #06121f;
        text-style: bold;
        background: #38bdf8;
    }
    FilesPanel > #files-glance {
        height: 1;
        background: #0b1628;
        color: #93a4c3;
        padding: 0 1;
        border-bottom: solid #1f2937;
    }
    FilesPanel > #files-body {
        height: 1fr;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        self._event_handlers: list = []
        self._main_loop = None
        self._glance_timer = None

    # -- compose / mount ---------------------------------------------------

    def compose(self) -> ComposeResult:
        # Lazy import: monitor_view.py/watchlist_view.py/diffs_view.py all
        # import FilesSubViewBase from this module, so importing any of them
        # at module level here would be circular. See the module docstring.
        from .diffs_view import DiffsView
        from .monitor_view import MonitorView
        from .watchlist_view import WatchlistView

        with Horizontal(id="files-tabbar"):
            yield Static(
                "Monitor",
                id="files-tab-monitor",
                classes="files-subtab -active",
            )
            yield Static("Watchlist", id="files-tab-watchlist", classes="files-subtab")
            yield Static("Diffs", id="files-tab-diffs", classes="files-subtab")
        yield Static(self._render_glance(), id="files-glance")
        with ContentSwitcher(initial="files-monitor", id="files-body"):
            yield MonitorView(id="files-monitor")
            yield WatchlistView(id="files-watchlist")
            yield DiffsView(id="files-diffs")

    def on_mount(self) -> None:
        self._subscribe_events()
        # Visibility-gated: mirrors SnapshotsPanel's _is_on_screen()/
        # _refresh_if_visible() pattern so a hidden Files tab doesn't keep
        # re-rendering a strip nobody sees.
        self._glance_timer = self.set_interval(_GLANCE_INTERVAL, self._tick_glance)

    def on_unmount(self) -> None:
        self._unsubscribe_events()
        if self._glance_timer is not None:
            try:
                self._glance_timer.stop()
            except Exception:
                pass
            self._glance_timer = None

    # -- focus forwarding ----------------------------------------------------

    def focus(self, scroll_visible: bool = True):
        """Delegate focus to the active inner sub-view.

        ``MainScreen._select_bottom_tab`` focuses ``#files-panel`` (this
        container); forward to whichever inner sub-view is current so its
        own key handling (arrow-key list/log navigation) works immediately.
        """
        try:
            switcher = self.query_one("#files-body", ContentSwitcher)
            current = switcher.current
            if current:
                self.query_one(f"#{current}").focus(scroll_visible)
                return self
        except Exception:
            pass
        return super().focus(scroll_visible)

    # -- inner sub-tab click routing ------------------------------------

    def on_click(self, event) -> None:
        """Route clicks on the inner sub-tab bar.

        Self-contained; does not need MainScreen's help since it only ever
        switches this panel's own inner ContentSwitcher.
        """
        wid = getattr(getattr(event, "widget", None), "id", None)
        if wid in _SUBTAB_TO_PANEL:
            self._select_subtab(_SUBTAB_TO_PANEL[wid])

    def _select_subtab(self, panel_id: str) -> None:
        try:
            self.query_one("#files-body", ContentSwitcher).current = panel_id
        except Exception:
            return
        for tab_id, pid in _SUBTAB_TO_PANEL.items():
            try:
                self.query_one(f"#{tab_id}").set_class(pid == panel_id, "-active")
            except Exception:
                pass
        view = None
        try:
            view = self.query_one(f"#{panel_id}")
            view.focus()
        except Exception:
            pass
        # Give the freshly-activated sub-view a chance to refresh itself
        # (e.g. DiffsView reloading its run rail) without polling — one level
        # down from MainScreen._select_bottom_tab's own
        # refresh_snapshots()/refresh_header() activation hooks.
        if view is not None and hasattr(view, "on_activated"):
            try:
                view.on_activated()
            except Exception:
                pass
        # A freshly-activated sub-view's glance fragment may have changed
        # since the last tick; refresh immediately rather than waiting for
        # the next interval (same reasoning as MainScreen's tab-activation
        # refresh_snapshots()/refresh_header() hooks).
        self.refresh_glance()
        # Clicking a sub-tab directly is "entering" the inner level, not
        # staying at outer -- highlight this bar and tell MainScreen the
        # active level moved, without it touching this bar's class itself
        # (we just set that above).
        self.set_subtab_bar_active(True)
        try:
            self.screen.set_nav_level_inner()
        except Exception:
            pass

    def select_subtab(self, panel_id: str) -> None:
        """Public: switch to a specific inner Files sub-tab from outside.

        Used by ``MainScreen.open_files_tab(sub_tab=...)`` — Play jumping
        straight to Diffs is the "tab-switch on Play-press" half of the
        unified focus rule, which always happens. The separate, gated
        run-*selection* half lives in DiffsView.on_new_run, not here.
        """
        self._select_subtab(panel_id)

    def cycle_subtab(self, delta: int) -> None:
        """Cycle the inner sub-tab by *delta*.

        Called by ``MainScreen.cycle_active_level`` (Shift+Left/Right) while
        this panel is the current outer tab and the inner level is active.
        """
        try:
            switcher = self.query_one("#files-body", ContentSwitcher)
        except Exception:
            return
        current = switcher.current or _SUBTAB_ORDER[0]
        try:
            idx = _SUBTAB_ORDER.index(current)
        except ValueError:
            idx = 0
        self._select_subtab(_SUBTAB_ORDER[(idx + delta) % len(_SUBTAB_ORDER)])

    def set_subtab_bar_active(self, active: bool) -> None:
        """Toggle this panel's own inner tab bar highlight.

        Called by ``MainScreen.shift_nav_level`` when moving the active level
        onto/off this panel's inner bar.
        """
        try:
            self.query_one("#files-tabbar").set_class(active, "-level-active")
        except Exception:
            pass

    # -- glance strip --------------------------------------------------------
    #
    # Load-bearing plumbing for later work: Monitor/Watchlist/Diffs will each
    # grow real badges/counters, all surfaced through glance_fragment(). This
    # panel owns the actual strip Static and re-renders it from all three
    # fragments (never lets a sub-view touch the strip directly), so there is
    # exactly one re-render mechanism instead of three bespoke ones.

    def _is_on_screen(self) -> bool:
        """True if the Files tab is the shown tool-body child."""
        try:
            switcher = self.screen.query_one("#tool-body", ContentSwitcher)
            return switcher.current == "files-panel"
        except Exception:
            return False

    def _tick_glance(self) -> None:
        """Interval tick (main thread): no-op unless the Files tab is on screen."""
        if not self._is_on_screen():
            return
        self.refresh_glance()

    def _render_glance(self) -> str:
        fragments = []
        for sub_id in _SUBTAB_ORDER:
            frag = "—"
            try:
                view = self.query_one(f"#{sub_id}")
                frag = view.glance_fragment()
            except Exception:
                pass
            fragments.append(frag)
        return "  ·  ".join(fragments)

    def refresh_glance(self) -> None:
        """Re-render the glance strip (main thread; best-effort).

        Public so the EventBus callbacks, the interval tick, and
        MainScreen's tab-activation hook can all share one code path.
        """
        try:
            self.query_one("#files-glance", Static).update(self._render_glance())
        except Exception:
            pass

    # -- EventBus wiring (non-blocking, thread-safe) ------------------------

    def _subscribe_events(self) -> None:
        try:
            import asyncio

            from sandroid.core.events import EventBus, EventType

            try:
                self._main_loop = asyncio.get_running_loop()
            except RuntimeError:
                self._main_loop = None

            bus = EventBus.get()

            def _make_cb():
                def _cb(_event) -> None:
                    # Fire-and-forget onto the main loop; never blocks the
                    # publisher's thread (avoids the call_from_thread
                    # deadlock — see FriTapPanel/SnapshotsPanel for the same
                    # idiom). Un-gated by visibility: glance_fragment() is
                    # cheap (no I/O), unlike the slow polls elsewhere in
                    # this app, so refreshing a hidden strip is harmless.
                    loop = self._main_loop
                    try:
                        if loop is not None and not loop.is_closed():
                            loop.call_soon_threadsafe(self.refresh_glance)
                    except RuntimeError:
                        pass

                return _cb

            for event_type in (EventType.TASK_STARTED, EventType.TASK_STOPPED):
                cb = _make_cb()
                bus.subscribe(event_type, cb)
                self._event_handlers.append((event_type, cb))
        except Exception as exc:
            logger.debug(f"FilesPanel event subscribe failed: {exc}")

    def _unsubscribe_events(self) -> None:
        try:
            from sandroid.core.events import EventBus

            bus = EventBus.get()
            for event_type, cb in self._event_handlers:
                bus.unsubscribe(event_type, cb)
        except Exception:
            pass
        self._event_handlers = []
