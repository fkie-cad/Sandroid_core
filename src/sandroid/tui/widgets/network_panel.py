"""TUI panel for the "Network" tab — consolidating the existing Mitmproxy and
friTap tool tabs under one home.

Purely organizational, the same way :class:`~sandroid.tui.widgets.files_panel.
FilesPanel` already groups three mechanistically unrelated sub-tabs (a live
log tail, a list, a diff viewer) under one tab just because they're all "file
activity" from a user's point of view. This groups the existing
``MitmproxyPanel`` (hosts an actual ``mitmweb`` subprocess) and ``FriTapPanel``
(no subprocess — Frida-based in-process TLS hooking) as "traffic-interception
tools" without requiring any shared plumbing between them; both are wrapped
**verbatim**, unchanged — they already use depth-agnostic ``self.query_one``/
``self.screen.query_one`` and self-scoped CSS selectors, so reparenting them
one level deeper needs zero internal changes.

Mirrors ``FilesPanel``'s two-level outer-tab/inner-sub-tab-bar structure
(module-level ``_SUBTAB_TO_PANEL``/``_SUBTAB_ORDER``, an inner tab bar +
``ContentSwitcher``, ``on_click``/``_select_subtab``/``select_subtab``/
``focus()`` delegation, ``cycle_subtab``, ``set_subtab_bar_active``) — see
that module's docstring, and ``_ToolPanel``'s class docstring
(``tui/screens/main_screen.py``), for the shared Shift+Arrow level-navigation
scheme this panel participates in (``MainScreen.shift_nav_level``/
``cycle_active_level``).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import ContentSwitcher, Static

from sandroid.tui.widgets.fritap_panel import FriTapPanel
from sandroid.tui.widgets.mitmproxy_panel import MitmproxyPanel

if TYPE_CHECKING:
    from textual.app import ComposeResult

logger = logging.getLogger(__name__)

# Inner sub-tab clickable id -> inner ContentSwitcher child id. Routed from
# NetworkPanel.on_click (mirrors FilesPanel's own inner-tab click routing).
_SUBTAB_TO_PANEL = {
    "network-tab-mitm": "mitm-panel",
    "network-tab-fritap": "fritap-panel",
}

# Cycling order for Shift+Left/Right while the inner level is active.
_SUBTAB_ORDER = ["mitm-panel", "fritap-panel"]


class NetworkPanel(Widget):
    """Outer "Network" tab: inner Mitmproxy/friTap switcher.

    Owns no bindings of its own — sub-tab cycling and the active-level
    highlight are driven externally by ``MainScreen.shift_nav_level``/
    ``cycle_active_level`` (Shift+Up/Down/Left/Right), through the same
    duck-typed ``cycle_subtab``/``set_subtab_bar_active`` contract
    ``FilesPanel`` implements. See ``_ToolPanel``'s class docstring
    (``tui/screens/main_screen.py``) for the full navigation scheme.
    """

    can_focus = True

    DEFAULT_CSS = """
    NetworkPanel {
        layout: vertical;
        height: 1fr;
        background: #080c18;
    }
    NetworkPanel > #network-tabbar {
        height: 1;
        background: #0a1124;
        padding: 0 0 0 1;
        /* Always reserve the left-border column (colored to match the
           background, so it's invisible) -- switching only the color
           in -level-active below avoids any width shift on toggle. */
        border-left: heavy #0a1124;
    }
    NetworkPanel > #network-tabbar.-level-active {
        border-left: heavy #38bdf8;
    }
    NetworkPanel .network-subtab {
        width: auto;
        padding: 0 2;
        margin: 0 1 0 0;
        color: #8f9bb3;
        background: #11203a;
    }
    NetworkPanel .network-subtab:hover {
        color: #cbd5e1;
        background: #1f2937;
    }
    NetworkPanel .network-subtab.-active {
        color: #06121f;
        text-style: bold;
        background: #38bdf8;
    }
    NetworkPanel > #network-body {
        height: 1fr;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True

    # -- compose ------------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Horizontal(id="network-tabbar"):
            yield Static(
                "Mitmproxy",
                id="network-tab-mitm",
                classes="network-subtab -active",
            )
            yield Static("friTap", id="network-tab-fritap", classes="network-subtab")
        with ContentSwitcher(initial="mitm-panel", id="network-body"):
            yield MitmproxyPanel(id="mitm-panel")
            yield FriTapPanel(id="fritap-panel")

    # -- focus forwarding -----------------------------------------------------

    def focus(self, scroll_visible: bool = True):
        """Delegate focus to the active inner sub-view.

        ``MainScreen._select_bottom_tab`` focuses ``#network-panel`` (this
        container); forward to whichever inner sub-view is current so its own
        key handling (Enter to start/stop, Ctrl+D/N/R/O/A/P/L/V, ...) works
        immediately. Mirrors ``FilesPanel.focus()``.
        """
        try:
            switcher = self.query_one("#network-body", ContentSwitcher)
            current = switcher.current
            if current:
                self.query_one(f"#{current}").focus(scroll_visible)
                return self
        except Exception:
            pass
        return super().focus(scroll_visible)

    # -- inner sub-tab click routing -------------------------------------

    def on_click(self, event) -> None:
        """Route clicks on the inner sub-tab bar.

        Self-contained; does not need MainScreen's help since it only ever
        switches this panel's own inner ContentSwitcher. Mirrors
        ``FilesPanel.on_click``.
        """
        wid = getattr(getattr(event, "widget", None), "id", None)
        if wid in _SUBTAB_TO_PANEL:
            self._select_subtab(_SUBTAB_TO_PANEL[wid])

    def _select_subtab(self, panel_id: str) -> None:
        try:
            self.query_one("#network-body", ContentSwitcher).current = panel_id
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
        # Forward to the freshly-activated child directly -- covers the case
        # where the sub-tab itself just changed, belt-and-suspenders with
        # NetworkPanel.refresh_header() below (which covers every OTHER
        # activation path). Mirrors FilesPanel._select_subtab's on_activated()
        # forwarding, using refresh_header as the relevant hook here since
        # neither MitmproxyPanel nor FriTapPanel implement on_activated.
        if view is not None and hasattr(view, "refresh_header"):
            try:
                view.refresh_header()
            except Exception:
                pass
        # Clicking a sub-tab directly is "entering" the inner level, not
        # staying at outer -- mirrors FilesPanel._select_subtab.
        self.set_subtab_bar_active(True)
        try:
            self.screen.set_nav_level_inner()
        except Exception:
            pass

    def select_subtab(self, panel_id: str) -> None:
        """Public: switch to a specific inner Network sub-tab from outside.

        Used by ``MainScreen.open_fritap_tab()`` — the ``h`` key jumping
        straight to friTap, mirroring ``FilesPanel.select_subtab``.
        """
        self._select_subtab(panel_id)

    # -- level-aware cycling (Feature A duck-typed contract) -----------------

    def cycle_subtab(self, delta: int) -> None:
        """Cycle the inner sub-tab by *delta*.

        Called by ``MainScreen.cycle_active_level`` (Shift+Left/Right) while
        this panel is the current outer tab and the inner level is active.
        Mirrors ``FilesPanel.cycle_subtab``.
        """
        try:
            switcher = self.query_one("#network-body", ContentSwitcher)
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
        onto/off this panel's inner bar. Mirrors
        ``FilesPanel.set_subtab_bar_active``.
        """
        try:
            self.query_one("#network-tabbar").set_class(active, "-level-active")
        except Exception:
            pass

    # -- header staleness fix -------------------------------------------------

    def refresh_header(self) -> None:
        """Forward to the current inner child's own ``refresh_header``, if any.

        Closes a real header-staleness gap found during verification:
        ``MainScreen._select_bottom_tab``'s generic
        ``hasattr(panel_widget, "refresh_header")`` hook only finds a method
        living directly on whatever ``#tool-body`` just switched to. Once
        friTap is nested inside this panel, that widget is ``NetworkPanel``,
        not ``FriTapPanel`` — so without this method, any activation path
        that does NOT go through ``_select_subtab`` (e.g. a bare click
        directly on the outer "Network" tab label while friTap is already
        the current inner sub-tab) would leave the friTap header stale
        exactly the way ``FriTapPanel.refresh_header()`` was built to
        prevent. ``MitmproxyPanel`` has no public ``refresh_header`` (it
        keeps its header live via its own event wiring), so the ``hasattr``
        guard below is a harmless no-op while Mitmproxy is the current
        sub-tab.
        """
        try:
            current = self.query_one("#network-body", ContentSwitcher).current
            view = self.query_one(f"#{current}")
            if hasattr(view, "refresh_header"):
                view.refresh_header()
        except Exception:
            pass
