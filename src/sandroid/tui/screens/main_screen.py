"""Main screen for Sandroid TUI: the "Lenses + Inspector" shell.

The layout pieces and the contract lens authors rely on (lens registry,
Enter→Inspector hook, scope, badges, log drawer) are documented in
``sandroid.tui.widgets.lens_shell``'s module docstring.
"""

import logging
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import ContentSwitcher, DataTable, OptionList, Static

from sandroid.core.menu_controller import MenuController
from sandroid.services import get_frida_session_service, get_ui_service
from sandroid.tui.key_display import key_words
from sandroid.tui.widgets import (
    ActivityLog,
    FilesPanel,
    NetworkPanel,
    SandroidFooter,
    SpotlightPanel,
    StatusBar,
    load_chat_panel_class,
)
from sandroid.tui.widgets.diffs_view import DiffsView
from sandroid.tui.widgets.identity_lens import IdentityLens
from sandroid.tui.widgets.lens_shell import (
    LENS_BY_ID,
    LENS_BY_WIDGET,
    LENSES,
    Inspector,
    InspectorContent,
    LensBar,
    LogDrawer,
    LogTicker,
    Mark,
    MarksChanged,
    ScopeChanged,
    SessionMarks,
    ShellHeader,
)
from sandroid.tui.widgets.timeline_lens import (
    TimelineLens,
    label_event_text,
    timeline_service,
)

if TYPE_CHECKING:
    from sandroid.core.actionQ import ActionQ

logger = logging.getLogger(__name__)

#: Task sources whose TASK_OUTPUT events must NOT reach Background Activity
#: because they already have their own dedicated display surface (monitor's
#: output is folded into the Files lens table -- see ``tui/widgets/files_panel.py``
#: and ``tui/widgets/monitor_view.py``). A frozenset (not a bare equality check)
#: makes this rule explicit and extensible to future dedicated-tab tools.
#: Lifecycle notices (TASK_STARTED/TASK_STOPPED) are NOT filtered -- only
#: TASK_OUTPUT, so monitor's start/stop still appears in Background Activity.
_ACTIVITY_LOG_EXCLUDED_SOURCES = frozenset({"monitor"})

#: Legacy ``open_files_tab(sub_tab=...)`` targets that now live in their own
#: lens (the former Files → Diffs sub-tab is the Runs lens).
_SUBTAB_TO_LENS = {"files-diffs": "runs"}


class _LensHost(Vertical):
    """Frame around the active lens; owns the Shift+Arrow navigation keys.

    Because the bindings live here (an ancestor of the focused lens) they
    only fire while focus is inside the lens area -- never stolen from the
    log drawer or the side slot.

    Shift+Up/Down move the active "nav level" between the lens bar and an
    inner tab bar of the current lens -- only for a lens that implements the
    ``set_subtab_bar_active``/``cycle_subtab`` hooks; none of the four lenses
    has sub-tabs any more, so today this is a no-op. Shift+Left/Right cycle
    whichever level is active: the lenses, or such a lens's inner tabs. All
    four delegate to ``MainScreen`` (``shift_nav_level``/
    ``cycle_active_level``). Shift-arrows are used because the lenses hand
    focus to OptionLists/RichLogs whose plain-arrow bindings would swallow
    them; Textual binds no Shift+arrow there, so they bubble up to here.
    """

    # Shift+Up/Down (nav level) have no binding any more: no lens has an
    # inner sub-tab bar, so they did nothing but show up in the ? help.
    BINDINGS = [
        Binding("shift+left", "cycle_prev", "Previous lens", show=False),
        Binding("shift+right", "cycle_next", "Next lens", show=False),
    ]

    def action_nav_level_up(self) -> None:
        self.screen.shift_nav_level(-1)

    def action_nav_level_down(self) -> None:
        self.screen.shift_nav_level(1)

    def action_cycle_prev(self) -> None:
        self.screen.cycle_active_level(-1)

    def action_cycle_next(self) -> None:
        self.screen.cycle_active_level(1)


#: Backwards-compatible name (the help screen and older code referred to it).
_ToolPanel = _LensHost

#: Chat dock split presets (share of the left column), smallest first.
CHAT_PRESETS: tuple[float, ...] = (0.3, 0.5, 0.7)
#: Default split.
CHAT_DEFAULT_RATIO = 0.5
#: Fewest chat rows in split mode, and fewest rows left for the lens.
CHAT_MIN_ROWS = 10
LENS_MIN_ROWS = 6
#: Below this left-column height the chat is shown maximized ("effective
#: max"): a split would leave the lens or the chat unusably small.
CHAT_SPLIT_MIN_HEIGHT = CHAT_MIN_ROWS + LENS_MIN_ROWS
#: Below this screen width the screen gets ``-narrow`` (narrower Inspector).
NARROW_WIDTH = 120
#: Dock frame title (the "Blockhead" antennae + name).
CHAT_TITLE = "▚▄▄▞ Sandroid AI"


def chat_rows(height: int, ratio: float) -> int:
    """Chat rows for a left column of ``height`` rows at ``ratio`` (split).

    ``clamp(round(H * ratio), 10, H - 6)``; callers switch to the effective
    max below :data:`CHAT_SPLIT_MIN_HEIGHT` rows.
    """
    return max(CHAT_MIN_ROWS, min(round(height * ratio), height - LENS_MIN_ROWS))


#: Textual's own ←/→ actions: sideways scrolling (scroll containers, a lens
#: table) and caret / cell cursors. They do not keep ←/→ from the Inspector's
#: tab switching -- whether they scrolled used to depend on the window size.
_BUILTIN_LEFT_RIGHT_ACTIONS = frozenset(
    {"scroll_left", "scroll_right", "cursor_left", "cursor_right"}
)


def handles_left_right(widget: Widget | None, stop: Widget | None = None) -> bool:
    """True if ``widget`` or an ancestor below ``stop`` binds ←/→ itself.

    Walks from ``widget`` up through its ancestors, stopping before ``stop``
    (and before any screen). Only a binding with its own meaning counts, such
    as the Timeline type bar or the chat's agents bar moving their selection;
    Textual's built-in scroll / cursor actions
    (:data:`_BUILTIN_LEFT_RIGHT_ACTIONS`) do not.

    Args:
        widget: The focused widget (None: nothing has focus).
        stop: An ancestor whose own ←/→ bindings are not looked at, and above
            which the walk ends (e.g. the Inspector, whose ←/→ switch its tabs).

    Returns:
        Whether a widget on that path claims ←/→ for itself.
    """
    node = widget
    while node is not None and node is not stop and not isinstance(node, Screen):
        bindings = getattr(node, "_bindings", None)
        key_map = getattr(bindings, "key_to_bindings", None) or {}
        for key in ("left", "right"):
            for binding in key_map.get(key, ()):
                action = str(getattr(binding, "action", "")).split("(", 1)[0]
                if action.strip() not in _BUILTIN_LEFT_RIGHT_ACTIONS:
                    return True
        node = node.parent if isinstance(node.parent, Widget) else None
    return False


def snap_chat_ratio(ratio: float) -> float:
    """The preset nearest to ``ratio``."""
    return min(CHAT_PRESETS, key=lambda p: abs(p - ratio))


class _LeftCol(Vertical):
    """``#left-col``: the lens above the chat dock; re-sizes the dock."""

    def on_resize(self, _event) -> None:
        apply = getattr(self.screen, "_apply_chat_layout", None)
        if apply is not None:
            apply()


class ChatDock(Vertical):
    """The AI chat frame under the lens (§6 of ai_foundations.rst).

    Holds the one ``ChatPanel`` (composed once, never unmounted). Dragging
    the top border resizes the split (snapping to the presets on release);
    a double-click on it toggles max. All state lives on ``MainScreen``
    (``chat_mode`` / ``chat_ratio``); this widget only forwards the mouse.
    """

    DEFAULT_CSS = """
    ChatDock {
        display: none;
        height: 50%;
        min-height: 0;
        border: round $lens-rule;
        border-title-color: $lens-accent;
        border-title-style: bold;
        border-subtitle-color: $lens-dim;
        background: $lens-panel;
    }
    ChatDock:focus-within {
        border: round $lens-rule-focus;
    }
    """

    def __init__(self, *children, **kwargs) -> None:
        super().__init__(*children, **kwargs)
        self._dragging = False
        self.border_title = CHAT_TITLE

    def _on_border(self, event) -> bool:
        return event.y == 0

    def on_mouse_down(self, event) -> None:
        if event.button != 1 or not self._on_border(event):
            return
        if not self.screen.chat_can_resize:
            return
        self._dragging = True
        self.capture_mouse()
        event.stop()
        event.prevent_default()

    def on_mouse_move(self, event) -> None:
        if not self._dragging:
            return
        self.screen.drag_chat_dock(event.screen_y)
        event.stop()

    def on_mouse_up(self, event) -> None:
        if not self._dragging:
            return
        self._dragging = False
        self.release_mouse()
        self.screen.end_chat_drag()
        event.stop()

    def on_click(self, event) -> None:
        if self._on_border(event) and event.chain >= 2:
            self.screen.toggle_chat_max()
            event.stop()


class MainScreen(Screen):
    """Main screen: header, lens bar, lens + AI chat dock, Inspector slot.

    Global keys live on the app; this screen only adds the Shift+Arrow
    fallback while NOTHING has focus (normally ``_LensHost`` catches them),
    Enter → Inspector for lenses that implement ``inspect_selected`` and
    Shift+Up/Down (chat size) while the chat is open.
    """

    BINDINGS = [
        Binding("shift+left", "unfocused_nav('cycle', -1)", show=False),
        Binding("shift+right", "unfocused_nav('cycle', 1)", show=False),
        Binding("enter", "inspect", "Inspect"),
        # AI chat dock size while it is open (whatever has focus): 0.3 ->
        # 0.5 -> 0.7 -> max. Not Ctrl+Up/Down: macOS's Mission Control.
        Binding(
            "shift+up",
            "chat_size(1)",
            "AI chat bigger (30% → 50% → 70% → max)",
            show=False,
        ),
        Binding("shift+down", "chat_size(-1)", "AI chat smaller", show=False),
        # Inspector tabs while it is open, whatever has focus: [ / ] always;
        # plain ←/→ too, except in a text input (caret) or a widget with its
        # own ←/→ (the Timeline type bar, the chat's agents bar; see
        # handles_left_right). They are priority bindings: a lens table used
        # to keep ←/→ for sideways scrolling only while it overflowed, so
        # whether they switched tabs depended on the window size (they
        # scrolled at 80x24, switched at 100x30).
        Binding(
            "left_square_bracket",
            "inspector_tab(-1)",
            "Inspector: prev tab",
            show=False,
        ),
        Binding(
            "right_square_bracket",
            "inspector_tab(1)",
            "Inspector: next tab",
            show=False,
        ),
        Binding(
            "left",
            "inspector_arrow(-1)",
            "Inspector: prev tab",
            show=False,
            priority=True,
        ),
        Binding(
            "right",
            "inspector_arrow(1)",
            "Inspector: next tab",
            show=False,
            priority=True,
        ),
        # Back to LIVE from REVIEW scope (shown only while reviewing a run).
        Binding("L", "back_to_live", "Live"),
        # Interactive Inspector content (InspectorContent.keys), e.g. the
        # Files lens's Versions / Content tabs. Enabled only while the open
        # Inspector's content declares the key. These keys are bound nowhere
        # else (no lens, no global key), so they never change meaning with
        # the focus: { } pair with [ ] (tabs); * is the diff base.
        Binding(
            "left_curly_bracket",
            "inspector_key('left_curly_bracket')",
            "Inspector: older version / previous table",
            key_display="{",
            show=False,
        ),
        Binding(
            "right_curly_bracket",
            "inspector_key('right_curly_bracket')",
            "Inspector: newer version / next table",
            key_display="}",
            show=False,
        ),
        Binding(
            "asterisk",
            "inspector_key('asterisk')",
            "Inspector: diff against this version (base)",
            key_display="*",
            show=False,
        ),
    ]

    #: Current review scope: a run id, or None for the live session. Watch it
    #: (``self.watch(screen, "scope_run", cb)``) or handle ``ScopeChanged``.
    scope_run: reactive[str | None] = reactive(None, init=False)

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action == "unfocused_nav":
            return self.focused is None
        if action == "chat_size":
            return self.chat_is_open
        if action == "inspect":
            # Not while the log drawer, the side slot or the chat has focus:
            # Enter means nothing there, and the footer must not offer
            # "⏎ Inspect".
            focused = self.focused
            if focused is not None:
                for box_id in ("#log-drawer", "#side-slot", "#chat-dock"):
                    try:
                        box = self.query_one(box_id)
                    except Exception:
                        continue
                    if focused is box or box in focused.ancestors:
                        return False
            return hasattr(self.lens_widget(), "inspect_selected")
        if action == "back_to_live":
            return self.scope_run is not None
        if action == "inspector_key":
            content = self.inspector_content
            if not (self.inspector_is_open and content is not None):
                return False
            if not parameters or parameters[0] not in (content.keys or {}):
                return False
            from textual.widgets import Input, TextArea

            return not isinstance(self.focused, Input | TextArea)
        if action in ("inspector_tab", "inspector_arrow"):
            content = self.inspector_content
            if not (self.inspector_is_open and content and content.tabs):
                return False
            from textual.widgets import Input, TextArea

            # A text input keeps ←/→ (caret) and [ / ] (typed characters).
            if isinstance(self.focused, Input | TextArea):
                return False
            if action == "inspector_arrow":
                # A widget with its own ←/→ (the Timeline type bar, the
                # chat's agents bar) keeps them; [ / ] still switch tabs.
                return not self._focus_handles_left_right()
            return True
        return True

    def _focus_handles_left_right(self) -> bool:
        """Whether the focused widget (or an ancestor) binds ←/→ itself.

        The walk stops at the Inspector: its own ←/→ switch its tabs too.

        Returns:
            True if plain ←/→ belong to the focus, not to the Inspector.
        """
        try:
            inspector: Widget | None = self.query_one("#inspector", Inspector)
        except Exception:
            inspector = None
        return handles_left_right(self.focused, stop=inspector)

    def action_inspector_tab(self, delta: int) -> None:
        """``[`` / ``]`` or ←/→: switch the open Inspector's tab."""
        try:
            self.query_one("#inspector", Inspector).action_tab(delta)
        except Exception:
            pass

    def action_inspector_arrow(self, delta: int) -> None:
        """←/→: switch the open Inspector's tab (unless the focus uses them)."""
        self.action_inspector_tab(delta)

    def action_inspector_key(self, key: str) -> None:
        """``{`` / ``}`` / ``*``: the open Inspector content's own key."""
        content = self.inspector_content
        handler = (content.keys or {}).get(key) if content is not None else None
        if handler is None:
            return
        try:
            tab = self.query_one("#inspector", Inspector).tab_name
        except Exception:
            tab = None
        handler(tab)

    def action_back_to_live(self) -> None:
        """``L`` -- leave REVIEW scope (no-op in LIVE)."""
        self.set_scope(None)

    def action_unfocused_nav(self, kind: str, delta: int) -> None:
        if kind == "level":
            self.shift_nav_level(delta)
        else:
            self.cycle_active_level(delta)

    # Theme files (styles.tcss + themes/*.tcss) restyle these ids; a loaded
    # stylesheet beats DEFAULT_CSS, so the values here are only the
    # default-theme baseline / fallback.
    DEFAULT_CSS = """
    MainScreen {
        layout: vertical;
    }
    MainScreen #status-bar {
        height: auto;
        max-height: 2;
    }
    MainScreen #workspace {
        height: 1fr;
    }
    MainScreen #lens-host {
        width: 1fr;
        height: 1fr;
        border: round #1f2d4d;
        border-title-color: #7dd3fc;
        border-subtitle-color: #5b6479;
        background: #080c18;
    }
    MainScreen #lens-host:focus-within {
        border: round #2b4a75;
    }
    MainScreen #lens-body {
        height: 1fr;
    }
    MainScreen #left-col {
        width: 1fr;
        height: 1fr;
    }
    MainScreen #left-col > #lens-host {
        min-height: 0;
    }
    MainScreen #left-col.-chat > #chat-dock {
        display: block;
    }
    /* Max (by choice, or the effective max of a short window): the lens
       hides and the dock fills the column. The inline split height is
       cleared on the way in (_apply_chat_layout), so 1fr applies. */
    MainScreen #left-col.-chat-max > #lens-host {
        display: none;
    }
    MainScreen #left-col.-chat-max > #chat-dock {
        height: 1fr;
    }
    MainScreen #side-slot {
        display: none;
        width: 40%;
        min-width: 56;
        height: 1fr;
    }
    MainScreen.-narrow #side-slot {
        width: 45%;
        min-width: 0;
    }
    MainScreen #side-slot.-open {
        display: block;
    }
    MainScreen #side-slot > #inspector {
        display: none;
    }
    MainScreen #side-slot.-inspector > #inspector {
        display: block;
    }
    /* While the chat is open the log drawer may not eat the chat's rows. */
    MainScreen.-chat-open #log-drawer {
        max-height: 30%;
    }
    """

    def __init__(
        self,
        action_queue: "ActionQ" = None,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the main screen.

        Args:
            action_queue: ActionQ instance for executing actions
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        logger.debug("[MAIN_SCREEN] __init__ start")
        super().__init__(name=name, id=id, classes=classes)
        self.action_queue = action_queue
        self._controller = MenuController.get()
        self._event_handlers = []
        # Active Shift+Arrow nav level: "outer" (the lens bar) or "inner"
        # (the current lens's own sub-tab bar, where it has one).
        self._nav_level = "outer"
        # Side slot mode: None (closed) or "inspector".
        self._side_mode: str | None = None
        # AI chat dock under the lens: "closed", "split" or "max"; the split
        # share is one of CHAT_PRESETS. ``_chat_max_pref`` is the persisted
        # "open maximized" choice. The chat always starts closed.
        self._chat_mode = "closed"
        self._chat_ratio = CHAT_DEFAULT_RATIO
        self._chat_max_pref = False
        self._chat_opened_once = False
        # Rows of the dock while its border is dragged (None: no drag).
        self._chat_drag_rows: int | None = None
        self._scope_label: str | None = None
        # lens id -> (title, info) for the lens frame.
        self._lens_captions: dict[str, tuple[str | None, str | None]] = {}
        # Typing guard (see on_key): monotonic deadline, ignored text.
        self._typing_until = 0.0
        self._typed_ignored = ""
        # monotonic time of the guard's start or its last swallowed key.
        self._typing_last = 0.0
        logger.debug("[MAIN_SCREEN] __init__ complete")

    def compose(self) -> ComposeResult:
        """Create the UI layout."""
        logger.debug("[MAIN_SCREEN] compose start")
        yield ShellHeader(id="shell-header")
        yield StatusBar(id="status-bar")
        # Starts "-level-active" to match the default nav level ("outer").
        yield LensBar(id="lens-bar", classes="-level-active")
        with Horizontal(id="workspace"):
            with _LeftCol(id="left-col"):
                with _LensHost(id="lens-host"):
                    with ContentSwitcher(initial=LENSES[0].widget_id, id="lens-body"):
                        yield SpotlightPanel(id="spotlight-panel")
                        yield NetworkPanel(id="network-panel")
                        yield FilesPanel(id="files-panel")
                        yield DiffsView(id="runs-panel")
                        yield TimelineLens(id="timeline-panel")
                        yield IdentityLens(id="identity-panel")
                # The one ChatPanel: composed once, never unmounted -- only
                # the dock's classes / height change (see _apply_chat_layout).
                with ChatDock(id="chat-dock"):
                    yield self._make_chat_panel()
            with Vertical(id="side-slot"):
                yield Inspector(id="inspector")
        yield LogTicker(id="log-ticker")
        with LogDrawer(id="log-drawer"):
            yield ActivityLog(id="activity-log")
        yield SandroidFooter()
        logger.debug("[MAIN_SCREEN] compose complete")

    def on_mount(self) -> None:
        """Called when the screen is mounted.

        Uses call_later() to defer updates and allow the UI to render first.
        This ensures the TUI appears responsive even during initialization.
        """
        logger.debug("[MAIN_SCREEN] on_mount started")
        # Defer event subscription to next event loop iteration.
        # Subscribing during mount deadlocks: if a background thread publishes
        # an event, the subscriber calls call_from_thread which blocks waiting
        # for the main thread — but the main thread is stuck in on_mount.
        self.call_later(self._subscribe_to_events)
        logger.debug("[MAIN_SCREEN] on_mount: event subscription deferred")
        self._update_lens_frame()
        self._disable_hidden_lenses()
        self._load_chat_dock_prefs()
        self.set_class(self.app.size.width < NARROW_WIDTH, "-narrow")

        # Show welcome message immediately (fast)
        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            logger.debug("[MAIN_SCREEN] on_mount: activity_log found")
            # One line instead of the old logo banner: the log lives in a
            # 12-row drawer now (the ticker shows this line until the next).
            from sandroid._version import __version__

            activity_log.write(
                f"[dim]Sandroid {__version__} · [bold]?[/] help · "
                "[bold]1-6[/] lenses · [bold]`[/] this log[/]"
            )
            logger.debug("[MAIN_SCREEN] on_mount: welcome shown")
        except Exception as e:
            logger.warning(f"Could not show welcome: {e}")

        # Defer state updates to allow UI to render first
        # This makes the TUI appear responsive immediately
        self.call_later(self._deferred_mount_updates)
        logger.debug("[MAIN_SCREEN] on_mount complete, deferred updates scheduled")

    # -- clicks ---------------------------------------------------------------

    def on_click(self, event) -> None:
        """Route clicks on the lens bar and on lens action cells.

        Clicks elsewhere are ignored (event is not stopped, so normal handling
        continues).
        """
        wid = getattr(getattr(event, "widget", None), "id", None)
        if not wid:
            return
        if wid.startswith("lens-tab-"):
            self.switch_lens(wid[len("lens-tab-") :])
        elif wid.startswith(("act-", "snap-")):
            # Lens action cells (spotlight uses act-*). The hasattr guard keeps
            # lenses without a dispatcher safe.
            panel = self.lens_widget()
            if panel is not None and hasattr(panel, "dispatch_action_cell"):
                try:
                    panel.dispatch_action_cell(wid)
                except Exception:
                    pass

    # -- lenses ---------------------------------------------------------------

    @property
    def active_lens(self) -> str:
        """Id of the active lens (``"app"`` ... ``"timeline"``, ``"identity"``)."""
        spec = LENS_BY_WIDGET.get(self._bottom_current() or "")
        return spec.id if spec else LENSES[0].id

    def is_lens_active(self, lens_id: str) -> bool:
        return self.active_lens == lens_id

    def lens_widget(self, lens_id: str | None = None):
        """The body widget of ``lens_id`` (default: the active lens), or None."""
        spec = LENS_BY_ID.get(lens_id or self.active_lens)
        if spec is None:
            return None
        try:
            return self.query_one(f"#{spec.widget_id}")
        except Exception:
            return None

    def switch_lens(self, lens_id: str) -> None:
        """Make ``lens_id`` the active lens and focus it."""
        spec = LENS_BY_ID.get(lens_id)
        if spec is not None:
            self._select_bottom_tab(spec.widget_id)

    def cycle_lens(self, delta: int) -> None:
        """Switch to the lens ``delta`` steps away (wraps)."""
        order = [spec.id for spec in LENSES]
        try:
            idx = order.index(self.active_lens)
        except ValueError:
            idx = 0
        self.switch_lens(order[(idx + delta) % len(order)])

    def set_lens_badge(self, lens_id: str, text: str | None) -> None:
        """Show ``text`` (e.g. ``"27 TLS failed"``) after the lens name; None clears it."""
        try:
            self.query_one("#lens-bar", LensBar).set_badge(lens_id, text)
        except Exception:
            pass

    def set_lens_caption(
        self, lens_id: str, title: str | None = None, info: str | None = None
    ) -> None:
        """Frame caption for ``lens_id``: ``"<Label> · title"`` and right-side info."""
        self._lens_captions[lens_id] = (title, info)
        if lens_id == self.active_lens:
            self._update_lens_frame()

    def _update_lens_frame(self) -> None:
        spec = LENS_BY_ID[self.active_lens]
        title, info = self._lens_captions.get(spec.id, (None, None))
        try:
            host = self.query_one("#lens-host")
        except Exception:
            return
        # No caption: no frame title (the lens bar already names the lens).
        # The Identity lens uses no separator glyph (plain spacing); the
        # other lenses keep their titles.
        sep = "  " if spec.id == "identity" else " · "
        host.border_title = f"{spec.label}{sep}{title}" if title else ""
        host.border_subtitle = info or ""
        try:
            self.query_one("#lens-bar", LensBar).set_active(spec.id)
        except Exception:
            pass

    #: Lens-bar tab id -> lens body widget id (legacy name, in lens order).
    _TOOL_TABS = {f"lens-tab-{s.id}": s.widget_id for s in LENSES}

    def _bottom_current(self) -> str | None:
        """Return the widget id of the active lens body, if any."""
        try:
            return self.query_one("#lens-body", ContentSwitcher).current
        except Exception:
            return None

    def _current_panel_widget(self):
        """Return the active lens body widget, if any."""
        return self.lens_widget()

    def _select_bottom_tab(self, panel_id: str) -> None:
        """Switch the active lens (by body widget id) and focus it."""
        try:
            self.query_one("#lens-body", ContentSwitcher).current = panel_id
        except Exception:
            return
        # A maximized chat hides the lens: switching lenses means "show me
        # the lens", so a chosen max goes back to the split, and a window
        # too short for a split closes the chat.
        if self.chat_is_maximized:
            if self._chat_too_short():
                self.close_chat()
            else:
                self._chat_mode = "split"
                self._apply_chat_layout()
        # The Inspector shows a row of the lens that opened it; on another
        # lens its content is stale and its key hints (e.g. "w watch") name
        # keys that mean something else there. Close it.
        content = self.inspector_content
        spec = LENS_BY_WIDGET.get(panel_id)
        if self.inspector_is_open and (
            content is None or spec is None or content.lens != spec.id
        ):
            self.close_inspector()
        self._update_lens_frame()
        try:
            panel = self.query_one(f"#{panel_id}")
            panel.disabled = False
            panel.focus()
        except Exception:
            pass
        # The other lenses go inert once focus has moved (queued after the
        # focus above, so disabling never bounces focus around).
        self.app.call_later(self._disable_hidden_lenses)
        # Let a freshly-activated lens refresh itself immediately.
        try:
            panel_widget = self.query_one(f"#{panel_id}")
            for hook in (
                "refresh_snapshots",
                "refresh_header",
                "refresh_glance",
                "on_activated",
                "on_lens_activated",
            ):
                if hasattr(panel_widget, hook):
                    try:
                        getattr(panel_widget, hook)()
                    except Exception:
                        logger.debug("lens hook %s failed", hook, exc_info=True)
        except Exception:
            pass
        self.call_after_refresh(self._ensure_view_focus, self._keys_routed())
        # Whenever the lens changes -- by any means -- the active nav level
        # goes back to "outer" and stale inner highlights are cleared.
        self._reset_nav_level_to_outer()
        self.refresh_bindings()

    def _disable_hidden_lenses(self) -> None:
        """Hidden lenses are ``disabled``: they cannot hold focus, so neither
        their bindings nor their own key handlers can see a key (E2E: keys
        reached the hidden App lens's ``A`` and similar through focus left
        in a lens that was no longer shown).
        """
        current = self._bottom_current()
        for spec in LENSES:
            panel = self.lens_widget(spec.id)
            if panel is not None:
                panel.disabled = spec.widget_id != current

    def _reset_nav_level_to_outer(self) -> None:
        """Force the active nav level back to "outer" + clear stale highlights."""
        self._nav_level = "outer"
        try:
            self.query_one("#lens-bar").set_class(True, "-level-active")
        except Exception:
            pass
        for spec in LENSES:
            panel = self.lens_widget(spec.id)
            if panel is not None and hasattr(panel, "set_subtab_bar_active"):
                try:
                    panel.set_subtab_bar_active(False)
                except Exception:
                    pass

    def shift_nav_level(self, delta: int) -> None:
        """Move the active nav level (Shift+Up/Down).

        ``delta=-1`` (up) moves to the lens bar; ``delta=+1`` (down) moves to
        the active lens's own inner sub-tab bar -- a no-op if the lens has no
        ``set_subtab_bar_active`` hook.
        """
        panel = self._current_panel_widget()
        has_inner_bar = panel is not None and hasattr(panel, "set_subtab_bar_active")

        if delta < 0:
            new_level = "outer"
        elif has_inner_bar:
            new_level = "inner"
        else:
            return

        if new_level == self._nav_level:
            return

        self._nav_level = new_level
        try:
            self.query_one("#lens-bar").set_class(new_level == "outer", "-level-active")
        except Exception:
            pass
        if has_inner_bar:
            try:
                panel.set_subtab_bar_active(new_level == "inner")
            except Exception:
                pass

    def cycle_active_level(self, delta: int) -> None:
        """Cycle whichever level is active (Shift+Left/Right).

        Outer: cycles the lenses. Inner: cycles the active lens's own sub-tabs
        via its duck-typed ``cycle_subtab`` hook.
        """
        if self._nav_level == "inner":
            panel = self._current_panel_widget()
            if panel is not None and hasattr(panel, "cycle_subtab"):
                try:
                    panel.cycle_subtab(delta)
                except Exception:
                    pass
                self.call_after_refresh(self._ensure_view_focus, self._keys_routed())
            return
        self.cycle_lens(delta)

    def _keys_routed(self) -> int:
        return int(getattr(self.app, "keys_routed", 0))

    def _ensure_view_focus(self, keys_at_switch: int | None = None) -> None:
        """After a view switch, never leave the caret in a text input.

        Switching lenses focuses the new view's table/list. If focus
        nevertheless ends up in a text field (a lens's inline filter or the
        Files lens's "watch a path" input, e.g. via Textual re-homing focus
        away from a widget the switch just hid), the next shortcut -- ``P``
        for the PDF report -- would be typed into it. Move focus to the first
        non-input focusable widget of the active lens instead (or to nothing,
        which keeps global keys live).

        Runs after the next refresh, which can come late under load: when a
        key was routed after the switch (``keys_at_switch``), that key's own
        focus move wins (``3`` then ``/aid``: the Files filter the ``/``
        opened must keep the focus, or ``aid`` runs as commands).
        """
        from textual.widgets import Input, TextArea

        if keys_at_switch is not None and self._keys_routed() != keys_at_switch:
            return
        focused = self.focused
        if focused is not None and not isinstance(focused, Input | TextArea):
            return
        panel = self._current_panel_widget()
        if panel is None:
            return
        if focused is None:
            panel.focus()  # lenses forward to their list/log
            return
        if panel not in focused.ancestors:
            return  # e.g. the AI chat input -- not part of the switched view
        chain = [w for w in self.focus_chain if not isinstance(w, Input | TextArea)]
        for ancestor in focused.ancestors:
            for widget in chain:
                if widget is not ancestor and ancestor in widget.ancestors:
                    self.set_focus(widget)
                    return
            if ancestor is panel:
                break
        self.set_focus(panel if panel.focusable else None)

    def set_nav_level_inner(self) -> None:
        """Move the active nav level to "inner" (called by a lens's own click)."""
        self._nav_level = "inner"
        try:
            self.query_one("#lens-bar").set_class(False, "-level-active")
        except Exception:
            pass

    # -- legacy navigation helpers (other code calls these) -------------------

    def open_snapshots_tab(self) -> None:
        """Snapshots are no longer a tab: open the snapshot picker (S / 0)."""
        self.open_snapshot_picker()

    def open_snapshot_picker(self, then=None) -> None:
        """Push the snapshot picker; ``then(panel)`` runs once it is mounted."""
        from sandroid.tui.modals import SnapshotPickerModal

        current = self.app.screen
        if isinstance(current, SnapshotPickerModal):
            if then is not None:
                current.run_with_panel(then)
            return
        self.app.push_screen(SnapshotPickerModal(then=then))

    def note_snapshot(self, tag: str | None, slot: str | None = None) -> None:
        """Remember the last loaded snapshot for the header (cheap, no I/O)."""
        label = ""
        if tag:
            label = f"slot {slot} · {tag}" if slot else tag
        try:
            self.query_one("#shell-header", ShellHeader).set_snapshot(label)
        except Exception:
            pass

    def note_snapshot_deleted(self, tag: str) -> None:
        """The header's snapshot was deleted: say so (R1-B5: it kept
        showing "snapshot <name>" as if it still existed).
        """
        try:
            header = self.query_one("#shell-header", ShellHeader)
        except Exception:
            return
        current = header._snapshot
        if (
            current == tag
            or current.endswith(f" · {tag}")
            or current.startswith(f"{tag} (")
        ):
            header.set_snapshot(f"{tag} (deleted)")

    def open_fritap_tab(self) -> None:
        """Switch to the Network lens and show friTap's state (key ``h``).

        The Network lens has no sub-tabs any more: its ``select_subtab`` hook
        opens the "Network status" Inspector page on its friTap tab.
        """
        self.switch_lens("network")
        try:
            panel = self.query_one("#network-panel")
            if hasattr(panel, "select_subtab"):
                panel.select_subtab("fritap-panel")
        except Exception:
            pass

    def open_files_tab(self, sub_tab: str | None = None) -> None:
        """Switch to the Files lens (legacy ``sub_tab`` ids still accepted).

        The Files lens is one table now; ``sub_tab`` is a pre-lens id that
        callers still pass: ``"files-watchlist"`` (key ``l``) puts the cursor
        on the first, watched row, ``"files-monitor"`` just shows the table.
        ``"files-diffs"`` is redirected to the Runs lens (Play lands on it on
        every press).
        """
        if sub_tab in _SUBTAB_TO_LENS:
            self.switch_lens(_SUBTAB_TO_LENS[sub_tab])
            return
        self.switch_lens("files")
        if sub_tab:
            try:
                panel = self.query_one("#files-panel")
                if hasattr(panel, "select_subtab"):
                    panel.select_subtab(sub_tab)
            except Exception:
                pass

    def open_runs_lens(self) -> None:
        """Switch to the Runs lens (run history / diffs)."""
        self.switch_lens("runs")

    def cycle_bottom_tab(self, delta: int) -> None:
        """Legacy name of :meth:`cycle_lens`."""
        self.cycle_lens(delta)

    # -- side slot: the Inspector ----------------------------------------------

    def _side_slot(self):
        try:
            return self.query_one("#side-slot")
        except Exception:
            return None

    def _set_side_mode(self, mode: str | None) -> None:
        slot = self._side_slot()
        if slot is None:
            return
        self._side_mode = mode
        slot.set_class(mode is not None, "-open")
        slot.set_class(mode == "inspector", "-inspector")
        self.refresh_bindings()

    @property
    def side_slot_mode(self) -> str | None:
        """``"inspector"`` or None (closed). The chat docks under the lens."""
        return self._side_mode

    @property
    def inspector_is_open(self) -> bool:
        return self._side_mode == "inspector"

    @property
    def inspector_content(self) -> InspectorContent | None:
        """What the Inspector shows (also while closed: the last content)."""
        try:
            return self.query_one("#inspector", Inspector).content
        except Exception:
            return None

    def open_inspector(self, content: InspectorContent) -> None:
        """Show ``content`` in the right-hand Inspector (the chat stays open)."""
        try:
            inspector = self.query_one("#inspector", Inspector)
        except Exception:
            return
        if content.lens is None:
            content.lens = self.active_lens
        inspector.show(content)
        if self._side_mode != "inspector":
            self._set_side_mode("inspector")

    def update_inspector(self, content: InspectorContent) -> None:
        """Replace the Inspector content in place -- only if it is open."""
        if self.inspector_is_open:
            self.open_inspector(content)

    def close_inspector(self) -> None:
        """Close the Inspector (no-op if it is not open)."""
        if self.inspector_is_open:
            self.close_side_slot()

    def close_side_slot(self) -> None:
        """Close the Inspector and return focus to the lens if it was there."""
        if self._side_mode is None:
            return
        refocus = self.focused is None or self._side_slot() in (
            self.focused.ancestors if self.focused else ()
        )
        self._set_side_mode(None)
        if refocus:
            self._focus_lens()

    def _focus_lens(self) -> None:
        panel = self.lens_widget()
        if panel is not None:
            try:
                panel.focus()
            except Exception:
                pass

    def action_inspect(self) -> None:
        """Enter reached the screen: ask the active lens for Inspector content."""
        self._inspect_active_lens()

    def _inspect_active_lens(self) -> bool:
        lens = self.lens_widget()
        hook = getattr(lens, "inspect_selected", None)
        if hook is None:
            return False
        try:
            content = hook()
        except Exception:
            logger.debug("inspect_selected failed", exc_info=True)
            return False
        if content is None:
            return False
        self.open_inspector(content)
        return True

    def _selection_from_active_lens(self, event) -> None:
        lens = self.lens_widget()
        control = getattr(event, "control", None)
        if lens is None or control is None or not hasattr(lens, "inspect_selected"):
            return
        if lens is control or lens in control.ancestors:
            self._inspect_active_lens()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self._selection_from_active_lens(event)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._selection_from_active_lens(event)

    def _focused_permission_prompt(self):
        """The approval prompt holding the focus (it or a child), or None."""
        focused = self.focused
        if focused is None:
            return None
        try:
            from sandroid.tui.widgets.tool_permission_prompt import (
                ToolPermissionPrompt,
            )
        except Exception:
            return None
        for node in focused.ancestors_with_self:
            if isinstance(node, ToolPermissionPrompt):
                return node
        return None

    def handle_escape(self) -> bool:
        """Esc on the main screen (called by the App's priority Esc handler).

        Order:

        0. A focused approval prompt answers "No" (its ``action_cancel``):
           the App's priority Esc would otherwise never reach it.
        1. Focus in the chat dock goes to the lens; the chat stays open.
        2. A focused text input elsewhere keeps the old behaviour (a lens
           filter may clear itself, else Esc leaves the input -> False).
        3. An open Inspector closes, then the log drawer, then the chat.
        4. The lens's own Esc hook (e.g. clear an applied filter).

        Returns True when Esc was consumed here.
        """
        from textual.widgets import Input, TextArea

        prompt = self._focused_permission_prompt()
        if prompt is not None:
            try:
                prompt.action_cancel()
            except Exception:
                logger.debug("approval prompt cancel failed", exc_info=True)
            return True
        if self.chat_has_focus:
            self._leave_chat_dock()
            return True
        focused = self.focused
        slot = self._side_slot()
        in_slot = focused is not None and slot is not None and slot in focused.ancestors
        lens = self.lens_widget()
        lens_escape = getattr(lens, "handle_escape", None)
        if isinstance(focused, Input | TextArea) and not in_slot:
            # A lens's own input (the Network ``/`` filter) may use Esc to
            # clear itself; any other input is just left.
            if (
                lens_escape is not None
                and lens is not None
                and lens in focused.ancestors
                and lens_escape()
            ):
                return True
            return False
        if self._side_mode is not None:
            self.close_side_slot()
            return True
        if self.log_drawer_is_open:
            self.toggle_log_drawer()
            return True
        if self.chat_is_open:
            self.close_chat()
            return True
        if lens_escape is not None:
            try:
                return bool(lens_escape())
            except Exception:
                logger.debug("lens Esc hook failed", exc_info=True)
        return False

    @staticmethod
    def _make_chat_panel() -> Static:
        """Build the AI Chat panel, or a placeholder when its deps are missing.

        The chat panel imports :mod:`sandroid.ai` (and optional packages such
        as ``mcp``); a plain ``pip install sandroid`` without the AI extras
        must still get a working TUI, so the import happens here, lazily.
        """
        from sandroid.tui import widgets as _widgets

        chat_panel_cls = load_chat_panel_class()
        if chat_panel_cls is not None:
            return chat_panel_cls(id="chat-panel")
        return Static(
            "[bold]AI Chat unavailable[/bold]\n"
            f"Missing optional dependency: {_widgets.CHAT_PANEL_IMPORT_ERROR}\n"
            "Install the AI extras (e.g. [i]pip install 'sandroid[ai]'[/i]) "
            "and restart Sandroid.",
            id="chat-panel",
            markup=True,
        )

    # -- AI chat dock (under the lens) ------------------------------------------
    #
    # ``_chat_mode`` is "closed", "split" or "max"; ``_chat_ratio`` one of
    # CHAT_PRESETS. In split the dock is ``chat_rows(H, ratio)`` rows of the
    # left column (H rows); below CHAT_SPLIT_MIN_HEIGHT rows the layout is an
    # "effective max" whatever the mode. Shift+Up/Down step 0.3 -> 0.5 -> 0.7
    # -> max; dragging the dock's top border resizes and snaps on release; a
    # double-click on it toggles max. Only key presses and mouse-up persist
    # the size (``tui.chat_dock``); the chat always starts closed.

    def _chat_dock(self):
        try:
            return self.query_one("#chat-dock", ChatDock)
        except Exception:
            return None

    def _left_col(self):
        try:
            return self.query_one("#left-col")
        except Exception:
            return None

    @property
    def chat_mode(self) -> str:
        """``"closed"``, ``"split"`` or ``"max"`` (the chosen mode)."""
        return self._chat_mode

    @property
    def chat_ratio(self) -> float:
        """The split share (one of :data:`CHAT_PRESETS`)."""
        return self._chat_ratio

    @property
    def chat_is_open(self) -> bool:
        return self._chat_mode != "closed"

    @property
    def chat_is_maximized(self) -> bool:
        """The dock fills the left column (chosen max or a short window)."""
        if not self.chat_is_open:
            return False
        return self._chat_mode == "max" or self._chat_too_short()

    def _chat_too_short(self) -> bool:
        col = self._left_col()
        height = col.size.height if col is not None else 0
        return 0 < height < CHAT_SPLIT_MIN_HEIGHT

    @property
    def chat_can_resize(self) -> bool:
        """The border can be dragged (open, and tall enough for a split)."""
        return self.chat_is_open and not self._chat_too_short()

    @property
    def chat_has_focus(self) -> bool:
        """The focus is inside the chat dock."""
        dock = self._chat_dock()
        focused = self.focused
        return (
            dock is not None
            and focused is not None
            and (focused is dock or dock in focused.ancestors)
        )

    def _apply_chat_layout(self) -> None:
        """Sync the dock's classes, height and subtitle to the chat state."""
        col, dock = self._left_col(), self._chat_dock()
        if col is None or dock is None:
            return
        is_open = self.chat_is_open
        maxed = self.chat_is_maximized
        col.set_class(is_open, "-chat")
        col.set_class(maxed, "-chat-max")
        self.set_class(is_open, "-chat-open")
        if not is_open:
            return
        if maxed:
            # The inline split height would beat the -chat-max rule.
            dock.styles.height = None
        else:
            rows = self._chat_drag_rows
            if rows is None:
                rows = chat_rows(col.size.height, self._chat_ratio)
            dock.styles.height = rows
        dock.border_subtitle = self._chat_subtitle()

    def _chat_subtitle(self) -> str:
        if self._chat_drag_rows is not None:
            col = self._left_col()
            height = max(1, col.size.height if col is not None else 1)
            return f"{round(100 * self._chat_drag_rows / height)}% · release to snap"
        if self._chat_mode == "max":
            return key_words("max · ⇧↓ restore · Ctrl+Y close")
        if self._chat_too_short():
            return "small window · Ctrl+Y close"
        return key_words(f"{round(self._chat_ratio * 100)}% · ⇧↑/↓ size · Ctrl+Y close")

    def open_chat(self, focus: bool = True, *, split: bool = False) -> None:
        """Open the chat dock (max if that was the last choice).

        ``split`` opens it split even then: used when the chat opens by
        itself (an approval) and the lens must stay visible with its focus.
        """
        if not self.chat_is_open:
            self._chat_mode = "max" if self._chat_max_pref and not split else "split"
            self._apply_chat_layout()
            self.refresh_bindings()
            panel = self._chat_panel()
            if panel is not None and hasattr(panel, "refresh_header"):
                try:
                    panel.refresh_header()
                except Exception:
                    pass
            if not self._chat_opened_once:
                self._chat_opened_once = True
                # The egress banner sits at the top of the transcript: show
                # it on the first open.
                self.call_after_refresh(self._scroll_chat_home)
        if focus:
            self._focus_chat_input()

    def close_chat(self) -> None:
        """Close the chat dock; the lens gets the focus back if it had it."""
        if not self.chat_is_open:
            return
        refocus = self.focused is None or self.chat_has_focus
        self._chat_mode = "closed"
        self._apply_chat_layout()
        self.refresh_bindings()
        if refocus:
            self._focus_lens()

    def toggle_chat_panel(self) -> None:
        """Ctrl+Y: open + focus the chat; focus it; or close it.

        Closed -> open it and focus its input. Open but the focus is
        elsewhere -> focus the input. Open and focused -> close it.
        """
        if not self.chat_is_open:
            self.open_chat()
        elif not self.chat_has_focus and self._chat_input() is not None:
            self._focus_chat_input()
        else:
            self.close_chat()

    def _leave_chat_dock(self) -> None:
        """Esc in the dock: the lens gets the focus, the chat stays open.

        A chosen max is restored to the split first (the lens must be
        visible to take the focus); a window too short for a split closes
        the chat instead.
        """
        if self._chat_too_short():
            self.close_chat()
            return
        if self._chat_mode == "max":
            self._chat_mode = "split"
            self._apply_chat_layout()
        self._focus_lens()

    def _chat_panel(self):
        try:
            return self.query_one("#chat-panel")
        except Exception:
            return None

    def _chat_input(self):
        try:
            return self.query_one("#chat-input")
        except Exception:
            return None

    def _focus_chat_input(self) -> None:
        """Focus the chat: a waiting approval card first, else the input."""
        panel = self._chat_panel()
        target = getattr(panel, "focus_target", None)
        widget = target() if callable(target) else self._chat_input()
        if widget is not None:
            try:
                widget.focus()
            except Exception:
                pass

    def set_chat_attention(self, text: str | None) -> None:
        """Badge outside the dock (the ticker hint), e.g. an approval waits."""
        try:
            self.query_one("#log-ticker", LogTicker).set_attention(text)
        except Exception:
            pass

    def _scroll_chat_home(self) -> None:
        """Scroll the transcript to its top (the egress banner)."""
        try:
            self.query_one("#chat-log").scroll_home(animate=False, immediate=True)
        except Exception:
            pass

    def action_chat_size(self, delta: int) -> None:
        """Shift+Up (+1) / Shift+Down (-1): step 0.3 -> 0.5 -> 0.7 -> max."""
        if not self.chat_is_open:
            return
        if delta > 0:
            if self._chat_mode == "max":
                return
            bigger = [p for p in CHAT_PRESETS if p > self._chat_ratio]
            if bigger:
                self._chat_ratio = bigger[0]
            else:
                self._chat_mode = "max"
        elif self._chat_mode == "max":
            self._chat_mode = "split"
        else:
            smaller = [p for p in CHAT_PRESETS if p < self._chat_ratio]
            if not smaller:
                return
            self._chat_ratio = smaller[-1]
        self._apply_chat_layout()
        self._persist_chat_dock()

    def toggle_chat_max(self) -> None:
        """Double-click on the dock border: max <-> split."""
        if not self.chat_is_open:
            return
        self._chat_mode = "split" if self._chat_mode == "max" else "max"
        self._apply_chat_layout()
        self._persist_chat_dock()

    def drag_chat_dock(self, screen_y: int) -> None:
        """The dock's top border is dragged to ``screen_y`` (live resize)."""
        col = self._left_col()
        if col is None or not self.chat_can_resize:
            return
        region = col.content_region
        height = region.height
        # Up to the full column while dragging: released past the 0.7
        # preset it snaps to max.
        rows = max(CHAT_MIN_ROWS, min(region.bottom - screen_y, height))
        if self._chat_mode == "max":
            self._chat_mode = "split"
        self._chat_drag_rows = rows
        self._apply_chat_layout()

    def end_chat_drag(self) -> None:
        """Mouse-up after a drag: snap to the nearest preset (or max)."""
        rows = self._chat_drag_rows
        self._chat_drag_rows = None
        col = self._left_col()
        if rows is None or col is None:
            self._apply_chat_layout()
            return
        share = rows / max(1, col.size.height)
        targets = [*CHAT_PRESETS, 1.0]
        nearest = min(targets, key=lambda p: abs(p - share))
        if nearest == 1.0:
            self._chat_mode = "max"
        else:
            self._chat_mode = "split"
            self._chat_ratio = nearest
        self._apply_chat_layout()
        self._persist_chat_dock()

    def _load_chat_dock_prefs(self) -> None:
        """Read the dock size: the remembered UI state, else ``tui.chat_dock``.

        The size the user last chose lives in the UI-state file
        (:mod:`sandroid.config.ui_state`); ``tui.chat_dock`` in the config
        is only the default for a first run.
        """
        prefs: object = None
        try:
            from sandroid.config.ui_state import load_ui_state

            prefs = load_ui_state().get("chat_dock")
        except Exception:
            logger.debug("reading the UI state failed", exc_info=True)
        if not isinstance(prefs, dict):
            try:
                cfg = self.app.sandroid_config.tui.chat_dock
                prefs = {"ratio": cfg.ratio, "maximized": cfg.maximized}
            except Exception:
                return
        try:
            self._chat_ratio = snap_chat_ratio(float(prefs.get("ratio", 0.5)))
            self._chat_max_pref = bool(prefs.get("maximized", False))
        except Exception:
            logger.debug("bad chat dock state", exc_info=True)

    def _persist_chat_dock(self) -> None:
        """Remember the dock size (off the UI thread)."""
        ratio, maximized = self._chat_ratio, self._chat_mode == "max"
        self._chat_max_pref = maximized
        self.run_worker(
            lambda: self._write_chat_dock_prefs(ratio, maximized),
            thread=True,
            group="chat-dock-prefs",
            exit_on_error=False,
        )

    def _write_chat_dock_prefs(self, ratio: float, maximized: bool) -> None:
        """Save the dock size to the UI-state file (runs on a worker thread).

        Never through the config loader: that path rewrote a config file
        with the whole merged configuration, API key included.
        """
        try:
            from sandroid.config.ui_state import update_ui_state

            update_ui_state("chat_dock", {"ratio": ratio, "maximized": maximized})
        except Exception as exc:
            logger.warning(f"Could not save the chat dock size: {exc}")

    def on_resize(self, event) -> None:
        self.set_class(event.size.width < NARROW_WIDTH, "-narrow")

    # -- focus guard + key routing ---------------------------------------------
    #
    # E2E finding (Files lens on Firefox): after ``B`` + a name, the since-mark
    # view was empty for a moment; the lens hid its table while focus was
    # still on its way there (``Widget.focus`` is deferred), Textual's
    # ``_reset_focus`` found no visible sibling and left focus on *nothing*.
    # The next modal close (``?`` help) then auto-focused the first focusable
    # widget in the DOM -- the hidden App lens. From there ``/`` did nothing
    # (no lens binding in the chain), ``A`` ran the hidden App lens's Attach,
    # and the typed word "places" fired the global p/l/a/c/e/s commands.
    # Three layers keep that from happening again:
    #
    # 1. ``_rehome_focus``: whenever focus is lost (any blur, any screen
    #    resume) and it is on nothing, on a widget inside a hidden view, or on
    #    the bare active lens, the active lens gets it back.
    # 2. ``on_key`` routing: a key the focus chain does not handle but the
    #    active lens binds runs on the lens (lens keys never fall through to a
    #    dead end because focus wandered off).
    # 3. Typing guard: ``/`` that finds no filter to open (the lens has none),
    #    or a stray-typing cancel of the Quit / Play confirm, starts a short
    #    window in which every printable key is swallowed -- the word typed
    #    after it is text, not commands (see ``swallow_stray_key``).

    #: Seconds after an unhandled ``/`` or a stray-typing cancel (and after
    #: each further swallowed key) during which printable keys are swallowed.
    TYPING_GUARD_SECONDS = 1.5
    #: A swallowed key this long after the previous one was pressed on
    #: purpose, not typed as part of a word: a notice says it did not run.
    TYPING_PAUSE_SECONDS = 0.5

    @property
    def AUTO_FOCUS(self) -> str:
        """Textual focuses this on resume when nothing has focus: the active
        lens, never the first focusable widget of a hidden lens (the chat
        input while the maximized chat hides the lens).
        """
        if self.chat_is_maximized and self._chat_input() is not None:
            return "#chat-input"
        spec = LENS_BY_ID.get(self.active_lens)
        return f"#{spec.widget_id}" if spec else "*"

    def _focus_in_limbo(self) -> bool:
        """True when focus is on nothing or on a widget the user cannot see
        (inside a hidden lens / view) -- keys then reach no visible target.
        """
        from sandroid.tui.widgets.lens_shell import is_shown

        focused = self.focused
        return focused is None or not is_shown(focused)

    def _focus_is_elsewhere_on_purpose(self) -> bool:
        """A text field (the AI chat, a lens filter), the side slot or the
        chat dock has focus: its unhandled keys (Ctrl+L ...) must not run
        lens commands.
        """
        from textual.widgets import Input, TextArea

        focused = self.focused
        if focused is None:
            return False
        if isinstance(focused, Input | TextArea) or self.chat_has_focus:
            return True
        slot = self._side_slot()
        return slot is not None and slot in focused.ancestors

    def _rehome_focus(self, resumed: bool = False) -> None:
        """Give focus back to the active lens if it is in limbo (see above).

        ``resumed``: after a modal closed, the bare lens itself may hold the
        focus (``AUTO_FOCUS``); it then forwards it to its table / list.
        """
        try:
            if self.app.screen is not self or not self.is_attached:
                return  # a modal is on top: on_screen_resume runs this again
        except Exception:
            return
        lens = self.lens_widget()
        if lens is None:
            return
        if self.chat_is_maximized and self._focus_in_limbo():
            # The lens is hidden behind the maximized chat.
            self._focus_chat_input()
            return
        focused = self.focused
        if resumed and focused is lens and type(lens).focus is not Widget.focus:
            lens.focus()
            return
        if self._focus_in_limbo():
            lens.focus()

    def on_descendant_blur(self, _event) -> None:
        self.call_after_refresh(self._rehome_focus)

    def on_screen_resume(self, _event) -> None:
        self.call_after_refresh(self._rehome_focus, True)

    def start_typing_guard(self) -> None:
        """Treat the next letters as stray text, not commands (see on_key).

        Also called by the guarded confirmations (Play, Quit) when a letter
        reveals that the key which opened them was part of a typed word: the
        rest of the word must not run app commands either.
        """
        import time

        self._typing_last = time.monotonic()
        self._typing_until = self._typing_last + self.TYPING_GUARD_SECONDS
        self._typed_ignored = ""

    def typing_guard_active(self) -> bool:
        """True while letters are treated as stray text (see on_key)."""
        import time

        return self._typing_until > time.monotonic()

    def swallow_stray_key(self, event) -> bool:
        """Swallow ``event`` if it is the rest of a stray word (True if so).

        Called by the app's key router before the key is routed at all, so
        no binding can run it: not the app's or this screen's (``y`` Proxy),
        not the active lens's (``w`` watch + pull, ``z`` zoom diff; E2E round
        3 N1), not a priority one (``D``, ``?``), not a key handler.

        Swallowed: every printable key -- letters, digits (a stray word may
        hold one, "sqlite3"; a lens switch would leave the lens), punctuation
        and space. Passed: keys that are not typing -- Escape, Enter, Tab,
        arrows, paging, F-keys, Ctrl/Alt combos -- and anything typed into a
        text field. Each swallowed key extends the window, so a word of any
        length is swallowed; a pause of ``TYPING_GUARD_SECONDS`` ends it.
        """
        import time

        from textual.widgets import Input, TextArea

        now = time.monotonic()
        if self._typing_until <= now:
            if self._typing_until:
                self._typing_until = 0.0
                self._typed_ignored = ""
            return False
        if self.app.screen is not self or not event.is_printable:
            return False
        if isinstance(self.focused, Input | TextArea):
            return False
        paused = now - self._typing_last >= self.TYPING_PAUSE_SECONDS
        self._typing_last = now
        self._typing_until = now + self.TYPING_GUARD_SECONDS
        self._typed_ignored += event.character or ""
        notice = getattr(self.lens_widget(), "stray_key_swallowed", None)
        if notice is not None and event.key == "R":
            notice(event.key)  # App lens: "Restart not run"
        elif paused:
            # Not the rest of a fast word but a key pressed on purpose (N6:
            # a q after a dialog closed as typing opened nothing): say why.
            from sandroid.tui.key_display import format_key

            self.app.notify(
                f"{format_key(event.key)} not run: keys right after typing are "
                "ignored for a moment. Press it again.",
                severity="warning",
                timeout=3,
            )
        return True

    def _lens_binding_for(self, key: str):
        """The active lens's enabled binding for ``key`` (None if it has none)."""
        lens = self.lens_widget()
        if lens is None:
            return None, None
        for binding in lens._bindings.key_to_bindings.get(key, ()):
            action_name = binding.action.split("(", 1)[0]
            try:
                if lens.check_action(action_name, ()) is False:
                    continue
            except Exception:
                continue
            return lens, binding
        return None, None

    async def on_key(self, event) -> None:
        """Route keys whose focus target is gone; guard text typed into nothing.

        Runs for every key that bubbled up from the focused widget unhandled
        (a focused text input consumes printable keys before this), and
        before the app's own non-priority bindings run.
        """
        import time

        if self.app.screen is not self:
            return
        key = event.key
        active = self.active_bindings.get(key)
        limbo = self._focus_in_limbo()
        lens, lens_binding = self._lens_binding_for(key)
        if lens_binding is not None and (
            limbo or (active is None and not self._focus_is_elsewhere_on_purpose())
        ):
            # Focus wandered off (or sits where nothing binds the key): the
            # visible lens gets the key and focus back.
            event.stop()
            event.prevent_default()
            if limbo:
                lens.focus()
            await self.app.run_action(lens_binding.action, lens)
            return

        # The typed word itself is swallowed before routing (swallow_stray_key).
        now = time.monotonic()
        if self._typing_until and self._typing_until <= now:
            self._typing_until = 0.0
            self._typed_ignored = ""
        if key == "slash" and active is None:
            self.start_typing_guard()
            label = LENS_BY_ID[self.active_lens].label
            self.app.notify(
                f"The {label} lens has no filter — the next letters you type "
                "are ignored, not run as commands.",
                timeout=3,
            )

    # -- log drawer + ticker --------------------------------------------------

    @property
    def log_drawer_is_open(self) -> bool:
        try:
            return self.query_one("#log-drawer").has_class("-open")
        except Exception:
            return False

    def toggle_log_drawer(self) -> None:
        """Show/hide the bottom log drawer (backtick)."""
        try:
            drawer = self.query_one("#log-drawer", LogDrawer)
        except Exception:
            return
        showing = not drawer.has_class("-open")
        drawer.set_class(showing, "-open")
        try:
            self.query_one("#log-ticker", LogTicker).set_drawer_open(showing)
        except Exception:
            pass
        if showing:
            try:
                log = self.query_one("#activity-log", ActivityLog)
            except Exception:
                log = None
            if log is not None:
                log.scroll_end(animate=False)
                # Lines written while the drawer was closed are only kept;
                # render them once the drawer has its width again. A Resize
                # alone is not reliable here (it can arrive before layout).
                log.reflow_when_shown()
        else:
            focused = self.focused
            if focused is None or drawer in focused.ancestors or focused is drawer:
                panel = self.lens_widget()
                if panel is not None:
                    panel.focus()

    def on_activity_log_line_written(self, event: ActivityLog.LineWritten) -> None:
        try:
            self.query_one("#log-ticker", LogTicker).show_line(event.content)
        except Exception:
            pass

    # -- scope (LIVE / REVIEW) ------------------------------------------------

    @property
    def scope(self) -> str | None:
        """The run id under review, or None for the live session."""
        return self.scope_run

    def set_scope(self, run_id: str | None, label: str | None = None) -> None:
        """Switch every lens to reviewing ``run_id`` (None = back to LIVE).

        ``label`` is what the header pill shows after "REVIEW" (default
        ``"Run <run_id>"``).
        """
        self._scope_label = label
        if run_id == self.scope_run:
            self._update_scope_pill()
            for spec in LENSES:
                self._post_scope(spec.id)
            return
        self.scope_run = run_id

    def watch_scope_run(self, run_id: str | None) -> None:
        self._update_scope_pill()
        self.refresh_bindings()  # "L Live" shows only in REVIEW
        for spec in LENSES:
            self._post_scope(spec.id)

    # -- marks + labels (shared by every lens) -----------------------------------
    #
    # Labels live in the session timeline (``Labels``); ``marks`` is the Files
    # projection of them (``labels.boundaries()``). Without the timeline core
    # the marks are an in-memory list of points (``SessionMarks.add``).

    @staticmethod
    def labels_api():
        """The timeline's ``Labels`` (None when the timeline is missing)."""
        svc = timeline_service()
        labels = getattr(svc, "labels", None) if svc is not None else None
        return labels if hasattr(labels, "boundaries") else None

    def _labels_cache_key(self, labels) -> tuple | None:
        """``(sink, labels.version)``: the version alone collides across sinks
        (each device's sink counts from 0), so the label sink (its folder,
        else its session id; else the one of the last ``bound`` doorbell) is
        part of the key.
        """
        version = getattr(labels, "version", None)
        if version is None:
            return None
        sink = None
        svc = timeline_service()
        if svc is not None:
            try:
                status = svc.status()
                sink = getattr(status, "folder", None) or getattr(
                    status, "session_id", None
                )
            except Exception:
                sink = None
        if not sink:
            sink = getattr(self, "_labels_sink", None)
        return (str(sink) if sink else None, version)

    @property
    def marks(self) -> SessionMarks:
        """The session's marks (see ``lens_shell.SessionMarks``)."""
        marks = getattr(self, "_marks", None)
        if marks is None:
            marks = self._marks = SessionMarks()
            self._labels_key = None
        labels = self.labels_api()
        if labels is not None:
            key = self._labels_cache_key(labels)
            if key is None or key != getattr(self, "_labels_key", None):
                try:
                    marks.rebuild(labels.boundaries())
                    self._labels_key = key
                except Exception:
                    logger.debug("marks: boundaries() failed", exc_info=True)
        return marks

    def add_mark(self, name: str = "", when=None, *, source: str = "api") -> Mark:
        """Drop a point (``labels.point``): log separator line +
        ``MarksChanged`` to every lens. Without the timeline: an in-memory
        mark (and the notice "timeline unavailable").
        """
        mark = self.add_label("point", name, when, source=source)
        return mark if mark is not None else self.marks[-1]

    def add_label(
        self,
        kind: str,
        name: str = "",
        when=None,
        *,
        level: str = "top",
        source: str = "key",
        actor: str | None = None,
    ) -> Mark | None:
        """Start a label (``kind="start"``, ``level`` top/sub/nest) or drop a
        point (``kind="point"``) at ``when`` (datetime / epoch / None = now).

        ``actor``: ``"user"`` for the label keys (None = the timeline's
        current actor, ``sandroid`` outside ``acting_as``).

        Returns the event as a :class:`Mark` (None if nothing was written).
        """
        import time as _time
        from datetime import datetime

        if isinstance(when, datetime):
            t = when.timestamp()
        elif when is None:
            t = _time.time()
        else:
            t = float(when)
        name = (name or "").strip()
        labels = self.labels_api()
        if labels is None:
            mark = self.marks.add(name, datetime.fromtimestamp(t))
            self._timeline_unavailable()
            self._log_label(mark.label(), mark.when)
            self._post_marks(mark)
            return mark
        try:
            if kind == "point":
                event = labels.point(name, t=t, actor=actor, source=source)
            else:
                event = labels.start(name, level=level, t=t, actor=actor, source=source)
        except Exception:
            logger.warning("Label not written", exc_info=True)
            self._post_marks(None)  # settle a pending pre-split (Files)
            return None
        if event is None:
            self._post_marks(None)
            return None
        return self._labels_changed(event)

    def stop_label(self, when=None, *, actor: str | None = None):
        """``-``: end the innermost open label (None when nothing is open).

        ``actor``: ``"user"`` for the ``-`` key (see :meth:`add_label`).
        """
        import time as _time
        from datetime import datetime

        labels = self.labels_api()
        if labels is None:
            return None
        if isinstance(when, datetime):
            when = when.timestamp()
        try:
            event = labels.stop(
                t=_time.time() if when is None else float(when), actor=actor
            )
        except Exception:
            logger.warning("Label stop not written", exc_info=True)
            return None
        if event is not None:
            self._labels_changed(event)
        return event

    def post_marks_pending(self, when, *, ends_open: bool = False) -> None:
        """A label name prompt is open (``when``) or closed (``None``).

        ``ends_open``: the pending label is a top-level start while a label
        is open, so it will add two boundaries at ``when`` (the open label's
        end, then the new start). The message's ``pending_times`` then holds
        both, so the Files pre-split matches the final segments (activity
        typed during the prompt lands in the new label, not in the
        zero-length "after label N" segment between them).
        """
        marks = self.marks.marks
        times = [] if when is None else [when, when] if ends_open else [when]
        for spec in LENSES:
            widget = self.lens_widget(spec.id)
            if widget is not None:
                message = MarksChanged(marks, None, pending=when)
                message.pending_times = list(times)
                widget.post_message(message)

    def _timeline_unavailable(self) -> None:
        try:
            self.app.notify(
                "Timeline unavailable — kept in memory only.",
                severity="warning",
                timeout=3,
            )
        except Exception:
            pass

    def _labels_changed(self, event) -> Mark:
        """Rebuild the marks from the labels, log the event, tell the lenses."""
        from datetime import datetime

        boundary = event.kind == "point" or getattr(event, "depth", 0) == 0
        mark = Mark.from_event(event)
        self._log_label(label_event_text(event), datetime.fromtimestamp(float(event.t)))
        self._post_marks(mark if boundary else None)
        self._refresh_label_note()
        return mark

    def _log_label(self, text: str, when) -> None:
        """``Section 7 'x' · 10:42:07`` in the log (bold, the notice colour)."""
        try:
            from rich.markup import escape

            from sandroid.tui.themes import fixed_color

            color = fixed_color("notice")
            self.query_one("#activity-log", ActivityLog).write(
                f"[bold {color}]{escape(text)} · {when:%H:%M:%S}[/]"
            )
        except Exception:
            pass

    def _post_marks(self, added: Mark | None) -> None:
        marks = self.marks.marks
        for spec in LENSES:
            widget = self.lens_widget(spec.id)
            if widget is not None:
                widget.post_message(MarksChanged(marks, added))

    def _refresh_label_note(self) -> None:
        try:
            self.query_one("#shell-header", ShellHeader).refresh_timeline_state()
        except Exception:
            pass

    def refresh_privacy_indicator(self) -> None:
        """Repaint the header's privacy indicator now (the 1 s tick does it
        too); the Identity lens calls it when an apply starts or ends.
        """
        try:
            self.query_one("#shell-header", ShellHeader).refresh_privacy_state()
        except Exception:
            pass

    def flash_label_note(self, text: str) -> None:
        """Show ``text`` (``Note 4 'text'``) top right for a few seconds."""
        try:
            self.query_one("#shell-header", ShellHeader).flash_label_note(text)
        except Exception:
            pass

    def _handle_timeline_event(self, event) -> None:
        """The timeline doorbell (``TIMELINE_EVENT``, no lines): labels added
        elsewhere (AI, API), a new sink, a lock.
        """
        data = getattr(event, "data", None) or {}
        op = data.get("op")
        if op == "lines" and "label" in (data.get("srcs") or ()):
            labels = self.labels_api()
            if labels is None:
                return
            key = self._labels_cache_key(labels)
            if key is not None and key == getattr(self, "_labels_key", None):
                return
            old = getattr(self, "_marks", None)
            before = len(old) if old is not None else 0
            marks = self.marks  # rebuilds: the version changed
            added = marks[-1] if len(marks) > before else None
            self._post_marks(added)
            self._refresh_label_note()
        elif op == "bound":
            # A (re)activated sink, possibly one already open: always rebuild
            # (marks, the Files segments and the Watchlist's acquisition mark
            # follow the active device's labels).
            sink = data.get("folder") or data.get("session_id")
            self._labels_sink = str(sink) if sink else None
            self._labels_key = None
            self._post_marks(None)
            lens = self.lens_widget("timeline")
            if lens is not None and hasattr(lens, "on_timeline_bound"):
                lens.on_timeline_bound()
            self._refresh_label_note()
        elif op in ("locked", "closed"):
            self._refresh_label_note()
            lens = self.lens_widget("timeline")
            if op == "locked" and lens is not None and hasattr(lens, "note_locked"):
                lens.note_locked()

    def _post_scope(self, lens_id: str) -> None:
        widget = self.lens_widget(lens_id)
        if widget is not None:
            widget.post_message(ScopeChanged(self.scope_run, self._scope_label))

    def refresh_scope_pill(self) -> None:
        """Re-render the scope pill from the recorder/player state now.

        Called by the app on every record/replay transition and phase change
        (``SandroidTUI._set_status_bar_mode`` / ``_set_replay_phase``).
        """
        self._update_scope_pill()

    def _update_scope_pill(self) -> None:
        try:
            header = self.query_one("#shell-header", ShellHeader)
        except Exception:
            return
        recording = replaying = False
        phase = None
        try:
            bar = self.query_one("#status-bar", StatusBar)
            recording = bool(getattr(bar, "recording_active", False))
            replaying = bool(getattr(bar, "replay_active", False))
            phase = getattr(bar, "replay_phase", None)
        except Exception:
            pass
        if self.scope_run is not None:
            label = self._scope_label or f"Run {self.scope_run}"
            # ``v`` during a Play: say that the Play goes on (L10).
            busy = " · recording" if recording else (" · rewind" if replaying else "")
            header.set_pill(f"REVIEW {label}{busy}", "review")
            return
        if recording or replaying or phase:
            # Record / Rewind: ● + state word; the phase line as is
            # (core/rewind.py).
            header.set_pill(
                phase or ("● Recording" if recording else "● Rewind running"), "rec"
            )
        else:
            header.set_pill("LIVE", "")

    def _update_header(self) -> None:
        """Header breadcrumb + pill from the status bar's cached state."""
        try:
            bar = self.query_one("#status-bar", StatusBar)
            crumb = bar.breadcrumb_markup()
            self.query_one("#shell-header", ShellHeader).set_crumb(crumb)
        except Exception:
            pass
        self._update_scope_pill()

    def _deferred_mount_updates(self) -> None:
        """Run deferred updates after UI has rendered.

        This is called via call_later() from on_mount() to ensure the UI
        renders before we start updating status bar, menu, etc.
        """
        logger.debug("[MAIN_SCREEN] _deferred_mount_updates started")
        # Update UI state from Toolbox (now with background Frida checks)
        self._update_from_toolbox()

        # Set initial subtitle based on current view
        try:
            current_view = get_ui_service().get_current_view()
            self.app.update_subtitle_for_view(current_view)
        except Exception:
            pass

        # Display any buffered startup messages that were logged before TUI started
        # These were stored in EventBus history since no subscribers existed yet
        self._display_buffered_logs()

        # Land focus in the active lens (App) on startup rather than wherever
        # Textual's tab order happens to pick.
        try:
            self.query_one("#spotlight-panel").focus()
        except Exception:
            pass

    def _update_from_toolbox(self) -> None:
        """Update UI state from Toolbox."""
        try:
            # Update status bar (refresh_status = update_from_toolbox + repaint;
            # the multi-row glance band needs an explicit refresh() or it would
            # update its attributes without re-rendering on this path).
            status_bar = self.query_one("#status-bar", StatusBar)
            status_bar.refresh_status()
            self._update_header()
        except ImportError:
            logger.warning("Toolbox not available")
        except Exception as e:
            logger.error(f"Error updating from Toolbox: {e}")

    def _subscribe_to_events(self) -> None:
        """Subscribe to EventBus events.

        Uses loop.call_soon_threadsafe for non-blocking, fire-and-forget
        scheduling instead of App.call_from_thread which blocks the caller.
        call_from_thread deadlocks when:
        - Called from the main thread (self-deadlock: waits for event loop
          to process callback, but event loop IS the blocked main thread)
        - Called from a background thread that holds EventBus._handlers_lock
          while the main thread also needs that lock (cross-thread deadlock)
        """
        try:
            import asyncio

            from sandroid.core.events import EventBus, EventType

            bus = EventBus.get()

            # Capture the running event loop for thread-safe scheduling.
            # This runs on the main thread (deferred via call_later from on_mount).
            try:
                main_loop = asyncio.get_running_loop()
            except RuntimeError:
                main_loop = None

            def _safe_call(handler, event):
                """Schedule handler on main thread without blocking caller.

                Uses loop.call_soon_threadsafe (fire-and-forget) instead of
                App.call_from_thread (blocks until processed). This prevents
                deadlocks when EventBus subscribers are called from any thread.
                """
                # call_later posts to this screen's message queue (thread-safe
                # and non-blocking like call_soon_threadsafe), but the handler
                # then runs with Textual's app context set. A bare loop
                # callback runs without it, so any handler that mounts or
                # pushes a widget raised NoActiveAppError (P2-H1).
                try:
                    if main_loop is not None and not main_loop.is_closed():
                        self.call_later(handler, event)
                except RuntimeError:
                    pass  # Event loop closed during shutdown
                except Exception as e:
                    logger.debug(f"Failed to schedule event handler: {e}")

            # Map event types to their handler methods
            event_handler_map = {
                EventType.TASK_OUTPUT: self._handle_task_output,
                EventType.TASK_STARTED: self._handle_task_started,
                EventType.TASK_STOPPED: self._handle_task_stopped,
                EventType.TASK_UPDATED: self._handle_task_updated,
                EventType.LOG_MESSAGE: self._handle_log_message,
                EventType.FILE_CHANGED: self._handle_file_changed,
                EventType.HOOK_TRIGGERED: self._handle_hook_triggered,
                EventType.NETWORK_EVENT: self._handle_network_event,
                EventType.STATE_CHANGED: self._handle_snapshot_state,
            }

            def _make_callback(h):
                def _cb(event):
                    _safe_call(h, event)

                return _cb

            # The timeline doorbell (WP1); absent without the timeline core.
            timeline_event = getattr(EventType, "TIMELINE_EVENT", None)
            if timeline_event is not None:
                event_handler_map[timeline_event] = self._handle_timeline_event

            for event_type, handler in event_handler_map.items():
                cb = _make_callback(handler)
                bus.subscribe(event_type, cb)
                self._event_handlers.append((event_type, cb))

        except ImportError:
            logger.warning(
                "Events module not available, TUI will not receive background updates"
            )

    def _handle_snapshot_state(self, event) -> None:
        """Header: the snapshot a load put on the device, from every load
        path (Rewind, the AI, a load that completed late), not only the
        snapshot picker's. A load the console gave up on says so.
        """
        data = getattr(event, "data", None) or {}
        if data.get("change_type") != "snapshot_state" or not data.get("name"):
            return
        name = str(data["name"])
        if data.get("state") == "unconfirmed":
            self.note_snapshot(f"{name} (load not confirmed)")
            return
        try:
            current = self.query_one("#shell-header", ShellHeader)._snapshot
        except Exception:
            current = ""
        if current == name or current.endswith(f" · {name}"):
            return  # the picker named it already (with its slot)
        self.note_snapshot(name)

    def _handle_task_output(self, event) -> None:
        """Handle task output event."""
        if getattr(event, "source", None) in _ACTIVITY_LOG_EXCLUDED_SOURCES:
            return
        try:
            message = event.data.get("message", "")
            if message.strip():
                activity_log = self.query_one("#activity-log", ActivityLog)
                task_name = event.data.get("task_name", "unknown")
                activity_log.log_message(message, task_name)
        except Exception:
            pass
        self._safe_refresh_status_bar()

    def _handle_task_started(self, event) -> None:
        """Handle task started event."""
        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            display_name = event.data.get(
                "display_name", event.data.get("name", "Unknown")
            )
            app_name = event.data.get("app_name")
            activity_log.log_task_started(display_name, app_name)
        except Exception:
            pass
        self._safe_refresh_status_bar()

    def _handle_task_stopped(self, event) -> None:
        """Handle task stopped event."""
        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            display_name = event.data.get(
                "display_name", event.data.get("name", "Unknown")
            )
            activity_log.log_task_stopped(display_name)
        except Exception:
            pass
        self._safe_refresh_status_bar()

    def _handle_task_updated(self, event) -> None:
        """Handle task display-name change (not a lifecycle event)."""
        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            display_name = event.data.get(
                "display_name", event.data.get("name", "Unknown")
            )
            activity_log.log_task_updated(display_name)
        except Exception:
            pass
        self._safe_refresh_status_bar()

    def _handle_log_message(self, event) -> None:
        """Handle log message event (from TUILoggingHandler)."""
        message = event.data.get("message", "")
        if not message.strip():
            return
        levelno = event.data.get("levelno", 20)

        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            self._route_log_by_level(activity_log, message, levelno)
        except Exception:
            pass

    @staticmethod
    def _route_log_by_level(
        activity_log: ActivityLog, message: str, levelno: int
    ) -> None:
        """Route a log message to the appropriate ActivityLog method.

        Args:
            activity_log: The ActivityLog widget
            message: The log message
            levelno: Python logging level number
        """
        if levelno >= 40:  # ERROR and above
            activity_log.log_error(message)
        elif levelno >= 30:  # WARNING
            activity_log.log_warning(message)
        elif levelno >= 20:  # INFO
            activity_log.log_info(message)
        else:  # DEBUG
            activity_log.log_info(f"[dim]{message}[/dim]")

    def _handle_file_changed(self, event) -> None:
        """Handle file changed event."""
        activity_log = self.query_one("#activity-log", ActivityLog)
        file_path = event.data.get("file_path", "unknown")
        change_type = event.data.get("change_type", "modified")
        # Only show filename, not full path
        filename = file_path.split("/")[-1] if "/" in file_path else file_path
        activity_log.log_message(f"File {change_type}: {filename}", "files")

    def _handle_hook_triggered(self, event) -> None:
        """Handle Frida hook triggered event."""
        activity_log = self.query_one("#activity-log", ActivityLog)
        hook_name = event.data.get("hook_name", "unknown")
        method = event.data.get("method", "")
        msg = f"Hook: {hook_name}"
        if method:
            msg += f" - {method}"
        activity_log.log_message(msg, "frida")

    def _handle_network_event(self, event) -> None:
        """Handle network event."""
        activity_log = self.query_one("#activity-log", ActivityLog)
        event_type = event.data.get("event_type_name", "connection")
        dest_ip = event.data.get("dest_ip", "")
        dest_port = event.data.get("dest_port", 0)
        if dest_ip:
            msg = f"Network: {event_type} -> {dest_ip}:{dest_port}"
            activity_log.log_message(msg, "network")

    def _display_buffered_logs(self) -> None:
        """Display buffered log messages from EventBus history.

        When the TUI starts, there may be log messages that were published
        before the TUI subscribed to events. These are stored in EventBus
        history and need to be displayed in the ActivityLog.
        """
        try:
            from sandroid.core.events import EventBus, EventType

            bus = EventBus.get()

            # Get buffered LOG_MESSAGE events (up to 50, newest first)
            buffered_logs = bus.get_history(EventType.LOG_MESSAGE, count=50)

            if not buffered_logs:
                return

            activity_log = self.query_one("#activity-log", ActivityLog)
            activity_log.write("[dim]─── Startup Messages ───[/dim]")

            # Process in chronological order (oldest first, so reverse the list)
            for event in reversed(buffered_logs):
                message = event.data.get("message", "")
                levelno = event.data.get("levelno", 20)
                self._route_log_by_level(activity_log, message, levelno)

            # Add separator after startup messages
            activity_log.write("[dim]────────────────────────[/dim]")
            activity_log.write("")

        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Error displaying buffered logs: {e}")

    def switch_view(self) -> None:
        """No-op: view modes were removed from the TUI.

        TODO(modes-as-presets): Kept as a safe no-op so any lingering caller
        does not break. View modes (FORENSIC/MALWARE/SECURITY) will return as
        user-selectable presets in a later feature.
        """

    def execute_action(self, action_name: str) -> None:
        """Execute an action by name.

        Actions are executed in a background worker thread so that UI modals
        can be displayed while the action waits for user input. The UIRequestBus
        routes dialog requests to the ModalManager which runs on the main thread.

        Args:
            action_name: Name of the action to execute
        """
        activity_log = self.query_one("#activity-log", ActivityLog)

        # Validate action (view-agnostic flat catalog; modes removed)
        valid, error_msg = self._controller.validate_action(action_name)
        if not valid:
            activity_log.log_validation_error(error_msg)
            # Show modal for validation errors so user gets clear feedback
            from sandroid.tui.modals import MessageModal

            self.app.push_screen(
                MessageModal(
                    title="Action Not Available",
                    message=error_msg,
                    level="error",
                )
            )
            return

        # Get action for logging
        action = self._controller.get_action_by_name(action_name)
        if action:
            activity_log.log_action_triggered(action.display_name, action.key)

        # Execute through action queue in a background worker thread
        # This allows UIRequestBus modals to display while the action runs
        # The action code calls request_toggle_config() etc which blocks waiting
        # for modal result - this only works if we're NOT on the main thread
        if self.action_queue:
            import functools

            self.run_worker(
                functools.partial(
                    self._execute_action_sync, action_name, self.action_queue
                ),
                name=f"action_{action_name}",
                exclusive=False,
                thread=True,  # Run in thread pool
            )
        else:
            activity_log.log_error("ActionQ not initialized")
            from sandroid.tui.modals import MessageModal

            self.app.push_screen(
                MessageModal(
                    title="ActionQ Not Initialized",
                    message="The action queue is not available. Record/Play disabled.\n\n"
                    "This is a fundamental error. Please restart the application.",
                    level="error",
                )
            )

    def _execute_action_sync(self, action_name: str, action_queue: "ActionQ") -> None:
        """Execute an action synchronously (runs in worker thread).

        This runs in a thread pool worker, allowing the main Textual thread
        to remain responsive for displaying modals from UIRequestBus.

        Args:
            action_name: Name of the action to execute
            action_queue: ActionQ instance
        """
        try:
            # Get command result from execution
            from sandroid.core.actionq_commands import (
                execute_command_from_actionq,
                is_command_key,
            )

            action = self._controller.get_action_by_name(action_name)
            if action and is_command_key(action.key):
                # Execute through command system to get result. Pass the app
                # through so commands that need to drive a real main-thread
                # ``action_*`` (recorder/player) can do so via
                # ``app.call_from_thread`` instead of returning an inert
                # pointer message -- see functionality_commands.py.
                result = execute_command_from_actionq(
                    action_queue, action.key, app=self.app
                )

                # Display result message in activity log (a cancel is
                # reported as information, not as an error)
                if result.message:
                    self.app.call_from_thread(
                        self._log_command_result,
                        result.success or result.error == "cancelled",
                        result.message,
                    )

                if result.success and (result.data or {}).get("toast"):
                    self.app.call_from_thread(
                        self.app.notify, result.message, timeout=4
                    )

                # Show device settings modal (tabbed, Shift+E)
                if (
                    result.success
                    and result.data
                    and result.data.get("show_device_settings_modal")
                ):
                    self.app.call_from_thread(
                        self._show_device_settings_modal,
                        result.data.get("is_emulator", False),
                        result.data.get("has_root", False),
                    )
                # Show device info modal (scrollable, sectioned)
                elif (
                    result.success
                    and result.data
                    and result.data.get("show_device_info_modal")
                ):
                    self.app.call_from_thread(
                        self._show_device_info_modal, result.data["device_info"]
                    )

                # Show modal for validation failures or command errors
                if not result.success and result.error == "Precondition not met":
                    self.app.call_from_thread(
                        self._show_validation_error, result.message
                    )
                elif not result.success and result.error:
                    cancelled = (
                        "cancel" in (result.error or "").lower()
                        or "cancel" in (result.message or "").lower()
                    )
                    if (result.data or {}).get("no_dialog"):
                        # The message says what to do: a red toast, never a
                        # dialog that eats the next keys (N6-B6).
                        self.app.call_from_thread(
                            self.app.notify,
                            result.message or str(result.error),
                            severity="error",
                            timeout=8,
                        )
                    elif not cancelled:
                        error_msg = result.message or str(result.error)
                        self.app.call_from_thread(
                            self._show_error_modal, "Command Failed", error_msg
                        )
            else:
                # Legacy path for non-command actions
                self._controller.execute_action(action_name, action_queue)

        except ValueError as e:
            # Validation error - show modal
            self.app.call_from_thread(self._show_validation_error, str(e))
        except Exception as e:
            # Log error on main thread
            self.app.call_from_thread(self._log_action_error, str(e))

        # Refresh UI state after action on main thread
        self.app.call_from_thread(self._refresh_after_action)

    def _log_action_error(self, error_msg: str) -> None:
        """Log an action error and show error modal (called from main thread).

        Ensures errors are always visible - either in the TUI ActivityLog
        or via stderr if the ActivityLog is not available. Also shows an
        ErrorModal so the user cannot miss the error.
        """
        try:
            from textual.css.query import NoMatches

            activity_log = self.query_one("#activity-log", ActivityLog)
            activity_log.log_error(f"Action failed: {error_msg}")
        except NoMatches:
            import sys

            print(f"[ERROR] Action failed: {error_msg}", file=sys.stderr)
        except Exception as e:
            import sys

            print(f"[ERROR] Action failed: {error_msg} (also: {e})", file=sys.stderr)

        self._show_error_modal("Action Failed", error_msg)

    def _log_command_result(self, success: bool, message: str) -> None:
        """Log a command result (called from main thread)."""
        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            if success:
                activity_log.log_info(message)
            else:
                activity_log.log_error(message)
        except Exception:
            pass

    def _show_validation_error(self, error_msg: str) -> None:
        """Show validation error modal (called from main thread)."""
        self._show_error_modal("Action Not Available", error_msg)

    def _show_error_modal(self, title: str, error_msg: str) -> None:
        """Show error modal with red danger styling (called from main thread)."""
        from sandroid.tui.modals import ErrorModal

        self.app.push_screen(
            ErrorModal(
                title=title,
                message=error_msg,
            )
        )

    def _show_info_modal(self, title: str, message: str) -> None:
        """Show informational modal (called from main thread)."""
        from sandroid.tui.modals import MessageModal

        self.app.push_screen(
            MessageModal(
                title=title,
                message=message,
                level="info",
            )
        )

    def _show_device_settings_modal(self, is_emulator: bool, has_root: bool) -> None:
        """Show device settings modal (called from main thread).

        Args:
            is_emulator: Whether the device is an emulator
            has_root: Whether root access is available
        """
        from sandroid.tui.modals import DeviceSettingsModal

        self.app.push_screen(
            DeviceSettingsModal(is_emulator=is_emulator, has_root=has_root)
        )

    def _show_device_info_modal(self, info: dict) -> None:
        """Show device information modal (called from main thread).

        Args:
            info: Device info dictionary from DeviceService.get_device_info()
        """
        from sandroid.tui.modals import DeviceInfoModal

        self.app.push_screen(DeviceInfoModal(info=info))

    def _refresh_after_action(self) -> None:
        """Refresh UI state after action (called from main thread)."""
        self._update_from_toolbox()

    def execute_action_by_key(self, key: str) -> bool:
        """Execute an action by keyboard shortcut.

        Args:
            key: The key that was pressed

        Returns:
            True if an action was executed, False otherwise
        """
        action = self._controller.find_action_by_key(key)
        if action:
            # Check if action requires Frida and Frida isn't running
            if action.requires_frida:
                if not self._is_frida_running():
                    self._prompt_frida_install(action.name, action.display_name)
                    return True
            self.execute_action(action.name)
            return True

        return False

    def _is_frida_running(self) -> bool:
        """Check if Frida server is running on the active device.

        Returns:
            True if Frida is running, False otherwise
        """
        try:
            frida_service = get_frida_session_service()
            frida_manager = frida_service.get_frida_manager()
            if frida_manager:
                return frida_manager.is_frida_server_running()
        except Exception:
            pass
        return False

    def _prompt_frida_install(self, action_name: str, feature_name: str) -> None:
        """Show Frida installation modal and handle result.

        Args:
            action_name: Name of the action to execute after install
            feature_name: Display name of the feature that needs Frida
        """
        from sandroid.core.frida_manager import frida_server_auto_start_enabled
        from sandroid.core.toolbox import Toolbox
        from sandroid.tui.modals import FridaInstallModal, FridaInstallResult

        if frida_server_auto_start_enabled():  # frida.server_auto_start: no prompt
            import functools

            self.run_worker(
                functools.partial(self._install_frida_and_execute, action_name),
                name=f"frida_install_{action_name}",
                exclusive=False,
                thread=True,
            )
            return

        # Get device name
        device_name = "device"
        try:
            dm = Toolbox.get_device_manager()
            if dm.active_device:
                device_name = dm.active_device.display_name
        except Exception:
            pass

        def on_frida_result(result: FridaInstallResult) -> None:
            """Handle Frida installation modal result."""
            if result.install:
                # Install and start Frida in a worker thread
                import functools

                self.run_worker(
                    functools.partial(self._install_frida_and_execute, action_name),
                    name=f"frida_install_{action_name}",
                    exclusive=False,
                    thread=True,
                )
            else:
                # User cancelled, log it
                try:
                    activity_log = self.query_one("#activity-log", ActivityLog)
                    activity_log.log_info("Frida installation cancelled")
                except Exception:
                    pass

        self.app.push_screen(
            FridaInstallModal(device_name=device_name, feature_name=feature_name),
            on_frida_result,
        )

    def _install_frida_and_execute(self, action_name: str) -> None:
        """Install Frida server and execute the action (runs in worker thread).

        Args:
            action_name: Name of the action to execute after installation
        """
        try:
            # Log start of installation on main thread
            self.app.call_from_thread(
                lambda: self._log_to_activity("Installing Frida server...")
            )

            # Install and start Frida using FridaSessionService
            frida_service = get_frida_session_service()
            frida_manager = frida_service.get_frida_manager()
            if frida_manager:
                from sandroid.core.frida_manager import ensure_frida_server_started

                started = ensure_frida_server_started(frida_manager)

                if started:
                    # Log success
                    self.app.call_from_thread(
                        lambda: self._log_to_activity(
                            "Frida server installed and started"
                        )
                    )
                else:
                    self.app.call_from_thread(
                        lambda: self._log_to_activity(
                            "Frida server failed to start (see log / adb logcat)",
                            error=True,
                        )
                    )

                # Now execute the original action
                if self.action_queue:
                    self._controller.execute_action(action_name, self.action_queue)

        except ImportError as e:
            msg = f"Frida not available: {e}"
            self.app.call_from_thread(lambda: self._log_to_activity(msg, error=True))
        except Exception as e:
            from sandroid.core.frida_manager import describe_frida_install_error

            msg = f"Frida installation failed: {describe_frida_install_error(e)}"
            self.app.call_from_thread(lambda: self._log_to_activity(msg, error=True))

        # Refresh UI
        self.app.call_from_thread(self._refresh_after_action)

    def _log_to_activity(self, message: str, error: bool = False) -> None:
        """Log a message to the activity log (call from main thread).

        Args:
            message: Message to log
            error: If True, log as error
        """
        try:
            activity_log = self.query_one("#activity-log", ActivityLog)
            if error:
                activity_log.log_error(message)
            else:
                activity_log.log_info(message)
        except Exception:
            pass

    def _safe_refresh_status_bar(self) -> None:
        """Refresh the status bar, tolerating missing widget.

        Uses refresh_status() (update + repaint) so the glance band re-renders
        on event-driven paths (task started/stopped/output) — important now
        that the band shows live hooks/bypass/pid that change on those events.
        """
        try:
            status_bar = self.query_one("#status-bar", StatusBar)
            status_bar.refresh_status()
        except Exception:
            pass
        self._update_header()

    def refresh_status(self) -> None:
        """Refresh the status bar from current state."""
        self._safe_refresh_status_bar()

    def refresh_menu(self) -> None:
        """No-op: the menu panel was removed. Kept for caller compatibility.

        Refreshes the status bar instead so external callers still get a
        sensible UI update.
        """
        self._safe_refresh_status_bar()

    def on_unmount(self) -> None:
        """Clean up when the screen is unmounted."""
        # Unsubscribe from events
        try:
            from sandroid.core.events import EventBus

            bus = EventBus.get()
            for event_type, handler in self._event_handlers:
                bus.unsubscribe(event_type, handler)
        except ImportError:
            pass
