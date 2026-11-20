"""Interactive Help & Keybindings editor for the Sandroid TUI.

This modal screen lists every feature action grouped by category together
with its currently effective key, and lets the user rebind, reset (per row
or all), and persist the result to the static config file. Changes are
applied LIVE via :meth:`textual.app.App.set_keymap`.

Order: the keys of the lens ``?`` was pressed in come first (the list opens
there), then the Inspector's, then the global keys (General, lens
navigation, main screen, the action categories), then the AI chat dock
(input, approval prompt, agents bar, slash commands) and the log drawer,
then the other lenses, the snapshot picker and the Devices screen. A lens
key that shadows a global key (Files ``w``/``n``/``O``, App ``b``, Sessions
``n``) is listed with its lens meaning and marked
"overrides global …"; the global row says which lens uses the key for
something else -- the same key never appears twice without that context.
"""

import logging
import re

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from sandroid.core.menu_controller import Action, ActionCategory, MenuController
from sandroid.tui.key_display import format_key, key_words

logger = logging.getLogger(__name__)

# Keys that may never be assigned to a rebindable action. They are used by
# protected (priority) app functions, reserved app features, or the editor's
# own navigation / control bindings.
RESERVED: set[str] = {
    # Protected / priority app keys.
    "q",
    "D",
    "Y",
    "comma",
    "ctrl+b",
    "ctrl+p",
    "ctrl+shift+p",
    "question_mark",
    "escape",
    "ctrl+c",
    "ctrl+q",
    # Vim scroll keys + G (multiplexes vim-bottom + forensic APKs).
    "j",
    "ctrl+j",
    "ctrl+k",
    "ctrl+d",
    "ctrl+u",
    "home",
    "end",
    "G",
    # Editor / OptionList navigation + control keys.
    "up",
    "down",
    "enter",
    "pageup",
    "pagedown",
    "tab",
    "backspace",
    "delete",
    "ctrl+r",
    # Main-screen keys that work whatever has focus (MainScreen BINDINGS,
    # app.py ``0``): a rebound action on them would never run there.
    "0",  # app: snapshot picker (same as S)
    "L",  # main screen: back to live from a reviewed run
    "left_square_bracket",  # [ ] Inspector tabs
    "right_square_bracket",
    "left_curly_bracket",  # { } * Inspector content (versions, tables, base)
    "right_curly_bracket",
    "asterisk",
    "left",  # Inspector tabs (priority while it is open), type / agents bars
    "right",
    "shift+left",  # previous / next lens (lens host, main screen, Files)
    "shift+right",
    "shift+up",  # AI chat size while it is open
    "shift+down",
}

# Category display order for the editor.
_CATEGORY_ORDER: list[ActionCategory] = [
    ActionCategory.RECORDING,
    ActionCategory.SPOTLIGHT,
    ActionCategory.FILES,
    ActionCategory.EMULATOR,
    ActionCategory.ANALYSIS,
    ActionCategory.NETWORK,
    ActionCategory.SNAPSHOTS,
    ActionCategory.NAVIGATION,
]

# Panel-scoped keys: read straight from each panel's own BINDINGS so the
# catalog can never drift from what the panels actually do. Shown (fixed, not
# rebindable) after the global categories: (heading, module, class name).
_PANEL_SECTIONS: list[tuple[str, str, str]] = [
    ("Lens navigation", "sandroid.tui.screens.main_screen", "_LensHost"),
    ("Main screen", "sandroid.tui.screens.main_screen", "MainScreen"),
    ("Inspector (while open)", "sandroid.tui.widgets.lens_shell", "Inspector"),
    ("App lens", "sandroid.tui.widgets.spotlight_panel", "SpotlightPanel"),
    ("App lens › b bypass", "sandroid.tui.widgets.spotlight_panel", "BypassChordModal"),
    ("Network lens", "sandroid.tui.widgets.network_panel", "NetworkPanel"),
    ("Files lens", "sandroid.tui.widgets.files_panel", "FilesPanel"),
    ("Sessions lens", "sandroid.tui.widgets.diffs_view", "DiffsView"),
    ("Timeline lens", "sandroid.tui.widgets.timeline_lens", "TimelineLens"),
    ("Identity lens", "sandroid.tui.widgets.identity_lens", "IdentityLens"),
    (
        "Snapshot picker (S)",
        "sandroid.tui.modals.snapshot_save_choice_modal",
        "SnapshotPickerModal",
    ),
    ("Snapshot picker (S)", "sandroid.tui.widgets.snapshots_panel", "SnapshotsPanel"),
    ("Timeline lens › t type bar", "sandroid.tui.widgets.timeline_lens", "TypeBar"),
    ("AI chat", "sandroid.tui.widgets.chat_panel", "ChatPanel"),
    ("AI chat › agents bar", "sandroid.tui.widgets.chat_panel", "AgentsBar"),
    ("Devices screen (D)", "sandroid.tui.screens.devices_screen", "DevicesScreen"),
    ("Proxy settings (y)", "sandroid.tui.modals.proxy_modal", "ProxyModal"),
    (
        "Static analysis (a)",
        "sandroid.tui.modals.static_analysis_modal",
        "StaticAnalysisModal",
    ),
]

#: Lens id -> the ``_PANEL_SECTIONS`` headings that belong to that lens.
_LENS_SECTIONS: dict[str, tuple[str, ...]] = {
    "app": ("App lens", "App lens › b bypass"),
    "network": ("Network lens",),
    "files": ("Files lens",),
    "runs": ("Sessions lens",),
    "timeline": ("Timeline lens", "Timeline lens › t type bar"),
    "identity": ("Identity lens",),
}
#: Display-only rows listed first in a lens's section: keys the lens gets
#: from elsewhere (Enter = MainScreen's inspect, Tab = focus order), which
#: its own BINDINGS cannot show. ``(key display, description, raw keys)``.
_LENS_EXTRA_ROWS: dict[str, list[tuple[str, str, tuple[str, ...]]]] = {
    "App lens": [
        ("Enter", "Inspect the selected row (Evidence / Raw tabs)", ("enter",)),
        ("Tab / Shift+Tab", "Next / previous section", ("tab", "shift+tab")),
    ],
    "Network lens": [
        ("Enter", "Inspect the selected flow", ("enter",)),
        ("Esc", "Clear the / filter, then leave the AI filter (H)", ()),
    ],
    "Files lens": [
        ("Esc", "Clear the / filter, then leave the AI filter (H)", ()),
    ],
    "Identity lens": [
        ("Enter", "Inspect the selected value (Found / Value tabs)", ("enter",)),
        ("{ / }", "Inspector: previous / next hit", ()),
    ],
    "Timeline lens": [
        (
            "Enter",
            "Inspect the line (Line/JSON/Ref/Chain); a folded row: open / close",
            ("enter",),
        ),
        (
            "Up/Dn PgUp/Dn",
            "Move (up stops following the newest line; End = live)",
            ("up", "down"),
        ),
        # No raw key (as Network / Files): the lens handles Esc first, then
        # the global Esc applies; no "overrides global" note to cut the row.
        ("Esc", "Close / or the type bar; clear the filter; show hidden types", ()),
    ],
    "Timeline lens › t type bar": [
        ("Esc", "Back to the list", ("escape",)),
    ],
    "AI chat": [
        ("Enter", "Send the message", ("enter",)),
        ("/", "Slash command (the list is below)", ("slash",)),
        ("Esc", "Back to the lens (the chat stays open)", ("escape",)),
    ],
    "Devices screen (D)": [
        ("Enter", "Attach a running device / start a stopped AVD", ("enter",)),
    ],
}
#: Longer help text for terse footer labels: ``(heading, raw key) -> text``.
#: Only the wording comes from here; the key itself must be in the class's
#: BINDINGS (a test checks it), so a removed binding drops its row.
_ROW_TEXT: dict[tuple[str, str], str] = {
    ("Main screen", "L"): "Back to live (while reviewing a run)",
    ("Timeline lens", "slash"): (
        "Filter: text, src: kind: actor: phase: run: world: pkg: level: -src:"
    ),
    ("AI chat", "ctrl+x"): "Stop the turn and its agents",
    ("AI chat", "ctrl+l"): "New thread (not while a turn runs)",
    ("AI chat", "up"): "To the agents bar (when the thread has agents)",
    ("AI chat", "pageup"): "Scroll the transcript up",
    ("AI chat", "pagedown"): "Scroll the transcript down",
    ("AI chat", "ctrl+home"): "Top of the transcript",
    ("AI chat", "ctrl+end"): "End of the transcript",
    ("Devices screen (D)", "c"): "Cold boot on / off (else a quick boot)",
    ("Devices screen (D)", "n"): "Snapshot to boot from…",
    ("Devices screen (D)", "h"): "Headless on / off (no emulator window)",
    ("Devices screen (D)", "s"): "Save state on exit on / off",
    ("Devices screen (D)", "w"): "Wipe data on the next start (once)",
    ("Devices screen (D)", "e"): "Rename the AVD…",
    ("Devices screen (D)", "x"): "Stop the emulator… (asks first)",
    ("Devices screen (D)", "R"): "Restart the emulator",
    ("Devices screen (D)", "a"): "adb connect host:port…",
    ("Devices screen (D)", "ctrl+r"): "Refresh (rescan the AVDs)",
    ("Devices screen (D)", "escape"): "Close (an open snapshot list first)",
    ("Devices screen (D)", "ctrl+c"): "Quit (at startup: stop the start)",
    ("Proxy settings (y)", "r"): "Remove CA (asks first)",
    ("Inspector (while open)", "left"): "Previous tab (unless the focus uses Left)",
    ("Inspector (while open)", "right"): "Next tab (unless the focus uses Right)",
    ("Inspector (while open)", "left_square_bracket"): "Previous tab (always)",
    ("Inspector (while open)", "right_square_bracket"): "Next tab (always)",
    ("Static analysis (a)", "enter"): "Start the analysis (Esc cancels)",
    ("Static analysis (a)", "p"): "Switch the analysis profile (privacy, generic)",
    ("Static analysis (a)", "t"): "Trackers on / off",
    ("Static analysis (a)", "s"): "Security analysis on / off",
    ("Static analysis (a)", "v"): "Verbose output on / off",
    ("Proxy settings (y)", "shift+left"): "Previous tab (in an empty text field)",
    ("Proxy settings (y)", "shift+right"): "Next tab (in an empty text field)",
}
#: Sections listed by hand: keys handled outside BINDINGS (the log is a
#: plain RichLog) or whose BINDINGS labels say nothing ("Option 1"). A test
#: checks that the raw keys cover the class's real bindings.
_HAND_SECTIONS: dict[str, list[tuple[str, str, tuple[str, ...]]]] = {
    "AI chat › approval prompt": [
        ("1", "Yes (this call)", ("1",)),
        (
            "2",
            "Yes, don't ask again for the offered rule (without a rule: No)",
            ("2",),
        ),
        ("3", "No, and tell it what to do instead (type, then Enter)", ("3",)),
        ("Up / Down", "Move between the options", ("up", "down")),
        ("Enter", "Pick the highlighted option", ("enter",)),
        ("Esc", "No (with the note typed so far)", ("escape",)),
    ],
    "Log drawer": [
        ("`", "Open / close the drawer (Esc closes it too)", ("grave_accent",)),
        (
            "Up/Dn PgUp/Dn",
            "Scroll the log (click into it first)",
            ("up", "down", "pageup", "pagedown"),
        ),
        ("Home / End", "Oldest / newest line (click into it first)", ("home", "end")),
        ("j / Ctrl+K", "Log a line down / up (also Ctrl+J)", ("j", "ctrl+j", "ctrl+k")),
        ("Ctrl+D / U", "Log half a page down / up", ("ctrl+d", "ctrl+u")),
        ("Shift+Y", "Copy the whole log", ("Y",)),
    ],
    "Review (p)": [
        ("Space", "Select a file or request to compare", ("space",)),
        (
            "Enter",
            "Rewind, or Rewind + Replay (requests are compared after a replay)",
            ("enter",),
        ),
        ("Esc", "Close (asks once when nothing is selected)", ("escape",)),
    ],
}
#: Main-screen bindings with this description prefix size the AI chat:
#: listed in the AI chat section.
_CHAT_PREFIX = "AI chat "
#: Sections for the AI chat dock and the log drawer, after the global
#: action categories (in this order).
_DOCK_SECTIONS = (
    "Review (p)",
    "AI chat",
    "AI chat › approval prompt",
    "AI chat › agents bar",
    "AI chat › slash commands",
    "Log drawer",
)
#: Headings of the global (works everywhere) panel sections.
_GLOBAL_PANEL_SECTIONS = ("Lens navigation", "Main screen")
#: Main-screen bindings with this description prefix are Inspector keys
#: (``[`` ``]`` ``{`` ``}`` ``*``): listed in the Inspector section.
_INSPECTOR_PREFIX = "Inspector: "

#: App-wide keys that no MenuController action describes (they are plain App
#: bindings without a rebindable id). Listed first, under "General".
_GENERAL_KEYS: list[tuple[str, str]] = [
    ("question_mark", "This help"),
    ("escape", "Chat to lens, then close Inspector / log drawer / chat, dialogs"),
    ("ctrl+b", "Focus the lens (back from the chat or Inspector)"),
    ("comma", "Settings"),
    ("0", "Snapshot picker (same as S)"),
    ("ctrl+p", "SSL unpinning on/off (armed until the app runs)"),
    ("Y", "Copy the log"),
    ("ctrl+c", "Quit (asks first, like q)"),
    ("ctrl+q", "Quit (asks first, like q)"),
]

#: Binding ids from earlier releases that may linger in a user's
#: ``tui.keybindings``: never applied (``app.effective_keymap``), shown or
#: re-saved. ``load_slot_N``: digits are lenses now (slots load from the
#: snapshot picker); ``pick_save_slot``: ``S`` opens the picker (``s`` inside
#: it saves to a slot); ``trigdroid``: ``t`` opened TrigDroid's bypass
#: wrapper, which BypassService (the App lens's ``b`` chord) replaced.
LEGACY_BINDING_IDS = frozenset(
    {f"load_slot_{i}" for i in range(1, 9)} | {"pick_save_slot", "trigdroid"}
)


#: Option-id prefix of the (non-rebindable) panel-key rows.
_PANEL_PREFIX = "panel:"


def _panel_bindings(module: str, cls_name: str) -> list[tuple[str, str]]:
    """``[(key display, description)]`` of a panel class's own BINDINGS.

    Keys with the same description are merged into one row (``o / b``,
    ``Del / Backspace``), and ``<desc> 1`` .. ``<desc> N`` bound to the digit
    keys collapse to one ``<desc> 1-N`` row. Best effort: ``[]`` on errors.
    """
    return [
        (shown, desc) for shown, desc, _raw in _panel_binding_rows(module, cls_name)
    ]


def _panel_binding_rows(
    module: str, cls_name: str
) -> list[tuple[str, str, tuple[str, ...]]]:
    """Like :func:`_panel_bindings`, plus each row's raw binding keys."""
    import importlib

    try:
        cls = getattr(importlib.import_module(module), cls_name)
    except Exception:
        return []
    merged: dict[str, list[str]] = {}
    raw: dict[str, list[str]] = {}
    for entry in cls.__dict__.get("BINDINGS", []):
        if isinstance(entry, Binding):
            key, desc = entry.key, entry.description
            shown = entry.key_display or _format_key_display(key)
        else:
            key, desc = entry[0], (entry[2] if len(entry) > 2 else "")
            shown = _format_key_display(key)
        if not desc:
            continue
        digit = re.fullmatch(r"(.*\S) (\d)", desc)
        if digit and key == digit.group(2):
            desc, shown = f"{digit.group(1)} #", key
        keys = merged.setdefault(desc, [])
        if shown not in keys:
            keys.append(shown)
        raw.setdefault(desc, []).extend(k.strip() for k in key.split(","))
    rows: list[tuple[str, str, tuple[str, ...]]] = []
    for desc, keys in merged.items():
        if desc.endswith(" #"):
            span = f"{keys[0]}-{keys[-1]}" if len(keys) > 1 else keys[0]
            rows.append((span, f"{desc[:-2]} {span}", tuple(raw[desc])))
        else:
            rows.append((" / ".join(keys), desc, tuple(raw[desc])))
    return rows


def _slash_rows() -> list[tuple[str, str, tuple[str, ...]]]:
    """The chat's slash commands, from its own ``SLASH_HELP`` (best effort)."""
    try:
        from sandroid.tui.widgets.chat_panel import SLASH_HELP
    except Exception:
        return []
    return [(name, _cap(text), ()) for name, text in SLASH_HELP.items()]


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:]


def _same_meaning(global_name: str, lens_desc: str) -> bool:
    """``SSL unpinning on/off`` vs the Network lens's ``SSL unpin``: one
    action under two labels, not a lens key overriding a global one.
    """
    a, b = global_name.lower(), lens_desc.lower()
    return a.startswith(b) or b.startswith(a) or a in b


def _current_lens(app) -> str | None:
    """The active lens of the main screen below the help (None if unknown)."""
    for screen in reversed(getattr(app, "screen_stack", [])):
        lens = getattr(screen, "active_lens", None)
        if isinstance(lens, str):
            return lens
    return None


# Column widths for the aligned row layout (command / description / key) on
# a wide terminal. ``HelpScreen._fit_columns`` shrinks them to the screen
# (the description column goes first); the detail pane below the list shows
# the highlighted row's full, untruncated text regardless.
_NAME_W = 32
_DESC_W = 50
_KEY_W = 18

#: Below this many rows (or 100 columns) the help drops its margins and the
#: detail pane, so the list keeps most of an 80x24 terminal.
_COMPACT_HEIGHT = 32


def _format_key_display(key: str) -> str:
    """Format a key string for human display, keeping Shift visible.

    ``c`` stays ``c`` while ``C`` (Shift+C) becomes ``Shift+C`` -- the old
    upper-casing made every lower/upper pair (c/C, e/E, f/F, g/G) look
    identical. See :func:`sandroid.tui.key_display.format_key`. Glyphs are
    written as words (:func:`key_words`).
    """
    return key_words(format_key(key, "long"))


class HelpScreen(ModalScreen):
    """Interactive Help & Keybindings editor.

    Lists all feature actions grouped by category with their effective keys.
    Rebindable rows can be selected (Enter) to capture a new key; reserved or
    already-used keys trigger a press-again confirmation. Changes persist to
    the static config and are applied live.
    """

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
        background: rgba(5, 8, 17, 0.85);
    }

    #kb-container {
        width: 112;
        max-width: 100%;
        height: 90%;
        max-height: 48;
        background: #0d1117;
        border: round #2f81f7;
        padding: 1 2;
    }

    #kb-title {
        text-align: center;
        text-style: bold;
        color: #58a6ff;
        margin-bottom: 1;
        width: 100%;
    }

    #kb-list {
        height: 1fr;
        background: #161b22;
        border: solid #30363d;
    }

    #kb-list:focus {
        border: solid #2f81f7;
    }

    #kb-detail {
        height: auto;
        min-height: 6;
        background: #161b22;
        border: solid #30363d;
        padding: 0 1;
        margin-top: 1;
    }

    #kb-footer {
        text-align: center;
        color: #8b949e;
        margin-top: 1;
        width: 100%;
    }

    HelpScreen.-compact #kb-container {
        height: 100%;
        max-height: 100%;
        padding: 0 1;
    }
    HelpScreen.-compact #kb-title,
    HelpScreen.-compact #kb-footer {
        margin: 0;
    }
    HelpScreen.-compact #kb-detail {
        display: none;
    }
    """

    BINDINGS = [
        Binding("escape", "close", "Close", priority=True),
        Binding("question_mark", "close", "Close", priority=True),
        Binding("q", "close", "Close", priority=True),
        Binding("backspace", "reset_row", "Reset row", show=False),
        Binding("delete", "reset_row", "Reset row", show=False),
        Binding("ctrl+r", "reset_all", "Reset all", show=False),
    ]

    def __init__(
        self,
        current_view=None,
        name: str = None,
        id: str = None,
        classes: str = None,
        lens: str | None = None,
    ):
        """Initialize the keybinding editor.

        Args:
            current_view: Ignored (retained for caller compatibility; the flat
                catalog no longer needs a view).
            name: Screen name.
            id: Screen ID.
            classes: CSS classes.
            lens: Lens id whose keys lead the list (default: the main
                screen's active lens).
        """
        super().__init__(name=name, id=id, classes=classes)
        self._lens = lens
        # Shadowed keys: (section heading, key display) -> the global action
        # name it overrides; raw global key -> "Files lens: Watch" notes.
        self._overrides: dict[tuple[str, str], str] = {}
        self._global_notes: dict[str, list[str]] = {}
        self._controller = MenuController.get()
        # Rebindable id -> default key; populated in on_mount once the app and
        # its BINDINGS are reliably reachable.
        self._defaults: dict[str, str] = {}
        # Working copy of the user overrides (only non-default entries).
        self._pending: dict[str, str] = {}
        # Capture state.
        self._capturing: bool = False
        self._capture_id: str | None = None
        # Pending conflict confirmation: (action_id, key) awaiting a re-press.
        self._pending_candidate: tuple[str, str] | None = None
        # Column widths fitted to the terminal (see _fit_columns).
        self._widths: tuple[int, int, int] = (_NAME_W, _DESC_W, _KEY_W)

    # -- Data helpers ---------------------------------------------------------

    def _effective_key(self, action_id: str) -> str | None:
        """Return the effective key for an action id (override or default)."""
        return self._pending.get(action_id) or self._defaults.get(action_id)

    def _conflict_owner(self, action_id: str, key: str) -> str | None:
        """Find what currently owns ``key`` (other than ``action_id``).

        Args:
            action_id: The action being rebound (its own key is ignored).
            key: The candidate key.

        Returns:
            A human-readable description of the conflicting owner, or None if
            the key is free for ``action_id``. Note: RESERVED keys are handled
            separately (hard-rejected) by the caller, so they are not reported
            here — this only covers action-vs-action collisions (overridable).
        """
        for other_id in self._defaults:
            if other_id == action_id:
                continue
            other_key = self._pending.get(other_id, self._defaults[other_id])
            if other_key == key:
                action = self._controller.get_action_by_name(other_id)
                return action.display_name if action else other_id
        return None

    # -- Layout ---------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """Create the editor layout."""
        with Vertical(id="kb-container"):
            yield Static(
                "[bold #58a6ff]Help & Keybindings[/]",
                id="kb-title",
            )
            yield OptionList(id="kb-list")
            yield Static("", id="kb-detail")
            yield Static(self._footer_text(), id="kb-footer")

    def on_mount(self) -> None:
        """Build the data model and option list once mounted."""
        app = self.app
        if self._lens is None:
            self._lens = _current_lens(app)
        self._defaults = {b.id: b.key for b in app.BINDINGS if b.id}
        cfg = getattr(app, "sandroid_config", None)
        if cfg is not None and getattr(cfg, "tui", None) is not None:
            # Drop retired ids so they neither crash nor get re-persisted.
            self._pending = {
                k: v
                for k, v in dict(cfg.tui.keybindings or {}).items()
                if k not in LEGACY_BINDING_IDS and isinstance(v, str)
            }
        else:
            self._pending = {}
        self._fit_columns()
        self._rebuild_list()
        # The list's real width is known after the first layout.
        self.call_after_refresh(self._refit)

    def on_resize(self, event) -> None:
        """Re-fit the columns (and compact mode) to a resized terminal."""
        try:
            width, height = self.app.size.width, self.app.size.height
            self.set_class(height < _COMPACT_HEIGHT or width < 100, "-compact")
        except Exception:
            pass
        self.call_after_refresh(self._refit)

    def _refit(self) -> None:
        if self._fit_columns():
            self._rebuild_list()

    def _fit_columns(self) -> bool:
        """Size the row columns to the list's width; True if anything changed.

        Uses the list's laid-out content width (before the first layout: an
        estimate from the terminal size). The key column keeps its width, the
        name column shrinks to 16, and the description column takes the rest
        (it is dropped below 12 cells -- the detail pane has the full text).
        Also switches the compact layout (no margins, no detail pane) on
        terminals under 32 rows or 100 columns.
        """
        try:
            width, height = self.app.size.width, self.app.size.height
        except Exception:
            return False
        compact = height < _COMPACT_HEIGHT or width < 100
        inner = 0
        try:
            inner = self.query_one(
                "#kb-list", OptionList
            ).scrollable_content_region.width
        except Exception:
            inner = 0
        if inner <= 0:
            inner = min(112, width) - (8 if compact else 12)
        name_w = max(16, min(_NAME_W, inner - _KEY_W - 2 - 24))
        desc_w = inner - name_w - 2 - _KEY_W
        if desc_w < 12:
            desc_w = 0
            name_w = max(12, inner - _KEY_W)
        widths = (name_w, min(desc_w, _DESC_W), _KEY_W)
        changed = widths != self._widths or compact != self.has_class("-compact")
        self._widths = widths
        self.set_class(compact, "-compact")
        return changed

    @staticmethod
    def _footer_text() -> str:
        """Return the default footer hint text."""
        return (
            "[dim]Up/Down navigate · Enter rebind · Backspace reset row · "
            "Ctrl+R reset all · Esc close[/dim]"
        )

    @staticmethod
    def _row_description(action: Action) -> str:
        """Description-column text."""
        if action.name.startswith("save_slot_"):
            return "save current state"
        return action.description or action.display_name

    def _columns(self, name: str, desc: str, key_display: str, *, colored: bool) -> str:
        """Lay out a row as aligned columns; pad on plain text, colour the key.

        Rich markup has no visible width, so the command/description columns are
        padded as plain text and only the (right-aligned) key gets colour.
        Widths come from :meth:`_fit_columns`; a zero description width drops
        that column.
        """
        name_w, desc_w, key_w = self._widths
        if not desc and desc_w:
            # No description (panel keys): the name uses both columns.
            name_w, desc_w = name_w + 2 + desc_w, 0
        if len(name) > name_w:
            name = name[: name_w - 1] + "…"
        if len(desc) > desc_w:
            desc = (desc[: desc_w - 1] + "…") if desc_w else ""
        bracket = f"[{key_display}]"  # plain, for width
        pad = max(1, key_w - len(bracket))
        name_field = name.ljust(name_w)
        desc_field = f"  {desc.ljust(desc_w)}" if desc_w else ""
        if colored:
            key_field = (" " * pad) + f"[bold #ff79c6]\\[{key_display}][/]"
        else:
            key_field = (" " * pad) + f"\\[{key_display}]"
        return f"{name_field}{desc_field}{key_field}"

    def _rebuild_list(self) -> None:
        """Rebuild the OptionList rows from the current effective keys."""
        try:
            option_list = self.query_one("#kb-list", OptionList)
        except Exception:
            return

        previous = option_list.highlighted
        option_list.clear_options()

        by_category: dict[ActionCategory, list[Action]] = {}
        for action in self._controller.get_all_actions():
            # ``switch_view`` is retired in the TUI (view modes removed); keep
            # it out of the editor. TODO(modes-as-presets): surface presets here.
            if action.name == "switch_view":
                continue
            # ``remove_file``/``pull_files``/``pull_spotlight_db`` no longer
            # have a live app.py Binding — Watchlist's in-tab row actions
            # (d/p/P) replaced their global v/u/space keys, with no
            # global-key equivalent. The MenuController registrations
            # themselves are kept (not removed) because the legacy Rich-CLI
            # path (``ActionQ.parse_interactive_char`` ->
            # ``MenuController.get_action_by_key``) still validates and
            # dispatches those same keys to the (still-shared)
            # ``commands/forensic_commands.py`` handlers. Without this
            # exclusion they'd fall into the generic "(fixed)" bucket below
            # and read as live TUI shortcuts when v/u/space now do nothing
            # in the TUI at all.
            if action.name in (
                "remove_file",
                "pull_files",
                "pull_spotlight_db",
            ):
                continue
            by_category.setdefault(action.category, []).append(action)

        # -- collect: global action rows, panel sections ---------------------
        def action_order(a: Action):
            # The main flow (Record, Review) leads, digit keys (the lenses
            # 1-6) follow in key order; the rest alphabetical.
            return (
                a.name not in ("record", "play"),
                a.name != "record",
                not str(a.key or "").isdigit(),
                str(a.key) if str(a.key or "").isdigit() else "",
                a.display_name.lower(),
            )

        global_keys: dict[str, str] = dict(_GENERAL_KEYS)
        categories: list[tuple[ActionCategory, list[tuple[Action, str]]]] = []
        for category in _CATEGORY_ORDER:
            actions = by_category.get(category)
            if not actions:
                continue
            block = []
            for action in sorted(actions, key=action_order):
                rebindable = action.name in self._defaults
                key = self._effective_key(action.name) if rebindable else action.key
                block.append((action, key))
                if key:
                    global_keys.setdefault(key, action.display_name)
            categories.append((category, block))

        sections: dict[str, list[tuple[str, str, tuple[str, ...]]]] = {}
        for heading, module, cls_name in _PANEL_SECTIONS:
            rows = _panel_binding_rows(module, cls_name)
            if heading == "Main screen":
                for prefix, target in (
                    (_INSPECTOR_PREFIX, "Inspector (while open)"),
                    (_CHAT_PREFIX, "AI chat"),
                ):
                    moved = [r for r in rows if r[1].startswith(prefix)]
                    rows = [r for r in rows if r not in moved]
                    sections.setdefault(target, []).extend(
                        (k, _cap(d[len(prefix) :]), raw) for k, d, raw in moved
                    )
            sections.setdefault(heading, []).extend(rows)
        for heading, extra in _LENS_EXTRA_ROWS.items():
            sections[heading] = [*extra, *sections.get(heading, [])]
        for heading, hand in _HAND_SECTIONS.items():
            sections[heading] = list(hand)
        sections["AI chat › slash commands"] = _slash_rows()
        for heading, rows in sections.items():
            sections[heading] = [
                (shown, _ROW_TEXT.get((heading, raw[0]), desc) if raw else desc, raw)
                for shown, desc, raw in rows
            ]

        # A lens key that is also a global key: the lens meaning wins while
        # the lens has focus -- say so on both rows.
        self._overrides = {}
        self._global_notes = {}
        for lens_id, headings in _LENS_SECTIONS.items():
            for heading in headings[:1]:  # the lens itself, not its chords
                for shown, desc, raw in sections.get(heading, []):
                    for key in raw:
                        name = global_keys.get(key)
                        if name is None or _same_meaning(name, desc):
                            continue  # not global, or the same meaning
                        self._overrides[(heading, shown)] = (
                            f"{_format_key_display(key)} = {name}"
                        )
                        self._global_notes.setdefault(key, []).append(
                            f"{heading.split()[0]}: {desc}"
                        )

        # -- emit, in order ----------------------------------------------------
        first_enabled: int | None = None
        lead: int | None = None

        def add(option: Option) -> int:
            option_list.add_option(option)
            return option_list.option_count - 1

        def heading_row(text: str) -> None:
            add(Option(f"[dim]── {text} ──[/]", disabled=True))

        def panel_section(heading: str) -> int | None:
            rows = sections.get(heading) or []
            if not rows:
                return None
            heading_row(heading)
            first = None
            for shown, desc, _raw in rows:
                override = self._overrides.get((heading, shown))
                text = f"{desc} · overrides global {override}" if override else desc
                label = self._columns(text, "", shown, colored=False)
                color = "#e3b341" if override else "#8b949e"
                # Enabled (so the list can scroll down to it from the
                # keyboard) but not rebindable: no id in self._defaults.
                index = add(
                    Option(
                        f"[{color}]{label}[/]", id=f"{_PANEL_PREFIX}{heading}|{shown}"
                    )
                )
                first = index if first is None else first
            return first

        current = _LENS_SECTIONS.get(self._lens or "", ())
        for heading in current:
            index = panel_section(heading)
            if lead is None:
                lead = index
        if current and lead is not None:
            add(
                Option(
                    "[dim]   this lens's keys (above) win over global ones[/]",
                    disabled=True,
                )
            )
        panel_section("Inspector (while open)")

        heading_row("General")
        for key, desc in _GENERAL_KEYS:
            label = self._columns(desc, "", _format_key_display(key), colored=False)
            add(
                Option(
                    f"[#8b949e]{label}[/]",
                    id=f"{_PANEL_PREFIX}General|{_format_key_display(key)}",
                )
            )
        for heading in _GLOBAL_PANEL_SECTIONS:
            panel_section(heading)
        for category, block in categories:
            heading_row(category.name.title())
            for action, key in block:
                rebindable = action.name in self._defaults
                key_display = _format_key_display(key)
                desc = self._row_description(action)
                name = action.display_name
                notes = self._global_notes.get(key or "")
                if notes:
                    # Same key, other meaning in a lens: say so first in the
                    # description (the detail pane has the lens meanings).
                    lenses = ", ".join(n.split(":")[0] for n in notes)
                    desc = f"not in {lenses} · {desc}"
                if rebindable:
                    label = self._columns(name, desc, key_display, colored=True)
                    index = add(Option(label, id=action.name))
                    if first_enabled is None:
                        first_enabled = index
                else:
                    label = self._columns(name, desc, key_display, colored=False)
                    # Not rebindable: dim (the detail pane says "fixed").
                    add(Option(f"[dim]{label}[/]", disabled=True))

        for heading in _DOCK_SECTIONS:
            panel_section(heading)
        shown_lens_headings = {h for hs in _LENS_SECTIONS.values() for h in hs}
        for headings in _LENS_SECTIONS.values():
            if headings == current:
                continue
            for heading in headings:
                panel_section(heading)
        for heading, _module, _cls in _PANEL_SECTIONS:
            if (
                heading in shown_lens_headings
                or heading in _GLOBAL_PANEL_SECTIONS
                or heading in _DOCK_SECTIONS
                or heading in ("Inspector (while open)",)
            ):
                continue
            if heading in sections:
                panel_section(heading)
                sections.pop(heading)  # listed once (two classes, one heading)

        # Restore / set highlight: the current lens's first key, else the
        # first rebindable row.
        if previous is not None and 0 <= previous < option_list.option_count:
            option_list.highlighted = previous
        elif lead is not None:
            option_list.highlighted = lead
            option_list.scroll_to(y=0, animate=False)
        elif first_enabled is not None:
            option_list.highlighted = first_enabled
        self._refresh_detail()

    # -- Detail pane ----------------------------------------------------------

    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted
    ) -> None:
        """Show the highlighted action's full detail in the pane below the list."""
        oid = getattr(event.option, "id", None)
        self._set_detail(self._detail_markup(oid) if oid else "")

    def _refresh_detail(self) -> None:
        """Re-render the detail pane for the currently highlighted row."""
        try:
            option_list = self.query_one("#kb-list", OptionList)
            highlighted = option_list.highlighted
            if highlighted is None:
                self._set_detail("")
                return
            option = option_list.get_option_at_index(highlighted)
        except Exception:
            return
        oid = getattr(option, "id", None)
        self._set_detail(self._detail_markup(oid) if oid else "")

    def _set_detail(self, markup: str) -> None:
        """Update the detail-pane text, tolerating a not-yet-mounted widget."""
        try:
            self.query_one("#kb-detail", Static).update(markup)
        except Exception:
            pass

    def _detail_markup(self, action_id: str) -> str:
        """Full, untruncated detail for one action: name · category, description, key."""
        if action_id.startswith(_PANEL_PREFIX):
            # The id carries the key as displayed (merged rows: "o / b").
            heading, _, key = action_id[len(_PANEL_PREFIX) :].partition("|")
            if heading == "General":
                where = "Works everywhere on the main screen."
            elif heading.startswith("AI chat"):
                where = "Works in the AI chat (Ctrl+Y opens it)."
            elif heading == "Log drawer":
                where = "Works on the log drawer (` opens it)."
            elif heading.startswith("Devices screen"):
                where = "Works on the Devices screen (Shift+D opens it)."
            else:
                where = (
                    "Works only while this lens / view has focus "
                    "(1-6 or Shift+Left/Right switch lenses)."
                )
            override = self._overrides.get((heading, key))
            if override:
                where += (
                    f" Overrides the global key {override} while this lens has focus."
                )
            return (
                f"[bold #58a6ff]{heading}[/]  [dim]·  panel key[/]\n\n"
                f"[#c9d1d9]{where}[/]\n\n"
                f"[dim]Key[/]  [#8b949e]\\[{key}][/]"
                "   [dim](fixed — cannot be rebound)[/]"
            )
        action = self._controller.get_action_by_name(action_id)
        if action is None:
            return ""
        rebindable = action.name in self._defaults
        full_desc = action.description or action.display_name
        cat = action.category.name.title()
        cur = self._effective_key(action.name) if rebindable else action.key
        cur_disp = _format_key_display(cur)

        head = f"[bold #58a6ff]{action.display_name}[/]  [dim]·  {cat}[/]"
        body = f"[#c9d1d9]{full_desc}[/]"
        notes = self._global_notes.get(cur or "")
        if notes:
            body += (
                f"\n[#e3b341]Not while these lenses have focus — the key means "
                f"something else there: {'; '.join(notes)}.[/]"
            )
        if rebindable:
            default = self._defaults.get(action.name)
            key_line = f"[dim]Key[/]  [bold #ff79c6]\\[{cur_disp}][/]"
            if cur != default:
                key_line += (
                    f"   [dim]default[/] "
                    f"[#8b949e]\\[{_format_key_display(default)}][/]"
                    f" [yellow](overridden)[/]"
                )
            else:
                key_line += "   [dim](default)[/]"
            key_line += "   [dim]· Enter to rebind[/]"
        else:
            key_line = (
                f"[dim]Key[/]  [#8b949e]\\[{cur_disp}][/]"
                "   [dim](fixed — cannot be rebound)[/]"
            )
        return f"{head}\n\n{body}\n\n{key_line}"

    # -- Capture mode ---------------------------------------------------------

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Begin capture when a rebindable row is selected (Enter/click)."""
        if self._capturing:
            return
        option_id = event.option.id
        if option_id and option_id in self._defaults:
            self._begin_capture(option_id)

    def _begin_capture(self, action_id: str) -> None:
        """Enter capture mode for ``action_id``."""
        self._capturing = True
        self._capture_id = action_id
        self._pending_candidate = None
        action = self._controller.get_action_by_name(action_id)
        name = action.display_name if action else action_id
        self._set_footer(f'[yellow]Press a key for "{name}"… (Esc to cancel)[/]')

    def _set_footer(self, markup: str) -> None:
        """Update the footer hint text."""
        try:
            self.query_one("#kb-footer", Static).update(markup)
        except Exception:
            pass

    def _cancel_capture(self) -> None:
        """Exit capture mode without applying a change."""
        self._capturing = False
        self._capture_id = None
        self._pending_candidate = None
        self._set_footer(self._footer_text())

    def on_key(self, event) -> None:
        """Intercept keys while capturing a new binding.

        When not capturing, normal handling proceeds (do not stop the event).
        """
        if not self._capturing:
            return

        key = event.key
        event.stop()
        event.prevent_default()

        action_id = self._capture_id
        # Leave capture state; specific branches re-enter where needed.
        self._capturing = False
        self._capture_id = None

        if action_id is None:
            self._set_footer(self._footer_text())
            return

        # Defensive cancel (escape is priority and normally won't reach here).
        if key == "escape":
            self._pending_candidate = None
            self._set_footer(self._footer_text())
            return

        # Conflict confirmation: a re-press of the same pending candidate.
        if self._pending_candidate is not None:
            pend_id, pend_key = self._pending_candidate
            self._pending_candidate = None
            if pend_id == action_id and key == pend_key:
                self._assign(action_id, key)
            else:
                self._set_footer("[yellow]Rebind cancelled.[/] " + self._footer_text())
            return

        # Reserved/protected keys can NEVER be assigned — hard reject (no
        # press-again override path, unlike an action-vs-action conflict).
        if key in RESERVED:
            self._pending_candidate = None
            self._set_footer(
                f"[red]Key '{_format_key_display(key)}' is reserved and cannot "
                f"be assigned.[/] " + self._footer_text()
            )
            return

        owner = self._conflict_owner(action_id, key)
        if owner is not None:
            # Require an explicit re-press to override.
            self._pending_candidate = (action_id, key)
            self._capturing = True
            self._capture_id = action_id
            self._set_footer(
                f"[red]Key '{_format_key_display(key)}' is used by {owner}.[/] "
                f"[yellow]Press it again to override, or Esc to cancel.[/]"
            )
            return

        self._assign(action_id, key)

    def _assign(self, action_id: str, key: str) -> None:
        """Record an override for ``action_id`` and commit it."""
        if key == self._defaults.get(action_id):
            # Reverting to default -> drop any override (no-op override).
            self._pending.pop(action_id, None)
        else:
            self._pending[action_id] = key
        self._commit()
        self._set_footer(self._footer_text())

    # -- Actions --------------------------------------------------------------

    def action_cancel(self) -> None:
        """Close the editor, or cancel an in-progress capture first.

        Defined as a **sync** method on purpose: ``Esc`` is an app-level
        *priority* binding (``escape → maybe_quit``) that fires before this
        screen's own bindings, and ``QuitController.maybe_quit`` dismisses a
        modal by calling ``action_cancel()`` if present — otherwise it calls the
        inherited *async* ``Screen.action_dismiss`` synchronously (an un-awaited
        coroutine that never runs), which is why Esc previously did nothing.
        """
        if self._capturing:
            self._cancel_capture()
            return
        self.app.call_later(self._refresh_app)
        self.dismiss()

    def action_close(self) -> None:
        """Alias for the ``q`` / ``?`` close bindings."""
        self.action_cancel()

    def action_reset_row(self) -> None:
        """Reset the highlighted rebindable action to its default key."""
        if self._capturing:
            return
        action_id = self._highlighted_action_id()
        if action_id is None:
            return
        if action_id in self._pending:
            self._pending.pop(action_id, None)
            self._commit()

    def action_reset_all(self) -> None:
        """Clear all overrides and revert every action to its default."""
        if self._capturing:
            return
        if not self._pending:
            return
        self._pending.clear()
        self._commit()
        self.app.notify("All keybindings reset to defaults", severity="information")

    def _highlighted_action_id(self) -> str | None:
        """Return the action id of the highlighted rebindable row, if any."""
        try:
            option_list = self.query_one("#kb-list", OptionList)
            highlighted = option_list.highlighted
            if highlighted is None:
                return None
            option = option_list.get_option_at_index(highlighted)
        except Exception:
            return None
        option_id = option.id
        if option_id and option_id in self._defaults:
            return option_id
        return None

    # -- Commit (persist + live apply) ----------------------------------------

    def _commit(self) -> None:
        """Persist the working overrides to disk and apply them live."""
        app = self.app
        new_map = dict(self._pending)
        try:
            from sandroid.config.loader import ConfigLoader

            updated_config, _path = ConfigLoader().load_and_update_section(
                "tui", {"keybindings": new_map}
            )
            app._sandroid_config = updated_config  # keep app config in sync
        except Exception as exc:
            # Still apply live even if disk persist failed; surface a notify.
            app.notify(f"Could not save keybindings: {exc}", severity="error")
        try:
            app.set_keymap(new_map)  # REPLACE so resets revert to default
        except Exception as exc:
            app.notify(f"Could not apply keybindings: {exc}", severity="error")
        self._rebuild_list()  # reflect new effective keys

    def _refresh_app(self) -> None:
        """Refresh the app display after the modal closes."""
        try:
            self.app.refresh(layout=True)
        except Exception:
            pass
