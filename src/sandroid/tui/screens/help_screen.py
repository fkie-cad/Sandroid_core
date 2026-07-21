"""Interactive Help & Keybindings editor for the Sandroid TUI.

This modal screen lists every feature action grouped by category together
with its currently effective key, and lets the user rebind, reset (per row
or all), and persist the result to the static config file. Changes are
applied LIVE via :meth:`textual.app.App.set_keymap`.
"""

import logging

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from sandroid.core.menu_controller import Action, ActionCategory, MenuController

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

# Column widths for the aligned row layout (command / description / key).
# Sized for the wide modal so rows rarely truncate; the detail pane below the
# list always shows the highlighted row's full, untruncated text regardless.
_NAME_W = 32
_DESC_W = 50
_KEY_W = 14


def _format_key_display(key: str) -> str:
    """Format a key string for human display.

    Title-cases each ``+``-split part and humanises a few common keys
    (e.g. ``ctrl+y`` -> ``Ctrl+Y``, ``space`` -> ``Space``).

    Args:
        key: Raw key string (e.g. ``"ctrl+y"``, ``" "``, ``"C"``).

    Returns:
        Human-readable representation of the key.
    """
    if not key:
        return "—"
    if key == " " or key == "space":
        return "Space"
    parts = key.split("+")
    out: list[str] = []
    for part in parts:
        if not part:
            continue
        if len(part) == 1:
            # Single chars: uppercase letters stay as-is (e.g. Shift+C is
            # already represented by the raw "C"); just upper for display.
            out.append(part.upper())
        else:
            out.append(part.title())
    return "+".join(out)


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
        width: 110;
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
    ):
        """Initialize the keybinding editor.

        Args:
            current_view: Ignored (retained for caller compatibility; the flat
                catalog no longer needs a view).
            name: Screen name.
            id: Screen ID.
            classes: CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
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
        self._defaults = {b.id: b.key for b in app.BINDINGS if b.id}
        cfg = getattr(app, "sandroid_config", None)
        if cfg is not None and getattr(cfg, "tui", None) is not None:
            self._pending = dict(cfg.tui.keybindings)
        else:
            self._pending = {}
        self._rebuild_list()

    @staticmethod
    def _footer_text() -> str:
        """Return the default footer hint text."""
        return (
            "[dim]↑/↓ navigate · Enter rebind · ⌫ reset row · "
            "Ctrl+R reset all · Esc close[/dim]"
        )

    def _snapshots_panel(self):
        """Find the SnapshotsPanel under the main screen (for slot assignments)."""
        try:
            for screen in self.app.screen_stack:
                try:
                    return screen.query_one("#snapshots-panel")
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def _slot_assignments(self) -> dict[str, str]:
        """Current AVD's ``{slot: tag}`` map, reusing the panel's AVD keying."""
        panel = self._snapshots_panel()
        if panel is not None and hasattr(panel, "_slot_map"):
            try:
                return panel._slot_map()
            except Exception:
                return {}
        return {}

    @staticmethod
    def _row_description(action: Action, slots: dict[str, str]) -> str:
        """Description-column text, with slot assignment for slot rows."""
        if action.name.startswith("load_slot_"):
            tag = slots.get(action.name.rsplit("_", 1)[-1])
            return f"→ {tag}" if tag else "(empty)"
        if action.name.startswith("save_slot_"):
            return "save current state"
        return action.description or action.display_name

    @staticmethod
    def _columns(name: str, desc: str, key_display: str, *, colored: bool) -> str:
        """Lay out a row as aligned columns; pad on plain text, colour the key.

        Rich markup has no visible width, so the command/description columns are
        padded as plain text and only the (right-aligned) key gets colour.
        """
        if len(name) > _NAME_W:
            name = name[: _NAME_W - 1] + "…"
        if len(desc) > _DESC_W:
            desc = desc[: _DESC_W - 1] + "…"
        bracket = f"[{key_display}]"  # plain, for width
        pad = max(1, _KEY_W - len(bracket))
        name_field = name.ljust(_NAME_W)
        desc_field = desc.ljust(_DESC_W)
        if colored:
            key_field = (" " * pad) + f"[bold #ff79c6]\\[{key_display}][/]"
        else:
            key_field = (" " * pad) + f"\\[{key_display}]"
        return f"{name_field}  {desc_field}{key_field}"

    def _rebuild_list(self) -> None:
        """Rebuild the OptionList rows from the current effective keys."""
        try:
            option_list = self.query_one("#kb-list", OptionList)
        except Exception:
            return

        previous = option_list.highlighted
        option_list.clear_options()

        slots = self._slot_assignments()

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

        first_enabled: int | None = None
        index = 0
        for category in _CATEGORY_ORDER:
            actions = by_category.get(category)
            if not actions:
                continue
            header = f"── {category.name.title()} ──"
            option_list.add_option(Option(f"[dim]{header}[/]", disabled=True))
            index += 1

            for action in sorted(actions, key=lambda a: a.display_name.lower()):
                rebindable = action.name in self._defaults
                key = self._effective_key(action.name) if rebindable else action.key
                key_display = _format_key_display(key)
                desc = self._row_description(action, slots)
                if rebindable:
                    label = self._columns(
                        action.display_name, desc, key_display, colored=True
                    )
                    option_list.add_option(Option(label, id=action.name))
                    if first_enabled is None:
                        first_enabled = index
                else:
                    label = self._columns(
                        action.display_name, desc, key_display, colored=False
                    )
                    option_list.add_option(
                        Option(f"[dim]{label}  (fixed)[/]", disabled=True)
                    )
                index += 1

        # Restore / set highlight to a sane enabled index.
        if previous is not None and 0 <= previous < option_list.option_count:
            option_list.highlighted = previous
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
        action = self._controller.get_action_by_name(action_id)
        if action is None:
            return ""
        rebindable = action.name in self._defaults
        full_desc = action.description or action.display_name
        # Slot rows: append the assigned snapshot tag (cheap config read).
        if action.name.startswith("load_slot_"):
            tag = self._slot_assignments().get(action.name.rsplit("_", 1)[-1])
            full_desc += f"  [dim]({('→ ' + tag) if tag else 'empty'})[/]"
        cat = action.category.name.title()
        cur = self._effective_key(action.name) if rebindable else action.key
        cur_disp = _format_key_display(cur)

        head = f"[bold #58a6ff]{action.display_name}[/]  [dim]·  {cat}[/]"
        body = f"[#c9d1d9]{full_desc}[/]"
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
