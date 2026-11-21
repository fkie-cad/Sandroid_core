"""Live editor for the Files lens path rules (``tui.files_noise_rules``).

Opened with ``R`` on the Files lens. Shows every hide / group rule in order
and applies each change at once: the lens re-draws and the rules are saved to
the config (``sandroid.config.update_config``, the same mechanism as the
Settings screen; only the changes to the shipped defaults are saved, see
``merge_files_noise_rules``). Keys: Space toggles the highlighted rule,
Delete (or ``d``) removes it (a default rule is turned off instead; ``u``
undoes the last Delete of either kind), Home/End jump to the first/last rule, the row
below adds one (action, kind, pattern, Enter), "Reset to defaults" restores
the shipped rules. Esc closes.

Rule kinds: ``prefix`` (absolute path starts with), ``segment`` (a
directory named so), ``suffix`` (file name ends with), ``glob`` (``fnmatch``
on the absolute or app-relative path). Actions: ``hide`` (``N`` in the lens
still shows the rows) and ``group`` (one expandable row per folder).

Rules added with ``M`` for this session only are listed too, marked
"session" in the "kept" column (``default`` / ``saved`` / ``session``); they
apply but are never saved (removing one here undoes it).

:class:`MuteRowModal` is that ``M`` chooser: this folder / parent folder /
this file with the number of rows each would hide; Enter hides for this
session, ``a`` always (a saved rule).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button,
    DataTable,
    Input,
    Label,
    OptionList,
    Select,
    Static,
)
from textual.widgets.option_list import Option

from sandroid.config.schema import (
    FILES_RULE_ACTIONS,
    FILES_RULE_KINDS,
    default_files_noise_rules,
)
from sandroid.tui.themes import lens_palette
from sandroid.tui.widgets.monitor_view import app_relative

from .base import ForensicModal, KeyHintFooter

if TYPE_CHECKING:
    from textual.app import ComposeResult

#: ``apply(rules) -> error text | None`` (the Files lens's ``apply_noise_rules``).
ApplyRules = Callable[[list[dict]], "str | None"]

_KIND_HELP = {
    "prefix": "absolute path starts with, e.g. /data/misc/",
    "segment": "a folder of the path is named, e.g. cache",
    "suffix": "file name ends with, e.g. -shm",
    "glob": "fnmatch on the full or app path, e.g. */files/*.log",
}


def fit_path(path: str, width: int) -> str:
    """``path`` in ``width`` cells, cut only at ``/``: the first part and
    as many trailing parts as fit (``/data/…/default/https+++x.com/``).
    Only a last part longer than ``width`` loses its start.
    """
    if width <= 1:
        return "…" if path else ""
    if len(path) <= width:
        return path
    trail = "/" if path.endswith("/") else ""
    parts = path.rstrip("/").split("/")
    head = parts[0] + "/" if len(parts) > 2 else ""
    tail = parts[-1] + trail
    middle = parts[1:-1] if head else parts[:-1]
    for part in reversed(middle):
        candidate = f"{part}/{tail}"
        if len(head) + 2 + len(candidate) > width:
            break
        tail = candidate
    shown = f"{head}…/{tail}"
    if len(shown) <= width:
        return shown
    return "…" + path[-(width - 1) :]


def _default_idents() -> set[tuple]:
    return {(r["action"], r["kind"], r["pattern"]) for r in default_files_noise_rules()}


class _RulesTable(DataTable):
    """The rule list: Space toggles, Delete / d removes, u undoes."""

    BINDINGS = [
        Binding("space", "toggle_rule", "On/off", show=False),
        Binding("delete", "remove_rule", "Remove", show=False),
        Binding("d", "remove_rule", "Remove", show=False),
        Binding("u", "undo_remove", "Undo", show=False),
    ]

    # Home/End move the cursor to the first/last rule (DataTable's own
    # scroll the table sideways in row mode).
    def action_scroll_home(self) -> None:
        self.action_scroll_top()

    def action_scroll_end(self) -> None:
        self.action_scroll_bottom()

    def action_undo_remove(self) -> None:
        screen = self.screen
        if isinstance(screen, NoiseRulesModal):
            screen.undo_remove()

    def action_toggle_rule(self) -> None:
        screen = self.screen
        if isinstance(screen, NoiseRulesModal):
            screen.toggle_rule(self.cursor_row)

    def action_remove_rule(self) -> None:
        screen = self.screen
        if isinstance(screen, NoiseRulesModal):
            screen.remove_rule(self.cursor_row)


class NoiseRulesModal(ForensicModal[None]):
    """See the module docstring."""

    DEFAULT_CSS = """
    NoiseRulesModal .modal-container {
        width: 96;
        max-width: 96%;
        height: 92%;
        max-height: 34;
        padding: 0 2;
    }
    NoiseRulesModal .modal-title {
        height: 1;
        margin-bottom: 0;
    }
    NoiseRulesModal #rules-help {
        color: $text-muted;
        margin-bottom: 1;
    }
    NoiseRulesModal #rules-table {
        height: 1fr;
        min-height: 3;
        overflow-x: hidden;
    }
    NoiseRulesModal #rules-add {
        height: auto;
    }
    NoiseRulesModal #rules-add Select {
        width: 14;
    }
    NoiseRulesModal #rules-pattern {
        width: 1fr;
        margin: 0 0;
    }
    NoiseRulesModal #rules-status {
        color: $text-muted;
        height: auto;
    }
    """

    AUTO_FOCUS = "#rules-table"

    def __init__(self, rules: list[dict], apply: ApplyRules, **kwargs) -> None:
        super().__init__(**kwargs)
        self._rules: list[dict] = [dict(r) for r in rules]
        self._apply = apply
        #: The last Delete: where the rule was, the rule, and whether it was
        #: turned off (a default) rather than removed (``u`` undoes either).
        self._removed: tuple[int, dict, bool] | None = None

    @property
    def rules(self) -> list[dict]:
        return [dict(r) for r in self._rules]

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label("Files lens — hide & group rules", classes="modal-title")
            yield Static(
                "Applies at once and is saved in your config "
                "(tui.files_noise_rules). [b]hide[/b] drops matching rows "
                "(N in the lens shows everything raw), [b]group[/b] collapses "
                "them into one row per folder. Open-only rows are hidden by "
                "tui.monitor_event_visibility (noise = verbose, Settings). "
                "Rules kept for this [b]session[/b] (from M) are not saved.",
                id="rules-help",
            )
            table = _RulesTable(id="rules-table", cursor_type="row")
            table.add_column("on", width=2, key="on")
            table.add_column("kept", width=7, key="kept")
            table.add_column("action", width=6, key="action")
            table.add_column("kind", width=7, key="kind")
            table.add_column("pattern", width=self._PATTERN_MIN, key="pattern")
            yield table
            with Horizontal(id="rules-add"):
                yield Select(
                    [(a, a) for a in FILES_RULE_ACTIONS],
                    value="hide",
                    allow_blank=False,
                    id="rules-action",
                )
                yield Select(
                    [(k, k) for k in FILES_RULE_KINDS],
                    value="prefix",
                    allow_blank=False,
                    id="rules-kind",
                )
                yield Input(placeholder=_KIND_HELP["prefix"], id="rules-pattern")
            yield Static("", id="rules-status")
            with Horizontal(classes="button-row"):
                yield Button("Add rule", id="rules-add-btn", classes="-primary")
                yield Button("Reset to defaults", id="rules-reset")
                yield Button("Close", id="rules-close")
            yield KeyHintFooter(
                hints={
                    "default": "[dim]Space on/off  Del remove  u undo  Tab to "
                    "the add row  Enter add  Esc close[/dim]"
                }
            )

    def on_mount(self) -> None:
        super().on_mount()
        self._fill()
        self._mark_focused_button()

    def on_descendant_focus(self, _event) -> None:
        self._mark_focused_button()

    def on_descendant_blur(self, _event) -> None:
        self.call_after_refresh(self._mark_focused_button)

    def _mark_focused_button(self) -> None:
        """Make the focused button stand out (E2E: the theme painted all
        three alike, so Tab gave no visible cue). Inline styles: they beat
        every theme's ``Button`` rules.
        """
        for button in self.query(".button-row Button"):
            focused = button.has_focus
            button.styles.text_style = "bold reverse" if focused else "none"
            button.styles.opacity = 1.0 if focused else 0.75

    # -- table ---------------------------------------------------------------

    #: Cells of the columns before the pattern, DataTable's cell padding
    #: (1 each side) and the vertical scrollbar.
    _FIXED_CELLS = (2 + 7 + 6 + 7) + 5 * 2 + 2
    _PATTERN_MIN = 30

    def _pattern_width(self) -> int:
        table = self.query_one("#rules-table", DataTable)
        width = table.size.width or 0
        return max(self._PATTERN_MIN, width - self._FIXED_CELLS)

    def on_resize(self, _event) -> None:
        self._fill()

    @staticmethod
    def _ident(rule: dict) -> tuple:
        return (rule.get("action"), rule.get("kind"), rule.get("pattern"))

    def _kept(self, rule: dict) -> str:
        """``session`` (M, not saved), ``default`` (shipped) or ``saved``."""
        if rule.get("session"):
            return "session"
        return "default" if self._ident(rule) in _default_idents() else "saved"

    def _fill(self, cursor: int | None = None) -> None:
        table = self.query_one("#rules-table", DataTable)
        keep = table.cursor_row if cursor is None else cursor
        width = self._pattern_width()
        column = table.columns.get("pattern")  # type: ignore[call-overload]
        if column is not None:
            column.width = width
        table.clear()
        pal = lens_palette()
        for i, rule in enumerate(self._rules):
            on = rule.get("enabled", True)
            style = "" if on else pal.dim
            kept = self._kept(rule)
            # Its own short column: a long pattern can no longer hide the
            # "session" mark.
            kept_style = pal.accent if kept == "session" else pal.muted
            table.add_row(
                # The header says "on": ● on, ○ off (muted).
                Text("●" if on else "○", style=pal.ok if on else pal.muted),
                Text(kept, style=kept_style),
                Text(rule.get("action", ""), style=style or pal.accent),
                Text(rule.get("kind", ""), style=style),
                Text(fit_path(str(rule.get("pattern", "")), width), style=style),
                key=str(i),
            )
        if self._rules:
            table.move_cursor(row=max(0, min(keep, len(self._rules) - 1)))

    def _commit(self, message: str) -> None:
        error = self._apply(self.rules)
        status = self.query_one("#rules-status", Static)
        if error:
            status.update(Text(f"Applied, but not saved: {error}", style="#fb7185"))
        else:
            status.update(Text(message, style="#8f9bb3"))

    def toggle_rule(self, index: int) -> None:
        if not 0 <= index < len(self._rules):
            return
        rule = self._rules[index]
        rule["enabled"] = not rule.get("enabled", True)
        self._fill(index)
        state = "on" if rule["enabled"] else "off"
        self._commit(f"{rule['action']} {rule['kind']} {rule['pattern']} — {state}")

    def remove_rule(self, index: int) -> None:
        """Remove the rule at ``index`` (the highlighted row); ``u`` puts it
        back. A shipped default is turned off instead (Space turns it on).
        """
        if not 0 <= index < len(self._rules):
            return
        rule = self._rules[index]
        label = f"{rule['action']} {rule['kind']} {rule['pattern']}"
        if self._kept(rule) == "default":
            if rule.get("enabled", True):
                rule["enabled"] = False
                self._removed = (index, rule, True)
                self._fill(index)
                self._commit(f"{label} — off (a default rule; u undoes)")
            return
        self._rules.pop(index)
        self._removed = (index, rule, False)
        self._fill(index)
        self._commit(f"Removed {label} — u undoes")

    def undo_remove(self) -> None:
        """``u``: undo the last Delete -- put a removed rule back where it
        was, or turn a default it turned off on again (R1-B4).
        """
        if self._removed is None:
            return
        index, rule, turned_off = self._removed
        self._removed = None
        if turned_off:
            at = next((i for i, r in enumerate(self._rules) if r is rule), None)
            if at is not None and not rule.get("enabled", True):
                rule["enabled"] = True
                self._fill(at)
                self._commit(
                    f"{rule['action']} {rule['kind']} {rule['pattern']} — on again"
                )
            return
        if any(self._ident(r) == self._ident(rule) for r in self._rules):
            return
        index = min(index, len(self._rules))
        self._rules.insert(index, rule)
        self._fill(index)
        self._commit(f"Restored {rule['action']} {rule['kind']} {rule['pattern']}")

    def add_rule(self, action: str, kind: str, pattern: str) -> bool:
        pattern = pattern.strip()
        status = self.query_one("#rules-status", Static)
        if not pattern:
            status.update(Text("Type a pattern first.", style="#facc15"))
            return False
        if action not in FILES_RULE_ACTIONS or kind not in FILES_RULE_KINDS:
            return False
        rule = {"action": action, "kind": kind, "pattern": pattern, "enabled": True}
        if any(
            (r.get("action"), r.get("kind"), r.get("pattern"))
            == (action, kind, pattern)
            for r in self._rules
        ):
            status.update(Text("That rule is already in the list.", style="#facc15"))
            return False
        self._rules.append(rule)
        self._fill(len(self._rules) - 1)
        self._commit(f"Added {action} {kind} {pattern}")
        return True

    def reset_defaults(self) -> None:
        self._removed = None
        self._rules = default_files_noise_rules()
        self._fill(0)
        self._commit("Default rules restored.")

    # -- events --------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "rules-kind" and isinstance(event.value, str):
            self.query_one("#rules-pattern", Input).placeholder = _KIND_HELP.get(
                event.value, ""
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        button = event.button.id
        if button == "rules-add-btn":
            field = self.query_one("#rules-pattern", Input)
            action = self.query_one("#rules-action", Select).value
            kind = self.query_one("#rules-kind", Select).value
            if self.add_rule(str(action), str(kind), field.value):
                field.value = ""
        elif button == "rules-reset":
            self.reset_defaults()
        elif button == "rules-close":
            self._dismiss_with_refresh(None)


#: ``(label, shown path, hide rule, rows it would hide)`` (``FilesPanel``).
MuteChoice = tuple[str, str, dict, int]
#: ``apply(rule, always)`` (the Files lens's ``apply_mute``).
ApplyMute = Callable[[dict, bool], None]


class MuteRowModal(ForensicModal[None]):
    """``M`` in the Files lens: hide rows like the selected one."""

    DEFAULT_CSS = """
    MuteRowModal .modal-container {
        width: 90;
        max-width: 96%;
        height: auto;
        padding: 0 2;
    }
    MuteRowModal .modal-title {
        height: 1;
        margin-bottom: 0;
    }
    MuteRowModal #mute-help {
        color: $text-muted;
        margin-bottom: 1;
    }
    MuteRowModal #mute-choices {
        height: auto;
    }
    """

    BINDINGS = [Binding("a", "always", "Hide always (saved)", show=False)]

    AUTO_FOCUS = "#mute-choices"

    def __init__(self, choices: list[MuteChoice], apply: ApplyMute, **kwargs) -> None:
        super().__init__(**kwargs)
        self.choices = list(choices)
        self._apply = apply

    #: Cells around an option's text: the container's border and padding,
    #: the list's border and padding, and its scrollbar.
    _CHROME = 2 + 4 + 2 + 2 + 2

    @staticmethod
    def choice_text(choice: MuteChoice, width: int = 0) -> Text:
        """One line per scope: ``label  path  hides N rows``. The path is
        app-relative (like the lens rows) and, for ``width`` (0: no limit),
        shortened at ``/`` so the line fits.
        """
        label, shown, _rule, count = choice
        pal = lens_palette()
        tail = f"  hides {count} row{'s' if count != 1 else ''}"
        rel = app_relative(shown)
        if rel != shown and shown.endswith("/") and not rel.endswith("/"):
            rel += "/"
        if width:
            rel = fit_path(rel, max(12, width - 14 - len(tail)))
        text = Text(no_wrap=True, overflow="ellipsis")
        text.append(f"{label:<14}", style="bold")
        text.append(rel)
        text.append(tail, style=pal.muted)
        return text

    def _line_width(self) -> int:
        """The cells an option's text has in the container (width 90, at
        most 96 % of the screen).
        """
        try:
            screen = self.app.size.width
        except Exception:
            screen = 0
        container = min(90, int((screen or 100) * 0.96))
        return max(30, container - self._CHROME)

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label("Hide rows like this one", classes="modal-title")
            yield Static(
                "For this session only, or always (saved in "
                "tui.files_noise_rules). Watched rows stay. R lists the rules "
                "and removes one.",
                id="mute-help",
            )
            width = self._line_width()
            yield OptionList(
                *(
                    Option(self.choice_text(c, width), id=str(i))
                    for i, c in enumerate(self.choices)
                ),
                id="mute-choices",
            )
            with Horizontal(classes="button-row"):
                yield Button("This session", id="mute-session", classes="-primary")
                yield Button("Always", id="mute-always")
                yield Button("Cancel", id="mute-cancel")
            hint = (
                "[dim]Up/Down choose  Enter this session  a always (saved)  "
                "Esc cancel[/dim]"
            )
            # The focused list showed the generic "j/k=Navigate" hint.
            yield KeyHintFooter(hints={"default": hint, "list": hint})

    def on_mount(self) -> None:
        super().on_mount()
        choices = self.query_one("#mute-choices", OptionList)
        # One line per scope, all of them visible (+2: the list's border).
        choices.styles.max_height = max(1, len(self.choices)) + 2
        if self.choices:
            choices.highlighted = 0  # Enter acts on the first scope at once

    def _highlighted(self) -> int:
        index = self.query_one("#mute-choices", OptionList).highlighted
        return index if index is not None else 0

    def choose(self, index: int, always: bool = False) -> None:
        if not 0 <= index < len(self.choices):
            return
        rule = dict(self.choices[index][2])
        self._dismiss_with_refresh(None)
        self._apply(rule, always)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self.choose(event.option_index)

    def action_always(self) -> None:
        self.choose(self._highlighted(), always=True)

    # j/k (SandroidModal's bindings) move through the scopes like Up/Down.
    def action_cursor_down(self) -> None:
        self.query_one("#mute-choices", OptionList).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#mute-choices", OptionList).action_cursor_up()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "mute-session":
            self.choose(self._highlighted())
        elif event.button.id == "mute-always":
            self.choose(self._highlighted(), always=True)
        else:
            self._dismiss_with_refresh(None)


__all__ = ["MuteRowModal", "NoiseRulesModal"]
