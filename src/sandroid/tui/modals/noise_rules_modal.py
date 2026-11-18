"""Live editor for the Files lens path rules (``tui.files_noise_rules``).

Opened with ``R`` on the Files lens. Shows every hide / group rule in order
and applies each change at once: the lens re-draws and the rules are saved to
the config (``sandroid.config.update_config``, the same mechanism as the
Settings screen). Keys: Space toggles the highlighted rule, Delete (or
``d``) removes it, the row below adds one (action, kind, pattern, ⏎),
"Reset to defaults" restores the shipped rules. Esc closes.

Rule kinds: ``prefix`` (absolute path starts with), ``segment`` (a
directory named so), ``suffix`` (file name ends with), ``glob`` (``fnmatch``
on the absolute or app-relative path). Actions: ``hide`` (``N`` in the lens
still shows the rows) and ``group`` (one expandable row per folder).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Label, Select, Static

from sandroid.config.schema import (
    FILES_RULE_ACTIONS,
    FILES_RULE_KINDS,
    default_files_noise_rules,
)

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


class _RulesTable(DataTable):
    """The rule list: Space toggles, Delete / d removes."""

    BINDINGS = [
        Binding("space", "toggle_rule", "On/off", show=False),
        Binding("delete", "remove_rule", "Remove", show=False),
        Binding("d", "remove_rule", "Remove", show=False),
    ]

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
                "tui.monitor_event_visibility (noise = verbose, Settings).",
                id="rules-help",
            )
            table = _RulesTable(id="rules-table", cursor_type="row")
            table.add_column("on", width=3, key="on")
            table.add_column("action", width=6, key="action")
            table.add_column("kind", width=8, key="kind")
            table.add_column("pattern", key="pattern")
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
                    "default": "[dim]Space on/off  Del remove  Tab to the add "
                    "row  ⏎ add  Esc close[/dim]"
                }
            )

    def on_mount(self) -> None:
        super().on_mount()
        self._fill()

    # -- table ---------------------------------------------------------------

    def _fill(self, cursor: int | None = None) -> None:
        table = self.query_one("#rules-table", DataTable)
        keep = table.cursor_row if cursor is None else cursor
        table.clear()
        for i, rule in enumerate(self._rules):
            on = rule.get("enabled", True)
            style = "" if on else "#5b6479"
            table.add_row(
                Text("✓" if on else "·", style="#4ade80" if on else "#5b6479"),
                Text(rule.get("action", ""), style=style or "#c4b5fd"),
                Text(rule.get("kind", ""), style=style),
                Text(rule.get("pattern", ""), style=style),
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
        if not 0 <= index < len(self._rules):
            return
        rule = self._rules.pop(index)
        self._fill(index)
        self._commit(f"Removed {rule['action']} {rule['kind']} {rule['pattern']}")

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


__all__ = ["NoiseRulesModal"]
