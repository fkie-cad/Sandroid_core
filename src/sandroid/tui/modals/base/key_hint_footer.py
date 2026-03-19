"""Dynamic key hint footer widget for Sandroid modals.

KeyHintFooter displays context-sensitive keyboard hints that update
when the user focuses different widget types (Input, OptionList, Button).

Usage:
    # In modal compose():
    yield KeyHintFooter()

    # With custom hints:
    yield KeyHintFooter(hints={
        "input": "[dim]Type to filter | Enter=Select | Esc=Cancel[/dim]",
        "list": "[dim]j/k=Navigate | Enter=Select | Esc=Cancel[/dim]",
    })

The parent SandroidModal calls update_for_widget() on DescendantFocus events.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.widgets import Button, Input, OptionList, RadioSet, Static

if TYPE_CHECKING:
    from textual.widget import Widget


class KeyHintFooter(Static):
    """Dynamic key hint footer that updates based on focused widget type.

    This widget displays context-sensitive keyboard hints at the bottom
    of modals. It automatically updates when focus changes between
    different widget types (Input, OptionList, Button).

    Attributes:
        HINTS: Default hint templates for each widget type.
        DEFAULT_CSS: Theme-aware styling for the footer.
    """

    DEFAULT_CSS = """
    KeyHintFooter {
        width: 100%;
        height: auto;
        text-align: center;
        color: #6e7681;
        margin-top: 1;
    }
    """

    HINTS: dict[str, str] = {
        "default": "[dim]Esc=Cancel  Tab=Next[/dim]",
        "input": "[dim]Esc=Cancel  Tab=Next Field  Enter=Submit[/dim]",
        "list": "[dim]Esc=Cancel  j/k=Navigate  Enter=Select[/dim]",
        "button": "[dim]Esc=Cancel  Tab=Next  Enter/Space=Activate[/dim]",
        "radioset": "[dim]Esc=Cancel  ↑↓=Navigate  Space=Select  Tab=Next[/dim]",
    }

    def __init__(
        self,
        hints: dict[str, str] | None = None,
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize KeyHintFooter with optional custom hints.

        Args:
            hints: Optional dict to override default hints.
                   Keys: "default", "input", "list", "button"
                   Values: Rich markup strings
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        # Merge custom hints with defaults (custom wins) FIRST
        if hints:
            self._hints = {**self.HINTS, **hints}
        else:
            self._hints = self.HINTS.copy()

        # Initialize with the (possibly custom) default
        super().__init__(self._hints["default"], name=name, id=id, classes=classes)

    _WIDGET_TYPE_MAP: dict[type, str] = {
        Input: "input",
        OptionList: "list",
        RadioSet: "radioset",
        Button: "button",
    }

    def update_for_widget(self, widget: Widget) -> None:
        """Update hints based on focused widget type.

        Called by SandroidModal.on_descendant_focus() when focus changes.

        Args:
            widget: The newly focused widget
        """
        hint_key = "default"
        for widget_type, key in self._WIDGET_TYPE_MAP.items():
            if isinstance(widget, widget_type):
                hint_key = key
                break
        self.update(self._hints.get(hint_key, self._hints["default"]))

    def set_hint(self, hint_type: str, text: str) -> None:
        """Set custom hint text for a specific type.

        Args:
            hint_type: One of "default", "input", "list", "button"
            text: Rich markup string for the hint
        """
        self._hints[hint_type] = text

    def reset_to_default(self) -> None:
        """Reset display to default hints."""
        self.update(self._hints["default"])
