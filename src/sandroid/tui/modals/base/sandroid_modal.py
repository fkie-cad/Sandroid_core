"""Base modal class for Sandroid TUI.

This module provides SandroidModal, the foundation for ALL Sandroid modals.
It enforces consistent keyboard navigation and dismiss behavior.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Generic, TypeVar

from textual.binding import Binding
from textual.css.query import NoMatches
from textual.screen import ModalScreen
from textual.widgets import Button, Input

from sandroid.tui.utils import apply_compact_widgets

from .key_hint_footer import KeyHintFooter

if TYPE_CHECKING:
    from textual import events
    from textual.events import DescendantFocus

T = TypeVar("T")


class SandroidModal(ModalScreen[T], Generic[T]):
    """Base class for ALL Sandroid modals."""

    # If True, pressing Enter while an Input is focused will press the primary button.
    ENTER_SUBMITS_FROM_INPUT = True

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", priority=True),
        Binding("tab", "modal_focus_next", "Next", show=False, priority=True),
        Binding(
            "shift+tab", "modal_focus_previous", "Previous", show=False, priority=True
        ),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
    ]

    AUTO_FOCUS = None  # CSS selector, override in subclass

    DEFAULT_CSS = """
    SandroidModal {
        align: center middle;
        background: $background 85%;
    }

    SandroidModal .modal-container {
        background: $surface;
        border: solid $primary;
        padding: 1 2;
        width: auto;
        min-width: 50;
        height: auto;
        max-width: 90%;
        max-height: 85%;
    }

    SandroidModal .modal-title {
        text-style: bold;
        color: $primary;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: 2;
        margin-bottom: 1;
    }

    SandroidModal .modal-message {
        color: $foreground-muted;
        text-align: center;
        margin-bottom: 1;
    }

    SandroidModal .modal-content {
        color: $foreground;
    }

    SandroidModal .modal-hint {
        color: $text-muted;
        text-align: center;
        margin-top: 1;
    }

    SandroidModal .button-row {
        align: center middle;
        width: 100%;
        height: 1;
        margin-top: 1;
    }

    /*
      1-line Button baseline:
      (No line-pad here; your Textual version rejects line-pad: 0.)
    */
    SandroidModal Button {
        height: 1;
        min-height: 1;
        min-width: 14;

        padding: 0 1;
        margin: 0 1;

        border: none;

        /* Safer than middle for 1-line widgets */
        content-align: center top;
        text-align: center;
    }

    /*
      CRITICAL OVERRIDE:
      Textual adds "-style-default" automatically and has a special rule
      for Button.-style-default.-primary that applies tall borders etc.
      That rule is MORE specific than "SandroidModal Button.-primary",
      so we override it with an even more specific selector.
    */
    SandroidModal Button.-style-default.-primary,
    SandroidModal Button.-style-default.-primary:hover,
    SandroidModal Button.-style-default.-primary:focus {
        border: none;
        padding: 0 1;
        height: 1;
        min-height: 1;
        content-align: center top;
        text-align: center;
    }

    /* Zero out padding/margins on internals regardless of structure */
    SandroidModal Button * {
        padding: 0 0;
        margin: 0 0;
    }

    /* Your variants */
    SandroidModal Button.-primary {
        background: $primary;
        color: $text-primary;
    }
    SandroidModal Button.-primary:hover {
        background: $primary-lighten-1;
    }

    SandroidModal Button.-secondary {
        background: $panel;
        color: $foreground;
    }
    SandroidModal Button.-secondary:hover {
        background: $panel-lighten-1;
    }

    SandroidModal Input {
        background: $surface;
        border: solid $primary;
        color: $foreground;
        margin: 1 0;
    }
    SandroidModal Input:focus {
        border: solid $primary-lighten-1;
    }

    /*
      Switch has no built-in "compact" mode (unlike Input/Select/RadioSet/
      Button) -- its stock border+padding wraps a 4x1 content box in a much
      bigger box, so it's slimmed by hand here instead.
    */
    SandroidModal Switch {
        background: $panel;
        border: none;
        padding: 0 1;
        height: 1;
        min-height: 1;
    }
    SandroidModal Switch:focus {
        background: $panel-lighten-1;
        border: none;
    }

    /* Disabled state styling - consistent across all themes */
    SandroidModal Button:disabled {
        background: $surface;
        color: $foreground-disabled;
        border: none;
    }

    SandroidModal Button:disabled:hover {
        /* No hover effect when disabled */
        background: $surface;
    }

    SandroidModal Input:disabled {
        background: $surface;
        color: $foreground-disabled;
        border: solid $foreground-muted;
    }

    SandroidModal Checkbox:disabled {
        color: $foreground-disabled;
    }

    /* Also override the primary button disabled state */
    SandroidModal Button.-style-default.-primary:disabled,
    SandroidModal Button.-style-default.-primary:disabled:hover {
        background: $surface;
        color: $foreground-disabled;
        border: none;
    }
    """

    def _dismiss_with_refresh(self, result: T | None = None) -> None:
        self.app.call_later(self._refresh_app)
        self.dismiss(result)

    def _refresh_app(self) -> None:
        try:
            self.app.refresh(layout=True)
        except Exception:
            pass

    def action_cancel(self) -> None:
        self._dismiss_with_refresh(None)

    def on_mount(self) -> None:
        apply_compact_widgets(self)
        self._auto_focus()

    def on_key(self, event: events.Key) -> None:
        """Handle Tab and Enter keys for modal navigation."""
        key = event.key.lower() if event.key else ""

        if key == "tab" or event.character == "\t":
            event.stop()
            event.prevent_default()
            self.focus_next()
            return

        if key == "shift+tab":
            event.stop()
            event.prevent_default()
            self.focus_previous()
            return

        if (
            self.ENTER_SUBMITS_FROM_INPUT
            and key in ("enter", "return")
            and isinstance(self.app.focused, Input)
        ):
            event.prevent_default()
            event.stop()
            self._press_primary_button()
            return

    # Multiple handler names needed because Textual resolves key/action
    # handlers differently depending on context (binding vs direct key).
    def key_tab(self) -> None:
        self.focus_next()

    def key_shift_tab(self) -> None:
        self.focus_previous()

    def action_modal_focus_next(self) -> None:
        self.focus_next()

    def action_modal_focus_previous(self) -> None:
        self.focus_previous()

    def action_focus_next(self) -> None:
        self.focus_next()

    def action_focus_previous(self) -> None:
        self.focus_previous()

    def _press_primary_button(self) -> None:
        """Press the modal's primary button if present, else fall back to the first button."""
        for selector in (
            ".button-row Button.-primary",
            "Button.-primary",
            ".button-row Button",
            "Button",
        ):
            try:
                button = self.query_one(selector, Button)
                button.press()
                return
            except NoMatches:
                continue

    def _auto_focus(self) -> None:
        if self.AUTO_FOCUS:
            try:
                widget = self.query_one(self.AUTO_FOCUS)
                widget.focus()
                return
            except NoMatches:
                pass

        for selector in ("Input", "OptionList", "Button", ".modal-container"):
            try:
                widget = self.query_one(selector)
                widget.focus()
                return
            except NoMatches:
                continue

    def on_descendant_focus(self, event: DescendantFocus) -> None:
        try:
            hint_footer = self.query_one(KeyHintFooter)
            hint_footer.update_for_widget(event.widget)
        except NoMatches:
            pass
