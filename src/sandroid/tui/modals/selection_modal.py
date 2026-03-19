"""Selection modal with fuzzy search."""

from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Input, Label, OptionList
from textual.widgets.option_list import Option

from .base import ForensicModal, KeyHintFooter


class SelectionModal(ForensicModal):
    """Modal for selecting from a list with fuzzy search.

    Features:
    - Fuzzy filter as you type
    - Keyboard navigation (j/k or arrow keys)
    - Enter to select
    - Escape to cancel
    - Returns selected item or None if cancelled
    """

    DEFAULT_CSS = """
    SelectionModal .modal-container {
        width: 70;
        max-width: 90%;
        max-height: 70%;
    }

    SelectionModal .modal-message {
        padding-bottom: 1;
    }

    SelectionModal #option-list {
        height: auto;
        max-height: 15;
        background: $surface;
        border: solid $panel;
    }

    SelectionModal #option-list:focus {
        border: solid $primary;
    }

    SelectionModal #option-list > .option-list--option-highlighted {
        background: $panel;
        color: #6ba3ff;
    }
    """

    BINDINGS = [
        # priority=True ensures Enter works even when Input is focused
        Binding("enter", "select", "Select", priority=True),
        Binding("j", "next", "Next", show=False),
        Binding("k", "prev", "Previous", show=False),
        Binding("down", "next", "Next", show=False),
        Binding("up", "prev", "Previous", show=False),
    ]

    AUTO_FOCUS = "#filter-input"

    def __init__(
        self,
        title: str,
        options: list[Any],
        message: str = "",
        display_func: callable = None,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the selection modal.

        Args:
            title: Dialog title
            options: List of options to choose from
            message: Optional description text
            display_func: Optional function to convert options to display strings
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.title_text = title
        self.message_text = message
        self.all_options = options
        self.filtered_options = options.copy()
        self.display_func = display_func or str

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label(self.title_text, classes="modal-title")
            if self.message_text:
                yield Label(self.message_text, classes="modal-message")
            yield Input(placeholder="Type to filter...", id="filter-input")
            yield OptionList(
                *[Option(self.display_func(o)) for o in self.filtered_options],
                id="option-list",
            )
            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus the filter input on mount."""
        super().on_mount()
        # Highlight first option if available
        option_list = self.query_one("#option-list", OptionList)
        if self.filtered_options:
            option_list.highlighted = 0

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle filter input changes."""
        if event.input.id != "filter-input":
            return

        query = event.value.lower().strip()
        if query:
            self.filtered_options = [
                o for o in self.all_options if query in self.display_func(o).lower()
            ]
        else:
            self.filtered_options = self.all_options.copy()

        self._update_option_list()

    def _update_option_list(self) -> None:
        """Update the option list with filtered options."""
        option_list = self.query_one("#option-list", OptionList)
        option_list.clear_options()
        for opt in self.filtered_options:
            option_list.add_option(Option(self.display_func(opt)))

        # Highlight first option if available
        if self.filtered_options:
            option_list.highlighted = 0

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle double-click or Enter on option."""
        self._select_current()

    def action_select(self) -> None:
        """Select the currently highlighted option."""
        self._select_current()

    def _select_current(self) -> None:
        """Select the current highlighted option."""
        option_list = self.query_one("#option-list", OptionList)
        if option_list.highlighted is not None and option_list.highlighted < len(
            self.filtered_options
        ):
            selected = self.filtered_options[option_list.highlighted]
            self._dismiss_with_refresh(selected)

    def action_next(self) -> None:
        """Move to next option."""
        option_list = self.query_one("#option-list", OptionList)
        option_list.action_cursor_down()

    def action_prev(self) -> None:
        """Move to previous option."""
        option_list = self.query_one("#option-list", OptionList)
        option_list.action_cursor_up()
