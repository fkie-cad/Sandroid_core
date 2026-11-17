"""Text input modal dialog."""

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label

from .base import ForensicModal, KeyHintFooter


class InputModal(ForensicModal[str]):
    """Modal for text input.

    Features:
    - Text input with optional default value
    - Submit with Enter or button
    - Cancel with Escape or button
    - Returns input value or None if cancelled
    - Centered with transparent background
    - ``select_all=True``: the default value starts selected, so typing
      replaces it (rename); otherwise the cursor sits at its end, so typing
      appends (e.g. completing a path)

    The input is a full-height bordered field (``no-compact``): the modal
    sweep made it compact (1 row) while the theme kept its border, which
    left a 2-row box with no visible text row -- the prefilled value was
    invisible and typing silently appended to it (M-30).
    """

    AUTO_FOCUS = "#input-field"

    DEFAULT_CSS = """
    InputModal .modal-container {
        width: 60;
        max-width: 90%;
    }

    InputModal .modal-message {
        padding-top: 1;
    }

    InputModal #input-field {
        width: 100%;
        height: 3;
    }
    """

    def __init__(
        self,
        title: str,
        message: str = "",
        default: str = "",
        placeholder: str = "",
        name: str = None,
        id: str = None,
        classes: str = None,
        select_all: bool = False,
    ):
        """Initialize the input modal.

        Args:
            title: Dialog title
            message: Optional description text
            default: Default value for input
            placeholder: Placeholder text when empty
            name: Widget name
            id: Widget ID
            classes: CSS classes
            select_all: Select the default value so typing replaces it.
        """
        super().__init__(name=name, id=id, classes=classes)
        self.title_text = title
        self.message_text = message
        self.default = default
        self.placeholder = placeholder or "Enter value..."
        self.select_all = select_all

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label(self.title_text, classes="modal-title")
            if self.message_text:
                yield Label(self.message_text, classes="modal-message")
            yield Input(
                value=self.default,
                placeholder=self.placeholder,
                id="input-field",
                classes="no-compact",
                select_on_focus=self.select_all,
            )
            with Horizontal(classes="button-row"):
                yield Button("Submit", id="submit", classes="-primary")
                yield Button("Cancel", id="cancel", classes="-secondary")
            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus the input field; select or place the cursor after the value."""
        super().on_mount()
        if self.default:
            input_field = self.query_one("#input-field", Input)
            if self.select_all:
                # After the focus handling, which may move the cursor.
                self.call_after_refresh(input_field.select_all)
            else:
                input_field.cursor_position = len(self.default)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in input field."""
        if event.input.id == "input-field":
            self._submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        if event.button.id == "submit":
            self._submit()
        else:
            self._dismiss_with_refresh(None)

    def _submit(self) -> None:
        """Submit the input value."""
        value = self.query_one("#input-field", Input).value
        self._dismiss_with_refresh(value)
