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
        """
        super().__init__(name=name, id=id, classes=classes)
        self.title_text = title
        self.message_text = message
        self.default = default
        self.placeholder = placeholder or "Enter value..."

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
            )
            with Horizontal(classes="button-row"):
                yield Button("Submit", id="submit", classes="-primary")
                yield Button("Cancel", id="cancel", classes="-secondary")
            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus the input field and position cursor."""
        super().on_mount()
        # Select all text if there's a default value
        if self.default:
            input_field = self.query_one("#input-field", Input)
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
