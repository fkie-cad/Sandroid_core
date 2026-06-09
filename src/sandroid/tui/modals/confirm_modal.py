"""Confirmation modal dialog."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Label

from .base import ForensicModal, KeyHintFooter


class ConfirmModal(ForensicModal[bool]):
    """Modal for yes/no confirmation.

    Features:
    - Yes/No buttons
    - Keyboard shortcuts (y/n)
    - Escape defaults to No
    - Returns True for Yes, False for No
    """

    DEFAULT_CSS = """
    ConfirmModal .modal-container {
        width: 50;
        max-width: 80%;
        max-height: 80%;
    }

    ConfirmModal .modal-message {
        width: 100%;
        padding-bottom: 1;
    }

    /* Yes button - primary action */
    ConfirmModal Button.-primary {
        background: $success;
        color: #ffffff;
    }

    ConfirmModal Button.-primary:hover {
        background: $success-darken-1;
    }

    /* Override Textual's default button styling for primary */
    ConfirmModal .button-row Button.-style-default.-primary,
    ConfirmModal .button-row Button.-style-default.-primary:hover,
    ConfirmModal .button-row Button.-style-default.-primary:focus {
        background: $success;
        color: #ffffff;
    }

    ConfirmModal .button-row Button.-style-default.-primary:hover {
        background: $success-darken-1;
    }
    """

    BINDINGS = [
        Binding("y", "yes", "Yes", show=False),
        Binding("n", "no", "No", show=False),
    ]

    def __init__(
        self,
        title: str,
        message: str = "",
        yes_label: str = "Yes",
        no_label: str = "No",
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the confirmation modal.

        Args:
            title: Dialog title
            message: Optional description text
            yes_label: Label for the Yes button
            no_label: Label for the No button
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.title_text = title
        self.message_text = message
        self.yes_label = yes_label
        self.no_label = no_label

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label(self.title_text, classes="modal-title")
            if self.message_text:
                yield Label(self.message_text, classes="modal-message")
            with Horizontal(classes="button-row"):
                yield Button(self.yes_label, id="yes", classes="-primary")
                yield Button(self.no_label, id="no", classes="-secondary")
            yield KeyHintFooter(hints={"button": "[dim]y=Yes  n=No  Esc=Cancel[/dim]"})

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        self._dismiss_with_refresh(event.button.id == "yes")

    def action_yes(self) -> None:
        """Confirm and close the modal."""
        self._dismiss_with_refresh(True)

    def action_no(self) -> None:
        """Decline and close the modal."""
        self._dismiss_with_refresh(False)
