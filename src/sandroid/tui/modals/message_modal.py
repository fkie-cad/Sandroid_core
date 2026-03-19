"""Message display modal (info/warning/error)."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Button, Label, Static

from .base import DangerModal, ForensicModal, KeyHintFooter


class MessageModal(ForensicModal):
    """Modal for displaying messages.

    Features:
    - Displays info/warning/error messages
    - Styled based on message level
    - Dismiss with Enter, Escape, or OK button
    """

    BINDINGS = [
        Binding("enter", "dismiss_modal", "Close", priority=True),
    ]

    AUTO_FOCUS = "#ok"

    DEFAULT_CSS = """
    MessageModal .modal-container {
        width: 60;
        max-width: 80%;
        max-height: 80%;
    }

    MessageModal .modal-content {
        margin-bottom: 1;
    }

    /* Level-specific title styling */
    MessageModal .modal-container.message-warning .modal-title {
        color: $warning;
    }

    MessageModal .modal-container.message-error .modal-title {
        color: $error;
    }
    """

    def __init__(
        self,
        title: str,
        message: str,
        level: str = "info",
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the message modal.

        Args:
            title: Dialog title
            message: The message to display
            level: Message level ("info", "warning", "error")
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.title_text = title
        self.message_text = message
        self.level = level

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        # Get icon based on level
        icons = {
            "info": "[blue]i[/]",
            "warning": "[yellow]![/]",
            "error": "[red]X[/]",
        }
        icon = icons.get(self.level, icons["info"])

        with Vertical(classes=f"modal-container message-{self.level}"):
            yield Label(f"{icon} {self.title_text}", classes="modal-title")
            yield Static(self.message_text, classes="modal-content")
            with Vertical(classes="button-row"):
                yield Button("OK", id="ok", classes="-primary")
            yield KeyHintFooter(hints={"button": "[dim]Enter=OK  Esc=Close[/dim]"})

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        self._dismiss_with_refresh(None)

    def action_dismiss_modal(self) -> None:
        """Dismiss the modal."""
        self._dismiss_with_refresh(None)


class ErrorModal(DangerModal):
    """Modal for displaying error messages with red danger styling.

    Features:
    - Displays error messages with full red (danger) theme
    - Red border, title, and button
    - Dismiss with Enter, Escape, or OK button
    """

    BINDINGS = [
        Binding("enter", "dismiss_modal", "Close", priority=True),
    ]

    AUTO_FOCUS = "#ok"

    DEFAULT_CSS = """
    ErrorModal .modal-container {
        width: 60;
        max-width: 80%;
        max-height: 80%;
    }

    ErrorModal .modal-content {
        margin-bottom: 1;
    }
    """

    def __init__(
        self,
        title: str,
        message: str,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the error modal.

        Args:
            title: Dialog title
            message: The error message to display
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.title_text = title
        self.message_text = message

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label(f"[red]X[/] {self.title_text}", classes="modal-title")
            yield Static(self.message_text, classes="modal-content")
            with Vertical(classes="button-row"):
                yield Button("OK", id="ok", classes="-primary")
            yield KeyHintFooter(hints={"button": "[dim]Enter=OK  Esc=Close[/dim]"})

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        self._dismiss_with_refresh(None)

    def action_dismiss_modal(self) -> None:
        """Dismiss the modal."""
        self._dismiss_with_refresh(None)
