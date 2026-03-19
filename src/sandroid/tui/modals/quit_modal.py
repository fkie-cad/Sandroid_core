"""Quit confirmation modal dialog."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, Label

from .base import DangerModal, KeyHintFooter


class QuitConfirmModal(DangerModal[bool]):
    """Compact centered modal for quit confirmation.

    Features:
    - Small centered overlay
    - Yes/No buttons with keyboard shortcuts (y/n)
    - Escape defaults to No (cancel quit)
    - Returns True to quit, False to cancel
    """

    BINDINGS = [
        # Keep modal-specific bindings (y/n/q/enter) - ESC inherited from SandroidModal
        Binding("q", "cancel", "Cancel", show=False, priority=True),
        Binding("y", "confirm", "Yes", show=False),
        Binding("n", "cancel", "No", show=False),
        # Enter should always quit, even when Cancel button is focused
        Binding("enter", "confirm", "Confirm", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    QuitConfirmModal .modal-container {
        width: 44;
        max-width: 80%;
        max-height: 80%;
    }
    """

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the quit confirmation modal."""
        super().__init__(name=name, id=id, classes=classes)

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Quit Sandroid?", classes="modal-title")
            yield Label("Are you sure you want to exit?", classes="modal-message")
            with Horizontal(classes="button-row"):
                yield Button("Quit", classes="-primary", id="btn-quit")
                yield Button("Cancel", classes="-secondary", id="btn-cancel")
            yield KeyHintFooter(
                hints={"button": "[dim]y/Enter=Quit  n/q/Esc=Cancel[/dim]"}
            )

    def on_mount(self) -> None:
        """Focus the Cancel button on mount (safer default)."""
        try:
            self.query_one("#btn-cancel", Button).focus()
        except NoMatches:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        if event.button.id == "btn-quit":
            self.dismiss(True)
        else:
            self._dismiss_with_refresh(False)

    def action_confirm(self) -> None:
        """Confirm quit."""
        self.dismiss(True)

    def action_cancel(self) -> None:
        """Cancel quit and close modal."""
        self._dismiss_with_refresh(False)
