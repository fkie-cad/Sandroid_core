"""Quit confirmation modal dialog."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, Label, Static

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
    QuitConfirmModal #quit-notes {
        width: 100%;
        height: auto;
        text-align: center;
        color: $text-muted;
    }
    """

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
        notes: list[str] | None = None,
    ):
        """Initialize the quit confirmation modal.

        Args:
            notes: What quitting tears down (e.g. "stops mitmweb", "clears
                the device proxy"), shown under the question.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._notes = list(notes or [])

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Quit Sandroid?", classes="modal-title")
            yield Label("Are you sure you want to exit?", classes="modal-message")
            if self._notes:
                yield Static(
                    "Quitting " + ", ".join(self._notes) + ".",
                    classes="modal-message",
                    id="quit-notes",
                )
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
            self.action_confirm()
        else:
            self._dismiss_with_refresh(False)

    def action_confirm(self) -> None:
        """Confirm quit.

        The exit watchdog is armed right here, in the dialog's own message
        loop: if the app's loop is stuck the dismiss callback never runs, and
        the watchdog still tears down mitmweb / the device proxy and exits.
        """
        try:
            from sandroid.tui.controllers.quit_controller import arm_exit_watchdog

            arm_exit_watchdog()
        except Exception:
            pass
        self.dismiss(True)

    def action_cancel(self) -> None:
        """Cancel quit and close modal."""
        self._dismiss_with_refresh(False)
