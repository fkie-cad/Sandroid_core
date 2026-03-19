"""Install warning modal for forensic APK installation."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, Checkbox, Label

from .base import DangerModal, KeyHintFooter


class InstallWarningResult:
    """Result from install warning modal.

    Attributes:
        proceed: True if user wants to proceed with install
        dont_show_again: True if user checked "don't show again"
    """

    def __init__(self, proceed: bool = False, dont_show_again: bool = False):
        self.proceed = proceed
        self.dont_show_again = dont_show_again


class InstallWarningModal(DangerModal[InstallWarningResult]):
    """Warning modal shown before installing forensic APKs.

    Features:
    - Warning about potentially malicious APK
    - "Don't show this again" checkbox
    - Proceed or Cancel buttons
    - Y/N keyboard shortcuts
    """

    BINDINGS = [
        # Keep modal-specific bindings - ESC inherited from SandroidModal
        Binding("y", "proceed", "Proceed", show=False, priority=True),
        Binding("n", "cancel", "Cancel", show=False, priority=True),
        Binding("enter", "proceed", "Proceed", priority=True),
    ]

    DEFAULT_CSS = """
    InstallWarningModal .modal-container {
        width: 70;
        max-width: 90%;
        max-height: 70%;
    }

    InstallWarningModal .warning-icon {
        text-style: bold;
        color: $error;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: 3;
    }

    InstallWarningModal .warning-details {
        color: $text-muted;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    InstallWarningModal .dont-show-checkbox {
        margin-top: 1;
        padding: 0 2;
    }

    InstallWarningModal .dont-show-checkbox:focus {
        text-style: bold;
    }
    """

    def __init__(
        self,
        package_name: str = "",
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the install warning modal.

        Args:
            package_name: Name of the package being installed
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.package_name = package_name

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("  ⚠", classes="warning-icon")
            yield Label("Security Warning", classes="modal-title")

            message = (
                "You are about to install a potentially malicious APK "
                "that was flagged by forensic scanning."
            )
            yield Label(message, classes="modal-message")

            if self.package_name:
                details = f"[bold]{self.package_name}[/bold]"
            else:
                details = "[dim]Selected forensic APK[/dim]"
            yield Label(details, classes="warning-details")

            yield Checkbox(
                "Don't show this warning again",
                classes="dont-show-checkbox",
                id="dont-show-checkbox",
            )

            with Horizontal(classes="button-row"):
                yield Button("Proceed", classes="-primary", id="btn-proceed")
                yield Button("Cancel", classes="-secondary", id="btn-cancel")

            yield KeyHintFooter(
                hints={"button": "[dim]Enter/y=Proceed  n/Esc=Cancel[/dim]"}
            )

    def on_mount(self) -> None:
        """Focus the proceed button on mount."""
        try:
            btn = self.query_one("#btn-proceed", Button)
            btn.focus()
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        self._finish(proceed=event.button.id == "btn-proceed")

    def action_cancel(self) -> None:
        """Cancel and close modal."""
        self._finish(proceed=False)

    def action_proceed(self) -> None:
        """Proceed with installation."""
        self._finish(proceed=True)

    def _finish(self, proceed: bool) -> None:
        """Dismiss with result."""
        try:
            dont_show = self.query_one("#dont-show-checkbox", Checkbox).value
        except NoMatches:
            dont_show = False
        self._dismiss_with_refresh(
            InstallWarningResult(proceed=proceed, dont_show_again=dont_show)
        )
