"""Frida server installation confirmation modal."""

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Label, Static

from sandroid.tui.modals.base import FridaModal, KeyHintFooter


@dataclass
class FridaInstallResult:
    """Result from Frida installation confirmation."""

    install: bool  # True to install, False to cancel
    device_name: str  # Name of the target device


class FridaInstallModal(FridaModal[FridaInstallResult]):
    """Modal for confirming Frida server installation.

    Shows a warning-styled overlay asking if the user wants to install
    Frida server on the target device.

    Returns FridaInstallResult with install=True/False.
    """

    DEFAULT_CSS = """
    FridaInstallModal .modal-container {
        border: solid $success;
        width: 55;
        max-width: 80%;
        max-height: 50%;
    }

    FridaInstallModal .modal-title {
        color: $success;
    }

    FridaInstallModal .modal-message {
        margin-bottom: 1;
    }

    FridaInstallModal #frida-device {
        color: $accent;
        text-align: center;
        margin-bottom: 1;
    }

    FridaInstallModal #frida-note {
        color: $text-muted;
        text-align: center;
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        Binding("enter", "install", "Install", show=False, priority=True),
        Binding("y", "install", "Yes", show=False, priority=True),
        Binding("n", "cancel", "No", show=False, priority=True),
        Binding("f", "install", "Install Frida", show=False, priority=True),
    ]

    AUTO_FOCUS = "#btn-install"

    def __init__(
        self,
        device_name: str = "device",
        feature_name: str = "this feature",
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the Frida installation modal.

        Args:
            device_name: Display name of the target device
            feature_name: Name of the feature that requires Frida
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.device_name = device_name
        self.feature_name = feature_name

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Frida Server Required", classes="modal-title")
            yield Label(
                f"{self.feature_name} requires Frida server to be running.",
                classes="modal-message",
            )
            yield Label(
                f"Target: [bold]{self.device_name}[/bold]",
                id="frida-device",
            )
            yield Static(
                "[dim]This will download and install frida-server on the device.[/dim]",
                id="frida-note",
            )

            with Horizontal(classes="button-row"):
                yield Button("Install & Start", id="btn-install", classes="-primary")
                yield Button("Cancel", id="btn-cancel", classes="-secondary")

            yield KeyHintFooter(
                hints={
                    "default": "[dim]Enter/Y/F=Install  Esc/N=Cancel[/dim]",
                    "button": "[dim]Enter/Y/F=Install  Esc/N=Cancel[/dim]",
                }
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-install":
            self._install()
        elif event.button.id == "btn-cancel":
            self.action_cancel()

    def action_install(self) -> None:
        """Install Frida server."""
        self._install()

    def _install(self) -> None:
        """Confirm installation and dismiss."""
        self._dismiss_with_refresh(
            FridaInstallResult(install=True, device_name=self.device_name)
        )

    def action_cancel(self) -> None:
        """Cancel and dismiss."""
        self._dismiss_with_refresh(
            FridaInstallResult(install=False, device_name=self.device_name)
        )
