"""Device switch confirmation modal."""

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, Label, Static

from .base import DangerModal, KeyHintFooter


@dataclass
class DeviceSwitchContext:
    """Context information for device switch confirmation."""

    from_device: str  # Display name of current device
    to_device: str  # Display name of target device
    to_serial: str  # Serial of target device
    has_spotlight: bool  # Whether spotlight app is set
    spotlight_app: str  # Name of spotlight app (if any)
    running_tasks: list[str]  # List of running background task names
    has_snapshots: bool  # Whether there are active snapshots (emulator only)


@dataclass
class DeviceSwitchResult:
    """Result from device switch confirmation."""

    confirmed: bool
    target_serial: str


class DeviceSwitchConfirmModal(DangerModal[DeviceSwitchResult]):
    """Modal for confirming device switch during active session.

    Shows what will be affected by the switch:
    - Active background tasks will be stopped
    - Spotlight app will be cleared
    - Frida hooks will be detached
    - Current results will be preserved

    Returns DeviceSwitchResult with confirmed=True/False and target serial.
    """

    DEFAULT_CSS = """
    DeviceSwitchConfirmModal .modal-container {
        width: 60;
        max-width: 85%;
        max-height: 70%;
    }

    DeviceSwitchConfirmModal .switch-subtitle {
        color: $foreground;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: 2;
    }

    DeviceSwitchConfirmModal .switch-section {
        margin: 0;
        padding: 0 1;
        width: 100%;
        height: auto;
    }

    DeviceSwitchConfirmModal .switch-section-title {
        text-style: bold;
        color: $error;
        padding-top: 1;
        padding-bottom: 0;
        height: 1;
    }

    DeviceSwitchConfirmModal .switch-section-title-preserved {
        text-style: bold;
        color: $primary;
        padding-top: 1;
        padding-bottom: 0;
        height: 1;
    }

    DeviceSwitchConfirmModal .switch-item {
        color: $foreground;
        padding-left: 1;
        height: 1;
    }

    DeviceSwitchConfirmModal .switch-item-warning {
        color: $warning;
        padding-left: 1;
        height: 1;
    }

    DeviceSwitchConfirmModal .switch-item-info {
        color: $text-muted;
        padding-left: 1;
        height: 1;
    }

    DeviceSwitchConfirmModal .switch-item-preserved {
        color: $primary-lighten-1;
        padding-left: 1;
        height: 1;
    }
    """

    BINDINGS = [
        # Keep modal-specific bindings - ESC inherited from SandroidModal
        # priority=True ensures Enter triggers confirm even when Cancel button is focused
        Binding("enter", "confirm", "Confirm", show=False, priority=True),
        Binding("y", "confirm", "Yes", show=False),
        Binding("n", "cancel", "No", show=False),
    ]

    def __init__(
        self,
        context: DeviceSwitchContext,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the device switch confirmation modal.

        Args:
            context: DeviceSwitchContext with switch details
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.context = context

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        ctx = self.context

        with Vertical(classes="modal-container"):
            yield Label("Device Switch", classes="modal-title")
            yield Label(
                f"Switch from [bold]{ctx.from_device}[/] to [bold]{ctx.to_device}[/]?",
                classes="switch-subtitle",
            )

            # What will be affected section
            with Vertical(classes="switch-section"):
                yield Static(
                    "The following will occur:",
                    classes="switch-section-title",
                )

                # Background tasks
                if ctx.running_tasks:
                    tasks_str = ", ".join(ctx.running_tasks)
                    yield Static(
                        f"• Background tasks stopped: {tasks_str}",
                        classes="switch-item-warning",
                    )
                else:
                    yield Static(
                        "• No background tasks running",
                        classes="switch-item-info",
                    )

                # Spotlight app
                if ctx.has_spotlight:
                    yield Static(
                        f"• Spotlight app cleared: {ctx.spotlight_app}",
                        classes="switch-item-warning",
                    )

                # Frida hooks
                yield Static(
                    "• All Frida hooks will be detached",
                    classes="switch-item",
                )

                # Snapshots (emulator only)
                if ctx.has_snapshots:
                    yield Static(
                        "• Emulator snapshots will be cleared",
                        classes="switch-item-warning",
                    )

            # What will be preserved section
            with Vertical(classes="switch-section"):
                yield Static(
                    "The following will be preserved:",
                    classes="switch-section-title-preserved",
                )
                yield Static(
                    "• Current results and collected data",
                    classes="switch-item-preserved",
                )
                yield Static(
                    "• New device data saved to subfolder",
                    classes="switch-item-preserved",
                )

            # Buttons
            with Horizontal(classes="button-row"):
                yield Button("Switch", classes="-primary", id="btn-confirm")
                yield Button("Cancel", classes="-secondary", id="btn-cancel")

            yield KeyHintFooter(
                hints={"button": "[dim]Enter/y=Switch  Esc/n=Cancel[/dim]"}
            )

    def on_mount(self) -> None:
        """Focus cancel button by default (safer option)."""
        try:
            self.query_one("#btn-cancel", Button).focus()
        except NoMatches:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-confirm":
            self._confirm()
        elif event.button.id == "btn-cancel":
            self._cancel()

    def action_confirm(self) -> None:
        """Confirm the device switch."""
        self._confirm()

    def action_cancel(self) -> None:
        """Cancel the device switch."""
        self._cancel()

    def _confirm(self) -> None:
        """Confirm and dismiss with result."""
        self.dismiss(
            DeviceSwitchResult(confirmed=True, target_serial=self.context.to_serial)
        )

    def _cancel(self) -> None:
        """Cancel and dismiss with refresh."""
        self._dismiss_with_refresh(
            DeviceSwitchResult(confirmed=False, target_serial="")
        )
