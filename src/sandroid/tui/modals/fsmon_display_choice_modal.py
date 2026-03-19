"""FSMon display choice modal for selecting observer vs background output."""

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Checkbox, Label, RadioButton, RadioSet, Static

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


@dataclass
class FSMonDisplayChoice:
    """Result from FSMon display choice modal.

    Attributes:
        cancelled: Whether the modal was cancelled
        display_mode: "observer" or "background"
        remember_choice: Whether to save this preference to config
    """

    cancelled: bool = True
    display_mode: str = "observer"
    remember_choice: bool = False


class FSMonDisplayChoiceModal(ForensicModal[FSMonDisplayChoice]):
    """Modal for choosing where FSMon output is displayed.

    Options:
    - Observer Modal: Live output in a dedicated window (can minimize/restore)
    - Background Activity: Output goes to the activity log panel

    Features:
    - Radio button selection
    - "Remember my choice" checkbox
    """

    BINDINGS = [
        Binding("enter", "continue", "Continue", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    FSMonDisplayChoiceModal .modal-container {
        width: 70;
        max-width: 90%;
        max-height: 85%;
    }

    FSMonDisplayChoiceModal #display-choice-description {
        color: $text-muted;
        text-align: center;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    FSMonDisplayChoiceModal #display-options {
        padding: 1 0;
        height: auto;
        background: transparent;
        border: none;
    }

    FSMonDisplayChoiceModal #display-options > RadioButton {
        height: auto;
        padding: 0;
        margin: 0 0 1 0;
        background: transparent;
    }

    FSMonDisplayChoiceModal #display-options > RadioButton:focus {
        text-style: bold;
    }

    FSMonDisplayChoiceModal .option-details {
        color: $text-muted;
        padding-left: 4;
        height: auto;
    }

    FSMonDisplayChoiceModal #remember-section {
        padding: 1 0;
        height: auto;
        border-top: solid $panel;
        margin-top: 1;
    }

    FSMonDisplayChoiceModal #remember-checkbox {
        padding-left: 1;
    }

    FSMonDisplayChoiceModal .button-row {
        align: center middle;
        width: 100%;
        height: 3;
        margin-top: 1;
    }
    """

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the FSMon display choice modal."""
        super().__init__(name=name, id=id, classes=classes)
        self._use_observer = True  # Default to observer

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("FSMon Display Mode", classes="modal-title")
            yield Label(
                "Choose where to view filesystem monitoring output:",
                id="display-choice-description",
            )

            with RadioSet(id="display-options"):
                yield RadioButton(
                    "Observer Modal",
                    id="option-observer",
                    value=True,
                )
                yield RadioButton(
                    "Background Activity",
                    id="option-background",
                )

            # Option descriptions
            yield Static(
                "[dim]Live output in a dedicated window. Can be minimized and restored.[/dim]",
                classes="option-details",
                id="observer-details",
            )
            yield Static(
                "[dim]Output goes to the activity log panel on the right.[/dim]",
                classes="option-details",
                id="background-details",
            )

            # Remember choice section
            with Vertical(id="remember-section"):
                yield Checkbox(
                    "Remember my choice",
                    id="remember-checkbox",
                )

            with Horizontal(classes="button-row"):
                yield Button("Continue", classes="-primary", id="btn-continue")
                yield Button("Cancel", classes="-secondary", id="btn-cancel")

            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus radio set on mount."""
        try:
            radio_set = self.query_one("#display-options", RadioSet)
            radio_set.focus()
            self._update_details_visibility()
        except Exception:
            pass

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Handle option selection change."""
        self._use_observer = event.pressed.id == "option-observer"
        self._update_details_visibility()

    def _update_details_visibility(self) -> None:
        """Show/hide details based on selection."""
        try:
            observer_details = self.query_one("#observer-details", Static)
            background_details = self.query_one("#background-details", Static)

            if self._use_observer:
                observer_details.display = True
                background_details.display = False
            else:
                observer_details.display = False
                background_details.display = True
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-continue":
            self.action_continue()
        elif event.button.id == "btn-cancel":
            self.action_cancel()

    def action_cancel(self) -> None:
        """Cancel and close modal."""
        self._dismiss_with_refresh(FSMonDisplayChoice(cancelled=True))

    def action_continue(self) -> None:
        """Process the selection and dismiss."""
        try:
            checkbox = self.query_one("#remember-checkbox", Checkbox)
            remember = checkbox.value
        except Exception:
            remember = False

        result = FSMonDisplayChoice(
            cancelled=False,
            display_mode="observer" if self._use_observer else "background",
            remember_choice=remember,
        )
        self.dismiss(result)
