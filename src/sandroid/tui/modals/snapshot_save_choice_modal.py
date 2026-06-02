"""Choice modal for saving into an already-occupied snapshot slot."""

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Checkbox, Label, RadioButton, RadioSet

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


@dataclass
class SnapshotSaveChoiceResult:
    """Result from the save-to-occupied-slot choice modal.

    Attributes:
        cancelled: Whether the modal was cancelled.
        mode: ``"overwrite"`` (re-save the slot's current tag in place) or
            ``"fresh"`` (create a new timestamped snapshot and re-point the slot).
        remember: Whether to persist ``mode`` as the default (skip this prompt
            in future saves).
    """

    cancelled: bool = True
    mode: str = "overwrite"
    remember: bool = False


class SnapshotSaveChoiceModal(ForensicModal[SnapshotSaveChoiceResult]):
    """Ask how to save into a slot that already holds a snapshot.

    Two outcomes: overwrite the existing snapshot in place, or keep it and save
    a fresh (timestamped) snapshot, re-pointing the slot. A "Don't ask again"
    checkbox persists the chosen mode to ``tui.snapshot_save_mode``.
    """

    BINDINGS = [
        Binding("enter", "continue", "Continue", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    SnapshotSaveChoiceModal .modal-container {
        width: 68;
        max-width: 90%;
        max-height: 85%;
    }

    SnapshotSaveChoiceModal #save-choice-description {
        color: $text-muted;
        text-align: center;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    SnapshotSaveChoiceModal #save-options {
        padding: 1 0;
        height: auto;
        background: transparent;
        border: none;
    }

    SnapshotSaveChoiceModal #save-options > RadioButton {
        height: auto;
        padding: 0;
        margin: 0 0 1 0;
        background: transparent;
    }

    SnapshotSaveChoiceModal #save-options > RadioButton:focus {
        text-style: bold;
    }

    SnapshotSaveChoiceModal #remember-section {
        padding: 1 0;
        height: auto;
        border-top: solid $panel;
        margin-top: 1;
    }

    SnapshotSaveChoiceModal #remember-checkbox {
        padding-left: 1;
    }

    SnapshotSaveChoiceModal .button-row {
        align: center middle;
        width: 100%;
        height: 3;
        margin-top: 1;
    }
    """

    def __init__(
        self,
        slot: str,
        existing_tag: str,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the save-choice modal.

        Args:
            slot: The slot number being saved into (e.g. ``"3"``).
            existing_tag: The snapshot tag the slot currently points at.
            name: Widget name.
            id: Widget ID.
            classes: CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._slot = slot
        self._existing_tag = existing_tag
        self._mode = "overwrite"  # default selection

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Save to slot", classes="modal-title")
            yield Label(
                f"Slot {self._slot} already holds [b]{self._existing_tag}[/]. "
                "How should the current state be saved?",
                id="save-choice-description",
            )

            with RadioSet(id="save-options"):
                yield RadioButton(
                    f"Overwrite '{self._existing_tag}' in place",
                    id="option-overwrite",
                    value=True,
                )
                yield RadioButton(
                    "Keep it — save a new snapshot and re-point the slot",
                    id="option-fresh",
                )

            with Vertical(id="remember-section"):
                yield Checkbox(
                    "Don't ask again (remember this choice)",
                    id="remember-checkbox",
                )

            with Horizontal(classes="button-row"):
                yield Button("Save", classes="-primary", id="btn-continue")
                yield Button("Cancel", classes="-secondary", id="btn-cancel")

            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus the option set on mount."""
        try:
            self.query_one("#save-options", RadioSet).focus()
        except Exception:
            pass

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Track the selected save mode."""
        self._mode = "fresh" if event.pressed.id == "option-fresh" else "overwrite"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-continue":
            self.action_continue()
        elif event.button.id == "btn-cancel":
            self.action_cancel()

    def action_cancel(self) -> None:
        """Cancel and close the modal."""
        self._dismiss_with_refresh(SnapshotSaveChoiceResult(cancelled=True))

    def action_continue(self) -> None:
        """Commit the selection and dismiss."""
        try:
            remember = self.query_one("#remember-checkbox", Checkbox).value
        except Exception:
            remember = False
        self.dismiss(
            SnapshotSaveChoiceResult(
                cancelled=False,
                mode=self._mode,
                remember=remember,
            )
        )
