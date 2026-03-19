"""Screenshot modal for taking device screenshots."""

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, Input, Label

from .base import ExtractionModal, KeyHintFooter


@dataclass
class ScreenshotResult:
    """Result from screenshot modal.

    Attributes:
        cancelled: True if user cancelled
        filename: Filename entered (None or empty for auto-timestamp)
    """

    cancelled: bool = True
    filename: str | None = None


class ScreenshotModal(ExtractionModal[ScreenshotResult]):
    """Modal for taking a screenshot with optional custom filename.

    Features:
    - Centered modal with transparent background
    - Input for custom filename (optional)
    - Auto-generates timestamped name if left blank
    """

    BINDINGS = [
        Binding("enter", "submit", "Submit", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    ScreenshotModal .modal-container {
        width: 60;
        max-width: 90%;
    }

    ScreenshotModal #screenshot-label {
        color: $foreground;
        height: 1;
        padding-top: 1;
    }

    ScreenshotModal #screenshot-hint {
        color: $foreground-muted;
        height: 1;
        padding-top: 0;
    }
    """

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Take Screenshot", classes="modal-title")

            yield Label("Enter filename (optional):", id="screenshot-label")
            yield Input(
                placeholder="Leave blank for auto timestamp",
                id="screenshot-input",
            )
            yield Label(
                "[dim]e.g., my_screenshot.png[/dim]",
                id="screenshot-hint",
            )

            with Horizontal(classes="button-row"):
                yield Button("Take Screenshot", id="btn-take", classes="-primary")
                yield Button("Cancel", id="btn-cancel", classes="-secondary")

            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus input on mount."""
        super().on_mount()
        try:
            self.query_one("#screenshot-input", Input).focus()
        except NoMatches:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id

        if button_id == "btn-cancel":
            self.action_cancel()
        elif button_id == "btn-take":
            self._take_screenshot()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter in input field."""
        if event.input.id == "screenshot-input":
            self._take_screenshot()

    def action_submit(self) -> None:
        """Handle Enter key."""
        self._take_screenshot()

    def _take_screenshot(self) -> None:
        """Take the screenshot with the entered filename."""
        try:
            input_field = self.query_one("#screenshot-input", Input)
            filename = input_field.value.strip()

            # Empty string means use auto-timestamp
            self._dismiss_with_refresh(
                ScreenshotResult(
                    cancelled=False,
                    filename=filename if filename else None,
                )
            )
        except Exception:
            self._dismiss_with_refresh(ScreenshotResult(cancelled=True))
