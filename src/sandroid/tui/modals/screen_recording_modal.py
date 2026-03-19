"""Screen recording status modal for TUI mode.

Shows recording status and allows stopping screen recording.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Button, Label, Static

from sandroid.tui.modals.base import ExtractionModal, KeyHintFooter

if TYPE_CHECKING:
    from textual.timer import Timer


@dataclass
class ScreenRecordingResult:
    """Result from screen recording modal."""

    stopped: bool = False


class ScreenRecordingModal(ExtractionModal[ScreenRecordingResult]):
    """Modal showing screen recording status with stop button.

    Features:
    - Shows recording is in progress
    - Displays elapsed time
    - Stop via button, Enter, or Escape
    """

    BINDINGS = [
        Binding("enter", "stop", "Stop", priority=True),
        # Escape is handled by overriding action_cancel from base class
    ]

    DEFAULT_CSS = """
    ScreenRecordingModal .modal-container {
        width: 60;
        height: auto;
        min-height: 14;
        border: solid $error;
    }

    ScreenRecordingModal .modal-title {
        color: $error;
    }

    ScreenRecordingModal #recording-status {
        text-align: center;
        width: 100%;
        height: 1;
        color: $error;
        text-style: bold;
        margin-top: 1;
    }

    ScreenRecordingModal #elapsed-time {
        text-align: center;
        width: 100%;
        height: 1;
        color: $foreground-muted;
    }

    ScreenRecordingModal #output-file {
        text-align: center;
        width: 100%;
        height: auto;
        color: $foreground-muted;
        margin-top: 1;
        margin-bottom: 1;
    }

    ScreenRecordingModal .button-row {
        width: 100%;
        height: auto;
        align: center middle;
        margin-top: 1;
    }

    ScreenRecordingModal #btn-stop {
        background: $error;
        color: #ffffff;
        min-width: 18;
    }

    ScreenRecordingModal #btn-stop:hover {
        background: $error-darken-1;
    }
    """

    elapsed_seconds = reactive(0)

    def __init__(
        self,
        output_file: str = "",
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        super().__init__(name=name, id=id, classes=classes)
        self._output_file = output_file
        self._timer: Timer | None = None

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label("Screen Recording", classes="modal-title")
            yield Static("● RECORDING", id="recording-status")
            yield Static("Elapsed: 00:00", id="elapsed-time")
            yield Static(f"[dim]{self._output_file}[/dim]", id="output-file")

            with Horizontal(classes="button-row"):
                yield Button("Stop Recording", id="btn-stop", classes="-primary")

            yield KeyHintFooter(
                hints={
                    "default": "[dim]Enter/Esc=Stop Recording[/dim]",
                }
            )

    def on_mount(self) -> None:
        super().on_mount()
        self._timer = self.set_interval(1.0, self._update_elapsed)
        try:
            btn = self.query_one("#btn-stop", Button)
            btn.focus()
        except Exception:
            pass

    def watch_elapsed_seconds(self, seconds: int) -> None:
        try:
            elapsed_label = self.query_one("#elapsed-time", Static)
            mins, secs = divmod(seconds, 60)
            elapsed_label.update(f"Elapsed: {mins:02d}:{secs:02d}")
        except Exception:
            pass

    def _update_elapsed(self) -> None:
        self.elapsed_seconds += 1

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-stop":
            self._stop()

    def action_stop(self) -> None:
        self._stop()

    def action_cancel(self) -> None:
        self._stop()

    def _stop(self) -> None:
        if self._timer:
            self._timer.stop()
        self._dismiss_with_refresh(ScreenRecordingResult(stopped=True))
