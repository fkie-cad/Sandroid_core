"""Network capture configuration modal.

Provides a modal for configuring network packet capture:
- Set output path for pcap file
- Show current capture status
- Start/stop capture
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Input, Label, Static

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


@dataclass
class NetworkCaptureResult:
    """Result from the network capture modal.

    Attributes:
        cancelled: Whether the dialog was cancelled.
        action: Action to perform - "start", "stop", or "close".
        output_path: Path for the pcap file (for start action).
    """

    cancelled: bool = True
    action: str = "close"  # "start", "stop", "close"
    output_path: Path | None = None


class NetworkCaptureModal(ForensicModal[NetworkCaptureResult]):
    """Modal for configuring network packet capture.

    Features:
    - Shows current capture status
    - Input field for output path (pre-filled with default)
    - Start capture with Enter
    - Stop capture if already running
    - Cancel with Escape
    """

    DEFAULT_CSS = """
    NetworkCaptureModal .modal-container {
        width: 80;
        max-width: 90%;
    }

    NetworkCaptureModal #capture-status {
        width: 100%;
        height: 1;
        padding: 0 2;
        margin-bottom: 1;
        background: $panel;
    }

    NetworkCaptureModal #capture-status.running {
        color: $success;
    }

    NetworkCaptureModal #capture-status.stopped {
        color: $text-muted;
    }

    NetworkCaptureModal .section-header {
        color: #6ba3ff;
        text-style: bold;
        height: 1;
        margin-top: 1;
    }

    NetworkCaptureModal #path-row {
        height: auto;
        padding: 0;
        margin-bottom: 1;
    }

    NetworkCaptureModal #path-input {
        width: 100%;
    }

    NetworkCaptureModal #default-path-hint {
        color: $text-muted;
        height: 1;
        padding: 0 2;
    }
    """

    BINDINGS = [
        Binding("enter", "confirm", "Start/Stop", priority=True),
    ]

    def __init__(
        self,
        is_capturing: bool = False,
        current_file: str | None = None,
        default_path: str | None = None,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the network capture modal.

        Args:
            is_capturing: Whether capture is currently running.
            current_file: Current capture file path (if capturing).
            default_path: Default path for new capture.
            name: Widget name.
            id: Widget ID.
            classes: CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self.is_capturing = is_capturing
        self.current_file = current_file

        # Generate default path if not provided
        if default_path:
            self.default_path = default_path
        else:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            self.default_path = f"network_captures/{timestamp}.pcap"

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Network Capture Configuration", classes="modal-title")

            # Status indicator
            if self.is_capturing:
                status_text = (
                    f"[green]\u25cf[/] Capturing to: [bold]{self.current_file}[/]"
                )
                status_class = "running"
            else:
                status_text = "[dim]\u25cb[/] Not capturing"
                status_class = "stopped"

            yield Static(
                status_text,
                id="capture-status",
                classes=status_class,
            )

            # Path input section (only show if not currently capturing)
            if not self.is_capturing:
                yield Label("Output Path", classes="section-header")
                with Horizontal(id="path-row"):
                    yield Input(
                        value=self.default_path,
                        placeholder="Path for pcap file...",
                        id="path-input",
                    )
                yield Static(
                    f"[dim]Default: {self.default_path}[/dim]",
                    id="default-path-hint",
                )

            # Dynamic key hints via footer
            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus the path input on mount."""
        if not self.is_capturing:
            try:
                self.query_one("#path-input", Input).focus()
            except NoMatches:
                pass

    def action_confirm(self) -> None:
        """Confirm action - start or stop capture."""
        if self.is_capturing:
            # Stop capture
            result = NetworkCaptureResult(
                cancelled=False,
                action="stop",
                output_path=None,
            )
        else:
            # Start capture with specified path
            path_input = self.query_one("#path-input", Input)
            path_value = path_input.value.strip()

            if not path_value:
                path_value = self.default_path

            # Ensure .pcap extension
            if not path_value.endswith(".pcap"):
                path_value += ".pcap"

            result = NetworkCaptureResult(
                cancelled=False,
                action="start",
                output_path=Path(path_value),
            )

        self._dismiss_with_refresh(result)

    def action_cancel(self) -> None:
        """Cancel and close the modal."""
        result = NetworkCaptureResult(cancelled=True, action="close")
        self._dismiss_with_refresh(result)
