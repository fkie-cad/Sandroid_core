"""Scan progress modal for forensic evidence scanning."""

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.containers import Center, Vertical
from textual.reactive import reactive
from textual.widgets import Button, Label, ProgressBar, Static

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


@dataclass
class ScanProgressResult:
    """Result from scan progress modal."""

    cancelled: bool = False
    completed: bool = False


class ScanProgressModal(ForensicModal[ScanProgressResult]):
    """Modal showing scan progress during forensic evidence scanning.

    Features:
    - Shows current scan type (APPS, SMS, CALLS, FILES)
    - Progress bar with percentage
    - Current item being scanned
    - Cancel button to abort scan
    - Auto-closes when scan completes
    """

    DEFAULT_CSS = """
    ScanProgressModal .modal-container {
        width: 90%;
        max-width: 80;
        max-height: 20;
    }

    ScanProgressModal #scan-type-label {
        text-align: center;
        color: $warning;
        text-style: bold;
        margin-bottom: 1;
        width: 100%;
    }

    ScanProgressModal #scan-progress-bar {
        margin: 1 0;
        width: 100%;
    }

    ScanProgressModal #scan-message {
        text-align: center;
        color: $text-muted;
        margin: 1 0;
        width: 100%;
    }

    ScanProgressModal #scan-item {
        text-align: center;
        color: $foreground;
        height: 1;
        margin-bottom: 1;
        width: 100%;
    }

    ScanProgressModal .button-row {
        align: center middle;
        width: 100%;
        height: auto;
    }
    """

    # Reactive properties for live updates
    scan_type = reactive("Initializing...")
    progress = reactive(0.0)
    message = reactive("Starting scan...")
    current_item = reactive("")
    is_complete = reactive(False)

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the scan progress modal.

        Args:
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self._cancelled = False

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Forensic Evidence Scan", classes="modal-title")
            yield Label(self.scan_type, id="scan-type-label")
            yield ProgressBar(id="scan-progress-bar", show_eta=False)
            yield Static(self.message, id="scan-message")
            yield Static(self.current_item, id="scan-item")
            with Center(classes="button-row"):
                yield Button("Cancel", classes="-secondary", id="cancel-button")
            yield KeyHintFooter()

    def watch_scan_type(self, value: str) -> None:
        """Update scan type label when changed."""
        try:
            label = self.query_one("#scan-type-label", Label)
            label.update(f"[{value}]")
        except Exception:
            pass

    def watch_progress(self, value: float) -> None:
        """Update progress bar when changed."""
        try:
            progress_bar = self.query_one("#scan-progress-bar", ProgressBar)
            progress_bar.update(progress=value)
        except Exception:
            pass

    def watch_message(self, value: str) -> None:
        """Update message when changed."""
        try:
            static = self.query_one("#scan-message", Static)
            static.update(value)
        except Exception:
            pass

    def watch_current_item(self, value: str) -> None:
        """Update current item when changed."""
        try:
            static = self.query_one("#scan-item", Static)
            static.update(f"[dim]{value}[/dim]" if value else "")
        except Exception:
            pass

    def watch_is_complete(self, value: bool) -> None:
        """Handle scan completion."""
        if value and not self._cancelled:
            # Auto-dismiss after a short delay
            self.set_timer(0.5, self._dismiss_complete)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        if event.button.id == "cancel-button":
            self._cancelled = True
            self.dismiss(ScanProgressResult(cancelled=True))

    def update_progress(
        self,
        scan_type: str = None,
        current: int = 0,
        total: int = 0,
        item: str = "",
        message: str = "",
    ) -> None:
        """Update scan progress from callback.

        Args:
            scan_type: Current scan type (APPS, SMS, CALLS, FILES)
            current: Current item number
            total: Total items
            item: Current item being scanned
            message: Status message
        """
        if scan_type:
            self.scan_type = scan_type

        if total > 0:
            self.progress = current / total
        elif current == 0 and total == 0:
            # Indeterminate progress
            self.progress = 0

        if message:
            self.message = message
        elif total > 0:
            self.message = f"{current}/{total} ({self.progress * 100:.0f}%)"

        self.current_item = item

    def mark_complete(self) -> None:
        """Mark the scan as complete."""
        self.progress = 1.0
        self.message = "Scan complete!"
        self.current_item = ""
        self.is_complete = True

    def _dismiss_complete(self) -> None:
        """Dismiss modal when scan is complete."""
        if not self._cancelled:
            self.dismiss(ScanProgressResult(completed=True))

    @property
    def cancelled(self) -> bool:
        """Check if scan was cancelled."""
        return self._cancelled
