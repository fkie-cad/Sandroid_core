"""IOC Choice modal for selecting IOC source before forensic scan."""

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Checkbox, Label, RadioButton, RadioSet, Static

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


@dataclass
class IOCChoiceResult:
    """Result from IOC choice modal.

    Attributes:
        cancelled: Whether the modal was cancelled
        use_cached: True to use cached IOCs, False to configure new
        remember_choice: Whether to save this preference to config
    """

    cancelled: bool = True
    use_cached: bool = False
    remember_choice: bool = False


class IOCChoiceModal(ForensicModal[IOCChoiceResult]):
    """Modal for choosing IOC source before forensic scan.

    Shown when cached IOCs exist, allowing user to choose between:
    - Using existing cached IOCs
    - Configuring new IOCs (opens IOCSetupModal)

    Features:
    - Shows cached IOC details (path, file count, indicator count)
    - "Remember my choice" checkbox to skip this modal in future
    - Radio button selection for clear choice
    """

    BINDINGS = [
        Binding("enter", "continue", "Continue", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    IOCChoiceModal .modal-container {
        width: 70;
        max-width: 90%;
        max-height: 85%;
    }

    IOCChoiceModal #ioc-choice-description {
        color: $text-muted;
        text-align: center;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    IOCChoiceModal #ioc-options {
        padding: 1 0;
        height: auto;
        background: transparent;
        border: none;
    }

    IOCChoiceModal #ioc-options > RadioButton {
        height: auto;
        padding: 0;
        margin: 0 0 1 0;
        background: transparent;
    }

    IOCChoiceModal #ioc-options > RadioButton:focus {
        text-style: bold;
    }

    IOCChoiceModal .option-details {
        color: $text-muted;
        padding-left: 4;
        height: auto;
    }

    IOCChoiceModal .cached-info {
        padding-left: 4;
        height: auto;
    }

    IOCChoiceModal .cached-path {
        color: #6ba3ff;
    }

    IOCChoiceModal .cached-stats {
        color: $text-muted;
    }

    IOCChoiceModal #remember-section {
        padding: 1 0;
        height: auto;
        border-top: solid $panel;
        margin-top: 1;
    }

    IOCChoiceModal #remember-checkbox {
        padding-left: 1;
    }

    IOCChoiceModal .button-row {
        align: center middle;
        width: 100%;
        height: 3;
        margin-top: 1;
    }
    """

    def __init__(
        self,
        cached_info: dict,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the IOC choice modal.

        Args:
            cached_info: Dict with 'path', 'file_count', 'indicator_count'
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self._cached_info = cached_info
        self._use_cached = True  # Default to using cached

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("IOC Configuration", classes="modal-title")
            yield Label(
                "Select IOC source for forensic scan:",
                id="ioc-choice-description",
            )

            with RadioSet(id="ioc-options"):
                yield RadioButton(
                    "Use cached IOCs",
                    id="option-cached",
                    value=True,
                )
                yield RadioButton(
                    "Configure new IOCs",
                    id="option-new",
                )

            # Cached IOC details
            with Vertical(classes="cached-info", id="cached-details"):
                path = self._cached_info.get("path", "Unknown")
                # Shorten path for display
                if len(path) > 45:
                    path = "..." + path[-42:]
                yield Static(
                    f"[dim]Path:[/dim] [{self._get_path_color()}]{path}[/]",
                    classes="cached-path",
                )

                file_count = self._cached_info.get("file_count", 0)
                indicator_count = self._cached_info.get("indicator_count", 0)

                stats_text = f"[dim]Files:[/dim] {file_count} STIX2 files"
                if indicator_count > 0:
                    stats_text += (
                        f"  [dim]|[/dim]  [dim]Indicators:[/dim] {indicator_count:,}"
                    )
                yield Static(stats_text, classes="cached-stats")

            # New IOC option description
            yield Static(
                "[dim]Select local path, URL, or MVT download[/dim]",
                classes="option-details",
                id="new-option-details",
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

    def _get_path_color(self) -> str:
        """Get color for path based on IOC source."""
        path = self._cached_info.get("path", "")
        if "github_mvt" in path:
            return "#22c55e"  # Green for GitHub download
        if "mvt" in path.lower():
            return "#58a6ff"  # Blue for MVT
        return "#8b949e"  # Muted for other

    def on_mount(self) -> None:
        """Focus radio set on mount."""
        try:
            radio_set = self.query_one("#ioc-options", RadioSet)
            radio_set.focus()
            # Initially hide the new option details
            self._update_details_visibility()
        except Exception:
            pass

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Handle option selection change."""
        self._use_cached = event.pressed.id == "option-cached"
        self._update_details_visibility()

    def _update_details_visibility(self) -> None:
        """Show/hide details based on selection."""
        try:
            cached_details = self.query_one("#cached-details", Vertical)
            new_details = self.query_one("#new-option-details", Static)

            if self._use_cached:
                cached_details.display = True
                new_details.display = False
            else:
                cached_details.display = False
                new_details.display = True
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
        self._dismiss_with_refresh(IOCChoiceResult(cancelled=True))

    def action_continue(self) -> None:
        """Process the selection and dismiss."""
        try:
            checkbox = self.query_one("#remember-checkbox", Checkbox)
            remember = checkbox.value
        except Exception:
            remember = False

        result = IOCChoiceResult(
            cancelled=False,
            use_cached=self._use_cached,
            remember_choice=remember,
        )
        self.dismiss(result)
