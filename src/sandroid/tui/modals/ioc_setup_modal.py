"""IOC Setup modal for configuring MVT indicators."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, RadioButton, RadioSet

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter

# Import config with fallback for standalone usage
try:
    from sandroid.config import get_config
except ImportError:
    get_config = None


class IOCSetupResult:
    """Result from IOC setup modal.

    Attributes:
        cancelled: True if user cancelled setup
        source_type: 'path', 'url', 'mvt_download', or None
        value: The path or URL entered (empty for mvt_download)
        auto_update: Whether to auto-update IOCs (for URL source)
    """

    def __init__(
        self,
        cancelled: bool = True,
        source_type: str | None = None,
        value: str = "",
        auto_update: bool = False,
    ):
        self.cancelled = cancelled
        self.source_type = source_type
        self.value = value
        self.auto_update = auto_update


class IOCSetupModal(ForensicModal[IOCSetupResult]):
    """Modal for setting up IOC configuration.

    Shown when user tries to run forensic evidence scan
    but IOCs are not configured.

    Features:
    - Three source options: local path, URL, or MVT download
    - Tab to navigate between options
    - Enter to configure
    - Escape to cancel
    """

    BINDINGS = [
        # priority=True ensures Enter works even when input is focused
        Binding("enter", "submit", "Configure", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    IOCSetupModal .modal-container {
        width: 75;
        max-width: 90%;
        max-height: 80%;
        align: center middle;
    }

    IOCSetupModal #ioc-description {
        color: $foreground;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    IOCSetupModal #ioc-source-label {
        text-style: bold;
        color: $text-muted;
        height: 1;
        padding-top: 1;
    }

    IOCSetupModal #ioc-source-selector {
        padding: 0 1;
        height: auto;
        background: transparent;
        border: none;
    }

    IOCSetupModal #ioc-source-selector > RadioButton {
        height: 1;
        padding: 0;
        margin: 0;
        background: transparent;
    }

    IOCSetupModal #ioc-source-selector > RadioButton:focus {
        text-style: bold;
    }

    IOCSetupModal #ioc-input-container {
        padding: 1 0 0 0;
        height: auto;
    }

    IOCSetupModal #ioc-input-label {
        color: $text-muted;
        height: 1;
    }

    IOCSetupModal #ioc-hint {
        color: $text-muted;
        height: auto;
        padding-top: 1;
    }

    IOCSetupModal .button-row {
        margin-top: 1;
        align: center middle;
        width: 100%;
        height: 3;
    }

    IOCSetupModal #ioc-footer {
        text-align: center;
        color: $text-muted;
        height: 1;
        padding-top: 1;
    }

    /* Hidden state for input container */
    IOCSetupModal .hidden {
        display: none;
    }
    """

    # Default stalkerware IOC URL (kept as fallback)
    _DEFAULT_EXAMPLE_URL = (
        "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators"
        "/master/generated/stalkerware.stix2"
    )

    @classmethod
    def _get_stalkerware_url(cls) -> str:
        """Get stalkerware IOC URL from config with fallback."""
        try:
            if get_config is not None:
                return get_config().external_urls.stalkerware_ioc_url
        except Exception:
            pass
        return cls._DEFAULT_EXAMPLE_URL

    # Keep class-level alias for backwards compatibility
    EXAMPLE_URL = _DEFAULT_EXAMPLE_URL

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the IOC setup modal."""
        super().__init__(name=name, id=id, classes=classes)
        self._source_type = "path"

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("IOC Configuration", classes="modal-title")
            yield Label(
                "Configure Indicators of Compromise (IOC) for forensic scanning.",
                id="ioc-description",
            )

            yield Label("Select source:", id="ioc-source-label")
            with RadioSet(id="ioc-source-selector"):
                yield RadioButton(
                    "Local file or directory", id="source-path", value=True
                )
                yield RadioButton("Download from URL", id="source-url")
                yield RadioButton("Download MVT IOCs (mvt-android)", id="source-mvt")

            with Vertical(id="ioc-input-container"):
                yield Label("Path to IOC file/directory:", id="ioc-input-label")
                yield Input(
                    placeholder="e.g., ~/iocs/indicators.stix2",
                    id="ioc-input",
                )
                yield Label(
                    "[dim]Tip: AmnestyTech provides IOCs at "
                    "github.com/AmnestyTech/investigations[/dim]",
                    id="ioc-hint",
                )

            with Horizontal(classes="button-row"):
                yield Button("Configure", classes="-primary", id="btn-configure")
                yield Button("Cancel", classes="-secondary", id="btn-cancel")

            yield Label(
                "[dim]CLI: sandroid-config ioc[/dim]",
                id="ioc-footer",
            )

            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus the radio set on mount for Tab navigation."""
        try:
            # Focus radio set first so Tab works immediately
            radio_set = self.query_one("#ioc-source-selector", RadioSet)
            radio_set.focus()
        except Exception:
            pass

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Handle source type selection change."""
        if event.pressed.id == "source-path":
            self._source_type = "path"
            self._show_input_container(True)
            self._update_input_label("Path to IOC file/directory:")
            self._update_input_placeholder("e.g., ~/iocs/indicators.stix2")
            self._update_hint(
                "[dim]Tip: AmnestyTech provides IOCs at "
                "github.com/AmnestyTech/investigations[/dim]"
            )
        elif event.pressed.id == "source-url":
            self._source_type = "url"
            self._show_input_container(True)
            self._update_input_label("URL to STIX2 IOC file:")
            self._update_input_placeholder(self._get_stalkerware_url())
            self._update_hint(
                "[dim]The file will be downloaded and cached locally[/dim]"
            )
        elif event.pressed.id == "source-mvt":
            self._source_type = "mvt_download"
            self._show_input_container(False)
            self._update_hint("[dim]Will run: mvt-android download-iocs[/dim]")

    def _show_input_container(self, show: bool) -> None:
        """Show or hide the input container."""
        try:
            container = self.query_one("#ioc-input-container", Vertical)
            if show:
                container.remove_class("hidden")
            else:
                container.add_class("hidden")
        except Exception:
            pass

    def _update_input_label(self, text: str) -> None:
        """Update input label text."""
        try:
            label = self.query_one("#ioc-input-label", Label)
            label.update(text)
        except Exception:
            pass

    def _update_input_placeholder(self, text: str) -> None:
        """Update input placeholder text."""
        try:
            input_field = self.query_one("#ioc-input", Input)
            input_field.placeholder = text
        except Exception:
            pass

    def _update_hint(self, text: str) -> None:
        """Update hint text."""
        try:
            hint = self.query_one("#ioc-hint", Label)
            hint.update(text)
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-cancel":
            self.action_cancel()
        elif event.button.id == "btn-configure":
            self.action_submit()

    def action_cancel(self) -> None:
        """Cancel and close modal."""
        self._dismiss_with_refresh(IOCSetupResult(cancelled=True))

    def action_submit(self) -> None:
        """Process and submit the configuration."""
        try:
            # MVT download doesn't need input value
            if self._source_type == "mvt_download":
                result = IOCSetupResult(
                    cancelled=False,
                    source_type="mvt_download",
                    value="",
                    auto_update=False,
                )
                self._dismiss_with_refresh(result)
                return

            # Path and URL require input value
            input_field = self.query_one("#ioc-input", Input)
            value = input_field.value.strip()

            if not value:
                # Show error - value required
                input_field.add_class("error")
                return

            result = IOCSetupResult(
                cancelled=False,
                source_type=self._source_type,
                value=value,
                auto_update=self._source_type == "url",
            )
            self._dismiss_with_refresh(result)

        except Exception:
            self._dismiss_with_refresh(IOCSetupResult(cancelled=True))
