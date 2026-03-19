"""Device information modal for displaying comprehensive device details.

Shows a scrollable, sectioned view of device information including
system details, location, network, and snapshots (for emulators).
"""

from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.widgets import Button, Label, Static

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


class DeviceInfoModal(ForensicModal[None]):
    """Modal for displaying comprehensive device information.

    Features:
    - Scrollable content for all device info sections
    - Adapts display for emulator vs physical devices
    - Vim-style keyboard navigation (j/k, g/G)
    - Dismiss with Esc, q, Enter, or OK button
    """

    BINDINGS = [
        Binding("q", "close", "Close", priority=True),
        Binding("enter", "close", "OK", priority=True),
        Binding("down", "scroll_down", "Down", show=False),
        Binding("up", "scroll_up", "Up", show=False),
        Binding("j", "scroll_down", "Down", show=False),
        Binding("k", "scroll_up", "Up", show=False),
        Binding("g", "scroll_top", "Top", show=False),
        Binding("G", "scroll_bottom", "Bottom", show=False),
    ]

    DEFAULT_CSS = """
    DeviceInfoModal .modal-container {
        width: 80%;
        max-width: 90;
        height: auto;
        max-height: 80%;
    }

    DeviceInfoModal #device-info-scroll {
        height: auto;
        max-height: 100%;
    }

    DeviceInfoModal #device-info-content {
        width: 100%;
        height: auto;
    }
    """

    def __init__(
        self,
        info: dict[str, Any],
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the device info modal.

        Args:
            info: Device info dictionary from DeviceService.get_device_info()
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self._info = info

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        from sandroid.services.renderers import DeviceInfoRenderer

        title = "Device Information"
        content = DeviceInfoRenderer.format_for_tui(self._info)

        with Vertical(classes="modal-container"):
            yield Label(title, classes="modal-title")

            with VerticalScroll(id="device-info-scroll"):
                yield Static(content, id="device-info-content")

            with Vertical(classes="button-row"):
                yield Button("OK", id="ok", classes="-primary")
            yield KeyHintFooter(
                hints={
                    "button": "[dim]Enter=OK  Esc=Close  j/k=Scroll  g/G=Top/Bottom[/dim]",
                }
            )

    def on_mount(self) -> None:
        """Focus scroll container on mount."""
        super().on_mount()
        try:
            self.query_one("#device-info-scroll", VerticalScroll).focus()
        except NoMatches:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self._dismiss_with_refresh(None)

    def action_close(self) -> None:
        self._dismiss_with_refresh(None)

    def _scroll_action(self, method_name: str, **kwargs) -> None:
        """Execute a scroll method on the scroll container."""
        try:
            scroll = self.query_one("#device-info-scroll", VerticalScroll)
            getattr(scroll, method_name)(**kwargs)
        except Exception:
            pass

    def action_scroll_down(self) -> None:
        self._scroll_action("scroll_relative", y=1)

    def action_scroll_up(self) -> None:
        self._scroll_action("scroll_relative", y=-1)

    def action_scroll_top(self) -> None:
        self._scroll_action("scroll_home")

    def action_scroll_bottom(self) -> None:
        self._scroll_action("scroll_end")
