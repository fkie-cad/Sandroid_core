"""Toggle configuration modal for multi-option settings.

Styled to match ObjectionModal with keyboard-only navigation.
"""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Label, Static

from .base import ForensicModal, KeyHintFooter


class ToggleConfigModal(ForensicModal[dict[str, bool]]):
    """Modal for toggling multiple configuration options.

    Features:
    - Centered overlay with semi-transparent background
    - Static text with [n] bullet indicators (no switch widgets)
    - Number keys (1-9) to toggle options
    - Enter to apply, Escape to cancel
    - No buttons - keyboard shortcuts only
    - Returns dict with updated values or None if cancelled
    """

    DEFAULT_CSS = """
    ToggleConfigModal .modal-container {
        width: 80;
        max-height: 24;
        max-width: 90%;
    }

    ToggleConfigModal .modal-message {
        margin-bottom: 1;
    }

    ToggleConfigModal .toggle-option {
        width: 100%;
        height: 1;
        padding: 0 2;
        margin: 0;
        background: $surface;
    }

    ToggleConfigModal .toggle-option.enabled {
        color: $success;
    }

    ToggleConfigModal .toggle-option.disabled {
        color: $foreground-muted;
    }
    """

    BINDINGS = [
        Binding("enter", "submit", "Apply", priority=True),
        Binding("1", "toggle_1", "Toggle 1", show=False),
        Binding("2", "toggle_2", "Toggle 2", show=False),
        Binding("3", "toggle_3", "Toggle 3", show=False),
        Binding("4", "toggle_4", "Toggle 4", show=False),
        Binding("5", "toggle_5", "Toggle 5", show=False),
        Binding("6", "toggle_6", "Toggle 6", show=False),
        Binding("7", "toggle_7", "Toggle 7", show=False),
        Binding("8", "toggle_8", "Toggle 8", show=False),
        Binding("9", "toggle_9", "Toggle 9", show=False),
    ]

    AUTO_FOCUS = ".modal-container"

    def __init__(
        self,
        title: str,
        options: dict[str, bool],
        message: str = "",
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the toggle configuration modal.

        Args:
            title: Dialog title
            options: Dict of {option_name: current_value (bool)}
            message: Optional description text
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.title_text = title
        self.message_text = message
        self.options = options.copy()
        self._option_keys = list(options.keys())

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label(self.title_text, classes="modal-title")
            if self.message_text:
                yield Label(self.message_text, classes="modal-message")

            # Create static options with [n] bullet indicators
            for idx, (name, value) in enumerate(self.options.items(), 1):
                indicator = "\u25cf" if value else "\u25cb"  # or
                css_class = "enabled" if value else "disabled"
                yield Static(
                    f"[{idx}] {indicator} {name}",
                    id=f"option-{idx}",
                    classes=f"toggle-option {css_class}",
                )

            # Key hint footer with toggle-specific hints
            max_key = min(len(self.options), 9)
            yield KeyHintFooter(
                hints={
                    "default": f"[dim]1-{max_key}=Toggle  Enter=Apply  Esc=Cancel[/dim]"
                }
            )

    def _toggle_option(self, index: int) -> None:
        """Toggle an option by its 1-based index."""
        if 1 <= index <= len(self._option_keys):
            key = self._option_keys[index - 1]
            self.options[key] = not self.options[key]
            self._update_display()

    def _update_display(self) -> None:
        """Update the visual state of all options."""
        for idx, (name, enabled) in enumerate(self.options.items(), 1):
            try:
                option = self.query_one(f"#option-{idx}", Static)
                indicator = "\u25cf" if enabled else "\u25cb"
                color = "green" if enabled else "dim"
                option.update(f"[{idx}] [{color}]{indicator}[/] {name}")
                option.set_class(enabled, "enabled")
                option.set_class(not enabled, "disabled")
            except Exception:
                pass

    # Toggle action handlers for keys 1-9
    def action_toggle_1(self) -> None:
        self._toggle_option(1)

    def action_toggle_2(self) -> None:
        self._toggle_option(2)

    def action_toggle_3(self) -> None:
        self._toggle_option(3)

    def action_toggle_4(self) -> None:
        self._toggle_option(4)

    def action_toggle_5(self) -> None:
        self._toggle_option(5)

    def action_toggle_6(self) -> None:
        self._toggle_option(6)

    def action_toggle_7(self) -> None:
        self._toggle_option(7)

    def action_toggle_8(self) -> None:
        self._toggle_option(8)

    def action_toggle_9(self) -> None:
        self._toggle_option(9)

    def action_submit(self) -> None:
        """Submit the configuration."""
        self._dismiss_with_refresh(self.options.copy())


class FridaToggleConfigModal(ToggleConfigModal):
    """Toggle config modal with Frida green theme for Frida-related tools."""

    DEFAULT_CSS = """
    FridaToggleConfigModal .modal-container {
        border: solid $success;
    }

    FridaToggleConfigModal .modal-title {
        color: $success;
    }
    """
