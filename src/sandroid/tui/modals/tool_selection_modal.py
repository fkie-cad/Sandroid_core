"""Tool Selection Modal for Frida-based analysis tools."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.binding import Binding
from textual.containers import Vertical
from textual.css.query import NoMatches
from textual.widgets import Label, Static

from .base import FridaModal, KeyHintFooter

if TYPE_CHECKING:
    from textual.app import ComposeResult


class ToolSelectionModal(FridaModal[dict[str, bool] | None]):
    """Modal for selecting Frida tools to load.

    Supports both multi-select mode (for multi-tool spawn) and single-select mode.

    Available tools:
    - FriTap: SSL/TLS interception and decryption
    - Dexray-Intercept: Runtime monitoring of crypto, network, file operations
    - TrigDroid Bypass: SSL unpinning, root/frida/emulator/debug detection bypass

    Returns a dict with selected tools, e.g.:
        {'fritap': True, 'dexray': False, 'trigdroid_bypass': True}
    Or None if cancelled.
    """

    DEFAULT_CSS = """
    ToolSelectionModal .modal-container {
        border: solid $success;
        width: 70;
        max-width: 90%;
    }

    ToolSelectionModal .modal-title {
        color: $success;
    }

    ToolSelectionModal #tool-selection-subtitle {
        color: $text-muted;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: 1;
        margin-bottom: 1;
    }

    ToolSelectionModal .tool-option {
        width: 100%;
        height: auto;
        padding: 1 2;
        margin-bottom: 1;
        background: $panel;
        border: solid $foreground-muted;
    }

    ToolSelectionModal .tool-option:hover {
        background: $panel-lighten-1;
    }

    ToolSelectionModal .tool-option.selected {
        border: solid $success;
        background: $panel-lighten-1;
    }

    ToolSelectionModal .tool-checkbox {
        width: auto;
        margin-right: 1;
    }

    ToolSelectionModal .tool-name {
        color: $success;
        text-style: bold;
    }

    ToolSelectionModal .tool-description {
        color: $text-muted;
        margin-left: 4;
    }

    ToolSelectionModal #tool-selection-warning {
        color: $accent;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: 1;
        padding-top: 1;
    }
    """

    BINDINGS = [
        Binding("enter", "confirm", "Confirm", priority=True),
        Binding("space", "toggle_current", "Toggle", show=False),
        Binding("1", "toggle_fritap", "FriTap", show=False),
        Binding("2", "toggle_dexray", "Dexray", show=False),
        Binding("3", "toggle_bypass", "Bypass", show=False),
    ]

    AUTO_FOCUS = ".modal-container"

    def __init__(
        self,
        multi_select: bool = True,
        title: str = "Select Tools to Load",
        show_trigdroid_note: bool = True,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the tool selection modal.

        Args:
            multi_select: If True, allow multiple selections (checkboxes).
                         If False, single selection only (radio-like).
            title: Modal title
            show_trigdroid_note: Show note about TrigDroid opening bypass modal
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.title_text = title
        self.multi_select = multi_select
        self.show_trigdroid_note = show_trigdroid_note

        self.selections: dict[str, bool] = {
            "fritap": False,
            "dexray": False,
            "trigdroid_bypass": False,
        }

        self._tool_to_option_id: dict[str, str] = {
            "fritap": "option-fritap",
            "dexray": "option-dexray",
            "trigdroid_bypass": "option-bypass",
        }
        self._option_id_to_tool: dict[str, str] = {
            v: k for k, v in self._tool_to_option_id.items()
        }

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label(self.title_text, classes="modal-title")

            mode_text = (
                "Multi-select enabled" if self.multi_select else "Single selection"
            )
            yield Label(f"[dim]{mode_text}[/dim]", id="tool-selection-subtitle")

            # FriTap option
            yield Static(
                "[1] FriTap SSL/TLS Interception\n"
                "[dim]    Capture decrypted HTTPS traffic[/dim]",
                classes="tool-option",
                id="option-fritap",
            )

            # Dexray-Intercept option
            yield Static(
                "[2] Dexray-Intercept Runtime Monitor\n"
                "[dim]    Monitor crypto, network, file operations[/dim]",
                classes="tool-option",
                id="option-dexray",
            )

            # TrigDroid Bypass option
            bypass_text = "[3] TrigDroid Bypass Hooks\n"
            bypass_text += (
                "[dim]    SSL unpinning, root/frida/emulator/debug bypass[/dim]"
            )
            if self.show_trigdroid_note:
                bypass_text += "\n[dim]    -> Opens bypass configuration modal[/dim]"
            yield Static(bypass_text, classes="tool-option", id="option-bypass")

            # Warning if no tools selected
            yield Label("", id="tool-selection-warning")

            hint_text = "[dim]1/2/3=Toggle  Enter=Continue  Esc=Back[/dim]"
            if not self.multi_select:
                hint_text = "[dim]1/2/3=Select  Enter=Continue  Esc=Back[/dim]"
            yield KeyHintFooter(hints={"default": hint_text})

    def on_mount(self) -> None:
        """Set focus when modal is mounted and update display."""
        super().on_mount()
        self._update_display()

    def _update_display(self) -> None:
        """Update the visual state of tool options."""
        for tool_id, is_selected in self.selections.items():
            option_id = self._tool_to_option_id.get(tool_id)
            if not option_id:
                continue
            try:
                self.query_one(f"#{option_id}").set_class(is_selected, "selected")
            except NoMatches:
                pass

        # Update warning
        warning = self.query_one("#tool-selection-warning", Label)
        if not any(self.selections.values()):
            warning.update(
                "[dim]No tools selected - press Enter to continue anyway[/dim]"
            )
        else:
            selected = [k for k, v in self.selections.items() if v]
            warning.update(f"[dim]Selected: {', '.join(selected)}[/dim]")

    def _toggle_tool(self, tool: str) -> None:
        """Toggle a tool selection.

        Args:
            tool: Tool key to toggle
        """
        if self.multi_select:
            # Multi-select: toggle the tool
            self.selections[tool] = not self.selections[tool]
        else:
            # Single-select: select only this tool
            for key in self.selections:
                self.selections[key] = key == tool

        self._update_display()

    def action_toggle_fritap(self) -> None:
        """Toggle FriTap selection."""
        self._toggle_tool("fritap")

    def action_toggle_dexray(self) -> None:
        """Toggle Dexray selection."""
        self._toggle_tool("dexray")

    def action_toggle_bypass(self) -> None:
        """Toggle TrigDroid bypass selection."""
        self._toggle_tool("trigdroid_bypass")

    def action_confirm(self) -> None:
        """Confirm selection and close modal."""
        self._dismiss_with_refresh(self.selections.copy())

    def on_static_click(self, event) -> None:
        """Handle click on tool options."""
        widget_id = getattr(event.widget, "id", None)
        tool = self._option_id_to_tool.get(widget_id)
        if tool:
            self._toggle_tool(tool)
