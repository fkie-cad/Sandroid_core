"""Spawn Mode Selection Modal for Frida tool loading."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Label, Static

from .base import FridaModal, KeyHintFooter

if TYPE_CHECKING:
    from textual.app import ComposeResult


class SpawnModeModal(FridaModal[str | None]):
    """Modal for selecting Frida spawn/attach mode.

    Three modes are available:
    - Multi-tool Mode: Spawn app paused, load multiple tools, then resume
    - Single Tool Mode: Spawn with one primary tool, auto-resume after hooks
    - Late Attach Mode: Spawn without pause, attach tools later

    Returns the selected mode as a string: 'multi_tool', 'single_tool', or 'late_attach'
    Returns None if cancelled.
    """

    DEFAULT_CSS = """
    SpawnModeModal .modal-container {
        width: 70;
        max-width: 90%;
    }

    SpawnModeModal #spawn-mode-target {
        color: $text-muted;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: 1;
        margin-bottom: 1;
    }

    SpawnModeModal .mode-option {
        width: 100%;
        height: auto;
        padding: 1 2;
        margin-bottom: 1;
        background: $panel;
        border: solid $foreground-muted;
    }

    SpawnModeModal .mode-option:hover {
        background: $panel-lighten-1;
        border: solid $success;
    }

    SpawnModeModal .mode-option.selected {
        background: $panel-lighten-1;
        border: solid $success;
    }

    SpawnModeModal .mode-key {
        color: $accent;
        text-style: bold;
    }

    SpawnModeModal .mode-title {
        color: $success;
        text-style: bold;
    }

    SpawnModeModal .mode-description {
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding("a", "select_multi", "Multi-tool", show=False),
        Binding("b", "select_single", "Single tool", show=False),
        Binding("c", "select_late", "Late attach", show=False),
        Binding("1", "select_multi", "Multi-tool", show=False),
        Binding("2", "select_single", "Single tool", show=False),
        Binding("3", "select_late", "Late attach", show=False),
    ]

    AUTO_FOCUS = ".modal-container"

    def __init__(
        self,
        package_name: str = "com.example.app",
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the spawn mode modal.

        Args:
            package_name: Target package name to display
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.package_name = package_name

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Spawn Mode Selection", classes="modal-title")
            yield Label(f"Target: {self.package_name}", id="spawn-mode-target")

            # Option A: Multi-tool Mode
            yield Static(
                "[bold class=mode-key][A][/] [bold class=mode-title]Multi-tool Mode[/] (Spawn + Pause)\n"
                "[dim]App spawns but stays paused. Add multiple tools[/]\n"
                "[dim](FriTap, Dexray, TrigDroid bypass) before resume.[/]",
                classes="mode-option",
                id="option-multi",
            )

            # Option B: Single Tool Mode
            yield Static(
                "[bold class=mode-key][B][/] [bold class=mode-title]Single Tool Mode[/] (Spawn + Tool)\n"
                "[dim]Spawn directly with one primary tool. Other tools[/]\n"
                "[dim]can be added afterward.[/]",
                classes="mode-option",
                id="option-single",
            )

            # Option C: Late Attach Mode
            yield Static(
                "[bold class=mode-key][C][/] [bold class=mode-title]Late Attach Mode[/] (Spawn without Pause)\n"
                "[dim]App runs immediately. Attach tools later.[/]\n"
                "[dim](May miss startup behavior)[/]",
                classes="mode-option",
                id="option-late",
            )

            yield KeyHintFooter(
                hints={
                    "default": "[dim]A/B/C or 1/2/3=Select  Esc=Cancel[/dim]",
                }
            )

    _OPTION_TO_MODE = {
        "option-multi": "multi_tool",
        "option-single": "single_tool",
        "option-late": "late_attach",
    }

    def action_select_multi(self) -> None:
        """Select multi-tool mode."""
        self._dismiss_with_refresh("multi_tool")

    def action_select_single(self) -> None:
        """Select single tool mode."""
        self._dismiss_with_refresh("single_tool")

    def action_select_late(self) -> None:
        """Select late attach mode."""
        self._dismiss_with_refresh("late_attach")

    def on_static_click(self, event) -> None:
        """Handle click on mode options."""
        widget_id = getattr(event.widget, "id", None)
        mode = self._OPTION_TO_MODE.get(widget_id)
        if mode:
            self._dismiss_with_refresh(mode)
