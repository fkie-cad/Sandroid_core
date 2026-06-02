"""Command palette screen for Sandroid TUI."""

from collections.abc import Callable

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from sandroid.core.enums import ViewMode
from sandroid.core.menu_controller import Action, MenuController


def _format_key_display(key: str) -> str:
    """Format an action key for display.

    Args:
        key: Raw key string from Action

    Returns:
        Formatted display string
    """
    if len(key) > 1:
        return key.upper()
    if key == " ":
        return "SPACE"
    return key


class CommandPalette(ModalScreen):
    """Command palette for searching and executing actions.

    Features:
    - Fuzzy search through all available actions
    - Keyboard navigation (j/k or arrow keys)
    - Enter to execute selected action
    - Shows action requirements and availability
    """

    DEFAULT_CSS = """
    CommandPalette {
        align: center middle;
        background: rgba(5, 8, 17, 0.85);
    }

    #palette-container {
        width: 75;
        height: auto;
        max-height: 30;
        background: #0d1117;
        border: solid #2f81f7;
        padding: 1 2;
    }

    #palette-input {
        width: 100%;
        background: #161b22;
        border: solid #30363d;
        color: #e5e9f0;
        padding: 0 1;
        margin-bottom: 1;
    }

    #palette-input:focus {
        border: solid #2f81f7;
    }

    #palette-results {
        height: auto;
        max-height: 20;
        background: #0d1117;
        padding: 0 1;
    }

    #palette-hint {
        text-align: center;
        color: #8b949e;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("down", "select_next", "Next", show=False),
        Binding("up", "select_previous", "Previous", show=False),
        Binding("j", "select_next", "Next", show=False),
        Binding("k", "select_previous", "Previous", show=False),
        Binding("enter", "execute_selected", "Execute", show=False),
    ]

    class ActionSelected(Message):
        """Message sent when an action is selected."""

        def __init__(self, action_name: str):
            self.action_name = action_name
            super().__init__()

    def __init__(
        self,
        current_view: str | ViewMode = ViewMode.FORENSIC,
        on_action: Callable[[str], None] = None,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the command palette.

        Args:
            current_view: Current view for filtering actions
            on_action: Callback when action is selected
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        # Ensure current_view is a string for MenuController compatibility
        self.current_view = (
            current_view.value if isinstance(current_view, ViewMode) else current_view
        )
        self.on_action = on_action
        self._controller = MenuController.get()
        self._filtered_actions: list[Action] = []
        self._selected_index = 0

    def compose(self) -> ComposeResult:
        """Create the command palette layout."""
        with Vertical(id="palette-container"):
            yield Input(
                placeholder="Search commands...",
                id="palette-input",
            )
            yield Static("", id="palette-results")
            yield Static(
                "[dim]Enter=Execute, Esc=Close, ↑/↓=Navigate[/dim]", id="palette-hint"
            )

    def on_mount(self) -> None:
        """Called when the screen is mounted."""
        # Focus the input
        self.query_one("#palette-input", Input).focus()

        # Show all actions initially
        self._update_results("")

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle input changes."""
        if event.input.id == "palette-input":
            self._update_results(event.value)

    def _update_results(self, query: str) -> None:
        """Update the results based on search query.

        Args:
            query: Search query string
        """
        # Get all actions (flat catalog; view modes removed). Hide the retired
        # switch_view action and the per-slot load/save actions (those are
        # hotkey- and Snapshots-tab-driven; dispatching them by name here would
        # bypass the slot handling). TODO(modes-as-presets): re-surface presets.
        all_actions = [
            a
            for a in self._controller.get_all_actions()
            if a.name != "switch_view"
            and not a.name.startswith(("load_slot_", "save_slot_"))
        ]

        # Filter by query (fuzzy match on name, display_name, description)
        query_lower = query.lower().strip()
        if query_lower:
            self._filtered_actions = [
                a
                for a in all_actions
                if (
                    query_lower in a.name.lower()
                    or query_lower in a.display_name.lower()
                    or query_lower in a.description.lower()
                    or query_lower in a.key.lower()
                )
            ]
        else:
            self._filtered_actions = all_actions

        # Reset selection
        self._selected_index = 0 if self._filtered_actions else -1

        # Update display
        self._render_results()

    def _render_results(self) -> None:
        """Render the filtered results."""
        if not self._filtered_actions:
            content = "[dim]No matching commands[/]"
        else:
            lines = []
            for i, action in enumerate(self._filtered_actions[:15]):
                key_display = _format_key_display(action.key)

                # Check availability (view-agnostic; flat catalog)
                valid, _ = self._controller.validate_action(action.name)

                # Build line - single brackets with magenta for keys
                if i == self._selected_index:
                    # Selected item
                    if valid:
                        line = (
                            f"[reverse] \\[{key_display:>5}] {action.display_name} [/]"
                        )
                    else:
                        line = f"[reverse dim] \\[{key_display:>5}] {action.display_name} [/]"
                # Normal item
                elif valid:
                    line = (
                        f"  [bold #ff00ff]\\[{key_display:>5}][/] {action.display_name}"
                    )
                else:
                    line = f"  [dim]\\[{key_display:>5}] {action.display_name}[/]"

                # Add description if space allows
                if action.description:
                    desc = (
                        action.description[:40] + "..."
                        if len(action.description) > 40
                        else action.description
                    )
                    line += f" [dim]- {desc}[/]"

                lines.append(line)

            content = "\n".join(lines)

            # Add count
            if len(self._filtered_actions) > 15:
                content += f"\n[dim]...and {len(self._filtered_actions) - 15} more[/]"

        results = self.query_one("#palette-results", Static)
        results.update(content)

    def action_select_next(self) -> None:
        """Select the next item in the list."""
        if self._filtered_actions:
            max_visible = min(15, len(self._filtered_actions))
            self._selected_index = (self._selected_index + 1) % max_visible
            self._render_results()

    def action_select_previous(self) -> None:
        """Select the previous item in the list."""
        if self._filtered_actions:
            max_visible = min(15, len(self._filtered_actions))
            self._selected_index = (self._selected_index - 1) % max_visible
            self._render_results()

    def action_execute_selected(self) -> None:
        """Execute the selected action."""
        if 0 <= self._selected_index < len(self._filtered_actions):
            action = self._filtered_actions[self._selected_index]

            # Check if action is available (view-agnostic; flat catalog)
            valid, error_msg = self._controller.validate_action(action.name)

            if not valid:
                # Show error but don't dismiss
                results = self.query_one("#palette-results", Static)
                results.update(
                    f"[yellow]! {error_msg}[/yellow]\n\n" + results.renderable
                )
                return

            # Execute action via callback or message
            if self.on_action:
                self.on_action(action.name)

            self.post_message(self.ActionSelected(action.name))
            self.dismiss()

    def action_dismiss(self) -> None:
        """Dismiss the command palette and refresh display."""
        # Schedule a refresh after dismissal to fix any display issues
        self.app.call_later(self._refresh_app)
        self.dismiss()

    def _refresh_app(self) -> None:
        """Refresh the app display after modal closes."""
        try:
            self.app.refresh(layout=True)
        except Exception:
            pass
