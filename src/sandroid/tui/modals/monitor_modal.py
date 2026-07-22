"""Monitor configuration modal for filesystem observation."""

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, RadioButton, RadioSet, Static

from sandroid.services import get_spotlight_service
from sandroid.tui.controllers.monitor_controller import MonitorConfig
from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


class MonitorConfigModal(ForensicModal[MonitorConfig]):
    """Modal for configuring Monitor filesystem monitoring.

    Features:
    - Choose between PID-based or Path-based monitoring
    - Shows current spotlight app info
    - Auto-fills path from spotlight app data directory
    - Validates inputs before starting
    """

    BINDINGS = [
        # Note: Enter binding is NOT priority so RadioSet can use it for toggle
        # When RadioSet is focused, Enter toggles; otherwise Enter starts
        Binding("enter", "start_or_toggle", "Start Monitoring", priority=False),
    ]

    DEFAULT_CSS = """
    MonitorConfigModal .modal-container {
        width: 75;
        max-width: 90%;
        max-height: 80%;
    }

    MonitorConfigModal #monitor-description {
        color: $foreground;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    MonitorConfigModal #spotlight-info {
        color: $text-muted;
        background: $panel;
        border: solid $foreground-muted;
        padding: 1;
        margin-bottom: 1;
        height: auto;
    }

    MonitorConfigModal #spotlight-info.has-app {
        border: solid $success;
    }

    MonitorConfigModal #mode-section {
        margin-bottom: 1;
    }

    MonitorConfigModal #mode-label {
        color: $foreground;
        text-style: bold;
        padding-bottom: 1;
    }

    MonitorConfigModal RadioSet {
        width: 100%;
        height: auto;
        background: transparent;
        border: solid transparent;
        padding: 0;
    }

    MonitorConfigModal RadioSet:focus {
        border: solid $primary;
    }

    MonitorConfigModal RadioSet:focus-within {
        border: solid $primary;
    }

    MonitorConfigModal RadioButton {
        background: transparent;
        padding: 0 1;
    }

    MonitorConfigModal RadioButton.-on {
        text-style: bold;
        color: $primary;
    }

    MonitorConfigModal #mode-info {
        padding: 0 1;
        height: auto;
    }

    MonitorConfigModal #path-section {
        margin-top: 1;
    }

    MonitorConfigModal #path-label {
        color: $text-muted;
        height: 1;
    }

    MonitorConfigModal #path-input {
        width: 100%;
        background: $panel;
        border: solid $foreground-muted;
    }

    MonitorConfigModal #path-input:focus {
        border: solid $success;
    }

    MonitorConfigModal #path-input.error {
        border: solid $error;
    }

    MonitorConfigModal #path-hint {
        color: $text-muted;
        height: auto;
        padding-top: 1;
    }

    MonitorConfigModal #error-label {
        color: $error;
        height: auto;
        padding-top: 1;
    }

    MonitorConfigModal .hidden {
        display: none;
    }

    MonitorConfigModal .button-row {
        margin-top: 1;
        height: 3;
    }

    MonitorConfigModal #btn-start {
        background: $success;
        color: #ffffff;
    }

    MonitorConfigModal #btn-start:hover {
        background: $success-darken-1;
    }

    MonitorConfigModal #btn-start:focus {
        background: $success;
        text-style: bold;
    }

    MonitorConfigModal #btn-start:disabled {
        background: $panel;
        color: $foreground-disabled;
    }

    MonitorConfigModal #btn-cancel {
        background: $panel;
        color: $foreground;
    }

    MonitorConfigModal #btn-cancel:hover {
        background: $panel-lighten-1;
    }
    """

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the Monitor configuration modal."""
        super().__init__(name=name, id=id, classes=classes)

        # Get spotlight info
        spotlight = get_spotlight_service()
        self._spotlight_app = spotlight.get_app_tuple()
        self._spotlight_pid = spotlight.get_pid()
        self._spawn_mode = spotlight.is_spawn_mode()
        self._spawn_app = spotlight.get_spawn_package()

        # Determine default path
        self._default_path = self._get_default_path()

    def _get_package_name(self) -> str:
        """Get package name from spawn app or spotlight app."""
        if self._spawn_mode and self._spawn_app:
            return self._spawn_app
        if self._spotlight_app:
            return (
                self._spotlight_app[0]
                if isinstance(self._spotlight_app, tuple)
                else str(self._spotlight_app)
            )
        return ""

    def _get_default_path(self) -> str:
        """Get default monitoring path based on spotlight app."""
        pkg = self._get_package_name()
        return f"/data/data/{pkg}" if pkg else "/data/"

    def _get_app_name(self) -> str:
        """Get display name for spotlight app."""
        return self._get_package_name()

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Filesystem Monitor", classes="modal-title")
            yield Label(
                "Monitor filesystem changes on the Android device in real-time.",
                id="monitor-description",
            )

            # Spotlight app info
            app_name = self._get_app_name()
            if app_name:
                mode_str = "SPAWN" if self._spawn_mode else "ATTACH"
                pid_str = (
                    f" (PID: {self._spotlight_pid})" if self._spotlight_pid else ""
                )
                info_text = f"[bold]Spotlight App:[/bold] {app_name}{pid_str}\n[bold]Mode:[/bold] {mode_str}"
                spotlight_info = Static(info_text, id="spotlight-info")
                spotlight_info.add_class("has-app")
                yield spotlight_info
            else:
                yield Static(
                    "[dim]No spotlight app selected. You can still monitor by path.[/dim]",
                    id="spotlight-info",
                )

            # Mode selection
            with Vertical(id="mode-section"):
                yield Label("Monitoring Mode:", id="mode-label")
                # Only show RadioSet if we have both options available
                if self._spotlight_pid:
                    with RadioSet(id="mode-select"):
                        yield RadioButton(
                            f"Monitor by PID ({self._spotlight_pid})",
                            id="mode-pid",
                            value=True,
                        )
                        yield RadioButton(
                            "Monitor by Path",
                            id="mode-path",
                        )
                    yield Label(
                        "[dim]PID mode falls back to path-mode on devices without fanotify support.[/dim]",
                        id="pid-mode-hint",
                    )
                else:
                    # Only path mode available - show as info, not a radio set
                    yield Static(
                        "[dim]●[/dim] Monitor by Path [dim](only option - no app running)[/dim]",
                        id="mode-info",
                    )

            # Path input
            with Vertical(id="path-section"):
                yield Label("Target Path:", id="path-label")
                yield Input(
                    value=self._default_path,
                    placeholder="/data/data/com.example.app or /sdcard/",
                    id="path-input",
                )
                yield Label(
                    "[dim]Path to monitor (directory on device). In PID mode, filters events to this path.[/dim]",
                    id="path-hint",
                )
                yield Label("", id="error-label", classes="hidden")

            with Horizontal(classes="button-row"):
                yield Button("Start Monitoring", id="btn-start", classes="-primary")
                yield Button("Cancel", id="btn-cancel", classes="-secondary")

            yield KeyHintFooter(
                hints={
                    "default": "[dim]Enter=Start  Esc=Cancel  Tab=Navigate[/dim]",
                    "input": "[dim]Enter=Start  Tab=Next  Esc=Cancel[/dim]",
                    "radioset": "[dim]↑↓=Select Mode  Space=Toggle  Tab=Next  Esc=Cancel[/dim]",
                }
            )

    def on_mount(self) -> None:
        """Focus appropriate widget on mount."""
        super().on_mount()
        try:
            # Focus the RadioSet if it exists (when PID is available)
            radio_set = self.query_one("#mode-select", RadioSet)
            radio_set.focus()
        except Exception:
            # No RadioSet (path-only mode), focus the path input instead
            try:
                path_input = self.query_one("#path-input", Input)
                path_input.focus()
            except Exception:
                pass

    def on_key(self, event: events.Key) -> None:
        """Handle key events, forwarding navigation to RadioSet when focused.

        When RadioSet is focused, we directly call its action methods for
        navigation and toggle since Textual's binding system may not
        properly route events through modal inheritance.
        """
        # Only handle RadioSet keys if PID is available (RadioSet exists)
        if self._spotlight_pid:
            key = event.key.lower() if event.key else ""
            focused = self.app.focused

            # Check if RadioSet or RadioButton is focused
            is_radio_focused = isinstance(focused, (RadioSet, RadioButton))

            if is_radio_focused:
                try:
                    radio_set = self.query_one("#mode-select", RadioSet)

                    radio_actions = {
                        "up": radio_set.action_previous_button,
                        "left": radio_set.action_previous_button,
                        "down": radio_set.action_next_button,
                        "right": radio_set.action_next_button,
                        "space": radio_set.action_toggle_button,
                        "enter": radio_set.action_toggle_button,
                        "return": radio_set.action_toggle_button,
                    }
                    action = radio_actions.get(key)
                    if action:
                        action()
                        event.stop()
                        event.prevent_default()
                        return
                except Exception:
                    pass

        # For non-RadioSet focus or no RadioSet, call parent handler
        super().on_key(event)

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Handle mode selection change."""
        # Update path hint based on mode
        try:
            path_hint = self.query_one("#path-hint", Label)
            if event.pressed.id == "mode-pid":
                path_hint.update(
                    "[dim]In PID mode, this path filters monitored events.[/dim]"
                )
            else:
                path_hint.update("[dim]Path to monitor (directory on device).[/dim]")
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-cancel":
            self._cancel()
        elif event.button.id == "btn-start":
            self._start()

    def action_start(self) -> None:
        """Start monitoring."""
        self._start()

    def action_start_or_toggle(self) -> None:
        """Handle Enter key - toggle RadioSet if focused, otherwise start.

        This allows Enter to work for both RadioSet selection and form submission.
        """
        focused = self.app.focused

        # Check if RadioSet or RadioButton is focused
        is_radio_focused = isinstance(focused, (RadioSet, RadioButton))

        if not is_radio_focused and focused is not None:
            try:
                for ancestor in focused.ancestors:
                    if isinstance(ancestor, RadioSet):
                        is_radio_focused = True
                        break
            except Exception:
                pass

        if is_radio_focused:
            # Let RadioSet handle the toggle via its own action
            try:
                radio_set = self.query_one("#mode-select", RadioSet)
                radio_set.action_toggle_button()
            except Exception:
                pass
        else:
            # Not on RadioSet, start monitoring
            self._start()

    def _show_error(self, message: str) -> None:
        """Show error message."""
        try:
            error_label = self.query_one("#error-label", Label)
            error_label.update(message)
            error_label.remove_class("hidden")

            path_input = self.query_one("#path-input", Input)
            path_input.add_class("error")
        except Exception:
            pass

    def _hide_error(self) -> None:
        """Hide error message."""
        try:
            error_label = self.query_one("#error-label", Label)
            error_label.add_class("hidden")

            path_input = self.query_one("#path-input", Input)
            path_input.remove_class("error")
        except Exception:
            pass

    def _get_selected_mode(self) -> str:
        """Get the selected monitoring mode."""
        # If no PID available, only path mode is possible
        if not self._spotlight_pid:
            return "path"

        try:
            radio_set = self.query_one("#mode-select", RadioSet)
            if radio_set.pressed_button and radio_set.pressed_button.id == "mode-pid":
                return "pid"
        except Exception:
            pass
        return "path"

    def _validate(self) -> tuple[bool, str]:
        """Validate inputs.

        Returns:
            Tuple of (valid, error_message)
        """
        try:
            path_input = self.query_one("#path-input", Input)
            path = path_input.value.strip()

            if not path:
                return False, "Please enter a path to monitor"

            if not path.startswith("/"):
                return False, "Path must be an absolute path (start with /)"

            return True, ""
        except Exception as e:
            return False, f"Validation error: {e}"

    def _cancel(self) -> None:
        """Cancel and dismiss."""
        self._dismiss_with_refresh(MonitorConfig(cancelled=True))

    def _start(self) -> None:
        """Validate and start monitoring."""
        valid, error = self._validate()
        if not valid:
            self._show_error(error)
            return

        self._hide_error()

        try:
            path_input = self.query_one("#path-input", Input)
            path = path_input.value.strip()

            mode = self._get_selected_mode()

            config = MonitorConfig(
                cancelled=False,
                mode=mode,
                target_path=path,
                target_pid=self._spotlight_pid if mode == "pid" else None,
                app_name=self._get_app_name(),
            )

            self._dismiss_with_refresh(config)

        except Exception as e:
            self._show_error(f"Error: {e}")
