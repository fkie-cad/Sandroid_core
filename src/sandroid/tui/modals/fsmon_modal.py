"""FSMon configuration and monitoring modal for filesystem observation."""

from collections import deque

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, Input, Label, RadioButton, RadioSet, RichLog, Static

from sandroid.services import get_spotlight_service
from sandroid.tui.controllers.fsmon_controller import FSMonConfig, colorize_fsmon_line
from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


class FSMonConfigModal(ForensicModal[FSMonConfig]):
    """Modal for configuring FSMon filesystem monitoring.

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
    FSMonConfigModal .modal-container {
        width: 75;
        max-width: 90%;
        max-height: 80%;
    }

    FSMonConfigModal #fsmon-description {
        color: $foreground;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    FSMonConfigModal #spotlight-info {
        color: $text-muted;
        background: $panel;
        border: solid $foreground-muted;
        padding: 1;
        margin-bottom: 1;
        height: auto;
    }

    FSMonConfigModal #spotlight-info.has-app {
        border: solid $success;
    }

    FSMonConfigModal #mode-section {
        margin-bottom: 1;
    }

    FSMonConfigModal #mode-label {
        color: $foreground;
        text-style: bold;
        padding-bottom: 1;
    }

    FSMonConfigModal RadioSet {
        width: 100%;
        height: auto;
        background: transparent;
        border: solid transparent;
        padding: 0;
    }

    FSMonConfigModal RadioSet:focus {
        border: solid $primary;
    }

    FSMonConfigModal RadioSet:focus-within {
        border: solid $primary;
    }

    FSMonConfigModal RadioButton {
        background: transparent;
        padding: 0 1;
    }

    FSMonConfigModal RadioButton.-on {
        text-style: bold;
        color: $primary;
    }

    FSMonConfigModal #mode-info {
        padding: 0 1;
        height: auto;
    }

    FSMonConfigModal #path-section {
        margin-top: 1;
    }

    FSMonConfigModal #path-label {
        color: $text-muted;
        height: 1;
    }

    FSMonConfigModal #path-input {
        width: 100%;
        background: $panel;
        border: solid $foreground-muted;
    }

    FSMonConfigModal #path-input:focus {
        border: solid $success;
    }

    FSMonConfigModal #path-input.error {
        border: solid $error;
    }

    FSMonConfigModal #path-hint {
        color: $text-muted;
        height: auto;
        padding-top: 1;
    }

    FSMonConfigModal #error-label {
        color: $error;
        height: auto;
        padding-top: 1;
    }

    FSMonConfigModal .hidden {
        display: none;
    }

    FSMonConfigModal .button-row {
        margin-top: 1;
        height: 3;
    }

    FSMonConfigModal #btn-start {
        background: $success;
        color: #ffffff;
    }

    FSMonConfigModal #btn-start:hover {
        background: $success-darken-1;
    }

    FSMonConfigModal #btn-start:focus {
        background: $success;
        text-style: bold;
    }

    FSMonConfigModal #btn-start:disabled {
        background: $panel;
        color: $foreground-disabled;
    }

    FSMonConfigModal #btn-cancel {
        background: $panel;
        color: $foreground;
    }

    FSMonConfigModal #btn-cancel:hover {
        background: $panel-lighten-1;
    }
    """

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the FSMon configuration modal."""
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
            yield Label("Filesystem Monitor (fsmon)", classes="modal-title")
            yield Label(
                "Monitor filesystem changes on the Android device in real-time.",
                id="fsmon-description",
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
        self._dismiss_with_refresh(FSMonConfig(cancelled=True))

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

            config = FSMonConfig(
                cancelled=False,
                mode=mode,
                target_path=path,
                target_pid=self._spotlight_pid if mode == "pid" else None,
                app_name=self._get_app_name(),
            )

            self._dismiss_with_refresh(config)

        except Exception as e:
            self._show_error(f"Error: {e}")


class FSMonRunningModal(ForensicModal[str]):
    """Modal shown while FSMon is running.

    Uses RichLog for incremental line rendering instead of Static.update()
    which rewrites all content and triggers full layout passes. RichLog only
    renders new lines and manages its own scrollbar, eliminating the
    compositor/scrollbar conflicts that caused right-edge artifacts.

    Returns:
        "stop" if user wants to stop fsmon
        "minimize" if user wants to minimize the modal
    """

    BINDINGS = [
        Binding("ctrl+c", "stop", "Stop", priority=True, show=False),
        Binding("q", "stop", "Stop", priority=True, show=False),
        Binding("m", "minimize", "Minimize", priority=True, show=False),
        Binding("o", "minimize", "Minimize", priority=True, show=False),
    ]

    _MAX_LINE_WIDTH = 115

    DEFAULT_CSS = """
    FSMonRunningModal .modal-container {
        width: 90%;
        height: 85%;
        max-width: 90%;
        max-height: 45;
    }

    FSMonRunningModal #running-info {
        color: $text-muted;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    FSMonRunningModal #output-log {
        background: $panel;
        border: solid $foreground-muted;
        height: 1fr;
        width: 1fr;
        overflow-x: hidden;
        overflow-y: scroll;
        scrollbar-size-vertical: 1;
        scrollbar-size-horizontal: 0;
        scrollbar-background: $panel;
        scrollbar-color: $primary;
        scrollbar-color-hover: $primary-lighten-1;
        scrollbar-color-active: $primary-lighten-2;
        padding: 0 0 0 1;
    }

    FSMonRunningModal #stop-button-container {
        align: center middle;
        width: 100%;
        height: 3;
        margin-top: 1;
    }

    FSMonRunningModal #btn-stop {
        background: $error;
        color: #ffffff;
        min-width: 20;
        border: none;
    }

    FSMonRunningModal #btn-stop:hover {
        background: $error-darken-1;
    }

    FSMonRunningModal #btn-stop:focus {
        background: $error;
        text-style: bold;
    }

    FSMonRunningModal #btn-minimize {
        background: $panel;
        color: $foreground;
        min-width: 14;
        border: none;
        margin-left: 2;
    }

    FSMonRunningModal #btn-minimize:hover {
        background: $panel-lighten-1;
    }

    FSMonRunningModal #btn-minimize:focus {
        background: $panel;
        text-style: bold;
    }
    """

    AUTO_FOCUS = "#btn-stop"

    def __init__(
        self,
        config: FSMonConfig,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the FSMon running modal.

        Args:
            config: FSMon configuration
        """
        super().__init__(name=name, id=id, classes=classes)
        self.config = config
        self._max_lines = self._get_config_max_lines()
        self._pending_buffer: list[str] | None = None
        self._pending_writes: deque[str] = deque(maxlen=self._max_lines)

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("FSMon Running", classes="modal-title")

            # Info about what's being monitored
            if self.config.mode == "pid":
                info = f"Monitoring PID {self.config.target_pid} ({self.config.app_name}) at {self.config.target_path}"
            else:
                info = f"Monitoring path: {self.config.target_path}"
            yield Label(info, id="running-info")

            # RichLog handles scrolling, scrollbar, and incremental rendering
            yield RichLog(
                id="output-log",
                markup=True,
                max_lines=self._max_lines,
                auto_scroll=True,
                wrap=False,
            )

            with Horizontal(id="stop-button-container"):
                yield Button("Stop Monitoring", id="btn-stop")
                yield Button("Minimize", id="btn-minimize", classes="-secondary")

            yield KeyHintFooter(
                hints={
                    "default": "[dim]Ctrl+C/Q=Stop  O/Esc=Minimize[/dim]",
                    "button": "[dim]Enter=Press  O=Minimize  Esc=Minimize[/dim]",
                }
            )

    def on_mount(self) -> None:
        """Apply pending buffer and start flush timer."""
        if self._pending_buffer is not None:
            self.load_buffer(self._pending_buffer)
            self._pending_buffer = None
        else:
            try:
                log = self.query_one("#output-log", RichLog)
                log.write("[dim]Waiting for filesystem events...[/dim]")
            except NoMatches:
                pass

        flush_rate = max(self._get_flush_interval(), 0.05)
        self.set_interval(flush_rate, self._flush_output)

    def _get_flush_interval(self) -> float:
        """Read fsmon_buffer_interval from config for UI flush rate."""
        try:
            from sandroid.config.loader import ConfigLoader

            loader = ConfigLoader()
            config = loader.load()
            return config.tui.fsmon_buffer_interval
        except Exception:
            return 0.1

    def _get_config_max_lines(self) -> int:
        """Read fsmon_max_lines from config."""
        try:
            from sandroid.config.loader import ConfigLoader

            loader = ConfigLoader()
            config = loader.load()
            return config.tui.fsmon_max_lines
        except Exception:
            return 500

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-stop":
            self.action_stop()
        elif event.button.id == "btn-minimize":
            self.action_minimize()

    def action_stop(self) -> None:
        """Stop monitoring and close modal."""
        self._dismiss_with_refresh("stop")

    def action_minimize(self) -> None:
        """Minimize modal (keep fsmon running)."""
        self._dismiss_with_refresh("minimize")

    def action_cancel(self) -> None:
        """Override Esc to minimize instead of stop."""
        self.action_minimize()

    def load_buffer(self, lines: list[str]) -> None:
        """Load buffered output lines (for restoring minimized observer).

        If the widget tree is not yet mounted, stores to _pending_buffer
        so on_mount() can apply it once ready.

        Args:
            lines: List of raw output lines to replay
        """
        truncated = lines[-self._max_lines :]
        try:
            log = self.query_one("#output-log", RichLog)
            log.clear()
            with self.app.batch_update():
                for line in truncated:
                    log.write(self._colorize_line(line))
            log.refresh(layout=True)
            self._pending_writes.clear()
        except NoMatches:
            self._pending_buffer = truncated

    def add_output(self, line: str) -> None:
        """Add a line to the output buffer.

        Only touches data structures; rendering happens via the interval timer.

        Args:
            line: Output line to add
        """
        self._pending_writes.append(line)

    def _flush_output(self) -> None:
        """Write only NEW lines to RichLog since last flush.

        Unlike Static.update() which rewrites all content and triggers
        refresh(layout=True), RichLog.write() only renders the new line
        and updates virtual_size — no full layout pass, no scrollbar
        space recalculation, no compositor conflicts.

        Caps at 100 lines per flush to prevent large render operations
        from stalling the UI. Remaining lines carry over to the next flush.
        """
        if not self._pending_writes:
            return
        try:
            log = self.query_one("#output-log", RichLog)
            # Write at most 100 lines per flush to prevent render stalls
            count = min(len(self._pending_writes), 100)
            for _ in range(count):
                line = self._pending_writes.popleft()
                log.write(self._colorize_line(line))
        except Exception:
            pass

    def _colorize_line(self, line: str) -> str:
        """Apply color markup based on filesystem event type.

        Delegates to the shared ``colorize_fsmon_line`` helper so that
        escape + colorize logic is not duplicated between the modal
        and the controller's activity-log path.
        """
        return colorize_fsmon_line(line, max_width=self._MAX_LINE_WIDTH)
