"""Monitor configuration modal for filesystem observation."""

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, RadioButton, RadioSet, Static

from sandroid.config import get_config
from sandroid.core.kprobe_tracer import KprobeTracer
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

    MonitorConfigModal #path-rows {
        height: auto;
        width: 100%;
    }

    MonitorConfigModal .path-row {
        height: 3;
        width: 100%;
    }

    MonitorConfigModal .path-input {
        width: 1fr;
        background: $panel;
        border: solid $foreground-muted;
        margin: 0;
    }

    MonitorConfigModal .path-input:focus {
        border: solid $success;
    }

    MonitorConfigModal .path-input.error {
        border: solid $error;
    }

    MonitorConfigModal .path-remove {
        width: 5;
        min-width: 5;
        margin-left: 1;
        margin-top: 1;
        background: $panel;
        color: $error;
    }

    MonitorConfigModal .path-remove:hover {
        background: $panel-lighten-1;
    }

    MonitorConfigModal #path-add {
        width: auto;
        margin-top: 1;
        background: $panel;
        color: $foreground;
    }

    MonitorConfigModal #path-add:hover {
        background: $panel-lighten-1;
    }

    MonitorConfigModal #multipath-hint {
        color: $text-muted;
        height: auto;
        padding-top: 1;
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

        # Multi-path is kprobe-only: enabled only when the configured backend
        # is "kprobe" AND the current device's cached verdict is definitively
        # True. A None (never-probed / inconclusive) verdict counts as NOT
        # kprobe, so the modal safely stays single-path.
        self._effective_kprobe = self._compute_effective_kprobe()

    @staticmethod
    def _compute_effective_kprobe() -> bool:
        """Return whether multi-path (kprobe) input is available.

        Returns:
            ``True`` only when ``tui.monitor_backend == "kprobe"`` and the
            cached availability verdict for the current device is exactly
            ``True``. Any error, a non-kprobe backend, or a ``None``/``False``
            verdict returns ``False`` (single-path).
        """
        try:
            return (
                get_config().tui.monitor_backend == "kprobe"
                and KprobeTracer.cached_availability() is True
            )
        except Exception:
            return False

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
        """Get default monitoring path based on spotlight app.

        When a spotlight app is selected, its data directory
        (``/data/data/<pkg>``) is used. Otherwise the configured
        ``device_paths.default_monitor_path`` drives the prefill, falling back
        to ``"/data/"`` if the config is unavailable.
        """
        pkg = self._get_package_name()
        if pkg:
            return f"/data/data/{pkg}"
        try:
            return get_config().device_paths.default_monitor_path
        except Exception:
            return "/data/"

    def _get_app_name(self) -> str:
        """Get display name for spotlight app."""
        return self._get_package_name()

    def _make_path_row(self, value: str = "") -> Horizontal:
        """Build one path-input row (input + remove button).

        The remove button is hidden when multi-path is unavailable (fsmon /
        no kprobe), leaving a single fixed path row.

        Args:
            value: Initial value for the row's path input.

        Returns:
            A ``Horizontal`` row widget ready to mount.
        """
        path_input = Input(
            value=value,
            placeholder="/data/data/com.example.app or /sdcard/",
            classes="path-input no-compact",
        )
        remove_btn = Button("−", classes="path-remove")
        if not self._effective_kprobe:
            remove_btn.add_class("hidden")
        return Horizontal(path_input, remove_btn, classes="path-row")

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
                    with RadioSet(id="mode-select", classes="no-compact"):
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

            # Path input(s). kprobe supports multiple target paths via an
            # add/remove row list; fsmon stays single-path.
            with Vertical(id="path-section"):
                yield Label("Target Path:", id="path-label")
                with Vertical(id="path-rows"):
                    yield self._make_path_row(self._default_path)
                if self._effective_kprobe:
                    yield Button("+ Add path", id="path-add", classes="-secondary")
                else:
                    yield Static(
                        "[dim]Multi-path requires the kprobe backend.[/dim]",
                        id="multipath-hint",
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
            # No RadioSet (path-only mode), focus the first path input instead
            try:
                path_input = self.query(".path-input").first(Input)
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
        elif event.button.id == "path-add":
            self._add_path_row()
        elif event.button.has_class("path-remove"):
            self._remove_path_row(event.button)

    def _add_path_row(self) -> None:
        """Mount a new (empty) path-input row into the row list."""
        try:
            rows = self.query_one("#path-rows", Vertical)
            rows.mount(self._make_path_row(""))
        except Exception:
            pass

    def _remove_path_row(self, button: Button) -> None:
        """Remove the row owning ``button``, but never the last remaining row."""
        try:
            rows = list(self.query(".path-row"))
            if len(rows) <= 1:
                return
            node = button
            while node is not None:
                if node in rows:
                    node.remove()
                    return
                node = node.parent
        except Exception:
            pass

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
        """Show error message and highlight the path input rows."""
        try:
            error_label = self.query_one("#error-label", Label)
            error_label.update(message)
            error_label.remove_class("hidden")

            for path_input in self.query(".path-input"):
                path_input.add_class("error")
        except Exception:
            pass

    def _hide_error(self) -> None:
        """Hide error message and clear the path input highlight."""
        try:
            error_label = self.query_one("#error-label", Label)
            error_label.add_class("hidden")

            for path_input in self.query(".path-input"):
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

    def _collect_paths(self) -> list[str]:
        """Return the non-empty, stripped values of every path-input row."""
        paths: list[str] = []
        for path_input in self.query(".path-input"):
            value = path_input.value.strip()
            if value:
                paths.append(value)
        return paths

    def _validate(self) -> tuple[bool, str]:
        """Validate inputs.

        Every non-empty path row must be absolute, and at least one non-empty
        path is required.

        Returns:
            Tuple of (valid, error_message)
        """
        try:
            paths = self._collect_paths()

            if not paths:
                return False, "Please enter a path to monitor"

            for path in paths:
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
            paths = self._collect_paths()

            mode = self._get_selected_mode()

            config = MonitorConfig(
                cancelled=False,
                mode=mode,
                target_path=paths[0],
                target_paths=paths,
                target_pid=self._spotlight_pid if mode == "pid" else None,
                app_name=self._get_app_name(),
            )

            self._dismiss_with_refresh(config)

        except Exception as e:
            self._show_error(f"Error: {e}")
