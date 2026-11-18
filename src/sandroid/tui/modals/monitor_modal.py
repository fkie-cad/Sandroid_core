"""Monitor configuration modal for filesystem observation."""

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button,
    Checkbox,
    Input,
    Label,
    RadioButton,
    RadioSet,
    Static,
)

from sandroid.config import get_config
from sandroid.core.kprobe_tracer import KprobeTracer
from sandroid.services import get_spotlight_service
from sandroid.tui.controllers.monitor_controller import MonitorConfig
from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


class MonitorConfigModal(ForensicModal[MonitorConfig]):
    """Modal for configuring Monitor filesystem monitoring.

    Features:
    - Choose between App mode (the app's processes; with "follow" every
      process of the app, also ones that start or restart later -- so it
      can start before the app runs) and Path mode (every process writing
      under the paths)
    - Shows current spotlight app info
    - Auto-fills path from spotlight app data directory
    - Validates inputs before starting
    """

    BINDINGS = [
        # Note: Enter binding is NOT priority so RadioSet can use it for toggle
        # When RadioSet is focused, Enter toggles; otherwise Enter starts
        Binding("enter", "start_or_toggle", "Start Monitoring", priority=False),
    ]

    # Open on the mode choice (falls back to the path input when there is no
    # PID to choose): Enter must not start a PID-mode monitor by accident.
    AUTO_FOCUS = "#mode-select"

    #: The mode picked last time ("pid"/"path"), for the next open.
    _last_mode: str | None = None

    DEFAULT_CSS = """
    MonitorConfigModal .modal-container {
        width: 75;
        max-width: 90%;
        max-height: 95%;
        /* scrolls instead of clipping the mode choice / hints on small
           terminals (100x30, 80x24) */
        overflow-y: auto;
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
        padding: 0 1;
        margin-bottom: 1;
        height: auto;
    }

    MonitorConfigModal #spotlight-info.has-app {
        border: solid $success;
    }

    MonitorConfigModal #mode-section {
        margin-bottom: 1;
        height: auto;  /* a Vertical is 1fr: squeezed to nothing on 100x30 */
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
        height: auto;
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
        width: 100%;
        padding-top: 1;
    }

    MonitorConfigModal #pid-mode-hint {
        height: auto;
        width: 100%;
    }

    MonitorConfigModal #follow-app {
        background: transparent;
        border: none;
        padding: 0 1;
        margin-top: 1;
        height: auto;
    }

    MonitorConfigModal #follow-app:focus {
        background: $panel;
    }

    MonitorConfigModal #caveat-hint {
        color: $text-muted;
        height: auto;
        width: 100%;
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

        # Following the app (kprobe): default from tui.monitor_follow_app.
        # With it App mode can start before the app runs.
        self._can_follow = self._compute_can_follow()
        self._follow_default = self._can_follow and self._follow_setting()
        self._has_mode_choice = bool(self._spotlight_pid) or bool(
            self._get_package_name() and self._can_follow
        )

    @staticmethod
    def _follow_setting() -> bool:
        try:
            return bool(getattr(get_config().tui, "monitor_follow_app", True))
        except Exception:
            return True

    @staticmethod
    def _compute_can_follow() -> bool:
        """Following needs the kprobe backend (not known to be unavailable)."""
        try:
            return (
                get_config().tui.monitor_backend == "kprobe"
                and KprobeTracer.cached_availability() is not False
            )
        except Exception:
            return False

    def _app_label(self, follow: bool) -> str:
        pkg = self._get_package_name()
        if follow:
            return f"App · {pkg} (all processes, follows restarts)"
        pid = f"PID {self._spotlight_pid}" if self._spotlight_pid else "not running"
        return f"App · {pkg} ({pid} + its children)"

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
            select_on_focus=False,  # extend the prefill, don't replace it
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
                # Only show RadioSet if we have both options available: a
                # running app, or (following) an app that may start later.
                if self._has_mode_choice:
                    by_path = MonitorConfigModal._last_mode == "path"
                    with RadioSet(id="mode-select", classes="no-compact"):
                        yield RadioButton(
                            self._app_label(self._follow_default),
                            id="mode-pid",
                            value=not by_path,
                        )
                        yield RadioButton(
                            "Path · every process writing under the paths below",
                            id="mode-path",
                            value=by_path,
                        )
                    if self._can_follow:
                        yield Checkbox(
                            "Follow the app: every process, also new and "
                            "restarted ones",
                            value=self._follow_default,
                            id="follow-app",
                        )
                    yield Label(
                        "[dim]Without kprobe App mode watches one PID (fsmon "
                        "falls back to Path mode on devices without fanotify)."
                        "[/dim]",
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
                    "[dim]Directory on the device; events are matched by path "
                    "prefix (in PID mode it narrows the app's events). "
                    "/data/data/<pkg> also covers /data/user/0/<pkg> and "
                    "/data/user_de/0/<pkg>.[/dim]",
                    id="path-hint",
                )
                yield Label(
                    "[dim]Writes are seen as they happen, also to files the app "
                    "opened before the start (its databases), so attaching to a "
                    "running app is enough.[/dim]",
                    id="caveat-hint",
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
        # Only handle RadioSet keys if the mode choice (RadioSet) exists
        if self._has_mode_choice:
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
                        "enter": lambda: self._radio_enter(radio_set),
                        "return": lambda: self._radio_enter(radio_set),
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

    def _radio_enter(self, radio_set: RadioSet) -> None:
        """Enter on the mode choice: pick the highlighted mode, or -- when it
        is already the chosen one (as when the dialog opens) -- start.

        Enter used to toggle the already-chosen button, i.e. do nothing.
        """
        highlighted = getattr(radio_set, "_selected", None)
        if highlighted is not None and highlighted != radio_set.pressed_index:
            radio_set.action_toggle_button()
            return
        self._start()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Handle mode selection change."""
        # Update path hint based on mode
        try:
            path_hint = self.query_one("#path-hint", Label)
            aliases = (
                " /data/data/<pkg> also covers /data/user/0/<pkg> and "
                "/data/user_de/0/<pkg>."
            )
            if event.pressed.id == "mode-pid":
                path_hint.update(
                    "[dim]App mode: the app's events, narrowed to paths under "
                    f"this prefix.{aliases}[/dim]"
                )
            else:
                path_hint.update(
                    "[dim]Path mode: every process's events under this "
                    f"directory (path prefix).{aliases}[/dim]"
                )
        except Exception:
            pass

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        """Follow toggled: the App choice says what it will watch."""
        if event.checkbox.id != "follow-app":
            return
        try:
            self.query_one("#mode-pid", RadioButton).label = self._app_label(
                event.value
            )
        except Exception:
            pass

    def _follow_selected(self) -> bool:
        if not self._can_follow:
            return False
        try:
            return bool(self.query_one("#follow-app", Checkbox).value)
        except Exception:
            return self._follow_default

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
            row = self._make_path_row("")
            mounting = rows.mount(row)
        except Exception:
            return

        async def _focus_new_input() -> None:
            # Focus the new input so the first keys typed land in it.
            await mounting
            try:
                row.query_one(Input).focus()
            except Exception:
                pass

        self.call_later(_focus_new_input)

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
        # Without the mode choice only path mode is possible
        if not self._has_mode_choice:
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

            if (
                self._get_selected_mode() == "pid"
                and not self._spotlight_pid
                and not self._follow_selected()
            ):
                return False, (
                    "The app is not running: turn on Follow the app, or use Path"
                )

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
            if self._has_mode_choice:
                MonitorConfigModal._last_mode = mode

            config = MonitorConfig(
                cancelled=False,
                mode=mode,
                target_path=paths[0],
                target_paths=paths,
                target_pid=self._spotlight_pid if mode == "pid" else None,
                app_name=self._get_app_name(),
                follow=mode == "pid" and self._follow_selected(),
            )

            self._dismiss_with_refresh(config)

        except Exception as e:
            self._show_error(f"Error: {e}")
