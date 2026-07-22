"""Recording modal for TUI mode.

Provides a modal interface for recording Android input events
with real-time status display and optional live event viewing.
"""

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Button, Checkbox, Input, Label, Static

from sandroid.core.toolbox import Toolbox
from sandroid.services import get_task_service
from sandroid.tui.modals.base import ExtractionModal, ForensicModal, KeyHintFooter
from sandroid.tui.utils.recording_wrapper import RecordingWrapper

if TYPE_CHECKING:
    from textual.timer import Timer


@dataclass
class RecordSettings:
    """The Record-settings form's captured values (idea B combined form).

    Dismissed from :class:`RecordSettingsModal` and forwarded live to the
    controller via ``on_settings_chosen``; also folded into the final
    :class:`RecordingResult` at Stop time.

    Attributes:
        label: Run name (kept as the auto-generated default if left blank).
        number_of_runs: Number of playback replays to perform.
        noise_filter: Whether the dry-run noise-subtraction pass runs.
    """

    label: str
    number_of_runs: int
    noise_filter: bool


@dataclass
class RecordingResult:
    """Result from recording modal."""

    cancelled: bool = True
    completed: bool = False
    duration: int = 0
    event_count: int = 0
    output_file: str = ""
    #: The label chosen (or kept as the auto-generated default) via the
    #: combined Record-settings form shown right after recording starts.
    #: Seeds RecordingController's ``_current_recording_label`` for every
    #: subsequent Play of this recording.
    label: str = ""
    #: Number of playback replays chosen in the Record-settings form. Drives
    #: the auto-chained playback (and every later manual Play of this
    #: recording) via ``RunConfig.for_playback(number_of_runs=...)``.
    number_of_runs: int = 2
    #: Whether the dry-run noise-subtraction pass runs during playback.
    #: Maps to ``RunConfig.for_playback(noise_filter=...)``.
    noise_filter: bool = True


class RecordSettingsModal(ForensicModal[RecordSettings]):
    """Combined Record-settings form (idea B): name + replays + dry-run.

    Replaces the old single-field "Label this run" prompt. Shown
    non-blockingly right after recording starts (recording captures *device*
    interaction, so a stacked form blocks nothing time-sensitive), it collects
    the three things the auto-chained playback needs. Modelled on
    :class:`~sandroid.tui.modals.export_modal.ExportModal`'s Checkbox+Input
    layout. Dismisses with a :class:`RecordSettings`, or ``None`` on cancel
    (the caller keeps its defaults).
    """

    DEFAULT_CSS = """
    RecordSettingsModal .modal-container {
        width: 64;
    }

    RecordSettingsModal .rs-field-label {
        color: $foreground-muted;
        padding-top: 1;
    }

    RecordSettingsModal #rs-dryrun-row {
        width: 100%;
        height: auto;
        padding: 1 0;
    }
    """

    def __init__(
        self,
        *,
        default_label: str = "",
        default_number_of_runs: int = 2,
        default_noise_filter: bool = True,
        name: str = None,
        id: str = None,
        classes: str = None,
    ) -> None:
        """Initialize the Record-settings form.

        Args:
            default_label: Auto-generated default run name (kept if left blank).
            default_number_of_runs: Default number of playback replays.
            default_noise_filter: Default dry-run noise-filter state.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._default_label = default_label
        self._default_number_of_runs = default_number_of_runs
        self._default_noise_filter = default_noise_filter

    def compose(self) -> ComposeResult:
        """Create the settings form layout."""
        with Vertical(classes="modal-container"):
            yield Label("Record settings", classes="modal-title")
            yield Label(
                "Recording is running — these apply when you Stop.",
                classes="modal-message",
            )
            yield Label("Run name:", classes="rs-field-label")
            yield Input(
                value=self._default_label,
                placeholder=self._default_label or "run label",
                id="rs-name-input",
            )
            yield Label("Number of replays:", classes="rs-field-label")
            yield Input(
                value=str(self._default_number_of_runs),
                type="integer",
                id="rs-runs-input",
            )
            with Horizontal(id="rs-dryrun-row"):
                yield Checkbox(
                    "Dry-run noise filter",
                    value=self._default_noise_filter,
                    id="rs-dryrun",
                )
            with Horizontal(classes="button-row"):
                yield Button("Save", id="rs-save", classes="-primary")
                yield Button("Cancel", id="rs-cancel", classes="-secondary")
            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus the name input on mount."""
        super().on_mount()
        try:
            self.query_one("#rs-name-input", Input).focus()
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle Save/Cancel."""
        if event.button.id == "rs-save":
            self._submit()
        elif event.button.id == "rs-cancel":
            self.action_cancel()

    def _submit(self) -> None:
        """Read the fields and dismiss with a :class:`RecordSettings`."""
        try:
            name = self.query_one("#rs-name-input", Input).value.strip()
            runs_raw = self.query_one("#rs-runs-input", Input).value.strip()
            noise = self.query_one("#rs-dryrun", Checkbox).value
        except Exception:
            self._dismiss_with_refresh(None)
            return

        label = name or self._default_label
        try:
            number_of_runs = int(runs_raw)
        except (TypeError, ValueError):
            number_of_runs = self._default_number_of_runs
        number_of_runs = max(1, number_of_runs)

        self._dismiss_with_refresh(
            RecordSettings(
                label=label,
                number_of_runs=number_of_runs,
                noise_filter=bool(noise),
            )
        )


class RecordingModal(ExtractionModal[RecordingResult]):
    """Modal for recording input events.

    Features:
    - Simple status display (elapsed time, event count)
    - Toggle for live event display
    - Stop via button, Escape, or Ctrl+C
    - Creates snapshot before recording starts
    """

    BINDINGS = [
        Binding("ctrl+c", "stop_or_cancel", "Stop", priority=True, show=False),
        Binding("enter", "start_or_stop", "Start/Stop", priority=True, show=False),
    ]

    DEFAULT_CSS = """
    RecordingModal .modal-container {
        width: 80;
        max-height: 35;
    }

    RecordingModal .modal-container.recording {
        border: solid $error;
    }

    RecordingModal .modal-title.recording {
        color: $error;
    }

    RecordingModal #status-display {
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: auto;
        padding: 1 0;
    }

    RecordingModal #elapsed-time {
        text-align: center;
        width: 100%;
        height: 1;
        color: $foreground-muted;
    }

    RecordingModal #event-count {
        text-align: center;
        width: 100%;
        height: 1;
        color: $foreground-muted;
    }

    RecordingModal #options-container {
        width: 100%;
        height: auto;
        padding: 1 0;
        align: center middle;
    }

    RecordingModal #live-events-container {
        background: $panel;
        border: solid $foreground-muted;
        height: 10;
        width: 100%;
        overflow: auto;
        padding: 1;
        display: none;
    }

    RecordingModal #live-events-container.visible {
        display: block;
    }

    RecordingModal #live-events-log {
        width: 100%;
        height: auto;
    }

    RecordingModal #hint-text {
        color: $foreground-muted;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: 2;
        padding-top: 1;
    }

    RecordingModal #btn-start {
        min-width: 20;
        margin-right: 2;
    }

    RecordingModal #btn-stop {
        background: $error;
        color: #ffffff;
        min-width: 20;
        margin-right: 2;
        display: none;
    }

    RecordingModal #btn-stop.visible {
        display: block;
    }

    RecordingModal #btn-start.hidden {
        display: none;
    }

    RecordingModal #btn-stop:hover {
        background: $error-darken-1;
    }
    """

    is_recording = reactive(False)
    elapsed_seconds = reactive(0)
    event_count = reactive(0)
    show_live_events = reactive(False)

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
        auto_start: bool = False,
        default_label: str = "",
        default_number_of_runs: int = 2,
        default_noise_filter: bool = True,
        on_settings_chosen: Callable[[str, int, bool], None] | None = None,
    ):
        """Initialize the recording modal.

        Args:
            auto_start: If True, start recording immediately on mount
                instead of waiting for the "Start Recording" button — used
                by ``RecordingController.start_recording()`` so pressing
                Record starts the device capture with no extra step.
            default_label: Auto-generated default name (e.g.
                ``"Run 3 · 14:22"``) shown as the settings form's placeholder.
            default_number_of_runs: Default number of playback replays shown
                in the combined Record-settings form.
            default_noise_filter: Default dry-run noise-filter state shown in
                the combined Record-settings form.
            on_settings_chosen: Called with ``(label, number_of_runs,
                noise_filter)`` the moment the non-blocking combined
                Record-settings form is dismissed — fires well before
                Stop/dismiss, since recording is device-driven and unaffected
                by a stacked modal, so the controller can seed every
                subsequent manual Play of this recording.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._wrapper: RecordingWrapper | None = None
        self._timer: Timer | None = None
        self._live_event_lines: list[str] = []
        self._max_live_lines = 100
        self._output_file = os.path.join(
            os.getenv("RAW_RESULTS_PATH", "./"), "recording.txt"
        )
        self._auto_start = auto_start
        self._default_label = default_label
        self._chosen_label = default_label
        self._default_number_of_runs = default_number_of_runs
        self._default_noise_filter = default_noise_filter
        self._number_of_runs = default_number_of_runs
        self._noise_filter = default_noise_filter
        self._on_settings_chosen = on_settings_chosen
        self._settings_prompted = False

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Record Input Events", classes="modal-title")

            # Status display
            with Vertical(id="status-display"):
                yield Static("Press Start to begin recording", id="elapsed-time")
                yield Static("Events: 0", id="event-count")

            # Options
            with Horizontal(id="options-container"):
                yield Checkbox("Show live events", id="live-events-checkbox")

            # Live events container (hidden by default)
            with Vertical(id="live-events-container"):
                yield Static(
                    "[dim]Events will appear here...[/dim]", id="live-events-log"
                )

            yield Label(
                "[dim]Interact with the device to record input events[/dim]",
                id="hint-text",
            )

            with Horizontal(classes="button-row"):
                yield Button("Start Recording", id="btn-start", classes="-primary")
                yield Button("Stop Recording", id="btn-stop")
                yield Button("Cancel", id="btn-cancel", classes="-secondary")

            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Set up on mount."""
        super().on_mount()
        try:
            btn = self.query_one("#btn-start", Button)
            btn.focus()
        except Exception:
            pass
        if self._auto_start and not self.is_recording:
            # Pressing Record starts device capture immediately — no extra
            # "press Start" step. _start_recording() itself pops the combined
            # Record-settings form right after (see its docstring / class
            # docstring).
            self._start_recording()

    def watch_is_recording(self, recording: bool) -> None:
        """React to recording state changes."""
        try:
            container = self.query_one(".modal-container")
            title = self.query_one(".modal-title", Label)
            btn_start = self.query_one("#btn-start", Button)
            btn_stop = self.query_one("#btn-stop", Button)
            hint = self.query_one("#hint-text", Label)

            if recording:
                container.add_class("recording")
                title.add_class("recording")
                title.update("Recording...")
                btn_start.add_class("hidden")
                btn_stop.add_class("visible")
                hint.update("[dim]Press Stop or Escape to stop recording[/dim]")
                btn_stop.focus()
            else:
                container.remove_class("recording")
                title.remove_class("recording")
                title.update("Record Input Events")
                btn_start.remove_class("hidden")
                btn_stop.remove_class("visible")
                hint.update(
                    "[dim]Interact with the device to record input events[/dim]"
                )
        except Exception:
            pass

    def watch_elapsed_seconds(self, seconds: int) -> None:
        """Update elapsed time display."""
        try:
            elapsed_label = self.query_one("#elapsed-time", Static)
            mins, secs = divmod(seconds, 60)
            elapsed_label.update(f"Elapsed: {mins:02d}:{secs:02d}")
        except Exception:
            pass

    def watch_event_count(self, count: int) -> None:
        """Update event count display."""
        try:
            count_label = self.query_one("#event-count", Static)
            count_label.update(f"Events: {count}")
        except Exception:
            pass

    def watch_show_live_events(self, show: bool) -> None:
        """Toggle live events container visibility."""
        try:
            container = self.query_one("#live-events-container")
            if show:
                container.add_class("visible")
            else:
                container.remove_class("visible")
        except Exception:
            pass

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        """Handle checkbox state changes."""
        if event.checkbox.id == "live-events-checkbox":
            self.show_live_events = event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-start":
            self._start_recording()
        elif event.button.id == "btn-stop":
            self._stop_recording()
        elif event.button.id == "btn-cancel":
            self._cancel()

    def action_stop_or_cancel(self) -> None:
        """Handle Escape/Ctrl+C."""
        if self.is_recording:
            self._stop_recording()
        else:
            self._cancel()

    def action_cancel(self) -> None:
        """Override base cancel to handle recording state."""
        self.action_stop_or_cancel()

    def action_start_or_stop(self) -> None:
        """Handle Enter key."""
        if self.is_recording:
            self._stop_recording()
        else:
            self._start_recording()

    def _start_recording(self) -> None:
        """Start the recording process."""
        # Create snapshot first
        try:
            Toolbox.create_snapshot(b"tmp")
        except Exception as e:
            self._show_error(f"Failed to create snapshot: {e}")
            return

        # Create wrapper with callbacks
        self._wrapper = RecordingWrapper(
            output_file=self._output_file,
            on_event=self._on_event if self.show_live_events else None,
            on_count_update=self._on_count_update,
        )

        # Start recording
        if not self._wrapper.start():
            self._show_error("Failed to start recording")
            return

        # Register as background task
        get_task_service().register(
            name="recording",
            display_name="Recording",
            instance=self._wrapper,
            stop_callback=self._wrapper.stop,
        )

        # Start elapsed time timer
        self._timer = self.set_interval(1.0, self._update_elapsed)

        self.is_recording = True
        self.elapsed_seconds = 0
        self.event_count = 0

        # Non-blocking: recording is already running in the background
        # (RecordingWrapper is device-driven), so stacking this form on
        # top right now costs nothing time-sensitive.
        self._prompt_settings()

    def _prompt_settings(self) -> None:
        """Pop the (non-blocking) combined Record-settings form (idea B).

        Only ever shown once per recording session. The chosen name (or the
        auto-generated default, kept on Esc/blank), replay count and dry-run
        flag are cached on ``self`` and forwarded live via
        ``on_settings_chosen`` — see ``RecordingController.start_recording()``
        for why they need to seed future Plays before this whole modal even
        dismisses.
        """
        if self._settings_prompted:
            return
        self._settings_prompted = True

        def on_result(settings: RecordSettings | None) -> None:
            if settings is None:
                # Cancelled — keep the auto-generated defaults untouched.
                label = self._default_label
                number_of_runs = self._default_number_of_runs
                noise_filter = self._default_noise_filter
            else:
                label = settings.label or self._default_label
                number_of_runs = settings.number_of_runs
                noise_filter = settings.noise_filter
            self._chosen_label = label
            self._number_of_runs = number_of_runs
            self._noise_filter = noise_filter
            if self._on_settings_chosen:
                try:
                    self._on_settings_chosen(label, number_of_runs, noise_filter)
                except Exception:
                    pass

        self.app.push_screen(
            RecordSettingsModal(
                default_label=self._default_label,
                default_number_of_runs=self._default_number_of_runs,
                default_noise_filter=self._default_noise_filter,
            ),
            on_result,
        )

    def _stop_recording(self) -> None:
        """Stop the recording process."""
        if self._timer:
            self._timer.stop()
            self._timer = None

        duration = 0
        event_count = 0

        if self._wrapper:
            duration = self._wrapper.stop()
            event_count = self._wrapper.event_count

            # Unregister background task
            try:
                get_task_service().unregister("recording")
            except Exception:
                pass

        self.is_recording = False

        # Dismiss with result
        result = RecordingResult(
            cancelled=False,
            completed=True,
            duration=duration,
            event_count=event_count,
            output_file=self._output_file,
            label=self._chosen_label,
            number_of_runs=self._number_of_runs,
            noise_filter=self._noise_filter,
        )
        self._dismiss_with_refresh(result)

    def _cancel(self) -> None:
        """Cancel recording and close modal."""
        if self._wrapper and self._wrapper.is_running:
            self._wrapper.stop()
            try:
                get_task_service().unregister("recording")
            except Exception:
                pass

        if self._timer:
            self._timer.stop()

        self._dismiss_with_refresh(RecordingResult(cancelled=True))

    def _update_elapsed(self) -> None:
        """Update elapsed time from wrapper."""
        if self._wrapper:
            self.elapsed_seconds = self._wrapper.elapsed_seconds
            self.event_count = self._wrapper.event_count

    def _on_event(self, line: str) -> None:
        """Callback for live event display."""
        if not self.show_live_events:
            return

        self._live_event_lines.append(line)
        if len(self._live_event_lines) > self._max_live_lines:
            self._live_event_lines = self._live_event_lines[-self._max_live_lines :]

        # Update display (thread-safe)
        self.app.call_from_thread(self._update_live_events)

    def _on_count_update(self, count: int) -> None:
        """Callback for event count updates."""
        # Update in main thread
        self.app.call_from_thread(setattr, self, "event_count", count)

    def _update_live_events(self) -> None:
        """Update live events display."""
        try:
            log = self.query_one("#live-events-log", Static)
            # Show last 20 lines
            display_lines = self._live_event_lines[-20:]
            log.update("\n".join(display_lines) if display_lines else "[dim]...[/dim]")
        except Exception:
            pass

    def _show_error(self, message: str) -> None:
        """Show error in status display."""
        try:
            elapsed_label = self.query_one("#elapsed-time", Static)
            elapsed_label.update(f"[red]Error: {message}[/red]")
        except Exception:
            pass
