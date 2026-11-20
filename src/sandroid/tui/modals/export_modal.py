"""Export modal: the TUI's ``x`` writes a Rewind recording to a file.

The newest stopped Rewind recording (or the one the recording controller
holds) is offered with its parts: the recording itself (``recording.json``,
the recorded steps, the file lists and the copied Before / After files) and
its start point (the ``sandroid_rec_*`` emulator snapshot) while it still
exists. The file is a zip named ``<name>.action`` (see
:func:`sandroid.core.rewind.export_recording`); ``i`` imports it again.
The headless batch keeps its own export (``Toolbox.export_action``).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Checkbox, Input, Label, Static

from .base import ExtractionModal, KeyHintFooter

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from sandroid.core.rewind import Recording


@dataclass
class ExportResult:
    """Result from export modal.

    Attributes:
        cancelled: Whether the export was cancelled
        success: Whether the export completed successfully
        action_name: Name of the exported action
        export_recording: Whether recording was included
        export_snapshot: Whether snapshot was included
        export_path: Path to the exported file
        error: Error message if export failed
    """

    cancelled: bool = True
    success: bool = False
    action_name: str = ""
    export_recording: bool = True
    export_snapshot: bool = True
    export_path: str = ""
    error: str = ""


class ExportModal(ExtractionModal[ExportResult]):
    """Modal for exporting recorded actions.

    Features:
    - Checkboxes for component selection (recording/snapshot)
    - Input field for action name
    - Validation before export
    - Progress indication during export
    """

    BINDINGS = [
        Binding("enter", "export", "Export", priority=True, show=False),
    ]

    DEFAULT_CSS = """
    ExportModal .modal-container {
        width: 80;
    }

    ExportModal #components-section {
        width: 100%;
        height: auto;
        padding: 1 0;
    }

    ExportModal #components-label {
        color: $foreground-muted;
        padding-bottom: 1;
    }

    ExportModal .component-row {
        width: 100%;
        height: auto;
        padding-left: 2;
    }

    ExportModal .component-status {
        color: $foreground-muted;
        padding-left: 2;
    }

    ExportModal .component-status.available {
        color: $success;
    }

    ExportModal .component-status.unavailable {
        color: $error;
    }

    ExportModal #name-section {
        width: 100%;
        height: auto;
        padding: 1 0;
    }

    ExportModal #name-label {
        color: $foreground-muted;
        padding-bottom: 1;
    }

    ExportModal #name-input {
        width: 100%;
    }

    ExportModal #location-section {
        width: 100%;
        height: auto;
        padding: 0 0 1 0;
    }

    ExportModal #location-label {
        color: $foreground-muted;
        padding-bottom: 1;
    }

    ExportModal #location-input {
        width: 100%;
    }

    ExportModal #error-label {
        color: $error;
        text-align: center;
        width: 100%;
        height: 2;
        display: none;
    }

    ExportModal #error-label.visible {
        display: block;
    }

    ExportModal #status-label {
        color: $foreground-muted;
        text-align: center;
        width: 100%;
        height: 2;
    }

    ExportModal #btn-export.disabled {
        background: $panel;
        color: $foreground-muted;
    }
    """

    def __init__(
        self,
        recording: Recording | None = None,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """Initialize the export modal.

        Args:
            recording: The recording to offer (a stopped one); default the
                newest stopped recording of this session folder.
            name: Widget name.
            id: Widget id.
            classes: Widget classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self._rec = self._pick_recording(recording)
        self._recording_exists = self._rec is not None
        self._snapshot_exists = self._check_snapshot_exists()
        self._exporting = False
        self._default_location = self._get_default_export_location()

    @staticmethod
    def _pick_recording(recording: Recording | None) -> Recording | None:
        """``recording`` when it has stopped, else the newest stopped one."""
        if recording is not None and recording.stopped is not None:
            return recording
        try:
            from sandroid.core import rewind

            return rewind.latest_recording()
        except Exception:
            return None

    def _get_default_export_location(self) -> str:
        """Get default export location (results folder)."""
        results_path = os.getenv("RESULTS_PATH", "")
        if results_path and os.path.isdir(results_path):
            return results_path
        return os.getcwd()

    def _check_snapshot_exists(self) -> bool:
        """The recording's start point snapshot still exists."""
        if self._rec is None:
            return False
        try:
            from sandroid.core import rewind

            return rewind.start_point_folder(self._rec) is not None
        except Exception:
            return False

    def _default_name(self) -> str:
        """A file name from the recording's name (``Recording_10-00``)."""
        if self._rec is None:
            return ""
        return re.sub(r"[^\w.-]+", "_", self._rec.name.replace(":", "-")).strip("_")

    def _rows(self) -> list[tuple[str, str, bool, str]]:
        """``(checkbox id, label, available, status words)`` per part."""
        rec = self._rec
        if rec is None:
            return [
                (
                    "chk-recording",
                    "Recording",
                    False,
                    "none yet: r records, r again stops",
                ),
                ("chk-snapshot", "Start point", False, "none"),
            ]
        sp = rec.start_point.get("name") or ""
        if not rec.emulator:
            sp_status = "none on a physical device"
        elif self._snapshot_exists:
            sp_status = "available"
        else:
            sp_status = "gone"
        return [
            (
                "chk-recording",
                f"Recording '{rec.name}' (steps, file lists, copied files)",
                True,
                "available",
            ),
            (
                "chk-snapshot",
                f"Start point {sp}".rstrip(),
                self._snapshot_exists,
                sp_status,
            ),
        ]

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Export recording", classes="modal-title")

            with Vertical(id="components-section"):
                yield Label("Select components to export:", id="components-label")

                for chk_id, label, exists, status_text in self._rows():
                    status_class = "available" if exists else "unavailable"
                    with Horizontal(classes="component-row"):
                        yield Checkbox(label, id=chk_id, value=exists)
                        yield Static(
                            f"[dim]{status_text}[/dim]",
                            classes=f"component-status {status_class}",
                        )

            # Name section
            with Vertical(id="name-section"):
                yield Label("File name:", id="name-label")
                yield Input(
                    value=self._default_name(),
                    placeholder="Name of the file (saved as <name>.action)",
                    id="name-input",
                )

            # Location section
            with Vertical(id="location-section"):
                yield Label("Save location:", id="location-label")
                yield Input(
                    value=self._default_location,
                    placeholder="Folder to save the file in",
                    id="location-input",
                )

            yield Label("", id="error-label")
            yield Label("", id="status-label")

            with Horizontal(classes="button-row"):
                yield Button("Export", id="btn-export", classes="-primary")
                yield Button("Cancel", id="btn-cancel", classes="-secondary")

            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus name input on mount."""
        super().on_mount()
        try:
            name_input = self.query_one("#name-input", Input)
            name_input.focus()

            # Disable checkboxes for unavailable components
            if not self._recording_exists:
                chk = self.query_one("#chk-recording", Checkbox)
                chk.value = False
                chk.disabled = True

            if not self._snapshot_exists:
                chk = self.query_one("#chk-snapshot", Checkbox)
                chk.value = False
                chk.disabled = True

            self._update_export_button()
        except Exception:
            pass

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        """Handle checkbox changes."""
        self._update_export_button()
        self._hide_error()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle input changes."""
        self._hide_error()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-export":
            self._do_export()
        elif event.button.id == "btn-cancel":
            self.action_cancel()

    def action_export(self) -> None:
        """Handle export action."""
        self._do_export()

    def _update_export_button(self) -> None:
        """Update export button state based on selections."""
        try:
            chk_recording = self.query_one("#chk-recording", Checkbox)
            chk_snapshot = self.query_one("#chk-snapshot", Checkbox)
            btn_export = self.query_one("#btn-export", Button)

            has_selection = chk_recording.value or chk_snapshot.value
            btn_export.set_class(not has_selection, "disabled")
        except Exception:
            pass

    def _show_error(self, message: str) -> None:
        """Show error message."""
        try:
            error_label = self.query_one("#error-label", Label)
            error_label.update(f"[red]{message}[/red]")
            error_label.add_class("visible")
        except Exception:
            pass

    def _hide_error(self) -> None:
        """Hide error message."""
        try:
            error_label = self.query_one("#error-label", Label)
            error_label.remove_class("visible")
        except Exception:
            pass

    def _update_status(self, message: str) -> None:
        """Update status message."""
        try:
            status_label = self.query_one("#status-label", Label)
            status_label.update(message)
        except Exception:
            pass

    def _do_export(self) -> None:
        """Check the inputs, then write the file on a worker thread."""
        if self._exporting:
            return

        try:
            name_input = self.query_one("#name-input", Input)
            location_input = self.query_one("#location-input", Input)
            chk_recording = self.query_one("#chk-recording", Checkbox)
            chk_snapshot = self.query_one("#chk-snapshot", Checkbox)

            action_name = name_input.value.strip()
            export_location = os.path.expanduser(location_input.value.strip())
            export_recording = chk_recording.value
            export_snapshot = chk_snapshot.value

            if self._rec is None:
                self._show_error("No recording yet: r records, r again stops")
                return
            if not action_name:
                self._show_error("Please enter a file name")
                name_input.focus()
                return
            if "/" in action_name or "\\" in action_name or action_name in (".", ".."):
                self._show_error("The file name cannot contain a folder")
                name_input.focus()
                return
            if not export_location:
                self._show_error("Please enter a save location")
                location_input.focus()
                return
            if not os.path.exists(export_location):
                try:
                    os.makedirs(export_location, exist_ok=True)
                except Exception as e:
                    self._show_error(f"Cannot create the folder: {e}")
                    location_input.focus()
                    return
            if not export_recording and not export_snapshot:
                self._show_error("Please select at least one part")
                return
            full_export_path = os.path.join(export_location, f"{action_name}.action")
            if os.path.exists(full_export_path):
                self._show_error(f"{action_name}.action already exists there")
                name_input.focus()
                return
            if export_snapshot and not self._snapshot_exists:
                self._show_error("The start point is gone")
                return

            self._exporting = True
            self._update_status(
                "[dim]Exporting (the start point takes a while)...[/dim]"
                if export_snapshot
                else "[dim]Exporting...[/dim]"
            )
            self.run_worker(
                lambda: self._export_worker(
                    action_name, export_location, export_recording, export_snapshot
                ),
                name="export_recording",
                thread=True,
                exclusive=True,
            )
        except Exception as e:
            self._exporting = False
            self._update_status("")
            self._show_error(f"Export failed: {e!s}")

    def _export_worker(
        self,
        action_name: str,
        export_location: str,
        export_recording: bool,
        export_snapshot: bool,
    ) -> None:
        """Write the file (worker thread), then finish on the UI thread."""
        success, path, error = self._perform_export(
            action_name, export_location, export_recording, export_snapshot
        )
        self.app.call_from_thread(
            self._finish_export,
            success,
            path,
            error,
            action_name,
            export_recording,
            export_snapshot,
        )

    def _finish_export(
        self,
        success: bool,
        export_path: str,
        error: str,
        action_name: str,
        export_recording: bool,
        export_snapshot: bool,
    ) -> None:
        """Close with the result, or show the error (UI thread)."""
        if success:
            self._dismiss_with_refresh(
                ExportResult(
                    cancelled=False,
                    success=True,
                    action_name=action_name,
                    export_recording=export_recording,
                    export_snapshot=export_snapshot,
                    export_path=export_path,
                )
            )
            return
        self._exporting = False
        self._update_status("")
        self._show_error(f"Export failed: {error}")

    def _perform_export(
        self,
        action_name: str,
        export_location: str,
        export_recording: bool,
        export_snapshot: bool,
    ) -> tuple[bool, str, str]:
        """Write the recording file.

        Args:
            action_name: The file name (without ``.action``).
            export_location: The folder to save it in.
            export_recording: Include the steps, file lists and copied files.
            export_snapshot: Include the start point.

        Returns:
            Tuple of (success, export_path, error_message)
        """
        from sandroid.core import rewind

        if self._rec is None:
            return False, "", "no recording"
        try:
            path = rewind.export_recording(
                self._rec,
                Path(export_location) / f"{action_name}.action",
                with_recording=export_recording,
                with_start_point=export_snapshot,
            )
        except Exception as e:
            return False, "", str(e)
        return True, str(path.resolve()), ""

    def action_cancel(self) -> None:
        """Esc: close without exporting (not while the file is written)."""
        if self._exporting:
            return
        super().action_cancel()
