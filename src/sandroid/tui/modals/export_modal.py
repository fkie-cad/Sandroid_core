"""Export modal for exporting recorded actions.

Provides a modal interface for exporting action packages with
selectable components (recording, snapshot, or both).
"""

import os
import shutil
import tempfile
from dataclasses import dataclass

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Checkbox, Input, Label, Static

from sandroid.core.toolbox import Toolbox

from .base import ExtractionModal, KeyHintFooter


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
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the export modal."""
        super().__init__(name=name, id=id, classes=classes)
        self._recording_exists = self._check_recording_exists()
        self._snapshot_exists = self._check_snapshot_exists()
        self._exporting = False
        self._default_location = self._get_default_export_location()

    def _get_default_export_location(self) -> str:
        """Get default export location (results folder)."""
        results_path = os.getenv("RESULTS_PATH", "")
        if results_path and os.path.isdir(results_path):
            return results_path
        # Fall back to RAW_RESULTS_PATH parent directory
        raw_path = os.getenv("RAW_RESULTS_PATH", "")
        if raw_path:
            parent = os.path.dirname(raw_path.rstrip("/"))
            if parent and os.path.isdir(parent):
                return parent
        # Default to current directory
        return os.getcwd()

    def _check_recording_exists(self) -> bool:
        """Check if recording.txt exists."""
        recording_path = os.path.join(
            os.getenv("RAW_RESULTS_PATH", "./"), "recording.txt"
        )
        return os.path.exists(recording_path)

    def _check_snapshot_exists(self) -> bool:
        """Check if tmp snapshot exists."""
        try:
            device_name = Toolbox.device_name
            snapshot_path = os.path.join(
                os.path.expanduser("~"),
                ".android",
                "avd",
                f"{device_name}.avd",
                "snapshots",
                "tmp",
            )
            return os.path.exists(snapshot_path)
        except Exception:
            return False

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Export Action", classes="modal-title")

            with Vertical(id="components-section"):
                yield Label("Select components to export:", id="components-label")

                for chk_id, label, exists in [
                    (
                        "chk-recording",
                        "Recording (recording.txt)",
                        self._recording_exists,
                    ),
                    (
                        "chk-snapshot",
                        "Snapshot (emulator state)",
                        self._snapshot_exists,
                    ),
                ]:
                    status_class = "available" if exists else "unavailable"
                    status_text = "available" if exists else "not found"
                    with Horizontal(classes="component-row"):
                        yield Checkbox(label, id=chk_id, value=exists)
                        yield Static(
                            f"[dim]{status_text}[/dim]",
                            classes=f"component-status {status_class}",
                        )

            # Name section
            with Vertical(id="name-section"):
                yield Label("Action name:", id="name-label")
                yield Input(
                    placeholder="Enter a name for this action",
                    id="name-input",
                )

            # Location section
            with Vertical(id="location-section"):
                yield Label("Save location:", id="location-label")
                yield Input(
                    value=self._default_location,
                    placeholder="Directory to save the action file",
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
        """Perform the export operation."""
        if self._exporting:
            return

        try:
            # Get values
            name_input = self.query_one("#name-input", Input)
            location_input = self.query_one("#location-input", Input)
            chk_recording = self.query_one("#chk-recording", Checkbox)
            chk_snapshot = self.query_one("#chk-snapshot", Checkbox)

            action_name = name_input.value.strip()
            export_location = location_input.value.strip()
            export_recording = chk_recording.value
            export_snapshot = chk_snapshot.value

            # Validate name
            if not action_name:
                self._show_error("Please enter an action name")
                name_input.focus()
                return

            # Validate location
            if not export_location:
                self._show_error("Please enter a save location")
                location_input.focus()
                return

            # Check if location exists, create if not
            if not os.path.exists(export_location):
                try:
                    os.makedirs(export_location, exist_ok=True)
                except Exception as e:
                    self._show_error(f"Cannot create directory: {e}")
                    location_input.focus()
                    return

            if not export_recording and not export_snapshot:
                self._show_error("Please select at least one component")
                return

            full_export_path = os.path.join(export_location, f"{action_name}.action")
            if os.path.exists(full_export_path):
                self._show_error(
                    f"Action '{action_name}' already exists in this location"
                )
                name_input.focus()
                return

            if export_recording and not self._recording_exists:
                self._show_error("Recording not found")
                return

            if export_snapshot and not self._snapshot_exists:
                self._show_error("Snapshot not found")
                return

            self._exporting = True
            self._update_status("[dim]Exporting...[/dim]")

            # Perform export
            success, export_path, error = self._perform_export(
                action_name, export_location, export_recording, export_snapshot
            )

            if success:
                result = ExportResult(
                    cancelled=False,
                    success=True,
                    action_name=action_name,
                    export_recording=export_recording,
                    export_snapshot=export_snapshot,
                    export_path=export_path,
                )
                self._dismiss_with_refresh(result)
            else:
                self._exporting = False
                self._update_status("")
                self._show_error(error)

        except Exception as e:
            self._exporting = False
            self._update_status("")
            self._show_error(f"Export failed: {e!s}")

    def _perform_export(
        self,
        action_name: str,
        export_location: str,
        export_recording: bool,
        export_snapshot: bool,
    ) -> tuple[bool, str, str]:
        """Perform the actual export operation.

        Args:
            action_name: Name for the exported action
            export_location: Directory to save the action file
            export_recording: Whether to include recording
            export_snapshot: Whether to include snapshot

        Returns:
            Tuple of (success, export_path, error_message)
        """
        try:
            recording_path = os.path.join(
                os.getenv("RAW_RESULTS_PATH", "./"), "recording.txt"
            )
            device_name = Toolbox.device_name
            snapshot_path = os.path.join(
                os.path.expanduser("~"),
                ".android",
                "avd",
                f"{device_name}.avd",
                "snapshots",
                "tmp",
            )

            temp_dir = tempfile.mkdtemp(prefix=f"{action_name}_")

            try:
                # Copy components to temp directory
                if export_snapshot and os.path.exists(snapshot_path):
                    # Copy snapshot directory contents
                    for item in os.listdir(snapshot_path):
                        src = os.path.join(snapshot_path, item)
                        dst = os.path.join(temp_dir, item)
                        if os.path.isdir(src):
                            shutil.copytree(src, dst)
                        else:
                            shutil.copy2(src, dst)

                if export_recording and os.path.exists(recording_path):
                    shutil.copy2(recording_path, temp_dir)

                # Create zip archive in temp location
                zip_base = os.path.join(tempfile.gettempdir(), action_name)
                shutil.make_archive(zip_base, "zip", temp_dir)

                # Move to final location with .action extension
                final_path = os.path.join(export_location, f"{action_name}.action")
                shutil.move(f"{zip_base}.zip", final_path)

                return True, os.path.abspath(final_path), ""

            finally:
                # Clean up temp directory
                if os.path.exists(temp_dir) and os.path.isdir(temp_dir):
                    shutil.rmtree(temp_dir)

        except Exception as e:
            return False, "", str(e)
