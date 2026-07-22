"""Folder selection modal for choosing output directory."""

import os
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label

from .base import ExtractionModal, KeyHintFooter


class FolderSelectResult:
    """Result from folder selection modal.

    Attributes:
        cancelled: True if user cancelled selection
        folder_path: Selected folder path (created if needed)
    """

    def __init__(self, cancelled: bool = True, folder_path: str = ""):
        self.cancelled = cancelled
        self.folder_path = folder_path


class FolderSelectModal(ExtractionModal[FolderSelectResult]):
    """Modal for selecting an output folder.

    Features:
    - Input field with default path
    - Creates folder if it doesn't exist
    - Validates path
    - Enter to confirm, Escape to cancel
    """

    BINDINGS = [
        Binding("enter", "confirm", "Confirm", priority=True),
    ]

    DEFAULT_CSS = """
    FolderSelectModal .modal-container {
        width: 75;
        max-width: 90%;
        max-height: 60%;
    }

    FolderSelectModal #folder-description {
        color: $foreground;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    FolderSelectModal #folder-input-label {
        color: $foreground-muted;
        height: 1;
        padding-top: 1;
    }

    FolderSelectModal #folder-input.error {
        border: solid $error;
    }

    FolderSelectModal #folder-hint {
        color: $foreground-muted;
        height: auto;
        padding-top: 1;
    }

    FolderSelectModal #folder-error {
        color: $error;
        height: auto;
        padding-top: 1;
    }

    FolderSelectModal .hidden {
        display: none;
    }
    """

    def __init__(
        self,
        title: str = "Select Folder",
        description: str = "",
        default_path: str = "",
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the folder selection modal.

        Args:
            title: Modal title
            description: Description text
            default_path: Default folder path
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.title_text = title
        self.description_text = description
        self.default_path = default_path

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label(self.title_text, classes="modal-title")

            if self.description_text:
                yield Label(self.description_text, id="folder-description")

            yield Label("Output folder:", id="folder-input-label")
            yield Input(
                value=self.default_path,
                placeholder="e.g., ./results/forensic_apks/",
                id="folder-input",
                classes="no-compact",
            )
            yield Label(
                "[dim]Folder will be created if it doesn't exist[/dim]",
                id="folder-hint",
            )
            yield Label("", id="folder-error", classes="hidden")

            with Horizontal(classes="button-row"):
                yield Button("Save Here", id="btn-save", classes="-primary")
                yield Button("Cancel", id="btn-cancel", classes="-secondary")

            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus the input on mount."""
        super().on_mount()
        try:
            input_field = self.query_one("#folder-input", Input)
            input_field.focus()
            # Move cursor to end
            input_field.cursor_position = len(input_field.value)
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-cancel":
            self._cancel()
        elif event.button.id == "btn-save":
            self._confirm()

    def action_confirm(self) -> None:
        """Confirm selection."""
        self._confirm()

    def _show_error(self, message: str) -> None:
        """Show error message.

        Args:
            message: Error message to display
        """
        try:
            error_label = self.query_one("#folder-error", Label)
            error_label.update(message)
            error_label.remove_class("hidden")

            input_field = self.query_one("#folder-input", Input)
            input_field.add_class("error")
        except Exception:
            pass

    def _hide_error(self) -> None:
        """Hide error message."""
        try:
            error_label = self.query_one("#folder-error", Label)
            error_label.add_class("hidden")

            input_field = self.query_one("#folder-input", Input)
            input_field.remove_class("error")
        except Exception:
            pass

    def _validate_and_create_folder(self, path_str: str) -> tuple[bool, str]:
        """Validate and create folder if needed.

        Args:
            path_str: Folder path string

        Returns:
            Tuple of (success, resolved_path or error_message)
        """
        if not path_str.strip():
            return False, "Please enter a folder path"

        try:
            folder_path = Path(path_str).expanduser().resolve()

            if folder_path.exists() and not folder_path.is_dir():
                return False, "Path exists but is not a directory"

            folder_path.mkdir(parents=True, exist_ok=True)
            return True, str(folder_path)
        except PermissionError:
            return False, "Permission denied to create folder"
        except Exception as e:
            return False, f"Cannot create folder: {e}"

    def _cancel(self) -> None:
        """Cancel and dismiss."""
        self._dismiss_with_refresh(FolderSelectResult(cancelled=True))

    def _confirm(self) -> None:
        """Validate path and confirm selection."""
        try:
            input_field = self.query_one("#folder-input", Input)
            path_str = input_field.value.strip()

            success, result = self._validate_and_create_folder(path_str)

            if success:
                self._hide_error()
                self._dismiss_with_refresh(
                    FolderSelectResult(cancelled=False, folder_path=result)
                )
            else:
                self._show_error(result)

        except Exception as e:
            self._show_error(f"Error: {e}")


def get_default_forensic_apks_folder() -> str:
    """Get the default folder for forensic APKs.

    Returns:
        Path string for default forensic APKs folder
    """
    results_path = os.environ.get("RESULTS_PATH", "results/")
    return os.path.join(results_path, "forensic_apks")
