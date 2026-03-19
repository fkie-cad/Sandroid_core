"""Spotlight files management modal for viewing and managing monitored files."""

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, OptionList, Static
from textual.widgets.option_list import Option

from sandroid.services import get_forensic_service, get_spotlight_service

from .base import ForensicModal, KeyHintFooter


@dataclass
class SpotlightFilesAction:
    """Result from spotlight files modal.

    Attributes:
        action: What action to take - "close", "add", "remove", "pull"
        file_path: File path for add/remove actions
        pull_all: If True, pull all files
    """

    action: str = "close"  # "close", "add", "remove", "pull", "pull_all"
    file_path: str = ""
    pull_all: bool = False


class SpotlightFilesModal(ForensicModal[SpotlightFilesAction]):
    """Modal for managing spotlight files.

    Features:
    - Lists all monitored files
    - Add new files/paths (supports wildcards)
    - Remove files from monitoring
    - Pull files to local disk
    - Keyboard navigation
    """

    BINDINGS = [
        Binding("q", "close", "Close", priority=True, show=False),
        Binding("a", "add_file", "Add File", show=False),
        Binding("d", "remove_file", "Remove", show=False),
        Binding("p", "pull_selected", "Pull Selected", show=False),
        Binding("P", "pull_all", "Pull All", show=False),
        Binding("down", "next", "Next", show=False),
        Binding("up", "prev", "Previous", show=False),
    ]

    DEFAULT_CSS = """
    SpotlightFilesModal .modal-container {
        width: 90;
        max-width: 95%;
        max-height: 85%;
    }

    SpotlightFilesModal #spotlight-description {
        color: $foreground;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    SpotlightFilesModal #app-info {
        color: $text-muted;
        background: $panel;
        border: solid $foreground-muted;
        padding: 1;
        margin-bottom: 1;
        height: auto;
    }

    SpotlightFilesModal #files-list-container {
        height: 12;
        width: 100%;
        background: $panel;
        border: solid $foreground-muted;
    }

    SpotlightFilesModal #files-list-container:focus-within {
        border: solid $success;
    }

    SpotlightFilesModal #files-option-list {
        width: 100%;
        height: 100%;
        background: transparent;
    }

    SpotlightFilesModal #files-option-list > .option-list--option-highlighted {
        background: $panel-lighten-1;
        color: $success;
    }

    SpotlightFilesModal #no-files-message {
        color: $text-muted;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: 6;
        padding: 2;
    }

    SpotlightFilesModal #add-section {
        margin-top: 1;
        padding: 1;
        border: solid $foreground-muted;
        background: $panel;
    }

    SpotlightFilesModal #add-label {
        color: $foreground;
        text-style: bold;
        height: 1;
    }

    SpotlightFilesModal #add-input {
        width: 100%;
        background: $surface;
        border: solid $foreground-muted;
        margin-top: 1;
    }

    SpotlightFilesModal #add-input:focus {
        border: solid $success;
    }

    SpotlightFilesModal #add-hint {
        color: $text-muted;
        height: auto;
        padding-top: 1;
    }

    SpotlightFilesModal .button-row {
        margin-top: 1;
        height: 3;
    }

    SpotlightFilesModal #btn-add {
        background: $success;
        color: #ffffff;
    }

    SpotlightFilesModal #btn-add:hover {
        background: $success-darken-1;
    }

    SpotlightFilesModal #btn-pull-all {
        background: $primary;
        color: #ffffff;
    }

    SpotlightFilesModal #btn-pull-all:hover {
        background: $primary-darken-1;
    }

    SpotlightFilesModal #btn-pull-all:disabled {
        background: $panel;
        color: $foreground-disabled;
    }

    SpotlightFilesModal #btn-remove {
        background: $error;
        color: #ffffff;
    }

    SpotlightFilesModal #btn-remove:hover {
        background: $error-darken-1;
    }

    SpotlightFilesModal #btn-remove:disabled {
        background: $panel;
        color: $foreground-disabled;
    }

    SpotlightFilesModal #btn-close {
        background: $panel;
        color: $foreground;
    }

    SpotlightFilesModal #btn-close:hover {
        background: $panel-lighten-1;
    }

    SpotlightFilesModal .hidden {
        display: none;
    }
    """

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the spotlight files modal."""
        super().__init__(name=name, id=id, classes=classes)
        self._files = get_forensic_service().get_spotlight_files()
        self._selected_file: str | None = None

        # Get spotlight app info
        spotlight = get_spotlight_service()
        self._spotlight_app = spotlight.get_app_tuple()
        self._spawn_app = spotlight.get_spawn_package()
        self._spawn_mode = spotlight.is_spawn_mode()

    def _get_app_name(self) -> str:
        """Get display name for spotlight app."""
        if self._spawn_mode and self._spawn_app:
            return self._spawn_app
        if self._spotlight_app:
            return (
                self._spotlight_app[0]
                if isinstance(self._spotlight_app, tuple)
                else str(self._spotlight_app)
            )
        return ""

    def _get_default_add_path(self) -> str:
        """Get default path for adding files."""
        app_name = self._get_app_name()
        if app_name:
            return f"/data/data/{app_name}/*"
        return "/data/"

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Spotlight Files Manager", classes="modal-title")

            # App info
            app_name = self._get_app_name()
            if app_name:
                mode_str = "SPAWN" if self._spawn_mode else "ATTACH"
                yield Static(
                    f"[bold]Spotlight App:[/bold] {app_name} [dim]({mode_str})[/dim]",
                    id="app-info",
                )
            else:
                yield Static(
                    "[dim]No spotlight app selected[/dim]",
                    id="app-info",
                )

            if self._files:
                yield Label(
                    f"{len(self._files)} file(s) being monitored",
                    id="spotlight-description",
                )

                with Vertical(id="files-list-container"):
                    yield OptionList(
                        *self._build_options(),
                        id="files-option-list",
                    )
            else:
                yield Label(
                    "No files are currently being monitored.\n\n"
                    "Add files using the input below or run FSMon to observe\n"
                    "filesystem changes and identify files of interest.",
                    id="no-files-message",
                )

            # Add file section
            with Vertical(id="add-section"):
                yield Label("Add File/Path:", id="add-label")
                yield Input(
                    value=self._get_default_add_path(),
                    placeholder="/data/data/com.example.app/databases/*",
                    id="add-input",
                )
                yield Label(
                    "[dim]Supports wildcards: /path/* or /path/**/* for recursive[/dim]",
                    id="add-hint",
                )

            with Horizontal(classes="button-row"):
                yield Button("Add", id="btn-add")
                if self._files:
                    yield Button("Pull All", id="btn-pull-all")
                    yield Button("Remove", id="btn-remove")
                yield Button("Close", id="btn-close", classes="-secondary")

            yield KeyHintFooter(
                hints={
                    "default": "[dim]a=Add  d=Remove  p=Pull  P=Pull All  j/k=Navigate  Tab=Focus  Esc=Close[/dim]",
                    "input": "[dim]Enter=Add  Tab=Next  Esc=Close[/dim]",
                    "list": "[dim]j/k=Navigate  d=Remove  p=Pull  Enter=Select  Esc=Close[/dim]",
                }
            )

    def _build_options(self) -> list[Option]:
        """Build option list items for files."""
        options = []
        for file_path in sorted(self._files):
            # Truncate long paths
            display = file_path
            if len(display) > 70:
                display = "..." + display[-67:]
            options.append(Option(display, id=file_path))
        return options

    def on_mount(self) -> None:
        """Focus appropriate widget on mount."""
        super().on_mount()
        if self._files:
            try:
                option_list = self.query_one("#files-option-list", OptionList)
                option_list.focus()
                option_list.highlighted = 0
                self._update_selection()
            except Exception:
                pass
        else:
            try:
                add_input = self.query_one("#add-input", Input)
                add_input.focus()
            except Exception:
                pass

    def action_close(self) -> None:
        """Close the modal."""
        self._dismiss_with_refresh(SpotlightFilesAction(action="close"))

    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted
    ) -> None:
        """Handle option highlight change."""
        self._update_selection()

    def _update_selection(self) -> None:
        """Update selection based on highlighted option."""
        self._selected_file = None
        try:
            option_list = self.query_one("#files-option-list", OptionList)
            highlighted = option_list.highlighted
            if highlighted is not None:
                option = option_list.get_option_at_index(highlighted)
                if option and option.id:
                    self._selected_file = option.id
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-close":
            self.action_close()
        elif event.button.id == "btn-add":
            self.action_add_file()
        elif event.button.id == "btn-remove":
            self.action_remove_file()
        elif event.button.id == "btn-pull-all":
            self.action_pull_all()

    def action_add_file(self) -> None:
        """Add file from input field."""
        try:
            add_input = self.query_one("#add-input", Input)
            path = add_input.value.strip()

            if path:
                self._dismiss_with_refresh(
                    SpotlightFilesAction(action="add", file_path=path)
                )
        except Exception:
            pass

    def action_remove_file(self) -> None:
        """Remove selected file."""
        self._update_selection()
        if self._selected_file:
            self._dismiss_with_refresh(
                SpotlightFilesAction(action="remove", file_path=self._selected_file)
            )

    def action_pull_selected(self) -> None:
        """Pull selected file."""
        self._update_selection()
        if self._selected_file:
            self._dismiss_with_refresh(
                SpotlightFilesAction(action="pull", file_path=self._selected_file)
            )

    def action_pull_all(self) -> None:
        """Pull all files."""
        if self._files:
            self._dismiss_with_refresh(
                SpotlightFilesAction(action="pull_all", pull_all=True)
            )

    def action_next(self) -> None:
        """Move to next option."""
        try:
            option_list = self.query_one("#files-option-list", OptionList)
            option_list.action_cursor_down()
        except Exception:
            pass

    def action_prev(self) -> None:
        """Move to previous option."""
        try:
            option_list = self.query_one("#files-option-list", OptionList)
            option_list.action_cursor_up()
        except Exception:
            pass
