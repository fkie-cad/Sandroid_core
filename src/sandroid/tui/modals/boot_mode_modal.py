"""Boot mode selection modal for AVD startup."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, Label, OptionList
from textual.widgets.option_list import Option

from .base import ForensicModal, KeyHintFooter


class BootMode(str, Enum):
    """AVD boot mode options."""

    DEFAULT = "default"  # Load default_boot snapshot (standard behavior)
    COLD = "cold"  # Don't load any snapshot (-no-snapshot-load)
    SNAPSHOT = "snapshot"  # Load specific snapshot (-snapshot <name>)
    WIPE = "wipe"  # Wipe all data (-wipe-data)


@dataclass
class SnapshotInfo:
    """Information about an AVD snapshot (for TUI display)."""

    name: str
    path: Path
    size_mb: float
    modified_date: str


@dataclass
class BootModeResult:
    """Result from boot mode selection modal."""

    boot_mode: BootMode = BootMode.DEFAULT
    snapshot_name: str | None = None
    cancelled: bool = False


class BootModeSelectionModal(ForensicModal[BootModeResult]):
    """Modal for selecting AVD boot mode.

    Shows available boot options:
    - Default Snapshot (last saved state)
    - Cold Boot (no snapshot)
    - Specific Snapshot (select from list)
    - Factory Reset (wipe data) - requires confirmation
    """

    DEFAULT_CSS = """
    BootModeSelectionModal .modal-container {
        width: 65;
        max-height: 26;
    }

    BootModeSelectionModal .modal-message {
        margin-bottom: 1;
    }

    BootModeSelectionModal #boot-options {
        height: auto;
        max-height: 10;
        background: $surface;
        border: solid $panel;
        margin-bottom: 1;
    }

    BootModeSelectionModal #boot-options:focus {
        border: solid $primary;
    }

    BootModeSelectionModal #boot-options > .option-list--option-highlighted {
        background: $panel;
        color: #6ba3ff;
    }
    """

    BINDINGS = [
        Binding("enter", "select", "Select", priority=True),
        Binding("j", "next", "Next", show=False),
        Binding("k", "prev", "Previous", show=False),
        Binding("down", "next", "Next", show=False),
        Binding("up", "prev", "Previous", show=False),
    ]

    AUTO_FOCUS = "#boot-options"

    def __init__(
        self,
        avd_name: str,
        snapshots: list[SnapshotInfo] | None = None,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """Initialize the boot mode selection modal.

        Args:
            avd_name: Name of the AVD being started
            snapshots: List of available snapshots (empty if none)
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.avd_name = avd_name
        self.snapshots = snapshots or []

    def _format_boot_option(self, mode: BootMode) -> str:
        """Format boot mode option for display."""
        descriptions = {
            BootMode.DEFAULT: "Default Snapshot - Boot with last saved state",
            BootMode.COLD: "Cold Boot - Start without loading any snapshot",
            BootMode.SNAPSHOT: f"Specific Snapshot - Choose from {len(self.snapshots)} available",
            BootMode.WIPE: "Factory Reset - Wipe all data [red](irreversible!)[/red]",
        }
        return descriptions.get(mode, str(mode))

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Select Boot Mode", classes="modal-title")
            yield Label(
                f"[dim]Starting AVD: {self.avd_name}[/dim]",
                classes="modal-message",
            )

            options = [
                Option(self._format_boot_option(BootMode.DEFAULT), id="default"),
                Option(self._format_boot_option(BootMode.COLD), id="cold"),
            ]

            if self.snapshots:
                options.append(
                    Option(self._format_boot_option(BootMode.SNAPSHOT), id="snapshot")
                )

            options.append(Option(self._format_boot_option(BootMode.WIPE), id="wipe"))

            yield OptionList(*options, id="boot-options")

            with Horizontal(classes="button-row"):
                yield Button("Select", id="select-button", classes="-primary")
                yield Button("Cancel", id="cancel-button", classes="-secondary")

            yield KeyHintFooter()

    def on_mount(self) -> None:
        """Focus the option list on mount."""
        super().on_mount()
        try:
            option_list = self.query_one("#boot-options", OptionList)
            option_list.highlighted = 0
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        if event.button.id == "select-button":
            self._select_current()
        elif event.button.id == "cancel-button":
            self._dismiss_with_refresh(BootModeResult(cancelled=True))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle double-click or Enter on option."""
        self._select_current()

    def action_select(self) -> None:
        """Select the currently highlighted option."""
        self._select_current()

    def _select_current(self) -> None:
        """Select the current highlighted boot mode."""
        try:
            option_list = self.query_one("#boot-options", OptionList)
            if option_list.highlighted is not None:
                option = option_list.get_option_at_index(option_list.highlighted)

                try:
                    selected_mode = BootMode(option.id)
                except ValueError:
                    selected_mode = BootMode.DEFAULT

                if selected_mode == BootMode.SNAPSHOT:
                    # Show snapshot selection modal
                    self.app.push_screen(
                        SnapshotSelectionModal(self.snapshots),
                        self._on_snapshot_selected,
                    )
                elif selected_mode == BootMode.WIPE:
                    # Show wipe confirmation
                    from .confirm_modal import ConfirmModal

                    self.app.push_screen(
                        ConfirmModal(
                            title="Factory Reset",
                            message="This will [red]permanently delete all user data[/red] on this AVD.\n\nAre you sure you want to continue?",
                        ),
                        self._on_wipe_confirmed,
                    )
                else:
                    self._dismiss_with_refresh(BootModeResult(boot_mode=selected_mode))
        except Exception:
            self._dismiss_with_refresh(BootModeResult(cancelled=True))

    def _on_snapshot_selected(self, result: "SnapshotSelectionResult | None") -> None:
        """Handle snapshot selection result."""
        if result is None or result.cancelled:
            # User cancelled snapshot selection, stay on boot mode modal
            return
        self._dismiss_with_refresh(
            BootModeResult(
                boot_mode=BootMode.SNAPSHOT,
                snapshot_name=result.snapshot_name,
            )
        )

    def _on_wipe_confirmed(self, confirmed: bool) -> None:
        """Handle wipe confirmation result."""
        if confirmed:
            self._dismiss_with_refresh(BootModeResult(boot_mode=BootMode.WIPE))
        # If not confirmed, stay on boot mode modal

    def action_next(self) -> None:
        """Move to next option."""
        try:
            option_list = self.query_one("#boot-options", OptionList)
            option_list.action_cursor_down()
        except Exception:
            pass

    def action_prev(self) -> None:
        """Move to previous option."""
        try:
            option_list = self.query_one("#boot-options", OptionList)
            option_list.action_cursor_up()
        except Exception:
            pass


@dataclass
class SnapshotSelectionResult:
    """Result from snapshot selection modal."""

    snapshot_name: str | None = None
    cancelled: bool = False


class SnapshotSelectionModal(ForensicModal[SnapshotSelectionResult]):
    """Modal for selecting a specific snapshot to load."""

    DEFAULT_CSS = """
    SnapshotSelectionModal .modal-container {
        width: 70;
        max-height: 22;
    }

    SnapshotSelectionModal #snapshot-list {
        height: auto;
        max-height: 12;
        background: $surface;
        border: solid $panel;
        margin-bottom: 1;
    }

    SnapshotSelectionModal #snapshot-list:focus {
        border: solid $primary;
    }

    SnapshotSelectionModal #snapshot-list > .option-list--option-highlighted {
        background: $panel;
        color: #6ba3ff;
    }
    """

    BINDINGS = [
        Binding("enter", "select", "Select", priority=True),
        Binding("j", "next", "Next", show=False),
        Binding("k", "prev", "Previous", show=False),
        Binding("down", "next", "Next", show=False),
        Binding("up", "prev", "Previous", show=False),
    ]

    AUTO_FOCUS = "#snapshot-list"

    def __init__(
        self,
        snapshots: list[SnapshotInfo],
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """Initialize the snapshot selection modal.

        Args:
            snapshots: List of SnapshotInfo objects
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.snapshots = snapshots

    def _format_snapshot(self, snap: SnapshotInfo) -> str:
        """Format snapshot for display."""
        size_str = f"{snap.size_mb:.0f}MB" if snap.size_mb > 0 else "-"
        return f"{snap.name} ({size_str}, {snap.modified_date})"

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Select Snapshot", classes="modal-title")
            yield OptionList(
                *[Option(self._format_snapshot(s), id=s.name) for s in self.snapshots],
                id="snapshot-list",
            )
            with Horizontal(classes="button-row"):
                yield Button("Select", id="snapshot-select-button", classes="-primary")
                yield Button("Back", id="snapshot-back-button", classes="-secondary")
            yield KeyHintFooter(
                hints={
                    "list": "[dim]Enter=Select  Esc=Back[/dim]",
                    "button": "[dim]Enter=Select  Esc=Back[/dim]",
                }
            )

    def on_mount(self) -> None:
        """Focus the snapshot list on mount."""
        super().on_mount()
        try:
            option_list = self.query_one("#snapshot-list", OptionList)
            option_list.highlighted = 0
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        if event.button.id == "snapshot-select-button":
            self._select_current()
        elif event.button.id == "snapshot-back-button":
            self._dismiss_with_refresh(SnapshotSelectionResult(cancelled=True))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle double-click or Enter on option."""
        self._select_current()

    def action_select(self) -> None:
        """Select the currently highlighted snapshot."""
        self._select_current()

    def _select_current(self) -> None:
        """Select the current highlighted snapshot."""
        try:
            option_list = self.query_one("#snapshot-list", OptionList)
            if option_list.highlighted is not None and option_list.highlighted < len(
                self.snapshots
            ):
                snapshot = self.snapshots[option_list.highlighted]
                self._dismiss_with_refresh(
                    SnapshotSelectionResult(snapshot_name=snapshot.name)
                )
        except Exception:
            self._dismiss_with_refresh(SnapshotSelectionResult(cancelled=True))

    def action_next(self) -> None:
        """Move to next option."""
        try:
            self.query_one("#snapshot-list", OptionList).action_cursor_down()
        except NoMatches:
            pass

    def action_prev(self) -> None:
        """Move to previous option."""
        try:
            self.query_one("#snapshot-list", OptionList).action_cursor_up()
        except NoMatches:
            pass
