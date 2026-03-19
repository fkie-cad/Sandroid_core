"""AVD selection modal for starting Android Virtual Devices."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Checkbox, Label, OptionList
from textual.widgets.option_list import Option

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter

if TYPE_CHECKING:
    from textual.app import ComposeResult


@dataclass
class AVDInfo:
    """Information about an Android Virtual Device."""

    name: str
    android_version: str = "Unknown"
    api_level: str = "?"
    device_name: str = ""


@dataclass
class AVDSelectionResult:
    """Result from AVD selection modal."""

    selected_avd: str | None = None
    headless: bool = False
    save_as_default: bool = False
    boot_mode: str = "default"  # "default", "cold", "snapshot", "wipe"
    snapshot_name: str | None = None
    cancelled: bool = False


class AVDSelectionModal(ForensicModal[AVDSelectionResult]):
    """Modal for selecting and starting an Android Virtual Device.

    Features:
    - Shows list of available AVDs with Android version info
    - Option to start with or without UI (headless mode)
    - Option to save selection as default
    - Keyboard navigation (j/k or arrow keys)
    - Enter to select
    - Escape to cancel
    """

    DEFAULT_CSS = """
    AVDSelectionModal .modal-container {
        width: 70;
        max-height: 36;
        height: auto;
    }

    AVDSelectionModal .modal-message {
        margin-bottom: 1;
    }

    AVDSelectionModal #avd-list {
        height: auto;
        max-height: 12;
        background: $surface;
        border: solid $panel;
        margin-bottom: 1;
    }

    AVDSelectionModal #avd-list:focus {
        border: solid $primary;
    }

    AVDSelectionModal #avd-list > .option-list--option-highlighted {
        background: $panel;
        color: #6ba3ff;
    }

    AVDSelectionModal #avd-options {
        height: auto;
        margin: 1 0;
        padding: 0 1;
    }

    AVDSelectionModal #avd-options Checkbox {
        margin-right: 2;
    }

    AVDSelectionModal #no-avds-message {
        color: $warning;
        text-align: center;
        margin: 2 0;
        width: 100%;
    }
    """

    BINDINGS = [
        Binding("enter", "select", "Start AVD"),
        Binding("s", "select_boot_mode", "Boot Mode", show=False),
        Binding("j", "next", "Next", show=False),
        Binding("k", "prev", "Previous", show=False),
        Binding("down", "next", "Next", show=False),
        Binding("up", "prev", "Previous", show=False),
    ]

    AUTO_FOCUS = "#avd-list"

    def __init__(
        self,
        avds: list[AVDInfo],
        from_device_modal: bool = False,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the AVD selection modal.

        Args:
            avds: List of AVDInfo objects for available AVDs
            from_device_modal: True if opened from DeviceSelectionModal (affects Esc behavior)
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.avds = avds
        self.from_device_modal = from_device_modal
        self._headless = False
        self._save_default = False
        self._boot_mode = "default"
        self._snapshot_name: str | None = None

    def _format_avd(self, avd: AVDInfo) -> str:
        """Format AVD for display in the list.

        Args:
            avd: AVD info to format

        Returns:
            Formatted string like "Pixel_6_API_34 (Android 14, API 34)"
        """
        device_info = f" - {avd.device_name}" if avd.device_name else ""
        return f"{avd.name} (Android {avd.android_version}, API {avd.api_level}){device_info}"

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Start Android Virtual Device", classes="modal-title")
            yield Label(
                "[dim]No device connected - select an AVD to start[/dim]",
                classes="modal-message",
            )

            if not self.avds:
                yield Label(
                    "No AVDs found. Create one with Android Studio\n"
                    "or use: sandroid-config avd create",
                    id="no-avds-message",
                )
            else:
                yield OptionList(
                    *[Option(self._format_avd(avd), id=avd.name) for avd in self.avds],
                    id="avd-list",
                )

                with Vertical(id="avd-options"):
                    yield Checkbox(
                        "Start with UI (uncheck for headless)", value=True, id="with-ui"
                    )
                    yield Checkbox(
                        "Cold boot (ignore snapshots)", value=False, id="cold-boot"
                    )
                    yield Checkbox(
                        "Save as default AVD", value=False, id="save-default"
                    )

            yield KeyHintFooter(
                hints={
                    "list": "[dim]↑↓/j/k=Navigate  Enter=Start  Tab=Options  Esc=Back[/dim]",
                    "default": "[dim]Space=Toggle  Tab/Shift+Tab=Navigate  Esc=Back[/dim]",
                }
            )

    def on_mount(self) -> None:
        """Focus the option list on mount."""
        super().on_mount()
        if not self.avds:
            return

        try:
            option_list = self.query_one("#avd-list", OptionList)
            option_list.highlighted = 0
        except Exception:
            pass

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        """Handle checkbox changes."""
        if event.checkbox.id == "with-ui":
            self._headless = not event.value
        elif event.checkbox.id == "cold-boot":
            self._boot_mode = "cold" if event.value else "default"
        elif event.checkbox.id == "save-default":
            self._save_default = event.value

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle double-click or Enter on option."""
        self._select_current()

    def action_select(self) -> None:
        """Select the currently highlighted option."""
        self._select_current()

    def action_select_boot_mode(self) -> None:
        """Show boot mode selection for the highlighted AVD."""
        if not self.avds:
            return

        try:
            option_list = self.query_one("#avd-list", OptionList)
            if option_list.highlighted is not None and option_list.highlighted < len(
                self.avds
            ):
                selected = self.avds[option_list.highlighted]

                # Import here to avoid circular imports
                from sandroid.config.android_env import (
                    get_avd_snapshots_from_filesystem,
                )

                from .boot_mode_modal import BootModeSelectionModal, SnapshotInfo

                # Get snapshots for this AVD
                fs_snapshots = get_avd_snapshots_from_filesystem(selected.name)

                # Convert to TUI SnapshotInfo
                tui_snapshots = [
                    SnapshotInfo(
                        name=s.name,
                        path=s.path,
                        size_mb=s.size_mb,
                        modified_date=s.modified_date,
                    )
                    for s in fs_snapshots
                ]

                def on_boot_mode_selected(result):
                    if result is not None and not result.cancelled:
                        self._boot_mode = result.boot_mode.value
                        self._snapshot_name = result.snapshot_name
                        # Now start the AVD with selected boot mode
                        self.dismiss(
                            AVDSelectionResult(
                                selected_avd=selected.name,
                                headless=self._headless,
                                save_as_default=self._save_default,
                                boot_mode=self._boot_mode,
                                snapshot_name=self._snapshot_name,
                                cancelled=False,
                            )
                        )

                self.app.push_screen(
                    BootModeSelectionModal(selected.name, tui_snapshots),
                    on_boot_mode_selected,
                )
        except Exception:
            pass

    def _select_current(self) -> None:
        """Select the current highlighted AVD."""
        if not self.avds:
            self._dismiss_with_refresh(AVDSelectionResult(cancelled=True))
            return

        try:
            option_list = self.query_one("#avd-list", OptionList)
            if option_list.highlighted is not None and option_list.highlighted < len(
                self.avds
            ):
                selected = self.avds[option_list.highlighted]
                self._dismiss_with_refresh(
                    AVDSelectionResult(
                        selected_avd=selected.name,
                        headless=self._headless,
                        save_as_default=self._save_default,
                        boot_mode=self._boot_mode,
                        snapshot_name=self._snapshot_name,
                        cancelled=False,
                    )
                )
        except Exception:
            self._dismiss_with_refresh(AVDSelectionResult(cancelled=True))

    def action_next(self) -> None:
        """Move to next option."""
        try:
            option_list = self.query_one("#avd-list", OptionList)
            option_list.action_cursor_down()
        except Exception:
            pass

    def action_prev(self) -> None:
        """Move to previous option."""
        try:
            option_list = self.query_one("#avd-list", OptionList)
            option_list.action_cursor_up()
        except Exception:
            pass
