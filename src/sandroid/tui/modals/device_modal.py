"""Device selection modal for multi-device support."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Label, OptionList
from textual.widgets.option_list import Option

from sandroid.core.device import Device
from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


class DeviceSelectionModal(ForensicModal[str | None]):
    """Modal for selecting from connected devices.

    Features:
    - Shows device list with type indicators [E]/[P]
    - Marks current device with *
    - Shows device state (device, offline, unauthorized)
    - Keyboard navigation (j/k or arrow keys)
    - Enter to select
    - Escape to cancel
    - Returns device serial or None if cancelled
    """

    DEFAULT_CSS = """
    DeviceSelectionModal .modal-container {
        width: 70;
        max-width: 80%;
        max-height: 80%;
    }

    DeviceSelectionModal .modal-message {
        margin-bottom: 1;
    }

    DeviceSelectionModal #device-list {
        height: auto;
        max-height: 15;
        background: $surface;
        border: solid $panel;
        margin-bottom: 1;
    }

    DeviceSelectionModal #device-list:focus {
        border: solid $primary;
    }

    DeviceSelectionModal #device-list > .option-list--option-highlighted {
        background: $panel;
        color: #6ba3ff;
    }

    DeviceSelectionModal #no-devices-message {
        color: $error;
        text-align: center;
        margin: 2 0;
    }
    """

    BINDINGS = [
        Binding("enter", "select", "Select"),
        Binding("a", "start_avd", "a=Start AVD", show=True),
        Binding("s", "restart_boot_mode", "s=Restart", show=True),
        Binding("j", "next", "Next", show=False),
        Binding("k", "prev", "Previous", show=False),
        Binding("down", "next", "Next", show=False),
        Binding("up", "prev", "Previous", show=False),
    ]

    AUTO_FOCUS = "#device-list"

    def __init__(
        self,
        devices: list[Device],
        current_serial: str | None = None,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the device selection modal.

        Args:
            devices: List of Device objects to choose from
            current_serial: Serial of currently active device (will be marked)
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.devices = devices
        self.current_serial = current_serial

    def _format_device(self, device: Device) -> str:
        """Format device for display in the list.

        Args:
            device: Device to format

        Returns:
            Formatted string like "* [E] Pixel_6_Pro_API_31"
        """
        indicator = "* " if device.serial == self.current_serial else "  "
        # Escape brackets to prevent Rich markup interpretation
        type_tag = "\\[E]" if device.is_emulator else "\\[P]"
        state_tag = "" if device.state == "device" else f" ({device.state})"
        name = device.name or device.model or device.serial[:12]
        return f"{indicator}{type_tag} {name} ({device.serial}){state_tag}"

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Select Device", classes="modal-title")
            yield Label(
                "[dim]* = current, \\[E] = emulator, \\[P] = physical[/dim]",
                classes="modal-message",
            )

            if not self.devices:
                yield Label(
                    "[warning]No devices connected[/warning]",
                    id="no-devices-message",
                )
            else:
                yield OptionList(
                    *[
                        Option(self._format_device(d), id=d.serial)
                        for d in self.devices
                    ],
                    id="device-list",
                )

            yield KeyHintFooter(
                hints={
                    "list": "[dim]Enter=Select  a=Start AVD  s=Restart Mode  Esc=Cancel[/dim]",
                    "default": "[dim]Enter=Select  a=Start AVD  s=Restart Mode  Esc=Cancel[/dim]",
                }
            )

    def on_mount(self) -> None:
        """Focus and highlight current device on mount."""
        super().on_mount()
        if not self.devices:
            return

        try:
            option_list = self.query_one("#device-list", OptionList)

            # Find and highlight current device
            for idx, device in enumerate(self.devices):
                if device.serial == self.current_serial:
                    option_list.highlighted = idx
                    break
            else:
                option_list.highlighted = 0
        except Exception:
            pass

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle double-click or Enter on option."""
        self._select_current()

    def action_select(self) -> None:
        """Select the currently highlighted option."""
        self._select_current()

    def _select_current(self) -> None:
        """Select the current highlighted device."""
        if not self.devices:
            self._dismiss_with_refresh(None)
            return

        try:
            option_list = self.query_one("#device-list", OptionList)
            if option_list.highlighted is not None and option_list.highlighted < len(
                self.devices
            ):
                selected = self.devices[option_list.highlighted]

                # Don't switch if device is not ready
                if selected.state != "device":
                    return

                self._dismiss_with_refresh(selected.serial)
        except Exception:
            self._dismiss_with_refresh(None)

    def action_next(self) -> None:
        """Move to next option."""
        try:
            option_list = self.query_one("#device-list", OptionList)
            option_list.action_cursor_down()
        except Exception:
            pass

    def action_prev(self) -> None:
        """Move to previous option."""
        try:
            option_list = self.query_one("#device-list", OptionList)
            option_list.action_cursor_up()
        except Exception:
            pass

    def action_start_avd(self) -> None:
        """Open AVD selection modal to start a new AVD."""
        from sandroid.config.android_env import get_avd_info, list_available_avds

        from .avd_selection_modal import AVDInfo, AVDSelectionModal

        try:
            # Get available AVDs
            avds = list_available_avds()
            if not avds:
                # No AVDs available - show message
                from .message_modal import MessageModal

                self.app.push_screen(
                    MessageModal(
                        title="No AVDs Found",
                        message="No Android Virtual Devices found.\n\nCreate one with:\n  sandroid-config avd create\n\nOr use Android Studio.",
                        level="warning",
                    )
                )
                return

            # Convert to AVDInfo objects
            avd_infos = []
            for avd_name in avds:
                info = get_avd_info(avd_name)
                avd_infos.append(
                    AVDInfo(
                        name=avd_name,
                        android_version=info.get("android_version", "Unknown"),
                        api_level=info.get("api_level", "?"),
                        device_name=info.get("device_name", ""),
                    )
                )

            def on_avd_selected(result):
                if result is not None and not result.cancelled:
                    # Pass result to app for handling
                    # First dismiss this modal, then let app handle AVD start
                    self._dismiss_with_refresh(
                        f"__start_avd__{result.selected_avd}__{result.boot_mode}__{result.snapshot_name or ''}"
                    )

            self.app.push_screen(
                AVDSelectionModal(avd_infos, from_device_modal=True),
                on_avd_selected,
            )
        except Exception:
            pass

    def action_restart_boot_mode(self) -> None:
        """Restart the selected emulator with a specific boot mode."""
        if not self.devices:
            return

        try:
            option_list = self.query_one("#device-list", OptionList)
            if option_list.highlighted is not None and option_list.highlighted < len(
                self.devices
            ):
                selected = self.devices[option_list.highlighted]

                # Only works for emulators
                if not selected.is_emulator:
                    from .message_modal import MessageModal

                    self.app.push_screen(
                        MessageModal(
                            title="Not an Emulator",
                            message="Boot mode selection is only available for emulators.\n\nPhysical devices don't support this feature.",
                            level="info",
                        )
                    )
                    return

                # Get the AVD name from the device
                avd_name = selected.name or selected.model or "Unknown"

                from sandroid.config.android_env import (
                    get_avd_snapshots_from_filesystem,
                )

                from .boot_mode_modal import BootModeSelectionModal, SnapshotInfo

                # Get snapshots for this AVD
                fs_snapshots = get_avd_snapshots_from_filesystem(avd_name)

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
                        # Signal app to restart emulator with this boot mode
                        self._dismiss_with_refresh(
                            f"__restart_emulator__{selected.serial}__{result.boot_mode.value}__{result.snapshot_name or ''}"
                        )

                self.app.push_screen(
                    BootModeSelectionModal(avd_name, tui_snapshots),
                    on_boot_mode_selected,
                )
        except Exception:
            pass
