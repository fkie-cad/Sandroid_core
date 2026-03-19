"""Forensic APK management modal for viewing and installing pulled APKs."""

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Label, OptionList, Static
from textual.widgets.option_list import Option

from sandroid.core.toolbox import ForensicAPK, Toolbox
from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


@dataclass
class ForensicAPKAction:
    """Result from forensic APK modal.

    Attributes:
        action: What action to take - "close", "install", "delete"
        apk: The selected ForensicAPK (if action is install/delete)
    """

    action: str = "close"  # "close", "install", "delete"
    apk: ForensicAPK | None = None


class ForensicAPKModal(ForensicModal[ForensicAPKAction]):
    """Modal for managing forensic APKs.

    Features:
    - Lists all pulled APKs grouped by source device
    - Shows severity badge, package name, timestamp
    - Install to current device (with warning)
    - Delete from session
    - Keyboard navigation
    """

    BINDINGS = [
        Binding("q", "close", "Close", priority=True),
        Binding("i", "install", "Install", show=False),
        Binding("d", "delete", "Delete", show=False),
        Binding("down", "next", "Next", show=False),
        Binding("up", "prev", "Previous", show=False),
        Binding("enter", "install", "Install", priority=True),
    ]

    DEFAULT_CSS = """
    ForensicAPKModal .modal-container {
        width: 85;
        max-width: 95%;
        max-height: 85%;
        align: center middle;
    }

    ForensicAPKModal #forensic-apk-description {
        color: $foreground;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    ForensicAPKModal #apk-list-container {
        height: 15;
        width: 100%;
        background: $panel;
        border: solid $panel;
    }

    ForensicAPKModal #apk-list-container:focus-within {
        border: solid $primary;
    }

    ForensicAPKModal #apk-option-list {
        width: 100%;
        height: 100%;
        background: transparent;
    }

    ForensicAPKModal #apk-option-list > .option-list--option-highlighted {
        background: $surface;
        color: #6ba3ff;
    }

    ForensicAPKModal #selected-apk-info {
        padding: 1;
        height: auto;
        min-height: 4;
        border: solid $panel;
        margin-top: 1;
    }

    ForensicAPKModal #no-apks-message {
        color: $text-muted;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: 6;
        padding: 2;
    }

    ForensicAPKModal .button-row {
        margin-top: 1;
        align: center middle;
        width: 100%;
        height: 3;
    }

    ForensicAPKModal .hidden {
        display: none;
    }
    """

    def __init__(
        self,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the forensic APK modal."""
        super().__init__(name=name, id=id, classes=classes)
        self._apks = Toolbox.get_forensic_apks()
        self._selected_apk: ForensicAPK | None = None

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Forensic APK Manager", classes="modal-title")

            if self._apks:
                yield Label(
                    f"{len(self._apks)} forensic APKs pulled from devices. "
                    "Select one to install to the current device.",
                    id="forensic-apk-description",
                )

                with Vertical(id="apk-list-container"):
                    yield OptionList(
                        *self._build_options(),
                        id="apk-option-list",
                    )

                yield Static(
                    self._build_apk_info(None),
                    id="selected-apk-info",
                )

                with Horizontal(classes="button-row"):
                    yield Button(
                        "Install to Device", classes="-primary", id="btn-install"
                    )
                    yield Button("Delete", classes="-secondary", id="btn-delete")
                    yield Button("Close", classes="-secondary", id="btn-close")

                yield KeyHintFooter()
            else:
                yield Label(
                    "No forensic APKs have been pulled yet.\n\n"
                    "Run a forensic scan (Shift+F) and pull suspicious\n"
                    "APKs to see them here.",
                    id="no-apks-message",
                )

                with Horizontal(classes="button-row"):
                    yield Button("Close", classes="-secondary", id="btn-close")

                yield KeyHintFooter()

    def _build_options(self) -> list[Option]:
        """Build option list items for APKs.

        Returns:
            List of Option objects
        """
        options = []

        # Group by source device
        by_device: dict[str, list[ForensicAPK]] = defaultdict(list)
        for apk in self._apks:
            device_name = apk.source_device_name or apk.source_device
            by_device[device_name].append(apk)

        for device_name, apks in by_device.items():
            # Add device header
            options.append(Option(f"[bold cyan]── {device_name} ──[/bold cyan]"))

            for apk in apks:
                severity_badge = self._format_severity_badge(apk.severity)
                timestamp = apk.pull_timestamp.strftime("%H:%M:%S")
                display = f"  {severity_badge} {apk.package_name} [{timestamp}]"
                options.append(Option(display, id=apk.package_name))

        return options

    def _format_severity_badge(self, severity: str) -> str:
        """Format a severity badge with color.

        Args:
            severity: Severity level string

        Returns:
            Rich-formatted severity badge
        """
        badges = {
            "critical": "[bold #ff0000][CRIT][/bold #ff0000]",
            "high": "[bold #ff6600][HIGH][/bold #ff6600]",
            "medium": "[#ffcc00][MED][/#ffcc00]",
            "low": "[dim][LOW][/dim]",
        }
        return badges.get(severity.lower(), "[dim][???][/dim]")

    def _build_apk_info(self, apk: ForensicAPK | None) -> str:
        """Build info panel content for selected APK.

        Args:
            apk: Selected ForensicAPK or None

        Returns:
            Formatted info string
        """
        if not apk:
            return "[dim]Select an APK to see details[/dim]"

        lines = []
        lines.append(f"[bold]Package:[/bold] {apk.package_name}")
        lines.append(
            f"[bold]Source Device:[/bold] {apk.source_device_name or apk.source_device}"
        )
        lines.append(
            f"[bold]Severity:[/bold] {self._format_severity_badge(apk.severity)}"
        )
        lines.append(
            f"[bold]Pulled:[/bold] {apk.pull_timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        )

        if apk.local_path:
            path = Path(apk.local_path)
            if path.exists():
                size_mb = path.stat().st_size / (1024 * 1024)
                lines.append(f"[bold]Size:[/bold] {size_mb:.2f} MB")
            lines.append(f"[bold]Path:[/bold] [dim]{apk.local_path}[/dim]")

        if apk.file_hash:
            lines.append(f"[bold]MD5:[/bold] [dim]{apk.file_hash}[/dim]")

        if apk.ioc_matches:
            lines.append(f"[bold]IOC Matches:[/bold] {len(apk.ioc_matches)}")

        return "\n".join(lines)

    def _get_apk_by_package(self, package_name: str) -> ForensicAPK | None:
        """Get ForensicAPK by package name.

        Args:
            package_name: Package name to look up

        Returns:
            ForensicAPK or None
        """
        for apk in self._apks:
            if apk.package_name == package_name:
                return apk
        return None

    def on_mount(self) -> None:
        """Focus option list and select first APK."""
        if not self._apks:
            return

        try:
            option_list = self.query_one("#apk-option-list", OptionList)
            option_list.focus()

            # Find first actual APK option (skip device headers)
            for i, apk in enumerate(self._apks):
                # Headers don't have IDs, APKs do
                option_list.highlighted = i + 1  # +1 for first device header
                break

            self._update_selection()
        except Exception:
            pass

    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted
    ) -> None:
        """Handle option highlight change."""
        self._update_selection()

    def _update_selection(self) -> None:
        """Update selection info based on highlighted option."""
        try:
            option_list = self.query_one("#apk-option-list", OptionList)
            highlighted = option_list.highlighted

            if highlighted is None:
                return

            option = option_list.get_option_at_index(highlighted)
            if option and option.id:
                self._selected_apk = self._get_apk_by_package(option.id)
            else:
                self._selected_apk = None

            # Update info panel
            info_panel = self.query_one("#selected-apk-info", Static)
            info_panel.update(self._build_apk_info(self._selected_apk))

        except Exception:
            pass

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle double-click on option - install APK."""
        self._update_selection()
        if self._selected_apk:
            self.action_install()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-close":
            self.action_close()
        elif event.button.id == "btn-install":
            self.action_install()
        elif event.button.id == "btn-delete":
            self.action_delete()

    def action_close(self) -> None:
        """Close the modal."""
        self._dismiss_with_refresh(ForensicAPKAction(action="close"))

    def action_install(self) -> None:
        """Install selected APK to current device."""
        self._update_selection()
        if self._selected_apk:
            self._dismiss_with_refresh(
                ForensicAPKAction(action="install", apk=self._selected_apk)
            )

    def action_delete(self) -> None:
        """Delete selected APK from session."""
        self._update_selection()
        if self._selected_apk:
            self._dismiss_with_refresh(
                ForensicAPKAction(action="delete", apk=self._selected_apk)
            )

    def action_next(self) -> None:
        """Move to next option."""
        try:
            option_list = self.query_one("#apk-option-list", OptionList)
            option_list.action_cursor_down()
        except Exception:
            pass

    def action_prev(self) -> None:
        """Move to previous option."""
        try:
            option_list = self.query_one("#apk-option-list", OptionList)
            option_list.action_cursor_up()
        except Exception:
            pass
