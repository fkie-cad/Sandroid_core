"""APK Selection modal for choosing which suspicious APKs to pull."""

from dataclasses import dataclass, field

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Checkbox, Label

from sandroid.core.forensic_evidence import IOCMatch, MatchSeverity
from sandroid.tui.modals.base import ExtractionModal, KeyHintFooter


@dataclass
class APKSelectionResult:
    """Result from APK selection modal.

    Attributes:
        cancelled: True if user cancelled selection
        selected_packages: List of selected package names
        matches_by_package: Dict mapping package name to IOCMatch objects
    """

    cancelled: bool = True
    selected_packages: list = field(default_factory=list)
    matches_by_package: dict = field(default_factory=dict)


class APKSelectionModal(ExtractionModal[APKSelectionResult]):
    """Modal for selecting which suspicious APKs to pull from device.

    Features:
    - Checkboxes for each matched package
    - Shows severity indicator per package
    - Select all / deselect all buttons
    - Keyboard navigation with space to toggle
    - Enter to confirm, Escape to cancel
    """

    BINDINGS = [
        Binding("enter", "confirm", "Confirm", priority=True),
        Binding("a", "select_all", "Select All", show=False),
        Binding("n", "select_none", "Select None", show=False),
        Binding("j", "next", "Next", show=False),
        Binding("k", "prev", "Previous", show=False),
        Binding("down", "next", "Next", show=False),
        Binding("up", "prev", "Previous", show=False),
    ]

    DEFAULT_CSS = """
    APKSelectionModal .modal-container {
        width: 80;
        max-width: 90%;
        max-height: 80%;
    }

    APKSelectionModal #apk-selection-description {
        color: $foreground;
        text-align: center;
        content-align: center middle;
        width: 100%;
        height: auto;
        padding-bottom: 1;
    }

    APKSelectionModal #apk-list-scroll {
        height: 12;
        width: 100%;
        background: $panel;
        border: solid $foreground-muted;
        padding: 0 1;
    }

    APKSelectionModal #apk-list-scroll:focus-within {
        border: solid $accent;
    }

    APKSelectionModal .package-row {
        width: 100%;
        height: auto;
        padding: 0;
    }

    APKSelectionModal .package-checkbox {
        width: auto;
    }

    APKSelectionModal .package-checkbox:focus {
        text-style: bold;
    }

    APKSelectionModal .severity-critical {
        color: #ff0000;
        text-style: bold;
    }

    APKSelectionModal .severity-high {
        color: #ff6600;
        text-style: bold;
    }

    APKSelectionModal .severity-medium {
        color: #ffcc00;
    }

    APKSelectionModal .severity-low {
        color: $foreground-muted;
    }

    APKSelectionModal #selection-count {
        color: $foreground-muted;
        text-align: center;
        width: 100%;
        height: 1;
        padding-top: 1;
    }

    APKSelectionModal #btn-select-all {
        background: $success;
        color: #ffffff;
    }

    APKSelectionModal #btn-select-all:hover {
        background: $success-darken-1;
    }
    """

    def __init__(
        self,
        packages: list[str],
        matches_by_package: dict[str, list[IOCMatch]],
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the APK selection modal.

        Args:
            packages: List of package names to choose from
            matches_by_package: Dict mapping package name to IOCMatch objects
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.packages = packages
        self.matches_by_package = matches_by_package
        self._checkboxes: dict[str, Checkbox] = {}

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Select APKs to Pull", classes="modal-title")
            yield Label(
                f"{len(self.packages)} suspicious packages detected. "
                "Select which APKs to download from the device.",
                id="apk-selection-description",
            )

            with VerticalScroll(id="apk-list-scroll"):
                for pkg in self.packages:
                    severity = self._get_package_severity(pkg)
                    severity_badge = self._format_severity_badge(severity)
                    with Horizontal(classes="package-row"):
                        cb = Checkbox(
                            f"{severity_badge} {pkg}",
                            value=True,  # Default to selected
                            id=f"pkg-{pkg.replace('.', '-')}",
                            classes="package-checkbox",
                        )
                        self._checkboxes[pkg] = cb
                        yield cb

            yield Label("0 selected", id="selection-count")

            with Horizontal(classes="button-row"):
                yield Button("Pull Selected", id="btn-confirm", classes="-primary")
                yield Button("Select All", id="btn-select-all")
                yield Button("Cancel", id="btn-cancel", classes="-secondary")

            yield KeyHintFooter(
                hints={
                    "default": "[dim]Space=Toggle  a=All  n=None  Enter=Confirm  Esc=Cancel[/dim]",
                }
            )

    _SEVERITY_ORDER = {
        MatchSeverity.CRITICAL: 0,
        MatchSeverity.HIGH: 1,
        MatchSeverity.MEDIUM: 2,
        MatchSeverity.LOW: 3,
    }

    def _get_package_severity(self, pkg: str) -> MatchSeverity:
        """Get the highest severity for a package."""
        matches = self.matches_by_package.get(pkg, [])
        if not matches:
            return MatchSeverity.MEDIUM

        return min(
            (m.severity for m in matches),
            key=lambda s: self._SEVERITY_ORDER.get(s, 99),
        )

    def _format_severity_badge(self, severity: MatchSeverity) -> str:
        """Format a severity badge with color.

        Args:
            severity: Severity level

        Returns:
            Rich-formatted severity badge
        """
        badges = {
            MatchSeverity.CRITICAL: "[bold #ff0000][CRIT][/bold #ff0000]",
            MatchSeverity.HIGH: "[bold #ff6600][HIGH][/bold #ff6600]",
            MatchSeverity.MEDIUM: "[#ffcc00][MED][/#ffcc00]",
            MatchSeverity.LOW: "[dim][LOW][/dim]",
        }
        return badges.get(severity, "[dim][???][/dim]")

    def on_mount(self) -> None:
        """Update selection count and focus first checkbox."""
        super().on_mount()
        self._update_selection_count()
        # Focus first checkbox
        if self._checkboxes:
            first_cb = list(self._checkboxes.values())[0]
            first_cb.focus()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        """Update selection count when checkbox changes."""
        self._update_selection_count()

    def _update_selection_count(self) -> None:
        """Update the selection count label."""
        try:
            count = sum(1 for cb in self._checkboxes.values() if cb.value)
            label = self.query_one("#selection-count", Label)
            label.update(f"{count} of {len(self.packages)} selected")
        except Exception:
            pass

    def _get_selected_packages(self) -> list[str]:
        """Get list of selected package names.

        Returns:
            List of selected package names
        """
        return [pkg for pkg, cb in self._checkboxes.items() if cb.value]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-cancel":
            self._cancel()
        elif event.button.id == "btn-confirm":
            self._confirm()
        elif event.button.id == "btn-select-all":
            self.action_select_all()

    def action_confirm(self) -> None:
        """Confirm selection."""
        self._confirm()

    def action_select_all(self) -> None:
        """Select all packages."""
        for cb in self._checkboxes.values():
            cb.value = True
        self._update_selection_count()

    def action_select_none(self) -> None:
        """Deselect all packages."""
        for cb in self._checkboxes.values():
            cb.value = False
        self._update_selection_count()

    def _focus_checkbox_offset(self, offset: int) -> None:
        """Focus a checkbox at the given offset from the current one."""
        checkboxes = list(self._checkboxes.values())
        if not checkboxes:
            return
        try:
            focused = self.focused
            if focused in checkboxes:
                idx = (checkboxes.index(focused) + offset) % len(checkboxes)
            else:
                idx = 0 if offset > 0 else -1
            checkboxes[idx].focus()
        except Exception:
            pass

    def action_next(self) -> None:
        self._focus_checkbox_offset(1)

    def action_prev(self) -> None:
        self._focus_checkbox_offset(-1)

    def _cancel(self) -> None:
        """Cancel and dismiss."""
        self._dismiss_with_refresh(APKSelectionResult(cancelled=True))

    def _confirm(self) -> None:
        """Confirm selection and dismiss."""
        selected = self._get_selected_packages()
        if not selected:
            # Nothing selected, treat as cancel
            self._cancel()
            return

        # Filter matches_by_package to only selected
        selected_matches = {
            pkg: matches
            for pkg, matches in self.matches_by_package.items()
            if pkg in selected
        }

        self._dismiss_with_refresh(
            APKSelectionResult(
                cancelled=False,
                selected_packages=selected,
                matches_by_package=selected_matches,
            )
        )
