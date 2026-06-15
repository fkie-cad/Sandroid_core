"""MVT Results modal for displaying forensic scan results."""

from dataclasses import dataclass, field

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Label, Static

from sandroid.core.forensic_evidence import (
    IOCMatch,
    MatchSeverity,
    ScanResult,
    extract_matched_packages,
)
from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


@dataclass
class MVTResultsAction:
    """Result from MVT results modal.

    Attributes:
        action: What action to take - "close", "pull_all", or "select"
        matched_packages: List of package names that had IOC matches
        matches_by_package: Dict mapping package name to list of IOCMatch objects
    """

    action: str = "close"  # "close", "pull_all", "select"
    matched_packages: list = field(default_factory=list)
    matches_by_package: dict = field(default_factory=dict)


class MVTResultsModal(ForensicModal[MVTResultsAction]):
    """Modal for displaying MVT forensic scan results.

    Features:
    - Shows summary of all scans
    - Lists matches by severity (critical first)
    - Color-coded severity indicators
    - Scrollable content for large result sets
    - Keyboard navigation
    - Pull suspicious APKs (p = Pull All, s = Select)
    """

    BINDINGS = [
        Binding("q", "close", "Close", priority=True),
        Binding("down", "scroll_down", "Down", show=False),
        Binding("up", "scroll_up", "Up", show=False),
        Binding("g", "scroll_top", "Top", show=False),
        Binding("G", "scroll_bottom", "Bottom", show=False),
        Binding("p", "pull_all", "Pull All APKs", show=False),
        Binding("s", "select_apks", "Select APKs", show=False),
    ]

    DEFAULT_CSS = """
    MVTResultsModal .modal-container {
        width: 90%;
        max-width: 100;
        height: 80%;
    }

    MVTResultsModal #mvt-summary {
        padding: 1;
        border: solid $primary-lighten-2;
        margin-bottom: 1;
    }

    MVTResultsModal #mvt-results-scroll {
        height: 1fr;
    }

    MVTResultsModal .match-critical {
        color: #ff0000;
        text-style: bold;
    }

    MVTResultsModal .match-high {
        color: #ff6600;
        text-style: bold;
    }

    MVTResultsModal .match-medium {
        color: #ffcc00;
    }

    MVTResultsModal .match-low {
        color: $text-muted;
    }

    MVTResultsModal .section-header {
        color: #6ba3ff;
        text-style: bold;
        padding-top: 1;
    }
    """

    def __init__(
        self,
        results: list[ScanResult],
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the MVT results modal.

        Args:
            results: List of ScanResult objects from forensic scan
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.results = results
        # Extract matched packages for APK pull actions
        self.matched_packages: list[str] = []
        self.matches_by_package: dict[str, list[IOCMatch]] = {}
        self._extract_matched_packages()

    def _extract_matched_packages(self) -> None:
        """Extract pullable package names from scan results that had IOC matches.

        Delegates to the shared core extractor so the modal and the Forensic
        panel agree — including packages detected only via an APK hash match.
        """
        self.matched_packages, self.matches_by_package = extract_matched_packages(
            self.results
        )

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Forensic Evidence Scan Results", classes="modal-title")
            yield Static(self._build_summary(), id="mvt-summary")

            with VerticalScroll(id="mvt-results-scroll"):
                yield Static(self._build_results_content(), id="mvt-results-content")

            yield KeyHintFooter()

    def _build_summary(self) -> str:
        """Build summary section content.

        Returns:
            Formatted summary string
        """
        total_scans = len(self.results)
        total_matches = sum(len(r.matches) for r in self.results)
        critical = sum(len(r.critical_matches) for r in self.results)
        high = sum(len(r.high_matches) for r in self.results)
        total_items = sum(r.scanned_items for r in self.results)
        total_duration = sum(r.scan_duration for r in self.results)
        total_errors = sum(len(r.errors) for r in self.results)

        lines = []
        lines.append("[bold]Scan Summary[/bold]")
        lines.append(f"  Scans completed: {total_scans}")
        lines.append(f"  Items scanned: {total_items}")
        lines.append(f"  Duration: {total_duration:.2f}s")
        lines.append("")

        if total_matches == 0:
            lines.append("[bold green]✓ No indicators of compromise found[/bold green]")
        else:
            lines.append(
                f"[bold red]⚠ {total_matches} potential IOC matches found:[/bold red]"
            )
            if critical > 0:
                lines.append(f"  [bold #ff0000]Critical: {critical}[/bold #ff0000]")
            if high > 0:
                lines.append(f"  [bold #ff6600]High: {high}[/bold #ff6600]")
            medium = total_matches - critical - high
            if medium > 0:
                lines.append(f"  [#ffcc00]Medium/Low: {medium}[/#ffcc00]")

        if total_errors > 0:
            lines.append(f"\n[yellow]Warnings: {total_errors} scan errors[/yellow]")

        return "\n".join(lines)

    def _build_results_content(self) -> str:
        """Build detailed results content.

        Returns:
            Formatted results string
        """
        lines = []

        # Collect all matches and sort by severity
        all_matches: list[tuple[IOCMatch, str]] = []
        for result in self.results:
            for match in result.matches:
                all_matches.append((match, result.scan_type.name))

        # Sort: critical first, then high, then others
        severity_order = {
            MatchSeverity.CRITICAL: 0,
            MatchSeverity.HIGH: 1,
            MatchSeverity.MEDIUM: 2,
            MatchSeverity.LOW: 3,
        }
        all_matches.sort(key=lambda x: severity_order.get(x[0].severity, 99))

        if all_matches:
            lines.append("[bold cyan]=== Detailed Matches ===[/bold cyan]")
            lines.append("")

            for match, scan_type in all_matches:
                severity_class = self._get_severity_style(match.severity)
                lines.append(
                    f"[{severity_class}][{match.severity.value.upper()}][/{severity_class}] "
                    f"[bold]{match.indicator_type}[/bold]"
                )
                lines.append(f"  Source: {match.source} ({scan_type})")
                lines.append(f"  Indicator: [cyan]{match.indicator_value}[/cyan]")
                lines.append(f"  Matched: {match.matched_data}")
                if match.description:
                    lines.append(f"  Description: [dim]{match.description}[/dim]")
                lines.append("")

        # Show scan details
        lines.append("[bold cyan]=== Scan Details ===[/bold cyan]")
        lines.append("")

        for result in self.results:
            status = "[green]✓[/green]" if not result.errors else "[yellow]![/yellow]"
            match_info = (
                f"[red]{len(result.matches)} matches[/red]"
                if result.matches
                else "[green]clean[/green]"
            )

            lines.append(
                f"{status} [bold]{result.scan_type.name}[/bold]: "
                f"{result.scanned_items} items, {match_info}, {result.scan_duration:.2f}s"
            )

            if result.errors:
                for error in result.errors:
                    lines.append(f"  [yellow]⚠ {error}[/yellow]")

        return "\n".join(lines)

    def _get_severity_style(self, severity: MatchSeverity) -> str:
        """Get Rich style for severity level.

        Args:
            severity: Match severity level

        Returns:
            Rich markup style string
        """
        styles = {
            MatchSeverity.CRITICAL: "bold #ff0000",
            MatchSeverity.HIGH: "bold #ff6600",
            MatchSeverity.MEDIUM: "#ffcc00",
            MatchSeverity.LOW: "dim",
        }
        return styles.get(severity, "")

    def on_mount(self) -> None:
        """Focus scroll container on mount."""
        try:
            scroll = self.query_one("#mvt-results-scroll", VerticalScroll)
            scroll.focus()
        except Exception:
            pass

    def action_close(self) -> None:
        """Close the modal."""
        self._dismiss_with_refresh(MVTResultsAction(action="close"))

    def _scroll_action(self, method_name: str, **kwargs) -> None:
        """Execute a scroll action on the results scroll container."""
        try:
            scroll = self.query_one("#mvt-results-scroll", VerticalScroll)
            getattr(scroll, method_name)(**kwargs)
        except Exception:
            pass

    def action_scroll_down(self) -> None:
        """Scroll down."""
        self._scroll_action("scroll_relative", y=1)

    def action_scroll_up(self) -> None:
        """Scroll up."""
        self._scroll_action("scroll_relative", y=-1)

    def action_scroll_top(self) -> None:
        """Scroll to top."""
        self._scroll_action("scroll_home")

    def action_scroll_bottom(self) -> None:
        """Scroll to bottom."""
        self._scroll_action("scroll_end")

    def _dismiss_with_apk_action(self, action: str) -> None:
        """Dismiss with an APK-related action, or close if no packages."""
        if self.matched_packages:
            self._dismiss_with_refresh(
                MVTResultsAction(
                    action=action,
                    matched_packages=self.matched_packages,
                    matches_by_package=self.matches_by_package,
                )
            )
        else:
            self._dismiss_with_refresh(MVTResultsAction(action="close"))

    def action_pull_all(self) -> None:
        """Pull all matched APKs from device."""
        self._dismiss_with_apk_action("pull_all")

    def action_select_apks(self) -> None:
        """Show APK selection modal for user to choose which to pull."""
        self._dismiss_with_apk_action("select")
