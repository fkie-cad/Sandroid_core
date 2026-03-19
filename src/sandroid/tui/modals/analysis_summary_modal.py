"""Analysis summary modal for displaying playback results.

Shows a scrollable summary of analysis results with color-coded
sections for changed, new, and deleted files.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Label, Static

from sandroid.tui.modals.base import ForensicModal, KeyHintFooter


@dataclass
class AnalysisSummaryResult:
    """Result from analysis summary modal.

    Attributes:
        action: What action to take - "close" or "exported"
        export_path: Path to exported JSON file (if exported)
    """

    action: str = "close"  # "close", "exported"
    export_path: str = ""


@dataclass
class AnalysisData:
    """Data structure for analysis results.

    Attributes:
        changed_files: List of file paths that were modified
        new_files: List of file paths that were created
        deleted_files: List of file paths that were deleted
        duration: Duration of the analysis in seconds
        metadata: Additional metadata about the analysis
    """

    changed_files: list[str] = field(default_factory=list)
    new_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    duration: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


class AnalysisSummaryModal(ForensicModal[AnalysisSummaryResult]):
    """Modal for displaying playback analysis summary.

    Features:
    - Scrollable content for large result sets
    - Color-coded sections (yellow=changed, green=new, red=deleted)
    - Vim-style keyboard navigation
    - Export option
    - Duration and metadata display
    """

    BINDINGS = [
        Binding("q", "close", "Close", priority=True),
        Binding("down", "scroll_down", "Down", show=False),
        Binding("up", "scroll_up", "Up", show=False),
        Binding("g", "scroll_top", "Top", show=False),
        Binding("G", "scroll_bottom", "Bottom", show=False),
        Binding("x", "export", "Export"),
    ]

    DEFAULT_CSS = """
    AnalysisSummaryModal .modal-container {
        width: 90%;
        max-width: 100;
        height: 80%;
    }

    AnalysisSummaryModal #summary-stats {
        padding: 1;
        border: solid $panel;
        margin-bottom: 1;
        height: auto;
    }

    AnalysisSummaryModal #summary-scroll {
        height: 1fr;
    }

    AnalysisSummaryModal #summary-content {
        width: 100%;
        height: auto;
    }

    AnalysisSummaryModal .section-header {
        color: #6ba3ff;
        text-style: bold;
        padding-top: 1;
    }

    AnalysisSummaryModal .file-changed {
        color: #facc15;
    }

    AnalysisSummaryModal .file-new {
        color: #22c55e;
    }

    AnalysisSummaryModal .file-deleted {
        color: #ef4444;
    }

    AnalysisSummaryModal #export-status {
        color: $success;
        text-align: center;
        width: 100%;
        height: 1;
        margin-top: 1;
    }
    """

    def __init__(
        self,
        data: AnalysisData,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the analysis summary modal.

        Args:
            data: AnalysisData containing analysis results
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.data = data

    @classmethod
    def from_lists(
        cls,
        changed_files: list[str] = None,
        new_files: list[str] = None,
        deleted_files: list[str] = None,
        duration: int = 0,
        metadata: dict[str, Any] = None,
        **kwargs,
    ) -> "AnalysisSummaryModal":
        """Create modal from individual lists.

        Args:
            changed_files: List of changed file paths
            new_files: List of new file paths
            deleted_files: List of deleted file paths
            duration: Analysis duration in seconds
            metadata: Additional metadata
            **kwargs: Additional arguments for ModalScreen

        Returns:
            AnalysisSummaryModal instance
        """
        data = AnalysisData(
            changed_files=changed_files or [],
            new_files=new_files or [],
            deleted_files=deleted_files or [],
            duration=duration,
            metadata=metadata or {},
        )
        return cls(data=data, **kwargs)

    def compose(self) -> ComposeResult:
        """Create the modal layout."""
        with Vertical(classes="modal-container"):
            yield Label("Analysis Summary", classes="modal-title")
            yield Static(self._build_stats(), id="summary-stats")

            with VerticalScroll(id="summary-scroll"):
                yield Static(self._build_content(), id="summary-content")

            yield Static("", id="export-status")
            yield KeyHintFooter(
                hints={
                    "default": "[dim]Esc=Cancel  q=Close  x=Export JSON  j/k=Scroll[/dim]",
                }
            )

    def _build_stats(self) -> str:
        """Build statistics section.

        Returns:
            Formatted statistics string
        """
        lines = []
        lines.append("[bold]Analysis Statistics[/bold]")

        # Duration
        mins, secs = divmod(self.data.duration, 60)
        lines.append(f"  Duration: {mins:02d}:{secs:02d}")

        # File counts
        total = (
            len(self.data.changed_files)
            + len(self.data.new_files)
            + len(self.data.deleted_files)
        )
        lines.append(f"  Total changes: {total} files")
        lines.append("")

        # Summary by type
        if total == 0:
            lines.append("[bold green]✓ No file system changes detected[/bold green]")
        else:
            if self.data.changed_files:
                lines.append(
                    f"  [#facc15]● Modified: {len(self.data.changed_files)} files[/#facc15]"
                )
            if self.data.new_files:
                lines.append(
                    f"  [#22c55e]● Created: {len(self.data.new_files)} files[/#22c55e]"
                )
            if self.data.deleted_files:
                lines.append(
                    f"  [#ef4444]● Deleted: {len(self.data.deleted_files)} files[/#ef4444]"
                )

        # Add metadata if present
        if self.data.metadata:
            if "snapshot" in self.data.metadata:
                lines.append(f"\n  Snapshot: {self.data.metadata['snapshot']}")
            if "runs" in self.data.metadata:
                lines.append(f"  Analysis runs: {self.data.metadata['runs']}")

        return "\n".join(lines)

    def _build_content(self) -> str:
        """Build detailed results content.

        Returns:
            Formatted results string
        """
        sections = [
            ("Changed Files", "#facc15", self.data.changed_files),
            ("New Files", "#22c55e", self.data.new_files),
            ("Deleted Files", "#ef4444", self.data.deleted_files),
        ]

        lines = []
        for title, color, files in sections:
            lines.append(f"[bold {color}]=== {title} ===[/bold {color}]")
            if files:
                for f in files:
                    lines.append(f"  [{color}]{f}[/{color}]")
            else:
                lines.append("  [dim](none)[/dim]")
            lines.append("")

        return "\n".join(lines)

    def on_mount(self) -> None:
        """Focus scroll container on mount."""
        try:
            scroll = self.query_one("#summary-scroll", VerticalScroll)
            scroll.focus()
        except Exception:
            pass

    def action_close(self) -> None:
        """Close the modal."""
        self._dismiss_with_refresh(AnalysisSummaryResult(action="close"))

    def action_export(self) -> None:
        """Export analysis results to JSON file."""
        try:
            export_path = self._export_to_json()
            # Update status to show success
            try:
                status = self.query_one("#export-status", Static)
                status.update(
                    f"[green]✓ Exported to: {os.path.basename(export_path)}[/green]"
                )
            except Exception:
                pass
            # Dismiss with export path after a brief moment
            self.set_timer(
                1.5,
                lambda: self._dismiss_with_refresh(
                    AnalysisSummaryResult(action="exported", export_path=export_path)
                ),
            )
        except Exception as e:
            try:
                status = self.query_one("#export-status", Static)
                status.update(f"[red]Export failed: {e}[/red]")
            except Exception:
                pass

    def _export_to_json(self) -> str:
        """Export analysis data to JSON file.

        Returns:
            Path to the exported JSON file.
        """
        # Get results path
        results_path = os.getenv("RESULTS_PATH", "")
        if not results_path:
            raw_path = os.getenv("RAW_RESULTS_PATH", "")
            if raw_path:
                results_path = os.path.dirname(raw_path.rstrip("/"))
        if not results_path:
            results_path = os.getcwd()

        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"analysis_results_{timestamp}.json"
        export_path = os.path.join(results_path, filename)

        # Build export data
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "analysis_duration_seconds": self.data.duration,
            "summary": {
                "total_changes": (
                    len(self.data.changed_files)
                    + len(self.data.new_files)
                    + len(self.data.deleted_files)
                ),
                "modified_count": len(self.data.changed_files),
                "created_count": len(self.data.new_files),
                "deleted_count": len(self.data.deleted_files),
            },
            "changed_files": self.data.changed_files,
            "new_files": self.data.new_files,
            "deleted_files": self.data.deleted_files,
            "metadata": self.data.metadata,
        }

        # Ensure directory exists
        os.makedirs(
            os.path.dirname(export_path) if os.path.dirname(export_path) else ".",
            exist_ok=True,
        )

        # Write JSON
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, default=str)

        return export_path

    def _scroll_action(self, method_name: str, **kwargs) -> None:
        """Execute a scroll action on the summary scroll container."""
        try:
            scroll = self.query_one("#summary-scroll", VerticalScroll)
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
