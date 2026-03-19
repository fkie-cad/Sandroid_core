"""Snapshot management for analysis modules.

Provides pre-analysis snapshot creation and post-analysis revert prompts,
extracted from MalwareMonitor to enable reuse across analysis tools.
"""

import logging
import sys
from datetime import datetime

logger = logging.getLogger(__name__)

# Box-drawing character constants for console UI
_HORIZ = "\u2550"  # ═
_TOP_LEFT = "\u2554"  # ╔
_TOP_RIGHT = "\u2557"  # ╗
_MID_LEFT = "\u2560"  # ╠
_MID_RIGHT = "\u2563"  # ╣
_BOT_LEFT = "\u255a"  # ╚
_BOT_RIGHT = "\u255d"  # ╝
_BOX_WIDTH = 76
_HORIZ_LINE = _HORIZ * _BOX_WIDTH


class SnapshotManager:
    """Manages AVD snapshots around analysis sessions.

    Handles creating a snapshot before analysis begins and prompting
    the user to revert when analysis stops. Only active in SPAWN mode
    with an interactive TTY session.

    Attributes:
        snapshot_name: The name of the created snapshot (bytes), or None.
        should_revert_snapshot: Whether to prompt for revert on stop.
    """

    def __init__(self):
        self.snapshot_name: bytes | None = None
        self.should_revert_snapshot: bool = False

    def _is_interactive(self) -> bool:
        """Check if the current session is interactive (TTY)."""
        return sys.stdin.isatty() and sys.stdout.isatty()

    def create_pre_analysis_snapshot(
        self, toolbox, prefix: str = "sandroid_malware"
    ) -> None:
        """Prompt the user to create a snapshot before analysis (SPAWN mode only).

        This ensures a clean state to revert to after analysis.

        Args:
            toolbox: The Toolbox instance for snapshot operations.
            prefix: Prefix for the snapshot name. Defaults to "sandroid_malware".
        """
        if not (toolbox.is_spawn_mode() and self._is_interactive()):
            return

        import click

        from sandroid.core.console import SandroidConsole
        from sandroid.tui.utils.box_renderer import box_line as _box_line

        console = SandroidConsole.get()
        console.print(f"\n[primary]{_TOP_LEFT}{_HORIZ_LINE}{_TOP_RIGHT}[/primary]")
        console.print(_box_line("[bold]Snapshot Management[/bold]"))
        console.print(
            _box_line(
                "[accent]Create snapshot before analysis? (Allows revert after)[/accent]"
            )
        )
        console.print(f"[primary]{_MID_LEFT}{_HORIZ_LINE}{_MID_RIGHT}[/primary]")
        console.print(
            _box_line(
                "This will save the current AVD state before spawning the app.",
                align="left",
            )
        )
        console.print(
            _box_line(
                "You can revert to this state when stopping the analysis.",
                align="left",
            )
        )
        console.print(f"[primary]{_MID_LEFT}{_HORIZ_LINE}{_MID_RIGHT}[/primary]")
        console.print(
            _box_line(
                "[success]\\[Y][/success] Yes (recommended)  [error]\\[N][/error] No",
                align="left",
            )
        )
        console.print(f"[primary]{_BOT_LEFT}{_HORIZ_LINE}{_BOT_RIGHT}[/primary]")

        console.print(
            "\n[primary]Create snapshot? [[success]Y[/success]/[error]n[/error]]:[/primary] ",
            end="",
        )
        choice = click.getchar().lower()
        console.print(f"[accent]{choice}[/accent]")

        if choice != "n":  # Default to yes (Enter, y, or any other key)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.snapshot_name = f"{prefix}_{timestamp}".encode()

            console.print(
                f"\n[primary]Creating snapshot: [accent]{self.snapshot_name.decode()}[/accent][/primary]"
            )
            toolbox.create_snapshot(self.snapshot_name)
            self.should_revert_snapshot = True
            console.print("[success]\u2713 Snapshot created successfully[/success]\n")
            logger.info(f"Created snapshot: {self.snapshot_name.decode()}")
        else:
            console.print("\n[warning]Skipping snapshot creation[/warning]\n")
            logger.info("User declined snapshot creation")

    def prompt_snapshot_revert(self, toolbox) -> None:
        """Prompt the user to revert to the pre-analysis snapshot if one was created.

        Args:
            toolbox: The Toolbox instance for snapshot operations.
        """
        if not (self.snapshot_name and self.should_revert_snapshot):
            return

        if not self._is_interactive():
            return

        import click

        from sandroid.core.console import SandroidConsole
        from sandroid.tui.utils.box_renderer import box_line as _box_line

        console = SandroidConsole.get()
        console.print(f"\n[primary]{_TOP_LEFT}{_HORIZ_LINE}{_TOP_RIGHT}[/primary]")
        console.print(_box_line("[bold]Snapshot Revert[/bold]"))
        console.print(
            _box_line(
                f"[accent]Revert to snapshot: {self.snapshot_name.decode()}?[/accent]"
            )
        )
        console.print(f"[primary]{_MID_LEFT}{_HORIZ_LINE}{_MID_RIGHT}[/primary]")
        console.print(
            _box_line(
                "This will restore the AVD to the state before analysis.",
                align="left",
            )
        )
        console.print(
            _box_line(
                "All changes made during analysis will be lost.",
                align="left",
            )
        )
        console.print(f"[primary]{_MID_LEFT}{_HORIZ_LINE}{_MID_RIGHT}[/primary]")
        console.print(
            _box_line(
                "[success]\\[Y][/success] Yes (recommended)  "
                "[error]\\[N][/error] No (keep changes)",
                align="left",
            )
        )
        console.print(f"[primary]{_BOT_LEFT}{_HORIZ_LINE}{_BOT_RIGHT}[/primary]")

        console.print(
            "\n[primary]Revert to snapshot? [[success]Y[/success]/[error]n[/error]]:[/primary] ",
            end="",
        )
        choice = click.getchar().lower()
        console.print(f"[accent]{choice}[/accent]")

        if choice != "n":  # Default to yes
            console.print(
                f"\n[primary]Reverting to snapshot: [accent]{self.snapshot_name.decode()}[/accent][/primary]"
            )
            toolbox.load_snapshot(self.snapshot_name)
            console.print("[success]\u2713 Snapshot restored successfully[/success]\n")
            logger.info(f"Reverted to snapshot: {self.snapshot_name.decode()}")
        else:
            console.print("\n[warning]Keeping current AVD state[/warning]\n")
            logger.info("User declined snapshot revert")
