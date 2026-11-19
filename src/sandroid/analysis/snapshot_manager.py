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
    the user to revert when analysis stops. Only active when the analysis
    spawns the app, with an interactive TTY session.

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

    @staticmethod
    def _tui_active() -> bool:
        """True when a TUI owns the terminal (questions must go to a modal).

        ``click.getchar()`` on a TUI worker thread competes with Textual for
        stdin: the TUI dexray start sat idle for minutes until a keypress
        happened to reach it (P2-H6).
        """
        try:
            from sandroid.core.ui_request_bus import UIRequestBus

            return UIRequestBus.get().has_active_handler()
        except Exception:
            return False

    @staticmethod
    def _is_emulator(toolbox) -> bool:
        """Snapshots only exist on emulators; assume yes if unknown."""
        check = getattr(toolbox, "is_emulator_device", None)
        if not callable(check):
            return True
        try:
            return bool(check())
        except Exception:
            return True

    def discard_snapshot(self, toolbox) -> bool:
        """Delete the temporary pre-analysis snapshot (if one was created).

        Called after the revert question on stop, and when the analysis
        failed to start, so no ``sandroid_malware_*`` snapshot is left on the
        AVD. Never raises.

        Returns:
            True if a snapshot was deleted.
        """
        name = self.snapshot_name
        self.snapshot_name = None
        self.should_revert_snapshot = False
        if not name:
            return False
        label = name.decode() if isinstance(name, bytes) else str(name)
        try:
            ok = toolbox.delete_snapshot(name)
        except Exception as e:
            logger.warning(f"Could not delete temporary snapshot {label}: {e}")
            return False
        if ok is False:
            logger.warning(f"Could not delete temporary snapshot {label}")
            return False
        logger.info(f"Deleted temporary snapshot: {label}")
        return True

    def create_pre_analysis_snapshot(
        self,
        toolbox,
        prefix: str = "sandroid_malware",
        *,
        will_spawn: bool = False,
    ) -> None:
        """Prompt the user to create a snapshot before analysis (spawns only).

        This ensures a clean state to revert to after analysis.

        Args:
            toolbox: The Toolbox instance for snapshot operations.
            prefix: Prefix for the snapshot name. Defaults to "sandroid_malware".
            will_spawn: This start spawns (or restarts) the app; attaching to
                a running app never asks.
        """
        if not (will_spawn and self._is_interactive()):
            return
        if not self._is_emulator(toolbox):
            return

        if self._tui_active():
            from sandroid.core.ui_request_bus import request_confirm

            create = request_confirm(
                "Snapshot before analysis?",
                "Save the current AVD state before spawning the app, so you "
                "can revert to it when the analysis stops. The snapshot is "
                "temporary and deleted afterwards.",
            )
            if create:
                self._save_snapshot(toolbox, prefix)
            else:
                logger.info("User declined snapshot creation")
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
            console.print("\n[primary]Creating snapshot...[/primary]")
            if self._save_snapshot(toolbox, prefix):
                console.print(
                    "[success]\u2713 Snapshot created successfully[/success]\n"
                )
            else:
                console.print("[warning]Snapshot could not be created[/warning]\n")
        else:
            console.print("\n[warning]Skipping snapshot creation[/warning]\n")
            logger.info("User declined snapshot creation")

    def _save_snapshot(self, toolbox, prefix: str) -> bool:
        """Save ``<prefix>_<timestamp>``; remember it only if the save worked."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"{prefix}_{timestamp}"
        try:
            ok = toolbox.create_snapshot(name.encode())
        except Exception as e:
            logger.warning(f"Snapshot {name} could not be created: {e}")
            return False
        if ok is False:
            logger.warning(f"Snapshot {name} could not be created")
            return False
        self.snapshot_name = name.encode()
        self.should_revert_snapshot = True
        logger.info(f"Created snapshot: {name}")
        return True

    def prompt_snapshot_revert(self, toolbox) -> None:
        """Prompt the user to revert to the pre-analysis snapshot if one was created.

        Args:
            toolbox: The Toolbox instance for snapshot operations.
        """
        if not (self.snapshot_name and self.should_revert_snapshot):
            return

        if self._tui_active():
            from sandroid.core.ui_request_bus import request_confirm

            label = self.snapshot_name.decode()
            if request_confirm(
                "Revert to pre-analysis snapshot?",
                f"Restore the AVD to '{label}' (the state before the analysis)? "
                "All changes made during the analysis will be lost.",
            ):
                if toolbox.load_snapshot(self.snapshot_name) is False:
                    logger.warning(f"Could not revert to snapshot {label}")
                else:
                    logger.info(f"Reverted to snapshot: {label}")
            else:
                logger.info("User declined snapshot revert")
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
