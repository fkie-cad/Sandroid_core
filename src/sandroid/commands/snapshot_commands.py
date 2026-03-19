"""Snapshot commands for emulator state management.

This module provides commands for creating and loading emulator snapshots,
migrated from actionQ.py parse_interactive_char() method.
"""

import logging
from datetime import datetime

from .base import CommandCategory, CommandContext, CommandHandler, CommandResult

logger = logging.getLogger(__name__)


class SnapshotListCommand(CommandHandler):
    """Command handler for listing and loading emulator snapshots.

    Displays available snapshots and allows the user to select one to load.
    In TUI mode, shows a selection modal. In Rich mode, shows a numbered list
    with console prompts.
    """

    key = "0"
    name = "Load Snapshot"
    description = "List available snapshots and load one"
    category = CommandCategory.SYSTEM
    views = ["forensic", "malware", "security"]

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """List snapshots and allow user to select one to load.

        Args:
            ctx: Command context with ADB and UI access

        Returns:
            CommandResult indicating success/failure
        """
        # Get available snapshots
        snapshots = self._get_snapshots(ctx)

        if not snapshots:
            logger.warning("No snapshots available.")
            return CommandResult(
                success=False,
                message="No snapshots available",
                error="No snapshots found for this AVD",
            )

        # Let user select a snapshot
        selected_tag = await self._select_snapshot(ctx, snapshots)

        if selected_tag is None:
            logger.info("Snapshot selection cancelled")
            return CommandResult(
                success=True,
                message="Snapshot selection cancelled",
                data={"action": "cancelled"},
            )

        # Load the selected snapshot
        return self._load_snapshot(ctx, selected_tag)

    def _get_snapshots(self, ctx: CommandContext) -> list[dict]:
        """Get list of available snapshots.

        Args:
            ctx: Command context with ADB access

        Returns:
            List of snapshot dictionaries with 'tag' and 'date' keys
        """
        try:
            if ctx.adb:
                return ctx.adb.get_avd_snapshots() or []
        except Exception as e:
            logger.error(f"Failed to get snapshots: {e}")
        return []

    async def _select_snapshot(
        self, ctx: CommandContext, snapshots: list[dict]
    ) -> str | None:
        """Present snapshot selection UI and get user's choice.

        Args:
            ctx: Command context with UI access
            snapshots: List of available snapshots

        Returns:
            Selected snapshot tag, or None if cancelled
        """
        if ctx.is_tui_mode and ctx.request_selection:
            # TUI mode: Use selection modal
            options = [f"{s['date']} - {s['tag']}" for s in snapshots]
            selected = ctx.request_selection(
                title="Load Snapshot",
                options=options,
                message="Select a snapshot to load",
            )

            if selected:
                # Find the matching snapshot tag
                for i, opt in enumerate(options):
                    if opt == selected:
                        return snapshots[i]["tag"]
            return None
        # Rich mode: Use console prompts
        return await self._rich_mode_selection(ctx, snapshots)

    async def _rich_mode_selection(
        self, ctx: CommandContext, snapshots: list[dict]
    ) -> str | None:
        """Handle snapshot selection in Rich console mode.

        Args:
            ctx: Command context
            snapshots: List of available snapshots

        Returns:
            Selected snapshot tag, or None if cancelled
        """
        try:
            import click

            from sandroid.core.sandroid_console import SandroidConsole

            console = SandroidConsole.get()

            # Build snapshot list display
            snapshot_list = ""
            for idx, snapshot in enumerate(snapshots, 1):
                snapshot_list += (
                    f"[success]{snapshot['date']}[/success] - "
                    f"[primary]{snapshot['tag']}[/primary]\n"
                )

            # Display snapshots in a Rich panel
            console.print()
            SandroidConsole.print_panel(
                snapshot_list.strip(), title="Available Snapshots"
            )

            # Ask user to select a snapshot
            selected_idx = 0
            try:
                while selected_idx < 1 or selected_idx > len(snapshots):
                    try:
                        console.print(
                            f"[primary]Select a snapshot to load "
                            f"([accent]1[/accent]-[accent]{len(snapshots)}[/accent]): [/primary]",
                            end="",
                        )
                        char = click.getchar()
                        if char.isdigit():
                            selected_idx = int(char)
                        else:
                            selected_idx = 0  # Invalid input
                        if selected_idx < 1 or selected_idx > len(snapshots):
                            console.print(
                                f"[error]Please enter a number between "
                                f"[accent]1[/accent] and [accent]{len(snapshots)}[/accent][/error]"
                            )
                    except ValueError:
                        console.print("[error]Please enter a valid number[/error]")
            except KeyboardInterrupt:
                console.print(
                    "\n[warning]Snapshot selection cancelled by user.[/warning]"
                )
                return None

            return snapshots[selected_idx - 1]["tag"]

        except ImportError:
            logger.error("SandroidConsole not available for Rich mode")
            return None

    def _load_snapshot(self, ctx: CommandContext, snapshot_tag: str) -> CommandResult:
        """Load the specified snapshot.

        Args:
            ctx: Command context with toolbox access
            snapshot_tag: Tag of the snapshot to load

        Returns:
            CommandResult indicating success/failure
        """
        try:
            if ctx.toolbox:
                # Toolbox expects bytes for the name
                ctx.toolbox.load_snapshot(snapshot_tag.encode())
                logger.info(f"Loaded snapshot: {snapshot_tag}")
                return CommandResult(
                    success=True,
                    message=f"Loaded snapshot: {snapshot_tag}",
                    data={"snapshot": snapshot_tag, "action": "loaded"},
                )
            return CommandResult(
                success=False,
                message="Toolbox not available",
                error="No toolbox in context",
            )
        except Exception as e:
            logger.exception(f"Error loading snapshot: {e}")
            return CommandResult(
                success=False, message=f"Failed to load snapshot: {e}", error=str(e)
            )


class SnapshotCreateCommand(CommandHandler):
    """Command handler for creating emulator snapshots.

    Creates a new snapshot of the current emulator state.
    Keys 1-8 trigger snapshot creation (any of these keys works the same).
    In TUI mode, shows an input modal. In Rich mode, uses console prompts.
    """

    # Note: This command will be registered for keys "1" through "8"
    key = "1"  # Base key - will register multiple instances
    name = "Create Snapshot"
    description = "Create a snapshot of the current emulator state"
    category = CommandCategory.SYSTEM
    views = ["forensic", "malware", "security"]

    def __init__(self, key_override: str | None = None):
        """Initialize with optional key override.

        Args:
            key_override: Override the default key (for registering keys 1-8)
        """
        super().__init__()
        if key_override:
            self.key = key_override

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Create a snapshot after prompting for a name.

        Args:
            ctx: Command context with toolbox and UI access

        Returns:
            CommandResult indicating success/failure
        """
        # Get snapshot name from user
        snapshot_name = await self._get_snapshot_name(ctx)

        if snapshot_name is None:
            logger.info("Snapshot creation cancelled")
            return CommandResult(
                success=True,
                message="Snapshot creation cancelled",
                data={"action": "cancelled"},
            )

        # Use timestamp if no name provided
        if not snapshot_name:
            snapshot_name = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        # Create the snapshot
        return self._create_snapshot(ctx, snapshot_name)

    async def _get_snapshot_name(self, ctx: CommandContext) -> str | None:
        """Get snapshot name from user input.

        Args:
            ctx: Command context with UI access

        Returns:
            Snapshot name string, empty string for timestamp, or None if cancelled
        """
        if ctx.is_tui_mode and ctx.request_input:
            # TUI mode: Use input modal
            return ctx.request_input(
                title="Create Snapshot",
                message="Enter snapshot name (leave blank for timestamp):",
                default="",
            )
        # Rich mode: Use console prompts
        return await self._rich_mode_input(ctx)

    async def _rich_mode_input(self, ctx: CommandContext) -> str | None:
        """Get snapshot name in Rich console mode.

        Args:
            ctx: Command context

        Returns:
            Snapshot name, empty string, or None if cancelled
        """
        try:
            from sandroid.core.sandroid_console import SandroidConsole

            console = SandroidConsole.get()

            try:
                console.print(
                    "[primary]Enter snapshot name (or press Enter for timestamp): [/primary]",
                    end="",
                )
                if ctx.toolbox:
                    snapshot_name = ctx.toolbox.safe_input()
                else:
                    snapshot_name = input()
                return snapshot_name
            except KeyboardInterrupt:
                console.print(
                    "\n[warning]Snapshot creation cancelled by user.[/warning]"
                )
                return None

        except ImportError:
            logger.error("SandroidConsole not available for Rich mode")
            return None

    def _create_snapshot(self, ctx: CommandContext, name: str) -> CommandResult:
        """Create a snapshot with the given name.

        Args:
            ctx: Command context with toolbox access
            name: Name for the snapshot

        Returns:
            CommandResult indicating success/failure
        """
        try:
            if ctx.toolbox:
                # Toolbox expects bytes for the name
                ctx.toolbox.create_snapshot(name.encode())
                logger.info(f"Created snapshot: {name}")
                return CommandResult(
                    success=True,
                    message=f"Created snapshot: {name}",
                    data={"snapshot": name, "action": "created"},
                )
            return CommandResult(
                success=False,
                message="Toolbox not available",
                error="No toolbox in context",
            )
        except Exception as e:
            logger.exception(f"Error creating snapshot: {e}")
            return CommandResult(
                success=False, message=f"Failed to create snapshot: {e}", error=str(e)
            )


def register_commands(registry) -> None:
    """Register all snapshot commands.

    Args:
        registry: CommandRegistry instance to register commands with
    """
    # Register snapshot list command (key "0")
    registry.register(SnapshotListCommand())

    # Register snapshot create commands for keys 1-8
    for key in "12345678":
        registry.register(SnapshotCreateCommand(key_override=key))


__all__ = [
    "SnapshotCreateCommand",
    "SnapshotListCommand",
    "register_commands",
]
