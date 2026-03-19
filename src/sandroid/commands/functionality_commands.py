"""Functionality commands for recorder, player, and trigdroid."""

import logging

from .base import CommandCategory, CommandContext, CommandHandler, CommandResult

logger = logging.getLogger(__name__)


class RecorderCommand(CommandHandler):
    """Command to start the session recorder.

    Records user interactions for later playback. The recorder captures
    touch events, key presses, and other user actions that can be
    replayed using the PlayerCommand.
    """

    key = "r"
    name = "Start Recorder"
    description = "Record user interactions for later playback"
    category = CommandCategory.FUNCTIONALITY
    views = ["forensic", "malware"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if recorder command can be executed.

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        if ctx.action_queue is None:
            return (False, "Action queue not available")
        return (True, "")

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Start the session recorder.

        Adds to the action queue:
        1. create_snapshot - Create a baseline snapshot
        2. Recorder instance - The recorder functionality
        3. interactive - Return to interactive mode after recording
        """
        try:
            from sandroid.features.recorder import Recorder

            if ctx.action_queue is None:
                return CommandResult(
                    success=False,
                    message="Action queue not available",
                    error="No action queue in context",
                )

            # Add items to the queue
            ctx.action_queue.q.append("create_snapshot")
            ctx.action_queue.q.append(Recorder())
            ctx.action_queue.q.append("interactive")

            logger.info("Recorder added to action queue")

            return CommandResult(
                success=True,
                message="Recorder queued - will create snapshot and start recording",
                should_return_to_menu=False,
            )

        except ImportError as e:
            logger.error(f"Failed to import Recorder: {e}")
            return CommandResult(
                success=False, message="Failed to load Recorder module", error=str(e)
            )
        except Exception as e:
            logger.exception("Error starting recorder")
            return CommandResult(
                success=False, message="Failed to start recorder", error=str(e)
            )


class PlayerCommand(CommandHandler):
    """Command to play back a recorded session.

    Plays back previously recorded user interactions. Uses the
    assembleQ_for_runs method to set up the queue for playback.
    """

    key = "p"
    name = "Start Player"
    description = "Play back recorded interactions"
    category = CommandCategory.FUNCTIONALITY
    views = ["forensic", "malware"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if player command can be executed.

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        if ctx.action_queue is None:
            return (False, "Action queue not available")
        return (True, "")

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Start playback of a recorded session.

        Uses assembleQ_for_runs to set up the action queue with
        the Player functionality for the configured number of runs.
        """
        try:
            from sandroid.features.player import Player

            if ctx.action_queue is None:
                return CommandResult(
                    success=False,
                    message="Action queue not available",
                    error="No action queue in context",
                )

            # Use assembleQ_for_runs to set up the queue
            ctx.action_queue.assembleQ_for_runs(Player())

            logger.info("Player added to action queue via assembleQ_for_runs")

            return CommandResult(
                success=True,
                message="Player queued - will play back recorded session",
                should_return_to_menu=False,
            )

        except ImportError as e:
            logger.error(f"Failed to import Player: {e}")
            return CommandResult(
                success=False, message="Failed to load Player module", error=str(e)
            )
        except Exception as e:
            logger.exception("Error starting player")
            return CommandResult(
                success=False, message="Failed to start player", error=str(e)
            )


class TrigdroidCommand(CommandHandler):
    """Command to run TrigDroid for automated malware triggering.

    TrigDroid automatically executes malware triggers to stimulate
    malicious behavior during forensic analysis. Creates a snapshot
    first to capture the baseline state.
    """

    key = "t"
    name = "Start TrigDroid"
    description = "Run automated malware triggers"
    category = CommandCategory.FUNCTIONALITY
    views = ["malware"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Check if TrigDroid command can be executed.

        Returns:
            Tuple of (can_execute, reason_if_not)
        """
        if ctx.action_queue is None:
            return (False, "Action queue not available")

        from sandroid.services import get_spotlight_service

        if not get_spotlight_service().has_app():
            return (
                False,
                "No spotlight app selected. Press 'c' or 'C' to select an app first.",
            )

        return (True, "")

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Start TrigDroid automated malware triggering.

        Adds to the action queue:
        1. create_snapshot - Create a baseline snapshot first
        2. Uses assembleQ_for_runs with Trigdroid for the actual triggering
        """
        try:
            from sandroid.features.trigdroid import Trigdroid

            if ctx.action_queue is None:
                return CommandResult(
                    success=False,
                    message="Action queue not available",
                    error="No action queue in context",
                )

            # Add snapshot creation first
            ctx.action_queue.q.append("create_snapshot")

            # Then use assembleQ_for_runs for the Trigdroid functionality
            ctx.action_queue.assembleQ_for_runs(Trigdroid())

            logger.info("TrigDroid added to action queue with snapshot creation")

            return CommandResult(
                success=True,
                message="TrigDroid queued - will create snapshot and run triggers",
                should_return_to_menu=False,
            )

        except ImportError as e:
            logger.error(f"Failed to import Trigdroid: {e}")
            return CommandResult(
                success=False, message="Failed to load TrigDroid module", error=str(e)
            )
        except Exception as e:
            logger.exception("Error starting TrigDroid")
            return CommandResult(
                success=False, message="Failed to start TrigDroid", error=str(e)
            )


def register_commands(registry) -> None:
    """Register all functionality commands.

    Args:
        registry: The CommandRegistry to register commands with
    """
    registry.register(RecorderCommand())
    registry.register(PlayerCommand())
    registry.register(TrigdroidCommand())
