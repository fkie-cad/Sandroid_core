"""Functionality commands for recorder, player, and trigdroid.

These palette entries used to append work to ``ActionQ`` and rely on the legacy
``do_next`` pump. That engine is gone: recording, playback and TrigDroid now run
through the TUI controllers (``app.action_record`` -> ``RecordingController``,
``app.action_play`` -> ``RecordingController``, ``app.action_trigdroid`` ->
``TrigdroidController``) which drive :class:`~sandroid.analysis.engine.AnalysisEngine`.

The TUI's live key-dispatch path (``MainScreen._execute_action_sync``) still
runs these handlers on a worker thread, but it now threads a reference to the
running app through as :attr:`~sandroid.commands.base.CommandContext.app`.
When that reference is present, these commands hand off to the exact same
``app.action_record``/``action_play``/``action_trigdroid`` methods the
panel-scoped ``r``/``p`` keys (and the global ``t`` binding) call, via
``app.call_from_thread`` -- the standard Textual mechanism for driving
main-thread app state from a worker thread. Contexts built outside the live
TUI (headless API, tests, `create_minimal_context`/`create_context_with_toolbox`)
never populate ``ctx.app``, so these commands fall back to an informative
result pointing the user at the live triggers instead of silently no-op'ing.

The three ``action_*`` methods return their controller's own success bool
(``RecordingController.start_recording``/``start_playback``,
``TrigdroidController.toggle_trigdroid``), which these commands propagate
honestly rather than reporting "success" whenever the call merely didn't
raise -- those controllers decline (log + return ``False``) rather than raise
for real preconditions (already recording, no recording to play, no target
app), so a declined action must surface as a failed ``CommandResult``, not a
misleading success toast. ``can_execute`` mirrors the same preconditions
(best-effort, only when a live app is reachable) so the palette can also
report *why* upfront, matching this app's existing gating convention for
other commands.
"""

import logging

from .base import CommandCategory, CommandContext, CommandHandler, CommandResult

logger = logging.getLogger(__name__)


def _drive_live_action(ctx: CommandContext, action_name: str) -> bool | None:
    """Invoke ``ctx.app.<action_name>()`` on the app's main thread, if reachable.

    ``action_record``/``action_play``/``action_trigdroid`` each return their
    controller's own success bool (``RecordingController.start_recording``/
    ``start_playback``, ``TrigdroidController.toggle_trigdroid``) -- those
    controllers already handle every real precondition (already recording, no
    recording to play, no target app) by logging a warning and returning
    ``False`` rather than raising, so that ``False`` must be propagated
    honestly rather than reported as success.

    Args:
        ctx: The command context. ``ctx.app`` is only populated by the TUI's
            live worker-thread key-dispatch path.
        action_name: Name of the zero-argument ``SandroidTUI`` action method
            to call (e.g. ``"action_record"``), which must return ``bool``.

    Returns:
        The action's own result (``True``/``False``) if a live app was
        reachable and the call completed. ``None`` if there is no reachable
        app (headless/API/test contexts) or the call raised unexpectedly --
        callers should fall back to the informative pointer message in both
        of those cases, but must not claim success for a real ``False``.
    """
    if ctx.app is None:
        return None
    try:
        return bool(ctx.app.call_from_thread(getattr(ctx.app, action_name)))
    except Exception:
        logger.warning(
            f"Could not drive live {action_name} from the command palette",
            exc_info=True,
        )
        return None


def _app_controller(ctx: CommandContext, attr_name: str):
    """Best-effort read of a controller off ``ctx.app``, or ``None``.

    Used only for ``can_execute`` precondition checks -- if the controller
    isn't reachable (no live app, or an unexpected shape), the precondition
    is simply not checked and the command is left executable; ``execute``'s
    own ``_drive_live_action`` handles the no-app case definitively either way.
    """
    if ctx.app is None:
        return None
    return getattr(ctx.app, attr_name, None)


class RecorderCommand(CommandHandler):
    """Command palette entry for starting the session recorder.

    Recording is normally driven by the Files -> Diffs panel's panel-scoped
    'r' key. This entry drives the identical ``app.action_record`` when a
    live app is reachable, and only falls back to pointing the user at the
    panel when it is not (e.g. headless API contexts).
    """

    key = "r"
    name = "Start Recorder"
    description = "Record user interactions for later playback"
    category = CommandCategory.FUNCTIONALITY
    views = ["forensic", "malware"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Block if a live app shows a recording is already in progress."""
        controller = _app_controller(ctx, "_recording_controller")
        if controller is not None and controller.is_recording():
            return (False, "Already recording. Stop the current recording first.")
        return (True, "")

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Start recording via the live app, or point at the live trigger."""
        driven = _drive_live_action(ctx, "action_record")
        if driven is True:
            return CommandResult(
                success=True,
                message="Recording started.",
                should_return_to_menu=True,
            )
        if driven is False:
            return CommandResult(
                success=False,
                message="Could not start recording (already recording?).",
                should_return_to_menu=True,
            )
        return CommandResult(
            success=True,
            message="Start recording from the Files -> Diffs panel (press 'r').",
            should_return_to_menu=True,
        )


class PlayerCommand(CommandHandler):
    """Command palette entry for replaying a recorded session.

    Playback is normally driven by the Files -> Diffs panel's panel-scoped
    'p' key. This entry drives the identical ``app.action_play`` when a live
    app is reachable, and only falls back to pointing the user at the panel
    when it is not (e.g. headless API contexts).
    """

    key = "p"
    name = "Start Player"
    description = "Play back recorded interactions"
    category = CommandCategory.FUNCTIONALITY
    views = ["forensic", "malware"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Block if a live app shows there is no recording to play back."""
        controller = _app_controller(ctx, "_recording_controller")
        if controller is not None and not controller.has_recording():
            return (False, "No recording to play back yet. Record something first.")
        return (True, "")

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Start playback via the live app, or point at the live trigger."""
        driven = _drive_live_action(ctx, "action_play")
        if driven is True:
            return CommandResult(
                success=True,
                message="Playback started.",
                should_return_to_menu=True,
            )
        if driven is False:
            return CommandResult(
                success=False,
                message="Could not start playback (no recording?).",
                should_return_to_menu=True,
            )
        return CommandResult(
            success=True,
            message="Replay from the Files -> Diffs panel (press 'p').",
            should_return_to_menu=True,
        )


class TrigdroidCommand(CommandHandler):
    """Command palette entry for running TrigDroid triggers.

    TrigDroid is normally driven by the global 't' key. This entry drives
    the identical ``app.action_trigdroid`` when a live app is reachable, and
    only falls back to pointing the user at the key when it is not (e.g.
    headless API contexts).
    """

    key = "t"
    name = "Start TrigDroid"
    description = "Run automated malware triggers"
    category = CommandCategory.FUNCTIONALITY
    views = ["malware"]

    def can_execute(self, ctx: CommandContext) -> tuple[bool, str]:
        """Block if a live app shows no spotlighted/spawned target app.

        Mirrors ``TrigdroidController.show_trigdroid_modal``'s own gate, so
        the palette's precondition matches what would actually happen.
        Skipped (never blocks) while TrigDroid is already running, since
        toggling it off has no target-app precondition.
        """
        controller = _app_controller(ctx, "_trigdroid_controller")
        if (
            controller is not None
            and not controller.is_running()
            and not controller.has_target_app()
        ):
            return (
                False,
                "No spotlight app selected. Press 'c' or 'C' to select an app first.",
            )
        return (True, "")

    async def execute(self, ctx: CommandContext) -> CommandResult:
        """Trigger TrigDroid via the live app, or point at the live trigger."""
        driven = _drive_live_action(ctx, "action_trigdroid")
        if driven is True:
            return CommandResult(
                success=True,
                message="TrigDroid triggered.",
                should_return_to_menu=True,
            )
        if driven is False:
            return CommandResult(
                success=False,
                message="Could not start TrigDroid (no target app selected?).",
                should_return_to_menu=True,
            )
        return CommandResult(
            success=True,
            message="Run TrigDroid from the tools (press 't').",
            should_return_to_menu=True,
        )


def register_commands(registry) -> None:
    """Register all functionality commands.

    Args:
        registry: The CommandRegistry to register commands with
    """
    registry.register(RecorderCommand())
    registry.register(PlayerCommand())
    registry.register(TrigdroidCommand())
