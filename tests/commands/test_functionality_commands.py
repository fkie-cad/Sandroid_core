"""Tests for the recorder/player/trigdroid command palette entries.

These commands used to be permanently message-only (see the NIT this file
was written to close): the palette dispatches them on a worker thread with a
:class:`~sandroid.commands.base.CommandContext` that, in headless/API/test
contexts, has no handle to the running TUI app. When the TUI's live
worker-thread dispatch path *does* thread an app reference through
(``ctx.app``), these commands must drive the real ``action_record`` /
``action_play`` / ``action_trigdroid`` via ``app.call_from_thread`` instead of
just pointing the user at the panel/key. These tests cover both branches, plus
the honest-``False``-propagation and restored ``can_execute`` preconditions
added after review found the original version reported false "success" and
had lost its precondition checks.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from sandroid.commands.base import CommandContext
from sandroid.commands.functionality_commands import (
    PlayerCommand,
    RecorderCommand,
    TrigdroidCommand,
)


def _fake_app() -> MagicMock:
    """A stand-in for SandroidTUI: call_from_thread just calls its argument."""
    app = MagicMock()
    app.call_from_thread.side_effect = lambda fn, *a, **kw: fn(*a, **kw)
    return app


@pytest.mark.parametrize(
    ("command_cls", "action_name"),
    [
        (RecorderCommand, "action_record"),
        (PlayerCommand, "action_play"),
        (TrigdroidCommand, "action_trigdroid"),
    ],
)
async def test_no_app_falls_back_to_pointer_message(command_cls, action_name):
    """Headless/API contexts (ctx.app is None) get the informative message."""
    ctx = CommandContext()  # app defaults to None
    result = await command_cls().execute(ctx)

    assert result.success is True
    assert result.should_return_to_menu is True
    # Never claims the live action ran.
    assert "started" not in result.message.lower()
    assert "triggered" not in result.message.lower()


@pytest.mark.parametrize(
    ("command_cls", "action_name"),
    [
        (RecorderCommand, "action_record"),
        (PlayerCommand, "action_play"),
        (TrigdroidCommand, "action_trigdroid"),
    ],
)
async def test_reachable_app_drives_the_real_action(command_cls, action_name):
    """A reachable ctx.app gets the live action called via call_from_thread."""
    app = _fake_app()
    action_mock = MagicMock()
    setattr(app, action_name, action_mock)
    ctx = CommandContext(app=app)

    result = await command_cls().execute(ctx)

    app.call_from_thread.assert_called_once_with(action_mock)
    action_mock.assert_called_once_with()
    assert result.success is True
    assert result.should_return_to_menu is True


@pytest.mark.parametrize(
    ("command_cls", "action_name"),
    [
        (RecorderCommand, "action_record"),
        (PlayerCommand, "action_play"),
        (TrigdroidCommand, "action_trigdroid"),
    ],
)
async def test_app_call_failure_falls_back_to_pointer_message(command_cls, action_name):
    """If call_from_thread raises, fall back to the informative message
    rather than propagating (a wedged/exiting app must not crash the palette).
    """
    app = MagicMock()
    app.call_from_thread.side_effect = RuntimeError("app not running")
    ctx = CommandContext(app=app)

    result = await command_cls().execute(ctx)

    assert result.success is True
    assert result.should_return_to_menu is True
    assert "started" not in result.message.lower()
    assert "triggered" not in result.message.lower()


@pytest.mark.parametrize(
    ("command_cls", "action_name"),
    [
        (RecorderCommand, "action_record"),
        (PlayerCommand, "action_play"),
        (TrigdroidCommand, "action_trigdroid"),
    ],
)
async def test_declined_action_reports_failure_not_success(command_cls, action_name):
    """A controller-declined action (returns False, doesn't raise) must
    surface as a failed CommandResult, not a misleading success toast --
    RecordingController/TrigdroidController decline real preconditions
    (already recording, no recording to play, no target app) this way.
    """
    app = _fake_app()
    setattr(app, action_name, MagicMock(return_value=False))
    ctx = CommandContext(app=app)

    result = await command_cls().execute(ctx)

    assert result.success is False
    assert result.should_return_to_menu is True
    assert "started" not in result.message.lower()
    assert "triggered" not in result.message.lower()


def test_recorder_can_execute_blocks_while_already_recording():
    app = MagicMock()
    app._recording_controller.is_recording.return_value = True
    ctx = CommandContext(app=app)

    can_execute, reason = RecorderCommand().can_execute(ctx)

    assert can_execute is False
    assert "recording" in reason.lower()


def test_recorder_can_execute_allows_when_not_recording():
    app = MagicMock()
    app._recording_controller.is_recording.return_value = False
    ctx = CommandContext(app=app)

    assert RecorderCommand().can_execute(ctx) == (True, "")


def test_player_can_execute_blocks_with_no_recording():
    app = MagicMock()
    app._recording_controller.has_recording.return_value = False
    ctx = CommandContext(app=app)

    can_execute, reason = PlayerCommand().can_execute(ctx)

    assert can_execute is False
    assert "recording" in reason.lower()


def test_player_can_execute_allows_with_a_recording():
    app = MagicMock()
    app._recording_controller.has_recording.return_value = True
    ctx = CommandContext(app=app)

    assert PlayerCommand().can_execute(ctx) == (True, "")


def test_trigdroid_can_execute_blocks_with_no_target_app():
    app = MagicMock()
    app._trigdroid_controller.is_running.return_value = False
    app._trigdroid_controller.has_target_app.return_value = False
    ctx = CommandContext(app=app)

    can_execute, reason = TrigdroidCommand().can_execute(ctx)

    assert can_execute is False
    assert "spotlight" in reason.lower()


def test_trigdroid_can_execute_allows_when_already_running():
    """Stopping an already-running TrigDroid has no target-app precondition."""
    app = MagicMock()
    app._trigdroid_controller.is_running.return_value = True
    app._trigdroid_controller.has_target_app.return_value = False
    ctx = CommandContext(app=app)

    assert TrigdroidCommand().can_execute(ctx) == (True, "")


@pytest.mark.parametrize(
    "command_cls", [RecorderCommand, PlayerCommand, TrigdroidCommand]
)
def test_can_execute_allows_when_no_app_reachable(command_cls):
    """Headless/API/test contexts have no controller to check -- never block."""
    ctx = CommandContext()  # app defaults to None

    assert command_cls().can_execute(ctx) == (True, "")


def test_registration_views_and_keys_unchanged():
    """Keys/views/should_return_to_menu contract is untouched by the rewire."""
    assert RecorderCommand.key == "r"
    assert RecorderCommand.views == ["forensic", "malware"]
    assert PlayerCommand.key == "p"
    assert PlayerCommand.views == ["forensic", "malware"]
    assert TrigdroidCommand.key == "t"
    assert TrigdroidCommand.views == ["malware"]
