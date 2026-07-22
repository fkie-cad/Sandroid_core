"""RecordingController auto-chain (idea B): completed Stop -> auto playback.

When a recording completes (Stop, not Cancel), ``on_recording_result`` folds
the combined Record-settings form's choices (name + replays + dry-run) into
the controller's ``_current_*`` seeds and then automatically kicks off
playback via ``start_playback()`` — so Record -> interact -> Stop lands the
user on the Diff panel with results, with no extra keypress. A cancelled
recording must not auto-play.

No physical device involved: ``start_recording`` only pushes a modal (captured
here) and ``start_playback`` is replaced with a spy, so the worker/engine is
never actually spun up.
"""

from __future__ import annotations

import pytest

from sandroid.services import get_task_service
from sandroid.tui.controllers.recording_controller import RecordingController
from sandroid.tui.modals import RecordingResult


@pytest.fixture(autouse=True)
def _clean_recording_task():
    """Guard the process-wide TaskService so is_recording() reads False."""
    svc = get_task_service()
    svc._tasks.pop("recording", None)
    yield
    svc._tasks.pop("recording", None)


def _controller_with_captured_result_cb() -> tuple[RecordingController, dict, list]:
    captured: dict = {}
    play_calls: list = []

    def push_modal(modal, callback) -> None:
        captured["modal"] = modal
        captured["callback"] = callback

    controller = RecordingController(
        log_info=lambda *_: None,
        log_warning=lambda *_: None,
        log_error=lambda *_: None,
        log_success=lambda *_: None,
        push_modal=push_modal,
    )
    # Spy on start_playback (instance attr shadows the bound method, so the
    # auto-chain's ``self.start_playback()`` resolves to this).
    controller.start_playback = lambda: (play_calls.append(True), True)[1]

    assert controller.start_recording() is True
    return controller, captured, play_calls


def test_completed_recording_auto_starts_playback_with_settings() -> None:
    controller, captured, play_calls = _controller_with_captured_result_cb()

    captured["callback"](
        RecordingResult(
            cancelled=False,
            completed=True,
            duration=3,
            event_count=10,
            label="My run",
            number_of_runs=4,
            noise_filter=False,
        )
    )

    assert play_calls == [True]
    # The chosen settings seed every subsequent Play of this recording.
    assert controller._current_recording_label == "My run"
    assert controller._current_number_of_runs == 4
    assert controller._current_noise_filter is False


def test_cancelled_recording_does_not_auto_start_playback() -> None:
    controller, captured, play_calls = _controller_with_captured_result_cb()

    captured["callback"](RecordingResult(cancelled=True))

    assert play_calls == []


def test_none_result_does_not_auto_start_playback() -> None:
    controller, captured, play_calls = _controller_with_captured_result_cb()

    captured["callback"](None)

    assert play_calls == []
