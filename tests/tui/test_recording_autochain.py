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
    controller.start_playback = lambda label=None: (play_calls.append(label), True)[1]

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

    assert play_calls == ["My run"]  # the auto-chained run keeps its label
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


# ---------------------------------------------------------------------------
# Session timeline: record / play lines
# ---------------------------------------------------------------------------


def test_record_start_stop_and_result_lines() -> None:
    from sandroid.core import timeline

    controller, captured, _play_calls = _controller_with_captured_result_cb()
    controller._current_recording_label = "Login"
    with timeline.capture() as lines:
        # The modal drives the indicator (wrapped by the controller).
        assert captured["modal"]._on_recording_active_changed is (
            controller._set_recording_indicator
        )
        controller._set_recording_indicator(True)
        controller._set_recording_indicator(True)  # no second start
        controller._set_recording_indicator(False)
        captured["callback"](RecordingResult(cancelled=True))
    start, stop, result = lines
    assert (start["src"], start["kind"], start["phase"]) == (
        "run",
        "record-start",
        "record",
    )
    assert start["actor"] == "user"
    assert start["data"]["via"] == "modal"
    assert start["data"]["label"] == "Login"
    assert start["summary"] == "● REC · Login"
    assert (stop["kind"], stop["phase"]) == ("record-stop", "live")
    assert stop["ref"] == {"of": start["seq"]}
    assert result["kind"] == "record-result"
    assert result["data"]["cancelled"] is True
    assert result["ref"] == {"of": stop["seq"]}
    assert controller._tl_record_range == [start["seq"], stop["seq"]]


def test_esc_on_the_record_settings_writes_no_result_line() -> None:
    """F6 (E2E): Esc on the Record-settings form (Record never started)
    wrote run/record-result "cancelled" without a record-start.
    """
    from sandroid.core import timeline

    controller, captured, _play_calls = _controller_with_captured_result_cb()
    with timeline.capture() as lines:
        captured["callback"](RecordingResult(cancelled=True))
        captured["callback"](None)
    assert lines == []
    # A later real recording still gets its start/stop/result.
    controller, captured, _play_calls = _controller_with_captured_result_cb()
    with timeline.capture() as lines:
        controller._set_recording_indicator(True)
        controller._set_recording_indicator(False)
        captured["callback"](RecordingResult(cancelled=True))
    assert [x["kind"] for x in lines] == [
        "record-start",
        "record-stop",
        "record-result",
    ]


def test_a_chat_recording_is_the_ais(monkeypatch) -> None:
    from types import SimpleNamespace

    from sandroid.core import timeline
    from sandroid.tui.utils import recording_wrapper

    class _Wrapper:
        event_count, elapsed_seconds = 4, 2.0

        def __init__(self, output_file=None):
            pass

        def start(self):
            return True

        def stop(self):
            return None

    monkeypatch.setattr(recording_wrapper, "RecordingWrapper", _Wrapper)
    controller = RecordingController(
        log_info=lambda *_: None,
        log_success=lambda *_: None,
        toolbox=SimpleNamespace(create_snapshot=lambda name: None),
    )
    with timeline.capture() as lines:
        assert controller.start_recording_chat("chat run")["success"] is True
        assert controller.stop_recording_chat()["success"] is True
    assert [x["kind"] for x in lines] == [
        "record-start",
        "record-stop",
        "record-result",
    ]
    assert {x["actor"] for x in lines} == {"ai"}
    assert lines[0]["data"]["via"] == "chat"
    assert lines[2]["data"]["events"] == 4
    assert lines[2]["data"]["completed"] is True


def test_play_start_and_end_bracket_the_run(monkeypatch, tmp_path) -> None:
    from types import SimpleNamespace

    from sandroid.analysis import engine as engine_module
    from sandroid.core import run_bundle, timeline
    from sandroid.tui.controllers import recording_controller as rc

    seen_configs = []

    class _Engine:
        def __init__(self, config, **kwargs):
            seen_configs.append(config)

        def run(self):
            return SimpleNamespace(
                error=None, changed_files=["a"], new_files=[], deleted_files=["b", "c"]
            )

    monkeypatch.setattr(engine_module, "AnalysisEngine", _Engine)
    monkeypatch.setattr(run_bundle, "create_bundle", lambda run_id: None)
    monkeypatch.setattr(run_bundle, "import_recording", lambda run_id, path: "rec")
    monkeypatch.setattr(run_bundle, "raw_dir", lambda run_id: str(tmp_path))
    monkeypatch.setattr(run_bundle, "bundle_dir", lambda run_id: tmp_path)
    monkeypatch.setattr(rc, "reset_device_handles_after_snapshot_load", lambda: None)
    controller = RecordingController(log_info=lambda *_: None)
    monkeypatch.setattr(controller, "_stop_monitor_before_revert", lambda: None)
    monkeypatch.setattr(controller, "_persist_run", lambda **kw: kw["run_id"])
    monkeypatch.setattr(controller, "_get_toolbox", lambda: None)
    monkeypatch.setattr(controller, "_get_forensic_service", lambda: None)
    monkeypatch.setattr(controller, "_get_action_window_service", lambda: None)
    monkeypatch.setattr(controller, "_current_device_name", lambda: "Pixel")
    controller._tl_record_range = [5, 9]
    controller._play_label = "Login"
    with timeline.capture() as lines:
        controller._run_playback_analysis()
        assert timeline.get_timeline().current_phase() == ("live", None)
    start, end = lines
    run_id = seen_configs[0].run_id
    assert run_id
    assert (start["kind"], start["run"], start["phase"]) == (
        "play-start",
        run_id,
        "live",
    )
    assert start["replays"] == {"run": None, "seq_range": [5, 9]}
    assert start["data"]["bundle"] == f"runs/{run_id}"
    assert start["data"]["label"] == "Login"
    assert (end["kind"], end["run"]) == ("play-end", None)
    assert end["ref"] == {"of": start["seq"], "run": run_id, "lens": "runs"}
    assert end["data"] == {
        "error": None,
        "failed": False,
        "saved": True,
        "changed": 1,
        "new": 0,
        "deleted": 2,
    }


@pytest.mark.parametrize(
    "boom",
    [SystemExit(1), RuntimeError("Device not ready, replay aborted: authorizing")],
)
def test_a_failing_play_ends_with_a_failed_play_end_and_never_exits(
    monkeypatch, tmp_path, boom
) -> None:
    """E2E crash: ``SystemExit(1)`` from ``adb shell date`` on the Play worker
    ended the whole TUI. Whatever the engine raises, the Play ends with a
    ``run/play-end`` marked failed and the worker returns normally.
    """
    from sandroid.analysis import engine as engine_module
    from sandroid.core import run_bundle, timeline
    from sandroid.tui.controllers import recording_controller as rc

    class _Engine:
        def __init__(self, config, **kwargs):
            pass

        def run(self):
            raise boom

    errors: list[str] = []
    monkeypatch.setattr(engine_module, "AnalysisEngine", _Engine)
    monkeypatch.setattr(run_bundle, "create_bundle", lambda run_id: None)
    monkeypatch.setattr(run_bundle, "import_recording", lambda run_id, path: "rec")
    monkeypatch.setattr(run_bundle, "raw_dir", lambda run_id: str(tmp_path))
    monkeypatch.setattr(run_bundle, "bundle_dir", lambda run_id: tmp_path)
    monkeypatch.setattr(rc, "reset_device_handles_after_snapshot_load", lambda: None)
    controller = RecordingController(log_info=lambda *_: None)
    monkeypatch.setattr(controller, "_log_error", errors.append)
    monkeypatch.setattr(controller, "_stop_monitor_before_revert", lambda: None)
    monkeypatch.setattr(controller, "_persist_run", lambda **kw: kw["run_id"])
    monkeypatch.setattr(controller, "_get_toolbox", lambda: None)
    monkeypatch.setattr(controller, "_get_forensic_service", lambda: None)
    monkeypatch.setattr(controller, "_get_action_window_service", lambda: None)
    monkeypatch.setattr(controller, "_current_device_name", lambda: "Pixel")
    with timeline.capture() as lines:
        controller._run_playback_analysis()  # must not raise
    end = [x for x in lines if x["kind"] == "play-end"]
    assert len(end) == 1
    assert end[0]["data"]["failed"] is True
    assert end[0]["data"]["error"].startswith("Playback failed:")
    assert errors
    assert controller._is_replaying is False
