"""Unit tests for RecordingController's monitor Play-safety-net mechanism.

Covers the riskiest piece of the Files-tab plan (Build order step 6): monitor's
live ``adb shell`` session cannot survive Play's snapshot revert
(``EmulatorService.load_snapshot()`` has zero adb-reconnect logic), so
``_stop_monitor_before_revert()`` stops it cleanly *before* the revert instead
of letting it silently die, and ``_run_playback_analysis()`` offers a
callback-driven "Resume monitoring" hand-off once Play finishes.

Two independent things are exercised:

1. ``_stop_monitor_before_revert()`` in isolation — including a real
   background-thread test that confirms the stop + notice actually marshal
   through ``call_from_thread`` from a non-main thread, the way
   ``_run_playback_analysis`` really calls it (``start_playback`` dispatches
   it via ``run_worker(..., thread=True)``).
2. ``_run_playback_analysis()`` end-to-end, with the analysis pipeline
   (``ChangedFiles``/``NewFiles``/``DeletedFiles``/``Player``) and the
   injected toolbox/forensic/action-window services monkeypatched to
   lightweight no-ops — this test is only about the monitor safety net
   wrapped around that pipeline, not the pipeline itself (already covered
   elsewhere). ``_run_playback_analysis()`` now drives the unified
   ``AnalysisEngine``, so the fakes are injected into the engine and a real
   ``recording.txt`` is written under a tmp ``RAW_RESULTS_PATH`` (the engine
   imports it into the run bundle up-front). ``get_config`` is pointed at
   ``tmp_path`` too so the config-first run-bundle root never leaks into the
   repo's ``./results/``.

No physical device involved anywhere: the real (process-wide) TaskService
singleton is used with a fake monitor "task" registered directly (same
convention as ``test_monitor_controller.py``), and an autouse fixture guards
against cross-test leakage.
"""

from __future__ import annotations

import os
import threading
from types import SimpleNamespace

import pytest

from sandroid.analysis.changedfiles import ChangedFiles
from sandroid.analysis.deletedfiles import DeletedFiles
from sandroid.analysis.newfiles import NewFiles
from sandroid.features.player import Player
from sandroid.services import get_task_service
from sandroid.tui.controllers.monitor_controller import MonitorConfig
from sandroid.tui.controllers.recording_controller import RecordingController


@pytest.fixture(autouse=True)
def _clean_monitor_task():
    """Guard the real (process-wide) TaskService singleton against leaks."""
    svc = get_task_service()
    svc._tasks.pop("monitor", None)
    yield
    svc._tasks.pop("monitor", None)


class _FakeToolbox:
    """Stand-in for Toolbox: just enough surface for _run_playback_analysis."""

    device_name = "fake-device"

    def __init__(self) -> None:
        self.load_snapshot_calls: list = []

    def load_snapshot(self, tag) -> None:
        self.load_snapshot_calls.append(tag)

    def fetch_changed_files(self, fetch_all: bool = False) -> dict:
        return {}


class _FakeForensicService:
    def __init__(self) -> None:
        self.baseline_calls: list = []

    def set_baseline(self, data) -> None:
        self.baseline_calls.append(data)

    def get_baseline(self) -> dict:
        return {}

    def get_action_duration(self) -> int:
        return 5


class _FakeActionWindow:
    """In-memory stand-in for ActionWindowService (keeps the engine fast)."""

    def get_action_time(self) -> int:
        return 0

    def get_duration(self) -> int:
        return 0

    def set_duration(self, value, force: bool = False) -> None:
        pass

    def start_dry_run(self) -> None:
        pass

    def end_dry_run(self) -> None:
        pass

    def is_dry_run(self) -> bool:
        return False


def _patch_pipeline(monkeypatch) -> None:
    """Neuter the analysis pipeline itself — irrelevant to this file's scope."""
    monkeypatch.setattr(ChangedFiles, "gather", lambda self: None)
    monkeypatch.setattr(ChangedFiles, "return_data", lambda self: {"Changed Files": []})
    monkeypatch.setattr(ChangedFiles, "pretty_print", lambda self: "")
    monkeypatch.setattr(NewFiles, "gather", lambda self: None)
    monkeypatch.setattr(NewFiles, "return_data", lambda self: {"New Files": []})
    monkeypatch.setattr(NewFiles, "pretty_print", lambda self: "")
    monkeypatch.setattr(DeletedFiles, "gather", lambda self: None)
    monkeypatch.setattr(DeletedFiles, "return_data", lambda self: {"Deleted Files": []})
    monkeypatch.setattr(DeletedFiles, "pretty_print", lambda self: "")
    monkeypatch.setattr(Player, "perform", lambda self: None)


def _make_controller(
    monkeypatch, tmp_path, **overrides
) -> tuple[RecordingController, _FakeToolbox, _FakeForensicService]:
    _patch_pipeline(monkeypatch)
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    monkeypatch.setenv("RAW_RESULTS_PATH", str(tmp_path) + os.sep)
    # run_history/run_bundle resolve their storage root config-first, so
    # isolate it to tmp_path (else the run bundle leaks into ./results/).
    fake_cfg = SimpleNamespace(paths=SimpleNamespace(results_path=tmp_path))
    monkeypatch.setattr("sandroid.config.get_config", lambda: fake_cfg)
    # A real recording.txt so run_bundle.import_recording (which the engine
    # path performs up-front) succeeds and the engine actually runs.
    (tmp_path / "recording.txt").write_text("0.0 /dev/input/event0 1 2 3\n")

    toolbox = _FakeToolbox()
    forensic = _FakeForensicService()
    action_window = _FakeActionWindow()

    defaults: dict = {
        "log_info": lambda *_: None,
        "log_warning": lambda *_: None,
        "log_error": lambda *_: None,
        "log_success": lambda *_: None,
        "call_from_thread": lambda fn, *args: fn(*args),
        "toolbox": toolbox,
    }
    defaults.update(overrides)
    controller = RecordingController(**defaults)
    monkeypatch.setattr(controller, "_get_forensic_service", lambda: forensic)
    monkeypatch.setattr(controller, "_get_action_window_service", lambda: action_window)
    return controller, toolbox, forensic


def _register_fake_monitor(config: MonitorConfig, stop_marker: list) -> None:
    get_task_service().register(
        name="monitor",
        display_name="Monitor",
        instance=SimpleNamespace(config=config),
        stop_callback=lambda: stop_marker.append(True),
    )


# =============================================================================
# _stop_monitor_before_revert in isolation
# =============================================================================


def test_stop_monitor_before_revert_is_true_noop_when_not_running(
    monkeypatch, tmp_path
):
    """(a) monitor not running: zero TaskService.stop calls, zero notice, zero
    callback firing, zero call_from_thread invocations at all.
    """
    call_from_thread_calls: list = []
    stopped_notice_calls: list = []

    controller, _toolbox, _forensic = _make_controller(
        monkeypatch,
        tmp_path,
        call_from_thread=lambda fn, *args: (
            call_from_thread_calls.append((fn, args)),
            fn(*args),
        )[1],
        on_monitor_stopped_for_playback=lambda: stopped_notice_calls.append(True),
    )

    assert not get_task_service().is_running("monitor")

    result = controller._stop_monitor_before_revert()

    assert result is None
    assert call_from_thread_calls == []
    assert stopped_notice_calls == []


def test_stop_monitor_before_revert_stops_task_and_returns_config(
    monkeypatch, tmp_path
):
    """(b) monitor running: TaskService.stop() actually runs (stop_callback
    fires, task is unregistered) and the notice callback fires.
    """
    stop_marker: list = []
    stopped_notice_calls: list = []
    config = MonitorConfig(mode="path", target_path="/data/")

    controller, _toolbox, _forensic = _make_controller(
        monkeypatch,
        tmp_path,
        on_monitor_stopped_for_playback=lambda: stopped_notice_calls.append(True),
    )
    _register_fake_monitor(config, stop_marker)

    result = controller._stop_monitor_before_revert()

    assert result is config
    assert stop_marker == [True]
    assert not get_task_service().is_running("monitor")
    assert stopped_notice_calls == [True]


def test_stop_monitor_before_revert_marshals_via_call_from_thread_off_main_thread(
    monkeypatch, tmp_path
):
    """(b) continued: verify the stop + notice genuinely marshal through
    call_from_thread when invoked from a real background thread — the
    actual shape of the call in production (start_playback dispatches
    _run_playback_analysis via run_worker(..., thread=True)).
    """
    config = MonitorConfig(mode="path", target_path="/data/")
    stop_marker: list = []
    stopped_notice_calls: list = []
    caller_threads: list = []

    def call_from_thread(fn, *args):
        # Real Textual call_from_thread asserts the CALLER is not the main
        # thread; emulate that contract-check here.
        caller_threads.append(threading.current_thread())
        return fn(*args)

    controller, _toolbox, _forensic = _make_controller(
        monkeypatch,
        tmp_path,
        call_from_thread=call_from_thread,
        on_monitor_stopped_for_playback=lambda: stopped_notice_calls.append(True),
    )
    _register_fake_monitor(config, stop_marker)

    result_holder: dict = {}

    def run_in_worker() -> None:
        result_holder["config"] = controller._stop_monitor_before_revert()

    worker = threading.Thread(target=run_in_worker)
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert result_holder["config"] is config
    assert stop_marker == [True]
    assert stopped_notice_calls == [True]
    # Every call_from_thread invocation was made FROM the worker thread, not
    # the thread running this test (standing in for "main").
    assert caller_threads
    for t in caller_threads:
        assert t is worker
        assert t is not threading.current_thread()


# =============================================================================
# _run_playback_analysis end-to-end (pipeline neutered, safety net exercised)
# =============================================================================


def test_run_playback_analysis_noop_when_monitor_not_running(monkeypatch, tmp_path):
    """(a) Full pipeline: with monitor not running, behavior is identical to
    before this feature existed — no stop, no notice, no resume offer.
    """
    stopped_notice_calls: list = []
    resume_calls: list = []
    controller, toolbox, _forensic = _make_controller(
        monkeypatch,
        tmp_path,
        on_monitor_stopped_for_playback=lambda: stopped_notice_calls.append(True),
        on_monitor_resume_available=resume_calls.append,
    )

    controller._run_playback_analysis()

    # The engine reverts to the tmp snapshot once per bracketed step (pre +
    # per-run), so there is >=1 call and every call targets b"tmp".
    assert toolbox.load_snapshot_calls
    assert set(toolbox.load_snapshot_calls) == {b"tmp"}
    assert stopped_notice_calls == []
    assert resume_calls == []


def test_run_playback_analysis_stops_monitor_and_offers_resume_on_success(
    monkeypatch, tmp_path
):
    stopped_notice_calls: list = []
    resume_calls: list = []
    controller, toolbox, _forensic = _make_controller(
        monkeypatch,
        tmp_path,
        on_monitor_stopped_for_playback=lambda: stopped_notice_calls.append(True),
        on_monitor_resume_available=resume_calls.append,
    )

    config = MonitorConfig(mode="pid", target_pid=1234, app_name="com.example.app")
    stop_marker: list = []
    _register_fake_monitor(config, stop_marker)

    controller._run_playback_analysis()

    # The safety-stop happened...
    assert stop_marker == [True]
    assert not get_task_service().is_running("monitor")
    assert stopped_notice_calls == [True]
    # ...the rest of the pipeline still ran normally (load_snapshot etc. is
    # unaffected by whether monitor was running)...
    assert toolbox.load_snapshot_calls
    assert set(toolbox.load_snapshot_calls) == {b"tmp"}
    # ...and the Resume offer fires exactly once, with the original config.
    assert resume_calls == [config]


def test_run_playback_analysis_offers_resume_even_when_pipeline_errors(
    monkeypatch, tmp_path
):
    """Resuming monitor is orthogonal to whether the diff analysis itself
    errored — the offer must still fire on a failed/partial run (the plan
    only requires "at minimum on success"; this deliberately does both).
    """
    monkeypatch.setattr(
        Player,
        "perform",
        lambda self: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    resume_calls: list = []
    controller, _toolbox, _forensic = _make_controller(
        monkeypatch,
        tmp_path,
        on_monitor_resume_available=resume_calls.append,
    )

    config = MonitorConfig(mode="path", target_path="/data/")
    _register_fake_monitor(config, [])

    controller._run_playback_analysis()

    assert resume_calls == [config]


def test_run_playback_analysis_resume_offer_absent_without_callback(
    monkeypatch, tmp_path
):
    """on_monitor_resume_available is optional — must not raise when unset,
    even though monitor was running and got auto-stopped.
    """
    controller, _toolbox, _forensic = _make_controller(monkeypatch, tmp_path)
    config = MonitorConfig(mode="path", target_path="/data/")
    _register_fake_monitor(config, [])

    controller._run_playback_analysis()  # must not raise

    assert not get_task_service().is_running("monitor")
