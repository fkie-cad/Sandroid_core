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


@pytest.fixture(autouse=True)
def _clean_recording_task():
    """Guard the real (process-wide) TaskService singleton against leaks.

    Same reasoning as ``_clean_monitor_task`` above, for the "recording" task
    the new ``start_recording_chat``/``stop_recording_chat`` tests register.
    """
    svc = get_task_service()
    svc._tasks.pop("recording", None)
    yield
    svc._tasks.pop("recording", None)


class _FakeToolbox:
    """Stand-in for Toolbox: just enough surface for _run_playback_analysis."""

    device_name = "fake-device"

    def __init__(self, create_snapshot_error: Exception | None = None) -> None:
        self.load_snapshot_calls: list = []
        self.create_snapshot_calls: list = []
        self._create_snapshot_error = create_snapshot_error

    def load_snapshot(self, tag) -> None:
        self.load_snapshot_calls.append(tag)

    def create_snapshot(self, tag) -> None:
        self.create_snapshot_calls.append(tag)
        if self._create_snapshot_error is not None:
            raise self._create_snapshot_error

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


# =============================================================================
# start_recording_chat / stop_recording_chat -- AI-chat headless entry points
#
# Both run on the AI tool-dispatch thread (never Textual's main thread), so
# every call touching a UI callback must go through call_from_thread -- the
# same threading-discipline contract _stop_monitor_before_revert's tests
# above already verify for the modal-driven path. The tests below reuse that
# real-background-thread verification technique for the new chat methods.
# =============================================================================


class _FakeRecordingWrapper:
    """Stand-in for RecordingWrapper -- no real getevent process spawned."""

    def __init__(self, output_file: str, start_ok: bool = True) -> None:
        self.output_file = output_file
        self._start_ok = start_ok
        self.stop_calls = 0
        self.event_count = 7
        self.elapsed_seconds = 4.0

    def start(self) -> bool:
        return self._start_ok

    def stop(self) -> None:
        self.stop_calls += 1


def test_start_recording_chat_already_recording_returns_failure(monkeypatch, tmp_path):
    call_from_thread_calls: list = []
    controller, toolbox, _forensic = _make_controller(
        monkeypatch,
        tmp_path,
        call_from_thread=lambda fn, *args: (
            call_from_thread_calls.append((fn, args)),
            fn(*args),
        )[1],
    )
    get_task_service().register(
        name="recording",
        display_name="Recording",
        instance=object(),
        stop_callback=lambda: None,
    )

    result = controller.start_recording_chat("my run")

    assert result == {"success": False, "message": "Recording already in progress"}
    assert call_from_thread_calls == []
    assert toolbox.create_snapshot_calls == []
    get_task_service().stop("recording")


def test_start_recording_chat_snapshot_failure_marshals_disconnect_guard(
    monkeypatch, tmp_path
):
    """Both the arm (True) and disarm (False) of the disconnect guard must go
    through call_from_thread -- even on the failure path, where the arm/
    disarm bracket a raising create_snapshot() call rather than the recorder
    itself.
    """
    guard_calls: list = []
    call_from_thread_calls: list = []
    controller, toolbox, _forensic = _make_controller(
        monkeypatch,
        tmp_path,
        call_from_thread=lambda fn, *args: (
            call_from_thread_calls.append((fn, args)),
            fn(*args),
        )[1],
        suppress_disconnect_guard=guard_calls.append,
    )
    toolbox._create_snapshot_error = RuntimeError("adb wedged")

    result = controller.start_recording_chat("my run")

    assert result["success"] is False
    assert "adb wedged" in result["message"]
    assert guard_calls == [True, False]
    assert len(call_from_thread_calls) == 2
    assert not get_task_service().is_running("recording")


def test_start_recording_chat_success_marshals_ui_via_call_from_thread_off_main_thread(
    monkeypatch, tmp_path
):
    """End-to-end success path, invoked from a REAL background thread (the
    actual shape in production: the AI tool-dispatch thread) -- confirms the
    indicator/log calls genuinely marshal through call_from_thread rather
    than merely being reachable in a single-threaded test.
    """
    indicator_calls: list = []
    log_calls: list = []
    caller_threads: list = []

    def call_from_thread(fn, *args):
        # Real Textual call_from_thread asserts the CALLER is not the main
        # thread; emulate that contract-check here (same convention as
        # test_stop_monitor_before_revert_marshals_via_call_from_thread_off_main_thread
        # above).
        caller_threads.append(threading.current_thread())
        return fn(*args)

    fake_wrapper = _FakeRecordingWrapper(output_file="/tmp/recording.txt")
    monkeypatch.setattr(
        "sandroid.tui.utils.recording_wrapper.RecordingWrapper",
        lambda output_file: fake_wrapper,
    )

    controller, toolbox, _forensic = _make_controller(
        monkeypatch,
        tmp_path,
        call_from_thread=call_from_thread,
        set_recording_indicator=indicator_calls.append,
        log_info=log_calls.append,
    )

    result_holder: dict = {}

    def run_in_worker() -> None:
        result_holder["result"] = controller.start_recording_chat(
            "my run", number_of_runs=4, noise_filter=False
        )

    worker = threading.Thread(target=run_in_worker)
    worker.start()
    worker.join(timeout=5)

    try:
        assert not worker.is_alive()
        result = result_holder["result"]
        assert result == {"success": True, "label": "my run"}
        assert toolbox.create_snapshot_calls == [b"tmp"]
        assert get_task_service().is_running("recording")
        assert indicator_calls == [True]
        assert any("my run" in msg for msg in log_calls)
        assert controller._current_number_of_runs == 4
        assert controller._current_noise_filter is False
        # Every UI-touching call was marshaled FROM the worker thread, never
        # the thread running this test (standing in for "main").
        assert caller_threads
        for t in caller_threads:
            assert t is worker
            assert t is not threading.current_thread()
    finally:
        get_task_service().stop("recording")


def test_stop_recording_chat_not_recording_returns_failure(monkeypatch, tmp_path):
    controller, _toolbox, _forensic = _make_controller(monkeypatch, tmp_path)

    result = controller.stop_recording_chat()

    assert result == {"success": False, "message": "No recording in progress"}


def test_stop_recording_chat_success_marshals_via_call_from_thread_off_main_thread(
    monkeypatch, tmp_path
):
    indicator_calls: list = []
    log_calls: list = []
    caller_threads: list = []

    def call_from_thread(fn, *args):
        caller_threads.append(threading.current_thread())
        return fn(*args)

    controller, _toolbox, _forensic = _make_controller(
        monkeypatch,
        tmp_path,
        call_from_thread=call_from_thread,
        set_recording_indicator=indicator_calls.append,
        log_success=log_calls.append,
    )
    controller._current_recording_label = "my run"
    fake_wrapper = _FakeRecordingWrapper(output_file="/tmp/recording.txt")
    fake_wrapper.event_count = 12
    fake_wrapper.elapsed_seconds = 9.0
    get_task_service().register(
        name="recording",
        display_name="Recording",
        instance=fake_wrapper,
        stop_callback=fake_wrapper.stop,
    )

    result_holder: dict = {}

    def run_in_worker() -> None:
        result_holder["result"] = controller.stop_recording_chat()

    worker = threading.Thread(target=run_in_worker)
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive()
    result = result_holder["result"]
    assert result == {
        "success": True,
        "event_count": 12,
        "duration": 9.0,
        "label": "my run",
    }
    assert fake_wrapper.stop_calls == 1
    assert not get_task_service().is_running("recording")
    assert indicator_calls == [False]
    assert log_calls
    assert caller_threads
    for t in caller_threads:
        assert t is worker
        assert t is not threading.current_thread()


# =============================================================================
# start_playback_chat / _release_replay_world_lease -- Part D's WORLD lease
#
# start_replay (ai/tools/recording_control.py) claims ResourceId.WORLD but
# declares releases=frozenset() -- deliberately NOT auto-released when the
# tool call itself returns, since the real replay work runs on a detached
# background worker. These tests exercise the OTHER half of that pattern:
# _run_playback_analysis's own finally releasing the lease once the replay
# actually finishes. Since none of these tests inject run_worker,
# start_playback() falls back to running _run_playback_analysis()
# synchronously (see that method's own source) -- so by the time
# start_playback_chat() returns here, the full deferred-release path has
# already run, and the lease must already be gone.
# =============================================================================


def test_start_playback_chat_no_recording_does_not_stash_owner(monkeypatch, tmp_path):
    controller, _toolbox, _forensic = _make_controller(monkeypatch, tmp_path)
    # _make_controller writes a real recording.txt for the common case --
    # remove it so has_recording() is False for this one test.
    (tmp_path / "recording.txt").unlink()

    result = controller.start_playback_chat(owner_id="owner-A")

    assert result == {
        "success": False,
        "message": "No recording found — record first",
    }
    assert controller._replay_owner_id is None


def test_start_playback_chat_already_recording_does_not_stash_owner(
    monkeypatch, tmp_path
):
    controller, _toolbox, _forensic = _make_controller(monkeypatch, tmp_path)
    get_task_service().register(
        name="recording",
        display_name="Recording",
        instance=object(),
        stop_callback=lambda: None,
    )

    result = controller.start_playback_chat(owner_id="owner-A")

    assert result["success"] is False
    assert controller._replay_owner_id is None
    get_task_service().stop("recording")


def test_start_playback_chat_releases_world_lease_once_replay_completes(
    monkeypatch, tmp_path
):
    """The core of Part D's deferred-release pattern."""
    from sandroid.ai import arbiter as ai_arbiter

    fresh_arbiter = ai_arbiter.DeviceResourceArbiter()
    monkeypatch.setattr(ai_arbiter, "get_arbiter", lambda: fresh_arbiter)
    fresh_arbiter.claim("owner-A", frozenset({ai_arbiter.ResourceId.WORLD}))

    controller, _toolbox, _forensic = _make_controller(monkeypatch, tmp_path)

    result = controller.start_playback_chat(owner_id="owner-A")

    assert result["success"] is True
    # No run_worker was injected, so start_playback() ran
    # _run_playback_analysis() synchronously -- by the time this call
    # returns, the lease has already been released.
    assert fresh_arbiter.snapshot() == {}
    assert controller._replay_owner_id is None


def test_start_playback_chat_releases_world_lease_even_on_pipeline_error(
    monkeypatch, tmp_path
):
    """_release_replay_world_lease must fire from the OUTERMOST finally --
    a pipeline error must not leak the lease.
    """
    from sandroid.ai import arbiter as ai_arbiter

    monkeypatch.setattr(
        Player,
        "perform",
        lambda self: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    fresh_arbiter = ai_arbiter.DeviceResourceArbiter()
    monkeypatch.setattr(ai_arbiter, "get_arbiter", lambda: fresh_arbiter)
    fresh_arbiter.claim("owner-A", frozenset({ai_arbiter.ResourceId.WORLD}))

    controller, _toolbox, _forensic = _make_controller(monkeypatch, tmp_path)

    controller.start_playback_chat(owner_id="owner-A")

    assert fresh_arbiter.snapshot() == {}


def test_start_playback_chat_manual_call_never_touches_arbiter(monkeypatch, tmp_path):
    """owner_id=None (manual/keybinding replay) must never call the arbiter
    at all -- guarded by ``if self._replay_owner_id:`` in
    _release_replay_world_lease.
    """
    from sandroid.ai import arbiter as ai_arbiter

    get_arbiter_calls: list = []

    def _tracking_get_arbiter():
        get_arbiter_calls.append(True)
        return ai_arbiter.DeviceResourceArbiter()

    monkeypatch.setattr(ai_arbiter, "get_arbiter", _tracking_get_arbiter)

    controller, _toolbox, _forensic = _make_controller(monkeypatch, tmp_path)

    result = controller.start_playback_chat()  # owner_id defaults to None

    assert result["success"] is True
    assert controller._replay_owner_id is None
    assert get_arbiter_calls == []
