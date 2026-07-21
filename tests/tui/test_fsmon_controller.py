"""Unit tests for FSMonController's EventBus integration + open_files_tab hook.

Covers the two non-UI pieces of the Monitor sub-tab work:

1. ``_log_fsmon_output_batch`` now ALSO publishes every line as an
   ``EventType.TASK_OUTPUT`` event (``source="fsmon"``) on top of whatever it
   already did for the Activity Log — additive, not a replacement (verified
   by asserting the ``log_message`` callback still fires too).
2. ``_start_fsmon`` calls the injected ``open_files_tab`` callback once fsmon
   has actually started (after TaskService registration), not merely when
   the config modal opens.

No device/adb/network involved: ``FSMon.check_and_install_fsmon`` and
``FSMon.run_fsmon_by_path`` are monkeypatched to no-ops, and
``_start_output_reader`` (which spawns a real background thread reading a
subprocess's stdout) is stubbed out entirely since it is unrelated to what
this task changed.
"""

from __future__ import annotations

import pytest

from sandroid.core.events import Event, EventBus, EventType
from sandroid.core.fsmon import FSMon
from sandroid.services import get_task_service
from sandroid.tui.controllers.fsmon_controller import (
    FSMonConfig,
    FSMonController,
    colorize_fsmon_line,
)


@pytest.fixture(autouse=True)
def _clean_fsmon_task():
    """Guard the real (process-wide) TaskService singleton against leaks.

    ``_start_fsmon`` registers a "fsmon" task on the real TaskService
    singleton (there is no DI seam for it in this controller today); make
    sure no test in this file leaves that behind for later tests/files.
    """
    svc = get_task_service()
    svc._tasks.pop("fsmon", None)
    yield
    svc._tasks.pop("fsmon", None)


@pytest.fixture(autouse=True)
def _clean_eventbus_history():
    """Keep EventBus history from bleeding across tests (handlers are
    subscribed/unsubscribed explicitly per-test, but history is process-wide).
    """
    EventBus.get().clear_history()
    yield
    EventBus.get().clear_history()


def _make_controller(**overrides) -> FSMonController:
    defaults: dict = {
        "log_info": lambda *_: None,
        "log_warning": lambda *_: None,
        "log_error": lambda *_: None,
        "log_success": lambda *_: None,
        "call_from_thread": lambda fn, *args: fn(*args),
    }
    defaults.update(overrides)
    return FSMonController(**defaults)


def test_log_fsmon_output_batch_publishes_to_eventbus_for_every_line():
    """Every line in a batch gets its own TASK_OUTPUT/source="fsmon" event,
    not just the throttled last-5 slice the Activity Log gets.
    """
    received: list[Event] = []
    EventBus.get().subscribe(EventType.TASK_OUTPUT, received.append)
    try:
        log_message_calls: list[tuple[str, str]] = []
        controller = _make_controller(
            log_message=lambda msg, source: log_message_calls.append((msg, source))
        )

        lines = [f"CREATE /data/file_{i}.txt" for i in range(8)]
        controller._log_fsmon_output_batch(lines)

        # Additive: the existing Activity Log path still fires (throttled to
        # the last 5 lines) — this must NOT have been removed.
        assert len(log_message_calls) == 5
        for _msg, source in log_message_calls:
            assert source == "FSMon"

        # New: EventBus gets EVERY line, not just the throttled subset.
        assert len(received) == len(lines)
        for event, line in zip(received, lines, strict=True):
            assert event.source == "fsmon"
            assert event.data["task_name"] == "FSMon"
            assert event.data["message"] == colorize_fsmon_line(line)
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, received.append)


def test_log_fsmon_output_batch_reuses_colorize_fsmon_line():
    """The published message is exactly colorize_fsmon_line's output (no
    re-implementation of the CREATE/DELETE/RENAME/OPEN coloring rules).
    """
    received: list[Event] = []
    EventBus.get().subscribe(EventType.TASK_OUTPUT, received.append)
    try:
        controller = _make_controller()
        controller._log_fsmon_output_batch(["DELETE /data/gone.txt"])
        assert len(received) == 1
        assert received[0].data["message"] == colorize_fsmon_line(
            "DELETE /data/gone.txt"
        )
        assert "[red]" in received[0].data["message"]
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, received.append)


def test_task_output_events_filterable_by_source(monkeypatch):
    """A subscriber filtering on source == "fsmon" must not see events from
    an unrelated task publishing the same EventType (mirrors how
    MonitorView/FriTapPanel filter their own stream).
    """
    seen_fsmon: list[Event] = []

    def handler(event: Event) -> None:
        if event.source == "fsmon":
            seen_fsmon.append(event)

    EventBus.get().subscribe(EventType.TASK_OUTPUT, handler)
    try:
        controller = _make_controller()
        controller._log_fsmon_output_batch(["OPEN /data/read.txt"])

        # An unrelated task publishing the same EventType/shape must be
        # ignored by the source filter.
        EventBus.get().publish(
            Event(
                type=EventType.TASK_OUTPUT,
                data={"task_name": "FriTap", "message": "unrelated"},
                source="fritap",
            )
        )

        assert len(seen_fsmon) == 1
        assert seen_fsmon[0].data["message"] == colorize_fsmon_line(
            "OPEN /data/read.txt"
        )
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, handler)


def test_start_fsmon_calls_open_files_tab_after_successful_start(monkeypatch):
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_path", classmethod(lambda cls, path: object())
    )
    monkeypatch.setattr(
        FSMonController, "_start_output_reader", lambda self, wrapper: None
    )

    open_files_tab_calls = []
    controller = _make_controller(
        open_files_tab=lambda: open_files_tab_calls.append(True)
    )

    config = FSMonConfig(mode="path", target_path="/data/")
    started = controller._start_fsmon(config)

    assert started is True
    assert open_files_tab_calls == [True]
    assert get_task_service().is_running("fsmon")


def test_start_fsmon_does_not_call_open_files_tab_on_failure(monkeypatch):
    """If fsmon fails to start, the Files tab must NOT be jumped to."""

    def _boom(cls):
        raise RuntimeError("no binary")

    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(_boom))

    open_files_tab_calls = []
    controller = _make_controller(
        open_files_tab=lambda: open_files_tab_calls.append(True)
    )

    config = FSMonConfig(mode="path", target_path="/data/")
    started = controller._start_fsmon(config)

    assert started is False
    assert open_files_tab_calls == []
    assert not get_task_service().is_running("fsmon")


def test_start_fsmon_works_without_open_files_tab_callback(monkeypatch):
    """open_files_tab is optional (defaults to None) — must not raise."""
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_path", classmethod(lambda cls, path: object())
    )
    monkeypatch.setattr(
        FSMonController, "_start_output_reader", lambda self, wrapper: None
    )

    controller = _make_controller()  # no open_files_tab kwarg
    config = FSMonConfig(mode="path", target_path="/data/")
    started = controller._start_fsmon(config)

    assert started is True


# =============================================================================
# resume_after_playback — "Resume monitoring" after Play's snapshot-revert
# safety stop (RecordingController._stop_fsmon_before_revert stops fsmon;
# this is the other half, re-forking it once Play is done).
# =============================================================================


def _patch_start_fsmon_ok(monkeypatch):
    """Make _start_fsmon succeed without touching adb/a real process."""
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_path", classmethod(lambda cls, path: object())
    )
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_pid", classmethod(lambda cls, pid, path=None: object())
    )
    monkeypatch.setattr(
        FSMonController, "_start_output_reader", lambda self, wrapper: None
    )


def test_resume_after_playback_with_no_config_fails_without_starting(monkeypatch):
    _patch_start_fsmon_ok(monkeypatch)
    start_calls = []
    monkeypatch.setattr(
        FSMonController,
        "_start_fsmon",
        lambda self, cfg: start_calls.append(cfg) or True,
    )

    controller = _make_controller()
    assert controller.resume_after_playback(None) is False
    assert start_calls == []


def test_resume_after_playback_noop_when_already_running(monkeypatch):
    _patch_start_fsmon_ok(monkeypatch)
    controller = _make_controller()
    config = FSMonConfig(mode="path", target_path="/data/")

    # Start a real (fake) fsmon session first.
    assert controller._start_fsmon(config) is True
    assert controller.is_running()

    start_calls = []
    monkeypatch.setattr(
        FSMonController,
        "_start_fsmon",
        lambda self, cfg: start_calls.append(cfg) or True,
    )
    assert controller.resume_after_playback(config) is False
    assert start_calls == []


def test_resume_after_playback_path_mode_reuses_config_unchanged(monkeypatch):
    """Path-mode configs have no PID to go stale — resume just re-forks as-is,
    no Adb.get_pid_for_package_name call at all.
    """
    _patch_start_fsmon_ok(monkeypatch)
    controller = _make_controller()
    config = FSMonConfig(mode="path", target_path="/data/local/tmp/")

    assert controller.resume_after_playback(config) is True
    assert controller.is_running()


def test_resume_after_playback_pid_mode_reresolves_stale_pid(monkeypatch):
    """The core PID-mode staleness fix: the stored target_pid (from before
    Play) must NOT be trusted — a fresh PID is re-resolved from app_name.
    """
    _patch_start_fsmon_ok(monkeypatch)

    from sandroid.core.adb import Adb

    monkeypatch.setattr(
        Adb,
        "get_pid_for_package_name",
        classmethod(lambda cls, pkg, use_frida_fallback=True, quiet=False: 9999),
    )

    start_calls = []
    monkeypatch.setattr(
        FSMonController,
        "_start_fsmon",
        lambda self, cfg: start_calls.append(cfg) or True,
    )

    controller = _make_controller()
    stale_config = FSMonConfig(
        mode="pid", target_pid=1111, app_name="com.example.app", target_path="/data/"
    )

    assert controller.resume_after_playback(stale_config) is True
    assert len(start_calls) == 1
    resolved = start_calls[0]
    assert resolved.mode == "pid"
    assert resolved.target_pid == 9999  # re-resolved, NOT the stale 1111
    assert resolved.app_name == "com.example.app"


def test_resume_after_playback_falls_back_to_path_mode_when_pid_unresolvable(
    monkeypatch,
):
    """App no longer running (PID unresolvable) but a target_path was
    configured — fall back to path-mode instead of forking against a dead
    PID.
    """
    _patch_start_fsmon_ok(monkeypatch)

    from sandroid.core.adb import Adb

    monkeypatch.setattr(
        Adb,
        "get_pid_for_package_name",
        classmethod(lambda cls, pkg, use_frida_fallback=True, quiet=False: None),
    )

    start_calls = []
    monkeypatch.setattr(
        FSMonController,
        "_start_fsmon",
        lambda self, cfg: start_calls.append(cfg) or True,
    )
    warnings = []
    controller = _make_controller(log_warning=warnings.append)
    stale_config = FSMonConfig(
        mode="pid",
        target_pid=1111,
        app_name="com.example.app",
        target_path="/data/local/tmp/",
    )

    assert controller.resume_after_playback(stale_config) is True
    assert len(start_calls) == 1
    resolved = start_calls[0]
    assert resolved.mode == "path"
    assert resolved.target_path == "/data/local/tmp/"
    assert resolved.target_pid is None
    assert any("no longer running" in w for w in warnings)


def test_resume_after_playback_refuses_to_start_when_nothing_resolvable(monkeypatch):
    """Neither a fresh PID nor a target_path — must NOT fork against a dead
    PID; refuse explicitly with a warning instead of silently failing.
    """
    _patch_start_fsmon_ok(monkeypatch)

    from sandroid.core.adb import Adb

    monkeypatch.setattr(
        Adb,
        "get_pid_for_package_name",
        classmethod(lambda cls, pkg, use_frida_fallback=True, quiet=False: None),
    )

    start_calls = []
    monkeypatch.setattr(
        FSMonController,
        "_start_fsmon",
        lambda self, cfg: start_calls.append(cfg) or True,
    )
    warnings = []
    controller = _make_controller(log_warning=warnings.append)
    stale_config = FSMonConfig(
        mode="pid", target_pid=1111, app_name="com.example.app", target_path=""
    )

    assert controller.resume_after_playback(stale_config) is False
    assert start_calls == []
    assert any("Could not resume" in w for w in warnings)
