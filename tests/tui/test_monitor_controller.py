"""Unit tests for MonitorController's EventBus integration + open_files_tab hook.

Covers the non-UI pieces of the Monitor sub-tab work:

1. ``_log_monitor_output_batch`` publishes the WHOLE BATCH as a SINGLE
   ``EventType.TASK_OUTPUT`` event (``source="monitor"``, ``data["batch"]`` a
   list of structured ``FileSystemMonitorItem``s -- one per parsed line), not one
   event per line (Part B -- grouping/dedup/visibility-filtering/tallying/
   width-aware rendering all now live in ``MonitorView``, not here). Bus-
   publish only, the old direct Background-Activity-log call was removed
   (Background Activity now gets monitor lines only via
   ``TASK_STARTED``/``TASK_STOPPED`` lifecycle notices, not ``TASK_OUTPUT``;
   see ``MainScreen``'s ``_ACTIVITY_LOG_EXCLUDED_SOURCES``).
2. ``_start_monitor`` calls the injected ``open_files_tab`` callback once monitor
   has actually started (after TaskService registration), not merely when
   the config modal opens.
3. ``parse_monitor_line``/``MONITOR_EVENT_INFO``/``format_monitor_event_row``/
   ``build_monitor_item`` -- the real ``FSE_*`` tab-separated wire
   format, exact-token color/category lookup (fixing the old substring-
   matching bug where ``FSE_CONTENT_MODIFIED``/``FSE_CLOSE`` got zero
   color), and path prefix-stripping/truncation/directory-filename
   splitting.

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
from sandroid.core.kprobe_tracer import KprobeTracer
from sandroid.services import get_task_service
from sandroid.tui.controllers.monitor_controller import (
    MONITOR_EVENT_INFO,
    FileSystemMonitorItem,
    KprobeStreamTranslator,
    MonitorConfig,
    MonitorController,
    MonitorEvent,
    build_monitor_item,
    colorize_monitor_line,
    format_monitor_event_row,
    parse_monitor_line,
)


@pytest.fixture(autouse=True)
def _clean_monitor_task():
    """Guard the real (process-wide) TaskService singleton against leaks.

    ``_start_monitor`` registers a "monitor" task on the real TaskService
    singleton (there is no DI seam for it in this controller today); make
    sure no test in this file leaves that behind for later tests/files.
    """
    svc = get_task_service()
    svc._tasks.pop("monitor", None)
    yield
    svc._tasks.pop("monitor", None)


@pytest.fixture(autouse=True)
def _clean_eventbus_history():
    """Keep EventBus history from bleeding across tests (handlers are
    subscribed/unsubscribed explicitly per-test, but history is process-wide).
    """
    EventBus.get().clear_history()
    yield
    EventBus.get().clear_history()


@pytest.fixture(autouse=True)
def _default_kprobe_unsupported(monkeypatch):
    """Default every test in this file to the fsmon path.

    ``_start_monitor`` now selects a backend: in "auto" (the default) it runs
    the kprobe preflight first. These controller tests exercise the fsmon
    behavior, so default ``kprobe_supported`` to False (device lacks kprobe
    support -> falls back to fsmon). The backend-selection tests below override
    this in-body. Also guards KprobeTracer's per-serial cache across tests.
    """
    KprobeTracer._kprobe_cache.clear()
    monkeypatch.setattr(
        KprobeTracer, "kprobe_supported", classmethod(lambda cls: False)
    )
    # A kprobe session's teardown reads the ring buffer's overrun counters
    # (an adb call): no device here.
    monkeypatch.setattr(KprobeTracer, "read_lost_events", classmethod(lambda c: None))
    yield
    KprobeTracer._kprobe_cache.clear()


def _make_controller(**overrides) -> MonitorController:
    defaults: dict = {
        "log_info": lambda *_: None,
        "log_warning": lambda *_: None,
        "log_error": lambda *_: None,
        "log_success": lambda *_: None,
        "call_from_thread": lambda fn, *args: fn(*args),
        # Run the (normally off-thread) kprobe preflight synchronously so tests
        # are deterministic; production defaults to a daemon thread.
        "run_off_thread": lambda fn: fn(),
    }
    defaults.update(overrides)
    return MonitorController(**defaults)


def _fse(
    event_type: str, path: str, pid: int = 123, process: str = "com.example.app"
) -> str:
    """Build a real tab-separated monitor wire-format line for tests."""
    return f'{event_type}\t{pid}\t"{process}"\t{path}'


def test_log_monitor_output_batch_publishes_one_event_for_the_whole_batch():
    """Part B: the WHOLE BATCH is published as a SINGLE TASK_OUTPUT event
    (``data["batch"]`` a list of structured items), not one event per line.

    Bus-publish only: the old direct Background-Activity-log call was
    removed (Problem 1) -- there is no more ``log_message`` callback on
    ``MonitorController`` at all.
    """
    received: list[Event] = []
    EventBus.get().subscribe(EventType.TASK_OUTPUT, received.append)
    try:
        controller = _make_controller()

        lines = [_fse("FSE_CREATE_FILE", f"/data/file_{i}.txt") for i in range(8)]
        controller._log_monitor_output_batch(lines)

        # ONE event for the whole batch now, not one per line.
        assert len(received) == 1
        event = received[0]
        assert event.source == "monitor"
        assert event.data["task_name"] == "Monitor"

        batch = event.data["batch"]
        assert len(batch) == len(lines)
        for item, i in zip(batch, range(len(lines)), strict=True):
            assert item.category == "create"
            assert item.label == "CREATE"
            assert item.directory == "/data"
            assert item.filename == f"file_{i}.txt"
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, received.append)


def test_log_monitor_output_batch_does_not_call_removed_log_message_kwarg():
    """``log_message`` is no longer a constructor parameter -- passing it
    must raise TypeError (confirms the dead param was actually removed).
    """
    with pytest.raises(TypeError):
        MonitorController(log_message=lambda *_: None)


def test_log_monitor_output_batch_reuses_build_monitor_item():
    """The published batch's items are exactly what
    ``build_monitor_item`` produces (no re-implementation of the
    parsing/color/category lookup a second time).
    """
    received: list[Event] = []
    EventBus.get().subscribe(EventType.TASK_OUTPUT, received.append)
    try:
        controller = _make_controller()
        line = _fse("FSE_DELETE", "/data/gone.txt")
        controller._log_monitor_output_batch([line])
        assert len(received) == 1
        batch = received[0].data["batch"]
        assert len(batch) == 1
        assert batch[0] == build_monitor_item(line)
        assert batch[0].category == "delete"
        assert batch[0].color == "#fb7185"
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, received.append)


def test_log_monitor_output_batch_empty_lines_publishes_nothing():
    """An empty batch must not publish an empty/no-op event at all."""
    received: list[Event] = []
    EventBus.get().subscribe(EventType.TASK_OUTPUT, received.append)
    try:
        controller = _make_controller()
        controller._log_monitor_output_batch([])
        assert received == []
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, received.append)


def test_task_output_events_filterable_by_source(monkeypatch):
    """A subscriber filtering on source == "monitor" must not see events from
    an unrelated task publishing the same EventType (mirrors how
    MonitorView/FriTapPanel filter their own stream).
    """
    seen_monitor: list[Event] = []

    def handler(event: Event) -> None:
        if event.source == "monitor":
            seen_monitor.append(event)

    EventBus.get().subscribe(EventType.TASK_OUTPUT, handler)
    try:
        controller = _make_controller()
        line = _fse("FSE_OPEN", "/data/read.txt")
        controller._log_monitor_output_batch([line])

        # An unrelated task publishing the same EventType/shape must be
        # ignored by the source filter.
        EventBus.get().publish(
            Event(
                type=EventType.TASK_OUTPUT,
                data={"task_name": "FriTap", "message": "unrelated"},
                source="fritap",
            )
        )

        assert len(seen_monitor) == 1
        batch = seen_monitor[0].data["batch"]
        assert len(batch) == 1
        assert batch[0].category == "noise"
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, handler)


# =============================================================================
# parse_monitor_line / MONITOR_EVENT_INFO / format_monitor_event_row
# =============================================================================


def test_parse_monitor_line_valid():
    line = _fse("FSE_CREATE_FILE", "/data/data/com.example.app/file.txt", pid=456)
    event = parse_monitor_line(line)
    assert event == MonitorEvent(
        event_type="FSE_CREATE_FILE",
        pid=456,
        process="com.example.app",
        path="/data/data/com.example.app/file.txt",
        new_path=None,
    )


def test_parse_monitor_line_rename_splits_old_and_new_path():
    line = 'FSE_RENAME\t789\t"com.example.app"\t/data/old.txt -> /data/new.txt'
    event = parse_monitor_line(line)
    assert event is not None
    assert event.event_type == "FSE_RENAME"
    assert event.path == "/data/old.txt"
    assert event.new_path == "/data/new.txt"


def test_parse_monitor_line_malformed_returns_none():
    assert parse_monitor_line("not a valid monitor line") is None
    assert parse_monitor_line("FSE_CREATE_FILE\t123") is None
    assert parse_monitor_line("") is None


def test_monitor_event_info_spot_check():
    assert MONITOR_EVENT_INFO["FSE_CREATE_FILE"].label == "CREATE"
    assert MONITOR_EVENT_INFO["FSE_CREATE_FILE"].category == "create"
    assert MONITOR_EVENT_INFO["FSE_CONTENT_MODIFIED"].label == "MODIFY"
    assert MONITOR_EVENT_INFO["FSE_CONTENT_MODIFIED"].category == "modify"
    assert MONITOR_EVENT_INFO["FSE_CONTENT_MODIFIED"].color == "#a78bfa"
    assert MONITOR_EVENT_INFO["FSE_DELETE"].category == "delete"
    assert MONITOR_EVENT_INFO["FSE_RENAME"].category == "rename"
    assert MONITOR_EVENT_INFO["FSE_ATTRIB"].category == "attrs"
    assert MONITOR_EVENT_INFO["FSE_STAT_CHANGED"].category == "attrs"
    assert MONITOR_EVENT_INFO["FSE_XATTR_MODIFIED"].category == "attrs"
    assert MONITOR_EVENT_INFO["FSE_OPEN"].category == "noise"
    assert MONITOR_EVENT_INFO["FSE_CLOSE"].category == "noise"


def test_monitor_content_modified_and_close_get_correct_colors_regression():
    """Direct regression test for the literal bug being fixed: the old
    substring-keyword matching missed FSE_CONTENT_MODIFIED (not a substring
    match for "MODIFY") and FSE_CLOSE (no rule mentioned it at all), so both
    got zero color/category. Exact-token lookup must fix both.
    """
    modified_line = _fse("FSE_CONTENT_MODIFIED", "/data/file.txt")
    close_line = _fse("FSE_CLOSE", "/data/file.txt")

    modified_colorized = colorize_monitor_line(modified_line)
    close_colorized = colorize_monitor_line(close_line)

    assert "#a78bfa" in modified_colorized
    assert "#5b6479" in close_colorized

    _, modified_category = format_monitor_event_row(modified_line)
    _, close_category = format_monitor_event_row(close_line)
    assert modified_category == "modify"
    assert close_category == "noise"


def test_format_monitor_event_row_strips_prefix_and_truncates():
    long_suffix = "a" * 50
    line = _fse(
        "FSE_CREATE_FILE",
        f"/data/data/com.example.app/cache/{long_suffix}/file.txt",
    )
    prefix_candidates = ("/data/data/com.example.app/",)
    message, category = format_monitor_event_row(line, prefix_candidates)

    assert category == "create"
    # Redundant package prefix must be gone.
    assert "/data/data/com.example.app/" not in message
    # Long remainder must be left-truncated keeping the tail.
    assert "…" in message
    assert message.endswith("file.txt")


def test_format_monitor_event_row_unparseable_line_falls_back_gracefully():
    message, category = format_monitor_event_row("totally not monitor output")
    assert category is None
    assert message  # never silently dropped
    assert "totally not monitor output" in message


def test_format_monitor_event_row_unknown_token_falls_back_gracefully():
    line = _fse("FSE_SOMETHING_NEW", "/data/file.txt")
    message, category = format_monitor_event_row(line)
    assert category is None
    assert "FSE_SOMETHING_NEW" in message
    assert "/data/file.txt" in message


# =============================================================================
# build_monitor_item -- structured per-item data for MonitorView's own
# grouping/dedup/rendering pipeline (Part B, B1)
# =============================================================================


def test_build_monitor_item_splits_directory_and_filename():
    line = _fse("FSE_CREATE_FILE", "/data/data/com.example.app/cache/sub/file.txt")
    item = build_monitor_item(line, ("/data/data/com.example.app/",))

    assert item == FileSystemMonitorItem(
        label="CREATE",
        color="#4ade80",
        category="create",
        directory="cache/sub",
        filename="file.txt",
        new_directory=None,
        new_filename=None,
    )


def test_build_monitor_item_bare_filename_has_empty_directory():
    """A path with no '/' at all (after prefix-stripping) yields an empty
    directory -- never groups into a breadcrumb run with anything else.
    """
    item = build_monitor_item(_fse("FSE_CREATE_FILE", "bare.txt"))
    assert item.directory == ""
    assert item.filename == "bare.txt"


def test_build_monitor_item_rename_splits_old_and_new_directory():
    line = _fse(
        "FSE_RENAME",
        "/data/data/com.example.app/cache/old.txt -> /data/data/com.example.app/cache/new.txt",
    )
    item = build_monitor_item(line, ("/data/data/com.example.app/",))
    assert item.directory == "cache"
    assert item.filename == "old.txt"
    assert item.new_directory == "cache"
    assert item.new_filename == "new.txt"


def test_build_monitor_item_rename_with_different_new_directory():
    line = _fse(
        "FSE_RENAME",
        "/data/data/com.example.app/cache/old.txt -> /data/data/com.example.app/moved/new.txt",
    )
    item = build_monitor_item(line, ("/data/data/com.example.app/",))
    assert item.directory == "cache"
    assert item.new_directory == "moved"


def test_build_monitor_item_unknown_token_falls_back_gracefully():
    line = _fse("FSE_SOMETHING_NEW", "/data/file.txt")
    item = build_monitor_item(line)
    assert item.label == "FSE_SOMETHING_NEW"
    assert item.color is None
    assert item.category is None
    assert item.directory == "/data"
    assert item.filename == "file.txt"


def test_build_monitor_item_malformed_line_never_raises_or_drops():
    item = build_monitor_item("totally not monitor output")
    assert item.category is None
    assert item.directory == ""
    assert item.filename == "totally not monitor output"


def test_start_monitor_calls_open_files_tab_after_successful_start(monkeypatch):
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_path", classmethod(lambda cls, path: object())
    )
    monkeypatch.setattr(
        MonitorController, "_start_output_reader", lambda self, wrapper: None
    )

    open_files_tab_calls = []
    controller = _make_controller(
        open_files_tab=lambda: open_files_tab_calls.append(True)
    )

    config = MonitorConfig(mode="path", target_path="/data/")
    started = controller._start_monitor(config)

    assert started is True
    assert open_files_tab_calls == [True]
    assert get_task_service().is_running("monitor")


def test_start_monitor_does_not_call_open_files_tab_on_failure(monkeypatch):
    """If monitor fails to start, the Files tab must NOT be jumped to."""

    def _boom(cls):
        raise RuntimeError("no binary")

    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(_boom))

    open_files_tab_calls = []
    controller = _make_controller(
        open_files_tab=lambda: open_files_tab_calls.append(True)
    )

    config = MonitorConfig(mode="path", target_path="/data/")
    started = controller._start_monitor(config)

    assert started is False
    assert open_files_tab_calls == []
    assert not get_task_service().is_running("monitor")


def test_start_monitor_works_without_open_files_tab_callback(monkeypatch):
    """open_files_tab is optional (defaults to None) — must not raise."""
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_path", classmethod(lambda cls, path: object())
    )
    monkeypatch.setattr(
        MonitorController, "_start_output_reader", lambda self, wrapper: None
    )

    controller = _make_controller()  # no open_files_tab kwarg
    config = MonitorConfig(mode="path", target_path="/data/")
    started = controller._start_monitor(config)

    assert started is True


# =============================================================================
# _start_monitor PID-mode branch — honest fanotify-aware fallback (Part A)
# =============================================================================


def _patch_binary_and_reader(monkeypatch):
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))
    monkeypatch.setattr(
        MonitorController, "_start_output_reader", lambda self, wrapper: None
    )


def test_start_monitor_pid_mode_uses_run_fsmon_by_pid_when_fanotify_supported(
    monkeypatch,
):
    """Fanotify-capable device: PID mode proceeds exactly as before (now with
    the -B fanotify fix already baked into run_fsmon_by_pid itself).
    """
    _patch_binary_and_reader(monkeypatch)
    monkeypatch.setattr(FSMon, "fanotify_supported", classmethod(lambda cls: True))

    pid_calls = []
    path_calls = []
    monkeypatch.setattr(
        FSMon,
        "run_fsmon_by_pid",
        classmethod(
            lambda cls, pid, path=None: pid_calls.append((pid, path)) or object()
        ),
    )
    monkeypatch.setattr(
        FSMon,
        "run_fsmon_by_path",
        classmethod(lambda cls, path: path_calls.append(path) or object()),
    )

    fallback_calls = []
    controller = _make_controller(on_pid_mode_fallback=fallback_calls.append)
    config = MonitorConfig(
        mode="pid",
        target_pid=1234,
        target_path="/data/data/com.example.app",
        app_name="com.example.app",
    )

    started = controller._start_monitor(config)

    assert started is True
    assert pid_calls == [(1234, "/data/data/com.example.app")]
    assert path_calls == []
    assert fallback_calls == []

    task = get_task_service().get_task("monitor")
    assert task.instance.config.mode == "pid"
    assert task.instance.config.target_pid == 1234


def test_start_monitor_pid_mode_falls_back_to_path_when_fanotify_unsupported(
    monkeypatch,
):
    """No fanotify on this device: fall back to run_fsmon_by_path, register a
    path-mode MonitorConfig (not the original pid-mode one), and fire
    on_pid_mode_fallback exactly once with the target path.
    """
    _patch_binary_and_reader(monkeypatch)
    monkeypatch.setattr(FSMon, "fanotify_supported", classmethod(lambda cls: False))

    pid_calls = []
    path_calls = []
    monkeypatch.setattr(
        FSMon,
        "run_fsmon_by_pid",
        classmethod(
            lambda cls, pid, path=None: pid_calls.append((pid, path)) or object()
        ),
    )
    monkeypatch.setattr(
        FSMon,
        "run_fsmon_by_path",
        classmethod(lambda cls, path: path_calls.append(path) or object()),
    )

    fallback_calls = []
    controller = _make_controller(on_pid_mode_fallback=fallback_calls.append)
    config = MonitorConfig(
        mode="pid",
        target_pid=1234,
        target_path="/data/data/com.example.app",
        app_name="com.example.app",
    )

    started = controller._start_monitor(config)

    assert started is True
    assert pid_calls == []  # PID-mode entry point must NOT be used
    assert path_calls == ["/data/data/com.example.app"]
    assert fallback_calls == ["/data/data/com.example.app"]

    # Header-honesty: the registered task's config must reflect what's
    # ACTUALLY running (path-mode), not the originally requested PID-mode.
    task = get_task_service().get_task("monitor")
    resolved_config = task.instance.config
    assert resolved_config.mode == "path"
    assert resolved_config.target_pid is None
    assert resolved_config.target_path == "/data/data/com.example.app"
    assert resolved_config.app_name == "com.example.app"


def test_start_monitor_pid_mode_fallback_works_without_callback(monkeypatch):
    """on_pid_mode_fallback is optional (defaults to None) — must not raise."""
    _patch_binary_and_reader(monkeypatch)
    monkeypatch.setattr(FSMon, "fanotify_supported", classmethod(lambda cls: False))
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_pid", classmethod(lambda cls, pid, path=None: object())
    )
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_path", classmethod(lambda cls, path: object())
    )

    controller = _make_controller()  # no on_pid_mode_fallback kwarg
    config = MonitorConfig(
        mode="pid", target_pid=1234, target_path="/data/", app_name="com.example.app"
    )

    started = controller._start_monitor(config)

    assert started is True


# =============================================================================
# resume_after_playback — "Resume monitoring" after Play's snapshot-revert
# safety stop (RecordingController._stop_monitor_before_revert stops monitor;
# this is the other half, re-forking it once Play is done).
# =============================================================================


def _patch_start_monitor_ok(monkeypatch):
    """Make _start_monitor succeed without touching adb/a real process."""
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_path", classmethod(lambda cls, path: object())
    )
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_pid", classmethod(lambda cls, pid, path=None: object())
    )
    monkeypatch.setattr(
        MonitorController, "_start_output_reader", lambda self, wrapper: None
    )


def test_resume_after_playback_with_no_config_fails_without_starting(monkeypatch):
    _patch_start_monitor_ok(monkeypatch)
    start_calls = []
    monkeypatch.setattr(
        MonitorController,
        "_start_monitor",
        lambda self, cfg: start_calls.append(cfg) or True,
    )

    controller = _make_controller()
    assert controller.resume_after_playback(None) is False
    assert start_calls == []


def test_resume_after_playback_noop_when_already_running(monkeypatch):
    _patch_start_monitor_ok(monkeypatch)
    controller = _make_controller()
    config = MonitorConfig(mode="path", target_path="/data/")

    # Start a real (fake) monitor session first.
    assert controller._start_monitor(config) is True
    assert controller.is_running()

    start_calls = []
    monkeypatch.setattr(
        MonitorController,
        "_start_monitor",
        lambda self, cfg: start_calls.append(cfg) or True,
    )
    assert controller.resume_after_playback(config) is False
    assert start_calls == []


def test_resume_after_playback_path_mode_reuses_config_unchanged(monkeypatch):
    """Path-mode configs have no PID to go stale — resume just re-forks as-is,
    no Adb.get_pid_for_package_name call at all.
    """
    _patch_start_monitor_ok(monkeypatch)
    controller = _make_controller()
    config = MonitorConfig(mode="path", target_path="/data/local/tmp/")

    assert controller.resume_after_playback(config) is True
    assert controller.is_running()


def test_resume_after_playback_pid_mode_reresolves_stale_pid(monkeypatch):
    """The core PID-mode staleness fix: the stored target_pid (from before
    Play) must NOT be trusted — a fresh PID is re-resolved from app_name.
    """
    _patch_start_monitor_ok(monkeypatch)

    from sandroid.core.adb import Adb

    monkeypatch.setattr(
        Adb,
        "get_pid_for_package_name",
        classmethod(lambda cls, pkg, use_frida_fallback=True, quiet=False: 9999),
    )

    start_calls = []
    monkeypatch.setattr(
        MonitorController,
        "_start_monitor",
        lambda self, cfg: start_calls.append(cfg) or True,
    )

    controller = _make_controller()
    stale_config = MonitorConfig(
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
    _patch_start_monitor_ok(monkeypatch)

    from sandroid.core.adb import Adb

    monkeypatch.setattr(
        Adb,
        "get_pid_for_package_name",
        classmethod(lambda cls, pkg, use_frida_fallback=True, quiet=False: None),
    )

    start_calls = []
    monkeypatch.setattr(
        MonitorController,
        "_start_monitor",
        lambda self, cfg: start_calls.append(cfg) or True,
    )
    warnings = []
    controller = _make_controller(log_warning=warnings.append)
    stale_config = MonitorConfig(
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
    _patch_start_monitor_ok(monkeypatch)

    from sandroid.core.adb import Adb

    monkeypatch.setattr(
        Adb,
        "get_pid_for_package_name",
        classmethod(lambda cls, pkg, use_frida_fallback=True, quiet=False: None),
    )

    start_calls = []
    monkeypatch.setattr(
        MonitorController,
        "_start_monitor",
        lambda self, cfg: start_calls.append(cfg) or True,
    )
    warnings = []
    controller = _make_controller(log_warning=warnings.append)
    stale_config = MonitorConfig(
        mode="pid", target_pid=1111, app_name="com.example.app", target_path=""
    )

    assert controller.resume_after_playback(stale_config) is False
    assert start_calls == []
    assert any("Could not resume" in w for w in warnings)


# =============================================================================
# KprobeStreamTranslator -- raw trace_pipe lines -> FileSystemMonitorItem
# =============================================================================


def _kp(event: str, tid: int, payload: str) -> str:
    """Build a realistic ftrace trace_pipe line for the given probe event."""
    return f"   comm-{tid}    [000] ...1 12345.678901: {event}: (sym+0x0/0x1) {payload}"


def test_translator_correlates_writes_via_file_pointer_map():
    """do_filp_open(entry->return) populates the file* map; a later vfs_write on
    that file* recovers the FULL path (not just a basename).
    """
    t = KprobeStreamTranslator()
    t.reset(None)

    assert t.feed(_kp("dfo", 100, 'path="/data/data/com.x/notes.db"')) == []
    assert t.feed(_kp("dfor", 100, "file=0xffffaaa0")) == []
    items = t.feed(_kp("vw", 100, "file=0xffffaaa0 count=0x40"))

    assert len(items) == 1
    assert items[0].source == "kprobe"
    assert items[0].category == "modify"
    assert items[0].directory == "/data/data/com.x"
    assert items[0].filename == "notes.db"


def test_translator_fput_invalidation_prevents_file_pointer_reuse_false_positive():
    """__fput MUST invalidate the file* map: the kernel reuses ``file*`` values,
    so without invalidation a write to a recycled pointer would be attributed to
    the OLD path. After __fput, a write to the same file* yields nothing until it
    is re-mapped to the NEW path.
    """
    t = KprobeStreamTranslator()
    t.reset(None)

    # First open/write of /a on file* 0xAAA.
    t.feed(_kp("dfo", 100, 'path="/data/a.txt"'))
    t.feed(_kp("dfor", 100, "file=0xaaa"))
    first = t.feed(_kp("vw", 100, "file=0xaaa count=0x10"))
    assert [i.filename for i in first] == ["a.txt"]

    # File closed -> map invalidated. A stale write to 0xAAA must NOT map to /a.
    t.feed(_kp("fput", 100, "file=0xaaa"))
    stale = t.feed(_kp("vw", 100, "file=0xaaa count=0x10"))
    assert stale == []  # no false positive

    # Kernel recycles the SAME file* value 0xAAA for /b -> now writes are /b.
    t.feed(_kp("dfo", 100, 'path="/data/b.txt"'))
    t.feed(_kp("dfor", 100, "file=0xaaa"))
    reused = t.feed(_kp("vw", 100, "file=0xaaa count=0x10"))
    assert [i.filename for i in reused] == ["b.txt"]


def test_translator_dropped_control_line_shows_write_becomes_unattributed():
    """A vfs_write whose do_filp_open-return was never seen (e.g. a dropped
    control line) has no file* map entry and is correctly emitted as NOTHING
    rather than mis-attributed.

    This is exactly why the translator MUST sit AHEAD of the reader thread's
    bounded ring buffer: if control lines (dfor/__fput) could be dropped by the
    ring buffer before correlation, the file* map would be corrupted. Here we
    prove the correlation genuinely depends on the control line -- with it the
    write is attributed, without it the write is dropped.
    """
    t = KprobeStreamTranslator()
    t.reset(None)

    # do_filp_open ENTRY seen, but its RETURN (dfor) dropped -> no file* entry.
    t.feed(_kp("dfo", 100, 'path="/data/x.bin"'))
    dropped = t.feed(_kp("vw", 100, "file=0xbbb count=0x10"))
    assert dropped == []

    # With the return present, the very same write IS attributed.
    t.feed(_kp("dfor", 100, "file=0xbbb"))
    ok = t.feed(_kp("vw", 100, "file=0xbbb count=0x10"))
    assert [i.filename for i in ok] == ["x.bin"]


def test_translator_skips_err_ptr_file_pointer():
    """Fix 5: do_filp_open returns an ERR_PTR (top 4 KiB of the address space)
    on a FAILED open. That value has no matching __fput, so it must NOT be
    stored in the file* map (it would leak). A write to it stays unattributed,
    and a real file* is still stored normally.
    """
    t = KprobeStreamTranslator()
    t.reset(None)

    # Failed open -> -ENOENT as an ERR_PTR. Must not populate the map.
    t.feed(_kp("dfo", 100, 'path="/data/fail.txt"'))
    assert t.feed(_kp("dfor", 100, "file=0xfffffffffffffffe")) == []
    assert t.feed(_kp("vw", 100, "file=0xfffffffffffffffe count=0x10")) == []

    # A genuine (non-ERR_PTR) file* is still correlated as before.
    t.feed(_kp("dfo", 100, 'path="/data/ok.txt"'))
    t.feed(_kp("dfor", 100, "file=0xffff8000abcd"))
    ok = t.feed(_kp("vw", 100, "file=0xffff8000abcd count=0x10"))
    assert [i.filename for i in ok] == ["ok.txt"]


def _created(tid: int, path: str, flags: str, mode: str) -> list:
    """openat2 + do_filp_open entry/return for one O_CREAT open."""
    t_items = []
    t_items.append(_kp("openat2", tid, f'fname="{path}" flags={flags}'))
    t_items.append(_kp("dfo", tid, f'path="{path}"'))
    t_items.append(_kp("dfor", tid, f"file=0xffff8000{tid:04x} mode={mode}"))
    return t_items


#: f_mode of a recorded open that created its file / of a reopen (0x100000
#: is FMODE_CREATED; recorded on emulator-5554, 6.6.30).
_MODE_CREATED = "0x495d801e"
_MODE_EXISTING = "0x494d801e"


def _feed_all(t: KprobeStreamTranslator, lines: list[str]) -> list:
    out: list = []
    for line in lines:
        out.extend(t.feed(line))
    return out


def test_translator_openat2_create_vs_open():
    t = KprobeStreamTranslator()
    t.reset(None)

    created = _feed_all(t, _created(5, "/data/new.txt", "0x241", _MODE_CREATED))
    opened = t.feed(_kp("openat2", 5, 'fname="/data/ro.txt" flags=0x0'))

    assert created[0].category == "create"
    assert created[0].filename == "new.txt"
    assert opened[0].category == "noise"  # plain OPEN (no O_CREAT)


def test_translator_metadata_and_rename_events():
    t = KprobeStreamTranslator()
    t.reset(None)

    assert t.feed(_kp("mkdir", 5, 'name="/data/sub"')) == []  # waits for its result
    mkdir = t.feed(_kp("mkdirr", 5, "ret=0"))
    unlink = t.feed(_kp("unlink", 5, 'name="/data/gone"'))
    rename = t.feed(_kp("rename", 5, 'from="/data/old" to="/data/new"'))

    assert mkdir[0].category == "create"
    assert mkdir[0].label == "CREATE DIR"
    assert unlink[0].category == "delete"
    assert rename[0].category == "rename"
    assert rename[0].filename == "old"
    assert rename[0].new_filename == "new"


def test_translator_reset_clears_correlation_state():
    t = KprobeStreamTranslator()
    t.reset(None)
    t.feed(_kp("dfo", 1, 'path="/data/a"'))
    t.feed(_kp("dfor", 1, "file=0xaaa"))

    t.reset(None)  # new session -> map wiped
    assert t.feed(_kp("vw", 1, "file=0xaaa count=0x10")) == []


def test_translator_strips_prefix_from_config():
    """reset(config) drives the same redundant-prefix stripping fsmon uses, so
    kprobe rows display identically.
    """
    t = KprobeStreamTranslator()
    t.reset(
        MonitorConfig(mode="path", target_path="/data/data/com.x/", app_name="com.x")
    )

    t.feed(_kp("dfo", 1, 'path="/data/data/com.x/cache/f.txt"'))
    t.feed(_kp("dfor", 1, "file=0xaaa"))
    items = t.feed(_kp("vw", 1, "file=0xaaa count=0x10"))
    assert items[0].directory == "cache"
    assert items[0].filename == "f.txt"


def test_translator_never_raises_on_garbage():
    t = KprobeStreamTranslator()
    t.reset(None)
    assert t.feed("not a trace line at all") == []
    assert t.feed("") == []


# -- fix round 3 (Files lens live test): paths, ops, actors ----------------


def test_translator_canonicalises_user0_paths_and_trailing_slash():
    """H3/M8: /data/user/0/<pkg> is /data/data/<pkg> (one row per file) and
    ``databases/`` is ``databases``.
    """
    t = KprobeStreamTranslator()
    t.reset(None)
    t.feed(_kp("dfo", 7, 'path="/data/user/0/org.w/shared_prefs/p.xml"'))
    t.feed(_kp("dfor", 7, "file=0xaaa"))
    write = t.feed(_kp("vw", 7, "file=0xaaa count=0x10"))
    t.feed(_kp("mkdir", 7, 'name="/data/user/0/org.w/databases/"'))
    mkdir = t.feed(_kp("mkdirr", 7, "ret=0"))
    assert write[0].path == "/data/data/org.w/shared_prefs/p.xml"
    assert mkdir[0].path == "/data/data/org.w/databases"


def test_translator_o_creat_is_decided_by_the_kernel():
    """M1: SQLite reopening its db and every ">>" append pass O_CREAT. The
    kernel says whether the open created the file (FMODE_CREATED in the
    returned file's f_mode) -- no scan of the targets needed.
    """
    t = KprobeStreamTranslator()
    t.reset(None)
    db = "/data/data/org.w/databases/w.db"
    f = "/data/data/org.w/files/f"
    reopen = _feed_all(t, _created(5, db, "0x80042", _MODE_EXISTING))
    first = _feed_all(t, _created(6, f, "0x441", _MODE_CREATED))
    append = _feed_all(t, _created(7, f, "0x441", _MODE_EXISTING))
    trunc = _feed_all(t, _created(8, f, "0x241", _MODE_EXISTING))
    failed = _feed_all(
        t,
        [
            _kp("openat2", 9, f'fname="{f}x" flags=0x241'),
            _kp("dfo", 9, f'path="{f}x"'),
            _kp("dfor", 9, "file=0xfffffffffffffffe mode=0x0"),
        ],
    )
    assert [(i.label, i.category) for i in reopen] == [("OPEN W", "noise")]
    assert [i.category for i in first] == ["create"]
    assert [(i.label, i.category) for i in append] == [("OPEN W", "noise")]
    assert [i.category for i in trunc] == ["modify"]  # O_TRUNC, existing file
    assert failed == []  # the open failed: nothing happened


def test_translator_mkdir_p_on_an_existing_directory_is_dropped():
    """M1: do_mkdirat fires before the outcome; its return (mkdirr) decides:
    -EEXIST is not a creation.
    """
    t = KprobeStreamTranslator()
    t.reset(None)
    t.feed(_kp("mkdir", 5, 'name="/data/data/org.w/files"'))
    assert t.feed(_kp("mkdirr", 5, "ret=-17")) == []
    t.feed(_kp("mkdir", 5, 'name="/data/data/org.w/files/bulk"'))
    new = t.feed(_kp("mkdirr", 5, "ret=0"))
    assert new[0].label == "CREATE DIR"
    assert new[0].path == "/data/data/org.w/files/bulk"
    # A result without a pending mkdir of that tid (other process, path mode).
    assert t.feed(_kp("mkdirr", 6, "ret=0")) == []


def test_translator_ignores_sandroids_own_adb_pulls():
    """M1: adbd's "sync svc" threads are Sandroid's pulls, not app activity."""
    t = KprobeStreamTranslator()
    t.reset(None)
    line = "  sync svc 27-4242  [001] ...1 12345.6: openat2: (s+0x0/0x1) "
    assert t.feed(line + 'fname="/data/data/org.w/databases/w.db" flags=0x0') == []
    t.feed(line.replace("openat2", "dfo") + 'path="/data/data/org.w/x"')
    t.feed(line.replace("openat2", "dfor") + "file=0xccc")
    assert t.feed(line.replace("openat2", "vw") + "file=0xccc count=0x1") == []


def test_translator_resolves_attr_basenames_and_unknown_comms():
    """M8: an attr line without a dentry chain is resolved by the basename
    seen earlier (unknown basenames are dropped, not orphan rows).
    ``<...>`` actors become the tid's earlier comm, or the app in PID mode.
    """
    t = KprobeStreamTranslator()
    t.reset(MonitorConfig(mode="pid", target_pid=3676, app_name="org.w"))
    t.feed(_kp("openat2", 5, 'fname="/data/data/org.w/databases/w.db" flags=0x0'))
    attr = t.feed(_kp("nc", 5, 'dentry="w.db" ia_valid=0x1'))
    assert attr[0].path == "/data/data/org.w/databases/w.db"
    assert t.feed(_kp("nc", 5, 'dentry="nobody.tmp" ia_valid=0x1')) == []
    t.feed(
        '   <...>-91  [000] ...1 1.0: openat2: (s+0x0/0x1) fname="/data/data/org.w/a" flags=0x0'
    )
    assert (
        t.feed(
            '   <...>-91  [000] ...1 1.0: openat2: (s+0x0/0x1) fname="/data/data/org.w/a" flags=0x0'
        )[0].process
        == "org.w"
    )
    t.feed(
        '   RxIo-92  [000] ...1 1.0: openat2: (s+0x0/0x1) fname="/data/data/org.w/b" flags=0x0'
    )
    later = t.feed(
        '   <...>-92  [000] ...1 1.0: openat2: (s+0x0/0x1) fname="/data/data/org.w/b" flags=0x0'
    )
    assert later[0].process == "RxIo"


# -- writes through files opened BEFORE the monitor started ----------------
# Lines recorded on emulator-5554 (API 35, kernel 6.6.30) while Firefox was
# attached; places.sqlite-wal had been open since app start.

_FF = "/data/data/org.mozilla.firefox"
_DATA_DEV = 266338348
_RECORDED_MOUNTS = (
    "254:0 / /\n254:44 / /data\n254:44 /data /data/user/0\n0:80 / /storage/emulated\n"
)
_REC_WAL = (
    " PlacesStorageWr-12262   [003] d.... 16650.023074: vw: (vfs_write+0x0/0x2e4) "
    'file=0xffffff801d3e8c80 count=24 dev=266338348 n0="places.sqlite-wal" '
    'n1="files" n2="org.mozilla.firefox" n3="data" n4="/" n5="/" n6="/" n7="/"'
)
_REC_SOCKET = (
    " AutoSave-thread-12030   [002] d.... 14741.676522: diw: (do_iter_write+0x0/0x338)"
    ' file=0xffffff800c4a9a40 dev=8 n0="UNIX" n1="UNIX" n2="UNIX" n3="UNIX"'
    ' n4="UNIX" n5="UNIX" n6="UNIX" n7="UNIX"'
)
_REC_EVENTFD = (
    "           Gecko-11966   [001] d.... 14823.018801: vw: (vfs_write+0x0/0x2e4) "
    'file=0xffffff803579d400 count=1 dev=15 n0="" n1="" n2="" n3="" n4="" n5=""'
    ' n6="" n7=""'
)
_REC_IDB = (
    " IndexedDB IO #5-14706   [000] d.... 14829.037772: vw: (vfs_write+0x0/0x2e4) "
    "file=0xffffff8066a6d2c0 count=1 dev=266338348 "
    'n0="3870112724rsegmnoittet-es.sqlite-shm" n1="idb" n2="chrome" '
    'n3="permanent" n4="storage" n5="k3m7yjvw.default" n6="mozilla" n7="files"'
)
_REC_NC = (
    " queued-work-loo-11951   [003] d.... 16649.960457: nc: (notify_change+0x0/0x2f4)"
    ' dentry="fenix_preferences.xml" ia_valid=0x41 dev=266338348'
    ' n1="shared_prefs" n2="org.mozilla.firefox" n3="data" n4="/" n5="/" n6="/"'
    ' n7="/"'
)


def _ff_translator(*, resolved: bool = True) -> KprobeStreamTranslator:
    from sandroid.core.kprobe_tracer import (
        build_write_scope,
        parse_mounts,
        scope_aliases,
    )

    t = KprobeStreamTranslator()
    t.reset(
        MonitorConfig(
            mode="pid",
            target_path=_FF,
            target_paths=[_FF],
            target_pid=11929,
            app_name="org.mozilla.firefox",
        )
    )
    if resolved:
        t.set_write_scope(
            build_write_scope(scope_aliases(_FF), parse_mounts(_RECORDED_MOUNTS), {})
        )
    return t


def test_translator_names_writes_through_files_opened_before_the_start():
    """The write's own dentry chain names places.sqlite-wal although no open
    of it was ever seen -- as a live MODIFY by its writer, not a rescan row.
    """
    t = _ff_translator()
    items = t.feed(_REC_WAL)
    assert [(i.label, i.path, i.process, i.source) for i in items] == [
        ("MODIFY", f"{_FF}/files/places.sqlite-wal", "PlacesStorageWr", "kprobe")
    ]
    # Without the device's view the targets' own path components still match.
    guessed = _ff_translator(resolved=False).feed(_REC_WAL)
    assert [i.path for i in guessed] == [f"{_FF}/files/places.sqlite-wal"]


def test_translator_drops_socket_and_anonymous_writes():
    t = _ff_translator()
    assert t.feed(_REC_SOCKET) == []
    assert t.feed(_REC_EVENTFD) == []


def test_translator_falls_back_to_the_open_time_map_for_deep_files():
    """The recorded IndexedDB file is 9 directories below the package: its
    chain can't reach the app directory, the open-time map names it.
    """
    t = _ff_translator()
    assert t.feed(_REC_IDB) == []  # opened before the start: not nameable
    idb = (
        f"{_FF}/files/mozilla/k3m7yjvw.default/storage/permanent/chrome/idb/"
        "3870112724rsegmnoittet-es.sqlite-shm"
    )
    t.feed(_kp("dfo", 14706, f'path="{idb}"'))
    t.feed(_kp("dfor", 14706, f"file=0xffffff8066a6d2c0 mode={_MODE_EXISTING}"))
    assert [i.path for i in t.feed(_REC_IDB)] == [idb]


def test_translator_prefers_the_chain_over_a_stale_file_pointer():
    """A lost __fput leaves a stale file* entry; the chain is the kernel's
    name at write time and wins.
    """
    t = _ff_translator()
    t.feed(_kp("dfo", 1, f'path="{_FF}/files/old.json"'))
    t.feed(_kp("dfor", 1, "file=0xffffff801d3e8c80"))
    assert [i.path for i in t.feed(_REC_WAL)] == [f"{_FF}/files/places.sqlite-wal"]


def test_translator_names_attr_changes_from_the_chain():
    t = _ff_translator()
    items = t.feed(_REC_NC)
    assert [(i.label, i.path) for i in items] == [
        ("ATTRS", f"{_FF}/shared_prefs/fenix_preferences.xml")
    ]
    # A complete chain outside the targets is dropped, even with a known name.
    t.feed(_REC_WAL)
    outside = _REC_NC.replace('n2="org.mozilla.firefox"', 'n2="com.other"')
    assert t.feed(outside) == []


def test_kprobe_setup_mode_desc_counts_the_extra_paths(monkeypatch):
    """L1: two paths read "(+1 path)" -- the primary path is already named."""
    monkeypatch.setattr(
        KprobeTracer, "run_by_path", classmethod(lambda cls, path: object())
    )
    controller = _make_controller()
    config = MonitorConfig(
        mode="path", target_path="/data/a", target_paths=["/data/a", "/data/b"]
    )
    _process, _translator, desc = controller._kprobe_setup(config)
    assert desc.endswith("(+1 path)")


def test_kprobe_setup_reads_the_write_scope_before_tracing(monkeypatch):
    """The device's view of the targets is read BEFORE tracing (the tracer
    filters the write probes by it) and handed to the translator; no scan.
    """
    from sandroid.core.kprobe_tracer import (
        build_write_scope,
        parse_mounts,
        scope_aliases,
    )

    order: list[str] = []
    monkeypatch.setattr(
        KprobeTracer,
        "run_by_pid",
        classmethod(lambda cls, pid, path=None: order.append("trace") or object()),
    )
    controller = _make_controller()
    scope = build_write_scope(scope_aliases(_FF), parse_mounts(_RECORDED_MOUNTS), {})
    monkeypatch.setattr(
        controller, "_write_scope", lambda paths: order.append("scope") or scope
    )
    config = MonitorConfig(
        mode="pid", target_pid=42, target_path=_FF, app_name="org.mozilla.firefox"
    )
    _process, translator, _desc = controller._kprobe_setup(config)
    assert order == ["scope", "trace"]
    assert translator._scope is scope
    assert not hasattr(controller, "_start_scan_watcher")
    assert [i.path for i in translator.feed(_REC_WAL)] == [
        f"{_FF}/files/places.sqlite-wal"
    ]


def test_user_stop_runs_no_rescan(monkeypatch):
    """The stop rescan is gone: a user stop just stops the task."""

    class _Wrapper:
        final_scan = False
        is_running = True

    controller = _make_controller()
    wrapper = _Wrapper()
    get_task_service().register(
        name="monitor",
        display_name="Monitor",
        instance=wrapper,
        stop_callback=lambda: None,
        app_name="org.w",
    )
    assert controller.stop() is True
    assert wrapper.final_scan is False


# =============================================================================
# _start_monitor -- backend selection (kprobe / auto / fallback)
# =============================================================================


def _patch_kprobe_launch(monkeypatch):
    """Make a kprobe launch succeed without touching adb/a real process."""
    monkeypatch.setattr(
        KprobeTracer, "run_by_path", classmethod(lambda cls, path: object())
    )
    monkeypatch.setattr(
        KprobeTracer, "run_by_pid", classmethod(lambda cls, pid, path=None: object())
    )
    monkeypatch.setattr(
        KprobeTracer, "run_capture_all", classmethod(lambda cls: object())
    )
    monkeypatch.setattr(KprobeTracer, "teardown", classmethod(lambda cls: None))
    monkeypatch.setattr(
        MonitorController, "_start_output_reader", lambda self, wrapper: None
    )


def test_start_monitor_auto_uses_kprobe_when_supported(monkeypatch):
    """Auto + kprobe_supported() True -> kprobe backend, no fsmon ELF install,
    no backend-fallback notice, and the registered wrapper carries a translator
    + teardown.
    """
    monkeypatch.setattr(KprobeTracer, "kprobe_supported", classmethod(lambda cls: True))
    _patch_kprobe_launch(monkeypatch)

    # fsmon must NOT be touched on the kprobe path.
    def _fsmon_boom(cls):
        raise AssertionError("fsmon must not be installed on the kprobe path")

    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(_fsmon_boom))

    backend_fallbacks: list[str] = []
    controller = _make_controller(on_backend_fallback=backend_fallbacks.append)
    config = MonitorConfig(mode="path", target_path="/data/data/com.x")

    assert controller._start_monitor(config) is True
    assert backend_fallbacks == []

    task = get_task_service().get_task("monitor")
    wrapper = task.instance
    assert isinstance(wrapper.translator, KprobeStreamTranslator)
    assert wrapper._teardown is not None
    assert wrapper.config.backend == "kprobe"


def test_start_monitor_auto_falls_back_to_fsmon_when_kprobe_unsupported(monkeypatch):
    """Auto + kprobe unsupported -> fsmon path AND on_backend_fallback fires."""
    monkeypatch.setattr(
        KprobeTracer, "kprobe_supported", classmethod(lambda cls: False)
    )
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))
    path_calls = []
    monkeypatch.setattr(
        FSMon,
        "run_fsmon_by_path",
        classmethod(lambda cls, path: path_calls.append(path) or object()),
    )
    monkeypatch.setattr(
        MonitorController, "_start_output_reader", lambda self, wrapper: None
    )

    backend_fallbacks: list[str] = []
    controller = _make_controller(on_backend_fallback=backend_fallbacks.append)
    config = MonitorConfig(mode="path", target_path="/data/x")

    assert controller._start_monitor(config) is True
    assert path_calls == ["/data/x"]
    assert len(backend_fallbacks) == 1
    assert "fsmon" in backend_fallbacks[0]

    task = get_task_service().get_task("monitor")
    assert task.instance.translator is None  # fsmon wrapper: no translator
    assert task.instance.config.backend == "fsmon"


def test_start_monitor_explicit_kprobe_preflight_fail_fires_fallback(monkeypatch):
    """backend=kprobe but preflight fails -> fsmon + a 'requested' fallback."""
    monkeypatch.setattr(
        KprobeTracer, "kprobe_supported", classmethod(lambda cls: False)
    )
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_path", classmethod(lambda cls, path: object())
    )
    monkeypatch.setattr(
        MonitorController, "_start_output_reader", lambda self, wrapper: None
    )

    backend_fallbacks: list[str] = []
    controller = _make_controller(on_backend_fallback=backend_fallbacks.append)
    # Explicit kprobe request via the config's resolved backend field.
    config = MonitorConfig(mode="path", target_path="/data/x", backend="kprobe")

    assert controller._start_monitor(config) is True
    assert len(backend_fallbacks) == 1
    assert "requested" in backend_fallbacks[0]


def test_start_monitor_explicit_fsmon_skips_kprobe_preflight(monkeypatch):
    """backend=fsmon -> fully synchronous fsmon, kprobe preflight never called."""

    def _preflight_boom(cls):
        raise AssertionError("kprobe preflight must not run for backend=fsmon")

    monkeypatch.setattr(KprobeTracer, "kprobe_supported", classmethod(_preflight_boom))
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_path", classmethod(lambda cls, path: object())
    )
    monkeypatch.setattr(
        MonitorController, "_start_output_reader", lambda self, wrapper: None
    )

    controller = _make_controller()
    config = MonitorConfig(mode="path", target_path="/data/x", backend="fsmon")
    assert controller._start_monitor(config) is True
    assert get_task_service().get_task("monitor").instance.config.backend == "fsmon"


# =============================================================================
# Backend-preference resolution + multi-path forwarding (new default: kprobe)
# =============================================================================


def test_resolve_backend_pref_normalizes_to_kprobe_default(monkeypatch):
    """The on-disk default is now ``"kprobe"``; the ``"auto"`` sentinel consults
    the global preference and any legacy/unknown value normalizes to kprobe. A
    concrete per-session backend is honored directly.
    """
    controller = _make_controller()

    # Sentinel -> consult the global preference; legacy/unknown -> kprobe.
    monkeypatch.setattr(controller, "_get_monitor_backend", lambda: "auto")
    assert controller._resolve_backend_pref(MonitorConfig(backend="auto")) == "kprobe"
    monkeypatch.setattr(controller, "_get_monitor_backend", lambda: "fsmon")
    assert controller._resolve_backend_pref(MonitorConfig(backend="auto")) == "fsmon"

    # An explicitly-resolved concrete backend is honored directly.
    assert controller._resolve_backend_pref(MonitorConfig(backend="fsmon")) == "fsmon"
    assert controller._resolve_backend_pref(MonitorConfig(backend="kprobe")) == "kprobe"


def test_kprobe_setup_path_mode_forwards_target_paths_list(monkeypatch):
    """A multi-path config in pure path mode forwards the whole ``target_paths``
    LIST (not just the primary str) to ``run_by_path``, and the extra paths are
    reflected in the mode description.
    """
    monkeypatch.setattr(KprobeTracer, "kprobe_supported", classmethod(lambda cls: True))
    monkeypatch.setattr(KprobeTracer, "teardown", classmethod(lambda cls: None))
    monkeypatch.setattr(
        MonitorController, "_start_output_reader", lambda self, wrapper: None
    )

    by_path: list = []
    monkeypatch.setattr(
        KprobeTracer,
        "run_by_path",
        classmethod(lambda cls, path: by_path.append(path) or object()),
    )

    descs: list[str] = []
    controller = _make_controller(
        log_task_started=lambda name, desc: descs.append(desc)
    )
    config = MonitorConfig(
        mode="path",
        target_path="/data/a",
        target_paths=["/data/a", "/data/b"],
    )
    assert controller._start_monitor(config) is True

    # The forwarded argument is the LIST, not a single str.
    assert by_path == [["/data/a", "/data/b"]]
    assert descs
    # L1: the primary path is already named; the suffix counts the others.
    assert "(+1 path)" in descs[0]


def test_kprobe_setup_pid_mode_forwards_target_paths_list(monkeypatch):
    """When a target PID is known, the multi-path LIST rides along on
    ``run_by_pid(pid, paths)`` (set_event_pid + OR'd path glob).
    """
    monkeypatch.setattr(KprobeTracer, "kprobe_supported", classmethod(lambda cls: True))
    monkeypatch.setattr(KprobeTracer, "teardown", classmethod(lambda cls: None))
    monkeypatch.setattr(
        MonitorController, "_start_output_reader", lambda self, wrapper: None
    )

    by_pid: list = []
    by_path: list = []
    monkeypatch.setattr(
        KprobeTracer,
        "run_by_pid",
        classmethod(lambda cls, pid, path=None: by_pid.append((pid, path)) or object()),
    )
    monkeypatch.setattr(
        KprobeTracer,
        "run_by_path",
        classmethod(lambda cls, path: by_path.append(path) or object()),
    )

    controller = _make_controller()
    config = MonitorConfig(
        mode="path",
        target_path="/data/a",
        target_paths=["/data/a", "/data/b"],
        target_pid=4321,
    )
    assert controller._start_monitor(config) is True

    assert by_pid == [(4321, ["/data/a", "/data/b"])]
    assert by_path == []  # PID path preferred; pure run_by_path not used


def test_launch_fsmon_ignores_extra_target_paths(monkeypatch):
    """Fsmon stays single-path: even with a multi-path config it consumes only
    the primary ``target_path`` (a str), never the ``target_paths`` list.
    """
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))
    monkeypatch.setattr(
        MonitorController, "_start_output_reader", lambda self, wrapper: None
    )
    path_calls: list = []
    monkeypatch.setattr(
        FSMon,
        "run_fsmon_by_path",
        classmethod(lambda cls, path: path_calls.append(path) or object()),
    )

    controller = _make_controller()
    # backend="fsmon" -> straight to _launch_fsmon, no kprobe preflight.
    config = MonitorConfig(
        mode="path",
        target_path="/data/a",
        target_paths=["/data/a", "/data/b"],
        backend="fsmon",
    )
    assert controller._start_monitor(config) is True
    assert path_calls == ["/data/a"]  # only the primary path, as a str


def test_resume_after_playback_pid_rebuild_carries_target_paths(monkeypatch):
    """The PID-mode resume rebuild (fresh PID re-resolved) preserves
    ``target_paths`` so a resumed multi-path kprobe session keeps its extras.
    """
    _patch_start_monitor_ok(monkeypatch)

    from sandroid.core.adb import Adb

    monkeypatch.setattr(
        Adb,
        "get_pid_for_package_name",
        classmethod(lambda cls, pkg, use_frida_fallback=True, quiet=False: 9999),
    )

    start_calls = []
    monkeypatch.setattr(
        MonitorController,
        "_start_monitor",
        lambda self, cfg: start_calls.append(cfg) or True,
    )

    controller = _make_controller()
    config = MonitorConfig(
        mode="pid",
        target_pid=1111,
        app_name="com.example.app",
        target_path="/data/a",
        target_paths=["/data/a", "/data/b"],
        backend="kprobe",
    )
    assert controller.resume_after_playback(config) is True
    resolved = start_calls[0]
    assert resolved.mode == "pid"
    assert resolved.target_pid == 9999
    assert resolved.target_paths == ["/data/a", "/data/b"]


def test_resume_after_playback_path_fallback_rebuild_carries_target_paths(monkeypatch):
    """The PID->path fallback resume rebuild (app gone) also preserves
    ``target_paths``.
    """
    _patch_start_monitor_ok(monkeypatch)

    from sandroid.core.adb import Adb

    monkeypatch.setattr(
        Adb,
        "get_pid_for_package_name",
        classmethod(lambda cls, pkg, use_frida_fallback=True, quiet=False: None),
    )

    start_calls = []
    monkeypatch.setattr(
        MonitorController,
        "_start_monitor",
        lambda self, cfg: start_calls.append(cfg) or True,
    )

    controller = _make_controller()
    config = MonitorConfig(
        mode="pid",
        target_pid=1111,
        app_name="com.example.app",
        target_path="/data/a",
        target_paths=["/data/a", "/data/b"],
        backend="kprobe",
    )
    assert controller.resume_after_playback(config) is True
    resolved = start_calls[0]
    assert resolved.mode == "path"
    assert resolved.target_pid is None
    assert resolved.target_paths == ["/data/a", "/data/b"]


def test_start_monitor_kprobe_reader_routes_through_translator(monkeypatch):
    """The kprobe wrapper's translator is wired to the reader thread: the reader
    ingests raw lines through it (ahead of the deque) and publishes correlated
    items. We drive one dfo->dfor->vw sequence and assert a modify item is
    published on the bus.
    """
    monkeypatch.setattr(KprobeTracer, "kprobe_supported", classmethod(lambda cls: True))

    class _FakeProc:
        def __init__(self, lines):
            self._lines = list(lines)
            self.stdout = self

        def readline(self):
            return self._lines.pop(0) if self._lines else ""

        def poll(self):
            return None if self._lines else 0

        def __iter__(self):
            return iter([])

    lines = [
        _kp("dfo", 7, 'path="/data/data/com.x/w.db"') + "\n",
        _kp("dfor", 7, "file=0xcafe") + "\n",
        _kp("vw", 7, "file=0xcafe count=0x8") + "\n",
    ]
    monkeypatch.setattr(
        KprobeTracer, "run_by_path", classmethod(lambda cls, path: _FakeProc(lines))
    )
    monkeypatch.setattr(KprobeTracer, "teardown", classmethod(lambda cls: None))

    received: list[Event] = []
    EventBus.get().subscribe(EventType.TASK_OUTPUT, received.append)
    try:
        # Reader runs inline (its thread is a real thread; drive it synchronously
        # by invoking the wrapper's process through the started reader). Use a
        # tiny buffer interval so the first line flushes immediately.
        controller = _make_controller()
        monkeypatch.setattr(controller, "_get_buffer_interval", lambda: 0.0)

        config = MonitorConfig(mode="path", target_path="/data/data/com.x")
        controller._launch_kprobe(config)

        # The reader thread is real; give it a brief moment to drain 3 lines.
        import time

        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and not received:
            time.sleep(0.01)

        assert received, "no batch published"
        batch = received[-1].data["batch"]
        modifies = [it for it in batch if it.category == "modify"]
        assert modifies, f"expected a correlated modify item, got {batch}"
        assert modifies[0].filename == "w.db"
        assert modifies[0].source == "kprobe"
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, received.append)


@pytest.mark.parametrize(("requested", "warned"), [(True, False), (False, True)])
def test_reader_logs_a_requested_stop_as_normal_not_unexpected(requested, warned):
    """M7: our own stop terminates the reader with SIGTERM (-15); that is a
    normal stop. Only an exit nobody asked for is "unexpected".
    """
    import time

    class _DeadProc:
        stdout = iter([])

        def poll(self):
            return -15

    warnings: list[str] = []
    ended: list[bool] = []
    controller = _make_controller(log_warning=warnings.append)
    controller._monitor_ended = lambda: ended.append(True)
    wrapper = type(
        "W",
        (),
        {"process": _DeadProc(), "translator": None, "stop_requested": requested},
    )()
    controller._start_output_reader(wrapper)
    deadline = time.monotonic() + 2
    while not ended and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ended
    assert any("unexpectedly" in w for w in warnings) is warned


# =============================================================================
# Off-thread setup / preflight guards (Fixes 1, 3b, 6, 7)
# =============================================================================


def test_start_monitor_kprobe_setup_runs_off_thread_registration_on_main(monkeypatch):
    """Fix 1: the device-heavy kprobe SETUP (run_by_*) runs inside the
    off-thread runner, and only the cheap finalization (registration + reader
    start) is marshaled back via call_from_thread.
    """
    monkeypatch.setattr(KprobeTracer, "kprobe_supported", classmethod(lambda cls: True))
    monkeypatch.setattr(KprobeTracer, "teardown", classmethod(lambda cls: None))

    events: list[str] = []
    monkeypatch.setattr(
        KprobeTracer,
        "run_by_path",
        classmethod(lambda cls, path: events.append("setup") or object()),
    )
    monkeypatch.setattr(
        MonitorController,
        "_start_output_reader",
        lambda self, wrapper: events.append("reader"),
    )

    def fake_off_thread(target):
        events.append("off_thread")
        target()  # run synchronously, but records it was routed off-thread

    def fake_from_thread(fn, *args):
        events.append("from_thread")
        return fn(*args)

    controller = _make_controller(
        run_off_thread=fake_off_thread, call_from_thread=fake_from_thread
    )
    assert (
        controller._start_monitor(MonitorConfig(mode="path", target_path="/d")) is True
    )

    # Ordering proves the structure: off-thread runner wraps the setup, and the
    # registration/reader-start happen inside the marshaled finalization.
    assert events.index("off_thread") < events.index("setup")
    assert events.index("setup") < events.index("from_thread")
    assert events.index("from_thread") < events.index("reader")
    assert get_task_service().is_running("monitor")


def test_start_monitor_double_start_is_noop_during_pending(monkeypatch):
    """Fix 6: a second start while the first is still pending (off-thread
    preflight/setup not yet finished, so the task hasn't registered) must be a
    no-op -- only ONE worker is ever scheduled.
    """
    monkeypatch.setattr(KprobeTracer, "kprobe_supported", classmethod(lambda cls: True))
    _patch_kprobe_launch(monkeypatch)

    deferred = []  # capture the worker instead of running it -> stays pending
    controller = _make_controller(run_off_thread=deferred.append)

    assert (
        controller._start_monitor(MonitorConfig(mode="path", target_path="/x")) is True
    )
    assert controller._start_pending is True

    warnings: list[str] = []
    controller._log_warning = warnings.append
    second = controller._start_monitor(MonitorConfig(mode="path", target_path="/y"))
    assert second is False
    assert len(deferred) == 1  # no concurrent worker scheduled
    assert any("already starting" in w for w in warnings)

    # Draining the first worker finalizes, clears the latch, and registers.
    deferred[0]()
    assert controller._start_pending is False
    assert get_task_service().is_running("monitor")


def test_start_monitor_clears_pending_on_kprobe_fallback(monkeypatch):
    """Fix 6: the pending latch is cleared even when kprobe is unsupported and
    we fall back to fsmon (else a later start would be wrongly blocked).
    """
    monkeypatch.setattr(
        KprobeTracer, "kprobe_supported", classmethod(lambda cls: False)
    )
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_path", classmethod(lambda cls, path: object())
    )
    monkeypatch.setattr(
        MonitorController, "_start_output_reader", lambda self, wrapper: None
    )

    controller = _make_controller()
    assert (
        controller._start_monitor(MonitorConfig(mode="path", target_path="/x")) is True
    )
    assert controller._start_pending is False


def test_start_monitor_logs_checking_backend_before_preflight(monkeypatch):
    """Fix 7: a user-visible notice is logged when the (potentially slow)
    kprobe preflight begins, so the delay is explained.
    """
    monkeypatch.setattr(KprobeTracer, "kprobe_supported", classmethod(lambda cls: True))
    _patch_kprobe_launch(monkeypatch)

    infos: list[str] = []
    controller = _make_controller(log_info=infos.append)
    controller._start_monitor(MonitorConfig(mode="path", target_path="/x"))
    assert any("kprobe" in m.lower() and "check" in m.lower() for m in infos)


def test_kprobe_path_mode_with_known_pid_prefers_run_by_pid(monkeypatch):
    """Fix 3b: when a target PID is known -- even a path-mode config -- prefer
    run_by_pid(pid, path) (set_event_pid bounds the write firehose) over pure
    run_by_path.
    """
    monkeypatch.setattr(KprobeTracer, "kprobe_supported", classmethod(lambda cls: True))
    monkeypatch.setattr(KprobeTracer, "teardown", classmethod(lambda cls: None))
    monkeypatch.setattr(
        MonitorController, "_start_output_reader", lambda self, wrapper: None
    )

    by_pid: list[tuple] = []
    by_path: list[str] = []
    monkeypatch.setattr(
        KprobeTracer,
        "run_by_pid",
        classmethod(lambda cls, pid, path=None: by_pid.append((pid, path)) or object()),
    )
    monkeypatch.setattr(
        KprobeTracer,
        "run_by_path",
        classmethod(lambda cls, path: by_path.append(path) or object()),
    )

    controller = _make_controller()
    # A path-mode config that nonetheless carries a resolved PID.
    config = MonitorConfig(mode="path", target_path="/data/data/com.x", target_pid=4321)
    assert controller._start_monitor(config) is True

    assert by_pid == [(4321, "/data/data/com.x")]
    assert by_path == []  # pure path mode NOT used when a PID is available


# =============================================================================
# Teardown runs on the natural-exit path (_monitor_ended), not just stop()
# =============================================================================


def test_monitor_ended_runs_teardown_on_natural_exit(monkeypatch):
    """The natural-exit path (process died / adb death) calls unregister() and
    does NOT go through stop_callback, so _monitor_ended must invoke the
    wrapper's teardown itself -- else the kprobe session state leaks and wedges
    the next start.
    """
    from sandroid.tui.utils import MonitorProcessWrapper

    teardown_calls = {"n": 0}

    class _DeadProc:
        def poll(self):
            return 0

    wrapper = MonitorProcessWrapper(
        _DeadProc(),
        config=MonitorConfig(mode="path", target_path="/data/x", backend="kprobe"),
        teardown=lambda: teardown_calls.__setitem__("n", teardown_calls["n"] + 1),
        translator=KprobeStreamTranslator(),
    )

    svc = get_task_service()
    svc.register(
        name="monitor",
        display_name="Monitor",
        instance=wrapper,
        stop_callback=wrapper.stop,
        app_name="/data/x",
    )

    controller = _make_controller()
    controller._monitor_ended()

    assert teardown_calls["n"] == 1
    assert not svc.is_running("monitor")  # unregistered afterwards


def test_monitor_ended_teardown_noop_for_fsmon_wrapper():
    """Fsmon wrappers pass teardown=None -> _monitor_ended must not raise."""
    from sandroid.tui.utils import MonitorProcessWrapper

    class _DeadProc:
        def poll(self):
            return 0

    wrapper = MonitorProcessWrapper(_DeadProc(), config=MonitorConfig())
    svc = get_task_service()
    svc.register(
        name="monitor",
        display_name="Monitor",
        instance=wrapper,
        stop_callback=wrapper.stop,
        app_name="/data/",
    )
    _make_controller()._monitor_ended()
    assert not svc.is_running("monitor")


# =============================================================================
# AI-chat additions (Part B1): start_with_config / get_status /
# get_recent_events, and the new recent_events population inside
# _start_output_reader's ingest() closures.
# =============================================================================


def test_get_status_when_not_running_is_all_empty():
    controller = _make_controller()

    assert controller.get_status() == {
        "running": False,
        "backend": None,
        "mode": None,
        "target_path": None,
        "target_paths": [],
        "target_pid": None,
        "app_name": None,
    }


def test_get_status_reads_running_config():
    from sandroid.tui.utils import MonitorProcessWrapper

    class _DeadProc:
        def poll(self):
            return None  # still "running"

    config = MonitorConfig(
        mode="pid",
        target_path="/data/data/com.example/",
        target_paths=["/data/data/com.example/"],
        target_pid=4321,
        app_name="com.example.app",
        backend="kprobe",
    )
    wrapper = MonitorProcessWrapper(_DeadProc(), config=config)
    get_task_service().register(
        name="monitor",
        display_name="Monitor",
        instance=wrapper,
        stop_callback=wrapper.stop,
        app_name="com.example.app",
    )

    controller = _make_controller()

    assert controller.get_status() == {
        "running": True,
        "backend": "kprobe",
        "mode": "pid",
        "target_path": "/data/data/com.example/",
        "target_paths": ["/data/data/com.example/"],
        "target_pid": 4321,
        "app_name": "com.example.app",
    }


def test_get_recent_events_no_monitor_task_is_all_empty():
    controller = _make_controller()

    assert controller.get_recent_events() == {
        "events": [],
        "next_seq": 0,
        "count": 0,
        "truncated": False,
    }


def test_get_recent_events_default_and_since_seq_cursor():
    from sandroid.tui.utils import MonitorProcessWrapper

    class _DeadProc:
        def poll(self):
            return None

    wrapper = MonitorProcessWrapper(_DeadProc(), config=MonitorConfig())
    for i in range(5):
        wrapper.record_event({"path": f"/data/f{i}.txt"})
    get_task_service().register(
        name="monitor",
        display_name="Monitor",
        instance=wrapper,
        stop_callback=wrapper.stop,
        app_name="/data/",
    )

    controller = _make_controller()

    # No since_cursor -> everything currently buffered, oldest-first.
    result = controller.get_recent_events()
    assert result["count"] == 5
    assert result["next_seq"] == 5
    assert result["truncated"] is False
    assert [e["seq"] for e in result["events"]] == [1, 2, 3, 4, 5]

    # since_seq=3 -> only seq 4 and 5, but next_seq is still the buffer's
    # overall latest (5), not the filtered subset's latest.
    result = controller.get_recent_events(since_seq=3)
    assert [e["seq"] for e in result["events"]] == [4, 5]
    assert result["next_seq"] == 5

    # limit=1 -> truncated, keeps the MOST RECENT event (last of the
    # oldest-first list), not the oldest.
    result = controller.get_recent_events(limit=1)
    assert result["truncated"] is True
    assert [e["seq"] for e in result["events"]] == [5]


def test_get_recent_events_limit_is_hard_capped(monkeypatch):
    """Mirrors ai/tools/flow_query.py's _MAX_LIMIT hard-cap convention --
    monkeypatch the (small, module-private) ceiling itself rather than
    generating thousands of fake events just to exercise the clamp.
    """
    from sandroid.tui.controllers import monitor_controller as mc
    from sandroid.tui.utils import MonitorProcessWrapper

    monkeypatch.setattr(mc, "_MAX_RECENT_EVENTS_LIMIT", 3)

    class _DeadProc:
        def poll(self):
            return None

    wrapper = MonitorProcessWrapper(_DeadProc(), config=MonitorConfig())
    for i in range(5):
        wrapper.record_event({"path": f"/data/f{i}.txt"})
    get_task_service().register(
        name="monitor",
        display_name="Monitor",
        instance=wrapper,
        stop_callback=wrapper.stop,
        app_name="/data/",
    )

    controller = _make_controller()

    result = controller.get_recent_events(limit=999_999)

    assert result["truncated"] is True
    assert len(result["events"]) == 3
    assert [e["seq"] for e in result["events"]] == [3, 4, 5]  # most recent 3


def test_start_with_config_reports_failure_without_registering_task(monkeypatch):
    def _boom(cls):
        raise RuntimeError("no binary")

    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(_boom))

    controller = _make_controller()
    config = MonitorConfig(mode="path", target_path="/data/")

    result = controller.start_with_config(config)

    assert result == {
        "success": False,
        "backend": None,
        "mode": "path",
        "target": "/data/",
        "pending": False,
    }
    assert not get_task_service().is_running("monitor")


def test_start_with_config_kprobe_async_path_reports_pending(monkeypatch):
    """The kprobe/auto path resolves off-thread; if that off-thread work
    never actually completes before start_with_config returns (the real
    production shape -- a spawned daemon thread), the task hasn't
    registered yet and this must report pending=True rather than treat the
    optimistic `_start_monitor() -> True` as settled fact.
    """
    monkeypatch.setattr(KprobeTracer, "kprobe_supported", classmethod(lambda cls: True))
    # Defer the off-thread preflight/setup indefinitely (never actually runs)
    # -- unlike _make_controller's normal synchronous-for-tests default.
    controller = _make_controller(run_off_thread=lambda fn: None)

    config = MonitorConfig(mode="path", target_path="/data/", backend="auto")
    result = controller.start_with_config(config)

    assert result == {
        "success": True,
        "backend": None,
        "mode": "path",
        "target": "/data/",
        "pending": True,
    }
    assert not get_task_service().is_running("monitor")


def test_start_with_config_fsmon_resolves_backend_and_populates_recent_events(
    monkeypatch,
):
    """End-to-end: a real reader thread ingests real fsmon wire-format lines
    through start_with_config -> _start_monitor -> _start_output_reader, and
    each parsed event lands in the new, non-cleared recent_events history --
    readable afterwards via get_recent_events -- in ADDITION to (not instead
    of) the existing transient flush-batch/EventBus publishing.
    """
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))

    class _FakeProc:
        """Stays "running" (poll() is None) until explicitly stopped, so the
        real reader thread never races start_with_config's own post-launch
        task lookup by spontaneously exiting and unregistering the task the
        moment its (short, fixed) line list is exhausted.
        """

        def __init__(self, lines):
            self._lines = list(lines)
            self.stdout = self
            self._terminated = False

        def readline(self):
            return self._lines.pop(0) if self._lines else ""

        def poll(self):
            return 0 if self._terminated else None

        def terminate(self):
            self._terminated = True

        def kill(self):
            self._terminated = True

        def wait(self, timeout=None):
            return 0

        def __iter__(self):
            return iter([])

    lines = [
        _fse("FSE_CREATE_FILE", "/data/data/com.example/f1.txt") + "\n",
        _fse("FSE_CONTENT_MODIFIED", "/data/data/com.example/f2.txt") + "\n",
    ]
    monkeypatch.setattr(
        FSMon, "run_fsmon_by_path", classmethod(lambda cls, path: _FakeProc(lines))
    )

    controller = _make_controller()
    monkeypatch.setattr(controller, "_get_buffer_interval", lambda: 0.0)

    config = MonitorConfig(mode="path", target_path="/data/data/com.example/")
    try:
        result = controller.start_with_config(config)

        assert result["success"] is True
        assert result["pending"] is False
        assert result["backend"] == "fsmon"
        assert result["mode"] == "path"

        # The reader thread is real; wait for both lines to be ingested into
        # recent_events (a genuinely separate destination from the transient
        # flush-batch EventBus publish already covered by
        # test_start_monitor_kprobe_reader_routes_through_translator above).
        import time

        deadline = time.monotonic() + 2.0
        events: list = []
        while time.monotonic() < deadline:
            events = controller.get_recent_events()["events"]
            if len(events) >= 2:
                break
            time.sleep(0.01)

        assert len(events) == 2
        assert [e["seq"] for e in events] == [1, 2]
        assert events[0]["path"] == "/data/data/com.example/f1.txt"
        assert events[0]["source"] == "fsmon"
        assert events[1]["path"] == "/data/data/com.example/f2.txt"

        status = controller.get_status()
        assert status["running"] is True
        assert status["backend"] == "fsmon"
        assert status["target_path"] == "/data/data/com.example/"
    finally:
        # Clean up the real background reader thread/task rather than
        # leaving a live daemon thread polling a fake process for the rest
        # of the test session.
        controller.stop()


# =============================================================================
# MonitorWatch: follow the app (multi-process seeding, restart via
# task_rename + poll, spawn hand-off), blind state, lost events
# =============================================================================

from datetime import datetime as _dt

from sandroid.core.kprobe_tracer import (
    AddResult,
    AppListing,
    AppProcess,
    build_write_scope,
    parse_app_listing,
    parse_mounts,
    scope_aliases,
)
from sandroid.tui.controllers.monitor_controller import MonitorWatch

_PKG = "org.mozilla.firefox"
_T = _dt(2026, 11, 18, 12, 47, 3)
_RENAME = (
    "           <...>-25983   [002] d..2.  9876.543210: task_rename: pid=25983 "
    "oldcomm=main newcomm=mozilla.firefox oom_score_adj=-1000"
)


def _procs(**named: int) -> dict[int, AppProcess]:
    names = {
        "main": _PKG,
        "tab_17": f"{_PKG}:sandboxed_tab_17",
        "tab_18": f"{_PKG}:sandboxed_tab_18",
        "gpu": f"{_PKG}:gpu_process",
        "crash": f"{_PKG}:crashhelper_service",
        "fresh": "zygote64",
    }
    return {pid: AppProcess(pid, 10219, names[key]) for key, pid in named.items()}


class _FakeDevice:
    """The watch's device side, scripted: a process table that tests edit."""

    def __init__(self, table: dict[int, AppProcess] | None = None) -> None:
        self.table = dict(table or {})
        self.adds: list[list[int]] = []
        self.lost_value: int | None = 0
        self.ok = True
        self.add_error = False
        self.rename = None  # what start_rename returns
        self.rename_stopped = False
        #: pid -> starttime (s since boot); uptime at the add.
        self.started: dict[int, float] = {}
        self.uptime = 1000.0

    def listing(self, package, tracked):
        return AppListing(
            app_uid=10219,
            processes=dict(self.table) if self.ok else {},
            tasks={p: [p, p + 1] for p in tracked if p in self.table},
            ok=self.ok,
        )

    def add(self, pids):
        self.adds.append(list(pids))
        return AddResult(
            tasks={p: [p, p + 1, p + 2] for p in pids},
            started={p: self.started.get(p, self.uptime) for p in pids},
            uptime=self.uptime,
            error=self.add_error,
        )

    def start_rename(self, package):
        return self.rename

    def stop_rename(self):
        self.rename_stopped = True

    def lost(self):
        return self.lost_value


def _watch(device, *, follow=True, mode="pid", notes=None, changes=None, **cfg):
    config = MonitorConfig(
        mode=mode,
        app_name=_PKG,
        target_path=f"/data/data/{_PKG}",
        follow=follow,
        **cfg,
    )
    return MonitorWatch(
        config,
        "kprobe",
        device=device,
        on_note=(lambda text, level, when: notes.append((level, text)))
        if notes is not None
        else None,
        on_change=(lambda: changes.append(1)) if changes is not None else None,
        now=lambda: _T,
    )


def test_watch_seeds_every_app_process_with_labels():
    device = _FakeDevice(
        _procs(main=24310, tab_17=24398, gpu=24402, tab_18=24455, crash=24470)
    )
    notes: list = []
    watch = _watch(device, notes=notes)
    listing = watch.initial_processes()
    watch.seed({p: [p] for p in listing.processes}, listing)
    assert sorted(watch.procs) == [24310, 24398, 24402, 24455, 24470]
    assert watch.label_for_tid(24310) == "main"
    assert watch.label_for_tid(24398) == "tab_17"
    assert watch.label_for_tid(24402) == "gpu_process"
    assert watch.label_for_tid(4242) is None
    assert notes == []  # running at start: no timeline line
    title, parts = watch.caption()
    assert title is None
    assert parts == [f"App {_PKG} · 5 proc · following", "o stops"]


def test_restart_noticed_by_task_rename_is_followed_with_its_gap():
    device = _FakeDevice(_procs(main=24310, gpu=24402))
    notes: list = []
    watch = _watch(device, notes=notes)
    notes_at: list = []
    watch.on_note = lambda text, level, when: (
        notes.append((level, text)),
        notes_at.append((level, text, when)),
    )
    watch.seed({24310: [24310], 24402: [24402]}, watch.initial_processes())
    # LMK kills Firefox, it relaunches as 25983.
    device.table = _procs(main=25983)
    device.started = {25983: 999.7}
    watch.on_rename_line(_RENAME)
    assert watch._wake.is_set()  # the poll runs now, not in 2 s
    watch.poll_once()
    assert device.adds == [[25983]]
    assert sorted(watch.procs) == [25983]
    assert watch.blind_since is None
    # In time order (as the Events tab shows them): the exit is dated just
    # before the restart, so the timeline reads exit -> restart.
    texts = [t for _lvl, t, _w in sorted(notes_at, key=lambda n: n[2])]
    assert texts[0] == f"{_PKG} exited · PID 24310 · noticed 12:47:03"
    assert texts[1].startswith(
        f"{_PKG} restarted 12:47:02 · new PID 25983 · gap ≈0.3 s"
    )
    assert "⇧R re-applies" in texts[1]
    assert watch.label_for_tid(25984) == "main"


def test_rename_of_a_tracked_pid_or_garbage_does_not_poll():
    device = _FakeDevice(_procs(main=25983))
    watch = _watch(device)
    watch.seed({25983: [25983]}, watch.initial_processes())
    watch.on_rename_line(_RENAME)
    watch.on_rename_line("not a trace line")
    assert not watch._wake.is_set()


def test_a_new_process_waits_for_its_name_before_it_is_announced():
    device = _FakeDevice(_procs(main=24310))
    notes: list = []
    watch = _watch(device, notes=notes)
    watch.seed({24310: [24310]}, watch.initial_processes())
    device.table = _procs(main=24310, fresh=24500)  # UID match, still zygote64
    watch.poll_once()
    assert 24500 in watch.procs  # already recorded (UID verified) ...
    assert notes == []  # ... but not named yet
    assert watch.label_for_tid(24500) == "pid 24500"
    device.table = _procs(main=24310, tab_17=24500)
    watch.poll_once()
    assert notes == [("info", "+ tab_17 (PID 24500) followed · gap ≈0.0 s")]
    assert watch.label_for_tid(24501) == "tab_17"
    assert device.adds == [[24500]]  # added once


def test_poll_only_when_task_rename_is_unavailable():
    device = _FakeDevice(_procs(main=24310))
    watch = _watch(device)
    watch.seed({24310: [24310]}, watch.initial_processes())
    watch.start_rename_watch()
    assert watch.rename_ok is False
    device.table = _procs(main=24310, gpu=24402)
    watch.poll_once()
    assert sorted(watch.procs) == [24310, 24402]
    assert "start detection by poll" in watch.caption()[1]


def test_an_adb_hiccup_is_never_read_as_every_process_exited():
    device = _FakeDevice(_procs(main=24310))
    watch = _watch(device, follow=False)
    watch.seed({24310: []})
    device.ok = False
    watch.poll_once()
    assert watch.procs
    assert watch.blind_since is None


def test_spawn_hands_the_paused_pid_over_before_resume():
    """SpotlightService.spawn_app_paused -> notify_spawned -> the running
    watch adds the PID (synchronously, on the spawning thread).
    """
    from sandroid.services.spotlight_service import SpotlightService

    device = _FakeDevice({})
    notes: list = []
    watch = _watch(device, notes=notes)
    watch.seed({}, watch.initial_processes())
    assert watch.caption()[1][0] == f"App {_PKG} · not running · follows its start"
    order: list[str] = []

    class _JM:
        def spawn_paused(self, package):
            order.append("spawn")
            return 31000

        def resume_app(self):
            order.append(f"resume (scope {sorted(watch.procs)})")
            return True

    svc = SpotlightService(job_manager_factory=lambda: _JM())
    watch.start()
    try:
        _jm, pid = svc.spawn_app_paused(_PKG)
        svc.notify_spawned(77, "com.other.app")  # another app: ignored
        svc.resume_paused_app()
    finally:
        watch.stop()
    assert pid == 31000
    assert device.adds == [[31000]]
    assert order == ["spawn", "resume (scope [31000])"]
    assert notes == [
        ("info", f"{_PKG} started 12:47:03 · PID 31000 · spawned paused · no gap")
    ]
    assert watch.on_spawned not in SpotlightService._spawn_listeners


def test_follow_off_goes_blind_when_the_target_is_gone():
    device = _FakeDevice(_procs(main=24310))
    changes: list = []
    watch = _watch(device, follow=False, changes=changes, target_pid=24310)
    watch.seed({24310: []})
    assert watch.caption() == (
        None,
        [f"App {_PKG} · PID 24310 + children", "o stops"],
    )
    device.table = _procs(main=25983)
    watch.poll_once()
    assert device.adds == []  # not following
    assert watch.blind_since == _T
    title, parts = watch.caption()
    assert title == "monitor blind since 12:47:03 · target gone"
    assert "o stops · o again re-targets" in parts[1]
    assert "follow restarts: monitor dialog / Settings" in parts[1]
    assert changes  # the caption was told


def test_follow_off_counts_app_processes_it_does_not_record():
    device = _FakeDevice(_procs(main=24310, gpu=24402))
    watch = _watch(device, follow=False, target_pid=24310)
    watch.seed({24310: []})
    watch.poll_once()
    assert "1 app process not followed" in watch.caption()[1]


def test_a_refused_add_is_blind_cant_follow():
    device = _FakeDevice(_procs(main=24310))
    watch = _watch(device)
    watch.seed({}, None)
    device.add_error = True
    watch.poll_once()
    assert watch.caption()[0] == "monitor blind since 12:47:03 · can't follow"


def test_fsmon_cannot_follow_and_path_mode_has_no_process_table():
    fs = MonitorWatch(
        MonitorConfig(mode="pid", app_name=_PKG, follow=True, target_pid=5),
        "fsmon",
        device=_FakeDevice(),
    )
    assert fs.track
    assert not fs.follow
    assert not fs.kprobe
    path = _watch(_FakeDevice(), mode="path", target_paths=["/sdcard", "/data/x"])
    assert not path.track
    assert path.caption() == (None, ["Path /sdcard +1 · every process", "o stops"])


def test_lost_events_are_noted_once_and_shown():
    device = _FakeDevice()
    notes: list = []
    watch = _watch(device, mode="path", notes=notes)
    device.lost_value = 0
    assert watch.check_lost() == 0
    device.lost_value = 340
    watch.check_lost()
    watch.check_lost()
    assert len(notes) == 1
    assert notes[0][1].startswith("340 trace events lost 12:47:03")
    assert "340 events lost" in watch.caption()[1]
    device.lost_value = None  # unreadable: keep what we know
    assert watch.check_lost() == 340


def test_stop_kills_the_rename_stream_and_removes_its_instance():
    class _Proc:
        stdout = iter(())
        terminated = False

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            return 0

    device = _FakeDevice()
    device.rename = _Proc()
    watch = _watch(device)
    watch.start_rename_watch()
    assert watch.rename_ok is True
    watch.stop()
    assert device.rename.terminated
    assert device.rename_stopped


def test_translator_names_the_app_process_of_each_write():
    device = _FakeDevice(_procs(main=12000, tab_17=12262))
    watch = _watch(device)
    listing = watch.initial_processes()
    watch.seed({12000: [12000], 12262: [12262, 12263]}, listing)
    translator = KprobeStreamTranslator()
    translator.reset(MonitorConfig(mode="pid", target_pid=12000, target_path=_FF))
    translator.set_write_scope(
        build_write_scope(scope_aliases(_FF), parse_mounts(_RECORDED_MOUNTS), {})
    )
    translator.set_process_labels(watch.label_for_tid)
    (item,) = translator.feed(_REC_WAL)
    assert item.process == "tab_17 · PlacesStorageWr"


def test_kprobe_setup_follow_seeds_all_processes_then_starts_the_rename_watch(
    monkeypatch,
):
    order: list = []
    device = _FakeDevice(_procs(main=24310, tab_17=24398, gpu=24402))

    def _run_by_app(cls, pids, path=None):
        order.append(("trace", list(pids)))
        cls.last_seeded = {p: [p] for p in pids}
        return object()

    monkeypatch.setattr(KprobeTracer, "run_by_app", classmethod(_run_by_app))
    monkeypatch.setattr(KprobeTracer, "last_seeded", {})
    monkeypatch.setattr(
        KprobeTracer,
        "run_by_pid",
        classmethod(lambda cls, pid, path=None: pytest.fail("one PID only")),
    )
    device.start_rename = lambda pkg: order.append("rename") or None
    controller = _make_controller()
    monkeypatch.setattr(controller, "_watch_device", lambda: device)
    monkeypatch.setattr(controller, "_write_scope", lambda paths: None)
    config = MonitorConfig(
        mode="pid", target_pid=24310, target_path=_FF, app_name=_PKG, follow=True
    )
    _process, translator, desc = controller._kprobe_setup(config)
    assert order == [("trace", [24310, 24398, 24402]), "rename"]
    assert desc == f"app {_PKG} · 3 processes · following (kprobe)"
    assert sorted(translator.watch.procs) == [24310, 24398, 24402]
    assert translator._labels == translator.watch.label_for_tid


def test_kprobe_setup_follow_before_the_app_runs(monkeypatch):
    seeded: list = []
    monkeypatch.setattr(
        KprobeTracer,
        "run_by_app",
        classmethod(lambda cls, pids, path=None: seeded.append(list(pids)) or object()),
    )
    monkeypatch.setattr(KprobeTracer, "last_seeded", {})
    controller = _make_controller()
    monkeypatch.setattr(controller, "_watch_device", lambda: _FakeDevice({}))
    monkeypatch.setattr(controller, "_write_scope", lambda paths: None)
    config = MonitorConfig(mode="pid", target_path=_FF, app_name=_PKG, follow=True)
    _process, translator, desc = controller._kprobe_setup(config)
    assert seeded == [[]]
    assert "not running yet" in desc
    assert translator.watch.blind_since is None


def test_kprobe_launch_teardown_stops_the_watch_and_reads_lost_events(monkeypatch):
    calls: list = []
    started: list = []
    monkeypatch.setattr(
        KprobeTracer, "teardown", classmethod(lambda cls: calls.append("teardown"))
    )
    monkeypatch.setattr(
        MonitorController,
        "_start_output_reader",
        lambda self, wrapper: started.append(wrapper),
    )
    device = _FakeDevice()
    device.lost_value = 12
    warnings: list = []
    controller = _make_controller(log_warning=warnings.append)
    monkeypatch.setattr(controller, "_watch_device", lambda: device)
    config = MonitorConfig(mode="path", target_path="/sdcard")

    class _P:
        def poll(self):
            return 0

    setup = (_P(), KprobeStreamTranslator(), "d")
    assert controller._finish_kprobe_launch(config, setup)
    (wrapper,) = started  # (the task may be gone: other tests' readers)
    assert isinstance(wrapper.watch, MonitorWatch)
    wrapper.run_teardown()
    assert calls == ["teardown"]
    assert any("12 trace events lost" in w for w in warnings)


def test_watch_notes_reach_the_log_and_the_files_lens():
    seen: list = []

    def _cb(event):
        if event.source == "monitor":
            seen.append(event.data)

    EventBus.get().subscribe(EventType.TASK_OUTPUT, _cb)
    warnings: list = []
    try:
        controller = _make_controller(log_warning=warnings.append)
        controller._watch_note("app restarted", "warning", _T)
        controller._watch_changed()
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, _cb)
    assert warnings == ["app restarted"]
    assert seen[0]["monitor_note"] == {
        "text": "app restarted",
        "level": "warning",
        "when": _T,
    }
    assert seen[1]["monitor_status"] is True


def test_resume_after_playback_with_follow_needs_no_pid(monkeypatch):
    start_calls: list = []
    monkeypatch.setattr(
        MonitorController,
        "_start_monitor",
        lambda self, cfg: start_calls.append(cfg) or True,
    )
    controller = _make_controller()
    config = MonitorConfig(
        mode="pid", target_pid=1111, app_name=_PKG, target_path=_FF, follow=True
    )
    assert controller.resume_after_playback(config) is True
    (resolved,) = start_calls
    assert resolved.follow is True
    assert resolved.target_pid is None
    assert resolved.mode == "pid"


def test_listing_parser_feeds_the_watch_end_to_end():
    """parse_app_listing (recorded ps) -> the watch table + labels."""
    text = (
        "UID 10219\n  PID   UID NAME\n24310 10219 org.mozilla.firefox\n"
        "24398 99012 org.mozilla.firefox:sandboxed_tab_17\n"
    )

    class _Dev(_FakeDevice):
        def listing(self, package, tracked):
            return parse_app_listing(text, package)

    watch = _watch(_Dev())
    listing = watch.initial_processes()
    watch.seed({p: [p] for p in listing.processes}, listing)
    assert {p.label for p in watch.procs.values()} == {"main", "tab_17"}


# =============================================================================
# FileSystemMonitorItem.timestamp / .pid (both backends, through the reader)
# =============================================================================


class _LinesProc:
    """A finished-after-its-lines stream for ``_start_output_reader``."""

    def __init__(self, lines):
        self._lines = list(lines)
        self.stdout = self

    def readline(self):
        return self._lines.pop(0) if self._lines else ""

    def poll(self):
        return None if self._lines else 0

    def __iter__(self):
        return iter([])


def _read_items(controller, wrapper) -> list:
    import threading as _threading

    received: list = []
    ended = _threading.Event()
    # The reader ends with its stream; don't let it unregister another
    # test's monitor task later.
    controller._monitor_ended = ended.set

    def _cb(event):
        if event.source == "monitor" and "batch" in event.data:
            received.extend(event.data["batch"])

    EventBus.get().subscribe(EventType.TASK_OUTPUT, _cb)
    try:
        controller._start_output_reader(wrapper)
        assert ended.wait(2.0), "reader did not finish"
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, _cb)
    return received


def test_fsmon_items_carry_capture_time_and_pid(monkeypatch):
    import time as _time

    from sandroid.tui.utils import MonitorProcessWrapper

    controller = _make_controller()
    monkeypatch.setattr(controller, "_get_buffer_interval", lambda: 0.0)
    line = 'FSE_CONTENT_MODIFIED\t4242\t"com.x"\t/data/data/com.x/a.db\n'
    wrapper = MonitorProcessWrapper(
        _LinesProc([line]), MonitorConfig(mode="path", target_path="/data/data/com.x")
    )
    before = _time.time()
    (item,) = _read_items(controller, wrapper)
    assert item.pid == 4242
    assert item.timestamp is not None
    assert before <= item.timestamp <= _time.time()
    # The same capture time the AI chat's recent_events history uses.
    (recent,) = wrapper.recent_events
    assert recent["timestamp"] == item.timestamp
    # build_monitor_item callers that pass no time are unaffected.
    assert build_monitor_item(line.strip()).timestamp is None


def test_kprobe_items_carry_capture_time_and_the_app_process_pid(monkeypatch):
    from sandroid.tui.utils import MonitorProcessWrapper

    device = _FakeDevice(_procs(main=12000, tab_17=12262))
    watch = _watch(device)
    watch.seed({12000: [12000], 12262: [12262, 12263]}, watch.initial_processes())
    translator = KprobeStreamTranslator()
    translator.reset(MonitorConfig(mode="pid", target_pid=12000, target_path=_FF))
    translator.set_write_scope(
        build_write_scope(scope_aliases(_FF), parse_mounts(_RECORDED_MOUNTS), {})
    )
    translator.set_process_labels(watch.label_for_tid, watch.pid_for_tid)
    other_thread = _REC_WAL.replace("PlacesStorageWr-12262", "PlacesStorageWr-12263")
    controller = _make_controller()
    monkeypatch.setattr(controller, "_get_buffer_interval", lambda: 0.0)
    wrapper = MonitorProcessWrapper(
        _LinesProc([other_thread + "\n"]),
        MonitorConfig(mode="pid", target_pid=12000, target_path=_FF),
        translator=translator,
    )
    (item,) = _read_items(controller, wrapper)
    assert item.pid == 12262  # thread 12263 belongs to tab_17's process
    assert item.timestamp is not None
    (recent,) = wrapper.recent_events
    assert recent["timestamp"] == item.timestamp
    assert recent["pid"] == 12262
    # Without an app scope the thread id is all the trace line tells.
    plain = KprobeStreamTranslator()
    plain.reset(MonitorConfig(mode="pid", target_pid=12000, target_path=_FF))
    plain.set_write_scope(
        build_write_scope(scope_aliases(_FF), parse_mounts(_RECORDED_MOUNTS), {})
    )
    (bare,) = plain.feed(_REC_WAL)
    assert bare.pid == 12262


# =============================================================================
# E2E round 2: process attribution (M4), stop (M8), exit detection (L2)
# =============================================================================

from sandroid.tui.controllers.monitor_controller import (
    _recent_event_from_item,
)

#: A thread born after the monitor started (not in the watch's TID table),
#: as the device prints it with the instance's ``record-tgid`` option.
_TGID_WAL = _REC_WAL.replace(
    " PlacesStorageWr-12262   [003]", " Classifier Upda-5656    (   4665) [003]"
)
#: The same thread while the kernel's pid->tgid map didn't have it yet.
_NO_TGID_WAL = _TGID_WAL.replace("(   4665)", "(-------)")
_TGID_OPEN = (
    " Classifier Upda-5656    (   4665) [003] ...1. 16650.1: openat2: "
    '(do_sys_openat2+0x0/0x10c) fname="/data/data/org.mozilla.firefox/files/x.tmp" '
    "flags=0x241"
)
_TGID_DFOR = (
    " Classifier Upda-5656    (   4665) [003] ...1. 16650.2: dfor: "
    "(do_sys_openat2+0xd0/0x10c <- do_filp_open) file=0xffffff801d3e9000 "
    "mode=0x10001f"
)


def _tgid_translator(watch):
    translator = KprobeStreamTranslator()
    translator.reset(
        MonitorConfig(mode="pid", app_name=_PKG, follow=True, target_path=_FF)
    )
    translator.set_write_scope(
        build_write_scope(scope_aliases(_FF), parse_mounts(_RECORDED_MOUNTS), {})
    )
    translator.set_process_labels(watch.label_for_tid, watch.pid_for_tid)
    return translator


def test_a_thread_born_after_start_is_attributed_to_its_process_by_tgid():
    """M4: the TID was written as ``pid`` with only the thread's name."""
    device = _FakeDevice(_procs(main=4665))
    watch = _watch(device)
    watch.seed({4665: [4665]}, watch.initial_processes())
    assert watch.pid_for_tid(5656) is None  # the follow table doesn't know it
    translator = _tgid_translator(watch)

    (item,) = translator.feed(_TGID_WAL)
    assert (item.pid, item.tid) == (4665, 5656)
    assert item.process == "main · Classifier Upda"
    assert _recent_event_from_item(item)["tid"] == 5656
    # "(-------)": the kernel didn't know it yet -- an earlier line did.
    (later,) = translator.feed(_NO_TGID_WAL)
    assert (later.pid, later.tid, later.process) == (4665, 5656, item.process)
    # A CREATE is decided on the do_filp_open RETURN line: same label.
    assert translator.feed(_TGID_OPEN) == []
    (created,) = translator.feed(_TGID_DFOR)
    assert created.label == "CREATE"
    assert (created.pid, created.process) == (4665, "main · Classifier Upda")


def test_the_label_is_stable_per_process_and_names_unknown_processes_by_pid():
    device = _FakeDevice(_procs(main=4665))
    watch = _watch(device)
    watch.seed({4665: [4665]}, watch.initial_processes())
    translator = _tgid_translator(watch)
    main_thread = _REC_WAL.replace(
        " PlacesStorageWr-12262   [003]", " mozilla.firefox-4665    (   4665) [003]"
    )
    (item,) = translator.feed(main_thread)
    assert item.process == "main · mozilla.firefox"
    # A process the watch has no name for (yet): "pid N", never a bare thread.
    child = _REC_WAL.replace(
        " PlacesStorageWr-12262   [003]", " GeckoChild-7001    (   7000) [003]"
    )
    (other,) = translator.feed(child)
    assert (other.pid, other.tid) == (7000, 7001)
    assert other.process == "pid 7000 · GeckoChild"
    # The follow table still answers for a line without the TGID column.
    watch.seed({4665: [4665, 4670]}, watch.initial_processes())
    legacy = _REC_WAL.replace("PlacesStorageWr-12262", "PlacesStorageWr-4670")
    (old_format,) = translator.feed(legacy)
    assert (old_format.pid, old_format.tid) == (4665, 4670)
    assert old_format.process == "main · PlacesStorageWr"


def test_the_main_threads_exit_wakes_the_poll_at_once():
    """L2: after ``am force-stop`` the exit waited for the 5 s poll."""
    device = _FakeDevice(_procs(main=24310))
    watch = _watch(device)
    watch.seed({24310: [24310]}, watch.initial_processes())
    other = (
        "  mozilla.firefox-9999    [001] d..2. 9876.6: sched_process_exit: "
        "comm=mozilla.firefox pid=9999 prio=120"
    )
    watch.on_rename_line(other)
    assert not watch._wake.is_set()  # not a followed process
    watch.on_rename_line(other.replace("9999", "24310"))
    assert watch._wake.is_set()


def test_stop_says_stopping_at_once_and_cleans_up_off_the_ui_thread():
    """M8: a stop froze the UI for 12-18 s with the old caption up."""
    deferred: list = []
    controller = _make_controller(run_off_thread=deferred.append)
    device = _FakeDevice(_procs(main=24310))
    watch = _watch(device)
    watch.seed({24310: [24310]}, watch.initial_processes())
    stopped: list = []
    wrapper = type("W", (), {"config": watch.config, "watch": watch})()
    get_task_service().register(
        name="monitor",
        display_name="Monitor",
        instance=wrapper,
        stop_callback=lambda: stopped.append(1),
        app_name=_PKG,
    )
    seen: list = []

    def _cb(event):
        if event.source == "monitor":
            seen.append(event.data)

    EventBus.get().subscribe(EventType.TASK_OUTPUT, _cb)
    try:
        assert controller.stop() is True
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, _cb)
    assert stopped == []  # nothing slow ran on the calling (UI) thread
    assert watch.caption() == ("monitor stopping…", [f"App {_PKG}"])
    assert any(d.get("monitor_status") for d in seen)  # the caption redraws
    assert controller.can_start() == (
        False,
        "Monitor is still stopping — please wait.",
    )
    assert controller.stop() is True  # a second o: no second stop
    assert len(deferred) == 1
    deferred[0]()
    assert stopped == [1]
    assert not controller.is_running()
    assert controller.can_start() == (True, "")


def test_natural_exit_leaves_a_requested_stops_teardown_to_the_stopper():
    """The reader notices the killed stream first: it must not run the
    (adb-heavy) teardown on the UI thread while the stopping thread does.
    """
    calls: list = []

    class _Wrapper:
        stop_requested = True

        def run_teardown(self):
            calls.append("teardown")

    controller = _make_controller()
    get_task_service().register(
        name="monitor",
        display_name="Monitor",
        instance=_Wrapper(),
        stop_callback=lambda: None,
        app_name=_PKG,
    )
    controller._monitor_ended()
    assert calls == []
    assert not controller.is_running()
