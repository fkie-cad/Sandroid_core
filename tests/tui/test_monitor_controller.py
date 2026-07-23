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


def test_translator_openat2_create_vs_open():
    t = KprobeStreamTranslator()
    t.reset(None)

    created = t.feed(_kp("openat2", 5, 'fname="/data/new.txt" flags=0x241'))
    opened = t.feed(_kp("openat2", 5, 'fname="/data/ro.txt" flags=0x0'))

    assert created[0].category == "create"
    assert created[0].filename == "new.txt"
    assert opened[0].category == "noise"  # plain OPEN (no O_CREAT)


def test_translator_metadata_and_rename_events():
    t = KprobeStreamTranslator()
    t.reset(None)

    mkdir = t.feed(_kp("mkdir", 5, 'name="/data/sub"'))
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
    assert "+2 paths" in descs[0]


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
