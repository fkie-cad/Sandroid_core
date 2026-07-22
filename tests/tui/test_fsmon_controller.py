"""Unit tests for FSMonController's EventBus integration + open_files_tab hook.

Covers the non-UI pieces of the Monitor sub-tab work:

1. ``_log_fsmon_output_batch`` publishes the WHOLE BATCH as a SINGLE
   ``EventType.TASK_OUTPUT`` event (``source="fsmon"``, ``data["batch"]`` a
   list of structured ``FSMonDisplayItem``s -- one per parsed line), not one
   event per line (Part B -- grouping/dedup/visibility-filtering/tallying/
   width-aware rendering all now live in ``MonitorView``, not here). Bus-
   publish only, the old direct Background-Activity-log call was removed
   (Background Activity now gets fsmon lines only via
   ``TASK_STARTED``/``TASK_STOPPED`` lifecycle notices, not ``TASK_OUTPUT``;
   see ``MainScreen``'s ``_ACTIVITY_LOG_EXCLUDED_SOURCES``).
2. ``_start_fsmon`` calls the injected ``open_files_tab`` callback once fsmon
   has actually started (after TaskService registration), not merely when
   the config modal opens.
3. ``parse_fsmon_line``/``FSMON_EVENT_INFO``/``format_fsmon_event_row``/
   ``build_fsmon_display_item`` -- the real ``FSE_*`` tab-separated wire
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
from sandroid.services import get_task_service
from sandroid.tui.controllers.fsmon_controller import (
    FSMON_EVENT_INFO,
    FSMonConfig,
    FSMonController,
    FSMonDisplayItem,
    FSMonEvent,
    build_fsmon_display_item,
    colorize_fsmon_line,
    format_fsmon_event_row,
    parse_fsmon_line,
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


def _fse(
    event_type: str, path: str, pid: int = 123, process: str = "com.example.app"
) -> str:
    """Build a real tab-separated fsmon wire-format line for tests."""
    return f'{event_type}\t{pid}\t"{process}"\t{path}'


def test_log_fsmon_output_batch_publishes_one_event_for_the_whole_batch():
    """Part B: the WHOLE BATCH is published as a SINGLE TASK_OUTPUT event
    (``data["batch"]`` a list of structured items), not one event per line.

    Bus-publish only: the old direct Background-Activity-log call was
    removed (Problem 1) -- there is no more ``log_message`` callback on
    ``FSMonController`` at all.
    """
    received: list[Event] = []
    EventBus.get().subscribe(EventType.TASK_OUTPUT, received.append)
    try:
        controller = _make_controller()

        lines = [_fse("FSE_CREATE_FILE", f"/data/file_{i}.txt") for i in range(8)]
        controller._log_fsmon_output_batch(lines)

        # ONE event for the whole batch now, not one per line.
        assert len(received) == 1
        event = received[0]
        assert event.source == "fsmon"
        assert event.data["task_name"] == "FSMon"

        batch = event.data["batch"]
        assert len(batch) == len(lines)
        for item, i in zip(batch, range(len(lines)), strict=True):
            assert item.category == "create"
            assert item.label == "CREATE"
            assert item.directory == "/data"
            assert item.filename == f"file_{i}.txt"
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, received.append)


def test_log_fsmon_output_batch_does_not_call_removed_log_message_kwarg():
    """``log_message`` is no longer a constructor parameter -- passing it
    must raise TypeError (confirms the dead param was actually removed).
    """
    with pytest.raises(TypeError):
        FSMonController(log_message=lambda *_: None)


def test_log_fsmon_output_batch_reuses_build_fsmon_display_item():
    """The published batch's items are exactly what
    ``build_fsmon_display_item`` produces (no re-implementation of the
    parsing/color/category lookup a second time).
    """
    received: list[Event] = []
    EventBus.get().subscribe(EventType.TASK_OUTPUT, received.append)
    try:
        controller = _make_controller()
        line = _fse("FSE_DELETE", "/data/gone.txt")
        controller._log_fsmon_output_batch([line])
        assert len(received) == 1
        batch = received[0].data["batch"]
        assert len(batch) == 1
        assert batch[0] == build_fsmon_display_item(line)
        assert batch[0].category == "delete"
        assert batch[0].color == "#fb7185"
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, received.append)


def test_log_fsmon_output_batch_empty_lines_publishes_nothing():
    """An empty batch must not publish an empty/no-op event at all."""
    received: list[Event] = []
    EventBus.get().subscribe(EventType.TASK_OUTPUT, received.append)
    try:
        controller = _make_controller()
        controller._log_fsmon_output_batch([])
        assert received == []
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
        line = _fse("FSE_OPEN", "/data/read.txt")
        controller._log_fsmon_output_batch([line])

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
        batch = seen_fsmon[0].data["batch"]
        assert len(batch) == 1
        assert batch[0].category == "noise"
    finally:
        EventBus.get().unsubscribe(EventType.TASK_OUTPUT, handler)


# =============================================================================
# parse_fsmon_line / FSMON_EVENT_INFO / format_fsmon_event_row
# =============================================================================


def test_parse_fsmon_line_valid():
    line = _fse("FSE_CREATE_FILE", "/data/data/com.example.app/file.txt", pid=456)
    event = parse_fsmon_line(line)
    assert event == FSMonEvent(
        event_type="FSE_CREATE_FILE",
        pid=456,
        process="com.example.app",
        path="/data/data/com.example.app/file.txt",
        new_path=None,
    )


def test_parse_fsmon_line_rename_splits_old_and_new_path():
    line = 'FSE_RENAME\t789\t"com.example.app"\t/data/old.txt -> /data/new.txt'
    event = parse_fsmon_line(line)
    assert event is not None
    assert event.event_type == "FSE_RENAME"
    assert event.path == "/data/old.txt"
    assert event.new_path == "/data/new.txt"


def test_parse_fsmon_line_malformed_returns_none():
    assert parse_fsmon_line("not a valid fsmon line") is None
    assert parse_fsmon_line("FSE_CREATE_FILE\t123") is None
    assert parse_fsmon_line("") is None


def test_fsmon_event_info_spot_check():
    assert FSMON_EVENT_INFO["FSE_CREATE_FILE"].label == "CREATE"
    assert FSMON_EVENT_INFO["FSE_CREATE_FILE"].category == "create"
    assert FSMON_EVENT_INFO["FSE_CONTENT_MODIFIED"].label == "MODIFY"
    assert FSMON_EVENT_INFO["FSE_CONTENT_MODIFIED"].category == "modify"
    assert FSMON_EVENT_INFO["FSE_CONTENT_MODIFIED"].color == "#a78bfa"
    assert FSMON_EVENT_INFO["FSE_DELETE"].category == "delete"
    assert FSMON_EVENT_INFO["FSE_RENAME"].category == "rename"
    assert FSMON_EVENT_INFO["FSE_ATTRIB"].category == "attrs"
    assert FSMON_EVENT_INFO["FSE_STAT_CHANGED"].category == "attrs"
    assert FSMON_EVENT_INFO["FSE_XATTR_MODIFIED"].category == "attrs"
    assert FSMON_EVENT_INFO["FSE_OPEN"].category == "noise"
    assert FSMON_EVENT_INFO["FSE_CLOSE"].category == "noise"


def test_fsmon_content_modified_and_close_get_correct_colors_regression():
    """Direct regression test for the literal bug being fixed: the old
    substring-keyword matching missed FSE_CONTENT_MODIFIED (not a substring
    match for "MODIFY") and FSE_CLOSE (no rule mentioned it at all), so both
    got zero color/category. Exact-token lookup must fix both.
    """
    modified_line = _fse("FSE_CONTENT_MODIFIED", "/data/file.txt")
    close_line = _fse("FSE_CLOSE", "/data/file.txt")

    modified_colorized = colorize_fsmon_line(modified_line)
    close_colorized = colorize_fsmon_line(close_line)

    assert "#a78bfa" in modified_colorized
    assert "#5b6479" in close_colorized

    _, modified_category = format_fsmon_event_row(modified_line)
    _, close_category = format_fsmon_event_row(close_line)
    assert modified_category == "modify"
    assert close_category == "noise"


def test_format_fsmon_event_row_strips_prefix_and_truncates():
    long_suffix = "a" * 50
    line = _fse(
        "FSE_CREATE_FILE",
        f"/data/data/com.example.app/cache/{long_suffix}/file.txt",
    )
    prefix_candidates = ("/data/data/com.example.app/",)
    message, category = format_fsmon_event_row(line, prefix_candidates)

    assert category == "create"
    # Redundant package prefix must be gone.
    assert "/data/data/com.example.app/" not in message
    # Long remainder must be left-truncated keeping the tail.
    assert "…" in message
    assert message.endswith("file.txt")


def test_format_fsmon_event_row_unparseable_line_falls_back_gracefully():
    message, category = format_fsmon_event_row("totally not fsmon output")
    assert category is None
    assert message  # never silently dropped
    assert "totally not fsmon output" in message


def test_format_fsmon_event_row_unknown_token_falls_back_gracefully():
    line = _fse("FSE_SOMETHING_NEW", "/data/file.txt")
    message, category = format_fsmon_event_row(line)
    assert category is None
    assert "FSE_SOMETHING_NEW" in message
    assert "/data/file.txt" in message


# =============================================================================
# build_fsmon_display_item -- structured per-item data for MonitorView's own
# grouping/dedup/rendering pipeline (Part B, B1)
# =============================================================================


def test_build_fsmon_display_item_splits_directory_and_filename():
    line = _fse("FSE_CREATE_FILE", "/data/data/com.example.app/cache/sub/file.txt")
    item = build_fsmon_display_item(line, ("/data/data/com.example.app/",))

    assert item == FSMonDisplayItem(
        label="CREATE",
        color="#4ade80",
        category="create",
        directory="cache/sub",
        filename="file.txt",
        new_directory=None,
        new_filename=None,
    )


def test_build_fsmon_display_item_bare_filename_has_empty_directory():
    """A path with no '/' at all (after prefix-stripping) yields an empty
    directory -- never groups into a breadcrumb run with anything else.
    """
    item = build_fsmon_display_item(_fse("FSE_CREATE_FILE", "bare.txt"))
    assert item.directory == ""
    assert item.filename == "bare.txt"


def test_build_fsmon_display_item_rename_splits_old_and_new_directory():
    line = _fse(
        "FSE_RENAME",
        "/data/data/com.example.app/cache/old.txt -> /data/data/com.example.app/cache/new.txt",
    )
    item = build_fsmon_display_item(line, ("/data/data/com.example.app/",))
    assert item.directory == "cache"
    assert item.filename == "old.txt"
    assert item.new_directory == "cache"
    assert item.new_filename == "new.txt"


def test_build_fsmon_display_item_rename_with_different_new_directory():
    line = _fse(
        "FSE_RENAME",
        "/data/data/com.example.app/cache/old.txt -> /data/data/com.example.app/moved/new.txt",
    )
    item = build_fsmon_display_item(line, ("/data/data/com.example.app/",))
    assert item.directory == "cache"
    assert item.new_directory == "moved"


def test_build_fsmon_display_item_unknown_token_falls_back_gracefully():
    line = _fse("FSE_SOMETHING_NEW", "/data/file.txt")
    item = build_fsmon_display_item(line)
    assert item.label == "FSE_SOMETHING_NEW"
    assert item.color is None
    assert item.category is None
    assert item.directory == "/data"
    assert item.filename == "file.txt"


def test_build_fsmon_display_item_malformed_line_never_raises_or_drops():
    item = build_fsmon_display_item("totally not fsmon output")
    assert item.category is None
    assert item.directory == ""
    assert item.filename == "totally not fsmon output"


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
# _start_fsmon PID-mode branch — honest fanotify-aware fallback (Part A)
# =============================================================================


def _patch_binary_and_reader(monkeypatch):
    monkeypatch.setattr(FSMon, "check_and_install_fsmon", classmethod(lambda cls: None))
    monkeypatch.setattr(
        FSMonController, "_start_output_reader", lambda self, wrapper: None
    )


def test_start_fsmon_pid_mode_uses_run_fsmon_by_pid_when_fanotify_supported(
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
    config = FSMonConfig(
        mode="pid",
        target_pid=1234,
        target_path="/data/data/com.example.app",
        app_name="com.example.app",
    )

    started = controller._start_fsmon(config)

    assert started is True
    assert pid_calls == [(1234, "/data/data/com.example.app")]
    assert path_calls == []
    assert fallback_calls == []

    task = get_task_service().get_task("fsmon")
    assert task.instance.config.mode == "pid"
    assert task.instance.config.target_pid == 1234


def test_start_fsmon_pid_mode_falls_back_to_path_when_fanotify_unsupported(
    monkeypatch,
):
    """No fanotify on this device: fall back to run_fsmon_by_path, register a
    path-mode FSMonConfig (not the original pid-mode one), and fire
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
    config = FSMonConfig(
        mode="pid",
        target_pid=1234,
        target_path="/data/data/com.example.app",
        app_name="com.example.app",
    )

    started = controller._start_fsmon(config)

    assert started is True
    assert pid_calls == []  # PID-mode entry point must NOT be used
    assert path_calls == ["/data/data/com.example.app"]
    assert fallback_calls == ["/data/data/com.example.app"]

    # Header-honesty: the registered task's config must reflect what's
    # ACTUALLY running (path-mode), not the originally requested PID-mode.
    task = get_task_service().get_task("fsmon")
    resolved_config = task.instance.config
    assert resolved_config.mode == "path"
    assert resolved_config.target_pid is None
    assert resolved_config.target_path == "/data/data/com.example.app"
    assert resolved_config.app_name == "com.example.app"


def test_start_fsmon_pid_mode_fallback_works_without_callback(monkeypatch):
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
    config = FSMonConfig(
        mode="pid", target_pid=1234, target_path="/data/", app_name="com.example.app"
    )

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
