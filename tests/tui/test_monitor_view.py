"""Headless Textual Pilot smoke tests for the Monitor sub-tab (MonitorView).

No physical device and no real fsmon process needed: MonitorView only ever
reads ``TaskService`` (a real, process-wide singleton — cleaned up via an
autouse fixture below) and the EventBus (``EventType.TASK_OUTPUT``/
``TASK_STARTED``/``TASK_STOPPED``). A minimal single-widget host App is
enough to exercise mount/compose, the live-event counter, and source-based
filtering; a second test mounts the real ``FilesPanel`` to confirm Monitor
is wired in as a real sub-view (not the old stub) reachable via the inner
ContentSwitcher.
"""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.widgets import RichLog

from sandroid.core.events import Event, EventBus, EventType
from sandroid.services import get_task_service
from sandroid.tui.controllers.fsmon_controller import FSMonConfig
from sandroid.tui.widgets.files_panel import FilesPanel
from sandroid.tui.widgets.monitor_view import MonitorView, _categorize_fsmon_line


@pytest.fixture(autouse=True)
def _clean_fsmon_task():
    """Guard the real TaskService singleton against cross-test leakage."""
    svc = get_task_service()
    svc._tasks.pop("fsmon", None)
    yield
    svc._tasks.pop("fsmon", None)


@pytest.fixture(autouse=True)
def _clean_eventbus_history():
    EventBus.get().clear_history()
    yield
    EventBus.get().clear_history()


def _publish_fsmon_output(message: str) -> None:
    EventBus.get().publish(
        Event(
            type=EventType.TASK_OUTPUT,
            data={"task_name": "FSMon", "message": message},
            source="fsmon",
        )
    )


class _MonitorHarness(App):
    """Minimal single-widget host app for MonitorView."""

    def compose(self) -> ComposeResult:
        yield MonitorView(id="files-monitor")


@pytest.mark.asyncio
async def test_stopped_state_before_any_start() -> None:
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        await pilot.pause()
        assert view.glance_fragment() == "fsmon ○ stopped"


@pytest.mark.asyncio
async def test_task_output_event_increments_counter_and_reaches_log() -> None:
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        assert view._total == 0

        _publish_fsmon_output("[green]CREATE /data/new_file.txt[/green]")
        await pilot.pause()

        assert view._total == 1
        assert view._create == 1

        log = view.query_one("#monitor-log", RichLog)
        # RichLog buffers rendered lines; confirm our line actually landed
        # (not just that the counter moved) by checking its line count grew
        # past the startup hint line written in on_mount.
        assert len(log.lines) >= 2


@pytest.mark.asyncio
async def test_log_is_capped_at_configured_max_lines(monkeypatch) -> None:
    """RichLog must actually trim old lines once ``tui.fsmon_max_lines`` is
    exceeded -- the now-retired ``FSMonRunningModal`` capped its own RichLog
    at this value (via the constructor's ``max_lines`` param), and Monitor's
    live, un-throttled feed must not regress to unbounded growth.
    """
    monkeypatch.setattr(MonitorView, "_get_config_max_lines", staticmethod(lambda: 5))

    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        log = view.query_one("#monitor-log", RichLog)
        assert log.max_lines == 5

        for i in range(20):
            _publish_fsmon_output(f"CREATE /data/file_{i}.txt")
            await pilot.pause()

        assert len(log.lines) <= 5
        # The event tally itself is a separate concern from the log's
        # display buffer -- the cap must not silently drop counted events.
        assert view._total == 20


@pytest.mark.asyncio
async def test_task_output_filtered_by_source_excludes_other_tasks() -> None:
    """A TASK_OUTPUT event from an unrelated task (e.g. friTap) must not be
    counted or rendered here — mirrors FriTapPanel's own source filter.
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)

        EventBus.get().publish(
            Event(
                type=EventType.TASK_OUTPUT,
                data={"task_name": "FriTap", "message": "unrelated fritap output"},
                source="fritap",
            )
        )
        await pilot.pause()

        assert view._total == 0

        _publish_fsmon_output("DELETE /data/gone.txt")
        await pilot.pause()
        assert view._total == 1
        assert view._delete == 1


@pytest.mark.asyncio
async def test_multiple_events_accumulate_per_category() -> None:
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)

        _publish_fsmon_output("CREATE /data/a.txt")
        _publish_fsmon_output("WRITE /data/a.txt")
        _publish_fsmon_output("DELETE /data/b.txt")
        _publish_fsmon_output("RENAME /data/c.txt -> /data/d.txt")
        _publish_fsmon_output("OPEN /data/e.txt")
        await pilot.pause()

        assert view._total == 5
        assert view._create == 2  # CREATE + WRITE
        assert view._delete == 1
        assert view._rename == 1
        assert view._access == 1


@pytest.mark.asyncio
async def test_glance_fragment_reflects_running_task_and_counter() -> None:
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)

        _publish_fsmon_output("CREATE /data/a.txt")
        await pilot.pause()

        # Register a fake fsmon task so is_running("fsmon") is True (no real
        # fsmon binary/process involved).
        get_task_service().register(
            name="fsmon",
            display_name="FSMon",
            instance=object(),
            stop_callback=lambda: None,
        )
        try:
            assert view.glance_fragment() == "fsmon ● running · 1 events"
        finally:
            get_task_service().unregister("fsmon")


@pytest.mark.asyncio
async def test_clear_log_resets_counters() -> None:
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        _publish_fsmon_output("CREATE /data/a.txt")
        await pilot.pause()
        assert view._total == 1

        view.action_clear_log()
        await pilot.pause()
        assert view._total == 0
        assert view._create == 0


def test_categorize_fsmon_line_matches_color_rules() -> None:
    """Category derivation reuses FSMON_COLOR_RULES rather than a second,
    hand-rolled keyword list — spot-check all four buckets plus "no match".
    """
    assert _categorize_fsmon_line("CREATE /data/a.txt") == "create"
    assert _categorize_fsmon_line("WRITE /data/a.txt") == "create"
    assert _categorize_fsmon_line("MODIFY /data/a.txt") == "create"
    assert _categorize_fsmon_line("DELETE /data/a.txt") == "delete"
    assert _categorize_fsmon_line("REMOVE /data/a.txt") == "delete"
    assert _categorize_fsmon_line("UNLINK /data/a.txt") == "delete"
    assert _categorize_fsmon_line("RENAME /data/a.txt") == "rename"
    assert _categorize_fsmon_line("MOVE /data/a.txt") == "rename"
    assert _categorize_fsmon_line("OPEN /data/a.txt") == "access"
    assert _categorize_fsmon_line("ACCESS /data/a.txt") == "access"
    assert _categorize_fsmon_line("READ /data/a.txt") == "access"
    assert _categorize_fsmon_line("STAT /data/a.txt") is None


@pytest.mark.asyncio
async def test_notify_fsmon_stopped_for_playback_writes_notice_without_bumping_counters() -> (
    None
):
    """The Play-safety-net notice must reach the log but NOT be treated as a
    live fsmon event — it's a system notice, not an fsmon-reported change.
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)

        view.notify_fsmon_stopped_for_playback()
        await pilot.pause()

        assert view._total == 0
        log = view.query_one("#monitor-log", RichLog)
        assert len(log.lines) >= 2  # startup hint + the new notice line


@pytest.mark.asyncio
async def test_offer_resume_shows_bar_and_clear_hides_it() -> None:
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        bar = view.query_one("#monitor-resume-bar")
        assert "-hidden" in bar.classes

        config = FSMonConfig(mode="path", target_path="/data/local/tmp/")
        view.offer_resume(config)
        await pilot.pause()

        assert "-hidden" not in bar.classes
        assert view._resume_config is config

        view.clear_resume_offer()
        await pilot.pause()

        assert "-hidden" in bar.classes
        assert view._resume_config is None


@pytest.mark.asyncio
async def test_fsmon_started_event_clears_pending_resume_offer() -> None:
    """A fresh fsmon start (Resume button, or plain 'o') must drop any
    stale Resume offer — it refers to an already-superseded config.
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        view.offer_resume(FSMonConfig(mode="path", target_path="/data/"))
        await pilot.pause()
        assert view._resume_config is not None

        get_task_service().register(
            name="fsmon",
            display_name="FSMon",
            instance=object(),
            stop_callback=lambda: None,
        )
        try:
            _publish_fsmon_output("CREATE /data/a.txt")  # not the trigger…
            await pilot.pause()

            EventBus.get().publish(
                Event(
                    type=EventType.TASK_STARTED,
                    data={"task_name": "fsmon"},
                    source="fsmon",
                )
            )
            await pilot.pause()

            assert view._resume_config is None
            bar = view.query_one("#monitor-resume-bar")
            assert "-hidden" in bar.classes
        finally:
            get_task_service().unregister("fsmon")


@pytest.mark.asyncio
async def test_resume_button_press_delegates_to_app(monkeypatch) -> None:
    """Pressing "Resume monitoring" must hand the stashed config straight to
    App.resume_fsmon_after_playback — MonitorView itself never resolves
    PIDs or re-forks fsmon.
    """

    class _AppWithResume(App):
        def compose(self) -> ComposeResult:
            yield MonitorView(id="files-monitor")

        def __init__(self) -> None:
            super().__init__()
            self.resume_calls: list = []

        def resume_fsmon_after_playback(self, config) -> None:
            self.resume_calls.append(config)

    app = _AppWithResume()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        config = FSMonConfig(mode="path", target_path="/data/")
        view.offer_resume(config)
        await pilot.pause()

        from textual.widgets import Button

        await pilot.click(view.query_one("#monitor-resume-btn", Button))
        await pilot.pause()

        assert app.resume_calls == [config]


@pytest.mark.asyncio
async def test_files_panel_mounts_real_monitor_view_not_stub() -> None:
    """FilesPanel's inner ContentSwitcher must host the real MonitorView
    (not the old files_panel.py stub) as the initial, focused sub-tab.
    """

    class _FilesHarness(App):
        def compose(self) -> ComposeResult:
            yield FilesPanel(id="files-panel")

    app = _FilesHarness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()

        monitor = panel.query_one("#files-monitor")
        assert isinstance(monitor, MonitorView)
        assert monitor.glance_fragment() == "fsmon ○ stopped"

        _publish_fsmon_output("CREATE /data/new_file.txt")
        await pilot.pause()
        assert monitor._total == 1
