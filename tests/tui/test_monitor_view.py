"""Headless Textual Pilot smoke tests for the Monitor sub-tab (MonitorView).

No physical device and no real monitor process needed: MonitorView only ever
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
from sandroid.tui.controllers.monitor_controller import (
    MonitorConfig,
    build_monitor_item,
)
from sandroid.tui.widgets.files_panel import FilesPanel
from sandroid.tui.widgets.monitor_view import MonitorView


@pytest.fixture(autouse=True)
def _clean_monitor_task():
    """Guard the real TaskService singleton against cross-test leakage."""
    svc = get_task_service()
    svc._tasks.pop("monitor", None)
    yield
    svc._tasks.pop("monitor", None)


@pytest.fixture(autouse=True)
def _clean_eventbus_history():
    EventBus.get().clear_history()
    yield
    EventBus.get().clear_history()


def _fse(
    event_type: str,
    path: str,
    new_path: str | None = None,
    pid: int = 123,
    process: str = "com.example.app",
) -> str:
    """Build a real tab-separated monitor wire-format line for tests."""
    if new_path is not None:
        return f'{event_type}\t{pid}\t"{process}"\t{path} -> {new_path}'
    return f'{event_type}\t{pid}\t"{process}"\t{path}'


def _publish_monitor_batch(lines: list[str]) -> None:
    """Publish a WHOLE BATCH of raw monitor lines as ONE TASK_OUTPUT event,
    matching production's real batch-shaped contract exactly (see
    ``MonitorController._log_monitor_output_batch``/``_publish_monitor_batch``,
    Part B): each line is parsed via the real ``build_monitor_item``
    (no re-implementation of that parsing here), and the whole list of
    structured items is published as ``data["batch"]`` in one event.
    """
    items = [build_monitor_item(line) for line in lines]
    EventBus.get().publish(
        Event(
            type=EventType.TASK_OUTPUT,
            data={"task_name": "Monitor", "batch": items},
            source="monitor",
        )
    )


def _publish_monitor_output(line: str) -> None:
    """Publish a single raw monitor line as a batch-of-1 event.

    A single-line "batch of 1" is the natural adaptation of the old
    per-line helper for most of this file's existing tests: since tallying
    is unconditional and per-item regardless of batching (see B1 of the
    monitor follow-up plan), everything that asserted counters after N
    single-line publishes stays true under the new batch-shaped model. A
    batch of 1 also never forms a directory-run (needs 2+), so it always
    renders via the isolated/inline path -- matching this file's existing
    assertions about single events landing as one row.
    """
    _publish_monitor_batch([line])


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
        assert view.glance_fragment() == "monitor ○ stopped"


@pytest.mark.asyncio
async def test_task_output_event_increments_counter_and_reaches_log() -> None:
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        assert view._total == 0

        _publish_monitor_output(_fse("FSE_CREATE_FILE", "/data/new_file.txt"))
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
    """RichLog must actually trim old lines once ``tui.monitor_max_lines`` is
    exceeded -- the now-retired ``MonitorRunningModal`` capped its own RichLog
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
            _publish_monitor_output(_fse("FSE_CREATE_FILE", f"/data/file_{i}.txt"))
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

        _publish_monitor_output(_fse("FSE_DELETE", "/data/gone.txt"))
        await pilot.pause()
        assert view._total == 1
        assert view._delete == 1


@pytest.mark.asyncio
async def test_multiple_events_accumulate_per_category() -> None:
    """The new 6-bucket model: create/modify/delete/rename/attrs/noise.

    Counters always tally regardless of visibility mode -- includes the
    default-hidden "noise" (OPEN/CLOSE) bucket, which still counts even
    though its line isn't rendered by default.
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)

        _publish_monitor_output(_fse("FSE_CREATE_FILE", "/data/a.txt"))
        _publish_monitor_output(_fse("FSE_CREATE_DIR", "/data/dir"))
        _publish_monitor_output(_fse("FSE_CONTENT_MODIFIED", "/data/a.txt"))
        _publish_monitor_output(_fse("FSE_DELETE", "/data/b.txt"))
        _publish_monitor_output(
            _fse("FSE_RENAME", "/data/c.txt", new_path="/data/d.txt")
        )
        _publish_monitor_output(_fse("FSE_ATTRIB", "/data/e.txt"))
        _publish_monitor_output(_fse("FSE_OPEN", "/data/f.txt"))
        await pilot.pause()

        assert view._total == 7
        assert view._create == 2  # CREATE_FILE + CREATE_DIR
        assert view._modify == 1
        assert view._delete == 1
        assert view._rename == 1
        assert view._attrs == 1
        assert view._noise == 1


@pytest.mark.asyncio
async def test_glance_fragment_reflects_running_task_and_counter() -> None:
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)

        _publish_monitor_output(_fse("FSE_CREATE_FILE", "/data/a.txt"))
        await pilot.pause()

        # Register a fake monitor task so is_running("monitor") is True (no real
        # monitor binary/process involved).
        get_task_service().register(
            name="monitor",
            display_name="Monitor",
            instance=object(),
            stop_callback=lambda: None,
        )
        try:
            assert view.glance_fragment() == "monitor ● running · 1 events"
        finally:
            get_task_service().unregister("monitor")


@pytest.mark.asyncio
async def test_clear_log_resets_counters() -> None:
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        _publish_monitor_output(_fse("FSE_CREATE_FILE", "/data/a.txt"))
        await pilot.pause()
        assert view._total == 1

        view.action_clear_log()
        await pilot.pause()
        assert view._total == 0
        assert view._create == 0


# =============================================================================
# Per-category visibility (tui.monitor_event_visibility) + the 'v' verbose toggle
# =============================================================================


@pytest.mark.asyncio
async def test_noise_hidden_by_default_but_still_counted(monkeypatch) -> None:
    """Default visibility ('noise' -> 'verbose', verbose off) hides OPEN/
    CLOSE lines from the RichLog body, but the _noise counter still tallies
    them -- counting and rendering are separate concerns.
    """
    monkeypatch.setattr(
        MonitorView,
        "_get_config_visibility",
        staticmethod(
            lambda: {
                "create": "always",
                "modify": "always",
                "delete": "always",
                "rename": "always",
                "attrs": "always",
                "noise": "verbose",
            }
        ),
    )

    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        log = view.query_one("#monitor-log", RichLog)
        lines_before = len(log.lines)

        _publish_monitor_output(_fse("FSE_OPEN", "/data/a.txt"))
        await pilot.pause()

        assert view._noise == 1
        assert len(log.lines) == lines_before  # not rendered


@pytest.mark.asyncio
async def test_verbose_toggle_is_forward_only(monkeypatch) -> None:
    """A line published BEFORE toggling verbose-on stays hidden; a line
    published AFTER shows -- toggling never retroactively replays skipped
    lines.
    """
    monkeypatch.setattr(
        MonitorView,
        "_get_config_visibility",
        staticmethod(lambda: {"noise": "verbose"}),
    )

    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        log = view.query_one("#monitor-log", RichLog)

        _publish_monitor_output(_fse("FSE_OPEN", "/data/before.txt"))
        await pilot.pause()
        lines_after_hidden = len(log.lines)
        assert not any("before.txt" in line.text for line in log.lines)

        view.action_toggle_verbose()
        await pilot.pause()
        assert view._verbose is True
        # The toggle itself writes an inline notice -- log grows by at least
        # that, but the earlier "before.txt" line must NOT have appeared.
        assert not any("before.txt" in line.text for line in log.lines)

        _publish_monitor_output(_fse("FSE_OPEN", "/data/after.txt"))
        await pilot.pause()
        assert any("after.txt" in line.text for line in log.lines)
        assert len(log.lines) > lines_after_hidden


@pytest.mark.asyncio
async def test_never_category_stays_hidden_even_with_verbose_on(monkeypatch) -> None:
    """A category configured to 'never' must stay hidden regardless of the
    'v' toggle -- only Settings can change that, not the runtime toggle.
    """
    monkeypatch.setattr(
        MonitorView,
        "_get_config_visibility",
        staticmethod(lambda: {"attrs": "never"}),
    )

    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        log = view.query_one("#monitor-log", RichLog)

        view.action_toggle_verbose()
        await pilot.pause()
        assert view._verbose is True

        _publish_monitor_output(_fse("FSE_ATTRIB", "/data/perm.txt"))
        await pilot.pause()

        assert view._attrs == 1
        assert not any("perm.txt" in line.text for line in log.lines)


@pytest.mark.asyncio
async def test_header_renders_noise_badge_when_verbose_off(monkeypatch) -> None:
    monkeypatch.setattr(
        MonitorView,
        "_get_config_visibility",
        staticmethod(lambda: {"noise": "verbose"}),
    )

    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)

        get_task_service().register(
            name="monitor",
            display_name="Monitor",
            instance=object(),
            stop_callback=lambda: None,
        )
        try:
            _publish_monitor_output(_fse("FSE_OPEN", "/data/a.txt"))
            await pilot.pause()

            header = view._render_header()
            assert "events" in header
            assert "1c" in header or "0c" in header  # 5-letter inline counts
            assert "+1 hidden (v)" in header

            view.action_toggle_verbose()
            header_verbose = view._render_header()
            assert "noise" not in header_verbose
        finally:
            get_task_service().unregister("monitor")


@pytest.mark.asyncio
async def test_header_hidden_badge_is_generic_across_categories(monkeypatch) -> None:
    """The hidden-count badge must reflect ANY category configured to
    "verbose", not just the "noise" bucket -- and must exclude "never"
    categories, since pressing 'v' can't reveal those (that's a Settings
    change, not a runtime toggle).
    """
    monkeypatch.setattr(
        MonitorView,
        "_get_config_visibility",
        staticmethod(
            lambda: {"noise": "always", "modify": "verbose", "delete": "never"}
        ),
    )

    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)

        get_task_service().register(
            name="monitor",
            display_name="Monitor",
            instance=object(),
            stop_callback=lambda: None,
        )
        try:
            # noise=always -> renders, doesn't count toward the badge.
            _publish_monitor_output(_fse("FSE_OPEN", "/data/a.txt"))
            # modify=verbose -> hidden, DOES count toward the badge.
            _publish_monitor_output(_fse("FSE_CONTENT_MODIFIED", "/data/b.txt"))
            # delete=never -> hidden, must NOT count toward the badge (v
            # can't reveal it).
            _publish_monitor_output(_fse("FSE_DELETE", "/data/c.txt"))
            await pilot.pause()

            header = view._render_header()
            assert "+1 hidden (v)" in header

            view.action_toggle_verbose()
            header_verbose = view._render_header()
            assert "hidden" not in header_verbose
        finally:
            get_task_service().unregister("monitor")


# =============================================================================
# Grouped/dedup view (Part B, B2) -- directory breadcrumbs, isolated inline
# rows, consecutive-identical collapse, and the tally-preservation invariant
# =============================================================================


@pytest.mark.asyncio
async def test_batch_of_same_directory_run_emits_one_breadcrumb() -> None:
    """A batch of >=2 same-directory items gets exactly ONE breadcrumb, with
    the items rendered underneath by filename only (not full paths).
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        log = view.query_one("#monitor-log", RichLog)

        lines = [
            _fse("FSE_CREATE_FILE", "/data/cache/one.txt"),
            _fse("FSE_CREATE_FILE", "/data/cache/two.txt"),
            _fse("FSE_CREATE_FILE", "/data/cache/three.txt"),
        ]
        _publish_monitor_batch(lines)
        await pilot.pause()

        breadcrumb_lines = [line for line in log.lines if "▸" in line.text]
        assert len(breadcrumb_lines) == 1
        assert "/data/cache" in breadcrumb_lines[0].text

        # Rows underneath show just the filename, not the full path again.
        for name in ("one.txt", "two.txt", "three.txt"):
            matches = [line for line in log.lines if name in line.text]
            assert len(matches) == 1
            assert "/data/cache" not in matches[0].text


@pytest.mark.asyncio
async def test_isolated_single_directory_items_render_inline_no_breadcrumb() -> None:
    """A batch of items each with a DIFFERENT directory (no run of 2+ formed
    for any of them) produces zero breadcrumbs -- each renders inline with
    directory + filename together.
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        log = view.query_one("#monitor-log", RichLog)

        lines = [
            _fse("FSE_CREATE_FILE", "/data/a/one.txt"),
            _fse("FSE_DELETE", "/data/b/two.txt"),
            _fse("FSE_CREATE_FILE", "/data/c/three.txt"),
        ]
        _publish_monitor_batch(lines)
        await pilot.pause()

        assert not any("▸" in line.text for line in log.lines)
        assert any(
            "/data/a" in line.text and "one.txt" in line.text for line in log.lines
        )
        assert any(
            "/data/b" in line.text and "two.txt" in line.text for line in log.lines
        )
        assert any(
            "/data/c" in line.text and "three.txt" in line.text for line in log.lines
        )


@pytest.mark.asyncio
async def test_mixed_batch_handles_isolated_and_grouped_runs() -> None:
    """A batch mixing an isolated item with a genuine same-directory run
    handles each correctly in the same pass.
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        log = view.query_one("#monitor-log", RichLog)

        lines = [
            _fse("FSE_CREATE_FILE", "/data/solo/alone.txt"),  # isolated
            _fse("FSE_CREATE_FILE", "/data/group/a.txt"),  # run of 2 starts
            _fse("FSE_CREATE_FILE", "/data/group/b.txt"),
        ]
        _publish_monitor_batch(lines)
        await pilot.pause()

        breadcrumb_lines = [line for line in log.lines if "▸" in line.text]
        assert len(breadcrumb_lines) == 1
        assert "/data/group" in breadcrumb_lines[0].text

        # The isolated item shows its directory inline (no breadcrumb).
        assert any(
            "/data/solo" in line.text and "alone.txt" in line.text for line in log.lines
        )
        # The grouped items show only their filename.
        assert any(
            "a.txt" in line.text and "/data/group" not in line.text
            for line in log.lines
        )
        assert any(
            "b.txt" in line.text and "/data/group" not in line.text
            for line in log.lines
        )


@pytest.mark.asyncio
async def test_consecutive_identical_items_collapse_with_count() -> None:
    """Consecutive items sharing the exact same (directory, filename, label)
    collapse into ONE rendered row with a trailing "xN" count.
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        log = view.query_one("#monitor-log", RichLog)

        lines = [_fse("FSE_CREATE_FILE", "/data/cache/dup.txt") for _ in range(4)]
        _publish_monitor_batch(lines)
        await pilot.pause()

        matches = [line for line in log.lines if "dup.txt" in line.text]
        assert len(matches) == 1
        assert "×4" in matches[0].text


@pytest.mark.asyncio
async def test_collapsed_run_tally_equals_n_not_one() -> None:
    """The dedup collapse only affects RENDERING -- the tally underneath an
    "xN" row must equal N, not 1 (tallying happens before collapsing, see
    B1's exact invariant).
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)

        lines = [_fse("FSE_CREATE_FILE", "/data/cache/dup.txt") for _ in range(4)]
        _publish_monitor_batch(lines)
        await pilot.pause()

        assert view._total == 4
        assert view._create == 4


@pytest.mark.asyncio
async def test_hidden_noise_item_within_visible_run_still_tallies_and_does_not_break_grouping(
    monkeypatch,
) -> None:
    """CRITICAL regression test for the defect the plan verification caught:
    a default-hidden "noise" item sitting IN THE MIDDLE of an otherwise
    same-directory, otherwise-visible run must:
    1. Still be tallied into ``_noise`` (the header badge depends on this).
    2. NOT prevent the surrounding visible items from forming their
       directory-run (the gate runs BEFORE grouping, so the hidden item is
       simply absent from the sequence grouping ever sees).
    3. NOT itself render anywhere in the log.
    """
    monkeypatch.setattr(
        MonitorView,
        "_get_config_visibility",
        staticmethod(
            lambda: {
                "create": "always",
                "modify": "always",
                "delete": "always",
                "rename": "always",
                "attrs": "always",
                "noise": "verbose",
            }
        ),
    )

    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        log = view.query_one("#monitor-log", RichLog)

        lines = [
            _fse("FSE_CREATE_FILE", "/data/cache/one.txt"),
            _fse("FSE_OPEN", "/data/cache/hidden.txt"),  # noise -- hidden
            _fse("FSE_CREATE_FILE", "/data/cache/two.txt"),
        ]
        _publish_monitor_batch(lines)
        await pilot.pause()

        # (1) Tallying is unconditional.
        assert view._total == 3
        assert view._create == 2
        assert view._noise == 1

        # (2) The two visible CREATE items still formed a run (breadcrumb
        # present) even though a hidden item sat between them in the batch.
        breadcrumb_lines = [line for line in log.lines if "▸" in line.text]
        assert len(breadcrumb_lines) == 1
        assert "/data/cache" in breadcrumb_lines[0].text

        # (3) The hidden item itself never rendered anywhere.
        assert not any("hidden.txt" in line.text for line in log.lines)


@pytest.mark.asyncio
async def test_grouped_rename_shows_old_arrow_new_filenames_when_same_directory() -> (
    None
):
    """A rename that shares its directory with the breadcrumb (the common
    case) shows just the filenames on both sides of the arrow.
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        log = view.query_one("#monitor-log", RichLog)

        lines = [
            _fse("FSE_CREATE_FILE", "/data/cache/a.txt"),
            _fse(
                "FSE_RENAME",
                "/data/cache/old.txt",
                new_path="/data/cache/new.txt",
            ),
        ]
        _publish_monitor_batch(lines)
        await pilot.pause()

        rename_lines = [line for line in log.lines if "old.txt -> new.txt" in line.text]
        assert len(rename_lines) == 1
        assert "/data/cache" not in rename_lines[0].text


# =============================================================================
# Full-path view (Part B, B3/B4) -- 'u' toggle
# =============================================================================


@pytest.mark.asyncio
async def test_toggle_view_mode_flips_full_path_view() -> None:
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        assert view._full_path_view is False

        view.action_toggle_view_mode()
        await pilot.pause()
        assert view._full_path_view is True

        view.action_toggle_view_mode()
        await pilot.pause()
        assert view._full_path_view is False


@pytest.mark.asyncio
async def test_full_path_view_wraps_long_paths_instead_of_truncating() -> None:
    """A full path wider than the log's content width wraps onto
    continuation lines rather than being truncated with an ellipsis.
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        log = view.query_one("#monitor-log", RichLog)
        view.action_toggle_view_mode()
        await pilot.pause()
        lines_before = len(log.lines)

        long_dir = "/data/data/com.example.app/cache/" + ("segment/" * 10)
        long_path = long_dir + "very_long_filename_tail_marker.tmp"
        _publish_monitor_batch([_fse("FSE_CREATE_FILE", long_path)])
        await pilot.pause()

        new_lines = log.lines[lines_before:]
        assert len(new_lines) > 1  # wrapped onto continuation lines
        combined = "".join(line.text for line in new_lines)
        assert "…" not in combined  # never truncated in full-path view
        assert "very_long_filename_tail_marker.tmp" in combined


@pytest.mark.asyncio
async def test_toggle_view_mode_does_not_reformat_already_written_rows() -> None:
    """Toggling 'u' is forward-only: rows already written before the toggle
    keep their original (grouped/truncated) formatting.
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        log = view.query_one("#monitor-log", RichLog)

        # Written in grouped mode: a breadcrumb + collapsed rows.
        lines = [
            _fse("FSE_CREATE_FILE", "/data/cache/one.txt"),
            _fse("FSE_CREATE_FILE", "/data/cache/two.txt"),
        ]
        _publish_monitor_batch(lines)
        await pilot.pause()

        breadcrumb_lines_before = [line.text for line in log.lines if "▸" in line.text]
        assert len(breadcrumb_lines_before) == 1

        view.action_toggle_view_mode()
        await pilot.pause()

        _publish_monitor_batch([_fse("FSE_DELETE", "/data/other/new_after_toggle.txt")])
        await pilot.pause()

        # The old breadcrumb is untouched -- still exactly one, same text.
        breadcrumb_lines_after = [line.text for line in log.lines if "▸" in line.text]
        assert breadcrumb_lines_after == breadcrumb_lines_before


@pytest.mark.asyncio
async def test_notify_monitor_stopped_for_playback_writes_notice_without_bumping_counters() -> (
    None
):
    """The Play-safety-net notice must reach the log but NOT be treated as a
    live monitor event — it's a system notice, not an monitor-reported change.
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)

        view.notify_monitor_stopped_for_playback()
        await pilot.pause()

        assert view._total == 0
        log = view.query_one("#monitor-log", RichLog)
        assert len(log.lines) >= 2  # startup hint + the new notice line


@pytest.mark.asyncio
async def test_notify_pid_mode_fallback_writes_notice_without_bumping_counters() -> (
    None
):
    """The PID-mode-unavailable notice must reach the log but NOT be treated
    as a live monitor event -- it's a system notice, not an monitor-reported
    change (mirrors notify_monitor_stopped_for_playback's test exactly).
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)

        view.notify_pid_mode_fallback("/data/data/com.example.app")
        await pilot.pause()

        assert view._total == 0
        log = view.query_one("#monitor-log", RichLog)
        assert len(log.lines) >= 2  # startup hint + the new notice line


@pytest.mark.asyncio
async def test_notify_pid_mode_fallback_wraps_instead_of_clipping() -> None:
    """Found during E2E testing: this notice was written unwrapped even
    though #monitor-log is wrap=False, so a long path could clip its tail
    in a narrow terminal -- inconsistent with the full-path view's "never
    cut off" goal. It must now wrap onto continuation lines instead.
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        log = view.query_one("#monitor-log", RichLog)
        lines_before = len(log.lines)

        long_path = "/data/data/com.example.app/" + ("segment/" * 10)
        view.notify_pid_mode_fallback(long_path)
        await pilot.pause()

        new_lines = log.lines[lines_before:]
        assert len(new_lines) > 1  # wrapped onto continuation lines
        combined = "".join(line.text for line in new_lines)
        assert "instead." in combined  # the trailing text isn't clipped off
        assert long_path.rstrip("/") in combined or "segment/" in combined


@pytest.mark.asyncio
async def test_offer_resume_shows_bar_and_clear_hides_it() -> None:
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        bar = view.query_one("#monitor-resume-bar")
        assert "-hidden" in bar.classes

        config = MonitorConfig(mode="path", target_path="/data/local/tmp/")
        view.offer_resume(config)
        await pilot.pause()

        assert "-hidden" not in bar.classes
        assert view._resume_config is config

        view.clear_resume_offer()
        await pilot.pause()

        assert "-hidden" in bar.classes
        assert view._resume_config is None


@pytest.mark.asyncio
async def test_monitor_started_event_clears_pending_resume_offer() -> None:
    """A fresh monitor start (Resume button, or plain 'o') must drop any
    stale Resume offer — it refers to an already-superseded config.
    """
    app = _MonitorHarness()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        view.offer_resume(MonitorConfig(mode="path", target_path="/data/"))
        await pilot.pause()
        assert view._resume_config is not None

        get_task_service().register(
            name="monitor",
            display_name="Monitor",
            instance=object(),
            stop_callback=lambda: None,
        )
        try:
            _publish_monitor_output(
                _fse("FSE_CREATE_FILE", "/data/a.txt")
            )  # not the trigger…
            await pilot.pause()

            EventBus.get().publish(
                Event(
                    type=EventType.TASK_STARTED,
                    data={"task_name": "monitor"},
                    source="monitor",
                )
            )
            await pilot.pause()

            assert view._resume_config is None
            bar = view.query_one("#monitor-resume-bar")
            assert "-hidden" in bar.classes
        finally:
            get_task_service().unregister("monitor")


@pytest.mark.asyncio
async def test_resume_button_press_delegates_to_app(monkeypatch) -> None:
    """Pressing "Resume monitoring" must hand the stashed config straight to
    App.resume_monitor_after_playback — MonitorView itself never resolves
    PIDs or re-forks monitor.
    """

    class _AppWithResume(App):
        def compose(self) -> ComposeResult:
            yield MonitorView(id="files-monitor")

        def __init__(self) -> None:
            super().__init__()
            self.resume_calls: list = []

        def resume_monitor_after_playback(self, config) -> None:
            self.resume_calls.append(config)

    app = _AppWithResume()
    async with app.run_test() as pilot:
        view = app.query_one(MonitorView)
        config = MonitorConfig(mode="path", target_path="/data/")
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
        assert monitor.glance_fragment() == "monitor ○ stopped"

        _publish_monitor_output(_fse("FSE_CREATE_FILE", "/data/new_file.txt"))
        await pilot.pause()
        assert monitor._total == 1
