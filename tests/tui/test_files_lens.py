"""Files lens (phase B): one table of live file activity with watch marks.

Covers the non-visual model (``monitor_view.FileActivity``: tally, collapse
per path, noise rules) and the lens itself (``files_panel.FilesPanel``):
watch pins, ``w``/``u``/``U``, noise toggle, filter, the inline add input,
Inspector content (incl. the pull diff), monitor notices and the REVIEW
scope. No device: monitor batches are built with the real
``build_monitor_item`` and published on the real EventBus; pulls go through
a class-level ``FileExtractionService.pull_file`` fake.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Button, Input

from sandroid.core.events import Event, EventBus, EventType
from sandroid.services import get_forensic_service, get_task_service
from sandroid.services.file_extraction_service import (
    ExtractionResult,
    FileExtractionService,
)
from sandroid.tui.controllers.monitor_controller import (
    MonitorConfig,
    build_monitor_item,
)
from sandroid.tui.widgets.files_panel import FilesPanel, render_diff
from sandroid.tui.widgets.lens_shell import ScopeChanged
from sandroid.tui.widgets.monitor_view import (
    FileActivity,
    app_relative,
    is_noise_path,
    smart_truncate,
)
from sandroid.tui.widgets.watchlist_view import RowState

PKG = "com.example.fit"
ROOT = f"/data/data/{PKG}"
PREFS = f"{ROOT}/shared_prefs/consent.xml"
DB = f"{ROOT}/databases/app.db"
CACHE = f"{ROOT}/cache/okhttp/journal"
AAID = f"{ROOT}/files/aaid.txt"
MISC = "/data/misc/keystore/x"
T0 = datetime(2026, 11, 17, 10, 40, 0)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    # The pre-pull on-device stat/sha256sum is an adb call: no device here.
    from sandroid.tui.widgets.watchlist_view import WatchlistView

    monkeypatch.setattr(WatchlistView, "_device_facts", staticmethod(lambda p: {}))
    svc = get_task_service()
    svc._tasks.pop("monitor", None)
    get_forensic_service()._spotlight_files.clear()
    EventBus.get().clear_history()
    yield tmp_path
    svc._tasks.pop("monitor", None)
    get_forensic_service()._spotlight_files.clear()
    EventBus.get().clear_history()


def _fse(event_type: str, path: str, new_path: str | None = None) -> str:
    rest = f"{path} -> {new_path}" if new_path else path
    return f'{event_type}\t123\t"fitness"\t{rest}'


def _items(*lines: str):
    return [build_monitor_item(line, (ROOT + "/",)) for line in lines]


def _publish(*lines: str, source: str = "monitor") -> None:
    EventBus.get().publish(
        Event(
            type=EventType.TASK_OUTPUT,
            data={"task_name": "Monitor", "batch": _items(*lines)},
            source=source,
        )
    )


class _Harness(App):
    def compose(self) -> ComposeResult:
        yield FilesPanel(id="files-panel")

    def __init__(self) -> None:
        super().__init__()
        self.resume_calls: list = []

    def resume_monitor_after_playback(self, config) -> None:
        self.resume_calls.append(config)


async def _wait_for(pilot, predicate, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await pilot.pause(0.02)
    assert predicate(), "condition was not met within timeout"


def _keys(panel: FilesPanel) -> list[str]:
    panel.refresh_rows()
    return [row.key for row in panel._rows]


def _fake_pull(content: dict[str, str]):
    def _pull(self, remote_path, local_path, compute_hash=False):
        if remote_path not in content:
            return ExtractionResult(
                source_path=remote_path,
                local_path=local_path,
                success=False,
                error="no such file on (fake) device",
            )
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        Path(local_path).write_text(content[remote_path], encoding="utf-8")
        return ExtractionResult(
            source_path=remote_path, local_path=local_path, success=True
        )

    return _pull


def _register_monitor(app_name: str = PKG) -> None:
    get_task_service().register(
        name="monitor",
        display_name="Monitor",
        instance=type("W", (), {"config": MonitorConfig(app_name=app_name)})(),
        stop_callback=lambda: None,
        app_name=app_name,
    )


# --------------------------------------------------------------------------
# model: FileActivity
# --------------------------------------------------------------------------


def test_events_collapse_per_path_with_ops_count_and_times() -> None:
    model = FileActivity()
    model.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
    model.ingest(
        _items(*[_fse("FSE_CONTENT_MODIFIED", PREFS)] * 3),
        now=T0 + timedelta(seconds=5),
    )
    assert set(model.paths) == {AAID, PREFS}
    prefs = model.paths[PREFS]
    assert prefs.count == 3
    assert prefs.ops == {"modify": 3}
    assert prefs.last == T0 + timedelta(seconds=5)
    assert prefs.processes == {"fitness": 3}
    assert prefs.rel == "shared_prefs/consent.xml"
    assert [letter for letter, _c in model.paths[AAID].op_letters()] == ["C"]


def test_rename_lands_on_destination_and_wal_folds_onto_database() -> None:
    model = FileActivity()
    model.ingest(
        _items(
            _fse("FSE_RENAME", PREFS + ".bak", PREFS),
            _fse("FSE_CONTENT_MODIFIED", DB + "-wal"),
            _fse("FSE_CREATE_FILE", DB + "-journal"),
        ),
        now=T0,
    )
    assert set(model.paths) == {PREFS, DB}
    assert model.paths[PREFS].events[-1].other == PREFS + ".bak"
    assert model.paths[DB].count == 2
    assert [e.via for e in model.paths[DB].events] == ["-wal", "-journal"]


def test_tally_counts_every_item_even_hidden_and_never() -> None:
    model = FileActivity({"noise": "verbose", "attrs": "never"})
    model.ingest(
        _items(
            _fse("FSE_OPEN", PREFS),
            _fse("FSE_STAT_CHANGED", AAID),
            _fse("FSE_CONTENT_MODIFIED", PREFS),
        ),
        now=T0,
    )
    assert model.total == 3
    assert model.counts["noise"] == 1
    assert model.counts["attrs"] == 1
    # "never" is not even collapsed; verbose-only rows are noise.
    assert AAID not in model.paths
    assert PREFS in model.paths


def test_noise_rules_and_show_all() -> None:
    """Only OS paths and open-only rows are hidden; never the app's data."""
    model = FileActivity({"noise": "verbose", "attrs": "never"})
    model.ingest(
        _items(
            _fse("FSE_CONTENT_MODIFIED", CACHE),
            _fse("FSE_OPEN", AAID),
            _fse("FSE_CONTENT_MODIFIED", PREFS),
            _fse("FSE_CONTENT_MODIFIED", MISC),
        ),
        now=T0,
    )
    assert {r.key for r in model.visible_rows()} == {CACHE, PREFS}
    assert model.hidden_count() == 2
    assert model.hide_reason(model.paths[MISC]) == "prefix"
    assert model.hide_reason(model.paths[AAID]) == "open-only"
    model.show_all = True
    assert {r.key for r in model.visible_rows()} == {CACHE, AAID, PREFS, MISC}
    assert model.hidden_count() == 0
    assert is_noise_path("/proc/1/stat")
    for app_data in (
        f"{ROOT}/files/x.tmp",
        f"{ROOT}/app_webview/Default/Cookies",
        f"{ROOT}/no_backup/id",
        f"{ROOT}/files/.hidden",
        "/data/local/tmp/payload.dex",
        DB,
    ):
        assert not is_noise_path(app_data), app_data


def test_tracked_paths_are_capped_oldest_first() -> None:
    model = FileActivity(max_paths=50)
    for i in range(60):
        model.ingest(
            _items(_fse("FSE_CREATE_FILE", f"{ROOT}/files/f{i}")),
            now=T0 + timedelta(seconds=i),
        )
    assert len(model.paths) == 50
    assert f"{ROOT}/files/f0" not in model.paths
    assert f"{ROOT}/files/f59" in model.paths


def test_path_helpers() -> None:
    assert app_relative("/data/user/0/x.y/databases/a.db") == "databases/a.db"
    assert app_relative("/system/etc/hosts") == "/system/etc/hosts"
    assert smart_truncate("files/a/b/c/d/report.json", 22) == "files/…/d/report.json"
    assert smart_truncate("databases/fittrack.db", 16) == "…/fittrack.db"
    assert smart_truncate("short.txt", 20) == "short.txt"


def test_render_diff_previews_long_diffs() -> None:
    from sandroid.tui.widgets.diff_view import DiffView

    long = [f"[green]+ line {i}[/green]" for i in range(DiffView.SOFT_LINE_THRESHOLD)]
    text = render_diff(long).plain
    assert "line 0" in text
    assert f"line {DiffView.PREVIEW_LINES}" not in text
    assert "z for the full diff" in text
    assert render_diff("[red]- a[/red]").plain == "- a"


# --------------------------------------------------------------------------
# lens: table
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_state_is_one_calm_line() -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        assert panel.has_class("-empty")
        empty = str(panel.query_one("#files-empty").render())
        assert empty == "Monitor off — press o to watch file activity"
        assert panel.caption() == ("LIVE", "")


@pytest.mark.asyncio
async def test_monitor_batches_fill_the_table_collapsed_per_path() -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        _publish(
            _fse("FSE_CREATE_FILE", AAID),
            _fse("FSE_CONTENT_MODIFIED", PREFS),
            _fse("FSE_CONTENT_MODIFIED", PREFS),
        )
        _publish(_fse("FSE_CREATE_FILE", f"{ROOT}/files/other"), source="fritap")
        await pilot.pause()
        assert set(_keys(panel)) == {AAID, PREFS}
        assert not panel.has_class("-empty")
        assert panel.activity.paths[PREFS].count == 2
        assert panel.table.row_count == 2
        assert panel.caption()[1].startswith("2 paths")


@pytest.mark.asyncio
async def test_watched_rows_are_pinned_on_top_with_a_star() -> None:
    get_forensic_service().add_spotlight_file(DB)  # watched, no events yet
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        panel.watchlist._watched_patterns.add(f"{ROOT}/files/datastore/*")
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", f"{ROOT}/files/datastore/p.pb")),
            now=T0 - timedelta(seconds=30),
        )
        keys = _keys(panel)
        # Pinned: the watched file, the pattern-matched file and the pattern
        # itself; then the unwatched activity.
        assert keys[-1] == AAID
        assert set(keys[:3]) == {
            DB,
            f"{ROOT}/files/datastore/p.pb",
            f"{ROOT}/files/datastore/*",
        }
        by_key = {row.key: row for row in panel._rows}
        # Its write made the pattern adopt the file (so auto-pull can pull it).
        assert by_key[f"{ROOT}/files/datastore/p.pb"].watched == (
            f"{ROOT}/files/datastore/p.pb"
        )
        assert panel.watchlist.watched_by(f"{ROOT}/files/datastore/q.pb") == (
            f"{ROOT}/files/datastore/*"
        )
        assert str(panel._mark_cell(by_key[DB])) == "★"
        assert str(panel._mark_cell(by_key[AAID])) == ""
        assert "3 watched" in panel.caption()[1]


@pytest.mark.asyncio
async def test_w_watches_and_unwatches_the_highlighted_row() -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(_items(_fse("FSE_CONTENT_MODIFIED", PREFS)), now=T0)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await pilot.pause()
        panel.table.move_cursor(row=_keys(panel).index(AAID))
        await pilot.press("w")
        await pilot.pause()
        assert AAID in get_forensic_service().get_spotlight_files()
        assert _keys(panel)[0] == AAID  # pinned now
        assert panel._cursor_key() == AAID  # cursor followed the row
        await pilot.press("w")
        await pilot.pause()
        assert AAID not in get_forensic_service().get_spotlight_files()


@pytest.mark.asyncio
async def test_w_on_a_wal_row_watches_the_database() -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(_items(_fse("FSE_CONTENT_MODIFIED", DB + "-wal")), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await pilot.press("w")
        await pilot.pause()
        assert get_forensic_service().get_spotlight_files() == [DB]


@pytest.mark.asyncio
async def test_u_pulls_the_row_and_U_pulls_all(monkeypatch) -> None:
    content = {PREFS: "<map/>\n", DB: "v1\n"}
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull(content))
    get_forensic_service().add_spotlight_file(PREFS)
    get_forensic_service().add_spotlight_file(DB)
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        panel.refresh_rows()
        panel.table.focus()
        panel.table.move_cursor(row=_keys(panel).index(PREFS))
        rows = panel.watchlist.rows
        await pilot.press("u")
        await _wait_for(pilot, lambda: rows[PREFS].state is RowState.BASELINE_ONLY)
        assert rows[DB].state is RowState.NEVER_PULLED
        assert rows[PREFS].size == len("<map/>\n")
        assert rows[PREFS].sha256
        assert rows[PREFS].pulled_at
        await pilot.press("U")
        await _wait_for(pilot, lambda: rows[DB].state is RowState.BASELINE_ONLY)
        await _wait_for(pilot, lambda: rows[PREFS].state is RowState.UNCHANGED)


@pytest.mark.asyncio
async def test_u_on_an_unwatched_row_watches_then_pulls(monkeypatch) -> None:
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull({AAID: "x"}))
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await pilot.press("u")
        rows = panel.watchlist.rows
        await _wait_for(
            pilot, lambda: AAID in rows and rows[AAID].state is RowState.BASELINE_ONLY
        )


@pytest.mark.asyncio
async def test_N_toggles_noise_and_the_caption_counts_it() -> None:
    """``N`` = "show hidden noise", the same key as in the Network lens."""
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(
            _items(
                _fse("FSE_CONTENT_MODIFIED", MISC),
                _fse("FSE_CONTENT_MODIFIED", PREFS),
            ),
            now=T0,
        )
        assert _keys(panel) == [PREFS]
        assert "1 hidden: prefix 1" in panel.caption()[1]
        panel.table.focus()
        await pilot.press("v")  # v is only "review" (Runs lens) now
        await pilot.pause()
        assert _keys(panel) == [PREFS]
        await pilot.press("N")
        await pilot.pause()
        assert set(_keys(panel)) == {PREFS, MISC}
        assert "hidden" not in panel.caption()[1]
        await pilot.press("N")
        await pilot.pause()
        assert _keys(panel) == [PREFS]


@pytest.mark.asyncio
async def test_slash_filters_and_escape_clears() -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(
            _items(
                _fse("FSE_CONTENT_MODIFIED", PREFS),
                _fse("FSE_CREATE_FILE", AAID),
            ),
            now=T0,
        )
        panel.refresh_rows()
        panel.table.focus()
        await pilot.press("slash")
        await pilot.pause()
        field = panel.query_one("#files-input", Input)
        assert app.focused is field
        await pilot.press(*"prefs")
        await pilot.pause()
        assert [r.key for r in panel._rows] == [PREFS]
        assert panel.caption()[1].startswith("/prefs")
        await pilot.press("enter")  # keep the filter
        await pilot.pause()
        assert app.focused is panel.table
        assert [r.key for r in panel._rows] == [PREFS]
        await pilot.press("slash")
        await pilot.press("escape")  # clear it
        await pilot.pause()
        assert app.focused is panel.table
        assert not field.has_class("-shown")
        assert set(_keys(panel)) == {PREFS, AAID}


@pytest.mark.asyncio
async def test_n_adds_an_arbitrary_path_and_keeps_failures_in_the_input() -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        panel.focus()
        await pilot.press("n")
        await pilot.pause()
        field = panel.query_one("#files-input", Input)
        assert app.focused is field
        field.value = DB
        await pilot.press("enter")
        await pilot.pause()
        assert DB in get_forensic_service().get_spotlight_files()
        assert _keys(panel) == [DB]
        assert not field.has_class("-shown")
        # The same path again is rejected: text and focus stay.
        panel.open_input("add")
        field.value = DB
        await pilot.press("enter")
        await pilot.pause()
        assert app.focused is field
        assert field.value == DB
        await pilot.press("escape")
        await pilot.pause()
        assert app.focused is panel.table
        assert field.value == ""


@pytest.mark.asyncio
async def test_n_with_a_pattern_pins_the_pattern_and_persists_it() -> None:
    class _Adb:
        @staticmethod
        def send_adb_command(_cmd):
            return "", ""  # matches nothing yet

    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        panel.watchlist._adb = lambda: _Adb
        assert panel.watchlist.add_path(f"{ROOT}/databases/*")
        await pilot.pause()
        assert _keys(panel) == [f"{ROOT}/databases/*"]
        from sandroid.core import watchlist_store

        assert watchlist_store.load_patterns() == [f"{ROOT}/databases/*"]
        panel.table.focus()
        await pilot.press("w")  # unwatch the pattern row
        await pilot.pause()
        assert _keys(panel) == []
        assert watchlist_store.load_patterns() == []


# --------------------------------------------------------------------------
# lens: inspector
# --------------------------------------------------------------------------


def _tab(content, name):
    return dict(content.tabs)[name]


def _plain(sections) -> str:
    from io import StringIO

    from rich.console import Console

    buf = StringIO()
    console = Console(file=buf, width=120, color_system=None)
    for heading, body in sections:
        if heading:
            console.print(heading)
        console.print(body)
    return buf.getvalue()


@pytest.mark.asyncio
async def test_inspector_summary_events_and_pull_diff(monkeypatch) -> None:
    content = {PREFS: '<map><boolean name="a" value="true" /></map>'}
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull(content))
    get_forensic_service().add_spotlight_file(PREFS)
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        panel.ingest(
            _items(
                _fse("FSE_CONTENT_MODIFIED", PREFS),
                _fse("FSE_RENAME", PREFS + ".bak", PREFS),
            ),
            now=T0,
        )
        panel.refresh_rows()
        inspected = panel.inspect_selected()
        assert inspected.key == ("files", "live", PREFS)
        assert inspected.title == "consent.xml"
        assert inspected.subtitle == PREFS
        assert [name for name, _s in inspected.tabs] == [
            "Summary",
            "Versions",
            "Content",
            "Events",
        ]
        summary = _plain(_tab(inspected, "Summary"))
        assert "★ watched" in summary
        assert "M 1×" in summary
        assert "R 1×" in summary
        assert "fitness" in summary
        # The monitor saw writes to the ★ file: an auto-pull is pending.
        assert "settling" in summary
        events = _plain(_tab(inspected, "Events"))
        assert "RENAME" in events
        assert "from shared_prefs/consent.xml.bak" in events
        versions = _plain(_tab(inspected, "Versions"))
        assert "settling" in versions
        assert "Not pulled yet" in versions

        rows = panel.watchlist.rows
        panel.watchlist.pull([PREFS])
        await _wait_for(pilot, lambda: rows[PREFS].state is RowState.BASELINE_ONLY)
        content[PREFS] = '<map><boolean name="a" value="false" /></map>'
        panel.watchlist.pull([PREFS])
        await _wait_for(pilot, lambda: rows[PREFS].state is RowState.CHANGED)
        inspected = panel.inspect_selected()
        diff = _plain(_tab(inspected, "Versions"))
        assert "true → false" in diff
        assert "Diff  v2" in diff
        summary = _plain(_tab(inspected, "Summary"))
        assert "changed since the pull before" in summary
        assert "sha256" in summary


@pytest.mark.asyncio
async def test_inspector_for_an_unwatched_row_says_how_to_diff() -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        await pilot.pause()
        inspected = panel.inspect_selected()
        assert "not watched" in _plain(_tab(inspected, "Summary"))
        assert "to diff this file" in _plain(_tab(inspected, "Versions"))


# --------------------------------------------------------------------------
# lens: monitor notices + resume offer
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_backend_and_playback_notices_and_their_lifetimes() -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        panel.notify_backend_fallback("kprobe unavailable — using fsmon")
        assert "kprobe unavailable" in panel.notice
        assert panel.query_one("#files-notice").has_class("-shown")
        # Notices are not file events.
        assert panel.activity.total == 0
        # The backend notice goes when the monitor stops.
        panel._on_monitor_lifecycle(EventType.TASK_STOPPED)
        assert panel.notice == ""
        panel.notify_pid_mode_fallback("/data/data/x")
        assert "PID mode unavailable" in panel.notice
        panel.notify_monitor_stopped_for_playback()
        assert "Play" in panel.notice
        panel._on_monitor_lifecycle(EventType.TASK_STARTED)
        assert panel.notice == ""


@pytest.mark.asyncio
async def test_resume_offer_button_delegates_and_start_clears_it() -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        config = MonitorConfig(mode="path", target_path="/data/")
        panel.offer_resume(config)
        await pilot.pause()
        assert panel.resume_offered
        assert "/data/" in panel.notice
        await pilot.click(panel.query_one("#files-resume-btn", Button))
        await pilot.pause()
        assert app.resume_calls == [config]
        EventBus.get().publish(
            Event(
                type=EventType.TASK_STARTED,
                data={"task_name": "monitor"},
                source="monitor",
            )
        )
        await _wait_for(pilot, lambda: not panel.resume_offered)
        assert not panel.query_one("#files-resume-btn").has_class("-shown")


@pytest.mark.asyncio
async def test_running_monitor_with_no_events_says_so() -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        _register_monitor()
        await pilot.pause()
        panel.refresh_rows()
        empty = str(panel.query_one("#files-empty").render())
        assert empty.startswith("Watching for file activity in com.example.fit")


# --------------------------------------------------------------------------
# lens: REVIEW scope
# --------------------------------------------------------------------------


def _run_dir(base: Path) -> Path:
    run_dir = base / "elsewhere" / "20261117_104210_ab12cd"
    run_dir.mkdir(parents=True)
    record = {
        "schema_version": 2,
        "run_id": run_dir.name,
        "label": "login",
        "recorded_at": "2026-11-17T10:40:02",
        "completed_at": "2026-11-17T10:42:10",
        "device_name": "emu",
        "recording_path": "",
        "duration": 12,
        "changed_files": [{PREFS: ["[red]- a=true[/red]", "[green]+ a=false[/green]"]}],
        "new_files": [AAID],
        "deleted_files": [CACHE],
    }
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    return run_dir


@pytest.mark.asyncio
async def test_review_scope_shows_the_runs_files_and_live_comes_back(
    tmp_path,
) -> None:
    run_dir = _run_dir(tmp_path)
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", f"{ROOT}/files/live")), now=T0)
        panel.post_message(ScopeChanged(str(run_dir), "Run #3"))
        await _wait_for(pilot, lambda: panel._review_record is not None)
        assert [r.key for r in panel._rows] == [PREFS, AAID, CACHE]
        assert [r.review_kind for r in panel._rows] == ["changed", "new", "deleted"]
        assert panel.caption() == ("Run #3", "3 files")
        assert panel.check_action("pull", ()) is False
        inspected = panel.inspect_selected()
        assert inspected.key == ("files", str(run_dir), PREFS)
        assert [name for name, _s in inspected.tabs] == ["Summary", "Diff"]
        diff = _plain(_tab(inspected, "Diff"))
        assert "- a=true" in diff
        assert "+ a=false" in diff
        assert "login" not in _plain(_tab(inspected, "Summary"))  # label wins
        panel.table.move_cursor(row=1)
        assert "New in this run" in _plain(_tab(panel.inspect_selected(), "Diff"))

        panel.post_message(ScopeChanged(None))
        await pilot.pause()
        assert [r.key for r in panel._rows] == [f"{ROOT}/files/live"]
        assert panel.caption()[0] == "LIVE"


@pytest.mark.asyncio
async def test_review_scope_with_a_missing_run_says_so(tmp_path) -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        panel.post_message(ScopeChanged(str(tmp_path / "nope")))
        await _wait_for(pilot, lambda: panel._review_error is not None)
        assert panel.has_class("-empty")
        assert "Could not load this run" in str(
            panel.query_one("#files-empty").render()
        )


# --------------------------------------------------------------------------
# full app
# --------------------------------------------------------------------------


async def test_files_lens_in_the_app_enter_opens_and_live_updates_inspector() -> None:
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(160, 45)) as pilot:
        for _ in range(8):
            await pilot.pause(0.05)
        if type(app.screen).__name__ != "MainScreen":
            await pilot.press("enter")
            await pilot.pause(0.2)
        ms = app.screen
        await pilot.press("3")
        await pilot.pause(0.1)
        panel = ms.lens_widget("files")
        assert isinstance(panel, FilesPanel)
        assert ms.query_one("#lens-host").border_title == "Files · LIVE"
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", PREFS)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert ms.inspector_is_open
        key = ms.inspector_content.key
        assert key[:2] == ("files", "live")
        path = key[2]
        other = PREFS if path == AAID else AAID
        # A batch on the inspected row refreshes it; one elsewhere does not.
        panel.ingest(_items(_fse("FSE_CONTENT_MODIFIED", path)), now=T0)
        assert "M 1×" in _plain(_tab(ms.inspector_content, "Summary"))
        before = ms.inspector_content
        panel.ingest(_items(_fse("FSE_CONTENT_MODIFIED", other)), now=T0)
        assert ms.inspector_content is before
        # Moving the cursor follows with the Inspector.
        await pilot.press("down")
        await pilot.pause(0.1)
        assert ms.inspector_content.key[2] != path
        await pilot.press("escape")
        await pilot.pause(0.1)
        assert not ms.inspector_is_open
        assert "paths" in ms.query_one("#lens-host").border_subtitle


# --------------------------------------------------------------------------
# fix round 3 (live test of the Files lens)
# --------------------------------------------------------------------------

USER0 = f"/data/user/0/{PKG}"


def test_user0_and_data_data_events_are_one_row() -> None:
    """H3: /data/user/0/<pkg> is /data/data/<pkg>; trailing slashes too."""
    model = FileActivity()
    model.ingest(
        _items(
            _fse("FSE_CONTENT_MODIFIED", f"{USER0}/shared_prefs/consent.xml"),
            _fse("FSE_CONTENT_MODIFIED", PREFS),
            _fse("FSE_CREATE_DIR", f"{ROOT}/databases/"),
            _fse("FSE_CREATE_DIR", f"{USER0}/databases"),
        ),
        now=T0,
    )
    assert set(model.paths) == {PREFS, f"{ROOT}/databases"}
    assert model.paths[PREFS].count == 2


def test_deleting_a_directory_marks_its_known_files_deleted() -> None:
    """H2b: ``rm -r`` unlinks children by relative name (not matched by the
    path filter); the directory's D takes its known files with it.
    """
    model = FileActivity()
    bulk = f"{ROOT}/files/bulk"
    model.ingest(
        _items(*[_fse("FSE_CREATE_FILE", f"{bulk}/f_{i}") for i in range(3)]),
        now=T0,
    )
    touched = model.ingest(_items(_fse("FSE_DELETE", bulk)), now=T0)
    assert {f"{bulk}/f_{i}" for i in range(3)} <= touched
    for i in range(3):
        row = model.paths[f"{bulk}/f_{i}"]
        assert row.deleted
        assert [letter for letter, _c in row.op_letters()] == ["C", "D"]
        assert row.events[-1].source == "parent"
    assert model.paths[bulk].is_dir


def test_rename_marks_the_source_row_and_attr_basenames_are_dropped() -> None:
    """M8: the old name says where the file went; basename-only attrs rows
    (unresolved dentry names) never become orphan rows.
    """
    model = FileActivity()
    old, new = f"{ROOT}/files/b.txt", f"{ROOT}/files/b_renamed.txt"
    model.ingest(_items(_fse("FSE_CREATE_FILE", old)), now=T0)
    model.ingest(_items(_fse("FSE_RENAME", old, new)), now=T0)
    item = build_monitor_item(_fse("FSE_STAT_CHANGED", "wikipedia.db"))
    model.ingest([item], now=T0)
    assert model.paths[old].moved_to == new
    assert model.paths[old].events[-1].label == "RENAMED"
    assert "wikipedia.db" not in model.paths
    # Re-creating the old name clears the marker.
    model.ingest(_items(_fse("FSE_CREATE_FILE", old)), now=T0)
    assert model.paths[old].moved_to is None


def test_open_noise_does_not_redate_a_row() -> None:
    """M1: an OPEN (e.g. Sandroid's own pull) on a file with real activity
    keeps its last-change time (U used to re-sort 100+ rows to the top).
    """
    model = FileActivity()
    model.ingest(_items(_fse("FSE_CONTENT_MODIFIED", PREFS)), now=T0)
    model.ingest(_items(_fse("FSE_OPEN", PREFS)), now=T0 + timedelta(minutes=5))
    assert model.paths[PREFS].last == T0


def test_scan_and_stat_findings_are_marked() -> None:
    from sandroid.tui.controllers.monitor_controller import scan_item

    model = FileActivity()
    model.ingest([scan_item("FSE_CONTENT_MODIFIED", DB + "-wal", "stat")], now=T0)
    event = model.paths[DB].events[-1]
    assert (event.via, event.source) == ("-wal", "stat")
    # A stop-rescan D for a file already known deleted is not repeated.
    model.ingest(_items(_fse("FSE_DELETE", AAID)), now=T0)
    model.ingest([scan_item("FSE_DELETE", AAID, "scan")], now=T0)
    assert model.paths[AAID].count == 1


@pytest.mark.asyncio
async def test_short_paths_name_the_package_in_review_and_for_other_apps(
    tmp_path,
) -> None:
    """Tester 4 M9: a run lists files of several apps; ``databases/bugle_db``
    must not read as the reviewed app's. REVIEW rows always name their
    package; live rows only when it is not the monitored app.
    """
    import json as _json

    bugle = "/data/data/com.google.android.apps.messaging/databases/bugle_db"
    run_dir = tmp_path / "runs" / "20261117_190000_aa11bb"
    run_dir.mkdir(parents=True)
    record = {
        "schema_version": 2,
        "run_id": run_dir.name,
        "label": "msg",
        "recorded_at": "2026-11-17T19:00:00",
        "completed_at": "2026-11-17T19:01:00",
        "device_name": "emu",
        "recording_path": "",
        "duration": 5,
        "changed_files": [{bugle: ["x"]}, {DB: ["y"]}],
        "new_files": ["/data/system/job/jobs_1000.xml"],
        "deleted_files": [],
    }
    (run_dir / "run.json").write_text(_json.dumps(record), encoding="utf-8")
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        _register_monitor()
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", bugle), _fse("FSE_CREATE_FILE", AAID)),
            now=T0,
        )
        _keys(panel)
        live = {r.key: panel._path_cell(r).plain for r in panel._rows}
        assert live[bugle] == "com.google.android.apps.messaging: databases/bugle_db"
        assert live[AAID] == "files/aaid.txt"  # the monitored app's own
        panel.post_message(ScopeChanged(str(run_dir), "Run #4"))
        await _wait_for(pilot, lambda: panel._review_record is not None)
        cells = {r.key: panel._path_cell(r).plain for r in panel._rows}
        assert cells[bugle] == "com.google.android.apps.messaging: databases/bugle_db"
        assert cells[DB] == f"{PKG}: databases/app.db"
        assert (
            cells["/data/system/job/jobs_1000.xml"] == "/data/system/job/jobs_1000.xml"
        )


def test_a_running_monitor_is_not_counted_as_a_hook() -> None:
    """L7: the monitor task carries the app's name but is not a Frida hook."""
    from sandroid.tui.widgets.spotlight_panel import SpotlightPanel

    _register_monitor()
    assert SpotlightPanel()._hooks_for_app(PKG) == []


def test_device_encrypted_and_external_app_paths_stay_distinguishable() -> None:
    assert app_relative(f"/data/user_de/0/{PKG}/files/x") == "@de/files/x"
    assert app_relative(f"/sdcard/Android/data/{PKG}/files/x") == "@ext/files/x"
    assert app_relative(f"{ROOT}/files/x") == "files/x"


def test_render_diff_keeps_xml_key_names_and_markup_lines() -> None:
    """L2: ``string[@name="k"]`` was parsed as a Rich tag and vanished."""
    xml = '\t[UPDATED] /map/string[@name="cookie"] text: "a" → "b"'
    assert '[@name="cookie"]' in render_diff(xml).plain
    db = "\t\\[[success]INSERT[/success]] Table \\[t] row \\[[success]1[/success]]"
    assert render_diff(db).plain.strip() == "[INSERT] Table [t] row [1]"


@pytest.mark.asyncio
async def test_pattern_does_not_star_deleted_paths_or_directories() -> None:
    """L6 (and L8: the caption counts files and patterns apart)."""
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        panel.watchlist._watched_patterns.add(f"{ROOT}/files/*")
        panel.ingest(
            _items(
                _fse("FSE_CREATE_FILE", f"{ROOT}/files/live.txt"),
                _fse("FSE_CREATE_FILE", f"{ROOT}/files/gone.txt"),
                _fse("FSE_DELETE", f"{ROOT}/files/gone.txt"),
                _fse("FSE_CREATE_DIR", f"{ROOT}/files/sub"),
            ),
            now=T0,
        )
        _keys(panel)
        by_key = {row.key: row for row in panel._rows}
        # The created file was adopted by the pattern (its own ★ row now);
        # the one deleted again in the same batch was not.
        assert by_key[f"{ROOT}/files/live.txt"].watched == f"{ROOT}/files/live.txt"
        assert by_key[f"{ROOT}/files/gone.txt"].watched is None
        assert by_key[f"{ROOT}/files/sub"].watched is None
        assert panel.caption()[1].startswith("3 paths + 1 pattern")


@pytest.mark.asyncio
async def test_watch_applies_to_writes_through_the_user0_alias() -> None:
    """H3: a ★ on /data/data/<pkg>/x also gets the app's /data/user/0 writes."""
    get_forensic_service().add_spotlight_file(PREFS)
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", f"{USER0}/shared_prefs/consent.xml")),
            now=T0,
        )
        assert _keys(panel) == [PREFS]
        assert panel._rows[0].watched == PREFS
        assert panel._rows[0].activity.count == 1
        # Watching via the alias is the same (canonical) watch.
        assert not panel.watchlist.add_path(f"{USER0}/shared_prefs/consent.xml")


@pytest.mark.asyncio
async def test_renamed_and_deleted_rows_say_so(monkeypatch) -> None:
    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        old, new = f"{ROOT}/files/b.txt", f"{ROOT}/files/c.txt"
        panel.ingest(_items(_fse("FSE_CREATE_FILE", old)), now=T0)
        panel.ingest(_items(_fse("FSE_RENAME", old, new)), now=T0)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.ingest(_items(_fse("FSE_DELETE", AAID)), now=T0)
        await pilot.pause()
        _keys(panel)
        rows = {row.key: row for row in panel._rows}
        assert panel._path_cell(rows[old]).plain.endswith("b.txt → c.txt")
        panel._path_width = 10  # narrow (beside the Inspector at 80 columns)
        assert panel._path_cell(rows[old]).plain.endswith(" →")
        assert "→" not in panel._path_cell(rows[AAID]).plain
        panel._path_width = 60
        summary = _plain(_tab(panel._inspector_for(rows[old]), "Summary"))
        assert "renamed → files/c.txt" in summary
        events = _plain(_tab(panel._inspector_for(rows[old]), "Events"))
        assert "RENAMED" in events
        assert "to files/c.txt" in events
        assert "deleted" in _plain(_tab(panel._inspector_for(rows[AAID]), "Summary"))
        notes: list[str] = []
        monkeypatch.setattr(app, "notify", lambda msg, **kw: notes.append(msg))
        panel.table.focus()
        panel.table.move_cursor(row=_keys(panel).index(AAID))
        await pilot.press("u")
        assert notes == ["Nothing to pull: deleted on the device."]


@pytest.mark.asyncio
async def test_n_prefill_is_extended_not_replaced_and_bad_paths_are_rejected(
    monkeypatch,
) -> None:
    """M5: the prefill isn't selected (typing appends); relative paths and
    shell metacharacters are refused with a message, the input stays open.
    """
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        _register_monitor()
        await pilot.pause()
        panel.focus()
        await pilot.press("n")
        await pilot.pause()
        field = panel.query_one("#files-input", Input)
        assert field.value == f"{ROOT}/"
        await pilot.press(*"files")
        assert field.value == f"{ROOT}/files"
        notes: list[str] = []
        monkeypatch.setattr(app, "notify", lambda msg, **kw: notes.append(msg))
        for bad in ("shared_prefs/x.xml", f"{ROOT}/x;touch y", ROOT + "/$" + "(id)"):
            field.value = bad
            await pilot.press("enter")
            await pilot.pause()
            assert app.focused is field
        assert "absolute" in notes[0]
        assert all("metacharacters" in n for n in notes[1:])
        assert get_forensic_service().get_spotlight_files() == []


@pytest.mark.asyncio
async def test_home_end_move_the_cursor_and_O_sorts_by_name() -> None:
    """L5: Home/End jump rows; ``O`` cycles recent / name (natural) / count."""
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        for i, n in enumerate((10, 2, 1)):
            panel.ingest(
                _items(_fse("FSE_CREATE_FILE", f"{ROOT}/files/f_{n}")),
                now=T0 + timedelta(seconds=i),
            )
        panel.refresh_rows()
        panel.table.focus()
        await pilot.pause()
        await pilot.press("end")
        assert panel.table.cursor_row == 2
        await pilot.press("home")
        assert panel.table.cursor_row == 0
        await pilot.press("O")
        await pilot.pause()
        assert [k.rsplit("/", 1)[1] for k in _keys(panel)] == ["f_1", "f_2", "f_10"]
        assert "by name" in panel.caption()[1]


@pytest.mark.asyncio
async def test_history_tab_keeps_every_pull_and_restart_restores_the_diff(
    monkeypatch,
) -> None:
    """M3/M4: pulls are versions with their diffs on disk; a new app (a
    restart) loads the watchlist and the last diff again.
    """
    content = {PREFS: '<map><string name="k">one</string></map>'}
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull(content))
    get_forensic_service().add_spotlight_file(PREFS)
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        rows = panel.watchlist.rows
        panel.watchlist.pull([PREFS])
        await _wait_for(pilot, lambda: rows[PREFS].state is RowState.BASELINE_ONLY)
        content[PREFS] = '<map><string name="k">two</string></map>'
        panel.watchlist.pull([PREFS])
        await _wait_for(pilot, lambda: rows[PREFS].state is RowState.CHANGED)
        panel.refresh_rows()
        history = _plain(_tab(panel.inspect_selected(), "Versions"))
        assert "▸ v2" in history
        assert "v1" in history
        assert "one → two" in history  # the k preference, old → new
        assert "first pull" in history

    get_forensic_service()._spotlight_files.clear()  # a new process
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        # Only the ★ membership persists; the versions of this session are
        # still in its results folder (and listed by the Versions tab).
        assert PREFS in panel.watchlist.rows
        info = panel.watchlist.rows[PREFS]
        assert info.state is RowState.BASELINE_ONLY
        panel.refresh_rows()
        history = _plain(_tab(panel.inspect_selected(), "Versions"))
        assert "▸ v2" in history
        assert "v1" in history
        assert "two" in history


async def test_inspector_keys_work_while_the_inspector_has_focus() -> None:
    """M6: with focus in the Inspector (needed to scroll it), the lens keys it
    advertises -- w watch, u pull, z zoom -- still act on the lens's row.
    """
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(160, 45)) as pilot:
        for _ in range(8):
            await pilot.pause(0.05)
        if type(app.screen).__name__ != "MainScreen":
            await pilot.press("enter")
            await pilot.pause(0.2)
        ms = app.screen
        await pilot.press("3")
        await pilot.pause(0.1)
        panel = ms.lens_widget("files")
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert ms.inspector_is_open
        ms.query_one("#inspector-scroll").focus()
        await pilot.pause()
        assert panel.table is not app.focused
        await pilot.press("w")
        await pilot.pause(0.1)
        assert AAID in get_forensic_service().get_spotlight_files()
        # The Inspector's own keys stay its own: ] still switches tabs.
        await pilot.press("right_square_bracket")
        await pilot.pause()
        assert ms.query_one("#inspector").tab_index == 1


# --------------------------------------------------------------------------
# marks + since-mark view
# --------------------------------------------------------------------------


def _row(panel: FilesPanel, key: str):
    return next(r for r in panel._rows if r.key == key)


@pytest.mark.asyncio
async def test_marks_show_only_activity_since_and_step_through_segments() -> None:
    """A mark splits the session: counts/ops per segment, rows without
    activity in it hidden, ★ rows pinned but dim; ``A`` shows everything,
    ``<``/``>`` step through the segments; the caption names the segment.
    """
    get_forensic_service().add_spotlight_file(DB)  # ★, never touched
    new = f"{ROOT}/files/token.json"
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        panel.ingest(_items(_fse("FSE_CONTENT_MODIFIED", PREFS)), now=T0)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.drop_mark("tap login", T0 + timedelta(seconds=10))
        assert panel.segment == 1
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", PREFS)),
            now=T0 + timedelta(seconds=20),
        )
        panel.ingest(
            _items(_fse("FSE_CREATE_FILE", new)), now=T0 + timedelta(seconds=25)
        )
        assert _keys(panel) == [DB, new, PREFS]
        assert _row(panel, PREFS).stats.count == 1  # reset per segment
        assert _row(panel, DB).dim
        assert panel._path_cell(_row(panel, DB)).spans[-1].style == "#5b6479"
        assert panel.caption()[0] == "since mark 1 'tap login' · 10:40:10"

        panel.table.focus()
        await pilot.press("A")  # everything again
        await pilot.pause()
        assert set(_keys(panel)) == {DB, new, PREFS, AAID}
        assert _row(panel, PREFS).stats.count == 2
        assert panel.caption()[0] == "LIVE"
        await pilot.press("A")
        await pilot.pause()
        assert panel.segment == 1

        panel.drop_mark("", T0 + timedelta(seconds=30))  # unnamed
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", AAID)), now=T0 + timedelta(seconds=35)
        )
        assert _keys(panel) == [DB, AAID]
        assert panel.caption()[0] == "since mark 2 · 10:40:30"
        await pilot.press("less_than_sign")
        await pilot.pause()
        assert _keys(panel) == [DB, new, PREFS]
        assert panel.caption()[0] == ("mark 1 'tap login' → mark 2 · 10:40:10–10:40:30")
        await pilot.press("less_than_sign")
        await pilot.pause()
        assert set(_keys(panel)) == {DB, PREFS, AAID}
        assert _row(panel, AAID).stats.ops == {"create": 1}
        assert panel.caption()[0] == "before mark 1 'tap login' · until 10:40:10"
        await pilot.press("less_than_sign")  # stays at the first segment
        await pilot.press("greater_than_sign", "greater_than_sign")
        await pilot.pause()
        assert panel.segment == 2

        # The Inspector's Events tab has the marks as separator lines.
        events = _plain(_tab(panel._inspector_for(_row(panel, AAID)), "Events"))
        lines = [ln.strip() for ln in events.splitlines() if ln.strip()]
        assert lines[0].startswith("10:40:35")
        assert lines[1] == "── mark 2 · 10:40:30 ──"
        assert lines[2] == "── mark 1 'tap login' · 10:40:10 ──"
        assert lines[3].startswith("10:40:00")
        # A file first touched after a mark ends with that mark.
        panel._segment = None
        panel.refresh_rows()
        events = _plain(_tab(panel._inspector_for(_row(panel, new)), "Events"))
        lines = [ln.strip() for ln in events.splitlines() if ln.strip()]
        assert lines[0] == "── mark 2 · 10:40:30 ──"
        assert lines[1].startswith("10:40:25")
        assert lines[2] == "── mark 1 'tap login' · 10:40:10 ──"
        assert len(lines) == 3


@pytest.mark.asyncio
async def test_B_asks_for_a_name_enter_keeps_it_unnamed_and_esc_cancels() -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await pilot.press("B")
        await pilot.pause()
        field = panel.query_one("#files-input", Input)
        assert app.focused is field
        assert "name mark 1" in field.placeholder
        await pilot.press("enter")  # empty name = unnamed
        await pilot.pause()
        assert [m.label() for m in panel.marks] == ["mark 1"]
        await pilot.press("B", *"login", "enter")
        await pilot.pause()
        assert [m.label() for m in panel.marks] == ["mark 1", "mark 2 'login'"]
        await pilot.press("B")
        await pilot.press("escape")  # no mark
        await pilot.pause()
        assert len(panel.marks) == 2
        assert len(panel.activity.mark_times) == 2
        assert not field.has_class("-shown")


def test_the_new_lens_keys_shadow_no_app_wide_key() -> None:
    """``B``/``A``/``<``/``>``/``R`` are free app-wide (``m`` is Dexray, ``a``
    Analyze -- the lens no longer shadows ``a``).
    """
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.screens.main_screen import MainScreen

    app_keys = {b.key for b in SandroidTUI.BINDINGS} | {
        b.key for b in MainScreen.BINDINGS
    }
    lens_keys = {b.key for b in FilesPanel.BINDINGS}
    for key in ("B", "A", "less_than_sign", "greater_than_sign", "R"):
        assert key in lens_keys
        assert key not in app_keys
    assert "a" not in lens_keys  # auto-pull poll mode removed; Analyze works


async def test_marks_are_a_shell_concept_logged_and_sent_to_every_lens() -> None:
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(160, 45)) as pilot:
        for _ in range(8):
            await pilot.pause(0.05)
        if type(app.screen).__name__ != "MainScreen":
            await pilot.press("enter")
            await pilot.pause(0.2)
        ms = app.screen
        await pilot.press("3")
        await pilot.pause(0.1)
        panel = ms.lens_widget("files")
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await pilot.press("B", *"tap login", "enter")
        await pilot.pause(0.1)
        assert [m.label() for m in ms.marks] == ["mark 1 'tap login'"]
        assert "mark 1 'tap login'" in ms.query_one("#log-ticker").last_line
        assert panel.segment == 1
        assert ms.query_one("#lens-host").border_title.startswith(
            "Files · since mark 1 'tap login' · "
        )
        mark = ms.add_mark("from elsewhere")
        await pilot.pause(0.1)
        assert mark.number == 2
        assert [m.number for m in panel.marks] == [1, 2]
        assert panel.segment == 2


# --------------------------------------------------------------------------
# cache groups + rule editor
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_folders_collapse_into_one_expandable_row() -> None:
    cache_files = [f"{ROOT}/cache/okhttp/{n}" for n in ("journal", "a.0", "b.1")]
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(
            _items(*[_fse("FSE_CONTENT_MODIFIED", p) for p in cache_files]), now=T0
        )
        panel.ingest(
            _items(_fse("FSE_CREATE_FILE", f"{ROOT}/code_cache/x.bin")),
            now=T0 + timedelta(seconds=1),
        )
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", PREFS)), now=T0 + timedelta(seconds=2)
        )
        group = f"{ROOT}/cache/"
        assert _keys(panel) == [PREFS, f"{ROOT}/code_cache/", group]
        row = _row(panel, group)
        assert panel._path_cell(row).plain == "cache/ · 3 files"
        assert str(panel._mark_cell(row)) == "▸"
        assert row.stats.count == 3
        assert panel.caption()[1].startswith("1 path + 2 groups")

        panel.table.focus()
        panel.table.move_cursor(row=2)
        await pilot.press("enter")  # opens the group, no Inspector
        await pilot.pause()
        assert _keys(panel)[2] == group
        assert set(_keys(panel)[3:]) == set(cache_files)
        assert str(panel._mark_cell(_row(panel, group))) == "▾"
        assert panel._path_cell(_row(panel, cache_files[0])).plain.startswith("  ")
        panel.table.move_cursor(row=4)
        await pilot.press("left")  # folds from a member row
        await pilot.pause()
        assert len(_keys(panel)) == 3
        assert panel._cursor_key() == group
        await pilot.press("right")
        await pilot.pause()
        assert len(_keys(panel)) == 6
        await pilot.press("N")  # raw: no grouping
        await pilot.pause()
        assert set(_keys(panel)) == {PREFS, f"{ROOT}/code_cache/x.bin", *cache_files}


@pytest.mark.asyncio
async def test_rule_editor_applies_at_once_persists_and_resets(monkeypatch) -> None:
    import sandroid.config as config_module
    from sandroid.config.schema import default_files_noise_rules
    from sandroid.tui.modals.noise_rules_modal import NoiseRulesModal

    saved: list[dict] = []
    monkeypatch.setattr(
        config_module, "update_config", lambda updates, **kw: saved.append(updates)
    )
    app = _Harness()
    async with app.run_test(size=(140, 40)) as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(
            _items(
                _fse("FSE_CONTENT_MODIFIED", f"{ROOT}/cache/a"),
                _fse("FSE_CONTENT_MODIFIED", f"{ROOT}/files/app.log"),
                _fse("FSE_CONTENT_MODIFIED", PREFS),
            ),
            now=T0,
        )
        panel.refresh_rows()
        panel.table.focus()
        await pilot.press("R")
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, NoiseRulesModal)
        assert modal.rules == default_files_noise_rules()

        assert modal.add_rule("hide", "suffix", ".log")
        assert f"{ROOT}/files/app.log" not in _keys(panel)
        assert "1 hidden: suffix 1" in panel.caption()[1]
        assert saved[-1]["tui.files_noise_rules"][-1] == {
            "action": "hide",
            "kind": "suffix",
            "pattern": ".log",
            "enabled": True,
        }
        assert not modal.add_rule("hide", "suffix", ".log")  # no duplicates

        cache_rule = next(
            i for i, r in enumerate(modal.rules) if r["pattern"] == "cache"
        )
        modal.toggle_rule(cache_rule)  # cache no longer grouped
        assert f"{ROOT}/cache/a" in _keys(panel)
        assert saved[-1]["tui.files_noise_rules"][cache_rule]["enabled"] is False

        modal.remove_rule(len(modal.rules) - 1)
        assert f"{ROOT}/files/app.log" in _keys(panel)

        modal.reset_defaults()
        assert modal.rules == default_files_noise_rules()
        assert f"{ROOT}/cache/" in _keys(panel)
        assert len(saved) == 4

        # Keys inside the editor: Space toggles, Delete removes.
        table = modal.query_one("#rules-table")
        table.focus()
        table.move_cursor(row=0)
        await pilot.press("space")
        await pilot.pause()
        assert modal.rules[0]["enabled"] is False
        await pilot.press("delete")
        await pilot.pause()
        assert len(modal.rules) == len(default_files_noise_rules()) - 1
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, NoiseRulesModal)


def test_noise_rules_are_validated_and_saved_in_the_config() -> None:
    from pydantic import ValidationError

    from sandroid.config.schema import TUIConfig

    cfg = TUIConfig(
        files_noise_rules=[{"action": "group", "kind": "glob", "pattern": "*.tmp"}]
    )
    assert cfg.files_noise_rules == [
        {"action": "group", "kind": "glob", "pattern": "*.tmp", "enabled": True}
    ]
    with pytest.raises(ValidationError):
        TUIConfig(
            files_noise_rules=[{"action": "drop", "kind": "glob", "pattern": "x"}]
        )
    with pytest.raises(ValidationError):
        TUIConfig(files_noise_rules=[{"kind": "regex", "pattern": "x"}])
    defaults = TUIConfig().files_noise_rules
    assert {r["pattern"] for r in defaults if r["action"] == "hide"} >= {
        "/proc/",
        "/data/dalvik-cache/",
        "/data/app/",
    }
    assert "/data/local/tmp/" not in {r["pattern"] for r in defaults}
    assert [r["pattern"] for r in defaults if r["action"] == "group"] == [
        "cache",
        "code_cache",
    ]


# --------------------------------------------------------------------------
# auto-pull + monitor-off caption
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_monitor_off_caption_when_files_are_watched() -> None:
    get_forensic_service().add_spotlight_file(DB)
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        panel.refresh_rows()
        hint = "monitor off — watched files not tracked · o starts it"
        assert hint in panel.caption()[1]
        _register_monitor()
        panel.refresh_rows()
        assert hint not in panel.caption()[1]


@pytest.mark.asyncio
async def test_a_monitor_write_to_a_star_file_is_auto_pulled(monkeypatch) -> None:
    from sandroid.core import watchlist_store
    from sandroid.tui.widgets import watchlist_view
    from sandroid.tui.widgets.watchlist_view import WatchlistView

    monkeypatch.setattr(watchlist_view, "AUTO_PULL_QUIET", 0.1)
    monkeypatch.setattr(WatchlistView, "_device_facts", staticmethod(lambda p: {}))
    monkeypatch.setattr(
        FileExtractionService, "pull_file", _fake_pull({DB: "SQLite format 3\x00"})
    )
    get_forensic_service().add_spotlight_file(DB)
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        _register_monitor()
        await pilot.pause()
        _publish(_fse("FSE_CONTENT_MODIFIED", DB + "-wal"))
        await _wait_for(pilot, lambda: panel.watchlist.pending_auto == [DB])
        rows = panel.watchlist.rows
        await _wait_for(pilot, lambda: rows[DB].state is RowState.BASELINE_ONLY)
        (version,) = watchlist_store.version_dirs(DB)
        record = watchlist_store.version_record(version)
        assert record["trigger"] == "auto"
        assert record["note"].startswith("no on-device sha256")
        assert version.parent == (
            watchlist_store.files_root() / PKG / "databases" / "app.db"
        )
