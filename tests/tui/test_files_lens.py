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
import re
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import timeline_fakes
from pilot_helpers import boot, settle, until
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


@pytest.fixture
def install_fakes(monkeypatch, tmp_path):
    """``install_fakes(lines=None, tracking=True)``: see ``timeline_fakes``."""

    def _install(lines=None, *, tracking: bool = True):
        return timeline_fakes.install(monkeypatch, tmp_path, lines, tracking=tracking)

    return _install


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    # The pre-pull on-device stat/sha256sum is an adb call: no device here.
    from sandroid.tui.widgets.watchlist_view import WatchlistView

    monkeypatch.setattr(WatchlistView, "_device_facts", staticmethod(lambda p: {}))
    # Watching pulls a first version: no device here either (a test that
    # needs content patches its own fake over this one).
    monkeypatch.setattr(FileExtractionService, "pull_file", _fake_pull({}))
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


_FOLLOW = re.compile(r"^(?:live|scrolled back(?: · [\d,]+ new below)? · End = live) · ")


def _markup_plain(markup: str) -> str:
    """A caption title (markup) as the words it shows."""
    from rich.text import Text

    return Text.from_markup(markup).plain


def _title(panel: FilesPanel) -> str:
    """The caption title (plain) without the follow state in front of it."""
    return _FOLLOW.sub("", _markup_plain(panel.caption()[0]), count=1)


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
    model = FileActivity(max_paths=50, auto_group_min=0)
    for i in range(60):
        model.ingest(
            _items(_fse("FSE_CREATE_FILE", f"{ROOT}/files/f{i}")),
            now=T0 + timedelta(seconds=i),
        )
    assert len(model.paths) == 50
    assert f"{ROOT}/files/f0" not in model.paths
    assert f"{ROOT}/files/f59" in model.paths
    assert model.dropped == 10  # never silent


def _ingest_one(model: FileActivity, line: str, second: int) -> None:
    model.ingest(_items(line), now=T0 + timedelta(seconds=second))


def test_the_cap_drops_rule_hidden_then_open_only_then_the_oldest_shown() -> None:
    """Hidden rows go first even when they are the newest; within a tier
    the oldest goes first; the counter counts every dropped file.
    """
    model = FileActivity({"noise": "verbose"}, max_paths=50, auto_group_min=0)
    shown = [f"{ROOT}/d{i}/f.txt" for i in range(40)]  # oldest, no siblings
    opened = [f"{ROOT}/o{i}/f.txt" for i in range(10)]
    os_paths = [f"/data/misc/m{i}/x" for i in range(10)]  # newest, rule-hidden
    for i, path in enumerate(shown):
        _ingest_one(model, _fse("FSE_CONTENT_MODIFIED", path), i)
    for i, path in enumerate(opened):
        _ingest_one(model, _fse("FSE_OPEN", path), 100 + i)
    for i, path in enumerate(os_paths):
        _ingest_one(model, _fse("FSE_CONTENT_MODIFIED", path), 200 + i)
    assert len(model.paths) == 50
    assert not any(p in model.paths for p in os_paths)  # tier 0 went first
    assert model.dropped == 10
    for i in range(10):
        _ingest_one(model, _fse("FSE_CONTENT_MODIFIED", f"{ROOT}/n{i}/f"), 300 + i)
    assert not any(p in model.paths for p in opened)  # then the open-only ones
    assert all(p in model.paths for p in shown)
    for i in range(5):
        _ingest_one(model, _fse("FSE_CONTENT_MODIFIED", f"{ROOT}/k{i}/f"), 400 + i)
    assert not any(p in model.paths for p in shown[:5])  # the oldest shown
    assert all(p in model.paths for p in shown[5:])
    assert model.dropped == 25
    model.reset()
    assert model.dropped == 0


def test_the_cap_never_drops_watched_or_highlighted_rows() -> None:
    model = FileActivity({"noise": "verbose"}, max_paths=50, auto_group_min=0)
    keep = {f"{ROOT}/d0/f.txt", "/data/misc/kept/x", f"{ROOT}/o0/open.txt"}
    model.protected = lambda key: key in keep
    _ingest_one(model, _fse("FSE_CONTENT_MODIFIED", f"{ROOT}/d0/f.txt"), 0)
    _ingest_one(model, _fse("FSE_CONTENT_MODIFIED", "/data/misc/kept/x"), 0)
    _ingest_one(model, _fse("FSE_OPEN", f"{ROOT}/o0/open.txt"), 0)
    for i in range(1, 80):
        _ingest_one(model, _fse("FSE_CONTENT_MODIFIED", f"{ROOT}/d{i}/f.txt"), i)
    assert keep <= set(model.paths)  # the oldest, but protected
    assert len(model.paths) == 50  # protected rows still take their slots
    assert model.dropped == 32


def test_a_group_row_is_one_slot_and_goes_whole() -> None:
    model = FileActivity(max_paths=50)  # auto-groups from 20 / 8 machine names
    cache = [f"{ROOT}/cache/c{i}" for i in range(100)]  # group rule
    idb = f"{ROOT}/files/idb/3870112724rsegmnoittet-es.files"
    model.ingest(_items(*[_fse("FSE_CONTENT_MODIFIED", p) for p in cache]), now=T0)
    model.ingest(
        _items(*[_fse("FSE_DELETE", f"{idb}/{n}") for n in range(445)]),
        now=T0 + timedelta(seconds=1),
    )
    for i in range(48):
        _ingest_one(model, _fse("FSE_CONTENT_MODIFIED", f"{ROOT}/d{i}/f"), 10 + i)
    assert len(model.paths) == 100 + 445 + 48  # 50 slots: nothing dropped
    assert model.dropped == 0
    _ingest_one(model, _fse("FSE_CONTENT_MODIFIED", f"{ROOT}/late/f"), 100)
    # the oldest slot is the cache group: all of its files go together
    assert not any(p in model.paths for p in cache)
    assert f"{idb}/444" in model.paths
    assert model.dropped == 100


def test_auto_group_thresholds_and_machine_names() -> None:
    from sandroid.tui.widgets.monitor_view import (
        auto_group_folders,
        machine_group_min,
        machine_name,
    )

    for name in (
        "445",
        "0a1b2c3d4e5f",
        "6f1c2a9e-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
        "12345.tmp",
    ):
        assert machine_name(name), name
    for name in ("journal", "cafe", "aaid.txt", "f_001", "data.sqlite"):
        assert not machine_name(name), name
    assert machine_group_min(20) == 8
    assert machine_group_min(0) == 0
    named = [f"/d/a/file{i}.json" for i in range(20)]
    assert auto_group_folders(named[:19], 20) == {}
    assert auto_group_folders(named, 20) == {"/d/a": named}
    numbered = [f"/d/idb/{i}" for i in range(8)]
    assert auto_group_folders(numbered[:7], 20) == {}
    assert auto_group_folders(numbered, 20) == {"/d/idb": numbered}
    mixed = [*numbered[:7], "/d/idb/readme"]  # one person-made name: 20 needed
    assert auto_group_folders(mixed, 20) == {}
    assert auto_group_folders(named, 0) == {}  # 0 = off


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
        # L8 (round 2): no "LIVE" title while the monitor is off.
        title, info = panel.caption()
        assert (_markup_plain(title), info) == ("monitor ○ off", "")
        # The dot and its word in the state's lens colour.
        from sandroid.tui.themes import lens_palette

        assert title == f"monitor [{lens_palette().dim}]○ off[/]"


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
        await until(pilot, lambda: rows[PREFS].state is RowState.BASELINE_ONLY)
        assert rows[DB].state is RowState.NEVER_PULLED
        assert rows[PREFS].size == len("<map/>\n")
        assert rows[PREFS].sha256
        assert rows[PREFS].pulled_at
        await pilot.press("U")
        await until(pilot, lambda: rows[DB].state is RowState.BASELINE_ONLY)
        await until(pilot, lambda: rows[PREFS].state is RowState.UNCHANGED)


@pytest.mark.asyncio
async def test_u_on_an_unwatched_row_watches_then_pulls(monkeypatch) -> None:
    pulled: list[str] = []
    fake = _fake_pull({AAID: "x"})

    def _pull(self, remote_path, local_path, compute_hash=False):
        pulled.append(remote_path)
        return fake(self, remote_path, local_path, compute_hash)

    monkeypatch.setattr(FileExtractionService, "pull_file", _pull)
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await pilot.press("u")
        rows = panel.watchlist.rows
        await until(
            pilot,
            lambda: AAID in rows and rows[AAID].state is RowState.BASELINE_ONLY,
        )
        # Watching pulls the first version; u adds no second pull of the
        # file on top of it (the two used to race on the staging folder).
        assert not panel.watchlist.is_pulling(AAID)
        assert pulled.count(AAID) == 1


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
        await until(pilot, lambda: rows[PREFS].state is RowState.BASELINE_ONLY)
        content[PREFS] = '<map><boolean name="a" value="false" /></map>'
        panel.watchlist.pull([PREFS])
        await until(pilot, lambda: rows[PREFS].state is RowState.CHANGED)
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
        assert "Rewind" in panel.notice
        assert "Play" not in panel.notice
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
        await until(pilot, lambda: not panel.resume_offered)
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
        await until(pilot, lambda: panel._review_record is not None)
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
        assert _title(panel) == "monitor ○ off"  # back to live, monitor off


@pytest.mark.asyncio
async def test_review_scope_with_a_missing_run_says_so(tmp_path) -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        panel.post_message(ScopeChanged(str(tmp_path / "nope")))
        await until(pilot, lambda: panel._review_error is not None)
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
        ms = await boot(app, pilot)
        await pilot.press("3")
        await settle(pilot)
        panel = ms.lens_widget("files")
        assert isinstance(panel, FilesPanel)
        border_title = ms.query_one("#lens-host").border_title
        assert _markup_plain(border_title) == "Files · monitor ○ off"
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", PREFS)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await pilot.pause()
        await pilot.press("enter")
        await settle(pilot)
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
        # Moving the cursor follows with the Inspector (newest last: up).
        await pilot.press("up")
        await settle(pilot)
        assert ms.inspector_content.key[2] != path
        await pilot.press("escape")
        await settle(pilot)
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
        await until(pilot, lambda: panel._review_record is not None)
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
        assert panel._path_cell(rows[old]).plain.endswith("b.txt renamed to c.txt")
        panel._path_width = 10  # narrow (beside the Inspector at 80 columns)
        assert panel._path_cell(rows[old]).plain.endswith(" renamed")
        assert "→" not in panel._path_cell(rows[AAID]).plain
        panel._path_width = 60
        summary = _plain(_tab(panel._inspector_for(rows[old]), "Summary"))
        assert "renamed to files/c.txt" in summary
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
        await until(pilot, lambda: rows[PREFS].state is RowState.BASELINE_ONLY)
        content[PREFS] = '<map><string name="k">two</string></map>'
        panel.watchlist.pull([PREFS])
        await until(pilot, lambda: rows[PREFS].state is RowState.CHANGED)
        panel.refresh_rows()
        history = _plain(_tab(panel.inspect_selected(), "Versions"))
        assert "v2" in history
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
        assert "v2" in history
        assert "v1" in history
        assert "two" in history


async def test_inspector_keys_work_while_the_inspector_has_focus() -> None:
    """M6: with focus in the Inspector (needed to scroll it), the lens keys it
    advertises -- w watch, u pull, z zoom -- still act on the lens's row.
    """
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("3")
        await settle(pilot)
        panel = ms.lens_widget("files")
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await pilot.pause()
        await pilot.press("enter")
        await settle(pilot)
        assert ms.inspector_is_open
        ms.query_one("#inspector-scroll").focus()
        await pilot.pause()
        assert panel.table is not app.focused
        await pilot.press("w")
        await settle(pilot)
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
        assert _keys(panel) == [DB, PREFS, new]  # newest last
        assert _row(panel, PREFS).stats.count == 1  # reset per segment
        assert _row(panel, DB).dim
        assert panel._path_cell(_row(panel, DB)).spans[-1].style == "#5b6479"
        assert _title(panel) == "since Note 1 'tap login' · 10:40:10"

        panel.table.focus()
        await pilot.press("A")  # everything again
        await pilot.pause()
        assert set(_keys(panel)) == {DB, new, PREFS, AAID}
        assert _row(panel, PREFS).stats.count == 2
        assert _title(panel) == "monitor ○ off"
        await pilot.press("A")
        await pilot.pause()
        assert panel.segment == 1

        panel.drop_mark("", T0 + timedelta(seconds=30))  # unnamed
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", AAID)), now=T0 + timedelta(seconds=35)
        )
        assert _keys(panel) == [DB, AAID]
        assert _title(panel) == "since Note 2 · 10:40:30"
        await pilot.press("less_than_sign")
        await pilot.pause()
        assert _keys(panel) == [DB, PREFS, new]
        assert _title(panel) == ("Note 1 'tap login' to Note 2 · 10:40:10–10:40:30")
        await pilot.press("less_than_sign")
        await pilot.pause()
        assert set(_keys(panel)) == {DB, PREFS, AAID}
        assert _row(panel, AAID).stats.ops == {"create": 1}
        assert _title(panel) == "before Note 1 'tap login' · until 10:40:10"
        await pilot.press("less_than_sign")  # stays at the first segment
        await pilot.press("greater_than_sign", "greater_than_sign")
        await pilot.pause()
        assert panel.segment == 2

        # The Inspector's Events tab has the marks as separator lines.
        events = _plain(_tab(panel._inspector_for(_row(panel, AAID)), "Events"))
        lines = [ln.strip() for ln in events.splitlines() if ln.strip()]
        assert lines[0].startswith("10:40:35")
        assert lines[1] == "Note 2 · 10:40:30"
        assert lines[2] == "Note 1 'tap login' · 10:40:10"
        assert lines[3].startswith("10:40:00")
        # A file first touched after a mark ends with that mark.
        panel._segment = None
        panel.refresh_rows()
        events = _plain(_tab(panel._inspector_for(_row(panel, new)), "Events"))
        lines = [ln.strip() for ln in events.splitlines() if ln.strip()]
        assert lines[0] == "Note 2 · 10:40:30"
        assert lines[1].startswith("10:40:25")
        assert lines[2] == "Note 1 'tap login' · 10:40:10"
        assert len(lines) == 3


async def test_B_asks_for_a_note_text_empty_enter_keeps_asking_esc_cancels(
    install_fakes,
) -> None:
    """``B`` is the App's Note key: an ``InputModal`` asks for the note's
    text, which it needs (an empty Enter keeps the prompt open with a hint,
    Esc = no note); the Files lens pre-splits at the key press while the
    prompt is open.
    """
    from sandroid.tui.app import SandroidTUI

    fakes = install_fakes()
    app = SandroidTUI()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, panel = await _boot_files(pilot, app)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await pilot.press("B")
        await settle(pilot)
        assert type(app.screen).__name__ == "InputModal"
        assert "Note 1 · at " in app.screen.title_text
        assert app.screen.title_text.endswith("— text")
        assert len(panel.activity.mark_times) == 1  # pre-split at the key press
        await pilot.press("enter")  # empty: the prompt stays, with a hint
        await settle(pilot)
        assert type(app.screen).__name__ == "InputModal"
        hint = str(app.screen.query_one("#input-hint").render())
        assert "needs its text" in hint
        assert panel.marks == []
        await pilot.press(*"first", "enter")
        await settle(pilot)
        assert [m.label() for m in panel.marks] == ["Note 1 'first'"]
        await pilot.press("B")
        await settle(pilot)
        await pilot.press(*"login", "enter")
        await settle(pilot)
        assert [m.label() for m in panel.marks] == ["Note 1 'first'", "Note 2 'login'"]
        await pilot.press("B")
        await settle(pilot)
        await pilot.press("escape")  # no mark
        await settle(pilot)
        assert len(panel.marks) == 2
        assert len(panel.activity.mark_times) == 2
        assert [e.kind for e in fakes.labels.history()] == ["point", "point"]
        assert type(app.screen).__name__ == "MainScreen"


def test_the_new_lens_keys_shadow_no_app_wide_key() -> None:
    """``A``/``<``/``>``/``R`` are free app-wide (``m`` is Dexray, ``a``
    Analyze -- the lens no longer shadows ``a``); ``B`` moved to the App
    (label point, every lens) and is no Files key any more.
    """
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.screens.main_screen import MainScreen

    app_keys = {b.key for b in SandroidTUI.BINDINGS} | {
        b.key for b in MainScreen.BINDINGS
    }
    lens_keys = {b.key for b in FilesPanel.BINDINGS}
    for key in ("A", "less_than_sign", "greater_than_sign", "R", "M", "W"):
        assert key in lens_keys
        assert key not in app_keys
    assert "a" not in lens_keys  # auto-pull poll mode removed; Analyze works
    assert "B" not in lens_keys
    by_key = {b.key: b.action for b in SandroidTUI.BINDINGS}
    assert by_key["B"] == "label_point"


async def test_marks_are_a_shell_concept_logged_and_sent_to_every_lens(
    install_fakes,
) -> None:
    from sandroid.tui.app import SandroidTUI

    fakes = install_fakes()
    app = SandroidTUI()
    async with app.run_test(size=(160, 45)) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("3")
        await settle(pilot)
        panel = ms.lens_widget("files")
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await pilot.press("B")
        await settle(pilot)
        await pilot.press(*"tap login", "enter")
        await settle(pilot)
        assert [m.label() for m in ms.marks] == ["Note 1 'tap login'"]
        assert "Note 1 'tap login'" in ms.query_one("#log-ticker").last_line
        assert panel.segment == 1
        assert ms.query_one("#lens-host").border_title.startswith(
            "Files · since Note 1 'tap login' · "
        )
        mark = ms.add_mark("from elsewhere")
        await settle(pilot)
        assert mark.number == 2
        assert [m.number for m in panel.marks] == [1, 2]
        assert panel.segment == 2

        # The marks are label lines of the session timeline (no marks.jsonl).
        points = [line for line in fakes.service.lines if line["src"] == "label"]
        assert [(line["kind"], line["data"]["name"]) for line in points] == [
            ("point", "tap login"),
            ("point", "from elsewhere"),
        ]
        assert [c[1]["source"] for c in fakes.labels.calls] == ["key", "api"]


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
        assert _keys(panel) == [group, f"{ROOT}/code_cache/", PREFS]  # newest last
        row = _row(panel, group)
        assert panel._path_cell(row).plain == "cache/ · 3 files"
        assert str(panel._mark_cell(row)) == ""  # no glyph: colour + words
        assert row.stats.count == 3
        assert panel.caption()[1].startswith("1 path + 2 groups")

        panel.table.focus()
        panel.table.move_cursor(row=0)
        await pilot.press("enter")  # opens the group, no Inspector
        await pilot.pause()
        assert _keys(panel)[0] == group
        assert set(_keys(panel)[1:4]) == set(cache_files)
        assert str(panel._mark_cell(_row(panel, group))) == ""
        assert panel._path_cell(_row(panel, group)).plain == "cache/ · 3 files · open"
        assert panel._path_cell(_row(panel, cache_files[0])).plain.startswith("  ")
        panel.table.move_cursor(row=2)
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
        # E2E LOW: the focused button is visibly different from the others.
        modal.query_one("#rules-reset").focus()
        await pilot.pause()
        styles = {b.id: str(b.styles.text_style) for b in modal.query("Button")}
        assert "reverse" in styles["rules-reset"]
        assert "reverse" not in styles["rules-add-btn"]
        assert "reverse" not in styles["rules-close"]
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

    monkeypatch.setattr(watchlist_view, "AUTO_PULL_QUIET", 0.5)
    monkeypatch.setattr(WatchlistView, "_device_facts", staticmethod(lambda p: {}))
    # Starting the monitor also pulls watched files once (trigger
    # "session-start"); under load that pull can win the race against the
    # auto-pull this test is about, so it is switched off here.
    monkeypatch.setattr(WatchlistView, "pull_session_baselines", lambda self, pkg: None)
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
        await until(pilot, lambda: panel.watchlist.pending_auto == [DB])
        rows = panel.watchlist.rows
        await until(
            pilot, lambda: rows[DB].state is RowState.BASELINE_ONLY, timeout=8.0
        )
        (version,) = watchlist_store.version_dirs(DB)
        record = watchlist_store.version_record(version)
        assert record["trigger"] == "auto"
        assert record["note"].startswith("no on-device sha256")
        assert version.parent == (
            watchlist_store.files_root() / PKG / "databases" / "app.db"
        )


# --------------------------------------------------------------------------
# stray keys (E2E Files/Firefox finding 2): focus limbo, routing, typing guard
# --------------------------------------------------------------------------


async def _boot_files(pilot, app):
    ms = await boot(app, pilot)
    await pilot.press("3")
    await settle(pilot)
    return ms, ms.lens_widget("files")


@pytest.mark.asyncio
async def test_mark_then_help_then_slash_types_into_the_filter(monkeypatch) -> None:
    """The E2E repro: ``B`` + a name with no activity since → the view is
    empty for a moment and the lens hid its table while focus was still on
    its way there; Textual left focus on nothing, closing ``?`` then focused
    the hidden App lens, ``/`` did nothing and "places" ran p/l/a/c/e/s.
    """
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(200, 50)) as pilot:
        ms, panel = await _boot_files(pilot, app)
        played: list[int] = []
        monkeypatch.setattr(app, "action_play", lambda: played.append(1))
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await pilot.pause()
        await pilot.press("B", *"open wikipedia", "enter")
        await settle(pilot)
        assert panel.has_class("-empty")  # nothing since the mark yet
        assert ms.focused is not None
        assert panel in ms.focused.ancestors_with_self
        await pilot.press("question_mark")
        await settle(pilot)
        assert type(app.screen).__name__ == "HelpScreen"
        await pilot.press("escape")
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert ms.focused is not None
        assert panel in ms.focused.ancestors_with_self
        await pilot.press("slash", *"places")
        await settle(pilot)
        field = panel.query_one("#files-input", Input)
        assert app.focused is field
        assert field.value == "places"
        assert played == []
        assert type(app.screen).__name__ == "MainScreen"


@pytest.mark.asyncio
async def test_focus_lost_to_nothing_or_a_hidden_lens_comes_back() -> None:
    """Focus on nothing / inside the hidden App lens returns to the lens."""
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, panel = await _boot_files(pilot, app)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        await pilot.pause()
        ms.set_focus(None)
        await settle(pilot)
        assert ms.focused is panel.table
        ms.set_focus(ms.query_one("#spotlight-panel"))  # hidden lens
        await settle(pilot)
        assert ms.focused is panel.table
        # A modal closing with nothing focused: AUTO_FOCUS is the active lens.
        assert ms.AUTO_FOCUS == "#files-panel"


@pytest.mark.asyncio
async def test_lens_keys_reach_the_lens_even_when_focus_is_elsewhere(
    monkeypatch,
) -> None:
    """Layer 2: with the re-homing disabled, a key the focus chain does not
    bind but the active lens does still runs on the lens; the hidden App
    lens's ``A`` (Attach) never fires from the Files lens.
    """
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.screens.main_screen import MainScreen
    from sandroid.tui.widgets.spotlight_panel import SpotlightPanel

    attached: list[int] = []
    monkeypatch.setattr(MainScreen, "_rehome_focus", lambda self, *a: None)
    monkeypatch.setattr(
        SpotlightPanel, "action_attach_app", lambda self: attached.append(1)
    )
    app = SandroidTUI()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, panel = await _boot_files(pilot, app)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.drop_mark("m", T0 + timedelta(seconds=1))
        await pilot.pause()
        assert panel.segment == 1
        ms.set_focus(ms.query_one("#spotlight-panel"))  # limbo: hidden lens
        await pilot.pause()
        await pilot.press("A")  # Files: all / since mark -- not App: Attach
        await pilot.pause()
        assert panel.segment is None
        assert attached == []
        assert ms.focused is not None
        assert panel in ms.focused.ancestors_with_self
        ms.set_focus(None)
        await pilot.pause()
        await pilot.press("slash")
        await pilot.pause()
        assert app.focused is panel.query_one("#files-input", Input)


@pytest.mark.asyncio
async def test_slash_in_a_lens_without_a_filter_swallows_the_typed_word(
    monkeypatch,
) -> None:
    """Layer 3: ``/`` that opens nothing starts the typing guard -- the word
    typed after it runs no single-letter app command; after a pause the
    commands work again.
    """
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.screens.main_screen import MainScreen

    monkeypatch.setattr(MainScreen, "TYPING_GUARD_SECONDS", 60.0)
    app = SandroidTUI()
    async with app.run_test(size=(160, 45), notifications=True) as pilot:
        ms, _panel = await _boot_files(pilot, app)
        played: list[int] = []
        monkeypatch.setattr(app, "action_play", lambda: played.append(1))
        await pilot.press("4")  # Runs lens: no "/" filter
        await settle(pilot)
        await pilot.press("slash", *"places")
        await settle(pilot)
        assert played == []
        assert type(app.screen).__name__ == "MainScreen"
        assert ms._typed_ignored == "places"
        assert any("no filter" in n.message for n in app._notifications)
        ms._typing_until = time.monotonic() - 1.0  # a pause ended the window
        await pilot.press("p")
        await pilot.pause()
        assert played == [1]


@pytest.mark.asyncio
async def test_quit_dialog_opened_by_a_stray_q_is_cancelled_by_the_next_letter(
    monkeypatch,
) -> None:
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(160, 45), notifications=True) as pilot:
        ms, _panel = await _boot_files(pilot, app)
        exits: list[int] = []
        monkeypatch.setattr(app, "exit", lambda *a, **k: exits.append(1))
        await pilot.press("4")
        await settle(pilot)
        await pilot.press(*"query", "enter")
        await settle(pilot)
        assert exits == []
        assert type(app.screen).__name__ == "MainScreen"
        assert any("looked like typing" in n.message for n in app._notifications)


# --------------------------------------------------------------------------
# E2E round 2: keys typed in a burst (H2, H3, M1), hidden lenses, Import Esc
# --------------------------------------------------------------------------

_CHARS = {"grave_accent": "`", "slash": "/", "enter": "\r", "escape": None}


def _burst(app, *keys: str) -> None:
    """Deliver keys the way a terminal does for fast typing / tmux send-keys:
    all queued at once, before the first one is handled (``pilot.press``
    waits for the app to go idle between keys and hides the race).
    """
    from textual import events

    # A key is never stale here: a slow host must not release the next key
    # before the previous one took effect (KEY_SETTLE_SECONDS is a valve).
    app.KEY_SETTLE_SECONDS = 60.0
    for key in keys:
        char = _CHARS.get(key, key if len(key) == 1 else None)
        app.post_message(events.Key(key, char))


@pytest.mark.asyncio
async def test_drawer_toggle_then_typed_filter_word_reaches_the_filter(
    monkeypatch,
) -> None:
    """H2: `` ` `` `` ` `` ``/heise`` typed at once ran the global h (friTap,
    which also switched to the Network lens), e (Device Info), i (Import),
    s (Screenshot): Textual routed every key to the table that had focus
    when the burst was dequeued, before ``/`` moved focus to the filter.
    """
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(200, 50)) as pilot:
        ms, panel = await _boot_files(pilot, app)
        ran: list[str] = []
        real = app.run_action

        async def spy(action, *args, **kwargs):
            ran.append(str(action))
            return await real(action, *args, **kwargs)

        monkeypatch.setattr(app, "run_action", spy)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        await settle(pilot)
        _burst(app, "grave_accent", "grave_accent", "slash", *"heise")
        await settle(pilot)
        field = panel.query_one("#files-input", Input)
        assert field.value == "heise"
        assert app.focused is field
        assert type(app.screen).__name__ == "MainScreen"
        assert ms.active_lens == "files"
        assert ran == ["toggle_log", "toggle_log", "filter"], ran


@pytest.mark.asyncio
async def test_quit_cancelled_as_typing_never_runs_the_next_letter(
    monkeypatch,
) -> None:
    """H3: ``q`` then ``xyz``: "Quit cancelled -- that looked like typing",
    but the ``y`` (routed to the dialog before it closed) then ran the main
    screen's global ``y`` = Proxy Settings.
    """
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(160, 45), notifications=True) as pilot:
        ms, _panel = await _boot_files(pilot, app)
        proxy: list[int] = []
        exits: list[int] = []
        monkeypatch.setattr(app, "action_proxy", lambda: proxy.append(1))
        monkeypatch.setattr(app, "exit", lambda *a, **k: exits.append(1))
        await pilot.press("q")
        await settle(pilot)
        assert type(app.screen).__name__ == "QuitConfirmModal"
        _burst(app, *"xyz")
        await settle(pilot)
        assert proxy == []
        assert exits == []
        assert type(app.screen).__name__ == "MainScreen"
        assert any("looked like typing" in n.message for n in app._notifications)
        # Within the guard window the next letters are text, not commands.
        _burst(app, "y")
        await settle(pilot)
        assert proxy == []
        assert ms.typing_guard_active()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("opener", "lens_key", "action"),
    [("q", "w", "toggle_watch"), ("p", "z", "zoom")],
)
async def test_lens_key_after_a_stray_typing_cancel_never_runs(
    monkeypatch, opener: str, lens_key: str, action: str
) -> None:
    """E2E round 3 N1: ``q x w`` cancelled the quit as typing, then ``w``
    added a watch and pulled the file; ``p x z`` opened the zoom diff. The
    stray window swallowed only app/screen bindings, not the lens's own.
    One burst, as typed.
    """
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(160, 45), notifications=True) as pilot:
        ms, panel = await _boot_files(pilot, app)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        panel.table.focus()
        ran: list[str] = []
        exits: list[int] = []
        monkeypatch.setattr(panel, f"action_{action}", lambda: ran.append(action))
        monkeypatch.setattr(app, "exit", lambda *a, **k: exits.append(1))
        # p: a guarded confirm (the stop-the-rewind question), not a device
        # action.
        monkeypatch.setattr(app, "action_play", app._confirm_stop_replay)
        await settle(pilot)
        _burst(app, opener, "x", lens_key)
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert any("looked like typing" in n.message for n in app._notifications)
        assert ran == []
        assert exits == []
        assert ms._typed_ignored == lens_key
        # The window is over: the lens key works again.
        ms._typing_until = 0.0
        await pilot.press(lens_key)
        await settle(pilot)
        assert ran == [action]


@pytest.mark.asyncio
async def test_stray_window_passes_keys_that_are_not_typing(monkeypatch) -> None:
    """Only printable keys are swallowed: arrows (and Esc, Enter, Tab) still
    work right after a stray-typing cancel.
    """
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(160, 45), notifications=True) as pilot:
        ms, panel = await _boot_files(pilot, app)
        panel.ingest(
            _items(_fse("FSE_CREATE_FILE", AAID), _fse("FSE_CREATE_FILE", PREFS)),
            now=T0,
        )
        panel.refresh_rows()
        panel.table.focus()
        panel.table.move_cursor(row=0)  # following sits on the newest (last)
        await settle(pilot)
        row = panel.table.cursor_row
        _burst(app, "q", "x", "3", "down")
        await settle(pilot)
        assert ms.typing_guard_active()
        assert ms._typed_ignored == "3"
        assert panel.table.cursor_row == row + 1


@pytest.mark.asyncio
async def test_first_key_after_declining_play_is_not_lost(monkeypatch) -> None:
    """M1: Enter declined the Play confirm and the ``p`` typed right behind
    it was dropped: it went to the closing dialog, which took it for stray
    typing ("that looked like typing") and swallowed it.
    """
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.modals import ConfirmModal

    app = SandroidTUI()
    async with app.run_test(size=(160, 45), notifications=True) as pilot:
        ms, _panel = await _boot_files(pilot, app)
        plays: list[int] = []
        monkeypatch.setattr(app, "action_play", lambda: plays.append(1))
        app.push_screen(ConfirmModal(title="Play (replay)", guard_typing=True))
        await settle(pilot)
        assert app.screen.focused.id == "no"
        _burst(app, "enter", "p")
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert plays == [1]
        assert not any("looked like typing" in n.message for n in app._notifications)


@pytest.mark.asyncio
async def test_first_key_after_a_lens_switch_reaches_the_new_lens() -> None:
    """M1: ``3`` then ``/`` at once: the ``/`` went to the lens being left."""
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, panel = await _boot_files(pilot, app)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        await pilot.press("4")
        await settle(pilot)
        _burst(app, "3", "slash", *"aid")
        await settle(pilot)
        assert ms.active_lens == "files"
        assert panel.query_one("#files-input", Input).value == "aid"


@pytest.mark.asyncio
async def test_hidden_lenses_cannot_take_focus() -> None:
    """Structural: a lens that is not shown is disabled, so focus (and with
    it every key, binding or key handler) can never land inside it.
    """
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, panel = await _boot_files(pilot, app)
        await settle(pilot)
        hidden = [ms.lens_widget(i) for i in ("app", "network", "runs")]
        assert all(w.disabled for w in hidden)
        assert not panel.disabled
        network = ms.lens_widget("network")
        ms.set_focus(network)
        for widget in network.query("*"):
            if widget.can_focus:
                ms.set_focus(widget)
        await settle(pilot)
        assert ms.focused is not None
        assert panel in ms.focused.ancestors_with_self
        await pilot.press("2")
        await settle(pilot)
        assert not network.disabled
        assert panel.disabled
        assert network in ms.focused.ancestors_with_self


@pytest.mark.asyncio
async def test_reopened_filter_selects_the_old_text() -> None:
    """L7: typing after ``/`` replaced nothing, it appended to the old filter."""
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(160, 45)) as pilot:
        _ms, panel = await _boot_files(pilot, app)
        panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
        panel.refresh_rows()
        await pilot.press("slash", *"aaid", "enter")
        await settle(pilot)
        await pilot.press("slash", *"aid")
        await settle(pilot)
        assert panel.query_one("#files-input", Input).value == "aid"


@pytest.mark.asyncio
async def test_proxy_settings_ignore_a_bare_enter_in_the_stray_window(
    monkeypatch,
) -> None:
    """H3: the Proxy Settings opened by stray typing were applied by the
    next Enter. A bare Enter right after the dialog opened, or while stray
    typing has just closed a dialog, does not apply.
    """
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.modals.confirm_modal import start_typing_guard
    from sandroid.tui.modals.proxy_modal import ProxyModal

    applied: list[int] = []
    monkeypatch.setattr(ProxyModal, "action_apply", lambda self: applied.append(1))
    monkeypatch.setattr(ProxyModal, "ENTER_ARM_SECONDS", 60.0)
    app = SandroidTUI()
    async with app.run_test(size=(160, 45), notifications=True) as pilot:
        await _boot_files(pilot, app)
        app.push_screen(ProxyModal())
        _burst(app, "enter")  # typed ahead
        await settle(pilot)
        modal = app.screen
        assert isinstance(modal, ProxyModal)
        modal.query_one("#device-ext-input", Input).focus()
        modal._opened_at -= 61.0  # the arm window is over
        start_typing_guard(app)  # stray typing just closed a dialog
        await pilot.press("enter")
        await settle(pilot)
        assert applied == []
        assert any("Enter ignored" in n.message for n in app._notifications)
        ms = app.screen_stack[-2]
        ms._typing_until = 0.0  # the window is over
        await pilot.press("enter")
        await settle(pilot)
        assert applied == [1]


def test_import_results_escape_cancels_without_importing(tmp_path) -> None:
    """H2 follow-on: Esc on Import Results logged "'NoneType' object can't be
    awaited" and then imported the default path as if submitted.
    """
    import asyncio
    from types import SimpleNamespace

    from sandroid.commands.io_commands import (
        ExportResultsCommand,
        ImportResultsCommand,
    )

    imported: list[str] = []
    ctx = SimpleNamespace(
        action_queue=object(),
        is_tui_mode=True,
        request_input=lambda **kw: None,  # synchronous, like the real one
        toolbox=SimpleNamespace(import_results=imported.append),
        get_results_path=lambda: str(tmp_path),
    )
    result = asyncio.run(ImportResultsCommand().execute(ctx))
    assert imported == []
    assert result.success is False
    assert result.error == "cancelled"
    result = asyncio.run(ExportResultsCommand().execute(ctx))
    assert result.error == "cancelled"
    assert list(tmp_path.iterdir()) == []
    # A typed path is used as typed (it was always the default before).
    ctx.request_input = lambda **kw: str(tmp_path / "x.json")
    asyncio.run(ImportResultsCommand().execute(ctx))
    assert imported == [str(tmp_path / "x.json")]


# --------------------------------------------------------------------------
# idle ★ rows fold into one row (E2E finding 9 / owner decision A)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(200, 50), (100, 30)])
async def test_idle_watched_rows_fold_into_one_expandable_row(size) -> None:
    from sandroid.tui.widgets.files_panel import IDLE_FOLD

    prefs = [f"{ROOT}/shared_prefs/p{i:02d}.xml" for i in range(21)]
    for path in prefs:
        get_forensic_service().add_spotlight_file(path)
    pattern = f"{ROOT}/files/*/cookies.sqlite"

    class _Adb:
        @staticmethod
        def send_adb_command(_cmd):
            return "", ""  # the pattern matches nothing yet

    app = _Harness()
    async with app.run_test(size=size) as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        panel.watchlist._adb = lambda: _Adb
        assert panel.watchlist.add_path(pattern)
        await pilot.pause()
        # Everything view, no activity at all: 22 never-touched watches
        # flood the table -> folded there too, and the row says so.
        keys = _keys(panel)
        assert keys == [IDLE_FOLD]
        assert panel._path_cell(_row(panel, IDLE_FOLD)).plain.startswith(
            "★ 22 watched · idle"
        )
        panel.ingest(_items(_fse("FSE_CONTENT_MODIFIED", prefs[3])), now=T0)
        panel.drop_mark("tap login", T0 + timedelta(seconds=10))
        panel.ingest(
            _items(
                _fse("FSE_CONTENT_MODIFIED", prefs[5]),
                _fse("FSE_CREATE_FILE", AAID),
            ),
            now=T0 + timedelta(seconds=20),
        )
        # Since the mark: ONE fold row for the 21 idle watches (incl. the
        # pattern and prefs[3], active before the mark only) on top, then
        # the segment's activity, the changed ★ row among it (newest last;
        # same time: by path).
        assert _keys(panel) == [IDLE_FOLD, AAID, prefs[5]]
        fold = _row(panel, IDLE_FOLD)
        assert len(fold.members) == 21
        assert pattern in {m.key for m in fold.members}
        cell = panel._path_cell(fold).plain
        if size[0] >= 200:
            assert cell == "★ 21 watched · idle since Note 1 'tap login'"
        else:
            assert cell.startswith("★ 21 ")
        assert str(panel._mark_cell(fold)) == ""
        assert "1 group" not in panel.caption()[1]  # the fold is no cache group

        panel.table.focus()
        panel.table.move_cursor(row=0)
        await pilot.press("enter")  # opens the fold, no Inspector
        await pilot.pause()
        keys = _keys(panel)
        assert keys[0] == IDLE_FOLD
        assert keys[-2:] == [AAID, prefs[5]]
        assert len(keys) == 2 + 21 + 1
        assert str(panel._mark_cell(_row(panel, IDLE_FOLD))) == ""
        assert panel._path_cell(_row(panel, prefs[0])).plain.startswith("  ")
        panel.table.move_cursor(row=4)
        await pilot.press("w")  # a member row: a real ★ row (unwatch works)
        await pilot.pause()
        assert len(panel.watchlist.rows) == 20
        panel.table.move_cursor(row=4)
        await pilot.press("left")  # folds from a member row
        await pilot.pause()
        assert _keys(panel) == [IDLE_FOLD, AAID, prefs[5]]
        assert panel._cursor_key() == IDLE_FOLD
        await pilot.press("u")  # on the fold row: a hint, no pull
        await pilot.pause()

        # Everything view (A): prefs[3] and prefs[5] were active this
        # session, the other 20 never -> still a flood, still folded.
        await pilot.press("A")
        await pilot.pause()
        keys = _keys(panel)
        assert keys[:4] == [IDLE_FOLD, prefs[3], AAID, prefs[5]]
        assert panel._path_cell(_row(panel, IDLE_FOLD)).plain.startswith(
            "★ 19 watched · idle"
        )


@pytest.mark.asyncio
async def test_a_single_idle_watch_is_not_folded() -> None:
    get_forensic_service().add_spotlight_file(DB)
    get_forensic_service().add_spotlight_file(PREFS)
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        assert set(_keys(panel)) == {DB, PREFS}  # 2 idle in the all view: kept
        panel.drop_mark("m", T0)
        panel.ingest(_items(_fse("FSE_CONTENT_MODIFIED", DB)), now=T0)
        assert _keys(panel) == [PREFS, DB]  # 1 idle in the segment: kept
        assert _row(panel, PREFS).dim


def test_narrow_paths_keep_the_distinguishing_directory() -> None:
    """E2E: beside the Inspector every per-origin store read
    ``files/…/ls/data.sqlite``; the origin directory is elided in the middle
    instead of dropped.
    """
    heise = (
        "files/mozilla/k3m7yjvw.default/storage/default/"
        "https+++688012155290337.mateti.net^partitionKey=%28https%2Cheise.de%29"
        "/ls/data.sqlite"
    )
    wiki = "files/mozilla/k3m7yjvw.default/storage/default/https+++www.wikipedia.org/ls/data.sqlite"
    for width in (40, 56):
        a, b = smart_truncate(heise, width), smart_truncate(wiki, width)
        assert len(a) <= width
        assert len(b) <= width
        assert a.endswith("/ls/data.sqlite")
        assert b.endswith("/ls/data.sqlite")
        assert a != b
        assert "heise.de" in a or "mateti" in a, a
        assert "wikipedia" in b, b
    # Too narrow for a useful part: as before.
    assert smart_truncate(heise, 24) == "files/…/ls/data.sqlite"
    assert smart_truncate("files/a/b/c/d/report.json", 22) == "files/…/d/report.json"


# --------------------------------------------------------------------------
# lens: what the monitor records (follow the app, blind, lost events)
# --------------------------------------------------------------------------


def _register_watched_monitor(device, **cfg):
    """A running monitor session whose MonitorWatch uses a fake device."""
    from sandroid.tui.controllers.monitor_controller import MonitorWatch

    config = MonitorConfig(app_name=PKG, target_path=ROOT, **cfg)
    watch = MonitorWatch(config, "kprobe", device=device, now=lambda: T0)
    wrapper = type("W", (), {"config": config, "watch": watch})()
    get_task_service().register(
        name="monitor",
        display_name="Monitor",
        instance=wrapper,
        stop_callback=lambda: None,
        app_name=PKG,
    )
    return watch


class _Device:
    def __init__(self, table):
        self.table = table

    def listing(self, package, tracked):
        from sandroid.core.kprobe_tracer import AppListing

        return AppListing(10100, dict(self.table), {}, True)

    def add(self, pids):
        from sandroid.core.kprobe_tracer import AddResult

        return AddResult({p: [p] for p in pids}, {}, None)

    def lost(self):
        return 0


@pytest.mark.asyncio
async def test_caption_names_the_scope_following_and_how_to_stop() -> None:
    from sandroid.core.kprobe_tracer import AppProcess

    table = {
        10: AppProcess(10, 10100, PKG),
        11: AppProcess(11, 10100, f"{PKG}:sandboxed_tab_17"),
    }
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        watch = _register_watched_monitor(_Device(table), mode="pid", follow=True)
        watch.seed({10: [10], 11: [11]}, watch.initial_processes())
        await pilot.pause()
        panel.refresh_rows()
        title, info = panel.caption()
        assert _markup_plain(title) == "monitor ● on"
        from sandroid.tui.themes import lens_palette

        assert title == f"monitor [{lens_palette().ok}]● on[/]"
        assert info.startswith(f"App {PKG} · 2 proc · following · o stops")
        watch.lost_events = 7
        assert "7 events lost" in panel.caption()[1]


@pytest.mark.asyncio
async def test_caption_says_blind_instead_of_live_when_the_target_is_gone() -> None:
    from sandroid.core.kprobe_tracer import AppProcess

    device = _Device({10: AppProcess(10, 10100, PKG)})
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        watch = _register_watched_monitor(device, mode="pid", target_pid=10)
        watch.seed({10: []})
        device.table = {}
        watch.poll_once()
        await pilot.pause()
        panel.refresh_rows()
        title, info = panel.caption()
        assert title == "monitor blind since 10:40:00 · target gone"
        assert "o stops · o again re-targets" in info


@pytest.mark.asyncio
async def test_path_mode_caption() -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        _register_watched_monitor(_Device({}), mode="path")
        await pilot.pause()
        panel.refresh_rows()
        expected = f"Path {ROOT} · every process · o stops"
        assert panel.caption()[1].startswith(expected)


@pytest.mark.asyncio
async def test_restart_separator_in_events_and_writes_counted_per_process() -> None:
    from dataclasses import replace

    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        items = _items(
            _fse("FSE_CONTENT_MODIFIED", DB), _fse("FSE_CONTENT_MODIFIED", DB)
        )
        items = [
            replace(items[0], process="main · mozStorage #1", pid=4665),
            replace(items[1], process="tab_17 · DOM Worker", pid=5395),
        ]
        panel.ingest(items[:1], now=T0)
        text = f"{PKG} restarted 10:40:05 · new PID 25983 · gap ≈0.3 s"
        # The monitor's timeline line, as the controller publishes it.
        EventBus.get().publish(
            Event(
                type=EventType.TASK_OUTPUT,
                data={
                    "task_name": "Monitor",
                    "monitor_note": {
                        "text": text,
                        "level": "warning",
                        "when": T0 + timedelta(seconds=5),
                    },
                },
                source="monitor",
            )
        )
        await until(pilot, lambda: bool(panel._monitor_notes))
        panel.ingest(items[1:], now=T0 + timedelta(seconds=9))
        panel.refresh_rows()
        inspected = panel.inspect_selected()
        events = _plain(_tab(inspected, "Events")).splitlines()
        sep = text
        assert sep in events
        # Newest first: the tab_17 write, the restart line, the main write.
        idx = events.index(sep)
        assert "tab_17 · DOM Worker" in events[idx - 1]
        assert "main · mozStorage #1" in events[idx + 1]
        summary = _plain(_tab(inspected, "Summary"))
        assert (
            "main (4665), tab_17 (5395)" in summary
            or "tab_17 (5395), main (4665)" in summary
        )


# --------------------------------------------------------------------------
# E2E round 2: companion delete (M5), separators (L1), OPEN-only idle (L3),
# no LIVE while off / stopping (L8, M8), tid in the timeline (M4)
# --------------------------------------------------------------------------


def test_a_journal_delete_does_not_mark_its_database_deleted() -> None:
    """M5: SQLite deletes ``-journal`` after every transaction; the
    database stays (the Summary said "now deleted" for live DBs).
    """
    activity = FileActivity()
    activity.ingest(
        _items(
            _fse("FSE_CONTENT_MODIFIED", DB),
            _fse("FSE_CREATE_FILE", DB + "-journal"),
            _fse("FSE_DELETE", DB + "-journal"),
        ),
        now=T0,
    )
    row = activity.paths[DB]
    assert row.ops.get("delete") == 1  # still shown, as a -journal event
    assert row.events[-1].via == "-journal"
    assert not row.deleted
    activity.ingest(_items(_fse("FSE_DELETE", DB)), now=T0 + timedelta(seconds=1))
    assert row.deleted  # the database's own delete does


@pytest.mark.asyncio
async def test_a_live_database_with_a_deleted_journal_is_not_now_deleted() -> None:
    get_forensic_service().add_spotlight_file(DB)
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        writes: list = []
        panel.watchlist.note_write = lambda key, when: writes.append(key)
        panel.ingest(
            _items(
                _fse("FSE_CONTENT_MODIFIED", DB),
                _fse("FSE_DELETE", DB + "-journal"),
            ),
            now=T0,
        )
        assert writes == [DB]  # the write still auto-pulls
        panel.refresh_rows()
        summary = _plain(panel._live_summary(_row(panel, DB)))
        assert "deleted" not in summary
        assert "strike" not in str(panel._path_cell(_row(panel, DB)).spans)


@pytest.mark.asyncio
async def test_a_restart_before_a_files_first_event_shows_in_its_events() -> None:
    """L1: ``places.sqlite-shm`` first touched after a restart showed the
    mark before it but not the restart line.
    """
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        panel.drop_mark("search", T0)
        panel.ingest(_items(_fse("FSE_CONTENT_MODIFIED", PREFS)), now=T0)
        old = f"{PKG} restarted 10:39:00 · new PID 7000 · gap ≈2.0 s"
        panel.add_monitor_note(old, T0 - timedelta(seconds=60), "warning")
        text = f"{PKG} restarted 10:40:05 · new PID 7592 · gap ≈2.6 s"
        panel.add_monitor_note(f"{PKG} exited · PID 4665", T0 + timedelta(seconds=4))
        panel.add_monitor_note(text, T0 + timedelta(seconds=5), "warning")
        panel.add_monitor_note(
            "+ tab_3 (PID 7700) followed", T0 + timedelta(seconds=6), "info"
        )
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", DB)), now=T0 + timedelta(seconds=9)
        )
        panel.refresh_rows()
        lines = panel._events_text(_row(panel, DB)).plain.splitlines()
        assert lines[0].startswith("10:40:09")
        assert lines[1:] == [
            text,
            f"{PKG} exited · PID 4665",
            "Note 1 'search' · 10:40:00",
        ]  # the follow note (info) and the restart before the mark are not


@pytest.mark.asyncio
async def test_watched_rows_with_only_open_events_stay_in_the_idle_fold() -> None:
    """L3: OPEN-only (hidden) activity took a ★ row out of the fold and
    showed an empty ops column with a count ("2x").
    """
    from sandroid.tui.widgets.files_panel import IDLE_FOLD

    prefs = [f"{ROOT}/shared_prefs/p{i}.xml" for i in range(5)]
    for path in prefs:
        get_forensic_service().add_spotlight_file(path)
    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        panel.drop_mark("restart", T0)
        panel.ingest(
            _items(
                _fse("FSE_OPEN", prefs[0]),
                _fse("FSE_OPEN", prefs[0]),
                _fse("FSE_OPEN", prefs[1]),
                _fse("FSE_CONTENT_MODIFIED", prefs[2]),
            ),
            now=T0 + timedelta(seconds=1),
        )
        assert _keys(panel) == [IDLE_FOLD, prefs[2]]
        assert len(_row(panel, IDLE_FOLD).members) == 4
        panel.table.focus()
        await pilot.press("A")  # everything: still 4 idle -> still folded
        await pilot.pause()
        assert _keys(panel) == [IDLE_FOLD, prefs[2]]
        # Unfolded, an OPEN-only row shows no ops and no count.
        panel._expanded.add(IDLE_FOLD)
        panel.refresh_rows()
        member = _row(panel, prefs[0])
        _mark, _path, ops, count, last = panel._cells(member)
        assert (ops.plain, count.plain, last.plain) == ("", "", "")
        # N (raw view) shows them as activity again.
        panel.activity.show_all = True
        assert prefs[0] in _keys(panel)[:3]


@pytest.mark.asyncio
async def test_title_is_not_live_while_the_monitor_is_off_or_stopping() -> None:
    from sandroid.core.kprobe_tracer import AppProcess

    app = _Harness()
    async with app.run_test() as pilot:
        panel = app.query_one(FilesPanel)
        await pilot.pause()
        assert _title(panel) == "monitor ○ off"
        device = _Device({10: AppProcess(10, 10100, PKG)})
        watch = _register_watched_monitor(device, mode="pid", follow=True)
        watch.seed({10: [10]}, watch.initial_processes())
        panel.refresh_rows()
        assert _title(panel) == "monitor ● on"
        watch.stopping = True  # o pressed: at once, before the device work
        panel.refresh_rows()
        title, info = panel.caption()
        assert _markup_plain(title) == "monitor ◌ stopping…"
        assert "o stops" not in info


@pytest.mark.asyncio
async def test_a_late_view_focus_fixup_keeps_a_filter_a_key_opened() -> None:
    """M1 root cause, deterministic: the switch's focus fix-up runs after the
    next refresh, which can come after the next key (``/`` opened the filter).
    A key routed since the switch wins; without one the fix-up still moves
    focus out of a text field.
    """
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, panel = await _boot_files(pilot, app)
        field = panel.query_one("#files-input", Input)
        at_switch = ms._keys_routed()
        await pilot.press("slash")  # a key after the switch opens the filter
        await settle(pilot)
        assert ms.focused is field
        ms._ensure_view_focus(at_switch)  # the late fix-up
        await settle(pilot)
        assert ms.focused is field
        ms._ensure_view_focus(ms._keys_routed())  # no key since: fix-up acts
        await settle(pilot)
        assert ms.focused is not field


# --------------------------------------------------------------------------
# newest at the bottom + follow (the shared rules of follow.py)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_newest_change_is_at_the_bottom_and_followed_until_moving_up() -> None:
    """Files changes list oldest first; while live the cursor sits on the
    newest row. ↑ stops following (the monitor keeps recording; the caption
    counts the rows that changed since), End resumes.
    """
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        for k, path in enumerate((DB, AAID, PREFS)):
            panel.ingest(
                _items(_fse("FSE_CONTENT_MODIFIED", path)),
                now=T0 + timedelta(seconds=k),
            )
        assert _keys(panel) == [DB, AAID, PREFS]  # newest last
        assert panel.following
        assert panel._cursor_key() == PREFS
        assert _markup_plain(panel.caption()[0]) == "live · monitor ○ off"
        # A change moves its row to the bottom; following keeps up with it.
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", DB)), now=T0 + timedelta(seconds=5)
        )
        assert _keys(panel) == [AAID, PREFS, DB]
        assert panel._cursor_key() == DB
        panel.table.focus()
        await pilot.press("up")
        await settle(pilot)
        assert not panel.following
        assert panel._cursor_key() == PREFS
        assert (
            _markup_plain(panel.caption()[0])
            == "scrolled back · End = live · monitor ○ off"
        )
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", AAID)), now=T0 + timedelta(seconds=9)
        )
        assert _keys(panel) == [PREFS, DB, AAID]
        assert panel._cursor_key() == PREFS  # the view stays put
        assert panel.caption()[0].startswith("scrolled back · 1 new below · End = live")
        assert "live" not in panel.caption()[1]  # one place: the title
        await pilot.press("end")
        await settle(pilot)
        assert panel.following
        assert panel._cursor_key() == AAID
        assert panel.caption()[0].startswith("live · ")
        # A click on a row above the newest one stops following too.
        await pilot.click("#files-table", offset=(5, 0))
        await settle(pilot)
        assert not panel.following
        assert panel._cursor_key() == PREFS
        # Sorted by name / count there is no "newest": no follow wording.
        await pilot.press("O")
        await settle(pilot)
        assert _markup_plain(panel.caption()[0]) == "monitor ○ off"


async def _three_changes(app):
    panel = app.query_one(FilesPanel)
    for k, path in enumerate((DB, AAID, PREFS)):
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", path)), now=T0 + timedelta(seconds=k)
        )
    _keys(panel)
    return panel


@pytest.mark.asyncio
async def test_a_second_up_keeps_counting_what_arrived_below() -> None:
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = await _three_changes(app)
        panel.table.focus()
        await pilot.press("up")
        await settle(pilot)
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", DB)), now=T0 + timedelta(seconds=9)
        )
        _keys(panel)
        assert panel.caption()[0].startswith("scrolled back · 1 new below")
        await pilot.press("up")  # already scrolled back: the count stays
        await settle(pilot)
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", AAID)), now=T0 + timedelta(seconds=12)
        )
        _keys(panel)
        assert panel.caption()[0].startswith("scrolled back · 2 new below")


@pytest.mark.asyncio
async def test_end_resumes_with_a_file_open_in_the_inspector() -> None:
    """End is the user's choice: it resumes, and an open Inspector then
    follows the newest row (no automatic stop for an open Inspector).
    """
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = await _three_changes(app)
        panel.table.focus()
        await pilot.press("up")
        await settle(pilot)
        assert not panel.following
        await pilot.press("end")
        await settle(pilot)
        assert panel.following
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", DB)), now=T0 + timedelta(seconds=9)
        )
        _keys(panel)
        assert panel.following
        assert panel._cursor_key() == DB


@pytest.mark.asyncio
async def test_moving_in_name_order_leaves_follow_for_the_recent_order() -> None:
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = await _three_changes(app)
        panel.table.focus()
        await pilot.press("O")  # by name: no newest row, no follow logic
        await settle(pilot)
        panel.table.move_cursor(row=0)
        await settle(pilot)
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", DB)), now=T0 + timedelta(seconds=5)
        )
        await pilot.press("O", "O")  # back to recent
        await settle(pilot)
        assert panel.following
        assert panel._cursor_key() == DB


@pytest.mark.asyncio
async def test_watched_changes_are_new_below_and_live_resumes_after_review(
    tmp_path,
) -> None:
    get_forensic_service().add_spotlight_file(PREFS)  # ★: moves when it changes
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = await _three_changes(app)
        panel.table.focus()
        await pilot.press("up")
        await settle(pilot)
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", PREFS)), now=T0 + timedelta(seconds=9)
        )
        _keys(panel)
        assert panel.caption()[0].startswith("scrolled back · 1 new below")
        assert not panel.following
        from sandroid.tui.widgets.lens_shell import ScopeChanged

        panel.post_message(ScopeChanged(str(tmp_path / "run"), "Run #1"))
        await settle(pilot)
        panel.post_message(ScopeChanged(None))
        await settle(pilot)
        assert panel.following


def _columns_fill(panel) -> bool:
    """The laid-out columns span the table (no empty strip on the right)."""
    table = panel.table
    used = sum(c.get_render_width(table) for c in table.columns.values())
    return 0 <= table.size.width - used <= 4


async def _files_with_a_row(pilot, app):
    ms, panel = await _boot_files(pilot, app)
    panel.ingest(_items(_fse("FSE_CREATE_FILE", AAID)), now=T0)
    panel.refresh_rows()
    panel.table.focus()
    await until(pilot, lambda: panel.table.row_count == 1 and _columns_fill(panel))
    return ms, panel


async def test_closing_the_inspector_gives_the_table_its_full_width_back() -> None:
    """Beside the Inspector the path column is narrow; after the Inspector
    closes (and after a terminal resize) the columns fill the table again --
    no truncated paths next to ~85 empty columns.
    """
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(200, 45)) as pilot:
        ms, panel = await _files_with_a_row(pilot, app)
        wide = panel._path_width
        await pilot.press("enter")
        await until(pilot, lambda: ms.inspector_is_open)
        await until(pilot, lambda: panel._path_width < wide and _columns_fill(panel))
        await pilot.press("escape")
        await until(pilot, lambda: not ms.inspector_is_open)
        await until(pilot, lambda: panel._path_width == wide and _columns_fill(panel))
        await pilot.resize_terminal(150, 45)
        await until(pilot, lambda: panel._path_width < wide and _columns_fill(panel))
        await pilot.resize_terminal(200, 45)
        await until(pilot, lambda: panel._path_width == wide and _columns_fill(panel))


async def test_the_table_relays_out_even_when_the_panel_refresh_came_too_early(
    monkeypatch,
) -> None:
    """The panel's resize refresh can run before the table has its new width
    (it then lays the columns out for the old one and clears ``_dirty``):
    the table's own resize re-lays them out.
    """
    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(200, 45)) as pilot:
        ms, panel = await _files_with_a_row(pilot, app)
        wide = panel._path_width
        await pilot.press("enter")
        await until(pilot, lambda: ms.inspector_is_open and panel._path_width < wide)
        monkeypatch.setattr(FilesPanel, "on_resize", lambda self, _event: None)
        await pilot.press("escape")
        await until(pilot, lambda: not ms.inspector_is_open)
        await until(pilot, lambda: panel._path_width == wide and _columns_fill(panel))
        cell = panel.table.get_cell_at((0, 1))
        assert cell.plain == "files/aaid.txt"  # full width: not truncated


async def test_the_table_relays_out_when_textual_resizes_it_without_a_resize(
    monkeypatch,
) -> None:
    """After a scroll-only refresh Textual's full widget map is stale; if it
    is rebuilt between the Inspector's CSS change and the layout pass, the
    layout sees no size change and sends neither the panel nor the table a
    Resize -- their sizes change silently. The columns still follow the
    table's width (the panel re-checks it after every layout).
    """
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.widgets.files_panel import _FilesTable

    app = SandroidTUI()
    async with app.run_test(size=(200, 45)) as pilot:
        ms, panel = await _files_with_a_row(pilot, app)
        wide = panel._path_width
        await pilot.press("enter")
        await until(pilot, lambda: ms.inspector_is_open and panel._path_width < wide)
        await settle(pilot)
        resized = []
        on_resize = _FilesTable.on_resize

        def recording(table, event) -> None:
            resized.append(event.size.width)
            on_resize(table, event)

        monkeypatch.setattr(_FilesTable, "on_resize", recording)
        ms._refresh_layout(scroll=True)  # a scroll-only refresh: map stale
        ms.close_side_slot()
        ms._compositor.full_map  # noqa: B018 -- rebuilt from the new CSS
        await settle(pilot)
        await settle(pilot)
        assert resized == []  # the silent resize this test is about
        await until(pilot, lambda: panel._path_width == wide and _columns_fill(panel))
        assert panel.table.get_cell_at((0, 1)).plain == "files/aaid.txt"


async def test_a_changed_watched_file_moves_down_keeps_its_star_and_a_tint() -> None:
    """A ★ file that changes moves to the bottom like any entry (newest
    last, followed), keeps its ★ and a light tint of the ★ colour; an idle
    ★ file stays on top, untinted.
    """
    from rich.style import Style

    from sandroid.tui.row_annotations import row_tint
    from sandroid.tui.widgets.files_panel import WATCHED_TINT

    get_forensic_service().add_spotlight_file(PREFS)
    get_forensic_service().add_spotlight_file(DB)

    def tint(key: str):
        table = panel.table
        return table._get_row_style(table.get_row_index(key), Style()).bgcolor

    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        await until(pilot, lambda: set(_keys(panel)) == {PREFS, DB})
        assert tint(PREFS) is None  # idle ★ rows: on top, no tint
        panel.ingest(_items(_fse("FSE_CONTENT_MODIFIED", PREFS)), now=T0)
        panel.ingest(
            _items(_fse("FSE_CREATE_FILE", AAID)), now=T0 + timedelta(seconds=1)
        )
        await until(pilot, lambda: _keys(panel) == [DB, PREFS, AAID])
        assert str(panel._mark_cell(_row(panel, PREFS))) == "★"
        expected = Style(bgcolor=row_tint(*WATCHED_TINT)).bgcolor
        assert tint(PREFS) == expected
        assert tint(DB) is None
        assert tint(AAID) is None
        # It changes again: the newest row, and the live cursor follows it.
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", PREFS)), now=T0 + timedelta(seconds=5)
        )
        await until(pilot, lambda: _keys(panel) == [DB, AAID, PREFS])
        await until(pilot, lambda: panel._cursor_key() == PREFS)
        assert panel.following
        assert tint(PREFS) == expected


async def test_an_idle_watched_file_with_only_hidden_opens_is_not_new_below() -> None:
    """A ★ file that only saw OPEN events (hidden) stays idle on top: it
    must not count as "new below" while scrolled back.
    """
    get_forensic_service().add_spotlight_file(PREFS)
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        for k, path in enumerate((DB, AAID)):
            panel.ingest(
                _items(_fse("FSE_CONTENT_MODIFIED", path)),
                now=T0 + timedelta(seconds=k),
            )
        _keys(panel)
        panel.table.focus()
        await pilot.press("up")
        await settle(pilot)
        panel.ingest(_items(_fse("FSE_OPEN", PREFS)), now=T0 + timedelta(seconds=9))
        assert _keys(panel)[0] == PREFS  # idle: still on top
        _keys(panel)
        assert panel.caption()[0].startswith("scrolled back · End = live")


# --------------------------------------------------------------------------
# bursts: auto-groups, the row cap, M (hide like this), W (watched only)
# --------------------------------------------------------------------------

IDB = f"{ROOT}/files/idb/3870112724rsegmnoittet-es.files"


async def test_a_burst_of_siblings_folds_into_one_group_and_the_star_stays() -> None:
    get_forensic_service().add_spotlight_file(f"{IDB}/7")  # a watched member
    app = _Harness()
    async with app.run_test(size=(140, 40)) as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(
            _items(*[_fse("FSE_DELETE", f"{IDB}/{n}") for n in range(30)]), now=T0
        )
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", PREFS)), now=T0 + timedelta(seconds=2)
        )
        group = IDB + "/"
        keys = _keys(panel)
        assert set(keys) == {f"{IDB}/7", group, PREFS}
        row = _row(panel, group)
        assert row.auto
        assert len(row.members) == 29
        assert panel._path_cell(row).plain.endswith(" · 29 files")
        assert panel.caption()[1].startswith("2 paths + 1 group")
        # The Inspector of the group: op counts and the time span.
        summary = _plain(panel._group_inspector(row).tabs[0][1])
        assert "29 files" in summary
        assert "D 29×" in summary
        assert "span" in summary
        assert "under 1 s" in summary
        assert "auto" in summary
        # Enter / Right open it, Left folds it (the existing group keys).
        panel.table.focus()
        panel.set_following(False)
        panel.table.move_cursor(row=panel.table.get_row_index(group))
        await pilot.press("enter")
        await settle(pilot)
        assert len(_keys(panel)) == 3 + 29
        assert _row(panel, f"{IDB}/12").depth == 1
        await pilot.press("left")
        await settle(pilot)
        assert len(_keys(panel)) == 3
        # 0 = off: every file is its own row again.
        panel.activity.auto_group_min = 0
        assert len(_keys(panel)) == 30 + 1


async def test_auto_groups_need_fewer_machine_made_names() -> None:
    app = _Harness()
    async with app.run_test(size=(140, 40)) as pilot:
        panel = app.query_one(FilesPanel)
        numbered = [f"{ROOT}/files/blobs/{n}" for n in range(8)]
        named = [f"{ROOT}/files/notes/note{n}.txt" for n in range(8)]
        panel.ingest(
            _items(*[_fse("FSE_CREATE_FILE", p) for p in numbered + named]), now=T0
        )
        keys = _keys(panel)
        assert f"{ROOT}/files/blobs/" in keys  # 8 machine-made names: a group
        assert set(named) <= set(keys)  # 8 named files: still rows
        await pilot.pause()


async def test_the_row_cap_says_what_it_dropped_once_and_keeps_watched_rows() -> None:
    kept = f"{ROOT}/d0/f"
    get_forensic_service().add_spotlight_file(kept)
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        notes: list[str] = []
        app.notify = lambda message, **kw: notes.append(str(message))
        panel.activity.max_paths = 50
        panel.activity.auto_group_min = 0
        for i in range(60):
            panel.ingest(
                _items(_fse("FSE_CONTENT_MODIFIED", f"{ROOT}/d{i}/f")),
                now=T0 + timedelta(seconds=i),
            )
        panel.refresh_rows()
        assert kept in panel.activity.paths  # the oldest, but watched
        assert f"{ROOT}/d1/f" not in panel.activity.paths
        assert "10 dropped at the 50-row limit" in panel.caption()[1]
        cap_notes = [n for n in notes if "tui.monitor_max_lines" in n]
        assert len(cap_notes) == 1  # once, not per batch
        await pilot.pause()


async def test_M_hides_rows_like_this_one_for_the_session_or_always(
    monkeypatch,
) -> None:
    import glob

    import sandroid.config as config_module
    from sandroid.tui.modals.noise_rules_modal import MuteRowModal, NoiseRulesModal

    saved: list[dict] = []
    monkeypatch.setattr(
        config_module, "update_config", lambda updates, **kw: saved.append(updates)
    )
    logs = [f"{ROOT}/files/logs/a.log", f"{ROOT}/files/logs/b.log"]
    other = f"{ROOT}/files/other.txt"
    app = _Harness()
    async with app.run_test(size=(140, 40)) as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(
            _items(*[_fse("FSE_CONTENT_MODIFIED", p) for p in [*logs, other, PREFS]]),
            now=T0,
        )
        _keys(panel)
        choices = panel.mute_choices(_row(panel, logs[0]))
        assert [(c[0], c[3]) for c in choices] == [
            ("this folder", 2),
            ("parent folder", 3),
            ("this file", 1),
        ]
        # Enter: the first scope, for this session only (nothing saved).
        panel.table.focus()
        panel.set_following(False)
        panel.table.move_cursor(row=panel.table.get_row_index(logs[0]))
        await pilot.press("M")
        await until(pilot, lambda: isinstance(app.screen, MuteRowModal))
        assert "hides 2 rows" in MuteRowModal.choice_text(app.screen.choices[0]).plain
        await pilot.press("enter")
        await until(pilot, lambda: not isinstance(app.screen, MuteRowModal))
        assert not set(logs) & set(_keys(panel))
        assert saved == []
        assert panel.activity.rules.rules[-1].session
        assert "2 hidden: prefix 2" in panel.caption()[1]
        # R lists it as "this session"; removing it there undoes it.
        panel.table.focus()
        await pilot.press("R")
        await until(pilot, lambda: isinstance(app.screen, NoiseRulesModal))
        modal = app.screen
        assert modal.rules[-1]["session"] is True
        table = modal.query_one("#rules-table")
        assert "this session" in str(table.get_row_at(len(modal.rules) - 1)[3])
        modal.remove_rule(len(modal.rules) - 1)
        assert set(logs) <= set(_keys(panel))
        assert all(not r.get("session") for r in saved[-1]["tui.files_noise_rules"])
        await pilot.press("escape")
        await until(pilot, lambda: not isinstance(app.screen, NoiseRulesModal))
        # a: always -- a saved hide rule for just this file.
        panel.table.focus()
        panel.set_following(False)
        panel.table.move_cursor(row=panel.table.get_row_index(other))
        await pilot.press("M")
        await until(pilot, lambda: isinstance(app.screen, MuteRowModal))
        labels = [c[0] for c in app.screen.choices]
        assert labels == ["this folder", "this file"]  # the app root is no choice
        await pilot.press("down")
        await pilot.press("a")
        await until(pilot, lambda: not isinstance(app.screen, MuteRowModal))
        assert other not in _keys(panel)
        assert saved[-1]["tui.files_noise_rules"][-1] == {
            "action": "hide",
            "kind": "glob",
            "pattern": glob.escape(other),
            "enabled": True,
        }


async def test_W_shows_only_watched_files() -> None:
    get_forensic_service().add_spotlight_file(DB)
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(
            _items(_fse("FSE_CONTENT_MODIFIED", PREFS), _fse("FSE_CREATE_FILE", AAID)),
            now=T0,
        )
        panel.table.focus()
        await pilot.press("W")
        await settle(pilot)
        assert _keys(panel) == [DB]
        assert "watched only · W all" in panel.caption()[1]
        await pilot.press("W")
        await settle(pilot)
        assert set(_keys(panel)) == {DB, PREFS, AAID}
        assert "watched only" not in panel.caption()[1]
        get_forensic_service()._spotlight_files.clear()
        panel.watchlist.reload()
        panel.action_toggle_watched_only()
        assert panel.has_class("-empty")
        empty = str(panel.query_one("#files-empty").render())
        assert empty == "No watched files — w watches a row, W shows all"


async def test_the_ai_own_reads_are_no_app_activity(monkeypatch) -> None:
    from sandroid.ai import device_files as df

    monkeypatch.setattr(df, "_TOOL_READS", {})
    monkeypatch.setattr(df, "recorded_serial_cached", lambda ttl=1.0: "emu")
    now = datetime.now()
    ours = f'FSE_OPEN\t456\t"cat"\t{PREFS}'
    app = _Harness()
    async with app.run_test(size=(140, 30)) as pilot:
        panel = app.query_one(FilesPanel)
        panel.ingest(_items(_fse("FSE_CONTENT_MODIFIED", PREFS), ours, ours), now=now)
        _keys(panel)
        row = _row(panel, PREFS)
        assert str(panel._cells(row)[3]) == "3×"  # not read by the tool yet
        t = now.timestamp()
        df.note_tool_read(PREFS, "emu", t - 1, t + 1)
        _keys(panel)
        row = _row(panel, PREFS)
        assert str(panel._cells(row)[3]) == "1×"
        panel.activity.show_all = True  # the raw view shows o for OPENs
        _keys(panel)
        assert str(panel._cells(_row(panel, PREFS))[2]) == "M"
        summary = _plain(panel._inspector_for(row).tabs[0][1])
        by = next(line for line in summary.splitlines() if line.startswith("by"))
        assert "cat" not in by
        assert "456" not in by
        assert "o 2×" not in summary
        await pilot.pause()
