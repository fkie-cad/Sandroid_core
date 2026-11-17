"""Headless Textual Pilot smoke tests for the Runs lens (DiffsView).

No physical device and no full ``App(MainScreen, ...)`` needed: DiffsView
only talks to ``core/run_history.py`` (an on-disk JSON store, pointed at a
pytest ``tmp_path`` via ``RESULTS_PATH``) and
``sandroid.core.toolbox.Toolbox.device_name`` (which has a deterministic
default, ``"Pixel_6_Pro_API_31"``, even with no device connected). A minimal
single-widget host App is enough to exercise mount/compose, table rendering,
the gated auto-select/unread-marker rule for ``on_new_run``, the Inspector
content, compare, and the REVIEW scope (``v`` / ``L``) inside the full app.

Detail loading goes through a real background thread (``run_worker`` inside
``DiffsView._run_bg``, since ``is_running`` is True once mounted under
Pilot), so assertions that depend on it use ``_wait_for`` to poll with real
wall-clock pauses rather than assuming synchronous completion.
"""

from __future__ import annotations

import time

import pytest
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Input

from sandroid.core import run_history
from sandroid.tui.widgets.diffs_view import DiffsView

DEVICE = "Pixel_6_Pro_API_31"  # SessionStateService's deterministic default


@pytest.fixture(autouse=True)
def _isolated_results_path(tmp_path, monkeypatch):
    # run_history v2 resolves its storage root config-first
    # (get_config().paths.results_path), so setting RESULTS_PATH alone is no
    # longer enough. Pin the resolver itself (run_bundle shares it) instead
    # of faking get_config(), so the full SandroidTUI tests below still get
    # their real config.
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    monkeypatch.setattr(run_history, "_results_path", lambda: tmp_path)
    return tmp_path


def _make_record(
    run_id: str, label: str = "Run · 10:00", **overrides
) -> run_history.RunRecord:
    # v2 records carry an absolute in-bundle recording_path + bundle_dir.
    bundle_dir = f"/tmp/sandroid-test/runs/{run_id}"
    fields = {
        "schema_version": run_history.SCHEMA_VERSION,
        "run_id": run_id,
        "label": label,
        "recorded_at": "2026-07-21T10:00:00",
        "completed_at": "2026-07-21T10:05:00",
        "device_name": DEVICE,
        "recording_path": f"{bundle_dir}/recording.txt",
        "bundle_dir": bundle_dir,
        "duration": 10,
        "error": None,
        "changed_files": [{"/data/data/app/db.sqlite": ["- old", "+ new"]}],
        "new_files": ["/data/new.txt"],
        "deleted_files": [],
        "counts": {"changed": 1, "new": 1, "deleted": 0},
    }
    fields.update(overrides)
    return run_history.RunRecord(**fields)


def _save(run_id: str, **kwargs) -> run_history.RunRecord:
    record = _make_record(run_id, **kwargs)
    run_history.save_run(record)
    return record


class _DiffsHarness(App):
    """Minimal single-widget host app for DiffsView."""

    def compose(self) -> ComposeResult:
        yield DiffsView(id="files-diffs")


async def _wait_for(pilot, predicate, timeout: float = 3.0) -> None:
    """Poll ``predicate`` with real pauses until true or ``timeout`` elapses.

    Needed because run detail loading happens on a genuine background
    thread; a plain ``await pilot.pause()`` does not guarantee the thread
    has posted its result back yet.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await pilot.pause(0.02)
    assert predicate(), "condition was not met within timeout"


@pytest.mark.asyncio
async def test_empty_state_before_any_run() -> None:
    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await _wait_for(
            pilot, lambda: view._summaries == [] or view._detail_record is None
        )
        assert view.glance_fragment() == "Diffs — no runs yet"
        table = view.query_one("#runs-table", DataTable)
        assert table.row_count == 0
        assert not table.display
        assert view.query_one("#runs-empty").display


@pytest.mark.asyncio
async def test_mount_loads_existing_runs_and_selects_newest() -> None:
    _save("20260101_000000_aaaaaa", label="Run A")
    _save("20260101_000001_bbbbbb", label="Run B")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await _wait_for(pilot, lambda: view._detail_record is not None)

        assert view._selected_run_id == "20260101_000001_bbbbbb"
        assert view._detail_record.run_id == "20260101_000001_bbbbbb"
        assert view.glance_fragment() == "Diffs — 2 runs"

        table = view.query_one("#runs-table", DataTable)
        assert table.row_count == 2
        # Newest first, numbered chronologically (oldest = #1).
        first = table.get_row_at(0)
        assert str(first[0]) == "2"
        assert "Run B" in str(first[1])


@pytest.mark.asyncio
async def test_on_new_run_auto_selects_when_viewing_latest() -> None:
    _save("20260101_000000_aaaaaa", label="Run A")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await _wait_for(
            pilot, lambda: view._selected_run_id == "20260101_000000_aaaaaa"
        )

        _save("20260101_000001_bbbbbb", label="Run B")
        view.on_new_run("20260101_000001_bbbbbb")

        await _wait_for(
            pilot,
            lambda: view._detail_record is not None
            and view._detail_record.run_id == "20260101_000001_bbbbbb",
        )
        assert view._selected_run_id == "20260101_000001_bbbbbb"
        assert "20260101_000001_bbbbbb" not in view._unread_run_ids


@pytest.mark.asyncio
async def test_on_new_run_does_not_steal_selection_from_older_run() -> None:
    """Viewing an older run: a new run arrives as unread, selection untouched."""
    _save("20260101_000000_aaaaaa", label="Run A")
    _save("20260101_000001_bbbbbb", label="Run B")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await _wait_for(pilot, lambda: view._detail_record is not None)

        # Navigate to the OLDER run (not the latest).
        view._select_run("20260101_000000_aaaaaa")
        await _wait_for(
            pilot,
            lambda: view._detail_record is not None
            and view._detail_record.run_id == "20260101_000000_aaaaaa",
        )

        _save("20260101_000002_cccccc", label="Run C")
        view.on_new_run("20260101_000002_cccccc")
        await pilot.pause(0.05)

        # Selection must NOT have moved to the new run.
        assert view._selected_run_id == "20260101_000000_aaaaaa"
        assert "20260101_000002_cccccc" in view._unread_run_ids
        assert "unread" in view.glance_fragment()


@pytest.mark.asyncio
async def test_new_run_cursor_stays_on_older_run_row() -> None:
    """The table is newest-first: a new row on top must not move the cursor
    off the older run the user is looking at.
    """
    _save("20260101_000000_aaaaaa", label="Run A")
    _save("20260101_000001_bbbbbb", label="Run B")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        table = view.query_one("#runs-table", DataTable)
        await _wait_for(pilot, lambda: view._detail_record is not None)
        view.focus()
        await pilot.press("down")
        await _wait_for(
            pilot, lambda: view._selected_run_id == "20260101_000000_aaaaaa"
        )
        _save("20260101_000002_cccccc", label="Run C")
        view.on_new_run("20260101_000002_cccccc")
        await pilot.pause(0.1)
        assert table.row_count == 3
        assert view._cursor_run_id() == "20260101_000000_aaaaaa"
        assert "●" in str(table.get_row_at(0)[1])


@pytest.mark.asyncio
async def test_rename_run_persists_via_run_history() -> None:
    _save("20260101_000000_aaaaaa", label="Run A")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await _wait_for(pilot, lambda: view._detail_record is not None)

        # Exercise the same worker path action_rename_run() would use after
        # the InputModal resolves, without driving the modal's keystrokes.
        view._rename_run_bg("20260101_000000_aaaaaa", "Renamed run")
        await _wait_for(
            pilot,
            lambda: run_history.load_run("20260101_000000_aaaaaa").label
            == "Renamed run",
        )
        assert view._current_label("20260101_000000_aaaaaa") == "Renamed run"


class _RPHarness(App):
    """Host app with *app-level* r/p bindings, like ``SandroidTUI``.

    Record/Play used to be panel-scoped to the Diffs view, which made them
    undiscoverable (``r`` on the main screen did nothing). They are global
    app bindings now; DiffsView no longer declares its own r/p.
    """

    BINDINGS = [("r", "record", "Record"), ("p", "play", "Play")]

    def __init__(self) -> None:
        super().__init__()
        self.record_calls = 0
        self.play_calls = 0

    def compose(self) -> ComposeResult:
        yield Input(id="other-widget")
        yield DiffsView(id="files-diffs")

    def action_record(self) -> None:
        self.record_calls += 1

    def action_play(self) -> None:
        self.play_calls += 1


def test_diffs_view_does_not_shadow_global_record_play() -> None:
    keys = {(b[0] if isinstance(b, tuple) else b.key) for b in DiffsView.BINDINGS}
    assert "r" not in keys
    assert "p" not in keys


@pytest.mark.asyncio
async def test_rp_reach_app_from_diffs_but_not_from_text_input() -> None:
    """r/p fire the app actions with the Diff panel focused.

    Typing them into an Input still just types (Input consumes printable keys).
    """
    app = _RPHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await _wait_for(pilot, lambda: view._summaries is not None)

        app.query_one("#other-widget", Input).focus()
        await pilot.pause()
        await pilot.press("r", "p")
        await pilot.pause()
        assert app.record_calls == 0
        assert app.play_calls == 0
        assert app.query_one("#other-widget", Input).value == "rp"

        view.focus()
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        await pilot.press("p")
        await pilot.pause()
        assert app.record_calls == 1
        assert app.play_calls == 1


@pytest.mark.asyncio
async def test_delete_run_removes_it_and_selects_remaining() -> None:
    _save("20260101_000000_aaaaaa", label="Run A")
    _save("20260101_000001_bbbbbb", label="Run B")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await _wait_for(pilot, lambda: view._detail_record is not None)
        assert view._selected_run_id == "20260101_000001_bbbbbb"

        view._delete_run_bg("20260101_000001_bbbbbb")
        await _wait_for(
            pilot,
            lambda: view._selected_run_id == "20260101_000000_aaaaaa",
        )

        with pytest.raises(run_history.RunHistoryError):
            run_history.load_run("20260101_000001_bbbbbb")
        assert len(view._summaries) == 1


# --------------------------------------------------------------------------
# Runs lens: table facts, Inspector, compare
# --------------------------------------------------------------------------


def _write_results(run_id: str, *, steps: int = 0, replays: int = 1) -> None:
    """A run folder's ``sandroid.json`` like ``run_report.finalize_run``'s."""
    import json

    run_dir = run_history.run_dir_for_scope(run_id)
    doc = {
        "Network": ["app-measurement.com", "graph.facebook.com", "api.fit.pro"],
        "Run Metadata": {
            "run_settings": {
                "number_of_runs": replays,
                "replay_settle_seconds": 8,
                "network_reset_after_snapshot": "airplane",
                "capture_network": True,
            }
        },
    }
    if steps:
        doc["Run Errors"] = {
            "status": "completed with errors",
            "fatal": None,
            "steps": [
                {"step": f"Step{i}", "run": 1, "error": "boom"} for i in range(steps)
            ],
        }
    (run_dir / run_history.RESULTS_JSON_NAME).write_text(json.dumps(doc))


@pytest.mark.asyncio
async def test_table_row_shows_changes_errors_and_batch() -> None:
    _save("20260101_000000_aaaaaa", label="Consent · accept")
    _write_results("20260101_000000_aaaaaa", replays=3)
    _save("20260101_000001_bbbbbb", label="Consent · refuse")
    _write_results("20260101_000001_bbbbbb", steps=2)
    _save("20260101_000002_cccccc", label="Workout", error="Device disconnected")

    app = _DiffsHarness()
    async with app.run_test(size=(140, 20)) as pilot:
        view = app.query_one(DiffsView)
        table = view.query_one("#runs-table", DataTable)
        await _wait_for(pilot, lambda: len(view._facts) == 3)
        await pilot.pause()
        rows = [[str(c) for c in table.get_row_at(i)] for i in range(3)]
        assert [r[0] for r in rows] == ["3", "2", "1"]
        assert "✕ aborted" in rows[0][4]
        assert "2 files · 3 hosts" in rows[1][4]
        assert "⚠ 2 errors" in rows[1][4]
        assert "×3" in rows[2][3]
        assert len(table.columns) == 5


@pytest.mark.asyncio
async def test_inspector_content_has_summary_changes_report_tabs() -> None:
    from rich.console import Console

    from sandroid.core import run_report

    run_id = "20260101_000000_aaaaaa"
    _save(run_id, label="Consent · refuse")
    _write_results(run_id, steps=1)
    run_report.write_hash_manifest(run_history.run_dir_for_scope(run_id))

    def text(sections) -> str:
        console = Console(width=200, record=True)
        for heading, body in sections:
            console.print(heading)
            console.print(body)
        return console.export_text()

    app = _DiffsHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        view = app.query_one(DiffsView)
        await _wait_for(
            pilot, lambda: view._detail_record is not None and run_id in view._facts
        )
        view.inspect_selected()  # starts the evidence check
        await _wait_for(pilot, lambda: view._evidence.get(run_id) == "verified")
        content = view.inspect_selected()
        assert content.key == ("run", run_id)
        assert content.title == "Consent · refuse"
        assert [name for name, _ in content.tabs] == ["Summary", "Changes", "Report"]

        summary, changes, report = (text(s) for _, s in content.tabs)
        assert "8 s after replay" in summary
        assert "airplane" in summary
        assert "Step0" in summary  # the run's step error
        assert "verified" in summary
        assert "/data/data/app/db.sqlite" in changes
        assert "/data/new.txt" in changes
        assert "Hosts (3)" in changes
        assert str(run_history.run_dir_for_scope(run_id)) in report


def test_compare_sections_list_files_only_in_each_run() -> None:
    a = _make_record(
        "20260101_000000_aaaaaa",
        changed_files=[{"/data/shared.db": ["x"]}],
        new_files=["/data/only_a.txt"],
    )
    b = _make_record(
        "20260101_000001_bbbbbb",
        changed_files=[{"/data/shared.db": ["y"]}],
        new_files=["/data/only_b.txt", "/data/also_b.txt"],
    )
    sections = DiffsView.compare_sections(a, b, numbers=(1, 2))
    head = str(sections[0][1])
    assert "2 files only in #2" in head
    assert "1 only in #1" in head
    assert "1 in both" in head
    by_title = dict(sections[1:])
    assert "only_b.txt" in str(by_title["Only in #2 · Run · 10:00"])
    assert "only_a.txt" in str(by_title["Only in #1 · Run · 10:00"])


# --------------------------------------------------------------------------
# Full app: Enter → Inspector, REVIEW scope (v / L), REC forces LIVE
# --------------------------------------------------------------------------


async def _settle(pilot, n: int = 4) -> None:
    for _ in range(n):
        await pilot.pause(0.05)


async def _boot_runs_lens(pilot, app, labels: list[str]):
    """Boot SandroidTUI, save runs for its device, land on the Runs lens."""
    await _settle(pilot, 8)
    if type(app.screen).__name__ != "MainScreen":
        await pilot.press("enter")  # first-run welcome modal
        await _settle(pilot, 4)
    ms = app.screen
    view = ms.query_one("#runs-panel", DiffsView)
    device = view._current_device_name()
    ids = [f"2026010{i}_100000_00000{i}" for i in range(len(labels))]
    for run_id, label in zip(ids, labels, strict=True):
        _save(run_id, label=label, device_name=device)
    await pilot.press("4")
    await _settle(pilot)
    view._reload_index()
    view.focus()
    await _wait_for(pilot, lambda: view._detail_record is not None)
    return ms, view, ids


def _sandroid_app():
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


@pytest.mark.asyncio
async def test_enter_inspects_run_and_v_reviews_it_until_l() -> None:
    app = _sandroid_app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, view, ids = await _boot_runs_lens(
            pilot, app, ["Consent · accept", "Consent · refuse"]
        )
        newest = ids[-1]
        await pilot.press("enter")
        await _settle(pilot)
        assert ms.inspector_is_open
        assert ms.inspector_content.key == ("run", newest)
        assert [t for t, _ in ms.inspector_content.tabs] == [
            "Summary",
            "Changes",
            "Report",
        ]
        # The open Inspector follows the cursor.
        await pilot.press("down")
        await _wait_for(pilot, lambda: ms.inspector_content.key == ("run", ids[0]))
        await pilot.press("escape")
        await _settle(pilot)

        assert ms.check_action("back_to_live", ()) is False
        await pilot.press("v")
        await _settle(pilot)
        assert ms.scope == run_history.scope_for_run(ids[0])
        assert ms.query_one("#shell-header").pill_text == "◆ REVIEW Consent · accept"
        assert view._scope_run_id == ids[0]
        assert "◆" in str(view.query_one("#runs-table").get_row_at(1)[1])
        assert ms.check_action("back_to_live", ()) is True

        await pilot.press("3")  # another lens: L works from there too
        await _settle(pilot)
        await pilot.press("L")
        await _settle(pilot)
        assert ms.scope is None
        assert ms.query_one("#shell-header").pill_text == "● LIVE"

        await pilot.press("4")
        await _settle(pilot)
        await pilot.press("v")
        await _settle(pilot)
        assert ms.scope is not None
        await pilot.press("v")  # same run again: back to LIVE
        await _settle(pilot)
        assert ms.scope is None


@pytest.mark.asyncio
async def test_recording_or_replay_forces_live_scope() -> None:
    app = _sandroid_app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, _view, ids = await _boot_runs_lens(pilot, app, ["Run A"])
        for flag in ("recording", "replaying"):
            ms.set_scope(run_history.scope_for_run(ids[0]), "Run A")
            await _settle(pilot)
            assert ms.scope is not None
            app._set_status_bar_mode(**{flag: True})
            await _settle(pilot)
            assert ms.scope is None
            app._set_status_bar_mode(**{flag: False})


@pytest.mark.asyncio
async def test_delete_key_confirms_and_leaves_review_scope() -> None:
    app = _sandroid_app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, view, ids = await _boot_runs_lens(pilot, app, ["Run A", "Run B"])
        await pilot.press("v")
        await _settle(pilot)
        assert ms.scope == run_history.scope_for_run(ids[-1])

        await pilot.press("delete")
        await _wait_for(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        await pilot.press("n")  # No: nothing happens
        await _settle(pilot)
        assert run_history.load_run(ids[-1]).label == "Run B"

        await pilot.press("delete")
        await _wait_for(pilot, lambda: type(app.screen).__name__ == "ConfirmModal")
        await pilot.press("y")
        await _wait_for(pilot, lambda: len(view._summaries) == 1)
        with pytest.raises(run_history.RunHistoryError):
            run_history.load_run(ids[-1])
        assert ms.scope is None


@pytest.mark.asyncio
async def test_new_run_after_play_lands_in_runs_lens_and_is_selected() -> None:
    app = _sandroid_app()
    async with app.run_test(size=(160, 45)) as pilot:
        ms, view, _ids = await _boot_runs_lens(pilot, app, ["Run A"])
        await pilot.press("1")
        await _settle(pilot)
        ms.open_files_tab("files-diffs")  # what Play-press does (legacy id)
        await _settle(pilot)
        assert ms.active_lens == "runs"

        new_id = "20260201_100000_ffffff"
        _save(new_id, label="Run B", device_name=view._current_device_name())
        app._notify_diffs_new_run(new_id)
        await _wait_for(pilot, lambda: view._selected_run_id == new_id)
        assert view._cursor_run_id() == new_id
        assert view.query_one("#runs-table").row_count == 2
