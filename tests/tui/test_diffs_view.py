"""Headless Textual Pilot smoke tests for the Diffs sub-tab (DiffsView).

No physical device and no full ``App(MainScreen, ...)`` needed: DiffsView
only talks to ``core/run_history.py`` (an on-disk JSON store, pointed at a
pytest ``tmp_path`` via ``RESULTS_PATH``) and
``sandroid.core.toolbox.Toolbox.device_name`` (which has a deterministic
default, ``"Pixel_6_Pro_API_31"``, even with no device connected). A minimal
single-widget host App is enough to exercise mount/compose, rail rendering,
the gated auto-select/unread-marker rule for ``on_new_run``, and the rail
collapse toggle.

Detail loading goes through a real background thread (``run_worker`` inside
``DiffsView._run_bg``, since ``is_running`` is True once mounted under
Pilot), so assertions that depend on it use ``_wait_for`` to poll with real
wall-clock pauses rather than assuming synchronous completion.
"""

from __future__ import annotations

import time

import pytest
from textual.app import App, ComposeResult
from textual.widgets import OptionList

from sandroid.core import run_history
from sandroid.tui.widgets.diffs_view import DiffsView

DEVICE = "Pixel_6_Pro_API_31"  # SessionStateService's deterministic default


@pytest.fixture(autouse=True)
def _isolated_results_path(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    return tmp_path


def _make_record(
    run_id: str, label: str = "Run · 10:00", **overrides
) -> run_history.RunRecord:
    fields = {
        "schema_version": run_history.SCHEMA_VERSION,
        "run_id": run_id,
        "label": label,
        "recorded_at": "2026-07-21T10:00:00",
        "completed_at": "2026-07-21T10:05:00",
        "device_name": DEVICE,
        "recording_path": "/tmp/recording.txt",
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
        option_list = view.query_one("#runs-list", OptionList)
        assert option_list.option_count == 1  # the "no runs yet" placeholder


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

        option_list = view.query_one("#runs-list", OptionList)
        assert option_list.option_count == 2


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
async def test_toggle_rail_collapses_and_shows_breadcrumb() -> None:
    _save("20260101_000000_aaaaaa", label="Run A")

    app = _DiffsHarness()
    async with app.run_test() as pilot:
        view = app.query_one(DiffsView)
        await _wait_for(pilot, lambda: view._detail_record is not None)

        rail = view.query_one("#diffs-rail")
        assert "-collapsed" not in rail.classes

        view.action_toggle_rail()
        await pilot.pause()

        assert "-collapsed" in rail.classes
        breadcrumb = view.query_one("#diffs-breadcrumb")
        assert "-visible" in breadcrumb.classes

        view.action_toggle_rail()
        await pilot.pause()
        assert "-collapsed" not in rail.classes


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
