"""Review modal (``tui/modals/review_modal.py``) and the Rewind controller.

Pilot tests use condition waits (``pilot_helpers``) only. The controller
tests drive ``RecordingController`` with fakes for the device side.
"""

from __future__ import annotations

from typing import Any

import pytest
from pilot_helpers import settle, until
from textual.app import App
from textual.widgets import Button, SelectionList, Static

from sandroid.core import rewind
from sandroid.tui.modals.review_modal import ReviewModal


class FakeController:
    def __init__(self, problem: str | None = None) -> None:
        self.problem = problem
        self.is_replaying = False
        self.selected: list[tuple[str, bool]] = []
        self.flows: list[tuple[dict, bool]] = []
        self.rewinds: list[bool] = []
        self.stopped = False
        self.closed = False
        self.names: list[str] = []

    def rewind_problem(self, rec=None):
        return self.problem

    def select_file(self, path, on):
        self.selected.append((path, on))

    def select_flow(self, row, on):
        self.flows.append((row, on))

    def start_rewind(self, replay):
        self.rewinds.append(replay)
        return True

    def stop_rewind(self):
        self.stopped = True
        return True

    def review_closed(self, modal):
        self.closed = True

    def rename(self, name):
        self.names.append(name)

    def set_pinned(self, pinned):
        pass

    def results(self, rec):
        return {"files": [], "flows": []}

    def run_requests(self, rec):
        return {"Your run": rec.requests}


def _rec(requests=True, emulator=True) -> rewind.Recording:
    rec = rewind.Recording(
        rec_id="rec-1",
        name="Recording 13:36",
        pkg="org.x",
        serial="emulator-5560",
        emulator=emulator,
        start_point={"name": "sandroid_rec_20261120_133600", "saved_ok": True},
        started=100.0,
        stopped=114.0,
    )
    rec.changed = [
        {"path": "/data/data/org.x/databases/c.sqlite", "state": "changed", "size": 96000},
        {"path": "/data/data/org.x/files/new.json", "state": "new", "size": 10},
    ]  # fmt: skip
    if requests:
        rec.requests = rewind.requests_in(
            [
                {"src": "net", "kind": "flow", "seq": 5, "ref": {"id": "f5"},
                 "data": {"method": "POST", "host": "c.example", "path": "/v1", "status": 200}},
            ]
        )  # fmt: skip
    return rec


class Host(App):
    def __init__(self, modal: ReviewModal) -> None:
        super().__init__()
        self.modal = modal

    def on_mount(self) -> None:
        self.push_screen(self.modal)


async def test_review_lists_files_and_requests_and_selecting_calls_the_controller():
    ctl = FakeController()
    modal = ReviewModal(_rec(), ctl)
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        files = modal.query_one("#review-files", SelectionList)
        assert files.option_count == 2
        reqs = modal.query_one("#review-requests", SelectionList)
        assert reqs.display
        assert reqs.option_count == 1
        hint = str(modal.query_one("#requests-hint", Static).render())
        assert "compared after Rewind + Replay" in hint
        files.focus()
        files.highlighted = 0
        await pilot.press("space")  # a user toggle (not a programmatic select)
        await until(pilot, lambda: ctl.selected)
        assert ctl.selected == [("/data/data/org.x/databases/c.sqlite", True)]
        reqs.focus()
        reqs.highlighted = 0
        await pilot.press("space")
        await until(pilot, lambda: ctl.flows)
        assert ctl.flows[0][0]["flow_id"] == "f5"


async def test_review_shows_nothing_for_requests_without_network_data():
    modal = ReviewModal(_rec(requests=False), FakeController())
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        await settle(pilot)
        assert not modal.query_one("#review-requests", SelectionList).display
        assert not modal.query_one("#requests-title", Static).display


async def test_rewind_buttons_disabled_on_a_physical_device():
    problem = "Rewind needs an emulator: physical devices have no snapshots."
    modal = ReviewModal(_rec(emulator=False), FakeController(problem))
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        await settle(pilot)
        assert modal.query_one("#rewind", Button).disabled
        assert modal.query_one("#rewind-replay", Button).disabled
        shown = str(modal.query_one("#review-problem", Static).render())
        assert "physical devices have no snapshots" in shown


async def test_buttons_start_rewind_and_esc_closes():
    ctl = FakeController()
    modal = ReviewModal(_rec(), ctl)
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        modal.query_one("#rewind", Button).press()
        await until(pilot, lambda: ctl.rewinds)
        modal.query_one("#rewind-replay", Button).press()
        await until(pilot, lambda: len(ctl.rewinds) == 2)
        assert ctl.rewinds == [False, True]
        await pilot.press("escape")
        await until(pilot, lambda: app.screen is not modal)
        assert ctl.closed


async def test_esc_while_a_rewind_runs_asks_before_stopping():
    from sandroid.tui.modals import ConfirmModal

    ctl = FakeController()
    ctl.is_replaying = True
    modal = ReviewModal(_rec(), ctl)
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        await pilot.press("escape")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("escape")  # Continue
        await until(pilot, lambda: app.screen is modal)
        assert not ctl.stopped
        await pilot.press("escape")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("y")
        await until(pilot, lambda: ctl.stopped)
        assert app.screen is modal


# ---------------------------------------------------------------------------
# controller (no widgets)
# ---------------------------------------------------------------------------


class FakeView:
    def __init__(self) -> None:
        self.watched: list[str] = []
        self.pulls: list[tuple] = []

    def add_path(self, path, *, pull_first=True):
        self.watched.append(path)
        return True

    def pull_role(self, path, role, rec_id, run):
        self.pulls.append((path, role, run))
        return "v001_10-00-00", None


@pytest.fixture
def controller(tmp_path, monkeypatch):
    from sandroid.tui.controllers.recording_controller import RecordingController

    monkeypatch.setattr(rewind, "recordings_root", lambda: tmp_path)
    view = FakeView()
    spawned: list[Any] = []
    ctl = RecordingController(watchlist=lambda: view)
    ctl._spawn = lambda fn, name: (spawned.append(name), fn())[1]
    ctl.view = view
    ctl.spawned = spawned
    return ctl


def test_select_file_watches_and_pulls_after(controller):
    rec = _rec()
    controller._rec = rec
    path = rec.changed[0]["path"]
    controller.select_file(path, True)
    assert controller.view.watched == [path]
    assert controller.view.pulls == [(path, "after", 1)]
    assert rec.role_version(path, "after") == "v001_10-00-00"
    controller.select_file(path, False)
    assert rec.selected == []


def test_select_after_a_rewind_does_not_pull_after(controller):
    rec = _rec()
    rec.runs = [{"n": 2, "kind": "rewind"}]
    controller._rec = rec
    controller.select_file(rec.changed[0]["path"], True)
    assert controller.view.pulls == []
    assert rec.selected == [rec.changed[0]["path"]]


def test_rewind_problems_in_plain_words(controller, monkeypatch):
    assert controller.rewind_problem() == "Nothing recorded yet."
    controller._rec = _rec(emulator=False)
    assert "physical devices have no snapshots" in controller.rewind_problem()
    rec = _rec()
    rec.start_point = {"name": None, "saved_ok": False}
    controller._rec = rec
    assert "start point is gone" in controller.rewind_problem()
    controller._rec = _rec()
    controller._state = "recording"
    assert "Stop the recording first" in controller.rewind_problem()
    controller._state = "idle"
    device = type("D", (), {"serial": "emulator-5562", "is_emulator": True})()
    monkeypatch.setattr(
        type(controller), "_active_device", staticmethod(lambda: device)
    )
    assert "emulator-5560" in controller.rewind_problem()


def test_start_rewind_refuses_while_recording(controller):
    controller._rec = _rec()
    controller._state = "recording"
    assert controller.start_rewind(replay=False) is False
    assert controller.spawned == []


def test_start_point_replaced_unless_pinned(controller, monkeypatch):
    deleted: list[tuple] = []

    class Emu:
        def delete_snapshot(self, name, serial=None):
            deleted.append((name, serial))
            return True

    from sandroid import services

    monkeypatch.setattr(services, "get_emulator_service", lambda: Emu())
    old, new = _rec(), _rec()
    new.rec_id = "rec-2"
    new.start_point = {"name": "sandroid_rec_20261120_140000", "saved_ok": True}
    old.start_point["pinned"] = True
    controller._replace_start_point(old, new)
    assert deleted == []
    old.start_point["pinned"] = False
    controller._replace_start_point(old, new)
    assert deleted == [("sandroid_rec_20261120_133600", "emulator-5560")]
    assert old.start_point_name is None
    # Never a name Sandroid did not make.
    other = _rec()
    other.start_point = {"name": "clean_8g", "saved_ok": True}
    controller._replace_start_point(other, new)
    assert len(deleted) == 1


def test_failed_start_point_records_nothing(controller, monkeypatch):
    from sandroid import services

    class Emu:
        def create_snapshot(self, name, serial=None):
            return False

    monkeypatch.setattr(services, "get_emulator_service", lambda: Emu())
    monkeypatch.setattr(rewind, "disk_problem", lambda _f: None)
    monkeypatch.setattr(controller, "_active_device_name", lambda: None)
    rec = _rec()
    controller._state = "saving"
    result = controller._start_worker(rec)
    assert result["success"] is False
    assert result["message"].startswith("Could not save the start point")
    assert controller.state == "idle"
    assert controller.recording is None


def test_monitor_is_stopped_before_the_load_and_its_config_returned(controller):
    from types import SimpleNamespace

    stopped: list[str] = []
    config = SimpleNamespace(mode="path")
    tasks = SimpleNamespace(
        is_running=lambda name: True,
        get_task=lambda name: SimpleNamespace(instance=SimpleNamespace(config=config)),
        stop=lambda name: stopped.append(name),
    )
    controller._get_task_service = lambda: tasks
    assert controller._stop_monitor_before_revert() is config
    assert stopped == ["monitor"]
    tasks.is_running = lambda name: False
    assert controller._stop_monitor_before_revert() is None


def test_monitor_restarts_after_a_rewind_or_is_offered(controller):
    offered: list = []
    controller._on_monitor_resume_available = offered.append
    controller._resume_monitor = lambda cfg: True
    controller._resume_after("cfg")
    assert offered == []
    controller._resume_monitor = lambda cfg: False
    controller._resume_after("cfg")
    assert offered == ["cfg"]
