"""Review modal (``tui/modals/review_modal.py``) and the Rewind controller.

Pilot tests use condition waits (``pilot_helpers``) only. The controller
tests drive ``RecordingController`` with fakes for the device side.
"""

from __future__ import annotations

import json
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
    rec = _rec()
    rec.selected = [rec.changed[0]["path"]]
    modal = ReviewModal(rec, ctl)
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

    def is_watched(self, path):
        return path in self.watched

    def unwatch(self, path):
        self.watched.remove(path)
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
    states: list[tuple[str, str]] = []
    controller._review_file_state = lambda path, text: states.append((path, text))
    path = rec.changed[0]["path"]
    controller.select_file(path, True)
    assert controller.view.pulls == []
    assert rec.selected == [path]
    assert rec.late_selected == [path]
    assert states == [(path, "no After from your run: selected after a Rewind")]
    # its result says so in plain words
    res = rewind.file_result(rec, path)
    assert res.late
    assert rewind.LATE_WORDS in rewind.result_lines(res)


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


# ---------------------------------------------------------------------------
# edge cases (review round)
# ---------------------------------------------------------------------------


async def test_enter_in_the_name_field_never_starts_a_rewind():
    from textual.widgets import Input

    ctl = FakeController()
    modal = ReviewModal(_rec(), ctl)
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        name = modal.query_one("#review-name", Input)
        name.focus()
        await until(pilot, lambda: app.focused is name)
        await pilot.press("x", "enter")
        await settle(pilot)
        assert ctl.rewinds == []
        assert ctl.names
        assert app.screen is modal


async def test_review_opens_on_the_file_list_so_q_quits_and_keeps_the_name():
    """R1-B2: Review opened in the Name field with its text selected, so q
    renamed the recording to "q" and never reached the quit dialog.
    """
    from textual.widgets import Input

    quits: list[bool] = []

    class QuitHost(Host):
        def action_request_quit(self) -> None:
            quits.append(True)

    ctl = FakeController()
    modal = ReviewModal(_rec(), ctl)
    app = QuitHost(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        files = modal.query_one("#review-files", SelectionList)
        await until(pilot, lambda: app.focused is files)
        await pilot.press("q")
        await until(pilot, lambda: quits)
        name = modal.query_one("#review-name", Input)
        assert name.value == "Recording 13:36"
        assert set(ctl.names) <= {"Recording 13:36"}  # never renamed to "q"
        await pilot.press("tab")  # the Name field is still reachable
        await settle(pilot)
        assert app.focused is not files


async def test_esc_on_the_stop_question_keeps_the_rewind_running():
    from sandroid.tui.modals import ConfirmModal

    ctl = FakeController()
    ctl.is_replaying = True
    modal = ReviewModal(_rec(), ctl)
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        await settle(pilot)
        assert modal.query_one("#rewind", Button).disabled  # running
        modal.query_one("#close", Button).press()  # Close behaves like Esc
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        assert hasattr(type(app.screen), "action_cancel")
        await pilot.press("escape")
        await until(pilot, lambda: app.screen is modal)
        assert not ctl.stopped
        assert not ctl.closed


async def test_huge_diff_lines_are_clipped_in_the_review():
    from sandroid.tui.modals.review_modal import _clip_lines

    text = "+ " + "x" * 200_000 + "\n" + "\n".join(f"+ {i}" for i in range(500))
    clipped = _clip_lines(text)
    assert len(clipped) < 5_000
    assert clipped.splitlines()[-1].startswith("…")

    class Results(FakeController):
        def results(self, rec):
            res = rewind.FileResult(rec.selected[0], "v1", "v2", "v3",
                                    text, text, rewind.DIFFERENT)  # fmt: skip
            res.only_run = [text.splitlines()[0]]
            return {"files": [res], "flows": []}

    rec = _rec()
    rec.selected = [rec.changed[0]["path"]]
    rec.runs = [{"n": 2, "kind": "rewind-replay", "result": "replayed"}]
    modal = ReviewModal(rec, Results())
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        await until(pilot, lambda: modal.query("#review-results Static"))
        longest = max(
            len(str(s.render())) for s in modal.query("#review-results Static")
        )
        assert longest < 20_000


def test_tls_failure_rows_read_as_plain_words():
    rec = _rec(requests=False)
    rec.requests = rewind.requests_in(
        [{"src": "net", "kind": "tls-fail", "seq": 3, "data": {"host": "h"}}]
    )
    assert rec.requests[0]["kind"] == "tls-fail"
    assert rewind.request_text(rec.requests[0]) == "TLS failed  h"


def _warnings(controller) -> list[str]:
    out: list[str] = []
    controller._log_warning = out.append
    return out


def test_r_during_a_rewind_or_while_stopping_starts_nothing(controller):
    warned = _warnings(controller)
    controller._rec = _rec()
    for state in ("running", "stopping", "saving"):
        controller._state = state
        assert controller.toggle_recording() is False
        assert controller.state == state
    assert controller.spawned == []
    assert "A rewind is still running" in warned[0]


def test_rewind_problem_while_recording_says_stop_first(controller):
    old = _rec()
    controller._rec = old
    controller._state = "saving"
    assert "Stop the recording first" in controller.rewind_problem()
    # Once recording, the current recording has not stopped yet.
    new = _rec()
    new.stopped = None
    controller._rec = new
    controller._state = "recording"
    assert "Stop the recording first" in controller.rewind_problem()


def test_p_during_recording_does_not_open_review(controller):
    pushed: list = []
    controller._push_modal = lambda modal, cb: pushed.append(modal)
    rec = _rec()
    rec.stopped = None
    controller._rec = rec
    controller._state = "recording"
    assert controller.open_review() is False
    assert pushed == []


def _emu(created: list, deleted: list, ok: bool = True):
    class Emu:
        def create_snapshot(self, name, serial=None):
            created.append((name, serial))
            return ok

        def delete_snapshot(self, name, serial=None):
            deleted.append((name, serial))
            return True

    return Emu()


def _start_fakes(controller, monkeypatch, created, deleted, capture_error=None):
    from sandroid import services

    monkeypatch.setattr(
        services, "get_emulator_service", lambda: _emu(created, deleted)
    )
    monkeypatch.setattr(rewind, "disk_problem", lambda _f: None)
    monkeypatch.setattr(controller, "_active_device_name", lambda: None)
    monkeypatch.setattr(controller, "_begin_capture", lambda rec: capture_error)
    monkeypatch.setattr(controller, "_start_ticker", lambda rec: None)


def test_physical_device_records_without_a_start_point(controller, monkeypatch):
    created: list = []
    deleted: list = []
    _start_fakes(controller, monkeypatch, created, deleted)
    previous = _rec()  # an emulator recording with a start point
    controller._rec = previous
    rec = _rec(emulator=False)
    rec.rec_id = "rec-2"
    rec.start_point = {}
    rec.stopped = None
    controller._state = "saving"
    result = controller._start_worker(rec)
    assert result["success"] is True
    assert result["start_point"] is None
    assert created == []
    assert deleted == []  # the old start point is kept
    assert controller.state == "recording"
    assert controller.recording is rec
    rec.stopped = 2.0
    controller._state = "idle"
    assert "physical devices have no snapshots" in controller.rewind_problem()


def test_failed_capture_deletes_the_new_start_point(controller, monkeypatch):
    created: list = []
    deleted: list = []
    _start_fakes(controller, monkeypatch, created, deleted,
                 capture_error="Could not start the recording: no input.")  # fmt: skip
    previous = _rec()
    controller._rec = previous
    rec = _rec()
    rec.rec_id = "rec-2"
    rec.start_point = {}
    controller._state = "saving"
    result = controller._start_worker(rec)
    assert result["success"] is False
    assert controller.state == "idle"
    assert controller.recording is previous
    assert len(created) == 1
    # Only the new, unused start point goes; the previous one stays.
    assert deleted == [created[0]]
    assert previous.start_point_name == "sandroid_rec_20261120_133600"


def test_a_new_recording_closes_the_old_review(controller, monkeypatch):
    created: list = []
    deleted: list = []
    _start_fakes(controller, monkeypatch, created, deleted)

    class OldReview:
        dismissed = False
        rec = None

        def close_for_new_recording(self):
            self.dismissed = True

    old = OldReview()
    controller._review = old
    controller._rec = _rec()
    rec = _rec()
    rec.rec_id = "rec-2"
    rec.start_point = {}
    controller._state = "saving"
    assert controller._start_worker(rec)["success"] is True
    assert old.dismissed
    assert controller._review is None


def test_open_review_replaces_a_review_of_an_older_recording(controller):
    pushed: list = []
    controller._push_modal = lambda modal, cb: pushed.append(modal)
    first = _rec()
    controller._rec = first
    assert controller.open_review() is True
    second = _rec()
    second.rec_id = "rec-2"
    controller._rec = second
    assert controller.open_review() is True
    assert [m.rec for m in pushed] == [first, second]
    assert controller._review is pushed[-1]


def test_late_writes_wait_out_a_rewind_or_a_new_recording(controller, monkeypatch):
    calls: list = []
    monkeypatch.setattr(controller, "_collect_changes",
                        lambda rec, name: calls.append(name))  # fmt: skip
    rec = _rec()
    controller._rec = rec
    for state in ("running", "saving"):
        controller._state = state
        controller._late_writes(rec, wait=0)
    assert calls == []
    controller._state = "idle"
    controller._late_writes(rec, wait=0)
    assert calls == ["files_late.tsv"]


def _capture_fakes(controller, monkeypatch, lists):
    from types import SimpleNamespace

    import sandroid.tui.utils.recording_wrapper as rw

    class Wrapper:
        def __init__(self, **_kw):
            pass

        def start(self):
            return True

        def stop(self):
            return None

    monkeypatch.setattr(rw, "RecordingWrapper", Wrapper)
    monkeypatch.setattr(type(controller), "_wait_tracking",
                        staticmethod(lambda serial, timeout=5.0: True))  # fmt: skip
    monkeypatch.setattr(type(controller), "_emit_phase",
                        staticmethod(lambda *a, **k: 7))  # fmt: skip
    controller._get_task_service = lambda: SimpleNamespace(
        register=lambda **_k: None, unregister=lambda _n: None
    )
    monkeypatch.setattr(rewind, "timeline_size", lambda: 0)
    monkeypatch.setattr(rewind, "lines_between", lambda *a, **k: [])
    monkeypatch.setattr(controller, "_file_list", lambda rec, name: lists.pop(0))
    monkeypatch.setattr(type(controller), "_shell",
                        staticmethod(lambda serial: lambda cmd: "Asia/Tokyo\n"))  # fmt: skip


def test_late_list_is_diffed_against_its_own_start_list(controller, monkeypatch):
    F = rewind.FileFact
    a_start = {"/data/data/org.x/a": F(1, 1, "t1")}
    b_start = {"/data/data/org.x/a": F(2, 2, "t2"), "/data/data/org.x/b": F(1, 1, "t")}
    a_late = {"/data/data/org.x/a": F(2, 2, "t2"), "/data/data/org.x/b": F(1, 1, "t")}
    lists = [a_start, b_start, a_late]
    _capture_fakes(controller, monkeypatch, lists)
    a, b = _rec(), _rec()
    b.rec_id = "rec-2"
    assert controller._begin_capture(a) is None
    assert controller._begin_capture(b) is None  # a newer recording starts
    controller._collect_changes(a, "files_late.tsv")
    assert {(e["path"], e["state"]) for e in a.changed} == {
        ("/data/data/org.x/a", "changed"),
        ("/data/data/org.x/b", "new"),
    }


def test_a_failed_first_list_does_not_make_every_file_new(controller, monkeypatch):
    F = rewind.FileFact
    stop = {f"/data/data/org.x/f{i}": F(1, 1, "t") for i in range(5)}
    _capture_fakes(controller, monkeypatch, [None, stop])
    rec = _rec()
    assert controller._begin_capture(rec) is None
    controller._collect_changes(rec, "files_stop.tsv")
    assert rec.changed == []
    # The device's timezone is kept for the verdict's zoneless ISO times.
    assert rec.device_tz == "Asia/Tokyo"


def test_stop_worker_failure_still_returns_to_idle(controller, monkeypatch):
    from types import SimpleNamespace

    def boom(rec, name):
        raise RuntimeError("list failed")

    controller._collect_changes = boom
    controller._late_writes = lambda rec, wait=None: None
    controller._get_task_service = lambda: SimpleNamespace(unregister=lambda _n: None)
    monkeypatch.setattr(type(controller), "_emit_phase",
                        staticmethod(lambda *a, **k: 3))  # fmt: skip
    indicator: list = []
    controller._set_recording_indicator = indicator.append
    rec = _rec()
    controller._rec = rec
    controller._state = "stopping"
    controller._stop_worker(rec, open_review=False)
    assert controller.state == "idle"
    assert indicator == [False]


def test_quit_during_a_recording_finalises_it(controller, monkeypatch, tmp_path):
    """N4-B8: quitting while recording left recording.json with stopped=None
    and changed=0; now the capture stops and the recording is finalised.
    """
    from types import SimpleNamespace

    stopped: list = []

    def collect(rec, name):
        rec.changed = [{"path": "/data/data/org.x/f", "state": "changed"}]

    controller._collect_changes = collect
    controller._late_writes = lambda rec, wait=None: None
    controller._get_task_service = lambda: SimpleNamespace(unregister=lambda _n: None)
    monkeypatch.setattr(type(controller), "_emit_phase",
                        staticmethod(lambda *a, **k: 3))  # fmt: skip
    opened: list = []
    controller.open_review = lambda: opened.append(1)
    rec = _rec()
    rec.stopped = None
    rec.changed = []
    controller._rec = rec
    controller._wrapper = SimpleNamespace(stop=lambda: stopped.append(1))
    controller._state = "recording"
    controller.finish_for_quit(budget=1.0)
    assert stopped == [1]
    assert controller.state == "idle"
    assert opened == []  # no Review on the way out
    saved = rewind.load_recording(rec.rec_id)
    assert saved.stopped is not None
    assert len(saved.changed) == 1


def test_quit_during_a_replay_stops_it_by_quit_and_waits_for_the_save(controller):
    controller._state = "running"
    controller._run_replays = True
    controller._run_done.clear()
    assert controller.quit_note() == "stops the replay"

    def worker_saves() -> None:
        controller._cancel.wait(2.0)
        controller._state = "idle"
        controller._run_done.set()

    import threading

    threading.Thread(target=worker_saves, daemon=True).start()
    controller.finish_for_quit(budget=2.0)
    assert controller._stop_reason == "stopped by quit"
    assert controller._run_done.is_set()
    assert controller.quit_note() is None


@pytest.mark.parametrize(
    ("start_point", "deleted"),
    [
        ({"name": "sandroid_rec_20261120_133600", "saved_ok": True}, True),
        ({"name": "sandroid_rec_20261120_133600", "saved_ok": True,
          "pinned": True}, False),  # kept
        ({"name": "sandroid_rec_20261120_133600", "saved_ok": True,
          "imported": True}, False),
        ({"name": "clean_8g", "saved_ok": True}, False),  # never another name
        ({"name": "sandroid_rec_20261120_133600", "saved_ok": False}, False),
    ],
)  # fmt: skip
def test_quit_deletes_only_this_sessions_unkept_start_point(
    controller, monkeypatch, start_point, deleted
):
    """N4-B8: each session left its last start point (70+ MB) behind."""
    from sandroid import services

    calls: list = []

    class Emu:
        def delete_snapshot(self, name, serial=None, **kw):
            calls.append((name, serial))
            return True

    monkeypatch.setattr(services, "get_emulator_service", lambda: Emu())
    rec = _rec()
    rec.start_point = dict(start_point)
    controller._rec = rec
    assert controller.delete_session_start_point() is deleted
    assert calls == ([("sandroid_rec_20261120_133600", "emulator-5560")]
                     if deleted else [])  # fmt: skip
    controller._state = "running"
    assert controller.delete_session_start_point() is False  # never mid-run


def test_rewind_worker_failure_never_leaves_it_running(controller):
    def broken(*_a):
        raise RuntimeError("no deps")

    controller._deps = broken
    indicator: list = []
    controller._set_replay_indicator = indicator.append
    controller._state = "running"
    out = controller._rewind_worker(_rec(), True, controller.view)
    assert out["success"] is False
    assert controller.state == "idle"
    assert indicator == [False]


def test_snapshot_load_failure_resumes_the_monitor_and_pulls_nothing(
    controller, monkeypatch
):
    from sandroid import services

    class Emu:
        def load_snapshot(self, name, serial=None, **_kw):
            return False

    monkeypatch.setattr(services, "get_emulator_service", lambda: Emu())
    # The emulator answered (refused the load): the device is unchanged.
    monkeypatch.setattr(
        "sandroid.tui.controllers.recording_controller._device_ready",
        lambda serial: True,
    )
    monkeypatch.setattr(rewind.RewindRunner, "_emit", lambda self, *a, **k: 1)
    monkeypatch.setattr(controller, "_stop_monitor_before_revert", lambda: "cfg")
    monkeypatch.setattr(controller, "_persist", lambda rec, out: None)
    resumed: list = []
    toasts: list = []
    controller._resume_monitor = lambda cfg: resumed.append(cfg) or True
    controller._notify = lambda message, severity: toasts.append(message)
    rec = _rec()
    rec.selected = [rec.changed[0]["path"]]
    controller._rec = rec
    controller._state = "running"
    out = controller._rewind_worker(rec, False, controller.view)
    assert out["success"] is False
    assert "The device was not changed." in out["error"]
    assert controller.view.pulls == []
    assert resumed == ["cfg"]
    assert any("not changed" in t for t in toasts)
    assert controller.state == "idle"


def test_requests_are_compared_only_after_rewind_and_replay(controller, monkeypatch):
    rec = _rec()
    rec.selected_flows = [dict(rec.requests[0])]
    replay_line = {"src": "net", "kind": "flow", "seq": 50, "ref": {"id": "f50"},
                   "data": {"method": "POST", "host": "c.example", "path": "/v1",
                            "status": 500}}  # fmt: skip
    monkeypatch.setattr(rewind, "lines_between", lambda *a, **k: [replay_line])
    monkeypatch.setattr(rewind, "flow_detail_reader", lambda: (lambda _i: None))
    rec.runs = [{"n": 2, "kind": "rewind", "seq": {"start": 40, "end": 60}}]
    assert controller.results(rec)["flows"] == []
    assert "Replay" not in controller.run_requests(rec)
    rec.runs.append({"n": 3, "kind": "rewind-replay", "seq": {"start": 40, "end": 60}})
    (flow,) = controller.results(rec)["flows"]
    assert flow.found == "found in the replay"
    assert flow.status == "different"
    assert flow.body == "not captured"
    monkeypatch.setattr(rewind, "lines_between", lambda *a, **k: [])
    (flow,) = controller.results(rec)["flows"]
    assert flow.found == "not seen in the replay"


# -- Files lens pulls for a role --------------------------------------------------


@pytest.fixture
def role_view(tmp_path, monkeypatch):
    from sandroid.core import watchlist_store
    from sandroid.services.file_extraction_service import (
        ExtractionResult,
        FileExtractionService,
    )
    from sandroid.tui.widgets.watchlist_view import WatchlistView

    monkeypatch.setenv(watchlist_store.FILES_DIR_ENV, str(tmp_path / "files"))
    state: dict[str, Any] = {"facts": {}, "error": "File not found on device"}

    def pull(self, remote_path, local_path, compute_hash=False):
        return ExtractionResult(remote_path, local_path, False, error=state["error"])

    monkeypatch.setattr(FileExtractionService, "pull_file", pull)
    monkeypatch.setattr(WatchlistView, "_device_facts",
                        staticmethod(lambda paths: state["facts"]))  # fmt: skip
    monkeypatch.setattr(WatchlistView, "_device_clock", staticmethod(lambda: None))
    view = WatchlistView()
    view.state = state
    return view


def test_pull_role_says_absent_only_when_the_file_is_missing(role_view):
    path = "/data/data/org.x/files/new.json"
    assert role_view.pull_role(path, "before", "rec-1", 2) == ("absent", None)
    # The device did not answer: an error, never "not on the device".
    role_view.state["error"] = "error: device 'emulator-5560' not found"
    version, error = role_view.pull_role(path, "before", "rec-1", 2)
    assert version is None
    assert "not found" in error
    role_view.state["error"] = "Permission denied"
    assert role_view.pull_role(path, "before", "rec-1", 2) == (
        None,
        "Permission denied",
    )


def test_a_failed_load_still_allows_after(controller):
    rec = _rec()
    rec.runs = [{"n": 2, "kind": "rewind", "result": "stopped", "loaded": False}]
    controller._rec = rec
    path = rec.changed[0]["path"]
    controller.select_file(path, True)
    assert controller.view.pulls == [(path, "after", 1)]


async def test_results_are_computed_off_the_ui_thread():
    import threading

    seen: list[bool] = []

    class Slow(FakeController):
        def results(self, rec):
            seen.append(threading.current_thread() is threading.main_thread())
            return {"files": [], "flows": []}

    rec = _rec()
    rec.runs = [{"n": 2, "kind": "rewind", "result": "rewound", "loaded": True}]
    modal = ReviewModal(rec, Slow())
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: seen)
        assert seen == [False]
        await until(
            pilot,
            lambda: "Results of the last Rewind"
            in " ".join(str(w.render()) for w in modal.query("#review-results Static")),
        )


def test_no_selection_while_a_rewind_runs(controller):
    rec = _rec()
    controller._rec = rec
    controller._state = "running"
    controller.select_file(rec.changed[0]["path"], True)
    assert rec.selected == []
    assert controller.view.pulls == []
    controller.select_flow(rec.requests[0], True)
    assert rec.selected_flows == []


def test_rewind_waits_for_after_pulls(controller):
    controller._rec = _rec()
    controller._pending_after.add("/data/data/org.x/databases/c.sqlite")
    assert "Saving After of 1 file" in controller.rewind_problem()


def test_replay_without_recorded_steps_is_an_error(controller, monkeypatch):
    monkeypatch.setattr(rewind, "lines_between", lambda *a, **k: [])
    runner = type("R", (), {"start_seq": 5, "deps": None})()
    report = controller._replay(_rec(), runner)
    assert "No steps were recorded" in report["error"]


def test_late_list_and_rewind_never_overlap(controller, monkeypatch):
    import threading

    rec = _rec()
    controller._rec = rec
    entered = threading.Event()
    release = threading.Event()

    def slow_collect(r, name):
        entered.set()
        release.wait(5)

    monkeypatch.setattr(controller, "_collect_changes", slow_collect)
    t = threading.Thread(target=controller._late_writes, args=(rec, 0))
    t.start()
    assert entered.wait(5)
    assert controller._list_lock.locked()  # a Rewind's worker waits here
    release.set()
    t.join(5)
    assert not controller._list_lock.locked()


def test_replay_requests_are_taken_by_time_including_late_ones(controller, monkeypatch):
    lines = [
        {"src": "net", "kind": "flow", "seq": 50, "t": 1000.0, "ref": {"id": "a"},
         "data": {"method": "GET", "host": "h", "path": "/early"}},
        {"src": "net", "kind": "flow", "seq": 60, "t": 1011.0, "ref": {"id": "b"},
         "data": {"method": "GET", "host": "h", "path": "/late"}},
        {"src": "net", "kind": "flow", "seq": 70, "t": 1100.0, "ref": {"id": "c"},
         "data": {"method": "GET", "host": "h", "path": "/after"}},
    ]  # fmt: skip
    monkeypatch.setattr(rewind, "lines_between", lambda *a, **k: lines)
    run = {"seq": {"replay": 40, "end": 55}, "replay_started": 999.0, "ended": 1010.0}
    got = [ln["data"]["path"] for ln in controller._replay_lines(_rec(), run)]
    assert got == ["/early", "/late"]


def test_a_timed_out_save_is_deleted_when_it_shows_up(monkeypatch):
    from types import SimpleNamespace

    from sandroid import services
    from sandroid.tui.controllers.recording_controller import RecordingController

    calls = {"list": 0, "deleted": []}

    class Emu:
        def list_snapshots(self):
            calls["list"] += 1
            names = ["clean_8g"] + (
                ["sandroid_rec_20261120_011933"] if calls["list"] > 1 else []
            )
            return [SimpleNamespace(name=n) for n in names]

        def delete_snapshot(self, name, serial=None):
            calls["deleted"].append((name, serial))
            return True

    monkeypatch.setattr(services, "get_emulator_service", lambda: Emu())
    ok = RecordingController._reap_start_point(
        "sandroid_rec_20261120_011933", "emulator-5560", wait_s=5, every_s=0.01
    )
    assert ok
    assert calls["deleted"] == [("sandroid_rec_20261120_011933", "emulator-5560")]
    assert RecordingController._reap_start_point("clean_8g", "x", wait_s=1) is False


async def test_results_are_visible_at_200x55():
    rec = _rec()
    rec.runs = [{"n": 2, "kind": "rewind", "result": "rewound", "loaded": True}]
    modal = ReviewModal(rec, FakeController())
    app = Host(modal)
    async with app.run_test(size=(200, 55)) as pilot:
        await until(
            pilot,
            lambda: any(
                "Results of the last" in str(w.render())
                for w in modal.query("#review-results Static")
            ),
        )
        row = modal.query_one("#review-name-row")
        assert row.size.height <= 3  # was ~17 empty rows (height 1fr)


def test_a_rewind_run_is_timed_from_its_own_start(controller, monkeypatch):
    from sandroid.core import run_history

    saved = []
    monkeypatch.setattr(run_history, "save_run", saved.append)
    monkeypatch.setattr(
        "sandroid.core.timeline.timeline_folder", lambda: rewind.recordings_root()
    )
    rec = _rec()
    rec.runs = [{"n": 2, "kind": "rewind", "started": 5000.0, "loaded": True}]
    outcome = rewind.RunOutcome(n=2, mode="rewind", result="rewound")
    assert controller._persist(rec, outcome)
    from datetime import datetime

    assert datetime.fromisoformat(saved[0].recorded_at).timestamp() == 5000.0


def test_selecting_a_wal_file_watches_its_database(controller):
    rec = _rec()
    rec.changed.append(
        {"path": "/data/data/org.x/cookies.sqlite-wal", "state": "changed", "size": 9}
    )
    controller._rec = rec
    controller.select_file("/data/data/org.x/cookies.sqlite-wal", True)
    assert rec.selected == ["/data/data/org.x/cookies.sqlite"]
    assert controller.view.pulls == [("/data/data/org.x/cookies.sqlite", "after", 1)]


async def test_review_body_scrolls_to_the_last_result():
    from textual.containers import VerticalScroll

    rec = _rec()
    rec.runs = [{"n": 2, "kind": "rewind", "result": "rewound", "loaded": True}]

    class Many(FakeController):
        def results(self, rec):
            res = rewind.FileResult("/data/data/org.x/f", "v1", "v2")
            res.action_text = "\n".join(f"line {i}" for i in range(80))
            return {"files": [res], "flows": []}

    modal = ReviewModal(rec, Many())
    app = Host(modal)
    async with app.run_test(size=(200, 55)) as pilot:
        body = modal.query_one("#review-body", VerticalScroll)
        await until(pilot, lambda: body.max_scroll_y > 0)
        body.scroll_end(animate=False)
        await settle(pilot)
        assert body.scroll_y == body.max_scroll_y > 0


def test_load_timeout_with_the_device_offline_is_not_reported_as_unchanged(
    controller, monkeypatch
):
    from sandroid import services
    from sandroid.tui.controllers import recording_controller as rc

    class Emu:
        def load_snapshot(self, name, serial=None, **_kw):
            return False

    monkeypatch.setattr(services, "get_emulator_service", lambda: Emu())
    monkeypatch.setattr(rc, "_device_ready", lambda serial: False)
    deps = controller._deps(_rec(), None, replay=False)
    with pytest.raises(rewind.RewindStoppedError, match="state is unknown"):
        deps.load_snapshot("sandroid_rec_20261120_133600", "emulator-5560")
    monkeypatch.setattr(rc, "_device_ready", lambda serial: True)
    assert deps.load_snapshot("sandroid_rec_20261120_133600", "emulator-5560") is False


def test_start_point_load_resets_the_network_before_step_1(controller, monkeypatch):
    """N4-B2: a Rewind's load resets the network (and waits until it is
    back) through the shared step; a stop during the wait stops the run.
    """
    from sandroid import services
    from sandroid.services import emulator_service as es

    calls: list = []

    class Emu:
        def load_snapshot(self, name, serial=None, **kw):
            calls.append(("load", kw))
            return True

    def reset(serial, *, sleep=None, **kw):
        calls.append(("network", serial))
        sleep(0.01)  # the wait for the network to come back
        return True

    monkeypatch.setattr(services, "get_emulator_service", lambda: Emu())
    monkeypatch.setattr(es, "reset_network_after_load", reset)
    deps = controller._deps(_rec(), None, replay=True)
    assert deps.load_snapshot("sandroid_rec_20261120_133600", "emulator-5560")
    assert calls == [("load", {"reset_network": False}), ("network", "emulator-5560")]
    controller._state = "running"
    controller.stop_rewind()
    with pytest.raises(rewind.RewindStoppedError, match=r"^Replay stopped\.$"):
        deps.load_snapshot("sandroid_rec_20261120_133600", "emulator-5560")


def test_stop_reasons_are_the_real_ones(controller):
    """N4-B10: Stop records "stopped", a quit "stopped by quit", never
    "you pressed Esc"; the first reason wins.
    """
    deps = controller._deps(_rec(), None, replay=True)
    controller._state = "running"
    assert controller.stop_playback() is True  # the quit path
    controller.stop_rewind()  # a later Stop does not overwrite it
    assert deps.stop_reason() == "stopped by quit"
    controller._stop_reason = "stopped"
    assert deps.stop_reason() == "stopped"


def test_replay_waits_the_recorded_tail_not_the_after_copy(controller, monkeypatch):
    """N4-B6: the wait after the last step is your run's tail (last input
    to Stop), never the time until a file was selected in Review.
    """
    seen: dict = {}

    class Rep:
        def __init__(self, **kw):
            seen["tail"] = kw.get("tail_s")

        def run(self, steps):
            return {"steps": [], "stopped_at_step": None, "error": None}

    import sandroid.features.player as player_mod

    monkeypatch.setattr(player_mod, "StepReplayer", Rep)
    tap = {"src": "input", "kind": "tap", "seq": 3, "t": 100.0, "actor": "user",
           "data": {"x": 1, "y": 2}}  # fmt: skip
    monkeypatch.setattr(rewind, "lines_between", lambda *a, **k: [tap])
    monkeypatch.setattr(
        "sandroid.services.tracking_service.get_tracking",
        lambda: (_ for _ in ()).throw(RuntimeError("no tracking")),
    )
    rec = _rec()
    rec.stopped = 115.0
    rec.selected = ["/data/data/org.x/databases/c.sqlite"]
    rec.after_at = {"/data/data/org.x/databases/c.sqlite": 143.0}
    runner = type("R", (), {"start_seq": 9, "deps": type("D", (), {"shell": None})()})()
    controller._replay(rec, runner)
    assert seen["tail"] == pytest.approx(15.0)  # stop 115 - last tap 100


async def test_companion_rows_keep_their_own_names():
    rec = _rec()
    rec.changed = [
        {"path": "/data/data/org.x/c.sqlite", "state": "changed", "size": 98304},
        {"path": "/data/data/org.x/c.sqlite-wal", "state": "changed", "size": 7},
    ]
    rec.selected = ["/data/data/org.x/c.sqlite"]
    modal = ReviewModal(rec, FakeController())
    app = Host(modal)
    async with app.run_test(size=(160, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        modal.set_file_state("/data/data/org.x/c.sqlite", "After saved")
        await settle(pilot)
        sel = modal.query_one("#review-files", SelectionList)
        prompts = [str(sel.get_option_at_index(i).prompt) for i in range(2)]
        assert "c.sqlite-wal" in prompts[1]
        assert "its database" in prompts[1]


def test_run_kind_and_stop_words_follow_the_phase(controller):
    """The running run is named Rewind or Replay (no "Play" wording)."""
    statuses: list[str | None] = []
    controller._status = statuses.append
    assert controller.run_kind is None
    controller._set_state("running")
    controller._run_replays = False
    assert controller.run_kind == "Rewind"
    controller.stop_rewind()
    assert statuses[-1] == "Stopping the rewind"
    controller._run_replays = True
    assert controller.run_kind == "Replay"
    controller.stop_rewind()
    assert statuses[-1] == "Stopping the replay"
    controller._set_state("idle")
    assert controller.run_kind is None


def test_a_diverged_replay_is_never_reported_as_success(controller, monkeypatch):
    from types import SimpleNamespace

    from sandroid.core import run_history
    from sandroid.tui.widgets import diffs_view
    from sandroid.tui.widgets.diffs_view import DiffsView

    saved: list = []
    monkeypatch.setattr(run_history, "save_run", saved.append)
    monkeypatch.setattr(
        "sandroid.core.timeline.timeline_folder", lambda: rewind.recordings_root()
    )
    why = "field reads 'sgelde', expected 'spiegel.de'"
    report = {
        "steps": [
            {"i": 1, "seq": 3, "what": 'typed "spiegel.de" into the address bar',
             "way": "diverged", "reason": why, "check": "diverged"},
        ],
        "stopped_at_step": None,
        "error": None,
        "diverged_at_step": 1,
        "diverged": f"step 1 of 1: {why}",
    }  # fmt: skip
    controller._deps = lambda rec, view, replay: rewind.RewindDeps(
        load_snapshot=lambda name, serial: True,
        shell=lambda cmd: "",
        pull=lambda path, role, rec_id, run: rewind.PullOutcome(f"v-{role}"),
        replay=lambda rec, runner: report,
        emit=lambda *a, **k: 1,
    )
    success: list[str] = []
    warnings: list[str] = []
    toasts: list[tuple[str, str]] = []
    controller._log_success = success.append
    controller._log_warning = warnings.append
    controller._notify = lambda message, severity: toasts.append((message, severity))
    rec = _rec()
    rec.selected = [rec.changed[0]["path"]]
    controller._rec = rec
    controller._state = "running"
    out = controller._rewind_worker(rec, True, controller.view)

    assert out["success"] is False
    assert out["result"] == "diverged"
    assert out["diverged_at_step"] == 1
    assert success == []
    assert any(f"The replay diverged at step 1 of 1: {why}" in w for w in warnings)
    assert all(sev == "warning" for _m, sev in toasts)
    assert not any("Done" in m for m, _sev in toasts)
    # run.json, the Review results and the Sessions lens say diverged
    record = saved[0]
    assert record.result == "diverged"
    assert record.rewind["diverged_at_step"] == 1
    assert "diverged at step 1" in record.rewind["note"]
    lines = next(iter(record.changed_files[0].values()))
    assert any(ln.startswith("Note: The replay diverged at step 1") for ln in lines)
    assert rec.runs[-1]["result"] == "diverged"
    summary = run_history._summary_from_record(record)
    assert summary["result"] == "diverged"
    problem = DiffsView._problem(SimpleNamespace(_facts={}), summary)
    assert problem == ("diverged", diffs_view._c("bad"))
    fake = SimpleNamespace(_short_path=DiffsView._short_path)
    sections = dict(DiffsView._rewind_sections(fake, record))
    assert why in sections["The replay diverged"].plain
    assert f"diverged: {why}" in sections["Replayed steps"].plain
    assert controller.review_dict(rec)["runs"][-1]["diverged_at_step"] == 1


async def test_review_results_say_the_replay_diverged():
    ctl = FakeController()
    rec = _rec()
    rec.runs = [
        {"n": 2, "kind": "rewind-replay", "result": "diverged",
         "diverged_at_step": 2, "diverged": "step 2 of 3: field text differs",
         "steps": [{"i": 2, "what": "typed 7 characters into password field",
                    "way": "diverged", "reason": "field text differs"}]},
    ]  # fmt: skip
    modal = ReviewModal(rec, ctl)
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)

        def text() -> str:
            return " ".join(
                str(w.render()) for w in modal.query("#review-results Static")
            )

        await until(pilot, lambda: "diverged" in text())
        body = text()
        assert "Results of the last Rewind + Replay (diverged at step 2)" in body
        assert "The replay diverged at step 2 of 3: field text differs" in body
        assert "diverged: field text differs" in body
        assert "Done" not in body


def test_unchecked_steps_are_never_reported_as_success(controller, monkeypatch):
    from types import SimpleNamespace

    from sandroid.core import run_history
    from sandroid.tui.widgets import diffs_view, timeline_lens
    from sandroid.tui.widgets.diffs_view import DiffsView

    saved: list = []
    monkeypatch.setattr(run_history, "save_run", saved.append)
    monkeypatch.setattr(
        "sandroid.core.timeline.timeline_folder", lambda: rewind.recordings_root()
    )
    report = {
        "steps": [
            {"i": 1, "seq": 3, "what": "tap 'spi' (View)", "way": "by position",
             "reason": "not found", "check": "unchecked"},
            {"i": 2, "seq": 4, "what": "tap at 539,1826 on spiegel.de",
             "way": "by position", "reason": "element off-screen",
             "check": "unchecked"},
        ],
        "stopped_at_step": None, "error": None, "diverged_at_step": None,
        "diverged": None, "unchecked_steps": [1, 2],
    }  # fmt: skip
    controller._deps = lambda rec, view, replay: rewind.RewindDeps(
        load_snapshot=lambda name, serial: True,
        shell=lambda cmd: "",
        pull=lambda path, role, rec_id, run: rewind.PullOutcome(f"v-{role}"),
        replay=lambda rec, runner: report,
        emit=lambda *a, **k: 1,
    )
    success: list[str] = []
    warnings: list[str] = []
    toasts: list[tuple[str, str]] = []
    controller._log_success = success.append
    controller._log_warning = warnings.append
    controller._notify = lambda message, severity: toasts.append((message, severity))
    rec = _rec()
    rec.selected = [rec.changed[0]["path"]]
    controller._rec = rec
    controller._state = "running"
    out = controller._rewind_worker(rec, True, controller.view)

    assert out["success"] is False
    assert out["result"] == "unchecked"
    assert out["unchecked_steps"] == [1, 2]
    assert success == []
    assert any(w.startswith("Replay done, 2 steps unchecked") for w in warnings)
    assert toasts
    assert all(sev == "warning" for _m, sev in toasts)
    record = saved[0]
    assert record.result == "unchecked"
    assert record.unchecked_count == 2
    assert record.rewind["result_words"] == "done, 2 steps unchecked"
    summary = run_history._summary_from_record(record)
    problem = DiffsView._problem(SimpleNamespace(_facts={}), summary)
    assert problem == ("done, 2 steps unchecked", diffs_view._c("warn"))
    fake = SimpleNamespace(_short_path=DiffsView._short_path)
    sections = dict(DiffsView._rewind_sections(fake, record))
    assert "done, 2 steps unchecked" in sections["Replay steps unchecked"].plain
    assert "by position (element off-screen), unchecked" in (
        sections["Replayed steps"].plain
    )
    assert controller.review_dict(rec)["runs"][-1]["unchecked_steps"] == [1, 2]
    # the timeline colours such a run line as a warning, a diverged one as bad
    row = SimpleNamespace(data={"result": "unchecked", "rec_id": "r"}, level="info")
    assert timeline_lens._run_failed(row)
    row = SimpleNamespace(data={"result": "replayed", "rec_id": "r"}, level="info")
    assert not timeline_lens._run_failed(row)


async def test_rewind_with_no_file_selected_asks_once():
    from sandroid.tui.modals.confirm_modal import ConfirmModal

    ctl = FakeController()
    rec = _rec()
    modal = ReviewModal(rec, ctl)
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        modal.query_one("#rewind-replay", Button).press()
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        text = " ".join(str(w.render()) for w in app.screen.query(Static))
        assert "No files selected: nothing will be compared. Go on?" in text
        assert ctl.rewinds == []
        await pilot.press("escape")  # Back: nothing starts
        await until(pilot, lambda: app.screen is modal)
        assert ctl.rewinds == []
        # asked once: the next press goes on at once
        modal.query_one("#rewind", Button).press()
        await until(pilot, lambda: ctl.rewinds == [False])


async def test_go_on_after_the_question_starts_the_rewind():
    from sandroid.tui.modals.confirm_modal import ConfirmModal

    ctl = FakeController()
    modal = ReviewModal(_rec(), ctl)
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        modal.query_one("#rewind", Button).press()
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        app.screen.query_one("#yes", Button).press()
        await until(pilot, lambda: ctl.rewinds == [False])


def test_sessions_say_how_many_changed_and_how_many_were_compared():
    from types import SimpleNamespace

    from sandroid.tui.widgets.diffs_view import DiffsView

    fake = SimpleNamespace(
        _facts={}, _problem=lambda s: None, divergence=lambda run_id: []
    )
    summary = {"run_id": "r1", "mode": "rewind-replay",
               "counts": {"changed": 0, "new": 0, "deleted": 0,
                          "recorded": 159, "compared": 0}}  # fmt: skip
    cell = DiffsView._changes_cell(fake, summary).plain
    assert cell == "159 changed, 0 compared"
    assert "no changes" not in cell
    summary["counts"].update(changed=2, compared=2)
    assert DiffsView._changes_cell(fake, summary).plain == "159 changed, 2 compared"
    # older runs (no recorded count) keep their words
    old = {"run_id": "r2", "counts": {"changed": 0}}
    assert DiffsView._changes_cell(fake, old).plain == "no changes"


# ---------------------------------------------------------------------------
# the next r removes old unpinned start points of the AVD
# ---------------------------------------------------------------------------


def _avd_with(tmp_path, names, size=1_000_000):
    avd = tmp_path / "avd" / "Dev3.avd"
    for name in names:
        folder = avd / "snapshots" / name
        folder.mkdir(parents=True)
        (folder / "ram.bin").write_bytes(b"\0" * size)
    return avd


def _old_recording(results, session, name, **sp):
    rec_id = "rec-" + name.removeprefix("sandroid_rec_").replace("_", "-")
    folder = results / session / "Dev3" / "recordings" / rec_id
    folder.mkdir(parents=True)
    rec = _rec()
    rec.rec_id = rec_id
    rec.start_point = {"name": name, "saved_ok": True, **sp}
    (folder / "recording.json").write_text(json.dumps(rec.to_dict(), default=str))


@pytest.fixture
def cleanup(controller, tmp_path, monkeypatch):
    from sandroid import services
    from sandroid.core import emulator, timeline

    results = tmp_path / "results"
    session = results / "now"
    session.mkdir(parents=True)
    deleted: list[tuple] = []
    logs: list[tuple[str, str]] = []

    class Emu:
        fail: set[str] = set()

        def delete_snapshot(self, name, serial=None):
            from sandroid.core.snapshot_policy import current_actor

            # The snapshot policy refuses start-point deletes by anyone else.
            assert current_actor()[0] == "rewind"
            deleted.append((name, serial))
            return name not in self.fail

    emu = Emu()
    monkeypatch.setattr(services, "get_emulator_service", lambda: emu)
    monkeypatch.setattr(timeline, "session_folder", lambda: session)
    monkeypatch.setattr(
        rewind, "recordings_root", lambda: session / "Dev3" / "recordings"
    )
    controller._log_info = lambda text: logs.append(("info", text))
    controller._log_warning = lambda text: logs.append(("warn", text))
    controller._ui = lambda fn, *a: fn(*a)
    return controller, results, emulator, emu, deleted, logs


def test_old_unpinned_start_points_are_removed_pinned_and_foreign_kept(
    cleanup, tmp_path, monkeypatch
):
    controller, results, emulator, _emu, deleted, logs = cleanup
    old, pinned, imported, new = (
        "sandroid_rec_20261101_090000",
        "sandroid_rec_20261102_090000",
        "sandroid_rec_20261103_090000",
        "sandroid_rec_20261120_140000",
    )
    avd = _avd_with(tmp_path, [old, pinned, imported, new, "clean_8g", "default_boot"])
    monkeypatch.setattr(emulator, "avd_dir", lambda name: avd)
    _old_recording(results, "s1", old)
    _old_recording(results, "s1", pinned, pinned=True)
    _old_recording(results, "s2", imported, pinned=True, imported=True)
    rec = _rec()
    rec.avd = "Dev3"
    rec.start_point = {"name": new, "saved_ok": True}
    rewind.save_recording(rec)
    assert controller._remove_old_start_points(rec) == 1
    assert deleted == [(old, "emulator-5560")]
    assert logs == [("info", "Removed 1 old start point (1 MB)")]


def test_an_unreadable_recording_keeps_the_start_points_it_names(
    cleanup, tmp_path, monkeypatch
):
    controller, results, emulator, _emu, deleted, _logs = cleanup
    name = "sandroid_rec_20261101_090000"
    avd = _avd_with(tmp_path, [name])
    monkeypatch.setattr(emulator, "avd_dir", lambda n: avd)
    folder = results / "s1" / "Dev3" / "recordings" / "rec-1"
    folder.mkdir(parents=True)
    (folder / "recording.json").write_text('{"start_point": {"name": "' + name)
    rec = _rec()
    rec.avd = "Dev3"
    rec.start_point = {"name": "sandroid_rec_20261120_140000", "saved_ok": True}
    rewind.save_recording(rec)
    assert controller._remove_old_start_points(rec) == 0
    assert deleted == []


def test_a_failed_delete_is_one_plain_line_and_never_blocks(
    cleanup, tmp_path, monkeypatch
):
    controller, _results, emulator, emu, deleted, logs = cleanup
    a, b = "sandroid_rec_20261101_090000", "sandroid_rec_20261102_090000"
    avd = _avd_with(tmp_path, [a, b])
    monkeypatch.setattr(emulator, "avd_dir", lambda n: avd)
    emu.fail = {a}
    rec = _rec()
    rec.avd = "Dev3"
    rec.start_point = {"name": "sandroid_rec_20261120_140000", "saved_ok": True}
    rewind.save_recording(rec)
    assert controller._remove_old_start_points(rec) == 1
    assert [n for n, _s in deleted] == [a, b]
    assert logs[0] == ("info", "Removed 1 old start point (1 MB)")
    assert logs[1][0] == "warn"
    assert a in logs[1][1]
    assert "recording goes on" in logs[1][1]


def test_nothing_is_removed_when_the_new_start_point_did_not_save(
    controller, monkeypatch
):
    from sandroid import services

    class Emu:
        def create_snapshot(self, name, serial=None):
            return False

        def delete_snapshot(self, name, serial=None):
            raise AssertionError("nothing may be deleted")

    started: list = []
    monkeypatch.setattr(services, "get_emulator_service", lambda: Emu())
    monkeypatch.setattr(rewind, "disk_problem", lambda _f: None)
    monkeypatch.setattr(controller, "_active_device_name", lambda: "Dev3")
    monkeypatch.setattr(
        controller, "_start_cleanup", lambda rec, prev: started.append(rec)
    )
    controller._state = "saving"
    assert controller._start_worker(_rec())["success"] is False
    assert started == []
    # and the cleanup itself does nothing without a saved start point
    rec = _rec()
    rec.start_point = {"name": None, "saved_ok": False}
    assert controller._remove_old_start_points(rec) == 0


def test_unknown_pinned_flags_delete_nothing(cleanup, tmp_path, monkeypatch):
    from sandroid.core import timeline

    controller, results, emulator, _emu, deleted, _logs = cleanup
    avd = _avd_with(tmp_path, ["sandroid_rec_20261101_090000"])
    monkeypatch.setattr(emulator, "avd_dir", lambda n: avd)
    rec = _rec()
    rec.avd = "Dev3"
    rec.start_point = {"name": "sandroid_rec_20261120_140000", "saved_ok": True}
    # the current recording is not saved where the scan looks: unknown layout
    assert controller._remove_old_start_points(rec) == 0
    rewind.save_recording(rec)
    # no session folder at all
    monkeypatch.setattr(timeline, "session_folder", lambda: None)
    assert controller._remove_old_start_points(rec) == 0
    # no serial: never the console of whatever device is current
    monkeypatch.setattr(timeline, "session_folder", lambda: results / "now")
    rec.serial = None
    assert controller._remove_old_start_points(rec) == 0
    assert deleted == []


_VOLATILE = {
    "field": "cookies, row name=sid, column expiry",
    "your_run": "1795136440",
    "replay": "1795140033",
    "rule": "same distance from its run",
}


def _volatile_result(path: str) -> rewind.FileResult:
    res = rewind.FileResult(path, "v1", "v2", "v3", "+ a", "+ b", rewind.VOLATILE)
    res.compared = "field by field"
    res.volatile = [dict(_VOLATILE)]
    return res


async def test_review_shows_volatile_fields_in_the_warning_colour():
    class Results(FakeController):
        def results(self, rec):
            vol = _volatile_result(rec.selected[0])
            byte = rewind.FileResult(rec.selected[1], "v1", "v2", "v3", "x", "y",
                                     rewind.DIFFERENT, compared="byte for byte")  # fmt: skip
            return {"files": [vol, byte], "flows": []}

    rec = _rec()
    rec.selected = [rec.changed[0]["path"], rec.changed[1]["path"]]
    rec.runs = [{"n": 2, "kind": "rewind-replay", "result": "replayed"}]
    modal = ReviewModal(rec, Results())
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        await until(pilot, lambda: modal.query("#review-results .verdict-volatile"))
        volatile = [str(w.render()) for w in modal.query(".verdict-volatile")]
        assert rewind.VOLATILE in volatile
        listed = " ".join(volatile)
        assert "1795136440 in your run, 1795140033 in the replay" in listed
        assert "(same distance from its run)" in listed
        different = [str(w.render()) for w in modal.query(".verdict-different")]
        assert rewind.DIFFERENT in different
        body = " ".join(str(w.render()) for w in modal.query("#review-results Static"))
        assert rewind.BYTE_WORDS in body


def test_volatile_verdicts_reach_run_json_recording_json_and_the_ai(
    controller, monkeypatch
):
    from types import SimpleNamespace

    from sandroid.core import run_history
    from sandroid.tui.widgets import diffs_view
    from sandroid.tui.widgets.diffs_view import DiffsView

    saved: list = []
    monkeypatch.setattr(run_history, "save_run", saved.append)
    monkeypatch.setattr(
        "sandroid.core.timeline.timeline_folder", lambda: rewind.recordings_root()
    )
    readers: list[str] = []
    monkeypatch.setattr(
        rewind,
        "hidden_texts",
        lambda rec, reader="ui": readers.append(reader) or frozenset(),
    )
    monkeypatch.setattr(
        rewind, "file_result", lambda rec, path, **kw: _volatile_result(path)
    )
    rec = _rec()
    rec.selected = [rec.changed[0]["path"]]
    rec.runs = [{"n": 2, "kind": "rewind-replay", "result": "replayed"}]
    outcome = rewind.RunOutcome(n=2, mode="rewind-replay", result="replayed")
    controller._persist(rec, outcome)

    path = rec.selected[0]
    record = saved[0]
    assert record.verdicts == {path: rewind.VOLATILE}
    assert record.rewind["volatile"] == {path: [_VOLATILE]}
    assert any(
        "same distance from its run" in ln for ln in record.changed_files[0][path]
    )
    stored = json.loads(rewind.save_recording(rec).read_text())
    assert stored["runs"][-1]["verdicts"] == {path: rewind.VOLATILE}
    fake = SimpleNamespace(_short_path=DiffsView._short_path)
    body = dict(DiffsView._rewind_sections(fake, record))["What your action changed"]
    assert any(
        span.style == diffs_view._c("warn")
        and rewind.VOLATILE in body.plain[span.start : span.end]
        for span in body.spans
    )

    ai = controller.review_dict(rec)
    (entry,) = ai["results"]
    assert entry["verdict"] == rewind.VOLATILE
    assert entry["volatile_fields"] == [_VOLATILE]
    assert entry["compared"] == "field by field"
    assert ai["runs"][-1]["verdicts"] == {path: rewind.VOLATILE}
    assert readers == ["any", "ai"]


_COOKIE = '{"meta.wikimedia.org":["WMF-Uniq=abc[/b]","[bold]x"]}'


def test_markup_helpers_show_device_text_literally():
    """N4-B1: ``rich.markup.escape`` leaves ``["`` alone; Textual reads it as
    a tag (``MarkupError``). The helpers keep any text literal.
    """
    from textual.content import Content

    from sandroid.tui.utils.markup import escape, plain

    for text in (_COOKIE, '["', "[Foo=bar]", "a\\[b]", "C:\\x\\", "[$var]"):
        assert Content.from_markup(escape(text)).plain.rstrip("\u200b") == text
        assert (
            Content.from_markup(f"[b]{escape(text)}[/b]").plain.rstrip("\u200b") == text
        )
        assert plain(text).plain == text


async def test_review_with_brackets_and_quotes_in_the_diff_does_not_crash():
    """N4-B1: a cookie_map value ``{"meta.wikimedia.org":["WMF-Uniq=...``
    in the diff, the error, a request body and the name crashed Sandroid.
    """

    class Results(FakeController):
        def results(self, rec):
            res = rewind.FileResult(rec.selected[0], "v1", "v2", "v3",
                                    f"+ {_COOKIE}", f"+ {_COOKIE}",
                                    rewind.DIFFERENT)  # fmt: skip
            res.only_run = [_COOKIE]
            res.note = _COOKIE
            return {"files": [res], "flows": []}

    rec = _rec()
    rec.name = _COOKIE
    rec.note = _COOKIE
    rec.selected = [rec.changed[0]["path"]]
    rec.runs = [{"n": 2, "kind": "rewind-replay", "result": "replayed",
                 "error": _COOKIE,
                 "steps": [{"i": 1, "what": _COOKIE, "way": "failed",
                            "reason": _COOKIE}]}]  # fmt: skip
    modal = ReviewModal(rec, Results())
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        await until(pilot, lambda: modal.query("#review-results .review-warn"))
        await settle(pilot)
        modal.set_progress(_COOKIE)
        await settle(pilot)
        body = " ".join(str(w.render()) for w in modal.query("#review-results Static"))
        assert _COOKIE in body
        assert _COOKIE in str(modal.query_one("#review-progress", Static).render())
        assert app.is_running


def test_a_notice_with_invalid_markup_is_shown_as_plain_text(monkeypatch):
    """N4-B1 safety net: ``notify(f"Failed: {exc}")`` with ``["`` in the
    exception must not raise ``MarkupError`` when the toast renders.
    """
    from textual.app import App

    from sandroid.tui.app import SandroidTUI

    seen: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        App, "notify", lambda self, message, **kw: seen.append((message, kw["markup"]))
    )
    app = SandroidTUI.__new__(SandroidTUI)
    app.notify(f"Failed: {_COOKIE}")
    app.notify("[b]bold[/b] fine")
    app.notify("x", markup=False)
    assert seen == [(f"Failed: {_COOKIE}", False), ("[b]bold[/b] fine", True),
                    ("x", False)]  # fmt: skip


def test_deselect_unwatches_only_what_review_watched(controller):
    """N4-B5: a deselected file stayed ★ watched in the watchlist."""
    rec = _rec()
    controller._rec = rec
    mine, theirs = rec.changed[0]["path"], rec.changed[1]["path"]
    controller.view.watched.append(theirs)  # watched before Review
    controller.select_file(mine, True)
    controller.select_file(theirs, True)
    controller.select_file(mine, False)
    controller.select_file(theirs, False)
    assert controller.view.watched == [theirs, theirs]  # add_path again, kept
    assert mine not in controller.view.watched


async def test_first_click_on_the_unfocused_file_list_selects_that_row():
    """N4-B5: the focus border appeared between press and release and
    shifted the rows: the click selected the row above.
    """
    ctl = FakeController()
    modal = ReviewModal(_rec(), ctl)
    app = Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal)
        files = modal.query_one("#review-files", SelectionList)
        modal.query_one("#review-name").focus()
        await settle(pilot)
        assert not files.has_focus
        await pilot.click(files, offset=(4, 1))  # the second row
        await until(pilot, lambda: ctl.selected)
        assert ctl.selected == [("/data/data/org.x/files/new.json", True)]
