"""The analysis-session change signal of ``InitializationService``."""

from __future__ import annotations

import threading

import pytest

from sandroid.services.initialization_service import (
    InitializationService,
    SessionChange,
)


@pytest.fixture
def service(tmp_path, monkeypatch):
    for name in ("SESSION_PATH", "RESULTS_PATH", "RAW_RESULTS_PATH"):
        monkeypatch.delenv(name, raising=False)
    svc = InitializationService(base_path=tmp_path)
    yield svc
    svc.reset()


def _collect(svc: InitializationService) -> tuple[list[SessionChange], object]:
    seen: list[SessionChange] = []
    return seen, svc.on_session_change(seen.append)


def test_new_resume_switch_and_close_each_fire_once(service, tmp_path):
    (tmp_path / "old").mkdir()
    seen, _unsub = _collect(service)

    service.create_session(timestamp="s1", setup_logging=False)
    assert [(c.kind, c.old_id, c.new_id) for c in seen] == [("new", None, "s1")]
    assert seen[0].new_path == (tmp_path / "s1").absolute()

    # a switch to an existing folder: resume, with the old session named
    service.create_session(timestamp="old", setup_logging=False)
    assert (seen[-1].kind, seen[-1].old_id, seen[-1].new_id) == ("resume", "s1", "old")
    assert seen[-1].old_path == (tmp_path / "s1").absolute()

    service.reset()
    assert (seen[-1].kind, seen[-1].old_id, seen[-1].new_id) == ("closed", "old", None)
    assert seen[-1].new_path is None
    assert len(seen) == 3


def test_same_session_again_and_device_switch_do_not_fire(service):
    seen, _unsub = _collect(service)
    service.create_session(timestamp="s1", setup_logging=False)
    service.create_session(timestamp="s1", setup_logging=False)  # re-select
    service.create_device_folder("Pixel")
    service.switch_device("Other")
    assert [c.kind for c in seen] == ["new"]
    service.reset()
    service.reset()  # already closed
    assert [c.kind for c in seen] == ["new", "closed"]


def test_unsubscribe_stops_the_calls_and_is_idempotent(service):
    seen, unsub = _collect(service)
    service.create_session(timestamp="s1", setup_logging=False)
    unsub()
    unsub()
    service.create_session(timestamp="s2", setup_logging=False)
    assert [c.new_id for c in seen] == ["s1"]


def test_a_raising_listener_does_not_break_the_others(service, caplog):
    def boom(_change):
        raise RuntimeError("listener bug")

    service.on_session_change(boom)
    seen, _unsub = _collect(service)
    service.create_session(timestamp="s1", setup_logging=False)
    assert [c.new_id for c in seen] == ["s1"]
    assert service.get_session_path() is not None
    assert "Session change listener failed" in caplog.text


def test_listeners_run_after_the_lock_is_released(service):
    """Even inside ``initialize_application`` (which holds the lock around
    ``create_session``), a listener runs with the lock free: another thread
    can read the new session from it.
    """
    from unittest import mock

    answers: list[object] = []

    def listener(change: SessionChange) -> None:
        box: list[object] = []
        t = threading.Thread(target=lambda: box.append(service.get_session_path()))
        t.start()
        t.join(2.0)
        answers.append(box[0] if box else "blocked")

    service.on_session_change(listener)
    with (
        mock.patch.object(service, "_initialize_app_logger"),
        mock.patch.object(service, "_create_frida_manager"),
    ):
        service.initialize_application(scan_directories=[])
    assert len(answers) == 1
    assert answers[0] == service.get_session_path()


def test_discard_unused_session_fires_closed(service):
    seen, _unsub = _collect(service)
    service.create_session(timestamp="s1", setup_logging=False)
    assert service.discard_unused_session() is True
    assert [c.kind for c in seen] == ["new", "closed"]
