"""Unit tests for MainScreen's TASK_OUTPUT -> Background Activity routing.

Covers Problem 1's fix: fsmon's output must NOT reach Background Activity
(it has its own dedicated home, the Files tab's Monitor sub-tab), while every
other task's output must still reach it unaffected.

No real Textual ``App``/``Pilot`` needed: ``MainScreen._handle_task_output``
is an unbound method called directly against a minimal duck-typed fake
``self`` -- an object with a ``query_one``-like method returning a fake
activity-log stub (recording ``log_message`` calls) and a no-op
``_safe_refresh_status_bar``. Mirrors ``test_fsmon_controller.py``'s
dependency-injected testing style (no UI framework spun up just to exercise
plain-Python routing logic).
"""

from __future__ import annotations

from sandroid.core.events import Event, EventType
from sandroid.tui.screens.main_screen import MainScreen


class _FakeActivityLog:
    """Records every ``log_message`` call, mirroring ``ActivityLog``'s API."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def log_message(self, message: str, source: str) -> None:
        self.calls.append((message, source))


class _FakeMainScreen:
    """Minimal duck-typed stand-in for ``MainScreen`` in this one method's
    dependencies -- no real Textual widget tree involved.
    """

    def __init__(self) -> None:
        self.activity_log = _FakeActivityLog()
        self.refresh_calls = 0

    def query_one(self, _selector, _cls=None):
        return self.activity_log

    def _safe_refresh_status_bar(self) -> None:
        self.refresh_calls += 1


def test_handle_task_output_excludes_fsmon():
    """FSMon output must never reach Background Activity -- it has its own
    dedicated display (Files tab's Monitor sub-tab).
    """
    fake_self = _FakeMainScreen()
    event = Event(
        type=EventType.TASK_OUTPUT,
        data={"task_name": "FSMon", "message": "some fsmon output"},
        source="fsmon",
    )

    MainScreen._handle_task_output(fake_self, event)

    assert fake_self.activity_log.calls == []
    # The early-return guard must exit before even the status-bar refresh.
    assert fake_self.refresh_calls == 0


def test_handle_task_output_still_shows_other_sources():
    """A TASK_OUTPUT event from any other source (friTap, mitmproxy,
    trigdroid, ...) must still reach Background Activity unaffected.
    """
    fake_self = _FakeMainScreen()
    event = Event(
        type=EventType.TASK_OUTPUT,
        data={"task_name": "FriTap", "message": "some fritap output"},
        source="fritap",
    )

    MainScreen._handle_task_output(fake_self, event)

    assert fake_self.activity_log.calls == [("some fritap output", "FriTap")]
    assert fake_self.refresh_calls == 1


def test_handle_task_output_with_no_source_still_shows():
    """Events with no ``source`` at all (e.g. legacy callers) must not be
    swept up by the fsmon exclusion -- only an explicit ``source == "fsmon"``
    is excluded.
    """
    fake_self = _FakeMainScreen()
    event = Event(
        type=EventType.TASK_OUTPUT,
        data={"task_name": "SomeTask", "message": "plain output"},
    )

    MainScreen._handle_task_output(fake_self, event)

    assert fake_self.activity_log.calls == [("plain output", "SomeTask")]
