"""Unit tests for sandroid.ai.tools.recording_control.

Every tool lazily imports its real dependency inside the function body
(mirroring ``session_control.py``'s documented convention), so tests
monkeypatch those modules' attributes directly (``sandroid.tui.
controller_registry.get_recording_controller``, ``sandroid.core.
run_history``, ``sandroid.ai.loop._current_owner_id``, etc.) rather than
patching names on ``recording_control`` itself.
"""

from __future__ import annotations

from typing import Any

import pytest

from sandroid.ai import loop as ai_loop
from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools import recording_control
from sandroid.core import run_history
from sandroid.tui import controller_registry


class _FakeRecordingController:
    def __init__(self) -> None:
        self.start_recording_calls: list[tuple] = []
        self.start_recording_result: dict[str, Any] = {
            "success": True,
            "label": "Run 1",
        }
        self.stop_recording_result: dict[str, Any] = {
            "success": True,
            "event_count": 5,
            "duration": 3.0,
            "label": "Run 1",
        }
        self.start_playback_calls: list[dict[str, Any]] = []
        self.start_playback_result: dict[str, Any] = {
            "success": True,
            "number_of_runs": 2,
            "noise_filter": True,
        }
        self._is_recording = False
        self._is_replaying = False
        self.current_recording_label: str | None = None

    def start_recording_chat(self, label, number_of_runs=2, noise_filter=True):
        self.start_recording_calls.append((label, number_of_runs, noise_filter))
        return self.start_recording_result

    def stop_recording_chat(self):
        return self.stop_recording_result

    def start_playback_chat(
        self, number_of_runs=None, noise_filter=None, owner_id=None
    ):
        self.start_playback_calls.append(
            {
                "number_of_runs": number_of_runs,
                "noise_filter": noise_filter,
                "owner_id": owner_id,
            }
        )
        return self.start_playback_result

    def is_recording(self):
        return self._is_recording

    @property
    def is_replaying(self):
        return self._is_replaying


def _as_owner(owner_id: str | None):
    """Context manager: run the block with ``_current_owner_id`` set.

    Mirrors ``tests/ai/tools/test_session_control.py``'s own ``_as_owner``
    helper -- drives the *actual* ``ContextVar`` ``start_replay`` reads
    (imported lazily inside the tool as ``from sandroid.ai.loop import
    _current_owner_id``, the same singleton object as ``ai_loop.
    _current_owner_id`` here).
    """

    class _OwnerContext:
        def __enter__(self):
            self._token = ai_loop._current_owner_id.set(owner_id)
            return self

        def __exit__(self, *exc_info):
            ai_loop._current_owner_id.reset(self._token)

    return _OwnerContext()


@pytest.fixture(autouse=True)
def _reset_registry():
    """Isolate the module-level controller registry across tests."""
    controller_registry._recording_controller = None
    yield
    controller_registry._recording_controller = None


# =============================================================================
# _require_recording_controller
# =============================================================================


def test_tools_raise_when_controller_not_registered():
    with pytest.raises(ToolExecutionError, match="not available"):
        recording_control.start_device_recording(label="foo")
    with pytest.raises(ToolExecutionError, match="not available"):
        recording_control.stop_device_recording()
    with pytest.raises(ToolExecutionError, match="not available"):
        recording_control.start_replay()
    with pytest.raises(ToolExecutionError, match="not available"):
        recording_control.get_recording_status()
    with pytest.raises(ToolExecutionError, match="not available"):
        recording_control.get_replay_status()


# =============================================================================
# start_device_recording / stop_device_recording
# =============================================================================


def test_start_device_recording_passes_arguments_through(monkeypatch):
    fake = _FakeRecordingController()
    monkeypatch.setattr(controller_registry, "get_recording_controller", lambda: fake)

    result = recording_control.start_device_recording(
        label="my run", number_of_runs=3, noise_filter=False
    )

    assert result == fake.start_recording_result
    assert fake.start_recording_calls == [("my run", 3, False)]


def test_stop_device_recording_passthrough(monkeypatch):
    fake = _FakeRecordingController()
    monkeypatch.setattr(controller_registry, "get_recording_controller", lambda: fake)

    assert recording_control.stop_device_recording() == fake.stop_recording_result


# =============================================================================
# start_replay
# =============================================================================


def test_start_replay_captures_owner_id_and_renames_dry_run_arg(monkeypatch):
    fake = _FakeRecordingController()
    monkeypatch.setattr(controller_registry, "get_recording_controller", lambda: fake)

    with _as_owner("owner-A"):
        result = recording_control.start_replay(number_of_runs=5, include_dry_run=False)

    assert result == fake.start_playback_result
    assert fake.start_playback_calls == [
        {"number_of_runs": 5, "noise_filter": False, "owner_id": "owner-A"}
    ]


def test_start_replay_no_owner_context_passes_none(monkeypatch):
    fake = _FakeRecordingController()
    monkeypatch.setattr(controller_registry, "get_recording_controller", lambda: fake)

    # No _as_owner context -- _current_owner_id.get() is None here.
    recording_control.start_replay()

    assert fake.start_playback_calls == [
        {"number_of_runs": None, "noise_filter": None, "owner_id": None}
    ]


# =============================================================================
# get_recording_status
# =============================================================================


def test_get_recording_status_when_not_recording(monkeypatch):
    fake = _FakeRecordingController()
    fake._is_recording = False
    fake.current_recording_label = "Last Run"
    monkeypatch.setattr(controller_registry, "get_recording_controller", lambda: fake)

    result = recording_control.get_recording_status()

    assert result == {
        "recording": False,
        "label": "Last Run",
        "event_count": 0,
        "elapsed_seconds": 0,
    }


def test_get_recording_status_when_recording(monkeypatch):
    fake = _FakeRecordingController()
    fake._is_recording = True
    fake.current_recording_label = "Run 1"
    monkeypatch.setattr(controller_registry, "get_recording_controller", lambda: fake)

    class _FakeWrapper:
        event_count = 42
        elapsed_seconds = 7.5

    class _FakeTask:
        instance = _FakeWrapper()

    class _FakeTaskService:
        def get_task(self, name):
            assert name == "recording"
            return _FakeTask()

    monkeypatch.setattr("sandroid.services.get_task_service", _FakeTaskService)

    result = recording_control.get_recording_status()

    assert result == {
        "recording": True,
        "label": "Run 1",
        "event_count": 42,
        "elapsed_seconds": 7.5,
    }


# =============================================================================
# get_replay_status
# =============================================================================


def test_get_replay_status(monkeypatch):
    fake = _FakeRecordingController()
    fake._is_replaying = True
    monkeypatch.setattr(controller_registry, "get_recording_controller", lambda: fake)

    assert recording_control.get_replay_status() == {"replaying": True}


# =============================================================================
# list_recent_runs
# =============================================================================


def test_list_recent_runs_slices_client_side(monkeypatch):
    entries = [{"run_id": f"run-{i}"} for i in range(5)]
    monkeypatch.setattr(run_history, "load_index", lambda device_name: entries)

    class _FakeToolbox:
        device_name = "emulator-5554"

    monkeypatch.setattr("sandroid.core.toolbox.Toolbox", _FakeToolbox)

    result = recording_control.list_recent_runs(limit=2)

    assert result["runs"] == entries[:2]
    assert result["count"] == 2
    assert result["total_available"] == 5


def test_list_recent_runs_rejects_non_integer_limit(monkeypatch):
    monkeypatch.setattr(run_history, "load_index", lambda device_name: [])

    with pytest.raises(ToolExecutionError, match="integer"):
        recording_control.list_recent_runs(limit="not-a-number")


# =============================================================================
# get_run_detail
# =============================================================================


def _make_run_record(**overrides) -> run_history.RunRecord:
    defaults: dict[str, Any] = {
        "schema_version": 2,
        "run_id": "run-1",
        "label": "Run 1",
        "recorded_at": "2026-01-01T00:00:00",
        "completed_at": "2026-01-01T00:01:00",
        "device_name": "emulator-5554",
        "recording_path": "/tmp/recording.txt",
        "duration": 60,
    }
    defaults.update(overrides)
    return run_history.RunRecord(**defaults)


def test_get_run_detail_raises_for_unknown_run(monkeypatch):
    def raise_not_found(run_id):
        raise run_history.RunHistoryError(f"Run '{run_id}' not found")

    monkeypatch.setattr(run_history, "load_run", raise_not_found)

    with pytest.raises(ToolExecutionError, match="not found"):
        recording_control.get_run_detail("no-such-run")


def test_get_run_detail_joins_and_truncates_diff_lines(monkeypatch):
    record = _make_run_record(
        changed_files=[
            {"a.txt": ["line1", "line2", "line3"]},
            "b.txt",  # undiffable, passes through unchanged
        ],
        new_files=["c.txt"],
    )
    monkeypatch.setattr(run_history, "load_run", lambda run_id: record)

    result = recording_control.get_run_detail("run-1", max_diff_chars=8)

    changed = result["changed_files"]
    assert changed[1] == "b.txt"
    assert changed[0]["a.txt"].startswith("line1\nli")
    assert "truncated" in changed[0]["a.txt"]
    assert result["diff_truncated"] is True
    assert result["new_files"] == ["c.txt"]


def test_get_run_detail_no_truncation_when_within_budget(monkeypatch):
    record = _make_run_record(changed_files=[{"a.txt": ["short"]}])
    monkeypatch.setattr(run_history, "load_run", lambda run_id: record)

    result = recording_control.get_run_detail("run-1", max_diff_chars=20000)

    assert result["changed_files"] == [{"a.txt": "short"}]
    assert result["diff_truncated"] is False


def test_get_run_detail_clamps_max_diff_chars_minimum(monkeypatch):
    record = _make_run_record(changed_files=[{"a.txt": ["x" * 500]}])
    monkeypatch.setattr(run_history, "load_run", lambda run_id: record)

    # A degenerate zero/negative request is clamped to _MIN_MAX_DIFF_CHARS
    # (1), not rejected or treated as "no limit".
    result = recording_control.get_run_detail("run-1", max_diff_chars=0)

    assert result["changed_files"][0]["a.txt"].startswith("x")
    assert result["diff_truncated"] is True
