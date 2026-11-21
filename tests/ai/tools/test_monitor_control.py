"""Unit tests for sandroid.ai.tools.monitor_control.

Every tool lazily imports its real dependency inside the function body
(mirroring ``session_control.py``'s documented convention), so tests
monkeypatch those modules' attributes directly (``sandroid.tui.
controller_registry.get_monitor_controller``, ``sandroid.core.
watchlist_store``, ``sandroid.services.file_extraction_service.
is_sqlite_file``, etc.) rather than patching names on ``monitor_control``
itself.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools import monitor_control
from sandroid.core import watchlist_store
from sandroid.services import file_extraction_service
from sandroid.tui import controller_registry

if TYPE_CHECKING:
    from sandroid.tui.controllers.monitor_controller import MonitorConfig


class _FakeMonitorController:
    def __init__(self) -> None:
        self.start_with_config_calls: list[MonitorConfig] = []
        self.start_with_config_result: dict[str, Any] = {
            "success": True,
            "backend": "fsmon",
            "mode": "path",
            "target": "/data/",
            "pending": False,
        }
        self.stop_result = True
        self.status_result: dict[str, Any] = {"running": True}
        self.recent_events_result: dict[str, Any] = {
            "events": [],
            "next_seq": 0,
            "count": 0,
            "truncated": False,
        }
        self.recent_events_calls: list[tuple] = []

    def start_with_config(self, config: MonitorConfig) -> dict[str, Any]:
        self.start_with_config_calls.append(config)
        return self.start_with_config_result

    def stop_from_ai(self) -> bool:
        return self.stop_result

    def get_status(self) -> dict[str, Any]:
        return self.status_result

    def get_recent_events(self, since_seq=None, limit=200) -> dict[str, Any]:
        self.recent_events_calls.append((since_seq, limit))
        return self.recent_events_result


@pytest.fixture(autouse=True)
def _reset_registry():
    """Isolate the module-level controller registry across tests."""
    controller_registry._monitor_controller = None
    yield
    controller_registry._monitor_controller = None


# =============================================================================
# _require_monitor_controller
# =============================================================================


def test_tools_raise_when_controller_not_registered():
    with pytest.raises(ToolExecutionError, match="not available"):
        monitor_control.start_file_monitor(mode="all")
    with pytest.raises(ToolExecutionError, match="not available"):
        monitor_control.stop_file_monitor()
    with pytest.raises(ToolExecutionError, match="not available"):
        monitor_control.get_file_monitor_status()
    with pytest.raises(ToolExecutionError, match="not available"):
        monitor_control.get_recent_file_changes()


# =============================================================================
# start_file_monitor / _build_monitor_config
# =============================================================================


def test_start_file_monitor_rejects_invalid_mode(monkeypatch):
    monkeypatch.setattr(
        controller_registry, "get_monitor_controller", _FakeMonitorController
    )
    with pytest.raises(ToolExecutionError, match="mode must be one of"):
        monitor_control.start_file_monitor(mode="bogus")


def test_start_file_monitor_pid_mode_requires_pid(monkeypatch):
    monkeypatch.setattr(
        controller_registry, "get_monitor_controller", _FakeMonitorController
    )
    with pytest.raises(ToolExecutionError, match="pid is required"):
        monitor_control.start_file_monitor(mode="pid")


def test_start_file_monitor_pid_mode_builds_config(monkeypatch):
    fake = _FakeMonitorController()
    monkeypatch.setattr(controller_registry, "get_monitor_controller", lambda: fake)

    result = monitor_control.start_file_monitor(
        mode="pid", pid=1234, app_name="com.example.app"
    )

    assert result == fake.start_with_config_result
    (config,) = fake.start_with_config_calls
    assert config.mode == "pid"
    assert config.target_pid == 1234
    assert config.app_name == "com.example.app"
    assert config.target_path == "/data/"  # default filter, none given


def test_start_file_monitor_path_mode_requires_path_or_paths(monkeypatch):
    monkeypatch.setattr(
        controller_registry, "get_monitor_controller", _FakeMonitorController
    )
    with pytest.raises(ToolExecutionError, match="path or paths is required"):
        monitor_control.start_file_monitor(mode="path")


def test_start_file_monitor_path_mode_single_path(monkeypatch):
    fake = _FakeMonitorController()
    monkeypatch.setattr(controller_registry, "get_monitor_controller", lambda: fake)

    monitor_control.start_file_monitor(mode="path", path="/data/data/com.example/")

    (config,) = fake.start_with_config_calls
    assert config.mode == "path"
    assert config.target_path == "/data/data/com.example/"
    assert config.target_paths == ["/data/data/com.example/"]
    assert config.target_pid is None


def test_start_file_monitor_path_mode_multiple_paths(monkeypatch):
    fake = _FakeMonitorController()
    monkeypatch.setattr(controller_registry, "get_monitor_controller", lambda: fake)

    monitor_control.start_file_monitor(mode="path", paths=["/a/", "/b/"])

    (config,) = fake.start_with_config_calls
    assert config.target_path == "/a/"
    assert config.target_paths == ["/a/", "/b/"]


def test_start_file_monitor_all_mode_uses_broad_default(monkeypatch):
    fake = _FakeMonitorController()
    monkeypatch.setattr(controller_registry, "get_monitor_controller", lambda: fake)

    monitor_control.start_file_monitor(mode="all")

    (config,) = fake.start_with_config_calls
    assert config.mode == "path"
    assert config.target_path == "/data/"
    assert config.target_paths == []
    assert config.target_pid is None


# =============================================================================
# stop_file_monitor
# =============================================================================


def test_stop_file_monitor_success(monkeypatch):
    fake = _FakeMonitorController()
    fake.stop_result = True
    monkeypatch.setattr(controller_registry, "get_monitor_controller", lambda: fake)

    assert monitor_control.stop_file_monitor() == {
        "success": True,
        "message": "Monitor stopped",
    }


def test_stop_file_monitor_not_running(monkeypatch):
    fake = _FakeMonitorController()
    fake.stop_result = False
    monkeypatch.setattr(controller_registry, "get_monitor_controller", lambda: fake)

    result = monitor_control.stop_file_monitor()
    assert result["success"] is False


# =============================================================================
# get_file_monitor_status / get_recent_file_changes
# =============================================================================


def test_get_file_monitor_status_passthrough(monkeypatch):
    fake = _FakeMonitorController()
    fake.status_result = {"running": False, "backend": None}
    monkeypatch.setattr(controller_registry, "get_monitor_controller", lambda: fake)

    assert monitor_control.get_file_monitor_status() == {
        "running": False,
        "backend": None,
    }


def test_get_recent_file_changes_passes_arguments_through(monkeypatch):
    fake = _FakeMonitorController()
    monkeypatch.setattr(controller_registry, "get_monitor_controller", lambda: fake)

    monitor_control.get_recent_file_changes(since_cursor=42, limit=10)

    assert fake.recent_events_calls == [(42, 10)]


# =============================================================================
# get_file_diff
# =============================================================================


class _FakeForensicService:
    def __init__(self) -> None:
        self.added: list[str] = []

    def add_spotlight_file(self, path, adb=None):
        self.added.append(path)
        return True


class _FakeExtractionResult:
    def __init__(self, success: bool, error: str | None = None) -> None:
        self.success = success
        self.error = error


class _FakeFileExtractionService:
    def __init__(self, success: bool = True, error: str | None = None) -> None:
        self.success = success
        self.error = error
        self.pull_calls: list[tuple[str, str]] = []

    def pull_file(self, remote_path: str, local_path: str):
        self.pull_calls.append((remote_path, local_path))
        return _FakeExtractionResult(self.success, self.error)


def test_get_file_diff_rejects_empty_path():
    with pytest.raises(ToolExecutionError, match="must not be empty"):
        monitor_control.get_file_diff("")


def test_get_file_diff_raises_on_pull_failure(monkeypatch, tmp_path):
    forensic = _FakeForensicService()
    fx = _FakeFileExtractionService(success=False, error="device offline")

    monkeypatch.setattr(watchlist_store, "has_baseline", lambda path: False)
    monkeypatch.setattr(
        watchlist_store, "reset_current", lambda path: tmp_path / "current"
    )
    (tmp_path / "current").mkdir()
    discarded: list[str] = []
    monkeypatch.setattr(watchlist_store, "discard_current", discarded.append)
    monkeypatch.setattr("sandroid.services.get_forensic_service", lambda: forensic)
    monkeypatch.setattr("sandroid.services.get_file_extraction_service", lambda: fx)

    with pytest.raises(ToolExecutionError, match="device offline"):
        monitor_control.get_file_diff("/data/data/com.example/prefs.xml")

    assert forensic.added == ["/data/data/com.example/prefs.xml"]
    # N1-B9: no empty staging folder left behind by the failed pull.
    assert discarded == ["/data/data/com.example/prefs.xml"]


def test_get_file_diff_first_pull_reports_baseline(monkeypatch, tmp_path):
    forensic = _FakeForensicService()
    fx = _FakeFileExtractionService(success=True)
    current_dir = tmp_path / "current"
    current_dir.mkdir()

    promoted: list[str] = []
    monkeypatch.setattr(watchlist_store, "has_baseline", lambda path: False)
    monkeypatch.setattr(watchlist_store, "reset_current", lambda path: current_dir)
    monkeypatch.setattr(
        watchlist_store,
        "keep_version",
        lambda path: promoted.append(path) or watchlist_store.KeptVersion(tmp_path),
    )
    monkeypatch.setattr("sandroid.services.get_forensic_service", lambda: forensic)
    monkeypatch.setattr("sandroid.services.get_file_extraction_service", lambda: fx)
    monkeypatch.setattr(file_extraction_service, "is_sqlite_file", lambda p: False)

    result = monitor_control.get_file_diff("/data/data/com.example/prefs.xml")

    assert result["baseline"] is True
    assert result["changed"] is None
    assert result["diff"] is None
    assert promoted == ["/data/data/com.example/prefs.xml"]
    # Pulled exactly the requested file, no sqlite companions.
    assert len(fx.pull_calls) == 1


def test_get_file_diff_changed(monkeypatch, tmp_path):
    forensic = _FakeForensicService()
    fx = _FakeFileExtractionService(success=True)
    current_dir = tmp_path / "current"
    current_dir.mkdir()
    previous_dir = tmp_path / "previous"
    previous_dir.mkdir()

    from sandroid.core.file_inspect import KeyChange, StructuredDiff

    kept_paths: list[str] = []
    changed = StructuredDiff(kind="xml", keys=[KeyChange("k", "added", new="1")])

    def fake_keep_version(path):
        kept_paths.append(path)
        return watchlist_store.KeptVersion(tmp_path, changed, "some diff text")

    monkeypatch.setattr(watchlist_store, "has_baseline", lambda path: True)
    monkeypatch.setattr(watchlist_store, "reset_current", lambda path: current_dir)
    monkeypatch.setattr(watchlist_store, "previous_dir", lambda path: previous_dir)
    monkeypatch.setattr(watchlist_store, "keep_version", fake_keep_version)
    monkeypatch.setattr("sandroid.services.get_forensic_service", lambda: forensic)
    monkeypatch.setattr("sandroid.services.get_file_extraction_service", lambda: fx)
    monkeypatch.setattr(file_extraction_service, "is_sqlite_file", lambda p: False)

    result = monitor_control.get_file_diff("/data/data/com.example/prefs.xml")

    assert result["baseline"] is False
    assert result["changed"] is True
    assert result["diff"] == "some diff text"
    # The pull is kept as a version (diff.json + diff.txt) through the store.
    assert kept_paths == ["/data/data/com.example/prefs.xml"]


def test_get_file_diff_keeps_a_real_version_with_diff_json(monkeypatch, tmp_path):
    """End to end through the real store: plain diff text, diff.json written."""
    forensic = _FakeForensicService()
    contents = iter(["a\n", "a\nb\n"])

    class _Fx:
        def pull_file(self, remote, local):
            from pathlib import Path

            Path(local).write_text(next(contents), encoding="utf-8")
            return type("R", (), {"success": True, "error": None})()

    monkeypatch.setattr("sandroid.services.get_forensic_service", lambda: forensic)
    monkeypatch.setattr("sandroid.services.get_file_extraction_service", _Fx)
    monkeypatch.setattr(file_extraction_service, "is_sqlite_file", lambda p: False)

    path = "/data/data/com.example/notes.txt"
    first = monitor_control.get_file_diff(path)
    second = monitor_control.get_file_diff(path)

    assert first["baseline"] is True
    assert second["changed"] is True
    assert "+b" in second["diff"]
    assert "[success]" not in second["diff"]
    newest = watchlist_store.version_dirs(path)[-1]
    assert watchlist_store.version_diff_doc(newest)["kind"] == "text"


def test_get_file_diff_unchanged(monkeypatch, tmp_path):
    forensic = _FakeForensicService()
    fx = _FakeFileExtractionService(success=True)
    current_dir = tmp_path / "current"
    current_dir.mkdir()
    previous_dir = tmp_path / "previous"
    previous_dir.mkdir()

    monkeypatch.setattr(watchlist_store, "has_baseline", lambda path: True)
    monkeypatch.setattr(watchlist_store, "reset_current", lambda path: current_dir)
    monkeypatch.setattr(watchlist_store, "previous_dir", lambda path: previous_dir)
    from sandroid.core.file_inspect import StructuredDiff

    monkeypatch.setattr(
        watchlist_store,
        "keep_version",
        lambda path: watchlist_store.KeptVersion(
            tmp_path, StructuredDiff(kind="text"), "No change.\n"
        ),
    )
    monkeypatch.setattr("sandroid.services.get_forensic_service", lambda: forensic)
    monkeypatch.setattr("sandroid.services.get_file_extraction_service", lambda: fx)
    monkeypatch.setattr(file_extraction_service, "is_sqlite_file", lambda p: False)

    result = monitor_control.get_file_diff("/data/data/com.example/prefs.xml")

    assert result["changed"] is False
    assert result["diff"] is None
    assert result["message"] == "No changes since last pull."


def test_get_file_diff_pulls_sqlite_companions(monkeypatch, tmp_path):
    forensic = _FakeForensicService()
    fx = _FakeFileExtractionService(success=True)
    current_dir = tmp_path / "current"
    current_dir.mkdir()

    monkeypatch.setattr(watchlist_store, "has_baseline", lambda path: False)
    monkeypatch.setattr(watchlist_store, "reset_current", lambda path: current_dir)
    monkeypatch.setattr(
        watchlist_store,
        "keep_version",
        lambda path: watchlist_store.KeptVersion(tmp_path),
    )
    monkeypatch.setattr("sandroid.services.get_forensic_service", lambda: forensic)
    monkeypatch.setattr("sandroid.services.get_file_extraction_service", lambda: fx)
    monkeypatch.setattr(file_extraction_service, "is_sqlite_file", lambda p: True)

    from sandroid.core import adb_utils

    quiet: list[int] = []
    pull = fx.pull_file

    def _pull(remote_path, local_path):
        quiet.append(getattr(adb_utils._quiet, "depth", 0))
        return pull(remote_path, local_path)

    fx.pull_file = _pull

    monitor_control.get_file_diff("/data/data/com.example/app.db")

    remote_paths = [call[0] for call in fx.pull_calls]
    assert remote_paths == [
        "/data/data/com.example/app.db",
        "/data/data/com.example/app.db-wal",
        "/data/data/com.example/app.db-journal",
    ]
    # e2e3 bug 10: a missing companion is no WARNING (quiet adb), the main
    # file's pull still warns.
    assert quiet == [0, 1, 1]


def test_get_file_diff_asks_for_approval():
    """It adds the path to the watchlist and keeps a version: not read-only."""
    from sandroid.ai.tools.registry import RiskTier, get_tool_registry

    spec = get_tool_registry().get_spec("get_file_diff")
    assert spec.risk == RiskTier.REVERSIBLE
    assert spec.can_remember_choice is True
    assert not spec.resources
