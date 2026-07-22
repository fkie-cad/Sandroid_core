"""Unit tests for sandroid.ai.tools.environment_control.

Both ``get_frida_session_service`` and ``get_emulator_service`` are looked up
lazily inside each tool function's own body (see that module's docstring), so
tests monkeypatch ``sandroid.services.get_frida_session_service`` /
``sandroid.services.get_emulator_service`` directly -- the same convention
``tests/ai/tools/test_device_query.py`` uses for
``get_device_settings_service``.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from sandroid import services
from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools import environment_control as ec

# -- shared helpers ------------------------------------------------------------


def _patch_frida_manager(monkeypatch, manager):
    """Point ``get_frida_session_service()`` at a fake wrapping *manager*."""
    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(get_frida_manager=lambda: manager),
    )


def _patch_emulator_service(monkeypatch, service):
    monkeypatch.setattr(services, "get_emulator_service", lambda: service)


def _patch_configuration_service(monkeypatch, raw_results_path="results/raw/"):
    monkeypatch.setattr(
        services,
        "get_configuration_service",
        lambda: SimpleNamespace(get_raw_results_path=lambda: raw_results_path),
    )


def _patch_device_service(monkeypatch, is_emulator=True):
    """Point ``get_device_service()`` at a fake reporting *is_emulator*."""
    monkeypatch.setattr(
        services,
        "get_device_service",
        lambda: SimpleNamespace(is_emulator_device=lambda: is_emulator),
    )


# -- _get_frida_manager failure propagation -------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        ec.check_frida_server_status,
        ec.start_frida_server,
        ec.stop_frida_server,
        ec.install_frida_server,
    ],
)
def test_frida_tools_raise_tool_execution_error_when_manager_unavailable(
    monkeypatch, call
):
    def _boom():
        raise RuntimeError("no device connected")

    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(get_frida_manager=_boom),
    )

    with pytest.raises(ToolExecutionError):
        call()


def test_get_frida_manager_converts_arbitrary_exception_too(monkeypatch):
    """The helper must catch broadly, not just (RuntimeError, ImportError)."""

    def _boom():
        raise ValueError("something else entirely")

    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(get_frida_manager=_boom),
    )

    with pytest.raises(ToolExecutionError):
        ec.check_frida_server_status()


# -- check_frida_server_status --------------------------------------------------


def test_check_frida_server_status_passes_through(monkeypatch):
    manager = SimpleNamespace(
        is_frida_server_running=lambda: True,
        get_installed_server_version=lambda: "16.1.4",
    )
    _patch_frida_manager(monkeypatch, manager)

    assert ec.check_frida_server_status() == {
        "running": True,
        "installed_version": "16.1.4",
    }


def test_check_frida_server_status_not_running_no_version(monkeypatch):
    manager = SimpleNamespace(
        is_frida_server_running=lambda: False,
        get_installed_server_version=lambda: None,
    )
    _patch_frida_manager(monkeypatch, manager)

    assert ec.check_frida_server_status() == {
        "running": False,
        "installed_version": None,
    }


# -- start_frida_server ----------------------------------------------------------


def test_start_frida_server_success(monkeypatch):
    manager = SimpleNamespace(run_frida_server=lambda: True)
    _patch_frida_manager(monkeypatch, manager)

    assert ec.start_frida_server() == {"started": True}


def test_start_frida_server_failure_includes_hint(monkeypatch):
    manager = SimpleNamespace(run_frida_server=lambda: False)
    _patch_frida_manager(monkeypatch, manager)

    result = ec.start_frida_server()

    assert result["started"] is False
    assert "hint" in result


# -- stop_frida_server ------------------------------------------------------------


def test_stop_frida_server_not_running_never_calls_stop(monkeypatch):
    calls = []
    manager = SimpleNamespace(
        is_frida_server_running=lambda: False,
        stop_frida_server=lambda: calls.append("stop"),
    )
    _patch_frida_manager(monkeypatch, manager)

    assert ec.stop_frida_server() == {"stopped": False, "was_running": False}
    assert calls == []


def test_stop_frida_server_running_then_stopped(monkeypatch):
    states = iter([True, False])  # before, after
    manager = SimpleNamespace(
        is_frida_server_running=lambda: next(states),
        stop_frida_server=lambda: None,
    )
    _patch_frida_manager(monkeypatch, manager)

    assert ec.stop_frida_server() == {"stopped": True, "was_running": True}


def test_stop_frida_server_running_but_silently_still_running(monkeypatch):
    """Simulates the real non-rooted-device silent no-op."""
    manager = SimpleNamespace(
        is_frida_server_running=lambda: True,  # never actually stops
        stop_frida_server=lambda: None,
    )
    _patch_frida_manager(monkeypatch, manager)
    monkeypatch.setattr(ec.time, "sleep", lambda _s: None)
    # Make the settle-timeout deadline appear already exceeded so the poll
    # loop gives up after its first post-stop check instead of spinning for
    # the real _STOP_FRIDA_SETTLE_TIMEOUT_S seconds.
    clock = iter([0.0, 100.0])
    monkeypatch.setattr(ec.time, "monotonic", lambda: next(clock))

    result = ec.stop_frida_server()

    assert result["stopped"] is False
    assert result["was_running"] is True
    assert "error" in result
    assert "root" in result["error"].lower()


def test_stop_frida_server_settles_after_a_short_delay(monkeypatch):
    """Regression: the kill takes ~1-2s to land on-device (found via E2E
    testing) -- an immediate single post-check produced false failures on a
    device that was, in fact, rooted and did stop shortly after.
    """
    responses = iter([True, True, False])  # before-stop, 1st post-check, 2nd
    manager = SimpleNamespace(
        is_frida_server_running=lambda: next(responses),
        stop_frida_server=lambda: None,
    )
    _patch_frida_manager(monkeypatch, manager)
    monkeypatch.setattr(ec.time, "sleep", lambda _s: None)

    assert ec.stop_frida_server() == {"stopped": True, "was_running": True}


def test_stop_frida_server_stop_call_raises(monkeypatch):
    def _boom():
        raise RuntimeError("killall failed")

    manager = SimpleNamespace(
        is_frida_server_running=lambda: True,
        stop_frida_server=_boom,
    )
    _patch_frida_manager(monkeypatch, manager)

    result = ec.stop_frida_server()

    assert result["stopped"] is False
    assert result["was_running"] is True
    assert "killall failed" in result["error"]


# -- install_frida_server ---------------------------------------------------------


def test_install_frida_server_success_reports_installed_version_not_input(monkeypatch):
    captured = {}

    def fake_install(version=None):
        captured["version"] = version

    manager = SimpleNamespace(
        install_frida_server=fake_install,
        get_installed_server_version=lambda: "17.0.2",
    )
    _patch_frida_manager(monkeypatch, manager)

    result = ec.install_frida_server(version="latest")

    assert captured["version"] == "latest"
    assert result == {"installed": True, "version": "17.0.2"}


def test_install_frida_server_not_rooted_raises_runtime_error(monkeypatch):
    def fake_install(version=None):
        raise RuntimeError("device is not rooted")

    manager = SimpleNamespace(install_frida_server=fake_install)
    _patch_frida_manager(monkeypatch, manager)

    result = ec.install_frida_server()

    assert result == {"installed": False, "error": "device is not rooted"}


def test_install_frida_server_other_exception_also_caught(monkeypatch):
    def fake_install(version=None):
        raise OSError("network unreachable")

    manager = SimpleNamespace(install_frida_server=fake_install)
    _patch_frida_manager(monkeypatch, manager)

    result = ec.install_frida_server()

    assert result == {"installed": False, "error": "network unreachable"}


# -- take_screenshot ---------------------------------------------------------------


def test_take_screenshot_returns_path(monkeypatch, tmp_path):
    _patch_configuration_service(monkeypatch)

    def fake_take_screenshot(filename=None):
        with open(filename, "wb") as f:
            f.write(b"fake-png-bytes")
        return filename

    service = SimpleNamespace(take_screenshot=fake_take_screenshot)
    _patch_emulator_service(monkeypatch, service)
    monkeypatch.chdir(tmp_path)

    result = ec.take_screenshot()

    assert os.path.exists(result["path"])


def test_take_screenshot_passes_an_absolute_filename(monkeypatch, tmp_path):
    """Regression (found via E2E testing): EmulatorService.take_screenshot()
    joins a *relative* screenshots directory (from
    ConfigurationService.get_raw_results_path(), never made absolute) with
    the filename, and the emulator's telnet console resolves that relative
    path against its own process cwd -- silently failing to write anywhere.
    Passing an absolute filename sidesteps this (os.path.join() discards a
    relative first argument once the second is absolute).
    """
    _patch_configuration_service(monkeypatch, raw_results_path="results/raw/")
    captured = {}

    def fake_take_screenshot(filename=None):
        captured["filename"] = filename
        with open(filename, "wb") as f:
            f.write(b"fake-png-bytes")
        return filename

    service = SimpleNamespace(take_screenshot=fake_take_screenshot)
    _patch_emulator_service(monkeypatch, service)
    monkeypatch.chdir(tmp_path)

    ec.take_screenshot()

    assert Path(captured["filename"]).is_absolute()


def test_take_screenshot_none_raises_mentioning_emulator(monkeypatch, tmp_path):
    _patch_configuration_service(monkeypatch)
    service = SimpleNamespace(take_screenshot=lambda filename=None: None)
    _patch_emulator_service(monkeypatch, service)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ToolExecutionError, match="emulator"):
        ec.take_screenshot()


def test_take_screenshot_path_returned_but_file_missing_raises(monkeypatch, tmp_path):
    """Regression (found via E2E testing): the emulator's telnet console can
    report success while never actually writing the file. The tool must not
    trust the path without checking it exists.
    """
    _patch_configuration_service(monkeypatch)
    service = SimpleNamespace(take_screenshot=lambda filename=None: filename)
    _patch_emulator_service(monkeypatch, service)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ToolExecutionError, match="emulator"):
        ec.take_screenshot()


# -- start_screen_recording ---------------------------------------------------------


def test_start_screen_recording_success_includes_path(monkeypatch):
    service = SimpleNamespace(
        start_recording=lambda: True,
        get_recording_file=lambda: "/tmp/rec.webm",
    )
    _patch_emulator_service(monkeypatch, service)

    assert ec.start_screen_recording() == {"started": True, "path": "/tmp/rec.webm"}


def test_start_screen_recording_already_active(monkeypatch):
    service = SimpleNamespace(start_recording=lambda: False)
    _patch_emulator_service(monkeypatch, service)

    result = ec.start_screen_recording()

    assert result["started"] is False
    assert "already active" in result["message"]


# -- stop_screen_recording -----------------------------------------------------------


def test_stop_screen_recording_not_recording(monkeypatch):
    service = SimpleNamespace(is_recording=lambda: False, stop_recording=lambda: None)
    _patch_emulator_service(monkeypatch, service)

    result = ec.stop_screen_recording()

    assert result["stopped"] is False
    assert "no screen recording was active" in result["message"]


def test_stop_screen_recording_was_recording_pull_failed(monkeypatch):
    service = SimpleNamespace(is_recording=lambda: True, stop_recording=lambda: None)
    _patch_emulator_service(monkeypatch, service)

    result = ec.stop_screen_recording()

    assert result["stopped"] is False
    assert "pulling the file from the device failed" in result["message"]


def test_stop_screen_recording_success(monkeypatch, tmp_path):
    recording_path = tmp_path / "rec.webm"
    recording_path.write_bytes(b"real-webm-bytes")
    service = SimpleNamespace(
        is_recording=lambda: True, stop_recording=lambda: str(recording_path)
    )
    _patch_emulator_service(monkeypatch, service)

    assert ec.stop_screen_recording() == {"stopped": True, "path": str(recording_path)}


def test_stop_screen_recording_empty_file_reported_as_failure(monkeypatch, tmp_path):
    """Regression (found via E2E testing): a race in EmulatorService's
    background kill/pull thread (its join() can time out, after which the
    service still proceeds to pull the file anyway) can produce a 0-byte
    .webm. The tool can't fix that race, but must not report it as a
    success.
    """
    recording_path = tmp_path / "empty.webm"
    recording_path.write_bytes(b"")
    service = SimpleNamespace(
        is_recording=lambda: True, stop_recording=lambda: str(recording_path)
    )
    _patch_emulator_service(monkeypatch, service)

    result = ec.stop_screen_recording()

    assert result["stopped"] is False
    assert "empty" in result["message"].lower()


# -- create_snapshot / load_snapshot ----------------------------------------------------


def test_create_snapshot_passes_through(monkeypatch):
    captured = {}

    def fake_create(name):
        captured["name"] = name
        return True

    service = SimpleNamespace(create_snapshot=fake_create)
    _patch_emulator_service(monkeypatch, service)

    assert ec.create_snapshot("baseline") == {"created": True, "name": "baseline"}
    assert captured["name"] == "baseline"


def test_create_snapshot_failure(monkeypatch):
    service = SimpleNamespace(create_snapshot=lambda name: False)
    _patch_emulator_service(monkeypatch, service)

    assert ec.create_snapshot("baseline") == {"created": False, "name": "baseline"}


def test_load_snapshot_passes_through(monkeypatch):
    captured = {}

    def fake_load(name):
        captured["name"] = name
        return True

    service = SimpleNamespace(load_snapshot=fake_load)
    _patch_emulator_service(monkeypatch, service)

    assert ec.load_snapshot("baseline") == {"loaded": True, "name": "baseline"}
    assert captured["name"] == "baseline"


def test_load_snapshot_failure(monkeypatch):
    service = SimpleNamespace(load_snapshot=lambda name: False)
    _patch_emulator_service(monkeypatch, service)

    assert ec.load_snapshot("missing") == {"loaded": False, "name": "missing"}


# -- list_snapshots -------------------------------------------------------------------


@dataclass
class _FakeSnapshotInfo:
    name: str
    date: str


def test_list_snapshots_converts_dataclasses_to_dicts(monkeypatch):
    fake_snapshots = [
        _FakeSnapshotInfo(name="baseline", date="2026-07-01"),
        _FakeSnapshotInfo(name="post-install", date="2026-07-02"),
    ]
    service = SimpleNamespace(list_snapshots=lambda: fake_snapshots)
    _patch_emulator_service(monkeypatch, service)

    assert ec.list_snapshots() == {
        "snapshots": [
            {"name": "baseline", "date": "2026-07-01"},
            {"name": "post-install", "date": "2026-07-02"},
        ],
        "count": 2,
    }


def test_list_snapshots_empty(monkeypatch):
    service = SimpleNamespace(list_snapshots=list)
    _patch_emulator_service(monkeypatch, service)

    assert ec.list_snapshots() == {"snapshots": [], "count": 0}


# -- delete_snapshot -------------------------------------------------------------


def test_delete_snapshot_passes_through(monkeypatch):
    _patch_device_service(monkeypatch, is_emulator=True)
    captured = {}

    def fake_delete(name):
        captured["name"] = name
        return True

    service = SimpleNamespace(delete_snapshot=fake_delete)
    _patch_emulator_service(monkeypatch, service)

    assert ec.delete_snapshot("baseline") == {"deleted": True, "name": "baseline"}
    assert captured["name"] == "baseline"


def test_delete_snapshot_failure(monkeypatch):
    _patch_device_service(monkeypatch, is_emulator=True)
    service = SimpleNamespace(delete_snapshot=lambda name: False)
    _patch_emulator_service(monkeypatch, service)

    assert ec.delete_snapshot("missing") == {"deleted": False, "name": "missing"}


def test_delete_snapshot_rejects_physical_device(monkeypatch):
    """A physical device must get a clean rejection, never a telnet attempt."""
    _patch_device_service(monkeypatch, is_emulator=False)
    calls = []
    service = SimpleNamespace(delete_snapshot=lambda name: calls.append(name) or True)
    _patch_emulator_service(monkeypatch, service)

    with pytest.raises(ToolExecutionError, match="emulator"):
        ec.delete_snapshot("baseline")
    assert calls == []


# -- restart_emulator -------------------------------------------------------------


def test_restart_emulator_passes_through(monkeypatch):
    _patch_device_service(monkeypatch, is_emulator=True)
    service = SimpleNamespace(restart=lambda: True)
    _patch_emulator_service(monkeypatch, service)

    assert ec.restart_emulator() == {"restarted": True}


def test_restart_emulator_binary_missing_caught_as_error(monkeypatch):
    _patch_device_service(monkeypatch, is_emulator=True)

    def fake_restart():
        raise RuntimeError("emulator binary not found")

    service = SimpleNamespace(restart=fake_restart)
    _patch_emulator_service(monkeypatch, service)

    result = ec.restart_emulator()

    assert result == {"restarted": False, "error": "emulator binary not found"}


def test_restart_emulator_rejects_physical_device(monkeypatch):
    """A physical device must get a clean rejection, never a process launch."""
    _patch_device_service(monkeypatch, is_emulator=False)
    calls = []
    service = SimpleNamespace(restart=lambda: calls.append("restart") or True)
    _patch_emulator_service(monkeypatch, service)

    with pytest.raises(ToolExecutionError, match="emulator"):
        ec.restart_emulator()
    assert calls == []


# -- kill_emulator ----------------------------------------------------------------


def test_kill_emulator_passes_through(monkeypatch):
    _patch_device_service(monkeypatch, is_emulator=True)
    service = SimpleNamespace(kill=lambda: True)
    _patch_emulator_service(monkeypatch, service)

    assert ec.kill_emulator() == {"killed": True}


def test_kill_emulator_send_failed(monkeypatch):
    _patch_device_service(monkeypatch, is_emulator=True)
    service = SimpleNamespace(kill=lambda: False)
    _patch_emulator_service(monkeypatch, service)

    assert ec.kill_emulator() == {"killed": False}


def test_kill_emulator_rejects_physical_device(monkeypatch):
    """A physical device must get a clean rejection, never a telnet attempt."""
    _patch_device_service(monkeypatch, is_emulator=False)
    calls = []
    service = SimpleNamespace(kill=lambda: calls.append("kill") or True)
    _patch_emulator_service(monkeypatch, service)

    with pytest.raises(ToolExecutionError, match="emulator"):
        ec.kill_emulator()
    assert calls == []


# -- get_running_frida_jobs -------------------------------------------------------


def test_get_running_frida_jobs_passes_through(monkeypatch):
    jobs = [{"job_id": "1", "target": "com.example.app"}]
    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(get_running_jobs=lambda: jobs),
    )

    assert ec.get_running_frida_jobs() == {"jobs": jobs, "count": 1}


def test_get_running_frida_jobs_empty(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(get_running_jobs=list),
    )

    assert ec.get_running_frida_jobs() == {"jobs": [], "count": 0}


# -- check_hook_conflicts ---------------------------------------------------------


def test_check_hook_conflicts_passes_hooks_through_and_reports_conflicts(monkeypatch):
    captured = {}

    def fake_check(hooks):
        captured["hooks"] = hooks
        return {"open": "job-42"}

    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(check_hook_conflicts=fake_check),
    )

    result = ec.check_hook_conflicts(["open", "read"])

    assert captured["hooks"] == ["open", "read"]
    assert result == {"conflicts": {"open": "job-42"}}


def test_check_hook_conflicts_no_conflicts(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(check_hook_conflicts=lambda hooks: {}),
    )

    assert ec.check_hook_conflicts(["open"]) == {"conflicts": {}}
