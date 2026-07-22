"""Unit tests for sandroid.ai.tools.process_control.

``Adb`` is imported at module level in ``process_control.py``, so tests
monkeypatch its classmethods directly on ``sandroid.core.adb.Adb`` --
wrapped in ``staticmethod(...)``, matching the convention in
``tests/ai/tools/test_device_query.py``.
"""

import pytest

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools import process_control
from sandroid.core.adb import Adb

# -- list_processes ---------------------------------------------------------------


def test_list_processes_passes_through_and_counts(monkeypatch):
    processes = [
        {"pid": 1, "user": "root", "name": "init"},
        {"pid": 42, "user": "u0_a123", "name": "com.example.app"},
    ]
    monkeypatch.setattr(
        Adb, "list_processes", staticmethod(lambda package_filter=None: processes)
    )

    assert process_control.list_processes() == {
        "processes": processes,
        "count": 2,
    }


def test_list_processes_forwards_package_filter(monkeypatch):
    captured = {}

    def fake_list_processes(package_filter=None):
        captured["package_filter"] = package_filter
        return []

    monkeypatch.setattr(Adb, "list_processes", staticmethod(fake_list_processes))

    process_control.list_processes(package_filter="com.example")

    assert captured["package_filter"] == "com.example"


def test_list_processes_empty(monkeypatch):
    monkeypatch.setattr(
        Adb, "list_processes", staticmethod(lambda package_filter=None: [])
    )

    assert process_control.list_processes() == {"processes": [], "count": 0}


# -- get_process_detail ------------------------------------------------------------


def test_get_process_detail_returns_detail_dict(monkeypatch):
    detail = {
        "pid": 42,
        "name": "com.example.app",
        "state": "S",
        "ppid": 1,
        "threads": 12,
        "uid": 10123,
        "vm_rss_kb": 51200,
        "vm_size_kb": 512000,
        "fd_count": 34,
        "map_region_count": 210,
    }
    monkeypatch.setattr(Adb, "get_process_detail", staticmethod(lambda pid: detail))

    assert process_control.get_process_detail(42) == detail


def test_get_process_detail_none_raises_tool_execution_error(monkeypatch):
    monkeypatch.setattr(Adb, "get_process_detail", staticmethod(lambda pid: None))

    with pytest.raises(ToolExecutionError, match="123"):
        process_control.get_process_detail(123)


def test_get_process_detail_forwards_pid(monkeypatch):
    captured = {}

    def fake_get_process_detail(pid):
        captured["pid"] = pid
        return {"pid": pid}

    monkeypatch.setattr(
        Adb, "get_process_detail", staticmethod(fake_get_process_detail)
    )

    process_control.get_process_detail(999)

    assert captured["pid"] == 999


# -- list_services ------------------------------------------------------------------


def test_list_services_device_wide_when_package_name_omitted(monkeypatch):
    captured = {}

    def fake_list_services(package_name=None):
        captured["package_name"] = package_name
        return [{"service": "com.example/.Foo"}]

    monkeypatch.setattr(Adb, "list_services", staticmethod(fake_list_services))

    result = process_control.list_services()

    assert captured["package_name"] is None
    assert result == {"services": [{"service": "com.example/.Foo"}], "count": 1}


def test_list_services_filters_to_given_package(monkeypatch):
    captured = {}

    def fake_list_services(package_name=None):
        captured["package_name"] = package_name
        return []

    monkeypatch.setattr(Adb, "list_services", staticmethod(fake_list_services))

    process_control.list_services(package_name="com.example.app")

    assert captured["package_name"] == "com.example.app"


def test_list_services_rejects_malicious_package_name(monkeypatch):
    called = []
    monkeypatch.setattr(
        Adb,
        "list_services",
        staticmethod(lambda package_name=None: called.append(package_name)),
    )

    with pytest.raises(ToolExecutionError, match="invalid package_name"):
        process_control.list_services(package_name="com.example; touch /tmp/x #")

    assert called == []


# -- get_activity_stack --------------------------------------------------------------


def test_get_activity_stack_passes_through_and_counts(monkeypatch):
    tasks = [
        {"task_id": 1, "activities": ["com.example.app/.MainActivity"]},
        {"task_id": 2, "activities": ["com.other/.Foo"]},
    ]
    monkeypatch.setattr(Adb, "get_activity_stack", staticmethod(lambda: tasks))

    assert process_control.get_activity_stack() == {"tasks": tasks, "count": 2}


def test_get_activity_stack_empty(monkeypatch):
    monkeypatch.setattr(Adb, "get_activity_stack", staticmethod(list))

    assert process_control.get_activity_stack() == {"tasks": [], "count": 0}


# -- kill_process: argument validation ------------------------------------------------


def test_kill_process_requires_exactly_one_of_package_name_or_pid(monkeypatch):
    with pytest.raises(ToolExecutionError, match="exactly one"):
        process_control.kill_process()


def test_kill_process_rejects_both_package_name_and_pid(monkeypatch):
    with pytest.raises(ToolExecutionError, match="exactly one"):
        process_control.kill_process(package_name="com.example.app", pid=42)


# -- kill_process: package path (force_stop) ------------------------------------------


def test_kill_process_package_path_success(monkeypatch):
    monkeypatch.setattr(
        Adb, "force_stop", staticmethod(lambda package_name: (True, "Force-stopped"))
    )

    result = process_control.kill_process(package_name="com.example.app")

    assert result == {
        "method": "force_stop",
        "package_name": "com.example.app",
        "success": True,
        "message": "Force-stopped",
    }


def test_kill_process_package_path_rejects_malicious_package_name(monkeypatch):
    """Regression (review-caught bug class): a package_name that doesn't
    match Android's package-identifier format must be rejected by
    validate_package_name() BEFORE it ever reaches Adb.force_stop -- a
    stronger, earlier check than shlex.quote()-ing it (which is still also
    applied, as defense in depth, for the one call site's host-shell
    boundary).
    """
    called = []
    monkeypatch.setattr(Adb, "force_stop", staticmethod(called.append))

    with pytest.raises(ToolExecutionError, match="invalid package_name"):
        process_control.kill_process(package_name="com.example.app; rm -rf /")

    assert called == []


def test_kill_process_package_path_quotes_a_valid_package_name(monkeypatch):
    captured = {}

    def fake_force_stop(package_name):
        captured["package_name"] = package_name
        return True, "ok"

    monkeypatch.setattr(Adb, "force_stop", staticmethod(fake_force_stop))

    process_control.kill_process(package_name="com.example.app")

    assert captured["package_name"] == "com.example.app"


# -- kill_process: pid path (kill_pid) -------------------------------------------------


def test_kill_process_pid_path_success(monkeypatch):
    monkeypatch.setattr(
        Adb, "kill_pid", staticmethod(lambda pid, signal="TERM": (True, False))
    )

    result = process_control.kill_process(pid=42)

    assert result == {
        "method": "kill_pid",
        "pid": 42,
        "signal": "TERM",
        "killed": True,
        "used_root": False,
    }


def test_kill_process_pid_path_forwards_signal(monkeypatch):
    captured = {}

    def fake_kill_pid(pid, signal="TERM"):
        captured["pid"] = pid
        captured["signal"] = signal
        return True, True

    monkeypatch.setattr(Adb, "kill_pid", staticmethod(fake_kill_pid))

    result = process_control.kill_process(pid=7, signal="KILL")

    assert captured == {"pid": 7, "signal": "KILL"}
    assert result["used_root"] is True


def test_kill_process_pid_path_wraps_value_error(monkeypatch):
    def fake_kill_pid(pid, signal="TERM"):
        raise ValueError("unsupported signal 'BOGUS'")

    monkeypatch.setattr(Adb, "kill_pid", staticmethod(fake_kill_pid))

    with pytest.raises(ToolExecutionError, match="unsupported signal"):
        process_control.kill_process(pid=7, signal="BOGUS")


def test_kill_process_rejects_zero_pid(monkeypatch):
    """Regression: POSIX kill() gives pid 0 special process-group-wide
    semantics -- kill_process must reject it before ever reaching
    Adb.kill_pid.
    """
    called = []
    monkeypatch.setattr(
        Adb, "kill_pid", staticmethod(lambda pid, signal="TERM": called.append(pid))
    )

    with pytest.raises(ToolExecutionError, match="positive integer"):
        process_control.kill_process(pid=0)

    assert called == []


def test_kill_process_rejects_negative_pid(monkeypatch):
    """Regression: a negative pid means "every process in that process
    group" under POSIX kill() semantics -- kill_process must reject it
    before ever reaching Adb.kill_pid.
    """
    called = []
    monkeypatch.setattr(
        Adb, "kill_pid", staticmethod(lambda pid, signal="TERM": called.append(pid))
    )

    with pytest.raises(ToolExecutionError, match="positive integer"):
        process_control.kill_process(pid=-42)

    assert called == []
