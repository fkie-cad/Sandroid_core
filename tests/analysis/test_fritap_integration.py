"""friTap 2.6.x integration: API surface, output finalisation, message formatting."""

from __future__ import annotations

import json
import types

import pytest

from sandroid.analysis import fritap as fritap_mod
from sandroid.analysis.fritap_formatter import FriTapMessageFormatter


def test_fritap_legacy_api_used_by_sandroid_exists():
    """The SSL_Logger surface Sandroid drives through AFM's JobManager."""
    from friTap import SSL_Logger

    for name in (
        "on_fritap_message",
        "get_agent_script_path",
        "close_output_handlers",
        "_finalize_json_output",
    ):
        assert callable(getattr(SSL_Logger, name, None)), name


def test_json_output_is_assembled_on_finalize(tmp_path):
    """FriTap >= 2.6 only assembles the JSON document when handlers close.

    Regression for the live run where fritap_output.json kept its empty
    start-time skeleton and all events stayed in the .events.jsonl sidecar.
    """
    from friTap import SSL_Logger

    json_path = tmp_path / "fritap_output.json"
    keylog_path = tmp_path / "fritap_keylog.log"
    ssl_log = SSL_Logger(1234, keylog=str(keylog_path), json_output=str(json_path))
    line = "CLIENT_RANDOM " + "ab" * 32 + " " + "cd" * 48
    ssl_log.on_fritap_message(
        None,
        {"type": "send", "payload": {"contentType": "keylog", "keylog": line}},
        None,
    )

    ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
    ft.ssl_log = ssl_log
    ft._finalize_outputs()
    ft._finalize_outputs()  # idempotent (headless calls stop() twice)

    assert line in keylog_path.read_text()
    doc = json.loads(json_path.read_text())
    assert doc["key_extractions"], doc
    assert not (tmp_path / "fritap_output.json.events.jsonl").exists()


class _Script:
    def __init__(self, calls, block=None):
        self.calls = calls
        self.block = block

    def unload(self):
        if self.block is not None:
            self.block.wait(10)  # a hooked SSL_read that never returns
        self.calls.append("unload")


def _job(calls, block=None):
    import threading

    return types.SimpleNamespace(
        state="running", stop_event=threading.Event(), script=_Script(calls, block)
    )


def _fritap_with_job(calls, block=None):
    ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
    ft.show_in_activity_log = False
    ft.job_id = ALIVE
    ft.app_package = "com.example"
    ft._get_toolbox = lambda: types.SimpleNamespace(unregister_frida_hooks=lambda j: 0)
    job = _job(calls, block)
    ft.job_manager = types.SimpleNamespace(
        jobs={ALIVE: job},
        process_session=types.SimpleNamespace(detach=lambda: calls.append("detach")),
        get_job_by_id=lambda j: job,
        unregister_hooks=lambda j: calls.append("unregister"),
    )
    ft.ssl_log = types.SimpleNamespace(
        close_output_handlers=lambda: calls.append("close_handlers"),
        _finalize_json_output=lambda: calls.append("finalize_json"),
    )
    return ft, job


def test_stop_finalizes_after_detaching():
    calls = []
    ft, job = _fritap_with_job(calls)
    ft.stop()
    assert calls == [
        "unload",
        "detach",
        "unregister",
        "close_handlers",
        "finalize_json",
    ]
    assert job.stop_event.is_set()
    assert job.state == "stopped"
    assert ft.job_manager.jobs == {}
    assert ft.job_manager.process_session is None


def test_stop_is_bounded_when_unload_hangs(monkeypatch):
    """P2 friTap stop: unload blocked by a hooked call -> still one quick stop."""
    import threading
    import time

    monkeypatch.setattr(fritap_mod, "_STOP_TIMEOUT", 0.3)
    calls = []
    block = threading.Event()
    ft, _job_ = _fritap_with_job(calls, block)
    t0 = time.monotonic()
    ft.stop()
    assert time.monotonic() - t0 < 3
    assert "close_handlers" in calls
    assert "finalize_json" in calls
    assert ft.job_manager.jobs == {}
    # Late agent messages are dropped once the outputs are closed.
    seen = []
    ft.print_to_console = False
    handler = ft._create_activity_log_wrapper(lambda *a: seen.append(a))
    handler(None, {"type": "send", "payload": {}}, None)
    assert seen == []
    block.set()


def test_stop_keeps_session_for_other_tools():
    calls = []
    ft, _job_ = _fritap_with_job(calls)
    ft.job_manager.jobs["other"] = types.SimpleNamespace(state="running")
    ft.stop()
    assert "detach" not in calls
    assert ft.job_manager.process_session is not None
    assert list(ft.job_manager.jobs) == ["other"]


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            {"src_addr": 167772687, "dst_addr": 2398776971, "ss_family": "AF_INET"},
            "10.0.2.15:47204 → 142.250.110.139:443",
        ),
        (
            {"src_addr": "10.0.2.15", "dst_addr": "1.2.3.4", "ss_family": "AF_INET"},
            "10.0.2.15:47204 → 1.2.3.4:443",
        ),
        (
            {
                "src_addr": "2001:db8::1",
                "dst_addr": "2001:db8::2",
                "ss_family": "AF_INET6",
            },
            "2001:db8::1:47204 → 2001:db8::2:443",
        ),
    ],
)
def test_datalog_addresses_are_human_readable(payload, expected):
    message = {
        "type": "send",
        "payload": {
            "contentType": "datalog",
            "function": "SSL_write",
            "src_port": 47204,
            "dst_port": 443,
            **payload,
        },
    }
    out = FriTapMessageFormatter.format_message(message, b"x" * 70)
    assert out == f"[SSL_write] {expected} (70 bytes)"


def test_console_detection():
    console = {"type": "send", "payload": {"contentType": "console", "console": "x"}}
    keylog = {"type": "send", "payload": {"contentType": "keylog", "keylog": "x"}}
    assert fritap_mod._is_console_message(console)
    assert not fritap_mod._is_console_message(keylog)
    assert not fritap_mod._is_console_message({"type": "error"})


# --- H1: spawn done outside JobManager must still be resumed -----------------


class _Device:
    def __init__(self):
        self.resumed = []

    def resume(self, pid):
        self.resumed.append(pid)


def _spawned_fritap(paused_in_jm: bool):
    ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
    ft.process_id = 4242
    ft._spawn_device = _Device()
    ft.frida_device = object()
    ft.job_manager = types.SimpleNamespace(is_paused=lambda: paused_in_jm)
    return ft


def test_spawned_target_is_resumed_when_jobmanager_did_not_spawn(monkeypatch):
    monkeypatch.setattr(fritap_mod.time, "sleep", lambda s: None)
    ft = _spawned_fritap(paused_in_jm=False)
    toolbox = types.SimpleNamespace(
        resume_spawned_process_after_hooks=lambda *a: pytest.fail("A2 path used")
    )
    job = types.SimpleNamespace(state="running")  # AFM 2.0.7 Job shape
    ft._resume_spawned_target(toolbox, job)
    assert ft._spawn_device.resumed == [4242]


def test_jobmanager_owned_spawn_uses_existing_resume_path():
    ft = _spawned_fritap(paused_in_jm=True)
    calls = []
    toolbox = types.SimpleNamespace(
        resume_spawned_process_after_hooks=lambda dev, pid: calls.append(pid)
    )
    ft._resume_spawned_target(toolbox, types.SimpleNamespace())
    assert calls == [4242]
    assert ft._spawn_device.resumed == []


# --- H2: hooks of dead jobs ----------------------------------------------------

DEAD = "11111111-2222-3333-4444-555555555555"
ALIVE = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ERRORED = "99999999-8888-7777-6666-555555555555"


def test_prune_dead_hook_owners():
    jobs = {
        ALIVE: types.SimpleNamespace(get_state=lambda: "running"),
        ERRORED: types.SimpleNamespace(get_state=lambda: "error"),
    }

    def get_job_by_id(job_id):
        if job_id not in jobs:
            raise ValueError(job_id)
        return jobs[job_id]

    ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
    ft.job_manager = types.SimpleNamespace(get_job_by_id=get_job_by_id)
    unregistered = []
    toolbox = types.SimpleNamespace(unregister_frida_hooks=unregistered.append)
    conflicts = {
        "SSL_read": DEAD,
        "SSL_write": ERRORED,
        "SSL_new": ALIVE,
        "open": "malwaremonitor-1a2b3c4d",  # virtual id: never pruned
    }
    left = ft._prune_dead_hook_owners(toolbox, conflicts)
    assert sorted(unregistered) == sorted([DEAD, ERRORED])
    assert left == {"SSL_new": ALIVE, "open": "malwaremonitor-1a2b3c4d"}


def test_stop_unregisters_its_hooks():
    ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
    ft.show_in_activity_log = False
    ft.job_id = ALIVE
    ft.app_package = "com.example"
    ft.ssl_log = None
    ft.job_manager = types.SimpleNamespace(
        get_job_by_id=lambda j: types.SimpleNamespace(get_state=lambda: "running"),
        jobs={},
        process_session=None,
    )
    unregistered = []
    ft._get_toolbox = lambda: types.SimpleNamespace(
        unregister_frida_hooks=unregistered.append
    )
    ft.stop()
    assert unregistered == [ALIVE]


def test_target_problem_reports_dead_job():
    ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
    ft.job_id = ALIVE
    state = {"s": "running", "session": True}
    ft.job_manager = types.SimpleNamespace(
        get_job_by_id=lambda j: types.SimpleNamespace(
            get_state=lambda: state["s"], get_error=lambda: "TransportError"
        ),
        has_active_session=lambda: state["session"],
    )
    assert ft.target_problem() is None
    state["session"] = False
    assert ft.target_problem() == "target process gone"
    state["s"] = "error"
    assert ft.target_problem() == "TransportError"


# --- Phase 3: stale detach, re-attach guard, target death, per-session files --


class _Session:
    def __init__(self):
        self.handlers = []
        self.detached = False

    def on(self, signal, cb):
        assert signal == "detached"
        self.handlers.append(cb)

    def fire(self, reason, crash=None):
        for cb in self.handlers:
            cb(reason, crash)

    def detach(self):
        self.detached = True


class _AfmJobManager:
    """Shape of AFM 2.0.7's JobManager detach handling."""

    def __init__(self):
        self.jobs = {}
        self.process_session = None
        self._paused = True
        self.device = types.SimpleNamespace(attach=lambda target: _Session())

    def _attach_with_detach_handler(self, target):  # replaced by the guard
        raise AssertionError("unguarded attach")

    def _on_session_detached(self, reason, crash):
        self.process_session = None
        self._paused = False
        for job in self.jobs.values():
            if job.state == "running":
                job._set_state("error", f"session detached: {reason}")


class _AfmJob:
    def __init__(self, session):
        self.process_session = session
        self.state = "running"

    def _set_state(self, state, msg=None):
        self.state = state


def test_detach_of_previous_session_is_ignored():
    """Spawn cycles 2-5: the old PID's detach must not fail the new job."""
    from sandroid.core.frida_manager import install_stale_detach_guard

    jm = _AfmJobManager()
    assert install_stale_detach_guard(jm)
    assert install_stale_detach_guard(jm)  # idempotent
    old = jm._attach_with_detach_handler(1111)
    old_job = _AfmJob(old)
    new = jm._attach_with_detach_handler(2222)
    new_job = _AfmJob(new)
    jm.jobs = {"old": old_job, "new": new_job}
    assert jm.process_session is new

    old.fire("process-terminated")
    assert jm.process_session is new
    assert new_job.state == "running"
    assert old_job.state == "error"

    new.fire("process-terminated", types.SimpleNamespace(summary="SIGSEGV\nmore"))
    assert jm.process_session is None
    assert new_job.state == "error"


@pytest.fixture
def _fresh_pids(monkeypatch):
    monkeypatch.setattr(fritap_mod, "_INJECTED_PIDS", {})
    monkeypatch.setattr(fritap_mod, "_device_key", lambda: "emulator-5556")


class _Spotlight:
    def __init__(self, pid=None, spawn=False):
        self.pid = pid
        self.spawn = spawn
        self.announced = []

    def is_spawn_mode(self):
        return self.spawn

    def get_spawn_package(self):
        return "org.wikipedia" if self.spawn else None

    def get_app_tuple(self):
        return ("org.wikipedia", "")

    def get_pid(self):
        return self.pid

    def announce_pid(self, pid, package=None):
        self.announced.append(pid)
        self.pid = pid
        return True


def _attach_check(monkeypatch, spotlight, live_pid, maps=False, shared=False):
    from sandroid import services
    from sandroid.core.adb import Adb

    monkeypatch.setattr(services, "get_spotlight_service", lambda: spotlight)
    monkeypatch.setattr(
        Adb, "get_pid_for_package_name", classmethod(lambda cls, p, **k: live_pid)
    )
    monkeypatch.setattr(fritap_mod, "frida_agent_mapped", lambda pid: maps)
    ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
    ft.job_manager = types.SimpleNamespace(
        has_active_session=lambda: shared, running_jobs=lambda: [1] if shared else []
    )
    return ft


def test_attach_reresolves_a_stale_pid(monkeypatch, _fresh_pids):
    spot = _Spotlight(pid=9756)
    _attach_check(monkeypatch, spot, live_pid=10588)._check_attach_target()
    assert spot.announced == [10588]


def test_attach_to_dead_app_is_refused_and_pid_cleared(monkeypatch, _fresh_pids):
    spot = _Spotlight(pid=9756)
    ft = _attach_check(monkeypatch, spot, live_pid=None)
    with pytest.raises(fritap_mod.FriTapTargetError, match="not running"):
        ft._check_attach_target()
    assert spot.pid is None


def test_reattach_to_injected_pid_is_refused(monkeypatch, _fresh_pids):
    fritap_mod.remember_injected_pid(10588)
    ft = _attach_check(monkeypatch, _Spotlight(pid=10588), live_pid=10588)
    with pytest.raises(fritap_mod.FriTapTargetError, match="spawn mode"):
        ft._check_attach_target()
    fritap_mod.forget_injected_pid(10588)
    ft._check_attach_target()  # process gone/forgotten -> allowed again


def test_leftover_agent_in_maps_is_refused(monkeypatch, _fresh_pids):
    ft = _attach_check(monkeypatch, _Spotlight(pid=7), live_pid=7, maps=True)
    with pytest.raises(fritap_mod.FriTapTargetError, match="earlier session"):
        ft._check_attach_target()


def test_live_agent_of_another_tool_is_allowed(monkeypatch, _fresh_pids):
    ft = _attach_check(monkeypatch, _Spotlight(pid=7), 7, maps=True, shared=True)
    ft._check_attach_target()


def test_spawn_mode_skips_the_attach_check(monkeypatch, _fresh_pids):
    ft = _attach_check(monkeypatch, _Spotlight(pid=1, spawn=True), live_pid=None)
    ft._check_attach_target()


def test_frida_agent_mapped_reads_proc_maps(monkeypatch):
    from sandroid.core.adb import Adb

    cmds = []

    def fake(cls, cmd, serial=None):
        cmds.append(cmd)
        return ("2\n", "") if "su 0" not in cmd else ("", "")

    monkeypatch.setattr(Adb, "send_adb_command", classmethod(fake))
    assert fritap_mod.frida_agent_mapped(42) is True
    assert cmds == ["shell grep -c frida-agent /proc/42/maps"]


def test_session_files_never_overwrite(tmp_path, monkeypatch):
    monkeypatch.setattr(fritap_mod.time, "strftime", lambda fmt: "20261116_193000")
    d = str(tmp_path) + "/"
    first = fritap_mod._session_stamp(d)
    (tmp_path / f"fritap_keylog_{first}.log").write_text("keys")
    second = fritap_mod._session_stamp(d)
    assert first == "20261116_193000"
    assert second == "20261116_193000_2"


class _TaskService:
    def __init__(self):
        self.tasks = {}
        self.stopped = []

    def get_task(self, name):
        return self.tasks.get(name)

    def stop(self, name):
        task = self.tasks.pop(name)
        self.stopped.append(name)
        task.stop_callback()
        return True


def test_stop_stops_the_fritap_network_capture(monkeypatch):
    calls = []
    ft, _job_ = _fritap_with_job(calls)
    net = types.SimpleNamespace(stop=lambda: calls.append("net_stop"))
    ft._network_instance = net
    ft.network_capture_path = None
    tasks = _TaskService()
    tasks.tasks["network"] = types.SimpleNamespace(instance=net, stop_callback=net.stop)
    monkeypatch.setattr(fritap_mod, "get_task_service", lambda: tasks)
    ft.stop()
    ft.stop()  # idempotent
    assert tasks.stopped == ["network"]
    assert calls.count("net_stop") == 1
    assert calls.index("finalize_json") < calls.index("net_stop")


def test_target_death_stops_fritap_and_clears_pid(monkeypatch, _fresh_pids):
    from sandroid import services

    calls = []
    ft, _job_ = _fritap_with_job(calls)
    ft.process_id = 4242
    fritap_mod.remember_injected_pid(4242)
    spot = _Spotlight(pid=4242)
    monkeypatch.setattr(services, "get_spotlight_service", lambda: spot)
    tasks = _TaskService()
    tasks.tasks["fritap"] = types.SimpleNamespace(instance=ft, stop_callback=ft.stop)
    monkeypatch.setattr(fritap_mod, "get_task_service", lambda: tasks)
    monkeypatch.setattr(fritap_mod, "_publish_fritap_event", lambda *a: None)

    ft._handle_target_death("process-terminated", None)
    assert tasks.stopped == ["fritap"]
    assert "finalize_json" in calls
    assert spot.pid is None
    assert not fritap_mod.was_injected(4242)
    assert ft.target_gone == "process-terminated"


def test_own_detach_and_post_stop_detach_are_ignored(monkeypatch):
    started = []
    monkeypatch.setattr(
        fritap_mod.threading,
        "Thread",
        lambda **kw: types.SimpleNamespace(start=lambda: started.append(kw)),
    )
    ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
    session = _Session()
    ft._watch_target(session)
    session.fire("application-requested")
    assert started == []
    session.fire("process-terminated")
    assert len(started) == 1
    ft._stopped = True
    session.fire("process-terminated")
    assert len(started) == 1


def test_spotlight_announce_pid_publishes():
    from sandroid.services.spotlight_service import SpotlightService

    events = []
    bus = types.SimpleNamespace(publish=events.append)
    svc = SpotlightService(event_bus=bus)
    svc.set_app("org.wikipedia", pid=3967)
    events.clear()
    assert svc.announce_pid(5927, "org.wikipedia")
    assert svc.get_pid() == 5927
    assert events[-1].data["pid"] == 5927
    assert not svc.announce_pid(5927, "org.wikipedia")  # unchanged: no event
    assert not svc.announce_pid(1, "com.other")  # other package: ignored
    assert svc.get_pid() == 5927
