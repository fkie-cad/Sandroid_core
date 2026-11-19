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


def _opened_fritap(monkeypatch, *, owns: bool, paused: bool = True):
    from sandroid.services import app_start

    ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
    ft.process_id = 4242
    ft._opened = app_start.Opened(4242, owns, paused, _Device(), "org.wikipedia")
    resumed: list = []

    def _resume(device, pid):
        resumed.append(pid)

    monkeypatch.setattr(
        "sandroid.services.get_frida_session_service",
        lambda: types.SimpleNamespace(resume_spawned_process=_resume),
    )
    monkeypatch.setattr(app_start, "_job_manager", lambda: None)
    monkeypatch.setattr(app_start, "apply_armed_after_launch", lambda tool: "")
    return ft, resumed


def test_own_spawn_is_resumed_after_the_agent_loaded(monkeypatch):
    monkeypatch.setattr(fritap_mod.time, "sleep", lambda s: None)
    ft, resumed = _opened_fritap(monkeypatch, owns=True)
    job = types.SimpleNamespace(state="running")  # AFM 2.0.7 Job shape
    ft._resume_spawned_target(None, job)
    assert resumed == [4242]


def test_a_joined_paused_app_is_never_resumed_by_fritap(monkeypatch):
    """Bug 3 / ownership: ⇧P then h joins the hold; Space resumes it."""
    ft, resumed = _opened_fritap(monkeypatch, owns=False, paused=True)
    note = ft._resume_spawned_target(None, types.SimpleNamespace(state="running"))
    assert resumed == []
    assert "still paused" in note


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
    def __init__(self, pid=None):
        self.pid = pid
        self.announced = []

    def get_app_tuple(self):
        return ("org.wikipedia", "")

    def get_pid(self):
        return self.pid

    def announce_pid(self, pid, package=None):
        self.announced.append(pid)
        self.pid = pid
        return True


def _attach_check(monkeypatch, maps=False, shared=False):
    monkeypatch.setattr(fritap_mod, "frida_agent_mapped", lambda pid: maps)
    ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
    ft.job_manager = types.SimpleNamespace(
        has_active_session=lambda: shared, running_jobs=lambda: [1] if shared else []
    )
    return ft


def _decision(action: str, pid=7):
    from sandroid.services.app_start import StartAction, StartDecision

    return StartDecision(StartAction(action), "org.wikipedia", pid=pid)


def test_reattach_to_injected_pid_is_refused(monkeypatch, _fresh_pids):
    fritap_mod.remember_injected_pid(10588)
    ft = _attach_check(monkeypatch)
    with pytest.raises(fritap_mod.FriTapTargetError, match="Restart the app"):
        ft._check_attach_target(_decision("attach", 10588))
    with pytest.raises(fritap_mod.FriTapTargetError, match="already ran"):
        ft._check_attach_target(_decision("join", 10588))
    fritap_mod.forget_injected_pid(10588)
    ft._check_attach_target(_decision("attach", 10588))  # forgotten -> allowed


def test_leftover_agent_in_maps_is_refused(monkeypatch, _fresh_pids):
    ft = _attach_check(monkeypatch, maps=True)
    with pytest.raises(fritap_mod.FriTapTargetError, match="earlier session"):
        ft._check_attach_target(_decision("attach"))


def test_live_agent_of_another_tool_is_allowed(monkeypatch, _fresh_pids):
    ft = _attach_check(monkeypatch, maps=True, shared=True)
    ft._check_attach_target(_decision("attach"))


def test_a_join_skips_the_agent_mapped_check(monkeypatch, _fresh_pids):
    """Our own session (⇧P hold, bypass) carries an agent by design."""
    ft = _attach_check(monkeypatch, maps=True)
    ft._check_attach_target(_decision("join"))


def test_a_spawn_skips_the_attach_check(monkeypatch, _fresh_pids):
    fritap_mod.remember_injected_pid(7)
    ft = _attach_check(monkeypatch, maps=True)
    ft._check_attach_target(_decision("spawn", None))
    ft._check_attach_target(_decision("respawn", None))
    fritap_mod.forget_injected_pid(7)


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


# ---------------------------------------------------------------------------
# Phase-4 M2: an agent unload that never finishes leaves the app frozen
# ---------------------------------------------------------------------------


def _hung_stop(monkeypatch, *, mode, pidof="4242", release_after=None):
    """Stop friTap with an unload that hangs; return (adb calls, warnings)."""
    import threading

    from sandroid.core.adb import Adb

    monkeypatch.setattr(fritap_mod, "_STOP_TIMEOUT", 0.1)
    monkeypatch.setattr(fritap_mod, "_HUNG_UNLOAD_GRACE", 0.3)
    adb_calls = []

    def fake_adb(cmd, *a, **k):
        adb_calls.append(cmd)
        return (pidof + "\n", "") if "pidof" in cmd else ("", "")

    monkeypatch.setattr(Adb, "send_adb_command", fake_adb)
    published = []
    monkeypatch.setattr(
        fritap_mod, "_publish_fritap_event", lambda bus, msg: published.append(msg)
    )
    block = threading.Event()
    ft, _job_ = _fritap_with_job([], block)
    ft.mode = mode
    ft.process_id = 4242
    ft.app_package = "org.wikipedia"
    ft.stop()
    if release_after is not None:
        threading.Timer(release_after, block.set).start()
    for thread in threading.enumerate():
        if thread.name == "fritap-unload-watchdog":
            thread.join(5)
    block.set()
    return adb_calls, published


def test_hung_unload_force_stops_a_spawned_app(monkeypatch):
    adb_calls, published = _hung_stop(monkeypatch, mode="spawn")

    assert adb_calls == [
        "shell pidof org.wikipedia",
        "shell am force-stop org.wikipedia",
    ]
    assert "was force-stopped" in published[0]


def test_hung_unload_of_attached_app_only_tells_how_to_recover(monkeypatch):
    adb_calls, published = _hung_stop(monkeypatch, mode="attach")

    assert adb_calls == []
    assert "adb shell am force-stop org.wikipedia" in published[0]
    assert "isn't responding" in published[0]


def test_late_but_finished_unload_leaves_the_app_alone(monkeypatch):
    adb_calls, published = _hung_stop(monkeypatch, mode="spawn", release_after=0.05)

    assert adb_calls == []
    assert published == []


def test_restarted_app_is_not_force_stopped(monkeypatch):
    adb_calls, published = _hung_stop(monkeypatch, mode="spawn", pidof="5555")

    assert adb_calls == ["shell pidof org.wikipedia"]
    assert "Shift+R" in published[0]


# ---------------------------------------------------------------------------
# Fix round 3 (live Network-lens test): lifecycle, freeze watch, quit hang
# ---------------------------------------------------------------------------


@pytest.fixture
def _lifecycle_events(monkeypatch):
    """Capture friTap STATE_CHANGED events; reset the phase afterwards."""
    from sandroid.core.events import EventBus, EventType

    seen: list[tuple[str, str]] = []

    def _cb(event) -> None:
        if event.source == "fritap":
            seen.append((event.data["phase"], event.data["detail"]))

    bus = EventBus.get()
    bus.subscribe(EventType.STATE_CHANGED, _cb)
    fritap_mod.set_lifecycle("stopped", "")
    seen.clear()
    yield seen
    bus.unsubscribe(EventType.STATE_CHANGED, _cb)
    fritap_mod.set_lifecycle("stopped", "")


def test_stop_reports_stopping_then_stopped(monkeypatch, _lifecycle_events):
    """M3: the tab said "running" for ~20 s after h (the unload wait)."""
    adb_calls, _published = _hung_stop(monkeypatch, mode="attach")
    phases = [phase for phase, _detail in _lifecycle_events]
    assert phases[:2] == ["stopping", "stopped"]
    assert _lifecycle_events[1][1] == "agent still unloading"
    # ...and the unload that never finished marks the app as frozen.
    assert fritap_mod.lifecycle()[0] == "failed"
    assert "app frozen" in fritap_mod.lifecycle()[1]


def test_lifecycle_events_only_on_change(_lifecycle_events):
    fritap_mod.set_lifecycle("starting", "org.wikipedia")
    fritap_mod.set_lifecycle("starting", "org.wikipedia")
    fritap_mod.set_lifecycle("running", "org.wikipedia")
    assert _lifecycle_events == [
        ("starting", "org.wikipedia"),
        ("running", "org.wikipedia"),
    ]


def test_app_not_responding_reads_the_anr_window(monkeypatch):
    from sandroid.core.adb import Adb

    out = {"text": "  Window #5 Window{a u0 Application Not Responding: org.wikipedia}"}
    monkeypatch.setattr(Adb, "send_adb_command", lambda cmd, *a, **k: (out["text"], ""))
    assert fritap_mod.app_not_responding("org.wikipedia") is True
    assert fritap_mod.app_not_responding("com.other") is False
    out["text"] = ""
    assert fritap_mod.app_not_responding("org.wikipedia") is None
    assert fritap_mod.app_not_responding(None) is None


def test_freeze_watch_warns_once_and_recovers(monkeypatch, _lifecycle_events):
    """M3: friTap froze Wikipedia and nothing said so until the stop."""
    import threading
    import time as _time

    states = iter([True, True, False])
    monkeypatch.setattr(fritap_mod, "_ANR_POLL_SECONDS", 0.01)
    monkeypatch.setattr(
        fritap_mod, "app_not_responding", lambda pkg: next(states, False)
    )
    published = []
    monkeypatch.setattr(
        fritap_mod, "_publish_fritap_event", lambda bus, msg: published.append(msg)
    )
    ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
    ft.app_package = "org.wikipedia"
    ft._stopping = ft._stopped = False
    ft._start_anr_watch()
    deadline = _time.monotonic() + 3
    while _time.monotonic() < deadline and ("running", "org.wikipedia") not in (
        _lifecycle_events
    ):
        _time.sleep(0.02)
    ft._stopped = True
    for thread in threading.enumerate():
        if thread.name == "fritap-anr-watch":
            thread.join(2)
    assert len(published) == 1
    assert "not responding while friTap is attached" in published[0]
    assert "Press h to stop friTap" in published[0]
    assert [p for p, _ in _lifecycle_events] == ["hung", "running"]


def test_cancelled_config_is_not_a_failure(monkeypatch):
    """L11: Esc in the friTap config logged "Command 'h' failed"."""
    from sandroid.commands.base import CommandContext
    from sandroid.commands.network_commands import FriTapCommand

    monkeypatch.setattr(
        fritap_mod.FriTap, "__init__", lambda self, **kw: setattr(self, "_x", 1)
    )

    def _start(self, interactive=True):
        self.cancelled = True
        return False

    monkeypatch.setattr(fritap_mod.FriTap, "start", _start)
    ctx = CommandContext(toolbox=object())
    result = FriTapCommand()._start_fritap(ctx)
    assert not result.success
    assert result.error == "cancelled"
    assert "cancelled" in result.message


def test_afm_job_threads_are_daemon_threads():
    """H1: a non-daemon "invoke_handle_hooking" thread kept the process alive."""
    import threading

    from AndroidFridaManager.job import Job

    from sandroid.core.frida_manager import daemonize_afm_job_threads

    assert daemonize_afm_job_threads()
    assert daemonize_afm_job_threads()  # idempotent
    done = threading.Event()
    fake = types.SimpleNamespace(job_id="abcdef123456", invoke_handle_hooking=done.set)
    Job.run_job_as_thread(fake)
    fake.thread.join(2)
    assert done.is_set()
    assert fake.thread.daemon


def test_current_session_detach_is_published_for_the_frida_pill():
    """E2E round 3 (N2): after ``kill -9 frida-server`` the pill stayed
    "● running" for 37 s+; only a log line said "connection-terminated".
    """
    from sandroid.core.events import EventBus, EventType
    from sandroid.core.frida_manager import install_stale_detach_guard

    jm = _AfmJobManager()
    install_stale_detach_guard(jm)
    old = jm._attach_with_detach_handler(1111)
    new = jm._attach_with_detach_handler(2222)
    seen: list = []

    def _cb(event):
        if event.data.get("change_type") == "frida_detached":
            seen.append((event.data["reason"], event.data["server_lost"]))

    EventBus.get().subscribe(EventType.STATE_CHANGED, _cb)
    try:
        old.fire("connection-terminated")  # a previous session: not news
        new.fire("process-terminated")  # the app died, the server is fine
        new2 = jm._attach_with_detach_handler(3333)
        new2.fire("connection-terminated")  # frida-server killed
    finally:
        EventBus.get().unsubscribe(EventType.STATE_CHANGED, _cb)
    assert seen == [
        ("process-terminated", False),
        ("connection-terminated", True),
    ]
