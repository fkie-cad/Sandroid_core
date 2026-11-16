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
