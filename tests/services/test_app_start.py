"""The one start rule (sandroid.services.app_start) and its callers.

Covers the decision table, liveness (running / not running / unknown), the
restart confirmation, acting on a decision (open_session, owned resume), the
lifecycle functions behind Space/⇧P/⇧R/⇧A, and the regressions of the old
spawn/attach mode (bugs 1-5 of the selection brief). No device: adb, the
JobManager and the UI request bus are fakes.
"""

from __future__ import annotations

import threading
import time
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sandroid import services
from sandroid.services import app_start
from sandroid.services.app_start import (
    AppStartError,
    Liveness,
    Opened,
    StartAction,
    StartDecision,
    StartInputs,
    decide_start,
)
from sandroid.services.spotlight_service import SpotlightService

PKG = "org.wikipedia"


def _inputs(**kw) -> StartInputs:
    base = {"package": PKG, "liveness": Liveness.RUNNING, "live_pid": 77}
    base.update(kw)
    if base["liveness"] != Liveness.RUNNING and "live_pid" not in kw:
        base["live_pid"] = None
    return StartInputs(**base)


# -- decide_start: the table ---------------------------------------------------


@pytest.mark.parametrize(
    ("kw", "action", "extra"),
    [
        # R0: a start/restart is in flight.
        ({"busy": "⇧R restart of org.wikipedia in progress"}, "refuse", "busy"),
        # R0b: adb could not tell.
        ({"liveness": Liveness.UNKNOWN}, "refuse", "unknown"),
        # R1: a held spawn of ours: join it (also when fresh: it has not run).
        (
            {"session_pid": 77, "session_paused": True, "session_package": PKG},
            "join",
            "paused",
        ),
        (
            {"session_pid": 77, "session_paused": True, "fresh": True},
            "join",
            "paused",
        ),
        # R1 + #218: a Java agent may not join a held spawn with hooks.
        (
            {"session_pid": 77, "session_paused": True, "live_jobs": ("Bypass",)},
            "refuse",
            "paused_hooks",
        ),
        # R2: not running.
        ({"liveness": Liveness.NOT_RUNNING}, "spawn", "owns"),
        (
            {"liveness": Liveness.NOT_RUNNING, "allow_spawn": False},
            "refuse",
            "not_running",
        ),
        # R3/R4: running and fresh.
        ({"fresh": True}, "needs_confirm", ""),
        ({"fresh": True, "consent": True}, "respawn", "owns"),
        # R5: our live session on the running PID.
        ({"session_pid": 77}, "join", ""),
        # R6: attach.
        ({}, "attach", ""),
    ],
)
def test_decision_table(kw, action, extra):
    d = decide_start(_inputs(**kw))

    assert d.action == StartAction(action)
    if extra == "owns":
        assert d.owns_spawn is True
    elif extra == "paused":
        assert d.paused is True
        assert d.pid == 77
        assert not d.owns_spawn
    elif extra:
        assert d.code == extra
    if d.action in (StartAction.JOIN, StartAction.ATTACH):
        assert d.owns_spawn is False


def test_a_still_unnamed_held_spawn_is_joined_never_spawned():
    """Pidof cannot name a held spawn (zygote64 / <pre-initialized>)."""
    d = decide_start(
        _inputs(
            liveness=Liveness.NOT_RUNNING,
            session_pid=99,
            session_package=PKG,
            session_paused=True,
        )
    )
    assert d.action == StartAction.JOIN
    assert d.pid == 99
    assert d.paused


def test_a_paused_java_free_caller_joins_despite_hooks():
    d = decide_start(
        _inputs(
            session_pid=77,
            session_paused=True,
            live_jobs=("Bypass",),
            java_agent=False,
        )
    )
    assert d.action == StartAction.JOIN
    assert d.paused


def test_a_live_session_on_another_process_with_jobs_is_refused():
    """Never a blanket reset_session that kills another target's live jobs."""
    d = decide_start(_inputs(session_pid=12, live_jobs=("FriTap SSL Logger",)))
    assert d.action == StartAction.REFUSE
    assert d.code == "frida_busy"
    assert "FriTap SSL Logger" in d.reason
    d = decide_start(
        _inputs(liveness=Liveness.NOT_RUNNING, session_pid=12, live_jobs=("Dexray",))
    )
    assert d.action == StartAction.REFUSE
    assert d.code == "frida_busy"


def test_an_idle_or_dead_session_is_dropped_before_attach_or_spawn():
    d = decide_start(_inputs(session_pid=12, has_session=True))
    assert d.action == StartAction.ATTACH
    assert d.reset_session
    d = decide_start(_inputs(has_session=True))  # dead: no live session PID
    assert d.action == StartAction.ATTACH
    assert d.reset_session
    d = decide_start(_inputs(liveness=Liveness.NOT_RUNNING, has_session=True))
    assert d.action == StartAction.SPAWN
    assert d.reset_session


def test_needs_confirm_names_the_tools_a_restart_stops():
    d = decide_start(
        _inputs(fresh=True, app_tools=("Dexray-Intercept", "Bypass: SSL"), tool="X")
    )
    assert d.action == StartAction.NEEDS_CONFIRM
    assert d.stops == ("Dexray-Intercept", "Bypass: SSL")
    assert "This stops: Dexray-Intercept, Bypass: SSL." in d.reason
    assert "(pid 77)" in d.reason


def test_fresh_tool_on_a_running_app_needs_confirmation():
    d = decide_start(_inputs(fresh=True, tool="Objection"))
    assert d.action == StartAction.NEEDS_CONFIRM


def test_initialized_jobs_count_as_live():
    jm = SimpleNamespace(
        jobs={
            "a": SimpleNamespace(state="initialized", display_name="FriTap"),
            "b": SimpleNamespace(state="stopped", display_name="Old"),
            "c": SimpleNamespace(state="error", display_name="Dead"),
            "d": SimpleNamespace(state="running", display_name="Bypass"),
        }
    )
    assert app_start.live_job_names(jm) == ("FriTap", "Bypass")


def test_session_pid_reads_the_attach_session():
    """AFM sets no jm.pid on attach: the PID is on the frida session."""
    jm = SimpleNamespace(
        has_active_session=lambda: True,
        process_session=SimpleNamespace(_impl=SimpleNamespace(pid=321)),
        pid=-1,
        package_name=321,
    )
    assert app_start.session_pid(jm) == 321
    jm.has_active_session = lambda: False
    assert app_start.session_pid(jm) is None


# -- probe_liveness ------------------------------------------------------------


@pytest.fixture
def adb(monkeypatch):
    from sandroid.core.adb import Adb

    answers: dict[str, tuple[str, str]] = {}

    def send(cmd, *a, **k):
        for prefix, answer in answers.items():
            if cmd.startswith(prefix):
                return answer
        return "", ""

    monkeypatch.setattr(Adb, "send_adb_command", staticmethod(send))
    return answers


def test_probe_liveness_running(adb):
    adb["shell pidof"] = ("4242\n", "")
    assert app_start.probe_liveness(PKG) == (Liveness.RUNNING, 4242)


def test_probe_liveness_not_running(adb):
    adb["shell pidof"] = ("", "")
    assert app_start.probe_liveness(PKG) == (Liveness.NOT_RUNNING, None)


def test_probe_liveness_adb_error_is_unknown(adb):
    adb["shell pidof"] = ("", "error: device offline")
    adb["shell ps -A"] = ("", "error: device offline")
    assert app_start.probe_liveness(PKG) == (Liveness.UNKNOWN, None)


def test_probe_liveness_without_pidof_reads_ps(adb):
    adb["shell pidof"] = ("", "/system/bin/sh: pidof: not found")
    adb["shell ps -A"] = (
        "USER PID PPID NAME\nu0_a1 555 1 org.wikipedia\nu0_a1 556 1 x.y\n",
        "",
    )
    assert app_start.probe_liveness(PKG) == (Liveness.RUNNING, 555)
    adb["shell ps -A"] = ("USER PID PPID NAME\nu0_a1 556 1 x.y\n", "")
    assert app_start.probe_liveness(PKG) == (Liveness.NOT_RUNNING, None)


# -- an environment with a real SpotlightService and a fake JobManager --------


class FakeJob:
    def __init__(self, state="running", display_name="job"):
        self.state = state
        self.display_name = display_name

    def wait_until_ready(self, timeout):
        return True

    def get_id(self):
        return "job-1"

    def get_script_of_job(self):
        return SimpleNamespace(
            is_destroyed=False,
            exports_sync=SimpleNamespace(
                set_flags=lambda flags: None, install_failures=list
            ),
        )

    def get_error(self):
        return None


class FakeJM:
    def __init__(self, *, session_pid=None, package_name="", paused=False):
        self.calls: list = []
        self.process_session = None
        self.pid = -1
        self.package_name = package_name
        self._paused = paused
        self.jobs: dict = {}
        self.device = SimpleNamespace(
            resume=lambda pid: self.calls.append(("resume", pid))
        )
        if session_pid:
            self._session(session_pid)

    def _session(self, pid):
        self.process_session = SimpleNamespace(_impl=SimpleNamespace(pid=pid))

    def has_active_session(self):
        return self.process_session is not None

    def is_paused(self):
        return self._paused

    def mark_resumed(self):
        self._paused = False

    def reset_session(self):
        self.calls.append("reset_session")
        self.process_session, self.jobs, self.pid = None, {}, -1

    def setup_frida_session(self, target, handler, should_spawn=True):
        self.calls.append(("setup_frida_session", target, should_spawn))
        if should_spawn:
            raise AssertionError("must never spawn through setup_frida_session")
        self.package_name = target
        self._session(target)

    def start_job(self, path, **kw):
        self.calls.append(("start_job", kw.get("job_type")))
        job = FakeJob(display_name=kw.get("display_name", "job"))
        self.jobs[job.get_id()] = job
        return job

    def stop_job_with_id(self, job_id):
        self.jobs.pop(job_id, None)

    def spawn_paused(self, package):
        raise AssertionError("must not spawn")


@pytest.fixture(autouse=True)
def _no_setup_owner():
    app_start._reset_setup()
    yield
    app_start._reset_setup()


@pytest.fixture
def env(monkeypatch):
    """Real SpotlightService + BypassService, fake JobManager/adb/tasks."""
    from sandroid.analysis import detection_bypass as db
    from sandroid.core.toolbox import Toolbox

    state = SimpleNamespace(
        jm=FakeJM(),
        live=(Liveness.NOT_RUNNING, None),
        tasks=[],
        stopped=[],
    )
    svc = SpotlightService(job_manager_factory=lambda: state.jm)
    svc.set_app(PKG)
    state.spotlight = svc
    monkeypatch.setattr(services, "get_spotlight_service", lambda: svc)
    monkeypatch.setattr(db, "get_spotlight_service", lambda: svc)
    monkeypatch.setattr(app_start, "_job_manager", lambda: state.jm)
    monkeypatch.setattr(
        Toolbox, "get_frida_job_manager", staticmethod(lambda: state.jm)
    )
    monkeypatch.setattr(
        app_start,
        "probe_liveness",
        lambda package, frida_fallback=False: state.live,
    )
    tasks = SimpleNamespace(
        get_running_tasks=lambda: list(state.tasks),
        stop=lambda name: state.stopped.append(name) or True,
        is_running=lambda name: False,
        register=lambda **kw: None,
        unregister=lambda name: None,
        update_display=lambda *a: None,
    )
    monkeypatch.setattr(services, "get_task_service", lambda: tasks)
    monkeypatch.setattr(db, "get_task_service", lambda: tasks)
    monkeypatch.setattr(db, "get_tool_usage_service", Mock)
    bypass = db.BypassService()
    monkeypatch.setattr(db, "_INSTANCE", bypass)
    state.bypass = bypass
    return state


def test_gather_inputs_announces_a_stale_cached_pid(env):
    env.spotlight.set_pid(9756)
    env.live = (Liveness.RUNNING, 10588)

    inputs = app_start.gather_inputs(PKG)

    assert inputs.live_pid == 10588
    assert env.spotlight.get_pid() == 10588


def test_a_tool_join_while_a_start_is_in_flight_is_refused(env):
    """R0: the lifecycle lock held by another thread (Space/⇧P/⇧R/AI)."""
    env.live = (Liveness.RUNNING, 77)
    held, release = threading.Event(), threading.Event()

    def _hold():
        assert app_start._LIFECYCLE.try_acquire()
        held.set()
        release.wait(5)
        app_start._LIFECYCLE.release()

    t = threading.Thread(target=_hold)
    t.start()
    held.wait(5)
    try:
        d = app_start.resolve_start(tool="friTap")
    finally:
        release.set()
        t.join(5)
    assert d.action == StartAction.REFUSE
    assert d.code == "busy"


# -- negotiate_start: the confirmation ----------------------------------------


def _in_worker(fn):
    out: dict = {}

    def run():
        try:
            out["value"] = fn()
        except BaseException as exc:  # re-raised below
            out["error"] = exc

    t = threading.Thread(target=run)
    t.start()
    t.join(10)
    if "error" in out:
        raise out["error"]
    return out["value"]


@pytest.fixture
def bus(monkeypatch):
    from sandroid.core import ui_request_bus

    state = SimpleNamespace(active=True, answer=True, asked=[])
    monkeypatch.setattr(
        ui_request_bus.UIRequestBus,
        "has_active_handler",
        lambda self: state.active,
    )

    def _request_modal(cls, **kw):
        state.asked.append((cls.__name__, kw))
        return state.answer

    monkeypatch.setattr(ui_request_bus, "request_modal", _request_modal)
    return state


@pytest.mark.parametrize(
    ("answer", "action", "code"),
    [
        (True, "respawn", ""),
        (False, "refuse", "declined"),
        (None, "refuse", "declined"),
    ],
)
def test_negotiate_asks_and_only_restart_respawns(env, bus, answer, action, code):
    env.live = (Liveness.RUNNING, 77)
    env.tasks = [
        SimpleNamespace(name="dexray-intercept", app_name=PKG, display_name="Dexray")
    ]
    bus.answer = answer

    d = _in_worker(lambda: app_start.negotiate_start("friTap", fresh=True))

    assert d.action == StartAction(action)
    assert d.code == code
    name, kw = bus.asked[0]
    assert name == "ConfirmModal"
    assert kw["title"] == f"Restart {PKG}?"
    assert kw["yes_label"] == "Restart"
    assert kw["no_label"] == "Keep running"
    assert kw["guard_typing"] is True
    assert "will stop" not in kw["message"]
    assert "This stops: Dexray." in kw["message"]
    if action == "refuse":
        assert d.reason == f"friTap not started — {PKG} keeps running."


def test_negotiate_without_ui_refuses_and_says_how(env, bus):
    env.live = (Liveness.RUNNING, 77)
    bus.active = False

    d = _in_worker(lambda: app_start.negotiate_start("friTap", fresh=True))

    assert d.action == StartAction.REFUSE
    assert d.code == "no_ui"
    assert "fresh=True" in d.reason
    assert bus.asked == []


def test_negotiate_with_consent_needs_no_dialog(env, bus):
    env.live = (Liveness.RUNNING, 77)

    d = _in_worker(
        lambda: app_start.negotiate_start("friTap", fresh=True, consent=True)
    )

    assert d.action == StartAction.RESPAWN
    assert bus.asked == []


def test_negotiate_on_the_ui_thread_refuses(env, bus):
    """request_modal from the UI thread would deadlock the event loop."""
    env.live = (Liveness.RUNNING, 77)
    assert threading.current_thread() is threading.main_thread()

    d = app_start.negotiate_start("friTap", fresh=True)

    assert d.action == StartAction.REFUSE
    assert d.code == "ui_thread"
    assert bus.asked == []


# -- open_session ---------------------------------------------------------------


def test_respawn_order_and_end_restart_on_failure(env, monkeypatch):
    from sandroid.core.adb import Adb

    order: list = []
    monkeypatch.setattr(app_start.time, "sleep", lambda s: None)
    monkeypatch.setattr(
        Adb, "force_stop", staticmethod(lambda pkg: order.append("force_stop"))
    )
    begin = env.spotlight.begin_restart
    monkeypatch.setattr(
        env.spotlight,
        "begin_restart",
        lambda pkg: (order.append("begin_restart"), begin(pkg)),
    )
    monkeypatch.setattr(
        env.bypass, "forget_process", lambda: order.append("forget_process")
    )
    env.jm.reset_session = lambda: order.append("reset_session")
    env.tasks = [
        SimpleNamespace(name="fritap", app_name=PKG, display_name="FriTap"),
        SimpleNamespace(name="bypass", app_name=PKG, display_name="Bypass"),
        SimpleNamespace(name="monitor", app_name=PKG, display_name="Monitor"),
    ]

    def _spawn(pkg):
        order.append("spawn_app_paused")
        return None, -1  # fails

    monkeypatch.setattr(env.spotlight, "spawn_app_paused", _spawn)
    d = StartDecision(StartAction.RESPAWN, PKG, owns_spawn=True)

    with pytest.raises(AppStartError):
        app_start.open_session(d)

    assert order == [
        "force_stop",
        "begin_restart",
        "forget_process",
        "reset_session",
        "spawn_app_paused",
    ]
    assert env.stopped == ["fritap"]  # tools stopped; bypass/monitor are not
    assert not env.spotlight.is_restarting()


def test_attach_drops_an_idle_session_first(env):
    env.jm = FakeJM(session_pid=12)
    d = StartDecision(StartAction.ATTACH, PKG, pid=77, reset_session=True)

    opened = app_start.open_session(d)

    assert env.jm.calls == ["reset_session", ("setup_frida_session", 77, False)]
    assert opened == Opened(77, False, False, env.jm.device, PKG)


def test_join_touches_nothing(env):
    """Bug 1: ⇧C, Space, h -- friTap joins the live session, no re-spawn."""
    env.jm = FakeJM(session_pid=77, package_name=PKG)
    env.live = (Liveness.RUNNING, 77)
    d = app_start.resolve_start(tool="friTap")
    assert d.action == StartAction.JOIN

    opened = app_start.open_session(d)

    assert env.jm.calls == []
    assert opened.pid == 77
    assert not opened.owns_spawn


def test_spawn_rechecks_liveness_and_never_kills(env, monkeypatch):
    """A config dialog passed since the decision: the app came up meanwhile."""
    monkeypatch.setattr(
        env.spotlight,
        "spawn_app_paused",
        lambda pkg: pytest.fail("spawned over a running app"),
    )
    env.live = (Liveness.RUNNING, 55)
    d = StartDecision(StartAction.SPAWN, PKG, owns_spawn=True, tool="Dexray")

    with pytest.raises(AppStartError, match="started meanwhile"):
        app_start.open_session(d)


def test_spawn_is_refused_while_the_lifecycle_is_busy(env):
    held = threading.Event()
    release = threading.Event()

    def _hold():
        app_start._LIFECYCLE.try_acquire()
        held.set()
        release.wait(5)
        app_start._LIFECYCLE.release()

    t = threading.Thread(target=_hold)
    t.start()
    held.wait(5)
    try:
        with pytest.raises(AppStartError, match="in progress"):
            app_start.open_session(StartDecision(StartAction.SPAWN, PKG))
    finally:
        release.set()
        t.join(5)


# -- finish_owned_spawn -----------------------------------------------------------


def test_not_owned_is_never_resumed(env, monkeypatch):
    resumed: list = []
    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(resume_spawned_process=lambda d, p: resumed.append(p)),
    )

    note = app_start.finish_owned_spawn(Opened(7, False, True))

    assert resumed == []
    assert note == "app still paused — ␣ resumes"


def test_owned_is_resumed_then_armed_bypasses_applied(env, monkeypatch):
    order: list = []
    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(
            resume_spawned_process=lambda d, p: order.append(("resume", p))
        ),
    )
    env.bypass._armed = {"root", "ssl"}
    monkeypatch.setattr(
        env.bypass, "apply_armed", lambda: (order.append("apply_armed"), (True, ""))[1]
    )

    note = app_start.finish_owned_spawn(Opened(7, True, True), tool="friTap")

    assert order == [("resume", 7), "apply_armed"]
    assert "startup" in note
    assert "␣ start first" in note
    assert "friTap" in note


# -- lifecycle (Space / ⇧P / ⇧R / ⇧A / AI) ---------------------------------------


def test_space_never_restarts_an_app_opened_from_the_launcher(env, monkeypatch):
    """The cached PID is None (poll window), but the app runs: no spawn."""
    monkeypatch.setattr(
        env.bypass,
        "apply_to_fresh_spawn_with_retry",
        lambda *a, **k: pytest.fail("Space spawned over a running app"),
    )
    env.live = (Liveness.RUNNING, 4242)

    ok, msg = app_start.start_app()

    assert ok is False
    assert "already running (pid 4242)" in msg
    assert env.spotlight.get_pid() == 4242


def test_space_on_an_adb_error_refuses(env, monkeypatch):
    monkeypatch.setattr(
        env.bypass,
        "apply_to_fresh_spawn_with_retry",
        lambda *a, **k: pytest.fail("spawned on an adb error"),
    )
    env.live = (Liveness.UNKNOWN, None)

    ok, msg = app_start.start_app()

    assert ok is False
    assert "Could not tell" in msg


def test_space_starts_a_stopped_app_with_the_ladder(env, monkeypatch):
    calls: list = []
    env.bypass._armed = {"ssl"}
    monkeypatch.setattr(
        env.bypass,
        "apply_to_fresh_spawn_with_retry",
        lambda pkg, cats, resume=True: calls.append((pkg, set(cats), resume))
        or (True, "Spawned"),
    )

    assert app_start.start_app(paused=True) == (True, "Spawned")
    assert calls == [(PKG, {"ssl"}, False)]


def test_lifecycle_refuses_while_busy(env):
    held, release = threading.Event(), threading.Event()

    def _hold():
        app_start._LIFECYCLE.try_acquire()
        held.set()
        release.wait(5)
        app_start._LIFECYCLE.release()

    t = threading.Thread(target=_hold)
    t.start()
    held.wait(5)
    try:
        assert app_start.start_app()[0] is False
        assert app_start.restart_app()[0] is False
    finally:
        release.set()
        t.join(5)


def test_resume_applies_bypasses_armed_while_paused(env, monkeypatch):
    env.jm = FakeJM(session_pid=77, package_name=PKG, paused=True)
    monkeypatch.setattr(env.spotlight, "resume_paused_app", lambda: True)
    env.bypass._armed = {"ssl"}
    applied: list = []
    monkeypatch.setattr(
        env.bypass, "apply_armed", lambda: applied.append(1) or (True, "Applied")
    )

    ok, msg = app_start.resume_app()

    assert ok
    assert applied == [1]
    assert "Applied" in msg


# -- bypass: never starts or restarts the app ----------------------------------


def test_b_on_a_running_app_attaches_never_spawns(env):
    """Bug 2: ⇧C on a running app, then b / Ctrl+P / AI unpin: attach."""
    env.live = (Liveness.RUNNING, 77)

    ok, msg = env.bypass.start("ssl")

    assert ok, msg
    setups = [c for c in env.jm.calls if c[0] == "setup_frida_session"]
    assert setups == [("setup_frida_session", 77, False)]


def test_ctrl_p_on_a_stopped_app_only_arms(env):
    """Q6: Ctrl+P / AI start_ssl_unpin arm a stopped app; ␣ starts it."""
    env.live = (Liveness.NOT_RUNNING, None)

    ok, msg = env.bypass.start("ssl")

    assert ok is True
    assert "armed" in msg
    assert "␣ starts" in msg
    assert env.bypass.armed_categories() == ["ssl"]
    assert env.bypass.active_categories() == []
    assert env.jm.calls == []


def test_ctrl_p_on_a_held_app_arms_for_resume(env):
    env.jm = FakeJM(session_pid=77, package_name=PKG, paused=True)
    env.live = (Liveness.NOT_RUNNING, None)

    ok, msg = env.bypass.start_many(["ssl", "root"])

    assert ok
    assert "␣ resume" in msg
    assert sorted(env.bypass.armed_categories()) == ["root", "ssl"]
    assert env.jm.calls == []


# -- other callers ---------------------------------------------------------------


def test_dexray_stop_keeps_the_spotlight(env):
    """Bug 5: stopping Dexray never clears the selection."""
    import asyncio

    from sandroid.commands.base import CommandContext
    from sandroid.commands.instrumentation_commands import MalwareMonitorCommand

    task = SimpleNamespace(app_name=PKG)
    stopped: list = []
    ts = SimpleNamespace(
        is_running=lambda name: name == "dexray-intercept",
        get_task=lambda name: task,
        stop=lambda name: stopped.append(name) or True,
    )
    ctx = CommandContext(is_tui_mode=True, task_service=ts)

    asyncio.run(MalwareMonitorCommand()._stop_monitoring(ctx))

    assert stopped == ["dexray-intercept"]
    assert env.spotlight.get_effective_package() == PKG


def test_fridump_never_starts_or_restarts(env, monkeypatch):
    from sandroid.services.frida_session_service import FridaSessionService

    device = SimpleNamespace(
        spawn=lambda *a: pytest.fail("fridump spawned"),
        attach=lambda pid: SimpleNamespace(pid=pid),
    )
    fss = FridaSessionService.__new__(FridaSessionService)
    fss._get_spotlight_service = lambda: env.spotlight
    fss._device_manager = SimpleNamespace(get_device_for_session=lambda: device)
    fss._logger = Mock()

    env.live = (Liveness.NOT_RUNNING, None)
    with pytest.raises(ValueError, match="not running"):
        fss.get_session_for_spotlight()

    env.live = (Liveness.RUNNING, 77)
    session, mode, info = fss.get_session_for_spotlight()
    assert (session.pid, mode, info["owns_spawn"]) == (77, "attach", False)


def test_chrome_ct_bypass_keeps_a_running_spotlight_chrome(env):
    from sandroid.core.proxy_manager import CAManager

    env.spotlight.set_app("com.android.chrome")
    env.live = (Liveness.RUNNING, 31)
    assert CAManager._chrome_is_running_spotlight() is True
    env.live = (Liveness.NOT_RUNNING, None)
    assert CAManager._chrome_is_running_spotlight() is False
    env.spotlight.set_app(PKG)
    env.live = (Liveness.RUNNING, 31)
    assert CAManager._chrome_is_running_spotlight() is False


def test_gather_inputs_keeps_the_pid_of_a_held_unnamed_spawn(env):
    env.jm = FakeJM(session_pid=99, package_name=PKG, paused=True)
    env.spotlight.set_pid(99)
    env.live = (Liveness.NOT_RUNNING, None)

    app_start.gather_inputs(PKG)

    assert env.spotlight.get_pid() == 99
    env.jm = FakeJM()
    app_start.gather_inputs(PKG)
    assert env.spotlight.get_pid() is None  # really gone now


# -- review fixes ----------------------------------------------------------------


def test_an_unnamable_session_with_live_jobs_is_never_reset():
    """Item 8: an attached session whose PID cannot be read keeps its jobs."""
    d = decide_start(
        _inputs(session_alive=True, live_jobs=("FriTap SSL Logger",), has_session=True)
    )
    assert d.action == StartAction.REFUSE
    assert d.code == "frida_busy"
    d = decide_start(
        _inputs(
            liveness=Liveness.NOT_RUNNING,
            session_alive=True,
            live_jobs=("Dexray",),
            has_session=True,
        )
    )
    assert d.action == StartAction.REFUSE


def test_spawn_rechecks_live_jobs_before_resetting(env, monkeypatch):
    """Item 8: a job started during Dexray's snapshot prompt is not killed."""
    monkeypatch.setattr(
        env.spotlight,
        "spawn_app_paused",
        lambda pkg: pytest.fail("spawned over live jobs"),
    )
    env.jm = FakeJM(session_pid=12)
    env.jm.jobs = {"x": FakeJob(display_name="FriTap SSL Logger")}
    d = StartDecision(
        StartAction.SPAWN, PKG, owns_spawn=True, reset_session=True, tool="Dexray"
    )

    with pytest.raises(AppStartError, match="FriTap SSL Logger"):
        app_start.open_session(d)
    assert "reset_session" not in env.jm.calls


def _spawning(env, monkeypatch, pid=4321):
    monkeypatch.setattr(env.spotlight, "spawn_app_paused", lambda pkg: (env.jm, pid))


def test_own_spawn_is_guarded_until_its_tool_resumes(env, monkeypatch):
    """Item 4: Space and other tools wait for the tool that spawned the app."""
    _spawning(env, monkeypatch)
    opened = app_start.open_session(
        StartDecision(StartAction.SPAWN, PKG, owns_spawn=True, tool="friTap")
    )
    env.jm = FakeJM(session_pid=4321, package_name=PKG, paused=True)
    assert app_start.setup_owner() == "friTap"

    monkeypatch.setattr(
        env.spotlight, "resume_paused_app", lambda: pytest.fail("resumed early")
    )
    ok, msg = app_start.resume_app()
    assert ok is False
    assert "friTap is still loading its hooks" in msg

    env.live = (Liveness.NOT_RUNNING, None)
    d = app_start.resolve_start(tool="Dexray", java_agent=False)
    assert d.action == StartAction.REFUSE
    assert d.code == "setup"
    assert "friTap is still loading" in d.reason

    def _boom(device, pid):
        raise RuntimeError("process died")

    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(resume_spawned_process=_boom),
    )
    with pytest.raises(RuntimeError):
        app_start.finish_owned_spawn(opened)
    assert app_start.setup_owner() is None  # cleared on every exit path


def test_a_stale_setup_marker_is_dropped(env, monkeypatch):
    _spawning(env, monkeypatch, pid=4321)
    app_start.open_session(
        StartDecision(StartAction.SPAWN, PKG, owns_spawn=True, tool="friTap")
    )
    env.jm = FakeJM(session_pid=999)  # the spawn is gone, another session
    assert app_start.setup_owner() is None


def test_abort_owned_spawn_kills_it_and_clears_everything(env, monkeypatch):
    """Item 2: a failed tool start leaves no frozen spawn behind."""
    from sandroid.core.adb import Adb

    killed: list = []
    monkeypatch.setattr(Adb, "force_stop", staticmethod(killed.append))
    _spawning(env, monkeypatch)
    opened = app_start.open_session(
        StartDecision(StartAction.SPAWN, PKG, owns_spawn=True, tool="friTap")
    )
    env.jm = FakeJM(session_pid=4321, package_name=PKG, paused=True)
    assert env.spotlight.get_pid() == 4321

    app_start.abort_owned_spawn(opened)

    assert killed == [PKG]
    assert "reset_session" in env.jm.calls
    assert env.spotlight.get_pid() is None
    assert app_start.setup_owner() is None
    env.jm.calls.clear()
    app_start.abort_owned_spawn(Opened(77, False, True, None, PKG))  # joined
    assert env.jm.calls == []


def test_restart_teardown_failure_never_leaves_restarting(env, monkeypatch):
    """Item 7: the teardown is inside the end_restart finally."""

    def _teardown(pkg):
        env.spotlight.begin_restart(pkg)
        raise RuntimeError("adb gone")

    monkeypatch.setattr(app_start, "respawn_teardown", _teardown)

    with pytest.raises(RuntimeError):
        app_start.restart_app()
    assert not env.spotlight.is_restarting()


def test_restart_teardown_stops_dexray_without_the_revert_dialog(env):
    """Item 3: no snapshot-revert prompt while the lifecycle lock is held."""
    calls: list = []
    monitor = SimpleNamespace(
        quiet_stop=lambda: calls.append("quiet"),
    )
    task = SimpleNamespace(
        name="dexray-intercept",
        app_name=PKG,
        display_name="Dexray",
        instance=monitor,
        stop_callback=lambda: calls.append("stop_monitoring (prompts)"),
    )
    env.tasks = [task]
    stopped: list = []

    def _stop(name):
        task.stop_callback()
        stopped.append(name)
        return True

    from sandroid.services import get_task_service

    get_task_service().stop = _stop  # the fixture's fake TaskService

    assert app_start.stop_app_tools(PKG) == ["Dexray"]
    assert calls == ["quiet"]


def test_dexray_stop_monitoring_can_skip_the_revert_prompt():
    from sandroid.analysis.malwaremonitor import MalwareMonitor

    mm = MalwareMonitor.__new__(MalwareMonitor)
    asked: list = []
    mm.running = True
    mm._accept_messages = True
    mm.profiler = None
    mm._bypass_claims = []
    mm._job_id = None
    mm.enable_fritap = False
    mm._hook_registry = SimpleNamespace(unregister_hooks=lambda tb: None)
    mm._registered_hooks = []
    mm._get_toolbox = lambda: SimpleNamespace(malware_monitor_running=True)
    mm._unregister_hooks_from_toolbox = lambda: None
    mm._prompt_snapshot_revert = lambda tb: asked.append("revert?")
    mm._snapshot_manager = SimpleNamespace(discard_snapshot=lambda tb: None)

    mm.quiet_stop()
    assert asked == []
    mm.running = True
    mm.stop_monitoring()
    assert asked == ["revert?"]


def test_ctrl_p_disarms_an_armed_ssl_unpin(env):
    """Item 9: a second Ctrl+P disarms SSL armed for a stopped app."""
    import threading as _threading

    from sandroid.services.mitmproxy_service import MitmproxyService

    env.live = (Liveness.NOT_RUNNING, None)
    svc = MitmproxyService.__new__(MitmproxyService)
    svc._lock = _threading.RLock()
    svc._state = SimpleNamespace(ssl_unpin_active=False, ssl_unpin_app=None)
    svc._ssl_via_mitm = False
    svc._emit = lambda line: None
    svc._bypass_service = lambda: env.bypass
    svc.is_running = lambda: False

    now_on, msg = svc.toggle_ssl_unpin()
    assert env.bypass.armed_categories() == ["ssl"]
    assert svc.ssl_unpin_is_on() is True
    assert svc.ssl_unpin_is_active() is False

    now_on, msg = svc.toggle_ssl_unpin()
    assert now_on is False
    assert msg == "SSL pinning bypass disarmed"
    assert env.bypass.armed_categories() == []


# -- friTap's own decision path (bugs 1 and 3) ----------------------------------


class _SSLLogger:
    def __init__(self, target, **kw):
        self.target = target
        self.session_data = {"session_info": {}}

    def on_fritap_message(self, job, message, data):
        return None

    def get_agent_script_path(self):
        return "/tmp/fritap-agent.js"


@pytest.fixture
def fritap(env, monkeypatch, tmp_path):
    from sandroid.analysis import fritap as fritap_mod

    monkeypatch.setattr(fritap_mod, "_INJECTED_PIDS", {})
    monkeypatch.setattr(fritap_mod, "_setup_fritap_logging", lambda: None)
    monkeypatch.setattr(fritap_mod, "_get_device_results_path", lambda: f"{tmp_path}/")
    monkeypatch.setattr(fritap_mod, "SSL_Logger", _SSLLogger)
    monkeypatch.setattr(
        env.spotlight, "spawn_app_paused", lambda pkg: pytest.fail("re-spawned")
    )

    def _make():
        ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
        ft.job_manager = env.jm
        ft.keylog_path = ft.json_output_path = None
        ft.fresh = ft.fresh_consent = False
        ft._opened = None
        ft.app_package = ft.process_id = None
        return ft

    return SimpleNamespace(make=_make, mod=fritap_mod)


def test_fritap_after_c_space_joins_the_running_app(env, fritap):
    """Bug 1: ⇧C, Space, h -- friTap joins the live session, no re-spawn."""
    env.jm = FakeJM(session_pid=77, package_name=PKG)
    env.live = (Liveness.RUNNING, 77)
    ft = fritap.make()

    ft._setup_session()

    assert env.jm.calls == []  # neither spawn nor setup_frida_session
    assert ft.process_id == 77
    assert ft.mode == "attach"
    assert ft._opened.owns_spawn is False


def test_fritap_after_shift_p_joins_the_held_app(env, fritap):
    """Bug 3: ⇧P, h -- friTap joins the paused spawn and never resumes it."""
    env.jm = FakeJM(session_pid=77, package_name=PKG, paused=True)
    env.live = (Liveness.NOT_RUNNING, None)  # pidof cannot name it yet
    ft = fritap.make()

    ft._setup_session()

    assert env.jm.calls == []
    assert ft._opened.paused is True
    assert "still paused" in ft._resume_spawned_target(None, FakeJob())
    assert ("resume", 77) not in env.jm.calls

    env.jm.jobs = {"b": FakeJob(display_name="Detection Bypass")}
    with pytest.raises(fritap.mod.FriTapTargetError, match="#218"):
        fritap.make()._setup_session()


def test_fritap_failed_start_kills_its_own_spawn(env, fritap, monkeypatch):
    """Item 2: start_job returning None after friTap spawned the app."""
    from sandroid.analysis import fritap as fritap_mod

    aborted: list = []
    monkeypatch.setattr(app_start, "abort_owned_spawn", aborted.append)
    ft = fritap.make()
    opened = Opened(4321, True, True, None, PKG)

    def _setup(config=None):
        ft._opened = opened
        ft.process_id = 4321
        ft.app_package = PKG
        ft.mode = "spawn"
        ft.frida_script_path = "/tmp/a.js"
        ft.message_handler = None

    ft._setup_session = _setup
    ft.show_in_activity_log = False
    ft.job_manager = SimpleNamespace(
        is_paused=lambda: False,
        running_jobs=list,
        start_job=lambda *a, **k: None,
        has_active_session=lambda: True,
        get_running_jobs_info=list,
    )
    ft._get_toolbox = lambda: SimpleNamespace(check_frida_hook_conflicts=lambda h: {})
    monkeypatch.setattr(fritap_mod, "set_lifecycle", lambda *a: None)

    with pytest.raises(RuntimeError):
        ft.start(interactive=False)
    assert aborted == [opened]
    assert ft._opened is None


# -- second review round -------------------------------------------------------


def test_setup_marker_is_owner_scoped():
    app_start._begin_setup("friTap", PKG, 4321)
    app_start.end_setup("Dexray")  # not Dexray's marker
    app_start.end_setup("friTap", 999)  # not this spawn
    assert app_start._SETUP == ("friTap", PKG, 4321)
    app_start.end_setup("friTap", 4321)
    assert app_start._SETUP is None


def test_marker_is_set_before_the_spawn_so_space_cannot_resume(env, monkeypatch):
    """The gap between spawn_app_paused and its PID is guarded too."""
    seen: dict = {}

    def _spawn(pkg):
        seen["owner"] = app_start.setup_owner()
        env.jm = FakeJM(session_pid=4321, package_name=PKG, paused=True)
        monkeypatch.setattr(env.spotlight, "is_app_paused", lambda: True)
        seen["resume"] = app_start.resume_app()
        return env.jm, 4321

    monkeypatch.setattr(env.spotlight, "spawn_app_paused", _spawn)
    app_start.open_session(
        StartDecision(StartAction.SPAWN, PKG, owns_spawn=True, tool="friTap")
    )
    assert seen["owner"] == "friTap"
    assert seen["resume"][0] is False
    assert "friTap is still loading" in seen["resume"][1]
    assert app_start._SETUP == ("friTap", PKG, 4321)


def test_a_failed_spawn_clears_its_placeholder(env, monkeypatch):
    monkeypatch.setattr(env.spotlight, "spawn_app_paused", lambda pkg: (None, -1))
    with pytest.raises(AppStartError):
        app_start.open_session(
            StartDecision(StartAction.SPAWN, PKG, owns_spawn=True, tool="friTap")
        )
    assert app_start._SETUP is None


def test_shift_r_during_a_tools_setup_never_kills_the_new_process(env, monkeypatch):
    """⇧R (or a die-and-respawn) replaced friTap's spawn: abort is harmless."""
    from sandroid.core.adb import Adb

    killed: list = []
    monkeypatch.setattr(Adb, "force_stop", staticmethod(killed.append))
    _spawning(env, monkeypatch, pid=4321)
    opened = app_start.open_session(
        StartDecision(StartAction.SPAWN, PKG, owns_spawn=True, tool="friTap")
    )
    # ⇧R: the app runs as 5555 now, with its own session.
    env.jm = FakeJM(session_pid=5555, package_name=PKG)
    env.live = (Liveness.RUNNING, 5555)
    env.spotlight.set_pid(5555)
    assert app_start.setup_owner() is None  # friTap's stale marker dropped

    app_start.abort_owned_spawn(opened)  # real liveness: the new process

    assert killed == []
    assert env.jm.calls == []  # the new session is not reset
    assert env.spotlight.get_pid() == 5555


def test_abort_kills_a_spawn_pidof_still_names(env, monkeypatch):
    from sandroid.core.adb import Adb

    killed: list = []
    monkeypatch.setattr(Adb, "force_stop", staticmethod(killed.append))
    env.jm = FakeJM()  # session already gone
    env.live = (Liveness.RUNNING, 4321)
    app_start._begin_setup("friTap", PKG, 4321)

    app_start.abort_owned_spawn(Opened(4321, True, True, None, PKG, "friTap"))

    assert killed == [PKG]
    assert app_start._SETUP is None


def test_a_newer_owner_keeps_its_marker_when_an_old_spawn_aborts(env, monkeypatch):
    from sandroid.core.adb import Adb

    monkeypatch.setattr(Adb, "force_stop", staticmethod(lambda p: None))
    app_start._begin_setup("Dexray", PKG, 6000)
    app_start.abort_owned_spawn(Opened(4321, True, True, None, PKG, "friTap"))
    assert app_start._SETUP == ("Dexray", PKG, 6000)


def test_attach_reset_runs_under_the_lifecycle_lock(env):
    """drop_idle_session refuses while another thread starts/restarts."""
    env.jm = FakeJM(session_pid=12)
    held, release = threading.Event(), threading.Event()

    def _hold():
        app_start._LIFECYCLE.try_acquire()
        held.set()
        release.wait(5)
        app_start._LIFECYCLE.release()

    t = threading.Thread(target=_hold)
    t.start()
    held.wait(5)
    try:
        with pytest.raises(AppStartError, match="in progress"):
            app_start.open_session(
                StartDecision(StartAction.ATTACH, PKG, pid=77, reset_session=True)
            )
    finally:
        release.set()
        t.join(5)
    assert env.jm.calls == []


def test_fritap_failure_after_its_resume_stops_only_its_job(env, fritap, monkeypatch):
    """The app runs: a late failure must not force-stop it."""
    stopped: list = []
    monkeypatch.setattr(
        app_start, "abort_owned_spawn", lambda o: pytest.fail("killed the app")
    )
    monkeypatch.setattr(
        fritap.mod,
        "stop_frida_job_bounded",
        lambda jm, job_id, timeout: stopped.append(job_id) or True,
    )
    ft = fritap.make()
    ft._opened = Opened(4321, True, True, None, PKG, "friTap")
    ft._spawn_resumed = True
    ft.job_id = "job-9"

    ft._cleanup_failed_start()

    assert stopped == ["job-9"]


def test_dexray_ends_only_its_own_marker(monkeypatch):
    from sandroid.analysis.malwaremonitor import MalwareMonitor

    mm = MalwareMonitor.__new__(MalwareMonitor)
    mm._decision = StartDecision(StartAction.SPAWN, PKG, owns_spawn=True, tool="Dexray")
    mm._app_pid = 4321
    app_start._begin_setup("friTap", PKG, 777)
    mm._end_own_setup()
    assert app_start._SETUP == ("friTap", PKG, 777)  # another tool's marker

    app_start._begin_setup("Dexray", PKG, 4321)
    mm._decision = StartDecision(StartAction.JOIN, PKG, pid=4321, tool="Dexray")
    mm._end_own_setup()  # did not spawn: leaves it
    assert app_start._SETUP == ("Dexray", PKG, 4321)

    mm._decision = StartDecision(StartAction.SPAWN, PKG, owns_spawn=True, tool="Dexray")
    mm._end_own_setup()
    assert app_start._SETUP is None


def test_dexray_resume_and_abort_end_its_marker(monkeypatch):
    from sandroid.analysis.malwaremonitor import MalwareMonitor

    mm = MalwareMonitor.__new__(MalwareMonitor)
    mm._decision = StartDecision(StartAction.SPAWN, PKG, owns_spawn=True, tool="Dexray")
    mm._app_pid = 4321
    mm.frida_device = None
    resumed: list = []
    mm.job_manager = SimpleNamespace(
        device=SimpleNamespace(resume=resumed.append), pid=4321
    )
    mm._spawned_at = 1.0
    app_start._begin_setup("Dexray", PKG, 4321)
    mm._resume_spawned_target()
    assert resumed == [4321]
    assert app_start._SETUP is None

    # _abort_start before the resume: resumes and ends the marker too.
    app_start._begin_setup("Dexray", PKG, 4321)
    mm._spawned_at = 1.0
    mm._owns_session = True
    mm._bypass_claims = []
    mm._snapshot_manager = SimpleNamespace(discard_snapshot=lambda tb: None)
    mm.job_manager.detach_from_app = lambda timeout=0: None
    mm._abort_start(SimpleNamespace(malware_monitor_running=True))
    assert app_start._SETUP is None


def test_abort_cleans_up_a_nameless_spawn_whose_session_is_gone(env, monkeypatch):
    """A held spawn has no pidof name; with its session gone too (e.g. an
    anti-Frida self-kill) it is still the tool's, so the header is cleared.
    An adb error, or another start holding the lock, leaves it alone.
    """
    from sandroid.core.adb import Adb

    killed: list = []
    monkeypatch.setattr(Adb, "force_stop", staticmethod(killed.append))
    env.jm = FakeJM()  # session gone
    env.live = (Liveness.NOT_RUNNING, None)
    env.spotlight.announce_pid(4321, PKG)

    app_start.abort_owned_spawn(Opened(4321, True, True, None, PKG, "friTap"))

    assert killed == [PKG]
    assert env.spotlight.get_pid() is None

    killed.clear()
    env.live = (Liveness.UNKNOWN, None)
    app_start.abort_owned_spawn(Opened(4321, True, True, None, PKG, "friTap"))
    assert killed == []


# -- pre-start steps (identity profile & co.) --------------------------------------

DESC = "apply identity profile 'mara' (ssaid, locale)"


_REAL_SYSTEM_SERVER_PID = app_start._system_server_pid
_REAL_PM_READY = app_start._package_manager_ready


@pytest.fixture(autouse=True)
def _no_pre_start_steps(monkeypatch):
    """Each test starts with an empty registry (a booted TUI may register);
    system_server never changes unless a test says so (no adb).
    """
    saved = list(app_start._PRE_START_STEPS)
    app_start._PRE_START_STEPS.clear()
    monkeypatch.setattr(app_start, "_system_server_pid", lambda serial=None: 100)
    monkeypatch.setattr(app_start, "_package_manager_ready", lambda serial=None: True)
    yield
    app_start._PRE_START_STEPS[:] = saved


def _registered() -> list:
    return list(app_start._PRE_START_STEPS)


def _hook(log: list, *, disruptive=False, fail=None, desc=DESC):
    """A hook whose plan logs ``apply`` (and raises ``fail`` there)."""

    def apply():
        log.append("apply")
        if fail is not None:
            raise fail

    def hook(package):
        log.append(("hook", package))
        return app_start.PreStartPlan(desc, disruptive, apply)

    return hook


@pytest.fixture
def framework(env, monkeypatch):
    """system_server PIDs, the Frida service and the frida-server check."""
    state = SimpleNamespace(pids=[100, 200], invalidated=[], refreshed=[])

    def _pid(serial=None):
        return state.pids.pop(0) if len(state.pids) > 1 else state.pids[0]

    monkeypatch.setattr(app_start, "_system_server_pid", _pid)
    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(
            invalidate_frida_device_cache=lambda: state.invalidated.append(1)
        ),
    )
    monkeypatch.setattr(
        app_start,
        "_refresh_frida_server",
        lambda: state.refreshed.append(1) or "frida-server already running",
    )
    return state


def _ladder(env, monkeypatch, log: list):
    monkeypatch.setattr(
        env.bypass,
        "apply_to_fresh_spawn_with_retry",
        lambda pkg, cats, resume=True: log.append(("spawn", set(cats))) or (True, "ok"),
    )


def test_registry_dedupes_keeps_order_and_unregisters():
    calls: list = []

    def first(pkg):
        calls.append("first")

    def second(pkg):
        calls.append("second")
        return app_start.PreStartPlan("x", False, lambda: None)

    class Owner:
        def hook(self, pkg):
            calls.append("bound")

    owner = Owner()
    for hook in (first, second, first, owner.hook, owner.hook):
        app_start.register_pre_start_step(hook)
    assert _registered() == [first, second, owner.hook]

    plans = app_start._collect_pre_start(PKG, "Start")

    assert calls == ["first", "second", "bound"]  # registration order
    assert [p.description for p in plans] == ["x"]  # None = nothing to do
    app_start.unregister_pre_start_step(owner.hook)
    app_start.unregister_pre_start_step(first)
    app_start.unregister_pre_start_step(first)  # not registered: no-op
    assert _registered() == [second]


def test_without_hooks_space_is_unchanged(env, monkeypatch):
    log: list = []
    _ladder(env, monkeypatch, log)
    monkeypatch.setattr(
        app_start,
        "_system_server_pid",
        lambda serial=None: pytest.fail("probed the framework"),
    )

    assert app_start.start_app() == (True, "ok")
    assert log == [("spawn", set())]


def test_a_non_disruptive_plan_is_applied_without_a_dialog(env, bus, monkeypatch):
    log: list = []
    _ladder(env, monkeypatch, log)
    app_start.register_pre_start_step(_hook(log))

    assert _in_worker(app_start.start_app) == (True, "ok")
    assert log == [("hook", PKG), "apply", ("spawn", set())]
    assert bus.asked == []


def test_a_disruptive_plan_asks_then_applies_and_recovers(
    env, bus, framework, monkeypatch
):
    log: list = []
    _ladder(env, monkeypatch, log)
    env.bypass._armed = {"ssl"}
    env.bypass._active = {"root"}
    monkeypatch.setattr(
        env.bypass, "forget_process", lambda: log.append("forget_process")
    )
    env.tasks = [SimpleNamespace(name="fritap", app_name=PKG, display_name="FriTap")]
    announce = env.spotlight.announce_pid
    monkeypatch.setattr(
        env.spotlight,
        "announce_pid",
        lambda pid, pkg=None: log.append(("pid", pid)) or announce(pid, pkg),
    )
    app_start.register_pre_start_step(_hook(log, disruptive=True))

    assert _in_worker(app_start.start_app) == (True, "ok")

    name, kw = bus.asked[0]
    assert name == "ConfirmModal"
    assert kw["title"] == f"Apply before starting {PKG}?"
    assert kw["message"] == (
        f"Before {PKG} starts, Sandroid will {DESC}. This restarts the Android "
        "framework: every running app on the device stops. This stops: FriTap."
    )
    assert (kw["yes_label"], kw["no_label"]) == ("Apply and start", "Cancel")
    assert kw["guard_typing"] is True
    assert log == [
        ("hook", PKG),
        "apply",
        "forget_process",  # the armed set stays
        ("pid", None),
        ("spawn", {"ssl"}),
    ]
    assert env.jm.calls == ["reset_session"]  # the dead session
    assert env.jm.device is None  # the AFM device handle re-resolves
    assert framework.invalidated == [1]
    assert framework.refreshed == [1]


def test_a_disruptive_plan_that_left_the_framework_up_needs_no_recovery(
    env, bus, framework, monkeypatch
):
    log: list = []
    _ladder(env, monkeypatch, log)
    framework.pids = [100]  # unchanged after apply: nothing was restarted
    monkeypatch.setattr(
        app_start,
        "recover_after_framework_restart",
        lambda pid, timeout=90.0: pytest.fail("waited for a restart"),
    )
    app_start.register_pre_start_step(_hook(log, disruptive=True))

    assert _in_worker(app_start.start_app) == (True, "ok")
    assert log == [("hook", PKG), "apply", ("spawn", set())]


@pytest.mark.parametrize("answer", [False, None])
def test_a_declined_plan_never_spawns(env, bus, monkeypatch, answer):
    log: list = []
    _ladder(env, monkeypatch, log)
    bus.answer = answer  # Cancel; Esc / timeout
    app_start.register_pre_start_step(_hook(log, disruptive=True))

    ok, msg = _in_worker(app_start.start_app)

    assert ok is False
    assert msg == f"{PKG} not started — {DESC} not applied"
    assert log == [("hook", PKG)]


def test_restart_asks_before_the_teardown_and_cancel_keeps_the_app(
    env, bus, framework, monkeypatch
):
    log: list = []
    _ladder(env, monkeypatch, log)
    monkeypatch.setattr(
        app_start, "respawn_teardown", lambda pkg: log.append("teardown")
    )
    monkeypatch.setattr(app_start, "_drop_dead_frida_state", lambda: None)
    app_start.register_pre_start_step(_hook(log, disruptive=True))
    bus.answer = False

    ok, msg = _in_worker(app_start.restart_app)

    assert (ok, msg) == (False, f"{PKG} not started — {DESC} not applied")
    assert log == [("hook", PKG)]  # never torn down

    log.clear()
    bus.answer = True  # ⇧R's no-dialog exemption does not cover this
    assert _in_worker(app_start.restart_app) == (True, "ok")
    assert len(bus.asked) == 2
    assert log == [("hook", PKG), "teardown", "apply", ("spawn", set())]
    assert not env.spotlight.is_restarting()


def test_a_failing_apply_aborts_the_spawn(env, bus, framework, monkeypatch):
    log: list = []
    _ladder(env, monkeypatch, log)
    forgot: list = []
    monkeypatch.setattr(env.bypass, "forget_process", lambda: forgot.append(1))
    app_start.register_pre_start_step(_hook(log, fail=RuntimeError("boom")))
    framework.pids = [100]  # this one left the framework alone

    ok, msg = _in_worker(app_start.start_app)

    assert (ok, msg) == (False, f"Could not {DESC}: boom — {PKG} not started")
    assert log == [("hook", PKG), "apply"]
    assert forgot == []  # not disruptive: nothing to recover

    # A disruptive one that fails mid-way still recovers the Frida state.
    app_start._PRE_START_STEPS.clear()
    log.clear()
    framework.pids = [100, 200]
    app_start.register_pre_start_step(
        _hook(log, disruptive=True, fail=RuntimeError("window aborted"))
    )
    ok, msg = _in_worker(app_start.start_app)
    assert msg == f"Could not {DESC}: window aborted — {PKG} not started"
    assert log == [("hook", PKG), "apply"]
    assert forgot == [1]
    assert framework.invalidated == [1]


def test_a_raising_hook_aborts_the_spawn(env, monkeypatch):
    log: list = []
    _ladder(env, monkeypatch, log)

    def broken(pkg):
        raise ValueError("bad profile")

    app_start.register_pre_start_step(broken)

    ok, msg = app_start.start_app()

    assert ok is False
    assert msg == (
        f"{PKG} not started — pre-start step "
        "test_a_raising_hook_aborts_the_spawn.<locals>.broken failed: bad profile"
    )
    assert log == []


def test_headless_needs_the_callers_consent(env, bus, framework, monkeypatch):
    """No UI: only consent (headless fresh=True) covers stopping every app."""
    log: list = []
    _ladder(env, monkeypatch, log)
    bus.active = False
    app_start.register_pre_start_step(_hook(log, disruptive=True))

    ok, msg = app_start.start_app()

    assert ok is False
    assert "no dialog to confirm it" in msg
    assert "fresh=True" in msg
    assert log == [("hook", PKG)]

    log.clear()
    assert app_start.start_app(consent=True) == (True, "ok")
    assert log == [("hook", PKG), "apply", ("spawn", set())]
    assert bus.asked == []


def test_the_ui_thread_never_shows_the_dialog(env, bus, monkeypatch):
    log: list = []
    _ladder(env, monkeypatch, log)
    app_start.register_pre_start_step(_hook(log, disruptive=True))
    assert threading.current_thread() is threading.main_thread()

    ok, msg = app_start.start_app(consent=True)  # consent is headless only

    assert ok is False
    assert "UI thread" in msg
    assert bus.asked == []
    assert log == [("hook", PKG)]


def test_join_attach_and_resume_never_run_hooks(env, monkeypatch):
    app_start.register_pre_start_step(lambda pkg: pytest.fail("hook ran"))
    env.jm = FakeJM(session_pid=77, package_name=PKG)
    app_start.open_session(StartDecision(StartAction.JOIN, PKG, pid=77))

    env.jm = FakeJM()
    app_start.open_session(StartDecision(StartAction.ATTACH, PKG, pid=77))

    env.jm = FakeJM(session_pid=77, package_name=PKG, paused=True)
    monkeypatch.setattr(env.spotlight, "resume_paused_app", lambda: True)
    assert app_start.resume_app()[0]

    env.live = (Liveness.RUNNING, 77)
    monkeypatch.setattr(env.bypass, "apply_armed", lambda: (True, "Attached"))
    assert app_start.attach_app() == (True, "Attached")


def test_a_tools_spawn_runs_hooks_and_respawn_asks_before_the_teardown(
    env, bus, framework, monkeypatch
):
    log: list = []
    monkeypatch.setattr(
        env.spotlight,
        "spawn_app_paused",
        lambda pkg: log.append("spawn") or (env.jm, 4321),
    )
    monkeypatch.setattr(
        app_start, "respawn_teardown", lambda pkg: log.append("teardown")
    )
    app_start.register_pre_start_step(_hook(log))
    spawn = StartDecision(StartAction.SPAWN, PKG, owns_spawn=True, tool="friTap")

    opened = app_start.open_session(spawn)

    assert opened.pid == 4321
    assert log == [("hook", PKG), "apply", "spawn"]
    app_start.end_setup("friTap")

    # RESPAWN: declined before the teardown, so the app keeps running.
    app_start._PRE_START_STEPS.clear()
    log.clear()
    app_start.register_pre_start_step(_hook(log, disruptive=True))
    bus.answer = False
    respawn = StartDecision(StartAction.RESPAWN, PKG, owns_spawn=True, tool="friTap")
    with pytest.raises(AppStartError, match="not applied"):
        _in_worker(lambda: app_start.open_session(respawn))
    assert log == [("hook", PKG)]
    assert not env.spotlight.is_restarting()

    # Headless: the decision's consent (an API fresh=True) covers it.
    bus.active = False
    log.clear()
    headless = StartDecision(
        StartAction.SPAWN, PKG, owns_spawn=True, tool="friTap", consent=True
    )
    assert app_start.open_session(headless).pid == 4321
    assert log == [("hook", PKG), "apply", "spawn"]
    app_start.end_setup("friTap")
    with pytest.raises(AppStartError, match=r"fresh=True"):
        app_start.open_session(replace(headless, consent=False))


def test_the_decision_carries_the_callers_consent():
    spawn = decide_start(_inputs(liveness=Liveness.NOT_RUNNING, consent=True))
    assert spawn.action == StartAction.SPAWN
    assert spawn.consent is True
    assert decide_start(_inputs(liveness=Liveness.NOT_RUNNING)).consent is False
    assert decide_start(_inputs(fresh=True, consent=True)).consent is True


def test_prepare_launch_runs_hooks_before_an_outside_spawn(env, monkeypatch):
    """The real prepare_launch (once reached via TrigDroid's spawn): hooks run
    before a launch outside the Frida spawn path, a failing hook aborts it,
    and a running app runs no plan.
    """
    env.live = (Liveness.NOT_RUNNING, None)
    log: list = []
    app_start.register_pre_start_step(_hook(log))

    assert _in_worker(lambda: app_start.prepare_launch(PKG, "Objection")) is True
    assert log == [("hook", PKG), "apply"]

    app_start._PRE_START_STEPS.clear()
    app_start.register_pre_start_step(_hook(log, fail=RuntimeError("boom")))
    with pytest.raises(AppStartError):
        _in_worker(lambda: app_start.prepare_launch(PKG, "Objection"))

    # Attaching to a running app applies nothing.
    app_start._PRE_START_STEPS.clear()
    running: list = []
    app_start.register_pre_start_step(_hook(running))
    env.live = (Liveness.RUNNING, 77)
    assert _in_worker(lambda: app_start.prepare_launch(PKG, "Objection")) is False
    assert "apply" not in running


def test_ai_launch_app_runs_hooks_on_a_first_launch_only(env, bus, monkeypatch):
    from sandroid.ai.tools import app_lifecycle
    from sandroid.core.adb import Adb

    log: list = []
    monkeypatch.setattr(
        Adb,
        "launch_app",
        staticmethod(lambda pkg, activity=None: log.append("launch") or (True, "ok")),
    )
    app_start.register_pre_start_step(_hook(log))
    env.live = (Liveness.NOT_RUNNING, None)

    assert _in_worker(lambda: app_lifecycle.launch_app(PKG))["launched"] is True
    assert log == [("hook", PKG), "apply", "launch"]

    log.clear()
    env.live = (Liveness.RUNNING, 77)  # am start only brings it to the front
    assert _in_worker(lambda: app_lifecycle.launch_app(PKG))["launched"] is True
    assert log == [("hook", PKG), "launch"]  # asked, nothing applied

    log.clear()
    env.live = (Liveness.UNKNOWN, None)
    result = _in_worker(lambda: app_lifecycle.launch_app(PKG))
    assert result["launched"] is False
    assert "adb error" in result["message"]
    assert log == [("hook", PKG)]

    app_start._PRE_START_STEPS.clear()
    log.clear()
    app_start.register_pre_start_step(_hook(log, disruptive=True))
    env.live = (Liveness.NOT_RUNNING, None)
    bus.answer = False
    result = _in_worker(lambda: app_lifecycle.launch_app(PKG))
    assert result == {
        "launched": False,
        "package_name": PKG,
        "activity_name": None,
        "message": f"{PKG} not started — {DESC} not applied",
    }
    assert log == [("hook", PKG)]


def test_ai_launch_app_with_a_step_is_refused_while_a_start_runs(env, monkeypatch):
    from sandroid.ai.tools import app_lifecycle
    from sandroid.core.adb import Adb

    monkeypatch.setattr(
        Adb,
        "launch_app",
        staticmethod(lambda pkg, activity=None: pytest.fail("launched")),
    )
    app_start.register_pre_start_step(_hook([]))
    held, release = threading.Event(), threading.Event()

    def _hold():
        with app_start.lifecycle_lock():
            held.set()
            release.wait(5)

    t = threading.Thread(target=_hold)
    t.start()
    held.wait(5)
    try:
        result = app_lifecycle.launch_app(PKG)
    finally:
        release.set()
        t.join(5)
    assert result["launched"] is False
    assert result["message"] == app_start._BUSY_MSG


def test_identity_registers_with_the_real_registry():
    from sandroid.services import identity

    svc = identity.IdentityService()
    assert identity._pre_spawn_plan_cls() is app_start.PreStartPlan
    assert svc.install_pre_spawn_hook() is True
    assert svc.install_pre_spawn_hook() is True
    assert _registered() == [svc.pre_spawn]
    svc.uninstall_pre_spawn_hook()
    assert _registered() == []


# -- recover_after_framework_restart -----------------------------------------------


@pytest.fixture
def clock(monkeypatch):
    """A fake clock for app_start (sleep advances it)."""
    state = SimpleNamespace(now=0.0, sleeps=0)

    def _sleep(seconds):
        state.sleeps += 1
        state.now += seconds

    monkeypatch.setattr(
        app_start,
        "time",
        SimpleNamespace(monotonic=lambda: state.now, sleep=_sleep),
    )
    return state


@pytest.fixture
def recovery(monkeypatch):
    """Answers for ``pidof system_server``; records the drop and frida check."""
    from sandroid.core.adb import Adb

    monkeypatch.setattr(app_start, "_system_server_pid", _REAL_SYSTEM_SERVER_PID)
    monkeypatch.setattr(app_start, "_package_manager_ready", _REAL_PM_READY)

    state = SimpleNamespace(
        pids=[], pm=[True], sent=[], dropped=0, refreshed=0, timeouts=[]
    )

    def send(cmd, *a, **k):
        state.sent.append(cmd)
        if cmd == "shell pidof system_server":
            pid = state.pids.pop(0) if len(state.pids) > 1 else state.pids[0]
            return (f"{pid}\n" if pid else ""), ""
        if cmd == "shell pm path android":
            state.timeouts.append(k.get("timeout"))
            up = state.pm.pop(0) if len(state.pm) > 1 else state.pm[0]
            return ("package:/system/framework/framework-res.apk\n" if up else ""), ""
        if "boot_completed" in cmd:
            return "1\n", ""  # stale across a framework restart
        return "", ""

    def _drop():
        state.dropped += 1

    def _refresh():
        state.refreshed += 1
        return "frida-server restarted"

    monkeypatch.setattr(Adb, "send_adb_command", staticmethod(send))
    monkeypatch.setattr(app_start, "_drop_dead_frida_state", _drop)
    monkeypatch.setattr(app_start, "_refresh_frida_server", _refresh)
    return state


def test_recovery_waits_for_a_new_system_server_not_boot_completed(recovery, clock):
    recovery.pids = [100, None, None, 100, 222]

    app_start.recover_after_framework_restart(100)

    assert clock.sleeps == 4  # 100, gone, gone, 100 again, then 222
    assert all("boot_completed" not in cmd for cmd in recovery.sent)
    assert (recovery.dropped, recovery.refreshed) == (1, 1)


def test_recovery_without_a_previous_pid_only_needs_system_server(recovery, clock):
    recovery.pids = [None, 100]

    app_start.recover_after_framework_restart(None)

    assert clock.sleeps == 1
    assert recovery.refreshed == 1


def test_recovery_reads_the_given_serial(recovery, clock, monkeypatch):
    """Per-call serial (sandroid-proxy's CA restart on a named device)."""
    from sandroid.core.adb import Adb

    serials: list = []
    send = Adb.send_adb_command

    def _send(cmd, *a, **k):
        serials.append(k.get("serial"))
        return send(cmd, *a, **k)

    monkeypatch.setattr(Adb, "send_adb_command", staticmethod(_send))
    monkeypatch.setattr(Adb, "get_target_device", classmethod(lambda c: "emu-1"))
    recovery.pids = [100, 222]

    app_start.recover_after_framework_restart(100, serial="emu-1")
    assert set(serials) == {"emu-1"}
    assert (recovery.dropped, recovery.refreshed) == (1, 1)

    recovery.pids = [100, 333]
    app_start.recover_after_framework_restart(100, serial="emu-2")
    # Another device: only the wait, the active device's handles stay.
    assert (recovery.dropped, recovery.refreshed) == (1, 1)


def test_recovery_times_out_but_still_drops_the_dead_handles(recovery, clock):
    recovery.pids = [100]

    with pytest.raises(AppStartError, match="did not come back within 5 s"):
        app_start.recover_after_framework_restart(100, timeout=5.0)

    assert clock.now >= 5.0
    assert recovery.dropped == 1
    assert recovery.refreshed == 0


@pytest.mark.parametrize(
    ("running", "stale", "expected"),
    [
        (True, False, []),  # fresh (the identity apply restarted it): untouched
        (True, True, ["restart"]),  # predates system_server: DeadSystemException
        (False, False, ["start"]),  # died with the framework
    ],
)
def test_frida_server_is_restarted_only_when_dead(
    monkeypatch, running, stale, expected
):
    from sandroid.core import frida_manager as fmod

    calls: list = []
    fm = SimpleNamespace(
        is_frida_server_running=lambda: running,
        restart_frida_server_and_wait=lambda: calls.append("restart") or True,
        is_device_rooted=True,
    )
    monkeypatch.setattr(
        services,
        "get_frida_session_service",
        lambda: SimpleNamespace(
            get_frida_manager=lambda: fm,
            invalidate_frida_device_cache=lambda: None,
            _job_manager=None,
        ),
    )
    monkeypatch.setattr(fmod, "frida_server_is_stale", lambda fm: stale)
    monkeypatch.setattr(
        fmod, "ensure_frida_server_started", lambda fm: calls.append("start") or True
    )
    monkeypatch.setattr(fmod, "frida_server_auto_start_enabled", lambda: True)

    app_start._refresh_frida_server()

    assert calls == expected


def test_invalidating_the_frida_cache_nulls_the_job_manager_device():
    from sandroid.services.frida_session_service import FridaSessionService

    svc = FridaSessionService.__new__(FridaSessionService)
    svc._frida_device_lock = threading.Lock()
    svc._cached_frida_device = object()
    svc._cached_device_serial = "emulator-5570"
    svc._logger = Mock()
    svc._job_manager = SimpleNamespace(device=object())

    svc.invalidate_frida_device_cache()

    assert svc._cached_frida_device is None
    assert svc._job_manager.device is None


# -- lifecycle_lock ------------------------------------------------------------------


def test_lifecycle_lock_waits_then_raises_while_busy():
    held, release = threading.Event(), threading.Event()

    def _hold():
        with app_start.lifecycle_lock():
            held.set()
            release.wait(5)

    t = threading.Thread(target=_hold)
    t.start()
    held.wait(5)
    try:

        def _wait():
            start = time.monotonic()
            with pytest.raises(AppStartError, match="in progress"):
                with app_start.lifecycle_lock(timeout=0.2):
                    pass
            return time.monotonic() - start

        assert _in_worker(_wait) >= 0.2
        with pytest.raises(AppStartError):  # no wait: refused at once
            with app_start.lifecycle_lock():
                pass
    finally:
        release.set()
        t.join(5)
    with app_start.lifecycle_lock():  # free again
        pass


def test_lifecycle_lock_is_reentrant_and_never_waits_on_the_ui_thread(env):
    def _nested():
        with app_start.lifecycle_lock(timeout=1.0):
            with app_start.lifecycle_lock(timeout=1.0):
                return app_start.start_app()  # a start inside it works

    env.live = (Liveness.RUNNING, 77)
    ok, msg = _in_worker(_nested)
    assert "already running" in msg
    assert not app_start._LIFECYCLE.locked()

    with pytest.raises(AppStartError, match="UI thread"):
        with app_start.lifecycle_lock(timeout=1.0):
            pass
    assert not app_start._LIFECYCLE.locked()


# -- ⇧K keeps the bypasses armed -----------------------------------------------------


def test_kill_keeps_active_bypasses_armed_and_space_applies_them(env, monkeypatch):
    env.bypass._armed = {"root"}
    env.bypass._active = {"ssl"}  # on live only (Ctrl+P on the running app)
    env.bypass._app_package = PKG

    assert env.bypass.keep_armed_and_forget(PKG) == ["ssl", "root"]
    assert env.bypass.active_categories() == []

    log: list = []
    _ladder(env, monkeypatch, log)
    assert app_start.start_app() == (True, "ok")
    assert log == [("spawn", {"ssl", "root"})]


def test_stop_all_and_a_new_selection_clear_the_armed_set(env):
    env.bypass._armed = {"ssl"}
    env.bypass.stop_all()
    assert env.bypass.armed_categories() == []

    env.bypass._armed = {"ssl"}
    env.spotlight.set_app(PKG, pid=77)  # same app: kept
    assert env.bypass.armed_categories() == ["ssl"]
    env.spotlight.set_app("org.example.other")
    assert env.bypass.armed_categories() == []

    env.bypass._armed = {"root"}
    env.spotlight.reset()
    assert env.bypass.armed_categories() == []


def test_recovery_waits_for_the_package_manager_before_frida(recovery, clock):
    """The PID alone is too early: frida would hit the post-restart ANRs."""
    recovery.pids = [222]
    recovery.pm = [False, False, True]
    order: list = []
    recovery_refresh = app_start._refresh_frida_server
    app_start._refresh_frida_server = lambda: (
        order.append(("refresh", clock.now)) or recovery_refresh()
    )
    try:
        app_start.recover_after_framework_restart(100)
    finally:
        app_start._refresh_frida_server = recovery_refresh
    assert clock.sleeps == 2  # pm silent twice
    assert order == [("refresh", 2.0)]
    assert recovery.timeouts == [5.0, 5.0, 5.0]  # short per-call timeout


def test_recovery_times_out_on_a_silent_package_manager(recovery, clock):
    recovery.pids = [222]
    recovery.pm = [False]

    with pytest.raises(AppStartError, match="package manager does not answer"):
        app_start.recover_after_framework_restart(100, timeout=5.0)

    assert recovery.dropped == 1  # dead handles dropped anyway
    assert recovery.refreshed == 0


# -- fix round: recovery, armed snapshot, no-plan launches, progress ------------


def test_recovery_follows_the_pid_not_the_disruptive_claim(env, framework, monkeypatch):
    """A plan that said "no restart" may still restart the framework."""
    log: list = []
    _ladder(env, monkeypatch, log)
    forgot: list = []
    monkeypatch.setattr(env.bypass, "forget_process", lambda: forgot.append(1))
    app_start.register_pre_start_step(_hook(log))  # disruptive=False
    framework.pids = [100, 200]

    assert app_start.start_app() == (True, "ok")
    assert forgot == [1]
    assert framework.refreshed == [1]


@pytest.mark.parametrize(
    ("after", "disruptive", "recovered", "dropped"),
    [
        (None, True, False, True),  # still unreadable: drop, never wait 90 s
        (200, False, False, False),  # cannot tell a restart: skip
        (200, True, True, False),  # the plan said so and system_server runs
    ],
)
def test_an_unreadable_pid_before_never_waits(
    env, bus, framework, monkeypatch, after, disruptive, recovered, dropped
):
    bus.active = False  # headless: consent covers it (no UI-thread refusal)
    log: list = []
    _ladder(env, monkeypatch, log)
    framework.pids = [None, after]
    calls: list = []
    drops: list = []
    monkeypatch.setattr(
        app_start,
        "recover_after_framework_restart",
        lambda pid, timeout=90.0: calls.append(pid),
    )
    monkeypatch.setattr(app_start, "_drop_dead_frida_state", lambda: drops.append(1))
    app_start.register_pre_start_step(_hook(log, disruptive=disruptive))

    assert app_start.start_app(consent=True)[0] or not disruptive
    assert calls == ([None] if recovered else [])
    assert drops == ([1] if dropped else [])


def test_start_keeps_the_bypasses_armed_before_the_pre_start_step(
    env, framework, monkeypatch
):
    """An AI select_app during the dialog/restart disarms; this app keeps
    the bypasses it was started with.
    """
    log: list = []
    _ladder(env, monkeypatch, log)
    env.bypass._armed = {"ssl"}
    framework.pids = [100]

    def hook(pkg):
        return app_start.PreStartPlan(
            DESC, False, lambda: env.spotlight.set_app("org.example.other")
        )

    app_start.register_pre_start_step(hook)

    assert app_start.start_app() == (True, "ok")
    assert env.bypass.armed_categories() == []  # the selection change disarmed
    assert log == [("spawn", {"ssl"})]


def test_prepare_launch_without_plans_needs_no_lock_or_adb(env, monkeypatch):
    monkeypatch.setattr(
        app_start,
        "probe_liveness",
        lambda *a, **k: pytest.fail("probed the app"),
    )
    app_start.register_pre_start_step(lambda pkg: None)  # identity off
    held, release = threading.Event(), threading.Event()

    def _hold():
        with app_start.lifecycle_lock():
            held.set()
            release.wait(5)

    t = threading.Thread(target=_hold)
    t.start()
    held.wait(5)
    try:
        assert app_start.prepare_launch(PKG, "Objection") is True
    finally:
        release.set()
        t.join(5)


def test_the_dialog_lists_the_spotlight_apps_tools_for_another_launch(
    env, bus, framework, monkeypatch
):
    """An AI launch of another app restarts the framework: the spotlight
    app's tools die too, are named in the dialog, and are stopped after.
    """
    other = "org.example.other"
    env.tasks = [
        SimpleNamespace(name="fritap", app_name=PKG, display_name="FriTap"),
        SimpleNamespace(name="dexray", app_name=other, display_name="Dexray"),
    ]
    log: list = []
    app_start.register_pre_start_step(_hook(log, disruptive=True))

    assert _in_worker(lambda: app_start.prepare_launch(other, other)) is True

    _name, kw = bus.asked[0]
    assert kw["message"].endswith("This stops: Dexray, FriTap.")
    assert sorted(env.stopped) == ["dexray", "fritap"]


def test_the_progress_text_is_set_while_a_step_applies(
    env, bus, framework, monkeypatch
):
    bus.active = False  # headless: consent covers it (no UI-thread refusal)
    log: list = []
    _ladder(env, monkeypatch, log)
    seen: list = []
    events: list = []
    app_start.add_pre_start_status_listener(lambda: events.append(1))
    framework.pids = [100]

    def hook(pkg):
        return app_start.PreStartPlan(
            "apply identity profile 'mara-de' (ssaid)",
            True,
            lambda: seen.append(app_start.pre_start_status(PKG)),
        )

    app_start.register_pre_start_step(hook)
    try:
        assert app_start.start_app(consent=True) == (True, "ok")
    finally:
        app_start._STATUS_LISTENERS.clear()

    assert seen == [
        "Applying identity profile 'mara-de' (ssaid) — the Android framework "
        "restarts; this can take a few minutes"
    ]
    assert app_start._progress_text([hook(PKG)])[1] == (
        "Applying identity profile 'mara-de', framework restarts"
    )
    assert app_start.pre_start_status() is None
    assert events == [1, 1]  # began, ended


def test_kill_takes_the_union_and_drops_the_script_in_one_lock_hold(env, monkeypatch):
    """A live toggle cannot slip between the union and the drop."""
    env.bypass._armed = {"root"}
    env.bypass._active = {"ssl"}
    seen: list = []
    take = env.bypass._take_script_locked

    def _take():
        seen.append((env.bypass._lock._is_owned(), set(env.bypass._armed)))
        return take()

    monkeypatch.setattr(env.bypass, "_take_script_locked", _take)

    env.bypass.keep_armed_and_forget()

    assert seen == [(True, {"root", "ssl"})]


def test_restart_keeps_the_bypasses_armed_before_the_dialog(
    env, framework, monkeypatch
):
    log: list = []
    _ladder(env, monkeypatch, log)
    monkeypatch.setattr(app_start, "respawn_teardown", lambda pkg: None)
    env.bypass._armed = {"ssl"}
    framework.pids = [100]

    def hook(pkg):
        env.spotlight.set_app("org.example.other")  # AI select_app meanwhile
        return app_start.PreStartPlan(DESC, False, lambda: None)

    app_start.register_pre_start_step(hook)

    assert app_start.restart_app() == (True, "ok")
    assert log == [("spawn", {"ssl"})]


def test_restart_keeps_bypasses_turned_on_live(env, monkeypatch):
    """Ctrl+P on the running app (active, not armed), then ⇧R: still on."""
    from sandroid.core.adb import Adb

    log: list = []
    _ladder(env, monkeypatch, log)
    monkeypatch.setattr(app_start.time, "sleep", lambda s: None)
    monkeypatch.setattr(Adb, "force_stop", staticmethod(lambda pkg: None))
    env.bypass._armed = {"root"}
    env.bypass._active = {"ssl"}
    env.bypass._app_package = PKG

    assert app_start.restart_app() == (True, "ok")
    assert log == [("spawn", {"ssl", "root"})]


def test_prepare_launch_restarts_a_running_app_only_with_consent(
    env, framework, monkeypatch
):
    """Objection spawn on a running app: dialog first, then stop, then plans."""
    order: list = []
    monkeypatch.setattr(
        app_start, "respawn_teardown", lambda pkg: order.append(("teardown", pkg))
    )
    framework.pids = [100]
    app_start.register_pre_start_step(
        lambda pkg: app_start.PreStartPlan(DESC, False, lambda: order.append("plan"))
    )
    env.live = (Liveness.RUNNING, 77)

    assert app_start.prepare_launch(PKG, "Objection") is False
    assert order == []

    assert app_start.prepare_launch(PKG, "Objection", restart=True) is True
    assert order == [("teardown", PKG), "plan"]
    assert not env.spotlight.is_restarting()


def test_teardown_arms_live_bypasses_before_the_kill(env, monkeypatch):
    """The liveness poll may clear the active set once the app is dead."""
    from sandroid.core.adb import Adb

    monkeypatch.setattr(app_start.time, "sleep", lambda s: None)
    env.bypass._active = {"ssl"}
    env.bypass._app_package = PKG

    def _kill(pkg):
        env.bypass._active.clear()  # the poll saw the dead process

    monkeypatch.setattr(Adb, "force_stop", staticmethod(_kill))

    app_start.respawn_teardown(PKG)

    assert env.bypass.armed_categories() == ["ssl"]


def test_restart_leaves_the_previous_apps_live_bypass_behind(env, monkeypatch):
    """Ctrl+P on app A, select B (disarms), ⇧R on B: B starts clean."""
    from sandroid.core.adb import Adb

    log: list = []
    _ladder(env, monkeypatch, log)
    monkeypatch.setattr(app_start.time, "sleep", lambda s: None)
    monkeypatch.setattr(Adb, "force_stop", staticmethod(lambda pkg: None))
    env.bypass._active = {"ssl"}
    env.bypass._app_package = "org.example.previous"

    assert app_start.restart_app() == (True, "ok")
    assert log == [("spawn", set())]
    assert env.bypass.armed_categories() == []


def test_respawn_teardown_keeps_live_bypasses_armed(env, monkeypatch):
    """A tool's confirmed respawn re-applies what was on live, too."""
    from sandroid.core.adb import Adb

    monkeypatch.setattr(app_start.time, "sleep", lambda s: None)
    monkeypatch.setattr(Adb, "force_stop", staticmethod(lambda pkg: None))
    env.bypass._active = {"ssl"}
    env.bypass._app_package = PKG

    app_start.respawn_teardown(PKG)

    assert env.bypass.armed_categories() == ["ssl"]
    assert env.bypass.active_categories() == []


def test_a_recovery_timeout_still_stops_the_launched_apps_tools(env, monkeypatch):
    other = "org.example.other"
    env.tasks = [SimpleNamespace(name="dexray", app_name=other, display_name="Dexray")]
    pids = iter([100, 200])
    monkeypatch.setattr(app_start, "_system_server_pid", lambda serial=None: next(pids))

    def timeout(pid, timeout=90.0):
        raise AppStartError("did not come back")

    monkeypatch.setattr(app_start, "recover_after_framework_restart", timeout)
    app_start.register_pre_start_step(_hook([], disruptive=True))

    plans = app_start._collect_pre_start(other, other)
    with pytest.raises(AppStartError, match="did not come back"):
        app_start._apply_pre_start(plans, other)
    assert env.stopped == ["dexray"]


def test_ai_start_tools_leave_timeouts_to_the_executor(env, monkeypatch):
    """No helper thread: the executor's timeout keeps the lease until the
    start really ends, and errors reach the model.
    """
    from sandroid.ai.tools import app_lifecycle, session_control

    assert not hasattr(session_control, "run_within_tool_deadline")

    def boom(*a, **k):
        raise RuntimeError("adb gone")

    monkeypatch.setattr(app_start, "prepare_launch", boom)
    with pytest.raises(RuntimeError, match="adb gone"):
        app_lifecycle.launch_app(PKG)


# -- machine-readable refusal reasons (the AI tools act on them) --------------------


def test_start_refusals_carry_a_reason(env, monkeypatch, bus):
    """needs_consent without a dialog, declined on Cancel, busy on the lock."""
    log: list = []
    _ladder(env, monkeypatch, log)
    app_start.register_pre_start_step(
        lambda pkg: app_start.PreStartPlan(DESC, True, lambda: None)
    )
    bus.active = False

    result = app_start.start_app()  # no UI handler, no consent
    ok, msg = result
    assert not ok
    assert result.reason == "needs_consent"
    assert log == []

    held = threading.Event()
    release = threading.Event()

    def _hold():
        with app_start.lifecycle_lock():
            held.set()
            release.wait(5)

    t = threading.Thread(target=_hold)
    t.start()
    held.wait(5)
    try:
        assert app_start.start_app().reason == "busy"
        assert app_start.restart_app().reason == "busy"
        with pytest.raises(AppStartError) as exc:
            with app_start.lifecycle_lock():
                pass
        assert exc.value.reason == "busy"
    finally:
        release.set()
        t.join(5)


def test_a_declined_pre_start_step_says_declined(bus):
    bus.answer = False
    plans = [app_start.PreStartPlan(DESC, True, lambda: None)]
    out: list = []

    def _run():
        try:
            app_start._confirm_pre_start(plans, PKG, "Start", False)
        except AppStartError as exc:
            out.append(exc)

    t = threading.Thread(target=_run)  # the dialog is refused on the UI thread
    t.start()
    t.join(5)
    assert len(out) == 1
    assert out[0].reason == "declined"


def test_the_old_pre_spawn_names_still_work():
    for old, new in (
        ("PreSpawnPlan", "PreStartPlan"),
        ("PreSpawnHook", "PreStartStep"),
        ("register_pre_spawn_hook", "register_pre_start_step"),
        ("unregister_pre_spawn_hook", "unregister_pre_start_step"),
        ("pre_spawn_running", "pre_start_running"),
        ("pre_spawn_status", "pre_start_status"),
        ("add_pre_spawn_status_listener", "add_pre_start_status_listener"),
        ("remove_pre_spawn_status_listener", "remove_pre_start_status_listener"),
    ):
        assert getattr(app_start, old) is getattr(app_start, new), old
    assert app_start.StartResult(True, "ok") == (True, "ok")
    assert app_start.StartResult.of((False, "x")).reason is None


def test_start_and_restart_always_return_a_start_result(env, monkeypatch, bus):
    log: list = []
    _ladder(env, monkeypatch, log)
    monkeypatch.setattr(app_start, "respawn_teardown", lambda pkg: None)

    ok = app_start.start_app()
    assert isinstance(ok, app_start.StartResult)
    assert ok == (True, "ok")
    assert ok.reason is None

    bus.answer = False  # Cancel in the pre-start dialog
    app_start.register_pre_start_step(
        lambda pkg: app_start.PreStartPlan(DESC, True, lambda: None)
    )
    out: list = []
    t = threading.Thread(target=lambda: out.append(app_start.restart_app()))
    t.start()
    t.join(5)
    assert out[0].reason == "declined"
    assert not out[0][0]
