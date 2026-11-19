"""The one start rule (sandroid.services.app_start) and its callers.

Covers the decision table, liveness (running / not running / unknown), the
restart confirmation, acting on a decision (open_session, owned resume), the
lifecycle functions behind Space/⇧P/⇧R/⇧A, and the regressions of the old
spawn/attach mode (bugs 1-5 of the selection brief). No device: adb, the
JobManager and the UI request bus are fakes.
"""

from __future__ import annotations

import threading
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


def test_trigdroid_on_a_running_app_needs_confirmation():
    d = decide_start(_inputs(fresh=True, tool="TrigDroid"))
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
    app_start.end_setup()
    yield
    app_start.end_setup()


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


def test_trigdroid_attaches_to_a_running_app_and_never_restarts(env, bus, monkeypatch):
    """TrigDroid spawns outside the JobManager: no RESPAWN, ever."""
    from sandroid.features.trigdroid import Trigdroid
    from sandroid.services import get_trigdroid_config_service

    cfg = get_trigdroid_config_service()
    monkeypatch.setattr(cfg, "fresh", False)
    env.live = (Liveness.RUNNING, 77)

    # spawn_mode=True (the default) no longer restarts a running app.
    assert _in_worker(lambda: Trigdroid._resolve_spawn(PKG, True)) is False

    monkeypatch.setattr(cfg, "fresh", True)  # needs a fresh process: refuse
    assert _in_worker(lambda: Trigdroid._resolve_spawn(PKG, True)) is None
    bus.active = False  # headless: refuses too, never kills
    assert _in_worker(lambda: Trigdroid._resolve_spawn(PKG, True)) is None
    assert bus.asked == []

    env.live = (Liveness.NOT_RUNNING, None)
    assert _in_worker(lambda: Trigdroid._resolve_spawn(PKG, True)) is True
    assert _in_worker(lambda: Trigdroid._resolve_spawn(PKG, False)) is None


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
