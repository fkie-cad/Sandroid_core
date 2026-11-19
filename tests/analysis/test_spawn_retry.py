"""Unit tests for the spawn-reliability ladder (no device required).

Covers:
- ``classify_spawn_failure`` taxonomy, including the load-bearing
  dirty-before-crash ordering.
- ``BypassService._poll_liveness`` guards (device-None accept, pid-vanish =>
  crash, transport-hiccup => alive).
- ``BypassService.apply_to_fresh_spawn_with_retry`` orchestration:
  (a) dirty-server => restart-once => re-spawn => success on attempt 2;
  (b) repeated ProcessNotFoundError => no restart => fail-loud after N with the
      anti-Frida diagnostic;
  (c) pid vanishes after resume => failure => re-spawn => eventual success
      (never a silent success);
  (d) attempt cap respected (spawn called exactly N times);
  (e) late_attach / non-spawn mode => ladder skipped (single call, no liveness);
  (f) each failed attempt calls ``_teardown_failed_spawn`` (Adb.force_stop);
  (g) ``resume=False`` (Start-paused) is not subjected to the liveness poll.

Style mirrors ``tests/core/test_device_manager_disconnect.py`` (monkeypatch +
fresh-instance isolation; no real ADB/Frida).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import frida
import pytest

from sandroid.analysis import detection_bypass as db
from sandroid.analysis.detection_bypass import BypassService, classify_spawn_failure
from sandroid.core.toolbox import Toolbox

PID = 4242


# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------
class FakeSpotlight:
    """Minimal spotlight double for the spawn paths."""

    def __init__(self, pid: int = PID) -> None:
        self._pid = pid
        self._seed_pid = pid
        self.spawn_calls: list[str] = []
        self.set_pid_calls: list = []
        self.auto_resume = None

    def get_pid(self):
        return self._pid

    def set_pid(self, pid) -> None:
        self.set_pid_calls.append(pid)
        self._pid = pid

    def announce_pid(self, pid, package=None) -> bool:
        self.set_pid(pid)  # the real one publishes too
        return True

    def spawn_app_paused(self, package: str):
        self.spawn_calls.append(package)
        return (object(), self._seed_pid)


class _Proc:
    def __init__(self, pid: int) -> None:
        self.pid = pid


class FakeDevice:
    """enumerate_processes() driven by a scripted sequence.

    Each element is either a list of present pids (returned as _Proc objects)
    or an Exception instance (raised). The last element repeats when exhausted.
    """

    def __init__(self, sequence) -> None:
        self._seq = list(sequence)
        self._i = 0

    def enumerate_processes(self):
        item = self._seq[min(self._i, len(self._seq) - 1)]
        self._i += 1
        if isinstance(item, BaseException):
            raise item
        return [_Proc(p) for p in item]


def make_spawn_fn(results, spotlight: FakeSpotlight | None = None, pid: int = PID):
    """Build a scripted ``spawn_fn`` returning canned (ok, msg) tuples.

    On a successful result it mirrors the real spawn by surfacing the pid via
    ``spotlight.set_pid`` so the ladder's liveness step has a pid to poll.
    """
    seq = iter(results)
    calls: list[dict] = []

    def _fn(package, categories, on_message=None, resume=True):
        calls.append({"package": package, "resume": resume})
        ok, msg = next(seq)
        if ok and spotlight is not None:
            spotlight.set_pid(pid)
        return ok, msg

    _fn.calls = calls  # type: ignore[attr-defined]
    return _fn


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
@pytest.fixture
def spotlight(monkeypatch) -> FakeSpotlight:
    sl = FakeSpotlight()
    monkeypatch.setattr("sandroid.services.get_spotlight_service", lambda: sl)
    return sl


@pytest.fixture
def force_stop_spy(monkeypatch) -> Mock:
    """Spy Adb.force_stop and neutralise the other teardown side effects."""
    spy = Mock()
    from sandroid.core.adb import Adb

    monkeypatch.setattr(Adb, "force_stop", staticmethod(spy))
    # _teardown_failed_spawn -> _reset_script_state -> _unregister_task and
    # reset_session touch services; stub them to harmless mocks.
    monkeypatch.setattr(db, "get_task_service", Mock)
    monkeypatch.setattr(Toolbox, "get_frida_job_manager", staticmethod(Mock()))
    return spy


@pytest.fixture
def cfg(monkeypatch):
    """Patch get_config; tests tune the knobs via the returned setter."""

    def _set(attempts: int = 4, window: float = 0.0, retry: float = 0.0):
        fake = SimpleNamespace(
            frida=SimpleNamespace(
                spawn_attempts=attempts,
                spawn_splash_window=window,
                spawn_retry_sleep=retry,
            )
        )
        monkeypatch.setattr("sandroid.config.get_config", lambda: fake)

    _set()  # sensible defaults; tests may re-call to override
    return _set


@pytest.fixture
def bypass() -> BypassService:
    return BypassService()


# --------------------------------------------------------------------------
# classify_spawn_failure
# --------------------------------------------------------------------------
class TestClassify:
    def test_dirty_markers(self):
        assert classify_spawn_failure("please restart frida-server again") == "dirty"
        assert classify_spawn_failure("TransportError: connection issue") == "dirty"
        assert classify_spawn_failure("the connection is closed") == "dirty"
        assert classify_spawn_failure("operation timed out (timeout)") == "dirty"

    def test_crash_markers(self):
        assert classify_spawn_failure("process no longer exists") == "crash"
        assert (
            classify_spawn_failure("Process 9 died during hook load — anti-Frida")
            == "crash"
        )
        assert classify_spawn_failure("the script destroyed itself") == "crash"

    def test_benign_markers(self):
        assert classify_spawn_failure("process already running") == "benign"
        assert classify_spawn_failure("InvalidOperationError") == "benign"

    def test_other(self):
        assert classify_spawn_failure("") == "other"
        assert classify_spawn_failure(None) == "other"
        assert classify_spawn_failure("some unrelated thing") == "other"

    def test_dirty_before_crash_ordering(self):
        """AFM's TransportError text contains 'may have crashed' — remedy is a
        server restart, so it MUST classify as dirty, not crash.
        """
        msg = (
            "TransportError: server may have crashed or restarted; restart frida-server"
        )
        assert "crash" in msg  # the trap
        assert classify_spawn_failure(msg) == "dirty"

    def test_real_processnotfound_message_is_crash(self):
        """The exact string apply_to_fresh_spawn emits on a resume crash must
        classify as crash (guards against taxonomy/string drift).
        """
        real = (
            f"Process {PID} died during hook load — target likely has "
            "anti-Frida detection. Enable the Frida detection bypass first, "
            "or attach after the app is fully started instead of spawning."
        )
        assert classify_spawn_failure(real) == "crash"

    def test_real_no_pid_message_is_dirty(self):
        """A no-PID spawn is the canonical dead/wedged-frida-server symptom and
        MUST route to the server-restart remedy (dirty), not a bare re-spawn.
        """
        real = "Failed to spawn com.x (no PID — is frida-server running?)"
        assert classify_spawn_failure(real) == "dirty"

    def test_exc_type_fastpath(self):
        assert (
            classify_spawn_failure("", exc=frida.ProcessNotFoundError("x")) == "crash"
        )
        assert (
            classify_spawn_failure("", exc=frida.InvalidOperationError("x")) == "benign"
        )


# --------------------------------------------------------------------------
# _poll_liveness
# --------------------------------------------------------------------------
class TestPollLiveness:
    def test_device_none_accepts(self, bypass):
        # Cannot confirm a crash without a device — accept the good spawn.
        assert bypass._poll_liveness(None, PID, 1.0) is True

    def test_present_pid_survives(self, bypass):
        dev = FakeDevice([[PID, 1, 2]])
        assert bypass._poll_liveness(dev, PID, 0.0) is True

    def test_absent_pid_is_crash(self, bypass):
        dev = FakeDevice([[1, 2, 3]])  # PID missing
        assert bypass._poll_liveness(dev, PID, 0.0) is False

    def test_pid_vanishes_mid_window(self, bypass, monkeypatch):
        monkeypatch.setattr(db.time, "sleep", lambda *_: None)
        dev = FakeDevice([[PID], [PID], []])  # alive, alive, gone
        assert bypass._poll_liveness(dev, PID, 1.0) is False

    def test_transport_hiccup_treated_as_alive(self, bypass, monkeypatch):
        monkeypatch.setattr(db.time, "sleep", lambda *_: None)
        # A blip raises, then the pid is present again — must NOT be a crash.
        dev = FakeDevice([RuntimeError("transport blip"), [PID]])
        assert bypass._poll_liveness(dev, PID, 0.0) is True

    def test_process_not_found_is_crash(self, bypass):
        dev = FakeDevice([frida.ProcessNotFoundError("gone")])
        assert bypass._poll_liveness(dev, PID, 0.0) is False


# --------------------------------------------------------------------------
# apply_to_fresh_spawn_with_retry — orchestration (spawn_fn injection)
# --------------------------------------------------------------------------
class TestRetryLadder:
    def test_happy_path_no_retry(self, bypass, spotlight, cfg, monkeypatch):
        cfg(attempts=4, window=0.0)
        monkeypatch.setattr(bypass, "_frida_device", object)
        monkeypatch.setattr(bypass, "_poll_liveness", Mock(return_value=True))
        teardown = Mock()
        monkeypatch.setattr(bypass, "_teardown_failed_spawn", teardown)
        sfn = make_spawn_fn([(True, "Spawned com.x with 1 bypass")], spotlight)

        ok, msg = bypass.apply_to_fresh_spawn_with_retry("com.x", {"ssl"}, spawn_fn=sfn)

        assert ok is True
        assert len(sfn.calls) == 1
        teardown.assert_not_called()

    def test_ladder_runs_for_an_app_picked_with_c(
        self, bypass, cfg, force_stop_spy, monkeypatch
    ):
        """Bug 4: a `c` selection (set_app, no mode) gets the retry ladder."""
        from sandroid.services.spotlight_service import SpotlightService

        svc = SpotlightService()
        svc.set_app("com.x", pid=1)
        monkeypatch.setattr("sandroid.services.get_spotlight_service", lambda: svc)
        cfg(attempts=4, window=0.0)
        monkeypatch.setattr(bypass, "_frida_device", object)
        monkeypatch.setattr(bypass, "_poll_liveness", Mock(side_effect=[False, True]))
        sfn = make_spawn_fn([(True, "Spawned"), (True, "Spawned")], svc)

        ok, msg = bypass.apply_to_fresh_spawn_with_retry("com.x", {"ssl"}, spawn_fn=sfn)

        assert ok is True
        assert len(sfn.calls) == 2  # the PID vanished: re-spawned

    def test_resume_false_no_liveness(self, bypass, spotlight, cfg, monkeypatch):
        poll = Mock(return_value=True)
        monkeypatch.setattr(bypass, "_poll_liveness", poll)
        monkeypatch.setattr(bypass, "_frida_device", object)
        sfn = make_spawn_fn([(True, "Spawned (paused)")], spotlight)

        ok, msg = bypass.apply_to_fresh_spawn_with_retry(
            "com.x", {"ssl"}, resume=False, spawn_fn=sfn
        )

        assert ok is True
        poll.assert_not_called()  # start-paused is intentionally frozen

    def test_pid_vanish_then_success(
        self, bypass, spotlight, cfg, force_stop_spy, monkeypatch
    ):
        cfg(attempts=4, window=0.0)
        monkeypatch.setattr(bypass, "_frida_device", object)
        # attempt 1 spawns ok but pid vanished; attempt 2 survives.
        monkeypatch.setattr(bypass, "_poll_liveness", Mock(side_effect=[False, True]))
        sfn = make_spawn_fn([(True, "Spawned"), (True, "Spawned")], spotlight)

        ok, msg = bypass.apply_to_fresh_spawn_with_retry("com.x", {"ssl"}, spawn_fn=sfn)

        assert ok is True
        assert len(sfn.calls) == 2  # re-spawned, not a silent success
        force_stop_spy.assert_called_once_with("com.x")  # one failed attempt

    def test_attempt_cap_and_fail_loud(
        self, bypass, spotlight, cfg, force_stop_spy, monkeypatch
    ):
        cfg(attempts=3, window=0.0)
        monkeypatch.setattr(bypass, "_frida_device", object)
        monkeypatch.setattr(bypass, "_poll_liveness", Mock(return_value=False))
        sfn = make_spawn_fn([(True, "Spawned")] * 3, spotlight)

        ok, msg = bypass.apply_to_fresh_spawn_with_retry("com.x", {"ssl"}, spawn_fn=sfn)

        assert ok is False
        assert len(sfn.calls) == 3  # exactly N spawn attempts
        assert "exhausted 3 attempts" in msg
        assert "Not falling back to attach" in msg
        assert "anti-Frida" in msg
        # teardown per failed attempt (3) + final fail-loud teardown (1).
        assert force_stop_spy.call_count == 4

    def test_benign_already_running_is_success(
        self, bypass, spotlight, cfg, monkeypatch
    ):
        cfg(attempts=4)
        teardown = Mock()
        monkeypatch.setattr(bypass, "_teardown_failed_spawn", teardown)
        sfn = make_spawn_fn(
            [(False, "Process already running; skipping resume")], spotlight
        )

        ok, msg = bypass.apply_to_fresh_spawn_with_retry("com.x", {"ssl"}, spawn_fn=sfn)

        assert ok is True  # benign => treated as success
        assert len(sfn.calls) == 1
        teardown.assert_not_called()

    def test_dirty_triggers_single_restart_then_success(
        self, bypass, spotlight, cfg, force_stop_spy, monkeypatch
    ):
        cfg(attempts=4, window=0.0)
        monkeypatch.setattr(bypass, "_frida_device", object)
        monkeypatch.setattr(bypass, "_poll_liveness", Mock(return_value=True))

        recover = Mock()
        monkeypatch.setattr(bypass, "_recover_frida_server", recover)
        sfn = make_spawn_fn(
            [
                (False, "TransportError: please restart frida-server again"),
                (True, "Spawned"),
            ],
            spotlight,
        )

        ok, msg = bypass.apply_to_fresh_spawn_with_retry("com.x", {"ssl"}, spawn_fn=sfn)

        assert ok is True
        assert len(sfn.calls) == 2
        recover.assert_called_once()  # server restart fired exactly once

    def test_no_pid_failure_triggers_recovery(
        self, bypass, spotlight, cfg, force_stop_spy, monkeypatch
    ):
        """A no-PID spawn (dead/wedged server) must drive the restart path."""
        cfg(attempts=4, window=0.0)
        monkeypatch.setattr(bypass, "_frida_device", object)
        monkeypatch.setattr(bypass, "_poll_liveness", Mock(return_value=True))
        recover = Mock()
        monkeypatch.setattr(bypass, "_recover_frida_server", recover)
        # The exact string apply_to_fresh_spawn emits when spawn yields no pid.
        sfn = make_spawn_fn(
            [
                (False, "Failed to spawn com.x (no PID — is frida-server running?)"),
                (True, "Spawned"),
            ],
            spotlight,
        )

        ok, _ = bypass.apply_to_fresh_spawn_with_retry("com.x", {"ssl"}, spawn_fn=sfn)

        assert ok is True
        recover.assert_called_once()  # dead-server symptom => restart, not bare retry

    def test_dirty_restart_fires_at_most_once(
        self, bypass, spotlight, cfg, force_stop_spy, monkeypatch
    ):
        cfg(attempts=4, window=0.0)
        monkeypatch.setattr(bypass, "_frida_device", object)
        monkeypatch.setattr(bypass, "_poll_liveness", Mock(return_value=True))
        recover = Mock()
        monkeypatch.setattr(bypass, "_recover_frida_server", recover)
        # Three consecutive dirty failures, then success.
        sfn = make_spawn_fn(
            [
                (False, "connection is closed"),
                (False, "transport error"),
                (False, "ProtocolError"),
                (True, "Spawned"),
            ],
            spotlight,
        )

        ok, _ = bypass.apply_to_fresh_spawn_with_retry("com.x", {"ssl"}, spawn_fn=sfn)

        assert ok is True
        recover.assert_called_once()  # at most once across the whole ladder

    def test_recover_frida_server_restarts_once_and_invalidates(
        self, bypass, monkeypatch
    ):
        fm = Mock()
        fm.restart_frida_server_and_wait.return_value = True
        svc = Mock()
        svc.get_frida_manager.return_value = fm
        monkeypatch.setattr("sandroid.services.get_frida_session_service", lambda: svc)

        bypass._recover_frida_server()

        fm.restart_frida_server_and_wait.assert_called_once()
        svc.invalidate_frida_device_cache.assert_called_once()


# --------------------------------------------------------------------------
# apply_to_fresh_spawn_with_retry — real apply_to_fresh_spawn path
# (validates the classifier against the genuine error strings)
# --------------------------------------------------------------------------
class TestRealSpawnPath:
    @pytest.fixture(autouse=True)
    def _wire_real_path(self, monkeypatch, force_stop_spy):
        # is_paused_session reads Toolbox; force it True so apply_to_fresh_spawn
        # proceeds without touching the real job manager.
        monkeypatch.setattr(BypassService, "is_paused_session", lambda self: True)

    def test_real_dirty_string_restarts_then_succeeds(
        self, bypass, spotlight, cfg, monkeypatch
    ):
        cfg(attempts=4, window=0.0)
        monkeypatch.setattr(bypass, "_frida_device", object)
        monkeypatch.setattr(bypass, "_poll_liveness", lambda *a, **k: True)
        recover = Mock()
        monkeypatch.setattr(bypass, "_recover_frida_server", recover)

        # set_active returns a dirty-server failure first, then loads cleanly.
        set_active = Mock(
            side_effect=[
                (False, "TransportError: restart frida-server again"),
                (True, "Loaded 1 bypass"),
            ]
        )
        monkeypatch.setattr(bypass, "set_active", set_active)
        # Resume succeeds on the second (good) attempt.
        monkeypatch.setattr(
            Toolbox, "resume_spawned_process_after_hooks", Mock(return_value=None)
        )

        ok, msg = bypass.apply_to_fresh_spawn_with_retry("com.x", {"ssl"})

        assert ok is True
        assert set_active.call_count == 2  # re-spawned through the real path
        recover.assert_called_once()
        assert spotlight.spawn_calls == ["com.x", "com.x"]

    def test_real_processnotfound_fails_loud_no_restart(
        self, bypass, spotlight, cfg, monkeypatch
    ):
        cfg(attempts=3, window=0.0)
        monkeypatch.setattr(bypass, "_frida_device", object)
        recover = Mock()
        monkeypatch.setattr(bypass, "_recover_frida_server", recover)

        monkeypatch.setattr(bypass, "set_active", Mock(return_value=(True, "Loaded")))
        # Every resume raises ProcessNotFoundError (anti-Frida self-kill).
        monkeypatch.setattr(
            Toolbox,
            "resume_spawned_process_after_hooks",
            Mock(side_effect=frida.ProcessNotFoundError("died")),
        )

        ok, msg = bypass.apply_to_fresh_spawn_with_retry("com.x", {"ssl"})

        assert ok is False
        assert spotlight.spawn_calls == ["com.x"] * 3  # exactly N attempts
        recover.assert_not_called()  # crash != dirty => no server restart
        assert "exhausted 3 attempts" in msg
        assert "anti-Frida" in msg


# --------------------------------------------------------------------------
# E2E M6: frida-server down after a wedge -> one clear message, fresh state
# --------------------------------------------------------------------------
GADGET = (
    "need Gadget to attach on jailed Android; its default location is: "
    "/x/.cache/frida/gadget-android-arm64.so"
)
NO_PID = "Failed to spawn com.x (no PID — is frida-server running?)"


class TestFridaServerDown:
    def test_failed_restart_stops_the_ladder_with_a_clear_message(
        self, bypass, spotlight, cfg, force_stop_spy, monkeypatch
    ):
        cfg(attempts=4)
        recover = Mock(return_value=False)  # "frida-server restart -> ready=False"
        monkeypatch.setattr(bypass, "_recover_frida_server", recover)
        sfn = make_spawn_fn([(False, NO_PID)] * 4, spotlight)

        ok, msg = bypass.apply_to_fresh_spawn_with_retry("com.x", {"ssl"}, spawn_fn=sfn)

        assert ok is False
        assert len(sfn.calls) == 1  # not 3 more doomed "need Gadget" attempts
        assert msg.startswith(db.FRIDA_SERVER_DOWN_MSG)
        recover.assert_called_once()

    def test_gadget_error_after_restart_stops_the_ladder(
        self, bypass, spotlight, cfg, force_stop_spy, monkeypatch
    ):
        cfg(attempts=4)
        monkeypatch.setattr(bypass, "_recover_frida_server", Mock(return_value=True))
        sfn = make_spawn_fn(
            [(False, NO_PID), (False, GADGET), (True, "Spawned")], spotlight
        )

        ok, msg = bypass.apply_to_fresh_spawn_with_retry("com.x", {"ssl"}, spawn_fn=sfn)

        assert ok is False
        assert len(sfn.calls) == 2
        assert msg == f"{db.FRIDA_SERVER_DOWN_MSG} (spawn of com.x)"

    def test_spawn_reports_the_gadget_error_as_server_down(
        self, bypass, spotlight, monkeypatch
    ):
        """apply_to_fresh_spawn names the cause instead of frida's wording."""
        spotlight.spawn_app_paused = lambda package: (None, -1)
        spotlight.last_spawn_error = GADGET
        monkeypatch.setattr(BypassService, "_reset_script_state", lambda self: None)

        ok, msg = bypass.apply_to_fresh_spawn("com.x", {"ssl"})

        assert ok is False
        assert msg == f"{db.FRIDA_SERVER_DOWN_MSG} (spawn of com.x)"
        assert db.classify_spawn_failure(msg) == "dirty"
        # Any other failure keeps the old wording.
        spotlight.last_spawn_error = "timeout was reached"
        assert bypass.apply_to_fresh_spawn("com.x", {"ssl"})[1] == NO_PID

    def test_recover_reports_readiness(self, bypass, monkeypatch):
        fm = Mock()
        fm.restart_frida_server_and_wait.return_value = False
        svc = Mock()
        svc.get_frida_manager.return_value = fm
        monkeypatch.setattr("sandroid.services.get_frida_session_service", lambda: svc)
        assert bypass._recover_frida_server() is False
        svc.get_frida_manager.return_value = None
        assert bypass._recover_frida_server() is None


def _real_spotlight(pid: int = 9117):
    from sandroid.services.spotlight_service import SpotlightService

    events: list = []
    svc = SpotlightService(event_bus=SimpleNamespace(publish=events.append))
    svc.set_app("org.mozilla.firefox", pid=pid)
    events.clear()
    return svc, events


def _pid_events(events) -> list:
    return [
        e.data["pid"] for e in events if e.data.get("change_type") == "spotlight_pid"
    ]


def test_failed_spawn_teardown_publishes_the_cleared_pid(bypass, force_stop_spy):
    """E2E M6: the header kept "running pid 9117" for a minute after the
    spawn failed; the PID clear must publish STATE_CHANGED (panel + header
    refresh), not only update the cache.
    """
    svc, events = _real_spotlight()
    bypass._teardown_failed_spawn(svc, "org.mozilla.firefox")
    assert svc.get_pid() is None
    assert _pid_events(events) == [None]


def _patch_restart(monkeypatch, svc, bypass, order=None):
    """Route app_start.restart_app at ``svc``/``bypass``; no device."""
    from sandroid import services
    from sandroid.core.adb import Adb
    from sandroid.services import app_start

    monkeypatch.setattr(services, "get_spotlight_service", lambda: svc)
    monkeypatch.setattr(app_start, "_bypass", lambda: bypass)
    monkeypatch.setattr(app_start, "_job_manager", lambda: None)
    monkeypatch.setattr(app_start, "stop_app_tools", lambda package: [])
    monkeypatch.setattr(app_start.time, "sleep", lambda s: None)
    monkeypatch.setattr(
        Adb,
        "force_stop",
        staticmethod(
            lambda package: order.append(("kill",)) if order is not None else None
        ),
    )
    return app_start


def test_restart_publishes_the_dead_pid_before_spawning(monkeypatch):
    svc, events = _real_spotlight()
    seen_at_spawn = []

    class _Bypass:
        def armed_categories(self):
            return {"ssl"}

        def carried_categories(self, package):
            return {"ssl"}

        def forget_process(self):
            pass

        def apply_to_fresh_spawn_with_retry(self, package, armed, resume=True):
            seen_at_spawn.append((svc.get_pid(), _pid_events(events)))
            return False, db.FRIDA_SERVER_DOWN_MSG

    app_start = _patch_restart(monkeypatch, svc, _Bypass())

    ok, msg = app_start.restart_app()

    assert (ok, msg) == (False, db.FRIDA_SERVER_DOWN_MSG)
    # The header already showed "not running" while the spawn ladder ran.
    assert seen_at_spawn == [(None, [None])]


# ---------------------------------------------------------------------------
# E2E round 3 (M6/N2): the header kept the dead PID for 13-28 s during ⇧R
# ---------------------------------------------------------------------------


def test_restart_says_restarting_from_the_kill_until_the_new_pid(monkeypatch):
    svc, events = _real_spotlight()
    order: list = []

    class _Bypass:
        def armed_categories(self):
            return set()

        def carried_categories(self, package):
            return set()

        def forget_process(self):
            # Already published before the (slow) teardown and spawn.
            order.append(("forget", svc.get_pid(), svc.is_restarting()))

        def apply_to_fresh_spawn_with_retry(self, package, armed, resume=True):
            assert svc.announce_pid(12345, package)  # the spawn knows it
            order.append(("spawned", svc.get_pid(), svc.is_restarting()))
            return True, "Spawned"

    app_start = _patch_restart(monkeypatch, svc, _Bypass(), order)

    assert app_start.restart_app() == (True, "Spawned")
    assert order == [
        ("kill",),
        ("forget", None, True),
        ("spawned", 12345, True),
    ]
    assert not svc.is_restarting("org.mozilla.firefox")
    published = [
        (e.data["pid"], e.data["restarting"])
        for e in events
        if e.data.get("change_type") == "spotlight_pid"
    ]
    # "restarting…" at the kill, the new PID at once, then the end.
    assert published == [(None, True), (12345, True), (12345, False)]


def test_shared_spotlight_service_publishes_pid_changes_on_the_bus():
    """The shared instance has no injected bus: announce_pid was silent."""
    from sandroid.core.events import EventBus, EventType
    from sandroid.services.spotlight_service import SpotlightService

    svc = SpotlightService()
    svc.set_app("org.mozilla.firefox", pid=22155)
    seen: list = []

    def _cb(event):
        if event.data.get("change_type") == "spotlight_pid":
            seen.append(event.data["pid"])

    EventBus.get().subscribe(EventType.STATE_CHANGED, _cb)
    try:
        assert svc.announce_pid(23326, "org.mozilla.firefox")
    finally:
        EventBus.get().unsubscribe(EventType.STATE_CHANGED, _cb)
    assert seen == [23326]


def test_fresh_spawn_announces_its_pid_before_hooks_and_resume(bypass, monkeypatch):
    calls: list = []
    spotlight = Mock()
    spotlight.spawn_app_paused.return_value = (Mock(), 23326)
    spotlight.announce_pid.side_effect = lambda pid, pkg: calls.append(pid) or True
    monkeypatch.setattr("sandroid.services.get_spotlight_service", lambda: spotlight)
    monkeypatch.setattr(
        bypass, "set_active", lambda *a, **k: (calls.append("hooks"), (False, "x"))[1]
    )
    monkeypatch.setattr(bypass, "_teardown_failed_spawn", lambda *a: None)
    monkeypatch.setattr(bypass, "_reset_script_state", lambda: None)
    monkeypatch.setattr(bypass, "is_paused_session", lambda: True)
    bypass.apply_to_fresh_spawn("org.mozilla.firefox", {"ssl"})
    assert calls[:2] == [23326, "hooks"]
    spotlight.set_pid.assert_not_called()
