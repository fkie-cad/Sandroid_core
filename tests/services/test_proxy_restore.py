"""One restore entry point for the proxy infra, the post-load sequence of
EmulatorService.load_snapshot, the device-prepared hook, the CA fallback
gating and the long-lived stream restarts after a load.
"""

from __future__ import annotations

import itertools
import sys
import types
from types import SimpleNamespace

import pytest

from sandroid.core import proxy_manager as pm
from sandroid.services import emulator_service as es
from sandroid.services import mitmproxy_service as ms
from sandroid.services import proxy_restore as pr

SERIAL = "emulator-5570"


class _Guard:
    """The device guard's leftover check, recorded (no device)."""

    def __init__(self):
        self.reconciled: list[tuple] = []

    def has_state(self, serial):
        return False

    def view_cached(self, serial=None):
        from sandroid.core.device_guard import GuardView

        return GuardView()

    def reconcile(self, serial, cause=""):
        from sandroid.core.device_guard import GuardView

        self.reconciled.append((serial, cause))
        return GuardView()


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    from sandroid.core import device_guard as dg

    pm._CA_DESIRED.clear()
    monkeypatch.setattr(pm, "_FOCUS_INSTANCE", None)
    monkeypatch.setattr(ms, "_INSTANCE", None)
    monkeypatch.setattr(pr, "_HOOK_INSTALLED", False)
    monkeypatch.setattr(dg, "_INSTANCE", _Guard())
    yield
    pm._CA_DESIRED.clear()


def _report(pkg="de.fkie.privacycanary", state=pm.LANE_ACTIVE, repaired=()):
    return pm.LaneReport(pkg, 0, pm.LaneHealth(state), list(repaired))


class _Focus:
    def __init__(self, calls, lanes=True):
        self.calls, self.lanes = calls, lanes

    def has_lanes(self, serial=None):
        return self.lanes

    def reconcile(self, serial=None, reason=""):
        self.calls.append(("lanes", serial, reason))
        return [_report(repaired=["gost restarted"])]


class _Mitm:
    owned_device_proxy = "127.0.0.1:8080"
    owned_device_proxy_serial = SERIAL

    def __init__(self, calls):
        self.calls = calls

    def reapply_device_proxy(self, serial=None):
        self.calls.append(("device_proxy", serial))
        return "kept"


def _with_everything(monkeypatch, calls):
    monkeypatch.setattr(pm, "_FOCUS_INSTANCE", _Focus(calls))
    monkeypatch.setattr(ms, "_INSTANCE", _Mitm(calls))
    pm._CA_DESIRED[SERIAL] = SimpleNamespace(cert_path=None)
    monkeypatch.setattr(
        pm.CAManager,
        "reconcile_ca",
        lambda self, serial: calls.append(("ca", serial)) or "re-injected",
    )


# -- restore_proxy_infra -------------------------------------------------------------


def test_restore_order_device_proxy_then_lanes_then_ca(monkeypatch):
    calls: list = []
    _with_everything(monkeypatch, calls)
    report = pr.restore_proxy_infra(SERIAL, "reconnect")
    assert calls == [
        ("device_proxy", SERIAL),
        ("lanes", SERIAL, "reconnect"),
        ("ca", SERIAL),
    ]
    assert report.ca == "re-injected"
    assert "App Proxy de.fkie.privacycanary active (gost restarted)" in report.summary()


def test_fresh_boot_rebuilds_as_a_cold_boot(monkeypatch):
    calls: list = []
    _with_everything(monkeypatch, calls)
    pr.restore_proxy_infra(SERIAL, "reconnect", fresh_boot=True)
    assert ("lanes", SERIAL, "cold-boot") in calls


def test_load_path_skips_the_device_proxy_step(monkeypatch):
    calls: list = []
    _with_everything(monkeypatch, calls)
    pr.restore_proxy_infra(SERIAL, "snapshot-load", device_proxy=False)
    assert [c[0] for c in calls] == ["lanes", "ca"]


def test_reconnect_during_a_load_is_left_to_the_load(monkeypatch):
    calls: list = []
    _with_everything(monkeypatch, calls)
    es._load_started(SERIAL)
    try:
        report = pr.restore_proxy_infra(SERIAL, "reconnect")
    finally:
        es._load_finished(SERIAL)
    assert calls == []
    assert report.skipped


def test_nothing_set_up_means_no_device_work(monkeypatch):
    monkeypatch.setattr(
        pm, "get_focus_manager", lambda: pytest.fail("focus manager created")
    )
    from sandroid.core import device_guard as dg

    pr._device_prepared_hook(SERIAL, True)
    report = pr.restore_proxy_infra(SERIAL, "cold-boot")
    assert not report.acted
    # The only device work: the leftover Kill switch check (one read).
    assert dg._INSTANCE.reconciled == [(SERIAL, "cold-boot"), (SERIAL, "cold-boot")]
    assert not hasattr(pr, "restore_proxy_infra_async")  # dead code removed


def test_snapshot_load_without_lanes_sweeps_orphans(monkeypatch):
    """A snapshot from an earlier session can bring back its App Proxy rules
    and gost; with no lane of this session they are removed.
    """
    swept = []
    monkeypatch.setattr(
        pm,
        "get_focus_manager",
        lambda: SimpleNamespace(sweep_orphans=lambda s, c: swept.append((s, c))),
    )
    pr.restore_proxy_infra(SERIAL, "snapshot-load", device_proxy=False)
    assert swept == [(SERIAL, "snapshot-load")]
    pr.restore_proxy_infra(SERIAL, "reconnect", device_proxy=False)
    assert swept == [(SERIAL, "snapshot-load")]


def test_ca_intent_is_per_serial(monkeypatch):
    """Auto re-inject only where the user injected in this session."""
    seen = []
    monkeypatch.setattr(
        pm.CAManager, "reconcile_ca", lambda self, s: seen.append(s) or "kept"
    )
    pm._CA_DESIRED["emulator-5554"] = SimpleNamespace(cert_path=None)
    assert pr.restore_proxy_infra(SERIAL, "cold-boot").ca == "none"
    assert seen == []
    assert pr.restore_proxy_infra("emulator-5554", "cold-boot").ca == "kept"
    assert seen == ["emulator-5554"]


# -- device-prepared hook (sandroid-startup) --------------------------------------


def test_device_prepared_hook_prefers_core_device_prep(monkeypatch):
    registered = []
    module = types.ModuleType("sandroid.core.device_prep")
    module.register_device_prepared_hook = registered.append
    monkeypatch.setitem(sys.modules, "sandroid.core.device_prep", module)
    import sandroid.core as core_pkg

    monkeypatch.setattr(core_pkg, "device_prep", module, raising=False)
    assert pr.install_device_prepared_hook()
    assert pr.install_device_prepared_hook()  # idempotent
    assert registered == [pr._device_prepared_hook]


def test_without_the_hook_restart_restores_itself(monkeypatch):
    monkeypatch.setitem(sys.modules, "sandroid.core.device_prep", None)
    calls = []
    monkeypatch.setattr(
        pr, "restore_proxy_infra", lambda s, c, **kw: calls.append((s, c, kw))
    )
    from sandroid.core import emulator

    monkeypatch.setattr(
        emulator,
        "restart_emulator",
        lambda serial, adb=None: SimpleNamespace(avd="Dev7", log_path="x"),
    )
    monkeypatch.setattr(emulator, "wait_until_ready", lambda *a, **k: True)
    monkeypatch.setattr(emulator, "emulator_binary", lambda: "/x/emulator")
    svc = es.EmulatorService()
    svc._get_adb = lambda: SimpleNamespace(get_target_device=lambda: "emulator-5570")
    assert svc.restart() is True
    assert calls == [(SERIAL, "cold-boot", {"fresh_boot": True})]


@pytest.mark.parametrize("enabled", [False, True])
def test_restart_relies_on_the_hook_only_while_device_prep_is_on(monkeypatch, enabled):
    """The hook may be registered while sandroid-startup's preparation is
    off: then it never fires and restart() must restore itself.
    """
    module = types.ModuleType("sandroid.core.device_prep")
    module.register_device_prepared_hook = lambda hook: None
    state = {"on": False}
    module.is_enabled = lambda: state["on"]
    monkeypatch.setitem(sys.modules, "sandroid.core.device_prep", module)
    import sandroid.core as core_pkg

    monkeypatch.setattr(core_pkg, "device_prep", module, raising=False)
    calls = []
    monkeypatch.setattr(
        pr, "restore_proxy_infra", lambda s, c, **kw: calls.append((s, c))
    )
    from sandroid.core import emulator

    monkeypatch.setattr(
        emulator,
        "restart_emulator",
        lambda serial, adb=None: SimpleNamespace(avd="Dev7", log_path="x"),
    )
    monkeypatch.setattr(emulator, "wait_until_ready", lambda *a, **k: True)
    monkeypatch.setattr(emulator, "emulator_binary", lambda: "/x/emulator")
    svc = es.EmulatorService()
    svc._get_adb = lambda: SimpleNamespace(get_target_device=lambda: SERIAL)
    state["on"] = enabled  # read at call time, not at registration
    monkeypatch.setattr(es, "is_active_serial", lambda s: True)
    assert svc.restart() is True
    assert calls == ([] if enabled else [(SERIAL, "cold-boot")])
    # The step prepares only the ACTIVE device: restarting another emulator
    # restores at once even while the step is on.
    calls.clear()
    monkeypatch.setattr(es, "is_active_serial", lambda s: False)
    assert svc.restart() is True
    assert calls == [(SERIAL, "cold-boot")]


# -- EmulatorService.load_snapshot ---------------------------------------------------


class _Adb:
    def send_telnet_command(self, command, serial=None):
        return "OK\n", ""

    def send_adb_command(self, command, serial=None):
        return ("device\n", "") if command == "get-state" else ("", "")

    def get_target_device(self):
        return SERIAL


def test_load_snapshot_order_keeps_the_restore_chain(monkeypatch):
    steps: list[str] = []
    svc = es.EmulatorService()
    svc._get_adb = lambda: _Adb()
    monkeypatch.setattr(
        svc, "_wait_for_device_ready", lambda adb, serial: steps.append("ready")
    )
    monkeypatch.setattr(
        svc, "_restore_selinux_permissive", lambda adb, serial: steps.append("selinux")
    )
    monkeypatch.setattr(
        svc, "_record_device_clock", lambda adb, name, serial: steps.append("clock")
    )
    monkeypatch.setattr(
        svc,
        "_restore_device_proxy",
        lambda serial: steps.append("device_proxy") or "restored",
    )
    monkeypatch.setattr(
        es, "reset_device_handles_after_snapshot_load", lambda: steps.append("frida")
    )

    def restore(serial, cause, **kw):
        assert es.snapshot_load_active(SERIAL)
        steps.append(f"proxy_infra:{cause}:{kw}")

    monkeypatch.setattr(pr, "restore_proxy_infra", restore)
    monkeypatch.setattr(
        es,
        "_auto_start_frida_after_load",
        lambda serial: steps.append(f"frida_start:{serial}"),
    )
    monkeypatch.setattr(es, "is_active_serial", lambda serial: True)
    hook = steps.append
    es.register_after_load_hook(hook)
    try:
        gen = es.snapshot_load_generation()
        assert svc.load_snapshot("tmp", serial=SERIAL) is True
    finally:
        es.unregister_after_load_hook(hook)
    assert steps == [
        "ready",
        "selinux",
        "clock",
        "device_proxy",
        "frida",
        # The device proxy step's outcome goes into the restore summary.
        "proxy_infra:snapshot-load:{'device_proxy': False, "
        "'device_proxy_result': 'restored'}",
        f"frida_start:{SERIAL}",
        SERIAL,
    ]
    assert es.snapshot_load_generation() == gen + 1
    assert not es.snapshot_load_active(SERIAL)


def test_load_on_another_serial_leaves_the_active_devices_frida_alone(
    monkeypatch,
):
    steps: list[str] = []
    svc = es.EmulatorService()
    monkeypatch.setattr(es, "is_active_serial", lambda serial: False)
    monkeypatch.setattr(
        es, "reset_device_handles_after_snapshot_load", lambda: steps.append("reset")
    )
    monkeypatch.setattr(
        es, "_auto_start_frida_after_load", lambda serial: steps.append("frida")
    )
    monkeypatch.setattr(
        pr, "restore_proxy_infra", lambda s, c, **kw: steps.append(f"restore:{s}")
    )
    svc._after_snapshot_load(_Adb(), "emulator-5590")
    assert steps == ["restore:emulator-5590"]


def test_frida_auto_start_after_a_load_is_pinned_and_reported(monkeypatch):
    from sandroid.core import frida_manager
    from sandroid.core.adb import Adb
    from sandroid.core.events import EventBus, EventType

    seen_target = []
    monkeypatch.setattr(frida_manager, "frida_server_auto_start_enabled", lambda: True)

    def start():
        seen_target.append(Adb.get_target_device())
        return False, "push failed"

    monkeypatch.setattr(frida_manager, "auto_start_frida_server", start)
    monkeypatch.setattr(es.threading.Thread, "start", lambda self: self.run())
    events = []
    handler = events.append
    EventBus.get().subscribe(EventType.STATE_CHANGED, handler)
    try:
        es._auto_start_frida_after_load("emulator-5590")
    finally:
        EventBus.get().unsubscribe(EventType.STATE_CHANGED, handler)
    assert seen_target == ["emulator-5590"]
    (event,) = [
        e for e in events if e.data.get("change_type") == "frida_server_after_load"
    ]
    assert event.data == {
        "change_type": "frida_server_after_load",
        "serial": "emulator-5590",
        "ok": False,
        "reason": "push failed",
    }


def test_a_failed_load_runs_no_post_load_step(monkeypatch):
    svc = es.EmulatorService()
    adb = _Adb()
    adb.send_telnet_command = lambda command, serial=None: ("KO: no such snapshot", "")
    svc._get_adb = lambda: adb
    monkeypatch.setattr(
        pr, "restore_proxy_infra", lambda *a, **k: pytest.fail("restored")
    )
    assert svc.load_snapshot("nope", serial=SERIAL) is False
    assert not es.snapshot_load_active()


# -- device proxy: adb reverse after a load / reconnect --------------------------------


def test_kept_loopback_proxy_gets_its_reverse_back(monkeypatch):
    from sandroid.core import proxy_manager

    svc = ms.MitmproxyService.__new__(ms.MitmproxyService)
    svc._owned_device_proxy = "127.0.0.1:8080"
    svc._owned_device_proxy_serial = SERIAL
    monkeypatch.setattr(
        proxy_manager.ProxyManager,
        "get_proxy_settings",
        lambda self: (
            proxy_manager.ProxyStatus.SET,
            proxy_manager.ProxyConfig("127.0.0.1", 8080),
        ),
    )
    monkeypatch.setattr(proxy_manager, "_reverse_registered", lambda port: False)
    reversed_ = []
    monkeypatch.setattr(
        proxy_manager.Adb, "reverse", classmethod(lambda cls, r, l: reversed_.append(r))
    )
    assert svc.reapply_device_proxy(SERIAL) == "kept"
    assert reversed_ == ["tcp:8080"]


def test_stopping_mitmproxy_keeps_app_proxies_quit_releases_them(monkeypatch):
    released = []
    monkeypatch.setattr(
        pm,
        "get_focus_manager",
        lambda: SimpleNamespace(disable_focus=lambda: released.append(1)),
    )
    svc = ms.MitmproxyService.__new__(ms.MitmproxyService)
    svc._proc = None
    svc._lock = ms.threading.RLock()
    svc.stop(release_device_proxy=False)
    assert released == []
    svc.stop(release_device_proxy=False, release_app_proxies=True)
    assert released == [1]


# -- CA fallback (user-confirmed Zygote restart, TUI only) ------------------------------


class _Ca:
    def __init__(self, calls, *, first_ok=False):
        self.calls, self.first_ok = calls, first_ok

    def ca_spec(self, cert_path):
        return SimpleNamespace(cert_path=cert_path, name="c8750f0d.0")

    def inject_spec(self, spec, serial=None):
        self.calls.append("inject")
        return pm.InjectionResult(
            success=self.first_ok, message="x", restart_required=not self.first_ok
        )

    killed = (712,)

    def kill_zygotes(self, serial=None):
        self.calls.append("kill")
        return 728, list(self.killed)

    def check_zygote_injection_status(self, cert_path, serial=None):
        return SimpleNamespace(injected=True, verdict="injected")


def _fallback(monkeypatch, calls, **kw):
    monkeypatch.setattr(pm, "CAManager", lambda: _Ca(calls, **kw))
    monkeypatch.setattr(
        pr,
        "_recover_after_framework_restart",
        lambda prev, serial, timeout=120.0, seen=None: calls.append(("recover", prev))
        or "ok",
    )
    monkeypatch.setattr(pr, "_system_server_pids", lambda serial: ["728"])
    monkeypatch.setattr(
        pr, "restore_proxy_infra", lambda s, c, **k: calls.append(("restore", c))
    )
    monkeypatch.setattr(pr, "_framework_world_change", lambda s: calls.append("world"))


def test_fallback_restarts_only_when_the_no_restart_path_fails(monkeypatch, tmp_path):
    calls: list = []
    _fallback(monkeypatch, calls, first_ok=True)
    assert pr.restart_framework_for_ca(tmp_path / "ca.pem", SERIAL).success
    assert calls == ["inject"]


def test_fallback_runs_the_full_restart_contract(monkeypatch, tmp_path):
    calls: list = []
    _fallback(monkeypatch, calls)
    result = pr.restart_framework_for_ca(tmp_path / "ca.pem", SERIAL)
    assert result.success
    assert result.restarted
    assert calls == [
        "inject",
        "kill",
        ("recover", 728),
        ("restore", "framework-restart"),
        "world",
    ]
    assert pm.ca_desired_for(SERIAL) is not None


def test_fallback_follow_up_runs_while_the_world_lease_is_held(monkeypatch, tmp_path):
    """The caller's CT bypass / status read run before the lease is released,
    so no AI task gets the device between the restart and that work.
    """
    from sandroid.ai import arbiter

    calls: list = []
    _fallback(monkeypatch, calls)
    arbiter.reset_for_tests()
    world = frozenset({arbiter.ResourceId.WORLD})
    seen: list = []

    def follow_up(res) -> None:
        seen.append(res.restarted)
        seen.append(
            isinstance(arbiter.get_arbiter().claim("ai-task", world), arbiter.Conflict)
        )

    try:
        result = pr.restart_framework_for_ca(
            tmp_path / "ca.pem", SERIAL, while_held=follow_up
        )
        after = arbiter.get_arbiter().claim("ai-task", world)
    finally:
        arbiter.reset_for_tests()
    assert result.success
    assert seen == [True, True]  # restarted, and the AI claim conflicted
    assert not isinstance(after, arbiter.Conflict)  # released afterwards


def test_fallback_follow_up_failure_does_not_fail_the_restart(monkeypatch, tmp_path):
    calls: list = []
    _fallback(monkeypatch, calls)

    def boom(res) -> None:
        raise RuntimeError("ct failed")

    result = pr.restart_framework_for_ca(tmp_path / "ca.pem", SERIAL, while_held=boom)
    assert result.success
    assert result.restarted


def test_fallback_fails_when_no_zygote_was_killed(monkeypatch, tmp_path):
    calls: list = []
    _fallback(monkeypatch, calls)
    monkeypatch.setattr(_Ca, "killed", ())
    result = pr.restart_framework_for_ca(tmp_path / "ca.pem", SERIAL)
    assert not result.success
    assert "nothing was restarted" in result.message
    assert calls == ["inject", "kill"]  # never waited for a framework restart


def test_fallback_not_run_when_a_restart_cannot_help(monkeypatch, tmp_path):
    """The fallback re-checks the precondition: inject_spec says a restart
    would not help (e.g. nsenter missing) -> nothing is killed.
    """
    calls: list = []
    _fallback(monkeypatch, calls)
    monkeypatch.setattr(
        _Ca,
        "inject_spec",
        lambda self, spec, serial=None: self.calls.append("inject")
        or pm.InjectionResult(success=False, message="nsenter missing"),
    )
    result = pr.restart_framework_for_ca(tmp_path / "ca.pem", SERIAL)
    assert not result.success
    assert calls == ["inject"]


def test_framework_wait_with_an_unknown_old_pid_needs_a_new_one(monkeypatch):
    """With the old system_server PID unknown, the old one still answering
    must not count as "back": only a PID never seen before does.
    """
    polls = iter([["728"], ["728"], [], ["12189"]])
    monkeypatch.setattr(pr, "_system_server_pids", lambda serial: next(polls))
    monkeypatch.setattr(pr.time, "sleep", lambda s: None)
    from sandroid.core.adb import Adb

    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        staticmethod(
            lambda cmd, serial=None, timeout=30: ("1\nService package: found", "")
        ),
    )
    assert pr._wait_system_server_changed(None, SERIAL, 5.0, seen=set())
    polls = iter([["728"]] * 50)
    monkeypatch.setattr(pr, "_system_server_pids", lambda serial: next(polls))
    clock = iter(range(100))
    monkeypatch.setattr(pr.time, "monotonic", lambda: next(clock))
    assert not pr._wait_system_server_changed(None, SERIAL, 10.0, seen={"728"})


def _real_recovery(monkeypatch, ss_pids, *, active_serial="emulator-OTHER"):
    """Drive the REAL app_start.recover_after_framework_restart.

    Only its adb reads are stubbed; ``serial`` is recorded on every read. The
    restarted device is not the active one, so no Frida handle is touched.
    """
    from sandroid.core.adb import Adb
    from sandroid.services import app_start

    reads: list = []
    polls = iter(ss_pids)

    def pid(serial=None):
        reads.append(("pid", serial))
        return next(polls)

    def pm_ready(serial=None):
        reads.append(("pm", serial))
        return True

    monkeypatch.setattr(app_start, "_system_server_pid", pid)
    monkeypatch.setattr(app_start, "_package_manager_ready", pm_ready)
    monkeypatch.setattr(app_start, "_RECOVERY_POLL_S", 0.0)
    monkeypatch.setattr(Adb, "get_target_device", staticmethod(lambda: active_serial))
    return reads


def test_recovery_uses_the_real_app_start_function_with_the_serial(monkeypatch):
    reads = _real_recovery(monkeypatch, [728, 728, 12189])
    note = pr._recover_after_framework_restart(728, SERIAL, timeout=5.0)
    assert note == "framework back"
    assert reads == [("pid", SERIAL)] * 3 + [("pm", SERIAL)]


def test_recovery_timeout_from_the_real_function_is_reported(monkeypatch):
    _real_recovery(monkeypatch, itertools.repeat(728))
    note = pr._recover_after_framework_restart(728, SERIAL, timeout=0.05)
    assert note.startswith("framework recovery failed")
    assert "no new system_server" in note


def test_recovery_with_an_unknown_pid_waits_for_a_new_one_first(monkeypatch):
    """app_start treats None as "no PID gate"; the old system_server still
    answers after the kill, so the local gate must see a NEW PID first.
    """
    reads = _real_recovery(monkeypatch, [12189])
    local = iter([["728"], ["728"], ["12189"]])
    monkeypatch.setattr(pr, "_system_server_pids", lambda serial: next(local))
    monkeypatch.setattr(pr.time, "sleep", lambda s: None)
    from sandroid.core.adb import Adb

    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        staticmethod(
            lambda cmd, serial=None, timeout=30: ("1\nService package: found", "")
        ),
    )
    note = pr._recover_after_framework_restart(None, SERIAL, timeout=5.0, seen={"728"})
    assert note == "framework back"
    assert reads[0] == ("pid", SERIAL)
    with pytest.raises(StopIteration):
        next(local)  # the local gate polled until the new PID showed up


def test_fallback_refuses_while_an_app_start_runs(monkeypatch, tmp_path):
    from sandroid.services import app_start

    calls: list = []
    _fallback(monkeypatch, calls)
    assert app_start._LIFECYCLE.try_acquire()
    try:
        import threading

        out = []
        t = threading.Thread(
            target=lambda: out.append(
                pr.restart_framework_for_ca(tmp_path / "ca.pem", SERIAL)
            )
        )
        t.start()
        t.join()
    finally:
        app_start._LIFECYCLE.release()
    (result,) = out
    assert not result.success
    assert "Zygote not restarted" in result.message
    assert calls == []


def test_fallback_refuses_while_the_ai_holds_the_device(monkeypatch, tmp_path):
    from sandroid.ai import arbiter

    calls: list = []
    _fallback(monkeypatch, calls)
    arbiter.reset_for_tests()
    world = frozenset({arbiter.ResourceId.WORLD})
    assert not isinstance(
        arbiter.get_arbiter().claim("ai-task", world), arbiter.Conflict
    )
    try:
        result = pr.restart_framework_for_ca(tmp_path / "ca.pem", SERIAL)
    finally:
        arbiter.reset_for_tests()
    assert not result.success
    assert calls == []


# -- long-lived streams after a load ---------------------------------------------------


def test_tracking_logcat_follower_restarts_after_a_load(monkeypatch):
    from sandroid.services import tracking_service as ts

    svc = ts.TrackingService.__new__(ts.TrackingService)
    svc._lock = ts.threading.Lock()
    terminated, started = [], []
    svc._active, svc._serial, svc._gen = True, SERIAL, 7
    svc._logcat = SimpleNamespace(terminate=lambda: terminated.append(1))
    svc._start_logcat = lambda gen, serial: started.append((gen, serial))
    assert svc.restart_logcat_after_load(SERIAL) is True
    assert terminated == [1]
    assert started == [(7, SERIAL)]
    assert svc.restart_logcat_after_load("emulator-5554") is False


def test_monitor_ended_by_a_load_restarts_once_the_load_is_done(monkeypatch):
    from sandroid.tui.controllers import monitor_controller as mc

    controller = mc.MonitorController()
    resumed = []
    monkeypatch.setattr(controller, "resume_after_playback", resumed.append)
    monkeypatch.setattr(controller, "is_running", lambda: False)
    controller._resume_after_load = "cfg"
    mc._after_snapshot_load(SERIAL)
    assert resumed == ["cfg"]
    mc._after_snapshot_load(SERIAL)  # once
    assert resumed == ["cfg"]


def _ended_monitor(monkeypatch, controller):
    tasks = SimpleNamespace(
        get_task=lambda name: SimpleNamespace(
            instance=SimpleNamespace(config="cfg", stop_requested=False, process=None)
        ),
        is_running=lambda name: False,
        unregister=lambda name: None,
    )
    monkeypatch.setattr(controller, "_get_task_service", lambda: tasks)
    monkeypatch.setattr(controller, "is_running", lambda: False)


def test_monitor_end_handled_after_the_load_hook_still_restarts(monkeypatch):
    """The stream end can reach the UI thread after the after-load hook ran
    but while the load is still marked in flight: it must restart then, not
    wait for a hook that already ran.
    """
    from sandroid.tui.controllers import monitor_controller as mc

    controller = mc.MonitorController()
    resumed = []
    monkeypatch.setattr(controller, "resume_after_playback", resumed.append)
    _ended_monitor(monkeypatch, controller)
    controller._load_gen_at_start = es.snapshot_load_generation()
    es._load_started(SERIAL)
    try:
        mc._after_snapshot_load(SERIAL)  # hook first (monitor still "up")
        controller._monitor_ended()  # then the end, load not finished yet
    finally:
        es._load_finished(SERIAL)
    assert resumed == ["cfg"]


def test_monitor_that_survived_a_load_is_not_restarted_later(monkeypatch):
    from sandroid.tui.controllers import monitor_controller as mc

    controller = mc.MonitorController()
    resumed = []
    monkeypatch.setattr(controller, "resume_after_playback", resumed.append)
    controller._load_gen_at_start = es.snapshot_load_generation()
    es._load_started(SERIAL)
    monkeypatch.setattr(controller, "is_running", lambda: True)
    mc._after_snapshot_load(SERIAL)  # survived: re-armed
    es._load_finished(SERIAL)
    controller._load_done_at -= controller.LOAD_END_GRACE_S + 1  # much later
    _ended_monitor(monkeypatch, controller)
    controller._monitor_ended()  # an unrelated end
    assert resumed == []


# -- TUI entry points ---------------------------------------------------------------


def test_ctrl_s_with_an_unchanged_list_still_reconciles(monkeypatch):
    from sandroid.tui.modals import proxy_modal

    calls = []
    fm = SimpleNamespace(
        app_proxies=lambda: {"de.fkie.privacycanary": "ours"},
        enable_focus=lambda *a: calls.append(("enable", a)) or (True, ""),
        disable_focus=lambda *a: calls.append(("disable", a)) or (True, ""),
        set_quic_blocking=lambda on: calls.append(("quic", on)),
        reconcile=lambda serial, reason: calls.append(("reconcile", reason))
        or [_report(state=pm.LANE_WAITING, repaired=["gost restarted"])],
    )
    monkeypatch.setattr(proxy_modal, "get_focus_manager", lambda: fm)
    toasts = proxy_modal.ProxyModal._reconcile_app_proxies(
        {"de.fkie.privacycanary": ""}, True
    )
    assert ("reconcile", "apply") in calls
    assert not any(c[0] in ("enable", "disable") for c in calls)
    assert (
        "App Proxy de.fkie.privacycanary repaired: gost restarted",
        "information",
    ) in toasts
    assert (
        "App Proxy de.fkie.privacycanary: waiting for mitmproxy",
        "warning",
    ) in toasts


def test_proxy_modal_ca_install_runs_off_the_ui_thread(monkeypatch, tmp_path):
    from sandroid.tui.modals import proxy_modal

    modal = proxy_modal.ProxyModal()
    monkeypatch.setattr(
        proxy_modal.ProxyModal, "app", property(lambda self: SimpleNamespace())
    )
    cert = tmp_path / "ca.pem"
    cert.write_text("x")
    monkeypatch.setattr(modal, "_get_selected_ca_path", lambda: cert)
    monkeypatch.setattr(
        modal, "query_one", lambda *a, **k: SimpleNamespace(update=lambda t: None)
    )
    injected = []
    modal._ca_manager = SimpleNamespace(
        inject_ca_into_zygote=lambda path: injected.append(path)
    )
    threads = []
    monkeypatch.setattr(
        proxy_modal.threading.Thread, "start", lambda self: threads.append(self.name)
    )
    modal.action_inject_ca()
    assert threads == ["proxy-modal-ca-inject"]
    assert injected == []  # nothing ran on the calling (UI) thread
    assert modal._ca_busy


# -- mitmproxy start: lanes are checked once mitmproxy listens ------------------------


def test_app_proxy_check_after_start_waits_for_the_socks_ports(monkeypatch):
    """Probing before mitmweb bound its SOCKS ports gave a false, sticky
    "mitmproxy unreachable from the device" after most starts.
    """
    svc = ms.MitmproxyService.__new__(ms.MitmproxyService)
    svc._lock = ms.threading.RLock()
    svc._state = SimpleNamespace(
        proxy_port=8080, socks_base=8082, focus_lanes=2, listen_host="127.0.0.1"
    )
    svc._proc = SimpleNamespace(pid=4242, poll=lambda: None)
    bound: set[int] = set()

    def listening(pid, port, host="127.0.0.1"):
        bound.add(port)  # each port comes up on its first check
        return port != 8083 or 8083 in seen_twice or seen_twice.add(8083)

    seen_twice: set[int] = set()
    monkeypatch.setattr(ms, "_pid_listening", listening)
    monkeypatch.setattr(ms.time, "sleep", lambda s: None)
    checks = []
    monkeypatch.setattr(
        pm,
        "_FOCUS_INSTANCE",
        SimpleNamespace(
            has_lanes=lambda serial=None: True,
            reconcile=lambda serial, reason: checks.append((reason, set(bound))),
        ),
    )
    monkeypatch.setattr(ms.threading.Thread, "start", lambda self: self.run())
    monkeypatch.setattr(pm, "_MITMPROXY_STARTED_AT", 0.0)
    svc._kick_app_proxy_reconcile("mitmproxy-start")
    assert checks == [("mitmproxy-start", {8080, 8082, 8083})]
    assert 8083 in seen_twice  # it waited for the late SOCKS port
    assert pm._MITMPROXY_STARTED_AT > 0


# -- Ctrl+N, ProxyModal ---------------------------------------------------------------


def test_ctrl_n_on_an_installed_ca_records_the_reinject_intent(monkeypatch, tmp_path):
    from sandroid.core.adb import Adb
    from sandroid.tui.widgets.mitmproxy_panel import install_or_adopt_ca

    monkeypatch.setattr(Adb, "_target_device", SERIAL)
    spec = SimpleNamespace(cert_path=tmp_path / "ca.pem")
    manager = SimpleNamespace(
        check_zygote_injection_status=lambda path: SimpleNamespace(verdict="injected"),
        ca_spec=lambda path: spec,
        inject_ca_into_zygote=lambda path: pytest.fail("re-installed"),
    )
    result = install_or_adopt_ca(manager, spec.cert_path)
    assert result.success
    assert "already in the trust store" in result.message
    assert pm.ca_desired_for(SERIAL) is spec


def test_panel_never_waits_for_the_focus_lock_on_the_ui_thread():
    import inspect

    from sandroid.tui.widgets import mitmproxy_panel

    source = inspect.getsource(mitmproxy_panel.MitmproxyPanel)
    for blocking in (".app_proxies()", ".lane_health()", ".is_focus_active()"):
        assert blocking not in source


def test_ca_result_after_the_modal_closed_goes_to_the_app(monkeypatch):
    from sandroid.tui.modals import proxy_modal

    modal = proxy_modal.ProxyModal()
    toasts = []
    app = SimpleNamespace(
        screen_stack=[],  # the modal was dismissed meanwhile
        notify=lambda message, **kw: toasts.append((message, kw["severity"])),
        push_screen=lambda *a, **k: pytest.fail("dialog over another screen"),
    )
    modal._ca_busy = True
    result = pm.InjectionResult(
        success=False, message="Installing the CA failed: x", restart_required=True
    )
    modal._on_ca_job_done("inject", None, result, None, None, app)
    assert not modal._ca_busy
    ((message, severity),) = toasts
    assert severity == "error"
    assert "press I again" in message
    modal._on_ca_job_done("remove", None, (True, "CA removed"), None, None, app)
    assert toasts[-1] == ("CA removed", "information")


async def _until(pilot, cond, rounds=200):
    for _ in range(rounds):
        if cond():
            return
        await pilot.pause(0.01)
    raise AssertionError("condition not reached")


async def test_proxy_modal_keys_work_on_open_and_remove_asks_first(monkeypatch):
    from textual.app import App

    from sandroid.tui.modals import proxy_modal
    from sandroid.tui.modals.confirm_modal import ConfirmModal

    for name in (
        "_refresh_device_proxy_status",
        "_refresh_device_info",
        "_detect_certificates",
    ):
        monkeypatch.setattr(proxy_modal.ProxyModal, name, lambda self: None)
    monkeypatch.setattr(
        proxy_modal,
        "get_focus_manager",
        lambda: SimpleNamespace(app_proxies_cached=dict),
    )
    jobs = []
    monkeypatch.setattr(
        proxy_modal.ProxyModal,
        "_run_ca_job",
        lambda self, kind, path: jobs.append(kind),
    )
    modal = proxy_modal.ProxyModal()

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(modal)

    app = _App()
    async with app.run_test() as pilot:
        await _until(pilot, lambda: app.screen is modal and app.focused is not None)
        assert app.focused.id == "device-radio-set"  # not the external Input
        await pilot.press("r")
        await _until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("escape")  # sync action_cancel closes it: No
        await _until(pilot, lambda: app.screen is modal)
        assert jobs == []
        await pilot.press("r")
        await _until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("y")
        await _until(pilot, lambda: jobs == ["remove"])


def _quiet_proxy_modal(monkeypatch):
    """A ProxyModal that touches no device (pilot tests)."""
    from sandroid.tui.modals import proxy_modal

    for name in (
        "_refresh_device_proxy_status",
        "_refresh_device_info",
        "_detect_certificates",
    ):
        monkeypatch.setattr(proxy_modal.ProxyModal, name, lambda self: None)
    monkeypatch.setattr(
        proxy_modal,
        "get_focus_manager",
        lambda: SimpleNamespace(app_proxies_cached=dict),
    )
    return proxy_modal


def _modal_app(modal):
    from textual.app import App

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(modal)

    return _App()


async def test_proxy_modal_letter_keys_work_in_both_cases(monkeypatch):
    """E2E: the hints say R=Remove CA, but only a lower-case r was bound, so
    Shift+R did nothing. Upper case works too; Remove CA still asks first.
    """
    from sandroid.tui.modals.confirm_modal import ConfirmModal

    proxy_modal = _quiet_proxy_modal(monkeypatch)
    calls = []
    for action in ("push_ca", "inject_ca", "add_app", "add_spotlight"):
        monkeypatch.setattr(
            proxy_modal.ProxyModal,
            f"action_{action}",
            lambda self, action=action: calls.append(action),
        )
    jobs = []
    monkeypatch.setattr(
        proxy_modal.ProxyModal,
        "_run_ca_job",
        lambda self, kind, path: jobs.append(kind),
    )
    modal = proxy_modal.ProxyModal()
    app = _modal_app(modal)
    async with app.run_test() as pilot:
        await _until(pilot, lambda: app.screen is modal and app.focused is not None)
        for key in ("P", "p", "I", "i", "A", "F"):
            await pilot.press(key)
        await _until(pilot, lambda: len(calls) == 6)
        assert calls == [
            "push_ca",
            "push_ca",
            "inject_ca",
            "inject_ca",
            "add_app",
            "add_spotlight",
        ]
        await pilot.press("R")
        await _until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("escape")
        await _until(pilot, lambda: app.screen is modal)
        assert jobs == []
        await pilot.press("R")
        await _until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("y")
        await _until(pilot, lambda: jobs == ["remove"])
        hints = str(modal.query_one(proxy_modal.KeyHintFooter).render())
        assert "R=Remove CA" in hints
        assert "Shift+Left/Right=Tabs" in hints


async def test_proxy_modal_shift_arrows_cycle_the_tabs(monkeypatch):
    """E2E: the tabs took an exact number of Tab presses, then an arrow.
    Shift+Left/Right cycle them (the project's Shift+Arrow level keys) and
    focus the tab's first control, never a text field.
    """
    from textual.widgets import Input, TabbedContent

    proxy_modal = _quiet_proxy_modal(monkeypatch)
    modal = proxy_modal.ProxyModal()
    app = _modal_app(modal)
    async with app.run_test(size=(120, 50)) as pilot:
        await _until(pilot, lambda: app.screen is modal and app.focused is not None)
        tabs = modal.query_one("#proxy-tabs", TabbedContent)
        assert tabs.active == "tab-device"
        seen = []
        for _ in range(3):
            await pilot.press("shift+right")
            await pilot.pause()
            seen.append(tabs.active)
        # The Method tab (Network method) comes first; the dialog opens on
        # Device.
        assert seen == ["tab-apps", "tab-ca", "tab-method"]
        await pilot.press("shift+left")
        await _until(pilot, lambda: tabs.active == "tab-ca")
        await _until(
            pilot,
            lambda: app.focused is not None
            and not isinstance(app.focused, Input)
            and tabs.query_one("#tab-ca") in app.focused.ancestors,
        )
        # Letter keys still act after a tab switch (focus is not in a field).
        assert not isinstance(app.focused, Input)

        # An empty field hands Shift+Arrow to the tabs ...
        field = modal.query_one("#custom-path-input", Input)
        field.focus()
        await pilot.pause()
        await pilot.press("shift+left")
        await _until(pilot, lambda: tabs.active == "tab-apps")
        # ... a field with text keeps it for selecting text.
        await pilot.press("shift+right")  # to the Certificate tab again
        await _until(pilot, lambda: tabs.active == "tab-ca")
        field.focus()
        field.value = "/tmp/ca.pem"
        field.cursor_position = len(field.value)
        await pilot.pause()
        await pilot.press("shift+left")
        await pilot.pause()
        assert tabs.active == "tab-ca"
        assert field.selection.start != field.selection.end
