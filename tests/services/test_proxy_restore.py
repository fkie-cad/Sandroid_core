"""One restore entry point for the proxy infra, the post-load sequence of
EmulatorService.load_snapshot, the device-prepared hook, the CA fallback
gating and the long-lived stream restarts after a load.
"""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import pytest

from sandroid.core import proxy_manager as pm
from sandroid.services import emulator_service as es
from sandroid.services import mitmproxy_service as ms
from sandroid.services import proxy_restore as pr

SERIAL = "emulator-5570"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    pm._CA_DESIRED.clear()
    monkeypatch.setattr(pm, "_FOCUS_INSTANCE", None)
    monkeypatch.setattr(ms, "_INSTANCE", None)
    monkeypatch.setattr(pr, "_HOOK_INSTALLED", False)
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
    started = []
    monkeypatch.setattr(pr.threading.Thread, "start", lambda self: started.append(1))
    pr.restore_proxy_infra_async(SERIAL, "reconnect")
    pr._device_prepared_hook(SERIAL, True)
    assert started == []
    report = pr.restore_proxy_infra(SERIAL, "cold-boot")
    assert not report.acted


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


def test_device_prepared_hook_falls_back_to_device_manager(monkeypatch):
    from sandroid.core import device_manager

    registered = []
    monkeypatch.setitem(sys.modules, "sandroid.core.device_prep", None)
    monkeypatch.setattr(
        device_manager,
        "register_device_prepared_hook",
        registered.append,
        raising=False,
    )
    assert pr.install_device_prepared_hook()
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
        svc, "_restore_device_proxy", lambda serial: steps.append("device_proxy")
    )
    monkeypatch.setattr(
        es, "reset_device_handles_after_snapshot_load", lambda: steps.append("frida")
    )

    def restore(serial, cause, **kw):
        assert es.snapshot_load_active(SERIAL)
        steps.append(f"proxy_infra:{cause}:{kw}")

    monkeypatch.setattr(pr, "restore_proxy_infra", restore)
    monkeypatch.setattr(
        es, "_auto_start_frida_after_load", lambda: steps.append("frida_start")
    )
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
        "proxy_infra:snapshot-load:{'device_proxy': False}",
        "frida_start",
        SERIAL,
    ]
    assert es.snapshot_load_generation() == gen + 1
    assert not es.snapshot_load_active(SERIAL)


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

    def restart_zygote(self, serial=None):
        self.calls.append("kill")
        return 728

    def check_zygote_injection_status(self, cert_path, serial=None):
        return SimpleNamespace(injected=True, verdict="injected")


def _fallback(monkeypatch, calls, **kw):
    monkeypatch.setattr(pm, "CAManager", lambda: _Ca(calls, **kw))
    monkeypatch.setattr(
        pr,
        "_recover_after_framework_restart",
        lambda prev, serial, timeout=120.0: calls.append(("recover", prev)) or "ok",
    )
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
    controller._resume_after_load = "cfg"
    mc._after_snapshot_load(SERIAL)
    assert resumed == ["cfg"]
    mc._after_snapshot_load(SERIAL)  # once
    assert resumed == ["cfg"]


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
