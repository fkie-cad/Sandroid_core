"""MitmproxyService: configured ports, listen address, reachability probe and
device-proxy ownership (phase-2 live-test findings).
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from sandroid.config.schema import MitmproxyConfig
from sandroid.core import proxy_manager
from sandroid.services import mitmproxy_service as ms


def _cfg(**overrides):
    mitm = MitmproxyConfig(**overrides)
    return SimpleNamespace(mitmproxy=mitm)


@pytest.fixture
def make_service(monkeypatch):
    """Build services against an in-memory config; never leak device state."""
    created = []

    def _make(**overrides):
        cfg = _cfg(**overrides)
        monkeypatch.setattr(ms, "get_config", lambda: cfg)
        svc = ms.MitmproxyService()
        created.append(svc)
        return svc, cfg

    yield _make
    for svc in created:
        # Keep the atexit hook from touching adb after the test.
        svc._owned_device_proxy = None
        svc._proc = None


class _FakeProc:
    def __init__(self, pid=4242):
        self.pid = pid
        self.stdout = iter(())
        self.terminated = False

    def poll(self):
        return 0 if self.terminated else None

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.terminated = True


# ── configured port while stopped ───────────────────────────────────────


def test_state_shows_configured_port_while_stopped(make_service):
    svc, _ = make_service(proxy_port=8090, web_port=8091)
    assert svc.state.proxy_port == 8090
    assert svc.state.web_port == 8091
    assert svc.state.listen_host == "127.0.0.1"


def test_state_follows_config_edits_while_stopped(make_service):
    svc, cfg = make_service(proxy_port=8090)
    cfg.mitmproxy.proxy_port = 8095
    assert svc.state.proxy_port == 8095


def test_state_keeps_live_port_while_running(make_service):
    svc, cfg = make_service(proxy_port=8090)
    svc._proc = _FakeProc()
    svc._state.proxy_port = 9000  # what the live process was started with
    cfg.mitmproxy.proxy_port = 8095
    assert svc.state.proxy_port == 9000


# ── listen address ──────────────────────────────────────────────────────


@pytest.fixture
def popen_spy(monkeypatch):
    calls = []

    def _popen(cmd, **kwargs):
        calls.append(cmd)
        return _FakeProc()

    monkeypatch.setattr(ms, "_find_mitmweb", lambda: "/x/mitmweb")
    monkeypatch.setattr(ms.subprocess, "Popen", _popen)
    monkeypatch.setattr(ms.threading.Thread, "start", lambda self: None)
    return calls


def _arg(cmd, flag):
    return cmd[cmd.index(flag) + 1]


def test_start_binds_loopback_by_default(make_service, popen_spy):
    svc, _ = make_service(proxy_port=8090)
    assert svc.start()
    cmd = popen_spy[0]
    assert _arg(cmd, "--listen-host") == "127.0.0.1"
    assert _arg(cmd, "--listen-port") == "8090"
    assert svc.state.listen_host == "127.0.0.1"
    svc._cleanup_addon()


def test_start_honours_configured_all_interfaces(make_service, popen_spy):
    svc, _ = make_service(listen_host="0.0.0.0")
    assert svc.start()
    assert _arg(popen_spy[0], "--listen-host") == "0.0.0.0"
    svc._cleanup_addon()


def test_restart_keeps_listen_host(make_service, popen_spy, monkeypatch):
    svc, _ = make_service(listen_host="0.0.0.0")
    released = []
    monkeypatch.setattr(svc, "release_device_proxy", lambda: released.append(1))
    svc.start()
    svc.restart(
        proxy_port=svc.state.proxy_port,
        web_port=svc.state.web_port,
        web_host=svc.state.web_host,
    )
    assert _arg(popen_spy[-1], "--listen-host") == "0.0.0.0"
    assert released == []  # restart must not drop the device proxy
    svc._cleanup_addon()


def test_schema_defaults_are_safe():
    cfg = MitmproxyConfig()
    assert cfg.listen_host == "127.0.0.1"
    assert cfg.auto_device_proxy is False


# ── flow classification ─────────────────────────────────────────────────


def test_direct_flow_line():
    assert ms._is_direct_flow_line("[FLOW]|t|HTTPS|200|GET|a/b|1KB|")
    assert ms._is_direct_flow_line("[FLOW]|t|200|GET|a/b|1KB")
    assert not ms._is_direct_flow_line("[FLOW]|t|HTTPS|200|GET|a/b|1KB|org.x")


# ── reachability probe ──────────────────────────────────────────────────


@pytest.fixture
def adb_out(monkeypatch):
    replies = []
    sent = []

    def _send(cmd, serial=None):
        sent.append(cmd)
        return replies.pop(0) if replies else ("", "")

    from sandroid.core import adb

    monkeypatch.setattr(adb.Adb, "send_adb_command", staticmethod(_send))
    monkeypatch.setattr(ms.time, "sleep", lambda s: None)
    return replies, sent


def test_probe_waits_for_listener_instead_of_blaming_device(
    make_service, adb_out, monkeypatch
):
    svc, _ = make_service()
    monkeypatch.setattr(svc, "wait_listening", lambda timeout=0: False)
    monkeypatch.setattr(svc, "is_running", lambda: True)
    res = svc.probe_device_reachability("10.0.2.2", 8090)
    assert res.inconclusive
    assert not res.reachable
    assert "CANNOT" not in res.detail
    assert adb_out[1] == []  # no device round-trip before mitmweb listens


def test_probe_reachable_on_http_reply(make_service, adb_out, monkeypatch):
    svc, _ = make_service()
    monkeypatch.setattr(svc, "wait_listening", lambda timeout=0: True)
    adb_out[0].append(("HTTP/1.1 200 OK\r\n", ""))
    res = svc.probe_device_reachability("10.0.2.2", 8090)
    assert res.reachable
    assert not res.inconclusive
    assert "10.0.2.2 8090" in adb_out[1][0]


def test_probe_retries_once(make_service, adb_out, monkeypatch):
    svc, _ = make_service()
    monkeypatch.setattr(svc, "wait_listening", lambda timeout=0: True)
    adb_out[0].extend([("", ""), ("HTTP/1.1 200 OK", "")])
    assert svc.probe_device_reachability("10.0.2.2", 8090).reachable
    assert len(adb_out[1]) == 2


def test_probe_unreachable_without_any_signal(make_service, adb_out, monkeypatch):
    svc, _ = make_service()
    monkeypatch.setattr(svc, "wait_listening", lambda timeout=0: True)
    res = svc.probe_device_reachability("10.0.2.2", 8090)
    assert not res.reachable
    assert not res.inconclusive
    assert "CANNOT" in res.detail


def test_probe_recent_device_flows_count_as_reachable(
    make_service, adb_out, monkeypatch
):
    svc, _ = make_service()
    monkeypatch.setattr(svc, "wait_listening", lambda timeout=0: True)
    svc._state.last_direct_flow_at = time.monotonic()
    res = svc.probe_device_reachability("10.0.2.2", 8090)
    assert res.reachable


def test_probe_missing_nc_is_inconclusive(make_service, adb_out, monkeypatch):
    svc, _ = make_service()
    monkeypatch.setattr(svc, "wait_listening", lambda timeout=0: True)
    adb_out[0].append(("", "Unknown command nc"))
    res = svc.probe_device_reachability("10.0.2.2", 8090)
    assert res.inconclusive
    assert not res.reachable


def test_probe_hints_listen_host_for_lan_ip(make_service, adb_out, monkeypatch):
    svc, _ = make_service()
    monkeypatch.setattr(svc, "wait_listening", lambda timeout=0: True)
    res = svc.probe_device_reachability("192.168.1.20", 8090)
    assert "listen_host" in res.hint
    assert "adb reverse" in res.hint


def test_wait_listening_false_when_process_gone(make_service):
    svc, _ = make_service()
    proc = _FakeProc()
    proc.terminated = True
    svc._proc = proc
    assert svc.wait_listening(timeout=0.1) is False


def test_wait_listening_checks_our_pid(make_service, monkeypatch):
    svc, _ = make_service(proxy_port=8090)
    svc._proc = _FakeProc(pid=77)
    seen = []
    monkeypatch.setattr(
        ms, "_pid_listening", lambda pid, port, host: seen.append((pid, port)) or True
    )
    assert svc.wait_listening(timeout=1)
    assert seen == [(77, 8090)]


# ── device proxy ownership ──────────────────────────────────────────────


class _FakePM:
    def __init__(self, current):
        self.current = current
        self.unset_calls = 0

    def get_proxy_settings(self):
        if not self.current:
            return proxy_manager.ProxyStatus.NOT_SET, None
        return (
            proxy_manager.ProxyStatus.SET,
            proxy_manager.ProxyConfig.from_string(self.current),
        )

    def unset_proxy(self):
        self.unset_calls += 1
        self.current = ""
        return True, "Proxy cleared"


@pytest.fixture
def fake_pm(monkeypatch):
    pm = _FakePM("")
    monkeypatch.setattr(proxy_manager, "ProxyManager", lambda: pm)
    monkeypatch.setattr(proxy_manager, "_reverse_registered", lambda port: False)
    return pm


def test_release_clears_our_proxy(make_service, fake_pm):
    svc, _ = make_service()
    fake_pm.current = "10.0.2.2:8090"
    svc.note_device_proxy("10.0.2.2:8090")
    assert svc.release_device_proxy() is True
    assert fake_pm.current == ""
    assert svc.owned_device_proxy is None


def test_release_leaves_foreign_proxy(make_service, fake_pm):
    svc, _ = make_service()
    fake_pm.current = "192.168.1.5:8888"  # changed by someone else since
    svc.note_device_proxy("10.0.2.2:8090")
    assert svc.release_device_proxy() is False
    assert fake_pm.unset_calls == 0


def test_release_noop_when_nothing_owned(make_service, fake_pm):
    svc, _ = make_service()
    fake_pm.current = "10.0.2.2:8090"
    assert svc.release_device_proxy() is False
    assert fake_pm.unset_calls == 0


def test_stop_and_exit_release_device_proxy(make_service, fake_pm):
    svc, _ = make_service()
    svc._proc = _FakeProc()
    fake_pm.current = "10.0.2.2:8090"
    svc.note_device_proxy("10.0.2.2:8090")
    svc.stop()
    assert fake_pm.current == ""

    fake_pm.current = "10.0.2.2:8090"
    svc.note_device_proxy("10.0.2.2:8090")
    svc._atexit_cleanup()
    assert fake_pm.current == ""


# ── Mitmproxy panel (no app mounted: log/header writes are best-effort) ──


@pytest.fixture
def panel(make_service, monkeypatch):
    from sandroid.tui.widgets import mitmproxy_panel as mp

    svc, cfg = make_service()
    monkeypatch.setattr(mp, "get_mitmproxy_service", lambda: svc)
    p = mp.MitmproxyPanel()
    lines = []
    monkeypatch.setattr(p, "_append_line", lines.append)
    monkeypatch.setattr(p, "_refresh_header", lambda: None)
    monkeypatch.setattr(p, "_kick_state_refresh", lambda: None)
    return p, svc, cfg, lines


def test_panel_inconclusive_probe_is_not_an_error(panel):
    p, _, _, lines = panel
    res = ms.ReachabilityResult(
        reachable=False,
        flows_incremented=False,
        detail="mitmproxy is not listening on :8090 yet",
        inconclusive=True,
    )
    p._apply_reachability_result(res, "10.0.2.2:8090")
    assert p._reach_state == "unknown"
    assert not any(line.startswith("[ERROR]") for line in lines)


def test_panel_device_flows_retract_unreachable(panel):
    p, _, _, _ = panel
    p._reach_state = "unreachable"
    p._note_direct_flow("[FLOW]|t|HTTPS|200|GET|x/y|1KB|org.app")  # app lane
    assert p._reach_state == "unreachable"
    p._note_direct_flow("[FLOW]|t|HTTPS|200|GET|x/y|1KB|")
    assert p._reach_state == "ok"


@pytest.mark.parametrize("auto", [False, True])
def test_panel_start_sets_device_proxy_only_when_configured(panel, monkeypatch, auto):
    p, svc, cfg, _ = panel
    cfg.mitmproxy.auto_device_proxy = auto
    import sandroid.config as config_pkg

    monkeypatch.setattr(config_pkg, "get_config", lambda: cfg)
    running = {"v": False}
    monkeypatch.setattr(svc, "is_running", lambda: running["v"])
    monkeypatch.setattr(svc, "start", lambda: running.update(v=True) or True)
    armed = []
    monkeypatch.setattr(p, "_arm_device", lambda: armed.append(1))
    p.action_toggle_running()
    assert armed == ([1] if auto else [])


# ── phase 3: settle after Zygote restart / reconnect, never a stale verdict ──


def _settle_device(adb_out, *answers):
    """Queue (boot_completed, pm ok) answers for wait_device_settled."""
    for boot, pm_ok in answers:
        adb_out[0].append((boot, ""))
        if boot == "1":
            adb_out[0].append(
                ("package:/system/framework-res.apk" if pm_ok else "", "")
            )


def test_wait_device_settled_needs_stable_package_manager(make_service, adb_out):
    svc, _ = make_service()
    # restarting: no boot, then pm down, then two good polls in a row.
    _settle_device(adb_out, ("", False), ("1", False), ("1", True), ("1", True))
    assert svc.wait_device_settled(timeout=30, poll=0)
    assert adb_out[0] == []


def test_wait_device_settled_times_out(make_service, adb_out, monkeypatch):
    svc, _ = make_service()
    clock = iter(range(0, 1000, 10))
    monkeypatch.setattr(ms.time, "monotonic", lambda: next(clock))
    assert not svc.wait_device_settled(timeout=25, poll=0)


def test_probe_after_restart_unsettled_is_inconclusive(make_service, monkeypatch):
    svc, _ = make_service()
    monkeypatch.setattr(svc, "wait_device_settled", lambda timeout=0: False)
    probes = []
    monkeypatch.setattr(svc, "probe_device_reachability", lambda h, p: probes.append(1))
    res = svc.probe_after_device_restart("10.0.2.2", 8090)
    assert res.inconclusive
    assert not res.reachable
    assert "CANNOT" not in res.detail
    assert probes == []


def test_probe_after_restart_retries_until_network_is_back(make_service, monkeypatch):
    svc, _ = make_service()
    monkeypatch.setattr(ms.time, "sleep", lambda s: None)
    monkeypatch.setattr(svc, "wait_device_settled", lambda timeout=0: True)
    seq = [_unreachable(), ms.ReachabilityResult(True, True, "reachable")]
    monkeypatch.setattr(svc, "probe_device_reachability", lambda h, p: seq.pop(0))
    assert svc.probe_after_device_restart("10.0.2.2", 8090).reachable
    assert seq == []


def _unreachable():
    return ms.ReachabilityResult(False, False, "device CANNOT reach mitmproxy")


def test_panel_unreachable_schedules_reprobe(panel, monkeypatch):
    p, _, _, lines = panel
    scheduled = []
    monkeypatch.setattr(p, "_schedule_reprobe", lambda: scheduled.append(1))
    p._apply_reachability_result(_unreachable(), "10.0.2.2:8090")
    assert p._reach_state == "unreachable"
    assert scheduled == [1]
    assert sum(line.startswith("[ERROR]") for line in lines) == 1
    # A quiet periodic re-probe that still fails neither re-logs nor stops.
    p._apply_reachability_result(_unreachable(), "10.0.2.2:8090", None, True)
    assert sum(line.startswith("[ERROR]") for line in lines) == 1
    assert scheduled == [1, 1]
    # ...and one that succeeds retracts the verdict explicitly.
    ok = ms.ReachabilityResult(True, True, "device→mitmproxy reachable")
    p._apply_reachability_result(ok, "10.0.2.2:8090", None, True)
    assert p._reach_state == "ok"
    assert "no longer applies" in lines[-1]


def test_panel_drops_stale_probe_result(panel, monkeypatch):
    p, _, _, lines = panel
    monkeypatch.setattr(p, "_schedule_reprobe", lambda: None)
    p._probe_gen = 5
    p._apply_reachability_result(_unreachable(), "10.0.2.2:8090", 4)
    assert p._reach_state == "unknown"
    assert lines == []


def test_panel_settle_probe_after_zygote_restart(panel, monkeypatch):
    """Ctrl+N success → wait for the device to settle, then probe (no
    immediate probe against a device without network).
    """
    p, _, _, _ = panel
    kicks = []
    monkeypatch.setattr(p, "_kick_reachability_probe", lambda **kw: kicks.append(kw))
    monkeypatch.setattr(p, "_nudge_unpin", lambda: None)
    monkeypatch.setattr(
        proxy_manager.CAManager,
        "bypass_chrome_ct",
        lambda self, path: (False, "skipped"),
    )
    p._proxy_state = "ours"
    result = proxy_manager.InjectionResult(
        success=True,
        message="ok",
        strategy=proxy_manager.InjectionStrategy.BIND_MOUNT,
        api_level=35,
    )
    p._apply_inject_result(result, None)
    assert kicks == [{"settle": True, "reason": "the Zygote restart"}]


def test_panel_settle_kick_shows_checking_not_stale(panel, monkeypatch):
    p, _, _, lines = panel
    import threading

    monkeypatch.setattr(threading.Thread, "start", lambda self: None)
    p._reach_state = "unreachable"
    p._kick_reachability_probe(settle=True, reason="the Zygote restart")
    assert p._reach_state == "checking"
    assert "settle" in lines[-1]
    # Device-Proxy flows arriving meanwhile prove it reachable.
    p._note_direct_flow("[FLOW]|t|HTTPS|200|GET|x/y|1KB|")
    assert p._reach_state == "ok"


def test_panel_device_reconnect_reprobes(panel, monkeypatch):
    p, svc, _, _ = panel
    kicks = []
    monkeypatch.setattr(p, "_kick_reachability_probe", lambda **kw: kicks.append(kw))
    monkeypatch.setattr(svc, "is_running", lambda: True)
    p._proxy_state = "ours"
    p._reach_state = "unreachable"
    gen = p._probe_gen
    p._handle_device_change(None)  # disconnect: the verdict no longer applies
    assert p._reach_state == "unknown"
    assert p._probe_gen > gen
    assert kicks == []
    p._handle_device_change(SimpleNamespace(serial="emulator-5556"))
    assert kicks == [{"settle": True, "reason": "device reconnected"}]


def test_panel_reprobe_due_only_while_unreachable(panel, monkeypatch):
    p, svc, _, _ = panel
    kicks = []
    monkeypatch.setattr(p, "_kick_reachability_probe", lambda **kw: kicks.append(kw))
    monkeypatch.setattr(svc, "is_running", lambda: True)
    p._proxy_state = "ours"
    p._reach_state = "ok"
    p._reprobe_due()
    assert kicks == []
    p._reach_state = "unreachable"
    p._reprobe_due()
    assert kicks == [{"quiet": True}]
