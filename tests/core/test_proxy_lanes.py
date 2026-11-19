"""App Proxy lanes: detached gost, reconcile against device truth, IPv6
fence, socket flush, health ("waiting for mitmproxy").

Observation lines are the shapes the lane script printed on API 35.
"""

from __future__ import annotations

import atexit
import base64
import re

import pytest

from sandroid.core import proxy_manager as pm

SERIAL = "emulator-5570"
BIN = "/data/local/tmp/gost"
UP = "socks5://10.0.2.2:8082"
UID = 10215


def _gost(pid, port=60080, up=UP, fd="/dev/null"):
    return f"GOST pid={pid} fd1={fd} fd2={fd} cmd={BIN} -L red://:{port} -F {up} "


def _rules(uid=UID, port=60080, quic=True, v6=True):
    out = [
        f"NAT4 -A OUTPUT -p tcp -m owner --uid-owner {uid} -m comment --comment "
        f"sandroid-focus -j REDIRECT --to-ports {port}"
    ]
    if quic:
        out.append(
            f"FILTER4 -A OUTPUT -p udp -m owner --uid-owner {uid} -m udp --dport 443 "
            "-m comment --comment sandroid-focus -j REJECT --reject-with "
            "icmp-port-unreachable"
        )
    if v6:
        out.append(
            f"FILTER6 -A OUTPUT -p tcp -m owner --uid-owner {uid} -m comment "
            "--comment sandroid-focus -j REJECT --reject-with tcp-reset"
        )
        if quic:
            out.append(
                f"FILTER6 -A OUTPUT -p udp -m owner --uid-owner {uid} -m udp "
                "--dport 443 -m comment --comment sandroid-focus -j REJECT "
                "--reject-with icmp6-port-unreachable"
            )
    return out


def _obs(*lines, uid=UID, listen=(60080,), ip6_nat=False):
    text = [*lines, *(f"LISTEN *:{p}" for p in listen), "IP6 filter"]
    if ip6_nat:
        text.append("IP6 nat")
    text.append(f"UID de.fkie.privacycanary {uid if uid else 'missing'}")
    text.append("rc=0")
    return pm.parse_lane_observation("\n".join(text))


DESIRED = [pm.DesiredLane(0, "de.fkie.privacycanary", 60080, UP)]


def _plan(obs, quic=True, desired=DESIRED):
    return pm.plan_lanes(
        desired, obs, binary=BIN, port_range=range(60080, 60085), quic=quic
    )


# -- parsing ------------------------------------------------------------------------


def test_parse_observation():
    obs = _obs(_gost(5300), _gost(5301, fd="socket:[119974]"), *_rules())
    assert [g.pid for g in obs.gosts] == [5300, 5301]
    assert obs.gosts[1].doomed
    assert not obs.gosts[0].doomed
    assert obs.gosts[0].port() == 60080
    assert obs.listening == {60080}
    assert obs.ip6_filter
    assert not obs.ip6_nat
    assert obs.uids == {"de.fkie.privacycanary": UID}
    assert len(obs.rules) == 4


def test_rule_keys_normalise_reject_and_drop():
    reject = pm.parse_rule_key("FILTER4", _rules()[1][len("FILTER4 ") :])
    drop = pm.parse_rule_key(
        "FILTER4",
        f"-A OUTPUT -p udp -m owner --uid-owner {UID} -m udp --dport 443 "
        "-m comment --comment sandroid-focus -j DROP",
    )
    assert reject == drop
    assert reject.target == "BLOCK"


# -- reconcile planning (decision table) -------------------------------------------


def test_healthy_lane_needs_nothing():
    (plan,), orphans, stale = _plan(_obs(_gost(5300), *_rules()))
    assert (plan.kill, plan.launch, plan.add) == ([], False, set())
    assert orphans == []
    assert stale == []


def test_missing_lane_after_loading_a_snapshot_without_it():
    (plan,), _, _ = _plan(_obs(listen=()))
    assert plan.launch
    assert "gost not running" in plan.why
    targets = {(k.family, k.table, k.proto, k.target) for k in plan.add}
    assert targets == {
        ("4", "nat", "tcp", "REDIRECT"),
        ("4", "filter", "udp", "BLOCK"),
        ("6", "filter", "tcp", "BLOCK"),
        ("6", "filter", "udp", "BLOCK"),
    }


def test_doomed_gost_from_an_old_launch_is_replaced():
    """Alive and listening, but stdout is the old adb session socket: it dies
    at its first logged connection after any session loss.
    """
    (plan,), _, _ = _plan(_obs(_gost(10899, fd="socket:[119974]"), *_rules()))
    assert plan.kill == [10899]
    assert plan.launch
    assert any("old adb session" in why for why in plan.why)


def test_gost_with_another_upstream_and_duplicates():
    obs = _obs(_gost(1, up="socks5://192.168.1.5:8082"), _gost(2), _gost(3), *_rules())
    (plan,), _, _ = _plan(obs)
    assert sorted(plan.kill) == [1, 3]
    assert not plan.launch


def test_gost_not_listening_is_relaunched():
    (plan,), _, _ = _plan(_obs(_gost(7), *_rules(), listen=()))
    assert plan.kill == [7]
    assert plan.launch


def test_missing_v6_fence_is_added_alone():
    (plan,), _, _ = _plan(_obs(_gost(5300), *_rules(v6=False)))
    assert not plan.launch
    assert {(k.family, k.proto) for k in plan.add} == {("6", "tcp"), ("6", "udp")}


def test_stale_rules_and_orphans_in_our_range_only():
    obs = _obs(
        _gost(5300),
        _gost(6000, port=60081),  # our range, no lane wants it: orphan
        _gost(7000, port=1080),  # someone else's gost: never touched
        *_rules(),
        *_rules(uid=10999, port=60081, quic=False, v6=False),  # other config
    )
    (plan,), orphans, stale = _plan(obs)
    assert orphans == [6000]
    assert [line for _, line in stale] == [_rules(10999, 60081)[0][len("NAT4 ") :]]
    assert plan.kill == []


def test_quic_off_makes_quic_rules_stale():
    _, _, stale = _plan(_obs(_gost(5300), *_rules()), quic=False)
    assert {kind for kind, _ in stale} == {"FILTER4", "FILTER6"}


def test_uninstalled_app_is_torn_down_loudly():
    (plan,), _, stale = _plan(_obs(_gost(5300), *_rules(), uid=None))
    assert plan.app_missing
    assert plan.kill == [5300]
    assert len(stale) == 4


def test_reinstalled_app_gets_rules_for_its_new_uid():
    (plan,), _, stale = _plan(_obs(_gost(5300), *_rules(), uid=10300))
    assert {k.uid for k in plan.add} == {10300}
    assert {pm.parse_rule_key(k, line).uid for k, line in stale} == {UID}


def test_v6_nat_redirects_instead_of_rejecting():
    keys = pm.desired_rule_keys(UID, 60080, quic=False, ip6_filter=True, ip6_nat=True)
    assert pm.RuleKey("6", "nat", "tcp", UID, None, "REDIRECT", 60080) in keys
    assert not any(k.family == "6" and k.table == "filter" for k in keys)


# -- the FocusManager against a fake device -----------------------------------------


class _Device:
    """Fake adb for the FocusManager: lane script ops + plain commands."""

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.ops: list[list[str]] = []
        self.observe = "\n".join(
            [
                *_rules(),
                "LISTEN *:60080",
                "IP6 filter",
                f"UID {DESIRED[0].package} {UID}",
            ]
        )
        self.gost_alive = True

    def __call__(self, cmd, serial=None, timeout=30):
        self.sent.append(cmd)
        if cmd == "shell id":
            return "uid=0(root)", ""
        m = re.search(r"echo ([A-Za-z0-9+/=]+) \| base64 -d \| sh -s -- (.*)'$", cmd)
        if m:
            script = base64.b64decode(m.group(1)).decode()
            args = m.group(2).split()
            self.ops.append(args)
            if script == pm._LANE_SCRIPT:
                op = args[0]
                if op == "observe":
                    gost = _gost(5300) if self.gost_alive else ""
                    return f"{gost}\n{self.observe}\nrc=0\n", ""
                if op == "listening":
                    return "LISTENING\nrc=0\n", ""
                if op == "flush":
                    return "flushed=2\nrc=0\n", ""
                return "rc=0\n", ""
        if "ip6tables -w -S OUTPUT" in cmd:
            return "-P OUTPUT ACCEPT\n", ""
        if "ip6tables -w -t nat -S OUTPUT" in cmd:
            return "", ""
        if "stat -c %u" in cmd:
            return f"{UID}\n", ""
        if "sha256sum" in cmd:
            return "", ""
        return "", ""


@pytest.fixture
def fm(monkeypatch):
    dev = _Device()
    monkeypatch.setattr(pm.Adb, "send_adb_command", staticmethod(dev))
    monkeypatch.setattr(pm.Adb, "_target_device", SERIAL)
    monkeypatch.setattr(pm.FocusManager, "_pool_size", property(lambda self: 5))
    manager = pm.FocusManager()
    atexit.unregister(manager._atexit_cleanup)  # never at exit on the stub adb
    manager._ca._use_su = False  # adb root (as the root probe would find)
    monkeypatch.setattr(manager, "_write_sidecar", lambda: None)
    monkeypatch.setattr(manager, "_add_to_state", lambda package: None)
    monkeypatch.setattr(manager, "_publish_health", lambda: None)
    monkeypatch.setattr(manager, "_ensure_binary", lambda: (True, "ok"))
    monkeypatch.setattr(manager, "_probe_owner_match", lambda: (True, "ok"))
    monkeypatch.setattr(manager, "_cleanup_stale_locked", lambda: None)
    monkeypatch.setattr(manager, "_device_tcp_reachable", lambda h, p: "reachable")
    monkeypatch.setattr(pm, "_install_restore_hook", lambda: None)
    manager.dev = dev
    return manager


def _mitm(monkeypatch, running: bool):
    monkeypatch.setattr(
        pm.FocusManager, "_mitmproxy_running", staticmethod(lambda: running)
    )


def test_gost_launch_is_detached_and_synchronous(fm):
    fm._launch_gost(60080, UP)
    (cmd,) = [c for c in fm.dev.sent if "setsid" in c]
    assert "setsid sh -c 'exec /data/local/tmp/gost -L red://:60080 -F " in cmd.replace(
        "'\"'\"'", "'"
    )
    assert "</dev/null >/dev/null 2>&1 &" in cmd


def test_no_pattern_kill_of_gost(fm):
    fm._kill_lane_process(60080)
    assert fm.dev.ops[-1] == ["kill", BIN, "60080"]
    assert not any("pkill" in c and "gost" in c for c in fm.dev.sent)


def test_enable_fails_closed_first_and_flushes_sockets(fm, monkeypatch):
    _mitm(monkeypatch, True)
    ok, msg = fm.enable_focus(DESIRED[0].package)
    assert ok, msg
    order = [
        c
        for c in fm.dev.sent
        if (("-A" in c or "-I" in c) and "tables" in c) or "setsid" in c
    ]
    kinds = [
        "v6" if "ip6tables" in c and "tcp-reset" in c else
        "quic" if "--dport 443" in c else
        "gost" if "setsid" in c else
        "redirect" if "REDIRECT" in c else "?"
        for c in order
    ]  # fmt: skip
    assert kinds.index("v6") < kinds.index("gost") < kinds.index("redirect")
    assert kinds.index("quic") < kinds.index("gost")
    assert ["flush", str(UID)] in fm.dev.ops
    assert fm.lane_health()[DESIRED[0].package].state == pm.LANE_ACTIVE


def test_ipv6_filter_is_probed_apart_from_nat(fm):
    assert fm._ip6_caps() == (True, False)
    fm._ensure_v6_fence(0, UID)
    assert any("ip6tables -w -I OUTPUT" in c and "tcp-reset" in c for c in fm.dev.sent)


def test_mitmproxy_off_keeps_the_lane_waiting(fm, monkeypatch):
    _mitm(monkeypatch, False)
    ok, msg = fm.enable_focus(DESIRED[0].package)
    assert ok
    assert "waiting for mitmproxy" in msg
    assert fm.app_proxies() == {DESIRED[0].package: "ours"}
    assert fm.lane_health()[DESIRED[0].package].label == "waiting for mitmproxy"
    # mitmproxy comes back: the same gost forwards again, no device action.
    _mitm(monkeypatch, True)
    assert fm.lane_health()[DESIRED[0].package].ok


def test_ctrl_s_on_a_proxied_app_reconciles_and_repairs(fm, monkeypatch):
    _mitm(monkeypatch, True)
    assert fm.enable_focus(DESIRED[0].package)[0]
    fm.dev.gost_alive = False  # gost died (e.g. after a snapshot load)
    fm.dev.observe = fm.dev.observe.replace("LISTEN *:60080", "")
    launches = sum("setsid" in c for c in fm.dev.sent)
    ok, msg = fm.enable_focus(DESIRED[0].package)
    assert ok
    assert "repaired" in msg
    assert sum("setsid" in c for c in fm.dev.sent) == launches + 1


def test_reconcile_reports_an_uninstalled_app(fm, monkeypatch):
    _mitm(monkeypatch, True)
    assert fm.enable_focus(DESIRED[0].package)[0]
    fm.dev.observe = fm.dev.observe.replace(
        f"{DESIRED[0].package} {UID}", f"{DESIRED[0].package} missing"
    )
    (report,) = fm.reconcile(SERIAL, "snapshot-load")
    assert report.health.state == pm.LANE_FAILED
    assert report.health.label == "failed: app not installed"
    assert fm.app_proxies() == {DESIRED[0].package: "ours"}  # still requested


def test_reconcile_without_lanes_costs_no_adb(fm):
    assert fm.reconcile(SERIAL, "snapshot-load") == []
    assert fm.dev.sent == []


def test_cleanup_kills_by_port_range_never_pkill_gost(monkeypatch):
    dev = _Device()
    monkeypatch.setattr(pm.Adb, "send_adb_command", staticmethod(dev))
    monkeypatch.setattr(pm.Adb, "_target_device", SERIAL)
    monkeypatch.setattr(pm.FocusManager, "_pool_size", property(lambda self: 3))
    manager = pm.FocusManager()
    atexit.unregister(manager._atexit_cleanup)  # never at exit on the stub adb
    manager._ca._use_su = False
    monkeypatch.setattr(manager, "_write_sidecar", lambda: None)
    manager._cleanup_stale_locked()
    assert ["kill", BIN, "60080", "60081", "60082"] in dev.ops
    assert not any("pkill -f /data/local/tmp/gost" in c for c in dev.sent)


def test_flush_uses_the_proven_sport_filter():
    """``state established`` plus ports matched nothing on the device's
    iproute2: the script picks the UID's ESTAB sockets and kills by sport.
    """
    script = pm._LANE_SCRIPT
    flush = script[script.index("flush)") :]
    assert 'ss -K -tn "( sport = :$sp )"' in flush
    assert "state established" not in flush
    assert '$1=="ESTAB"' in flush
    assert 'u="uid:$uid"' in flush
