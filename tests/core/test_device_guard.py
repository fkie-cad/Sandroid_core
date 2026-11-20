"""Kill switch + identity relay (core.device_guard), without a device.

Observation lines are the ``iptables -S`` / ``-L -nvx`` shapes Android's
iptables prints; the device script is replaced by a recorder.
"""

from __future__ import annotations

import logging

import pytest

from sandroid.core import device_guard as dg

SERIAL = "emulator-5570"
LOOP = dg.Endpoint("127.0.0.1", 8080)
SLIRP = dg.Endpoint("10.0.2.2", 8080)
BURP = dg.Endpoint("192.168.1.5", 8081)


def _ks_lines(chain="sandroid_ks", endpoint=SLIRP, family="4", counters=(0, 0)):
    tag = f"KS{family}"
    lo = "127.0.0.0/8" if family == "4" else "::1/128"
    lines = [f"{tag} -N {chain}", f"{tag} -A {chain} -d {lo} -j RETURN"]
    if family == "4" and endpoint is not None and not endpoint.loopback:
        lines.append(
            f"{tag} -A {chain} -d {endpoint.ip}/32 -p tcp -m tcp --dport "
            f"{endpoint.port} -j RETURN"
        )
    lines += [
        f"{tag} -A {chain} -p tcp -j REJECT --reject-with tcp-reset",
        f"{tag} -A {chain} -j REJECT --reject-with "
        + ("icmp-port-unreachable" if family == "4" else "icmp6-port-unreachable"),
        f"JUMP{family} -A OUTPUT -m owner --uid-owner 10000-29999 -j {chain}",
        f"CNT{family} {counters[0]}",
        f"CNT{family} {counters[1]}",
    ]
    return lines


def _obs(*lines, proxy="10.0.2.2:8080", ip6=True, packages=None):
    text = list(lines)
    if ip6:
        text.append("IP6 filter")
    text.append(f"PROXY {proxy}")
    for pkg, uid in (packages or {}).items():
        text.append(f"PKG {pkg} {uid}")
    text.append("rc=0")
    return dg.parse_guard_observation("\n".join(text))


# -- endpoint ------------------------------------------------------------------------


def test_endpoint_parse():
    assert dg.Endpoint.parse("10.0.2.2:8080") == SLIRP
    assert dg.Endpoint.parse(":0") is None
    assert dg.Endpoint.parse("null") is None
    assert dg.Endpoint.parse("") is None
    assert dg.Endpoint.parse("burp.local:8080").is_ipv4 is False
    assert LOOP.loopback
    assert not SLIRP.loopback
    assert SLIRP.is_ipv4


# -- kill switch rules ---------------------------------------------------------------


def test_kill_switch_rules_loopback_by_destination_never_by_interface():
    rules = dg.desired_ks_rules(SLIRP, "4")
    assert rules[0] == dg.KsRule("127.0.0.0/8", "", None, "RETURN")
    assert rules[1] == dg.KsRule("10.0.2.2/32", "tcp", 8080, "RETURN")
    assert rules[-2:] == [
        dg.KsRule("", "tcp", None, "REJECT"),
        dg.KsRule("", "", None, "REJECT"),
    ]
    cmds = dg.plan_kill_switch(True, SLIRP, _obs(proxy="10.0.2.2:8080"), "4")
    text = "\n".join(cmds)
    assert "-o lo" not in text  # -o lo broke App Proxy lanes after REDIRECT
    assert "-d 127.0.0.0/8 -j RETURN" in text


def test_kill_switch_loopback_endpoint_needs_no_extra_allow():
    assert dg.desired_ks_rules(LOOP, "4") == [
        dg.KsRule("127.0.0.0/8", "", None, "RETURN"),
        dg.KsRule("", "tcp", None, "REJECT"),
        dg.KsRule("", "", None, "REJECT"),
    ]


def test_kill_switch_external_endpoint_is_allowed():
    cmds = dg.plan_kill_switch(True, BURP, _obs(proxy="192.168.1.5:8081"), "4")
    assert any(
        "-d 192.168.1.5/32 -p tcp -m tcp --dport 8081 -j RETURN" in c for c in cmds
    )


def test_kill_switch_ipv6_rejects_everything_but_loopback():
    rules = dg.desired_ks_rules(SLIRP, "6")
    assert rules[0].dst == "::1/128"
    assert all(r.dst in ("", "::1/128") for r in rules)  # no v4 endpoint in v6
    cmds = dg.plan_kill_switch(True, SLIRP, _obs(), "6")
    assert all(c.startswith("ip6tables") for c in cmds)
    assert any("-d ::1/128 -j RETURN" in c for c in cmds)


def test_kill_switch_fresh_install_order():
    cmds = dg.plan_kill_switch(True, SLIRP, _obs(), "4")
    assert cmds[0] == "iptables -w -N sandroid_ks"
    jump = next(i for i, c in enumerate(cmds) if "-I OUTPUT 1" in c)
    rules = [i for i, c in enumerate(cmds) if "-A sandroid_ks" in c]
    assert rules
    assert max(rules) < jump  # the chain is complete before the jump
    assert "--uid-owner 10000-29999 -j sandroid_ks" in cmds[jump]
    reject = [c for c in cmds if "REJECT" in c]
    assert all("|| " in c and "-j DROP" in c for c in reject)  # DROP fallback


def test_kill_switch_matching_chain_is_left_alone():
    obs = _obs(*_ks_lines(counters=(7, 5)))
    assert obs.kill_switch_on
    assert obs.refused["4"] == 12
    assert dg.plan_kill_switch(True, SLIRP, obs, "4") == []


def test_kill_switch_endpoint_change_is_double_buffered():
    obs = _obs(*_ks_lines(endpoint=SLIRP), proxy="192.168.1.5:8081")
    cmds = dg.plan_kill_switch(True, BURP, obs, "4")
    assert cmds[0] == "iptables -w -N sandroid_ks2"
    new_jump = next(i for i, c in enumerate(cmds) if "-I OUTPUT 1" in c)
    old_jump = next(i for i, c in enumerate(cmds) if "-D OUTPUT" in c)
    flush_old = cmds.index("iptables -w -F sandroid_ks")
    assert "sandroid_ks2" in cmds[new_jump]
    assert new_jump < old_jump < flush_old  # never a moment without a chain
    assert cmds[-1] == "iptables -w -X sandroid_ks"


def test_kill_switch_removal_drops_jumps_before_chains():
    obs = _obs(*_ks_lines())
    cmds = dg.plan_kill_switch(False, None, obs, "4")
    assert cmds == [
        "iptables -w -D OUTPUT -m owner --uid-owner 10000-29999 -j sandroid_ks",
        "iptables -w -F sandroid_ks",
        "iptables -w -X sandroid_ks",
    ]
    assert dg.plan_kill_switch(False, None, _obs(), "4") == []


def test_counters_sum_both_families():
    obs = _obs(*_ks_lines(counters=(3, 1)), *_ks_lines(family="6", counters=(2, 0)))
    assert obs.refused == {"4": 4, "6": 2}


# -- proxy-port chain (app naming + the App Proxy bug fix) ----------------------------


def test_proxy_chain_fresh_install():
    obs = _obs(proxy="127.0.0.1:8080")
    cmds, added = dg.plan_proxy_chain(LOOP, {10215: 61000, 10146: 61001}, obs)
    assert added
    assert cmds[0] == "iptables -w -t nat -N sandroid_dp"
    assert any("--uid-owner 10215 -j REDIRECT --to-ports 61000" in c for c in cmds)
    accept = cmds.index("iptables -w -t nat -A sandroid_dp -j ACCEPT")
    jump = next(i for i, c in enumerate(cmds) if "-I OUTPUT 1" in c)
    assert accept < jump
    assert cmds[jump].endswith(
        "-d 127.0.0.1/32 -p tcp -m tcp --dport 8080 -j sandroid_dp"
    )


def test_proxy_chain_goes_before_app_proxy_lanes():
    """Regression: an App Proxy lane REDIRECT (appended to nat OUTPUT) caught
    the app's own connection to the device proxy; Mitmproxy refused to
    connect to itself and the flow was lost. The proxy-port jump must come
    first, and the chain ends in ACCEPT so the lane never sees it.
    """
    lane = (
        "NATOUT -A OUTPUT -p tcp -m owner --uid-owner 10215 -m comment --comment "
        "sandroid-focus -j REDIRECT --to-ports 60080"
    )
    ours = "NATOUT -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport 8080 -j sandroid_dp"
    chain = [
        "DP -N sandroid_dp",
        "DP -A sandroid_dp -p tcp -m owner --uid-owner 10215 -j REDIRECT "
        "--to-ports 61000",
        "DP -A sandroid_dp -j ACCEPT",
    ]
    wrong = _obs(lane, ours, *chain, proxy="127.0.0.1:8080")
    cmds, _ = dg.plan_proxy_chain(LOOP, {10215: 61000}, wrong)
    assert cmds[0].startswith("iptables -w -t nat -I OUTPUT 1 -d 127.0.0.1/32")
    assert cmds[1].startswith("iptables -w -t nat -D OUTPUT -d 127.0.0.1/32")
    right = _obs(ours, lane, *chain, proxy="127.0.0.1:8080")
    assert dg.plan_proxy_chain(LOOP, {10215: 61000}, right) == ([], False)
    # Without app naming the chain still ends in ACCEPT (the bug fix alone).
    cmds, _ = dg.plan_proxy_chain(LOOP, {}, _obs(lane, proxy="127.0.0.1:8080"))
    assert "iptables -w -t nat -A sandroid_dp -j ACCEPT" in cmds


def test_proxy_chain_updates_uids_and_removes_on_clear():
    chain = [
        "DP -N sandroid_dp",
        "DP -A sandroid_dp -p tcp -m owner --uid-owner 10100 -j REDIRECT "
        "--to-ports 61000",
        "DP -A sandroid_dp -j ACCEPT",
        "NATOUT -A OUTPUT -d 10.0.2.2/32 -p tcp -m tcp --dport 8080 -j sandroid_dp",
    ]
    obs = _obs(*chain)
    cmds, added = dg.plan_proxy_chain(SLIRP, {10200: 61001}, obs)
    assert not added
    assert cmds == [
        "iptables -w -t nat -I sandroid_dp 1 -p tcp -m owner --uid-owner 10200 "
        "-j REDIRECT --to-ports 61001",
        "iptables -w -t nat -D sandroid_dp -p tcp -m owner --uid-owner 10100 "
        "-j REDIRECT --to-ports 61000",
    ]
    cmds, _ = dg.plan_proxy_chain(None, {}, obs)
    assert cmds == [
        "iptables -w -t nat -D OUTPUT -d 10.0.2.2/32 -p tcp -m tcp --dport 8080 "
        "-j sandroid_dp",
        "iptables -w -t nat -F sandroid_dp",
        "iptables -w -t nat -X sandroid_dp",
    ]


# -- relay ---------------------------------------------------------------------------


def test_uid_groups_and_ports():
    packages = {"a.b": 10215, "c.d": 10146, "shared.one": 10300, "shared.two": 10300}
    packages["android"] = 1000
    groups = dg.app_uid_groups(packages)
    assert groups == {
        10146: ["c.d"],
        10215: ["a.b"],
        10300: ["shared.one", "shared.two"],
    }
    ports = dg.assign_relay_ports(list(groups), {10215: 61005, 10146: 99})
    assert ports[10215] == 61005  # kept
    assert ports[10146] == 61000  # out of range: reassigned
    assert len(set(ports.values())) == 3


def test_relay_health_needs_tag_and_listeners():
    ports = {10215: 61000}
    tag = dg.relay_tag(ports, "127.0.0.1:8080")
    assert tag != dg.relay_tag(ports, "10.0.2.2:8080")
    good = _obs(
        "RELAY pid=77 fd1=/dev/null fd2=/dev/null", "LISTEN 61000", f"CFG # {tag}"
    )
    assert dg.relay_healthy(good, ports, tag)
    doomed = _obs(
        "RELAY pid=77 fd1=socket:[1] fd2=/dev/null", "LISTEN 61000", f"CFG # {tag}"
    )
    assert not dg.relay_healthy(doomed, ports, tag)
    assert not dg.relay_healthy(_obs("LISTEN 61000", f"CFG # {tag}"), ports, tag)


def test_relay_script_writes_identity_config(tmp_path):
    """The device script's config is what the addon expects (uid<U> auth)."""
    import shutil
    import subprocess

    if shutil.which("sh") is None:
        pytest.skip("no sh")
    script = dg._GUARD_SCRIPT.replace("setsid sh -c", ": setsid sh -c").replace(
        "while [ $i -lt 40 ]", "while [ $i -lt 0 ]"
    )
    cfg = tmp_path / "relay.yaml"
    out = subprocess.run(
        [
            "sh",
            "-s",
            "--",
            "relay",
            "/x/relaybin",
            str(cfg),
            "127.0.0.1:8080",
            "TAG",
            "10215:61000",
            "10146:61001",
        ],
        input=script,
        capture_output=True,
        text=True,
        check=False,
    )
    assert "rc=" in out.stdout
    text = cfg.read_text()
    assert text.splitlines()[0] == "# TAG"
    assert "addr: 127.0.0.1:61000" in text
    assert "username: uid10146" in text
    assert text.count("addr: 127.0.0.1:8080") == 2


# -- DeviceGuard against a recorded device ---------------------------------------------


class _Device:
    """Answers the guard script: observe text per call, records the rest."""

    def __init__(self, observe: str):
        self.observe = observe
        self.calls: list[tuple] = []

    def __call__(self, serial, *args, timeout=60.0):
        self.calls.append(args)
        if args[0] == "observe":
            return self.observe
        if args[0] == "relay":
            return "LISTENING\nrc=0"
        return "rc=0"

    def commands(self) -> list[str]:
        return [c for call in self.calls if call[0] == "run" for c in call[1:]]


@pytest.fixture
def guard(monkeypatch, tmp_path):
    g = dg.DeviceGuard()
    monkeypatch.setattr(g, "_root", lambda serial: True)
    monkeypatch.setattr(g, "_is_ours", staticmethod(lambda endpoint: False))
    monkeypatch.setattr(g, "_publish", staticmethod(lambda serial: None))
    monkeypatch.setattr(dg, "device_uids_path", lambda: str(tmp_path / "uids.json"))
    return g


def _text(*lines, proxy="10.0.2.2:8080", ip6=True):
    text = list(lines)
    if ip6:
        text.append("IP6 filter")
    text += [f"PROXY {proxy}", "PKG de.fkie.canary 10215", "rc=0"]
    return "\n".join(text)


def test_set_kill_switch_needs_a_device_proxy(guard, monkeypatch):
    device = _Device(_text(proxy=":0"))
    monkeypatch.setattr(guard, "_script", device)
    ok, msg = guard.set_kill_switch(True, SERIAL)
    assert not ok
    assert "device proxy first" in msg
    assert not guard.kill_switch_wanted(SERIAL)
    assert device.commands() == []


def test_set_kill_switch_refuses_a_hostname_proxy(guard, monkeypatch):
    monkeypatch.setattr(guard, "_script", _Device(_text(proxy="burp.local:8080")))
    ok, msg = guard.set_kill_switch(True, SERIAL)
    assert not ok
    assert "not an IP address" in msg


def test_set_kill_switch_on_installs_v4_and_v6(guard, monkeypatch):
    device = _Device(_text())
    monkeypatch.setattr(guard, "_script", device)
    ok, msg = guard.set_kill_switch(True, SERIAL)
    assert ok, msg
    cmds = device.commands()
    assert any(c.startswith("iptables -w -I OUTPUT 1") for c in cmds)
    assert any(c.startswith("ip6tables -w -I OUTPUT 1") for c in cmds)
    assert guard.kill_switch_wanted(SERIAL)
    assert guard.view_cached(SERIAL).kill_switch
    # External proxy: no app naming, the relay is not started.
    assert not any(call[0] == "relay" for call in device.calls)


def test_cleared_proxy_removes_the_kill_switch(guard, monkeypatch):
    guard._wanted[SERIAL] = dg._Wanted(kill_switch=True, endpoint=SLIRP)
    device = _Device(_text(*_ks_lines(), proxy=":0"))
    monkeypatch.setattr(guard, "_script", device)
    view = guard.after_device_proxy_write(SERIAL, None)
    assert not view.kill_switch
    assert not guard.kill_switch_wanted(SERIAL)
    assert "iptables -w -X sandroid_ks" in device.commands()


def test_kill_switch_never_outlives_its_proxy_on_reconcile(guard, monkeypatch, caplog):
    guard._wanted[SERIAL] = dg._Wanted(kill_switch=True, endpoint=SLIRP)
    device = _Device(_text(*_ks_lines(), proxy="null"))
    monkeypatch.setattr(guard, "_script", device)
    with caplog.at_level(logging.ERROR):
        guard.reconcile(SERIAL, "snapshot-load")
    assert "device proxy is gone" in caplog.text
    assert "iptables -w -F sandroid_ks" in device.commands()


def test_leftover_chain_without_proxy_is_removed(guard, monkeypatch):
    device = _Device(_text(*_ks_lines(), proxy=":0"))
    monkeypatch.setattr(guard, "_script", device)
    guard.reconcile(SERIAL, "snapshot-load")
    assert "iptables -w -X sandroid_ks" in device.commands()


def test_our_proxy_starts_the_relay_and_names_apps(guard, monkeypatch, tmp_path):
    monkeypatch.setattr(guard, "_is_ours", staticmethod(lambda endpoint: True))
    monkeypatch.setattr(guard, "_ensure_binary", staticmethod(lambda s: (True, "")))
    device = _Device(_text(proxy="127.0.0.1:8080"))
    monkeypatch.setattr(guard, "_script", device)
    view = guard.after_device_proxy_write(SERIAL, "127.0.0.1:8080")
    assert view.attribution == "on"
    assert view.named_apps == 1
    kinds = [call[0] for call in device.calls]
    # relay first, then the chain pointing at it, then the socket flush
    assert kinds.index("relay") < len(kinds) - 1
    assert kinds[-1] == "flush"
    relay = next(call for call in device.calls if call[0] == "relay")
    assert relay[3] == "127.0.0.1:8080"
    assert "10215:61000" in relay
    import json

    uids = json.loads((tmp_path / "uids.json").read_text())
    assert uids["10215"]["package"] == "de.fkie.canary"


def test_relay_that_does_not_start_leaves_flows_unnamed(guard, monkeypatch):
    monkeypatch.setattr(guard, "_is_ours", staticmethod(lambda endpoint: True))
    monkeypatch.setattr(guard, "_ensure_binary", staticmethod(lambda s: (True, "")))
    device = _Device(_text(proxy="127.0.0.1:8080"))
    device_call = device.__call__

    def no_relay(serial, *args, timeout=60.0):
        out = device_call(serial, *args, timeout=timeout)
        return "rc=0" if args[0] == "relay" else out

    monkeypatch.setattr(guard, "_script", no_relay)
    view = guard.after_device_proxy_write(SERIAL, "127.0.0.1:8080")
    assert view.attribution == "failed"
    # No REDIRECT may point at a dead relay; the ACCEPT (bug fix) stays.
    assert not any("REDIRECT" in c for c in device.commands())
    assert "iptables -w -t nat -A sandroid_dp -j ACCEPT" in device.commands()


def test_teardown_removes_everything(guard, monkeypatch):
    chain = [
        "DP -N sandroid_dp",
        "DP -A sandroid_dp -j ACCEPT",
        "RELAY pid=5 fd1=/dev/null fd2=/dev/null",
    ]
    device = _Device(_text(*_ks_lines(), *chain))
    monkeypatch.setattr(guard, "_script", device)
    guard._wanted[SERIAL] = dg._Wanted(kill_switch=True)
    assert guard.teardown(SERIAL)
    cmds = device.commands()
    assert cmds.index(
        "iptables -w -D OUTPUT -m owner --uid-owner 10000-29999 -j sandroid_ks"
    ) < cmds.index("iptables -w -t nat -X sandroid_dp")
    assert any(call[0] == "relay" and len(call) == 5 for call in device.calls)
    assert not guard.has_state(SERIAL)


def test_hook_on_clear_without_state_costs_no_adb(monkeypatch):
    monkeypatch.setattr(dg, "_INSTANCE", None)
    seen = []
    from sandroid.core.events import EventBus, EventType

    def handler(event):
        seen.append(event.data)

    EventBus.get().subscribe(EventType.STATE_CHANGED, handler)
    try:
        dg.after_device_proxy_write(None, serial=SERIAL)
    finally:
        EventBus.get().unsubscribe(EventType.STATE_CHANGED, handler)
    assert seen == [{"change_type": "device_proxy", "serial": SERIAL, "address": None}]
    assert dg._INSTANCE is None  # nothing created, nothing read
