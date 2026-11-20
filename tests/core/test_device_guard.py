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
    # N7: delete the misplaced jump FIRST. ``-D <spec>`` removes the first
    # match: after an insert at 1 that would be the new rule.
    assert cmds[0].startswith("iptables -w -t nat -D OUTPUT -d 127.0.0.1/32")
    assert cmds[1].startswith("iptables -w -t nat -I OUTPUT 1 -d 127.0.0.1/32")
    assert len(cmds) == 2
    # Played against a model of iptables: the jump ends up first, once.
    rules = [line[len("NATOUT ") :] for line in (lane, ours)]
    for cmd in cmds:
        if " -D " in cmd:
            rules.remove("-A " + cmd.split(" -D ", 1)[1])  # the first match
        else:
            rest = cmd.split(" -I ", 1)[1]  # "OUTPUT 1 <spec>"
            rules.insert(0, "-A OUTPUT " + rest.split(" ", 2)[2])
    assert rules == [line[len("NATOUT ") :] for line in (ours, lane)]
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
            "dev5570",
            "s3cr3t",
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
    # N4/N5: the identity carries the device token, the password is the
    # session secret, and the file is readable by its owner only.
    assert 'username: "uid10146-dev5570"' in text
    assert text.count('password: "s3cr3t"') == 2
    assert text.count("addr: 127.0.0.1:8080") == 2
    assert (cfg.stat().st_mode & 0o777) == 0o600


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
    assert relay[5] == dg.device_token(SERIAL)
    assert relay[6] == dg.relay_secret()
    assert "10215:61000" in relay
    import json

    uids = json.loads((tmp_path / "uids.json").read_text())
    entry = uids["devices"][dg.device_token(SERIAL)]
    assert entry["uids"]["10215"] == "de.fkie.canary"
    assert entry["secret"] == dg.relay_secret()
    assert entry["serial"] == SERIAL


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
    assert any(call[0] == "relay" and len(call) == 7 for call in device.calls)
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


# -- review fixes (NETMETHOD-FIX-LIST) ---------------------------------------------


def _healthy_naming(uid=10215, port=61000, endpoint="10.0.2.2:8080"):
    """Observation lines of a working app naming for one UID."""
    ip, _, dport = endpoint.partition(":")
    return [
        "RELAY pid=77 fd1=/dev/null fd2=/dev/null",
        f"LISTEN {port}",
        "DP -N sandroid_dp",
        f"DP -A sandroid_dp -p tcp -m owner --uid-owner {uid} -j REDIRECT "
        f"--to-ports {port}",
        "DP -A sandroid_dp -j ACCEPT",
        f"NATOUT -A OUTPUT -d {ip}/32 -p tcp -m tcp --dport {dport} -j sandroid_dp",
        "RL -N sandroid_rl",
        f"RL -A sandroid_rl -p tcp -m tcp --dport {port} -m owner ! --uid-owner "
        f"{uid} -j REJECT --reject-with tcp-reset",
        "RLJUMP -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport 61000:64999 "
        "-j sandroid_rl",
    ]


def test_relay_lock_reserves_each_port_for_its_uid():
    """N4: after its own REDIRECT an app reaches its relay port; any other UID
    connecting straight to that port is refused (filter sees the post-NAT
    destination). The lock goes away with the naming.
    """
    obs = _obs()
    cmds = dg.plan_relay_lock({10215: 61000, 10146: 61001}, obs)
    assert cmds[0] == "iptables -w -N sandroid_rl"
    rule = next(c for c in cmds if "--dport 61000 " in c)
    assert rule.startswith(
        "iptables -w -A sandroid_rl -p tcp -m tcp --dport 61000 -m owner ! "
        "--uid-owner 10215 -j REJECT --reject-with tcp-reset"
    )
    assert rule.endswith("-j DROP")  # REJECT falls back to DROP
    assert cmds[-1] == (
        "iptables -w -I OUTPUT 1 -d 127.0.0.1/32 -p tcp -m tcp --dport 61000:64999 "
        "-j sandroid_rl"
    )
    healthy = _obs(*_healthy_naming())
    assert dg.plan_relay_lock({10215: 61000}, healthy) == []
    assert dg.relay_lock_ok(healthy, {10215: 61000})
    assert not dg.relay_lock_ok(healthy, {10215: 61000, 10146: 61001})
    cmds = dg.plan_relay_lock({}, healthy)
    assert cmds[0].startswith("iptables -w -D OUTPUT -d 127.0.0.1/32")
    assert cmds[-2:] == ["iptables -w -F sandroid_rl", "iptables -w -X sandroid_rl"]


def test_relay_identity_changes_with_the_session_secret():
    """N4: a relay from an earlier session (other secret) is not "healthy":
    it is restarted with this session's secret.
    """
    ports = {10215: 61000}
    assert dg.relay_tag(ports, "10.0.2.2:8080", "dev:a") != dg.relay_tag(
        ports, "10.0.2.2:8080", "dev:b"
    )
    assert len(dg.relay_secret()) == 32
    assert dg.relay_secret() == dg.relay_secret()


def test_uid_map_is_keyed_by_device(guard, tmp_path):
    """N5: two devices on one Mitmproxy keep their own UID -> package map."""
    import json

    dg.write_device_uids("emulator-5570", {10215: ["de.fkie.canary"]})
    dg.write_device_uids("emulator-5572", {10215: ["com.other"]})
    data = json.loads((tmp_path / "uids.json").read_text())
    a = data["devices"][dg.device_token("emulator-5570")]
    b = data["devices"][dg.device_token("emulator-5572")]
    assert (a["uids"]["10215"], b["uids"]["10215"]) == ("de.fkie.canary", "com.other")
    assert a["serial"] == "emulator-5570"
    assert dg.device_token("emulator-5570") != dg.device_token("emulator-5572")
    assert ((tmp_path / "uids.json").stat().st_mode & 0o777) == 0o600
    # Rewriting one device keeps the other.
    dg.write_device_uids("emulator-5570", {10300: ["x.y"]})
    data = json.loads((tmp_path / "uids.json").read_text())
    assert data["devices"][dg.device_token("emulator-5572")]["uids"] == {
        "10215": "com.other"
    }


def test_kill_switch_covers_every_android_user():
    """N13: apps of a work profile / second user (UID 1010000+) are covered."""
    obs = _obs("USER 0", "USER 10")
    cmds = dg.plan_kill_switch(True, SLIRP, obs, "4")
    jumps = [c for c in cmds if "-I OUTPUT 1" in c]
    assert jumps == [
        "iptables -w -I OUTPUT 1 -m owner --uid-owner 10000-29999 -j sandroid_ks",
        "iptables -w -I OUTPUT 1 -m owner --uid-owner 1010000-1029999 -j sandroid_ks",
    ]
    # Installed for both users: nothing to do; a missing user's jump: rebuild.
    both = _obs(
        *_ks_lines(),
        "JUMP4 -A OUTPUT -m owner --uid-owner 1010000-1029999 -j sandroid_ks",
        "USER 0",
        "USER 10",
        ip6=False,
    )
    assert dg.plan_kill_switch(True, SLIRP, both, "4") == []
    only_zero = _obs(*_ks_lines(), "USER 0", "USER 10", ip6=False)
    assert dg.plan_kill_switch(True, SLIRP, only_zero, "4") != []


def test_failed_kill_switch_removal_is_reported(guard, monkeypatch):
    """N12: a removal the device refused is "still on", and stays installed
    so a later clear retries it.
    """
    device = _Device(_text(*_ks_lines(), ip6=False))

    def script(serial, *args, timeout=60.0):
        out = device(serial, *args, timeout=timeout)
        if args[0] == "run":
            return "FAIL iptables -w -D OUTPUT :: busy\nrc=0"
        return out

    monkeypatch.setattr(guard, "_script", script)
    guard._wanted[SERIAL] = dg._Wanted(kill_switch=True, endpoint=SLIRP)
    ok, msg = guard.set_kill_switch(False, SERIAL)
    assert not ok
    assert "could not be removed" in msg
    view = guard.view_cached(SERIAL)
    assert view.kill_switch
    assert view.installed
    assert guard.has_state(SERIAL)


def test_kill_switch_without_ip6tables_says_ipv4_only(guard, monkeypatch):
    """N12: no ip6tables: the Kill switch is on for IPv4 and says so."""
    monkeypatch.setattr(guard, "_script", _Device(_text(ip6=False)))
    ok, msg = guard.set_kill_switch(True, SERIAL)
    assert ok
    assert "IPv4 only" in msg
    assert not guard.view_cached(SERIAL).ipv6


def _naming_guard(guard, monkeypatch, observe):
    monkeypatch.setattr(guard, "_ensure_binary", staticmethod(lambda s: (True, "")))
    device = _Device(observe)
    monkeypatch.setattr(guard, "_script", device)
    guard._named_for[SERIAL] = SLIRP
    return device


def test_refresh_repairs_a_dead_relay(guard, monkeypatch):
    """N3: the relay died: REDIRECTs point at dead ports (proxy connections
    fail; without the Kill switch apps go direct). The refresh says so and
    relaunches it (detached), at most once per backoff.
    """
    lines = [x for x in _healthy_naming() if not x.startswith(("RELAY", "LISTEN"))]
    device = _naming_guard(guard, monkeypatch, _text(*lines))
    view = guard.refresh(SERIAL)  # read only
    assert view.attribution == "failed"
    assert "relay down" in view.detail
    assert not any(call[0] == "relay" for call in device.calls)
    guard.refresh(SERIAL, repair=True)
    assert [call[0] for call in device.calls].count("relay") == 1
    guard.refresh(SERIAL, repair=True)  # within the backoff: no second restart
    assert [call[0] for call in device.calls].count("relay") == 1


def test_refresh_names_apps_installed_later(guard, monkeypatch):
    """N3: an app installed after "Whole device" is not named yet: the line
    must not say "apps named", and the repair adds it (packages.list is
    re-read on the refresh).
    """
    text = _text(*_healthy_naming()).replace("rc=0", "PKG com.new.sample 10400\nrc=0")
    device = _naming_guard(guard, monkeypatch, text)
    view = guard.refresh(SERIAL)  # the fake device always lists the packages
    assert view.attribution == "partial"
    assert view.unnamed_apps == 1
    guard.refresh(SERIAL, repair=True)
    assert any("--uid-owner 10400 -j REDIRECT" in c for c in device.commands())
    assert any("! --uid-owner 10400 -j REJECT" in c for c in device.commands())


def test_refresh_needs_the_nat_jump_for_apps_named(guard, monkeypatch):
    """N21: with the sandroid_dp jump gone flows are unnamed: the refresh
    must not say "apps named", and the repair puts the jump back.
    """
    lines = [x for x in _healthy_naming() if not x.startswith("NATOUT")]
    device = _naming_guard(guard, monkeypatch, _text(*lines))
    assert guard.refresh(SERIAL).attribution == "failed"
    guard.refresh(SERIAL, repair=True)
    assert any(
        c.startswith("iptables -w -t nat -I OUTPUT 1 -d 10.0.2.2/32")
        for c in device.commands()
    )


def test_relay_restart_waits_for_the_old_process(tmp_path):
    """N3: a still-running OLD relay (same config path) must never count as
    the new one listening; the old one is killed before the new one starts.
    """
    import shutil
    import subprocess

    if shutil.which("sh") is None:
        pytest.skip("no sh")
    proc = tmp_path / "proc"
    (proc / "111").mkdir(parents=True)
    (proc / "111" / "cmdline").write_bytes(b"relaybin\0-C\0CFG\0")
    stubs = f"""
pidof() {{ ls {proc}; }}
kill() {{ echo "kill $*" >> {tmp_path}/kills; }}
ss() {{
  echo "State Recv-Q Send-Q Local Peer"
  echo "LISTEN 0 0 127.0.0.1:61000 0.0.0.0:* users:((\\"relaybin\\",pid=111,fd=3))"
}}
setsid() {{ :; }}
"""
    script = stubs + dg._GUARD_SCRIPT.replace("/proc/", f"{proc}/").replace(
        "sleep 0.1", ":"
    )
    out = subprocess.run(
        [
            "sh",
            "-s",
            "--",
            "relay",
            "/x/relaybin",
            "CFG",
            "10.0.2.2:8080",
            "TAG",
            "dev",
            "sec",
            "10215:61000",
        ],
        input=script,
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
    )
    assert "rc=" in out.stdout, out.stderr
    out = out.stdout
    kills = (tmp_path / "kills").read_text()
    assert "kill 111" in kills
    assert "kill -9 111" in kills  # it did not go on SIGTERM
    # The old relay still holds the port and no new one came up: not ready.
    assert "LISTENING" not in out


def test_teardown_never_holds_the_lock_across_adb(guard, monkeypatch):
    """N10: quit's teardown frees the guard lock before its adb work; with a
    busy lock and a timeout it skips instead of blocking.
    """
    import threading

    seen = []

    def script(serial, *args, timeout=60.0):
        # From another thread the lock must be free during the adb call.
        def probe():
            got = guard._lock.acquire(timeout=0.5)
            seen.append(got)
            if got:
                guard._lock.release()

        t = threading.Thread(target=probe)
        t.start()
        t.join()
        return _text(*_ks_lines()) if args[0] == "observe" else "rc=0"

    monkeypatch.setattr(guard, "_script", script)
    guard._wanted[SERIAL] = dg._Wanted(kill_switch=True)
    assert guard.teardown(SERIAL)
    assert seen
    assert all(seen)
    # A guard busy elsewhere: skipped after the timeout, never blocking.
    holder = threading.Event()
    release = threading.Event()

    def hold():
        with guard._lock:
            holder.set()
            release.wait(5)

    t = threading.Thread(target=hold)
    t.start()
    holder.wait(5)
    try:
        assert guard.teardown(SERIAL, lock_timeout=0.05) is False
    finally:
        release.set()
        t.join()


def test_guard_pins_every_device_call_to_its_serial(guard, monkeypatch):
    """N14: the restore and the Proxy dialog's Kill switch path run on a
    worker without a pin; the guard pins its serial itself (the "ours"
    classification reads adb reverse of THAT device).
    """
    seen = []

    def is_ours(endpoint):
        seen.append(dg.Adb.get_target_device())
        return False

    monkeypatch.setattr(guard, "_is_ours", staticmethod(is_ours))
    monkeypatch.setattr(guard, "_script", _Device(_text()))
    monkeypatch.setattr(dg.Adb, "_target_device", "emulator-5554")
    guard.set_kill_switch(True, SERIAL)
    guard.reconcile(SERIAL, "reconnect")
    assert seen
    assert set(seen) == {SERIAL}


def test_restore_keeps_ours_for_the_prepared_endpoint(guard, monkeypatch):
    """N15: the restore prepares the guard, then sets the proxy: that write
    must not drop "ours" (127.0.0.1 without its reverse yet reads as someone
    else's) and stop the relay for a moment.
    """
    monkeypatch.setattr(guard, "_ensure_binary", staticmethod(lambda s: (True, "")))
    device = _Device(_text(proxy="127.0.0.1:8080"))
    monkeypatch.setattr(guard, "_script", device)
    guard.prepare(SERIAL, LOOP, kill_switch=True, ours=True)
    before = [call[0] for call in device.calls].count("relay")
    view = guard.after_device_proxy_write(SERIAL, "127.0.0.1:8080")
    assert view.attribution == "on"
    stops = [c for c in device.calls if c[0] == "relay" and len(c) == 7]
    assert stops == []  # the relay was never stopped
    assert [call[0] for call in device.calls].count("relay") >= before
    # Another endpoint written by hand: no longer assumed ours.
    guard.after_device_proxy_write(SERIAL, "10.0.2.2:9999")
    assert not guard._wanted[SERIAL].ours


def test_new_android_user_is_covered_by_the_repair(guard, monkeypatch):
    """B2: a user created after the Kill switch went on is seen on the
    refresh (users re-read) and its jump is added.
    """
    device = _Device(_text(*_ks_lines(), "USER 0", "USER 11", ip6=False))
    monkeypatch.setattr(guard, "_script", device)
    guard._wanted[SERIAL] = dg._Wanted(kill_switch=True, endpoint=SLIRP)
    view = guard.refresh(SERIAL)
    assert view.uncovered_users == (11,)
    guard.refresh(SERIAL, repair=True)
    assert any("--uid-owner 1110000-1129999" in c for c in device.commands())


def test_naming_problem_tells_dead_relay_from_missing_jump(guard, monkeypatch):
    """B4: the real effect, not only "apps not named"."""
    no_relay = [x for x in _healthy_naming() if not x.startswith(("RELAY", "LISTEN"))]
    _naming_guard(guard, monkeypatch, _text(*no_relay))
    assert guard.refresh(SERIAL).naming_problem == "relay_down"
    no_jump = [x for x in _healthy_naming() if not x.startswith("NATOUT")]
    _naming_guard(guard, monkeypatch, _text(*no_jump))
    assert guard.refresh(SERIAL).naming_problem == "jump_missing"
