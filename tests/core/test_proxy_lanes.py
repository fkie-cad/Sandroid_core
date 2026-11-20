"""App Proxy lanes: detached gost, reconcile against device truth, IPv6
fence, socket flush, health ("waiting for mitmproxy").

Observation lines are the shapes the lane script printed on API 35.
"""

from __future__ import annotations

import atexit
import base64
import re
import shlex
import threading
import time

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
    iproute2: the script picks the UID's ESTAB sockets and kills by port
    pair, and only when every socket that filter selects is that UID's (ss
    has no UID match; another app may share the port pair).
    """
    script = pm._LANE_SCRIPT
    flush = script[script.index("flush)") :]
    assert 'sel="( sport = :$sp and dport = :$dp )"' in flush
    assert 'ss -K -tn "$sel"' in flush
    assert '[ -z "$other" ] || continue' in flush
    assert "state established" not in flush
    assert '$1=="ESTAB"' in flush
    assert 'u="uid:$uid"' in flush


def test_observe_tells_unknown_from_uninstalled():
    """A failed ``stat`` of the data dir (CE storage locked after a boot) is
    not "uninstalled": only packages.list decides, else the UID is unknown.
    """
    script = pm._LANE_SCRIPT
    observe = script[script.index("observe)") : script.index("kill)")]
    assert "/data/system/packages.list" in observe
    assert "u=unknown" in observe
    obs = pm.parse_lane_observation(
        "UID a.b unknown\nUID c.d missing\nUID e.f 10300\nrc=0"
    )
    assert obs.uids == {"a.b": None, "c.d": None, "e.f": 10300}
    assert obs.uid_unknown == {"a.b"}


def test_unknown_uid_keeps_the_lane_with_its_last_uid():
    obs = _obs(_gost(5300), *_rules(), uid=None)
    obs.uid_unknown.add(DESIRED[0].package)
    hinted = [pm.DesiredLane(0, DESIRED[0].package, 60080, UP, uid_hint=UID)]
    (plan,), _, stale = _plan(obs, desired=hinted)
    assert not plan.app_missing
    assert plan.uid == UID
    assert (plan.kill, plan.launch, plan.add, stale) == ([], False, set(), [])
    # Without a known UID nothing at all is torn down.
    (plan,), _, stale = _plan(obs)
    assert plan.uid_unknown
    assert not plan.app_missing
    assert (plan.kill, stale) == ([], [])


# -- the device as a state machine: the fail-closed invariant -----------------------

PORTS = range(60080, 60085)
PKG = DESIRED[0].package


def _key(kind: str, spec: str):
    return pm.parse_rule_key(kind, "-A " + spec)


class _World:
    """A stateful fake device: iptables tables, gost processes, packages.

    Every adb command goes through ``__call__``; each one that changes the
    device is recorded with whether the requested app could leak before and
    after it, so a test can assert the forensic guarantee: during a repair
    no IPv4 TCP of the app goes past our REDIRECT and no IPv6 TCP past our
    REJECT (or v6 REDIRECT).
    """

    def __init__(
        self,
        *,
        uid=UID,
        ip6_nat=False,
        comment_ok=True,
        reject_ok=True,
        uid_state=None,
    ):
        self.uid = uid
        self.tables = {
            ("iptables", "nat"): [],
            ("iptables", "filter"): [],
            ("ip6tables", "filter"): [],
        }
        if ip6_nat:
            self.tables[("ip6tables", "nat")] = []
        self.comment_ok = comment_ok
        self.reject_ok = reject_ok
        self.fail_v6_redirect = False
        self.listen_fails = False
        self.uid_state = uid_state  # None = installed, "missing", "unknown"
        self.gosts: dict[int, dict] = {}
        self.next_pid = 9000
        self.events: list[tuple[str, bool, bool, bool]] = []
        self.flushes = 0
        self.targets: list[str | None] = []

    # -- state ---------------------------------------------------------------

    def rule(self, binary, table, spec):
        self.tables[(binary, table)].append(" ".join(shlex.split(spec)))

    def lane(self, uid=UID, port=60080, *, v6=True, quic=True, drop=False):
        tag = '-m comment --comment "sandroid-focus" ' if self.comment_ok else ""
        block = "DROP" if drop else "REJECT"
        self.rule(
            "iptables",
            "nat",
            f"OUTPUT -m owner --uid-owner {uid} -p tcp {tag}-j REDIRECT "
            f"--to-ports {port}",
        )
        if v6:
            self.rule(
                "ip6tables",
                "filter",
                f"OUTPUT -m owner --uid-owner {uid} -p tcp {tag}-j {block}",
            )
        if quic:
            for binary in ("iptables", "ip6tables"):
                self.rule(
                    binary,
                    "filter",
                    f"OUTPUT -m owner --uid-owner {uid} -p udp --dport 443 "
                    f"{tag}-j {block}",
                )

    def gost(self, port=60080, up=UP, fd="/dev/null", listening=True):
        pid = self.next_pid
        self.next_pid += 1
        self.gosts[pid] = {"port": port, "up": up, "fd": fd, "listen": listening}
        return pid

    def keys(self):
        out = set()
        for (binary, table), specs in self.tables.items():
            kind = ("NAT" if table == "nat" else "FILTER") + (
                "6" if binary == "ip6tables" else "4"
            )
            out |= {k for spec in specs if (k := _key(kind, spec)) is not None}
        return out

    def safe(self, uid=None) -> bool:
        """No IPv4 or IPv6 TCP of the app can leave unproxied."""
        uid = self.uid if uid is None else uid
        keys = self.keys()
        v4 = any(
            k.family == "4"
            and k.target == "REDIRECT"
            and k.uid == uid
            and k.to_port in PORTS
            for k in keys
        )
        if ("ip6tables", "nat") in self.tables:
            v6 = any(
                k.family == "6" and k.uid == uid and k.proto == "tcp" for k in keys
            )
        else:
            v6 = any(
                k.family == "6" and k.table == "filter" and k.proto == "tcp"
                and k.target == "BLOCK" and k.uid == uid
                for k in keys
            )  # fmt: skip
        return v4 and v6

    def violations(self) -> list[str]:
        """Device changes that opened a leak, or ran while one was open
        without closing it (only protective rule adds may run then).
        """
        bad = []
        for what, before, after, protective in self.events:
            if before and not after:
                bad.append(f"{what}: opened a leak")
            elif not before and not protective:
                bad.append(f"{what}: changed the device while the app leaked")
        return bad

    def mutations(self) -> list[str]:
        return [what for what, *_ in self.events]

    # -- adb -----------------------------------------------------------------

    def __call__(self, cmd, serial=None, timeout=30):
        self.targets.append(pm.Adb.get_target_device())
        if cmd in ("shell id",):
            return "uid=0(root)", ""
        inner = shlex.split(cmd)[1] if cmd.startswith("shell ") else cmd
        if cmd.startswith("push "):
            self._record("push gost", False)
            return "1 file pushed", ""
        m = re.match(r"echo (\S+) \| base64 -d \| sh -s -- ?(.*)$", inner)
        if m:
            return self._lane_op(shlex.split(m.group(2)))
        m = re.match(r"(ip6?tables)(?: -w)? (?:-t (nat) )?-S OUTPUT", inner)
        if m:
            table = m.group(2) or "filter"
            exists = (m.group(1), table) in self.tables
            return ("-P OUTPUT ACCEPT\n" if exists else ""), ""
        m = re.match(r"(ip6?tables)(?: -w)? (?:-t (nat) )?(-[IAD]) (OUTPUT .*)$", inner)
        if m:
            return self._iptables(m.group(1), m.group(2) or "filter", m.group(3), m)
        if "setsid" in inner:
            g = re.search(r"-L red://:(\d+) -F (\S+?)'", inner)
            before = self.safe()
            self.gost(int(g.group(1)), g.group(2), listening=not self.listen_fails)
            self.events.append(
                (f"launch gost :{g.group(1)}", before, self.safe(), False)
            )
            return "", ""
        m = re.match(r"kill ([\d ]+)$", inner)
        if m:
            before = self.safe()
            for pid in m.group(1).split():
                self.gosts.pop(int(pid), None)
            self.events.append((f"kill {m.group(1)}", before, self.safe(), False))
            return "", ""
        return "", ""

    def _record(self, what, protective):
        before = self.safe()
        self.events.append((what, before, before, protective))

    def _iptables(self, binary, table, op, m):
        spec = " ".join(shlex.split(m.group(4)))
        if (binary, table) not in self.tables:
            return "", f"{binary}: can't initialize table `{table}'"
        if "comment" in spec and not self.comment_ok:
            return "", "iptables: Couldn't load match `comment'"
        if "REJECT" in spec and not self.reject_ok:
            return "", "iptables: No chain/target/match by that name."
        if (
            op != "-D"
            and binary == "ip6tables"
            and table == "nat"
            and self.fail_v6_redirect
        ):
            return "", "ip6tables: No chain/target/match by that name."
        rules = self.tables[(binary, table)]
        before = self.safe()
        if op == "-D":
            if spec not in rules:
                return (
                    "",
                    "iptables: Bad rule (does a matching rule exist in that chain?).",
                )
            rules.remove(spec)
            self.events.append(
                (f"{binary} {table} -D {spec}", before, self.safe(), False)
            )
            return "", ""
        rules.insert(0, spec) if op == "-I" else rules.append(spec)
        protective = f"--uid-owner {self.uid} " in spec
        self.events.append(
            (f"{binary} {table} {op} {spec}", before, self.safe(), protective)
        )
        return "", ""

    def _lane_op(self, args):
        op = args[0]
        if op == "observe":
            out = []
            for pid, g in self.gosts.items():
                out.append(
                    f"GOST pid={pid} fd1={g['fd']} fd2={g['fd']} cmd={BIN} "
                    f"-L red://:{g['port']} -F {g['up']} "
                )
            out += [f"LISTEN *:{g['port']}" for g in self.gosts.values() if g["listen"]]
            pick = "sandroid-focus" if args[3] == "0" else "--uid-owner "
            for (binary, table), specs in self.tables.items():
                kind = ("NAT" if table == "nat" else "FILTER") + (
                    "6" if binary == "ip6tables" else "4"
                )
                if binary == "ip6tables":
                    out.append(f"IP6 {table}")
                out += [f"{kind} -A {spec}" for spec in specs if pick in spec]
            for pkg in args[4:]:
                state = self.uid_state or str(self.uid)
                out.append(f"UID {pkg} {state}")
            return "\n".join(out) + "\nrc=0\n", ""
        if op == "listening":
            port = int(args[2])
            ok = any(g["port"] == port and g["listen"] for g in self.gosts.values())
            return ("LISTENING\n" if ok else "") + "rc=0\n", ""
        if op == "kill":
            ports = {int(a) for a in args[2:]}
            before = self.safe()
            gone = [p for p, g in self.gosts.items() if g["port"] in ports]
            for pid in gone:
                del self.gosts[pid]
            if gone:
                self.events.append(
                    (f"kill ports {sorted(ports)}", before, self.safe(), False)
                )
            return "rc=0\n", ""
        if op == "flush":
            self.flushes += 1
            return "flushed=0\nrc=0\n", ""
        return "rc=0\n", ""


def _manager(monkeypatch, world, *, lanes=((0, UID),), binary_ok=True):
    monkeypatch.setattr(pm.Adb, "send_adb_command", staticmethod(world))
    monkeypatch.setattr(pm.Adb, "_target_device", SERIAL)
    monkeypatch.setattr(pm.FocusManager, "_pool_size", property(lambda self: 5))
    _mitm(monkeypatch, True)
    m = pm.FocusManager()
    atexit.unregister(m._atexit_cleanup)
    m._ca._use_su = False

    def ensure_binary():
        world._record("push gost binary", False)
        return (True, "ok") if binary_ok else (False, "push failed")

    monkeypatch.setattr(m, "_ensure_binary", ensure_binary)
    for name, value in [
        ("_write_sidecar", lambda: None),
        ("_add_to_state", lambda package: None),
        ("_remove_from_state", lambda package: None),
        ("_publish_health", lambda: None),
        ("_probe_owner_match", lambda: (True, "ok")),
        ("_cleanup_stale_locked", lambda: None),
        ("_device_tcp_reachable", lambda h, p: "reachable"),
    ]:
        monkeypatch.setattr(m, name, value)
    monkeypatch.setattr(pm, "_install_restore_hook", lambda: None)
    m._ensure_lanes()
    for lane, uid in lanes:
        m._lanes[lane] = PKG
        m._lane_targets[lane] = "ours"
        m._lane_serials[lane] = SERIAL
        m._lane_upstreams[lane] = UP
        m._lane_uids[lane] = uid
    return m


def _repair(monkeypatch, world, **kw):
    m = _manager(monkeypatch, world, **kw)
    world.events.clear()
    (report,) = m.reconcile(SERIAL, "snapshot-load")
    assert world.violations() == []
    assert world.safe(), world.tables
    return m, report


def test_invariant_missing_lane_after_a_load(monkeypatch):
    """A snapshot saved before the lane: no rules, no gost. The protective
    rules go in before anything else; the REDIRECT before gost.
    """
    world = _World()
    m, report = _repair(monkeypatch, world)
    assert report.health.state == pm.LANE_ACTIVE
    done = world.mutations()
    first_unprotective = next(i for i, (_, _, _, p) in enumerate(world.events) if not p)
    redirect = next(i for i, w in enumerate(done) if "REDIRECT" in w)
    assert redirect < first_unprotective
    assert redirect < next(i for i, w in enumerate(done) if w.startswith("launch"))
    assert world.flushes == 1


def test_invariant_dead_gost(monkeypatch):
    world = _World()
    world.lane()
    m, report = _repair(monkeypatch, world)
    assert world.events[0][1]  # safe from the start
    assert any(w.startswith("launch") for w in world.mutations())
    assert report.repaired == ["gost restarted"]
    assert report.health.ok


def test_invariant_doomed_gost(monkeypatch):
    world = _World()
    world.lane()
    doomed = world.gost(fd="socket:[119974]")
    m, report = _repair(monkeypatch, world)
    assert doomed not in world.gosts
    assert [g["fd"] for g in world.gosts.values()] == ["/dev/null"]
    assert report.health.ok


def test_invariant_gost_binary_push_fails(monkeypatch):
    world = _World()
    m, report = _repair(monkeypatch, world, binary_ok=False)
    assert report.health.state == pm.LANE_FAILED
    assert "fail closed" in report.health.detail
    assert world.gosts == {}  # nothing listens: the REDIRECT refuses


def test_invariant_gost_does_not_listen(monkeypatch):
    world = _World()
    world.listen_fails = True
    m, report = _repair(monkeypatch, world)
    assert report.health.state == pm.LANE_FAILED
    assert "did not start" in report.health.detail
    assert any(k.target == "REDIRECT" for k in world.keys())


def test_invariant_stale_rules_of_another_lane_set(monkeypatch):
    """The snapshot's lane for this app sat on another port: the new
    REDIRECT goes in before the stale one is deleted and its gost killed.
    """
    world = _World()
    world.lane(port=60081)
    old = world.gost(port=60081)
    m, report = _repair(monkeypatch, world)
    redirects = [k for k in world.keys() if k.target == "REDIRECT"]
    assert [k.to_port for k in redirects] == [60080]
    assert old not in world.gosts
    assert report.health.ok


def test_invariant_orphans_and_an_old_uid(monkeypatch):
    """Another app's lane (orphan gost, its rules) and this app's rules for
    an old UID (reinstalled) are removed only after the new rules are in.
    """
    world = _World()
    world.lane(uid=10999, port=60082)
    orphan = world.gost(port=60082)
    world.lane(uid=10100)  # the app's UID before a reinstall
    world.gost()
    m, report = _repair(monkeypatch, world)
    assert orphan not in world.gosts
    assert {k.uid for k in world.keys()} == {UID}
    assert "app UID changed" not in report.repaired  # same UID as recorded


def test_invariant_v6_redirect_fails_falls_back_to_reject(monkeypatch):
    world = _World(ip6_nat=True)
    world.fail_v6_redirect = True
    m, report = _repair(monkeypatch, world)
    assert any(
        k.family == "6" and k.target == "BLOCK" and k.proto == "tcp"
        for k in world.keys()
    )
    world.events.clear()
    m.reconcile(SERIAL, "apply")
    assert world.mutations() == []  # no re-add, no delete-then-add gap


def test_steady_state_changes_nothing(monkeypatch):
    world = _World()
    world.lane()
    world.gost()
    m, report = _repair(monkeypatch, world)
    assert world.mutations() == []
    assert world.flushes == 0


def test_untagged_rules_are_seen_and_not_readded(monkeypatch):
    """No xt_comment: rules go in untagged; later reconciles must see them
    (no re-add, no socket flush every run).
    """
    world = _World(comment_ok=False)
    m, report = _repair(monkeypatch, world)
    assert SERIAL in m._untagged_serials
    world.events.clear()
    world.flushes = 0
    m.reconcile(SERIAL, "apply")
    assert world.mutations() == []
    assert world.flushes == 0


def test_teardown_removes_drop_fallback_rules_a_snapshot_restored(monkeypatch):
    world = _World(reject_ok=False)
    world.lane(drop=True)
    world.gost()
    m, report = _repair(monkeypatch, world)
    assert world.mutations() == []
    m.disable_focus()
    assert world.keys() == set()


def test_unreadable_uid_never_tears_the_lane_down(monkeypatch):
    world = _World(uid_state="unknown")
    world.lane()
    world.gost()
    m, report = _repair(monkeypatch, world)
    assert world.mutations() == []
    assert report.health.state != pm.LANE_FAILED


def test_uninstalled_app_per_packages_list_is_torn_down(monkeypatch):
    world = _World(uid_state="missing")
    world.lane()
    world.gost()
    m = _manager(monkeypatch, world)
    (report,) = m.reconcile(SERIAL, "snapshot-load")
    assert report.health.label == "failed: app not installed"
    assert world.keys() == set()
    assert world.gosts == {}


def test_orphan_lanes_from_a_snapshot_are_swept_without_session_lanes(monkeypatch):
    world = _World()
    world.lane(uid=10999, port=60081)
    world.gost(port=60081)
    foreign = world.gost(port=1080)  # not ours: never touched
    m = _manager(monkeypatch, world, lanes=())
    assert m.sweep_orphans(SERIAL, "snapshot-load") == 5
    assert world.keys() == set()
    assert list(world.gosts) == [foreign]


def test_enable_pins_every_adb_call_to_its_serial(monkeypatch):
    world = _World()
    m = _manager(monkeypatch, world, lanes=())
    original = world.__call__

    class _Switching:
        def __call__(self, cmd, serial=None, timeout=30):
            out = original(cmd, serial, timeout)
            pm.Adb._target_device = "emulator-5554"  # user switched devices
            return out

    monkeypatch.setattr(pm.Adb, "send_adb_command", staticmethod(_Switching()))
    monkeypatch.setattr(m, "_resolve_uid", lambda package: UID)
    ok, msg = m.enable_focus(PKG)
    assert ok, msg
    assert set(world.targets) == {SERIAL}
    assert m._lane_serials[0] == SERIAL


# -- the UI thread never waits for the lock; probes run without it --------------


def test_cached_reads_never_block(fm, monkeypatch):
    _mitm(monkeypatch, True)
    assert fm.enable_focus(PKG)[0]
    assert fm.app_proxies_cached() == {PKG: "ours"}
    assert fm.lane_health_cached()[PKG].ok
    held = threading.Event()
    release = threading.Event()

    def hold():
        with fm._lock:
            held.set()
            release.wait(5)

    t = threading.Thread(target=hold)
    t.start()
    held.wait(5)
    try:
        start = time.monotonic()
        assert fm.app_proxies_cached() == {PKG: "ours"}  # last value
        assert fm.lane_health_cached()[PKG].ok
        assert time.monotonic() - start < 0.5
    finally:
        release.set()
        t.join()


def test_upstream_probe_runs_outside_the_lock_and_retries(fm, monkeypatch):
    _mitm(monkeypatch, True)
    answers = iter(["unreachable", "reachable"])
    locked = []

    def probe(host, port):
        locked.append(fm._lock.locked())
        return next(answers)

    monkeypatch.setattr(fm, "_device_tcp_reachable", probe)
    monkeypatch.setattr(fm, "_PROBE_RETRY_DELAYS", (0.0, 0.0))
    ok, msg = fm.enable_focus(PKG)
    assert ok, msg
    assert locked == [False, False]
    assert fm.lane_health()[PKG].ok


def test_unreachable_before_the_last_mitmproxy_start_is_stale(fm, monkeypatch):
    _mitm(monkeypatch, True)
    monkeypatch.setattr(fm, "_device_tcp_reachable", lambda h, p: "unreachable")
    monkeypatch.setattr(fm, "_PROBE_RETRY_DELAYS", ())
    ok, msg = fm.enable_focus(PKG)
    assert fm.lane_health()[PKG].state == pm.LANE_UNREACHABLE
    assert "host_ip_override" not in msg
    monkeypatch.setattr(pm, "_MITMPROXY_STARTED_AT", 0.0)
    pm.note_mitmproxy_started()
    assert fm.lane_health()[PKG].ok


# -- routine lane events are not WARNINGs; removal tells the UI ----------------------


def _logging_adb(monkeypatch, world):
    """Route the fake device through the real adb result logging."""
    from sandroid.core.adb_utils import log_adb_result

    def send(cmd, serial=None, timeout=30):
        out, err = world(cmd, serial, timeout)
        log_adb_result(cmd, out, err)
        return out, err

    monkeypatch.setattr(pm.Adb, "send_adb_command", staticmethod(send))


def test_lane_add_and_remove_log_no_warning_and_publish(monkeypatch, caplog):
    """E2E: "App proxy lane 0 → ..." and the ip6tables "No chain/target/
    match" of a delete-before-add / an absent rule were WARNINGs, and the
    Network caption kept "app proxies 1" after the App Proxy was removed.
    """
    world = _World()
    m = _manager(monkeypatch, world, lanes=())
    monkeypatch.setattr(m, "_resolve_uid", lambda package: UID)
    published = []
    monkeypatch.setattr(m, "_publish_health", lambda: published.append(1))
    _logging_adb(monkeypatch, world)
    with caplog.at_level("DEBUG"):
        ok, msg = m.enable_focus(PKG)
        assert ok, msg
        assert published == [1]
        assert m.disable_focus(PKG)[0]
    assert published == [1, 1]
    assert world.keys() == set()
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert warnings == []
    lane = [r for r in caplog.records if "App proxy lane 0" in r.getMessage()]
    assert [r.levelname for r in lane] == ["INFO"]
    assert any("rule absent" in r.getMessage() for r in caplog.records)


def test_a_real_rule_removal_failure_stays_a_warning(monkeypatch, caplog):
    world = _World()
    m = _manager(monkeypatch, world, lanes=())

    def offline(cmd, serial=None, timeout=30):
        return "", "error: device offline"

    monkeypatch.setattr(pm.Adb, "send_adb_command", staticmethod(offline))
    with caplog.at_level("DEBUG"):
        m._delete_rule_loop("ip6tables", "{op} OUTPUT -p tcp -j REJECT")
    assert any(
        r.levelname == "WARNING" and "device offline" in r.getMessage()
        for r in caplog.records
    )


def test_releasing_a_serial_publishes_the_lane_change(monkeypatch):
    world = _World()
    world.lane()
    world.gost()
    m = _manager(monkeypatch, world)
    published = []
    monkeypatch.setattr(m, "_publish_health", lambda: published.append(1))
    assert m.release_serial(SERIAL) == 1
    assert published == [1]
    assert m.release_serial(SERIAL) == 0
    assert published == [1]
