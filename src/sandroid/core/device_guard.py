"""Device-proxy guard: the Kill switch and per-app naming of device-proxy flows.

Two pieces of device state follow the device proxy Sandroid set:

* **Kill switch** (filter table, IPv4 and IPv6): while on, app UIDs
  (10000-19999 and the SDK sandbox 20000-29999) may reach only loopback
  (``-d 127.0.0.0/8``, never ``-o lo``: after a nat REDIRECT the filter
  table still sees the old out-interface) and the device proxy's endpoint.
  Everything else is refused (REJECT), so a proxy-aware app that falls back
  to a direct connection, or a proxy-unaware app, cannot leak. adb, DNS and
  system/shell UIDs are untouched. The kernel has no ``-j LOG``: refused
  traffic is counted with the REJECT rules' packet counters.
* **Proxy-port chain** (nat table, ``sandroid_dp``, jumped from nat OUTPUT
  at position 1 for traffic to the device proxy's endpoint): per-UID
  REDIRECTs to the on-device **identity relay** (one detached gost with one
  ``http`` listener per app UID, chaining to the device proxy with proxy
  auth ``uid<U>``; the Mitmproxy addon maps the UID to the package), then
  ``ACCEPT``. The final ACCEPT also keeps App Proxy lane REDIRECTs (appended
  to nat OUTPUT) from catching an app's own connection to the device proxy:
  Mitmproxy refused to connect to itself and the flow was lost.

The device state is read in ONE adb call (:func:`parse_guard_observation`),
diffed against what is wanted by pure planners (:func:`plan_kill_switch`,
:func:`plan_proxy_chain`) and repaired in one more call. Kill-switch changes
are double-buffered (two chain names): a new chain is filled first, the jump
moves to it, then the old one goes, so there is never an open window. A
kill-switch chain never outlives its device proxy: every write of the device
proxy goes through :func:`after_device_proxy_write`, and a reconcile that
finds no device proxy removes the chain.

Everything blocking (adb) runs on worker threads; the UI reads
:meth:`DeviceGuard.view_cached` and :meth:`DeviceGuard.kill_switch_wanted`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import tempfile
import threading
from dataclasses import dataclass, field, replace
from pathlib import Path

from sandroid.core.adb import Adb

logger = logging.getLogger(__name__)

#: Kill-switch chains (filter table, v4 and v6), double-buffered.
KS_CHAINS = ("sandroid_ks", "sandroid_ks2")
#: Proxy-port chain (nat table, v4).
DP_CHAIN = "sandroid_dp"
#: App UIDs: user-0 apps plus the SDK sandbox (Android 13+).
APP_UID_RANGE = "10000-29999"
#: App UIDs that get a relay identity (user-0 apps).
_APP_UID_MIN, _APP_UID_MAX = 10000, 19999
#: First device port of the identity relay listeners (127.0.0.1 only).
RELAY_BASE = 61000
#: Relay ports available (61000-64999).
RELAY_SPAN = 4000
#: Relay config on the device; the relay gost is matched by ``-C <path>``.
RELAY_CONFIG = "/data/local/tmp/sandroid-relay.yaml"

#: Sentinel: "the serial adb currently targets".
CURRENT = object()


# ---------------------------------------------------------------------------
# Device script
# ---------------------------------------------------------------------------

#: One ``adb shell`` per operation (base64-piped, see ``run_device_script``);
#: the last output line is ``rc=<n>``.
#:
#:   observe <binary> <cfg> <lo> <hi> <uids 0|1>
#:                       relay gost (pid, stdio), relay listeners, config tag,
#:                       both kill-switch chains and their jumps (v4/v6),
#:                       refused counters, the proxy-port chain and nat
#:                       OUTPUT, the device proxy, packages.list (uids=1)
#:   run <cmd> ...       eval each command; failures print ``FAIL``
#:   relay <binary> <cfg> <upstream> <tag> [uid:port ...]
#:                       kill the relay, write its config, launch it detached
#:                       (setsid, stdio /dev/null), wait <=4 s for the last
#:                       port; no uid:port = stop it and remove the config
#:   flush <ip> <port>   drop established sockets to the proxy endpoint
_GUARD_SCRIPT = r"""
op=$1
[ $# -gt 0 ] && shift
relay_pids() {
  for p in $(pidof "$1" 2>/dev/null); do
    tr '\0' ' ' </proc/$p/cmdline 2>/dev/null | grep -q -- "-C $2" && echo $p
  done
}
listeners() { (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | awk 'NR>1 {print $4}'; }
case "$op" in
observe)
  name=${1##*/}; cfg=$2; lo=$3; hi=$4; uids=$5
  for p in $(relay_pids "$name" "$cfg"); do
    echo "RELAY pid=$p fd1=$(readlink /proc/$p/fd/1) fd2=$(readlink /proc/$p/fd/2)"
  done
  listeners | awk -F: -v lo="$lo" -v hi="$hi" '{ p=$NF+0; if (p>=lo && p<=hi) print "LISTEN " p }'
  [ -r "$cfg" ] && echo "CFG $(head -n 1 "$cfg")"
  for c in sandroid_ks sandroid_ks2; do
    iptables -w -S $c 2>/dev/null | sed 's/^/KS4 /'
  done
  iptables -w -S OUTPUT 2>/dev/null | grep -- '-j sandroid_ks' | sed 's/^/JUMP4 /'
  for c in sandroid_ks sandroid_ks2; do
    iptables -w -L $c -nvx 2>/dev/null | awk '$3=="REJECT" || $3=="DROP" {s+=$1} END {print "CNT4 " s+0}'
  done
  if ip6tables -w -S OUTPUT >/dev/null 2>&1; then
    echo "IP6 filter"
    for c in sandroid_ks sandroid_ks2; do
      ip6tables -w -S $c 2>/dev/null | sed 's/^/KS6 /'
    done
    ip6tables -w -S OUTPUT 2>/dev/null | grep -- '-j sandroid_ks' | sed 's/^/JUMP6 /'
    for c in sandroid_ks sandroid_ks2; do
      ip6tables -w -L $c -nvx 2>/dev/null | awk '$3=="REJECT" || $3=="DROP" {s+=$1} END {print "CNT6 " s+0}'
    done
  fi
  iptables -w -t nat -S sandroid_dp 2>/dev/null | sed 's/^/DP /'
  iptables -w -t nat -S OUTPUT 2>/dev/null | grep -- '^-A ' | sed 's/^/NATOUT /'
  echo "PROXY $(settings get global http_proxy 2>/dev/null)"
  if [ "$uids" = 1 ]; then
    if [ -r /data/system/packages.list ]; then
      awk '{print "PKG " $1 " " $2}' /data/system/packages.list
    else
      echo "PKGS unreadable"
    fi
  fi
  true
  ;;
run)
  for c in "$@"; do
    out=$(eval "$c" 2>&1) || echo "FAIL $c :: $(echo "$out" | tr '\n' ' ')"
  done
  true
  ;;
relay)
  bin=$1; cfg=$2; up=$3; tag=$4; shift 4
  name=${bin##*/}
  for p in $(relay_pids "$name" "$cfg"); do kill $p 2>/dev/null && echo "killed=$p"; done
  if [ $# -eq 0 ]; then
    rm -f "$cfg"
  else
    {
      echo "# $tag"
      echo "services:"
      for e in "$@"; do
        u=${e%%:*}; p=${e##*:}
        echo "- name: s$u"
        echo "  addr: 127.0.0.1:$p"
        echo "  handler:"
        echo "    type: http"
        echo "    chain: c$u"
        echo "  listener:"
        echo "    type: tcp"
      done
      echo "chains:"
      for e in "$@"; do
        u=${e%%:*}
        echo "- name: c$u"
        echo "  hops:"
        echo "  - name: h$u"
        echo "    nodes:"
        echo "    - name: n$u"
        echo "      addr: $up"
        echo "      connector:"
        echo "        type: http"
        echo "        auth:"
        echo "          username: uid$u"
        echo "          password: x"
        echo "      dialer:"
        echo "        type: tcp"
      done
    } > "$cfg.tmp" && mv -f "$cfg.tmp" "$cfg"
    setsid sh -c "exec $bin -C $cfg" </dev/null >/dev/null 2>&1 &
    for e in "$@"; do last=${e##*:}; done
    i=0
    while [ $i -lt 40 ]; do
      if [ -n "$(relay_pids "$name" "$cfg")" ] && listeners | grep -q "[:.]$last\$"; then
        echo LISTENING; break
      fi
      sleep 0.1; i=$((i+1))
    done
  fi
  true
  ;;
flush)
  ss -K -tn dst "$1" dport = :"$2" >/dev/null 2>&1
  echo flushed
  ;;
*) echo "usage: observe|run|relay|flush"; false ;;
esac
echo "rc=$?"
"""


# ---------------------------------------------------------------------------
# Pure model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Endpoint:
    """The device proxy's host:port as the device sees it."""

    ip: str
    port: int

    @classmethod
    def parse(cls, address: str | None) -> Endpoint | None:
        """``"ip:port"`` (as ``settings get global http_proxy`` prints it)."""
        text = (address or "").strip()
        if not text or text in (":0", "null") or ":" not in text:
            return None
        host, _, port = text.rpartition(":")
        if not port.isdigit() or int(port) <= 0 or not host:
            return None
        return cls(host, int(port))

    @property
    def address(self) -> str:
        return f"{self.ip}:{self.port}"

    @property
    def is_ipv4(self) -> bool:
        try:
            return isinstance(ipaddress.ip_address(self.ip), ipaddress.IPv4Address)
        except ValueError:
            return False

    @property
    def loopback(self) -> bool:
        """Reached through loopback (``adb reverse``): covered by 127.0.0.0/8."""
        try:
            return ipaddress.ip_address(self.ip).is_loopback
        except ValueError:
            return False


@dataclass(frozen=True)
class KsRule:
    """One kill-switch rule, normalised (``iptables -S`` or our own spec)."""

    dst: str = ""
    proto: str = ""
    dport: int | None = None
    target: str = "REJECT"  # RETURN | REJECT (a DROP fallback counts as REJECT)


def desired_ks_rules(endpoint: Endpoint | None, family: str) -> list[KsRule]:
    """The kill-switch chain for *family* (``"4"``/``"6"``), in order (pure).

    Loopback first (the device proxy via ``adb reverse``, App Proxy lanes and
    the identity relay after their REDIRECT), then a non-loopback IPv4
    endpoint (``10.0.2.2``, a LAN host, an external proxy), then REJECT: TCP
    with a reset (fast failure instead of a timeout), everything else.
    """
    rules = [KsRule("127.0.0.0/8" if family == "4" else "::1/128", "", None, "RETURN")]
    if (
        family == "4"
        and endpoint is not None
        and endpoint.is_ipv4
        and not endpoint.loopback
    ):
        rules.append(KsRule(f"{endpoint.ip}/32", "tcp", endpoint.port, "RETURN"))
    rules.append(KsRule("", "tcp", None, "REJECT"))
    rules.append(KsRule("", "", None, "REJECT"))
    return rules


def parse_ks_rule(line: str) -> tuple[str, KsRule] | None:
    """``-A <chain> ...`` of a kill-switch chain -> (chain, rule); else None."""
    m = re.match(r"-A (\S+) (.*)$", line.strip())
    if not m or m.group(1) not in KS_CHAINS:
        return None
    rest = m.group(2)
    dst = re.search(r"-d (\S+)", rest)
    proto = re.search(r"-p (\w+)", rest)
    dport = re.search(r"--dport (\d+)", rest)
    target = re.search(r"-j (\w+)", rest)
    if not target:
        return None
    jump = target.group(1)
    return m.group(1), KsRule(
        dst=dst.group(1) if dst else "",
        proto=proto.group(1) if proto else "",
        dport=int(dport.group(1)) if dport else None,
        target="RETURN" if jump == "RETURN" else "REJECT",
    )


def ks_rule_command(tbl: str, chain: str, rule: KsRule, family: str) -> str:
    """The ``iptables -A`` command for one rule (REJECT falls back to DROP)."""
    parts = []
    if rule.dst:
        parts.append(f"-d {rule.dst}")
    if rule.proto:
        parts.append(f"-p {rule.proto}")
        if rule.dport is not None:
            parts.append(f"-m {rule.proto} --dport {rule.dport}")
    spec = " ".join(parts)
    head = f"{tbl} -w -A {chain}" + (f" {spec}" if spec else "")
    if rule.target == "RETURN":
        return f"{head} -j RETURN"
    if rule.proto == "tcp":
        return f"{head} -j REJECT --reject-with tcp-reset || {head} -j DROP"
    return f"{head} -j REJECT || {head} -j DROP"


def ks_jump(chain: str) -> str:
    """The OUTPUT jump spec (without the ``-A``/``-I`` op) to a ks chain."""
    return f"OUTPUT -m owner --uid-owner {APP_UID_RANGE} -j {chain}"


@dataclass
class GuardObservation:
    """Device truth for the guard of one serial (one adb read)."""

    relays: list[tuple[int, bool]] = field(default_factory=list)  # (pid, doomed)
    listening: set[int] = field(default_factory=set)
    config_tag: str = ""
    #: family -> chain -> rules (in order); a chain present with no rule is [].
    ks: dict[str, dict[str, list[KsRule]]] = field(
        default_factory=lambda: {"4": {}, "6": {}}
    )
    #: family -> raw ``-A OUTPUT ... -j sandroid_ks*`` jump lines.
    jumps: dict[str, list[str]] = field(default_factory=lambda: {"4": [], "6": []})
    refused: dict[str, int] = field(default_factory=lambda: {"4": 0, "6": 0})
    ip6_filter: bool = False
    #: The nat chain exists.
    dp_exists: bool = False
    #: uid -> relay port of the chain's REDIRECTs (in order of appearance).
    dp_uids: dict[int, int] = field(default_factory=dict)
    dp_accept: bool = False
    #: Raw rule lines of the nat chain (``-A sandroid_dp ...``).
    dp_lines: list[str] = field(default_factory=list)
    #: nat OUTPUT ``-A`` lines, in order.
    nat_output: list[str] = field(default_factory=list)
    proxy: Endpoint | None = None
    proxy_raw: str = ""
    #: package -> uid (packages.list); None = not asked / unreadable.
    packages: dict[str, int] | None = None

    @property
    def relay_running(self) -> bool:
        return any(not doomed for _pid, doomed in self.relays)

    def active_ks(self, family: str) -> str | None:
        """The kill-switch chain OUTPUT jumps to (first jump), else None."""
        for line in self.jumps.get(family, []):
            m = re.search(r"-j (sandroid_ks2?)\b", line)
            if m:
                return m.group(1)
        return None

    @property
    def kill_switch_on(self) -> bool:
        return self.active_ks("4") is not None

    def dp_jumps(self) -> list[str]:
        return [
            line for line in self.nat_output if re.search(r"-j sandroid_dp\b", line)
        ]


def parse_guard_observation(output: str) -> GuardObservation:
    """Parse the guard script's ``observe`` output (pure; never raises)."""
    obs = GuardObservation()
    cnt_seen = {"4": 0, "6": 0}
    for raw in (output or "").splitlines():
        line = raw.strip()
        kind, _, rest = line.partition(" ")
        rest = rest.strip()
        if kind == "RELAY":
            m = re.match(r"pid=(\d+) fd1=(\S*) fd2=(\S*)", rest)
            if m:
                doomed = any(
                    fd.startswith(("socket:", "pipe:", "/dev/pts"))
                    for fd in (m.group(2), m.group(3))
                )
                obs.relays.append((int(m.group(1)), doomed))
        elif kind == "LISTEN":
            if rest.isdigit():
                obs.listening.add(int(rest))
        elif kind == "CFG":
            obs.config_tag = rest.lstrip("# ").strip()
        elif kind in ("KS4", "KS6"):
            family = kind[-1]
            m = re.match(r"-N (\S+)$", rest)
            if m and m.group(1) in KS_CHAINS:
                obs.ks[family].setdefault(m.group(1), [])
                continue
            parsed = parse_ks_rule(rest)
            if parsed is not None:
                obs.ks[family].setdefault(parsed[0], []).append(parsed[1])
        elif kind in ("JUMP4", "JUMP6"):
            if rest.startswith("-A "):
                obs.jumps[kind[-1]].append(rest)
        elif kind in ("CNT4", "CNT6"):
            family = kind[-1]
            if rest.isdigit():
                cnt_seen[family] += 1
                obs.refused[family] += int(rest)
        elif kind == "IP6":
            obs.ip6_filter = obs.ip6_filter or rest == "filter"
        elif kind == "DP":
            if rest == f"-N {DP_CHAIN}":
                obs.dp_exists = True
            elif rest.startswith(f"-A {DP_CHAIN} "):
                obs.dp_exists = True
                obs.dp_lines.append(rest)
                if re.search(r"-j ACCEPT\b", rest):
                    obs.dp_accept = True
                    continue
                uid = re.search(r"--uid-owner (\d+)\b", rest)
                port = re.search(r"--to-ports (\d+)", rest)
                if uid and port and int(uid.group(1)) not in obs.dp_uids:
                    obs.dp_uids[int(uid.group(1))] = int(port.group(1))
        elif kind == "NATOUT":
            obs.nat_output.append(rest)
        elif kind == "PROXY":
            obs.proxy_raw = rest
            obs.proxy = Endpoint.parse(rest)
        elif kind == "PKG":
            pkg, _, uid = rest.partition(" ")
            if obs.packages is None:
                obs.packages = {}
            if uid.strip().isdigit():
                obs.packages[pkg] = int(uid.strip())
        elif kind == "PKGS":
            obs.packages = None
    return obs


def plan_kill_switch(
    on: bool,
    endpoint: Endpoint | None,
    obs: GuardObservation,
    family: str,
) -> list[str]:
    """Commands that bring one family's kill switch to *on* (pure).

    On: a matching active chain with exactly one jump is left alone (its
    counters keep counting). Otherwise the inactive chain name is filled
    first, the jump moves to it, then every other jump and the old chain go:
    never a moment without a complete chain. Off: jumps first, then the
    chains.
    """
    tbl = "iptables" if family == "4" else "ip6tables"
    chains = obs.ks.get(family, {})
    jumps = obs.jumps.get(family, [])
    cmds: list[str] = []
    if not on:
        for line in jumps:
            cmds.append(f"{tbl} -w -D {line[3:]}")
        for chain in KS_CHAINS:
            if chain in chains:
                cmds.append(f"{tbl} -w -F {chain}")
                cmds.append(f"{tbl} -w -X {chain}")
        return cmds
    want = desired_ks_rules(endpoint, family)
    active = obs.active_ks(family)
    if (
        active is not None
        and chains.get(active) == want
        and len(jumps) == 1
        and jumps[0].strip() == f"-A {ks_jump(active)}"
        and all(c == active for c in chains)
    ):
        return []
    target = KS_CHAINS[1] if active == KS_CHAINS[0] else KS_CHAINS[0]
    if target in chains:
        cmds.append(f"{tbl} -w -F {target}")
    else:
        cmds.append(f"{tbl} -w -N {target}")
    cmds += [ks_rule_command(tbl, target, rule, family) for rule in want]
    cmds.append(
        f"{tbl} -w -I OUTPUT 1 -m owner --uid-owner {APP_UID_RANGE} -j {target}"
    )
    for line in jumps:
        cmds.append(f"{tbl} -w -D {line[3:]}")
    for chain in KS_CHAINS:
        if chain != target and chain in chains:
            cmds.append(f"{tbl} -w -F {chain}")
            cmds.append(f"{tbl} -w -X {chain}")
    return cmds


def dp_jump(endpoint: Endpoint) -> str:
    """The nat OUTPUT jump spec (without op) for traffic to the endpoint."""
    return (
        f"OUTPUT -d {endpoint.ip}/32 -p tcp -m tcp --dport {endpoint.port} "
        f"-j {DP_CHAIN}"
    )


def dp_rule(uid: int, port: int) -> str:
    """One per-UID REDIRECT of the proxy-port chain (without op)."""
    return f"{DP_CHAIN} -p tcp -m owner --uid-owner {uid} -j REDIRECT --to-ports {port}"


def plan_proxy_chain(
    endpoint: Endpoint | None,
    uid_ports: dict[int, int],
    obs: GuardObservation,
) -> tuple[list[str], bool]:
    """Commands for the nat proxy-port chain (pure).

    With an IPv4 endpoint: the chain holds one REDIRECT per attributed UID
    (to its relay port) and ends in ACCEPT; nat OUTPUT jumps to it at
    position 1, before any App Proxy lane REDIRECT (appended), so a lane
    never catches the app's connection to the device proxy. Without an
    endpoint the jumps and the chain are removed.

    Returns:
        ``(commands, jump_added)``; ``jump_added`` means connections opened
        before were not seen by the chain (flush them).
    """
    tbl = "iptables -w -t nat"
    cmds: list[str] = []
    jumps = obs.dp_jumps()
    if endpoint is None or not endpoint.is_ipv4:
        for line in jumps:
            cmds.append(f"{tbl} -D {line[3:]}")
        if obs.dp_exists:
            cmds += [f"{tbl} -F {DP_CHAIN}", f"{tbl} -X {DP_CHAIN}"]
        return cmds, False
    if not obs.dp_exists:
        cmds.append(f"{tbl} -N {DP_CHAIN}")
    # REDIRECTs: add the missing ones at the top (ahead of ACCEPT), then drop
    # stale ones; an UID moving to another port is re-added first.
    for uid, port in sorted(uid_ports.items()):
        if obs.dp_uids.get(uid) != port:
            cmds.append(
                f"{tbl} -I {DP_CHAIN} 1 {dp_rule(uid, port)[len(DP_CHAIN) + 1 :]}"
            )
    for line in obs.dp_lines:
        if re.search(r"-j ACCEPT\b", line):
            continue
        uid = re.search(r"--uid-owner (\d+)\b", line)
        port = re.search(r"--to-ports (\d+)", line)
        keep = (
            uid is not None
            and port is not None
            and uid_ports.get(int(uid.group(1))) == int(port.group(1))
        )
        if not keep:
            cmds.append(f"{tbl} -D {line[3:]}")
    if not obs.dp_accept:
        cmds.append(f"{tbl} -A {DP_CHAIN} -j ACCEPT")
    want = f"-A {dp_jump(endpoint)}"
    first_redirect = next(
        (i for i, line in enumerate(obs.nat_output) if "-j REDIRECT" in line), None
    )
    ours_at = [i for i, line in enumerate(obs.nat_output) if line.strip() == want]
    jump_ok = (
        len(ours_at) == 1
        and len(jumps) == 1
        and (first_redirect is None or ours_at[0] < first_redirect)
    )
    jump_added = False
    if not jump_ok:
        cmds.append(f"{tbl} -I OUTPUT 1 {dp_jump(endpoint)[len('OUTPUT ') :]}")
        jump_added = not ours_at
        for line in jumps:
            cmds.append(f"{tbl} -D {line[3:]}")
    return cmds, jump_added


def app_uid_groups(packages: dict[str, int]) -> dict[int, list[str]]:
    """Group user-0 app UIDs: UID -> sorted packages (pure)."""
    groups: dict[int, list[str]] = {}
    for pkg, uid in packages.items():
        if _APP_UID_MIN <= uid <= _APP_UID_MAX:
            groups.setdefault(uid, []).append(pkg)
    return {uid: sorted(pkgs) for uid, pkgs in sorted(groups.items())}


def assign_relay_ports(
    uids: list[int], current: dict[int, int], base: int = RELAY_BASE
) -> dict[int, int]:
    """Map each UID to a relay port, keeping current in-range ports (pure)."""
    span = range(base, base + RELAY_SPAN)
    result: dict[int, int] = {}
    used: set[int] = set()
    for uid in uids:
        port = current.get(uid)
        if port in span and port not in used:
            result[uid] = port
            used.add(port)
    free = (p for p in span if p not in used)
    for uid in uids:
        if uid not in result:
            port = next(free, None)
            if port is None:
                break
            result[uid] = port
            used.add(port)
    return result


def relay_tag(uid_ports: dict[int, int], upstream: str) -> str:
    """Config tag: changes whenever the listeners or the upstream change."""
    text = upstream + ";" + ",".join(f"{u}:{p}" for u, p in sorted(uid_ports.items()))
    return "sandroid-relay " + hashlib.sha1(text.encode()).hexdigest()[:12]


def relay_healthy(obs: GuardObservation, uid_ports: dict[int, int], tag: str) -> bool:
    """The running relay serves exactly this map (pure)."""
    return (
        obs.relay_running
        and len(obs.relays) == 1
        and obs.config_tag == tag
        and set(uid_ports.values()) <= obs.listening
    )


# ---------------------------------------------------------------------------
# View (what the UI and the method derivation read)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GuardView:
    """Last known guard state of one serial."""

    #: The device proxy seen on the device at the last read.
    endpoint: Endpoint | None = None
    kill_switch: bool = False
    refused: int = 0
    #: "off" | "on" | "failed" | "external" | "unavailable".
    attribution: str = "off"
    named_apps: int = 0
    detail: str = ""
    checked: bool = False
    #: Something of ours is on the device (Kill switch, proxy-port chain or
    #: relay): a later clear of the device proxy must remove it.
    installed: bool = False


_SIDECAR_LOCK = threading.Lock()


def device_uids_path() -> str:
    """Host path of the uid -> package map the Mitmproxy addon reads."""
    default = os.path.expanduser("~/.cache/sandroid/device_uids.json")
    try:
        from sandroid.config import get_config

        lanes = os.path.expanduser(get_config().focus.sidecar_path)
        return os.path.join(os.path.dirname(lanes), "device_uids.json")
    except Exception:
        return default


def write_device_uids(serial: str | None, groups: dict[int, list[str]]) -> None:
    """Merge *serial*'s uid -> package map into the addon's sidecar (atomic).

    Shape: ``{"<uid>": {"package": "a.b" | "a.b,c.d", "serial": "..."}}``.
    """
    path = device_uids_path()
    with _SIDECAR_LOCK:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                data = {}
        except (OSError, ValueError):
            data = {}
        data = {k: v for k, v in data.items() if (v or {}).get("serial") != serial}
        for uid, pkgs in groups.items():
            data[str(uid)] = {"package": ",".join(pkgs), "serial": serial or ""}
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                prefix="device_uids_", suffix=".json", dir=os.path.dirname(path)
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
            Path(tmp).replace(path)
        except OSError as exc:
            logger.warning("Failed to write the device UID map: %s", exc)


# ---------------------------------------------------------------------------
# DeviceGuard
# ---------------------------------------------------------------------------


@dataclass
class _Wanted:
    kill_switch: bool = False
    #: The last device proxy endpoint Sandroid set (restored before the proxy).
    endpoint: Endpoint | None = None
    ours: bool = False


class DeviceGuard:
    """Kill switch + identity relay on each serial (one per process).

    Desired state is session-ephemeral, like App Proxy lanes: whether the
    Kill switch is wanted on a serial and the last endpoint Sandroid set. The
    device is always the truth for what is installed; every apply re-reads
    it first.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._wanted: dict[str | None, _Wanted] = {}
        self._views: dict[str | None, GuardView] = {}
        self._use_su: dict[str | None, bool] = {}

    # -- cached reads (UI thread) -------------------------------------------

    @staticmethod
    def _serial(serial) -> str | None:
        if serial is CURRENT:
            return Adb.get_target_device()
        return serial

    def kill_switch_wanted(self, serial=CURRENT) -> bool:
        """Whether the Kill switch is wanted on *serial* (in-process)."""
        wanted = self._wanted.get(self._serial(serial))
        return bool(wanted and wanted.kill_switch)

    def view_cached(self, serial=CURRENT) -> GuardView:
        """Last known :class:`GuardView` (never blocks)."""
        return self._views.get(self._serial(serial), GuardView())

    def wanted_endpoint(self, serial=CURRENT) -> Endpoint | None:
        wanted = self._wanted.get(self._serial(serial))
        return wanted.endpoint if wanted else None

    def serials_with_state(self) -> list[str | None]:
        """Serials where something is wanted or installed (in-process)."""
        serials = set(self._wanted) | set(self._views)
        return [serial for serial in serials if self.has_state(serial)]

    def has_state(self, serial: str | None) -> bool:
        """Anything wanted, or seen installed, on *serial* (in-process)."""
        wanted = self._wanted.get(serial)
        view = self._views.get(serial)
        return bool((wanted and wanted.kill_switch) or (view and view.installed))

    # -- device helpers -------------------------------------------------------

    def _root(self, serial: str | None) -> bool:
        if serial in self._use_su:
            return True
        try:
            from sandroid.core.proxy_manager import CAManager

            ca = CAManager()
            with Adb.targeting(serial):
                if not ca._check_root_access():
                    return False
            self._use_su[serial] = bool(ca._use_su)
            return True
        except Exception:
            return False

    def _script(self, serial: str | None, *args: str, timeout: float = 60.0) -> str:
        from sandroid.core.proxy_manager import run_device_script

        try:
            out, _err = run_device_script(
                _GUARD_SCRIPT,
                list(args),
                serial=serial,
                use_su=self._use_su.get(serial, False),
                timeout=timeout,
            )
        except Exception as exc:
            logger.debug("guard script %s failed: %s", args[:1], exc)
            return ""
        return out or ""

    @staticmethod
    def _binary() -> str:
        try:
            from sandroid.config import get_config

            return get_config().focus.gost_binary_dst
        except Exception:
            return "/data/local/tmp/gost"

    def _observe(self, serial: str | None, *, uids: bool) -> GuardObservation | None:
        from sandroid.core.proxy_manager import _script_rc

        out = self._script(
            serial,
            "observe",
            self._binary(),
            RELAY_CONFIG,
            str(RELAY_BASE),
            str(RELAY_BASE + RELAY_SPAN - 1),
            "1" if uids else "0",
        )
        if _script_rc(out) is None:
            return None
        return parse_guard_observation(out)

    def _run(self, serial: str | None, cmds: list[str]) -> list[str]:
        """Run commands in one adb call; returns the FAIL lines."""
        if not cmds:
            return []
        out = self._script(serial, "run", *cmds)
        fails = [line for line in out.splitlines() if line.startswith("FAIL ")]
        for line in fails:
            logger.warning("Device guard: %s", line[5:])
        return fails

    @staticmethod
    def _is_ours(endpoint: Endpoint) -> bool:
        try:
            from sandroid.core.proxy_manager import classify_device_proxy
            from sandroid.services.mitmproxy_service import peek_mitmproxy_service

            service = peek_mitmproxy_service()
            if service is None:
                return False  # no Mitmproxy this session: not ours
            port = service.state.proxy_port
            return classify_device_proxy(endpoint.ip, endpoint.port, port) == "ours"
        except Exception:
            return False

    @staticmethod
    def _publish(serial: str | None) -> None:
        try:
            from sandroid.core.events import Event, EventBus, EventType

            EventBus.get().publish(
                Event(
                    type=EventType.STATE_CHANGED,
                    data={"change_type": "network_guard", "serial": serial},
                    source="device_guard",
                )
            )
        except Exception:
            logger.debug("guard publish failed", exc_info=True)

    # -- public, blocking (worker threads) -----------------------------------

    def set_kill_switch(
        self, enabled: bool, serial: str | None = None
    ) -> tuple[bool, str]:
        """Turn the Kill switch on/off on *serial* (default: current target).

        Needs a device proxy: the Kill switch allows apps only that proxy, so
        without one it would just take every app offline. Blocking (adb).
        """
        serial = serial or Adb.get_target_device()
        with self._lock:
            if not enabled:
                self._wanted.setdefault(serial, _Wanted()).kill_switch = False
                view = self.apply(serial)
                if view.kill_switch:
                    return False, "Kill switch could not be removed (see the log)"
                return True, "Kill switch off"
            if not self._root(serial):
                return False, "The Kill switch needs root on the device"
            obs = self._observe(serial, uids=False)
            if obs is None:
                return False, "Device state unreadable"
            if obs.proxy is None:
                return False, (
                    "Set a device proxy first: the Kill switch only lets apps "
                    "reach that proxy"
                )
            if not obs.proxy.is_ipv4:
                return False, (
                    f"The device proxy {obs.proxy.address} is not an IP address; "
                    "the Kill switch needs one"
                )
            self._wanted.setdefault(serial, _Wanted()).kill_switch = True
            view = self.apply(serial, obs=obs)
        if not view.kill_switch:
            return False, view.detail or "Kill switch could not be applied"
        return True, (
            f"Kill switch on: apps may only reach {obs.proxy.address}, "
            "everything else is refused"
        )

    def prepare(
        self,
        serial: str | None,
        endpoint: Endpoint,
        *,
        kill_switch: bool | None = None,
        ours: bool | None = None,
    ) -> GuardView:
        """Install the guard for a device proxy that is ABOUT to be set.

        Fail-closed order for "Whole device" and the restore after a load:
        the Kill switch (allowing *endpoint*) and the proxy-port chain go in
        before the device proxy points anywhere. Blocking (adb).
        """
        with self._lock:
            wanted = self._wanted.setdefault(serial, _Wanted())
            if kill_switch is not None:
                wanted.kill_switch = kill_switch
            wanted.endpoint = endpoint
            if ours is not None:
                wanted.ours = ours
            return self.apply(serial, endpoint=endpoint, ours=ours)

    def after_device_proxy_write(
        self, serial: str | None, address: str | None
    ) -> GuardView:
        """The device proxy on *serial* was set (``address``) or cleared.

        Clearing removes the Kill switch and the proxy-port chain (a Kill
        switch never outlives its device proxy); setting moves the Kill
        switch's allowed endpoint and (for our Mitmproxy) names the apps.
        Blocking (adb).
        """
        endpoint = Endpoint.parse(address)
        with self._lock:
            wanted = self._wanted.setdefault(serial, _Wanted())
            wanted.endpoint = endpoint
            wanted.ours = False
            if endpoint is None:
                wanted.kill_switch = False
            return self.apply(serial)

    def reconcile(self, serial: str | None, reason: str = "") -> GuardView:
        """Check the guard against the device and repair it (restore path).

        With nothing wanted on *serial* only a leftover is handled: a
        kill-switch chain without a device proxy (e.g. from a snapshot) is
        removed. Blocking (adb), never raises.
        """
        with self._lock:
            if serial not in self._wanted:
                obs = self._observe(serial, uids=False) if self._root(serial) else None
                if obs is None:
                    return self.view_cached(serial)
                leftover = (
                    obs.kill_switch_on
                    or obs.active_ks("6") is not None
                    or obs.dp_exists
                    or bool(obs.relays)
                )
                if not leftover:
                    return self.view_cached(serial)
                if obs.proxy is not None:
                    # Somebody's proxy with our chains (an older session's
                    # snapshot): keep it consistent rather than guessing.
                    self._wanted[serial] = _Wanted(
                        kill_switch=obs.kill_switch_on, endpoint=obs.proxy
                    )
                    logger.info(
                        "Device guard after %s: adopted the Kill switch of the "
                        "device proxy %s",
                        reason or "a check",
                        obs.proxy.address,
                    )
                return self.apply(serial, obs=obs)
            return self.apply(serial)

    def refresh(self, serial: str | None) -> GuardView:
        """Read the guard state (one adb call, no change, no event).

        ``checked`` is False when the device could not be read (no root):
        the caller then reads the device proxy itself.
        """
        with self._lock:
            if not self._root(serial):
                return GuardView(attribution="unavailable", detail="no root")
            obs = self._observe(serial, uids=False)
            if obs is None:
                return replace(self.view_cached(serial), checked=False)
            prev = self._views.get(serial, GuardView())
            if obs.proxy is None:
                attribution, named = "off", 0
            elif obs.relay_running and obs.dp_uids:
                attribution, named = "on", len(obs.dp_uids)
            elif prev.attribution == "on":
                attribution, named = "failed", 0  # the relay died
            else:
                attribution, named = prev.attribution, 0
            view = GuardView(
                installed=bool(obs.kill_switch_on or obs.dp_exists or obs.relays),
                endpoint=obs.proxy,
                kill_switch=obs.kill_switch_on,
                refused=obs.refused.get("4", 0) + obs.refused.get("6", 0),
                attribution=attribution,
                named_apps=named,
                detail=prev.detail,
                checked=True,
            )
            self._views[serial] = view
            return view

    def teardown(self, serial: str | None) -> bool:
        """Remove the Kill switch, the proxy-port chain and the relay (quit).

        Returns:
            True when something was removed.
        """
        with self._lock:
            self._wanted.pop(serial, None)
            if not self._root(serial):
                return False
            obs = self._observe(serial, uids=False)
            if obs is None:
                return False
            cmds = plan_kill_switch(False, None, obs, "4")
            if obs.ip6_filter:
                cmds += plan_kill_switch(False, None, obs, "6")
            cmds += plan_proxy_chain(None, {}, obs)[0]
            self._run(serial, cmds)
            if obs.relays:
                self._script(serial, "relay", self._binary(), RELAY_CONFIG, "-", "-")
            self._views[serial] = GuardView(checked=True)
        removed = bool(cmds or obs.relays)
        if removed:
            self._publish(serial)
        return removed

    def apply(
        self,
        serial: str | None,
        *,
        endpoint: Endpoint | None = None,
        ours: bool | None = None,
        obs: GuardObservation | None = None,
    ) -> GuardView:
        """Bring *serial*'s guard in line with what is wanted (blocking).

        The endpoint is the device's real proxy unless *endpoint* is given
        (the proxy is about to be set). Order: Kill switch, relay, then the
        proxy-port chain, then a flush of connections the chain did not see.
        """
        with self._lock:
            view = self._apply_locked(serial, endpoint, ours, obs)
            self._views[serial] = view
        self._publish(serial)
        return view

    def _apply_locked(
        self,
        serial: str | None,
        endpoint: Endpoint | None,
        ours: bool | None,
        obs: GuardObservation | None,
    ) -> GuardView:
        wanted = self._wanted.setdefault(serial, _Wanted())
        if not self._root(serial):
            return GuardView(
                attribution="unavailable", detail="no root on the device", checked=True
            )
        if obs is None or obs.packages is None:
            obs = self._observe(serial, uids=True)
        if obs is None:
            return replace(
                self.view_cached(serial), detail="device state unreadable", checked=True
            )
        target = endpoint or obs.proxy
        if target is None and wanted.kill_switch:
            logger.error(
                "Kill switch removed on %s: the device proxy is gone, and a Kill "
                "switch without its proxy would take every app offline",
                serial,
            )
            wanted.kill_switch = False
        ks_on = wanted.kill_switch and target is not None and target.is_ipv4
        cmds = plan_kill_switch(ks_on, target, obs, "4")
        if obs.ip6_filter:
            cmds += plan_kill_switch(ks_on, target, obs, "6")
        fails = self._run(serial, cmds)
        if ks_on and fails:
            detail = "the Kill switch rules failed (see the log)"
        else:
            detail = ""

        if ours is None:
            ours = target is not None and (
                (wanted.ours and wanted.endpoint == target) or self._is_ours(target)
            )
        attribution = "off"
        uid_ports: dict[int, int] = {}
        groups: dict[int, list[str]] = {}
        if target is not None and ours:
            attribution, uid_ports, groups, why = self._ensure_relay(
                serial, target, obs
            )
            if why:
                detail = detail or why
        elif target is not None:
            attribution = "external"
            if obs.relays:
                self._script(serial, "relay", self._binary(), RELAY_CONFIG, "-", "-")
        elif obs.relays:
            self._script(serial, "relay", self._binary(), RELAY_CONFIG, "-", "-")
        dp_cmds, jump_added = plan_proxy_chain(target, uid_ports, obs)
        self._run(serial, dp_cmds)
        if target is not None and jump_added:
            # Pooled keep-alive sockets opened before the chain keep their
            # old NAT mapping (unnamed) until they close.
            self._script(serial, "flush", target.ip, str(target.port))
        if groups:
            write_device_uids(serial, groups)
        refused = obs.refused.get("4", 0) + obs.refused.get("6", 0)
        if cmds:
            refused = 0  # a rebuilt chain starts counting again
        return GuardView(
            endpoint=target,
            kill_switch=ks_on and not fails,
            refused=refused,
            attribution=attribution,
            named_apps=len(uid_ports),
            detail=detail,
            checked=True,
            installed=target is not None and target.is_ipv4,
        )

    def _ensure_relay(
        self, serial: str | None, target: Endpoint, obs: GuardObservation
    ) -> tuple[str, dict[int, int], dict[int, list[str]], str]:
        """Start or repair the identity relay; ``(state, uid_ports, groups, why)``."""
        if obs.packages is None:
            return "failed", {}, {}, "the app list is unreadable, apps not named"
        groups = app_uid_groups(obs.packages)
        if not groups:
            return "failed", {}, {}, "no apps found, apps not named"
        uid_ports = assign_relay_ports(list(groups), obs.dp_uids)
        tag = relay_tag(uid_ports, target.address)
        if relay_healthy(obs, uid_ports, tag):
            return "on", uid_ports, groups, ""
        ok, msg = self._ensure_binary(serial)
        if not ok:
            logger.warning("Identity relay not started: %s", msg)
            return "failed", {}, {}, f"apps not named ({msg})"
        entries = [f"{uid}:{port}" for uid, port in sorted(uid_ports.items())]
        out = self._script(
            serial,
            "relay",
            self._binary(),
            RELAY_CONFIG,
            target.address,
            tag,
            *entries,
            timeout=90.0,
        )
        if "LISTENING" not in out:
            logger.warning(
                "Identity relay did not start on %s: device-proxy flows stay "
                "without app names",
                serial,
            )
            # Unnamed but working: no REDIRECT may point at a dead relay.
            return "failed", {}, {}, "identity relay not running, apps not named"
        logger.info(
            "Identity relay on %s names %d app UIDs of device-proxy flows",
            serial,
            len(uid_ports),
        )
        return "on", uid_ports, groups, ""

    @staticmethod
    def _ensure_binary(serial: str | None) -> tuple[bool, str]:
        try:
            from sandroid.core.proxy_manager import get_focus_manager

            return get_focus_manager().ensure_gost(serial)
        except Exception as exc:
            return False, str(exc)


_INSTANCE: DeviceGuard | None = None
_INSTANCE_LOCK = threading.Lock()


def get_device_guard() -> DeviceGuard:
    """The process-wide :class:`DeviceGuard`."""
    global _INSTANCE
    if _INSTANCE is None:
        with _INSTANCE_LOCK:
            if _INSTANCE is None:
                _INSTANCE = DeviceGuard()
    return _INSTANCE


def peek_device_guard() -> DeviceGuard | None:
    """The guard if it exists already (never creates it)."""
    return _INSTANCE


def after_device_proxy_write(address: str | None, serial=CURRENT) -> None:
    """The ONE hook every device-proxy write path calls (set or clear).

    Publishes ``STATE_CHANGED{change_type: device_proxy}`` and syncs the
    guard (Kill switch endpoint or removal, app naming). On the UI thread
    the device work moves to a worker; elsewhere it runs inline so the
    caller's order holds. Never raises.
    """
    if serial is CURRENT:
        serial = Adb.get_target_device()
    try:
        from sandroid.core.events import Event, EventBus, EventType

        EventBus.get().publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={
                    "change_type": "device_proxy",
                    "serial": serial,
                    "address": address,
                },
                source="device_proxy",
            )
        )
    except Exception:
        logger.debug("device proxy publish failed", exc_info=True)

    if address is None:
        guard = peek_device_guard()
        if guard is None or not guard.has_state(serial):
            return  # nothing of ours on that device to remove

    def _sync() -> None:
        try:
            with Adb.targeting(serial):
                get_device_guard().after_device_proxy_write(serial, address)
        except Exception as exc:
            logger.warning("Device guard sync after a proxy change failed: %s", exc)

    if threading.current_thread() is threading.main_thread():
        threading.Thread(target=_sync, name="device-guard-sync", daemon=True).start()
    else:
        _sync()
