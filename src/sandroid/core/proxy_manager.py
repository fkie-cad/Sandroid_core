"""Proxy and CA Certificate management for Sandroid.

This module provides TUI-agnostic business logic for:
- HTTP proxy configuration via ADB
- CA certificate detection and management
- Zygote CA injection for system-wide SSL interception
"""

import atexit
import base64
import hashlib
import io
import logging
import os
import re
import shlex
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import requests

from sandroid.core.adb import Adb
from sandroid.core.adb_utils import (
    device_shell_arg,
    device_shell_command,
    is_valid_package_name,
    quote_host_arg,
)

# Import config with fallback for standalone usage
try:
    from sandroid.config import get_config
except ImportError:
    get_config = None

logger = logging.getLogger(__name__)


def _is_emulator() -> bool:
    """Whether the current target device is an Android emulator.

    True when the ADB serial starts with ``emulator-`` or the device reports
    ``ro.boot.qemu == 1``. Shared by both proxy paths so the device proxy and
    app proxies resolve the host IP the same way.
    """
    serial = Adb.get_target_device()
    if serial and serial.startswith("emulator-"):
        return True
    try:
        out, _ = Adb.send_adb_command("shell getprop ro.boot.qemu")
        if (out or "").strip() == "1":
            return True
    except Exception:
        pass
    return False


def resolve_proxy_host_ip() -> str:
    """Host IP the device should route proxy traffic to (emulator-aware).

    One resolver shared by the Device Proxy and the App Proxies so they never
    disagree on where the host is:

    * ``focus.host_ip_override`` wins (one knob, no new config key);
    * else ``10.0.2.2`` on an emulator (the SLIRP loopback alias);
    * else the auto-detected host LAN IP (``ProxyManager.get_host_ip()``).

    NOTE: this is the *reachability* IP. ``device_info.get_host_ip()`` stays the
    display IP for system_info and is intentionally left unchanged.
    """
    try:
        if get_config is not None:
            override = (get_config().focus.host_ip_override or "").strip()
            if override:
                return override
    except Exception:
        pass
    if _is_emulator():
        return "10.0.2.2"
    return ProxyManager.get_host_ip()


def _reverse_registered(proxy_port: int) -> bool:
    """Whether an ``adb reverse tcp:<proxy_port> tcp:<proxy_port>`` is active.

    Live ``adb reverse --list`` output carries a transport-id prefix per line
    (e.g. ``host-16 tcp:8080 tcp:8080``), so match by SUBSTRING, never exact
    line. Best-effort: any error reads as "not registered".
    """
    needle = f"tcp:{proxy_port} tcp:{proxy_port}"
    try:
        out, _ = Adb.reverse_list()
    except Exception:
        return False
    return needle in (out or "")


def classify_device_proxy(cfg_ip: str, cfg_port: int, proxy_port: int) -> str:
    """Classify a device http_proxy as ``"ours"`` / ``"other"``.

    The single shared rule used by every "is this our proxy?" call site (the
    panel's three classifiers and ``MitmproxyService.capture_view``) so they
    never disagree:

    * port must equal our ``proxy_port``; AND
    * ``cfg_ip`` is the resolved host IP (emulator-aware), OR ``127.0.0.1``
      *only when* an ``adb reverse tcp:<proxy_port>`` binding is registered
      (our circumvention tunnel). A loopback proxy without that binding is a
      foreign proxy, not ours.

    Returns ``"ours"`` or ``"other"`` (callers handle the ``"none"`` /
    unset case before calling).
    """
    if cfg_port != proxy_port:
        return "other"
    if cfg_ip == resolve_proxy_host_ip():
        return "ours"
    if cfg_ip == "127.0.0.1" and _reverse_registered(proxy_port):
        return "ours"
    return "other"


def _after_device_proxy_write(address: str | None) -> None:
    """Route a device-proxy write through the one guard hook (never raises)."""
    try:
        from sandroid.core.device_guard import after_device_proxy_write

        after_device_proxy_write(address)
    except Exception:
        logger.debug("device proxy hook failed", exc_info=True)


class ProxyStatus(Enum):
    """Status of the HTTP proxy configuration."""

    NOT_SET = "not_set"
    SET = "set"
    ERROR = "error"


class CASource(Enum):
    """Source of CA certificate."""

    MITMPROXY = "mitmproxy"
    HTTP_TOOLKIT = "http_toolkit"
    BURP_SUITE = "burp_suite"
    CUSTOM = "custom"


@dataclass
class ProxyConfig:
    """Proxy configuration settings."""

    ip: str
    port: int

    @property
    def address(self) -> str:
        """Return the full proxy address."""
        return f"{self.ip}:{self.port}"

    @classmethod
    def from_string(cls, address: str) -> "ProxyConfig":
        """Parse a proxy address string (e.g., '192.168.1.1:8080')."""
        try:
            ip, port_str = address.rsplit(":", 1)
            return cls(ip=ip, port=int(port_str))
        except (ValueError, AttributeError):
            raise ValueError(f"Invalid proxy address format: {address}")


@dataclass
class CAInfo:
    """Information about a CA certificate file."""

    source: CASource
    path: Path
    display_name: str

    @property
    def exists(self) -> bool:
        """Check if the certificate file exists."""
        return self.path.exists()


@dataclass
class ZygoteStatus:
    """Status of Zygote CA injection."""

    injected: bool
    cert_hash: str | None
    zygote64_pid: int | None
    zygote_pid: int | None
    error_message: str | None = None
    #: Trust-store dir the CA was found in (APEX or system cacerts).
    location: str | None = None
    #: True when the device copy's SHA-256 fingerprint matched the host CA
    #: (False = matched by subject-hash file name only).
    fingerprint_verified: bool = False
    #: ``injected`` | ``partial`` | ``other_ca`` | ``absent`` | ``unknown``.
    verdict: str = ""
    #: Whether the target process's namespace has the CA (None: not asked).
    target_injected: bool | None = None
    #: Swept namespaces that still lack the CA (API 34+).
    lacking: int = 0
    #: init's namespace holds our CA (our tmpfs, plus the APEX bind on API
    #: 34+): only then does a restarted Zygote inherit it.
    init_has_ca: bool = False


_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", re.S
)


def _pem_der_certs(text: str) -> list[bytes]:
    """DER bytes of every PEM ``CERTIFICATE`` block in ``text``.

    Android's cacerts files are PEM, often preceded by ``openssl x509 -text``
    output, so the blocks are searched rather than parsed from the start.
    """
    import base64
    import binascii

    out: list[bytes] = []
    for body in _PEM_CERT_RE.findall(text or ""):
        try:
            out.append(base64.b64decode("".join(body.split()), validate=True))
        except (binascii.Error, ValueError):
            continue
    return out


def _subject_hash_old(der: bytes) -> str | None:
    """OpenSSL ``-subject_hash_old`` (the cacerts file name) of a DER cert.

    MD5 over the DER-encoded subject, first four bytes read little-endian.
    Returns None when ``cryptography`` is unavailable.
    """
    try:
        from cryptography import x509
    except ImportError:  # pragma: no cover - cryptography ships with mitmproxy
        return None
    try:
        subject = x509.load_der_x509_certificate(der).subject.public_bytes()
    except Exception:
        return None
    digest = hashlib.md5(subject).digest()
    return f"{int.from_bytes(digest[:4], 'little'):08x}"


#: Device script for the CA trust store (one ``adb shell`` per operation,
#: base64-piped so the host shell never parses it). Every mount is done with
#: an explicit ``nsenter`` into the namespace it belongs to, so it works from
#: adb root and from a ``su`` in an isolated mount namespace alike.
#:
#: Recipe (no Zygote restart): ONE tmpfs (stock CAs + ours) on the system
#: cacerts dir in init's mount namespace (``/`` is shared there, so it shows
#: up in every zygote/app namespace), then on API 34+ a bind of it onto the
#: private APEX cacerts dir in init (a later Zygote restart inherits it), in
#: each Zygote whose parent is init (every future fork) and in every mount
#: namespace below a Zygote (running apps, system_server). Rotation replaces
#: the file in the shared tmpfs; uninject deletes our file in the shared
#: tmpfs first (every bind stops trusting it, also one the sweep misses),
#: then unmounts everywhere (Zygotes first, two passes) and verifies.
#:
#: Operations (the last output line is always ``rc=<n>``):
#:   inject <staged.pem> <name> <apex 0|1>
#:   status <name> <apex 0|1> [pid ...]
#:   uninject <apex 0|1>
#:   restart-zygote          (user-confirmed fallback only)
_CA_SCRIPT = r"""
SYS=/system/etc/security/cacerts
APEX=/apex/com.android.conscrypt/cacerts
LABEL=u:object_r:system_security_cacerts_file:s0
WORK=/data/local/tmp
MANIFEST=$WORK/.sandroid-ca-manifest
SEEDED=$WORK/.sandroid-ca-seeded
op=$1
[ $# -gt 0 ] && shift

zygotes() {
  for p in $(pidof zygote64) $(pidof zygote); do
    pp=; read -r _ _ _ pp _ </proc/$p/stat 2>/dev/null
    [ "$pp" = 1 ] && echo "$p"
  done
}
top_mount() {
  awk -v mp="$2" '$5==mp { fs=""; for(i=7;i<=NF;i++) if($i=="-"){fs=$(i+1);break}; last=$3" "fs } END { if(last!="") print last }' /proc/$1/mountinfo 2>/dev/null
}
our_dev() {
  set -- $(top_mount 1 $SYS)
  [ "$2" = tmpfs ] && echo "$1"
}
descendants() {
  ps -A -o PID=,PPID= 2>/dev/null | awk -v roots="$(zygotes | tr '\n' ' ')" '
    { pp[$1]=$2; ids[NR]=$1 }
    END { n=split(roots, r, " "); for (i=1;i<=n;i++) inset[r[i]]=1
      changed=1
      while (changed) { changed=0
        for (k in ids) { p=ids[k]; if (!(p in inset) && (pp[p] in inset)) { inset[p]=1; changed=1 } } }
      for (p in inset) print p }'
}
namespaces() {
  seen=" $(readlink /proc/1/ns/mnt) "
  for z in $(zygotes); do
    ns=$(readlink /proc/$z/ns/mnt 2>/dev/null) || continue
    seen="$seen$ns "
    echo "$z"
  done
  for p in $(descendants); do
    ns=$(readlink /proc/$p/ns/mnt 2>/dev/null) || continue
    case "$seen" in *" $ns "*) continue;; esac
    seen="$seen$ns "
    [ -d /proc/$p/root$APEX ] || continue
    echo "$p"
  done
}
sweep() {
  dev=$(our_dev)
  [ -n "$dev" ] || { echo "sweep: no tmpfs of ours in init"; return 1; }
  ok=0; skip=0; fail=0
  for p in $(namespaces); do
    set -- $(top_mount $p $APEX)
    if [ "$1" = "$dev" ]; then skip=$((skip+1)); continue; fi
    if nsenter -t $p -m -- mount --bind $SYS $APEX 2>/dev/null; then
      ok=$((ok+1))
    elif [ -d /proc/$p ]; then
      fail=$((fail+1)); echo "sweep: failed pid=$p"
    fi
  done
  echo "sweep: bound=$ok already=$skip failed=$fail"
  [ $fail = 0 ]
}
inject() {
  stage=$1; name=$2; apex=$3
  [ -s "$stage" ] || { echo "inject: no staged certificate"; return 2; }
  command -v nsenter >/dev/null 2>&1 || { echo "inject: nsenter missing"; return 3; }
  orig=
  [ "$apex" = 1 ] && orig=$(ls -d /apex/com.android.conscrypt@*/cacerts 2>/dev/null | head -n1)
  if [ -n "$(our_dev)" ]; then
    # Reuse only a tmpfs this script seeded completely: an empty or partial
    # one (a failed earlier copy, a foreign overlay) would leave every stock
    # CA untrusted.
    want=$(cat $SEEDED 2>/dev/null)
    have=$(nsenter -t 1 -m -- ls $SYS 2>/dev/null | wc -l)
    if [ -n "$want" ] && [ "$have" -ge "$want" ] 2>/dev/null; then
      echo "inject: reusing the tmpfs on $SYS"
    else
      echo "inject: the tmpfs on $SYS is incomplete (have=$have want=${want:-unknown}); rebuilding it"
      nsenter -t 1 -m -- umount $SYS || { echo "inject: tmpfs mount failed (could not remove the incomplete tmpfs)"; return 5; }
    fi
  fi
  if [ -z "$(our_dev)" ]; then
    seed=$SYS
    if [ "$apex" = 1 ]; then seed=${orig:-$APEX}; fi
    tmp=$WORK/.sandroid-ca-seed.$$
    rm -rf $tmp && mkdir -p $tmp && cp $seed/* $tmp/ || { echo "inject: seed copy failed"; rm -rf $tmp; return 4; }
    count=$(ls $tmp | wc -l)
    nsenter -t 1 -m -- sh -c "mount -t tmpfs -o mode=755 tmpfs $SYS || exit 5; cp $tmp/* $SYS/ || { umount $SYS; exit 6; }"
    r=$?
    rm -rf $tmp
    case $r in
      0) ;;
      6) echo "inject: seed copy into the tmpfs failed (tmpfs removed)"; return 6 ;;
      *) echo "inject: tmpfs mount failed"; return 5 ;;
    esac
    echo "$count" >$SEEDED
    echo "inject: tmpfs on $SYS seeded from $seed"
  fi
  for old in $(cat $MANIFEST 2>/dev/null); do
    [ "$old" = "$name" ] && continue
    [ -n "$orig" ] && [ -e "$orig/$old" ] && continue
    nsenter -t 1 -m -- rm -f $SYS/$old && echo "inject: replaced=$old"
  done
  prev=$(nsenter -t 1 -m -- sha256sum $SYS/$name 2>/dev/null | cut -d' ' -f1)
  echo "inject: previous=${prev:-none}"
  nsenter -t 1 -m -- sh -c "cp $stage $SYS/$name.tmp && mv $SYS/$name.tmp $SYS/$name && chown root:root $SYS $SYS/* && chmod 755 $SYS && chmod 644 $SYS/* && { chcon -R $LABEL $SYS 2>/dev/null || chcon -R u:object_r:system_file:s0 $SYS; }" || { echo "inject: certificate copy failed"; return 6; }
  rm -f "$stage"
  echo "$name" >$MANIFEST
  [ "$apex" = 1 ] || { echo "inject: system dir only (it propagates)"; return 0; }
  dev=$(our_dev)
  set -- $(top_mount 1 $APEX)
  if [ "$1" != "$dev" ]; then
    nsenter -t 1 -m -- mount --bind $SYS $APEX || { echo "inject: init APEX bind failed"; return 7; }
  fi
  sweep || return 8
  sweep || return 8
}
st_one() {
  role=$1; p=$2; dir=$3; name=$4
  if [ ! -d /proc/$p ]; then echo "ns role=$role pid=$p comm=- mount=none file=missing"; return; fi
  comm=$(tr '\0' '\n' </proc/$p/cmdline 2>/dev/null | head -n1)
  comm=${comm##*/}
  set -- $(top_mount $p $dir)
  m=none; [ -n "$1" ] && m="$1/$2"
  h=$(nsenter -t $p -m -- sha256sum $dir/$name 2>/dev/null | cut -d' ' -f1)
  echo "ns role=$role pid=$p comm=$comm mount=$m file=${h:-missing}"
}
status() {
  name=$1; apex=$2; shift 2
  dir=$SYS; [ "$apex" = 1 ] && dir=$APEX
  dev=$(our_dev)
  echo "our_dev=${dev:-none}"
  st_one init 1 $dir $name
  for z in $(zygotes); do st_one zygote $z $dir $name; done
  for s in $(pidof system_server); do st_one system_server $s $dir $name; done
  for p in "$@"; do st_one target $p $dir $name; done
  if [ "$apex" = 1 ] && [ -n "$dev" ]; then
    have=0; lack=0
    for p in $(namespaces); do
      set -- $(top_mount $p $APEX)
      if [ "$1" = "$dev" ]; then have=$((have+1)); else lack=$((lack+1)); fi
    done
    echo "namespaces have=$have lack=$lack"
  fi
}
unbind_all() {
  for p in $(namespaces) 1; do
    while :; do
      set -- $(top_mount $p $APEX)
      [ "$2" = tmpfs ] || break
      if nsenter -t $p -m -- umount $APEX 2>/dev/null; then n=$((n+1)); else
        [ -d /proc/$p ] && fail=$((fail+1)); break
      fi
    done
  done
}
uninject() {
  apex=$1; n=0; fail=0
  # Delete our certificate in the shared tmpfs FIRST: every bind of it, also
  # one in a namespace the sweep below misses, then stops trusting it.
  orig=$(ls -d /apex/com.android.conscrypt@*/cacerts 2>/dev/null | head -n1)
  if [ -n "$(our_dev)" ]; then
    for old in $(cat $MANIFEST 2>/dev/null); do
      if [ -n "$orig" ] && [ -e "$orig/$old" ]; then
        nsenter -t 1 -m -- cp "$orig/$old" $SYS/$old
      else
        nsenter -t 1 -m -- rm -f $SYS/$old
      fi
      echo "uninject: deleted=$old"
    done
  fi
  if [ "$apex" = 1 ]; then
    # Zygotes first, then every app namespace; twice, so an app forked
    # between the listing and the Zygote unmount is caught too.
    unbind_all
    fail=0
    unbind_all
  fi
  while [ -n "$(our_dev)" ]; do
    nsenter -t 1 -m -- umount $SYS || { fail=$((fail+1)); break; }
    n=$((n+1))
  done
  left=0
  if [ "$apex" = 1 ]; then
    for p in $(namespaces) 1; do
      set -- $(top_mount $p $APEX)
      [ "$2" = tmpfs ] && left=$((left+1))
    done
  fi
  [ -n "$(our_dev)" ] && left=$((left+1))
  [ $left = 0 ] && rm -f $MANIFEST $SEEDED
  echo "uninject: unmounted=$n failed=$fail left=$left"
  [ $fail = 0 ] && [ $left = 0 ]
}
restart_zygote() {
  echo "ss_before=$(pidof system_server | cut -d' ' -f1)"
  for z in $(zygotes); do kill $z && echo "killed=$z"; done
  true
}
case "$op" in
  inject) inject "$@" ;;
  status) status "$@" ;;
  uninject) uninject "$@" ;;
  restart-zygote) restart_zygote ;;
  *) echo "usage: inject|status|uninject|restart-zygote"; false ;;
esac
echo "rc=$?"
"""

#: Where the host stages the CA (PEM) for the inject operation.
_CA_STAGE_PATH = "/data/local/tmp/sandroid-ca.pem"

#: Note shown after a rotation or removal: a process that already validated
#: the old CA keeps trusting it (in-process trust/session caches).
CA_RUNNING_APPS_NOTE = (
    "Apps that are already running keep the old trust until they restart."
)


def run_device_script(
    script: str,
    args: list[str] | tuple[str, ...] = (),
    *,
    serial: str | None,
    use_su: bool = False,
    timeout: float = 90.0,
) -> tuple[str, str]:
    """Run a device shell *script* in ONE ``adb shell`` call (base64-piped).

    The script travels as base64 (``echo <b64> | base64 -d | sh -s -- args``),
    so neither the host shell nor the device shell parses its text; every
    argument is quoted for the device shell, and the whole command line is
    one host-shell word. ``use_su`` wraps the interpreter in ``su -c``.

    Args:
        script: The ``sh`` script text.
        args: Positional arguments for the script.
        serial: Device serial for this call only (never the global target).
        use_su: Run the interpreter through ``su -c`` (no adb root).
        timeout: Seconds before adb is abandoned.

    Returns:
        ``(stdout, stderr)`` of the adb call.
    """
    payload = base64.b64encode(script.encode("utf-8")).decode("ascii")
    argline = " ".join(shlex.quote(str(a)) for a in args)
    runner = f"sh -s -- {argline}".rstrip()
    if use_su:
        runner = f"su -c {shlex.quote(runner)}"
    command = f"echo {payload} | base64 -d | {runner}"
    return Adb.send_adb_command(
        device_shell_command(command), serial=serial, timeout=timeout
    )


def _script_rc(output: str) -> int | None:
    """The ``rc=<n>`` trailer a device script prints last (None: missing)."""
    for line in reversed((output or "").splitlines()):
        m = re.fullmatch(r"\s*rc=(\d+)\s*", line)
        if m:
            return int(m.group(1))
    return None


@dataclass
class CaNamespace:
    """One mount namespace as the CA status script saw it."""

    role: str
    pid: int
    comm: str
    mount: str
    sha256: str | None


@dataclass
class CaStatusReport:
    """Parsed output of the CA script's ``status`` operation."""

    our_dev: str | None
    namespaces: list[CaNamespace]
    have: int | None = None
    lack: int | None = None


def parse_ca_status(output: str) -> CaStatusReport:
    """Parse the CA script's ``status`` output (pure; never raises)."""
    our_dev: str | None = None
    entries: list[CaNamespace] = []
    have = lack = None
    for raw in (output or "").splitlines():
        line = raw.strip()
        if line.startswith("our_dev="):
            value = line.split("=", 1)[1]
            our_dev = None if value in ("", "none") else value
        elif line.startswith("ns "):
            fields = dict(
                part.split("=", 1) for part in line[3:].split() if "=" in part
            )
            try:
                pid = int(fields.get("pid", ""))
            except ValueError:
                continue
            sha = fields.get("file", "missing")
            entries.append(
                CaNamespace(
                    role=fields.get("role", ""),
                    pid=pid,
                    comm=fields.get("comm", "").strip("()"),
                    mount=fields.get("mount", "none"),
                    sha256=None if sha in ("", "missing") else sha.lower(),
                )
            )
        elif line.startswith("namespaces "):
            m = re.search(r"have=(\d+)\s+lack=(\d+)", line)
            if m:
                have, lack = int(m.group(1)), int(m.group(2))
    return CaStatusReport(our_dev=our_dev, namespaces=entries, have=have, lack=lack)


def ca_verdict(report: CaStatusReport, ours: set[str]) -> str:
    """Classify a CA status report (pure).

    Returns:
        ``"injected"`` (every Zygote, system_server and target namespace
        holds our CA and no swept namespace lacks it), ``"partial"`` (the
        Zygotes have it, so new apps trust it, but a running namespace
        lacks it: a re-sweep fixes that), ``"other_ca"`` (a different CA
        under the same file name), ``"absent"``, or ``"unknown"`` (no
        Zygote seen).
    """
    zygotes = [ns for ns in report.namespaces if ns.role == "zygote"]
    if not zygotes:
        return "unknown"
    if all(ns.sha256 in ours for ns in zygotes):
        others = [
            ns
            for ns in report.namespaces
            if ns.role in ("system_server", "target") and ns.comm != "-"
        ]
        if any(ns.sha256 not in ours for ns in others) or (report.lack or 0) > 0:
            return "partial"
        return "injected"
    if any(ns.sha256 is not None for ns in zygotes):
        return "other_ca"
    return "absent"


@dataclass
class CaSpec:
    """A CA Sandroid injected (kept per serial as the re-inject intent)."""

    cert_path: Path
    cert_hash: str
    fingerprint: str
    pem: bytes

    @property
    def name(self) -> str:
        """File name in the trust store (``<subject_hash_old>.0``)."""
        return f"{self.cert_hash}.0"

    @property
    def pem_sha256(self) -> str:
        """SHA-256 of the exact bytes pushed to the device."""
        return hashlib.sha256(self.pem).hexdigest()


#: serial -> the CA the user injected on that serial in this session. Drives
#: the automatic no-restart re-inject after a snapshot load / cold boot.
_CA_DESIRED: dict[str, CaSpec] = {}
_CA_STATE_LOCK = threading.Lock()
#: serial -> lock serialising inject/uninject/status (TUI and AI never mix).
_CA_OP_LOCKS: dict[str, threading.RLock] = {}


def _ca_op_lock(serial: str | None) -> threading.RLock:
    with _CA_STATE_LOCK:
        return _CA_OP_LOCKS.setdefault(serial or "", threading.RLock())


def ca_desired_serials() -> list[str]:
    """Serials the user injected a CA on in this session."""
    with _CA_STATE_LOCK:
        return list(_CA_DESIRED)


def ca_desired_for(serial: str | None) -> CaSpec | None:
    """The CA the user injected on *serial* in this session, if any."""
    if not serial:
        return None
    with _CA_STATE_LOCK:
        return _CA_DESIRED.get(serial)


def _install_restore_hook() -> None:
    """Let the device-prepared hook restore what was just recorded (lazy)."""
    try:
        from sandroid.services.proxy_restore import install_device_prepared_hook

        install_device_prepared_hook()
    except Exception:
        logger.debug("proxy restore hook not installed", exc_info=True)


def restart_can_help(rc: int, status: ZygoteStatus) -> bool:
    """Whether the Zygote-restart fallback can install the CA (pure).

    A new Zygote only inherits what init's namespace holds: our tmpfs (and
    on API 34+ its APEX bind). That is the case after the script got that
    far (rc 0, or rc 8 when only the Zygote/app binds failed) and init
    shows our CA. Never for a missing ``nsenter``, a failed seed, tmpfs or
    init bind (rc 2-7) or an adb timeout (rc -1): the retry after the
    restart would fail the same way.
    """
    return rc in (0, 8) and status.init_has_ca and status.verdict != "injected"


def remember_ca_intent(serial: str | None, spec: CaSpec | None) -> None:
    """Record (or with None forget) the CA the user injected on *serial*."""
    if not serial:
        return
    if spec is not None:
        _install_restore_hook()
    with _CA_STATE_LOCK:
        if spec is None:
            _CA_DESIRED.pop(serial, None)
        else:
            _CA_DESIRED[serial] = spec


def publish_ca_change(serial: str | None, installed: bool | None) -> None:
    """Tell the UI that the CA state of *serial* changed (``STATE_CHANGED``).

    ``installed`` is the outcome when known (True after a successful install,
    False after a successful removal), else None: the listeners re-read the
    device. Any thread; never raises.
    """
    try:
        from sandroid.core.events import Event, EventBus, EventType

        EventBus.get().publish(
            Event(
                type=EventType.STATE_CHANGED,
                data={
                    "change_type": "proxy_ca",
                    "serial": serial,
                    "installed": installed,
                },
                source="ca_manager",
            )
        )
    except Exception:
        logger.debug("CA change publish failed", exc_info=True)


class InjectionStrategy(Enum):
    """Strategy for CA injection based on Android version."""

    LEGACY = "legacy"
    BIND_MOUNT = "bind_mount"


@dataclass
class InjectionResult:
    """Result of a CA injection attempt."""

    success: bool
    message: str
    strategy: InjectionStrategy | None = None
    api_level: int | None = None
    needs_root: bool = False
    #: The no-restart path could not apply; only a user-confirmed Zygote
    #: restart (never automatic, never from the AI) would.
    restart_required: bool = False
    #: Zygote was restarted (the user-confirmed fallback ran).
    restarted: bool = False
    #: Status verdict after the attempt (see ``ZygoteStatus.verdict``).
    verdict: str | None = None


class ProxyManager:
    """Manages HTTP proxy configuration for Android devices via ADB."""

    def __init__(self, adb: Adb | None = None):
        """Initialize ProxyManager.

        Args:
            adb: Optional Adb instance. If not provided, creates a new one.
        """
        self._adb = adb

    @property
    def adb(self) -> Adb:
        """Get ADB wrapper, creating if needed."""
        if self._adb is None:
            self._adb = Adb()
        return self._adb

    def get_proxy_settings(self) -> tuple[ProxyStatus, ProxyConfig | None]:
        """Get the current proxy settings from the device.

        Returns:
            Tuple of (status, config). Config is None if proxy not set.
        """
        try:
            stdout, stderr = Adb.send_adb_command(
                "shell settings get global http_proxy"
            )
            if stderr:
                logger.warning(
                    f"ADB command warning while getting proxy settings: {stderr}"
                )
            proxy_value = stdout.strip() if stdout else ""

            if not proxy_value or proxy_value == "null" or proxy_value == ":0":
                return ProxyStatus.NOT_SET, None

            try:
                config = ProxyConfig.from_string(proxy_value)
                return ProxyStatus.SET, config
            except ValueError:
                if "Failure calling service" in proxy_value:
                    # settings service down (system_server restarting after
                    # a Zygote restart): unreadable for now, not invalid.
                    logger.debug(f"Device proxy unreadable: {proxy_value}")
                else:
                    logger.warning(f"Invalid proxy format from device: {proxy_value}")
                return ProxyStatus.ERROR, None

        except Exception as e:
            logger.error(f"Error getting proxy settings: {e}")
            return ProxyStatus.ERROR, None

    def set_proxy(self, config: ProxyConfig) -> tuple[bool, str]:
        """Set the HTTP proxy on the device.

        Every device-proxy write ends in
        :func:`sandroid.core.device_guard.after_device_proxy_write` (the
        Kill switch follows the endpoint, apps are named, an event repaints
        the UI).

        Args:
            config: ProxyConfig with IP and port.

        Returns:
            Tuple of (success, message).
        """
        try:
            # Set the proxy
            Adb.send_adb_command(
                f"shell settings put global http_proxy {config.address}"
            )

            # Verify it was set correctly
            status, current = self.get_proxy_settings()
            if (
                status == ProxyStatus.SET
                and current
                and current.address == config.address
            ):
                logger.info(f"Proxy set to {config.address}")
                _after_device_proxy_write(config.address)
                return True, f"Proxy set to {config.address}"
            return False, "Proxy was not set correctly"

        except Exception as e:
            logger.error(f"Error setting proxy: {e}")
            return False, f"Error setting proxy: {e}"

    def unset_proxy(self) -> tuple[bool, str]:
        """Remove the HTTP proxy from the device.

        Returns:
            Tuple of (success, message).
        """
        try:
            # Clear the proxy setting
            Adb.send_adb_command("shell settings put global http_proxy :0")

            # Verify it was cleared
            status, _ = self.get_proxy_settings()
            if status == ProxyStatus.NOT_SET:
                logger.info("Proxy cleared")
                _after_device_proxy_write(None)
                return True, "Proxy cleared"
            return False, "Failed to clear proxy"

        except Exception as e:
            logger.error(f"Error clearing proxy: {e}")
            return False, f"Error clearing proxy: {e}"

    @staticmethod
    def get_host_ip() -> str:
        """Get the host machine's IP address (delegated to SetupService).

        Returns the IP that's likely accessible from the Android device.
        """
        from sandroid.services import get_setup_service

        return get_setup_service().get_host_ip()

    @classmethod
    def get_default_config(cls) -> ProxyConfig:
        """Default proxy: the host IP and the configured mitmproxy port.

        The port is ``mitmproxy.proxy_port`` (8080 only if the config cannot
        be read), so the suggestion points at Sandroid's own mitmproxy.
        """
        port = 8080
        try:
            from sandroid.config import get_config

            port = int(get_config().mitmproxy.proxy_port)
        except Exception:
            pass
        return ProxyConfig(ip=cls.get_host_ip(), port=port)


class CAManager:
    """Manages CA certificates for SSL interception."""

    # Common CA certificate locations
    CA_LOCATIONS = {
        CASource.MITMPROXY: [
            Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem",
            Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer",
        ],
        CASource.HTTP_TOOLKIT: [
            Path.home() / ".config" / "httptoolkit" / "ca.pem",
            Path.home() / ".httptoolkit" / "ca.pem",
        ],
        CASource.BURP_SUITE: [
            Path.home() / ".BurpSuite" / "burp-ca-cert.der",
            Path.home() / "BurpSuite" / "PortSwigger" / "burp-ca-cert.der",
        ],
    }

    # Default device paths (kept as fallbacks)
    _DEFAULT_DEVICE_CERT_PATH = "/data/local/tmp/cert-der.crt"
    _DEFAULT_SYSTEM_CA_PATH = "/system/etc/security/cacerts"
    _DEFAULT_APEX_CA_PATH = "/apex/com.android.conscrypt/cacerts"

    @property
    def DEVICE_CERT_PATH(self) -> str:
        """Get device cert path from config with fallback."""
        try:
            if get_config is not None:
                return get_config().device_paths.device_cert_path
        except Exception:
            pass
        return self._DEFAULT_DEVICE_CERT_PATH

    @property
    def SYSTEM_CA_PATH(self) -> str:
        """Get system CA path from config with fallback."""
        try:
            if get_config is not None:
                return get_config().device_paths.system_ca_path
        except Exception:
            pass
        return self._DEFAULT_SYSTEM_CA_PATH

    @property
    def APEX_CA_PATH(self) -> str:
        """Get APEX CA path from config with fallback."""
        try:
            if get_config is not None:
                return get_config().device_paths.apex_ca_path
        except Exception:
            pass
        return self._DEFAULT_APEX_CA_PATH

    # Display names for CA sources
    SOURCE_NAMES = {
        CASource.MITMPROXY: "mitmproxy",
        CASource.HTTP_TOOLKIT: "HTTP Toolkit",
        CASource.BURP_SUITE: "Burp Suite",
        CASource.CUSTOM: "Custom Certificate",
    }

    def __init__(self, adb: Adb | None = None):
        """Initialize CAManager.

        Args:
            adb: Optional Adb instance. If not provided, creates a new one.
        """
        self._adb = adb
        self._use_su: bool = True

    @property
    def adb(self) -> Adb:
        """Get ADB wrapper, creating if needed."""
        if self._adb is None:
            self._adb = Adb()
        return self._adb

    def detect_ca_certificates(self) -> list[CAInfo]:
        """Auto-detect available CA certificates on the host.

        Returns:
            List of CAInfo for detected certificates.
        """
        found = []

        for source, paths in self.CA_LOCATIONS.items():
            for path in paths:
                if path.exists():
                    found.append(
                        CAInfo(
                            source=source,
                            path=path,
                            display_name=self.SOURCE_NAMES[source],
                        )
                    )
                    break  # Only add first found for each source

        return found

    def convert_pem_to_der(
        self, pem_path: Path, der_path: Path | None = None
    ) -> tuple[bool, str, Path | None]:
        """Convert a PEM certificate to DER format.

        Args:
            pem_path: Path to the PEM certificate.
            der_path: Optional output path. If not provided, uses temp directory.

        Returns:
            Tuple of (success, message, output_path).
        """
        if der_path is None:
            der_path = Path(tempfile.gettempdir()) / "sandroid-ca-cert.der"

        try:
            result = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(pem_path),
                    "-outform",
                    "DER",
                    "-out",
                    str(der_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )

            if result.returncode == 0:
                logger.debug(f"Converted PEM to DER: {der_path}")
                return True, f"Certificate converted to {der_path}", der_path
            error = result.stderr or "Unknown error"
            return False, f"OpenSSL error: {error}", None

        except FileNotFoundError:
            return False, "OpenSSL not found. Please install OpenSSL.", None
        except OSError as e:
            logger.error(f"Failed to start OpenSSL process: {e}")
            return False, f"Failed to start OpenSSL process: {e}", None
        except subprocess.SubprocessError as e:
            logger.error(f"Subprocess error during certificate conversion: {e}")
            return False, f"Subprocess error during certificate conversion: {e}", None

    def get_cert_hash(self, cert_path: Path) -> str | None:
        """Get the OpenSSL hash of a certificate.

        This hash is used for naming certificates in Android's CA store.

        Args:
            cert_path: Path to the certificate (PEM or DER).

        Returns:
            The certificate hash, or None on error.
        """
        try:
            # Determine format
            inform = "PEM" if cert_path.suffix.lower() in (".pem", ".crt") else "DER"

            result = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-inform",
                    inform,
                    "-in",
                    str(cert_path),
                    "-noout",
                    "-subject_hash_old",
                ],
                check=False,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )

            if result.returncode == 0:
                return result.stdout.strip()
            return None

        except OSError as e:
            logger.error(f"Failed to start OpenSSL process: {e}")
            return None
        except subprocess.SubprocessError as e:
            logger.error(f"Subprocess error getting certificate hash: {e}")
            return None

    def push_cert_to_device(self, local_path: Path) -> tuple[bool, str]:
        """Push a certificate to the device's temp directory.

        Args:
            local_path: Path to the local certificate file.

        Returns:
            Tuple of (success, message).
        """
        try:
            # Ensure the certificate is in DER format
            if local_path.suffix.lower() in (".pem", ".crt"):
                success, message, der_path = self.convert_pem_to_der(local_path)
                if not success:
                    return False, message
                local_path = der_path

            # Push to device
            Adb.send_adb_command(
                f"push {quote_host_arg(str(local_path))} {self.DEVICE_CERT_PATH}"
            )

            # Verify
            check_stdout, check_stderr = Adb.send_adb_command(
                f"shell ls {self.DEVICE_CERT_PATH}"
            )
            if check_stderr:
                logger.warning(
                    f"ADB command warning while verifying certificate push: {check_stderr}"
                )
            if self.DEVICE_CERT_PATH in (check_stdout or ""):
                logger.debug(f"Certificate pushed to {self.DEVICE_CERT_PATH}")
                return True, f"Certificate pushed to {self.DEVICE_CERT_PATH}"
            return False, "Certificate was not pushed correctly"

        except Exception as e:
            logger.error(f"Error pushing certificate: {e}")
            return False, f"Error pushing certificate: {e}"

    def get_device_api_level(self) -> int | None:
        """Get the API level of the device adb currently targets.

        Uses DeviceManager's active device only when it is that device (the
        thread may be pinned to another serial), else asks the device.

        Returns:
            API level as int, or None if unavailable.
        """
        serial = Adb.get_target_device()
        try:
            from sandroid.core.device_manager import DeviceManager

            # The existing singleton only (never create it here).
            dm = DeviceManager._instance
            active = dm.active_device if dm is not None else None
            # Only the device this call targets (Adb.targeting / serial=):
            # a CA operation on another serial must not use the active
            # device's API level (it picks the trust store).
            if (
                active
                and active.api_level
                and getattr(active, "serial", None) in (None, serial)
            ):
                return int(active.api_level)
        except Exception:
            pass

        try:
            stdout, _ = Adb.send_adb_command(
                "shell getprop ro.build.version.sdk", serial=serial
            )
            if stdout and stdout.strip().isdigit():
                return int(stdout.strip())
        except Exception:
            pass

        return None

    def determine_injection_strategy(
        self,
    ) -> tuple[InjectionStrategy, int | None]:
        """Determine which CA injection strategy to use.

        Uses API level (>= 34 → BIND_MOUNT) with a fallback check for
        the APEX cacerts directory existence.

        Returns:
            Tuple of (strategy, api_level).
        """
        api_level = self.get_device_api_level()

        if api_level is not None and api_level >= 34:
            return InjectionStrategy.BIND_MOUNT, api_level

        # Fallback: check if APEX cacerts dir exists on device
        if api_level is None or api_level >= 33:
            try:
                stdout, _ = Adb.send_adb_command(
                    f"shell '[ -d {self.APEX_CA_PATH} ] && echo EXISTS'"
                )
                if "EXISTS" in (stdout or ""):
                    return InjectionStrategy.BIND_MOUNT, api_level
            except Exception:
                pass

        return InjectionStrategy.LEGACY, api_level

    def _check_root_access(self) -> bool:
        """Verify root access on the device.

        Tries direct shell (adb root mode) first, then falls back to su binary.
        Sets `_use_su` flag so subsequent commands use the right method.
        """
        # Try direct shell first (adb root mode — shell already runs as root)
        try:
            stdout, _ = Adb.send_adb_command("shell id")
            if "uid=0" in (stdout or ""):
                self._use_su = False
                return True
        except Exception:
            pass
        # Fall back to su binary (Magisk, SuperSU, etc.)
        try:
            stdout, _ = Adb.send_adb_command("shell su -c id")
            if "uid=0" in (stdout or ""):
                self._use_su = True
                return True
        except Exception:
            pass
        return False

    def _root_cmd(self, cmd: str) -> str:
        """Wrap a command for root execution on the device.

        The result is ONE host-shell-quoted word, so shell metacharacters
        (&&, *, etc.) are interpreted by the device shell, never the host
        shell -- even when *cmd* itself contains quotes. Uses
        ``su -c '<cmd>'`` (device-quoted) when root is via the su binary, or
        the plain command when the shell is already root (adb root).
        """
        if self._use_su:
            return quote_host_arg("su -c " + shlex.quote(cmd))
        return quote_host_arg(cmd)

    def enable_adb_root(self) -> tuple[bool, str]:
        """Enable ADB root access on the device.

        Runs `adb root` to restart adbd as root, then verifies.

        Returns:
            Tuple of (success, message).
        """
        import time

        try:
            stdout, stderr = Adb.send_adb_command("root")
            combined = (stdout or "") + (stderr or "")

            if "adbd cannot run as root" in combined:
                return False, (
                    "Device does not support adb root. "
                    "Please ensure the device is rooted."
                )

            if "restarting" in combined.lower():
                time.sleep(0.5)

            stdout, _ = Adb.send_adb_command("shell id")
            if "uid=0" in (stdout or ""):
                self._use_su = False
                logger.info("ADB root enabled successfully")
                return True, "ADB root enabled successfully"

            return False, "ADB root command did not grant root access"

        except Exception as e:
            logger.error(f"Error enabling ADB root: {e}")
            return False, f"Error enabling root: {e}"

    def get_cert_spki_hash(self, cert_path: Path) -> str | None:
        """Get the SPKI (Subject Public Key Info) SHA-256 hash of a certificate.

        Used by Chrome's --ignore-certificate-errors-spki-list flag.

        Returns:
            Base64-encoded SPKI hash, or None on error.
        """
        try:
            import base64

            pubkey = subprocess.run(
                ["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"],
                check=True,
                capture_output=True,
                stdin=subprocess.DEVNULL,
            )
            der = subprocess.run(
                ["openssl", "pkey", "-pubin", "-outform", "der"],
                input=pubkey.stdout,
                check=True,
                capture_output=True,
            )
            dgst = subprocess.run(
                ["openssl", "dgst", "-sha256", "-binary"],
                input=der.stdout,
                check=True,
                capture_output=True,
            )
            return base64.b64encode(dgst.stdout).decode("ascii")
        except Exception as e:
            logger.error(f"Failed to compute SPKI hash: {e}")
            return None

    @staticmethod
    def _chrome_is_running_spotlight() -> bool:
        """True if Chrome is the spotlight app and runs (fail safe: True)."""
        try:
            from sandroid.services import get_spotlight_service

            if get_spotlight_service().get_package_name() != "com.android.chrome":
                return False
            from sandroid.services.app_start import Liveness, probe_liveness

            liveness, _pid = probe_liveness("com.android.chrome")
            return liveness != Liveness.NOT_RUNNING
        except Exception:
            return True

    def bypass_chrome_ct(self, cert_path: Path) -> tuple[bool, str]:
        """Bypass Chrome Certificate Transparency enforcement for a CA cert.

        Chrome 99+ enforces CT for system CAs, rejecting mitmproxy certs.
        Writes chrome-command-line files with --ignore-certificate-errors-spki-list
        to skip CT for our specific cert. Covers Chrome, WebView, and
        content-shell variants (same approach as HTTP Toolkit).

        Args:
            cert_path: Path to the CA certificate (PEM).

        Returns:
            Tuple of (success, message).
        """
        spki_hash = self.get_cert_spki_hash(cert_path)
        if not spki_hash:
            return False, "Could not compute SPKI hash (is OpenSSL installed?)"

        flag_line = f"chrome --ignore-certificate-errors-spki-list={spki_hash}"
        logger.info(f"Chrome CT bypass SPKI: {spki_hash}")

        try:
            local_tmp = Path(tempfile.gettempdir()) / "chrome-command-line"
            local_tmp.write_text(flag_line)

            # All 8 locations matching HTTP Toolkit's approach:
            # 4 variants x 2 paths (/data/local + /data/local/tmp)
            variants = [
                "chrome-command-line",
                "android-webview-command-line",
                "webview-command-line",
                "content-shell-command-line",
            ]
            for variant in variants:
                for base in ["/data/local", "/data/local/tmp"]:
                    target = f"{base}/{variant}"
                    try:
                        Adb.send_adb_command(
                            f"push {quote_host_arg(str(local_tmp))} {quote_host_arg(str(target))}"
                        )
                        Adb.send_adb_command(
                            f"shell {self._root_cmd(f'chmod 744 {target}')}"
                        )
                        Adb.send_adb_command(
                            f"shell {self._root_cmd(f'chcon u:object_r:shell_data_file:s0 {target}')}"
                        )
                    except Exception:
                        pass

            local_tmp.unlink(missing_ok=True)

            # On user builds, Chrome only reads flags if set as debug app
            Adb.send_adb_command(
                "shell settings put global debug_app com.android.chrome"
            )

            # Force-stop Chrome so it picks up the new flags on next launch --
            # unless Chrome is the running spotlight app: that is never
            # killed without the user's OK (they restart it with Shift+R).
            if self._chrome_is_running_spotlight():
                logger.info("Chrome CT bypass flags installed (8 locations)")
                return True, (
                    f"Chrome CT bypass installed (SPKI: {spki_hash[:12]}...) "
                    "— Chrome keeps running; restart it (Shift+R) to apply"
                )
            Adb.send_adb_command("shell am force-stop com.android.chrome")

            logger.info("Chrome CT bypass flags installed (8 locations)")
            return True, f"Chrome CT bypass installed (SPKI: {spki_hash[:12]}...)"

        except Exception as e:
            logger.error(f"Chrome CT bypass failed: {e}")
            return False, f"Chrome CT bypass failed: {e}"

    def cert_identity(self, cert_path: Path) -> tuple[str | None, str | None]:
        """Return ``(subject_hash_old, sha256_fingerprint)`` of a host cert.

        Reads PEM or DER. The hash names the file in the Android trust store
        (``<hash>.0``); the fingerprint tells two CAs with the same subject
        apart (every mitmproxy CA is ``CN=mitmproxy`` → ``c8750f0d``).
        Falls back to ``openssl`` for the hash. Never raises.
        """
        try:
            raw = Path(cert_path).read_bytes()
        except OSError:
            return None, None
        ders = _pem_der_certs(raw.decode("latin-1"))
        der = ders[0] if ders else raw
        fingerprint = hashlib.sha256(der).hexdigest()
        cert_hash = _subject_hash_old(der) or self.get_cert_hash(Path(cert_path))
        if not cert_hash:
            return None, None
        return cert_hash, fingerprint

    def ca_spec(self, cert_path: Path | None = None) -> CaSpec | None:
        """Identity and canonical PEM of a host CA (PEM or DER input).

        Defaults to Sandroid's mitmproxy CA (``~/.mitmproxy``). The PEM is
        re-encoded from the DER, so the bytes pushed (and their SHA-256 that
        the device status reports per namespace) never depend on how the
        source file was laid out. Never raises; None when unreadable.
        """
        ref = cert_path if cert_path is not None else self._sandroid_ca_path()
        if ref is None:
            return None
        try:
            raw = Path(ref).read_bytes()
        except OSError:
            return None
        ders = _pem_der_certs(raw.decode("latin-1"))
        der = ders[0] if ders else raw
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization

            pem = x509.load_der_x509_certificate(der).public_bytes(
                serialization.Encoding.PEM
            )
        except Exception:
            return None
        cert_hash = _subject_hash_old(der)
        if not cert_hash:
            return None
        return CaSpec(
            cert_path=Path(ref),
            cert_hash=cert_hash,
            fingerprint=hashlib.sha256(der).hexdigest(),
            pem=pem,
        )

    def _sandroid_ca_path(self) -> Path | None:
        """The host mitmproxy CA Sandroid injects (``~/.mitmproxy``), if any."""
        for info in self.detect_ca_certificates():
            if info.source == CASource.MITMPROXY:
                return info.path
        return None

    def _read_device_cert(self, path: str, ns_pid: int | None = None) -> str | None:
        """``cat`` a trust-store file; inside ``ns_pid``'s mount ns if given.

        Without ``ns_pid`` this needs no root (cacerts are world-readable).
        Returns None when the file is missing or unreadable.
        """
        # A missing file is the normal "CA not installed yet" answer: drop the
        # device-side stderr so it isn't logged as an ADB WARNING.
        if ns_pid is None:
            cmd = f"shell {quote_host_arg(f'cat {path} 2>/dev/null')}"
        else:
            inner = f"nsenter --mount=/proc/{ns_pid}/ns/mnt -- cat {path} 2>/dev/null"
            cmd = f"shell {self._root_cmd(inner)}"
        try:
            stdout, _ = Adb.send_adb_command(cmd)
        except Exception:
            return None
        stdout = stdout or ""
        if not stdout.strip() or "No such file" in stdout:
            return None
        return stdout

    @staticmethod
    def _fingerprint_verdict(content: str, fingerprint: str | None) -> bool | None:
        """True/False = device file is/isn't our CA; None = can't tell."""
        ders = _pem_der_certs(content)
        if not ders or not fingerprint:
            return None
        return any(hashlib.sha256(d).hexdigest() == fingerprint for d in ders)

    # ── CA trust store: inject / status / uninject (no Zygote restart) ──

    @staticmethod
    def _serial(serial: str | None) -> str | None:
        return serial or Adb.get_target_device()

    def _apex_flag(self) -> tuple[str, InjectionStrategy, int | None]:
        """``("1"|"0", strategy, api)``: whether apps read the APEX store."""
        strategy, api_level = self.determine_injection_strategy()
        flag = "1" if strategy == InjectionStrategy.BIND_MOUNT else "0"
        return flag, strategy, api_level

    def _run_ca(self, op: str, args: list[str], serial: str | None) -> tuple[str, int]:
        """Run one CA script operation; ``(stdout, rc)`` (rc -1: no trailer)."""
        out, err = run_device_script(
            _CA_SCRIPT, [op, *args], serial=serial, use_su=self._use_su
        )
        rc = _script_rc(out)
        if rc is None:
            logger.debug("CA script %s gave no rc (stderr: %s)", op, err)
        return out or "", -1 if rc is None else rc

    def _push_stage(self, spec: CaSpec, serial: str | None) -> tuple[bool, str]:
        """Push the canonical PEM to the staging path (unique host temp file)."""
        fd, tmp = tempfile.mkstemp(prefix="sandroid-ca-", suffix=".pem")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(spec.pem)
            out, err = Adb.send_adb_command(
                f"push {quote_host_arg(tmp)} {_CA_STAGE_PATH}", serial=serial
            )
        except Exception as exc:
            return False, f"Could not push the CA to the device: {exc}"
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        text = f"{out}\n{err}".lower()
        if "error" in text or "failed" in text or "timed out" in text:
            return False, f"Could not push the CA to the device: {(err or out).strip()}"
        return True, "staged"

    def _status_for_spec(
        self,
        spec: CaSpec,
        serial: str | None,
        target_pids: tuple[int, ...] = (),
        apex: str | None = None,
    ) -> ZygoteStatus:
        """Read the trust store in Zygote's (and the targets') namespace.

        Never the adb shell's own namespace: that is init's, which holds the
        mounts even when Zygote and the apps do not.
        """
        if not self._check_root_access():
            return ZygoteStatus(
                injected=False,
                cert_hash=spec.cert_hash,
                zygote64_pid=None,
                zygote_pid=None,
                error_message="Root access is needed to read Zygote's trust store",
                verdict="unknown",
            )
        if apex is None:
            apex = self._apex_flag()[0]
        out, _rc = self._run_ca(
            "status", [spec.name, apex, *(str(p) for p in target_pids)], serial
        )
        report = parse_ca_status(out)
        store = self.APEX_CA_PATH if apex == "1" else self.SYSTEM_CA_PATH
        ours = {spec.pem_sha256}
        zygotes = [ns for ns in report.namespaces if ns.role == "zygote"]
        foreign = [ns for ns in zygotes if ns.sha256 and ns.sha256 not in ours]
        if foreign:
            # Our CA in another file layout (an older Sandroid, a manual
            # install): compare the certificate itself, once.
            content = self._read_device_cert(f"{store}/{spec.name}", foreign[0].pid)
            if content and self._fingerprint_verdict(content, spec.fingerprint):
                ours.add(foreign[0].sha256 or "")
        verdict = ca_verdict(report, ours)
        targets = [ns for ns in report.namespaces if ns.role == "target"]
        injected = verdict in ("injected", "partial")
        error = None
        if verdict == "other_ca":
            error = (
                f"{spec.name} in Zygote's trust store is a different CA (same "
                "subject, other key: another mitmproxy install?); inject again "
                "to replace it"
            )
        elif verdict == "absent":
            global _CA_NOT_INSTALLED_LOGGED
            log = logger.debug if _CA_NOT_INSTALLED_LOGGED else logger.info
            _CA_NOT_INSTALLED_LOGGED = True
            log(f"mitmproxy CA ({spec.name}) not installed on the device yet")
        return ZygoteStatus(
            injected=injected,
            cert_hash=spec.cert_hash,
            zygote64_pid=next(
                (ns.pid for ns in zygotes if ns.comm == "zygote64"), None
            ),
            zygote_pid=next((ns.pid for ns in zygotes if ns.comm == "zygote"), None),
            error_message=error,
            location=store if injected else None,
            fingerprint_verified=injected,
            verdict=verdict,
            target_injected=(
                all(ns.sha256 in ours for ns in targets) if targets else None
            ),
            lacking=report.lack or 0,
            init_has_ca=report.our_dev is not None
            and any(
                ns.role == "init" and ns.sha256 in ours for ns in report.namespaces
            ),
        )

    def check_zygote_injection_status(
        self,
        cert_path: Path | None = None,
        target_pid: int | None = None,
        *,
        serial: str | None = None,
    ) -> ZygoteStatus:
        """Whether our CA is in the trust store Zygote and the apps use.

        Reads ``<subject_hash>.0`` of Sandroid's mitmproxy CA (or
        ``cert_path``) inside the namespaces of the Zygote(s), system_server
        and ``target_pid`` (optional, e.g. the spotlight app) in ONE adb call
        and compares its SHA-256 with the canonical PEM. API 34+ reads the
        APEX conscrypt store, API 29-33 the system cacerts dir.

        Args:
            cert_path: Host CA; default Sandroid's mitmproxy CA.
            target_pid: Also check this process's namespace.
            serial: Device; default the current adb target.

        Returns:
            ZygoteStatus; ``verdict`` is one of ``injected``, ``partial``,
            ``other_ca``, ``absent``, ``unknown``.
        """
        spec = self.ca_spec(cert_path)
        if spec is None:
            return ZygoteStatus(
                injected=False,
                cert_hash=None,
                zygote64_pid=None,
                zygote_pid=None,
                error_message=(
                    "No host CA certificate (start mitmproxy once to create "
                    "~/.mitmproxy, or pick a certificate file)"
                ),
                verdict="unknown",
            )
        serial = self._serial(serial)
        targets = (target_pid,) if target_pid else ()
        with _ca_op_lock(serial), Adb.targeting(serial):
            return self._status_for_spec(spec, serial, targets)

    def inject_ca_into_zygote(
        self, cert_path: Path | None = None, *, serial: str | None = None
    ) -> InjectionResult:
        """Make the CA system-wide trusted WITHOUT restarting Zygote.

        One device script (see ``_CA_SCRIPT``) mounts the shared tmpfs in
        init's namespace, binds it into every Zygote first and then into
        every running app's namespace, so running apps, new spawns, Frida
        sessions and system_server all keep their PIDs. Idempotent: a second
        call mounts nothing; another CA under the same name is replaced
        (rotation). Records the CA as this serial's re-inject intent.

        Never restarts anything: when the no-restart path cannot apply (no
        ``nsenter``, a mount fails, Zygote's namespace still lacks the CA)
        the result has ``restart_required=True`` and the caller may offer the
        user-confirmed fallback (:func:`sandroid.services.proxy_restore.
        restart_framework_for_ca`).

        Args:
            cert_path: Host CA (PEM or DER); default Sandroid's mitmproxy CA.
            serial: Device; default the current adb target.

        Returns:
            InjectionResult with outcome details.
        """
        spec = self.ca_spec(cert_path)
        if spec is None:
            return InjectionResult(
                success=False,
                message=(
                    "No CA certificate to inject (start mitmproxy once to create "
                    "~/.mitmproxy, or pick a certificate file)"
                ),
            )
        return self.inject_spec(spec, serial=serial)

    def inject_spec(
        self, spec: CaSpec, *, serial: str | None = None
    ) -> InjectionResult:
        """:meth:`inject_ca_into_zygote` for an already-resolved :class:`CaSpec`."""
        serial = self._serial(serial)
        result = self._inject_spec(spec, serial)
        # Outside the CA lock: the listeners may re-read the device.
        publish_ca_change(serial, True if result.success else None)
        return result

    def _inject_spec(self, spec: CaSpec, serial: str | None) -> InjectionResult:
        """:meth:`inject_spec` body (resolved *serial*)."""
        with _ca_op_lock(serial), Adb.targeting(serial):
            try:
                if not self._check_root_access():
                    return InjectionResult(
                        success=False,
                        message="Root access required. Is the device rooted with 'su'?",
                        needs_root=True,
                    )
                apex, strategy, api_level = self._apex_flag()
                ok, message = self._push_stage(spec, serial)
                if not ok:
                    return InjectionResult(
                        success=False,
                        message=message,
                        strategy=strategy,
                        api_level=api_level,
                    )
                out, rc = self._run_ca(
                    "inject", [_CA_STAGE_PATH, spec.name, apex], serial
                )
                status = self._status_for_spec(spec, serial, apex=apex)
                sweep = re.findall(r"sweep: bound=\d+ already=\d+ failed=\d+", out)
                detail = sweep[0] if sweep else f"API {api_level}, system dir"
                if status.injected:
                    remember_ca_intent(serial, spec)
                    msg = f"CA trusted system-wide without a Zygote restart ({detail})"
                    previous = re.search(r"inject: previous=(\w+)", out)
                    rotated = "inject: replaced=" in out or (
                        previous is not None
                        and previous.group(1) not in ("none", spec.pem_sha256)
                    )
                    if status.verdict == "partial" and status.lacking:
                        msg += (
                            f"; {status.lacking} running namespace(s) missed it "
                            "(new apps trust it)"
                        )
                    if rotated:
                        msg += f". It replaced another CA: {CA_RUNNING_APPS_NOTE}"
                    return InjectionResult(
                        success=True,
                        message=msg,
                        strategy=strategy,
                        api_level=api_level,
                        verdict=status.verdict,
                    )
                errors = [
                    line.strip()
                    for line in out.splitlines()
                    if line.startswith(("inject:", "sweep: failed", "sweep: no"))
                    and ("fail" in line or "missing" in line or " no " in line)
                ]
                why = (
                    errors[-1]
                    if errors
                    else (
                        f"Zygote's namespace does not show the CA ({status.verdict}, "
                        f"script rc {rc})"
                    )
                )
                restart_helps = restart_can_help(rc, status)
                if rc == -1:
                    message = (
                        "The device did not answer the CA install (adb timed out "
                        "or the connection dropped); try again"
                    )
                else:
                    message = (
                        f"Installing the CA without a Zygote restart failed: {why}"
                    )
                    if not restart_helps:
                        message += " (a Zygote restart would not help here)"
                return InjectionResult(
                    success=False,
                    message=message,
                    strategy=strategy,
                    api_level=api_level,
                    restart_required=restart_helps,
                    verdict=status.verdict,
                )
            except Exception as e:
                logger.error(f"Error injecting CA: {e}")
                return InjectionResult(
                    success=False, message=f"Error injecting CA: {e}"
                )

    def uninject_ca(self, *, serial: str | None = None) -> tuple[bool, str]:
        """Remove our CA from the trust store in every namespace.

        Deletes our certificate in the shared tmpfs first (every bind of it,
        also one in a namespace the sweep misses, stops trusting it), then
        unmounts the APEX binds (Zygotes first, two passes, init last) and
        the tmpfs on the system dir, also stacked mounts an older injection
        left, and verifies nothing is left. Clears this serial's re-inject
        intent only when the removal succeeded. Removes any tmpfs on those
        dirs, also a third party's CA overlay. Running apps that already
        validated the CA keep trusting it until they restart.

        Returns:
            ``(ok, message)``.
        """
        serial = self._serial(serial)
        with _ca_op_lock(serial), Adb.targeting(serial):
            if not self._check_root_access():
                return False, "Root access required to remove the CA"
            apex = self._apex_flag()[0]
            out, rc = self._run_ca("uninject", [apex], serial)
            if rc == 0:
                remember_ca_intent(serial, None)
        # Outside the CA lock; a failed removal may still have removed mounts.
        publish_ca_change(serial, False if rc == 0 else None)
        m = re.search(r"unmounted=(\d+) failed=(\d+)", out)
        removed, failed = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
        left = re.search(r"left=(\d+)", out)
        deleted = "uninject: deleted=" in out
        if rc == 0:
            if removed == 0 and not deleted:
                return True, "No CA of Sandroid's was installed"
            return True, (
                f"CA removed from the system trust store ({removed} mounts). "
                f"{CA_RUNNING_APPS_NOTE}"
            )
        if rc == -1:
            return False, (
                "The device did not answer the CA removal (adb timed out or the "
                "connection dropped); try again"
            )
        still = f", {left.group(1)} still mounted" if left else ""
        return False, (
            f"CA removal incomplete ({removed} mounts removed, {failed} failed"
            f"{still}); try again"
        )

    def reconcile_ca(self, serial: str | None) -> str:
        """Re-establish the CA the user injected on *serial* (no restart).

        Only acts when this session injected a CA on that serial. Reads the
        status in Zygote's namespace; anything but ``injected`` is repaired
        with the no-restart inject. Never restarts Zygote (that would kill
        the app a replay just restored). Never raises.

        Returns:
            ``"none"`` (no intent), ``"kept"``, ``"re-injected"`` or
            ``"failed: <why>"``.
        """
        spec = ca_desired_for(serial)
        if spec is None:
            return "none"
        try:
            with _ca_op_lock(serial), Adb.targeting(serial):
                status = self._status_for_spec(spec, serial)
                if status.verdict == "injected":
                    return "kept"
                result = self.inject_spec(spec, serial=serial)
        except Exception as exc:
            return f"failed: {exc}"
        if result.success:
            return "re-injected"
        hint = " (needs a Zygote restart: inject it again from the TUI)"
        return f"failed: {result.message}" + (hint if result.restart_required else "")

    def restart_zygote(self, *, serial: str | None = None) -> int | None:
        """Kill the Zygote(s) whose parent is init (user-confirmed fallback only).

        init restarts them; a later Zygote inherits the CA from init's APEX
        bind. Callers must hold the app-start lifecycle lock and wait for a
        system_server PID change afterwards.

        Returns:
            The system_server PID before the kill (None if unknown).
        """
        return self.kill_zygotes(serial=serial)[0]

    def kill_zygotes(
        self, *, serial: str | None = None
    ) -> tuple[int | None, list[int]]:
        """:meth:`restart_zygote` that also says which Zygotes were killed.

        Returns:
            ``(system_server PID before the kill or None, killed Zygote PIDs)``;
            an empty list means nothing was restarted.
        """
        serial = self._serial(serial)
        with _ca_op_lock(serial), Adb.targeting(serial):
            self._check_root_access()
            out, _rc = self._run_ca("restart-zygote", [], serial)
        m = re.search(r"ss_before=(\d+)", out)
        killed = [int(k) for k in re.findall(r"killed=(\d+)", out)]
        return (int(m.group(1)) if m else None), killed


#: The "CA not installed yet" probe result is logged at INFO once, then DEBUG.
_CA_NOT_INSTALLED_LOGGED = False

#: Sentinel: "the serial adb currently targets" (``None`` is a real value).
_CURRENT_SERIAL = object()
#: Sentinel: "every device" (``None`` is a real value).
_ALL_SERIALS = object()


#: Device script for App Proxy lanes (one ``adb shell`` per operation; the
#: last output line is ``rc=<n>``). gost processes are only ever matched by
#: their exact ``-L red://:<port> `` argument, never ``pkill -f`` (that also
#: hit other sessions' gost and the adb ``sh -c`` wrapper itself).
#:
#:   observe <binary> <tag> <all 0|1> [pkg ...]
#:                                      gost (pid, stdio, argv), listeners,
#:                                      tagged rules (v4/v6, nat/filter; with
#:                                      all=1 every per-UID rule, for devices
#:                                      without xt_comment), ip6tables tables,
#:                                      app UIDs (``unknown`` when the data
#:                                      dir and packages.list are unreadable)
#:   kill <binary> <port> ...           kill the gost of these ports
#:   listening <binary> <port>          wait <=2 s for that gost + listener
#:   flush <uid>                        drop the UID's established TCP sockets
_LANE_SCRIPT = r"""
op=$1
[ $# -gt 0 ] && shift
gost_pids() {
  for p in $(pidof "$1" 2>/dev/null); do
    tr '\0' ' ' </proc/$p/cmdline 2>/dev/null | grep -q -- "-L red://:$2 " && echo $p
  done
}
listeners() { (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | awk 'NR>1 {print $4}'; }
case "$op" in
observe)
  name=${1##*/}; tag=$2; all=$3; shift 3
  pick="$tag"; [ "$all" = 1 ] && pick="--uid-owner "
  for p in $(pidof "$name" 2>/dev/null); do
    c=$(tr '\0' ' ' </proc/$p/cmdline 2>/dev/null) || continue
    echo "GOST pid=$p fd1=$(readlink /proc/$p/fd/1) fd2=$(readlink /proc/$p/fd/2) cmd=$c"
  done
  listeners | sed 's/^/LISTEN /'
  iptables -w -t nat -S OUTPUT 2>/dev/null | grep -- "$pick" | sed 's/^/NAT4 /'
  iptables -w -S OUTPUT 2>/dev/null | grep -- "$pick" | sed 's/^/FILTER4 /'
  if ip6tables -w -S OUTPUT >/dev/null 2>&1; then
    echo "IP6 filter"
    ip6tables -w -S OUTPUT | grep -- "$pick" | sed 's/^/FILTER6 /'
  fi
  if ip6tables -w -t nat -S OUTPUT >/dev/null 2>&1; then
    echo "IP6 nat"
    ip6tables -w -t nat -S OUTPUT | grep -- "$pick" | sed 's/^/NAT6 /'
  fi
  for pkg in "$@"; do
    u=$(stat -c %u /data/data/$pkg 2>/dev/null)
    if [ -z "$u" ]; then
      # The data dir can be unreadable for a moment (CE storage locked
      # right after a boot): only packages.list says the app is gone.
      if [ -r /data/system/packages.list ]; then
        u=$(awk -v p="$pkg" '$1==p { print $2; exit }' /data/system/packages.list)
        [ -n "$u" ] || u=missing
      else
        u=unknown
      fi
    fi
    echo "UID $pkg $u"
  done
  ;;
kill)
  name=${1##*/}; shift
  for port in "$@"; do
    for p in $(gost_pids "$name" "$port"); do kill $p && echo "killed=$p"; done
  done
  true
  ;;
listening)
  name=${1##*/}; port=$2; i=0
  while [ $i -lt 20 ]; do
    if [ -n "$(gost_pids "$name" "$port")" ] && listeners | grep -q "[:.]$port\$"; then
      echo LISTENING; break
    fi
    sleep 0.1; i=$((i+1))
  done
  true
  ;;
flush)
  uid=$1; n=0
  for pp in $(ss -tnae 2>/dev/null | awk -v u="uid:$uid" '$1=="ESTAB" { for (i=1;i<=NF;i++) if ($i==u) { k=split($4,a,":"); m=split($5,b,":"); print a[k] "/" b[m]; break } }'); do
    sp=${pp%/*}; dp=${pp#*/}
    sel="( sport = :$sp and dport = :$dp )"
    # Only when every socket the filter selects is this UID's: ss -K has no
    # UID match, and another app may share that port pair.
    other=$(ss -tnae "$sel" 2>/dev/null | awk -v u="uid:$uid" 'NR>1 && NF { own=0; for (i=1;i<=NF;i++) if ($i==u) own=1; if (!own) print }')
    [ -z "$other" ] || continue
    ss -K -tn "$sel" >/dev/null 2>&1 && n=$((n+1))
  done
  echo "flushed=$n"
  ;;
*) echo "usage: observe|kill|listening|flush"; false ;;
esac
echo "rc=$?"
"""


@dataclass(frozen=True)
class RuleKey:
    """A lane rule, normalised from an ``iptables -S`` line or our own spec.

    ``target`` is ``REDIRECT`` or ``BLOCK`` (REJECT and the DROP fallback
    count as the same block).
    """

    family: str  # "4" | "6"
    table: str  # "nat" | "filter"
    proto: str
    uid: int
    dport: int | None
    target: str
    to_port: int | None = None


_RULE_KINDS = {
    "NAT4": ("4", "nat"),
    "FILTER4": ("4", "filter"),
    "NAT6": ("6", "nat"),
    "FILTER6": ("6", "filter"),
}


def parse_rule_key(kind: str, line: str) -> RuleKey | None:
    """Normalise one tagged ``iptables -S`` line (pure; None if not a lane rule)."""
    family_table = _RULE_KINDS.get(kind)
    if family_table is None:
        return None
    uid = re.search(r"--uid-owner (\d+)", line)
    target = re.search(r"-j (\w+)", line)
    if not uid or not target:
        return None
    proto = re.search(r"-p (\w+)", line)
    dport = re.search(r"--dport (\d+)", line)
    to_port = re.search(r"--to-ports (\d+)", line)
    jump = target.group(1)
    return RuleKey(
        family=family_table[0],
        table=family_table[1],
        proto=proto.group(1) if proto else "all",
        uid=int(uid.group(1)),
        dport=int(dport.group(1)) if dport else None,
        target="REDIRECT" if jump == "REDIRECT" else "BLOCK",
        to_port=int(to_port.group(1)) if to_port else None,
    )


@dataclass
class GostProc:
    """One running gost as the observe script saw it."""

    pid: int
    fd1: str
    fd2: str
    cmd: str

    def port(self) -> int | None:
        """The ``red://`` listener port of this gost, if any."""
        m = re.search(r"-L red://:(\d+)", self.cmd)
        return int(m.group(1)) if m else None

    @property
    def doomed(self) -> bool:
        """Stdio still on an adb session: dies (SIGPIPE) at its first log line."""
        return any(
            fd.startswith(("socket:", "pipe:", "/dev/pts"))
            for fd in (self.fd1, self.fd2)
        )


@dataclass
class LaneObservation:
    """Device truth for the App Proxy lanes of one serial."""

    gosts: list[GostProc] = field(default_factory=list)
    listening: set[int] = field(default_factory=set)
    rules: list[tuple[str, str]] = field(default_factory=list)
    ip6_filter: bool = False
    ip6_nat: bool = False
    uids: dict[str, int | None] = field(default_factory=dict)
    #: Packages whose UID could not be read (data dir and packages.list
    #: unreadable): NOT "uninstalled", their lane is left as it is.
    uid_unknown: set[str] = field(default_factory=set)


def parse_lane_observation(output: str) -> LaneObservation:
    """Parse the lane script's ``observe`` output (pure; never raises)."""
    obs = LaneObservation()
    for raw in (output or "").splitlines():
        line = raw.strip()
        kind, _, rest = line.partition(" ")
        if kind == "GOST":
            m = re.match(r"pid=(\d+) fd1=(\S*) fd2=(\S*) cmd=(.*)$", rest)
            if m:
                obs.gosts.append(
                    GostProc(
                        int(m.group(1)), m.group(2), m.group(3), m.group(4).strip()
                    )
                )
        elif kind == "LISTEN":
            port = rest.rsplit(":", 1)[-1]
            if port.isdigit():
                obs.listening.add(int(port))
        elif kind in _RULE_KINDS:
            obs.rules.append((kind, rest.strip()))
        elif kind == "IP6":
            if rest.strip() == "filter":
                obs.ip6_filter = True
            elif rest.strip() == "nat":
                obs.ip6_nat = True
        elif kind == "UID":
            pkg, _, value = rest.partition(" ")
            value = value.strip()
            obs.uids[pkg] = int(value) if value.isdigit() else None
            if value == "unknown":
                obs.uid_unknown.add(pkg)
    return obs


def desired_rule_keys(
    uid: int, port: int, *, quic: bool, ip6_filter: bool, ip6_nat: bool
) -> set[RuleKey]:
    """Every rule one lane needs (pure).

    IPv4 TCP is redirected to the lane's gost. IPv6 has no nat table on most
    Android kernels, so v6 TCP is REJECTed (tcp-reset) instead: fail closed,
    never a silent bypass past mitmproxy. With a v6 nat table it is
    redirected like v4 (a filter REJECT would then reject the redirected
    connection too). QUIC (UDP/443) is blocked on both families while
    ``focus.block_quic`` is on.
    """
    keys = {RuleKey("4", "nat", "tcp", uid, None, "REDIRECT", port)}
    if ip6_nat:
        keys.add(RuleKey("6", "nat", "tcp", uid, None, "REDIRECT", port))
    elif ip6_filter:
        keys.add(RuleKey("6", "filter", "tcp", uid, None, "BLOCK"))
    if quic:
        keys.add(RuleKey("4", "filter", "udp", uid, 443, "BLOCK"))
        if ip6_filter:
            keys.add(RuleKey("6", "filter", "udp", uid, 443, "BLOCK"))
    return keys


@dataclass
class LanePlan:
    """What a reconcile has to do for one lane (pure planning result)."""

    lane: int
    package: str
    port: int
    uid: int | None
    app_missing: bool = False
    #: The UID could not be read and none is known: the lane is left alone.
    uid_unknown: bool = False
    kill: list[int] = field(default_factory=list)
    launch: bool = False
    add: set[RuleKey] = field(default_factory=set)
    why: list[str] = field(default_factory=list)


@dataclass
class DesiredLane:
    """A lane the user asked for (host-side desired state)."""

    lane: int
    package: str
    port: int
    upstream: str
    #: The UID the lane was built for (used when the device cannot say).
    uid_hint: int | None = None


def plan_lanes(
    desired: list[DesiredLane],
    obs: LaneObservation,
    *,
    binary: str,
    port_range: range,
    quic: bool,
) -> tuple[list[LanePlan], list[int], list[tuple[str, str]]]:
    """Diff desired lanes against device truth (pure).

    Returns:
        ``(plans, orphan_gost_pids, stale_rules)``: one plan per desired
        lane; gost on OUR port range that no lane wants (never one outside
        it); tagged rules no desired lane needs (another snapshot's lane set,
        a reinstalled app's old UID, a lane of an app that is gone). An app
        whose UID could not be read is not taken for uninstalled: its last
        known UID is used, and without one nothing stale is removed.
    """
    plans: list[LanePlan] = []
    wanted: set[RuleKey] = set()
    wanted_ports = {d.port for d in desired}
    hold_stale = False
    for d in desired:
        uid = obs.uids.get(d.package)
        unknown = uid is None and d.package in obs.uid_unknown
        if unknown and d.uid_hint is not None:
            uid = d.uid_hint
        plan = LanePlan(lane=d.lane, package=d.package, port=d.port, uid=uid)
        on_port = [g for g in obs.gosts if g.port() == d.port]
        if unknown and uid is None:
            plan.uid_unknown = True
            plan.why.append("the app's UID could not be read")
            hold_stale = True
            plans.append(plan)
            continue
        if unknown:
            plan.why.append("the app's UID could not be read; kept its last UID")
        if uid is None:
            plan.app_missing = True
            plan.kill = [g.pid for g in on_port]
            plans.append(plan)
            continue
        exact = f"{binary} -L red://:{d.port} -F {d.upstream}"
        healthy = [g for g in on_port if g.cmd.strip() == exact and not g.doomed]
        keep = healthy[0] if healthy else None
        if keep is not None and d.port not in obs.listening:
            plan.why.append("gost not listening")
            keep = None
        for g in on_port:
            if g is keep:
                continue
            plan.kill.append(g.pid)
            if g.doomed:
                plan.why.append(f"gost {g.pid} bound to an old adb session")
            elif g.cmd.strip() != exact:
                plan.why.append(f"gost {g.pid} has another upstream")
            elif keep is not None:
                plan.why.append(f"duplicate gost {g.pid}")
        if keep is None:
            plan.launch = True
            if not on_port:
                plan.why.append("gost not running")
        keys = desired_rule_keys(
            uid, d.port, quic=quic, ip6_filter=obs.ip6_filter, ip6_nat=obs.ip6_nat
        )
        wanted |= keys
        present = {parse_rule_key(k, line) for k, line in obs.rules}
        plan.add = keys - present
        if plan.add:
            plan.why.append(f"{len(plan.add)} rule(s) missing")
        plans.append(plan)
    orphans = [
        g.pid
        for g in obs.gosts
        if g.port() in port_range and g.port() not in wanted_ports
    ]
    stale = [
        (kind, line)
        for kind, line in obs.rules
        if (key := parse_rule_key(kind, line)) is not None and key not in wanted
    ]
    if hold_stale:
        stale = []
    return plans, orphans, stale


#: ``time.time()`` of the last mitmproxy start (see
#: :func:`note_mitmproxy_started`): an "unreachable" verdict checked before
#: it is stale.
_MITMPROXY_STARTED_AT = 0.0


def note_mitmproxy_started() -> None:
    """Record that our mitmproxy (re)started: older "unreachable" verdicts of
    App Proxy lanes no longer count until the lanes are probed again.
    """
    global _MITMPROXY_STARTED_AT
    _MITMPROXY_STARTED_AT = time.time()


@dataclass
class _UpstreamProbe:
    """A device-side SOCKS probe deferred until FocusManager's lock is free."""

    lane: int
    package: str
    serial: str | None
    host: str
    port: int


#: Lane health states (``LaneHealth.state``).
LANE_ACTIVE = "active"
LANE_WAITING = "waiting"
LANE_UNREACHABLE = "unreachable"
LANE_FAILED = "failed"


@dataclass
class LaneHealth:
    """Last known health of one App Proxy lane (for status bar, panel, AI)."""

    state: str
    detail: str = ""
    checked_at: float = 0.0

    @property
    def label(self) -> str:
        """Plain words for the UI (no symbols)."""
        if self.state == LANE_ACTIVE:
            return "active"
        if self.state == LANE_WAITING:
            return "waiting for mitmproxy"
        if self.state == LANE_UNREACHABLE:
            return "mitmproxy unreachable from the device"
        return f"failed: {self.detail}" if self.detail else "failed"

    @property
    def ok(self) -> bool:
        """Traffic flows through the lane right now."""
        return self.state == LANE_ACTIVE


@dataclass
class LaneReport:
    """Outcome of a reconcile for one lane."""

    package: str
    lane: int
    health: LaneHealth
    repaired: list[str] = field(default_factory=list)


@dataclass
class _LaneEnabled:
    """``enable_focus`` outcome whose upstream probe may still be pending.

    ``label`` is None for an app that was already proxied (reconciled).
    """

    report: LaneReport
    label: str | None


class FocusManager:
    """Per-app proxy ("App Proxies") lane pool.

    Each app proxy gets its own *lane*: a full vertical slice of app UID →
    on-device iptables REDIRECT port → its own ``gost`` redirector. gost's
    ``red://`` listener forwards to the lane's upstream — our host mitmproxy
    SOCKS5 port (the default; the arrival SOCKS port *is* the app identity the
    mitmproxy addon reads to label flows) or an external HTTP proxy (Burp/ZAP).

    App Proxies coexist with the global Device Proxy: the per-UID REDIRECT
    short-circuits in the kernel before the userspace ``http_proxy`` is read, so
    a proxied app follows its lane and everyone else follows the device proxy —
    no double-capture.

    Composition (not inheritance): the reused root/host helpers live on two
    different classes, so this class holds a :class:`CAManager` (for
    ``_check_root_access``/``_root_cmd``/``_use_su`` root-command wrapping) and
    uses :meth:`ProxyManager.get_host_ip`.

    Lane ``i`` (0-based) uses fixed ports:
        host SOCKS5 port   = ``mitmproxy.socks_base + i`` (our-mitmproxy lanes)
        device REDIRECT port = ``focus.redirect_base + i``

    The pool size ``N`` is ``mitmproxy.focus_lanes``. All mutating public
    methods are guarded by a single :class:`threading.Lock`. (The class and its
    ``enable_focus``/``focused_apps`` API keep their internal names for
    continuity; user-facing surfaces say "App Proxies".)
    """

    # Valid mitmproxy ``flow.marked`` emoji keys (any other non-empty string
    # collapses to a single red dot, so the per-app palette must use these).
    PALETTE = [
        ":green_circle:",
        ":large_blue_circle:",
        ":purple_circle:",
        ":orange_circle:",
        ":yellow_circle:",
        ":brown_circle:",
        ":red_circle:",
        ":black_circle:",
    ]

    _RULE_TAG = "sandroid-focus"

    def __init__(self) -> None:
        """Initialize the lane pool and register crash-safe cleanup."""
        self._lock = threading.Lock()
        self._ca = CAManager()
        # lane index 0..N-1 → package or None (free). Sized lazily from config.
        self._lanes: dict[int, str | None] = {}
        # Per-lane upstream target chosen by the user: "ours" (our mitmproxy,
        # the default) or an external "http://host:port". Parallel to _lanes;
        # session-ephemeral (never persisted — lanes are live state).
        self._lane_targets: dict[int, str] = {}
        # Per-lane exact iptables rule specs to delete on teardown (populated
        # when xt_comment is unavailable and we fall back to tuple-match).
        self._lane_rule_specs: dict[int, list[tuple[str, str]]] = {}
        # Per-lane app UID, recorded at enable so set_quic_blocking() can
        # add/remove the QUIC REJECT for a live lane without re-resolving it.
        # Tracked/cleared exactly like _lane_rule_specs/_lane_targets so a
        # freed or reused lane never carries a stale uid.
        self._lane_uids: dict[int, int] = {}
        # Per-lane filter-table QUIC-block (UDP/443 REJECT) rule specs, kept
        # separate from _lane_rule_specs (which are nat REDIRECT rules) so the
        # toggle can add/remove just the QUIC rules.
        self._lane_quic_specs: dict[int, list[tuple[str, str]]] = {}
        # Per-lane device serial the lane's gost/iptables live on. Lanes are
        # torn down on THAT device (Adb.targeting), never on whatever device
        # happens to be selected later, and are looked up per serial.
        self._lane_serials: dict[int, str | None] = {}
        # Per-lane gost ``-F`` upstream as launched (reconcile relaunches it).
        self._lane_upstreams: dict[int, str] = {}
        # Per-lane last known health (reconcile / enable), see LaneHealth.
        self._lane_health: dict[int, LaneHealth] = {}
        # Serials whose /data/local/tmp/gost matches the host binary.
        self._binary_ok: set[str | None] = set()
        # cleanup_stale() runs once per device at its first enable.
        self._cleaned_serials: set[str | None] = set()
        # serial -> (ip6tables filter table usable, ip6tables nat usable).
        # Most Android kernels have v6 filter but no v6 nat; a world change
        # (snapshot load, cold boot) re-probes.
        self._ip6_cap_cache: dict[str | None, tuple[bool, bool]] = {}
        # Serials with an ip6tables nat table whose v6 REDIRECT failed: v6
        # TCP is REJECTed there instead (never a leak). A world change
        # re-probes.
        self._ip6_redirect_broken: set[str | None] = set()
        # Serials where lane rules had to be added without the tag (no
        # xt_comment): observe then lists every per-UID rule.
        self._untagged_serials: set[str | None] = set()
        # serial -> every lane UID used there this session (recognises our
        # untagged rules).
        self._uids_used: dict[str | None, set[int]] = {}
        # Last values read for the UI thread, which must never wait on
        # self._lock (a reconcile holds it across adb work).
        self._routes_cache: dict[str, str] = {}
        self._health_cache: dict[str | None, dict[str, LaneHealth]] = {}
        atexit.register(self._atexit_cleanup)

    # ── config helpers ────────────────────────────────────────────────

    @property
    def _pool_size(self) -> int:
        """Number of lanes (``mitmproxy.focus_lanes``)."""
        try:
            if get_config is not None:
                return int(get_config().mitmproxy.focus_lanes)
        except Exception:
            pass
        return 5

    @property
    def _socks_base(self) -> int:
        """The lanes' first SOCKS port: the running mitmweb's, else the
        configured one (the default follows the proxy port, so a second
        Sandroid instance does not share 8082-8086).
        """
        try:
            from sandroid.services.mitmproxy_service import (
                effective_socks_base,
                peek_mitmproxy_service,
            )

            svc = peek_mitmproxy_service()
            if svc is not None and svc.is_running():
                return int(svc.state.socks_base)
            if get_config is not None:
                return effective_socks_base(get_config().mitmproxy)
        except Exception:
            pass
        return 8082

    @property
    def _redirect_base(self) -> int:
        try:
            if get_config is not None:
                return int(get_config().focus.redirect_base)
        except Exception:
            pass
        return 60080

    @property
    def _binary_dst(self) -> str:
        try:
            if get_config is not None:
                return get_config().focus.gost_binary_dst
        except Exception:
            pass
        return "/data/local/tmp/gost"

    def _quic_blocking_enabled(self) -> bool:
        """Whether new lanes should REJECT QUIC (``focus.block_quic``)."""
        try:
            if get_config is not None:
                return bool(get_config().focus.block_quic)
        except Exception:
            pass
        return True

    def _socks_port(self, lane: int) -> int:
        return self._socks_base + lane

    def _redirect_port(self, lane: int) -> int:
        return self._redirect_base + lane

    def _marker(self, lane: int) -> str:
        return self.PALETTE[lane % len(self.PALETTE)]

    def _ensure_lanes(self) -> None:
        """Materialize the lane dict to the current pool size (free slots)."""
        n = self._pool_size
        for i in range(n):
            self._lanes.setdefault(i, None)
        # Drop any lanes beyond the (possibly shrunk) pool that are free.
        for i in list(self._lanes):
            if i >= n and self._lanes[i] is None:
                self._lanes.pop(i, None)
                self._lane_rule_specs.pop(i, None)
                self._lane_targets.pop(i, None)
                self._lane_uids.pop(i, None)
                self._lane_quic_specs.pop(i, None)
                self._lane_serials.pop(i, None)
                self._lane_upstreams.pop(i, None)
                self._lane_health.pop(i, None)

    # ── public API ────────────────────────────────────────────────────

    def enable_focus(
        self, package: str | None = None, target: str | None = None
    ) -> tuple[bool, str]:
        """Assign an app-proxy lane to ``package`` (fail-closed order).

        Resolves the package (falling back to the spotlight app), allocates a
        free lane, then: IPv6 fence + QUIC block first, the detached gost
        redirector next (confirmed listening), the IPv4 REDIRECT last, so the
        app never talks to the network past mitmproxy while the lane is being
        built. Afterwards the app's open TCP sockets are dropped: pooled
        keep-alive connections opened before the lane would otherwise keep
        bypassing it.

        A package that is already proxied on this device is reconciled
        against the device instead (a dead or stale lane is repaired). With
        our mitmproxy not running the lane stays applied and fails closed
        (the app has no network) and reports "waiting for mitmproxy"; it
        works on its own once mitmproxy runs.

        Args:
            package: Target package, or None to use the spotlight app.
            target: Lane upstream — ``None`` routes to our mitmproxy (default);
                an ``http://host:port`` (or bare ``host:port``) string routes the
                app to an external HTTP proxy (Burp/ZAP). The host is resolved to
                an IP host-side before gost launches.

        Returns:
            ``(ok, message)``.
        """
        deferred: list[_UpstreamProbe] = []
        with self._lock:
            serial = Adb.get_target_device()
            # Every device call of this enable goes to the serial it started
            # on, even if the selected device changes meanwhile.
            with Adb.targeting(serial):
                outcome = self._enable_locked(package, target, serial, deferred)
        if not isinstance(outcome, _LaneEnabled):
            return outcome
        report, label = outcome.report, outcome.label
        if deferred:
            self._finish_probes(deferred, [report])
        self._publish_health()
        if label is None:
            return self._report_message(report)
        message = f"App proxy → {label} (lane {report.lane})"
        if not report.health.ok:
            message += f": {self._health_sentence(report.health)}"
        return True, message

    def _enable_locked(
        self,
        package: str | None,
        target: str | None,
        serial: str | None,
        deferred: list[_UpstreamProbe],
    ) -> tuple[bool, str] | _LaneEnabled:
        """:meth:`enable_focus` body (lock held, adb pinned to *serial*).

        Returns:
            ``(ok, message)`` when finished, or a :class:`_LaneEnabled` for a
            lane whose upstream probe may still be pending.
        """
        self._ensure_lanes()

        # 1. Resolve package.
        if not package:
            package = self._spotlight_package()
        if not package:
            return False, "No spotlight app set — pick one first."
        if not is_valid_package_name(package):
            return False, f"Invalid package name {package!r}."

        # 2. Already proxied (on THIS device): verify against the device
        #    and repair (Ctrl+S with an unchanged list used to be a no-op
        #    even when gost had died).
        existing = self._lane_index_for(package, serial)
        if existing is not None:
            reports = self._reconcile_locked(serial, "apply", deferred)
            report = next((r for r in reports if r.lane == existing), None)
            if report is None:
                return True, f"{package} already proxied"
            return _LaneEnabled(report, None)
        free = self._first_free_lane()
        if free is None:
            n = self._pool_size
            return False, (
                f"All {n} app-proxy lanes in use — remove an app or raise "
                "mitmproxy.focus_lanes."
            )

        # 3. Root probe (sets _use_su, required by every device command
        #    below — including the stale-rule cleanup, which must wrap with
        #    the right su/non-su form to actually clear leftovers).
        if not self._ca._check_root_access():
            return False, "Focus requires root (su)."

        # 4. Housekeeping: clear stale rules/processes once per session.
        if serial not in self._cleaned_serials:
            self._cleanup_stale_locked()
            self._cleaned_serials.add(serial)

        # 5. owner-match capability probe.
        ok, msg = self._probe_owner_match()
        if not ok:
            return False, msg

        # 6. Resolve UID.
        uid = self._resolve_uid(package)
        if uid is None:
            return False, f"Could not resolve Linux UID for {package}."

        # 7. Ensure the gost binary is on this device.
        ok, msg = self._ensure_binary()
        if not ok:
            return False, msg

        lane = free
        redirect_port = self._redirect_port(lane)

        # 8. Resolve the lane's upstream host-side BEFORE launching, so a bad
        #    external target fails loud without leaving a half-applied lane.
        ok, upstream = self._build_upstream(target, lane)
        if not ok:
            return False, upstream  # upstream holds the error message
        lane_target = "ours" if target is None else upstream

        # 9. Fail closed first: IPv6 fence and QUIC block before anything
        #    can redirect, so no v6 or HTTP/3 packet leaks meanwhile.
        self._lane_uids[lane] = uid
        self._uids_used.setdefault(serial, set()).add(uid)
        self._ensure_v6_fence(lane, uid)
        if self._quic_blocking_enabled():
            self._add_quic_block(lane, uid)

        # 10. The detached gost redirector (any leftover on the port first).
        self._kill_lane_process(redirect_port)
        self._launch_gost(redirect_port, upstream)
        if not self._wait_listening(redirect_port):
            self._remove_lane_rules(lane)
            self._kill_lane_process(redirect_port)
            self._lane_uids.pop(lane, None)
            return False, f"gost failed to bind port {redirect_port}."

        # 11. The IPv4 REDIRECT LAST (fatal: roll back on failure so a
        #     redirector never runs without a working rule).
        ok, msg = self._ensure_redirect(lane, uid, redirect_port)
        if not ok:
            self._remove_lane_rules(lane)
            self._kill_lane_process(redirect_port)
            self._lane_uids.pop(lane, None)
            return False, msg

        # 12. Commit lane state, target, sidecar, and shared MitmproxyState.
        self._lanes[lane] = package
        self._lane_targets[lane] = lane_target
        self._lane_upstreams[lane] = upstream
        self._lane_serials[lane] = serial
        health = self._upstream_health(lane, probe=True, deferred=deferred)
        self._lane_health[lane] = health
        _install_restore_hook()
        self._flush_app_sockets(uid)
        self._write_sidecar()
        self._add_to_state(package)
        dest = "our mitmproxy" if target is None else upstream
        # Routine (the user added an App Proxy): INFO, not WARNING.
        logger.info(
            "App proxy lane %d → %s (uid %s) upstream %s",
            lane,
            package,
            uid,
            dest,
        )
        label = package if target is None else f"{package} → {upstream}"
        return _LaneEnabled(LaneReport(package, lane, health), label)

    @staticmethod
    def _health_sentence(health: LaneHealth) -> str:
        """One sentence about a lane that does not pass traffic right now."""
        if health.state == LANE_WAITING:
            return "waiting for mitmproxy, the app has no network until mitmproxy runs"
        if health.state == LANE_UNREACHABLE:
            return (
                "mitmproxy is not reachable from the device, the app has no "
                "network until it is"
            )
        return health.label

    def _report_message(self, report: LaneReport) -> tuple[bool, str]:
        """``(ok, message)`` for a reconciled lane (``enable_focus`` callers)."""
        what = (
            f"repaired ({', '.join(report.repaired)})"
            if report.repaired
            else "already proxied"
        )
        if report.health.state == LANE_FAILED:
            return False, f"{report.package}: {report.health.label}"
        if report.health.ok:
            return True, f"{report.package} {what}"
        return True, f"{report.package} {what}: {self._health_sentence(report.health)}"

    def disable_focus(self, package: str | None = None) -> tuple[bool, str]:
        """Free one lane (by package) or ALL lanes (``package=None``).

        Rules-first removal then process kill, so iptables never points at a
        dead port. Idempotent: freeing an already-free lane / disabling when
        nothing is active is a harmless no-op.

        Args:
            package: Package to unfocus, or None to free every lane.

        Returns:
            ``(ok, message)``.
        """
        with self._lock:
            self._ensure_lanes()
            if package is None:
                targets = [i for i, p in self._lanes.items() if p is not None]
                if not targets:
                    return True, "No app proxies to disable"
                for lane in targets:
                    self._teardown_lane(lane)
                self._write_sidecar()
                message = "App proxies disabled (all lanes freed)"
            else:
                lane = self._lane_index_for(package)
                if lane is None:
                    return True, f"{package} has no app proxy"
                self._teardown_lane(lane)
                self._write_sidecar()
                message = f"App proxy removed for {package}"
        # Outside the lock: the lens caption and glance re-read the lanes.
        self._publish_health()
        return True, message

    def release_serial(self, serial: str | None) -> int:
        """Tear down every lane that lives on *serial* (e.g. on device switch).

        The rules and gost processes are removed on that device explicitly
        (``Adb.targeting``), whatever device is selected meanwhile.

        Returns:
            The number of lanes released.
        """
        with self._lock:
            lanes = [
                lane
                for lane, pkg in self._lanes.items()
                if pkg and self._lane_serials.get(lane) == serial
            ]
            for lane in lanes:
                self._teardown_lane(lane)
            if lanes:
                self._write_sidecar()
            self._cleaned_serials.discard(serial)
        if lanes:
            self._publish_health()
        return len(lanes)

    def ensure_gost(self, serial: str | None) -> tuple[bool, str]:
        """Make sure *serial* has the gost binary (root needed; blocking).

        Public for the identity relay (``core.device_guard``), which runs the
        same binary.
        """
        with self._lock, Adb.targeting(serial):
            if not self._ca._check_root_access():
                return False, "root is needed for gost"
            return self._ensure_binary()

    def focused_apps(self) -> list[str]:
        """Return the packages currently assigned to a lane."""
        with self._lock:
            return [p for p in self._lanes.values() if p]

    def app_proxies(self) -> dict[str, str]:
        """Return ``{package: "ours" | "http://ip:port"}`` for live lanes.

        ``"ours"`` means the app routes to our mitmproxy; an ``http://`` value is
        the resolved external HTTP-proxy upstream (Burp/ZAP). In-process read.
        """
        with self._lock:
            return {
                pkg: self._lane_targets.get(lane, "ours")
                for lane, pkg in self._lanes.items()
                if pkg
            }

    def app_proxies_nonblocking(self, timeout: float = 0.05) -> dict[str, str] | None:
        """Best-effort :meth:`app_proxies` read that never blocks the caller.

        ``enable_focus``/``disable_focus``/``set_quic_blocking`` hold
        ``self._lock`` for their entire (potentially multi-second) body — root
        probes, binary pushes, listen polling, a device-reachability probe,
        iptables installs. A plain :meth:`app_proxies` call from a per-turn hot
        path (the ambient-context builder) would block for however long a
        concurrent mutation elsewhere takes. This returns ``None`` on lock
        contention instead of blocking; callers needing a guaranteed read
        should use :meth:`app_proxies` instead.

        Args:
            timeout: Max seconds to wait for the lock before giving up.

        Returns:
            The same ``{package: "ours" | "http://ip:port"}`` shape as
            :meth:`app_proxies`, or ``None`` if the lock could not be
            acquired within ``timeout``.
        """
        if not self._lock.acquire(timeout=timeout):
            return None
        try:
            self._routes_cache = self._routes_locked()
            return dict(self._routes_cache)
        finally:
            self._lock.release()

    def _routes_locked(self) -> dict[str, str]:
        return {
            pkg: self._lane_targets.get(lane, "ours")
            for lane, pkg in self._lanes.items()
            if pkg
        }

    def app_proxies_cached(
        self, serial: str | None | object = _ALL_SERIALS
    ) -> dict[str, str]:
        """:meth:`app_proxies` for the UI thread: never waits for the lock.

        The current value when the lock is free, else the last value read
        (a reconcile holds the lock across seconds of adb work). With
        *serial*, only the lanes that live on that device.
        """
        if self._lock.acquire(blocking=False):
            try:
                self._routes_cache = self._routes_locked()
                self._route_serials_cache = {
                    pkg: self._lane_serials.get(lane)
                    for lane, pkg in self._lanes.items()
                    if pkg
                }
            finally:
                self._lock.release()
        routes = dict(self._routes_cache)
        if serial is _ALL_SERIALS:
            return routes
        serials = getattr(self, "_route_serials_cache", {})
        return {pkg: t for pkg, t in routes.items() if serials.get(pkg) == serial}

    def lane_health_cached(
        self, serial: str | None | object = _CURRENT_SERIAL
    ) -> dict[str, LaneHealth]:
        """:meth:`lane_health` for the UI thread (last value on contention)."""
        if serial is _CURRENT_SERIAL:
            serial = Adb.get_target_device()
        if self._lock.acquire(blocking=False):
            try:
                self._health_cache[serial] = self._health_snapshot(serial)
            finally:
                self._lock.release()
        return dict(self._health_cache.get(serial, {}))

    def lane_for(self, package: str) -> int | None:
        """Return the host SOCKS port serving ``package``, or None."""
        with self._lock:
            lane = self._lane_index_for(package)
            return None if lane is None else self._socks_port(lane)

    def is_focus_active(self) -> bool:
        """Whether any lane is currently assigned."""
        with self._lock:
            return any(p for p in self._lanes.values())

    # ── reconcile against device truth ────────────────────────────────

    def has_lanes(self, serial: str | None | object = _CURRENT_SERIAL) -> bool:
        """Whether any lane is desired on *serial* (default: current target)."""
        if serial is _CURRENT_SERIAL:
            serial = Adb.get_target_device()
        with self._lock:
            return any(
                pkg and self._lane_serials.get(lane) == serial
                for lane, pkg in self._lanes.items()
            )

    def reconcile(
        self, serial: str | None = None, reason: str = ""
    ) -> list[LaneReport]:
        """Bring the lanes of *serial* in line with what the user asked for.

        Reads the device in ONE adb call (gost PIDs with their argv and stdio,
        listeners, tagged v4/v6 rules, app UIDs) and repairs only what
        differs, in fail-closed order: first every missing protective rule
        (IPv6 fence, QUIC block AND the IPv4 REDIRECT, which a dead or
        missing gost turns into a refused connection), then stale rules and
        dead, doomed (stdio on an old adb session), duplicate or orphan
        gost, then the binary check and the detached relaunch. A failed
        relaunch keeps the REDIRECT (fail closed). A lane whose app is gone
        (packages.list says so) is torn down on the device and reported as
        failed (the lane stays requested); an unreadable UID is not "gone".
        With our mitmproxy off a lane stays applied and reports "waiting
        for mitmproxy". The upstream probe runs after the lock is released.
        Blocking (adb): never call it on the UI thread.

        Args:
            serial: Device; default the current adb target.
            reason: Why (``apply``, ``snapshot-load``, ``cold-boot``,
                ``reconnect``, ``mitmproxy-start`` ...). A world change also
                re-probes the ip6tables capabilities.

        Returns:
            One :class:`LaneReport` per lane on that serial.
        """
        deferred: list[_UpstreamProbe] = []
        with self._lock:
            reports = self._reconcile_locked(serial, reason, deferred)
        if deferred:
            # Outside the lock: the SOCKS probe takes seconds.
            self._finish_probes(deferred, reports)
        if reports:
            self._publish_health()
        return reports

    #: Reasons after which the device's kernel/tables may differ.
    _WORLD_CHANGES = ("snapshot-load", "cold-boot", "framework-restart")

    def _reconcile_locked(
        self,
        serial: str | None,
        reason: str,
        deferred: list[_UpstreamProbe] | None = None,
    ) -> list[LaneReport]:
        """:meth:`reconcile` with ``self._lock`` held (probes go to *deferred*)."""
        if serial is None:
            serial = Adb.get_target_device()
        self._ensure_lanes()
        lanes = [
            lane
            for lane, pkg in self._lanes.items()
            if pkg and self._lane_serials.get(lane) == serial
        ]
        if not lanes:
            return []
        now = time.time()
        if reason in self._WORLD_CHANGES:
            self._ip6_cap_cache.pop(serial, None)
            self._ip6_redirect_broken.discard(serial)
            self._binary_ok.discard(serial)
        with Adb.targeting(serial):
            if not self._ca._check_root_access():
                return self._mark_failed(lanes, "root access is gone", now)
            desired = [
                DesiredLane(
                    lane=lane,
                    package=self._lanes[lane] or "",
                    port=self._redirect_port(lane),
                    upstream=self._lane_upstream(lane),
                    uid_hint=self._lane_uids.get(lane),
                )
                for lane in lanes
            ]
            obs = self._observe([d.package for d in desired])
            if obs is None:
                return self._mark_failed(lanes, "device state unreadable", now)
            obs.ip6_nat = obs.ip6_nat and serial not in self._ip6_redirect_broken
            self._ip6_cap_cache[serial] = (obs.ip6_filter, obs.ip6_nat)
            plans, orphans, stale = plan_lanes(
                desired,
                obs,
                binary=self._binary_dst,
                port_range=self._port_range(),
                quic=self._quic_blocking_enabled(),
            )
            reports = self._apply_plans(
                plans, orphans, stale, obs, now, [] if deferred is None else deferred
            )
        if any(r.repaired for r in reports) or stale or orphans:
            # Repairing lanes is the expected job after a world change (a
            # snapshot load, a cold boot); after anything else it is news.
            level = logging.INFO if reason in self._WORLD_CHANGES else logging.WARNING
            logger.log(
                level,
                "App proxies reconciled after %s: %s",
                reason or "a check",
                "; ".join(
                    f"{r.package} {r.health.label}"
                    + (f" ({', '.join(r.repaired)})" if r.repaired else "")
                    for r in reports
                ),
            )
            self._write_sidecar()
        return reports

    def _port_range(self) -> range:
        """Our gost REDIRECT ports (the lane pool)."""
        return range(self._redirect_base, self._redirect_base + self._pool_size)

    def sweep_orphans(self, serial: str | None, reason: str = "") -> int:
        """Remove App Proxy rules and gost this session did not ask for.

        A snapshot saved by an earlier session with an App Proxy restores
        its tagged rules and its gost. With no lane of this session on
        *serial* nothing reconciles them, so the app is cut off (mitmproxy
        off) or captured without attribution. One adb read; only our tag
        and our port range are touched. Blocking (adb), never raises.

        Returns:
            The number of rules and gost processes removed.
        """
        try:
            with self._lock:
                if any(
                    pkg and self._lane_serials.get(lane) == serial
                    for lane, pkg in self._lanes.items()
                ):
                    return 0  # the reconcile of those lanes handles it
                with Adb.targeting(serial):
                    if not self._ca._check_root_access():
                        return 0
                    obs = self._observe([])
                    if obs is None:
                        return 0
                    _plans, orphans, stale = plan_lanes(
                        [],
                        obs,
                        binary=self._binary_dst,
                        port_range=self._port_range(),
                        quic=self._quic_blocking_enabled(),
                    )
                    for kind, line in stale:
                        self._delete_observed_rule(kind, line)
                    if orphans:
                        self._kill_pids(orphans)
        except Exception as exc:
            logger.debug("App Proxy orphan sweep failed: %s", exc)
            return 0
        if stale or orphans:
            logger.warning(
                "Removed %d App Proxy rule(s) and %d gost process(es) on %s "
                "that %s brought back without an App Proxy of this session",
                len(stale),
                len(orphans),
                serial,
                reason or "the device state",
            )
        return len(stale) + len(orphans)

    def _mark_failed(self, lanes: list[int], why: str, now: float) -> list[LaneReport]:
        reports = []
        for lane in lanes:
            health = LaneHealth(LANE_FAILED, why, now)
            self._lane_health[lane] = health
            reports.append(LaneReport(self._lanes[lane] or "", lane, health))
        return reports

    def _apply_plans(
        self,
        plans: list[LanePlan],
        orphans: list[int],
        stale: list[tuple[str, str]],
        obs: LaneObservation,
        now: float,
        deferred: list[_UpstreamProbe],
    ) -> list[LaneReport]:
        """Execute reconcile plans in fail-closed order (lock + targeting held).

        Invariant: from the first device change on, no requested app has an
        IPv4 TCP path without our REDIRECT or an IPv6 path without our
        REJECT (or v6 REDIRECT). So every missing protective rule goes in
        FIRST; only then are stale rules deleted, gost killed, the binary
        checked and gost relaunched. A REDIRECT to a port without a
        listening gost refuses the connection: closed, never a leak.
        """
        serial = Adb.get_target_device()
        repaired: dict[int, list[str]] = {p.lane: [] for p in plans}
        redirect_errors: dict[int, str] = {}
        # 1. Fail closed: v6 fence, QUIC block and the IPv4 REDIRECT.
        for plan in plans:
            if plan.app_missing or plan.uid is None:
                continue
            if plan.uid != self._lane_uids.get(plan.lane):
                repaired[plan.lane].append("app UID changed")
                self._lane_uids[plan.lane] = plan.uid
                self._lane_rule_specs.pop(plan.lane, None)
                self._lane_quic_specs.pop(plan.lane, None)
            self._uids_used.setdefault(serial, set()).add(plan.uid)
            blocks = {k for k in plan.add if k.target == "BLOCK"}
            if any(k.proto == "tcp" for k in blocks):
                self._ensure_v6_fence(plan.lane, plan.uid)
            if any(k.proto == "udp" for k in blocks):
                self._add_quic_block(plan.lane, plan.uid)
            if blocks:
                repaired[plan.lane].append("fail-closed rules restored")
            families = {k.family for k in plan.add if k.target == "REDIRECT"}
            if families:
                ok, msg = self._ensure_redirect(
                    plan.lane, plan.uid, plan.port, families=families
                )
                if ok:
                    repaired[plan.lane].append("redirect restored")
                else:
                    redirect_errors[plan.lane] = msg
        # 2. Stale rules (other lane sets, old UIDs, gone apps) and bad gost.
        for kind, line in stale:
            self._delete_observed_rule(kind, line)
        kills = sorted({pid for p in plans for pid in p.kill} | set(orphans))
        if kills:
            self._kill_pids(kills)
        for plan in plans:
            if plan.kill and not plan.app_missing:
                repaired[plan.lane].append("; ".join(plan.why[:2]) or "gost replaced")
        # 3. The binary (only when a gost has to start), 4. detached relaunch.
        binary_missing = (
            any(p.launch and not p.app_missing and p.uid is not None for p in plans)
            and not self._ensure_binary()[0]
        )
        reports: list[LaneReport] = []
        for plan in plans:
            lane = plan.lane
            if plan.app_missing:
                self._lane_rule_specs.pop(lane, None)
                self._lane_quic_specs.pop(lane, None)
                health = LaneHealth(LANE_FAILED, "app not installed", now)
                logger.error(
                    "App proxy for %s: the app is not installed on this device "
                    "(any more); its lane is removed from the device",
                    plan.package,
                )
            elif plan.uid is None:
                health = self._lane_health.get(lane) or LaneHealth(
                    LANE_FAILED,
                    "the app's UID could not be read; its rules were left as they are",
                    now,
                )
                logger.warning(
                    "App proxy for %s: could not read the app's UID; its lane "
                    "is left as it is",
                    plan.package,
                )
            else:
                health = self._repair_lane(
                    plan,
                    binary_missing,
                    repaired[lane],
                    redirect_errors.get(lane),
                    obs,
                    now,
                    deferred,
                )
            self._lane_health[lane] = health
            reports.append(LaneReport(plan.package, lane, health, repaired[lane]))
        return reports

    def _repair_lane(
        self,
        plan: LanePlan,
        binary_missing: bool,
        repaired: list[str],
        redirect_error: str | None,
        obs: LaneObservation,
        now: float,
        deferred: list[_UpstreamProbe],
    ) -> LaneHealth:
        """Relaunch gost for one lane whose rules are in place (lock held)."""
        lane, port, uid = plan.lane, plan.port, plan.uid or 0
        self._remember_observed(lane, uid, port, obs.rules)
        health: LaneHealth | None = None
        if plan.launch:
            if binary_missing:
                health = LaneHealth(
                    LANE_FAILED, "gost binary missing on the device (fail closed)", now
                )
            else:
                self._launch_gost(port, self._lane_upstream(lane))
                if not self._wait_listening(port):
                    health = LaneHealth(
                        LANE_FAILED, f"gost did not start on :{port} (fail closed)", now
                    )
                elif "gost not running" in plan.why:
                    repaired.append("gost restarted")
        if health is None and redirect_error:
            health = LaneHealth(LANE_FAILED, redirect_error, now)
        if plan.launch or plan.add:
            # Connections opened before the rules (or through a dead gost)
            # are dropped, so they reconnect through the lane or are refused.
            self._flush_app_sockets(uid)
        if health is not None:
            return health
        changed = bool(plan.launch or plan.add)
        return self._upstream_health(lane, probe=changed, now=now, deferred=deferred)

    def _remember_observed(
        self, lane: int, uid: int, port: int, rules: list[tuple[str, str]]
    ) -> None:
        """Record the lane's rules exactly as the device lists them.

        Teardown deletes these lines, so a DROP fallback or an untagged rule
        a snapshot restored is removed too (rebuilding the REJECT spec would
        miss them).
        """
        for kind, line in rules:
            key = parse_rule_key(kind, line)
            spec = line.strip()
            if key is None or key.uid != uid or not spec.startswith("-A "):
                continue
            if key.target == "REDIRECT" and key.to_port != port:
                continue
            tbl = "ip6tables" if kind.endswith("6") else "iptables"
            table = "-t nat " if kind.startswith("NAT") else ""
            body = table + "{op} " + spec[3:].replace("{", "{{").replace("}", "}}")
            quic = key.proto == "udp" and key.dport == 443
            store = self._lane_quic_specs if quic else self._lane_rule_specs
            self._remember(store, lane, (tbl, body))

    def _lane_upstream(self, lane: int) -> str:
        """The gost ``-F`` upstream of a lane (rebuilt if unknown)."""
        upstream = self._lane_upstreams.get(lane)
        if upstream:
            return upstream
        target = self._lane_targets.get(lane, "ours")
        ok, built = self._build_upstream(None if target == "ours" else target, lane)
        upstream = built if ok else f"socks5://{self._resolve_host_ip()}:0"
        self._lane_upstreams[lane] = upstream
        return upstream

    def _upstream_health(
        self,
        lane: int,
        *,
        probe: bool,
        now: float | None = None,
        deferred: list[_UpstreamProbe] | None = None,
    ) -> LaneHealth:
        """Health of a lane whose device side is in place (lock held).

        External upstreams are taken as given. For our mitmproxy: not running
        means waiting (the lane stays and fails closed); running is probed
        from the device (SOCKS greeting) only when asked to or when the last
        verdict was not active, so a steady reconcile costs no probe. With
        *deferred* the probe is queued for :meth:`_finish_probes` (after the
        lock is released) and the previous verdict stands meanwhile.
        """
        now = time.time() if now is None else now
        if self._lane_targets.get(lane, "ours") != "ours":
            return LaneHealth(LANE_ACTIVE, "", now)
        if not self._mitmproxy_running():
            return LaneHealth(LANE_WAITING, "", now)
        previous = self._lane_health.get(lane)
        if not probe and previous is not None and previous.state == LANE_ACTIVE:
            return LaneHealth(LANE_ACTIVE, "", now)
        host_ip = self._resolve_host_ip()
        socks = self._socks_port(lane)
        if deferred is not None:
            deferred.append(
                _UpstreamProbe(
                    lane,
                    self._lanes.get(lane) or "",
                    Adb.get_target_device(),
                    host_ip,
                    socks,
                )
            )
            if previous is not None and previous.state == LANE_UNREACHABLE:
                return previous
            return LaneHealth(LANE_ACTIVE, "", now)
        return self._probe_verdict(host_ip, socks)

    #: Waits before re-probing an "unreachable" upstream (mitmproxy may still
    #: be binding its SOCKS listeners).
    _PROBE_RETRY_DELAYS: tuple[float, ...] = (1.0, 2.0)

    def _probe_verdict(self, host_ip: str, socks: int) -> LaneHealth:
        """Probe our SOCKS port from the device; retry "unreachable" twice."""
        verdict = self._device_tcp_reachable(host_ip, socks)
        for delay in self._PROBE_RETRY_DELAYS:
            if verdict != "unreachable":
                break
            time.sleep(delay)
            verdict = self._device_tcp_reachable(host_ip, socks)
        if verdict == "unreachable":
            return LaneHealth(LANE_UNREACHABLE, f"{host_ip}:{socks}", time.time())
        return LaneHealth(LANE_ACTIVE, "", time.time())

    def _finish_probes(
        self, probes: list[_UpstreamProbe], reports: list[LaneReport]
    ) -> None:
        """Run deferred upstream probes WITHOUT the lock, then store them."""
        results: dict[int, LaneHealth] = {}
        for probe in probes:
            try:
                with Adb.targeting(probe.serial):
                    results[probe.lane] = self._probe_verdict(probe.host, probe.port)
            except Exception as exc:
                logger.debug("App Proxy upstream probe failed: %s", exc)
        with self._lock:
            for probe in probes:
                health = results.get(probe.lane)
                if health is None:
                    continue
                still = self._lanes.get(probe.lane) == probe.package and (
                    self._lane_serials.get(probe.lane) == probe.serial
                )
                current = self._lane_health.get(probe.lane)
                if still and (current is None or current.state != LANE_FAILED):
                    self._lane_health[probe.lane] = health
        for report in reports:
            health = results.get(report.lane)
            if health is not None and report.health.state != LANE_FAILED:
                report.health = health

    @staticmethod
    def _mitmproxy_running() -> bool:
        try:
            from sandroid.services.mitmproxy_service import peek_mitmproxy_service

            service = peek_mitmproxy_service()
            return bool(service is not None and service.is_running())
        except Exception:
            return False

    def lane_health(
        self, serial: str | None | object = _CURRENT_SERIAL
    ) -> dict[str, LaneHealth]:
        """``{package: LaneHealth}`` of the lanes on *serial* (no adb).

        "Waiting for mitmproxy" is derived live: a lane of ours whose last
        check passed reads as waiting while mitmproxy is stopped.
        """
        with self._lock:
            return self._health_snapshot(serial)

    def lane_health_nonblocking(
        self, timeout: float = 0.05, serial: str | None | object = _CURRENT_SERIAL
    ) -> dict[str, LaneHealth] | None:
        """:meth:`lane_health` that returns None instead of blocking."""
        if not self._lock.acquire(timeout=timeout):
            return None
        try:
            return self._health_snapshot(serial)
        finally:
            self._lock.release()

    def _health_snapshot(self, serial: str | None | object) -> dict[str, LaneHealth]:
        if serial is _CURRENT_SERIAL:
            serial = Adb.get_target_device()
        running = None
        out: dict[str, LaneHealth] = {}
        for lane, pkg in self._lanes.items():
            if not pkg or self._lane_serials.get(lane, serial) != serial:
                continue
            health = self._lane_health.get(lane) or LaneHealth(LANE_ACTIVE)
            if (
                health.state in (LANE_ACTIVE, LANE_WAITING, LANE_UNREACHABLE)
                and self._lane_targets.get(lane, "ours") == "ours"
            ):
                if running is None:
                    running = self._mitmproxy_running()
                if not running:
                    health = LaneHealth(LANE_WAITING, "", health.checked_at)
                elif health.state == LANE_WAITING or (
                    health.state == LANE_UNREACHABLE
                    and health.checked_at < _MITMPROXY_STARTED_AT
                ):
                    # mitmproxy came back: the same gost forwards again (an
                    # "unreachable" from before this start no longer counts).
                    health = LaneHealth(LANE_ACTIVE, "", health.checked_at)
            out[pkg] = health
        return out

    def _publish_health(self) -> None:
        """Tell the panels and the glance that lane health changed."""
        try:
            from sandroid.core.events import Event, EventBus, EventType

            EventBus.get().publish(
                Event(
                    type=EventType.STATE_CHANGED,
                    data={"change_type": "app_proxies"},
                    source="focus_manager",
                )
            )
        except Exception:
            logger.debug("app proxy health publish failed", exc_info=True)

    # ── device-side helpers (lock + targeting held) ───────────────────

    def _run_lane(self, *args: str, timeout: float = 30.0) -> str:
        """Run one lane script operation on the current target; stdout."""
        try:
            out, _err = run_device_script(
                _LANE_SCRIPT,
                list(args),
                serial=Adb.get_target_device(),
                use_su=self._ca._use_su,
                timeout=timeout,
            )
        except Exception as exc:
            logger.debug("lane script %s failed: %s", args[:1], exc)
            return ""
        return out or ""

    def _observe(self, packages: list[str]) -> LaneObservation | None:
        """Device truth for the lanes (one adb call); None if unreadable.

        On a device where our rules had to go in untagged (no xt_comment)
        every per-UID rule is listed and those of our lane UIDs (REDIRECTs
        into our port range) are kept, so they are neither re-added on every
        reconcile nor left behind as stale.
        """
        serial = Adb.get_target_device()
        untagged = serial in self._untagged_serials
        valid = [p for p in packages if is_valid_package_name(p)]
        out = self._run_lane(
            "observe",
            self._binary_dst,
            self._RULE_TAG,
            "1" if untagged else "0",
            *valid,
        )
        if _script_rc(out) is None:
            return None
        obs = parse_lane_observation(out)
        if untagged:
            ours = set(self._uids_used.get(serial, set()))
            ours |= {u for u in obs.uids.values() if u is not None}
            ports = self._port_range()
            kept = []
            for kind, line in obs.rules:
                key = parse_rule_key(kind, line)
                if self._RULE_TAG in line or (
                    key is not None
                    and key.uid in ours
                    and (key.target != "REDIRECT" or key.to_port in ports)
                ):
                    kept.append((kind, line))
            obs.rules = kept
        return obs

    def _kill_pids(self, pids: list[int]) -> None:
        """Kill exact gost PIDs (observed by argv; never a pattern kill)."""
        if not pids:
            return
        inner = "kill " + " ".join(str(int(p)) for p in pids)
        try:
            Adb.send_adb_command(f"shell {self._ca._root_cmd(inner)}")
        except Exception:
            pass

    def _delete_observed_rule(self, kind: str, line: str) -> None:
        """Delete one tagged rule exactly as ``iptables -S`` listed it."""
        spec = line.strip()
        if not spec.startswith("-A "):
            return
        binary = "ip6tables" if kind.endswith("6") else "iptables"
        table = "-t nat " if kind.startswith("NAT") else ""
        cmd = f"{binary} -w {table}-D {spec[3:]}"
        try:
            Adb.send_adb_command(f"shell {self._ca._root_cmd(cmd)}")
        except Exception:
            pass

    def _flush_app_sockets(self, uid: int) -> None:
        """Drop the app's established TCP sockets (``ss -K``) after a change.

        Pooled keep-alive connections the app opened before the lane existed
        go straight to the server and would keep bypassing the REDIRECT until
        they close; killing them makes the app reconnect through the lane.
        Matches the UID from ``ss -tnae`` and kills per source port (a
        ``state established`` filter combined with ports matched nothing on
        the device's iproute2). Best-effort.
        """
        out = self._run_lane("flush", str(int(uid)))
        m = re.search(r"flushed=(\d+)", out)
        if m and int(m.group(1)):
            logger.info(
                "Closed %s open connection(s) of uid %s so they reconnect "
                "through the app proxy",
                m.group(1),
                uid,
            )

    def set_quic_blocking(self, enabled: bool) -> None:
        """Add/remove the QUIC (UDP/443) REJECT across all session lanes.

        Public, so it takes the lock itself and calls ONLY the lock-free
        internals (``_add_quic_block``/``_delete_rule_loop``) — never the public
        ``enable_focus``/``disable_focus``, which would re-acquire the
        non-reentrant ``self._lock`` and deadlock. Re-syncs the session-tracked
        lanes in ``_lanes`` via ``_lane_uids``: enabling adds the block to lanes
        that lack it; disabling deletes the rules and drops the tracked specs.

        Only affects lanes created this session — there is no cross-restart
        ``_lanes`` rebuild, which is consistent with the modal (after a restart
        the app rows are empty, so re-adding an app re-runs ``enable_focus`` and
        reapplies QUIC fresh).
        """
        with self._lock:
            for lane, package in self._lanes.items():
                if not package:
                    continue
                with Adb.targeting(self._lane_serials.get(lane)):
                    if enabled:
                        uid = self._lane_uids.get(lane)
                        if uid is None or lane in self._lane_quic_specs:
                            continue  # unknown uid, or already blocked.
                        self._add_quic_block(lane, uid)
                    else:
                        for tbl, body in self._lane_quic_specs.get(lane, []):
                            self._delete_rule_loop(tbl, body)
                        self._lane_quic_specs.pop(lane, None)
        # Outside the lock: the Network method line re-reads the QUIC block.
        self._publish_health()

    def cleanup_stale(self) -> None:
        """Remove every tagged rule + stray gost/ipt2socks and clear lane state.

        Self-heals after a SIGKILL'd prior run that would otherwise blackhole
        apps. Probes root first so the su/non-su command wrapping is correct
        when called standalone (e.g. at app startup). Swallows all errors.
        """
        with self._lock:
            try:
                self._ca._check_root_access()
            except Exception:
                pass
            self._cleanup_stale_locked()

    # ── internals (assume lock held unless noted) ─────────────────────

    def _spotlight_package(self) -> str | None:
        """Resolve the effective spotlight package (lazy import)."""
        try:
            from sandroid.services import get_spotlight_service

            return get_spotlight_service().get_effective_package()
        except Exception:
            return None

    def _first_free_lane(self) -> int | None:
        for i in range(self._pool_size):
            if self._lanes.get(i) is None:
                return i
        return None

    def _lane_index_for(
        self, package: str, serial: str | None | object = _CURRENT_SERIAL
    ) -> int | None:
        """Lane serving *package* on *serial* (default: the current target)."""
        if serial is _CURRENT_SERIAL:
            serial = Adb.get_target_device()
        for i, p in self._lanes.items():
            if p == package and self._lane_serials.get(i, serial) == serial:
                return i
        return None

    def _resolve_uid(self, package: str) -> int | None:
        """Resolve the app's Linux UID, robust across Android versions.

        Strategy 1 (authoritative, version-independent): the owner UID of the
        app's private data dir via ``stat -c %u /data/data/<pkg>`` as root
        (Focus already requires root). The data dir is chowned to the app's UID
        on every Android release, so this needs no per-version parsing.

        Strategy 2 (fallback): parse ``dumpsys package``. The field name drifts
        across versions — older builds print ``userId=<n>`` while Android 15
        (API 35) prints ``appId=<n>`` (== the per-user-0 UID) and dropped
        ``userId=`` entirely — so match either. The previous code matched only
        ``userId=`` and so returned None (and "Could not resolve UID") on 15.
        """
        if not is_valid_package_name(package):
            logger.warning("Refusing to resolve UID for invalid package %r", package)
            return None
        # 1. Data-dir owner — the exact Linux UID, no version dependence.
        try:
            out, _ = Adb.send_adb_command(
                "shell "
                + self._ca._root_cmd(
                    f"stat -c %u {shlex.quote('/data/data/' + package)}"
                )
            )
            val = (out or "").strip()
            if val.isdigit():
                return int(val)
        except Exception:
            pass

        # 2. dumpsys fallback (userId= pre-15, appId= on API 35+).
        try:
            out, _ = Adb.send_adb_command(
                f"shell dumpsys package {device_shell_arg(package)}"
            )
        except Exception:
            return None
        m = re.search(r"\b(?:userId|appId)=(\d+)", out or "")
        if not m:
            return None
        try:
            return int(m.group(1))
        except ValueError:
            return None

    #: UID well outside Android's entire allocation space (system <10000,
    #: apps 10000-19999, isolated 90000-99999, +100000*userId per profile),
    #: so the probe rule matches no real process for its brief lifetime.
    _PROBE_UID = "2000000000"

    def _probe_owner_match(self) -> tuple[bool, str]:
        """Probe that the kernel supports the per-app lane rule shape.

        Probes by installing the feature's EXACT rule (UID ``_PROBE_UID``,
        which matches no real process) and immediately deleting it — NOT
        ``iptables -C``. The legacy backend (iptables 1.8.x) reports the
        generic "No chain/target/match by that name" for a *non-existent*
        nat/REDIRECT rule even when the owner match AND the REDIRECT target
        are both compiled in, so a ``-C`` probe false-negatives and wrongly
        disabled App Proxies on perfectly capable kernels (e.g. Android 15).
        An add that loads the modules either succeeds or fails for an
        unrelated reason; only a missing-module error on the add is
        conclusive. ip6tables absence is a warning only.
        """
        ok, _ = self._probe_lane_rule("iptables")
        if not ok:
            return False, (
                "iptables owner/REDIRECT rule unavailable on this kernel "
                "(netfilter module missing) — Focus can't scope by app UID."
            )
        # IPv6 redirect is best-effort. Only probe when the ip6tables nat
        # table exists (cached per serial); most kernels lack it
        # (CONFIG_IP6_NF_NAT off) and then v6 is fenced by a filter REJECT.
        if self._ip6_nat_ok() and not self._probe_lane_rule("ip6tables")[0]:
            logger.warning(
                "ip6tables owner/REDIRECT unavailable — Focus will only "
                "scope IPv4 traffic on this device."
            )
        return True, "owner match available"

    def _probe_lane_rule(self, binary: str) -> tuple[bool, str]:
        """Add the feature's exact lane rule (bogus UID), then delete it.

        Returns ``(supported, add_output)``. ``supported`` is False only when
        the ADD failed with a missing-module error; the DELETE is best-effort
        cleanup that runs regardless. A probe that can't run at all (ADB
        error) is treated as supported so a transient failure never disables
        the feature. Appends (``-A``) so the throwaway rule is evaluated last.
        """
        add = (
            f"{binary} -t nat -A OUTPUT -m owner --uid-owner {self._PROBE_UID} "
            "-p tcp -j REDIRECT --to-ports 1"
        )
        dele = (
            f"{binary} -t nat -D OUTPUT -m owner --uid-owner {self._PROBE_UID} "
            "-p tcp -j REDIRECT --to-ports 1"
        )
        try:
            out, err = Adb.send_adb_command(f"shell {self._ca._root_cmd(add)}")
        except Exception:
            return True, ""
        # Clean up whether or not the add reported success (a failed add just
        # makes the delete a harmless no-op, whose "no such rule" answer is
        # expected: DEBUG, not an adb WARNING).
        from sandroid.core.adb_utils import quiet_adb_warnings

        try:
            with quiet_adb_warnings():
                Adb.send_adb_command(f"shell {self._ca._root_cmd(dele)}")
        except Exception:
            pass
        return (not self._is_missing_match(f"{out}\n{err}")), err

    @staticmethod
    def _is_missing_match(err: str) -> bool:
        # iptables phrases a missing extension/module several ways: "Couldn't
        # load match `owner'" (kernel module absent), "Couldn't find match
        # `…'" (userspace extension absent), or the generic "No chain/target/
        # match by that name." Match any so a real capability gap is caught.
        text = err or ""
        return bool(
            re.search(r"Couldn't (load|find) (match|target)", text)
            or "No chain/target/match" in text
        )

    # ── binary acquisition ────────────────────────────────────────────

    def _ensure_binary(self) -> tuple[bool, str]:
        """Download (cached, sha256-verified), then make sure the device has it.

        The host cache download is skipped when a matching file exists. On
        the device the binary is compared by SHA-256 (once per serial and
        world) and pushed only when missing or different, to ``<dst>.new``
        then renamed over ``<dst>``: a gost of another lane running from that
        file is never ``rm``-ed under it.
        """
        from sandroid.core.fsmon import FSMon

        abi = FSMon.get_device_architecture()
        try:
            assets = get_config().focus.gost_assets
            asset = assets[abi]
        except Exception:
            return False, f"No gost asset configured for ABI '{abi}'."

        url = asset.get("url", "")
        sha256 = asset.get("sha256", "")
        if not url:
            return False, f"No gost URL configured for ABI '{abi}'."

        cache_dir = os.path.expanduser("~/.cache/sandroid/gost/")
        try:
            os.makedirs(cache_dir, exist_ok=True)
        except OSError as exc:
            return False, f"Cannot create gost cache dir: {exc}"
        cached = os.path.join(cache_dir, f"gost-{abi}")

        # Reuse a cached file only if it is non-empty and (when a hash is
        # configured) matches it. The cached file is the EXTRACTED ELF.
        need_download = True
        if os.path.exists(cached) and os.path.getsize(cached) > 0:
            if not sha256 or self._file_sha256(cached) == sha256:
                need_download = False

        if need_download:
            ok, msg = self._download_binary(url, cached, sha256)
            if not ok:
                return False, msg

        dst = self._binary_dst
        serial = Adb.get_target_device()
        if serial in self._binary_ok:
            return True, "gost present"
        want = self._file_sha256(cached)
        try:
            out, _ = Adb.send_adb_command(
                f"shell {self._ca._root_cmd(f'sha256sum {dst} 2>/dev/null')}"
            )
        except Exception:
            out = ""
        if (out or "").split()[:1] == [want]:
            self._binary_ok.add(serial)
            return True, "gost present"
        # Through Adb.send_adb_command (not a bare `adb`), so the -s <serial>
        # targeting applies; verified with a follow-up sha256sum, because
        # send_adb_command drops push's exit code and push writes progress to
        # stderr even on success.
        tmp = f"{dst}.new"
        try:
            Adb.send_adb_command(
                f"push {quote_host_arg(str(cached))} {quote_host_arg(tmp)}"
            )
            install = f"chmod 755 {tmp} && mv -f {tmp} {dst} && sha256sum {dst}"
            out, err = Adb.send_adb_command(f"shell {self._ca._root_cmd(install)}")
        except Exception as exc:
            return False, f"Failed to install gost: {exc}"
        if (out or "").split()[:1] != [want]:
            detail = (err or out or "file not found after push").strip()
            return False, f"Failed to push gost: {detail}"
        self._binary_ok.add(serial)
        return True, "gost installed"

    def _download_binary(self, url: str, dst: str, sha256: str) -> tuple[bool, str]:
        """Download the gost ``.tar.gz``, extract the ``gost`` ELF to ``dst``.

        The gost release ships gzip tarballs (``LICENSE``, ``README*``, and a
        ``gost`` binary), so we read the archive from memory, ``extractfile`` the
        member whose basename is ``gost`` (NOT ``extractall`` — that is path-
        traversal-safe and avoids writing the docs), write only that ELF, then
        verify the sha256 of the EXTRACTED file. Mirrors the frida-server
        cached-download pattern otherwise.
        """
        try:
            with requests.get(url, timeout=300, allow_redirects=True) as res:
                res.raise_for_status()
                content = res.content
            if not content:
                return False, f"gost download returned empty content: {url}"
        except requests.RequestException as exc:
            return False, f"Failed to download gost from {url}: {exc}"

        # Extract only the `gost` member (traversal-safe: never extractall).
        try:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tf:
                member = next(
                    (
                        m
                        for m in tf.getmembers()
                        if m.isfile() and os.path.basename(m.name) == "gost"
                    ),
                    None,
                )
                if member is None:
                    return False, (f"gost archive has no 'gost' member: {url}")
                extracted = tf.extractfile(member)
                if extracted is None:
                    return False, "Could not read 'gost' member from archive."
                data = extracted.read()
        except (tarfile.TarError, OSError, EOFError) as exc:
            return False, f"Failed to extract gost from {url}: {exc}"

        try:
            with open(dst, "wb") as f:
                f.write(data)
        except OSError as exc:
            return False, f"Failed to write gost binary: {exc}"

        if sha256:
            actual = self._file_sha256(dst)
            if actual != sha256:
                try:
                    os.unlink(dst)
                except OSError:
                    pass
                return False, (
                    "gost sha256 mismatch "
                    f"(expected {sha256[:12]}…, got {actual[:12]}…). "
                    "Note: the checksum is of the extracted ELF, not the tarball."
                )
        else:
            logger.warning(
                "No sha256 configured for gost asset — skipping "
                "verification (configure focus.gost_assets)."
            )
        return True, "gost downloaded"

    @staticmethod
    def _file_sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    # ── upstream resolution ───────────────────────────────────────────

    @staticmethod
    def _resolve_to_ip(host: str) -> tuple[bool, str]:
        """Resolve ``host`` to an IPv4 address host-side (gost stays IP-only).

        gost is kept IP-only (never ``?sniffing``) and the device's resolv.conf
        can't be relied on, so any external-proxy hostname is resolved HERE. A
        numeric IP is returned unchanged. ``gethostbyname`` is v4-only — switch
        to ``getaddrinfo`` if IPv6 upstreams are ever needed.

        Returns ``(ok, ip_or_error)``.
        """
        host = (host or "").strip()
        if not host:
            return False, "External proxy host is empty."
        try:
            return True, socket.gethostbyname(host)
        except OSError as exc:
            return False, f"Could not resolve external proxy host '{host}': {exc}"

    def _build_upstream(self, target: str | None, lane: int) -> tuple[bool, str]:
        """Build the gost ``-F`` upstream for a lane (host-side resolved).

        ``target=None`` ⇒ our mitmproxy: ``socks5://<host_ip>:<socks_port>`` (the
        lane's SOCKS port is the app identity the addon reads). Otherwise
        ``target`` is an external HTTP proxy as ``http://host:port`` or bare
        ``host:port``; the host is resolved to an IP here, yielding
        ``http://<ip>:<port>``. Non-http schemes are rejected and a resolve
        failure fails loud (returned as the message) before gost launches.

        Returns ``(ok, upstream_or_error)``.
        """
        if target is None:
            host_ip = self._resolve_host_ip()
            return True, f"socks5://{host_ip}:{self._socks_port(lane)}"

        spec = (target or "").strip()
        if "://" in spec:
            scheme, spec = spec.split("://", 1)
            if scheme.lower() != "http":
                return False, (
                    f"Unsupported proxy scheme '{scheme}://' — external app "
                    "proxies must be http://host:port (Burp/ZAP)."
                )
        if ":" not in spec:
            return False, (
                f"External proxy '{target}' must include a port (host:port)."
            )
        host, port_str = spec.rsplit(":", 1)
        # Strip brackets from a bracketed host; note _resolve_to_ip uses
        # gethostbyname (IPv4-only), so a real IPv6 literal still fails loud.
        host = host.strip().strip("[]")
        try:
            port = int(port_str)
        except ValueError:
            return False, f"External proxy port not a number: '{port_str}'."
        ok, ip_or_err = self._resolve_to_ip(host)
        if not ok:
            return False, ip_or_err
        return True, f"http://{ip_or_err}:{port}"

    # ── gost process lifecycle ────────────────────────────────────────

    def _resolve_host_ip(self) -> str:
        """Host IP our-mitmproxy lanes forward SOCKS traffic to.

        Delegates to the module-level :func:`resolve_proxy_host_ip` so the
        Device Proxy and App Proxies share one resolver:
        ``focus.host_ip_override`` wins; else ``10.0.2.2`` on an emulator
        (SLIRP loopback alias); else the auto-detected host LAN IP.
        """
        return resolve_proxy_host_ip()

    @staticmethod
    def _is_emulator() -> bool:
        return _is_emulator()

    def _launch_gost(self, redirect_port: int, upstream: str) -> None:
        """Launch one gost redirector fully detached, in ONE synchronous adb call.

        ``setsid sh -c 'exec gost -L red://:<port> -F <upstream>'`` with
        stdin/stdout/stderr on ``/dev/null``: gost gets its own session, PPID
        1 and no adb session socket as stdio. The old launch (a host Popen of
        ``adb shell sh -c "gost ... &"``) left gost's stdout on the adb
        session, so after any session loss (snapshot load, ``adb root``,
        reconnect) gost died of SIGPIPE at its first logged connection while
        the REDIRECT kept pointing at its dead port. The args carry no shell
        metacharacters (port int, upstream ``scheme://ip:port``).
        """
        inner = (
            f"setsid sh -c 'exec {self._binary_dst} -L red://:{redirect_port} "
            f"-F {upstream}' </dev/null >/dev/null 2>&1 &"
        )
        try:
            Adb.send_adb_command(f"shell {self._ca._root_cmd(inner)}")
        except Exception as exc:
            logger.warning("Failed to launch gost: %s", exc)

    def _wait_listening(self, redirect_port: int) -> bool:
        """Wait (on the device, <=2 s) for this port's gost and its listener."""
        out = self._run_lane("listening", self._binary_dst, str(int(redirect_port)))
        return "LISTENING" in out

    def _kill_lane_process(self, redirect_port: int) -> None:
        """Kill the gost bound to ``redirect_port`` (matched by its argv)."""
        self._run_lane("kill", self._binary_dst, str(int(redirect_port)))

    @staticmethod
    def _device_tcp_reachable(host: str, port: int, *, timeout: int = 4) -> str:
        r"""Open a SOCKS5 handshake from the device to ``host:port``.

        Used by the App-Proxy lane to confirm gost's *upstream* (our mitmproxy
        SOCKS5 port) is actually reachable from the device — the same host-IP-
        reachability blind spot the device proxy hits, one layer down. Sends
        the SOCKS5
        greeting ``\\x05\\x01\\x00`` and treats a 2-byte ``\\x05\\x00`` reply as
        proof the upstream answered.

        QUOTING: ``Adb.send_adb_command`` runs the whole string through the host
        shell (``shell=True``), so the device-side pipe and ``printf`` byte
        escapes are passed as ONE host-quoted word (``device_shell_command``)
        so only the *device* shell interprets them — a bare pipe would be split
        by the *host* shell, and a double-quoted wrapper would still expand
        ``$``/backticks host-side. ``toybox nc`` closes the socket on stdin EOF before the
        reply arrives, so we hold stdin open with ``{ ...; sleep N; }`` — do NOT
        simplify it back to a bare pipe or stdout comes back empty.

        Returns:
            ``"reachable"`` (got the SOCKS5 reply), ``"unreachable"`` (a real
            connect failure), or ``"unknown"`` (``toybox nc`` missing/errored —
            never report a false ``"unreachable"`` on a device without the tool).
        """
        inner = (
            f"{{ printf '\\x05\\x01\\x00'; sleep 2; }} | "
            f"toybox nc -w {timeout} {host} {port} | "
            "toybox xxd -p"
        )
        try:
            out, err = Adb.send_adb_command(device_shell_command(inner))
        except Exception:
            return "unknown"
        text = (out or "").strip().lower()
        if "0500" in text:
            return "reachable"
        # Distinguish "tool missing" from "connect failed": toybox reports the
        # absent applet / a usage error on stderr without ever connecting
        # (toybox's own wording for a missing applet is "Unknown command nc").
        blob = (err or "").lower()
        if (
            "not found" in blob
            or "no such" in blob
            or "usage" in blob
            or "unknown command" in blob
        ):
            return "unknown"
        return "unreachable"

    # ── iptables rule management ──────────────────────────────────────

    def _ip6_caps(self) -> tuple[bool, bool]:
        """``(filter, nat)`` ip6tables tables on the current target (cached).

        Probed separately: most Android kernels have the v6 filter table (so
        the per-UID REJECT works) but no v6 nat table. The old single probe
        tested only nat and so disabled every v6 rule, the QUIC block and the
        stale sweep included. Cached per serial; a world change re-probes.
        """
        serial = Adb.get_target_device()
        caps = self._ip6_cap_cache.get(serial)
        if caps is None:
            caps = (self._probe_ip6_table(""), self._probe_ip6_table("-t nat "))
            self._ip6_cap_cache[serial] = caps
            if not caps[1]:
                logger.debug(
                    "ip6tables nat unavailable: IPv6 traffic of proxied apps "
                    "is rejected instead of redirected"
                )
        return caps

    def _probe_ip6_table(self, table_flag: str) -> bool:
        cmd = f"ip6tables -w {table_flag}-S OUTPUT 2>/dev/null"
        try:
            out, _ = Adb.send_adb_command("shell " + self._ca._root_cmd(cmd))
        except Exception:
            return False
        return "OUTPUT" in (out or "")

    def _ip6_filter_ok(self) -> bool:
        return self._ip6_caps()[0]

    def _ip6_nat_ok(self) -> bool:
        return self._ip6_caps()[1]

    def _rule_body(self, uid: int, redirect_port: int, tagged: bool) -> str:
        comment = f'-m comment --comment "{self._RULE_TAG}" ' if tagged else ""
        return (
            f"-t nat {{op}} OUTPUT -m owner --uid-owner {uid} -p tcp "
            f"{comment}-j REDIRECT --to-ports {redirect_port}"
        )

    def _v6_reject_body(self, uid: int, tagged: bool, target: str = "REJECT") -> str:
        """Filter-table rule rejecting the UID's IPv6 TCP (fail closed)."""
        comment = f'-m comment --comment "{self._RULE_TAG}" ' if tagged else ""
        jump = "REJECT --reject-with tcp-reset" if target == "REJECT" else target
        return f"{{op}} OUTPUT -m owner --uid-owner {uid} -p tcp {comment}-j {jump}"

    def _install_rule(
        self, tbl: str, make_body, *, insert: bool, allow_drop: bool
    ) -> tuple[str, str]:
        """Delete-then-add one rule with the tag/REJECT fallbacks.

        Args:
            tbl: ``iptables`` or ``ip6tables``.
            make_body: ``(tagged, target) -> body`` with an ``{op}`` slot.
            insert: ``-I`` (ahead of Android's own chains) instead of ``-A``.
            allow_drop: Fall back from REJECT to DROP when REJECT is missing.

        Returns:
            ``(body_used, error)``; ``error`` is empty on success.
        """
        tagged, target, err, body = True, "REJECT", "", ""
        op = "-I" if insert else "-A"
        for _ in range(4):
            body = make_body(tagged, target)
            self._delete_rule_loop(tbl, body)
            try:
                _, err = Adb.send_adb_command(
                    f"shell {self._ca._root_cmd(f'{tbl} -w ' + body.format(op=op))}"
                )
            except Exception as exc:
                err = str(exc)
            if self._is_comment_error(err) and tagged:
                tagged = False
                continue
            if allow_drop and self._is_reject_error(err) and target == "REJECT":
                target = "DROP"
                continue
            break
        if not tagged and not (err or "").strip():
            # No xt_comment: observe must list untagged rules from now on.
            self._untagged_serials.add(Adb.get_target_device())
        return body, (err or "").strip()

    @staticmethod
    def _remember(store: dict, lane: int, spec: tuple[str, str]) -> None:
        specs = store.setdefault(lane, [])
        if spec not in specs:
            specs.append(spec)

    def _ensure_v6_fence(self, lane: int, uid: int) -> None:
        """REJECT the UID's IPv6 TCP unless v6 can be redirected (best-effort).

        Without it a lane whose gost died, or a host with global IPv6, let
        the app reach the internet over v6 past mitmproxy.
        """
        filter_ok, nat_ok = self._ip6_caps()
        if nat_ok or not filter_ok:
            if not filter_ok and not nat_ok:
                logger.warning(
                    "ip6tables unavailable: IPv6 traffic of uid %s is not fenced",
                    uid,
                )
            return
        body, err = self._install_rule(
            "ip6tables",
            lambda tagged, target: self._v6_reject_body(uid, tagged, target),
            insert=True,
            allow_drop=True,
        )
        self._remember(self._lane_rule_specs, lane, ("ip6tables", body))
        if err:
            logger.warning("ip6tables fence (uid %s) add warning: %s", uid, err)

    def _ensure_redirect(
        self,
        lane: int,
        uid: int,
        redirect_port: int,
        *,
        families: set[str] | frozenset[str] = frozenset({"4", "6"}),
    ) -> tuple[bool, str]:
        """Add the v4 (and, with a v6 nat table, v6) REDIRECT of a lane.

        Only the *families* asked for (a reconcile re-adds just the missing
        one; re-adding a present rule would open a delete-then-add gap).
        The IPv4 rule is fatal: a genuine failure is returned so the caller
        rolls back, because a redirector with no rule captures nothing. A
        failed v6 REDIRECT falls back to the v6 REJECT (fail closed).

        Returns:
            ``(ok, message)``.
        """
        tables = []
        if "4" in families:
            tables.append(("iptables", True))
        if "6" in families and self._ip6_nat_ok():
            tables.append(("ip6tables", False))
        for tbl, fatal in tables:
            body, err = self._install_rule(
                tbl,
                lambda tagged, _target: self._rule_body(uid, redirect_port, tagged),
                insert=False,
                allow_drop=False,
            )
            if err:
                if fatal:
                    return False, f"iptables redirect rule failed: {err}"
                self._v6_redirect_failed(lane, uid, err)
                continue
            self._remember(self._lane_rule_specs, lane, (tbl, body))
        return True, "rules added"

    def _v6_redirect_failed(self, lane: int, uid: int, err: str) -> None:
        """ip6tables nat exists but the v6 REDIRECT failed: REJECT v6 instead."""
        serial = Adb.get_target_device()
        logger.warning(
            "ip6tables redirect failed (%s): IPv6 TCP of uid %s is rejected instead",
            err,
            uid,
        )
        self._ip6_redirect_broken.add(serial)
        filter_ok = self._ip6_caps()[0]
        self._ip6_cap_cache[serial] = (filter_ok, False)
        self._ensure_v6_fence(lane, uid)

    def _quic_rule_body(self, uid: int, tagged: bool, target: str = "REJECT") -> str:
        """A filter-table OUTPUT rule REJECTing the UID's QUIC (UDP/443).

        No ``-t nat`` ⇒ the (default) filter table, kept separate from the nat
        REDIRECT rules. ``uid``/``comment``/``target`` are interpolated now and
        ONLY ``{{op}}`` is left for ``.format(op=...)`` — so the stored spec is
        directly delete-able via the shared ``_delete_rule_loop`` (if ``{uid}``
        survived into the spec, ``body.format(op='-D')`` would raise KeyError).
        """
        comment = f'-m comment --comment "{self._RULE_TAG}" ' if tagged else ""
        return (
            f"{{op}} OUTPUT -m owner --uid-owner {uid} -p udp --dport 443 "
            f"{comment}-j {target}"
        )

    def _add_quic_block(self, lane: int, uid: int) -> None:
        """Best-effort REJECT of the lane UID's QUIC (UDP/443), v4 (+v6).

        Forces the app off HTTP/3 — which the TCP-only nat REDIRECT can't
        intercept — back onto interceptable TCP/TLS. Inserted (``-I``) ahead
        of Android's own OUTPUT chains, tracked in ``_lane_quic_specs`` so the
        toggle/teardown can delete just them; REJECT→DROP and untagged
        fallbacks as before. Non-fatal: a failure leaves the TCP redirect
        working, so we log and move on.
        """
        tbls = ["iptables"]
        if self._ip6_filter_ok():
            tbls.append("ip6tables")
        for tbl in tbls:
            body, err = self._install_rule(
                tbl,
                lambda tagged, target: self._quic_rule_body(uid, tagged, target),
                insert=True,
                allow_drop=True,
            )
            self._remember(self._lane_quic_specs, lane, (tbl, body))
            if err:
                logger.warning("%s QUIC-block (uid %s) add warning: %s", tbl, uid, err)

    @staticmethod
    def _is_reject_error(err: str) -> bool:
        """Whether a REJECT add failed because the target isn't loadable.

        Legacy iptables names it (``Couldn't load target `REJECT'``), but
        nf_tables kernels (Android 10+) emit a bare ``No chain/target/match by
        that name`` with no target token. The caller checks this ONLY on a
        REJECT add and ONLY after the xt_comment fallback, so any load/match
        failure that reaches here means REJECT is unavailable → fall back to
        DROP (matching only the legacy ``reject`` token would silently skip the
        fallback on nf_tables and leave QUIC unblocked).
        """
        text = (err or "").lower()
        return "couldn't load" in text or "no chain/target/match" in text

    @staticmethod
    def _is_absent_rule(err: str) -> bool:
        """Whether a ``-D`` failed only because no such rule is there."""
        return "No chain/target/match" in err or "does a matching" in err

    def _delete_rule_loop(self, tbl: str, body: str) -> None:
        """Delete every copy of a rule (never raises).

        The loop ends at the "no such rule" answer: the expected last round,
        and the only answer for a rule that was never added (the delete
        before every add, an ip6tables rule on a kernel without it). That
        one is DEBUG; any other error stops the loop and is a WARNING.
        """
        from sandroid.core.adb_utils import quiet_adb_warnings

        del_cmd = f"{tbl} {body.format(op='-D')}"
        for _ in range(10):
            try:
                with quiet_adb_warnings():
                    _, err = Adb.send_adb_command(
                        f"shell {self._ca._root_cmd(del_cmd)}"
                    )
            except Exception as exc:
                logger.debug("%s rule delete failed: %s", tbl, exc)
                return
            text = (err or "").strip()
            if not text:
                continue
            if self._is_absent_rule(text):
                logger.debug("%s rule absent (%s): %s", tbl, del_cmd, text)
            else:
                # Any other error (e.g. bad rule, device gone): stop trying.
                logger.warning("Removing an App Proxy %s rule failed: %s", tbl, text)
            return

    @staticmethod
    def _is_comment_error(err: str) -> bool:
        text = (err or "").lower()
        return "comment" in text and (
            "couldn't load" in text or "no chain/target/match" in text
        )

    def _remove_lane_rules(self, lane: int) -> None:
        """Delete a lane's recorded rule specs (v4+v6), ignoring errors.

        Removes both the nat REDIRECT specs and the filter-table QUIC-block
        specs, so disabling an app proxy leaves no stray rule in either table.
        """
        for tbl, body in self._lane_rule_specs.get(lane, []):
            self._delete_rule_loop(tbl, body)
        self._lane_rule_specs.pop(lane, None)
        for tbl, body in self._lane_quic_specs.get(lane, []):
            self._delete_rule_loop(tbl, body)
        self._lane_quic_specs.pop(lane, None)

    # ── lane teardown / cleanup ───────────────────────────────────────

    def _teardown_lane(self, lane: int) -> None:
        """Rules-first removal, then kill the lane's gost; free the slot."""
        package = self._lanes.get(lane)
        with Adb.targeting(self._lane_serials.get(lane)):
            self._remove_lane_rules(lane)
            self._kill_lane_process(self._redirect_port(lane))
        self._lanes[lane] = None
        self._lane_targets.pop(lane, None)
        self._lane_uids.pop(lane, None)
        self._lane_serials.pop(lane, None)
        self._lane_upstreams.pop(lane, None)
        self._lane_health.pop(lane, None)
        if package:
            self._remove_from_state(package)

    def _cleanup_stale_locked(self) -> None:
        """Remove every tagged OUTPUT rule + stray gost; clear lane state.

        Sweeps the tagged ``-A OUTPUT`` rules out of BOTH the ``nat`` table
        (REDIRECT rules) and the ``filter`` table (QUIC-block REJECT rules) so a
        SIGKILL'd prior run self-heals in either table. The table flag is
        parameterized per pass — ``-t nat`` for the nat pass, omitted for the
        filter pass — and the reconstructed ``-D`` delete reuses the SAME flag
        it listed (a stale ``-t nat`` copied into the filter delete would miss).

        gost is killed by PID, and only the gost of OUR lane port range (never
        ``pkill -f``, which also hit other sessions' gost). Also kills/removes
        any leftover ipt2socks (the pre-gost redirector) so a device
        transitioned from the old build self-heals.
        """
        ip6_filter, ip6_nat = self._ip6_caps()
        passes = [("iptables", "-t nat "), ("iptables", "")]
        if ip6_filter:
            passes.append(("ip6tables", ""))
        if ip6_nat:
            passes.append(("ip6tables", "-t nat "))
        # ("-t nat ", "") — trailing space so f"{tbl} {flag}-S OUTPUT" stays
        # well-formed; "" targets the default (filter) table.
        for tbl, table_flag in passes:
            try:
                out, _ = Adb.send_adb_command(
                    f"shell {self._ca._root_cmd(f'{tbl} {table_flag}-S OUTPUT')}"
                )
            except Exception:
                continue
            for line in (out or "").splitlines():
                if self._RULE_TAG not in line:
                    continue
                spec = line.strip()
                if not spec.startswith("-A "):
                    continue
                del_spec = "-D " + spec[len("-A ") :]
                del_cmd = f"{tbl} {table_flag}{del_spec}"
                try:
                    Adb.send_adb_command(f"shell {self._ca._root_cmd(del_cmd)}")
                except Exception:
                    pass
        # Kill the gost of our lane ports and any ipt2socks (legacy), then
        # remove the legacy ipt2socks binary so transitioned devices self-heal.
        # Runs once per session (mount/atexit/stop), not per-lane.
        ports = range(self._redirect_base, self._redirect_base + self._pool_size)
        self._run_lane("kill", self._binary_dst, *(str(p) for p in ports))
        try:
            Adb.send_adb_command(f"shell {self._ca._root_cmd('pkill -f ipt2socks')}")
        except Exception:
            pass
        try:
            Adb.send_adb_command(
                f"shell {self._ca._root_cmd('rm -f /data/local/tmp/ipt2socks')}"
            )
        except Exception:
            pass
        # Forget only the lanes of THIS device: lanes on another device are
        # still live there and must stay tracked so they can be torn down.
        serial = Adb.get_target_device()
        for lane in list(self._lanes):
            if self._lane_serials.get(lane, serial) != serial:
                continue
            self._lanes.pop(lane, None)
            self._lane_targets.pop(lane, None)
            self._lane_rule_specs.pop(lane, None)
            self._lane_uids.pop(lane, None)
            self._lane_quic_specs.pop(lane, None)
            self._lane_serials.pop(lane, None)
            self._lane_upstreams.pop(lane, None)
            self._lane_health.pop(lane, None)
        try:
            self._write_sidecar()
        except Exception:
            pass

    def _atexit_cleanup(self) -> None:
        try:
            self.disable_focus()
        except Exception:
            pass

    # ── sidecar map ───────────────────────────────────────────────────

    @staticmethod
    def _sidecar_path() -> str:
        default = os.path.expanduser("~/.cache/sandroid/focus_lanes.json")
        try:
            if get_config is not None:
                return os.path.expanduser(get_config().focus.sidecar_path)
        except Exception:
            pass
        return default

    def _write_sidecar(self) -> None:
        """Atomically write the lane→app sidecar map (string SOCKS-port keys).

        Shape: ``{"8082": {"package": "com.foo", "marker": ":green_circle:"}}``.
        Empty when no lane is assigned.
        """
        import json

        data: dict[str, dict[str, str]] = {}
        for lane, package in self._lanes.items():
            if not package:
                continue
            # External lanes forward to an HTTP proxy (Burp/ZAP) and never reach
            # our mitmweb SOCKS listener, so there is no arrival port to key on —
            # the addon can't (and shouldn't) attribute them. Skip them; only
            # our-mitmproxy lanes get a sidecar entry.
            if self._lane_targets.get(lane, "ours") != "ours":
                continue
            data[str(self._socks_port(lane))] = {
                "package": package,
                "marker": self._marker(lane),
            }
        path = self._sidecar_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                prefix="focus_lanes_", suffix=".json", dir=os.path.dirname(path)
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
            Path(tmp).replace(path)
        except OSError as exc:
            logger.warning("Failed to write Focus sidecar map: %s", exc)

    # ── shared MitmproxyState mirroring ───────────────────────────────

    @staticmethod
    def _mitm_state():
        try:
            from sandroid.services.mitmproxy_service import get_mitmproxy_service

            return get_mitmproxy_service().state
        except Exception:
            return None

    def _add_to_state(self, package: str) -> None:
        state = self._mitm_state()
        if state is not None and package not in state.focus_apps:
            state.focus_apps.append(package)

    def _remove_from_state(self, package: str) -> None:
        state = self._mitm_state()
        if state is not None and package in state.focus_apps:
            try:
                state.focus_apps.remove(package)
            except ValueError:
                pass


_FOCUS_INSTANCE: FocusManager | None = None
_FOCUS_INSTANCE_LOCK = threading.Lock()


def get_focus_manager() -> FocusManager:
    """Module-level accessor for the singleton FocusManager."""
    global _FOCUS_INSTANCE
    if _FOCUS_INSTANCE is None:
        with _FOCUS_INSTANCE_LOCK:
            if _FOCUS_INSTANCE is None:
                _FOCUS_INSTANCE = FocusManager()
    return _FOCUS_INSTANCE


# Convenience functions for use without class instantiation
def get_proxy_status() -> tuple[ProxyStatus, ProxyConfig | None]:
    """Get current proxy status using default ADB wrapper."""
    return ProxyManager().get_proxy_settings()


def set_proxy(ip: str, port: int) -> tuple[bool, str]:
    """Set proxy using default ADB wrapper."""
    return ProxyManager().set_proxy(ProxyConfig(ip=ip, port=port))


def unset_proxy() -> tuple[bool, str]:
    """Unset proxy using default ADB wrapper."""
    return ProxyManager().unset_proxy()


def detect_ca_certificates() -> list[CAInfo]:
    """Detect available CA certificates on host."""
    return CAManager().detect_ca_certificates()
