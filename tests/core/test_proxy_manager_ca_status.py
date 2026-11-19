"""CAManager trust store: status read in Zygote's namespace, the no-restart
install, rotation, removal and the per-serial re-inject intent.

The device side is one script per operation (``_CA_SCRIPT``); these tests
feed its recorded output shapes (API 35, emulator) through a fake adb.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import re
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sandroid.core import proxy_manager as pm

SERIAL = "emulator-5570"


def _mitm_like_cert() -> bytes:
    """A self-signed ``CN=mitmproxy, O=mitmproxy`` CA (PEM), fresh key each call."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "mitmproxy"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mitmproxy"),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def host_ca(tmp_path):
    path = tmp_path / "mitmproxy-ca-cert.pem"
    path.write_bytes(_mitm_like_cert())
    return path


@pytest.fixture(autouse=True)
def _no_intent():
    pm._CA_DESIRED.clear()
    yield
    pm._CA_DESIRED.clear()


def _status_out(zyg_sha, *, ss_sha=None, target_sha=None, lack=0, dev="0:101"):
    ss_sha = zyg_sha if ss_sha is None else ss_sha
    lines = [
        f"our_dev={dev if zyg_sha else 'none'}",
        f"ns role=init pid=1 comm=init mount=none file={zyg_sha or 'missing'}",
        "ns role=zygote pid=712 comm=zygote64 mount="
        f"{dev + '/tmpfs' if zyg_sha else 'none'} file={zyg_sha or 'missing'}",
        f"ns role=system_server pid=728 comm=system_server mount=none "
        f"file={ss_sha or 'missing'}",
    ]
    if target_sha is not None:
        lines.append(
            f"ns role=target pid=5396 comm=canary mount=none file={target_sha}"
        )
    if zyg_sha:
        lines.append(f"namespaces have={36 - lack} lack={lack}")
    lines.append("rc=0")
    return "\n".join(lines) + "\n"


class _Device:
    """Fake adb: decodes the base64 script runs and answers per operation."""

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.ops: list[list[str]] = []
        self.root = True
        self.status = _status_out(None)
        self.inject_out = "inject: tmpfs on ...\nsweep: bound=36 already=0 failed=0\n"
        self.inject_out += "sweep: bound=0 already=36 failed=0\nrc=0\n"
        self.after_inject: str | None = None
        self.ns_cat = ""

    def __call__(self, cmd, serial=None, timeout=30):
        self.sent.append(cmd)
        if cmd == "shell id":
            return ("uid=0(root)" if self.root else "uid=2000(shell)"), ""
        if "su -c id" in cmd:
            return "", "su: not found"
        if cmd.startswith("push "):
            return "1 file pushed", ""
        if "[ -d" in cmd:
            return "EXISTS", ""
        if "nsenter" in cmd and " cat " in cmd:
            return self.ns_cat, ""
        m = re.search(
            r"echo ([A-Za-z0-9+/=]+) \| base64 -d \| (?:su -c '?)?sh -s -- (.*)'$", cmd
        )
        if m:
            script = base64.b64decode(m.group(1)).decode()
            assert script == pm._CA_SCRIPT
            args = m.group(2).rstrip("'").split()
            self.ops.append(args)
            op = args[0]
            if op == "status":
                return self.status, ""
            if op == "inject":
                if self.after_inject is not None:
                    self.status = self.after_inject
                return self.inject_out, ""
            if op == "uninject":
                self.status = _status_out(None)
                return "uninject: unmounted=37 failed=0\nrc=0\n", ""
            if op == "restart-zygote":
                return "ss_before=728\nkilled=712\nrc=0\n", ""
        return "", ""


@pytest.fixture
def device(monkeypatch):
    dev = _Device()
    monkeypatch.setattr(pm.Adb, "send_adb_command", staticmethod(dev))
    monkeypatch.setattr(pm.Adb, "_target_device", SERIAL)
    monkeypatch.setattr(pm.CAManager, "get_device_api_level", lambda self: 35)
    return dev


def _sha(path) -> str:
    return pm.CAManager().ca_spec(path).pem_sha256


# -- pure parsing / verdicts ---------------------------------------------------


def test_subject_hash_matches_openssl_format(host_ca):
    cert_hash, fp = pm.CAManager().cert_identity(host_ca)
    assert cert_hash
    assert len(cert_hash) == 8
    assert fp
    assert len(fp) == 64
    other = host_ca.parent / "other.pem"
    other.write_bytes(_mitm_like_cert())
    other_hash, other_fp = pm.CAManager().cert_identity(other)
    assert other_hash == cert_hash
    assert other_fp != fp


def test_parse_status_reads_every_namespace():
    report = pm.parse_ca_status(_status_out("ab" * 32, target_sha="ab" * 32, lack=2))
    roles = [(ns.role, ns.pid, ns.comm) for ns in report.namespaces]
    assert roles == [
        ("init", 1, "init"),
        ("zygote", 712, "zygote64"),
        ("system_server", 728, "system_server"),
        ("target", 5396, "canary"),
    ]
    assert report.our_dev == "0:101"
    assert (report.have, report.lack) == (34, 2)


@pytest.mark.parametrize(
    ("out", "verdict"),
    [
        (_status_out("aa" * 32), "injected"),
        (_status_out("aa" * 32, target_sha="missing"), "partial"),
        (_status_out("aa" * 32, lack=3), "partial"),
        (_status_out("aa" * 32, ss_sha="missing"), "partial"),
        (_status_out("bb" * 32), "other_ca"),
        (_status_out(None), "absent"),
        ("our_dev=none\nrc=0\n", "unknown"),
    ],
)
def test_verdicts(out, verdict):
    assert pm.ca_verdict(pm.parse_ca_status(out), {"aa" * 32}) == verdict


def test_script_rc_trailer():
    assert pm._script_rc("x\nrc=0\n") == 0
    assert pm._script_rc("sweep: failed pid=9\nrc=8") == 8
    assert pm._script_rc("no trailer") is None


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh")
@pytest.mark.parametrize("script", ["_CA_SCRIPT", "_LANE_SCRIPT"])
def test_device_scripts_parse(script, tmp_path):
    path = tmp_path / "s.sh"
    path.write_text(getattr(pm, script))
    assert subprocess.run(["sh", "-n", str(path)], check=False).returncode == 0


def test_script_runs_as_one_base64_command(monkeypatch):
    sent = []
    monkeypatch.setattr(
        pm.Adb,
        "send_adb_command",
        staticmethod(lambda cmd, serial=None, timeout=30: sent.append((cmd, serial))),
    )
    pm.run_device_script("echo hi", ["status", "a b"], serial=SERIAL)
    pm.run_device_script("echo hi", ["x"], serial=SERIAL, use_su=True)
    (plain, serial), (su, _) = sent
    assert serial == SERIAL
    payload = base64.b64encode(b"echo hi").decode()
    assert (
        plain
        == f"shell 'echo {payload} | base64 -d | sh -s -- status '\"'\"'a b'\"'\"''"
    )
    assert "base64 -d | su -c " in su


# -- status: Zygote's namespace, never the adb shell's ---------------------------


def test_status_reads_zygote_namespace_not_the_adb_shell(host_ca, device):
    device.status = _status_out(_sha(host_ca))
    status = pm.CAManager().check_zygote_injection_status(host_ca)
    assert status.injected
    assert status.verdict == "injected"
    assert status.zygote64_pid == 712
    assert status.location == "/apex/com.android.conscrypt/cacerts"
    # No plain `cat` of the trust store in adb's own (init) namespace.
    assert not any(c.startswith("shell 'cat ") for c in device.sent)
    assert device.ops == [["status", status.cert_hash + ".0", "1"]]


def test_status_target_pid_is_checked(host_ca, device):
    device.status = _status_out(_sha(host_ca), target_sha="missing")
    status = pm.CAManager().check_zygote_injection_status(host_ca, target_pid=5396)
    assert status.verdict == "partial"
    assert status.target_injected is False
    assert device.ops[-1][-1] == "5396"


def test_same_hash_different_ca_is_not_ours(host_ca, device):
    device.status = _status_out("cc" * 32)
    device.ns_cat = _mitm_like_cert().decode()
    status = pm.CAManager().check_zygote_injection_status(host_ca)
    assert not status.injected
    assert status.verdict == "other_ca"
    assert "different CA" in (status.error_message or "")


def test_our_ca_in_another_file_layout_counts(host_ca, device):
    """An older Sandroid pushed the PEM with ``openssl x509 -text`` in front:
    another SHA-256, same certificate.
    """
    device.status = _status_out("dd" * 32)
    device.ns_cat = "Certificate:\n    Data: ...\n" + host_ca.read_text()
    status = pm.CAManager().check_zygote_injection_status(host_ca)
    assert status.verdict == "injected"


def test_not_injected_on_clean_device(host_ca, device):
    status = pm.CAManager().check_zygote_injection_status(host_ca)
    assert not status.injected
    assert status.verdict == "absent"
    assert status.error_message is None


def test_status_without_root_says_so(host_ca, device):
    device.root = False
    status = pm.CAManager().check_zygote_injection_status(host_ca)
    assert status.verdict == "unknown"
    assert "Root" in (status.error_message or "")


def test_defaults_to_host_mitmproxy_ca(host_ca, device, monkeypatch):
    mgr = pm.CAManager()
    monkeypatch.setattr(mgr, "_sandroid_ca_path", lambda: host_ca)
    device.status = _status_out(_sha(host_ca))
    assert mgr.check_zygote_injection_status().injected


# -- inject: no restart, idempotent, intent per serial ---------------------------


def test_inject_never_restarts_and_records_the_intent(host_ca, device):
    device.after_inject = _status_out(_sha(host_ca))
    result = pm.CAManager().inject_ca_into_zygote(host_ca)
    assert result.success, result.message
    assert not result.restart_required
    assert "without a Zygote restart" in result.message
    assert [op[0] for op in device.ops] == ["inject", "status"]
    assert not any("restart-zygote" in " ".join(op) for op in device.ops)
    assert not any(re.search(r"\bkill\b", c) for c in device.sent)
    # The canonical PEM went to the staging path; the stage is the arg.
    assert any(c.startswith("push ") and pm._CA_STAGE_PATH in c for c in device.sent)
    assert device.ops[0][1:] == [pm._CA_STAGE_PATH, _name(host_ca), "1"]
    spec = pm.ca_desired_for(SERIAL)
    assert spec is not None
    assert spec.cert_path == host_ca
    assert pm.ca_desired_for("emulator-5554") is None


def _name(path) -> str:
    return pm.CAManager().ca_spec(path).name


def test_failed_no_restart_path_reports_restart_required(host_ca, device):
    device.inject_out = "inject: nsenter missing\nrc=3\n"
    result = pm.CAManager().inject_ca_into_zygote(host_ca)
    assert not result.success
    assert result.restart_required
    assert "nsenter missing" in result.message
    assert pm.ca_desired_for(SERIAL) is None
    assert not any("restart-zygote" in " ".join(op) for op in device.ops)


def test_inject_needs_root(host_ca, device):
    device.root = False
    result = pm.CAManager().inject_ca_into_zygote(host_ca)
    assert result.needs_root
    assert device.ops == []


def test_canonical_pem_hash_matches_what_the_device_reports(host_ca):
    spec = pm.CAManager().ca_spec(host_ca)
    assert spec.pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert spec.pem_sha256 == hashlib.sha256(spec.pem).hexdigest()
    der = host_ca.parent / "ca.der"
    cert = x509.load_pem_x509_certificate(host_ca.read_bytes())
    der.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    assert pm.CAManager().ca_spec(der).pem_sha256 == spec.pem_sha256


# -- uninject / reconcile ---------------------------------------------------------


def test_uninject_clears_the_intent_and_warns_about_running_apps(host_ca, device):
    pm.remember_ca_intent(SERIAL, pm.CAManager().ca_spec(host_ca))
    ok, message = pm.CAManager().uninject_ca()
    assert ok
    assert pm.CA_RUNNING_APPS_NOTE in message
    assert pm.ca_desired_for(SERIAL) is None
    assert device.ops == [["uninject", "1"]]


def test_reconcile_without_intent_touches_nothing(device):
    assert pm.CAManager().reconcile_ca(SERIAL) == "none"
    assert device.sent == []


def test_reconcile_keeps_an_injected_ca(host_ca, device):
    pm.remember_ca_intent(SERIAL, pm.CAManager().ca_spec(host_ca))
    device.status = _status_out(_sha(host_ca))
    assert pm.CAManager().reconcile_ca(SERIAL) == "kept"
    assert [op[0] for op in device.ops] == ["status"]


def test_reconcile_reinjects_without_restart_after_a_load(host_ca, device):
    """A snapshot saved before the injection came back without the CA."""
    pm.remember_ca_intent(SERIAL, pm.CAManager().ca_spec(host_ca))
    device.after_inject = _status_out(_sha(host_ca))
    assert pm.CAManager().reconcile_ca(SERIAL) == "re-injected"
    assert [op[0] for op in device.ops] == ["status", "inject", "status"]
    assert not any("restart-zygote" in " ".join(op) for op in device.ops)


def test_reconcile_never_restarts_when_the_no_restart_path_fails(host_ca, device):
    pm.remember_ca_intent(SERIAL, pm.CAManager().ca_spec(host_ca))
    device.inject_out = "inject: tmpfs mount failed\nrc=5\n"
    outcome = pm.CAManager().reconcile_ca(SERIAL)
    assert outcome.startswith("failed")
    assert "TUI" in outcome
    assert not any("restart-zygote" in " ".join(op) for op in device.ops)


def test_rotation_says_running_apps_keep_the_old_trust(host_ca, device):
    device.after_inject = _status_out(_sha(host_ca))
    device.inject_out = "inject: reusing the tmpfs\ninject: previous=" + "ee" * 32
    device.inject_out += "\nsweep: bound=0 already=36 failed=0\nrc=0\n"
    result = pm.CAManager().inject_ca_into_zygote(host_ca)
    assert result.success
    assert pm.CA_RUNNING_APPS_NOTE in result.message
    device.inject_out = device.inject_out.replace("ee" * 32, _sha(host_ca))
    assert (
        pm.CA_RUNNING_APPS_NOTE
        not in pm.CAManager().inject_ca_into_zygote(host_ca).message
    )
