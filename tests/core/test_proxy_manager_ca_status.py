"""CAManager trust-store status (phase-3 finding: an active bind mount from an
earlier session was reported as "no CA in trust store yet").
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sandroid.core import proxy_manager as pm

APEX = "/apex/com.android.conscrypt/cacerts"
SYSTEM = "/system/etc/security/cacerts"


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


@pytest.fixture
def device(monkeypatch):
    """Fake device: ``files`` maps path -> content (adb-shell view);
    ``ns_files`` is what Zygote's mount namespace sees (root only).
    """
    state = {"files": {}, "ns_files": {}, "root": False, "api": 35, "sent": []}

    def _send(cmd, serial=None):
        state["sent"].append(cmd)
        if "ps -A" in cmd:
            return "root 812 1 0 0 0 S zygote64\n", ""
        if cmd == "shell id":
            return ("uid=0(root)" if state["root"] else "uid=2000(shell)"), ""
        if "su -c id" in cmd:
            return "", "su: not found"
        if "nsenter" in cmd and " cat " in cmd:
            path = cmd.split(" cat ", 1)[1].strip(" '")
            return state["ns_files"].get(path, ""), ""
        if cmd.startswith("shell cat "):
            path = cmd[len("shell cat ") :]
            if path in state["files"]:
                return state["files"][path], ""
            return "", f"cat: {path}: No such file or directory"
        if "[ -d" in cmd:
            return ("EXISTS" if state["api"] >= 34 else ""), ""
        return "", ""

    monkeypatch.setattr(pm.Adb, "send_adb_command", staticmethod(_send))
    monkeypatch.setattr(pm.CAManager, "get_device_api_level", lambda self: state["api"])
    return state


def test_subject_hash_matches_openssl_format(host_ca):
    cert_hash, fp = pm.CAManager().cert_identity(host_ca)
    assert cert_hash
    assert len(cert_hash) == 8
    assert int(cert_hash, 16) >= 0
    assert fp
    assert len(fp) == 64
    # Every mitmproxy CA has the same subject, hence the same file name.
    other = host_ca.parent / "other.pem"
    other.write_bytes(_mitm_like_cert())
    other_hash, other_fp = pm.CAManager().cert_identity(other)
    assert other_hash == cert_hash
    assert other_fp != fp


def test_existing_apex_bind_mount_is_recognised(host_ca, device):
    """API 34+: an active bind mount from an earlier session counts, without
    the staging file and without root.
    """
    mgr = pm.CAManager()
    cert_hash, _ = mgr.cert_identity(host_ca)
    device["files"][f"{APEX}/{cert_hash}.0"] = host_ca.read_text()
    status = mgr.check_zygote_injection_status(host_ca)
    assert status.injected
    assert status.location == APEX
    assert status.fingerprint_verified
    assert status.cert_hash == cert_hash
    assert not any("cert-der.crt" in c for c in device["sent"])


def test_api_33_checks_system_cacerts(host_ca, device):
    device["api"] = 33
    mgr = pm.CAManager()
    cert_hash, _ = mgr.cert_identity(host_ca)
    # Present only in the APEX dir (not used on 33) → not trusted.
    device["files"][f"{APEX}/{cert_hash}.0"] = host_ca.read_text()
    assert not mgr.check_zygote_injection_status(host_ca).injected
    device["files"][f"{SYSTEM}/{cert_hash}.0"] = (
        "Certificate:\n    Data: ...\n" + host_ca.read_text()
    )
    status = mgr.check_zygote_injection_status(host_ca)
    assert status.injected
    assert status.location == SYSTEM


def test_same_hash_different_ca_is_not_ours(host_ca, device):
    mgr = pm.CAManager()
    cert_hash, _ = mgr.cert_identity(host_ca)
    device["files"][f"{APEX}/{cert_hash}.0"] = _mitm_like_cert().decode()
    status = mgr.check_zygote_injection_status(host_ca)
    assert not status.injected
    assert "different CA" in (status.error_message or "")


def test_zygote_namespace_checked_with_root(host_ca, device):
    """Not visible to adb shell, but inside Zygote's namespace (adb root)."""
    device["root"] = True
    mgr = pm.CAManager()
    cert_hash, _ = mgr.cert_identity(host_ca)
    device["ns_files"][f"{APEX}/{cert_hash}.0"] = host_ca.read_text()
    status = mgr.check_zygote_injection_status(host_ca)
    assert status.injected
    # adb root: plain quoting, never `su -c` (which emulator su rejects).
    ns_cmds = [c for c in device["sent"] if "nsenter" in c]
    assert ns_cmds
    assert not any("su -c" in c for c in ns_cmds)


def test_not_injected_on_clean_device(host_ca, device):
    status = pm.CAManager().check_zygote_injection_status(host_ca)
    assert not status.injected
    assert status.error_message is None


def test_defaults_to_host_mitmproxy_ca(host_ca, device, monkeypatch):
    mgr = pm.CAManager()
    monkeypatch.setattr(mgr, "_sandroid_ca_path", lambda: host_ca)
    cert_hash, _ = mgr.cert_identity(host_ca)
    device["files"][f"{APEX}/{cert_hash}.0"] = host_ca.read_text()
    assert mgr.check_zygote_injection_status().injected
