"""Unit tests for sandroid.ai.tools.certificate_control.

``_get_ca_manager`` is looked up lazily inside each tool function's own body
(see that module's docstring), so tests monkeypatch
``certificate_control._get_ca_manager`` directly -- the same convention
``tests/ai/tools/test_environment_control.py`` uses for
``_get_frida_manager``. ``resolve_confined_host_path`` is imported by name
into ``certificate_control``'s own namespace, so custom-path tests
monkeypatch ``certificate_control.resolve_confined_host_path`` directly --
mirroring ``tests/ai/tools/test_host_files.py``'s convention for the same
helper.

Fixtures use the real ``CASource``/``InjectionStrategy``/``InjectionResult``/
``ZygoteStatus`` types from ``sandroid.core.proxy_manager`` (read-only
usage -- this test file never edits that module) so enum ``.value`` strings
match exactly what the tool code expects.
"""

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools import certificate_control as cc
from sandroid.core.proxy_manager import (
    CASource,
    InjectionResult,
    InjectionStrategy,
    ZygoteStatus,
)


@dataclass
class _FakeCAInfo:
    source: Any
    path: Path
    display_name: str
    exists: bool


def _patch_ca_manager(monkeypatch, manager):
    monkeypatch.setattr(cc, "_get_ca_manager", lambda: manager)


# -- list_detected_ca_certificates -----------------------------------------------


def test_list_detected_ca_certificates_passes_through(monkeypatch, tmp_path):
    cert_path = tmp_path / "mitmproxy-ca-cert.pem"
    cert_path.write_text("fake pem bytes")
    fake_cert = _FakeCAInfo(
        source=CASource.MITMPROXY,
        path=cert_path,
        display_name="mitmproxy",
        exists=True,
    )
    _patch_ca_manager(
        monkeypatch, SimpleNamespace(detect_ca_certificates=lambda: [fake_cert])
    )

    assert cc.list_detected_ca_certificates() == {
        "certificates": [
            {
                "source": "mitmproxy",
                "path": str(cert_path),
                "display_name": "mitmproxy",
                "exists": True,
            }
        ],
        "count": 1,
    }


def test_list_detected_ca_certificates_empty(monkeypatch):
    _patch_ca_manager(monkeypatch, SimpleNamespace(detect_ca_certificates=list))

    assert cc.list_detected_ca_certificates() == {"certificates": [], "count": 0}


# -- push_ca_certificate ----------------------------------------------------------


def test_push_ca_certificate_default_source(monkeypatch, tmp_path):
    cert_path = tmp_path / "mitmproxy-ca-cert.pem"
    cert_path.write_text("fake pem bytes")
    fake_cert = _FakeCAInfo(
        source=CASource.MITMPROXY,
        path=cert_path,
        display_name="mitmproxy",
        exists=True,
    )
    captured = {}

    def fake_push(path):
        captured["path"] = path
        return True, "Certificate pushed to /data/local/tmp/cert-der.crt"

    _patch_ca_manager(
        monkeypatch,
        SimpleNamespace(
            detect_ca_certificates=lambda: [fake_cert], push_cert_to_device=fake_push
        ),
    )

    result = cc.push_ca_certificate()

    assert captured["path"] == cert_path
    assert result == {
        "success": True,
        "message": "Certificate pushed to /data/local/tmp/cert-der.crt",
        "path": str(cert_path),
    }


def test_push_ca_certificate_custom_path_is_confined(monkeypatch, tmp_path):
    custom_file = tmp_path / "custom.pem"
    custom_file.write_text("custom pem bytes")
    captured = {}

    def fake_resolve(user_path):
        captured["user_path"] = user_path
        return custom_file

    monkeypatch.setattr(cc, "resolve_confined_host_path", fake_resolve)
    _patch_ca_manager(
        monkeypatch,
        SimpleNamespace(push_cert_to_device=lambda path: (True, "pushed")),
    )

    result = cc.push_ca_certificate(source="custom", custom_path="custom.pem")

    assert captured["user_path"] == "custom.pem"
    assert result == {"success": True, "message": "pushed", "path": str(custom_file)}


def test_push_ca_certificate_custom_outside_allowlist_raises(monkeypatch):
    def fake_resolve(user_path):
        raise ToolExecutionError(
            f"path {user_path!r} is outside every allowed host directory"
        )

    monkeypatch.setattr(cc, "resolve_confined_host_path", fake_resolve)

    with pytest.raises(ToolExecutionError, match="outside every allowed"):
        cc.push_ca_certificate(source="custom", custom_path="../../etc/passwd")


def test_push_ca_certificate_custom_missing_path_raises(monkeypatch):
    with pytest.raises(ToolExecutionError, match="custom_path is required"):
        cc.push_ca_certificate(source="custom", custom_path=None)


def test_push_ca_certificate_source_not_detected_raises(monkeypatch):
    _patch_ca_manager(monkeypatch, SimpleNamespace(detect_ca_certificates=list))

    with pytest.raises(ToolExecutionError, match="list_detected_ca_certificates"):
        cc.push_ca_certificate(source="burp_suite")


# -- check_ca_injection_status -----------------------------------------------------


def test_check_ca_injection_status_passes_through(monkeypatch):
    zygote_status = ZygoteStatus(
        injected=True, cert_hash="a1b2c3d4", zygote_pid=100, zygote64_pid=101
    )
    _patch_ca_manager(
        monkeypatch,
        SimpleNamespace(
            check_zygote_injection_status=lambda: zygote_status,
            determine_injection_strategy=lambda: (InjectionStrategy.BIND_MOUNT, 34),
        ),
    )

    assert cc.check_ca_injection_status() == {
        "injected": True,
        "cert_hash": "a1b2c3d4",
        "zygote_pid": 100,
        "zygote64_pid": 101,
        "recommended_strategy": "bind_mount",
        "api_level": 34,
    }


def test_check_ca_injection_status_not_injected(monkeypatch):
    zygote_status = ZygoteStatus(
        injected=False, cert_hash=None, zygote_pid=100, zygote64_pid=101
    )
    _patch_ca_manager(
        monkeypatch,
        SimpleNamespace(
            check_zygote_injection_status=lambda: zygote_status,
            determine_injection_strategy=lambda: (InjectionStrategy.LEGACY, 28),
        ),
    )

    result = cc.check_ca_injection_status()

    assert result["injected"] is False
    assert result["cert_hash"] is None
    assert result["recommended_strategy"] == "legacy"
    assert result["api_level"] == 28


# -- enable_adb_root ----------------------------------------------------------------


def test_enable_adb_root_success(monkeypatch):
    _patch_ca_manager(
        monkeypatch,
        SimpleNamespace(
            enable_adb_root=lambda: (True, "ADB root enabled successfully")
        ),
    )

    assert cc.enable_adb_root() == {
        "success": True,
        "message": "ADB root enabled successfully",
    }


def test_enable_adb_root_not_rooted_failure(monkeypatch):
    _patch_ca_manager(
        monkeypatch,
        SimpleNamespace(
            enable_adb_root=lambda: (
                False,
                "Device does not support adb root. Please ensure the device "
                "is rooted.",
            )
        ),
    )

    result = cc.enable_adb_root()

    assert result["success"] is False
    assert "rooted" in result["message"]


# -- inject_ca_certificate ----------------------------------------------------------


def test_inject_ca_certificate_no_args_resolves_real_path_never_none(
    monkeypatch, tmp_path
):
    """Regression pinning the DER/PEM bug fix.

    ``inject_ca_into_zygote(cert_path=None)`` skips CAManager's
    PEM-producing re-push and infers PEM format purely from a hardcoded
    local filename -- which silently breaks once the on-device file is DER
    (the format the default push_cert_to_device() leaves behind).
    inject_ca_certificate() must always resolve a real Path and must never
    call the underlying manager with cert_path=None, even with no
    arguments at all.
    """
    cert_path = tmp_path / "mitmproxy-ca-cert.pem"
    cert_path.write_text("fake pem bytes")
    fake_cert = _FakeCAInfo(
        source=CASource.MITMPROXY,
        path=cert_path,
        display_name="mitmproxy",
        exists=True,
    )
    captured = {}

    def fake_inject(cert_path=None):
        captured["cert_path"] = cert_path
        return InjectionResult(
            success=True,
            message="CA injected",
            strategy=InjectionStrategy.BIND_MOUNT,
            api_level=34,
        )

    _patch_ca_manager(
        monkeypatch,
        SimpleNamespace(
            detect_ca_certificates=lambda: [fake_cert],
            inject_ca_into_zygote=fake_inject,
            bypass_chrome_ct=lambda path: (True, "Chrome CT bypass installed"),
        ),
    )

    result = cc.inject_ca_certificate()

    assert captured["cert_path"] is not None
    assert captured["cert_path"] == cert_path
    assert isinstance(captured["cert_path"], Path)
    assert result == {
        "success": True,
        "message": "CA injected",
        "needs_root": False,
        "strategy": "bind_mount",
        "api_level": 34,
        "chrome_ct_bypass": {"success": True, "message": "Chrome CT bypass installed"},
    }


def test_inject_ca_certificate_needs_root_does_not_autochain(monkeypatch, tmp_path):
    cert_path = tmp_path / "mitmproxy-ca-cert.pem"
    cert_path.write_text("fake pem bytes")
    fake_cert = _FakeCAInfo(
        source=CASource.MITMPROXY,
        path=cert_path,
        display_name="mitmproxy",
        exists=True,
    )
    root_calls = []
    ct_calls = []

    _patch_ca_manager(
        monkeypatch,
        SimpleNamespace(
            detect_ca_certificates=lambda: [fake_cert],
            inject_ca_into_zygote=lambda cert_path=None: InjectionResult(
                success=False,
                message="Root access required. Is the device rooted with 'su'?",
                needs_root=True,
            ),
            enable_adb_root=lambda: root_calls.append("called") or (True, "rooted"),
            bypass_chrome_ct=lambda path: ct_calls.append("called") or (True, "ok"),
        ),
    )

    result = cc.inject_ca_certificate()

    assert result["success"] is False
    assert result["needs_root"] is True
    assert result["chrome_ct_bypass"] is None
    assert root_calls == []
    assert ct_calls == []


def test_inject_ca_certificate_no_cert_on_device_failure(monkeypatch, tmp_path):
    cert_path = tmp_path / "mitmproxy-ca-cert.pem"
    cert_path.write_text("fake pem bytes")
    fake_cert = _FakeCAInfo(
        source=CASource.MITMPROXY,
        path=cert_path,
        display_name="mitmproxy",
        exists=True,
    )
    ct_calls = []

    _patch_ca_manager(
        monkeypatch,
        SimpleNamespace(
            detect_ca_certificates=lambda: [fake_cert],
            inject_ca_into_zygote=lambda cert_path=None: InjectionResult(
                success=False,
                message="No certificate on device. Push certificate first.",
            ),
            bypass_chrome_ct=lambda path: ct_calls.append("called") or (True, "ok"),
        ),
    )

    result = cc.inject_ca_certificate()

    assert result["success"] is False
    assert "No certificate on device" in result["message"]
    assert result["needs_root"] is False
    assert result["chrome_ct_bypass"] is None
    assert ct_calls == []


def test_inject_ca_certificate_custom_source(monkeypatch, tmp_path):
    custom_file = tmp_path / "custom-ca.pem"
    custom_file.write_text("custom pem bytes")
    captured = {}

    monkeypatch.setattr(cc, "resolve_confined_host_path", lambda p: custom_file)

    def fake_inject(cert_path=None):
        captured["cert_path"] = cert_path
        return InjectionResult(
            success=True,
            message="CA injected",
            strategy=InjectionStrategy.LEGACY,
            api_level=28,
        )

    _patch_ca_manager(
        monkeypatch,
        SimpleNamespace(
            inject_ca_into_zygote=fake_inject,
            bypass_chrome_ct=lambda path: (True, "ok"),
        ),
    )

    result = cc.inject_ca_certificate(source="custom", custom_path="custom-ca.pem")

    assert captured["cert_path"] == custom_file
    assert result["success"] is True
    assert result["strategy"] == "legacy"


def test_inject_ca_certificate_source_not_detected_raises(monkeypatch):
    _patch_ca_manager(monkeypatch, SimpleNamespace(detect_ca_certificates=list))

    with pytest.raises(ToolExecutionError, match="list_detected_ca_certificates"):
        cc.inject_ca_certificate(source="http_toolkit")
