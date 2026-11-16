"""mitmweb is found next to the interpreter when the venv is not on PATH."""

from __future__ import annotations

import sys

from sandroid.services import mitmproxy_service


def test_prefers_path(monkeypatch):
    monkeypatch.setattr(mitmproxy_service.shutil, "which", lambda name: "/usr/x/mitmweb")
    assert mitmproxy_service._find_mitmweb() == "/usr/x/mitmweb"


def test_falls_back_to_interpreter_bin(monkeypatch, tmp_path):
    exe = tmp_path / "python"
    exe.write_text("")
    (tmp_path / "mitmweb").write_text("")
    monkeypatch.setattr(mitmproxy_service.shutil, "which", lambda name: None)
    monkeypatch.setattr(sys, "executable", str(exe))
    assert mitmproxy_service._find_mitmweb() == str(tmp_path / "mitmweb")


def test_not_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(mitmproxy_service.shutil, "which", lambda name: None)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python"))
    assert mitmproxy_service._find_mitmweb() is None
