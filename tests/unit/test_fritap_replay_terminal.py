"""Unit tests for the friTap tab's 'replay capture' terminal launcher.

These verify the cross-platform command construction without spawning a real
terminal (subprocess.Popen is monkeypatched) and need no device.
"""

from __future__ import annotations

from pathlib import Path

import sandroid.tui.widgets.fritap_panel as fp_mod
from sandroid.tui.widgets.fritap_panel import FriTapPanel


def _panel() -> FriTapPanel:
    # The terminal helpers don't touch self.app, so a bare instance is enough.
    return FriTapPanel()


def test_open_terminal_macos_uses_osascript(monkeypatch):
    calls = []
    monkeypatch.setattr(fp_mod.subprocess, "Popen", lambda argv, **kw: calls.append(argv))
    monkeypatch.setattr(fp_mod.sys, "platform", "darwin")

    _panel()._open_terminal_with_command(["/venv/bin/fritap", "-r", "/caps/a b.pcap"])

    assert len(calls) == 1
    argv = calls[0]
    assert argv[0] == "osascript"
    assert argv[1] == "-e"
    script = argv[2]
    assert "do script" in script
    assert "fritap" in script
    assert "-r" in script
    # A path with a space must be shell-quoted inside the AppleScript command.
    assert "'/caps/a b.pcap'" in script


def test_open_terminal_linux_prefers_available_emulator(monkeypatch):
    calls = []
    monkeypatch.setattr(fp_mod.subprocess, "Popen", lambda argv, **kw: calls.append(argv))
    monkeypatch.setattr(fp_mod.sys, "platform", "linux")
    # Only gnome-terminal is "installed".
    monkeypatch.setattr(
        fp_mod.shutil,
        "which",
        lambda name: "/usr/bin/gnome-terminal" if name == "gnome-terminal" else None,
    )

    _panel()._open_terminal_with_command(["/venv/bin/fritap", "-r", "/caps/x.pcap"])

    assert len(calls) == 1
    argv = calls[0]
    assert argv[0] == "/usr/bin/gnome-terminal"
    assert argv[1] == "--"  # gnome-terminal command separator
    assert "exec bash" in argv[-1]  # window stays open after replay exits


def test_resolve_fritap_prefers_which(monkeypatch):
    monkeypatch.setattr(fp_mod.shutil, "which", lambda name: "/venv/bin/fritap")
    assert FriTapPanel._resolve_fritap() == ["/venv/bin/fritap"]


def test_resolve_fritap_falls_back_to_module(monkeypatch, tmp_path):
    monkeypatch.setattr(fp_mod.shutil, "which", lambda name: None)
    # Point sys.executable at a dir with no sibling 'fritap'.
    fake_python = tmp_path / "python"
    fake_python.write_text("")
    monkeypatch.setattr(fp_mod.sys, "executable", str(fake_python))
    assert FriTapPanel._resolve_fritap() == [str(fake_python), "-m", "friTap"]


def test_launch_replay_missing_file_does_not_open_terminal(monkeypatch):
    opened = []
    panel = _panel()
    monkeypatch.setattr(panel, "_open_terminal_with_command", opened.append)

    class _App:
        def notify(self, *a, **k):
            pass

    def _get_app(_self):
        return _App()

    monkeypatch.setattr(type(panel), "app", property(_get_app))
    panel._launch_fritap_replay(Path("/definitely/missing/capture.pcap"))
    assert opened == []
