"""Regression tests for ``Adb.push_file`` / ``Adb.pull_file`` quoting.

The ADB command pipeline executes its command string through a shell
(``shell=True``). Paths containing spaces — e.g. a directory under
``.../2024 fritap issues/...`` — would be word-split by the shell unless
quoted, causing ``adb`` to receive the wrong arguments.

These tests assert that the centralized push/pull helpers shell-quote both
the local and remote path, and that ``Path`` objects are accepted.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from sandroid.core.adb import Adb


def _capture(monkeypatch) -> list[str]:
    captured: list[str] = []

    def fake_send(cls, command: str) -> tuple[str, str]:
        captured.append(command)
        return ("", "")

    monkeypatch.setattr(Adb, "send_adb_command", classmethod(fake_send))
    return captured


def test_pull_file_quotes_spaced_paths(monkeypatch):
    captured = _capture(monkeypatch)
    remote = "/sdcard/capture.pcap"
    local = "/Users/d/2024 fritap issues/out.pcap"

    Adb.pull_file(remote, local)

    assert captured == [f"pull {shlex.quote(remote)} {shlex.quote(local)}"]
    # Both paths survive as single tokens after the leading "pull" verb.
    tokens = shlex.split(captured[0])
    assert tokens == ["pull", remote, local]


def test_push_file_quotes_spaced_paths(monkeypatch):
    captured = _capture(monkeypatch)
    local = "/local/2024 fritap issues/a.cert"
    remote = "/data/local/tmp/cert.0"

    Adb.push_file(local, remote)

    assert captured == [f"push {shlex.quote(local)} {shlex.quote(remote)}"]
    assert shlex.split(captured[0]) == ["push", local, remote]


def test_helpers_accept_path_objects(monkeypatch):
    captured = _capture(monkeypatch)
    local = Path("/Users/d/2024 fritap issues/y.apk")

    Adb.pull_file("/sdcard/y.apk", local)

    assert str(local) in shlex.split(captured[0])
