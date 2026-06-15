"""Regression tests for APK install command quoting.

The ADB command pipeline ultimately executes its command string through a
shell (``shell=True``). An APK path containing spaces — e.g. a results
directory under ``.../2024 fritap issues/...`` — was being word-split by the
shell, so ``adb`` received the wrong positional argument and reported
``failed to stat ...: No such file or directory``.

These tests assert that ``install_apk`` shell-quotes the path it hands to the
command callable, so paths with spaces survive intact.
"""

from __future__ import annotations

import shlex

from sandroid.core import adb_packages


def _capturing_send_command(captured: list[str]):
    def send_command(command: str) -> tuple[str, str]:
        captured.append(command)
        return ("Success", "")

    return send_command


def test_install_command_quotes_path_with_spaces(monkeypatch):
    # aapt extraction is irrelevant to this test; short-circuit it.
    monkeypatch.setattr(adb_packages, "find_aapt_paths", lambda: [])

    captured: list[str] = []
    path = "/Users/danielbaier/research/2024 fritap issues/results/de.fkie.ground_truth.apk"

    adb_packages.install_apk(_capturing_send_command(captured), path)

    assert len(captured) == 1
    command = captured[0]
    # The full path must appear as a single shell token.
    assert path in shlex.split(command)
    # And the raw, unquoted path must NOT be present (it would word-split).
    assert command == f"install -r {shlex.quote(path)}"


def test_install_command_path_without_spaces_unchanged(monkeypatch):
    monkeypatch.setattr(adb_packages, "find_aapt_paths", lambda: [])

    captured: list[str] = []
    path = "/tmp/app.apk"

    adb_packages.install_apk(_capturing_send_command(captured), path)

    # shlex.quote leaves a metacharacter-free path untouched.
    assert captured == ["install -r /tmp/app.apk"]
    assert path in shlex.split(captured[0])
