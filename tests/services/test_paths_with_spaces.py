"""Device paths with spaces (phase-3 finding: WebView "Session Storage").

In the Wikipedia run 20261116_191449_a72d6d, 40 pulls of
``app_webview/Default/Session Storage/*``, ``Shared Dictionary/*`` and
``cache/WebView/Default/HTTP Cache/*`` failed with ``adb: error: failed to
access 'Storage/LOCK'`` (the unquoted ``pull`` ran through ``shell=True``),
and the ``ls -ltRAp --full-time`` parser cut ``Default/Web Data`` down to
``Default/Web``, which then showed up as a new file.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

import pytest

from sandroid.services.file_extraction_service import (
    FileExtractionService,
    device_shell_arg,
    pull_command,
)
from sandroid.services.forensic_service import ForensicService

WEBVIEW = "/data/data/org.wikipedia/app_webview/Default"
SESSION_LOCK = f"{WEBVIEW}/Session Storage/LOCK"

posix_only = pytest.mark.skipif(os.name == "nt", reason="uses /bin/sh")


def _host_argv(command: str) -> list[str]:
    """The argv adb receives when ``command`` runs through ``/bin/sh``."""
    out = subprocess.run(
        ["/bin/sh", "-c", f"printf '%s\\0' {command}"],
        capture_output=True,
        check=True,
    ).stdout.decode()
    return out.split("\0")[:-1]


@posix_only
def test_pull_command_keeps_each_path_one_argument(tmp_path):
    local = tmp_path / "new pull" / SESSION_LOCK.lstrip("/")

    argv = _host_argv(pull_command(SESSION_LOCK, local))

    assert argv == ["pull", SESSION_LOCK, str(local)]


@posix_only
def test_device_shell_arg_survives_host_and_device_shell():
    """``adb shell`` joins its argv with spaces for the device shell."""
    path = f"{WEBVIEW}/Web Data"
    host_argv = _host_argv(f"shell test -f {device_shell_arg(path)}")
    assert host_argv[:3] == ["shell", "test", "-f"]

    device_argv = _host_argv(" ".join(host_argv[1:]))

    assert device_argv == ["test", "-f", path]


class _RecordingAdb:
    """Fake adb: parses the command like the host shell and 'pulls'."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def send_adb_command(self, command: str) -> tuple[str, str]:
        argv = shlex.split(command)
        self.calls.append(argv)
        if argv[0] == "pull" and len(argv) == 3:
            Path(argv[2]).write_bytes(b"x")
            return "1 file pulled", ""
        return "", f"adb: error: failed to access '{argv[-2]}'"


def test_pull_file_with_spaces_succeeds(tmp_path):
    adb = _RecordingAdb()
    local = tmp_path / "raw" / "Session Storage" / "LOCK"

    result = FileExtractionService(adb=adb).pull_file(SESSION_LOCK, str(local))

    assert result.success, result.error
    assert adb.calls == [["pull", SESSION_LOCK, str(local)]]
    assert result.source_path == SESSION_LOCK


def test_pull_file_legacy_with_spaces(tmp_path, monkeypatch):
    monkeypatch.setenv("RAW_RESULTS_PATH", str(tmp_path) + "/")
    adb = _RecordingAdb()

    FileExtractionService(adb=adb).pull_file_legacy("new", f"{WEBVIEW}/Web Data")

    target = tmp_path / "new_pull" / WEBVIEW.lstrip("/") / "Web Data"
    assert adb.calls == [["pull", f"{WEBVIEW}/Web Data", str(target)]]
    assert target.read_bytes() == b"x"


# Shaped like the emulator's toybox ``ls -ltRAp --full-time`` output.
LISTING = f"""\
{WEBVIEW}:
total 140
drwx------ 2 u0_a172 u0_a172  4096 2026-11-16 19:15:37.811000000 +0100 Session Storage/
drwx------ 3 u0_a172 u0_a172  4096 2026-11-16 19:15:36.902000000 +0100 Shared Dictionary/
-rw------- 1 u0_a172 u0_a172 98304 2026-11-16 19:15:40.123456789 +0100 Web Data
-rw------- 1 u0_a172 u0_a172     0 2026-11-16 19:15:40.223456789 +0100 Web Data-journal
-rw------- 1 u0_a172 u0_a172    12 2026-11-16 19:15:41.000000000 +0100 two  spaces
lrwxrwxrwx 1 u0_a172 u0_a172    20 2026-11-16 19:15:41.000000000 +0100 link name -> /x y

{WEBVIEW}/Session Storage:
total 16
-rw------- 1 u0_a172 u0_a172     0 2026-11-16 19:15:37.811000000 +0100 LOCK
-rw------- 1 u0_a172 u0_a172   326 2026-11-16 19:15:37.900000000 +0100 000003.log
"""


def test_ls_parser_keeps_names_with_spaces():
    entries = ForensicService()._parse_filesystem_listing(LISTING)

    assert [(d, f) for d, f, _ in entries] == [
        (f"{WEBVIEW}/", "Web Data"),
        (f"{WEBVIEW}/", "Web Data-journal"),
        (f"{WEBVIEW}/", "two  spaces"),
        (f"{WEBVIEW}/Session Storage/", "LOCK"),
        (f"{WEBVIEW}/Session Storage/", "000003.log"),
    ]
    # 2026-11-16 19:15:40.12 +0100 == 18:15:40 UTC (rounded to seconds)
    assert entries[0][2] == 1794852940


def test_changed_files_report_full_names():
    class _ListingAdb:
        @staticmethod
        def send_adb_command(command: str) -> tuple[str, str]:
            return LISTING, ""

    service = ForensicService(adb=_ListingAdb())
    service.set_action_window(1794852930, 60)

    changed = service.fetch_changed_files()

    assert f"{WEBVIEW}/Web Data" in changed
    assert f"{WEBVIEW}/Session Storage/LOCK" in changed
    assert f"{WEBVIEW}/Web" not in changed
