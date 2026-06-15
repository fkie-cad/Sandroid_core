"""Unit tests for the forensic scan-strategy fixes.

Covers the two warning/error sources seen during a real scan:
- FILES: split APKs (``pm path`` returns several ``package:`` lines) must be
  hashed individually — never collapsed into one malformed, newline-bearing
  command (which made the device shell try to *execute* the trailing paths).
- CALLS/SMS: the ``content query --projection`` arg is dropped (it was rejected
  as one invalid column); matching is substring-based on the whole row.
"""

from __future__ import annotations

import sandroid.core.adb as adb_mod
from sandroid.core.forensic_scanners.calls_strategy import CallsScanStrategy
from sandroid.core.forensic_scanners.files_strategy import FilesScanStrategy
from sandroid.core.forensic_scanners.sms_strategy import SMSScanStrategy


class _FilesLoader:
    hashes = [{"value": "ABC123", "type": "MD5", "description": "bad apk"}]


class _CallLoader:
    phone_numbers = [{"value": "+15550001111", "description": "bad caller"}]


class _SmsLoader:
    phone_numbers: list = []
    urls = [{"value": "http://evil.example/x", "description": "phish"}]
    domains: list = []


def _patch_adb(monkeypatch, fake_send):
    monkeypatch.setattr(adb_mod.Adb, "send_adb_command", staticmethod(fake_send))


def test_split_apk_hashes_each_file_separately(monkeypatch):
    commands: list[str] = []

    def fake_send(command):
        commands.append(command)
        if command.startswith("shell pm path"):
            return (
                "package:/data/app/A/base.apk\n"
                "package:/data/app/A/split_config.arm64_v8a.apk\n",
                "",
            )
        if command.startswith("shell md5sum") and "base.apk" in command:
            return ("abc123  /data/app/A/base.apk\n", "")
        if command.startswith("shell md5sum"):
            return ("999000  /data/app/A/split_config.arm64_v8a.apk\n", "")
        return ("", "")

    _patch_adb(monkeypatch, fake_send)

    matches = FilesScanStrategy()._scan_package("com.x", _FilesLoader(), sha256_iocs=[])

    # Each APK hashed with its own single-path command; no command spans lines.
    md5_cmds = [c for c in commands if c.startswith("shell md5sum")]
    assert len(md5_cmds) == 2
    assert all("\n" not in c for c in commands)
    assert "base.apk" in md5_cmds[0]
    assert "split_config.arm64_v8a.apk" in md5_cmds[1]
    # base.apk's md5 (abc123) matches IOC ABC123 -> exactly one match.
    assert len(matches) == 1
    assert matches[0].matched_data == "com.x (/data/app/A/base.apk)"


def test_calls_query_has_no_projection_and_matches(monkeypatch):
    commands: list[str] = []

    def fake_send(command):
        commands.append(command)
        return ("Row: 0 _id=1, number=+15550001111, date=123, type=2\n", "")

    _patch_adb(monkeypatch, fake_send)

    result = CallsScanStrategy().scan(_CallLoader(), progress_callback=None)

    query = next(c for c in commands if "content query" in c)
    assert "--projection" not in query
    assert "call_log/calls" in query
    assert len(result.matches) == 1
    assert result.matches[0].indicator_value == "+15550001111"


def test_sms_query_has_no_projection_and_matches(monkeypatch):
    commands: list[str] = []

    def fake_send(command):
        commands.append(command)
        return ("Row: 0 address=000, body=click http://evil.example/x now\n", "")

    _patch_adb(monkeypatch, fake_send)

    result = SMSScanStrategy().scan(_SmsLoader(), progress_callback=None)

    query = next(c for c in commands if "content query" in c)
    assert "--projection" not in query
    assert "sms/inbox" in query
    assert len(result.matches) == 1
    assert result.matches[0].indicator_type == "url"
