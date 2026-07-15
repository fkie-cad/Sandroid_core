"""Unit tests for the plain (no-job) friTap spawn-resume gating.

When friTap owns the spawn (plain / ``SANDROID_FRITAP_NO_JOB`` path) it resumes
the paused app immediately after loading the agent. Hardened apps like Signal
crash if resumed before the base hooks finish arming, so for SPAWN we set
``DeviceConfig.timeout`` (friTap's pre-resume sleep). These tests cover the
delay-resolution helper and that the delay is wired onto the built config for
spawn but not attach.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import sandroid.analysis.fritap as fritap_mod
from sandroid.analysis.fritap import FriTap, _spawn_resume_delay_seconds


def test_spawn_resume_delay_default(monkeypatch):
    # Default is 0 (immediate resume, like standalone friTap); the Signal spawn
    # crash is fixed in the friTap agent, so no delay is needed by default.
    monkeypatch.delenv("SANDROID_FRITAP_SPAWN_RESUME_DELAY", raising=False)
    assert _spawn_resume_delay_seconds() == 0


@pytest.mark.parametrize(
    ("env_value", "expected"),
    [("0", 0), ("3", 3), ("30", 30), ("-5", 0), ("not-a-number", 0)],
)
def test_spawn_resume_delay_env_override(monkeypatch, env_value, expected):
    monkeypatch.setenv("SANDROID_FRITAP_SPAWN_RESUME_DELAY", env_value)
    assert _spawn_resume_delay_seconds() == expected


def _session_config():
    return SimpleNamespace(
        capture_mode="full",
        library_scan=False,
        encapsulated_protocols=[],
        quic_capture_mode="",
        protocol="signal",
        verbose=False,
        debug_log=False,
    )


def _bare_fritap(monkeypatch, *, mode: str, serial=None) -> FriTap:
    """A FriTap with only the attributes ``_build_ssl_logger_from_session_config``
    touches (bypasses the heavy DataGatherBase __init__)."""
    inst = object.__new__(FriTap)
    inst.mode = mode
    inst.keylog_path = "/tmp/keys.log"
    inst.pcap_path = "/tmp/capture.pcapng"
    inst.json_output_path = "/tmp/out.json"
    monkeypatch.setattr(type(inst), "_active_device_serial", staticmethod(lambda: serial))
    return inst


def test_spawn_sets_device_timeout(monkeypatch):
    monkeypatch.setenv("SANDROID_FRITAP_SPAWN_RESUME_DELAY", "8")
    inst = _bare_fritap(monkeypatch, mode="spawn", serial="31041FDH2006EY")

    ssl_log = inst._build_ssl_logger_from_session_config(
        "org.thoughtcrime.securesms", _session_config(), verbose=False, debug_output=False
    )

    assert ssl_log.timeout == 8


def test_spawn_delay_disabled_leaves_timeout_unset(monkeypatch):
    monkeypatch.setenv("SANDROID_FRITAP_SPAWN_RESUME_DELAY", "0")
    inst = _bare_fritap(monkeypatch, mode="spawn", serial=None)

    ssl_log = inst._build_ssl_logger_from_session_config(
        "org.thoughtcrime.securesms", _session_config(), verbose=False, debug_output=False
    )

    assert ssl_log.timeout is None


def test_attach_does_not_set_timeout(monkeypatch):
    monkeypatch.setenv("SANDROID_FRITAP_SPAWN_RESUME_DELAY", "8")
    inst = _bare_fritap(monkeypatch, mode="attach", serial="31041FDH2006EY")

    ssl_log = inst._build_ssl_logger_from_session_config(
        12345, _session_config(), verbose=False, debug_output=False
    )

    assert ssl_log.timeout is None
