"""friTap 2.6.x integration: API surface, output finalisation, message formatting."""

from __future__ import annotations

import json
import types

import pytest

from sandroid.analysis import fritap as fritap_mod
from sandroid.analysis.fritap_formatter import FriTapMessageFormatter


def test_fritap_legacy_api_used_by_sandroid_exists():
    """The SSL_Logger surface Sandroid drives through AFM's JobManager."""
    from friTap import SSL_Logger

    for name in (
        "on_fritap_message",
        "get_agent_script_path",
        "close_output_handlers",
        "_finalize_json_output",
    ):
        assert callable(getattr(SSL_Logger, name, None)), name


def test_json_output_is_assembled_on_finalize(tmp_path):
    """FriTap >= 2.6 only assembles the JSON document when handlers close.

    Regression for the live run where fritap_output.json kept its empty
    start-time skeleton and all events stayed in the .events.jsonl sidecar.
    """
    from friTap import SSL_Logger

    json_path = tmp_path / "fritap_output.json"
    keylog_path = tmp_path / "fritap_keylog.log"
    ssl_log = SSL_Logger(1234, keylog=str(keylog_path), json_output=str(json_path))
    line = "CLIENT_RANDOM " + "ab" * 32 + " " + "cd" * 48
    ssl_log.on_fritap_message(
        None,
        {"type": "send", "payload": {"contentType": "keylog", "keylog": line}},
        None,
    )

    ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
    ft.ssl_log = ssl_log
    ft._finalize_outputs()
    ft._finalize_outputs()  # idempotent (headless calls stop() twice)

    assert line in keylog_path.read_text()
    doc = json.loads(json_path.read_text())
    assert doc["key_extractions"], doc
    assert not (tmp_path / "fritap_output.json.events.jsonl").exists()


def test_stop_finalizes_after_detaching():
    calls = []
    ft = fritap_mod.FriTap.__new__(fritap_mod.FriTap)
    ft.show_in_activity_log = False
    ft.job_id = None
    ft.app_package = "com.example"
    ft.job_manager = types.SimpleNamespace(
        stop_jobs=lambda timeout_per_job: calls.append("stop_jobs") or {},
        detach_from_app=lambda timeout: calls.append("detach"),
    )
    ft.ssl_log = types.SimpleNamespace(
        close_output_handlers=lambda: calls.append("close_handlers"),
        _finalize_json_output=lambda: calls.append("finalize_json"),
    )
    ft.stop()
    assert calls == ["stop_jobs", "detach", "close_handlers", "finalize_json"]


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            {"src_addr": 167772687, "dst_addr": 2398776971, "ss_family": "AF_INET"},
            "10.0.2.15:47204 → 142.250.110.139:443",
        ),
        (
            {"src_addr": "10.0.2.15", "dst_addr": "1.2.3.4", "ss_family": "AF_INET"},
            "10.0.2.15:47204 → 1.2.3.4:443",
        ),
        (
            {"src_addr": "2001:db8::1", "dst_addr": "2001:db8::2", "ss_family": "AF_INET6"},
            "2001:db8::1:47204 → 2001:db8::2:443",
        ),
    ],
)
def test_datalog_addresses_are_human_readable(payload, expected):
    message = {
        "type": "send",
        "payload": {
            "contentType": "datalog",
            "function": "SSL_write",
            "src_port": 47204,
            "dst_port": 443,
            **payload,
        },
    }
    out = FriTapMessageFormatter.format_message(message, b"x" * 70)
    assert out == f"[SSL_write] {expected} (70 bytes)"


def test_console_detection():
    console = {"type": "send", "payload": {"contentType": "console", "console": "x"}}
    keylog = {"type": "send", "payload": {"contentType": "keylog", "keylog": "x"}}
    assert fritap_mod._is_console_message(console)
    assert not fritap_mod._is_console_message(keylog)
    assert not fritap_mod._is_console_message({"type": "error"})
