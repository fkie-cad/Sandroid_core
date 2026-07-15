"""Unit tests for friTap full-capture finalization + result collection.

These cover the stop-time logic added so a full capture's pcap + keylogs are
pulled/finalized and surfaced to the TUI (Capture Results + decrypt offer).
They use bare instances (``FriTap.__new__``) + fakes, so no device is needed.
"""

from __future__ import annotations

import struct
from types import SimpleNamespace

from sandroid.analysis.fritap import (
    FriTap,
    _count_keys,
    _file_size_str,
    _pcap_has_packets,
)


# --- module-level helpers -------------------------------------------------


def test_count_keys_ignores_blank_and_comment_lines(tmp_path):
    f = tmp_path / "keys.log"
    f.write_text(
        "# comment\n"
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET aaa bbb\n"
        "\n"
        "SERVER_HANDSHAKE_TRAFFIC_SECRET ccc ddd\n"
    )
    assert _count_keys(str(f)) == 2


def test_count_keys_missing_file_returns_none(tmp_path):
    assert _count_keys(str(tmp_path / "nope.log")) is None


def test_file_size_str_human_readable(tmp_path):
    f = tmp_path / "cap.pcapng"
    f.write_bytes(b"\x00" * 164250)
    size = _file_size_str(str(f))
    assert size is not None and size.endswith("KB")


def test_pcap_has_packets_classic_with_record(tmp_path):
    f = tmp_path / "c.pcap"
    # 24-byte classic global header (LE microsecond magic) + one 16-byte record.
    f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20 + b"\x11" * 16)
    assert _pcap_has_packets(str(f)) is True


def test_pcap_has_packets_classic_header_only_is_empty(tmp_path):
    f = tmp_path / "empty.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)  # header, no records
    assert _pcap_has_packets(str(f)) is False


def test_pcap_has_packets_pcapng_section_header_only_is_empty(tmp_path):
    f = tmp_path / "empty.pcapng"
    # Section Header Block only (type 0x0A0D0D0A), no packet blocks.
    body = b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + b"\x4d\x3c\x2b\x1a"
    body += b"\x00" * (28 - len(body) - 4) + struct.pack("<I", 28)
    f.write_bytes(body)
    assert _pcap_has_packets(str(f)) is False


# --- _finalize_full_capture ----------------------------------------------


class _FakeSSLLog:
    def __init__(self, full_capture=True):
        self.full_capture = full_capture
        self.mobile = True
        self.pcap_name = "capture.pcapng"
        self.live = False
        self.socket_trace = False
        self.debug_output = False
        self.calls = []

    def pcap_cleanup(self, full, mobile, name):
        self.calls.append(("pcap_cleanup", full, mobile, name))

    def cleanup(self, live, socket_trace, full, debug):
        self.calls.append(("cleanup", live, socket_trace, full, debug))


def _bare_fritap() -> FriTap:
    inst = FriTap.__new__(FriTap)
    inst.full_capture_done = False
    inst.pcap_has_packets = False
    inst.result_paths = {}
    inst.result_stats = {}
    inst.result_keylogs = {}
    inst.protocol = "tls"
    inst.keylog_path = None
    inst.pcap_path = None
    inst.log_path = None
    inst.json_output_path = None
    inst.app_package = "com.example.app"
    return inst


def test_finalize_full_capture_pulls_and_cleans():
    inst = _bare_fritap()
    inst.ssl_log = _FakeSSLLog(full_capture=True)
    inst._finalize_full_capture()
    names = [c[0] for c in inst.ssl_log.calls]
    assert names == ["pcap_cleanup", "cleanup"]
    assert inst.full_capture_done is True


def test_finalize_keys_only_skips_device_pull_but_closes_handlers():
    inst = _bare_fritap()
    inst.ssl_log = _FakeSSLLog(full_capture=False)
    inst._finalize_full_capture()
    names = [c[0] for c in inst.ssl_log.calls]
    assert names == ["cleanup"]  # no device pull when not a full capture
    assert inst.full_capture_done is False


def test_finalize_is_resilient_to_pull_errors():
    inst = _bare_fritap()
    log = _FakeSSLLog(full_capture=True)

    def _boom(*a):
        raise RuntimeError("adb pull failed")

    log.pcap_cleanup = _boom
    inst.ssl_log = log
    # Must not raise — a finalize hiccup cannot strand the TaskService stop.
    inst._finalize_full_capture()
    assert any(c[0] == "cleanup" for c in log.calls)


# --- _collect_capture_results --------------------------------------------


class _FakeToolbox:
    def __init__(self):
        self.marked = None

    def mark_tool_used(self, name, files=None):
        self.marked = (name, files)


def test_collect_capture_results_split_keylogs_register_new_files(tmp_path, monkeypatch):
    # A Signal full capture splits the base -k path into per-protocol logs.
    keys_tls = tmp_path / "keys.tls.log"
    keys_tls.write_text("CLIENT_TRAFFIC_SECRET_0 aaa bbb\n")
    keys_signal = tmp_path / "keys.signal.log"
    keys_signal.write_text("SIGNAL one_to_one key=deadbeef\n")
    pcap = tmp_path / "capture.pcapng"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20 + b"\x22" * 16)  # has a record

    import friTap.output.factory as factory_mod

    monkeypatch.setattr(
        factory_mod,
        "active_keylog_paths",
        lambda base, proto, reg, **k: {"tls": str(keys_tls), "signal": str(keys_signal)},
    )

    inst = _bare_fritap()
    inst.keylog_path = str(tmp_path / "keys.log")  # base, never written verbatim
    inst.pcap_path = str(pcap)
    inst.log_path = str(tmp_path / "fritap.log")
    inst.json_output_path = str(tmp_path / "fritap_output.json")
    inst.protocol = "signal"
    inst.ssl_log = SimpleNamespace(_protocol_registry=None)

    fake_tb = _FakeToolbox()
    inst._get_toolbox = lambda: fake_tb

    inst._collect_capture_results()

    # Both split keylogs surfaced with per-protocol labels, plus the pcap.
    assert inst.result_paths["Key log (tls)"] == str(keys_tls)
    assert inst.result_paths["Key log (signal)"] == str(keys_signal)
    assert inst.result_paths["PCAP"] == str(pcap)
    assert inst.result_keylogs == {"tls": str(keys_tls), "signal": str(keys_signal)}
    assert inst.pcap_has_packets is True
    assert "PCAP" in inst.result_stats  # human-readable size present

    # Only the NEW split keylogs are registered (base log/json/pcap were already
    # registered at start; re-adding them would duplicate the summary entries).
    assert fake_tb.marked is not None
    name, files = fake_tb.marked
    assert name == "fritap"
    assert set(files) == {str(keys_tls), str(keys_signal)}
    assert str(pcap) not in files  # already registered at start


def test_collect_capture_results_single_keylog_no_duplicate_registration(
    tmp_path, monkeypatch
):
    # A plain TLS capture writes the base -k path directly: nothing new to
    # register at stop (it was registered at start), so mark_tool_used is NOT
    # called again — avoiding duplicate summary entries.
    keylog = tmp_path / "keys.log"
    keylog.write_text("CLIENT_TRAFFIC_SECRET_0 aaa bbb\n")
    pcap = tmp_path / "capture.pcapng"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20 + b"\x22" * 16)

    import friTap.output.factory as factory_mod

    monkeypatch.setattr(
        factory_mod,
        "active_keylog_paths",
        lambda base, proto, reg, **k: {"tls": str(keylog)},
    )

    inst = _bare_fritap()
    inst.keylog_path = str(keylog)
    inst.pcap_path = str(pcap)
    inst.log_path = str(tmp_path / "fritap.log")
    inst.protocol = "tls"
    inst.ssl_log = SimpleNamespace(_protocol_registry=None)

    fake_tb = _FakeToolbox()
    inst._get_toolbox = lambda: fake_tb

    inst._collect_capture_results()

    assert inst.result_paths["Key log"] == str(keylog)
    assert inst.result_paths["PCAP"] == str(pcap)
    # No new files → no re-registration (start-time registration already covers them).
    assert fake_tb.marked is None


def test_collect_capture_results_no_files_is_safe(tmp_path):
    inst = _bare_fritap()
    inst.keylog_path = str(tmp_path / "missing.log")
    inst.pcap_path = str(tmp_path / "missing.pcapng")
    inst.log_path = str(tmp_path / "fritap.log")

    class _SSL:
        _protocol_registry = None

    inst.ssl_log = _SSL()
    inst._get_toolbox = lambda: _FakeToolbox()

    inst._collect_capture_results()
    assert inst.result_paths == {}
    assert inst.result_keylogs == {}
