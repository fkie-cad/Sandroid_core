"""Network target labels: shared-IP DNS names, TLS SNI and IPv6 flows.

``wikipedia_run_1_excerpt.pcap`` is cut from the tester's real Wikipedia
capture (run 20261116_173858_df1034): the DNS answers, all SYNs, the TLS
ClientHellos and a few server packets. en.wikipedia.org, meta/thumb and
intake-analytics.wikimedia.org all resolve to the Wikimedia load balancer
185.15.59.224; OkHttp coalesces them onto a connection whose SNI is
intake-analytics, so the old "first DNS answer wins" label attributed 4 MB
of article traffic to the analytics host.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "fixtures"
    / "p2_live"
    / "wikipedia_run_1_excerpt.pcap"
)


def _network(tmp_path, monkeypatch) -> tuple[Any, Path]:
    from sandroid.analysis.network import Network

    monkeypatch.setenv("RAW_RESULTS_PATH", str(tmp_path) + "/")
    folder = tmp_path / "network_trace_pull"
    folder.mkdir()
    return Network(), folder


def test_shared_ip_lists_every_dns_name_and_the_sni(tmp_path, monkeypatch):
    network, folder = _network(tmp_path, monkeypatch)
    shutil.copy(FIXTURE, folder / "network_trace_run_1.pcap")

    targets = network.return_data()["Network IP:Port (send/recv)"]

    by_ip = {t.split(" ", 1)[0]: t for t in targets}
    lb = by_ip["185.15.59.224:443"]
    assert lb.startswith(
        "185.15.59.224:443 [en.wikipedia.org, intake-analytics.wikimedia.org, "
        "meta.wikimedia.org, thumb.wikimedia.org] "
        "(TLS SNI: intake-analytics.wikimedia.org) ("
    )
    # Single host behind the IP and SNI agrees -> no redundant SNI note.
    assert by_ip["185.15.59.240:443"] == (
        "185.15.59.240:443 [upload.wikimedia.org] (517B sent to / 0B received from)"
    )


def test_unanswered_ipv6_syn_is_marked_as_attempt(tmp_path, monkeypatch):
    """The emulator has no IPv6 route: the SYN gets ICMPv6 unreachable."""
    network, folder = _network(tmp_path, monkeypatch)
    shutil.copy(FIXTURE, folder / "network_trace_run_1.pcap")

    targets = network.return_data()["Network IP:Port (send/recv)"]

    v6 = [t for t in targets if t.startswith("[2a02:ec80:300:ed1a::1]:443")]
    assert v6 == [
        "[2a02:ec80:300:ed1a::1]:443 [en.wikipedia.org, "
        "intake-analytics.wikimedia.org, meta.wikimedia.org, thumb.wikimedia.org] "
        "(0B sent to / 0B received from; no reply, connection attempt only)"
    ]


def test_ipv6_flow_bytes_are_counted(tmp_path, monkeypatch):
    from scapy.all import TCP, Ether, IPv6, Raw, wrpcap

    network, folder = _network(tmp_path, monkeypatch)
    dev, server = "fec0::ecd0:4699:85fe:5daa", "2a02:ec80:300:ed1a::1"
    wrpcap(
        str(folder / "network_trace_run_1.pcap"),
        [
            Ether() / IPv6(src=dev, dst=server) / TCP(sport=46622, dport=443, flags="S"),
            Ether()
            / IPv6(src=server, dst=dev)
            / TCP(sport=443, dport=46622, flags="SA"),
            Ether()
            / IPv6(src=dev, dst=server)
            / TCP(sport=46622, dport=443, flags="PA")
            / Raw(b"a" * 100),
            Ether()
            / IPv6(src=server, dst=dev)
            / TCP(sport=443, dport=46622, flags="PA")
            / Raw(b"b" * 2500),
        ],
    )

    targets = network.return_data()["Network IP:Port (send/recv)"]

    assert targets == [
        "[2a02:ec80:300:ed1a::1]:443 (100B sent to / 2500B received from)"
    ]


def test_analyze_pcap_reports_names_and_sni():
    from sandroid.analysis.network import Network

    analysis = Network().analyze_pcap(str(FIXTURE))

    entry = next(e for e in analysis["ip_analysis"] if e["ip"] == "185.15.59.224")
    assert entry["dns_names"] == [
        "en.wikipedia.org",
        "intake-analytics.wikimedia.org",
        "meta.wikimedia.org",
        "thumb.wikimedia.org",
    ]
    assert entry["tls_sni"] == ["intake-analytics.wikimedia.org"]


def test_tls_sni_parser_rejects_garbage():
    from sandroid.analysis.network import Network

    assert Network._tls_sni(b"") is None
    assert Network._tls_sni(b"\x16\x03\x01" + b"\x00" * 10) is None
    assert Network._tls_sni(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n" * 3) is None
