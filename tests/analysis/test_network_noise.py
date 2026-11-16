"""Dry-run (background) comparison of the network results (phase-3 N1).

The fixtures are header-only cuts of the tester's real Wikipedia run
20261116_191449_a72d6d (Pixel_9_2): DNS packets and TLS ClientHellos are
whole, every other packet keeps only its headers while the pcap record keeps
the on-wire length, so the IP length fields still give the true volumes
(checked against ``tshark``: 3 998 771 B received / 11 508 B sent for
185.15.59.224:443).

In that run the dry run made one analytics POST to the Wikimedia load
balancer 185.15.59.224:443 (about 15 KB). The old set difference per
IP:port therefore removed the 4 MB of article + analytics traffic of the
action run, and intake-analytics.wikimedia.org vanished from the DNS list.
"""

from __future__ import annotations

import gzip
import shutil
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "p3_live"
LB = "185.15.59.224:443"
LB_NAMES = (
    "[en.wikipedia.org, intake-analytics.wikimedia.org, meta.wikimedia.org, "
    "thumb.wikimedia.org]"
)


def _gunzip(name: str, target: Path) -> None:
    with gzip.open(FIXTURES / name, "rb") as src, target.open("wb") as dst:
        shutil.copyfileobj(src, dst)


def _network(tmp_path, monkeypatch, *, noise: bool = True) -> Any:
    from sandroid.analysis.network import Network

    monkeypatch.setenv("RAW_RESULTS_PATH", str(tmp_path) + "/")
    monkeypatch.setattr(Network, "performed_diff", False)
    folder = tmp_path / "network_trace_pull"
    folder.mkdir()
    _gunzip("wikipedia_run_1_headers.pcap.gz", folder / "network_trace_run_1.pcap")
    if noise:
        _gunzip(
            "wikipedia_noise_headers.pcap.gz",
            folder / "network_trace_run_noise.pcap",
        )
    return Network()


def _by_endpoint(targets: list[str]) -> dict[str, str]:
    return {t.split(" ", 1)[0]: t for t in targets}


def test_busy_destination_seen_in_dry_run_is_still_reported(tmp_path, monkeypatch):
    network = _network(tmp_path, monkeypatch)

    targets = _by_endpoint(network.return_data()["Network IP:Port (send/recv)"])

    assert targets[LB] == (
        f"{LB} {LB_NAMES} "
        "(TLS SNI: en.wikipedia.org, intake-analytics.wikimedia.org) "
        "(11508B sent to / 3998771B received from; "
        "also seen in background: 15142B in 55 packets / 2 connections)"
    )
    assert targets["185.15.59.240:443"] == (
        "185.15.59.240:443 [upload.wikimedia.org] (1322B sent to / 2473B received from)"
    )


def test_analytics_name_seen_in_dry_run_stays_in_dns_list(tmp_path, monkeypatch):
    network = _network(tmp_path, monkeypatch)

    assert network.return_data()["Network"] == [
        "en.wikipedia.org.",
        "intake-analytics.wikimedia.org. (also seen in background: 4 queries)",
        "meta.wikimedia.org.",
        "thumb.wikimedia.org.",
        "upload.wikimedia.org.",
    ]


def test_background_level_destination_is_listed_as_filtered_noise(
    tmp_path, monkeypatch
):
    """The unanswered IPv6 SYNs happen in both captures -> noise, not dropped."""
    network = _network(tmp_path, monkeypatch)

    targets = _by_endpoint(network.return_data()["Network IP:Port (send/recv)"])

    assert "[2a02:ec80:300:ed1a::1]:443" not in targets
    assert network.filtered_network_noise == {
        "Network": {},
        "Network IP:Port (send/recv)": {
            f"[2a02:ec80:300:ed1a::1]:443 {LB_NAMES}": (
                "comparable to background: dry run 0B in 2 packets / "
                "2 connections, busiest action run 0B in 2 packets / "
                "2 connections"
            )
        },
    }
    assert "1 DNS name(s) / target(s) comparable" in network.pretty_print()


def test_without_dry_run_nothing_is_filtered(tmp_path, monkeypatch):
    network = _network(tmp_path, monkeypatch, noise=False)

    data = network.return_data()

    assert "intake-analytics.wikimedia.org." in data["Network"]
    targets = _by_endpoint(data["Network IP:Port (send/recv)"])
    assert "[2a02:ec80:300:ed1a::1]:443" in targets
    assert "also seen in background" not in targets[LB]
    assert network.filtered_network_noise == {
        "Network": {},
        "Network IP:Port (send/recv)": {},
    }


def test_dns_name_only_queried_like_background_is_filtered(tmp_path, monkeypatch):
    from scapy.all import DNS, DNSQR, IP, UDP, Ether, wrpcap

    from sandroid.analysis.network import Network

    monkeypatch.setenv("RAW_RESULTS_PATH", str(tmp_path) + "/")
    monkeypatch.setattr(Network, "performed_diff", False)
    folder = tmp_path / "network_trace_pull"
    folder.mkdir()

    def query(name: str) -> Any:
        return (
            Ether()
            / IP(src="10.0.2.16", dst="10.0.2.3")
            / UDP(sport=40000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=name))
        )

    wrpcap(
        str(folder / "network_trace_run_noise.pcap"),
        [query("crashlyticsreports-pa.googleapis.com"), query("chatty.example")],
    )
    wrpcap(
        str(folder / "network_trace_run_1.pcap"),
        [query("crashlyticsreports-pa.googleapis.com")]
        + [query("chatty.example")] * 6
        + [query("app.example")],
    )

    network = Network()
    assert network.return_data()["Network"] == [
        "app.example.",
        "chatty.example. (also seen in background: 1 queries)",
    ]
    assert list(network.filtered_network_noise["Network"]) == [
        "crashlyticsreports-pa.googleapis.com."
    ]


@pytest.mark.parametrize(
    ("action", "noise", "expected"),
    [
        # 4 MB vs 15 KB -> reported (the N1 case).
        ((4_010_279, 3700, 2), (15_142, 55, 2), True),
        # Crashlytics upload of the same size in both runs -> noise.
        ((7236, 24, 1), (7357, 24, 1), False),
        # A second TLS session to a background host stays below the floors.
        ((12_000, 40, 2), (6000, 20, 1), False),
        # Many new connections with little payload -> reported.
        ((3000, 30, 9), (1000, 10, 1), True),
    ],
)
def test_above_background_thresholds(action, noise, expected):
    from sandroid.analysis.network import _above_background, _Volume

    def volume(total: int, packets: int, connections: int) -> _Volume:
        return _Volume(sent=total, packets=packets, local_ports=set(range(connections)))

    assert _above_background(volume(*action), volume(*noise)) is expected


def test_engine_reports_network_noise_under_filtered_noise():
    from sandroid.analysis.engine import AnalysisEngine

    class _Net:
        filtered_network_noise = {
            "Network": {"x.example.": "comparable to background"},
            "Network IP:Port (send/recv)": {},
        }

    engine = AnalysisEngine.__new__(AnalysisEngine)
    engine.gatherers = {"network": _Net()}

    report = engine._filtered_noise_report()

    assert report["Network"] == {"x.example.": "comparable to background"}
    assert report["Network IP:Port (send/recv)"] == {}
    assert "network_note" in report
