"""MVT results modal text: plain words and theme colours, no glyphs."""

from __future__ import annotations

import re

from sandroid.core.forensic_evidence import (
    IOCMatch,
    MatchSeverity,
    ScanResult,
    ScanType,
)
from sandroid.tui.modals.mvt_results_modal import MVTResultsModal

_GLYPHS = re.compile(r"[^\x00-\x7f]|===")


def _texts(results: list[ScanResult]) -> tuple[str, str]:
    modal = MVTResultsModal(results)
    return modal._build_summary(), modal._build_results_content()


def test_a_clean_scan_reads_in_words():
    summary, details = _texts([ScanResult(ScanType.SMS, scanned_items=12)])
    assert "No indicators of compromise found" in summary
    assert "SMS[/bold]: 12 items" in details
    assert "clean" in details
    assert "done" in details
    assert not _GLYPHS.search(summary + details)


def test_matches_and_errors_read_in_words():
    match = IOCMatch(
        "domain",
        "evil.example",
        "https://evil.example/x",
        "SMS",
        severity=MatchSeverity.CRITICAL,
    )
    result = ScanResult(
        ScanType.SMS, matches=[match], scanned_items=3, errors=["timeout"]
    )
    summary, details = _texts([result])
    assert "1 potential IOC matches found" in summary
    assert "Critical: 1" in summary
    assert "Detailed matches" in details
    assert "Scan details" in details
    assert "with errors" in details
    assert "error: timeout" in details
    assert not _GLYPHS.search(summary + details)
