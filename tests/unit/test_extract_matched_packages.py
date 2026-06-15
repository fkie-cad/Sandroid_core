"""Unit tests for forensic_evidence.extract_matched_packages.

Covers package extraction for APK pulling — including packages detected ONLY
via an APK hash match (parsed from ``matched_data``), and exclusion of
non-APK matches (SMS/CALLS).
"""

from __future__ import annotations

from sandroid.core.forensic_evidence import (
    IOCMatch,
    MatchSeverity,
    ScanResult,
    ScanType,
    extract_matched_packages,
)


def _result(scan_type: ScanType, matches: list[IOCMatch]) -> ScanResult:
    return ScanResult(scan_type=scan_type, matches=matches)


def _apps_match(pkg: str) -> IOCMatch:
    return IOCMatch(
        indicator_type="package",
        indicator_value=pkg,
        matched_data=pkg,
        source="installed_apps",
        severity=MatchSeverity.HIGH,
    )


def _hash_match(pkg: str, apk_path: str) -> IOCMatch:
    # Mirrors FilesScanStrategy: matched_data = "<pkg> (<apk_path>)".
    return IOCMatch(
        indicator_type="file_hash",
        indicator_value="abc123",
        matched_data=f"{pkg} ({apk_path})",
        source="apk_hash",
        severity=MatchSeverity.CRITICAL,
    )


def _sms_match() -> IOCMatch:
    return IOCMatch(
        indicator_type="domain",
        indicator_value="bad.example.com",
        matched_data="hello visit bad.example.com",
        source="sms_body",
        severity=MatchSeverity.MEDIUM,
    )


def test_extracts_direct_package_match():
    pkgs, by_pkg = extract_matched_packages(
        [_result(ScanType.APPS, [_apps_match("de.fkie.ground_truth")])]
    )
    assert pkgs == ["de.fkie.ground_truth"]
    assert len(by_pkg["de.fkie.ground_truth"]) == 1


def test_extracts_package_from_hash_only_match():
    pkgs, by_pkg = extract_matched_packages(
        [
            _result(
                ScanType.FILES,
                [_hash_match("de.fkie.ground_truth", "/data/app/~~x/base.apk")],
            )
        ]
    )
    assert pkgs == ["de.fkie.ground_truth"]
    assert len(by_pkg["de.fkie.ground_truth"]) == 1


def test_dedupes_package_across_apps_and_hash_matches():
    pkg = "de.fkie.ground_truth"
    pkgs, by_pkg = extract_matched_packages(
        [
            _result(ScanType.APPS, [_apps_match(pkg)]),
            _result(ScanType.FILES, [_hash_match(pkg, "/data/app/~~x/base.apk")]),
        ]
    )
    assert pkgs == [pkg]  # one entry
    assert len(by_pkg[pkg]) == 2  # but both matches retained


def test_ignores_non_apk_matches():
    pkgs, by_pkg = extract_matched_packages([_result(ScanType.SMS, [_sms_match()])])
    assert pkgs == []
    assert by_pkg == {}


def test_rejects_malformed_package_token():
    bad = IOCMatch(
        indicator_type="file_hash",
        indicator_value="abc",
        matched_data="/data/app/orphan/base.apk",  # no "<pkg> (" prefix
        source="apk_hash",
        severity=MatchSeverity.CRITICAL,
    )
    pkgs, _ = extract_matched_packages([_result(ScanType.FILES, [bad])])
    assert pkgs == []  # path-like token rejected, not pulled
