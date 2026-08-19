"""Regression test: ChangedFiles' .xml branch must reuse the already-computed
os.path.join()-based pull paths (not rebuild hardcoded forward-slash
f-strings) in both return_data() and pretty_print().
"""

from __future__ import annotations

import os

import pytest

from sandroid.analysis.changedfiles import ChangedFiles
from sandroid.core import file_diff


@pytest.fixture(autouse=True)
def _raw_results_path(monkeypatch):
    monkeypatch.setenv("RAW_RESULTS_PATH", "/results/raw/")


def _expected(pull_dir, device_path):
    return os.path.join(f"/results/raw/{pull_dir}", device_path.lstrip("/"))


def _patch_xml_diff(monkeypatch):
    captured = {}

    def fake_xml_diff(p1, p2, p3):
        captured["args"] = (p1, p2, p3)
        return "ITS ALL NOISE"

    monkeypatch.setattr(file_diff, "xml_diff", fake_xml_diff)
    return captured


def test_return_data_and_pretty_print_use_joined_xml_paths(monkeypatch):
    device_path = "/nested/sub/settings.xml"
    cf = ChangedFiles()
    monkeypatch.setattr(cf, "process_data", lambda: [device_path])
    expected = (
        _expected("first_pull", device_path),
        _expected("second_pull", device_path),
        _expected("noise_pull", device_path),
    )

    captured = _patch_xml_diff(monkeypatch)
    cf.return_data()
    assert captured["args"] == expected
    assert "//" not in captured["args"][0]  # old hardcoded f-string bug

    captured = _patch_xml_diff(monkeypatch)
    cf.pretty_print()
    assert captured["args"] == expected
