"""Unit tests for the Forensic panel's IOC-status rendering.

These assert the header reflects the CONFIGURED IOC source (count + file/dir
name) rather than the MVT cache pool — the bug where a small custom IOC file
looked like it was never applied. Pure logic; no device or Textual runtime.
"""

from __future__ import annotations

from sandroid.tui.widgets.forensic_panel import ForensicPanel


def _panel() -> ForensicPanel:
    return ForensicPanel()


def test_source_summary_single_file(tmp_path):
    f = tmp_path / "ground_truth_ioc.stix2"
    f.write_text("{}")
    count, label = ForensicPanel._ioc_source_summary(f)
    assert count == 1
    assert label == "ground_truth_ioc.stix2"


def test_source_summary_directory(tmp_path):
    (tmp_path / "a.stix2").write_text("{}")
    (tmp_path / "b.json").write_text("{}")
    (tmp_path / "notes.txt").write_text("ignore me")
    count, label = ForensicPanel._ioc_source_summary(tmp_path)
    assert count == 2
    assert label == "2 files"


def test_source_summary_none():
    assert ForensicPanel._ioc_source_summary(None) == (0, None)


def test_render_configured_shows_source_not_cache():
    panel = _panel()
    panel._ioc_info = {
        "configured": True,
        "indicator_count": 3,
        "file_count": 1,
        "source_label": "ground_truth_ioc.stix2",
    }
    rendered = panel._render_ioc_status()
    assert "IOC ✓" in rendered
    assert "3 indicators" in rendered
    assert "ground_truth_ioc.stix2" in rendered


def test_render_unconfigured_offers_cached_hint():
    panel = _panel()
    panel._ioc_info = {
        "configured": False,
        "indicator_count": 22227,
        "file_count": 11,
        "source_label": None,
    }
    rendered = panel._render_ioc_status()
    assert "IOC ○" in rendered
    assert "22,227 cached" in rendered
    assert "press c" in rendered


def test_render_unconfigured_no_cache():
    panel = _panel()
    panel._ioc_info = {"configured": False, "indicator_count": 0, "file_count": 0}
    assert "not configured" in panel._render_ioc_status()
