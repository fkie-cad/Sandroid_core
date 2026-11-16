"""IOCDownloader's no-mvt-CLI fallback reads the mvt-indicators index.

The old hard-coded files (mvt/android/data/*.stix2 in mvt-project/mvt)
return 404 upstream, so the fallback downloaded nothing.
"""

from __future__ import annotations

import io

from sandroid.core import ioc_downloader
from sandroid.core.ioc_downloader import IOCDownloader

INDEX = b"""
indicators:
  - type: github
    name: Pegasus
    github:
      owner: AmnestyTech
      repo: investigations
      branch: master
      path: 2021-07-18_nso/pegasus.stix2
  - type: github
    name: RCS
    github:
      owner: mvt-project
      repo: mvt-indicators
      path: 2022-06-23_rcs_lab/rcs.stix2
  - type: download
    name: Other
    download_url: https://example.org/x/other.stix2
  - type: github
    name: broken entry
    github: {}
"""


def _fake_urlopen(responses, seen):
    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def urlopen(url, timeout=None, context=None):
        seen.append(url)
        if url not in responses:
            raise OSError(f"404 {url}")
        return _Resp(responses[url])

    return urlopen


def test_fallback_downloads_every_index_entry(tmp_path, monkeypatch):
    seen = []
    responses = {
        IOCDownloader.MVT_INDICATORS_INDEX: INDEX,
        "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2": b"{}",
        "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2022-06-23_rcs_lab/rcs.stix2": b"{}",
        "https://example.org/x/other.stix2": b"{}",
    }
    monkeypatch.setattr(ioc_downloader, "urlopen", _fake_urlopen(responses, seen))
    monkeypatch.setattr(IOCDownloader, "CACHE_DIR", tmp_path)

    out = IOCDownloader()._download_from_github()

    assert out == tmp_path / "github_mvt"
    names = sorted(p.name for p in out.iterdir())
    assert names == sorted(
        [
            "raw.githubusercontent.com_AmnestyTech_investigations_master_2021-07-18_nso_pegasus.stix2",
            "raw.githubusercontent.com_mvt-project_mvt-indicators_main_2022-06-23_rcs_lab_rcs.stix2",
            "example.org_x_other.stix2",
        ]
    )


def test_legacy_list_used_when_index_unreachable(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(ioc_downloader, "urlopen", _fake_urlopen({}, seen))
    monkeypatch.setattr(IOCDownloader, "CACHE_DIR", tmp_path)

    assert IOCDownloader()._download_from_github() is None
    assert seen[0] == IOCDownloader.MVT_INDICATORS_INDEX
    assert any(u.endswith("mvt/android/data/pegasus.stix2") for u in seen[1:])
