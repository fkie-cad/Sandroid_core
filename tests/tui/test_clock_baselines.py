"""Files lens: the device clock in pull evidence + session-start baselines.

* every ``acquisition.json`` and ``checks.jsonl`` line carries the
  ``device_clock`` sample of its pull;
* the Inspector shows the offset next to device times when it is > 1 s;
* when the file monitor starts, watched files get one ``session-start``
  pull (no-change path: only a ``checks.jsonl`` line; at most 50).

``WatchlistView`` runs unmounted here, so its pull worker runs inline.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from sandroid.core import device_clock, watchlist_store
from sandroid.services import get_forensic_service
from sandroid.services.file_extraction_service import (
    ExtractionResult,
    FileExtractionService,
)
from sandroid.tui.widgets import file_inspect as tfi
from sandroid.tui.widgets.files_panel import FilesPanel
from sandroid.tui.widgets.watchlist_view import (
    SESSION_BASELINE_CAP,
    RowState,
    WatchlistView,
)

PREFS = "/data/data/com.app/shared_prefs/p.xml"
OTHER = "/data/data/org.other/shared_prefs/o.xml"
#: A device 75 min behind the host (off_wall = host - device).
CLOCK = {
    "serial": "emu-1",
    "host_at": "2026-11-18T15:58:01.042+01:00",
    "device_at": "2026-11-18T14:43:01.042+01:00",
    "off_wall": 4500.0,
    "off_mono": 1763470000.5,
    "dev_mono": 81234.5,
    "rtt_ms": 14.2,
    "err_ms": 7.1,
    "method": "shell",
    "samples": 5,
    "mono_note": None,
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.fixture
def content(monkeypatch) -> dict[str, str]:
    files = {PREFS: "<map/>\n", OTHER: "<map/>\n"}

    def pull(self, remote_path, local_path, compute_hash=False):
        if remote_path not in files:
            return ExtractionResult(remote_path, local_path, False, error="none")
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        Path(local_path).write_text(files[remote_path], encoding="utf-8")
        return ExtractionResult(remote_path, local_path, True)

    def facts(paths):
        return {
            p: {"mtime": 1763473501, "size": len(files[p]), "sha256": _sha(files[p])}
            for p in paths
            if p in files
        }

    monkeypatch.setattr(FileExtractionService, "pull_file", pull)
    monkeypatch.setattr(WatchlistView, "_device_facts", staticmethod(facts))
    monkeypatch.setattr(WatchlistView, "_device_clock", staticmethod(lambda: CLOCK))
    svc = get_forensic_service()
    svc._spotlight_files.clear()
    yield files
    svc._spotlight_files.clear()


def _view(*paths: str) -> WatchlistView:
    for path in paths:
        get_forensic_service().add_spotlight_file(path)
    view = WatchlistView()
    view.reload()
    return view


# -- device_clock in the evidence -------------------------------------------------


def test_acquisition_and_checks_carry_the_device_clock(content):
    view = _view(PREFS)
    view.pull([PREFS])
    (version,) = watchlist_store.version_dirs(PREFS)
    record = watchlist_store.version_record(version)
    assert record["device_clock"] == CLOCK
    assert view.rows[PREFS].device_clock == CLOCK
    view.pull([PREFS])  # unchanged on the device: a check line, no copy
    (check,) = watchlist_store.version_checks(PREFS)
    assert check["device_clock"] == CLOCK
    assert len(watchlist_store.version_dirs(PREFS)) == 1


def test_inspector_versions_show_the_offset_next_to_device_times(tmp_path):
    def version(clock):
        record = {
            "local": {"file": "p.xml", "size": 6, "sha256": _sha("x")},
            "device": {"mtime": 1763473501, "size": 6, "sha256": _sha("x")},
            "trigger": "auto",
            "device_clock": clock,
        }
        return tfi.Version(1, tmp_path / "v001_10-00-00", tmp_path / "p.xml",
                           None, 6, record)  # fmt: skip

    assert "device clock −75 min" in tfi.RecordLines(version(CLOCK)).second
    close = {**CLOCK, "off_wall": 0.4}
    assert not any("device clock" in b for b in tfi.RecordLines(version(close)).second)
    assert not any("device clock" in b for b in tfi.RecordLines(version(None)).second)


def test_inspector_summary_shows_the_offset_only_when_over_a_second():
    text = FilesPanel._clock_text(CLOCK)
    assert text.plain.startswith("−75 min vs host")
    assert str(text.style) == "#fbbf24"
    assert FilesPanel._clock_text({**CLOCK, "off_wall": -0.9}) is None
    assert FilesPanel._clock_text(None) is None
    ahead = FilesPanel._clock_text({**CLOCK, "off_wall": -2.3})
    assert ahead.plain.startswith("+2.3 s vs host")


# -- session-start baselines -------------------------------------------------------


def test_monitor_start_pulls_the_apps_watched_files_once(content):
    view = _view(PREFS, OTHER)
    assert view.pull_session_baselines("com.app") == 1
    (version,) = watchlist_store.version_dirs(PREFS)
    assert watchlist_store.version_record(version)["trigger"] == "session-start"
    assert view.rows[PREFS].state is RowState.BASELINE_ONLY
    assert watchlist_store.version_dirs(OTHER) == []  # another app's watch
    # Once per session: a monitor restart does not pull again.
    assert view.pull_session_baselines("com.app") == 0
    assert view.pull_session_baselines(None) == 1  # whole-device scope
    assert len(watchlist_store.version_dirs(OTHER)) == 1


def test_session_start_with_an_unchanged_file_only_writes_a_check(content):
    view = _view(PREFS)
    view.pull([PREFS])  # pulled earlier in this session
    assert view.pull_session_baselines("com.app") == 1
    assert len(watchlist_store.version_dirs(PREFS)) == 1
    (check,) = watchlist_store.version_checks(PREFS)
    assert check["trigger"] == "session-start"
    assert check["same_as"] == "v001"
    assert check["device_clock"] == CLOCK


def test_session_start_is_capped_and_names_the_rest(content, monkeypatch, caplog):
    paths = [f"/data/data/com.app/files/f{i:02d}" for i in range(53)]
    view = _view(*paths)
    started: list[tuple[list[str], str]] = []
    monkeypatch.setattr(
        view,
        "_start_pull",
        lambda p, trigger="manual", **k: started.append((p, trigger)),
    )
    with caplog.at_level(logging.WARNING):
        assert view.pull_session_baselines("com.app") == SESSION_BASELINE_CAP
    ((pulled, trigger),) = started
    assert trigger == "session-start"
    assert pulled == sorted(paths)[:SESSION_BASELINE_CAP]
    (warning,) = [r.getMessage() for r in caplog.records if "limited" in r.getMessage()]
    for rest in sorted(paths)[SESSION_BASELINE_CAP:]:
        assert rest in warning
    assert sorted(paths)[0] not in warning


def test_files_lens_monitor_start_hook(monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        device_clock, "record_async", lambda *a, **k: calls.append(("clock", a))
    )
    wl = SimpleNamespace(pull_session_baselines=lambda pkg: calls.append(("pull", pkg)))
    lens = SimpleNamespace(
        _watchlist_or_none=lambda: wl, _app_root=lambda: "/data/data/com.app/"
    )
    FilesPanel._on_monitor_started(lens)
    assert calls == [("clock", ("monitor-start",)), ("pull", "com.app")]
    calls.clear()
    lens._app_root = lambda: None  # device-wide monitor: every watched file
    FilesPanel._on_monitor_started(lens)
    assert calls[-1] == ("pull", None)
