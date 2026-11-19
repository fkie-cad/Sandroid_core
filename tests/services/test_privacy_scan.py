"""Privacy scan service: flows, pulled versions, sweep, retro, timeline lines.

Hermetic: flows are fixture ``flows.jsonl`` + ``details/<id>.json`` files,
versions are folders below the per-test ``SDROID_FILES_DIR``, and the
timeline is the in-memory ``timeline.capture()`` sink.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import threading
import time
from pathlib import Path

import pytest

from sandroid.core import timeline, watchlist_store
from sandroid.core.privacy_markers import Marker, build_needles
from sandroid.services import privacy_scan as ps
from sandroid.services import tracking_service as ts

AD_ID = "38400000-8cf0-11bd-b23e-10b96e40000d"
EMAIL = "Jane.Canary@example.org"
EMAIL_SHA = hashlib.sha256(EMAIL.lower().encode()).hexdigest()
LAT = "52.520008"
LON = "13.404954"
FP = "fp-1"

MARKERS = [
    Marker("ad_id", AD_ID, kind="uuid", label="Advertising ID", tag="Ad ID"),
    Marker("email", EMAIL, kind="email", label="E-mail", tag="Mail"),
    Marker("lat", LAT, kind="latitude", label="Latitude", group="gps", tag="GPS"),
    Marker("lon", LON, kind="longitude", label="Longitude", group="gps", tag="GPS"),
]


def wait_for(cond, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return bool(cond())


def _fake_recipients(host: str) -> tuple[str, bool]:
    if host.endswith("facebook.com"):
        return "Meta", True
    return ps.registrable_domain(host), False


@pytest.fixture(autouse=True)
def _recipients(monkeypatch):
    monkeypatch.setattr(ps, "_RECIPIENT_FN", _fake_recipients)


@pytest.fixture
def folder(tmp_path) -> Path:
    return tmp_path / "session"


@pytest.fixture
def flow_dir(tmp_path) -> Path:
    d = tmp_path / "raw" / "mitm_flows"
    (d / "details").mkdir(parents=True)
    return d


@pytest.fixture
def svc(folder, flow_dir):
    service = ps.PrivacyScanService(
        folder_fn=lambda: folder, flow_dir_fn=lambda: flow_dir
    )
    yield service
    service.close()


def _rec(seq: int, **kw) -> dict:
    rec = {
        "seq": seq,
        "id": f"f{seq}",
        "ts_start": 1_700_000_000.0 + seq,
        "ts_end": 1_700_000_000.5 + seq,
        "method": "POST",
        "host": "graph.facebook.com",
        "path": f"/v1/collect?aid={AD_ID}",
        "status_code": 200,
        "app": "com.fittrack.app",
    }
    rec.update(kw)
    return rec


def _body(data: bytes) -> dict:
    try:
        content, encoding = data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        content, encoding = base64.b64encode(data).decode("ascii"), "base64"
    return {"content": content, "encoding": encoding, "truncated": False}


def _detail(flow_id: str, *, req: bytes = b"", resp: bytes = b"", headers=()) -> dict:
    return {
        "id": flow_id,
        "request_headers": [["Content-Type", "application/json"], *headers],
        "response_headers": [["Server", "x"]],
        "request_body": _body(req),
        "response_body": _body(resp),
        "error": None,
    }


def _write_flow(flow_dir: Path, rec: dict, detail: dict | None) -> None:
    with open(flow_dir / "flows.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    if detail is not None:
        (flow_dir / "details" / f"{rec['id']}.json").write_text(json.dumps(detail))


def _standard_flow(flow_dir: Path, seq: int = 1) -> dict:
    """URL + header hit, gzip-in-base64 request body, echoed response."""
    rec = _rec(seq)
    req = gzip.compress(json.dumps({"em": EMAIL_SHA}).encode())
    resp = json.dumps({"ok": True, "aid": AD_ID}).encode()
    headers = [["X-Ad-Id", AD_ID.replace("-", "")]]
    _write_flow(flow_dir, rec, _detail(rec["id"], req=req, resp=resp, headers=headers))
    return rec


def _privacy_lines(lines: list[dict]) -> list[dict]:
    return [line for line in lines if line["src"] == "privacy"]


# --------------------------------------------------------------------- network


def test_flow_scan_parts_echo_and_timeline(svc, flow_dir, folder):
    rec = _standard_flow(flow_dir)
    with timeline.capture() as lines:
        svc.set_markers(FP, MARKERS)
        assert svc.flush()  # the retro scan of the existing flow
        svc.set_markers(None, [])
        svc.set_markers(FP, MARKERS)  # same fp again: nothing rescanned
        assert svc.flush()
        svc._covered.discard(("flow:f1", FP, ps.ENGINE_VERSION))
        svc.submit_flow(rec, flow_dir, 42)
        assert svc.flush()
    hits = svc.hits_for_flow("f1")
    by_part = {(h.part, h.marker_id): h for h in hits}
    assert ("url", "ad_id") in by_part
    header = by_part[("req.header:X-Ad-Id", "ad_id")]
    assert header.transform == "strip_dashes(value)"
    body = by_part[("req.body", "email")]
    assert body.decoded == "gzip"
    assert body.transform == "sha256(lower(value))"
    assert body.encoded
    assert body.direction == "sent"
    assert len(body.snippet[1]) <= ps.SNIPPET_MATCH_MAX
    assert sum(len(s) for s in body.snippet) <= 120
    echo = by_part[("resp.body", "ad_id")]
    assert echo.direction == "received"
    assert echo.echo
    assert not by_part[("url", "ad_id")].echo
    assert header.recipient == {
        "label": "Meta",
        "party": "third",
        "host": "graph.facebook.com",
        "domain": "facebook.com",
    }
    assert header.source["flow_id"] == "f1"
    # The first (retro) scan made the lines; the second scan only records.
    sent = _privacy_lines(lines)
    assert [line["kind"] for line in sent] == ["sent"] * 3
    first = sent[0]
    assert first["actor"] == "app"
    assert first["level"] == "info"
    assert not first.get("sensitive")
    assert first["ref"] == {"id": "f1", "path": "privacy/hits.jsonl", "lens": "network"}
    assert timeline._instant(first["t"]) == pytest.approx(rec["ts_start"], abs=1e-3)
    summaries = " ".join(line["summary"] for line in sent)
    assert "Advertising ID sent to graph.facebook.com" in summaries
    assert "req body · sha256(lower)" in summaries
    assert AD_ID not in summaries
    assert EMAIL_SHA not in summaries
    live = [h for h in hits if not h.retro]
    assert live
    assert all(not h.new and h.tl_seq is None for h in live)
    assert live[0].source["net_seq"] == 42
    # Records on disk mirror memory; the ledger has one line per scan.
    written = (folder / "privacy" / "hits.jsonl").read_text().splitlines()
    assert len(written) == len(hits)
    coverage = (folder / "privacy" / "coverage.jsonl").read_text().splitlines()
    assert len(coverage) == 2


def test_live_flow_ref_points_at_the_net_line(svc, flow_dir):
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    rec = _standard_flow(flow_dir, seq=7)
    with timeline.capture() as lines:
        svc.submit_flow(rec, flow_dir, 99)
        assert svc.flush()
    sent = _privacy_lines(lines)
    assert len(sent) == 3
    assert sent[0]["ref"]["of"] == 99
    assert sent[0]["ref"]["id"] == "f7"
    by_seq = {
        h.tl_seq for h in svc.hits_for_flow("f7") if h.new and h.direction == "sent"
    }
    assert by_seq == {line["seq"] for line in sent}


def test_detail_file_race_is_retried(svc, flow_dir):
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    rec = _rec(1)
    _write_flow(flow_dir, rec, None)
    detail = _detail("f1", req=json.dumps({"mail": EMAIL}).encode())
    timer = threading.Timer(
        0.3,
        lambda: (flow_dir / "details" / "f1.json").write_text(json.dumps(detail)),
    )
    timer.start()
    try:
        svc.submit_flow(rec, flow_dir, None)
        assert svc.flush()
    finally:
        timer.join()
    assert {h.marker_id for h in svc.hits_for_flow("f1")} == {"ad_id", "email"}


def test_vanished_details_are_unscannable(svc, flow_dir, folder, monkeypatch):
    monkeypatch.setattr(ps, "DETAIL_RETRY_S", 0.1)
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    rec = _rec(1)
    _write_flow(flow_dir, rec, None)
    svc.submit_flow(rec, flow_dir, 5)
    assert svc.flush()
    assert svc.hits_for_flow("f1") == []
    coverage = [
        json.loads(x)
        for x in (folder / "privacy" / "coverage.jsonl").read_text().splitlines()
    ]
    assert [c["skip"] for c in coverage if c["key"] == "flow:f1"] == ["unscannable"]


def test_tls_records_and_inactive_service_are_ignored(svc, flow_dir):
    svc.submit_flow(_rec(1), flow_dir, 1)  # no markers: nothing queued
    assert svc._queue.qsize() == 0
    svc.set_markers(FP, MARKERS)
    svc.submit_flow(_rec(2, kind="tls"), flow_dir, 2)
    assert svc.flush()
    assert svc.hits_for_flow("f2") == []


def test_tags_for_flow_are_plain_words(svc, flow_dir):
    _standard_flow(flow_dir)
    rec = _rec(2, path="/geo?lat=52.520&lon=13.405")
    _write_flow(flow_dir, rec, _detail("f2"))
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    tags = svc.tags_for_flow("f1")
    assert [t.tag for t in tags] == ["Ad ID", "Mail"]
    assert all(t.tag.replace(" ", "").isalnum() for t in tags)
    ad, mail = tags
    assert (ad.party, ad.direction, ad.encoded, ad.approx) == (
        "third",
        "sent",
        False,
        False,
    )
    assert mail.encoded
    assert mail.confidence == "high"
    geo = svc.tags_for_flow("f2")
    assert {t.marker_id for t in geo} == {"lat", "lon"}
    assert all(t.approx and not t.encoded for t in geo)
    assert svc.tags_for_flow("nope") == []


def test_classify_party():
    pkg = "com.fittrack.app"
    assert ps.classify_party("api.fittrack.de", pkg) == ("fittrack.de", "first")
    assert ps.classify_party("graph.facebook.com", pkg) == ("Meta", "third")
    assert ps.classify_party("cdn.random.io", pkg) == ("random.io", "unknown")
    assert ps.classify_party("cdn.random.io", None)[1] == "unknown"
    assert ps.classify_party("x.app.com", pkg)[1] == "unknown"  # generic token


# ------------------------------------------------------------------- scanning


def test_chunk_boundary_overlap_reports_once(monkeypatch):
    needles = build_needles(MARKERS)
    monkeypatch.setattr(ps, "CHUNK", 64)
    for start in range(40, 70):
        data = b"x" * start + EMAIL.encode() + b"y" * 100
        aggs, truncated = ps.scan_bytes(needles, data)
        agg = aggs[("email", "value")]
        assert (agg.count, agg.offsets, truncated) == (1, [start], False), start


def test_file_cap_flags_truncated(monkeypatch):
    needles = build_needles(MARKERS)
    data = b"z" * 300 + EMAIL.encode()
    aggs, truncated = ps.scan_bytes(needles, data, cap=200)
    assert truncated
    assert not aggs


def test_body_bytes_unwraps_zlib_and_keeps_plain():
    raw = json.dumps({"a": EMAIL}).encode()
    import zlib

    data, truncated, decoded = ps.body_bytes(_body(zlib.compress(raw)))
    assert (data, truncated, decoded) == (raw, False, "zlib")
    assert ps.body_bytes(_body(raw)) == (raw, False, None)
    assert ps.body_bytes(None) == (b"", False, None)


# ----------------------------------------------------------------------- files

DB = "/data/data/com.fittrack.app/databases/app.db"
PREFS = "/data/data/com.fittrack.app/shared_prefs/ids.xml"


def _version(device_path: str, n: int, files: dict[str, bytes]) -> Path:
    vdir = watchlist_store.row_dir(device_path) / f"v{n:03d}_10-00-0{n}"
    vdir.mkdir(parents=True)
    for name, data in files.items():
        (vdir / name).write_bytes(data)
    return vdir


def test_wal_member_and_new_vs_repeat(svc):
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    v1 = _version(DB, 1, {"app.db": b"SQLite format 3\0", "app.db-wal": EMAIL.encode()})
    with timeline.capture() as lines:
        svc.submit_version(DB, v1, 11)
        assert svc.flush()
        v2 = _version(
            DB,
            2,
            {"app.db": b"SQLite " + EMAIL.encode(), "app.db-wal": AD_ID.encode()},
        )
        svc.submit_version(DB, v2, 12)
        assert svc.flush()
        v3 = _version(DB, 3, {"app.db": b"nothing"})
        svc.submit_version(DB, v3, 13)
        v4 = _version(DB, 4, {"app.db": EMAIL.encode()})
        svc.submit_version(DB, v4, 14)
        assert svc.flush()
    hits = svc.hits_for_file(DB)
    first = [h for h in hits if h.source["version"] == v1.name]
    assert [(h.part, h.marker_id, h.new) for h in first] == [
        ("file:app.db-wal", "email", True)
    ]
    assert first[0].source["member"] == "app.db-wal"
    assert first[0].source["pull_seq"] == 11
    assert first[0].direction == "stored"
    second = {h.marker_id: h for h in hits if h.source["version"] == v2.name}
    assert not second["email"].new
    assert second["ad_id"].new
    fourth = [h for h in hits if h.source["version"] == v4.name]
    assert [h.new for h in fourth] == [True]  # not in v003
    stored = _privacy_lines(lines)
    # One line per (marker, transform, path), even when it comes back in v004.
    assert [line["kind"] for line in stored] == ["stored", "stored"]
    assert stored[0]["ref"] == {
        "of": 11,
        "path": "privacy/hits.jsonl",
        "lens": "files",
    }
    assert stored[0]["summary"] == "E-mail stored in databases/app.db · plain"
    assert svc.tags_for_file(DB)[0].party == "stored"


def test_retro_scan_is_idempotent_per_fingerprint(svc, flow_dir, folder):
    _standard_flow(flow_dir)
    _version(PREFS, 1, {"ids.xml": f"<string>{AD_ID}</string>".encode()})
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    first = svc.hits()
    assert first
    assert all(h.retro for h in first)
    assert {h.source["type"] for h in first} == {"flow", "file"}
    coverage_file = folder / "privacy" / "coverage.jsonl"
    n_cov = len(coverage_file.read_text().splitlines())

    # A fresh service (restart) loads the ledger: nothing is scanned again.
    again = ps.PrivacyScanService(
        folder_fn=lambda: folder, flow_dir_fn=lambda: flow_dir
    )
    try:
        again.set_markers(FP, MARKERS)
        assert again.flush()
        assert len(again.hits()) == len(first)
        assert len(coverage_file.read_text().splitlines()) == n_cov
        # A new profile rescans everything once.
        again.set_markers("fp-2", MARKERS)
        assert again.flush()
        assert len([h for h in again.hits() if h.fp == "fp-2"]) == len(first)
        assert len(coverage_file.read_text().splitlines()) == 2 * n_cov
    finally:
        again.close()


def test_load_session_and_hits_between(svc, flow_dir, folder):
    _standard_flow(flow_dir)
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    other = ps.PrivacyScanService(folder_fn=lambda: None)
    other.load_session(folder)
    assert [h.to_json() for h in other.hits()] == [h.to_json() for h in svc.hits()]
    t = 1_700_000_001.0
    assert len(other.hits_between(t - 1, t + 1)) == len(svc.hits_for_flow("f1"))
    assert other.hits_between(0, 1) == []
    assert other.hits(marker_id="email")[0].marker_id == "email"


def test_sweep_keeps_only_files_with_hits(svc, folder, monkeypatch):
    from sandroid import services
    from sandroid.services.file_extraction_service import ExtractionResult

    class FakeFx:
        def pull_all_for_package(self, package, output_dir=None):
            base = Path(output_dir) / "stamp" / "data_data_pkg"
            base.mkdir(parents=True)
            out = []
            for name, data in (("prefs.xml", EMAIL.encode()), ("cache.bin", b"0")):
                (base / name).write_bytes(data)
                out.append(
                    ExtractionResult(
                        source_path=f"/data/data/{package}/{name}",
                        local_path=str(base / name),
                        success=True,
                    )
                )
            return out

    monkeypatch.setattr(services, "get_file_extraction_service", FakeFx)
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    svc.sweep_app_data("emulator-test", "com.fittrack.app")
    assert wait_for(lambda: svc.hits())
    assert svc.flush()
    (hit,) = svc.hits()
    assert hit.device_path == "/data/data/com.fittrack.app/prefs.xml"
    assert hit.source["version"].startswith("sweep:com.fittrack.app_")
    kept = [p.name for p in (folder / "privacy" / "sweep").rglob("*") if p.is_file()]
    assert kept == ["prefs.xml"]


# --------------------------------------------------------- queue / listeners


def test_queue_overflow_goes_to_the_ledger(folder, flow_dir):
    service = ps.PrivacyScanService(
        folder_fn=lambda: folder, flow_dir_fn=lambda: flow_dir, queue_max=3
    )
    try:
        service._ensure_worker = lambda: None  # nothing drains the queue
        service.set_markers(FP, MARKERS)  # the retro wake-up takes one slot
        for seq in range(1, 6):
            rec = _rec(seq)
            _write_flow(flow_dir, rec, _detail(rec["id"]))
            service.submit_flow(rec, flow_dir, seq)
        assert service.dropped == 3
        del service._ensure_worker
        service._ensure_worker()
        assert service.flush()
    finally:
        service.close()
    coverage = [
        json.loads(x)
        for x in (folder / "privacy" / "coverage.jsonl").read_text().splitlines()
    ]
    full = {c["key"] for c in coverage if c.get("skip") == "queue-full"}
    assert full == {"flow:f3", "flow:f4", "flow:f5"}
    # ...and the retro scan picked the dropped flows up again.
    assert {h.flow_id for h in service.hits()} == {f"f{i}" for i in range(1, 6)}


def test_listener_runs_on_the_worker(svc, flow_dir):
    seen: list[tuple[str, str]] = []
    svc.add_listener(
        lambda rec: seen.append((threading.current_thread().name, rec.part))
    )
    _standard_flow(flow_dir)
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    assert seen
    assert {name for name, _ in seen} == {"privacy-scan"}


def test_summary_counts_values(svc, flow_dir):
    summary = svc.summary()
    assert not summary.active
    assert summary.values_total == 0
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    summary = svc.summary()
    assert summary.active
    assert summary.fingerprint == FP
    assert (summary.values_total, summary.values_found, summary.hits_total) == (
        3,
        0,
        0,
    )
    rec = _rec(1, path="/geo?lat=52.520008&lon=13.404954")
    _write_flow(flow_dir, rec, _detail("f1"))
    svc.submit_flow(rec, flow_dir, 1)
    assert svc.flush()
    summary = svc.summary()
    assert summary.values_found == 1  # latitude + longitude are one value
    assert summary.hits_total == len(svc.hits()) == 2
    assert summary.last_hit_at is not None


# ---------------------------------------------------------------- auto-watch


def test_auto_watch_covers_and_min_interval(svc, monkeypatch):
    pkg = "com.fittrack.app"
    assert not svc.auto_watch_covers(PREFS, pkg)  # no profile yet
    svc.set_markers(FP, MARKERS)
    assert svc.auto_watch_covers(PREFS, pkg)
    assert svc.auto_watch_covers(DB, pkg)
    assert not svc.auto_watch_covers(DB + "-shm", pkg)
    assert not svc.auto_watch_covers("/data/data/com.fittrack.app/cache/x", pkg)
    assert not svc.auto_watch_covers(PREFS, "com.other")
    assert svc.auto_watch_patterns(pkg)[0].endswith("/shared_prefs/*")
    clock = [100.0]
    monkeypatch.setattr(ps, "_clock", lambda: clock[0])
    assert svc.auto_watch_delay(PREFS) == 0.0
    clock[0] += 4.0
    assert svc.auto_watch_delay(PREFS) == pytest.approx(6.0)
    clock[0] += 6.0
    assert svc.auto_watch_delay(PREFS) == 0.0


def test_watchlist_privacy_auto_pull_is_not_persisted(svc, monkeypatch):
    """A write to an auto-watched file pulls it (no row, no membership file)
    and the kept version reaches the scan.
    """
    from sandroid.services.file_extraction_service import (
        ExtractionResult,
        FileExtractionService,
    )
    from sandroid.tui.widgets.watchlist_view import WatchlistView

    def pull(self, remote_path, local_path, compute_hash=False):
        if remote_path != PREFS:
            return ExtractionResult(remote_path, local_path, False, "missing")
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        Path(local_path).write_text(f"<s>{AD_ID}</s>")
        return ExtractionResult(remote_path, local_path, True)

    monkeypatch.setattr(FileExtractionService, "pull_file", pull)
    monkeypatch.setattr(WatchlistView, "_device_facts", staticmethod(lambda p: {}))
    monkeypatch.setattr(WatchlistView, "_device_clock", staticmethod(lambda: None))
    monkeypatch.setattr(WatchlistView, "_start_timer", lambda *a, **k: None)
    monkeypatch.setattr(ps, "get_privacy_scan_service", lambda: svc)
    svc.set_markers(FP, MARKERS)
    view = WatchlistView()
    assert not view.privacy_watching  # the monitored app is not known yet
    view._monitored_package = "com.fittrack.app"
    assert view.privacy_watching
    assert view.note_write(PREFS)
    assert view.pending_auto == [PREFS]
    view.fire_auto_pull(PREFS)  # inline: no app, so no worker thread
    assert svc.flush()
    assert view.rows == {}
    assert list(watchlist_store.watchlist_dir().glob("*.json")) == []
    (hit,) = svc.hits_for_file(PREFS)
    assert hit.source["version"].startswith("v001_")
    # A second write within the minimum interval waits instead of pulling.
    assert view.note_write(PREFS)
    view.fire_auto_pull(PREFS)
    assert view.pending_auto == [PREFS]
    assert len(watchlist_store.version_dirs(PREFS)) == 1


# ------------------------------------------------------------ NetFlowSource


def test_net_flow_source_calls_sinks_after_the_line(tmp_path, flow_dir):
    for rec in (_rec(1), _rec(2, kind="tls", id="t2")):
        _write_flow(flow_dir, rec, _detail(rec["id"]))
    (flow_dir / "meta.json").write_text(
        json.dumps({"earliest_seq": 1, "latest_seq": 2, "generation": 0})
    )
    got: list[tuple[str, int | None]] = []

    def sink(rec, fdir, seq):
        got.append((rec["id"], seq))

    def bad_sink(rec, fdir, seq):
        raise RuntimeError("boom")

    src = ts.NetFlowSource(flow_dir_fn=lambda: flow_dir, folder_fn=lambda: tmp_path)
    ts.NetFlowSource.add_sink(bad_sink)
    ts.NetFlowSource.add_sink(sink)
    try:
        assert src.poll() == 2  # no open timeline: no sink call
        assert got == []
        src.cursor = 0
        with timeline.capture() as lines:
            assert src.poll() == 2
    finally:
        ts.NetFlowSource.remove_sink(sink)
        ts.NetFlowSource.remove_sink(bad_sink)
    flow = next(line for line in lines if line["kind"] == "flow")
    assert got == [("f1", flow["seq"])]  # the tls-fail record is not passed


def test_net_flow_source_sinks_get_none_when_policy_drops_the_line(tmp_path, flow_dir):
    _write_flow(flow_dir, _rec(1), _detail("f1"))
    (flow_dir / "meta.json").write_text(
        json.dumps({"earliest_seq": 1, "latest_seq": 1, "generation": 0})
    )
    got: list[tuple[str, int | None]] = []

    def sink(rec, fdir, seq):
        got.append((rec["id"], seq))

    src = ts.NetFlowSource(flow_dir_fn=lambda: flow_dir, folder_fn=lambda: tmp_path)
    ts.NetFlowSource.add_sink(sink)
    service = timeline.get_timeline()
    try:
        with timeline.capture() as lines:
            service._policy = timeline.Policy({"sources": {"net": False}})
            assert src.poll() == 1
    finally:
        ts.NetFlowSource.remove_sink(sink)
    assert lines == []
    assert got == [("f1", None)]
