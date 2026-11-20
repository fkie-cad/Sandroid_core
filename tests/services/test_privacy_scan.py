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
    # The first (retro) scan made the lines; the rescan adds nothing.
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
    assert (
        "Advertising ID sent to graph.facebook.com, URL, as is" in summaries
    )  # plain words, commas: no separator glyphs
    assert (
        "E-mail sent to graph.facebook.com, request body, sha256 of the "
        "lower-case value" in summaries
    )
    assert "·" not in summaries
    assert AD_ID not in summaries
    assert EMAIL_SHA not in summaries
    # The rescan of the same flow (coverage dropped) records no duplicates.
    assert all(h.retro for h in hits)
    assert len({(h.part, h.marker_id, h.transform) for h in hits}) == len(hits)
    # Records on disk mirror memory; the ledger has one line per scan.
    written = (folder / "privacy" / "hits.jsonl").read_text().splitlines()
    assert len(written) == len(hits)
    coverage = _coverage(folder)
    assert len([c for c in coverage if c["skip"] != "markers"]) == 2
    # The marker set both scans name is defined once.
    defined = [c for c in coverage if c["skip"] == "markers"]
    assert [c["set"] for c in defined] == [coverage[1]["set"]]
    assert coverage[1]["set"] == coverage[2]["set"]


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


def _coverage(folder: Path) -> list[dict]:
    return [
        json.loads(x)
        for x in (folder / "privacy" / "coverage.jsonl").read_text().splitlines()
    ]


def test_flow_without_details_scans_the_url_and_completes_later(
    svc, flow_dir, folder, monkeypatch
):
    """No details file: the URL is still scanned and the flow stays "partial";
    a later retro scan with the details adds the body hits, without
    recording the URL hit or its timeline line again.
    """
    monkeypatch.setattr(ps, "DETAIL_RETRY_S", 0.1)
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    rec = _rec(1)
    _write_flow(flow_dir, rec, None)
    with timeline.capture() as lines:
        svc.submit_flow(rec, flow_dir, 5)
        assert svc.flush()
        first = svc.hits_for_flow("f1")
        assert [(h.part, h.marker_id) for h in first] == [("url", "ad_id")]
        assert [c["skip"] for c in _coverage(folder) if c["key"] == "flow:f1"] == [
            "partial"
        ]
        # The details appear (a later retro scan, e.g. a new profile or a
        # restart): the body is scanned, the URL hit is not recorded again.
        detail = _detail("f1", req=json.dumps({"mail": EMAIL}).encode())
        (flow_dir / "details" / "f1.json").write_text(json.dumps(detail))
        again = ps.PrivacyScanService(
            folder_fn=lambda: folder, flow_dir_fn=lambda: flow_dir
        )
        try:
            again.set_markers(FP, MARKERS)
            assert again.flush()
            hits = again.hits_for_flow("f1")
        finally:
            again.close()
    assert sorted((h.part, h.marker_id) for h in hits) == [
        ("req.body", "email"),
        ("url", "ad_id"),
    ]
    assert [c["skip"] for c in _coverage(folder) if c["key"] == "flow:f1"] == [
        "partial",
        None,
    ]
    sent = _privacy_lines(lines)
    assert [line["data"]["marker_id"] for line in sent] == ["ad_id", "email"]


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


@pytest.mark.parametrize(
    ("host", "package"),
    [
        ("www.google-analytics.com", "com.google.android.youtube"),
        ("pagead2.googlesyndication.com", "com.google.android.apps.maps"),
        ("aax.amazon-adsystem.com", "com.amazon.mShop.android.shopping"),
        ("config.samsungads.com", "com.samsung.android.app.notes"),
    ],
)
def test_party_trackers_of_the_apps_vendor_are_third(monkeypatch, host, package):
    """A package token inside a tracker's domain name is no first party."""
    # Unknown to the lookup: whole labels only, so not "first" either.
    assert ps.classify_party(host, package)[1] == "unknown"
    assert not ps._first_party(host, package)

    def known(h: str) -> tuple[str, bool]:
        return ("Ad network", True) if h == host else (ps.registrable_domain(h), False)

    monkeypatch.setattr(ps, "_RECIPIENT_FN", known)
    assert ps.classify_party(host, package) == ("Ad network", "third")


def test_party_known_tracker_wins_over_a_matching_package(monkeypatch):
    monkeypatch.setattr(ps, "_RECIPIENT_FN", lambda h: ("Meta", True))
    assert ps.classify_party("graph.facebook.com", "com.facebook.katana") == (
        "Meta",
        "third",
    )


# ------------------------------------------------------------------- scanning


def test_chunk_boundary_overlap_reports_once(monkeypatch):
    needles = build_needles(MARKERS)
    monkeypatch.setattr(ps, "CHUNK", 64)
    for start in range(40, 70):
        data = b"x" * start + EMAIL.encode() + b"y" * 100
        aggs, truncated = ps.scan_bytes(needles, data)
        agg = aggs[("email", "value")]
        assert (agg.count, agg.offsets, truncated) == (1, [start], False), start


def test_chunk_boundary_keeps_a_weaker_form_suppressed(monkeypatch):
    """``+4915112345678`` straddling a chunk limit: its digits-only form
    (inside it, found again in the next chunk) is not a second record.
    """
    phone = "+4915112345678"
    needles = build_needles([Marker("phone", phone, kind="phone", label="Phone")])
    monkeypatch.setattr(ps, "CHUNK", 64)
    for start in range(200):  # some put "+" before a limit, the digits after
        data = b"x" * start + phone.encode() + b"y" * 150
        aggs, _truncated = ps.scan_bytes(needles, data)
        assert set(aggs) == {("phone", "value")}, start
        assert aggs[("phone", "value")].offsets == [start], start


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
    assert stored[0]["summary"] == "E-mail stored in databases/app.db, as is"
    assert svc.tags_for_file(DB)[0].party == "stored"


def _item_lines(folder: Path) -> list[dict]:
    """Coverage lines of scanned items (not the marker set definitions)."""
    return [c for c in _coverage(folder) if c.get("skip") != "markers"]


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
    n_items = len(_item_lines(folder))
    assert n_items == 2

    # A fresh service (restart) loads the ledger: nothing is scanned again.
    again = ps.PrivacyScanService(
        folder_fn=lambda: folder, flow_dir_fn=lambda: flow_dir
    )
    try:
        again.set_markers(FP, MARKERS)
        assert again.flush()
        assert len(again.hits()) == len(first)
        assert len(coverage_file.read_text().splitlines()) == n_cov
        # The same markers again (another apply of the profile): nothing.
        again.set_markers(FP, list(MARKERS))
        assert again.flush()
        assert len(coverage_file.read_text().splitlines()) == n_cov
        # A new profile rescans everything once (the marker set is the
        # same, so it is not defined again).
        again.set_markers("fp-2", MARKERS)
        assert again.flush()
        assert len([h for h in again.hits() if h.fp == "fp-2"]) == len(first)
        assert len(_item_lines(folder)) == 2 * n_items
        assert len(coverage_file.read_text().splitlines()) == n_cov + n_items
    finally:
        again.close()


SSAID = "3f9a1c07deadbeef"
SSAID_MARKER = Marker(
    "android_id@com.fittrack.app", SSAID, kind="hex_id", label="Android ID"
)
GROWN = [*MARKERS, SSAID_MARKER]


def _ssaid_flow(flow_dir: Path, seq: int) -> dict:
    """A flow that sends the advertising ID and the per-app Android ID."""
    rec = _rec(seq, path=f"/v1/collect?aid={AD_ID}&ssaid={SSAID}")
    _write_flow(flow_dir, rec, _detail(rec["id"], req=b"{}"))
    return rec


def _spy_needles(monkeypatch) -> list[list[str]]:
    """The marker ids of every build_needles call of the scan service."""
    calls: list[list[str]] = []
    real = ps.build_needles

    def spy(markers):
        markers = list(markers)
        calls.append([m.id for m in markers])
        return real(markers)

    monkeypatch.setattr(ps, "build_needles", spy)
    return calls


def test_grown_marker_set_runs_a_delta_pass(svc, flow_dir, folder, monkeypatch):
    """Same fingerprint, more markers (the apply adds the per-app Android
    IDs): the flows and versions already scanned are rescanned for the new
    markers only, once, without duplicate records or timeline lines.
    """
    _ssaid_flow(flow_dir, 1)
    vdir = _version(PREFS, 1, {"ids.xml": f"<a>{AD_ID}</a><b>{SSAID}</b>".encode()})
    with timeline.capture() as lines:
        svc.set_markers(FP, MARKERS)  # the startup markers: no Android ID
        assert svc.flush()
        before = svc.hits()
        assert {h.marker_id for h in before} == {"ad_id"}
        n_lines = len(_privacy_lines(lines))
        n_items = len(_item_lines(folder))
        calls = _spy_needles(monkeypatch)
        svc.set_markers(FP, GROWN)  # the apply: same profile, more markers
        assert svc.flush()
    # The delta needles are built from the new marker only.
    assert calls[-1] == [SSAID_MARKER.id]
    hits = svc.hits()
    new = [h for h in hits if h.marker_id == SSAID_MARKER.id]
    assert {h.source["type"] for h in new} == {"flow", "file"}
    assert all(h.fp == FP and h.retro for h in new)
    assert len(hits) == len(before) + len(new)
    keys = [
        (h.source.get("flow_id"), h.source.get("version"), h.part, h.marker_id)
        + (h.transform,)
        for h in hits
    ]
    assert len(keys) == len(set(keys))
    # One timeline line per new finding, none again for the old ones.
    added = _privacy_lines(lines)[n_lines:]
    assert sorted(line["kind"] for line in added) == ["sent", "stored"]
    assert {line["data"]["marker_id"] for line in added} == {SSAID_MARKER.id}
    # The header counts include the delta's findings (same fingerprint).
    summary = svc.summary()
    assert summary.values_found == 2
    assert summary.hits_total == len(hits)
    # Each item got one delta line naming a set of only the new marker.
    delta = _item_lines(folder)[n_items:]
    assert sorted(c["key"] for c in delta) == [
        f"file:{PREFS}@{vdir.name}",
        "flow:f1",
    ]
    assert all(c["delta"] and c["fp"] == FP for c in delta)
    defined = {
        c["set"]: c["markers"] for c in _coverage(folder) if c["skip"] == "markers"
    }
    assert len(defined[delta[0]["set"]]) == 1

    # A rescan of the same version (coverage dropped) records nothing twice.
    with svc._lock:
        svc._covered.discard((f"file:{PREFS}@{vdir.name}", FP, ps.ENGINE_VERSION))
    with timeline.capture() as again_lines:
        svc.submit_version(PREFS, vdir, None)
        assert svc.flush()
    assert len(svc.hits()) == len(hits)
    assert _privacy_lines(again_lines) == []

    # A restart loads the ledger: neither the startup markers nor the apply
    # repeat the finished delta pass.
    n_cov = len(_coverage(folder))
    fresh = ps.PrivacyScanService(
        folder_fn=lambda: folder, flow_dir_fn=lambda: flow_dir
    )
    try:
        fresh.set_markers(FP, MARKERS)
        assert fresh.flush()
        fresh.set_markers(FP, GROWN)
        assert fresh.flush()
        assert len(fresh.hits()) == len(svc.hits())
        assert len(_coverage(folder)) == n_cov
    finally:
        fresh.close()


def test_restart_then_apply_rescans_flows_seen_with_the_startup_markers(
    folder, flow_dir
):
    """The reported case: after a restart the startup markers lack the
    recorded Android IDs; flows captured until the apply are rescanned for
    them, flows scanned with them before the restart are not.
    """
    first = ps.PrivacyScanService(
        folder_fn=lambda: folder, flow_dir_fn=lambda: flow_dir
    )
    try:
        _ssaid_flow(flow_dir, 1)
        first.set_markers(FP, GROWN)
        assert first.flush()
        assert SSAID_MARKER.id in {h.marker_id for h in first.hits_for_flow("f1")}
        n_f1 = len(first.hits_for_flow("f1"))
    finally:
        first.close()
    n_items = len(_item_lines(folder))
    svc = ps.PrivacyScanService(folder_fn=lambda: folder, flow_dir_fn=lambda: flow_dir)
    try:
        svc.set_markers(FP, MARKERS)  # startup_markers(profile)
        assert svc.flush()
        rec = _ssaid_flow(flow_dir, 2)
        svc.submit_flow(rec, flow_dir, 2)  # live, before the apply
        assert svc.flush()
        assert {h.marker_id for h in svc.hits_for_flow("f2")} == {"ad_id"}
        svc.set_markers(FP, GROWN)  # the apply: same fingerprint
        assert svc.flush()
        assert {h.marker_id for h in svc.hits_for_flow("f2")} == {
            "ad_id",
            SSAID_MARKER.id,
        }
        assert len(svc.hits_for_flow("f1")) == n_f1
        lines = _item_lines(folder)[n_items:]
        assert [(c["key"], bool(c.get("delta"))) for c in lines] == [
            ("flow:f2", False),
            ("flow:f2", True),
        ]
    finally:
        svc.close()


def test_changed_marker_value_runs_a_delta_pass(svc, flow_dir, folder, monkeypatch):
    old = Marker(SSAID_MARKER.id, "0123456789abcdef", kind="hex_id", label="AID")
    _ssaid_flow(flow_dir, 1)
    svc.set_markers(FP, [*MARKERS, old])
    assert svc.flush()
    assert SSAID_MARKER.id not in {h.marker_id for h in svc.hits()}
    calls = _spy_needles(monkeypatch)
    svc.set_markers(FP, GROWN)  # the same marker id, a new value
    assert svc.flush()
    assert calls[-1] == [SSAID_MARKER.id]
    assert SSAID_MARKER.id in {h.marker_id for h in svc.hits_for_flow("f1")}
    assert [c["key"] for c in _item_lines(folder) if c.get("delta")] == ["flow:f1"]


def test_removed_markers_are_not_rescanned(svc, flow_dir, folder):
    """Fewer markers under the same fingerprint: no rescan, the removed
    markers are no longer looked for; adding them back rescans only what
    was scanned without them.
    """
    _ssaid_flow(flow_dir, 1)
    svc.set_markers(FP, GROWN)
    assert svc.flush()
    n_hits = len(svc.hits())
    n_cov = len(_coverage(folder))
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    assert len(svc.hits()) == n_hits
    assert len(_coverage(folder)) == n_cov
    assert SSAID_MARKER.id not in svc._markers
    rec = _ssaid_flow(flow_dir, 2)
    svc.submit_flow(rec, flow_dir, 2)
    assert svc.flush()
    assert {h.marker_id for h in svc.hits_for_flow("f2")} == {"ad_id"}
    n_items = len(_item_lines(folder))
    svc.set_markers(FP, GROWN)
    assert svc.flush()
    assert [c["key"] for c in _item_lines(folder)[n_items:]] == ["flow:f2"]
    assert SSAID_MARKER.id in {h.marker_id for h in svc.hits_for_flow("f2")}


def test_older_ledger_lines_cover_every_marker(folder, flow_dir):
    """A coverage line without a marker set (written before sets were
    recorded) still means: scanned for that fingerprint, no rescan.
    """
    _ssaid_flow(flow_dir, 1)
    privacy = folder / "privacy"
    privacy.mkdir(parents=True)
    legacy = {
        "v": 1,
        "at": 1.0,
        "key": "flow:f1",
        "fp": FP,
        "engine": ps.ENGINE_VERSION,
        "skip": None,
        "retro": True,
    }
    (privacy / "coverage.jsonl").write_text(json.dumps(legacy) + "\n")
    svc = ps.PrivacyScanService(folder_fn=lambda: folder, flow_dir_fn=lambda: flow_dir)
    try:
        svc.set_markers(FP, MARKERS)
        assert svc.flush()
        svc.set_markers(FP, GROWN)
        assert svc.flush()
        assert svc.hits() == []
        assert _coverage(folder) == [legacy]
    finally:
        svc.close()


SSAID_B = "5c0ffee0b0b0cafe"


def test_renamed_marker_ids_across_two_applies(svc, flow_dir, folder, monkeypatch):
    """Older apply records named the applied app's Android ID ``android_id``
    and the others ``android_id@<pkg>``: an apply for app B renames A's
    marker. Coverage and findings follow the value, not the id: A's value
    is not recorded again, B's value is found in a flow that also holds A's
    (whose old hit has B's new id), and the timeline gets one line for B.
    """
    rec = _rec(1, path=f"/c?a={SSAID}&b={SSAID_B}")
    _write_flow(flow_dir, rec, _detail("f1", req=b"{}"))
    apply_a = [*MARKERS, Marker("android_id", SSAID, kind="hex_id", label="AID")]
    apply_b = [
        *MARKERS,
        Marker("android_id", SSAID_B, kind="hex_id", label="AID"),
        Marker("android_id@a", SSAID, kind="hex_id", label="AID (a)"),
    ]
    with timeline.capture() as lines:
        svc.set_markers(FP, apply_a)
        assert svc.flush()
        first = svc.hits_for_flow("f1")
        n_lines = len(_privacy_lines(lines))
        calls = _spy_needles(monkeypatch)
        svc.set_markers(FP, apply_b)
        assert svc.flush()
    # Only B's value was new: the delta looked for it alone.
    assert calls[-1] == ["android_id"]
    hits = svc.hits_for_flow("f1")
    values = sorted(h.snippet[1] for h in hits if h.marker_id.startswith("android"))
    assert values == sorted([SSAID, SSAID_B])
    assert len(hits) == len(first) + 1
    assert len({(h.part, h.value_key, h.transform) for h in hits}) == len(hits)
    added = _privacy_lines(lines)[n_lines:]
    assert len(added) == 1
    assert added[0]["data"]["marker_id"] == "android_id"
    # The header counts the seeded values, each once.
    summary = svc.summary()
    assert (summary.values_total, summary.values_found) == (5, 2)
    # Back to the first naming: nothing is new.
    n_cov = len(_coverage(folder))
    svc.set_markers(FP, apply_a + [Marker("android_id@b", SSAID_B, kind="hex_id")])
    assert svc.flush()
    assert len(svc.hits_for_flow("f1")) == len(hits)
    assert len(_coverage(folder)) == n_cov


def test_coverage_shares_one_marker_set_per_item(svc, flow_dir, folder):
    """Each covered item keeps the (shared) digests of the marker sets it
    was scanned for, not a copy of the markers; a reload shares them too.
    """
    for seq in (1, 2, 3):
        _ssaid_flow(flow_dir, seq)
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    svc.set_markers(FP, GROWN)
    assert svc.flush()

    def sets(service) -> list[tuple[str, ...]]:
        keys = [(f"flow:f{i}", FP, ps.ENGINE_VERSION) for i in (1, 2, 3)]
        return [service._covered_markers[key] for key in keys]

    first = sets(svc)
    assert all(len(names) == 2 for names in first)
    assert all(isinstance(n, str) for names in first for n in names)
    for names in first[1:]:
        assert all(a is b for a, b in zip(names, first[0], strict=True))
    fresh = ps.PrivacyScanService(
        folder_fn=lambda: folder, flow_dir_fn=lambda: flow_dir
    )
    try:
        fresh.load_session(folder)
        loaded = sets(fresh)
        assert loaded == first
        for names in loaded[1:]:
            assert all(a is b for a, b in zip(names, loaded[0], strict=True))
    finally:
        fresh.close()


def test_sweep_items_keep_no_marker_sets(svc, folder):
    item = ps._SweepItem(
        build_needles(MARKERS), FP, 0.0, mset="abc", sweep_id="s", member="m"
    )
    svc._folder = folder
    svc._ledger(item)
    entry = (item.key(), FP, ps.ENGINE_VERSION)
    assert entry in svc._covered
    assert entry not in svc._covered_markers


def test_older_line_plus_set_line_still_covers_every_marker(folder, flow_dir):
    """An item with an older (set-less) line stays covered for every marker,
    whichever order its lines come in.
    """
    _ssaid_flow(flow_dir, 1)
    _ssaid_flow(flow_dir, 2)
    small = ps._set_digest({ps._marker_digest(MARKERS[0])})
    base = {"v": 1, "at": 1.0, "fp": FP, "engine": ps.ENGINE_VERSION, "skip": None}
    lines = [
        {**base, "key": f"markers:{small}", "skip": "markers", "set": small,
         "markers": [ps._marker_digest(MARKERS[0])]},
        {**base, "key": "flow:f1"},
        {**base, "key": "flow:f1", "set": small},
        {**base, "key": "flow:f2", "set": small},
        {**base, "key": "flow:f2"},
    ]  # fmt: skip
    (folder / "privacy").mkdir(parents=True)
    (folder / "privacy" / "coverage.jsonl").write_text(
        "".join(json.dumps(line) + "\n" for line in lines)
    )
    svc = ps.PrivacyScanService(folder_fn=lambda: folder, flow_dir_fn=lambda: flow_dir)
    try:
        svc.set_markers(FP, GROWN)
        assert svc.flush()
        assert svc.hits() == []
        assert len(_coverage(folder)) == len(lines)
    finally:
        svc.close()
    covered: set = set()
    names: dict = {}
    entry = ("flow:f3", FP, 1)
    ps._note_cover(covered, names, entry, "s1")
    ps._note_cover(covered, names, entry, None)
    ps._note_cover(covered, names, entry, "s2")
    assert entry in covered
    assert entry not in names


def test_delta_pass_scans_whole_marker_groups(svc, flow_dir, monkeypatch):
    """A changed latitude is rescanned with its longitude, so the pair's
    proximity boost still applies; the longitude is not recorded again.
    """
    rec = _rec(1, path="/geo?ll=52.5200,13.4050")  # 4 places: medium alone
    _write_flow(flow_dir, rec, _detail("f1", req=b"{}"))
    old_lat = Marker("lat", "48.137154", kind="latitude", group="gps", tag="GPS")
    svc.set_markers(FP, [MARKERS[0], MARKERS[1], old_lat, MARKERS[3]])
    assert svc.flush()
    lon_hits = [h for h in svc.hits_for_flow("f1") if h.marker_id == "lon"]
    assert lon_hits
    calls = _spy_needles(monkeypatch)
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    assert sorted(calls[-1]) == ["lat", "lon"]
    hits = svc.hits_for_flow("f1")
    assert [h for h in hits if h.marker_id == "lon"] == lon_hits
    lat = [h for h in hits if h.marker_id == "lat"]
    assert lat
    assert {h.confidence for h in lat} == {"high"}  # boosted by the pair


def test_read_hits_and_run_hits(svc, flow_dir, folder, tmp_path):
    _standard_flow(flow_dir)
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    records, scanned = ps.read_hits(folder)
    assert scanned
    assert [r.to_json() for r in records] == [h.to_json() for h in svc.hits()]
    assert ps.read_hits(tmp_path / "nowhere") == ([], False)
    t = 1_700_000_001.0
    assert ps.run_hits(records, ps.run_scope(None, (t - 1, t + 1))) == records
    assert ps.run_hits(records, ps.run_scope("run-x", (0, 1))) == []
    # The recording window the run replays counts too.
    both = ps.run_scope("run-x", (0, 1), record=(t - 1, t + 1))
    assert ps.run_hits(records, both) == records


# ------------------------------------------------------------ session switch


def _session_with_hits(folder: Path, flow_dir: Path) -> int:
    service = ps.PrivacyScanService(
        folder_fn=lambda: folder, flow_dir_fn=lambda: flow_dir
    )
    try:
        _standard_flow(flow_dir)
        service.set_markers(FP, MARKERS)
        assert service.flush()
        return len(service.hits())
    finally:
        service.close()


def test_switch_folder_loads_stored_findings_without_a_profile(tmp_path, flow_dir):
    """Identity mode off: a resumed session's findings still show, and a new
    session drops them at once (hits, summary, flow folder).
    """
    old, new = tmp_path / "old", tmp_path / "new"
    n = _session_with_hits(old, flow_dir)
    current = {"folder": old}
    service = ps.PrivacyScanService(folder_fn=lambda: current["folder"])
    resets: list = []
    service.add_listener(resets.append)
    try:
        service.switch_folder()  # startup: no profile, no submit, still loads
        assert service.flush()
        assert len(service.hits()) == n
        assert service.has_hits()
        assert service.folder == old
        assert resets == [None]
        assert not service.is_active
        assert wait_for(lambda: service._thread is None)  # idle worker ends
        rev = service.revision
        service._flow_dir = flow_dir
        current["folder"] = new
        service.switch_folder(new)  # the "bound" doorbell
        # Dropped at once, before the worker reads the new folder.
        assert service.hits() == []
        assert not service.has_hits()
        assert service._flow_dir is None
        assert service.revision > rev
        assert service.flush()
        assert service.folder == new
        assert service.hits() == []
        assert service.summary().hits_total == 0
        assert resets[-1] is None
        # Switching back reads the old session again.
        current["folder"] = old
        service.switch_folder(old)
        assert service.flush()
        assert len(service.hits()) == n
    finally:
        service.close()


def test_switch_folder_resets_the_summary_and_retro_scans_the_new_session(
    tmp_path, flow_dir, monkeypatch
):
    """With a profile active the header counts restart in the new session,
    and the previous session's flow folder is not retro-scanned into it.
    """
    old, new = tmp_path / "old", tmp_path / "new"
    current = {"folder": old}
    monkeypatch.setattr(ps, "_default_flow_dir", lambda: None)
    service = ps.PrivacyScanService(folder_fn=lambda: current["folder"])
    try:
        service.set_markers(FP, MARKERS)
        assert service.flush()
        rec = _standard_flow(flow_dir)
        service.submit_flow(rec, flow_dir, 1)  # caches the old flow folder
        assert service.flush()
        assert service.summary().values_found == 2
        current["folder"] = new
        service.switch_folder(new)
        assert service.summary().values_found == 0
        assert service.flush()
        assert service.summary().values_found == 0
        assert service.hits() == []
        assert not (new / "privacy" / "hits.jsonl").exists()
    finally:
        service.close()


def test_timeline_bound_doorbell_switches_the_folder(monkeypatch, tmp_path):
    from sandroid.core.events import Event, EventType

    calls: list = []

    class Fake:
        def switch_folder(self, folder=None):
            calls.append(folder)

    monkeypatch.setattr(ps, "_existing_service", lambda: None)
    bound = {"op": "bound", "folder": str(tmp_path), "active": True}
    ps._on_timeline_event(Event(EventType.TIMELINE_EVENT, bound))  # no service
    monkeypatch.setattr(ps, "_existing_service", lambda: Fake())
    ps._on_timeline_event(Event(EventType.TIMELINE_EVENT, bound))
    ps._on_timeline_event(Event(EventType.TIMELINE_EVENT, {"op": "lines"}))
    ps._on_timeline_event(Event(EventType.TIMELINE_EVENT, {**bound, "active": False}))
    assert calls == [str(tmp_path)]
    # Through the bus, as the timeline writer rings it (subscribed once).
    from sandroid.core.events import EventBus

    ps._subscribe_timeline(True)
    ps._subscribe_timeline(True)
    try:
        EventBus.get().publish(Event(EventType.TIMELINE_EVENT, bound))
    finally:
        ps._subscribe_timeline(False)
    EventBus.get().publish(Event(EventType.TIMELINE_EVENT, bound))
    assert calls == [str(tmp_path)] * 2


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
            out = []
            # /data/user/0/<pkg> is the same folder as /data/data/<pkg>: the
            # extraction service pulls it twice.
            for root, sub in (("/data/data", "data_data_pkg"), ("/data/user/0", "u0")):
                base = Path(output_dir) / "stamp" / sub
                base.mkdir(parents=True)
                for name, data in (("prefs.xml", EMAIL.encode()), ("cache.bin", b"0")):
                    (base / name).write_bytes(data)
                    out.append(
                        ExtractionResult(
                            source_path=f"{root}/{package}/{name}",
                            local_path=str(base / name),
                            success=True,
                        )
                    )
            return out

    monkeypatch.setattr(services, "get_file_extraction_service", FakeFx)
    svc.set_markers(FP, MARKERS)
    assert svc.flush()
    with timeline.capture() as lines:
        assert (
            ps.sweep_after_run(
                "com.fittrack.app", "emulator-test", run_id="20260101_000000_abcdef"
            )
            is False
        )  # another service is the singleton: not active
        svc.sweep_app_data("emulator-test", "com.fittrack.app", run_id="run-7")
        assert wait_for(lambda: svc.hits())
        assert svc.flush()
    (hit,) = svc.hits()
    assert hit.device_path == "/data/data/com.fittrack.app/prefs.xml"
    assert hit.source["version"].startswith("sweep:com.fittrack.app_")
    # Found after the run's end, still the run's: it carries the run id.
    assert hit.source["run_id"] == "run-7"
    assert svc.hits_between(0, 1) == []
    assert svc.hits_for_run(ps.run_scope("run-7", (0, 1))) == [hit]
    assert svc.hits_for_run(ps.run_scope("run-8", (0, 1))) == []
    (line,) = _privacy_lines(lines)
    assert line["data"]["run_id"] == "run-7"
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


def test_sweep_after_run_passes_the_run_id(monkeypatch):
    calls: list = []

    class Fake:
        is_active = True

        def sweep_app_data(self, serial, package, *, run_id=None):
            calls.append((serial, package, run_id))
            thread = threading.Thread(target=lambda: None)
            thread.start()
            return thread

    monkeypatch.setattr(ps, "get_privacy_scan_service", lambda: Fake())
    assert ps.sweep_after_run("com.a", "emulator-5", run_id="r1")
    assert calls == [("emulator-5", "com.a", "r1")]


def test_sweep_after_run_waits_for_the_pulls_and_the_scans(monkeypatch):
    """The Play waits for its sweep before it seals the run report."""
    done = threading.Event()
    flushed: list[float] = []

    class Fake:
        is_active = True

        def sweep_app_data(self, serial, package, *, run_id=None):
            thread = threading.Thread(target=lambda: (time.sleep(0.2), done.set()))
            thread.start()
            return thread

        def flush(self, timeout):
            flushed.append(timeout)
            return True

    monkeypatch.setattr(ps, "get_privacy_scan_service", lambda: Fake())
    assert ps.sweep_after_run("com.a", "emulator-5", run_id="r1", wait=5.0)
    assert done.is_set()
    assert flushed
    assert 0 < flushed[0] <= 5.0


def test_listener_runs_on_the_worker(svc, flow_dir):
    seen: list[tuple[str, str]] = []
    svc.add_listener(
        lambda rec: seen.append(
            (threading.current_thread().name, rec.part if rec else "reset")
        )
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


def test_attach_identity_reads_the_markers_off_the_calling_thread(svc, monkeypatch):
    """Startup (UI thread): the first marker read is file I/O, so it runs on
    a thread; the identity service's notification turns the scan on.
    """
    import threading

    from sandroid.services import identity

    calls: list = []

    class _Identity:
        def __init__(self) -> None:
            self.listeners: list = []

        def add_markers_listener(self, cb) -> None:
            self.listeners.append(cb)

        def active_markers(self, *, load=True):
            calls.append((load, threading.current_thread().name))
            if not load:
                return None
            for cb in self.listeners:
                cb(FP, MARKERS)
            return FP, MARKERS

    fake = _Identity()
    monkeypatch.setattr(identity, "get_identity_service", lambda: fake)
    assert svc.attach_identity()
    assert wait_for(lambda: svc.is_active)
    assert svc.fingerprint == FP
    me = threading.current_thread().name
    assert calls[0] == (False, me)
    assert calls[1][0] is True
    assert calls[1][1] != me


def test_has_versions_knows_pulled_files_without_io(svc, folder, flow_dir):
    """The Files lens asks whether an unstarred file has kept versions."""
    assert not svc.has_versions(PREFS)
    v1 = _version(PREFS, 1, {"ids.xml": f"<string>{AD_ID}</string>".encode()})
    svc.submit_version(PREFS, v1, 1)  # no markers yet: still a pulled file
    assert svc.has_versions(PREFS.replace("/data/data/", "/data/user/0/"))
    svc.set_markers(FP, MARKERS)
    svc.submit_version(PREFS, v1, 1)
    assert svc.flush()
    # A restart reads the coverage ledger of the session.
    again = ps.PrivacyScanService(
        folder_fn=lambda: folder, flow_dir_fn=lambda: flow_dir
    )
    try:
        again.load_session(folder)
        assert wait_for(lambda: again.has_versions(PREFS))
        assert not again.has_versions("/data/data/com.fittrack.app/other.xml")
    finally:
        again.close()


def test_close_never_joins_a_worker_that_has_not_started():
    """close() racing the worker start: it joins a started thread or none."""
    for _ in range(200):
        service = ps.PrivacyScanService()
        starter = threading.Thread(target=service._ensure_worker)
        starter.start()
        service.close(timeout=1.0)  # must not raise "cannot join thread..."
        starter.join()
        service.close(timeout=1.0)
        thread = service._thread
        assert thread is None or thread.ident is not None
