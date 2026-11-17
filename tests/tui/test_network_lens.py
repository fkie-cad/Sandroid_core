"""Network lens (phase B): flow table, filters, Inspector, TLS badge, scope.

Hermetic: the flow log is a fixture ``flows.jsonl`` in ``tmp_path`` (the
lens's ``_flow_dir`` is patched to it); no mitmweb process is started and the
suite-wide conftest blocks every device access.
"""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime
from typing import TYPE_CHECKING

import pytest

from sandroid.tui.widgets import network_panel as np_mod
from sandroid.tui.widgets.network_panel import (
    STATUS_KEY,
    FlowRow,
    NetworkPanel,
    body_renderable,
    is_noise,
    recipient_of,
    smart_request,
)

if TYPE_CHECKING:
    from pathlib import Path

SIZE = (160, 45)
PKG = "de.fittrack.pro"


# --------------------------------------------------------------------------
# fixture flow log
# --------------------------------------------------------------------------


def _body(content) -> dict:
    if content is None:
        return {"content": "", "encoding": "utf-8", "size_bytes": 0, "bytes_read": 0}
    raw = content if isinstance(content, bytes) else content.encode()
    try:
        text, enc = raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        text, enc = base64.b64encode(raw).decode(), "base64"
    return {
        "content": text,
        "encoding": enc,
        "truncated": False,
        "size_bytes": len(raw),
        "bytes_read": len(raw),
    }


_SPECS = [
    # (method, host, path, status, app, request body, response body, error)
    (
        "GET",
        "connectivitycheck.gstatic.com",
        "/generate_204",
        204,
        "",
        None,
        None,
        None,
    ),
    (
        "POST",
        "graph.facebook.com",
        "/v19.0/218934/activities",
        200,
        PKG,
        "event=MOBILE_APP_INSTALL&advertiser_id=3b9f",
        '{"success": true}',
        None,
    ),
    ("GET", "api.fittrack.de", "/v2/profile", 200, PKG, None, '{"id": 88213}', None),
    ("POST", "app-measurement.com", "/a", 204, PKG, b"\x0a\x8c\xff\x00", None, None),
    (
        "POST",
        "play.googleapis.com",
        "/log/batch",
        200,
        "com.google.android.gms",
        None,
        None,
        None,
    ),
    (
        "POST",
        "stats.fittrack.de",
        "/collect",
        None,
        PKG,
        '{"e": 1}',
        None,
        "Connection reset by peer",
    ),
    (
        "GET",
        "cdn.other-app.com",
        "/x.png",
        200,
        "com.other.app",
        None,
        b"\x89PNG\x00",
        None,
    ),
]


def write_flows(
    flow_dir: Path, base: float, specs=None, start_seq: int = 1
) -> list[dict]:
    """Append fixture records (one every 10 s from ``base``) + detail files."""
    flow_dir.mkdir(parents=True, exist_ok=True)
    (flow_dir / "details").mkdir(exist_ok=True)
    records = []
    with open(flow_dir / "flows.jsonl", "a", encoding="utf-8") as f:
        for i, spec in enumerate(specs or _SPECS):
            method, host, path, status, app, req, resp, error = spec
            seq = start_seq + i
            rec = {
                "seq": seq,
                "id": f"flow-{seq}",
                "ts_start": base + i * 10,
                "ts_end": base + i * 10 + 0.2,
                "protocol": "HTTPS/2",
                "method": method,
                "host": host,
                "path": path,
                "status_code": status,
                "error": error,
                "request_bytes": _body(req)["size_bytes"],
                "response_bytes": None if status is None else _body(resp)["size_bytes"],
                "app": app,
                "request_content_type": (
                    "application/x-www-form-urlencoded"
                    if req and "=" in str(req)
                    else None
                ),
                "response_content_type": "application/json"
                if resp and str(resp).startswith("{")
                else None,
            }
            f.write(json.dumps(rec) + "\n")
            (flow_dir / "details" / f"flow-{seq}.json").write_text(
                json.dumps(
                    {
                        "id": rec["id"],
                        "request_headers": [
                            ["host", host],
                            ["user-agent", "FitTrack/4.12"],
                        ],
                        "response_headers": [["content-type", "application/json"]],
                        "request_body": _body(req),
                        "response_body": _body(resp),
                        "error": error,
                    }
                )
            )
            records.append(rec)
    (flow_dir / "meta.json").write_text(
        json.dumps(
            {
                "earliest_seq": 1,
                "latest_seq": records[-1]["seq"],
                "total_flows_lifetime": records[-1]["seq"],
                "generation": 0,
            }
        )
    )
    return records


@pytest.fixture
def flow_dir(tmp_path, monkeypatch):
    d = tmp_path / "mitm_flows"
    d.mkdir()
    monkeypatch.setattr(np_mod, "_flow_dir", lambda: d)
    monkeypatch.setattr(NetworkPanel, "_spotlight_package", lambda self: PKG)
    return d


# --------------------------------------------------------------------------
# pure helpers
# --------------------------------------------------------------------------


def test_recipient_labels():
    assert recipient_of("graph.facebook.com") == ("Meta", True)
    assert recipient_of("app-measurement.com") == ("Google Analytics", True)
    assert recipient_of("launches.appsflyer.com") == ("AppsFlyer", True)
    assert recipient_of("api.fittrack.de") == ("fittrack.de", False)
    assert recipient_of("a.b.example.co.uk") == ("example.co.uk", False)


def test_noise_rules():
    assert is_noise("connectivitycheck.gstatic.com", "/generate_204", "")
    assert is_noise("play.googleapis.com", "/log/batch", "")
    assert is_noise("example.org", "/x", "com.google.android.gms")
    assert is_noise("www.google.com", "/gen_204?x=1", "")
    assert not is_noise("api.fittrack.de", "/v2/profile", PKG)
    # the spotlight app's own traffic is never noise
    assert not is_noise("play.googleapis.com", "/log", PKG, focus_app=PKG)


def test_smart_request_truncates_middle_segments():
    long_path = "/v2/activities/88213/summary/details?include=everything&x=1"
    text = smart_request("GET", "api.fittrack.de", long_path, 40)
    assert len(text.plain) <= 40
    assert text.plain.startswith("GET api.fittrack.de/")
    assert text.plain.endswith("…/details")
    full = smart_request("POST", "a.io", "/x", 40)
    assert full.plain == "POST a.io/x"


def test_body_renderable_json_form_and_binary():
    from rich.console import Console

    def plain(r) -> str:
        console = Console(width=80, record=True, color_system=None)
        console.print(r)
        return console.export_text()

    out = plain(body_renderable(_body('{"a": {"b": 1}}'), "application/json"))
    assert '"b": 1' in out
    assert "\n" in out.strip()
    out = plain(
        body_renderable(_body("x=1&y=two"), "application/x-www-form-urlencoded")
    )
    assert "x" in out
    assert "two" in out
    out = plain(body_renderable(_body(b"\x89PNG\x00\xff"), "image/png"))
    assert "binary" in out
    assert "89 50 4e 47" in out
    assert "empty" in plain(body_renderable(_body(None), None))


def test_fetch_new_is_cursor_based_and_cheap_when_idle(flow_dir):
    panel = NetworkPanel()
    write_flows(flow_dir, time.time() - 100)
    res = panel.fetch_new(None, None, None)
    assert res is not None
    _dir, records, cursor, stat, reset = res
    assert len(records) == len(_SPECS)
    assert cursor == len(_SPECS)
    assert not reset
    # unchanged file: nothing read
    assert panel.fetch_new(cursor, flow_dir, stat) is None
    # appended flows: only the new ones
    write_flows(flow_dir, time.time(), specs=_SPECS[:2], start_seq=cursor + 1)
    res2 = panel.fetch_new(cursor, flow_dir, stat)
    assert [r["seq"] for r in res2[1]] == [cursor + 1, cursor + 2]


def write_run(run_dir: Path, start: float, end: float, label: str = "") -> Path:
    """A minimal but complete ``run.json`` (what ``run_history`` loads)."""
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "run_id": run_dir.name,
                "label": label,
                "recorded_at": datetime.fromtimestamp(start).isoformat(),
                "completed_at": datetime.fromtimestamp(end).isoformat(),
                "device_name": "demo",
                "recording_path": "",
                "duration": int(end - start),
                "bundle_dir": str(run_dir),
            }
        )
    )
    return run_dir


def test_run_window_uses_the_shared_run_history_resolver(tmp_path):
    t0 = datetime(2026, 11, 17, 10, 0, 0).timestamp()
    run = write_run(tmp_path / "runs" / "r1", t0, t0 + 60, label="Run 7")
    label, start, end = np_mod._run_window(str(run))
    assert label == "Run 7"
    assert start == pytest.approx(t0)
    assert end - start == pytest.approx(60)
    assert np_mod._run_window(str(tmp_path / "nope")) is None


# --------------------------------------------------------------------------
# mounted lens
# --------------------------------------------------------------------------


async def _settle(pilot, n: int = 4) -> None:
    for _ in range(n):
        await pilot.pause(0.05)


async def _boot(app, pilot):
    await _settle(pilot, 8)
    if type(app.screen).__name__ != "MainScreen":
        await pilot.press("enter")
        await _settle(pilot, 4)
    assert type(app.screen).__name__ == "MainScreen"
    return app.screen


async def _wait(pilot, cond, timeout: float = 4.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return
        await pilot.pause(0.05)
    assert cond()


def _app():
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


async def _lens_with_flows(app, pilot, flow_dir, base=None):
    ms = await _boot(app, pilot)
    await pilot.press("2")
    await _settle(pilot)
    panel = ms.query_one("#network-panel", NetworkPanel)
    write_flows(flow_dir, base if base is not None else time.time() - 100)
    panel.poll_now()
    await _wait(pilot, lambda: panel.table.row_count > 0)
    return ms, panel


async def test_empty_state_and_enter_starts_mitm(flow_dir, monkeypatch):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await _boot(app, pilot)
        await pilot.press("2")
        await _settle(pilot)
        panel = ms.query_one("#network-panel", NetworkPanel)
        head = str(panel.query_one("#net-empty-head").render())
        assert "No flows yet" in head
        assert panel.table.has_class("-empty")
        calls = []
        monkeypatch.setattr(
            panel.mitm, "action_toggle_running", lambda: calls.append("toggle")
        )
        assert app.focused is panel
        await pilot.press("enter")
        await _settle(pilot)
        assert calls == ["toggle"]


async def test_flows_fill_the_table_noise_hidden(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        total = len(_SPECS)
        # connectivity check + gms batch are OS noise
        assert panel.table.row_count == total - 2
        assert len(panel.table.columns) == 5
        _title, info = ms._lens_captions["network"]
        assert f"{total - 2} of {total}" in info
        # newest row is selected (tail-follow)
        assert panel.table.cursor_row == panel.table.row_count - 1
        await pilot.press("N")
        await _settle(pilot)
        assert panel.table.row_count == total
        # error row shows a ✗ marker
        cells = [
            str(panel.table.get_row_at(i)[3]) for i in range(panel.table.row_count)
        ]
        assert any(c.startswith("✗") for c in cells)


async def test_new_rows_do_not_yank_a_moved_cursor(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        panel.table.move_cursor(row=0)
        await _settle(pilot)
        count = panel.table.row_count
        write_flows(flow_dir, time.time(), specs=_SPECS[1:3], start_seq=100)
        panel.poll_now()
        await _wait(pilot, lambda: panel.table.row_count == count + 2)
        assert panel.table.cursor_row == 0


async def test_filter_and_app_only(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        await pilot.press("slash")
        await _settle(pilot)
        for ch in "facebook":
            await pilot.press(ch)
        await pilot.press("enter")
        await _wait(pilot, lambda: panel.table.row_count == 1)
        assert "facebook" in ms._lens_captions["network"][1]
        panel.set_filter("")
        await _settle(pilot)
        await pilot.press("N")  # show everything, then narrow to the app
        await pilot.press("v")
        await _settle(pilot)
        apps = {
            panel._row_by_key(
                panel.table.coordinate_to_cell_key((i, 0)).row_key.value
            ).app
            for i in range(panel.table.row_count)
        }
        assert apps == {PKG}
        assert "app only" in ms._lens_captions["network"][1]


async def test_enter_opens_inspector_with_tabs(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        panel.set_filter("facebook")
        await _settle(pilot)
        panel.table.focus()
        await pilot.press("enter")
        await _settle(pilot)
        assert ms.inspector_is_open
        content = ms.inspector_content
        assert [name for name, _ in content.tabs] == ["Summary", "Request", "Response"]
        assert content.key == "network:row:f2"
        assert content.lens == "network"
        # live rows arriving do not replace the open Inspector
        write_flows(flow_dir, time.time(), specs=_SPECS[2:3], start_seq=50)
        panel.poll_now()
        await _settle(pilot, 8)
        assert ms.inspector_content.key == "network:row:f2"


async def test_tls_failure_row_and_badge(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        await pilot.press("1")
        await _settle(pilot)
        panel.mitm._append_line("[TLS_FAIL]|10:00:00|api.revenuecat.com|cert|" + PKG)
        panel.mitm._append_line("[TLS_FAIL]|10:00:01|pinned.example.com|cert|" + PKG)
        await _settle(pilot)
        assert ms.query_one("#lens-bar").badge("network") == "⚑2"
        tls = [r for r in panel._live if r.kind == "tls"]
        assert [r.host for r in tls] == ["api.revenuecat.com", "pinned.example.com"]
        await pilot.press("2")
        await _settle(pilot)
        assert ms.query_one("#lens-bar").badge("network") is None
        last = panel.table.get_row_at(panel.table.row_count - 1)
        assert "✗ TLS" in str(last[3])
        content = panel.flow_content(tls[0])
        assert "pinning" in str(content.sections[1][1])


async def test_mitm_lines_go_to_the_activity_log(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await _boot(app, pilot)
        panel = ms.query_one("#network-panel", NetworkPanel)
        log = ms.query_one("#activity-log")
        panel.mitm._append_line(
            "[ERROR] device CANNOT reach mitmproxy at 10.0.2.2:8080"
        )
        await _settle(pilot)
        assert any(
            "mitm:" in line and "CANNOT reach" in line for line in log._plain_lines
        )
        assert "CANNOT reach" in panel.mitm.recent_lines[-1]


async def test_proxy_controls_stay_bound(flow_dir, monkeypatch):
    keys = {b.key: b.action for b in NetworkPanel.BINDINGS}
    for key in ("ctrl+d", "ctrl+n", "ctrl+p", "ctrl+r", "ctrl+a", "ctrl+o", "ctrl+v"):
        assert keys[key].startswith("mitm("), key
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        calls = []
        for name in ("toggle_device", "inject_ca", "manage_addons", "toggle_running"):
            monkeypatch.setattr(
                panel.mitm, f"action_{name}", lambda n=name: calls.append(n)
            )
        for key in ("ctrl+d", "ctrl+n", "ctrl+a", "M"):
            await pilot.press(key)
            await _settle(pilot, 2)
        assert calls == [
            "toggle_device",
            "inject_ca",
            "manage_addons",
            "toggle_running",
        ]
        await pilot.press("I")
        await _settle(pilot)
        assert ms.inspector_content.key == STATUS_KEY
        assert [n for n, _ in ms.inspector_content.tabs] == ["mitmproxy", "friTap"]


async def test_review_scope_filters_by_run_window(flow_dir, tmp_path):
    base = time.time() - 1000
    # window covers flows 3..5 (t = 20 s .. 40 s)
    run = write_run(tmp_path / "runs" / "20261117_100000_ab12cd", base + 19, base + 41)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir, base=base)
        live_rows = panel.table.row_count
        ms.set_scope(str(run), label="Run 3")
        await _wait(pilot, lambda: not panel._review_loading)
        await _settle(pilot)
        assert {r.seq for r in panel._review} == {3, 4, 5}
        title, info = ms._lens_captions["network"]
        assert "Run 3" in title
        assert "time window" in title
        # play.googleapis (seq 5) is noise -> 2 of 3 shown
        assert panel.table.row_count == 2
        assert "2 of 3" in info
        ms.set_scope(None)
        await _settle(pilot)
        assert panel.table.row_count == live_rows


async def test_review_scope_empty_and_unknown_runs(flow_dir, tmp_path):
    empty = write_run(tmp_path / "runs" / "r0", 1, 2, label="Run 1")
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        ms.set_scope(str(empty))  # label comes from run.json
        await _wait(pilot, lambda: not panel._review_loading)
        await _settle(pilot)
        assert panel.table.has_class("-empty")
        assert "No flows were captured during Run 1" in str(
            panel.query_one("#net-empty-head").render()
        )
        ms.set_scope(str(tmp_path / "missing"), label="Run 9")
        await _wait(pilot, lambda: not panel._review_loading)
        await _settle(pilot)
        assert "No flow data for Run 9" in str(
            panel.query_one("#net-empty-head").render()
        )


def test_flow_row_from_record_and_url():
    row = FlowRow.from_record(
        {
            "seq": 7,
            "id": "x",
            "ts_end": 10.0,
            "method": "GET",
            "host": "a.io",
            "path": "/p?q=1",
            "status_code": 200,
            "protocol": "HTTPS/2",
        },
        None,
    )
    assert row.key == "f7"
    assert row.url() == "https://a.io/p?q=1"
    assert not row.failed
