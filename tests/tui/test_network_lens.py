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
from pilot_helpers import boot, settle, until

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
                "response_content_type": (
                    "application/json" if resp and str(resp).startswith("{") else None
                ),
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
    # Labels come from Dexray Insight's tracker DB (the one intentional
    # change vs the old built-in table: unity3d.com is Unity, not Unity Ads).
    import sandroid.tui.widgets.network_panel as net

    if not net._insight_labeller():
        pytest.skip("Dexray Insight >= 2.0 not importable here (fallback table)")
    assert recipient_of("unity3d.com") == ("Unity", True)
    assert recipient_of("unityads.unity3d.com") == ("Unity Ads", True)


def test_recipient_labels_fall_through_hosts_insight_does_not_know(monkeypatch):
    import sandroid.tui.widgets.network_panel as net

    monkeypatch.setattr(net, "_INSIGHT_LABELLER", lambda host: None)
    assert recipient_of("graph.facebook.com") == ("Meta", True)
    assert recipient_of("api.fittrack.de") == ("fittrack.de", False)


def test_recipient_labels_fall_back_without_insight(monkeypatch):
    import sandroid.tui.widgets.network_panel as net

    monkeypatch.setattr(net, "_INSIGHT_LABELLER", False)
    assert recipient_of("graph.facebook.com") == ("Meta", True)
    assert recipient_of("x.unity3d.com") == ("Unity Ads", True)
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


def _app():
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


def _column(panel, key: str) -> list[str]:
    """The drawn cells of column ``key``, top to bottom (order-proof)."""
    table = panel.table
    return [
        str(table.get_cell_at((i, table.get_column_index(key))))
        for i in range(table.row_count)
    ]


async def _lens_with_flows(app, pilot, flow_dir, base=None):
    ms = await boot(app, pilot)
    await pilot.press("2")
    await settle(pilot)
    panel = ms.query_one("#network-panel", NetworkPanel)
    write_flows(flow_dir, base if base is not None else time.time() - 100)
    panel.poll_now()
    await until(pilot, lambda: panel.table.row_count > 0)
    return ms, panel


async def test_empty_state_and_space_starts_mitm(flow_dir, monkeypatch):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("2")
        await settle(pilot)
        panel = ms.query_one("#network-panel", NetworkPanel)
        head = str(panel.query_one("#net-empty-head").render())
        assert "No flows yet" in head
        assert panel.table.has_class("-empty")
        calls = []
        monkeypatch.setattr(
            panel.mitm, "action_toggle_running", lambda: calls.append("toggle")
        )
        assert app.focused is panel
        # Enter is "inspect" everywhere: with nothing captured it does nothing.
        await pilot.press("enter")
        await settle(pilot)
        assert calls == []
        assert not ms.inspector_is_open
        await pilot.press("space")
        await settle(pilot)
        assert calls == ["toggle"]
        # Space only starts: with mitmproxy running it stops nothing (M does).
        monkeypatch.setattr(panel.mitm, "is_running", lambda: True)
        await pilot.press("space")
        await settle(pilot)
        assert calls == ["toggle"]
        await pilot.press("M")
        await settle(pilot)
        assert calls == ["toggle", "toggle"]


async def test_space_starts_a_stopped_mitm_with_flows_listed(flow_dir, monkeypatch):
    """N3-B6: once flows exist Space still starts a stopped Mitmproxy; the
    footer offers "Start Mitmproxy" only while it is stopped.
    """
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        running = {"v": False}
        calls = []
        monkeypatch.setattr(panel.mitm, "is_running", lambda: running["v"])
        monkeypatch.setattr(
            panel.mitm, "action_toggle_running", lambda: calls.append("toggle")
        )
        panel._do_refresh_status()
        await settle(pilot)
        assert panel.check_action("start_mitm", ()) is True
        await pilot.press("space")
        await settle(pilot)
        assert calls == ["toggle"]
        running["v"] = True
        panel._do_refresh_status()
        await settle(pilot)
        assert panel.check_action("start_mitm", ()) is False
        await pilot.press("space")
        await settle(pilot)
        assert calls == ["toggle"]


async def test_flows_fill_the_table_noise_hidden(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        total = len(_SPECS)
        # connectivity check + gms batch are OS noise
        assert panel.table.row_count == total - 2
        assert [str(c.value) for c in panel.table.columns] == [
            "time",
            "app",
            "who",
            "req",
            "tls",
            "status",
            "size",
        ]
        _title, info = ms._lens_captions["network"]
        assert f"{total - 2} of {total}" in info
        # newest row is selected (tail-follow)
        assert panel.table.cursor_row == panel.table.row_count - 1
        await pilot.press("N")
        await settle(pilot)
        assert panel.table.row_count == total
        # an errored flow says so in words
        cells = _column(panel, "status")
        assert any(c.startswith("error") for c in cells)


async def test_new_rows_do_not_yank_a_moved_cursor(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        panel.table.move_cursor(row=0)
        await settle(pilot)
        count = panel.table.row_count
        write_flows(flow_dir, time.time(), specs=_SPECS[1:3], start_seq=100)
        panel.poll_now()
        await until(pilot, lambda: panel.table.row_count == count + 2)
        assert panel.table.cursor_row == 0


async def test_filter_and_app_only(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        await pilot.press("slash")
        await settle(pilot)
        for ch in "facebook":
            await pilot.press(ch)
        await pilot.press("enter")
        await until(pilot, lambda: panel.table.row_count == 1)
        assert "facebook" in ms._lens_captions["network"][1]
        panel.set_filter("")
        await settle(pilot)
        await pilot.press("N")  # show everything, then narrow to the app
        await pilot.press("v")  # v is only "review" (Runs lens) now: no-op
        await settle(pilot)
        assert "app only" not in ms._lens_captions["network"][1]
        await pilot.press("T")
        await settle(pilot)
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
        await settle(pilot)
        panel.table.focus()
        await pilot.press("enter")
        await settle(pilot)
        assert ms.inspector_is_open
        content = ms.inspector_content
        assert [name for name, _ in content.tabs] == ["Summary", "Request", "Response"]
        assert content.key == "network:row:f2"
        assert content.lens == "network"
        # live rows arriving do not replace the open Inspector
        write_flows(flow_dir, time.time(), specs=_SPECS[2:3], start_seq=50)
        panel.poll_now()
        await settle(pilot)
        assert ms.inspector_content.key == "network:row:f2"


async def test_a_late_flow_goes_to_its_start_time(flow_dir):
    """A flow is read when it finishes, a TLS failure at once: a long request
    that started before the failure still shows above it (time order).
    """
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        panel.mitm._append_line("[TLS_FAIL]|10:00:00|pinned.example.com|cert|" + PKG)
        await until(pilot, lambda: any(r.kind == "tls" for r in panel._live))
        count = panel.table.row_count
        late_host = _SPECS[1][1]
        write_flows(flow_dir, time.time() - 30, specs=_SPECS[1:2], start_seq=100)
        panel.poll_now()
        await until(pilot, lambda: panel.table.row_count == count + 1)
        stamps = [r.ts for r in panel._live]
        assert stamps == sorted(stamps)
        keys = [
            panel.table.coordinate_to_cell_key((i, 0))[0].value
            for i in range(count + 1)
        ]
        rows = [panel._row_by_key(k) for k in keys]
        assert rows[-1].kind == "tls"
        assert rows[-2].host == late_host
        assert rows[-2].kind != "tls"


async def test_a_late_flow_keeps_a_moved_cursor_on_its_flow(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        panel.table.move_cursor(row=1)
        await settle(pilot)
        key = panel._cursor_key()
        count = panel.table.row_count
        write_flows(flow_dir, time.time() - 200, specs=_SPECS[1:2], start_seq=100)
        panel.poll_now()
        await until(pilot, lambda: panel.table.row_count == count + 1)
        assert panel._cursor_key() == key


async def test_tls_failure_row_and_badge(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        await pilot.press("1")
        await settle(pilot)
        panel.mitm._append_line("[TLS_FAIL]|10:00:00|api.revenuecat.com|cert|" + PKG)
        panel.mitm._append_line("[TLS_FAIL]|10:00:01|pinned.example.com|cert|" + PKG)
        await settle(pilot)
        assert ms.query_one("#lens-bar").badge("network") == "2 TLS failed"
        tls = [r for r in panel._live if r.kind == "tls"]
        assert [r.host for r in tls] == ["api.revenuecat.com", "pinned.example.com"]
        await pilot.press("2")
        await settle(pilot)
        assert ms.query_one("#lens-bar").badge("network") is None
        assert "TLS failed" in _column(panel, "status")[-1]
        content = panel.flow_content(tls[0])
        assert "pinning" in str(content.sections[1][1])


async def test_mitm_lines_go_to_the_activity_log(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        panel = ms.query_one("#network-panel", NetworkPanel)
        log = ms.query_one("#activity-log")
        panel.mitm._append_line(
            "[ERROR] device CANNOT reach mitmproxy at 10.0.2.2:8080"
        )
        await settle(pilot)
        assert any(
            "mitm:" in line and "CANNOT reach" in line for line in log._plain_lines
        )
        assert "CANNOT reach" in panel.mitm.recent_lines[-1]
        # N6-V8: the SSL unpin bypass logs as bypass, not "mitm: Bypass …".
        panel.mitm._append_line("[BYPASS] Bypass (experimental): SSL Pinning Bypass")
        await settle(pilot)
        line = next(x for x in log._plain_lines if "SSL Pinning Bypass" in x)
        assert "bypass: Bypass (experimental)" in line
        assert "mitm:" not in line


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
            await settle(pilot)
        assert calls == [
            "toggle_device",
            "inject_ca",
            "manage_addons",
            "toggle_running",
        ]
        await pilot.press("I")
        await settle(pilot)
        assert ms.inspector_content.key == STATUS_KEY
        assert [n for n, _ in ms.inspector_content.tabs] == ["Mitmproxy", "friTap"]


async def test_review_scope_filters_by_run_window(flow_dir, tmp_path):
    base = time.time() - 1000
    # window covers flows 3..5 (t = 20 s .. 40 s)
    run = write_run(tmp_path / "runs" / "20261117_100000_ab12cd", base + 19, base + 41)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir, base=base)
        live_rows = panel.table.row_count
        ms.set_scope(str(run), label="Run 3")
        await until(pilot, lambda: not panel._review_loading)
        await settle(pilot)
        assert {r.seq for r in panel._review} == {3, 4, 5}
        title, info = ms._lens_captions["network"]
        assert "Run 3" in title
        assert "time window" in title
        # play.googleapis (seq 5) is noise -> 2 of 3 shown
        assert panel.table.row_count == 2
        assert "2 of 3" in info
        ms.set_scope(None)
        await settle(pilot)
        assert panel.table.row_count == live_rows


async def test_review_scope_empty_and_unknown_runs(flow_dir, tmp_path):
    empty = write_run(tmp_path / "runs" / "r0", 1, 2, label="Run 1")
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        ms.set_scope(str(empty))  # label comes from run.json
        await until(pilot, lambda: not panel._review_loading)
        await settle(pilot)
        assert panel.table.has_class("-empty")
        assert "No flows were captured during Run 1" in str(
            panel.query_one("#net-empty-head").render()
        )
        ms.set_scope(str(tmp_path / "missing"), label="Run 9")
        await until(pilot, lambda: not panel._review_loading)
        await settle(pilot)
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


def test_mitm_port_shown_is_the_configured_one(monkeypatch):
    """Caption, empty hint, status page and proxy default: never a fixed 8080."""
    import sandroid.config as config_mod
    from sandroid.config import SandroidConfig
    from sandroid.core.proxy_manager import ProxyManager
    from sandroid.services.mitmproxy_service import MitmproxyService
    from sandroid.tui.widgets.mitmproxy_panel import MitmproxyPanel

    cfg = SandroidConfig()
    cfg.mitmproxy.proxy_port = 8090
    monkeypatch.setattr(config_mod, "_config_instance", cfg)
    service = MitmproxyService()
    panel = MitmproxyPanel()
    panel._service = service

    head, _hint = panel.empty_hint()
    assert ":8090" in head
    assert any("8090" in markup for _label, markup in panel.status_rows())

    monkeypatch.setattr(service, "is_running", lambda: True)
    monkeypatch.setattr(service, "ssl_unpin_is_active", lambda: False)
    caption = panel.status_caption()
    assert ":8090" in caption
    assert "8080" not in caption

    monkeypatch.setattr(
        ProxyManager, "get_host_ip", classmethod(lambda cls: "10.0.2.2")
    )
    assert ProxyManager.get_default_config().port == 8090


def test_capture_status_is_dots_and_words(monkeypatch):
    """● on / ○ off / ◌ pending before the state word, in the state's lens
    colour; no ✓ ✗ → and no ^N / ^P key glyphs.
    """
    from rich.text import Text

    from sandroid.services.mitmproxy_service import MitmproxyService
    from sandroid.tui.themes import lens_palette
    from sandroid.tui.widgets.mitmproxy_panel import MitmproxyPanel

    pal = lens_palette()
    service = MitmproxyService()
    panel = MitmproxyPanel()
    panel._service = service
    monkeypatch.setattr(service, "ssl_unpin_is_active", lambda: False)

    def plain(markup: str) -> str:
        return Text.from_markup(markup).plain

    monkeypatch.setattr(service, "is_running", lambda: False)
    assert plain(panel.status_caption()) == "Mitmproxy ○ off"
    rows = dict(panel.status_rows())
    assert plain(rows["Mitmproxy web interface"]).startswith("○ stopped")
    assert rows["Mitmproxy web interface"].startswith(f"[{pal.dim}]○ stopped[/]")
    assert plain(rows["CA"]) == "○ not installed  Ctrl+N"
    # "CA not installed" is a warning (not muted), like the Proxy dialog's.
    assert rows["CA"].startswith(f"[{pal.warn}]○ not installed[/]")
    assert plain(rows["Chrome CT"]) == "○ off"
    assert plain(rows["SSL unpin"]) == "○ off  Ctrl+P"

    monkeypatch.setattr(service, "is_running", lambda: True)
    panel._ca_ok = panel._ct_ok = True
    panel._proxy_state, panel._proxy_addr = "ours", "10.0.2.2:8080"
    caption = panel.status_caption()
    assert f"[{pal.ok}]Mitmproxy ● running[/]" in caption
    assert f"CA [{pal.ok}]● installed[/]" in caption
    rows = dict(panel.status_rows())
    assert rows["CA"].startswith(f"[{pal.ok}]● installed[/]")
    assert plain(rows["Chrome CT"]) == "● bypassed"
    # Status bar order: name, dot, state (then the detail).
    assert rows["routing"] == (
        f"Device proxy [{pal.ok}]● on: our Mitmproxy 10.0.2.2:8080[/]"
    )
    assert plain(rows["routing"]) == "Device proxy ● on: our Mitmproxy 10.0.2.2:8080"
    panel._reach_state = "checking"
    routing = dict(panel.status_rows())["routing"]
    assert routing.startswith(f"Device proxy [{pal.warn}]◌ re-checking: ")
    assert plain(routing) == "Device proxy ◌ re-checking: our Mitmproxy 10.0.2.2:8080"
    panel._reach_state = "unreachable"
    routing = dict(panel.status_rows())["routing"]
    # A failure: the words in the bad colour, no dot.
    assert plain(routing) == "Device proxy to our Mitmproxy 10.0.2.2:8080, unreachable"
    assert routing.startswith(f"[{pal.bad}]")
    panel._reach_state = "ok"
    panel._proxy_state = "other"
    routing = dict(panel.status_rows())["routing"]
    assert routing == f"Device proxy [{pal.accent}]● on: external 10.0.2.2:8080[/]"
    panel._proxy_state = "none"
    routing = dict(panel.status_rows())["routing"]
    assert routing == f"Device proxy [{pal.dim}]○ off[/]"
    assert plain(routing) == "Device proxy ○ off"
    text = " ".join(plain(value) for _label, value in panel.status_rows())
    assert not set("✓✗→▲^") & set(text), text
    panel._ca_ok = False
    caption = panel.status_caption()
    assert f"CA [{pal.warn}]○ not installed[/]" in caption
    assert "CA ○ not installed" in plain(caption)
    assert not set("✓✗▸◐⚑⇧␣⏎") & set(plain(caption)), caption


def _caption_panel(monkeypatch, running: bool):
    from sandroid.services.mitmproxy_service import MitmproxyService
    from sandroid.tui.widgets.mitmproxy_panel import MitmproxyPanel

    service = MitmproxyService()
    panel = MitmproxyPanel()
    panel._service = service
    monkeypatch.setattr(service, "is_running", lambda: running)
    monkeypatch.setattr(service, "ssl_unpin_is_active", lambda: False)
    return panel, service


def test_caption_routing_follows_the_network_method(monkeypatch):
    """N3-B2: "device routed" follows the method service's device read (Off,
    keys only, Whole device, adb reverse), not only M / Ctrl+D.
    """
    from types import SimpleNamespace

    from sandroid.services import network_method as nm

    panel, _ = _caption_panel(monkeypatch, running=True)
    snap = {"value": nm.MethodSnapshot(device_proxy="none")}
    fake = SimpleNamespace(snapshot_cached=lambda: snap["value"])
    monkeypatch.setattr(nm, "peek_network_method_service", lambda: fake)
    panel._proxy_state = "ours"  # set by an earlier Ctrl+D
    panel._handle_proxy_change("network_method", None, None)
    assert "device routed" not in panel.status_caption()
    assert panel._proxy_state == "none"
    snap["value"] = nm.MethodSnapshot(device_proxy="ours", device_addr="127.0.0.1:8090")
    panel._handle_proxy_change("network_method", None, None)
    assert "device routed" in panel.status_caption()
    snap["value"] = nm.MethodSnapshot(device_proxy="external", device_addr="1.2.3.4:8")
    panel._handle_proxy_change("network_method", None, None)
    assert "device on another proxy" in panel.status_caption()


def test_caption_shows_a_stopped_mitmproxy_as_a_red_problem(monkeypatch):
    """N3-B3: Mitmproxy down while something routes to it is red words, not
    a muted "○ off"; the reason of a failed start or exit is named.
    """
    from sandroid.tui.themes import lens_palette

    pal = lens_palette()
    panel, service = _caption_panel(monkeypatch, running=False)
    panel._proxy_state = "ours"
    assert panel.status_caption() == (
        f"[{pal.bad}]Mitmproxy stopped: app traffic blocked[/]"
    )
    service._state.last_error = "port 8390 is in use"
    assert panel.status_caption() == (
        f"[{pal.bad}]Mitmproxy stopped: port 8390 is in use, app traffic blocked[/]"
    )
    panel._proxy_state = "none"
    service._state.last_error = None
    assert panel.status_caption() == f"[{pal.dim}]Mitmproxy ○ off[/]"


def test_caption_says_starting_until_mitmweb_listens(monkeypatch):
    from sandroid.tui.themes import lens_palette

    pal = lens_palette()
    panel, service = _caption_panel(monkeypatch, running=True)
    service._state.running, service._state.listening = True, False
    assert f"[{pal.warn}]Mitmproxy ◌ starting[/]" in panel.status_caption()
    service._state.listening = True
    assert f"[{pal.ok}]Mitmproxy ● running[/]" in panel.status_caption()


def test_fritap_stopped_is_muted_like_mitmproxy(monkeypatch):
    """The friTap "○ stopped" uses the lens dim token Mitmproxy uses, not red;
    "failed" stays a word in the bad colour, without a dot.
    """
    from rich.text import Text

    from sandroid.analysis import fritap as fritap_mod
    from sandroid.tui.themes import lens_palette
    from sandroid.tui.widgets.fritap_panel import FriTapPanel

    pal = lens_palette()
    panel = FriTapPanel()
    monkeypatch.setattr(panel, "is_running", lambda: False)
    try:
        fritap_mod.set_lifecycle("stopped", "")
        head = dict(panel.status_rows())["friTap"]
        assert head == f"[{pal.dim}]○ stopped[/]"
        fritap_mod.set_lifecycle("stopped", "agent still unloading")
        head = dict(panel.status_rows())["friTap"]
        assert head == f"[{pal.dim}]○ stopped (agent still unloading)[/]"
        assert Text.from_markup(head).plain == "○ stopped (agent still unloading)"
        fritap_mod.set_lifecycle("failed", "agent stuck")
        head = dict(panel.status_rows())["friTap"]
        assert head.startswith(f"[{pal.bad}]failed[/]")
        assert not set("●○◌✓✗▸◐⚑⇧␣⏎") & set(Text.from_markup(head).plain)
    finally:
        fritap_mod.set_lifecycle("stopped", "")


def test_proxy_dialog_status_reads_name_dot_state(monkeypatch):
    """Device proxy line: "Device proxy ● on: …" / "Device proxy ○ off"; the
    CA line's "○ Not installed" is a warning.
    """
    from types import SimpleNamespace

    from sandroid.core.proxy_manager import ZygoteStatus
    from sandroid.tui.modals.proxy_modal import ProxyModal

    shown: list[str] = []
    sink = SimpleNamespace(update=shown.append)
    modal = ProxyModal()
    monkeypatch.setattr(modal, "query_one", lambda *a, **k: sink)
    monkeypatch.setattr(modal, "_select_device_radio", lambda radio_id: None)

    modal._on_device_probe_done({"device": {"state": "ours", "addr": "10.0.2.2:8080"}})
    assert shown[-1] == (
        "Device proxy [$lens-ok]● on[/]: our Mitmproxy at [bold]10.0.2.2:8080[/bold]"
    )
    modal._on_device_probe_done(
        {"device": {"state": "external", "addr": "192.168.1.5:8081"}}
    )
    assert shown[-1] == (
        "Device proxy [$lens-accent]● on[/]: external proxy at "
        "[bold]192.168.1.5:8081[/bold]"
    )
    modal._on_device_probe_done({"device": {"state": "none", "addr": ""}})
    assert shown[-1] == "Device proxy [$lens-dim]○ off[/]"

    modal._show_zygote_status(
        ZygoteStatus(
            injected=False,
            cert_hash=None,
            zygote64_pid=None,
            zygote_pid=None,
            verdict="absent",
        )
    )
    assert shown[-1].startswith("[$warning]○ Not installed[/]")
    for markup in shown:
        assert not set("✓✗▸◐⚑⇧␣⏎") & set(markup), markup


def test_network_keys_are_words(monkeypatch):
    """Hints and key lists name keys in words (Ctrl+D, Shift+C, Space)."""
    import re

    import sandroid.config as config_mod
    from sandroid.config import SandroidConfig
    from sandroid.services.mitmproxy_service import MitmproxyService
    from sandroid.tui.widgets.mitmproxy_panel import MitmproxyPanel
    from sandroid.tui.widgets.network_panel import NetworkPanel

    key_glyphs = re.compile(r"[⇧␣⏎←→]|\^[A-Z]\b")
    monkeypatch.setattr(config_mod, "_config_instance", SandroidConfig())
    service = MitmproxyService()
    panel = MitmproxyPanel()
    panel._service = service
    texts = list(panel.empty_hint())
    monkeypatch.setattr(service, "is_running", lambda: True)
    texts += list(panel.empty_hint())
    for text in texts:
        assert not key_glyphs.search(text), text
    space = [b for b in NetworkPanel.BINDINGS if b.key == "space"]
    assert space
    assert not space[0].key_display


# --------------------------------------------------------------------------
# fix round 3 (live traffic test): noise, filter, keys, bodies, threads
# --------------------------------------------------------------------------


def test_noise_rules_cover_play_services_background_traffic():
    """M5: ~90 Google background flows stayed visible with N off."""
    for host, path in (
        ("infinitedata-pa.googleapis.com", "/v1/x"),
        ("phonedeviceverification-pa.googleapis.com", "/v1/a"),
        ("prod-lt-playstoregatewayadapter-pa.googleapis.com", "/b"),
        ("geller-pa.googleapis.com", "/c"),
        ("www.googleapis.com", "/experimentsandconfigs/v1/getExperimentsAndConfigs"),
        ("www.googleapis.com", "/androidantiabuse/v1/x/create"),
        ("www.googleapis.com", "/androidcheck/v1/attestations/adAttest"),
        ("play-lh.googleusercontent.com", "/icon.png"),
        ("android-safebrowsing.google.com", "/v4/x"),
        ("mitm.it", "/"),  # Sandroid's own reachability probe (L8)
    ):
        assert is_noise(host, path, ""), host + path
    # The app's own analytics and ordinary Google APIs stay visible.
    assert not is_noise("firebaselogging-pa.googleapis.com", "/v1/log", "")
    assert not is_noise("www.googleapis.com", "/youtube/v3/videos", "")
    assert not is_noise("en.wikipedia.org", "/api/rest_v1/feed", "")


async def test_caption_says_how_much_noise_is_hidden(flow_dir):
    """M5: "9 of 15" did not say that N brings the rest back."""
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        info = ms._lens_captions["network"][1]
        assert "N: 2 OS noise hidden" in info
        await pilot.press("N")
        await settle(pilot)
        info = ms._lens_captions["network"][1]
        assert "+ OS noise" in info
        assert "hidden" not in info
        await pilot.press("N")
        write_flows(
            flow_dir,
            time.time(),
            specs=[("GET", "geller-pa.googleapis.com", "/x", 200, "", None, "", None)],
            start_seq=50,
        )
        panel.poll_now()
        await until(
            pilot, lambda: "N: 3 OS noise" in (ms._lens_captions["network"][1] or "")
        )


async def test_filter_matches_status_and_esc_clears_it(flow_dir):
    """L4/L5: ``/200`` found nothing; Esc left a filter applied for good."""
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        shown = panel.table.row_count
        await pilot.press("slash")
        for ch in "200":
            await pilot.press(ch)
        await until(pilot, lambda: panel._filter == "200")
        assert set(_column(panel, "status")) == {"200"}
        # Esc in the input: filter cleared, input closed, back on the table
        await pilot.press("escape")
        await settle(pilot)
        assert panel._filter == ""
        # No debounce is left armed by the cleared input: it would re-apply
        # "" over a filter set right after (the next step, under load).
        assert panel._filter_timer is None
        assert panel.table.row_count == shown
        assert not panel.query_one("#net-filter").has_class("-open")
        assert app.focused is panel.table
        # an applied filter with the input closed: Esc clears it too
        panel.set_filter("error")
        await settle(pilot)
        assert panel.table.row_count == 1  # the reset upload
        await pilot.press("escape")
        await settle(pilot)
        assert panel._filter == ""
        assert panel.table.row_count == shown


async def test_end_and_home_jump_to_the_last_and_first_row(flow_dir):
    """L14: End scrolled sideways instead of reaching the newest flow."""
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        panel.table.focus()
        await pilot.press("home")
        await settle(pilot)
        assert panel.table.cursor_row == 0
        await pilot.press("end")
        await settle(pilot)
        assert panel.table.cursor_row == panel.table.row_count - 1


def _layout_at(monkeypatch, width: int, identity: bool) -> list[tuple[str, str, int]]:
    from textual.geometry import Size

    monkeypatch.setattr(NetworkPanel, "size", property(lambda self: Size(width, 40)))
    monkeypatch.setattr(NetworkPanel, "_privacy_wanted", lambda self: identity)
    return NetworkPanel()._layout()


@pytest.mark.parametrize(
    ("width", "identity", "keys"),
    [
        (160, False, ["time", "app", "who", "req", "tls", "status", "size"]),
        (
            160,
            True,
            ["time", "app", "who", "req", "tls", "ident", "status", "size"],
        ),
        (120, True, ["time", "app", "who", "req", "tls", "ident", "status"]),
        (100, False, ["time", "app", "who", "req", "tls", "status"]),
        # Inspector open (~100 columns) with Identity: TLS and Time go
        (100, True, ["app", "who", "req", "ident", "status"]),
        (80, False, ["app", "who", "req", "status"]),
        (60, False, ["who", "req", "status"]),
    ],
)
def test_column_order_and_narrow_drop_order(monkeypatch, width, identity, keys):
    """Time | App | Recipient | Request | TLS | Identity | Status | Size; a
    narrow lens drops Size, TLS, Time, App (in that order) for Request.
    """
    layout = _layout_at(monkeypatch, width, identity)
    assert [k for k, _l, _w in layout] == keys
    widths = {k: w for k, _l, w in layout}
    if width >= 80:
        assert widths["req"] >= np_mod.REQUEST_MIN_WIDTH
    if "ident" in widths:  # Identity keeps its own width rule
        assert widths["ident"] == (18 if width >= 130 else 14)
    labels = {k: label for k, label, _w in layout}
    assert labels.get("app", "App") == "App"
    assert labels.get("tls", "TLS") == "TLS"


def test_highlight_column_may_take_the_size_place(monkeypatch):
    """AI highlights: Highlight goes last, in Size's place when needed, and
    not at all when Request would get too narrow.
    """
    from sandroid.tui.widgets.highlight_bar import HighlightView

    monkeypatch.setattr(HighlightView, "show_column", lambda self, width: True)
    keys = [k for k, _l, _w in _layout_at(monkeypatch, 200, False)]
    assert keys[-2:] == ["size", "hl"]
    keys = [k for k, _l, _w in _layout_at(monkeypatch, 158, True)]
    assert keys == ["time", "app", "who", "req", "tls", "ident", "status", "hl"]
    assert "hl" not in [k for k, _l, _w in _layout_at(monkeypatch, 100, True)]


def _cell_texts(row: FlowRow) -> dict[str, str]:
    panel = NetworkPanel()
    layout = [
        ("time", "Time", 8),
        ("app", "App", 20),
        ("who", "Recipient", 18),
        ("req", "Request", 40),
        ("tls", "TLS", 10),
        ("status", "Status", 13),
        ("size", "Size", 16),
    ]
    cells = panel._cells(row, layout)
    return {k: cells[i].plain for i, (k, _l, _w) in enumerate(layout)}


def test_app_and_tls_cells_say_it_in_words():
    from sandroid.tui.themes import lens_palette

    # an App Proxy flow carries its app tag; over https it is TLS
    proxied = FlowRow(
        key="f1",
        ts=0.0,
        host="a.io",
        status=200,
        app=PKG,
        protocol="HTTPS/2",
        req_bytes=2048,
    )
    cells = _cell_texts(proxied)
    assert cells["app"] == PKG
    assert cells["tls"] == "TLS"
    assert cells["size"] == "sent 2.0 KB"
    # an untagged flow shows no app (nothing, not a placeholder)
    untagged = FlowRow(
        key="f2",
        ts=0.0,
        host="b.io",
        status=200,
        protocol="HTTP/1.1",
        resp_bytes=5 * 1024,
    )
    cells = _cell_texts(untagged)
    assert cells["app"] == ""
    assert cells["tls"] == "plain"
    assert cells["size"] == "received 5.0 KB"
    panel = NetworkPanel()
    layout = [("req", "Request", 40), ("who", "Recipient", 18), ("tls", "TLS", 10)]
    assert panel._cells(untagged, layout)[2].style == lens_palette().warn
    # a failed handshake
    tls = FlowRow(key="t1", ts=0.0, host="c.io", kind="tls", method="TLS", app=PKG)
    cells = _cell_texts(tls)
    assert cells["tls"] == "TLS failed"
    assert cells["status"] == "TLS failed"
    assert cells["app"] == PKG
    # no protocol recorded (older log): no guess
    assert _cell_texts(FlowRow(key="f3", ts=0.0, host="d.io"))["tls"] == ""
    # websockets
    assert _cell_texts(FlowRow(key="f4", ts=0.0, protocol="WSS"))["tls"] == "TLS"
    assert _cell_texts(FlowRow(key="f5", ts=0.0, protocol="WS"))["tls"] == "plain"
    # a long package keeps its trailing name parts, cut without a glyph
    long_app = FlowRow(key="f6", ts=0.0, app="com.ebay.kleinanzeigen")
    assert _cell_texts(long_app)["app"] == "ebay.kleinanzeigen"
    assert np_mod.app_label("com.ebay.kleinanzeigen", 14) == "kleinanzeigen"
    assert np_mod.app_label("com.x.averyveryverylongname", 8) == "averyver"


def test_status_and_size_cells_have_no_glyphs():
    pending = FlowRow(key="f1", ts=0.0, host="a.io")  # no response yet
    cells = _cell_texts(pending)
    assert cells["status"] == ""
    assert cells["size"] == ""
    rows = [
        pending,
        FlowRow(key="f2", ts=0.0, status=200, req_bytes=10),
        FlowRow(key="f3", ts=0.0, status=200, resp_bytes=3 * 1024 * 1024),
        FlowRow(key="f4", ts=0.0, error="weird"),
        FlowRow(key="t1", ts=0.0, kind="tls"),
    ]
    for row in rows:
        cells = _cell_texts(row)
        for key in ("app", "tls", "status", "size"):
            assert not set(cells[key]) & set("\u2191\u2193\u2013\u2026\u2691"), (
                key,
                cells[key],
            )
    assert _cell_texts(rows[2])["size"] == "received 3.0 MB"


def test_error_reads_once_in_the_status_and_the_filter_text():
    """The unknown-reason fallback said "error error"."""
    panel = NetworkPanel()
    odd = FlowRow(key="f1", ts=0.0, host="a.io", error="something odd")
    assert _cell_texts(odd)["status"] == "error"
    assert panel._haystack(odd).count("error") == 1
    reset = FlowRow(key="f2", ts=0.0, host="a.io", error="Connection reset by peer")
    assert _cell_texts(reset)["status"] == "error reset"
    assert panel._haystack(reset).count("error") == 1


def test_size_column_fits_three_digit_kilobytes():
    """L2: "190.9 K" lost its B; the cell says it in words now."""
    panel = NetworkPanel()
    layout = [
        ("time", "Time", 8),
        ("who", "Recipient", 18),
        ("req", "Request", 40),
        ("status", "Status", 13),
        ("size", "Size", 16),
    ]
    row = FlowRow(key="f1", ts=0.0, host="a.io", status=200, resp_bytes=195482)
    size = panel._cells(row, layout)[4].plain
    assert size == "received 191 KB"
    assert len(size) <= {k: w for k, _l, w in panel._layout()}["size"]

    # R4-N7: in REVIEW with A, a setup/dry-run TLS failure had no marker.
    panel._scope = "/runs/r1"
    tls = FlowRow(key="f2", ts=0.0, host="ssl.gstatic.com", kind="tls", phase="setup")
    request = panel._cells(tls, layout)[2].plain
    assert request.startswith("setup TLS ssl.gstatic.com")
    assert len(request) <= 40


def test_decoded_body_note_and_protocol_label():
    """M1: decoded bodies say what they were decoded from; HTTPS/2 not 2.0."""
    from rich.console import Console

    from sandroid.tui.widgets.network_panel import protocol_label

    def plain(r) -> str:
        console = Console(width=80, record=True, color_system=None)
        console.print(r)
        return console.export_text()

    body = _body('{"items": [1, 2]}')
    body.update(content_encoding="gzip", encoded_bytes=31)
    out = plain(body_renderable(body, "application/json"))
    assert "decoded from gzip · 31 B on the wire" in out
    assert '"items"' in out
    broken = _body(b"\x1f\x8b\x08\x00garbage")
    broken.update(content_encoding="gzip", decode_failed=True)
    out = plain(body_renderable(broken, "application/json"))
    assert "could not be decoded" in out
    assert "1f 8b 08" in out
    assert protocol_label("HTTPS/2.0") == "HTTPS/2"
    assert protocol_label("HTTP/1.1") == "HTTP/1.1"


async def test_persisted_tls_failures_are_one_row(flow_dir):
    """L7: TLS failures are in flows.jsonl now; the stdout row is not doubled."""
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        panel.add_tls_failure("12:00:00", "pinned.example.com", "cert", "")
        await settle(pilot)
        now = time.time()
        with open(flow_dir / "flows.jsonl", "a", encoding="utf-8") as f:
            for seq, host in ((200, "pinned.example.com"), (201, "other.example")):
                f.write(
                    json.dumps(
                        {
                            "seq": seq,
                            "id": f"tls-{seq}",
                            "kind": "tls",
                            "ts_start": now,
                            "ts_end": now,
                            "protocol": "TLS",
                            "method": "TLS",
                            "host": host,
                            "path": "",
                            "status_code": None,
                            "error": "TLS handshake failed (cert)",
                            "tls_reason": "cert",
                            "app": "",
                        }
                    )
                    + "\n"
                )
        panel.poll_now()
        await until(pilot, lambda: any(r.host == "other.example" for r in panel._live))
        tls = [r for r in panel._live if r.kind == "tls"]
        assert sorted(r.host for r in tls) == ["other.example", "pinned.example.com"]
        assert all(r.reason == "cert" for r in tls)


async def test_mitm_lines_from_a_thread_raise_no_lookup_error(flow_dir):
    """M2: every mitmweb line from the reader thread started a caption timer
    without Textual's app context: 562 ``LookupError: active_app`` in 28 min.
    """
    import threading

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        loop = panel.mitm._ui.loop
        errors: list = []
        loop.set_exception_handler(lambda _loop, ctx: errors.append(ctx))
        lines = [f"[TLS_FAIL]|12:00:{i:02d}|host{i}.example|cert|" for i in range(30)]
        lines += ["[INFO] Hooked: cronet:SSL_CTX_set_custom_verify"] * 3

        def reader() -> None:
            for line in lines:
                panel.mitm._on_service_line(line)

        worker = threading.Thread(target=reader)
        worker.start()
        worker.join()
        await until(pilot, lambda: sum(r.kind == "tls" for r in panel._live) == 30)
        await until(pilot, lambda: not panel._status_pending)
        loop.set_exception_handler(None)
        assert errors == []


async def test_refresh_status_outside_the_app_context(flow_dir):
    """A bare loop callback (no ``active_app``) must not start a timer."""
    import contextvars

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        loop = panel.mitm._ui.loop
        errors: list = []
        loop.set_exception_handler(lambda _loop, ctx: errors.append(ctx))
        ms._lens_captions["network"] = (None, None)
        loop.call_soon(panel.refresh_status, context=contextvars.Context())
        await until(pilot, lambda: ms._lens_captions["network"][1])
        loop.set_exception_handler(None)
        assert errors == []
        assert not panel._status_pending


async def test_ctrl_o_opens_mitmweb_with_its_token(flow_dir, monkeypatch):
    """M6: Ctrl+O opened the UI without the token (403) and said nothing."""
    import webbrowser

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        svc = panel.mitm._service
        monkeypatch.setattr(svc, "is_running", lambda: True)
        monkeypatch.setattr(svc, "_web_token", "s3cret-token")
        opened: list[str] = []
        monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url) or True)
        await pilot.press("ctrl+o")
        await settle(pilot)
        assert opened == [f"{svc.web_url(with_token=False)}?token=s3cret-token"]
        toast = [n.message for n in app._notifications]
        assert any(
            "Opened the Mitmproxy web interface" in m and "token" in m for m in toast
        )
        assert not any("s3cret-token" in m for m in toast)


async def test_fritap_caption_follows_its_lifecycle(flow_dir, monkeypatch):
    """M3: "stopped" for ~50 s while starting, "running" ~20 s after stop."""
    from sandroid.analysis import fritap as fritap_mod

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        fritap = panel.fritap
        running = {"on": False}
        monkeypatch.setattr(fritap, "is_running", lambda: running["on"])
        try:
            fritap_mod.set_lifecycle("starting", "org.wikipedia")
            await until(
                pilot, lambda: "friTap ◌ starting" in ms._lens_captions["network"][0]
            )
            running["on"] = True
            fritap_mod.set_lifecycle("running", "org.wikipedia")
            await until(
                pilot, lambda: "friTap ● running" in ms._lens_captions["network"][0]
            )
            fritap_mod.set_lifecycle("hung", "org.wikipedia is not responding")
            await until(
                pilot, lambda: "not responding" in ms._lens_captions["network"][0]
            )
            head = dict(fritap.status_rows())["friTap"]
            assert "h stops friTap" in head
            fritap_mod.set_lifecycle("stopping", "org.wikipedia")
            await until(
                pilot, lambda: "friTap ◌ stopping" in ms._lens_captions["network"][0]
            )
            running["on"] = False
            fritap_mod.set_lifecycle("stopped", "agent still unloading")
            await until(pilot, lambda: "friTap" not in ms._lens_captions["network"][0])
            assert "agent still unloading" in dict(fritap.status_rows())["friTap"]
            # NEW-2: a failed unload dropped friTap from the caption (read
            # like a clean stop); only the tab said "✗ failed".
            fritap_mod.set_lifecycle("failed", "agent stuck in org.wikipedia")
            await until(
                pilot, lambda: "friTap failed" in ms._lens_captions["network"][0]
            )
        finally:
            fritap_mod.set_lifecycle("stopped", "")


def test_ssl_unpin_indicator_follows_the_hooked_process(monkeypatch):
    """M4: "unpin ✓" stayed 15 min after the Zygote restart killed the app."""
    from types import SimpleNamespace

    from sandroid.analysis import detection_bypass as db
    from sandroid.services.mitmproxy_service import MitmproxyService
    from sandroid.tui.widgets.mitmproxy_panel import MitmproxyPanel

    svc = db.BypassService()
    job = SimpleNamespace(state="running", get_id=lambda: "j1")
    svc._job = job
    svc._script = SimpleNamespace(is_destroyed=False)
    svc._active = {"ssl"}
    svc._process_id = 6008
    svc._app_package = "org.wikipedia"
    jm = SimpleNamespace(has_active_session=lambda: True, jobs={"j1": job})
    monkeypatch.setattr(db.Toolbox, "get_frida_job_manager", lambda: jm)
    spot = SimpleNamespace(get_pid=lambda: 6008)
    monkeypatch.setattr(db, "get_spotlight_service", lambda: spot)
    reset: list[int] = []
    monkeypatch.setattr(svc, "_reset_script_state", lambda: reset.append(1))
    monkeypatch.setattr(db, "get_bypass_service", lambda: svc)

    mitm = MitmproxyPanel()
    mitm._service = MitmproxyService()
    monkeypatch.setattr(mitm._service, "is_running", lambda: True)
    monkeypatch.setattr(mitm._service, "_bypass_service", lambda: svc)

    assert svc.reconcile_liveness() == []  # alive: nothing changes
    from rich.text import Text

    assert "unpin ● on" in Text.from_markup(mitm.status_caption()).plain

    # The Zygote restart: the session detaches, the app comes back as 8593.
    jm.has_active_session = lambda: False
    spot.get_pid = lambda: 8593
    original_reset = db.BypassService._reset_script_state

    def _reset() -> None:
        reset.append(1)
        original_reset(svc)

    monkeypatch.setattr(svc, "_reset_script_state", _reset)
    monkeypatch.setattr(db.BypassService, "_unregister_task", lambda self: None)
    assert svc.reconcile_liveness() == ["ssl"]
    assert reset == [1]
    assert not svc.is_active("ssl")
    assert "unpin" not in mitm.status_caption()
    assert any(
        "SSL unpin" in label and "off" in value for label, value in mitm.status_rows()
    )


def test_bypass_install_lines_do_not_claim_inactive_categories(caplog):
    """R2-N5: a Frida-only ``b 3`` logged root/debug/SSL "Hooked:" lines.
    The combined script installs every category's hooks; flags gate them.
    """
    import logging

    from sandroid.analysis import detection_bypass as db

    svc = db.BypassService()
    with caplog.at_level(logging.INFO, logger=db.logger.name):
        for payload in (
            {"type": "info", "hook": "root-bypass:File.exists"},
            {"type": "ready", "message": "Root detection bypass hooks loaded"},
        ):
            svc._message_handler(None, {"type": "send", "payload": payload}, None)
    assert not [r for r in caplog.records if r.levelno >= logging.INFO]


# --------------------------------------------------------------------------
# REVIEW: flows stored in the run bundle, tagged by phase (H-6, H-7, M-27)
# --------------------------------------------------------------------------


def _phased_run(tmp_path, base: float, label: str = "Run C") -> Path:
    """A run whose replay 1 covers flows 3-4 and whose dry run covers 6-7."""
    run = write_run(tmp_path / "runs" / "20261117_184630_e8fb29", base - 1, base + 70)
    doc = json.loads((run / "run.json").read_text())
    doc["label"] = label
    doc["phases"] = [
        {"kind": "replay", "run": 1, "start": base + 15, "end": base + 35},
        {"kind": "dry_run", "run": 2, "start": base + 45, "end": base + 65},
    ]
    (run / "run.json").write_text(json.dumps(doc))
    return run


def test_export_run_flows_tags_phases_and_copies_details(tmp_path):
    from sandroid.core import run_history
    from sandroid.services.mitmproxy_flow_log import export_run_flows, read_run_flows

    base = time.time() - 1000
    session = tmp_path / "session" / "mitm_flows"
    write_flows(session, base)
    write_flows(session, base + 5000, specs=_SPECS[:1], start_seq=99)  # later
    run = _phased_run(tmp_path, base)
    phases = run_history.resolve_scope(str(run)).phases
    meta = export_run_flows(
        session, run / "network", base - 1, base + 70, phases, mitm_running=True
    )
    assert meta["count"] == len(_SPECS)  # the later flow is not in the window
    assert meta["per_phase"] == {"setup": 3, "replay 1": 2, "dry run": 2}
    assert meta["mitm_running"] is True
    records, stored_meta = read_run_flows(run / "network")
    assert [r["phase"] for r in records] == [
        "setup",
        "setup",
        "replay 1",
        "replay 1",
        "setup",
        "dry run",
        "dry run",
    ]
    assert stored_meta["count"] == len(_SPECS)
    # details travel with the rows (headers + capped bodies)
    assert (run / "network" / "details" / "flow-2.json").is_file()


def test_export_run_flows_is_bounded(tmp_path):
    from sandroid.services.mitmproxy_flow_log import export_run_flows

    base = time.time() - 1000
    session = tmp_path / "mitm_flows"
    write_flows(session, base)
    dest = tmp_path / "run" / "network"
    meta = export_run_flows(
        session, dest, base - 1, base + 70, max_flows=3, max_detail_bytes=0
    )
    assert meta["count"] == 3
    assert meta["truncated"] is True
    assert meta["details_skipped"] == 3
    assert not (dest / "details").exists()
    # no flow log at all: still a definitive (empty) record
    meta = export_run_flows(None, tmp_path / "r2" / "network", 0, 1)
    assert meta["count"] == 0
    assert meta["flow_log_present"] is False


async def test_review_reads_the_bundle_and_hides_dry_run_flows(flow_dir, tmp_path):
    """H-6 + H-7: a run reviewed from a *later* session (empty session log)
    shows its replay flows from the bundle; dry-run and setup flows are
    hidden and counted, A shows them marked.
    """
    from sandroid.core import run_history
    from sandroid.services.mitmproxy_flow_log import export_run_flows

    base = time.time() - 1000
    old_session = tmp_path / "old_session" / "mitm_flows"
    write_flows(old_session, base)
    run = _phased_run(tmp_path, base)
    export_run_flows(
        old_session,
        run / "network",
        base - 1,
        base + 70,
        run_history.resolve_scope(str(run)).phases,
    )
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("2")
        await settle(pilot)
        panel = ms.query_one("#network-panel", NetworkPanel)
        assert not (flow_dir / "flows.jsonl").exists()  # new session: no flows
        ms.set_scope(str(run), label="#3 Run C")
        await until(pilot, lambda: not panel._review_loading)
        await settle(pilot)
        assert len(panel._review) == len(_SPECS)
        assert panel._review_data.source == "bundle"
        # replay 1 only: api.fittrack.de + app-measurement.com
        assert panel.table.row_count == 2
        title, info = ms._lens_captions["network"]
        assert "flows of the replays" in title
        assert "A: 2 dry run · 3 setup hidden" in info
        assert panel.check_action("toggle_phases", ()) is True

        await pilot.press("A")
        await settle(pilot)
        # all phases, OS noise (connectivitycheck, play.googleapis) still hidden
        assert panel.table.row_count == len(_SPECS) - 2
        cells = _column(panel, "req")[:5]
        assert sum(c.startswith("dry ") for c in cells) == 2
        assert sum(c.startswith("setup ") for c in cells) == 1
        title, info = ms._lens_captions["network"]
        assert "all phases" in title
        # the Inspector names the phase of a dry-run flow
        panel.table.move_cursor(row=4, animate=False)
        content = panel.inspect_selected()
        assert content is not None
        grid = content.tabs[0][1][0][1]
        assert "dry run" in [str(c) for c in grid.columns[1]._cells]


async def test_review_without_mitm_points_to_the_pcap(flow_dir, tmp_path):
    """M-27: no flows, but a pcap -- say why and where the traffic is."""
    from sandroid.services.mitmproxy_flow_log import export_run_flows

    run = write_run(tmp_path / "runs" / "20261117_182433_c52ae2", 100, 200, "Run 1")
    raw = run / "raw"
    raw.mkdir()
    (raw / "network_2.pcap").write_bytes(b"\0" * (1024 * 1100))
    export_run_flows(flow_dir, run / "network", 100, 200, mitm_running=False)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("2")
        await settle(pilot)
        panel = ms.query_one("#network-panel", NetworkPanel)
        ms.set_scope(str(run))
        await until(pilot, lambda: not panel._review_loading)
        await settle(pilot)
        head = str(panel.query_one("#net-empty-head").render())
        hint = str(panel.query_one("#net-empty-hint").render())
        assert "mitmproxy was not running during Run 1" in head
        assert "raw/network_2.pcap" in hint
        assert "1.1 MB" in hint


async def test_review_of_an_old_run_says_where_it_looked(flow_dir, tmp_path):
    """A run from before in-bundle flows: honest about the session fallback."""
    run = write_run(tmp_path / "runs" / "r_old", 100, 200, label="Run 1")
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("2")
        await settle(pilot)
        panel = ms.query_one("#network-panel", NetworkPanel)
        ms.set_scope(str(run))
        await until(pilot, lambda: not panel._review_loading)
        await settle(pilot)
        hint = str(panel.query_one("#net-empty-hint").render())
        assert "predates flows stored in its bundle" in hint


def test_network_tab_ctrl_p_disarms_an_armed_ssl_unpin(monkeypatch):
    """Armed-only SSL (stopped app): Ctrl+P disarms, no "[ERROR] … failed"."""
    from types import SimpleNamespace

    from sandroid.analysis import detection_bypass as db
    from sandroid.services.mitmproxy_service import MitmproxyService
    from sandroid.tui.widgets.mitmproxy_panel import MitmproxyPanel

    svc = db.BypassService()
    svc._armed = {"ssl"}
    monkeypatch.setattr(db, "get_bypass_service", lambda: svc)
    monkeypatch.setattr(db.BypassService, "_unregister_task", lambda self: None)
    service = MitmproxyService()
    monkeypatch.setattr(service, "_bypass_service", lambda: svc)
    mitm = MitmproxyPanel()
    mitm._service = service
    lines: list[str] = []
    monkeypatch.setattr(mitm, "_append_line", lines.append)
    monkeypatch.setattr(mitm, "_refresh_header", lambda: None)
    monkeypatch.setattr(mitm, "run_worker", lambda fn, **kw: fn())
    monkeypatch.setattr(
        MitmproxyPanel,
        "app",
        property(lambda self: SimpleNamespace(call_from_thread=lambda f: f())),
    )

    mitm.action_toggle_ssl_unpin()

    assert svc.armed_categories() == []
    assert lines == ["[INFO] SSL pinning bypass disarmed"]


async def test_follow_live_stops_on_up_or_a_click_and_end_resumes(flow_dir):
    """The shared follow rules: newest flow at the bottom and selected while
    live; ↑ or a click above it stops that (capturing goes on: the caption
    counts what arrived below); End resumes.
    """
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        table = panel.table
        assert panel.following
        assert ms._lens_captions["network"][0].startswith("live · ")
        table.focus()
        await pilot.press("up")
        await settle(pilot)
        assert not panel.following
        title = ms._lens_captions["network"][0]
        assert title.startswith("scrolled back · End = live · ")
        row = table.cursor_row
        count = table.row_count
        write_flows(flow_dir, time.time(), specs=_SPECS[1:3], start_seq=100)
        panel.poll_now()
        await until(pilot, lambda: table.row_count == count + 2)
        await settle(pilot)
        assert table.cursor_row == row
        title = ms._lens_captions["network"][0]
        assert title.startswith("scrolled back · 2 new below · End = live · ")
        await pilot.press("end")
        await settle(pilot)
        assert panel.following
        assert table.cursor_row == table.row_count - 1
        assert ms._lens_captions["network"][0].startswith("live · ")
        # A click on a row above the newest one stops following.
        await pilot.click("#net-flows", offset=(4, 2))
        await settle(pilot)
        assert not panel.following
        assert table.cursor_row < table.row_count - 1


async def test_a_rebuild_that_loses_the_kept_flow_is_live_again(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        panel.table.focus()
        await pilot.press("up")
        await settle(pilot)
        assert not panel.following
        panel.set_filter("no-such-flow-anywhere")
        await settle(pilot)
        panel.set_filter("")
        await settle(pilot)
        assert panel.table.cursor_row == panel.table.row_count - 1
        assert panel.following
        assert ms._lens_captions["network"][0].startswith("live · ")


async def test_new_below_counts_rows_through_a_width_rebuild(flow_dir):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        panel.table.focus()
        await pilot.press("up")
        await settle(pilot)
        panel._width = -1  # the next batch takes the rebuild path
        count = panel.table.row_count
        write_flows(flow_dir, time.time(), specs=_SPECS[1:3], start_seq=100)
        panel.poll_now()
        await until(pilot, lambda: panel.table.row_count == count + 2)
        assert panel._follow.new_below == 2


# --------------------------------------------------------------------------
# identity profile values (privacy scan)
# --------------------------------------------------------------------------


def _plain(renderable, width: int = 100) -> str:
    import io

    from rich.console import Console

    console = Console(width=width, record=True, color_system=None, file=io.StringIO())
    console.print(renderable)
    return console.export_text()


def _tinted(table) -> set[str]:
    """Row keys drawn with a row tint (a background colour)."""
    from rich.style import Style

    return {
        str(key.value)
        for key in table.rows
        if table._get_row_style(table.get_row_index(key), Style()).bgcolor
    }


def _privacy_hits():
    from privacy_fakes import flow_hit

    return [
        flow_hit("flow-2"),
        flow_hit(
            "flow-3",
            "Email",
            "Email",
            party="first",
            recipient="fittrack.de",
            host="api.fittrack.de",
            path="/v2/profile?mail=jane.canary@example.org",
            part="url",
            transform="value",
            snippet=("/v2/profile?mail=", "jane.canary@example.org", ""),
            offsets=(32,),
        ),
    ]


async def test_flows_with_profile_values_are_tinted_named_and_filtered(
    flow_dir, monkeypatch
):
    import privacy_fakes
    from rich.style import Style

    from sandroid.tui.themes import lens_palette

    privacy_fakes.install(monkeypatch, _privacy_hits())
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        table = panel.table
        assert [str(c.value) for c in table.columns][:7] == [
            "time",
            "app",
            "who",
            "req",
            "tls",
            "ident",
            "status",
        ]
        assert _tinted(table) == {"f2", "f3"}
        assert str(table.get_cell("f2", "ident")) == "Ad ID"
        assert str(table.get_cell("f3", "ident")) == "Email"
        pal = lens_palette()
        assert table.get_cell("f2", "ident").spans[0].style == pal.warn
        assert table.get_cell("f3", "ident").spans[0].style == pal.accent
        assert str(table.get_cell("f4", "ident")) == ""
        # The row tint: a background on f2 / f3 only.
        tinted = table._get_row_style(table.get_row_index("f2"), Style())
        plain = table._get_row_style(table.get_row_index("f4"), Style())
        assert tinted.bgcolor is not None
        assert plain.bgcolor is None
        assert "2 carry profile values" in ms._lens_captions["network"][1]
        # ! shows only the flows with profile values, and back.
        total = table.row_count
        await pilot.press("exclamation_mark")
        await until(pilot, lambda: table.row_count == 2)
        assert "!: profile values only" in ms._lens_captions["network"][1]
        await pilot.press("exclamation_mark")
        await until(pilot, lambda: table.row_count == total)
        # / matches the value names too.
        panel.set_filter("ad id")
        await until(pilot, lambda: table.row_count == 1)
        assert table.coordinate_to_cell_key((0, 0)).row_key.value == "f2"
        cells = "".join(
            str(table.get_cell(k, "ident")) for k in ("f2",) if table.row_count
        )
        assert not set(privacy_fakes.GLYPHS) & set(cells)


async def test_identity_tab_lists_each_hit_in_words(flow_dir, monkeypatch):
    import privacy_fakes

    from sandroid.tui.themes import lens_palette

    privacy_fakes.install(monkeypatch, _privacy_hits())
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        content = panel.flow_content(panel._row_by_key("f2"))
        names = [name for name, _ in content.tabs]
        assert names == ["Summary", "Request", "Response", "Identity"]
        heading, body = dict(content.tabs)["Identity"][0]
        assert heading == "1 profile value in this flow"
        text = _plain(body)
        for words in (
            "Advertising ID",
            "request body, sha256 of the lower-case value",
            "sent to Meta, third party, high confidence",
            "event=INSTALL&advertiser_id=3b9f0c1d&os=android",
        ):
            assert words in text, words
        assert not set(privacy_fakes.GLYPHS) & set(text)
        # The matched bytes are drawn on a warn background.
        snippet = body.renderables[0]
        marked = [s for s in snippet.spans if "on" in str(s.style)]
        assert marked
        assert snippet.plain[marked[0].start : marked[0].end] == "3b9f0c1d"
        assert lens_palette().warn.lstrip("#") in str(marked[0].style.bgcolor)
        url = _plain(
            dict(panel.flow_content(panel._row_by_key("f3")).tabs)["Identity"][0][1]
        )
        assert "query string, as is" in url
        assert "first party" in url
        # A flow without profile values has no Identity tab.
        plain = panel.flow_content(panel._row_by_key("f4"))
        assert [name for name, _ in plain.tabs] == ["Summary", "Request", "Response"]


async def test_hits_found_later_mark_rows_already_drawn(flow_dir, monkeypatch):
    import privacy_fakes
    from privacy_fakes import flow_hit

    fake = privacy_fakes.install(monkeypatch, [flow_hit("flow-2")])
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        assert _tinted(panel.table) == {"f2"}
        panel.table.move_cursor(row=0)
        await settle(pilot)
        fake.add(flow_hit("flow-4", "GPS", "GPS", party="third", recipient="Google"))
        await until(
            pilot,
            lambda: "f4" in _tinted(panel.table)
            and str(panel.table.get_cell("f4", "ident")) == "GPS",
        )
        assert panel.table.cursor_row == 0  # not yanked
        await until(
            pilot, lambda: "2 carry profile values" in ms._lens_captions["network"][1]
        )


async def test_narrow_lens_drops_the_identity_column_but_keeps_the_tint(
    flow_dir, monkeypatch
):
    import privacy_fakes

    privacy_fakes.install(monkeypatch, _privacy_hits())
    app = _app()
    async with app.run_test(size=(96, 40)) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        assert "ident" not in [str(c.value) for c in panel.table.columns]
        assert _tinted(panel.table) == {"f2", "f3"}


async def test_no_identity_column_without_a_profile(flow_dir, monkeypatch):
    import privacy_fakes

    privacy_fakes.install(monkeypatch, [], active=False)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        assert "ident" not in [str(c.value) for c in panel.table.columns]
        assert len(panel.table.columns) == 7
        assert _tinted(panel.table) == set()


async def test_identity_column_appears_when_markers_arrive_later(flow_dir, monkeypatch):
    """Markers found after the first draw (the identity service reads them
    on a thread) add the Identity column without ``!``; ``!`` only filters.
    """
    import privacy_fakes

    fake = privacy_fakes.install(monkeypatch, [], active=False)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        total = panel.table.row_count
        assert "ident" not in [str(c.value) for c in panel.table.columns]
        fake.is_active = True  # the scan got its markers
        await until(
            pilot, lambda: "ident" in [str(c.value) for c in panel.table.columns]
        )
        assert not panel._profile_only
        assert panel.table.row_count == total  # no row filtered


async def test_identity_column_whenever_identity_mode_is_on(flow_dir, monkeypatch):
    import privacy_fakes

    from sandroid.config import get_config

    privacy_fakes.install(monkeypatch, [], active=False)  # no markers yet
    monkeypatch.setattr(get_config().identity, "mode", "profile")
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        widths = {str(c.key.value): c.width for c in panel.table.columns.values()}
        assert "ident" in widths
        assert not panel._profile_only
        assert widths["ident"] == 18
        assert widths["req"] >= 24  # Request keeps a readable width


async def test_each_row_looks_up_its_profile_values_once(flow_dir, monkeypatch):
    """The "!" filter, "/" and the Identity cell share one lookup per row and
    service revision; a new hit (new revision) looks up again.
    """
    import privacy_fakes
    from privacy_fakes import flow_hit

    fake = privacy_fakes.install(monkeypatch, _privacy_hits())
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        flows = {r.flow_id for r in panel._model() if r.flow_id}
        panel._profile_only = True
        panel._filter = "a"
        fake.tag_calls = 0
        panel._rebuild()
        assert 0 < fake.tag_calls <= len(flows)
        fake.tag_calls = 0
        panel._rebuild()
        assert fake.tag_calls == 0  # same revision: all cached
        fake.add(flow_hit("flow-4", "GPS", "GPS"))
        await until(pilot, lambda: "f4" in _tinted(panel.table))
        assert fake.tag_calls <= len(flows)


async def test_a_session_switch_redraws_every_row(flow_dir, monkeypatch):
    """The service's ``None`` notification (records of another session
    loaded) re-marks every row, not only the ones of new hits.
    """
    import privacy_fakes
    from privacy_fakes import flow_hit

    fake = privacy_fakes.install(monkeypatch, _privacy_hits())
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        assert _tinted(panel.table) == {"f2", "f3"}
        fake.reset([flow_hit("flow-4", "GPS", "GPS")])
        await until(pilot, lambda: _tinted(panel.table) == {"f4"})


async def test_an_ai_highlight_wins_the_tint_over_profile_values(flow_dir, monkeypatch):
    """A higher-priority source (AI marks) tints a row that also carries
    profile values in its own colour; the Identity column keeps the privacy
    words and colours, and the privacy-only row keeps the warn tint.
    """
    import privacy_fakes
    from rich.style import Style

    from sandroid.tui.row_annotations import (
        LENS_NETWORK,
        PRIORITY_AI,
        Annotation,
        bg_style,
        registry,
        row_tint,
    )
    from sandroid.tui.themes import lens_palette

    class _Ai:
        source = "ai"
        revision = 0
        keys: frozenset = frozenset()

        def annotations_for(self, lens, key):
            if lens != LENS_NETWORK or key not in self.keys:
                return []
            return [
                Annotation(
                    "ai",
                    "matches",
                    tint_role="accent",
                    priority=PRIORITY_AI,
                    tint_amount=0.2,
                )
            ]

        def filter_predicate(self, lens):
            return None

    privacy_fakes.install(monkeypatch, _privacy_hits())
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        table = panel.table
        assert _tinted(table) == {"f2", "f3"}
        warn = bg_style(row_tint("warn")).bgcolor
        ai_tint = bg_style(row_tint("accent", 0.2)).bgcolor
        assert ai_tint != warn

        def bg(key):
            return table._get_row_style(table.get_row_index(key), Style()).bgcolor

        assert bg("f2") == warn
        cursor = table.cursor_row
        ai = _Ai()
        ai.keys = frozenset({"flow-2", "flow-4"})  # flow ids, not row keys
        registry().register(ai)
        await until(pilot, lambda: bg("f2") == ai_tint)
        assert bg("f4") == ai_tint  # no profile values: AI tint only
        assert bg("f3") == warn  # profile values only: the privacy tint
        assert table.cursor_row == cursor
        cell = table.get_cell("f2", "ident")
        assert str(cell) == "Ad ID"
        assert cell.spans[0].style == lens_palette().warn
        # The AI source goes away: the privacy tint is back.
        registry().unregister("ai")
        await until(pilot, lambda: bg("f2") == warn)
        assert bg("f4") is None


def test_privacy_annotations_provider(monkeypatch):
    """The privacy row-annotation provider: one note per value in plain
    words, coloured by party, the warn tint; flow ids and canonical paths as
    keys; new records and session switches reach the registry.
    """
    import privacy_fakes
    from privacy_fakes import file_hit

    from sandroid.services import privacy_scan
    from sandroid.tui.row_annotations import (
        LENS_FILES,
        LENS_NETWORK,
        PRIORITY_PRIVACY,
        registry,
    )

    prefs = "/data/data/de.fittrack.pro/shared_prefs/p.xml"
    fake = privacy_fakes.install(monkeypatch, [*_privacy_hits(), file_hit(prefs)])
    reg = registry()
    provider = reg.provider("privacy")
    assert isinstance(provider, privacy_scan.PrivacyAnnotations)
    assert privacy_scan.register_annotations(fake) is provider  # idempotent
    assert fake.listeners == [provider.on_record]

    (meta,) = reg.annotations_for(LENS_NETWORK, "flow-2")
    assert (meta.source, meta.label, meta.colour_role) == ("privacy", "Ad ID", "warn")
    assert meta.reason == "sent to Meta, third party, sha256 of the lower-case value"
    assert (meta.tint_role, meta.priority) == ("warn", PRIORITY_PRIVACY)
    assert meta.group == "advertising_id"
    (mail,) = reg.annotations_for(LENS_NETWORK, "flow-3")
    assert (mail.label, mail.colour_role) == ("Email", "accent")
    assert mail.reason == "sent to fittrack.de, first party, as is"
    assert reg.annotations_for(LENS_NETWORK, "flow-4") == []
    assert reg.annotations_for(LENS_NETWORK, "f2") == []  # row keys are not keys
    # Files: the canonical path (an alias finds the same file).
    (stored,) = reg.annotations_for(LENS_FILES, prefs)
    assert (stored.label, stored.colour_role) == ("Email", "accent")
    assert stored.reason == "stored on the device, as is"
    alias = prefs.replace("/data/data/", "/data/user/0/")
    assert reg.annotations_for(LENS_FILES, alias) == [stored]
    assert provider.filter_predicate(LENS_NETWORK) is None
    no_glyphs = "".join(a.label + a.reason for a in (meta, mail, stored))
    assert not set(privacy_fakes.GLYPHS) & set(no_glyphs)

    seen = []
    reg.subscribe(lambda lens, keys: seen.append((lens, keys)))
    fake.add(file_hit(alias, "GPS", "GPS"))
    fake.reset([])
    assert seen == [(LENS_FILES, frozenset({prefs})), (None, None)]
    assert reg.annotations_for(LENS_NETWORK, "flow-2") == []  # new revision

    privacy_scan.unregister_annotations()
    assert reg.provider("privacy") is None
    assert fake.listeners == []


def test_privacy_row_tint_style_is_cached():
    from sandroid.tui.row_annotations import bg_style, row_tint

    first = bg_style(row_tint("warn"))
    assert bg_style(row_tint("warn")) is first
    assert first.bgcolor is not None


def test_markers_sharing_a_tag_show_it_once():
    from sandroid.services.privacy_scan import TagInfo

    def tag(marker_id, word, party="unknown"):
        return TagInfo(
            tag=word,
            label=word,
            marker_id=marker_id,
            party=party,
            direction="sent",
            encoded=False,
            approx=False,
            confidence="high",
        )

    tags = [
        tag("gaid", "AdID"),
        tag("gps.latitude", "GPS"),
        tag("gps.longitude", "GPS"),
    ]
    assert np_mod.tags_plain(tags) == "AdID, GPS"
    assert np_mod.tag_words(tags).plain == "AdID, GPS"


async def test_reveal_lands_on_a_flow_the_hidden_lens_has_not_loaded(flow_dir):
    """J from another lens (Identity, Sessions) on a flow logged while the
    Network lens was hidden: the lens loads it and puts the cursor on it.
    """
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        await pilot.press("1")
        await settle(pilot)
        write_flows(flow_dir, time.time(), specs=_SPECS[1:2], start_seq=200)
        assert panel._listed_flow("flow-200") is None  # hidden: not polled
        ms.switch_lens("network")
        # Nothing to open yet (no record): False, so a caller can fall back;
        # the lens polls and still puts the cursor on the flow once listed.
        assert not panel.reveal_flow("flow-200")
        assert panel._pending_reveal is not None
        await until(
            pilot,
            lambda: getattr(ms.inspector_content, "key", None) == "network:row:f200",
        )
        row_key = panel.table.coordinate_to_cell_key(
            (panel.table.cursor_row, 0)
        ).row_key.value
        assert row_key == "f200"
        assert panel._pending_reveal is None
        # A flow that is not in the log: its record opens it, nothing else.
        record = {"id": "flow-gone", "host": "gone.example", "ts_start": time.time()}
        assert panel.reveal_flow("flow-gone", record=record)
        await until(pilot, lambda: panel._pending_reveal is None)
        assert ms.inspector_content.key.startswith("network:row:")
        assert panel.table.row_count  # the table is unchanged


async def test_caption_follows_ca_removal_and_app_proxy_changes(flow_dir, monkeypatch):
    """E2E: after Remove CA the caption still said "CA installed", after the
    App Proxy was removed still "app proxies 1" -- until a lens switch.
    Both are now repainted from STATE_CHANGED (published off the UI thread).
    """
    import threading

    from rich.text import Text

    from sandroid.core import proxy_manager as pm

    routes: dict[str, str] = {"org.mozilla.firefox": "ours"}
    monkeypatch.setattr(
        pm.FocusManager, "app_proxies_cached", lambda self: dict(routes)
    )
    monkeypatch.setattr(pm.FocusManager, "lane_health_cached", lambda self: {})
    device = {"ca": True}
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("2")
        await settle(pilot)
        panel = ms.query_one("#network-panel", NetworkPanel)
        mitm = panel.mitm
        monkeypatch.setattr(mitm._service, "is_running", lambda: True)
        monkeypatch.setattr(mitm._service, "ssl_unpin_is_active", lambda: False)
        probes: list[str] = []

        def probe():
            probes.append(threading.current_thread().name)
            return ("none", "", device["ca"], False)

        monkeypatch.setattr(mitm, "_compute_setup_state", probe)
        mitm._ca_ok = True
        panel.refresh_header()

        def title() -> str:
            return Text.from_markup(ms._lens_captions["network"][0] or "").plain

        assert "app proxies 1" in title()
        assert "CA ● installed" in title()

        def publish(fn, *args) -> None:
            worker = threading.Thread(target=fn, args=args)
            worker.start()
            worker.join()

        device["ca"] = False
        publish(pm.publish_ca_change, None, False)
        await until(pilot, lambda: "CA ○ not installed" in title())
        await until(pilot, lambda: not mitm._state_probe_busy)
        assert probes
        assert "MainThread" not in probes  # the device read is off-thread
        assert "CA ○ not installed" in title()

        routes.clear()
        publish(pm.FocusManager._publish_health, None)
        await until(pilot, lambda: "app proxies" not in title())

        device["ca"] = True
        publish(pm.publish_ca_change, None, True)
        await until(pilot, lambda: "CA ● installed" in title())
        assert "CA ○ not installed" not in title()


async def test_ca_change_of_another_device_leaves_the_caption(flow_dir, monkeypatch):
    from sandroid.core import proxy_manager as pm
    from sandroid.core.adb import Adb

    monkeypatch.setattr(Adb, "_target_device", "emulator-5570")
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("2")
        await settle(pilot)
        mitm = ms.query_one("#network-panel", NetworkPanel).mitm
        kicks = []
        monkeypatch.setattr(mitm, "_kick_state_refresh", lambda: kicks.append(1))
        mitm._ca_ok = True
        pm.publish_ca_change("emulator-5554", False)
        await settle(pilot)
        assert mitm._ca_ok
        assert kicks == []
        pm.publish_ca_change("emulator-5570", False)
        await until(pilot, lambda: not mitm._ca_ok)
        assert kicks == [1]


# --------------------------------------------------------------------------
# Network method (W), its status line, and Shift+T with relay-named flows
# --------------------------------------------------------------------------


def test_app_only_matches_shared_uid_lists():
    from sandroid.tui.widgets.network_panel import app_matches

    assert app_matches(PKG, PKG)
    assert app_matches(f"com.other,{PKG}", PKG)
    assert not app_matches("", PKG)
    assert not app_matches("de.fittrack", PKG)


async def test_app_only_keeps_relay_named_device_flows(flow_dir):
    """Shift+T: device-proxy flows the identity relay named (``via``
    device, shared UID lists included) count as the app's own.
    """
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("2")
        await settle(pilot)
        panel = ms.query_one("#network-panel", NetworkPanel)
        specs = [
            ("GET", "api.fittrack.de", "/a", 200, PKG, None, None, None),
            ("GET", "api.fittrack.de", "/b", 200, f"com.x,{PKG}", None, None, None),
            ("GET", "cdn.other.com", "/c", 200, "com.other.app", None, None, None),
            ("GET", "api.unnamed.com", "/d", 200, "", None, None, None),
        ]
        write_flows(flow_dir, time.time() - 100, specs)
        panel.poll_now()
        await until(pilot, lambda: panel.table.row_count > 0)
        await pilot.press("N")
        await pilot.press("T")
        await settle(pilot)
        paths = {
            panel._row_by_key(
                panel.table.coordinate_to_cell_key((i, 0)).row_key.value
            ).path
            for i in range(panel.table.row_count)
        }
        assert paths == {"/a", "/b"}


async def test_network_method_line_and_W_opens_the_picker(flow_dir, monkeypatch):
    from textual.widgets import RadioButton

    from sandroid.services import network_method as nm
    from sandroid.tui.modals import proxy_modal

    applied = []
    monkeypatch.setattr(
        proxy_modal,
        "run_method_apply",
        lambda app, preset, pin, **kw: applied.append((preset, pin)),
    )
    service = nm.NetworkMethodService(actions=None)
    monkeypatch.setattr(service, "refresh", lambda **kw: None)
    monkeypatch.setattr(nm, "_INSTANCE", service)
    service._store(
        nm.MethodSnapshot(spotlight=PKG, device_proxy="ours", kill_switch=True)
    )
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("2")
        await settle(pilot)
        panel = ms.query_one("#network-panel", NetworkPanel)
        line = str(panel.query_one("#net-method").render())
        assert line.startswith("Network method: Whole device.")
        assert "Mitmproxy stopped" in line
        assert "W changes it" in line
        await pilot.press("W")
        await until(
            pilot, lambda: isinstance(app.screen, proxy_modal.NetworkMethodModal)
        )
        modal = app.screen
        assert modal.query_one("#nm-whole_device", RadioButton).value
        assert modal.query_one("#nm-custom", RadioButton).disabled
        # A change elsewhere repaints the open dialog (from a worker thread).
        import threading

        snap = nm.MethodSnapshot(spotlight=PKG, lanes={PKG: "ours"})
        worker = threading.Thread(target=service._store, args=(snap,))
        worker.start()
        worker.join()
        await until(pilot, lambda: modal.query_one("#nm-this_app", RadioButton).value)
        modal.query_one("#nm-off", RadioButton).value = True  # the user's pick
        await settle(pilot)
        # N6: a later event (the dialog's own refresh lands ~1 s after it
        # opens) updates the status line, never the pending choice.
        later = nm.MethodSnapshot(
            spotlight=PKG, device_proxy="ours", kill_switch=True, refused=3
        )
        worker = threading.Thread(target=service._store, args=(later,))
        worker.start()
        worker.join()
        await until(pilot, lambda: "(3)" in str(modal.query_one("#nm-status").render()))
        assert modal.query_one("#nm-off", RadioButton).value
        assert not modal.query_one("#nm-whole_device", RadioButton).value
        await pilot.press("ctrl+s")
        # The untouched pinning box sends no pinning change (None).
        await until(pilot, lambda: applied == [("off", None)])
        assert not isinstance(app.screen, proxy_modal.NetworkMethodModal)
        # Esc closes it (sync action_cancel) without applying anything.
        await pilot.press("W")
        await until(
            pilot, lambda: isinstance(app.screen, proxy_modal.NetworkMethodModal)
        )
        await pilot.press("escape")
        await until(
            pilot, lambda: not isinstance(app.screen, proxy_modal.NetworkMethodModal)
        )
        assert applied == [("off", None)]


def _method_modal_app(modal):
    from textual.app import App

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(modal)

    return _App()


async def test_method_dialog_pinning_is_sent_only_when_toggled(monkeypatch):
    """N6: "Defeat pinning" is tri-state: an untouched box never starts or
    stops a bypass, and a later event never resets a box the user toggled.
    N20: the footer shows the dialog's own hint, in words, also while the
    radio row has the focus.
    """
    import re
    import threading
    from dataclasses import replace

    from textual.widgets import Checkbox

    from sandroid.services import network_method as nm
    from sandroid.tui.modals import proxy_modal
    from sandroid.tui.modals.base import KeyHintFooter

    applied = []
    monkeypatch.setattr(
        proxy_modal,
        "run_method_apply",
        lambda app, preset, pin, **kw: applied.append((preset, pin)),
    )
    service = nm.NetworkMethodService(actions=None)
    monkeypatch.setattr(service, "refresh", lambda **kw: None)
    monkeypatch.setattr(nm, "_INSTANCE", service)
    whole = nm.MethodSnapshot(
        spotlight=PKG, device_proxy="ours", kill_switch=True, pinning="on"
    )
    service._store(whole)

    modal = proxy_modal.NetworkMethodModal()
    app = _method_modal_app(modal)
    async with app.run_test(size=(120, 40)) as pilot:
        await until(pilot, lambda: app.screen is modal and app.focused is not None)
        footer = str(modal.query_one(KeyHintFooter).render())
        assert "Ctrl+S=Apply" in footer
        assert "Up/Down" in footer
        assert not re.search("[←-⇿]", footer)  # no arrow glyphs
        assert modal.query_one("#nm-pinning", Checkbox).value  # live state
        await pilot.press("ctrl+s")
        await until(pilot, lambda: applied == [("whole_device", None)])

    applied.clear()
    modal = proxy_modal.NetworkMethodModal()
    app = _method_modal_app(modal)
    async with app.run_test(size=(120, 40)) as pilot:
        await until(pilot, lambda: app.screen is modal and app.focused is not None)
        box = modal.query_one("#nm-pinning", Checkbox)
        box.value = False  # the user unticks it
        await settle(pilot)
        worker = threading.Thread(
            target=service._store, args=(replace(whole, refused=9),)
        )
        worker.start()
        worker.join()
        await until(pilot, lambda: "(9)" in str(modal.query_one("#nm-status").render()))
        assert not box.value  # not reset by the event
        await pilot.press("ctrl+s")
        await until(pilot, lambda: applied == [("whole_device", False)])


async def test_kill_switch_checkbox_works_without_a_device_proxy(monkeypatch):
    """N2: a Kill switch left without its device proxy (every app offline) is
    shown checked, and unticking it removes it; ticking it without a proxy
    says why nothing happens.
    """
    from types import SimpleNamespace

    from textual.widgets import Checkbox

    from sandroid.core import device_guard as dg
    from sandroid.tui.modals import proxy_modal

    for name in (
        "_refresh_device_proxy_status",
        "_refresh_device_info",
        "_detect_certificates",
    ):
        monkeypatch.setattr(proxy_modal.ProxyModal, name, lambda self: None)
    monkeypatch.setattr(
        proxy_modal.ProxyModal, "_start_app_proxy_apply", lambda self, *a: None
    )
    monkeypatch.setattr(
        proxy_modal,
        "get_focus_manager",
        lambda: SimpleNamespace(app_proxies_cached=dict),
    )
    guard = dg.DeviceGuard()
    monkeypatch.setattr(dg, "_INSTANCE", guard)
    monkeypatch.setattr(dg.Adb, "get_target_device", staticmethod(lambda: "emu-1"))
    calls = []
    monkeypatch.setattr(
        proxy_modal.ProxyModal,
        "_start_kill_switch_apply",
        lambda self, enabled: calls.append(enabled),
    )
    notes = []
    for start, wanted in ((True, False), (False, True)):
        guard._views["emu-1"] = dg.GuardView(kill_switch=start, checked=True)
        modal = proxy_modal.ProxyModal()
        app = _method_modal_app(modal)
        async with app.run_test(size=(120, 50)) as pilot:
            await until(pilot, lambda app=app, modal=modal: app.screen is modal)
            monkeypatch.setattr(
                modal, "notify", lambda msg, **kw: notes.append(str(msg))
            )
            monkeypatch.setattr(
                modal,
                "_proxy_manager",
                SimpleNamespace(unset_proxy=lambda: (True, "Proxy cleared")),
            )
            monkeypatch.setattr(
                "sandroid.core.proxy_manager._reverse_registered", lambda port: False
            )
            box = modal.query_one("#kill-switch-checkbox", Checkbox)
            assert box.value is start  # the device's truth, a leftover too
            box.value = wanted
            await settle(pilot)
            modal._apply_commit(None)  # no device proxy
            await settle(pilot)
    assert calls == [False]  # removed without a device proxy
    assert any("needs a device proxy" in n for n in notes)


async def test_proxy_dialog_method_tab_and_kill_switch(monkeypatch):
    from types import SimpleNamespace

    from textual.app import App
    from textual.widgets import Checkbox, RadioButton, TabbedContent

    from sandroid.services import network_method as nm
    from sandroid.tui.modals import proxy_modal

    for name in (
        "_refresh_device_proxy_status",
        "_refresh_device_info",
        "_detect_certificates",
    ):
        monkeypatch.setattr(proxy_modal.ProxyModal, name, lambda self: None)
    monkeypatch.setattr(
        proxy_modal,
        "get_focus_manager",
        lambda: SimpleNamespace(app_proxies_cached=dict),
    )
    applied = []
    monkeypatch.setattr(
        proxy_modal,
        "run_method_apply",
        lambda app, preset, pin, **kw: applied.append(preset),
    )
    service = nm.NetworkMethodService(actions=None)
    monkeypatch.setattr(service, "refresh", lambda **kw: None)
    monkeypatch.setattr(nm, "_INSTANCE", service)
    modal = proxy_modal.ProxyModal()

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(modal)

    app = _App()
    async with app.run_test(size=(120, 50)) as pilot:
        await until(pilot, lambda: app.screen is modal and app.focused is not None)
        tabs = modal.query_one("#proxy-tabs", TabbedContent)
        assert tabs.active == "tab-device"  # opens where it always did
        # A Checkbox label never wraps: the label is short, the explanation
        # is a note below it that wraps (the one-line label was cut off).
        box = modal.query_one("#kill-switch-checkbox", Checkbox)
        assert str(box.label) == "Kill switch"
        note = modal.query_one("#kill-switch-note")
        assert "the rest is refused" in str(note.render())
        await pilot.press("shift+left")
        await until(pilot, lambda: tabs.active == "tab-method")
        modal.query_one("#nm-this_app", RadioButton).value = True
        await pilot.press("ctrl+s")
        await until(pilot, lambda: applied == ["this_app"])


async def test_device_radios_start_on_the_choice_and_space_types(monkeypatch):
    """N3-B7: back on the Device tab (Shift+Left), Down + Space picks the
    option after the current one, never Off from a stray cursor; Space in
    the External field types a space instead of replacing the address.
    V5: the Kill switch label fits (keeps "refused").
    """
    from types import SimpleNamespace

    from textual.app import App
    from textual.widgets import Checkbox, Input, RadioSet, TabbedContent

    from sandroid.services import network_method as nm
    from sandroid.tui.modals import proxy_modal

    for name in (
        "_refresh_device_proxy_status",
        "_refresh_device_info",
        "_detect_certificates",
    ):
        monkeypatch.setattr(proxy_modal.ProxyModal, name, lambda self: None)
    monkeypatch.setattr(
        proxy_modal,
        "get_focus_manager",
        lambda: SimpleNamespace(app_proxies_cached=dict),
    )
    service = nm.NetworkMethodService(actions=None)
    monkeypatch.setattr(service, "refresh", lambda **kw: None)
    monkeypatch.setattr(nm, "_INSTANCE", service)
    modal = proxy_modal.ProxyModal()

    class _App(App):
        def on_mount(self) -> None:
            self.push_screen(modal)

    app = _App()
    async with app.run_test(size=(120, 35)) as pilot:
        await until(pilot, lambda: app.screen is modal and app.focused is not None)
        radios = modal.query_one("#device-radio-set", RadioSet)
        # The device probe found our proxy via adb reverse.
        modal._on_device_probe_done(
            {"device": {"state": "ours", "addr": "127.0.0.1:8080"}}
        )
        await settle(pilot)
        tabs = modal.query_one("#proxy-tabs", TabbedContent)
        await pilot.press("shift+left")
        await until(pilot, lambda: tabs.active == "tab-method")
        await pilot.press("shift+right")
        await until(pilot, lambda: tabs.active == "tab-device")
        await until(pilot, lambda: app.focused is radios)
        assert radios.pressed_button.id == "device-radio-reverse"
        await pilot.press("up", "space")
        await settle(pilot)
        assert radios.pressed_button.id == "device-radio-external"
        await pilot.press("down", "down", "space")
        await settle(pilot)
        # Wraps from adb reverse straight to Off (no caption in between).
        assert radios.pressed_button.id == "device-radio-off"

        field = modal.query_one("#device-ext-input", Input)
        field.value = "1.2.3.4:8080"
        field.focus()
        await settle(pilot)
        await pilot.press("space")
        await settle(pilot)
        assert field.value.strip() == "1.2.3.4:8080"
        assert field.value != " "

        box = modal.query_one("#kill-switch-checkbox", Checkbox)
        # The label is short; the "refused" explanation is the note below
        # it, which wraps instead of being cut.
        assert str(box.label) == "Kill switch"
        note = str(modal.query_one("#kill-switch-note").render())
        assert note.rstrip(".").endswith("refused")
        assert len(str(box.label)) <= 70

        # V5: the CA actions are on screen at 120x35 without scrolling.
        tabs.active = "tab-ca"
        await settle(pilot)
        remove = modal.query_one("#btn-remove-ca")
        assert remove.region.height > 0
        assert remove.region.bottom <= 35


def test_bypass_listener_on_the_ui_thread_only_schedules(monkeypatch):
    """The bypass state callback can run on the UI thread (a new selection
    disarms from UI code): it must only schedule, never marshal or block.
    """
    import threading

    from sandroid.services import network_method as nm

    service = nm.NetworkMethodService(actions=None)
    started = []
    monkeypatch.setattr(service, "refresh_now", lambda **kw: started.append(1))
    assert threading.current_thread() is threading.main_thread()
    service._on_bypass_state()
    for _ in range(100):
        if started:
            break
        time.sleep(0.01)
    assert started == [1]


@pytest.mark.parametrize(
    ("app", "ca", "why_part", "next_part"),
    [
        ("org.mozilla.firefox", "installed", "Firefox uses its own certificate", "h"),
        ("org.mozilla.firefox", "missing", "own certificate store", "friTap"),
        ("com.example", "installed", "although the CA is installed", "Ctrl+P"),
        ("com.example", "missing", "The CA is not installed", "Ctrl+N"),
        ("com.example", "unknown", "or the CA is not trusted yet", "Ctrl+N"),
    ],
)
def test_tls_failure_why_uses_the_known_ca_state(app, ca, why_part, next_part):
    """N3-V6: the "Why" of a TLS failure follows the CA state and names an
    app with its own trust store instead of always blaming pinning or the CA.
    """
    why, nxt = np_mod.tls_failure_why("cert", app, ca)
    assert why_part in why
    assert next_part in nxt
    if ca == "installed":
        assert "installs the CA" not in nxt


def test_fritap_did_not_start_is_red_words(monkeypatch):
    """N3-B5/V7: a failed or hung friTap start reads "did not start: <reason>"
    in the bad colour (caption and Inspector), not a muted line.
    """
    from sandroid.analysis import fritap as fritap_mod
    from sandroid.tui.themes import lens_palette
    from sandroid.tui.widgets.fritap_panel import FriTapPanel

    pal = lens_palette()
    panel = FriTapPanel()
    monkeypatch.setattr(panel, "is_running", lambda: False)
    try:
        fritap_mod.set_lifecycle(
            "failed", "did not start: no answer from org.x after 90 s"
        )
        assert panel.caption_token() == f"[{pal.bad}]friTap did not start[/]"
        head = dict(panel.status_rows())["friTap"]
        assert head == f"[{pal.bad}]did not start: no answer from org.x after 90 s[/]"
    finally:
        fritap_mod.set_lifecycle("stopped", "")


def test_recent_failures_are_red_words():
    from sandroid.tui.themes import lens_palette

    pal = lens_palette()
    text = np_mod._recent_text(["started", "✗ ERROR: unable to intercept"])
    assert text.plain == "started\nERROR: unable to intercept"
    styles = {str(span.style) for span in text.spans}
    assert pal.bad in styles


def test_activity_log_task_errors_are_red():
    from sandroid.tui.widgets.activity_log import ActivityLog

    colors = {"error": "#ff0000", "warning": "#ffff00"}
    red = ActivityLog._level_colored("[error]friTap did not start: x[/error]", colors)
    assert red == "[#ff0000]friTap did not start: x[/]"
    assert ActivityLog._level_colored("ERROR: Error: boom", colors).startswith(
        "[#ff0000]"
    )
    assert ActivityLog._level_colored("plain line", colors) == "plain line"
