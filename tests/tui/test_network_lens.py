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
    # Labels come from Dexray Insight's tracker DB (the one intentional
    # change vs the old built-in table: unity3d.com is Unity, not Unity Ads).
    import sandroid.tui.widgets.network_panel as net

    if not net._insight_labeller():
        pytest.skip("Dexray Insight >= 2.0 not importable here (fallback table)")
    assert recipient_of("unity3d.com") == ("Unity", True)
    assert recipient_of("unityads.unity3d.com") == ("Unity Ads", True)


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


async def test_empty_state_and_space_starts_mitm(flow_dir, monkeypatch):
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
        # Enter is "inspect" everywhere: with nothing captured it does nothing.
        await pilot.press("enter")
        await _settle(pilot)
        assert calls == []
        assert not ms.inspector_is_open
        await pilot.press("space")
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
        await pilot.press("v")  # v is only "review" (Runs lens) now: no-op
        await _settle(pilot)
        assert "app only" not in ms._lens_captions["network"][1]
        await pilot.press("T")
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
        await _settle(pilot)
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
        await _wait(
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
        await _wait(pilot, lambda: panel._filter == "200")
        statuses = {
            str(panel.table.get_row_at(i)[3]) for i in range(panel.table.row_count)
        }
        assert statuses == {"200"}
        # Esc in the input: filter cleared, input closed, back on the table
        await pilot.press("escape")
        await _settle(pilot)
        assert panel._filter == ""
        assert panel.table.row_count == shown
        assert not panel.query_one("#net-filter").has_class("-open")
        assert app.focused is panel.table
        # an applied filter with the input closed: Esc clears it too
        panel.set_filter("✗")
        await _settle(pilot)
        assert panel.table.row_count == 1  # the reset upload
        await pilot.press("escape")
        await _settle(pilot)
        assert panel._filter == ""
        assert panel.table.row_count == shown


async def test_end_and_home_jump_to_the_last_and_first_row(flow_dir):
    """L14: End scrolled sideways instead of reaching the newest flow."""
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _lens_with_flows(app, pilot, flow_dir)
        panel.table.focus()
        await pilot.press("home")
        await _settle(pilot)
        assert panel.table.cursor_row == 0
        await pilot.press("end")
        await _settle(pilot)
        assert panel.table.cursor_row == panel.table.row_count - 1


def test_size_column_fits_three_digit_kilobytes():
    """L2: "↓ 190.9 K" lost its B."""
    panel = NetworkPanel()
    layout = [
        ("time", "Time", 8),
        ("who", "Recipient", 18),
        ("req", "Request", 40),
        ("status", "Status", 9),
        ("size", "Size", 10),
    ]
    row = FlowRow(key="f1", ts=0.0, host="a.io", status=200, resp_bytes=195482)
    size = panel._cells(row, layout)[4].plain
    assert size == "↓ 190.9 KB"
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
        await _settle(pilot)
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
        await _wait(pilot, lambda: any(r.host == "other.example" for r in panel._live))
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
        await _wait(pilot, lambda: sum(r.kind == "tls" for r in panel._live) == 30)
        await _wait(pilot, lambda: not panel._status_pending)
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
        await _wait(pilot, lambda: ms._lens_captions["network"][1])
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
        await _settle(pilot)
        assert opened == [f"{svc.web_url(with_token=False)}?token=s3cret-token"]
        toast = [n.message for n in app._notifications]
        assert any("Opened mitmweb UI" in m and "token" in m for m in toast)
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
            await _wait(pilot, lambda: "starting" in ms._lens_captions["network"][0])
            running["on"] = True
            fritap_mod.set_lifecycle("running", "org.wikipedia")
            await _wait(pilot, lambda: "friTap ●" in ms._lens_captions["network"][0])
            fritap_mod.set_lifecycle("hung", "org.wikipedia is not responding")
            await _wait(
                pilot, lambda: "not responding" in ms._lens_captions["network"][0]
            )
            head = dict(fritap.status_rows())["friTap"]
            assert "h stops friTap" in head
            fritap_mod.set_lifecycle("stopping", "org.wikipedia")
            await _wait(pilot, lambda: "stopping" in ms._lens_captions["network"][0])
            running["on"] = False
            fritap_mod.set_lifecycle("stopped", "agent still unloading")
            await _wait(pilot, lambda: "friTap" not in ms._lens_captions["network"][0])
            assert "agent still unloading" in dict(fritap.status_rows())["friTap"]
            # NEW-2: a failed unload dropped friTap from the caption (read
            # like a clean stop); only the tab said "✗ failed".
            fritap_mod.set_lifecycle("failed", "agent stuck in org.wikipedia")
            await _wait(
                pilot, lambda: "friTap ✗ failed" in ms._lens_captions["network"][0]
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
    assert "unpin ✓" in mitm.status_caption()

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
        ms = await _boot(app, pilot)
        await pilot.press("2")
        await _settle(pilot)
        panel = ms.query_one("#network-panel", NetworkPanel)
        assert not (flow_dir / "flows.jsonl").exists()  # new session: no flows
        ms.set_scope(str(run), label="#3 Run C")
        await _wait(pilot, lambda: not panel._review_loading)
        await _settle(pilot)
        assert len(panel._review) == len(_SPECS)
        assert panel._review_data.source == "bundle"
        # replay 1 only: api.fittrack.de + app-measurement.com
        assert panel.table.row_count == 2
        title, info = ms._lens_captions["network"]
        assert "flows of the replays" in title
        assert "A: 2 dry run · 3 setup hidden" in info
        assert panel.check_action("toggle_phases", ()) is True

        await pilot.press("A")
        await _settle(pilot)
        # all phases, OS noise (connectivitycheck, play.googleapis) still hidden
        assert panel.table.row_count == len(_SPECS) - 2
        cells = [str(panel.table.get_row_at(i)[2]) for i in range(5)]
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
        ms = await _boot(app, pilot)
        await pilot.press("2")
        await _settle(pilot)
        panel = ms.query_one("#network-panel", NetworkPanel)
        ms.set_scope(str(run))
        await _wait(pilot, lambda: not panel._review_loading)
        await _settle(pilot)
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
        ms = await _boot(app, pilot)
        await pilot.press("2")
        await _settle(pilot)
        panel = ms.query_one("#network-panel", NetworkPanel)
        ms.set_scope(str(run))
        await _wait(pilot, lambda: not panel._review_loading)
        await _settle(pilot)
        hint = str(panel.query_one("#net-empty-hint").render())
        assert "predates flows stored in its bundle" in hint
