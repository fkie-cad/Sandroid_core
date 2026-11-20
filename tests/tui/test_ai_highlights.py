"""AI row highlights in the Network and Files lenses (the TUI side).

The real highlight store (``sandroid.services.row_highlights``) drives the
lenses through the shared row-annotation registry: row tint, the Highlight
column, the highlight bar, the AI filter (``H``, Esc), ``X`` clear, the
Inspector section, new-since counts and the row sources the AI tools read.
Hermetic: fixture flow log / fixture monitor batches, memory-only store.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import timedelta

import pytest
from pilot_helpers import settle, until
from rich.style import Style
from test_files_lens import (
    AAID,
    CACHE,
    DB,
    MISC,
    PREFS,
    ROOT,
    T0,
    _fse,
    _Harness,
    _items,
    _run_dir,
)
from test_network_lens import (
    _SPECS,
    PKG,
    SIZE,
    _app,
    _lens_with_flows,
    write_flows,
)

from sandroid.services import row_highlights
from sandroid.services.row_highlights import get_row_highlights, tls_row_key
from sandroid.tui.row_annotations import row_tint
from sandroid.tui.themes import (
    HIGHLIGHT_DARK,
    HIGHLIGHT_LIGHT,
    THEMES,
    LensPalette,
    _is_light,
)
from sandroid.tui.widgets import network_panel as np_mod
from sandroid.tui.widgets.files_panel import FilesPanel
from sandroid.tui.widgets.highlight_bar import HighlightBar
from sandroid.tui.widgets.network_panel import NetworkPanel


@pytest.fixture(autouse=True)
def store(monkeypatch, tmp_path):
    """A fresh, memory-only highlight store per test."""
    from sandroid.ai import results
    from sandroid.core.events import EventBus
    from sandroid.services import get_task_service
    from sandroid.tui.widgets.watchlist_view import WatchlistView

    monkeypatch.setattr(results, "session_root", lambda: None)
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path))
    monkeypatch.setattr(WatchlistView, "_device_facts", staticmethod(lambda p: {}))
    get_task_service()._tasks.pop("monitor", None)
    EventBus.get().clear_history()
    row_highlights.reset_for_tests()
    yield get_row_highlights()
    row_highlights.reset_for_tests()
    get_task_service()._tasks.pop("monitor", None)
    EventBus.get().clear_history()


@pytest.fixture
def flow_dir(tmp_path, monkeypatch):
    """The fixture flow log dir (as in test_network_lens)."""
    d = tmp_path / "mitm_flows"
    d.mkdir()
    monkeypatch.setattr(np_mod, "_flow_dir", lambda: d)
    monkeypatch.setattr(NetworkPanel, "_spotlight_package", lambda self: PKG)
    return d


def _cols(table) -> list[str]:
    return [str(c.value) for c in table.columns]


def _cell(table, row_key: str, col: str) -> str:
    return str(table.get_cell(row_key, col))


def _bar(panel) -> str:
    bar = panel.query_one(HighlightBar)
    return str(bar.render()) if bar.has_class("-shown") else ""


def _tint_of(table, row_key: str):
    index = table.get_row_index(row_key)
    return table._get_row_style(index, Style()).bgcolor


def _expected_tint(slot: int):
    return Style(bgcolor=row_tint(f"highlight_{slot}", 0.18)).bgcolor


def _keys(table) -> list[str]:
    return [
        table.coordinate_to_cell_key((i, 0)).row_key.value
        for i in range(table.row_count)
    ]


# --------------------------------------------------------------------------
# theme tokens
# --------------------------------------------------------------------------


def test_highlight_tokens_follow_the_background_in_every_theme():
    def contrast(a: str, b: str) -> float:
        def lum(h: str) -> float:
            h = h.lstrip("#")
            rgb = [int(h[i : i + 2], 16) / 255 for i in (0, 2, 4)]
            lin = [
                c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb
            ]
            return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]

        hi, lo = sorted((lum(a), lum(b)), reverse=True)
        return (hi + 0.05) / (lo + 0.05)

    seen_light = seen_dark = False
    for name, theme in THEMES.items():
        pal = theme.lens
        slots = tuple(getattr(pal, f"highlight_{n}") for n in range(1, 5))
        if _is_light(pal.bg):
            seen_light = True
            assert slots == HIGHLIGHT_LIGHT, name
        else:
            seen_dark = True
            assert slots == HIGHLIGHT_DARK, name
        assert _is_light(pal.bg) == (not theme.is_dark), name
        for colour in slots:
            assert contrast(colour, pal.bg) >= 4.5, (name, colour)
        assert pal.css_variables()["lens-highlight-1"] == slots[0]
    assert seen_light
    assert seen_dark


def test_an_explicit_highlight_colour_is_kept():
    base = THEMES["default"].lens
    fields = {
        f: getattr(base, f)
        for f in base.__dataclass_fields__
        if not f.startswith("highlight_")
    }
    pal = LensPalette(**fields, highlight_2="#123456")
    assert pal.highlight_2 == "#123456"
    assert pal.highlight_1 == HIGHLIGHT_DARK[0]


# --------------------------------------------------------------------------
# keys
# --------------------------------------------------------------------------


def test_H_and_X_shadow_no_app_wide_key_and_are_in_the_help():
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.screens.help_screen import _LENS_EXTRA_ROWS, _panel_binding_rows
    from sandroid.tui.screens.main_screen import MainScreen

    app_keys = {b.key for b in SandroidTUI.BINDINGS} | {
        b.key for b in MainScreen.BINDINGS
    }
    for cls in (NetworkPanel, FilesPanel):
        keys = {b.key: b.action for b in cls.BINDINGS}
        assert keys["H"] == "cycle_highlight_filter"
        assert keys["X"] == "clear_highlights"
        # ``!`` belongs to the privacy scan (Network: profile values only).
        assert keys.get("exclamation_mark") in (None, "toggle_profile_only")
        assert "ctrl+h" not in keys
    assert not {"H", "X"} & app_keys
    for module, cls_name, heading in (
        ("sandroid.tui.widgets.network_panel", "NetworkPanel", "Network lens"),
        ("sandroid.tui.widgets.files_panel", "FilesPanel", "Files lens"),
    ):
        rows = {
            raw: desc for _shown, desc, raw in _panel_binding_rows(module, cls_name)
        }
        assert "AI filter" in rows[("H",)]
        assert "AI highlights" in rows[("X",)]
        assert any("AI filter" in desc for _k, desc, _r in _LENS_EXTRA_ROWS[heading])


# --------------------------------------------------------------------------
# Network lens
# --------------------------------------------------------------------------


async def _network(app, pilot, flow_dir):
    ms, panel = await _lens_with_flows(app, pilot, flow_dir)
    await settle(pilot)
    return ms, panel


async def test_network_tint_column_bar_and_inspector(flow_dir, store):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        table = panel.table
        assert "hl" not in _cols(table)
        assert not _bar(panel)
        assert not panel.check_action("cycle_highlight_filter", ())
        assert not panel.check_action("clear_highlights", ())
        store.create(
            "network",
            "POST to Meta and Analytics",
            short="POST trackers",
            reasons={"flow-2": "POST to graph.facebook.com", "flow-4": "POST /a"},
            origin="ai",
            basis={"judged_at": time.time(), "evaluated": 7},
        )
        await until(pilot, lambda: "hl" in _cols(table))
        assert _cell(table, "f2", "hl") == "POST trackers"
        assert _cell(table, "f3", "hl") == ""
        assert _tint_of(table, "f2") == _expected_tint(1)
        assert _tint_of(table, "f3") is None
        bar = _bar(panel)
        assert "AI highlights" in bar
        assert "POST to Meta and Analytics 2" in bar
        assert "H filter · X clear" in bar
        assert panel.check_action("cycle_highlight_filter", ())
        sections = panel.flow_content(panel._row_by_key("f2")).tabs[0][1]
        titles = [title for title, _body in sections]
        assert titles.count("AI highlight") == 1
        body = str(dict(sections)["AI highlight"])
        assert "AI: POST to graph.facebook.com" in body
        assert "7 flows looked at" in body
        # a second set: two words in the cell, the row keeps the first slot
        store.create("network", "Meta", reasons={"flow-2": "Meta host"})
        await until(pilot, lambda: "," in _cell(table, "f2", "hl"))
        assert _cell(table, "f2", "hl") == "POST trackers, Meta"


async def test_network_ai_filter_noise_bypass_H_cycle_and_esc_order(flow_dir, store):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _network(app, pilot, flow_dir)
        table = panel.table
        shown = table.row_count  # 5: two OS-noise flows hidden
        h1 = store.create(
            "network", "facebook", reasons={"flow-2": "fb", "flow-3": "x"}
        )
        # flow-1 (connectivity check) and flow-5 (gms) are OS noise
        store.create("network", "noise", reasons={"flow-1": "n", "flow-5": "n"})
        await until(pilot, lambda: "hl" in _cols(table))
        table.focus()
        await pilot.press("H")
        await settle(pilot)
        assert store.filter_set("network") == h1.id
        assert sorted(_keys(table)) == ["f2", "f3"]
        # M = what the lens shows without the AI filter (the footer's base:
        # the two OS-noise flows stay out of it).
        assert "AI filter: facebook · 2 of 5" in ms._lens_captions["network"][1]
        assert "filtering" in _bar(panel)
        await pilot.press("H")
        await settle(pilot)
        # the noise set's rows bypass the noise filter while it filters
        assert sorted(_keys(table)) == ["f1", "f5"]
        assert not panel._show_noise
        await pilot.press("H")
        await settle(pilot)
        assert store.filter_set("network") is None
        assert table.row_count == shown
        # Esc: the / filter first, then the AI filter, then falls through
        store.set_filter("network", h1.id)
        panel.set_filter("facebook")
        await settle(pilot)
        assert _keys(table) == ["f2"]
        table.focus()
        await pilot.press("escape")
        await settle(pilot)
        assert panel._filter == ""
        assert store.filter_set("network") == h1.id
        assert sorted(_keys(table)) == ["f2", "f3"]
        await pilot.press("escape")
        await settle(pilot)
        assert store.filter_set("network") is None
        assert table.row_count == shown
        assert panel.handle_escape() is False


async def test_network_filtered_empty_and_follow_counts_shown_rows(flow_dir, store):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        table = panel.table
        store.create(
            "network",
            "facebook",
            reasons={"flow-2": "fb"},
            basis={"judged_at": time.time(), "through_seq": len(_SPECS)},
            filter=True,
        )
        await until(pilot, lambda: table.row_count == 1)
        panel.set_filter("nothing-like-this")
        await settle(pilot)
        head = str(panel.query_one("#net-empty-head").render())
        hint = str(panel.query_one("#net-empty-hint").render())
        assert head.startswith("No highlighted flow matches")
        assert "H or Esc leaves the AI filter" in hint
        panel.set_filter("")
        await settle(pilot)
        panel.set_following(False)
        # two new app flows: not in the set -> hidden, never "new below"
        write_flows(flow_dir, time.time(), specs=_SPECS[1:3], start_seq=100)
        panel.poll_now()
        await until(pilot, lambda: len(panel._live) == len(_SPECS) + 2)
        await settle(pilot)
        assert table.row_count == 1
        assert panel._follow.new_below == 0
        assert "2 new since" in _bar(panel)
        # without the AI filter they count again
        store.set_filter("network", None)
        await settle(pilot)
        write_flows(flow_dir, time.time(), specs=_SPECS[1:2], start_seq=200)
        panel.poll_now()
        await until(pilot, lambda: len(panel._live) == len(_SPECS) + 3)
        await until(pilot, lambda: panel._follow.new_below >= 1)


async def test_network_X_clears_after_confirm_and_the_column_follows_width(
    flow_dir, store, monkeypatch
):
    from sandroid.tui.modals import ConfirmModal

    monkeypatch.setattr(ConfirmModal, "ARM_SECONDS", 0.0)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        table = panel.table
        store.create("network", "empty set")  # no rows: no column yet
        await until(pilot, lambda: _bar(panel))
        assert "hl" not in _cols(table)
        store.create("network", "facebook", reasons={"flow-2": "fb"})
        await until(pilot, lambda: "hl" in _cols(table))
        await pilot.resize_terminal(95, 45)
        await until(pilot, lambda: panel.size.width < 100)
        await settle(pilot)
        assert "hl" not in _cols(table)
        assert _tint_of(table, "f2") == _expected_tint(2)  # tint stays
        await pilot.resize_terminal(*SIZE)
        await until(pilot, lambda: "hl" in _cols(table))
        table.focus()
        await pilot.press("X")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("n")
        await settle(pilot)
        assert len(store.sets("network")) == 2
        await pilot.press("X")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("y")
        await until(pilot, lambda: not store.sets("network"))
        await until(pilot, lambda: "hl" not in _cols(table))
        assert not _bar(panel)
        assert _tint_of(table, "f2") is None
        assert not panel.check_action("clear_highlights", ())


async def test_network_row_source_snapshot(flow_dir, store):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        rows = await asyncio.to_thread(store.snapshot_rows, "network")
        assert rows is not None
        by_key = {r["key"]: r for r in rows}
        assert set(by_key) == {f"flow-{n}" for n in range(1, len(_SPECS) + 1)}
        fb = by_key["flow-2"]
        assert fb["shown"] is True
        assert fb["method"] == "POST"
        assert fb["host"] == "graph.facebook.com"
        assert fb["url"].startswith("https://graph.facebook.com/")
        assert fb["kind"] == "flow"
        assert fb["seq"] == 2
        assert fb["flow_dir"] == str(flow_dir)
        assert by_key["flow-1"]["shown"] is False  # OS noise, hidden
        assert by_key["flow-6"]["kind"] == "error"
        before = {r["key"] for r in rows if r["shown"]}
        store.create("network", "fb", reasons={"flow-2": "fb"}, filter=True)
        await until(pilot, lambda: panel.table.row_count == 1)
        # The AI filter is not a lens filter for the tools: same shown rows.
        rows = await asyncio.to_thread(store.snapshot_rows, "network")
        assert {r["key"] for r in rows if r["shown"]} == before
    assert not store.has_row_source("network")  # unregistered on unmount


async def test_network_highlight_words_take_the_light_theme_colours(flow_dir, store):
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        store.create("network", "facebook", reasons={"flow-2": "fb"})
        await until(pilot, lambda: "hl" in _cols(panel.table))
        cell = panel.table.get_cell("f2", "hl")
        assert HIGHLIGHT_DARK[0] in str(cell.spans[0].style)
        app.theme = "sandroid-light"
        await settle(pilot)
        app.call_later(panel._redraw_highlights)  # in the app's context
        await settle(pilot)
        cell = panel.table.get_cell("f2", "hl")
        assert HIGHLIGHT_LIGHT[0] in str(cell.spans[0].style)
        assert _tint_of(panel.table, "f2") == _expected_tint(1)


async def test_network_identity_and_highlight_columns_together(
    flow_dir, store, monkeypatch
):
    """With the privacy scan on the same registry: Identity after Recipient,
    Highlight last, the AI tint wins a row that has both, and a privacy hit
    redraws through the privacy feed only (no whole-lens AI redraw).
    """
    import privacy_fakes
    from test_network_lens import _privacy_hits

    from sandroid.tui.row_annotations import registry

    fake = privacy_fakes.install(monkeypatch, _privacy_hits()[:1])
    registry().register(store)  # install() starts a fresh registry
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        table = panel.table
        store.create("network", "POST trackers", reasons={"flow-2": "POST"})
        await until(pilot, lambda: "hl" in _cols(table))
        cols = _cols(table)
        assert cols.index("who") + 1 == cols.index("ident")
        assert cols[-1] == "hl"
        assert _cell(table, "f2", "ident") == "Ad ID"
        assert _cell(table, "f2", "hl") == "POST trackers"
        assert _tint_of(table, "f2") == _expected_tint(1)
        rebuilds = []
        rebuild = panel._rebuild
        monkeypatch.setattr(
            panel, "_rebuild", lambda *a, **k: (rebuilds.append(1), rebuild(*a, **k))
        )
        fake.add(privacy_fakes.flow_hit("flow-4", "Email", "Email"))
        await until(pilot, lambda: _cell(table, "f4", "ident") == "Email")
        await asyncio.sleep(1.2)  # past the feeds' once-a-second window
        await settle(pilot)
        assert rebuilds == []
        assert _cell(table, "f2", "hl") == "POST trackers"


# --------------------------------------------------------------------------
# Files lens
# --------------------------------------------------------------------------

WIDE = (160, 40)
OTHER_CACHE = f"{ROOT}/cache/okhttp/other"


async def _files(app, pilot) -> FilesPanel:
    panel = app.query_one(FilesPanel)
    panel.ingest(
        _items(
            _fse("FSE_CONTENT_MODIFIED", PREFS),
            _fse("FSE_CREATE_FILE", AAID),
            _fse("FSE_CONTENT_MODIFIED", DB),
            _fse("FSE_CONTENT_MODIFIED", CACHE),
            _fse("FSE_CONTENT_MODIFIED", OTHER_CACHE),
            _fse("FSE_CONTENT_MODIFIED", MISC),
        ),
        now=T0,
    )
    panel.refresh_rows()
    await pilot.pause()
    return panel


async def test_files_tint_column_group_cell_bar_and_inspector(store):
    app = _Harness()
    async with app.run_test(size=WIDE) as pilot:
        panel = await _files(app, pilot)
        table = panel.table
        assert "hl" not in _cols(table)
        judged = (T0 + timedelta(seconds=5)).timestamp()
        user0 = PREFS.replace("/data/data/", "/data/user/0/")
        store.create(
            "files",
            "files with personal data",
            short="personal",
            reasons={user0: "email in consent.xml", CACHE: "cached profile"},
            origin="ai",
            basis={"judged_at": judged, "evaluated": 5},
        )
        await until(pilot, lambda: "hl" in _cols(table))
        assert _cell(table, PREFS, "hl") == "personal"
        assert _tint_of(table, PREFS) == _expected_tint(1)
        group = next(r.key for r in panel._rows if r.group and not r.fold)
        assert _cell(table, group, "hl") == "1 inside"
        assert _tint_of(table, group) is None
        assert "files with personal data 2" in _bar(panel)
        # after the judgement: a new file, and a highlighted one changed
        later = T0 + timedelta(seconds=10)
        panel.ingest(
            _items(
                _fse("FSE_CREATE_FILE", f"{ROOT}/files/new.txt"),
                _fse("FSE_CONTENT_MODIFIED", PREFS),
            ),
            now=later,
        )
        panel.refresh_rows()
        bar = _bar(panel)
        assert "1 new since" in bar
        assert "1 changed since" in bar
        row = next(r for r in panel._rows if r.key == PREFS)
        summary = dict(panel._inspector_for(row).tabs)["Summary"]
        body = str(dict(summary)["AI highlight"])
        assert "AI: email in consent.xml" in body
        assert "changed after the AI looked at it" in body
        # narrow: no column, the tint stays
        await pilot.resize_terminal(100, 40)
        await until(pilot, lambda: "hl" not in _cols(table))
        assert _tint_of(table, PREFS) == _expected_tint(1)


async def test_files_ai_filter_bypasses_rules_ungroups_and_esc_order(store):
    app = _Harness()
    async with app.run_test(size=WIDE) as pilot:
        panel = await _files(app, pilot)
        table = panel.table
        assert MISC not in _keys(table)  # an OS path: hidden by the rules
        before = set(_keys(table))
        h1 = store.create(
            "files", "secrets", reasons={PREFS: "a", MISC: "b", CACHE: "c"}
        )
        await until(pilot, lambda: _bar(panel))
        table.focus()
        await pilot.press("H")
        await settle(pilot)
        assert store.filter_set("files") == h1.id
        # flat (no cache group) and the rule-hidden path shows
        assert sorted(_keys(table)) == sorted([PREFS, MISC, CACHE])
        assert panel.caption()[1].startswith("AI filter: secrets · 3 of ")
        # Esc: the / filter first, then the AI filter, then nothing
        panel._filter = "prefs"
        panel.refresh_rows()
        assert _keys(table) == [PREFS]
        assert panel.handle_escape() is True
        assert panel._filter == ""
        assert store.filter_set("files") == h1.id
        assert panel.handle_escape() is True
        assert store.filter_set("files") is None
        assert set(_keys(table)) == before
        assert panel.handle_escape() is False
        # nothing in view under the filter: the empty state says how out
        store.create("files", "nothing here", reasons={"/data/data/x/y": "z"})
        store.set_filter("files", store.sets("files")[-1].id)
        await until(pilot, lambda: panel.has_class("-empty"))
        empty = str(panel.query_one("#files-empty").render())
        assert "No highlighted file here" in empty
        assert "H or Esc leaves the AI filter" in empty


async def test_files_X_clears_after_confirm(store, monkeypatch):
    from sandroid.tui.modals import ConfirmModal

    monkeypatch.setattr(ConfirmModal, "ARM_SECONDS", 0.0)
    app = _Harness()
    async with app.run_test(size=WIDE) as pilot:
        panel = await _files(app, pilot)
        store.create("files", "secrets", reasons={PREFS: "a"})
        await until(pilot, lambda: "hl" in _cols(panel.table))
        assert panel.check_action("clear_highlights", ())
        panel.table.focus()
        await pilot.press("X")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("y")
        await until(pilot, lambda: not store.sets("files"))
        await until(pilot, lambda: "hl" not in _cols(panel.table))
        assert not _bar(panel)
        assert not panel.check_action("cycle_highlight_filter", ())


async def test_files_row_source_snapshot(store):
    app = _Harness()
    async with app.run_test(size=WIDE) as pilot:
        await _files(app, pilot)
        rows = await asyncio.to_thread(store.snapshot_rows, "files")
        assert rows is not None
        by_key = {r["key"]: r for r in rows}
        assert {PREFS, AAID, DB, CACHE, OTHER_CACHE, MISC} <= set(by_key)
        prefs = by_key[PREFS]
        assert prefs["shown"] is True
        assert prefs["ops"] == "M"
        assert prefs["count"] == 1
        assert prefs["app"] == "com.example.fit"
        assert prefs["watched"] is False
        assert prefs["review_kind"] is None
        assert prefs["last"] == pytest.approx(T0.timestamp())
        assert by_key[CACHE]["shown"] is True  # inside a folded cache group
        assert by_key[MISC]["shown"] is False  # hidden by a path rule
        before = {r["key"] for r in rows if r["shown"]}
        store.create("files", "prefs", reasons={PREFS: "a"}, filter=True)
        await until(pilot, lambda: _keys(app.query_one(FilesPanel).table) == [PREFS])
        # The AI filter is not a lens filter for the tools: same shown rows.
        rows = await asyncio.to_thread(store.snapshot_rows, "files")
        assert {r["key"] for r in rows if r["shown"]} == before
    assert not store.has_row_source("files")


async def test_network_review_snapshot_points_at_the_run_bundle(flow_dir, store):
    from sandroid.tui.widgets.network_panel import FlowRow

    bundle = flow_dir.parent / "run" / "network"
    records = write_flows(bundle, time.time() - 500)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        panel._scope = "/runs/run-1"
        panel._review = [FlowRow.from_record(r, bundle) for r in records]
        panel._rebuild()
        rows = await asyncio.to_thread(store.snapshot_rows, "network")
        by_key = {r["key"]: r for r in rows}
        assert by_key["flow-2"]["flow_dir"] == str(bundle)
        assert by_key["flow-2"]["scope"] == "/runs/run-1"
        assert by_key["flow-2"]["error"] is None
        assert by_key["flow-6"]["error"] == "Connection reset by peer"


async def test_files_review_snapshot_carries_the_diff_head(store, tmp_path):
    from sandroid.tui.widgets.highlight_bar import DIFF_HEAD_CAP, diff_head
    from sandroid.tui.widgets.lens_shell import ScopeChanged

    run_dir = _run_dir(tmp_path)
    app = _Harness()
    async with app.run_test(size=WIDE) as pilot:
        panel = app.query_one(FilesPanel)
        panel.post_message(ScopeChanged(str(run_dir), "Run #3"))
        await until(pilot, lambda: panel._review_record is not None)
        rows = await asyncio.to_thread(store.snapshot_rows, "files")
        by_key = {r["key"]: r for r in rows}
        prefs = by_key[PREFS]
        assert prefs["review_kind"] == "changed"
        assert prefs["scope"] == str(run_dir)
        assert "a=false" in prefs["diff_head"]
        assert by_key[AAID]["diff_head"] is None
    head = diff_head(["x" * 4000])
    assert len(head) == DIFF_HEAD_CAP


# --------------------------------------------------------------------------
# verifier findings: labels are never markup
# --------------------------------------------------------------------------

BRACKET_LABEL = "POSTs to [/v1/track] [bold]x"


async def test_network_H_and_X_with_a_bracket_label_do_not_crash(
    flow_dir, store, monkeypatch
):
    from sandroid.tui.modals import ConfirmModal

    monkeypatch.setattr(ConfirmModal, "ARM_SECONDS", 0.0)
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        ms, panel = await _network(app, pilot, flow_dir)
        store.create("network", BRACKET_LABEL, reasons={"flow-2": "x"})
        await until(pilot, lambda: panel._hl.active)
        panel.table.focus()
        await pilot.press("H")
        for _ in range(4):
            await pilot.pause(0.1)
        notes = [n.message for n in app._notifications]
        assert f"AI filter: {BRACKET_LABEL}" in notes
        assert BRACKET_LABEL in ms._lens_captions["network"][1].replace("\\", "")
        await pilot.press("X")
        await until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.pause(0.2)
        message = str(app.screen.query_one(".modal-message").render())
        assert "[/v1/track] [bold]x" in message
        await pilot.press("y")
        await until(pilot, lambda: not store.sets("network"))
    assert app.return_code in (None, 0)


async def test_files_bracket_label_in_the_caption_and_H_notice(store):
    app = _Harness()
    async with app.run_test(size=WIDE, notifications=True) as pilot:
        panel = await _files(app, pilot)
        store.create("files", "prefs under [/sdcard]", reasons={PREFS: "r"})
        await until(pilot, lambda: _bar(panel))
        panel.table.focus()
        await pilot.press("H")
        for _ in range(4):
            await pilot.pause(0.1)
        assert "AI filter: prefs under [/sdcard]" in [
            n.message for n in app._notifications
        ]
        info = panel.caption()[1]
        assert "prefs under \\[/sdcard]" in info  # escaped for the frame markup
        from textual.content import Content

        assert "prefs under [/sdcard]" in Content.from_markup(info).plain
    assert app.return_code in (None, 0)


# --------------------------------------------------------------------------
# verifier findings: counts, column order, bar width
# --------------------------------------------------------------------------


async def test_files_bar_counts_idle_watched_rows_as_present(store):
    from sandroid.services import get_forensic_service

    watched = [f"{ROOT}/shared_prefs/w{i}.xml" for i in range(5)]
    for path in watched:
        get_forensic_service().add_spotlight_file(path)
    try:
        app = _Harness()
        async with app.run_test(size=WIDE) as pilot:
            panel = await _files(app, pilot)
            store.create(
                "files",
                "watched prefs",
                reasons={**dict.fromkeys(watched[:3], "w"), PREFS: "p"},
            )
            await until(pilot, lambda: _bar(panel))
            bar = _bar(panel)
            assert "watched prefs 4" in bar
            assert "of 4" not in bar
            assert "hidden by lens filters" not in bar
    finally:
        get_forensic_service()._spotlight_files.clear()


def _view_with(store, n: int):
    from sandroid.tui.widgets.highlight_bar import HighlightView

    labels = ["shop POSTs to the API", "tracker hosts", "cdn assets", "geo lookups"]
    for i in range(n):
        store.create(
            "network",
            labels[i],
            reasons={f"k{i}": "r"},
            basis={"through_seq": 5, "judged_at": 1.0},
        )
    return HighlightView("network")


def test_highlight_cell_shows_the_filter_set_first(store):
    view = _view_with(store, 3)
    store.add("h3", {"k0": "also"})
    first, third = store.get("h1").short, store.get("h3").short
    assert view.cell("k0").plain == f"{first}, {third}"
    store.set_filter("network", "h3")
    assert view.cell("k0").plain == f"{third}, {first}"
    assert [e[0] for e in view.ordered("k0")] == ["h3", "h1"]


def test_rows_without_a_key_never_count_as_new(store):
    view = _view_with(store, 1)
    view.measure(
        iter([("k0", True, 1, 1.0), (None, True, 9, 9.0), ("x", True, 6, 9.0)]),
        live=True,
    )
    assert view.counts["h1"].new == 1  # only "x"; the keyless TLS row is not


@pytest.mark.parametrize("width", [200, 170, 120, 100, 80, 60, 40])
def test_the_bar_condenses_instead_of_overflowing(store, width):
    view = _view_with(store, 4)
    view.measure(iter([(f"k{i}", True, 1, 1.0) for i in range(4)]), live=True)
    text = view.bar_text(width)
    plain = text.plain
    full = view.bar_text(1000).plain
    assert "H filter · X clear" in full
    if text.cell_len > width - 2:
        # only the last form may be cut, and then with an ellipsis
        assert plain.startswith(" AI highlights   4 sets:")
    if width <= 100:
        assert "H filter" not in plain  # the hint goes first
    if width <= 60:
        assert plain.startswith(" AI highlights   4 sets: ")


# --------------------------------------------------------------------------
# E2E finding: the Network lens follows light themes
# --------------------------------------------------------------------------


async def test_network_lens_follows_a_light_theme(flow_dir, store):
    from textual.color import Color

    from sandroid.tui.themes import lens_palette

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        dark_bg = panel.styles.background
        assert dark_bg == Color.parse("#050811")  # the default stays identical
        from sandroid.tui.themes import textual_theme_name

        app.theme = textual_theme_name("paper")
        await settle(pilot)
        app.call_later(panel._rebuild)
        await settle(pilot)
        pal = lens_palette()
        assert pal.bg.upper() == "#FBF8F1"  # paper's lens background
        assert panel.styles.background == Color.parse(pal.bg)
        assert panel.table.styles.background == Color.parse(pal.bg)
        request = panel.table.get_cell("f2", "req")
        assert all(
            str(span.style) in (pal.text, pal.muted) for span in request.spans
        ), request.spans


def test_the_bar_heading_has_a_theme_background(store):
    from sandroid.tui.themes import lens_palette

    view = _view_with(store, 1)
    text = view.bar_text(200)
    heading = next(span for span in text.spans if span.start == 0)
    assert str(heading.style).endswith(f"on {lens_palette().band}")


async def test_network_H_while_live_keeps_live_and_the_newest_row(flow_dir, store):
    """sandroid-tracking: toggling the AI filter while live stays live, cursor
    on the newest shown row.
    """
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        table = panel.table
        store.create("network", "facebook", reasons={"flow-2": "fb", "flow-3": "x"})
        await until(pilot, lambda: "hl" in _cols(table))
        assert panel.following
        table.focus()
        for _ in range(3):  # set -> off -> set
            await pilot.press("H")
            await settle(pilot)
            assert panel.following
            assert table.cursor_row == table.row_count - 1


async def test_files_H_while_live_keeps_live_and_the_newest_row(store):
    app = _Harness()
    async with app.run_test(size=WIDE) as pilot:
        panel = await _files(app, pilot)
        table = panel.table
        store.create("files", "secrets", reasons={PREFS: "a", MISC: "b", CACHE: "c"})
        await until(pilot, lambda: _bar(panel))
        assert panel.following
        table.focus()
        for _ in range(3):
            await pilot.press("H")
            await settle(pilot)
            assert panel.following
            assert table.cursor_row == table.row_count - 1


async def test_files_lens_repaints_on_a_live_theme_switch(store):
    """Visual check on main: after a live switch to paper the Files bar and
    Highlight words kept the dark palette until the lens was switched.
    """
    from sandroid.tui.themes import (
        THEMES,
        build_textual_theme,
        lens_palette,
        textual_theme_name,
    )

    app = _Harness()
    async with app.run_test(size=WIDE) as pilot:
        app.register_theme(build_textual_theme(THEMES["paper"]))
        panel = await _files(app, pilot)
        table = panel.table
        store.create("files", "secrets", short="secrets", reasons={PREFS: "a"})
        await until(pilot, lambda: "hl" in _cols(table))
        dark = str(table.get_cell(PREFS, "hl").spans[0].style)
        app.theme = textual_theme_name("paper")
        await settle(pilot)
        light = str(table.get_cell(PREFS, "hl").spans[0].style)
        assert light != dark
        assert lens_palette().highlight_1 in light
        bar = panel.query_one("#files-highlights", HighlightBar)
        from textual.color import Color

        heading = bar.render().spans[0].style
        assert heading.background == Color.parse(lens_palette().band)


async def test_network_lens_repaints_on_a_live_theme_switch(flow_dir, store):
    from sandroid.tui.themes import lens_palette, textual_theme_name

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        table = panel.table
        store.create("network", "facebook", short="fb", reasons={"flow-2": "fb"})
        await until(pilot, lambda: "hl" in _cols(table))
        dark = str(table.get_cell("f2", "hl").spans[0].style)
        app.theme = textual_theme_name("paper")
        await settle(pilot)
        light = str(table.get_cell("f2", "hl").spans[0].style)
        assert light != dark
        assert lens_palette().highlight_1 in light


# --------------------------------------------------------------------------
# E2E finding: a TLS-failed tracker row is a row of the AI tools
# --------------------------------------------------------------------------


def _append_tls(flow_dir, seq: int, host: str) -> None:
    now = time.time()
    record = {
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
        "app": PKG,
    }
    with open(flow_dir / "flows.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


async def test_network_tls_failed_tracker_row_is_highlighted(
    flow_dir, store, monkeypatch
):
    from sandroid.ai.tools import lens_rows

    monkeypatch.setattr("sandroid.core.timeline.emit", lambda *a, **k: None)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        table = panel.table
        # mitmweb's stdout line comes first: a "t<n>" row without a key yet.
        panel.add_tls_failure("12:00:00", "sdk.pa-cd.com", "cert", PKG)
        await settle(pilot)
        stdout_row = next(r for r in panel._live if r.kind == "tls")
        assert stdout_row.key.startswith("t")
        assert stdout_row.flow_id is None
        early = await asyncio.to_thread(
            lens_rows.find_rows, "network", {"host_glob": ["*pa-cd.com"]}
        )
        assert early["keys"] == []
        assert early["not_in_flow_log_yet"] == 1
        k100 = tls_row_key(flow_dir, "tls-100")
        k101 = tls_row_key(flow_dir, "tls-101")
        # The flow log catches up (the stdout row adopts tls-100), a second
        # TLS failure is only in the flow log, and Sandroid's mitm.it probe
        # is OS noise the lens hides.
        _append_tls(flow_dir, 100, "sdk.pa-cd.com")
        _append_tls(flow_dir, 101, "cdn.pa-cd.com")
        write_flows(
            flow_dir,
            time.time(),
            specs=[("GET", "mitm.it", "/", 200, "", None, "ok", None)],
            start_seq=102,
        )
        panel.poll_now()
        await until(pilot, lambda: any(r.host == "mitm.it" for r in panel._live))
        await settle(pilot)
        assert stdout_row.flow_id == k100
        assert panel.table.get_row_index(stdout_row.key) >= 0
        persisted = next(r for r in panel._live if r.host == "cdn.pa-cd.com")
        assert (persisted.key, persisted.flow_id) == ("f101", k101)
        rows = await asyncio.to_thread(store.snapshot_rows, "network")
        by_key = {r["key"]: r for r in rows}
        assert by_key[k100]["kind"] == "tls"
        assert by_key[k100]["shown"] is True
        assert "TLS handshake failed" in by_key[k100]["error"]
        assert by_key["flow-102"]["shown"] is False  # mitm.it: OS noise

        found = await asyncio.to_thread(
            lens_rows.find_rows,
            "network",
            {"host_glob": ["*pa-cd.com"]},
            apply="highlight",
            label="tracker pa-cd.com",
            short="pa-cd",
        )
        assert found["keys"] == [k100, k101]
        assert found["hidden_by_lens_filters"] == 0
        listed = await asyncio.to_thread(lens_rows.find_rows, "network")
        assert "flow-102" not in listed["keys"]
        assert listed["hidden_by_lens_filters"] >= 1
        every = await asyncio.to_thread(lens_rows.find_rows, "network", scope="all")
        assert "flow-102" in every["keys"]

        await until(pilot, lambda: "hl" in _cols(table))
        for key in (stdout_row.key, "f101"):
            assert _cell(table, key, "hl") == "pa-cd"
            assert _tint_of(table, key) == _expected_tint(1)
        assert _tint_of(table, "f3") is None
        assert "tracker pa-cd.com 2" in _bar(panel)
        # The AI filter shows exactly the two TLS rows.
        store.set_filter("network", found["highlight_id"])
        await until(pilot, lambda: table.row_count == 2)
        assert sorted(_keys(table)) == sorted([stdout_row.key, "f101"])


def test_the_bar_says_scanning_while_running_then_partial_or_nothing(store):
    from sandroid.tui.widgets.highlight_bar import HighlightView

    hs = store.create("network", "tracker hosts", origin="ai", scanning=True)
    store.add(hs.id, {"tls-3": "tracker"})
    view = HighlightView("network")
    view.measure(iter([("tls-3", True, 3, 3.0)]), live=True)
    plain = view.bar_text(200).plain
    assert "scanning" in plain
    assert "partial" not in plain
    section = str(view.sections("tls-3")[0][1])
    assert "scanning" in section
    store.finish(hs.id, complete=False)  # stopped, cancelled or deadline
    plain = view.bar_text(200).plain
    assert "partial" in plain
    assert "scanning" not in plain
    assert "partial" in str(view.sections("tls-3")[0][1])
    store.start_scan(hs.id)
    assert "scanning" in view.bar_text(200).plain
    store.finish(hs.id, complete=True)
    plain = view.bar_text(200).plain
    assert "scanning" not in plain
    assert "partial" not in plain


def test_a_reloaded_scanning_set_shows_partial(store, tmp_path):
    from sandroid.services.row_highlights import HighlightStore
    from sandroid.tui.widgets.highlight_bar import set_state

    saved = HighlightStore()
    saved.bind_folder(tmp_path)
    hs = saved.create("network", "tracker hosts", origin="ai", scanning=True)
    saved.add(hs.id, {"tls-3": "tracker"})
    assert saved.flush()  # the process ends mid-scan
    store.bind_folder(tmp_path)
    loaded = store.get(hs.id)
    assert set_state(loaded) == "partial"
    from sandroid.tui.widgets.highlight_bar import HighlightView

    view = HighlightView("network")
    view.measure(iter([("tls-3", True, 3, 3.0)]), live=True)
    plain = view.bar_text(200).plain
    assert "partial" in plain
    assert "scanning" not in plain


# --------------------------------------------------------------------------
# verifier findings (fix/ai-polish-verify)
# --------------------------------------------------------------------------


async def test_ai_filter_does_not_narrow_the_next_find_and_extends_add_rows(
    flow_dir, store, monkeypatch
):
    """Finding 1: the AI filter is not a lens filter for the tools."""
    from sandroid.ai.tools import lens_rows

    monkeypatch.setattr("sandroid.core.timeline.emit", lambda *a, **k: None)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        posts_before = await asyncio.to_thread(
            lens_rows.find_rows, "network", {"method": ["POST"]}
        )
        fb = await asyncio.to_thread(
            lens_rows.find_rows,
            "network",
            {"host_glob": ["graph.facebook.com"]},
            apply="filter",
            label="facebook",
            short="fb",
        )
        await until(pilot, lambda: panel.table.row_count == len(fb["keys"]))
        posts = await asyncio.to_thread(
            lens_rows.find_rows, "network", {"method": ["POST"]}
        )
        assert posts["keys"] == posts_before["keys"]
        assert posts["hidden_by_lens_filters"] == posts_before["hidden_by_lens_filters"]
        # Extending the filter set adds rows outside it.
        more = await asyncio.to_thread(
            lens_rows.find_rows,
            "network",
            {"method": ["POST"]},
            apply="filter",
            highlight_id=fb["highlight_id"],
        )
        assert more["highlight_id"] == fb["highlight_id"]
        assert set(store.keys(fb["highlight_id"])) == set(posts_before["keys"]) | set(
            fb["keys"]
        )
        await until(
            pilot,
            lambda: panel.table.row_count == len(store.keys(fb["highlight_id"])),
        )
        # Nothing new: the set stays and the result says so.
        again = await asyncio.to_thread(
            lens_rows.find_rows,
            "network",
            {"method": ["POST"]},
            apply="filter",
            highlight_id=fb["highlight_id"],
        )
        assert again["highlight_id"] == fb["highlight_id"]
        assert "no new rows" in again["note"]
        assert "no highlight set was created" not in str(again)


async def test_hidden_network_lens_tls_row_is_paired_by_the_tools(
    flow_dir, store, monkeypatch
):
    """Finding 2: a hidden lens does not poll; the tools pair the stdout TLS
    row with its flow-log record, and the lens adopts the key on its poll.
    """
    from sandroid.ai.tools import lens_rows

    monkeypatch.setattr("sandroid.core.timeline.emit", lambda *a, **k: None)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _network(app, pilot, flow_dir)
        ms.switch_lens("timeline")
        await settle(pilot)
        panel.add_tls_failure("12:00:00", "sdk.pa-cd.com", "cert", PKG)
        _append_tls(flow_dir, 100, "sdk.pa-cd.com")
        await settle(pilot)
        stdout_row = next(r for r in panel._live if r.kind == "tls")
        k100 = tls_row_key(flow_dir, "tls-100")
        res = await asyncio.to_thread(
            lens_rows.find_rows,
            "network",
            {"host_glob": ["*pa-cd.com"]},
            apply="highlight",
            label="pa-cd",
            short="pa-cd",
        )
        assert res["source"] == "lens"
        assert res["keys"] == [k100]
        assert "not_in_flow_log_yet" not in res
        assert stdout_row.flow_id is None  # the hidden lens did not poll
        ms.switch_lens("network")
        panel.poll_now()
        await until(pilot, lambda: stdout_row.flow_id == k100)
        await until(
            pilot,
            lambda: _tint_of(panel.table, stdout_row.key) == _expected_tint(1),
        )
        assert sum(1 for r in panel._live if r.kind == "tls") == 1


async def test_flows_logged_while_the_lens_is_hidden_are_rows_of_the_tools(
    flow_dir, store, monkeypatch
):
    """The original report: the analyst works (and chats) in another lens;
    the hidden Network lens does not poll, yet the tools see the flows that
    reached the flow log meanwhile, keyed as the lens will key them.
    """
    from sandroid.ai.tools import lens_rows

    monkeypatch.setattr("sandroid.core.timeline.emit", lambda *a, **k: None)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, panel = await _network(app, pilot, flow_dir)
        ms.switch_lens("timeline")
        await settle(pilot)
        # Meanwhile: a TLS failure on mitmweb's stdout and in the flow log
        # (one row, not two), another one only in the flow log, two new
        # flows, and Sandroid's mitm.it probe (OS noise).
        panel.add_tls_failure("12:00:00", "sdk.pa-cd.com", "cert", PKG)
        _append_tls(flow_dir, 100, "sdk.pa-cd.com")
        _append_tls(flow_dir, 101, "cdn.pa-cd.com")
        write_flows(
            flow_dir,
            time.time(),
            specs=[
                ("POST", "api.pa-cd.com", "/collect", 200, PKG, "a=1", "{}", None),
                ("GET", "img.pa-cd.com", "/p.gif", 200, PKG, None, None, None),
                ("GET", "mitm.it", "/", 200, "", None, "ok", None),
            ],
            start_seq=102,
        )
        await settle(pilot)
        assert not any(r.seq and r.seq >= 100 for r in panel._live)  # no poll
        k100 = tls_row_key(flow_dir, "tls-100")
        k101 = tls_row_key(flow_dir, "tls-101")
        found = await asyncio.to_thread(
            lens_rows.find_rows,
            "network",
            {"host_glob": ["*pa-cd.com"]},
            apply="highlight",
            label="pa-cd",
            short="pa-cd",
        )
        assert found["source"] == "lens"
        assert sorted(found["keys"]) == sorted([k100, k101, "flow-102", "flow-103"])
        assert "not_in_flow_log_yet" not in found
        assert "4 newer row(s)" in found["shown_basis"]
        every = await asyncio.to_thread(lens_rows.find_rows, "network", scope="all")
        assert every["keys"].count(k100) == 1
        assert "flow-104" in every["keys"]  # mitm.it: hidden by the noise rule
        shown = await asyncio.to_thread(lens_rows.find_rows, "network")
        assert "flow-104" not in shown["keys"]
        assert {"flow-2", "flow-3"} <= set(shown["keys"])  # the polled rows

        ms.switch_lens("network")
        panel.poll_now()
        await until(pilot, lambda: any(r.seq == 103 for r in panel._live))
        await until(pilot, lambda: "hl" in _cols(panel.table))
        stdout_row = next(r for r in panel._live if r.host == "sdk.pa-cd.com")
        assert stdout_row.flow_id == k100
        for key in (stdout_row.key, "f101", "f102", "f103"):
            await until(
                pilot,
                lambda key=key: _tint_of(panel.table, key) == _expected_tint(1),
            )
            assert _cell(panel.table, key, "hl") == "pa-cd", key
        assert _tint_of(panel.table, "f3") is None
        snap = await asyncio.to_thread(store.snapshot_rows, "network")
        assert snap.polled_through == 104
        assert "shown_basis" not in await asyncio.to_thread(
            lens_rows.find_rows, "network"
        )


async def test_never_shown_network_lens_reads_the_flow_log_with_the_noise_rule(
    flow_dir, store, monkeypatch
):
    """Findings 2 and 5: a lens that never polled is no empty view; the
    fallback rows follow the lens's noise rule and say so.
    """
    from pilot_helpers import boot

    from sandroid.ai.tools import lens_rows
    from sandroid.services import mitmproxy_flow_log

    monkeypatch.setattr(mitmproxy_flow_log, "resolve_flow_dir", lambda: flow_dir)
    mitmproxy_flow_log._CURSOR_CACHE.clear()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        write_flows(flow_dir, time.time() - 100)
        for panel in ms.query(NetworkPanel):
            assert panel._highlight_rows_snapshot() is None
        res = await asyncio.to_thread(lens_rows.find_rows, "network")
        assert res["source"] == "flow_log"
        assert res["shown_basis"] == "noise rule only (lens not open)"
        assert "flow-1" not in res["keys"]  # connectivity check: OS noise
        assert "flow-2" in res["keys"]
        assert res["hidden_by_lens_filters"] >= 1


async def test_device_switch_drops_tls_rows_of_the_old_flow_dir(
    flow_dir, store, tmp_path, monkeypatch
):
    """Finding 3: TLS rows keyed in the old flow dir do not survive a reset."""
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        _append_tls(flow_dir, 100, "pinned.example")
        panel.poll_now()
        await until(pilot, lambda: any(r.kind == "tls" for r in panel._live))
        panel.add_tls_failure("12:00:00", "fresh.example", "cert", PKG)
        await settle(pilot)
        other = tmp_path / "other" / "mitm_flows"
        other.mkdir(parents=True)
        monkeypatch.setattr(np_mod, "_flow_dir", lambda: other)
        panel.poll_now()
        await until(pilot, lambda: panel._live_dir == other)
        tls = [r for r in panel._live if r.kind == "tls"]
        assert [(r.host, r.flow_id) for r in tls] == [("fresh.example", None)]


async def test_two_tls_failures_to_one_host_keep_their_order(flow_dir, store):
    """Finding 8: the oldest stdout row adopts the oldest record."""
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        panel.add_tls_failure("12:00:00", "twice.example", "cert", PKG)
        panel.add_tls_failure("12:00:01", "twice.example", "cert", PKG)
        await settle(pilot)
        first, second = [r for r in panel._live if r.kind == "tls"]
        _append_tls(flow_dir, 100, "twice.example")
        _append_tls(flow_dir, 101, "twice.example")
        panel.poll_now()
        await until(pilot, lambda: second.seq is not None)
        assert (first.seq, second.seq) == (100, 101)
        assert first.flow_id == tls_row_key(flow_dir, "tls-100")


async def test_shown_scope_set_counts_rows_it_did_not_judge(
    flow_dir, store, monkeypatch
):
    """Finding 4: rows hidden when the set was made show as "not judged"."""
    from sandroid.ai.context import _describe_lens_highlights
    from sandroid.ai.tools import lens_rows

    monkeypatch.setattr("sandroid.core.timeline.emit", lambda *a, **k: None)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        _ms, panel = await _network(app, pilot, flow_dir)
        found = await asyncio.to_thread(
            lens_rows.find_rows,
            "network",
            {"method": ["GET"]},
            apply="highlight",
            label="GET requests",
            short="GET",
        )
        hs = store.get(found["highlight_id"])
        assert hs.basis["scope"] == "shown"
        assert "flow-1" in hs.basis["not_judged"]  # OS noise, hidden
        assert "flow-1" not in hs.reasons
        await until(pilot, lambda: "GET requests" in _bar(panel))
        assert "not judged" not in _bar(panel)
        panel.action_toggle_noise()  # N: the noise rows come into view
        await until(pilot, lambda: "not judged" in _bar(panel))
        n = found["hidden_by_lens_filters"]
        assert f"{n} not judged" in _bar(panel)
        assert f"{n} not judged" in (_describe_lens_highlights() or "")
