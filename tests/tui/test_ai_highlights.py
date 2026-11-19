"""AI row highlights in the Network and Files lenses (the TUI side).

The real highlight store (``sandroid.services.row_highlights``) drives the
lenses through the shared row-annotation registry: row tint, the Highlight
column, the highlight bar, the AI filter (``H``, Esc), ``X`` clear, the
Inspector section, new-since counts and the row sources the AI tools read.
Hermetic: fixture flow log / fixture monitor batches, memory-only store.
"""

from __future__ import annotations

import asyncio
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
from sandroid.services.row_highlights import get_row_highlights
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
        assert "exclamation_mark" not in keys
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
        assert "AI filter: facebook · 2 of 7" in ms._lens_captions["network"][1]
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
        # An empty set changes no row key: the store's notify carries no key,
        # which the feed does not flush; redraw as H / X would.
        app.call_later(panel._redraw_highlights)
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
        store.create("network", "fb", reasons={"flow-2": "fb"}, filter=True)
        await until(pilot, lambda: panel.table.row_count == 1)
        rows = await asyncio.to_thread(store.snapshot_rows, "network")
        assert {r["key"] for r in rows if r["shown"]} == {"flow-2"}
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
        store.create("files", "prefs", reasons={PREFS: "a"}, filter=True)
        await until(pilot, lambda: _keys(app.query_one(FilesPanel).table) == [PREFS])
        rows = await asyncio.to_thread(store.snapshot_rows, "files")
        assert {r["key"] for r in rows if r["shown"]} == {PREFS}
    assert not store.has_row_source("files")
