"""Timeline lens (lens 5), label keys, Tracking key, header, Settings tab.

The timeline core (WP1) and Tracking (WP4) are faked (``timeline_fakes``):
the fakes go into ``sys.modules`` for one test. The last tests use the real
``sandroid.core.timeline`` and are skipped until it exists.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
import timeline_fakes
from pilot_helpers import boot, settle, until
from textual.app import App, ComposeResult
from timeline_fakes import make_line

from sandroid.tui.widgets.lens_shell import LENSES, Mark, MarksChanged, is_shown
from sandroid.tui.widgets.timeline_lens import (
    TimelineLens,
    format_delta,
    parse_query,
    row_from_line,
)

SIZE = (160, 45)
NOW = time.time()


@pytest.fixture
def install_fakes(monkeypatch, tmp_path):
    """``install_fakes(lines=None, tracking=True)``: see ``timeline_fakes``."""

    def _install(lines=None, *, tracking: bool = True):
        return timeline_fakes.install(monkeypatch, tmp_path, lines, tracking=tracking)

    return _install


def _app():
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


def _messages(app) -> list[str]:
    return [n.message for n in app._notifications]


def _chips(lens) -> str:
    return str(lens.query_one("#tl-chips").render())


def _lines(n: int, start: float, step: float = 2.5) -> list[dict]:
    """``n`` files lines ``step`` s apart (more than ``BURST_GAP_S``: no fold)."""
    return [make_line(i + 1, start + i * step) for i in range(n)]


class _LensHarness(App):
    def compose(self) -> ComposeResult:
        yield TimelineLens(id="timeline-panel")


async def _loaded_lens(pilot, app) -> TimelineLens:
    lens = app.query_one(TimelineLens)
    lens.on_lens_activated()
    await until(pilot, lambda: lens._loaded)
    lens.view.focus()
    await pilot.pause()
    return lens


# --------------------------------------------------------------------------
# model: rows, query grammar
# --------------------------------------------------------------------------


def test_rows_parse_the_envelope_and_mark_separators() -> None:
    row = row_from_line(make_line(5, NOW, "files", "modify", t_err_ms=250.0), 10)
    assert (row.seq, row.offset, row.src, row.kind) == (5, 10, "files", "modify")
    assert abs(row.t - NOW) < 0.001
    assert "~" in row.flags  # t_err_ms > 100 ms
    assert row.sep == ""
    world = row_from_line(
        make_line(6, NOW, "snapshot", "load", data={"ok": True, "name": "clean"})
    )
    assert world.sep == "world"
    failed = row_from_line(make_line(7, NOW, "snapshot", "load", data={"ok": False}))
    assert failed.sep == ""
    assert row_from_line(make_line(8, NOW, "label", "start")).sep == "label"
    assert row_from_line(make_line(9, NOW, "run", "play-start")).sep == "run"
    assert row_from_line(make_line(10, NOW, "sandroid", "resume")).sep == "resume"
    coalesced = row_from_line(make_line(11, NOW, data={"n": 7, "first": "x"}))
    assert coalesced.n == 7
    secret = row_from_line(
        make_line(12, NOW, "input", "text", sensitive=True, data={"text": "pw"})
    )
    assert secret.sensitive
    assert secret.data is None


def test_query_grammar() -> None:
    q = parse_query('src:files,label -src:clock actor:user "accept all" cookie')
    assert q.pos == {"src": {"files", "label"}, "actor": {"user"}}
    assert q.neg == {"src": {"clock"}}
    assert q.words == ["accept all", "cookie"]
    assert parse_query("bogus:x").words == ["bogus:x"]
    assert parse_query('"unbalanced').words == ["unbalanced"]
    assert parse_query("").empty


def test_delta_format() -> None:
    assert format_delta(0.012) == "+12ms"
    assert format_delta(1.42) == "+1.4s"
    assert format_delta(200) == "+3m"
    assert format_delta(-2) == "-2.0s"


# --------------------------------------------------------------------------
# registration, keys, footer, help
# --------------------------------------------------------------------------


async def test_5_switches_and_focuses_the_lens_and_shift_arrow_reaches_it(
    install_fakes,
) -> None:
    install_fakes(_lines(30, NOW - 100))
    assert LENSES[4].id == "timeline"
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        await pilot.press("5")
        await settle(pilot)
        assert ms.active_lens == "timeline"
        lens = ms.lens_widget("timeline")
        assert isinstance(lens, TimelineLens)
        assert is_shown(lens)
        assert app.focused is not None
        assert lens in app.focused.ancestors_with_self
        await until(pilot, lambda: len(lens.rows) == 30)
        assert ms.query_one("#lens-host").border_title.startswith("Timeline · ")
        await pilot.press("4", "shift+right")
        await settle(pilot)
        assert ms.active_lens == "timeline"
        await pilot.press("shift+right")
        await settle(pilot)
        assert ms.active_lens == "identity"
        await pilot.press("5", "question_mark")
        await settle(pilot)
        from textual.widgets import OptionList

        options = app.screen.query_one("#kb-list", OptionList)
        heads = [
            str(options.get_option_at_index(i).prompt)
            for i in range(options.option_count)
        ]
        assert "Timeline lens" in heads[0]
        await pilot.press("escape")


async def test_footer_on_the_timeline_lens_has_at_most_seven_keys(
    install_fakes,
) -> None:
    from sandroid.tui.widgets.sandroid_footer import SandroidFooter

    install_fakes()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        await pilot.press("5")
        await settle(pilot)
        keys = list(app.screen.query_one(SandroidFooter).query("FooterKey"))
        assert 0 < len(keys) <= SandroidFooter.MAX_KEYS
        labels = [k.description for k in keys]
        assert labels[:2] == ["Record", "Review"]
        assert "Live" in labels


def _binding_keys(cls) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for key, bindings in cls._merge_bindings().key_to_bindings.items():
        for binding in bindings:
            for k in key.split(","):
                out.setdefault(k.strip(), set()).add(binding.action)
    return out


NEW_GLOBAL = {"5", "number_sign", "plus", "minus", "B", "ctrl+t"}
INSPECTOR_KEYS = {
    "left_square_bracket",
    "right_square_bracket",
    "left_curly_bracket",
    "right_curly_bracket",
    "asterisk",
}


def test_no_key_clashes_app_screen_lenses_inspector_inputs() -> None:
    """The new global keys are bound once, on the App, and nowhere in the
    main screen, any lens (or its focusable children), the Inspector or a
    text input; the Timeline lens's own keys leave the Inspector keys free.
    """
    from textual.containers import VerticalScroll
    from textual.widgets import DataTable, Input, OptionList, TextArea

    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.screens.main_screen import MainScreen, _LensHost
    from sandroid.tui.widgets.diffs_view import DiffsView
    from sandroid.tui.widgets.files_panel import FilesPanel, _FilesTable
    from sandroid.tui.widgets.lens_shell import Inspector
    from sandroid.tui.widgets.network_panel import FlowTable, NetworkPanel
    from sandroid.tui.widgets.spotlight_panel import SpotlightPanel
    from sandroid.tui.widgets.timeline_lens import TimelineView, TypeBar, _TLInput

    app_keys = [b.key for b in SandroidTUI.BINDINGS]
    for key in NEW_GLOBAL:
        assert app_keys.count(key) == 1, key
    ids = {b.id: b.key for b in SandroidTUI.BINDINGS if b.id}
    assert ids["lens_timeline"] == "5"
    assert ids["label_start"] == "number_sign"
    assert ids["label_sub"] == "plus"
    assert ids["label_stop"] == "minus"
    assert ids["label_point"] == "B"
    assert ids["tracking_toggle"] == "ctrl+t"

    others = [
        MainScreen,
        _LensHost,
        Inspector,
        SpotlightPanel,
        NetworkPanel,
        FilesPanel,
        DiffsView,
        TimelineLens,
        TimelineView,
        TypeBar,
        _TLInput,
        _FilesTable,
        FlowTable,
        DataTable,
        OptionList,
        VerticalScroll,
        Input,
        TextArea,
    ]
    for cls in others:
        clash = NEW_GLOBAL & _binding_keys(cls).keys()
        assert not clash, (cls.__name__, clash)
    lens_keys = _binding_keys(TimelineLens).keys() | _binding_keys(TimelineView).keys()
    assert {"space", "end", "home", "slash", "t", "z", "N", "J", "V"} <= lens_keys
    assert not INSPECTOR_KEYS & lens_keys
    assert not lens_keys & {k for k in _binding_keys(MainScreen) if k != "enter"}
    assert "enter" not in lens_keys  # MainScreen's Enter inspects
    # The App lens keeps space / z / u / b; the Files lens its A < > R.
    app_lens = _binding_keys(SpotlightPanel)
    assert {"space", "z", "u", "b"} <= app_lens.keys()
    files = _binding_keys(FilesPanel)
    assert {"A", "less_than_sign", "greater_than_sign", "R"} <= files.keys()
    assert "B" not in files


# --------------------------------------------------------------------------
# load, live feed, follow
# --------------------------------------------------------------------------


@pytest.mark.perf
async def test_tail_load_of_100k_lines_paints_in_under_a_second(
    install_fakes,
) -> None:
    install_fakes(_lines(100_000, NOW - 260_000, step=2.5))
    app = _LensHarness()
    async with app.run_test(size=SIZE) as pilot:
        lens = app.query_one(TimelineLens)
        started = time.monotonic()
        lens.on_lens_activated()
        await until(pilot, lambda: lens._loaded, timeout=10)
        await pilot.pause()
        elapsed = time.monotonic() - started
        assert len(lens.rows) == 20_000
        assert lens.rows[-1].seq == 100_000
        assert elapsed < 1.0, elapsed
        # Following: the newest line is selected and visible.
        assert lens.following
        assert lens.cursor_row.seq == 100_000
        strip = lens.view.render_line(lens.view.scrollable_content_region.height - 1)
        assert "MODIFY" in "".join(seg.text for seg in strip)
        # The older page is announced on the top row.
        top = lens.strip_for(0, 120)
        assert "older lines on disk" in "".join(seg.text for seg in top)


async def test_live_lines_arrive_through_tail_and_late_lines_keep_the_viewport(
    install_fakes,
) -> None:
    fakes = install_fakes(_lines(200, NOW - 1000))
    app = _LensHarness()
    async with app.run_test(size=(140, 20)) as pilot:
        lens = await _loaded_lens(pilot, app)
        assert len(lens.rows) == 200
        # A new line goes through the hold, then lands at the end.
        fakes.service.emit("files", "create", summary="CREATE files/new.txt")
        lens._poll()
        assert lens.rows[-1].seq == 200  # still held
        lens.release_pending(now=time.time() + 1)
        assert lens.rows[-1].seq == 201
        assert lens.cursor_row.seq == 201  # following
        # Pause, scroll to the middle, then a late line lands above.
        await pilot.press("up")
        assert not lens.following
        for _ in range(100):
            lens.move_cursor(-1)
        await pilot.pause()
        view = lens.view
        top_before = lens._row_at_display(int(view.scroll_offset.y))
        assert top_before is not None
        late_t = lens.rows[10].t + 0.1
        fakes.service.emit("files", "modify", summary="LATE databases/x.db", t=late_t)
        lens._poll()
        lens.release_pending(now=time.time() + 1)
        await pilot.pause()
        late = next(r for r in lens.rows if r.summary.startswith("LATE"))
        assert lens.rows.index(late) == 11  # in place (time order)
        top_after = lens._row_at_display(int(view.scroll_offset.y))
        assert top_after.seq == top_before.seq  # viewport kept
        assert lens.late_above == 1
        assert "1 late line above" in lens.caption()[1]


async def test_follow_pauses_on_up_and_resumes_with_end_or_space(
    install_fakes,
) -> None:
    fakes = install_fakes(_lines(50, NOW - 500))
    app = _LensHarness()
    async with app.run_test(size=(140, 20)) as pilot:
        lens = await _loaded_lens(pilot, app)
        lens.view.focus()
        await pilot.press("up")
        assert not lens.following
        fakes.service.emit("files", "create", summary="CREATE a")
        lens._poll()
        lens.release_pending(now=time.time() + 1)
        assert lens.cursor_row.seq == 49  # stays put
        assert lens.caption()[0] == "scrolled back · 1 new below · End = live"
        assert "live" not in _chips(lens)  # one place: the caption title
        await pilot.press("end")
        assert lens.following
        assert lens.cursor_row.seq == 51
        await pilot.press("space")
        assert not lens.following
        await pilot.press("space")
        assert lens.following
        assert lens.cursor_row.seq == 51


async def test_a_gap_in_the_ring_reloads_from_the_file(install_fakes) -> None:
    fakes = install_fakes(_lines(20, NOW - 500))
    app = _LensHarness()
    async with app.run_test(size=(140, 20)) as pilot:
        lens = await _loaded_lens(pilot, app)
        from timeline_fakes import write_lines

        write_lines(fakes.path, [make_line(21, NOW - 100), make_line(22, NOW - 99)])
        fakes.service.gap_once = True
        lens._poll()
        await until(pilot, lambda: len(lens.rows) == 22)


# --------------------------------------------------------------------------
# separators, hidden rows, filter
# --------------------------------------------------------------------------


def _mixed() -> list[dict]:
    t = NOW - 600
    return [
        make_line(1, t, "files", "modify", summary="MODIFY a.db"),
        make_line(2, t + 1, "clock", "sample", summary="clock · device +0 s"),
        make_line(
            3, t + 2, "files", "count", summary="counts", data={"counts": {"open": 4}}
        ),
        make_line(
            4,
            t + 3,
            "snapshot",
            "load",
            summary="snapshot 'clean'",
            world=1,
            epoch=1,
            data={"ok": True},
        ),
        make_line(5, t + 4, "files", "modify", summary="MODIFY b.db", world=1, epoch=1),
        make_line(6, t + 5, "clock", "jump", summary="⏱ clock jump", world=1, epoch=2),
        make_line(
            7,
            t + 6,
            "label",
            "start",
            summary="▶ 1 'cookies'",
            actor="user",
            world=1,
            epoch=2,
            data={"number": 1, "name": "cookies", "depth": 0},
        ),
        make_line(
            8,
            t + 7,
            "run",
            "play-start",
            summary="Play 'login'",
            run="r1",
            world=1,
            epoch=2,
        ),
        make_line(
            9,
            t + 8,
            "net",
            "flow",
            summary="POST 200 api.x.com/v1/cookie",
            actor="app",
            run="r1",
            world=1,
            epoch=2,
        ),
        make_line(10, t + 9, "device", "lost", summary="device lost", world=1, epoch=2),
        make_line(
            11, t + 10, "device", "connect", summary="device back", world=1, epoch=2
        ),
        make_line(
            12,
            t + 11,
            "files",
            "modify",
            summary="MODIFY c.db",
            level="warn",
            world=1,
            epoch=2,
        ),
    ]


async def test_row_columns_never_run_together(install_fakes) -> None:
    """F4: full-width src/kind/actor values are still separated by a gap."""
    import re

    install_fakes(
        [
            make_line(1, NOW - 2, "sandroid", "policy", summary="FIRST"),
            make_line(2, NOW - 1, "sandroid", "play-result", summary="SECOND"),
        ]
    )
    app = _LensHarness()
    async with app.run_test(size=SIZE) as pilot:
        lens = await _loaded_lens(pilot, app)
        assert [r.seq for r in lens.rows] == [1, 2]

        def text(y: int, width: int) -> str:
            return "".join(seg.text for seg in lens.strip_for(y, width))

        # >= 100 cols: delta, src, kind, actor, summary.
        # >= 100 cols: delta, type word, kind, actor, summary.
        assert re.search(r"\.\d{3} +system +policy +sandr… +FIRST", text(0, 160))
        assert re.search(r"\+\S+ +system +play-result +sandr… +SECOND", text(1, 160))
        # 80..99 cols: no actor column.
        assert re.search(r"\+\S+ +system +play-result +SECOND", text(1, 90))
        # < 80 cols: no delta column either.
        assert re.search(r"\.\d{3} +system +play-result +SECOND", text(1, 70))
        for width in (160, 90, 70):
            assert "systempolicy" not in text(0, width)
            assert "play-resultsandr" not in text(1, width)


async def test_separators_hidden_rows_and_N(install_fakes) -> None:
    install_fakes(_mixed())
    app = _LensHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        lens = await _loaded_lens(pilot, app)
        seqs = [r.seq for r in lens.visible_rows]
        assert not {2, 3} & set(seqs)  # clock sample, count
        assert 11 not in seqs  # reconnect folded into the lost row
        assert 10 in seqs
        assert len(lens.rows) == 12

        def text(seq: int) -> str:
            vi = [r.seq for r in lens.visible_rows].index(seq)
            strip = lens.strip_for(vi + lens._display_offset(), 140)
            return "".join(seg.text for seg in strip)

        assert "snapshot 'clean' · world 1" in text(4)
        assert "clock epoch 2 · clock jump" in text(6)
        assert "Section 1 'cookies'" in text(7)
        assert "replay started · Play 'login'" in text(8)
        for seq in (4, 6, 7, 8):  # plain words: no symbols, no rule line
            assert not set(text(seq)) & set("⟲⏱▶▷◉⚑─⇢↓↑‖")
        assert "reconnected +1.0s" in text(10)
        assert text(12)[3] == "!"  # warn flag in the gutter
        assert "│" in text(9)[:4]  # inside Section 1
        lens.app.notify = lambda *a, **k: None
        await pilot.press("N")
        assert {2, 3, 11} <= {r.seq for r in lens.visible_rows}


async def test_filter_grammar_chips_separators_survive_and_esc_clears(
    install_fakes,
) -> None:
    install_fakes(_mixed())
    app = _LensHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        lens = await _loaded_lens(pilot, app)
        lens.view.focus()
        await pilot.press("slash", *"src:files", "space", *"-kind:count")
        await pilot.press("enter")
        await pilot.pause()
        seqs = {r.seq for r in lens.visible_rows}
        assert {1, 5, 12} <= seqs
        assert 9 not in seqs  # a net row
        assert {4, 6, 7, 8} <= seqs  # separators survive src filters
        assert lens.chip_text().startswith("src files · -kind count · ")
        lens.set_filter("cookie")
        assert {r.seq for r in lens.visible_rows} == {7, 9}  # text hides seps too
        lens.set_filter("-src:label")
        assert 7 not in {r.seq for r in lens.visible_rows}
        lens.set_filter("actor:user level:warn")
        assert 12 not in {r.seq for r in lens.visible_rows}
        lens.set_filter("world:1 phase:live")
        assert 1 not in {r.seq for r in lens.visible_rows}
        assert lens.handle_escape()
        assert lens.query_text == ""
        assert not lens.handle_escape()


async def test_review_scope_adds_a_run_chip(install_fakes) -> None:
    from sandroid.tui.widgets.lens_shell import ScopeChanged

    install_fakes(_mixed())
    app = _LensHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        lens = await _loaded_lens(pilot, app)
        lens.post_message(ScopeChanged("/results/runs/r1", "#1 login"))
        await settle(pilot)
        assert lens.chip_text().startswith("REVIEW run r1")
        assert {r.seq for r in lens.visible_rows} == {8, 9}
        lens.set_review_window((NOW - 600 + 2.5, NOW - 600 + 6.5))
        assert {r.seq for r in lens.visible_rows} == {4, 6, 7, 8, 9}
        lens.post_message(ScopeChanged(None))
        await settle(pilot)
        assert "REVIEW" not in lens.chip_text()


# --------------------------------------------------------------------------
# inspector, masking, reveal
# --------------------------------------------------------------------------


def _plain(content, tab: str) -> str:
    from rich.console import Console

    console = Console(width=120, record=True, color_system=None)
    for heading, body in dict(content.tabs)[tab]:
        console.print(heading)
        console.print(body)
    return console.export_text()


async def test_inspector_masks_per_setting_and_V_reveals_after_confirm(
    install_fakes,
) -> None:
    lines = _lines(3, NOW - 100) + [
        make_line(
            4, NOW - 90, "input", "text", summary="typed 8 chars into 'Password'",
            sensitive=True, actor="user", data={"text": "hunter22", "password": True},
            ref={"raw": "tracking/raw/getevent.txt#L1-2"},
        )
    ]  # fmt: skip
    fakes = install_fakes(lines)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        await pilot.press("5")
        lens = ms.lens_widget("timeline")
        await until(pilot, lambda: len(lens.rows) == 4)
        # Masking off: the JSON tab shows the text.
        await pilot.press("enter")
        await until(pilot, lambda: 4 in lens._detail)
        assert ms.inspector_is_open
        content = ms.inspector_content
        assert content.title == "#4 input/text"
        assert "hunter22" in _plain(content, "JSON")
        # V is inert while masking is off.
        await pilot.press("V")
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert any("Masking is off" in m for m in _messages(app))
        # Masking on: masked, V asks, Esc keeps it masked.
        fakes.module.MASK = True
        ms.update_inspector(lens._content(lens.cursor_row))
        assert "hunter22" not in _plain(ms.inspector_content, "JSON")
        assert "_masked" in _plain(ms.inspector_content, "JSON")
        await pilot.press("V")
        await settle(pilot)
        assert type(app.screen).__name__ == "ConfirmModal"
        await pilot.press("escape")
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert fakes.service.reveals == []
        await pilot.press("V")
        await settle(pilot)
        await pilot.press("tab")  # any focus; y answers
        app.screen.action_yes()
        await settle(pilot)
        assert fakes.service.reveals == [4]
        assert lens.revealed == 4
        # The reveal paused follow: its own audit line (#5), pulled in by the
        # live poll, must not move the cursor and end the reveal (this raced
        # the 250 ms poll under load).
        assert not lens.following
        lens._poll()
        lens.release_pending()
        await until(pilot, lambda: 5 in lens._by_seq)
        assert lens.revealed == 4
        await until(pilot, lambda: "hunter22" in _plain(ms.inspector_content, "JSON"))
        # Moving the selection masks it again.
        lens.view.focus()
        await pilot.press("up")
        await settle(pilot)
        assert lens.revealed is None
        assert "Chain" in dict(ms.inspector_content.tabs)


# --------------------------------------------------------------------------
# J jumps
# --------------------------------------------------------------------------


async def test_J_jumps_to_files_network_runs_and_ref_of(
    install_fakes, monkeypatch
) -> None:
    from sandroid.tui.widgets.diffs_view import DiffsView
    from sandroid.tui.widgets.files_panel import FilesPanel
    from sandroid.tui.widgets.network_panel import NetworkPanel

    calls: list = []
    monkeypatch.setattr(
        FilesPanel,
        "reveal",
        lambda self, path, version=None: calls.append(("files", path, version)) or True,
    )
    monkeypatch.setattr(
        NetworkPanel,
        "reveal_flow",
        lambda self, fid, record=None: (
            calls.append(("net", fid, record["host"])) or True
        ),
    )
    monkeypatch.setattr(
        DiffsView, "select_run", lambda self, rid: calls.append(("runs", rid)) or True
    )
    t = NOW - 100
    install_fakes(
        [
            make_line(
                1,
                t,
                "files",
                "pull",
                summary="◆ v003 app.db",
                data={"path": "/data/data/x/app.db", "version": "v003"},
                ref={"path": "files/x/app.db/v003/diff.json", "lens": "files"},
            ),
            make_line(
                2,
                t + 1,
                "net",
                "flow",
                summary="POST 200",
                data={"host": "api.x.com", "method": "POST", "flow_seq": 9},
                ref={"id": "abc", "lens": "network"},
            ),
            make_line(
                3,
                t + 2,
                "run",
                "play-end",
                summary="Play done",
                ref={"of": 1, "run": "r7", "lens": "runs"},
            ),
            make_line(4, t + 3, "input", "confirm", summary="confirmed", ref={"of": 2}),
            make_line(5, t + 4, "files", "modify", summary="MODIFY x"),
        ]
    )
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await boot(app, pilot)
        ms = app.screen
        await pilot.press("5")
        lens = ms.lens_widget("timeline")
        await until(pilot, lambda: len(lens.rows) == 5)
        for seq, lens_id in ((1, "files"), (2, "network"), (3, "runs")):
            await pilot.press("5")
            await settle(pilot)
            assert lens._select_seq(seq)
            await pilot.press("J")
            await settle(pilot)
            assert ms.active_lens == lens_id
        assert calls == [
            ("files", "/data/data/x/app.db", "v003"),
            ("net", "abc", "api.x.com"),
            ("runs", "r7"),
        ]
        await pilot.press("5")
        await settle(pilot)
        lens._select_seq(4)
        await pilot.press("J")  # ref.of -> that row here
        await settle(pilot)
        assert ms.active_lens == "timeline"
        assert lens.cursor_row.seq == 2
        lens._select_seq(5)
        await pilot.press("J")
        await settle(pilot)
        assert any("Nothing to jump to" in m for m in _messages(app))


async def test_jump_targets_reveal_flow_and_select_run(install_fakes) -> None:
    install_fakes()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        ms.switch_lens("network")
        net = ms.lens_widget("network")
        assert not net.reveal_flow("nope")
        record = {"id": "abc", "seq": 5, "method": "POST", "host": "api.x.com"}
        record.update(path="/v1", status_code=200, ts_start=NOW, ts_end=NOW)
        assert net.reveal_flow("abc", record=record)
        await settle(pilot)
        assert ms.inspector_is_open
        assert ms.inspector_content.key == "network:row:f5"
        ms.switch_lens("runs")
        runs = ms.lens_widget("runs")
        assert runs.select_run("missing") is False
        runs._summaries = [{"run_id": "r1", "label": "login", "started_at": None}]
        runs._load_run_detail = lambda run_id: None
        assert runs.select_run("r1") is True
        await settle(pilot)
        assert runs._selected_run_id == "r1"
        assert ms.inspector_is_open


async def test_files_reveal_selects_the_row_and_opens_versions(install_fakes) -> None:
    from sandroid.tui.controllers.monitor_controller import build_monitor_item

    install_fakes()
    root = "/data/data/com.example.fit"
    path = f"{root}/databases/app.db"
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        ms.switch_lens("files")
        files = ms.lens_widget("files")
        files.ingest(
            [
                build_monitor_item(
                    f'FSE_CONTENT_MODIFIED\t1\t"fit"\t{p}', (root + "/",)
                )
                for p in (f"{root}/files/a.txt", path)
            ]
        )
        files.refresh_rows()
        assert files.reveal("/data/data/unknown") is False
        assert files.reveal(path, version="v002")
        await settle(pilot)
        assert files.current_row().key == path
        assert ms.inspector_is_open
        assert ms.query_one("#inspector").tab_name == "Versions"
        from sandroid.tui.widgets import file_inspect

        assert file_inspect.state_for(path).selected == "v002"


# --------------------------------------------------------------------------
# label keys (#, +, -, B), the name prompt, Files segments
# --------------------------------------------------------------------------


async def _label(pilot, key: str, name: str = "") -> None:
    await pilot.press(key)
    await settle(pilot)
    if name:
        await pilot.press(*name)
    await pilot.press("enter")
    await settle(pilot)


async def test_label_keys_nest_close_stop_and_esc_writes_nothing(install_fakes) -> None:
    fakes = install_fakes()
    labels = fakes.labels
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await boot(app, pilot)
        ms = app.screen
        await pilot.press("number_sign")
        await settle(pilot)
        assert type(app.screen).__name__ == "InputModal"
        assert "Section 1 · start at" in str(app.screen.title_text)
        await pilot.press(*"cookies", "enter")
        await settle(pilot)
        await _label(pilot, "plus", "a")  # 2 under 1
        await _label(pilot, "plus", "b")  # sibling: ends 2, starts 3 under 1
        hist = [(e.kind, e.number, e.ended_by, e.depth) for e in labels.history()]
        assert hist == [
            ("start", 1, None, 0),
            ("start", 2, None, 1),
            ("end", 2, "sibling", 1),
            ("start", 3, None, 1),
        ]
        await _label(pilot, "number_sign", "next")  # closes the whole stack
        assert [s.number for s in labels.open_spans()] == [4]
        ended = [(e.number, e.ended_by) for e in labels.history() if e.kind == "end"]
        assert ended[-2:] == [(3, "new_label"), (1, "new_label")]
        await _label(pilot, "plus", "sub")
        await pilot.press("minus")  # innermost
        await settle(pilot)
        assert [s.number for s in labels.open_spans()] == [4]
        await pilot.press("minus", "minus")
        await settle(pilot)
        assert labels.open_spans() == []
        assert any("No open section." in m for m in _messages(app))
        # + with nothing open: a top-level label and the notice.
        await _label(pilot, "plus", "top")
        assert labels.open_spans()[0].depth == 0
        assert any("started a top-level section" in m for m in _messages(app))
        # Esc writes nothing.
        before = len(labels.history())
        for key in ("number_sign", "plus", "B"):
            await pilot.press(key)
            await settle(pilot)
            await pilot.press("escape")
            await settle(pilot)
        assert len(labels.history()) == before
        assert type(app.screen).__name__ == "MainScreen"
        # The marks are the Files projection of the labels.
        assert [m.label() for m in ms.marks][:3] == [
            "Section 1 'cookies'",
            "after Section 1",
            "Section 4 'next'",
        ]
        # t is the key press, not the Enter.
        start = labels.calls[0]
        assert start[0] == "start"
        assert isinstance(start[1]["t"], float)


async def test_B_is_global_in_every_lens_and_the_name_is_typed_into_the_prompt(
    install_fakes,
) -> None:
    fakes = install_fakes()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        for spec in LENSES:
            await pilot.press(spec.key)
            await settle(pilot)
            await _label(pilot, "B", spec.id)
        points = [e for e in fakes.labels.history() if e.kind == "point"]
        assert [p.name for p in points] == [spec.id for spec in LENSES]
        # Label keys typed into the prompt are text, not commands.
        await pilot.press("number_sign")
        await settle(pilot)
        await pilot.press("a", "plus", "b", "minus", "c", "number_sign", "B", "5")
        await pilot.press("enter")
        await settle(pilot)
        assert fakes.labels.history()[-1].name == "a+b-c#B5"
        assert ms.active_lens == LENSES[-1].id
        assert "Note 1 'app'" in ms.query_one("#log-ticker").last_line or (
            f"Section {len(LENSES) + 1}" in ms.query_one("#log-ticker").last_line
        )


async def test_the_typing_guard_swallows_label_keys(install_fakes) -> None:
    fakes = install_fakes()
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await boot(app, pilot)
        ms = app.screen
        # "/" in a lens without a filter (Sessions) starts the guard ...
        await pilot.press("4", "slash")
        await settle(pilot)
        assert ms.typing_guard_active()
        await pilot.press("a", "number_sign", "plus", "minus", "B", "5")
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert ms.active_lens == "runs"
        assert fakes.labels.history() == []
        # ... and so does a "that looked like typing" cancel.
        ms.start_typing_guard()
        await pilot.press("x", "number_sign", "B")
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert fakes.labels.history() == []
        # ctrl+t is not typing: it passes the guard.
        ms.start_typing_guard()
        await pilot.press("ctrl+t")
        await until(pilot, lambda: fakes.tracking.toggles == ["user"])


async def test_label_keys_do_nothing_under_a_modal(install_fakes) -> None:
    fakes = install_fakes()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        await pilot.press("question_mark")
        await settle(pilot)
        assert app.check_action("label_start", ()) is False
        app.action_label_stop()  # direct call: no MainScreen on top
        await pilot.press("escape")
        await settle(pilot)
        assert app.check_action("label_start", ()) is True
        assert fakes.labels.history() == []


async def test_files_lens_segments_follow_labels_in_note_and_section_wording(
    install_fakes,
) -> None:
    from sandroid.tui.controllers.monitor_controller import build_monitor_item

    fakes = install_fakes()
    root = "/data/data/com.example.fit"
    t0 = datetime.now() - timedelta(minutes=10)

    def item(path: str):
        return build_monitor_item(
            f'FSE_CONTENT_MODIFIED\t1\t"fit"\t{path}', (root + "/",)
        )

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        await pilot.press("3")
        await settle(pilot)
        files = ms.lens_widget("files")
        files.ingest([item(f"{root}/a.db")], now=t0)
        ms.add_label("start", "cookies", t0 + timedelta(seconds=10))
        await settle(pilot)  # MarksChanged reaches the lens
        files.ingest([item(f"{root}/b.db")], now=t0 + timedelta(seconds=15))
        fakes.labels.stop(t=(t0 + timedelta(seconds=20)).timestamp())
        ms._labels_changed(fakes.labels.history()[-1])
        await settle(pilot)  # MarksChanged reaches the lens
        files.ingest([item(f"{root}/c.db")], now=t0 + timedelta(seconds=25))
        ms.add_mark("tap", t0 + timedelta(seconds=30))
        await settle(pilot)  # MarksChanged reaches the lens
        files.ingest([item(f"{root}/d.db")], now=t0 + timedelta(seconds=35))
        await settle(pilot)
        assert [m.kind for m in files.marks] == ["start", "end", "point"]
        assert files.segment == 3
        t = lambda s: (t0 + timedelta(seconds=s)).strftime("%H:%M:%S")  # noqa: E731
        assert files._segment_title() == f"since Note 2 'tap' · {t(30)}"
        files._segment = 2
        assert files._segment_title() == (
            f"after Section 1 (no section) → Note 2 'tap' · {t(20)}–{t(30)}"
        )
        files._segment = 1
        assert files._segment_title() == (
            f"Section 1 'cookies' → after Section 1 · {t(10)}–{t(20)}"
        )
        files._segment = 0
        assert files._segment_title() == f"before Section 1 'cookies' · until {t(10)}"
        # A / < > still navigate the segments on top of the label model.
        files.table.focus()
        files._segment = 3
        await pilot.press("less_than_sign")
        await settle(pilot)
        assert files.segment == 2
        rows = {r.key for r in files._rows}
        assert f"{root}/c.db" in rows
        assert f"{root}/d.db" not in rows
        await pilot.press("A")
        await settle(pilot)
        assert files.segment is None
        await pilot.press("A")
        await settle(pilot)
        assert files.segment == 3
        await pilot.press("greater_than_sign")
        await settle(pilot)
        assert files.segment == 3


async def test_a_pending_label_pre_splits_files_and_esc_settles(install_fakes) -> None:
    install_fakes()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        await pilot.press("3")
        await settle(pilot)
        files = ms.lens_widget("files")
        await pilot.press("B")
        await settle(pilot)
        assert type(app.screen).__name__ == "InputModal"
        assert len(files.activity.mark_times) == 1  # pre-split at the key press
        await pilot.press("escape")
        await settle(pilot)
        assert len(files.activity.mark_times) == 0
        assert files.marks == []


def test_marks_changed_carries_pending_and_mark_wording() -> None:
    when = datetime(2026, 11, 19, 10, 0, 0)
    msg = MarksChanged([], None, pending=when)
    assert msg.pending == when
    assert Mark(3, when, "tap").label() == "Note 3 'tap'"
    assert Mark(3, when).label() == "Note 3"
    assert Mark(7, when, "x", "start").label() == "Section 7 'x'"
    assert Mark(7, when, "x", "end").label() == "after Section 7"


async def test_without_the_timeline_labels_stay_in_memory(monkeypatch) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "sandroid.core.timeline", None)
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await boot(app, pilot)
        ms = app.screen
        await _label(pilot, "B", "x")
        assert [m.label() for m in ms.marks] == ["Note 1 'x'"]
        assert any("Timeline unavailable" in m for m in _messages(app))
        await pilot.press("minus")
        await settle(pilot)
        assert any("sections need the session timeline" in m for m in _messages(app))
        await pilot.press("5")
        await settle(pilot)
        lens = ms.lens_widget("timeline")
        await until(pilot, lambda: lens._loaded)
        assert "Timeline unavailable" in "".join(
            seg.text for seg in lens.strip_for(0, 120)
        )


# --------------------------------------------------------------------------
# Tracking key, header, doorbell
# --------------------------------------------------------------------------


async def test_ctrl_t_toggles_tracking_and_the_header_shows_it(install_fakes) -> None:
    fakes = install_fakes()
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await boot(app, pilot)
        ms = app.screen
        header = ms.query_one("#shell-header")
        await pilot.press("ctrl+t")
        await until(pilot, lambda: fakes.tracking.active)
        await until(pilot, lambda: header.tracking_on)
        assert fakes.tracking.toggles == ["user"]
        await pilot.press("ctrl+t")
        await until(pilot, lambda: not header.tracking_on)


async def test_ctrl_t_without_tracking_says_so(install_fakes) -> None:
    install_fakes(tracking=False)
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await boot(app, pilot)
        await pilot.press("ctrl+t")
        await settle(pilot)
        assert any("Tracking not available" in m for m in _messages(app))


async def test_header_label_note_banner_and_no_clock_sampling(
    install_fakes, monkeypatch
) -> None:
    from sandroid.core import device_clock
    from sandroid.core.adb import Adb

    sampled: list = []
    monkeypatch.setattr(device_clock, "record_async", lambda *a, **k: sampled.append(a))
    monkeypatch.setattr(Adb, "get_target_device", staticmethod(lambda: "emulator-test"))
    fakes = install_fakes()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        header = ms.query_one("#shell-header")
        now = time.time()
        for step in range(4):
            header.update_device_clock(now + step * 120)
        assert sampled == []  # the timeline writer samples, not the header
        fakes.labels.start("accept cookies", t=now - 12)
        header.refresh_timeline_state(now)
        assert header.label_note == "Section 1 'accept cookies' 0:12"
        fakes.labels.stop()
        header.refresh_timeline_state(now)
        assert header.label_note is None
        fakes.service.state = "locked"
        fakes.service.locked_by = "PID 4711 on host"
        header.refresh_timeline_state(now)
        assert header.timeline_banner == "timeline locked (PID 4711 on host)"
        lens = ms.lens_widget("timeline")
        assert lens.badge() == "locked"
        assert "Timeline locked by PID 4711" in lens._banner()
        ms._handle_timeline_event(SimpleNamespace(data={"op": "locked"}))
        await settle(pilot)
        assert ms.query_one("#lens-bar").badge("timeline") == "locked"


async def test_doorbell_rebuilds_marks_for_labels_added_elsewhere(
    install_fakes,
) -> None:
    fakes = install_fakes()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        assert len(ms.marks) == 0
        fakes.labels.point("from the AI", source="ai")  # not through the UI
        ms._handle_timeline_event(
            SimpleNamespace(data={"op": "lines", "srcs": ["label"], "last_seq": 1})
        )
        await settle(pilot)
        assert [m.label() for m in ms.marks] == ["Note 1 'from the AI'"]
        assert ms.lens_widget("files").segment == 1


def test_no_call_from_thread_in_timeline_subscribers() -> None:
    import inspect

    from sandroid.tui.screens.main_screen import MainScreen
    from sandroid.tui.widgets import timeline_lens

    assert "call_from_thread" not in inspect.getsource(timeline_lens)
    assert "call_from_thread" not in inspect.getsource(
        MainScreen._handle_timeline_event
    )


# --------------------------------------------------------------------------
# Settings → Timeline
# --------------------------------------------------------------------------


class _ConfigProxy:
    """A real config plus the WP1 ``timeline``/``tracking`` sections."""

    def __init__(self, config) -> None:
        self._config = config
        self.timeline = SimpleNamespace(
            sources={"files": True, "monitor": True, "net": True, "input": True,
                     "screen": True, "shot": True},
            kinds_off=[], count_only=["files.open", "files.close"],
            files_attrs="app_dirs", files_modify_coalesce_ms=1000,
            count_window_s=5.0, queue_max=10_000, clock_every_s=60,
            mask_sensitive=False,
        )  # fmt: skip
        self.tracking = SimpleNamespace(
            helper_mode="full", auto_on_record=True, shot_before_tap=True,
            shot_screen_change=True, shot_after_tap=False, shot_label=False,
            settle_interval_ms=300, settle_max_ms=2000, capture_text=True,
            text_idle_ms=1500, long_press_ms=500, swipe_slop_px=24,
            logcat_screen_backup=True,
        )  # fmt: skip
        ai = config.ai
        self.ai = SimpleNamespace(
            **{"mask_sensitive": False}
            | {k: getattr(ai, k) for k in type(ai).model_fields}
        )

    def __getattr__(self, name):
        return getattr(self._config, name)


async def test_settings_timeline_tab_stages_whole_values_and_two_part_keys(
    monkeypatch,
) -> None:
    from textual.widgets import Input, Select, Switch

    from sandroid.config import SandroidConfig
    from sandroid.tui.screens.settings_screen import SettingsScreen

    monkeypatch.setattr(SettingsScreen, "_fetch_frida_versions", lambda self: None)

    class _Harness(App):
        def __init__(self) -> None:
            super().__init__()
            self.sandroid_config = _ConfigProxy(SandroidConfig())

        def on_mount(self) -> None:
            self.push_screen(SettingsScreen())

    app = _Harness()
    async with app.run_test(size=(140, 50)) as pilot:
        await settle(pilot)
        screen = app.screen
        screen._pending.clear()
        screen.query_one("#setting-timeline--sources__net", Switch).value = False
        screen.query_one(
            "#setting-timeline--kinds_off", Input
        ).value = "files.attrs, monitor.*"
        screen.query_one("#setting-timeline--count_window_s", Input).value = "7.5"
        screen.query_one("#setting-timeline--mask_sensitive", Switch).value = True
        screen.query_one("#setting-ai--mask_sensitive", Switch).value = True
        screen.query_one("#setting-tracking--settle_max_ms", Input).value = "3000"
        screen.query_one("#setting-tracking--shot_after_tap", Switch).value = True
        screen.query_one("#setting-tracking--helper_mode", Select).value = "invisible"
        await settle(pilot)
        pending = screen._pending
        assert pending["timeline.sources"] == {
            "files": True, "monitor": True, "net": False, "input": True,
            "screen": True, "shot": True,
        }  # fmt: skip
        assert pending["timeline.kinds_off"] == ["files.attrs", "monitor.*"]
        assert pending["timeline.count_window_s"] == 7.5
        assert pending["timeline.mask_sensitive"] is True
        assert pending["ai.mask_sensitive"] is True
        assert pending["tracking.settle_max_ms"] == 3000
        assert pending["tracking.shot_after_tap"] is True
        assert pending["tracking.helper_mode"] == "invisible"
        assert all(key.count(".") == 1 for key in pending), pending
        # Every TrackingConfig field has a widget.
        for name in vars(app.sandroid_config.tracking):
            assert screen.query(f"#setting-tracking--{name}"), name


async def test_settings_save_is_the_users_and_skips_unchanged_timeline_keys(
    monkeypatch,
) -> None:
    """F5 + F9: Ctrl+S is logged as the user's, and the Timeline tab's
    Inputs/Selects (which post Changed while mounting) save nothing unchanged.
    """
    from textual.widgets import Select

    import sandroid.config as config_mod
    from sandroid.config import SandroidConfig
    from sandroid.core import timeline
    from sandroid.tui.controllers import settings_controller
    from sandroid.tui.screens.settings_screen import SettingsScreen

    monkeypatch.setattr(SettingsScreen, "_fetch_frida_versions", lambda self: None)
    config = SandroidConfig()
    monkeypatch.setattr(config_mod, "_config_instance", config)
    saved: list[set[str]] = []
    real_update = config_mod.update_config

    def _update(pending, persist=True):
        saved.append(set(pending))
        return real_update(pending, persist=False)  # never touch a real file

    monkeypatch.setattr(settings_controller, "update_config", _update)

    class _Harness(App):
        def __init__(self) -> None:
            super().__init__()
            self.sandroid_config = config

        def on_mount(self) -> None:
            self.push_screen(SettingsScreen())

    async def open_and_save(change=None) -> None:
        app = _Harness()
        async with app.run_test(size=(140, 50)) as pilot:
            await settle(pilot)
            if change is not None:
                change(app.screen)
                await settle(pilot)
            await pilot.press("ctrl+s")
            await settle(pilot)
            assert not isinstance(app.screen, SettingsScreen)

    def helper_invisible(screen) -> None:
        select = screen.query_one("#setting-tracking--helper_mode", Select)
        select.value = "invisible"

    def policy_keys(keys: set[str]) -> set[str]:
        return {k for k in keys if k.startswith(("timeline.", "tracking."))}

    with timeline.capture() as lines:
        await open_and_save()
        await open_and_save(helper_invisible)
    assert len(saved) == 2
    assert policy_keys(saved[0]) == set()  # nothing changed on the tab
    assert policy_keys(saved[1]) == {"tracking.helper_mode"}
    policy = [line for line in lines if line["kind"] == "policy"]
    assert len(policy) == 1, policy  # no empty changed:{} line
    assert policy[0]["actor"] == "user"
    assert policy[0]["data"]["by"] == "user"
    assert policy[0]["data"]["changed"] == {
        "tracking.helper_mode": ["full", "invisible"]
    }


# --------------------------------------------------------------------------
# with the real timeline core (active after the WP1 merge)
# --------------------------------------------------------------------------


def _real_timeline():
    mod = pytest.importorskip("sandroid.core.timeline")
    if not hasattr(mod, "TimelineService"):
        pytest.skip("sandroid.core.timeline is not the WP1 core yet")
    return mod


async def test_real_labels_are_written_as_timeline_lines(tmp_path) -> None:
    mod = _real_timeline()
    svc = mod.get_timeline()
    folder = tmp_path / "session" / "dev"
    svc.bind("emulator-test", folder)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        await _label(pilot, "number_sign", "cookies")
        await _label(pilot, "B", "tap")
        await pilot.press("minus")
        await settle(pilot)
        assert [m.label() for m in ms.marks] == [
            "Section 1 'cookies'",
            "Note 2 'tap'",
            "after Section 1",
        ]
        assert svc.flush(2.0)
        kinds = [
            (line["src"], line["kind"])
            for _off, line in mod.read_lines(folder / mod.FILE_NAME)
            if line["src"] == "label"
        ]
        assert kinds == [("label", "start"), ("label", "point"), ("label", "end")]


async def test_real_lens_shows_lines_written_by_the_service(tmp_path) -> None:
    mod = _real_timeline()
    svc = mod.get_timeline()
    folder = tmp_path / "session" / "dev"
    svc.bind("emulator-test", folder)
    svc.emit("sandroid", "intervention", summary="a11y helper on", data={"what": "x"})
    assert svc.flush(2.0)
    app = _LensHarness()
    async with app.run_test(size=SIZE) as pilot:
        lens = await _loaded_lens(pilot, app)
        assert any(r.kind == "intervention" for r in lens.rows)
        svc.emit("files", "pull", summary="◆ v001 app.db", data={"path": "/x"})
        await until(pilot, lambda: any(r.kind == "pull" for r in lens.rows))


# --------------------------------------------------------------------------
# review fixes (R1 #3/#5, R2 M2/M4/M10/M11/L17/L18)
# --------------------------------------------------------------------------


async def test_live_row_without_offset_is_read_back_by_seq(
    install_fakes, monkeypatch
) -> None:
    """R2-M11: a live row that left the line cache never hangs on loading…"""
    from sandroid.tui.widgets import timeline_lens as tl

    fakes = install_fakes([make_line(1, NOW - 100)])
    fakes.service.write_through = True  # the writer put every line in the file
    monkeypatch.setattr(tl, "_LINE_CACHE", 3)
    app = _LensHarness()
    async with app.run_test(size=(160, 40)) as pilot:
        lens = await _loaded_lens(pilot, app)
        for i in range(10):
            fakes.service.emit("files", "modify", summary=f"m{i}", t=NOW - 50 + i)
        lens._poll()
        await until(pilot, lambda: len(lens.rows) == 11)
        row = lens._by_seq[3]
        assert row.offset is None  # TailResult without offsets (today's core)
        assert 3 not in lens._lines  # evicted
        lens._load_detail(row)
        await until(pilot, lambda: 3 in lens._detail)
        detail = lens._detail[3]
        assert detail["line"]["summary"] == "m1"
        assert detail["prev"]["seq"] == 2
        assert lens._by_seq[3].offset == fakes.service.offsets[3]  # remembered
        assert "loading" not in _plain(lens._content(lens._by_seq[3]), "Line")
        # A row whose line is nowhere: an error, not "loading…" forever.
        ghost = row_from_line(make_line(99, NOW - 1))
        lens._load_detail(ghost)
        await until(pilot, lambda: 99 in lens._detail)
        assert "not readable" in _plain(lens._content(ghost), "JSON")
        assert "not readable" in _plain(lens._content(ghost), "Line")


async def test_live_rows_keep_ring_offsets_when_tail_has_them(install_fakes) -> None:
    fakes = install_fakes([make_line(1, NOW - 100)])
    fakes.service.write_through = True
    fakes.service.ring_offsets = True
    app = _LensHarness()
    async with app.run_test(size=(160, 40)) as pilot:
        lens = await _loaded_lens(pilot, app)
        fakes.service.emit("files", "modify", summary="live", t=NOW - 50)
        lens._poll()
        await until(pilot, lambda: 2 in lens._by_seq)
        assert lens._by_seq[2].offset == fakes.service.offsets[2]


async def test_reveal_ends_on_follow_filter_and_rebind(install_fakes) -> None:
    """R2-L17: the reveal is tied to the selection, however it changes."""
    secret = {
        "sensitive": True,
        "data": {"text": "hunter22"},
        "summary": "typed",
        "ref": {"raw": "tracking/raw/getevent.txt#L1-2"},
    }
    lines = [make_line(1, NOW - 100), make_line(2, NOW - 90, "input", "text", **secret)]
    fakes = install_fakes(lines)
    fakes.module.MASK = True
    app = _LensHarness()
    async with app.run_test(size=(160, 40)) as pilot:
        lens = await _loaded_lens(pilot, app)
        assert lens.cursor_row.seq == 2
        assert lens.following
        lens.reveal(2)
        assert fakes.service.reveal_devs == [timeline_fakes.SERIAL]  # dev passed
        # the reveal paused follow: a new line keeps the selection (and it)
        assert not lens.following
        fakes.service.emit("files", "modify", summary="new", t=NOW - 10)
        lens._poll()
        lens.release_pending()
        await until(pilot, lambda: len(lens.rows) >= 3)
        assert lens.cursor_row.seq == 2
        assert lens.revealed == 2
        # resuming follow moves the selection to the newest line: it ends
        lens.action_newest()
        assert lens.cursor_row.seq != 2
        assert lens.revealed is None
        lens.click_line(1)
        assert lens.cursor_row.seq == 2
        lens._load_detail(lens.cursor_row)
        await until(pilot, lambda: 2 in lens._detail)
        assert "hunter22" not in _plain(lens._content(lens.cursor_row), "JSON")
        # a filter change ends it even when the same row stays selected
        lens.reveal(2)
        lens.set_filter("typed")
        assert lens.cursor_row.seq == 2
        assert lens.revealed is None
        # a new sink ends it
        lens.reveal(2)
        lens.on_timeline_bound()
        assert lens.revealed is None


async def test_ref_tab_masks_ref_raw(install_fakes) -> None:
    """R1#5: the Ref tab shows the masked ref while masking is on."""
    lines = [
        make_line(
            1, NOW - 90, "input", "text", sensitive=True, summary="typed",
            data={"text": "hunter22"}, ref={"raw": "tracking/raw/getevent.txt#L1-2"},
        )
    ]  # fmt: skip
    fakes = install_fakes(lines)
    fakes.module.MASK = True
    app = _LensHarness()
    async with app.run_test(size=(160, 40)) as pilot:
        lens = await _loaded_lens(pilot, app)
        content = lens._content(lens.cursor_row)
        assert "getevent.txt#L1-2" not in _plain(content, "JSON")
        assert "getevent.txt#L1-2" not in _plain(content, "Ref")
        lens.reveal(1)
        assert "getevent.txt#L1-2" in _plain(lens._content(lens.cursor_row), "Ref")


async def test_negative_terms_keep_separators_but_minus_src_hides_them(
    install_fakes,
) -> None:
    install_fakes(_mixed())
    app = _LensHarness()
    async with app.run_test(size=(140, 30)) as pilot:
        lens = await _loaded_lens(pilot, app)
        lens.set_filter("-actor:user -kind:start,load")
        seqs = {r.seq for r in lens.visible_rows}
        assert {4, 7} <= seqs  # the world and label separators stay
        lens.set_filter("-src:label")
        assert 7 not in {r.seq for r in lens.visible_rows}


def test_late_insert_patches_the_view_like_a_full_rebuild() -> None:
    """R2-L18: a late line no longer rebuilds the whole view."""
    t0 = NOW - 10_000
    base = []
    for i in range(400):
        src, kind = [("files", "modify"), ("clock", "sample"), ("net", "flow")][i % 3]
        epoch = i // 100
        base.append(row_from_line(make_line(i + 1, t0 + i, src, kind, epoch=epoch)))
    for text in ("", "src:files", "-src:clock", "src:net"):
        lens = TimelineLens()
        lens._apply_rows(list(base), 0)
        lens._query = parse_query(text)
        lens._rebuild_view(keep=False)
        late = [
            row_from_line(make_line(1000 + k, t0 + k * 37.5, "files", "create"))
            for k in range(10)
        ] + [row_from_line(make_line(2000, t0 + 99.5, "net", "flow", epoch=0))]
        lens._follow = False
        lens.insert_rows(late)
        patched = list(lens._view)
        lens._rebuild_view(keep=False)
        assert patched == lens._view, text


@pytest.mark.perf
def test_late_insert_is_much_cheaper_than_a_rebuild() -> None:
    n = 60_000
    t0 = NOW - n
    rows = [row_from_line(make_line(i + 1, t0 + i), i * 300) for i in range(n)]
    lens = TimelineLens()
    lens._apply_rows(rows, 0)
    lens._follow = False
    started = time.perf_counter()
    lens._rebuild_view(keep=False)
    rebuild = time.perf_counter() - started
    late = row_from_line(make_line(n + 1, t0 + n - 50))
    started = time.perf_counter()
    lens.insert_rows([late])
    insert = time.perf_counter() - started
    assert insert < rebuild / 3, (insert, rebuild)


async def test_label_keys_record_actor_user(install_fakes) -> None:
    """R2-M2: key labels are the user's (the root fallback keeps them)."""
    fakes = install_fakes()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        await _label(pilot, "number_sign", "a")
        await _label(pilot, "plus", "b")
        await _label(pilot, "B", "c")
        await pilot.press("minus")
        await settle(pilot)
        actors = [(name, call["actor"]) for name, call in fakes.labels.calls]
        assert actors == [
            ("start", "user"),
            ("start", "user"),
            ("point", "user"),
            ("stop", "user"),
        ]
        assert {e.actor for e in fakes.labels.history()} == {"user"}


async def test_hash_with_an_open_label_pre_splits_at_end_and_start(
    install_fakes,
) -> None:
    """R2-M10: activity typed during the prompt lands in the new label."""
    from sandroid.tui.controllers.monitor_controller import build_monitor_item

    install_fakes()
    root = "/data/data/com.example.fit"
    path = f"{root}/shared_prefs/x.xml"
    item = build_monitor_item(f'FSE_CONTENT_MODIFIED\t1\t"fit"\t{path}', (root + "/",))
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        await pilot.press("3")
        await settle(pilot)
        files = ms.lens_widget("files")
        await _label(pilot, "number_sign", "login")  # label 1 open
        assert len(files.marks) == 1
        await pilot.press("number_sign")  # ends 1 + starts 2 at this instant
        await settle(pilot)
        assert type(app.screen).__name__ == "InputModal"
        assert len(files.activity.mark_times) == 3  # start 1, end 1, start 2
        typed_at = datetime.now()
        files.ingest([item], now=typed_at)  # the app writes while the user types
        await pilot.press(*"cookies", "enter")
        await settle(pilot)
        assert [m.kind for m in files.marks] == ["start", "end", "start"]
        row = files.activity.paths[path]
        assert sorted(row.segments) == [3]
        assert files.activity.segment_of(typed_at) == 3
        assert files.segment == 3


@pytest.mark.parametrize("failure", ["raises", "none"])
async def test_a_failed_label_start_settles_the_files_pre_split(
    install_fakes, failure
) -> None:
    fakes = install_fakes()

    def broken(*_a, **_k):
        if failure == "raises":
            raise RuntimeError("sink gone")

    fakes.labels.start = broken
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        await pilot.press("3")
        await settle(pilot)
        files = ms.lens_widget("files")
        await pilot.press("number_sign")
        await settle(pilot)
        assert len(files.activity.mark_times) == 1  # pre-split
        await pilot.press("enter")
        await settle(pilot)
        assert files.activity.mark_times == []
        assert files._pending_mark is None


async def test_rebind_rebuilds_marks_per_sink_and_refreshes_the_watchlist(
    install_fakes, tmp_path
) -> None:
    """R1#3 / R2-M4: marks follow the active sink, even at equal versions."""
    fakes = install_fakes()
    svc = fakes.service
    labels_a = svc.labels
    labels_a.point("in A")
    folder_a = svc.folder
    folder_b = tmp_path / "session" / "dev-b"
    folder_b.mkdir(parents=True)
    labels_b = timeline_fakes.FakeLabels(svc)
    labels_b.point("in B")
    assert labels_a.version == labels_b.version  # the versions collide

    def bind(folder, labels, op="bound"):
        svc.folder, svc.labels = folder, labels
        if op:
            ms._handle_timeline_event(
                SimpleNamespace(
                    data={"op": op, "folder": str(folder), "srcs": ["label"]}
                )
            )

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        files = ms.lens_widget("files")
        bind(folder_a, labels_a)
        await settle(pilot)
        assert [m.label() for m in ms.marks] == ["Note 1 'in A'"]
        assert [m.name for m in files.watchlist.marks] == ["in A"]
        bind(folder_b, labels_b)
        await settle(pilot)
        assert [m.label() for m in ms.marks] == ["Note 1 'in B'"]
        assert [m.name for m in files.watchlist.marks] == ["in B"]
        # back to the already-open A: its own labels again
        bind(folder_a, labels_a)
        await settle(pilot)
        assert [m.label() for m in ms.marks] == ["Note 1 'in A'"]
        assert [m.name for m in files.watchlist.marks] == ["in A"]
        # a label doorbell from another sink at the same version still
        # rebuilds (the cache key is (sink, version), not the version)
        bind(folder_b, labels_b, op="lines")
        await settle(pilot)
        assert [m.label() for m in ms.marks] == ["Note 1 'in B'"]
        # a session-id-only payload works too
        svc.folder, svc.labels = None, labels_a
        ms._handle_timeline_event(
            SimpleNamespace(data={"op": "bound", "session_id": "s-a"})
        )
        await settle(pilot)
        assert [m.label() for m in ms.marks] == ["Note 1 'in A'"]


# --------------------------------------------------------------------------
# types by colour and plain words, type bar, folding, follow, notes
# --------------------------------------------------------------------------


def _typed_lines() -> list[dict]:
    t = NOW - 900
    return [
        make_line(1, t, "input", "tap", summary="tap Login", actor="user"),
        make_line(2, t + 10, "input", "text", summary="typed 5 chars", actor="user"),
        make_line(3, t + 20, "screen", "activity", summary="→ MainActivity"),
        make_line(4, t + 30, "shot", "after_tap", summary="shot after tap"),
        make_line(5, t + 40, "net", "flow", summary="GET 200 x.com/a", pkg="org.x"),
        make_line(6, t + 50, "net", "tls-fail", summary="TLS x.com", pkg="org.x"),
        make_line(7, t + 60, "files", "modify", summary="MODIFY a.db", pkg="org.x"),
        make_line(8, t + 70, "clock", "jump", summary="clock jumped"),
        make_line(9, t + 80, "sandroid", "policy", summary="policy changed"),
        make_line(10, t + 90, "files", "create", summary="CREATE b", pkg="com.y"),
    ]


def _user_tint(pal, role: str = "user") -> str:
    """The user-input row background: ``user`` (typed text: ``typed``)
    blended into ``bg``.
    """
    from textual.color import Color

    from sandroid.tui.widgets.timeline_lens import _TINT_AMOUNT

    colour = getattr(pal, role)
    blend = Color.parse(pal.bg).blend(Color.parse(colour), _TINT_AMOUNT)
    return blend.hex.lower()


def _row_text(lens, vi: int, width: int = 160) -> str:
    return "".join(
        seg.text for seg in lens.strip_for(vi + lens._display_offset(), width)
    )


def _segments(lens, vi: int, width: int = 160) -> list:
    return list(lens.strip_for(vi + lens._display_offset(), width))


async def test_types_are_plain_words_coloured_from_the_theme_tokens(
    install_fakes,
) -> None:
    """The type column says what a line is; colour, brightness and the band
    tint (lens theme tokens) tell the types apart -- no symbols.
    """
    from sandroid.tui.themes import DEFAULT_LENS
    from sandroid.tui.widgets.timeline_lens import type_style, type_word

    install_fakes(_typed_lines())
    app = _LensHarness()
    async with app.run_test(size=(170, 30)) as pilot:
        lens = await _loaded_lens(pilot, app)
        words = {
            r.seq: type_word(r.src, r.kind) for r in lens.rows
        }  # the mapping itself
        assert words == {
            1: "tap",
            2: "typed",
            3: "screen",
            4: "screenshot",
            5: "request",
            6: "TLS failed",
            7: "file",
            8: "clock",
            9: "system",
            10: "file",
        }
        assert lens.cursor_row.seq == 10  # following: rows 1-9 not selected
        for vi, row in enumerate(lens.display_rows):
            assert f" {words[row.seq]} " in _row_text(lens, vi)

        def word_color(vi: int) -> str:
            seg = next(
                s for s in _segments(lens, vi) if s.text.strip() in words.values()
            )
            return seg.style.color.triplet.hex

        def bg(vi: int):
            return _segments(lens, vi)[-1].style.bgcolor

        pal = DEFAULT_LENS
        rows = [r.seq for r in lens.display_rows]
        vi = {seq: rows.index(seq) for seq in rows}
        assert word_color(vi[1]) == pal.user  # the user's own input: accent
        assert bg(vi[1]).triplet.hex == _user_tint(pal)  # ... on its accent's tint
        assert word_color(vi[2]) == pal.typed  # typed text: its own accent
        assert bg(vi[2]).triplet.hex == _user_tint(pal, "typed")
        assert word_color(vi[3]) == pal.screen.lower()  # screen: 2nd accent
        assert word_color(vi[4]) == pal.shot.lower()  # screenshot: its own
        assert word_color(vi[5]) == pal.muted  # request: muted type word
        assert bg(vi[5]) is None  # only input rows are tinted
        # File / clock / system rows: dimmed as a whole row.
        for seq in (7, 8, 9):
            colors = {
                s.style.color.triplet.hex
                for s in _segments(lens, vi[seq])
                if s.style and s.style.color and s.text.strip()
            }
            assert colors <= {pal.dim, pal.label}, (seq, colors)
        # The privacy contract (another branch adds the entries' users).
        summary, tint = type_style("privacy", "sent")
        assert summary.bold
        assert summary.color.triplet.hex == pal.warn
        assert tint.bgcolor is not None
        assert tint.bgcolor.triplet.hex != pal.bg


async def test_a_theme_switch_recolors_the_timeline(install_fakes) -> None:
    from sandroid.tui.themes import DEFAULT_THEME, LIGHT_THEME, get_theme_css_path

    install_fakes(_typed_lines())
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("5")
        lens = ms.lens_widget("timeline")
        await until(pilot, lambda: len(lens.rows) == 10)
        lens.move_cursor(-100)

        def typed_bg() -> str:  # row 1 (row 0 has the cursor): typed text
            return _segments(lens, 1)[-1].style.bgcolor.triplet.hex.upper()

        assert typed_bg() == _user_tint(DEFAULT_THEME.lens, "typed").upper()
        app._apply_theme(LIGHT_THEME, get_theme_css_path("light"))
        await settle(pilot)
        assert typed_bg() == _user_tint(LIGHT_THEME.lens, "typed").upper()
        assert lens.view.styles.background.hex.upper() == LIGHT_THEME.lens.bg
        # The Line API draws no widget background: an untinted row and the
        # empty area below the rows get the view's (not the terminal's).
        for y in (4, lens.view.size.height - 1):
            backgrounds = {
                seg.style.bgcolor.triplet.hex.upper()
                for seg in lens.view.render_line(y)
                if seg.style is not None and seg.style.bgcolor is not None
            }
            assert backgrounds == {LIGHT_THEME.lens.bg}, (y, backgrounds)
            assert all(
                seg.style and seg.style.bgcolor for seg in lens.view.render_line(y)
            )
        app._apply_theme(DEFAULT_THEME, get_theme_css_path("default"))
        await settle(pilot)
        assert typed_bg() == _user_tint(DEFAULT_THEME.lens, "typed").upper()


def test_every_theme_has_readable_type_tokens() -> None:
    """``user`` / ``screen`` exist in every theme, apart from each other."""
    from sandroid.tui.themes import THEMES

    for name, theme in THEMES.items():
        p = theme.lens
        assert p.user.startswith("#"), name
        assert p.screen.startswith("#"), name
        assert p.user.lower() != p.screen.lower(), name
        assert {"lens-user", "lens-screen"} <= p.css_variables().keys()


async def test_type_bar_lists_types_with_counts_hides_on_click_and_picks_an_app(
    install_fakes,
) -> None:
    from sandroid.tui.widgets.timeline_lens import TypeBar

    install_fakes(_typed_lines())
    app = _LensHarness()
    async with app.run_test(size=(170, 30)) as pilot:
        lens = await _loaded_lens(pilot, app)
        bar = lens.query_one("#tl-types", TypeBar)
        await settle(pilot)
        text = str(bar.render())
        assert text.startswith("tap 1 · typed 1 · screen 1 · screenshot 1 · ")
        assert "request 1" in text
        assert "file 2" in text
        assert "clock 1" in text
        assert "app all 4 · org.x 3 · com.y 1" in text
        # A click on "file" hides the file rows; its count stays in the bar.
        k = next(i for i, item in enumerate(bar.items) if item[1] == "file")
        x0 = next(h[1] for h in bar._hits if h[3] == k and h[0] == 0)
        await pilot.click("#tl-types", offset=(x0 + 1, 0))
        await settle(pilot)
        assert lens.hidden_types == {"file"}
        assert not {7, 10} & {r.seq for r in lens.visible_rows}
        assert "hidden file" in lens.chip_text()
        assert lens.type_counts["file"] == 2
        # The keyboard: t focuses the bar, ←/→ move, Space toggles, t leaves.
        await pilot.press("t")
        assert bar.has_focus
        bar.index = 0
        await pilot.press("right", "space")  # "typed"
        assert lens.hidden_types == {"file", "typed"}
        await pilot.press("t")
        assert lens.view.has_focus
        # It combines with the / query (and Esc clears the query first).
        lens.set_filter("src:input,net")
        assert {r.seq for r in lens.visible_rows} == {1, 5, 6}
        # The app filter is the query's pkg: term.
        lens.pick_bar_item(("app", "org.x", 3, None))
        assert lens.query_text == "src:input,net pkg:org.x"
        assert lens.app_pick == "org.x"
        assert {r.seq for r in lens.visible_rows} == {5, 6}
        # Every app the rest of the query lets through stays pickable.
        assert lens.pkg_counts == {"org.x": 2}
        lens.pick_bar_item(("all", "all", 4, None))
        assert lens.query_text == "src:input,net"
        assert lens.handle_escape()  # the query
        assert lens.hidden_types == {"file", "typed"}
        assert lens.handle_escape()  # then the hidden types
        assert lens.hidden_types == set()
        assert len(lens.visible_rows) == 10


def _burst_lines() -> list[dict]:
    t = NOW - 800
    lines = [make_line(1, t, "input", "tap", summary="tap Save", actor="user")]
    for k in range(5):  # one app writing, 0.5 s apart
        kind = "create" if k % 2 else "modify"
        folder = "cache2" if k < 4 else "databases"
        lines.append(
            make_line(
                2 + k,
                t + 1 + k * 0.5,
                "files",
                kind,
                summary=f"{kind.upper()} {folder}/f{k} · main",
                pkg="org.x",
            )
        )
    lines.append(
        make_line(7, t + 3.6, "files", "modify", summary="MODIFY x · main", pkg="com.y")
    )
    lines.append(make_line(8, t + 20, "net", "flow", summary="GET x.com", pkg="org.x"))
    return lines


async def test_file_bursts_fold_into_one_row_and_enter_or_a_click_opens_them(
    install_fakes,
) -> None:
    fakes = install_fakes(_burst_lines())
    app = _LensHarness()
    async with app.run_test(size=(170, 30)) as pilot:
        lens = await _loaded_lens(pilot, app)
        assert [r.seq for r in lens.display_rows] == [1, 2, 7, 8]
        assert len(lens.visible_rows) == 8  # the rows keep every line
        text = _row_text(lens, 1)
        assert (
            "file · org.x · 5 changes (3 modify, 2 create) in cache2, databases" in text
        )
        # Enter (inspect) on the fold opens it instead of the Inspector.
        lens._cursor = 1
        assert lens.inspect_selected() is None
        assert [r.seq for r in lens.display_rows] == [1, 2, 2, 3, 4, 5, 6, 7, 8]
        assert "Enter folds" in _row_text(lens, 1)
        assert lens.cursor_fold is not None
        lens.click_line(1 + lens._display_offset())  # a click closes it
        assert [r.seq for r in lens.display_rows] == [1, 2, 7, 8]
        assert not lens.following  # the click was above the newest row
        # Filters apply before folding.
        lens.set_filter("-kind:create")
        assert "3 changes (3 modify)" in _row_text(lens, 1)
        lens.set_filter("")
        # A live file line of that app within the gap joins the burst...
        lens.action_newest()
        fakes.service.emit(
            "files",
            "modify",
            summary="MODIFY late · main",
            pkg="com.y",
            t=NOW - 800 + 3.9,
        )
        lens._poll()
        lens.release_pending(now=time.time() + 1)
        # (late, behind the request: it joins com.y's single row into a burst)
        assert [r.seq for r in lens.display_rows] == [1, 2, 7, 8]
        assert "file · com.y · 2 changes" in _row_text(lens, 2)
        # ... and the hidden rows (N) still work: a clock sample shows up and
        # splits the burst it lies in.
        lens.insert_rows(
            [row_from_line(make_line(50, NOW - 800 + 1.7, "clock", "sample"))]
        )
        assert 50 not in {r.seq for r in lens.visible_rows}
        lens.app.notify = lambda *a, **k: None
        lens.action_toggle_hidden()
        seqs = [r.seq for r in lens.display_rows]
        assert 50 in seqs
        assert seqs.index(50) == 2
        lens.action_toggle_hidden()
        # J to a line inside a closed burst opens it and selects the line.
        assert lens._select_seq(4, expand=True)
        assert lens.cursor_row.seq == 4
        assert lens.cursor_fold is None


async def test_folds_patched_live_match_a_full_rebuild(install_fakes) -> None:
    """Live appends and late lines patch the folds like a full rebuild."""
    t0 = NOW - 10_000
    base = []
    for i in range(300):
        src, kind = [("files", "modify"), ("files", "create"), ("net", "flow")][
            (i // 4) % 3
        ]
        base.append(
            row_from_line(
                make_line(i + 1, t0 + i * 0.7, src, kind, pkg="org.x", epoch=i // 120)
            )
        )
    for opened in (False, True):
        lens = TimelineLens()
        lens._apply_rows(list(base[:200]), 0)
        if opened:
            first = lens._folds[next(iter(lens._folds))]
            lens._open_bursts.add(first.head)
            lens._build_display()
        lens._follow = False
        lens.insert_rows(base[200:])  # appended
        late = [
            row_from_line(
                make_line(1000 + k, t0 + k * 13.35, "files", "modify", pkg="org.x")
            )
            for k in range(15)
        ] + [row_from_line(make_line(2000, t0 + 40.1, "net", "flow", epoch=0))]
        lens.insert_rows(late)
        patched = list(lens._view)
        counts = dict(lens._type_counts)
        lens._rebuild_view(keep=False)
        assert patched == lens._view, opened
        assert counts == lens._type_counts


def _section_lines() -> list[dict]:
    t = NOW - 700
    return [
        make_line(1, t, "net", "flow", summary="GET before"),
        make_line(
            2,
            t + 1,
            "label",
            "start",
            summary="▶ 1 'Login'",
            actor="user",
            data={"number": 1, "name": "Login", "depth": 0},
        ),
        make_line(3, t + 3, "input", "tap", summary="tap Login", actor="user"),
        make_line(4, t + 10, "files", "modify", summary="MODIFY a · main"),
        make_line(5, t + 20, "net", "flow", summary="POST login"),
        make_line(6, t + 30, "input", "tap", summary="tap OK", actor="user"),
        make_line(
            7,
            t + 135,
            "label",
            "end",
            summary="■ 1 'Login' · 134.0 s",
            data={"number": 1, "duration_s": 134.0},
            ref={"of": 2},
        ),
        make_line(8, t + 140, "net", "flow", summary="GET after"),
    ]


async def test_z_or_a_click_on_the_header_folds_a_section(install_fakes) -> None:
    install_fakes(_section_lines())
    app = _LensHarness()
    async with app.run_test(size=(170, 30)) as pilot:
        lens = await _loaded_lens(pilot, app)
        assert "Section 1 'Login'" in _row_text(lens, 1)
        assert "End section 1 'Login' · 134.0 s" in _row_text(lens, 6)
        lens._select_seq(4)
        await pilot.press("z")
        assert [r.seq for r in lens.display_rows] == [1, 2, 8]
        assert lens.cursor_row.seq == 2
        assert not lens.following
        text = _row_text(lens, 1)
        # Lines without separators, the user's actions first.
        assert "Section 1 'Login' · 2:14 · 4 lines (2 taps, 1 request, 1 file)" in text
        await pilot.press("z")  # unfolds again
        assert [r.seq for r in lens.display_rows] == [1, 2, 3, 4, 5, 6, 7, 8]
        lens.click_line(1 + lens._display_offset())  # the header row folds
        assert [r.seq for r in lens.display_rows] == [1, 2, 8]
        lens.click_line(1 + lens._display_offset())  # the folded row unfolds
        assert len(lens.display_rows) == 8
        messages = []
        lens.app.notify = lambda m, **k: messages.append(m)
        lens._select_seq(8)
        await pilot.press("z")
        assert messages == ["Not inside a section."]


async def test_follow_a_click_above_the_newest_stops_end_resumes(
    install_fakes,
) -> None:
    fakes = install_fakes(_lines(30, NOW - 100))
    app = _LensHarness()
    async with app.run_test(size=(140, 20)) as pilot:
        lens = await _loaded_lens(pilot, app)
        assert lens.following
        assert lens.caption()[0] == "live"
        last = len(lens.display_rows) - 1
        lens.click_line(last + lens._display_offset())  # the newest row: stays
        assert lens.following
        lens.click_line(last - 3 + lens._display_offset())
        assert not lens.following
        for k in range(2):
            fakes.service.emit("net", "flow", summary=f"GET new {k}")
        lens._poll()
        lens.release_pending(now=time.time() + 1)
        assert lens.cursor_row.seq == 27  # recording went on, the view stayed
        assert lens.caption()[0] == "scrolled back · 2 new below · End = live"
        await pilot.press("end")
        assert lens.following
        assert lens.cursor_row.seq == 32


async def test_B_note_needs_its_text_and_flashes_in_the_header(install_fakes) -> None:
    fakes = install_fakes()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        header = ms.query_one("#shell-header")
        await _label(pilot, "number_sign", "Login")
        await pilot.press("B")
        await settle(pilot)
        prompt = app.screen
        assert type(prompt).__name__ == "InputModal"
        assert prompt.title_text.startswith("Note 2 · at ")
        assert prompt.title_text.endswith(" — text")
        await pilot.press("enter")  # no text: the prompt stays, with a hint
        await settle(pilot)
        assert app.screen is prompt
        assert "needs its text" in str(prompt.query_one("#input-hint").render())
        await pilot.press(*"cookie banner", "enter")
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert [e.name for e in fakes.labels.history() if e.kind == "point"] == [
            "cookie banner"
        ]
        assert header.label_note == "Note 2 'cookie banner'"
        now = time.time()
        header.refresh_timeline_state(now + 1)
        assert header.label_note == "Note 2 'cookie banner'"
        header.refresh_timeline_state(now + 6)  # about 5 s later: the section
        assert header.label_note.startswith("Section 1 'Login' ")


@pytest.mark.perf
async def test_100k_lines_with_bursts_and_types_paint_in_under_a_second(
    install_fakes,
) -> None:
    """Folding and the type counts are built with the view, not per frame."""
    lines = []
    t = NOW - 200_000
    for i in range(100_000):
        k = i % 12
        if k < 8:  # a file burst of 8 lines
            line = make_line(i + 1, t, "files", "modify", pkg="org.x")
            t += 0.2
        elif k == 8:
            line = make_line(i + 1, t, "input", "tap", summary="tap", actor="user")
            t += 1.0
        else:
            line = make_line(i + 1, t, "net", "flow", summary="GET x", pkg="org.x")
            t += 2.5
        lines.append(line)
    install_fakes(lines)
    app = _LensHarness()
    async with app.run_test(size=SIZE) as pilot:
        lens = app.query_one(TimelineLens)
        started = time.monotonic()
        lens.on_lens_activated()
        await until(pilot, lambda: lens._loaded, timeout=10)
        await pilot.pause()
        elapsed = time.monotonic() - started
        assert len(lens.rows) == 20_000
        assert elapsed < 1.0, elapsed
        assert lens.following
        assert lens.cursor_fold is not None  # the newest burst, folded
        assert lens.cursor_fold.last == 100_000
        words = {"files": "file", "input": "tap", "net": "request"}
        expected: dict[str, int] = {}
        for line in lines[-20_000:]:
            word = words[line["src"]]
            expected[word] = expected.get(word, 0) + 1
        assert lens.type_counts == expected
        assert len(lens.display_rows) < 9_000
        started = time.monotonic()
        for _ in range(20):  # repaints hit the strip cache
            lens.view.refresh()
            await pilot.pause()
        assert time.monotonic() - started < 1.0


def test_random_live_and_late_lines_keep_folds_and_counts_exact(monkeypatch) -> None:
    """Seeded mixes of appends, late lines, the cap, filters, opened bursts
    and folded sections: the patched view and type / app counts always
    equal a full rebuild.
    """
    import random

    import sandroid.tui.widgets.timeline_lens as tl

    kinds = [
        ("files", "modify"),
        ("files", "create"),
        ("net", "flow"),
        ("input", "tap"),
        ("clock", "sample"),
        ("files", "pull"),
    ]

    def line(rnd, seq, t, epoch):
        src, kind = rnd.choice(kinds)
        level = "warn" if rnd.random() < 0.03 else "info"
        pkg = rnd.choice(["org.x", "org.x", "com.y", None])
        return row_from_line(
            make_line(seq, t, src, kind, pkg=pkg, epoch=epoch, level=level), seq
        )

    for trial in range(120):
        rnd = random.Random(trial)  # noqa: S311 -- a seeded test mix
        t, seq, epoch, number, open_labels, rows = NOW - 50_000, 0, 0, 0, [], []
        for _ in range(rnd.randint(20, 90)):
            seq += 1
            t += rnd.choice([0.1, 0.5, 1.5, 2.5, 4])
            epoch += rnd.random() < 0.02
            if rnd.random() < 0.05:
                number += 1
                open_labels.append(number)
                data = {"number": number, "name": f"s{number}", "depth": 0}
                rows.append(
                    row_from_line(make_line(seq, t, "label", "start", data=data))
                )
            elif open_labels and rnd.random() < 0.04:
                data = {"number": open_labels.pop()}
                rows.append(row_from_line(make_line(seq, t, "label", "end", data=data)))
            else:
                rows.append(line(rnd, seq, t, epoch))
        lens = TimelineLens()
        split = rnd.randint(1, len(rows))
        lens._apply_rows(rows[:split], 0)
        if rnd.random() < 0.5:
            lens._query = parse_query(
                rnd.choice(["-kind:create", "pkg:org.x", "src:files,net", "-src:clock"])
            )
        if rnd.random() < 0.3:
            lens._hidden_types.add(rnd.choice(["file", "request", "tap"]))
        lens._show_hidden = rnd.random() < 0.3
        lens._rebuild_view(keep=False)
        lens._open_bursts = {
            f.head
            for f in lens._folds.values()
            if f.kind == "burst" and rnd.random() < 0.5
        }
        lens._folded_sections = {n for n in range(1, number + 1) if rnd.random() < 0.4}
        lens._build_display()
        lens._follow = rnd.random() < 0.5
        monkeypatch.setattr(tl, "ROW_CAP", rnd.choice([10**9, max(5, len(rows) // 2)]))
        rest = rows[split:]
        while rest:
            k = rnd.randint(1, 5)
            lens.insert_rows(rest[:k])
            rest = rest[k:]
        for _ in range(rnd.randint(0, 8)):
            seq += 1
            anchor = rnd.choice(lens.rows)
            late_t = anchor.t + rnd.choice([-0.3, 0.05, 0.2, 1.0])
            if open_labels and rnd.random() < 0.2:
                # A late section end (# / + / - write at the key press).
                data = {"number": open_labels.pop()}
                late = row_from_line(make_line(seq, late_t, "label", "end", data=data))
            elif rnd.random() < 0.15:
                number += 1
                data = {"number": number, "name": f"s{number}", "depth": 0}
                late = row_from_line(
                    make_line(seq, late_t, "label", "start", data=data)
                )
                if rnd.random() < 0.5:
                    lens._folded_sections.add(number)
            else:
                late = line(rnd, seq, late_t, anchor.epoch + rnd.choice([0, -1]))
            lens.insert_rows([late])
        patched = (list(lens._view), dict(lens.type_counts), dict(lens.pkg_counts))
        lens._rebuild_view(keep=False)
        rebuilt = (lens._view, lens.type_counts, lens.pkg_counts)
        assert patched == rebuilt, trial


# --------------------------------------------------------------------------
# review fixes
# --------------------------------------------------------------------------


def _section_rows(gap: float = 3.0) -> list:
    t0 = NOW - 1000
    data = {"number": 1, "name": "a", "depth": 0}
    rows = [row_from_line(make_line(1, t0, "label", "start", data=data))]
    for k in range(10):
        rows.append(row_from_line(make_line(2 + k, t0 + 1 + k * gap, "net", "flow")))
    return rows


def test_a_late_section_end_cuts_a_folded_open_section() -> None:
    """A late end row (written at the key press) lands inside the folded,
    still open section: the fold ends there, the rest shows again.
    """
    rows = _section_rows()
    lens = TimelineLens()
    lens._apply_rows(rows, 0)
    lens._folded_sections.add(1)
    lens._build_display()
    assert len(lens._view) == 1
    lens._follow = False
    end_t = rows[0].t + 1 + 5 * 3 + 0.5
    end = row_from_line(make_line(500, end_t, "label", "end", data={"number": 1}))
    lens.insert_rows([end])
    patched = list(lens._view)
    lens._rebuild_view(keep=False)
    assert patched == lens._view
    assert len(lens._view) == 1 + 4  # the fold, then the 4 rows after its end


def test_hash_typed_late_starts_a_new_section_outside_the_fold() -> None:
    """``#`` with a name typed for a few seconds: its end + start rows arrive
    late, after newer lines; the new section is not swallowed by the fold.
    """
    rows = _section_rows(gap=1.0)
    lens = TimelineLens()
    lens._apply_rows(rows, 0)
    lens._folded_sections.add(1)
    lens._build_display()
    press = rows[0].t + 6.5
    start2 = {"number": 2, "name": "Login", "depth": 0}
    lens.insert_rows(
        [
            row_from_line(make_line(50, press, "label", "end", data={"number": 1})),
            row_from_line(make_line(51, press, "label", "start", data=start2)),
        ]
    )
    lens.insert_rows([row_from_line(make_line(52, rows[0].t + 20, "net", "flow"))])
    patched = list(lens._view)
    lens._rebuild_view(keep=False)
    assert patched == lens._view
    assert 51 in {r.seq for r in lens.display_rows}  # Section 2 is shown


def test_new_below_counts_a_batch_with_a_late_line() -> None:
    t0 = NOW - 1000
    rows = [row_from_line(make_line(i + 1, t0 + i * 3)) for i in range(20)]
    lens = TimelineLens()
    lens._apply_rows(rows, 0)
    lens._follow = False
    last_t = rows[-1].t
    late = row_from_line(make_line(100, last_t - 1.0, "net", "flow"))
    newer = [
        row_from_line(make_line(101 + k, last_t + 10 + k * 3, "net", "flow"))
        for k in range(4)
    ]
    lens.insert_rows([late, *newer])
    assert lens._new_below == 4  # the 4 below the newest; the late one is above


async def test_J_stops_following_so_the_next_line_does_not_move_away(
    install_fakes,
) -> None:
    lines = _lines(30, NOW - 200)
    lines.append(make_line(31, NOW - 5, "net", "flow", ref={"of": 3}))
    fakes = install_fakes(lines)
    app = _LensHarness()
    async with app.run_test(size=(140, 20)) as pilot:
        lens = await _loaded_lens(pilot, app)
        assert lens.following
        assert lens.cursor_row.seq == 31
        assert lens.jump(lens.cursor_row) is True
        assert lens.cursor_row.seq == 3
        assert not lens.following
        fakes.service.emit("net", "flow", summary="GET later")
        lens._poll()
        lens.release_pending(now=time.time() + 1)
        assert lens.cursor_row.seq == 3


def test_app_filter_keeps_an_unbalanced_query_as_typed() -> None:
    lens = TimelineLens()
    lens._apply_rows([row_from_line(make_line(1, NOW - 10, pkg="org.x"))], 0)
    lens.set_filter('src:files "half quote -pkg:old')
    lens.set_app("org.x")
    assert lens.query_text == 'src:files "half quote pkg:org.x'
    lens.set_app(None)
    assert lens.query_text == 'src:files "half quote'


async def test_app_filter_updates_an_open_filter_input(install_fakes) -> None:
    install_fakes(_typed_lines())
    app = _LensHarness()
    async with app.run_test(size=(170, 30)) as pilot:
        lens = await _loaded_lens(pilot, app)
        await pilot.press("slash", *"src:net")
        await settle(pilot)
        lens.pick_bar_item(("app", "org.x", 2, None))
        await settle(pilot)
        field = lens.query_one("#tl-filter")
        assert field.value == "src:net pkg:org.x"
        assert lens.query_text == "src:net pkg:org.x"


def test_rows_show_no_leading_symbols_and_failed_runs_say_so() -> None:
    t = NOW - 300
    lines = [
        make_line(1, t, "screen", "activity", summary="→ org.x/.MainActivity"),
        make_line(2, t + 5, "input", "confirm", summary="✓ click #5"),
        make_line(3, t + 10, "run", "record-start", summary="● REC · login"),
        make_line(4, t + 20, "run", "play-start", summary="▷ Play · login"),
        make_line(5, t + 30, "run", "play-end", summary="■ Play done · 3 changed"),
        make_line(
            6,
            t + 40,
            "run",
            "play-end",
            summary="■ Play ended · adb gone",
            data={"error": "adb gone", "failed": True},
        ),
    ]
    lens = TimelineLens()
    lens._apply_rows([row_from_line(line) for line in lines], 0)
    text = {r.seq: _row_text(lens, vi) for vi, r in enumerate(lens.display_rows)}
    assert " org.x/.MainActivity" in text[1]
    assert "→" not in text[1]
    assert "click #5" in text[2]
    assert "✓" not in text[2]
    assert "recording started · login" in text[3]
    assert "replay started · login" in text[4]
    assert "replay finished · 3 changed" in text[5]
    assert "replay failed · adb gone" in text[6]
    from sandroid.tui.themes import DEFAULT_LENS

    body = [s for s in _segments(lens, 5) if "failed" in s.text][0]
    assert body.style.color.triplet.hex == DEFAULT_LENS.bad


def test_masked_and_uncertain_lines_use_words_and_colour_not_symbols(
    monkeypatch,
) -> None:
    import sandroid.tui.widgets.timeline_lens as tl
    from sandroid.tui.themes import DEFAULT_LENS

    monkeypatch.setattr(tl, "should_mask_ui", lambda: True)
    lines = [
        make_line(1, NOW - 50, "input", "text", summary="typed ***", sensitive=True),
        make_line(2, NOW - 40, "screen", "activity", summary="x", t_err_ms=900.0),
    ]
    lens = TimelineLens()
    lens._apply_rows([row_from_line(line) for line in lines], 0)
    masked, uncertain = _row_text(lens, 0), _row_text(lens, 1)
    assert " masked " in masked
    assert "▒" not in masked
    assert "~" not in uncertain[:6]
    time_seg = _segments(lens, 1)[2]
    assert time_seg.style.color.triplet.hex == DEFAULT_LENS.warn


def test_a_masked_row_never_shows_the_typed_text(monkeypatch) -> None:
    """A typed-text summary quotes the text (passwords too): masked, the row,
    the search and the Inspector show only the count.
    """
    import sandroid.tui.widgets.timeline_lens as tl

    line = make_line(
        1, NOW - 50, "input", "text", sensitive=True,
        summary="typed \"hunter22\" into password field 'pw'",
        data={"text": "hunter22",
              "masked_summary": "typed 8 chars into password field 'pw'"},
    )  # fmt: skip
    row = row_from_line(line)
    assert row.masked_summary == "typed 8 chars into password field 'pw'"
    assert row.data is None  # a sensitive line keeps no data in the row
    lens = TimelineLens()
    lens._apply_rows([row], 0)
    monkeypatch.setattr(tl, "should_mask_ui", lambda: True)
    assert "hunter22" not in _row_text(lens, 0)
    assert "typed 8 chars" in _row_text(lens, 0)
    monkeypatch.setattr(tl, "should_mask_ui", lambda: False)
    plain = TimelineLens()
    plain._apply_rows([row], 0)
    assert "hunter22" in _row_text(plain, 0)


def test_palettes_built_elsewhere_get_user_and_screen_defaults() -> None:
    from dataclasses import asdict

    from sandroid.tui.themes import DEFAULT_LENS, LensPalette

    fields = asdict(DEFAULT_LENS)
    for name in ("user", "screen", "typed", "shot"):
        fields.pop(name)
    pal = LensPalette(**fields)
    assert pal.user == pal.accent
    assert pal.screen == pal.title
    assert pal.typed == pal.user
    assert pal.shot == pal.screen
    assert pal.css_variables()["lens-user"] == pal.accent


def test_type_tokens_meet_their_contrast_floors_in_every_theme() -> None:
    """``user`` on its row tint and ``screen`` on bg / panel / cursor: >= 4.5;
    under the focused cursor >= 3; the row text on the tint >= 4.5.
    """
    from textual.color import Color

    from sandroid.tui.themes import THEMES
    from sandroid.tui.widgets.timeline_lens import _TINT_AMOUNT

    def lum(hexv: str) -> float:
        c = Color.parse(hexv)
        rgb = [v / 255 for v in (c.r, c.g, c.b)]
        lin = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in rgb]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]

    def ratio(a: str, b: str) -> float:
        hi, lo = sorted((lum(a), lum(b)), reverse=True)
        return (hi + 0.05) / (lo + 0.05)

    for name, theme in THEMES.items():
        p = theme.lens
        for token in ("user", "typed"):
            colour = getattr(p, token)
            tint = Color.parse(p.bg).blend(Color.parse(colour), _TINT_AMOUNT).hex
            assert ratio(colour, tint) >= 4.5, (name, token)
            assert ratio(p.text, tint) >= 4.5, (name, token)
            assert ratio(colour, p.cursor_focus) >= 3, (name, token)
        for token in ("screen", "shot"):
            colour = getattr(p, token)
            for surface in (p.bg, p.panel, p.cursor):
                assert ratio(colour, surface) >= 4.5, (name, token, surface)
            assert ratio(colour, p.cursor_focus) >= 3, (name, token)


def _delta_e(a: str, b: str) -> float:
    """CIE76 colour difference of two hex colours (Lab, D65)."""
    import math

    def lab(hexv: str) -> tuple[float, float, float]:
        h = hexv.lstrip("#")
        rgb = [int(h[i : i + 2], 16) / 255 for i in (0, 2, 4)]
        r, g, b = (
            v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in rgb
        )
        x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047
        y = 0.2126 * r + 0.7152 * g + 0.0722 * b
        z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883

        def f(t: float) -> float:
            return t ** (1 / 3) if t > 0.008856 else 7.787 * t + 16 / 116

        return 116 * f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z))

    return math.dist(lab(a), lab(b))


def test_tap_typed_screen_and_screenshot_have_their_own_colours() -> None:
    """The four type words are told apart in every theme (delta E >= 20),
    and the lens colours them from their own tokens.
    """
    from itertools import combinations

    from sandroid.tui.themes import THEMES
    from sandroid.tui.widgets.timeline_lens import type_style, type_word_style

    for name, theme in THEMES.items():
        p = theme.lens
        four = {t: getattr(p, t) for t in ("user", "typed", "screen", "shot")}
        for a, b in combinations(four, 2):
            assert _delta_e(four[a], four[b]) >= 20, (name, a, b)
    words = {
        kind: type_word_style(src, kind).color.triplet.hex
        for src, kind in (("input", "tap"), ("input", "text"), ("screen", "x"))
    }
    words["shot"] = type_word_style("shot", "x").color.triplet.hex
    assert len(set(words.values())) == 4, words
    assert type_style("input", "tap")[1] != type_style("input", "text")[1]


async def test_an_open_inspector_follows_the_newest_line_while_live(
    install_fakes,
) -> None:
    fakes = install_fakes(_lines(20, NOW - 200))
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("5")
        lens = ms.lens_widget("timeline")
        await until(pilot, lambda: len(lens.rows) == 20)
        await pilot.press("enter")
        await until(pilot, lambda: ms.inspector_is_open)
        assert ms.inspector_content.key[2] == 20
        assert lens.following
        fakes.service.emit("net", "flow", summary="GET newest")
        lens._poll()
        lens.release_pending(now=time.time() + 1)
        await until(pilot, lambda: ms.inspector_content.key[2] == 21)


# --------------------------------------------------------------------------
# privacy lines (identity profile values)
# --------------------------------------------------------------------------


def _privacy_lines(t: float) -> list[dict]:
    return [
        make_line(
            1,
            t,
            "files",
            "pull",
            summary="v003 prefs.xml",
            data={"path": "/data/data/x/shared_prefs/p.xml", "version": "v003"},
            ref={"path": "files/x/p.xml/v003/diff.json", "lens": "files"},
        ),
        make_line(
            2,
            t + 1,
            "net",
            "flow",
            summary="POST 200",
            data={"host": "graph.facebook.com", "method": "POST", "flow_seq": 9},
            ref={"id": "abc", "lens": "network"},
        ),
        make_line(
            3,
            t + 2,
            "privacy",
            "sent",
            summary="Advertising ID sent to graph.facebook.com, request body, as is",
            actor="app",
            ref={"of": 2, "id": "abc", "path": "privacy/hits.jsonl", "lens": "network"},
        ),
        make_line(
            4,
            t + 3,
            "privacy",
            "stored",
            summary="Email stored in shared_prefs/p.xml, as is",
            actor="app",
            ref={"of": 1, "path": "privacy/hits.jsonl", "lens": "files"},
        ),
        make_line(
            5,
            t + 4,
            "privacy",
            "sent",
            summary="GPS sent to example.com, URL, as is",
            actor="app",
            ref={
                "of": 999,
                "id": "gone",
                "path": "privacy/hits.jsonl",
                "lens": "network",
            },
        ),
        make_line(
            6,
            t + 5,
            "privacy",
            "stored",
            summary="Email stored in databases/a.db, as is",
            actor="app",
            ref={"of": 998, "path": "privacy/hits.jsonl", "lens": "files"},
        ),
    ]


def test_privacy_line_types_have_their_own_style() -> None:
    from sandroid.tui.themes import lens_palette
    from sandroid.tui.widgets import timeline_lens as tl

    pal = lens_palette()
    assert ("privacy", "sent") in tl._TYPE_STYLE
    text, tint = tl.type_style("privacy", "sent")
    assert text.color.name == pal.warn
    assert text.bold
    assert tint.bgcolor is not None
    assert tint.bgcolor.name != pal.bg
    text, tint = tl.type_style("privacy", "stored")
    assert text.color.name == pal.accent
    assert tint.bgcolor is not None
    assert tl.type_style("no-such-src", "x") == (None, None)


async def test_privacy_rows_are_tinted_and_keep_their_summary(install_fakes) -> None:
    from sandroid.tui.themes import lens_palette

    install_fakes(_privacy_lines(NOW - 100))
    app = _LensHarness()
    async with app.run_test(size=SIZE) as pilot:
        lens = await _loaded_lens(pilot, app)
        lens._select_seq(1)  # the cursor away from the privacy rows
        await pilot.pause()
        y = lens._view_index(3) + lens._display_offset()
        segments = list(lens.strip_for(y, 160))
        text = "".join(s.text for s in segments)
        assert "Advertising ID sent to graph.facebook.com, request body, as is" in text
        warn = lens_palette().warn
        summary = next(s for s in segments if "Advertising ID" in s.text)
        assert summary.style.color.name == warn
        assert summary.style.bgcolor is not None
        assert all(s.style.bgcolor is not None for s in segments if s.style)
        plain = list(lens.strip_for(lens._view_index(2) + lens._display_offset(), 160))
        assert not any(s.style.bgcolor for s in plain if s.style)


async def test_J_on_privacy_lines_reaches_the_flow_or_file(
    install_fakes, monkeypatch
) -> None:
    import privacy_fakes
    from privacy_fakes import file_hit

    from sandroid.tui.widgets.files_panel import FilesPanel
    from sandroid.tui.widgets.network_panel import NetworkPanel

    calls: list = []
    monkeypatch.setattr(
        FilesPanel,
        "reveal",
        lambda self, path, version=None: calls.append(("files", path, version)) or True,
    )
    monkeypatch.setattr(
        NetworkPanel,
        "reveal_flow",
        lambda self, fid, record=None: (
            calls.append(("net", fid, (record or {}).get("host"))) or True
        ),
    )
    privacy_fakes.install(
        monkeypatch, [file_hit("/data/data/x/databases/a.db", version="v002", tl_seq=6)]
    )
    install_fakes(_privacy_lines(NOW - 100))
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        ms = app.screen
        await pilot.press("5")
        lens = ms.lens_widget("timeline")
        await until(pilot, lambda: len(lens.rows) == 6)
        for seq, lens_id in (
            (3, "network"),
            (4, "files"),
            (5, "network"),
            (6, "files"),
        ):
            await pilot.press("5")
            await settle(pilot)
            assert lens.select_seq(seq)
            await pilot.press("J")
            await settle(pilot)
            assert ms.active_lens == lens_id
        assert calls == [
            # cited net line: the full flow record
            ("net", "abc", "graph.facebook.com"),
            # cited pull line: its file and version
            ("files", "/data/data/x/shared_prefs/p.xml", "v003"),
            # cited line not loaded: the flow by ref.id
            ("net", "gone", None),
            # ... the file by the scan record of the line
            ("files", "/data/data/x/databases/a.db", "v002"),
        ]


def test_the_inspector_says_a_legacy_label_line_in_words() -> None:
    """A timeline written before the plain-word summaries (``▶ 1 'x'``)
    reads ``Section 1 'x'`` in the Inspector, as its row does.
    """
    row = row_from_line(
        make_line(
            1, NOW - 10, "label", "start", summary="▶ 1 'cookies'",
            data={"number": 1, "name": "cookies", "depth": 0},
        )
    )  # fmt: skip
    lens = TimelineLens()
    lens._apply_rows([row], 0)
    assert lens._words(row, row.summary) == "Section 1 'cookies'"
    other = row_from_line(make_line(2, NOW - 5, "device", "boot", summary="⟲ booted"))
    assert lens._words(other, other.summary) == "booted"
