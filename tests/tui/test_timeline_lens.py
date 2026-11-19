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


async def _settle(pilot, n: int = 4) -> None:
    for _ in range(n):
        await pilot.pause(0.05)


async def _wait(pilot, predicate, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await pilot.pause(0.02)
    assert predicate(), "condition not met in time"


async def _boot(app, pilot) -> None:
    await _settle(pilot, 8)
    if type(app.screen).__name__ != "MainScreen":
        await pilot.press("enter")  # first-run welcome modal
        await _settle(pilot, 4)
    assert type(app.screen).__name__ == "MainScreen"


def _app():
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


def _messages(app) -> list[str]:
    return [n.message for n in app._notifications]


def _lines(n: int, start: float, step: float = 0.5) -> list[dict]:
    return [make_line(i + 1, start + i * step) for i in range(n)]


class _LensHarness(App):
    def compose(self) -> ComposeResult:
        yield TimelineLens(id="timeline-panel")


async def _loaded_lens(pilot, app) -> TimelineLens:
    lens = app.query_one(TimelineLens)
    lens.on_lens_activated()
    await _wait(pilot, lambda: lens._loaded)
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
    assert LENSES[-1].id == "timeline"
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        await pilot.press("5")
        await _settle(pilot)
        assert ms.active_lens == "timeline"
        lens = ms.lens_widget("timeline")
        assert isinstance(lens, TimelineLens)
        assert is_shown(lens)
        assert app.focused is not None
        assert lens in app.focused.ancestors_with_self
        await _wait(pilot, lambda: len(lens.rows) == 30)
        assert ms.query_one("#lens-host").border_title.startswith("Timeline · ")
        await pilot.press("4", "shift+right")
        await _settle(pilot)
        assert ms.active_lens == "timeline"
        await pilot.press("shift+right")
        await _settle(pilot)
        assert ms.active_lens == "app"
        await pilot.press("5", "question_mark")
        await _settle(pilot)
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
        await _boot(app, pilot)
        await pilot.press("5")
        await _settle(pilot)
        keys = list(app.screen.query_one(SandroidFooter).query("FooterKey"))
        assert 0 < len(keys) <= SandroidFooter.MAX_KEYS
        labels = [k.description for k in keys]
        assert labels[:2] == ["Record", "Play/Replay"]
        assert "Follow" in labels


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
    from sandroid.tui.widgets.timeline_lens import TimelineView, _TLInput

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
    assert {"space", "end", "home", "slash", "N", "J", "V"} <= lens_keys
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


async def test_tail_load_of_100k_lines_paints_in_under_a_second(
    install_fakes,
) -> None:
    install_fakes(_lines(100_000, NOW - 100_000, step=0.9))
    app = _LensHarness()
    async with app.run_test(size=SIZE) as pilot:
        lens = app.query_one(TimelineLens)
        started = time.monotonic()
        lens.on_lens_activated()
        await _wait(pilot, lambda: lens._loaded, timeout=10)
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
        assert "↑ 1 late lines" in lens.caption()[1]


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
        assert "paused · 1 new ↓" in lens.caption()[0]
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
        await _wait(pilot, lambda: len(lens.rows) == 22)


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

        assert "⟲ world 1" in text(4)
        assert "⏱ epoch 2" in text(6)
        assert "▶ 1 'cookies'" in text(7)
        assert "▷ Play" in text(8)
        assert "reconnected +1.0s" in text(10)
        assert text(12)[3] == "!"  # warn flag in the gutter
        assert "│" in text(9)[:4]  # inside label 1
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
        await _settle(pilot)
        assert lens.chip_text().startswith("REVIEW run r1")
        assert {r.seq for r in lens.visible_rows} == {8, 9}
        lens.set_review_window((NOW - 600 + 2.5, NOW - 600 + 6.5))
        assert {r.seq for r in lens.visible_rows} == {4, 6, 7, 8, 9}
        lens.post_message(ScopeChanged(None))
        await _settle(pilot)
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
        await _boot(app, pilot)
        ms = app.screen
        await pilot.press("5")
        lens = ms.lens_widget("timeline")
        await _wait(pilot, lambda: len(lens.rows) == 4)
        # Masking off: the JSON tab shows the text.
        await pilot.press("enter")
        await _wait(pilot, lambda: 4 in lens._detail)
        assert ms.inspector_is_open
        content = ms.inspector_content
        assert content.title == "#4 input/text"
        assert "hunter22" in _plain(content, "JSON")
        # V is inert while masking is off.
        await pilot.press("V")
        await _settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert any("Masking is off" in m for m in _messages(app))
        # Masking on: masked, V asks, Esc keeps it masked.
        fakes.module.MASK = True
        ms.update_inspector(lens._content(lens.cursor_row))
        assert "hunter22" not in _plain(ms.inspector_content, "JSON")
        assert "_masked" in _plain(ms.inspector_content, "JSON")
        await pilot.press("V")
        await _settle(pilot)
        assert type(app.screen).__name__ == "ConfirmModal"
        await pilot.press("escape")
        await _settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert fakes.service.reveals == []
        await pilot.press("V")
        await _settle(pilot)
        await pilot.press("tab")  # any focus; y answers
        app.screen.action_yes()
        await _settle(pilot)
        assert fakes.service.reveals == [4]
        assert lens.revealed == 4
        await _wait(pilot, lambda: "hunter22" in _plain(ms.inspector_content, "JSON"))
        # Moving the selection masks it again.
        lens.view.focus()
        await pilot.press("up")
        await _settle(pilot)
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
        await _boot(app, pilot)
        ms = app.screen
        await pilot.press("5")
        lens = ms.lens_widget("timeline")
        await _wait(pilot, lambda: len(lens.rows) == 5)
        for seq, lens_id in ((1, "files"), (2, "network"), (3, "runs")):
            await pilot.press("5")
            await _settle(pilot)
            assert lens._select_seq(seq)
            await pilot.press("J")
            await _settle(pilot)
            assert ms.active_lens == lens_id
        assert calls == [
            ("files", "/data/data/x/app.db", "v003"),
            ("net", "abc", "api.x.com"),
            ("runs", "r7"),
        ]
        await pilot.press("5")
        await _settle(pilot)
        lens._select_seq(4)
        await pilot.press("J")  # ref.of -> that row here
        await _settle(pilot)
        assert ms.active_lens == "timeline"
        assert lens.cursor_row.seq == 2
        lens._select_seq(5)
        await pilot.press("J")
        await _settle(pilot)
        assert any("Nothing to jump to" in m for m in _messages(app))


async def test_jump_targets_reveal_flow_and_select_run(install_fakes) -> None:
    install_fakes()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        ms.switch_lens("network")
        net = ms.lens_widget("network")
        assert not net.reveal_flow("nope")
        record = {"id": "abc", "seq": 5, "method": "POST", "host": "api.x.com"}
        record.update(path="/v1", status_code=200, ts_start=NOW, ts_end=NOW)
        assert net.reveal_flow("abc", record=record)
        await _settle(pilot)
        assert ms.inspector_is_open
        assert ms.inspector_content.key == "network:row:f5"
        ms.switch_lens("runs")
        runs = ms.lens_widget("runs")
        assert runs.select_run("missing") is False
        runs._summaries = [{"run_id": "r1", "label": "login", "started_at": None}]
        runs._load_run_detail = lambda run_id: None
        assert runs.select_run("r1") is True
        await _settle(pilot)
        assert runs._selected_run_id == "r1"
        assert ms.inspector_is_open


async def test_files_reveal_selects_the_row_and_opens_versions(install_fakes) -> None:
    from sandroid.tui.controllers.monitor_controller import build_monitor_item

    install_fakes()
    root = "/data/data/com.example.fit"
    path = f"{root}/databases/app.db"
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
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
        await _settle(pilot)
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
    await _settle(pilot, 3)
    if name:
        await pilot.press(*name)
    await pilot.press("enter")
    await _settle(pilot, 3)


async def test_label_keys_nest_close_stop_and_esc_writes_nothing(install_fakes) -> None:
    fakes = install_fakes()
    labels = fakes.labels
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        await pilot.press("number_sign")
        await _settle(pilot, 3)
        assert type(app.screen).__name__ == "InputModal"
        assert "Label 1 · start at" in str(app.screen.title_text)
        await pilot.press(*"cookies", "enter")
        await _settle(pilot, 3)
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
        await _settle(pilot)
        assert [s.number for s in labels.open_spans()] == [4]
        await pilot.press("minus", "minus")
        await _settle(pilot)
        assert labels.open_spans() == []
        assert any("No open label." in m for m in _messages(app))
        # + with nothing open: a top-level label and the notice.
        await _label(pilot, "plus", "top")
        assert labels.open_spans()[0].depth == 0
        assert any("started a top-level label" in m for m in _messages(app))
        # Esc writes nothing.
        before = len(labels.history())
        for key in ("number_sign", "plus", "B"):
            await pilot.press(key)
            await _settle(pilot, 3)
            await pilot.press("escape")
            await _settle(pilot, 3)
        assert len(labels.history()) == before
        assert type(app.screen).__name__ == "MainScreen"
        # The marks are the Files projection of the labels.
        assert [m.label() for m in ms.marks][:3] == [
            "label 1 'cookies'",
            "after label 1",
            "label 4 'next'",
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
        await _boot(app, pilot)
        ms = app.screen
        for spec in LENSES:
            await pilot.press(spec.key)
            await _settle(pilot)
            await _label(pilot, "B", spec.id)
        points = [e for e in fakes.labels.history() if e.kind == "point"]
        assert [p.name for p in points] == [spec.id for spec in LENSES]
        # Label keys typed into the prompt are text, not commands.
        await pilot.press("number_sign")
        await _settle(pilot, 3)
        await pilot.press("a", "plus", "b", "minus", "c", "number_sign", "B", "5")
        await pilot.press("enter")
        await _settle(pilot, 3)
        assert fakes.labels.history()[-1].name == "a+b-c#B5"
        assert ms.active_lens == "timeline"
        assert "mark 1 'app'" in ms.query_one("#log-ticker").last_line or (
            "label 6" in ms.query_one("#log-ticker").last_line
        )


async def test_the_typing_guard_swallows_label_keys(install_fakes) -> None:
    fakes = install_fakes()
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        # "/" in a lens without a filter (Sessions) starts the guard ...
        await pilot.press("4", "slash")
        await _settle(pilot, 2)
        assert ms.typing_guard_active()
        await pilot.press("a", "number_sign", "plus", "minus", "B", "5")
        await _settle(pilot, 3)
        assert type(app.screen).__name__ == "MainScreen"
        assert ms.active_lens == "runs"
        assert fakes.labels.history() == []
        # ... and so does a "that looked like typing" cancel.
        ms.start_typing_guard()
        await pilot.press("x", "number_sign", "B")
        await _settle(pilot, 3)
        assert type(app.screen).__name__ == "MainScreen"
        assert fakes.labels.history() == []
        # ctrl+t is not typing: it passes the guard.
        ms.start_typing_guard()
        await pilot.press("ctrl+t")
        await _wait(pilot, lambda: fakes.tracking.toggles == ["user"])


async def test_label_keys_do_nothing_under_a_modal(install_fakes) -> None:
    fakes = install_fakes()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        await pilot.press("question_mark")
        await _settle(pilot)
        assert app.check_action("label_start", ()) is False
        app.action_label_stop()  # direct call: no MainScreen on top
        await pilot.press("escape")
        await _settle(pilot)
        assert app.check_action("label_start", ()) is True
        assert fakes.labels.history() == []


async def test_files_lens_segments_follow_labels_and_keeps_mark_wording(
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
        await _boot(app, pilot)
        ms = app.screen
        await pilot.press("3")
        await _settle(pilot)
        files = ms.lens_widget("files")
        files.ingest([item(f"{root}/a.db")], now=t0)
        ms.add_label("start", "cookies", t0 + timedelta(seconds=10))
        await _settle(pilot, 2)  # MarksChanged reaches the lens
        files.ingest([item(f"{root}/b.db")], now=t0 + timedelta(seconds=15))
        fakes.labels.stop(t=(t0 + timedelta(seconds=20)).timestamp())
        ms._labels_changed(fakes.labels.history()[-1])
        await _settle(pilot, 2)  # MarksChanged reaches the lens
        files.ingest([item(f"{root}/c.db")], now=t0 + timedelta(seconds=25))
        ms.add_mark("tap", t0 + timedelta(seconds=30))
        await _settle(pilot, 2)  # MarksChanged reaches the lens
        files.ingest([item(f"{root}/d.db")], now=t0 + timedelta(seconds=35))
        await _settle(pilot)
        assert [m.kind for m in files.marks] == ["start", "end", "point"]
        assert files.segment == 3
        t = lambda s: (t0 + timedelta(seconds=s)).strftime("%H:%M:%S")  # noqa: E731
        assert files._segment_title() == f"since mark 2 'tap' · {t(30)}"
        files._segment = 2
        assert files._segment_title() == (
            f"after label 1 (no label) → mark 2 'tap' · {t(20)}–{t(30)}"
        )
        files._segment = 1
        assert files._segment_title() == (
            f"label 1 'cookies' → after label 1 · {t(10)}–{t(20)}"
        )
        files._segment = 0
        assert files._segment_title() == f"before label 1 'cookies' · until {t(10)}"
        # A / < > still navigate the segments on top of the label model.
        files.table.focus()
        files._segment = 3
        await pilot.press("less_than_sign")
        await _settle(pilot, 2)
        assert files.segment == 2
        rows = {r.key for r in files._rows}
        assert f"{root}/c.db" in rows
        assert f"{root}/d.db" not in rows
        await pilot.press("A")
        await _settle(pilot, 2)
        assert files.segment is None
        await pilot.press("A")
        await _settle(pilot, 2)
        assert files.segment == 3
        await pilot.press("greater_than_sign")
        await _settle(pilot, 2)
        assert files.segment == 3


async def test_a_pending_label_pre_splits_files_and_esc_settles(install_fakes) -> None:
    install_fakes()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        await pilot.press("3")
        await _settle(pilot)
        files = ms.lens_widget("files")
        await pilot.press("B")
        await _settle(pilot, 3)
        assert type(app.screen).__name__ == "InputModal"
        assert len(files.activity.mark_times) == 1  # pre-split at the key press
        await pilot.press("escape")
        await _settle(pilot, 3)
        assert len(files.activity.mark_times) == 0
        assert files.marks == []


def test_marks_changed_carries_pending_and_mark_wording() -> None:
    when = datetime(2026, 11, 19, 10, 0, 0)
    msg = MarksChanged([], None, pending=when)
    assert msg.pending == when
    assert Mark(3, when, "tap").label() == "mark 3 'tap'"
    assert Mark(3, when).label() == "mark 3"
    assert Mark(7, when, "x", "start").label() == "label 7 'x'"
    assert Mark(7, when, "x", "end").label() == "after label 7"


async def test_without_the_timeline_labels_stay_in_memory(monkeypatch) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "sandroid.core.timeline", None)
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        await _label(pilot, "B", "x")
        assert [m.label() for m in ms.marks] == ["mark 1 'x'"]
        assert any("Timeline unavailable" in m for m in _messages(app))
        await pilot.press("minus")
        await _settle(pilot)
        assert any("labels need the session timeline" in m for m in _messages(app))
        await pilot.press("5")
        await _settle(pilot)
        lens = ms.lens_widget("timeline")
        await _wait(pilot, lambda: lens._loaded)
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
        await _boot(app, pilot)
        ms = app.screen
        header = ms.query_one("#shell-header")
        await pilot.press("ctrl+t")
        await _wait(pilot, lambda: fakes.tracking.active)
        await _wait(pilot, lambda: header.tracking_on)
        assert fakes.tracking.toggles == ["user"]
        await pilot.press("ctrl+t")
        await _wait(pilot, lambda: not header.tracking_on)


async def test_ctrl_t_without_tracking_says_so(install_fakes) -> None:
    install_fakes(tracking=False)
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await _boot(app, pilot)
        await pilot.press("ctrl+t")
        await _settle(pilot)
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
        await _boot(app, pilot)
        ms = app.screen
        header = ms.query_one("#shell-header")
        now = time.time()
        for step in range(4):
            header.update_device_clock(now + step * 120)
        assert sampled == []  # the timeline writer samples, not the header
        fakes.labels.start("accept cookies", t=now - 12)
        header.refresh_timeline_state(now)
        assert header.label_note == "▶ 1 'accept cookies' 0:12"
        fakes.labels.stop()
        header.refresh_timeline_state(now)
        assert header.label_note is None
        fakes.service.state = "locked"
        fakes.service.locked_by = "PID 4711 on host"
        header.refresh_timeline_state(now)
        assert header.timeline_banner == "⚠ timeline locked (PID 4711 on host)"
        lens = ms.lens_widget("timeline")
        assert lens.badge() == "⚠"
        assert "Timeline locked by PID 4711" in lens._banner()
        ms._handle_timeline_event(SimpleNamespace(data={"op": "locked"}))
        await _settle(pilot)
        assert ms.query_one("#lens-bar").badge("timeline") == "⚠"


async def test_doorbell_rebuilds_marks_for_labels_added_elsewhere(
    install_fakes,
) -> None:
    fakes = install_fakes()
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        assert len(ms.marks) == 0
        fakes.labels.point("from the AI", source="ai")  # not through the UI
        ms._handle_timeline_event(
            SimpleNamespace(data={"op": "lines", "srcs": ["label"], "last_seq": 1})
        )
        await _settle(pilot)
        assert [m.label() for m in ms.marks] == ["mark 1 'from the AI'"]
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
        await _settle(pilot)
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
        await _settle(pilot)
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
        await _boot(app, pilot)
        ms = app.screen
        await _label(pilot, "number_sign", "cookies")
        await _label(pilot, "B", "tap")
        await pilot.press("minus")
        await _settle(pilot)
        assert [m.label() for m in ms.marks] == [
            "label 1 'cookies'",
            "mark 2 'tap'",
            "after label 1",
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
        await _wait(pilot, lambda: any(r.kind == "pull" for r in lens.rows))
