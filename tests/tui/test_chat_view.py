"""The AI chat view layer (``sandroid.tui.widgets.chat_view``).

Formatter goldens, the context-meter thresholds, the mascot frames, the
transcript blocks and their cap, a re-render guard for streaming, and a
sweep over every theme. No device, no AI backend.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pilot_helpers import settle, until
from rich.cells import cell_len
from textual.app import App, ComposeResult
from textual.content import Content
from textual.widgets import Button, Static

from sandroid.tui.widgets.chat_view import (
    ASCII_FRAMES,
    BLOCK_FRAMES,
    MASCOT_STATES,
    AgentCard,
    BudgetNotice,
    ChatHeader,
    ChatMascot,
    ChatTranscript,
    CompactionRule,
    EmptyState,
    FoldMarker,
    MascotRow,
    NoticeLine,
    ReasoningLine,
    ReplyBlock,
    ToolBlock,
    UserBlock,
    configured_mascot_style,
    format_args,
    format_card_title,
    format_chip,
    format_compaction,
    format_elapsed,
    format_empty_state,
    format_header,
    format_meter,
    format_retry,
    format_tokens,
    humanize_tool_name,
    meter_style,
    resolve_mascot_style,
    ruled,
)

# --------------------------------------------------------------------------
# formatters
# --------------------------------------------------------------------------


def test_token_and_elapsed_formats() -> None:
    assert [format_tokens(n) for n in (None, 0, 950, 9_200, 41_000, 262_144)] == [
        "?",
        "0",
        "950",
        "9.2k",
        "41k",
        "262k",
    ]
    assert format_tokens(1_250_000) == "1.2M"
    assert format_tokens(10_000) == "10k"
    assert [format_elapsed(s) for s in (None, 0.4, 4.0, 3.62, 38.2, 62, 3723)] == [
        "",
        "0.4s",
        "4s",
        "3.6s",
        "38s",
        "1:02",
        "1:02:03",
    ]


@pytest.mark.parametrize(
    ("fraction", "style"),
    [
        (0.0, "$lens-dim"),
        (0.16, "$lens-dim"),
        (0.49, "$lens-dim"),
        (0.50, "$lens-warn"),
        (0.849, "$lens-warn"),
        (0.85, "$lens-bad"),
        (1.30, "$lens-bad"),
    ],
)
def test_meter_thresholds(fraction, style) -> None:
    assert meter_style(fraction) == style


def test_meter_text_and_style() -> None:
    meter = format_meter(41_000, 262_144)
    assert meter.plain == "41k/262k 16%"  # no fill glyph: the colour says it
    assert {span.style for span in meter.spans} == {"$lens-dim"}
    assert format_meter(41_000, 262_144, compact=True).plain == "41k 16%"
    hot = format_meter(230_000, 262_144)
    assert hot.plain == "230k/262k 88%"
    assert {span.style for span in hot.spans} == {"$lens-bad"}
    assert format_meter(12_000, None).plain == "12k"


def test_header_wide_and_compact_goldens() -> None:
    fields = {
        "detail": "List Flows",
        "model": "deepseek-v3 @ fhgenie",
        "remote": True,
        "used": 41_000,
        "window": 262_144,
        "compactions": 1,
        "agents": 2,
    }
    wide = format_header("tool", width=100, **fields)
    assert wide.cell_length == 100
    assert wide.plain.startswith(" tool · List Flows · deepseek-v3 @ fhgenie REMOTE ")
    assert wide.plain.endswith("41k/262k 16%  1 compacted  2 agents ")
    narrow = format_header("tool", width=60, **fields)
    assert narrow.cell_length == 60
    assert "deepseek" not in narrow.plain
    assert narrow.plain.startswith(" tool · List Flows REMOTE ")
    assert narrow.plain.endswith("41k 16% 1 compacted 2 agents ")
    # Too long for the row: the left part is cut, the meter stays.
    tight = format_header("tool", detail="x" * 80, width=40, used=1, window=10)
    assert tight.cell_length == 40
    assert "…" in tight.plain
    assert tight.plain.rstrip().endswith("10%")
    idle = format_header(width=30)
    assert idle.plain.startswith(" idle")
    assert "$chat-muted" in {s.style for s in idle.spans}


@pytest.mark.parametrize("width", [140, 110, 90, 70, 60, 50])
def test_header_drops_the_model_first_and_keeps_both_markers(width) -> None:
    """§8: REMOTE and EXPERIMENTAL stay whole at every width (E2E saw
    ``E…``); the model goes first, then the meter's window, then the detail
    is cut.
    """
    model = "deepseek-ai/DeepSeek-V4.1-Flash"
    header = format_header(
        "approval",
        detail="Kill Process",
        model=model,
        remote=True,
        experimental=True,
        used=49_000,
        window=262_144,
        width=width,
    )
    plain = header.plain
    assert header.cell_length == width
    assert " REMOTE EXPERIMENTAL " in plain
    assert "E…" not in plain
    assert plain.rstrip().endswith("19%")
    if width >= 110:
        assert model in plain
        assert "49k/262k" in plain
    if width <= 90:
        assert model not in plain
    if width <= 60:
        # Whole, or cut with "…" (never a half word without one).
        assert "Kill Process" in plain or "…" in plain


def test_tool_name_args_and_chip_goldens() -> None:
    assert humanize_tool_name("list_flows") == "List Flows"
    assert humanize_tool_name("get_tls_keys") == "Get TLS Keys"
    assert humanize_tool_name("mcp:jadx:decompile_class") == "Decompile Class (jadx)"
    args = {"package": "com.example.bank", "since": "launch", "limit": 5, "x": None}
    assert (
        format_args(args).plain == 'package="com.example.bank"  since="launch"  limit=5'
    )
    assert (
        format_args(args, compact=True).plain
        == "package=com.example.bank  since=launch  limit=5"
    )
    cut = format_args(args, compact=True, max_width=30)
    assert cut.cell_length == 30
    assert cut.plain.endswith("…")
    long = format_args({"q": "a" * 100}).plain
    assert cell_len(long) <= 2 + 40 + 1
    assert format_args({"flags": ["a", "b"]}).plain == 'flags=["a", "b"]'

    ok = format_chip(ref="R17", summary="12 rows", elapsed=0.4)
    assert ok.plain == "done · R17 · 12 rows · 0.4s"
    assert "$lens-ok" in {s.style for s in ok.spans}
    err = format_chip(ok=False, code="frida_not_attached", message="no session")
    assert err.plain == "frida_not_attached: no session"
    assert "$lens-bad" in {s.style for s in err.spans}
    assert format_chip().plain == "done"
    # Words, not glyphs: a plain tool failure reads "failed"; denied is warn.
    failed = format_chip(ok=False, code="tool_failed", message="replay diverged")
    assert failed.plain == "failed: replay diverged"
    denied = format_chip(ok=False, code="denied", elapsed=62)
    assert denied.plain == "denied · 1:02"
    assert "$lens-warn" in {s.style for s in denied.spans}
    assert format_chip(ok=False).plain == "failed"
    # App-start refusals read as words in the warn colour.
    for code, word in (
        ("needs_confirmation", "needs your confirmation"),
        ("declined_by_analyst", "declined by you"),
        ("busy", "busy"),
    ):
        chip = format_chip(ok=False, code=code, message="x")
        assert chip.plain == f"{word}: x"
        assert "$lens-warn" in {s.style for s in chip.spans}


def test_card_rule_and_notice_goldens() -> None:
    title = format_card_title("researcher", "r2", "done", elapsed=38, tokens=9_200)
    assert title.plain == "researcher r2 · done · 38s · 9.2k tok"
    assert "$lens-ok" in {s.style for s in title.spans}
    running = format_card_title("explorer", "r1", "running")
    assert running.plain == "explorer r1 · running"
    assert "$lens-accent" in {s.style for s in running.spans}
    assert format_compaction(182_000, 41_000, 14) == (
        "compacted · 182k → 41k · 14 results masked"
    )
    assert format_compaction(182_000, 41_000) == "compacted · 182k → 41k"
    assert format_retry(4, 2, 5, "429 rate limited") == (
        "Retrying in 4s · attempt 2/5 · 429 rate limited"
    )
    rule = ruled("compacted", 30)
    assert rule.cell_length == 30
    assert rule.plain.startswith("─")
    assert rule.plain.endswith("─")
    assert " compacted " in rule.plain


def test_formatters_use_theme_variables_only() -> None:
    """No hard-coded colours: every style names a ``$`` variable (or bold)."""
    contents = [
        format_header("approval", model="m", remote=True, used=1, window=2, agents=1),
        format_chip(ref="R1", summary="s", elapsed=1),
        format_chip(ok=False, code="c", message="m"),
        format_card_title("r", "a1", "failed", elapsed=1, tokens=1),
        format_args({"a": "b"}),
        format_empty_state(80, model="m", endpoint="e", remote=True),
    ]
    for content in contents:
        for span in content.spans:
            for token in str(span.style).split():
                assert token.startswith("$") or token in {"bold", "italic"}, span


# --------------------------------------------------------------------------
# mascot
# --------------------------------------------------------------------------


def test_mascot_frames_are_nine_by_three() -> None:
    for table in (BLOCK_FRAMES, ASCII_FRAMES):
        assert set(table) == set(MASCOT_STATES)
        for state, frames in table.items():
            for frame in frames:
                assert len(frame) == 3, state
                assert {cell_len(row) for row in frame} == {9}, (state, frame)
    for frames in ASCII_FRAMES.values():
        for frame in frames:
            assert all(row.isascii() for row in frame)


def test_mascot_style_resolution() -> None:
    assert resolve_mascot_style("auto", encoding="utf-8", term="xterm-256color") == (
        "blocks"
    )
    assert resolve_mascot_style("auto", encoding="UTF8", term="screen") == "blocks"
    assert resolve_mascot_style("auto", encoding="ascii", term="xterm") == "ascii"
    for term in ("linux", "vt100", "dumb"):
        assert resolve_mascot_style("auto", encoding="utf-8", term=term) == "ascii"
    assert resolve_mascot_style("blocks", encoding="ascii", term="dumb") == "blocks"
    assert resolve_mascot_style("off") == "off"

    def cfg(**ai):
        return SimpleNamespace(ai=SimpleNamespace(**ai))

    assert configured_mascot_style(cfg(mascot_style="ascii")) == "ascii"
    assert configured_mascot_style(cfg(mascot_style="off")) == "off"
    # Without the property: chat_mascot, with show_chat_mascot as the alias.
    assert configured_mascot_style(cfg(chat_mascot="ascii")) == "ascii"
    assert configured_mascot_style(
        cfg(chat_mascot="blocks", show_chat_mascot=False)
    ) == ("off")


def test_ai_config_mascot_style_property_drives_it() -> None:
    from sandroid.config.schema import AIConfig

    ai = AIConfig(chat_mascot="ascii")
    assert configured_mascot_style(SimpleNamespace(ai=ai)) == "ascii"
    ai = AIConfig(chat_mascot="blocks", show_chat_mascot=False)
    assert configured_mascot_style(SimpleNamespace(ai=ai)) == "off"


class _MascotApp(App):
    def compose(self) -> ComposeResult:
        with MascotRow(id="row"):
            yield Static("input", id="fake-input")
            yield ChatMascot(style="blocks", id="mascot")


async def test_mascot_timer_runs_only_in_animated_states() -> None:
    app = _MascotApp()
    async with app.run_test(size=(80, 10)) as pilot:
        await settle(pilot)
        mascot = app.query_one(ChatMascot)
        assert mascot.display
        assert mascot.animated  # idle blinks
        for state, animated in (
            ("thinking", True),
            ("streaming", True),
            ("tool", False),
            ("approval", False),
            ("error", False),
            ("idle", True),
        ):
            mascot.set_state(state)
            await settle(pilot)
            assert mascot.animated is animated, state
            assert mascot.has_class(f"-{state}")
            assert "\n".join(mascot.current_frame()) == str(mascot.render())
        mascot.set_state("error")
        assert str(mascot.render()).splitlines()[2] == "▐█x███x█▌"


async def test_mascot_hides_below_fifty_columns_and_when_off() -> None:
    app = _MascotApp()
    async with app.run_test(size=(45, 10)) as pilot:
        await settle(pilot)
        mascot = app.query_one(ChatMascot)
        assert not mascot.display
        assert not mascot.animated
        await pilot.resize_terminal(70, 10)
        await until(pilot, lambda: mascot.display)
        assert mascot.animated
        mascot.style_name = "off"
        mascot.set_state("thinking")
        await settle(pilot)
        assert not mascot.display
        assert not mascot.animated


async def test_ascii_mascot_renders_ascii_only() -> None:
    class _App(App):
        def compose(self) -> ComposeResult:
            yield ChatMascot("thinking", style="ascii")

    app = _App()
    async with app.run_test(size=(80, 10)) as pilot:
        await settle(pilot)
        mascot = app.query_one(ChatMascot)
        assert mascot.style_name == "ascii"
        assert str(mascot.render()).isascii()


def test_empty_state_shows_the_tray_and_adapts_to_width() -> None:
    wide = format_empty_state(100, model="deepseek-v3", endpoint="fhgenie", remote=True)
    lines = wide.plain.splitlines()
    assert any(line.strip() == "╘═══════╛" for line in lines)
    assert any("Sandroid AI · experimental" in line for line in lines)
    assert any("deepseek-v3 @ fhgenie · REMOTE" in line for line in lines)
    assert "/permissions" in wide.plain
    narrow = format_empty_state(60, mascot_style="ascii")
    assert "`-------'" in narrow.plain
    assert "· / for all" in narrow.plain
    assert "╘" not in format_empty_state(60, mascot_style="off").plain


# --------------------------------------------------------------------------
# blocks + transcript
# --------------------------------------------------------------------------


class _TranscriptApp(App):
    def __init__(self, **kwargs) -> None:
        super().__init__()
        self._kwargs = kwargs
        self.events: list[tuple[str, object]] = []

    def on_agent_card_open(self, message: AgentCard.Open) -> None:
        self.events.append(("open", message.agent_id))

    def on_chat_transcript_earlier_turns_requested(
        self, message: ChatTranscript.EarlierTurnsRequested
    ) -> None:
        self.events.append(("earlier", message.folded_turns))

    def compose(self) -> ComposeResult:
        yield ChatHeader(id="chat-header")
        yield ChatTranscript(id="transcript", **self._kwargs)


async def test_blocks_render_and_update_in_place() -> None:
    app = _TranscriptApp()
    async with app.run_test(size=(100, 40)) as pilot:
        t = app.query_one(ChatTranscript)
        t.add_block(UserBlock("What is com.example.bank sending?"), key="u1")
        thought = t.add_block(ReasoningLine(started=0.0), key="th1")
        tool = t.add_block(
            ToolBlock("list_flows", {"package": "com.example.bank"}, call_id="c1"),
            key="c1",
        )
        await settle(pilot)
        assert t.current_turn == 1
        assert tool.running
        assert tool.size.height == 2  # the call, then "running" (a word)
        assert str(tool.render()).splitlines()[1] == "  running"
        assert tool.call_line().plain.startswith("List Flows")
        tool.set_result(ref="R17", summary="12 rows", elapsed=0.4)
        thought.finish(4)
        await settle(pilot)
        assert not tool.running
        assert tool.size.height == 2
        assert str(tool.render()).splitlines()[1] == "  done · R17 · 12 rows · 0.4s"
        assert str(thought.render()) == "Thought for 4s"
        assert t.block("c1") is tool

        failed = t.add_block(ToolBlock("get_tls_keys", {}), key="c2")
        failed.set_error("frida_not_attached", "no session")
        notice = t.add_block(NoticeLine(format_retry(4, 2, 5)), key="n1")
        notice.set_notice(format_retry(2, 3, 5))
        rule = t.add_block(CompactionRule(182_000, 41_000, 14))
        card = t.add_block(
            AgentCard(
                "r2",
                "researcher",
                summary="adtrk.io is an ad-attribution SDK.",
                claims=[("ANDROID_ID sent in plaintext", ["R17", "R21"])],
            ),
            key="agent:r2",
        )
        reply = t.add_block(ReplyBlock(), key="reply1")
        await reply.append_text("The app talks to **three** hosts.")
        await reply.finish()
        await settle(pilot)
        assert "  frida_not_attached: no session" in str(failed.render())
        assert str(notice.render()).startswith("Retrying in 2s · attempt 3/5")
        assert "compacted · 182k → 41k" in str(rule.render())
        body = str(card.render()).splitlines()
        assert body[0] == "adtrk.io is an ad-attribution SDK."
        assert body[1].startswith("• ANDROID_ID")
        assert body[1].endswith("R17  R21")
        assert cell_len(body[1]) == card.content_size.width
        card.update_card(status="done", elapsed=38, tokens=9_200)
        title = Content.from_markup(card.border_title).plain
        assert title == "researcher r2 · done · 38s · 9.2k tok"
        assert reply.text == "The app talks to **three** hosts."
        assert "three" in reply.source

        card.focus()
        await pilot.press("enter")
        await settle(pilot)
        assert app.events == [("open", "r2")]


async def test_tool_args_lose_quotes_when_narrow() -> None:
    app = _TranscriptApp()
    async with app.run_test(size=(60, 20)) as pilot:
        t = app.query_one(ChatTranscript)
        tool = t.add_block(ToolBlock("list_flows", {"package": "com.example.bank"}))
        await settle(pilot)
        assert "package=com.example.bank" in tool.call_line().plain


async def test_budget_notice_posts_continue_and_collapses() -> None:
    got: list[str] = []

    class _App(_TranscriptApp):
        def on_budget_notice_continue(self, message: BudgetNotice.Continue) -> None:
            got.append(f"continue+{message.notice.grant}")

        def on_budget_notice_stop(self, message: BudgetNotice.Stop) -> None:
            got.append("stop")

    app = _App()
    async with app.run_test(size=(100, 20)) as pilot:
        t = app.query_one(ChatTranscript)
        notice = t.add_block(BudgetNotice(25, 25, grant=10))
        other = t.add_block(BudgetNotice(25, 25))
        await settle(pilot)
        await pilot.click("#budget-continue")
        await settle(pilot)
        assert got == ["continue+10"]
        assert notice.choice == "continue"
        assert not any(b.display for b in notice.query(Button))
        assert "continued (+10)" in str(notice.query_one("#budget-text").render())
        other.query_one("#budget-stop", Button).press()
        await settle(pilot)
        assert got == ["continue+10", "stop"]


async def test_transcript_folds_oldest_turns_past_the_cap() -> None:
    app = _TranscriptApp(max_blocks=20)
    async with app.run_test(size=(100, 30)) as pilot:
        t = app.query_one(ChatTranscript)
        for turn in range(1, 9):  # 8 turns x 4 blocks = 32 blocks
            t.add_block(UserBlock(f"q{turn}"), key=f"u{turn}")
            for i in range(3):
                t.add_block(Static(f"b{turn}.{i}"), key=f"b{turn}.{i}")
        await settle(pilot)
        assert len(t.blocks) <= 20
        assert t.folded_turns == 3
        assert t.block("u1") is None
        assert t.block("u4") is not None
        fold = t.query_one(FoldMarker)
        assert t.children[0] is fold
        assert str(fold.render()) == "3 earlier turns"
        assert {b.turn for b in t.blocks} == set(range(4, 9))
        fold.scroll_visible(animate=False)
        await settle(pilot)
        await pilot.click(FoldMarker)
        await settle(pilot)
        assert app.events == [("earlier", 3)]
        # One huge turn: only its oldest blocks go, the turn count stays.
        t.add_block(UserBlock("big"))
        for i in range(40):
            t.add_block(Static(f"big{i}"))
        await settle(pilot)
        assert len(t.blocks) == 20
        assert t.blocks[-1].turn == t.current_turn


async def test_streaming_reply_does_not_re_render_earlier_blocks() -> None:
    """2000 deltas into the live ReplyBlock leave 200 earlier blocks alone."""
    renders = {"n": 0}

    class _Counted(UserBlock):
        def render(self):
            renders["n"] += 1
            return super().render()

    app = _TranscriptApp()
    async with app.run_test(size=(100, 40)) as pilot:
        t = app.query_one(ChatTranscript)
        for i in range(200):
            t.add_block(_Counted(f"earlier message {i}"))
        await settle(pilot)
        reply = t.add_block(ReplyBlock())
        await settle(pilot)
        before = renders["n"]
        for i in range(2000):
            await reply.append_text(f"word{i} ")
            if i % 100 == 0:
                await pilot.pause()
        await reply.finish()
        await settle(pilot)
        assert reply.text.count("word") == 2000
        # Mounting the reply may re-render the few visible earlier blocks once
        # or twice (the anchor scroll); streaming must not re-render them.
        assert renders["n"] - before <= 10, renders["n"] - before


async def test_header_widget_throttles_and_fits_its_width() -> None:
    app = _TranscriptApp()
    async with app.run_test(size=(60, 10)) as pilot:
        header = app.query_one(ChatHeader)
        header.set_fields(
            state="tool", detail="List Flows", model="m", used=1, window=4
        )
        for i in range(50):
            header.set_fields(used=i)
        await until(pilot, lambda: header._pending is None)
        await settle(pilot)
        text = str(header.render())
        assert cell_len(text) == 60
        assert "49 1225%" in text  # compact form at 60 columns
        assert header.fields["used"] == 49
        assert text.rstrip().endswith("%")


async def test_empty_state_widget_and_all_blocks_mount_in_every_theme() -> None:
    """Every Sandroid theme provides the $chat-* / $lens-* variables used here."""
    from sandroid.tui.themes import THEMES, build_textual_theme, textual_theme_name

    class _App(App):
        def compose(self) -> ComposeResult:
            yield ChatHeader()
            with ChatTranscript():
                yield EmptyState(model="m", endpoint="e", mascot_style="blocks")
                yield UserBlock("hi")
                yield ReasoningLine()
                yield ToolBlock("list_flows", {"a": 1})
                yield AgentCard("r1", "explorer")
                yield CompactionRule(10, 5)
                yield NoticeLine("n")
                yield BudgetNotice(1, 1)
                yield ReplyBlock("**hi**")
            with MascotRow():
                yield Static("x")
                yield ChatMascot(style="blocks")

    app = _App()
    for theme in THEMES.values():
        app.register_theme(build_textual_theme(theme))
    async with app.run_test(size=(100, 60)) as pilot:
        await settle(pilot)
        for name in THEMES:
            app.theme = textual_theme_name(name)
            await settle(pilot)
            variables = app.theme_variables
            for var in ("chat-user-band", "chat-reply", "chat-tool", "chat-wait"):
                assert variables[var].startswith("#"), (name, var)
            band = app.query_one(UserBlock).styles.background.hex.upper()
            assert band == THEMES[name].user_highlight_background.upper()
            mascot = app.query_one(ChatMascot)
            # The softer lens accent (the logo colour was harsh, e.g. #00ff00).
            accent = THEMES[name].lens.accent.upper()
            assert mascot.styles.color.hex.upper() == accent
            assert _contrast(accent, THEMES[name].lens.bg) >= 4.0, name


def _contrast(a: str, b: str) -> float:
    """WCAG contrast ratio of two ``#rrggbb`` colours."""

    def lum(hex_: str) -> float:
        h = hex_.lstrip("#")
        rgb = [int(h[i : i + 2], 16) / 255 for i in (0, 2, 4)]
        lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]

    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


async def test_transcript_starts_at_the_top_then_follows_the_end() -> None:
    app = _TranscriptApp()
    async with app.run_test(size=(80, 20)) as pilot:
        t = app.query_one(ChatTranscript)
        first = t.add_block(UserBlock("first"))
        await settle(pilot)
        assert t.scroll_y == 0
        assert first.region.y <= 3  # top-aligned, not pushed to the bottom
        assert not t.is_anchored
        for i in range(30):
            t.add_block(Static(f"line {i}"))
        await settle(pilot)
        assert t.is_anchored
        assert t.scroll_y == t.max_scroll_y > 0
