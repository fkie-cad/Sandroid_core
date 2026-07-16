"""Headless smoke tests for the Chat tab (ChatPanel + main_screen wiring).

Uses Textual's own headless harness (``App.run_test()``) to mount ChatPanel
without a real terminal. There is no prior use of ``run_test()``/Textual's
test harness anywhere else in this repo's test suite (grepped, none found),
so this is a new pattern here -- but it's the standard, documented way to
drive a Textual app/widget in a test, and the only way to confirm
``ChatPanel.compose()``/``on_mount()`` actually run end-to-end without
raising (as opposed to just importing the module).

Does not touch ``Toolbox``/config/ADB at all: ChatPanel's constructor,
``compose()``, and ``on_mount()`` never read config or talk to a device --
that only happens once a message is actually submitted -- so this mounts
cleanly with zero fixtures.
"""

import time as time_module
from types import SimpleNamespace

import pytest
from rich.markdown import Markdown
from rich.text import Text
from textual.app import App, ComposeResult
from textual.widgets import Input, RichLog, Static

from sandroid.tui.screens.main_screen import MainScreen
from sandroid.tui.widgets.chat_panel import ChatPanel


class _ChatPanelHarness(App):
    """Minimal host app: just enough DOM for ChatPanel to mount standalone."""

    def compose(self) -> ComposeResult:
        yield ChatPanel(id="chat-panel")


@pytest.mark.smoke
async def test_chat_panel_mounts_without_error():
    app = _ChatPanelHarness()
    async with app.run_test() as pilot:
        panel = app.query_one("#chat-panel", ChatPanel)
        assert isinstance(panel, ChatPanel)
        # compose() produced its children with no exception raised.
        assert app.query_one("#chat-header") is not None
        assert app.query_one("#chat-log") is not None
        assert app.query_one("#chat-input") is not None
        # The mascot is a sibling of #chat-input-bar (not nested inside
        # it) -- it's positioned on top of the bar via CSS layering, not
        # laid out as one of the bar's own row children.
        assert app.query_one("#chat-input-bar") is not None
        assert app.query_one("#chat-mascot") is not None
        await pilot.pause()


def test_chat_tab_registered_in_tool_tabs():
    """main_screen.py's additive wiring: the Chat tab maps to chat-panel."""
    assert MainScreen._TOOL_TABS["tab-chat"] == "chat-panel"


def test_chat_panel_seeds_orchestrator_system_prompt():
    """Regression test for a real bug found by review: the top-level chat
    loop never actually sent a system prompt, so the model had no idea it
    was Sandroid's assistant or that tool results are sample data.
    """
    from sandroid.ai.prompts import ORCHESTRATOR_SYSTEM_PROMPT

    panel = ChatPanel(id="chat-panel")
    assert panel._messages == [
        {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT}
    ]


@pytest.mark.smoke
async def test_ctrl_l_resets_conversation_history_too():
    """Ctrl+X/L UX fix: clearing the screen but not `self._messages` left
    the model "remembering" things no longer visible, with no way to tell
    what it still knows. Clearing must reset both together.
    """
    from sandroid.ai.prompts import ORCHESTRATOR_SYSTEM_PROMPT

    app = _ChatPanelHarness()
    async with app.run_test() as pilot:
        panel = app.query_one("#chat-panel", ChatPanel)
        panel._messages.append({"role": "user", "content": "hello"})
        panel._messages.append({"role": "assistant", "content": "hi there"})
        assert len(panel._messages) == 3

        panel.action_clear_log()
        await pilot.pause()

        assert panel._messages == [
            {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT}
        ]


@pytest.mark.smoke
async def test_ctrl_l_refused_while_a_turn_is_in_progress():
    """Clearing mid-turn would just get silently undone: `_run_turn_sync`
    commits its own `turn_messages` copy back to `self._messages` when the
    in-flight turn finishes, resurrecting exactly what was just cleared.
    """
    app = _ChatPanelHarness()
    async with app.run_test() as pilot:
        panel = app.query_one("#chat-panel", ChatPanel)
        panel._messages.append({"role": "user", "content": "hello"})
        panel._turn_in_progress = True

        panel.action_clear_log()
        await pilot.pause()

        assert len(panel._messages) == 2  # unchanged -- clear was refused


# -- Task 1: Markdown rendering ------------------------------------------


def test_finalized_assistant_reply_renders_as_markdown():
    """Regression test for the reported bug: `**Emulator status**` showing
    up on screen with literal asterisks. The model's reply is real
    Markdown, not Rich console markup, so a finalized reply must become a
    ``rich.markdown.Markdown`` renderable -- never an escaped plain string
    with the Markdown syntax still in it.
    """
    panel = ChatPanel(id="chat-panel")
    panel._live_text = "**Emulator status**\n- running\n- rooted"
    panel._finalize_live()

    markdown_entries = [
        line for line in panel._history_lines if isinstance(line, Markdown)
    ]
    assert len(markdown_entries) == 1
    assert markdown_entries[0].markup == "**Emulator status**\n- running\n- rooted"

    # The old bug: an escaped markup string with the literal `**` still in
    # it. No history entry should look like that.
    assert not any(
        isinstance(line, str) and "**Emulator status**" in line
        for line in panel._history_lines
    )
    # live buffer was folded away
    assert panel._live_text == ""


def test_tool_call_lines_stay_plain_markup():
    """Only LLM-authored prose gets the Markdown treatment, and only the
    user's own echoed input gets the highlight-band ``Text`` treatment (see
    the "Task 4" tests below) -- tool-call announcements and errors are our
    own UI chrome and stay simple Rich console-markup strings.
    """
    panel = ChatPanel(id="chat-panel")
    panel._append_ui_event(
        {"type": "tool_call_done", "name": "list_packages", "arguments": {}}
    )

    assert all(isinstance(line, str) for line in panel._history_lines)


# -- Task 2: verbose thinking toggle --------------------------------------


def test_reasoning_collapses_to_thought_for_line_by_default(monkeypatch):
    """Default (show_verbose_thinking=False, and also true if config isn't
    set at all): once real text starts after a reasoning phase, the raw
    reasoning text must NOT appear in the transcript -- only a compact
    "Thought for Ns" summary, timed with `time.monotonic()`.
    """
    from sandroid.core.toolbox import Toolbox

    monkeypatch.setattr(
        Toolbox,
        "config",
        SimpleNamespace(ai=SimpleNamespace(show_verbose_thinking=False)),
        raising=False,
    )
    ticks = iter([100.0, 104.0])
    monkeypatch.setattr(time_module, "monotonic", lambda: next(ticks))

    panel = ChatPanel(id="chat-panel")
    panel._append_ui_event(
        {"type": "reasoning_delta", "content": "Let me think about this..."}
    )
    panel._append_ui_event({"type": "text_delta", "content": "Here's the answer."})

    assert any(
        isinstance(line, str) and "Thought for 4s" in line
        for line in panel._history_lines
    )
    assert not any(
        "Let me think about this" in str(getattr(line, "markup", line))
        for line in panel._history_lines
    )
    assert panel._live_reasoning == ""
    assert panel._reasoning_started_at is None


def test_reasoning_kept_verbatim_as_markdown_when_verbose(monkeypatch):
    """With show_verbose_thinking=True, the full reasoning text is kept
    (as Markdown, like the final reply) -- no collapsed summary line.
    """
    from sandroid.core.toolbox import Toolbox

    monkeypatch.setattr(
        Toolbox,
        "config",
        SimpleNamespace(ai=SimpleNamespace(show_verbose_thinking=True)),
        raising=False,
    )

    panel = ChatPanel(id="chat-panel")
    panel._append_ui_event(
        {"type": "reasoning_delta", "content": "Let me think about this..."}
    )
    panel._append_ui_event({"type": "text_delta", "content": "Here's the answer."})

    assert any(
        isinstance(line, Markdown) and line.markup == "Let me think about this..."
        for line in panel._history_lines
    )
    assert not any(
        isinstance(line, str) and "Thought for" in line for line in panel._history_lines
    )


def test_reasoning_before_a_tool_call_also_collapses(monkeypatch):
    """The reasoning-phase-ended heuristic must also fire for
    reasoning -> tool_call_done (not just reasoning -> text_delta).
    """
    from sandroid.core.toolbox import Toolbox

    monkeypatch.setattr(
        Toolbox,
        "config",
        SimpleNamespace(ai=SimpleNamespace(show_verbose_thinking=False)),
        raising=False,
    )
    ticks = iter([50.0, 52.0])
    monkeypatch.setattr(time_module, "monotonic", lambda: next(ticks))

    panel = ChatPanel(id="chat-panel")
    panel._append_ui_event({"type": "reasoning_delta", "content": "hmm"})
    panel._append_ui_event(
        {"type": "tool_call_done", "name": "list_packages", "arguments": {}}
    )

    assert any(
        isinstance(line, str) and "Thought for 2s" in line
        for line in panel._history_lines
    )


# -- Task 3: chat mascot ---------------------------------------------------


@pytest.mark.smoke
async def test_mascot_animates_while_streaming_and_idles_when_done():
    app = _ChatPanelHarness()
    async with app.run_test() as pilot:
        panel = app.query_one("#chat-panel", ChatPanel)
        mascot = app.query_one("#chat-mascot", Static)
        assert panel._mascot_timer is None  # nothing wasted while idle

        panel._header_state = "streaming"
        panel.refresh_header()
        await pilot.pause()
        assert panel._mascot_timer is not None
        assert mascot.display is True

        panel._header_state = "idle"
        panel.refresh_header()
        await pilot.pause()
        assert panel._mascot_timer is None  # stopped, not just paused


@pytest.mark.smoke
async def test_mascot_hidden_and_not_animated_when_setting_off(monkeypatch):
    from sandroid.core.toolbox import Toolbox

    monkeypatch.setattr(
        Toolbox,
        "config",
        SimpleNamespace(ai=SimpleNamespace(show_chat_mascot=False)),
        raising=False,
    )

    app = _ChatPanelHarness()
    async with app.run_test() as pilot:
        panel = app.query_one("#chat-panel", ChatPanel)
        mascot = app.query_one("#chat-mascot", Static)

        panel._header_state = "streaming"
        panel.refresh_header()
        await pilot.pause()

        assert mascot.display is False
        assert panel._mascot_timer is None


@pytest.mark.smoke
async def test_mascot_overlaps_input_bar_near_the_right_edge():
    """Regression test for the requested layout: the mascot must stand ON
    the input bar (its feet on the bar's top rim, body rising above it into
    the transcript), near the panel's right edge -- not live beside it in its
    own column, and not sink down over the text field.

    Uses real computed regions from Textual's layout engine (available even
    headless, with no real terminal) rather than just checking CSS text, so
    this actually fails if the positioning regresses to a side-by-side
    layout or drifts off the bar entirely.
    """
    app = _ChatPanelHarness()
    async with app.run_test(size=(100, 30)) as pilot:
        panel = app.query_one("#chat-panel", ChatPanel)
        mascot = app.query_one("#chat-mascot", Static)
        bar = app.query_one("#chat-input-bar")
        await pilot.pause()

        # Genuine overlap: the mascot's region and the input bar's region
        # actually intersect on screen (not just adjacent columns).
        assert mascot.region.overlaps(bar.region)

        # "Near the right side": flush with the panel's own right edge.
        assert mascot.region.right == panel.region.right

        # "Standing on top of"/"rising above" the bar's own top border: the
        # mascot starts above the bar's top and its feet just reach the bar's
        # top rim -- overlapping exactly that top row, without sinking into
        # the row below (which is where the user's typed text lives).
        assert mascot.region.y < bar.region.y
        assert mascot.region.bottom >= bar.region.y + 1
        assert mascot.region.bottom <= bar.region.y + 2


@pytest.mark.smoke
async def test_mascot_does_not_block_clicks_on_chat_input():
    """Regression test for a real bug found while implementing the overlap:
    an earlier version made the mascot's own hit-test region span the full
    width of the input bar (to right-align its content), which -- since
    Textual's mouse targeting is purely region-based, with no
    "click-through" for a widget's blank cells -- silently ate every click
    meant for the Input underneath it. The mascot must stay small/auto-
    sized so only clicks on its own glyphs are captured by it.
    """
    app = _ChatPanelHarness()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.click("#chat-input", offset=(5, 1))
        assert isinstance(app.focused, Input)


def test_mascot_idle_frame_is_a_real_crop_of_the_logo():
    """The mascot must genuinely be a small version of the real Sandroid
    logo -- not a hand-drawn approximation (three earlier attempts at drawing
    new glyphs failed to read as the robot). Assert each idle-frame row is a
    verbatim substring of the matching SANDROID_LOGO line (i.e. an actual
    crop of the same asset the startup banner renders) and pure Braille.
    """
    from sandroid.core.console import SANDROID_LOGO
    from sandroid.tui.widgets.chat_panel import _MASCOT_IDLE_FRAME

    logo_lines = SANDROID_LOGO.splitlines()
    assert len(_MASCOT_IDLE_FRAME) == 5
    for i, row in enumerate(_MASCOT_IDLE_FRAME):
        assert len(row) == 16
        # a real, contiguous crop of the actual logo line (the head region)
        assert row in logo_lines[i]
        # every cell is a Braille-pattern block (U+2800..U+28FF), like the logo
        assert all(0x2800 <= ord(ch) <= 0x28FF for ch in row)


def test_mascot_talk_frames_are_the_same_figure_subtly_moving():
    """The "talking" animation must stay recognizably the same little robot,
    just moving: frame 0 is the resting pose, and every other frame differs
    from idle by a single row (a blink or an antenna sway), never a redraw,
    and keeps the exact frame dimensions so it doesn't jitter/resize.
    """
    from sandroid.tui.widgets.chat_panel import (
        _MASCOT_IDLE_FRAME,
        _MASCOT_TALK_FRAMES,
    )

    assert _MASCOT_TALK_FRAMES[0] == _MASCOT_IDLE_FRAME
    for frame in _MASCOT_TALK_FRAMES:
        assert len(frame) == len(_MASCOT_IDLE_FRAME)
        assert all(
            len(row) == len(_MASCOT_IDLE_FRAME[i]) for i, row in enumerate(frame)
        )
    for frame in _MASCOT_TALK_FRAMES[1:]:
        differing = [i for i in range(len(frame)) if frame[i] != _MASCOT_IDLE_FRAME[i]]
        assert len(differing) == 1


@pytest.mark.smoke
async def test_mascot_blends_into_log_with_no_visible_box():
    """Regression test for the reported "it's in a box" bug. Textual
    composites sibling layers front-to-back with no per-cell transparency, so
    the mascot always paints its whole region -- meaning its background MUST
    equal #chat-log's, or it shows as a lighter rectangle ("a box") over the
    darker transcript. Assert (a) the styles agree and (b) the actually
    composited cells the mascot covers over the log all carry the log's own
    background colour, i.e. the box is genuinely invisible.
    """
    app = _ChatPanelHarness()
    async with app.run_test(size=(100, 30)) as pilot:
        log = app.query_one("#chat-log", RichLog)
        for i in range(60):
            log.write(f"line {i} " + "x" * 80)
        mascot = app.query_one("#chat-mascot", Static)
        log_region = app.query_one("#chat-log").region
        await pilot.pause()

        # (a) the invariant that prevents the box, at the style level
        assert mascot.styles.background == log.styles.background

        # (b) the same invariant, in the actually composited pixels
        strips = app.screen._compositor.render_strips()

        def bg_at(x: int, y: int):
            cx = 0
            for seg in strips[y]:
                for _ in seg.text:
                    if cx == x:
                        return seg.style.bgcolor if seg.style else None
                    cx += 1
            return None

        mr = mascot.region
        # a reference log background, well away from the mascot's columns
        ref = bg_at(1, mr.y)
        assert ref is not None
        for y in range(mr.y, min(mr.bottom, log_region.bottom)):
            for x in range(mr.x, mr.right):
                assert bg_at(x, y) == ref, f"box edge visible at ({x}, {y})"


# -- Task 4: Claude-Code-style user input highlight (round-3 variant I) ---


def test_format_user_line_returns_highlighted_text_not_markup_string():
    """The user's echoed input must be a `>`-prefixed, bold `rich.text.Text`
    carrying a lighter background highlight style -- not the old colored
    heavy-angle-quote-plus-"You:" console-markup string. This is the one
    and only change this variant makes; everything else
    (assistant/reasoning/tool-call rendering) stays exactly as baseline.
    """
    panel = ChatPanel(id="chat-panel")  # unmounted: no #chat-log width yet
    rendered = panel._format_user_line("hello there")

    assert isinstance(rendered, Text)
    assert rendered.plain == "> hello there"
    assert "bold" in rendered.style
    assert "on #1c2333" in rendered.style
    # no leftover trace of the old blue label/glyph scheme
    old_glyph = "❯"  # HEAVY RIGHT-POINTING ANGLE QUOTATION MARK ORNAMENT
    assert "You:" not in rendered.plain
    assert old_glyph not in rendered.plain


@pytest.mark.smoke
async def test_user_line_highlight_band_spans_full_log_width():
    """The whole point of this variant: the lighter background must stretch
    the full row, not just hug the typed characters -- so the rendered
    `Text`'s cell length has to match the log's own current content width.
    """
    app = _ChatPanelHarness()
    async with app.run_test(size=(100, 30)) as pilot:
        panel = app.query_one("#chat-panel", ChatPanel)
        log = app.query_one("#chat-log", RichLog)
        await pilot.pause()

        rendered = panel._format_user_line("hi")

        assert isinstance(rendered, Text)
        assert rendered.cell_len == log.scrollable_content_region.width
        assert rendered.plain.startswith("> hi")
        assert rendered.plain == rendered.plain.rstrip() + " " * (
            log.scrollable_content_region.width - len(rendered.plain.rstrip())
        )


def test_format_user_line_prefixes_only_the_first_row_of_pasted_text():
    """A pasted multi-line message must only get the `>` echo marker once,
    on its first physical line -- matching a blockquote-style echo -- while
    every row still individually carries the highlight style so a multi-line
    paste doesn't lose the band partway through.
    """
    panel = ChatPanel(id="chat-panel")
    rendered = panel._format_user_line("first line\nsecond line")

    assert isinstance(rendered, Text)
    assert rendered.plain == "> first line\nsecond line"


@pytest.mark.smoke
async def test_on_input_submitted_pushes_a_text_renderable_for_the_user_line(
    monkeypatch,
):
    """Integration point for the extracted method: submitting a message must
    push whatever `_format_user_line` builds (a `Text`), not the old inline
    f-string, into history -- verifying the wiring, not just the formatter
    in isolation. `_run_turn_sync` is stubbed out so this only exercises the
    synchronous, UI-thread half of `on_input_submitted` -- no real worker
    thread/network call.
    """
    from sandroid.core.toolbox import Toolbox

    monkeypatch.setattr(
        Toolbox,
        "config",
        SimpleNamespace(
            ai=SimpleNamespace(base_url="http://x", api_key="k", model="m")
        ),
        raising=False,
    )

    app = _ChatPanelHarness()
    async with app.run_test(size=(100, 30)) as pilot:
        panel = app.query_one("#chat-panel", ChatPanel)
        monkeypatch.setattr(panel, "_run_turn_sync", lambda *a, **kw: None)

        input_widget = app.query_one("#chat-input", Input)
        input_widget.value = "hello"
        await pilot.pause()
        input_widget.post_message(Input.Submitted(input_widget, "hello"))
        await pilot.pause()

        user_lines = [line for line in panel._history_lines if isinstance(line, Text)]
        assert len(user_lines) == 1
        assert user_lines[0].plain.startswith("> hello")
