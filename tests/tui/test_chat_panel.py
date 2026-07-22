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

import asyncio
import functools
import threading
import time as time_module
from types import SimpleNamespace

import pytest
from rich.markdown import Markdown
from rich.text import Text
from textual.app import App, ComposeResult
from textual.css.query import NoMatches
from textual.widgets import Button, Input, RichLog, Static

import sandroid.tui.widgets.chat_panel as chat_panel_module
from sandroid.ai.subtasks import CompletionRecord
from sandroid.ai.tools.registry import RiskTier, ToolSpec
from sandroid.tui.screens.main_screen import MainScreen
from sandroid.tui.widgets.chat_panel import ChatPanel, ChatTurnHandle
from sandroid.tui.widgets.tool_permission_prompt import ToolPermissionPrompt


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
    """Chat is no longer one of the left tool tabs -- it docks separately
    (see ``MainScreen.toggle_chat_panel``) -- so it must never reappear in
    ``_TOOL_TABS`` (the 4-way Spotlight/Network/Snapshots/Files cycle).
    """
    assert "tab-chat" not in MainScreen._TOOL_TABS


@pytest.mark.smoke
async def test_toggle_chat_panel_shows_and_hides_the_dock():
    """``Ctrl+Y`` (``MainScreen.toggle_chat_panel``) shows/hides ``#chat-dock``
    via its ``visible`` CSS class, focusing ``#chat-input`` when opening and
    the active tool panel when closing.
    """
    app = App()
    screen = MainScreen()
    async with app.run_test() as pilot:
        await app.push_screen(screen)
        await pilot.pause()

        dock = screen.query_one("#chat-dock")
        assert not dock.has_class("visible")

        screen.toggle_chat_panel()
        await pilot.pause()

        assert dock.has_class("visible")
        assert isinstance(app.focused, Input)
        assert app.focused.id == "chat-input"

        screen.toggle_chat_panel()
        await pilot.pause()

        assert not dock.has_class("visible")
        assert app.focused is not None
        assert app.focused.id == "spotlight-panel"


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


@pytest.mark.smoke
async def test_ambient_block_reaches_the_turn_but_never_persists(monkeypatch):
    """Regression test for the ambient-context wiring (``ai/context.py``):
    ``build_ambient_block()`` is merged into the SAME system message as
    ``ORCHESTRATOR_SYSTEM_PROMPT`` for the turn actually sent to the model
    (never as a second, separate system message -- the real backend only
    attends to the first system-role message in the list, see
    ``_run_turn_sync``), but must never survive into ``self._messages``
    afterward, which must keep carrying the pure, unmodified prompt. Runs
    the real ``_run_turn_sync`` worker-thread method (via
    ``run_worker(thread=True)``, same as ``on_input_submitted`` does), with
    ``build_ambient_block`` and ``run_agent_turn`` monkeypatched so no real
    network/tool call happens.
    """
    from sandroid.ai.prompts import ORCHESTRATOR_SYSTEM_PROMPT

    sentinel = "SENTINEL-AMBIENT-BLOCK-content"
    monkeypatch.setattr(chat_panel_module, "build_ambient_block", lambda: sentinel)

    captured_calls = []

    def fake_run_agent_turn(
        messages,
        tools,
        client,
        cancel_event,
        on_event=None,
        approve=None,
        owner_id=None,
        **kwargs,
    ):
        captured_calls.append(list(messages))
        return "assistant reply"

    monkeypatch.setattr(chat_panel_module, "run_agent_turn", fake_run_agent_turn)

    app = _ChatPanelHarness()
    async with app.run_test() as pilot:
        panel = app.query_one("#chat-panel", ChatPanel)
        handle = ChatTurnHandle()

        worker = panel.run_worker(
            functools.partial(
                panel._run_turn_sync, "hello", handle, "http://x", "k", "m"
            ),
            name="chat_turn",
            thread=True,
        )
        await worker.wait()
        await pilot.pause()

        assert captured_calls, "run_agent_turn was never invoked"
        sent_messages = captured_calls[0]
        assert sentinel in sent_messages[0]["content"], (
            "the ambient block must reach the model for this turn, merged "
            "into the first (system) message's own content"
        )
        assert sent_messages[0]["role"] == "system"
        assert ORCHESTRATOR_SYSTEM_PROMPT in sent_messages[0]["content"], (
            "the merged system message must still carry the orchestrator "
            "prompt alongside the ambient block"
        )
        # Only ONE system message is ever sent -- never a second, separate
        # one -- since the real backend silently ignores any system message
        # past the first.
        assert sum(1 for m in sent_messages if m["role"] == "system") == 1
        assert not any(
            sentinel in m.get("content", "") for m in panel._messages
        ), "the ambient block must never persist into self._messages"
        assert panel._messages[0] == {
            "role": "system",
            "content": ORCHESTRATOR_SYSTEM_PROMPT,
        }, "self._messages[0] must remain the pure, unmodified system prompt"


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


# -- Tool-permission gate (approve_tool_call) ------------------------------

#: Both tests below need `_run_turn_sync` to actually run on a background OS
#: thread (so `approve_tool_call`'s blocking wait doesn't freeze the event
#: loop), but deliberately use a bare `threading.Thread` instead of this
#: file's usual `panel.run_worker(..., thread=True)`. A repeatable
#: investigation (see task notes) found that Textual's own Worker/
#: WorkerManager bookkeeping, when combined with a worker callable that makes
#: *multiple, blocking* `call_from_thread` round-trips into the app while the
#: test's own coroutine is concurrently polling the DOM, intermittently wedges
#: the app's event loop hard enough that even `asyncio.wait_for`'s
#: cancellation is never delivered -- a genuine, pre-existing hazard in
#: combining `run_worker(thread=True)` with this brand-new
#: blocks-on-a-cross-thread-round-trip pattern, not a bug in
#: `approve_tool_call` itself (confirmed independently reproducible with a
#: minimal, ChatPanel-free widget). A bare `Thread` runs the exact same
#: `_run_turn_sync` method on the exact same kind of real OS thread `approve_
#: tool_call` is written to expect, without going through that flaky
#: machinery -- reliable across 15+ repeated manual runs, vs. failing roughly
#: a third of the time via `run_worker`. Flagged for separate follow-up.


async def _wait_for_thread_done(
    thread: threading.Thread, max_wait: float = 10.0
) -> bool:
    """Cooperatively wait for `thread` to finish without blocking the loop.

    Polls `thread.is_alive()` with short `asyncio.sleep`s (never a blocking
    `Thread.join()`) so that if something ever goes wrong, the *surrounding*
    `asyncio.wait_for(...)` in the calling test can still deliver its
    cancellation -- a synchronous `join()` would have no await point for
    that cancellation to land on, defeating the whole safety net.

    Returns:
        True once `thread` has finished; False if `max_wait` elapsed first.
    """
    deadline = time_module.monotonic() + max_wait
    while thread.is_alive():
        if time_module.monotonic() > deadline:
            return False
        await asyncio.sleep(0.05)
    return True


@pytest.mark.smoke
async def test_approve_tool_call_resolves_via_real_button_click(monkeypatch):
    """End-to-end regression test for the tool-permission gate: a pending
    tool call blocks the worker thread until a real button click on the
    mounted ``ToolPermissionPrompt`` resolves it.

    Sequencing is critical here. The fake ``run_agent_turn`` below calls the
    panel's real ``approve_tool_call`` closure directly -- on a real
    background thread, simulating exactly what ``ai.loop._dispatch_one``
    does for a real "ask"-policy tool call. That closure blocks on a local
    ``threading.Event`` that only a button click (handled on the app's
    event-loop thread) can set. So this test MUST poll for the mounted
    prompt's own button and click it BEFORE awaiting the thread -- awaiting
    it first (this file's more common ``run_worker``/``wait()`` pattern)
    would deadlock, since nothing would ever click the button to unblock it.
    There is no ``pytest-timeout`` configured in this repo, so the whole
    scenario is additionally wrapped in ``asyncio.wait_for`` as a
    belt-and-braces guard: a sequencing mistake fails fast with a
    ``TimeoutError`` instead of hanging the suite.
    """
    captured: dict[str, str] = {}

    spec = ToolSpec(
        name="dangerous_tool",
        description="Does something dangerous.",
        parameters={"type": "object", "properties": {}, "required": []},
        func=lambda: None,
        risk=RiskTier.REVERSIBLE,
    )

    def fake_run_agent_turn(
        messages,
        tools,
        client,
        cancel_event,
        on_event=None,
        approve=None,
        owner_id=None,
        **kwargs,
    ):
        assert approve is not None, "approve_tool_call was not passed through"
        captured["choice"] = approve(spec, {"target": "thing"})
        return "assistant reply"

    monkeypatch.setattr(chat_panel_module, "run_agent_turn", fake_run_agent_turn)

    async def scenario() -> None:
        app = _ChatPanelHarness()
        async with app.run_test(size=(100, 30)) as pilot:
            panel = app.query_one("#chat-panel", ChatPanel)
            handle = ChatTurnHandle()

            thread = threading.Thread(
                target=panel._run_turn_sync,
                args=("hello", handle, "http://x", "k", "m"),
                daemon=True,
            )
            thread.start()

            # Poll for the prompt's OWN button (not just its parent
            # container) FIRST: mounting the container is awaited, but its
            # composed children (the buttons) can lag a beat behind that --
            # polling for the button itself is the only fully reliable
            # "ready to click" signal. Also wait for the header state, not
            # just the button: `approve_tool_call` mounts the widget and
            # flips the header state inside the SAME awaited coroutine, but
            # `Widget.mount()` has its own internal await points, so the
            # button can become queryable a beat before that coroutine
            # actually resumes past its `await self.mount(...)` to set the
            # header state -- wait for both together rather than assume
            # they land in the same tick.
            button = None
            for _ in range(300):
                try:
                    candidate = app.query_one("#btn-once", Button)
                except NoMatches:
                    candidate = None
                if candidate is not None and panel._header_state == "awaiting-approval":
                    button = candidate
                    break
                await asyncio.sleep(0.02)
            assert button is not None, "ToolPermissionPrompt's button never mounted"
            assert panel._header_state == "awaiting-approval"

            # ONLY NOW simulate the click -- this is what sets the local
            # Event the background thread is blocked waiting on.
            clicked = await pilot.click("#btn-once")
            assert clicked

            # Wait for the thread AFTER the click, never before -- and
            # cooperatively (never a blocking Thread.join()), so this
            # test's own asyncio.wait_for can still cancel it if wrong.
            finished = await _wait_for_thread_done(thread)
            assert finished, "background thread never finished after the click"
            await pilot.pause()

            assert captured.get("choice") == "once"
            # The prompt is unmounted and the header state restored once
            # the approval is resolved.
            with pytest.raises(NoMatches):
                app.query_one(ToolPermissionPrompt)
            assert panel._header_state != "awaiting-approval"

    await asyncio.wait_for(scenario(), timeout=15)


@pytest.mark.smoke
async def test_approve_tool_call_never_hangs_returns_cancelled_on_stop(monkeypatch):
    """A Stop (Ctrl+X, i.e. the turn's own ``cancel_event``) must unblock a
    pending approval as ``"cancelled"`` -- never a permanent "never" -- so
    hitting Stop while a prompt is up can't silently blacklist whatever tool
    happened to be pending. No button is ever clicked in this test; the
    cancel_event alone must be enough to resolve the wait within a couple of
    poll ticks, so this also indirectly proves the wait loop's cancellation
    check actually runs. Wrapped in ``asyncio.wait_for`` for the same
    hang-safety reason as the sibling test above.
    """
    captured: dict[str, str] = {}

    spec = ToolSpec(
        name="dangerous_tool",
        description="Does something dangerous.",
        parameters={"type": "object", "properties": {}, "required": []},
        func=lambda: None,
        risk=RiskTier.REVERSIBLE,
    )

    def fake_run_agent_turn(
        messages,
        tools,
        client,
        cancel_event,
        on_event=None,
        approve=None,
        owner_id=None,
        **kwargs,
    ):
        assert approve is not None
        captured["choice"] = approve(spec, {"target": "thing"})
        return ""

    monkeypatch.setattr(chat_panel_module, "run_agent_turn", fake_run_agent_turn)

    async def scenario() -> None:
        app = _ChatPanelHarness()
        async with app.run_test(size=(100, 30)) as pilot:
            panel = app.query_one("#chat-panel", ChatPanel)
            handle = ChatTurnHandle()

            thread = threading.Thread(
                target=panel._run_turn_sync,
                args=("hello", handle, "http://x", "k", "m"),
                daemon=True,
            )
            thread.start()

            button = None
            for _ in range(300):
                try:
                    button = app.query_one("#btn-once", Button)
                    break
                except NoMatches:
                    await asyncio.sleep(0.02)
            assert button is not None, "ToolPermissionPrompt's button never mounted"

            # Simulate Ctrl+X: set the turn's cancel_event directly, exactly
            # what ChatPanel.action_stop_turn does via `handle.stop()`.
            handle.stop()

            finished = await _wait_for_thread_done(thread)
            assert finished, "background thread never finished after cancel_event.set()"
            await pilot.pause()

            assert captured.get("choice") == "cancelled"
            with pytest.raises(NoMatches):
                app.query_one(ToolPermissionPrompt)

    await asyncio.wait_for(scenario(), timeout=15)


# -- Phase 3/4: async-subtask integration ---------------------------------
#
# These drive the completion scheduler (Phase 3) and the collapsible,
# selection-aware subtask status bar (Phase 4) against a stub SubtaskManager
# -- no real threads or network. The completion-scheduler tests deliberately
# replace ``panel._launch_turn`` with a recorder instead of letting a real
# worker thread run (this file already documents run_worker(thread=True) as a
# flaky-under-test hazard for the blocks-on-a-round-trip pattern); the launch
# decision is exactly what those tests assert, so recording the call is both
# sufficient and deterministic.


class _StubSubtaskManager:
    """Minimal SubtaskManager stand-in for the Phase 3/4 ChatPanel tests.

    Records spawn/cancel/stop calls and lets a test inject completion records
    and a running-row snapshot, with no real threads, arbiter, or network.
    Only the surface ChatPanel actually calls is implemented.
    """

    def __init__(self) -> None:
        self._completed: list[CompletionRecord] = []
        self._running_rows: list[dict] = []
        self.cancelled: list[str] = []
        self.stop_all_calls = 0
        self.on_complete = None
        self.epoch_probe = None

    def configure(self, *, client_factory=None, epoch_probe=None, on_complete=None):
        if epoch_probe is not None:
            self.epoch_probe = epoch_probe
        if on_complete is not None:
            self.on_complete = on_complete

    def take_all_completed(self) -> list[CompletionRecord]:
        drained = list(self._completed)
        self._completed.clear()
        return drained

    def running(self) -> list[dict]:
        return [dict(row) for row in self._running_rows]

    def active_owner_ids(self) -> set[str]:
        return {row["subtask_id"] for row in self._running_rows}

    def cancel(self, subtask_id: str) -> bool:
        self.cancelled.append(subtask_id)
        return True

    def stop_all(self) -> None:
        self.stop_all_calls += 1

    # -- test helpers --
    def add_completion(self, subtask_id, label, result, epoch, privileged=False):
        self._completed.append(
            CompletionRecord(
                subtask_id=subtask_id,
                label=label,
                privileged=privileged,
                result=result,
                epoch=epoch,
            )
        )

    def set_running(self, rows: list[dict]) -> None:
        self._running_rows = rows


@pytest.fixture
def stub_manager(monkeypatch):
    """Point ChatPanel at a stub SubtaskManager and reset the real singletons.

    Resetting ``subtasks._subtask_manager`` / ``arbiter._arbiter`` before and
    after keeps the process-wide singletons from leaking configured callbacks
    or leases across tests.
    """
    import sandroid.ai.arbiter as arbiter_mod
    import sandroid.ai.subtasks as subtasks_mod

    subtasks_mod._subtask_manager = None
    arbiter_mod._arbiter = None
    stub = _StubSubtaskManager()
    monkeypatch.setattr(chat_panel_module, "get_subtask_manager", lambda: stub)
    yield stub
    subtasks_mod._subtask_manager = None
    arbiter_mod._arbiter = None


def test_completion_while_idle_launches_one_synthetic_turn(stub_manager):
    """Idle + one finished subtask -> exactly one synthetic turn, carrying the
    batched result text.
    """
    panel = ChatPanel(id="chat-panel")
    calls: list[tuple[str, bool]] = []
    panel._launch_turn = lambda text, *, synthetic=False: calls.append(
        (text, synthetic)
    )

    stub_manager.add_completion("s1", "probe", "found 3 things", epoch=0)
    panel._drain_completions()

    assert len(calls) == 1
    text, synthetic = calls[0]
    assert synthetic is True
    assert "s1" in text
    assert "probe" in text
    assert "found 3 things" in text


def test_completion_during_turn_defers_then_launches_once_after_finish(stub_manager):
    """A completion arriving mid-turn is NOT launched immediately (and stays
    queued, not lost); it launches exactly once after ``_finish_turn``.
    """
    panel = ChatPanel(id="chat-panel")
    calls: list[tuple[str, bool]] = []
    panel._launch_turn = lambda text, *, synthetic=False: calls.append(
        (text, synthetic)
    )

    panel._turn_in_progress = True
    stub_manager.add_completion("s1", "probe", "done", epoch=0)

    panel._drain_completions()
    assert calls == []  # deferred while a turn is in progress
    assert len(stub_manager._completed) == 1  # left queued, not drained

    panel._finish_turn()  # flips _turn_in_progress off, then re-drains
    assert len(calls) == 1
    assert calls[0][1] is True
    assert "done" in calls[0][0]


def test_two_completions_are_batched_into_one_synthetic_turn(stub_manager):
    """Two fresh completions collapse into ONE synthetic turn (neither lost)."""
    panel = ChatPanel(id="chat-panel")
    calls: list[tuple[str, bool]] = []
    panel._launch_turn = lambda text, *, synthetic=False: calls.append(
        (text, synthetic)
    )

    stub_manager.add_completion("s1", "alpha", "resultA", epoch=0)
    stub_manager.add_completion("s2", "beta", "resultB", epoch=0)
    panel._drain_completions()

    assert len(calls) == 1
    text = calls[0][0]
    assert "s1" in text
    assert "resultA" in text
    assert "s2" in text
    assert "resultB" in text


def test_stale_epoch_completion_is_dropped(stub_manager):
    """A completion whose epoch predates a Ctrl+L clear (epoch bumped) is
    dropped -- no synthetic turn is launched.
    """
    panel = ChatPanel(id="chat-panel")
    calls: list[tuple[str, bool]] = []
    panel._launch_turn = lambda text, *, synthetic=False: calls.append(
        (text, synthetic)
    )

    panel._epoch = 1  # conversation was cleared since the subtask was spawned
    stub_manager.add_completion("s1", "probe", "stale result", epoch=0)
    panel._drain_completions()

    assert calls == []


def test_ctrl_x_cancels_selected_subtask_not_the_turn(stub_manager):
    """Ctrl+X with a subtask selected cancels THAT subtask and leaves the
    active turn running.
    """
    panel = ChatPanel(id="chat-panel")
    stub_manager.set_running(
        [
            {
                "subtask_id": "s1",
                "label": "probe",
                "privileged": False,
                "elapsed": 2.0,
                "last_activity": None,
            }
        ]
    )
    panel._selected_subtask_id = "s1"
    handle = ChatTurnHandle()
    panel._active_handle = handle

    panel.action_stop_turn()

    assert stub_manager.cancelled == ["s1"]
    assert not handle.cancel_event.is_set()  # the reply was NOT stopped
    assert panel._selected_subtask_id is None


def test_ctrl_x_with_no_selection_stops_the_turn(stub_manager):
    """Ctrl+X with nothing selected preserves the original behavior: stop the
    active turn, cancel no subtask.
    """
    panel = ChatPanel(id="chat-panel")
    panel._selected_subtask_id = None
    handle = ChatTurnHandle()
    panel._active_handle = handle

    panel.action_stop_turn()

    assert handle.cancel_event.is_set()
    assert stub_manager.cancelled == []


@pytest.mark.smoke
async def test_subtask_bar_hides_shows_count_and_lists_rows(stub_manager):
    """The bar hides at 0 subtasks, shows a count collapsed, lists rows when
    expanded, and gates the mascot off whenever it is shown.
    """
    app = _ChatPanelHarness()
    async with app.run_test(size=(100, 30)) as pilot:
        panel = app.query_one("#chat-panel", ChatPanel)
        bar = app.query_one("#chat-subtask-bar", Static)
        mascot = app.query_one("#chat-mascot", Static)
        await pilot.pause()

        # 0 rows -> hidden (on_mount already refreshed against the empty stub)
        assert bar.display is False

        # collapsed: a count line, privileged note, mascot gated off
        stub_manager.set_running(
            [
                {
                    "subtask_id": "s1",
                    "label": "probe",
                    "privileged": False,
                    "elapsed": 1.0,
                    "last_activity": "list_processes",
                },
                {
                    "subtask_id": "s2",
                    "label": "deep",
                    "privileged": True,
                    "elapsed": 5.0,
                    "last_activity": None,
                },
            ]
        )
        panel._refresh_subtask_bar()
        await pilot.pause()
        assert bar.display is True
        collapsed = bar.content.plain
        assert "2 subtasks running" in collapsed
        assert "privileged" in collapsed
        assert mascot.display is False  # gated off while the bar is shown

        # expanded: header + one row per subtask
        panel.action_subtasks_up()
        await pilot.pause()
        assert panel._subtasks_expanded is True
        assert panel._selected_subtask_id == "s1"
        expanded = bar.content.plain
        assert "s1" in expanded
        assert "s2" in expanded
        assert "probe" in expanded
        assert "deep" in expanded

        # back to 0 -> hidden again, mascot restored
        stub_manager.set_running([])
        panel._refresh_subtask_bar()
        await pilot.pause()
        assert bar.display is False
        assert mascot.display is True
