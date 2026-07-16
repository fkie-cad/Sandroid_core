"""TUI panel for the AI Chat tab: a streaming, tool-calling chat with Sandroid.

Backed by ``sandroid.ai`` (see that package's own docstring for the full
public surface): an OpenAI-compatible streaming client, a hand-rolled
tool-calling loop (:func:`sandroid.ai.run_agent_turn`), and a merged
native + MCP :class:`~sandroid.ai.tools.registry.ToolRegistry`.

Structurally mirrors ``FriTapPanel``/``MitmproxyPanel`` (header ``Static``
reflecting live state + a ``RichLog`` tail), but adds an ``Input`` for the
message box, since this is the first panel that needs one -- plus a small
animated mascot ``Static`` sharing that same bottom row, right beside the
prompt (see the ``_MASCOT_*`` constants and ``_update_mascot`` below).

**Event-handling note (read before touching ``on_event`` below):** the
plan this was built from assumed ``on_event`` would see a ``tool_call_done``
*and* would somehow get told the tool's result. In reality,
:func:`sandroid.ai.loop.run_agent_turn` only ever calls its ``on_event``
callback for ``text_delta``, ``reasoning_delta``, ``tool_call_done``, and
``error`` -- ``client.py``'s own ``tool_call_delta``/``done`` events are
consumed internally by the loop and never forwarded, and a tool's *result*
is appended straight to the ``messages`` list with no matching event at
all (see ``loop._dispatch_tool_calls``). So a tool call is shown live the
moment it's dispatched, but its result is only ever visible indirectly,
via the model's next streamed reply -- there is no "tool-result" line in
this transcript, because the interface genuinely has nothing to render one
from.

**RichLog has no "edit the last line" API** -- ``write()`` only appends,
and the only way to revise already-written content is ``clear()`` + full
rewrite. So token-by-token streaming is implemented as: keep every
*completed* line in ``self._history_lines`` (immutable once finalized),
keep the in-progress reasoning/reply text in two small buffers, and redraw
(``clear()`` + rewrite history + rewrite the live buffers) on every delta.
This keeps history and the live tail visually consistent with no private
API access, at the cost of a full redraw per token -- acceptable for a
chat transcript's realistic length/rate.

**Markdown rendering:** the model's actual reply/reasoning text is real
Markdown (``**bold**``, lists, code fences, ...), which is a different
language from Rich's console markup (``[bold]...[/]``) used for our own
UI chrome. So ``self._history_lines`` holds a mix of plain markup
*strings* (for chrome: the tool-call/error lines), ``rich.text.Text``
(the user's own echoed input -- see ``_format_user_line``), and
``rich.markdown.Markdown`` renderables (for LLM-authored prose) --
``RichLog.write()`` accepts all three uniformly (see ``_make_renderable``:
non-str ``RenderableType``s pass straight through, untouched by the
``markup=True`` flag). Re-parsing Markdown on every streamed token would
be wasteful and can render oddly mid-stream (unclosed ``**``/code fences),
so the *live* buffers stay plain escaped text while streaming and only
become real ``Markdown(...)`` once folded into history at
``_finalize_live``.

**Verbose thinking:** ``config.ai.show_verbose_thinking`` (default
``False``) controls whether a finished reasoning phase gets dumped into
the transcript verbatim (as ``Markdown``, verbose) or collapsed into one
compact "Thought for Ns" line (default) -- see ``_finalize_reasoning_only``.
There is no explicit "reasoning phase ended" event from ``loop.py``; it's
derived purely from event sequencing here: a reasoning phase ends the
moment a ``text_delta`` or ``tool_call_done`` shows up after some
``reasoning_delta``s were buffered.
"""

from __future__ import annotations

import functools
import json
import logging
import threading
import time
from typing import TYPE_CHECKING

from rich.markdown import Markdown
from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Input, RichLog, Static

from sandroid.ai import AIClientError, OpenAIClient, get_tool_registry, run_agent_turn
from sandroid.ai.prompts import ORCHESTRATOR_SYSTEM_PROMPT
from sandroid.core.console import SANDROID_LOGO

if TYPE_CHECKING:
    from rich.console import RenderableType
    from textual.timer import Timer

logger = logging.getLogger(__name__)

# Seconds between talk frames while the mascot is "talking" -- brisk enough
# to read as animated/lively rather than a slow, barely-perceptible blink.
_MASCOT_FRAME_INTERVAL = 0.35

# The mascot is NOT a hand-drawn approximation -- it is an actual crop of
# ``core.console.SANDROID_LOGO`` (the exact Braille-block asset the startup
# banner renders), so it is guaranteed to read as a small version of the real
# Sandroid android head. The android is the left figure in that banner; its
# antenna + rounded head + eyes occupy rows 0-4, columns 3-18, so that
# 16-wide x 5-tall rectangle is sliced out verbatim as the idle frame:
#
#     ⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀   row 0: the two antennae
#     ⠀⠀⠙⢷⣤⣤⣴⣶⣶⣦⣤⣤⡾⠋⠀⠀   row 1: rounded top of the head
#     ⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀   row 2: solid crown
#     ⠀⣼⣿⣿⣉⣹⣿⣿⣿⣿⣏⣉⣿⣿⣧⠀   row 3: the face, with the two eyes (⣉⣹ / ⣏⣉)
#     ⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇   row 4: the solid jaw/base it "stands" on
_MASCOT_IDLE_FRAME: tuple[str, ...] = tuple(
    line[3:19] for line in SANDROID_LOGO.splitlines()[0:5]
)

_BRAILLE_BLANK = "⠀"  # U+2800, the "blank" Braille cell used as filler
_SOLID_BLOCK = "⣿"  # U+28FF, the full 8-dot block used all over the logo


def _blink(frame: tuple[str, ...]) -> tuple[str, ...]:
    """Return ``frame`` with the head's two eyes filled in (a single blink).

    The eye row is row 3 of the head slice; within the 16-column crop the
    left eye sits at columns 4-5 and the right eye at columns 10-11. Filling
    exactly those four cells with the logo's own solid block shuts the eyes
    for one frame without moving anything else -- the same little robot,
    mid-blink.

    Args:
        frame: A mascot frame (tuple of equal-width Braille rows).

    Returns:
        A new frame identical to ``frame`` except for the blinked eye row.
    """
    rows = list(frame)
    eye_row = list(rows[3])
    for col in (4, 5, 10, 11):
        eye_row[col] = _SOLID_BLOCK
    rows[3] = "".join(eye_row)
    return tuple(rows)


def _tilt(frame: tuple[str, ...], dx: int) -> tuple[str, ...]:
    """Return ``frame`` with only the antenna row (row 0) shifted ``dx`` cols.

    The head stays put; just the two antennae slide left (``dx < 0``) or
    right (``dx > 0``) by a cell, kept at the original width by padding/
    trimming the blank edges -- a tiny "alive" sway, not a redraw.

    Args:
        frame: A mascot frame (tuple of equal-width Braille rows).
        dx: Column shift for the antenna row; positive is rightward.

    Returns:
        A new frame identical to ``frame`` except for the shifted antennae.
    """
    rows = list(frame)
    antenna = rows[0]
    width = len(antenna)
    if dx > 0:
        antenna = (_BRAILLE_BLANK * dx + antenna)[:width]
    elif dx < 0:
        antenna = antenna[-dx:] + _BRAILLE_BLANK * (-dx)
    rows[0] = antenna
    return tuple(rows)


# Idle frame first (so index 0 is also the resting pose), then a blink and a
# right/left antenna sway -- cycled while a turn is streaming/thinking so the
# robot visibly blinks and sways instead of sitting frozen, while staying
# recognizably the same cropped-from-the-logo figure throughout (each talk
# frame differs from idle by a single row).
_MASCOT_TALK_FRAMES: tuple[tuple[str, ...], ...] = (
    _MASCOT_IDLE_FRAME,
    _blink(_MASCOT_IDLE_FRAME),
    _tilt(_MASCOT_IDLE_FRAME, 1),
    _tilt(_MASCOT_IDLE_FRAME, -1),
)


class ChatTurnHandle:
    """Cancellation handle for one active top-level chat turn.

    Registered with ``Toolbox`` as the ``"chat"`` background task so an
    in-flight turn shows up in the StatusBar for free (see
    ``Toolbox.register_background_task``); ``stop()`` is the
    ``stop_callback`` Toolbox calls, and is also what Ctrl+X calls directly.
    """

    def __init__(self) -> None:
        self.cancel_event = threading.Event()

    def stop(self) -> None:
        self.cancel_event.set()


class ChatPanel(Widget):
    """Bottom-left panel: AI Chat header + transcript + message input.

    Holds ``self._messages`` (OpenAI-style role/content history) as
    instance state across turns -- safe because ``ContentSwitcher`` children
    are composed once at screen mount and persist for the app's lifetime
    (same assumption ``FriTapPanel`` makes).

    Bindings (when focused):
        Ctrl+X: stop the active turn
        Ctrl+L: clear the transcript AND reset conversation history -- the
            model forgets everything said so far, so what's on screen
            always matches what it actually knows. Refused while a turn is
            in flight (see ``action_clear_log``).
    """

    DEFAULT_CSS = """
    ChatPanel {
        layout: vertical;
        height: 1fr;
        background: #080c18;
        /* Two layers: everything (header/log/input-bar) sits on the implicit
           "default" layer; #chat-mascot is the only thing on "overlay",
           declared last so it always composites in front and can visually
           stand on top of the input bar instead of being clipped into its
           own row. */
        layers: default overlay;
        /* Pins the one auto-sized overlay child (#chat-mascot) to the
           bottom-right corner; its own `offset` then lifts it onto the input
           bar's top edge (see the #chat-mascot rule). A no-op for the
           default-layer children, which already fill their own width/height. */
        align: right bottom;
    }
    ChatPanel > #chat-header {
        height: 1;
        color: #38bdf8;
        text-style: bold;
        padding: 0 1;
    }
    ChatPanel > #chat-log {
        height: 1fr;
        background: #050811;
        scrollbar-size: 1 1;
    }
    ChatPanel > #chat-input-bar {
        height: 3;
    }
    ChatPanel > #chat-input-bar > #chat-input {
        width: 1fr;
        height: 3;
        border: solid #1f2d4d;
        background: #0a1124;
    }
    ChatPanel > #chat-mascot {
        /* A direct sibling of #chat-input-bar (NOT nested inside it) on its
           own "overlay" layer. ChatPanel's `align: right bottom` pins this
           auto-width box to the bottom-right corner; `offset: 0 -2` then
           lifts it two rows so only its bottom row (the robot's solid
           base/"feet") rests on the input bar's top border -- it stands ON
           the bar rather than covering the text field on the row below.

           The background MUST equal #chat-log's (#050811), NOT ChatPanel's
           (#080c18): Textual composites sibling layers front-to-back per
           strip with no per-cell transparency (a widget always paints its
           whole region, and `background: transparent` only resolves against
           ancestors, i.e. ChatPanel), so any other colour would paint a
           visible lighter rectangle -- "a box" -- over the darker log.
           Matching the log makes that box vanish, leaving only the teal
           glyphs floating over the transcript: no border, no panel, no box
           edges. (Keep this in sync with #chat-log's background above.)

           Deliberately auto-width, NOT `width: 100%` + `dock: bottom` (an
           earlier version): a full-width box made the *hit-test* region span
           the whole row too (Textual's mouse targeting is purely
           region-based, with no click-through for a widget's blank cells),
           silently eating every click meant for #chat-input underneath it.
           Auto-sizing keeps that hit-test box tight to the robot's own
           glyphs, so clicks elsewhere on the input bar still reach it. */
        layer: overlay;
        width: auto;
        height: 5;
        offset: 0 -2;
        background: #050811;
        color: #38bdf8;
    }
    """

    BINDINGS = [
        ("ctrl+x", "stop_turn", "Stop"),
        ("ctrl+l", "clear_log", "Clear log"),
    ]

    _HEADER_IDLE = "[#5b6479]○ idle[/]"
    _HEADER_ERROR = "[#fb7185]○ error[/]"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        # OpenAI-style role/content conversation history, across turns.
        # Seeded with the orchestrator system prompt so the model actually
        # knows its role/tools/sample-data caveat -- previously never sent.
        self._messages: list[dict] = [
            {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT}
        ]
        # Finalized transcript lines -- the single source of truth for
        # what's on screen; see module docstring for why a full
        # redraw-on-delta is used instead of live line edits. A mix of
        # plain markup strings (our own UI chrome), ``Text`` (the user's
        # own echoed input, see ``_format_user_line``), and ``Markdown``
        # renderables (LLM-authored prose) -- ``RichLog.write()`` accepts
        # all three uniformly.
        self._history_lines: list[str | Markdown | Text] = []
        self._live_reasoning: str = ""
        self._live_text: str = ""
        # Wall-clock (monotonic) start of the current reasoning phase, for
        # the collapsed "Thought for Ns" summary -- see
        # ``_finalize_reasoning_only``.
        self._reasoning_started_at: float | None = None
        self._header_state = "idle"  # idle | streaming | thinking | tool | error
        self._header_detail = ""
        self._turn_in_progress = False
        self._active_handle: ChatTurnHandle | None = None
        self._mascot_timer: Timer | None = None
        self._mascot_frame_index: int = 0

    # -- compose / mount --------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(self._HEADER_IDLE, id="chat-header")
        yield RichLog(
            markup=True,
            wrap=True,
            auto_scroll=True,
            id="chat-log",
        )
        with Horizontal(id="chat-input-bar"):
            yield Input(
                placeholder="Ask Sandroid… (Enter to send, Ctrl+X to stop)",
                id="chat-input",
            )
        # Mascot is a sibling of #chat-input-bar (not nested inside it) so it
        # isn't confined to -- or clipped by -- the input row's own bounds.
        # It's positioned entirely via CSS (a separate "overlay" layer +
        # `align: right bottom` + `offset`, see DEFAULT_CSS on #chat-mascot):
        # a small crop of the real SANDROID_LOGO android head, background
        # matched to the log so no box shows, perched with its feet on the
        # input bar's top edge near the right side.
        yield Static("\n".join(_MASCOT_IDLE_FRAME), id="chat-mascot")

    def on_mount(self) -> None:
        try:
            self.query_one("#chat-log", RichLog).write(
                "[#5b6479]Enter: send · Ctrl+X: stop · Ctrl+L: clear[/]"
            )
        except Exception:
            pass
        self._update_mascot()

    def on_unmount(self) -> None:
        self._stop_mascot_timer()

    # -- submit -------------------------------------------------------

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "chat-input":
            return
        event.stop()

        text = event.value.strip()
        if not text:
            return

        # Concurrent-turn guard: exclusive=True on run_worker only cancels a
        # same-named *worker*, it cannot force-kill the raw OS thread a prior
        # turn is running on -- only the cooperative cancel_event actually
        # stops it. So refuse a second submit outright while one is active
        # (the Input is also disabled below, this is defense in depth).
        if self._turn_in_progress:
            return

        from sandroid.core.toolbox import Toolbox

        ai_cfg = getattr(getattr(Toolbox, "config", None), "ai", None)
        base_url = getattr(ai_cfg, "base_url", None)
        api_key = getattr(ai_cfg, "api_key", None)
        model = getattr(ai_cfg, "model", None)
        if not (base_url and api_key and model):
            self._push_history(
                "[#fb7185]Set config.ai.base_url/api_key/model to use Chat — "
                "see `sandroid-config` docs[/]"
            )
            return

        event.input.value = ""
        event.input.disabled = True
        self._turn_in_progress = True
        self._header_state = "streaming"
        self._header_detail = ""
        self.refresh_header()

        # Blank line before each new turn (skipped for the very first one)
        # so consecutive turns read as visually distinct blocks in the
        # transcript, on top of the user's highlighted input band.
        if self._history_lines:
            self._push_history("")
        self._push_history(self._format_user_line(text))

        handle = ChatTurnHandle()
        self._active_handle = handle

        self.run_worker(
            functools.partial(
                self._run_turn_sync, text, handle, base_url, api_key, model
            ),
            name="chat_turn",
            exclusive=True,
            thread=True,
        )

    # -- worker thread ------------------------------------------------

    def _run_turn_sync(
        self,
        text: str,
        handle: ChatTurnHandle,
        base_url: str,
        api_key: str,
        model: str,
    ) -> None:
        """Run one full agent turn to completion. Runs on a worker thread."""
        from sandroid.core.toolbox import Toolbox

        try:
            Toolbox.register_background_task(
                name="chat",
                display_name="AI Chat",
                instance=handle,
                stop_callback=handle.stop,
            )
        except Exception as exc:
            logger.debug("Failed to register 'chat' background task: %s", exc)

        def on_event(event: dict) -> None:
            self.app.call_from_thread(self._append_ui_event, event)

        try:
            client = OpenAIClient(base_url, api_key, model)
            tools = get_tool_registry().openai_tools_schema()
            turn_messages = [*self._messages, {"role": "user", "content": text}]

            result = run_agent_turn(
                turn_messages,
                tools,
                client,
                handle.cancel_event,
                on_event=on_event,
            )
            if result:
                turn_messages.append({"role": "assistant", "content": result})
            self._messages = turn_messages
        except AIClientError as exc:
            self.app.call_from_thread(
                self._report_turn_error, f"AI backend error: {exc}"
            )
        except Exception as exc:  # must never crash the worker thread
            logger.exception("Chat turn failed")
            self.app.call_from_thread(
                self._report_turn_error, f"Chat turn failed: {exc}"
            )
        finally:
            try:
                Toolbox.unregister_background_task("chat")
            except Exception:
                pass
            self._active_handle = None
            self.app.call_from_thread(self._finish_turn)

    # -- UI-thread event handling --------------------------------------

    def _append_ui_event(self, event: dict) -> None:
        """Handle one streamed ChatEvent. Always runs on the UI thread.

        Only ever sees ``text_delta``/``reasoning_delta``/``tool_call_done``/
        ``error`` -- see the module docstring for why (loop.py's real event
        surface, not client.py's raw one).
        """
        etype = event.get("type")
        if etype == "text_delta":
            if not self._live_text and self._live_reasoning:
                # First text token after a reasoning phase -- that phase is
                # now over, fold it in (verbatim or collapsed) before the
                # reply itself starts accumulating.
                self._finalize_reasoning_only()
            self._live_text += event.get("content", "")
            self._header_state = "streaming"
            self.refresh_header()
            self._redraw()
        elif etype == "reasoning_delta":
            if not self._live_reasoning:
                self._reasoning_started_at = time.monotonic()
            self._live_reasoning += event.get("content", "")
            self._header_state = "thinking"
            self.refresh_header()
            self._redraw()
        elif etype == "tool_call_done":
            self._finalize_live()
            name = event.get("name") or "?"
            args = event.get("arguments") or {}
            self._push_history(
                f"[#a78bfa]→ tool call: {escape(name)}"
                f"({escape(json.dumps(args))})[/]"
            )
            self._header_state = "tool"
            self._header_detail = name
            self.refresh_header()
        elif etype == "error":
            self._finalize_live()
            message = event.get("message", "unknown error")
            self._push_history(f"[#fb7185]error: {escape(message)}[/]")
            self._header_state = "error"
            self.refresh_header()

    def _report_turn_error(self, message: str) -> None:
        self._finalize_live()
        self._push_history(f"[#fb7185]{escape(message)}[/]")
        self._header_state = "error"
        self.refresh_header()

    def _finish_turn(self) -> None:
        self._finalize_live()
        self._turn_in_progress = False
        if self._header_state != "error":
            self._header_state = "idle"
            self._header_detail = ""
            self.refresh_header()
        try:
            input_widget = self.query_one("#chat-input", Input)
            input_widget.disabled = False
            input_widget.focus()
        except Exception:
            pass

    # -- transcript rendering -------------------------------------------

    def _format_user_line(self, text: str) -> str | RenderableType:
        """Render one user turn, Claude-Code-CLI style: a ``>``-prefixed,
        bold line sitting inside a full-width band that's a subtly lighter
        neutral shade than the surrounding background -- no border, no box,
        no per-role hue, just a plain background shift. The assistant's
        reply carries no label at all -- with the user's own line this
        clearly marked, anything else in the transcript is unambiguously
        the reply, so a "Sandroid:" tag would be redundant.

        A ``rich.text.Text`` shorter than the log's own width only paints
        its background behind its own characters -- ``RichLog.write()``
        pads a rendered line out to the target width using the *renderable's*
        trailing style, which defaults to ``None`` (see
        ``Strip.adjust_cell_length``), so without explicit padding here the
        highlight would show as a short island hugging the text instead of
        spanning the whole row. Padding is done per physical line (split on
        newlines) so a pasted multi-line message gets a full-width band on
        every row, not just the first.

        Args:
            text: The raw, already-stripped text the user submitted.

        Returns:
            A ``Text`` renderable ready to hand to ``RichLog.write()``
            (accepted uniformly alongside plain markup strings and
            ``Markdown``, see the module docstring).
        """
        width = 0
        try:
            log = self.query_one("#chat-log", RichLog)
            width = log.scrollable_content_region.width
        except Exception:
            width = 0

        line = Text(style="bold white on #1c2333", no_wrap=True)
        for i, row in enumerate(text.split("\n")):
            if i == 0:
                row = f"> {row}"
            if i:
                line.append("\n")
            line.append(row)
            if width > len(row):
                line.append(" " * (width - len(row)))
        return line

    def _finalize_live(self) -> None:
        """Fold any in-progress reasoning/reply buffers into history."""
        changed = self._finalize_reasoning_only()
        if self._live_text:
            # No "Sandroid:" label -- the user's own line already stands
            # out via its highlight band (see ``_format_user_line``), so
            # anything else in the transcript is unambiguously the reply.
            # ``style=`` is still required here -- Markdown() defaults to
            # "none" (the console's default foreground), so without it the
            # reply body would render plain white instead of green.
            self._history_lines.append(Markdown(self._live_text, style="#4ade80"))
            self._live_text = ""
            changed = True
        if changed:
            self._redraw()

    def _finalize_reasoning_only(self) -> bool:
        """Fold the in-progress reasoning buffer into history, if any.

        With ``config.ai.show_verbose_thinking`` on, the raw reasoning text
        is kept (rendered as ``Markdown``, same as the final reply). Off
        (the default), it collapses into a single Claude-Code-style
        "Thought for Ns" line, timed with ``time.monotonic()`` (never
        ``time.time()`` -- durations must never be skewed by clock
        adjustments) from the first ``reasoning_delta`` of this phase.

        Returns:
            True if a reasoning buffer was folded in (i.e. history changed).
        """
        if not self._live_reasoning:
            return False
        if self._show_verbose_thinking():
            self._history_lines.append("[italic #facc15]thinking:[/]")
            # Same reasoning as the reply body above: an explicit ``style``
            # is needed or this renders in the default foreground instead
            # of matching the "thinking:" label's italic yellow.
            self._history_lines.append(
                Markdown(self._live_reasoning, style="italic #facc15")
            )
        else:
            duration = 0.0
            if self._reasoning_started_at is not None:
                duration = max(0.0, time.monotonic() - self._reasoning_started_at)
            self._history_lines.append(f"[dim]✻ Thought for {round(duration)}s[/]")
        self._live_reasoning = ""
        self._reasoning_started_at = None
        return True

    def _show_verbose_thinking(self) -> bool:
        """Read ``config.ai.show_verbose_thinking`` (default off)."""
        from sandroid.core.toolbox import Toolbox

        ai_cfg = getattr(getattr(Toolbox, "config", None), "ai", None)
        return bool(getattr(ai_cfg, "show_verbose_thinking", False))

    def _push_history(self, line: str) -> None:
        self._history_lines.append(line)
        self._redraw()

    def _redraw(self) -> None:
        try:
            log = self.query_one("#chat-log", RichLog)
        except Exception:
            return
        log.clear()
        for line in self._history_lines:
            log.write(line)
        if self._live_reasoning:
            log.write(f"[italic #facc15]thinking: {escape(self._live_reasoning)}[/]")
        if self._live_text:
            log.write(f"[#4ade80]{escape(self._live_text)}[/]")

    # -- header -----------------------------------------------------------

    def _render_header(self) -> str:
        if self._header_state == "streaming":
            return "[#4ade80]● streaming…[/]"
        if self._header_state == "thinking":
            return "[#facc15]● thinking…[/]"
        if self._header_state == "tool":
            return f"[#a78bfa]● tool: `{escape(self._header_detail)}`[/]"
        if self._header_state == "error":
            return self._HEADER_ERROR
        return self._HEADER_IDLE

    def refresh_header(self) -> None:
        """Re-render the status header (main thread; best-effort).

        Public so ``MainScreen._select_bottom_tab`` can refresh it the
        moment the Chat tab is activated (mirrors ``FriTapPanel``).

        Also the single choke point that syncs the mascot to
        ``_header_state`` -- every place that changes header state already
        calls this right after, so it's the natural spot to start/stop the
        wiggle animation too instead of a separate polling loop.
        """
        try:
            self.query_one("#chat-header", Static).update(self._render_header())
        except Exception:
            pass
        self._update_mascot()

    # -- mascot -------------------------------------------------------------

    def _mascot_enabled(self) -> bool:
        """Read ``config.ai.show_chat_mascot`` (default on)."""
        from sandroid.core.toolbox import Toolbox

        ai_cfg = getattr(getattr(Toolbox, "config", None), "ai", None)
        return bool(getattr(ai_cfg, "show_chat_mascot", True))

    def _update_mascot(self) -> None:
        """Sync the mascot widget's visibility + animation to current state.

        Streaming/thinking starts the wiggle timer; anything else (idle,
        tool, error) stops it and shows the single idle frame -- no timer
        ticks wasted animating nothing. Also hides the widget outright when
        ``show_chat_mascot`` is off.
        """
        try:
            mascot = self.query_one("#chat-mascot", Static)
        except Exception:
            return

        if not self._mascot_enabled():
            mascot.display = False
            self._stop_mascot_timer()
            return

        mascot.display = True
        active = self._header_state in ("streaming", "thinking")
        if active:
            if self._mascot_timer is None:
                self._mascot_frame_index = 0
                mascot.update("\n".join(_MASCOT_TALK_FRAMES[0]))
                self._mascot_timer = self.set_interval(
                    _MASCOT_FRAME_INTERVAL, self._tick_mascot
                )
        else:
            self._stop_mascot_timer()
            mascot.update("\n".join(_MASCOT_IDLE_FRAME))

    def _tick_mascot(self) -> None:
        """Timer callback: advance to the next blink/bounce/tilt frame."""
        self._mascot_frame_index = (self._mascot_frame_index + 1) % len(
            _MASCOT_TALK_FRAMES
        )
        try:
            self.query_one("#chat-mascot", Static).update(
                "\n".join(_MASCOT_TALK_FRAMES[self._mascot_frame_index])
            )
        except Exception:
            self._stop_mascot_timer()

    def _stop_mascot_timer(self) -> None:
        if self._mascot_timer is not None:
            try:
                self._mascot_timer.stop()
            except Exception:
                pass
            self._mascot_timer = None

    # -- actions ----------------------------------------------------------

    def action_stop_turn(self) -> None:
        """Ctrl+X — stop the active turn, if any."""
        handle = self._active_handle
        if handle is not None:
            handle.stop()

    def action_clear_log(self) -> None:
        """Ctrl+L — clear the transcript AND reset conversation history.

        Clearing only the on-screen log while ``self._messages`` kept
        growing was actively misleading: the model would keep referencing
        things no longer visible on screen, and there'd be no way to tell
        what it still "knows". So both are reset together, back to the
        same state as a freshly-mounted panel (just the system prompt).

        Refused while a turn is in flight: ``_run_turn_sync`` (on its own
        worker thread) commits its own ``turn_messages`` copy back to
        ``self._messages`` when it finishes, which would silently undo a
        clear that happened underneath it a moment earlier.
        """
        if self._turn_in_progress:
            self._push_history(
                "[dim]Can't clear while a reply is in progress -- wait for "
                "it to finish, or Ctrl+X to stop it first.[/]"
            )
            return
        self._messages = [{"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT}]
        self._history_lines = []
        self._live_reasoning = ""
        self._live_text = ""
        self._reasoning_started_at = None
        try:
            self.query_one("#chat-log", RichLog).clear()
        except Exception:
            pass
