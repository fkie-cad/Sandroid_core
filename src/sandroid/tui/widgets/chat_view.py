"""AI chat view layer: transcript blocks, pure formatters and the mascot.

The look of the chat dock (``docs/development/ai_foundations.rst`` §6). This
module only renders; it owns no conversation state. ``ChatPanel`` drives it
from ``AgentEvent`` objects:

* :class:`ChatTranscript` -- a ``VerticalScroll`` holding one widget per
  block, keyed by turn / call / agent id (``add_block`` / ``block``). At most
  :data:`MAX_BLOCKS` stay mounted; older turns fold into "N earlier turns".
* Blocks: :class:`UserBlock`, :class:`ReplyBlock` (Markdown fed through
  ``get_stream`` so only the live block re-renders), :class:`ReasoningLine`,
  :class:`ToolBlock` (result chip filled in place), :class:`AgentCard`,
  :class:`CompactionRule`, :class:`NoticeLine`, :class:`BudgetNotice`
  (posts :class:`BudgetNotice.Continue` / :class:`BudgetNotice.Stop`).
* :class:`ChatHeader` -- one row: state, model, markers, context meter,
  compactions and agents (:func:`format_header`; refreshes <= 10 Hz).
* :class:`ChatMascot` -- "Blockhead", 9x3 cells, one frame set per state,
  plus an ASCII fallback; :class:`EmptyState` shows it in its sandbox tray.

States are plain words in a theme colour, never glyphs (the mascot is
decoration). Colors are theme variables only (``$lens-*`` and the six ``$chat-*`` built
in :func:`sandroid.tui.themes.chat_css_variables`); the formatters return
Textual :class:`~textual.content.Content` whose styles name those variables,
resolved when the widget renders.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import TYPE_CHECKING, Any

from rich.cells import cell_len
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.content import Content
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Button, Markdown, Static

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from textual.app import ComposeResult

# --------------------------------------------------------------------------
# Pure formatters
# --------------------------------------------------------------------------

#: Meter colour thresholds (share of the context window).
METER_WARN = 0.50
METER_BAD = 0.85
#: Header width at or below which the model is dropped and the meter is short.
HEADER_COMPACT_WIDTH = 60
#: Tool call lines narrower than this drop the quotes around string args.
ARGS_COMPACT_WIDTH = 80
#: Longest single argument value shown (cells) before "…".
ARG_VALUE_MAX = 40
#: Most blocks kept mounted in a :class:`ChatTranscript`.
MAX_BLOCKS = 300

#: Header state -> (label, dot style).
HEADER_STATES: dict[str, tuple[str, str]] = {
    "idle": ("idle", "$chat-muted"),
    "thinking": ("thinking", "$lens-accent"),
    "streaming": ("streaming", "$chat-reply"),
    "tool": ("tool", "$chat-tool"),
    "approval": ("waiting on you", "$chat-wait"),
    "compacting": ("compacting", "$lens-warn"),
    "retrying": ("retrying", "$lens-warn"),
    "error": ("error", "$lens-bad"),
    "off": ("not configured", "$chat-muted"),
}

#: Words shown upper-case in humanized tool names.
_ACRONYMS = frozenset(
    [
        "adb",
        "apk",
        "api",
        "avd",
        "ca",
        "cpu",
        "db",
        "dex",
        "dns",
        "fs",
        "http",
        "https",
        "id",
        "ip",
        "json",
        "mcp",
        "mitm",
        "pid",
        "quic",
        "sql",
        "ssl",
        "tcp",
        "tls",
        "ui",
        "uid",
        "udp",
        "url",
        "xml",
    ]
)

#: Agent card status -> (label, style): the word and its colour carry it.
AGENT_STATUS: dict[str, tuple[str, str]] = {
    "queued": ("queued", "$chat-muted"),
    "running": ("running", "$lens-accent"),
    "waiting": ("awaiting approval", "$chat-wait"),
    "done": ("done", "$lens-ok"),
    "failed": ("failed", "$lens-bad"),
    "cancelled": ("cancelled", "$chat-muted"),
}

#: Error codes shown as another word on a result chip.
CHIP_CODE_WORDS = {"tool_failed": "failed"}
#: Error codes of a call the analyst or the runtime stopped (warn, not bad).
CHIP_WARN_CODES = frozenset({"denied", "cancelled"})


def format_tokens(count: float | None) -> str:
    """``950`` / ``9.2k`` / ``41k`` / ``1.2M`` (``?`` when unknown)."""
    if count is None:
        return "?"
    n = int(count)
    if n < 1000:
        return str(n)
    if n < 10_000:
        return f"{n / 1000:.1f}".rstrip("0").rstrip(".") + "k"
    if n < 1_000_000:
        return f"{round(n / 1000)}k"
    return f"{n / 1_000_000:.1f}".rstrip("0").rstrip(".") + "M"


def format_elapsed(seconds: float | None) -> str:
    """``0.4s`` / ``4s`` / ``38s`` / ``1:02`` / ``1:02:03`` (``""`` if None)."""
    if seconds is None:
        return ""
    s = max(0.0, float(seconds))
    if s < 10:
        text = f"{s:.1f}".rstrip("0").rstrip(".")
        return f"{text}s"
    if s < 60:
        return f"{round(s)}s"
    total = round(s)
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes}:{secs:02d}"


def meter_style(fraction: float) -> str:
    """``$lens-dim`` below 50 %, ``$lens-warn`` from 50 %, ``$lens-bad`` from 85 %."""
    if fraction >= METER_BAD:
        return "$lens-bad"
    if fraction >= METER_WARN:
        return "$lens-warn"
    return "$lens-dim"


def format_meter(
    used: int | None, window: int | None, *, compact: bool = False
) -> Content:
    """The context meter: ``41k/262k 16%`` (compact: ``41k 16%``).

    Coloured by fill level (:func:`meter_style`). Without a known window
    only the token count shows (``41k``).
    """
    if not window:
        return Content.styled(format_tokens(used or 0), "$lens-dim")
    fraction = max(0.0, (used or 0) / window)
    pct = round(fraction * 100)
    if compact:
        text = f"{format_tokens(used or 0)} {pct}%"
    else:
        text = f"{format_tokens(used or 0)}/{format_tokens(window)} {pct}%"
    return Content.styled(text, meter_style(fraction))


def format_header(
    state: str = "idle",
    *,
    detail: str | None = None,
    model: str | None = None,
    remote: bool = False,
    experimental: bool = False,
    used: int | None = None,
    window: int | None = None,
    compactions: int = 0,
    agents: int = 0,
    width: int = 100,
) -> Content:
    """The one-row chat header, ``width`` cells wide.

    ``tool · List Flows · deepseek-v3 REMOTE EXPERIMENTAL ... 41k/262k 16%``.
    The state is a word in its colour. When it does not fit, parts go in
    this order: the model, the meter's window (``41k 16%``), then the detail is cut with "…". ``REMOTE`` and
    ``EXPERIMENTAL`` always stay whole (§8); at :data:`HEADER_COMPACT_WIDTH`
    columns or less the model is never shown.
    """
    label, state_style = HEADER_STATES.get(state, (state, "$chat-muted"))

    markers: list[Any] = []
    if remote:
        markers += [" ", ("REMOTE", "bold $lens-warn")]
    if experimental:
        markers += [" ", ("EXPERIMENTAL", "$lens-warn")]
    tail = Content.assemble(*markers)

    def right_side(compact: bool) -> Content:
        parts: list[Any] = []
        if used is not None or window:
            parts.append(format_meter(used, window, compact=compact))
        sep = " " if compact else "  "
        if compactions:
            parts += [sep, (f"{compactions} compacted", "$chat-muted")]
        if agents:
            plural = "s" if agents != 1 else ""
            parts += [sep, (f"{agents} agent{plural}", "$chat-tool")]
        return Content.assemble(*parts, " ")

    head = Content.assemble(" ", (label, state_style))
    detail_part = (
        Content.assemble((" · ", "$chat-muted"), detail) if detail else Content("")
    )
    model_part = (
        Content.assemble((" · ", "$chat-muted"), (model, "$chat-muted"))
        if model
        else Content("")
    )
    allow_model = width > HEADER_COMPACT_WIDTH
    attempts = [
        # (show model, compact meter)
        (allow_model, width <= HEADER_COMPACT_WIDTH),
        (False, width <= HEADER_COMPACT_WIDTH),
        (False, True),
    ]
    for show_model, compact in attempts:
        right = right_side(compact)
        left = Content.assemble(
            head, detail_part, model_part if show_model else Content(""), tail
        )
        room = width - right.cell_length - 1
        if left.cell_length <= room:
            gap = max(1, width - left.cell_length - right.cell_length)
            return Content.assemble(left, " " * gap, right)
    # Still too wide: cut the detail (then the label), keep the markers whole.
    keep = Content.assemble(head, tail)
    room = width - right.cell_length - 1
    if keep.cell_length < room and detail:
        detail_room = room - keep.cell_length
        left = Content.assemble(
            head, detail_part.truncate(max(1, detail_room), ellipsis=True), tail
        )
    elif tail.cell_length < room:
        left = Content.assemble(
            head.truncate(max(1, room - tail.cell_length), ellipsis=True), tail
        )
    else:
        left = keep.truncate(max(1, room), ellipsis=True)
    gap = max(1, width - left.cell_length - right.cell_length)
    return Content.assemble(left, " " * gap, right)


def humanize_tool_name(name: str) -> str:
    """``list_flows`` -> ``List Flows``; ``get_tls_keys`` -> ``Get TLS Keys``.

    MCP tools (``mcp:<server>:<tool>``) read ``<Tool> (<server>)``.
    """
    server = None
    if name.startswith("mcp:"):
        _, _, rest = name.partition(":")
        server, _, name = rest.partition(":")
    words = name.replace("-", "_").replace(".", "_").split("_")
    shown = " ".join(
        w.upper() if w.lower() in _ACRONYMS else w[:1].upper() + w[1:]
        for w in words
        if w
    )
    return f"{shown} ({server})" if server else shown


def _arg_value(value: Any, *, quote: bool) -> str:
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, int | float):
        text = str(value)
    elif isinstance(value, str):
        text = json.dumps(value, ensure_ascii=False) if quote else value
        text = text.replace("\n", " ")
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            text = str(value)
    if cell_len(text) > ARG_VALUE_MAX:
        cut = Content(text).truncate(ARG_VALUE_MAX - 1).plain
        text = cut + ('…"' if quote and text.startswith('"') else "…")
    return text


def format_args(
    args: Mapping[str, Any] | None,
    *,
    compact: bool = False,
    max_width: int | None = None,
) -> Content:
    """Tool arguments: ``package="com.example"  since="launch"``.

    ``compact`` drops the quotes (``package=com.example``); ``None`` values
    are left out; ``max_width`` cuts the whole line with "…".
    """
    parts: list[str | tuple[str, str]] = []
    for key, value in (args or {}).items():
        if value is None:
            continue
        if parts:
            parts.append("  ")
        parts += [(f"{key}=", "$chat-muted"), _arg_value(value, quote=not compact)]
    content = Content.assemble(*parts)
    if max_width is not None and content.cell_length > max_width:
        content = content.truncate(max(1, max_width), ellipsis=True)
    return content


def format_chip(
    *,
    ok: bool = True,
    ref: str | None = None,
    summary: str | None = None,
    elapsed: float | None = None,
    code: str | None = None,
    message: str | None = None,
) -> Content:
    """A tool result chip: ``done · R17 · 12 rows · 0.4s`` / ``code: message``.

    The first word says how the call ended, in its colour: ``done`` (ok),
    the error code (``denied`` / ``cancelled`` warn, others bad; a plain
    tool failure reads ``failed``).
    """
    if not ok:
        word = CHIP_CODE_WORDS.get(code or "", code) or "failed"
        style = "$lens-warn" if code in CHIP_WARN_CODES else "$lens-bad"
        parts: list[str | tuple[str, str]] = [(f"{word}:" if message else word, style)]
        if message:
            parts += [" ", (message, "$chat-muted")]
        if elapsed is not None:
            parts.append((f" · {format_elapsed(elapsed)}", "$chat-muted"))
        return Content.assemble(*parts)
    bits = [b for b in (ref, summary, format_elapsed(elapsed)) if b]
    parts = [("done", "$lens-ok")]
    for bit in bits:
        parts.append((" · ", "$chat-muted"))
        parts.append((bit, "bold $lens-accent" if bit == ref else "$chat-muted"))
    return Content.assemble(*parts)


def format_progress(text: str) -> Content:
    """A running call's progress line: ``classifying 120/412 · 9 matched``."""
    return Content.styled(text, "$chat-muted")


def progress_text(payload: Mapping[str, Any]) -> str:
    """Chip text of a ``tool_progress`` payload.

    ``{"note": "classifying", "done": 120, "total": 412, "matched": 9}`` ->
    ``"classifying 120/412 · 9 matched"``.
    """
    note = str(payload.get("note") or "working")
    done = payload.get("done")
    total = payload.get("total")
    text = note
    if isinstance(done, int):
        text += f" {done}/{total}" if isinstance(total, int) else f" {done}"
    matched = payload.get("matched")
    if isinstance(matched, int):
        text += f" · {matched} matched"
    return text


def format_card_title(
    role: str,
    agent_id: str,
    status: str = "running",
    *,
    elapsed: float | None = None,
    tokens: int | None = None,
) -> Content:
    """``researcher r2 · done · 38s · 9.2k tok`` (the status in its colour)."""
    label, style = AGENT_STATUS.get(status, (status, "$chat-muted"))
    parts: list[str | tuple[str, str]] = [
        (f"{role} {agent_id}", "bold"),
        (" · ", "$chat-muted"),
        (label, style),
    ]
    if elapsed is not None:
        parts += [(" · ", "$chat-muted"), (format_elapsed(elapsed), "$chat-muted")]
    if tokens is not None:
        parts += [
            (" · ", "$chat-muted"),
            (f"{format_tokens(tokens)} tok", "$chat-muted"),
        ]
    return Content.assemble(*parts)


def format_compaction(before: int, after: int, masked: int = 0) -> str:
    """``compacted · 182k → 41k · 14 results masked``."""
    text = f"compacted · {format_tokens(before)} → {format_tokens(after)}"
    if masked:
        text += f" · {masked} result{'s' if masked != 1 else ''} masked"
    return text


def format_retry(
    seconds: float, attempt: int, attempts: int, reason: str | None = None
) -> str:
    """``Retrying in 4s · attempt 2/5 · 429 rate limited``."""
    text = f"Retrying in {format_elapsed(seconds)} · attempt {attempt}/{attempts}"
    return f"{text} · {reason}" if reason else text


def ruled(label: str, width: int, style: str = "$chat-muted") -> Content:
    """``label`` centred in a ``─`` rule ``width`` cells wide."""
    text = f" {label} "
    if cell_len(text) + 2 > width:
        return Content.styled(text.strip(), style).truncate(
            max(1, width), ellipsis=True
        )
    left = (width - cell_len(text)) // 2
    right = width - left - cell_len(text)
    return Content.styled("─" * left + text + "─" * right, style)


# --------------------------------------------------------------------------
# Mascot ("Blockhead", 9x3 cells)
# --------------------------------------------------------------------------

#: Mascot states.
MASCOT_STATES = ("idle", "thinking", "streaming", "tool", "approval", "error")

_B_IDLE = ("  ▚   ▞  ", " ▄█████▄ ", "▐█▄███▄█▌")
#: Block frames per state, played in a loop (one frame = static).
BLOCK_FRAMES: dict[str, tuple[tuple[str, str, str], ...]] = {
    # Blink: seven open-eye frames, one closed.
    "idle": (_B_IDLE,) * 7 + (("  ▚   ▞  ", " ▄█████▄ ", "▐███████▌"),),
    # Eye-scan left / centre / right / centre.
    "thinking": (
        ("  ▚   ▞  ", " ▄█████▄ ", "▐▄███▄██▌"),
        _B_IDLE,
        ("  ▚   ▞  ", " ▄█████▄ ", "▐██▄███▄▌"),
        _B_IDLE,
    ),
    # Antennae flicker.
    "streaming": (_B_IDLE, ("  ▘   ▝  ", " ▄█████▄ ", "▐█▄███▄█▌")),
    "tool": (("  ▚   ▞  ", " ▄█████▄ ", "▐█▆███▆█▌"),),
    "approval": (("  ▐   ▌  ", " ▄█████▄ ", "▐█ ███ █▌"),),
    "error": (("  ▗   ▖  ", " ▄█████▄ ", "▐█x███x█▌"),),
}

_A_IDLE = ("  \\   /  ", " .-----. ", "[| o o |]")
#: ASCII-only fallback frames (same states, same 9x3 cells).
ASCII_FRAMES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "idle": (_A_IDLE,) * 7 + (("  \\   /  ", " .-----. ", "[| _ _ |]"),),
    "thinking": (
        ("  \\   /  ", " .-----. ", "[|o o  |]"),
        _A_IDLE,
        ("  \\   /  ", " .-----. ", "[|  o o|]"),
        _A_IDLE,
    ),
    "streaming": (_A_IDLE, ("  '   '  ", " .-----. ", "[| o o |]")),
    "tool": (("  \\   /  ", " .-----. ", "[| - - |]"),),
    "approval": (("  |   |  ", " .-----. ", "[| O O |]"),),
    "error": (("  /   \\  ", " .-----. ", "[| x x |]"),),
}

#: The sandbox tray under the head in the empty state (blocks / ASCII).
MASCOT_TRAY = {"blocks": "╘═══════╛", "ascii": "`-------'"}
#: Seconds per frame of the animated states.
MASCOT_INTERVAL = {"idle": 0.5, "thinking": 0.35, "streaming": 0.3}
#: Narrower than this (cells), the mascot hides.
MASCOT_MIN_WIDTH = 50
#: ``TERM`` values that get the ASCII mascot under ``auto``.
ASCII_TERMS = frozenset({"linux", "vt100", "dumb"})


def resolve_mascot_style(
    setting: str | None = "auto",
    *,
    encoding: str | None = None,
    term: str | None = None,
) -> str:
    """``blocks``, ``ascii`` or ``off`` for an ``ai.chat_mascot`` setting.

    ``auto`` picks ASCII when the output encoding is not UTF-8 or ``TERM``
    is ``linux``, ``vt100`` or ``dumb``; otherwise blocks.
    """
    setting = (setting or "auto").lower()
    if setting in ("blocks", "ascii", "off"):
        return setting
    if encoding is None:
        stream = getattr(sys, "__stdout__", None) or sys.stdout
        encoding = getattr(stream, "encoding", None) or ""
    if term is None:
        term = os.environ.get("TERM", "")
    if "utf8" not in encoding.lower().replace("-", "").replace("_", ""):
        return "ascii"
    if term.lower() in ASCII_TERMS:
        return "ascii"
    return "blocks"


def configured_mascot_style(config: Any = None) -> str:
    """The configured mascot style (``ai.mascot_style``), resolved.

    ``config`` defaults to ``Toolbox.config``; a missing config means
    ``auto``.
    """
    if config is None:
        try:
            from sandroid.core.toolbox import Toolbox

            config = getattr(Toolbox, "config", None)
        except Exception:
            config = None
    ai = getattr(config, "ai", None)
    setting = getattr(ai, "mascot_style", None)
    if setting is None and ai is not None:
        setting = getattr(ai, "chat_mascot", "auto")
        if not getattr(ai, "show_chat_mascot", True):
            setting = "off"
    return resolve_mascot_style(setting or "auto")


def mascot_frames(
    state: str, style: str = "blocks"
) -> tuple[tuple[str, str, str], ...]:
    """The frame loop of ``state`` in ``style`` (``blocks`` / ``ascii``)."""
    table = ASCII_FRAMES if style == "ascii" else BLOCK_FRAMES
    return table.get(state, table["idle"])


class ChatMascot(Static):
    """The 9x3 chat mascot beside the input; one frame loop per state.

    ``state`` is one of :data:`MASCOT_STATES` (set it with
    :meth:`set_state`). A timer runs only while the state animates (idle
    blink, thinking eye-scan, streaming antennae); tool, approval and error
    are still frames. ``style`` is ``blocks``, ``ascii``, ``off`` or None
    (the configured ``ai.chat_mascot``). Hidden below
    :data:`MASCOT_MIN_WIDTH` cells (:meth:`fit_width`).
    """

    DEFAULT_CSS = """
    ChatMascot {
        width: 9;
        height: 3;
        color: $chat-brand;
        background: transparent;
    }
    ChatMascot.-approval {
        color: $chat-wait;
    }
    ChatMascot.-error {
        color: $lens-bad;
    }
    """

    def __init__(
        self,
        state: str = "idle",
        *,
        style: str | None = None,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__("", name=name, id=id, classes=classes)
        self.style_name = (
            resolve_mascot_style(style) if style else configured_mascot_style()
        )
        self._state = state if state in MASCOT_STATES else "idle"
        self._frame = 0
        self._timer = None
        self._fits = True

    @property
    def state(self) -> str:
        return self._state

    @property
    def animated(self) -> bool:
        """True while a frame timer runs."""
        return self._timer is not None

    def frames(self) -> tuple[tuple[str, str, str], ...]:
        return mascot_frames(self._state, self.style_name)

    def current_frame(self) -> tuple[str, str, str]:
        frames = self.frames()
        return frames[self._frame % len(frames)]

    def on_mount(self) -> None:
        self._apply()

    def set_state(self, state: str) -> None:
        """Switch to ``state`` (unknown states show idle)."""
        state = state if state in MASCOT_STATES else "idle"
        if state == self._state and (
            self._timer is not None or not self._wants_timer()
        ):
            return
        self._state = state
        self._frame = 0
        self._apply()

    def set_style(self, style: str | None = None) -> None:
        """Switch to ``style`` (``None``: re-read the configured one)."""
        resolved = resolve_mascot_style(style) if style else configured_mascot_style()
        if resolved == self.style_name:
            return
        self.style_name = resolved
        self._frame = 0
        self._apply()

    def fit_width(self, width: int) -> None:
        """Hide the mascot when the row it sits in is narrower than 50 cells."""
        self._fits = width >= MASCOT_MIN_WIDTH
        self._apply()

    def _wants_timer(self) -> bool:
        return (
            self.style_name != "off"
            and self._fits
            and len(self.frames()) > 1
            and self._state in MASCOT_INTERVAL
        )

    def _apply(self) -> None:
        for state in MASCOT_STATES:
            self.set_class(state == self._state, f"-{state}")
        visible = self.style_name != "off" and self._fits
        self.display = visible
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        if not self.is_mounted:
            return
        if visible and self._wants_timer():
            self._timer = self.set_interval(MASCOT_INTERVAL[self._state], self._tick)
        self._paint()

    def _tick(self) -> None:
        self._frame += 1
        self._paint()

    def _paint(self) -> None:
        if self.style_name == "off":
            return
        self.update(Content("\n".join(self.current_frame())))


class MascotRow(Horizontal):
    """A ``Horizontal`` that tells its :class:`ChatMascot` children its width."""

    DEFAULT_CSS = """
    MascotRow {
        height: auto;
    }
    MascotRow > ChatMascot {
        dock: right;
        margin: 0 0 0 1;
    }
    """

    def on_resize(self, event) -> None:
        for mascot in self.query_children(ChatMascot):
            mascot.fit_width(event.size.width)


# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------


class ChatHeader(Static):
    """The chat's one-row header (:func:`format_header`), <= 10 refreshes/s.

    Call :meth:`set_fields` with any :func:`format_header` keyword
    (``state``, ``detail``, ``model``, ``remote``, ``experimental``,
    ``used``, ``window``, ``compactions``, ``agents``); unchanged fields
    keep their value.
    """

    DEFAULT_CSS = """
    ChatHeader {
        height: 1;
        width: 1fr;
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }
    """

    #: Minimum seconds between two repaints.
    MIN_INTERVAL = 0.1

    def __init__(self, **kwargs: Any) -> None:
        super().__init__("", **kwargs)
        self.fields: dict[str, Any] = {"state": "idle"}
        self._last_paint = 0.0
        self._pending = None

    def set_fields(self, **fields: Any) -> None:
        """Update header fields; repaints at most every 100 ms."""
        self.fields.update(fields)
        if self._pending is not None:
            return
        wait = self._last_paint + self.MIN_INTERVAL - time.monotonic()
        if wait <= 0 or not self.is_mounted:
            self._paint()
        else:
            self._pending = self.set_timer(wait, self._paint)

    def _paint(self) -> None:
        self._pending = None
        self._last_paint = time.monotonic()
        self.refresh()

    def render(self) -> Content:
        width = self.size.width or 100
        return format_header(width=width, **self.fields)


# --------------------------------------------------------------------------
# Transcript blocks
# --------------------------------------------------------------------------


class TranscriptBlock:
    """Mixin of every transcript block: ``block_key`` and ``turn``.

    :meth:`ChatTranscript.add_block` sets both.
    """

    block_key: str | None = None
    turn: int = 0


class UserBlock(Static, TranscriptBlock):
    """The user's message: a full-width band (``$chat-user-band``)."""

    DEFAULT_CSS = """
    UserBlock {
        width: 1fr;
        height: auto;
        margin: 1 0 1 0;
        padding: 0 1;
        background: $chat-user-band;
        color: $text;
    }
    """

    def __init__(self, text: str, **kwargs: Any) -> None:
        self.text = text
        super().__init__(Content.assemble(("› ", "bold $chat-muted"), text), **kwargs)


class ReplyBlock(Markdown, TranscriptBlock):
    """The assistant's reply, streamed through ``Markdown.get_stream``.

    :meth:`feed` (sync, from an event handler) or :meth:`append_text`
    (async) add a text delta; :meth:`finish` flushes and stops the stream.
    Only this block re-renders while it streams.
    """

    DEFAULT_CSS = """
    ReplyBlock {
        width: 1fr;
        height: auto;
        padding: 0 1;
        margin: 1 0 1 0;
        color: $chat-reply;
        background: transparent;
    }
    ReplyBlock > MarkdownParagraph:last-child {
        margin: 0;
    }
    """

    def __init__(self, text: str = "", **kwargs: Any) -> None:
        super().__init__(text, **kwargs)
        self.text = text
        self._stream = None
        self.finished = False

    def feed(self, delta: str) -> None:
        """Append ``delta`` (schedules :meth:`append_text`)."""
        if delta:
            self.call_later(self.append_text, delta)

    async def append_text(self, delta: str) -> None:
        """Append ``delta`` through the Markdown stream."""
        if not delta or self.finished:
            return
        self.text += delta
        if self._stream is None:
            self._stream = Markdown.get_stream(self)
        await self._stream.write(delta)

    async def finish(self) -> None:
        """Flush the stream; later deltas are ignored."""
        self.finished = True
        if self._stream is not None:
            stream, self._stream = self._stream, None
            await stream.stop()


class ReasoningLine(Static, TranscriptBlock):
    """``Thinking… 3s`` while the model reasons, ``Thought for 4s`` after.

    ``verbose`` shows the reasoning text (fed by :meth:`append`) under the
    line. A one-second timer runs only while thinking.
    """

    DEFAULT_CSS = """
    ReasoningLine {
        width: 1fr;
        height: auto;
        padding: 0 1;
        color: $chat-muted;
        text-style: italic;
    }
    """

    def __init__(
        self, *, verbose: bool = False, started: float | None = None, **kwargs: Any
    ) -> None:
        super().__init__("", **kwargs)
        self.verbose = verbose
        self.started = time.monotonic() if started is None else started
        self.seconds: float | None = None
        self.text = ""
        self._timer = None

    @property
    def running(self) -> bool:
        return self.seconds is None

    def on_mount(self) -> None:
        if self.running:
            self._timer = self.set_interval(1.0, self._paint)
        self._paint()

    def append(self, delta: str) -> None:
        """Add reasoning text (shown only when ``verbose``)."""
        self.text += delta
        if self.verbose:
            self._paint()

    def finish(self, seconds: float | None = None) -> None:
        """Thinking ended (``seconds`` defaults to the time since start)."""
        self.seconds = time.monotonic() - self.started if seconds is None else seconds
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        self._paint()

    def line(self) -> Content:
        if self.running:
            spent = format_elapsed(int(time.monotonic() - self.started))
            head = f"Thinking… {spent}"
        else:
            head = f"Thought for {format_elapsed(round(self.seconds or 0))}"
        if self.verbose and self.text:
            return Content.assemble(head, "\n", (self.text.strip(), "$chat-muted"))
        return Content(head)

    def _paint(self) -> None:
        self.update(self.line())


class ToolBlock(Widget, TranscriptBlock):
    """One tool call: ``Name args`` and, once done, its result chip.

    The name is in the tool colour (bad once the call failed); the line
    under it reads ``running`` until progress or the chip replaces it.
    :meth:`set_result` /
    :meth:`set_error` / :meth:`set_chip` fill the chip line in place.
    Narrower than :data:`ARGS_COMPACT_WIDTH` cells, string args lose their
    quotes; every line is cut with "…" at the block's width.
    """

    DEFAULT_CSS = """
    ToolBlock {
        width: 1fr;
        height: auto;
        padding: 0 1;
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }
    """

    def __init__(
        self,
        name: str,
        args: Mapping[str, Any] | None = None,
        *,
        call_id: str | None = None,
        label: str | None = None,
        running: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.tool_name = name
        self.call_id = call_id
        self.args: dict[str, Any] = dict(args or {})
        self.label = label or humanize_tool_name(name)
        self.chip: Content | None = None
        self.ok: bool | None = None
        #: The analyst's answer to this call's approval (shown above the chip).
        self.decision: Content | None = None
        self.decision_approved: bool | None = None
        #: Live progress of a long call (``classifying 120/412 · 9 matched``),
        #: shown while it runs; replaced by the chip.
        self.progress: Content | None = None
        self.running = running

    def _stop(self) -> None:
        self.running = False

    def set_args(self, args: Mapping[str, Any]) -> None:
        """Replace the shown arguments (e.g. once they finished streaming)."""
        self.args = dict(args)
        self.refresh()

    def set_result(
        self,
        *,
        ref: str | None = None,
        summary: str | None = None,
        elapsed: float | None = None,
    ) -> None:
        """The call succeeded: ``done · R17 · 12 rows · 0.4s``."""
        self.set_chip(
            format_chip(ok=True, ref=ref, summary=summary, elapsed=elapsed), ok=True
        )

    def set_error(
        self,
        code: str | None,
        message: str | None = None,
        *,
        elapsed: float | None = None,
    ) -> None:
        """The call failed: ``code: message``."""
        self.set_chip(
            format_chip(ok=False, code=code, message=message, elapsed=elapsed), ok=False
        )

    def set_decision(
        self, text: str, *, style: str = "$chat-muted", approved: bool = True
    ) -> None:
        """Show the approval answer (``allowed by you``) under the call."""
        self.decision = Content.styled(text, style)
        self.decision_approved = approved
        self.refresh(layout=True)

    def set_chip(self, chip: Content | str, *, ok: bool | None = True) -> None:
        """Any chip line (e.g. ``r2 running · see agents bar``)."""
        self.chip = chip if isinstance(chip, Content) else Content(chip)
        self.ok = ok
        self.progress = None
        self._stop()
        self.refresh(layout=True)

    def set_progress(self, text: str) -> None:
        """Progress of the running call (``classifying 120/412 · 9 matched``).

        Ignored once the call has its chip.
        """
        if self.chip is not None or not text:
            return
        line = format_progress(text)
        grew = self.progress is None
        self.progress = line
        self.refresh(layout=grew)

    def call_line(self, width: int | None = None) -> Content:
        width = width or self.content_size.width or 100
        style = "bold $lens-bad" if self.ok is False else "bold $chat-tool"
        args = format_args(self.args, compact=width < ARGS_COMPACT_WIDTH)
        parts: list[Any] = [(self.label, style)]
        if args.cell_length:
            parts += ["  ", args]
        return Content.assemble(*parts)

    def render(self) -> Content:
        lines = [self.call_line()]
        if self.decision is not None:
            lines.append(Content.assemble("  ", self.decision))
        if self.chip is not None:
            lines.append(Content.assemble("  ", self.chip))
        elif self.progress is not None:
            lines.append(Content.assemble("  ", self.progress))
        elif self.running:
            lines.append(Content.assemble("  ", ("running", "$lens-accent")))
        return Content("\n").join(lines)

    def get_content_height(self, container, viewport, width: int) -> int:
        return (
            1
            + (self.decision is not None)
            + (self.chip is not None or self.progress is not None or bool(self.running))
        )


class AgentCard(Widget, TranscriptBlock, can_focus=True):
    """A subagent's card: round border, status title, summary and claims.

    Title ``researcher r2 · done · 38s · 9.2k tok``; each claim is a
    bullet with its evidence R-ids right-aligned as chips. Enter (or a
    click) posts :class:`AgentCard.Open`.
    """

    DEFAULT_CSS = """
    AgentCard {
        width: 1fr;
        height: auto;
        margin: 0 0 1 0;
        padding: 0 1;
        border: round $lens-rule;
        border-title-color: $text;
        border-subtitle-color: $lens-dim;
    }
    AgentCard:focus {
        border: round $lens-rule-focus;
    }
    """

    BINDINGS = [Binding("enter", "open", "Open agent", show=False)]

    class Open(Message):
        """The user wants this agent's transcript."""

        def __init__(self, card: AgentCard) -> None:
            super().__init__()
            self.card = card

        @property
        def agent_id(self) -> str:
            return self.card.agent_id

    def __init__(
        self,
        agent_id: str,
        role: str,
        *,
        status: str = "running",
        elapsed: float | None = None,
        tokens: int | None = None,
        summary: str = "",
        claims: Sequence[tuple[str, Sequence[str]]] = (),
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.agent_id = agent_id
        self.role = role
        self.status = status
        self.elapsed = elapsed
        self.tokens = tokens
        self.summary = summary
        self.claims: list[tuple[str, list[str]]] = [(t, list(r)) for t, r in claims]
        self.border_subtitle = "Enter open"
        self._sync_title()

    def update_card(self, **fields: Any) -> None:
        """Change any of ``status``, ``elapsed``, ``tokens``, ``summary``, ``claims``."""
        changed = False
        for key in ("status", "elapsed", "tokens", "summary"):
            if key in fields and getattr(self, key) != fields[key]:
                setattr(self, key, fields[key])
                changed = True
        if "claims" in fields:
            claims = [(t, list(r)) for t, r in fields["claims"]]
            changed = changed or claims != self.claims
            self.claims = claims
        if not changed:
            return
        self._sync_title()
        self.refresh(layout=True)

    def _sync_title(self) -> None:
        self.border_title = format_card_title(
            self.role,
            self.agent_id,
            self.status,
            elapsed=self.elapsed,
            tokens=self.tokens,
        )

    def body(self, width: int) -> Content:
        lines: list[Content] = []
        if self.summary:
            lines.append(Content(self.summary))
        for text, refs in self.claims:
            chips = Content.assemble(
                *[
                    part
                    for i, ref in enumerate(refs)
                    for part in (("  " if i else ""), (ref, "bold $lens-accent"))
                ]
            )
            room = max(4, width - chips.cell_length - 1)
            bullet = Content(f"• {text}")
            if bullet.cell_length > room:
                bullet = bullet.truncate(room, ellipsis=True)
            gap = max(1, width - bullet.cell_length - chips.cell_length)
            lines.append(Content.assemble(bullet, " " * gap, chips))
        if not lines:
            return Content.styled("working…", "$chat-muted")
        return Content("\n").join(lines)

    def render(self) -> Content:
        return self.body(self.content_size.width or 80)

    def action_open(self) -> None:
        self.post_message(self.Open(self))

    def on_click(self) -> None:
        self.post_message(self.Open(self))


class CompactionRule(Static, TranscriptBlock):
    """``──── compacted · 182k → 41k · 14 results masked ────``."""

    DEFAULT_CSS = """
    CompactionRule {
        width: 1fr;
        height: 1;
        margin: 0 0 1 0;
    }
    """

    def __init__(self, before: int, after: int, masked: int = 0, **kwargs: Any) -> None:
        super().__init__("", **kwargs)
        self.label = format_compaction(before, after, masked)

    def render(self) -> Content:
        return ruled(self.label, self.size.width or 80)


class NoticeLine(Static, TranscriptBlock):
    """A one-line notice updated in place (``Retrying in 4s · attempt 2/5``)."""

    DEFAULT_CSS = """
    NoticeLine {
        width: 1fr;
        height: auto;
        padding: 0 1;
    }
    """

    def __init__(
        self, text: str = "", *, style: str = "$lens-warn", **kwargs: Any
    ) -> None:
        super().__init__("", **kwargs)
        self.text = text
        self.notice_style = style
        self._sync()

    def set_notice(self, text: str, *, style: str | None = None) -> None:
        """Replace the notice text (and its style)."""
        self.text = text
        if style is not None:
            self.notice_style = style
        self._sync()

    def _sync(self) -> None:
        self.update(Content.styled(self.text, self.notice_style))


class BudgetNotice(Horizontal, TranscriptBlock):
    """``Round budget used (25/25)   [Continue] [Stop]``.

    The buttons post :class:`BudgetNotice.Continue` / :class:`BudgetNotice.Stop`
    (``notice.grant`` = the extra rounds offered) and the notice collapses
    to one line saying what was chosen.
    """

    DEFAULT_CSS = """
    BudgetNotice {
        width: 1fr;
        height: auto;
        padding: 0 1;
    }
    BudgetNotice > #budget-text {
        width: 1fr;
        color: $lens-warn;
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }
    BudgetNotice > Button {
        width: auto;
        min-width: 0;
        margin: 0 0 0 2;
    }
    """

    class Continue(Message):
        """Grant ``notice.grant`` more rounds and continue."""

        def __init__(self, notice: BudgetNotice) -> None:
            super().__init__()
            self.notice = notice

    class Stop(Message):
        """End the turn here."""

        def __init__(self, notice: BudgetNotice) -> None:
            super().__init__()
            self.notice = notice

    def __init__(
        self, used: int, budget: int, *, grant: int | None = None, **kwargs: Any
    ) -> None:
        super().__init__(**kwargs)
        self.used = used
        self.budget = budget
        self.grant = grant
        self.choice: str | None = None

    def _text(self) -> str:
        text = f"Round budget used ({self.used}/{self.budget})"
        if self.choice == "continue":
            text += f" · continued (+{self.grant})" if self.grant else " · continued"
        elif self.choice == "stop":
            text += " · stopped"
        return text

    def compose(self) -> ComposeResult:
        yield Static(self._text(), id="budget-text")
        label = f"Continue (+{self.grant})" if self.grant else "Continue"
        yield Button(label, id="budget-continue", compact=True, variant="primary")
        yield Button("Stop", id="budget-stop", compact=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if self.choice is not None:
            return
        if event.button.id == "budget-continue":
            self.resolve("continue")
            self.post_message(self.Continue(self))
        elif event.button.id == "budget-stop":
            self.resolve("stop")
            self.post_message(self.Stop(self))

    def resolve(self, choice: str) -> None:
        """Collapse to one line (``continue`` / ``stop``); no message."""
        self.choice = choice
        for button in self.query(Button):
            button.display = False
        try:
            self.query_one("#budget-text", Static).update(self._text())
        except Exception:
            pass


class FoldMarker(Static):
    """``N earlier turns`` at the top of a capped transcript."""

    DEFAULT_CSS = """
    FoldMarker {
        width: 1fr;
        height: 1;
        padding: 0 1;
        color: $chat-muted;
    }
    FoldMarker:hover {
        color: $lens-accent;
    }
    """


class ChatTranscript(VerticalScroll):
    """The scrolling transcript: one widget per block, newest last.

    :meth:`add_block` mounts a block (a :class:`UserBlock` starts a new
    turn) and remembers it under ``key`` (turn / call / agent id) for
    :meth:`block`. Past :data:`MAX_BLOCKS` mounted blocks the oldest whole
    turns are removed and counted in "N earlier turns"; clicking that
    line posts :class:`ChatTranscript.EarlierTurnsRequested`. The view
    stays anchored to the end while the user has not scrolled up.
    """

    DEFAULT_CSS = """
    ChatTranscript {
        width: 1fr;
        height: 1fr;
        background: $lens-bg;
        scrollbar-size-vertical: 1;
    }
    """

    class EarlierTurnsRequested(Message):
        """The user clicked "N earlier turns"."""

        def __init__(self, folded_turns: int) -> None:
            super().__init__()
            self.folded_turns = folded_turns

    def __init__(
        self, *children: Widget, max_blocks: int | None = None, **kwargs: Any
    ) -> None:
        super().__init__(*children, **kwargs)
        self.max_blocks = max_blocks or MAX_BLOCKS
        self.folded_turns = 0
        self._turn = 0
        self._by_key: dict[str, Widget] = {}
        self._blocks: list[Widget] = list(children)
        self._fold: FoldMarker | None = None

    def _maybe_anchor(self) -> None:
        """Anchor to the end once the blocks overflow the view.

        Not before: an anchored, not yet full view bottom-aligns its blocks;
        the transcript should start at the top (the egress notice).
        """
        if not self.is_anchored and self.max_scroll_y > 0:
            self.anchor()

    @property
    def current_turn(self) -> int:
        return self._turn

    @property
    def blocks(self) -> list[Widget]:
        """The mounted blocks, oldest first (without the fold line)."""
        return list(self._blocks)

    def block(self, key: str) -> Widget | None:
        """The block added under ``key`` (None if unknown or folded away)."""
        return self._by_key.get(key)

    def add_block(
        self, block: Widget, *, key: str | None = None, turn: int | None = None
    ) -> Widget:
        """Mount ``block`` at the end; returns it."""
        if turn is None:
            if isinstance(block, UserBlock):
                self._turn += 1
            turn = self._turn
        else:
            self._turn = max(self._turn, turn)
        block.turn = turn  # type: ignore[attr-defined]
        if key is not None:
            block.block_key = key  # type: ignore[attr-defined]
            self._by_key[key] = block
        self._blocks.append(block)
        self.mount(block)
        self._enforce_cap()
        self.call_after_refresh(self._maybe_anchor)
        return block

    def clear_blocks(self) -> None:
        """Remove every block (a new conversation)."""
        self.anchor(False)
        self.remove_children()
        self._blocks.clear()
        self._by_key.clear()
        self._fold = None
        self.folded_turns = 0
        self._turn = 0

    def _enforce_cap(self) -> None:
        blocks = self._blocks
        excess = len(blocks) - self.max_blocks
        if excess <= 0:
            return
        doomed: list[Widget] = []
        newest_turn = getattr(blocks[-1], "turn", 0)
        index = 0
        while excess > 0 and index < len(blocks):
            turn = getattr(blocks[index], "turn", 0)
            group = []
            while index < len(blocks) and getattr(blocks[index], "turn", 0) == turn:
                group.append(blocks[index])
                index += 1
            if turn == newest_turn:
                # One huge turn: drop its oldest blocks only.
                index -= len(group)
                group = group[:excess]
                index += len(group)
            else:
                self.folded_turns += 1
            doomed += group
            excess -= len(group)
        gone = set(doomed)
        self._blocks = [w for w in blocks if w not in gone]
        for widget in doomed:
            key = getattr(widget, "block_key", None)
            if key is not None and self._by_key.get(key) is widget:
                del self._by_key[key]
        self.remove_children(doomed)
        self._sync_fold()

    def _sync_fold(self) -> None:
        if not self.folded_turns:
            return
        plural = "s" if self.folded_turns != 1 else ""
        text = f"{self.folded_turns} earlier turn{plural}"
        if self._fold is None:
            self._fold = FoldMarker(text)
            first = self._blocks[0] if self._blocks else None
            if first is not None:
                self.mount(self._fold, before=first)
            else:
                self.mount(self._fold)
        else:
            self._fold.update(text)

    def on_click(self, event) -> None:
        if isinstance(event.widget, FoldMarker):
            self.post_message(self.EarlierTurnsRequested(self.folded_turns))


# --------------------------------------------------------------------------
# Empty state
# --------------------------------------------------------------------------

#: Example prompts in the empty state.
EXAMPLE_PROMPTS = (
    "What is the spotlight app sending over the network?",
    "Diff its files against the last snapshot",
    "Spawn a researcher to check these hosts against trackers",
)
#: Slash commands in the empty state (the first four at narrow widths).
SLASH_COMMANDS = (
    "/new",
    "/threads",
    "/compact",
    "/context",
    "/permissions",
    "/agents",
    "/doctor",
)
_NARROW_COMMANDS = ("/new", "/threads", "/context", "/agents")


def format_empty_state(
    width: int,
    *,
    model: str | None = None,
    endpoint: str | None = None,
    remote: bool = False,
    experimental: bool = True,
    egress: str | None = "Device and app data you discuss is sent to this endpoint.",
    examples: Iterable[str] = EXAMPLE_PROMPTS,
    mascot_style: str = "blocks",
) -> Content:
    """The empty transcript: mascot in its tray, model, egress, examples."""

    def center(text: str, style: str = "") -> Content:
        pad = max(0, (width - cell_len(text)) // 2)
        return Content.assemble(" " * pad, (text, style))

    lines: list[Content] = [Content("")]
    if mascot_style != "off":
        head = mascot_frames("idle", mascot_style)[0]
        for row in (*head, MASCOT_TRAY.get(mascot_style, MASCOT_TRAY["blocks"])):
            lines.append(center(row, "$chat-brand"))
        lines.append(Content(""))
    title = "Sandroid AI · experimental" if experimental else "Sandroid AI"
    lines.append(center(title, "bold $lens-accent"))
    target = " @ ".join(p for p in (model, endpoint) if p)
    if remote:
        target = f"{target} · REMOTE" if target else "REMOTE"
    if target:
        lines.append(center(target, "$chat-muted"))
    lines.append(Content(""))
    if egress:
        lines.append(Content.assemble(" ", (egress, "$lens-warn")))
        lines.append(Content(""))
    examples = list(examples)
    if examples:
        lines.append(Content.styled(" Try", "bold"))
        for example in examples:
            line = Content.assemble("   ", ("› ", "$chat-muted"), example)
            lines.append(line.truncate(max(1, width), ellipsis=True))
        lines.append(Content(""))
    wide = "  ".join(SLASH_COMMANDS)
    if cell_len(wide) + 1 <= width:
        lines.append(Content.styled(" " + wide, "$chat-muted"))
    else:
        lines.append(
            Content.styled(
                " " + " ".join(_NARROW_COMMANDS) + "  · / for all", "$chat-muted"
            )
        )
    return Content("\n").join(lines)


class EmptyState(Static):
    """The transcript before the first message (:func:`format_empty_state`)."""

    DEFAULT_CSS = """
    EmptyState {
        width: 1fr;
        height: auto;
    }
    """

    def __init__(
        self,
        *,
        model: str | None = None,
        endpoint: str | None = None,
        remote: bool = False,
        experimental: bool = True,
        egress: (
            str | None
        ) = "Device and app data you discuss is sent to this endpoint.",
        examples: Iterable[str] = EXAMPLE_PROMPTS,
        mascot_style: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__("", **kwargs)
        self.options: dict[str, Any] = {
            "model": model,
            "endpoint": endpoint,
            "remote": remote,
            "experimental": experimental,
            "egress": egress,
            "examples": tuple(examples),
            "mascot_style": (
                resolve_mascot_style(mascot_style)
                if mascot_style
                else configured_mascot_style()
            ),
        }

    def render(self) -> Content:
        width = self.size.width or 80
        options = dict(self.options)
        if width < MASCOT_MIN_WIDTH:
            options["mascot_style"] = "off"
        return format_empty_state(width, **options)


__all__ = [
    "AGENT_STATUS",
    "ASCII_FRAMES",
    "BLOCK_FRAMES",
    "CHIP_CODE_WORDS",
    "CHIP_WARN_CODES",
    "EXAMPLE_PROMPTS",
    "HEADER_STATES",
    "MASCOT_STATES",
    "MAX_BLOCKS",
    "SLASH_COMMANDS",
    "AgentCard",
    "BudgetNotice",
    "ChatHeader",
    "ChatMascot",
    "ChatTranscript",
    "CompactionRule",
    "EmptyState",
    "FoldMarker",
    "MascotRow",
    "NoticeLine",
    "ReasoningLine",
    "ReplyBlock",
    "ToolBlock",
    "TranscriptBlock",
    "UserBlock",
    "configured_mascot_style",
    "format_args",
    "format_card_title",
    "format_chip",
    "format_compaction",
    "format_elapsed",
    "format_empty_state",
    "format_header",
    "format_meter",
    "format_progress",
    "format_retry",
    "format_tokens",
    "humanize_tool_name",
    "mascot_frames",
    "meter_style",
    "progress_text",
    "resolve_mascot_style",
    "ruled",
]
