"""AI chat panel: renders the agent runtime's events and forwards input.

The chat dock's content (``docs/development/ai_foundations.rst`` §3.10, §6).
The panel owns no conversation state: an orchestrator
:class:`~sandroid.ai.session.AgentSession` (opened on the first message)
holds the messages, runs the turns on its own worker thread and reports
everything as :class:`~sandroid.ai.loop.AgentEvent` objects to
:meth:`ChatPanel._sink`. The panel turns those events into the blocks of
:mod:`sandroid.tui.widgets.chat_view` and forwards input, approvals and slash
commands back to the session, the approval broker and the agent manager.

**Event sink.** The sink runs on whatever thread emits (the turn worker, an
agent thread, a tool thread, sometimes the UI thread itself), so it only
appends to a queue and posts one :class:`ChatPanel.EventsReady` message
(``post_message`` is thread-safe and never blocks; ``call_from_thread`` would
block the worker and raises on the UI thread). The handler drains the queue at
most every :data:`DRAIN_INTERVAL_S` (about 20 Hz) and merges consecutive text
and reasoning deltas, so a fast stream costs a few repaints per second.

**Approvals.** An ``approval_request`` event pins a
:class:`~sandroid.tui.widgets.tool_permission_prompt.ToolPermissionPrompt`
above the input (one at a time, FIFO); the answer goes to
``get_approval_broker().resolve``. The matching ``approval_resolved`` event
collapses it into one transcript line.

**Keys.** Enter sends; ``/`` starts a slash command (``/new``, ``/threads``,
``/compact``, ``/context``, ``/permissions``, ``/agents``, ``/doctor``);
Ctrl+X stops the turn and its agents; Ctrl+L opens a new thread (refused while
a turn runs); Up moves to the agents bar, where Left/Right select and Enter
opens an agent's transcript.

Widget ids kept for the dock and the themes: ``#chat-header``, ``#chat-log``
(the :class:`~sandroid.tui.widgets.chat_view.ChatTranscript`), ``#chat-input``
and ``#chat-mascot``. :meth:`ChatPanel.refresh_header` is public (the dock and
the settings screen call it).
"""

from __future__ import annotations

import contextlib
import json
import logging
import threading
import time
from collections import deque
from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING, Any

from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.content import Content
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Button, Input, Label, OptionList, Static
from textual.widgets.option_list import Option

from sandroid.ai.agents import get_agent_manager, orchestrator_extra_tools
from sandroid.ai.errors import AIClientError
from sandroid.ai.loop import ORCHESTRATOR_ID
from sandroid.ai.prompts import ORCHESTRATOR_AGENTS_ADDENDUM, ORCHESTRATOR_PROMPT_V2
from sandroid.ai.safety import egress_notice_lines, get_ai_settings, redact_secrets
from sandroid.ai.session import (
    AUTO_ROOT,
    AgentSession,
    ConversationStore,
    SessionBusyError,
    build_session_client,
    list_threads,
)
from sandroid.ai.tool_permissions import (
    ALLOW_ALL_NOTICE,
    get_approval_broker,
    get_tool_permission_store,
)
from sandroid.tui.modals.base import ForensicModal, KeyHintFooter
from sandroid.tui.widgets.chat_view import (
    AGENT_STATUS,
    AgentCard,
    BudgetNotice,
    ChatHeader,
    ChatMascot,
    ChatTranscript,
    CompactionRule,
    EmptyState,
    MascotRow,
    NoticeLine,
    ReasoningLine,
    ReplyBlock,
    ToolBlock,
    UserBlock,
    configured_mascot_style,
    format_args,
    format_elapsed,
    format_retry,
    format_tokens,
    humanize_tool_name,
)
from sandroid.tui.widgets.tool_permission_prompt import ToolPermissionPrompt

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from textual.app import ComposeResult

    from sandroid.ai.loop import AgentEvent
    from sandroid.ai.tool_permissions import Decision

logger = logging.getLogger(__name__)

#: The orchestrator's system prompt (the session appends the toolset catalogue).
SYSTEM_PROMPT = f"{ORCHESTRATOR_PROMPT_V2}\n\n{ORCHESTRATOR_AGENTS_ADDENDUM}"

#: Shortest gap between two drains of the event queue (about 20 Hz).
DRAIN_INTERVAL_S = 0.05

#: Period of the housekeeping timer (agents bar, leases, stale prompts).
TICK_S = 1.0

#: Slash commands and their one-line help (the "/" hint list).
SLASH_HELP: dict[str, str] = {
    "/new": "close this thread and start a new one (Ctrl+L)",
    "/threads": "earlier threads; /threads <n> resumes one",
    "/compact": "summarise older history now; /compact <focus>",
    "/context": "what fills the context window",
    "/permissions": "approval mode and rules; /permissions allow_all | ask",
    "/agents": "subagents of this thread; /agents <n|id> opens one",
    "/doctor": "check the AI endpoint",
}

#: Header state -> mascot state.
_MASCOT_FOR_STATE = {
    "idle": "idle",
    "off": "idle",
    "thinking": "thinking",
    "compacting": "thinking",
    "retrying": "thinking",
    "streaming": "streaming",
    "tool": "tool",
    "approval": "approval",
    "error": "error",
}

#: ``/context`` rows: breakdown key -> label.
_CONTEXT_ROWS = (
    ("system", "System prompt"),
    ("tools_schema", "Tools schema"),
    ("ambient", "Live state"),
    ("history", "Conversation"),
    ("tool_results", "Tool results"),
    ("summaries", "Summaries"),
    ("reasoning", "Reasoning"),
)


# =============================================================================
# Session factory (patched by tests)
# =============================================================================


def open_orchestrator_session(
    *, sink: Callable[[AgentEvent], None], thread_id: str | None = None
) -> AgentSession:
    """Open (or resume) the orchestrator's thread in the current session root.

    The client is wrapped by the agent manager's gateway (the orchestrator's
    reserved slot); the agent tools are part of the fixed tools array.

    Raises:
        AIClientError: The egress policy refuses the endpoint.
        FileNotFoundError: Unknown *thread_id* (resume).
    """
    manager = get_agent_manager()
    client = manager.gateway_client(build_session_client(), reserved=True)
    kwargs: dict[str, Any] = {
        "root": AUTO_ROOT,
        "client": client,
        "extra_tools": orchestrator_extra_tools(),
        "system_prompt": SYSTEM_PROMPT,
        "sink": sink,
    }
    if thread_id:
        session = AgentSession.resume(thread_id, **kwargs)
    else:
        session = AgentSession.open_new(**kwargs)
    manager.attach_parent(session)
    return session


# =============================================================================
# Pure formatters
# =============================================================================


def card_status(status: str | None) -> str:
    """Agent status -> :data:`~sandroid.tui.widgets.chat_view.AGENT_STATUS` key."""
    return {"complete": "done", "budget_exhausted": "partial"}.get(
        status or "", status or "running"
    )


def agent_tokens(usage: dict | None) -> int | None:
    """Prompt + completion tokens of an agent's usage dict."""
    if not usage:
        return None
    return int(usage.get("prompt_tokens", 0)) + int(usage.get("completion_tokens", 0))


def card_claims(result: dict | None) -> list[tuple[str, list[str]]]:
    """``AgentResult.claims`` as ``(text, evidence ids)`` pairs."""
    claims = []
    for claim in (result or {}).get("claims") or []:
        if isinstance(claim, dict):
            evidence = [str(e) for e in claim.get("evidence") or []]
            claims.append((str(claim.get("text", "")), evidence))
    return claims


def egress_banner_lines(settings: Any, mode: str) -> list[str]:
    """The data-egress notice, with the approval mode's line for *mode*."""
    lines = [line for line in egress_notice_lines(settings) if line]
    if mode == "allow_all" and settings.is_configured:
        lines = [ln for ln in lines if not ln.startswith("Device-changing tools")]
        lines.append(f"Approval mode allow_all: {ALLOW_ALL_NOTICE}.")
    return lines


def format_banner(settings: Any, mode: str) -> Content:
    """The banner at the top of the transcript (theme variables only)."""
    lines = egress_banner_lines(settings, mode)
    if not settings.is_configured:
        body = "$chat-muted"
    elif settings.is_ready:
        body = "$lens-warn"
    else:
        body = "$lens-bad"
    parts: list[Any] = [("⚠ " + lines[0], "bold $lens-warn")]
    for line in lines[1:]:
        style = "bold $lens-bad" if line.startswith("Approval mode") else body
        parts += ["\n", ("  " + line, style)]
    return Content.assemble(*parts)


def unwrap_call(name: str, args: Any) -> tuple[str, dict]:
    """Show a ``call_tool`` call as the tool it calls."""
    if not isinstance(args, dict):
        args = {}
    if name == "call_tool" and isinstance(args.get("name"), str):
        inner = args.get("arguments")
        if isinstance(inner, str):
            with contextlib.suppress(ValueError):
                inner = json.loads(inner)
        return args["name"], inner if isinstance(inner, dict) else {}
    return name, args


def _parse_args(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def format_when(stamp: str | None) -> str:
    """ISO timestamp -> ``2026-11-19 14:03`` (local time)."""
    if not stamp:
        return "?"
    try:
        return datetime.fromisoformat(stamp).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return str(stamp)[:16]


def format_thread_row(index: int, entry: dict, *, current: str | None = None) -> str:
    """``1. title · 2026-11-19 14:03 · 3 turns``."""
    title = entry.get("title") or "(untitled)"
    turns = int(entry.get("turns") or 0)
    text = (
        f"{index}. {title} · {format_when(entry.get('updated'))} · "
        f"{turns} turn{'s' if turns != 1 else ''}"
    )
    if current and entry.get("thread_id") == current:
        text += " · current"
    return text


def format_context(session: Any, agents_usage: dict | None = None) -> str:
    """The ``/context`` table: breakdown, meter and totals."""
    meter = session.meter
    used, window = int(meter.used or 0), int(meter.window or 0)
    pct = round(100 * used / window) if window else 0
    lines = [f"Context · {format_tokens(used)}/{format_tokens(window)} ({pct}%)"]
    breakdown = session.context_breakdown()
    width = max(len(label) for _, label in _CONTEXT_ROWS)
    for key, label in _CONTEXT_ROWS:
        value = breakdown.get(key, 0)
        lines.append(f"  {label:<{width}}  {format_tokens(value):>6}")
    last = getattr(meter, "last_prompt_tokens", None)
    if last is not None:
        lines.append(f"  {'Last request':<{width}}  {format_tokens(last):>6}")
    limit = getattr(meter, "input_limit", None)
    if limit:
        lines.append(f"  {'Input limit':<{width}}  {format_tokens(limit):>6}")
    totals = getattr(session, "totals", {}) or {}
    lines.append(
        f"Session · {format_tokens(totals.get('prompt_tokens', 0))} in · "
        f"{format_tokens(totals.get('completion_tokens', 0))} out · "
        f"{totals.get('requests', 0)} requests"
    )
    if agents_usage:
        lines.append(
            f"Agents · {format_tokens(agents_usage.get('prompt_tokens', 0))} in · "
            f"{format_tokens(agents_usage.get('completion_tokens', 0))} out"
        )
    return "\n".join(lines)


def format_permissions(store: Any) -> str:
    """The ``/permissions`` view."""
    mode = store.mode
    lines = [f"Approval mode: {mode}"]
    if store.session_mode is not None:
        lines[0] += f" (this session; file: {store.file_mode})"
    if mode == "allow_all":
        lines.append(f"  {ALLOW_ALL_NOTICE}")
    allow, deny = store.allow_rules(), store.deny_rules()
    lines.append("Allow: " + (", ".join(allow) if allow else "(none)"))
    lines.append("Deny: " + (", ".join(deny) if deny else "(none)"))
    declines = store.legacy_declines()
    if declines:
        lines.append("Previous declines (not enforced): " + ", ".join(declines))
    for warning in store.warnings():
        lines.append(f"! {warning}")
    if store.load_error:
        lines.append(f"! {store.load_error}")
    lines.append(f"Rules file: {store.path}")
    lines.append("/permissions allow_all · /permissions ask (this session only)")
    return "\n".join(lines)


def format_agent_row(index: int, row: dict) -> str:
    """``1. researcher a-re-3f9c2k · ✓ done · 38s · 9.2k tok · <title>``."""
    status = card_status(row.get("status"))
    label = AGENT_STATUS.get(status, (status, ""))[0]
    parts = [f"{index}. {row.get('profile')} {row.get('agent_id')}", label]
    elapsed = format_elapsed(row.get("elapsed_s"))
    if elapsed:
        parts.append(elapsed)
    tokens = agent_tokens(row.get("usage"))
    if tokens:
        parts.append(f"{format_tokens(tokens)} tok")
    if row.get("title"):
        parts.append(str(row["title"]))
    return " · ".join(parts)


def render_agent_transcript(
    events: Iterable[AgentEvent] = (), records: Iterable[dict] = ()
) -> str:
    """Plain-text transcript of a subagent (live events, else its file)."""
    lines: list[str] = []
    text = ""

    def flush() -> None:
        nonlocal text
        if text.strip():
            lines.append(text.strip())
        text = ""

    events = list(events)
    if events:
        thinking = False
        for ev in events:
            p = ev.payload or {}
            if ev.type == "reasoning_delta":
                if not thinking:
                    flush()
                    lines.append("✧ thinking…")
                    thinking = True
                continue
            thinking = thinking and ev.type not in ("text_delta", "tool_call")
            if ev.type == "text_delta":
                text += str(p.get("text", ""))
            elif ev.type == "tool_call":
                flush()
                name, args = unwrap_call(str(p.get("name", "")), p.get("args"))
                shown = format_args(args).plain
                lines.append(f"● {humanize_tool_name(name)}  {shown}".rstrip())
            elif ev.type == "tool_result":
                ok = p.get("status") == "ok"
                bits = [p.get("result_id"), p.get("summary")]
                if not ok:
                    bits = [p.get("error_code") or p.get("status"), p.get("summary")]
                shown = " · ".join(str(b) for b in bits if b)
                lines.append(f"  └ {'✓' if ok else '✗'} {shown}".rstrip())
            elif ev.type == "error":
                flush()
                lines.append(f"✗ {p.get('message') or p.get('kind')}")
            elif ev.type == "turn_end":
                flush()
                lines.append(f"── turn {p.get('reason')} · {p.get('rounds', 0)} rounds")
        flush()
        return "\n".join(lines)
    for rec in records:
        if rec.get("type") != "msg":
            continue
        role = rec.get("role")
        if role == "user" and not rec.get("runtime"):
            lines.append(f"› {rec.get('text') or rec.get('content') or ''}".rstrip())
        elif role == "assistant":
            if rec.get("content"):
                lines.append(str(rec["content"]).strip())
            for call in rec.get("tool_calls") or []:
                fn = (call or {}).get("function") or {}
                name, args = unwrap_call(
                    str(fn.get("name", "")), _parse_args(fn.get("arguments"))
                )
                shown = format_args(args).plain
                lines.append(f"● {humanize_tool_name(name)}  {shown}".rstrip())
        elif role == "tool":
            ok = rec.get("status", "ok") == "ok"
            shown = rec.get("result_id") or rec.get("status") or ""
            lines.append(f"  └ {'✓' if ok else '✗'} {shown}".rstrip())
    return "\n".join(lines)


def coalesce_events(events: Iterable[AgentEvent]) -> list[AgentEvent]:
    """Merge runs of text / reasoning deltas of one agent into one event."""
    out: list[AgentEvent] = []
    for ev in events:
        if (
            out
            and ev.type in ("text_delta", "reasoning_delta")
            and out[-1].type == ev.type
            and out[-1].agent_id == ev.agent_id
            and out[-1].turn_id == ev.turn_id
        ):
            prev = out[-1]
            text = str(prev.payload.get("text", "")) + str(ev.payload.get("text", ""))
            out[-1] = replace(prev, payload={**prev.payload, "text": text})
        else:
            out.append(ev)
    return out


# =============================================================================
# Widgets
# =============================================================================


class AgentsBar(Static, can_focus=True):
    """One line under the transcript: the thread's subagents.

    Left/Right select, Enter (or a click) posts :class:`AgentsBar.Open`,
    Down returns to the input. Hidden while the thread has no agents.
    """

    DEFAULT_CSS = """
    AgentsBar {
        height: 1;
        width: 1fr;
        padding: 0 1;
        color: $chat-muted;
        text-wrap: nowrap;
        text-overflow: ellipsis;
        display: none;
    }
    AgentsBar:focus {
        background: $lens-cursor-focus;
    }
    """

    BINDINGS = [
        Binding("enter", "open", "Open agent", show=False),
        Binding("left", "move(-1)", "Previous agent", show=False),
        Binding("right", "move(1)", "Next agent", show=False),
        Binding("down", "leave", "Back to the input", show=False),
    ]

    class Open(Message):
        """The user wants this agent's transcript."""

        def __init__(self, agent_id: str) -> None:
            super().__init__()
            self.agent_id = agent_id

    class Leave(Message):
        """Focus should go back to the chat input."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__("", **kwargs)
        self.rows: list[dict] = []
        self.selected = 0

    def set_rows(self, rows: list[dict]) -> None:
        """Show *rows* (``AgentManager.list`` snapshots, newest first)."""
        self.rows = list(rows)
        self.selected = max(0, min(self.selected, len(self.rows) - 1))
        self.display = bool(self.rows)
        self.refresh()

    @property
    def selected_id(self) -> str | None:
        if not self.rows:
            return None
        return str(self.rows[self.selected].get("agent_id"))

    def render(self) -> Content:
        parts: list[Any] = [("◆ ", "$chat-tool")]
        for index, row in enumerate(self.rows):
            if index:
                parts.append("   ")
            status = card_status(row.get("status"))
            label, style = AGENT_STATUS.get(status, (status, "$chat-muted"))
            text = f"{row.get('profile')} {row.get('agent_id')} · {label}"
            elapsed = format_elapsed(row.get("elapsed_s"))
            if elapsed and status in ("running", "queued"):
                text += f" {elapsed}"
            if self.has_focus and index == self.selected:
                parts.append((text, "reverse bold"))
            else:
                parts.append((text, style))
        hint = "  ←→ select · ⏎ open" if self.has_focus else "  ↑ select"
        parts.append((hint, "$chat-muted"))
        return Content.assemble(*parts)

    def on_focus(self) -> None:
        self.refresh()

    def on_blur(self) -> None:
        self.refresh()

    def action_move(self, delta: int) -> None:
        if self.rows:
            self.selected = (self.selected + delta) % len(self.rows)
            self.refresh()

    def action_open(self) -> None:
        agent_id = self.selected_id
        if agent_id:
            self.post_message(self.Open(agent_id))

    def action_leave(self) -> None:
        self.post_message(self.Leave())

    def on_click(self) -> None:
        self.action_open()


class AgentTranscriptModal(ForensicModal[None]):
    """A subagent's transcript, live, with cancel and send-message.

    Live events come from :meth:`AgentManager.transcript_events` (deltas
    included) and a manager listener; an agent known only from disk shows its
    ``transcript.jsonl``. Esc closes (sync ``action_cancel``).
    """

    ENTER_SUBMITS_FROM_INPUT = False
    AUTO_FOCUS = "#agent-message"

    DEFAULT_CSS = """
    AgentTranscriptModal .modal-container {
        width: 110;
        max-width: 95%;
        max-height: 90%;
    }
    AgentTranscriptModal #agent-meta {
        color: $lens-dim;
        margin-bottom: 1;
    }
    AgentTranscriptModal #agent-transcript-scroll {
        height: auto;
        max-height: 26;
        margin-bottom: 1;
        background: $lens-bg;
    }
    AgentTranscriptModal #agent-transcript {
        padding: 0 1;
    }
    """

    #: Shortest gap between two re-renders while events stream in.
    REFRESH_S = 0.25

    class Changed(Message):
        """New events for this agent (posted from agent threads)."""

        bubble = False

    def __init__(
        self,
        agent_id: str,
        *,
        parent: Any = None,
        manager: Any = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.agent_id = agent_id
        self.parent_session = parent
        self.manager = manager or get_agent_manager()
        self._remove_listener: Callable[[], None] | None = None
        self._pending = False
        self._lock = threading.Lock()
        self._timer = None

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label(f"◆ Agent {self.agent_id}", classes="modal-title")
            yield Static("", id="agent-meta")
            with VerticalScroll(id="agent-transcript-scroll"):
                yield Static("", id="agent-transcript")
            yield Input(
                placeholder="Message this agent (Enter sends)", id="agent-message"
            )
            with Horizontal(classes="button-row"):
                yield Button("Cancel agent", id="agent-cancel")
                yield Button("Close", id="agent-close", classes="-primary")
            yield KeyHintFooter(hints={"button": "[dim]Enter=Send  Esc=Close[/dim]"})

    def on_mount(self) -> None:
        try:
            self._remove_listener = self.manager.add_listener(self._on_agent_event)
        except Exception:
            logger.debug("agent listener failed", exc_info=True)
        self.render_transcript()

    def on_unmount(self) -> None:
        if self._remove_listener is not None:
            with contextlib.suppress(Exception):
                self._remove_listener()
            self._remove_listener = None

    def _on_agent_event(self, event: AgentEvent) -> None:
        """Manager listener (agent threads): post one Changed per burst."""
        if event.agent_id != self.agent_id:
            return
        with self._lock:
            if self._pending:
                return
            self._pending = True
        if not self.post_message(self.Changed()):
            with self._lock:
                self._pending = False

    def on_agent_transcript_modal_changed(self, message: Changed) -> None:
        if self._timer is None:
            self._timer = self.set_timer(self.REFRESH_S, self._refresh_now)

    def _refresh_now(self) -> None:
        self._timer = None
        with self._lock:
            self._pending = False
        self.render_transcript()

    def transcript_text(self) -> str:
        """The rendered transcript (live events, else the file)."""
        events = []
        with contextlib.suppress(Exception):
            events = self.manager.transcript_events(self.agent_id)
        if events:
            return render_agent_transcript(events)
        info = self._info() or {}
        path = info.get("transcript_path")
        if path:
            with contextlib.suppress(Exception):
                from pathlib import Path

                return render_agent_transcript(
                    records=ConversationStore.read(Path(path))
                )
        return ""

    def _info(self) -> dict | None:
        try:
            return self.manager.info(self.agent_id)
        except Exception:
            return None

    def render_transcript(self) -> None:
        info = self._info() or {}
        meta = [
            f"{info.get('profile', '?')} · "
            + AGENT_STATUS.get(
                card_status(info.get("status")), (str(info.get("status")), "")
            )[0]
        ]
        if info.get("elapsed_s") is not None:
            meta[0] += f" · {format_elapsed(info.get('elapsed_s'))}"
        if info.get("task"):
            meta.append(f"Task: {info['task']}")
        result = info.get("result") or {}
        if result.get("summary"):
            meta.append(f"Result: {result['summary']}")
        try:
            self.query_one("#agent-meta", Static).update(Content("\n".join(meta)))
            text = self.transcript_text() or "(no transcript yet)"
            self.query_one("#agent-transcript", Static).update(Content(text))
            self.query_one("#agent-cancel", Button).disabled = info.get(
                "status"
            ) not in ("queued", "running")
        except Exception:
            logger.debug("agent transcript render failed", exc_info=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "agent-cancel":
            with contextlib.suppress(Exception):
                self.manager.cancel(self.agent_id)
            self.render_transcript()
        elif event.button.id == "agent-close":
            self._dismiss_with_refresh(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "agent-message":
            return
        event.stop()
        text = event.value.strip()
        if not text:
            return
        try:
            self.manager.send(self.agent_id, text, parent=self.parent_session)
            event.input.value = ""
            self.notify(f"Sent to {self.agent_id}", timeout=2)
        except Exception as exc:
            self.notify(f"Could not send: {redact_secrets(exc)}", severity="error")
        self.render_transcript()

    def action_cancel(self) -> None:
        """Esc closes (sync on purpose; the App's priority Esc calls it)."""
        self._dismiss_with_refresh(None)


class ThreadPickerModal(ForensicModal[str | None]):
    """Pick an earlier thread to resume (dismisses with its thread id)."""

    AUTO_FOCUS = "#thread-list"

    DEFAULT_CSS = """
    ThreadPickerModal .modal-container {
        width: 100;
        max-width: 95%;
    }
    ThreadPickerModal #thread-list {
        height: auto;
        max-height: 20;
    }
    """

    def __init__(
        self, threads: list[dict], *, current: str | None = None, **kwargs: Any
    ) -> None:
        super().__init__(**kwargs)
        self.threads = threads
        self.current = current

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-container"):
            yield Label("Earlier threads", classes="modal-title")
            yield OptionList(
                *[
                    Option(
                        format_thread_row(i, t, current=self.current),
                        id=str(t.get("thread_id")),
                    )
                    for i, t in enumerate(self.threads, 1)
                ],
                id="thread-list",
            )
            yield KeyHintFooter(hints={"button": "[dim]Enter=Resume  Esc=Close[/dim]"})

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self._dismiss_with_refresh(event.option.id)

    def action_cancel(self) -> None:
        self._dismiss_with_refresh(None)


# =============================================================================
# The panel
# =============================================================================


class ChatPanel(Widget):
    """The chat dock's content: header, transcript, agents bar, input.

    See the module docstring for the event flow. Public helpers used by
    tests and other widgets: :meth:`send_message`, :meth:`run_slash`,
    :meth:`refresh_header`, :attr:`session`, :attr:`state`.
    """

    DEFAULT_CSS = """
    ChatPanel {
        layout: vertical;
        height: 1fr;
        background: $lens-bg;
    }
    ChatPanel > #chat-header {
        background: $lens-panel;
    }
    ChatPanel > #chat-log {
        height: 1fr;
    }
    ChatPanel .chat-banner {
        width: 1fr;
        height: auto;
        padding: 0 1;
        margin: 0 0 1 0;
    }
    ChatPanel .chat-intro-notice {
        margin: 0 0 1 0;
    }
    ChatPanel > #chat-hints {
        height: auto;
        padding: 0 1;
        color: $chat-muted;
        display: none;
    }
    ChatPanel > #chat-input-bar {
        height: auto;
    }
    ChatPanel #chat-input {
        width: 1fr;
        height: 3;
        border: round $lens-rule;
        background: $lens-input-bg;
        color: $lens-input-text;
        border-subtitle-color: $lens-dim;
    }
    ChatPanel #chat-input:focus {
        border: round $lens-rule-focus;
        background: $lens-input-focus-bg;
    }
    """

    BINDINGS = [
        # priority: the focused Input binds ctrl+x to "cut"; a priority
        # binding of an ancestor of the focused widget runs first.
        Binding("ctrl+x", "stop_turn", "Stop", priority=True),
        Binding("ctrl+l", "new_thread", "New thread"),
        # Bare Up is unbound in the Input and app-wide (Shift+Up sizes the
        # dock), so it bubbles here from the input.
        Binding("up", "focus_agents", "Agents", show=False),
    ]

    #: Keyboard grace of the approval card (tests set 0).
    APPROVAL_INPUT_GRACE_S: float | None = None

    class EventsReady(Message):
        """Events wait in the sink queue (posted from any thread)."""

        bubble = False

    class UiCall(Message):
        """Run a callable on the UI thread (posted from worker threads)."""

        bubble = False

        def __init__(self, fn: Callable[..., Any], args: tuple) -> None:
            super().__init__()
            self.fn = fn
            self.args = args

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.can_focus = True
        self._session: AgentSession | None = None
        # Sink queue (any thread) -> drained on the UI thread.
        self._events: deque[AgentEvent] = deque()
        self._events_lock = threading.Lock()
        self._drain_posted = False
        self._drain_timer = None
        self._last_drain = 0.0
        #: Number of queue drains (tests check the coalescing with it).
        self.drain_count = 0
        # View state.
        self._state = "idle"
        self._detail: str | None = None
        self._reply: ReplyBlock | None = None
        self._reasoning: ReasoningLine | None = None
        self._compactions = 0
        self._used: int | None = None
        self._window: int | None = None
        self._has_blocks = False
        self._intro: list[Widget] = []
        self._banner: Static | None = None
        self._banner_key: tuple | None = None
        self._empty: EmptyState | None = None
        self._busy: str | None = None
        self._notice_seq = 0
        # Approvals: request ids waiting for the card, FIFO.
        self._approvals: list[str] = []
        self._prompt: ToolPermissionPrompt | None = None
        self._prompt_rid: str | None = None

    # -- properties -----------------------------------------------------------------

    @property
    def session(self) -> AgentSession | None:
        """The open orchestrator thread (``None`` before the first message)."""
        return self._session

    @property
    def state(self) -> str:
        """Header state (``idle``, ``thinking``, ``streaming``, ``tool``, ...)."""
        return self._state

    @property
    def running(self) -> bool:
        """A turn runs or is queued (or ``/compact`` works)."""
        session = self._session
        return self._busy is not None or bool(session is not None and session.running)

    def _transcript(self) -> ChatTranscript:
        return self.query_one("#chat-log", ChatTranscript)

    def _input(self) -> Input | None:
        try:
            return self.query_one("#chat-input", Input)
        except Exception:
            return None

    # -- compose / mount ------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield ChatHeader(id="chat-header")
        yield ChatTranscript(id="chat-log")
        yield AgentsBar(id="chat-agents-bar")
        yield Static("", id="chat-hints")
        with MascotRow(id="chat-input-bar"):
            yield Input(placeholder="Ask Sandroid… / for commands", id="chat-input")
            yield ChatMascot(id="chat-mascot")

    def on_mount(self) -> None:
        field = self._input()
        if field is not None:
            field.border_subtitle = "⏎ send · ^X stop"
        self._render_intro(legacy_notice=True)
        self.refresh_header()
        self.set_interval(TICK_S, self._tick)

    def on_unmount(self) -> None:
        session = self._session
        if session is not None:
            with contextlib.suppress(Exception):
                session.cancel()
            with contextlib.suppress(Exception):
                get_agent_manager().cancel_all(session)
        with contextlib.suppress(Exception):
            from sandroid.ai.arbiter import get_arbiter

            get_arbiter().release_all(ORCHESTRATOR_ID)

    def _render_intro(self, *, legacy_notice: bool = False) -> None:
        """Mount the egress banner (+ legacy notice, + empty state)."""
        transcript = self._transcript()
        settings = get_ai_settings()
        self._banner = Static(
            format_banner(settings, self._permission_mode()), classes="chat-banner"
        )
        self._banner_key = None
        widgets: list[Widget] = [self._banner]
        if legacy_notice:
            notice = self._legacy_notice()
            if notice is not None:
                widgets.append(notice)
        if not self._has_blocks:
            self._empty = EmptyState(
                model=settings.model,
                endpoint=settings.endpoint_display if settings.base_url else None,
                remote=settings.is_configured and not settings.is_local,
                egress=None,
            )
            widgets.append(self._empty)
        self._intro = widgets
        transcript.mount(*widgets)

    def _legacy_notice(self) -> NoticeLine | None:
        """The one-time "previous declines are not enforced" notice."""
        try:
            store = get_tool_permission_store()
            if not store.legacy_notice_pending():
                return None
            declines = store.legacy_declines()
            store.acknowledge_legacy_notice()
        except Exception:
            logger.debug("legacy declines notice failed", exc_info=True)
            return None
        return NoticeLine(
            "Previous 'never' choices are no longer enforced: "
            + ", ".join(declines)
            + ". Review them with /permissions.",
            style="$lens-warn",
            classes="chat-intro-notice",
        )

    def _permission_mode(self) -> str:
        try:
            return get_tool_permission_store().mode
        except Exception:
            return "ask"

    # -- header / mascot ------------------------------------------------------------

    def refresh_header(self) -> None:
        """Repaint the header, banner and mascot from the live config/state."""
        settings = get_ai_settings()
        state, detail = self._state, self._detail
        mode = self._permission_mode()
        if state == "idle":
            if not settings.is_configured:
                state, detail = "off", None
            elif settings.problem:
                state, detail = "error", "endpoint refused"
            elif mode == "allow_all":
                detail = "allow all"
        session = self._session
        used, window = self._used, self._window
        if session is not None:
            with contextlib.suppress(Exception):
                used = int(session.meter.used) if used is None else used
                window = int(session.meter.window) if window is None else window
        agents = 0
        if session is not None:
            with contextlib.suppress(Exception):
                agents = get_agent_manager().running_count(session)
        model = (getattr(session, "model", None) if session else None) or (
            settings.model
        )
        try:
            self.query_one("#chat-header", ChatHeader).set_fields(
                state=state,
                detail=detail,
                model=model,
                remote=settings.is_configured and not settings.is_local,
                experimental=True,
                used=used,
                window=window,
                compactions=self._compactions,
                agents=agents,
            )
        except Exception:
            pass
        banner_key = (
            tuple(egress_banner_lines(settings, mode)),
            settings.is_configured,
            settings.is_ready,
        )
        if self._banner is not None and banner_key != self._banner_key:
            self._banner_key = banner_key
            with contextlib.suppress(Exception):
                self._banner.update(format_banner(settings, mode))
        self._sync_mascot(state)

    def _sync_mascot(self, state: str | None = None) -> None:
        try:
            mascot = self.query_one("#chat-mascot", ChatMascot)
        except Exception:
            return
        mascot.set_style(configured_mascot_style())
        mascot.set_state(_MASCOT_FOR_STATE.get(state or self._state, "idle"))

    def _set_state(self, state: str, detail: str | None = None) -> None:
        self._state = state
        self._detail = detail
        self.refresh_header()

    # -- transcript helpers ---------------------------------------------------------

    def _add(self, block: Widget, key: str | None = None) -> Widget:
        if not self._has_blocks:
            self._has_blocks = True
            if self._empty is not None:
                with contextlib.suppress(Exception):
                    self._empty.remove()
                self._empty = None
        return self._transcript().add_block(block, key=key)

    def _notice(
        self, text: str, *, style: str = "$chat-muted", key: str | None = None
    ) -> NoticeLine:
        """Add (or update, with an existing *key*) a one-line notice."""
        if key is not None:
            existing = self._transcript().block(key)
            if isinstance(existing, NoticeLine):
                existing.set_notice(text, style=style)
                return existing
        return self._add(NoticeLine(text, style=style), key=key)  # type: ignore[return-value]

    def _info(self, text: str) -> NoticeLine:
        """A multi-line informational block (``/context`` and friends)."""
        return self._notice(text, style="$lens-text")

    def _focus_input(self) -> None:
        field = self._input()
        if field is None:
            return
        focused = self.screen.focused if self.is_attached else None
        if focused is None or self in focused.ancestors_with_self:
            with contextlib.suppress(Exception):
                field.focus()

    def _finish_stream(self) -> None:
        """End the live reasoning line and reply block of this request."""
        if self._reasoning is not None and self._reasoning.running:
            self._reasoning.finish()
        self._reasoning = None
        reply = self._reply
        if reply is not None and not reply.finished:
            reply.call_later(reply.finish)
        self._reply = None

    # -- the event sink (any thread) ------------------------------------------------

    def _sink(self, event: AgentEvent) -> None:
        """Queue *event* for the UI thread; never blocks, never raises."""
        with self._events_lock:
            self._events.append(event)
            if self._drain_posted:
                return
            self._drain_posted = True
        posted = False
        try:
            posted = self.post_message(self.EventsReady())
        except Exception:
            logger.debug("posting chat events failed", exc_info=True)
        if not posted:
            with self._events_lock:
                self._drain_posted = False

    def _post_ui(self, fn: Callable[..., Any], *args: Any) -> None:
        """Run ``fn(*args)`` on the UI thread (from a worker); non-blocking."""
        with contextlib.suppress(Exception):
            self.post_message(self.UiCall(fn, args))

    def on_chat_panel_ui_call(self, message: UiCall) -> None:
        message.stop()
        try:
            message.fn(*message.args)
        except Exception:
            logger.exception("chat UI callback failed")

    def on_chat_panel_events_ready(self, message: EventsReady) -> None:
        message.stop()
        if self._drain_timer is not None:
            return
        wait = self._last_drain + DRAIN_INTERVAL_S - time.monotonic()
        if wait > 0:
            self._drain_timer = self.set_timer(wait, self._drain)
        else:
            self._drain()

    def _drain(self) -> None:
        self._drain_timer = None
        with self._events_lock:
            events = list(self._events)
            self._events.clear()
            self._drain_posted = False
        self._last_drain = time.monotonic()
        if not events:
            return
        self.drain_count += 1
        for event in coalesce_events(events):
            try:
                self.handle_event(event)
            except Exception:
                logger.exception("chat event %s failed", event.type)
        self.refresh_header()

    def flush_events(self) -> None:
        """Drain the queue now (tests; the timer does it otherwise)."""
        if self._drain_timer is not None:
            self._drain_timer.stop()
        self._drain()

    # -- event -> blocks (UI thread) ------------------------------------------------

    def handle_event(self, ev: AgentEvent) -> None:
        """Render one runtime event."""
        handler = getattr(self, f"_on_{ev.type}", None)
        own = ev.agent_id == ORCHESTRATOR_ID
        if handler is None:
            return
        if not own and not ev.type.startswith(("agent_", "approval_")):
            return  # subagent internals: only in the agent's transcript
        handler(ev, ev.payload or {})

    def _on_turn_start(self, ev: AgentEvent, p: dict) -> None:
        self._finish_stream()
        self._set_state("thinking")

    def _on_request_start(self, ev: AgentEvent, p: dict) -> None:
        retry = self._transcript().block(f"retry:{ev.turn_id}")
        if isinstance(retry, NoticeLine) and retry.notice_style != "$chat-muted":
            retry.set_notice(
                retry.text.replace("Retrying in", "Retried after"), style="$chat-muted"
            )
        if self._state not in ("streaming", "approval"):
            self._set_state("thinking")

    def _on_retry(self, ev: AgentEvent, p: dict) -> None:
        text = format_retry(
            float(p.get("delay_s") or 0),
            int(p.get("attempt") or 1),
            int(p.get("max_attempts") or 1),
            p.get("reason"),
        )
        self._notice(text, style="$lens-warn", key=f"retry:{ev.turn_id}")
        self._set_state("retrying")

    def _on_reasoning_delta(self, ev: AgentEvent, p: dict) -> None:
        text = str(p.get("text", ""))
        if self._reasoning is None or not self._reasoning.running:
            self._reasoning = self._add(  # type: ignore[assignment]
                ReasoningLine(verbose=self._verbose_thinking())
            )
        self._reasoning.append(text)  # type: ignore[union-attr]
        if self._state != "thinking":
            self._set_state("thinking")

    def _on_text_delta(self, ev: AgentEvent, p: dict) -> None:
        if self._reasoning is not None and self._reasoning.running:
            self._reasoning.finish()
        if self._reply is None:
            self._reply = self._add(ReplyBlock())  # type: ignore[assignment]
        self._reply.feed(str(p.get("text", "")))  # type: ignore[union-attr]
        if self._state != "streaming":
            self._set_state("streaming")

    def _on_tool_call(self, ev: AgentEvent, p: dict) -> None:
        self._finish_stream()
        name, args = unwrap_call(str(p.get("name", "")), p.get("args"))
        call_id = str(p.get("call_id", ""))
        self._add(
            ToolBlock(name, args, call_id=call_id), key=f"tool:{ev.turn_id}:{call_id}"
        )
        if name == "spawn_agent" and args.get("task"):
            # Spawn transparency: the whole task, not the 40-cell preview.
            self._notice(f"  task: {args['task']}", style="$chat-muted")
        self._set_state("tool", humanize_tool_name(name))

    def _on_tool_result(self, ev: AgentEvent, p: dict) -> None:
        block = self._transcript().block(f"tool:{ev.turn_id}:{p.get('call_id', '')}")
        elapsed = (p.get("duration_ms") or 0) / 1000
        if isinstance(block, ToolBlock):
            if p.get("status") == "ok":
                block.set_result(
                    ref=p.get("result_id"), summary=p.get("summary"), elapsed=elapsed
                )
            else:
                block.set_error(
                    p.get("error_code") or p.get("status"),
                    p.get("summary") or None,
                    elapsed=elapsed,
                )
        self._set_state("thinking")

    def _on_approval_request(self, ev: AgentEvent, p: dict) -> None:
        rid = p.get("request_id")
        if rid and rid not in self._approvals:
            self._approvals.append(rid)
        self._show_next_approval()

    def _on_approval_resolved(self, ev: AgentEvent, p: dict) -> None:
        rid = p.get("request_id")
        label = p.get("agent_label") or (
            "Sandroid AI" if ev.agent_id == ORCHESTRATOR_ID else ev.agent_id
        )
        tool = humanize_tool_name(str(p.get("tool", "")))
        decision, by = p.get("decision"), p.get("by")
        if decision in ("once", "always"):
            text = f"✓ {tool} allowed"
            if p.get("remembered_rule"):
                text += f" · remembered {p['remembered_rule']}"
            elif by == "rule":
                text += " by a rule"
            style = "$chat-muted"
        else:
            reason = {"timeout": " (no answer)", "cancelled": " (cancelled)"}.get(
                by or "", ""
            )
            text = f"✗ {tool} declined{reason}"
            if p.get("note"):
                text += f" · {p['note']}"
            style = "$lens-warn"
        if ev.agent_id != ORCHESTRATOR_ID:
            text += f" · {label}"
        self._notice(text, style=style)
        if rid in self._approvals:
            self._approvals.remove(rid)
        if rid is not None and rid == self._prompt_rid:
            self._close_prompt()
        elif self._prompt is None:
            self._show_next_approval()

    def _on_compaction(self, ev: AgentEvent, p: dict) -> None:
        masked = len(p.get("ids") or []) if p.get("kind") == "mask" else 0
        self._add(
            CompactionRule(
                int(p.get("tokens_before") or 0),
                int(p.get("tokens_after") or 0),
                masked,
            )
        )
        self._compactions += 1
        self._used = int(p.get("tokens_after") or 0) or self._used

    def _on_warning(self, ev: AgentEvent, p: dict) -> None:
        text = p.get("message") or str(p.get("kind", "warning")).replace("_", " ")
        self._notice(f"⚠ {text}", style="$lens-warn")

    def _on_error(self, ev: AgentEvent, p: dict) -> None:
        self._finish_stream()
        message = redact_secrets(p.get("message") or p.get("kind") or "error")
        self._notice(f"✗ {message}", style="$lens-bad")
        self._set_state("error")

    def _on_usage(self, ev: AgentEvent, p: dict) -> None:
        if p.get("context_used") is not None:
            self._used = int(p["context_used"])
        if p.get("context_window"):
            self._window = int(p["context_window"])

    def _on_budget_exhausted(self, ev: AgentEvent, p: dict) -> None:
        pass  # the BudgetNotice follows with turn_end (it knows the rounds)

    def _on_turn_end(self, ev: AgentEvent, p: dict) -> None:
        self._finish_stream()
        reason = p.get("reason")
        session = self._session
        if reason == "max_rounds" and session is not None:
            budget = int(getattr(session.budgets, "max_rounds", 0) or 0)
            self._add(
                BudgetNotice(int(p.get("rounds") or budget), budget, grant=budget),
                key=f"budget:{ev.turn_id}",
            )
        elif reason == "cancelled":
            self._notice("◼ Stopped", style="$chat-muted")
        if reason in ("error", "content_filter"):
            self._set_state("error")
        elif self._prompt is None:
            self._set_state("idle")

    def _on_agent_spawned(self, ev: AgentEvent, p: dict) -> None:
        agent_id = str(p.get("agent_id") or ev.agent_id)
        key = f"agent:{agent_id}"
        if self._transcript().block(key) is None:
            self._add(
                AgentCard(
                    agent_id,
                    str(p.get("profile", "agent")),
                    status=card_status(p.get("status")),
                    elapsed=p.get("elapsed_s"),
                    tokens=agent_tokens(p.get("usage")),
                    summary=str(p.get("title") or ""),
                ),
                key=key,
            )
        self._refresh_agents()

    def _on_agent_status(self, ev: AgentEvent, p: dict) -> None:
        card = self._transcript().block(f"agent:{p.get('agent_id') or ev.agent_id}")
        if isinstance(card, AgentCard):
            card.update_card(
                status=card_status(p.get("status")),
                elapsed=p.get("elapsed_s"),
                tokens=agent_tokens(p.get("usage")),
            )
        self._refresh_agents()

    def _on_agent_result(self, ev: AgentEvent, p: dict) -> None:
        agent_id = str(p.get("agent_id") or ev.agent_id)
        card = self._transcript().block(f"agent:{agent_id}")
        fields = {
            "status": card_status(p.get("status")),
            "elapsed": p.get("elapsed_s"),
            "tokens": agent_tokens(p.get("usage")),
            "summary": str(p.get("summary") or p.get("error") or ""),
            "claims": card_claims(p),
        }
        if isinstance(card, AgentCard):
            card.update_card(**fields)
        else:
            self._add(
                AgentCard(agent_id, str(p.get("profile", "agent")), **fields),
                key=f"agent:{agent_id}",
            )
        self._refresh_agents()

    def _verbose_thinking(self) -> bool:
        try:
            from sandroid.core.toolbox import Toolbox

            ai_cfg = getattr(getattr(Toolbox, "config", None), "ai", None)
        except Exception:
            ai_cfg = None
        return bool(getattr(ai_cfg, "show_verbose_thinking", False))

    # -- approvals ------------------------------------------------------------------

    def _show_next_approval(self) -> None:
        if self._prompt is not None:
            return
        broker = get_approval_broker()
        while self._approvals:
            rid = self._approvals[0]
            request = broker.get(rid)
            if request is None:  # answered elsewhere (rule, timeout, cancel)
                self._approvals.pop(0)
                continue
            kwargs: dict[str, Any] = {}
            if self.APPROVAL_INPUT_GRACE_S is not None:
                kwargs["input_grace_s"] = self.APPROVAL_INPUT_GRACE_S
            prompt = ToolPermissionPrompt(
                request=request,
                on_decision=lambda decision, rid=rid: self._on_decision(rid, decision),
                classes="chat-approval",
                **kwargs,
            )
            self._prompt, self._prompt_rid = prompt, rid
            self.mount(prompt, before=self.query_one("#chat-input-bar"))
            self._set_state("approval", humanize_tool_name(request.tool))
            return

    def _on_decision(self, rid: str, decision: Decision) -> None:
        """The card was answered: tell the broker, close the card."""
        try:
            get_approval_broker().resolve(rid, decision)
        except Exception:
            logger.exception("resolving approval %s failed", rid)
        if rid in self._approvals:
            self._approvals.remove(rid)
        if rid == self._prompt_rid:
            self._close_prompt()

    def _close_prompt(self) -> None:
        prompt, self._prompt, self._prompt_rid = self._prompt, None, None
        if prompt is not None:
            had_focus = self.screen.focused is not None and (
                prompt in self.screen.focused.ancestors_with_self
            )
            with contextlib.suppress(Exception):
                prompt.remove()
            if had_focus:
                self.call_after_refresh(self._focus_input)
        if self._approvals:
            self._show_next_approval()
        if self._prompt is None:
            session = self._session
            self._set_state(
                "thinking" if session is not None and session.running else "idle"
            )

    def pending_prompt(self) -> ToolPermissionPrompt | None:
        """The approval card on screen, if any."""
        return self._prompt

    # -- input ----------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "chat-input":
            return
        try:
            hints = self.query_one("#chat-hints", Static)
        except Exception:
            return
        value = event.value
        if not value.startswith("/") or " " in value:
            hints.display = False
            return
        matches = [c for c in SLASH_HELP if c.startswith(value.lower())]
        if not matches:
            hints.display = False
            return
        width = max(len(c) for c in matches)
        hints.update(
            Content("\n".join(f"{c:<{width}}  {SLASH_HELP[c]}" for c in matches))
        )
        hints.display = True

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "chat-input":
            return
        event.stop()
        text = event.value.strip()
        if not text:
            return
        if text.startswith("/"):
            event.input.value = ""
            self.run_slash(text)
            return
        if self.send_message(text):
            event.input.value = ""

    def send_message(self, text: str) -> bool:
        """Send an analyst message; False when refused (the text stays)."""
        text = text.strip()
        if not text:
            return False
        if self.running:
            self._notice(
                "A reply is still running. Wait for it, or press Ctrl+X to stop it.",
                style="$lens-warn",
            )
            return False
        session = self._ensure_session()
        if session is None:
            return False
        self._add(UserBlock(text))
        self._set_state("thinking")
        try:
            session.submit_user_message(text)
        except Exception as exc:
            self._notice(f"✗ {redact_secrets(exc)}", style="$lens-bad")
            self._set_state("error")
            return True
        with contextlib.suppress(Exception):
            get_agent_manager().note_analyst_message(session)
        return True

    def _ensure_session(self) -> AgentSession | None:
        session = self._session
        if session is not None and not session.closed:
            return session
        settings = get_ai_settings()
        if settings.problem:
            self._notice(redact_secrets(settings.problem), style="$lens-bad")
            self._set_state("off" if not settings.is_configured else "error")
            return None
        try:
            session = open_orchestrator_session(sink=self._sink)
        except AIClientError as exc:
            self._notice(f"✗ {redact_secrets(exc)}", style="$lens-bad")
            self._set_state("error")
            return None
        except Exception as exc:
            logger.exception("Opening the AI thread failed")
            self._notice(
                f"✗ Could not open the AI thread: {redact_secrets(exc)}",
                style="$lens-bad",
            )
            self._set_state("error")
            return None
        self._session = session
        if not session.persistent:
            self._notice(
                "No analysis session: this thread is kept in memory only.",
                style="$chat-muted",
            )
        return session

    # -- actions --------------------------------------------------------------------

    def action_stop_turn(self) -> None:
        """Ctrl+X: stop the running turn and every agent of this thread."""
        session = self._session
        if session is None:
            return
        was_running = session.running
        with contextlib.suppress(Exception):
            session.cancel()
        cancelled = 0
        with contextlib.suppress(Exception):
            cancelled = get_agent_manager().cancel_all(session)
        if cancelled:
            plural = "s" if cancelled != 1 else ""
            self._notice(f"◼ Cancelled {cancelled} agent{plural}")
        elif not was_running:
            self._refresh_agents()

    def action_new_thread(self) -> None:
        """Ctrl+L: close this thread and start a new one."""
        self.new_thread()

    def new_thread(self) -> bool:
        """``/new``: refused while a turn runs; else close and clear."""
        if self.running:
            self._notice(
                "Can't start a new thread while a reply is running. "
                "Press Ctrl+X to stop it first.",
                style="$lens-warn",
            )
            return False
        if not self._close_session():
            return False
        self._reset_view()
        return True

    def _close_session(self) -> bool:
        session = self._session
        if session is None:
            return True
        with contextlib.suppress(Exception):
            get_agent_manager().cancel_all(session)
        try:
            session.close("new")
        except SessionBusyError:
            self._notice(
                "The thread is busy. Press Ctrl+X to stop it first.",
                style="$lens-warn",
            )
            return False
        except Exception:
            logger.exception("Closing the AI thread failed")
        self._session = None
        return True

    def _reset_view(self) -> None:
        """Empty the transcript and the per-thread view state."""
        if self._prompt is not None:
            with contextlib.suppress(Exception):
                self._prompt.remove()
        self._prompt = self._prompt_rid = None
        self._approvals.clear()
        self._reply = self._reasoning = None
        self._compactions = 0
        self._used = self._window = None
        self._has_blocks = False
        self._empty = None
        self._transcript().clear_blocks()
        self._render_intro()
        self._state, self._detail = "idle", None
        self._refresh_agents()
        self.refresh_header()

    def action_focus_agents(self) -> None:
        bar = self.query_one("#chat-agents-bar", AgentsBar)
        if bar.display and bar.rows:
            bar.focus()

    def on_agents_bar_open(self, message: AgentsBar.Open) -> None:
        message.stop()
        self.open_agent(message.agent_id)

    def on_agents_bar_leave(self, message: AgentsBar.Leave) -> None:
        message.stop()
        field = self._input()
        if field is not None:
            field.focus()

    def on_agent_card_open(self, message: AgentCard.Open) -> None:
        message.stop()
        self.open_agent(message.agent_id)

    def open_agent(self, agent_id: str) -> AgentTranscriptModal | None:
        """Show an agent's transcript (cancel / send from there)."""
        modal = AgentTranscriptModal(agent_id, parent=self._session)
        try:
            self.app.push_screen(modal)
        except Exception:
            logger.debug("opening the agent transcript failed", exc_info=True)
            return None
        return modal

    def on_budget_notice_continue(self, message: BudgetNotice.Continue) -> None:
        message.stop()
        session = self._session
        if session is None or self.running:
            self._notice("Can't continue while a reply is running.", style="$lens-warn")
            return
        grant = message.notice.grant
        self._notice(f"↻ Continue (+{grant} rounds)" if grant else "↻ Continue")
        self._set_state("thinking")
        try:
            session.continue_turn(grant)
        except Exception as exc:
            self._notice(f"✗ {redact_secrets(exc)}", style="$lens-bad")
            return
        with contextlib.suppress(Exception):
            get_agent_manager().note_analyst_message(session)

    def on_budget_notice_stop(self, message: BudgetNotice.Stop) -> None:
        message.stop()

    # -- housekeeping ---------------------------------------------------------------

    def _tick(self) -> None:
        """1 s timer: leases, agents bar, stale approval cards, header."""
        manager = get_agent_manager()
        with contextlib.suppress(Exception):
            manager.reconcile_leases()
        self._refresh_agents()
        rid = self._prompt_rid
        if rid is not None and get_approval_broker().get(rid) is None:
            if rid in self._approvals:
                self._approvals.remove(rid)
            self._close_prompt()
        if self._state in ("thinking", "streaming", "tool", "retrying"):
            session = self._session
            if session is None or not session.running:
                self._set_state("idle")
                return
        self.refresh_header()

    def _agent_rows(self) -> list[dict]:
        session = self._session
        if session is None:
            return []
        try:
            return get_agent_manager().list(session)
        except Exception:
            return []

    def _refresh_agents(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#chat-agents-bar", AgentsBar).set_rows(self._agent_rows())

    # -- slash commands -------------------------------------------------------------

    def run_slash(self, text: str) -> None:
        """Run one slash command line (``/name args``)."""
        command, _, arg = text.strip().partition(" ")
        command, arg = command.lower(), arg.strip()
        handler = {
            "/new": self._cmd_new,
            "/clear": self._cmd_new,
            "/threads": self._cmd_threads,
            "/compact": self._cmd_compact,
            "/context": self._cmd_context,
            "/permissions": self._cmd_permissions,
            "/agents": self._cmd_agents,
            "/doctor": self._cmd_doctor,
            "/help": self._cmd_help,
        }.get(command)
        try:
            self.query_one("#chat-hints", Static).display = False
        except Exception:
            pass
        if handler is None:
            self._notice(
                f"Unknown command {command}. Commands: " + " ".join(SLASH_HELP),
                style="$lens-warn",
            )
            return
        handler(arg)

    def _cmd_help(self, arg: str) -> None:
        width = max(len(c) for c in SLASH_HELP)
        self._info("\n".join(f"{c:<{width}}  {h}" for c, h in SLASH_HELP.items()))

    def _cmd_new(self, arg: str) -> None:
        self.new_thread()

    def _cmd_threads(self, arg: str) -> None:
        current = self._session.thread_id if self._session is not None else None
        try:
            threads = [t for t in list_threads() if t.get("kind", "chat") == "chat"]
        except Exception as exc:
            self._notice(f"✗ {redact_secrets(exc)}", style="$lens-bad")
            return
        if not threads:
            self._notice("No earlier threads in this analysis session.")
            return
        if arg:
            target = None
            if arg.isdigit() and 1 <= int(arg) <= len(threads):
                target = threads[int(arg) - 1].get("thread_id")
            else:
                target = next(
                    (t["thread_id"] for t in threads if t.get("thread_id") == arg),
                    None,
                )
            if target is None:
                self._notice(f"No thread {arg}. Try /threads.", style="$lens-warn")
                return
            self.resume_thread(str(target))
            return

        def picked(thread_id: str | None) -> None:
            if thread_id:
                self.resume_thread(thread_id)

        self.app.push_screen(ThreadPickerModal(threads, current=current), picked)

    def resume_thread(self, thread_id: str) -> bool:
        """Close the current thread and reopen *thread_id* with its history."""
        if self._session is not None and self._session.thread_id == thread_id:
            self._notice("That is the current thread.")
            return False
        if self.running:
            self._notice(
                "Can't switch threads while a reply is running. "
                "Press Ctrl+X to stop it first.",
                style="$lens-warn",
            )
            return False
        settings = get_ai_settings()
        if settings.problem:
            self._notice(redact_secrets(settings.problem), style="$lens-bad")
            return False
        if not self._close_session():
            return False
        try:
            session = open_orchestrator_session(sink=self._sink, thread_id=thread_id)
        except Exception as exc:
            self._reset_view()
            self._notice(
                f"✗ Could not resume {thread_id}: {redact_secrets(exc)}",
                style="$lens-bad",
            )
            return False
        self._reset_view()
        self._session = session
        self._render_history(session)
        title = session.title or thread_id
        self._notice(f"↺ Resumed “{title}”")
        self.refresh_header()
        return True

    def _render_history(self, session: AgentSession) -> None:
        """Rebuild the blocks of a resumed thread from its records."""
        path = getattr(session, "thread_path", None)
        records: list[dict] = []
        if path is not None:
            with contextlib.suppress(Exception):
                records = ConversationStore.read(path)
        for widget, key in history_blocks(records):
            self._add(widget, key=key)
        self._compactions = sum(1 for r in records if r.get("type") == "compaction")

    def _cmd_compact(self, arg: str) -> None:
        session = self._session
        if session is None:
            self._notice("Nothing to compact yet.")
            return
        if self.running:
            self._notice(
                "Can't compact while a reply is running. Press Ctrl+X first.",
                style="$lens-warn",
            )
            return
        self._busy = "compact"
        self._set_state("compacting")
        focus = arg or None

        def work() -> None:
            result: Any = None
            error: str | None = None
            try:
                result = session.compact_now(focus)
            except SessionBusyError as exc:
                error = str(exc)
            except Exception as exc:
                logger.exception("Manual compaction failed")
                error = redact_secrets(exc)
            self._post_ui(self._compact_done, result, error)

        self.run_worker(work, thread=True, exclusive=False, group="chat-compact")

    def _compact_done(self, result: Any, error: str | None) -> None:
        self._busy = None
        if error:
            self._notice(f"✗ Compaction failed: {error}", style="$lens-bad")
        elif result is None:
            self._notice("Compaction is not available.", style="$lens-warn")
        self._set_state("idle")

    def _cmd_context(self, arg: str) -> None:
        session = self._session
        if session is None:
            self._notice("No thread yet: send a message first.")
            return
        agents_usage = None
        with contextlib.suppress(Exception):
            agents_usage = get_agent_manager().usage_totals(session)
        self._info(format_context(session, agents_usage))

    def _cmd_permissions(self, arg: str) -> None:
        try:
            store = get_tool_permission_store()
        except Exception as exc:
            self._notice(f"✗ {redact_secrets(exc)}", style="$lens-bad")
            return
        choice = arg.lower().replace("-", "_")
        if choice in ("allow_all", "toggle"):
            mode = store.toggle_session_allow_all()
            if choice == "allow_all" and mode != "allow_all":
                mode = store.toggle_session_allow_all()
            self._notice(f"Approval mode for this session: {mode}", style="$lens-warn")
        elif choice == "ask":
            store.set_session_mode("ask")
            self._notice("Approval mode for this session: ask")
        elif choice:
            self._notice(
                "Use /permissions, /permissions allow_all or /permissions ask.",
                style="$lens-warn",
            )
            return
        self._info(format_permissions(store))
        self.refresh_header()

    def _cmd_agents(self, arg: str) -> None:
        rows = self._agent_rows()
        if arg:
            target = None
            if arg.isdigit() and 1 <= int(arg) <= len(rows):
                target = rows[int(arg) - 1].get("agent_id")
            elif any(r.get("agent_id") == arg for r in rows) or arg.startswith("a-"):
                target = arg
            if target is None:
                self._notice(f"No agent {arg}. Try /agents.", style="$lens-warn")
                return
            self.open_agent(str(target))
            return
        if not rows:
            self._notice("No agents in this thread.")
            return
        lines = [format_agent_row(i, r) for i, r in enumerate(rows, 1)]
        lines.append("Open one with /agents <n>, or ↑ to the agents bar.")
        self._info("\n".join(lines))

    def _cmd_doctor(self, arg: str) -> None:
        session = self._session
        self._notice("Checking the AI endpoint…", key="doctor")

        def work() -> None:
            try:
                client = session.client if session is not None else None
                if client is None:
                    client = build_session_client()
                report = client.health()
                text, style = format_health(report)
            except Exception as exc:
                text, style = f"✗ {redact_secrets(exc)}", "$lens-bad"
            self._post_ui(lambda: self._notice(text, style=style, key="doctor"))

        self.run_worker(work, thread=True, exclusive=False, group="chat-doctor")


def format_health(report: Any) -> tuple[str, str]:
    """``/doctor`` result line and its style."""
    if getattr(report, "ok", False):
        bits = ["✓ Endpoint OK"]
        if report.ping_ms is not None:
            bits.append(f"ping {report.ping_ms:.0f} ms")
        if report.max_input_tokens:
            bits.append(f"max input {format_tokens(report.max_input_tokens)}")
        if report.model_listed is False:
            bits.append("model not in /models")
        return " · ".join(bits), "$lens-ok"
    error = redact_secrets(getattr(report, "error", None) or "unknown error")
    return f"✗ Endpoint check failed: {error}", "$lens-bad"


def history_blocks(records: Iterable[dict]) -> list[tuple[Widget, str | None]]:
    """Blocks of a resumed thread: user, replies, tool calls + chips, rules."""
    blocks: list[tuple[Widget, str | None]] = []
    tools: dict[str, ToolBlock] = {}
    for rec in records:
        rtype = rec.get("type")
        if rtype == "compaction":
            events = rec.get("events") or [{}]
            last = events[-1] if isinstance(events[-1], dict) else {}
            blocks.append(
                (
                    CompactionRule(
                        int(last.get("tokens_before") or 0),
                        int(last.get("tokens_after") or 0),
                    ),
                    None,
                )
            )
            continue
        if rtype != "msg":
            continue
        role = rec.get("role")
        if role == "user":
            if rec.get("kind") in ("user", "continue"):
                blocks.append((UserBlock(str(rec.get("text") or "")), None))
        elif role == "assistant":
            if rec.get("content"):
                reply = ReplyBlock(str(rec["content"]))
                reply.finished = True
                blocks.append((reply, None))
            for call in rec.get("tool_calls") or []:
                if not isinstance(call, dict):
                    continue
                fn = call.get("function") or {}
                name, args = unwrap_call(
                    str(fn.get("name", "")), _parse_args(fn.get("arguments"))
                )
                call_id = str(call.get("id", ""))
                block = ToolBlock(name, args, call_id=call_id, running=False)
                tools[call_id] = block
                blocks.append((block, None))
        elif role == "tool":
            block = tools.get(str(rec.get("tool_call_id", "")))
            if block is None:
                continue
            status = rec.get("status", "ok")
            if status == "ok":
                block.set_result(ref=rec.get("result_id"))
            else:
                block.set_error(str(status))
    return blocks


__all__ = [
    "SLASH_HELP",
    "SYSTEM_PROMPT",
    "AgentTranscriptModal",
    "AgentsBar",
    "ChatPanel",
    "ThreadPickerModal",
    "agent_tokens",
    "card_claims",
    "card_status",
    "coalesce_events",
    "egress_banner_lines",
    "format_agent_row",
    "format_banner",
    "format_context",
    "format_health",
    "format_permissions",
    "format_thread_row",
    "history_blocks",
    "open_orchestrator_session",
    "render_agent_transcript",
    "unwrap_call",
]
