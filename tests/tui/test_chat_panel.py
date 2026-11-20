"""The AI chat panel (``sandroid.tui.widgets.chat_panel``) over the runtime.

The panel renders :class:`~sandroid.ai.loop.AgentEvent` objects and forwards
input, approvals and slash commands. Most tests drive it with a scripted fake
session (events pushed through the real sink); a few run a real
:class:`~sandroid.ai.session.AgentSession` with a scripted fake client. No
network, no device.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from pilot_helpers import settle, until
from textual.app import App, ComposeResult
from textual.content import Content
from textual.widgets import Input, Static

import sandroid.ai.tool_permissions as perms
import sandroid.tui.widgets.chat_panel as chat_panel_module
from sandroid.ai.client import ModelProfile, StreamChunk, ToolCallDelta, Usage
from sandroid.ai.loop import AgentEvent, Budgets
from sandroid.ai.session import AgentSession, list_threads
from sandroid.ai.tool_permissions import ALLOW_ALL_NOTICE, ToolPermissionStore
from sandroid.ai.tools.registry import RiskTier
from sandroid.core.toolbox import Toolbox
from sandroid.tui.screens.main_screen import MainScreen
from sandroid.tui.widgets.chat_panel import (
    AgentsBar,
    AgentTranscriptModal,
    AgentTranscriptView,
    ChatPanel,
    coalesce_events,
    egress_banner_lines,
    format_thread_row,
    render_agent_transcript,
    unwrap_call,
)
from sandroid.tui.widgets.chat_view import (
    AgentCard,
    BudgetNotice,
    ChatMascot,
    ChatTranscript,
    CompactionRule,
    EmptyState,
    NoticeLine,
    ReasoningLine,
    ReplyBlock,
    ToolBlock,
    UserBlock,
)
from sandroid.tui.widgets.tool_permission_prompt import ToolPermissionPrompt

LOCAL = "http://127.0.0.1:8000/v1"
REMOTE = "https://llm.example.com/v1"


# =============================================================================
# Fakes and fixtures
# =============================================================================


def _ai(**overrides):
    values = {
        "base_url": LOCAL,
        "api_key": "test-key-1234",
        "model": "fake-model",
        "allow_remote": False,
        "chat_mascot": "blocks",
        "show_chat_mascot": True,
        "show_verbose_thinking": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.fixture
def ai_on(monkeypatch):
    cfg = _ai()
    monkeypatch.setattr(Toolbox, "config", SimpleNamespace(ai=cfg), raising=False)
    return cfg


@pytest.fixture
def perm_store(tmp_path, monkeypatch):
    store = ToolPermissionStore(path=tmp_path / "perms.toml")
    monkeypatch.setattr(perms, "_tool_permission_store", store)
    return store


@pytest.fixture(autouse=True)
def _no_grace(monkeypatch):
    monkeypatch.setattr(ChatPanel, "APPROVAL_INPUT_GRACE_S", 0.0)


class FakeMeter:
    used = 41_000
    window = 262_144
    input_limit = 230_144
    last_prompt_tokens = 40_000


class FakeSession:
    """Stands in for the orchestrator's AgentSession."""

    def __init__(self, sink, thread_id="t-1"):
        self.sink = sink
        self.thread_id = thread_id
        self.running = False
        self.closed = False
        self.persistent = True
        self.model = "fake-model"
        self.title = "first question"
        self.meter = FakeMeter()
        self.budgets = Budgets(max_rounds=25)
        self.totals = {"prompt_tokens": 1200, "completion_tokens": 80, "requests": 3}
        self.thread_path = None
        self.messages: list[dict] = []
        self.tools: list[dict] = []
        self.submitted: list[str] = []
        self.continued: list[int | None] = []
        self.cancelled = 0
        self.compact_focus: list[str | None] = []
        self.client = SimpleNamespace(
            health=lambda: SimpleNamespace(
                ok=True,
                ping_ms=12.0,
                max_input_tokens=262_144,
                model_listed=True,
                error=None,
            )
        )

    def submit_user_message(self, text, **_):
        self.submitted.append(text)

    def continue_turn(self, extra_rounds=None):
        self.continued.append(extra_rounds)

    def cancel(self, clear_queue=True):
        self.cancelled += 1
        self.running = False

    def close(self, reason="new"):
        from sandroid.ai.session import SessionBusyError

        if self.running:
            raise SessionBusyError("busy")
        self.closed = True

    def context_breakdown(self):
        return {
            "system": 3000,
            "tools_schema": 9000,
            "ambient": 500,
            "history": 8000,
            "tool_results": 20000,
            "summaries": 0,
            "reasoning": 500,
        }

    def compact_now(self, focus=None):
        self.compact_focus.append(focus)
        self.sink(
            ev("compaction", kind="summary", tokens_before=182_000, tokens_after=41_000)
        )
        return SimpleNamespace(changed=True)


class FakeManager:
    """Stands in for the AgentManager."""

    def __init__(self):
        self.rows: list[dict] = []
        self.events: dict[str, list] = {}
        self.cancelled: list[str] = []
        self.cancel_all_calls = 0
        self.sent: list[tuple[str, str]] = []
        self.noted = 0
        self.listeners: list = []

    def list(self, parent=None, *, live_only=False):
        return list(self.rows)

    def info(self, agent_id):
        for row in self.rows:
            if row["agent_id"] == agent_id:
                return {**row, "task": "check the hosts", "transcript_path": None}
        return None

    def transcript_events(self, agent_id):
        return list(self.events.get(agent_id, []))

    def add_listener(self, cb):
        self.listeners.append(cb)
        return lambda: self.listeners.remove(cb)

    def cancel(self, agent_id):
        self.cancelled.append(agent_id)
        return True

    def cancel_all(self, parent=None):
        self.cancel_all_calls += 1
        return 0

    def send(self, agent_id, text, *, parent=None):
        self.sent.append((agent_id, text))
        return {"agent_id": agent_id, "delivery": "next_round"}

    def running_count(self, parent=None):
        return sum(1 for r in self.rows if r["status"] in ("queued", "running"))

    def note_analyst_message(self, parent):
        self.noted += 1
        return 0

    def reconcile_leases(self):
        pass

    def usage_totals(self, parent=None):
        return {"prompt_tokens": 500, "completion_tokens": 50}


@pytest.fixture
def manager(monkeypatch):
    fake = FakeManager()
    monkeypatch.setattr(chat_panel_module, "get_agent_manager", lambda: fake)
    return fake


@pytest.fixture
def sessions(monkeypatch, ai_on):
    """Patch the session factory; returns the list of opened fakes."""
    opened: list[FakeSession] = []

    def factory(*, sink, thread_id=None):
        session = FakeSession(sink, thread_id or f"t-{len(opened) + 1}")
        opened.append(session)
        return session

    monkeypatch.setattr(chat_panel_module, "open_orchestrator_session", factory)
    return opened


def ev(type_, who="orchestrator", turn_id="u1", **payload):
    """An AgentEvent from agent *who* (the payload may carry its own agent_id)."""
    if "agent_id" in payload and who == "orchestrator":
        who = payload["agent_id"]
    return AgentEvent(type_, who, None, "t-1", turn_id, 0, time.time(), payload)


class _Harness(App):
    def compose(self) -> ComposeResult:
        yield ChatPanel(id="chat-panel")


async def _panel(pilot) -> ChatPanel:
    await settle(pilot)
    return pilot.app.query_one(ChatPanel)


async def _push(pilot, panel: ChatPanel, *events) -> None:
    for event in events:
        panel._sink(event)
    await until(pilot, lambda: not panel._events and panel._drain_timer is None)
    await settle(pilot)


def _blocks(panel: ChatPanel, kind=None) -> list:
    blocks = panel.query_one(ChatTranscript).blocks
    return [b for b in blocks if kind is None or isinstance(b, kind)]


def _notices(panel: ChatPanel) -> str:
    return "\n".join(b.text for b in _blocks(panel, NoticeLine))


async def _send(pilot, panel: ChatPanel, text: str) -> None:
    field = panel.query_one("#chat-input", Input)
    field.focus()
    field.value = text
    await pilot.press("enter")
    # Opening / resuming a thread and listing threads run on workers.
    await until(pilot, lambda: not panel.io_pending)
    await settle(pilot)


# =============================================================================
# Mount, banner, header
# =============================================================================


@pytest.mark.smoke
async def test_mounts_with_the_kept_ids_banner_and_empty_state(ai_on):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        assert isinstance(app.query_one("#chat-log"), ChatTranscript)
        assert isinstance(app.query_one("#chat-mascot"), ChatMascot)
        assert app.query_one("#chat-input", Input).border_subtitle
        assert app.query_one("#chat-header") is not None
        banner = app.query_one(".chat-banner", Static)
        text = banner.plain_text
        assert "EXPERIMENTAL" in text
        assert "fake-model" in text
        assert app.query(EmptyState)
        assert panel.session is None  # opened on the first message
        header = app.query_one("#chat-header").render().plain
        assert "idle" in header
        assert "EXPERIMENTAL" in header


async def test_not_configured_shows_off_state(monkeypatch):
    monkeypatch.setattr(
        Toolbox, "config", SimpleNamespace(ai=_ai(base_url=None)), raising=False
    )
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        await _panel(pilot)
        assert "not configured" in app.query_one("#chat-header").render().plain
        assert "not configured" in app.query_one(".chat-banner").plain_text


async def test_remote_endpoint_is_refused_before_opening_a_session(
    monkeypatch, sessions
):
    monkeypatch.setattr(
        Toolbox, "config", SimpleNamespace(ai=_ai(base_url=REMOTE)), raising=False
    )
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "hello")
        assert sessions == []
        assert "not on this machine" in _notices(panel)
        assert panel.state == "error"
        # The text stays in the box: nothing was sent.
        assert panel.query_one("#chat-input", Input).value == "hello"


async def test_allow_all_mode_shows_in_banner_and_header(ai_on, perm_store):
    perm_store.set_session_mode("allow_all")
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        await _panel(pilot)
        banner = app.query_one(".chat-banner").plain_text
        assert ALLOW_ALL_NOTICE in banner
        assert "always ask" not in banner
        assert "allow all" in app.query_one("#chat-header").render().plain


def test_banner_lines_swap_the_approval_line_in_allow_all_mode():
    from sandroid.ai.safety import get_ai_settings

    settings = get_ai_settings(_ai())
    ask = egress_banner_lines(settings, "ask")
    allow = egress_banner_lines(settings, "allow_all")
    assert any(line.startswith("Device-changing tools always ask") for line in ask)
    assert not any(line.startswith("Device-changing tools") for line in allow)
    assert ALLOW_ALL_NOTICE in allow[-1]


async def test_legacy_declines_notice_is_shown_once(ai_on, tmp_path, monkeypatch):
    path = tmp_path / "perms.toml"
    path.write_text('never = ["kill_process"]\n')
    store = ToolPermissionStore(path=path)
    monkeypatch.setattr(perms, "_tool_permission_store", store)
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        await _panel(pilot)
        notices = [
            n.text for n in app.query(NoticeLine) if "no longer enforced" in n.text
        ]
        assert len(notices) == 1
        assert "kill_process" in notices[0]
    assert not store.legacy_notice_pending()


# =============================================================================
# Sending and rendering events
# =============================================================================


async def test_send_opens_a_session_and_renders_the_turn(sessions, manager):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "What is it sending?")
        assert len(sessions) == 1
        session = sessions[0]
        assert session.submitted == ["What is it sending?"]
        assert manager.noted == 1
        assert panel.query_one("#chat-input", Input).value == ""
        assert not app.query(EmptyState)
        session.running = True
        await _push(
            pilot,
            panel,
            ev("turn_start", mode="chat"),
            ev("request_start", iteration=1),
            ev("reasoning_delta", text="Let me look."),
            ev("tool_call", call_id="c1", name="list_flows", args={"package": "x"}),
            ev(
                "tool_result",
                call_id="c1",
                name="list_flows",
                status="ok",
                result_id="R17",
                summary="12 rows",
                duration_ms=400,
            ),
            ev("text_delta", text="It talks to "),
            ev("text_delta", text="**tracker.example**."),
            ev("usage", context_used=41_000, context_window=262_144),
        )
        session.running = False
        await _push(pilot, panel, ev("turn_end", reason="completed", rounds=2))
        user, thought, tool, reply = (
            _blocks(panel, UserBlock),
            _blocks(panel, ReasoningLine),
            _blocks(panel, ToolBlock),
            _blocks(panel, ReplyBlock),
        )
        assert user[0].text == "What is it sending?"
        assert not thought[0].running
        assert "R17" in tool[0].chip.plain
        assert "12 rows" in tool[0].chip.plain
        await until(pilot, lambda: reply[0].text == "It talks to **tracker.example**.")
        assert panel.state == "idle"
        header = app.query_one("#chat-header").render().plain
        assert "41k/262k" in header


async def test_deltas_from_a_worker_thread_are_coalesced(sessions):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        words = [f"w{i} " for i in range(300)]

        def produce():
            for word in words:
                panel._sink(ev("text_delta", text=word))

        thread = threading.Thread(target=produce)
        thread.start()
        thread.join()
        await until(pilot, lambda: not panel._events and panel._drain_timer is None)
        await settle(pilot)
        replies = _blocks(panel, ReplyBlock)
        assert len(replies) == 1
        await until(pilot, lambda: replies[0].text == "".join(words))
        assert panel.drain_count <= 5


def test_coalesce_merges_runs_of_deltas_per_agent():
    events = [
        ev("text_delta", text="a"),
        ev("text_delta", text="b"),
        ev("reasoning_delta", text="r"),
        ev("text_delta", text="c"),
        ev("text_delta", agent_id="a-re-xxxxxx", text="z"),
    ]
    merged = coalesce_events(events)
    assert [(e.type, e.payload["text"]) for e in merged] == [
        ("text_delta", "ab"),
        ("reasoning_delta", "r"),
        ("text_delta", "c"),
        ("text_delta", "z"),
    ]


async def test_failed_tool_call_shows_an_error_chip(sessions):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _push(
            pilot,
            panel,
            ev(
                "tool_call",
                call_id="c1",
                name="call_tool",
                args={"name": "get_tls_keys", "arguments": "{}"},
            ),
            ev(
                "tool_result",
                call_id="c1",
                status="error",
                error_code="not_loaded",
                summary="load it with tool_search",
            ),
        )
        (tool,) = _blocks(panel, ToolBlock)
        assert tool.tool_name == "get_tls_keys"  # call_tool is unwrapped
        assert tool.ok is False
        assert "not_loaded" in tool.chip.plain


async def test_tool_progress_updates_the_running_chip(sessions):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _push(
            pilot,
            panel,
            ev(
                "tool_call",
                call_id="c7",
                name="classify_rows",
                args={"lens": "network"},
            ),
            ev(
                "tool_progress",
                call_id="c7",
                done=120,
                total=412,
                matched=9,
                note="classifying",
            ),
        )
        (tool,) = _blocks(panel, ToolBlock)
        assert tool.running
        assert tool.chip is None
        assert tool.progress.plain == "classifying 120/412 · 9 matched"
        assert "classifying 120/412 · 9 matched" in tool.render().plain
        # A subagent's progress and a later result: the result chip wins.
        await _push(
            pilot,
            panel,
            ev("tool_progress", who="a-re-xxxxxx", call_id="c7", done=1, total=2),
            ev("tool_result", call_id="c7", status="ok", summary="9 of 412"),
            ev("tool_progress", call_id="c7", done=412, total=412, matched=9),
        )
        assert tool.progress is None
        assert "9 of 412" in tool.chip.plain
        assert "classifying" not in tool.render().plain


async def test_spawn_agent_shows_the_full_task(sessions):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        task = "Check every host in R3 against the tracker list " * 3
        await _push(
            pilot,
            panel,
            ev(
                "tool_call",
                call_id="c9",
                name="spawn_agent",
                args={"profile": "researcher", "task": task},
            ),
        )
        assert task.strip() in _notices(panel)


async def test_errors_retries_and_compaction(sessions):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _push(
            pilot,
            panel,
            ev("retry", attempt=2, max_attempts=4, delay_s=4, reason="HTTP 503"),
        )
        assert panel.state == "retrying"
        await _push(pilot, panel, ev("retry", attempt=3, max_attempts=4, delay_s=8))
        retries = [n for n in _blocks(panel, NoticeLine) if "Retr" in n.text]
        assert len(retries) == 1
        assert "3/4" in retries[0].text
        await _push(
            pilot,
            panel,
            ev(
                "compaction",
                kind="mask",
                tokens_before=140_000,
                tokens_after=90_000,
                ids=["R1", "R2"],
            ),
            ev("error", kind="interrupted", message="stream dropped"),
        )
        (rule,) = _blocks(panel, CompactionRule)
        assert "2 results masked" in rule.label
        assert "1 compacted" in app.query_one("#chat-header").render().plain
        assert "stream dropped" in _notices(panel)
        assert panel.state == "error"


async def test_mascot_follows_the_panel_state(sessions):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        mascot = app.query_one("#chat-mascot", ChatMascot)
        assert mascot.state == "idle"
        await _push(pilot, panel, ev("reasoning_delta", text="x"))
        assert mascot.state == "thinking"
        await _push(pilot, panel, ev("text_delta", text="y"))
        assert mascot.state == "streaming"
        await _push(
            pilot, panel, ev("tool_call", call_id="c", name="list_flows", args={})
        )
        assert mascot.state == "tool"
        await _push(pilot, panel, ev("error", message="boom"))
        assert mascot.state == "error"
        await _push(pilot, panel, ev("turn_end", reason="completed", rounds=1))
        assert mascot.state == "idle"


async def test_mascot_off_hides_it_on_refresh_header(ai_on):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        mascot = app.query_one("#chat-mascot", ChatMascot)
        assert mascot.display
        ai_on.show_chat_mascot = False
        panel.refresh_header()
        await settle(pilot)
        assert not mascot.display


# =============================================================================
# Approvals
# =============================================================================


def _submit(tool="kill_process", label="Sandroid AI", agent_id="orchestrator"):
    broker = perms.get_approval_broker()
    return broker.submit(
        agent_id=agent_id,
        agent_label=label,
        tool=tool,
        args={"package_name": "com.example"},
        risk=RiskTier.REVERSIBLE,
        suggested_rule=f"{tool}(package_name=com.example)",
        description="Kill a process.",
        argument_dependent=True,
    )


def _request_event(pending, agent_id="orchestrator"):
    r = pending.request
    return ev(
        "approval_request",
        agent_id=agent_id,
        request_id=r.request_id,
        agent_label=r.agent_label,
        tool=r.tool,
        args=dict(r.args),
    )


def _resolved_event(pending, agent_id="orchestrator"):
    d = pending.decision
    return ev(
        "approval_resolved",
        agent_id=agent_id,
        request_id=pending.request.request_id,
        tool=pending.request.tool,
        decision=d.choice,
        note=d.note,
        remembered_rule=d.remembered_rule,
        by=d.by,
    )


@pytest.mark.parametrize(
    ("keys", "choice", "note"),
    [
        (["1"], "once", None),
        (["2"], "always", None),
        (["3", "u", "s", "e", " ", "x", "enter"], "no", "use x"),
        (["escape"], "no", None),
    ],
)
async def test_approval_card_answers_the_broker(
    sessions, perm_store, keys, choice, note
):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        pending = _submit()
        await _push(pilot, panel, _request_event(pending))
        prompt = panel.pending_prompt()
        assert isinstance(prompt, ToolPermissionPrompt)
        assert panel.state == "approval"
        assert app.query_one("#chat-mascot", ChatMascot).state == "approval"
        await until(pilot, lambda: prompt.has_focus)
        for key in keys:
            await pilot.press(key)
        await settle(pilot)
        await until(pilot, lambda: pending.done)  # resolved on a worker
        assert pending.decision.choice == choice
        assert pending.decision.note == note
        assert panel.pending_prompt() is None
        assert not app.query(ToolPermissionPrompt)
        await until(pilot, lambda: app.focused is not None)
        assert app.focused.id == "chat-input"
        await _push(pilot, panel, _resolved_event(pending))
        line = _notices(panel)
        assert ("allowed" if choice != "no" else "declined") in line
        if note:
            assert note in line


async def test_approvals_queue_one_card_at_a_time(sessions, perm_store):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        first = _submit()
        second = _submit(
            tool="uninstall_apk", label="operator a-op-abcdef", agent_id="a-op-abcdef"
        )
        await _push(
            pilot,
            panel,
            _request_event(first),
            _request_event(second, agent_id="a-op-abcdef"),
        )
        assert len(app.query(ToolPermissionPrompt)) == 1
        assert panel._prompt_rid == first.request.request_id
        # The first one times out elsewhere: the card moves on.
        perms.get_approval_broker().cancel(first.request.request_id)
        await _push(pilot, panel, _resolved_event(first))
        await until(pilot, lambda: panel._prompt_rid == second.request.request_id)
        assert len(app.query(ToolPermissionPrompt)) == 1


# =============================================================================
# Threads: Ctrl+L, /new, /threads
# =============================================================================


async def test_ctrl_l_closes_the_thread_and_clears_the_transcript(sessions, manager):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "hello")
        old = panel.session
        await _push(pilot, panel, ev("text_delta", text="hi"))
        await pilot.press("ctrl+l")
        await settle(pilot)
        await until(pilot, lambda: old.closed)  # closed on a worker
        assert manager.cancel_all_calls == 1
        assert panel.session is None
        assert _blocks(panel) == []
        assert app.query(EmptyState)
        assert app.query(".chat-banner")
        await _send(pilot, panel, "again")
        assert len(sessions) == 2
        assert sessions[1].submitted == ["again"]


async def test_new_thread_is_refused_while_a_turn_runs(sessions, manager):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "hello")
        panel.session.running = True
        await _send(pilot, panel, "/new")
        assert not panel.session.closed
        assert "Ctrl+X" in _notices(panel)
        assert _blocks(panel, UserBlock)
        # A second message is refused too, and stays in the box.
        await _send(pilot, panel, "more")
        assert panel.session.submitted == ["hello"]
        assert panel.query_one("#chat-input", Input).value == "more"


async def test_ctrl_x_cancels_the_turn_and_its_agents(sessions, manager):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "hello")
        panel.session.running = True
        panel.query_one("#chat-input", Input).focus()
        await pilot.press("ctrl+x")
        await settle(pilot)
        assert panel.session.cancelled == 1
        assert manager.cancel_all_calls == 1


def _script(*replies):
    return list(replies)


def _usage():
    return Usage(100, 10, 0, 110)


def _text(text):
    return [
        StreamChunk("text", text=text),
        StreamChunk("done", finish_reason="stop", usage=_usage()),
    ]


def _tool(name, raw, call_id="call_1"):
    return [
        StreamChunk("tool_call", tool_call=ToolCallDelta(0, call_id, name, raw)),
        StreamChunk("done", finish_reason="tool_calls", usage=_usage()),
    ]


class ScriptedClient:
    model = "fake-model"
    profile = ModelProfile(
        name="test",
        context_window=262_144,
        system_mode="multi",
        think_tags=False,
        echo_reasoning="all",
        stream_usage=True,
        tool_choice_none=True,
    )

    def __init__(self, script):
        self.script = list(script)

    def stream(self, messages, tools=None, **_):
        yield from self.script.pop(0)

    def health(self):
        return SimpleNamespace(
            ok=True, ping_ms=5.0, max_input_tokens=None, model_listed=True, error=None
        )


def _real_factory(monkeypatch, root, scripts):
    """Real AgentSessions in *root*; each open/resume takes the next script."""

    def factory(*, sink, thread_id=None):
        kwargs = {
            "root": root,
            "client": ScriptedClient(scripts.pop(0) if scripts else []),
            "sink": sink,
            "task_registrar": None,
            "ambient_provider": lambda: "",
        }
        if thread_id:
            return AgentSession.resume(thread_id, **kwargs)
        return AgentSession.open_new(**kwargs)

    monkeypatch.setattr(chat_panel_module, "open_orchestrator_session", factory)
    monkeypatch.setattr(chat_panel_module, "list_threads", lambda: list_threads(root))


async def test_real_session_streams_and_threads_resume_with_history(
    ai_on, perm_store, tmp_path, monkeypatch
):
    scripts = [
        _script(_tool("no_such_tool", "{}"), _text("Found **nothing**.")),
        _script(),
        _script(),
    ]
    _real_factory(monkeypatch, tmp_path, scripts)
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "first question")
        session = panel.session
        await until(pilot, lambda: not session.running)
        await until(pilot, lambda: not panel._events and panel._drain_timer is None)
        await settle(pilot)
        (tool,) = _blocks(panel, ToolBlock)
        assert tool.ok is False
        assert "unknown_tool" in tool.chip.plain
        (reply,) = _blocks(panel, ReplyBlock)
        await until(pilot, lambda: reply.text == "Found **nothing**.")
        assert panel.state == "idle"
        first_id = session.thread_id

        await pilot.press("ctrl+l")
        await settle(pilot)
        await until(pilot, lambda: session.closed)  # closed on a worker
        assert panel.session is None
        threads = list_threads(tmp_path)
        assert [t["thread_id"] for t in threads] == [first_id]

        await _send(pilot, panel, "/threads 1")
        await until(pilot, lambda: panel.session is not None)
        assert panel.session.thread_id == first_id
        users = [b.text for b in _blocks(panel, UserBlock)]
        assert users == ["first question"]
        (tool,) = _blocks(panel, ToolBlock)
        assert tool.tool_name == "no_such_tool"
        assert tool.ok is False
        assert [b.text for b in _blocks(panel, ReplyBlock)] == ["Found **nothing**."]
        assert "Resumed" in _notices(panel)


async def test_threads_picker_lists_and_resumes(sessions, monkeypatch):
    rows = [
        {
            "thread_id": "t-b",
            "title": "second",
            "updated": "2026-11-19T10:00:00+00:00",
            "turns": 2,
        },
        {
            "thread_id": "t-a",
            "title": "first",
            "updated": "2026-11-18T10:00:00+00:00",
            "turns": 1,
        },
    ]
    monkeypatch.setattr(chat_panel_module, "list_threads", lambda: rows)
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "/threads")
        await until(pilot, lambda: type(app.screen).__name__ == "ThreadPickerModal")
        await pilot.press("down", "enter")
        await until(pilot, lambda: panel.session is not None)
        assert panel.session.thread_id == "t-a"


def test_thread_rows_read_well():
    row = format_thread_row(
        2,
        {"thread_id": "t-x", "title": "hosts", "updated": None, "turns": 1},
        current="t-x",
    )
    assert row.startswith("2. hosts")
    assert "1 turn" in row
    assert "current" in row


# =============================================================================
# Slash commands
# =============================================================================


async def test_slash_shows_a_hint_list(sessions):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        field = panel.query_one("#chat-input", Input)
        field.focus()
        await pilot.press("slash")
        await settle(pilot)
        hints = panel.query_one("#chat-hints", Static)
        assert hints.display
        assert "/threads" in str(hints.render())
        # Every command the panel runs is listed (the help screen reads it too).
        assert {"/clear", "/help"} <= set(chat_panel_module.SLASH_HELP)
        assert "/help" in str(hints.render())
        await pilot.press("t")
        await settle(pilot)
        assert "/compact" not in str(hints.render())
        field.value = "hello"
        await settle(pilot)
        assert not hints.display


async def test_compact_runs_off_the_ui_thread_and_renders_the_rule(sessions):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "/compact")
        assert "Nothing to compact" in _notices(panel)
        await _send(pilot, panel, "hello")
        await _send(pilot, panel, "/compact keep the hosts")
        await until(
            pilot, lambda: panel._busy is None and _blocks(panel, CompactionRule)
        )
        assert panel.session.compact_focus == ["keep the hosts"]
        assert "182k → 41k" in _blocks(panel, CompactionRule)[0].label
        assert panel.state == "idle"


async def test_context_shows_the_breakdown(sessions, manager):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "hello")
        await _send(pilot, panel, "/context")
        text = _notices(panel)
        assert "41k/262k" in text
        assert "Tool results" in text
        assert "20k" in text
        assert "Session" in text
        assert "Agents" in text


async def test_permissions_shows_rules_and_toggles_allow_all(sessions, perm_store):
    perm_store.add_allow_rule("launch_app")
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "/permissions")
        assert "Approval mode: ask" in _notices(panel)
        assert "launch_app" in _notices(panel)
        before = len(_blocks(panel, NoticeLine))
        await _send(pilot, panel, "/permissions allow_all")
        assert perm_store.mode == "allow_all"
        assert perm_store.file_mode == "ask"  # session only
        await settle(pilot)
        assert ALLOW_ALL_NOTICE in app.query_one(".chat-banner").plain_text
        # One line, not "...for this session: allow_all" plus the whole view.
        added = [b.text for b in _blocks(panel, NoticeLine)[before:]]
        assert added == ["Approval mode: allow_all (this session; file: ask)"]
        before = len(_blocks(panel, NoticeLine))
        await _send(pilot, panel, "/permissions ask")
        assert perm_store.mode == "ask"
        added = [b.text for b in _blocks(panel, NoticeLine)[before:]]
        assert added == ["Approval mode: ask (this session; file: ask)"]


async def test_doctor_reports_the_health_check(sessions):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "hello")
        await _send(pilot, panel, "/doctor")
        await until(pilot, lambda: "Endpoint OK" in _notices(panel))
        assert "ping 12 ms" in _notices(panel)


async def test_unknown_command_lists_the_commands(sessions):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "/frobnicate")
        assert "Unknown command" in _notices(panel)
        assert sessions == []


# =============================================================================
# Agents
# =============================================================================


def _agent_row(status="running", agent_id="a-re-abcdef"):
    return {
        "agent_id": agent_id,
        "profile": "researcher",
        "title": "check hosts",
        "status": status,
        "elapsed_s": 12.0,
        "usage": {"prompt_tokens": 9000, "completion_tokens": 200},
    }


async def test_agent_card_bar_and_transcript_modal(sessions, manager):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "spawn one")
        manager.rows = [_agent_row()]
        manager.events["a-re-abcdef"] = [
            ev(
                "tool_call",
                agent_id="a-re-abcdef",
                call_id="c1",
                name="list_flows",
                args={},
            ),
            ev(
                "tool_result",
                agent_id="a-re-abcdef",
                call_id="c1",
                status="ok",
                result_id="R4",
                summary="3 rows",
            ),
            ev("text_delta", agent_id="a-re-abcdef", text="Two trackers."),
        ]
        await _push(
            pilot,
            panel,
            ev(
                "agent_spawned",
                **_agent_row(),
                task="check the hosts",
            ),
            # Subagent internals never reach the main transcript.
            ev("text_delta", agent_id="a-re-abcdef", text="secret"),
        )
        (card,) = _blocks(panel, AgentCard)
        assert card.status == "running"
        assert card.role == "researcher"
        assert not _blocks(panel, ReplyBlock)
        bar = panel.query_one("#chat-agents-bar", AgentsBar)
        assert bar.display
        assert "a-re-abcdef" in bar.render().plain
        assert "1 agent" in app.query_one("#chat-header").render().plain

        panel.query_one("#chat-input", Input).focus()
        await pilot.press("up")
        await settle(pilot)
        assert bar.has_focus
        await pilot.press("enter")
        await until(pilot, lambda: isinstance(app.screen, AgentTranscriptModal))
        modal = app.screen
        view = modal.query_one("#agent-transcript", AgentTranscriptView)
        (tool,) = [b for b in view.blocks if isinstance(b, ToolBlock)]
        assert tool.label == "List Flows"
        assert "R4" in tool.chip.plain
        await until(
            pilot,
            lambda: any(
                isinstance(b, ReplyBlock) and "Two trackers." in b.text
                for b in view.blocks
            ),
        )
        assert "Two trackers." in modal.transcript_text()
        modal.query_one("#agent-message", Input).value = "also check DNS"
        modal.query_one("#agent-message", Input).focus()
        await pilot.press("enter")
        await settle(pilot)
        assert manager.sent == [("a-re-abcdef", "also check DNS")]
        await pilot.click("#agent-cancel")
        await settle(pilot)
        assert manager.cancelled == ["a-re-abcdef"]
        await pilot.press("escape")
        await until(pilot, lambda: not isinstance(app.screen, AgentTranscriptModal))

        manager.rows = [_agent_row("complete")]
        await _push(
            pilot,
            panel,
            ev(
                "agent_result",
                **{**_agent_row("complete"), "summary": "Two trackers found."},
                claims=[{"text": "tracker.example gets the IMEI", "evidence": ["R4"]}],
                delivery=None,
            ),
        )
        assert card.status == "done"
        assert card.claims == [("tracker.example gets the IMEI", ["R4"])]
        assert "Two trackers found." in card.summary

        # Clicking the card opens its transcript too.
        card.post_message(AgentCard.Open(card))
        await until(pilot, lambda: isinstance(app.screen, AgentTranscriptModal))
        app.screen.action_cancel()
        await until(pilot, lambda: not isinstance(app.screen, AgentTranscriptModal))


async def test_agents_command_lists_and_opens(sessions, manager):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "/agents")
        assert "No agents" in _notices(panel)
        await _send(pilot, panel, "hello")
        manager.rows = [_agent_row("complete")]
        await _send(pilot, panel, "/agents")
        assert "1. researcher a-re-abcdef" in _notices(panel)
        await _send(pilot, panel, "/agents 1")
        await until(pilot, lambda: isinstance(app.screen, AgentTranscriptModal))
        assert app.screen.agent_id == "a-re-abcdef"


def test_agent_transcript_renders_file_records():
    records = [
        {"type": "msg", "role": "user", "kind": "user", "text": "Check the hosts"},
        {
            "type": "msg",
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "c1",
                    "function": {
                        "name": "call_tool",
                        "arguments": '{"name": "list_flows", "arguments": {"limit": 5}}',
                    },
                }
            ],
        },
        {
            "type": "msg",
            "role": "tool",
            "tool_call_id": "c1",
            "status": "ok",
            "result_id": "R2",
        },
        {"type": "msg", "role": "assistant", "content": "Done."},
    ]
    text = render_agent_transcript(records=records)
    assert text.splitlines() == [
        "› Check the hosts",
        "List Flows  limit=5",
        "  done · R2",
        "Done.",
    ]


def test_unwrap_call_parses_string_arguments():
    assert unwrap_call("call_tool", {"name": "x", "arguments": '{"a": 1}'}) == (
        "x",
        {"a": 1},
    )
    assert unwrap_call("list_flows", None) == ("list_flows", {})


# =============================================================================
# Budget
# =============================================================================


async def test_budget_notice_continue_grants_more_rounds(sessions, manager):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "dig deep")
        await _push(
            pilot,
            panel,
            ev("budget_exhausted", kind="rounds", can_continue=True),
            ev("turn_end", reason="max_rounds", rounds=26, budget_kind="rounds"),
        )
        (notice,) = _blocks(panel, BudgetNotice)
        assert notice.grant == 25
        await pilot.click("#budget-continue")
        await settle(pilot)
        assert panel.session.continued == [25]
        assert notice.choice == "continue"
        assert manager.noted == 2


# =============================================================================
# Dock integration
# =============================================================================


def test_chat_is_not_a_lens():
    from sandroid.tui.widgets.lens_shell import LENSES

    assert "tab-chat" not in MainScreen._TOOL_TABS
    assert "chat" not in {spec.id for spec in LENSES}


@pytest.mark.smoke
async def test_toggle_chat_panel_shows_and_hides_the_dock():
    app = App()
    screen = MainScreen()
    async with app.run_test() as pilot:
        await app.push_screen(screen)
        await pilot.pause()
        assert screen.chat_mode == "closed"
        screen.toggle_chat_panel()
        await pilot.pause()
        assert screen.chat_is_open
        assert app.focused is not None
        assert app.focused.id == "chat-input"
        screen.toggle_chat_panel()
        await pilot.pause()
        assert screen.chat_mode == "closed"


# =============================================================================
# Regressions: E2E + verifier findings (fix pass B)
# =============================================================================

BRACKETS = ["[x]", "[/]", "[bold]", "[Black on black]", "[A-Z]{3}"]


async def test_bracket_text_is_shown_verbatim_and_never_crashes(
    sessions, manager, monkeypatch
):
    """``/threads`` crashed with MarkupError on a ``[`` in a title; model and
    user text anywhere must be plain text.
    """
    from textual.widgets import OptionList

    rows = [
        {"thread_id": f"t-{i}", "title": f"list {b} please", "turns": 1}
        for i, b in enumerate(BRACKETS)
    ]
    monkeypatch.setattr(chat_panel_module, "list_threads", lambda: rows)
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "hello [bold]x[/] [x]")
        (user,) = _blocks(panel, UserBlock)
        assert "hello [bold]x[/] [x]" in str(user.render())
        await _push(
            pilot,
            panel,
            ev("tool_call", call_id="c1", name="run_x", args={"q": "[/] [A-Z]"}),
            ev(
                "tool_result",
                call_id="c1",
                status="error",
                error_code="bad_args",
                summary="bad_args: [Black on black] gone",
                duration_ms=5,
            ),
            ev("warning", message="[/] careful"),
            ev("error", message="[bold]boom[/]"),
        )
        (tool,) = _blocks(panel, ToolBlock)
        assert "[/] [A-Z]" in tool.call_line(200).plain
        assert "[Black on black] gone" in tool.chip.plain
        notices = _notices(panel)
        assert "[/] careful" in notices
        assert "[bold]boom[/]" in notices
        await _send(pilot, panel, "/threads")
        await until(pilot, lambda: type(app.screen).__name__ == "ThreadPickerModal")
        options = app.screen.query_one(OptionList)
        await settle(pilot)  # rendering the rows must not raise
        shown = [str(options.get_option_at_index(i).prompt) for i in range(len(rows))]
        for bracket, text in zip(BRACKETS, shown, strict=True):
            assert f"list {bracket} please" in text
        app.screen.action_cancel()
        await settle(pilot)


async def test_approval_answer_sits_on_the_call_above_a_clean_chip(
    sessions, perm_store
):
    """E2E: ``denied: denied: …`` and the decline line after the chip."""
    app = _Harness()
    async with app.run_test(size=(120, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "kill it")
        pending = _submit()
        await _push(
            pilot,
            panel,
            ev(
                "tool_call",
                call_id="c1",
                name="kill_process",
                args={"package_name": "com.example"},
            ),
            _request_event(pending),
        )
        prompt = panel.pending_prompt()
        await until(pilot, lambda: prompt.has_focus)
        await pilot.press("3", *"use chrome", "enter")
        await until(pilot, lambda: pending.done)
        await _push(
            pilot,
            panel,
            _resolved_event(pending),
            ev(
                "tool_result",
                call_id="c1",
                name="kill_process",
                status="denied",
                error_code="denied",
                summary="denied: The analyst declined kill_process. "
                "Their note: use chrome",
                duration_ms=22_000,
            ),
        )
        (tool,) = _blocks(panel, ToolBlock)
        lines = tool.render().plain.splitlines()
        # One line: the decision, the note and the time; no "denied" chip.
        assert len(lines) == 2
        assert lines[1].strip() == "declined by you · use chrome · 22s"
        assert tool.get_content_height(None, None, 100) == 2
        assert "declined" not in _notices(panel)  # no extra line after the chip
    assert chat_panel_module.strip_code_prefix("cancelled", "cancelled: x") == "x"
    assert chat_panel_module.strip_code_prefix("denied", "other") == "other"


async def test_resume_shows_the_threads_context_use_at_once(sessions, monkeypatch):
    """E2E: the meter read ``0/262k`` after /threads until the next request."""
    monkeypatch.setattr(FakeMeter, "used", 0)
    monkeypatch.setattr(
        FakeMeter, "estimate", lambda self, messages, tools: 55_000, raising=False
    )
    monkeypatch.setattr(
        chat_panel_module,
        "list_threads",
        lambda: [{"thread_id": "t-old", "title": "old", "turns": 3}],
    )
    app = _Harness()
    async with app.run_test(size=(120, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "/threads t-old")
        await until(pilot, lambda: panel.session is not None)
        await settle(pilot)
        assert "55k/262k" in app.query_one("#chat-header").render().plain
    records = [
        {"type": "usage", "prompt": 1000, "completion": 10},
        {"type": "usage", "prompt": 30_000, "completion": 500},
    ]
    no_estimate = SimpleNamespace(meter=SimpleNamespace(), messages=[], tools=[])
    assert chat_panel_module.resumed_context_used(no_estimate, records) == 30_500
    assert chat_panel_module.resumed_context_used(no_estimate, []) is None


async def test_late_events_of_a_closed_thread_are_dropped(sessions, manager):
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "hello")
        old = sessions[0]
        # Queued but not drained yet when Ctrl+L clears the view...
        old.sink(ev("text_delta", text="late reply"))
        assert panel.new_thread()
        await settle(pilot)
        # ...and emitted afterwards by the winding-down old thread.
        old.sink(ev("tool_call", call_id="c9", name="list_flows", args={}))
        old.sink(ev("approval_request", request_id="ap-x", tool="kill_process"))
        await until(pilot, lambda: not panel._events and panel._drain_timer is None)
        await settle(pilot)
        assert _blocks(panel) == []
        assert panel.pending_prompt() is None
        await _send(pilot, panel, "again")
        await _push(pilot, panel, ev("text_delta", text="new reply"))
        (reply,) = _blocks(panel, ReplyBlock)
        await until(pilot, lambda: reply.text == "new reply")


async def test_thread_and_approval_disk_work_runs_off_the_ui_thread(
    ai_on, perm_store, manager, monkeypatch
):
    on_ui: dict[str, bool] = {}

    def mark(name):
        on_ui[name] = threading.current_thread() is threading.main_thread()

    class _Session(FakeSession):
        def close(self, reason="new"):
            mark("close")
            super().close(reason)

    def factory(*, sink, thread_id=None):
        mark(f"open:{thread_id}")
        return _Session(sink, thread_id or "t-new")

    def listing():
        mark("list")
        return [{"thread_id": "t-old", "title": "old", "turns": 1}]

    monkeypatch.setattr(chat_panel_module, "open_orchestrator_session", factory)
    monkeypatch.setattr(chat_panel_module, "list_threads", listing)
    broker = perms.get_approval_broker()
    real_resolve = broker.resolve

    def resolve(*args, **kwargs):
        mark("resolve")
        return real_resolve(*args, **kwargs)

    monkeypatch.setattr(broker, "resolve", resolve)
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "hello")
        pending = _submit()
        await _push(pilot, panel, _request_event(pending))
        await until(pilot, lambda: panel.pending_prompt().has_focus)
        await pilot.press("2")
        await until(pilot, lambda: pending.done)
        await _send(pilot, panel, "/threads")
        await until(pilot, lambda: type(app.screen).__name__ == "ThreadPickerModal")
        await pilot.press("enter")
        await until(pilot, lambda: panel.session is not None and not panel.io_pending)
    assert set(on_ui) == {"open:None", "resolve", "list", "close", "open:t-old"}
    assert not any(on_ui.values()), on_ui


async def test_page_keys_scroll_the_transcript_from_the_input(sessions):
    app = _Harness()
    async with app.run_test(size=(100, 24)) as pilot:
        panel = await _panel(pilot)
        for i in range(80):
            panel._notice(f"line {i}")
        await settle(pilot)
        log = panel.query_one(ChatTranscript)
        field = panel.query_one("#chat-input", Input)
        field.focus()
        log.scroll_end(animate=False, immediate=True)
        await settle(pilot)
        bottom = log.scroll_y
        assert bottom > 0
        await pilot.press("pageup")
        await settle(pilot)
        assert log.scroll_y < bottom
        await pilot.press("ctrl+home")
        await settle(pilot)
        assert log.scroll_y == 0
        await pilot.press("pagedown")
        await settle(pilot)
        assert log.scroll_y > 0
        await pilot.press("ctrl+end")
        await settle(pilot)
        assert log.scroll_y == log.max_scroll_y
        assert field.has_focus


async def test_typing_on_the_agents_bar_goes_to_the_input(sessions, manager):
    """E2E: keys typed with the agents bar focused ran the App's hotkeys."""
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "spawn")
        manager.rows = [_agent_row()]
        panel._refresh_agents()
        field = panel.query_one("#chat-input", Input)
        field.focus()
        await pilot.press("up")
        await settle(pilot)
        assert panel.query_one(AgentsBar).has_focus
        await pilot.press("h", "i")
        await settle(pilot)
        assert field.has_focus
        assert field.value == "hi"


async def test_agents_bar_states_are_words_in_their_colour():
    """No spinner glyph ("⠋ running 17s"): the word and its colour say it."""

    class _BarApp(App):
        def compose(self) -> ComposeResult:
            yield AgentsBar()

    def row(status: str, **extra) -> dict:
        return {"agent_id": "a1", "profile": "researcher", "status": status, **extra}

    def styled(bar: AgentsBar, word: str) -> set[str]:
        content = bar.render()
        return {
            str(span.style)
            for span in content.spans
            if content.plain[span.start : span.end].startswith(word)
        }

    app = _BarApp()
    async with app.run_test(size=(100, 5)) as pilot:
        bar = app.query_one(AgentsBar)
        app.set_focus(None)  # focused, the selected row is reverse video
        await settle(pilot)
        bar.set_rows([row("running", elapsed_s=17)])
        text = bar.render().plain
        assert "researcher a1 · running 17s" in text
        assert not any(ch in text for ch in "⠋⠙◆✓✗◼")
        assert styled(bar, "running") == {"$lens-accent"}
        for status, word, style in (
            ("complete", "done", "$lens-ok"),
            ("failed", "failed", "$lens-bad"),
            ("cancelled", "cancelled", "$chat-muted"),
        ):
            bar.set_rows([row(status)])
            assert f"researcher a1 · {word}" in bar.render().plain
            assert styled(bar, word) == {style}


async def test_closing_the_agent_modal_returns_to_the_chat_input(sessions, manager):
    """E2E: focus came back to the agents bar (Ctrl+Y then closed the chat)."""
    app = _Harness()
    async with app.run_test(size=(100, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "spawn")
        manager.rows = [_agent_row()]
        panel._refresh_agents()
        panel.query_one("#chat-input", Input).focus()
        await pilot.press("up", "enter")
        await until(pilot, lambda: isinstance(app.screen, AgentTranscriptModal))
        await pilot.press("escape")
        await until(pilot, lambda: not isinstance(app.screen, AgentTranscriptModal))
        await until(pilot, lambda: app.focused is not None)
        await settle(pilot)
        assert app.focused.id == "chat-input"


class _LongAgentManager(FakeManager):
    TASK = "Task: produce an accurate summary of the exported surface.\n\n" + "\n".join(
        f"{i}. step number {i} with plenty of words" for i in range(60)
    )
    TABLE = "| package | perms |\n|---|---|\n" + "\n".join(
        f"| com.app{i} | CAMERA |" for i in range(40)
    )

    def info(self, agent_id):
        row = super().info(agent_id)
        if row is None:
            return None
        return {
            **row,
            "task": self.TASK,
            "result": {"summary": "Result: " + self.TABLE},
        }


@pytest.mark.parametrize("size", [(120, 45), (200, 110), (90, 24)])
async def test_agent_modal_keeps_input_and_buttons_on_screen(
    sessions, monkeypatch, size
):
    """E2E bug 2: the unbounded meta pushed transcript, input and buttons off
    screen; Markdown tables were flattened; "Task: Task:".
    """
    manager = _LongAgentManager()
    monkeypatch.setattr(chat_panel_module, "get_agent_manager", lambda: manager)
    manager.rows = [_agent_row("complete")]
    manager.events["a-re-abcdef"] = [
        ev("text_delta", agent_id="a-re-abcdef", text=_LongAgentManager.TABLE),
        ev("turn_end", agent_id="a-re-abcdef", reason="completed", rounds=3),
    ]
    app = _Harness()
    async with app.run_test(size=size) as pilot:
        panel = await _panel(pilot)
        panel.open_agent("a-re-abcdef")
        await until(pilot, lambda: isinstance(app.screen, AgentTranscriptModal))
        modal = app.screen
        await settle(pilot)
        height = app.size.height
        for selector in ("#agent-message", "#agent-cancel", "#agent-close"):
            region = modal.query_one(selector).region
            assert region.height > 0, selector
            assert region.bottom <= height, (selector, region, height)
        meta = modal.query_one("#agent-meta", Static)
        assert meta.region.height <= 4
        meta_text = str(meta.render())
        assert "Task: Task:" not in meta_text
        assert "produce an accurate summary" in meta_text
        view = modal.query_one("#agent-transcript", AgentTranscriptView)
        assert view.region.height >= 3
        await until(pilot, lambda: view.query("MarkdownTable"))  # not flattened
        await settle(pilot)
        view.scroll_home(animate=False, immediate=True)
        await settle(pilot)
        if view.max_scroll_y > 0:
            await pilot.press("pagedown")
            await settle(pilot)
            assert view.scroll_y > 0
            await pilot.press("pageup")
            await settle(pilot)
            assert view.scroll_y == 0
        await pilot.press("ctrl+t")
        await settle(pilot)
        assert modal.has_class("-details")
        details = str(modal.query_one("#agent-details-text", Static).render())
        assert "step number 59" in details
        assert modal.query_one("#agent-message").region.bottom <= height
        modal.action_cancel()
        await settle(pilot)


async def test_agent_cards_update_live_while_running(sessions, manager):
    """E2E bug 3: the card stayed at "0 tok" with a frozen timer and spinner."""
    app = _Harness()
    async with app.run_test(size=(120, 40)) as pilot:
        panel = await _panel(pilot)
        await _send(pilot, panel, "spawn")
        row = {**_agent_row(), "usage": {}, "elapsed_s": 3.0}
        manager.rows = [row]
        await _push(pilot, panel, ev("agent_spawned", **row))
        (card,) = _blocks(panel, AgentCard)
        assert "running" in Content.from_markup(card.border_title).plain
        manager.rows = [{**row, "elapsed_s": 75.0}]
        manager.events["a-re-abcdef"] = [
            ev("usage", agent_id="a-re-abcdef", prompt=1200, completion=34),
            ev("usage", agent_id="a-re-abcdef", prompt=1300, completion=10),
        ]
        panel._tick()
        assert card.tokens == 2544
        assert card.elapsed == 75.0
        title = card.border_title
        assert "1:15" in title
        assert "2.5k tok" in title
        manager.rows = [{**row, "status": "complete", "usage": {"prompt_tokens": 2600}}]
        panel._tick()
        assert card.status == "done"
        assert "done" in Content.from_markup(card.border_title).plain
        assert card.tokens == 2600


def test_history_chips_show_summary_time_and_the_approval():
    records = [
        {"type": "msg", "role": "user", "kind": "user", "text": "go"},
        {
            "type": "msg",
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "c1",
                    "function": {
                        "name": "kill_process",
                        "arguments": '{"package_name": "x"}',
                    },
                }
            ],
        },
        {
            "type": "approval",
            "tool": "kill_process",
            "decision": "no",
            "by": "user",
            "note": "use chrome",
        },
        {
            "type": "msg",
            "role": "tool",
            "tool_call_id": "c1",
            "status": "denied",
            "error_code": "denied",
            "summary": "denied: The analyst declined kill_process.",
            "ms": 2200,
        },
        {
            "type": "msg",
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"id": "c2", "function": {"name": "list_flows", "arguments": "{}"}}
            ],
        },
        {
            "type": "msg",
            "role": "tool",
            "tool_call_id": "c2",
            "status": "ok",
            "result_id": "R4",
            "summary": "12 rows",
            "duration_ms": 400,
        },
        {
            "type": "msg",
            "role": "tool",
            "tool_call_id": "c3",
            "status": "ok",
        },
    ]
    tools = [
        w
        for w, _ in chat_panel_module.history_blocks(records)
        if isinstance(w, ToolBlock)
    ]
    killed, listed = tools
    assert "declined by you · use chrome" in killed.decision.plain
    assert killed.chip.plain == "denied · 2.2s"
    shown = killed.render().plain.splitlines()
    assert [line.strip() for line in shown[1:]] == [
        "declined by you · use chrome · 2.2s"
    ]
    assert listed.chip.plain == "done · R4 · 12 rows · 0.4s"
    # Without timing in the record there is no made-up "0s".
    bare = chat_panel_module.history_blocks(
        [records[4], {**records[5], "summary": None, "duration_ms": None}]
    )
    assert [w for w, _ in bare if isinstance(w, ToolBlock)][0].chip.plain == "done · R4"


def test_banner_wraps_with_a_hanging_indent():
    from sandroid.ai.safety import get_ai_settings

    settings = get_ai_settings(_ai())
    lines = chat_panel_module.format_banner(settings, "ask", width=40).plain.split("\n")
    # Words in the warn colour, no "⚠"; wrapped continuations hang by two.
    assert not lines[0].startswith(" ")
    assert "⚠" not in "".join(lines)
    assert any(line.startswith("  ") for line in lines[1:])
    assert all(len(line) <= 40 for line in lines)
    assert len(lines) > len(egress_banner_lines(settings, "ask"))  # it wrapped
