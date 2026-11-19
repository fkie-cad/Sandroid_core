"""Subagents: profiles, the agent manager/scheduler and the orchestrator tools.

A *subagent* is a separate :class:`~sandroid.ai.session.AgentSession`
(``kind="agent"``) that works on one self-contained task for the orchestrator
(the main chat agent) and reports back a structured :class:`AgentResult`.

- **Profiles** (:class:`AgentProfile`) are data: a system prompt, a tool
  selector (tiers, toolsets, include/exclude), budgets, a concurrency cap, an
  optional model and a resource ceiling. Built-ins: ``researcher`` (read-only
  tools, up to ``ai.agents.researcher_max`` at once) and ``operator`` (every
  tier, ``ai.agents.operator_max`` at once; its device changes go through the
  normal permission rules and the approval broker under the agent's own
  label, never auto-approved). Every profile excludes ``NOT_EXPOSED`` tools,
  the agent tools (no nesting), orchestrator-only tools
  (``start_spotlight_app``) and tools that hold a lease across an
  asynchronous completion (``start_replay``).
- **Scheduler** (:class:`AgentManager`): per-profile caps; spawns over the cap
  are queued, not refused. A process-wide :class:`Gateway` limits concurrent
  HTTP requests (``ai.agents.gateway_concurrency``, one slot reserved for the
  orchestrator). The slot is held only for the duration of one streamed
  request (:class:`GatewayClient`), so a parent blocked in ``spawn_agent``
  with ``wait=true`` never holds one.
- **Arbiter**: the owner id is the agent id, registered before the worker
  thread starts and forgotten in its ``finally``. A synchronous child may use
  its blocked parent's leases (lineage); the profile's ``resource_ceiling`` is
  enforced before any claim. Lease reconcile (:meth:`AgentManager.reconcile_leases`)
  replaces the chat panel's timer-driven reconcile.
- **Result**: the agent prompt demands a fixed final report (STATUS / SUMMARY /
  CLAIMS with R-ids or #seq / OPEN QUESTIONS), parsed by :func:`parse_result`.
  A completed turn whose report does not parse gets one wrap-up request (same
  tools array, ``tool_choice="none"``); budget exhaustion already ends with
  the runtime's wrap-up. Otherwise the result is ``partial`` with the last
  text. A crash gives ``failed`` with a redacted error; never an empty result.
- **Return path**: ``agent_spawned`` / ``agent_status`` / ``agent_result``
  :class:`~sandroid.ai.loop.AgentEvent` objects go to the parent session's
  sink and to manager listeners. An asynchronous result is delivered to the
  parent with ``enqueue_wake`` as a fenced ``<subagent-result>`` block
  (coalesced, at most ``ai.agents.max_auto_wakes`` automatic wakes per
  analyst message); a closed parent thread gets nothing enqueued.

Files (with a session root): ``<root>/ai/agents/<id>/transcript.jsonl`` (the
agent's thread) and ``<root>/ai/agents/<id>/meta.json`` (profile, parent
thread and tool-call id, task, status, usage, result).

Only :mod:`sandroid.ai.session`, :mod:`sandroid.ai.loop` and the tool layer are
used.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import secrets
import threading
import time
import weakref
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from sandroid.ai import tool_permissions as _perms
from sandroid.ai.arbiter import ResourceId, get_arbiter
from sandroid.ai.loop import (
    ORCHESTRATOR_ID,
    AgentEvent,
    Budgets,
    RunContext,
    TurnResult,
    current_run_context,
)
from sandroid.ai.prompts import (
    AGENT_FORMAT_WRAP_UP_PROMPT,
    AGENT_MESSAGE_TEMPLATE,
    AGENT_TASK_TEMPLATE,
    OPERATOR_PROMPT,
    RESEARCHER_PROMPT,
    SUBAGENT_RESULT_PREAMBLE,
)
from sandroid.ai.results import CHARS_PER_TOKEN, ensure_private_dir
from sandroid.ai.tools.registry import (
    AllowedPredicate,
    RiskTier,
    ToolError,
    ToolRegistry,
    ToolSpec,
    get_tool_registry,
)
from sandroid.ai.tools.toolsets import AGENTS_TOOLSET, META_TOOL_NAMES

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

#: The orchestrator agent tools, in their fixed tools-array order. Pass as
#: ``extra_tools`` when opening the orchestrator's session.
ORCHESTRATOR_AGENT_TOOLS: tuple[str, ...] = (
    "spawn_agent",
    "wait_agent",
    "get_agent_result",
    "cancel_agent",
    "send_to_agent",
    "list_agents",
)

#: Every agent tool name (never visible to a subagent: depth 1).
AGENT_TOOL_NAMES = frozenset(ORCHESTRATOR_AGENT_TOOLS)

#: Tools that refuse to run outside the orchestrator's own turn (they could
#: restart the app the analyst is watching); hidden from subagents.
ORCHESTRATOR_ONLY_TOOL_NAMES = frozenset({"start_spotlight_app"})

#: Tools that hold a device lease across an asynchronous completion (released
#: by a detached worker, not when the dispatch returns). A subagent's
#: ``forget_subtask`` would race that release, so they stay orchestrator-only.
ASYNC_LEASE_TOOL_NAMES = frozenset({"start_replay"})

#: Excluded from every profile regardless of its selector.
ALWAYS_EXCLUDED = (
    AGENT_TOOL_NAMES | ORCHESTRATOR_ONLY_TOOL_NAMES | ASYNC_LEASE_TOOL_NAMES
)

#: Agent states. ``queued``/``running`` are live; the rest are final and equal
#: :attr:`AgentResult.status`.
LIVE_STATES = frozenset({"queued", "running"})
RESULT_STATES = frozenset(
    {"complete", "partial", "failed", "budget_exhausted", "cancelled"}
)

#: Approximate token cap of one ``<subagent-result>`` block.
RESULT_BLOCK_TOKENS = 2000

#: ``wait_agent`` never blocks longer than this (seconds).
MAX_WAIT_AGENT_S = 60.0

#: A ``wait=true`` spawn turns asynchronous after this many seconds (below the
#: ``spawn_agent`` executor timeout in the toolset table).
SYNC_WAIT_CAP_S = 1700.0

#: A ``wait=true`` spawn stops waiting this long before the executor would
#: abandon the ``spawn_agent`` call (at most 10% of the remaining time).
SYNC_WAIT_MARGIN_S = 30.0

_POLL_S = 0.1
#: How long a resume waits for the previous run's result delivery.
_RESUME_SETTLE_S = 10.0
_B32 = "abcdefghijklmnopqrstuvwxyz234567"
_DEFAULT: Any = object()

# =============================================================================
# Profiles
# =============================================================================


@dataclass(frozen=True)
class AgentProfile:
    """A data-defined subagent kind.

    Attributes:
        name: Profile name (the ``spawn_agent`` ``profile`` value).
        description: One line for the tool schema and the UI.
        system_prompt: The agent's system prompt (the session appends the
            toolset catalogue).
        tiers: Risk tiers the agent may use.
        toolsets: Toolsets the agent may use (``None``: every toolset).
        include: Tool names allowed regardless of tiers/toolsets.
        exclude: Tool names never allowed (on top of
            :data:`ALWAYS_EXCLUDED`).
        max_rounds: Round budget per turn (``None``: ``ai.budgets.agent_max_rounds``).
        max_tokens: Token budget per turn (``None``: ``ai.budgets.agent_max_tokens``).
        max_wall_s: Wall-clock budget per turn (``None``:
            ``ai.budgets.agent_max_wall_s``; 0 disables).
        max_concurrent: Concurrency cap (``None``: ``ai.agents.<concurrency_key>``).
        concurrency_key: ``ai.agents`` field holding the default cap.
        default_concurrent: Cap used when neither is available.
        model: Model name (``None``: inherit the parent's client).
        resource_ceiling: Arbiter resources the agent may ever claim
            (``None``: any). Tools needing more are hidden from the agent.
        may_spawn: Profiles this profile may spawn (empty: agents are depth 1).
        spawn_risk: Risk of spawning this profile; ``READ_ONLY`` spawns run
            without asking, anything else goes through the permission rules
            (``spawn_agent(profile=<name>)``) and the approval broker.
    """

    name: str
    description: str
    system_prompt: str
    tiers: frozenset[RiskTier] = frozenset({RiskTier.READ_ONLY})
    toolsets: frozenset[str] | None = None
    include: frozenset[str] = frozenset()
    exclude: frozenset[str] = frozenset()
    max_rounds: int | None = None
    max_tokens: int | None = None
    max_wall_s: float | None = None
    max_concurrent: int | None = None
    concurrency_key: str | None = None
    default_concurrent: int = 1
    model: str | None = None
    resource_ceiling: frozenset[ResourceId] | None = None
    may_spawn: tuple[str, ...] = ()
    spawn_risk: RiskTier = RiskTier.READ_ONLY

    def allows(self, spec: ToolSpec) -> bool:
        """Whether an agent of this profile may see and call *spec*."""
        name = spec.name
        if spec.risk == RiskTier.NOT_EXPOSED:
            return False
        if name in ALWAYS_EXCLUDED or spec.toolset == AGENTS_TOOLSET:
            return False
        if name in self.exclude:
            return False
        if name in META_TOOL_NAMES:
            return True
        if self.resource_ceiling is not None and not (
            frozenset(spec.resources) <= self.resource_ceiling
        ):
            return False
        if name in self.include:
            return True
        if self.toolsets is not None and spec.toolset not in self.toolsets:
            return False
        return spec.risk in self.tiers

    def allowed_predicate(self) -> AllowedPredicate:
        """The :data:`AllowedPredicate` for sessions, tool_search and resolve."""
        return self.allows

    def budgets(self, ai_cfg: Any = None) -> Budgets:
        """Per-turn budgets (profile values, else ``ai.budgets.agent_*``)."""
        cfg = getattr(ai_cfg, "budgets", None)
        rounds = self.max_rounds or int(getattr(cfg, "agent_max_rounds", 20) or 20)
        tokens = (
            self.max_tokens
            if self.max_tokens is not None
            else int(getattr(cfg, "agent_max_tokens", 1_500_000) or 0)
        )
        wall = (
            self.max_wall_s
            if self.max_wall_s is not None
            else float(getattr(cfg, "agent_max_wall_s", 900) or 0)
        )
        return Budgets(
            max_rounds=int(rounds), max_tokens=tokens or None, max_wall_s=wall or None
        )

    def concurrency(self, ai_cfg: Any = None) -> int:
        """How many agents of this profile may run at once (at least 1)."""
        if self.max_concurrent is not None:
            return max(1, int(self.max_concurrent))
        cfg = getattr(ai_cfg, "agents", None)
        if self.concurrency_key and cfg is not None:
            value = getattr(cfg, self.concurrency_key, None)
            if value is not None:
                with contextlib.suppress(TypeError, ValueError):
                    return max(1, int(value))
        return max(1, int(self.default_concurrent))


RESEARCHER = AgentProfile(
    name="researcher",
    description=(
        "read-only investigation (cannot change the device); several may run at once"
    ),
    system_prompt=RESEARCHER_PROMPT,
    tiers=frozenset({RiskTier.READ_ONLY}),
    concurrency_key="researcher_max",
    default_concurrent=3,
    resource_ceiling=frozenset(),
    spawn_risk=RiskTier.READ_ONLY,
)

OPERATOR = AgentProfile(
    name="operator",
    description=(
        "may change the device (every device change still needs the analyst's "
        "approval); one at a time"
    ),
    system_prompt=OPERATOR_PROMPT,
    tiers=frozenset({RiskTier.READ_ONLY, RiskTier.REVERSIBLE, RiskTier.CONSEQUENTIAL}),
    concurrency_key="operator_max",
    default_concurrent=1,
    resource_ceiling=None,
    spawn_risk=RiskTier.CONSEQUENTIAL,
)

#: Built-in profiles by name (dict order = schema enum order).
BUILTIN_PROFILES: dict[str, AgentProfile] = {
    RESEARCHER.name: RESEARCHER,
    OPERATOR.name: OPERATOR,
}


def get_profile(name: str | AgentProfile) -> AgentProfile:
    """Return a profile by name (or the profile itself).

    Raises:
        KeyError: Unknown profile name.
    """
    if isinstance(name, AgentProfile):
        return name
    return BUILTIN_PROFILES[str(name)]


# =============================================================================
# Gateway (process-wide request concurrency)
# =============================================================================


class Gateway:
    """Counts concurrent model requests; one slot is kept for the orchestrator.

    ``acquire(reserved=False)`` (agents) succeeds while fewer than
    ``capacity - 1`` agent requests and fewer than ``capacity`` requests in
    total run; ``reserved=True`` (orchestrator) only needs a free slot. A
    capacity of 1 shares the single slot.
    """

    def __init__(self, capacity: int = 4) -> None:
        """Create a gateway with *capacity* concurrent requests."""
        self._cond = threading.Condition()
        self._capacity = max(1, int(capacity))
        self._in_use = 0
        self._agents_in_use = 0
        self.peak_in_use = 0
        self.peak_agents_in_use = 0

    @property
    def capacity(self) -> int:
        """Total concurrent requests."""
        return self._capacity

    def set_capacity(self, capacity: int) -> None:
        """Change the capacity (takes effect for the next acquire)."""
        with self._cond:
            self._capacity = max(1, int(capacity))
            self._cond.notify_all()

    @property
    def in_use(self) -> int:
        """Requests currently holding a slot."""
        with self._cond:
            return self._in_use

    @property
    def agents_in_use(self) -> int:
        """Agent requests currently holding a slot."""
        with self._cond:
            return self._agents_in_use

    def _agent_limit(self) -> int:
        return max(1, self._capacity - 1)

    def acquire(
        self,
        *,
        reserved: bool = False,
        cancel_event: threading.Event | None = None,
        timeout: float | None = None,
    ) -> bool:
        """Take a slot; returns False when cancelled or timed out."""
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._cond:
            while True:
                free = self._in_use < self._capacity and (
                    reserved or self._agents_in_use < self._agent_limit()
                )
                if free:
                    self._in_use += 1
                    if not reserved:
                        self._agents_in_use += 1
                    self.peak_in_use = max(self.peak_in_use, self._in_use)
                    self.peak_agents_in_use = max(
                        self.peak_agents_in_use, self._agents_in_use
                    )
                    return True
                if cancel_event is not None and cancel_event.is_set():
                    return False
                if deadline is not None and time.monotonic() >= deadline:
                    return False
                self._cond.wait(_POLL_S)

    def release(self, *, reserved: bool = False) -> None:
        """Give a slot back."""
        with self._cond:
            self._in_use = max(0, self._in_use - 1)
            if not reserved:
                self._agents_in_use = max(0, self._agents_in_use - 1)
            self._cond.notify_all()


class GatewayClient:
    """Client wrapper that holds a :class:`Gateway` slot per streamed request.

    The slot is taken when the stream starts and released when it ends or is
    closed (the runtime closes every stream before running tools), so waiting
    for a tool, an approval or a child agent never holds a slot. Every other
    attribute (``model``, ``profile``, ...) is the wrapped client's.
    """

    def __init__(self, inner: Any, gateway: Gateway, *, reserved: bool = False):
        """Wrap *inner*; ``reserved=True`` for the orchestrator."""
        self.__dict__["inner"] = inner
        self.__dict__["gateway"] = gateway
        self.__dict__["reserved"] = reserved

    def __getattr__(self, name: str) -> Any:
        return getattr(self.__dict__["inner"], name)

    def stream(self, messages: list[dict], tools: Any = None, **kwargs: Any):
        """``inner.stream(...)`` inside a gateway slot (a generator)."""
        return self._stream(messages, tools, kwargs)

    def _stream(self, messages: list[dict], tools: Any, kwargs: dict) -> Iterator:
        from sandroid.ai.client import StreamChunk

        cancel = kwargs.get("cancel_event")
        if cancel is not None and cancel.is_set():
            yield StreamChunk("cancelled")
            return
        if not self.gateway.acquire(reserved=self.reserved, cancel_event=cancel):
            yield StreamChunk("cancelled")
            return
        try:
            inner_stream = self.inner.stream(messages, tools, **kwargs)
            try:
                yield from inner_stream
            finally:
                close = getattr(inner_stream, "close", None)
                if close is not None:
                    close()
        finally:
            self.gateway.release(reserved=self.reserved)


def unwrap_client(client: Any) -> Any:
    """Return the client inside any :class:`GatewayClient` layers."""
    while isinstance(client, GatewayClient):
        client = client.inner
    return client


# =============================================================================
# Results
# =============================================================================


@dataclass
class AgentResult:
    """The structured outcome of one subagent run.

    Attributes:
        agent_id: Agent id.
        profile: Profile name.
        status: ``complete``, ``partial``, ``failed``, ``budget_exhausted``
            or ``cancelled``.
        summary: Short answer (never empty).
        claims: ``[{"text", "evidence": [ids], "invalid_evidence"?: [ids]}]``;
            ``evidence`` holds only ids that exist (R-ids in the result store,
            #seq within the timeline).
        open_questions: What the agent could not settle.
        usage: ``prompt_tokens``, ``completion_tokens``, ``reasoning_tokens``,
            ``requests``, ``rounds``.
        transcript_path: Absolute path of the transcript (``None`` in memory).
        title: Display title.
        error: Redacted error for crashes and backend errors.
        parsed: Whether the final report parsed.
        raw_text: The agent's last text.
        undelivered: ``send_to_agent`` messages that arrived after the
            agent's last round (not seen by it).
    """

    agent_id: str
    profile: str
    status: str
    summary: str
    claims: list[dict] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    transcript_path: str | None = None
    title: str = ""
    error: str | None = None
    parsed: bool = False
    raw_text: str = ""
    undelivered: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable form (tool results, events, meta.json)."""
        data = {
            "agent_id": self.agent_id,
            "profile": self.profile,
            "title": self.title,
            "status": self.status,
            "summary": self.summary,
            "claims": [dict(c) for c in self.claims],
            "open_questions": list(self.open_questions),
            "usage": dict(self.usage),
            "transcript_path": self.transcript_path,
            "error": self.error,
            "parsed": self.parsed,
        }
        if self.undelivered:
            data["undelivered_messages"] = list(self.undelivered)
        return data

    @classmethod
    def from_dict(cls, data: dict) -> AgentResult:
        """Rebuild from :meth:`to_dict` output (meta.json)."""
        return cls(
            agent_id=str(data.get("agent_id", "")),
            profile=str(data.get("profile", "")),
            status=str(data.get("status", "partial")),
            summary=str(data.get("summary", "")),
            claims=list(data.get("claims") or []),
            open_questions=list(data.get("open_questions") or []),
            usage=dict(data.get("usage") or {}),
            transcript_path=data.get("transcript_path"),
            title=str(data.get("title", "")),
            error=data.get("error"),
            parsed=bool(data.get("parsed")),
            raw_text=str(data.get("raw_text", "")),
            undelivered=[str(m) for m in data.get("undelivered_messages") or []],
        )


@dataclass
class ParsedReport:
    """What :func:`parse_result` extracts from a final report."""

    status: str
    summary: str
    claims: list[dict]
    open_questions: list[str]


_SECTION_RE = re.compile(
    r"^[\s#>*_]*(status|summary|claims|open questions)[\s*_]*:[\s*_]*(.*)$",
    re.IGNORECASE,
)
_BULLET_RE = re.compile(r"^\s*(?:[-*•+]|\d+[.)])\s+(.*)$")
_EVIDENCE_RE = re.compile(r"(?<![\w#])(R\d+)\b|(?<![\w#])#(\d+)\b")
_TRAILING_REFS_RE = re.compile(r"\s*[\[(]([^\[\]()]*)[\])]\s*[.;,]?\s*$")
_STATUS_ALIASES = {
    "complete": "complete",
    "completed": "complete",
    "done": "complete",
    "partial": "partial",
    "failed": "failed",
    "failure": "failed",
}
_NONE_WORDS = {"none", "n/a", "na", "-", "nothing", "none."}


def _evidence_ids(text: str) -> list[str]:
    ids: list[str] = []
    for match in _EVIDENCE_RE.finditer(text):
        rid = match.group(1) or f"#{match.group(2)}"
        if rid not in ids:
            ids.append(rid)
    return ids


def _split_claim(text: str) -> dict:
    text = " ".join(text.split())
    evidence = _evidence_ids(text)
    clean = text
    trailing = _TRAILING_REFS_RE.search(text)
    if trailing and _evidence_ids(trailing.group(1)):
        clean = text[: trailing.start()].rstrip(" .;,:") or text
    return {"text": clean, "evidence": evidence}


def _bullets(lines: list[str]) -> list[str]:
    items: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        match = _BULLET_RE.match(line)
        if match:
            items.append(match.group(1).strip())
        elif items:
            items[-1] = f"{items[-1]} {line.strip()}"
        else:
            items.append(line.strip())
    return [i for i in items if i]


def parse_result(text: str | None) -> ParsedReport | None:
    """Parse a subagent's final report; ``None`` when it is not in format.

    The report starts at the LAST ``STATUS:`` line; markdown emphasis and
    headings around the labels are tolerated. It parses when the status is
    complete/partial/failed and the summary is not empty.
    """
    if not text:
        return None
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        match = _SECTION_RE.match(line)
        if match and match.group(1).lower() == "status":
            start = index
    if start is None:
        return None
    sections: dict[str, list[str]] = {}
    status_value = ""
    current: str | None = None
    for line in lines[start:]:
        match = _SECTION_RE.match(line)
        if match:
            current = match.group(1).lower()
            rest = match.group(2).strip()
            if current == "status":
                status_value = rest
                current = None
                continue
            sections.setdefault(current, [])
            if rest:
                sections[current].append(rest)
            continue
        if current is not None:
            sections[current].append(line)
    word = re.sub(r"[^a-z]", " ", status_value.lower()).split()
    status = _STATUS_ALIASES.get(word[0]) if word else None
    summary = " ".join(" ".join(sections.get("summary", [])).split())
    if status is None or not summary:
        return None
    claims = [
        _split_claim(item)
        for item in _bullets(sections.get("claims", []))
        if item.strip().lower() not in _NONE_WORDS
    ]
    questions = [
        q
        for q in _bullets(sections.get("open questions", []))
        if q.strip().lower() not in _NONE_WORDS
    ]
    return ParsedReport(status, summary, claims, questions)


def _neutralise(text: str) -> str:
    """Keep agent text from closing or opening a result fence."""
    return re.sub(r"<(/?)subagent-result", r"‹\1subagent-result", str(text))


def _attr(value: str) -> str:
    return _neutralise(value).replace('"', "'").replace("\n", " ")[:120]


def render_result_block(
    result: AgentResult, *, cap_tokens: int = RESULT_BLOCK_TOKENS
) -> str:
    """The fenced ``<subagent-result>`` block delivered to the parent.

    Labelled as subagent data (not analyst instructions) and capped at about
    *cap_tokens* tokens; a cut block points at ``get_agent_result``.
    """
    head = (
        f'<subagent-result id="{result.agent_id}" profile="{result.profile}" '
        f'status="{result.status}"'
        + (f' title="{_attr(result.title)}"' if result.title else "")
        + ">"
    )
    lines = [SUBAGENT_RESULT_PREAMBLE, f"Summary: {_neutralise(result.summary)}"]
    if result.claims:
        lines.append("Claims:")
        for claim in result.claims:
            refs = ", ".join(claim.get("evidence") or [])
            suffix = f" [{refs}]" if refs else " [no valid evidence]"
            lines.append(f"- {_neutralise(claim.get('text', ''))}{suffix}")
    if result.open_questions:
        lines.append("Open questions:")
        lines.extend(f"- {_neutralise(q)}" for q in result.open_questions)
    if result.error:
        lines.append(f"Error: {_neutralise(result.error)}")
    if result.undelivered:
        lines.append(
            f"Undelivered: {len(result.undelivered)} message(s) sent with "
            "send_to_agent arrived after the agent finished; it did not see "
            "them. Send them again to resume it."
        )
    body = "\n".join(lines)
    limit = int(cap_tokens * CHARS_PER_TOKEN)
    if len(body) > limit:
        body = (
            body[: max(0, limit - 120)].rstrip()
            + f"\n[truncated: call get_agent_result('{result.agent_id}') for the "
            "full result]"
        )
    return f"{head}\n{body}\n</subagent-result>"


# =============================================================================
# Records
# =============================================================================


def new_agent_id(profile: str) -> str:
    """``a-<profile[:2]>-<6 base32 chars>``."""
    prefix = re.sub(r"[^a-z0-9]", "x", profile.lower())[:2] or "ag"
    return f"a-{prefix}-{''.join(secrets.choice(_B32) for _ in range(6))}"


@dataclass(eq=False)
class AgentRecord:
    """Live bookkeeping of one subagent (manager-internal; read via ``info``)."""

    id: str
    profile: AgentProfile
    task: str
    title: str
    parent: Any = None  # AgentSession | None
    parent_agent_id: str = ORCHESTRATOR_ID
    parent_thread_id: str | None = None
    parent_tool_call_id: str | None = None
    parent_owner: str | None = None
    root: Path | None = None
    sync: bool = False
    status: str = "queued"
    created: float = field(default_factory=time.time)
    started: float | None = None
    finished: float | None = None
    session: Any = None  # AgentSession | None
    result: AgentResult | None = None
    done: threading.Event = field(default_factory=threading.Event)
    cancel_requested: bool = False
    inbox: list[str] = field(default_factory=list)
    start_text: str = ""
    resume_from_file: bool = False
    usage: dict[str, int] = field(
        default_factory=lambda: {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "reasoning_tokens": 0,
            "requests": 0,
            "rounds": 0,
        }
    )
    live_rounds: int = 0
    last_tool: str | None = None
    events: deque = field(default_factory=lambda: deque(maxlen=4000))
    delivered: bool = False
    delivery: str | None = None
    awaited: int = 0
    runs: int = 0
    #: Set while no run (or its result delivery) is in progress.
    idle: threading.Event = field(default_factory=threading.Event)

    @property
    def label(self) -> str:
        """Agent identity in approval prompts (``operator a-op-3f9c2k``)."""
        return f"{self.profile.name} {self.id}"

    @property
    def agent_dir(self) -> Path | None:
        """``<root>/ai/agents/<id>`` (``None`` in memory)."""
        return None if self.root is None else agents_dir(self.root) / self.id

    @property
    def transcript_path(self) -> Path | None:
        """The agent's thread file (``None`` in memory)."""
        folder = self.agent_dir
        return None if folder is None else folder / "transcript.jsonl"

    @property
    def live(self) -> bool:
        """Queued or running."""
        return self.status in LIVE_STATES


def agents_dir(root: Path) -> Path:
    """``<root>/ai/agents``."""
    return Path(root) / "ai" / "agents"


@dataclass
class _ParentState:
    wakes_used: int = 0
    pending: list[AgentRecord] = field(default_factory=list)
    flushing: bool = False
    waiting: bool = False


def _redact(text: Any) -> str:
    from sandroid.ai.safety import redact_secrets

    return redact_secrets(text)


def _live_ai_config() -> Any:
    from sandroid.ai.session import _live_ai_config as live

    return live()


def _default_thread(fn: Callable[[], None], name: str) -> threading.Thread:
    thread = threading.Thread(target=fn, name=name, daemon=True)
    thread.start()
    return thread


# =============================================================================
# Manager
# =============================================================================

#: ``listener(event)``; called on whatever thread produced the event.
AgentListener = Callable[[AgentEvent], None]
#: ``client_factory(profile, parent_session) -> client`` (unwrapped).
ClientFactory = Callable[[AgentProfile, Any], Any]


class AgentManager:
    """Process-wide owner of every subagent: scheduling, delivery, files.

    Thread safety: public methods may be called from any thread. Each agent
    runs on its own daemon thread (the agent session's turns run inline on
    it). Events reach the parent session's sink (and manager listeners) on
    the thread that produced them, so a UI sink must marshal.
    """

    def __init__(
        self,
        *,
        ai_cfg: Any = None,
        client_factory: ClientFactory | None = None,
        task_registrar: Any = _DEFAULT,
        start_thread: Callable[[Callable[[], None], str], Any] | None = None,
        ambient_provider: Callable[[], str] | None = None,
    ) -> None:
        """Create a manager (normally via :func:`get_agent_manager`).

        Args:
            ai_cfg: ``AIConfig``-like object (default: the live config).
            client_factory: Builds an agent's client (default: the parent's
                client, or a fresh one; a profile ``model`` overrides).
            task_registrar: Toolbox task registrar for ``agent:<id>``
                (default: the session's; ``None`` disables).
            start_thread: ``start_thread(fn, name)`` runs an agent worker.
            ambient_provider: Ambient block for agent turns (default: the
                session's live-state block).
        """
        self._ai_cfg_override = ai_cfg
        self._client_factory = client_factory
        self._task_registrar = task_registrar
        self._start_thread = start_thread or _default_thread
        self._ambient_provider = ambient_provider
        self._lock = threading.RLock()
        self._records: dict[str, AgentRecord] = {}
        self._queue: deque[AgentRecord] = deque()
        self._parents: weakref.WeakValueDictionary[str, Any] = (
            weakref.WeakValueDictionary()
        )
        self._parent_states: dict[int, _ParentState] = {}
        self._listeners: list[AgentListener] = []
        self._used_call_ids: set[str] = set()
        self.gateway = Gateway(self._agents_cfg("gateway_concurrency", 4))

    # -- configuration -----------------------------------------------------------

    def configure(
        self,
        *,
        ai_cfg: Any = _DEFAULT,
        client_factory: Any = _DEFAULT,
        task_registrar: Any = _DEFAULT,
        start_thread: Any = _DEFAULT,
        ambient_provider: Any = _DEFAULT,
    ) -> None:
        """Override collaborators (only the ones passed)."""
        if ai_cfg is not _DEFAULT:
            self._ai_cfg_override = ai_cfg
            self.gateway.set_capacity(self._agents_cfg("gateway_concurrency", 4))
        if client_factory is not _DEFAULT:
            self._client_factory = client_factory
        if task_registrar is not _DEFAULT:
            self._task_registrar = task_registrar
        if start_thread is not _DEFAULT:
            self._start_thread = start_thread or _default_thread
        if ambient_provider is not _DEFAULT:
            self._ambient_provider = ambient_provider

    def ai_cfg(self) -> Any:
        """The ``AIConfig`` in use."""
        if self._ai_cfg_override is not None:
            return self._ai_cfg_override
        return _live_ai_config()

    def _agents_cfg(self, key: str, default: int) -> int:
        cfg = getattr(self.ai_cfg(), "agents", None)
        try:
            return int(getattr(cfg, key, default))
        except (TypeError, ValueError):
            return default

    def gateway_client(self, client: Any, *, reserved: bool = True) -> GatewayClient:
        """Wrap a client so its requests count against the gateway.

        The TUI wraps the orchestrator's client with ``reserved=True`` (the
        slot kept for it) before opening the main session.
        """
        return GatewayClient(unwrap_client(client), self.gateway, reserved=reserved)

    def attach_parent(self, session: Any) -> None:
        """Register an orchestrator session so agent tools can find it.

        Optional: the tools also find the calling session through the run
        context. Held weakly.
        """
        self._parents[session.thread_id] = session

    def add_listener(self, listener: AgentListener) -> Callable[[], None]:
        """Receive every agent event (``agent_*`` and the agents' own events).

        Returns:
            A function that removes the listener.
        """
        with self._lock:
            self._listeners.append(listener)

        def remove() -> None:
            with self._lock, contextlib.suppress(ValueError):
                self._listeners.remove(listener)

        return remove

    # -- spawning ---------------------------------------------------------------------

    def spawn(
        self,
        profile: str | AgentProfile,
        task: str,
        *,
        title: str | None = None,
        parent: Any = None,
        sync: bool = False,
        parent_owner: str | None = None,
        parent_tool_call_id: str | None = None,
        root: Path | None | Any = _DEFAULT,
    ) -> AgentRecord:
        """Create an agent; it starts now or is queued behind the profile cap.

        Args:
            profile: Profile name or object.
            task: The self-contained task.
            title: Display title (default: the task's first line).
            parent: The spawning :class:`~sandroid.ai.session.AgentSession`
                (receives events and the result wake).
            sync: The parent waits (``wait=true``): the child may use the
                parent's leases and its result is not delivered as a wake.
            parent_owner: The parent's arbiter owner (lineage, sync only).
            parent_tool_call_id: The ``spawn_agent`` call id (meta.json).
            root: Session root (default: the parent's root).

        Raises:
            KeyError: Unknown profile.
            ValueError: Empty task.
        """
        prof = get_profile(profile)
        task = str(task or "").strip()
        if not task:
            raise ValueError("the task is empty")
        if root is _DEFAULT:
            root = getattr(parent, "root", None)
        title = " ".join((title or task.splitlines()[0]).split())[:80]
        rec = AgentRecord(
            id=new_agent_id(prof.name),
            profile=prof,
            task=task,
            title=title,
            parent=parent,
            parent_agent_id=getattr(parent, "agent_id", ORCHESTRATOR_ID),
            parent_thread_id=getattr(parent, "thread_id", None),
            parent_tool_call_id=parent_tool_call_id,
            parent_owner=parent_owner or getattr(parent, "agent_id", None),
            root=Path(root) if root is not None else None,
            sync=sync,
        )
        title_part = f" ({title})" if title else ""
        rec.start_text = AGENT_TASK_TEMPLATE.format(title=title_part, task=task)
        rec.idle.clear()
        with self._lock:
            while rec.id in self._records:
                rec.id = new_agent_id(prof.name)
            self._records[rec.id] = rec
            if parent_tool_call_id:
                self._used_call_ids.add(parent_tool_call_id)
            start = self._can_start_locked(prof)
            rec.status = "running" if start else "queued"
            if not start:
                self._queue.append(rec)
        self._write_meta(rec)
        self._emit(
            rec,
            "agent_spawned",
            self._event_payload(rec, task=task, sync=sync),
        )
        if start:
            self._start(rec)
        return rec

    def _can_start_locked(self, profile: AgentProfile) -> bool:
        running = sum(
            1
            for r in self._records.values()
            if r.status == "running" and r.profile.name == profile.name
        )
        return running < profile.concurrency(self.ai_cfg())

    def _start(self, rec: AgentRecord) -> None:
        """Register the arbiter owner, then start the worker thread."""
        lineage = rec.parent_owner if rec.sync else None
        get_arbiter().note_subtask(
            rec.id, parent=lineage, ceiling=rec.profile.resource_ceiling
        )
        rec.started = time.time()
        rec.runs += 1
        self._write_meta(rec)
        self._emit(rec, "agent_status", self._event_payload(rec))
        try:
            self._start_thread(lambda: self._run(rec), f"ai-agent:{rec.id}")
        except Exception as exc:  # the thread never ran: settle here
            logger.exception("Starting agent %s failed", rec.id)
            get_arbiter().forget_subtask(rec.id)
            self._finish(
                rec, self._failed(rec, f"could not start: {type(exc).__name__}: {exc}")
            )

    def _start_queued(self) -> None:
        starts: list[AgentRecord] = []
        with self._lock:
            for rec in list(self._queue):
                if rec.cancel_requested:
                    continue
                if self._can_start_locked(rec.profile):
                    self._queue.remove(rec)
                    rec.status = "running"
                    starts.append(rec)
        for rec in starts:
            self._start(rec)

    # -- the worker -----------------------------------------------------------------

    def _run(self, rec: AgentRecord) -> None:
        result: AgentResult | None = None
        try:
            if rec.cancel_requested:
                result = self._cancelled(rec, "cancelled before it started")
            else:
                session = rec.session
                if session is None:
                    session = self._open_session(rec)
                    rec.session = session
                text = rec.start_text
                turn: TurnResult | None = None
                while True:
                    if rec.cancel_requested:
                        break
                    turn = session.submit_user_message(text).result()
                    self._add_usage(rec, turn.usage, turn.rounds)
                    if rec.cancel_requested or turn.status != "completed":
                        break
                    pending = self._take_inbox(rec)
                    if pending:
                        text = self._inbox_text(pending)
                        continue
                    result = self._build_result(rec, session, turn)
                    # Messages that arrived while the report was built (e.g.
                    # during the format wrap-up) get another round.
                    pending = self._take_inbox(rec)
                    if not pending:
                        break
                    if rec.cancel_requested:
                        with self._lock:  # reported as undelivered
                            rec.inbox[:0] = pending
                        break
                    result = None
                    text = self._inbox_text(pending)
                if result is None:
                    result = self._build_result(rec, session, turn)
        except BaseException as exc:  # never die silently
            logger.exception("Agent %s crashed", rec.id)
            result = self._failed(rec, f"{type(exc).__name__}: {exc}")
        finally:
            with contextlib.suppress(Exception):
                get_arbiter().forget_subtask(rec.id)
            if result is None:
                result = self._failed(rec, "the agent ended without a result")
            try:
                self._finish(rec, result)
            except Exception:
                logger.exception("Finishing agent %s failed", rec.id)
                rec.done.set()
                rec.idle.set()

    def _open_session(self, rec: AgentRecord) -> Any:
        from sandroid.ai.session import AgentSession

        parent = rec.parent
        ai_cfg = getattr(parent, "ai_cfg", None) or self.ai_cfg()
        client = self.gateway_client(self._make_client(rec, ai_cfg), reserved=False)
        kwargs: dict[str, Any] = {
            "kind": "agent",
            "agent_id": rec.id,
            "parent_id": rec.parent_agent_id,
            "agent_label": rec.label,
            "system_prompt": rec.profile.system_prompt,
            "allowed": rec.profile.allowed_predicate(),
            "budgets": rec.profile.budgets(ai_cfg),
            "summaries": False,
            "sink": lambda event: self._on_child_event(rec, event),
            "spawn_worker": lambda fn: fn(),
            "depth": 1,
            "approval_mode": getattr(parent, "approval_mode", "ask"),
            "broker": getattr(parent, "broker", None),
            "thread_path": rec.transcript_path,
        }
        registry = getattr(parent, "registry", None)
        if registry is not None:
            kwargs["registry"] = registry
        if self._task_registrar is not _DEFAULT:
            kwargs["task_registrar"] = self._task_registrar
        if self._ambient_provider is not None:
            kwargs["ambient_provider"] = self._ambient_provider
        path = rec.transcript_path
        if rec.resume_from_file and path is not None and path.is_file():
            session = AgentSession.resume(
                rec.id, root=rec.root, client=client, ai_cfg=ai_cfg, **kwargs
            )
        else:
            session = AgentSession.open_new(
                root=rec.root, client=client, ai_cfg=ai_cfg, thread_id=rec.id, **kwargs
            )
        self._install_round_hook(rec, session)
        return session

    def _make_client(self, rec: AgentRecord, ai_cfg: Any) -> Any:
        if self._client_factory is not None:
            return unwrap_client(self._client_factory(rec.profile, rec.parent))
        base = getattr(rec.parent, "client", None)
        if base is None:
            from sandroid.ai.session import build_session_client

            base = build_session_client(ai_cfg)
        base = unwrap_client(base)
        model = rec.profile.model
        if model and model != getattr(base, "model", None):
            try:
                from sandroid.ai.client import resolve_profile

                base = type(base)(
                    base._base_url,
                    base._api_key,
                    model,
                    options=getattr(base, "_options", None),
                    profile=resolve_profile(model, ai_cfg),
                )
            except Exception:
                logger.warning(
                    "Profile %s: cannot switch to model %r; inheriting",
                    rec.profile.name,
                    model,
                )
        return base

    def _install_round_hook(self, rec: AgentRecord, session: Any) -> None:
        """Deliver ``send_to_agent`` messages and cancels at round boundaries."""
        original = session._before_request

        def before_request(ctx: RunContext, messages: list[dict]) -> list[dict]:
            if rec.cancel_requested:
                ctx.cancel_event.set()
            for text in self._take_inbox(rec):
                msg = {
                    "role": "user",
                    "content": AGENT_MESSAGE_TEMPLATE.format(text=text),
                }
                messages.append(msg)
                with contextlib.suppress(Exception):
                    session._persist_msg(
                        msg, {"kind": "orchestrator_message", "text": text}, ctx.turn_id
                    )
            return original(ctx, messages)

        session._before_request = before_request

    def _take_inbox(self, rec: AgentRecord) -> list[str]:
        with self._lock:
            pending, rec.inbox = rec.inbox, []
        return pending

    @staticmethod
    def _inbox_text(pending: list[str]) -> str:
        return "\n\n".join(AGENT_MESSAGE_TEMPLATE.format(text=t) for t in pending)

    def _add_usage(self, rec: AgentRecord, usage: dict | None, rounds: int) -> None:
        with self._lock:
            for key in ("prompt_tokens", "completion_tokens", "reasoning_tokens"):
                rec.usage[key] = rec.usage.get(key, 0) + int((usage or {}).get(key, 0))
            rec.usage["requests"] = rec.usage.get("requests", 0) + int(
                (usage or {}).get("requests", 0)
            )
            rec.usage["rounds"] = rec.usage.get("rounds", 0) + int(rounds or 0)

    # -- results ------------------------------------------------------------------------

    def _base_result(self, rec: AgentRecord, status: str, summary: str) -> AgentResult:
        path = rec.transcript_path
        return AgentResult(
            agent_id=rec.id,
            profile=rec.profile.name,
            status=status,
            summary=summary,
            usage=dict(rec.usage),
            transcript_path=str(path) if path is not None else None,
            title=rec.title,
        )

    def _failed(self, rec: AgentRecord, error: str) -> AgentResult:
        error = _redact(error)
        result = self._base_result(rec, "failed", f"The agent failed: {error}")
        result.error = error
        return result

    def _cancelled(self, rec: AgentRecord, why: str) -> AgentResult:
        return self._base_result(rec, "cancelled", f"The agent was {why}.")

    def _build_result(
        self, rec: AgentRecord, session: Any, turn: TurnResult | None
    ) -> AgentResult:
        if turn is None or rec.cancel_requested or turn.status == "cancelled":
            text = (turn.final_text if turn else "") or ""
            result = self._cancelled(rec, "cancelled")
            result.raw_text = text
            if text.strip():
                result.summary = f"Cancelled. Last output: {_clip(text, 600)}"
            return result
        text = turn.final_text or ""
        parsed = parse_result(text)
        status: str
        if turn.status == "max_rounds":
            # The runtime already sent its one wrap-up request.
            status = "budget_exhausted"
        elif turn.status in ("error", "content_filter"):
            if parsed is None:
                result = self._failed(rec, turn.error or turn.status)
                result.raw_text = text
                if text.strip():
                    result.summary = (
                        f"The agent stopped with an error ({result.error}). "
                        f"Last output: {_clip(text, 600)}"
                    )
                return result
            status = "failed" if parsed.status == "complete" else parsed.status
        else:
            if parsed is None:
                wrap_text = self._format_wrap_up(rec, session)
                parsed = parse_result(wrap_text)
                if wrap_text.strip():
                    text = wrap_text
            status = parsed.status if parsed is not None else "partial"
            if turn.status == "length" and status == "complete":
                status = "partial"
        result = self._base_result(rec, status, "")
        result.raw_text = text
        if parsed is not None:
            result.parsed = True
            result.summary = parsed.summary
            result.claims = self._validate_claims(session, parsed.claims)
            result.open_questions = parsed.open_questions
        else:
            result.summary = (
                _clip(text, 1500) if text.strip() else "The agent gave no report."
            )
        if turn.error and result.error is None and turn.status != "completed":
            result.error = _redact(turn.error)
        result.usage = dict(rec.usage)
        return result

    def _format_wrap_up(self, rec: AgentRecord, session: Any) -> str:
        """One request asking for the report: same tools, ``tool_choice=none``.

        Reuses the runtime's request path (events, usage, persistence) on the
        session's existing prefix; tool calls in the reply are never run.
        """
        from sandroid.ai import loop as _loop

        if rec.cancel_requested:
            return ""
        try:
            # session.cancel() (cancel_agent, shutdown) sets this event.
            with session._run_lock, session.cancellable() as cancel:
                if rec.cancel_requested:
                    return ""
                ctx = session._make_context(session._current_turn(), cancel)
                runner = _loop._TurnRunner(
                    session.messages, ctx, session.client, session.tools, False
                )
                runner._append(
                    {"role": "user", "content": AGENT_FORMAT_WRAP_UP_PROMPT},
                    {"runtime": "wrap_up", "kind": "agent_report"},
                )
                profile = getattr(session.client, "profile", None)
                choice = "none" if getattr(profile, "tool_choice_none", False) else None
                runner.rounds = 1
                resp = runner._request(1, tool_choice=choice)
                if resp.status != "done":
                    text = runner._append_partial(resp)
                else:
                    runner._append(runner._assistant(resp.text, resp.reasoning))
                    text = resp.text
                self._add_usage(rec, runner.usage, 1)
                return text or ""
        except Exception:
            logger.exception("Agent %s report wrap-up failed", rec.id)
            return ""

    @staticmethod
    def _validate_claims(session: Any, claims: list[dict]) -> list[dict]:
        ids = {i for c in claims for i in c.get("evidence", [])}
        valid: set[str] = set(ids)
        checker = getattr(session, "_valid_ids", None)
        if checker is not None and ids:
            try:
                valid = set(checker(set(ids)))
            except Exception:
                logger.debug("evidence validation failed", exc_info=True)
        out = []
        for claim in claims:
            evidence = [i for i in claim.get("evidence", []) if i in valid]
            bad = [i for i in claim.get("evidence", []) if i not in valid]
            item = {"text": claim.get("text", ""), "evidence": evidence}
            if bad:
                item["invalid_evidence"] = bad
            out.append(item)
        return out

    def _finish(self, rec: AgentRecord, result: AgentResult) -> None:
        with self._lock:
            # A message that arrived after the last inbox check can no longer
            # reach this run: report it instead of losing it.
            late, rec.inbox = rec.inbox, []
            if late:
                result.undelivered = [*result.undelivered, *late]
            result.usage = dict(rec.usage)
            rec.result = result
            rec.status = result.status
            rec.finished = time.time()
            if rec.sync:
                rec.delivery, rec.delivered = "sync", True
            elif rec.awaited > 0:
                rec.delivery, rec.delivered = "waited", True
            elif result.status == "cancelled":
                rec.delivery = "none"
            with contextlib.suppress(ValueError):
                self._queue.remove(rec)
            deliver = rec.delivery is None
            if deliver and not self._parent_open(rec):
                # Epoch guard: the parent thread is gone; files only.
                rec.delivery, deliver = "dropped", False
        try:
            self._write_meta(rec)
            self._emit(
                rec,
                "agent_result",
                {
                    **self._event_payload(rec),
                    **result.to_dict(),
                    "delivery": rec.delivery,
                },
            )
            rec.done.set()
            if deliver:
                self._deliver(rec)
        finally:
            # A resume (send_to_agent) waits for this before resetting rec.
            rec.idle.set()
        self._start_queued()

    # -- delivery -----------------------------------------------------------------------

    def _state(self, parent: Any) -> _ParentState:
        with self._lock:
            return self._parent_states.setdefault(id(parent), _ParentState())

    def _parent_open(self, rec: AgentRecord) -> bool:
        parent = rec.parent
        return (
            parent is not None
            and not getattr(parent, "closed", False)
            and getattr(parent, "thread_id", None) == rec.parent_thread_id
        )

    def _deliver(self, rec: AgentRecord) -> None:
        if not self._parent_open(rec):
            with self._lock:
                rec.delivery = "dropped"
            logger.info("Agent %s finished after its parent thread closed", rec.id)
            self._write_meta(rec)
            return
        state = self._state(rec.parent)
        with self._lock:
            if not rec.delivered and rec not in state.pending:
                state.pending.append(rec)
        self._flush(rec.parent)

    def _flush(self, parent: Any) -> None:
        """Deliver pending results as ONE wake once the parent is idle.

        Results that arrive while the parent runs a turn (an analyst turn, a
        previous wake, a ``wait=true`` spawn) are held and coalesced; a
        helper thread waits for the parent to go idle and flushes them.
        """
        state = self._state(parent)
        start_waiter = False
        with self._lock:
            if state.flushing:
                return
            state.pending = [r for r in state.pending if not r.delivered]
            if not state.pending:
                return
            if getattr(parent, "closed", False):
                for r in state.pending:
                    r.delivery = "dropped"
                state.pending = []
                return
            if state.wakes_used >= self._agents_cfg("max_auto_wakes", 3):
                return
            if getattr(parent, "running", False):
                if state.waiting:
                    return
                state.waiting = True
                start_waiter = True
                batch: list[AgentRecord] = []
            else:
                batch, state.pending = state.pending, []
                state.wakes_used += 1
                state.flushing = True
                for r in batch:
                    r.delivered, r.delivery = True, "wake"
        if start_waiter:
            _default_thread(lambda: self._flush_when_idle(parent), "ai-agent-deliver")
            return
        text = "\n\n".join(render_result_block(r.result) for r in batch if r.result)
        meta = {"source": "agents", "agent_ids": [r.id for r in batch]}
        try:
            parent.enqueue_wake(text, meta)
        except Exception:
            logger.exception("Waking the parent with agent results failed")
        finally:
            with self._lock:
                state.flushing = False
        for r in batch:
            self._write_meta(r)
        # Results that arrived while this wake was being enqueued (an inline
        # worker runs the whole wake turn inside enqueue_wake).
        self._flush(parent)

    def _flush_when_idle(self, parent: Any) -> None:
        state = self._state(parent)
        try:
            parent.wait_idle()
        except Exception:
            logger.debug("wait_idle failed", exc_info=True)
        finally:
            with self._lock:
                state.waiting = False
        self._flush(parent)

    def note_analyst_message(self, parent: Any) -> int:
        """Reset the automatic-wake budget of *parent* (call per analyst message).

        Results held back because the budget was used up are then delivered
        as one coalesced wake once the parent is idle. Call it right after
        ``submit_user_message`` so the analyst's turn runs first.

        Returns:
            How many held-back results are now being delivered.
        """
        state = self._state(parent)
        with self._lock:
            state.wakes_used = 0
            count = sum(1 for r in state.pending if not r.delivered)
        self._flush(parent)
        return count

    def pending_results(self, parent: Any) -> list[str]:
        """Agent ids whose results wait for an automatic wake."""
        state = self._state(parent)
        with self._lock:
            return [r.id for r in state.pending if not r.delivered]

    # -- events ---------------------------------------------------------------------

    def _event_payload(self, rec: AgentRecord, **extra: Any) -> dict[str, Any]:
        now = time.time()
        end = rec.finished or now
        payload = {
            "agent_id": rec.id,
            "profile": rec.profile.name,
            "title": rec.title,
            "status": rec.status,
            "rounds": rec.usage.get("rounds", 0) + rec.live_rounds,
            "last_tool": rec.last_tool,
            "usage": dict(rec.usage),
            "elapsed_s": round(end - (rec.started or rec.created), 1),
            "sync": rec.sync,
            "parent_tool_call_id": rec.parent_tool_call_id,
            "transcript_path": (
                str(rec.transcript_path) if rec.transcript_path is not None else None
            ),
        }
        payload.update(extra)
        return payload

    def _emit(self, rec: AgentRecord, type_: str, payload: dict[str, Any]) -> None:
        """Send an event about *rec* to its parent's sink and the listeners."""
        parent = rec.parent
        seq = 0
        if parent is not None:
            with contextlib.suppress(Exception):
                seq = next(parent._seq)
        event = AgentEvent(
            type=type_,
            agent_id=rec.id,
            parent_id=rec.parent_agent_id,
            thread_id=rec.parent_thread_id or "",
            turn_id="",
            seq=seq,
            ts=time.time(),
            payload=payload,
        )
        if self._parent_open(rec):
            try:
                parent._on_event(event)
            except Exception:
                logger.exception("Parent sink failed for %s", type_)
        self._notify(event)

    def _notify(self, event: AgentEvent) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(event)
            except Exception:
                logger.exception("Agent listener failed")

    def _on_child_event(self, rec: AgentRecord, event: AgentEvent) -> None:
        rec.events.append(event)
        etype = event.type
        if etype == "request_start":
            rec.live_rounds += 1
        elif etype == "turn_end":
            rec.live_rounds = 0
        self._notify(event)
        if etype in ("approval_request", "approval_resolved"):
            # The analyst must see an agent's approval prompts in the main
            # transcript; the payload already names the agent.
            self._emit(rec, etype, dict(event.payload))
        elif etype == "tool_result":
            rec.last_tool = event.payload.get("name")
            self._emit(rec, "agent_status", self._event_payload(rec))

    # -- queries ------------------------------------------------------------------------

    def get(self, agent_id: str) -> AgentRecord | None:
        """The record of *agent_id* (``None`` if unknown)."""
        with self._lock:
            return self._records.get(agent_id)

    def result(self, agent_id: str) -> AgentResult | None:
        """The final result (``None`` while live or unknown)."""
        rec = self.get(agent_id)
        return None if rec is None else rec.result

    def info(self, agent_id: str) -> dict[str, Any] | None:
        """A UI/tool snapshot of one agent (``None`` if unknown)."""
        rec = self.get(agent_id)
        if rec is None:
            return None
        with self._lock:
            data = self._event_payload(rec, task=rec.task)
            data["queued_position"] = (
                list(self._queue).index(rec) + 1 if rec in self._queue else None
            )
            data["delivery"] = rec.delivery
            data["inbox"] = len(rec.inbox)
            if rec.result is not None:
                data["result"] = rec.result.to_dict()
        return data

    def list(self, parent: Any = None, *, live_only: bool = False) -> list[dict]:
        """Snapshots of the agents of *parent* (``None``: all), newest first."""
        with self._lock:
            recs = [
                r
                for r in self._records.values()
                if (parent is None or r.parent is parent) and (not live_only or r.live)
            ]
        recs.sort(key=lambda r: r.created, reverse=True)
        return [i for i in (self.info(r.id) for r in recs) if i is not None]

    def transcript_events(self, agent_id: str) -> list[AgentEvent]:
        """The agent's buffered events (deltas included) for a transcript view.

        The persisted thread is at ``info(id)["transcript_path"]``
        (``ConversationStore.read``).
        """
        rec = self.get(agent_id)
        return [] if rec is None else list(rec.events)

    def live_owner_ids(self) -> set[str]:
        """Arbiter owners that are alive: the orchestrator plus running agents."""
        with self._lock:
            running = {r.id for r in self._records.values() if r.status == "running"}
        return {ORCHESTRATOR_ID} | running

    def reconcile_leases(self) -> None:
        """Drop leases of dead owners (call from a ~1 s UI timer).

        An owner whose abandoned tool call still runs counts as live in the
        arbiter, and a lease an in-flight call uses is only released when
        that call's thread exits.
        """
        try:
            get_arbiter().reconcile(self.live_owner_ids())
        except Exception:
            logger.debug("Arbiter reconcile failed", exc_info=True)

    def usage_totals(self, parent: Any = None) -> dict[str, int]:
        """Summed agent usage (for the parent's header roll-up)."""
        totals: dict[str, int] = {}
        with self._lock:
            for r in self._records.values():
                if parent is not None and r.parent is not parent:
                    continue
                for key, value in r.usage.items():
                    totals[key] = totals.get(key, 0) + int(value)
        return totals

    def running_count(self, parent: Any = None) -> int:
        """Live (running or queued) agents of *parent*."""
        with self._lock:
            return sum(
                1
                for r in self._records.values()
                if r.live and (parent is None or r.parent is parent)
            )

    # -- waiting --------------------------------------------------------------------

    def wait(
        self,
        agent_id: str,
        timeout: float | None = None,
        *,
        cancel_event: threading.Event | None = None,
    ) -> AgentResult | None:
        """Block until *agent_id* finishes; ``None`` on timeout/cancel.

        A result returned here is not also delivered as a wake.
        """
        rec = self.get(agent_id)
        if rec is None:
            raise KeyError(agent_id)
        with self._lock:
            if rec.result is not None and not rec.live:
                self._mark_taken_locked(rec, "waited")
                return rec.result
            rec.awaited += 1
            done = rec.done
        deadline = None if timeout is None else time.monotonic() + timeout
        try:
            while not done.wait(_POLL_S):
                if cancel_event is not None and cancel_event.is_set():
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    break
        finally:
            with self._lock:
                rec.awaited -= 1
                finished = rec.result is not None and not rec.live
                if finished:
                    self._mark_taken_locked(rec, rec.delivery or "waited")
        return rec.result if finished else None

    def _mark_taken_locked(self, rec: AgentRecord, how: str) -> None:
        if not rec.delivered:
            rec.delivered = True
            rec.delivery = how
        parent = rec.parent
        if parent is not None:
            state = self._parent_states.get(id(parent))
            if state is not None and rec in state.pending:
                state.pending.remove(rec)

    def wait_sync(
        self,
        agent_id: str,
        *,
        cancel_event: threading.Event | None = None,
        max_wait: float = SYNC_WAIT_CAP_S,
    ) -> AgentResult | None:
        """Wait for a ``sync`` child of a blocked parent.

        If the parent's turn is cancelled the child is cancelled too. After
        *max_wait* the child turns asynchronous (lineage dropped, result
        delivered as a wake) and ``None`` is returned.
        """
        rec = self.get(agent_id)
        if rec is None:
            raise KeyError(agent_id)
        deadline = time.monotonic() + max_wait
        while not rec.done.wait(_POLL_S):
            if cancel_event is not None and cancel_event.is_set():
                self.cancel(agent_id)
                rec.done.wait(10.0)
                break
            if time.monotonic() >= deadline:
                with self._lock:
                    converted = rec.live
                    if converted:
                        # Background delivery from now on: no parent leases,
                        # the result arrives as a wake.
                        rec.sync = False
                        get_arbiter().set_parent(rec.id, None)
                if converted:
                    self._write_meta(rec)
                    self._emit(rec, "agent_status", self._event_payload(rec))
                    return None
                break
        return rec.result

    def take_result(self, agent_id: str) -> AgentResult | None:
        """The final result, marked as delivered (no later wake for it)."""
        rec = self.get(agent_id)
        if rec is None:
            raise KeyError(agent_id)
        with self._lock:
            if rec.result is None or rec.live:
                return None
            self._mark_taken_locked(rec, "fetched")
            return rec.result

    # -- control ----------------------------------------------------------------------

    def cancel(self, agent_id: str) -> bool:
        """Cancel a queued or running agent; its final record is still written."""
        rec = self.get(agent_id)
        if rec is None:
            return False
        with self._lock:
            if not rec.live:
                return False
            rec.cancel_requested = True
            queued = rec.status == "queued"
            if queued:
                with contextlib.suppress(ValueError):
                    self._queue.remove(rec)
            session = rec.session
        if queued:
            self._finish(rec, self._cancelled(rec, "cancelled before it started"))
            return True
        if session is not None:
            with contextlib.suppress(Exception):
                session.cancel()
        with contextlib.suppress(Exception):
            broker = getattr(rec.parent, "broker", None) or _perms.get_approval_broker()
            broker.cancel_agent(rec.id)
        return True

    def cancel_all(self, parent: Any = None) -> int:
        """Cancel every live agent of *parent* (``None``: all). Ctrl+L / ``/new``."""
        with self._lock:
            ids = [
                r.id
                for r in self._records.values()
                if r.live and (parent is None or r.parent is parent)
            ]
        return sum(1 for agent_id in ids if self.cancel(agent_id))

    def send(
        self,
        agent_id: str,
        text: str,
        *,
        parent: Any = None,
        authorize: Callable[[AgentRecord], None] | None = None,
    ) -> dict[str, Any]:
        """Send *text* to an agent.

        A live agent gets it at its next round boundary (or as a follow-up
        turn); a finished one is resumed from its transcript with it, and its
        new result is delivered like a fresh one.

        Args:
            agent_id: The agent.
            text: The message.
            parent: The calling session (resume reattaches to it).
            authorize: Called (without the manager lock) before a finished
                agent is resumed; raises to refuse. Resuming starts the
                agent again, so it needs the same approval as spawning it.

        Raises:
            KeyError: Unknown agent.
            ValueError: Empty text.
        """
        text = str(text or "").strip()
        if not text:
            raise ValueError("the message is empty")
        rec = self.get(agent_id) or self._load_record(agent_id, parent)
        if rec is None:
            raise KeyError(agent_id)
        with self._lock:
            if rec.live:
                rec.inbox.append(text)
                return {
                    "agent_id": rec.id,
                    "status": rec.status,
                    "delivery": "next_round",
                }
        if authorize is not None:
            authorize(rec)
        # The previous run may still be delivering its result.
        rec.idle.wait(_RESUME_SETTLE_S)
        with self._lock:
            if rec.live:  # resumed by someone else meanwhile
                rec.inbox.append(text)
                return {
                    "agent_id": rec.id,
                    "status": rec.status,
                    "delivery": "next_round",
                }
            if parent is not None and rec.parent is None:
                rec.parent = parent
                rec.parent_thread_id = getattr(parent, "thread_id", None)
            rec.result = None
            rec.done = threading.Event()
            rec.cancel_requested = False
            rec.sync = False
            rec.delivered = False
            rec.delivery = None
            rec.finished = None
            rec.start_text = AGENT_MESSAGE_TEMPLATE.format(text=text)
            rec.idle.clear()
            start = self._can_start_locked(rec.profile)
            rec.status = "running" if start else "queued"
            if not start:
                self._queue.append(rec)
        self._write_meta(rec)
        if start:
            self._start(rec)
        else:
            self._emit(rec, "agent_status", self._event_payload(rec))
        return {"agent_id": rec.id, "status": rec.status, "delivery": "resumed"}

    def _load_record(self, agent_id: str, parent: Any) -> AgentRecord | None:
        """Rebuild a finished agent from its meta.json (resume after restart)."""
        root = getattr(parent, "root", None)
        if root is None or not re.match(r"^a-[a-z0-9]{2}-[a-z2-7]{6}$", agent_id):
            return None
        meta_path = agents_dir(root) / agent_id / "meta.json"
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            profile = get_profile(meta["profile"])
        except (OSError, ValueError, KeyError):
            return None
        if meta.get("parent_thread_id") != getattr(parent, "thread_id", None):
            # Only agents spawned from the calling thread can be resumed.
            return None
        rec = AgentRecord(
            id=agent_id,
            profile=profile,
            task=str(meta.get("task", "")),
            title=str(meta.get("title", "")),
            parent=parent,
            parent_agent_id=getattr(parent, "agent_id", ORCHESTRATOR_ID),
            parent_thread_id=getattr(parent, "thread_id", None),
            parent_owner=getattr(parent, "agent_id", None),
            root=Path(root),
            status="partial",
            resume_from_file=True,
        )
        if isinstance(meta.get("result"), dict):
            rec.result = AgentResult.from_dict(meta["result"])
            rec.status = rec.result.status
        rec.usage.update({k: int(v) for k, v in (meta.get("usage") or {}).items()})
        rec.done.set()
        rec.idle.set()
        with self._lock:
            return self._records.setdefault(agent_id, rec)

    def shutdown(self, timeout: float = 2.0) -> None:
        """Cancel everything and wait briefly (never unbounded)."""
        self.cancel_all()
        deadline = time.monotonic() + timeout
        with self._lock:
            recs = list(self._records.values())
        for rec in recs:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            rec.done.wait(remaining)

    # -- persistence ------------------------------------------------------------------

    def _write_meta(self, rec: AgentRecord) -> None:
        folder = rec.agent_dir
        if folder is None:
            return
        with self._lock:
            data = {
                "v": 1,
                "agent_id": rec.id,
                "profile": rec.profile.name,
                "title": rec.title,
                "task": rec.task,
                "status": rec.status,
                "parent_agent_id": rec.parent_agent_id,
                "parent_thread_id": rec.parent_thread_id,
                "parent_tool_call_id": rec.parent_tool_call_id,
                "sync": rec.sync,
                "created": rec.created,
                "started": rec.started,
                "finished": rec.finished,
                "runs": rec.runs,
                "usage": dict(rec.usage),
                "delivery": rec.delivery,
                "model": rec.profile.model,
                "transcript": "transcript.jsonl",
                "result": rec.result.to_dict() if rec.result is not None else None,
            }
        try:
            ensure_private_dir(folder)
            tmp = folder / f".meta.{os.getpid()}.{threading.get_ident()}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=1, default=str)
            tmp.replace(folder / "meta.json")
        except OSError:
            logger.exception("Writing meta.json of agent %s failed", rec.id)

    # -- parent lookup (tools) --------------------------------------------------------

    def parent_for(self, ctx: RunContext | None) -> Any:
        """The session whose turn runs *ctx* (attached, else via its sink)."""
        if ctx is None:
            return None
        session = self._parents.get(ctx.thread_id)
        if session is not None:
            return session
        owner = getattr(ctx.sink, "__self__", None)
        if owner is not None and getattr(owner, "thread_id", None) == ctx.thread_id:
            return owner
        return None

    def find_tool_call_id(self, parent: Any, arguments: dict) -> str | None:
        """Best-effort id of the ``spawn_agent`` call that carries *arguments*."""
        messages = list(getattr(parent, "messages", []) or [])
        for msg in reversed(messages):
            if msg.get("role") != "assistant" or not msg.get("tool_calls"):
                continue
            for call in msg["tool_calls"]:
                fn = call.get("function") or {}
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    continue
                if not isinstance(args, dict):
                    continue
                if fn.get("name") == "call_tool" and args.get("name") == "spawn_agent":
                    inner = args.get("arguments")
                    if isinstance(inner, str):
                        with contextlib.suppress(ValueError):
                            inner = json.loads(inner)
                    args = inner if isinstance(inner, dict) else {}
                elif fn.get("name") != "spawn_agent":
                    continue
                call_id = call.get("id")
                with self._lock:
                    used = call_id in self._used_call_ids
                if (
                    call_id
                    and not used
                    and args.get("task") == arguments.get("task")
                    and args.get("profile") == arguments.get("profile")
                ):
                    return call_id
            return None
        return None


def _clip(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


_manager: AgentManager | None = None
_manager_lock = threading.Lock()


def get_agent_manager() -> AgentManager:
    """The process-wide :class:`AgentManager`."""
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = AgentManager()
        return _manager


def reset_for_tests() -> None:
    """Cancel every agent and drop the singleton (test isolation)."""
    global _manager
    with _manager_lock:
        manager, _manager = _manager, None
    if manager is not None:
        with contextlib.suppress(Exception):
            manager.shutdown(timeout=1.0)


# =============================================================================
# Orchestrator tools
# =============================================================================


def _calling_context() -> tuple[RunContext, Any]:
    ctx = current_run_context()
    if ctx is None:
        raise ToolError(
            "tool_failed", "agent tools can only be used inside an orchestrator turn"
        )
    if ctx.kind == "agent" or ctx.depth > 0:
        raise ToolError(
            "denied",
            "subagents cannot use agent tools (agents cannot spawn agents)",
            hint="Report back to the orchestrator instead.",
        )
    return ctx, get_agent_manager().parent_for(ctx)


def _own_record(agent_id: str, parent: Any) -> AgentRecord:
    manager = get_agent_manager()
    rec = manager.get(str(agent_id or ""))
    if rec is None and parent is not None:
        rec = manager._load_record(str(agent_id or ""), parent)
    if rec is None or (parent is not None and rec.parent not in (parent, None)):
        raise ToolError(
            "invalid_arguments",
            f"no agent {agent_id!r} in this conversation",
            hint="Call list_agents for the ids.",
        )
    return rec


def _authorize_spawn(ctx: RunContext, profile: AgentProfile, args: dict) -> None:
    """Permission check for spawning *profile* (argument-dependent risk).

    The executor already applied deny rules (``spawn_agent`` is registered
    read-only); a profile with a ``spawn_risk`` above read-only goes through
    the rules again under that risk, keyed by ``profile`` so "don't ask
    again" is remembered per profile, and through the approval broker.
    """
    if profile.spawn_risk == RiskTier.READ_ONLY:
        return
    resolution = _perms.resolve(
        "spawn_agent", profile.spawn_risk, args, permission_key="profile"
    )
    if resolution.allowed:
        return
    if resolution.denied:
        raise ToolError(
            "denied",
            f"spawning a {profile.name} agent is blocked by a permission rule",
            hint="Do not retry; tell the analyst it is blocked.",
        )
    if ctx.approval_mode != "ask":
        raise ToolError(
            "denied",
            f"spawning a {profile.name} agent needs the analyst's approval, but "
            "nobody can approve it here",
        )
    broker = ctx.broker or _perms.get_approval_broker()
    pending = broker.submit(
        agent_id=ctx.agent_id,
        agent_label=ctx.agent_label,
        tool="spawn_agent",
        args=dict(args),
        risk=profile.spawn_risk,
        suggested_rule=resolution.suggested_rule,
        description=f"Start a {profile.name} subagent: {profile.description}",
        argument_dependent=True,
    )
    request = pending.request
    ctx.emit(
        "approval_request",
        request_id=request.request_id,
        agent_id=request.agent_id,
        agent_label=request.agent_label,
        tool="spawn_agent",
        args=dict(args),
        risk=profile.spawn_risk.name.lower(),
        suggested_rule=request.suggested_rule,
        rule_description=request.suggested_rule_description,
        argument_dependent=True,
    )
    decision = pending.wait(cancel_event=ctx.cancel_event)
    ctx.emit(
        "approval_resolved",
        request_id=request.request_id,
        tool="spawn_agent",
        decision=decision.choice,
        note=decision.note,
        remembered_rule=decision.remembered_rule,
        by=decision.by,
    )
    if decision.approved:
        return
    if decision.by == "cancelled":
        raise ToolError("cancelled", "the turn was cancelled during approval")
    message = f"The analyst declined starting a {profile.name} agent."
    if decision.note:
        message += f" Their note: {decision.note}"
    raise ToolError(
        "denied",
        message,
        hint="Do not retry the same call; follow the analyst's note if any.",
        details={"note": decision.note} if decision.note else None,
    )


def spawn_agent(
    profile: str, task: str, title: str | None = None, wait: bool = False
) -> dict:
    """Start a subagent (see the tool description)."""
    ctx, parent = _calling_context()
    try:
        prof = get_profile(profile)
    except KeyError:
        raise ToolError(
            "invalid_arguments",
            f"unknown profile {profile!r}",
            hint=f"Use one of: {', '.join(BUILTIN_PROFILES)}.",
        ) from None
    if not str(task or "").strip():
        raise ToolError("invalid_arguments", "task must not be empty")
    args = {"profile": prof.name, "task": task}
    if title:
        args["title"] = title
    args["wait"] = bool(wait)
    _authorize_spawn(ctx, prof, args)
    manager = get_agent_manager()
    call_id = (
        manager.find_tool_call_id(parent, {"profile": profile, "task": task})
        if parent is not None
        else None
    )
    rec = manager.spawn(
        prof,
        task,
        title=title,
        parent=parent,
        sync=bool(wait),
        parent_owner=ctx.owner_id,
        parent_tool_call_id=call_id,
    )
    base = {
        "agent_id": rec.id,
        "profile": prof.name,
        "title": rec.title,
        "task": task,
    }
    if not wait:
        return {
            **base,
            "status": rec.status,
            "note": (
                "The agent runs in the background; its result arrives later as a "
                "<subagent-result> message. Continue with other work, or call "
                "wait_agent."
            ),
        }
    result = manager.wait_sync(
        rec.id, cancel_event=ctx.cancel_event, max_wait=_sync_wait_budget()
    )
    if result is None:
        return {
            **base,
            "status": "running",
            "note": (
                "Still running after the wait limit; the result will arrive as a "
                "<subagent-result> message."
            ),
        }
    return {**base, **result.to_dict()}


def _sync_wait_budget() -> float:
    """How long a ``wait=true`` spawn may wait (measured after approval).

    Capped at :data:`SYNC_WAIT_CAP_S` and to the executor time left for the
    ``spawn_agent`` call minus a margin, so the executor never abandons the
    call while a synchronous child still uses the parent's leases; the child
    turns asynchronous first.
    """
    from sandroid.ai.loop import tool_time_remaining

    remaining = tool_time_remaining()
    if remaining is None:
        return SYNC_WAIT_CAP_S
    margin = min(SYNC_WAIT_MARGIN_S, remaining * 0.1)
    return max(0.0, min(SYNC_WAIT_CAP_S, remaining - margin))


def wait_agent(agent_id: str, timeout_s: float = 30) -> dict:
    """Wait up to 60 s for an agent's result (see the tool description)."""
    ctx, parent = _calling_context()
    rec = _own_record(agent_id, parent)
    try:
        timeout = float(timeout_s)
    except (TypeError, ValueError):
        timeout = 30.0
    timeout = max(0.0, min(MAX_WAIT_AGENT_S, timeout))
    result = get_agent_manager().wait(rec.id, timeout, cancel_event=ctx.cancel_event)
    if result is None:
        info = get_agent_manager().info(rec.id) or {}
        return {
            "agent_id": rec.id,
            "status": info.get("status", rec.status),
            "rounds": info.get("rounds"),
            "last_tool": info.get("last_tool"),
            "note": "Not finished yet; the result will arrive as a message.",
        }
    return result.to_dict()


def get_agent_result(agent_id: str) -> dict:
    """Return an agent's result or its current state."""
    _ctx, parent = _calling_context()
    rec = _own_record(agent_id, parent)
    result = get_agent_manager().take_result(rec.id)
    if result is None:
        info = get_agent_manager().info(rec.id) or {}
        return {
            "agent_id": rec.id,
            "status": info.get("status", rec.status),
            "rounds": info.get("rounds"),
            "last_tool": info.get("last_tool"),
            "queued_position": info.get("queued_position"),
        }
    return result.to_dict()


def cancel_agent(agent_id: str) -> dict:
    """Cancel a queued or running agent."""
    _ctx, parent = _calling_context()
    rec = _own_record(agent_id, parent)
    cancelled = get_agent_manager().cancel(rec.id)
    return {
        "agent_id": rec.id,
        "cancelled": cancelled,
        "status": rec.status,
        "note": None if cancelled else "the agent had already finished",
    }


def send_to_agent(agent_id: str, text: str) -> dict:
    """Send a message to an agent (next round, or resume a finished one)."""
    ctx, parent = _calling_context()
    rec = _own_record(agent_id, parent)

    def authorize(target: AgentRecord) -> None:
        # Resuming runs the agent again: same approval as spawning it.
        args = {
            "profile": target.profile.name,
            "task": str(text or ""),
            "resume": target.id,
        }
        _authorize_spawn(ctx, target.profile, args)

    try:
        return get_agent_manager().send(
            rec.id, text, parent=parent, authorize=authorize
        )
    except ValueError as exc:
        raise ToolError("invalid_arguments", str(exc)) from None


def list_agents() -> dict:
    """List this conversation's agents."""
    _ctx, parent = _calling_context()
    rows = []
    for info in get_agent_manager().list(parent):
        row = {
            k: info.get(k)
            for k in (
                "agent_id",
                "profile",
                "title",
                "status",
                "rounds",
                "last_tool",
                "elapsed_s",
                "queued_position",
                "delivery",
            )
        }
        rows.append(row)
    return {"agents": rows}


def _profile_enum_text() -> str:
    return "; ".join(f"{p.name}: {p.description}" for p in BUILTIN_PROFILES.values())


def _agent_id_param() -> dict:
    return {"type": "string", "description": "Agent id, e.g. a-re-k3j9qa."}


def agent_tool_specs() -> list[ToolSpec]:
    """The orchestrator agent tools as :class:`ToolSpec` objects."""
    no_args = {"type": "object", "properties": {}, "required": []}
    return [
        ToolSpec(
            name="spawn_agent",
            description=(
                "Start a subagent with its own context for a self-contained task. "
                f"Profiles: {_profile_enum_text()}. By default returns at once and "
                "the result arrives later as a <subagent-result> message; "
                "wait=true blocks until the result is ready. The agent does not "
                "see this conversation, so the task must include everything it "
                "needs."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "profile": {
                        "type": "string",
                        "enum": list(BUILTIN_PROFILES),
                        "description": "Agent profile.",
                    },
                    "task": {
                        "type": "string",
                        "description": "Self-contained task with all needed context.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Short label shown to the analyst.",
                    },
                    "wait": {
                        "type": "boolean",
                        "description": "Block until the result is ready.",
                    },
                },
                "required": ["profile", "task"],
            },
            func=spawn_agent,
            risk=RiskTier.READ_ONLY,
            category="agents",
        ),
        ToolSpec(
            name="wait_agent",
            description=(
                "Wait up to timeout_s seconds (max 60) for a subagent's result. "
                "Returns the result, or its state if still running."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "agent_id": _agent_id_param(),
                    "timeout_s": {
                        "type": "number",
                        "description": "Seconds to wait, at most 60.",
                    },
                },
                "required": ["agent_id"],
            },
            func=wait_agent,
            risk=RiskTier.READ_ONLY,
            category="agents",
        ),
        ToolSpec(
            name="get_agent_result",
            description=(
                "Return a subagent's full result (status, summary, claims with "
                "evidence ids, open questions) or its current state."
            ),
            parameters={
                "type": "object",
                "properties": {"agent_id": _agent_id_param()},
                "required": ["agent_id"],
            },
            func=get_agent_result,
            risk=RiskTier.READ_ONLY,
            category="agents",
        ),
        ToolSpec(
            name="cancel_agent",
            description="Cancel a queued or running subagent.",
            parameters={
                "type": "object",
                "properties": {"agent_id": _agent_id_param()},
                "required": ["agent_id"],
            },
            func=cancel_agent,
            risk=RiskTier.READ_ONLY,
            category="agents",
        ),
        ToolSpec(
            name="send_to_agent",
            description=(
                "Send a message to a subagent. A running agent gets it before "
                "its next model request; a finished agent resumes from its "
                "transcript and reports again."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "agent_id": _agent_id_param(),
                    "text": {"type": "string", "description": "The message."},
                },
                "required": ["agent_id", "text"],
            },
            func=send_to_agent,
            risk=RiskTier.READ_ONLY,
            category="agents",
        ),
        ToolSpec(
            name="list_agents",
            description="List this conversation's subagents and their state.",
            parameters=no_args,
            func=list_agents,
            risk=RiskTier.READ_ONLY,
            category="agents",
        ),
    ]


def register_agent_tools(registry: ToolRegistry | None = None) -> None:
    """Register the agent tools (idempotent: re-registering replaces)."""
    reg = registry or get_tool_registry()
    for spec in agent_tool_specs():
        reg.register(spec)


def orchestrator_extra_tools(registry: ToolRegistry | None = None) -> tuple[str, ...]:
    """Make sure the agent tools are registered; return their names.

    The agent tools are registered lazily (not on import), so only a caller
    that exposes them to an orchestrator puts them into a registry. Pass the
    result as ``extra_tools`` to the orchestrator's
    :meth:`~sandroid.ai.session.AgentSession.open_new`.
    """
    reg = registry or get_tool_registry()
    if any(reg.get_spec(name) is None for name in ORCHESTRATOR_AGENT_TOOLS):
        register_agent_tools(reg)
    return ORCHESTRATOR_AGENT_TOOLS


def with_profile_overrides(profile: AgentProfile, **changes: Any) -> AgentProfile:
    """A copy of *profile* with some fields changed (tests, custom profiles)."""
    return replace(profile, **changes)


def iter_profiles() -> Iterable[AgentProfile]:
    """Every built-in profile."""
    return BUILTIN_PROFILES.values()


__all__ = [
    "ALWAYS_EXCLUDED",
    "ASYNC_LEASE_TOOL_NAMES",
    "BUILTIN_PROFILES",
    "OPERATOR",
    "ORCHESTRATOR_AGENT_TOOLS",
    "RESEARCHER",
    "AgentManager",
    "AgentProfile",
    "AgentRecord",
    "AgentResult",
    "Gateway",
    "GatewayClient",
    "ParsedReport",
    "agent_tool_specs",
    "get_agent_manager",
    "get_profile",
    "new_agent_id",
    "orchestrator_extra_tools",
    "parse_result",
    "register_agent_tools",
    "render_result_block",
    "reset_for_tests",
    "unwrap_client",
]
