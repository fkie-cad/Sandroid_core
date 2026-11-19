"""Agent runtime: the tool-calling loop, its events and the tool executor.

Two generations live here until the panel cut-over (WP6a):

- **Runtime v2** (used by :class:`sandroid.ai.session.AgentSession` and the
  subagents): :func:`run_turn` drives one turn on a message list with an
  :class:`~sandroid.ai.client.OpenAICompatClient`, reports everything as
  :class:`AgentEvent` objects to an :data:`EventSink`, runs tools through the
  :class:`ToolExecutor` (resolve -> permission/approval -> arbiter leases ->
  dispatch on a helper thread -> result store and shaping) and returns a
  :class:`TurnResult`. It enforces round, token and wall-clock budgets with
  one wrap-up request at the end. It never imports Toolbox; the session does
  the Toolbox and timeline integration.
- **Legacy shims** (:func:`run_agent_turn`, :func:`_dispatch_one`,
  :func:`get_current_turn_context`): the first-generation loop the current
  chat panel and ``ai/subtasks.py`` still call. They are deleted in WP6a.

``_current_owner_id`` keeps its name and module because tools read the
resource-arbiter owner from it; :func:`run_turn` sets it together with the
run-context variable.
"""

from __future__ import annotations

import contextvars
import itertools
import json
import logging
import threading
import time
import uuid
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Protocol

from sandroid.ai import tool_permissions as _perms
from sandroid.ai.arbiter import Conflict, get_arbiter
from sandroid.ai.prompts import WRAP_UP_PROMPT
from sandroid.ai.results import (
    CHARS_PER_TOKEN,
    TurnBudget,
    get_result_store,
    shape_result,
)
from sandroid.ai.tool_permissions import get_tool_permission_store, resolve_tool_policy
from sandroid.ai.tools.meta import (
    LoadedTools,
    MetaContext,
    resolve_call,
    use_meta_context,
)
from sandroid.ai.tools.registry import (
    AllowedPredicate,
    ToolError,
    ToolRegistry,
    ToolSpec,
    get_tool_registry,
    parse_tool_arguments,
)

if TYPE_CHECKING:
    from sandroid.ai.client import (
        ModelProfile,
        OpenAIClient,
        OpenAICompatClient,
        Usage,
    )
    from sandroid.ai.results import ResultStore
    from sandroid.ai.tool_permissions import ApprovalBroker

logger = logging.getLogger(__name__)

#: Owner id (and agent id) of the main chat agent; fixed across threads.
ORCHESTRATOR_ID = "orchestrator"

#: Every :attr:`AgentEvent.type` the runtime emits (agent events: WP5).
EVENT_TYPES = frozenset(
    {
        "turn_start",
        "request_start",
        "retry",
        "reasoning_delta",
        "text_delta",
        "tool_call",
        "approval_request",
        "approval_resolved",
        "tool_result",
        "usage",
        "compaction",
        "agent_spawned",
        "agent_status",
        "agent_result",
        "budget_exhausted",
        "warning",
        "error",
        "turn_end",
    }
)

TurnStatus = Literal[
    "completed", "max_rounds", "cancelled", "error", "length", "content_filter"
]
ToolStatus = Literal["ok", "error", "denied", "cancelled", "timeout"]

#: How often a waiting executor re-checks the cancel event (seconds).
_POLL_S = 0.1


# =============================================================================
# Events
# =============================================================================


@dataclass(frozen=True)
class AgentEvent:
    """One runtime event (see the design doc, section 3.1, for payloads).

    Attributes:
        type: One of :data:`EVENT_TYPES`.
        agent_id: ``"orchestrator"`` or a subagent id.
        parent_id: Parent agent id (``None`` for the orchestrator).
        thread_id: Conversation thread id.
        turn_id: Turn id within the thread (``""`` outside a turn).
        seq: Per-session monotonic sequence number.
        ts: Wall-clock time (``time.time()``).
        payload: Type-specific fields.
    """

    type: str
    agent_id: str
    parent_id: str | None
    thread_id: str
    turn_id: str
    seq: int
    ts: float
    payload: dict[str, Any] = field(default_factory=dict)


class EventSink(Protocol):
    """Receives :class:`AgentEvent` objects.

    Called on the turn's worker thread (never on a tool helper thread), in
    order. It must not block; a UI sink marshals to its own thread and
    coalesces deltas. Exceptions are logged and ignored.
    """

    def __call__(self, event: AgentEvent) -> None: ...


# =============================================================================
# Run context
# =============================================================================


@dataclass
class Budgets:
    """Per-turn limits; ``None`` or ``0`` disables tokens/wall."""

    max_rounds: int = 25
    max_tokens: int | None = None
    max_wall_s: float | None = None


#: ``before_request(ctx, messages) -> messages`` (compaction).
BeforeRequestHook = Callable[["RunContext", list[dict]], list[dict]]
#: ``on_message(msg, meta) -> ref`` (persistence); the ref is a small dict
#: (``msg_id``, ``path``, ``sha256``) attached to ``tool_result`` events.
MessageHook = Callable[[dict, dict], "dict | None"]
#: ``on_usage(usage, request_messages) -> extra usage-event fields``; gets the
#: exact message list that was sent (the token meter anchors on it).
UsageHook = Callable[["Usage", list[dict]], "dict | None"]
#: ``estimate(messages, tools) -> tokens``.
EstimateHook = Callable[[list[dict], list[dict]], int]


@dataclass
class RunContext:
    """Everything one agent turn needs besides the messages and the client.

    Attributes:
        agent_id: ``"orchestrator"`` or a subagent id (store owner, broker id).
        thread_id: Conversation thread id.
        parent_id: Parent agent id.
        owner_id: Resource-arbiter owner (default: *agent_id*).
        agent_label: Name shown in approval prompts.
        kind: ``"chat"`` or ``"agent"``.
        turn_id: Current turn id (set by the session per turn).
        cancel_event: Set to stop the turn.
        approval_mode: ``"ask"`` uses the broker; ``"deny"`` refuses every
            call that needs approval (no UI, headless).
        broker: Approval broker (``None``: the process-wide one).
        allowed: Tool predicate of this agent (``None``: every tool).
        exposed: Names in the session's fixed tools array.
        loaded: Names loaded via ``tool_search`` in this thread.
        store: Result store (``None``: the one of the current session root).
        registry: Tool registry (``None``: the singleton).
        budgets: Turn budgets.
        depth: Agent nesting depth (0 = orchestrator).
        cap_tokens: Result ingest cap (``None``: configured).
        turn_result_budget_tokens: Per-assistant-message result budget.
        sink: Event sink.
        before_request: Compaction hook.
        on_message: Persistence hook.
        on_usage: Usage hook (token meter).
        estimate: Prompt-token estimator for ``request_start``.
    """

    agent_id: str = ORCHESTRATOR_ID
    thread_id: str = ""
    parent_id: str | None = None
    owner_id: str | None = None
    agent_label: str = "Sandroid AI"
    kind: str = "chat"
    turn_id: str = ""
    cancel_event: threading.Event = field(default_factory=threading.Event)
    approval_mode: Literal["ask", "deny"] = "ask"
    broker: ApprovalBroker | None = None
    allowed: AllowedPredicate | None = None
    exposed: frozenset[str] = frozenset()
    loaded: LoadedTools = field(default_factory=LoadedTools)
    store: ResultStore | None = None
    registry: ToolRegistry | None = None
    budgets: Budgets = field(default_factory=Budgets)
    depth: int = 0
    cap_tokens: int | None = None
    turn_result_budget_tokens: int | None = None
    sink: EventSink | None = None
    before_request: BeforeRequestHook | None = None
    on_message: MessageHook | None = None
    on_usage: UsageHook | None = None
    estimate: EstimateHook | None = None
    seq: Callable[[], int] = field(default_factory=lambda: itertools.count(1).__next__)

    def __post_init__(self) -> None:
        if self.owner_id is None:
            self.owner_id = self.agent_id

    def get_registry(self) -> ToolRegistry:
        """The registry this context dispatches against."""
        return self.registry or get_tool_registry()

    def get_store(self) -> ResultStore:
        """The result store of this context."""
        if self.store is None:
            from sandroid.ai.results import session_root

            self.store = get_result_store(session_root())
        return self.store

    def emit(self, type: str, payload: dict | None = None, **fields: Any) -> AgentEvent:
        """Build an event and hand it to the sink (sink errors are swallowed)."""
        data = dict(payload or {})
        data.update(fields)
        event = AgentEvent(
            type=type,
            agent_id=self.agent_id,
            parent_id=self.parent_id,
            thread_id=self.thread_id,
            turn_id=self.turn_id,
            seq=self.seq(),
            ts=time.time(),
            payload=data,
        )
        if self.sink is not None:
            try:
                self.sink(event)
            except Exception:
                logger.exception("AI event sink failed for %s", type)
        return event


_current_run_context: ContextVar[RunContext | None] = ContextVar(
    "sandroid_ai_run_context", default=None
)

#: The resource-arbiter owner id of the turn running in this context, or
#: ``None`` for callers outside arbitration. Kept under this exact name:
#: ``tools/session_control.py``, ``tools/recording_control.py`` and tests import
#: it. :func:`run_turn` sets it to ``ctx.owner_id`` (an alias of the run
#: context); it propagates into tool helper threads via ``copy_context``.
_current_owner_id: ContextVar[str | None] = ContextVar(
    "_current_owner_id", default=None
)


def current_run_context() -> RunContext | None:
    """The :class:`RunContext` of the turn running in this context, if any."""
    return _current_run_context.get()


@dataclass
class TurnResult:
    """How one :func:`run_turn` call ended.

    Attributes:
        status: ``completed``, ``max_rounds`` (any budget), ``cancelled``,
            ``error``, ``length`` or ``content_filter``.
        final_text: Text of the turn's last assistant message ("" if none).
        usage: Token totals of the turn (``prompt_tokens``,
            ``completion_tokens``, ``reasoning_tokens``, ``requests``).
        rounds: Model requests made (wrap-up included).
        error: Redacted error message for ``error``/``content_filter``.
        budget_kind: ``rounds``/``tokens``/``wall`` when a budget ran out.
    """

    status: TurnStatus
    final_text: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    rounds: int = 0
    error: str | None = None
    budget_kind: str | None = None

    @property
    def can_continue(self) -> bool:
        """Whether "Continue" makes sense (budget hit or output cut off)."""
        return self.status in ("max_rounds", "length") or (
            self.status == "error" and self.error is not None
        )


# =============================================================================
# Request assembly
# =============================================================================

_MESSAGE_KEYS = ("role", "content", "name", "tool_calls", "tool_call_id")


def build_request_messages(messages: list[dict], profile: ModelProfile) -> list[dict]:
    """Copy *messages* for a request, applying the profile's reasoning echo.

    ``reasoning_content`` on assistant messages is kept for ``echo_reasoning``
    ``all``, only after the newest user message for ``turn``, never for
    ``none``. Unknown keys are dropped.
    """
    echo = getattr(profile, "echo_reasoning", "all")
    last_user = max(
        (i for i, m in enumerate(messages) if m.get("role") == "user"), default=-1
    )
    out: list[dict] = []
    for i, msg in enumerate(messages):
        clean = {k: msg[k] for k in _MESSAGE_KEYS if k in msg}
        reasoning = msg.get("reasoning_content")
        if (
            msg.get("role") == "assistant"
            and reasoning
            and (echo == "all" or (echo == "turn" and i > last_user))
        ):
            clean["reasoning_content"] = reasoning
        out.append(clean)
    return out


def _json_chars(value: Any) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=False, default=str))
    except (TypeError, ValueError):
        return len(str(value))


def _redact(text: Any) -> str:
    from sandroid.ai.safety import redact_secrets

    return redact_secrets(text)


# =============================================================================
# Tool executor
# =============================================================================


@dataclass
class ToolOutcome:
    """What one executed tool call produced.

    Attributes:
        call_id: The model's tool_call id.
        name: Tool that ran (the inner tool for ``call_tool``).
        args: Validated arguments (best effort for failures).
        content: Model-facing tool-message content (JSON string).
        status: ``ok``/``error``/``denied``/``cancelled``/``timeout``.
        error_code: :class:`ToolError` code for failures.
        summary: One-line human summary.
        bytes: Size of the stored result.
        result_id: R-id of the stored result.
        truncated: Whether the model only got a preview.
        duration_ms: Wall time of the call.
        via_call_tool: Whether the model used ``call_tool``.
    """

    call_id: str
    name: str
    args: dict
    content: str
    status: ToolStatus = "ok"
    error_code: str | None = None
    summary: str = ""
    bytes: int = 0
    result_id: str | None = None
    truncated: bool = False
    duration_ms: int = 0
    via_call_tool: bool = False

    def event_payload(self) -> dict[str, Any]:
        """Fields of the ``tool_result`` event."""
        return {
            "call_id": self.call_id,
            "name": self.name,
            "status": self.status,
            "error_code": self.error_code,
            "summary": self.summary,
            "bytes": self.bytes,
            "result_id": self.result_id,
            "truncated": self.truncated,
            "duration_ms": self.duration_ms,
        }


_ERROR_STATUS: dict[str, ToolStatus] = {
    "denied": "denied",
    "cancelled": "cancelled",
    "timeout": "timeout",
}


def _clip(text: str, limit: int = 120) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _is_logical_failure(result: Any) -> bool:
    """Legacy convention: an error/success/started flag, unless running."""
    return (
        isinstance(result, dict)
        and not result.get("running")
        and bool(
            result.get("error")
            or result.get("success") is False
            or result.get("started") is False
        )
    )


def summarize_result(result: Any) -> str:
    """One-line summary of a tool result for chips and timeline lines."""
    if isinstance(result, dict):
        err = result.get("error")
        if err:
            return _clip(err if isinstance(err, str) else json.dumps(err, default=str))
        for key, value in result.items():
            if isinstance(value, list):
                return f"{len(value)} {key}"
        return f"{len(result)} fields"
    if isinstance(result, list | tuple):
        return f"{len(result)} rows"
    if result is None:
        return "no result"
    return _clip(str(result).splitlines()[0] if str(result) else "empty")


def _settle_leases(
    owner: str | None,
    spec: ToolSpec,
    newly: frozenset,
    *,
    result: Any = None,
    failed: bool = False,
    abandoned: bool = False,
) -> None:
    """Keep, roll back or release leases after a call (legacy semantics).

    A raising or logically failed call rolls back only what it newly
    acquired (never what the owner already held) and does not apply its
    declared releases. A successful call applies ``spec.releases``. A call
    the executor stopped waiting for (timeout/cancel) rolls back its new
    leases once its thread really exits; its releases still apply when it
    eventually succeeded.
    """
    if owner is None:
        return
    arbiter = get_arbiter()
    failure = failed or _is_logical_failure(result)
    if newly and (failure or abandoned):
        arbiter.release_resources(owner, newly)
    if not failure and spec.releases:
        arbiter.release_resources(owner, spec.releases)


class ToolExecutor:
    """Runs one agent's tool calls (sequentially) for one :class:`RunContext`.

    Order per call: resolve (``call_tool`` unwrapped, exposure/loaded/allowed,
    validation) -> permission rules and approval -> arbiter leases ->
    dispatch on a helper thread (``copy_context`` so ``acting_as``, the owner
    id and the meta context propagate) within ``spec.timeout_s`` -> result
    store + shaping -> lease settlement.
    """

    def __init__(self, ctx: RunContext) -> None:
        """Bind the executor to *ctx*."""
        self.ctx = ctx

    # -- public ---------------------------------------------------------------

    def execute(
        self, call_id: str, name: str | None, raw_args: Any, *, budget: TurnBudget
    ) -> ToolOutcome:
        """Execute one model tool call; never raises."""
        ctx = self.ctx
        started = time.monotonic()
        meta = MetaContext(
            loaded=ctx.loaded,
            allowed=ctx.allowed,
            store=ctx.get_store(),
            cap_tokens=ctx.cap_tokens,
            registry=ctx.get_registry(),
        )
        with use_meta_context(meta):
            try:
                call = resolve_call(
                    name,
                    raw_args,
                    loaded=ctx.loaded,
                    allowed=ctx.allowed,
                    exposed=ctx.exposed,
                    registry=ctx.get_registry(),
                )
            except ToolError as err:
                args, parse_error = self._best_effort_args(raw_args)
                ctx.emit(
                    "tool_call",
                    call_id=call_id,
                    name=name or "",
                    args=args,
                    parse_error=parse_error or err.message,
                    via_call_tool=name == "call_tool",
                )
                return self._error(call_id, name or "", args, err, started)
            ctx.emit(
                "tool_call",
                call_id=call_id,
                name=call.spec.name,
                args=call.arguments,
                parse_error=None,
                via_call_tool=call.via_call_tool,
            )
            try:
                outcome = self._run(call_id, call.spec, call.arguments, budget)
            except ToolError as err:
                outcome = self._error(call_id, call.spec.name, call.arguments, err)
            except Exception as exc:  # executor bug: never crash the turn
                logger.exception("Tool executor failed for %s", call.spec.name)
                outcome = self._error(
                    call_id,
                    call.spec.name,
                    call.arguments,
                    ToolError("tool_failed", _redact(f"{type(exc).__name__}: {exc}")),
                )
        outcome.via_call_tool = call.via_call_tool
        outcome.duration_ms = int((time.monotonic() - started) * 1000)
        return outcome

    def not_run(
        self, call_id: str, name: str | None, raw_args: Any, error: ToolError
    ) -> ToolOutcome:
        """Outcome for a call that is answered without running it."""
        args, parse_error = self._best_effort_args(raw_args)
        self.ctx.emit(
            "tool_call",
            call_id=call_id,
            name=name or "",
            args=args,
            parse_error=parse_error,
            via_call_tool=name == "call_tool",
        )
        return self._error(call_id, name or "", args, error)

    # -- steps ----------------------------------------------------------------

    def _run(
        self, call_id: str, spec: ToolSpec, args: dict, budget: TurnBudget
    ) -> ToolOutcome:
        ctx = self.ctx
        self._check_permission(spec, args)
        if ctx.cancel_event.is_set():
            raise ToolError("cancelled", "the turn was cancelled before this call ran")
        owner = ctx.owner_id
        newly: frozenset = frozenset()
        if spec.resources and owner is not None:
            claimed = get_arbiter().claim(owner, spec.resources)
            if isinstance(claimed, Conflict):
                raise ToolError(
                    "resource_conflict",
                    f"resource {claimed.resource.value!r} is in use by another "
                    "task; it must be released before this tool can run",
                    retryable=True,
                    hint="Wait for the other task to finish, or report the conflict.",
                )
            newly = claimed
        result, exc = self._dispatch(spec, args, owner, newly)
        if exc is not None:
            if isinstance(exc, ToolError):
                raise exc
            raise ToolError(
                "tool_failed",
                _redact(str(exc) or type(exc).__name__),
                hint="The tool raised an error; check its arguments or the device.",
            )
        return self._store(call_id, spec, args, result, budget)

    def _check_permission(self, spec: ToolSpec, args: dict) -> None:
        ctx = self.ctx
        resolution = _perms.resolve(
            spec.name,
            spec.risk,
            args,
            permission_key=spec.permission_key,
            can_remember_choice=spec.can_remember_choice,
        )
        if resolution.allowed:
            return
        if resolution.denied:
            rule = f" ({resolution.rule})" if resolution.rule else ""
            raise ToolError(
                "denied",
                f"{spec.name} is blocked by a permission rule{rule}",
                hint="Do not retry this call; tell the analyst it is blocked.",
            )
        if ctx.approval_mode != "ask":
            raise ToolError(
                "denied",
                f"{spec.name} needs the analyst's approval, but nobody can "
                "approve it here",
                hint="Report what you would run instead of running it.",
            )
        broker = ctx.broker or _perms.get_approval_broker()
        pending = broker.submit(
            agent_id=ctx.agent_id,
            agent_label=ctx.agent_label,
            tool=spec.name,
            args=args,
            risk=spec.risk,
            suggested_rule=resolution.suggested_rule,
            description=_clip(spec.description, 200),
            argument_dependent=_perms.is_argument_dependent(
                spec.permission_key, spec.can_remember_choice
            ),
        )
        request = pending.request
        ctx.emit(
            "approval_request",
            request_id=request.request_id,
            agent_id=request.agent_id,
            agent_label=request.agent_label,
            tool=spec.name,
            args=dict(args),
            risk=spec.risk.name.lower(),
            suggested_rule=request.suggested_rule,
            rule_description=request.suggested_rule_description,
            argument_dependent=request.argument_dependent,
        )
        decision = pending.wait(cancel_event=ctx.cancel_event)
        ctx.emit(
            "approval_resolved",
            request_id=request.request_id,
            tool=spec.name,
            decision=decision.choice,
            note=decision.note,
            remembered_rule=decision.remembered_rule,
            by=decision.by,
        )
        if decision.approved:
            return
        if decision.by == "cancelled":
            raise ToolError("cancelled", "the turn was cancelled during approval")
        if decision.by == "timeout":
            raise ToolError(
                "denied",
                f"nobody answered the approval prompt for {spec.name} in time",
                hint="Do not retry automatically; ask the analyst first.",
            )
        details = {"note": decision.note} if decision.note else None
        message = f"The analyst declined {spec.name}."
        if decision.note:
            message += f" Their note: {decision.note}"
        raise ToolError(
            "denied",
            message,
            hint="Do not retry the same call; follow the analyst's note if any.",
            details=details,
        )

    def _dispatch(
        self, spec: ToolSpec, args: dict, owner: str | None, newly: frozenset
    ) -> tuple[Any, BaseException | None]:
        """Run the tool on a helper thread; return ``(result, exception)``."""
        ctx = self.ctx
        registry = ctx.get_registry()
        lock = threading.Lock()
        state: dict[str, Any] = {"done": False, "abandoned": False}
        finished = threading.Event()

        def body() -> None:
            from sandroid.core.timeline import acting_as

            result: Any = None
            error: BaseException | None = None
            try:
                with acting_as("ai"):
                    result = registry.dispatch(spec.name, args)
            except BaseException as exc:  # reported to the model
                error = exc
            with lock:
                state["done"] = True
                state["result"] = result
                state["error"] = error
                abandoned = state["abandoned"]
            finished.set()
            if abandoned:
                # The executor gave up waiting: settle the leases now that
                # the tool really stopped (never while it still ran).
                try:
                    _settle_leases(
                        owner,
                        spec,
                        newly,
                        result=result,
                        failed=error is not None,
                        abandoned=True,
                    )
                except Exception:
                    logger.exception("Lease settlement failed for %s", spec.name)
                logger.info(
                    "Abandoned tool %s finished after the executor stopped waiting",
                    spec.name,
                )

        cctx = contextvars.copy_context()
        thread = threading.Thread(
            target=cctx.run, args=(body,), name=f"ai-tool:{spec.name}", daemon=True
        )
        thread.start()
        timeout = spec.timeout_s if spec.timeout_s and spec.timeout_s > 0 else None
        deadline = None if timeout is None else time.monotonic() + timeout
        stop: str | None = None
        while not finished.wait(_POLL_S):
            if ctx.cancel_event.is_set():
                stop = "cancelled"
            elif deadline is not None and time.monotonic() >= deadline:
                stop = "timeout"
            if stop is None:
                continue
            with lock:
                if state["done"]:
                    stop = None  # finished in the meantime: treat as normal
                else:
                    state["abandoned"] = True
            break
        if stop == "cancelled":
            return None, ToolError(
                "cancelled",
                f"{spec.name} was cancelled while running; it may still finish "
                "in the background",
            )
        if stop == "timeout":
            return None, ToolError(
                "timeout",
                f"{spec.name} did not finish within {timeout:g}s; it may still "
                "finish in the background",
                retryable=True,
                hint="Check the state with a status tool before retrying.",
            )
        error = state.get("error")
        result = state.get("result")
        _settle_leases(owner, spec, newly, result=result, failed=error is not None)
        return result, error

    def _store(
        self, call_id: str, spec: ToolSpec, args: dict, result: Any, budget: TurnBudget
    ) -> ToolOutcome:
        ctx = self.ctx
        rid: str | None = None
        size = 0
        truncated = False
        try:
            stored = ctx.get_store().put(spec.name, args, result, agent_id=ctx.agent_id)
            rid, size = stored.id, stored.bytes
            content = shape_result(
                result, rid, cap_tokens=ctx.cap_tokens, budget=budget
            )
            try:
                shaped = json.loads(content)
                truncated = isinstance(shaped, dict) and shaped.get("truncated") is True
            except ValueError:
                truncated = False
        except Exception:
            logger.exception("Storing/shaping the result of %s failed", spec.name)
            try:
                content = json.dumps(
                    {"result": result}, ensure_ascii=False, default=str
                )
            except Exception:
                content = json.dumps({"result": str(result)})
            size = len(content.encode("utf-8", errors="replace"))
        status: ToolStatus = "error" if _is_logical_failure(result) else "ok"
        return ToolOutcome(
            call_id=call_id,
            name=spec.name,
            args=args,
            content=content,
            status=status,
            error_code="tool_failed" if status == "error" else None,
            summary=summarize_result(result),
            bytes=size,
            result_id=rid,
            truncated=truncated,
        )

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _best_effort_args(raw_args: Any) -> tuple[dict, str | None]:
        try:
            return parse_tool_arguments(raw_args), None
        except ToolError as err:
            return {}, err.message

    @staticmethod
    def _error(
        call_id: str,
        name: str,
        args: dict,
        err: ToolError,
        started: float | None = None,
    ) -> ToolOutcome:
        return ToolOutcome(
            call_id=call_id,
            name=name,
            args=args,
            content=err.to_json(),
            status=_ERROR_STATUS.get(err.code, "error"),
            error_code=err.code,
            summary=_clip(f"{err.code}: {err.message}"),
            duration_ms=int((time.monotonic() - started) * 1000) if started else 0,
        )


# =============================================================================
# The turn loop
# =============================================================================


@dataclass
class _Response:
    status: Literal["done", "error", "cancelled"] = "done"
    text: str = ""
    reasoning: str = ""
    tool_calls: dict[int, dict] = field(default_factory=dict)
    finish_reason: str | None = None
    usage: Usage | None = None
    error_kind: str | None = None
    error_message: str | None = None
    retryable: bool = False


class _TurnRunner:
    def __init__(
        self,
        messages: list[dict],
        ctx: RunContext,
        client: OpenAICompatClient,
        tools: list[dict],
        continuation: bool,
    ) -> None:
        self.messages = messages
        self.ctx = ctx
        self.client = client
        self.tools = tools
        self.continuation = continuation
        self.executor = ToolExecutor(ctx)
        self.rounds = 0
        self.usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "reasoning_tokens": 0,
            "requests": 0,
        }
        self.started = time.monotonic()

    # -- persistence ------------------------------------------------------------

    def _append(self, msg: dict, meta: dict | None = None) -> dict | None:
        self.messages.append(msg)
        if self.ctx.on_message is None:
            return None
        try:
            return self.ctx.on_message(msg, dict(meta or {}))
        except Exception:
            logger.exception("AI on_message hook failed")
            return None

    def _assistant(self, text: str, reasoning: str) -> dict:
        msg: dict[str, Any] = {"role": "assistant", "content": text}
        if reasoning:
            msg["reasoning_content"] = reasoning
        return msg

    def _append_partial(self, resp: _Response) -> str:
        if resp.text or resp.reasoning:
            self._append(
                self._assistant(resp.text, resp.reasoning), {"partial": resp.status}
            )
        return resp.text

    # -- run ------------------------------------------------------------------------

    def run(self) -> TurnResult:
        ctx = self.ctx
        mode = "continuation" if self.continuation else ctx.kind
        ctx.emit("turn_start", mode=mode, model=getattr(self.client, "model", None))
        status: TurnStatus = "completed"
        final_text = ""
        error: str | None = None
        budget_kind: str | None = None
        try:
            while True:
                if ctx.cancel_event.is_set():
                    status = "cancelled"
                    break
                budget_kind = self._exhausted_budget()
                if budget_kind is not None:
                    final_text = self._wrap_up(budget_kind)
                    ctx.emit("budget_exhausted", kind=budget_kind, can_continue=True)
                    status = "max_rounds"
                    break
                self.rounds += 1
                resp = self._request(self.rounds)
                if resp.status == "cancelled":
                    final_text = self._append_partial(resp)
                    status = "cancelled"
                    break
                if resp.status == "error":
                    final_text = self._append_partial(resp)
                    error = resp.error_message
                    ctx.emit(
                        "error",
                        kind=resp.error_kind,
                        retryable=resp.retryable,
                        message=error,
                        partial=bool(resp.text),
                    )
                    status = "error"
                    break
                if resp.finish_reason == "content_filter":
                    final_text = self._append_partial(resp)
                    error = "the response was blocked by the backend's content filter"
                    ctx.emit(
                        "error", kind="content_filter", retryable=False, message=error
                    )
                    status = "content_filter"
                    break
                if resp.tool_calls:
                    self._run_tools(resp)
                    continue
                self._append(self._assistant(resp.text, resp.reasoning))
                final_text = resp.text
                status = "length" if resp.finish_reason == "length" else "completed"
                if status == "length":
                    ctx.emit(
                        "warning",
                        kind="length",
                        retryable=True,
                        message="the reply hit the output limit",
                    )
                break
        except Exception as exc:  # the worker thread must never crash
            logger.exception("AI turn failed")
            status = "error"
            error = _redact(f"{type(exc).__name__}: {exc}")
            ctx.emit("error", kind="internal", retryable=False, message=error)
        ctx.emit(
            "turn_end",
            reason=status,
            final_text=final_text,
            usage=dict(self.usage),
            rounds=self.rounds,
            budget_kind=budget_kind,
            error=error,
        )
        return TurnResult(
            status=status,
            final_text=final_text,
            usage=dict(self.usage),
            rounds=self.rounds,
            error=error,
            budget_kind=budget_kind,
        )

    def _exhausted_budget(self) -> str | None:
        budgets = self.ctx.budgets
        if budgets.max_rounds and self.rounds >= budgets.max_rounds:
            return "rounds"
        spent = self.usage["prompt_tokens"] + self.usage["completion_tokens"]
        if budgets.max_tokens and spent >= budgets.max_tokens:
            return "tokens"
        if budgets.max_wall_s and time.monotonic() - self.started >= budgets.max_wall_s:
            return "wall"
        return None

    # -- one request ----------------------------------------------------------------

    def _request(self, iteration: int, tool_choice: str | None = None) -> _Response:
        ctx = self.ctx
        if ctx.before_request is not None:
            try:
                new = ctx.before_request(ctx, self.messages)
            except Exception:
                logger.exception("AI before_request hook failed")
                new = self.messages
            if new is not None and new is not self.messages:
                self.messages[:] = new
        request = build_request_messages(self.messages, self.client.profile)
        chars = _json_chars(request)
        estimate = None
        if ctx.estimate is not None:
            try:
                estimate = int(ctx.estimate(request, self.tools))
            except Exception:
                logger.debug("AI estimate hook failed", exc_info=True)
        if estimate is None:
            estimate = int((chars + _json_chars(self.tools)) / CHARS_PER_TOKEN)
        ctx.emit("request_start", iteration=iteration, est_prompt_tokens=estimate)
        resp = _Response()
        text: list[str] = []
        reasoning: list[str] = []
        stream = self.client.stream(
            request,
            self.tools or None,
            tool_choice=tool_choice,
            cancel_event=ctx.cancel_event,
        )
        try:
            for chunk in stream:
                kind = chunk.kind
                if kind == "text":
                    text.append(chunk.text)
                    ctx.emit("text_delta", text=chunk.text)
                elif kind == "reasoning":
                    reasoning.append(chunk.text)
                    ctx.emit("reasoning_delta", text=chunk.text)
                elif kind == "tool_call" and chunk.tool_call is not None:
                    self._accumulate(resp.tool_calls, chunk.tool_call)
                elif kind == "usage" and chunk.usage is not None:
                    resp.usage = chunk.usage
                elif kind == "retry" and chunk.retry is not None:
                    ctx.emit(
                        "retry",
                        attempt=chunk.retry.attempt,
                        max_attempts=chunk.retry.max_attempts,
                        delay_s=chunk.retry.delay_s,
                        reason=chunk.retry.reason,
                    )
                elif kind == "done":
                    resp.finish_reason = chunk.finish_reason
                    if chunk.usage is not None:
                        resp.usage = chunk.usage
                    break
                elif kind == "error" and chunk.error is not None:
                    resp.status = "error"
                    resp.error_kind = chunk.error.kind
                    resp.error_message = chunk.error.message
                    resp.retryable = chunk.error.retryable
                    break
                elif kind == "cancelled":
                    resp.status = "cancelled"
                    break
        finally:
            close = getattr(stream, "close", None)
            if close is not None:
                close()
        resp.text = "".join(text)
        resp.reasoning = "".join(reasoning)
        if resp.usage is not None:
            self._record_usage(resp.usage, request)
        return resp

    @staticmethod
    def _accumulate(calls: dict[int, dict], delta: Any) -> None:
        slot = calls.setdefault(delta.index, {"id": None, "name": None, "args": ""})
        if delta.id:
            slot["id"] = delta.id
        if delta.name:
            slot["name"] = delta.name
        slot["args"] += delta.arguments_fragment or ""

    def _record_usage(self, usage: Usage, request: list[dict]) -> None:
        ctx = self.ctx
        self.usage["prompt_tokens"] += usage.prompt_tokens
        self.usage["completion_tokens"] += usage.completion_tokens
        self.usage["reasoning_tokens"] += usage.reasoning_tokens
        self.usage["requests"] += 1
        extra: dict | None = None
        if ctx.on_usage is not None:
            try:
                extra = ctx.on_usage(usage, request)
            except Exception:
                logger.exception("AI on_usage hook failed")
        payload = {
            "prompt": usage.prompt_tokens,
            "completion": usage.completion_tokens,
            "reasoning": usage.reasoning_tokens,
            "cumulative": dict(self.usage),
            "context_used": usage.prompt_tokens + usage.completion_tokens,
            "context_window": getattr(self.client.profile, "context_window", None),
        }
        payload.update(extra or {})
        ctx.emit("usage", payload)

    # -- tools ------------------------------------------------------------------------

    def _run_tools(self, resp: _Response) -> None:
        calls = []
        for index in sorted(resp.tool_calls):
            slot = resp.tool_calls[index]
            call_id = slot["id"] or f"call_{uuid.uuid4().hex[:12]}"
            calls.append((call_id, slot["name"] or "", slot["args"]))
        assistant = {
            "role": "assistant",
            "content": resp.text or None,
            "tool_calls": [
                {
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": _echo_args(raw)},
                }
                for call_id, name, raw in calls
            ],
        }
        if resp.reasoning:
            assistant["reasoning_content"] = resp.reasoning
        self._append(assistant)
        cut_off = resp.finish_reason == "length" and any(
            not _parses(raw) for _, _, raw in calls
        )
        budget = TurnBudget(self.ctx.turn_result_budget_tokens)
        for call_id, name, raw in calls:
            if cut_off:
                outcome = self.executor.not_run(
                    call_id,
                    name,
                    raw,
                    ToolError(
                        "invalid_arguments",
                        "the reply hit the output limit before the tool "
                        "arguments were complete; nothing was run",
                        retryable=True,
                        hint="Call the tool again with shorter arguments.",
                        details={"received": raw[:500]},
                    ),
                )
            elif self.ctx.cancel_event.is_set():
                outcome = self.executor.not_run(
                    call_id,
                    name,
                    raw,
                    ToolError("cancelled", "cancelled before this tool call ran"),
                )
            else:
                outcome = self.executor.execute(call_id, name, raw, budget=budget)
            ref = self._append(
                {"role": "tool", "tool_call_id": call_id, "content": outcome.content},
                {
                    "result_id": outcome.result_id,
                    "tool": outcome.name,
                    "status": outcome.status,
                },
            )
            payload = outcome.event_payload()
            payload["args"] = outcome.args
            payload["via_call_tool"] = outcome.via_call_tool
            if ref:
                payload["ref"] = ref
            self.ctx.emit("tool_result", payload)

    # -- wrap-up --------------------------------------------------------------------

    def _wrap_up(self, kind: str) -> str:
        """One final request on the same prefix, same tools, tool_choice none."""
        prompt = WRAP_UP_PROMPT.format(kind=kind)
        self._append({"role": "user", "content": prompt}, {"runtime": "wrap_up"})
        profile = self.client.profile
        choice = "none" if getattr(profile, "tool_choice_none", False) else None
        self.rounds += 1
        resp = self._request(self.rounds, tool_choice=choice)
        if resp.status == "error":
            self.ctx.emit(
                "error",
                kind=resp.error_kind,
                retryable=resp.retryable,
                message=resp.error_message,
            )
        # Tool calls in a wrap-up reply are never dispatched (and not echoed,
        # so no tool_call is left unanswered).
        if resp.status != "done":
            return self._append_partial(resp)
        self._append(self._assistant(resp.text, resp.reasoning))
        return resp.text


def _parses(raw: str) -> bool:
    try:
        parse_tool_arguments(raw)
    except ToolError:
        return False
    return True


def _echo_args(raw: str) -> str:
    """Arguments string echoed in the assistant message (always valid JSON).

    Malformed arguments are echoed as ``{}``: a backend chat template may parse
    them when rendering history; the tool message carries what was received.
    """
    if not raw or not raw.strip():
        return "{}"
    try:
        json.loads(raw)
        return raw
    except ValueError:
        pass
    try:
        return json.dumps(parse_tool_arguments(raw), ensure_ascii=False)
    except ToolError:
        return "{}"


def run_turn(
    messages: list[dict],
    ctx: RunContext,
    *,
    client: OpenAICompatClient,
    tools: list[dict],
    continuation: bool = False,
) -> TurnResult:
    """Drive one agent turn on *messages* until the model stops or a limit hits.

    The caller has already appended (and persisted) the turn's user message.
    Assistant and tool messages are appended to *messages* as they happen and
    handed to ``ctx.on_message``; ``ctx.before_request`` may replace the list
    contents (compaction). Never raises; failures end the turn with status
    ``error``.

    Args:
        messages: The thread's message history (mutated).
        ctx: The run context (agent identity, cancel event, hooks, sink).
        client: Transport (``stream()`` with typed chunks).
        tools: The session's fixed tools array.
        continuation: Whether this turn continues a previous one.

    Returns:
        The :class:`TurnResult`.
    """
    run_token = _current_run_context.set(ctx)
    owner_token = _current_owner_id.set(ctx.owner_id)
    try:
        return _TurnRunner(messages, ctx, client, tools, continuation).run()
    finally:
        _current_owner_id.reset(owner_token)
        _current_run_context.reset(run_token)


def install_permission_resolver() -> None:
    """Point the permission store's argument-dependency lookup at the toolsets.

    The central toolset table decides permission keys; tools not in it fall
    back to their registered spec.
    """
    from sandroid.ai.tools.toolsets import lookup_entry

    def resolver(name: str) -> bool:
        entry = lookup_entry(name)
        if entry is not None and entry.permission_key:
            return True
        spec = get_tool_registry().get_spec(name)
        if spec is None:
            return False
        return _perms.is_argument_dependent(
            spec.permission_key, spec.can_remember_choice
        )

    _perms.set_argument_dependency_resolver(resolver)


# =============================================================================
# Legacy shims (first-generation loop; deleted in WP6a)
# =============================================================================

#: Default cap on tool-calling round-trips within a single legacy turn.
MAX_ITERATIONS_DEFAULT = 8

#: A pending tool call's approval callback: given the tool's ToolSpec and its
#: parsed arguments, blocks until the user (or caller) decides, returning
#: "once" | "always" | "decline" | "cancelled". See _dispatch_one.
ApproveCallback = Callable[[ToolSpec, dict], str]

#: (client, cancel_event, approve) for the legacy turn executing on this
#: thread (see get_current_turn_context()).
_current_turn_context: ContextVar[
    tuple[OpenAIClient, threading.Event, ApproveCallback | None] | None
] = ContextVar("_current_turn_context", default=None)


def get_current_turn_context() -> (
    tuple[OpenAIClient, threading.Event, ApproveCallback | None] | None
):
    """Return the ``(client, cancel_event, approve)`` of the legacy turn here.

    Returns:
        The active legacy turn's context, or ``None`` if no
        :func:`run_agent_turn` call is on the stack in this context.
    """
    return _current_turn_context.get()


def run_agent_turn(
    messages: list[dict],
    tools: list[dict],
    client: OpenAIClient,
    cancel_event: threading.Event,
    on_event: Callable[[dict], None] | None = None,
    max_iterations: int = MAX_ITERATIONS_DEFAULT,
    approve: ApproveCallback | None = None,
    owner_id: str | None = None,
) -> str:
    """Legacy: drive one agent turn with the first-generation dict events.

    Kept for the current chat panel and ``ai/subtasks.py`` until WP6a.

    Args:
        messages: Chat history so far (mutated in place: assistant and tool
            messages are appended as the loop progresses).
        tools: The ``tools=[...]`` schema offered this turn; dispatch refuses
            names outside it (``call_tool`` may reach any of them).
        client: The backend client (legacy ``chat()`` API).
        cancel_event: Stops the turn early when set.
        on_event: Callback for every ChatEvent dict as it's produced.
        max_iterations: Cap on tool-calling round-trips within this turn.
        approve: Approval callback for ``ask`` tools (``None``: refuse them).
        owner_id: Resource-arbiter owner id (``None``: no arbitration).

    Returns:
        The final reply text not yet reflected in ``messages`` (``""`` when the
        turn ended already fully persisted). Callers append it only when
        non-empty.
    """

    def emit(event: dict) -> None:
        if on_event is not None:
            on_event(event)

    allowed_names = {
        t["function"]["name"] for t in tools if t.get("type") == "function"
    }

    token = _current_turn_context.set((client, cancel_event, approve))
    owner_token = _current_owner_id.set(owner_id)
    try:
        return _run_iterations(
            messages,
            tools,
            client,
            cancel_event,
            emit,
            max_iterations,
            allowed_names,
            approve,
        )
    finally:
        _current_owner_id.reset(owner_token)
        _current_turn_context.reset(token)


def _run_iterations(
    messages: list[dict],
    tools: list[dict],
    client: OpenAIClient,
    cancel_event: threading.Event,
    emit: Callable[[dict], None],
    max_iterations: int,
    allowed_names: set[str],
    approve: ApproveCallback | None = None,
) -> str:
    for _ in range(max_iterations):
        if cancel_event.is_set():
            return ""

        text_accum, tool_calls, stopped_early = _stream_one_response(
            messages, tools, client, cancel_event, emit
        )
        if stopped_early:
            return text_accum

        if not tool_calls:
            return text_accum

        # _dispatch_tool_calls persists this round's text into `messages`.
        _dispatch_tool_calls(
            messages, tool_calls, text_accum, emit, cancel_event, allowed_names, approve
        )
        if cancel_event.is_set():
            return ""

    return ""


def _stream_one_response(
    messages: list[dict],
    tools: list[dict],
    client: OpenAIClient,
    cancel_event: threading.Event,
    emit: Callable[[dict], None],
) -> tuple[str, dict[int, dict], bool]:
    """Stream one legacy ``client.chat(...)`` response.

    Returns:
        ``(accumulated_text, tool_calls_by_index, stopped_early)``.
    """
    text_accum = ""
    tool_calls: dict[int, dict] = {}

    for event in client.chat(messages, tools=tools, stream=True):
        if cancel_event.is_set():
            return text_accum, tool_calls, True

        etype = event.get("type")
        if etype == "text_delta":
            text_accum += event.get("content", "")
            emit(event)
        elif etype == "reasoning_delta":
            emit(event)
        elif etype == "tool_call_delta":
            _accumulate_tool_call_delta(tool_calls, event)
        elif etype == "error":
            emit(event)
            return text_accum, tool_calls, True
        elif etype == "done":
            break

    return text_accum, tool_calls, False


def _accumulate_tool_call_delta(tool_calls: dict[int, dict], event: dict) -> None:
    index = event["index"]
    slot = tool_calls.setdefault(index, {"id": None, "name": None, "arguments": ""})
    if event.get("id"):
        slot["id"] = event["id"]
    if event.get("name"):
        slot["name"] = event["name"]
    slot["arguments"] += event.get("arguments_fragment", "")


def _dispatch_tool_calls(
    messages: list[dict],
    tool_calls: dict[int, dict],
    text_accum: str,
    emit: Callable[[dict], None],
    cancel_event: threading.Event,
    allowed_names: set[str] | None = None,
    approve: ApproveCallback | None = None,
) -> None:
    """Assemble, announce, append, and execute every tool call from one turn.

    Every declared ``tool_call_id`` gets a matching ``role="tool"`` response,
    even on cancel.
    """
    registry = get_tool_registry()
    assistant_tool_calls = []
    parsed_by_index: dict[int, dict] = {}

    for index in sorted(tool_calls):
        call = tool_calls[index]
        parsed_args = _parse_arguments(call["arguments"])
        parsed_by_index[index] = parsed_args
        call_id = call["id"] or f"call_{index}"
        assistant_tool_calls.append(
            {
                "id": call_id,
                "type": "function",
                "function": {"name": call["name"], "arguments": call["arguments"]},
            }
        )
        emit(
            {
                "type": "tool_call_done",
                "index": index,
                "id": call_id,
                "name": call["name"],
                "arguments": parsed_args,
            }
        )

    messages.append(
        {
            "role": "assistant",
            "content": text_accum or None,
            "tool_calls": assistant_tool_calls,
        }
    )

    cancelled = False
    for index in sorted(tool_calls):
        call = tool_calls[index]
        call_id = call["id"] or f"call_{index}"
        if cancelled or cancel_event.is_set():
            cancelled = True
            content = json.dumps({"error": "cancelled before this tool call ran"})
        else:
            content = _dispatch_one(
                registry, call["name"], parsed_by_index[index], allowed_names, approve
            )
        messages.append({"role": "tool", "tool_call_id": call_id, "content": content})


def _legacy_error(err: ToolError) -> str:
    payload: dict[str, Any] = {"error": err.message, "code": err.code}
    if err.hint:
        payload["hint"] = err.hint
    return json.dumps(payload, default=str)


def _dispatch_one(
    registry,
    name: str | None,
    arguments: dict,
    allowed_names: set[str] | None = None,
    approve: ApproveCallback | None = None,
) -> str:
    """Legacy: dispatch one tool call, converting any failure into an error.

    ``call_tool`` is unwrapped through :func:`~sandroid.ai.tools.meta.resolve_call`
    (restricted to *allowed_names*), so the inner tool's permission gate and
    leases apply. A decline is call-scoped: nothing is persisted.
    """
    if allowed_names is not None and name not in allowed_names:
        logger.debug("Tool %r not in this turn's allowed set; refusing", name)
        return json.dumps({"error": f"tool {name!r} is not available this turn"})

    if name == "call_tool":
        allowed_pred = (
            None if allowed_names is None else (lambda spec: spec.name in allowed_names)
        )
        try:
            call = resolve_call(
                name,
                arguments,
                loaded=LoadedTools(),
                allowed=allowed_pred,
                registry=registry,
            )
        except ToolError as err:
            return _legacy_error(err)
        name, arguments = call.spec.name, call.arguments

    spec = registry.get_spec(name)
    if spec is not None:
        policy = resolve_tool_policy(spec.name, spec.risk, spec.can_remember_choice)
        if policy == "never":
            return json.dumps({"error": f"{name!r} is blocked by saved policy"})
        if policy == "ask":
            if approve is None:
                return json.dumps(
                    {"error": f"{name!r} needs confirmation but no UI is available"}
                )
            try:
                choice = approve(spec, arguments)
            except Exception as exc:
                logger.debug("approve() raised for %r: %s", name, exc)
                return json.dumps(
                    {"error": f"could not obtain confirmation for {name!r}: {exc}"}
                )
            if choice in ("decline", "cancelled"):
                # Call-scoped: a decline is never persisted as "never".
                return json.dumps({"error": f"{name!r} was not approved ({choice})"})
            if choice == "always" and spec.can_remember_choice:
                get_tool_permission_store().mark_allowed(spec.name)

    owner = _current_owner_id.get()
    newly: frozenset = frozenset()
    if spec is not None and spec.resources and owner is not None:
        claimed = get_arbiter().claim(owner, spec.resources)
        if isinstance(claimed, Conflict):
            return json.dumps(
                {
                    "error": (
                        f"resource {claimed.resource.value!r} is in use by "
                        "another task; it must be released before this tool "
                        "can run"
                    )
                }
            )
        newly = claimed

    try:
        result = registry.dispatch(name, arguments)
    except Exception as exc:
        if newly and owner is not None:
            get_arbiter().release_resources(owner, newly)
        logger.debug("Tool %r raised during dispatch: %s", name, exc)
        return json.dumps({"error": str(exc)})

    if owner is not None and spec is not None:
        _settle_leases(owner, spec, newly, result=result)

    try:
        return json.dumps(result, default=str)
    except (TypeError, ValueError):
        return json.dumps({"result": str(result)})


def _parse_arguments(raw_arguments: str) -> dict:
    if not raw_arguments:
        return {}
    try:
        return json.loads(raw_arguments)
    except json.JSONDecodeError:
        logger.debug("Failed to parse tool-call arguments as JSON: %r", raw_arguments)
        return {}


__all__ = [
    "EVENT_TYPES",
    "ORCHESTRATOR_ID",
    "AgentEvent",
    "Budgets",
    "EventSink",
    "RunContext",
    "ToolExecutor",
    "ToolOutcome",
    "TurnResult",
    "build_request_messages",
    "current_run_context",
    "get_current_turn_context",
    "install_permission_resolver",
    "run_agent_turn",
    "run_turn",
    "summarize_result",
]
