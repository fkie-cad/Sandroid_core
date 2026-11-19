"""Agent runtime: the tool-calling loop, its events and the tool executor.

Used by :class:`sandroid.ai.session.AgentSession` (the main chat and the
subagents): :func:`run_turn` drives one turn on a message list with an
:class:`~sandroid.ai.client.OpenAICompatClient`, reports everything as
:class:`AgentEvent` objects to an :data:`EventSink`, runs tools through the
:class:`ToolExecutor` (resolve -> permission/approval -> arbiter leases ->
dispatch on a helper thread -> result store and shaping) and returns a
:class:`TurnResult`. It enforces round, token and wall-clock budgets with one
wrap-up request at the end. It never imports Toolbox; the session does the
Toolbox and timeline integration.

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
from sandroid.ai.arbiter import Conflict, LeaseHandle, get_arbiter
from sandroid.ai.prompts import WRAP_UP_PROMPT
from sandroid.ai.results import (
    CHARS_PER_TOKEN,
    TurnBudget,
    get_result_store,
    result_cap_tokens,
    shape_result,
)
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

#: Maximum characters of the preview sent when storing/shaping a result fails.
_FALLBACK_PREVIEW_CHARS = 4000


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


#: ``time.monotonic()`` at which the executor stops waiting for the tool
#: running in this context (``None``: no timeout / not inside a tool call).
_tool_deadline: ContextVar[float | None] = ContextVar(
    "sandroid_ai_tool_deadline", default=None
)


def tool_time_remaining() -> float | None:
    """Seconds left before the executor abandons the current tool call.

    ``None`` outside a tool call or for a tool without a timeout. Long tools
    that wait on something (``spawn_agent`` with ``wait=true``) use it to stop
    waiting in time instead of being abandoned while still running.
    """
    deadline = _tool_deadline.get()
    if deadline is None:
        return None
    return max(0.0, deadline - time.monotonic())


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
    handle: LeaseHandle | None,
    spec: ToolSpec,
    *,
    result: Any = None,
    failed: bool = False,
    abandoned: bool = False,
) -> None:
    """Keep, roll back or release a call's leases (once its thread exited).

    A raising or logically failed call rolls back only what it newly
    acquired (never what the owner already held) and does not apply its
    declared releases. A successful call keeps its new leases and applies
    ``spec.releases``. A call the executor stopped waiting for
    (timeout/cancel) is settled when its thread really exits: its new leases
    are rolled back (the model was told it did not finish), its declared
    releases still apply when it eventually succeeded. Leases are reference
    counted per call (:meth:`~sandroid.ai.arbiter.DeviceResourceArbiter.settle`),
    so a newer call of the same owner that reused a lease keeps it.
    """
    if handle is None:
        return
    failure = failed or _is_logical_failure(result)
    get_arbiter().settle(
        handle,
        failed=failure or abandoned,
        releases=frozenset() if failure else frozenset(spec.releases or ()),
    )


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
        handle: LeaseHandle | None = None
        if owner is not None:
            # Every call is tracked (also without resources): an abandoned
            # call keeps its owner live until its thread exits.
            claimed = get_arbiter().acquire(owner, frozenset(spec.resources or ()))
            if isinstance(claimed, Conflict):
                raise ToolError(
                    "resource_conflict",
                    f"resource {claimed.resource.value!r} is in use by another "
                    "task; it must be released before this tool can run",
                    retryable=True,
                    hint="Wait for the other task to finish, or report the conflict.",
                )
            handle = claimed
        try:
            result, exc = self._dispatch(spec, args, handle)
        except BaseException:
            # The dispatch machinery itself failed (e.g. no thread): the
            # tool never ran, so its leases are rolled back now.
            _settle_leases(handle, spec, failed=True)
            raise
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
        self, spec: ToolSpec, args: dict, handle: LeaseHandle | None
    ) -> tuple[Any, BaseException | None]:
        """Run the tool on a helper thread; return ``(result, exception)``."""
        ctx = self.ctx
        registry = ctx.get_registry()
        lock = threading.Lock()
        state: dict[str, Any] = {"done": False, "abandoned": False}
        finished = threading.Event()
        timeout = spec.timeout_s if spec.timeout_s and spec.timeout_s > 0 else None
        deadline = None if timeout is None else time.monotonic() + timeout

        def body() -> None:
            from sandroid.core.timeline import acting_as

            _tool_deadline.set(deadline)
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
                        handle,
                        spec,
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
                    if handle is not None:
                        # Under the state lock: the body sees ``abandoned``
                        # only after the arbiter counts the owner as busy.
                        get_arbiter().abandon(handle)
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
        _settle_leases(handle, spec, result=result, failed=error is not None)
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
        except Exception as exc:
            logger.exception("Storing/shaping the result of %s failed", spec.name)
            content, size = self._fallback_content(result, rid, exc)
            truncated = True
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

    def _fallback_content(
        self, result: Any, rid: str | None, exc: BaseException
    ) -> tuple[str, int]:
        """A capped preview plus an error note (storing/shaping failed).

        Never sends the uncapped result: the preview is clipped to the ingest
        cap (and at most :data:`_FALLBACK_PREVIEW_CHARS` characters).
        """
        try:
            text = json.dumps(result, ensure_ascii=False, default=str)
        except Exception:
            try:
                text = str(result)
            except Exception:
                text = f"<unprintable {type(result).__name__}>"
        try:
            cap = self.ctx.cap_tokens or result_cap_tokens()
        except Exception:
            cap = 0
        limit = _FALLBACK_PREVIEW_CHARS
        if cap and cap > 0:
            limit = min(limit, int(cap * CHARS_PER_TOKEN * 0.9))
        limit = max(200, limit)
        preview = text[:limit]
        payload: dict[str, Any] = {
            "preview": preview,
            "truncated": len(text) > len(preview),
            "total_chars": len(text),
            "note": _redact(
                "the full result could not be stored or shaped "
                f"({type(exc).__name__}); only this preview is available"
                + ("" if rid is None else f"; read_result({rid!r}) may work")
            ),
        }
        if rid is not None:
            payload["result_id"] = rid
        return json.dumps(payload, ensure_ascii=False), len(
            text.encode("utf-8", errors="replace")
        )

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
            self._repair_pairs()
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

    def _repair_pairs(self) -> None:
        """Answer tool calls an internal error left unanswered (in memory).

        The next request would otherwise carry an assistant ``tool_calls``
        message without its tool replies, which backends reject. Resume
        repairs the persisted thread the same way.
        """
        try:
            repaired = repair_tool_pairs(self.messages)
            if repaired != self.messages:
                self.messages[:] = repaired
        except Exception:
            logger.exception("Repairing tool-call pairing failed")

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


def repair_tool_pairs(messages: list[dict]) -> list[dict]:
    """Answer tool calls a crash left unanswered (backends reject them).

    Unanswered calls get a ``cancelled`` error message right after their
    assistant message; orphan tool messages are dropped.
    """
    out: list[dict] = []
    pending: list[str] = []

    def flush() -> None:
        for call_id in pending:
            out.append(
                {
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": json.dumps(
                        {
                            "error": {
                                "code": "cancelled",
                                "message": "the session ended before this call "
                                "finished",
                                "retryable": True,
                            }
                        }
                    ),
                }
            )
        pending.clear()

    for msg in messages:
        if msg.get("role") == "tool":
            call_id = msg.get("tool_call_id")
            if call_id in pending:
                pending.remove(call_id)
                out.append(msg)
            continue  # orphan tool message: drop
        flush()
        out.append(msg)
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            pending.extend(
                c.get("id") for c in msg["tool_calls"] if isinstance(c, dict)
            )
    flush()
    return out


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
    "install_permission_resolver",
    "repair_tool_pairs",
    "run_turn",
    "summarize_result",
    "tool_time_remaining",
]
