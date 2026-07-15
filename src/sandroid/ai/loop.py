"""Provider-agnostic tool-calling loop.

Deliberately does not import :mod:`sandroid.core.toolbox` -- Toolbox
integration (registering a running turn as a background task so it shows up
in the StatusBar) is the caller's concern, not this loop's. See
:mod:`sandroid.ai.subagents`, which recurses into :func:`run_agent_turn` for
subagent dispatch and *does* import Toolbox, since that is exactly where the
Toolbox integration belongs.

The loop is a hand-rolled while-loop, not a framework (no LangChain/LangGraph/
OpenAI Agents SDK): stream a response, forward text as it arrives, accumulate
any tool-call fragments, dispatch complete tool calls once the stream ends,
append results, and repeat until the model stops asking for tools or
``max_iterations`` is hit.
"""

import json
import logging
import threading
from collections.abc import Callable
from contextvars import ContextVar

from sandroid.ai.client import OpenAIClient
from sandroid.ai.tools.registry import get_tool_registry

logger = logging.getLogger(__name__)

#: Default cap on tool-calling round-trips within a single turn, so a model
#: that keeps requesting tools can't loop forever.
MAX_ITERATIONS_DEFAULT = 8

#: (client, cancel_event) for the turn currently executing on this thread.
#: Subagent tool dispatch (sandroid.ai.subagents) reads this via
#: get_current_turn_context() to recurse into run_agent_turn with the same
#: client and a cancel_event that ORs the parent's. Deliberately lives here
#: (not in subagents.py) so this module has zero knowledge of subagents --
#: the dependency points one way: subagents.py -> loop.py.
_current_turn_context: ContextVar[tuple[OpenAIClient, threading.Event] | None] = (
    ContextVar("_current_turn_context", default=None)
)


def get_current_turn_context() -> tuple[OpenAIClient, threading.Event] | None:
    """Return the ``(client, cancel_event)`` of the turn running on this thread.

    Returns:
        The active turn's context, or ``None`` if no :func:`run_agent_turn`
        call is currently on the stack for this thread (subagent recursion is
        plain synchronous Python on the same worker thread, so a
        ``contextvars.ContextVar`` correctly scopes this to "the call
        currently in progress here" without any explicit passing through
        :class:`~sandroid.ai.tools.registry.ToolRegistry.dispatch`, which has
        no side-channel for extra context).
    """
    return _current_turn_context.get()


def run_agent_turn(
    messages: list[dict],
    tools: list[dict],
    client: OpenAIClient,
    cancel_event: threading.Event,
    on_event: Callable[[dict], None] | None = None,
    max_iterations: int = MAX_ITERATIONS_DEFAULT,
) -> str:
    """Drive one full agent turn (streaming + tool-calling) to completion.

    Args:
        messages: Chat history so far (mutated in place: assistant and tool
            messages are appended as the loop progresses).
        tools: The ``tools=[...]`` schema to offer the model this turn (see
            :meth:`~sandroid.ai.tools.registry.ToolRegistry.openai_tools_schema`
            or :meth:`~sandroid.ai.tools.registry.ToolRegistry.subset`).
        client: The backend client to stream from.
        cancel_event: Checked between streamed events, between loop
            iterations, and between tool dispatches; setting it stops the
            turn early and returns whatever text was accumulated so far.
        on_event: Optional callback invoked with every ChatEvent as it's
            produced (``text_delta``/``reasoning_delta`` live as they stream,
            plus a synthesized ``tool_call_done`` once a call's fragments are
            fully assembled, and any ``error`` event) -- this is how a UI
            renders token-by-token streaming.
        max_iterations: Cap on tool-calling round-trips within this turn.

    Returns:
        The final reply text not yet reflected in ``messages`` -- i.e. only
        the text from the turn's last iteration, since every earlier
        iteration's text was already persisted into ``messages`` alongside
        its tool calls (see :func:`_dispatch_tool_calls`). Returns ``""``
        when the turn ended in a way that's already fully persisted (hit
        ``max_iterations`` right after a tool round, or was cancelled
        immediately after one) -- the caller should only append this return
        value to its own message list when it's non-empty, never
        unconditionally, or a tool-calling round's text gets duplicated.
    """

    def emit(event: dict) -> None:
        if on_event is not None:
            on_event(event)

    # The exact name set offered to the model this turn -- dispatch refuses
    # anything outside it, so a narrower subset (e.g. a subagent's, built via
    # ToolRegistry.subset()) is an enforced boundary, not just advisory.
    allowed_names = {
        t["function"]["name"] for t in tools if t.get("type") == "function"
    }

    token = _current_turn_context.set((client, cancel_event))
    try:
        return _run_iterations(
            messages, tools, client, cancel_event, emit, max_iterations, allowed_names
        )
    finally:
        _current_turn_context.reset(token)


def _run_iterations(
    messages: list[dict],
    tools: list[dict],
    client: OpenAIClient,
    cancel_event: threading.Event,
    emit: Callable[[dict], None],
    max_iterations: int,
    allowed_names: set[str],
) -> str:
    for _ in range(max_iterations):
        if cancel_event.is_set():
            return ""

        text_accum, tool_calls, stopped_early = _stream_one_response(
            messages, tools, client, cancel_event, emit
        )
        if stopped_early:
            # Not yet persisted anywhere -- this partial reply is the
            # caller's to append (or discard) as it sees fit.
            return text_accum

        if not tool_calls:
            # The final natural-language answer -- also not yet persisted.
            return text_accum

        # _dispatch_tool_calls persists this round's text_accum (alongside
        # the tool calls it made) directly into `messages`. Anything
        # returned after this point must NOT re-include text_accum, or the
        # caller would duplicate it by appending the return value again.
        _dispatch_tool_calls(
            messages, tool_calls, text_accum, emit, cancel_event, allowed_names
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
    """Stream one ``client.chat(...)`` response.

    Returns:
        A tuple of ``(accumulated_text, tool_calls_by_index, stopped_early)``.
        ``stopped_early`` is True if the turn was cancelled or the backend
        reported an error mid-stream -- in both cases the caller should stop
        immediately rather than proceeding to tool dispatch.
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
) -> None:
    """Assemble, announce, append, and execute every tool call from one turn.

    Every ``tool_call_id`` declared in the appended assistant message is
    guaranteed a matching ``role="tool"`` response in ``messages`` by the
    time this returns, even if ``cancel_event`` fires mid-dispatch -- an
    OpenAI-compatible backend rejects a follow-up request that leaves any
    tool_call unanswered, so a cancelled dispatch synthesizes a "cancelled"
    error result for whatever wasn't reached rather than just stopping.
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
                registry, call["name"], parsed_by_index[index], allowed_names
            )
        messages.append({"role": "tool", "tool_call_id": call_id, "content": content})


def _dispatch_one(
    registry,
    name: str | None,
    arguments: dict,
    allowed_names: set[str] | None = None,
) -> str:
    """Dispatch one tool call, converting any failure into a tool-result error.

    A tool's own bug (or an unknown tool name, raised by the registry as
    ``ToolExecutionError``) must never crash the turn -- the model needs to
    see the failure and can react to it (retry differently, apologize, ask
    the user), so any exception here is caught and serialized as
    ``{"error": "..."}`` rather than propagated.

    If ``allowed_names`` is given (the name set actually offered to the
    model this turn -- see :func:`run_agent_turn`'s ``tools`` argument), a
    call to anything outside it is refused rather than dispatched: a
    narrower tool subset (e.g. a subagent's) is meant to be an enforced
    boundary, not just an advisory hint in the schema the model was shown.
    """
    if allowed_names is not None and name not in allowed_names:
        logger.debug("Tool %r not in this turn's allowed set; refusing", name)
        return json.dumps({"error": f"tool {name!r} is not available this turn"})
    try:
        result = registry.dispatch(name, arguments)
        return json.dumps(result)
    except Exception as exc:
        logger.debug("Tool %r raised during dispatch: %s", name, exc)
        return json.dumps({"error": str(exc)})


def _parse_arguments(raw_arguments: str) -> dict:
    if not raw_arguments:
        return {}
    try:
        return json.loads(raw_arguments)
    except json.JSONDecodeError:
        logger.debug("Failed to parse tool-call arguments as JSON: %r", raw_arguments)
        return {}
