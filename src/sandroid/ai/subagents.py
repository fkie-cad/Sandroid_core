"""Subagent mechanism: "agent-as-tool".

A subagent is just another :func:`sandroid.ai.loop.run_agent_turn` call,
recursively invoked with a narrower system prompt and a narrower tool subset.
The mechanism here is generic and data-driven (:class:`SubagentTemplate`:
name, system prompt, allowed tool-name subset) -- adding a real domain later
(static-analysis, dynamic-hooking, network, ...) is just adding a new
template entry once real Toolbox-wrapped tools exist to populate
``tool_names``, no mechanism changes required. For now there is exactly one
demo template (``device-inspector``) proving the mechanism end-to-end against
a deliberately mixed set of native + MCP tools.

This module *does* import :mod:`sandroid.core.toolbox` (unlike
:mod:`sandroid.ai.loop`, which is intentionally Toolbox-agnostic) -- dispatch
of a subagent is exactly where that integration belongs, so a running
subagent shows up in the StatusBar's background-task list, nested under the
top-level chat turn via ``started_by="chat"``.
"""

import threading
import uuid
from dataclasses import dataclass, field

from sandroid.ai.context import build_ambient_block
from sandroid.ai.loop import get_current_turn_context, run_agent_turn
from sandroid.ai.prompts import DEVICE_INSPECTOR_SYSTEM_PROMPT
from sandroid.ai.tools.registry import RiskTier, ToolSpec, get_tool_registry


@dataclass
class SubagentTemplate:
    """A named, data-driven subagent definition.

    Attributes:
        name: Template identifier (e.g. ``"device-inspector"``); also used
            to derive the orchestrator-facing tool name and the background
            task's display name.
        system_prompt: System prompt the subagent runs with -- narrower and
            more focused than the top-level orchestrator's.
        tool_names: Subset of :class:`~sandroid.ai.tools.registry.ToolRegistry`
            tool names this subagent is allowed to call (resolved via
            :meth:`~sandroid.ai.tools.registry.ToolRegistry.subset` at
            dispatch time, so tools registered after this template is defined
            -- e.g. MCP tools bridged in later -- still work).
    """

    name: str
    system_prompt: str
    tool_names: list[str] = field(default_factory=list)


SUBAGENT_TEMPLATES: dict[str, SubagentTemplate] = {
    "device-inspector": SubagentTemplate(
        name="device-inspector",
        system_prompt=DEVICE_INSPECTOR_SYSTEM_PROMPT,
        tool_names=[
            "get_foreground_app",  # native (sandroid.ai.tools.app_query)
            "is_package_installed",  # native
            "list_installed_packages",  # native
            "get_package_pid",  # native
            "get_package_details",  # native
            "list_exported_components",  # native
            "get_build_and_patch_info",  # native (sandroid.ai.tools.device_query)
            "check_root_and_magisk",  # native
            "mcp:sandroid-dummy:sample_forensic_lookup",  # external MCP demo
        ],
    ),
}


class _OrCancelEvent(threading.Event):
    """A cancel_event whose ``is_set()`` ORs a parent event with a local one.

    Lets a top-level Stop propagate into a running subagent (the parent's
    event is checked) while still giving the subagent its own independent
    stop switch (e.g. if the parent turn wants to cancel just this one
    subagent call in the future) -- without the subagent needing the parent
    Event object's identity for anything beyond reading it.
    """

    def __init__(self, parent: threading.Event, local: threading.Event):
        super().__init__()
        self._parent = parent
        self._local = local

    def is_set(self) -> bool:
        return self._parent.is_set() or self._local.is_set()

    def set(self) -> None:
        self._local.set()


def register_subagent_tools() -> None:
    """Register one orchestrator-facing tool per entry in SUBAGENT_TEMPLATES.

    Idempotent: safe to call more than once (each call just re-registers the
    same tool names, which :meth:`ToolRegistry.register` already treats as a
    normal overwrite). Called once at :mod:`sandroid.ai` import time.
    """
    for template in SUBAGENT_TEMPLATES.values():
        _register_template(template)


def _register_template(template: SubagentTemplate) -> None:
    tool_name = f"{template.name.replace('-', '_')}_agent"
    agent_func = _build_agent_tool(template)

    get_tool_registry().register(
        ToolSpec(
            name=tool_name,
            description=(
                f"Delegate a focused task to the {template.name} subagent, "
                "which can only see a narrow subset of tools relevant to it."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "task": {
                        "type": "string",
                        "description": "The task to delegate to this subagent.",
                    },
                },
                "required": ["task"],
            },
            func=agent_func,
            risk=RiskTier.READ_ONLY,
            category="subagent",
        )
    )


def _build_agent_tool(template: SubagentTemplate):
    """Build the orchestrator-facing tool function for one template.

    Returned as a closure (rather than one shared function parameterized at
    call time) so each template's tool has its own name/description/prompt
    baked in, matching how it's registered as a distinct ``ToolSpec``.
    """

    def agent_tool(task: str) -> str:
        from sandroid.core.toolbox import Toolbox

        turn_context = get_current_turn_context()
        if turn_context is None:
            # Defensive: this tool is only ever dispatched from inside a
            # running run_agent_turn() call, which always sets the context.
            raise RuntimeError(
                f"{template.name} subagent invoked outside of an active agent turn"
            )
        client, parent_cancel_event, approve = turn_context

        local_cancel = threading.Event()
        combined_cancel = _OrCancelEvent(parent_cancel_event, local_cancel)

        task_id = uuid.uuid4().hex[:8]
        task_name = f"chat-agent-{template.name}-{task_id}"
        Toolbox.register_background_task(
            name=task_name,
            display_name=f"AI Subagent: {template.name}",
            instance=local_cancel,
            stop_callback=local_cancel.set,
            started_by="chat",
        )
        try:
            # A subagent turn is one-shot and never persisted anywhere
            # outside this closure, so the ambient block can be spliced in
            # directly -- no identity-filter needed (contrast
            # chat_panel.py._run_turn_sync, which keeps `self._messages`
            # across turns and must filter it back out). Merged into the
            # SAME system message as the template's own prompt, not sent as
            # a second, separate system message -- the actually-configured
            # production model only attends to the first system-role
            # message in the list and silently ignores any later one
            # (confirmed against the real backend for the top-level chat
            # turn; this call site has the identical shape).
            sub_messages = [
                {
                    "role": "system",
                    "content": f"{template.system_prompt}\n\n{build_ambient_block()}",
                },
                {"role": "user", "content": task},
            ]
            sub_tools = get_tool_registry().subset(template.tool_names)
            return run_agent_turn(
                messages=sub_messages,
                tools=sub_tools,
                client=client,
                cancel_event=combined_cancel,
                approve=approve,
            )
        finally:
            Toolbox.unregister_background_task(task_name)

    return agent_tool
