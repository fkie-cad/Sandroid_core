"""Tool registry for the Sandroid AI package.

Merges two kinds of tools behind one flat namespace and one schema shape:

- native, in-process Python functions (see :mod:`sandroid.ai.tools.app_query`
  and :mod:`sandroid.ai.tools.device_query`)
- tools bridged in from external MCP servers, registered as
  ``mcp:<server>:<tool>`` (see :mod:`sandroid.ai.tools.mcp_bridge`)

The LLM tool-calling loop (:mod:`sandroid.ai.loop`) only ever talks to a
:class:`ToolRegistry` -- it has no idea whether a given tool dispatches to a
plain Python call or a round-trip through an MCP session.

Usage::

    from sandroid.ai.tools.registry import sandroid_tool, RiskTier

    @sandroid_tool(
        name="get_emulator_status",
        description="Get the current status of the running Android emulator.",
        parameters={"type": "object", "properties": {}, "required": []},
    )
    def get_emulator_status() -> dict:
        ...

Decorating a function registers it into the module-level singleton
(:func:`get_tool_registry`) at *decoration time* -- i.e. at import time of
whatever module defines the tool.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from sandroid.ai.arbiter import ResourceId
from sandroid.ai.errors import ToolExecutionError

logger = logging.getLogger(__name__)


class RiskTier(IntEnum):
    """How consequential a tool call is; consulted by the permission gate.

    ``READ_ONLY`` calls auto-run. ``REVERSIBLE``/``CONSEQUENTIAL`` calls
    prompt the analyst for approval (see :mod:`sandroid.ai.tool_permissions`).
    """

    READ_ONLY = 0
    REVERSIBLE = 1
    CONSEQUENTIAL = 2
    NOT_EXPOSED = 3


@dataclass
class ToolSpec:
    """A single tool's schema plus its dispatch target.

    Attributes:
        name: Unique tool name as seen by the LLM (e.g. ``get_emulator_status``
            or ``mcp:<server>:<tool>``).
        description: Human/LLM-readable description of what the tool does.
        parameters: Hand-written JSON Schema for the tool's arguments -- the
            ``function.parameters`` shape from OpenAI's tool-calling spec,
            e.g. ``{"type": "object", "properties": {...}, "required": [...]}``.
        func: Callable dispatched with ``func(**arguments)``.
        risk: Safety tier (see :class:`RiskTier`). Defaults to read-only.
        category: Free-form grouping label (e.g. ``"general"``, ``"mcp"``,
            ``"subtask"``), used for display/filtering, not enforced.
        can_remember_choice: Whether a user's "Allow always"/"Never" choice
            for this tool may be persisted and reused on future calls (see
            :mod:`sandroid.ai.tool_permissions`). Defaults to ``True``. Set
            to ``False`` for tools whose risk lives in their *arguments*
            rather than their identity (e.g. ``invoke_exported_component`` --
            approving one call must not silently approve every future call
            with different, unreviewed arguments): such a tool always
            resolves to ``"ask"`` and its decline is call-scoped only, never
            written to the permission store.
        resources: Device resources (see
            :class:`~sandroid.ai.arbiter.ResourceId`) this tool needs an
            exclusive lease on for the duration of its dispatch. The loop
            claims them from the :class:`~sandroid.ai.arbiter.DeviceResourceArbiter`
            after the permission gate and before dispatch, and rolls the
            newly-acquired ones back on failure. Empty (the default) means a
            read-only tool that touches no shared resource and skips the
            arbiter entirely. Never sent to the model.
        releases: Device resources this tool *releases* on a successful
            dispatch (e.g. ``clear_device_proxy`` releases
            :attr:`~sandroid.ai.arbiter.ResourceId.DEVICE_PROXY`). Empty by
            default. Never sent to the model.
    """

    name: str
    description: str
    parameters: dict
    func: Callable
    risk: RiskTier = RiskTier.READ_ONLY
    category: str = "general"
    can_remember_choice: bool = True
    resources: frozenset[ResourceId] = frozenset()
    releases: frozenset[ResourceId] = frozenset()


class ToolRegistry:
    """Holds every tool available to the LLM loop, native or MCP-bridged.

    Thread safety: registration happens at import time (native tools) or once
    at MCP-bridge time, both effectively single-threaded in practice; reads
    (``dispatch``/``openai_tools_schema``/``subset``) are plain dict lookups.
    No locking is used -- mirrors the low-contention assumption already made
    by similar registries in this codebase (e.g. app-selection parsers).
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        """Register (or overwrite) a tool spec.

        Overwriting an existing name is allowed (logged at debug level) rather
        than raising -- registration happens at module-import time, and a
        raising re-registration would turn an unrelated re-import into a hard
        crash.
        """
        if spec.name in self._tools:
            logger.debug("Tool %r already registered, overwriting", spec.name)
        self._tools[spec.name] = spec

    def openai_tools_schema(self) -> list[dict]:
        """Return the full ``tools=[...]`` param shape for every registered tool."""
        return [self._to_schema_entry(spec) for spec in self._tools.values()]

    def subset(self, names: list[str]) -> list[dict]:
        """Same schema shape as :meth:`openai_tools_schema`, filtered by name.

        Used to build a subtask's narrower tool view. Names not currently
        registered are silently skipped (e.g. an MCP tool listed in a
        subtask's tool set before :func:`bridge_mcp_tools` has run yet)
        rather than raising, so a tool set can be defined before every one of
        its tools necessarily exists.
        """
        wanted = set(names)
        return [
            self._to_schema_entry(spec)
            for spec in self._tools.values()
            if spec.name in wanted
        ]

    def names(self) -> list[str]:
        """Return the names of every currently registered tool.

        Used to compute a privileged tool subset dynamically (e.g. a
        subtask's allowed set), so the caller does not have to hardcode a
        list that would drift as tools are added or MCP tools bridged in.
        """
        return list(self._tools.keys())

    def dispatch(self, name: str, arguments: dict) -> Any:
        """Look up and call a tool by name.

        Args:
            name: Registered tool name.
            arguments: Keyword arguments passed through as ``func(**arguments)``.

        Returns:
            Whatever the tool's ``func`` returns.

        Raises:
            ToolExecutionError: If no tool is registered under ``name``, or
                an argument does not match the JSON-schema ``type`` its tool
                declares (defence in depth: e.g. a model-supplied ``"1;id"``
                for an ``integer`` pid never reaches the tool). Any
                exception raised by the tool's own ``func`` propagates
                unchanged -- the caller (:mod:`sandroid.ai.loop`) is
                responsible for catching and converting that into a
                tool-result error message, so the model can see and react to
                a failing tool instead of the whole turn crashing.
        """
        spec = self._tools.get(name)
        if spec is None:
            raise ToolExecutionError(f"Unknown tool: {name!r}")
        _check_argument_types(spec, arguments)
        from sandroid.core.timeline import acting_as

        # Session-timeline lines a tool causes on this thread are the AI's.
        with acting_as("ai"):
            return spec.func(**arguments)

    def get_spec(self, name: str) -> ToolSpec | None:
        """Look up a tool's spec without executing it.

        Non-executing counterpart to :meth:`dispatch`'s lookup -- used by the
        tool-permission gate (:mod:`sandroid.ai.tool_permissions`) to inspect
        a tool's ``risk``/``can_remember_choice`` before deciding whether to
        call it at all.

        Args:
            name: Registered tool name.

        Returns:
            The registered :class:`ToolSpec`, or ``None`` if no tool is
            registered under ``name``.
        """
        return self._tools.get(name)

    @staticmethod
    def _to_schema_entry(spec: ToolSpec) -> dict:
        return {
            "type": "function",
            "function": {
                "name": spec.name,
                "description": spec.description,
                "parameters": spec.parameters,
            },
        }


#: JSON-schema primitive type -> accepted Python types (``bool`` is an
#: ``int`` subclass in Python but never a JSON integer/number).
_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "array": (list, tuple),
    "object": (dict,),
    "null": (type(None),),
}


def _matches_json_type(value: Any, json_type: Any) -> bool:
    """True if *value* matches a JSON-schema ``type`` (str or list of str).

    Unknown/missing types match anything (the check is a minimal guard, not a
    full validator). ``3.0`` counts as an ``integer`` like in JSON Schema.
    """
    types = json_type if isinstance(json_type, list) else [json_type]
    for t in types:
        accepted = _JSON_TYPES.get(t) if isinstance(t, str) else None
        if accepted is None:
            return True
        if t in ("integer", "number") and isinstance(value, bool):
            continue
        if t == "integer" and isinstance(value, float) and value.is_integer():
            return True
        if isinstance(value, accepted):
            return True
    return False


def _check_argument_types(spec: ToolSpec, arguments: dict) -> None:
    """Reject arguments whose type contradicts the tool's declared schema.

    Checks each top-level argument with a declared ``type`` (and, for arrays,
    the declared ``items.type`` of each element). No jsonschema dependency;
    anything the schema does not declare is left to the tool itself.

    Raises:
        ToolExecutionError: An argument has the wrong JSON type.
    """
    if not isinstance(arguments, dict):
        raise ToolExecutionError(
            f"{spec.name}: arguments must be a JSON object, "
            f"got {type(arguments).__name__}"
        )
    properties = (spec.parameters or {}).get("properties") or {}
    for key, value in arguments.items():
        prop = properties.get(key)
        if not isinstance(prop, dict) or "type" not in prop:
            continue
        if not _matches_json_type(value, prop["type"]):
            raise ToolExecutionError(
                f"{spec.name}: argument {key!r} must be of type "
                f"{prop['type']}, got {type(value).__name__} {value!r}"
            )
        items = prop.get("items")
        if isinstance(value, list | tuple) and isinstance(items, dict):
            item_type = items.get("type")
            if item_type is None:
                continue
            for item in value:
                if not _matches_json_type(item, item_type):
                    raise ToolExecutionError(
                        f"{spec.name}: argument {key!r} items must be of type "
                        f"{item_type}, got {type(item).__name__} {item!r}"
                    )


_tool_registry: ToolRegistry | None = None


def get_tool_registry() -> ToolRegistry:
    """Get or create the ToolRegistry singleton.

    Returns:
        ToolRegistry instance shared by every tool source (native + MCP).
    """
    global _tool_registry
    if _tool_registry is None:
        _tool_registry = ToolRegistry()
    return _tool_registry


def sandroid_tool(
    name: str,
    description: str,
    parameters: dict,
    risk: RiskTier = RiskTier.READ_ONLY,
    category: str = "general",
    can_remember_choice: bool = True,
    resources: frozenset[ResourceId] = frozenset(),
    releases: frozenset[ResourceId] = frozenset(),
) -> Callable:
    """Decorator that wraps a function and registers it as a tool.

    Builds a :class:`ToolSpec` from the decorated function and registers it
    into the module-level :func:`get_tool_registry` singleton at decoration
    time (i.e. at import time of whatever module defines the tool).

    Args:
        name: Unique tool name.
        description: Human/LLM-readable description.
        parameters: Hand-written JSON Schema for the tool's arguments.
        risk: Safety tier, see :class:`RiskTier`.
        category: Free-form grouping label.
        can_remember_choice: Whether an "Allow always"/"Never" choice for
            this tool may be persisted, see :attr:`ToolSpec.can_remember_choice`.
        resources: Device resources this tool needs an exclusive lease on,
            see :attr:`ToolSpec.resources`.
        releases: Device resources this tool releases on success, see
            :attr:`ToolSpec.releases`.

    Returns:
        A decorator that returns the original function unchanged.
    """

    def decorator(func: Callable) -> Callable:
        get_tool_registry().register(
            ToolSpec(
                name=name,
                description=description,
                parameters=parameters,
                func=func,
                risk=risk,
                category=category,
                can_remember_choice=can_remember_choice,
                resources=resources,
                releases=releases,
            )
        )
        return func

    return decorator
