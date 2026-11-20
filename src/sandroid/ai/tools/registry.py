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

import hashlib
import json
import logging
import re
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from sandroid.ai.arbiter import ResourceId
from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools.toolsets import (
    AGENTS_TOOLSET,
    DEFAULT_TIMEOUT_S,
    META_TOOL_NAMES,
    META_TOOLSET,
    TOOLSET_DESCRIPTIONS,
    is_mcp_toolset,
    lookup_entry,
    mcp_toolset,
)

logger = logging.getLogger(__name__)

#: Structured error codes a tool call can end with (see :class:`ToolError`).
TOOL_ERROR_CODES = frozenset(
    {
        "unknown_tool",
        "not_loaded",
        "invalid_arguments",
        "denied",
        "resource_conflict",
        "timeout",
        "cancelled",
        "device_unavailable",
        "tool_failed",
        "backend_error",
        # An app start the analyst must confirm in the TUI dialog, one the
        # analyst declined, one blocked by another start (app_start reasons).
        "needs_confirmation",
        "declined_by_analyst",
        "busy",
    }
)


class ToolError(ToolExecutionError):
    """A structured tool-call failure the model can react to.

    Subclasses :class:`ToolExecutionError`, so every existing ``except
    ToolExecutionError`` keeps catching it.

    Attributes:
        code: One of :data:`TOOL_ERROR_CODES`.
        message: Human/model-readable explanation.
        retryable: Whether repeating the same call may succeed later.
        hint: Optional next step for the model (e.g. "call tool_search").
        details: Extra JSON-serialisable fields (e.g. ``received``).
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        hint: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        if code not in TOOL_ERROR_CODES:
            raise ValueError(f"unknown tool error code {code!r}")
        self.code = code
        self.message = message
        self.retryable = retryable
        self.hint = hint
        self.details = dict(details or {})

    def to_dict(self) -> dict[str, Any]:
        """Return the model-facing ``{"error": {...}}`` payload."""
        error: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
        }
        if self.hint:
            error["hint"] = self.hint
        for key, value in self.details.items():
            error.setdefault(key, value)
        return {"error": error}

    def to_json(self) -> str:
        """Serialise :meth:`to_dict` (``default=str`` for odd detail values)."""
        return json.dumps(self.to_dict(), default=str, ensure_ascii=False)


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
        toolset: Toolset name (see :mod:`sandroid.ai.tools.toolsets`).
            Resolved from the central table on :meth:`ToolRegistry.register`;
            MCP tools get ``mcp:<server>``.
        core: Whether the tool is in the fixed per-session ``tools`` array.
            Resolved from the central table; never true for MCP tools.
        timeout_s: Seconds the executor waits for the call. Resolved from
            the central table, default 120.
        permission_key: For argument-dependent tools, the argument a
            remembered permission rule must constrain. Resolved from the
            central table.
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
    toolset: str = ""
    core: bool = False
    timeout_s: float = DEFAULT_TIMEOUT_S
    permission_key: str | None = None


#: Predicate deciding whether an agent may use a tool (subagent restrictions).
AllowedPredicate = Callable[[ToolSpec], bool]


def _resolve_exposure(spec: ToolSpec) -> None:
    """Apply the central toolset table (or the MCP derivation) to *spec*.

    The table wins for every name it lists. MCP tools get ``mcp:<server>`` and
    are never core. Anything else keeps what its constructor set, falling back
    to its free-form ``category`` as the toolset.
    """
    derived = mcp_toolset(spec.name)
    entry = lookup_entry(spec.name)
    if entry is not None and derived is None:
        spec.toolset = entry.toolset
        spec.core = entry.core
        spec.timeout_s = entry.timeout_s
        spec.permission_key = entry.permission_key
    elif derived is not None:
        spec.toolset = spec.toolset if is_mcp_toolset(spec.toolset) else derived
        spec.core = False
    elif not spec.toolset:
        spec.toolset = spec.category or "general"


def _canonical(value: Any) -> Any:
    """Return *value* with every dict's keys sorted, recursively."""
    if isinstance(value, dict):
        return {k: _canonical(value[k]) for k in sorted(value)}
    if isinstance(value, list | tuple):
        return [_canonical(v) for v in value]
    return value


def tools_schema_hash(tools: list[dict]) -> str:
    """Return a stable sha256 of a tools array (for thread headers)."""
    blob = json.dumps(tools, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class ToolRegistry:
    """Holds every tool available to the LLM loop, native or MCP-bridged.

    Thread safety: native tools register at import time, MCP bridges register
    late from a worker thread, and ``tool_search`` reads live. A re-entrant
    lock guards the dict; :attr:`version` increments on every change so search
    indexes know when to rebuild.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._lock = threading.RLock()
        self._version = 0

    @property
    def version(self) -> int:
        """Monotonic counter, bumped by every register/unregister."""
        return self._version

    def register(self, spec: ToolSpec) -> None:
        """Register (or overwrite) a tool spec.

        The spec's ``toolset``/``core``/``timeout_s``/``permission_key`` are
        resolved from the central toolset table in place. Overwriting an
        existing name is allowed (logged at debug level) rather than raising
        -- registration happens at module-import time, and a raising
        re-registration would turn an unrelated re-import into a hard crash.
        """
        _resolve_exposure(spec)
        with self._lock:
            if spec.name in self._tools:
                logger.debug("Tool %r already registered, overwriting", spec.name)
            self._tools[spec.name] = spec
            self._version += 1

    def unregister(self, name: str) -> bool:
        """Remove a tool (e.g. an MCP tool that vanished). Returns if it existed."""
        with self._lock:
            if self._tools.pop(name, None) is None:
                return False
            self._version += 1
            return True

    def specs(self) -> list[ToolSpec]:
        """Return a snapshot of every registered spec, in registration order."""
        with self._lock:
            return list(self._tools.values())

    def openai_tools_schema(self) -> list[dict]:
        """Return the full ``tools=[...]`` param shape for every registered tool."""
        return [self._to_schema_entry(spec) for spec in self.specs()]

    def subset(self, names: list[str]) -> list[dict]:
        """Same schema shape as :meth:`openai_tools_schema`, filtered by name.

        Names not currently registered are silently skipped (e.g. an MCP tool
        listed before :func:`bridge_mcp_tools` has run yet) rather than
        raising, so a tool set can be defined before every one of its tools
        necessarily exists.
        """
        wanted = set(names)
        return [
            self._to_schema_entry(spec) for spec in self.specs() if spec.name in wanted
        ]

    def names(self) -> list[str]:
        """Return the names of every currently registered tool."""
        with self._lock:
            return list(self._tools.keys())

    def get_spec(self, name: str) -> ToolSpec | None:
        """Look up a tool's spec without executing it.

        Args:
            name: Registered tool name.

        Returns:
            The registered :class:`ToolSpec`, or ``None`` if no tool is
            registered under ``name``.
        """
        with self._lock:
            return self._tools.get(name)

    def validate(self, name: str, arguments: Any) -> ToolError | None:
        """Validate *arguments* for tool *name* without dispatching.

        Returns:
            ``None`` when the call is well-formed, else a :class:`ToolError`
            (``unknown_tool`` or ``invalid_arguments``).
        """
        spec = self.get_spec(name)
        if spec is None:
            return ToolError("unknown_tool", f"Unknown tool: {name!r}")
        return validate_arguments(spec, arguments)

    def dispatch(self, name: str, arguments: dict) -> Any:
        """Look up, validate and call a tool by name.

        Args:
            name: Registered tool name.
            arguments: Keyword arguments passed through as ``func(**arguments)``.

        Returns:
            Whatever the tool's ``func`` returns.

        Raises:
            ToolError: (a :class:`ToolExecutionError`) if no tool is
                registered under ``name`` (``unknown_tool``) or the arguments
                fail schema validation (``invalid_arguments``: not an object,
                missing required, unknown key, wrong JSON type, value outside
                ``enum``) -- defence in depth: e.g. a model-supplied ``"1;id"``
                for an ``integer`` pid never reaches the tool. Any exception
                raised by the tool's own ``func`` propagates unchanged; the
                executor converts it into a tool-result error.
        """
        spec = self.get_spec(name)
        if spec is None:
            raise ToolError("unknown_tool", f"Unknown tool: {name!r}")
        check_arguments(spec, arguments)
        from sandroid.core.timeline import acting_as

        # Session-timeline lines a tool causes on this thread are the AI's.
        with acting_as("ai"):
            return spec.func(**arguments)

    def schema_entries(self, names: Iterable[str]) -> list[dict]:
        """Return canonical (key-sorted) schema entries for *names*, in order.

        Unregistered names are skipped. The result is deterministic for a
        given registry state, so ``json.dumps`` of it is byte-stable.
        """
        out: list[dict] = []
        seen: set[str] = set()
        for name in names:
            spec = self.get_spec(name)
            if spec is None or name in seen:
                continue
            seen.add(name)
            out.append(_canonical(self._to_schema_entry(spec)))
        return out

    def core_names(self, allowed: AllowedPredicate | None = None) -> list[str]:
        """Return the sorted names of core, non-meta, exposed tools."""
        return sorted(
            spec.name
            for spec in self.specs()
            if spec.core
            and spec.name not in META_TOOL_NAMES
            and spec.risk != RiskTier.NOT_EXPOSED
            and (allowed is None or allowed(spec))
        )

    def fixed_tools_array(
        self,
        *,
        allowed: AllowedPredicate | None = None,
        extras: Iterable[str | dict] = (),
    ) -> list[dict]:
        """Build the FIXED per-session ``tools`` array.

        Order: core tools (sorted by name), then the meta tools
        ``tool_search``/``call_tool``/``read_result`` (always included when
        registered), then *extras* in the given order (registered names, or
        ready-made schema entries such as agent tools). Every entry is
        key-sorted, so the array serialises byte-identically.

        Args:
            allowed: Optional per-agent predicate; core tools it rejects are
                left out. Meta tools are always kept.
            extras: Additional tool names or schema dicts (e.g. orchestrator
                agent tools).

        Returns:
            The list to send as ``tools`` for the whole session.
        """
        names = [*self.core_names(allowed), *META_TOOL_NAMES]
        tools = self.schema_entries(names)
        seen = {t["function"]["name"] for t in tools}
        for extra in extras:
            if isinstance(extra, dict):
                entry = _canonical(extra)
                name = (entry.get("function") or {}).get("name")
            else:
                entry_list = self.schema_entries([extra])
                if not entry_list:
                    continue
                entry, name = entry_list[0], extra
            if name in seen:
                continue
            seen.add(name)
            tools.append(entry)
        return tools

    def exposed_names(
        self,
        *,
        allowed: AllowedPredicate | None = None,
        extras: Iterable[str | dict] = (),
    ) -> frozenset[str]:
        """Names in :meth:`fixed_tools_array` (callable without loading)."""
        tools = self.fixed_tools_array(allowed=allowed, extras=extras)
        return frozenset(t["function"]["name"] for t in tools)

    def toolset_catalogue(self, *, allowed: AllowedPredicate | None = None) -> str:
        """Return the one-line-per-toolset catalogue for ``system[0]``.

        Lists every native toolset that has at least one visible non-core
        tool, in :data:`TOOLSET_DESCRIPTIONS` order, with its description and
        the names of its deferred tools. The ``core`` and ``agents`` toolsets
        and MCP toolsets (announced in the ambient block instead, see
        :meth:`mcp_catalogue`) are left out, so the text stays byte-stable for
        the session.
        """
        groups = self._deferred_by_toolset(allowed)
        order = [t for t in TOOLSET_DESCRIPTIONS if t in groups]
        order += sorted(t for t in groups if t not in TOOLSET_DESCRIPTIONS)
        lines = []
        for toolset in order:
            if toolset in (META_TOOLSET, AGENTS_TOOLSET) or is_mcp_toolset(toolset):
                continue
            desc = TOOLSET_DESCRIPTIONS.get(toolset, toolset)
            names = ", ".join(sorted(groups[toolset]))
            lines.append(f"- {toolset}: {desc}. Tools: {names}")
        return "\n".join(lines)

    def mcp_catalogue(self, *, allowed: AllowedPredicate | None = None) -> str:
        """Return one line per bridged MCP server, for the ambient block."""
        groups = self._deferred_by_toolset(allowed)
        lines = []
        for toolset in sorted(t for t in groups if is_mcp_toolset(t)):
            names = ", ".join(sorted(groups[toolset]))
            lines.append(
                f"- {toolset} (external server, asks before each call; use "
                f"call_tool): {names}"
            )
        return "\n".join(lines)

    def _deferred_by_toolset(
        self, allowed: AllowedPredicate | None
    ) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = {}
        for spec in self.specs():
            if spec.core or spec.risk == RiskTier.NOT_EXPOSED:
                continue
            if allowed is not None and not allowed(spec):
                continue
            groups.setdefault(spec.toolset, []).append(spec.name)
        return groups

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


def _short(value: Any, limit: int = 80) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _check_value(key: str, value: Any, prop: dict, errors: list[str]) -> None:
    json_type = prop.get("type")
    if json_type is not None and not _matches_json_type(value, json_type):
        errors.append(
            f"argument {key!r} must be of type {json_type}, got "
            f"{type(value).__name__} {_short(value)}"
        )
        return
    enum = prop.get("enum")
    if isinstance(enum, list) and value not in enum:
        errors.append(f"argument {key!r} must be one of {enum}, got {_short(value)}")
    items = prop.get("items")
    if isinstance(value, list | tuple) and isinstance(items, dict):
        item_type = items.get("type")
        item_enum = items.get("enum")
        for item in value:
            if item_type is not None and not _matches_json_type(item, item_type):
                errors.append(
                    f"argument {key!r} items must be of type {item_type}, got "
                    f"{type(item).__name__} {_short(item)}"
                )
                return
            if isinstance(item_enum, list) and item not in item_enum:
                errors.append(
                    f"argument {key!r} items must be one of {item_enum}, got "
                    f"{_short(item)}"
                )
                return


def validate_arguments(spec: ToolSpec, arguments: Any) -> ToolError | None:
    """Validate *arguments* against the tool's top-level JSON schema.

    Checks: the arguments are an object; every ``required`` key is present;
    no key outside ``properties`` (unless the schema sets
    ``additionalProperties`` to true or a schema); each value's JSON ``type``
    (arrays: also ``items.type``); ``enum`` membership. No jsonschema
    dependency; nested objects are left to the tool itself.

    Returns:
        ``None`` if valid, else an ``invalid_arguments`` :class:`ToolError`
        listing every problem, with the valid parameter names in ``details``.
    """
    if not isinstance(arguments, dict):
        return ToolError(
            "invalid_arguments",
            f"{spec.name}: arguments must be a JSON object, "
            f"got {type(arguments).__name__}",
            hint="Pass the arguments as a JSON object.",
        )
    schema = spec.parameters or {}
    properties = schema.get("properties") or {}
    required = [r for r in (schema.get("required") or []) if isinstance(r, str)]
    additional = schema.get("additionalProperties", False)
    errors: list[str] = []
    missing = [r for r in required if r not in arguments]
    if missing:
        errors.append(f"missing required argument(s): {', '.join(missing)}")
    if not additional:
        unknown = [k for k in arguments if k not in properties]
        if unknown:
            errors.append(f"unknown argument(s): {', '.join(map(str, unknown))}")
    for key, value in arguments.items():
        prop = properties.get(key)
        if isinstance(prop, dict):
            _check_value(key, value, prop, errors)
    if not errors:
        return None
    return ToolError(
        "invalid_arguments",
        f"{spec.name}: " + "; ".join(errors),
        retryable=True,
        hint="Fix the arguments to match the tool's parameter schema.",
        details={"errors": errors, "valid_parameters": sorted(properties)},
    )


def check_arguments(spec: ToolSpec, arguments: Any) -> None:
    """Raise the :func:`validate_arguments` error, if any.

    Raises:
        ToolError: ``invalid_arguments``.
    """
    error = validate_arguments(spec, arguments)
    if error is not None:
        raise error


_FENCE_RE = re.compile(r"^\s*```[a-zA-Z0-9_-]*\s*\n?(.*?)\n?\s*```\s*$", re.DOTALL)
_TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")


def parse_tool_arguments(raw: Any) -> dict:
    """Parse a model-supplied tool-arguments value into a dict.

    Accepts a dict (returned as is), ``None``/empty string (``{}``) or a JSON
    string. One cheap repair is attempted on unparsable text: strip a code
    fence and trailing commas. Never falls back to ``{}`` for bad input.

    Raises:
        ToolError: ``invalid_arguments`` when the text is not JSON or parses
            to something other than an object; ``received`` holds the first
            500 characters.
    """
    if isinstance(raw, dict):
        return raw
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return {}
    if not isinstance(raw, str):
        raise ToolError(
            "invalid_arguments",
            f"arguments must be a JSON object, got {type(raw).__name__}",
            retryable=True,
            details={"received": _short(raw, 500)},
        )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        repaired = raw.strip()
        fenced = _FENCE_RE.match(repaired)
        if fenced:
            repaired = fenced.group(1)
        repaired = _TRAILING_COMMA_RE.sub(r"\1", repaired)
        try:
            parsed = json.loads(repaired)
        except json.JSONDecodeError as exc:
            raise ToolError(
                "invalid_arguments",
                f"arguments are not valid JSON: {exc.msg} at char {exc.pos}",
                retryable=True,
                hint="Send the arguments as one JSON object.",
                details={"received": raw[:500]},
            ) from None
    if not isinstance(parsed, dict):
        raise ToolError(
            "invalid_arguments",
            f"arguments must be a JSON object, got {type(parsed).__name__}",
            retryable=True,
            details={"received": raw[:500]},
        )
    return parsed


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
    time (i.e. at import time of whatever module defines the tool). Toolset,
    core flag, timeout and permission key come from the central table in
    :mod:`sandroid.ai.tools.toolsets`.

    Args:
        name: Unique tool name.
        description: Human/LLM-readable description.
        parameters: Hand-written JSON Schema for the tool's arguments.
        risk: Safety tier, see :class:`RiskTier`.
        category: Free-form grouping label.
        can_remember_choice: Whether an "Allow always" choice for this tool
            may be persisted, see :attr:`ToolSpec.can_remember_choice`.
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
