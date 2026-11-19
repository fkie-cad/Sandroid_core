"""Meta tools: ``tool_search``, ``call_tool`` and ``read_result``.

The per-session ``tools`` array is fixed (core tools plus these three, see
:meth:`~sandroid.ai.tools.registry.ToolRegistry.fixed_tools_array`); every
other tool is found with ``tool_search`` and then called through
``call_tool(name, arguments)`` or directly by name once loaded.

How the runtime's executor uses this module (every call, including
``call_tool`` and direct calls to loaded tools, takes the same path)::

    ctx = MetaContext(loaded=thread_loaded, allowed=agent_allows, store=store)
    with use_meta_context(ctx):
        try:
            call = resolve_call(name, raw_arguments, loaded=ctx.loaded,
                                allowed=ctx.allowed, exposed=session_names)
        except ToolError as err:
            content = err.to_json()          # unknown_tool / not_loaded / ...
        else:
            # permission/approval on call.spec + call.arguments, arbiter
            # leases on call.spec.resources, then
            result = registry.dispatch(call.spec.name, call.arguments)
            stored = store.put(call.spec.name, call.arguments, result,
                               agent_id=agent_id)
            content = shape_result(result, stored.id, budget=turn_budget)

``call_tool`` is never dispatched itself: :func:`resolve_call` unwraps it into
the inner tool's spec, so the inner tool's risk tier, permission rules and
leases apply. Its registered function fails closed if anything dispatches it
directly. ``tool_search`` and ``read_result`` are ordinary read-only tools that
read the :class:`MetaContext` of the calling thread.
"""

from __future__ import annotations

import contextlib
import difflib
import math
import re
import threading
import weakref
from collections import Counter
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sandroid.ai.results import (
    ResultStore,
    get_result_store,
    read_stored_result,
    session_root,
)
from sandroid.ai.tools.registry import (
    AllowedPredicate,
    RiskTier,
    ToolError,
    ToolRegistry,
    ToolSpec,
    get_tool_registry,
    parse_tool_arguments,
    validate_arguments,
)
from sandroid.ai.tools.toolsets import META_TOOL_NAMES, TOOLSET_DESCRIPTIONS

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

#: Number of full schemas ``tool_search`` returns.
SEARCH_LIMIT = 5


class LoadedTools:
    """Names loaded via ``tool_search`` in one conversation thread.

    Thread-safe; persisted by the runtime (``names()``) and restored on resume
    (``LoadedTools(saved_names)``).
    """

    def __init__(self, names: Iterable[str] = ()) -> None:
        """Create the set, optionally pre-filled (resume)."""
        self._names: set[str] = set(names)
        self._lock = threading.Lock()

    def add(self, names: Iterable[str]) -> None:
        """Mark *names* as loaded."""
        with self._lock:
            self._names.update(names)

    def __contains__(self, name: object) -> bool:
        with self._lock:
            return name in self._names

    def names(self) -> list[str]:
        """Return the loaded names, sorted."""
        with self._lock:
            return sorted(self._names)


@dataclass
class MetaContext:
    """Per-thread state the meta tools need, set by the executor.

    Attributes:
        loaded: The thread's loaded tool names.
        allowed: The calling agent's tool predicate (``None``: everything).
        store: The session's result store (``None``: the store of the current
            session root).
        cap_tokens: Ingest cap for ``read_result`` (``None``: configured).
        registry: Registry to search (``None``: the singleton).
    """

    loaded: LoadedTools = field(default_factory=LoadedTools)
    allowed: AllowedPredicate | None = None
    store: ResultStore | None = None
    cap_tokens: int | None = None
    registry: ToolRegistry | None = None


_meta_context: ContextVar[MetaContext | None] = ContextVar(
    "sandroid_ai_meta_context", default=None
)


@contextlib.contextmanager
def use_meta_context(ctx: MetaContext) -> Iterator[MetaContext]:
    """Make *ctx* the meta context of this thread/context for the block.

    It propagates into helper threads started with
    ``contextvars.copy_context().run``.
    """
    token = _meta_context.set(ctx)
    try:
        yield ctx
    finally:
        _meta_context.reset(token)


def current_meta_context() -> MetaContext | None:
    """Return the active :class:`MetaContext`, if any."""
    return _meta_context.get()


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResolvedCall:
    """A tool call ready for permission check, leases and dispatch.

    Attributes:
        spec: The tool that will actually run (the inner tool for
            ``call_tool``). Its risk tier governs approval.
        arguments: Parsed, normalised and validated arguments.
        via_call_tool: Whether the model used ``call_tool``.
    """

    spec: ToolSpec
    arguments: dict
    via_call_tool: bool = False

    @property
    def name(self) -> str:
        """Name of the tool that will run."""
        return self.spec.name


def _schema_allows_null(prop: Any) -> bool:
    if not isinstance(prop, dict):
        return True
    types = prop.get("type")
    types = types if isinstance(types, list) else [types]
    return "null" in types or types == [None]


def normalize_arguments(spec: ToolSpec, arguments: dict) -> dict:
    """Drop ``null`` values of optional parameters that do not accept null.

    Models often send ``"activity_name": null`` to mean "not given"; the
    tool's own default is the right value then.
    """
    schema = spec.parameters or {}
    properties = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    return {
        k: v
        for k, v in arguments.items()
        if not (
            v is None
            and k not in required
            and k in properties
            and not _schema_allows_null(properties[k])
        )
    }


def _usable(spec: ToolSpec, allowed: AllowedPredicate | None) -> bool:
    if spec.risk == RiskTier.NOT_EXPOSED:
        return False
    return allowed is None or bool(allowed(spec))


def _unknown_tool(name: str, registry: ToolRegistry, allowed) -> ToolError:
    candidates = [
        s.name for s in registry.specs() if _usable(s, allowed) and s.name != name
    ]
    close = difflib.get_close_matches(name, candidates, n=3, cutoff=0.6)
    hint = "Use tool_search('<what you want to do>') to find the right tool."
    if close:
        hint = f"Did you mean {', '.join(close)}? " + hint
    return ToolError("unknown_tool", f"Unknown tool: {name!r}", hint=hint)


def resolve_call(
    name: str | None,
    arguments: Any,
    *,
    loaded: LoadedTools,
    allowed: AllowedPredicate | None = None,
    exposed: Iterable[str] | None = None,
    registry: ToolRegistry | None = None,
) -> ResolvedCall:
    """Resolve a model tool call into the spec and arguments to execute.

    Unwraps ``call_tool``; checks that the tool exists, that the calling agent
    may use it, and (for direct calls) that it is in the session's tools array
    or was loaded via ``tool_search``; normalises and validates the
    arguments. ``call_tool`` may name any usable tool (loaded or not; it is
    then remembered as loaded).

    Args:
        name: Function name as the model sent it.
        arguments: Raw arguments (JSON string or dict).
        loaded: The thread's loaded names (updated for ``call_tool``).
        allowed: The calling agent's tool predicate.
        exposed: Names in the session's fixed tools array (default: every
            core tool and the meta tools).
        registry: Registry to resolve against (default: singleton).

    Returns:
        The :class:`ResolvedCall`.

    Raises:
        ToolError: ``unknown_tool``, ``not_loaded``, ``denied`` (not available
            to this agent) or ``invalid_arguments``.
    """
    registry = registry or get_tool_registry()
    if not name or not isinstance(name, str):
        raise ToolError(
            "unknown_tool",
            "tool call without a function name",
            hint="Call a tool by its exact name.",
        )
    args = parse_tool_arguments(arguments)
    via_call_tool = name == "call_tool"
    if via_call_tool:
        name, args = _unwrap_call_tool(args)

    spec = registry.get_spec(name)
    if spec is None:
        raise _unknown_tool(name, registry, allowed)
    if not _usable(spec, allowed):
        raise ToolError(
            "denied",
            f"tool {name!r} is not available to this agent",
            hint="Use a different tool or report back what you need.",
        )
    if via_call_tool:
        loaded.add([name])
    else:
        exposed_names = (
            set(exposed)
            if exposed is not None
            else {s.name for s in registry.specs() if s.core} | set(META_TOOL_NAMES)
        )
        if name not in exposed_names and name not in loaded:
            raise ToolError(
                "not_loaded",
                f"tool {name!r} is not loaded",
                retryable=True,
                hint=(
                    f"Call tool_search('select:{name}') to load its schema, or "
                    f"call_tool(name='{name}', arguments={{...}})."
                ),
            )
    args = normalize_arguments(spec, args)
    error = validate_arguments(spec, args)
    if error is not None:
        raise error
    return ResolvedCall(spec, args, via_call_tool)


def _unwrap_call_tool(args: dict) -> tuple[str, dict]:
    inner = args.get("name")
    if not isinstance(inner, str) or not inner.strip():
        raise ToolError(
            "invalid_arguments",
            "call_tool needs 'name' (the tool to call) as a string",
            retryable=True,
            hint="call_tool(name='<tool>', arguments={...})",
        )
    inner = inner.strip()
    if inner == "call_tool":
        raise ToolError(
            "invalid_arguments",
            "call_tool cannot call itself",
            hint="Put the target tool's name in 'name'.",
        )
    if "arguments" in args:
        extra = [k for k in args if k not in ("name", "arguments")]
        if extra:
            raise ToolError(
                "invalid_arguments",
                f"call_tool takes only 'name' and 'arguments', got {extra}",
                retryable=True,
                hint="Put the tool's own arguments inside 'arguments'.",
            )
        inner_args = parse_tool_arguments(args["arguments"])
    else:
        # Repair: the tool's arguments were given flat next to 'name'.
        inner_args = {k: v for k, v in args.items() if k != "name"}
    return inner, inner_args


# ---------------------------------------------------------------------------
# Search (BM25)
# ---------------------------------------------------------------------------

_STOPWORDS = frozenset(
    (
        *("a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "if"),
        *("in", "into", "is", "it", "its", "of", "on", "or", "the", "this"),
        *("that", "to", "with", "when", "which", "what", "use", "used"),
        *("returns", "return", "tool", "tools"),
    )
)
_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")
_WORD_RE = re.compile(r"[a-z0-9]+")
_CONSONANTS = frozenset("bcdfghjklmnpqrstvwxz")


def _stem(word: str) -> str:
    if len(word) > 4 and word.endswith("ies"):
        word = word[:-3] + "y"
    elif len(word) > 4 and word.endswith(("sses", "xes", "ches", "shes")):
        word = word[:-2]
    elif len(word) > 3 and word.endswith("s") and not word.endswith(("ss", "us", "is")):
        word = word[:-1]
    for suffix in ("ing", "ed"):
        if len(word) > len(suffix) + 3 and word.endswith(suffix):
            word = word[: -len(suffix)]
            if len(word) > 3 and word[-1] == word[-2] and word[-1] in _CONSONANTS:
                word = word[:-1]
            break
    if len(word) > 4 and word.endswith("e"):
        word = word[:-1]
    return word


def tokenize(text: str) -> list[str]:
    """Split snake_case/camelCase/prose into lower-case, lightly stemmed terms."""
    text = _CAMEL_RE.sub(r"\1 \2", text or "").lower()
    return [
        _stem(w) for w in _WORD_RE.findall(text) if w not in _STOPWORDS and len(w) > 1
    ]


def _document_terms(spec: ToolSpec) -> list[str]:
    terms = tokenize(spec.name) * 3
    terms += tokenize(spec.toolset.replace(":", " "))
    terms += tokenize(TOOLSET_DESCRIPTIONS.get(spec.toolset, ""))
    terms += tokenize(spec.description)
    for pname, prop in ((spec.parameters or {}).get("properties") or {}).items():
        terms += tokenize(pname)
        if isinstance(prop, dict):
            terms += tokenize(str(prop.get("description", "")))
    return terms


class _Bm25Index:
    """Okapi BM25 over every exposed tool of one registry version."""

    K1 = 1.2
    B = 0.75

    def __init__(self, specs: list[ToolSpec]) -> None:
        self.docs = [
            (s.name, Counter(terms), len(terms))
            for s in specs
            for terms in [_document_terms(s)]
        ]
        self.avgdl = sum(d[2] for d in self.docs) / len(self.docs) if self.docs else 1
        df: Counter[str] = Counter()
        for _, counts, _ in self.docs:
            df.update(counts.keys())
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def rank(self, query: str) -> list[tuple[float, str]]:
        """Return ``(score, name)`` for every matching tool, best first."""
        weights: dict[str, float] = {}
        for term in set(tokenize(query)):
            if term in self.idf:
                weights[term] = 1.0
            elif len(term) >= 3:
                # Unknown word: half credit for terms it prefixes (mitm ->
                # mitmproxy).
                for known in self.idf:
                    if known.startswith(term):
                        weights.setdefault(known, 0.5)
        scored = []
        for name, counts, length in self.docs:
            score = 0.0
            for term, weight in weights.items():
                tf = counts.get(term)
                if not tf:
                    continue
                norm = tf + self.K1 * (1 - self.B + self.B * length / self.avgdl)
                score += weight * self.idf[term] * tf * (self.K1 + 1) / norm
            if score > 0:
                scored.append((score, name))
        scored.sort(key=lambda sn: (-sn[0], sn[1]))
        return scored


_index_cache: weakref.WeakKeyDictionary[ToolRegistry, tuple[int, _Bm25Index]] = (
    weakref.WeakKeyDictionary()
)
_index_lock = threading.Lock()


def _index_for(registry: ToolRegistry) -> _Bm25Index:
    """Return the registry's index, rebuilt when its version changed."""
    with _index_lock:
        version = registry.version
        cached = _index_cache.get(registry)
        if cached is not None and cached[0] == version:
            return cached[1]
        specs = [s for s in registry.specs() if s.risk != RiskTier.NOT_EXPOSED]
        index = _Bm25Index(specs)
        _index_cache[registry] = (version, index)
        return index


def _search_entry(spec: ToolSpec) -> dict:
    return {
        "name": spec.name,
        "toolset": spec.toolset,
        "risk": spec.risk.name.lower(),
        "description": spec.description,
        "parameters": spec.parameters,
    }


def search_tools(
    query: str,
    *,
    loaded: LoadedTools | None = None,
    allowed: AllowedPredicate | None = None,
    registry: ToolRegistry | None = None,
    limit: int = SEARCH_LIMIT,
) -> dict:
    """Search the live registry and return the best tools' full schemas.

    ``select:a,b`` loads exact names; anything else is ranked with BM25 over
    name (x3), toolset, description and parameter names/descriptions, ties
    broken by name; an exact name match comes first. Only tools *allowed*
    accepts are returned. Returned names are added to *loaded*.

    Returns:
        ``{"query", "tools": [{name, toolset, risk, description,
        parameters}], "loaded": [...], "note"}`` (plus ``"not_found"`` for
        unknown ``select:`` names).
    """
    registry = registry or get_tool_registry()
    query = (query or "").strip()
    result: dict[str, Any] = {"query": query}
    picked: list[ToolSpec] = []
    if query.lower().startswith("select:"):
        missing = []
        for raw in query[len("select:") :].split(","):
            wanted = raw.strip()
            if not wanted:
                continue
            spec = registry.get_spec(wanted)
            if spec is None or not _usable(spec, allowed):
                missing.append(wanted)
            elif spec not in picked:
                picked.append(spec)
        if missing:
            result["not_found"] = missing
    elif query:
        exact = registry.get_spec(query)
        if exact is not None and _usable(exact, allowed):
            picked.append(exact)
        for _, name in _index_for(registry).rank(query):
            if len(picked) >= limit:
                break
            spec = registry.get_spec(name)
            if spec is not None and spec not in picked and _usable(spec, allowed):
                picked.append(spec)
    result["tools"] = [_search_entry(s) for s in picked]
    names = [s.name for s in picked]
    if loaded is not None and names:
        loaded.add(names)
    result["loaded"] = names
    if names:
        result["note"] = (
            "These tools are now loaded: call them directly by name or via "
            "call_tool(name, arguments)."
        )
    else:
        result["note"] = (
            "No matching tool. Try other words, a toolset name from the "
            "catalogue, or select:<exact_name>."
        )
    return result


# ---------------------------------------------------------------------------
# Registered meta tools
# ---------------------------------------------------------------------------


def _tool_search(query: str) -> dict:
    ctx = current_meta_context()
    if ctx is None:
        return search_tools(query)
    return search_tools(
        query, loaded=ctx.loaded, allowed=ctx.allowed, registry=ctx.registry
    )


def _call_tool(name: str, arguments: Any = None) -> dict:
    raise ToolError(
        "tool_failed",
        "call_tool must be resolved by the agent runtime (resolve_call), "
        "never dispatched directly",
    )


def _read_result(
    id: str,
    offset: int = 0,
    length: int | None = None,
    grep: str | None = None,
) -> dict:
    ctx = current_meta_context()
    store = ctx.store if ctx is not None and ctx.store is not None else None
    if store is None:
        store = get_result_store(session_root())
    cap = ctx.cap_tokens if ctx is not None else None
    return read_stored_result(
        store, id, offset=offset, length=length, grep=grep, cap_tokens=cap
    )


META_TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="tool_search",
        description=(
            "Find and load tools that are not in your tool list. Ranks every "
            "available tool by relevance to the query and returns the top 5 "
            "full schemas; 'select:name1,name2' loads exact names. Use it "
            "before calling any tool from the toolset catalogue. Returns "
            "{tools: [{name, toolset, risk, description, parameters}], loaded}; "
            "afterwards call a returned tool directly or via call_tool."
        ),
        parameters={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Words describing what you want to do (e.g. 'start "
                        "frida server'), a toolset name, or "
                        "'select:<name>[,<name>...]'."
                    ),
                }
            },
            "required": ["query"],
        },
        func=_tool_search,
        category="meta",
    ),
    ToolSpec(
        name="call_tool",
        description=(
            "Call a tool found with tool_search (including external mcp:* "
            "tools) by name. The called tool's own approval rules apply. "
            "Returns that tool's result."
        ),
        parameters={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Exact name of the tool to call.",
                },
                "arguments": {
                    "type": "object",
                    "description": (
                        "The tool's arguments as a JSON object matching its "
                        "parameter schema; {} when it takes none."
                    ),
                },
            },
            "required": ["name"],
        },
        func=_call_tool,
        category="meta",
    ),
    ToolSpec(
        name="read_result",
        description=(
            "Read a stored tool result by its id (e.g. 'R17'). Large results "
            "only show a preview; use this to page through the full text "
            "(offset/length, in characters) or to grep matching lines (regex, "
            "case-insensitive). Returns content and next_offset, or matches "
            "with their locations; output is capped."
        ),
        parameters={
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                    "description": "Result id, e.g. 'R17'.",
                },
                "offset": {
                    "type": "integer",
                    "description": "Character offset to start at (default 0).",
                },
                "length": {
                    "type": "integer",
                    "description": "Characters to return (default and max: cap).",
                },
                "grep": {
                    "type": "string",
                    "description": (
                        "Regex; return only matching lines instead of a slice."
                    ),
                },
            },
            "required": ["id"],
        },
        func=_read_result,
        category="meta",
    ),
)


def register_meta_tools(registry: ToolRegistry | None = None) -> None:
    """Register the three meta tools (idempotent)."""
    registry = registry or get_tool_registry()
    for spec in META_TOOL_SPECS:
        if registry.get_spec(spec.name) is not spec:
            registry.register(spec)


register_meta_tools()

__all__ = [
    "SEARCH_LIMIT",
    "LoadedTools",
    "MetaContext",
    "ResolvedCall",
    "current_meta_context",
    "normalize_arguments",
    "register_meta_tools",
    "resolve_call",
    "search_tools",
    "tokenize",
    "use_meta_context",
]
