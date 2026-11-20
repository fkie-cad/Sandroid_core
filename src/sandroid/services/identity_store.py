"""Identity profile files: YAML schema 2, overlays and built-in profiles.

A library profile is one human-editable YAML file (``<id>.yaml``). Saving
never rewrites it from scratch: the loaded ruamel document is kept with the
profile and only the nodes that changed are patched, so the user's comments
and key order survive every save.

``extends`` overlays a profile on another one: ``builtin:<id>`` (shipped in
``sandroid/identity_profiles/``) or a library profile id. Parents merge key by
key (maps recursively, lists replace); a profile file holds only its own keys.
A ``null`` there means "removed here" (``[]`` for an emptied list). The token,
seed, revision and creation time belong to the leaf profile only.

This module is the file format only (no templates, no device);
:mod:`sandroid.services.identity` builds :class:`Profile` objects from it.
"""

from __future__ import annotations

import copy
import functools
import hashlib
import io
import json
import re
from datetime import date, datetime
from importlib import resources
from typing import TYPE_CHECKING, Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError
from ruamel.yaml.scalarbool import ScalarBoolean

if TYPE_CHECKING:
    from collections.abc import Callable

#: ``extends`` prefix of a profile shipped in the package.
BUILTIN_PREFIX = "builtin:"
#: Longest ``extends`` chain (parents above a profile).
EXTENDS_DEPTH_MAX = 8
#: Keys that belong to one profile file and are never inherited.
LEAF_ONLY = frozenset(
    {
        "format",
        "schema",
        "id",
        "extends",
        "extends_digest",
        "token",
        "seed",
        "revision",
        "created",
        "retired_tokens",
    }
)
#: The keys of a value of which exactly one is set: a child setting one of
#: them replaces the parent's source instead of merging next to it.
VALUE_SOURCES = ("value", "template", "derive")
#: What a value's optional keys mean when left out: a profile that drops one
#: its parent sets writes the default, or the parent's would show through.
VALUE_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "provider": "",
    "label": "",
    "scope": "signer",
}
_BUILTIN_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")

#: Paths whose maps and lists are written in flow style (one line), ``*``
#: matching any key or index.
_FLOW_PATHS = (
    ("owner",),
    ("retired_tokens",),
    ("values", "*"),
    ("lists", "*", "*"),
    ("world", "mix"),
    ("world", "counts"),
    ("world", "device"),
)


class ProfileError(ValueError):
    """An identity profile file is unreadable or not a valid profile."""


_MISSING = object()
#: A profile file larger than this is refused (bytes of text).
MAX_FILE_CHARS = 1_000_000
#: At most this many nodes after alias expansion (an alias bomb is refused).
MAX_NODES = 200_000

# ---------------------------------------------------------------------------
# YAML text
# ---------------------------------------------------------------------------


def _yaml() -> YAML:
    """A round-trip YAML instance (one per call: they are not thread-safe)."""
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    yaml.width = 4096
    yaml.indent(mapping=2, sequence=4, offset=2)
    return yaml


def load_yaml(text: str) -> CommentedMap:
    """Parse profile YAML into a round-trip document.

    Raises:
        ProfileError: Too large, invalid YAML or not a mapping.
    """
    if len(text) > MAX_FILE_CHARS:
        raise ProfileError(f"profile file is larger than {MAX_FILE_CHARS} characters")
    try:
        doc = _yaml().load(text)
    except (YAMLError, RecursionError) as exc:
        raise ProfileError(f"invalid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise ProfileError("a profile file must be a YAML mapping")
    return doc


def dump_yaml(doc: Any) -> str:
    """The YAML text of a document (comments and order as they are)."""
    buf = io.StringIO()
    _yaml().dump(doc, buf)
    return buf.getvalue()


def plain(node: Any) -> Any:
    """``node`` with every ruamel type replaced by its plain Python type.

    Timestamps become :class:`datetime` (``str()`` must match a TOML-loaded
    one: fingerprints serialise list dates with it).

    Raises:
        ProfileError: More than :data:`MAX_NODES` nodes once aliases are
            expanded (an alias bomb), or an alias that contains itself.
    """
    return _plain(node, [MAX_NODES], set())


def _plain(node: Any, budget: list[int], stack: set[int]) -> Any:
    budget[0] -= 1
    if budget[0] < 0:
        raise ProfileError(f"profile has more than {MAX_NODES} nodes (aliases?)")
    if isinstance(node, (dict, list, tuple)):
        if id(node) in stack:
            raise ProfileError("profile has an alias that contains itself")
        stack.add(id(node))
        try:
            if isinstance(node, dict):
                return {str(k): _plain(v, budget, stack) for k, v in node.items()}
            return [_plain(v, budget, stack) for v in node]
        finally:
            stack.discard(id(node))
    if isinstance(node, (bool, ScalarBoolean)):
        return bool(node)
    if isinstance(node, int):
        return int(node)
    if isinstance(node, float):
        return float(node)
    if isinstance(node, str):
        return str(node)
    if isinstance(node, datetime):
        return datetime(
            node.year,
            node.month,
            node.day,
            node.hour,
            node.minute,
            node.second,
            node.microsecond,
            tzinfo=node.tzinfo,
        )
    if isinstance(node, date):
        return date(node.year, node.month, node.day)
    return node


def _flow(path: tuple[Any, ...]) -> bool:
    return any(
        len(p) == len(path) and all(a in ("*", b) for a, b in zip(p, path, strict=True))
        for p in _FLOW_PATHS
    )


def to_node(value: Any, path: tuple[Any, ...] = ()) -> Any:
    """A plain value as a ruamel node (small maps in flow style by ``path``)."""
    if isinstance(value, dict):
        node = CommentedMap()
        for k, v in value.items():
            node[k] = to_node(v, (*path, k))
        if _flow(path):
            node.fa.set_flow_style()
        return node
    if isinstance(value, (list, tuple)):
        seq = CommentedSeq(to_node(v, (*path, i)) for i, v in enumerate(value))
        if _flow(path) or not value:
            seq.fa.set_flow_style()
        return seq
    if isinstance(value, datetime):
        return timestamp_node(value.isoformat()) or value
    return value


def timestamp_node(raw: str) -> Any:
    """A YAML timestamp that is written back exactly as ``raw`` (None when
    ``raw`` is not one YAML reads as a timestamp and writes back verbatim).
    """
    try:
        value = _yaml().load(f"v: {raw}\n")["v"]
    except (YAMLError, TypeError, KeyError):
        return None
    if not isinstance(value, (datetime, date)):
        return None
    probe = CommentedMap()
    probe["v"] = value
    return value if dump_yaml(probe) == f"v: {raw}\n" else None


# ---------------------------------------------------------------------------
# overlays
# ---------------------------------------------------------------------------


def merge(base: Any, child: Any, path: tuple[str, ...] = ()) -> Any:
    """``child`` over ``base``: maps merge key by key, everything else
    (lists too) replaces. A ``null`` in ``child`` removes the key ("removed
    here"). A value (``values.<id>``) that sets one of :data:`VALUE_SOURCES`
    drops the parent's source.
    """
    if not isinstance(child, dict):
        return copy.deepcopy(child)
    out = copy.deepcopy(base) if isinstance(base, dict) else {}
    if _is_value(path) and any(child.get(s) is not None for s in VALUE_SOURCES):
        for source in VALUE_SOURCES:
            out.pop(source, None)
    for key, value in child.items():
        if value is None:
            out.pop(key, None)
            continue
        out[key] = merge(out.get(key, _MISSING), value, (*path, str(key)))
    return out


def parents_of(
    own: dict[str, Any],
    lookup: Callable[[str], dict[str, Any]],
    self_ref: str = "",
    chain: list[str] | None = None,
) -> dict[str, Any]:
    """The merged parents of a profile (its ``extends`` chain), without the
    profile itself and without the parents' :data:`LEAF_ONLY` keys.

    Args:
        own: The profile's own keys (plain).
        lookup: Returns a parent's own keys for an ``extends`` reference
            (raises :class:`ProfileError` when there is none).
        self_ref: The profile's own reference (its library id), so a chain
            that comes back to it is a loop.
        chain: When given, the references of the chain are appended to it
            (nearest parent first).

    Raises:
        ProfileError: A loop, a chain deeper than :data:`EXTENDS_DEPTH_MAX`,
            a malformed or unknown reference.
    """
    parents: list[dict[str, Any]] = []
    seen = [self_ref] if self_ref else []
    ref = own.get("extends")
    while ref:
        if not isinstance(ref, str):
            raise ProfileError("extends must be a profile reference (text)")
        if ref in seen:
            loop = " extends ".join([*seen, ref])
            raise ProfileError(f"extends goes round in a loop: {loop}")
        if len(parents) >= EXTENDS_DEPTH_MAX:
            raise ProfileError(
                f"extends chain is deeper than {EXTENDS_DEPTH_MAX} profiles"
            )
        seen.append(ref)
        if chain is not None:
            chain.append(ref)
        parent = lookup(ref)
        parents.append(parent)
        ref = parent.get("extends")
    base: dict[str, Any] = {}
    for parent in reversed(parents):
        base = merge(base, {k: v for k, v in parent.items() if k not in LEAF_ONLY})
    return base


def base_digest(base: dict[str, Any]) -> str:
    """A short digest of the merged parents (``extends_digest``)."""
    blob = json.dumps(base, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _is_value(path: tuple[Any, ...]) -> bool:
    return len(path) == 2 and path[0] == "values"


def _tombstone(path: tuple[Any, ...], key: str, inherited: Any, sibling: Any) -> Any:
    """What a profile writes for ``key`` that it no longer has but its parents
    do (``_MISSING``: nothing to write). ``sibling`` is the profile's map
    that held ``key``.
    """
    if _is_value(path):
        if key in VALUE_SOURCES and any(s in sibling for s in VALUE_SOURCES):
            return _MISSING  # the new source replaces the parent's anyway
        if key in VALUE_DEFAULTS:
            default = VALUE_DEFAULTS[key]
            return _MISSING if inherited == default else default
    if path == ("lists",):
        return []
    if path == () and key == "lists" and isinstance(inherited, dict):
        return {name: [] for name in inherited}
    return None


def own_diff(new: Any, base: Any, path: tuple[Any, ...] = ()) -> Any:
    """What a profile has to write itself so that it merges to ``new`` over
    ``base`` (``_MISSING`` when it inherits all of it). A key of ``base``
    that ``new`` has not is written as a removal (``null``, ``[]`` for a
    list, the default for a value's optional key).
    """
    if base is _MISSING:
        return new
    if isinstance(new, dict) and isinstance(base, dict):
        out = {}
        for key, value in new.items():
            diff = own_diff(value, base.get(key, _MISSING), (*path, str(key)))
            if diff is not _MISSING:
                out[key] = diff
        for key, inherited in base.items():
            if key not in new:
                mark = _tombstone(path, key, inherited, new)
                if mark is not _MISSING:
                    out[key] = mark
        return out if out else _MISSING
    return _MISSING if new == base else new


def own_view(new: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
    """The keys a new profile file holds: its leaf keys and every key that
    differs from its parents (removals as ``null`` or ``[]``).
    """
    out: dict[str, Any] = {}
    for key, value in new.items():
        if key in LEAF_ONLY:
            out[key] = value
            continue
        diff = own_diff(value, base.get(key, _MISSING), (str(key),))
        if diff is not _MISSING:
            out[key] = diff
    for key, inherited in base.items():
        if key not in new and key not in LEAF_ONLY:
            mark = _tombstone((), key, inherited, new)
            if mark is not _MISSING:
                out[key] = mark
    return out


def shared_nodes(doc: Any) -> set[int]:
    """Ids of the maps and lists that occur more than once in ``doc`` (YAML
    aliases): a save copies them before it changes one.
    """
    seen: set[int] = set()
    shared: set[int] = set()
    todo = [doc]
    while todo:
        node = todo.pop()
        if not isinstance(node, (dict, list)):
            continue
        if id(node) in seen:
            shared.add(id(node))
            continue
        seen.add(id(node))
        todo.extend(node.values() if isinstance(node, dict) else node)
    return shared


def _own_node(parent: Any, key: Any, shared: set[int]) -> Any:
    """``parent[key]``, first replaced by an unaliased copy when it is shared
    (so the alias keeps its old content).
    """
    node = parent[key]
    if isinstance(node, (dict, list)) and id(node) in shared:
        node = copy.deepcopy(node)
        for sub in [node, *_containers(node)]:
            anchor = getattr(sub, "anchor", None)
            if anchor is not None:
                anchor.value = None
        parent[key] = node
    return node


def _containers(node: Any) -> list[Any]:
    out = []
    todo = list(node.values() if isinstance(node, dict) else node)
    while todo:
        sub = todo.pop()
        if isinstance(sub, (dict, list)):
            out.append(sub)
            todo.extend(sub.values() if isinstance(sub, dict) else sub)
    return out


def _put(doc: Any, key: str, node: Any, order: Any) -> None:
    """Set ``doc[key]``; a new key goes right after the nearest key that
    comes before it in ``order`` (not at the end).
    """
    if key in doc or not isinstance(doc, CommentedMap):
        doc[key] = node
        return
    keys = list(order)
    present = list(doc)
    if key not in keys:
        doc[key] = node
        return
    earlier = keys[: keys.index(key)]
    pos = next((present.index(k) + 1 for k in reversed(earlier) if k in doc), 0)
    doc.insert(pos, key, node)


def apply_changes(
    doc: dict[str, Any],
    old: dict[str, Any],
    new: dict[str, Any],
    base: Any,
    path: tuple[Any, ...] = (),
    shared: set[int] | None = None,
) -> None:
    """Patch ``doc`` (the profile's own keys) with what changed from ``old``
    to ``new`` (both the resolved profile).

    Unchanged nodes, and with them their comments, stay as they are; a list
    is edited item by item and field by field; an inherited key is written
    only when it now differs from the parents (``base``); a key that is
    gone but inherited is written as a removal (:func:`own_diff`). Aliased
    nodes are copied before they change.
    """
    base = base if isinstance(base, dict) else {}
    shared = shared_nodes(doc) if shared is None else shared
    for key, value in new.items():
        before = old.get(key, _MISSING)
        if before == value:
            continue
        sub = (*path, str(key))
        current = doc.get(key, _MISSING)
        if current is not _MISSING and current is not None:
            if isinstance(value, dict) and isinstance(current, dict):
                current = _own_node(doc, key, shared)
                apply_changes(
                    current,
                    before if isinstance(before, dict) else {},
                    value,
                    base.get(key),
                    sub,
                    shared,
                )
            elif (
                isinstance(value, list)
                and isinstance(current, list)
                and isinstance(before, list)
            ):
                _patch_list(_own_node(doc, key, shared), before, value, sub, shared)
            else:
                doc[key] = to_node(value, sub)
            continue
        diff = own_diff(value, base.get(key, _MISSING), sub)
        if diff is _MISSING:
            doc.pop(key, None)  # a removal that is undone: inherited again
        else:
            _put(doc, key, to_node(diff, sub), new)
    for key in [k for k in old if k not in new]:
        _remove(doc, key, old, base.get(key, _MISSING), path, new, shared)


def _remove(
    doc: Any,
    key: str,
    old: dict[str, Any],
    inherited: Any,
    path: tuple[Any, ...],
    new: dict[str, Any],
    shared: set[int],
) -> None:
    """``key`` (in ``old``, not in ``new``) is gone from the profile: drop it,
    or write a removal when a parent has it (an emptied list is always
    written as ``[]``).
    """
    sub = (*path, str(key))
    before = old[key]
    if path == () and key == "lists" and isinstance(before, dict):
        if not isinstance(doc.get(key), dict):
            _put(doc, key, CommentedMap(), old)
        node = _own_node(doc, key, shared)
        inner = inherited if isinstance(inherited, dict) else {}
        for name in before:
            _remove(node, name, before, inner.get(name, _MISSING), sub, {}, shared)
        return
    if path == ("lists",):
        if isinstance(doc.get(key), list):
            seq = _own_node(doc, key, shared)
            while seq:
                del seq[-1]
        else:
            _put(doc, key, to_node([], sub), old)
        return
    mark = _MISSING if inherited is _MISSING else _tombstone(path, key, inherited, new)
    if mark is _MISSING:
        doc.pop(key, None)
    else:
        _put(doc, key, to_node(mark, sub), old)


def _patch_list(
    seq: list[Any],
    before: list[Any],
    after: list[Any],
    path: tuple[Any, ...],
    shared: set[int],
) -> None:
    """Edit ``seq`` in place from ``before`` to ``after``: changed items
    field by field, new items appended, surplus items removed.
    """
    if not seq and _flow(path):
        seq.fa.set_flow_style()  # it was ``[]``: stay on one line
    for i, item in enumerate(after):
        sub = (*path, i)
        if i >= len(seq):
            node = to_node(item, sub)
            first = seq[0] if seq else None
            if isinstance(node, CommentedMap) and isinstance(first, CommentedMap):
                node.fa._flow_style = first.fa.flow_style()  # like its siblings
            seq.append(node)
            continue
        old_item = before[i] if i < len(before) else _MISSING
        if old_item == item:
            continue
        if isinstance(item, dict) and isinstance(seq[i], dict):
            node = _own_node(seq, i, shared)
            prior = old_item if isinstance(old_item, dict) else {}
            apply_changes(node, prior, item, {}, sub, shared)
        else:
            seq[i] = to_node(item, sub)
    while len(seq) > len(after):
        del seq[-1]


# ---------------------------------------------------------------------------
# built-in profiles
# ---------------------------------------------------------------------------


def _builtin_dir() -> Any:
    return resources.files("sandroid").joinpath("identity_profiles")


def builtin_ids() -> list[str]:
    """Ids of the profiles shipped in the package (``builtin:<id>``)."""
    try:
        entries = list(_builtin_dir().iterdir())
    except (FileNotFoundError, NotADirectoryError):
        return []
    return sorted(
        e.name[: -len(".yaml")]
        for e in entries
        if e.name.endswith(".yaml") and _BUILTIN_ID_RE.fullmatch(e.name[:-5])
    )


@functools.lru_cache(maxsize=64)
def _builtin_raw(builtin_id: str) -> dict[str, Any]:
    if not _BUILTIN_ID_RE.fullmatch(builtin_id):
        raise ProfileError(f"invalid built-in profile id {builtin_id!r}")
    try:
        text = _builtin_dir().joinpath(f"{builtin_id}.yaml").read_text("utf-8")
    except (FileNotFoundError, OSError) as exc:
        raise ProfileError(f"no built-in profile {builtin_id!r}") from exc
    return plain(load_yaml(text))


def load_builtin(builtin_id: str) -> dict[str, Any]:
    """The own keys of a built-in profile (a copy).

    Raises:
        ProfileError: No such built-in profile.
    """
    return copy.deepcopy(_builtin_raw(builtin_id))


# ---------------------------------------------------------------------------
# the world section (passed through to sandroid.world)
# ---------------------------------------------------------------------------

WORLD_KEYS = (
    "seed",
    "size",
    "country",
    "mix",
    "numbers",
    "history",
    "counts",
    "places",
    "device",
    "emails",
)
WORLD_SIZES = ("small", "medium", "large")
WORLD_NUMBERS = ("fiction", "unallocated", "realistic")
WORLD_EMAILS = ("reserved", "owned", "realistic")
WORLD_COUNTS = ("contacts", "sms", "calls", "events", "photos", "files", "notes")
WORLD_DEVICE_KEYS = ("make", "model", "codename", "min_sdk", "max_sdk")
WORLD_SEED_RE = re.compile(r"hex:[0-9a-fA-F]{32,}")
_HISTORY_RE = re.compile(r"[1-9][0-9]*(d|w|mo|y)")


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def world_seed_pending(world: dict[str, Any]) -> bool:
    """True when ``world`` still needs its seed generated (``auto``)."""
    return bool(world) and world.get("seed", "auto") == "auto"


def world_issues(world: Any) -> list[tuple[str, str, str]]:
    """``(severity, path, message)`` for a ``world:`` section (none when the
    profile has no world).

    The world module's own validator (``sandroid.world.WorldSpec``) is the
    single source of truth; its first problem is reported. Only when that
    module cannot be imported, :func:`world_shape_issues` checks the shape.
    The caller decides what a finding blocks (identity apply: nothing).
    """
    if isinstance(world, dict) and not world:
        return []
    try:
        from sandroid.world import WorldSpec
    except ImportError:
        return world_shape_issues(world)
    try:
        WorldSpec.from_dict(world)
    except (ValueError, TypeError) as exc:
        return [("error", "world", str(exc))]
    return []


def world_shape_issues(world: Any) -> list[tuple[str, str, str]]:
    """``(severity, path, message)`` for the shape of a ``world:`` section,
    the fallback of :func:`world_issues`.

    Only types, enums and known keys are checked; an unknown key is a
    warning.
    """
    out: list[tuple[str, str, str]] = []

    def add(sev: str, path: str, msg: str) -> None:
        out.append((sev, f"world.{path}" if path else "world", msg))

    if not isinstance(world, dict):
        add("error", "", "world must be a mapping")
        return out
    for key in world:
        if key not in WORLD_KEYS:
            add("warning", str(key), f"unknown world key {key!r} (ignored here)")
    seed = world.get("seed", "auto")
    if not (
        seed == "auto" or (isinstance(seed, str) and WORLD_SEED_RE.fullmatch(seed))
    ):
        add("error", "seed", "seed must be 'auto' or 'hex:' and 32 or more hex digits")
    for key, allowed in (
        ("size", WORLD_SIZES),
        ("numbers", WORLD_NUMBERS),
        ("emails", WORLD_EMAILS),
    ):
        if key in world and world[key] not in allowed:
            add("error", key, f"{key} must be one of {', '.join(allowed)}")
    if "country" in world and not (
        isinstance(world["country"], str) and world["country"].strip()
    ):
        add("error", "country", "country must be a country pack id (text)")
    mix = world.get("mix")
    if mix is not None:
        if not isinstance(mix, dict):
            add("error", "mix", "mix must map country pack ids to shares")
        else:
            for k, v in mix.items():
                if not _number(v) or v < 0:
                    add("error", f"mix.{k}", "a share must be a number, 0 or more")
    if "history" in world and not (
        isinstance(world["history"], str) and _HISTORY_RE.fullmatch(world["history"])
    ):
        add("error", "history", "history must be like 18mo, 2y, 6w or 30d")
    counts = world.get("counts")
    if counts is not None:
        if not isinstance(counts, dict):
            add("error", "counts", "counts must be a mapping")
        else:
            for k, v in counts.items():
                if k not in WORLD_COUNTS:
                    add("warning", f"counts.{k}", f"unknown count {k!r}")
                if not _int(v) or v < 0:
                    add("error", f"counts.{k}", "a count must be a whole number")
    if "places" in world and not isinstance(world["places"], (dict, type(None))):
        add("error", "places", "places must be a mapping")
    device = world.get("device")
    if device is not None:
        out.extend(_device_issues(device))
    return out


def _device_issues(device: Any) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    if not isinstance(device, dict):
        return [("error", "world.device", "device must be {make, model}")]
    for key in device:
        if key not in WORLD_DEVICE_KEYS:
            out.append(("warning", f"world.device.{key}", f"unknown key {key!r}"))
    for key in ("make", "model"):
        value = device.get(key)
        if not (isinstance(value, str) and value.strip()):
            out.append(("error", f"world.device.{key}", f"{key} must be text"))
    if "codename" in device and not isinstance(device["codename"], str):
        out.append(("error", "world.device.codename", "codename must be text"))
    for key in ("min_sdk", "max_sdk"):
        if key in device and not (_int(device[key]) and device[key] > 0):
            out.append(("error", f"world.device.{key}", f"{key} must be an API level"))
    lo, hi = device.get("min_sdk"), device.get("max_sdk")
    if _int(lo) and _int(hi) and lo > hi:
        out.append(("error", "world.device", "min_sdk is above max_sdk"))
    make = device.get("make")
    if isinstance(make, str) and make.strip() and make.strip().lower() != "google":
        out.append(
            (
                "warning",
                "world.device.make",
                "apps will see a Google Pixel: the Build spoof knows Pixels only",
            )
        )
    return out


__all__ = [
    "BUILTIN_PREFIX",
    "EXTENDS_DEPTH_MAX",
    "LEAF_ONLY",
    "ProfileError",
    "apply_changes",
    "base_digest",
    "builtin_ids",
    "dump_yaml",
    "load_builtin",
    "load_yaml",
    "merge",
    "own_view",
    "parents_of",
    "plain",
    "timestamp_node",
    "to_node",
    "world_issues",
    "world_seed_pending",
    "world_shape_issues",
]
