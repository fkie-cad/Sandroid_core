"""Identity profile files: YAML schema 2, overlays and built-in profiles.

A library profile is one human-editable YAML file (``<id>.yaml``). Saving
never rewrites it from scratch: the loaded ruamel document is kept with the
profile and only the nodes that changed are patched, so the user's comments
and key order survive every save.

``extends`` overlays a profile on another one: ``builtin:<id>`` (shipped in
``sandroid/identity_profiles/``) or a library profile id. Parents merge key by
key (maps recursively, lists replace); a profile file holds only its own keys.
The token, seed, revision and creation time belong to the leaf profile only.

This module is the file format only (no templates, no device);
:mod:`sandroid.services.identity` builds :class:`Profile` objects from it.
"""

from __future__ import annotations

import copy
import functools
import io
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
        ProfileError: Invalid YAML or not a mapping.
    """
    try:
        doc = _yaml().load(text)
    except YAMLError as exc:
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
    """
    if isinstance(node, dict):
        return {str(k): plain(v) for k, v in node.items()}
    if isinstance(node, (list, tuple)):
        return [plain(v) for v in node]
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
        if _flow(path):
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
    (lists too) replaces. A value (``values.<id>``) that sets one of
    :data:`VALUE_SOURCES` drops the parent's source.
    """
    if not (isinstance(base, dict) and isinstance(child, dict)):
        return copy.deepcopy(child)
    out = copy.deepcopy(base)
    if (
        len(path) == 2
        and path[0] == "values"
        and any(child.get(s) is not None for s in VALUE_SOURCES)
    ):
        for source in VALUE_SOURCES:
            out.pop(source, None)
    for key, value in child.items():
        out[key] = merge(out.get(key, _MISSING), value, (*path, str(key)))
    return out


def parents_of(
    own: dict[str, Any],
    lookup: Callable[[str], dict[str, Any]],
    self_ref: str = "",
) -> dict[str, Any]:
    """The merged parents of a profile (its ``extends`` chain), without the
    profile itself and without the parents' :data:`LEAF_ONLY` keys.

    Args:
        own: The profile's own keys (plain).
        lookup: Returns a parent's own keys for an ``extends`` reference
            (raises :class:`ProfileError` when there is none).
        self_ref: The profile's own reference (its library id), so a chain
            that comes back to it is a cycle.

    Raises:
        ProfileError: A cycle, a chain deeper than :data:`EXTENDS_DEPTH_MAX`,
            a malformed or unknown reference.
    """
    chain: list[dict[str, Any]] = []
    seen = [self_ref] if self_ref else []
    ref = own.get("extends")
    while ref:
        if not isinstance(ref, str):
            raise ProfileError("extends must be a profile reference (text)")
        if ref in seen:
            raise ProfileError(f"extends cycle: {' -> '.join([*seen, ref])}")
        if len(chain) >= EXTENDS_DEPTH_MAX:
            raise ProfileError(
                f"extends chain is deeper than {EXTENDS_DEPTH_MAX} profiles"
            )
        seen.append(ref)
        parent = lookup(ref)
        chain.append(parent)
        ref = parent.get("extends")
    base: dict[str, Any] = {}
    for parent in reversed(chain):
        base = merge(base, {k: v for k, v in parent.items() if k not in LEAF_ONLY})
    return base


def _is_value(path: tuple[str, ...]) -> bool:
    return len(path) == 2 and path[0] == "values"


def own_diff(new: Any, base: Any, path: tuple[str, ...] = ()) -> Any:
    """What a profile has to write itself so that it merges to ``new`` over
    ``base`` (``_MISSING`` when it inherits all of it).
    """
    if base is _MISSING:
        return new
    if isinstance(new, dict) and isinstance(base, dict):
        out = {}
        for key, value in new.items():
            diff = own_diff(value, base.get(key, _MISSING), (*path, str(key)))
            if diff is not _MISSING:
                out[key] = diff
        if _is_value(path):
            for key, default in VALUE_DEFAULTS.items():
                if key not in new and base.get(key, default) != default:
                    out[key] = default  # else the parent's would show through
        return out if out else _MISSING
    return _MISSING if new == base else new


def own_view(new: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
    """The keys a new profile file holds: its leaf keys and every key that
    differs from its parents.
    """
    out: dict[str, Any] = {}
    for key, value in new.items():
        if key in LEAF_ONLY:
            out[key] = value
            continue
        diff = own_diff(value, base.get(key, _MISSING), (str(key),))
        if diff is not _MISSING:
            out[key] = diff
    return out


def apply_changes(
    doc: dict[str, Any],
    old: dict[str, Any],
    new: dict[str, Any],
    base: Any,
    path: tuple[str, ...] = (),
) -> None:
    """Patch ``doc`` (the profile's own keys) with what changed from ``old``
    to ``new`` (both the resolved profile). Unchanged nodes, and with them
    their comments, stay as they are; an inherited key is written only when
    it now differs from the parents (``base``).
    """
    base = base if isinstance(base, dict) else {}
    for key, value in new.items():
        before = old.get(key, _MISSING)
        if before == value:
            continue
        sub = (*path, str(key))
        if key in doc:
            current = doc[key]
            if (
                isinstance(value, dict)
                and isinstance(current, dict)
                and isinstance(before, dict)
            ):
                apply_changes(current, before, value, base.get(key), sub)
            else:
                doc[key] = to_node(value, sub)
            continue
        diff = own_diff(value, base.get(key, _MISSING), sub)
        if diff is not _MISSING:
            doc[key] = to_node(diff, sub)
    for key in [k for k in old if k not in new]:
        removed = doc.pop(key, _MISSING)
        inherited = base.get(key, _MISSING)
        default = VALUE_DEFAULTS.get(key, _MISSING) if _is_value(path) else _MISSING
        if default is not _MISSING and inherited not in (_MISSING, default):
            doc[key] = default  # back to the default over a parent's value
        elif removed is _MISSING and isinstance(inherited, list):
            doc[key] = to_node([], (*path, str(key)))  # lists replace


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
    """``(severity, path, message)`` for the shape of a ``world:`` section.

    Only types, enums and known keys are checked (the world module owns the
    meaning); an unknown key is a warning.
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
]
