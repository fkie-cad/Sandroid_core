"""Who may overwrite or delete which emulator snapshot.

Snapshots are shared by every part of Sandroid (and every session using
an AVD): Rewind's start points, persona snapshots, the analysis
snapshots, the user's golden images. This module decides, for one save
or delete, whether the caller may do it. It is enforced at the one place
every snapshot save/delete goes through
(:meth:`sandroid.services.emulator_service.EmulatorService.create_snapshot`
/ ``delete_snapshot``). Callers say who they are with ``actor=`` or, through
layers that don't pass it on (Toolbox, test doubles), with
``with acting_as("rewind"): ...``; without either the actor is the user.
Callers ask ``EmulatorService.snapshot_refusal`` first to explain a refusal.

Rules:

* **Loads are never restricted.**
* **Pinned names** (per AVD, default :data:`DEFAULT_PINS`) can neither be
  overwritten (saved onto while they exist) nor deleted, by anyone. Only
  the user unpins them, after a confirm in the Devices screen
  (:func:`unpin`); the AI never can.
* **Owned names** (a registered :class:`Namespace`, e.g. Rewind's start
  points) are saved and deleted by their owner only. The user may still
  delete one after a confirm that names the owner (``confirmed=True``);
  the AI never can.
* Everything else: anyone (as before).

What happens outside Sandroid (``qemu-img snapshot -d``, removing the
directory while the AVD is stopped) cannot be prevented; :func:`vanished_pins`
reports a pinned snapshot that disappeared, once.

:func:`snapshot_warnings` reads each snapshot's ``snapshot.pb`` (read only,
never rewritten) and says why one may not load: a recorded
``failed_to_load_reason_code`` or another emulator build than the installed
one (the Devices screen shows it).
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from logging import getLogger
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator
    from pathlib import Path

logger = getLogger(__name__)

#: Pinned on every AVD unless the user unpinned them there.
DEFAULT_PINS: tuple[str, ...] = ("clean_8g", "default_boot")

#: Who saves or deletes: the user (TUI/CLI), the AI assistant, or the owner
#: of a namespace (``rewind``, ``persona``, ``analysis`` ...).
USER = "user"
AI = "ai"

SAVE = "save"
DELETE = "delete"
LOAD = "load"


@dataclass(frozen=True)
class Namespace:
    """Snapshot names one part of Sandroid owns.

    Attributes:
        owner: The actor that may save and delete them.
        label: What a snapshot of it is, for messages ("Rewind start point").
        match: True for a name of this namespace.
        delete_warning: Said in the user's delete confirm (what is lost).
    """

    owner: str
    label: str
    match: Callable[[str], bool]
    delete_warning: str = ""


@dataclass(frozen=True)
class Refusal:
    """Why a save or delete is not allowed.

    Attributes:
        reason: One sentence for the user / the AI.
        pinned: The name is pinned (unpin in the Devices screen first).
        owner: The owning actor of the name, if any.
        confirmable: The user may do it after a confirm (``confirmed=True``).
    """

    reason: str
    pinned: bool = False
    owner: str | None = None
    confirmable: bool = False


_ACTOR: ContextVar[tuple[str, bool]] = ContextVar(
    "snapshot_actor", default=(USER, False)
)


@contextmanager
def acting_as(actor: str, *, confirmed: bool = False) -> Iterator[None]:
    """Snapshot saves/deletes in this block are made by *actor*.

    Args:
        actor: :data:`USER`, :data:`AI` or a namespace owner.
        confirmed: The user confirmed deleting an owned name.
    """
    token = _ACTOR.set((actor, confirmed))
    try:
        yield
    finally:
        _ACTOR.reset(token)


def current_actor() -> tuple[str, bool]:
    """``(actor, confirmed)`` of the current :func:`acting_as` block."""
    return _ACTOR.get()


def _rewind_match(name: str) -> bool:
    from sandroid.core.rewind import is_start_point_name

    return is_start_point_name(name)


_LOCK = threading.Lock()
_NAMESPACES: dict[str, Namespace] = {}


def register_namespace(namespace: Namespace) -> None:
    """Register (or replace) the namespace of ``namespace.owner``."""
    if not callable(namespace.match):
        raise TypeError("Namespace.match must be callable")
    with _LOCK:
        _NAMESPACES[namespace.owner] = namespace


def unregister_namespace(owner: str) -> None:
    """Forget the namespace of *owner* (no-op when there is none)."""
    with _LOCK:
        _NAMESPACES.pop(owner, None)


def _register_builtins() -> None:
    register_namespace(
        Namespace(
            "rewind",
            "Rewind start point",
            _rewind_match,
            "Rewind can't go back to this start point afterwards.",
        )
    )
    register_namespace(
        Namespace(
            "persona",
            "persona snapshot",
            lambda n: n.startswith("sandroid_persona_"),
            "The persona is prepared again on its next start.",
        )
    )
    register_namespace(
        Namespace(
            "analysis",
            "analysis snapshot",
            lambda n: n.startswith("sandroid_malware"),
            "The analysis can't revert to it afterwards.",
        )
    )


_register_builtins()


def owner_of(name: str) -> Namespace | None:
    """The namespace *name* belongs to, or ``None``."""
    with _LOCK:
        spaces = list(_NAMESPACES.values())
    for space in spaces:
        try:
            if space.match(name):
                return space
        except Exception:
            logger.debug("snapshot namespace %s: match failed", space.owner)
    return None


# -- pins ---------------------------------------------------------------------


def _pins_of(entry: dict) -> frozenset[str]:
    pins = entry.get("pins")
    if not isinstance(pins, list):
        return frozenset(DEFAULT_PINS)
    return frozenset(p for p in pins if isinstance(p, str))


def pinned(avd: str | None) -> frozenset[str]:
    """Pinned snapshot names of AVD *avd*.

    Unknown AVD (``None``: its name could not be read): the default pins
    and every name pinned on any AVD -- never less protection.
    """
    from sandroid.core import emulator

    avds = emulator.load_launch_prefs()["avds"]
    if not avd:
        union = set(DEFAULT_PINS)
        for entry in avds.values():
            if isinstance(entry, dict):
                union |= _pins_of(entry)
        return frozenset(union)
    return _pins_of(avds.get(avd, {}))


def _set_pins(avd: str, pins: Iterable[str]) -> None:
    from sandroid.core import emulator

    with emulator._PREFS_LOCK:
        prefs = emulator.load_launch_prefs()
        entry = prefs["avds"].setdefault(avd, {})
        entry["pins"] = sorted(set(pins))
        emulator._save_prefs(prefs)


def pin(avd: str, name: str) -> None:
    """Pin snapshot *name* of AVD *avd*."""
    _set_pins(avd, pinned(avd) | {name})
    _remember_present(avd, [name])


def unpin(avd: str, name: str) -> None:
    """Unpin snapshot *name* of AVD *avd* (the user, after a confirm only)."""
    _set_pins(avd, pinned(avd) - {name})
    _forget_seen(avd, [name])


def is_pinned(avd: str | None, name: str) -> bool:
    """*name* is pinned on AVD *avd*."""
    return name in pinned(avd)


# -- the decision ---------------------------------------------------------------


def check(
    op: str,
    name: str,
    *,
    actor: str = USER,
    avd: str | None = None,
    exists: bool | None = None,
    confirmed: bool = False,
) -> Refusal | None:
    """``None`` when *actor* may *op* (``save``/``delete``/``load``) *name*.

    Args:
        op: ``save``, ``delete`` or ``load``.
        name: Snapshot name.
        actor: Who asks (:data:`USER`, :data:`AI` or a namespace owner).
        avd: The AVD (pins are per AVD; ``None``: the default pins).
        exists: Whether the snapshot exists now (a save onto an existing
            name overwrites it). ``None`` (unknown) counts as existing.
        confirmed: The user confirmed deleting an owned name (ignored for
            any other actor).
    """
    if op == LOAD:
        return None
    if op not in (SAVE, DELETE):
        raise ValueError(f"unknown snapshot operation {op!r}")
    overwrite = op == DELETE or exists is not False
    if overwrite and is_pinned(avd, name):
        verb = "deleted" if op == DELETE else "overwritten"
        return Refusal(
            f"Snapshot '{name}' is pinned and can't be {verb}; unpin it in the "
            "Devices screen (D) first.",
            pinned=True,
        )
    space = owner_of(name)
    if space is None or space.owner == actor:
        return None
    if op == DELETE and actor == USER:
        if confirmed:
            return None
        warning = f" {space.delete_warning}" if space.delete_warning else ""
        return Refusal(
            f"Snapshot '{name}' is a {space.label}.{warning}",
            owner=space.owner,
            confirmable=True,
        )
    verb = "deleted" if op == DELETE else "saved"
    return Refusal(
        f"Snapshot '{name}' is a {space.label}; only {space.owner} may "
        f"{'delete' if op == DELETE else 'save'} it, so it can't be {verb} here.",
        owner=space.owner,
    )


def snapshot_exists(avd: str | None, name: str) -> bool | None:
    """Whether AVD *avd* has a loadable snapshot *name* (``None``: unknown).

    A stub (``snapshot.pb`` only, left by ``-snapshot <unknown name>``)
    holds nothing to protect: it does not count (see
    :func:`snapshot_complete`).
    """
    if not avd:
        return None
    from sandroid.core import emulator

    directory = emulator.avd_dir(avd)
    if directory is None:
        return None
    return snapshot_complete(avd, name)


def snapshot_complete(avd: str, name: str) -> bool:
    """Snapshot *name* of *avd* can be loaded (has its RAM image).

    ``-snapshot <unknown name>`` leaves a stub directory (``snapshot.pb``
    only); a stub is listed but not loadable.
    """
    from sandroid.core import emulator

    directory = emulator.avd_dir(avd)
    if directory is None:
        return False
    path = directory / "snapshots" / name
    return (path / "ram.bin").is_file() or (path / "ram.img").is_file()


# -- pinned snapshots that vanished behind our back -------------------------------


def _seen(entry: dict) -> list[str]:
    seen = entry.get("pins_seen")
    return [s for s in seen if isinstance(s, str)] if isinstance(seen, list) else []


def _remember_present(avd: str, names: Iterable[str]) -> None:
    from sandroid.core import emulator

    names = set(names)
    if not names:
        return
    with emulator._PREFS_LOCK:
        prefs = emulator.load_launch_prefs()
        entry = prefs["avds"].setdefault(avd, {})
        seen = set(_seen(entry))
        if names <= seen:
            return
        entry["pins_seen"] = sorted(seen | names)
        emulator._save_prefs(prefs)


def _forget_seen(avd: str, names: Iterable[str]) -> None:
    from sandroid.core import emulator

    names = set(names)
    with emulator._PREFS_LOCK:
        prefs = emulator.load_launch_prefs()
        entry = prefs["avds"].get(avd)
        if not entry or not names & set(_seen(entry)):
            return
        entry["pins_seen"] = sorted(set(_seen(entry)) - names)
        emulator._save_prefs(prefs)


def vanished_pins(avd: str, present: Iterable[str]) -> list[str]:
    """Pinned snapshots of *avd* seen before and now gone (reported once).

    Called with the snapshot names on disk (e.g. on each Devices refresh):
    remembers the pinned ones that exist, and returns the pinned ones that
    existed before and are missing now, then forgets them -- a deletion
    outside Sandroid (``qemu-img snapshot -d`` while stopped, a removed
    directory, a factory reset) is reported loudly once, never recreated.
    """
    from sandroid.core import emulator

    present = set(present)
    pins = pinned(avd)
    entry = emulator.load_launch_prefs()["avds"].get(avd, {})
    gone = sorted(n for n in _seen(entry) if n in pins and n not in present)
    if gone:
        _forget_seen(avd, gone)
    _remember_present(avd, pins & present)
    return gone


def snapshot_dir(avd: str, name: str) -> Path | None:
    """The directory of snapshot *name* of *avd* (``None``: AVD unknown)."""
    from sandroid.core import emulator

    directory = emulator.avd_dir(avd)
    return None if directory is None else directory / "snapshots" / name


# -- snapshot.pb (read only) --------------------------------------------------

#: ``failed_to_load_reason_code`` values below this make the emulator refuse
#: the snapshot for good (``android::snapshot::FailureReason``); higher ones
#: record a failed load (a config mismatch, an error while loading).
UNRECOVERABLE_LIMIT = 10000

#: ``FailureReason`` codes in plain words.
FAILURE_WORDS = {
    1: "corrupted data",
    2: "snapshot.pb missing",
    3: "snapshot.pb unreadable",
    4: "saved by an incompatible emulator version",
    5: "RAM image missing",
    6: "textures file missing",
    7: "snapshots not supported",
    8: "load cancelled",
    9: "tombstone",
    10001: "host hypervisor changed",
    10002: "host GPU changed",
    10003: "renderer changed",
    10004: "emulator features changed",
    10005: "AVD configuration changed",
    10006: "system image changed",
    20001: "internal error",
    20002: "emulation engine failed",
    20003: "RAM load failed",
    20004: "textures load failed",
    20005: "adb offline",
    20006: "out of disk space",
}

#: Bytes of a ``snapshot.pb`` read at most (they are about 1 KB).
_PB_MAX = 1 << 20


@dataclass(frozen=True)
class SnapshotPb:
    """The top-level facts of a snapshot's ``snapshot.pb`` (emulator proto).

    Attributes:
        version: Snapshot format version (field 1).
        created: Creation time, Unix seconds (field 2; 0 unknown).
        failed_reason: ``failed_to_load_reason_code`` (field 7; 0 none).
        invalid_loads: Field 10.
        successful_loads: Field 11.
        emulator_build: Build id of the emulator that last wrote it (field 18).
        system_image_build: The system image's build id (field 19).
    """

    version: int = 0
    created: int = 0
    failed_reason: int = 0
    invalid_loads: int = 0
    successful_loads: int = 0
    emulator_build: str = ""
    system_image_build: str = ""


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if pos >= len(data) or shift > 63:
            raise ValueError("truncated varint")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def parse_snapshot_pb(data: bytes) -> SnapshotPb:
    """Decode the top-level scalar fields of ``snapshot.pb`` bytes (pure).

    Only the wire format is used (no generated code); nested messages and
    unknown fields are skipped. Raises :class:`ValueError` on bytes that are
    not a protobuf message.
    """
    ints = {1: 0, 2: 0, 7: 0, 10: 0, 11: 0}
    texts = {18: "", 19: ""}
    pos = 0
    while pos < len(data):
        key, pos = _varint(data, pos)
        field_no, wire = key >> 3, key & 7
        if field_no == 0:
            raise ValueError("field number 0")
        if wire == 0:
            value, pos = _varint(data, pos)
            if field_no in ints:
                ints[field_no] = value
        elif wire == 2:
            size, pos = _varint(data, pos)
            if pos + size > len(data):
                raise ValueError("truncated field")
            if field_no in texts:
                texts[field_no] = data[pos : pos + size].decode("utf-8", "replace")
            pos += size
        elif wire == 1:
            pos += 8
        elif wire == 5:
            pos += 4
        else:
            raise ValueError(f"unsupported wire type {wire}")
    if pos != len(data):
        raise ValueError("truncated field")
    return SnapshotPb(
        version=ints[1],
        created=ints[2],
        failed_reason=ints[7],
        invalid_loads=ints[10],
        successful_loads=ints[11],
        emulator_build=texts[18],
        system_image_build=texts[19],
    )


_PB_CACHE: dict[str, tuple[tuple[int, int], SnapshotPb | None]] = {}
_PB_LOCK = threading.Lock()


def read_snapshot_pb(path: Path) -> SnapshotPb | None:
    """``snapshot.pb`` at *path*, opened read-only and never written
    (``None``: missing or unreadable). Cached by size and mtime.
    """
    try:
        st = path.stat()
    except OSError:
        return None
    sig = (st.st_size, st.st_mtime_ns)
    with _PB_LOCK:
        hit = _PB_CACHE.get(str(path))
    if hit is not None and hit[0] == sig:
        return hit[1]
    try:
        with path.open("rb") as fh:
            data = fh.read(_PB_MAX + 1)
        info = None if len(data) > _PB_MAX else parse_snapshot_pb(data)
    except (OSError, ValueError):
        info = None
    with _PB_LOCK:
        _PB_CACHE[str(path)] = (sig, info)
    return info


def failure_words(code: int) -> str:
    """A ``failed_to_load_reason_code`` in plain words."""
    return FAILURE_WORDS.get(code, f"reason code {code}")


def snapshot_pb_warning(
    info: SnapshotPb | None,
    *,
    installed_version: str = "",
    installed_build: str = "",
    launch_build: str = "",
) -> str:
    """Why a snapshot may not load, in words (``""``: nothing to say).

    A ``failed_to_load_reason_code`` below :data:`UNRECOVERABLE_LIMIT` means
    the emulator refuses the snapshot (a start cold boots); a higher one
    records a failed load. A snapshot last written by another emulator build
    than the installed one (or than the one the running emulator was
    launched with, *launch_build*) may not load either: a 35.x snapshot
    touched by emulator 37 becomes unloadable.
    """
    if info is None:
        return ""
    parts = []
    code = info.failed_reason
    if code and code < UNRECOVERABLE_LIMIT:
        parts.append(f"will not load ({failure_words(code)}); a start cold boots")
    elif code:
        parts.append(f"a load failed before ({failure_words(code)})")
    build = info.emulator_build
    expected = [b for b in (launch_build, installed_build) if b]
    if build and expected and build not in expected:
        mine = f"emulator {installed_version} (build {installed_build})"
        if launch_build and launch_build != installed_build:
            mine = f"the running emulator (build {launch_build})"
        elif not installed_version:
            mine = f"build {installed_build}"
        parts.append(
            f"last written by emulator build {build}, not {mine}; loading it "
            "may fail and cold boot"
        )
    return "; ".join(parts)


#: Words of a warning that means a load will (or may well) fail.
_SERIOUS = ("will not load", "last written by")


def snapshot_warning_serious(text: str) -> bool:
    """A :func:`snapshot_pb_warning` that means a start may cold boot (the
    snapshot is refused or another emulator build wrote it), not only that
    a load failed once (e.g. a config mismatch the emulator got over).
    """
    return any(words in text for words in _SERIOUS)


def snapshot_warnings(
    avd: str,
    names: Iterable[str],
    *,
    installed: tuple[str, str] = ("", ""),
    launch_build: str = "",
) -> dict[str, str]:
    """Warnings for the snapshots *names* of *avd* (see
    :func:`snapshot_pb_warning`); only snapshots with something to say.
    *installed* is ``(version, build id)`` of the installed emulator.
    """
    out: dict[str, str] = {}
    for name in names:
        folder = snapshot_dir(avd, name)
        if folder is None:
            continue
        text = snapshot_pb_warning(
            read_snapshot_pb(folder / "snapshot.pb"),
            installed_version=installed[0],
            installed_build=installed[1],
            launch_build=launch_build,
        )
        if text:
            out[name] = text
    return out


__all__ = [
    "AI",
    "DEFAULT_PINS",
    "DELETE",
    "LOAD",
    "SAVE",
    "UNRECOVERABLE_LIMIT",
    "USER",
    "Namespace",
    "Refusal",
    "SnapshotPb",
    "acting_as",
    "check",
    "current_actor",
    "failure_words",
    "is_pinned",
    "owner_of",
    "parse_snapshot_pb",
    "pin",
    "pinned",
    "read_snapshot_pb",
    "register_namespace",
    "snapshot_complete",
    "snapshot_dir",
    "snapshot_exists",
    "snapshot_pb_warning",
    "snapshot_warning_serious",
    "snapshot_warnings",
    "unpin",
    "unregister_namespace",
    "vanished_pins",
]
