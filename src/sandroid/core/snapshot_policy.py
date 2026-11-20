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


def pinned(avd: str | None) -> frozenset[str]:
    """Pinned snapshot names of AVD *avd* (:data:`DEFAULT_PINS` if unknown)."""
    if not avd:
        return frozenset(DEFAULT_PINS)
    from sandroid.core import emulator

    entry = emulator.load_launch_prefs()["avds"].get(avd, {})
    pins = entry.get("pins")
    if not isinstance(pins, list):
        return frozenset(DEFAULT_PINS)
    return frozenset(p for p in pins if isinstance(p, str))


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
    """Whether AVD *avd* has a snapshot directory *name* (``None``: unknown)."""
    if not avd:
        return None
    from sandroid.core import emulator

    directory = emulator.avd_dir(avd)
    if directory is None:
        return None
    return (directory / "snapshots" / name).is_dir()


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


__all__ = [
    "AI",
    "DEFAULT_PINS",
    "DELETE",
    "LOAD",
    "SAVE",
    "USER",
    "Namespace",
    "Refusal",
    "acting_as",
    "check",
    "current_actor",
    "is_pinned",
    "owner_of",
    "pin",
    "pinned",
    "register_namespace",
    "snapshot_complete",
    "snapshot_dir",
    "snapshot_exists",
    "unpin",
    "unregister_namespace",
    "vanished_pins",
]
