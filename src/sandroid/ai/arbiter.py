"""Device-resource arbiter: fail-fast leases over shared device resources.

The async-subtasks feature lets more than one agent turn (the top-level
orchestrator plus any concurrently running subtasks) reach for the same
physical device resources -- the device's global HTTP proxy, the mitmproxy
subprocess, frida-server, the spotlight selection, screen recording, the
App-Proxy ("Focus") lane pool, or the whole "world" (a snapshot restore /
emulator restart that invalidates everything). Two turns mutating the same
resource at once is a correctness hazard, so this module hands out
short-lived, owner-scoped *leases* and refuses (fail-fast, never blocks) a
claim that would collide with a lease another owner already holds.

Design notes:

- **Pure and stdlib-only.** This module imports nothing from the tool
  registry, the loop, or the Toolbox -- the dependency points one way
  (registry -> arbiter), so there is no import cycle. Callers pass an opaque
  ``owner`` string; the arbiter never inspects or derives it.
- **The orchestrator is never a live subtask.** Only subtasks call
  :meth:`~DeviceResourceArbiter.note_subtask`/
  :meth:`~DeviceResourceArbiter.forget_subtask`; the orchestrator does not.
  This is what lets a privileged subtask claim :attr:`ResourceId.WORLD` while
  the orchestrator is merely idle (holding no lease) -- an idle orchestrator
  is not "in use", so it does not block a world-level operation.
- **Claims return the newly-acquired set.** :meth:`DeviceResourceArbiter.claim`
  returns exactly the resources it *newly* granted (a same-owner re-claim of
  an already-held resource grants nothing new), so the caller can roll back
  precisely those leases on a failure without touching leases it already
  held coming in.
- **Lineage (subagents).** A synchronous subagent (spawned with
  ``wait=true``) runs while its parent's turn is blocked inside the spawn
  tool call. It is registered with ``note_subtask(child, parent=...)`` and may
  then use leases its (blocked) parent holds: a resource held by an ancestor
  counts as already held, is never part of the child's newly-acquired set
  (so the child's rollback never frees it) and a declared release by the
  child drops it. Asynchronous subagents have no lineage.
- **Ceiling.** ``note_subtask(owner, ceiling=...)`` limits the resources an
  owner may ever claim; a claim outside it is refused before any lease check
  (``Conflict(owner=CEILING_OWNER)``).
"""

import logging
import threading
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ResourceId(Enum):
    """A shared device resource that can be leased to a single owner at a time.

    :attr:`WORLD` is special: it represents an operation that invalidates all
    device state at once (a snapshot restore, an emulator restart/kill), so a
    :attr:`WORLD` claim conflicts with *any* other owner's lease and with any
    other live subtask, and any other claim conflicts with a held
    :attr:`WORLD` lease.
    """

    DEVICE_PROXY = "device_proxy"
    MITMPROXY = "mitmproxy"
    FRIDA_SERVER = "frida_server"
    SPOTLIGHT = "spotlight"
    SCREEN_RECORDING = "screen_recording"
    FOCUS = "focus"
    WORLD = "world"
    #: The filesystem monitor (kprobe/fsmon) background capture -- see
    #: :mod:`sandroid.ai.tools.monitor_control`.
    MONITOR = "monitor"
    #: The device input-event recording (getevent capture) -- see
    #: :mod:`sandroid.ai.tools.recording_control`. Named ``INPUT_RECORDING``
    #: (not a bare ``RECORDING``) so it reads unambiguously next to
    #: :attr:`SCREEN_RECORDING`, an unrelated video-capture feature.
    INPUT_RECORDING = "input_recording"


@dataclass(frozen=True)
class Conflict:
    """A rejected claim: ``resource`` is already held by ``owner``.

    Attributes:
        resource: The specific resource whose lease blocked the claim.
        owner: The owner id currently holding the conflicting lease (or the
            sentinel ``"<subtask>"`` when the conflict is a live-subtask
            collision on a :attr:`ResourceId.WORLD` claim rather than a
            held lease, or ``"<ceiling>"`` when the resource is outside the
            claiming owner's ceiling).
    """

    resource: ResourceId
    owner: str


#: ``Conflict.owner`` sentinel for a claim outside the owner's ceiling.
CEILING_OWNER = "<ceiling>"

#: ``Conflict.owner`` sentinel for a WORLD claim blocked by a live subtask.
SUBTASK_OWNER = "<subtask>"


class DeviceResourceArbiter:
    """Hands out fail-fast, owner-scoped leases over :class:`ResourceId`.

    Thread-safe: every public method takes ``self._lock`` for the whole of
    its (short, non-blocking) body. Claims never block waiting for a lease --
    a collision is reported immediately as a :class:`Conflict`.

    Internal state:
        - ``_leases``: ``{ResourceId: owner_id}`` -- who currently holds each
          resource.
        - ``_live_subtasks``: the set of subtask owner ids currently alive.
          The orchestrator is deliberately never a member (see the module
          docstring), so an idle orchestrator never blocks a subtask's
          :attr:`ResourceId.WORLD` claim.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._leases: dict[ResourceId, str] = {}
        self._live_subtasks: set[str] = set()
        #: child owner -> parent owner (synchronous subagents only).
        self._parents: dict[str, str] = {}
        #: owner -> the only resources it may claim.
        self._ceilings: dict[str, frozenset[ResourceId]] = {}

    def note_subtask(
        self,
        owner: str,
        *,
        parent: str | None = None,
        ceiling: frozenset[ResourceId] | None = None,
    ) -> None:
        """Register ``owner`` as a live subtask.

        Args:
            owner: The subtask's owner id. The orchestrator must never be
                registered here (see the module docstring).
            parent: Owner whose leases ``owner`` may use (a blocked parent of
                a synchronous subagent); ``None`` for no lineage.
            ceiling: Resources ``owner`` may claim at all (``None``: any).
        """
        with self._lock:
            self._live_subtasks.add(owner)
            if parent is not None and parent != owner:
                self._parents[owner] = parent
            else:
                self._parents.pop(owner, None)
            if ceiling is not None:
                self._ceilings[owner] = frozenset(ceiling)
            else:
                self._ceilings.pop(owner, None)

    def set_parent(self, owner: str, parent: str | None) -> None:
        """Set or clear the lineage of a live subtask.

        Used when a synchronous subagent becomes asynchronous (its parent
        stopped waiting): it must no longer use the parent's leases.
        """
        with self._lock:
            if parent is None or parent == owner:
                self._parents.pop(owner, None)
            else:
                self._parents[owner] = parent

    def forget_subtask(self, owner: str) -> None:
        """Deregister a live subtask and release every lease it still holds.

        Lineage and ceiling of ``owner`` are dropped too.

        Args:
            owner: The subtask's owner id.
        """
        with self._lock:
            self._live_subtasks.discard(owner)
            self._parents.pop(owner, None)
            self._ceilings.pop(owner, None)
            self._release_all_locked(owner)

    def _lineage_locked(self, owner: str) -> set[str]:
        """``owner`` plus its ancestors (cycle-safe); caller holds the lock."""
        chain = {owner}
        current = owner
        while current in self._parents:
            current = self._parents[current]
            if current in chain:
                break
            chain.add(current)
        return chain

    def lineage(self, owner: str) -> set[str]:
        """Return ``owner`` plus every ancestor whose leases it may use."""
        with self._lock:
            return self._lineage_locked(owner)

    def live_subtasks(self) -> set[str]:
        """Return a copy of the live subtask owner ids."""
        with self._lock:
            return set(self._live_subtasks)

    def claim(
        self, owner: str, resources: frozenset[ResourceId]
    ) -> "Conflict | frozenset[ResourceId]":
        """Try to lease ``resources`` for ``owner``, fail-fast on conflict.

        Args:
            owner: The claiming owner id.
            resources: The resources to lease. A :attr:`ResourceId.WORLD`
                claim is treated specially (see :class:`ResourceId`).

        Returns:
            The frozenset of *newly*-acquired resources (empty if ``owner``
            already held all of them) on success, or a :class:`Conflict`
            describing the first collision on failure. On a conflict, no
            lease is granted (the claim is all-or-nothing). A resource held
            by an ancestor (lineage) counts as held and is never newly
            acquired. A resource outside the owner's ceiling is refused
            with ``Conflict(owner=CEILING_OWNER)``.
        """
        with self._lock:
            ceiling = self._ceilings.get(owner)
            if ceiling is not None:
                outside = sorted(
                    (r for r in resources if r not in ceiling), key=lambda r: r.value
                )
                if outside:
                    return Conflict(resource=outside[0], owner=CEILING_OWNER)

            mine = self._lineage_locked(owner)
            # A held WORLD lease (by a different owner) blocks EVERY claim,
            # WORLD or not: a world-invalidating op in flight (snapshot
            # restore, emulator restart/kill) must not race any other device
            # mutation. This is the reverse of the WORLD-vs-lease check below.
            world_holder = self._leases.get(ResourceId.WORLD)
            if world_holder is not None and world_holder not in mine:
                return Conflict(resource=ResourceId.WORLD, owner=world_holder)

            if ResourceId.WORLD in resources:
                for resource, holder in self._leases.items():
                    if holder not in mine:
                        return Conflict(resource=resource, owner=holder)
                for subtask in self._live_subtasks:
                    if subtask not in mine:
                        return Conflict(resource=ResourceId.WORLD, owner=SUBTASK_OWNER)

            for resource in resources:
                holder = self._leases.get(resource)
                if holder is not None and holder not in mine:
                    return Conflict(resource=resource, owner=holder)

            newly = frozenset(r for r in resources if self._leases.get(r) is None)
            for resource in newly:
                self._leases[resource] = owner
            return newly

    def release_resources(self, owner: str, resources: frozenset[ResourceId]) -> None:
        """Release ``resources``, but only those actually held by ``owner``.

        A resource currently leased to an unrelated owner is left untouched
        -- releasing is owner-scoped, so a stale/mistaken release can never
        free another owner's lease. A resource held by an ancestor of
        ``owner`` (lineage) is released: the synchronous child acted for its
        blocked parent (e.g. it cleared the parent's device proxy). Rollbacks
        only pass the child's newly-acquired set, so they never touch
        ancestor leases.

        Args:
            owner: The owner id releasing its leases.
            resources: The resources to release.
        """
        with self._lock:
            mine = self._lineage_locked(owner)
            for resource in resources:
                if self._leases.get(resource) in mine:
                    del self._leases[resource]

    def release_all(self, owner: str) -> None:
        """Release every lease currently held by ``owner``.

        Args:
            owner: The owner id whose leases should all be dropped.
        """
        with self._lock:
            self._release_all_locked(owner)

    def _release_all_locked(self, owner: str) -> None:
        """Drop all of ``owner``'s leases; caller must already hold the lock."""
        for resource in [r for r, holder in self._leases.items() if holder == owner]:
            del self._leases[resource]

    def reconcile(self, live_owner_ids: set[str]) -> None:
        """Drop any lease whose owner is not in ``live_owner_ids`` (safety net).

        Guards against a leaked lease from an owner that died without its
        ``finally``/``forget_subtask`` running. Not a substitute for explicit
        release -- just a backstop.

        Args:
            live_owner_ids: The set of owner ids currently known to be alive
                (e.g. the orchestrator plus every live subtask).
        """
        with self._lock:
            for resource in [
                r for r, holder in self._leases.items() if holder not in live_owner_ids
            ]:
                del self._leases[resource]

    def snapshot(self) -> dict[ResourceId, str]:
        """Return a copy of the current ``{resource: owner}`` lease map.

        For UI/debugging only -- a point-in-time copy, safe to read without
        holding the lock afterwards.
        """
        with self._lock:
            return dict(self._leases)


_arbiter: DeviceResourceArbiter | None = None


def reset_for_tests() -> None:
    """Drop the singleton (test isolation)."""
    global _arbiter
    _arbiter = None


def get_arbiter() -> DeviceResourceArbiter:
    """Get or create the :class:`DeviceResourceArbiter` singleton.

    Mirrors :func:`sandroid.ai.tools.registry.get_tool_registry`.

    Returns:
        The process-wide arbiter instance.
    """
    global _arbiter
    if _arbiter is None:
        _arbiter = DeviceResourceArbiter()
    return _arbiter
