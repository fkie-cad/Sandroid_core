"""Device-resource arbiter: fail-fast leases over shared device resources.

Subagents let more than one agent turn (the top-level orchestrator plus any
concurrently running subagents) reach for the same
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
- **The orchestrator is never a live subagent.** Only subagents are
  registered with :meth:`~DeviceResourceArbiter.note_subtask`/
  :meth:`~DeviceResourceArbiter.forget_subtask` (method names kept from the
  former subtasks API); the orchestrator is not. This is what lets a
  subagent claim :attr:`ResourceId.WORLD` while the orchestrator is merely
  idle (holding no lease) -- an idle orchestrator is not "in use", so it
  does not block a world-level operation.
- **Claims return the newly-acquired set.** :meth:`DeviceResourceArbiter.claim`
  returns exactly the resources it *newly* granted (a same-owner re-claim of
  an already-held resource grants nothing new), so the caller can roll back
  precisely those leases on a failure without touching leases it already
  held coming in.
- **Per-call reference counting.** Tool calls go through
  :meth:`~DeviceResourceArbiter.acquire`/:meth:`~DeviceResourceArbiter.settle`.
  A lease still used by an in-flight call (including one the executor
  abandoned after a timeout or cancel) is never deleted: owner-level
  releases only mark it dropped until that call's thread exits, and an owner
  with abandoned calls still running stays live (it blocks WORLD claims and
  survives :meth:`~DeviceResourceArbiter.reconcile`).
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
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


#: Owner-id prefix of leases held outside the AI (TUI operations). The AI's
#: lease reconcile only knows AI owners, so it never drops these.
EXTERNAL_OWNER_PREFIX = "tui:"

#: Age (seconds) after which :meth:`DeviceResourceArbiter.reconcile` logs a
#: warning, once per lease, about an external (``tui:``) lease it keeps.
EXTERNAL_LEASE_WARN_S = 15 * 60


class ResourceId(Enum):
    """A shared device resource that can be leased to a single owner at a time.

    :attr:`WORLD` is special: it represents an operation that invalidates all
    device state at once (a snapshot restore, an emulator restart/kill), so a
    :attr:`WORLD` claim conflicts with *any* other owner's lease and with any
    other live subagent, and any other claim conflicts with a held
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
            sentinel ``"<subtask>"`` when the conflict is a live-subagent
            collision on a :attr:`ResourceId.WORLD` claim rather than a
            held lease, or ``"<ceiling>"`` when the resource is outside the
            claiming owner's ceiling).
    """

    resource: ResourceId
    owner: str


#: ``Conflict.owner`` sentinel for a claim outside the owner's ceiling.
CEILING_OWNER = "<ceiling>"

#: ``Conflict.owner`` sentinel for a WORLD claim blocked by a live subagent
#: (or an owner whose abandoned tool call still runs).
SUBTASK_OWNER = "<subtask>"


@dataclass
class _Lease:
    """One held resource.

    Attributes:
        owner: Holder of the lease.
        inflight: Tracked tool calls (:meth:`DeviceResourceArbiter.acquire`)
            currently using the resource, abandoned ones included.
        keep: Whether the lease outlives its in-flight calls. A lease newly
            acquired by a tracked call is not kept until a call using it
            succeeds; a legacy :meth:`DeviceResourceArbiter.claim` keeps it.
        dropped: The owner released it while a call still used it; it goes
            away when the last such call settles.
        acquired_at: ``time.monotonic()`` (the arbiter's clock) when
            ``owner`` got it.
        age_warned: :meth:`DeviceResourceArbiter.reconcile` already warned
            that this (external) lease is old.
    """

    owner: str
    inflight: int = 0
    keep: bool = True
    dropped: bool = False
    acquired_at: float = field(default_factory=time.monotonic)
    age_warned: bool = False


@dataclass(eq=False)
class LeaseHandle:
    """One tool call's use of leases (from :meth:`DeviceResourceArbiter.acquire`).

    Attributes:
        owner: The claiming owner.
        resources: Every resource the call uses (newly acquired or already
            held by the owner or its lineage).
        newly: The subset this call newly acquired.
        abandoned: The executor stopped waiting for the call (timeout or
            cancel) while its thread still runs.
        settled: :meth:`DeviceResourceArbiter.settle` ran.
    """

    owner: str
    resources: frozenset[ResourceId]
    newly: frozenset[ResourceId]
    abandoned: bool = False
    settled: bool = False


class DeviceResourceArbiter:
    """Hands out fail-fast, owner-scoped leases over :class:`ResourceId`.

    Thread-safe: every public method takes ``self._lock`` for the whole of
    its (short, non-blocking) body. Claims never block waiting for a lease --
    a collision is reported immediately as a :class:`Conflict`.

    Leases are reference-counted per tool call: :meth:`acquire` returns a
    :class:`LeaseHandle` and :meth:`settle` ends the call. A lease still used
    by an in-flight call is never deleted -- an owner-level release
    (:meth:`release_all`, :meth:`forget_subtask`, :meth:`reconcile`, a
    declared release) only marks it dropped, and it goes away when the last
    call using it settles. So a call the executor abandoned (timeout/cancel)
    keeps its leases until its thread really exits, and a newer call of the
    same owner that reuses a lease is never undercut by an older call's
    rollback.

    Internal state:
        - ``_leases``: ``{ResourceId: _Lease}`` -- who holds each resource.
        - ``_live_subtasks``: the subagent owner ids currently alive. The
          orchestrator is deliberately never a member (see the module
          docstring), so an idle orchestrator never blocks a subagent's
          :attr:`ResourceId.WORLD` claim.
        - ``_abandoned``: owner -> number of abandoned calls still running.
          Such an owner counts as live (it still touches the device) until
          they exit, even after :meth:`forget_subtask`.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._lock = threading.Lock()
        #: Monotonic clock for lease ages (tests pass a fake).
        self._clock = clock
        self._leases: dict[ResourceId, _Lease] = {}
        self._live_subtasks: set[str] = set()
        #: child owner -> parent owner (synchronous subagents only).
        self._parents: dict[str, str] = {}
        #: owner -> the only resources it may claim.
        self._ceilings: dict[str, frozenset[ResourceId]] = {}
        #: owner -> abandoned calls still running.
        self._abandoned: dict[str, int] = {}
        #: forgotten subagents kept live until their abandoned calls exit.
        self._pending_forget: set[str] = set()
        #: Bumped every time a WORLD lease is newly taken (snapshot restore,
        #: emulator restart): device-derived caches compare it.
        self._world_epoch = 0

    # -- registration -----------------------------------------------------------

    def note_subtask(
        self,
        owner: str,
        *,
        parent: str | None = None,
        ceiling: frozenset[ResourceId] | None = None,
    ) -> None:
        """Register ``owner`` as a live subagent.

        Args:
            owner: The subagent's owner id. The orchestrator must never be
                registered here (see the module docstring).
            parent: Owner whose leases ``owner`` may use (a blocked parent of
                a synchronous subagent); ``None`` for no lineage.
            ceiling: Resources ``owner`` may claim at all (``None``: any).
        """
        with self._lock:
            self._live_subtasks.add(owner)
            self._pending_forget.discard(owner)
            if parent is not None and parent != owner:
                self._parents[owner] = parent
            else:
                self._parents.pop(owner, None)
            if ceiling is not None:
                self._ceilings[owner] = frozenset(ceiling)
            else:
                self._ceilings.pop(owner, None)

    def set_parent(self, owner: str, parent: str | None) -> None:
        """Set or clear the lineage of a live subagent.

        Used when a synchronous subagent becomes asynchronous (its parent
        stopped waiting): it must no longer use the parent's leases.
        """
        with self._lock:
            if parent is None or parent == owner:
                self._parents.pop(owner, None)
            else:
                self._parents[owner] = parent

    def forget_subtask(self, owner: str) -> None:
        """Deregister a subagent and release every lease it still holds.

        Lineage and ceiling of ``owner`` are dropped too. Leases an in-flight
        call still uses are only marked dropped (they go when it settles), and
        an owner with abandoned calls still running stays live until the last
        one exits.

        Args:
            owner: The subagent's owner id.
        """
        with self._lock:
            self._parents.pop(owner, None)
            self._ceilings.pop(owner, None)
            self._release_all_locked(owner)
            if self._abandoned.get(owner, 0) > 0:
                self._pending_forget.add(owner)
            else:
                self._live_subtasks.discard(owner)
                self._pending_forget.discard(owner)

    # -- queries ----------------------------------------------------------------

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
        """Return a copy of the live subagent owner ids.

        Includes forgotten subagents whose abandoned calls still run.
        """
        with self._lock:
            return set(self._live_subtasks)

    def abandoned_owners(self) -> dict[str, int]:
        """``{owner: abandoned calls still running}`` (UI/debugging)."""
        with self._lock:
            return {o: n for o, n in self._abandoned.items() if n > 0}

    def snapshot(self) -> dict[ResourceId, str]:
        """Return a copy of the current ``{resource: owner}`` lease map.

        For UI/debugging only -- a point-in-time copy, safe to read without
        holding the lock afterwards. A dropped lease that an in-flight call
        still uses is listed (it still blocks other owners).
        """
        with self._lock:
            return {r: lease.owner for r, lease in self._leases.items()}

    # -- claiming ---------------------------------------------------------------

    def claim(
        self, owner: str, resources: frozenset[ResourceId]
    ) -> "Conflict | frozenset[ResourceId]":
        """Try to lease ``resources`` for ``owner``, fail-fast on conflict.

        Untracked claim: the granted leases are kept until released. Tool
        calls use :meth:`acquire`/:meth:`settle` instead.

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
            result = self._acquire_locked(owner, frozenset(resources), track=False)
        return result if isinstance(result, Conflict) else result.newly

    def acquire(
        self, owner: str, resources: frozenset[ResourceId]
    ) -> "Conflict | LeaseHandle":
        """Claim ``resources`` for one tool call (reference-counted).

        Same rules as :meth:`claim`. The returned handle must be passed to
        :meth:`settle` when the call ends (and to :meth:`abandon` when the
        executor stops waiting first). An empty ``resources`` never conflicts;
        the handle then only tracks abandonment.
        """
        with self._lock:
            return self._acquire_locked(owner, frozenset(resources), track=True)

    def _acquire_locked(
        self, owner: str, resources: frozenset[ResourceId], *, track: bool
    ) -> "Conflict | LeaseHandle":
        mine = self._lineage_locked(owner)
        if resources:
            conflict = self._conflict_locked(owner, resources, mine)
            if conflict is not None:
                return conflict
        newly: set[ResourceId] = set()
        for resource in resources:
            lease = self._leases.get(resource)
            if lease is None:
                self._leases[resource] = _Lease(
                    owner,
                    inflight=1 if track else 0,
                    keep=not track,
                    acquired_at=self._clock(),
                )
                newly.add(resource)
                continue
            if lease.dropped:
                # Released while an older call still used it: re-acquired.
                lease.owner = owner
                lease.dropped = False
                lease.keep = not track
                lease.acquired_at = self._clock()
                lease.age_warned = False
                newly.add(resource)
            elif not track:
                lease.keep = True
            if track:
                lease.inflight += 1
        if ResourceId.WORLD in newly:
            self._world_epoch += 1
        return LeaseHandle(owner, resources, frozenset(newly))

    def world_epoch(self) -> int:
        """How many times a WORLD lease was taken (device state may differ)."""
        with self._lock:
            return self._world_epoch

    def _conflict_locked(
        self, owner: str, resources: frozenset[ResourceId], mine: set[str]
    ) -> Conflict | None:
        ceiling = self._ceilings.get(owner)
        if ceiling is not None:
            outside = sorted(
                (r for r in resources if r not in ceiling), key=lambda r: r.value
            )
            if outside:
                return Conflict(resource=outside[0], owner=CEILING_OWNER)

        # A held WORLD lease (by a different owner) blocks EVERY claim, WORLD
        # or not: a world-invalidating op in flight (snapshot restore,
        # emulator restart/kill) must not race any other device mutation.
        # This is the reverse of the WORLD-vs-lease check below.
        world = self._leases.get(ResourceId.WORLD)
        if world is not None and world.owner not in mine:
            return Conflict(resource=ResourceId.WORLD, owner=world.owner)

        if ResourceId.WORLD in resources:
            for resource, lease in self._leases.items():
                if lease.owner not in mine:
                    return Conflict(resource=resource, owner=lease.owner)
            for subtask in self._live_subtasks:
                if subtask not in mine:
                    return Conflict(resource=ResourceId.WORLD, owner=SUBTASK_OWNER)
            for busy, count in self._abandoned.items():
                if count > 0 and busy not in mine:
                    return Conflict(resource=ResourceId.WORLD, owner=SUBTASK_OWNER)

        for resource in resources:
            lease = self._leases.get(resource)
            if lease is not None and lease.owner not in mine:
                return Conflict(resource=resource, owner=lease.owner)
        return None

    def abandon(self, handle: LeaseHandle) -> None:
        """The executor stopped waiting for this call; its thread still runs.

        The owner counts as live until :meth:`settle` runs for the handle.
        """
        with self._lock:
            if handle.settled or handle.abandoned:
                return
            handle.abandoned = True
            self._abandoned[handle.owner] = self._abandoned.get(handle.owner, 0) + 1

    def settle(
        self,
        handle: LeaseHandle,
        *,
        failed: bool,
        releases: frozenset[ResourceId] = frozenset(),
    ) -> None:
        """End a call: keep, roll back or release its leases (idempotent).

        A lease the call newly acquired is kept once any call using it
        succeeded; it is rolled back when the last call using it ends and
        none succeeded. Leases already kept coming in are never rolled back.
        ``releases`` (a successful call's declared releases) are applied
        after the call's own use ends.

        Args:
            handle: From :meth:`acquire`.
            failed: The call failed (or was abandoned): it does not make its
                leases kept.
            releases: Resources to release afterwards (owner/lineage scoped).
        """
        with self._lock:
            if handle.settled:
                return
            handle.settled = True
            for resource in handle.resources:
                lease = self._leases.get(resource)
                if lease is None:
                    continue
                lease.inflight = max(0, lease.inflight - 1)
                if not failed and not lease.dropped:
                    lease.keep = True
                if lease.inflight == 0 and (lease.dropped or not lease.keep):
                    del self._leases[resource]
            if releases:
                self._release_resources_locked(handle.owner, releases)
            if handle.abandoned:
                left = self._abandoned.get(handle.owner, 0) - 1
                if left > 0:
                    self._abandoned[handle.owner] = left
                else:
                    self._abandoned.pop(handle.owner, None)
                    if handle.owner in self._pending_forget:
                        self._pending_forget.discard(handle.owner)
                        self._live_subtasks.discard(handle.owner)

    # -- releasing --------------------------------------------------------------

    def _drop_locked(self, resource: ResourceId) -> None:
        """Release ``resource`` now, or once its in-flight calls settle."""
        lease = self._leases.get(resource)
        if lease is None:
            return
        if lease.inflight > 0:
            lease.dropped = True
        else:
            del self._leases[resource]

    def release_resources(self, owner: str, resources: frozenset[ResourceId]) -> None:
        """Release ``resources``, but only those actually held by ``owner``.

        A resource currently leased to an unrelated owner is left untouched
        -- releasing is owner-scoped, so a stale/mistaken release can never
        free another owner's lease. A resource held by an ancestor of
        ``owner`` (lineage) is released: the synchronous child acted for its
        blocked parent (e.g. it cleared the parent's device proxy). A lease
        an in-flight call still uses goes when that call settles.

        Args:
            owner: The owner id releasing its leases.
            resources: The resources to release.
        """
        with self._lock:
            self._release_resources_locked(owner, resources)

    def _release_resources_locked(
        self, owner: str, resources: frozenset[ResourceId]
    ) -> None:
        mine = self._lineage_locked(owner)
        for resource in resources:
            lease = self._leases.get(resource)
            if lease is not None and lease.owner in mine:
                self._drop_locked(resource)

    def release_all(self, owner: str) -> None:
        """Release every lease currently held by ``owner``.

        Leases an in-flight (e.g. abandoned) call still uses go when it
        settles.

        Args:
            owner: The owner id whose leases should all be dropped.
        """
        with self._lock:
            self._release_all_locked(owner)

    def _release_all_locked(self, owner: str) -> None:
        """Drop all of ``owner``'s leases; caller must already hold the lock."""
        for resource in [
            r for r, lease in self._leases.items() if lease.owner == owner
        ]:
            self._drop_locked(resource)

    def reconcile(self, live_owner_ids: set[str]) -> None:
        """Drop any lease whose owner is not in ``live_owner_ids`` (safety net).

        Guards against a leaked lease from an owner that died without its
        ``finally``/``forget_subtask`` running. Not a substitute for explicit
        release -- just a backstop. Owners with abandoned calls still running
        count as live, and a lease an in-flight call uses goes only when it
        settles.

        Args:
            live_owner_ids: The set of owner ids currently known to be alive
                (e.g. the orchestrator plus every live subagent). Owners
                outside the AI (``tui:...``, e.g. the TUI's Zygote-restart
                fallback) are never dropped here: the AI does not know them,
                and they release their own leases in a ``finally``. One
                older than :data:`EXTERNAL_LEASE_WARN_S` is kept but logged
                once (owner, resource, age): a ``finally`` that never ran.
        """
        old: list[tuple[str, str, float]] = []
        with self._lock:
            live = set(live_owner_ids) | {
                o for o, n in self._abandoned.items() if n > 0
            }
            for resource in [
                r
                for r, lease in self._leases.items()
                if lease.owner not in live
                and not lease.owner.startswith(EXTERNAL_OWNER_PREFIX)
            ]:
                self._drop_locked(resource)
            now = self._clock()
            for resource, lease in self._leases.items():
                if (
                    lease.owner.startswith(EXTERNAL_OWNER_PREFIX)
                    and not lease.dropped
                    and not lease.age_warned
                    and now - lease.acquired_at >= EXTERNAL_LEASE_WARN_S
                ):
                    lease.age_warned = True
                    old.append((lease.owner, resource.value, now - lease.acquired_at))
        for owner, resource_name, age in old:
            logger.warning(
                "Lease %s held by %s for %.0f min; kept (external owners "
                "release their own leases)",
                resource_name,
                owner,
                age / 60,
            )


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
