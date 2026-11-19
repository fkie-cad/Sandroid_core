"""Unit tests for sandroid.ai.arbiter.DeviceResourceArbiter.

Each test builds its own fresh DeviceResourceArbiter() instance rather than
using the process-wide get_arbiter() singleton, to stay isolated. The
singleton is exercised separately for its identity contract.
"""

from sandroid.ai.arbiter import (
    CEILING_OWNER,
    Conflict,
    DeviceResourceArbiter,
    ResourceId,
    get_arbiter,
)


def test_claim_returns_newly_acquired_set():
    arb = DeviceResourceArbiter()

    newly = arb.claim("A", frozenset({ResourceId.DEVICE_PROXY, ResourceId.MITMPROXY}))

    assert newly == frozenset({ResourceId.DEVICE_PROXY, ResourceId.MITMPROXY})
    assert arb.snapshot() == {
        ResourceId.DEVICE_PROXY: "A",
        ResourceId.MITMPROXY: "A",
    }


def test_same_owner_reclaim_returns_empty_newly_set():
    arb = DeviceResourceArbiter()
    arb.claim("A", frozenset({ResourceId.DEVICE_PROXY}))

    # Re-claiming a resource this owner already holds grants nothing new.
    newly = arb.claim("A", frozenset({ResourceId.DEVICE_PROXY}))

    assert newly == frozenset()


def test_same_owner_partial_reclaim_returns_only_the_new_resource():
    arb = DeviceResourceArbiter()
    arb.claim("A", frozenset({ResourceId.DEVICE_PROXY}))

    newly = arb.claim("A", frozenset({ResourceId.DEVICE_PROXY, ResourceId.MITMPROXY}))

    assert newly == frozenset({ResourceId.MITMPROXY})


def test_conflict_against_a_different_owners_lease():
    arb = DeviceResourceArbiter()
    arb.claim("B", frozenset({ResourceId.MITMPROXY}))

    result = arb.claim("A", frozenset({ResourceId.MITMPROXY}))

    assert isinstance(result, Conflict)
    assert result.resource == ResourceId.MITMPROXY
    assert result.owner == "B"
    # The failed claim must not have granted anything.
    assert arb.snapshot() == {ResourceId.MITMPROXY: "B"}


def test_conflict_is_all_or_nothing():
    arb = DeviceResourceArbiter()
    arb.claim("B", frozenset({ResourceId.MITMPROXY}))

    result = arb.claim("A", frozenset({ResourceId.DEVICE_PROXY, ResourceId.MITMPROXY}))

    assert isinstance(result, Conflict)
    # DEVICE_PROXY must NOT have been leased to A despite being free -- a
    # conflicting claim grants nothing at all.
    assert ResourceId.DEVICE_PROXY not in arb.snapshot()


def test_world_conflicts_with_another_owners_lease():
    arb = DeviceResourceArbiter()
    arb.claim("B", frozenset({ResourceId.FRIDA_SERVER}))

    result = arb.claim("A", frozenset({ResourceId.WORLD}))

    assert isinstance(result, Conflict)
    assert result.resource == ResourceId.FRIDA_SERVER
    assert result.owner == "B"


def test_held_world_lease_blocks_a_different_owners_non_world_claim():
    # The reverse of test_world_conflicts_with_another_owners_lease: while one
    # owner holds WORLD (e.g. mid snapshot-restore), no OTHER owner may claim
    # any resource -- the world is being invalidated and must not be raced.
    arb = DeviceResourceArbiter()
    arb.claim("A", frozenset({ResourceId.WORLD}))

    result = arb.claim("orchestrator", frozenset({ResourceId.DEVICE_PROXY}))

    assert isinstance(result, Conflict)
    assert result.resource == ResourceId.WORLD
    assert result.owner == "A"
    assert ResourceId.DEVICE_PROXY not in arb.snapshot()


def test_owner_holding_world_can_still_claim_its_own_other_resources():
    # The WORLD-blocks-everything rule is scoped to OTHER owners; the WORLD
    # holder itself is not blocked.
    arb = DeviceResourceArbiter()
    arb.claim("A", frozenset({ResourceId.WORLD}))

    newly = arb.claim("A", frozenset({ResourceId.DEVICE_PROXY}))

    assert newly == frozenset({ResourceId.DEVICE_PROXY})


def test_world_conflicts_when_another_live_subtask_exists_without_a_lease():
    arb = DeviceResourceArbiter()
    arb.note_subtask("subtask-1")  # live, but holds no lease

    result = arb.claim("A", frozenset({ResourceId.WORLD}))

    assert isinstance(result, Conflict)
    assert result.resource == ResourceId.WORLD


def test_world_by_owner_x_succeeds_when_only_x_is_live_and_no_foreign_lease():
    arb = DeviceResourceArbiter()
    arb.note_subtask("X")

    newly = arb.claim("X", frozenset({ResourceId.WORLD}))

    assert newly == frozenset({ResourceId.WORLD})


def test_subtask_world_claim_succeeds_when_no_other_subtask_and_no_orchestrator_lease():
    # The orchestrator being merely idle (no lease, not tracked as a live
    # subtask) must not block a subtask's WORLD claim.
    arb = DeviceResourceArbiter()
    arb.note_subtask("subtask-1")

    newly = arb.claim("subtask-1", frozenset({ResourceId.WORLD}))

    assert newly == frozenset({ResourceId.WORLD})


def test_world_claim_succeeds_when_owner_holds_its_own_leases_only():
    arb = DeviceResourceArbiter()
    arb.claim("A", frozenset({ResourceId.MITMPROXY}))

    # A's own existing lease does not block A's WORLD claim.
    newly = arb.claim("A", frozenset({ResourceId.WORLD}))

    assert newly == frozenset({ResourceId.WORLD})


def test_release_resources_only_frees_this_owners_leases():
    arb = DeviceResourceArbiter()
    arb.claim("A", frozenset({ResourceId.DEVICE_PROXY}))
    arb.claim("B", frozenset({ResourceId.MITMPROXY}))

    # A tries to release a resource actually owned by B -- must be a no-op.
    arb.release_resources("A", frozenset({ResourceId.MITMPROXY}))

    assert arb.snapshot() == {
        ResourceId.DEVICE_PROXY: "A",
        ResourceId.MITMPROXY: "B",
    }

    # Releasing its own resource works.
    arb.release_resources("A", frozenset({ResourceId.DEVICE_PROXY}))
    assert arb.snapshot() == {ResourceId.MITMPROXY: "B"}


def test_release_all_drops_only_the_owners_leases():
    arb = DeviceResourceArbiter()
    arb.claim("A", frozenset({ResourceId.DEVICE_PROXY, ResourceId.SPOTLIGHT}))
    arb.claim("B", frozenset({ResourceId.MITMPROXY}))

    arb.release_all("A")

    assert arb.snapshot() == {ResourceId.MITMPROXY: "B"}


def test_forget_subtask_removes_from_live_set_and_releases_its_leases():
    arb = DeviceResourceArbiter()
    arb.note_subtask("subtask-1")
    arb.claim("subtask-1", frozenset({ResourceId.FRIDA_SERVER}))

    arb.forget_subtask("subtask-1")

    # Its lease is gone...
    assert arb.snapshot() == {}
    # ...and it no longer counts as a live subtask blocking a WORLD claim.
    newly = arb.claim("A", frozenset({ResourceId.WORLD}))
    assert newly == frozenset({ResourceId.WORLD})


def test_reconcile_drops_dead_owners_leases():
    arb = DeviceResourceArbiter()
    arb.claim("A", frozenset({ResourceId.DEVICE_PROXY}))
    arb.claim("B", frozenset({ResourceId.MITMPROXY}))
    arb.claim("orchestrator", frozenset({ResourceId.SPOTLIGHT}))

    # Only orchestrator and A are still alive; B leaked a lease.
    arb.reconcile({"orchestrator", "A"})

    assert arb.snapshot() == {
        ResourceId.DEVICE_PROXY: "A",
        ResourceId.SPOTLIGHT: "orchestrator",
    }


def test_get_arbiter_is_a_singleton():
    first = get_arbiter()
    second = get_arbiter()
    assert first is second


# -- lineage and ceiling (subagents, WP5) ---------------------------------------


def test_sync_child_uses_its_blocked_parents_lease():
    arb = DeviceResourceArbiter()
    arb.claim("orchestrator", frozenset({ResourceId.FRIDA_SERVER}))
    arb.note_subtask("a-op-child1", parent="orchestrator")

    newly = arb.claim("a-op-child1", frozenset({ResourceId.FRIDA_SERVER}))

    # Counts as held: nothing new, so the child's rollback never frees it.
    assert newly == frozenset()
    assert arb.snapshot() == {ResourceId.FRIDA_SERVER: "orchestrator"}
    arb.release_resources("a-op-child1", newly)
    assert arb.snapshot() == {ResourceId.FRIDA_SERVER: "orchestrator"}


def test_async_child_conflicts_with_the_parents_lease():
    arb = DeviceResourceArbiter()
    arb.claim("orchestrator", frozenset({ResourceId.FRIDA_SERVER}))
    arb.note_subtask("a-op-child1")

    result = arb.claim("a-op-child1", frozenset({ResourceId.FRIDA_SERVER}))

    assert result == Conflict(ResourceId.FRIDA_SERVER, "orchestrator")


def test_sync_child_declared_release_drops_the_parents_lease():
    arb = DeviceResourceArbiter()
    arb.claim("orchestrator", frozenset({ResourceId.DEVICE_PROXY}))
    arb.note_subtask("a-op-child1", parent="orchestrator")

    arb.release_resources("a-op-child1", frozenset({ResourceId.DEVICE_PROXY}))

    assert arb.snapshot() == {}


def test_sync_child_world_claim_ignores_parent_leases_but_not_strangers():
    arb = DeviceResourceArbiter()
    arb.claim("orchestrator", frozenset({ResourceId.MITMPROXY}))
    arb.note_subtask("a-op-child1", parent="orchestrator")
    assert arb.claim("a-op-child1", frozenset({ResourceId.WORLD})) == frozenset(
        {ResourceId.WORLD}
    )
    arb.release_resources("a-op-child1", frozenset({ResourceId.WORLD}))

    arb.claim("other", frozenset({ResourceId.FOCUS}))
    result = arb.claim("a-op-child1", frozenset({ResourceId.WORLD}))
    assert result == Conflict(ResourceId.FOCUS, "other")


def test_lineage_dropped_by_set_parent_and_forget():
    arb = DeviceResourceArbiter()
    arb.claim("orchestrator", frozenset({ResourceId.FRIDA_SERVER}))
    arb.note_subtask("c", parent="orchestrator")
    assert arb.lineage("c") == {"c", "orchestrator"}

    arb.set_parent("c", None)
    assert arb.lineage("c") == {"c"}
    assert isinstance(arb.claim("c", frozenset({ResourceId.FRIDA_SERVER})), Conflict)

    arb.set_parent("c", "orchestrator")
    arb.forget_subtask("c")
    assert arb.lineage("c") == {"c"}
    assert "c" not in arb.live_subtasks()


def test_ceiling_refuses_before_any_lease_check():
    arb = DeviceResourceArbiter()
    arb.note_subtask("a-re-x", ceiling=frozenset())

    result = arb.claim("a-re-x", frozenset({ResourceId.MONITOR}))

    assert result == Conflict(ResourceId.MONITOR, CEILING_OWNER)
    assert arb.snapshot() == {}
    arb.note_subtask("a-op-y", ceiling=frozenset({ResourceId.MONITOR}))
    assert arb.claim("a-op-y", frozenset({ResourceId.MONITOR})) == frozenset(
        {ResourceId.MONITOR}
    )
    arb.forget_subtask("a-re-x")
    # Without a registered ceiling anything may be claimed again.
    assert arb.claim("a-re-x", frozenset({ResourceId.FOCUS})) == frozenset(
        {ResourceId.FOCUS}
    )


def test_reset_for_tests_drops_the_singleton():
    from sandroid.ai import arbiter as arbiter_module

    first = get_arbiter()
    arbiter_module.reset_for_tests()
    assert get_arbiter() is not first
