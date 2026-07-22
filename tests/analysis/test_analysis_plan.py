"""Pure, device-free tests for ``AnalysisPlan.build``.

These assert the exact ordered *step-kind* sequence the builder produces for
the four canonical shapes called out in the plan (N=2 all-options-on, N=1
single-run, options-off, and noise-filter-off), plus the invariant that a
``PullStep`` is never separated from its preceding ``GatherStep`` by an action
that would reset the action-time cache.
"""

from __future__ import annotations

from sandroid.analysis.engine import AnalysisPlan, PullStep
from sandroid.analysis.run_config import RunConfig


class _DummyAction:
    """A non-``None`` stand-in so an ``ActionStep`` is emitted (never performed)."""

    def perform(self) -> None:  # pragma: no cover - never called in plan tests
        raise AssertionError("plan building must not perform the action")


class _DummyGatherer:
    """Opaque gatherer sentinel; the pure builder only references identity."""


def _gatherers(*keys: str) -> dict[str, _DummyGatherer]:
    """Build a gatherer map with a distinct sentinel per requested key."""
    return {key: _DummyGatherer() for key in keys}


def _kinds(config: RunConfig, gatherers: dict[str, _DummyGatherer]) -> list[str]:
    """Return the ordered step-kind sequence of the built plan."""
    return [step.kind for step in AnalysisPlan.build(config, gatherers)]


# ---------------------------------------------------------------------------
# N=2, every option on, dry run on
# ---------------------------------------------------------------------------
def test_n2_all_options_on():
    """N=2 with network/processes/sockets/deleted + dry run reproduces legacy."""
    config = RunConfig(
        number_of_runs=2,
        noise_filter=True,
        network=True,
        processes=True,
        sockets=True,
        show_deleted=True,
        action=_DummyAction(),
    )
    gatherers = _gatherers(
        "changed_files",
        "new_files",
        "deleted_files",
        "network",
        "processes",
        "sockets",
    )

    assert _kinds(config, gatherers) == [
        # pre
        "load_snapshot",
        "baseline",
        # run 0 (== legacy pull0)
        "action",
        "gather",
        "gather",
        "gather",
        "load_snapshot",
        "pull",
        # run 1 (captures, then pull1)
        "start_capture",
        "start_capture",
        "start_capture",
        "action",
        "stop_capture",
        "stop_capture",
        "stop_capture",
        "gather",
        "gather",
        "gather",
        "pull",
        "load_snapshot",
        # dry run
        "dry_run_begin",
        "start_capture",
        "start_capture",
        "start_capture",
        "dry_run_sleep",
        "stop_capture",
        "stop_capture",
        "stop_capture",
        "gather",
        "pull",
        "dry_run_end",
    ]


def test_n2_capture_start_order_is_network_processes_sockets():
    """Capture start steps keep the legacy network -> processes -> sockets order."""
    config = RunConfig(
        number_of_runs=2,
        noise_filter=False,
        network=True,
        processes=True,
        sockets=True,
        action=_DummyAction(),
    )
    gatherers = _gatherers(
        "changed_files", "new_files", "network", "processes", "sockets"
    )
    plan = AnalysisPlan.build(config, gatherers)

    started = [
        type(s.gatherer).__name__ if hasattr(s, "gatherer") else None
        for s in plan
        if s.kind == "start_capture"
    ]
    # Two capture rounds (run 1 only, dry run off), each network/proc/socket.
    ordered = [
        gatherers["network"],
        gatherers["processes"],
        gatherers["sockets"],
    ]
    start_steps = [s for s in plan if s.kind == "start_capture"]
    assert [s.gatherer for s in start_steps] == ordered
    assert len(started) == 3


# ---------------------------------------------------------------------------
# N=1 single-run special case
# ---------------------------------------------------------------------------
def test_n1_single_run_yields_both_pulls():
    """A single run still produces first + second (+noise) pulls for real diffs."""
    config = RunConfig(
        number_of_runs=1,
        noise_filter=True,
        network=False,
        processes=False,
        sockets=False,
        show_deleted=False,
        action=_DummyAction(),
    )
    gatherers = _gatherers("changed_files", "new_files")

    assert _kinds(config, gatherers) == [
        "load_snapshot",
        "baseline",
        # single run: gather, pull second, revert, pull first
        "action",
        "gather",
        "gather",
        "pull",
        "load_snapshot",
        "pull",
        # dry run
        "dry_run_begin",
        "dry_run_sleep",
        "gather",
        "pull",
        "dry_run_end",
    ]


def test_n1_pull_slots_are_second_then_first():
    """The N=1 pulls are ordered second (post-action) then first (reverted)."""
    config = RunConfig(number_of_runs=1, noise_filter=False, action=_DummyAction())
    gatherers = _gatherers("changed_files", "new_files")
    plan = AnalysisPlan.build(config, gatherers)

    slots = [s.slot for s in plan if isinstance(s, PullStep)]
    assert slots == ["second", "first"]


# ---------------------------------------------------------------------------
# Options off (only changed/new + dry run)
# ---------------------------------------------------------------------------
def test_options_off():
    """No captures, no deleted files -- plain 2-run changed/new + dry run."""
    config = RunConfig(
        number_of_runs=2,
        noise_filter=True,
        network=False,
        processes=False,
        sockets=False,
        show_deleted=False,
        action=_DummyAction(),
    )
    gatherers = _gatherers("changed_files", "new_files")

    assert _kinds(config, gatherers) == [
        "load_snapshot",
        "baseline",
        # run 0
        "action",
        "gather",
        "gather",
        "load_snapshot",
        "pull",
        # run 1
        "action",
        "gather",
        "gather",
        "pull",
        "load_snapshot",
        # dry run
        "dry_run_begin",
        "dry_run_sleep",
        "gather",
        "pull",
        "dry_run_end",
    ]


# ---------------------------------------------------------------------------
# Noise filter off (no dry run at all)
# ---------------------------------------------------------------------------
def test_noise_filter_off_drops_dry_run():
    """With noise_filter off the plan has no dry-run steps."""
    config = RunConfig(
        number_of_runs=2,
        noise_filter=False,
        network=False,
        processes=False,
        sockets=False,
        show_deleted=False,
        action=_DummyAction(),
    )
    gatherers = _gatherers("changed_files", "new_files")

    kinds = _kinds(config, gatherers)
    assert kinds == [
        "load_snapshot",
        "baseline",
        "action",
        "gather",
        "gather",
        "load_snapshot",
        "pull",
        "action",
        "gather",
        "gather",
        "pull",
        "load_snapshot",
    ]
    assert "dry_run_begin" not in kinds
    assert "dry_run_sleep" not in kinds
    assert "dry_run_end" not in kinds


# ---------------------------------------------------------------------------
# Playback (recording_path, no explicit action) resolves a Player
# ---------------------------------------------------------------------------
def test_playback_builds_player_action():
    """recording_path + action None resolves to a Player-backed ActionStep."""
    from sandroid.features.player import Player

    config = RunConfig.for_playback(
        recording_path="/abs/bundle/recording.txt",
        number_of_runs=1,
        noise_filter=False,
    )
    gatherers = _gatherers("changed_files", "new_files")
    plan = AnalysisPlan.build(config, gatherers)

    action_steps = [s for s in plan if s.kind == "action"]
    assert len(action_steps) == 1
    action = action_steps[0].action
    assert isinstance(action, Player)
    assert action._recording_path == "/abs/bundle/recording.txt"


# ---------------------------------------------------------------------------
# Invariant: no action step ever sits between a gather and its pull
# ---------------------------------------------------------------------------
def test_no_action_between_gather_and_pull():
    """A PullStep is never preceded (since its gather) by an action step.

    ``set_action_time`` wipes the changed-files cache, so an action between a
    gather and its pull would empty the pull. Assert that between each gather
    and the next pull there is no ``action``/``dry_run_begin`` (both reset the
    action time).
    """
    config = RunConfig(
        number_of_runs=2,
        noise_filter=True,
        network=True,
        processes=True,
        sockets=True,
        show_deleted=True,
        action=_DummyAction(),
    )
    gatherers = _gatherers(
        "changed_files",
        "new_files",
        "deleted_files",
        "network",
        "processes",
        "sockets",
    )
    kinds = _kinds(config, gatherers)

    resetting = {"action", "dry_run_begin"}
    for idx, kind in enumerate(kinds):
        if kind != "pull":
            continue
        # Walk backwards to the nearest gather; no resetting step in between.
        j = idx - 1
        while j >= 0 and kinds[j] != "gather":
            assert kinds[j] not in resetting, (
                f"resetting step {kinds[j]!r} sits between a gather and pull "
                f"at index {idx}"
            )
            j -= 1
        assert j >= 0, "every pull must be preceded by a gather"
