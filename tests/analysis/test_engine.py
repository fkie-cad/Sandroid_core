"""Device-free tests for :class:`sandroid.analysis.engine.AnalysisEngine`.

These exercise the engine core with fully injected collaborators: a mock
forensic service, a *real* ``ActionWindowService``, a fake toolbox (snapshot /
pull / fetch mocked), and DI'd fake gatherer classes. They cover accumulation
(gather called once per run), event publication, per-step error isolation, the
device-stability guard, and the ``RAW_RESULTS_PATH`` env pin (trailing sep
during the run + restoration afterwards, and that gatherers are not handed a
path-bearing config).
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import MagicMock

from sandroid.analysis.engine import EVENT_SOURCE, AnalysisEngine
from sandroid.analysis.run_config import RunConfig
from sandroid.core.events import EventBus, EventType
from sandroid.services.action_window_service import ActionWindowService
from sandroid.services.forensic_service import ForensicService
from sandroid.services.spotlight_service import SpotlightService

# ===========================================================================
# Fakes
# ===========================================================================


class FakeAction:
    """A Functionality stand-in that just records ``perform`` calls.

    Optionally sets a duration on an ``ActionWindowService`` at the end of
    ``perform()``, mirroring what ``Player``/``Trigdroid`` really do via
    ``Toolbox.set_action_duration()`` (unforced -- only takes effect once per
    analysis, exactly like the real ``ActionWindowService.set_duration``).
    """

    def __init__(
        self,
        *,
        action_window_service: Any = None,
        duration: int | None = None,
    ) -> None:
        self.performed = 0
        self._action_window_service = action_window_service
        self._duration = duration

    def perform(self) -> None:
        self.performed += 1
        if self._action_window_service is not None and self._duration is not None:
            self._action_window_service.set_duration(self._duration)


class FakeToolbox:
    """Minimal toolbox surface the engine touches, all in-memory.

    Records snapshot loads and pulls, serves a canned changed-files map, and
    supports the finalize surface (``submit_other_data`` +
    ``other_output_data_collector`` + ``_timestamps_shadow_dict_list``).
    Optionally flips ``device_name`` on the first ``fetch_changed_files`` to
    exercise the device-stability guard.
    """

    def __init__(
        self,
        device_name: str = "emu-1",
        changed: dict[str, int] | None = None,
        flip_to: str | None = None,
        shadow_entry: Any = None,
    ) -> None:
        self.device_name = device_name
        self._changed = changed or {}
        self._flip_to = flip_to
        self._shadow_entry = shadow_entry
        self._fetched = 0
        self.loaded_snapshots: list[Any] = []
        self.pulled: list[tuple[str, str]] = []
        self.action_times_set = 0
        self.other_output_data_collector: dict[str, Any] = {}
        self._timestamps_shadow_dict_list: list[Any] = []

    def load_snapshot(self, name: Any) -> None:
        self.loaded_snapshots.append(name)

    def fetch_changed_files(self, fetch_all: bool = False) -> dict[str, int]:
        self._fetched += 1
        if self._flip_to is not None and self._fetched == 1:
            self.device_name = self._flip_to
        # Simulate the timeline callback populating the shadow list during a
        # real filesystem scan (the engine resets it once, then it fills up).
        # Append just once so the list-wrapping assertion is deterministic.
        if (
            self._shadow_entry is not None
            and not fetch_all
            and self._shadow_entry not in self._timestamps_shadow_dict_list
        ):
            self._timestamps_shadow_dict_list.append(self._shadow_entry)
        if fetch_all:
            # Baseline scan: a real device always lists files; the engine
            # aborts on an empty (failed) baseline.
            return {"/data/baseline.db": 1, **self._changed}
        return dict(self._changed)

    def pull_file(self, slot: str, file_to_pull: str) -> None:
        self.pulled.append((slot, file_to_pull))

    def set_action_time(self) -> None:
        self.action_times_set += 1

    def submit_other_data(self, identifier: str, data: Any) -> None:
        if identifier not in self.other_output_data_collector:
            self.other_output_data_collector[identifier] = [data]
        else:
            self.other_output_data_collector[identifier].append(data)


def make_fake_gatherer(
    return_data: dict[str, Any] | None = None,
    *,
    raise_on_gather: bool = False,
    has_stop: bool = False,
):
    """Build a fresh fake gatherer *class* recording construction + calls."""

    class _Fake:
        instances: list[_Fake] = []

        def __init__(self, **kwargs: Any) -> None:
            self.init_kwargs = kwargs
            self.gather_calls = 0
            self.stop_calls = 0
            self.env_seen: list[str | None] = []
            type(self).instances.append(self)

        def gather(self) -> None:
            self.gather_calls += 1
            self.env_seen.append(os.environ.get("RAW_RESULTS_PATH"))
            if raise_on_gather:
                raise RuntimeError("boom in gather")

        def return_data(self) -> dict[str, Any]:
            return dict(return_data or {})

        def pretty_print(self) -> str:
            return ""

        if has_stop:

            def stop(self) -> None:
                self.stop_calls += 1

    return _Fake


def _classes(
    *,
    cf_raise: bool = False,
    nf_raise: bool = False,
) -> dict[str, type]:
    """Standard fake gatherer class map for the tests."""
    return {
        "changed_files": make_fake_gatherer(
            {"Changed Files": ["/data/a.db"]}, raise_on_gather=cf_raise
        ),
        "new_files": make_fake_gatherer(
            {"New Files": ["/data/new.txt"]}, raise_on_gather=nf_raise
        ),
        "deleted_files": make_fake_gatherer({"Deleted Files": []}),
        "network": make_fake_gatherer(
            {"Network": [], "Network IP:Port (send/recv)": []}, has_stop=True
        ),
        "processes": make_fake_gatherer({"Processes": []}),
        "sockets": make_fake_gatherer({"Listening Sockets": []}),
    }


def _make_engine(
    config: RunConfig,
    *,
    toolbox: FakeToolbox | None = None,
    classes: dict[str, type] | None = None,
    progress: Any = None,
    forensic: Any = None,
    spotlight: SpotlightService | None = None,
) -> AnalysisEngine:
    """Construct an engine wired to injected fakes + a real ActionWindowService.

    A fresh ``SpotlightService`` keeps the process-wide singleton (and any
    app another test left in it) out of the noise filter's protected list.
    """
    return AnalysisEngine(
        config,
        progress=progress,
        forensic_service=forensic or MagicMock(),
        action_window_service=ActionWindowService(adb=MagicMock()),
        toolbox=toolbox or FakeToolbox(),
        gatherer_classes=classes or _classes(),
        spotlight_service=spotlight or SpotlightService(),
    )


# ===========================================================================
# Accumulation + gatherer construction
# ===========================================================================


def test_gather_called_once_per_run():
    """With N runs and no dry run, changed/new gather exactly N times each."""
    config = RunConfig(
        number_of_runs=2,
        noise_filter=False,
        network=False,
        processes=False,
        sockets=False,
        show_deleted=False,
        action=FakeAction(),
    )
    engine = _make_engine(config)
    engine.run()

    assert engine.gatherers["changed_files"].gather_calls == 2
    assert engine.gatherers["new_files"].gather_calls == 2


def test_changed_files_also_gathered_in_dry_run():
    """The dry run adds one extra ChangedFiles gather (noise measurement)."""
    config = RunConfig(
        number_of_runs=2,
        noise_filter=True,
        action=FakeAction(),
    )
    engine = _make_engine(config)
    engine.run()

    # run 0 + run 1 + dry run.
    assert engine.gatherers["changed_files"].gather_calls == 3
    assert engine.gatherers["new_files"].gather_calls == 2


def test_gatherers_not_constructed_with_path_bearing_config():
    """Gatherers get forensic_service + adb, never a path-bearing config."""
    config = RunConfig(number_of_runs=2, noise_filter=False, action=FakeAction())
    forensic = MagicMock()
    engine = _make_engine(config, forensic=forensic)
    engine.run()

    for key in ("changed_files", "new_files"):
        kwargs = engine.gatherers[key].init_kwargs
        assert "config" not in kwargs
        assert kwargs.get("forensic_service") is forensic
        assert "adb" in kwargs


def test_single_gatherer_instance_threaded_across_runs():
    """Only one instance of each gatherer class is ever created."""
    classes = _classes()
    config = RunConfig(number_of_runs=3, noise_filter=True, action=FakeAction())
    engine = _make_engine(config, classes=classes)
    engine.run()

    assert len(classes["changed_files"].instances) == 1
    assert len(classes["new_files"].instances) == 1


# ===========================================================================
# Events
# ===========================================================================


def test_gather_syncs_forensic_action_window_before_gathering():
    """GatherStep must sync forensic_service's action-time window immediately
    before invoking gather().

    ChangedFiles/NewFiles fetch via ``DataGatherBase._fetch_changed_files``,
    which calls ``forensic_service.fetch_changed_files()`` directly -- this
    never passes through ``Toolbox._fetch_changed_files``, the only place
    that used to call ``forensic_service.set_action_window(...)``. Without an
    explicit sync in GatherStep itself, the gatherer would scan against
    whatever window a *previous* run's PullStep last synced (or (0, 0) on the
    very first run), silently returning empty/wrong results while the
    separately-synced Pull that follows still pulls real file content. This
    exact split (empty ``RunResult.new_files``/``changed_files`` alongside a
    fully-populated pull directory) was found via on-device E2E testing.
    """
    forensic = MagicMock()
    action_window_service = ActionWindowService(adb=MagicMock())
    action_window_service.set_action_time(1_700_000_000)

    # _resolve_services() re-derives action_window_service from the
    # constructor arg at the top of run(), so it must be injected there
    # (not set on the engine instance afterwards, which would be clobbered).
    action = FakeAction(action_window_service=action_window_service, duration=7)
    config = RunConfig(number_of_runs=1, noise_filter=False, action=action)
    engine = AnalysisEngine(
        config,
        forensic_service=forensic,
        action_window_service=action_window_service,
        toolbox=FakeToolbox(),
        gatherer_classes=_classes(),
    )
    engine.run()

    forensic.set_action_window.assert_any_call(1_700_000_000, 7)


def test_gather_uses_this_analysis_duration_not_a_stale_prior_one():
    """A second top-level ``run()`` sharing one ``ActionWindowService`` must
    not reuse an earlier analysis's measured duration.

    ``ActionWindowService.set_duration`` is deliberately set-once *within* one
    analysis (so replay runs 2..N don't override the window the first replay
    established), but with no reset between *separate* analyses sharing the
    same (process-singleton, in production) service, a second analysis would
    otherwise silently scan with the first analysis's stale duration -- found
    via review of ``_reset_accumulators``, which resets other cross-analysis
    state but originally missed this one.
    """
    action_window_service = ActionWindowService(adb=MagicMock())

    # First analysis: a real action measures a 999s duration.
    forensic_1 = MagicMock()
    action_1 = FakeAction(action_window_service=action_window_service, duration=999)
    config_1 = RunConfig(number_of_runs=1, noise_filter=False, action=action_1)
    AnalysisEngine(
        config_1,
        forensic_service=forensic_1,
        action_window_service=action_window_service,
        toolbox=FakeToolbox(),
        gatherer_classes=_classes(),
    ).run()
    assert action_window_service.get_duration() == 999

    # Second analysis, same (shared) ActionWindowService: its own action
    # measures a *different*, shorter duration.
    forensic_2 = MagicMock()
    action_2 = FakeAction(action_window_service=action_window_service, duration=7)
    config_2 = RunConfig(number_of_runs=1, noise_filter=False, action=action_2)
    AnalysisEngine(
        config_2,
        forensic_service=forensic_2,
        action_window_service=action_window_service,
        toolbox=FakeToolbox(),
        gatherer_classes=_classes(),
    ).run()

    # The second analysis's own gathers must see its own duration (7), never
    # the first analysis's leftover 999.
    seen_durations = [c.args[1] for c in forensic_2.set_action_window.call_args_list]
    assert 999 not in seen_durations
    assert 7 in seen_durations


def test_reset_clears_whitelist_and_noise_caches_from_a_prior_analysis():
    """A second top-level ``run()`` sharing one ``ForensicService``/``Toolbox``
    must not inherit an earlier analysis's whitelist path or dry-run noise
    caches.

    ``ForensicService`` is the same process-wide singleton in production;
    ``ChangedFiles``/``Processes.process_data()`` apply whatever whitelist/
    noise state is currently set UNCONDITIONALLY, even when *this* analysis
    never configured a whitelist or ran its own dry run -- found via review
    of ``_reset_accumulators``, which originally reset other cross-analysis
    state (accumulators, then the stale-duration bug) but missed this one.
    """
    forensic = ForensicService()
    forensic.set_whitelist_path("/tmp/some-prior-analysis-whitelist.txt")
    toolbox = FakeToolbox()
    toolbox.noise_files = {"/data/prior/noise.db": "somehash"}
    toolbox.noise_processes = ["prior.noise.process"]

    config = RunConfig(number_of_runs=1, noise_filter=False, action=FakeAction())
    AnalysisEngine(
        config,
        forensic_service=forensic,
        action_window_service=ActionWindowService(adb=MagicMock()),
        toolbox=toolbox,
        gatherer_classes=_classes(),
    ).run()

    assert forensic.file_paths_whitelist == ""
    assert toolbox.noise_files == {}
    assert toolbox.noise_processes == []


def test_reset_does_not_clear_persistent_spotlight_watchlist():
    """Resetting cross-analysis state must not wipe the user's spotlight
    watchlist -- unlike whitelist/noise, it is persistent user configuration
    that must survive across analyses, not per-analysis state.
    """
    forensic = ForensicService()
    forensic.add_spotlight_files(["/sdcard/watched.txt"])

    config = RunConfig(number_of_runs=1, noise_filter=False, action=FakeAction())
    AnalysisEngine(
        config,
        forensic_service=forensic,
        action_window_service=ActionWindowService(adb=MagicMock()),
        toolbox=FakeToolbox(),
        gatherer_classes=_classes(),
    ).run()

    assert forensic.get_spotlight_files() == ["/sdcard/watched.txt"]


def test_analysis_events_published_with_engine_source():
    """AnalysisStarted + AnalysisCompleted publish, tagged source=analysis_engine."""
    EventBus.reset()
    events: list[Any] = []
    EventBus.get().subscribe(EventType.STATE_CHANGED, events.append)

    config = RunConfig(number_of_runs=2, noise_filter=False, action=FakeAction())
    _make_engine(config).run()

    engine_events = [e for e in events if e.source == EVENT_SOURCE]
    started = [e for e in engine_events if "modules" in e.data]
    completed = [e for e in engine_events if "files_changed" in e.data]

    assert started, "expected at least one AnalysisStarted from the engine"
    assert completed, "expected an AnalysisCompleted from the engine"
    # The completed event carries the real changed/new counts.
    assert completed[-1].data["files_changed"] == 1
    assert completed[-1].data["new_files"] == 1
    EventBus.reset()


def test_progress_callback_invoked_per_run():
    """The progress callback fires at run boundaries with run/total numbers."""
    updates: list[Any] = []
    config = RunConfig(number_of_runs=2, noise_filter=True, action=FakeAction())
    _make_engine(config, progress=updates.append).run()

    run_numbers = [u.run_number for u in updates]
    # Setup (0), run 1, run 2, dry run (3) all announced.
    assert 1 in run_numbers
    assert 2 in run_numbers
    assert all(u.total_runs == 2 for u in updates)


# ===========================================================================
# Per-step error isolation
# ===========================================================================


def test_non_fatal_step_failure_recorded_but_run_continues():
    """A gather that raises lands in per_step_errors; later gathers still run."""
    classes = _classes(nf_raise=True)
    config = RunConfig(number_of_runs=2, noise_filter=False, action=FakeAction())
    engine = _make_engine(config, classes=classes)
    result = engine.run()

    assert result.error is None  # non-fatal: the whole run does not abort
    assert result.per_step_errors, "the failing gather should be recorded"
    assert all(se.label.startswith("gather") for se in result.per_step_errors)
    # ChangedFiles (which precedes NewFiles in each run) still gathered N times.
    assert engine.gatherers["changed_files"].gather_calls == 2
    # NewFiles raised on each of its two attempts.
    assert len(result.per_step_errors) == 2


# ===========================================================================
# Device-stability guard
# ===========================================================================


def test_device_change_mid_run_aborts_with_partial_result():
    """A device switch mid-run raises FatalStepError -> partial RunResult."""
    toolbox = FakeToolbox(device_name="dev-A", flip_to="dev-B")
    config = RunConfig(
        number_of_runs=2,
        noise_filter=False,
        device_name="dev-A",
        action=FakeAction(),
    )
    engine = _make_engine(config, toolbox=toolbox)
    result = engine.run()

    assert result.error is not None
    assert "device" in result.error.lower()
    # The baseline fetch flipped the device; the first changed-files gather in
    # run 0 is guarded and never runs.
    assert engine.gatherers["changed_files"].gather_calls == 0
    assert result.device_name == "dev-A"


def test_stable_device_does_not_abort():
    """No device change -> no fatal error, gathers proceed normally."""
    toolbox = FakeToolbox(device_name="dev-A")
    config = RunConfig(
        number_of_runs=2,
        noise_filter=False,
        device_name="dev-A",
        action=FakeAction(),
    )
    engine = _make_engine(config, toolbox=toolbox)
    result = engine.run()

    assert result.error is None
    assert engine.gatherers["changed_files"].gather_calls == 2


# ===========================================================================
# Env-path pin
# ===========================================================================


def test_env_pin_trailing_sep_during_run_and_restored_after(monkeypatch, tmp_path):
    """RAW_RESULTS_PATH is pinned with a trailing sep during the run, restored after."""
    original = str(tmp_path / "session") + os.sep
    monkeypatch.setenv("RAW_RESULTS_PATH", original)
    monkeypatch.setenv("RESULTS_PATH", original)

    raw_dir = str(tmp_path / "bundle" / "raw")  # deliberately NO trailing sep
    config = RunConfig(
        number_of_runs=1,
        noise_filter=False,
        raw_results_path=raw_dir,
        results_path=str(tmp_path / "bundle"),
        action=FakeAction(),
    )
    engine = _make_engine(config)
    engine.run()

    # During the run, gather() saw the pinned value with exactly one trailing sep.
    seen = engine.gatherers["changed_files"].env_seen
    assert seen, "gather should have observed the env at least once"
    assert seen[0] == raw_dir + os.sep
    assert seen[0].endswith(os.sep)

    # After the run the original value is restored.
    assert os.environ["RAW_RESULTS_PATH"] == original
    assert os.environ["RESULTS_PATH"] == original


def test_empty_paths_leave_env_untouched(monkeypatch, tmp_path):
    """Empty path fields (CLI/headless) do not clobber the existing env value."""
    original = str(tmp_path / "session") + os.sep
    monkeypatch.setenv("RAW_RESULTS_PATH", original)

    config = RunConfig(
        number_of_runs=1,
        noise_filter=False,
        raw_results_path="",
        results_path="",
        action=FakeAction(),
    )
    engine = _make_engine(config)
    engine.run()

    seen = engine.gatherers["changed_files"].env_seen
    assert seen[0] == original  # identity pin: unchanged during the run
    assert os.environ["RAW_RESULTS_PATH"] == original


# ===========================================================================
# Pull semantics
# ===========================================================================


def test_pull_only_baseline_files_for_first_second_but_all_for_noise():
    """first/second pulls filter by baseline; noise pulls everything."""
    forensic = MagicMock()
    forensic.get_baseline.return_value = {"/data/a.db": "h"}  # /data/b.db is new
    toolbox = FakeToolbox(changed={"/data/a.db": 1, "/data/b.db": 2})
    config = RunConfig(number_of_runs=1, noise_filter=True, action=FakeAction())
    engine = _make_engine(config, toolbox=toolbox, forensic=forensic)
    engine.run()

    first = [f for slot, f in toolbox.pulled if slot == "first"]
    second = [f for slot, f in toolbox.pulled if slot == "second"]
    noise = [f for slot, f in toolbox.pulled if slot == "noise"]

    assert first == ["/data/a.db"]  # baseline-filtered
    assert second == ["/data/a.db"]  # baseline-filtered
    assert sorted(noise) == ["/data/a.db", "/data/b.db"]  # unfiltered


# ===========================================================================
# Finalize / Other Data
# ===========================================================================


def test_finalize_populates_list_wrapped_timeline_other_data():
    """The finalize submits list-wrapped Timeline Data into other_data."""
    # The shadow list is filled during the run (as the real timeline callback
    # does), because the engine resets it once at the start of run().
    toolbox = FakeToolbox(shadow_entry={"dir": "/data", "ts": 1})
    config = RunConfig(number_of_runs=1, noise_filter=False, action=FakeAction())
    engine = _make_engine(config, toolbox=toolbox)
    result = engine.run()

    assert "Timeline Data" in result.other_data
    # List-wrapped exactly like Toolbox.submit_other_data would produce.
    assert result.other_data["Timeline Data"] == [[{"dir": "/data", "ts": 1}]]


def test_whitelist_path_set_before_gathering():
    """When a whitelist path is configured the forensic service ends up
    pointed at it (after first being cleared by ``_reset_accumulators`` --
    see ``test_reset_clears_whitelist_and_noise_caches_from_a_prior_analysis``
    -- so this call happens twice: clear, then this analysis's real path).
    """
    forensic = MagicMock()
    config = RunConfig(
        number_of_runs=1,
        noise_filter=False,
        whitelist="/etc/whitelist.txt",
        action=FakeAction(),
    )
    engine = _make_engine(config, forensic=forensic)
    engine.run()

    forensic.set_whitelist_path.assert_called_with("/etc/whitelist.txt")
    assert forensic.set_whitelist_path.call_args_list[-1].args == (
        "/etc/whitelist.txt",
    )


def test_result_preserves_native_changed_files_shape():
    """changed_files is copied verbatim from the gatherer's return_data."""
    classes = _classes()
    classes["changed_files"] = make_fake_gatherer(
        {"Changed Files": [{"/data/a.db": ["- old", "+ new"]}, "/data/plain"]}
    )
    config = RunConfig(number_of_runs=1, noise_filter=False, action=FakeAction())
    engine = _make_engine(config, classes=classes)
    result = engine.run()

    assert result.changed_files == [{"/data/a.db": ["- old", "+ new"]}, "/data/plain"]


# ===========================================================================
# Phase-4 M3: post-replay settle time, applied to the dry run as well
# ===========================================================================


def _settle_run(monkeypatch, settle: int):
    """N=2 + dry run with a 16 s replay; return (settle waits, dry-run sleeps)."""
    import types

    from sandroid.analysis import engine as engine_module
    from sandroid.features import player as player_module

    action_window_service = ActionWindowService(adb=MagicMock())

    class _FakePlayer(player_module.Player):
        def perform(self, recording_path=None):
            action_window_service.set_duration(16)

    waits: list[float] = []
    monkeypatch.setattr(
        player_module,
        "_cancel_event",
        types.SimpleNamespace(wait=lambda s: waits.append(s) or False),
    )
    sleeps: list[float] = []
    monkeypatch.setattr(engine_module.time, "sleep", sleeps.append)
    monkeypatch.setattr(
        "sandroid.config.get_config",
        lambda: types.SimpleNamespace(
            analysis=types.SimpleNamespace(replay_settle_seconds=settle)
        ),
    )
    config = RunConfig(
        number_of_runs=2, noise_filter=True, action=_FakePlayer(recording_path="x")
    )
    result = AnalysisEngine(
        config,
        forensic_service=MagicMock(),
        action_window_service=action_window_service,
        toolbox=FakeToolbox(),
        gatherer_classes=_classes(),
    ).run()
    return waits, sleeps, result


def test_replay_settle_extends_every_replay_and_the_dry_run(monkeypatch):
    waits, sleeps, result = _settle_run(monkeypatch, settle=5)

    assert waits == [5, 5]  # after each of the two replays
    assert sleeps == [21]  # dry run: replay (16 s) + settle (5 s)
    assert result.action_duration == 21


def test_zero_settle_keeps_the_replay_window(monkeypatch):
    waits, sleeps, result = _settle_run(monkeypatch, settle=0)

    assert waits == []
    assert sleeps == [16]
    assert result.action_duration == 16


def test_settle_seconds_default_is_in_schema_and_default_toml():
    import tomllib
    from pathlib import Path

    from sandroid.config.schema import AnalysisConfig

    assert AnalysisConfig().replay_settle_seconds == 8
    default = Path(__file__).resolve().parents[2] / "src/sandroid/config/default.toml"
    data = tomllib.loads(default.read_text())
    assert data["analysis"]["replay_settle_seconds"] == 8


def test_dry_run_start_and_end_are_logged(monkeypatch, caplog):
    """Headless only has the log: the dry run must show up there (phase 4)."""
    import logging

    caplog.set_level(logging.INFO, logger="sandroid.analysis.engine")
    _settle_run(monkeypatch, settle=5)

    messages = [r.getMessage() for r in caplog.records]
    begin = "Dry run: measuring background noise (snapshot state, no replay)"
    sleep = "Dry run: capturing for 21s, as long as one action run"
    end = "Dry run finished (noise baseline captured)"
    assert messages.index(begin) < messages.index(sleep) < messages.index(end)


# ===========================================================================
# Phase-5 N1: network reset after every snapshot load before a window
# ===========================================================================


def test_plan_resets_network_before_every_replay_and_the_dry_run():
    from sandroid.analysis.engine import AnalysisPlan, LoadSnapshotStep

    gatherers = {k: object() for k in ("changed_files", "new_files")}
    for runs, noise, expected in (
        (2, True, [True, True, True]),  # pre, before run 2, before dry run
        (2, False, [True, True, False]),  # last load has nothing after it
        (3, True, [True, True, True, True]),
        (1, True, [True, True]),  # pre, before dry run
        (1, False, [True, False]),
    ):
        config = RunConfig(number_of_runs=runs, noise_filter=noise, action=FakeAction())
        loads = [
            s
            for s in AnalysisPlan.build(config, gatherers)
            if isinstance(s, LoadSnapshotStep)
        ]
        assert [s.reset_network for s in loads] == expected, (runs, noise)


class _ResettingToolbox(FakeToolbox):
    def __init__(self) -> None:
        super().__init__()
        self.events: list[str] = []
        self.modes: list[str] = []

    def load_snapshot(self, name: Any) -> None:
        super().load_snapshot(name)
        self.events.append("load")

    def reset_network(self, mode: str = "airplane", sleep: Any = None) -> bool:
        self.events.append("reset")
        self.modes.append(mode)
        return True


def _reset_config(monkeypatch, mode: str) -> None:
    import types

    monkeypatch.setattr(
        "sandroid.config.get_config",
        lambda: types.SimpleNamespace(
            analysis=types.SimpleNamespace(
                network_reset_after_snapshot=mode, replay_settle_seconds=0
            )
        ),
    )


def test_engine_resets_network_after_loads_with_configured_mode(monkeypatch):
    _reset_config(monkeypatch, "svc")
    toolbox = _ResettingToolbox()
    config = RunConfig(number_of_runs=2, noise_filter=True, action=FakeAction())
    result = _make_engine(config, toolbox=toolbox).run()

    assert result.error is None
    assert toolbox.events == ["load", "reset"] * 3
    assert toolbox.modes == ["svc"] * 3


def test_engine_network_reset_off_and_failures_are_not_fatal(monkeypatch):
    _reset_config(monkeypatch, "off")
    toolbox = _ResettingToolbox()
    config = RunConfig(number_of_runs=2, noise_filter=True, action=FakeAction())
    _make_engine(config, toolbox=toolbox).run()
    assert "reset" not in toolbox.events

    _reset_config(monkeypatch, "airplane")

    class _Broken(_ResettingToolbox):
        def reset_network(self, mode: str = "airplane", sleep: Any = None) -> bool:
            raise RuntimeError("adb gone")

    result = _make_engine(config, toolbox=_Broken()).run()
    assert result.error is None


def test_network_reset_default_is_in_schema_and_default_toml():
    import tomllib
    from pathlib import Path

    from sandroid.config.schema import AnalysisConfig

    assert AnalysisConfig().network_reset_after_snapshot == "airplane"
    default = Path(__file__).resolve().parents[2] / "src/sandroid/config/default.toml"
    data = tomllib.loads(default.read_text())
    assert data["analysis"]["network_reset_after_snapshot"] == "airplane"


# ===========================================================================
# Session timeline: phases
# ===========================================================================


def test_the_engine_writes_its_phases_and_restores_the_one_it_found():
    """Each step's window maps to a phase (replay / dry-run / setup), one
    ``run/phase`` line per change, stamped with the run id; afterwards the
    phase the run found is back.
    """
    import itertools

    from sandroid.core import timeline

    config = RunConfig(number_of_runs=2, noise_filter=True, action=FakeAction())
    config.run_id = "run-7"
    with timeline.capture() as lines:
        service = timeline.get_timeline()
        service.set_phase("live", "run-7", kind="play-start")
        _make_engine(config).run()
        assert service.current_phase() == ("live", "run-7")
    phases = [x for x in lines if x["kind"] == "phase"]
    order = [x["data"]["to"] for x in phases]
    assert order[0] == "setup"
    assert "replay" in order
    assert "dry-run" in order
    assert order[-1] == "live"  # restored
    for previous, line in itertools.pairwise(phases):
        assert line["data"]["from"] == previous["data"]["to"]  # only changes
    replay = next(x for x in phases if x["data"]["to"] == "replay")
    assert (replay["phase"], replay["run"], replay["actor"]) == (
        "replay",
        "run-7",
        "sandroid",
    )
    assert replay["data"]["of"] == 2
    assert replay["data"]["replay"] in (1, 2)
    assert replay["data"]["step"]


def test_run_config_carries_an_optional_run_id():
    assert RunConfig().run_id is None
    assert RunConfig(run_id="r1").run_id == "r1"


# ===========================================================================
# Device time unreadable (E2E: "device still authorizing" after a load)
# ===========================================================================


class _NoClockToolbox(FakeToolbox):
    """``set_action_time`` fails ``fails`` times with ``DeviceTimeError``."""

    def __init__(self, fails: int, **kw: Any) -> None:
        super().__init__(**kw)
        self.fails = fails

    def set_action_time(self) -> None:
        from sandroid.core.exceptions import DeviceTimeError

        super().set_action_time()
        if self.action_times_set <= self.fails:
            raise DeviceTimeError("adb: device still authorizing")


def test_dry_run_retries_the_device_time_after_the_snapshot_load(monkeypatch):
    from sandroid.features import player as player_module

    monkeypatch.setattr(player_module, "ACTION_TIME_RETRY_S", 0.0)
    toolbox = _NoClockToolbox(fails=2)
    config = RunConfig(number_of_runs=1, noise_filter=True, action=FakeAction())
    result = _make_engine(config, toolbox=toolbox).run()
    assert result.error is None
    assert toolbox.action_times_set == 3


def test_an_unreadable_device_time_ends_the_run_with_an_error(monkeypatch):
    """Never ``SystemExit`` (it ended the TUI); never a silently stale window."""
    from sandroid.core.exceptions import DeviceTimeError
    from sandroid.features import player as player_module

    monkeypatch.setattr(player_module, "ACTION_TIME_RETRY_S", 0.0)

    class _ClockAction(FakeAction):  # e.g. TrigDroid / manual capture
        def perform(self) -> None:
            raise DeviceTimeError("adb: device still authorizing")

    config = RunConfig(number_of_runs=2, noise_filter=False, action=_ClockAction())
    engine = _make_engine(config)
    result = engine.run()
    assert "authorizing" in (result.error or "")
    assert engine.gatherers["changed_files"].gather_calls == 0

    toolbox = _NoClockToolbox(fails=99)
    config = RunConfig(number_of_runs=1, noise_filter=True, action=FakeAction())
    result = _make_engine(config, toolbox=toolbox).run()
    assert "Device not ready" in (result.error or "")
