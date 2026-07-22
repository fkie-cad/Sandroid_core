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
) -> AnalysisEngine:
    """Construct an engine wired to injected fakes + a real ActionWindowService."""
    return AnalysisEngine(
        config,
        progress=progress,
        forensic_service=forensic or MagicMock(),
        action_window_service=ActionWindowService(adb=MagicMock()),
        toolbox=toolbox or FakeToolbox(),
        gatherer_classes=classes or _classes(),
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
