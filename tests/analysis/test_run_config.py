"""Tests for ``sandroid.analysis.run_config`` dataclasses."""

from __future__ import annotations

from sandroid.analysis.run_config import (
    ProgressUpdate,
    RunConfig,
    RunResult,
    StepError,
)
from sandroid.api.interfaces import AnalysisConfig
from sandroid.config.schema import AnalysisConfig as SchemaAnalysisConfig
from sandroid.config.schema import EmulatorConfig, PathConfig, SandroidConfig


# ---------------------------------------------------------------------------
# RunConfig.from_sandroid_config
# ---------------------------------------------------------------------------
def test_from_sandroid_config_defaults_map_correctly():
    """Default SandroidConfig maps to the expected RunConfig fields."""
    cfg = SandroidConfig()
    rc = RunConfig.from_sandroid_config(cfg)

    assert rc.number_of_runs == cfg.analysis.number_of_runs
    # Default avoid_strong_noise_filter=False -> noise_filter=True.
    assert rc.noise_filter is True
    assert rc.network == cfg.analysis.capture_network
    assert rc.processes == cfg.analysis.capture_processes
    assert rc.sockets == cfg.analysis.capture_sockets
    assert rc.show_deleted == cfg.analysis.show_deleted_files
    assert rc.hash_files == cfg.analysis.hash_files
    assert rc.pull_apk == cfg.analysis.list_apks
    assert rc.screenshot_interval == cfg.analysis.screenshot_interval
    assert rc.whitelist is None
    assert rc.results_path == str(cfg.paths.results_path)
    assert rc.raw_results_path == str(cfg.paths.raw_results_path)
    assert rc.device_name == cfg.emulator.device_name
    assert rc.action is None
    assert rc.recording_path is None


def test_from_sandroid_config_noise_filter_inversion():
    """avoid_strong_noise_filter=True inverts to noise_filter=False (and back)."""
    cfg_avoid = SandroidConfig(
        analysis=SchemaAnalysisConfig(avoid_strong_noise_filter=True)
    )
    assert RunConfig.from_sandroid_config(cfg_avoid).noise_filter is False

    cfg_keep = SandroidConfig(
        analysis=SchemaAnalysisConfig(avoid_strong_noise_filter=False)
    )
    assert RunConfig.from_sandroid_config(cfg_keep).noise_filter is True


def test_from_sandroid_config_non_default_fields():
    """Non-default analysis/path/emulator fields propagate through."""
    cfg = SandroidConfig(
        whitelist_file="/tmp/whitelist.txt",
        analysis=SchemaAnalysisConfig(
            number_of_runs=5,
            capture_network=True,
            capture_processes=False,
            capture_sockets=True,
            show_deleted_files=True,
            hash_files=True,
            list_apks=True,
            screenshot_interval=7,
        ),
        paths=PathConfig(
            results_path="/tmp/results", raw_results_path="/tmp/results/raw"
        ),
        emulator=EmulatorConfig(device_name="Pixel_Test_API_35"),
    )
    rc = RunConfig.from_sandroid_config(cfg)

    assert rc.number_of_runs == 5
    assert rc.network is True
    assert rc.processes is False
    assert rc.sockets is True
    assert rc.show_deleted is True
    assert rc.hash_files is True
    assert rc.pull_apk is True
    assert rc.screenshot_interval == 7
    # whitelist carries the file path as a string.
    assert rc.whitelist == "/tmp/whitelist.txt"
    assert rc.results_path == str(cfg.paths.results_path)
    assert rc.raw_results_path == str(cfg.paths.raw_results_path)
    assert rc.device_name == "Pixel_Test_API_35"


def test_from_sandroid_config_passes_action_and_recording_path():
    """action/recording_path keyword params are stored verbatim."""

    class _FakeAction:
        def perform(self) -> None:  # pragma: no cover - trivial stub
            pass

    action = _FakeAction()
    rc = RunConfig.from_sandroid_config(
        SandroidConfig(), action=action, recording_path="/abs/rec.txt"
    )
    assert rc.action is action
    assert rc.recording_path == "/abs/rec.txt"


# ---------------------------------------------------------------------------
# RunConfig.from_analysis_config
# ---------------------------------------------------------------------------
def test_from_analysis_config_dry_run_maps_to_noise_filter():
    """dry_run maps directly onto noise_filter."""
    assert RunConfig.from_analysis_config(AnalysisConfig(dry_run=True)).noise_filter
    assert not RunConfig.from_analysis_config(
        AnalysisConfig(dry_run=False)
    ).noise_filter


def test_from_analysis_config_field_maps():
    """Monitor toggles and counts map from AnalysisConfig."""
    ac = AnalysisConfig(
        number_of_runs=3,
        capture_network=True,
        capture_processes=False,
        capture_sockets=True,
        show_deleted=True,
        hash_files=True,
        pull_apk=True,
        dry_run=True,
    )
    rc = RunConfig.from_analysis_config(ac, whitelist=["a", "b"])

    assert rc.number_of_runs == 3
    assert rc.network is True
    assert rc.processes is False
    assert rc.sockets is True
    assert rc.show_deleted is True
    assert rc.hash_files is True
    assert rc.pull_apk is True
    assert rc.noise_filter is True
    assert rc.whitelist == ["a", "b"]


def test_from_analysis_config_screenshot_gated_by_take_screenshots():
    """screenshot_interval is None unless take_screenshots is set."""
    off = RunConfig.from_analysis_config(
        AnalysisConfig(take_screenshots=False, screenshot_interval=9)
    )
    assert off.screenshot_interval is None

    on = RunConfig.from_analysis_config(
        AnalysisConfig(take_screenshots=True, screenshot_interval=9)
    )
    assert on.screenshot_interval == 9


# ---------------------------------------------------------------------------
# RunConfig.for_playback
# ---------------------------------------------------------------------------
def test_for_playback_defaults_and_no_action():
    """for_playback sets recording_path and leaves action None (engine builds it)."""
    rc = RunConfig.for_playback(recording_path="/abs/bundle/recording.txt")
    assert rc.recording_path == "/abs/bundle/recording.txt"
    assert rc.action is None
    assert rc.number_of_runs == 2
    assert rc.noise_filter is True
    assert rc.show_deleted is True
    assert rc.network is False
    assert rc.processes is False
    assert rc.sockets is False
    assert rc.hash_files is False


# ---------------------------------------------------------------------------
# RunResult.to_json_dict
# ---------------------------------------------------------------------------
def test_to_json_dict_exact_legacy_key_set():
    """to_json_dict returns exactly the legacy get_data() key names."""
    result = RunResult(device_name="dev")
    keys = set(result.to_json_dict().keys())
    assert keys == {
        "Device Name",
        "Emulator relative action timestamp",
        "Action Duration",
        "Changed Files",
        "New Files",
        "Deleted Files",
        "Processes",
        "Listening Sockets",
        "Network",
        "Network IP:Port (send/recv)",
        "Other Data",
    }


def test_to_json_dict_preserves_native_shapes_and_wrapped_other_data():
    """Native changed_files shape and list-wrapped Other Data survive verbatim."""
    changed = {"/data/data/app/db.sqlite": ["- old row", "+ new row"]}
    other = {
        "Artifact Hashes": [{"/f": "abc123"}],
        "APK Hashes": [{"base.apk": "deadbeef"}],
        "Timeline Data": [[{"t": 1, "event": "x"}]],
    }
    result = RunResult(
        device_name="Pixel_6_API_33",
        action_time=42,
        action_duration=7,
        changed_files=changed,
        new_files=["/data/new.txt"],
        deleted_files=["/data/gone.txt"],
        processes=["1234 com.example"],
        sockets=["tcp 0.0.0.0:5555"],
        network_dns=["example.com"],
        network_targets=["1.2.3.4:443"],
        other_data=other,
    )
    d = result.to_json_dict()

    assert d["Device Name"] == "Pixel_6_API_33"
    assert d["Emulator relative action timestamp"] == 42
    assert d["Action Duration"] == 7
    # changed_files kept as the native {file: [diff_lines]} dict.
    assert d["Changed Files"] == changed
    assert d["Changed Files"]["/data/data/app/db.sqlite"] == ["- old row", "+ new row"]
    assert d["New Files"] == ["/data/new.txt"]
    assert d["Deleted Files"] == ["/data/gone.txt"]
    assert d["Processes"] == ["1234 com.example"]
    assert d["Listening Sockets"] == ["tcp 0.0.0.0:5555"]
    assert d["Network"] == ["example.com"]
    assert d["Network IP:Port (send/recv)"] == ["1.2.3.4:443"]
    # Other Data preserved with its list-wrapped sub-values ([0]-indexable).
    assert d["Other Data"] == other
    assert d["Other Data"]["Artifact Hashes"][0] == {"/f": "abc123"}
    assert d["Other Data"]["Timeline Data"][0] == [{"t": 1, "event": "x"}]


def test_to_json_dict_changed_files_string_shape():
    """changed_files may also be the legacy bare-string shape; kept verbatim."""
    result = RunResult(device_name="dev", changed_files="ITS ALL NOISE")
    assert result.to_json_dict()["Changed Files"] == "ITS ALL NOISE"


def test_run_result_pretty_print_returns_pretty_text():
    """pretty_print returns the engine-filled pretty_text."""
    assert RunResult(device_name="d", pretty_text="hello").pretty_print() == "hello"


# ---------------------------------------------------------------------------
# StepError / ProgressUpdate
# ---------------------------------------------------------------------------
def test_step_error_fields():
    """StepError stores label/run_number/error."""
    err = StepError(label="Gather", run_number=2, error="boom")
    assert (err.label, err.run_number, err.error) == ("Gather", 2, "boom")


def test_progress_update_defaults():
    """ProgressUpdate message defaults to empty string."""
    pu = ProgressUpdate(run_number=1, total_runs=2, label="Baseline")
    assert pu.message == ""
    assert (pu.run_number, pu.total_runs, pu.label) == (1, 2, "Baseline")
