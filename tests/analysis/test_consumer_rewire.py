"""Device-free tests for the CLI + headless-API rewire onto ``AnalysisEngine``.

These cover the three consumers rewired in Part 1 without touching a device:

* the CLI-automated path (``cli_modes/analysis.run_analysis``) writes the
  engine's ``RunResult.to_json_dict()`` to the results file,
* the headless malware/forensic runners return that dict (forensic still
  carrying its ``analysis_type``/``runs`` metadata), and
* ``RunConfig.from_analysis_config`` threads the new ``AnalysisConfig.whitelist``
  field through.

``AnalysisEngine.run`` is monkeypatched to a canned :class:`RunResult` so no
snapshot/adb/device work happens; every other collaborator is a lightweight
fake or a monkeypatched service accessor.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import MagicMock

import sandroid.cli_modes.analysis as cli_analysis
from sandroid.analysis.engine import AnalysisEngine
from sandroid.analysis.run_config import ProgressUpdate, RunConfig, RunResult
from sandroid.api import analysis_runners
from sandroid.api.interfaces import AnalysisConfig
from sandroid.config.schema import SandroidConfig
from sandroid.core.json_utils import json_encoder


def _canned_result() -> RunResult:
    """A representative RunResult exercising every to_json_dict key."""
    return RunResult(
        device_name="emu-test",
        action_time=42,
        action_duration=7,
        changed_files=[{"/data/a.db": ["- old", "+ new"]}, "/data/plain.txt"],
        new_files=["/data/new.txt"],
        deleted_files=["/data/gone.txt"],
        processes=["1234 com.example"],
        sockets=["tcp 0.0.0.0:8080"],
        network_dns=["example.com"],
        network_targets=["1.2.3.4:443"],
        other_data={"Timeline Data": [[{"dir": "/data", "ts": 1}]]},
        pretty_text="PRETTY-PRINT-OUTPUT",
    )


class _FakeToolbox:
    """Minimal Toolbox surface the rewired consumers touch."""

    args: Any = None

    def __init__(self) -> None:
        self.snapshots: list[bytes] = []

    def create_snapshot(self, name: bytes) -> None:
        self.snapshots.append(name)

    def get_tools_used(self) -> dict[str, Any]:
        return {}


# ===========================================================================
# (c) from_analysis_config maps whitelist
# ===========================================================================


def test_from_analysis_config_maps_whitelist():
    """The new AnalysisConfig.whitelist field threads into the RunConfig."""
    ac = AnalysisConfig(whitelist="/etc/whitelist.txt")
    assert ac.whitelist == "/etc/whitelist.txt"

    run_config = RunConfig.from_analysis_config(ac, whitelist=ac.whitelist)
    assert run_config.whitelist == "/etc/whitelist.txt"


def test_analysis_config_whitelist_defaults_none():
    """The whitelist field defaults to None (whitelisting disabled)."""
    assert AnalysisConfig().whitelist is None


# ===========================================================================
# (a) CLI-automated path writes to_json_dict() to the results file
# ===========================================================================


def test_cli_run_analysis_writes_to_json_dict(monkeypatch, tmp_path):
    """The CLI path reaches the engine and writes to_json_dict() to the file."""
    canned = _canned_result()

    # Engine.run -> canned result (no device work).
    monkeypatch.setattr(AnalysisEngine, "run", lambda self: canned)

    # Stub the setup/service accessors the CLI path calls.
    from sandroid.core import initializer

    monkeypatch.setattr(initializer, "initialize_core", lambda cfg: None)

    setup_service = MagicMock()
    setup_service.check_critical_setup.return_value = MagicMock(success=True)
    monkeypatch.setattr(cli_analysis, "get_setup_service", lambda: setup_service)

    spotlight = MagicMock()
    task_service = MagicMock()
    ui_service = MagicMock()
    monkeypatch.setattr(cli_analysis, "get_spotlight_service", lambda: spotlight)
    monkeypatch.setattr(cli_analysis, "get_task_service", lambda: task_service)
    monkeypatch.setattr(cli_analysis, "get_ui_service", lambda: ui_service)

    config = SandroidConfig(
        paths={
            "results_path": tmp_path,
            "raw_results_path": tmp_path / "raw",
        },
        trigdroid={"package_name": "com.example.app"},
        report={"generate_pdf": False},
    )

    toolbox = _FakeToolbox()
    adb = MagicMock()

    cli_analysis.run_analysis(
        config,
        MagicMock(),  # active_logger
        toolbox,
        adb,
        MagicMock(),  # ActionQ (unused now)
        MagicMock(),  # PDFReport (report disabled)
    )

    # The tmp snapshot the engine reverts to was created before the run.
    assert b"tmp" in toolbox.snapshots
    # Spotlight was pointed at the target package in spawn mode.
    spotlight.set_spawn_app.assert_called_once_with("com.example.app", auto_resume=True)
    # Network was reset (degrade_network defaults off).
    assert adb.send_telnet_command.call_count == 2

    # The results file holds exactly the serialized to_json_dict().
    output_file = tmp_path / "sandroid.json"
    assert output_file.exists()
    written = json.loads(output_file.read_text(encoding="utf-8"))
    expected = json.loads(json.dumps(canned.to_json_dict(), default=json_encoder))
    assert written == expected
    assert written["Device Name"] == "emu-test"
    assert written["Changed Files"] == [
        {"/data/a.db": ["- old", "+ new"]},
        "/data/plain.txt",
    ]
    assert written["Other Data"] == {"Timeline Data": [[{"dir": "/data", "ts": 1}]]}


# ===========================================================================
# (b) headless malware/forensic return the expected dict
# ===========================================================================


def test_headless_malware_returns_engine_dict(monkeypatch):
    """run_malware_analysis returns the JSON-safe to_json_dict() of the run."""
    canned = _canned_result()
    monkeypatch.setattr(AnalysisEngine, "run", lambda self: canned)
    monkeypatch.setattr(analysis_runners, "_apply_network_degradation", lambda d: None)

    spotlight = MagicMock()
    from sandroid import services

    monkeypatch.setattr(services, "get_spotlight_service", lambda: spotlight)

    toolbox = _FakeToolbox()

    result = asyncio.run(
        analysis_runners.run_malware_analysis(
            toolbox=toolbox,
            package="com.evil.app",
            runs=2,
            capture_network=True,
            compute_hashes=False,
        )
    )

    spotlight.set_spawn_app.assert_called_once_with("com.evil.app", auto_resume=True)
    assert b"tmp" in toolbox.snapshots

    expected = json.loads(json.dumps(canned.to_json_dict(), default=json_encoder))
    assert result == expected
    assert result["Device Name"] == "emu-test"
    assert result["New Files"] == ["/data/new.txt"]


def test_headless_forensic_returns_engine_dict_with_metadata(monkeypatch):
    """run_forensic_analysis returns the unified dict + analysis_type/runs."""
    canned = _canned_result()
    monkeypatch.setattr(AnalysisEngine, "run", lambda self: canned)

    toolbox = _FakeToolbox()

    result = asyncio.run(
        analysis_runners.run_forensic_analysis(
            toolbox=toolbox,
            runs=3,
            track_deleted=True,
            compute_hashes=False,
        )
    )

    assert b"tmp" in toolbox.snapshots
    # Legacy metadata keys preserved.
    assert result["analysis_type"] == "forensic"
    assert result["runs"] == 3
    # Unified to_json_dict shape merged in.
    assert result["Changed Files"] == [
        {"/data/a.db": ["- old", "+ new"]},
        "/data/plain.txt",
    ]
    assert result["Deleted Files"] == ["/data/gone.txt"]


def test_headless_forensic_action_is_none(monkeypatch):
    """The forensic run builds an action-less RunConfig (pure forensic)."""
    captured: dict[str, Any] = {}

    def _capture_init(self, config, **kwargs):
        captured["config"] = config
        captured["progress"] = kwargs.get("progress")

    monkeypatch.setattr(AnalysisEngine, "__init__", _capture_init)
    monkeypatch.setattr(AnalysisEngine, "run", lambda self: _canned_result())

    asyncio.run(
        analysis_runners.run_forensic_analysis(
            toolbox=_FakeToolbox(),
            runs=2,
            track_deleted=False,
            compute_hashes=False,
            whitelist="/etc/wl.txt",
        )
    )

    run_config = captured["config"]
    assert run_config.action is None
    assert run_config.recording_path is None
    # Identity pin for the headless (bundle-less) path.
    assert run_config.results_path == ""
    assert run_config.raw_results_path == ""
    # Whitelist threaded through from the kwarg.
    assert run_config.whitelist == "/etc/wl.txt"


# ===========================================================================
# Progress adapter
# ===========================================================================


def test_progress_adapter_clamps_and_skips_setup():
    """The adapter forwards clamped 1-based run numbers, ignoring setup (0)."""
    seen: list[int] = []
    adapter = analysis_runners._make_progress_adapter(seen.append, runs=2)

    adapter(ProgressUpdate(run_number=0, total_runs=2, label="Setup"))  # skipped
    adapter(ProgressUpdate(run_number=1, total_runs=2, label="Run 1/2"))
    adapter(ProgressUpdate(run_number=2, total_runs=2, label="Run 2/2"))
    adapter(ProgressUpdate(run_number=3, total_runs=2, label="Dry run"))  # clamped

    assert seen == [1, 2, 2]


def test_progress_adapter_tolerates_no_setter():
    """A None setter is a safe no-op."""
    adapter = analysis_runners._make_progress_adapter(None, runs=2)
    adapter(ProgressUpdate(run_number=1, total_runs=2, label="Run 1/2"))
