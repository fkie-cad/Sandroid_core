"""Device-free regression tests for the 2.1 analysis-pipeline fixes.

Covers:

* the changed-files cache being populated by ``GatherStep`` *before* the
  snapshot revert, so ``PullStep("first")`` pulls the pre-action versions
  (``raw/first_pull`` used to stay empty -> no intra-file diffs),
* ``LoadSnapshotStep`` aborting the run when the revert fails,
* ``EmulatorService`` treating the console's ``KO:`` replies as failures,
* the N=1 plan capturing network/processes/sockets,
* ``Processes``/``Sockets`` stoppable, joined polling + noise heuristics,
* ``Network`` pcap discovery / parsing (TCP SYN, UDP, missing noise pcap),
* ``RunConfig.for_playback`` honouring the ``[analysis]`` config toggles.
"""

from __future__ import annotations

import threading
import time
from typing import Any
from unittest.mock import MagicMock

import pytest

from sandroid.analysis import run_config as run_config_module
from sandroid.analysis.engine import (
    AnalysisEngine,
    AnalysisPlan,
    EngineContext,
    LoadSnapshotStep,
)
from sandroid.analysis.run_config import RunConfig
from sandroid.services.action_window_service import ActionWindowService

# ===========================================================================
# Changed-files cache across the snapshot revert
# ===========================================================================


class CachingToolbox:
    """Fake toolbox reproducing the real ``Toolbox`` cache semantics.

    ``fetch_changed_files()`` lists the "device" only when the action-window
    cache is not populated; ``set_action_time()`` clears it (as
    ``ActionWindowService.set_action_time_from_device`` does). The device state
    is reverted by ``load_snapshot``: a rescan after the revert finds nothing
    inside the action window -- exactly the on-device behaviour that left
    ``raw/first_pull`` empty.
    """

    device_name = "emu-1"

    def __init__(self, files_changed_by_action: dict[str, int]) -> None:
        self._action_files = files_changed_by_action
        self._device_changed: dict[str, int] = {}
        self._cache: dict[str, int] | None = None
        self.scans = 0
        self.pulled: list[tuple[str, str]] = []
        self.other_output_data_collector: dict[str, Any] = {}
        self._timestamps_shadow_dict_list: list[Any] = []

    # -- action / snapshot ------------------------------------------------
    def perform_action(self) -> None:
        self.set_action_time()
        self._device_changed = dict(self._action_files)

    def set_action_time(self) -> None:
        self._cache = None

    def load_snapshot(self, name: Any) -> bool:
        self._device_changed = {}
        return True

    # -- forensic surface -------------------------------------------------
    def fetch_changed_files(self, fetch_all: bool = False) -> dict[str, int]:
        if fetch_all:
            return {"/data/base.db": 1, "/data/app/GroundTruth.db": 1}
        if self._cache is None:
            self.scans += 1
            self._cache = dict(self._device_changed)
        return dict(self._cache)

    def pull_file(self, slot: str, file_to_pull: str) -> None:
        self.pulled.append((slot, file_to_pull))

    def submit_other_data(self, identifier: str, data: Any) -> None:
        self.other_output_data_collector.setdefault(identifier, []).append(data)


class _Action:
    def __init__(self, toolbox: CachingToolbox, aws: ActionWindowService) -> None:
        self._toolbox = toolbox
        self._aws = aws

    def perform(self) -> None:
        self._toolbox.perform_action()
        self._aws.set_duration(5)


class _NoopGatherer:
    def __init__(self, **kwargs: Any) -> None:
        pass

    def gather(self) -> None:
        pass

    def return_data(self) -> dict[str, Any]:
        return {}

    def pretty_print(self) -> str:
        return ""


def _noop_classes() -> dict[str, type]:
    return dict.fromkeys(
        (
            "changed_files",
            "new_files",
            "deleted_files",
            "network",
            "processes",
            "sockets",
        ),
        _NoopGatherer,
    )


@pytest.mark.parametrize("runs", [1, 2, 3])
def test_first_pull_uses_pre_revert_changed_list(runs: int) -> None:
    """``PullStep("first")`` after the revert pulls the files the action changed."""
    changed = {"/data/app/GroundTruth.db": 100}
    toolbox = CachingToolbox(changed)
    aws = ActionWindowService(adb=MagicMock())
    config = RunConfig(
        number_of_runs=runs,
        noise_filter=False,
        processes=False,
        action=_Action(toolbox, aws),
    )
    forensic = MagicMock()
    forensic.get_baseline.return_value = {"/data/app/GroundTruth.db": 1}
    AnalysisEngine(
        config,
        forensic_service=forensic,
        action_window_service=aws,
        toolbox=toolbox,
        gatherer_classes=_noop_classes(),
    ).run()

    assert ("first", "/data/app/GroundTruth.db") in toolbox.pulled
    assert ("second", "/data/app/GroundTruth.db") in toolbox.pulled
    # One filesystem scan per replay (the gatherers + pulls share it).
    assert toolbox.scans == runs


def test_load_snapshot_failure_is_fatal() -> None:
    """A failed revert aborts the run instead of producing bogus diffs."""
    toolbox = MagicMock()
    toolbox.load_snapshot.return_value = False
    ctx = EngineContext(
        config=RunConfig(),
        toolbox=toolbox,
        forensic_service=MagicMock(),
        action_window_service=MagicMock(),
    )
    from sandroid.analysis.engine import FatalStepError

    with pytest.raises(FatalStepError):
        LoadSnapshotStep().run(ctx)

    toolbox.load_snapshot.return_value = None  # legacy toolboxes: not fatal
    LoadSnapshotStep().run(ctx)


def test_engine_reports_failed_snapshot_as_error() -> None:
    toolbox = CachingToolbox({})
    toolbox.load_snapshot = lambda name: False  # type: ignore[method-assign]
    result = AnalysisEngine(
        RunConfig(number_of_runs=2, noise_filter=False, processes=False),
        forensic_service=MagicMock(),
        action_window_service=ActionWindowService(adb=MagicMock()),
        toolbox=toolbox,
        gatherer_classes=_noop_classes(),
    ).run()
    assert result.error
    assert "snapshot" in result.error


# ===========================================================================
# EmulatorService KO handling
# ===========================================================================


@pytest.mark.parametrize("method", ["load_snapshot", "create_snapshot"])
def test_emulator_service_snapshot_ko_is_failure(method: str) -> None:
    from sandroid.services.emulator_service import EmulatorService

    adb = MagicMock()
    adb.send_telnet_command.return_value = (
        "KO: Snapshot load failure: snapshot doesn't exist\n",
        "",
    )
    service = EmulatorService(adb=adb)
    assert getattr(service, method)("tmp") is False


# ===========================================================================
# Plan: N=1 captures
# ===========================================================================


def test_n1_plan_captures_around_the_action() -> None:
    config = RunConfig(
        number_of_runs=1,
        noise_filter=False,
        network=True,
        processes=True,
        sockets=False,
        action=MagicMock(),
    )
    gatherers = {
        k: object() for k in ("changed_files", "new_files", "network", "processes")
    }
    kinds = [s.kind for s in AnalysisPlan.build(config, gatherers)]
    assert kinds[:7] == [
        "load_snapshot",
        "baseline",
        "start_capture",
        "start_capture",
        "action",
        "stop_capture",
        "stop_capture",
    ]


# ===========================================================================
# Processes / Sockets polling
# ===========================================================================


class _PollToolbox:
    def __init__(self, duration: int, dry: bool = False) -> None:
        self._duration = duration
        self._dry = dry
        self.noise_processes: list[str] = []

    def get_action_duration(self) -> int:
        return self._duration

    def is_dry_run(self) -> bool:
        return self._dry


def _poller(cls: type, toolbox: _PollToolbox, stdout: str) -> Any:
    adb = MagicMock()
    adb.send_adb_command.return_value = (stdout, "")
    gatherer = cls(adb=adb)
    gatherer._get_toolbox = lambda: toolbox  # type: ignore[method-assign]
    gatherer._POLL_INTERVAL = 0.01
    return gatherer, adb


def test_processes_stop_joins_and_stores_run() -> None:
    from sandroid.analysis.processes import Processes

    toolbox = _PollToolbox(duration=60)
    gatherer, adb = _poller(
        Processes, toolbox, "NAME\nyes\n[kworker/0:1-events]\nls\nsystem_server\n"
    )
    gatherer.gather()
    time.sleep(0.05)
    started = time.monotonic()
    gatherer.stop()
    assert time.monotonic() - started < 5
    assert not gatherer._poll_thread.is_alive()
    assert gatherer.run_process_lists  # stored before stop() returned
    toolbox.noise_processes = ["system_server"]
    assert gatherer.return_data() == {"Processes": ["yes"]}
    # idempotent: a second read does not duplicate entries
    assert gatherer.return_data() == {"Processes": ["yes"]}


def test_processes_dry_run_slot_decided_at_start() -> None:
    from sandroid.analysis.processes import Processes

    toolbox = _PollToolbox(duration=60, dry=True)
    gatherer, _ = _poller(Processes, toolbox, "NAME\nnoisy\n")
    gatherer.gather()
    toolbox._dry = False  # DryRunEndStep may clear the flag mid-poll
    gatherer.stop()
    assert toolbox.noise_processes == ["noisy"]
    assert gatherer.run_process_lists == {}


def test_poll_is_bounded_by_duration_without_stop() -> None:
    from sandroid.analysis.sockets import Sockets

    toolbox = _PollToolbox(duration=0)
    gatherer, adb = _poller(Sockets, toolbox, "header\n")
    gatherer._POLL_MAX_SECONDS = 0.05
    gatherer.gather()
    gatherer._poll_thread.join(timeout=2)
    assert not gatherer._poll_thread.is_alive()
    assert adb.send_adb_command.call_count >= 1


def test_sockets_noise_matches_exact_ports() -> None:
    from sandroid.analysis.sockets import Sockets

    gatherer = Sockets(adb=MagicMock())
    line = "tcp 0 0 0.0.0.0:{port} 0.0.0.0:* LISTEN 123/{prog}"
    gatherer.run_sockets_lists = {0: [line.format(port=80, prog="evil")]}
    gatherer.noise_sockets = [line.format(port=8080, prog="system")]
    assert gatherer.return_data() == {"Listening Sockets": ["Port 80 used by evil"]}


def test_is_noise_process() -> None:
    from sandroid.analysis.processes import is_noise_process

    assert is_noise_process("[kworker/u8:10-ext4-rsv-conversion]")
    assert is_noise_process("sendevent")
    assert not is_noise_process("yes")
    assert not is_noise_process("de.fkie.ground_truth")


# ===========================================================================
# Network pcap parsing
# ===========================================================================


def _write_pcap(path: str, packets: list[Any]) -> None:
    from scapy.all import wrpcap

    wrpcap(path, packets)


def _traffic() -> list[Any]:
    from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw

    dev, server, target = "10.0.2.16", "10.0.2.3", "192.102.162.236"
    return [
        Ether()
        / IP(src=dev, dst=server)
        / UDP(sport=40000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="fkie.fraunhofer.de")),
        Ether()
        / IP(src=server, dst=dev)
        / UDP(sport=53, dport=40000)
        / DNS(
            qr=1,
            qd=DNSQR(qname="fkie.fraunhofer.de"),
            an=DNSRR(rrname="fkie.fraunhofer.de", type="A", rdata=target),
        ),
        Ether() / IP(src=dev, dst=target) / TCP(sport=50000, dport=443, flags="S"),
        Ether() / IP(src=target, dst=dev) / TCP(sport=443, dport=50000, flags="SA"),
        Ether()
        / IP(src=dev, dst=target)
        / TCP(sport=50000, dport=443, flags="PA")
        / Raw(b"\x00" * 42),
        Ether() / IP(src=dev, dst="8.8.4.4") / UDP(sport=50001, dport=4500) / Raw(b"x"),
        Ether() / IP(src=dev, dst="224.0.0.251") / UDP(sport=5353, dport=5353),
    ]


def _network(tmp_path, monkeypatch) -> Any:
    from sandroid.analysis.network import Network

    monkeypatch.setenv("RAW_RESULTS_PATH", str(tmp_path) + "/")
    (tmp_path / "network_trace_pull").mkdir()
    return Network(), tmp_path / "network_trace_pull"


def test_network_reports_tcp_and_udp_without_noise_capture(
    tmp_path, monkeypatch
) -> None:
    """No noise pcap (noise filter off) must not abort the network result."""
    network, folder = _network(tmp_path, monkeypatch)
    _write_pcap(str(folder / "network_trace_run_1.pcap"), _traffic())

    data = network.return_data()
    assert data["Network"] == ["fkie.fraunhofer.de."]
    targets = data["Network IP:Port (send/recv)"]
    assert (
        "192.102.162.236:443 [fkie.fraunhofer.de] (42B sent to / 0B received from)"
        in targets
    )
    assert any(t.startswith("8.8.4.4:4500/udp") for t in targets)
    assert not any("224.0.0.251" in t for t in targets)


def test_network_subtracts_noise_and_finds_all_runs(tmp_path, monkeypatch) -> None:
    from scapy.all import IP, TCP, Ether

    network, folder = _network(tmp_path, monkeypatch)
    noise = [Ether() / IP(src="10.0.2.16", dst="1.1.1.1") / TCP(dport=443, flags="S")]
    _write_pcap(str(folder / "network_trace_run_1.pcap"), noise)
    _write_pcap(str(folder / "network_trace_run_2.pcap"), _traffic() + noise)
    _write_pcap(str(folder / "network_trace_run_noise.pcap"), noise)

    targets = network.return_data()["Network IP:Port (send/recv)"]
    assert any(t.startswith("192.102.162.236:443") for t in targets)
    assert not any(t.startswith("1.1.1.1") for t in targets)


# ===========================================================================
# RunConfig.for_playback config toggles
# ===========================================================================


def test_for_playback_follows_analysis_config(monkeypatch) -> None:
    monkeypatch.setattr(
        run_config_module,
        "_analysis_toggle_defaults",
        lambda: {
            "network": True,
            "processes": True,
            "sockets": False,
            "hash_files": True,
            "pull_apk": False,
        },
    )
    rc = RunConfig.for_playback(recording_path="/r.txt")
    assert (rc.network, rc.processes, rc.sockets, rc.hash_files) == (
        True,
        True,
        False,
        True,
    )
    assert rc.show_deleted is True
    # explicit arguments win over the configuration
    rc = RunConfig.for_playback(recording_path="/r.txt", network=False)
    assert rc.network is False


def test_for_playback_falls_back_when_config_unavailable(monkeypatch) -> None:
    import sandroid.config as config_pkg

    def boom() -> None:
        raise RuntimeError("no config")

    monkeypatch.setattr(config_pkg, "get_config", boom)
    assert run_config_module._analysis_toggle_defaults() == {
        "network": False,
        "processes": False,
        "sockets": False,
        "hash_files": False,
        "pull_apk": False,
    }


def test_polling_thread_is_daemon() -> None:
    """Capture threads must never keep the interpreter alive."""
    from sandroid.analysis.processes import Processes

    toolbox = _PollToolbox(duration=60)
    gatherer, _ = _poller(Processes, toolbox, "NAME\n")
    gatherer.gather()
    try:
        assert gatherer._poll_thread.daemon
        assert isinstance(gatherer._poll_stop, threading.Event)
    finally:
        gatherer.stop()


# ===========================================================================
# Device guard on the adb serial / txt diff paths
# ===========================================================================


def test_serial_change_mid_run_is_fatal(monkeypatch) -> None:
    """Switching the active adb device mid-run aborts (device_name never changes)."""
    serials = iter(["emulator-5554", "emulator-5556"])
    current = {"serial": "emulator-5554"}

    def active_serial() -> str:
        current["serial"] = next(serials, current["serial"])
        return current["serial"]

    monkeypatch.setattr(AnalysisEngine, "_active_serial", staticmethod(active_serial))
    result = AnalysisEngine(
        RunConfig(number_of_runs=2, noise_filter=False, processes=False),
        forensic_service=MagicMock(),
        action_window_service=ActionWindowService(adb=MagicMock()),
        toolbox=CachingToolbox({}),
        gatherer_classes=_noop_classes(),
    ).run()
    assert result.error
    assert "emulator-5556" in result.error


def test_txt_diff_uses_pull_folders_for_absolute_device_paths(
    tmp_path, monkeypatch
) -> None:
    from sandroid.core import file_diff

    monkeypatch.setenv("RAW_RESULTS_PATH", str(tmp_path) + "/")
    for slot, text in (("first", "a\n"), ("second", "a\nb\n")):
        target = tmp_path / f"{slot}_pull" / "data" / "x"
        target.mkdir(parents=True)
        (target / "notes.txt").write_text(text)
    diff = file_diff.txt_diff("/data/x/notes.txt")
    assert "[LINE ADDED] b" in diff
    assert "Error" not in diff


def test_playback_persists_full_results_json(tmp_path, monkeypatch) -> None:
    """Record->Play writes the full legacy JSON (network/processes/other data)."""
    import json

    from sandroid.analysis.run_config import RunResult
    from sandroid.core import run_bundle
    from sandroid.tui.controllers.recording_controller import RecordingController

    monkeypatch.setattr(run_bundle, "write_manifest", lambda record: None)
    session = tmp_path / "session"
    bundle = tmp_path / "bundle"
    session.mkdir()
    bundle.mkdir()
    monkeypatch.setenv("RESULTS_PATH", str(session) + "/")
    result = RunResult(
        device_name="emu",
        network_targets=["192.102.162.236:443 (42B sent to / 0B received from)"],
        processes=["yes"],
        other_data={"Timeline Data": [[]]},
    )
    RecordingController(toolbox=MagicMock())._persist_run(
        run_id="r1",
        result=result,
        recording_path="/rec.txt",
        bundle_dir=str(bundle),
        device_name="emu",
        recorded_at="t0",
        error=None,
    )
    for folder in (session, bundle):
        data = json.loads((folder / "sandroid.json").read_text())
        assert data["Processes"] == ["yes"]
        assert data["Network IP:Port (send/recv)"][0].startswith("192.102.162.236")
        assert "Other Data" in data


def test_dry_run_deletions_are_subtracted(monkeypatch) -> None:
    from sandroid.analysis.deletedfiles import DeletedFiles

    dry = {"on": False}
    toolbox = MagicMock()
    toolbox.is_dry_run.side_effect = lambda: dry["on"]
    listings = iter(
        [
            {"/data/keep": 1},  # run 1: app.db + cache.log deleted
            {"/data/keep": 1},  # run 2: same
            {"/data/keep": 1, "/data/app.db": 1},  # dry run: only cache.log
        ]
    )
    toolbox.fetch_changed_files.side_effect = lambda fetch_all=False: next(listings)
    forensic = MagicMock()
    forensic.get_baseline.return_value = {
        "/data/keep": 1,
        "/data/app.db": 1,
        "/data/cache.log": 1,
    }
    forensic.get_noise_files.return_value = {}
    monkeypatch.setattr(DeletedFiles, "deletedFileListList", [])
    gatherer = DeletedFiles(forensic_service=forensic)
    gatherer._get_toolbox = lambda: toolbox  # type: ignore[method-assign]
    gatherer._exclude_whitelist = lambda files: files  # type: ignore[method-assign]
    gatherer.gather()
    gatherer.gather()
    dry["on"] = True
    gatherer.gather()
    assert gatherer.return_data() == {"Deleted Files": ["/data/app.db"]}


def test_art_profiles_are_structural_noise() -> None:
    from sandroid.analysis.filters import filter_noise_files, is_structural_noise

    prof = "/data/misc/profiles/cur/0/de.fkie.ground_truth/primary.prof"
    assert is_structural_noise(prof)
    assert is_structural_noise("/data/system/package-dex-usage.pb")
    assert not is_structural_noise("/data/data/de.fkie.ground_truth/files/a.txt")
    kept = filter_noise_files(
        [prof, "/data/data/de.fkie.ground_truth/databases/GroundTruth.db"], {}
    )
    assert kept == ["/data/data/de.fkie.ground_truth/databases/GroundTruth.db"]


def test_snapshot_load_resyncs_guest_clock(monkeypatch) -> None:
    """After a revert the guest clock is set back to the host's epoch."""
    from sandroid.services import emulator_service as es_module
    from sandroid.services.emulator_service import EmulatorService

    monkeypatch.setattr(es_module.time, "time", lambda: 1_800_000_000.0)
    adb = MagicMock()
    adb.send_telnet_command.return_value = ("OK\n", "")
    calls: list[str] = []

    def send(command: str, serial: str | None = None) -> tuple[str, str]:
        calls.append(command)
        if command == "get-state":
            return "device\n", ""
        if command == "shell date +%s":
            return "1800000000\n", ""
        return "", ""

    adb.send_adb_command.side_effect = send
    assert EmulatorService(adb=adb).load_snapshot("tmp") is True
    assert "shell date -u @1800000000" in calls


def test_xml_beautify_handles_three_arg_update_text() -> None:
    """The xmldiff formatter emits ``[update-text, path, new, old]``."""
    from sandroid.core import file_diff

    out = file_diff.xml_diff_beautify(
        '[update-text, /root/Element[2], "1794842548", null]\n'
        '[update-text, /root/Element[1], "2", "1"]'
    )
    assert "Unknown" not in out
    assert 'Updated text: /root/Element[2] to "1794842548"' in out
    assert '(was "1")' in out
