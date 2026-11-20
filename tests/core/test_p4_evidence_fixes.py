"""Regression tests for the 2.1 evidence-integrity fixes (P4 findings A1-A12).

Device-free: ``sqldiff`` is replaced by a small Python stand-in on ``PATH``
(it opens the databases with SQLite exactly like the real tool, so it also
creates ``-shm`` files and replays WAL/journal files), adb by fake scripts.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from sandroid.analysis.run_config import RunResult, StepError
from sandroid.core import file_diff, run_report

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

FAKE_SQLDIFF = textwrap.dedent(
    """\
    import sqlite3, sys
    a, b = sys.argv[1:3]

    def rows(path):
        con = sqlite3.connect(path)
        out = set()
        for (table,) in con.execute(
            "select name from sqlite_master where type='table'"
        ):
            for row in con.execute(f"select * from {table}"):
                out.add((table, row))
        con.close()
        return out

    try:
        old, new = rows(a), rows(b)
    except sqlite3.DatabaseError as exc:
        print(f"sqldiff: {exc}", file=sys.stderr)
        sys.exit(1)
    for table, row in sorted(new - old):
        print(f"INSERT INTO {table}(id,v) VALUES({row[0]},'{row[1]}');")
    """
)


@pytest.fixture
def fake_sqldiff(tmp_path, monkeypatch):
    """Put a Python ``sqldiff`` stand-in first on PATH."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "sqldiff"
    script.write_text(f"#!{sys.executable}\n" + FAKE_SQLDIFF)
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return script


@pytest.fixture
def no_sqldiff(tmp_path, monkeypatch):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "-"


def _pulled_wal_db(dest: Path, rows: list[str]) -> Path:
    """A database copied while its writer still held uncheckpointed WAL frames."""
    src_dir = dest.parent.parent / f".src-{dest.parent.name}-{dest.name}"
    src_dir.mkdir(parents=True)
    src = src_dir / "a.db"
    con = sqlite3.connect(src)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("create table t(id integer primary key, v text)")
    con.commit()
    for value in rows:
        con.execute("insert into t(v) values (?)", (value,))
        con.commit()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(src.read_bytes())
    Path(f"{dest}-wal").write_bytes(Path(f"{src}-wal").read_bytes())
    con.close()
    return dest


def _plain_db(path: Path, rows: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("create table t(id integer primary key, v text)")
    for value in rows:
        con.execute("insert into t(v) values (?)", (value,))
    con.commit()
    con.close()
    return path


def _paragraph_texts(flowables) -> list[str]:
    out: list[str] = []
    for f in flowables:
        if isinstance(f, (list, tuple)):
            out.extend(_paragraph_texts(f))
        elif hasattr(f, "_cellvalues"):
            for row in f._cellvalues:
                out.extend(_paragraph_texts([c for c in row if c is not None]))
        elif isinstance(getattr(f, "text", None), str):
            out.append(f.text)
    return out


# ---------------------------------------------------------------------------
# A1 -- the diff must never modify pulled evidence
# ---------------------------------------------------------------------------


def test_db_diff_leaves_pulled_wal_database_untouched(tmp_path, fake_sqldiff):
    first = _pulled_wal_db(tmp_path / "raw/first_pull/a.db", ["hello"])
    second = _pulled_wal_db(tmp_path / "raw/second_pull/a.db", ["hello", "secret"])
    before = {p: _digest(p) for p in (first, second)}
    before.update({Path(f"{p}-wal"): _digest(Path(f"{p}-wal")) for p in before})

    diff = file_diff.db_diff(str(first), str(second))

    assert "secret" in diff  # the WAL content was integrated (in a copy)
    for path, digest in before.items():
        assert _digest(path) == digest, f"{path} was modified"
    # Neither VACUUM nor sqldiff left SQLite side files in the pull tree.
    assert sorted(p.name for p in (tmp_path / "raw/second_pull").iterdir()) == [
        "a.db",
        "a.db-wal",
    ]


def test_db_diff_does_not_roll_back_hot_journal_in_place(tmp_path, fake_sqldiff):
    first = _plain_db(tmp_path / "first.db", ["x"])
    second = _plain_db(tmp_path / "second.db", ["x", "y"])
    journal = Path(f"{second}-journal")
    journal.write_bytes(b"\x00" * 512)  # a (bogus) hot journal next to the pull
    before = (_digest(second), _digest(journal))

    file_diff.db_diff(str(first), str(second))

    assert (_digest(second), _digest(journal)) == before


# ---------------------------------------------------------------------------
# A2 -- one undiffable file must not wipe Changed Files
# ---------------------------------------------------------------------------


def _changed_files(raw: Path, files: list[str]):
    from sandroid.analysis.changedfiles import ChangedFiles

    fs = MagicMock()
    fs.get_noise_files.return_value = {}
    fs.get_baseline.return_value = dict.fromkeys(files, 1)
    cf = ChangedFiles(forensic_service=fs, adb=MagicMock())
    cf.fileListList = [files]
    cf._exclude_whitelist = lambda x: x
    return cf


def test_changed_files_survive_non_utf8_text_and_raising_diff(
    tmp_path, monkeypatch, fake_sqldiff
):
    raw = tmp_path / "raw"
    monkeypatch.setenv("RAW_RESULTS_PATH", f"{raw}/")
    files = [
        "/data/data/x/files/notes.txt",
        "/data/data/x/shared_prefs/p.xml",
        "/data/data/x/files/blob.bin",
    ]
    for slot in ("first_pull", "second_pull"):
        base = raw / slot / "data/data/x"
        (base / "files").mkdir(parents=True)
        (base / "shared_prefs").mkdir(parents=True)
        (base / "files/notes.txt").write_bytes(b"caf\xe9 " + slot.encode())
        (base / "shared_prefs/p.xml").write_text("<map/>")
        (base / "files/blob.bin").write_bytes(slot.encode())

    def boom(*_args, **_kwargs):
        raise RuntimeError("diff exploded")

    monkeypatch.setattr(file_diff, "xml_diff", boom)
    cf = _changed_files(raw, files)

    out = cf.return_data()["Changed Files"]

    names = [next(iter(e)) if isinstance(e, dict) else e for e in out]
    assert names == files
    assert "not a text file" in out[0][files[0]][0]
    assert (
        "Could not analyse this file: RuntimeError: diff exploded"
        in (out[1][files[1]][0])
    )
    assert "diff exploded" in cf.pretty_print()


def test_abx_unknown_token_type_is_reported_not_raised(tmp_path):
    abx = tmp_path / "f.xml"
    abx.write_bytes(
        b"ABX\x00"
        + bytes.fromhex(
            "8d3b583bad38c275f34aed056ad6ea8eeca4192fa1feb9dc4b1ebe55e5b8f9"
        )
    )
    diff = file_diff.xml_diff(str(abx), str(abx))
    assert file_diff.is_diff_failure(diff)


# ---------------------------------------------------------------------------
# A7 -- failures must never look like "no change" / noise
# ---------------------------------------------------------------------------


def test_db_diff_missing_version_is_not_enough_data(tmp_path, fake_sqldiff):
    first = _plain_db(tmp_path / "a.db", ["x"])
    diff = file_diff.db_diff(str(first), str(tmp_path / "missing.db"))
    assert diff.startswith("\tNot enough data")


def test_db_diff_reports_sqldiff_failure(tmp_path, fake_sqldiff):
    first = _plain_db(tmp_path / "a.db", ["x"])
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"SQLite format 3\x00" + b"\x00" * 50)
    diff = file_diff.db_diff(str(first), str(bad))
    assert diff.startswith("\tCould not analyse: sqldiff failed")


def test_missing_sqldiff_with_noise_is_not_all_noise(tmp_path, no_sqldiff):
    first = _plain_db(tmp_path / "first.db", ["x"])
    second = _plain_db(tmp_path / "second.db", ["x", "EVIDENCE"])
    noise = _plain_db(tmp_path / "noise.db", ["x", "bg"])
    diff = file_diff.db_diff(str(first), str(second), str(noise))
    assert diff != "ITS ALL NOISE"
    assert "sqldiff" in diff
    assert file_diff.is_diff_failure(diff)


def test_db_noise_filter_drops_only_noise_lines(tmp_path, fake_sqldiff):
    first = _plain_db(tmp_path / "first.db", ["x"])
    second = _plain_db(tmp_path / "second.db", ["x", "bg", "EVIDENCE"])
    noise = _plain_db(tmp_path / "noise.db", ["x", "bg"])
    diff = file_diff.db_diff(str(first), str(second), str(noise))
    assert "EVIDENCE" in diff
    assert "'bg'" not in diff
    all_noise = file_diff.db_diff(str(first), str(noise), str(noise))
    assert all_noise == "ITS ALL NOISE"


def test_xml_parse_error_is_reported_and_never_noise(tmp_path):
    good = tmp_path / "p.xml"
    good.write_text("<map><string name='a'>1</string></map>")
    broken = tmp_path / "q.xml"
    broken.write_text("<map><string name='tok'>SECRET</str")
    assert file_diff.xml_diff(str(good), str(broken)).startswith(
        "\tCould not analyse: XML parse error"
    )
    # Broken first version: diff and noise diff fail identically -> not noise.
    diff = file_diff.xml_diff(str(broken), str(good), str(good))
    assert diff != "ITS ALL NOISE"
    assert file_diff.is_diff_failure(diff)


def test_critical_setup_warns_when_sqldiff_is_missing(monkeypatch):
    from sandroid.services import setup_checks
    from sandroid.services.setup_service import SetupResult, SetupService

    service = SetupService.__new__(SetupService)
    import threading

    service._lock = threading.RLock()
    service._check_lock = threading.Lock()
    service._run_critical_checks = lambda **kw: SetupResult(success=True)
    monkeypatch.setattr(setup_checks.shutil, "which", lambda name: None)
    result = SetupService.check_critical_setup(service)
    assert any("sqldiff" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# A3 -- failed runs are never sealed as clean
# ---------------------------------------------------------------------------


def test_run_errors_in_json_metadata_and_pdf_banner(tmp_path):
    from sandroid.core import report_render

    result = RunResult(
        device_name="emu",
        error="Failed to load emulator snapshot 'tmp'",
        per_step_errors=[
            StepError(label="gather:NewFiles", run_number=2, error="boom")
        ],
    )
    doc = result.to_json_dict()
    assert doc["Run Errors"]["status"] == "aborted"
    assert doc["Run Errors"]["steps"][0]["error"] == "boom"
    assert "Run Errors" not in RunResult(device_name="emu").to_json_dict()

    out = run_report.finalize_run(tmp_path, doc, generate_pdf=False)
    written = json.loads(out.results_json.read_text())
    assert written["Run Errors"]["fatal"].startswith("Failed to load")
    assert written["Run Metadata"]["run_status"] == "aborted"

    doc = json.loads(out.report_json.read_text())
    overview = next(s for s in doc["sections"] if s["id"] == "overview")
    renderer = report_render.PdfRenderer(doc, tmp_path)
    first_page = renderer._render_unit(overview["title"], True, overview["blocks"])
    texts = "\n".join(_paragraph_texts(first_page))
    assert "RUN ABORTED" in texts
    assert "boom" in texts


def test_engine_records_return_data_failure_and_empty_baseline_is_fatal():
    from sandroid.analysis.engine import (
        AnalysisEngine,
        BaselineStep,
        EngineContext,
        FatalStepError,
    )

    engine = AnalysisEngine.__new__(AnalysisEngine)
    errors: list[StepError] = []
    broken = MagicMock()
    broken.return_data.side_effect = UnicodeDecodeError("utf-8", b"\xe9", 0, 1, "x")
    assert engine._safe_return(broken, "Changed Files", [], errors=errors) == []
    assert [e.label for e in errors] == ["results:Changed Files"]

    def ctx(fetch):
        return EngineContext(
            config=MagicMock(),
            toolbox=SimpleNamespace(fetch_changed_files=fetch),
            forensic_service=MagicMock(),
            action_window_service=MagicMock(),
        )

    with pytest.raises(FatalStepError, match="no files"):
        BaselineStep().run(ctx(lambda fetch_all=False: {}))

    def failing(fetch_all=False):
        raise RuntimeError("timed out")

    with pytest.raises(FatalStepError, match="timed out"):
        BaselineStep().run(ctx(failing))


def test_headless_summary_exits_nonzero_on_run_errors():
    from sandroid.api import AnalysisMode
    from sandroid.cli_modes import headless

    console = MagicMock()
    results = {
        "Changed Files": [],
        "Run Errors": {"status": "aborted", "fatal": "snapshot", "steps": []},
    }
    rc = headless._print_summary(
        console,
        SimpleNamespace(),
        AnalysisMode.MALWARE,
        results,
        headless._MISSING,
        None,
    )
    assert rc == headless.EXIT_DOCUMENTATION_FAILED


# ---------------------------------------------------------------------------
# A3 + A5 -- CLI --package: session folder, exit 3 on run errors
# ---------------------------------------------------------------------------


def test_cli_package_run_writes_into_session_folder_and_exits_3(monkeypatch, tmp_path):
    from sandroid.analysis.engine import AnalysisEngine
    from sandroid.cli_modes import analysis as cli_analysis
    from sandroid.config import SandroidConfig
    from sandroid.core import initializer

    failed = RunResult(device_name="emu", error="Baseline filesystem scan failed")
    monkeypatch.setattr(AnalysisEngine, "run", lambda self: failed)
    monkeypatch.setattr(initializer, "initialize_core", lambda cfg, **kw: None)
    setup = MagicMock()
    setup.check_critical_setup.return_value = MagicMock(success=True)
    monkeypatch.setattr(cli_analysis, "get_setup_service", lambda: setup)
    for name in ("get_spotlight_service", "get_task_service", "get_ui_service"):
        monkeypatch.setattr(cli_analysis, name, lambda: MagicMock())
    session = tmp_path / "results" / "20261116_120000"
    session.mkdir(parents=True)
    monkeypatch.setenv("SESSION_PATH", f"{session}/")
    config = SandroidConfig(
        paths={"results_path": tmp_path / "results"},
        report={"generate_pdf": False},
    )
    toolbox = MagicMock()
    toolbox.get_tools_used.return_value = []

    with pytest.raises(SystemExit) as info:
        cli_analysis.run_analysis(
            config,
            MagicMock(),
            toolbox,
            MagicMock(),
            MagicMock(),
            package="com.example.app",
        )

    assert info.value.code == 3
    assert (session / "sandroid.json").exists()
    assert (session / "SHA256SUMS").exists()
    assert not (tmp_path / "results" / "sandroid.json").exists()
    written = json.loads((session / "sandroid.json").read_text())
    assert written["Run Errors"]["fatal"] == "Baseline filesystem scan failed"


# ---------------------------------------------------------------------------
# A4 -- non-UTF-8 device file names, failed scans
# ---------------------------------------------------------------------------


def test_adb_output_with_non_utf8_name_round_trips(tmp_path, monkeypatch):
    from sandroid.core.adb import Adb

    record = tmp_path / "args.bin"
    fake = tmp_path / "fakeadb"
    fake.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "pull" ]; then printf "%s" "$2" > "'
        + str(record)
        + '"; exit 0; fi\n'
        "printf '/data/data/x/files:\\n'\n"
        "printf -- '-rw------- 1 u u 4 2026-11-16 10:00:00.000000000 +0000 "
        "bad\\377name\\n'\n"
    )
    fake.chmod(0o755)
    monkeypatch.setattr(Adb, "ADB_PATH", str(fake))
    monkeypatch.setattr(Adb, "_target_device", None)

    from sandroid.services.forensic_service import ForensicService

    found = ForensicService(adb=Adb).fetch_changed_files(fetch_all=True)
    (name,) = found
    assert name == "/data/data/x/files/bad\udcffname"
    # The surrogate-escaped name reaches adb as the original bytes again.
    Adb.send_adb_command(f"pull '{name}'")
    assert record.read_bytes() == b"/data/data/x/files/bad\xffname"


def test_empty_scan_raises_and_uses_long_timeout(monkeypatch):
    from sandroid.services import forensic_service as fs_mod

    calls = []

    class _Adb:
        @staticmethod
        def send_adb_command(command, serial=None, timeout=30):
            calls.append(timeout)
            return "", "Command timed out after 30 seconds"

    monkeypatch.setenv("SANDROID_SCAN_TIMEOUT", "900")
    with pytest.raises(fs_mod.FilesystemScanError, match="timed out"):
        fs_mod.ForensicService(adb=_Adb).fetch_changed_files(fetch_all=True)
    assert calls == [900.0]


def test_results_json_survives_surrogate_file_names(tmp_path):
    out = run_report.finalize_run(
        tmp_path, {"Device Name": "emu", "New Files": ["/data/x/bad\udcffname"]}
    )
    assert json.loads(out.results_json.read_text())["New Files"] == [
        "/data/x/bad\udcffname"
    ]


# ---------------------------------------------------------------------------
# A6 -- batch packages get their own folders; caches do not leak
# ---------------------------------------------------------------------------


def test_batch_gives_every_package_its_own_result_folder(monkeypatch, tmp_path):
    from sandroid.api import batch, headless
    from sandroid.api.interfaces import AnalysisMode

    seen: list[dict] = []

    class _FakeAPI:
        def __init__(self, config_path=None, config=None):
            pass

        async def initialize(self):
            return SimpleNamespace(success=True)

        async def run_analysis(self, **kwargs):
            seen.append(kwargs)
            return {}

        async def shutdown(self):
            return None

    monkeypatch.setattr(headless, "SandroidHeadlessAPI", _FakeAPI)
    monkeypatch.setenv("SESSION_PATH", f"{tmp_path / 'session'}/")
    res = asyncio.run(
        batch.batch_analyze(
            ["com.a", "com.b", "com.a"],
            mode=AnalysisMode.MALWARE,
            output_dir=str(tmp_path / "out"),
        )
    )
    dirs = [kw["result_dir"] for kw in seen]
    assert len(set(dirs)) == 3
    assert all(
        Path(d).is_dir() and Path(d).parent == tmp_path / "session" for d in dirs
    )
    assert res["com.b"]["result_dir"] == dirs[1]


def test_pinned_result_dir_drives_engine_paths_and_finalize(tmp_path, monkeypatch):
    from sandroid.analysis.run_config import RunConfig
    from sandroid.api import analysis_runners

    rc = RunConfig()
    analysis_runners._pin_result_dir(rc, str(tmp_path / "pkg"))
    assert rc.results_path == str(tmp_path / "pkg")
    assert rc.raw_results_path == str(tmp_path / "pkg" / "raw")
    analysis_runners._pin_result_dir(rc, None)
    assert rc.results_path == ""
    assert rc.raw_results_path == ""

    captured = {}

    def fake_finalize(result_dir, results, **kw):
        captured["dir"] = result_dir
        return run_report.FinalizeOutcome(results_json=Path(result_dir) / "s.json")

    monkeypatch.setattr(run_report, "finalize_run", fake_finalize)
    monkeypatch.setenv("SESSION_PATH", f"{tmp_path / 'session'}/")
    pinned = RunConfig(results_path=str(tmp_path / "pkg"))
    analysis_runners._finalize_headless_run(
        SimpleNamespace(config=None),
        RunResult(device_name="e"),
        "m",
        "t",
        run_config=pinned,
    )
    assert captured["dir"] == str(tmp_path / "pkg")


def test_engine_run_clears_sqlite_header_cache(tmp_path):
    from sandroid.analysis.engine import AnalysisEngine

    db = tmp_path / "x"
    db.write_bytes(b"not sqlite")
    assert file_diff.is_sqlite_file(str(db)) is False
    _plain_db(tmp_path / "y.db", ["a"]).replace(db)
    engine = AnalysisEngine.__new__(AnalysisEngine)
    engine.action_window_service = MagicMock()
    engine.forensic_service = MagicMock()
    engine.toolbox = MagicMock()
    engine._reset_accumulators()
    assert file_diff.is_sqlite_file(str(db)) is True


# ---------------------------------------------------------------------------
# A8 -- renaming a run keeps its sealed run.json intact
# ---------------------------------------------------------------------------


def test_rename_run_keeps_sealed_bundle_verifiable(tmp_path, monkeypatch):
    from sandroid.core import run_bundle, run_history

    monkeypatch.setattr(run_history, "_results_path", lambda: tmp_path)
    rid = run_history.new_run_id()
    bundle = run_bundle.create_bundle(rid)
    res = RunResult(device_name="emu", changed_files=["/data/x/f"])
    record = res.to_run_record(
        run_id=rid,
        label="Run A",
        recording_path="r",
        bundle_dir=str(bundle),
        recorded_at="t",
        completed_at="t",
        duration=1,
    )
    run_bundle.write_manifest(record)
    run_report.finalize_run(bundle, res.to_json_dict())
    run_json = (bundle / "run.json").read_bytes()

    run_history.update_label(rid, "Renamed")

    assert (bundle / "run.json").read_bytes() == run_json
    assert run_report.verify_hash_manifest(bundle).ok
    assert run_history.load_run(rid).label == "Renamed"
    assert run_history.load_index()[0]["label"] == "Renamed"
    (tmp_path / "runs" / "index.json").unlink()  # rebuild keeps the label
    assert run_history.load_index()[0]["label"] == "Renamed"
    run_history.delete_run(rid)
    assert rid not in (tmp_path / "runs" / "labels.json").read_text()


# ---------------------------------------------------------------------------
# A9 -- a deleted SHA256SUMS does not unseal the folder
# ---------------------------------------------------------------------------


def test_missing_sha256sums_verifies_against_manifest_json(tmp_path):
    run_report.finalize_run(
        tmp_path, {"Device Name": "emu", "New Files": ["/data/mal/c2.txt"]}
    )
    results = tmp_path / "sandroid.json"
    doc = json.loads(results.read_text())
    doc["New Files"] = []
    results.write_text(json.dumps(doc))
    (tmp_path / "SHA256SUMS").unlink()

    check = run_report.verify_hash_manifest(tmp_path)

    assert check.present
    assert not check.ok
    assert "SHA256SUMS" in check.missing
    assert "sandroid.json" in check.mismatched
    with pytest.raises(run_report.EvidenceVerificationError):
        run_report.report_from_folder(tmp_path)


# ---------------------------------------------------------------------------
# A11 / A12 -- recorded noise drops, deterministic order
# ---------------------------------------------------------------------------


def test_structural_and_dry_run_noise_are_recorded(tmp_path, monkeypatch):
    from sandroid.analysis import filters

    monkeypatch.setenv("RAW_RESULTS_PATH", f"{tmp_path}/")
    files = [
        "/data/misc/profiles/cur/0/x/primary.prof",
        "/data/data/x/cache/noisy.bin",
        "/data/data/x/files/real.bin",
    ]
    cf = _changed_files(tmp_path, files)
    cf._get_noise_files = lambda: {"/data/data/x/cache/noisy.bin": 1}
    assert cf.process_data() == ["/data/data/x/files/real.bin"]
    assert cf.filtered_noise == {
        files[0]: filters.NOISE_REASON_STRUCTURAL,
        files[1]: filters.NOISE_REASON_DRY_RUN,
    }


def test_pdf_has_filtered_noise_appendix(tmp_path):
    from sandroid.core import report_engine, report_render

    doc = {
        "Device Name": "emu",
        "Changed Files": [],
        "Other Data": {
            "Filtered Noise": [
                {
                    "enabled": True,
                    "note": "hidden",
                    "Changed Files": {
                        "/data/system/netstats/x": "/data/system/netstats/*"
                    },
                }
            ]
        },
    }
    (tmp_path / "sandroid.json").write_text(json.dumps(doc))
    assert "Filtered Noise" in [t for t, _ in report_engine.results_plan(doc)]
    report = report_engine.build_report(
        timeline=None,
        seal=None,
        scope=report_engine.ReportScope(),
        bundle_dir=tmp_path,
        options=report_engine.ReportOptions(sections=("results",)),
    )
    renderer = report_render.PdfRenderer(report, tmp_path)
    unit = next(u for u in renderer._units() if u[1] == "Filtered Noise")
    texts = "\n".join(_paragraph_texts(renderer._render_unit(unit[1], False, unit[3])))
    assert "/data/system/netstats/x" in texts


def test_intersection_keeps_first_list_order():
    from sandroid.analysis.filters import intersect_file_lists

    lists = [["/c", "/a", "/b", "/a"], ["/b", "/a", "/c", "/z"]]
    assert intersect_file_lists(lists) == ["/c", "/a", "/b"]


def test_update_columns_keep_statement_order(tmp_path, monkeypatch):
    out = (
        "UPDATE t SET zeta=2, alpha=3, mid=4 WHERE id=1;\n",
        "UPDATE t SET zeta=1, alpha=3, mid=5 WHERE id=1;\n",
    )
    runs = iter([(out[1], None), (out[0], None)])
    monkeypatch.setattr(file_diff, "_run_sqldiff", lambda a, b: next(runs))
    diff = file_diff._db_diff_copies("a", "b", "a")
    assert diff.index("zeta") < diff.index("alpha") < diff.index("mid")


# ---------------------------------------------------------------------------
# Run results hold plain diff text; markup only where it is displayed
# ---------------------------------------------------------------------------

_LEGACY_LINE = (
    "\t\\[[success]INSERT[/success]] Table \\[t] row "
    "\\[[success]2,'b'[/success]] has been added"
)
_LEGACY_UPDATE = (
    "\t\\[[warning]UPDATE[/warning]] Table \\[t] row where \\[id=1] "
    "changed: v=([warning]a → b[/warning])"
)


def _run_record(run_id: str, changed: list):
    from sandroid.core import run_history

    return run_history.RunRecord(
        schema_version=run_history.SCHEMA_VERSION,
        run_id=run_id,
        label="",
        recorded_at="",
        completed_at="",
        device_name="",
        recording_path="",
        duration=0,
        changed_files=changed,
    )


def test_run_results_contain_no_display_markup(tmp_path, monkeypatch, fake_sqldiff):
    raw = tmp_path / "raw"
    monkeypatch.setenv("RAW_RESULTS_PATH", f"{raw}/")
    rel = "data/data/x/databases/a.db"
    _plain_db(raw / "first_pull" / rel, ["x"])
    _plain_db(raw / "second_pull" / rel, ["x", "[bold]y"])
    cf = _changed_files(raw, [f"/{rel}"])

    out = cf.return_data()["Changed Files"]
    lines = out[0][f"/{rel}"]
    joined = "\n".join(lines)
    for tag in ("[success]", "[warning]", "[error]", "[/", "\\["):
        assert tag not in joined
    assert joined == "\t[INSERT] Table [t] row [2,'[bold]y'] has been added"

    # Sealed as-is: the results JSON keeps the data's brackets ...
    cleaned = run_report.sanitize_results({"Changed Files": out})
    assert cleaned["Changed Files"][0][f"/{rel}"] == lines
    # ... and so does the run record (run.json).
    from sandroid.core import run_history

    record = _run_record("r1", out)
    (row,) = run_history.file_diff_rows(record)
    assert row.diff == lines

    # The console still gets colour, with the data escaped.
    from rich.text import Text

    printed = file_diff.diff_markup(joined)
    assert printed.startswith("\t\\[[success]INSERT[/success]]")
    assert Text.from_markup(printed).plain == joined
    console = cf.pretty_print()
    assert "\\[[success]INSERT[/success]]" in console
    assert "[2,'[bold]y'] has been added" in Text.from_markup(console).plain


def test_old_runs_with_markup_are_stripped_when_shown_or_exported():
    """Runs recorded before the change keep working: legacy lines are
    rendered (TUI), stripped for exports (results JSON, AI, zoom export).
    """
    from rich.text import Text

    from sandroid.tui.widgets.files_panel import diff_line_text, render_diff

    assert file_diff.is_legacy_markup_line(_LEGACY_LINE)
    assert not file_diff.is_legacy_markup_line("\t[INSERT] Table [t] row [1]")
    plain = "\t[INSERT] Table [t] row [2,'b'] has been added"
    assert file_diff.plain_diff_line(_LEGACY_LINE) == plain
    assert file_diff.plain_diff_line(_LEGACY_UPDATE) == (
        "\t[UPDATE] Table [t] row where [id=1] changed: v=(a → b)"
    )
    # Plain lines are never run through a markup parser.
    data = "\t[INSERT] Table [t] row [1,'[bold]x[/bold]'] has been added"
    assert file_diff.plain_diff_line(data) == data
    assert diff_line_text(data).plain == data
    # TUI: both forms render to the same text, both coloured.
    assert diff_line_text(_LEGACY_LINE).plain == diff_line_text(plain).plain
    assert diff_line_text(plain).spans
    assert "[success]" not in render_diff([_LEGACY_LINE, plain]).plain
    # Results JSON / PDF input.
    cleaned = run_report.sanitize_results(
        {"Changed Files": [{"/a.db": [_LEGACY_LINE, _LEGACY_UPDATE, data]}]}
    )
    assert cleaned["Changed Files"][0]["/a.db"] == [
        plain,
        "\t[UPDATE] Table [t] row where [id=1] changed: v=(a → b)",
        data,
    ]
    # Zoom view / export: markup lines rendered, plain lines escaped.
    zoom = file_diff.diff_markup(["~ /a.db", f"    {_LEGACY_LINE}", f"    {data}"])
    assert Text.from_markup(zoom).plain.splitlines() == [
        "~ /a.db",
        f"    {plain}",
        f"    {data}",
    ]


def test_ai_run_detail_strips_legacy_markup(monkeypatch):
    from sandroid.ai.tools import recording_control
    from sandroid.core import run_history

    record = _run_record("old", [{"/a.db": [_LEGACY_LINE]}, "/b.bin"])
    monkeypatch.setattr(run_history, "load_run", lambda run_id: record)
    data = recording_control.get_run_detail("old")
    assert data["changed_files"][0]["/a.db"] == (
        "\t[INSERT] Table [t] row [2,'b'] has been added"
    )
    assert data["changed_files"][1] == "/b.bin"
