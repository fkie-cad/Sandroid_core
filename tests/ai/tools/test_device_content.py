"""Tests for the ``read_device_files`` tool (sandroid.ai.tools.device_content)
and its integration with the Files lens tools (find_rows / get_rows /
classify_rows content).

Rows come from a fake Files lens row source; the device is the fake of
tests/ai/test_device_files.py (argv -> bytes, no adb).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from sandroid.ai import arbiter as arb
from sandroid.ai import device_files as df
from sandroid.ai import loop
from sandroid.ai.loop import RunContext
from sandroid.ai.tools import device_content, lens_rows
from sandroid.ai.tools.registry import RiskTier, ToolError, get_tool_registry
from sandroid.ai.tools.toolsets import TOOLSET_TABLE
from sandroid.core.adb import Adb
from sandroid.services import row_highlights as rh


def _fakes():
    name = "_sandroid_device_files_fakes"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[1] / "test_device_files.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


F = _fakes()
JWT = F.JWT
PREFS = F.PREFS
SERIAL = "emulator-5570"
PKG = "/data/data/com.x"
P_PREFS = f"{PKG}/shared_prefs/e2e.xml"
P_JSON = f"{PKG}/files/conf.json"
P_GZ = f"{PKG}/files/log.json.gz"
P_PNG = f"{PKG}/cache/a.png"
P_DB = f"{PKG}/databases/app.db"
P_GONE = f"{PKG}/files/gone.txt"
P_DIR = f"{PKG}/files/dir"
P_REVIEW = f"{PKG}/shared_prefs/old.xml"


def _row(path, last=100.0, scope=None, shown=True):
    return {
        "key": path,
        "path": path,
        "shown": shown,
        "ops": "M",
        "count": 1,
        "processes": ["com.x"],
        "first": last,
        "last": last,
        "watched": False,
        "app": "com.x",
        "review_kind": "changed" if scope else None,
        "scope": scope,
    }


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Session store + fake device + Files rows; returns a namespace."""
    import gzip

    session = tmp_path / "session"
    monkeypatch.setattr("sandroid.ai.results.session_root", lambda: session)
    lines: list[tuple] = []
    monkeypatch.setattr(
        "sandroid.core.timeline.emit", lambda *a, **k: lines.append((a, k))
    )
    monkeypatch.setattr(Adb, "ADB_PATH", "adb")
    monkeypatch.setattr(Adb, "_target_device", None)
    monkeypatch.setattr(df, "current_serial", lambda: SERIAL)
    rh.reset_for_tests()
    arb.reset_for_tests()
    store = rh.get_row_highlights()
    main, wal = F._wal_db(tmp_path)
    dev = F.FakeDevice(
        {
            P_PREFS: PREFS,
            P_JSON: json.dumps({"device_id": "d-1", "api_key": "K-777"}).encode(),
            P_GZ: gzip.compress(b'{"event": "open", "user": "u-4711"}'),
            P_PNG: F.PNG,
            P_DB: main,
            P_DB + "-wal": wal,
            P_REVIEW: b"<map/>",
        },
        dirs=(P_DIR,),
    )
    real = df.DeviceFileReader
    monkeypatch.setattr(
        df,
        "DeviceFileReader",
        lambda serial, **kw: real(serial, run=dev.run, popen=dev.popen, **kw),
    )
    rows = [
        _row(P_PREFS),
        _row(P_JSON),
        _row(P_GZ),
        _row(P_PNG),
        _row(P_DB),
        _row(P_GONE),
        _row(P_DIR),
        _row(P_REVIEW, scope="run-1"),
    ]
    store.register_row_source("files", lambda: rows, None)

    class Env:
        pass

    e = Env()
    e.dev, e.rows, e.store, e.lines = dev, rows, store, lines
    e.root = session / "ai" / "content_cache"
    yield e
    rh.reset_for_tests()
    arb.reset_for_tests()


# -- registration ---------------------------------------------------------------


def test_registration_risk_and_toolset():
    spec = get_tool_registry().get_spec("read_device_files")
    assert spec.risk == RiskTier.REVERSIBLE
    assert spec.can_remember_choice is True
    assert not spec.resources
    entry = TOOLSET_TABLE["read_device_files"]
    assert entry.toolset == "lenses"
    assert entry.core is True
    assert entry.timeout_s == 300
    assert spec.core is True


# -- the read ---------------------------------------------------------------------


def test_reads_counts_and_never_returns_content(env):
    result = device_content.read_device_files()
    assert result["serial"] == SERIAL
    assert result["candidates"] == 8
    assert result["read"] == 4  # prefs, json, gz, db
    assert result["cached"] == 0
    sk = result["skipped"]
    assert sk["binary"] == 1
    assert sk["gone"] == 1
    assert sk["not_regular"] == 1
    assert sk["review_row"] == 1
    assert result["partial"] is False
    assert set(result["keys_read"]) == {P_PREFS, P_JSON, P_GZ, P_DB}
    assert result["skipped_keys"]["review_row"] == [P_REVIEW]
    text = json.dumps(result)
    for secret in (JWT, "u-4711", "K-777", "alice@example.com"):
        assert secret not in text
    # Every device call went to the pinned serial; the review row was never read.
    for argv in env.dev.calls:
        assert argv[1:3] == ["-s", SERIAL]
        assert P_REVIEW not in " ".join(argv)
    # One timeline audit line, no content in it.
    (args, kw) = env.lines[-1]
    assert args == ("ai", "files_read")
    assert kw["data"]["read"] == 4
    assert JWT not in json.dumps(kw, default=str)


def test_content_reaches_the_lens_tools_reduced_but_findable(env):
    before = lens_rows.find_rows("files", {"content_contains": "eyJ"})
    assert before["matched"] == 0
    assert before["content_missing"] >= 4
    assert "read_device_files" in before["content_hint"]

    device_content.read_device_files(where={"path_glob": [f"{PKG}/*"]})

    found = lens_rows.find_rows("files", {"content_contains": "eyJ"})
    assert found["keys"] == [P_PREFS]  # a token under a secret-named key
    assert lens_rows.find_rows("files", {"content_contains": "u-4711"})["keys"] == [
        P_PREFS,
        P_GZ,
    ]
    assert lens_rows.find_rows("files", {"content_contains": "alice@"})["keys"] == [
        P_DB
    ]
    got = lens_rows.get_rows("files", keys=[P_PREFS, P_JSON, P_DB])
    digests = {r["key"]: r["digest"] for r in got["rows"]}
    assert f"auth_token = [jwt, {len(JWT)} chars]" in digests[P_PREFS]
    assert "content read from device" in digests[P_PREFS]
    assert JWT not in digests[P_PREFS]
    assert "user_id = u-4711" in digests[P_PREFS]
    assert "K-777" not in digests[P_JSON]
    assert '"device_id":"d-1"' in digests[P_JSON]
    assert "accounts (1 rows)" in digests[P_DB]
    assert got["rows"][0]["content"] == "content"


def test_second_call_uses_the_cache_until_the_file_changes(env):
    device_content.read_device_files()
    reads = len(env.dev.procs)
    again = device_content.read_device_files()
    assert again["read"] == 0
    assert again["cached"] == 5  # the png's binary entry too
    assert len(env.dev.procs) == reads  # stat only
    # The device file changed (mtime): read again, the rest stays cached.
    env.dev.files[P_PREFS] = PREFS.replace(b"u-4711", b"u-9999")
    env.dev.mtimes[P_PREFS] += 10
    third = device_content.read_device_files()
    assert third["read"] == 1
    assert third["keys_read"] == [P_PREFS]
    assert third["cached"] == 4
    hits = lens_rows.find_rows("files", {"content_contains": "u-9999"})
    assert hits["keys"] == [P_PREFS]
    # The monitor saw a later write (row last): stale without a stat change.
    env.rows[1]["last"] = 500.0
    assert device_content.read_device_files()["keys_read"] == [P_JSON]
    # refresh reads everything again.
    assert device_content.read_device_files(refresh=True)["read"] == 4


def test_serial_change_invalidates(env, monkeypatch):
    device_content.read_device_files()
    monkeypatch.setattr(df, "current_serial", lambda: "emulator-5580")
    first_new = len(env.dev.calls)
    result = device_content.read_device_files()
    assert result["serial"] == "emulator-5580"
    assert result["cached"] == 0
    assert result["read"] == 4
    assert all(a[1:3] == ["-s", "emulator-5580"] for a in env.dev.calls[first_new:])


def test_max_files_and_total_budget(env):
    one = device_content.read_device_files(max_files=1)
    assert one["read"] == 1
    assert one["skipped"]["budget"] == 4
    assert one["stop_reason"] == "max_files"
    assert one["partial"] is True
    small = device_content.read_device_files(
        refresh=True, max_total_bytes=len(PREFS) + 10
    )
    assert small["read"] == 1  # prefs fits
    assert small["skipped"]["budget"] >= 3
    assert small["bytes_read"] <= len(PREFS) + 10
    assert small["stop_reason"] == "budget"


def test_where_keys_and_validation(env):
    only = device_content.read_device_files(keys=[P_JSON, "/nope"])
    assert only["candidates"] == 1
    assert only["keys_read"] == [P_JSON]
    assert only["unknown_keys"] == ["/nope"]
    globbed = device_content.read_device_files(where={"path_glob": ["*.xml"]})
    assert globbed["candidates"] == 2
    assert globbed["skipped"]["review_row"] == 1
    for bad in ({"max_files": 301}, {"max_bytes_per_file": 0}, {"sqlite": "all"}):
        with pytest.raises(ToolError) as err:
            device_content.read_device_files(**bad)
        assert err.value.code == "invalid_arguments"
    with pytest.raises(ToolError):
        device_content.read_device_files(where={"bogus": 1})


def test_watchlist_is_never_touched(env, monkeypatch):
    from sandroid import services
    from sandroid.core import watchlist_store

    def boom(*a, **k):
        raise AssertionError("watchlist / forensic write")

    for name in ("keep_version", "reset_current", "submit_pulled_version"):
        if hasattr(watchlist_store, name):
            monkeypatch.setattr(watchlist_store, name, boom)
    monkeypatch.setattr(services, "get_forensic_service", boom)
    assert device_content.read_device_files()["read"] == 4


def test_cancel_after_the_first_file_is_partial_and_keeps_the_entry(env):
    ctx = RunContext()
    token = loop._current_run_context.set(ctx)
    try:

        def cancel_after_first(proc):
            ctx.cancel_event.set()

        env.dev.on_read = cancel_after_first
        result = device_content.read_device_files()
    finally:
        loop._current_run_context.reset(token)
    assert result["partial"] is True
    assert result["stop_reason"] == "cancelled"
    assert result["read"] == 1
    assert result["skipped"]["cancelled"] >= 1
    assert df.load_entry(result["keys_read"][0], env.root) is not None


def test_world_lease_answers_busy(env):
    arbiter = arb.get_arbiter()
    claimed = arbiter.claim("someone", frozenset({arb.ResourceId.WORLD}))
    assert claimed == frozenset({arb.ResourceId.WORLD})
    before = arbiter.snapshot()
    with pytest.raises(ToolError) as err:
        device_content.read_device_files()
    assert err.value.code == "busy"
    assert arbiter.snapshot() == before
    assert env.dev.calls == []


def test_mask_on_withholds_digests_when_redaction_fails(env, monkeypatch):
    device_content.read_device_files()
    monkeypatch.setattr("sandroid.ai.row_classifier.mask_enabled", lambda: True)

    def boom(text):
        raise RuntimeError("no redactor")

    monkeypatch.setattr("sandroid.ai.safety.redact_secrets", boom)
    got = lens_rows.get_rows("files", keys=[P_PREFS])
    assert got["rows"][0]["digest"].startswith("[digest withheld")
    # Local matching still works (nothing is sent).
    assert lens_rows.find_rows("files", {"content_contains": "eyJ"})["keys"] == [
        P_PREFS
    ]


def test_deadline_stops_early(env, monkeypatch):
    monkeypatch.setattr("sandroid.ai.loop.tool_time_remaining", lambda: 1.0)
    result = device_content.read_device_files()
    assert result["stop_reason"] == "deadline"
    assert result["partial"] is True
    assert result["read"] == 0
