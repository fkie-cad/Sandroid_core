"""Tests for sandroid.ai.results: R-id store, session root and result shaping."""

import json
import os
import stat
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sandroid.ai import results
from sandroid.ai.results import (
    ResultStore,
    TurnBudget,
    estimate_tokens,
    get_result_store,
    read_stored_result,
    session_root,
    shape_result,
)


@pytest.fixture(autouse=True)
def _reset_stores():
    results.reset_for_tests()
    yield
    results.reset_for_tests()


# ---------------------------------------------------------------------------
# session_root
# ---------------------------------------------------------------------------


def _patch_service(monkeypatch, service):
    from sandroid import services

    monkeypatch.setattr(services, "get_initialization_service", lambda: service)


def test_session_root_uses_session_path(monkeypatch, tmp_path):
    session = SimpleNamespace(session_path=tmp_path / "20261119_120000")
    _patch_service(monkeypatch, SimpleNamespace(get_current_session=lambda: session))
    assert session_root() == (tmp_path / "20261119_120000").absolute()
    # Nothing is created by asking.
    assert not (tmp_path / "20261119_120000").exists()


def test_session_root_is_none_without_session(monkeypatch):
    _patch_service(monkeypatch, SimpleNamespace(get_current_session=lambda: None))
    assert session_root() is None


def test_session_root_is_none_when_service_fails(monkeypatch):
    def boom():
        raise RuntimeError("no service")

    from sandroid import services

    monkeypatch.setattr(services, "get_initialization_service", boom)
    assert session_root() is None


# ---------------------------------------------------------------------------
# ResultStore
# ---------------------------------------------------------------------------


def test_store_is_lazy_private_and_records_full_metadata(tmp_path):
    store = ResultStore(tmp_path)
    assert not (tmp_path / "ai").exists()
    stored = store.put(
        "list_processes",
        {"package_filter": "x"},
        {"rows": [1]},
        agent_id="orchestrator",
    )
    assert stored.id == "R1"
    folder = tmp_path / "ai" / "results"
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "ai").stat().st_mode) == 0o700
    path = folder / "R1.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    record = json.loads(path.read_text())
    assert set(record) == {
        "id",
        "tool",
        "args",
        "agent_id",
        "ts",
        "sha256",
        "bytes",
        "result",
    }
    assert record["agent_id"] == "orchestrator"
    assert record["bytes"] == stored.bytes
    assert store.get("R1")["result"] == {"rows": [1]}
    assert store.get("R2") is None
    assert store.get("../etc") is None


def test_store_serialises_odd_values_with_default_str(tmp_path):
    store = ResultStore(tmp_path)
    rid = store.put("t", {"p": Path("/x")}, {"when": object}).id
    assert "class 'object'" in store.get(rid)["result"]["when"]


def test_concurrent_puts_get_unique_sequential_ids(tmp_path):
    store = ResultStore(tmp_path)
    ids: list[str] = []
    lock = threading.Lock()

    def worker(n):
        for i in range(25):
            rid = store.put("t", {}, {"n": n, "i": i}).id
            with lock:
                ids.append(rid)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(ids)) == 200
    assert sorted(int(r[1:]) for r in ids) == list(range(1, 201))


def test_reopen_continues_after_max_and_skips_taken_ids(tmp_path):
    first = ResultStore(tmp_path)
    for _ in range(3):
        first.put("t", {}, "x")
    (tmp_path / "ai" / "results" / "R2.json").unlink()
    reopened = ResultStore(tmp_path)
    assert reopened.put("t", {}, "y").id == "R4"
    # A second store on the same folder never overwrites (O_EXCL).
    assert first.put("t", {}, "z").id == "R5"
    assert reopened.ids() == ["R1", "R3", "R4", "R5"]


def test_in_memory_mode_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = get_result_store(None)
    assert store.persistent is False
    rid = store.put("t", {}, {"a": 1}).id
    assert store.get(rid)["result"] == {"a": 1}
    assert list(tmp_path.iterdir()) == []


def test_get_result_store_is_shared_per_root(tmp_path):
    assert get_result_store(tmp_path) is get_result_store(tmp_path)
    assert get_result_store(tmp_path) is not get_result_store(None)


# ---------------------------------------------------------------------------
# shape_result
# ---------------------------------------------------------------------------


def test_small_result_is_inlined_with_rid():
    content = json.loads(shape_result({"pid": 4}, "R3", cap_tokens=8000))
    assert content == {"pid": 4, "_rid": "R3"}
    listed = json.loads(shape_result([1, 2], "R4", cap_tokens=8000))
    assert listed == {"result": [1, 2], "_rid": "R4"}


def _big_flows(n=3000):
    return {
        "count": n,
        "flows": [
            {
                "id": i,
                "host": f"api{i % 3}.example.com",
                "method": "POST" if i % 4 else "GET",
                "url": f"https://api{i % 3}.example.com/v1/item/{i}",
                "status": 500 if i == 1777 else 200,
                "note": "Exception: boom" if i == 1777 else "ok",
            }
            for i in range(n)
        ],
    }


def test_large_result_gets_capped_selected_preview():
    result = _big_flows()
    content = shape_result(result, "R9", cap_tokens=8000, keywords=["item/2999"])
    assert estimate_tokens(content) <= 8000
    preview = json.loads(content)
    assert preview["truncated"] is True
    assert preview["result_id"] == "R9"
    assert preview["bytes"] > 32_000
    assert "read_result('R9'" in preview["hint"]
    structure = preview["structure"]
    assert structure["keys"]["count"] == 3000
    largest = structure["largest_array"]
    assert largest["key"] == "flows"
    assert largest["rows"] == 3000
    assert "host" in largest["columns"]
    assert ["GET", 750] in largest["top_values"]["method"]
    hits = preview["hits"]
    assert any("Exception: boom" in line for line in hits["error_lines"])
    assert any("item/2999" in line for line in hits["keyword_lines"])
    assert "https://api0.example.com/v1/item/0" in hits["urls"]
    assert preview["head"]
    assert preview["tail"]


def test_one_mib_host_file_result_is_capped():
    text = "\n".join(f"line {i} com.example.app GET /path" for i in range(40_000))
    result = {
        "path": "/data/share/big.log",
        "size_bytes": 1024 * 1024,
        "truncated": False,
        "content": text[: 1024 * 1024],
    }
    content = shape_result(result, "R1", cap_tokens=8000)
    assert estimate_tokens(content) <= 8000
    preview = json.loads(content)
    assert preview["structure"]["keys"]["path"] == "/data/share/big.log"
    assert preview["structure"]["keys"]["content"].startswith("string[")
    assert "com.example.app" in preview["hits"]["packages"]


def test_small_cap_still_fits():
    content = shape_result(_big_flows(500), "R2", cap_tokens=1000)
    assert estimate_tokens(content) <= 1000


def test_turn_budget_turns_results_into_compact_previews():
    budget = TurnBudget(3000)
    medium = {"rows": ["x" * 50 for _ in range(150)]}  # ~2.3k tokens
    first = json.loads(shape_result(medium, "R1", cap_tokens=8000, budget=budget))
    assert "truncated" not in first
    second = json.loads(shape_result(medium, "R2", cap_tokens=8000, budget=budget))
    assert second["truncated"] is True
    assert "budget" in second["reason"]
    assert estimate_tokens(json.dumps(second)) <= results.COMPACT_PREVIEW_TOKENS
    # Tiny results stay inline even with the budget spent.
    tiny = json.loads(shape_result({"ok": True}, "R3", cap_tokens=8000, budget=budget))
    assert tiny == {"ok": True, "_rid": "R3"}
    assert budget.remaining < results.COMPACT_PREVIEW_TOKENS


def test_config_defaults_without_ai_context(monkeypatch):
    from sandroid import config

    monkeypatch.setattr(config, "get_config", lambda: SimpleNamespace(ai=object()))
    assert results.result_cap_tokens() == 8000
    assert results.turn_result_budget_tokens() == 25000
    ai = SimpleNamespace(context=SimpleNamespace(result_cap_tokens=4000))
    monkeypatch.setattr(config, "get_config", lambda: SimpleNamespace(ai=ai))
    assert results.result_cap_tokens() == 4000


# ---------------------------------------------------------------------------
# read_stored_result
# ---------------------------------------------------------------------------


def test_read_result_pages_and_caps(tmp_path):
    store = ResultStore(tmp_path)
    big = "abcdefghij" * 20_000
    rid = store.put("read_host_file", {}, big).id
    page = read_stored_result(store, rid, cap_tokens=1000)
    assert page["offset"] == 0
    assert page["length"] <= 3500
    assert page["next_offset"] == page["length"]
    nxt = read_stored_result(
        store, rid, offset=page["next_offset"], length=10, cap_tokens=1000
    )
    assert nxt["content"] == big[page["length"] : page["length"] + 10]
    huge = read_stored_result(store, rid, length=10**9, cap_tokens=1000)
    assert huge["length"] == page["length"]
    last = read_stored_result(store, rid, offset=len(big) - 5, cap_tokens=1000)
    assert last["next_offset"] is None
    assert last["content"] == big[-5:]


def test_read_result_grep_finds_lines_with_locations(tmp_path):
    store = ResultStore(tmp_path)
    rid = store.put("t", {}, {"content": "a\nneedle one\nb\nNEEDLE two"}).id
    out = read_stored_result(store, rid, grep="needle")
    assert out["match_count"] == 2
    assert out["matches"] == ["content:2: needle one", "content:4: NEEDLE two"]
    literal = read_stored_result(store, rid, grep="needle (")
    assert literal["match_count"] == 0


def test_read_result_unknown_id_is_an_error(tmp_path):
    store = ResultStore(tmp_path)
    out = read_stored_result(store, "R77")
    assert out["error"]["code"] == "invalid_arguments"
    assert not os.path.exists(tmp_path / "ai")


@pytest.mark.parametrize(
    "pattern", ["(a+)+$", "(a*)*b", "(a|aa)+$", "(?:x+){2,}", "(a)\\1", "x" * 201]
)
def test_grep_refuses_catastrophic_patterns_without_running_them(tmp_path, pattern):
    store = ResultStore(tmp_path)
    rid = store.put("t", {}, {"x": "a" * 28 + "!"}).id
    started = time.monotonic()
    out = read_stored_result(store, rid, grep=pattern)
    assert time.monotonic() - started < 0.5
    assert out["error"]["code"] == "invalid_arguments"


def test_grep_searches_long_lines_in_bounded_windows_within_a_budget(
    tmp_path, monkeypatch
):
    store = ResultStore(tmp_path)
    tail = "x" * 3000 + " needle at the end"
    rid = store.put("t", {}, {"rows": ["a" * 5000] * 40 + [tail]}).id
    # A match far beyond one search window is still found...
    found = read_stored_result(store, rid, grep="needle")
    assert found["match_count"] == 1
    # ...and a slow (polynomial) pattern stops at the time budget instead of
    # freezing the process.
    monkeypatch.setattr(results, "GREP_TIME_BUDGET_S", 0.3)
    started = time.monotonic()
    slow = read_stored_result(store, rid, grep=".*a.*b")
    assert time.monotonic() - started < 2.0
    assert slow["truncated"] is True
    assert "stopped" in slow["note"]
