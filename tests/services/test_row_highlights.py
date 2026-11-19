"""Tests for sandroid.services.row_highlights (the AI highlight store)."""

from __future__ import annotations

import json
import stat
import threading
import time

import pytest

from sandroid.services import row_highlights as rh
from sandroid.services.row_highlights import (
    MAX_KEYS_PER_SET,
    MAX_SETS_PER_LENS,
    HighlightError,
    HighlightStore,
)
from sandroid.tui.row_annotations import PRIORITY_AI, RowAnnotationRegistry


class _Calls(list):
    reg: RowAnnotationRegistry


@pytest.fixture
def notes(monkeypatch):
    """A private annotation registry; returns the recorded notify calls."""
    reg = RowAnnotationRegistry()
    calls = _Calls()
    calls.reg = reg
    reg.subscribe(lambda lens, keys: calls.append((lens, keys)))
    monkeypatch.setattr(rh, "registry", lambda: reg)
    return calls


@pytest.fixture
def store(notes):
    return HighlightStore()


def test_create_assigns_ids_slots_and_short_labels(store):
    a = store.create("network", "POST requests to api.example.com", reasons={"f1": "x"})
    b = store.create("network", "tracking", reasons={})
    c = store.create("files", "personal data")
    assert (a.id, a.slot) == ("h1", 1)
    assert (b.id, b.slot) == ("h2", 2)
    assert (c.id, c.slot) == ("h3", 1)
    assert len(a.short) <= 14
    assert a.short == "POST requests"
    assert [s.id for s in store.sets("network")] == ["h1", "h2"]


def test_lowest_free_slot_and_ids_never_reused(store):
    for i in range(MAX_SETS_PER_LENS):
        store.create("network", f"s{i}")
    with pytest.raises(HighlightError, match="already has 4"):
        store.create("network", "too many")
    store.remove("h2")
    new = store.create("network", "again")
    assert new.slot == 2
    assert new.id == "h5"


def test_bad_lens_unknown_set_and_key_cap(store):
    with pytest.raises(HighlightError):
        store.create("timeline", "x")
    with pytest.raises(HighlightError):
        store.add("h9", {"a": "b"})
    with pytest.raises(HighlightError):
        store.create(
            "network", "big", reasons={f"k{i}": "" for i in range(MAX_KEYS_PER_SET + 1)}
        )
    hs = store.create("network", "x", reasons={f"k{i}": "" for i in range(4999)})
    store.add(hs.id, {"k0": "again"})  # existing key: no growth
    with pytest.raises(HighlightError):
        store.add(hs.id, {"n1": "", "n2": ""})


def test_add_remove_replace_and_lookup(store):
    hs = store.create("network", "x", reasons={"f1": "first"})
    assert store.add(hs.id, {"f2": "second", "f3": "third"}) == 3
    assert store.remove_keys(hs.id, ["f1", "nope"]) == 2
    assert store.lookup("network", "f2") == ((hs.id, 1, "x", "second"),)
    assert store.lookup("network", "f1") == ()
    assert store.replace_keys(hs.id, {"f9": "nine"}) == 1
    assert store.lookup("network", "f2") == ()
    assert store.keys(hs.id) == ["f9"]


def test_reasons_are_clipped_and_files_keys_canonical(store):
    hs = store.create(
        "files",
        "x",
        reasons={"/data/user/0/com.a/shared_prefs/p.xml": "r" * 300},
    )
    (key,) = store.keys(hs.id)
    assert key == "/data/data/com.a/shared_prefs/p.xml"
    assert len(store.get(hs.id).reasons[key]) == 120


def test_annotations_and_filter_priority(store):
    a = store.create("network", "aa", reasons={"f1": "ra"})
    b = store.create("network", "bb", reasons={"f1": "rb"}, filter=True)
    notes_ = store.annotations_for("network", "f1")
    assert [n.group for n in notes_] == [b.id, a.id]
    first = notes_[0]
    assert first.source == "ai"
    assert first.colour_role == "highlight_2" == first.tint_role
    assert first.tint_amount == pytest.approx(0.18)
    assert first.priority == PRIORITY_AI + 1
    assert notes_[1].priority == PRIORITY_AI
    assert store.annotations_for("network", "f2") == []
    assert store.annotations_for("files", "f1") == []


def test_filter_predicate_one_per_lens(store):
    a = store.create("network", "a", reasons={"f1": ""})
    b = store.create("network", "b", reasons={"f2": ""})
    assert store.filter_predicate("network") is None
    store.set_filter("network", a.id)
    pred = store.filter_predicate("network")
    assert pred("f1")
    assert not pred("f2")
    assert store.filter_predicate("network") is pred  # cached per revision
    store.set_filter("network", b.id)
    assert store.filter_set("network") == b.id
    pred = store.filter_predicate("network")
    assert pred("f2")
    assert not pred("f1")
    with pytest.raises(HighlightError):
        store.set_filter("files", b.id)
    store.set_filter("network", None)
    assert store.filter_predicate("network") is None
    store.set_filter("network", b.id)
    store.remove(b.id)
    assert store.filter_set("network") is None


def test_registry_passes_with_store_registered(store, notes):
    notes.reg.register(store)
    hs = store.create("files", "x", reasons={"/sdcard/a": ""}, filter=True)
    assert notes.reg.passes("files", "/sdcard/a")
    assert not notes.reg.passes("files", "/sdcard/b")
    assert notes.reg.passes("network", "anything")
    assert notes.reg.tint_for("files", "/sdcard/a") == ("highlight_1", 0.18)
    store.clear("files")
    assert store.get(hs.id) is None
    assert notes.reg.passes("files", "/sdcard/b")


def test_notify_after_mutations(store, notes):
    hs = store.create("network", "x", reasons={"f1": ""})
    # A new set changes the bar / column / filter: the whole lens redraws.
    assert notes[-1] == ("network", None)
    store.add(hs.id, {"f2": ""})
    assert notes[-1] == ("network", frozenset({"f2"}))
    store.finish(hs.id, complete=False, stats={"scanned": 3})
    assert notes[-1] == ("network", None)
    assert store.get(hs.id).complete is False
    assert store.get(hs.id).stats == {"scanned": 3}
    empty = store.create("network", "empty")
    assert notes[-1] == ("network", None)
    store.remove(empty.id)
    assert notes[-1] == ("network", None)
    rev = store.revision
    store.clear()
    assert store.revision > rev
    assert notes[-1] == (None, None)


def test_notify_runs_outside_the_lock(notes):
    store = HighlightStore()
    seen: list[bool] = []

    def listener(lens, keys):
        # Another thread must be able to take the lock while we are notified.
        t = threading.Thread(target=lambda: seen.append(bool(store.sets())))
        t.start()
        t.join(1.0)
        seen.append(not t.is_alive())

    notes.reg.subscribe(listener)
    store.create("network", "x", reasons={"f1": ""})
    assert seen
    assert seen[-1] is True


def test_copies_are_detached(store):
    hs = store.create("network", "x", reasons={"f1": ""})
    copy = store.get(hs.id)
    copy.reasons["f2"] = "y"
    assert store.keys(hs.id) == ["f1"]


def test_persistence_round_trip(tmp_path, notes):
    store = HighlightStore()
    store.bind_folder(tmp_path)
    a = store.create(
        "network", "posts", reasons={"f1": "r"}, origin="structural", filter=True
    )
    store.create("files", "pii", reasons={"/sdcard/x": "email"}, origin="ai")
    store.finish(a.id, complete=False, stats={"scanned": 9})
    path = tmp_path / "ai" / "highlights.json"
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    data = json.loads(path.read_text())
    assert data["filters"] == {"network": "h1"}

    other = HighlightStore()
    other.bind_folder(tmp_path)
    assert [s.id for s in other.sets()] == ["h1", "h2"]
    loaded = other.get("h1")
    assert loaded.complete is False
    assert loaded.stats == {"scanned": 9}
    assert other.filter_set("network") == "h1"
    assert other.lookup("files", "/sdcard/x") == (("h2", 1, "pii", "email"),)
    # ids are not reused after a reload
    assert other.create("files", "next").id == "h3"


def test_bind_folder_switches_sessions(tmp_path, notes):
    one, two = tmp_path / "one", tmp_path / "two"
    store = HighlightStore()
    store.create("network", "memory only")  # unbound: memory
    store.bind_folder(None)
    assert len(store.sets()) == 1  # None while never bound keeps memory
    store.bind_folder(one)
    assert store.sets() == []
    store.create("network", "in one", reasons={"f1": ""})
    store.bind_folder(two)
    assert store.sets() == []
    assert store.lookup("network", "f1") == ()
    assert notes[-1] == (None, None)
    store.bind_folder(one)
    assert [s.label for s in store.sets()] == ["in one"]
    store.bind_folder(one)  # same folder: no reload, no notify
    store.bind_folder(None)
    assert store.sets() == []
    assert store.path is None


def test_corrupt_file_starts_empty(tmp_path, notes):
    path = tmp_path / "ai" / "highlights.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not json")
    store = HighlightStore()
    store.bind_folder(tmp_path)
    assert store.sets() == []


class _Dispatcher:
    """Runs posted callables on its own thread (like the UI loop)."""

    def __init__(self, delay: float = 0.0, accept: bool = True):
        self.delay = delay
        self.accept = accept
        self.threads: list[str] = []

    def post(self, fn, *args):
        if not self.accept:
            return False

        def run():
            time.sleep(self.delay)
            self.threads.append(threading.current_thread().name)
            fn(*args)

        threading.Thread(target=run, name="fake-ui", daemon=True).start()
        return True


def test_snapshot_rows_runs_on_the_dispatcher(store):
    disp = _Dispatcher()
    rows = [{"key": "f1", "shown": True}]
    store.register_row_source("network", lambda: rows, disp)
    got = store.snapshot_rows("network")
    assert got == rows
    assert got[0] is not rows[0]
    assert disp.threads == ["fake-ui"]
    assert store.snapshot_rows("files") is None


def test_snapshot_rows_timeout_and_unposted(store):
    slow = _Dispatcher(delay=0.5)
    store.register_row_source("network", lambda: [{"key": "a"}], slow)
    assert store.snapshot_rows("network", timeout=0.05) is None
    fn = list
    store.register_row_source("files", fn, _Dispatcher(accept=False))
    assert store.snapshot_rows("files") is None
    store.unregister_row_source("files", fn)
    assert not store.has_row_source("files")


def test_snapshot_rows_without_dispatcher_and_failing_source(store):
    store.register_row_source("network", lambda: [{"key": "a"}], None)
    assert store.snapshot_rows("network") == [{"key": "a"}]

    def boom():
        raise RuntimeError("x")

    store.register_row_source("network", boom, None)
    assert store.snapshot_rows("network") is None


def test_singleton_registers_into_registry(monkeypatch, notes):
    rh.reset_for_tests()
    monkeypatch.setattr("sandroid.ai.results.session_root", lambda: None)
    try:
        store = rh.get_row_highlights()
        assert rh.get_row_highlights() is store
        assert notes.reg.provider("ai") is store
    finally:
        rh.reset_for_tests()
    assert notes.reg.provider("ai") is None
