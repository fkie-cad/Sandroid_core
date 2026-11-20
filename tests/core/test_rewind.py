"""Rewind core (``core/rewind.py``) and the step replay (``features/player.py``).

No device: every device call goes through fakes. Covers the file lists, the
Review list, start point names, role diffs and verdicts, the request
matching, the Rewind order, the element matcher and the step replay.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sandroid.core import rewind
from sandroid.features import player
from sandroid.features.player import (
    Step,
    StepReplayer,
    extract_steps,
    find_element,
    input_text_arg,
)

# ---------------------------------------------------------------------------
# names, file lists, Review list
# ---------------------------------------------------------------------------


def test_start_point_names_are_the_only_deletable_ones():
    from datetime import datetime

    name = rewind.start_point_name(datetime(2026, 11, 20, 13, 36, 2))
    assert name == "sandroid_rec_20261120_133602"
    assert rewind.is_start_point_name(name)
    for other in ("clean_8g", "tmp", "default_boot", "sandroid_rec_x", None, ""):
        assert not rewind.is_start_point_name(other)


def test_default_name_is_recording_hh_mm():
    from datetime import datetime

    assert rewind.default_name(datetime(2026, 1, 1, 9, 5)) == "Recording 09:05"


def test_file_list_command_quotes_and_validates_the_package():
    cmd = rewind.file_list_command("org.mozilla.firefox")
    assert "/data/data/org.mozilla.firefox" in cmd
    assert "stat -c '%s %Y %y %n'" in cmd
    with pytest.raises(ValueError):
        rewind.file_list_command("a; rm -rf /")


def test_parse_file_list_keeps_spaces_and_subseconds():
    text = (
        "96000 1763642162 2026-11-20 13:36:02.123456789 +0100 "
        "/data/data/p/files/my cookies.sqlite\n"
        "12 1763642100 /data/data/p/short\n"
        "garbage line\n"
    )
    facts = rewind.parse_file_list(text)
    fact = facts["/data/data/p/files/my cookies.sqlite"]
    assert fact.size == 96000
    assert fact.stamp.endswith(".123456789 +0100")
    assert facts["/data/data/p/short"].size == 12


def test_diff_file_lists_new_changed_deleted_in_order():
    F = rewind.FileFact
    start = {
        "/a/same": F(1, 10, "t1"),
        "/a/changed": F(1, 10, "t1"),
        "/a/gone": F(5, 10, "t1"),
        "/a/touched": F(1, 10, "t1"),
    }
    stop = {
        "/a/same": F(1, 10, "t1"),
        "/a/changed": F(2, 20, "t2"),
        "/a/new": F(3, 30, "t3"),
        "/a/touched": F(1, 10, "t1.5"),  # same size, newer sub-second stamp
    }
    out = rewind.diff_file_lists(start, stop)
    assert [(e["path"], e["state"]) for e in out] == [
        ("/a/changed", "changed"),
        ("/a/touched", "changed"),
        ("/a/new", "new"),
        ("/a/gone", "deleted"),
    ]


def test_monitor_changes_and_merge():
    lines = [
        {"src": "files", "kind": "create", "data": {"path": "/data/data/p/x"}},
        {"src": "files", "kind": "modify", "data": {"path": "/data/data/p/x"}},
        {"src": "files", "kind": "modify", "data": {"path": "/sdcard/Download/y"}},
        {
            "src": "files",
            "kind": "create",
            "data": {"path": "/data/data/p/d", "dir": 1},
        },
        {"src": "input", "kind": "tap", "data": {}},
    ]
    mon = rewind.monitor_changes(lines, "p")
    by = {e["path"]: e for e in mon}
    assert by["/data/data/p/x"]["state"] == "new"  # created, then written
    assert by["/sdcard/Download/y"]["outside_app"] is True
    assert "/data/data/p/d" not in by
    listed = [{"path": "/data/user/0/p/x", "state": "new", "mtime": 5, "size": 1}]
    merged = rewind.merge_changes(listed, mon)
    assert len(merged) == 2  # /data/user/0 is /data/data: one row
    by_merged = {e["path"]: e for e in merged}
    assert by_merged["/data/user/0/p/x"]["source"] == "list+monitor"


def test_app_pids_finds_main_and_sub_processes():
    ps = "  PID NAME\n 100 org.x\n 101 org.x:tab\n 102 org.xy\n 103 other\n"
    assert rewind.app_pids(ps, "org.x") == [100, 101]


def test_recording_round_trips_through_json(tmp_path, monkeypatch):
    monkeypatch.setattr(rewind, "recordings_root", lambda: tmp_path)
    rec = rewind.Recording(rec_id="rec-1", name="R", pkg="p", serial="emulator-5560")
    rec.set_role("/a", "before", "v002")
    rec.set_role("/a", "after_replay", "v003")
    rec.set_role("/a", "after_replay", "v004")
    rewind.save_recording(rec)
    back = rewind.load_recording("rec-1")
    assert back is not None
    assert back.role_version("/a", "before") == "v002"
    assert back.role_version("/a", "after_replay") == "v004"
    with pytest.raises(ValueError):
        rewind.recording_dir("../etc")


def test_disk_problem_needs_ram_plus_margin(tmp_path, monkeypatch):
    (tmp_path / "config.ini").write_text("hw.ramSize=8192\n")
    usage = type("U", (), {"free": 12 * 1024**3})
    monkeypatch.setattr(rewind.shutil, "disk_usage", lambda _p: usage)
    assert "needs about 18 GB" in rewind.disk_problem(tmp_path)
    usage.free = 40 * 1024**3
    assert rewind.disk_problem(tmp_path) is None


# ---------------------------------------------------------------------------
# role diffs and verdicts (Before is pulled after After: never backwards)
# ---------------------------------------------------------------------------


@pytest.fixture
def files_root(tmp_path, monkeypatch):
    from sandroid.core import watchlist_store

    monkeypatch.setenv(watchlist_store.FILES_DIR_ENV, str(tmp_path / "files"))
    return tmp_path / "files"


def _version(path: str, name: str, content: bytes) -> str:
    from sandroid.core import watchlist_store

    folder = watchlist_store.row_dir(path) / name
    folder.mkdir(parents=True, exist_ok=True)
    (folder / Path(path).name).write_bytes(content)
    return name


def test_role_diff_reads_before_to_after_even_when_before_is_newer(files_root):
    path = "/data/data/p/files/prefs.txt"
    after = _version(path, "v001_10-00-00", b"consent=yes\n")
    before = _version(path, "v002_10-01-00", b"consent=no\n")
    rec = rewind.Recording(rec_id="rec-1", name="R", pkg="p", serial="s")
    rec.set_role(path, "after", after)
    rec.set_role(path, "before", before)
    res = rewind.file_result(rec, path)
    assert res.verdict == rewind.NO_REPLAY
    removed = [ln for ln in res.action_text.splitlines() if "consent=no" in ln]
    added = [ln for ln in res.action_text.splitlines() if "consent=yes" in ln]
    assert removed
    assert added
    assert res.action_text.index("consent=no") < res.action_text.index("consent=yes")


def test_verdicts_same_different_unchanged(files_root):
    path = "/data/data/p/files/a.txt"
    before = _version(path, "v001_10-00-00", b"x\n")
    after = _version(path, "v002_10-01-00", b"x\ny\n")
    other = _version(path, "v003_10-02-00", b"x\nz\n")
    rec = rewind.Recording(rec_id="rec-1", name="R", pkg="p", serial="s")
    rec.set_role(path, "before", before)
    rec.set_role(path, "after", after)
    rec.set_role(path, "after_replay", after)
    assert rewind.file_result(rec, path).verdict == rewind.SAME
    rec.set_role(path, "after_replay", other)
    res = rewind.file_result(rec, path)
    assert res.verdict == rewind.DIFFERENT
    assert any("y" in ln for ln in res.only_run)
    assert any("z" in ln for ln in res.only_replay)
    rec.set_role(path, "after_replay", before)
    assert rewind.file_result(rec, path).verdict == rewind.UNCHANGED


def test_new_and_deleted_files_are_results_not_errors(files_root):
    path = "/data/data/p/files/new.txt"
    after = _version(path, "v001_10-00-00", b"hello\n")
    rec = rewind.Recording(rec_id="rec-1", name="R", pkg="p", serial="s")
    rec.set_role(path, "after", after)
    rec.set_role(path, "before", rewind.ABSENT)
    res = rewind.file_result(rec, path)
    assert "did not exist before" in res.action_text
    assert not res.error
    rec2 = rewind.Recording(rec_id="rec-2", name="R", pkg="p", serial="s")
    rec2.set_role(path, "before", after)
    rec2.set_role(path, "after", rewind.ABSENT)
    assert "deleted" in rewind.file_result(rec2, path).action_text


def test_binary_and_sqlite_files_get_a_diff(files_root, tmp_path):
    path = "/data/data/p/files/blob.bin"
    rec = rewind.Recording(rec_id="rec-1", name="R", pkg="p", serial="s")
    rec.set_role(path, "before", _version(path, "v001_10-00-00", b"\x00\x01\x02"))
    rec.set_role(path, "after", _version(path, "v002_10-00-01", b"\x00\x09\x02\x03"))
    res = rewind.file_result(rec, path)
    assert res.action_text
    assert not res.error

    db = "/data/data/p/databases/c.sqlite"
    for name, rows in (("v001_10-00-00", []), ("v002_10-00-01", [("a", "1")])):
        from sandroid.core import watchlist_store

        folder = watchlist_store.row_dir(db) / name
        folder.mkdir(parents=True)
        con = sqlite3.connect(folder / "c.sqlite")
        con.execute("create table cookies (name text primary key, value text)")
        con.executemany("insert into cookies values (?, ?)", rows)
        con.commit()
        con.close()
    rec.set_role(db, "before", "v001_10-00-00")
    rec.set_role(db, "after", "v002_10-00-01")
    text = rewind.file_result(rec, db).action_text
    assert "cookies" in text


def test_result_lines_use_the_plain_words():
    res = rewind.FileResult("/a", "v1", "v2", "v3", "x", "y", rewind.DIFFERENT)
    res.only_run = ["+ a"]
    lines = rewind.result_lines(res)
    assert lines[0] == "What your action changed (Before to After):"
    assert any("only in your run" in ln for ln in lines)
    assert lines[-1] == f"Result: {rewind.DIFFERENT}"


# ---------------------------------------------------------------------------
# requests: Review rows and the replay comparison
# ---------------------------------------------------------------------------


def _flow(seq, method, host, path, status=200, fid=None):
    return {
        "src": "net",
        "kind": "flow",
        "seq": seq,
        "ref": {"id": fid or f"f{seq}"},
        "data": {"method": method, "host": host, "path": path, "status": status},
    }


def _detail(body: str, headers=None):
    return {
        "request_headers": headers or [["content-type", "text/plain"]],
        "request_body": {"content": body, "encoding": "utf-8", "bytes_read": len(body)},
    }


def test_flow_matched_in_the_replay():
    orig = rewind.requests_in([_flow(1, "POST", "c.example", "/v1/consent")])
    replay = rewind.requests_in([_flow(9, "POST", "c.example", "/v1/consent", 200)])
    details = {"f1": _detail("ok=1"), "f9": _detail("ok=1")}
    res = rewind.compare_flow(orig[0], replay, details.get)
    assert res.found == "found in the replay"
    assert res.body == "same"
    assert res.status == "same"
    assert res.sides["your run"]["url"] == "POST c.example/v1/consent"
    assert res.sides["replay"]["headers"] == ["content-type: text/plain"]


def test_flow_not_seen_in_the_replay():
    orig = rewind.requests_in([_flow(1, "POST", "c.example", "/v1/consent")])
    replay = rewind.requests_in([_flow(9, "GET", "c.example", "/v1/consent")])
    res = rewind.compare_flow(orig[0], replay, lambda _id: None)
    assert res.found == "not seen in the replay"
    assert res.replay is None
    assert rewind.flow_result_lines(res) == [
        f"{rewind.request_text(orig[0])}: not seen in the replay"
    ]


def test_duplicate_flows_are_matched_by_order():
    orig = rewind.requests_in(
        [_flow(1, "GET", "h", "/p", 200), _flow(2, "GET", "h", "/p", 204)]
    )
    replay = rewind.requests_in(
        [
            _flow(10, "GET", "h", "/other"),
            _flow(11, "GET", "h", "/p", 200),
            _flow(12, "GET", "h", "/p", 500),
        ]
    )
    assert [r["order"] for r in orig] == [0, 1]
    second = rewind.compare_flow(orig[1], replay, lambda _id: _detail("a"))
    assert second.replay["seq"] == 12
    assert second.status == "different"
    first = rewind.compare_flow(orig[0], replay, lambda _id: _detail("a"))
    assert first.replay["seq"] == 11
    assert first.status == "same"


def test_flow_body_different_and_not_captured():
    orig = rewind.requests_in([_flow(1, "POST", "h", "/p")])
    replay = rewind.requests_in([_flow(2, "POST", "h", "/p")])
    details = {"f1": _detail("a=1"), "f2": _detail("a=2")}
    assert rewind.compare_flow(orig[0], replay, details.get).body == "different"
    assert rewind.compare_flow(orig[0], replay, lambda _i: None).body == "not captured"


def test_no_network_data_gives_no_requests():
    lines = [{"src": "input", "kind": "tap", "seq": 1, "data": {}}]
    assert rewind.requests_in(lines) == []


# ---------------------------------------------------------------------------
# the Rewind order (fake device)
# ---------------------------------------------------------------------------


class FakeDevice:
    def __init__(self, *, load_ok=True, pull_error_on=None, absent=()):
        self.calls: list[str] = []
        self.load_ok = load_ok
        self.pull_error_on = pull_error_on
        self.absent = set(absent)
        self.cancel = False

    def deps(self, replay=None) -> rewind.RewindDeps:
        return rewind.RewindDeps(
            load_snapshot=self.load,
            shell=self.shell,
            pull=self.pull,
            after_load=lambda: self.calls.append("reset"),
            stop_monitor=lambda: self.calls.append("monitor-stop") or "cfg",
            progress=lambda t: None,
            cancelled=lambda: self.cancel,
            replay=replay,
            clock_fix=lambda: self.calls.append("clock"),
            emit=lambda *a, **k: len(self.calls) + 1,
        )

    def load(self, name, serial):
        self.calls.append(f"load {name}")
        return self.load_ok

    def shell(self, cmd):
        self.calls.append(cmd.split()[0] + " " + cmd.split()[1])
        if cmd.startswith("ps"):
            return " PID NAME\n 10 p\n 11 p:x\n"
        return ""

    def pull(self, path, role, rec_id, run):
        self.calls.append(f"pull {role} {path}")
        if path == self.pull_error_on:
            raise OSError("adb pull failed")
        if path in self.absent:
            return rewind.PullOutcome(rewind.ABSENT)
        return rewind.PullOutcome(f"v-{role}")


def _rec(tmp_path, monkeypatch, **kw):
    monkeypatch.setattr(rewind, "recordings_root", lambda: tmp_path)
    rec = rewind.Recording(
        rec_id="rec-1",
        name="R",
        pkg="p",
        serial="emulator-5560",
        start_point={"name": "sandroid_rec_20261120_100000", "saved_ok": True},
        selected=["/data/data/p/a", "/data/data/p/b"],
        stopped=1.0,
        **kw,
    )
    return rec


def test_rewind_order_and_resume_after_a_failed_pull(tmp_path, monkeypatch):
    dev = FakeDevice(pull_error_on="/data/data/p/a", absent={"/data/data/p/b"})
    rec = _rec(tmp_path, monkeypatch)
    out = rewind.RewindRunner(rec, dev.deps()).run(replay=False)
    assert dev.calls == [
        "monitor-stop",
        "load sandroid_rec_20261120_100000",
        "clock",
        "reset",
        "ps -A",
        "kill -STOP",
        "pull before /data/data/p/a",
        "pull before /data/data/p/b",
        "kill -CONT",
    ]
    assert out.result == "rewound"
    assert out.error is None
    assert out.monitor_config == "cfg"
    assert rec.role_version("/data/data/p/b", "before") == rewind.ABSENT
    assert rec.role_version("/data/data/p/a", "before") is None
    assert rec.runs[-1]["kind"] == "rewind"
    assert (tmp_path / "rec-1" / "recording.json").is_file()


def test_rewind_load_failure_changes_nothing(tmp_path, monkeypatch):
    dev = FakeDevice(load_ok=False)
    rec = _rec(tmp_path, monkeypatch)
    out = rewind.RewindRunner(rec, dev.deps()).run(replay=False)
    assert "Could not go back to the start point" in out.error
    assert not any(c.startswith("pull") for c in dev.calls)
    assert rec.runs[-1]["result"] == "stopped"


def test_rewind_without_a_start_point_stops_at_once(tmp_path, monkeypatch):
    dev = FakeDevice()
    rec = _rec(tmp_path, monkeypatch)
    rec.start_point = {"name": None, "saved_ok": False}
    out = rewind.RewindRunner(rec, dev.deps()).run(replay=False)
    assert out.error == "The start point is gone. Record again to rewind."
    assert dev.calls == []


def test_rewind_replay_pulls_after_replay_and_keeps_stop_reason(tmp_path, monkeypatch):
    dev = FakeDevice()
    rec = _rec(tmp_path, monkeypatch)

    def replay(r, runner):
        dev.calls.append("replay")
        return {"steps": [{"i": 1, "way": "failed"}], "stopped_at_step": 1,
                "error": "Replay stopped at step 1 of 1: x: gone."}  # fmt: skip

    out = rewind.RewindRunner(rec, dev.deps(replay)).run(replay=True)
    assert dev.calls.index("replay") < dev.calls.index(
        "pull after_replay /data/data/p/a"
    )
    assert out.result == "stopped"
    assert out.stopped_at_step == 1
    assert rec.role_version("/data/data/p/a", "after_replay") == "v-after_replay"


def test_rewind_esc_before_the_load(tmp_path, monkeypatch):
    dev = FakeDevice()
    dev.cancel = True
    rec = _rec(tmp_path, monkeypatch)
    out = rewind.RewindRunner(rec, dev.deps()).run(replay=False)
    assert out.error == "you pressed Esc"
    assert not any(c.startswith("load") for c in dev.calls)


# ---------------------------------------------------------------------------
# element matching and the step replay
# ---------------------------------------------------------------------------


def _dump(*nodes, pkg="p"):
    return {
        "windows": [
            {
                "id": 1,
                "type": "app",
                "pkg": pkg,
                "root": {"cls": "android.widget.FrameLayout", "bounds": [0, 0, 1080, 2400],
                         "kids": list(nodes)},
            }
        ]
    }  # fmt: skip


def _node(text=None, rid=None, bounds=(100, 100, 300, 200), cls="android.widget.Button",
          **kw):  # fmt: skip
    return {"cls": cls, "text": text, "rid": rid, "bounds": list(bounds), **kw}


def test_find_element_unique_ambiguous_and_missing():
    target = {"text": "Accept all", "cls": "android.widget.Button"}
    item, why = find_element(target, _dump(_node("Accept all")))
    assert item is not None
    assert why == ""
    item, why = find_element(
        target, _dump(_node("Accept all"), _node("Accept all", bounds=(0, 500, 9, 600)))
    )
    assert item is None
    assert why == "2 elements match"
    item, why = find_element(target, _dump(_node("Reject")))
    assert item is None
    assert why == "not found"
    assert find_element({"cls": "X"}, _dump())[1] == "nothing to match"


def test_find_element_tie_broken_by_recorded_bounds():
    target = {"text": "OK", "bounds": [0, 500, 9, 600]}
    item, _ = find_element(
        target, _dump(_node("OK"), _node("OK", bounds=(0, 500, 9, 600)))
    )
    assert item is not None
    assert item["node"]["bounds"] == [0, 500, 9, 600]


def test_find_element_by_row_label_and_web_fields():
    row = _node(cls="android.widget.LinearLayout",
                kids=[_node("Battery"), _node("Charged")])  # fmt: skip
    item, _ = find_element({"label": "Battery / Charged"}, _dump(row))
    assert item is not None
    assert item["node"]["cls"].endswith("LinearLayout")
    web = _node(rid="accept", web={"role": "button", "label": None})
    target = {"web": {"html_id": "accept", "raw_role": "button"}}
    assert find_element(target, _dump(web))[0] is not None
    target = {"web": {"html_id": "accept", "raw_role": "link"}}
    assert find_element(target, _dump(web))[0] is None


class FakeHelper:
    def __init__(self, replies):
        self.replies = list(replies)

    def dump(self, timeout=5.0):
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


class Clock:
    def __init__(self):
        self.t = 0.0

    def sleep(self, s):
        self.t += s

    def mono(self):
        return self.t


def _replayer(helper, shell_log, **kw):
    clock = Clock()
    lines: list[dict] = []
    rep = StepReplayer(
        shell=lambda c: shell_log.append(c) or "",
        helper=helper,
        sleep=clock.sleep,
        monotonic=clock.mono,
        emit=lambda *a, **k: lines.append(k) or 1,
        **kw,
    )
    return rep, lines


def _tap(seq=1, t=100.0, target=None, x=500, y=600, **data):
    return {"src": "input", "kind": "tap", "seq": seq, "t": t, "actor": "user",
            "summary": "tap 'Accept all' (Button)",
            "data": {"x": x, "y": y, "target": target, **data}}  # fmt: skip


def test_replay_taps_the_element_centre_when_found():
    steps = extract_steps([_tap(target={"text": "Accept all"})])
    node = _node("Accept all", bounds=(100, 1000, 300, 1100))
    log: list[str] = []
    rep, lines = _replayer(FakeHelper([_dump(node)]), log)
    report = rep.run(steps)
    assert log == ["input tap 200 1050"]
    assert report["steps"][0]["way"] == "by element"
    assert "by element" in lines[0]["summary"]


def test_replay_falls_back_to_position_when_ambiguous():
    steps = extract_steps([_tap(target={"text": "OK"})])
    dump = _dump(_node("OK"), _node("OK", bounds=(0, 800, 50, 900)))
    log: list[str] = []
    rep, lines = _replayer(FakeHelper([dump]), log, element_wait_s=1.0)
    report = rep.run(steps)
    assert log == ["input tap 500 600"]
    assert report["steps"][0]["way"] == "by position"
    assert report["error"] is None
    assert "by position (2 elements match)" in lines[0]["summary"]


def test_replay_element_gone_and_no_position_fails_and_stops():
    steps = extract_steps(
        [_tap(target={"text": "Accept all"}, x=None, y=None), _tap(seq=2, t=101)]
    )
    log: list[str] = []
    rep, lines = _replayer(FakeHelper([_dump()]), log, element_wait_s=1.0)
    report = rep.run(steps)
    assert log == []
    assert report["stopped_at_step"] == 1
    assert report["steps"][0]["way"] == "failed"
    assert "not found" in report["steps"][0]["reason"]
    assert "failed: not found" in lines[0]["summary"]
    assert report["error"].startswith("Replay stopped at step 1 of 2")


def test_replay_without_a_helper_goes_by_position():
    steps = extract_steps([_tap(target={"text": "Go"})])
    log: list[str] = []
    rep, _ = _replayer(lambda: None, log, element_wait_s=0.5)
    assert rep.run(steps)["steps"][0]["way"] == "by position"
    assert log == ["input tap 500 600"]


def test_keyboard_taps_replay_typed_text_by_position_and_text_fallback():
    lines = [
        _tap(seq=1, target={"rid": "p:id/field"}),
        _tap(seq=2, t=101, ime=True, x=50, y=2000),
        {"src": "input", "kind": "text", "seq": 3, "t": 101.5, "actor": "user",
         "data": {"text": "hunter2", "password": True}},
        {"src": "input", "kind": "text", "seq": 4, "t": 103, "actor": "user",
         "data": {"text": "hello world"}},
        {"src": "input", "kind": "confirm", "seq": 5, "data": {}},
        {**_tap(seq=6, t=104), "actor": "replay"},
    ]  # fmt: skip
    steps = extract_steps(lines)
    assert [s.kind for s in steps] == ["tap", "tap", "text"]
    log: list[str] = []
    rep, _ = _replayer(FakeHelper([_dump(_node(rid="p:id/field"))]), log)
    report = rep.run(steps)
    assert log[1] == "input tap 50 2000"
    assert log[2] == "input text hello%sworld"
    assert [s["way"] for s in report["steps"]] == [
        "by element",
        "by position",
        "replayed",
    ]


def test_input_text_arg_rejects_non_ascii():
    assert input_text_arg("a b") == "a%sb"
    assert input_text_arg("grüß") is None
    assert input_text_arg("it's") == "'it'\"'\"'s'"


def test_uncertain_tap_takes_the_confirm_target():
    lines = [
        _tap(seq=1, target=None, xy_uncertain=True),
        {"src": "input", "kind": "confirm", "seq": 2, "ref": {"of": 1},
         "data": {"target_of_input": True, "node": {"text": "Next", "bounds": [0, 0, 10, 10]}}},
    ]  # fmt: skip
    steps = extract_steps(lines)
    assert steps[0].target == {"text": "Next", "bounds": [0, 0, 10, 10]}


def test_replay_keeps_the_recorded_pause_and_stops_on_esc():
    steps = extract_steps([_tap(seq=1, t=100), _tap(seq=2, t=104)])
    log: list[str] = []
    clock = Clock()
    cancel = {"on": False}

    def shell(cmd):
        log.append((clock.t, cmd))
        cancel["on"] = True  # Esc right after the first tap
        return ""

    rep = StepReplayer(shell=shell, helper=None, sleep=clock.sleep,
                       monotonic=clock.mono, cancelled=lambda: cancel["on"])  # fmt: skip
    report = rep.run(steps)
    assert len(log) == 1
    assert report["stopped_at_step"] == 2
    assert report["steps"][1]["reason"] == "you pressed Esc"


def test_swipe_key_and_device_gone():
    lines = [
        {"src": "input", "kind": "swipe", "seq": 1, "t": 1, "actor": "user",
         "data": {"x": 10, "y": 900, "x1": 10, "y1": 100, "dur_ms": 250}},
        {"src": "input", "kind": "key", "seq": 2, "t": 1.1, "actor": "user",
         "data": {"name": "BACK"}},
    ]  # fmt: skip
    log: list[str] = []
    rep, _ = _replayer(None, log)
    rep.run(extract_steps(lines))
    assert log == ["input swipe 10 900 10 100 250", "input keyevent KEYCODE_BACK"]

    def gone(_cmd):
        raise RuntimeError("device offline")

    rep = StepReplayer(shell=gone, helper=None, sleep=lambda s: None)
    report = rep.run(extract_steps(lines[:1]))
    assert "did not answer" in report["error"]


def test_step_what_uses_the_timeline_summary():
    step = Step(1, 5, "tap", None, {}, "tap 'OK' (Button)")
    assert step.what == "tap 'OK' (Button)"
    assert Step(2, 6, "long_press", None, {}).what == "long press"


def test_raw_gesture_is_sent_as_sendevent():
    line = {"src": "input", "kind": "gesture", "seq": 1, "t": 1, "actor": "user",
            "data": {"pointers": 2}, "ref": {"raw": "tracking/raw/getevent.txt#L3-L4"}}  # fmt: skip
    raw = [
        "[   10.000000] /dev/input/event1: 0003 0035 00000010\n",
        "[   10.050000] /dev/input/event1: 0000 0000 00000000\n",
    ]
    log: list[str] = []
    rep, _ = _replayer(None, log, raw_lines=lambda f, a, b: raw)
    rep.run(extract_steps([line]))
    assert log == [
        "sendevent /dev/input/event1 3 53 16; sleep 0.050; "
        "sendevent /dev/input/event1 0 0 0"
    ]


def test_player_module_keeps_the_raw_cli_player():
    assert hasattr(player, "Player")
    assert hasattr(player, "parse_store_line")


# ---------------------------------------------------------------------------
# edge cases (review round)
# ---------------------------------------------------------------------------


def test_replay_element_gone_but_position_known_goes_by_position():
    steps = extract_steps([_tap(target={"text": "Accept all"})])
    log: list[str] = []
    rep, lines = _replayer(FakeHelper([_dump(_node("Reject"))]), log,
                           element_wait_s=1.0)  # fmt: skip
    report = rep.run(steps)
    assert log == ["input tap 500 600"]
    assert report["steps"][0] == {
        "i": 1, "seq": 1, "what": "tap 'Accept all' (Button)",
        "way": "by position", "reason": "not found",
    }  # fmt: skip
    assert "by position (not found)" in lines[0]["summary"]
    assert report["error"] is None


def test_replay_ambiguous_element_without_position_fails_and_stops():
    steps = extract_steps(
        [_tap(target={"text": "OK"}, x=None, y=None), _tap(seq=2, t=101)]
    )
    dump = _dump(_node("OK"), _node("OK", bounds=(0, 800, 50, 900)))
    log: list[str] = []
    rep, lines = _replayer(FakeHelper([dump]), log, element_wait_s=1.0)
    report = rep.run(steps)
    assert log == []
    assert [s["way"] for s in report["steps"]] == ["failed"]
    assert report["steps"][0]["reason"] == (
        "2 elements match, and the recorded position is unknown"
    )
    assert lines[0]["level"] == "error"


def test_replay_swipe_without_an_end_point_is_a_failed_step():
    lines = [
        {"src": "input", "kind": "swipe", "seq": 1, "t": 1, "actor": "user",
         "data": {"x": 10, "y": 900, "x1": 10, "y1": None}},
    ]  # fmt: skip
    log: list[str] = []
    rep, _ = _replayer(None, log)
    report = rep.run(extract_steps(lines))
    assert log == []
    assert report["stopped_at_step"] == 1
    assert report["steps"][0]["way"] == "failed"
    assert "swipe" in report["steps"][0]["reason"]


def test_replay_unexpected_step_error_is_a_failed_step_not_a_crash():
    line = {"src": "input", "kind": "gesture", "seq": 1, "t": 1, "actor": "user",
            "data": {}, "ref": {"raw": "tracking/raw/getevent.txt#L3-L4"}}  # fmt: skip

    def broken(*_a):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")

    log: list[str] = []
    rep, _ = _replayer(None, log, raw_lines=broken)
    report = rep.run(extract_steps([line]))
    assert report["stopped_at_step"] == 1
    assert report["steps"][0]["way"] == "failed"
    assert report["error"].startswith("Replay stopped at step 1 of 1")


def test_rewind_with_the_app_not_running_pulls_without_pausing(tmp_path, monkeypatch):
    dev = FakeDevice()
    dev.shell = lambda cmd: (dev.calls.append(cmd.split()[0]) or " PID NAME\n 9 x\n")
    rec = _rec(tmp_path, monkeypatch)
    out = rewind.RewindRunner(rec, dev.deps()).run(replay=False)
    assert out.paused == []
    assert "kill" not in dev.calls
    assert [c for c in dev.calls if c.startswith("pull")] == [
        "pull before /data/data/p/a",
        "pull before /data/data/p/b",
    ]
    assert out.result == "rewound"


def test_rewind_when_ps_fails_still_pulls(tmp_path, monkeypatch):
    dev = FakeDevice()

    def shell(cmd):
        raise RuntimeError("device offline")

    dev.shell = shell
    rec = _rec(tmp_path, monkeypatch)
    out = rewind.RewindRunner(rec, dev.deps()).run(replay=False)
    assert out.paused == []
    assert out.result == "rewound"
    assert sum(c.startswith("pull before") for c in dev.calls) == 2


def test_file_absent_on_both_sides_says_not_on_the_device(files_root):
    rec = rewind.Recording(rec_id="rec-1", name="R", pkg="p", serial="s")
    path = "/data/data/p/files/tmp.lock"
    rec.set_role(path, "after", rewind.ABSENT)
    rec.set_role(path, "before", rewind.ABSENT)
    res = rewind.file_result(rec, path)
    assert res.action_text == "not on the device"
    assert not res.error
    rec.set_role(path, "after_replay", rewind.ABSENT)
    # Neither run left the file: the replay ended like your run.
    assert rewind.file_result(rec, path).verdict == rewind.SAME


def test_new_and_deleted_files_get_replay_verdicts(files_root):
    path = "/data/data/p/files/new.txt"
    after = _version(path, "v001_10-00-00", b"hello\n")
    rec = rewind.Recording(rec_id="rec-1", name="R", pkg="p", serial="s")
    rec.set_role(path, "after", after)
    rec.set_role(path, "before", rewind.ABSENT)
    rec.set_role(path, "after_replay", after)  # identical copy: same version
    assert rewind.file_result(rec, path).verdict == rewind.SAME
    rec.set_role(path, "after_replay", rewind.ABSENT)  # replay made nothing
    assert rewind.file_result(rec, path).verdict == rewind.UNCHANGED

    gone = "/data/data/p/files/gone.txt"
    before = _version(gone, "v001_10-00-00", b"bye\n")
    rec.set_role(gone, "after", rewind.ABSENT)
    rec.set_role(gone, "before", before)
    rec.set_role(gone, "after_replay", rewind.ABSENT)
    res = rewind.file_result(rec, gone)
    assert res.verdict == rewind.SAME
    assert "deleted" in res.replay_text


def test_large_text_change_stays_bounded(files_root):
    path = "/data/data/p/files/big.txt"
    rec = rewind.Recording(rec_id="rec-1", name="R", pkg="p", serial="s")
    big = b"x" * (5 * 1024 * 1024)  # over the line-diff limit: binary diff
    rec.set_role(path, "before", _version(path, "v001_10-00-00", big + b"\n"))
    rec.set_role(path, "after", _version(path, "v002_10-00-01", big + b"y\n"))
    res = rewind.file_result(rec, path)
    assert not res.error
    assert len(res.action_text) < 100_000


def test_tls_failures_never_match_and_extra_duplicates_take_the_last():
    orig = rewind.requests_in(
        [
            {"src": "net", "kind": "tls-fail", "seq": 1, "data": {"host": "h"}},
            _flow(2, "GET", "h", "/p", 200),
            _flow(3, "GET", "h", "/p", 201),
            _flow(4, "GET", "h", "/p", 202),
        ]
    )
    replay = rewind.requests_in(
        [
            {"src": "net", "kind": "tls-fail", "seq": 9, "data": {"host": "h"}},
            _flow(10, "GET", "H", "/p", 200),  # host compared without case
            _flow(11, "get", "h", "/p", 201),
        ]
    )
    assert rewind.match_flow(orig[0], replay) is None
    assert rewind.compare_flow(orig[3], replay, lambda _i: None).replay["seq"] == 11
    assert rewind.compare_flow(orig[1], replay, lambda _i: None).replay["seq"] == 10
    assert rewind.match_flow(orig[1], []) is None


def test_replay_keeps_pauses_with_iso_times_from_the_timeline_file():
    lines = [
        {**_tap(seq=1), "t": "2026-11-20T13:36:02.000+01:00"},
        {**_tap(seq=2), "t": "2026-11-20T13:36:07.000+01:00"},
    ]
    log: list[tuple[float, str]] = []
    clock = Clock()
    rep = StepReplayer(
        shell=lambda c: log.append((clock.t, c)) or "",
        helper=None,
        sleep=clock.sleep,
        monotonic=clock.mono,
    )
    rep.run(extract_steps(lines))
    assert log[1][0] - log[0][0] == pytest.approx(5.0, abs=0.25)


def test_in_time_and_line_time_read_iso_text():
    lines = [{"t": "2026-11-20T13:36:02+00:00"}, {"t": "2026-11-20T13:36:09+00:00"}]
    t0 = rewind.line_time(lines[0])
    assert rewind.line_time({"t": None}) is None
    assert rewind.in_time(lines, t0, t0 + 5) == lines[:1]


def test_verdict_categories(files_root):
    path = "/data/data/p/files/v.txt"
    same = _version(path, "v001_10-00-00", b"a\n")
    copy = _version(path, "v002_10-00-01", b"a\n")  # same content, new version
    rec = rewind.Recording(rec_id="rec-1", name="R", pkg="p", serial="s")
    rec.set_role(path, "before", same)
    rec.set_role(path, "after", same)
    rec.set_role(path, "after_replay", copy)
    # The action did not change it, nor did the replay: the same.
    assert rewind.file_result(rec, path).verdict == rewind.SAME
    changed = _version(path, "v003_10-00-02", b"b\n")
    rec.set_role(path, "after", changed)
    # The action changed it; the replay's copy has the Before content.
    assert rewind.file_result(rec, path).verdict == rewind.UNCHANGED


def test_failed_after_replay_says_not_copied_and_a_plain_rewind_hides_it(files_root):
    path = "/data/data/p/files/w.txt"
    rec = rewind.Recording(rec_id="rec-1", name="R", pkg="p", serial="s")
    rec.set_role(path, "before", _version(path, "v001_10-00-00", b"a\n"))
    rec.set_role(path, "after", _version(path, "v002_10-00-01", b"b\n"))
    rec.set_role(path, "after_replay", None)
    assert rewind.file_result(rec, path).verdict == rewind.NOT_COPIED
    rec.set_role(path, "after_replay", "v002_10-00-01")
    assert rewind.file_result(rec, path, with_replay=False).verdict == rewind.NO_REPLAY


def test_a_failed_before_pull_keeps_the_earlier_before(tmp_path, monkeypatch):
    dev = FakeDevice(pull_error_on="/data/data/p/a")
    rec = _rec(tmp_path, monkeypatch)
    rec.set_role("/data/data/p/a", "before", "v-old")
    rewind.RewindRunner(rec, dev.deps()).run(replay=False)
    assert rec.role_version("/data/data/p/a", "before") == "v-old"


def test_input_text_percent_is_sent_as_is():
    assert input_text_arg("100%") == "100%"
    assert input_text_arg("a%sb") is None


def test_replay_waits_as_long_as_the_run_went_on_after_its_last_step():
    clock = Clock()
    rep = StepReplayer(
        shell=lambda c: "", helper=None, sleep=clock.sleep, monotonic=clock.mono,
        tail_s=20.0,
    )  # fmt: skip
    rep.run(extract_steps([_tap(seq=1)]))
    assert clock.t == pytest.approx(20.0, abs=0.3)
    clock.t = 0.0
    rep.tail_s = 500.0
    rep.run(extract_steps([_tap(seq=1)]))
    assert clock.t == pytest.approx(player.MAX_TAIL_S, abs=0.3)


def test_before_version_gets_no_backwards_chain_diff(files_root):
    from sandroid.core import watchlist_store

    path = "/data/data/p/files/c.txt"
    _version(path, "v001_10-00-00", b"after\n")
    staging = watchlist_store.reset_current(path)
    (staging / "c.txt").write_bytes(b"before\n")
    kept = watchlist_store.keep_version(path, {"rewind": {"role": "before"}})
    assert watchlist_store.version_diff(kept.dir) is None
    assert not (kept.dir / "diff.json").exists()


def test_version_list_names_the_role():
    from sandroid.tui.widgets.file_inspect import Version

    v = Version(1, Path("/x/v001"), Path("/x/v001/f"), None, 1,
                {"trigger": "rewind-after_replay", "rewind": {"role": "after_replay"}})  # fmt: skip
    assert v.trigger == "After (replay)"


def test_main_database_of_companions():
    assert rewind.main_database("/d/c.sqlite-wal") == "/d/c.sqlite"
    assert rewind.main_database("/d/c.sqlite-shm") == "/d/c.sqlite"
    assert rewind.main_database("/d/c.sqlite") == "/d/c.sqlite"


def test_before_version_summary_never_reads_backwards():
    from sandroid.tui.widgets.file_inspect import BEFORE_NOTE, Version, version_summary

    a = Version(1, Path("/x/v001"), Path("/x/v001/f"), None, 1, {})
    b = Version(2, Path("/x/v002"), Path("/x/v002/f"), None, 1,
                {"rewind": {"role": "before"}})  # fmt: skip
    assert version_summary(b, a) == BEFORE_NOTE


def test_find_element_reads_the_merged_web_target_shape():
    """tracking-web's data.target.web: engine, role, raw_role, html_id,
    href, field, input, doc, page.
    """
    node = _node(
        rid="email",
        cls="android.widget.EditText",
        web={"engine": "chromium", "role": "textbox", "label": "E-Mail",
             "input_type": 0x21},
    )  # fmt: skip
    target = {
        "rid": "email",
        "cls": "android.widget.EditText",
        "web": {"engine": "chromium", "role": "text field", "raw_role": "textbox",
                "html_id": "email", "href": None, "field": "E-Mail",
                "input": "email", "doc": "Login", "page": "example.com"},
    }  # fmt: skip
    assert find_element(target, _dump(node))[0] is not None
    other = {**target, "web": {**target["web"], "engine": "gecko"}}
    assert find_element(other, _dump(node))[0] is None


def test_a_load_that_timed_out_says_the_state_is_unknown(tmp_path, monkeypatch):
    dev = FakeDevice()

    def hung(name, serial):
        raise rewind.RewindStoppedError("the device state is unknown")

    rec = _rec(tmp_path, monkeypatch)
    deps = dev.deps()
    deps.load_snapshot = hung
    out = rewind.RewindRunner(rec, deps).run(replay=False)
    assert out.error == "the device state is unknown"
    assert out.loaded is True
    assert rec.runs[-1]["loaded"] is True
    assert not any(c.startswith("pull") for c in dev.calls)
