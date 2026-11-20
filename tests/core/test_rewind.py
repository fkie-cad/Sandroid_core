"""Rewind core (``core/rewind.py``) and the step replay (``features/player.py``).

No device: every device call goes through fakes. Covers the file lists, the
Review list, start point names, role diffs and verdicts, the request
matching, the Rewind order, the element matcher and the step replay.
"""

from __future__ import annotations

import itertools
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


def _hit_test(reply, x, y):
    """A live ``node_at`` answer at (x, y) on a fake dump: the first window
    holding the point, its deepest node there (later children on top), the
    nearest clickable node at or above it as ``target``.
    """
    for window in (reply or {}).get("windows") or []:
        root = window.get("root") or {}
        wb = window.get("bounds") or root.get("bounds")
        if not (wb[0] <= x < wb[2] and wb[1] <= y < wb[3]):
            continue
        chain = [root]
        while True:
            kids = [
                k for k in chain[-1].get("kids") or []
                if k.get("bounds") and k["bounds"][0] <= x < k["bounds"][2]
                and k["bounds"][1] <= y < k["bounds"][3]
            ]  # fmt: skip
            if not kids:
                break
            chain.append(kids[-1])
        target = next((n for n in reversed(chain) if n.get("clickable")), None)
        return {"hit": chain[-1], "target": target,
                "window": {"id": window.get("id")}}  # fmt: skip
    return {"hit": None, "reason": "no_window"}


class FakeHelper:
    """A helper with ``dump``, a live hit test on that dump (``hits`` keeps
    every tested point) and the display.
    """

    def __init__(self, replies, display=None):
        self.replies = list(replies)
        self.last = None
        self.hits: list[tuple[int, int]] = []
        self.cleared = 0
        self.disp = display or {"w": 1080, "h": 2424, "rotation": 0}

    def dump(self, timeout=5.0):
        self.last = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        return self.last

    def node_at(self, x, y, *, mode="both", timeout=1.0, t_mono_ms=None):
        self.hits.append((x, y))
        return {"type": "node_at", "live": _hit_test(self.last, x, y)}

    def clear_cache(self, timeout=1.0):
        self.cleared += 1
        return True

    def display(self, timeout=2.0):
        return self.disp


class DumpOnly:
    """A helper that can dump but has no live hit test."""

    def __init__(self, reply):
        self.reply = reply

    def dump(self, timeout=5.0):
        return self.reply


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
    # typed one character at a time (a space as %s)
    chars = ["h", "e", "l", "l", "o", "%s", "w", "o", "r", "l", "d"]
    assert log[2:] == [f"input text {c}" for c in chars]
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
        "way": "by position", "reason": "not found", "check": "unchecked",
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


# ---------------------------------------------------------------------------
# the replay checks its outcome: typed text is read back, misses add up
# ---------------------------------------------------------------------------


class FocusHelper(FakeHelper):
    """A helper whose focused field reads ``value``."""

    def __init__(self, value, *, password=False, replies=None):
        super().__init__(replies or [_dump()])
        self.value = value
        self.password = password
        self.reads = 0

    def focus(self, x=None, y=None, timeout=1.0):
        self.reads += 1
        return {"input": {"editable": True, "text": self.value,
                          "password": self.password, "rid": "p:id/url"}}  # fmt: skip


def _text(text, seq=1, t=100.0, password=False, dur_ms=3400.0, summary=None):
    data = {
        "text": text,
        "password": password,
        "dur_ms": dur_ms,
        "target": {"rid": "p:id/url", "bounds": [180, 164, 807, 290]},
    }
    line = {"src": "input", "kind": "text", "seq": seq, "t": t, "actor": "user",
            "summary": summary or f'typed "{text}" into the address bar',
            "data": data}  # fmt: skip
    if password:
        line["sensitive"] = True
        data["masked_summary"] = f"typed {len(text)} characters into password field"
    return line


def test_typed_text_is_typed_at_the_recorded_pace_and_checked():
    steps = extract_steps([_text("spiegel.de")])
    log: list[str] = []
    helper = FocusHelper("spiegel.de")
    rep, lines = _replayer(helper, log)
    report = rep.run(steps)
    assert log == [f"input text {c}" for c in "spiegel.de"]
    assert helper.reads >= 1
    step = report["steps"][0]
    assert step["way"] == "replayed"
    assert step["check"] == "verified"
    assert "field checked" in step["reason"]
    assert report["diverged_at_step"] is None
    assert "replayed (typed 10 characters, field checked)" in lines[0]["summary"]


def test_typing_keeps_the_recorded_pace_within_bounds():
    clock = Clock()
    sent: list[float] = []
    rep = StepReplayer(shell=lambda c: sent.append(clock.t) or "",
                       helper=FocusHelper("abcd"), sleep=clock.sleep,
                       monotonic=clock.mono)  # fmt: skip
    rep.run(extract_steps([_text("abcd", dur_ms=900.0)]))
    gaps = [b - a for a, b in itertools.pairwise(sent)]
    assert gaps == [pytest.approx(0.3, abs=0.01)] * 3
    sent.clear()
    rep.run(extract_steps([_text("abcd", dur_ms=0.1)]))
    gaps = [b - a for a, b in itertools.pairwise(sent)]
    assert gaps == [pytest.approx(player.TYPE_MIN_GAP_S, abs=0.01)] * 3


def test_typed_text_that_reads_otherwise_diverges_the_run(tmp_path, monkeypatch):
    lines_in = [_text("spiegel.de"), _tap(seq=2, t=101, target={"text": "Accept"})]
    steps = extract_steps(lines_in)
    log: list[str] = []
    helper = FocusHelper("sgelde", replies=[_dump(_node("Accept"))])
    rep, lines = _replayer(helper, log)
    report = rep.run(steps)
    step = report["steps"][0]
    assert step["way"] == "diverged"
    assert step["reason"] == "field reads 'sgelde', expected 'spiegel.de'"
    assert (
        "· diverged: field reads 'sgelde', expected 'spiegel.de'"
        in (lines[0]["summary"])
    )
    assert lines[0]["level"] == "warn"
    # the replay goes on, the run is not a success
    assert report["steps"][1]["way"] == "by element"
    assert report["error"] is None
    assert report["diverged_at_step"] == 1

    dev = FakeDevice()
    progress: list[str] = []
    ends: list[dict] = []
    rec = _rec(tmp_path, monkeypatch)
    deps = dev.deps(lambda r, runner: report)
    deps.progress = progress.append

    def emit(*a, **k):
        if k.get("kind") == "play-end":
            ends.append(k)
        return 1

    deps.emit = emit
    out = rewind.RewindRunner(rec, deps).run(replay=True)
    assert out.result == "diverged"
    assert out.error is None
    assert out.diverged_at_step == 1
    assert rec.runs[-1]["result"] == "diverged"
    assert rec.runs[-1]["diverged_at_step"] == 1
    words = " ".join(progress).lower()
    assert "done" not in words
    assert "success" not in words
    assert any("The replay diverged at step 1 of 2" in p for p in progress)
    assert ends[0]["summary"].startswith("replay diverged at step 1")
    assert ends[0]["data"]["result"] == "diverged"
    assert "finished" not in ends[0]["summary"]
    # verdicts computed after it carry the note
    note = rewind.diverged_note(rec.runs[-1])
    assert "diverged at step 1" in note
    res = rewind.FileResult("/data/data/p/a", None, None, None, note=note)
    assert f"Note: {note}" in rewind.result_lines(res)


def test_autocomplete_suffix_after_the_recorded_text_is_accepted():
    assert player.text_check("wdr.de", "wdr.de/") == (True, "")
    assert player.text_check(" spiegel.de", "spiegel.de ") == (True, "")
    assert player.text_check("spiegel.de", "sgelde")[0] is False
    assert player.text_check("spiegel.de", "spiegel.d")[0] is False
    rep, _ = _replayer(FocusHelper("wdr.de/"), [])
    report = rep.run(extract_steps([_text("wdr.de")]))
    assert report["steps"][0]["check"] == "verified"
    assert report["diverged_at_step"] is None


def test_password_divergence_prints_no_text():
    steps = extract_steps([_text("hunter2", password=True)])
    assert steps[0].sensitive
    assert "hunter2" not in steps[0].what
    rep, lines = _replayer(FocusHelper("letmein", password=True), [])
    report = rep.run(steps)
    step = report["steps"][0]
    assert step["way"] == "diverged"
    assert step["reason"] == "field text differs"
    for text in (str(step), str(report), str(lines)):
        assert "hunter" not in text
        assert "letmein" not in text
    assert lines[0]["sensitive"] is True
    # bullets of the right length are a match; of another length not
    assert player.text_check("hunter2", "\u2022" * 7, password=True) == (True, "")
    assert player.text_check("hunter2", "\u2022" * 5, password=True) == (
        False,
        "field text differs",
    )


def test_unreadable_field_is_a_note_not_a_divergence():
    rep, lines = _replayer(FakeHelper([_dump()]), [])  # no focus read-back
    report = rep.run(extract_steps([_text("abc")]))
    step = report["steps"][0]
    assert step["way"] == "replayed"
    assert step["check"] == "unchecked"
    assert "not checked: the typed field could not be read back" in step["reason"]
    assert report["diverged_at_step"] is None


def test_keyboard_typed_text_is_checked_after_the_last_key():
    lines = [
        _tap(seq=1, t=100, ime=True, x=50, y=2000),
        _tap(seq=2, t=100.5, ime=True, x=60, y=2000),
        {**_text("ab", seq=3, t=101), "data": {"text": "ab", "target": None}},
    ]
    steps = extract_steps(lines)
    assert [s.kind for s in steps] == ["tap", "tap"]
    assert "check_text" not in steps[0].data
    assert steps[1].data["check_text"] == "ab"
    rep, _ = _replayer(FocusHelper("xb"), [])
    report = rep.run(steps)
    assert [s["way"] for s in report["steps"]] == ["by position", "diverged"]
    assert report["diverged_at_step"] == 2


def test_two_missed_elements_in_a_row_diverge_one_is_a_note():
    log: list[str] = []
    one = [
        _tap(seq=1, target={"text": "Gone"}),
        _tap(seq=2, t=101, target={"text": "OK"}),
    ]
    rep, _ = _replayer(FakeHelper([_dump(_node("OK"))]), log, element_wait_s=0.6)
    report = rep.run(extract_steps(one))
    assert [s["way"] for s in report["steps"]] == ["by position", "by element"]
    assert report["diverged_at_step"] is None

    two = [
        _tap(seq=1, target={"text": "Gone"}),
        _tap(seq=2, t=101, target={"text": "Away"}),
    ]
    rep, lines = _replayer(FakeHelper([_dump(_node("OK"))]), [], element_wait_s=0.6)
    report = rep.run(extract_steps(two))
    assert [s["way"] for s in report["steps"]] == ["by position", "diverged"]
    assert "and step 1 before it missed its element too" in report["steps"][1]["reason"]
    assert report["diverged_at_step"] == 2
    assert "diverged: its element did not appear (not found)" in lines[1]["summary"]

    # no helper: nothing was looked for, so nothing diverged
    rep, _ = _replayer(lambda: None, [], element_wait_s=0.6)
    report = rep.run(extract_steps(two))
    assert report["diverged_at_step"] is None


def test_a_run_with_a_failed_step_is_not_a_success(tmp_path, monkeypatch):
    steps = extract_steps([_tap(target={"text": "Gone"}, x=None, y=None)])
    rep, _ = _replayer(FakeHelper([_dump()]), [], element_wait_s=0.6)
    report = rep.run(steps)
    dev = FakeDevice()
    progress: list[str] = []
    deps = dev.deps(lambda r, runner: report)
    deps.progress = progress.append
    out = rewind.RewindRunner(_rec(tmp_path, monkeypatch), deps).run(replay=True)
    assert out.result == "stopped"
    assert out.error
    assert not any("Done" in p for p in progress)


def test_password_field_showing_its_last_character_and_a_moved_focus():
    bullets = "•" * 6
    assert player.text_check("hunter2", bullets + "2", password=True) == (True, "")
    assert player.text_check("hunter2", bullets + "x", password=True)[0] is False

    class Moved(FocusHelper):
        def focus(self, x=None, y=None, timeout=1.0):
            return {"input": {"editable": True, "text": "", "rid": "p:id/next"}}

    rep, _ = _replayer(Moved(""), [])
    report = rep.run(extract_steps([_text("1234")]))
    assert report["steps"][0]["check"] == "unchecked"
    assert report["diverged_at_step"] is None


# ---------------------------------------------------------------------------
# taps never land off the screen; unchecked steps are not a success
# ---------------------------------------------------------------------------

_SCREEN = [1080, 2424]


def _web_dump(*nodes):
    reply = _dump(*nodes)
    reply["windows"][0]["bounds"] = [0, 0, 1080, 2424]
    reply["display"] = {"w": 1080, "h": 2424, "rotation": 0}
    return reply


def _page_node(top, bottom):
    return _node(cls="android.view.View", bounds=(0, top, 1080, bottom),
                 web={"engine": "gecko", "role": "text container"})  # fmt: skip


def _overview_run_lines():
    """The 20261120_052151 recording: Suchen, typed spiegel.de, the stale
    'spi' suggestion, two swipes, a tap on the page body.
    """
    page = {
        "bounds": [0, 307, 1080, 7697],
        "cls": "android.view.View",
        "rid": None,
        "text": None,
        "desc": None,
        "web": {
            "engine": "gecko",
            "raw_role": "text container",
            "page": "spiegel.de",
            "doc": "spiegel.de - Google Suche",
        },
    }
    swipe = {"x": 540, "y": 1900, "x1": 540, "y1": 700, "dur_ms": 680}
    return [
        _tap(seq=28, t=100, x=458, y=226, screen=_SCREEN,
             target={"desc": "Suchen", "rid": "ADDRESSBAR_URL_BOX",
                     "cls": "android.widget.Button", "bounds": [180, 163, 702, 289]}),
        _text("spiegel.de", seq=32, t=101),
        _tap(seq=33, t=105, x=245, y=479, screen=_SCREEN,
             target={"label": "spi", "rid": "mozac.awesomebar.suggestion",
                     "cls": "android.view.View", "bounds": [0, 415, 1080, 541]}),
        {"src": "input", "kind": "swipe", "seq": 37, "t": 107, "actor": "user",
         "data": swipe},
        {"src": "input", "kind": "swipe", "seq": 39, "t": 108, "actor": "user",
         "data": swipe},
        {**_tap(seq=41, t=110, x=539, y=1826, screen=_SCREEN, target=page),
         "summary": "tap at 539,1826 on spiegel.de"},
    ]  # fmt: skip


def test_overview_run_reads_unchecked_not_success(tmp_path, monkeypatch):
    suchen = _node(desc="Suchen", rid="ADDRESSBAR_URL_BOX", bounds=(180, 163, 702, 289))
    # The consent page scrolled: its node's page position centres at y=3641.
    # (the page lies below the toolbar: the toolbar is drawn on top)
    dump = _web_dump(_page_node(-415, 7697), suchen)
    log: list[str] = []
    rep, lines = _replayer(FocusHelper("spiegel.de", replies=[dump]), log,
                           element_wait_s=1.0)  # fmt: skip
    report = rep.run(extract_steps(_overview_run_lines()))
    ways = [(s["way"], s["reason"], s["check"]) for s in report["steps"]]
    assert ways == [
        ("by element", "", "verified"),
        ("replayed", "typed 10 characters, field checked", "verified"),
        ("by position", "not found", "unchecked"),
        ("by position", "", "none"),
        ("by position", "", "none"),
        ("by position", "element off-screen", "unchecked"),
    ]
    assert log[-1] == "input tap 539 1826"  # the recorded point, never y=3641
    assert all(int(c.split()[3]) < 2424 for c in log if c.startswith("input tap"))
    assert "by position (element off-screen)" in lines[5]["summary"]
    assert lines[5]["data"]["check"] == "unchecked"
    assert report["unchecked_steps"] == [3, 6]
    assert report["diverged_at_step"] is None

    dev = FakeDevice()
    progress: list[str] = []
    ends: list[dict] = []
    deps = dev.deps(lambda r, runner: report)
    deps.progress = progress.append
    deps.emit = lambda *a, **k: ends.append(k) or 1
    rec = _rec(tmp_path, monkeypatch)
    out = rewind.RewindRunner(rec, deps).run(replay=True)
    assert out.result == "unchecked"
    assert rec.runs[-1]["result"] == "unchecked"
    assert rec.runs[-1]["unchecked_steps"] == [3, 6]
    assert rewind.result_words(rec.runs[-1]) == "done, 2 steps unchecked"
    assert not any(p.startswith("Done") for p in progress)
    assert any(
        p.startswith("Replay done, 2 steps unchecked (steps 3 and 6)") for p in progress
    )
    end = next(k for k in ends if k.get("kind") == "play-end")
    assert end["summary"] == "replay done, 2 steps unchecked"
    assert end["data"]["result"] == "unchecked"
    assert end["level"] == "warn"
    assert "Replay steps 3 and 6 could not be checked" in rewind.diverged_note(
        rec.runs[-1]
    )


def test_tap_point_clips_to_the_window_and_display():
    target = {"web": {"raw_role": "text container"}}
    reply = _web_dump()
    item = {"node": {"bounds": [0, 2000, 1080, 3000]},
            "window": {"bounds": [0, 0, 1080, 2424]}}  # fmt: skip
    assert player.tap_point(item, reply, target, _SCREEN) is None  # centre off
    item["node"]["bounds"] = [0, 2000, 1080, 2600]
    assert player.tap_point(item, reply, target, _SCREEN) == (540, 2300)
    item["window"]["bounds"] = [0, 0, 1080, 2200]  # a window above the keyboard
    assert player.tap_point(item, reply, target, _SCREEN) is None
    item["node"]["bounds"] = [100, 3000, 200, 3100]
    assert player.tap_point(item, reply, target, _SCREEN) is None  # not visible
    # a page-sized recorded target does not say where you tapped
    big = {"bounds": [0, 307, 1080, 7697]}
    item = {"node": {"bounds": [0, 307, 1080, 1500]}, "window": {}}
    assert player.tap_point(item, reply, big, _SCREEN) is None
    assert player.tap_point(item, reply, {"bounds": [0, 307, 1080, 1500]},
                            _SCREEN) == (540, 903)  # fmt: skip


def test_an_off_screen_recorded_position_is_never_tapped():
    steps = extract_steps([_tap(x=500, y=3000, screen=_SCREEN)])
    log: list[str] = []
    rep, _ = _replayer(None, log)
    report = rep.run(steps)
    assert log == []
    assert report["steps"][0]["way"] == "failed"
    assert "off the screen" in report["steps"][0]["reason"]


def test_a_stale_partial_reading_is_unchecked_not_diverged():
    rep, _ = _replayer(FocusHelper("spieg"), [])
    report = rep.run(extract_steps([_text("spiegel.de")]))
    step = report["steps"][0]
    assert step["way"] == "replayed"
    assert step["check"] == "unchecked"
    assert "only part of the text" in step["reason"]
    assert report["unchecked_steps"] == [1]
    assert report["diverged_at_step"] is None


def test_without_an_id_a_field_elsewhere_is_unchecked_not_diverged():
    class Elsewhere(FocusHelper):
        def focus(self, x=None, y=None, timeout=1.0):
            return {"input": {"editable": True, "text": "",
                              "bounds": [0, 1800, 1080, 1900]}}  # fmt: skip

    line = _text("abc")
    line["data"]["target"] = {"rid": None, "bounds": [0, 200, 1080, 300]}
    rep, _ = _replayer(Elsewhere(""), [])
    report = rep.run(extract_steps([line]))
    assert report["steps"][0]["check"] == "unchecked"
    assert report["diverged_at_step"] is None

    class Moved(FocusHelper):  # the keyboard panned the same field up
        def focus(self, x=None, y=None, timeout=1.0):
            return {"input": {"editable": True, "text": "xyz",
                              "bounds": [0, 100, 1080, 200]}}  # fmt: skip

    rep, _ = _replayer(Moved(""), [])
    report = rep.run(extract_steps([line]))
    assert report["steps"][0]["way"] == "diverged"


def test_steps_with_nothing_to_check_keep_a_plain_success():
    lines = [
        {"src": "input", "kind": "swipe", "seq": 1, "t": 1, "actor": "user",
         "data": {"x": 10, "y": 900, "x1": 10, "y1": 100}},
        {"src": "input", "kind": "key", "seq": 2, "t": 1.1, "actor": "user",
         "data": {"name": "BACK"}},
        _tap(seq=3, t=2, target=None),
    ]  # fmt: skip
    rep, _ = _replayer(None, [])
    report = rep.run(extract_steps(lines))
    assert [s["check"] for s in report["steps"]] == ["none", "none", "none"]
    assert report["unchecked_steps"] == []


# ---------------------------------------------------------------------------
# verified means hit: the live hit test at the tapped spot
# ---------------------------------------------------------------------------


def _two_windows(top, app_nodes):
    """A dump with ``top`` (a dialog or the keyboard, drawn first) above the
    app window holding ``app_nodes``.
    """
    reply = _dump(*app_nodes)
    reply["windows"][0]["bounds"] = [0, 0, 1080, 2424]
    reply["windows"].insert(0, top)
    reply["display"] = {"w": 1080, "h": 2424, "rotation": 0}
    return reply


def test_a_covered_element_is_tapped_by_position_and_unchecked():
    dialog = {"id": 7, "type": "app", "bounds": [0, 800, 1080, 1400],
              "root": {"cls": "android.widget.FrameLayout",
                       "bounds": [0, 800, 1080, 1400], "kids": []}}  # fmt: skip
    button = _node("Accept all", bounds=(100, 1000, 300, 1100))
    helper = FakeHelper([_two_windows(dialog, [button])])
    log: list[str] = []
    rep, lines = _replayer(helper, log)
    report = rep.run(extract_steps([_tap(target={"text": "Accept all"})]))
    step = report["steps"][0]
    assert (step["way"], step["reason"], step["check"]) == (
        "by position", "element covered", "unchecked",
    )  # fmt: skip
    assert log == ["input tap 500 600"]  # the recorded position, never the button
    assert len(helper.hits) > 1  # other spots were tried
    assert "by position (element covered)" in lines[0]["summary"]
    assert report["unchecked_steps"] == [1]
    assert report["diverged_at_step"] is None  # covered is not a miss


def test_a_container_is_tapped_where_you_tapped_it_and_verified():
    row = _node(rid="p:id/row", cls="android.widget.LinearLayout",
                bounds=(0, 600, 1080, 700), clickable=True,
                kids=[_node("Battery", bounds=(40, 610, 400, 690))])  # fmt: skip
    target = {"rid": "p:id/row", "bounds": [0, 400, 1080, 500]}
    helper = FakeHelper([_dump(row)])
    log: list[str] = []
    rep, lines = _replayer(helper, log)
    report = rep.run(extract_steps([_tap(target=target, x=900, y=450)]))
    assert log == ["input tap 900 650"]  # not the centre (540, 650)
    assert helper.hits[0] == (900, 650)
    step = report["steps"][0]
    assert (step["way"], step["check"]) == ("by element", "verified")
    assert helper.cleared >= 1  # the hit test reads the screen fresh


def test_a_control_inside_the_element_taking_the_tap_is_not_the_element():
    inner = _node("Delete", bounds=(800, 600, 1080, 700), clickable=True)
    row = _node(rid="p:id/row", cls="android.widget.LinearLayout",
                bounds=(0, 600, 1080, 700), clickable=True, kids=[inner])  # fmt: skip
    target = {"rid": "p:id/row", "bounds": [0, 600, 1080, 700]}
    rep, _ = _replayer(FakeHelper([_dump(row)]), [])
    report = rep.run(extract_steps([_tap(target=target, x=900, y=650)]))
    step = report["steps"][0]
    # your spot is the Delete button now: another spot of the row is tapped
    assert step["check"] == "verified"
    assert "tapped another spot of it" in step["reason"]


def test_without_a_hit_test_an_element_tap_is_unchecked():
    node = _node("Accept all", bounds=(100, 1000, 300, 1100))
    log: list[str] = []
    rep, lines = _replayer(DumpOnly(_dump(node)), log)
    step = rep.run(extract_steps([_tap(target={"text": "Accept all"})]))["steps"][0]
    assert log == ["input tap 200 1050"]
    assert (step["way"], step["reason"], step["check"]) == (
        "by element", "not hit-tested", "unchecked",
    )  # fmt: skip
    assert "by element (not hit-tested)" in lines[0]["summary"]
    # no helper at all: by position, unchecked
    rep, _ = _replayer(lambda: None, [], element_wait_s=0.5)
    step = rep.run(extract_steps([_tap(target={"text": "Go"})]))["steps"][0]
    assert (step["way"], step["check"]) == ("by position", "unchecked")


def test_a_partly_visible_element_verifies_when_your_spot_is_visible():
    link = _node(rid="more", cls="android.view.View", bounds=(0, 2300, 1080, 2600),
                 web={"engine": "gecko", "role": "link"})  # fmt: skip
    target = {"web": {"html_id": "more"}, "bounds": [0, 2000, 1080, 2300]}
    log: list[str] = []
    rep, _ = _replayer(FakeHelper([_web_dump(link)]), log)
    steps = extract_steps([_tap(target=target, x=540, y=2050, screen=_SCREEN)])
    step = rep.run(steps)["steps"][0]
    assert log == ["input tap 540 2350"]  # its centre (2450) is off the screen
    assert (step["way"], step["reason"], step["check"]) == (
        "by element", "", "verified",
    )  # fmt: skip
    # your spot off the screen: another visible spot of it, said so
    log.clear()
    rep, _ = _replayer(FakeHelper([_web_dump(link)]), log)
    steps = extract_steps([_tap(target=target, x=540, y=2250, screen=_SCREEN)])
    step = rep.run(steps)["steps"][0]
    assert step["check"] == "verified"
    assert "your spot was off the screen" in step["reason"]
    assert all(int(c.split()[3]) < 2424 for c in log)


class WebCoverHelper(FakeHelper):
    """The real helper's hit rule on a page: the actionable button wins the
    ``hit`` even under an unclickable page element, which it reports as
    ``top`` (device check: a fixed div over part of a button in Firefox).
    """

    def __init__(self, reply, button, cover, send_top=True):
        super().__init__([reply])
        self.button, self.cover, self.send_top = button, cover, send_top

    def node_at(self, x, y, *, mode="both", timeout=1.0, t_mono_ms=None):
        self.hits.append((x, y))
        live = {"hit": self.button, "target": self.button, "window": {"id": 1}}
        b = self.cover["bounds"]
        if self.send_top and b[0] <= x < b[2] and b[1] <= y < b[3]:
            live["top"] = self.cover
        return {"type": "node_at", "live": live}


def _web_cover_case(cover_bounds, send_top=True):
    gecko = {"engine": "gecko", "role": "button"}
    button = _node("Target", rid="target", bounds=(42, 1016, 1038, 1381), web=gecko)
    cover = _node("Cover notice", cls="android.view.View", bounds=cover_bounds,
                  web={"engine": "gecko", "role": "alert"})  # fmt: skip
    helper = WebCoverHelper(_web_dump(button, cover), button, cover, send_top)
    target = {"text": "Target", "web": {"html_id": "target", "raw_role": "button"},
              "bounds": [42, 1016, 1038, 1381]}  # fmt: skip
    log: list[str] = []
    rep, _ = _replayer(helper, log)
    report = rep.run(
        extract_steps([_tap(target=target, x=250, y=1200, screen=_SCREEN)])
    )
    return report["steps"][0], log, helper


def test_a_web_element_partly_under_a_page_element_is_tapped_where_visible():
    # the cover hides your spot (left 60 %): another spot of the button
    step, log, helper = _web_cover_case((38, 1012, 636, 1385))
    assert (step["way"], step["check"]) == ("by element", "verified")
    assert step["reason"] == "your spot was covered, tapped another spot of it"
    (tap,) = log
    assert int(tap.split()[2]) >= 636  # right of the cover
    assert helper.hits[0] == (250, 1200)  # your spot was tested first
    # fully covered: by position, unchecked
    step, log, _ = _web_cover_case((34, 1008, 1046, 1389))
    assert (step["way"], step["reason"], step["check"]) == (
        "by position", "element covered", "unchecked",
    )  # fmt: skip
    assert log == ["input tap 250 1200"]
    # visible (or an older helper that names no top node): your spot
    step, log, _ = _web_cover_case((38, 1012, 636, 1385), send_top=False)
    assert (step["way"], step["check"], log) == (
        "by element", "verified", ["input tap 250 1200"],
    )  # fmt: skip


def test_a_top_node_inside_the_web_element_is_the_element():
    gecko = {"engine": "gecko", "role": "button"}
    label = _node("Target", cls="android.view.View", bounds=(400, 1150, 700, 1250),
                  web={"engine": "gecko", "role": "text leaf"})  # fmt: skip
    button = _node(rid="target", bounds=(42, 1016, 1038, 1381), web=gecko,
                   kids=[label])  # fmt: skip
    helper = WebCoverHelper(_web_dump(button), button, label)
    target = {"web": {"html_id": "target"}, "bounds": [42, 1016, 1038, 1381]}
    log: list[str] = []
    rep, _ = _replayer(helper, log)
    step = rep.run(extract_steps([_tap(target=target, x=540, y=1200, screen=_SCREEN)]))
    assert (step["steps"][0]["check"], log) == ("verified", ["input tap 540 1200"])


def test_a_web_overlay_inside_the_element_box_is_not_part_of_it():
    # a badge over the button that the dump does not know (appeared later):
    # never "inside" by its box alone
    gecko = {"engine": "gecko", "role": "button"}
    button = _node("Target", rid="target", bounds=(42, 1016, 1038, 1381), web=gecko,
                   nid=7)  # fmt: skip
    badge = _node("New", cls="android.view.View", bounds=(100, 1100, 700, 1300),
                  web={"engine": "gecko", "role": "alert"}, nid=99)  # fmt: skip
    helper = WebCoverHelper(_web_dump(button), button, badge)
    target = {"web": {"html_id": "target"}, "bounds": [42, 1016, 1038, 1381]}
    log: list[str] = []
    rep, _ = _replayer(helper, log)
    report = rep.run(
        extract_steps([_tap(target=target, x=250, y=1200, screen=_SCREEN)])
    )
    step = report["steps"][0]
    assert step["reason"] == "your spot was covered, tapped another spot of it"
    x, y = (int(v) for v in log[0].split()[2:])
    assert not (100 <= x < 700 and 1100 <= y < 1300)
    # the same node known to the dump as the button's child: part of it
    inner = {**badge, "nid": 8}
    button2 = {**button, "kids": [inner]}
    helper = WebCoverHelper(_web_dump(button2), button2, inner)
    log.clear()
    rep, _ = _replayer(helper, log)
    report = rep.run(
        extract_steps([_tap(target=target, x=250, y=1200, screen=_SCREEN)])
    )
    assert (report["steps"][0]["check"], log) == ("verified", ["input tap 250 1200"])


def test_a_weak_recorded_target_goes_by_position_unchecked():
    target = {"label": "spi", "rid": "mozac.awesomebar.suggestion",
              "stale_possible": True}  # fmt: skip
    node = _node(rid="mozac.awesomebar.suggestion", label="spi")
    log: list[str] = []
    rep, lines = _replayer(FakeHelper([_dump(node)]), log)
    step = rep.run(extract_steps([_tap(target=target)]))["steps"][0]
    assert log == ["input tap 500 600"]
    assert (step["way"], step["reason"], step["check"]) == (
        "by position", "recorded element unsure", "unchecked",
    )  # fmt: skip


def test_position_taps_on_another_display_are_unchecked_never_scaled():
    tap = _tap(target=None, x=500, y=600, screen=_SCREEN, rotation=0)
    helper = FakeHelper([_dump()], display={"w": 1440, "h": 3120, "rotation": 0})
    log: list[str] = []
    rep, _ = _replayer(helper, log)
    step = rep.run(extract_steps([tap]))["steps"][0]
    assert log == ["input tap 500 600"]  # the same pixels, not scaled
    assert step["check"] == "unchecked"
    assert "the screen is 1440x3120, your run had 1080x2424" in step["reason"]
    # turned: a position outside the screen now is never tapped
    helper = FakeHelper([_dump()], display={"w": 2424, "h": 1080, "rotation": 1})
    log.clear()
    rep, _ = _replayer(helper, log)
    far = _tap(target=None, x=500, y=2000, screen=_SCREEN, rotation=0)
    report = rep.run(extract_steps([far]))
    assert log == []
    assert report["steps"][0]["way"] == "failed"
    # the same display: nothing to check, a plain step
    log.clear()
    rep, _ = _replayer(FakeHelper([_dump()]), log)
    assert rep.run(extract_steps([tap]))["steps"][0]["check"] == "none"
    # without a helper, ``wm size`` tells (natural orientation)
    rep = StepReplayer(shell=lambda c: "Physical size: 720x1280\n" if c == "wm size"
                       else "", helper=None, sleep=lambda s: None)  # fmt: skip
    step = rep.run(extract_steps([tap]))["steps"][0]
    assert step["check"] == "unchecked"


def test_without_an_id_a_field_of_another_size_is_unchecked():
    class Wider(FocusHelper):
        def focus(self, x=None, y=None, timeout=1.0):
            return {"input": {"editable": True, "text": "xyz",
                              "bounds": [0, 200, 1080, 420]}}  # fmt: skip

    line = _text("abc")
    line["data"]["target"] = {"rid": None, "bounds": [0, 200, 1080, 300]}
    rep, _ = _replayer(Wider(""), [])
    report = rep.run(extract_steps([line]))
    assert report["steps"][0]["check"] == "unchecked"
    assert report["diverged_at_step"] is None


# ---------------------------------------------------------------------------
# keyboard-typed text is typed into its verified field
# ---------------------------------------------------------------------------


class TypingField(FakeHelper):
    """A focused field ``rid`` that holds what ``input text`` typed (a
    character replaces the selection ``sel``, then the cursor is at the end).
    """

    def __init__(self, rid="p:id/url", value="", password=False, sel=None):
        super().__init__([_dump()])
        self.rid, self.value, self.password = rid, value, password
        self.sel = sel  # (start, end) or None: the helper sent none

    def shell(self, cmd):
        if cmd.startswith("input text "):
            typed = cmd.split(" ", 2)[2].replace("%s", " ").strip("'")
            if self.sel is not None:
                lo, hi = sorted(self.sel)
                self.value = self.value[:lo] + typed + self.value[hi:]
                self.sel = (lo + len(typed), lo + len(typed))
            else:
                self.value += typed
        return ""

    def focus(self, x=None, y=None, timeout=1.0):
        node = {"editable": True, "text": self.value, "rid": self.rid,
                "password": self.password}  # fmt: skip
        if self.sel is not None:
            node["sel_start"], node["sel_end"] = self.sel
        return {"input": node}


def _keyboard_lines(text, password=False):
    target = {"rid": "p:id/url", "bounds": [180, 164, 807, 290]}
    keys = [_tap(seq=1 + i, t=100 + i * 0.3, ime=True, x=50 + 10 * i, y=2000)
            for i in range(len(text))]  # fmt: skip
    line = _text(text, seq=50, t=101, password=password)
    line["data"]["target"] = target
    return [*keys, line]


def _typing_replayer(helper):
    log: list[str] = []
    lines: list[dict] = []
    clock = Clock()

    def shell(cmd):
        log.append(cmd)
        return helper.shell(cmd)

    rep = StepReplayer(shell=shell, helper=helper, sleep=clock.sleep,
                       monotonic=clock.mono,
                       emit=lambda *a, **k: lines.append(k) or 1)  # fmt: skip
    return rep, log, lines


def test_keyboard_typed_text_goes_into_its_verified_field():
    steps = extract_steps(_keyboard_lines("wdr"))
    assert steps[0].data["type_text"]["taps"] == 3
    assert [s.data["typed_by"] for s in steps] == [1, 1, 1]
    helper = TypingField()
    rep, log, lines = _typing_replayer(helper)
    report = rep.run(steps)
    assert not any(c.startswith("input tap") for c in log)  # no key taps
    assert [c for c in log if c.startswith("input text")] == [
        "input text w", "input text d", "input text r",
    ]  # fmt: skip
    got = [(s["way"], s["reason"], s["check"]) for s in report["steps"]]
    assert got == [
        ("replayed",
         "typed 3 characters into the field instead of 3 keyboard taps, field checked",
         "verified"),
        ("replayed", "typed with step 1", "none"),
        ("replayed", "typed with step 1", "none"),
    ]  # fmt: skip
    assert report["unchecked_steps"] == []


def test_keyboard_taps_stay_when_the_field_cannot_be_verified():
    # the focus is on another field: the keys are tapped, unchecked
    rep, log, _ = _typing_replayer(TypingField(rid="p:id/other"))
    report = rep.run(extract_steps(_keyboard_lines("ab")))
    assert [c for c in log if c.startswith("input tap")] == [
        "input tap 50 2000", "input tap 60 2000",
    ]  # fmt: skip
    first = report["steps"][0]
    assert first["check"] == "unchecked"
    assert first["reason"] == "keyboard key, its field could not be verified"
    assert report["diverged_at_step"] is None  # keys are never "missed"
    # the field holds text already: where typing goes is unknown, keys again
    rep, log, _ = _typing_replayer(TypingField(value="old"))
    rep.run(extract_steps(_keyboard_lines("ab")))
    assert any(c.startswith("input tap") for c in log)
    # ... also with only part of it selected, or just a cursor in it
    for sel in ((1, 3), (3, 3), (0, 2), (-1, -1)):
        rep, log, _ = _typing_replayer(TypingField(value="old", sel=sel))
        rep.run(extract_steps(_keyboard_lines("ab")))
        assert any(c.startswith("input tap") for c in log), sel


def test_typing_replaces_a_fields_text_that_is_all_selected():
    # An address bar selects its URL on focus: your first key replaced it,
    # and so does the first typed character (device check, Firefox).
    url = "http://10.0.2.2:8765/b.html"
    helper = TypingField(value=url, sel=(0, len(url)))
    rep, log, _ = _typing_replayer(helper)
    report = rep.run(extract_steps(_keyboard_lines("sandro")))
    assert not any(c.startswith("input tap") for c in log)
    first = report["steps"][0]
    assert (first["way"], first["check"]) == ("replayed", "verified")
    assert first["reason"] == (
        "typed 6 characters into the field instead of 6 keyboard taps, field checked"
    )
    assert helper.value == "sandro"
    # selected the other way round (end before start): the same
    helper = TypingField(value=url, sel=(len(url), 0))
    rep, log, _ = _typing_replayer(helper)
    assert rep.run(extract_steps(_keyboard_lines("ab")))["steps"][0]["check"] == (
        "verified"
    )


def test_typing_a_password_into_its_field_prints_no_value():
    rep, log, lines = _typing_replayer(TypingField(password=True))
    report = rep.run(extract_steps(_keyboard_lines("hunter2", password=True)))
    assert report["steps"][0]["check"] == "verified"
    for text in (str(report), str(lines)):
        assert "hunter2" not in text
    assert all(ln["sensitive"] for ln in lines[:1])


# ---------------------------------------------------------------------------
# review round: action keys, ids, recycled rows, other windows
# ---------------------------------------------------------------------------


def test_an_action_key_after_the_text_is_tapped_not_swallowed():
    lines = _keyboard_lines("wdr")
    # Go, tapped after the last character, before the text line was written
    go = _tap(seq=40, t=104.5, ime=True, x=1000, y=2300)
    lines.insert(3, go)
    lines[-1]["data"]["dur_ms"] = 600.0  # the field's last change at 100.6 s
    steps = extract_steps(lines)
    assert steps[0].data["type_text"]["taps"] == 3
    assert "typed_by" not in steps[3].data
    rep, log, _ = _typing_replayer(TypingField())
    report = rep.run(steps)
    assert [c for c in log if c.startswith("input tap")] == ["input tap 1000 2300"]
    assert report["steps"][3]["way"] == "by position"
    # The text went in by typing: Go's spot on the keyboard proves nothing
    # (device check: Gboard showed its compact bar, Go hit a suggestion).
    assert report["steps"][3]["check"] == "unchecked"
    assert report["steps"][3]["reason"] == (
        "keyboard key, the keyboard may look different after typing"
    )
    assert report["unchecked_steps"] == [4]
    # one tap more than characters (Go inside the text's time): keys stay
    lines[-1]["data"]["dur_ms"] = 5000.0
    steps = extract_steps(lines)
    assert all("type_text" not in s.data for s in steps)


def test_a_key_is_nothing_to_check_without_typing_or_after_another_step():
    # no text was typed in place of keys: a key after it is "nothing to check"
    lines = _keyboard_lines("wdr")
    go = _tap(seq=40, t=104.5, ime=True, x=1000, y=2300)
    lines.insert(3, go)
    lines[-1]["data"]["dur_ms"] = 600.0
    rep, _, _ = _typing_replayer(TypingField(rid="p:id/other"))
    report = rep.run(extract_steps(lines))
    assert report["steps"][3]["reason"] == "keyboard key"
    assert report["steps"][3]["check"] == "none"
    # typed, then a tap on the app, then a key: the key is plain again
    lines = _keyboard_lines("wdr")
    lines[-1]["data"]["dur_ms"] = 600.0
    lines += [_tap(seq=55, t=105.0, x=500, y=500),
              _tap(seq=60, t=106.0, ime=True, x=1000, y=2300)]  # fmt: skip
    rep, _, _ = _typing_replayer(TypingField())
    report = rep.run(extract_steps(lines))
    assert report["steps"][0]["check"] == "verified"
    assert report["steps"][4]["reason"] == "keyboard key"
    assert report["steps"][4]["check"] == "none"


def test_a_key_after_a_typed_text_step_is_unchecked():
    # text typed another way (a text step), then Go on the keyboard
    line = _text("abc", seq=10, t=100.0)
    go = _tap(seq=20, t=101.0, ime=True, x=1000, y=2300)
    rep, _, _ = _typing_replayer(TypingField())
    report = rep.run(extract_steps([line, go]))
    assert report["steps"][1]["reason"] == (
        "keyboard key, the keyboard may look different after typing"
    )
    assert report["unchecked_steps"] == [2]


def test_all_selected_needs_the_whole_text_in_utf16_units():
    from sandroid.features.player import _all_selected

    assert _all_selected({"text": "old", "sel_start": 0, "sel_end": 3})
    assert _all_selected({"text": "old", "sel_start": 3, "sel_end": 0})
    assert not _all_selected({"text": "old", "sel_start": 0, "sel_end": 2})
    assert not _all_selected({"text": "old", "sel_start": True, "sel_end": 3})
    assert not _all_selected({"text": "old"})
    # an emoji is two UTF-16 units: (0, 2) covers it
    assert _all_selected({"text": "\U0001f600", "sel_start": 0, "sel_end": 2})
    assert not _all_selected({"text": "a\U0001f600", "sel_start": 0, "sel_end": 2})
    # a text the helper cut: its length is unknown
    assert not _all_selected({"text": "x" * 500 + "\u2026", "sel_start": 0,
                              "sel_end": 501})  # fmt: skip


def test_a_later_texts_keys_are_plain_keys_when_its_field_is_not_verified():
    # "ab" is typed into p:id/url; "cd" belongs to p:id/pw, which never has
    # the focus: its keys are tapped, and are not "after typing"
    first = _keyboard_lines("ab")
    second = [_tap(seq=60 + i, t=110 + i * 0.3, ime=True, x=70, y=2000)
              for i in range(2)]  # fmt: skip
    text2 = _text("cd", seq=70, t=110)
    text2["data"]["target"] = {"rid": "p:id/pw", "bounds": [180, 400, 807, 520]}
    rep, _, _ = _typing_replayer(TypingField())
    report = rep.run(extract_steps([*first, *second, text2]))
    assert report["steps"][0]["check"] == "verified"
    assert report["steps"][2]["reason"] == (
        "keyboard key, its field could not be verified"
    )
    assert report["steps"][3]["reason"].startswith("keyboard key")
    assert "after typing" not in report["steps"][3]["reason"]


def test_an_earlier_texts_keys_are_never_typed_again():
    first = _keyboard_lines("ab")
    second = [
        {**_tap(seq=60 + i, t=110 + i * 0.3, ime=True, x=70, y=2000)} for i in range(2)
    ]
    text2 = _text("cd", seq=70, t=110)
    text2["data"]["target"] = {"rid": "p:id/pw", "bounds": [180, 400, 807, 520]}
    steps = extract_steps([*first, *second, text2])
    assert steps[0].data["type_text"]["text"] == "ab"
    assert steps[2].data["type_text"]["text"] == "cd"
    assert [s.data["typed_by"] for s in steps] == [1, 1, 3, 3]


def test_a_recorded_id_never_accepts_a_focused_field_without_one():
    class NoId(TypingField):
        def focus(self, x=None, y=None, timeout=1.0):
            return {"input": {"editable": True, "text": self.value,
                              "bounds": [0, 1800, 1080, 1900]}}  # fmt: skip

    rep, log, _ = _typing_replayer(NoId())
    report = rep.run(extract_steps(_keyboard_lines("ab")))
    assert any(c.startswith("input tap") for c in log)  # not typed into it
    assert report["steps"][0]["check"] == "unchecked"


class LiveAnswers(FakeHelper):
    """A helper whose live hit test gives the scripted ``answers``."""

    def __init__(self, reply, answers):
        super().__init__([reply])
        self.answers = list(answers)

    def node_at(self, x, y, *, mode="both", timeout=1.0, t_mono_ms=None):
        self.hits.append((x, y))
        live = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        return {"type": "node_at", "live": live}


def _row_dump():
    row = _node(rid="p:id/row", cls="android.view.View", bounds=(0, 400, 1080, 500),
                nid=11, clickable=True,
                kids=[_node("spiegel.de", cls="android.widget.TextView",
                            bounds=(40, 410, 600, 490), nid=12)])  # fmt: skip
    reply = _dump(row)
    reply["windows"][0]["id"] = 10
    return reply, row


def test_the_helper_node_id_decides_and_a_recycled_row_is_not_verified():
    reply, row = _row_dump()
    target = {"rid": "p:id/row", "label": "spiegel.de", "bounds": [0, 400, 1080, 500]}
    same = {"hit": {"nid": 12, "text": "spiegel.de", "bounds": [40, 410, 600, 490]},
            "target": {"nid": 11, "rid": "p:id/row", "cls": "android.view.View",
                       "bounds": [0, 400, 1080, 500]},
            "label": "spiegel.de", "window": {"id": 10}}  # fmt: skip
    rep, _ = _replayer(LiveAnswers(reply, [same]), [])
    step = rep.run(extract_steps([_tap(target=target, x=300, y=450)]))["steps"][0]
    assert step["check"] == "verified"
    # the list refilled: same row id, another text
    other = {**same, "label": "spi", "hit": {**same["hit"], "text": "spi"}}
    rep, _ = _replayer(LiveAnswers(reply, [other]), [])
    step = rep.run(extract_steps([_tap(target=target, x=300, y=450)]))["steps"][0]
    assert (step["way"], step["reason"], step["check"]) == (
        "by position", "element covered", "unchecked",
    )  # fmt: skip
    # the same node id in another window (a dialog) is never it
    dialog = {**same, "window": {"id": 99}}
    rep, _ = _replayer(LiveAnswers(reply, [dialog]), [])
    step = rep.run(extract_steps([_tap(target=target, x=300, y=450)]))["steps"][0]
    assert step["check"] == "unchecked"


def test_a_hit_test_that_answers_nothing_is_not_called_covered():
    reply, _row = _row_dump()
    target = {"rid": "p:id/row", "bounds": [0, 400, 1080, 500]}
    rep, _ = _replayer(LiveAnswers(reply, [{"hit": None, "reason": "no_window"}]), [])
    step = rep.run(extract_steps([_tap(target=target, x=300, y=450)]))["steps"][0]
    assert (step["way"], step["reason"], step["check"]) == (
        "by position", "not hit-tested", "unchecked",
    )  # fmt: skip
