"""The smart Rewind + Replay verdict (``core/replay_verdict.py`` via
``rewind.file_result``): both runs' changes read from the Files lens's
structured diff, volatile fields only by rule (no field names). No device.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

import pytest

from sandroid.core import replay_verdict as rv
from sandroid.core import rewind

#: Your run starts at T0; the replay an hour later at T1.
T0 = 1_763_600_000.0
T1 = T0 + 3600.0
YEAR = 365 * 24 * 3600
PATH_DB = "/data/data/p/databases/app.db"
PATH_PREFS = "/data/data/p/shared_prefs/app.xml"
PATH_JSON = "/data/data/p/files/state.json"
PATH_TXT = "/data/data/p/files/log.txt"
PATH_BIN = "/data/data/p/files/blob.bin"


@pytest.fixture
def files_root(tmp_path, monkeypatch):
    from sandroid.core import watchlist_store

    monkeypatch.setenv(watchlist_store.FILES_DIR_ENV, str(tmp_path / "files"))
    return tmp_path / "files"


def _folder(path: str, name: str) -> Path:
    from sandroid.core import watchlist_store

    folder = watchlist_store.row_dir(path) / name
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _version(path: str, name: str, content: bytes) -> str:
    (_folder(path, name) / Path(path).name).write_bytes(content)
    return name


def _db(name: str, sql: list[str]) -> str:
    con = sqlite3.connect(_folder(PATH_DB, name) / "app.db")
    for stmt in sql:
        con.execute(stmt)
    con.commit()
    con.close()
    return name


def _rec(path: str, before: str, after: str, replay: str) -> rewind.Recording:
    rec = rewind.Recording(rec_id="rec-1", name="R", pkg="p", serial="s")
    rec.started, rec.stopped = T0, T0 + 60
    rec.runs = [
        {
            "n": 2,
            "kind": "rewind-replay",
            "started": T1 - 30,
            "replay_started": T1,
            "ended": T1 + 70,
        }
    ]
    rec.set_role(path, "before", before)
    rec.set_role(path, "after", after)
    rec.set_role(path, "after_replay", replay)
    return rec


_SCHEMA = "create table visits (id integer primary key, url text, seen integer)"


def _visits(name: str, rows: list[tuple]) -> str:
    return _db(
        name,
        [_SCHEMA]
        + [f"insert into visits values ({i}, '{u}', {s})" for i, u, s in rows],
    )


# ---------------------------------------------------------------------------
# SQLite
# ---------------------------------------------------------------------------


def test_sqlite_time_of_its_own_run_is_volatile(files_root):
    before = _visits("v001", [(1, "a", 1_700_000_000_000)])
    after = _visits("v002", [(1, "a", int((T0 + 20) * 1000))])
    replay = _visits("v003", [(1, "a", int((T1 + 5) * 1000))])
    res = rewind.file_result(_rec(PATH_DB, before, after, replay), PATH_DB)
    assert res.verdict == rewind.VOLATILE
    assert res.compared == "field by field"
    (v,) = res.volatile
    assert v["rule"] == rv.RULE_OWN_RUN
    assert v["field"] == "visits, row id=1, column seen"
    assert v["your_run"] == str(int((T0 + 20) * 1000))
    lines = rewind.result_lines(res)
    assert f"Result: {rewind.VOLATILE}" in lines
    assert rewind.VOLATILE_HEADING in lines
    assert any("in your run" in ln and rv.RULE_OWN_RUN in ln for ln in lines)


def test_cookie_expiry_same_distance_from_its_run(files_root):
    schema = "create table cookies (name text primary key, value text, expiry int)"
    before = _db("v001", [schema])
    after = _db(
        "v002",
        [schema, f"insert into cookies values ('sid', 'x', {int(T0 + 40 + YEAR)})"],
    )
    replay = _db(
        "v003",
        [schema, f"insert into cookies values ('sid', 'x', {int(T1 + 33 + YEAR)})"],
    )
    res = rewind.file_result(_rec(PATH_DB, before, after, replay), PATH_DB)
    assert res.verdict == rewind.VOLATILE
    assert [v["rule"] for v in res.volatile] == [rv.RULE_SAME_DISTANCE]
    # The rest of the inserted row (name, value) was the same in both runs.
    assert res.volatile[0]["field"] == "cookies, row name=sid, column expiry"


def test_counter_five_versus_six_is_different(files_root):
    before = _visits("v001", [(1, "a", 4)])
    after = _visits("v002", [(1, "a", 5)])
    replay = _visits("v003", [(1, "a", 6)])
    res = rewind.file_result(_rec(PATH_DB, before, after, replay), PATH_DB)
    assert res.verdict == rewind.DIFFERENT
    assert res.only_run == ["visits, row id=1, column seen: 4 to 5"]
    assert res.only_replay == ["visits, row id=1, column seen: 4 to 6"]
    assert not res.volatile


def test_row_only_in_one_run_is_different_even_beside_a_volatile_field(files_root):
    before = _visits("v001", [(1, "a", 1)])
    after = _visits("v002", [(1, "a", int(T0 + 5)), (2, "b", 1)])
    replay = _visits("v003", [(1, "a", int(T1 + 5))])
    res = rewind.file_result(_rec(PATH_DB, before, after, replay), PATH_DB)
    assert res.verdict == rewind.DIFFERENT
    assert any(ln.startswith("visits, row id=2, column url") for ln in res.only_run)
    assert not res.only_replay
    # The volatile field is still listed, never hidden.
    assert [v["rule"] for v in res.volatile] == [rv.RULE_OWN_RUN]


def test_deleted_in_one_run_and_changed_in_the_other_is_different(files_root):
    before = _visits("v001", [(1, "a", 1)])
    after = _visits("v002", [])
    replay = _visits("v003", [(1, "a", 2)])
    res = rewind.file_result(_rec(PATH_DB, before, after, replay), PATH_DB)
    assert res.verdict == rewind.DIFFERENT


def test_replay_did_not_change_it_when_its_copy_has_the_before_content(files_root):
    before = _visits("v001", [(1, "a", 1)])
    after = _visits("v002", [(1, "a", 2)])
    replay = _visits("v003", [(1, "a", 1)])  # a new version, Before's rows
    res = rewind.file_result(_rec(PATH_DB, before, after, replay), PATH_DB)
    assert res.verdict == rewind.UNCHANGED


def test_same_change_in_both_runs(files_root):
    before = _visits("v001", [(1, "a", 1)])
    after = _visits("v002", [(1, "a", 2), (2, "b", 3)])
    replay = _visits("v003", [(1, "a", 2), (2, "b", 3)])
    res = rewind.file_result(_rec(PATH_DB, before, after, replay), PATH_DB)
    assert res.verdict == rewind.SAME
    assert not res.volatile


def test_many_changed_rows_are_compared_row_by_row_or_byte_for_byte(
    files_root, monkeypatch
):
    from sandroid.core import file_inspect

    # The Files lens keeps 3 rows per table here; the verdict reads more.
    monkeypatch.setattr(file_inspect.sqlite_structured_diff, "__defaults__", (3,))
    rows = [(i, "u", i) for i in range(1, 20)]
    before = _visits("v001", [])
    after = _visits("v002", rows)
    replay = _visits("v003", rows)
    rec = _rec(PATH_DB, before, after, replay)
    res = rewind.file_result(rec, PATH_DB)
    assert res.verdict == rewind.SAME
    assert res.compared == "field by field"
    monkeypatch.setattr(rv, "VERDICT_ROW_LIMIT", 3)
    res2 = rewind.file_result(rec, PATH_DB)
    assert res2.compared == "byte for byte"


# ---------------------------------------------------------------------------
# preferences XML, JSON, text
# ---------------------------------------------------------------------------


def _prefs(entries: str) -> bytes:
    return (
        "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
        f"<map>\n{entries}</map>\n"
    ).encode()


UUID_A = "3f2b8c1e-9d4a-4f6b-8e2c-7a1d5b9c0e34"
UUID_B = "a7c40e92-1b3f-4d58-9a6e-2c8f0b7d4e11"


def _consent_rec() -> rewind.Recording:
    base = '<int name="launches" value="1" />\n'
    before = _version(PATH_PREFS, "v001", _prefs(base))
    after = _version(
        PATH_PREFS,
        "v002",
        _prefs(base + f'<string name="consentUUID">{UUID_A}</string>\n'),
    )
    replay = _version(
        PATH_PREFS,
        "v003",
        _prefs(base + f'<string name="consentUUID">{UUID_B}</string>\n'),
    )
    return _rec(PATH_PREFS, before, after, replay)


def test_consent_uuid_is_a_freshly_generated_id(files_root):
    res = rewind.file_result(_consent_rec(), PATH_PREFS)
    assert res.verdict == rewind.VOLATILE
    (v,) = res.volatile
    assert v == {
        "field": "key consentUUID",
        "your_run": UUID_A,
        "replay": UUID_B,
        "rule": rv.RULE_FRESH_ID,
    }


def test_with_the_id_rule_off_a_fresh_id_is_different(files_root, monkeypatch):
    monkeypatch.setattr(rv, "FRESH_IDS", False)
    res = rewind.file_result(_consent_rec(), PATH_PREFS)
    assert res.verdict == rewind.DIFFERENT
    assert res.only_run == [f"key consentUUID: not there to {UUID_A}"]


def test_an_id_that_was_already_in_before_is_not_fresh(files_root):
    base = f'<string name="old">{UUID_B}</string>\n'
    before = _version(PATH_PREFS, "v001", _prefs(base))
    after = _version(
        PATH_PREFS, "v002", _prefs(base + f'<string name="id">{UUID_A}</string>\n')
    )
    replay = _version(
        PATH_PREFS, "v003", _prefs(base + f'<string name="id">{UUID_B}</string>\n')
    )
    res = rewind.file_result(_rec(PATH_PREFS, before, after, replay), PATH_PREFS)
    assert res.verdict == rewind.DIFFERENT


def test_prefs_counter_different_and_time_volatile(files_root):
    old = '<int name="opens" value="4" />\n<long name="last" value="1" />\n'
    before = _version(PATH_PREFS, "v001", _prefs(old))
    after = _version(
        PATH_PREFS,
        "v002",
        _prefs(
            f'<int name="opens" value="5" />\n<long name="last" value="{int(T0 + 9)}" />\n'
        ),
    )
    replay = _version(
        PATH_PREFS,
        "v003",
        _prefs(
            f'<int name="opens" value="5" />\n<long name="last" value="{int(T1 + 2)}" />\n'
        ),
    )
    res = rewind.file_result(_rec(PATH_PREFS, before, after, replay), PATH_PREFS)
    assert res.verdict == rewind.VOLATILE
    assert [v["field"] for v in res.volatile] == ["key last"]

    replay2 = _version(
        PATH_PREFS,
        "v004",
        _prefs(
            f'<int name="opens" value="6" />\n<long name="last" value="{int(T1 + 2)}" />\n'
        ),
    )
    res2 = rewind.file_result(_rec(PATH_PREFS, before, after, replay2), PATH_PREFS)
    assert res2.verdict == rewind.DIFFERENT
    assert res2.only_run == ["key opens: 4 to 5"]
    assert [v["field"] for v in res2.volatile] == ["key last"]


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t).astimezone().isoformat(timespec="seconds")


def test_json_iso_time_volatile_and_a_real_change_different(files_root):
    def doc(sync: str, items: list[str]) -> bytes:
        return json.dumps({"sync": {"last": sync}, "items": items}).encode()

    before = _version(PATH_JSON, "v001", doc("never", ["a"]))
    after = _version(PATH_JSON, "v002", doc(_iso(T0 + 30), ["a", "b"]))
    replay = _version(PATH_JSON, "v003", doc(_iso(T1 + 12), ["a", "b"]))
    res = rewind.file_result(_rec(PATH_JSON, before, after, replay), PATH_JSON)
    assert res.verdict == rewind.VOLATILE
    assert res.volatile[0]["field"] == "path sync.last"
    assert res.volatile[0]["rule"] == rv.RULE_OWN_RUN

    replay2 = _version(PATH_JSON, "v004", doc(_iso(T1 + 12), ["a", "c"]))
    res2 = rewind.file_result(_rec(PATH_JSON, before, after, replay2), PATH_JSON)
    assert res2.verdict == rewind.DIFFERENT
    assert res2.only_run == ["path items[1]: not there to b"]
    assert res2.only_replay == ["path items[1]: not there to c"]


def test_text_blocks_with_different_old_lines_are_different(files_root):
    before = _version(PATH_TXT, "v001", b"a\nb\nc\n")
    after = _version(PATH_TXT, "v002", b"a\nX\nc\n")  # line 2 replaced
    replay = _version(PATH_TXT, "v003", b"a\nX\n")  # lines 2 to 3 replaced
    res = rewind.file_result(_rec(PATH_TXT, before, after, replay), PATH_TXT)
    assert res.verdict == rewind.DIFFERENT
    assert res.only_run == ["line 2: b to X"]
    assert res.only_replay == ["lines 2 to 3: b | c to X"]


def test_text_line_with_its_run_time_is_volatile(files_root):
    before = _version(PATH_TXT, "v001", b"start\n")
    after = _version(PATH_TXT, "v002", f"start\nsaved at {_iso(T0 + 3)}\n".encode())
    replay = _version(PATH_TXT, "v003", f"start\nsaved at {_iso(T1 + 4)}\n".encode())
    res = rewind.file_result(_rec(PATH_TXT, before, after, replay), PATH_TXT)
    assert res.verdict == rewind.VOLATILE
    assert res.volatile[0]["field"] == "new lines after line 1"

    other = _version(PATH_TXT, "v004", f"start\nloaded at {_iso(T1 + 4)}\n".encode())
    res2 = rewind.file_result(_rec(PATH_TXT, before, after, other), PATH_TXT)
    assert res2.verdict == rewind.DIFFERENT


# ---------------------------------------------------------------------------
# byte comparison, new files, masking
# ---------------------------------------------------------------------------


def test_binary_file_is_compared_byte_for_byte(files_root):
    before = _version(PATH_BIN, "v001", b"\x00\x01\x02")
    after = _version(PATH_BIN, "v002", b"\x00\x09\x02")
    replay = _version(PATH_BIN, "v003", b"\x00\x08\x02")
    res = rewind.file_result(_rec(PATH_BIN, before, after, replay), PATH_BIN)
    assert res.verdict == rewind.DIFFERENT
    assert res.compared == "byte for byte"
    assert rewind.BYTE_WORDS in rewind.result_lines(res)

    copy = _version(PATH_BIN, "v004", b"\x00\x09\x02")
    res2 = rewind.file_result(_rec(PATH_BIN, before, after, copy), PATH_BIN)
    assert res2.verdict == rewind.SAME
    assert res2.compared == "byte for byte"


def test_a_new_file_from_both_runs_compares_its_fields(files_root):
    after = _version(PATH_JSON, "v001", json.dumps({"id": UUID_A, "n": 1}).encode())
    replay = _version(PATH_JSON, "v002", json.dumps({"id": UUID_B, "n": 1}).encode())
    res = rewind.file_result(_rec(PATH_JSON, rewind.ABSENT, after, replay), PATH_JSON)
    assert res.verdict == rewind.VOLATILE
    assert res.volatile[0]["rule"] == rv.RULE_FRESH_ID

    replay2 = _version(PATH_JSON, "v003", json.dumps({"id": UUID_A, "n": 2}).encode())
    res2 = rewind.file_result(_rec(PATH_JSON, rewind.ABSENT, after, replay2), PATH_JSON)
    assert res2.verdict == rewind.DIFFERENT


def test_masking_hides_typed_secrets_in_volatile_values(files_root):
    secret = "hunter2pass"  # noqa: S105 (a typed value, not a credential)
    before = _version(PATH_PREFS, "v001", _prefs(""))
    after = _version(
        PATH_PREFS,
        "v002",
        _prefs(f'<string name="t">{secret} {_iso(T0 + 1)}</string>\n'),
    )
    replay = _version(
        PATH_PREFS,
        "v003",
        _prefs(f'<string name="t">{secret} {_iso(T1 + 1)}</string>\n'),
    )
    rec = _rec(PATH_PREFS, before, after, replay)
    shown = rewind.file_result(rec, PATH_PREFS)
    assert shown.verdict == rewind.VOLATILE
    assert secret in shown.volatile[0]["your_run"]
    res = rewind.file_result(rec, PATH_PREFS, secrets={secret})
    assert res.verdict == rewind.VOLATILE
    assert res.volatile[0]["your_run"] == rv.HIDDEN
    assert secret not in "\n".join(rewind.result_lines(res))


def test_hidden_texts_follow_the_masking_setting(monkeypatch):
    from sandroid.core import timeline

    rec = rewind.Recording(rec_id="rec-1", name="R", pkg="p", serial="s")
    rec.seq = {"start": 1, "stop": 9}
    lines = [
        {"seq": 2, "src": "input", "sensitive": True, "data": {"text": "s3cret!"}},
        {"seq": 3, "src": "input", "data": {"text": "plain words"}},
        {"seq": 4, "src": "input", "data": {"text": "ab", "password": True}},
    ]
    monkeypatch.setattr(rewind, "lines_between", lambda *a, **k: lines)
    monkeypatch.setattr(timeline, "should_mask", lambda reader="ui": False)
    assert rewind.hidden_texts(rec) == frozenset()
    monkeypatch.setattr(timeline, "should_mask", lambda reader="ui": True)
    assert rewind.hidden_texts(rec) == {"s3cret!"}


# ---------------------------------------------------------------------------
# the rules on their own
# ---------------------------------------------------------------------------


def test_time_parsing_units_and_iso():
    assert rv.as_time(int(T0)) == T0
    assert rv.as_time(int(T0 * 1000)) == pytest.approx(T0)
    assert rv.as_time(int(T0 * 1_000_000)) == pytest.approx(T0)
    assert rv.as_time(T0 + 0.5) == T0 + 0.5
    assert rv.as_time(str(int(T0))) == T0
    assert rv.as_time(_iso(T0)) == pytest.approx(T0)
    assert rv.as_time("2025-11-20T00:00:00Z") is not None
    for not_a_time in (5, 6, True, "hello", "20261120", None, rv.ABSENT):
        assert rv.as_time(not_a_time) is None


def test_fresh_id_needs_class_length_randomness_and_no_trace_in_before():
    def empty() -> bytes:
        return b""

    assert rv.is_fresh_id(UUID_A, UUID_B, empty)
    assert rv.is_fresh_id("9f86d081884c7d65", "2c26b46b68ffc68f", empty)
    assert rv.is_fresh_id("aZ3_x-Q9pL0w", "Kd8sV2mQ7rTn", empty)  # b64url ~ alnum
    assert not rv.is_fresh_id("1234567", "7654321", empty)  # digits, short
    assert not rv.is_fresh_id("password", "username", empty)  # words
    assert not rv.is_fresh_id("00000001", "00000002", empty)  # not random
    assert not rv.is_fresh_id("abc12345", "abc1234", empty)  # length
    assert not rv.is_fresh_id(UUID_A, "9f86d081884c7d659f86d081884c7d659f86", empty)
    assert not rv.is_fresh_id(UUID_A, UUID_B, UUID_A.encode)


def test_no_rule_for_names_alone():
    # A field named like a time with values that are not times: no rule.
    ctx = rv._Context(rv.RunWindow(T0, T0 + 60), rv.RunWindow(T1, T1 + 60),
                      lambda: b"", True)  # fmt: skip
    assert rv.volatile_rule(5, 6, ctx) is None
    assert rv.volatile_rule("on", "off", ctx) is None
    assert rv.volatile_rule(int(T0 + 1), int(T1 + 1), ctx) == rv.RULE_OWN_RUN
    # Times far from both runs, at different distances: no rule.
    assert rv.volatile_rule(int(T0 - 5000), int(T0 - 9000), ctx) is None
