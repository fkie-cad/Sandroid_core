"""Structured diffs + content previews (``core/file_inspect``), and the proof
that the existing text diff formats (stored diffs, run results, CLI) did not
change.
"""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path

import pytest
from file_inspect_samples import (
    PREFS_NEW,
    PREFS_OLD,
    T_MS,
    make_places,
    write_pairs,
)

from sandroid.core import file_diff
from sandroid.core import file_inspect as fi


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# the text formats are unchanged
# ---------------------------------------------------------------------------

#: What ``sqldiff`` prints for the two directions of a small places.sqlite
#: change (old→new, new→old), as used by ``_db_diff_copies``.
_SQLDIFF_NEW = (
    "INSERT INTO moz_historyvisits(id,from_visit,place_id,visit_date,visit_type,"
    "session,source,triggeringPlaceId) VALUES(6,1,NULL,6,1794994868383,6,NULL);\n"
    "UPDATE moz_meta SET value=7 WHERE \"key\"='origin_frecency_count';\n"
    "UPDATE moz_places SET visit_count=3, frecency=374 WHERE id=2;\n"
)
_SQLDIFF_OLD = (
    "UPDATE moz_meta SET value=4 WHERE \"key\"='origin_frecency_count';\n"
    "UPDATE moz_places SET visit_count=2, frecency=274 WHERE id=2;\n"
    "INSERT INTO moz_bookmarks(id,type,title) VALUES(9,1,'gone, really');\n"
)

#: The exact text ``db_diff`` produced before this change (sealed run
#: results and the CLI print it): byte-for-byte.
_DB_TEXT = (
    "\t\\[[success]INSERT[/success]] Table \\[moz_historyvisits] row "
    "\\[[success]6,1,NULL,6,1794994868383,6,NULL[/success]] has been added\n"
    "\t\\[[warning]UPDATE[/warning]] Table \\[moz_meta] row where "
    "\\[\"key\"='origin_frecency_count'] changed: value=([warning]4 → 7[/warning])\n"
    "\t\\[[warning]UPDATE[/warning]] Table \\[moz_places] row where \\[id=2] "
    "changed: visit_count=([warning]2 → 3[/warning]), "
    "frecency=([warning]274 → 374[/warning])\n"
    "\t\\[[error]DELETE[/error]] Table \\[moz_bookmarks] row "
    "\\[[error]9,1,'gone, really'[/error]] has been removed"
)

_XML_TEXT = (
    '\t[DELETED] /map/string[@name="session_token"] '
    'text="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.old"\n'
    '\t[UPDATED] /map/string[@name="consent_state"] text: "pending" → "granted"\n'
    '\t[UPDATED] /map/boolean[@name="analytics_enabled"] value: "false" → "true"\n'
    '\t[UPDATED] /map/int[@name="launch_count"] value: "3" → "4"\n'
    '\t[ADDED] /map/long[@name="consent_granted_at"] value="1794994868383"\n'
    '\t[ADDED] /map/string[@name="advertising_id"] '
    'text="38400000-8cf0-11bd-b23e-10b96e40000d"\n'
    '\t[ADDED] /map/set[@name="seen_tips"]/string[2] text="sync"\n'
)

_TXT_TEXT = (
    "\t@@ line 12 @@\n"
    "\t[LINE DELETED] line 12: steady state\n"
    "\t[LINE ADDED] line 12: user logged in\n"
    "\t@@ line 26 @@\n"
    "\t[LINE ADDED] line 25b: token refreshed\n"
)


def test_existing_text_diff_formats_are_byte_identical(tmp_path, monkeypatch):
    """The text diffs (``diff.txt``, run results, ``changedfiles``, CLI) are
    exactly what they were; the structured diff is computed next to them.
    """
    calls = []

    def fake_run(source, target):
        calls.append((source, target))
        # _db_diff_copies asks for (new→old) first, then (old→new).
        return (_SQLDIFF_OLD if len(calls) == 1 else _SQLDIFF_NEW), None

    monkeypatch.setattr(file_diff, "_run_sqldiff", fake_run)
    assert file_diff._db_diff_copies("old.db", "new.db", "old.db") == _DB_TEXT

    pairs = write_pairs(tmp_path)
    old_xml, new_xml = pairs["xml"]
    assert file_diff.xml_diff(str(old_xml), str(new_xml)) == _XML_TEXT
    old_txt, new_txt = pairs["text"]
    assert file_diff.txt_diff_paths(str(old_txt), str(new_txt)) == _TXT_TEXT
    raw = tmp_path / "raw"
    for slot, src in (("first_pull", old_txt), ("second_pull", new_txt)):
        dest = raw / slot / "data/data/app/files/app.log"
        dest.parent.mkdir(parents=True)
        dest.write_bytes(src.read_bytes())
    monkeypatch.setenv("RAW_RESULTS_PATH", str(raw))
    assert file_diff.txt_diff("/data/data/app/files/app.log") == _TXT_TEXT

    # diff_files_structured: same text as diff_files, plus the structure.
    def is_sqlite(p):
        return fi.detect_kind(p) == "sqlite"

    text, changed, structured = file_diff.diff_files_structured(
        old_xml, new_xml, is_sqlite
    )
    assert (text, changed) == file_diff.diff_files(old_xml, new_xml, is_sqlite)
    assert text == _XML_TEXT
    assert changed
    assert structured.kind == "xml"
    assert structured.counts() == (2, 4, 1)


def test_parse_text_diff_reads_the_stored_sqlite_format():
    parsed = fi.parse_text_diff(_DB_TEXT)
    assert parsed.kind == "sqlite"
    assert parsed.source == "text"
    by_name = {t.name: t for t in parsed.tables}
    visits = by_name["moz_historyvisits"]
    assert visits.inserted == 1
    assert list(visits.rows[0].values.values()) == [6, 1, None, 6, T_MS, 6, None]
    meta = by_name["moz_meta"].rows[0]
    assert meta.op == "update"
    assert meta.key == [("key", "origin_frecency_count")]
    assert meta.changes == [("value", 4, 7)]
    places = by_name["moz_places"].rows[0]
    assert places.changes == [("visit_count", 2, 3), ("frecency", 274, 374)]
    gone = by_name["moz_bookmarks"]
    assert gone.deleted == 1
    assert list(gone.rows[0].values.values()) == [9, 1, "gone, really"]
    assert parsed.summary() == (
        "moz_bookmarks −1 · moz_historyvisits +1 · moz_meta ~1 · +1 more"
    )


def test_parse_text_diff_xml_text_and_unknown():
    xml = fi.parse_text_diff(_XML_TEXT)
    ops = {(k.op, k.key, k.type) for k in xml.keys}
    assert ("changed", "consent_state", "string") in ops
    assert ("removed", "session_token", "string") in ops
    assert ("added", "seen_tips/string[2]", "set") in ops
    changed = next(k for k in xml.keys if k.key == "launch_count")
    assert (changed.old, changed.new) == ("3", "4")

    text = fi.parse_text_diff(_TXT_TEXT)
    assert text.kind == "text"
    assert text.counts() == (2, 0, 1)

    assert fi.parse_text_diff("\tNo changes detected").empty
    assert (
        fi.parse_text_diff(["[red]- a=true[/red]", "[green]+ a=false[/green]"]) is None
    )
    assert fi.parse_text_diff(None) is None


# ---------------------------------------------------------------------------
# structured diffs from the copies
# ---------------------------------------------------------------------------


def test_sqlite_structured_diff_has_column_names_keys_and_changed_cells(tmp_path):
    old = make_places(tmp_path / "a" / "places.sqlite", 1)
    new = make_places(tmp_path / "b" / "places.sqlite", 2)
    diff = fi.structured_diff(old, new)
    assert diff.kind == "sqlite"
    assert not diff.error
    tables = {t.name: t for t in diff.tables}
    visits = tables["moz_historyvisits"]
    assert (visits.inserted, visits.updated, visits.deleted) == (3, 0, 0)
    assert visits.columns[:4] == ["id", "from_visit", "place_id", "visit_date"]
    first = visits.rows[0]
    assert first.op == "insert"
    assert first.key == [("id", 6)]
    assert first.values["place_id"] == 6
    meta = tables["moz_meta"]  # WITHOUT ROWID, TEXT primary key
    assert meta.updated == 3
    count = next(r for r in meta.rows if r.key == [("key", "origin_frecency_count")])
    assert count.changes == [("value", 4, 7)]
    places = tables["moz_places"]
    assert (places.inserted, places.updated) == (2, 1)
    upd = next(r for r in places.rows if r.op == "update")
    assert upd.key == [("id", 2)]
    assert [c for c, _o, _n in upd.changes] == [
        "visit_count",
        "frecency",
        "last_visit_date",
    ]
    assert "moz_bookmarks" in tables
    assert tables["moz_bookmarks"].inserted == 1
    assert diff.summary() == (
        "moz_historyvisits +3 · moz_meta ~3 · moz_places +2 ~1 · +2 more"
    )


def test_sqlite_diff_reads_wal_and_never_touches_the_copies(tmp_path):
    old = make_places(tmp_path / "a" / "places.sqlite", 3)
    new = make_places(tmp_path / "b" / "places.sqlite", 3, wal=True)
    wal = Path(str(new) + "-wal")
    assert wal.exists()
    before = {p.name: _sha(p) for p in new.parent.iterdir()}
    diff = fi.structured_diff(old, new)
    # The title change exists only in the -wal: it must show up.
    places = next(t for t in diff.tables if t.name == "moz_places")
    assert places.rows[0].changes == [("title", "Firefox", "Firefox — Get the browser")]
    preview = fi.preview_file(new, "moz_places")
    assert preview.rows[0][2] == "Firefox — Get the browser"
    after = {p.name: _sha(p) for p in new.parent.iterdir()}
    assert after == before  # no -shm created, nothing rewritten


def test_sqlite_diff_limits_rows_but_keeps_exact_counts(tmp_path):
    import sqlite3

    paths = []
    for name, n in (("a.db", 10), ("b.db", 40)):
        p = tmp_path / name
        con = sqlite3.connect(p)
        con.execute("CREATE TABLE t (v TEXT)")  # rowid table, no primary key
        con.executemany("INSERT INTO t VALUES (?)", [(f"r{i}",) for i in range(n)])
        con.execute("UPDATE t SET v='changed' WHERE rowid=1")
        con.commit()
        con.close()
        paths.append(p)
    con = sqlite3.connect(paths[0])
    con.execute("UPDATE t SET v='old' WHERE rowid=1")
    con.commit()
    con.close()
    diff = fi.sqlite_structured_diff(*paths, row_limit=5)
    (table,) = diff.tables
    assert (table.inserted, table.updated, table.deleted) == (30, 1, 0)
    assert len(table.rows) == 5
    assert table.truncated
    assert table.rows[0].key[0][0] == "rowid"


def test_xml_json_text_binary_structured(tmp_path):
    pairs = write_pairs(tmp_path)
    xml = fi.structured_diff(*pairs["xml"])
    keys = {k.key: k for k in xml.keys}
    assert keys["consent_state"].op == "changed"
    assert (keys["consent_state"].old, keys["consent_state"].new) == (
        "pending",
        "granted",
    )
    assert keys["seen_tips"].new == ["sync", "welcome"]
    assert keys["advertising_id"].op == "added"
    assert keys["session_token"].op == "removed"
    assert keys["launch_count"].type == "int"

    js = fi.structured_diff(*pairs["json"])
    assert js.kind == "json"
    assert {k.key: k.op for k in js.keys} == {
        "sync.enabled": "changed",
        "sync.last": "changed",
        "device": "added",
        "user.flags[1]": "added",
    }

    text = fi.structured_diff(*pairs["text"])
    assert text.kind == "text"
    first = text.hunks[0]
    assert first.old_start == 9
    assert first.new_start == 9
    removed = [ln for ln in first.lines if ln.tag == "-"]
    assert removed[0].old_no == 12
    assert removed[0].text == "line 12: steady state"

    binary = fi.structured_diff(*pairs["binary"])
    change = binary.binary
    assert binary.kind == "binary"
    assert change.offset == 300
    assert (change.old_size, change.new_size) == (1024, 1040)
    assert change.window_start <= 300 < change.window_start + len(change.new_bytes)
    assert b"\xde\xad\xbe\xef" in change.new_bytes

    same = fi.structured_diff(pairs["xml"][0], pairs["xml"][0])
    assert same.empty
    assert same.summary() == "no change"


def test_abx_is_diffed_like_xml(tmp_path, monkeypatch):
    old, new = tmp_path / "a.xml", tmp_path / "b.xml"
    old.write_bytes(b"ABX\x00old")
    new.write_bytes(b"ABX\x00new")
    docs = {str(old): PREFS_OLD, str(new): PREFS_NEW}
    monkeypatch.setattr(
        file_diff,
        "_convert_abx_to_xml_string",
        lambda p: docs[str(p)].split("?>", 1)[1],
    )
    diff = fi.structured_diff(old, new)
    assert diff.kind == "abx"
    assert {k.key for k in diff.keys} >= {"consent_state", "advertising_id"}


@pytest.mark.parametrize(
    ("value", "column", "expected"),
    [
        (T_MS, "", True),  # ms
        (T_MS * 1000, "", True),  # µs (PRTime)
        (T_MS // 1000, "visit_date", True),  # s with a time-like name
        (T_MS // 1000, "size", False),  # s without one
        (42, "date", False),
        ("1794994868383", "", True),
        (True, "", False),
    ],
)
def test_timestamp_hint(value, column, expected):
    hint = fi.timestamp_hint(value, column)
    assert (hint is not None) == expected
    if expected:
        assert hint.startswith("2026-11-1")


# ---------------------------------------------------------------------------
# previews
# ---------------------------------------------------------------------------


def _png(width: int, height: int) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data))
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + b"\x00" * width * 3 for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def test_previews_of_every_kind(tmp_path):
    pairs = write_pairs(tmp_path)
    db = fi.preview_file(pairs["sqlite"][1])
    assert db.kind == "sqlite"
    counts = {t.name: t.rows for t in db.tables}
    assert counts["moz_places"] == 7
    assert counts["moz_meta"] == 3
    assert db.table == "moz_historyvisits"  # the largest table first
    assert db.columns[:3] == ["id", "from_visit", "place_id"]
    meta = fi.preview_file(pairs["sqlite"][1], "moz_meta")
    assert meta.columns == ["key", "value"]
    assert len(meta.rows) == 3

    prefs = fi.preview_file(pairs["xml"][1])
    assert ("consent_state", "string", "granted") in prefs.keys
    assert ("seen_tips", "set", ["sync", "welcome"]) in prefs.keys

    js = fi.preview_file(pairs["json"][1])
    assert js.kind == "json"
    assert js.data["device"] == "Pixel 7"

    text = fi.preview_file(pairs["text"][1])
    assert text.kind == "text"
    assert text.total_lines == 31
    assert text.lines[11] == "line 12: user logged in"

    png = tmp_path / "shot.png"
    png.write_bytes(_png(7, 3))
    img = fi.preview_file(png)
    assert img.kind == "image"
    assert img.image == {"format": "PNG", "width": 7, "height": 3, "bit_depth": 8}

    blob = fi.preview_file(pairs["binary"][1])
    assert blob.kind == "binary"
    assert blob.type_guess == "binary data"
    assert len(blob.head) == fi.PREVIEW_BYTES

    gz = tmp_path / "x.gz"
    gz.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 20)
    assert fi.preview_file(gz).type_guess == "gzip compressed data"
    assert fi.preview_file(tmp_path / "missing").error


def test_flatten_json_paths():
    flat = fi.flatten_json(json.loads('{"a": {"b": [1, {"c": null}]}, "e": {}}'))
    assert flat == {
        "a.b[0]": ("int", 1),
        "a.b[1].c": ("null", None),
        "e": ("dict", {}),
    }


@pytest.mark.parametrize("download_rows", [1, 0])
def test_content_opens_on_a_data_table_not_android_metadata(
    tmp_path, download_rows
) -> None:
    """E2E (Firefox downloads DB): every table had one row and the Content
    tab opened on ``android_metadata`` (first by name). Bookkeeping tables
    come last -- even after an empty data table.
    """
    import sqlite3

    db = tmp_path / "mozac_downloads_database"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE android_metadata (locale TEXT)")
    con.execute("INSERT INTO android_metadata VALUES ('en_US')")
    con.execute("CREATE TABLE room_master_table (id INTEGER, identity_hash TEXT)")
    con.execute("INSERT INTO room_master_table VALUES (42, 'abc')")
    con.execute("CREATE TABLE downloads (id TEXT, url TEXT, file_name TEXT)")
    for i in range(download_rows):
        con.execute(
            "INSERT INTO downloads VALUES (?, ?, ?)",
            (str(i), "https://example.com/1Mb.dat", "1Mb.dat"),
        )
    con.commit()
    con.close()
    preview = fi.preview_file(db)
    assert preview.table == "downloads"
    assert {t.name for t in preview.tables} >= {"android_metadata", "downloads"}
