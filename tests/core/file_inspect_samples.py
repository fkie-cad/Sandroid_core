"""Realistic sample files for the structured diff / preview tests (and the
screenshot script): a Firefox-like ``places.sqlite`` in three versions, a
SharedPreferences pair, JSON, text and binary pairs.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

PLACES_SCHEMA = """
CREATE TABLE moz_places (
  id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
  rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0,
  hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL,
  frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER,
  guid TEXT, foreign_count INTEGER DEFAULT 0 NOT NULL,
  url_hash INTEGER DEFAULT 0 NOT NULL, description TEXT,
  preview_image_url TEXT, origin_id INTEGER);
CREATE TABLE moz_historyvisits (
  id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER,
  visit_date INTEGER, visit_type INTEGER, session INTEGER,
  source INTEGER DEFAULT 0 NOT NULL, triggeringPlaceId INTEGER);
CREATE TABLE moz_meta (key TEXT PRIMARY KEY, value NOT NULL) WITHOUT ROWID;
CREATE TABLE moz_origins (
  id INTEGER PRIMARY KEY, prefix TEXT NOT NULL, host TEXT NOT NULL,
  frecency INTEGER NOT NULL, UNIQUE (prefix, host));
CREATE TABLE moz_bookmarks (
  id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER DEFAULT NULL,
  parent INTEGER, position INTEGER, title LONGVARCHAR,
  dateAdded INTEGER, lastModified INTEGER, guid TEXT);
"""

#: 2026-11-18 ~10:41 local-ish epoch values (ms for visits, µs for places).
T_MS = 1794994868383
T_US = T_MS * 1000

SITES = [
    ("https://www.mozilla.org/en-US/firefox/", "Firefox", "gro.allizom.www."),
    (
        "https://en.wikipedia.org/wiki/Android_(operating_system)",
        "Android (operating system) - Wikipedia",
        "gro.aidepikiw.ne.",
    ),
    (
        "https://duckduckgo.com/?q=sandroid+forensics",
        "sandroid forensics at DuckDuckGo",
        "moc.ogkcudkcud.",
    ),
    ("https://news.ycombinator.com/", "Hacker News", "moc.rotanibmocy.swen."),
    (
        "https://github.com/fkie-cad/Sandroid_core",
        "fkie-cad/Sandroid_core",
        "moc.buhtig.",
    ),
    ("https://www.heise.de/newsticker/", "heise online News", "ed.esieh.www."),
    ("https://maps.google.com/?q=Bonn", "Bonn - Google Maps", "moc.elgoog.spam."),
    (
        "https://accounts.example.com/login?next=%2Finbox",
        "Sign in",
        "moc.elpmaxe.stnuocca.",
    ),
]


def _place(i: int, visits: int, when_us: int) -> tuple:
    url, title, rev = SITES[i - 1]
    return (
        i,
        url,
        title,
        rev,
        visits,
        0,
        1 if i % 3 == 0 else 0,
        100 * visits + 37 * i,
        when_us,
        f"guid{i:08d}AbC",
        0,
        47_000_000_000_000 + i * 991,
        None,
        None,
        i,
    )


def make_places(path: Path, version: int, wal: bool = False) -> Path:
    """``places.sqlite`` as it looks after browsing step ``version`` (1..3)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm", "-journal"):
        Path(str(path) + suffix).unlink(missing_ok=True)
    con = sqlite3.connect(path)
    if wal:
        con.execute("PRAGMA journal_mode=WAL")
    con.executescript(PLACES_SCHEMA)
    n_places = {1: 5, 2: 7, 3: 8}[version]
    for i in range(1, n_places + 1):
        visits = 1 + (i == 2) + (version >= 2 and i == 2) + (version >= 3 and i == 1)
        when = T_US - (8 - i) * 61_000_000
        if version >= 2 and i == 2:
            when = T_US + 2_000_000  # revisited
        con.execute(
            f"INSERT INTO moz_places VALUES ({','.join('?' * 15)})",
            _place(i, visits, when),
        )
    n_visits = {1: 5, 2: 8, 3: 9}[version]
    for v in range(1, n_visits + 1):
        place = min(v, n_places)
        con.execute(
            "INSERT INTO moz_historyvisits VALUES (?,?,?,?,?,?,?,?)",
            (
                v,
                v - 1 if v > 1 else 0,
                place,
                T_MS - (9 - v) * 61_000,
                1 if v % 2 else 6,
                v,
                0,
                None,
            ),
        )
    meta = {
        1: {
            "origin_frecency_count": 4,
            "origin_frecency_sum": 512,
            "origin_frecency_sum_of_squares": 70144,
        },
        2: {
            "origin_frecency_count": 7,
            "origin_frecency_sum": 941,
            "origin_frecency_sum_of_squares": 133921,
        },
        3: {
            "origin_frecency_count": 8,
            "origin_frecency_sum": 1003,
            "origin_frecency_sum_of_squares": 141012,
        },
    }[version]
    for k, v in meta.items():
        con.execute("INSERT INTO moz_meta VALUES (?, ?)", (k, v))
    for i in range(1, n_places + 1):
        con.execute(
            "INSERT INTO moz_origins VALUES (?,?,?,?)",
            (i, "https://", SITES[i - 1][0].split("/")[2], 100 + i),
        )
    con.execute(
        "INSERT INTO moz_bookmarks VALUES (1, 2, NULL, 0, 0, '', ?, ?, 'root________')",
        (T_US - 10**9, T_US - 10**9),
    )
    if version >= 2:
        con.execute(
            "INSERT INTO moz_bookmarks VALUES (2, 1, 5, 1, 0, 'Sandroid', ?, ?, ?)",
            (T_US, T_US, "bmkSandroid1"),
        )
    con.commit()
    if not wal:
        con.close()
        return path
    # Keep the last change in the -wal (not checkpointed), like a live app.
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute(
        "UPDATE moz_places SET title=? WHERE id=1", ("Firefox — Get the browser",)
    )
    con.commit()
    import shutil

    snap = path.with_suffix(".snap")
    snap.mkdir(exist_ok=True)
    for suffix in ("", "-wal"):
        shutil.copyfile(str(path) + suffix, str(snap / path.name) + suffix)
    con.close()
    for suffix in ("", "-wal", "-shm"):
        Path(str(path) + suffix).unlink(missing_ok=True)
        src = Path(str(snap / path.name) + suffix)
        if src.exists():
            shutil.copyfile(src, str(path) + suffix)
    shutil.rmtree(snap)
    return path


PREFS_OLD = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="consent_state">pending</string>
    <boolean name="analytics_enabled" value="false" />
    <int name="launch_count" value="3" />
    <long name="first_launch_ms" value="1794994000000" />
    <string name="session_token">eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.old</string>
    <set name="seen_tips">
        <string>welcome</string>
    </set>
</map>
"""

PREFS_NEW = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="consent_state">granted</string>
    <boolean name="analytics_enabled" value="true" />
    <int name="launch_count" value="4" />
    <long name="first_launch_ms" value="1794994000000" />
    <long name="consent_granted_at" value="1794994868383" />
    <string name="advertising_id">38400000-8cf0-11bd-b23e-10b96e40000d</string>
    <set name="seen_tips">
        <string>welcome</string>
        <string>sync</string>
    </set>
</map>
"""

JSON_OLD = {
    "user": {"id": 1234, "name": "alex", "flags": ["beta"]},
    "sync": {"enabled": False, "last": 1794994000},
}
JSON_NEW = {
    "user": {"id": 1234, "name": "alex", "flags": ["beta", "ads"]},
    "sync": {"enabled": True, "last": 1794994868},
    "device": "Pixel 7",
}

TEXT_OLD = "".join(f"line {i}: steady state\n" for i in range(1, 31))
TEXT_NEW = TEXT_OLD.replace("line 12: steady state", "line 12: user logged in").replace(
    "line 25: steady state\n", "line 25: steady state\nline 25b: token refreshed\n"
)


def write_pairs(root: Path) -> dict[str, tuple[Path, Path]]:
    """Old/new pairs of every kind under ``root``; ``{kind: (old, new)}``."""
    root.mkdir(parents=True, exist_ok=True)
    pairs: dict[str, tuple[Path, Path]] = {}
    for tag, version in (("old", 1), ("new", 2)):
        make_places(root / tag / "places.sqlite", version)
    pairs["sqlite"] = (root / "old" / "places.sqlite", root / "new" / "places.sqlite")
    for tag, text in (("old", PREFS_OLD), ("new", PREFS_NEW)):
        (root / tag / "prefs.xml").write_text(text, encoding="utf-8")
    pairs["xml"] = (root / "old" / "prefs.xml", root / "new" / "prefs.xml")
    for tag, data in (("old", JSON_OLD), ("new", JSON_NEW)):
        (root / tag / "state.json").write_text(json.dumps(data), encoding="utf-8")
    pairs["json"] = (root / "old" / "state.json", root / "new" / "state.json")
    for tag, text in (("old", TEXT_OLD), ("new", TEXT_NEW)):
        (root / tag / "app.log").write_text(text, encoding="utf-8")
    pairs["text"] = (root / "old" / "app.log", root / "new" / "app.log")
    blob = bytes(range(256)) * 4
    (root / "old" / "cache.bin").write_bytes(blob)
    (root / "new" / "cache.bin").write_bytes(
        blob[:300] + b"\xde\xad\xbe\xef" + blob[304:] + b"\x00" * 16
    )
    pairs["binary"] = (root / "old" / "cache.bin", root / "new" / "cache.bin")
    return pairs
