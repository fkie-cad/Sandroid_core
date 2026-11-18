"""Structured file diffs and read-only content previews (no Rich, no device).

The line diffs of :mod:`sandroid.core.file_diff` (plain text) end up in
sealed run results, the CLI output and ``analysis/changedfiles.py``. This
module computes the *same* changes as data -- grouped, named, typed -- for
the TUI's Inspector (Files lens "Versions" tab), the ``diff.json`` /
``diff.txt`` stored with every kept version (:func:`diff_document`,
:func:`diff_from_dict`, :func:`render_plain_diff`) and anything else that
wants to render or query a diff:

* :func:`structured_diff` -- two local copies of one file to a
  :class:`StructuredDiff` (SQLite: per table with column names, rows keyed by
  their primary key; XML/ABX: key table; JSON: key paths; text: unified
  hunks with line numbers; anything else: size/hash + first differing bytes).
* :func:`diff_document` / :func:`diff_from_dict` -- a diff to and from the
  ``diff.json`` stored with a kept version (the canonical record);
  :func:`render_plain_diff` -- the plain ``diff.txt`` next to it.
* :func:`parse_text_diff` -- a legacy text diff (``diff.txt`` of a version
  kept before ``diff.json`` existed, or a run's diff lines) back into a
  :class:`StructuredDiff`; only a fallback where no ``diff.json`` exists.
* :func:`preview_file` -- a first look inside one local copy
  (:class:`Preview`): SQLite tables + rows, preference keys, JSON, text,
  image facts, or a hex dump.

Everything is read-only on the given files. SQLite databases are copied to a
temporary directory first; pending ``-wal``/``-journal`` content is folded
into that *copy* (a checkpoint), and the copy is then opened with
``mode=ro&immutable=1``. (``immutable=1`` alone would silently ignore a
``-wal`` file, i.e. show stale data.)
"""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import struct
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from logging import getLogger
from pathlib import Path
from typing import Any

logger = getLogger(__name__)

#: Changed rows kept per table (counts stay exact beyond it).
ROW_LIMIT = 500
#: Rows a content preview reads from one table.
PREVIEW_ROWS = 200
#: Lines a text preview shows.
PREVIEW_LINES = 400
#: Bytes a hex preview shows.
PREVIEW_BYTES = 512
#: Text diffs larger than this (bytes per side) are not diffed line by line.
TEXT_DIFF_MAX = 4 * 1024 * 1024

SQLITE_MAGIC = b"SQLite format 3\x00"
SQLITE_COMPANIONS = ("-wal", "-journal")
#: Bookkeeping tables (Android / Room / SQLite): the Content tab opens on
#: one of these only when the database has nothing else.
METADATA_TABLES = frozenset(
    {"android_metadata", "room_master_table", "sqlite_sequence", "sqlite_stat1"}
)


# ---------------------------------------------------------------------------
# data
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Blob:
    """A BLOB cell: its size and the first bytes (values are not kept whole)."""

    size: int
    head: bytes = b""

    def __str__(self) -> str:
        return f"<blob {self.size} B>"


@dataclass
class RowChange:
    """One inserted, deleted or updated row of a table.

    ``key`` names the row (``[("id", 6)]`` or ``[("rowid", 6)]``); ``values``
    holds the whole row for an insert/delete, ``changes`` only the changed
    cells ``(column, old, new)`` of an update.
    """

    op: str  # "insert" | "delete" | "update"
    key: list[tuple[str, Any]] = field(default_factory=list)
    values: dict[str, Any] = field(default_factory=dict)
    changes: list[tuple[str, Any, Any]] = field(default_factory=list)

    @property
    def key_text(self) -> str:
        return ", ".join(f"{k}={format_value(v)}" for k, v in self.key)


@dataclass
class TableDiff:
    """The changes of one SQLite table."""

    name: str
    columns: list[str] = field(default_factory=list)
    inserted: int = 0
    updated: int = 0
    deleted: int = 0
    rows: list[RowChange] = field(default_factory=list)
    truncated: bool = False
    note: str = ""
    columns_known: bool = True

    @property
    def total(self) -> int:
        return self.inserted + self.updated + self.deleted

    def counts_text(self) -> str:
        parts = []
        if self.inserted:
            parts.append(f"+{self.inserted}")
        if self.updated:
            parts.append(f"~{self.updated}")
        if self.deleted:
            parts.append(f"−{self.deleted}")
        return " ".join(parts) or "±0"


@dataclass
class KeyChange:
    """One added / removed / changed key (XML preference, JSON path)."""

    key: str
    op: str  # "added" | "removed" | "changed"
    old: Any = None
    new: Any = None
    type: str = ""


@dataclass
class TextLine:
    tag: str  # " " context, "+" added, "-" removed
    old_no: int | None
    new_no: int | None
    text: str


@dataclass
class TextHunk:
    old_start: int
    new_start: int
    lines: list[TextLine] = field(default_factory=list)


@dataclass
class BinaryChange:
    old_size: int | None
    new_size: int | None
    old_sha256: str = ""
    new_sha256: str = ""
    offset: int | None = None  # first differing byte
    window_start: int = 0
    old_bytes: bytes = b""
    new_bytes: bytes = b""


@dataclass
class StructuredDiff:
    """A diff as data. ``kind`` says which of the fields carries it."""

    kind: str  # sqlite | xml | abx | json | text | binary | none
    tables: list[TableDiff] = field(default_factory=list)
    keys: list[KeyChange] = field(default_factory=list)
    hunks: list[TextHunk] = field(default_factory=list)
    binary: BinaryChange | None = None
    note: str = ""
    error: str = ""
    #: "files" (computed from the two copies) or "text" (parsed back from a
    #: stored text diff -- SQLite column names are unknown then).
    source: str = "files"

    @property
    def empty(self) -> bool:
        if self.error:
            return False
        if self.kind == "binary":
            b = self.binary
            return b is None or (
                b.old_sha256 == b.new_sha256 and b.old_size == b.new_size
            )
        return not (self.tables or self.keys or self.hunks)

    def counts(self) -> tuple[int, int, int]:
        """``(added, changed, removed)`` over the whole diff."""
        if self.kind == "sqlite":
            return (
                sum(t.inserted for t in self.tables),
                sum(t.updated for t in self.tables),
                sum(t.deleted for t in self.tables),
            )
        if self.keys:
            ops = [k.op for k in self.keys]
            return ops.count("added"), ops.count("changed"), ops.count("removed")
        if self.hunks:
            tags = [ln.tag for h in self.hunks for ln in h.lines]
            return tags.count("+"), 0, tags.count("-")
        return 0, 0, 0

    def summary(self, max_tables: int = 3) -> str:
        """One line, e.g. ``moz_places +3 ~1 · moz_meta ~3``."""
        if self.error:
            return "could not diff"
        if self.empty:
            return "no change"
        if self.kind == "sqlite":
            parts = [f"{t.name} {t.counts_text()}" for t in self.tables[:max_tables]]
            if len(self.tables) > max_tables:
                parts.append(f"+{len(self.tables) - max_tables} more")
            return " · ".join(parts)
        if self.kind == "binary" and self.binary is not None:
            b = self.binary
            old, new = format_size(b.old_size), format_size(b.new_size)
            if old == new and b.old_size != b.new_size:
                old, new = f"{b.old_size}", f"{b.new_size} B"
            where = f" · first diff @{b.offset}" if b.offset is not None else ""
            return f"{old} → {new}{where}"
        added, changed, removed = self.counts()
        unit = "lines" if self.hunks else "keys"
        parts = []
        if added:
            parts.append(f"+{added}")
        if changed:
            parts.append(f"~{changed}")
        if removed:
            parts.append(f"−{removed}")
        return f"{' '.join(parts)} {unit}"


# ---------------------------------------------------------------------------
# formatting helpers (shared with the renderer)
# ---------------------------------------------------------------------------


def format_size(size: int | None) -> str:
    if size is None:
        return "?"
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def format_value(value: Any) -> str:
    """A cell value as one line of text (``NULL``, ``<blob 12 B>``, strings)."""
    if value is None:
        return "NULL"
    if isinstance(value, Blob):
        return str(value)
    if isinstance(value, bytes):
        return f"<blob {len(value)} B>"
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(format_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, default=str)
    text = str(value)
    return text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")


_TIME_NAME = re.compile(
    r"(date|time|_at$|^at$|ts$|stamp|expir|modified|created|updated|last|seen|"
    r"visit|access)",
    re.IGNORECASE,
)
#: 2001-09-09 .. 2096-10-02 in s / ms / µs / ns.
_EPOCH_RANGES = (
    (1_000_000_000_000_000_000, 4_000_000_000_000_000_000, 1e9, "ns"),
    (1_000_000_000_000_000, 4_000_000_000_000_000, 1e6, "µs"),
    (1_000_000_000_000, 4_000_000_000_000, 1e3, "ms"),
    (1_000_000_000, 4_000_000_000, 1.0, "s"),
)


def timestamp_hint(
    value: Any, column: str = "", with_offset: bool = False
) -> str | None:
    """A human time for an int that looks like an epoch timestamp, else None.

    Milli-, micro- and nanoseconds are recognised by magnitude alone (no
    other integers that large are common in app data); plain seconds only
    when the column name suggests a time (``date``, ``time``, ``_at`` ...),
    since sizes and counters overlap with that range. Local time, like the
    pull times shown next to it; ``with_offset`` adds the UTC offset and the
    unit (``2026-11-18 12:33:10+01:00, ms``) for files people keep.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        if not value.isdigit() or len(value) > 19:
            return None
        value = int(value)
    if not isinstance(value, int):
        return None
    for low, high, div, unit in _EPOCH_RANGES:
        if low <= value < high:
            if unit == "s" and not _TIME_NAME.search(column or ""):
                return None
            try:
                when = datetime.fromtimestamp(value / div)
            except (OverflowError, OSError, ValueError):
                return None
            if with_offset:
                stamp = when.astimezone().isoformat(sep=" ", timespec="seconds")
                return f"{stamp}, {unit} epoch"
            return when.strftime("%Y-%m-%d %H:%M:%S")
    return None


# ---------------------------------------------------------------------------
# type detection
# ---------------------------------------------------------------------------

_MAGIC: tuple[tuple[bytes, int, str], ...] = (
    (SQLITE_MAGIC, 0, "SQLite 3 database"),
    (b"ABX\x00", 0, "Android binary XML (ABX)"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image"),
    (b"\xff\xd8\xff", 0, "JPEG image"),
    (b"GIF87a", 0, "GIF image"),
    (b"GIF89a", 0, "GIF image"),
    (b"%PDF-", 0, "PDF document"),
    (b"PK\x03\x04", 0, "ZIP archive (APK/JAR/ZIP)"),
    (b"PK\x05\x06", 0, "ZIP archive (empty)"),
    (b"\x1f\x8b", 0, "gzip compressed data"),
    (b"\x7fELF", 0, "ELF executable / shared object"),
    (b"dex\n", 0, "Dalvik DEX bytecode"),
    (b"bplist00", 0, "Apple binary property list"),
    (b"\x03\x00\x08\x00", 0, "Android binary XML (AXML)"),
    (b"ftyp", 4, "MP4 / ISO media"),
    (b"OggS", 0, "Ogg media"),
    (b"ID3", 0, "MP3 audio"),
    (b"BZh", 0, "bzip2 compressed data"),
    (b"\xfd7zXZ\x00", 0, "xz compressed data"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive"),
    (b"\x28\xb5\x2f\xfd", 0, "Zstandard compressed data"),
    (b"\x04\x22\x4d\x18", 0, "LZ4 compressed data"),
    (b"BM", 0, "BMP image"),
    (b"\x00\x00\x01\x00", 0, "ICO image"),
)


def _read_head(path: str | Path, size: int = 64) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(size)
    except OSError:
        return b""


def guess_type(path: str | Path, head: bytes | None = None) -> str:
    """A ``file``-style description from the magic bytes (and the name)."""
    head = _read_head(path, 4096) if head is None else head
    if not head:
        return "empty file"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "WebP image"
    for magic, offset, label in _MAGIC:
        if head[offset : offset + len(magic)] == magic:
            return label
    if b"\x00" not in head:
        try:
            text = head.decode("utf-8")
        except UnicodeDecodeError:
            # The cut may fall inside a multi-byte character.
            try:
                text = head[:-3].decode("utf-8")
            except UnicodeDecodeError:
                text = None
        if text is not None:
            stripped = text.lstrip()
            if stripped.startswith("<?xml") or stripped.startswith("<"):
                return "XML text"
            if stripped.startswith(("{", "[")):
                return "JSON text" if _is_json(path) else "text"
            return "UTF-8 text"
    name = str(path).lower()
    if name.endswith((".pb", ".proto", ".protobuf")):
        return "binary (protobuf?)"
    return "binary data"


def _is_json(path: str | Path) -> bool:
    try:
        if os.path.getsize(path) > TEXT_DIFF_MAX:
            return False
        json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return True


def detect_kind(path: str | Path) -> str:
    """``sqlite`` / ``abx`` / ``xml`` / ``json`` / ``text`` / ``image`` /
    ``binary`` / ``missing`` for one local file.
    """
    if not os.path.isfile(path):
        return "missing"
    head = _read_head(path, 4096)
    label = guess_type(path, head)
    if label.startswith("SQLite"):
        return "sqlite"
    if label.startswith("Android binary XML (ABX)"):
        return "abx"
    if label == "XML text":
        return "xml"
    if label == "JSON text":
        return "json"
    if label.endswith("image"):
        return "image"
    if label in ("UTF-8 text", "text", "empty file"):
        return "text"
    return "binary"


# ---------------------------------------------------------------------------
# SQLite: read-only copies
# ---------------------------------------------------------------------------


def readable_sqlite_copy(db_path: str | Path, dest_dir: str | Path, name: str) -> Path:
    """Copy a pulled database (+ ``-wal``/``-journal``) into ``dest_dir`` and
    fold the pending writes into the *copy*; returns the copy's path.

    The source files are only read. Open the result with :func:`open_ro`.
    """
    src = str(db_path)
    copy = Path(dest_dir) / name
    shutil.copyfile(src, copy)
    companions = False
    for suffix in SQLITE_COMPANIONS:
        if os.path.isfile(src + suffix):
            shutil.copyfile(src + suffix, str(copy) + suffix)
            companions = True
    if companions:
        con = sqlite3.connect(str(copy))
        try:
            # Reading replays a hot journal; the checkpoint moves WAL frames
            # into the main file so the immutable reader below sees them.
            con.execute("SELECT count(*) FROM sqlite_master").fetchall()
            with contextlib.suppress(sqlite3.Error):
                con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
            with contextlib.suppress(sqlite3.Error):
                con.execute("PRAGMA journal_mode=DELETE").fetchall()
        except sqlite3.Error as exc:
            logger.debug(f"Could not integrate pending writes of {src}: {exc}")
        finally:
            con.close()
    return copy


def _ro_uri(path: str | Path) -> str:
    return Path(path).resolve().as_uri() + "?mode=ro&immutable=1"


def open_ro(path: str | Path) -> sqlite3.Connection:
    """A read-only, immutable connection to a (temporary) database copy."""
    con = sqlite3.connect(_ro_uri(path), uri=True)
    con.text_factory = lambda b: b.decode("utf-8", errors="replace")
    return con


def _qi(name: str) -> str:
    """Quote an SQL identifier.

    Identifiers come from the database's own ``sqlite_master`` and are always
    quoted with this; values are bound parameters. The queries built from
    them (``# nosec B608``) run on a read-only, immutable temporary copy.
    """
    return '"' + name.replace('"', '""') + '"'


def _cell(value: Any) -> Any:
    if isinstance(value, bytes):
        return Blob(len(value), value[:32])
    return value


def _user_tables(con: sqlite3.Connection, schema: str) -> dict[str, str]:
    """``{table name: CREATE sql}`` of the user tables (no sqlite_* / virtual)."""
    rows = con.execute(
        f"SELECT name, sql FROM {schema}.sqlite_master "  # nosec B608
        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {
        name: sql or ""
        for name, sql in rows
        if not (sql or "").upper().startswith("CREATE VIRTUAL")
    }


def _table_info(con, schema: str, table: str) -> list[tuple[str, int]]:
    """``[(column, pk position)]`` (pk 0 = not part of the primary key)."""
    rows = con.execute(f"PRAGMA {schema}.table_info({_qi(table)})").fetchall()
    return [(r[1], int(r[5] or 0)) for r in rows]


def sqlite_structured_diff(
    old_path: str | Path, new_path: str | Path, row_limit: int = ROW_LIMIT
) -> StructuredDiff:
    """Per-table row changes between two database copies, with column names.

    Rows are matched by their primary key (or ``rowid``); a row present on
    both sides with different values is an update listing only the changed
    cells. Computed with ``EXCEPT`` queries inside SQLite, so a large table
    with few changes stays cheap; at most ``row_limit`` changed rows per
    table are kept (the counts stay exact).
    """
    result = StructuredDiff(kind="sqlite")
    try:
        with tempfile.TemporaryDirectory(prefix="sandroid_inspect_") as tmp:
            old_copy = readable_sqlite_copy(old_path, tmp, "old.db")
            new_copy = readable_sqlite_copy(new_path, tmp, "new.db")
            con = open_ro(new_copy)
            try:
                con.execute("ATTACH DATABASE ? AS o", (_ro_uri(old_copy),))
                result.tables = _diff_tables(con, row_limit)
            finally:
                con.close()
    except (OSError, sqlite3.Error) as exc:
        result.error = f"Could not read the database: {exc}"
    result.tables.sort(key=lambda t: (-t.total, t.name))
    return result


def _diff_tables(con: sqlite3.Connection, row_limit: int) -> list[TableDiff]:
    new_tables = _user_tables(con, "main")
    old_tables = _user_tables(con, "o")
    out: list[TableDiff] = []
    for name in sorted(set(new_tables) | set(old_tables)):
        try:
            table = _diff_one_table(
                con,
                name,
                name in old_tables,
                name in new_tables,
                "WITHOUT ROWID" in (new_tables.get(name) or old_tables[name]).upper(),
                row_limit,
            )
        except sqlite3.Error as exc:
            table = TableDiff(name=name, note=f"could not diff: {exc}")
            out.append(table)
            continue
        if table.total or table.note:
            out.append(table)
    return out


def _diff_one_table(
    con, name: str, in_old: bool, in_new: bool, without_rowid: bool, limit: int
) -> TableDiff:
    if not in_old or not in_new:
        schema = "main" if in_new else "o"
        info = _table_info(con, schema, name)
        cols = [c for c, _pk in info]
        table = TableDiff(name=name, columns=cols)
        table.note = "new table" if in_new else "table dropped"
        sel = ", ".join(_qi(c) for c in cols)
        total = con.execute(f"SELECT count(*) FROM {schema}.{_qi(name)}").fetchone()[0]  # nosec B608
        rows = con.execute(
            f"SELECT {sel} FROM {schema}.{_qi(name)} LIMIT ?",  # nosec B608
            (limit,),
        ).fetchall()
        op = "insert" if in_new else "delete"
        pk = [c for c, p in sorted(info, key=lambda x: x[1]) if p] or []
        for row in rows:
            values = {c: _cell(v) for c, v in zip(cols, row, strict=False)}
            key = [(c, values[c]) for c in pk]
            table.rows.append(RowChange(op=op, key=key, values=values))
        if in_new:
            table.inserted = total
        else:
            table.deleted = total
        table.truncated = total > len(rows)
        return table

    new_info = _table_info(con, "main", name)
    old_info = _table_info(con, "o", name)
    old_cols = [c for c, _ in old_info]
    cols = [c for c, _ in new_info if c in old_cols]
    table = TableDiff(name=name, columns=cols)
    added_cols = [c for c, _ in new_info if c not in old_cols]
    dropped_cols = [c for c in old_cols if c not in cols]
    notes = []
    if added_cols:
        notes.append("column added: " + ", ".join(added_cols))
    if dropped_cols:
        notes.append("column dropped: " + ", ".join(dropped_cols))
    table.note = "; ".join(notes)
    if not cols:
        return table
    pk = [c for c, p in sorted(new_info, key=lambda x: x[1]) if p and c in cols]
    use_rowid = not pk and not without_rowid
    key_cols = ["rowid"] if use_rowid else pk
    sel_cols = (['rowid AS "__rowid__"'] if use_rowid else []) + [_qi(c) for c in cols]
    sel = ", ".join(sel_cols)
    q_new = f"SELECT {sel} FROM main.{_qi(name)}"  # nosec B608
    q_old = f"SELECT {sel} FROM o.{_qi(name)}"  # nosec B608
    gone_q = f"{q_old} EXCEPT {q_new}"
    came_q = f"{q_new} EXCEPT {q_old}"
    n_gone = con.execute(f"SELECT count(*) FROM ({gone_q})").fetchone()[0]  # nosec B608
    n_came = con.execute(f"SELECT count(*) FROM ({came_q})").fetchone()[0]  # nosec B608
    if not n_gone and not n_came:
        return table
    names = (["rowid"] if use_rowid else []) + cols

    def as_dict(row) -> dict[str, Any]:
        return dict(zip(names, row, strict=False))

    def key_of(values: dict[str, Any]) -> tuple:
        return tuple(values[c] for c in key_cols) if key_cols else tuple(values.items())

    if key_cols:
        # Exact counts: a key on both sides is an update.
        on = " AND ".join(
            f"g.{_qi('__rowid__' if c == 'rowid' else c)} IS "
            f"c.{_qi('__rowid__' if c == 'rowid' else c)}"
            for c in key_cols
        )
        both = con.execute(
            f"SELECT count(*) FROM ({gone_q}) g JOIN ({came_q}) c ON {on}"  # nosec B608
        ).fetchone()[0]
    else:
        both = 0
    table.updated = both
    table.deleted = n_gone - both
    table.inserted = n_came - both

    fetch = max(limit, 1) * 4
    gone = [as_dict(r) for r in con.execute(f"{gone_q} LIMIT ?", (fetch,))]
    came = [as_dict(r) for r in con.execute(f"{came_q} LIMIT ?", (fetch,))]
    gone_by = {key_of(v): v for v in gone}
    came_by = {key_of(v): v for v in came}
    rows: list[RowChange] = []
    for k, new_v in came_by.items():
        key = [(c, _cell(new_v[c])) for c in key_cols]
        old_v = gone_by.get(k)
        if old_v is not None:
            changes = [
                (c, _cell(old_v[c]), _cell(new_v[c]))
                for c in cols
                if old_v[c] != new_v[c] or type(old_v[c]) is not type(new_v[c])
            ]
            rows.append(RowChange(op="update", key=key, changes=changes))
        else:
            values = {c: _cell(new_v[c]) for c in cols}
            rows.append(RowChange(op="insert", key=key, values=values))
    for k, old_v in gone_by.items():
        if k not in came_by:
            key = [(c, _cell(old_v[c])) for c in key_cols]
            values = {c: _cell(old_v[c]) for c in cols}
            rows.append(RowChange(op="delete", key=key, values=values))
    order = {"insert": 0, "update": 1, "delete": 2}
    rows.sort(key=lambda r: (order[r.op], [_sort_key(v) for _c, v in r.key]))
    table.rows = rows[:limit]
    table.truncated = table.total > len(table.rows)
    return table


def _sort_key(value: Any) -> tuple:
    if value is None:
        return (0, 0, "")
    if isinstance(value, (int, float)):
        return (1, value, "")
    return (2, 0, str(value))


# ---------------------------------------------------------------------------
# XML / ABX / JSON / text / binary
# ---------------------------------------------------------------------------


def _xml_root_from_file(path: str | Path, kind: str):
    from sandroid.core import file_diff

    if kind == "abx":
        data = file_diff._convert_abx_to_xml_string(str(path)).encode("utf-8")
    else:
        data = Path(path).read_bytes()
    return file_diff._parse_xml_bytes(data)


def _pref_value(element) -> tuple[str, Any]:
    from sandroid.core import file_diff

    tag = file_diff._local_name(element.tag)
    attrs = {file_diff._local_name(k): v for k, v in element.attrib.items()}
    if tag == "set":
        items = [
            (child.text or "")
            for child in file_diff._child_elements(element)
            if file_diff._local_name(child.tag) == "string"
        ]
        return tag, sorted(items)
    if "value" in attrs:
        return tag, attrs["value"]
    if tag == "null":
        return tag, None
    return tag, (element.text or "")


def flatten_xml(root) -> dict[str, tuple[str, Any]]:
    """``{key: (type, value)}`` of an XML document.

    SharedPreferences (``<map>``): one entry per preference, keyed by its
    name, typed by its tag (``string``/``int``/``boolean``/``set``...).
    Other XML: one entry per element path (as in the text diff) with its
    attributes/text as the value.
    """
    from sandroid.core import file_diff

    out: dict[str, tuple[str, Any]] = {}
    if file_diff._local_name(root.tag) == "map":
        for child in file_diff._child_elements(root):
            name = child.attrib.get("name")
            tag, value = _pref_value(child)
            key = name if name is not None else tag
            while key in out:
                key += "'"
            out[key] = (tag, value)
        return out

    def walk(path: str, element) -> None:
        out[path] = (
            file_diff._local_name(element.tag),
            file_diff._describe_element(element),
        )
        keyed, unkeyed = file_diff._split_children(element)
        for segment, child in keyed.items():
            walk(f"{path}/{segment}", child)
        for tag, children in unkeyed.items():
            for i, child in enumerate(children):
                seg = file_diff._unkeyed_segment(tag, i, len(children) > 1)
                walk(f"{path}/{seg}", child)

    walk(f"/{file_diff._local_name(root.tag)}", root)
    return out


def _key_changes(
    old: dict[str, tuple[str, Any]], new: dict[str, tuple[str, Any]]
) -> list[KeyChange]:
    changes: list[KeyChange] = []
    for key in sorted(set(old) | set(new), key=str):
        if key not in old:
            typ, value = new[key]
            changes.append(KeyChange(key, "added", new=value, type=typ))
        elif key not in new:
            typ, value = old[key]
            changes.append(KeyChange(key, "removed", old=value, type=typ))
        elif old[key] != new[key]:
            changes.append(
                KeyChange(
                    key, "changed", old=old[key][1], new=new[key][1], type=new[key][0]
                )
            )
    order = {"changed": 0, "added": 1, "removed": 2}
    changes.sort(key=lambda c: order[c.op])
    return changes


def xml_structured_diff(old_path, new_path, kind: str = "xml") -> StructuredDiff:
    result = StructuredDiff(kind=kind)
    try:
        old_root = _xml_root_from_file(old_path, kind)
        new_root = _xml_root_from_file(new_path, kind)
    except Exception as exc:  # parse/decode errors of many kinds
        result.error = f"Could not parse: {exc}"
        return result
    result.keys = _key_changes(flatten_xml(old_root), flatten_xml(new_root))
    return result


def flatten_json(value: Any, prefix: str = "") -> dict[str, tuple[str, Any]]:
    """``{key.path[0]: (type, leaf value)}``; empty containers are leaves."""
    out: dict[str, tuple[str, Any]] = {}
    if isinstance(value, dict) and value:
        for k, v in value.items():
            out.update(flatten_json(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(value, list) and value:
        for i, v in enumerate(value):
            out.update(flatten_json(v, f"{prefix}[{i}]"))
    else:
        out[prefix or "$"] = (
            type(value).__name__ if value is not None else "null",
            value,
        )
    return out


def json_structured_diff(old_path, new_path) -> StructuredDiff:
    result = StructuredDiff(kind="json")
    try:
        old = json.loads(Path(old_path).read_text(encoding="utf-8"))
        new = json.loads(Path(new_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        result.error = f"Could not parse: {exc}"
        return result
    result.keys = _key_changes(flatten_json(old), flatten_json(new))
    return result


def _read_lines(path) -> list[str] | None:
    try:
        if os.path.getsize(path) > TEXT_DIFF_MAX:
            return None
        return Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None


def text_hunks(old: list[str], new: list[str], context: int = 3) -> list[TextHunk]:
    """Unified-diff hunks with line numbers on both sides."""
    hunks: list[TextHunk] = []
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    for group in matcher.get_grouped_opcodes(context):
        hunk = TextHunk(old_start=group[0][1] + 1, new_start=group[0][3] + 1)
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                for k in range(i2 - i1):
                    hunk.lines.append(
                        TextLine(" ", i1 + k + 1, j1 + k + 1, old[i1 + k])
                    )
                continue
            for k in range(i1, i2):
                hunk.lines.append(TextLine("-", k + 1, None, old[k]))
            for k in range(j1, j2):
                hunk.lines.append(TextLine("+", None, k + 1, new[k]))
        hunks.append(hunk)
    return hunks


def text_structured_diff(old_path, new_path) -> StructuredDiff:
    old, new = _read_lines(old_path), _read_lines(new_path)
    if old is None or new is None:
        return binary_structured_diff(old_path, new_path)
    return StructuredDiff(kind="text", hunks=text_hunks(old, new))


def _sha256(path) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _first_difference(old_path, new_path) -> int | None:
    try:
        with open(old_path, "rb") as a, open(new_path, "rb") as b:
            offset = 0
            while True:
                ca, cb = a.read(1 << 16), b.read(1 << 16)
                if ca != cb:
                    n = min(len(ca), len(cb))
                    for i in range(n):
                        if ca[i] != cb[i]:
                            return offset + i
                    return offset + n
                if not ca:
                    return None
                offset += len(ca)
    except OSError:
        return None


def _read_window(path, start: int, size: int) -> bytes:
    try:
        with open(path, "rb") as f:
            f.seek(start)
            return f.read(size)
    except OSError:
        return b""


def binary_structured_diff(old_path, new_path, window: int = 64) -> StructuredDiff:
    """Size + sha256 of both, and the bytes around the first difference."""

    def size(p):
        try:
            return os.path.getsize(p)
        except OSError:
            return None

    change = BinaryChange(
        old_size=size(old_path),
        new_size=size(new_path),
        old_sha256=_sha256(old_path),
        new_sha256=_sha256(new_path),
    )
    if change.old_sha256 != change.new_sha256:
        change.offset = _first_difference(old_path, new_path)
        if change.offset is not None:
            change.window_start = max(0, (change.offset // 16) * 16 - 16)
            change.old_bytes = _read_window(old_path, change.window_start, window)
            change.new_bytes = _read_window(new_path, change.window_start, window)
    return StructuredDiff(kind="binary", binary=change)


def structured_diff(old_path: str | Path, new_path: str | Path) -> StructuredDiff:
    """The changes from ``old_path`` to ``new_path`` as a :class:`StructuredDiff`.

    Same dispatch idea as ``file_diff.diff_files`` (magic header first), but
    widened to ABX, JSON and binary files.
    """
    old_kind, new_kind = detect_kind(old_path), detect_kind(new_path)
    if "missing" in (old_kind, new_kind):
        return StructuredDiff(kind="none", error="A version's file is missing.")
    kind = new_kind if new_kind == old_kind else "binary"
    if old_kind in ("text", "json", "xml") and new_kind in ("text", "json", "xml"):
        kind = new_kind if old_kind == new_kind else "text"
    try:
        if kind == "sqlite":
            return sqlite_structured_diff(old_path, new_path)
        if kind in ("xml", "abx"):
            result = xml_structured_diff(old_path, new_path, kind)
            return (
                result if not result.error else text_structured_diff(old_path, new_path)
            )
        if kind == "json":
            return json_structured_diff(old_path, new_path)
        if kind == "text":
            return text_structured_diff(old_path, new_path)
        return binary_structured_diff(old_path, new_path)
    except Exception as exc:  # never let a preview crash the UI
        logger.debug("structured_diff failed", exc_info=True)
        return StructuredDiff(kind=kind, error=f"Could not diff: {exc}")


# ---------------------------------------------------------------------------
# parsing a stored text diff back into structure
# ---------------------------------------------------------------------------

_SQL_INSERT = re.compile(
    r"^\[(INSERT|DELETE)\] Table \[(.+?)\] row \[(.*)\] has been (added|removed)$"
)
_SQL_UPDATE = re.compile(
    r"^\[UPDATE\] Table \[(.+?)\] row where \[(.*?)\] changed: (.*)$"
)
_XML_LINE = re.compile(r"^\[(ADDED|DELETED|UPDATED)\] (\S+)(?: (.*))?$")
_TEXT_HUNK = re.compile(r"^@@ line (\d+) @@$")
_PREF_SEGMENT = re.compile(r'^/map/(\w+)\[@name="(.*?)"\](?:\[\d+\])?(/.*)?$')


def _plain_line(line: str) -> str:
    r"""A stored diff line without Rich markup.

    Only the legacy SQLite lines (``\\[[success]INSERT[/success]] ...``,
    written before diffs were stored as plain text) carry markup; a plain
    line is returned as is, even when its data holds brackets.
    """
    if line.lstrip().startswith("\\[["):
        try:
            from rich.text import Text

            return Text.from_markup(line).plain
        except Exception:
            pass
    return line


def split_sql_values(text: str) -> list[Any]:
    """Split ``1,'a,b',NULL,X'00'`` (sqldiff VALUES) into Python values."""
    values: list[Any] = []
    i, n = 0, len(text)
    while i <= n:
        if i < n and text[i] == "'":
            j, buf = i + 1, []
            while j < n:
                if text[j] == "'" and j + 1 < n and text[j + 1] == "'":
                    buf.append("'")
                    j += 2
                elif text[j] == "'":
                    break
                else:
                    buf.append(text[j])
                    j += 1
            values.append("".join(buf))
            i = j + 1
            while i < n and text[i] != ",":
                i += 1
            i += 1
            continue
        j = text.find(",", i)
        if j < 0:
            j = n
        token = text[i:j].strip()
        if token.upper() == "NULL":
            values.append(None)
        elif re.fullmatch(r"[xX]'[0-9a-fA-F]*'", token):
            values.append(Blob(len(token[2:-1]) // 2))
        else:
            try:
                values.append(int(token))
            except ValueError:
                try:
                    values.append(float(token))
                except ValueError:
                    values.append(token)
        i = j + 1
    return values


def _split_assignments(text: str) -> list[tuple[str, str]]:
    """``a=1, b=(x → y)`` → ``[("a", "1"), ("b", "(x → y)")]`` (paren aware)."""
    parts, depth, quote, buf = [], 0, False, []
    for ch in text:
        if ch == "'" and depth == 0:
            quote = not quote
        if not quote:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            elif ch == "," and depth == 0:
                parts.append("".join(buf))
                buf = []
                continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf))
    out = []
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            out.append((k.strip(), v.strip()))
    return out


def _sql_literal(token: str) -> Any:
    values = split_sql_values(token)
    return values[0] if len(values) == 1 else token


def parse_text_diff(diff: str | list[str] | None) -> StructuredDiff | None:
    """A stored ``file_diff`` text diff as a :class:`StructuredDiff`.

    Understands the SQLite (``[INSERT] Table [t] row [...]``), keyed XML
    (``[ADDED] /map/string[@name="k"] ...``) and line (``@@ line N @@``)
    formats. Returns None when the text is none of them (the caller shows
    it as text), or an empty diff for the "no change" messages.
    """
    if diff is None:
        return None
    lines = diff.splitlines() if isinstance(diff, str) else [str(x) for x in diff]
    plain = [_plain_line(line).strip() for line in lines]
    plain = [line for line in plain if line]
    if not plain or all(
        p.lower().startswith(("no change", "no changes")) for p in plain
    ):
        return StructuredDiff(kind="none", source="text")
    if any(_SQL_INSERT.match(p) or _SQL_UPDATE.match(p) for p in plain):
        return _parse_sql_lines(plain)
    if any(p.startswith(("[LINE ADDED]", "[LINE DELETED]")) for p in plain):
        return _parse_line_diff(plain)
    if any(_XML_LINE.match(p) for p in plain):
        return _parse_xml_lines(plain)
    return None


def _parse_sql_lines(lines: list[str]) -> StructuredDiff:
    result = StructuredDiff(kind="sqlite", source="text")
    tables: dict[str, TableDiff] = {}

    def table(name: str) -> TableDiff:
        if name not in tables:
            tables[name] = TableDiff(name=name, columns_known=False)
        return tables[name]

    for line in lines:
        m = _SQL_INSERT.match(line)
        if m:
            op = "insert" if m.group(1) == "INSERT" else "delete"
            values = split_sql_values(m.group(3))
            t = table(m.group(2))
            cols = [f"#{i + 1}" for i in range(len(values))]
            if len(cols) > len(t.columns):
                t.columns = cols
            t.rows.append(
                RowChange(op=op, values=dict(zip(cols, values, strict=False)))
            )
            if op == "insert":
                t.inserted += 1
            else:
                t.deleted += 1
            continue
        m = _SQL_UPDATE.match(line)
        if m:
            t = table(m.group(1))
            key = [
                (k.strip('"'), _sql_literal(v))
                for k, v in _split_assignments(m.group(2))
            ]
            if not key and m.group(2):
                key = [("where", m.group(2))]
            changes = []
            for col, value in _split_assignments(m.group(3)):
                if value.startswith("(") and value.endswith(")") and " → " in value:
                    old, new = value[1:-1].split(" → ", 1)
                    changes.append((col, _sql_literal(old), _sql_literal(new)))
            t.rows.append(RowChange(op="update", key=key, changes=changes))
            t.updated += 1
    result.tables = sorted(tables.values(), key=lambda t: (-t.total, t.name))
    return result


def _parse_line_diff(lines: list[str]) -> StructuredDiff:
    result = StructuredDiff(kind="text", source="text")
    hunk: TextHunk | None = None
    old_no = new_no = 0
    for line in lines:
        m = _TEXT_HUNK.match(line)
        if m:
            new_no = int(m.group(1))
            old_no = new_no
            hunk = TextHunk(old_start=old_no, new_start=new_no)
            result.hunks.append(hunk)
            continue
        if hunk is None:
            hunk = TextHunk(old_start=1, new_start=1)
            result.hunks.append(hunk)
            old_no = new_no = 1
        if line.startswith("[LINE DELETED]"):
            hunk.lines.append(TextLine("-", None, None, line[len("[LINE DELETED] ") :]))
        elif line.startswith("[LINE ADDED]"):
            hunk.lines.append(TextLine("+", None, new_no, line[len("[LINE ADDED] ") :]))
            new_no += 1
    return result


_XML_UPDATE_DETAIL = re.compile(r'^(text|[\w:.-]+): "(.*)" → "(.*)"$')


def _xml_key(path: str) -> tuple[str, str]:
    m = _PREF_SEGMENT.match(path)
    if m:
        return m.group(2) + (m.group(3) or ""), m.group(1)
    return path, ""


def _parse_xml_lines(lines: list[str]) -> StructuredDiff:
    result = StructuredDiff(kind="xml", source="text")
    for line in lines:
        m = _XML_LINE.match(line)
        if not m:
            continue
        label, path, detail = m.group(1), m.group(2), m.group(3) or ""
        key, typ = _xml_key(path)
        if label in ("ADDED", "DELETED"):
            value = detail
            vm = re.fullmatch(r'value="(.*)"', detail) or re.fullmatch(
                r'text="(.*)"', detail
            )
            if vm:
                value = vm.group(1)
            op = "added" if label == "ADDED" else "removed"
            change = KeyChange(key, op, type=typ)
            if op == "added":
                change.new = value
            else:
                change.old = value
            result.keys.append(change)
            continue
        um = _XML_UPDATE_DETAIL.match(detail)
        if um:
            attr = um.group(1)
            name = key if attr in ("value", "text") or not typ else f"{key} @{attr}"
            if not typ and attr not in ("text",):
                name = f"{key} @{attr}"
            result.keys.append(
                KeyChange(name, "changed", old=um.group(2), new=um.group(3), type=typ)
            )
        else:
            result.keys.append(KeyChange(key, "changed", new=detail, type=typ))
    return result


# ---------------------------------------------------------------------------
# diff.json: a StructuredDiff on disk, and the plain diff.txt rendered from it
# ---------------------------------------------------------------------------

#: ``diff.json`` document format (bump on an incompatible change).
DIFF_SCHEMA = "sandroid.file_diff"
DIFF_SCHEMA_VERSION = 1
#: Version of the structured diff engine in this module (bump when the
#: computed changes would differ for the same two files).
ENGINE_VERSION = "1"


def _json_value(value: Any) -> Any:
    """A cell / key value as JSON (blobs as ``{"$blob": ...}``)."""
    if isinstance(value, Blob):
        return {"$blob": {"size": value.size, "head_hex": value.head.hex()}}
    if isinstance(value, (bytes, bytearray)):
        return {"$blob": {"size": len(value), "head_hex": bytes(value[:32]).hex()}}
    if isinstance(value, float) and not math.isfinite(value):
        return {"$float": repr(value)}
    if isinstance(value, (list, tuple)):
        return [_json_value(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _json_value(v) for k, v in value.items()}
    return value


def _from_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {"$blob"} and isinstance(value["$blob"], dict):
            blob = value["$blob"]
            try:
                head = bytes.fromhex(str(blob.get("head_hex") or ""))
            except ValueError:
                head = b""
            return Blob(int(blob.get("size") or 0), head)
        if set(value) == {"$float"}:
            try:
                return float(value["$float"])
            except (TypeError, ValueError):
                return value
        return {k: _from_json_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_from_json_value(v) for v in value]
    return value


def _row_dict(row: RowChange) -> dict[str, Any]:
    out: dict[str, Any] = {
        "op": row.op,
        "key": {c: _json_value(v) for c, v in row.key},
    }
    if row.op == "update":
        out["changes"] = [
            {"column": c, "old": _json_value(o), "new": _json_value(n)}
            for c, o, n in row.changes
        ]
    else:
        out["values"] = {c: _json_value(v) for c, v in row.values.items()}
    return out


def diff_to_dict(diff: StructuredDiff) -> dict[str, Any]:
    """The changes of a :class:`StructuredDiff` as JSON-ready data.

    SQLite: ``tables`` (columns, primary key, counts, rows: ``op`` +
    ``key`` + the whole row or the changed cells with old/new); XML/ABX/JSON:
    ``keys``; text: ``hunks``; anything else: ``binary``. Inverse:
    :func:`diff_from_dict`.
    """
    added, changed, removed = diff.counts()
    out: dict[str, Any] = {
        "kind": diff.kind,
        "changed": not diff.empty,
        "summary": diff.summary(),
        "counts": {"added": added, "changed": changed, "removed": removed},
        "note": diff.note,
        "error": diff.error,
    }
    if diff.tables:
        out["tables"] = [
            {
                "name": t.name,
                "columns": list(t.columns),
                "primary_key": [c for c, _v in t.rows[0].key] if t.rows else [],
                "inserted": t.inserted,
                "updated": t.updated,
                "deleted": t.deleted,
                "truncated": t.truncated,
                "note": t.note,
                "rows": [_row_dict(r) for r in t.rows],
            }
            for t in diff.tables
        ]
    if diff.keys:
        out["keys"] = [
            {
                "key": k.key,
                "op": k.op,
                "type": k.type,
                "old": _json_value(k.old),
                "new": _json_value(k.new),
            }
            for k in diff.keys
        ]
    if diff.hunks:
        out["hunks"] = [
            {
                "old_start": h.old_start,
                "new_start": h.new_start,
                "lines": [
                    {
                        "tag": ln.tag,
                        "old_no": ln.old_no,
                        "new_no": ln.new_no,
                        "text": ln.text,
                    }
                    for ln in h.lines
                ],
            }
            for h in diff.hunks
        ]
    if diff.binary is not None:
        b = diff.binary
        out["binary"] = {
            "old_size": b.old_size,
            "new_size": b.new_size,
            "old_sha256": b.old_sha256,
            "new_sha256": b.new_sha256,
            "first_difference": b.offset,
            "window_start": b.window_start,
            "old_bytes_hex": b.old_bytes.hex(),
            "new_bytes_hex": b.new_bytes.hex(),
        }
    return out


def diff_from_dict(data: dict[str, Any]) -> StructuredDiff:
    """A :class:`StructuredDiff` from :func:`diff_to_dict` data (``diff.json``)."""
    result = StructuredDiff(
        kind=str(data.get("kind") or "none"),
        note=str(data.get("note") or ""),
        error=str(data.get("error") or ""),
        source="json",
    )
    for t in data.get("tables") or []:
        table = TableDiff(
            name=str(t.get("name")),
            columns=[str(c) for c in t.get("columns") or []],
            inserted=int(t.get("inserted") or 0),
            updated=int(t.get("updated") or 0),
            deleted=int(t.get("deleted") or 0),
            truncated=bool(t.get("truncated")),
            note=str(t.get("note") or ""),
        )
        for r in t.get("rows") or []:
            key = [
                (str(c), _from_json_value(v)) for c, v in (r.get("key") or {}).items()
            ]
            if r.get("op") == "update":
                changes = [
                    (
                        str(c.get("column")),
                        _from_json_value(c.get("old")),
                        _from_json_value(c.get("new")),
                    )
                    for c in r.get("changes") or []
                ]
                table.rows.append(RowChange("update", key=key, changes=changes))
            else:
                values = {
                    str(c): _from_json_value(v)
                    for c, v in (r.get("values") or {}).items()
                }
                table.rows.append(
                    RowChange(str(r.get("op") or "insert"), key=key, values=values)
                )
        result.tables.append(table)
    for k in data.get("keys") or []:
        result.keys.append(
            KeyChange(
                key=str(k.get("key")),
                op=str(k.get("op")),
                old=_from_json_value(k.get("old")),
                new=_from_json_value(k.get("new")),
                type=str(k.get("type") or ""),
            )
        )
    for h in data.get("hunks") or []:
        hunk = TextHunk(int(h.get("old_start") or 0), int(h.get("new_start") or 0))
        for ln in h.get("lines") or []:
            hunk.lines.append(
                TextLine(
                    str(ln.get("tag") or " "),
                    ln.get("old_no"),
                    ln.get("new_no"),
                    str(ln.get("text") or ""),
                )
            )
        result.hunks.append(hunk)
    b = data.get("binary")
    if isinstance(b, dict):
        try:
            old_bytes = bytes.fromhex(str(b.get("old_bytes_hex") or ""))
            new_bytes = bytes.fromhex(str(b.get("new_bytes_hex") or ""))
        except ValueError:
            old_bytes = new_bytes = b""
        result.binary = BinaryChange(
            old_size=b.get("old_size"),
            new_size=b.get("new_size"),
            old_sha256=str(b.get("old_sha256") or ""),
            new_sha256=str(b.get("new_sha256") or ""),
            offset=b.get("first_difference"),
            window_start=int(b.get("window_start") or 0),
            old_bytes=old_bytes,
            new_bytes=new_bytes,
        )
    return result


def diff_document(diff: StructuredDiff, **meta: Any) -> dict[str, Any]:
    """The ``diff.json`` document: format and engine metadata, ``meta``
    (version ids, compared files with sha256, ``created_at`` ...) and the
    diff itself (:func:`diff_to_dict`).
    """
    try:
        from sandroid import __version__ as sandroid_version
    except Exception:  # pragma: no cover - partial installs
        sandroid_version = "unknown"
    doc: dict[str, Any] = {
        "schema": DIFF_SCHEMA,
        "schema_version": DIFF_SCHEMA_VERSION,
        "engine": {
            "name": "sandroid.core.file_inspect.structured_diff",
            "version": ENGINE_VERSION,
            "sandroid": sandroid_version,
        },
    }
    doc.update(meta)
    doc.update(diff_to_dict(diff))
    return doc


def _plain_value(value: Any, column: str = "") -> str:
    """A value for ``diff.txt``: raw, plus a readable time for epoch-like ints."""
    text = format_value(value)
    hint = timestamp_hint(value, column, with_offset=True)
    return f"{text}  ({hint})" if hint else text


def _plain_header(doc: dict[str, Any], diff: StructuredDiff) -> list[str]:
    out: list[str] = []
    head = (
        f"{doc.get('file') or doc.get('device_path') or ''}  {doc.get('version') or ''}"
    )
    if doc.get("base_version"):
        head += f"  <-  {doc['base_version']}"
    out.append(head.strip())
    out.append(f"{diff.kind} · {doc.get('summary') or diff.summary()}")
    if doc.get("created_at"):
        out.append(f"created {doc['created_at']}")
    compared = doc.get("compared") or {}
    for side in ("base", "new"):
        for f in compared.get(side) or []:
            out.append(
                f"{side:<4} {f.get('file')}  {f.get('size')} B  "
                f"sha256 {f.get('sha256') or '?'}"
            )
    out.append("")
    return out


def _plain_tables(diff: StructuredDiff) -> list[str]:
    out: list[str] = []
    for t in diff.tables:
        line = f"Table {t.name}  ({t.counts_text()})"
        if t.note:
            line += f"  -- {t.note}"
        out.append(line)
        width = max((len(c) for c in t.columns), default=0)
        for r in t.rows:
            out.append(f"  {r.op.upper()}  {r.key_text}".rstrip())
            if r.op == "update":
                for c, old, new in r.changes:
                    out.append(
                        f"    {c:<{width}}  {_plain_value(old, c)}  ->  "
                        f"{_plain_value(new, c)}"
                    )
            else:
                for c, v in r.values.items():
                    out.append(f"    {c:<{width}}  {_plain_value(v, c)}")
        if t.truncated:
            out.append(f"  ... {t.total - len(t.rows)} more changed rows not listed")
        out.append("")
    return out


def render_plain_diff(doc: dict[str, Any]) -> str:
    """``diff.txt``: a ``diff.json`` document as plain text for people.

    No markup. SQLite rows with column names and raw values (epoch-like
    values followed by a readable local time with UTC offset); preference /
    JSON keys with their type; text as unified hunks; binary as sizes,
    hashes and the bytes around the first difference.
    """
    diff = diff_from_dict(doc)
    out = _plain_header(doc, diff)
    if diff.error:
        out.append(f"Could not diff: {diff.error}")
    elif diff.empty:
        out.append(diff.note or "No change.")
    out.extend(_plain_tables(diff))
    for k in diff.keys:
        typ = f" ({k.type})" if k.type else ""
        if k.op == "changed":
            out.append(
                f"CHANGED  {k.key}{typ}: {_plain_value(k.old, k.key)}  ->  "
                f"{_plain_value(k.new, k.key)}"
            )
        elif k.op == "added":
            out.append(f"ADDED    {k.key}{typ} = {_plain_value(k.new, k.key)}")
        else:
            out.append(f"REMOVED  {k.key}{typ} = {_plain_value(k.old, k.key)}")
    for h in diff.hunks:
        olds = sum(1 for ln in h.lines if ln.tag != "+")
        news = sum(1 for ln in h.lines if ln.tag != "-")
        out.append(f"@@ -{h.old_start},{olds} +{h.new_start},{news} @@")
        out.extend(f"{ln.tag}{ln.text}" for ln in h.lines)
    b = diff.binary
    if b is not None and not diff.empty:
        out.append(f"Binary  {b.old_size} B  ->  {b.new_size} B")
        out.append(f"  sha256 old {b.old_sha256}")
        out.append(f"  sha256 new {b.new_sha256}")
        if b.offset is not None:
            out.append(f"  first difference at byte {b.offset}")
            out.append(f"  old @{b.window_start}: {b.old_bytes.hex(' ')}")
            out.append(f"  new @{b.window_start}: {b.new_bytes.hex(' ')}")
    return "\n".join(out).rstrip("\n") + "\n"


# ---------------------------------------------------------------------------
# content preview
# ---------------------------------------------------------------------------


@dataclass
class SqliteTable:
    name: str
    rows: int | None
    columns: list[str] = field(default_factory=list)
    kind: str = "table"


@dataclass
class Preview:
    """A first look inside one local file; ``kind`` says which fields are set."""

    kind: str
    path: str
    size: int | None = None
    type_guess: str = ""
    error: str = ""
    tables: list[SqliteTable] = field(default_factory=list)
    table: str | None = None  # the table whose rows are below
    columns: list[str] = field(default_factory=list)
    rows: list[tuple] = field(default_factory=list)
    keys: list[tuple[str, str, Any]] = field(default_factory=list)  # key, type, value
    data: Any = None  # parsed JSON
    lines: list[str] = field(default_factory=list)
    total_lines: int = 0
    image: dict[str, Any] = field(default_factory=dict)
    head: bytes = b""


def sqlite_tables(con: sqlite3.Connection) -> list[SqliteTable]:
    out = []
    for name, typ, sql in con.execute(
        "SELECT name, type, sql FROM sqlite_master WHERE type IN ('table','view') "
        "ORDER BY type, name"
    ).fetchall():
        if name.startswith("sqlite_") and name != "sqlite_sequence":
            continue
        virtual = (sql or "").upper().startswith("CREATE VIRTUAL")
        try:
            cols = [r[1] for r in con.execute(f"PRAGMA table_info({_qi(name)})")]
        except sqlite3.Error:
            cols = []
        count: int | None = None
        if not virtual:
            try:
                count = con.execute(f"SELECT count(*) FROM {_qi(name)}").fetchone()[0]  # nosec B608
            except sqlite3.Error:
                count = None
        out.append(SqliteTable(name, count, cols, "virtual" if virtual else typ))
    return out


def _preview_sqlite(preview: Preview, path: str, table: str | None, limit: int) -> None:
    with tempfile.TemporaryDirectory(prefix="sandroid_preview_") as tmp:
        copy = readable_sqlite_copy(path, tmp, "preview.db")
        con = open_ro(copy)
        try:
            preview.tables = sqlite_tables(con)
            names = [t.name for t in preview.tables]
            if table not in names:
                # The largest table first -- never a bookkeeping table: with
                # one row each, android_metadata used to win on its name
                # (E2E: Firefox's downloads DB opened on its locale row).
                ranked = [t for t in preview.tables if t.kind == "table"]
                ranked.sort(
                    key=lambda t: (t.name in METADATA_TABLES, -(t.rows or 0), t.name)
                )
                table = ranked[0].name if ranked else (names[0] if names else None)
            preview.table = table
            if table is not None:
                cur = con.execute(f"SELECT * FROM {_qi(table)} LIMIT ?", (limit,))  # nosec B608
                preview.columns = [d[0] for d in cur.description or ()]
                preview.rows = [tuple(_cell(v) for v in row) for row in cur.fetchall()]
        finally:
            con.close()


def _image_info(path: str, head: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {}
    try:
        if head.startswith(b"\x89PNG") and head[12:16] == b"IHDR":
            w, h = struct.unpack(">II", head[16:24])
            info.update(format="PNG", width=w, height=h, bit_depth=head[24])
        elif head[:6] in (b"GIF87a", b"GIF89a"):
            w, h = struct.unpack("<HH", head[6:10])
            info.update(format="GIF", width=w, height=h)
        elif head[:4] == b"RIFF" and head[8:12] == b"WEBP":
            info["format"] = "WebP"
            chunk = head[12:16]
            if chunk == b"VP8X":
                w = 1 + int.from_bytes(head[24:27], "little")
                h = 1 + int.from_bytes(head[27:30], "little")
                info.update(width=w, height=h)
            elif chunk == b"VP8 ":
                w, h = struct.unpack("<HH", head[26:30])
                info.update(width=w & 0x3FFF, height=h & 0x3FFF)
            elif chunk == b"VP8L":
                bits = int.from_bytes(head[21:25], "little")
                info.update(
                    width=(bits & 0x3FFF) + 1, height=((bits >> 14) & 0x3FFF) + 1
                )
        elif head[:2] == b"\xff\xd8":
            info["format"] = "JPEG"
            info.update(_jpeg_size(path))
        elif head[:2] == b"BM":
            w, h = struct.unpack("<ii", head[18:26])
            info.update(format="BMP", width=w, height=abs(h))
    except (struct.error, OSError):
        pass
    return info


def _jpeg_size(path: str) -> dict[str, int]:
    with open(path, "rb") as f:
        data = f.read(256 * 1024)
    i = 2
    while i + 9 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        length = struct.unpack(">H", data[i + 2 : i + 4])[0]
        if marker in (
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        ):
            h, w = struct.unpack(">HH", data[i + 5 : i + 9])
            return {"width": w, "height": h}
        i += 2 + length
    return {}


def preview_file(
    path: str | Path, table: str | None = None, row_limit: int = PREVIEW_ROWS
) -> Preview:
    """A read-only first look inside ``path`` (see :class:`Preview`).

    ``table`` picks the SQLite table whose first ``row_limit`` rows are read
    (default: the largest table).
    """
    p = str(path)
    kind = detect_kind(p)
    preview = Preview(kind=kind, path=p)
    if kind == "missing":
        preview.error = "The local copy is missing."
        return preview
    try:
        preview.size = os.path.getsize(p)
    except OSError:
        preview.size = None
    head = _read_head(p, 4096)
    preview.type_guess = guess_type(p, head)
    preview.head = head[:PREVIEW_BYTES]
    try:
        if kind == "sqlite":
            _preview_sqlite(preview, p, table, row_limit)
        elif kind in ("xml", "abx"):
            root = _xml_root_from_file(p, kind)
            preview.keys = [(k, t, v) for k, (t, v) in flatten_xml(root).items()]
        elif kind == "json":
            preview.data = json.loads(Path(p).read_text(encoding="utf-8"))
        elif kind == "text":
            with open(p, encoding="utf-8", errors="replace") as f:
                for n, line in enumerate(f):
                    if n < PREVIEW_LINES:
                        preview.lines.append(line.rstrip("\n"))
                    preview.total_lines = n + 1
        elif kind == "image":
            preview.image = _image_info(p, head)
    except Exception as exc:  # show what we can, never crash the Inspector
        logger.debug("preview_file failed", exc_info=True)
        preview.error = f"Could not read it as {kind}: {exc}"
    return preview


__all__ = [
    "DIFF_SCHEMA",
    "DIFF_SCHEMA_VERSION",
    "ENGINE_VERSION",
    "BinaryChange",
    "Blob",
    "KeyChange",
    "Preview",
    "RowChange",
    "SqliteTable",
    "StructuredDiff",
    "TableDiff",
    "TextHunk",
    "TextLine",
    "detect_kind",
    "diff_document",
    "diff_from_dict",
    "diff_to_dict",
    "flatten_json",
    "flatten_xml",
    "format_size",
    "format_value",
    "guess_type",
    "open_ro",
    "parse_text_diff",
    "preview_file",
    "readable_sqlite_copy",
    "render_plain_diff",
    "split_sql_values",
    "structured_diff",
    "timestamp_hint",
]
