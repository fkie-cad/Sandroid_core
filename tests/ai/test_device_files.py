"""Tests for sandroid.ai.device_files (device reads + content cache) and the
shared content renderer in sandroid.ai.row_classifier.

No device: every adb call goes to a fake device (``FakeDevice.run`` /
``FakeDevice.popen``, argv -> bytes), as in tests/services/test_tracking_service.
"""

from __future__ import annotations

import gzip
import inspect
import json
import shlex
import sqlite3
import struct
import threading
import time
from typing import TYPE_CHECKING

import pytest

from sandroid.ai import device_files as df
from sandroid.ai import row_classifier as rc
from sandroid.core.adb import Adb

if TYPE_CHECKING:
    from pathlib import Path

SERIAL = "emulator-5570"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTQ3MTEifQ.c2lnbmF0dXJlLXZhbHVl"
PREFS = (
    "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
    '    <string name="user_id">u-4711</string>\n'
    f'    <string name="auth_token">{JWT}</string>\n'
    '    <int name="launches" value="3" />\n'
    '    <boolean name="onboarded" value="true" />\n'
    "</map>\n"
).encode()
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 200


# --------------------------------------------------------------------------
# fakes
# --------------------------------------------------------------------------


class FakeStream:
    def __init__(self, data: bytes | None, chunk: int = 4096) -> None:
        self.data = data  # None: endless
        self.pos = 0
        self.chunk = chunk
        self.closed = False
        self.delay = 0.0

    def read1(self, n: int) -> bytes:
        if self.delay:
            time.sleep(self.delay)
        if self.closed:
            return b""
        n = min(n, self.chunk)
        if self.data is None:
            return b"A" * n
        out = self.data[self.pos : self.pos + n]
        self.pos += len(out)
        return out

    def exhausted(self) -> bool:
        return self.data is not None and self.pos >= len(self.data)


class FakeProc:
    def __init__(self, argv, data: bytes | None, on_start=None) -> None:
        self.argv = list(argv)
        self.stdout = FakeStream(data)
        self.killed = False
        self.rc = None
        if on_start is not None:
            on_start(self)

    def poll(self):
        if self.killed:
            return -9
        return 0 if self.stdout.exhausted() else None

    def wait(self, timeout=None):
        return self.poll()

    def kill(self) -> None:
        self.killed = True
        self.stdout.closed = True


class FakeDevice:
    """A device: ``files`` {path: bytes}; adbd root, ``su`` or neither."""

    def __init__(
        self,
        files: dict[str, bytes],
        *,
        adbd_root: bool = True,
        su: bool = False,
        dirs: tuple[str, ...] = (),
        endless: tuple[str, ...] = (),
    ) -> None:
        self.files = dict(files)
        self.mtimes = dict.fromkeys(files, 1_700_000_000)
        self.adbd_root = adbd_root
        self.su = su
        self.dirs = set(dirs)
        self.endless = set(endless)
        self.calls: list[list[str]] = []
        self.procs: list[FakeProc] = []
        self.on_read = None  # hook(proc)

    def _words(self, argv: list[str]) -> tuple[list[str], bool]:
        assert argv[0] == "adb"
        assert argv[3] == "exec-out", argv
        words = list(argv[4:])
        rooted = self.adbd_root
        if words[:2] == ["su", "0"]:
            if not self.su:
                return ["__nosu__"], False
            words, rooted = words[2:], True
        elif words[:2] == ["su", "-c"]:
            if not self.su:
                return ["__nosu__"], False
            words, rooted = [words[2]], True
        parsed = shlex.split(" ".join(words))
        return [w for w in parsed if not w.startswith("2>")], rooted

    def run(self, argv, timeout=10.0):
        self.calls.append(list(argv))
        words, rooted = self._words(argv)
        if words == ["__nosu__"]:
            return 127, b"/system/bin/sh: su: not found\n", b""
        if words == ["id", "-u"]:
            return 0, b"0\n" if rooted else b"2000\n", b""
        if words[:2] == ["stat", "-c"]:
            fmt = words[2]
            assert fmt == "%s|%Y|%F|%n"
            lines = []
            for p in words[3:]:
                if p in self.dirs:
                    lines.append(f"4096|1700000000|directory|{p}")
                elif p.startswith("/data/") and not rooted:
                    lines.append(f"stat: '{p}': Permission denied")
                elif p in self.files:
                    size = len(self.files[p]) if p not in self.endless else 10**9
                    lines.append(f"{size}|{self.mtimes[p]}|regular file|{p}")
                else:
                    lines.append(f"stat: '{p}': No such file or directory")
            return 0, ("\n".join(lines) + "\n").encode(), b""
        raise AssertionError(f"unexpected run argv {argv}")

    def popen(self, argv, **kwargs):
        self.calls.append(list(argv))
        words, _rooted = self._words(argv)
        if words[0] == "head":
            n, path = int(words[2]), words[3]
            data = None if path in self.endless else self.files.get(path, b"")[:n]
        elif words[0] == "cat":
            path = words[1]
            data = None if path in self.endless else self.files.get(path, b"")
        else:
            raise AssertionError(f"unexpected popen argv {argv}")
        proc = FakeProc(argv, data, self.on_read)
        self.procs.append(proc)
        return proc

    def reader(self, serial: str = SERIAL, **kw) -> df.DeviceFileReader:
        return df.DeviceFileReader(serial, run=self.run, popen=self.popen, **kw)


@pytest.fixture(autouse=True)
def _adb(monkeypatch):
    monkeypatch.setattr(Adb, "ADB_PATH", "adb")
    monkeypatch.setattr(Adb, "_target_device", None)


def _interned(s: str) -> bytes:
    return struct.pack(">h", -1) + struct.pack(">h", len(s)) + s.encode()


def _raw(s: str) -> bytes:
    return struct.pack(">h", len(s)) + s.encode()


def _abx_prefs(pairs: dict[str, str]) -> bytes:
    out = b"ABX\x00" + bytes([0x10]) + bytes([0x32]) + _interned("map")
    for name, value in pairs.items():
        out += bytes([0x32]) + _interned("string")
        out += bytes([0x2F]) + _interned("name") + _raw(name)
        out += bytes([0x04]) + _raw(value)
        out += bytes([0x33]) + _interned("string")
    return out + bytes([0x33]) + _interned("map") + bytes([0x11])


def _wal_db(tmp_path: Path) -> tuple[bytes, bytes]:
    """A real WAL-mode database whose rows are only in the -wal file."""
    path = tmp_path / "wal.db"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE accounts (id INTEGER, email TEXT, session_key TEXT)")
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute(
        "INSERT INTO accounts VALUES (1, 'alice@example.com', 'deadbeefcafebabe')"
    )
    conn.commit()
    main = path.read_bytes()
    wal = (tmp_path / "wal.db-wal").read_bytes()
    conn.close()
    assert wal, "the insert must be in the WAL"
    return main, wal


# --------------------------------------------------------------------------
# reader: serial pin, root modes, stat, caps
# --------------------------------------------------------------------------


def test_serial_is_pinned_even_after_a_target_switch():
    dev = FakeDevice({"/sdcard/a.txt": b"hello"})
    Adb.set_target_device("other")
    reader = dev.reader("pinned-1")
    reader.probe_root()
    Adb.set_target_device("other-2")  # a device switch mid-run
    stats = reader.stat(["/sdcard/a.txt"])
    got = reader.head("/sdcard/a.txt", 100)
    assert stats["/sdcard/a.txt"].size == 5
    assert got.data == b"hello"
    assert dev.calls
    for argv in dev.calls:
        assert argv[1:3] == ["-s", "pinned-1"], argv
    assert Adb.get_target_device() == "other-2"  # never changed by the reader


def test_root_modes():
    files = {"/data/data/com.x/a.txt": b"secret"}
    root = FakeDevice(files)
    r = root.reader()
    assert r.probe_root() == "root"
    assert r.head("/data/data/com.x/a.txt", 10).data == b"secret"
    assert "su" not in root.procs[-1].argv

    su = FakeDevice(files, adbd_root=False, su=True)
    r = su.reader()
    assert r.probe_root() == "su"
    assert r.stat(["/data/data/com.x/a.txt"])["/data/data/com.x/a.txt"].regular
    assert r.head("/data/data/com.x/a.txt", 10).data == b"secret"
    assert su.procs[-1].argv[4:6] == ["su", "0"]

    none = FakeDevice(files, adbd_root=False)
    r = none.reader()
    assert r.probe_root() == "none"
    st = r.stat(["/data/data/com.x/a.txt"])["/data/data/com.x/a.txt"]
    assert st.error == "permission_denied"


def test_stat_parsing():
    paths = ["/a", "/b c", "/d", "/e", "/f", "/g"]
    text = (
        "12|1700000001|regular file|/a\n"
        "0|1700000002|regular empty file|/b c\n"
        "stat: '/d': No such file or directory\n"
        "stat: '/e': Permission denied\n"
        "4096|1700000003|directory|/f\n"
    )
    out = df.parse_stat(text, paths)
    assert (out["/a"].size, out["/a"].mtime, out["/a"].regular) == (
        12,
        1700000001,
        True,
    )
    assert out["/b c"].regular
    assert out["/b c"].size == 0
    assert out["/d"].error == "gone"
    assert out["/e"].error == "permission_denied"
    assert out["/f"].error is None
    assert not out["/f"].regular
    assert out["/g"].error == "error"  # no line for it
    gnu = df.parse_stat("stat: cannot stat ‘/x’: No such file or directory\n", ["/x"])
    assert gnu["/x"].error == "gone"


def test_stat_batches_fifty_paths_per_call():
    dev = FakeDevice({f"/sdcard/{i}": b"x" for i in range(120)})
    reader = dev.reader()
    out = reader.stat([f"/sdcard/{i}" for i in range(120)])
    assert len(out) == 120
    assert all(s.regular for s in out.values())
    stat_calls = [c for c in dev.calls if "stat" in c]
    assert len(stat_calls) == 3


def test_host_cap_kills_an_oversized_stream():
    dev = FakeDevice({"/sdcard/big": b""}, endless=("/sdcard/big",))
    got = dev.reader().head("/sdcard/big", 10_000)
    assert got.over
    assert got.killed
    assert len(got.data) == 10_001
    assert dev.procs[-1].killed
    assert dev.procs[-1].argv[-3:-1] == ["10001", "/sdcard/big"]


def test_should_stop_ends_a_read():
    dev = FakeDevice({"/sdcard/big": b""}, endless=("/sdcard/big",))
    flag = threading.Event()
    reader = dev.reader(should_stop=lambda: "cancelled" if flag.is_set() else None)

    def slow_then_cancel(proc):
        proc.stdout.delay = 0.01
        flag.set()

    dev.on_read = slow_then_cancel
    got = reader.cat("/sdcard/big", 10**12)
    assert got.stop == "cancelled"


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------


def test_render_prefs_reduces_secret_names_but_matches_them():
    r = rc.render_content("/data/data/com.x/shared_prefs/e2e.xml", PREFS)
    assert r.kind == "content"
    assert r.label == "prefs"
    assert "user_id = u-4711" in r.digest
    assert f"auth_token = [jwt, {len(JWT)} chars]" in r.digest
    assert JWT not in r.digest
    assert JWT in r.match
    assert "launches = 3" in r.digest


def test_render_abx_prefs():
    data = _abx_prefs({"email": "a@b.c", "refresh_token": "abcdef0123456789"})
    r = rc.render_content("/data/system/x.xml", data)
    assert r.label == "abx/prefs"
    assert "email = a@b.c" in r.digest
    assert "refresh_token = [hex, 16 chars]" in r.digest
    assert "abcdef0123456789" in r.match


def test_render_json_text_and_truncated_json():
    doc = {"user": {"name": "bob", "access_token": "tok-123456"}, "n": 1}
    r = rc.render_content("/sdcard/a.json", json.dumps(doc, indent=2).encode())
    assert r.label == "json"
    assert '"name":"bob"' in r.digest
    assert "tok-123456" not in r.digest
    assert "tok-123456" in r.match
    cut = rc.render_content("/sdcard/a.json", b'{"api_key": "k-999", "x": "y", "z')
    assert "k-999" not in cut.digest
    assert "k-999" in cut.match
    kv = rc.render_content("/sdcard/a.conf", b"host=x.example\npassword = hunter2\n")
    assert "host=x.example" in kv.digest
    assert "hunter2" not in kv.digest
    assert "hunter2" in kv.match


def test_render_binary_and_gzip():
    png = rc.render_content("/sdcard/a.png", PNG, size=4096)
    assert png.kind == "binary"
    assert "magic png" in png.digest
    assert "4 kB" in png.digest
    gz = rc.render_content("/sdcard/a.json.gz", gzip.compress(b'{"secret": "s1"}'))
    assert gz.label == "gzip+json"
    assert "s1" not in gz.digest
    assert "s1" in gz.match


def test_gzip_bomb_is_bounded():
    bomb = gzip.compress(b"\x20" * (64 * 1024 * 1024), compresslevel=9)
    assert len(bomb) < 200_000
    t0 = time.monotonic()
    r = rc.render_content("/sdcard/bomb.gz", bomb)
    assert time.monotonic() - t0 < 5
    assert len(r.match) <= rc.RENDER_CAP
    assert "decompressed output capped" in r.digest


def test_render_wal_sqlite(tmp_path):
    main, wal = _wal_db(tmp_path)
    d = tmp_path / "copy"
    d.mkdir()
    (d / "x.db").write_bytes(main)
    (d / "x.db-wal").write_bytes(wal)
    r = rc.render_content("/data/data/com.x/databases/x.db", db=d / "x.db")
    assert r.label == "sqlite"
    assert r.kind == "content"
    assert "accounts (1 rows)" in r.digest  # the row is only in the WAL
    assert "email=alice@example.com" in r.digest
    assert "session_key=[hex, 16 chars]" in r.digest
    assert "deadbeefcafebabe" in r.match
    # The source files were not changed (a private copy was opened).
    assert (d / "x.db").read_bytes() == main
    assert (d / "x.db-wal").read_bytes() == wal
    tables = rc.render_content("/x.db", db=d / "x.db", sqlite="tables")
    assert tables.digest == "sqlite tables: accounts (1 rows)"


# --------------------------------------------------------------------------
# read_into_cache + cache
# --------------------------------------------------------------------------


def _read(dev, root, path, **kw):
    reader = dev.reader()
    st = reader.stat([path])[path]
    return df.read_into_cache(reader, root, path, st, **kw)


def test_read_into_cache_writes_private_atomic_entries(tmp_path):
    root = tmp_path / "session" / "ai" / "content_cache"
    dev = FakeDevice({"/data/data/com.x/shared_prefs/e2e.xml": PREFS})
    out = _read(dev, root, "/data/data/com.x/shared_prefs/e2e.xml", row_last=5.0)
    assert out.status == "read"
    assert out.bytes_read == len(PREFS)
    entry = out.entry
    assert root.stat().st_mode & 0o777 == 0o700
    assert entry.dir.stat().st_mode & 0o777 == 0o700
    names = sorted(p.name for p in entry.dir.iterdir())
    assert names == ["digest.txt", "match.txt", "meta.json", "raw.bin"]
    for p in entry.dir.iterdir():
        assert p.stat().st_mode & 0o777 == 0o600, p
    meta = json.loads((entry.dir / "meta.json").read_text())
    assert meta["serial"] == SERIAL
    assert meta["row_last"] == 5.0
    assert meta["size"] == len(PREFS)
    assert meta["kind"] == "content"
    assert JWT not in entry.digest()
    assert JWT in entry.match()


def test_read_into_cache_sqlite_with_wal(tmp_path):
    main, wal = _wal_db(tmp_path)
    path = "/data/data/com.x/databases/app.db"
    dev = FakeDevice({path: main, path + "-wal": wal})
    root = tmp_path / "cache"
    reader = dev.reader()
    stats = reader.stat([path, path + "-wal"])
    out = df.read_into_cache(reader, root, path, stats[path], wal=stats[path + "-wal"])
    assert out.status == "read"
    assert out.bytes_read == len(main) + len(wal)
    assert (out.entry.dir / "db").read_bytes() == main
    assert (out.entry.dir / "db-wal").read_bytes() == wal
    assert "alice@example.com" in out.entry.digest()
    cats = [p.argv for p in dev.procs]
    assert all(a[4] == "cat" for a in cats)  # no head read for a .db name


def test_sqlite_too_big_and_skip(tmp_path, monkeypatch):
    main, _wal = _wal_db(tmp_path)
    path = "/data/data/com.x/databases/app.db"
    dev = FakeDevice({path: main})
    monkeypatch.setattr(df, "DB_COPY_CAP", len(main) - 1)
    assert _read(dev, tmp_path / "c", path).status == "too_big"
    assert not dev.procs  # not even started
    assert _read(dev, tmp_path / "c", path, sqlite="skip").status == "sqlite_skipped"


def test_binary_keeps_only_size_and_magic(tmp_path):
    dev = FakeDevice({"/sdcard/a.png": PNG})
    out = _read(dev, tmp_path / "c", "/sdcard/a.png")
    assert out.status == "binary"
    assert not (out.entry.dir / "raw.bin").exists()
    assert "magic png" in out.entry.digest()


def test_cache_invalidation(tmp_path):
    root = tmp_path / "c"
    path = "/sdcard/a.txt"
    dev = FakeDevice({path: b"v1"})
    out = _read(dev, root, path, row_last=100.0)
    entry = df.load_entry(path, root)
    st = dev.reader().stat([path])[path]
    assert entry.valid(row_last=100.0, serial=SERIAL, mtime=st.mtime, size=st.size)
    assert not entry.valid(row_last=101.0)  # the monitor saw a later write
    assert not entry.valid(serial="emulator-5556")
    assert not entry.valid(mtime=st.mtime + 1)
    assert not entry.valid(size=st.size + 1)
    assert df.lookup(path, row_last=100.0, serial=SERIAL, root=root) is not None
    assert df.lookup(path, row_last=200.0, root=root) is None
    assert out.entry.meta["read_at"] <= time.time()


def test_eviction_drops_the_oldest(tmp_path):
    root = tmp_path / "c"
    for i, at in enumerate((300.0, 100.0, 200.0)):
        df.write_entry(
            root,
            f"/sdcard/{i}",
            {"read_at": at},
            digest="d",
            match="m",
            files={"raw.bin": b"x" * 1000},
        )
    assert df.evict(root, cap=2500) == 1
    assert df.load_entry("/sdcard/1", root) is None  # read_at 100
    assert df.load_entry("/sdcard/0", root) is not None
    assert df.load_entry("/sdcard/2", root) is not None


def test_file_content_prefers_the_newer_source(tmp_path, monkeypatch):
    from sandroid.core import watchlist_store

    root = tmp_path / "c"
    monkeypatch.setattr(df, "cache_root", lambda session=None: root)
    path = "/data/data/com.x/shared_prefs/e2e.xml"
    dev = FakeDevice({path: PREFS})
    _read(dev, root, path, row_last=10.0)
    got = rc.file_content(path, row_last=10.0, serial=SERIAL)
    assert got.source == "device"
    assert got.digest.startswith("content read from device ")
    assert f"auth_token = [jwt, {len(JWT)} chars]" in got.digest
    assert JWT in got.match
    # Stale (a later write) -> nothing local.
    assert rc.file_content(path, row_last=11.0).kind == "metadata"
    # A newer kept watchlist version wins.
    version = tmp_path / "v002_10-00-00"
    version.mkdir()
    (version / "e2e.xml").write_bytes(b"<map><string name='x'>kept</string></map>")
    from datetime import datetime

    monkeypatch.setattr(watchlist_store, "version_dirs", lambda p: [version])
    monkeypatch.setattr(
        watchlist_store,
        "version_time",
        lambda v: datetime.fromtimestamp(time.time() + 60),
    )
    monkeypatch.setattr(
        watchlist_store, "version_file", lambda v, p: version / "e2e.xml"
    )
    monkeypatch.setattr(watchlist_store, "version_diff", lambda v: None)
    newer = rc.file_content(path, row_last=10.0)
    assert newer.source == "watchlist"
    assert "x = kept" in newer.digest
    monkeypatch.setattr(
        watchlist_store, "version_time", lambda v: datetime.fromtimestamp(1.0)
    )
    assert rc.file_content(path, row_last=10.0).source == "device"


def test_mask_on_withholds_when_redaction_fails(tmp_path, monkeypatch):
    root = tmp_path / "c"
    monkeypatch.setattr(df, "cache_root", lambda session=None: root)
    path = "/sdcard/a.txt"
    _read(FakeDevice({path: b"phone 0151 23456789"}), root, path)
    row = {"key": path, "path": path}

    def boom(text):
        raise RuntimeError("no redactor")

    monkeypatch.setattr("sandroid.ai.safety.redact_secrets", boom)
    d = rc.files_digest(row, mask=True)
    assert d.text == rc.WITHHELD
    assert d.kind == "metadata"
    plain = rc.files_digest(row, mask=False)
    assert "phone 0151 23456789" in plain.text


def test_watchlist_and_forensics_are_never_touched(tmp_path, monkeypatch):
    from sandroid import services
    from sandroid.core import watchlist_store

    def boom(*a, **k):
        raise AssertionError("watchlist / forensic write")

    for name in ("keep_version", "reset_current", "submit_pulled_version"):
        if hasattr(watchlist_store, name):
            monkeypatch.setattr(watchlist_store, name, boom)
    monkeypatch.setattr(services, "get_forensic_service", boom)
    root = tmp_path / "c"
    path = "/data/data/com.x/shared_prefs/e2e.xml"
    assert _read(FakeDevice({path: PREFS}), root, path).status == "read"
    source = inspect.getsource(df)
    for word in ("watchlist_store", "get_forensic_service", "privacy_scan"):
        assert f"import {word}" not in source
        assert f"{word}." not in source
